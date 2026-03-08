//! A machine determines when to send decoy traffic or delay traffic. Consists
//! of one or more [`State`] structs.

use crate::constants::{MAX_DECOMPRESSED_SIZE, STATE_MAX, VERSION};
use crate::{Error, state};
use base64::prelude::*;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::fmt;
use std::io::prelude::*;
use std::str::FromStr;

use self::state::State;

/// A probabilistic state machine (a probabilistic Moore machine) consisting of
/// one or more [`State`] that determine when to send decoy traffic or delay
/// traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Machine {
    /// The number of decoy packets the machine is allowed to generate as
    /// actions before other limits apply. Use with care.
    pub allowed_decoy_packets: u64,
    /// The number of microseconds of delay a machine is allowed to generate as
    /// actions before other limits apply. Use with care.
    pub allowed_delay_microsec: u64,
    /// The states that make up the machine.
    pub states: Vec<State>,
}

impl Machine {
    /// Create a new [`Machine`] with the given limits and states. Returns an
    /// error if the machine or any of its states are invalid.
    pub fn new(
        allowed_decoy_packets: u64,
        allowed_delay_microsec: u64,
        states: Vec<State>,
    ) -> Result<Self, Error> {
        let machine = Machine {
            allowed_decoy_packets,
            allowed_delay_microsec,
            states,
        };
        machine.validate()?;

        Ok(machine)
    }

    /// Get a unique and deterministic string that represents the machine. The
    /// string is 32 characters long, hex-encoded.
    pub fn name(&self) -> String {
        let s = digest(self.serialize());
        s[0..32].to_string()
    }

    pub fn serialize(&self) -> String {
        let encoded = postcard::to_allocvec(&self).unwrap();
        let mut e = ZlibEncoder::new(Vec::new(), Compression::best());
        e.write_all(encoded.as_slice()).unwrap();
        let s = BASE64_STANDARD.encode(e.finish().unwrap());
        // version as first 2 characters, then base64 compressed postcard
        format!("{VERSION:02}{s}")
    }

    /// Validates that the machine is in a valid state (machines that are
    /// mutated may get into an invalid state).
    pub fn validate(&self) -> Result<(), Error> {
        // sane number of states
        let num_states = self.states.len();

        if num_states == 0 {
            Err(Error::Machine(
                "a machine must have at least one state".to_string(),
            ))?;
        }
        if num_states > STATE_MAX {
            Err(Error::Machine(format!(
                "too many states, max is {STATE_MAX}, found {num_states}"
            )))?;
        }

        // validate all states
        for state in self.states.iter() {
            state
                .validate(num_states)
                .map_err(|e| Error::Machine(e.to_string()))?;
        }

        Ok(())
    }
}

/// From a serialized string, attempt to create a machine.
impl FromStr for Machine {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // version as first 2 bytes (len() checks bytes)
        if s.len() < 3 {
            Err(Error::Machine("string too short".to_string()))?;
        }
        if !s.is_ascii() {
            Err(Error::Machine("string is not ascii".to_string()))?;
        }
        let version = &s[0..2];
        let body = &s[2..];

        // base64 decoding has a fixed ratio of ~4:3
        let compressed = BASE64_STANDARD
            .decode(body.as_bytes())
            .map_err(|_| Error::Machine("base64 decoding failed".to_string()))?;
        // decompress, but scared of exceeding memory limits / zlib bombs
        let decoder = ZlibDecoder::new(compressed.as_slice());
        let mut buf = Vec::new();
        decoder
            .take(MAX_DECOMPRESSED_SIZE as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| Error::Machine(e.to_string()))?;
        if buf.len() > MAX_DECOMPRESSED_SIZE {
            return Err(Error::Machine("decompressed data too large".to_string()));
        }
        let bytes_read = buf.len();

        let m: Machine = match version {
            "03" => postcard::from_bytes(&buf[..bytes_read])
                .map_err(|e| Error::Machine(e.to_string()))?,
            _ => Err(Error::Machine(format!(
                "version mismatch, expected {VERSION:02}, got {version}"
            )))?,
        };

        // ensure that the machine is valid
        m.validate()?;
        Ok(m)
    }
}

impl fmt::Display for Machine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Machine {}\n\
            - allowed_decoy_packets: {}\n\
            - allowed_delay_microsec: {}\n\
            States:\n\
            {}",
            self.name(),
            self.allowed_decoy_packets,
            self.allowed_delay_microsec,
            self.states
                .iter()
                .map(|s| format!("{s}"))
                .collect::<Vec<String>>()
                .join("\n")
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::event::Event;
    use crate::machine::*;
    use crate::state::Trans;
    use enum_map::enum_map;

    #[test]
    fn machine_name_generation() {
        let s0 = State::new(enum_map! {
                 Event::DecoyQueued => vec![Trans(0, 1.0)],
             _ => vec![],
        });

        // machine
        let m = Machine::new(1000, 0, vec![s0]).unwrap();

        // name generation should be deterministic
        assert_eq!(m.name(), m.name());
    }

    #[test]
    fn validate_machine_num_states() {
        // invalid machine lacking state
        let r = Machine::new(1000, 0, vec![]);

        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());
    }

    #[test]
    fn validate_machine_states() {
        // out of bounds index
        let s0 = State::new(enum_map! {
                 Event::DecoyQueued => vec![Trans(1, 1.0)],
             _ => vec![],
        });
        // machine with broken state
        let r = Machine::new(1000, 0, vec![s0]);
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        // valid states should be allowed
        let s0 = State::new(enum_map! {
                 Event::DecoyQueued => vec![Trans(0, 0.8)],
             _ => vec![],
        });
        let r = Machine::new(1000, 0, vec![s0]);
        assert!(r.is_ok());
    }

    #[test]
    fn roundtrip_serialization() {
        let s0 = State::new(enum_map! {
            Event::DecoyQueued => vec![Trans(0, 1.0)],
            _ => vec![],
        });
        let m = Machine::new(1000, 0, vec![s0]).unwrap();
        let serialized = m.serialize();
        let m2 = Machine::from_str(&serialized).unwrap();
        assert_eq!(m2.serialize(), serialized);
    }
}
