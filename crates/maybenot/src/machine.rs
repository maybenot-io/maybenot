//! A machine determines when to inject and/or block outgoing traffic. Consists
//! of one or more [`State`] structs.

use crate::constants::*;
use crate::*;
use base64::prelude::*;
use bincode::Options;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::fmt;
use std::io::prelude::*;
use std::str::FromStr;

use self::state::State;

/// A probabilistic state machine (Rabin automaton) consisting of one or more
/// [`State`] that determine when to inject and/or block outgoing traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Machine {
    /// The number of padding packets the machine is allowed to generate as
    /// actions before other limits apply.
    pub allowed_padding_packets: u64,
    /// The maximum fraction of padding packets to allow as actions.
    pub max_padding_frac: f64,
    /// The number of microseconds of blocking a machine is allowed to generate
    /// as actions before other limits apply.
    pub allowed_blocked_microsec: u64,
    /// The maximum fraction of blocking (microseconds) to allow as actions.
    pub max_blocking_frac: f64,
    /// The states that make up the machine.
    pub states: Vec<State>,
}

impl Machine {
    /// Create a new [`Machine`] with the given limits and states. Returns an
    /// error if the machine or any of its states are invalid.
    pub fn new(
        allowed_padding_packets: u64,
        max_padding_frac: f64,
        allowed_blocked_microsec: u64,
        max_blocking_frac: f64,
        states: Vec<State>,
    ) -> Result<Self, Error> {
        let machine = Machine {
            allowed_padding_packets,
            max_padding_frac,
            allowed_blocked_microsec,
            max_blocking_frac,
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
        let bincoder = bincode::DefaultOptions::new().with_limit(MAX_DECOMPRESSED_SIZE as u64);
        let encoded = bincoder.serialize(&self).unwrap();
        let mut e = ZlibEncoder::new(Vec::new(), Compression::best());
        e.write_all(encoded.as_slice()).unwrap();
        let s = BASE64_STANDARD.encode(e.finish().unwrap());
        // version as first 2 characters, then base64 compressed bincoded
        format!("{:02}{}", VERSION, s)
    }

    /// Validates that the machine is in a valid state (machines that are
    /// mutated may get into an invalid state).
    pub fn validate(&self) -> Result<(), Error> {
        // sane limits
        if self.max_padding_frac < 0.0 || self.max_padding_frac > 1.0 {
            return Err(Error::Machine(format!(
                "max_padding_frac has to be [0.0, 1.0], got {}",
                self.max_padding_frac
            )));
        }
        if self.max_blocking_frac < 0.0 || self.max_blocking_frac > 1.0 {
            return Err(Error::Machine(format!(
                "max_blocking_frac has to be [0.0, 1.0], got {}",
                self.max_blocking_frac
            )));
        }

        // sane number of states
        let num_states = self.states.len();

        if num_states == 0 {
            Err(Error::Machine(
                "a machine must have at least one state".to_string(),
            ))?;
        }
        if num_states > STATE_MAX {
            Err(Error::Machine(format!(
                "too many states, max is {}, found {}",
                STATE_MAX, num_states
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
        if version != format!("{:02}", VERSION) {
            Err(Error::Machine(format!(
                "version mismatch, expected {}, got {}",
                VERSION, version
            )))?;
        }
        let s = &s[2..];

        // base64 decoding has a fixed ratio of ~4:3
        let compressed = BASE64_STANDARD.decode(s.as_bytes());
        if compressed.is_err() {
            Err(Error::Machine("base64 decoding failed".to_string()))?;
        }
        let compressed = compressed.unwrap();
        // decompress, but scared of exceeding memory limits / zlib bombs
        let mut decoder = ZlibDecoder::new(compressed.as_slice());
        let mut buf = vec![0; MAX_DECOMPRESSED_SIZE];
        let bytes_read = decoder
            .read(&mut buf)
            .map_err(|e| Error::Machine(e.to_string()))?;

        // With binencode, note that "The size of the encoded object will be the
        // same or smaller than the size that the object takes up in memory in a
        // running Rust program".
        let bincoder = bincode::DefaultOptions::new().with_limit(MAX_DECOMPRESSED_SIZE as u64);
        let r = bincoder.deserialize(&buf[..bytes_read]);

        // ensure that the machine is valid
        let m: Machine = r.map_err(|e| Error::Machine(e.to_string()))?;
        m.validate()?;
        Ok(m)
    }
}

impl fmt::Display for Machine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Machine {}\n\
            - allowed_padding_packets: {}\n\
            - max_padding_frac: {}\n\
            - allowed_blocked_microsec: {}\n\
            - max_blocking_frac: {}\n\
            States:\n\
            {}",
            self.name(),
            self.allowed_padding_packets,
            self.max_padding_frac,
            self.allowed_blocked_microsec,
            self.max_blocking_frac,
            self.states
                .iter()
                .map(|s| format!("{}", s))
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
                 Event::PaddingSent => vec![Trans(0, 1.0)],
             _ => vec![],
        });

        // machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0]).unwrap();

        // name generation should be deterministic
        assert_eq!(m.name(), m.name());
    }

    #[test]
    fn validate_machine_limits() {
        let s0 = State::new(enum_map! {
               Event::PaddingSent => vec![Trans(0, 1.0)],
             _ => vec![],
        });

        let mut m = Machine::new(1000, 1.0, 0, 0.0, vec![s0]).unwrap();

        // max padding frac
        m.max_padding_frac = -0.1;
        let r = m.validate();
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        m.max_padding_frac = 1.1;
        let r = m.validate();
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        m.max_padding_frac = 0.5;
        let r = m.validate();
        assert!(r.is_ok());

        // max blocking frac
        m.max_blocking_frac = -0.1;
        let r = m.validate();
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        m.max_blocking_frac = 1.1;
        let r = m.validate();
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        m.max_blocking_frac = 0.5;
        let r = m.validate();
        assert!(r.is_ok());
    }

    #[test]
    fn validate_machine_num_states() {
        // invalid machine lacking state
        let r = Machine::new(1000, 1.0, 0, 0.0, vec![]);

        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());
    }

    #[test]
    fn validate_machine_states() {
        // out of bounds index
        let s0 = State::new(enum_map! {
                 Event::PaddingSent => vec![Trans(1, 1.0)],
             _ => vec![],
        });
        // machine with broken state
        let r = Machine::new(1000, 1.0, 0, 0.0, vec![s0]);
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        // valid states should be allowed
        let s0 = State::new(enum_map! {
                 Event::PaddingSent => vec![Trans(0, 0.8)],
             _ => vec![],
        });
        let r = Machine::new(1000, 1.0, 0, 0.0, vec![s0]);
        assert!(r.is_ok());
    }
}
