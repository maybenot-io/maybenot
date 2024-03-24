//! A machine determines when to inject and/or block outgoing traffic. Consists
//! of one or more [`State`] structs.

use crate::constants::*;
use crate::state::*;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use simple_error::bail;
use std::error::Error;
use std::str::FromStr;
extern crate simple_error;
use base64::prelude::*;
use hex::encode;
use ring::digest::{Context, SHA256};
use std::io::prelude::*;

/// A probabilistic state machine (Rabin automaton) consisting of one or more
/// [`State`] that determine when to inject and/or block outgoing traffic.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
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
    /// Get a unique and deterministic string that represents the machine. The
    /// string is 32 characters long, hex-encoded.
    pub fn name(&self) -> String {
        let mut context = Context::new(&SHA256);
        context.update(&self.allowed_padding_packets.to_le_bytes());
        context.update(&self.max_padding_frac.to_le_bytes());
        context.update(&self.allowed_blocked_microsec.to_le_bytes());
        context.update(&self.max_blocking_frac.to_le_bytes());

        // We can't just do a json serialization here, because State uses a
        // HashMap, which doesn't guarantee a stable order. Therefore, we add a
        // deterministic print (which is not pretty, but works) for each state,
        // then hash that.
        for state in &self.states {
            context.update(format!("{:?}", state).as_bytes());
        }

        let d = context.finish();
        let s = encode(d);
        s[0..32].to_string()
    }

    pub fn serialize(&self) -> String {
        let encoded = bincode::serialize(&self).unwrap();
        let mut e = ZlibEncoder::new(Vec::new(), Compression::best());
        e.write_all(encoded.as_slice()).unwrap();
        let s = BASE64_STANDARD.encode(e.finish().unwrap());
        // version as first 2 characters, then base64 compressed bincoded
        format!("{:02}{}", VERSION, s)
    }

    /// Validates that the machine is in a valid state (machines that are
    /// mutated may get into an invalid state).
    pub fn validate(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // sane limits
        if self.max_padding_frac < 0.0 || self.max_padding_frac > 1.0 {
            bail!(
                "max_padding_frac has to be [0.0, 1.0], got {}",
                self.max_padding_frac
            )
        }
        if self.max_blocking_frac < 0.0 || self.max_blocking_frac > 1.0 {
            bail!(
                "max_blocking_frac has to be [0.0, 1.0], got {}",
                self.max_blocking_frac
            )
        }

        // sane number of states
        if self.states.is_empty() {
            bail!("a machine must have at least one state")
        }
        if self.states.len() > STATE_MAX {
            bail!(
                "too many states, max is {}, found {}",
                STATE_MAX,
                self.states.len()
            )
        }

        // check each state
        for (index, state) in self.states.iter().enumerate() {
            // validate transitions
            for next in &state.next_state {
                if next.1.len() != self.states.len() + 2 {
                    bail!(
                        "found too small next_state vector, expected {}, got {}",
                        self.states.len() + 2,
                        next.1.len()
                    )
                }

                let mut p_total = 0.0;
                for p in next.1 {
                    if !(&0.0..=&1.0).contains(&p) {
                        bail!("found probability {}, has to be [0.0, 1.0]", &p)
                    }
                    p_total += p;
                }

                // we are (0.0, 1.0] here, because:
                // - if pTotal <= 0.0, then we shouldn't have an entry in NextState
                // - pTotal < 1.0 is OK, to support a "nop" transition (self
                // transition has implications in the framework, i.e., involving
                // limits on padding sent in the state)
                if p_total <= 0.0 || p_total > 1.0 {
                    bail!(
                        "found invalid total probability vector {} at index {}, must be (0.0, 1.0]",
                        p_total,
                        index
                    )
                }
            }

            // validate distribution parameters
            // check that required distributions are present
            if let Some(action) = &state.action {
                action.validate()?;
            }
            if let Some(counter_update) = &state.counter_update {
                counter_update.validate()?;
            }
        }

        Ok(())
    }
}

/// from a serialized string, attempt to create a machine
impl FromStr for Machine {
    type Err = Box<dyn Error + Send + Sync>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // version as first 2 characters, then base64
        if s.len() < 3 {
            bail!("string too short")
        }
        let version = &s[0..2];
        if version != format!("{:02}", VERSION) {
            bail!("version mismatch, expected {}, got {}", VERSION, version)
        }
        let s = &s[2..];

        // base64 decoding has a fixed ratio of ~4:3
        let compressed = BASE64_STANDARD.decode(s.as_bytes()).unwrap();
        // decompress, but scared of exceeding memory limits / zlib bombs
        let mut decoder = ZlibDecoder::new(compressed.as_slice());
        let mut buf = vec![0; MAX_DECOMPRESSED_SIZE];
        let bytes_read = decoder.read(&mut buf)?;
        let m: Machine = bincode::deserialize(&buf[..bytes_read]).unwrap();
        m.validate()?;
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use crate::action::*;
    use crate::counter::*;
    use crate::dist::*;
    use crate::event::Event;
    use crate::machine::*;
    use std::collections::HashMap;

    #[test]
    fn validate_machine() {
        let num_states = 1;

        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        // invalid state transition
        e.insert(1, 1.0);
        t.insert(Event::PaddingSent, e);

        let mut s0 = State::new(t, num_states);
        s0.action = Some(Action::InjectPadding {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform,
                param1: 10.0,
                param2: 10.0,
                start: 0.0,
                max: 0.0,
            },
            limit_dist: Dist::new(),
        });

        // machine with broken state
        let m = Machine {
            allowed_padding_packets: 1000,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0.clone()],
        };
        // while we get an error here, as intended, the error is not the
        // expected one, because make_next_state() actually ignores the
        // transition to the non-existing state as it makes the probability
        // matrix based on num_states
        let r = m.validate();
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        // try setting total probability too high
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.1);
        t.insert(Event::PaddingSent, e);

        s0.next_state = make_next_state(t, num_states);

        // machine with broken state
        let m = Machine {
            allowed_padding_packets: 1000,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0.clone()],
        };
        // we get the expected error here
        let r = m.validate();
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        // repair state
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        t.insert(Event::PaddingSent, e);

        s0.next_state = make_next_state(t, num_states);

        let m = Machine {
            allowed_padding_packets: 1000,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0.clone()],
        };

        let r = m.validate();
        println!("{:?}", r.as_ref().err());
        assert!(r.is_ok());

        // invalid machine lacking state
        let m = Machine {
            allowed_padding_packets: 1000,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![],
        };
        let r = m.validate();
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        // invalid action in state
        s0.action = Some(Action::InjectPadding {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform,
                param1: 2.0, // NOTE param1 > param2
                param2: 1.0,
                start: 0.0,
                max: 0.0,
            },
            limit_dist: Dist::new(),
        });

        // machine with broken state
        let m = Machine {
            allowed_padding_packets: 1000,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0.clone()],
        };
        let r = m.validate();
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        // repair state
        s0.action = None;

        // invalid counter update in state
        s0.counter_update = Some(CounterUpdate {
            counter: Counter::CounterA,
            operation: CounterOperation::Set,
            value_dist: Dist::new(), // NOTE DistType::None
        });

        // machine with broken state
        let m = Machine {
            allowed_padding_packets: 1000,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0.clone()],
        };
        let r = m.validate();
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        // repair state
        s0.counter_update = None;

        // bad padding and blocking fractions
        let mut m = Machine {
            allowed_padding_packets: 1000,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0.clone()],
        };

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
        println!("{:?}", r.as_ref().err());
        assert!(r.is_ok());

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
        println!("{:?}", r.as_ref().err());
        assert!(r.is_ok());

        // name generation should be deterministic
        assert_eq!(m.name(), m.name());
    }
}
