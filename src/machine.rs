//! A machine determines when to inject and/or block outgoing traffic. Consists
//! of one or more [`State`] structs.

use crate::action::*;
use crate::constants::*;
use crate::state::*;
use serde::{Deserialize, Serialize};
use simple_error::bail;
use std::error::Error;
extern crate simple_error;
use hex::encode;
use ring::digest::{Context, SHA256};

/// A probabilistic state machine (Rabin automaton) consisting of one or more
/// [`State`] that determine when to inject and/or block outgoing traffic.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Machine {
    /// The number of bytes of padding a machine is allowed to generate as
    /// actions before other limits apply.
    pub allowed_padding_bytes: u64,
    /// The maximum fraction of padding bytes to allow as actions.
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
        context.update(&self.allowed_padding_bytes.to_le_bytes());
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
        if self.states.len() > STATEMAX {
            bail!(
                "too many states, max is {}, found {}",
                STATEMAX,
                self.states.len()
            )
        }

        // check each state
        for (index, state) in self.states.iter().enumerate() {
            // validate counter actions
            if let Action::UpdateCounter { counter, .. } = &state.action {
                if counter >= &COUNTERSPERMACHINE {
                    bail!(
                        "found UpdateCounter w/ id {}, has to be [0, {})",
                        counter,
                        COUNTERSPERMACHINE
                    )
                }
            }

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
                if p_total <= 0.0 || p_total >= 1.0005 {
                    // 1.0005 due to rounding
                    bail!(
                        "found invalid total probability vector {} at index {}, must be (0.0, 1.0]",
                        p_total,
                        index
                    )
                }
            }

            // validate distribution parameters
            state.action_dist.validate()?;
            state.limit_dist.validate()?;
            state.timeout_dist.validate()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
        s0.timeout_dist = Dist {
            dist: DistType::Uniform,
            param1: 10.0,
            param2: 10.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action_dist = Dist {
            dist: DistType::Uniform,
            param1: 10.0,
            param2: 10.0,
            start: 0.0,
            max: 0.0,
        };

        // machine with broken state
        let m = Machine {
            allowed_padding_bytes: 1000 * 1024,
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

        let m = Machine {
            allowed_padding_bytes: 1000 * 1024,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0.clone()],
        };

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
            allowed_padding_bytes: 1000 * 1024,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0.clone()],
        };

        let r = m.validate();
        println!("{:?}", r.as_ref().err());
        assert!(r.is_ok());

        // counter update action with invalid id
        s0.action = Action::UpdateCounter {
            counter: COUNTERSPERMACHINE,
            decrement: false,
        };

        let m = Machine {
            allowed_padding_bytes: 1000 * 1024,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0.clone()],
        };

        let r = m.validate();
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        // repair state
        s0.action = Action::InjectPadding {
            bypass: false,
            replace: false,
        };

        // invalid machine lacking state
        let m = Machine {
            allowed_padding_bytes: 1000 * 1024,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![],
        };
        let r = m.validate();
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        // bad padding and blocking fractions
        let mut m = Machine {
            allowed_padding_bytes: 1000 * 1024,
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
