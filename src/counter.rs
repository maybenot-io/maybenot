//! Counters as part of a [`Machine`](crate::machine).

use serde::{Deserialize, Serialize};

use crate::constants::MAX_SAMPLED_COUNTER_VALUE;
use crate::*;
use std::fmt;

/// The two counters that are part of each [`Machine`](crate::machine).
#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum Counter {
    A,
    B,
}

/// The operation applied to a [`Machine`](crate::machine)'s counters upon
/// transition to a [`State`](crate::state).
#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum Operation {
    /// Increment the counter by the sampled value.
    Increment,
    /// Decrement the counter by the sampled value.
    Decrement,
    /// Replace the current value of the counter with the sampled one.
    Set,
}

/// A specification of how a [`Machine`](crate::machine)'s counters should be
/// updated when transitioning to a [`State`](crate::machine). Consists of a
/// [`Counter`], an [`Operation`] to be applied to the counter, and a
/// distribution to sample values from when updating the counter.
#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CounterUpdate {
    /// Which counter to update.
    pub counter: Counter,
    /// The operation to apply to the counter upon a state transition.
    pub operation: Operation,
    /// If set, sample the value to update the counter with from a
    /// distribution. If not set, value is 1.
    pub value: Option<Dist>,
}

impl fmt::Display for CounterUpdate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#?}", self)
    }
}

impl CounterUpdate {
    /// Sample a value to update the counter with.
    pub fn sample_value(&self) -> u64 {
        match self.value {
            Some(value) => {
                let s = value.sample() as u64;
                s.min(MAX_SAMPLED_COUNTER_VALUE)
            }
            None => 1,
        }
    }

    // Validate the value dist.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(value) = self.value {
            value.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::counter::*;

    #[test]
    fn validate_counter_update() {
        // valid counter update
        let mut cu = CounterUpdate {
            counter: Counter::A,
            operation: Operation::Increment,
            value: Some(Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            }),
        };

        let r = cu.validate();
        assert!(r.is_ok());

        // counter update with invalid dist
        cu.value = Some(Dist {
            dist: DistType::Uniform {
                low: 15.0, // NOTE low > high
                high: 5.0,
            },
            start: 0.0,
            max: 0.0,
        });

        let r = cu.validate();
        assert!(r.is_err());

        // counter with empty dist
        cu.value = None;

        let r = cu.validate();
        assert!(r.is_ok());

        assert_eq!(cu.sample_value(), 1);
    }
}
