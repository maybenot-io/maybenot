//! Counters as part of a [`Machine`](crate::Machine).

use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use crate::{Error, dist};
use std::fmt;

use self::dist::Dist;

/// The operation applied to one of a [`Machine`](crate::Machine)'s counters
/// upon transition to a [`State`](crate::state::State).
#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum Operation {
    /// Increment the counter.
    Increment,
    /// Decrement the counter.
    Decrement,
    /// Replace the current value of the counter.
    Set,
}

/// A specification of how one of a [`Machine`](crate::Machine)'s counters
/// should be updated when transitioning to a [`State`](crate::state::State).
/// Consists of an [`Operation`] to be applied to the counter with one of three
/// values: by default, the value 1, unless a distribution is provided or the
/// copy flag is set to true. If the copy flag is set to true, the counter will
/// be updated with the value of the other counter *prior to transitioning to
/// the state*. If a distribution is provided, the counter will be updated with
/// a value sampled from the distribution.
#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Counter {
    /// The operation to apply to the counter upon a state transition. If the
    /// distribution is not set and copy is false, the counter will be updated
    /// by 1.
    pub operation: Operation,
    /// If set, sample the value to update the counter with from a
    /// distribution.
    pub dist: Option<Dist>,
    /// If set, the counter will be updated by the other counter's value *prior
    /// to transitioning to the state*. Supersedes the `dist` field.
    pub copy: bool,
}

impl fmt::Display for Counter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:#?}")
    }
}

impl Counter {
    /// Create a new counter with an operation that modifies the counter with
    /// value 1.
    pub fn new(operation: Operation) -> Self {
        Counter {
            operation,
            dist: None,
            copy: false,
        }
    }

    /// Create a new counter with an operation and a distribution to sample the
    /// value from.
    pub fn new_dist(operation: Operation, dist: Dist) -> Self {
        Counter {
            operation,
            dist: Some(dist),
            copy: false,
        }
    }

    /// Create a new counter with an operation that copies the value of the
    /// other counter *prior to transitioning to the state*.
    pub fn new_copy(operation: Operation) -> Self {
        Counter {
            operation,
            dist: None,
            copy: true,
        }
    }

    /// Sample a value to update the counter with.
    pub fn sample_value<R: RngCore>(&self, rng: &mut R) -> u64 {
        // Maximum safe f64 value that can be converted to u64 without overflow
        const MAX_SAFE_F64_TO_U64: f64 = u64::MAX as f64;

        match self.dist {
            None => 1,
            Some(dist) => {
                let sampled = dist.sample(rng);
                if !sampled.is_finite() || sampled < 0.0 {
                    0
                } else if sampled > MAX_SAFE_F64_TO_U64 {
                    u64::MAX
                } else {
                    sampled as u64
                }
            }
        }
    }

    // Validate the value dist.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(dist) = self.dist {
            dist.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{counter::*, dist::DistType};

    #[test]
    fn validate_counter_update() {
        // valid counter update
        let mut cu = Counter::new_dist(
            Operation::Increment,
            Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            },
        );

        let r = cu.validate();
        assert!(r.is_ok());

        // counter update with invalid dist
        cu.dist = Some(Dist {
            dist: DistType::Uniform {
                low: 15.0, // NOTE low > high
                high: 5.0,
            },
            start: 0.0,
            max: 0.0,
        });

        let r = cu.validate();
        assert!(r.is_err());

        // counter with default value
        cu.dist = None;

        let r = cu.validate();
        assert!(r.is_ok());

        assert_eq!(cu.sample_value(&mut rand::rng()), 1);

        // counter with copy value
        cu.copy = true;

        let r = cu.validate();
        assert!(r.is_ok());
    }

    #[test]
    fn sample_value_overflow_protection() {
        use crate::dist::{Dist, DistType};

        // Test with distribution that can produce very large values
        let cu = Counter::new_dist(
            Operation::Increment,
            Dist {
                dist: DistType::Uniform {
                    low: f64::MAX,
                    high: f64::MAX,
                },
                start: 0.0,
                max: 0.0,
            },
        );

        let sampled = cu.sample_value(&mut rand::rng());
        assert_eq!(sampled, u64::MAX);

        // Test with distribution that can produce negative values
        let cu_negative = Counter::new_dist(
            Operation::Increment,
            Dist {
                dist: DistType::Uniform {
                    low: -1000.0,
                    high: -500.0,
                },
                start: 0.0,
                max: 0.0,
            },
        );

        let sampled_negative = cu_negative.sample_value(&mut rand::rng());
        assert_eq!(sampled_negative, 0);

        // Test with distribution that can produce NaN (create invalid Normal dist case)
        let cu_nan = Counter::new_dist(
            Operation::Increment,
            Dist {
                dist: DistType::Normal {
                    mean: f64::NAN,
                    stdev: 1.0,
                },
                start: 0.0,
                max: 0.0,
            },
        );

        let sampled_nan = cu_nan.sample_value(&mut rand::rng());
        assert_eq!(sampled_nan, 0);
    }
}
