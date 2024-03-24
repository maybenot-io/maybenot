//! Counters as part of a [`Machine`](crate::machine).

use serde::{Deserialize, Serialize};
use simple_error::bail;

use crate::constants::*;
use crate::dist::*;
use std::error::Error;

/// The two counters that are part of each [`Machine`](crate::machine).
#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum Counter {
    CounterA,
    CounterB,
}

/// The operation applied to a [`Machine`](crate::machine)'s counters upon
/// transition to a [`State`](crate::state).
#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum CounterOperation {
    /// Increment the counter by the sampled value.
    Increment,
    /// Decrement the counter by the sampled value.
    Decrement,
    /// Replace the current value of the counter with the sampled one.
    Set,
}

/// A specification of how a [`Machine`](crate::machine)'s counters should be
/// updated when transitioning to a [`State`](crate::machine). Consists of a
/// [`Counter`], a [`CounterOperation`] to be applied to the counter, and a
/// distribution to sample values from when updating the counter.
#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CounterUpdate {
    /// Which counter to update.
    pub counter: Counter,
    /// The operation to apply to the counter upon a state transition.
    pub operation: CounterOperation,
    /// A distribution from which a value is sampled to update the counter.
    pub value_dist: Dist,
}

impl CounterUpdate {
    /// Sample a value to update the counter with.
    pub fn sample_value(&self) -> u64 {
        let s = self.value_dist.sample() as u64;
        s.min(MAX_SAMPLED_COUNTER_VALUE)
    }

    // Validate the value dist and ensure that it is not DistType::None.
    pub fn validate(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.value_dist.validate()?;
        if self.value_dist.dist == DistType::None {
            bail!("must specify a value dist for CounterUpdate");
        }
        Ok(())
    }
}
