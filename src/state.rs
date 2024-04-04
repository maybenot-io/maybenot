//! A state as part of a [`Machine`](crate::machine).

use crate::action::*;
use crate::constants::{EVENT_NUM, STATE_CANCEL, STATE_END};
use crate::counter::CounterUpdate;
use crate::event::*;
use enum_map::EnumMap;
use rand::{thread_rng, Rng};
#[cfg(feature = "fast-sample")]
use rand_distr::{Distribution, WeightedAliasIndex};
use serde::Deserialize;
use serde::Serialize;
use simple_error::bail;
use std::error::Error;
use std::fmt;
extern crate simple_error;

/// A state index and probability for a transition.
#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Trans(pub usize, pub f32);

impl fmt::Display for Trans {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}
/// A state as part of a [`Machine`](crate::machine).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    /// The action to be taken upon transition to this state.
    pub action: Option<Action>,
    /// On transition to this state, this struct will be used to determine how to
    /// update the containing machine's counters.
    pub counter: Option<CounterUpdate>,
    /// A map of [`Event`] to state transition vector specifying the possible
    /// transitions out of this state.
    transitions: [Option<Vec<Trans>>; EVENT_NUM],
    #[cfg(feature = "fast-sample")]
    #[serde(skip_serializing, skip_deserializing)]
    /// Alias method for fast sampling of transitions if feature fast-sample is
    /// enabled: trades increased memory usage for sampling speed.
    alias_index: [Option<AliasIndex>; EVENT_NUM],
}

#[cfg(feature = "fast-sample")]
#[derive(Debug, Clone)]
/// Alias method for fast sampling of transitions at the cost of memory.
struct AliasIndex {
    /// The alias method for fast sampling.
    alias: WeightedAliasIndex<f32>,
    /// The state index choices to sample from.
    choices: Vec<usize>,
}

impl State {
    /// Create a new [`State`] with the given map of transitions ([`Event`] to
    /// state transition vector) and number of total states in the
    /// [`Machine`](crate::machine).
    pub fn new(t: EnumMap<Event, Vec<Trans>>) -> Self {
        const ARRAY_NO_TRANS: std::option::Option<Vec<Trans>> = None;
        let mut transitions = [ARRAY_NO_TRANS; EVENT_NUM];
        for (event, vector) in t {
            if !vector.is_empty() {
                transitions[event.to_usize()] = Some(vector);
            }
        }

        #[cfg(feature = "fast-sample")]
        let alias_index = make_alias_index(&transitions);

        State {
            transitions,
            action: None,
            counter: None,
            #[cfg(feature = "fast-sample")]
            alias_index,
        }
    }

    /// Validate that this state has acceptable transitions and that the
    /// distributions, if set, are valid.
    pub fn validate(&self, num_states: usize) -> Result<(), Box<dyn Error + Send + Sync>> {
        // validate transition probabilities
        for (event, transitions) in self.transitions.iter().enumerate() {
            if transitions.is_none() {
                continue;
            }
            let transitions = transitions.as_ref().unwrap();
            if self.transitions.is_empty() {
                bail!("found empty transition vector for {}", &event);
            }

            let mut sum: f32 = 0.0;
            for t in transitions.iter() {
                if t.0 >= num_states && t.0 != STATE_CANCEL && t.0 != STATE_END {
                    bail!("found invalid state index {}", t.0);
                }
                if t.1 <= 0.0 || t.1 > 1.0 {
                    bail!("found probability {}, has to be (0.0, 1.0]", t.1);
                }
                sum += t.1;
            }

            if sum <= 0.0 || sum > 1.0 {
                bail!(
                    "found invalid total probability vector {} for {}, must be (0.0, 1.0]",
                    &sum,
                    &event
                );
            }
        }

        // validate distribution parameters
        // check that required distributions are present
        if let Some(action) = &self.action {
            action.validate()?;
        }
        if let Some(counter) = &self.counter {
            counter.validate()?;
        }

        Ok(())
    }

    /// Sample a state to transition to given an [`Event`].
    pub(crate) fn sample_state(&self, event: Event) -> Option<usize> {
        let mut rng = thread_rng();

        // NOTE: redundant but needed to make rust-analyzer and cargo happy
        #[cfg(feature = "fast-sample")]
        if cfg!(feature = "fast-sample") {
            if let Some(alias) = &self.alias_index[event.to_usize()] {
                return Some(alias.choices[alias.alias.sample(&mut rng)]);
            }

            return None;
        }
        if let Some(vector) = &self.transitions[event.to_usize()] {
            let mut sum = 0.0;
            let r = rng.gen_range(0.0..1.0);
            for t in vector.iter() {
                sum += t.1;
                if r < sum {
                    return Some(t.0);
                }
            }
        }

        None
    }
}

#[cfg(feature = "fast-sample")]
fn make_alias_index(
    transitions: &[Option<Vec<Trans>>; EVENT_NUM],
) -> [Option<AliasIndex>; EVENT_NUM] {
    const ARRAY_NO_ALIAS: std::option::Option<AliasIndex> = None;
    let mut alias = [ARRAY_NO_ALIAS; EVENT_NUM];

    for (event, vector) in transitions.iter().enumerate() {
        if vector.is_none() {
            continue;
        }
        let vector = vector.as_ref().unwrap();
        let mut weights = Vec::new();
        let mut choices = Vec::new();
        for t in vector.iter() {
            choices.push(t.0);
            weights.push(t.1);
        }
        alias[event] = Some(AliasIndex {
            alias: WeightedAliasIndex::new(weights).unwrap(),
            choices,
        });
    }

    alias
}
impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(action) = self.action {
            writeln!(f, "action: {}", action)?;
        } else {
            writeln!(f, "action: None")?;
        }
        if let Some(counter) = self.counter {
            writeln!(f, "counter: {}", counter)?;
        } else {
            writeln!(f, "counter: None")?;
        }

        write!(f, "transitions: ")?;
        for event in Event::iter() {
            if let Some(vector) = &self.transitions[event.to_usize()] {
                if vector.is_empty() {
                    continue;
                }
                write!(f, "{}: ", event)?;
                for trans in vector {
                    write!(f, " * {}", trans)?;
                }
                writeln!(f)?;
            }
        }

        Ok(())
    }
}
