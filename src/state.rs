//! A state as part of a [`Machine`](crate::machine).

use crate::action::*;
use crate::constants::*;
use crate::counter::CounterUpdate;
use crate::event::*;
use enum_map::{enum_map, EnumMap};
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde_with::DeserializeAs;
use serde_with::SerializeAs;
use simple_error::bail;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use vose_alias::VoseAlias;
extern crate simple_error;

/// A state index and probability for a transition.
#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Transition {
    /// The index of the state to transition to. Must be less than the number
    /// of states in the corresponding machine, or STATE_CANCEL or STATE_END.
    pub state: usize,
    /// The probability of taking this transition, must be (0.0, 1.0].
    pub probability: f32,
}

impl fmt::Display for Transition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {:.4}", self.state, self.probability)
    }
}

impl Transition {
    /// Validate that this state transition specifies a valid state and that
    /// its probability is in the range (0.0, 1.0].
    pub fn validate(&self, num_states: usize) -> Result<(), Box<dyn Error + Send + Sync>> {
        if self.state >= num_states && self.state != STATE_CANCEL && self.state != STATE_END {
            bail!("found invalid state index {}", &self.state);
        }

        if self.probability <= 0.0 || self.probability > 1.0 {
            bail!(
                "found probability {}, has to be (0.0, 1.0]",
                &self.probability
            );
        }

        Ok(())
    }
}

/// A state as part of a [`Machine`](crate::machine).
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct State {
    /// The action to be taken upon transition to this state.
    pub action: Option<Action>,
    /// On transition to this state, this struct will be used to determine how to
    /// update the containing machine's counters.
    pub counter: Option<CounterUpdate>,
    /// A map of [`Event`] to state transition vector specifying the possible
    /// transitions out of this state.
    transitions: HashMap<Event, Vec<Transition>>,
}

/// A wrapper for [`State`] to support the internal alias table.
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct StateWrapper {
    /// The state that is wrapped by this struct.
    pub(crate) state: State,
    /// A data structure that allows the Vose-Alias method to be used for
    /// sampling the next state. Probabilities sum to 1.0: any remaining
    /// probabilities up to 1.0 are filled with STATE_NOP.
    next_state: EnumMap<Event, Option<VoseAlias<usize>>>,
}

impl State {
    /// Create a new [`State`] with the given map of transitions ([`Event`] to
    /// state transition vector) and number of total states in the
    /// [`Machine`](crate::machine).
    pub fn new(t: EnumMap<Event, Vec<Transition>>) -> Self {
        let mut transitions: HashMap<Event, Vec<Transition>> = HashMap::new();
        for event in Event::iter() {
            if !t[*event].is_empty() {
                transitions.insert(*event, t[*event].clone());
            }
        }

        State {
            transitions,
            action: None,
            counter: None,
        }
    }

    /// Validate that this state has acceptable individual and total transition
    /// probabilities, all required distributions are present, and distribution
    /// parameters are permissible.
    pub fn validate(&self, num_states: usize) -> Result<(), Box<dyn Error + Send + Sync>> {
        // validate transition probabilities
        for event in Event::iter() {
            if !self.transitions.contains_key(event) || self.transitions[event].is_empty() {
                continue;
            }
            let probmap = &self.transitions[event];

            let mut probability_sum: f32 = 0.0;

            // go over the set states
            for trans in probmap {
                trans.validate(num_states)?;
                probability_sum += trans.probability;
            }

            if probability_sum <= 0.0 || probability_sum > 1.0 {
                bail!(
                    "found invalid total probability vector {} for {}, must be (0.0, 1.0]",
                    &probability_sum,
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

    /// Construct an alias table based on a map of transitions
    /// ([`Event`] to [`Transition`] vector) and the total number of
    /// states in the [`Machine`](crate::machine). Validate state before
    /// calling this method.
    fn make_next_state(&self) -> EnumMap<Event, Option<VoseAlias<usize>>> {
        let mut r: EnumMap<Event, Option<VoseAlias<usize>>> = enum_map! { _ => None };
        for event in Event::iter() {
            if !self.transitions.contains_key(event) || self.transitions[event].is_empty() {
                continue;
            }
            let probmap = &self.transitions[event];

            let mut element_vector: Vec<usize> = vec![];
            let mut probability_vector: Vec<f32> = vec![];
            let mut probability_sum: f32 = 0.0;

            // go over the set states
            for trans in probmap {
                element_vector.push(trans.state);
                probability_vector.push(trans.probability);
                probability_sum += trans.probability;
            }

            if probability_sum < 1.0 {
                element_vector.push(STATE_NOP);
                probability_vector.push(1.0 - probability_sum);
            }

            r[*event] = Some(VoseAlias::new(element_vector, probability_vector));
        }

        r
    }
}

impl StateWrapper {
    pub(crate) fn new(
        state: State,
        num_states: usize,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        state.validate(num_states)?;
        let next_state = state.make_next_state();

        Ok(StateWrapper { state, next_state })
    }

    /// Sample a state to transition to given an [`Event`].
    pub(crate) fn sample_state(&self, event: Event) -> Option<usize> {
        let next = &self.next_state[event];
        if let Some(alias_table) = next {
            return Some(alias_table.sample());
        };
        None
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(action) = self.action {
            write!(f, "action: {}\n", action)?;
        } else {
            write!(f, "action: None\n")?;
        }
        if let Some(counter) = self.counter {
            write!(f, "counter: {}\n", counter)?;
        } else {
            write!(f, "counter: None\n")?;
        }

        // next_state: iterate over every possible event in order (because
        // HashMap is not stable), if found, print event and vector
        write!(f, "next_state: ")?;
        for event in Event::iter() {
            if self.transitions.contains_key(event) && !self.transitions[event].is_empty() {
                write!(f, "{}: ", event)?;
                for trans in self.transitions[event].iter() {
                    write!(f, " * {}", trans)?;
                }
                write!(f, "")?;
            }
        }

        Ok(())
    }
}

impl SerializeAs<StateWrapper> for State {
    fn serialize_as<S>(value: &StateWrapper, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        State::serialize(&value.state, serializer)
    }
}

impl<'de> DeserializeAs<'de, StateWrapper> for State {
    fn deserialize_as<D>(deserializer: D) -> Result<StateWrapper, D::Error>
    where
        D: Deserializer<'de>,
    {
        let r = StateWrapper::new(State::deserialize(deserializer)?, STATE_MAX);

        match r {
            Ok(val) => Ok(val),
            r => Err(<D::Error as serde::de::Error>::custom(format!(
                "failed to parse state: {:?}",
                r.as_ref().err()
            ))),
        }
    }
}
