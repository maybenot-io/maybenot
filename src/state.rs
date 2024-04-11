//! A state as part of a [`Machine`](crate::machine). Contains an optional
//! [`Action`] and [`CounterUpdate`] to be executed upon transition to this
//! state, and a vector of state transitions for each possible [`Event`].

use crate::action::*;
use crate::constants::{EVENT_NUM, STATE_CANCEL, STATE_END};
use crate::counter::CounterUpdate;
use crate::event::*;
use enum_map::EnumMap;
use rand::{thread_rng, Rng};
#[cfg(feature = "fast-sample")]
use rand_distr::{Distribution, WeightedAliasIndex};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Serialize;
use serde::{Deserialize, Deserializer};
use simple_error::bail;
use std::collections::HashSet;
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
#[derive(Debug, Clone, Serialize)]
pub struct State {
    /// Take an action upon transitioning to this state.
    pub action: Option<Action>,
    /// On transition to this state, update a machine counter.
    pub counter: Option<CounterUpdate>,
    /// For each possible [`Event`], a vector of state transitions.
    transitions: [Option<Vec<Trans>>; EVENT_NUM],
    #[cfg(feature = "fast-sample")]
    #[serde(skip_serializing)]
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
    choices: Vec<Option<usize>>,
}

impl State {
    /// Create a new [`State`] that transitions on the given [`Event`]s.
    ///
    /// Example:
    /// ```
    /// use maybenot::state::*;
    /// use maybenot::event::*;
    /// use enum_map::enum_map;
    /// let state = State::new(enum_map! {
    ///     Event::PaddingSent => vec![Trans(1, 1.0)],
    ///     Event::CounterZero => vec![Trans(2, 1.0)],
    ///     _ => vec![],
    /// });
    /// ```
    /// This creates a state that transitions to state 1 on
    /// [`Event::PaddingSent`] and to state 2 on [`Event::CounterZero`], both
    /// with 100% probability. All other events will not cause a transition.
    /// Note that state indexes are 0-based and determined by the order in which
    /// states are added to the [`Machine`](crate::machine).
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
    /// distributions, if set, are valid. Note that num_states is the number of
    /// states in the machine, not the number of states in this state's
    /// transitions. Called by [`Machine::new`](crate::machine::Machine::new).
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
            let mut seen: HashSet<usize> = HashSet::new();

            for t in transitions.iter() {
                if t.0 >= num_states && t.0 != STATE_CANCEL && t.0 != STATE_END {
                    bail!("found invalid state index {}", t.0);
                }
                if seen.contains(&t.0) {
                    bail!("found duplicate state index {}", t.0);
                }
                seen.insert(t.0);

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
                return alias.choices[alias.alias.sample(&mut rng)];
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
        let mut sum: f32 = 0.0;

        for t in vector.iter() {
            choices.push(Some(t.0));
            weights.push(t.1);
            sum += t.1;
        }

        // STATE_NOP for remaining probability up to 1.0
        if sum < 1.0 {
            choices.push(None);
            weights.push(1.0 - sum);
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

/// Deserialize a [`State`]. This is implemented manually so that the alias
/// table can be constructed from the transitions array.
impl<'de> Deserialize<'de> for State {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Action,
            Counter,
            Transitions,
        }

        struct StateVisitor;

        impl<'de> Visitor<'de> for StateVisitor {
            type Value = State;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct State")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<State, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let action = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let counter = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let transitions: [Option<Vec<Trans>>; EVENT_NUM] = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                #[cfg(feature = "fast-sample")]
                let alias_index = make_alias_index(&transitions);

                Ok(State {
                    action,
                    counter,
                    transitions,
                    #[cfg(feature = "fast-sample")]
                    alias_index,
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<State, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut action = None;
                let mut counter = None;
                let mut transitions = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Action => {
                            if action.is_some() {
                                return Err(de::Error::duplicate_field("action"));
                            }
                            action = Some(map.next_value()?);
                        }
                        Field::Counter => {
                            if counter.is_some() {
                                return Err(de::Error::duplicate_field("counter"));
                            }
                            counter = Some(map.next_value()?);
                        }
                        Field::Transitions => {
                            if transitions.is_some() {
                                return Err(de::Error::duplicate_field("transitions"));
                            }
                            transitions = Some(map.next_value()?);
                        }
                    }
                }
                let action = action.ok_or_else(|| de::Error::missing_field("action"))?;
                let counter = counter.ok_or_else(|| de::Error::missing_field("counter"))?;
                let transitions: [Option<Vec<Trans>>; EVENT_NUM] =
                    transitions.ok_or_else(|| de::Error::missing_field("transitions"))?;

                #[cfg(feature = "fast-sample")]
                let alias_index = make_alias_index(&transitions);

                Ok(State {
                    action,
                    counter,
                    transitions,
                    #[cfg(feature = "fast-sample")]
                    alias_index,
                })
            }
        }

        const FIELDS: &[&str] = &["action", "counter", "transitions"];
        deserializer.deserialize_struct("State", FIELDS, StateVisitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::counter::{Counter, CounterUpdate, Operation};
    use crate::dist::{Dist, DistType};
    use crate::event::Event;
    use crate::state::*;
    use enum_map::enum_map;

    #[test]
    fn serialization() {
        // Ensure that sampling works after deserialization
        // Note: enable fast-sample to verify alias table is reconstructed
        let s0 = State::new(enum_map! {
                 Event::PaddingSent => vec![Trans(6, 1.0)],
             _ => vec![],
        });

        let s0 = bincode::serialize(&s0).unwrap();
        let s0: State = bincode::deserialize(&s0).unwrap();

        assert_eq!(s0.sample_state(Event::PaddingSent), Some(6));
    }

    #[test]
    fn validate_state_transitions() {
        // assume a machine with two states
        let num_states = 2;

        // out of bounds index
        let s = State::new(enum_map! {
                 Event::PaddingSent => vec![Trans(num_states, 1.0)],
             _ => vec![],
        });
        let r = s.validate(num_states);
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        // try setting one probability too high
        let s = State::new(enum_map! {
                 Event::PaddingSent => vec![Trans(0, 1.1)],
             _ => vec![],
        });
        let r = s.validate(num_states);
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        // try setting total probability too high
        let s = State::new(enum_map! {
                 Event::PaddingSent => vec![Trans(0, 0.5), Trans(1, 0.6)],
             _ => vec![],
        });
        let r = s.validate(num_states);
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        // try specifying duplicate transitions
        let s = State::new(enum_map! {
                 Event::PaddingSent => vec![Trans(0, 0.4), Trans(0, 0.6)],
             _ => vec![],
        });
        let r = s.validate(num_states);
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());

        // valid transitions should be allowed
        let s = State::new(enum_map! {
                 Event::PaddingSent => vec![Trans(0, 0.4), Trans(STATE_CANCEL, 0.3), Trans(STATE_END, 0.3)],
             _ => vec![],
        });
        let r = s.validate(num_states);
        assert!(r.is_ok());
    }

    #[test]
    fn validate_state_nop_transition() {
        // Note: enable fast-sample to test the alias table.
        // Ensure that STATE_NOP can be sampled. This is an invalid state but
        // doesn't matter for the behavior we want to invoke in sample_state()
        // and make_alias_index(). The other option would be a probabilistic
        // test since the thread rng can't be seeded...
        let mut s = State::new(enum_map! { _ => vec![] });
        s.transitions[Event::PaddingSent.to_usize()] = Some(vec![]);

        #[cfg(feature = "fast-sample")]
        if cfg!(feature = "fast-sample") {
            s.alias_index = make_alias_index(&s.transitions);
        }

        assert_eq!(s.sample_state(Event::PaddingSent), None);
    }

    #[test]
    fn validate_state_action() {
        // assume a machine with one state
        let num_states = 1;

        // valid actions should be allowed
        let mut s = State::new(enum_map! {
                 Event::PaddingSent => vec![Trans(0, 1.0)],
             _ => vec![],
        });
        s.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        let r = s.validate(num_states);
        println!("{:?}", r.as_ref().err());
        assert!(r.is_ok());

        // invalid action in state
        s.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 2.0, // NOTE low > high
                    high: 1.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        let r = s.validate(num_states);
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());
    }

    #[test]
    fn validate_state_counter() {
        // assume a machine with one state
        let num_states = 1;

        // valid counter updates should be allowed
        let mut s = State::new(enum_map! {
                 Event::PaddingSent => vec![Trans(0, 1.0)],
             _ => vec![],
        });
        s.counter = Some(CounterUpdate {
            counter: Counter::A,
            operation: Operation::Increment,
            value: None,
        });

        let r = s.validate(num_states);
        println!("{:?}", r.as_ref().err());
        assert!(r.is_ok());

        // invalid counter update in state
        s.counter = Some(CounterUpdate {
            counter: Counter::B,
            operation: Operation::Set,
            value: Some(Dist {
                dist: DistType::Uniform {
                    low: 2.0, // NOTE low > high
                    high: 1.0,
                },
                start: 0.0,
                max: 0.0,
            }),
        });

        let r = s.validate(num_states);
        println!("{:?}", r.as_ref().err());
        assert!(r.is_err());
    }
}
