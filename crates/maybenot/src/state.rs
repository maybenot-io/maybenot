//! A state as part of a [`Machine`]. Contains an optional
//! [`Action`] and [`CounterUpdate`] to be executed upon transition to this
//! state, and a vector of state transitions for each possible [`Event`].

use crate::constants::*;
use crate::*;
use enum_map::Enum;
use enum_map::EnumMap;
use rand::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;

use self::action::Action;
use self::counter::CounterUpdate;
use self::event::Event;

use enum_map::enum_map;

/// A state index and probability for a transition.
#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Trans(pub usize, pub f32);

impl fmt::Display for Trans {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}

/// A state as part of a [`Machine`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    /// Take an action upon transitioning to this state.
    pub action: Option<Action>,
    /// On transition to this state, update a machine counter.
    pub counter: Option<CounterUpdate>,
    /// For each possible [`Event`], a vector of state transitions.
    transitions: [Option<Vec<Trans>>; EVENT_NUM],
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
    /// states are added to the [`Machine`].
    pub fn new(t: EnumMap<Event, Vec<Trans>>) -> Self {
        const ARRAY_NO_TRANS: std::option::Option<Vec<Trans>> = None;
        let mut transitions = [ARRAY_NO_TRANS; EVENT_NUM];
        for (event, vector) in t {
            if !vector.is_empty() {
                transitions[event.to_usize()] = Some(vector);
            }
        }

        State {
            transitions,
            action: None,
            counter: None,
        }
    }

    /// Validate that this state has acceptable transitions and that the
    /// distributions, if set, are valid. Note that num_states is the number of
    /// states in the machine, not the number of states in this state's
    /// transitions. Called by [`Machine::new`](crate::machine::Machine::new).
    pub fn validate(&self, num_states: usize) -> Result<(), Error> {
        // validate transition probabilities
        for (event, transitions) in self.transitions.iter().enumerate() {
            let Some(transitions) = transitions else {
                continue;
            };
            if self.transitions.is_empty() {
                Err(Error::Machine(format!(
                    "found empty transition vector for {}",
                    &event
                )))?;
            }

            let mut sum: f32 = 0.0;
            let mut seen: HashSet<usize> = HashSet::new();

            for t in transitions.iter() {
                if t.0 >= num_states && t.0 != STATE_END {
                    Err(Error::Machine(format!(
                        "found out-of-bounds state index {}",
                        t.0
                    )))?;
                }
                if seen.contains(&t.0) {
                    Err(Error::Machine(format!(
                        "found duplicate state index {}",
                        t.0
                    )))?;
                }
                seen.insert(t.0);

                if t.1 <= 0.0 || t.1 > 1.0 {
                    Err(Error::Machine(format!(
                        "found probability {}, has to be (0.0, 1.0]",
                        t.1
                    )))?;
                }
                sum += t.1;
            }

            if sum <= 0.0 || sum > 1.0 {
                Err(Error::Machine(format!(
                    "found invalid total probability vector {} for {}, must be (0.0, 1.0]",
                    &sum, &event
                )))?;
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
    pub fn sample_state<R: RngCore>(&self, event: Event, rng: &mut R) -> Option<usize> {
        use rand::Rng;
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

    /// Get the transitions for this state as an [`EnumMap`] of [`Event`] to
    /// vectors of [`Trans`].
    pub fn get_transitions(&self) -> EnumMap<Event, Vec<Trans>> {
        let mut map = enum_map! {_ => vec![]};
        for (event, vector) in self.transitions.iter().enumerate() {
            if let Some(vector) = vector {
                map[Event::from_usize(event)] = vector.clone();
            }
        }

        map
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
        let s0 = State::new(enum_map! {
                 Event::PaddingSent => vec![Trans(6, 1.0)],
             _ => vec![],
        });

        let s0 = bincode::serialize(&s0).unwrap();
        let s0: State = bincode::deserialize(&s0).unwrap();

        assert_eq!(
            s0.sample_state(Event::PaddingSent, &mut rand::thread_rng()),
            Some(6)
        );
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
                 Event::PaddingSent => vec![Trans(0, 0.4), Trans(STATE_END, 0.3)],
             _ => vec![],
        });
        let r = s.validate(num_states);
        assert!(r.is_ok());
    }

    #[test]
    fn validate_state_nop_transition() {
        // Ensure that STATE_NOP can be sampled. This is an invalid state but
        // doesn't matter for the behavior we want to invoke in sample_state()
        // and make_alias_index(). The other option would be a probabilistic
        // test since the thread rng can't be seeded...
        let mut s = State::new(enum_map! { _ => vec![] });
        s.transitions[Event::PaddingSent.to_usize()] = Some(vec![]);
        assert_eq!(
            s.sample_state(Event::PaddingSent, &mut rand::thread_rng()),
            None
        );
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
