//! A state as part of a [`Machine`](crate::machine).

use crate::action::*;
use crate::constants::*;
use crate::dist::*;
use crate::event::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
extern crate simple_error;

/// A state as part of a [`Machine`](crate::machine).
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct State {
    /// On transition to this state, this distribution will be sampled for a
    /// timeout duration after which the action is triggered. This distribution
    /// is ignored for timer and counter actions.
    pub timeout_dist: Dist,
    /// A distribution from which a value for the action is sampled. If
    /// padding, this is the size of the padding packet; if blocking, it is
    /// the duration of the blocking. For timer and counter actions, it is the
    /// value to set the timer to or add/subtract from the counter.
    pub action_dist: Dist,
    /// A distribution from which a limit on the number of actions allowed on
    /// repeated transitions to the same state is sampled.
    pub limit_dist: Dist,
    /// The action to be taken upon transition to this state.
    pub action: Action,
    /// A flag that specifies if the sampled limit should also be decremented on
    /// non-padding (normal) traffic sent.
    pub limit_includes_nonpadding: bool,
    /// A map of all possible events to associated probability vectors. This is
    /// a transition matrix, so the length of the probability vector is a
    /// function of the total number of states in a machine. The structure of
    /// the map is created by [`make_next_state()`].
    pub next_state: HashMap<Event, Vec<f64>>,
}

impl State {
    /// Create a new [`State`] with the given map of transitions ([`Event`] to probability vector)
    /// and number of total states in the [`Machine`](crate::machine).
    pub fn new(t: HashMap<Event, HashMap<usize, f64>>, num_states: usize) -> Self {
        State {
            timeout_dist: Dist::new(),
            action_dist: Dist::new(),
            limit_dist: Dist::new(),
            action: Action::InjectPadding {
                bypass: false,
                replace: false,
            },
            limit_includes_nonpadding: false,
            next_state: make_next_state(t, num_states),
        }
    }

    /// Sample a timeout.
    pub fn sample_timeout(&self) -> f64 {
        self.timeout_dist.sample().min(MAX_SAMPLED_TIMEOUT)
    }

    /// Sample a limit.
    pub fn sample_limit(&self) -> u64 {
        if self.limit_dist.dist == DistType::None {
            return STATE_LIMIT_MAX;
        }
        let s = self.limit_dist.sample().round() as u64;
        s.min(STATE_LIMIT_MAX)
    }

    /// Sample a blocking duration for a blocking action.
    pub fn sample_block(&self) -> f64 {
        self.action_dist.sample().min(MAX_SAMPLED_BLOCK)
    }

    /// Sample a value for a counter update action.
    pub fn sample_counter_value(&self) -> u64 {
        let s = self.action_dist.sample().round() as u64;
        s.min(MAX_SAMPLED_COUNTER_VALUE)
    }

    /// Sample a duration for a timer update action.
    pub fn sample_timer_duration(&self) -> f64 {
        self.action_dist.sample().min(MAX_SAMPLED_TIMER_DURATION)
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "timeout_dist: {}", self.timeout_dist)?;
        write!(f, "action_dist: {}", self.action_dist)?;
        write!(f, "limit_dist: {}", self.limit_dist)?;
        write!(f, "action: {:?}", self.action)?;
        write!(
            f,
            "limit_includes_nonpadding: {}",
            self.limit_includes_nonpadding
        )?;

        // next_state: iterate over every possible event in order (because
        // HashMap is not stable), if found, print event and vector
        write!(f, "next_state: ")?;
        for event in Event::iter() {
            if self.next_state.contains_key(event) {
                write!(f, "{:?}: ", event)?;
                write!(f, "{:?}", self.next_state.get(event).unwrap())?;
            }
        }

        Ok(())
    }
}
/// A helper used to construct [`State::next_state`] based on a map of
/// transitions ([`Event`] to probability vector) and the total number of states
/// in the [`Machine`](crate::machine).
pub fn make_next_state(
    t: HashMap<Event, HashMap<usize, f64>>,
    num_states: usize,
) -> HashMap<Event, Vec<f64>> {
    let mut r = HashMap::new();
    for event in Event::iter() {
        if !t.contains_key(event) {
            continue;
        }
        let probmap = t.get(event).unwrap();
        let mut res: Vec<f64> = vec![];

        // go over the set states
        for i in 0..num_states {
            if probmap.contains_key(&i) {
                res.push(*probmap.get(&i).unwrap());
            } else {
                res.push(0.0);
            }
        }

        // set StateCancel and StateEnd
        if probmap.contains_key(&STATE_CANCEL) {
            res.push(*probmap.get(&STATE_CANCEL).unwrap());
        } else {
            res.push(0.0);
        }
        if probmap.contains_key(&STATE_END) {
            res.push(*probmap.get(&STATE_END).unwrap());
        } else {
            res.push(0.0);
        }

        r.insert(*event, res);
    }

    r
}
