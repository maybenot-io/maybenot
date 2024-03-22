//! A state as part of a [`Machine`](crate::machine).

use crate::action::*;
use crate::constants::*;
use crate::counter::CounterUpdate;
use crate::event::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
extern crate simple_error;

/// A state as part of a [`Machine`](crate::machine).
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct State {
    /// The action to be taken upon transition to this state.
    pub action: Option<Action>,
    /// On transition to this state, this struct will be used to determine how to
    /// update the containing machine's counters.
    pub counter_update: Option<CounterUpdate>,
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
            action: None,
            counter_update: None,
            next_state: make_next_state(t, num_states),
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "action: {:?}", self.action)?;
        write!(f, "counter update: {:?}", self.counter_update)?;

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
