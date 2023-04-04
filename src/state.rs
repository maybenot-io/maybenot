//! A state as part of a [`Machine`](crate::machine).

use crate::constants::*;
use crate::dist::*;
use crate::event::*;
use byteorder::ByteOrder;
use byteorder::{LittleEndian, WriteBytesExt};
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::io::Write;
extern crate simple_error;
use simple_error::bail;

/// A state as part of a [`Machine`](crate::machine).
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct State {
    /// On transition to this state, sampled for a timeout duration until the
    /// action is triggered.
    pub timeout: Dist,
    /// A sampled duration for the action.
    pub action: Dist,
    /// A flag that determines the action. If true, the action on timeout is to
    /// block. If false, the action is to inject padding.
    pub action_is_block: bool,
    /// if the action is to block, this flag determines if padding actions are
    /// allowed to bypass this block action. If the action is to pad, this flag
    /// determines if the padding packet bypasses any existing blocking (that
    /// was triggered with the bypass flag set). This might seem excessive, but
    /// we want to be able to be able to make machines that can fail closed
    /// (never bypass blocking) while being able to make machines that can
    /// bypass some kinds of blocking is essential for constant-rate defenses.
    pub bypass: bool,
    /// If the action is to block, this flag determines if the action duration
    /// should replace any existing blocking. If the action is to pad, this flag
    /// determines if the padding packet MAY be replaced by a non-padding packet
    /// queued at the time the padding packet would have been sent.
    pub replace: bool,
    /// A sampled limit on the number of actions allowed on repeated transitions
    /// to the same state.
    pub limit: Dist,
    /// A flag that specifies if the sampled limit should also be decremented on
    /// nonpadding (normal) traffic sent.
    pub limit_includes_nonpadding: bool,
    /// A map of all possible events associated to a probability vector. This is
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
            timeout: Dist::new(),
            action: Dist::new(),
            action_is_block: false,
            bypass: false,
            replace: false,
            limit: Dist::new(),
            limit_includes_nonpadding: false,
            next_state: make_next_state(t, num_states),
        }
    }

    /// Sample a timeout.
    pub fn sample_timeout(&self) -> f64 {
        self.timeout.sample().min(MAXSAMPLEDTIMEOUT)
    }

    /// Sample a limit.
    pub fn sample_limit(&self) -> u64 {
        if self.limit.dist == DistType::None {
            return STATELIMITMAX;
        }
        self.limit.sample().round() as u64
    }

    /// Sample a size for a padding action.
    pub fn sample_size(&self, mtu: u64) -> u64 {
        if self.action.dist == DistType::None {
            return mtu;
        }
        let s = self.action.sample().round() as u64;
        if s > mtu {
            return mtu;
        }
        if s == 0 {
            // never send empty padding
            return 1;
        }
        s
    }

    /// Sample a block duration for a blocking action.
    pub fn sample_block(&self) -> f64 {
        self.action.sample().min(MAXSAMPLEDBLOCK)
    }

    /// Serialize the state into a byte vector.
    pub fn serialize(&self, num_states: usize) -> Vec<u8> {
        let mut wtr = vec![];

        // distributions
        wtr.write_all(&self.action.serialize()).unwrap();
        wtr.write_all(&self.limit.serialize()).unwrap();
        wtr.write_all(&self.timeout.serialize()).unwrap();

        // flags
        if self.action_is_block {
            wtr.write_u8(1).unwrap();
        } else {
            wtr.write_u8(0).unwrap();
        }
        if self.bypass {
            wtr.write_u8(1).unwrap();
        } else {
            wtr.write_u8(0).unwrap();
        }
        if self.replace {
            wtr.write_u8(1).unwrap();
        } else {
            wtr.write_u8(0).unwrap();
        }
        if self.limit_includes_nonpadding {
            wtr.write_u8(1).unwrap();
        } else {
            wtr.write_u8(0).unwrap();
        }

        // next_state, ugly, encodes every possible event to be constant size
        for event in Event::iterator() {
            let exists = self.next_state.contains_key(event);
            for i in 0..num_states + 2 {
                if exists {
                    wtr.write_f64::<LittleEndian>(self.next_state[event][i])
                        .unwrap();
                } else {
                    wtr.write_f64::<LittleEndian>(0.0).unwrap();
                }
            }
        }

        wtr
    }
}

/// Attempt to construct a [`State`] from the given bytes as part of a
/// [`Machine`](crate::machine) with the specific number of states. The number
/// of states has to be known since the size of the transition matrix depends on
/// it.
pub fn parse_state(buf: Vec<u8>, num_states: usize) -> Result<State, Box<dyn Error>> {
    // len: 3 distributions + 4 flags + next_state
    if buf.len() < 3 * SERIALIZEDDISTSIZE + 4 + (num_states + 2) * 8 * Event::iterator().len() {
        bail!("too small")
    }

    // distributions
    let mut r: usize = 0;
    let action = parse_dist(buf[r..r + SERIALIZEDDISTSIZE].to_vec()).unwrap();
    r += SERIALIZEDDISTSIZE;
    let limit = parse_dist(buf[r..r + SERIALIZEDDISTSIZE].to_vec()).unwrap();
    r += SERIALIZEDDISTSIZE;
    let timeout = parse_dist(buf[r..r + SERIALIZEDDISTSIZE].to_vec()).unwrap();
    r += SERIALIZEDDISTSIZE;

    // flags
    let action_is_block: bool = buf[r] == 1;
    r += 1;
    let bypass: bool = buf[r] == 1;
    r += 1;
    let replace: bool = buf[r] == 1;
    r += 1;
    let limit_includes_nonpadding: bool = buf[r] == 1;
    r += 1;

    // next state
    let mut next_state: HashMap<Event, Vec<f64>> = HashMap::new();
    for event in Event::iterator() {
        let mut m = vec![];

        let mut all_zeroes = true;
        for _ in 0..num_states + 2 {
            let v = LittleEndian::read_f64(&buf[r..r + 8]);
            m.push(v);
            r += 8; // for f64
            if v != 0.0 {
                all_zeroes = false;
            }
        }
        if !all_zeroes {
            next_state.insert(*event, m);
        }
    }

    Ok(State {
        timeout,
        limit,
        action,
        action_is_block,
        bypass,
        replace,
        limit_includes_nonpadding,
        next_state,
    })
}

/// A helper used to construct [`State::next_state`] based on a map of
/// transitions ([`Event`] to probability vector) and the total number of states
/// in the [`Machine`](crate::machine).
pub fn make_next_state(
    t: HashMap<Event, HashMap<usize, f64>>,
    num_states: usize,
) -> HashMap<Event, Vec<f64>> {
    let mut r = HashMap::new();
    for event in Event::iterator() {
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
        if probmap.contains_key(&STATECANCEL) {
            res.push(*probmap.get(&STATECANCEL).unwrap());
        } else {
            res.push(0.0);
        }
        if probmap.contains_key(&STATEEND) {
            res.push(*probmap.get(&STATEEND).unwrap());
        } else {
            res.push(0.0);
        }

        r.insert(*event, res);
    }

    r
}

#[cfg(test)]
mod tests {
    use crate::state::*;

    #[test]
    fn serialization() {
        // assume state as part of a machine with 4 states
        let num_states = 4;
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e0: HashMap<usize, f64> = HashMap::new();
        e0.insert(0, 0.3);
        e0.insert(1, 0.2);
        let mut e1: HashMap<usize, f64> = HashMap::new();
        e1.insert(2, 0.6);
        let mut e2: HashMap<usize, f64> = HashMap::new();
        e2.insert(0, 0.4);
        e2.insert(1, 0.5);
        e2.insert(2, 0.1);
        t.insert(Event::NonPaddingRecv, e0);
        t.insert(Event::BlockingBegin, e1);
        t.insert(Event::LimitReached, e2);

        // create master
        let s = State {
            timeout: Dist {
                dist: DistType::Poisson,
                param1: 1.2,
                param2: 3.4,
                start: 5.6,
                max: 7.8,
            },
            limit: Dist {
                dist: DistType::Pareto,
                param1: 9.0,
                param2: 1.2,
                start: 3.4,
                max: 5.6,
            },
            action: Dist {
                dist: DistType::Geometric,
                param1: 7.8,
                param2: 9.0,
                start: 1.2,
                max: 3.4,
            },
            action_is_block: false,
            bypass: false,
            replace: true,
            limit_includes_nonpadding: false,
            next_state: make_next_state(t, num_states),
        };

        let buf = s.serialize(num_states);
        let parsed = parse_state(buf, num_states).unwrap();
        assert_eq!(s, parsed);
    }
}
