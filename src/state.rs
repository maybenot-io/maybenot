use crate::constants::*;
use crate::dist::*;
use crate::event::*;
use byteorder::ByteOrder;
use byteorder::{LittleEndian, WriteBytesExt};
use std::collections::HashMap;
use std::error::Error;
use std::io::Write;
extern crate simple_error;
use simple_error::bail;

#[derive(PartialEq, Debug, Clone)]
pub struct State {
    pub timeout: Dist,
    pub limit: Dist,
    pub size: Dist,
    pub block: Dist,
    pub block_overwrite: bool,
    pub limit_includes_nonpadding: bool,
    pub next_state: HashMap<Event, Vec<f64>>,
}

impl State {
    pub fn sample_timeout(&self) -> f64 {
        self.timeout.sample().min(MAXSAMPLEDTIMEOUT)
    }

    pub fn sample_limit(&self) -> u64 {
        if self.limit.dist == DistType::None {
            return STATELIMITMAX;
        }
        self.limit.sample().round() as u64
    }

    pub fn sample_size(&self, mtu: u64) -> u64 {
        if self.size.dist == DistType::None {
            return mtu;
        }

        let s = self.size.sample().round() as u64;
        if s > mtu {
            return mtu;
        }
        if s == 0 {
            // never send empty padding
            return 1;
        }
        s
    }

    pub fn sample_block(&self) -> f64 {
        self.block.sample().min(MAXSAMPLEDBLOCK)
    }

    pub fn serialize(&self, num_states: usize) -> Vec<u8> {
        let mut wtr = vec![];

        // distributions
        wtr.write_all(&self.timeout.serialize()).unwrap();
        wtr.write_all(&self.limit.serialize()).unwrap();
        wtr.write_all(&self.size.serialize()).unwrap();
        wtr.write_all(&self.block.serialize()).unwrap();

        // flags
        if self.limit_includes_nonpadding {
            wtr.write_u8(1).unwrap();
        } else {
            wtr.write_u8(0).unwrap();
        }
        if self.block_overwrite {
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

pub fn parse_state(buf: Vec<u8>, num_states: usize) -> Result<State, Box<dyn Error>> {
    // len: 4 distributions + 2 flag + next_state
    if buf.len() < 4 * SERIALIZEDDISTSIZE + 2 + (num_states + 2) * 8 * Event::iterator().len() {
        bail!("too small")
    }

    // distributions
    let mut r: usize = 0;
    let timeout = parse_dist(buf[r..r + SERIALIZEDDISTSIZE].to_vec()).unwrap();
    r += SERIALIZEDDISTSIZE;
    let limit = parse_dist(buf[r..r + SERIALIZEDDISTSIZE].to_vec()).unwrap();
    r += SERIALIZEDDISTSIZE;
    let size = parse_dist(buf[r..r + SERIALIZEDDISTSIZE].to_vec()).unwrap();
    r += SERIALIZEDDISTSIZE;
    let block = parse_dist(buf[r..r + SERIALIZEDDISTSIZE].to_vec()).unwrap();
    r += SERIALIZEDDISTSIZE;

    // flags
    let limit_includes_nonpadding: bool = buf[r] == 1;
    r += 1;
    let block_overwrite: bool = buf[r] == 1;
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
            next_state.insert(event.clone(), m);
        }
    }

    Ok(State {
        timeout: timeout,
        limit: limit,
        size: size,
        block: block,
        block_overwrite: block_overwrite,
        limit_includes_nonpadding: limit_includes_nonpadding,
        next_state: next_state,
    })
}

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
            size: Dist {
                dist: DistType::Geometric,
                param1: 7.8,
                param2: 9.0,
                start: 1.2,
                max: 3.4,
            },
            block: Dist {
                dist: DistType::LogNormal,
                param1: 5.6,
                param2: 7.8,
                start: 9.0,
                max: 1.2,
            },
            block_overwrite: true,
            limit_includes_nonpadding: false,
            next_state: make_next_state(t, num_states),
        };

        let buf = s.serialize(num_states);
        let parsed = parse_state(buf, num_states).unwrap();
        assert_eq!(s, parsed);
    }
}
