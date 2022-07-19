use crate::constants::*;
use crate::event::*;
use crate::state::*;
use byteorder::ByteOrder;
use byteorder::{LittleEndian, WriteBytesExt};
use std::error::Error;
use std::io::Write;
extern crate simple_error;
use hex::{decode, encode};
use libflate::zlib::{Decoder, Encoder};
use ring::digest::{Context, SHA256};
use simple_error::bail;
use std::io::Read;

#[derive(PartialEq, Debug, Clone)]
pub struct Machine {
    pub allowed_padding_bytes: u64,
    pub max_padding_frac: f64,
    pub allowed_blocked_microsec: u64,
    pub max_blocking_frac: f64,
    pub states: Vec<State>,
    pub include_small_packets: bool,
}

impl Machine {
    pub fn name(&self) -> String {
        let mut context = Context::new(&SHA256);
        context.update(self.serialize().as_bytes());
        let d = context.finish();
        let s = encode(d);
        s[0..32].to_string()
    }

    pub fn validate(&self) -> Result<(), Box<dyn Error>> {
        if self.max_padding_frac < 0.0 || self.max_padding_frac > 1.0 {
            bail!(
                "max_padding_frac has to be [0.0, 1.0], got {}",
                self.max_padding_frac
            )
        }

        if self.states.len() == 0 {
            bail!("a machine must have at least one state")
        }
        if self.states.len() > STATEMAX {
            bail!(
                "too many states, max is {}, found {}",
                STATEMAX,
                self.states.len()
            )
        }

        for state in &self.states {
            for next in &state.next_state {
                if next.1.len() != self.states.len() + 2 {
                    bail!(
                        "found too small next_state vector, expected {}, got {}",
                        self.states.len() + 2,
                        next.1.len()
                    )
                }

                let mut p_total = 0.0;
                for p in next.1 {
                    if p < &0.0 || p > &1.0 {
                        bail!("found probability {}, has to be [0.0, 1.0]", &p)
                    }
                    p_total += p;
                }

                // we are (0.0, 1.0] here, because:
                // - if pTotal <= 0.0, then we shouldn't have an entry in NextState
                // - pTotal < 1.0 is OK, to support a "nop" transition (self
                // transition has implications in the framework, i.e., involving
                // limits on padding sent in he state)
                if p_total <= 0.0 || p_total >= 1.0005 {
                    // 1.0005 due to rounding
                    bail!("found invalid total probability vector {}, must be (0.0, 1.0]")
                }
            }
        }

        Ok(())
    }

    pub fn serialize(&self) -> String {
        let mut wtr = vec![];

        wtr.write_u16::<LittleEndian>(VERSION as u16).unwrap();
        wtr.write_u64::<LittleEndian>(self.allowed_padding_bytes)
            .unwrap();
        wtr.write_f64::<LittleEndian>(self.max_padding_frac)
            .unwrap();
        wtr.write_u64::<LittleEndian>(self.allowed_blocked_microsec)
            .unwrap();
        wtr.write_f64::<LittleEndian>(self.max_blocking_frac)
            .unwrap();

        if self.include_small_packets {
            wtr.write_u8(1).unwrap();
        } else {
            wtr.write_u8(0).unwrap();
        }

        let num_states = self.states.len();
        wtr.write_u16::<LittleEndian>(num_states as u16).unwrap();

        for i in 0..self.states.len() {
            wtr.write_all(&self.states[i].serialize(num_states))
                .unwrap();
        }

        let mut encoder = Encoder::new(Vec::new()).unwrap();
        encoder.write_all(&wtr).unwrap();
        let compressed = encoder.finish().into_result().unwrap();

        // return hex encoded string
        encode(compressed)
    }
}

pub fn validate_machines(machines: Vec<Machine>) -> Result<(), Box<dyn Error>> {
    for m in machines {
        m.validate()?;
    }
    Ok(())
}

pub fn parse_machine(m: String) -> Result<Machine, Box<dyn Error>> {
    // hex -> zlib -> vec
    let compressed = decode(m).expect("failed to decode hex");

    let mut decoder = Decoder::new(&compressed[..]).unwrap();
    let mut buf = Vec::new();
    decoder.read_to_end(&mut buf).unwrap();

    if buf.len() < 2 {
        bail!("cannot read version")
    }

    match LittleEndian::read_u16(&buf[0..2]) {
        1 => parse_v1_machine(buf[2..].to_vec()),
        _ => bail!("unsupported version"),
    }
}

fn parse_v1_machine(buf: Vec<u8>) -> Result<Machine, Box<dyn Error>> {
    // note that we already read 2 bytes of version in fn parse_machine()
    if buf.len() < 4 * 8 + 1 + 2 {
        bail!("not enough data for version 1 machine")
    }

    let mut r: usize = 0;
    // 4 8-byte values
    let allowed_padding_bytes = LittleEndian::read_u64(&buf[r..r + 8]);
    r += 8;
    let max_padding_frac = LittleEndian::read_f64(&buf[r..r + 8]);
    r += 8;
    let allowed_blocked_microsec = LittleEndian::read_u64(&buf[r..r + 8]);
    r += 8;
    let max_blocking_frac = LittleEndian::read_f64(&buf[r..r + 8]);
    r += 8;

    // 1-byte flag
    let include_small_packets = buf[r] == 1;
    r += 1;

    // 2-byte num of states
    let num_states: usize = LittleEndian::read_u16(&buf[r..r + 2]) as usize;
    r += 2;

    // each state has 4 distributions + 2 flags + next_state matrix
    let expected_state_len: usize =
        4 * SERIALIZEDDISTSIZE + 2 + (num_states + 2) * 8 * Event::iterator().len();
    if buf[r..].len() != expected_state_len * num_states {
        bail!(format!(
            "expected {} bytes for {} states, but got {} bytes",
            expected_state_len * num_states,
            num_states,
            buf[r..].len()
        ))
    }

    let mut states = vec![];
    for _ in 0..num_states {
        let s = parse_state(buf[r..r + expected_state_len].to_vec(), num_states).unwrap();
        r += expected_state_len;
        states.push(s);
    }

    Ok(Machine {
        allowed_padding_bytes: allowed_padding_bytes,
        max_padding_frac: max_padding_frac,
        allowed_blocked_microsec: allowed_blocked_microsec,
        max_blocking_frac: max_blocking_frac,
        include_small_packets: include_small_packets,
        states: states,
    })
}

#[cfg(test)]
mod tests {
    use crate::dist::*;
    use crate::machine::*;
    use std::collections::HashMap;

    #[test]
    fn basic_serialization() {
        // plan: manually create a machine, serialize it, parse it, and then compare

        let num_states = 2;

        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e0: HashMap<usize, f64> = HashMap::new();
        e0.insert(0, 0.4);
        e0.insert(1, 0.6);
        let mut e1: HashMap<usize, f64> = HashMap::new();
        e1.insert(1, 1.0);
        t.insert(Event::PaddingRecv, e0);
        t.insert(Event::LimitReached, e1);
        let state1 = State {
            timeout: Dist {
                dist: DistType::Poisson,
                param1: 1.2,
                param2: 3.4,
                start: 5.6,
                max: 7.8,
            },
            limit: Dist {
                dist: DistType::GenPareto,
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
                dist: DistType::LogLogistic,
                param1: 5.6,
                param2: 7.8,
                start: 9.0,
                max: 1.2,
            },
            block_overwrite: true,
            limit_includes_nonpadding: false,
            next_state: make_next_state(t, num_states),
        };

        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e0: HashMap<usize, f64> = HashMap::new();
        e0.insert(0, 0.2);
        e0.insert(1, 0.8);
        let mut e1: HashMap<usize, f64> = HashMap::new();
        e1.insert(0, 1.0);
        t.insert(Event::NonPaddingRecv, e0);
        t.insert(Event::PaddingSent, e1);
        let state2 = State {
            timeout: Dist {
                dist: DistType::Uniform,
                param1: 9.0,
                param2: 1.2,
                start: 3.4,
                max: 5.6,
            },
            limit: Dist {
                dist: DistType::Weibull,
                param1: 1.2,
                param2: 3.4,
                start: 5.6,
                max: 7.8,
            },
            size: Dist {
                dist: DistType::Logistic,
                param1: 5.6,
                param2: 7.8,
                start: 9.0,
                max: 1.2,
            },
            block: Dist {
                dist: DistType::Poisson,
                param1: 7.8,
                param2: 9.0,
                start: 1.2,
                max: 3.4,
            },
            block_overwrite: false,
            limit_includes_nonpadding: true,
            next_state: make_next_state(t, num_states),
        };

        let m = Machine {
            allowed_padding_bytes: 1000,
            max_padding_frac: 0.123,
            allowed_blocked_microsec: 2000,
            max_blocking_frac: 0.456,
            states: vec![state1, state2],
            include_small_packets: true,
        };

        // serialize, parse, eq
        let s = m.serialize();
        let m_parsed = parse_machine(s).unwrap();
        assert_eq!(m, m_parsed);
    }

    #[test]
    fn parse_v1_machine_nop() {
        // attempt to parse a "no-op" machine from the go implementation
        let s = "789c62642008885032c4c007fb81b219100000ffff94510132".to_string();
        let m = parse_machine(s).unwrap();

        assert_eq!(m.allowed_blocked_microsec, 0);
        assert_eq!(m.allowed_padding_bytes, 0);
        assert_eq!(m.max_blocking_frac, 0.0);
        assert_eq!(m.max_padding_frac, 0.0);
        assert_eq!(m.include_small_packets, false);

        assert_eq!(m.states.len(), 1);
        assert_empty_default_state(&m.states[0]);

        assert_eq!(m.states[0].next_state.len(), 1);
        assert_eq!(m.states[0].next_state[&Event::NonPaddingSent].len(), 3);
        // index 0 is transition to self (state 0)
        assert_eq!(m.states[0].next_state[&Event::NonPaddingSent][0], 0.0);
        // index 1 is transition to STATECANCEL (state 1 after fn make_next_state())
        assert_eq!(m.states[0].next_state[&Event::NonPaddingSent][1], 0.0);
        // index 2 is transition to STATEEND (state 2 after fn make_next_state())
        assert_eq!(m.states[0].next_state[&Event::NonPaddingSent][2], 1.0);
    }

    #[test]
    fn parse_v1_machine_larger() {
        // attempt to parse a much larger machine, based on an early
        // constant-rate client prototype (not documented here)
        let s = "789c62642008d8092b1920f0c17ea05d800a069b7b46013a2022b9d3cc9686163d473a3b64d881d11c36d400b5626c34e647c1e000a3297a140c2f309aa247012a80354f61314a9b9825c29641de4e1ee9297ef0fb9f1a2919cd8c82e90e5472dc2002a375c0600780000000ffff67d71a77".to_string();
        let m = parse_machine(s).unwrap();

        assert_eq!(m.allowed_blocked_microsec, 0);
        assert_eq!(m.allowed_padding_bytes, 0);
        assert_eq!(m.max_blocking_frac, 0.0);
        assert_eq!(m.max_padding_frac, 0.0);
        assert_eq!(m.include_small_packets, false);
        assert_eq!(m.states.len(), 7);

        // the machine has 7 states
        let num_states: usize = 7;

        // state 0
        assert_empty_default_state(&m.states[0]);
        assert_eq!(m.states[0].next_state.len(), 2);
        assert_eq!(
            m.states[0].next_state[&Event::NonPaddingSent].len(),
            num_states + 2
        );
        assert_eq!(m.states[0].next_state[&Event::NonPaddingSent][1], 1.0);
        assert_eq!(
            m.states[0].next_state[&Event::NonPaddingRecv].len(),
            num_states + 2
        );
        assert_eq!(m.states[0].next_state[&Event::NonPaddingRecv][1], 1.0);

        // state 1
        assert_eq!(m.states[1].next_state.len(), 1);
        assert_eq!(
            m.states[1].next_state[&Event::BlockingBegin].len(),
            num_states + 2
        );
        assert_eq!(m.states[1].next_state[&Event::BlockingBegin][2], 1.0);
        assert_eq!(m.states[1].timeout.dist, DistType::Uniform);
        assert_eq!(m.states[1].timeout.param1, 0.0);
        assert_eq!(m.states[1].timeout.param2, 0.0);
        assert_eq!(m.states[1].timeout.max, 0.0);
        assert_eq!(m.states[1].timeout.start, 0.0);
        assert_eq!(m.states[1].block.dist, DistType::Uniform);
        assert_eq!(m.states[1].block.param1, 0.0);
        assert_eq!(m.states[1].block.param2, 0.0);
        assert_eq!(m.states[1].block.max, 0.0);
        assert_eq!(m.states[1].block.start, 1000.0 * 1000.0);

        // state 2
        assert_empty_default_state(&m.states[2]);
        assert_eq!(m.states[2].next_state.len(), 2);
        assert_eq!(
            m.states[2].next_state[&Event::NonPaddingRecv].len(),
            num_states + 2
        );
        assert_eq!(m.states[2].next_state[&Event::NonPaddingRecv][3], 1.0);
        assert_eq!(
            m.states[2].next_state[&Event::PaddingRecv].len(),
            num_states + 2
        );
        assert_eq!(m.states[2].next_state[&Event::PaddingRecv][3], 1.0);

        // state 3
        assert_empty_default_state(&m.states[3]);
        assert_eq!(m.states[3].next_state.len(), 2);
        assert_eq!(
            m.states[3].next_state[&Event::NonPaddingRecv].len(),
            num_states + 2
        );
        assert_eq!(m.states[3].next_state[&Event::NonPaddingRecv][4], 1.0);
        assert_eq!(
            m.states[3].next_state[&Event::PaddingRecv].len(),
            num_states + 2
        );
        assert_eq!(m.states[3].next_state[&Event::PaddingRecv][4], 1.0);

        // state 4
        assert_empty_default_state(&m.states[4]);
        assert_eq!(m.states[4].next_state.len(), 2);
        assert_eq!(
            m.states[4].next_state[&Event::NonPaddingRecv].len(),
            num_states + 2
        );
        assert_eq!(m.states[4].next_state[&Event::NonPaddingRecv][5], 1.0);
        assert_eq!(
            m.states[4].next_state[&Event::PaddingRecv].len(),
            num_states + 2
        );
        assert_eq!(m.states[4].next_state[&Event::PaddingRecv][5], 1.0);

        // state 5
        assert_eq!(m.states[5].next_state.len(), 2);
        assert_eq!(
            m.states[5].next_state[&Event::NonPaddingSent].len(),
            num_states + 2
        );
        assert_eq!(m.states[5].next_state[&Event::NonPaddingSent][1], 1.0);
        assert_eq!(
            m.states[5].next_state[&Event::BlockingEnd].len(),
            num_states + 2
        );
        assert_eq!(m.states[5].next_state[&Event::BlockingEnd][6], 1.0);
        assert_eq!(m.states[5].timeout.dist, DistType::Uniform);
        assert_eq!(m.states[5].timeout.param1, 1.0);
        assert_eq!(m.states[5].timeout.param2, 1.0);
        assert_eq!(m.states[5].timeout.max, 0.0);
        assert_eq!(m.states[5].timeout.start, 0.0);
        assert_eq!(m.states[5].block.dist, DistType::Uniform);
        assert_eq!(m.states[5].block.param1, 1.0);
        assert_eq!(m.states[5].block.param2, 1.0);
        assert_eq!(m.states[5].block.max, 0.0);
        assert_eq!(m.states[5].block.start, 0.0);
        assert_eq!(m.states[5].block_overwrite, true);

        // state 6
        assert_eq!(m.states[6].next_state.len(), 2);
        assert_eq!(
            m.states[6].next_state[&Event::NonPaddingSent].len(),
            num_states + 2
        );
        assert_eq!(m.states[6].next_state[&Event::NonPaddingSent][1], 1.0);
        assert_eq!(
            m.states[6].next_state[&Event::PaddingSent].len(),
            num_states + 2
        );
        assert_eq!(m.states[6].next_state[&Event::PaddingSent][1], 1.0);
        assert_eq!(m.states[6].timeout.dist, DistType::Uniform);
        assert_eq!(m.states[6].timeout.param1, 1.0);
        assert_eq!(m.states[6].timeout.param2, 1.0);
        assert_eq!(m.states[6].timeout.max, 0.0);
        assert_eq!(m.states[6].timeout.start, 0.0);
        assert_eq!(m.states[6].size.dist, DistType::Uniform);
        assert_eq!(m.states[6].size.param1, 1.0);
        assert_eq!(m.states[6].size.param2, 1500.0);
        assert_eq!(m.states[6].size.max, 0.0);
        assert_eq!(m.states[6].size.start, 0.0);
    }

    fn assert_empty_default_state(s: &State) {
        assert_eq!(s.block_overwrite, false);
        assert_eq!(s.limit_includes_nonpadding, false);
        assert_eq!(s.block.dist, DistType::None);
        assert_eq!(s.block.param1, 0.0);
        assert_eq!(s.block.param2, 0.0);
        assert_eq!(s.block.max, 0.0);
        assert_eq!(s.block.start, 0.0);
        assert_eq!(s.limit.dist, DistType::None);
        assert_eq!(s.limit.param1, 0.0);
        assert_eq!(s.limit.param2, 0.0);
        assert_eq!(s.limit.max, 0.0);
        assert_eq!(s.limit.start, 0.0);
        assert_eq!(s.timeout.dist, DistType::None);
        assert_eq!(s.timeout.param1, 0.0);
        assert_eq!(s.timeout.param2, 0.0);
        assert_eq!(s.timeout.max, 0.0);
        assert_eq!(s.timeout.start, 0.0);
        assert_eq!(s.size.dist, DistType::None);
        assert_eq!(s.size.param1, 0.0);
        assert_eq!(s.size.param2, 0.0);
        assert_eq!(s.size.max, 0.0);
        assert_eq!(s.size.start, 0.0);
    }
}
