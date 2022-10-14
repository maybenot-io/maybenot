use crate::constants::*;
use crate::event::*;
use crate::state::*;
use byteorder::ByteOrder;
use byteorder::{LittleEndian, WriteBytesExt};
use std::error::Error;
use std::io::Write;
use std::str::FromStr;
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

impl FromStr for Machine {
    type Err = Box<dyn Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // hex -> zlib -> vec
        let compressed = decode(s).expect("failed to decode hex");

        let mut decoder = Decoder::new(&compressed[..]).unwrap();
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf).unwrap();

        if buf.len() < 2 {
            bail!("cannot read version")
        }

        let (version, payload) = buf.split_at(2);

        match u16::from_le_bytes(version.try_into().unwrap()) {
            1 => parse_v1_machine(payload),
            v => bail!("unsupported version: {}", v),
        }
    }
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
        // sane limits
        if self.max_padding_frac < 0.0 || self.max_padding_frac > 1.0 {
            bail!(
                "max_padding_frac has to be [0.0, 1.0], got {}",
                self.max_padding_frac
            )
        }
        if self.max_blocking_frac < 0.0 || self.max_blocking_frac > 1.0 {
            bail!(
                "max_blocking_frac has to be [0.0, 1.0], got {}",
                self.max_blocking_frac
            )
        }

        // sane number of states
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

        // check each state
        for state in &self.states {
            // validate transitions
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
                    bail!(
                        "found invalid total probability vector {}, must be (0.0, 1.0]",
                        p_total
                    )
                }
            }

            // validate distribution parameters
            state.action.validate()?;
            state.limit.validate()?;
            state.timeout.validate()?;
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

fn parse_v1_machine(buf: &[u8]) -> Result<Machine, Box<dyn Error>> {
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

    // each state has 3 distributions + 3 flags + next_state matrix
    let expected_state_len: usize =
        3 * SERIALIZEDDISTSIZE + 3 + (num_states + 2) * 8 * Event::iterator().len();
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

    let m = Machine {
        allowed_padding_bytes: allowed_padding_bytes,
        max_padding_frac: max_padding_frac,
        allowed_blocked_microsec: allowed_blocked_microsec,
        max_blocking_frac: max_blocking_frac,
        include_small_packets: include_small_packets,
        states: states,
    };
    m.validate()?;
    Ok(m)
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
        let mut s0 = State::new(t, num_states);
        s0.timeout = Dist {
            dist: DistType::Poisson,
            param1: 1.2,
            param2: 3.4,
            start: 5.6,
            max: 7.8,
        };
        s0.limit = Dist {
            dist: DistType::Pareto,
            param1: 9.0,
            param2: 1.2,
            start: 3.4,
            max: 5.6,
        };
        s0.action = Dist {
            dist: DistType::Geometric,
            param1: 0.8,
            param2: 9.0,
            start: 1.2,
            max: 3.4,
        };

        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e0: HashMap<usize, f64> = HashMap::new();
        e0.insert(0, 0.2);
        e0.insert(1, 0.8);
        let mut e1: HashMap<usize, f64> = HashMap::new();
        e1.insert(0, 1.0);
        t.insert(Event::NonPaddingRecv, e0);
        t.insert(Event::PaddingSent, e1);
        let mut s1 = State::new(t, num_states);
        s1.timeout = Dist {
            dist: DistType::Uniform,
            param1: 0.1,
            param2: 1.2,
            start: 3.4,
            max: 5.6,
        };
        s1.limit = Dist {
            dist: DistType::Weibull,
            param1: 1.2,
            param2: 3.4,
            start: 5.6,
            max: 7.8,
        };
        s1.action = Dist {
            dist: DistType::Beta,
            param1: 5.6,
            param2: 7.8,
            start: 9.0,
            max: 1.2,
        };
        s1.action_is_block = true;

        let m = Machine {
            allowed_padding_bytes: 1000,
            max_padding_frac: 0.123,
            allowed_blocked_microsec: 2000,
            max_blocking_frac: 0.456,
            states: vec![s0, s1],
            include_small_packets: true,
        };

        // serialize, parse, eq
        let s = m.serialize();
        let m_parsed = Machine::from_str(&s).unwrap();
        assert_eq!(m, m_parsed);
    }

    #[test]
    fn parse_v1_machine_nop() {
        // attempt to parse an empty no-op machine (does nothing)
        let s = "789cedca31010000000141fa9736084080bff9ace928a80003c70003".to_string();
        let m = Machine::from_str(&s).unwrap();

        assert_eq!(m.allowed_blocked_microsec, 0);
        assert_eq!(m.allowed_padding_bytes, 0);
        assert_eq!(m.max_blocking_frac, 0.0);
        assert_eq!(m.max_padding_frac, 0.0);
        assert_eq!(m.include_small_packets, false);

        assert_eq!(m.states.len(), 1);
        assert_eq!(m.states[0].block_overwrite, false);
        assert_eq!(m.states[0].limit_includes_nonpadding, false);
        assert_eq!(m.states[0].action_is_block, false);
        assert_eq!(m.states[0].action.dist, DistType::None);
        assert_eq!(m.states[0].action.param1, 0.0);
        assert_eq!(m.states[0].action.param2, 0.0);
        assert_eq!(m.states[0].action.max, 0.0);
        assert_eq!(m.states[0].action.start, 0.0);
        assert_eq!(m.states[0].limit.dist, DistType::None);
        assert_eq!(m.states[0].limit.param1, 0.0);
        assert_eq!(m.states[0].limit.param2, 0.0);
        assert_eq!(m.states[0].limit.max, 0.0);
        assert_eq!(m.states[0].limit.start, 0.0);
        assert_eq!(m.states[0].timeout.dist, DistType::None);
        assert_eq!(m.states[0].timeout.param1, 0.0);
        assert_eq!(m.states[0].timeout.param2, 0.0);
        assert_eq!(m.states[0].timeout.max, 0.0);
        assert_eq!(m.states[0].timeout.start, 0.0);

        assert_eq!(m.states[0].next_state.len(), 0);
    }

    #[test]
    fn parse_v1_machine_padding() {
        // make a 1-state padding machine, serialize, and compare
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        t.insert(Event::PaddingSent, e);
        let mut s0 = State::new(t, 1);
        s0.timeout = Dist {
            dist: DistType::Uniform,
            param1: 1.2,
            param2: 3.4,
            start: 5.6,
            max: 7.8,
        };
        s0.action = Dist {
            dist: DistType::Poisson,
            param1: 0.5,
            param2: 0.0,
            start: 1.2,
            max: 3.4,
        };
        let m = Machine {
            allowed_padding_bytes: 1000,
            max_padding_frac: 0.123,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0],
            include_small_packets: false,
        };
        let s = m.serialize();
        println!("{}", s);
        let m_parsed = Machine::from_str(&s).unwrap();
        assert_eq!(m, m_parsed);

        // add hardcoded assert
        let hardcoded = "789cbdcebb0d80201006e0bb5858d8db3a8403c034c6dada25dcc40d5cc59286848405f8b9828450000d5f71b947ee724c6622f15ee763ef4f21cd31cd88d19f86bbf00a01168d5605173b8758350ad81a6e7472e9dd5102920813d3".to_string();
        let m_hardcoded = Machine::from_str(&hardcoded).unwrap();
        assert_eq!(m, m_hardcoded);
    }

    #[test]
    fn parse_v1_machine_blocking() {
        // make a 1-state blocking machine, serialize, and compare
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        t.insert(Event::BlockingEnd, e);
        let mut s0 = State::new(t, 1);
        s0.timeout = Dist {
            dist: DistType::Pareto,
            param1: 1.2,
            param2: 3.4,
            start: 5.6,
            max: 7.8,
        };
        s0.action = Dist {
            dist: DistType::Geometric,
            param1: 0.3,
            param2: 0.7,
            start: 3.4,
            max: 7.9,
        };
        s0.action_is_block = true;
        let m = Machine {
            allowed_padding_bytes: 0,
            max_padding_frac: 0.0,
            allowed_blocked_microsec: 100000,
            max_blocking_frac: 0.9999,
            states: vec![s0],
            include_small_packets: true,
        };
        let s = m.serialize();
        println!("{}", s);
        let m_parsed = Machine::from_str(&s).unwrap();
        assert_eq!(m, m_parsed);

        // add hardcoded assert
        let hardcoded = "789cc5cda11180300c05d04480c123e9061806482493300a3b80c231103b7038b86300f8b45c454d45459fc85d72c90f536819ddac598fbe7d4e61a6823a6b93c1da050d543a4f1fa3d88f28ff8cdbdf22086a450346dddb8c2e4149f202ecef1a22".to_string();
        let m_hardcoded = Machine::from_str(&hardcoded).unwrap();
        assert_eq!(m, m_hardcoded);
    }

    #[test]
    fn parse_v1_machine_mixed() {
        // make a 2-state mixed machine, serialize, and compare
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(1, 1.0);
        t.insert(Event::BlockingEnd, e);
        let mut s0 = State::new(t, 2);
        s0.timeout = Dist {
            dist: DistType::Pareto,
            param1: 1.2,
            param2: 3.4,
            start: 5.6,
            max: 7.8,
        };
        s0.action = Dist {
            dist: DistType::Geometric,
            param1: 0.3,
            param2: 0.7,
            start: 3.4,
            max: 7.9,
        };
        s0.action_is_block = true;
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        t.insert(Event::PaddingSent, e);
        let mut s1 = State::new(t, 2);
        s1.timeout = Dist {
            dist: DistType::Uniform,
            param1: 1.2,
            param2: 3.4,
            start: 5.6,
            max: 7.8,
        };
        s1.action = Dist {
            dist: DistType::Poisson,
            param1: 0.5,
            param2: 0.0,
            start: 1.2,
            max: 3.4,
        };
        let m = Machine {
            allowed_padding_bytes: 0,
            max_padding_frac: 0.0,
            allowed_blocked_microsec: 100000,
            max_blocking_frac: 0.9999,
            states: vec![s0, s1],
            include_small_packets: true,
        };
        let s = m.serialize();
        println!("{}", s);
        let m_parsed = Machine::from_str(&s).unwrap();
        assert_eq!(m, m_parsed);

        // add hardcoded assert
        let hardcoded = "789cd5d0b10980301005d044500b7b4bb3818d03e44a27711477d0cace815cc04aec141c407f1249408b3441f0410239ee2ef0397b1a5a532bc6b52ecf4df288c5acd226d9688bc40332ea3b4510fa3d927bc76167b10872c20304996f7f6497b8824a7194d96e4632e04243c983bf669032b8a0d1f48df00185720150642886".to_string();
        let m_hardcoded = Machine::from_str(&hardcoded).unwrap();
        assert_eq!(m, m_hardcoded);
    }

    #[test]
    fn parse_v1_machine_100_states() {
        // make a machine with 100 states, serialize, and compare
        let num_states = 100;
        let mut states: Vec<State> = vec![];
        for i in 0..num_states {
            let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
            let mut e: HashMap<usize, f64> = HashMap::new();
            e.insert(i, 1.0);
            t.insert(Event::PaddingSent, e);
            let mut s = State::new(t,num_states);
            s.timeout = Dist {
                dist: DistType::Uniform,
                param1: 1.2,
                param2: 3.4,
                start: 5.6,
                max: 7.8,
            };
            s.action = Dist {
                dist: DistType::Poisson,
                param1: 0.5,
                param2: 0.0,
                start: 1.2,
                max: 3.4,
            };
            states.push(s);
        }
        let m = Machine {
            allowed_padding_bytes: 0,
            max_padding_frac: 0.0,
            allowed_blocked_microsec: 100000,
            max_blocking_frac: 0.9999,
            states,
            include_small_packets: true,
        };
        let s = m.serialize();
        println!("{}", s);
        let m_parsed = Machine::from_str(&s).unwrap();
        assert_eq!(m, m_parsed);

        let hardcoded = "789cedd93b6e14411080613b222027841b90708075c8411047e11c645c8b900c240e00e33558f67a1fb3f3e8e9aafabea0a52aa93b6ee9bfbd39f4f5cbc3eeedb71f1fdffff9b9bbfd74f36a18ef7ddf0dc7de87bddfbbe118bcbe1b5617dcbeb8f379efcddd300cde8d78030080267e3d7efb00000080f8841e008092041f000000c840e80100284df001000080c8841e000006820f0000004424f40000f084e00300000091083d00001c21f80000004004420f000067083e000000d033a107008011041f000000e891d00300c015041f000000e889d00300c004820f000000f440e801006006c107000000b624f40000b000c107000000b620f40000b020c1070000005a127a00005881e0030000002d083d0000ac48f00100008035093d00003420f8000000c01a841e00001a127c0000006049420f00001b107c0000006009420f00001b127c000000600ea10700800e083e0000003085d003004047041f000000b886d003004087041f0000001843e80100a063820f0000009c23f400001080e003000000c7083d00000422f8000000c053420f000001093e000000704fe801002030c107000080da841e000012107c000000a849e801002011c1070000805a841e000012127c000000a841e801002031c107000080dc841e00000a107c000000c849e80100a010c1070000805c841e00000a127c000000c841e80100a030c107000080d8841e0000107c000000084ae801008047820f000000b1083d0000f082e0030000400c420f00009c24f8000000d037a10700002e127c000000e893d0030000a3093e000000f445e8010080ab093e000000f441e8010080c9041f000000b625f40000c06c820f000000db107a00006031820f0000006d093d0000b038c10700008036841e0000588de0030000c0ba841e0000589de0030000c03a841e00006846f00100006059420f00003427f8000000b00ca10700003623f8000000308fd00300009b137c0000009846e80100806e083e0000005c47e8010080ee083e0000008c23f4000040b7041f000000ce137a0000a07b820f000000c7093d00001086e0030000c073420f00008423f8000000f040e8010080b0041f000080ea841e0000084ff0010000a84ae801008034041f0000806a841e00004847f0010000a842e8010080b4041f000080ec841e0000484ff0010000c84ae801008032041f0000806c841e00002847f0010000c842e8010080b2041f000080e8841e0000284ff0010000884ae8010000fe117c000000a2117a00008003820f00004014420f00007082e0030000d03ba1070000b840f0010000e895d00300008c24f8000000f446e8010000ae24f8000000f442e801000026127c000000b626f400000033093e0000005b117a00008085083e000000ad093d0000c0c2041f00008056841e00006025820f0000c0da841e00006065820f0000c05a841e0000a011c10700006069420f0000d098e0030000b014a1070000d888e00300003097d00300006c4cf0010000984ae80100003a21f80000005c4be80100003a23f80000008c25f40000009d127c0000002e117a000080ce093e000000a7083d00004010820f0000c021a10700000846f0010000f84fe801000082127c000000841e00002038c1070000a84be801000092107c0000807a841e00002019c1070000a843e801000092127c000080fc841e00002039c1070000c84be80100008a107c0000807c841e0000a018c1070000c843e80100008a127c000080f8841e0000a038c107000088eb2fd70ea4d5".to_string();
        let m_hardcoded = Machine::from_str(&hardcoded).unwrap();
        assert_eq!(m, m_hardcoded);
    }
}
