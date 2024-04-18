use std::{error::Error, io::Read};

use byteorder::{ByteOrder, LittleEndian};
use enum_map::{enum_map, EnumMap};
use flate2::read::ZlibDecoder;
use hex::decode;
use simple_error::{bail, map_err_with};
use std::cmp::Ordering;
use std::slice::Iter;

use crate::{
    action::Action,
    constants::STATE_END,
    dist::{Dist, DistType},
    event::Event,
    machine::Machine,
    state::{State, Trans},
};

// The size (in bytes) of a serialized distribution for a
// [`State`](crate::state) in v1.
const SERIALIZED_DIST_SIZE: usize = 2 + 8 * 4;

// helper function to iterate over all supported v1 events
fn v1_events_iter() -> Iter<'static, Event> {
    static EVENTS: [Event; 7] = [
        Event::NormalRecv,
        Event::PaddingRecv,
        // was in v1 NonPaddingSent
        Event::NormalSent,
        Event::PaddingSent,
        Event::BlockingBegin,
        Event::BlockingEnd,
        Event::LimitReached,
    ];
    EVENTS.iter()
}

/// parses a v1 machine from a hex string into a [`Machine`](crate::machine).
/// This format is deprecated and should not be used for new machines.
/// Therefore, no support for writing machines in this format is provided.
pub fn parse_v1_machine(s: &str) -> Result<Machine, Box<dyn Error + Send + Sync>> {
    // hex -> zlib -> vec
    let compressed = map_err_with!(decode(s), "failed to decode hex")?;

    let mut d = ZlibDecoder::new(compressed.as_slice());
    let mut buf = vec![];
    d.read_to_end(&mut buf)?;

    if buf.len() < 2 {
        bail!("cannot read version")
    }

    let (version, payload) = buf.split_at(2);

    match u16::from_le_bytes(version.try_into().unwrap()) {
        1 => parse_v1(payload),
        v => bail!("unsupported version: {}", v),
    }
}

fn parse_v1(buf: &[u8]) -> Result<Machine, Box<dyn Error + Send + Sync>> {
    // note that we already read 2 bytes of version in fn parse_machine()
    if buf.len() < 4 * 8 + 1 + 2 {
        bail!("not enough data for version 1 machine")
    }

    let mut r: usize = 0;
    // 4 8-byte values
    let allowed_padding_packets = LittleEndian::read_u64(&buf[r..r + 8]);
    r += 8;
    let max_padding_frac = LittleEndian::read_f64(&buf[r..r + 8]);
    r += 8;
    let allowed_blocked_microsec = LittleEndian::read_u64(&buf[r..r + 8]);
    r += 8;
    let max_blocking_frac = LittleEndian::read_f64(&buf[r..r + 8]);
    r += 8;

    // 1-byte flag
    //let include_small_packets = buf[r] == 1;
    r += 1;

    // 2-byte num of states
    let num_states: usize = LittleEndian::read_u16(&buf[r..r + 2]) as usize;
    r += 2;

    // each state has 3 distributions + 4 flags + next_state matrix
    let expected_state_len: usize =
        3 * SERIALIZED_DIST_SIZE + 4 + (num_states + 2) * 8 * (v1_events_iter().len() + 1);
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
        let s = parse_state(buf[r..r + expected_state_len].to_vec(), num_states)?;
        r += expected_state_len;
        states.push(s);
    }

    Machine::new(
        allowed_padding_packets,
        max_padding_frac,
        allowed_blocked_microsec,
        max_blocking_frac,
        states,
    )
}

pub fn parse_state(buf: Vec<u8>, num_states: usize) -> Result<State, Box<dyn Error + Send + Sync>> {
    // len: 3 distributions + 4 flags + next_state
    if buf.len()
        < 3 * SERIALIZED_DIST_SIZE + 4 + (num_states + 2) * 8 * (v1_events_iter().len() + 1)
    {
        bail!("too small")
    }

    // distributions
    let mut r: usize = 0;
    let duration = parse_dist(buf[r..r + SERIALIZED_DIST_SIZE].to_vec())?;
    r += SERIALIZED_DIST_SIZE;
    let limit = parse_dist(buf[r..r + SERIALIZED_DIST_SIZE].to_vec())?;
    r += SERIALIZED_DIST_SIZE;
    let timeout = parse_dist(buf[r..r + SERIALIZED_DIST_SIZE].to_vec())?;
    r += SERIALIZED_DIST_SIZE;

    // flags
    let action_is_block: bool = buf[r] == 1;
    r += 1;
    let bypass: bool = buf[r] == 1;
    r += 1;
    let replace: bool = buf[r] == 1;
    r += 1;

    let action: Option<Action>;
    if timeout.is_none() {
        action = None;
    } else {
        let timeout = timeout.unwrap();
        if action_is_block {
            if duration.is_none() {
                bail!("action dist is None")
            }
            action = Some(Action::BlockOutgoing {
                bypass,
                replace,
                timeout,
                duration: duration.unwrap(),
                limit,
            });
        } else {
            action = Some(Action::SendPadding {
                bypass,
                replace,
                timeout,
                limit,
            });
        };
    }

    //let limit_includes_nonpadding: bool = buf[r] == 1;
    r += 1;

    // next state
    let mut transitions: EnumMap<Event, Vec<Trans>> = enum_map! { _ => vec![] };

    for event in v1_events_iter() {
        for i in 0..num_states + 2 {
            let v = LittleEndian::read_f64(&buf[r..r + 8]);
            r += 8; // for f64

            if v != 0.0 {
                let state = match i.cmp(&(num_states)) {
                    Ordering::Less => i,
                    // FIXME: if someone really needs this, it can be supported
                    // by dynamically creating a new state with the cancel
                    // action and adjusting transitions accordingly
                    Ordering::Equal => bail!("invalid state, not supported in v2"),
                    Ordering::Greater => STATE_END,
                };

                transitions[*event].push(Trans(state, v as f32));
            }
        }
    }

    let mut s = State::new(transitions);
    s.action = action;
    Ok(s)
}

fn parse_dist(buf: Vec<u8>) -> Result<Option<Dist>, Box<dyn Error + Send + Sync>> {
    if buf.len() < SERIALIZED_DIST_SIZE {
        bail!("too small")
    }

    let type_buf = LittleEndian::read_u16(&buf[..2]);
    let param1 = LittleEndian::read_f64(&buf[2..10]);
    let param2 = LittleEndian::read_f64(&buf[10..18]);
    let dist_type = buf_to_dist_type(type_buf, param1, param2);
    let start = LittleEndian::read_f64(&buf[18..26]);
    let max = LittleEndian::read_f64(&buf[26..34]);

    if dist_type.is_none() {
        return Ok(None);
    }

    Ok(Some(Dist {
        dist: dist_type.unwrap(),
        start,
        max,
    }))
}

fn buf_to_dist_type(buf: u16, param1: f64, param2: f64) -> Option<DistType> {
    match buf {
        // same as DistType::None before
        0 => None,
        1 => Some(DistType::Uniform {
            low: param1,
            high: param2,
        }),
        2 => Some(DistType::Normal {
            mean: param1,
            stdev: param2,
        }),
        3 => Some(DistType::LogNormal {
            mu: param1,
            sigma: param2,
        }),
        4 => Some(DistType::Binomial {
            trials: param1 as u64,
            probability: param2,
        }),
        5 => Some(DistType::Geometric { probability: 0.0 }),
        6 => Some(DistType::Pareto {
            scale: param1,
            shape: param2,
        }),
        7 => Some(DistType::Poisson { lambda: 0.0 }),
        8 => Some(DistType::Weibull {
            scale: param1,
            shape: param2,
        }),
        9 => Some(DistType::Gamma {
            scale: param1,
            shape: param2,
        }),
        10 => Some(DistType::Beta {
            alpha: param1,
            beta: param2,
        }),
        // same as DistType::None before
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_parse_v1_machine() {
        // some examples machines, from noop to manually more complex and two
        // larger generated
        let machines = vec![
            "789cedca2101000000c230e85f1a8387009f9e351d051503ca0003",
            "789cd5cfbb0900200c04d08b833886adb889389f5bb9801be811acb58ae2837ce02010c158b070555c9538b6377a64dbb0ceff242c20b79038507dd169fbede9f629bf6f021efa1b66",
            "789ccdd14b4802411807f0d122d630a80e75e920646a9db2d24bd48c9587b012bc04415d32e856eca107d4210f792809a38804e910f400835ca88387d8961e144920b551aed8b59032cc0e59d16c0f41962510dafa0d0cc3cc77f8bef9cbc0b7e0092f06f131832c076f3f21c0e88d464f4c1b51449d3731df6b432feb0fa1f6e20e841f3fc801e5bd5f3d28efa43d8bbc1a1a5f6692e12589b860c84f62f752fbcd3e14605fb549f6bb6de86e0c1a7a028d88f09575d9a7dad2491120ff6279b0a1ca84ecf551ab6b418502adca267a486bc28f5fb20d4a7cb2db0d32fe34c94067ccda6d64afe1dba926585a782e5a2fb5dcdd9496721e42dfd5e35aed5e04865a0a9a13c3ec9ff62707db89d7b391233d1ae7a35458d219ce3049dd40b40827966d52e24a1c4a0be362a05fcde9923b97d0ecf1fa2b9f39c14f181ceeb914c74273f52cb9143e862b7d1554dd565850f7dfbd03f1ca70ff"
            ];

        for m in machines.iter() {
            let machine = parse_v1_machine(m).unwrap();
            println!("{:?}", machine);
            assert_eq!(
                machine.name(),
                Machine::from_str(machine.serialize().as_str())
                    .unwrap()
                    .name()
            );
        }
    }
}
