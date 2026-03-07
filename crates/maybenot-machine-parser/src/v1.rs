//! Parser for v1 hex-encoded binary machine strings.
//!
//! V1 machines use a custom binary format: hex-encoded, zlib-compressed, with a
//! 2-byte little-endian version header followed by per-machine and per-state data.
//! This format predates the serde-based serialization used in v2 and v3.

use std::cmp::Ordering;
use std::io::Read;

use byteorder::{ByteOrder, LittleEndian};
use enum_map::{EnumMap, enum_map};
use flate2::read::ZlibDecoder;
use maybenot::{
    Error, Machine,
    action::Action,
    constants::{MAX_DECOMPRESSED_SIZE, MAX_SAMPLED_DELAY_N, STATE_END},
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};

// Size in bytes of one serialized distribution in the v1 binary format:
// 2 bytes for type tag + 4 × 8 bytes for params (param1, param2, start, max).
const SERIALIZED_DIST_SIZE: usize = 2 + 8 * 4;

// The 7 v1 events in wire order, mapped directly to their v3 equivalents.
const V1_EVENTS: [Event; 7] = [
    Event::NormalRecv,
    Event::DecoyRecv,    // v1: PaddingRecv
    Event::NormalQueued, // v1: NonPaddingSent / NormalSent
    Event::DecoyQueued,  // v1: PaddingSent
    Event::DelayBegin,   // v1: BlockingBegin
    Event::DelayEnd,     // v1: BlockingEnd
    Event::LimitReached,
];

/// Parse a v1 hex-encoded machine string into a v3 [`Machine`].
///
/// V1 strings are plain hex (no version prefix) encoding zlib-compressed
/// binary data whose first 2 bytes are a little-endian version number (`1`).
pub fn parse_v1(s: &str) -> Result<Machine, Error> {
    let compressed =
        hex::decode(s).map_err(|e| Error::Machine(format!("v1 hex decode failed: {e}")))?;

    let mut decoder = ZlibDecoder::new(compressed.as_slice());
    let mut buf = vec![0u8; MAX_DECOMPRESSED_SIZE];
    let bytes_read = decoder
        .read(&mut buf)
        .map_err(|e| Error::Machine(format!("v1 zlib decompress failed: {e}")))?;
    let buf = &buf[..bytes_read];

    if buf.len() < 2 {
        return Err(Error::Machine(
            "v1: buffer too small to read version".to_string(),
        ));
    }

    let (version_bytes, payload) = buf.split_at(2);
    let version = u16::from_le_bytes(version_bytes.try_into().unwrap());

    match version {
        1 => parse_v1_payload(payload),
        v => Err(Error::Machine(format!("v1: unsupported version {v}"))),
    }
}

fn parse_v1_payload(buf: &[u8]) -> Result<Machine, Error> {
    if buf.len() < 4 * 8 + 1 + 2 {
        return Err(Error::Machine(
            "v1: buffer too small for machine header".to_string(),
        ));
    }

    let mut r: usize = 0;

    let allowed_padding_packets = LittleEndian::read_u64(&buf[r..r + 8]);
    r += 8;
    let _max_padding_frac = LittleEndian::read_f64(&buf[r..r + 8]);
    r += 8;
    let allowed_blocked_microsec = LittleEndian::read_u64(&buf[r..r + 8]);
    r += 8;
    let _max_blocking_frac = LittleEndian::read_f64(&buf[r..r + 8]);
    r += 8;

    // 1-byte flag (include_small_packets) — not used in v3
    r += 1;

    let num_states = LittleEndian::read_u16(&buf[r..r + 2]) as usize;
    r += 2;

    // The binary format stores (V1_EVENTS.len() + 1) rows in the transition
    // matrix per state, even though only V1_EVENTS.len() rows are parsed.
    // The extra row is a legacy artifact of the original v1 format.
    let expected_state_len =
        3 * SERIALIZED_DIST_SIZE + 4 + (num_states + 2) * 8 * (V1_EVENTS.len() + 1);

    if buf[r..].len() != expected_state_len * num_states {
        return Err(Error::Machine(format!(
            "v1: expected {} bytes for {} states, got {}",
            expected_state_len * num_states,
            num_states,
            buf[r..].len()
        )));
    }

    let mut states = Vec::with_capacity(num_states);
    for _ in 0..num_states {
        let s = parse_v1_state(&buf[r..r + expected_state_len], num_states)?;
        r += expected_state_len;
        states.push(s);
    }

    // Map v1 field names to v3:
    //   allowed_padding_packets  → allowed_decoy_packets
    //   allowed_blocked_microsec → allowed_delay_microsec
    //   max_*_frac fields are dropped (moved to framework-level limits in v3)
    Machine::new(allowed_padding_packets, allowed_blocked_microsec, states)
        .map_err(|e| Error::Machine(e.to_string()))
}

fn parse_v1_state(buf: &[u8], num_states: usize) -> Result<State, Error> {
    let mut r = 0usize;

    let duration = parse_v1_dist(&buf[r..r + SERIALIZED_DIST_SIZE])?;
    r += SERIALIZED_DIST_SIZE;
    let limit = parse_v1_dist(&buf[r..r + SERIALIZED_DIST_SIZE])?;
    r += SERIALIZED_DIST_SIZE;
    let timeout = parse_v1_dist(&buf[r..r + SERIALIZED_DIST_SIZE])?;
    r += SERIALIZED_DIST_SIZE;

    let action_is_block: bool = buf[r] == 1;
    r += 1;
    let bypass: bool = buf[r] == 1;
    r += 1;
    let replace: bool = buf[r] == 1;
    r += 1;
    // 4th flag (limit_includes_nonpadding) — not used in v3
    r += 1;

    let action: Option<Action> = if let Some(timeout) = timeout {
        if action_is_block {
            let Some(duration) = duration else {
                return Err(Error::Machine(
                    "v1: BlockOutgoing action missing duration".to_string(),
                ));
            };
            // BlockOutgoing → DelayTraffic; use a large n to approximate
            // "block all outgoing packets" (best effort)
            Some(Action::DelayTraffic {
                bypass,
                replace,
                timeout,
                n: Dist {
                    dist: DistType::Uniform {
                        low: 0.0,
                        high: 0.0,
                    },
                    start: MAX_SAMPLED_DELAY_N as f64,
                    max: 0.0,
                },
                duration,
                limit,
            })
        } else {
            // SendPadding → DecoyTraffic; send exactly 1 decoy packet (n=1)
            Some(Action::DecoyTraffic {
                bypass,
                replace,
                timeout,
                n: Dist {
                    dist: DistType::Uniform {
                        low: 1.0,
                        high: 1.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
                limit,
            })
        }
    } else {
        None
    };

    let mut transitions: EnumMap<Event, Vec<Trans>> = enum_map! { _ => vec![] };

    for &event in V1_EVENTS.iter() {
        for i in 0..num_states + 2 {
            let v = LittleEndian::read_f64(&buf[r..r + 8]);
            r += 8;

            if v != 0.0 {
                let state = match i.cmp(&num_states) {
                    Ordering::Less => i,
                    // Index num_states was the "NOP" pseudo-state in v1,
                    // which has no v3 equivalent.
                    Ordering::Equal => {
                        return Err(Error::Machine(
                            "v1: NOP pseudo-state is not supported in v3".to_string(),
                        ));
                    }
                    Ordering::Greater => STATE_END,
                };
                transitions[event].push(Trans(state, v as f32));
            }
        }
    }

    let mut s = State::new(transitions);
    s.action = action;
    Ok(s)
}

fn parse_v1_dist(buf: &[u8]) -> Result<Option<Dist>, Error> {
    let type_tag = LittleEndian::read_u16(&buf[..2]);
    let param1 = LittleEndian::read_f64(&buf[2..10]);
    let param2 = LittleEndian::read_f64(&buf[10..18]);
    let start = LittleEndian::read_f64(&buf[18..26]);
    let max = LittleEndian::read_f64(&buf[26..34]);

    let Some(dist) = buf_to_dist_type(type_tag, param1, param2) else {
        return Ok(None);
    };

    Ok(Some(Dist { dist, start, max }))
}

fn buf_to_dist_type(tag: u16, p1: f64, p2: f64) -> Option<DistType> {
    match tag {
        0 => None,
        1 => Some(DistType::Uniform { low: p1, high: p2 }),
        2 => Some(DistType::Normal {
            mean: p1,
            stdev: p2,
        }),
        3 => Some(DistType::LogNormal { mu: p1, sigma: p2 }),
        4 => Some(DistType::Binomial {
            trials: p1 as u64,
            probability: p2,
        }),
        5 => Some(DistType::Geometric { probability: 0.0 }),
        6 => Some(DistType::Pareto {
            scale: p1,
            shape: p2,
        }),
        7 => Some(DistType::Poisson { lambda: 0.0 }),
        8 => Some(DistType::Weibull {
            scale: p1,
            shape: p2,
        }),
        9 => Some(DistType::Gamma {
            scale: p1,
            shape: p2,
        }),
        10 => Some(DistType::Beta {
            alpha: p1,
            beta: p2,
        }),
        _ => None,
    }
}
