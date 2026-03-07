//! Parser for v2 bincode-encoded machine strings.
//!
//! V2 machines are serialized as: `"02"` prefix + base64(zlib(bincode(MachineV2))).
//! This module defines the v2-specific structs with their original field names and
//! enum variants, deserializes them with bincode 1.3, then converts to v3 [`Machine`].

use std::io::Read;

use base64::prelude::*;
use bincode::Options;
use enum_map::{EnumMap, enum_map};
use flate2::read::ZlibDecoder;
use maybenot::{
    Error, Machine,
    action::{Action, Timer},
    constants::{MAX_DECOMPRESSED_SIZE, MAX_SAMPLED_DELAY_N},
    counter::Counter,
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};
use serde::{Deserialize, Serialize};

// V2 had 13 events; V3 has 14 (added Congestion at index 13).
const EVENT_NUM_V2: usize = 13;

// V2-to-V3 event index mapping (position = v2 index, value = v3 Event).
const V2_TO_V3_EVENTS: [Event; EVENT_NUM_V2] = [
    Event::NormalRecv,   // 0  NormalRecv    → NormalRecv
    Event::DecoyRecv,    // 1  PaddingRecv   → DecoyRecv
    Event::PacketRecv,   // 2  TunnelRecv    → PacketRecv
    Event::NormalQueued, // 3  NormalSent    → NormalQueued
    Event::DecoyQueued,  // 4  PaddingSent   → DecoyQueued
    Event::PacketSent,   // 5  TunnelSent    → PacketSent
    Event::DelayBegin,   // 6  BlockingBegin → DelayBegin
    Event::DelayEnd,     // 7  BlockingEnd   → DelayEnd
    Event::LimitReached, // 8  LimitReached  → LimitReached
    Event::CounterZero,  // 9  CounterZero   → CounterZero
    Event::TimerBegin,   // 10 TimerBegin    → TimerBegin
    Event::TimerEnd,     // 11 TimerEnd      → TimerEnd
    Event::Signal,       // 12 Signal        → Signal
                         // index 13 (Congestion) is new in v3 and absent in v2; left as None
];

// V2 machine struct with original field names (bincode layout must match exactly).
#[derive(Deserialize, Serialize)]
pub(crate) struct MachineV2 {
    allowed_padding_packets: u64,
    // Dropped in v3: moved to framework-level limits
    _max_padding_frac: f64,
    allowed_blocked_microsec: u64,
    // Dropped in v3: moved to framework-level limits
    _max_blocking_frac: f64,
    states: Vec<StateV2>,
}

// V2 state struct (13-event transition array).
#[derive(Deserialize, Serialize)]
pub(crate) struct StateV2 {
    action: Option<ActionV2>,
    counter: (Option<Counter>, Option<Counter>),
    transitions: [Option<Vec<Trans>>; EVENT_NUM_V2],
}

// V2 action enum with original variant names.
// Cancel and UpdateTimer are identical to v3; SendPadding and BlockOutgoing
// are converted to DecoyTraffic and DelayTraffic respectively.
#[derive(Deserialize, Serialize)]
pub(crate) enum ActionV2 {
    Cancel {
        timer: Timer,
    },
    SendPadding {
        bypass: bool,
        replace: bool,
        timeout: Dist,
        limit: Option<Dist>,
    },
    BlockOutgoing {
        bypass: bool,
        replace: bool,
        timeout: Dist,
        duration: Dist,
        limit: Option<Dist>,
    },
    UpdateTimer {
        replace: bool,
        duration: Dist,
        limit: Option<Dist>,
    },
}

/// Parse a v2 base64-encoded machine string into a v3 [`Machine`].
///
/// V2 strings start with the `"02"` prefix followed by
/// base64(zlib(bincode(MachineV2))).
pub fn parse_v2(s: &str) -> Result<Machine, Error> {
    if s.len() < 3 {
        return Err(Error::Machine("v2: string too short".to_string()));
    }
    if !s.is_ascii() {
        return Err(Error::Machine("v2: string is not ASCII".to_string()));
    }
    if &s[..2] != "02" {
        return Err(Error::Machine("v2: expected '02' prefix".to_string()));
    }

    let body = &s[2..];
    let compressed = BASE64_STANDARD
        .decode(body.as_bytes())
        .map_err(|e| Error::Machine(format!("v2: base64 decode failed: {e}")))?;

    let mut decoder = ZlibDecoder::new(compressed.as_slice());
    let mut buf = vec![0u8; MAX_DECOMPRESSED_SIZE];
    let bytes_read = decoder
        .read(&mut buf)
        .map_err(|e| Error::Machine(format!("v2: zlib decompress failed: {e}")))?;

    let bincoder = bincode::DefaultOptions::new().with_limit(MAX_DECOMPRESSED_SIZE as u64);
    let machine_v2: MachineV2 = bincoder
        .deserialize(&buf[..bytes_read])
        .map_err(|e| Error::Machine(format!("v2: bincode deserialize failed: {e}")))?;

    let machine = convert_machine(machine_v2);
    machine.validate()?;
    Ok(machine)
}

fn convert_machine(m: MachineV2) -> Machine {
    // max_padding_frac and max_blocking_frac are dropped — moved to
    // framework-level limits in v3 (best-effort conversion).
    let states = m.states.into_iter().map(convert_state).collect();
    Machine {
        allowed_decoy_packets: m.allowed_padding_packets,
        allowed_delay_microsec: m.allowed_blocked_microsec,
        states,
    }
}

fn convert_state(s: StateV2) -> State {
    let mut transitions: EnumMap<Event, Vec<Trans>> = enum_map! { _ => vec![] };

    for (v2_idx, v3_event) in V2_TO_V3_EVENTS.iter().enumerate() {
        if let Some(trans_vec) = s.transitions[v2_idx].clone() {
            if !trans_vec.is_empty() {
                transitions[*v3_event] = trans_vec;
            }
        }
    }

    let mut state = State::new(transitions);
    state.action = s.action.map(convert_action);
    state.counter = s.counter;
    state
}

fn convert_action(a: ActionV2) -> Action {
    match a {
        ActionV2::Cancel { timer } => Action::Cancel { timer },
        ActionV2::SendPadding {
            bypass,
            replace,
            timeout,
            limit,
        } => Action::DecoyTraffic {
            bypass,
            replace,
            timeout,
            // v1/v2 sent exactly one padding packet per action
            n: Dist {
                dist: DistType::Uniform {
                    low: 1.0,
                    high: 1.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit,
        },
        ActionV2::BlockOutgoing {
            bypass,
            replace,
            timeout,
            duration,
            limit,
        } => Action::DelayTraffic {
            bypass,
            replace,
            timeout,
            // Approximate "block all" with n = MAX_SAMPLED_DELAY_N (best effort)
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
        },
        ActionV2::UpdateTimer {
            replace,
            duration,
            limit,
        } => Action::UpdateTimer {
            replace,
            duration,
            limit,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maybenot::state::Trans;

    fn v2_machine_string(m: &MachineV2) -> String {
        use base64::prelude::*;
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let bincoder = bincode::DefaultOptions::new();
        let encoded = bincoder.serialize(m).unwrap();
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&encoded).unwrap();
        let compressed = enc.finish().unwrap();
        format!("02{}", BASE64_STANDARD.encode(&compressed))
    }

    fn noop_v2() -> MachineV2 {
        MachineV2 {
            allowed_padding_packets: 0,
            _max_padding_frac: 0.0,
            allowed_blocked_microsec: 0,
            _max_blocking_frac: 0.0,
            states: vec![StateV2 {
                action: None,
                counter: (None, None),
                transitions: [const { None::<Vec<Trans>> }; EVENT_NUM_V2],
            }],
        }
    }

    #[test]
    fn v2_noop_roundtrip() {
        let s = v2_machine_string(&noop_v2());
        assert!(s.starts_with("02"), "expected '02' prefix");
        let m = parse_v2(&s).expect("parse_v2 noop failed");
        m.validate().expect("validate failed");
        assert!(
            m.serialize().starts_with("03"),
            "expected v3 re-serialization"
        );
        assert_eq!(m.allowed_decoy_packets, 0);
        assert_eq!(m.allowed_delay_microsec, 0);
    }

    #[test]
    fn v2_budget_preserved() {
        let mut machine_v2 = noop_v2();
        machine_v2.allowed_padding_packets = 500;
        machine_v2._max_padding_frac = 0.5;
        machine_v2.allowed_blocked_microsec = 1_000_000;
        machine_v2._max_blocking_frac = 0.1;

        let s = v2_machine_string(&machine_v2);
        let m = parse_v2(&s).expect("parse_v2 budget failed");
        m.validate().expect("validate failed");
        assert_eq!(m.allowed_decoy_packets, 500);
        assert_eq!(m.allowed_delay_microsec, 1_000_000);
    }

    #[test]
    fn v2_send_padding_action() {
        use maybenot::dist::{Dist, DistType};
        let timeout = Dist {
            dist: DistType::Uniform {
                low: 10.0,
                high: 10.0,
            },
            start: 0.0,
            max: 0.0,
        };
        let mut machine_v2 = noop_v2();
        machine_v2.states[0].action = Some(ActionV2::SendPadding {
            bypass: false,
            replace: true,
            timeout,
            limit: None,
        });
        // Add a self-transition so the machine is valid (action state must be reachable)
        machine_v2.states[0].transitions[0] = Some(vec![Trans(0, 1.0)]);

        let s = v2_machine_string(&machine_v2);
        let m = parse_v2(&s).expect("parse_v2 SendPadding failed");
        m.validate().expect("validate failed");

        // Should have been converted to DecoyTraffic
        match m.states[0].action {
            Some(maybenot::action::Action::DecoyTraffic { replace, .. }) => {
                assert!(replace, "replace flag should be preserved");
            }
            other => panic!("expected DecoyTraffic, got {other:?}"),
        }
    }

    #[test]
    fn v2_invalid_prefix_rejected() {
        assert!(parse_v2("03somedata").is_err());
        assert!(parse_v2("01somedata").is_err());
    }

    #[test]
    fn v2_cancel_action() {
        let mut machine_v2 = noop_v2();
        machine_v2.states[0].action = Some(ActionV2::Cancel {
            timer: Timer::Action,
        });
        machine_v2.states[0].transitions[0] = Some(vec![Trans(0, 1.0)]);

        let s = v2_machine_string(&machine_v2);
        let m = parse_v2(&s).expect("parse_v2 Cancel failed");
        m.validate().expect("validate failed");

        match m.states[0].action {
            Some(maybenot::action::Action::Cancel {
                timer: Timer::Action,
            }) => {}
            other => panic!("expected Cancel(Action), got {other:?}"),
        }
    }

    #[test]
    fn parse_legacy_routes_to_v2() {
        // Verify that parse_legacy correctly dispatches "02..." to parse_v2.
        let s = v2_machine_string(&noop_v2());
        let m = crate::parse_legacy(&s).expect("parse_legacy v2 routing failed");
        m.validate().expect("validate failed");
        assert!(m.serialize().starts_with("03"));
    }
}
