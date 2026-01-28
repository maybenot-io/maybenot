pub mod common;

use std::{slice, time::Duration};

use common::run_test_sim;
use maybenot::{
    Machine,
    action::Action,
    constants::MAX_SAMPLED_DELAY_DURATION,
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};
use maybenot_simulator::{SimulatorArgs, network::Network, parse_trace, sim, sim_advanced};

use enum_map::enum_map;

#[test_log::test]
fn test_network_excessive_delay() {
    const EARLY_TRACE: &str = include_str!("EARLY_TEST_TRACE.log");

    // start with a reasonable 10ms delay: we should get events at the client
    let network = Network::new(Duration::from_millis(10), None);
    let pq = parse_trace(EARLY_TRACE, network);
    let trace = sim(&[], &[], &mut pq.clone(), network.delay, 10000, true);
    let client_trace = trace
        .clone()
        .into_iter()
        .filter(|t| t.client)
        .collect::<Vec<_>>();
    assert!(!client_trace.is_empty());

    // set a silly delay of 10s: this should result in zero events at the
    // client, because we hit the limit of events below before we get to the
    // first event at the client
    let network = Network::new(Duration::from_millis(10000), None);
    let pq = parse_trace(EARLY_TRACE, network);
    let trace = sim(&[], &[], &mut pq.clone(), network.delay, 10000, true);
    let client_trace = trace
        .clone()
        .into_iter()
        .filter(|t| t.client)
        .collect::<Vec<_>>();
    assert_eq!(client_trace.len(), 0);

    // increase the limit of events to 100000: this should result in all events
    let trace = sim(&[], &[], &mut pq.clone(), network.delay, 100000, true);
    let client_trace = trace
        .clone()
        .into_iter()
        .filter(|t| t.client)
        .collect::<Vec<_>>();
    // 21574 is the number of events in EARLY_TRACE
    assert_eq!(client_trace.len(), 21574);
}

#[test_log::test]
fn test_network_bottleneck() {
    // for added_delay() due to 3 pps in the bottleneck, send 6 events right
    // away and verify increasing delay at the server when receiving the 4th to
    // 6th event
    let input = "0,nq\n0,nq\n0,nq\n0,nq\n0,nq\n0,nq\n";
    let network = Network::new(Duration::from_millis(3), Some(3));
    let mut sq = parse_trace(input, network);
    let args = SimulatorArgs::new(network, 20, true);
    let trace = sim_advanced(&[], &[], &mut sq, &args);

    let client_trace = trace
        .clone()
        .into_iter()
        .filter(|t| t.client)
        .collect::<Vec<_>>();
    assert_eq!(client_trace.len(), 6);
    assert_eq!(client_trace[0].time, client_trace[5].time);

    let server_trace = trace
        .clone()
        .into_iter()
        .filter(|t| !t.client)
        .collect::<Vec<_>>();
    assert_eq!(server_trace.len(), 6);
    assert_eq!(server_trace[0].time, server_trace[2].time);
    // increasing delay at the server
    assert_eq!(
        server_trace[3].time - server_trace[2].time,
        Duration::from_secs(1) / 3
    );
    assert_eq!(
        server_trace[4].time - server_trace[3].time,
        Duration::from_secs(1) / 3
    );
    assert_eq!(
        server_trace[5].time - server_trace[4].time,
        Duration::from_secs(1) / 3
    );
}

#[test_log::test]
fn test_delay_packet_reordering() {
    // The purpose of this test is to test packet reordering in the simulator,
    // using bypassable delay to create a constant-rate defense on one side
    // of the connection, with significant simulated delays as a consequence.

    // The constant-rate defense is a "ratio3 machine". The ratio3 machine
    // blocks all outgoing traffic at the client (after the first packet) and
    // then attempts to send one packet for every 3 received packets. If there
    // is real traffic queued up (from the delay), real traffic will be sent,
    // otherwise, a decoy packet is sent.

    // The trace is the first 40 cells (out of 5092) from a trace part of the
    // "BigEnough" dataset by Mathews et al., "SoK: A Critical Evaluation of
    // Efficient Website Fingerprinting Defenses" SP 2023.
    const BE000_TRACE: &str = include_str!("BE000.log");
    // cat crates/maybenot-simulator/tests/BE000.log (time rewritten to make it
    // easier to follow):
    // 0,r
    // 170ms,r
    // 180ms,s
    // 430ms,r
    // 430ms,s
    // 690ms,r
    // 700ms,s
    // 700ms,s
    // 990ms,r
    // 990ms,r
    // 990ms,r
    // 990ms,r
    // 990ms,r
    // 990ms,r
    // 990ms,r
    // 1120ms,r
    // 1120ms,r
    // 1120ms,r
    // 1120ms,s
    // 1380ms,r
    // 1380ms,s
    // 1680ms,r
    // 1680ms,r
    // 1930ms,s
    // 1930ms,s
    // 2200ms,r
    // 2200ms,s
    // 2300ms,r
    // 2430ms,r
    // 2430ms,r
    // 2430ms,r
    // 2430ms,s
    // 2880ms,s
    // 3220ms,r
    // 3220ms,r
    // 3220ms,r
    // 3220ms,r
    // 3300ms,r
    // 3300ms,r
    // 3300ms,r

    // NOTE the 50ms network delay between the client and the server
    let delay = Duration::from_millis(50);
    let network = Network::new(delay, None);
    let pq = parse_trace(BE000_TRACE, network);
    let trace = sim(
        &[ratio3_machine()],
        &[],
        &mut pq.clone(),
        network.delay,
        10000,
        true,
    );
    let client_trace = trace
        .clone()
        .into_iter()
        .filter(|t| t.client)
        .collect::<Vec<_>>();
    assert_eq!(client_trace.len(), 40);

    assert!(client_trace[0].event.is_event(Event::PacketRecv));
    assert!(client_trace[1].event.is_event(Event::PacketRecv));
    // the send is blocked
    assert!(client_trace[2].event.is_event(Event::PacketRecv));
    // a send is blocked again
    assert!(client_trace[3].event.is_event(Event::PacketRecv));
    assert!(client_trace[4].event.is_event(Event::PacketSent));
    assert!(!client_trace[4].contains_decoy);

    // two sends are blocked and queued up starting at 700ms

    for event in client_trace.iter().take(12).skip(5) {
        // next, we have 7 received packets, happening at the exact same time
        // (thanks to the example trace aggressive truncation of timestamps, not
        // likely in practice)
        assert!(event.event.is_event(Event::PacketRecv));
    }
    // the ratio3 machine only has time to trigger a decoy packet once, now
    // sending the packet queued at 430ms
    assert!(client_trace[12].event.is_event(Event::PacketSent));
    assert!(!client_trace[12].contains_decoy);

    for event in client_trace.iter().take(16).skip(13) {
        // 3 received packets, happening at the exact same time again
        assert!(event.event.is_event(Event::PacketRecv));
    }

    assert!(client_trace[16].event.is_event(Event::PacketSent));

    // receive one packet at 1380ms
    assert!(client_trace[17].event.is_event(Event::PacketRecv));

    // receive two packets at 1680ms
    for event in client_trace.iter().take(20).skip(18) {
        assert!(event.event.is_event(Event::PacketRecv));
    }

    assert!(client_trace[20].event.is_event(Event::PacketSent));
    assert!(!client_trace[20].contains_decoy);
    assert!(client_trace[21].event.is_event(Event::PacketRecv));
    assert!(client_trace[22].event.is_event(Event::PacketRecv));

    // receive three packets at 2430ms
    for event in client_trace.iter().take(26).skip(23) {
        assert!(event.event.is_event(Event::PacketRecv));
    }
    // one sent is blocked
    assert!(client_trace[26].event.is_event(Event::PacketSent));
    assert!(!client_trace[26].contains_decoy);

    // receive four packets at 3220ms
    for event in client_trace.iter().take(31).skip(27) {
        assert!(event.event.is_event(Event::PacketRecv));
    }
    assert!(client_trace[31].event.is_event(Event::PacketSent));
    assert!(!client_trace[31].contains_decoy);

    for event in client_trace.iter().take(35).skip(32) {
        assert!(event.event.is_event(Event::PacketRecv));
    }
}

fn ratio3_machine() -> Machine {
    let n = 3;
    let mut states = vec![];

    // start state 0
    let start_state = State::new(enum_map! {
       Event::PacketSent | Event::PacketRecv => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start_state);

    // delay state 1
    let mut delay_state = State::new(enum_map! {
        Event::DelayBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    delay_state.action = Some(Action::DelayTraffic {
        bypass: true,
        replace: true,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 0.0,
            max: 0.0,
        },
        duration: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: MAX_SAMPLED_DELAY_DURATION,
            max: 0.0,
        },
        limit: None,
    });
    states.push(delay_state);

    // recv states 2..n+2
    for i in 0..n {
        states.push(State::new(enum_map! {
           // to the next state
           Event::PacketRecv => vec![Trans(3+i, 1.0)],
           // something else let traffic through, back to counting
           //Event::PacketSent => vec![Trans(2, 1.0)],
           _ => vec![],
        }));
    }

    // padding state n+2
    let mut padding_state = State::new(enum_map! {
        Event::DecoyQueued => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    padding_state.action = Some(Action::DecoyTraffic {
        bypass: true,
        replace: true,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 0.0,
            max: 0.0,
        },
        n: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 1.0,
            max: 0.0,
        },
        limit: None,
    });
    states.push(padding_state);

    Machine::new(u64::MAX, 0.0, u64::MAX, 0.0, states).unwrap()
}

fn delay_machine(delay_duration: DistType, padding_delay: DistType) -> Machine {
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut s1 = State::new(enum_map! {
        Event::DelayBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::DelayTraffic {
        bypass: true,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 0.0,
            max: 0.0,
        },
        duration: Dist {
            dist: delay_duration,
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s2 = State::new(enum_map! {
        _ => vec![],
    });
    s2.action = Some(Action::DecoyTraffic {
        bypass: true,
        replace: true,
        timeout: Dist {
            dist: padding_delay,
            start: 0.0,
            max: 0.0,
        },
        n: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 1.0,
            max: 0.0,
        },
        limit: None,
    });
    Machine::new(0, 0.0, 0, 0.0, vec![s0, s1, s2]).unwrap()
}

#[test_log::test]
fn test_network_aggregate_delay_one_packet() {
    // block for 5ms, pad after 100ms
    let m = delay_machine(
        DistType::Uniform {
            low: 5.0 * 1000.0,
            high: 5.0 * 1000.0,
        },
        DistType::Uniform {
            low: 100.0 * 1000.0,
            high: 100.0 * 1000.0,
        },
    );
    let delay = Duration::from_millis(10);

    // machine only at client
    let base = "0,nq 1,nq 40,nq 40,nr 41,nq 41,nr";
    // delay at 0, delaying 1 by 4 until 5:
    // - delay goes into effect at 41 at client
    // - delay goes into effect at 31 at server
    let result = "0,ps 5,ps 40,ps 40,pr 45,ps 45,pr";
    run_test_sim(
        base,
        result,
        delay,
        slice::from_ref(&m),
        &[],
        true, // client trace
        50,
        true, // only packets
        true, // ms, needed because delay window is expressed in ms
    );

    // machine at client and server
    let base = "0,nq 1,nq 30,nr 31,nr 40,nq 41,nq 41,nr 80,nr";
    // @client: delay at 0, delaying 1 by 4 until 5:
    // - delay goes into effect at 41 at client
    // - delay goes into effect at 31 at server
    // @server: delay at 20, delaying 21 until 25
    // - delay goes into effect at 31 at client
    // - delay goes into effect at 61 at server
    let result = "0,ps 5,ps 30,pr 35,pr 45,pr 48,ps 49,ps 88,pr";
    run_test_sim(
        base,
        result,
        delay,
        slice::from_ref(&m),
        slice::from_ref(&m),
        true,
        50,
        true,
        true,
    );
}

#[test_log::test]
fn test_network_aggregate_delay_many_packets() {
    // block for 5ms, pad after 100ms
    let m = delay_machine(
        DistType::Uniform {
            low: 5.0 * 1000.0,
            high: 5.0 * 1000.0,
        },
        DistType::Uniform {
            low: 100.0 * 1000.0,
            high: 100.0 * 1000.0,
        },
    );
    let delay = Duration::from_millis(10);

    // machine only at client
    let base = "0,nq 1,nq 2,nq 2,nq 3,nq 40,nq 40,nr 42,nq 42,nr";
    // delay at 0, delaying burst 1-2 by 3 (tail, window 1ms) until 5:
    // - delay goes into effect at 42 at client
    // - delay goes into effect at 32 at server
    let result = "0,ps 5,ps 5,ps 5,ps 5,ps 40,ps 40,pr 45,ps 45,pr";
    run_test_sim(
        base,
        result,
        delay,
        slice::from_ref(&m),
        &[],
        true,
        50,
        true,
        true,
    );

    // machine at client and server
    let base = "0,nq 1,nq 2,nq 2,nq 3,nq 29,nr 30,nr 31,nr 42,nq 80,nr";
    // delay at 0, delaying burst 1-2 by 3 (tail, window 1ms) until 5:
    // - delay goes into effect at 42 at client
    // - delay goes into effect at 32 at server
    // @server: delay at 19, delaying 20-21 by 4 (tail, window 1ms) until 25
    // - delay goes into effect at 30 at client
    // - delay goes into effect at 60 at server
    let result = "0,ps 5,ps 5,ps 5,ps 5,ps 29,pr 34,pr 34,pr 49,ps 87,pr";
    run_test_sim(
        base,
        result,
        delay,
        slice::from_ref(&m),
        slice::from_ref(&m),
        true,
        50,
        true,
        true,
    );
}

#[test_log::test]
fn test_network_aggregate_delay_many_packets_normal_no_delay() {
    // block for 5ms, pad after 100ms
    let m = delay_machine(
        DistType::Uniform {
            low: 5.0 * 1000.0,
            high: 5.0 * 1000.0,
        },
        DistType::Uniform {
            low: 100.0 * 1000.0,
            high: 100.0 * 1000.0,
        },
    );
    let delay = Duration::from_millis(10);

    // machine only at client
    let base = "0,nq 4,nq 5,nq 45,nq 45,nr 47,nq 47,nr";
    // delay at 0, delaying 4 BUT also 5 normal so no delay:
    let result = "0,ps 5,ps 5,ps 45,ps 45,pr 47,ps 47,pr";
    run_test_sim(
        base,
        result,
        delay,
        slice::from_ref(&m),
        &[],
        true,
        50,
        true,
        true,
    );

    // machine at client and server
    let base = "0,nq 4,nq 5,nq 45,nq 45,nr 47,nq 49,nr 50,nr";
    let result = "0,ps 5,ps 5,ps 45,ps 45,pr 47,ps 50,pr 50,pr";
    run_test_sim(
        base,
        result,
        delay,
        slice::from_ref(&m),
        slice::from_ref(&m),
        true,
        50,
        true,
        true,
    );
}

#[test_log::test]
fn test_network_aggregate_decoy_bypass_replace_one_packet() {
    // block for 100ms, pad after 5ms
    let m = delay_machine(
        DistType::Uniform {
            low: 100.0 * 1000.0,
            high: 100.0 * 1000.0,
        },
        DistType::Uniform {
            low: 5.0 * 1000.0,
            high: 5.0 * 1000.0,
        },
    );
    let delay = Duration::from_millis(10);

    // machine only at client
    let base = "0,nq 1,nq 40,nq 40,nr 41,nq 41,nr";
    // delay at 0, delaying 1 by 4 until padding is sent at 5:
    // - delay goes into effect at 41 at client
    // - delay goes into effect at 31 at server
    let result = "0,ps 5,ps 40,pr 45,pr 100,ps 100,ps";
    run_test_sim(
        base,
        result,
        delay,
        slice::from_ref(&m),
        &[],
        true,
        50,
        true,
        true,
    );

    // machine at client and server
    let base = "0,nq 1,nq 40,nq 40,nr 41,nq 41,nr 100,nr 100,nq";
    // the 1,nq is delayed by 4
    // the 100,nr is queued up at the server at 94
    // the 40,nq is delayed until 100 (block expiry), resulting in 60 delay
    // the 100,nr, queued up at server at 94, is sent when delay expires at 130,
    // resulting in 36 delay
    // total delay: 36+4+60 = 100
    let result = "0,ps 5,ps 40,pr 45,pr 100,ps 100,ps 140,pr 200,ps";
    run_test_sim(
        base,
        result,
        delay,
        slice::from_ref(&m),
        slice::from_ref(&m),
        true,
        50,
        true,
        true,
    );
}

#[test_log::test]
fn test_network_aggregate_padding_bypass_replace_one_packet_normal() {
    // block for 100ms, pad after 1ms
    let m = delay_machine(
        DistType::Uniform {
            low: 100.0 * 1000.0,
            high: 100.0 * 1000.0,
        },
        DistType::Uniform {
            low: 2.0 * 1000.0,
            high: 2.0 * 1000.0,
        },
    );
    let delay = Duration::from_millis(10);

    // machine only at client
    let base = "0,nq 1500,nq 2499,nq 40000,nq 40000,nr 41000,nq 41000,nr";
    // the decoy at 2000 sends packet blocked at 15000, but since 2499 is
    // within the 1000 microseconds window, no delay is added
    let result = "0,ps 2000,ps 40000,pr 41000,pr 100000,ps 100000,ps 100000,ps";
    run_test_sim(
        base,
        result,
        delay,
        slice::from_ref(&m),
        &[],
        true,
        50,
        true,
        false,
    );

    // machine at client and server
    let base = "0,nq 1500,nq 2499,nq 40000,nq 40000,nr 41000,nq 41500,nr 42499,nr";
    // as above for the client, for the server the decoy at 42000 sends packet
    // blocked at 415000, but since 42499 is within the 1000 microseconds
    // window, no delay is added
    let result = "0,ps 2000,ps 40000,pr 42000,pr 100000,ps 100000,ps 100000,ps 140000,pr";
    run_test_sim(
        base,
        result,
        delay,
        slice::from_ref(&m),
        slice::from_ref(&m),
        true,
        50,
        true,
        false,
    );
}

#[test_log::test]
fn test_network_aggregate_decoy_bypass_replace_many_packets() {
    // block for 100ms, pad after 5ms
    let m = delay_machine(
        DistType::Uniform {
            low: 100.0 * 1000.0,
            high: 100.0 * 1000.0,
        },
        DistType::Uniform {
            low: 5.0 * 1000.0,
            high: 5.0 * 1000.0,
        },
    );
    let delay = Duration::from_millis(10);

    // machine only at client
    let base = "0,nq 1,nq 40,nq 40,nr 41,nq 41,nr";
    // causes 4 delay by delay 1 until 5, in effect at server at 31
    let result = "0,ps 5,ps 40,pr 45,pr 100,ps 100,ps";
    run_test_sim(
        base,
        result,
        delay,
        slice::from_ref(&m),
        &[],
        true,
        50,
        true,
        true,
    );

    // machine at client and server
    let base = "0,nq 1,nq 40,nq 41,nr 42,nq 42,nr 50,nr 70,nq";
    let result = "0,ps 5,ps 45,pr 50,pr 100,ps 100,ps 100,ps 145,pr";
    run_test_sim(
        base,
        result,
        delay,
        slice::from_ref(&m),
        slice::from_ref(&m),
        true,
        50,
        true,
        true,
    );
}

#[test_log::test]
fn test_network_aggregate_decoy_bypass_replace_many_packets_window() {
    // block for 100ms, pad after 5ms
    let m = delay_machine(
        DistType::Uniform {
            low: 100.0 * 1000.0,
            high: 100.0 * 1000.0,
        },
        DistType::Uniform {
            low: 5.0 * 1000.0,
            high: 5.0 * 1000.0,
        },
    );
    let delay = Duration::from_millis(10);

    // machine only at client
    let base = "0,nq 1,nq 2,nq 40,nq 40,nr 41,nq 41,nr";
    let result = "0,ps 5,ps 40,pr 41,pr 100,ps 100,ps 100,ps";
    run_test_sim(
        base,
        result,
        delay,
        slice::from_ref(&m),
        &[],
        true,
        50,
        true,
        true,
    );

    // machine at client and server
    let base = "0,nq 1,nq 2,nq 40,nq 40,nr 41,nq 41,nr 42,nr";
    let result = "0,ps 5,ps 40,pr 45,pr 100,ps 100,ps 100,ps 140,pr";
    run_test_sim(
        base,
        result,
        delay,
        slice::from_ref(&m),
        slice::from_ref(&m),
        true,
        50,
        true,
        true,
    );
}
