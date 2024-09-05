pub mod common;

use std::time::Duration;

use common::run_test_sim;
use maybenot::{
    action::Action,
    constants::MAX_SAMPLED_BLOCK_DURATION,
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
    Machine,
};
use maybenot_simulator::{
    linktrace::{load_linktrace_from_file, LinkTrace},
    network::{ExtendedNetwork, Network},
    parse_trace, sim, sim_advanced, SimulatorArgs,
};

use enum_map::enum_map;

#[test_log::test]
fn test_network_excessive_delay() {
    const EARLY_TRACE: &str = include_str!("EARLY_TEST_TRACE.log");

    // start with a reasonable 10ms delay: we should get events at the client
    let network = Network::new(Duration::from_millis(10), None);
    let pq = parse_trace(EARLY_TRACE, &network);
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
    let pq = parse_trace(EARLY_TRACE, &network);
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
    let input = "0,sn\n0,sn\n0,sn\n0,sn\n0,sn\n0,sn\n";
    let network = Network::new(Duration::from_millis(3), Some(3));
    let mut sq = parse_trace(input, &network);
    let args = SimulatorArgs::new(&network, 20, true);
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

/// This test is designed to be run when extended enum is fully implemented
/// TODO: Find out why first packet sometimes do not get txdelay added
#[test_log::test]
fn test_network_extendednetwork() {
    // for added_delay() due to 3 pps in the bottleneck, send 6 events right
    // away and verify increasing delay at the server when receiving the 4th to
    // 6th event
    let input = "0,sn\n0,sn\n0,sn\n0,sn\n0,sn\n0,sn\n";
    let network = Network::new(Duration::from_millis(3), Some(3));
    let linktrace = load_linktrace_from_file("tests/ether100M_synth5K.ltbin.gz")
        .expect("Failed to load LinkTrace ltbin from file");
    let network_lt = ExtendedNetwork::new_linktrace(network.clone(), &linktrace);

    let mut sq = parse_trace(input, &network);
    let args = SimulatorArgs::new(&network, 20, true);
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

    // Second packet does not get txdealy, unclear why
    /*
    assert_eq!(
        server_trace[1].time - server_trace[0].time,
        Duration::from_millis(120)
    );
    */
    assert_eq!(
        server_trace[2].time - server_trace[1].time,
        Duration::from_micros(120)
    );
    assert_eq!(
        server_trace[3].time - server_trace[2].time,
        Duration::from_micros(120)
    );
    assert_eq!(
        server_trace[4].time - server_trace[3].time,
        Duration::from_micros(120)
    );

    println!("{:?}{:?}", server_trace, client_trace);
    assert_eq!(1, 0, "Forced stop");
}

/// This test is designed to be run when netowrk has been edited to the
/// Linktrace version of NetworkBottleneck, using the  ether100M_synth5M.ltbin file.
/// TODO: Find out why first packet sometimes do not get txdelay added
#[test_log::test]
fn test_network_linktrace() {
    // for added_delay() due to 3 pps in the bottleneck, send 6 events right
    // away and verify increasing delay at the server when receiving the 4th to
    // 6th event
    let input = "0,sn\n0,sn\n0,sn\n0,sn\n0,sn\n0,sn\n";
    let network = Network::new(Duration::from_millis(3), Some(3));
    let mut sq = parse_trace(input, &network);
    let args = SimulatorArgs::new(&network, 20, true);
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

    // Second packet does not get txdealy, unclear why
    /*
    assert_eq!(
        server_trace[1].time - server_trace[0].time,
        Duration::from_millis(120)
    );
    */
    assert_eq!(
        server_trace[2].time - server_trace[1].time,
        Duration::from_micros(120)
    );
    assert_eq!(
        server_trace[3].time - server_trace[2].time,
        Duration::from_micros(120)
    );
    assert_eq!(
        server_trace[4].time - server_trace[3].time,
        Duration::from_micros(120)
    );

    println!("{:?}{:?}", server_trace, client_trace);
    assert_eq!(1, 0, "Forced stop");
}

#[test_log::test]
fn test_network_aggregate_base_delay_on_bypass_replace() {
    // this test combined the bypass and replace flags for blocking and padding,
    // as well as our network model that causes aggregate base delays ... it's
    // an annoying test to write and follow along, but it's also hits on many
    // important aspects of the simulator

    // a simple machine, running at the client and the server, that starts
    // bypassable blocking for 5us, then after 2us sends a replaceable and
    // bypassable padding packet
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut s1 = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::BlockOutgoing {
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
            dist: DistType::Uniform {
                low: 5.0,
                high: 5.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s2 = State::new(enum_map! {
        _ => vec![],
    });
    s2.action = Some(Action::SendPadding {
        bypass: true,
        replace: true,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 2.0,
                high: 2.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let m = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1, s2]).unwrap();
    let delay = Duration::from_micros(3);

    // NOTE: trace from the perspective of the client
    let base = "0,sn 1,sn 2,sn 8,sn 11,sn 12,rn 13,rn 14,sn 15,sn";
    let mut result = String::new();
    // the first normal event starts the results, causing the client machine to
    // transition to state 1
    result.push_str("0,sn ");
    // the event is turned into a sent packet, because it has higher priority
    // than blocking
    result.push_str("0,st ");
    // the 5u bypassable blocking kicks in from the machine, causing the machine
    // to transition to state 2, scheduling padding in 2us
    result.push_str("0,bb ");
    // the sn event @1 is triggered from the base trace, but not the following st
    // due to the blocking
    result.push_str("1,sn ");
    // the sn event @2 is triggered from the base trace, but not the following
    // st due to the blocking
    result.push_str("2,sn ");
    // the machine's padding event is triggered: it has bypass and replace flags
    // set, and we got a normal packet queued up from 1us, so we replace the
    // padding with the normal packet
    result.push_str("2,sp ");
    // the normal packet from 1us is sent, now at 2us, propagating the base
    // delay of 1us in it: arriving at the receiver at 5us, due to the 3us
    // network delay,and queueing a base delay of 1us to come into effect in 2x
    // delay = 2*3us + 5us = 11us
    result.push_str("2,st ");
    // at at 5us, the blocking ends, so the first thing that happens is that the
    // blocked packet from 2us is sent, causing the base delay of 3us to be
    // propagated, arriving at the server at 8us
    result.push_str("5,st ");
    // the blocking end event at the client (has lower priority than the st so
    // it happens after, but still at time 5us)
    result.push_str("5,be ");

    // NOTE: at 8us, the two normal packets have arrived at the server and
    // queued a base delay of 3+1=4us in total, to come into effect in 2x delay
    // = 2*3us + 8us = 14us

    // from the base trace
    result.push_str("8,sn ");
    // the packet is sent
    result.push_str("8,st ");

    // NOTE: in between this and the next event in the client trace:
    // - the 12,rn event at the server is sent at 12-3=9us
    // - this causes the server's machine to start blocking for 5us and
    //   transitioning, scheduling padding to be sent in 2us
    // - at 10, the 13,rn event (in the base trace) at the server is blocked
    // - at 11, the server receives the packet sent at 8us
    // - at 11, the padding is sent at the server and replaces the blocked
    //   packet at 10, with a base delay of 1us to be propagated to the client
    // - at 11, the delayed queueing of the base delay of 1us from the padding
    //   packet at 2us is in effect

    // the 11,sn event in the base trace is delayed by 1us, so it's sent at 12us
    result.push_str("12,sn ");
    // in a packet
    result.push_str("12,st ");
    // the 12us rn event
    result.push_str("12,rt ");
    // and the event is received
    result.push_str("12,rn ");

    // the padding packet the server sent @11us
    result.push_str("14,rt ");
    // and its a normal packet
    result.push_str("14,rn ");

    // now, at 14, the aggregate base delay of 3us is also in effect that was
    // queued before from the client's blocking AND the propagated delay from
    // the server's padding is directly in effect (because it's from the server
    // to client), in total 5us

    // the 14us sn event is sent at 19us
    result.push_str("19,sn ");
    // the event is sent
    result.push_str("19,st ");

    // the 15us sn event is sent at 20us
    result.push_str("20,sn ");
    // the packet is sent
    result.push_str("20,st");

    run_test_sim(base, &result, delay, &[m.clone()], &[m], true, 40, false);
}

#[test_log::test]
fn test_ratio3_machine() {
    // The purpose of this test is to test a large part of the simulator, using
    // bypassable blocking to create a constant-rate defense on one side of the
    // tunnel, with significant simulated delays as a consequence.

    // The constant-rate defense is a "ratio3 machine". The ratio3 machine
    // blocks all outgoing traffic at the client (after the first packet) and
    // then attempts to send one packet for every 3 received packets. If there
    // is real traffic queued up (from the blocking), real traffic will be sent,
    // otherwise, a padding packet is sent.

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
    let pq = parse_trace(BE000_TRACE, &network);
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

    // reading the base trace, to receive at 0 at the client, the server has to
    // send the packet 50ms before, which is what becomes 0 in the resulting
    // simulated trace (so the trace below is shifted by 50ms, in addition to
    // what the ratio client does)
    let first = client_trace[0].time;
    // first recv: this will start the client'side blocking in the ratio3
    // machine and start counting
    assert_eq!(client_trace[0].time - first, Duration::ZERO);
    assert!(client_trace[0].event.is_event(Event::TunnelRecv));

    assert_eq!(client_trace[1].time - first, Duration::from_millis(170));
    assert!(client_trace[1].event.is_event(Event::TunnelRecv));
    // the send is blocked
    assert_eq!(client_trace[2].time - first, Duration::from_millis(430));
    assert!(client_trace[2].event.is_event(Event::TunnelRecv));
    // a send is blocked again
    assert_eq!(client_trace[3].time - first, Duration::from_millis(690));
    assert!(client_trace[3].event.is_event(Event::TunnelRecv));
    // we have received 3 packets, the client will pad and replace once with the
    // packet queued at 180ms, propagating a delay of 690-180=510ms, coming into
    // effect at time 690 + 3x delay = 840
    let mut aggregate_delay = Duration::from_millis(510);
    assert_eq!(client_trace[4].time - first, Duration::from_millis(690));
    assert!(client_trace[4].event.is_event(Event::TunnelSent));
    assert!(!client_trace[4].contains_padding);
    // two sends are blocked and queued up starting at 700ms

    // the aggregate delay is now in effect

    for event in client_trace.iter().take(12).skip(5) {
        // next, we have 7 received packets, happening at the exact same time
        // (thanks to the example trace aggressive truncation of timestamps, not
        // likely in practice)
        assert_eq!(
            event.time - first,
            Duration::from_millis(990) + aggregate_delay
        );
        assert!(event.event.is_event(Event::TunnelRecv));
    }
    // the ratio3 machine only has time to trigger padding once, now sending the
    // packet queued at 430ms, which will trigger more aggregated delay into
    // effect at 990+3x delay = 1140
    assert_eq!(
        client_trace[12].time - first,
        Duration::from_millis(990) + aggregate_delay
    );
    assert!(client_trace[12].event.is_event(Event::TunnelSent));

    for event in client_trace.iter().take(16).skip(13) {
        // 3 received packets, happening at the exact same time again
        assert_eq!(
            event.time - first,
            Duration::from_millis(1120) + aggregate_delay
        );
        assert!(event.event.is_event(Event::TunnelRecv));
    }
    // one sent is blocked and queued up starting at 1120ms + aggregate_delay
    // (we need to save this for later to calculate the aggregate delay)
    let first_delayed_sent_blocked = Duration::from_millis(1120) + aggregate_delay;

    // the ratio3 machine triggers one padding, sending the packet queued at
    // 700ms, which will trigger more aggregated delay into effect at 1120+3x
    // delay = 1270
    assert_eq!(
        client_trace[16].time - first,
        Duration::from_millis(1120) + aggregate_delay
    );
    assert!(client_trace[16].event.is_event(Event::TunnelSent));

    let prev_aggregate_delay = aggregate_delay;
    // at 1140ms, the aggregate delay is in effect from the previously sent
    aggregate_delay += Duration::from_millis(990) + aggregate_delay - Duration::from_millis(430);

    // at 1270ms, the aggregate delay is in effect from the previously sent at
    // 1120ms (note that we need to use the previous aggregate delay here)
    aggregate_delay +=
        Duration::from_millis(1120) + prev_aggregate_delay - Duration::from_millis(700);

    // receive one packet at 1380ms
    assert_eq!(
        client_trace[17].time - first,
        Duration::from_millis(1380) + aggregate_delay
    );
    assert!(client_trace[17].event.is_event(Event::TunnelRecv));
    // one sent is blocked
    let second_delay_sent_blocked = Duration::from_millis(1380) + aggregate_delay;

    // receive two packets at 1680ms
    for event in client_trace.iter().take(20).skip(18) {
        assert_eq!(
            event.time - first,
            Duration::from_millis(1680) + aggregate_delay
        );
        assert!(event.event.is_event(Event::TunnelRecv));
    }

    // the ratio3 machine triggers one padding, sending the second packet queued
    // at 700ms, with aggregate delay into effect at 1680+3x delay = 1830 ...
    assert_eq!(
        client_trace[20].time - first,
        Duration::from_millis(1680) + aggregate_delay
    );
    assert!(client_trace[20].event.is_event(Event::TunnelSent));
    // ... which is next
    aggregate_delay += Duration::from_millis(1680) + aggregate_delay - Duration::from_millis(700);
    // at 1930ms, two send packets are blocked

    // receive one packet at 2200ms
    assert_eq!(
        client_trace[21].time - first,
        Duration::from_millis(2200) + aggregate_delay
    );
    assert!(client_trace[21].event.is_event(Event::TunnelRecv));
    // one sent is blocked

    // receive one packet at 2300ms
    assert_eq!(
        client_trace[22].time - first,
        Duration::from_millis(2300) + aggregate_delay
    );
    assert!(client_trace[22].event.is_event(Event::TunnelRecv));

    // receive three packets at 2430ms
    for event in client_trace.iter().take(26).skip(23) {
        assert_eq!(
            event.time - first,
            Duration::from_millis(2430) + aggregate_delay
        );
        assert!(event.event.is_event(Event::TunnelRecv));
    }
    // one sent is blocked

    // the ratio3 machine triggers one padding, sending the packet queued at
    // 1120ms, with aggregate delay into effect at 2430+3x delay = 2580 ...
    assert_eq!(
        client_trace[26].time - first,
        Duration::from_millis(2430) + aggregate_delay
    );
    assert!(client_trace[26].event.is_event(Event::TunnelSent));
    // ... which is next
    aggregate_delay += Duration::from_millis(2430) + aggregate_delay - first_delayed_sent_blocked;

    // one sent is blocked at 2880ms

    // receive four packets at 3220ms
    for event in client_trace.iter().take(31).skip(27) {
        assert_eq!(
            event.time - first,
            Duration::from_millis(3220) + aggregate_delay
        );
        assert!(event.event.is_event(Event::TunnelRecv));
    }

    // the ratio3 machine triggers one padding, sending the packet queued at
    // 1380ms
    assert_eq!(
        client_trace[31].time - first,
        Duration::from_millis(3220) + aggregate_delay
    );
    assert!(client_trace[31].event.is_event(Event::TunnelSent));

    // receive three packets at 3300ms, NOTE: sent by the server before the
    // aggregate delay is propagated to the server in the sent above
    for event in client_trace.iter().take(35).skip(32) {
        assert_eq!(
            event.time - first,
            Duration::from_millis(3300) + aggregate_delay
        );
        assert!(event.event.is_event(Event::TunnelRecv));
    }

    aggregate_delay += Duration::from_millis(3220) + aggregate_delay - second_delay_sent_blocked;
    assert_eq!(aggregate_delay, Duration::from_millis(24930));
}

pub fn ratio3_machine() -> Machine {
    ratio_machine(3)
}

fn ratio_machine(n: usize) -> Machine {
    let mut states = vec![];

    // start state 0
    let start_state = State::new(enum_map! {
       Event::TunnelSent | Event::TunnelRecv => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start_state);

    // blocking state 1
    let mut blocking_state = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    blocking_state.action = Some(Action::BlockOutgoing {
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
            start: MAX_SAMPLED_BLOCK_DURATION,
            max: 0.0,
        },
        limit: None,
    });
    states.push(blocking_state);

    // recv states 2..n+2
    for i in 0..n {
        states.push(State::new(enum_map! {
           // to the next state
           Event::TunnelRecv => vec![Trans(3+i, 1.0)],
           // something else let traffic through, back to counting
           //Event::TunnelSent => vec![Trans(2, 1.0)],
           _ => vec![],
        }));
    }

    // padding state n+2
    let mut padding_state = State::new(enum_map! {
        Event::PaddingSent => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    padding_state.action = Some(Action::SendPadding {
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
        limit: None,
    });
    states.push(padding_state);

    Machine::new(u64::MAX, 0.0, u64::MAX, 0.0, states).unwrap()
}
