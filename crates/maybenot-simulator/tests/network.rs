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
use maybenot_simulator::{network::Network, parse_trace, sim, sim_advanced, SimulatorArgs};

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

#[test_log::test]
fn test_network_aggregate_base_delay() {
    // a simple machine that blocks for 5us
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut s1 = State::new(enum_map! {
        _ => vec![],
    });
    s1.action = Some(Action::BlockOutgoing {
        bypass: false,
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
    let m = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1]).unwrap();

    let input = "0,sn\n1000,sn\n2000,sn\n7000,sn\n11000,sn\n12000,rn\n";
    let network = Network::new(Duration::from_micros(3), None);
    let mut sq = parse_trace(input, &network);
    let args = SimulatorArgs::new(&network, 20, true);

    let trace = sim_advanced(&[m], &[], &mut sq, &args);
    let client_trace = trace
        .clone()
        .into_iter()
        .filter(|t| t.client)
        .collect::<Vec<_>>();
    assert_eq!(client_trace.len(), 6);
    assert_eq!(
        client_trace[1].time - client_trace[0].time,
        Duration::from_micros(5)
    );
    assert_eq!(client_trace[1].time, client_trace[2].time);
    assert_eq!(
        client_trace[4].time - client_trace[0].time,
        Duration::from_micros(15)
    );
    // the event at 12us is delayed by 4us, due to the block at 0s first
    // impacting the event at 1us --- delaying it 4us due to 5us block
    assert_eq!(
        client_trace[5].time - client_trace[0].time,
        Duration::from_micros(16)
    );
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
    // network delay, and updating the base delay to 1us *for both client and
    // server*
    result.push_str("2,st ");
    // at at 5us, the blocking ends, so the first thing that happens is that the
    // blocked packet from 2us is sent, causing the base delay of 3us to be
    // propagated, arriving at the receiver at 8us
    result.push_str("5,st ");
    // the blocking end event at the client (has lower priority than the st so
    // it happens after, but still at time 5us)
    result.push_str("5,be ");

    // NOTE: in between this and the next event in the client trace, the two
    // normal packets have arrived at the server and thus propagated the base
    // delay to both parties, now at 3+1=4us in total

    // in the base trace, the 8us sn event should be delayed by in total 4us
    result.push_str("12,sn ");
    // the packet is sent
    result.push_str("12,st ");

    // NOTE: in between this and the next event in the client trace:
    // - the 12,rn event at the server is sent at 12-3+4=13us
    // - this causes the server's machine to start blocking for 5us and
    //   transitioning, scheduling padding to be sent in 2us
    // - at 14, the 12,rn event (in the base trace) at the server is blocked

    // 4us later, the 11,sn event in the base trace is sent at 15us
    result.push_str("15,sn ");
    // in a packet
    result.push_str("15,st ");

    // NOTE: at 15, the server machine's padding timer expires, causing the
    // padding packet to be replaced with the queued up normal packet from 12us,
    // and the packet is sent at 15us with a 1us base delay to be propagated, in
    // (global) effect at 18us upon reception

    // the 12us rn event, sent at 13us, arrives in a packet
    result.push_str("16,rt ");
    // and the event is received
    result.push_str("16,rn ");

    // the 14us sn event is sent at 18us
    result.push_str("18,sn ");
    // the event is sent
    result.push_str("18,st ");
    // the padding packet the server sent @15us
    result.push_str("18,rt ");
    // and the actual padding, not normal: this moves the aggregate base delay
    // up to 5us
    result.push_str("18,rn ");

    // the 15us sn event is sent at 20us
    result.push_str("20,sn ");
    // the packet is sent
    result.push_str("20,st");

    run_test_sim(base, &result, delay, &[m.clone()], &[m], true, 40, false);
}

#[test_log::test]
fn test_ratio3_machine() {
    // The purpose of this test is to test a large parte of the simulator, using
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

    let network = Network::new(Duration::from_millis(50), None);
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
    // packet queued at 180ms, propagating a delay of 690-180=510ms
    let mut aggregate_delay = Duration::from_millis(510);
    assert_eq!(client_trace[4].time - first, Duration::from_millis(690));
    assert!(client_trace[4].event.is_event(Event::TunnelSent));
    assert!(!client_trace[4].contains_padding);
    // two sends are blocked and queued up starting at 700ms

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
    // packet queued at 430ms
    assert_eq!(
        client_trace[12].time - first,
        Duration::from_millis(990) + aggregate_delay
    );
    assert!(client_trace[12].event.is_event(Event::TunnelSent));
    aggregate_delay += Duration::from_millis(990) + aggregate_delay - Duration::from_millis(430);

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
    // 700ms
    assert_eq!(
        client_trace[16].time - first,
        Duration::from_millis(1120) + aggregate_delay
    );
    assert!(client_trace[16].event.is_event(Event::TunnelSent));
    aggregate_delay += Duration::from_millis(1120) + aggregate_delay - Duration::from_millis(700);

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
    // at 700ms
    assert_eq!(
        client_trace[20].time - first,
        Duration::from_millis(1680) + aggregate_delay
    );
    assert!(client_trace[20].event.is_event(Event::TunnelSent));
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
    // 1120ms
    assert_eq!(
        client_trace[26].time - first,
        Duration::from_millis(2430) + aggregate_delay
    );
    assert!(client_trace[26].event.is_event(Event::TunnelSent));
    assert_eq!(aggregate_delay, Duration::from_millis(8140));
    aggregate_delay += Duration::from_millis(2430) + aggregate_delay - first_delayed_sent_blocked;
    assert_eq!(aggregate_delay, Duration::from_millis(16010));

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
    assert_eq!(aggregate_delay, Duration::from_millis(30280));
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
