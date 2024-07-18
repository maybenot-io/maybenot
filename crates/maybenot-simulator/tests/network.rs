use std::time::Duration;

use maybenot::{
    action::Action,
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

    let input = "0,sn\n1000,sn\n2000,sn\n7000,sn\n12000,rn\n";
    let network = Network::new(Duration::from_micros(3), None);
    let mut sq = parse_trace(input, &network);
    let args = SimulatorArgs::new(&network, 20, true);

    let trace = sim_advanced(&[m], &[], &mut sq, &args);
    let client_trace = trace
        .clone()
        .into_iter()
        .filter(|t| t.client)
        .collect::<Vec<_>>();
    assert_eq!(client_trace.len(), 5);
    assert_eq!(
        client_trace[1].time - client_trace[0].time,
        Duration::from_micros(5)
    );
    assert_eq!(client_trace[1].time, client_trace[2].time);
    assert_eq!(
        client_trace[3].time - client_trace[0].time,
        Duration::from_micros(7)
    );
    println!("{:#?}", client_trace);
    // the event at 12us is delayed by 4us, due to the block at 0s first
    // impacting the event at 1us --- delaying it 4us due to 5us block
    assert_eq!(
        client_trace[4].time - client_trace[0].time,
        Duration::from_micros(16)
    );
}
