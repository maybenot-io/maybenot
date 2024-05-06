use std::time::Duration;

use maybenot::{
    action::Action,
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
    Machine,
};
use maybenot_simulator::{
    integration::{BinDist, Integration},
    network::Network,
    parse_trace_advanced, sim_advanced, SimEvent, SimulatorArgs,
};

use enum_map::enum_map;

fn get_test_machine() -> Machine {
    // a simple machine that pads once after 5ms
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut s1 = State::new(enum_map! {
        _ => vec![],
    });
    s1.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 5.0 * 1000.0,
            max: 0.0,
        },
        limit: None,
    });

    Machine::new(0, 0.0, 0, 0.0, vec![s0, s1]).unwrap()
}

fn run_sim(
    client: Option<&Integration>,
    server: Option<&Integration>,
    only_client: bool,
) -> Vec<SimEvent> {
    // a simple machine that pads once after 5ms
    let m = get_test_machine();

    let raw_trace = "0,s,100
        10000000,r,100
        20000000,s,100
        32000000,r,100
        56000000,s,100
        100000000,s,100";
    let network = Network::new(Duration::from_millis(5));

    let mut input_trace = parse_trace_advanced(raw_trace, &network, client, server);

    let mut args = SimulatorArgs::new(&network, 100, true);
    args.client_integration = client;
    args.server_integration = server;
    let trace = sim_advanced(&[m], &[], &mut input_trace, &args);

    let trace: Vec<_> = trace
        .into_iter()
        .filter(|e| e.client == only_client)
        .collect();
    println!("trace: {:?}", trace);
    trace
}

fn get_1ms_delay_dist() -> BinDist {
    BinDist::new(
        r#"{
        "(1.0, 1.0)": 1.0
    }"#,
    )
    .unwrap()
}

fn get_0ms_delay_dist() -> BinDist {
    BinDist::new(
        r#"{
        "(0.0, 0.0)": 1.0
    }"#,
    )
    .unwrap()
}

#[test_log::test]
fn test_action_delay() {
    // action delay should be visible in the network trace we get from the
    // simulator, by simply delaying padding packets by the action delay or
    // delaying blocking to start/stop by the action delay

    let integration = Integration {
        action_delay: get_1ms_delay_dist(),
        reporting_delay: get_0ms_delay_dist(),
        trigger_delay: get_0ms_delay_dist(),
    };
    assert_eq!(integration.action_delay(), Duration::from_micros(1000));
    assert_eq!(integration.reporting_delay(), Duration::from_micros(0));

    // for client
    let base_trace = run_sim(None, None, true);
    let delayed_trace = run_sim(Some(&integration), None, true);

    assert_eq!(base_trace.len(), delayed_trace.len());
    assert_eq!(base_trace[1].event, delayed_trace[1].event);
    assert!(base_trace[1].event.is_event(Event::TunnelSent));
    assert!(base_trace[1].contains_padding);
    assert_eq!(
        (delayed_trace[1].time - delayed_trace[0].time) - (base_trace[1].time - base_trace[0].time),
        integration.action_delay()
    );

    let delayed_trace_server = run_sim(Some(&integration), None, false);
    assert_eq!(base_trace.len(), delayed_trace_server.len());
    assert!(delayed_trace_server[2].event.is_event(Event::TunnelRecv));
    assert!(delayed_trace_server[2].contains_padding);
    // note below that first recv is 5ms in
    assert_eq!(
        delayed_trace_server[2].time - delayed_trace_server[0].time + Duration::from_millis(5),
        Duration::from_millis(5) * 2 + integration.action_delay()
    );

    // for server, everything should be the same (no action there due to machine
    // being client-side)
    let base_trace = run_sim(None, None, false);
    let delayed_trace = run_sim(None, Some(&integration), false);
    assert_eq!(base_trace.len(), delayed_trace.len());
    for i in 0..base_trace.len() {
        assert_eq!(base_trace[i].event, delayed_trace[i].event);
        assert_eq!(
            base_trace[i].time - base_trace[0].time,
            delayed_trace[i].time - delayed_trace[0].time
        );
    }
}

#[test_log::test]
fn test_reporting_delay() {
    // reporting delay should be indirectly visible in the network trace we get
    // from the simulator, because events reported by the simulator will have a
    // delay, resulting actions will be delayed, and the resulting padding
    // packets will therefore be delayed in the network trace

    let integration = Integration {
        action_delay: get_0ms_delay_dist(),
        reporting_delay: get_1ms_delay_dist(),
        trigger_delay: get_0ms_delay_dist(),
    };
    assert_eq!(integration.action_delay(), Duration::from_micros(0));
    assert_eq!(integration.reporting_delay(), Duration::from_micros(1000));

    // for client
    let base_trace = run_sim(None, None, true);
    let delayed_trace = run_sim(Some(&integration), None, true);

    assert_eq!(base_trace.len(), delayed_trace.len());
    assert_eq!(base_trace[1].event, delayed_trace[1].event);
    assert!(base_trace[1].event.is_event(Event::TunnelSent));
    assert!(base_trace[1].contains_padding);
    assert_eq!(
        (delayed_trace[1].time - delayed_trace[0].time) - (base_trace[1].time - base_trace[0].time),
        integration.reporting_delay()
    );

    let delayed_trace_server = run_sim(Some(&integration), None, false);
    assert_eq!(base_trace.len(), delayed_trace_server.len());
    assert!(delayed_trace_server[2].event.is_event(Event::TunnelRecv));
    assert!(delayed_trace_server[2].contains_padding);
    // note below that first recv is 5ms in
    assert_eq!(
        delayed_trace_server[2].time - delayed_trace_server[0].time + Duration::from_millis(5),
        Duration::from_millis(5) * 2 + integration.reporting_delay()
    );

    // for server, everything should be the same (no action there due to machine
    // being client-side)
    let base_trace = run_sim(None, None, false);
    let delayed_trace = run_sim(None, Some(&integration), false);
    assert_eq!(base_trace.len(), delayed_trace.len());

    for i in 0..base_trace.len() {
        assert_eq!(base_trace[i].event, delayed_trace[i].event);
        assert_eq!(
            base_trace[i].time - base_trace[0].time,
            delayed_trace[i].time - delayed_trace[0].time
        );
    }
}

#[test_log::test]
fn test_trigger_delay() {
    // trigger delay should be visible in the network trace we get from the
    // simulator, by simply delaying padding packets by the trigger delay

    let integration = Integration {
        action_delay: get_0ms_delay_dist(),
        reporting_delay: get_0ms_delay_dist(),
        trigger_delay: get_1ms_delay_dist(),
    };
    assert_eq!(integration.action_delay(), Duration::from_micros(0));
    assert_eq!(integration.reporting_delay(), Duration::from_micros(0));
    assert_eq!(integration.trigger_delay(), Duration::from_micros(1000));

    // for client
    let base_trace = run_sim(None, None, true);
    let delayed_trace = run_sim(Some(&integration), None, true);

    assert_eq!(base_trace.len(), delayed_trace.len());
    assert_eq!(base_trace[1].event, delayed_trace[1].event);
    assert!(base_trace[1].event.is_event(Event::TunnelSent));
    assert!(base_trace[1].contains_padding);
    assert_eq!(
        (delayed_trace[1].time - delayed_trace[0].time) - (base_trace[1].time - base_trace[0].time),
        integration.trigger_delay()
    );

    let delayed_trace_server = run_sim(Some(&integration), None, false);
    assert_eq!(base_trace.len(), delayed_trace_server.len());
    assert!(delayed_trace_server[2].event.is_event(Event::TunnelRecv));
    assert!(delayed_trace_server[2].contains_padding);
    // note below that first recv is 5ms in
    assert_eq!(
        delayed_trace_server[2].time - delayed_trace_server[0].time + Duration::from_millis(5),
        Duration::from_millis(5) * 2 + integration.trigger_delay()
    );

    // for server, everything should be the same (no action there due to machine
    // being client-side)
    let base_trace = run_sim(None, None, false);
    let delayed_trace = run_sim(None, Some(&integration), false);
    assert_eq!(base_trace.len(), delayed_trace.len());

    for i in 0..base_trace.len() {
        assert_eq!(base_trace[i].event, delayed_trace[i].event);
        assert_eq!(
            base_trace[i].time - base_trace[0].time,
            delayed_trace[i].time - delayed_trace[0].time
        );
    }
}

#[test_log::test]
fn test_action_and_reporting_delay() {
    let integration = Integration {
        action_delay: get_1ms_delay_dist(),
        reporting_delay: get_1ms_delay_dist(),
        trigger_delay: get_0ms_delay_dist(),
    };
    assert_eq!(integration.action_delay(), Duration::from_micros(1000));
    assert_eq!(integration.reporting_delay(), Duration::from_micros(1000));

    // for client
    let base_trace = run_sim(None, None, true);
    let delayed_trace = run_sim(Some(&integration), None, true);

    assert_eq!(base_trace.len(), delayed_trace.len());
    assert_eq!(base_trace[1].event, delayed_trace[1].event);
    assert!(base_trace[1].event.is_event(Event::TunnelSent));
    assert!(base_trace[1].contains_padding);
    assert_eq!(
        (delayed_trace[1].time - delayed_trace[0].time) - (base_trace[1].time - base_trace[0].time),
        integration.action_delay() + integration.reporting_delay()
    );

    let delayed_trace_server = run_sim(Some(&integration), None, false);
    assert_eq!(base_trace.len(), delayed_trace_server.len());
    // note below that first recv is 5ms in
    assert_eq!(
        delayed_trace_server[2].time - delayed_trace_server[0].time + Duration::from_millis(5),
        Duration::from_millis(5) * 2 + integration.reporting_delay() + integration.action_delay()
    );

    // for server, everything should be the same (no action there due to machine
    // being client-side)
    let base_trace = run_sim(None, None, false);
    let delayed_trace = run_sim(None, Some(&integration), false);
    assert_eq!(base_trace.len(), delayed_trace.len());

    for i in 0..base_trace.len() {
        assert_eq!(base_trace[i].event, delayed_trace[i].event);
        assert_eq!(
            base_trace[i].time - base_trace[0].time,
            delayed_trace[i].time - delayed_trace[0].time
        );
    }
}

#[test_log::test]
fn test_action_reporting_and_delay() {
    let integration = Integration {
        action_delay: get_1ms_delay_dist(),
        reporting_delay: get_1ms_delay_dist(),
        trigger_delay: get_1ms_delay_dist(),
    };
    assert_eq!(integration.action_delay(), Duration::from_micros(1000));
    assert_eq!(integration.reporting_delay(), Duration::from_micros(1000));
    assert_eq!(integration.trigger_delay(), Duration::from_micros(1000));

    // for client
    let base_trace = run_sim(None, None, true);
    let delayed_trace = run_sim(Some(&integration), None, true);

    assert_eq!(base_trace.len(), delayed_trace.len());
    assert_eq!(base_trace[1].event, delayed_trace[1].event);
    assert!(base_trace[1].event.is_event(Event::TunnelSent));
    assert!(base_trace[1].contains_padding);
    assert_eq!(
        (delayed_trace[1].time - delayed_trace[0].time) - (base_trace[1].time - base_trace[0].time),
        integration.action_delay() + integration.reporting_delay() + integration.trigger_delay()
    );

    let delayed_trace_server = run_sim(Some(&integration), None, false);
    assert_eq!(base_trace.len(), delayed_trace_server.len());
    // note below that first recv is 5ms in
    assert_eq!(
        delayed_trace_server[2].time - delayed_trace_server[0].time + Duration::from_millis(5),
        Duration::from_millis(5) * 2
            + integration.reporting_delay()
            + integration.action_delay()
            + integration.trigger_delay()
    );

    // for server, everything should be the same (no action there due to machine
    // being client-side)
    let base_trace = run_sim(None, None, false);
    let delayed_trace = run_sim(None, Some(&integration), false);
    assert_eq!(base_trace.len(), delayed_trace.len());

    for i in 0..base_trace.len() {
        assert_eq!(base_trace[i].event, delayed_trace[i].event);
        assert_eq!(
            base_trace[i].time - base_trace[0].time,
            delayed_trace[i].time - delayed_trace[0].time
        );
    }
}
