use std::time::Duration;

use enum_map::enum_map;
use maybenot::{
    Machine,
    action::Action,
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};
use maybenot_simulator::{
    SimEvent, SimulatorArgs,
    integration::{BinDist, Integration},
    parse_trace, sim_advanced,
    topology::load_topology_from_str,
};

// Modifies the prop_us parameter for Link instances that use fixed propagation
// in a TOML string. Links with prop_us_file (time-dependent propagation) are
// left unchanged.
fn set_toml_propagation_us(toml_in: &str, delay_us: u64) -> String {
    // Parse input TOML into a mutable value
    let mut toml_value: toml::Value =
        toml::from_str(toml_in).unwrap_or_else(|e| panic!("Failed to parse input TOML: {}", e));

    // Get the root table
    let root_table = toml_value
        .as_table_mut()
        .unwrap_or_else(|| panic!("TOML root is not a table"));

    // Find the Link section array
    let link_array = root_table
        .get_mut("Link")
        .and_then(|v| v.as_array_mut())
        .unwrap_or_else(|| panic!("Link section is not an array or doesn't exist"));

    // Update prop_us for Link instances that use fixed propagation
    for link_entry in link_array.iter_mut() {
        let link_table = link_entry
            .as_table_mut()
            .unwrap_or_else(|| panic!("Link entry is not a table"));

        // Only modify links that have prop_us (fixed propagation) Skip links
        // that have prop_us_file (time-dependent propagation)
        if link_table.contains_key("prop_us") && !link_table.contains_key("prop_us_file") {
            link_table.insert("prop_us".to_string(), toml::Value::Integer(delay_us as i64));
        }
    }

    // Serialize back to TOML string
    toml::to_string_pretty(&toml_value)
        .unwrap_or_else(|e| panic!("Failed to serialize TOML: {}", e))
}

fn get_test_machine() -> Machine {
    // a simple machine that sends a decoy once after 5ms
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut s1 = State::new(enum_map! {
        _ => vec![],
    });
    s1.action = Some(Action::DecoyTraffic {
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
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });

    Machine::new(0, 0, vec![s0, s1]).unwrap()
}

fn run_sim(
    client: Option<&Integration>,
    server: Option<&Integration>,
    only_client: bool,
) -> Vec<SimEvent> {
    // a simple machine that sends a decoy once after 5ms
    let m = get_test_machine();

    let raw_trace = "0,s,100
        10000000,r,100
        20000000,s,100
        32000000,r,100
        56000000,s,100
        100000000,s,100";

    let config_file = "tests/cfg/maybenot_baseline_test.toml";
    let delay = Duration::from_millis(5);

    //Read in config path to toml_str
    let mut toml_str =
        std::fs::read_to_string(config_file).expect("Failed to read TOML configuration file");

    toml_str = set_toml_propagation_us(&toml_str, delay.as_micros() as u64);

    // Create Topology and link-state from the TOML string
    let (topology, mut link_state) = load_topology_from_str(&toml_str)
        .expect("Failed to parse the network configuration from TOML string");

    // Parse trace into simulation queue
    let (si, mut sq) = parse_trace(raw_trace, &topology, 2 * delay).unwrap();

    let mut args = SimulatorArgs::new(100, true);
    args.client_integration = client.cloned();
    args.server_integration = server.cloned();
    args.only_client_events = only_client;

    let mut trace = sim_advanced(&[m], &[], &topology, &mut link_state, &si, &mut sq, &args);

    if !only_client {
        trace.retain(|e| e.node_id == topology.get_maybenot_relay().node_id());
    }

    for event in &trace {
        println!("{}", event.display_full(&si, &topology, &link_state));
    }

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
    // simulator, by simply delaying decoy packets by the action delay or
    // delaying delay to start/stop by the action delay

    let integration = Integration {
        action_delay: get_1ms_delay_dist(),
        reporting_delay: get_0ms_delay_dist(),
        trigger_delay: get_0ms_delay_dist(),
    };
    assert_eq!(
        integration.action_delay(&mut rand::rng()),
        Duration::from_micros(1000)
    );
    assert_eq!(
        integration.reporting_delay(&mut rand::rng()),
        Duration::from_micros(0)
    );

    // for client
    let base_trace = run_sim(None, None, true);
    let delayed_trace = run_sim(Some(&integration), None, true);

    assert_eq!(base_trace.len(), delayed_trace.len());
    assert_eq!(base_trace[1].event, delayed_trace[1].event);
    assert!(matches!(
        base_trace[1].event,
        maybenot::TriggerEvent::PacketSent
    ));
    assert!(base_trace[1].contains_decoy);
    assert_eq!(
        (delayed_trace[1].time - delayed_trace[0].time) - (base_trace[1].time - base_trace[0].time),
        integration.action_delay(&mut rand::rng())
    );

    let delayed_trace_server = run_sim(Some(&integration), None, false);
    assert_eq!(base_trace.len(), delayed_trace_server.len());
    assert!(matches!(
        delayed_trace_server[2].event,
        maybenot::TriggerEvent::PacketRecv
    ));
    assert!(delayed_trace_server[2].contains_decoy);
    // note below that first recv is 5ms in
    assert_eq!(
        delayed_trace_server[2].time - delayed_trace_server[0].time + Duration::from_millis(5),
        Duration::from_millis(5) * 2 + integration.action_delay(&mut rand::rng())
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
    // delay, resulting actions will be delayed, and the resulting decoy packets
    // will therefore be delayed in the network trace

    let integration = Integration {
        action_delay: get_0ms_delay_dist(),
        reporting_delay: get_1ms_delay_dist(),
        trigger_delay: get_0ms_delay_dist(),
    };
    assert_eq!(
        integration.action_delay(&mut rand::rng()),
        Duration::from_micros(0)
    );
    assert_eq!(
        integration.reporting_delay(&mut rand::rng()),
        Duration::from_micros(1000)
    );

    // for client
    let base_trace = run_sim(None, None, true);
    let delayed_trace = run_sim(Some(&integration), None, true);

    assert_eq!(base_trace.len(), delayed_trace.len());
    assert_eq!(base_trace[1].event, delayed_trace[1].event);
    assert!(matches!(
        base_trace[1].event,
        maybenot::TriggerEvent::PacketSent
    ));
    assert!(base_trace[1].contains_decoy);
    assert_eq!(
        (delayed_trace[1].time - delayed_trace[0].time) - (base_trace[1].time - base_trace[0].time),
        integration.reporting_delay(&mut rand::rng())
    );

    let delayed_trace_server = run_sim(Some(&integration), None, false);
    assert_eq!(base_trace.len(), delayed_trace_server.len());
    assert!(matches!(
        delayed_trace_server[2].event,
        maybenot::TriggerEvent::PacketRecv
    ));
    assert!(delayed_trace_server[2].contains_decoy);
    // note below that first recv is 5ms in
    assert_eq!(
        delayed_trace_server[2].time - delayed_trace_server[0].time + Duration::from_millis(5),
        Duration::from_millis(5) * 2 + integration.reporting_delay(&mut rand::rng())
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
    // simulator, by simply delaying decoy packets by the trigger delay

    let integration = Integration {
        action_delay: get_0ms_delay_dist(),
        reporting_delay: get_0ms_delay_dist(),
        trigger_delay: get_1ms_delay_dist(),
    };
    assert_eq!(
        integration.action_delay(&mut rand::rng()),
        Duration::from_micros(0)
    );
    assert_eq!(
        integration.reporting_delay(&mut rand::rng()),
        Duration::from_micros(0)
    );
    assert_eq!(
        integration.trigger_delay(&mut rand::rng()),
        Duration::from_micros(1000)
    );

    // for client
    let base_trace = run_sim(None, None, true);
    let delayed_trace = run_sim(Some(&integration), None, true);

    assert_eq!(base_trace.len(), delayed_trace.len());
    assert_eq!(base_trace[1].event, delayed_trace[1].event);
    assert!(matches!(
        base_trace[1].event,
        maybenot::TriggerEvent::PacketSent
    ));
    assert!(base_trace[1].contains_decoy);
    assert_eq!(
        (delayed_trace[1].time - delayed_trace[0].time) - (base_trace[1].time - base_trace[0].time),
        integration.trigger_delay(&mut rand::rng())
    );

    let delayed_trace_server = run_sim(Some(&integration), None, false);
    assert_eq!(base_trace.len(), delayed_trace_server.len());
    assert!(matches!(
        delayed_trace_server[2].event,
        maybenot::TriggerEvent::PacketRecv
    ));
    assert!(delayed_trace_server[2].contains_decoy);
    // note below that first recv is 5ms in
    assert_eq!(
        delayed_trace_server[2].time - delayed_trace_server[0].time + Duration::from_millis(5),
        Duration::from_millis(5) * 2 + integration.trigger_delay(&mut rand::rng())
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
    assert_eq!(
        integration.action_delay(&mut rand::rng()),
        Duration::from_micros(1000)
    );
    assert_eq!(
        integration.reporting_delay(&mut rand::rng()),
        Duration::from_micros(1000)
    );

    // for client
    let base_trace = run_sim(None, None, true);
    let delayed_trace = run_sim(Some(&integration), None, true);

    assert_eq!(base_trace.len(), delayed_trace.len());
    assert_eq!(base_trace[1].event, delayed_trace[1].event);
    assert!(matches!(
        base_trace[1].event,
        maybenot::TriggerEvent::PacketSent
    ));
    assert!(base_trace[1].contains_decoy);
    assert_eq!(
        (delayed_trace[1].time - delayed_trace[0].time) - (base_trace[1].time - base_trace[0].time),
        integration.action_delay(&mut rand::rng()) + integration.reporting_delay(&mut rand::rng())
    );

    let delayed_trace_server = run_sim(Some(&integration), None, false);
    assert_eq!(base_trace.len(), delayed_trace_server.len());
    // note below that first recv is 5ms in
    assert_eq!(
        delayed_trace_server[2].time - delayed_trace_server[0].time + Duration::from_millis(5),
        Duration::from_millis(5) * 2
            + integration.reporting_delay(&mut rand::rng())
            + integration.action_delay(&mut rand::rng())
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
    assert_eq!(
        integration.action_delay(&mut rand::rng()),
        Duration::from_micros(1000)
    );
    assert_eq!(
        integration.reporting_delay(&mut rand::rng()),
        Duration::from_micros(1000)
    );
    assert_eq!(
        integration.trigger_delay(&mut rand::rng()),
        Duration::from_micros(1000)
    );

    // for client
    let base_trace = run_sim(None, None, true);
    let delayed_trace = run_sim(Some(&integration), None, true);

    assert_eq!(base_trace.len(), delayed_trace.len());
    assert_eq!(base_trace[1].event, delayed_trace[1].event);
    assert!(matches!(
        base_trace[1].event,
        maybenot::TriggerEvent::PacketSent
    ));
    assert!(base_trace[1].contains_decoy);
    assert_eq!(
        (delayed_trace[1].time - delayed_trace[0].time) - (base_trace[1].time - base_trace[0].time),
        integration.action_delay(&mut rand::rng())
            + integration.reporting_delay(&mut rand::rng())
            + integration.trigger_delay(&mut rand::rng())
    );

    let delayed_trace_server = run_sim(Some(&integration), None, false);
    assert_eq!(base_trace.len(), delayed_trace_server.len());
    // note below that first recv is 5ms in
    assert_eq!(
        delayed_trace_server[2].time - delayed_trace_server[0].time + Duration::from_millis(5),
        Duration::from_millis(5) * 2
            + integration.reporting_delay(&mut rand::rng())
            + integration.action_delay(&mut rand::rng())
            + integration.trigger_delay(&mut rand::rng())
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
