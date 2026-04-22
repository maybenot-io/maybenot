use std::time::Duration;

use maybenot::{MachineId, TriggerAction, TriggerEvent};
use maybenot_simulator::{
    ActionProducer, SimTime, SimulatorArgs, parse_trace, sim_user_provided,
    topology::load_topology_from_file,
};

/// Minimal [`ActionProducer`] for testing: emits one `DecoyTraffic` action
/// per `NormalQueued` event, so the simulator should produce one
/// `DecoyQueued` event per outgoing normal packet.
#[derive(Debug)]
struct ConstantDecoyProducer {
    timeout: Duration,
}

impl ActionProducer for ConstantDecoyProducer {
    fn trigger_events(
        &mut self,
        events: &[TriggerEvent],
        _current_time: SimTime,
    ) -> Vec<TriggerAction<SimTime>> {
        events
            .iter()
            .filter_map(|e| match e {
                TriggerEvent::NormalQueued => Some(TriggerAction::DecoyTraffic {
                    timeout: self.timeout,
                    n: 1,
                    bypass: false,
                    replace: false,
                    machine: MachineId::from_raw(0),
                }),
                _ => None,
            })
            .collect()
    }

    fn num_machines(&self) -> usize {
        1
    }
}

#[test_log::test]
fn user_provided_decoy_producer_emits_decoys() {
    // Same minimal trace as v3test.rs::simulator_example_use, plenty of
    // NormalQueued events to feed the producer.
    let raw_trace = "0,s
    19714282,r
    183976147,s
    243699564,r
    1696037773,s
    2047985926,s
    2055955094,r
    9401039609,s
    9401094589,s
    9420892765,r";

    let (topology, mut link_state) =
        load_topology_from_file("tests/cfg/maybenot_test.toml").unwrap();

    let trafserv_to_client_delay = Duration::from_millis(20);
    let (si, mut sq) = parse_trace(raw_trace, &topology, trafserv_to_client_delay).unwrap();

    let client_producer: Box<dyn ActionProducer> = Box::new(ConstantDecoyProducer {
        timeout: Duration::from_millis(5),
    });
    let server_producer: Box<dyn ActionProducer> = Box::new(ConstantDecoyProducer {
        timeout: Duration::from_millis(5),
    });

    // Default args; trigger only_network_activity=false so we can spot
    // DecoyQueued in the output trace (it's not a wire-level packet event).
    let mut args = SimulatorArgs::new(200, false);
    args.stop_after_all_normal_packets = true;

    let trace = sim_user_provided(
        client_producer,
        server_producer,
        &topology,
        &mut link_state,
        &si,
        &mut sq,
        &args,
    );

    let decoy_count = trace
        .iter()
        .filter(|e| matches!(e.event, TriggerEvent::DecoyQueued { .. }))
        .count();
    assert!(
        decoy_count > 0,
        "expected user-provided producer's decoys to appear in trace, got 0 (out of {} events)",
        trace.len()
    );
}
