use maybenot_simulator::{
    linktrace::load_linktrace_from_file,
    network::{ExtendedNetworkLabels, Network},
    parse_trace, sim_advanced, SimulatorArgs,
};

use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linktrace_simulator_run() {
        const EARLY_TRACE: &str = include_str!("../tests/EARLY_TEST_TRACE.log");

        let linktrace = load_linktrace_from_file("tests/ether100M_synth10K_std.ltbin.gz")
            .expect("Failed to load LinkTrace ltbin from file");

        let network = Network::new(Duration::from_millis(10), None);
        let sq = parse_trace(EARLY_TRACE, network);
        let args = SimulatorArgs::new(network, 2000, true);
        let linktrace_args = SimulatorArgs {
            simulated_network_type: Some(ExtendedNetworkLabels::Linktrace),
            linktrace: Some(linktrace),
            ..args
        };
        let _trace = sim_advanced(&[], &[], &mut sq.clone(), &linktrace_args);
    }
}
