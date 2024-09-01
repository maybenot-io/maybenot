//use std::fs::File;
//use std::io::{self, Write, Read};
//use std::panic::resume_unwind;
use maybenot_simulator::linktrace::{
    load_linktrace_from_file, mk_sizebin_lookuptable, mk_start_instant, save_linktrace_to_file,
    LinkTrace, SizebinLookupTable,
};
use maybenot_simulator::network::{Network, NetworkLinktrace};

use rand::Rng;
use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(
        expected = "index out of bounds: the len is 50 but the index is 18446744073709551615"
    )]
    fn sizebin_lookup_table_panic_below_min() {
        // Example boundary values
        let boundaries = [0, 10, 20, 30, 50];
        let bin_tput_values = [5, 15, 25, 40];
        let sizebin_lookuptable = SizebinLookupTable::new(&boundaries, &bin_tput_values);

        // This should panic because -1 is below the minimum boundary value (0)
        sizebin_lookuptable.get_bin_idx(-1);
    }

    #[test]
    #[should_panic(expected = "Value 50 is above range [0, 50")]
    fn sizebin_lookup_table_panic_above_max() {
        // Example boundary values
        let boundaries = [0, 10, 20, 30, 50];
        let bin_tput_values = [5, 15, 25, 40];
        let sizebin_lookuptable = SizebinLookupTable::new(&boundaries, &bin_tput_values);

        // This should panic because 50 is outside the maximum boundary value (50)
        sizebin_lookuptable.get_bin_idx(50);
    }

    #[test]
    #[should_panic(expected = "Throughput value 30 at index 2 is out of bounds for bin 20-30.")]
    fn sizebin_lookup_table_panic_above_binboundary() {
        // Example boundary values
        let boundaries = [0, 10, 20, 30, 50];
        let bin_tput_values = [5, 15, 30, 40];
        let sizebin_lookuptable = SizebinLookupTable::new(&boundaries, &bin_tput_values);

        // This should panic because 50 is outside the maximum boundary value (50)
        sizebin_lookuptable.get_bin_idx(50);
    }

    #[test]
    fn sizebin_lookup_table_within_range() {
        // Example boundary values
        let boundaries = [0, 10, 20, 30, 50];
        let bin_tput_values = [9, 11, 25, 30];
        let sizebin_lookuptable = SizebinLookupTable::new(&boundaries, &bin_tput_values);

        // Test various values within the range
        assert_eq!(sizebin_lookuptable.get_bin_idx(5), 0); // 10 -> Bin 0
        assert_eq!(sizebin_lookuptable.get_bin_idx(10), 1); // 15 -> Bin 1
        assert_eq!(sizebin_lookuptable.get_bin_idx(15), 1); // 20 -> Bin 1
        assert_eq!(sizebin_lookuptable.get_bin_idx(25), 2); // 25 -> Bin 2
        assert_eq!(sizebin_lookuptable.get_bin_idx(30), 3); // 30 -> Bin 3
        assert_eq!(sizebin_lookuptable.get_bin_idx(35), 3); // 35 -> Bin 3
        assert_eq!(sizebin_lookuptable.get_bin_idx(49), 3); // 50 -> Bin 3
    }

    #[test]
    fn preconfig_sizebin_lookup() {
        let sizebin_lookuptable = mk_sizebin_lookuptable();

        // These are depenent on the boundaries used in mk_sizebin_lookuptable
        let expected = vec![64, 240, 576, 1200, 1420];
        for (i, value) in vec![50, 200, 520, 1200, 1201].into_iter().enumerate() {
            let bin_result = std::panic::catch_unwind(|| sizebin_lookuptable.get_bin_idx(value));
            let bin_pktsize = sizebin_lookuptable.get_bin_pktsize(value);
            match bin_result {
                Ok(_) => assert_eq!(bin_pktsize, expected[i], "bin_pktsize not as expected"),
                Err(e) => std::panic::resume_unwind(e),
            }
        }
    }

    #[test]
    fn save_load_linksimtrace() {
        let dl_traceinput = "tests/ether100M_synth5K_g.tr.gz";
        let ul_traceinput = "tests/ether100M_synth5K_g.tr.gz";
        let sizebin_lookuptable = mk_sizebin_lookuptable();
        let link_trace = LinkTrace::new(dl_traceinput, ul_traceinput, sizebin_lookuptable);

        // Save the instance to a file
        let _ = save_linktrace_to_file("ether100M_synth5K.ltbin", &link_trace)
            .expect("Failed to save LinkTrace ltbin to file");

        // Load the instance back from the file
        let loaded_link_trace = load_linktrace_from_file("ether100M_synth5K.ltbin")
            .expect("Failed to load LinkTrace ltbin from file");
        assert_eq!(link_trace, loaded_link_trace);
    }

    #[test]
    fn linksimtrace_lookup() {
        // Load the instance back from the test above
        let linksim_trace = load_linktrace_from_file("ether100M_synth5K.ltbin")
            .expect("Failed to load LinkTrace ltbin from file");
        // Confirm that different packet sizes give different busy_to times
        assert_eq!(linksim_trace.get_dl_busy_to(1000, 1500), 1119);
        assert_eq!(linksim_trace.get_dl_busy_to(1000, 750), 1067);
        assert_eq!(linksim_trace.get_dl_busy_to(1000, 56), 1005);

        assert_eq!(linksim_trace.get_dl_busy_to(3245, 1500), 3365);

        // Packets that that would have a busy_to time
        // after the end of the link trace return 0.
        assert_eq!(linksim_trace.get_dl_busy_to(4989, 1500), 0);
        assert_eq!(linksim_trace.get_dl_busy_to(4989, 56), 4995);
        assert_eq!(linksim_trace.get_dl_busy_to(4999, 1500), 0);
    }

    #[test]
    fn simulator_execution() {
        //How many packets to process
        let nr_iter = 1000;

        let mut instants = Vec::with_capacity(nr_iter);
        let mut rng = rand::thread_rng();

        // Start with the defined  Instant
        let mut current_instant = mk_start_instant();
        instants.push(current_instant + Duration::from_micros(1));

        // Total duration target
        let target_duration = 4_000_000;
        let mut accumulated_duration = 0;

        // Generate more Instants
        for _ in 1..nr_iter {
            // Calculate remaining microseconds and divide by remaining instants to get average step size
            let remaining_steps = nr_iter - instants.len();
            let remaining_duration = target_duration - accumulated_duration;
            let average_step = remaining_duration / remaining_steps;

            // Generate a random step, allowing some variation around the average step
            let step_micros: u64 = rng.gen_range(average_step / 2..=average_step * 2) as u64;

            // Update the accumulated duration
            accumulated_duration += step_micros as usize;

            // Add the random step to the current Instant
            current_instant += Duration::from_micros(step_micros);

            // Push the new Instant into the vector
            instants.push(current_instant);
        }

        println!("{:?}", instants[nr_iter - 1]);
        // start with a reasonable 10ms delay: we should get events at the client
        let network = Network::new(Duration::from_millis(10), None);
        let linktrace = load_linktrace_from_file("ether100M_synth5M.ltbin")
            .expect("Failed to load LinkTrace ltbin from file");
        let mut network_lt = NetworkLinktrace::new(network, &linktrace);

        let tinstant = mk_start_instant() + Duration::from_micros(1);
        network_lt.sample(&tinstant, true);
        network_lt.sample(&instants[0], true);
        network_lt.sample(&instants[1], true);
        network_lt.sample(&instants[50], true);
        network_lt.sample(&instants[98], true);
        network_lt.sample(&instants[99], true);

        for i in 0..nr_iter {
            // Use black_box to prevent the compiler from optimizing away the call
            network_lt.sample(&instants[i], true);
        }

        //sim(&[], &[], &mut pq.clone(), network.delay, 1000, true);
    }
}
