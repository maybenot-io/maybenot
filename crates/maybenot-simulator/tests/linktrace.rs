#[cfg(feature = "trace-tests")]
use maybenot_simulator::links::{
    LinkTrace, SizebinLookupTable, load_linktrace_from_file, save_linktrace_to_file,
};
#[cfg(feature = "trace-tests")]
use std::sync::Arc;

#[cfg(feature = "trace-tests")]
mod common;

// Helper function to create sizebin lookup table for tests
#[cfg(feature = "trace-tests")]
fn mk_sizebin_lookuptable() -> SizebinLookupTable {
    let boundaries = [
        0, 49, 65, 81, 97, 113, 129, 145, 161, 193, 241, 289, 369, 449, 513, 577, 705, 849, 1009,
        1201, 1421, 1501,
    ];
    let bin_pkt_sizes = [
        48, 64, 80, 96, 112, 128, 144, 160, 192, 240, 288, 368, 448, 512, 576, 704, 848, 1008,
        1200, 1420, 1500,
    ];
    SizebinLookupTable::new(&boundaries, &bin_pkt_sizes)
}

#[test]
#[cfg(feature = "trace-tests")]
fn save_load_linktrace() {
    common::setup_traces();
    let traceinput = "tests/data/ether100M_synth5K.tr";
    let sizebin_lookuptable = mk_sizebin_lookuptable();
    let link_trace = Arc::new(LinkTrace::new_hi_res(traceinput, sizebin_lookuptable));

    // Save the instance to a file
    save_linktrace_to_file("tests/data/ether100M_synth5K_tst.ltbin.gz", &link_trace)
        .expect("Failed to save LinkTrace ltbin to file");

    // Load the instance back from the file
    let loaded_link_trace = load_linktrace_from_file("tests/data/ether100M_synth5K_tst.ltbin.gz")
        .expect("Failed to load LinkTrace ltbin from file");
    assert_eq!(link_trace, loaded_link_trace);
}

#[test]
#[cfg(feature = "trace-tests")]
fn linksimtrace_lookup() {
    common::setup_traces();
    // Load the instance back from the test above
    let linksim_trace = load_linktrace_from_file("tests/data/ether100M_synth5K.ltbin.gz")
        .expect("Failed to load LinkTrace ltbin from file");
    // Confirm that different packet sizes give different busy_to times
    assert_eq!(linksim_trace.get_busy_to(1000, 1500), 1120);
    assert_eq!(linksim_trace.get_busy_to(1000, 750), 1068);
    assert_eq!(linksim_trace.get_busy_to(1000, 56), 1006);

    assert_eq!(linksim_trace.get_busy_to(3245, 1500), 3365);

    // Packets that that would have a busy_to time
    // after the end of the link trace return 0.
    assert_eq!(linksim_trace.get_busy_to(4989, 1500), 0);
    assert_eq!(linksim_trace.get_busy_to(4989, 56), 4995);
    assert_eq!(linksim_trace.get_busy_to(4999, 1500), 0);
}
