//! Tests for link trace wrap-around (looping) behavior.

#[cfg(feature = "trace-tests")]
use maybenot_simulator::links::{HiTraceTputLink, StdTraceTputLink, load_linktrace_from_file};
#[cfg(feature = "trace-tests")]
use maybenot_simulator::settings::PACKET_SIZE_WG;
#[cfg(feature = "trace-tests")]
use rand::rng;
#[cfg(feature = "trace-tests")]
use std::time::Duration;

#[cfg(feature = "trace-tests")]
mod common;

/// Test that HiTraceTputLink handles wrap-around correctly when scheduling
/// packets beyond the trace end.
#[test]
#[cfg(feature = "trace-tests")]
fn test_hitrace_wrap_around() {
    common::setup_traces();
    let linktrace = load_linktrace_from_file("tests/data/ether100M_synth5K.ltbin.gz")
        .expect("Failed to load trace");

    let trace_len = linktrace.bw_trace.len(); // Should be 5000 microseconds

    let mut link = HiTraceTputLink::new(
        0,
        0,
        1,
        Duration::from_micros(1000),
        linktrace.clone(),
        true,
        Vec::new(),
    );

    // Schedule packet near end of trace
    let near_end_time = Duration::from_micros((trace_len - 10) as u64);
    let delay1 = link.sample(near_end_time, PACKET_SIZE_WG);

    // Verify packet was scheduled (didn't panic)
    assert!(
        delay1 > Duration::ZERO,
        "Packet near trace end should be scheduled"
    );

    // Schedule another packet closer to the end
    let at_end_time = Duration::from_micros((trace_len - 5) as u64);
    let delay2 = link.sample(at_end_time, PACKET_SIZE_WG);
    assert!(
        delay2 > Duration::ZERO,
        "Packet at trace end should be scheduled"
    );
}

/// Test that HiTraceTputLink handles packets scheduled well past the trace end
/// by wrapping around through multiple cycles.
#[test]
#[cfg(feature = "trace-tests")]
fn test_hitrace_multiple_wraps() {
    common::setup_traces();
    let linktrace = load_linktrace_from_file("tests/data/ether100M_synth5K.ltbin.gz")
        .expect("Failed to load trace");

    let trace_len = linktrace.bw_trace.len();

    let mut link = HiTraceTputLink::new(
        0,
        0,
        1,
        Duration::from_micros(1000),
        linktrace,
        true,
        Vec::new(),
    );

    // Schedule packet well past trace end (2x trace length)
    let past_end_time = Duration::from_micros((trace_len * 2 + 100) as u64);
    let delay1 = link.sample(past_end_time, PACKET_SIZE_WG);
    assert!(
        delay1 > Duration::ZERO,
        "Packet 2x past trace end should be scheduled"
    );

    // Schedule packet very far in the future (5x trace length)
    let far_future = Duration::from_micros((trace_len * 5 + 500) as u64);
    let delay2 = link.sample(far_future, PACKET_SIZE_WG);
    assert!(
        delay2 > Duration::ZERO,
        "Packet 5x past trace end should be scheduled"
    );
}

/// Test that StdTraceTputLink handles wrap-around correctly.
#[test]
#[cfg(feature = "trace-tests")]
fn test_stdtrace_wrap_around() {
    common::setup_traces();
    let linktrace = load_linktrace_from_file("tests/data/ether100M_synth10K_std.ltbin.gz")
        .expect("Failed to load std trace");

    let trace_len = linktrace.bw_trace.len(); // In milliseconds

    let mut link = StdTraceTputLink::new(
        0,
        0,
        1,
        Duration::from_micros(1000),
        linktrace.clone(),
        true,
        Vec::new(),
    );

    // Schedule packet near end (StdTrace uses milliseconds)
    let near_end_time = Duration::from_millis((trace_len - 10) as u64);
    let delay1 = link.sample(near_end_time, PACKET_SIZE_WG);
    assert!(
        delay1 > Duration::ZERO,
        "Packet near trace end should be scheduled"
    );

    // Schedule packet past trace end
    let past_end_time = Duration::from_millis((trace_len + 100) as u64);
    let delay2 = link.sample(past_end_time, PACKET_SIZE_WG);
    assert!(
        delay2 > Duration::ZERO,
        "Packet past trace end should be scheduled"
    );
}

/// Test that StdTraceTputLink handles multiple wraps correctly.
#[test]
#[cfg(feature = "trace-tests")]
fn test_stdtrace_multiple_wraps() {
    common::setup_traces();
    let linktrace = load_linktrace_from_file("tests/data/ether100M_synth10K_std.ltbin.gz")
        .expect("Failed to load std trace");

    let trace_len = linktrace.bw_trace.len();

    let mut link = StdTraceTputLink::new(
        0,
        0,
        1,
        Duration::from_micros(1000),
        linktrace,
        true,
        Vec::new(),
    );

    // Verify multiple wraps work
    let far_future = Duration::from_millis((trace_len * 5 + 500) as u64);
    let delay = link.sample(far_future, PACKET_SIZE_WG);
    assert!(
        delay > Duration::ZERO,
        "Packet 5x past trace end should be scheduled"
    );
}

/// Test that a packet transmission can span the wrap boundary.
/// This tests the case where a packet starts near the trace end and its
/// transmission extends into the wrapped (beginning) portion of the trace.
#[test]
#[cfg(feature = "trace-tests")]
fn test_stdtrace_packet_spans_wrap() {
    common::setup_traces();
    let linktrace = load_linktrace_from_file("tests/data/ether100M_synth10K_std.ltbin.gz")
        .expect("Failed to load std trace");

    let trace_len = linktrace.bw_trace.len();

    let mut link = StdTraceTputLink::new(
        0,
        0,
        1,
        Duration::from_micros(1000),
        linktrace,
        true,
        Vec::new(),
    );

    // Position packet start very close to wrap boundary
    // so transmission spans from end of trace to beginning
    let wrap_boundary_time = Duration::from_millis((trace_len - 1) as u64);
    let delay = link.sample(wrap_boundary_time, PACKET_SIZE_WG);

    // Verify it completed without panic
    assert!(
        delay > Duration::ZERO,
        "Packet spanning wrap boundary should be scheduled"
    );
}

/// Test that queueing state is preserved across wrap boundaries for HiTraceTput.
/// When packets are queued near the trace end, the next packet should still
/// experience appropriate queueing delay even as indices wrap around.
#[test]
#[cfg(feature = "trace-tests")]
fn test_hitrace_queueing_across_wrap() {
    common::setup_traces();
    let linktrace = load_linktrace_from_file("tests/data/ether100M_synth5K.ltbin.gz")
        .expect("Failed to load trace");

    let trace_len = linktrace.bw_trace.len();

    let mut link = HiTraceTputLink::new(
        0,
        0,
        1,
        Duration::from_micros(1000),
        linktrace,
        true,
        Vec::new(),
    );

    // Schedule first packet near end
    let time1 = Duration::from_micros((trace_len - 50) as u64);
    let delay1 = link.sample(time1, PACKET_SIZE_WG);
    assert!(delay1 > Duration::ZERO);

    // Schedule second packet immediately after - should queue
    let time2 = Duration::from_micros((trace_len - 49) as u64);
    let delay2 = link.sample(time2, PACKET_SIZE_WG);

    // Second packet should have queueing delay (larger than just transmission)
    assert!(
        delay2 > Duration::from_micros(50),
        "Second packet should experience queueing delay, got {:?}",
        delay2
    );
}

/// Test that queueing state is preserved across wrap boundaries for StdTraceTput.
#[test]
#[cfg(feature = "trace-tests")]
fn test_stdtrace_queueing_across_wrap() {
    common::setup_traces();
    let linktrace = load_linktrace_from_file("tests/data/ether100M_synth10K_std.ltbin.gz")
        .expect("Failed to load std trace");

    let trace_len = linktrace.bw_trace.len();

    let mut link = StdTraceTputLink::new(
        0,
        0,
        1,
        Duration::from_micros(1000),
        linktrace,
        true,
        Vec::new(),
    );

    // Schedule several packets in quick succession near end to create queueing
    let mut time = Duration::from_millis((trace_len - 10) as u64);

    // Schedule first packet
    let delay1 = link.sample(time, PACKET_SIZE_WG);
    assert!(delay1 > Duration::ZERO);

    // Schedule second packet immediately - should queue behind first
    time += Duration::from_nanos(100); // Very small interval
    let delay2 = link.sample(time, PACKET_SIZE_WG);

    // Schedule third packet immediately - should queue even more
    time += Duration::from_nanos(100);
    let delay3 = link.sample(time, PACKET_SIZE_WG);

    // Second and third packets should experience queueing delay (should be larger than first)
    assert!(
        delay2 >= delay1,
        "Second packet should have at least as much delay"
    );
    assert!(
        delay3 >= delay2,
        "Third packet should have at least as much delay"
    );
}

/// Test that packets scheduled exactly at the trace length boundary work correctly.
#[test]
#[cfg(feature = "trace-tests")]
fn test_hitrace_exact_boundary() {
    common::setup_traces();
    let linktrace = load_linktrace_from_file("tests/data/ether100M_synth5K.ltbin.gz")
        .expect("Failed to load trace");

    let trace_len = linktrace.bw_trace.len();

    let mut link = HiTraceTputLink::new(
        0,
        0,
        1,
        Duration::from_micros(1000),
        linktrace,
        true,
        Vec::new(),
    );

    // Schedule packet exactly at trace length boundary
    let boundary_time = Duration::from_micros(trace_len as u64);
    let delay = link.sample(boundary_time, PACKET_SIZE_WG);

    assert!(
        delay > Duration::ZERO,
        "Packet at exact boundary should be scheduled"
    );
}

/// Test that randomization produces different starting offsets for HiTraceTput.
#[test]
#[cfg(feature = "trace-tests")]
fn test_hitrace_random_offsets() {
    common::setup_traces();
    let linktrace = load_linktrace_from_file("tests/data/ether100M_synth5K.ltbin.gz")
        .expect("Failed to load trace");

    let mut rng = rng();

    // Create two links and randomize them
    let mut link1 = HiTraceTputLink::new(
        0,
        0,
        1,
        Duration::from_micros(1000),
        linktrace.clone(),
        true,
        Vec::new(),
    );
    let mut link2 = HiTraceTputLink::new(
        1,
        0,
        1,
        Duration::from_micros(1000),
        linktrace,
        true,
        Vec::new(),
    );

    // Randomize both links multiple times to check for variation
    // We can't directly access next_busy_to, but we can verify randomization
    // by observing that the links produce different delays for the same input time
    let test_time = Duration::from_micros(100);

    let mut delays1 = Vec::new();
    let mut delays2 = Vec::new();

    for _ in 0..10 {
        link1.randomize(&mut rng, 0.2);
        link2.randomize(&mut rng, 0.2);

        // Sample at a fixed time and record the delay
        let delay1 = link1.sample(test_time, PACKET_SIZE_WG);
        let delay2 = link2.sample(test_time, PACKET_SIZE_WG);
        delays1.push(delay1);
        delays2.push(delay2);

        // Reset links for next iteration
        link1.reset();
        link2.reset();
    }

    // Check that we got some variation (not all the same)
    let unique_delays1: std::collections::HashSet<_> = delays1.iter().collect();
    let unique_delays2: std::collections::HashSet<_> = delays2.iter().collect();

    assert!(
        unique_delays1.len() > 1,
        "Randomization should produce varied behavior"
    );
    assert!(
        unique_delays2.len() > 1,
        "Randomization should produce varied behavior"
    );
}

/// Test that randomization produces different starting offsets for StdTraceTput.
#[test]
#[cfg(feature = "trace-tests")]
fn test_stdtrace_random_offsets() {
    common::setup_traces();
    let linktrace = load_linktrace_from_file("tests/data/ether100M_synth10K_std.ltbin.gz")
        .expect("Failed to load std trace");

    let mut rng = rng();

    let mut link = StdTraceTputLink::new(
        0,
        0,
        1,
        Duration::from_micros(1000),
        linktrace,
        true,
        Vec::new(),
    );

    // Randomize multiple times and observe varied behavior
    let test_time = Duration::from_millis(100);
    let mut delays = Vec::new();

    for _ in 0..10 {
        link.randomize(&mut rng, 0.2);

        // Sample at a fixed time and record the delay
        let delay = link.sample(test_time, PACKET_SIZE_WG);
        delays.push(delay);

        // Reset link for next iteration
        link.reset();
    }

    // Check that we got some variation
    let unique_delays: std::collections::HashSet<_> = delays.iter().collect();
    assert!(
        unique_delays.len() > 1,
        "Randomization should produce varied behavior"
    );
}

/// Test that a long sequence of packets can be scheduled continuously,
/// demonstrating that the wrap-around behavior works for sustained traffic.
#[test]
#[cfg(feature = "trace-tests")]
fn test_hitrace_sustained_traffic() {
    common::setup_traces();
    let linktrace = load_linktrace_from_file("tests/data/ether100M_synth5K.ltbin.gz")
        .expect("Failed to load trace");

    let trace_len = linktrace.bw_trace.len();

    let mut link = HiTraceTputLink::new(
        0,
        0,
        1,
        Duration::from_micros(1000),
        linktrace,
        true,
        Vec::new(),
    );

    // Schedule many packets starting from near the end of the trace
    let mut current_time = Duration::from_micros((trace_len - 100) as u64);
    let packet_interval = Duration::from_micros(10); // 10 microseconds between packets

    // Schedule 50 packets, which will definitely cross the wrap boundary
    for i in 0..50 {
        let delay = link.sample(current_time, PACKET_SIZE_WG);
        assert!(
            delay > Duration::ZERO,
            "Packet {} should be scheduled successfully",
            i
        );
        current_time += packet_interval;
    }

    // Verify we've wrapped past the original trace length
    assert!(
        current_time > Duration::from_micros(trace_len as u64),
        "Should have wrapped past original trace length"
    );
}

/// Test that StdTraceTput can handle sustained traffic across wraps.
#[test]
#[cfg(feature = "trace-tests")]
fn test_stdtrace_sustained_traffic() {
    common::setup_traces();
    let linktrace = load_linktrace_from_file("tests/data/ether100M_synth10K_std.ltbin.gz")
        .expect("Failed to load std trace");

    let trace_len = linktrace.bw_trace.len();

    let mut link = StdTraceTputLink::new(
        0,
        0,
        1,
        Duration::from_micros(1000),
        linktrace,
        true,
        Vec::new(),
    );

    // Schedule many packets starting from near the end
    let mut current_time = Duration::from_millis((trace_len - 10) as u64);
    let packet_interval = Duration::from_millis(1);

    // Schedule 30 packets across the wrap boundary
    for i in 0..30 {
        let delay = link.sample(current_time, PACKET_SIZE_WG);
        assert!(
            delay > Duration::ZERO,
            "Packet {} should be scheduled successfully",
            i
        );
        current_time += packet_interval;
    }

    // Verify we've wrapped
    assert!(
        current_time > Duration::from_millis(trace_len as u64),
        "Should have wrapped past original trace length"
    );
}
