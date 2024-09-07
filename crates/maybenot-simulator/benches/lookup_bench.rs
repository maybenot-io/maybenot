use std::time::Duration;

use maybenot_simulator::{
    linktrace::{load_linktrace_from_file, mk_start_instant},
    network::{ExtendedNetworkLabels, Network, NetworkBottleneck, NetworkLinktrace},
    parse_trace, sim, sim_advanced, SimulatorArgs,
};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ndarray::Array2;
use rand::Rng;

// Evaluate lookup perfpormance of different data structures
fn initialize_flat_vector(rows: usize, cols: usize) -> (Vec<u32>, Vec<(usize, usize)>) {
    let mut array: Vec<u32> = vec![0; rows * cols];
    let mut rng = rand::thread_rng();

    // Initialize the array with random numbers
    for row in 0..rows {
        for col in 0..cols {
            array[row * cols + col] = rng.gen_range(0..10000);
        }
    }

    // Generate 10,000 random indices for lookup
    let indices: Vec<(usize, usize)> = (0..10_000)
        .map(|_| (rng.gen_range(0..rows), rng.gen_range(0..cols)))
        .collect();

    (array, indices)
}

fn initialize_ndarray(rows: usize, cols: usize) -> (Array2<u32>, Vec<(usize, usize)>) {
    let mut array = Array2::<u32>::zeros((rows, cols));
    let mut rng = rand::thread_rng();

    // Initialize the array with random numbers
    for row in 0..rows {
        for col in 0..cols {
            array[[row, col]] = rng.gen_range(0..10000);
        }
    }

    // Generate 10,000 random indices for lookup
    let indices: Vec<(usize, usize)> = (0..10_000)
        .map(|_| (rng.gen_range(0..rows), rng.gen_range(0..cols)))
        .collect();

    (array, indices)
}

fn flat_vector_lookup(array: &Vec<u32>, indices: &[(usize, usize)], cols: usize) -> u64 {
    let mut sum: u64 = 0;

    // Perform lookups using pre-generated indices
    for &(row, col) in indices {
        sum += array[row * cols + col] as u64;
    }

    black_box(sum) // Prevents the compiler from optimizing away the computation
}

fn ndarray_lookup(array: &Array2<u32>, indices: &[(usize, usize)]) -> u64 {
    let mut sum: u64 = 0;

    // Perform lookups using pre-generated indices
    for &(row, col) in indices {
        sum += array[[row, col]] as u64;
    }

    black_box(sum) // Prevents the compiler from optimizing away the computation
}

pub fn benchmark_flat_vector(c: &mut Criterion) {
    let rows = 22;
    let cols = 5_000_000;
    let (array, indices) = initialize_flat_vector(rows, cols); // Initialize once

    c.bench_function("Flat Vector Lookup", |b| {
        b.iter(|| flat_vector_lookup(&array, &indices, cols))
    });
}

pub fn benchmark_ndarray(c: &mut Criterion) {
    let rows = 22;
    let cols = 5_000_000;
    let (array, indices) = initialize_ndarray(rows, cols); // Initialize once

    c.bench_function("Ndarray Lookup", |b| {
        b.iter(|| ndarray_lookup(&array, &indices))
    });
}

// Evaluate lookup performace for different sizes of traces. Larger traces will be slower
// because of less cache locality. Note that the random lookup here is conservative as the
// actual use would be sequentially increasing within a limited range.
pub fn benchmark_busy_to(c: &mut Criterion) {
    // List of linktrace files to benchmark
    let linktrace_files = vec![
        "tests/ether100M_synth5K.ltbin.gz",
        "tests/ether100M_synth5M.ltbin.gz",
        "tests/ether100M_synth40M.ltbin.gz",
    ];

    let nr_samples = 10_000;
    let mut rng = rand::thread_rng();

    for file in linktrace_files {
        // Load the LinkTrace instance from the file
        let linksim_trace = load_linktrace_from_file(file).expect(&format!(
            "Failed to load LinkTrace ltbin from file: {}",
            file
        ));

        // Generate random time slot values between 0 and trace length
        let nr_time_slots = linksim_trace.get_nr_timeslots() as usize;
        let time_slots: Vec<usize> = (0..nr_samples)
            .map(|_| rng.gen_range(0..nr_time_slots))
            .collect();

        // Generate random packet size values between 40 and 1500
        let pkt_sizes: Vec<i32> = (0..nr_samples).map(|_| rng.gen_range(40..=1500)).collect();

        // Benchmark the get_dl_busy_to function for the current linktrace file
        c.bench_function(&format!("get_dl_busy_to_  {}", file), |b| {
            b.iter(|| {
                for i in 0..nr_samples {
                    // Use black_box to prevent the compiler from optimizing away the call
                    black_box(linksim_trace.get_dl_busy_to(time_slots[i], pkt_sizes[i]));
                }
            })
        });
    }
}

fn simulator_execution(c: &mut Criterion) {
    //How many packets to process
    let nr_iter = 10_000;

    // Initialize the vector with the first Instant
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
    // Initalize network, start with a reasonable 10ms delay
    let network = Network::new(Duration::from_millis(10), None);
    let linktrace = load_linktrace_from_file("tests/ether100M_synth5M.ltbin.gz")
        .expect("Failed to load LinkTrace ltbin from file");
    let mut network_lt = NetworkLinktrace::new(network, linktrace);

    c.bench_function("Linktrace network.sample", |b| {
        b.iter(|| {
            for i in 0..nr_iter {
                // Use black_box to prevent the compiler from optimizing away the call
                black_box(network_lt.sample(&instants[i], true));
                network_lt.reset_linktrace();
            }
        })
    });

    let network = Network::new(Duration::from_millis(10), None);
    let mut network_bneck =
        NetworkBottleneck::new(network, Duration::from_millis(1000), Some(1000));

    c.bench_function("Bottleneck network.sample", |b| {
        b.iter(|| {
            for i in 0..nr_iter {
                // Use black_box to prevent the compiler from optimizing away the call
                black_box(network_bneck.sample(&instants[i], true));
                // TODO: Find out why memory consumption goes haywaire without the line below...
                network_lt.reset_linktrace();
            }
        })
    });

    let network = Network::new(Duration::from_millis(10), Some(100));
    let mut network_bneck = NetworkBottleneck::new(network, Duration::from_millis(1000), Some(100));

    c.bench_function("Bottleneck network.sample queue_pps 100", |b| {
        b.iter(|| {
            for i in 0..nr_iter {
                // Use black_box to prevent the compiler from optimizing away the call
                black_box(network_bneck.sample(&instants[i], true));
                network_lt.reset_linktrace();
            }
        })
    });

    //sim(&[], &[], &mut pq.clone(), network.delay, 1000, true);
}

fn simple_simulator_run(c: &mut Criterion) {
    const EARLY_TRACE: &str = include_str!("../tests/EARLY_TEST_TRACE.log");

    c.bench_function("Simple network simulation run", |b| {
        b.iter(|| {
            let network = Network::new(Duration::from_millis(10), None);
            let pq = parse_trace(EARLY_TRACE, &network);
            black_box(sim(&[], &[], &mut pq.clone(), network.delay, 10000, true));
        });
    });
}

fn bottleneck_simulator_run(c: &mut Criterion) {
    const EARLY_TRACE: &str = include_str!("../tests/EARLY_TEST_TRACE.log");

    c.bench_function("Bottleneck network simulation run", |b| {
        b.iter(|| {
            let network = Network::new(Duration::from_millis(10), None);
            let sq = parse_trace(EARLY_TRACE, &network);
            let args = SimulatorArgs::new(&network, 10000, true, None, None);
            black_box(sim_advanced(&[], &[], &mut sq.clone(), &args));
        });
    });
}

fn linktrace_simulator_run(c: &mut Criterion) {
    const EARLY_TRACE: &str = include_str!("../tests/EARLY_TEST_TRACE.log");

    let linktrace = load_linktrace_from_file("tests/ether100M_synth40M.ltbin.gz")
        .expect("Failed to load LinkTrace ltbin from file");

    c.bench_function("Linktrace network simulation run", |b| {
        b.iter(|| {
            let network = Network::new(Duration::from_millis(10), None);
            let sq = parse_trace(EARLY_TRACE, &network);
            let args = SimulatorArgs::new(
                &network,
                10000,
                true,
                Some(ExtendedNetworkLabels::Linktrace),
                Some(linktrace.clone()),
            );
            black_box(sim_advanced(&[], &[], &mut sq.clone(), &args));
        });
    });
}

//criterion_group!(benches, benchmark_flat_vector, benchmark_ndarray, benchmark_busy_to);
//criterion_group!(benches, benchmark_busy_to, simulator_execution);
//criterion_group!(benches, benchmark_busy_to, simulator_execution, simulator_exec_new_network);
criterion_group!(
    benches,
    benchmark_busy_to,
    simulator_execution,
    simple_simulator_run,
    bottleneck_simulator_run,
    linktrace_simulator_run
);
//criterion_group!(benches, linktrace_simulator_run);
criterion_main!(benches);
