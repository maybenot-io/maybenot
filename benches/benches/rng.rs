use criterion::{Criterion, black_box, criterion_group, criterion_main};
use enum_map::enum_map;
use maybenot::Machine;
use maybenot::dist::{Dist, DistType};
use maybenot::event::Event;
use maybenot::state::{State, Trans};
use maybenot_simulator::topology::{NetworkLinkState, NetworkTopology};
use maybenot_simulator::{
    PARSE_ONE_WAY_DELAY_HTTPS, SimInfo, SimQueue, SimulatorArgs, parse_trace, settings::Setting,
    sim_advanced,
};
use rand::SeedableRng;
use rand_core::Rng;
use rand_xoshiro::Xoshiro256StarStar;

pub fn dist_rng_source_benchmarks(c: &mut Criterion) {
    let n = 10;
    c.bench_function("11 distributions 10 samples, thread_rng()", |b| {
        let mut rng = rand::rng();
        b.iter(|| {
            sample_uniform(&mut rng, black_box(n));
            sample_normal(&mut rng, black_box(n));
            sample_skew_normal(&mut rng, black_box(n));
            sample_log_normal(&mut rng, black_box(n));
            sample_binomial(&mut rng, black_box(n));
            sample_geometric(&mut rng, black_box(n));
            sample_pareto(&mut rng, black_box(n));
            sample_poisson(&mut rng, black_box(n));
            sample_weibull(&mut rng, black_box(n));
            sample_gamma(&mut rng, black_box(n));
            sample_beta(&mut rng, black_box(n));
        })
    });
    c.bench_function("11 distributions 10 samples, Xoshiro256StarStar", |b| {
        let mut rng = Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            sample_uniform(&mut rng, black_box(n));
            sample_normal(&mut rng, black_box(n));
            sample_skew_normal(&mut rng, black_box(n));
            sample_log_normal(&mut rng, black_box(n));
            sample_binomial(&mut rng, black_box(n));
            sample_geometric(&mut rng, black_box(n));
            sample_pareto(&mut rng, black_box(n));
            sample_poisson(&mut rng, black_box(n));
            sample_weibull(&mut rng, black_box(n));
            sample_gamma(&mut rng, black_box(n));
            sample_beta(&mut rng, black_box(n));
        })
    });
}

pub fn transition_rng_source_benchmarks(c: &mut Criterion) {
    let n = 10;

    // create a state with several transition probabilities
    let state = State::new(enum_map! {
        Event::PacketSent => vec![
            Trans(0, 0.1),
            Trans(1, 0.1),
            Trans(2, 0.1),
            Trans(3, 0.1),
            Trans(4, 0.1),
            Trans(5, 0.1),
            Trans(6, 0.1),
            Trans(7, 0.1),
            Trans(8, 0.1),
            Trans(9, 0.1),
        ],
    _ => vec![],
    });

    c.bench_function("1000 state transitions, thread_rng()", |b| {
        let mut rng = rand::rng();
        b.iter(|| {
            sample_state(&state, &mut rng, black_box(n));
        })
    });
    c.bench_function("1000 state transitions, Xoshiro256StarStar", |b| {
        let mut rng = Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            sample_state(&state, &mut rng, black_box(n));
        })
    });
}

pub fn complete_trace_rng_source_benchmarks(c: &mut Criterion) {
    let n = 1;
    const EARLY_TRACE: &str =
        include_str!("../../crates/maybenot-simulator/tests/EARLY_TEST_TRACE.log");
    // No user-configured RTT here — fall back to the reasonable HTTPS constant.
    let (topology, link_state) = Setting::Vpn.create().expect("build Vpn topology");
    let (si, sq) =
        parse_trace(EARLY_TRACE, &topology, PARSE_ONE_WAY_DELAY_HTTPS).expect("parse EARLY_TRACE");
    let mut args = SimulatorArgs::new(1000, true);

    let client: Vec<Machine> = vec![];
    let server: Vec<Machine> = vec![];
    // default is to use thread_rng()
    args.insecure_rng_seed = None;
    c.bench_function("1k trace simulation, no machines, thread_rng()", |b| {
        b.iter(|| {
            run_sim(
                &client,
                &server,
                &topology,
                &link_state,
                &si,
                &sq,
                &args,
                black_box(n),
            );
        })
    });
    // setting the seed enables deterministic simulation using the Xoshiro256StarStar RNG
    args.insecure_rng_seed = Some(0);
    c.bench_function(
        "1k trace simulation, no machines, Xoshiro256StarStar",
        |b| {
            b.iter(|| {
                run_sim(
                    &client,
                    &server,
                    &topology,
                    &link_state,
                    &si,
                    &sq,
                    &args,
                    black_box(n),
                );
            })
        },
    );

    // TODO: benchmarks for decoy and delaying machines
}

criterion_group!(
    rng,
    dist_rng_source_benchmarks,
    transition_rng_source_benchmarks,
    complete_trace_rng_source_benchmarks
);
criterion_main!(rng);

#[allow(clippy::too_many_arguments)]
fn run_sim(
    client: &[Machine],
    server: &[Machine],
    topology: &NetworkTopology,
    link_state: &NetworkLinkState,
    si: &SimInfo,
    sq: &SimQueue,
    args: &SimulatorArgs,
    n: usize,
) {
    for _ in 0..n {
        let mut link_state = link_state.clone();
        let mut sq = sq.clone();
        sim_advanced(client, server, topology, &mut link_state, si, &mut sq, args);
    }
}

fn sample_state<R: Rng>(s: &State, rng: &mut R, n: usize) {
    for _ in 0..n {
        s.sample_state(Event::PacketSent, rng);
    }
}

fn sample_uniform<R: Rng>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Uniform {
            low: 0.0,
            high: 0.0,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_normal<R: Rng>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Normal {
            mean: 10.0,
            stdev: 20.0,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_skew_normal<R: Rng>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::SkewNormal {
            location: 10.0,
            scale: 20.0,
            shape: 0.5,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_log_normal<R: Rng>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::LogNormal {
            mu: 10.0,
            sigma: 20.0,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_binomial<R: Rng>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Binomial {
            trials: 10,
            probability: 0.5,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_geometric<R: Rng>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Geometric { probability: 0.5 },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_pareto<R: Rng>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Pareto {
            shape: 2.0,
            scale: 1.0,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_poisson<R: Rng>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Poisson { lambda: 2.0 },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_weibull<R: Rng>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Weibull {
            shape: 2.0,
            scale: 1.0,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_gamma<R: Rng>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Gamma {
            shape: 2.0,
            scale: 1.0,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_beta<R: Rng>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Beta {
            alpha: 2.0,
            beta: 1.0,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}
