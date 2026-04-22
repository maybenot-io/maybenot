// End-to-end benchmark of the simulator driven by `sim_advanced`. Scales the
// number of Maybenot machines on the client node while holding the trace size
// constant — designed to expose per-event work that grows with machine count
// (the linear scans in `pick_next_maybenot` / `maybenot_do_*`).
//
// Run with: `cargo bench -p maybenot-simulator --bench sim`.

use std::{fmt::Write, time::Duration};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use enum_map::enum_map;
use maybenot::{
    Machine,
    action::Action,
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};
use maybenot_simulator::{
    SimulatorArgs, parse_trace, sim_advanced, topology::load_topology_from_str,
};

const BASELINE_TOML: &str = include_str!("../tests/cfg/maybenot_baseline_test.toml");

// Simple two-state decoy machine firing a decoy 8us after every NormalQueued /
// DecoyQueued. Used purely to populate `scheduled_action` slots — the exact
// semantics are not what's under test.
fn decoy_machine() -> Machine {
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::DecoyQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::DecoyTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        timeout: Dist {
            dist: DistType::Uniform {
                low: 8.0,
                high: 8.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    Machine::new(0, 0, vec![s0, s1]).unwrap()
}

// Build a comma-separated trace of `n_packets` alternating sends/receives,
// spaced `step_ns` apart. The parser expects nanosecond timestamps.
fn synthetic_trace(n_packets: usize, step_ns: u64) -> String {
    let mut out = String::with_capacity(n_packets * 16);
    for i in 0..n_packets {
        let dir = if i % 2 == 0 { "s" } else { "r" };
        writeln!(out, "{},{}", i as u64 * step_ns, dir).unwrap();
    }
    out
}

fn bench_sim(c: &mut Criterion) {
    let trace = synthetic_trace(2_000, 1_000);
    let (topology, link_state) =
        load_topology_from_str(BASELINE_TOML).expect("load baseline topology");
    let (si, sq) =
        parse_trace(&trace, &topology, Duration::from_micros(20)).expect("parse synthetic trace");

    let mut group = c.benchmark_group("sim_advanced_vs_machine_count");
    for &m in &[0usize, 1, 4, 16] {
        let machines: Vec<Machine> = (0..m).map(|_| decoy_machine()).collect();

        group.bench_with_input(BenchmarkId::from_parameter(m), &machines, |b, machines| {
            b.iter(|| {
                let mut args = SimulatorArgs::new(50_000, true);
                args.insecure_rng_seed = Some(42);
                args.stop_after_all_normal_packets = true;
                let mut link_state = link_state.clone();
                let mut sq = sq.clone();
                sim_advanced(
                    machines,
                    &[],
                    &topology,
                    &mut link_state,
                    &si,
                    &mut sq,
                    &args,
                )
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_sim);
criterion_main!(benches);
