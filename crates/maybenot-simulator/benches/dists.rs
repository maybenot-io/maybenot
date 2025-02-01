use criterion::{black_box, criterion_group, criterion_main, Criterion};
use maybenot::dist::{Dist, DistType};
use rand::Rng;
use rand_xoshiro::rand_core::SeedableRng;
use rand_xoshiro::Xoshiro256StarStar;

pub fn dist_benchmarks(c: &mut Criterion) {
    let n = 10;

    c.bench_function("DistType::Uniform 10 samples", |b| {
        let rng = &mut Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            let point = rng.gen_range(50_000.0..1_000_000.0);

            let x = round_f64(rng.gen_range(0.0..=point));
            let y = round_f64(rng.gen_range(x..=point));
            let d = Dist {
                dist: DistType::Uniform { low: x, high: y },
                start: 0.0,
                max: 0.0,
            };
            bench_dist(rng, d, black_box(n))
        })
    });

    c.bench_function("DistType::Normal 10 samples", |b| {
        let rng = &mut Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            let point = rng.gen_range(50_000.0..1_000_000.0);

            let d = Dist {
                dist: DistType::Normal {
                    mean: round_f64(rng.gen_range(0.0..=point)),
                    stdev: round_f64(rng.gen_range(0.0..=point)),
                },
                start: 0.0,
                max: 0.0,
            };
            bench_dist(rng, d, black_box(n))
        })
    });

    c.bench_function("DistType::SkewNormal 10 samples", |b| {
        let rng = &mut Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            let point = rng.gen_range(50_000.0..1_000_000.0);

            let d = Dist {
                dist: DistType::SkewNormal {
                    location: round_f64(rng.gen_range(point * 0.5..point * 1.5)),
                    scale: round_f64(rng.gen_range(point / 100.0..=point / 10.0)),
                    shape: round_f64(rng.gen_range(-5.0..=5.0)),
                },
                start: 0.0,
                max: 0.0,
            };
            bench_dist(rng, d, black_box(n))
        })
    });

    c.bench_function("DistType::LogNormal 10 samples", |b| {
        let rng = &mut Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            let d = Dist {
                dist: DistType::LogNormal {
                    mu: round_f64(rng.gen_range(0.0..=20.0)),
                    sigma: round_f64(rng.gen_range(0.0..=1.0)),
                },
                start: 0.0,
                max: 0.0,
            };
            bench_dist(rng, d, black_box(n))
        })
    });

    c.bench_function("DistType::Binomial 10 samples", |b| {
        let rng = &mut Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            let d = Dist {
                dist: DistType::Binomial {
                    trials: rng.gen_range(10..=1000),
                    probability: round_f64(rng.gen_range(0.0..=1.0)),
                },
                start: 0.0,
                max: 0.0,
            };
            bench_dist(rng, d, black_box(n))
        })
    });

    c.bench_function("DistType::Geometric 10 samples", |b| {
        let rng = &mut Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            let d = Dist {
                dist: DistType::Geometric {
                    probability: round_f64(rng.gen_range(0.0..=1.0)),
                },
                start: 0.0,
                max: 0.0,
            };
            bench_dist(rng, d, black_box(n))
        })
    });

    c.bench_function("DistType::Pareto 10 samples", |b| {
        let rng = &mut Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            let point = rng.gen_range(50_000.0..1_000_000.0);
            let d = Dist {
                dist: DistType::Pareto {
                    scale: round_f64(
                        rng.gen_range::<f64, _>(point / 100.0..point / 10.0)
                            .max(0.001),
                    ),
                    shape: round_f64(rng.gen_range(0.001..=10.0)),
                },
                start: 0.0,
                max: 0.0,
            };
            bench_dist(rng, d, black_box(n))
        })
    });

    c.bench_function("DistType::Poisson 10 samples", |b| {
        let rng = &mut Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            let point = rng.gen_range(50_000.0..1_000_000.0);
            let d = Dist {
                dist: DistType::Poisson {
                    lambda: round_f64(rng.gen_range(0.0..=point)),
                },
                start: 0.0,
                max: 0.0,
            };
            bench_dist(rng, d, black_box(n))
        })
    });

    c.bench_function("DistType::Weibull 10 samples", |b| {
        let rng = &mut Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            let point = rng.gen_range(50_000.0..1_000_000.0);
            let d = Dist {
                dist: DistType::Weibull {
                    scale: round_f64(rng.gen_range(0.0..=point)),
                    shape: round_f64(rng.gen_range(0.5..5.0)),
                },
                start: 0.0,
                max: 0.0,
            };
            bench_dist(rng, d, black_box(n))
        })
    });

    c.bench_function("DistType::Gamma 10 samples", |b| {
        let rng = &mut Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            let point = rng.gen_range(50_000.0..1_000_000.0);
            let d = Dist {
                dist: DistType::Gamma {
                    scale: round_f64(rng.gen_range(0.001..=point)),
                    shape: round_f64(rng.gen_range(0.001..=10.0)),
                },
                start: 0.0,
                max: 0.0,
            };
            bench_dist(rng, d, black_box(n))
        })
    });

    c.bench_function("DistType::Beta 10 samples", |b| {
        let rng = &mut Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            let point = rng.gen_range(50_000.0..1_000_000.0);
            let d = Dist {
                dist: DistType::Beta {
                    alpha: round_f64(rng.gen_range(0.0..=point)),
                    beta: round_f64(rng.gen_range(0.0..=point)),
                },
                start: 0.0,
                max: 0.0,
            };
            bench_dist(rng, d, black_box(n))
        })
    });
}

fn criterion_config() -> Criterion {
    Criterion::default().sample_size(1_000)
}

criterion_group! {
    name = dists;
    config = criterion_config();
    targets = dist_benchmarks
}
criterion_main!(dists);

fn bench_dist<R: rand::Rng>(rng: &mut R, d: Dist, n: usize) {
    for _ in 0..n {
        d.sample(rng);
    }
}

// from gen crate
pub fn round_f32(num: f32) -> f32 {
    const THREE_DECIMAL_PLACES: f32 = 1000.0;
    (num * THREE_DECIMAL_PLACES).round() / THREE_DECIMAL_PLACES
}
pub fn round_f64(num: f64) -> f64 {
    const THREE_DECIMAL_PLACES: f64 = 1000.0;
    (num * THREE_DECIMAL_PLACES).round() / THREE_DECIMAL_PLACES
}
