use std::{
    fs::{create_dir, create_dir_all, metadata, read_dir, read_to_string},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::{
    config::Config,
    get_progress_style,
    storage::{load_defenses, read_dataset},
};
use anyhow::{Context, Result, anyhow, bail};
use indicatif::ParallelProgressIterator;
use log::{info, warn};
use maybenot::TriggerEvent;
use maybenot_gen::{
    dealer::{Dealer, DealerFixed, Limits},
    defense::Defense,
    environment::{
        IntegrationType, NetworkConfig, get_example_client, get_example_server,
        integration_from_file,
    },
    rng_range,
};
use maybenot_simulator::{SimulatorArgs, network::Network, parse_trace_advanced, sim_advanced};
use rand::{Rng, RngCore, SeedableRng, seq::SliceRandom};
use rand_seeder::Seeder;
use rand_xoshiro::Xoshiro256StarStar;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SimConfig {
    /// base dataset to use for simulation, must be a directory with traces in
    /// the format <class>-<sample>.log. Between <class> and <sample> there can
    /// be any number of characters, but splitting on '-' must yield the class
    /// (first) and sample (last) parts.
    pub base_dataset: String,
    /// configuration for the network
    pub network: NetworkConfig,
    /// trace length to simulate
    pub trace_length: usize,
    /// extra events in the simulator, set higher for more complex defenses
    pub events_multiplier: usize,
    /// seed for the simulation, if not set, uses a random seed
    pub seed: Option<String>,
    /// simulate with tunable defense limits using a list of factors [0,1] to
    /// multiply limits set in the simulator config
    pub tunable_defense_limits: Option<Vec<f64>>,
    /// client limits, if not set, uses no limits
    pub client: Option<Limits>,
    /// server limits, if not set, uses no limits
    pub server: Option<Limits>,
    /// simulate each trace multiple times
    pub augmentation: Option<usize>,
    /// maximum number of samples to simulate per class/subpage
    pub max_samples: Option<usize>,
    /// integration type
    pub integration: Option<IntegrationType>,
    /// stop after all normal packets are processed, default is false
    pub stop_after_all_normal_packets_processed: Option<bool>,
}

pub fn sim(
    config: Config,
    input: Vec<PathBuf>,
    output: PathBuf,
    seed: Option<String>,
) -> Result<()> {
    let Some(cfg) = config.sim else {
        bail!("no simulation configuration found in config file")
    };
    info!("simulation configuration: {cfg:#?}");
    if metadata(&output).is_ok() {
        bail!("output '{}' already exists", output.display());
    }

    // safe to always use Xoshiro256S**, since there's nothing adversarial to
    // learn here from simulation output
    let mut rng = match &seed.or(cfg.seed.clone()) {
        Some(seed) => {
            info!("deterministic, using seed {seed}");
            Seeder::from(seed).into_rng()
        }
        None => Xoshiro256StarStar::from_os_rng(),
    };

    let mut defenses = Vec::new();
    for in_dataset in &input {
        if Path::new(in_dataset).is_dir() {
            let mut loaded = 0;
            for entry in read_dir(in_dataset)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let mut read = load_defenses(&path)?;
                    for d in read.defenses.iter_mut() {
                        d.update_id();
                    }
                    loaded += read.defenses.len();
                    defenses.extend(read.defenses);
                }
            }
            info!(
                "read {loaded} defenses from directory {}",
                in_dataset.display()
            );
            continue;
        }

        let mut read = load_defenses(in_dataset)?;
        for d in read.defenses.iter_mut() {
            d.update_id();
        }
        info!(
            "read {} defenses from {}",
            read.defenses.len(),
            in_dataset.display()
        );
        defenses.extend(read.defenses);
    }
    if input.len() > 1 {
        info!("read {} defenses in total", defenses.len());
    }
    if defenses.is_empty() {
        bail!("no defenses found in input files");
    }
    defenses.shuffle(&mut rng);

    info!("reading base dataset from {}", cfg.base_dataset);
    let base_dataset = Path::new(&cfg.base_dataset);
    if !base_dataset.exists() {
        bail!("base dataset {} does not exist", base_dataset.display());
    }
    if !base_dataset.is_dir() {
        bail!("base dataset {} is not a directory", base_dataset.display());
    }
    let dataset = read_dataset(base_dataset);
    info!("read {} traces", dataset.len());

    let mut dataset_samples = 0;
    for (_, fname, _) in &dataset {
        let parts = fname.split('-').collect::<Vec<_>>();
        // we assume that the filename ends with sample.log
        let sample: usize = parts
            .last()
            .ok_or_else(|| anyhow!("no sample found in filename: {fname}"))?
            .split('.')
            .next()
            .ok_or_else(|| anyhow!("filename format error: missing sample number in {fname}"))?
            .parse::<usize>()
            .with_context(|| format!("failed to parse sample number from filename: {fname}"))?;
        if sample + 1 > dataset_samples {
            dataset_samples = sample + 1;
        }
    }

    do_sim_def(
        &cfg,
        &mut defenses,
        &dataset,
        dataset_samples,
        output,
        &mut rng,
    )
}

pub fn do_sim_def<R: RngCore>(
    cfg: &SimConfig,
    defenses: &mut [Defense],
    dataset: &[(usize, String, String)],
    dataset_samples: usize,
    output: PathBuf,
    rng: &mut R,
) -> Result<()> {
    if let Some(aug) = cfg.augmentation {
        if aug == 0 {
            bail!("augmentation must be at least 1");
        }
        if aug > 1 {
            info!("augmenting dataset {aug} times");
        }
        // check for edge case: augmentation set and max_samples is below the
        // number of (non-augmented) samples per subpage
        if let Some(max_samples) = cfg.max_samples {
            if max_samples > 0 && max_samples < dataset_samples {
                bail!(
                    "augmentation set, but max_samples < |samples| in dataset {}",
                    dataset_samples
                );
            }
        }
    }

    let enough_defenses = defenses.len() >= dataset.len() * cfg.augmentation.unwrap_or(1);
    if enough_defenses {
        info!("enough defenses to cover dataset");
    } else {
        info!("not enough defenses to cover dataset, will randomly choose");
    }

    if let Some(limits) = &cfg.tunable_defense_limits {
        if limits.is_empty() {
            bail!("tunable defense limits cannot be empty");
        }
        if cfg.client.is_none() || cfg.server.is_none() {
            bail!("tunable defense limits require client and server limits to be set");
        }
        for limit in limits {
            if *limit < 0.0 || *limit > 1.0 {
                bail!("tunable defense limits must be in the range [0, 1]");
            }
        }
        info!("using tunable defense limits: {limits:?}");
    } else {
        info!("not using tunable defense limits");
    }

    // all checks passed, we can now simulate
    create_dir(&output)?;

    if cfg.tunable_defense_limits.is_none() {
        info!("simulating...");
        sim_dataset(
            dataset,
            dataset_samples,
            enough_defenses,
            cfg,
            defenses,
            1.0,
            &output,
            rng,
        )?;
        info!(
            "done, wrote {} traces to {}",
            dataset.len() * cfg.augmentation.unwrap_or(1),
            output.display()
        );
    } else {
        let limits = cfg.tunable_defense_limits.as_ref().unwrap();
        for limit in limits.iter() {
            // subdirectory for the limit
            let output = Path::new(&output).join(format!("limit-{limit}"));

            info!("simulating with limit {limit}...");
            sim_dataset(
                dataset,
                dataset_samples,
                enough_defenses,
                cfg,
                defenses,
                *limit,
                &output,
                rng,
            )?;
            info!(
                "done, wrote {} traces to {}",
                dataset.len() * cfg.augmentation.unwrap_or(1),
                output.display()
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sim_dataset<R: RngCore>(
    dataset: &[(usize, String, String)],
    dataset_samples: usize,
    enough_defenses: bool,
    cfg: &SimConfig,
    defenses: &[Defense],
    scale: f64,
    output: &PathBuf,
    rng: &mut R,
) -> Result<()> {
    let (c_integration, s_integration) = match cfg.integration {
        Some(IntegrationType::Example) => (get_example_client(), get_example_server()),
        Some(IntegrationType::File { ref src }) => {
            let (c, s) = integration_from_file(src)?;
            (Some(c), Some(s))
        }
        None => (None, None),
    };

    let augmentation = cfg.augmentation.unwrap_or(1);

    // create a dealer for client and server setups
    let mut dealer = DealerFixed::new(
        defenses.to_vec(),
        cfg.client.clone(),
        cfg.server.clone(),
        !enough_defenses,
        rng,
    )?;
    let setups = dealer.draw_n(dataset.len() * augmentation, scale, rng)?;

    // we need to know if the original dataset filenames are zero-padded or not
    // to generate correct filenames for the augmented traces
    let is_zero_padded = find_if_zero_padded(dataset);

    // shared seed for all traces ...
    let shared_seed: u64 = rng.random();

    dataset
        .par_iter()
        .enumerate()
        .progress_with_style(get_progress_style())
        .for_each(|(index, (class, fname, trace_path))| {
            // ... combined with a per-trace seed using the trace class+fname,
            // which is unique for our dataset structure
            let mut rng: Xoshiro256StarStar = Seeder::from(format!(
                "shared seed {shared_seed}, class {class}, fname {fname}"
            ))
            .into_rng();

            // we assume that the filename ends with sample.log
            let parts = fname.split('-').collect::<Vec<_>>();
            let sample: usize = parts
                .last()
                .unwrap()
                .split('.')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            // early exit?
            if let Some(max_samples) = cfg.max_samples {
                if max_samples > 0 && sample >= max_samples {
                    return;
                }
            }
            // prefix is everything before the sample number and extension
            let prefix = parts[..parts.len() - 1].join("-");

            let base_trace = &read_to_string(trace_path).unwrap();

            for a in 0..augmentation {
                let setup = &setups[index + dataset.len() * a];

                // sample delay and packets per second
                let network = Network::new(
                    Duration::from_millis((rng_range!(rng, cfg.network.rtt_in_ms) / 2) as u64),
                    cfg.network
                        .packets_per_sec
                        .as_ref()
                        .map(|pps| rng_range!(rng, pps)),
                );

                // parse content into a pq and sim
                let mut pq = parse_trace_advanced(
                    base_trace,
                    network,
                    c_integration.as_ref(),
                    s_integration.as_ref(),
                );
                let trace = sim_advanced(
                    &setup.client.machines,
                    &setup.server.machines,
                    &mut pq,
                    &SimulatorArgs {
                        network,
                        max_trace_length: cfg.trace_length,
                        max_sim_iterations: cfg.trace_length * cfg.events_multiplier,
                        continue_after_all_normal_packets_processed: !cfg
                            .stop_after_all_normal_packets_processed
                            .unwrap_or(false),
                        only_client_events: true,
                        only_network_activity: true,
                        max_padding_frac_client: setup.client.max_padding_frac,
                        max_blocking_frac_client: setup.client.max_blocking_frac,
                        max_padding_frac_server: setup.server.max_padding_frac,
                        max_blocking_frac_server: setup.server.max_blocking_frac,
                        insecure_rng_seed: Some(rng.next_u64()),
                        client_integration: c_integration.clone(),
                        server_integration: s_integration.clone(),
                    },
                );

                // in trace, filter out the events at the client
                if trace.is_empty() {
                    warn!("no client events in trace from {fname}, skipping");
                }
                let starting_time = if !trace.is_empty() {
                    trace[0].time
                } else {
                    Instant::now()
                };

                let mut s = String::with_capacity(cfg.trace_length * 20);
                let mut n: usize = 0;
                for t in trace {
                    if n > cfg.trace_length {
                        warn!("trace too long, truncating, broken sim args?");
                        break;
                    }

                    // timestamp, nanoseconds granularity (for consistency)
                    let ts = &format!("{}", t.time.duration_since(starting_time).as_nanos());

                    match t.event {
                        TriggerEvent::TunnelRecv => {
                            n += 1;
                            if t.contains_padding {
                                s.push_str(&format!("{ts},rp,514\n"));
                            } else {
                                s.push_str(&format!("{ts},rn,514\n"));
                            }
                        }
                        TriggerEvent::TunnelSent => {
                            n += 1;
                            if t.contains_padding {
                                s.push_str(&format!("{ts},sp,514\n"));
                            } else {
                                s.push_str(&format!("{ts},sn,514\n"));
                            }
                        }
                        _ => {}
                    }
                }

                // new fname, taking augmentation into account
                let new_fname = if !prefix.is_empty() {
                    if is_zero_padded {
                        format!("{}-{:04}.log", prefix, sample + (a * dataset_samples))
                    } else {
                        format!("{}-{}.log", prefix, sample + (a * dataset_samples))
                    }
                } else if is_zero_padded {
                    format!("{:04}.log", sample + (a * dataset_samples))
                } else {
                    format!("{}.log", sample + (a * dataset_samples))
                };

                // write to file
                let outdir = Path::new(&output).join(format!("{class}"));
                create_dir_all(&outdir).unwrap();
                let outfile = outdir.join(new_fname);
                std::fs::write(outfile, s).unwrap();
            }
        });
    Ok(())
}

fn find_if_zero_padded(dataset: &[(usize, String, String)]) -> bool {
    let mut is_zero_padded = false;
    for (_, fname, _) in dataset {
        // HACK: find more suitable way
        if fname.ends_with("-01.log") || fname.ends_with("-001.log") || fname.ends_with("-0001.log")
        {
            is_zero_padded = true;
            break;
        }
    }

    is_zero_padded
}
