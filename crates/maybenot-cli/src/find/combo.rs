use std::{
    fs::{metadata, read_dir},
    path::{Path, PathBuf},
};

use crate::{
    config::Config,
    get_progress_style,
    storage::{load_defenses, save_defenses},
};
use anyhow::{Result, anyhow, bail};
use indicatif::ProgressBar;
use log::{debug, info};
use maybenot_gen::{
    combo::{big_uint_to_scientific, combine_machines, count_stacked_combinations},
    constraints::ConstraintsConfig,
    environment::EnvironmentConfig,
};
use rand::{Rng, seq::SliceRandom};
use rand_seeder::Seeder;
use rand_xoshiro::Xoshiro256StarStar;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};

/// The configuration for creating defenses by combining machines
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComboConfig {
    /// the number of defenses to create
    pub n: Option<usize>,
    /// the maximum number of machines per defense
    pub height: Option<usize>,
    /// the maximum number of attempts to find a constrained defense before
    /// sampling another environment (default: 100)
    pub max_attempts: Option<usize>,
    /// if not set, ignore constraints when combining machines as new defenses
    pub constraints: Option<ConstraintsConfig>,
    /// the environment for constraints if provided
    pub env: Option<EnvironmentConfig>,
    /// a seed for the random number generator
    pub seed: Option<String>,
}

pub fn combo(
    config: Config,
    input: Vec<PathBuf>,
    output: &Path,
    n: Option<usize>,
    height: Option<usize>,
    seed: Option<String>,
) -> Result<()> {
    let combo_config = config
        .combo
        .ok_or_else(|| anyhow!("combo configuration is missing in the provided config file"))?;

    let height = height
        .or(combo_config.height)
        .ok_or_else(|| anyhow!("height of defenses must be set"))?;
    if height < 1 {
        bail!("height of defenses must be at least 1");
    }

    let n = n
        .or(combo_config.n)
        .ok_or_else(|| anyhow!("number of defenses to create must be set"))?;
    if n == 0 {
        bail!("number of defenses to create must be at least 1");
    }

    let max_attempts = combo_config.max_attempts.unwrap_or(100);
    if max_attempts == 0 {
        bail!("maximum attempts must be greater than 0");
    }
    if metadata(output).is_ok() {
        bail!("output '{}' already exists", output.display());
    }

    let mut rng: Box<dyn rand::RngCore> = match &seed.or(combo_config.seed.clone()) {
        Some(seed) => {
            info!("deterministic, using seed {seed}");
            Box::new(Seeder::from(seed).into_rng::<Xoshiro256StarStar>())
        }
        None => {
            info!("using system RNG");
            Box::new(rand::rng())
        }
    };

    let mut clients = Vec::new();
    let mut servers = Vec::new();
    let mut load_from_path = |i: &Path| -> Result<()> {
        info!("loading defenses from {}...", i.display());
        match load_defenses(i) {
            Ok(read) => {
                info!(
                    "loaded {} defenses from '{}'",
                    read.defenses.len(),
                    i.display()
                );
                for d in read.defenses {
                    clients.extend(d.client);
                    servers.extend(d.server);
                }
            }
            Err(_) => {
                info!("no defenses in {}", i.display());
            }
        }
        Ok(())
    };
    for i in &input {
        if Path::new(i).is_dir() {
            info!("loading defenses from directory {}", i.display());
            for entry in read_dir(i)? {
                let entry = entry?;
                if entry.path().is_file() {
                    load_from_path(&entry.path())?;
                }
            }
        } else {
            load_from_path(i)?;
        }
    }
    if clients.is_empty() || servers.is_empty() {
        bail!("no machines loaded");
    }
    info!(
        "in total {} client machines and {} server machines",
        clients.len(),
        servers.len()
    );

    let possible = count_stacked_combinations(clients.len(), servers.len(), height);
    info!(
        "possible combinations with height {}: {}",
        height,
        big_uint_to_scientific(&possible, 3)
    );

    clients.shuffle(&mut rng);
    servers.shuffle(&mut rng);

    info!("creating {n} defenses with height {height}...");
    let bar = ProgressBar::new(n as u64);
    bar.set_style(get_progress_style());

    let mut defenses = vec![];
    let mut remaining = n;

    loop {
        let base_seed: u64 = rng.random();
        let collected = (0..remaining)
            .into_par_iter()
            .map(|n| {
                // create a new RNG for each defense for deterministic results
                let mut rng: Xoshiro256StarStar =
                    Seeder::from(format!("{base_seed}-{n}")).into_rng();
                loop {
                    let constraints = combo_config.constraints.clone();
                    let env = combo_config.env.clone();
                    let r = combine_machines(
                        &clients,
                        &servers,
                        height,
                        max_attempts,
                        constraints,
                        env,
                        &mut rng,
                    );
                    match r {
                        Ok(Some(defense)) => {
                            bar.inc(1);
                            return Ok(defense);
                        }
                        Ok(None) => debug!("No valid defense found, retrying..."),
                        Err(e) => return Err(e),
                    }
                }
            })
            .collect::<Vec<_>>();

        if let Some(e) = collected.iter().find_map(|r| r.as_ref().err()) {
            bail!("error combining defense: {}", e);
        }

        // sort by id to deterministically order, then remove duplicates
        defenses.extend(collected.into_iter().filter_map(Result::ok));
        defenses.sort_by(|a, b| a.id().cmp(b.id()));
        defenses.dedup_by(|a, b| a.id() == b.id());
        remaining = n - defenses.len();
        if remaining == 0 {
            break;
        }
        info!("removed {remaining} duplicate defenses, creating new ones...");
        bar.set_position((n - remaining) as u64);
    }

    bar.finish_and_clear();

    info!("done, saving...");
    save_defenses("combo".to_owned(), &defenses, output)?;

    Ok(())
}
