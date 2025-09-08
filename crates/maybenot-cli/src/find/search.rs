use std::{
    fs::metadata,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{config::Config, get_progress_style, storage::save_defenses};
use anyhow::{Result, bail};
use indicatif::ProgressBar;
use log::info;
use maybenot_gen::{defense::Defense, derive::DeriveConfig};
use rand::Rng;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SearchConfig {
    pub n: usize,
    pub max_search_sec: Option<usize>,
    pub seed: Option<String>,
}

pub fn search(config: Config, output: &Path, n: Option<usize>, seed: Option<String>) -> Result<()> {
    let Some(derive_config) = config.derive else {
        bail!("no derive configuration found in config file")
    };
    if metadata(output).is_ok() {
        bail!("output '{}' already exists", output.display());
    }
    let n = match n.unwrap_or(config.search.as_ref().map_or(0, |s| s.n)) {
        0 => bail!("n must be at least 1"),
        n => n,
    };
    let max_search_time = config
        .search
        .as_ref()
        .and_then(|s| s.max_search_sec)
        .map(|secs| Duration::from_secs(secs as u64));
    if let Some(max) = max_search_time {
        if max.as_secs() == 0 {
            bail!("max search time must be at least 1 second");
        }
        info!("max search time {} seconds", max.as_secs());
    }

    let mut defenses = vec![];
    let description;

    if let Some(seed) = seed.or(config.search.as_ref().and_then(|f| f.seed.clone())) {
        info!(
            "deterministically searching for up to {n} defenses with seed {seed} for xoshiro256**...",
        );
        search_deterministically(n, &seed, &derive_config, max_search_time)
            .map(|d| defenses.extend(d))?;
        description = format!("deterministic search for {n} defenses with seed {seed}");
    } else {
        info!("securely searching for up to {n} defenses using the system RNG...");
        search_securely(n, &derive_config, max_search_time).map(|d| defenses.extend(d))?;
        description = format!("secure search for {n} defenses");
    }

    info!("done, found {}/{} defenses, saving...", defenses.len(), n);
    save_defenses(description, &defenses, output)?;

    Ok(())
}

pub fn search_deterministically(
    n: usize,
    base_seed: &str,
    derive_config: &DeriveConfig,
    max_search_time: Option<Duration>,
) -> Result<Vec<Defense>> {
    let mut results: Vec<Option<Result<Defense>>> = vec![];
    let bar = ProgressBar::new(n as u64);
    bar.set_style(get_progress_style());
    let start_time = Instant::now();

    (0..n)
        .into_par_iter()
        .map(|defense_n| {
            let seed = format!("{base_seed}-{defense_n}");

            let max_runtime = max_search_time.map(|d| {
                d.checked_sub(start_time.elapsed())
                    .unwrap_or(Duration::from_secs(0))
            });

            match derive_config.derive_defense_from_seed(max_runtime, &seed) {
                Ok(Some((mut defense, attempts))) => {
                    defense.note = Some(format!("seed {seed}, attempts {attempts}"));
                    bar.inc(1);
                    Some(Ok(defense))
                }
                Ok(None) => None,
                Err(e) => Some(Err(e)),
            }
        })
        .collect_into_vec(&mut results);

    bar.finish_and_clear();
    if let Some(e) = results.iter().find_map(|r| match r {
        Some(Err(e)) => Some(e),
        _ => None,
    }) {
        bail!("error deriving defense: {}", e);
    }

    // filter and sort defenses by id to deterministically order them
    let mut defenses: Vec<Defense> = results.into_iter().flatten().flatten().collect();
    defenses.sort_by(|a, b| a.id().cmp(b.id()));

    Ok(defenses)
}

pub fn search_securely(
    n: usize,
    derive_config: &DeriveConfig,
    max_search_time: Option<Duration>,
) -> Result<Vec<Defense>> {
    let results = Arc::new(Mutex::new(Vec::with_capacity(n)));
    let cancel = Arc::new(AtomicBool::new(false));
    let bar = ProgressBar::new(n as u64);
    bar.set_style(get_progress_style());
    let start_time = Instant::now();

    // we spin up one thread per CPU core to derive defenses in parallel
    (0..num_cpus::get()).into_par_iter().for_each(|_| {
        while !cancel.load(Ordering::SeqCst) {
            let seed = format!("{:x}", rand::rng().random::<u128>());

            let max_runtime = max_search_time.map(|d| {
                d.checked_sub(start_time.elapsed())
                    .unwrap_or(Duration::from_secs(0))
            });

            let def: Option<Result<Defense>> =
                match derive_config.derive_defense_from_seed(max_runtime, &seed) {
                    Ok(Some((mut d, attempts))) => {
                        d.note = Some(format!("seed {seed}, attempts {attempts}"));
                        Some(Ok(d))
                    }
                    Ok(None) => None,
                    Err(e) => Some(Err(e)),
                };

            let mut r = results.lock().unwrap();

            // got something to add?
            let mut errored = false;
            if let Some(def) = def {
                errored = def.is_err();
                if errored {
                    r.push(def);
                } else if r.len() < n {
                    r.push(def);
                    bar.inc(1);
                    bar.set_message(format!(
                        "found {} defenses, searching for {} more",
                        r.len(),
                        n - r.len()
                    ));
                }
            }
            // check if we should cancel
            if r.len() >= n || errored || (max_runtime.is_some_and(|d| d == Duration::from_secs(0)))
            {
                cancel.store(true, Ordering::SeqCst);
                break;
            }
        }
    });

    bar.finish_and_clear();
    let results = results.lock().unwrap();
    // find the first error, if any, in the results
    if let Some(e) = results.iter().find_map(|r| r.as_ref().err()) {
        bail!("error deriving defense: {e}");
    }
    // filter out any None values, make sure we only take `n` defenses and sort
    // them by id to deterministically order them
    let mut defenses: Vec<Defense> = results
        .iter()
        .filter_map(|r| r.as_ref().ok().cloned())
        .take(n)
        .collect();
    defenses.sort_by(|a, b| a.id().cmp(b.id()));

    Ok(defenses)
}
