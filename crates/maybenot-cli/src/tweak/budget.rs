use std::{fs::metadata, ops::RangeInclusive, path::PathBuf};

use anyhow::{Result, anyhow, bail};
use log::info;
use maybenot::Machine;
use rand::Rng;
use rand::RngCore;
use rand_seeder::Seeder;
use rand_xoshiro::Xoshiro256StarStar;

use crate::storage::load_defenses;
use crate::storage::save_defenses;

const BUDGETS: [&str; 4] = ["abs_pad", "abs_block", "max_pad", "max_block"];

pub fn budget(
    input: PathBuf,
    output: PathBuf,
    client: Vec<String>,
    server: Vec<String>,
    soft: Option<bool>,
    seed: Option<String>,
) -> Result<()> {
    if metadata(&output).is_ok() {
        bail!("output '{}' already exists", output.display());
    }
    if client.is_empty() && server.is_empty() {
        bail!(
            "missing client and server budgets, valid budgets are (min and max are floats, sampled range inclusive): {} min max",
            BUDGETS.join("|")
        );
    }
    let client = client
        .into_iter()
        .map(|c| parse_budget_item(&c))
        .collect::<Result<Vec<_>, _>>()?;
    let server = server
        .into_iter()
        .map(|s| parse_budget_item(&s))
        .collect::<Result<Vec<_>, _>>()?;
    let mut rng: Box<dyn rand::RngCore> = match seed {
        Some(seed) => {
            info!("deterministic, using seed {seed}");
            Box::new(Seeder::from(seed).into_rng::<Xoshiro256StarStar>())
        }
        None => {
            info!("using system RNG");
            Box::new(rand::rng())
        }
    };

    let mut loaded_defenses = load_defenses(&input)?;
    info!(
        "loaded {} defenses from {}",
        loaded_defenses.defenses.len(),
        input.display()
    );

    if !client.is_empty() {
        info!("client budgets:");
        for (name, range) in &client {
            info!("  {}: [{}, {}]", name, range.start(), range.end());
        }
    }
    if !server.is_empty() {
        info!("server budgets:");
        for (name, range) in &server {
            info!("  {}: [{}, {}]", name, range.start(), range.end());
        }
    }

    let soft = soft.unwrap_or(false);
    info!("soft budget: {soft}");

    info!(
        "updating budgets for {} defenses",
        loaded_defenses.defenses.len()
    );
    for defense in &mut loaded_defenses.defenses {
        for m in &mut defense.client {
            update_budgets(m, client.clone(), soft, &mut rng);
        }
        for m in &mut defense.server {
            update_budgets(m, server.clone(), soft, &mut rng);
        }
    }

    info!("saving updated defenses to {}", output.display());
    save_defenses(
        loaded_defenses.description,
        &loaded_defenses.defenses,
        &output,
    )
}

fn update_budgets<R: RngCore>(
    machine: &mut Machine,
    budgets: Vec<(String, RangeInclusive<f64>)>,
    soft: bool,
    rng: &mut R,
) {
    for (name, range) in budgets {
        match name.as_str() {
            "abs_pad" => {
                if machine.allowed_padding_packets == 0 || !soft {
                    machine.allowed_padding_packets = rng.random_range(range).round() as u64;
                }
            }
            "abs_block" => {
                if machine.allowed_blocked_microsec == 0 || !soft {
                    machine.allowed_blocked_microsec = rng.random_range(range).round() as u64;
                }
            }
            "max_pad" => {
                if machine.max_padding_frac == 0.0 || !soft {
                    machine.max_padding_frac = rng.random_range(range).clamp(0.0, 1.0);
                }
            }
            "max_block" => {
                if machine.max_blocking_frac == 0.0 || !soft {
                    machine.max_blocking_frac = rng.random_range(range).clamp(0.0, 1.0);
                }
            }
            _ => unreachable!(),
        }
    }
}

fn parse_budget_item(item: &str) -> Result<(String, RangeInclusive<f64>)> {
    let parts: Vec<&str> = item.split_whitespace().collect();
    if parts.len() != 3 {
        bail!(
            "invalid budget item '{}', expected format: name min max",
            item
        );
    }
    let name = parts[0].to_string();
    let min: f64 = parts[1]
        .parse()
        .map_err(|_| anyhow!("invalid min value in '{}'", item))?;
    let max: f64 = parts[2]
        .parse()
        .map_err(|_| anyhow!("invalid max value in '{}'", item))?;
    if min > max {
        bail!(
            "invalid budget item '{}', min value is greater than max",
            item
        );
    }
    if !BUDGETS.contains(&name.as_str()) {
        bail!(
            "invalid budget name '{}', valid names are: {}",
            name,
            BUDGETS.join(", ")
        );
    }
    Ok((name, min..=max))
}
