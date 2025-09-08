use anyhow::{Result, bail};
use log::info;
use maybenot_gen::defense::Defense;
use maybenot_machines::{StaticMachine, get_machine, get_static_machine_strings};
use rand_seeder::Seeder;
use rand_xoshiro::Xoshiro256StarStar;
use std::{fs::metadata, path::PathBuf, str::FromStr};

use crate::storage::{load_defenses, save_defenses};

pub fn fixed(
    input: Option<PathBuf>,
    output: PathBuf,
    client: Vec<String>,
    server: Vec<String>,
    n: Option<usize>,
    seed: Option<String>,
) -> Result<()> {
    if metadata(&output).is_ok() {
        bail!("output '{}' already exists", output.display());
    }
    if client.is_empty() && server.is_empty() {
        let valid_machines = get_static_machine_strings();
        bail!(
            "no client or server machines provided, please specify at least one of each, valid machines are:\n{}",
            valid_machines.join("\n")
        );
    }
    let n = n.unwrap_or(1);
    if n == 0 {
        bail!("n must be greater than 0");
    }
    // note that we need to Box here, since if in a setting where adversaries
    // can observe some machines, using Xoshiro256StarStar is insecure
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

    if !client.is_empty() {
        info!("parsing client machines...");
    }
    let client = client
        .into_iter()
        .map(|c| StaticMachine::from_str(&c))
        .collect::<Result<Vec<_>>>()?;
    if !client.is_empty() {
        info!("client machines: {client:?}");
    }
    if !server.is_empty() {
        info!("parsing server machines...");
    }
    let server = server
        .into_iter()
        .map(|s| StaticMachine::from_str(&s))
        .collect::<Result<Vec<_>>>()?;
    if !server.is_empty() {
        info!("server machines: {server:?}");
    }

    let mut defenses = vec![];
    let mut description = String::new();
    if let Some(input) = input {
        info!("loading defenses from input file {}", input.display());
        let loaded = load_defenses(&input)?;
        info!("will add machines to each loaded defense, repeating {n} times");
        for _ in 0..n {
            defenses.extend(loaded.defenses.iter().cloned());
        }
        description = loaded.description;
    } else {
        info!("no input file provided, generating {n} new empty defenses to add machines to");
        defenses.extend((0..n).map(|_| Defense::new(vec![], vec![])));
    }

    for defense in &mut defenses {
        defense.client.extend(get_machine(&client, &mut rng));
        defense.server.extend(get_machine(&server, &mut rng));
        defense.update_id();
    }

    // update description if we loaded defenses
    description = if description.is_empty() {
        format!("fixed {client:?} client and {server:?} server machines")
    } else {
        format!("{description}, fixed {client:?} client and {server:?} server machines",)
    };
    info!(
        "done, saving {} defenses to {}",
        defenses.len(),
        output.display()
    );
    save_defenses(description, &defenses, &output)
}
