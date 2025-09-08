use std::{fs::File, io::BufWriter, path::PathBuf};

use anyhow::Result;
use log::info;
use maybenot::Machine;
use serde::{Deserialize, Serialize};

use crate::storage::load_defenses;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Limits {
    min_padding_frac: f64,
    max_padding_frac: f64,
    min_blocking_frac: f64,
    max_blocking_frac: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Release {
    version: String,
    platform: String,
    client_limits: Limits,
    server_limits: Limits,
    defenses: Vec<(Vec<String>, Vec<String>)>,
}

pub fn do_release(input: PathBuf, output: PathBuf) -> Result<()> {
    let input = load_defenses(&input)?;

    let mut defenses = vec![];

    for d in input.defenses {
        let client: Vec<String> = d.client.iter().map(Machine::serialize).collect();
        let server: Vec<String> = d.server.iter().map(Machine::serialize).collect();
        defenses.push((client, server));
    }

    let release = Release {
        version: "version".to_string(),
        platform: "platform".to_string(),
        client_limits: Limits {
            min_padding_frac: 0.0,
            max_padding_frac: 0.0,
            min_blocking_frac: 0.0,
            max_blocking_frac: 0.0,
        },
        server_limits: Limits {
            min_padding_frac: 0.0,
            max_padding_frac: 0.0,
            min_blocking_frac: 0.0,
            max_blocking_frac: 0.0,
        },
        defenses,
    };

    let file = File::create(output.clone())?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &release)?;
    info!("saved release to {}", output.display());

    Ok(())
}
