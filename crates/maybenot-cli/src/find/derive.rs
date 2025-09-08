use crate::config::Config;
use anyhow::{Result, bail};
use log::info;

pub fn derive(config: Config, seed: String) -> Result<()> {
    let Some(derive_config) = config.derive else {
        bail!("no derive configuration found in config file")
    };

    info!("attempting to derive defense with seed {seed}");
    match derive_config.derive_defense_from_seed(None, &seed)? {
        Some((defense, attempts)) => {
            info!("successfully derived defense in {attempts} attempts:");
            print!("{defense}");
            Ok(())
        }
        None => {
            bail!("failed to derive defense within maximum attempts")
        }
    }
}
