use std::{
    time::{Duration, Instant},
    vec,
};

use anyhow::{Result, bail};
use log::{Level, debug, log_enabled};
use rand::Rng;
use rand_seeder::Seeder;
use rand_xoshiro::Xoshiro256StarStar;
use serde::{Deserialize, Serialize};

use crate::{
    constraints::ConstraintsConfig,
    defense::Defense,
    environment::{Environment, EnvironmentConfig},
    random_machine::RandomMachineConfig,
};

/// Complete configuration for defense derivation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeriveConfig {
    /// The constraints the defense must satisfy.
    pub constraints: ConstraintsConfig,
    /// The environment to derive the defense in.
    pub env: EnvironmentConfig,
    /// The type of machines making up the defense.
    pub machine: RandomMachineConfig,
    /// If set, the maximum number of attempts to derive a defense.
    pub max_attempts: Option<usize>,
    /// If set, the maximum duration (in seconds) to attempt to derive a
    /// defense.
    pub max_duration_sec: Option<usize>,
}

/// The default maximum number of attempts to derive a defense.
pub const DEFAULT_MAX_ATTEMPTS: usize = 1024;

impl DeriveConfig {
    /// Attempt to derive a defense from a configuration.
    pub fn derive_defense<R: Rng>(
        &self,
        max_duration_sec: Option<Duration>,
        rng: &mut R,
    ) -> Result<Option<(Defense, usize)>> {
        let max_attempts = self.max_attempts.unwrap_or(DEFAULT_MAX_ATTEMPTS);
        if max_attempts == 0 {
            bail!("max_attempts must be greater than 0");
        }
        let max_duration = max_duration_sec.or_else(|| {
            self.max_duration_sec
                .map(|sec| Duration::from_secs(sec as u64))
        });

        let env = Environment::new(&self.env, &self.constraints, rng)?;

        // attempt to derive the defense
        find_constrained_defense(
            &self.constraints,
            &env,
            max_attempts,
            max_duration,
            &self.machine,
            rng,
        )
    }

    /// Attempt to derive a defense deterministically from a seed. The seed must
    /// be an ASCII string, which is hashed to create a random seed for the
    /// Xoshiro256** RNG.
    pub fn derive_defense_from_seed(
        &self,
        max_duration_sec: Option<Duration>,
        seed: &str,
    ) -> Result<Option<(Defense, usize)>> {
        if !seed.is_ascii() {
            bail!("seed must be an ascii string");
        }
        let mut rng: Xoshiro256StarStar = Seeder::from(seed).into_rng();
        self.derive_defense(max_duration_sec, &mut rng)
    }
}

fn find_constrained_defense<R: Rng>(
    constraints: &ConstraintsConfig,
    env: &Environment,
    max_attempts: usize,
    max_duration_sec: Option<Duration>,
    machine: &RandomMachineConfig,
    rng: &mut R,
) -> Result<Option<(Defense, usize)>> {
    let mut attempts = 0;
    let start_time = Instant::now();

    loop {
        attempts += 1;
        if attempts > max_attempts {
            return Ok(None);
        }
        if let Some(max_duration) = max_duration_sec
            && start_time.elapsed() >= max_duration
        {
            return Ok(None);
        }

        let client = vec![machine.get_random_machine(true, rng)];
        let server = vec![machine.get_random_machine(false, rng)];

        match constraints.check(&client, &server, env, rng.next_u64()) {
            Ok(_) => {
                return Ok(Some((Defense::new(client, server), attempts)));
            }
            Err(e) => {
                if log_enabled!(Level::Debug) {
                    debug!("Constraint check failed: {e}");
                }
            }
        }
    }
}
