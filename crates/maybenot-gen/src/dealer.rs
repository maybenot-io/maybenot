use std::ops::RangeInclusive;

use anyhow::{Result, bail};
use maybenot::Machine;
use maybenot_simulator::{DecoyLimitConfig, DelayLimitConfig};
use rand::{
    Rng, RngExt,
    seq::{IndexedMutRandom, SliceRandom},
};
use serde::{Deserialize, Serialize};

use crate::{
    defense::Defense,
    environment::{DecoyLimitRange, DelayLimitRange},
    rng_range,
};

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Setup {
    pub client: Params,
    pub server: Params,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Params {
    pub machines: Vec<Machine>,
    pub decoy_limit: DecoyLimitConfig,
    pub delay_limit: DelayLimitConfig,
}

/// A "dealer" "draws" a "setup" for the client and the server. Each party gets
/// a list of machines, and maximum fractions of decoy and delay for their
/// instance of Maybenot. The scale parameter is used to scale the decoy and
/// delay budgets for the client and server, between (0.0, 1.0]. This is
/// useful for creating defense-overhead trade-offs.
pub trait Dealer {
    /// draw a setup for the client and server
    fn draw<R: Rng>(&mut self, scale: f64, rng: &mut R) -> Result<Setup>;
    /// draw n setups for the client and server
    fn draw_n<R: Rng>(&mut self, n: usize, scale: f64, rng: &mut R) -> Result<Vec<Setup>>;
    /// the number of defenses left in the dealer
    fn len(&self) -> usize;
    /// whether the dealer is empty
    fn is_empty(&self) -> bool;
}

/// Limits for the client and server setups. Each is used only if set. The
/// ranges are sampled from.
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Limits {
    /// absolute number of decoy packets before other limits apply, split over
    /// all machines in the defense
    pub decoy_budget: Option<RangeInclusive<f64>>,
    /// absolute time in microseconds of delay before other limits apply,
    /// split over all machines in the defense
    pub delay_budget: Option<RangeInclusive<f64>>,
    /// framework-wide decoy limit configuration range
    pub decoy_limit: Option<DecoyLimitRange>,
    /// framework-wide delay limit configuration range
    pub delay_limit: Option<DelayLimitRange>,
}
/// A dealer based on a fixed list of defenses. The defenses are either drawn
/// with replacement (reused) or not. Setup fractions are sampled from the
/// optionally provided limits.
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct DealerFixed {
    defenses: Vec<Defense>,
    client_limits: Option<Limits>,
    server_limits: Option<Limits>,
    reuse: bool,
}

impl DealerFixed {
    pub fn new<R: Rng>(
        mut defenses: Vec<Defense>,
        client_limits: Option<Limits>,
        server_limits: Option<Limits>,
        reuse: bool,
        rng: &mut R,
    ) -> Result<Self> {
        if defenses.is_empty() {
            bail!("no defenses provided");
        }
        if !reuse {
            defenses.shuffle(rng);
        }
        Ok(Self {
            defenses,
            client_limits,
            server_limits,
            reuse,
        })
    }
}

impl Dealer for DealerFixed {
    fn draw<R: Rng>(&mut self, scale: f64, rng: &mut R) -> Result<Setup> {
        if !(0.0..=1.0).contains(&scale) {
            bail!("invalid scale");
        }
        if self.defenses.is_empty() {
            bail!("no defenses left");
        }

        let mut def = if self.reuse {
            self.defenses.choose_mut(rng).unwrap().clone()
        } else {
            self.defenses.pop().unwrap()
        };

        // sample and scale client and server machine absolute limits
        if let Some(limits) = &self.client_limits {
            set_machine_limits(&mut def.client, limits, scale, rng);
        }
        if let Some(limits) = &self.server_limits {
            set_machine_limits(&mut def.server, limits, scale, rng);
        }

        // return the setup, sampling decoy and delay limit configs for the
        // client and server framework instances if limits are set
        Ok(Setup {
            client: Params {
                machines: def.client,
                decoy_limit: self
                    .client_limits
                    .as_ref()
                    .and_then(|l| l.decoy_limit.as_ref())
                    .map_or(DecoyLimitConfig::None, |r| r.sample(rng)),
                delay_limit: self
                    .client_limits
                    .as_ref()
                    .and_then(|l| l.delay_limit.as_ref())
                    .map_or(DelayLimitConfig::None, |r| r.sample(rng)),
            },
            server: Params {
                machines: def.server,
                decoy_limit: self
                    .server_limits
                    .as_ref()
                    .and_then(|l| l.decoy_limit.as_ref())
                    .map_or(DecoyLimitConfig::None, |r| r.sample(rng)),
                delay_limit: self
                    .server_limits
                    .as_ref()
                    .and_then(|l| l.delay_limit.as_ref())
                    .map_or(DelayLimitConfig::None, |r| r.sample(rng)),
            },
        })
    }

    fn draw_n<R: Rng>(&mut self, n: usize, scale: f64, rng: &mut R) -> Result<Vec<Setup>> {
        if !(0.0..=1.0).contains(&scale) {
            bail!("invalid scale");
        }
        if self.defenses.is_empty() {
            bail!("no defenses left");
        }
        if !self.reuse && n > self.defenses.len() {
            bail!("not enough defenses left");
        }

        let mut setups = Vec::with_capacity(n);
        for _ in 0..n {
            setups.push(self.draw(scale, rng).unwrap());
        }
        Ok(setups)
    }

    fn len(&self) -> usize {
        self.defenses.len()
    }

    fn is_empty(&self) -> bool {
        self.defenses.is_empty()
    }
}

fn sample_budget_scaled<R: Rng>(
    range: &Option<RangeInclusive<f64>>,
    scale: f64,
    rng: &mut R,
) -> f64 {
    range.as_ref().map_or(0.0, |r| rng_range!(rng, r) * scale)
}

fn set_machine_limits<R: Rng>(machines: &mut [Machine], limits: &Limits, scale: f64, rng: &mut R) {
    let decoy_budget = sample_budget_scaled(&limits.decoy_budget, scale, rng);
    let delay_budget = sample_budget_scaled(&limits.delay_budget, scale, rng);

    let n_machines_with_decoy_budget = machines
        .iter()
        .filter(|m| m.allowed_decoy_packets > 0)
        .count() as f64;
    let n_machines_with_delay_budget = machines
        .iter()
        .filter(|m| m.allowed_delay_microsec > 0)
        .count() as f64;

    for m in machines.iter_mut() {
        // we use framework fraction limits and disable machine-specific ones:
        // this is more chaotic with several machines, because interactions are
        // don't scale if the machine doesn't have a budget: if there's a
        // budget, split it evenly among the machines
        if m.allowed_decoy_packets > 0 && limits.decoy_budget.is_some() {
            m.allowed_decoy_packets = (decoy_budget / n_machines_with_decoy_budget) as u64;
        }
        if m.allowed_delay_microsec > 0 && limits.delay_budget.is_some() {
            m.allowed_delay_microsec = (delay_budget / n_machines_with_delay_budget) as u64;
        }
    }
}
