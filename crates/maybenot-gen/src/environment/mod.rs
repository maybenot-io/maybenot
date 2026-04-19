pub mod traces;
use anyhow::{Result, bail};
use maybenot::TriggerEvent;
use std::{fmt, ops::RangeInclusive, time::Duration};
use traces::load_traces;

use maybenot_simulator::{
    DecoyLimitConfig, DelayLimitConfig, SimulatorArgs,
    integration::{BinDist, Integration},
    network::Network,
    queue::SimQueue,
    sim_advanced,
};
use rand::{Rng, RngExt};
use serde::{Deserialize, Serialize};

use crate::rng_range;

/// Configurable decoy limit range for sampling in an instance of the framework.
#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DecoyLimitRange {
    Frac {
        frac: RangeInclusive<f64>,
    },
    FracWindowed {
        frac: RangeInclusive<f64>,
        window_ms: RangeInclusive<u64>,
        min_normal: RangeInclusive<u64>,
    },
}

impl DecoyLimitRange {
    pub fn sample<R: Rng>(&self, rng: &mut R) -> DecoyLimitConfig {
        match self {
            DecoyLimitRange::Frac { frac } => DecoyLimitConfig::Frac {
                frac: rng_range!(rng, frac).clamp(0.0, 1.0),
            },
            DecoyLimitRange::FracWindowed {
                frac,
                window_ms,
                min_normal,
            } => DecoyLimitConfig::FracWindowed {
                frac: rng_range!(rng, frac).clamp(0.0, 1.0),
                window_ms: rng_range!(rng, window_ms),
                min_normal: rng_range!(rng, min_normal),
            },
        }
    }
}

/// Configurable delay limit range for sampling in an instance of the framework.
#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DelayLimitRange {
    Frac {
        frac: RangeInclusive<f64>,
        window_ms: RangeInclusive<u64>,
        max_packets: RangeInclusive<usize>,
    },
}

impl DelayLimitRange {
    pub fn sample<R: Rng>(&self, rng: &mut R) -> DelayLimitConfig {
        match self {
            DelayLimitRange::Frac {
                frac,
                window_ms,
                max_packets,
            } => DelayLimitConfig::Frac {
                frac: rng_range!(rng, frac).clamp(0.0, 1.0),
                window_ms: rng_range!(rng, window_ms),
                max_packets: rng_range!(rng, max_packets),
            },
        }
    }
}

/// Network traces for the basis of the environment that we evaluate defenses
/// within.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub enum Traces {
    /// From the BigEnough dataset by Mathews et al., "SoK: A Critical
    /// Evaluation of Efficient Website Fingerprinting Defenses", S&P 2023.
    BigEnough,
    /// From Syverson et al. "Onion-Location Measurements and Fingerprinting",
    /// PETS 2025.
    TorCircuit,
    /// From the Deep Fingerprinting dataset by Sirinam et al., "Deep
    /// Fingerprinting: Undermining Website Fingerprinting Defenses with Deep
    /// Learning", CCS 2018.
    DeepFingerprinting,
    /// From the undefended Gong-Surakav dataset by Gong et al., "Surakav:
    /// Generating Realistic Traces for a Strong Website Fingerprinting
    /// Defense", IEEE S&P 2022.
    GongSurakav,
    /// Load custom traces from a directory with specific size constraints.
    Custom {
        root: String,
        min_bytes: u64,
        max_bytes: u64,
    },
}

/// Integrations relate to the Maybenot simulator and simulating integration
/// delays between the Maybenot framework and an encrypted transport. For
/// example, one might have Maybenot in user space and the encrypted transport
/// WireGuard in the kernel. There is then delays between the two.
#[derive(Debug, Deserialize, Clone, Serialize)]
pub enum IntegrationType {
    Example,
    File { src: String },
}

/// Configuration for simulation environment setup.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnvironmentConfig {
    /// The base undefended traces.
    pub traces: Vec<Traces>,
    /// The number of traces to load.
    pub num_traces: RangeInclusive<usize>,
    /// The number of simulation steps to run.
    pub sim_steps: RangeInclusive<usize>,
    /// The integration type to use.
    pub integration: Option<IntegrationType>,
    /// Configuration for the network used in the simulation environment.
    pub network: NetworkConfig,
    /// Optional framework-wide decoy limit for the client.
    pub client_decoy_limit: Option<DecoyLimitRange>,
    /// Optional framework-wide delay limit for the client.
    pub client_delay_limit: Option<DelayLimitRange>,
    /// Optional framework-wide decoy limit for the server.
    pub server_decoy_limit: Option<DecoyLimitRange>,
    /// Optional framework-wide delay limit for the server.
    pub server_delay_limit: Option<DelayLimitRange>,
}

/// Configuration for the network used in the simulation environment.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    /// Round-trip time in milliseconds.
    pub rtt_in_ms: RangeInclusive<usize>,
    /// Packets per second bottleneck between client and server.
    pub packets_per_sec: Option<RangeInclusive<usize>>,
}

/// An instance of an environment represents the concrete conditions a single
/// client-server pair is operating under. Under these conditions, we later
/// search for defenses that fulfill constraints.
#[derive(Debug, Clone)]
pub struct Environment {
    /// describes the selected traces
    pub description: String,
    /// the network
    pub network: Network,
    /// the parsed traces, prepared for simulation
    pub traces: Vec<SimQueue>,
    /// the durations of each packet in each trace, for calculating constraints
    pub trace_durations: Vec<Vec<Duration>>,
    /// the integration type to use
    pub integration_type: Option<IntegrationType>,
    /// the simulator arguments
    pub sim_args: SimulatorArgs,
}

impl Environment {
    pub fn new<R: Rng>(cfg: &EnvironmentConfig, rng: &mut R) -> Result<Self> {
        let (client_integration, server_integration) = match cfg.integration {
            Some(IntegrationType::Example) => (get_example_client(), get_example_server()),
            Some(IntegrationType::File { ref src }) => {
                let (c, s) = integration_from_file(src)?;
                (Some(c), Some(s))
            }
            None => (None, None),
        };

        let network = Network::new(
            Duration::from_millis((rng_range!(rng, cfg.network.rtt_in_ms) / 2) as u64),
            cfg.network
                .packets_per_sec
                .as_ref()
                .map(|pps| rng_range!(rng, pps)),
        );

        let traces = load_traces(
            &cfg.traces,
            rng_range!(rng, cfg.num_traces),
            network,
            &client_integration,
            &server_integration,
            rng,
        )?;

        // one instance of simulator arguments for this environment
        let max_sim_steps = rng_range!(rng, cfg.sim_steps);
        let mut args = SimulatorArgs::new(network, max_sim_steps, false);
        args.max_sim_iterations = max_sim_steps;
        args.client_integration = client_integration;
        args.server_integration = server_integration;

        // Compute relative durations for every sent packet for all traces,
        // once, for later use in computing constraints related to time. We get
        // the relative durations (from start) of all the packets given the
        // simulated network and integration delays. Here we use the maximum sim
        // step and no machines, so we get more or equal number of packets as
        // when machines are running with the same simulator args.
        args.insecure_rng_seed = Some(rng.next_u64());
        let trace_durations = traces
            .iter()
            .map(|trace| {
                let trace = sim_advanced(&[], &[], &mut trace.clone(), &args);
                let starting_time = trace[0].time;
                trace
                    .iter()
                    .filter(|event| matches!(event.event, TriggerEvent::PacketSent) && event.client)
                    .map(|event| event.time - starting_time)
                    .collect()
            })
            .collect();
        // fresh seed
        args.insecure_rng_seed = Some(rng.next_u64());

        // apply environment-level framework limits
        if let Some(ref r) = cfg.client_decoy_limit {
            args.decoy_limit_client = r.sample(rng);
        }
        if let Some(ref r) = cfg.client_delay_limit {
            args.delay_limit_client = r.sample(rng);
        }
        if let Some(ref r) = cfg.server_decoy_limit {
            args.decoy_limit_server = r.sample(rng);
        }
        if let Some(ref r) = cfg.server_delay_limit {
            args.delay_limit_server = r.sample(rng);
        }

        Ok(Self {
            network,
            traces,
            trace_durations,
            integration_type: cfg.integration.clone(),
            description: format!("{:?}", cfg.traces),
            sim_args: args,
        })
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.sim_args.client_integration.is_some() && self.sim_args.server_integration.is_some()
        {
            write!(
                f,
                "Environment {{{}, {}, {:?} }}",
                self.description,
                self.network,
                self.integration_type.clone().unwrap()
            )
        } else {
            write!(f, "Environment {{{}, {} }}", self.description, self.network,)
        }
    }
}

pub fn get_example_client() -> Option<Integration> {
    Some(Integration {
        action_delay: BinDist::new(GENERIC_SMALL_INTEGRATION_DELAY).unwrap(),
        reporting_delay: BinDist::new(GENERIC_SMALL_INTEGRATION_DELAY).unwrap(),
        trigger_delay: BinDist::new(GENERIC_SMALL_INTEGRATION_DELAY).unwrap(),
    })
}

pub fn get_example_server() -> Option<Integration> {
    Some(Integration {
        action_delay: BinDist::new(GENERIC_SMALL_INTEGRATION_DELAY).unwrap(),
        reporting_delay: BinDist::new(GENERIC_SMALL_INTEGRATION_DELAY).unwrap(),
        trigger_delay: BinDist::new(GENERIC_SMALL_INTEGRATION_DELAY).unwrap(),
    })
}

/// A generic small integration delay for testing purposes.
const GENERIC_SMALL_INTEGRATION_DELAY: &str = r#"
{
    "(0.0, 0.0)": 0.45,
    "(0.0, 1.0)": 0.40,
    "(1.0, 2.0)": 0.10,
    "(2.0, 3.0)": 0.05
}
"#;

pub fn integration_from_file(fname: &str) -> Result<(Integration, Integration)> {
    let contents = std::fs::read_to_string(fname)?;
    // check that it contains at least six lines
    let lines: Vec<&str> = contents.lines().collect();
    if lines.len() < 6 {
        bail!("integration file must contain at least six lines");
    }
    let client_action_delay = match BinDist::new(lines[0]) {
        Ok(dist) => dist,
        Err(e) => bail!("error parsing client action delay: {}", e),
    };
    let client_reporting_delay = match BinDist::new(lines[1]) {
        Ok(dist) => dist,
        Err(e) => bail!("error parsing client reporting delay: {}", e),
    };
    let client_trigger_delay = match BinDist::new(lines[2]) {
        Ok(dist) => dist,
        Err(e) => bail!("error parsing client trigger delay: {}", e),
    };

    let server_action_delay = match BinDist::new(lines[3]) {
        Ok(dist) => dist,
        Err(e) => bail!("error parsing server action delay: {}", e),
    };
    let server_reporting_delay = match BinDist::new(lines[4]) {
        Ok(dist) => dist,
        Err(e) => bail!("error parsing server reporting delay: {}", e),
    };
    let server_trigger_delay = match BinDist::new(lines[5]) {
        Ok(dist) => dist,
        Err(e) => bail!("error parsing server trigger delay: {}", e),
    };

    Ok((
        Integration {
            action_delay: client_action_delay,
            reporting_delay: client_reporting_delay,
            trigger_delay: client_trigger_delay,
        },
        Integration {
            action_delay: server_action_delay,
            reporting_delay: server_reporting_delay,
            trigger_delay: server_trigger_delay,
        },
    ))
}
