//! Decoy and delay limit configuration and dynamic wrappers.
//!
//! Provides the serializable [`DecoyLimitConfig`] and [`DelayLimitConfig`] enums
//! used by [`SimulatorArgs`](crate::SimulatorArgs), along with the
//! [`DynamicLimitDecoy`] and [`DynamicLimitDelay`] runtime wrappers that let the
//! simulator select a concrete limit variant at runtime.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use maybenot::{
    LimitDecoy, LimitDecoyFrac, LimitDecoyFracWindowed, LimitDecoyNone, LimitDelay, LimitDelayFrac,
    LimitDelayNone, MachineId,
};

use crate::SimTime;

/// Configuration for the decoy limit used in the simulator.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DecoyLimitConfig {
    #[default]
    None,
    Frac {
        frac: f64,
    },
    FracWindowed {
        frac: f64,
        window_ms: u64,
        min_normal: u64,
    },
}

/// Configuration for the delay limit used in the simulator.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DelayLimitConfig {
    #[default]
    None,
    Frac {
        frac: f64,
        window_ms: u64,
        max_packets: usize,
    },
}

/// Dynamic wrapper over the supported decoy-limit variants so the simulator can
/// select one at runtime.
#[derive(Debug, Clone)]
pub enum DynamicLimitDecoy {
    None(LimitDecoyNone),
    Frac(LimitDecoyFrac),
    FracWindowed(LimitDecoyFracWindowed<SimTime>),
}

impl Default for DynamicLimitDecoy {
    fn default() -> Self {
        DynamicLimitDecoy::None(LimitDecoyNone)
    }
}

impl LimitDecoy<SimTime> for DynamicLimitDecoy {
    fn allow_decoy(&self, current_time: SimTime, machine: MachineId) -> bool {
        match self {
            DynamicLimitDecoy::None(t) => t.allow_decoy(current_time, machine),
            DynamicLimitDecoy::Frac(t) => t.allow_decoy(current_time, machine),
            DynamicLimitDecoy::FracWindowed(t) => t.allow_decoy(current_time, machine),
        }
    }

    fn max_decoys(&self, current_time: SimTime, machine: MachineId) -> usize {
        match self {
            DynamicLimitDecoy::None(t) => t.max_decoys(current_time, machine),
            DynamicLimitDecoy::Frac(t) => t.max_decoys(current_time, machine),
            DynamicLimitDecoy::FracWindowed(t) => t.max_decoys(current_time, machine),
        }
    }

    fn packet_sent(&mut self, current_time: SimTime) {
        match self {
            DynamicLimitDecoy::None(t) => t.packet_sent(current_time),
            DynamicLimitDecoy::Frac(t) => t.packet_sent(current_time),
            DynamicLimitDecoy::FracWindowed(t) => t.packet_sent(current_time),
        }
    }

    fn normal_queued(&mut self, current_time: SimTime) {
        match self {
            DynamicLimitDecoy::None(t) => t.normal_queued(current_time),
            DynamicLimitDecoy::Frac(t) => t.normal_queued(current_time),
            DynamicLimitDecoy::FracWindowed(t) => t.normal_queued(current_time),
        }
    }

    fn decoy_queued(&mut self, current_time: SimTime, machine: MachineId) {
        match self {
            DynamicLimitDecoy::None(t) => t.decoy_queued(current_time, machine),
            DynamicLimitDecoy::Frac(t) => t.decoy_queued(current_time, machine),
            DynamicLimitDecoy::FracWindowed(t) => t.decoy_queued(current_time, machine),
        }
    }

    fn congestion(&mut self, current_time: SimTime) {
        match self {
            DynamicLimitDecoy::None(t) => t.congestion(current_time),
            DynamicLimitDecoy::Frac(t) => t.congestion(current_time),
            DynamicLimitDecoy::FracWindowed(t) => t.congestion(current_time),
        }
    }
}

/// Dynamic wrapper over the supported delay-limit variants.
#[derive(Debug, Clone)]
pub enum DynamicLimitDelay {
    None(LimitDelayNone),
    Frac(LimitDelayFrac<SimTime>),
}

impl Default for DynamicLimitDelay {
    fn default() -> Self {
        DynamicLimitDelay::None(LimitDelayNone)
    }
}

impl LimitDelay<SimTime> for DynamicLimitDelay {
    fn allow_delay(&self, current_time: SimTime, machine: MachineId) -> bool {
        match self {
            DynamicLimitDelay::None(t) => t.allow_delay(current_time, machine),
            DynamicLimitDelay::Frac(t) => t.allow_delay(current_time, machine),
        }
    }

    fn max_delayed_packets(&self, current_time: SimTime, machine: MachineId) -> usize {
        match self {
            DynamicLimitDelay::None(t) => t.max_delayed_packets(current_time, machine),
            DynamicLimitDelay::Frac(t) => t.max_delayed_packets(current_time, machine),
        }
    }

    fn max_delayed_duration(&self, current_time: SimTime, machine: MachineId) -> Duration {
        match self {
            DynamicLimitDelay::None(t) => t.max_delayed_duration(current_time, machine),
            DynamicLimitDelay::Frac(t) => t.max_delayed_duration(current_time, machine),
        }
    }

    fn delay_begin(&mut self, current_time: SimTime) {
        match self {
            DynamicLimitDelay::None(t) => t.delay_begin(current_time),
            DynamicLimitDelay::Frac(t) => t.delay_begin(current_time),
        }
    }

    fn delay_end(&mut self, current_time: SimTime) {
        match self {
            DynamicLimitDelay::None(t) => t.delay_end(current_time),
            DynamicLimitDelay::Frac(t) => t.delay_end(current_time),
        }
    }
}

impl DecoyLimitConfig {
    /// Build a `DynamicLimitDecoy` from this configuration.
    pub fn build(&self) -> DynamicLimitDecoy {
        match *self {
            DecoyLimitConfig::None => DynamicLimitDecoy::None(LimitDecoyNone),
            // map 0.0 → None to preserve v2 semantics (0.0 meant "no limit")
            DecoyLimitConfig::Frac { frac: 0.0 } => DynamicLimitDecoy::None(LimitDecoyNone),
            DecoyLimitConfig::Frac { frac } => {
                DynamicLimitDecoy::Frac(LimitDecoyFrac::new(frac).unwrap())
            }
            DecoyLimitConfig::FracWindowed { frac: 0.0, .. } => {
                DynamicLimitDecoy::None(LimitDecoyNone)
            }
            DecoyLimitConfig::FracWindowed {
                frac,
                window_ms,
                min_normal,
            } => DynamicLimitDecoy::FracWindowed(
                LimitDecoyFracWindowed::new(frac, Duration::from_millis(window_ms), min_normal)
                    .unwrap(),
            ),
        }
    }
}

impl DelayLimitConfig {
    /// Build a `DynamicLimitDelay` from this configuration.
    pub fn build(&self) -> DynamicLimitDelay {
        match *self {
            DelayLimitConfig::None => DynamicLimitDelay::None(LimitDelayNone),
            DelayLimitConfig::Frac { frac: 0.0, .. } => DynamicLimitDelay::None(LimitDelayNone),
            DelayLimitConfig::Frac {
                frac,
                window_ms,
                max_packets,
            } => DynamicLimitDelay::Frac(
                LimitDelayFrac::new(frac, Duration::from_millis(window_ms), max_packets).unwrap(),
            ),
        }
    }
}
