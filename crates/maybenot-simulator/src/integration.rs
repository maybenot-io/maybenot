use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error::Error, time::Duration};

#[derive(Serialize, Deserialize, Debug)]
struct Bin {
    range: (f64, f64),
    probability: f64,
}

/// Represents a Maybenot integration and its associated delays. This can happen
/// in the case of Maybenot being integrated, e.g., in user space with a
/// protocol running in kernel space.
#[derive(Clone, Debug)]
pub struct Integration {
    /// The *action* delay is the time between the integration taking action and
    /// the action happening. For example, if a padding packet is to be sent,
    /// user space might need to signal to kernel space to craft one. NOTE: we
    /// assume that the PaddingSent event is triggered directly as padding is
    /// sent from Maybenot, while we assume that the BlockingBegin event is
    /// triggered when the blocking actually begins in the protocol and the
    /// event is transported with a reporting delay.
    pub action_delay: BinDist,
    /// The *reporting* delay is the time between an event being created by the
    /// integrated protocol and the event being reported (trigger_events) to
    /// Maybenot. For example, this could be the time it takes to go from kernel
    /// space to user space.
    pub reporting_delay: BinDist,
    /// The *trigger* delay is the time it takes for the integration to perform
    /// a scheduled action. For example, suppose an action is scheduled for time
    /// T. In that case, the trigger delay is added to T. This is important for
    /// capturing async integrations, where a zero timeout on an action to send
    /// padding would still take some (tiny) time to execute.
    pub trigger_delay: BinDist,
}

impl Integration {
    pub fn action_delay(&self) -> Duration {
        // TODO: needs to use the configured RngSource if we want to support
        // deterministic testing of integration delays
        self.action_delay.sample(&mut rand::thread_rng())
    }

    pub fn reporting_delay(&self) -> Duration {
        // TODO: needs to use the configured RngSource if we want to support
        // deterministic testing of integration delays
        self.reporting_delay.sample(&mut rand::thread_rng())
    }

    pub fn trigger_delay(&self) -> Duration {
        // TODO: needs to use the configured RngSource if we want to support
        // deterministic testing of integration delays
        self.trigger_delay.sample(&mut rand::thread_rng())
    }
}

/// A distribution of values in bins with a probability for each bin. Used to
/// estimate delay distributions in a Maybenot integration.
#[derive(Clone, Debug)]
pub struct BinDist {
    bins: Vec<(f64, f64)>,              // Vec of (min, max) tuples for each bin
    cumulative_probabilities: Vec<f64>, // Cumulative probabilities for efficient sampling
}

impl BinDist {
    pub fn new(json_input: &str) -> Result<Self, Box<dyn Error>> {
        let bins: HashMap<String, f64> = serde_json::from_str(json_input)?;

        let mut sorted_bins: Vec<_> = bins
            .into_iter()
            .map(|(range, prob)| {
                // Manually parsing the range tuple
                let range_values: Vec<f64> = range
                    .trim_matches(|c: char| c == '(' || c == ')')
                    .split(',')
                    .map(str::trim)
                    .map(str::parse)
                    .collect::<Result<Vec<f64>, _>>()?;

                if range_values.len() != 2 {
                    return Err("Range must have exactly two values".into());
                }

                Ok(((range_values[0], range_values[1]), prob))
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

        // Sort bins by range start for cumulative probability calculation
        sorted_bins.sort_by(|a, b| a.0 .0.partial_cmp(&b.0 .0).unwrap());

        let mut cumulative_probabilities = Vec::with_capacity(sorted_bins.len());
        let mut total_prob = 0.0;
        let mut ranges = Vec::with_capacity(sorted_bins.len());

        for (range, prob) in sorted_bins {
            total_prob += prob;
            cumulative_probabilities.push(total_prob);
            ranges.push(range);
        }

        Ok(BinDist {
            bins: ranges,
            cumulative_probabilities,
        })
    }

    pub fn sample<R: RngCore>(&self, rng: &mut R) -> Duration {
        let sample_prob = rng.gen::<f64>();
        let bin_index = match self
            .cumulative_probabilities
            .binary_search_by(|prob| prob.partial_cmp(&sample_prob).unwrap())
        {
            Ok(index) => index,
            Err(index) => index,
        };

        let (min, max) = self.bins[bin_index];
        // bins are in milliseconds, to get microseconds we multiply by 1000
        if min == max {
            return Duration::from_micros((min * 1000.0) as u64);
        }
        Duration::from_micros((rng.gen_range(min..max) * 1000.0) as u64)
    }
}
