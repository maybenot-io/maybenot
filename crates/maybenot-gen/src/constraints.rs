use anyhow::Result;
use std::{ops::RangeInclusive, time::Duration};

use anyhow::bail;
use maybenot::{Machine, TriggerEvent};
use maybenot_simulator::{SimEvent, sim_advanced};
use serde::{Deserialize, Serialize};

use crate::environment::Environment;

/// Constraints on defenses in a given search space.
///
/// The constraints are expressed as overheads, i.e., load and delay, and
/// minimal observed normal packets.
///
/// The load is the percentage of additional (padding) packets, and the delay is
/// the fraction of duration delayed, both compared to the base case without a
/// defense. Additionally, the load is defined per side (client and server),
/// since padding can be asymmetric (just like common traffic to defend, e.g.,
/// web traffic). Delay is a single value, since padding and blocking on both
/// sides cause aggregate delays from propagated delays (in a realistic
/// simulator).
///
/// The minimal number of normal packets is a sanity check to ensure that the
/// defense does not complete block traffic or overwhelm the simulator with
/// padding packets or TriggerEvents (e.g., infinite BlockingBegin ->
/// BlockingBegin or BlockingBegin -> BlockingEnd loops). Random defenses,
/// especially with learning, get creative fast.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConstraintsConfig {
    /// load is (#defended packets / #undefended packets) - 1
    pub client_load: Option<RangeInclusive<f64>>,
    /// load is (#defended packets / #undefended packets) - 1
    pub server_load: Option<RangeInclusive<f64>>,
    /// Delay is (time with defense / time without defense) - 1.0. For computing
    /// the delay we find the location of the last *normal* packet in the
    /// simulated trace and compare the time it was sent with the base time for
    /// the same packet. This is needed since we may simulate a subset of the
    /// trace and only care about the delay of the normal packets.
    pub delay: Option<RangeInclusive<f64>>,
    /// Minimum number of normal packets sent by the client.
    pub client_min_normal_packets: Option<usize>,
    /// Minimum number of normal packets sent by the server.
    pub server_min_normal_packets: Option<usize>,
    /// Include all events after the last normal packet in the simulated
    /// defended trace. If false (default), all events after the last normal
    /// packet are stripped from the trace. This mimics how overheads are
    /// typically computed for defenses.
    pub include_after_last_normal: Option<bool>,
}

impl ConstraintsConfig {
    pub fn check(
        &self,
        client: &[Machine],
        server: &[Machine],
        env: &Environment,
        seed: u64,
    ) -> Result<()> {
        let mut client_stats = vec![Stats::new(); env.traces.len()];
        let mut server_stats = vec![Stats::new(); env.traces.len()];
        let mut undefended_duration = Duration::from_secs(0);
        let mut defended_duration = Duration::from_secs(0);

        let mut args = env.sim_args.clone();
        // we need client and server events, and update the seed
        args.only_client_events = false;
        args.insecure_rng_seed = Some(seed);

        // compute all stats
        for (i, pq) in env.traces.iter().enumerate() {
            let mut trace = sim_advanced(client, server, &mut pq.clone(), &args);
            // increment for next trace
            args.insecure_rng_seed = args.insecure_rng_seed.map(|s| s + 1);

            // strip all events after the last normal packet in the defended
            // trace by default
            if !self.include_after_last_normal.unwrap_or(false) {
                let last_normal = trace.iter().rev().position(|event| {
                    (matches!(event.event, TriggerEvent::TunnelSent)
                        || matches!(event.event, TriggerEvent::TunnelRecv))
                        && !event.contains_padding
                });
                if let Some(last_normal) = last_normal {
                    trace.truncate(trace.len() - last_normal);
                }
            }

            // compute stats for the trace
            count_events(&mut client_stats[i], &mut server_stats[i], &trace);

            // early, obvious checks (that may filter out a significant number
            // of machines, so we do them ASAP)
            if self.client_load.is_some()
                && client_stats[i].normal < self.client_min_normal_packets.unwrap_or(1)
            {
                bail!("too few normal client packets");
            }
            if self.server_load.is_some()
                && server_stats[i].normal < self.server_min_normal_packets.unwrap_or(1)
            {
                bail!("too few normal server packets");
            }

            // If a machine should produce some padding, check for at least 5
            // padding packets (arbitrary number) in the trace. This is to
            // ensure that the machine actually does something.
            if let Some(client_load) = &self.client_load
                && client_load.contains(&0.001)
                && client_stats[i].padding < 5
            {
                bail!("too few padding packets from client");
            }
            if let Some(server_load) = &self.server_load
                && server_load.contains(&0.001)
                && server_stats[i].padding < 5
            {
                bail!("too few padding packets from server");
            }

            // event sanity check: if we spend less than 20% of counted
            // TriggerEvents (note: no recv events) sending packets, something
            // is wrong
            if self.client_load.is_some()
                && (client_stats[i].sum_packets() as f64 / client_stats[i].len() as f64) < 0.20
            {
                bail!("too many non-packet events from client");
            }
            if self.server_load.is_some()
                && (server_stats[i].sum_packets() as f64 / server_stats[i].len() as f64) < 0.20
            {
                bail!("too many non-packet events from server");
            }

            // if we care about delay, compute the durations
            if self.delay.is_some() {
                match get_durations(&trace, &env.trace_durations[i]) {
                    (Some(defended), Some(undefended)) => {
                        if defended < undefended {
                            bail!(
                                "defended trace duration shorter than base trace, simulation error?"
                            );
                        }
                        defended_duration += defended;
                        undefended_duration += undefended;
                    }
                    _ => bail!("no normal network activity"),
                }
            }
        }

        if let Some(client_load) = &self.client_load {
            check_load(&client_stats, client_load, "client")?;
        }
        if let Some(server_load) = &self.server_load {
            check_load(&server_stats, server_load, "server")?;
        }
        if let Some(delay_range) = &self.delay {
            check_delay(undefended_duration, defended_duration, delay_range)?;
        }

        Ok(())
    }
}

fn check_delay(
    time_base: Duration,
    time_defended: Duration,
    oh: &RangeInclusive<f64>,
) -> Result<()> {
    // delay is (defended / undefended) - 1.0
    let avg_delay = (time_defended.as_secs_f64() / time_base.as_secs_f64()) - 1.0;

    if !oh.contains(&avg_delay) {
        bail!(
            "average delay {} not in expected range [{}, {}]",
            avg_delay,
            oh.start(),
            oh.end()
        );
    }
    Ok(())
}

fn check_load(stats: &[Stats], oh: &RangeInclusive<f64>, party: &str) -> Result<()> {
    // load is (defended / undefended) - 1.0
    let normal = stats.iter().map(|s| s.normal).sum::<usize>() as f64;
    let padding = stats.iter().map(|s| s.padding).sum::<usize>() as f64;
    let avg_load = (padding + normal) / normal - 1.0;

    if !oh.contains(&avg_load) {
        bail!(
            "average load from {}: got {}, expected [{}, {}]",
            party,
            avg_load,
            oh.start(),
            oh.end()
        );
    }

    Ok(())
}

#[derive(Clone)]
struct Stats {
    /// sum of padding packets sent (from TriggerEvent:TunnelSent with the
    /// padding flag)
    padding: usize,
    /// sum of normal packets sent (from TriggerEvent:TunnelSent without the
    /// padding flag)
    normal: usize,
    /// sum of blocking begin events
    blocking_begin: usize,
    /// sum of blocking end events
    blocking_end: usize,
    /// sum of timer begin events
    timer_begin: usize,
    /// sum of timer end events
    timer_end: usize,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            padding: 0,
            normal: 0,
            blocking_begin: 0,
            blocking_end: 0,
            timer_begin: 0,
            timer_end: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.padding
            + self.normal
            + self.blocking_begin
            + self.blocking_end
            + self.timer_begin
            + self.timer_end
    }

    pub fn sum_packets(&self) -> usize {
        self.padding + self.normal
    }
}

fn count_events(client: &mut Stats, server: &mut Stats, trace: &[SimEvent]) {
    // iterate over the trace and count the events for client and server
    for event in trace {
        match event.event {
            TriggerEvent::TunnelSent => {
                if event.contains_padding {
                    if event.client {
                        client.padding += 1;
                    } else {
                        server.padding += 1;
                    }
                } else if event.client {
                    client.normal += 1;
                } else {
                    server.normal += 1;
                }
            }
            TriggerEvent::BlockingBegin { .. } => {
                if event.client {
                    client.blocking_begin += 1;
                } else {
                    server.blocking_begin += 1;
                }
            }
            TriggerEvent::BlockingEnd => {
                if event.client {
                    client.blocking_end += 1;
                } else {
                    server.blocking_end += 1;
                }
            }
            TriggerEvent::TimerBegin { .. } => {
                if event.client {
                    client.timer_begin += 1;
                } else {
                    server.timer_begin += 1;
                }
            }
            TriggerEvent::TimerEnd { .. } => {
                if event.client {
                    client.timer_end += 1;
                } else {
                    server.timer_end += 1;
                }
            }
            _ => {}
        }
    }
}

// get the base and defended durations for the trace, based on the last normal
// packet in the defended trace
fn get_durations(defended: &[SimEvent], base: &[Duration]) -> (Option<Duration>, Option<Duration>) {
    let starting_time = defended[0].time;
    // the duration of the last normal sent packet in the defended trace for the client
    let defended_duration = defended.iter().rev().find_map(|event| {
        if let TriggerEvent::TunnelSent = event.event
            && !event.contains_padding
            && event.client
        {
            return Some(event.time - starting_time);
        }
        None
    });

    // the number of normal packets in the defended trace
    let defended_normal = defended
        .iter()
        .filter(|event| {
            matches!(event.event, TriggerEvent::TunnelSent)
                && !event.contains_padding
                && event.client
        })
        .count();

    // get the base duration for the same number of normal packets
    let base_duration = base.get(defended_normal - 1).cloned();

    (defended_duration, base_duration)
}
