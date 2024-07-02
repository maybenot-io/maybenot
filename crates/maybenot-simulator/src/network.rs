//! For simulating the network stack and network between client and server.

use std::{
    cmp::max, collections::VecDeque, fmt, time::{Duration, Instant}
};

use log::debug;
use maybenot::{Machine, TriggerEvent};

use crate::{queue::SimQueue, RngSource, SimEvent, SimState};

/// A model of the network between the client and server.
#[derive(Debug, Clone)]
pub struct Network {
    // The delay between the client and server.
    pub delay: Duration,
    // The maximum number of packets/cells (depends on trace) per second before
    // adding delay due to a simulated bottleneck. None means no limit.
    pub pps: Option<usize>,
}

impl Network {
    pub fn new(delay: Duration, packets_per_second: Option<usize>) -> Self {
        Self {
            delay,
            pps: packets_per_second,
        }
    }

    pub fn sample(&self) -> Duration {
        // NOTE: if ever randomized, need to use the configured RngSource
        self.delay
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pps {
            Some(pps) => write!(f, "Network {{ delay {:?}, bottleneck {:?}pps }}", self.delay, pps),
            None => write!(f, "Network {{ delay {:?}, ∞ pps }}", self.delay),
        }
    }
}

/// a network bottleneck that adds delay to packets above a certain packets per
/// window limit (default 1s window, so pps)
#[derive(Debug, Clone)]
pub struct NetworkBottleneck {
    // aggregate of delays to add to base packets due to the bottleneck: used to
    // shift the baseline trace time at both client and relay
    pub aggregate_base_delay: Duration,
    // the network model
    network: Network,
    // window counts for the client and server
    client_window: WindowCount,
    server_window: WindowCount,
    // delay added to packets above the limit
    added_delay: Duration,
    // packets per second limit
    pps: usize,
}

impl NetworkBottleneck {
    pub fn new(network: Network, window: Duration) -> Self {
        let pps = network.pps.unwrap_or(usize::MAX);
        // average delay, based on window and limit
        let added_delay = window / pps as u32;

        Self {
            network,
            client_window: WindowCount::new(window),
            server_window: WindowCount::new(window),
            added_delay,
            aggregate_base_delay: Duration::default(),
            pps,
        }
    }

    pub fn sample(
        &mut self,
        current_time: &Instant,
        is_client: bool,
    ) -> (Duration, Option<Duration>) {
        let window = if is_client {
            &mut self.client_window
        } else {
            &mut self.server_window
        };

        let count = window.add(current_time);
        let delay = if count > self.pps {
            self.added_delay * (count - self.pps) as u32
        } else {
            Duration::default()
        };
        if delay > Duration::default() {
            (delay + self.network.sample(), Some(delay))
        } else {
            (self.network.sample(), None)
        }
    }
}

#[derive(Debug, Clone)]
struct WindowCount {
    window: Duration,
    timestamps: VecDeque<Instant>,
}

impl WindowCount {
    pub fn new(window: Duration) -> Self {
        WindowCount {
            window,
            timestamps: VecDeque::with_capacity(512),
        }
    }

    pub fn add(&mut self, current_time: &Instant) -> usize {
        // add the current time of the event
        self.timestamps.push_back(*current_time);

        // prune old timestamps
        while let Some(&oldest) = self.timestamps.front() {
            if current_time.duration_since(oldest) > self.window {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }

        // return the number of events in the window
        self.timestamps.len()
    }
}

/// The network replace window is the time window in which we can replace
/// padding with existing padding or normal packets already queued (or about to
/// be queued up). The behavior here is tricky, since it'll differ how different
/// implementations handle it.
const NETWORK_REPLACE_WINDOW: Duration = Duration::from_micros(1);

// This is the only place where the simulator simulates the entire network
// between the client and the server.
//
// Queued normal or padding packets create the corresponding sent packet events.
// Here, we could simulate the egress queue of the network stack. We assume that
// it is always possible to turn a queued packet into a sent packet, but that
// sending a packet can be blocked (dealt with by the simulation of blocking in
// the main loop of the simulator).
//
// For sending a normal packet, we queue the corresponding recv event on the
// other side, simulating the network up until the point where the packet is
// received. We current do not have a receiver-side queue. TODO?
//
// For sending padding, in principle we treat it like a normal packet, but we
// need to consider the replace flag.
//
// Returns true if there was network activity (i.e., a packet was sent or
// received), false otherwise.
pub(crate) fn sim_network_stack<M: AsRef<[Machine]>>(
    next: &SimEvent,
    sq: &mut SimQueue,
    state: &SimState<M, RngSource>,
    recipient: &mut SimState<M, RngSource>,
    network: &mut NetworkBottleneck,
    current_time: &Instant,
) -> bool {
    let side = if next.client { "client" } else { "server" };

    match next.event {
        // here we simulate sending the packet into the tunnel
        TriggerEvent::NormalSent => {
            debug!("\tqueue {:#?}", TriggerEvent::TunnelSent);
            sq.push_sim(SimEvent {
                event: TriggerEvent::TunnelSent,
                time: next.time,
                integration_delay: next.integration_delay,
                client: next.client,
                contains_padding: false,
                bypass: next.bypass,
                replace: next.replace,
                base_delay: None,
            });
            false
        }
        // here we simulate sending the packet into the tunnel
        TriggerEvent::PaddingSent { .. } => {
            if next.replace {
                // replace flag is set:
                // - if we just sent a packet, we can skip sending the padding
                // - if we have a normal packet queued up to be sent within the
                //   network replace window, we can replace the padding with that

                // check if we can replace with last sent up to the network
                // replace window: this probably poorly simulates an egress
                // queue where it takes up to 1us to send the packet
                debug!(
                    "\treplace with earlier? {:?} <= {:?}",
                    next.time.duration_since(state.last_sent_time),
                    NETWORK_REPLACE_WINDOW
                );
                if next.time.duration_since(state.last_sent_time) <= NETWORK_REPLACE_WINDOW {
                    debug!("replacing normal sent with last sent @{}", side);
                    return false;
                }

                // can replace with normal that's queued to be sent within the
                // network replace window? FIXME: here be bugs related to
                // integration delays.
                if let (Some(queued), qid) =
                    sq.peek_blocking(state.blocking_bypassable, next.client)
                {
                    debug!(
                        "\treplace with queued? {:?} <= {:?}",
                        queued.time.duration_since(next.time),
                        NETWORK_REPLACE_WINDOW
                    );
                    if queued.client == next.client
                        && queued.time.duration_since(next.time) <= NETWORK_REPLACE_WINDOW
                        && TriggerEvent::TunnelSent == queued.event
                        && !queued.contains_padding
                    {
                        debug!("replacing padding sent with normal sent @{}", side,);
                        // let the NormalSent event bypass
                        // blocking by making a copy of the event
                        // with the appropriate flags set
                        let mut tmp = queued.clone();
                        tmp.bypass = true;
                        tmp.replace = false;
                        // we send the NormalSent now since it is queued
                        tmp.time = next.time;

                        // we need to remove and push, because we
                        // change flags and potentially time, which
                        // changes the priority
                        sq.pop_blocking(
                            qid,
                            state.blocking_bypassable,
                            next.client,
                            network.aggregate_base_delay,
                        );
                        sq.push_sim(tmp);
                        return false;
                    }
                }
            }
            // nothing to replace with (or we're not replacing), so queue up
            debug!("\tqueue {:#?}", TriggerEvent::TunnelSent);
            sq.push_sim(SimEvent {
                event: TriggerEvent::TunnelSent,
                time: next.time,
                integration_delay: next.integration_delay,
                client: next.client,
                contains_padding: true,
                bypass: next.bypass,
                replace: next.replace,
                base_delay: None,
            });
            false
        }
        TriggerEvent::TunnelSent => {
            debug!("\tqueue {:#?}", TriggerEvent::TunnelRecv);
            let reporting_delay = recipient.reporting_delay();
            let (network_delay, mut baseline_delay) = network.sample(current_time, next.client);

            // blocked TunnelSent may have a base delay to propagate
            match (next.base_delay, baseline_delay) {
                (Some(baseline), Some(delay)) => {
                    baseline_delay = Some(baseline + delay);
                }
                (Some(baseline), None) => {
                    baseline_delay = Some(baseline);
                }
                _ => {}
            }

            if !next.contains_padding {
                // The time the event was reported to us is in next.time. We have to
                // remove the reporting delay locally, then add a network delay and
                // a reporting delay (at the recipient) for the recipient.
                //
                // LIMITATION, we also have to deal with an ugly edge-case: if the
                // reporting delay is very long *at the sender*, then the event can
                // actually arrive earlier at the recipient than it was reported to
                // the sender. This we cannot deal with in the current design of the
                // simulator (support for integration delays was bolted on late),
                // because it would move time backwards. Therefore, we clamp.

                let reported = max(
                    next.time - next.integration_delay + network_delay + reporting_delay,
                    *current_time,
                );
                sq.push_sim(SimEvent {
                    event: TriggerEvent::TunnelRecv,
                    time: reported,
                    integration_delay: reporting_delay,
                    client: !next.client,
                    contains_padding: false,
                    bypass: false,
                    replace: false,
                    base_delay: baseline_delay,
                });
                return true;
            }

            // padding, less complicated
            debug!("\tqueue {:#?}", TriggerEvent::TunnelRecv);
            // action delay + network + recipient reporting delay
            let reported = next.time + next.integration_delay + network_delay + reporting_delay;
            sq.push_sim(SimEvent {
                event: TriggerEvent::TunnelRecv,
                time: reported,
                integration_delay: reporting_delay,
                client: !next.client,
                contains_padding: true,
                bypass: false,
                replace: false,
                // NOTE: padding does not contribute to delaying the base trace
                // (beyond filling the bottleneck window)
                base_delay: None,
            });

            true
        }
        TriggerEvent::TunnelRecv => {
            if let Some(bottleneck) = next.base_delay {
                // NOTE: we add the delay to the sum of delays, but this is
                // overly conservative (for client->server direction), because
                // it is first once application data arrives (later than in the
                // base trace) at the destination that the delay impact
                // application data. So, this design excessively punishes client
                // blocking.
                network.aggregate_base_delay += bottleneck;
            }

            // spawn NormalRecv or PaddingRecv
            if next.contains_padding {
                debug!("\tqueue {:#?}", TriggerEvent::PaddingRecv);
                sq.push(
                    TriggerEvent::PaddingRecv,
                    next.client,
                    true,
                    next.time,
                    next.integration_delay,
                );
            } else {
                debug!("\tqueue {:#?}", TriggerEvent::NormalRecv);
                sq.push(
                    TriggerEvent::NormalRecv,
                    next.client,
                    false,
                    next.time,
                    next.integration_delay,
                );
            }
            true
        }
        // all other events are not network activity
        _ => false,
    }
}
