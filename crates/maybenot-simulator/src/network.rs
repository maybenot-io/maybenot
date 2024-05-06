//! For simulating the network stack and network between client and server.

use std::{
    cmp::{max, Reverse},
    time::{Duration, Instant},
};

use log::debug;
use maybenot::{Machine, TriggerEvent};

use crate::{queue::SimQueue, RngSource, SimEvent, SimState};

/// A model of the network between the client and server.
#[derive(Debug, Clone)]
pub struct Network {
    pub delay: Duration,
}

impl Network {
    pub fn new(delay: Duration) -> Self {
        Self { delay }
    }

    pub fn sample(&self) -> Duration {
        // NOTE: if ever randomized, need to use the configured RngSource
        self.delay
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
    recipient: &SimState<M, RngSource>,
    network: &Network,
    current_time: &Instant,
) -> bool {
    let side = if next.client { "client" } else { "server" }.to_string();

    match next.event {
        // here we simulate sending the packet into the tunnel
        TriggerEvent::NormalSent => {
            debug!("\tqueue {}", TriggerEvent::TunnelSent);
            sq.push_sim(
                SimEvent {
                    event: TriggerEvent::TunnelSent,
                    time: next.time,
                    delay: next.delay,
                    client: next.client,
                    contains_padding: false,
                    bypass: next.bypass,
                    replace: next.replace,
                    fuzz: next.fuzz,
                },
                Reverse(next.time),
            );
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
                let peek = sq.peek_blocking(state.blocking_bypassable, next.client);
                if let Some((queued, _)) = peek {
                    let queued = queued.clone();
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
                        sq.remove(&queued);
                        sq.push_sim(tmp.clone(), Reverse(tmp.time));
                        return false;
                    }
                }
            }
            // nothing to replace with (or we're not replacing), so queue up
            debug!("\tqueue {}", TriggerEvent::TunnelSent);
            sq.push_sim(
                SimEvent {
                    event: TriggerEvent::TunnelSent,
                    time: next.time,
                    delay: next.delay,
                    client: next.client,
                    contains_padding: true,
                    bypass: next.bypass,
                    replace: next.replace,
                    fuzz: next.fuzz,
                },
                Reverse(next.time),
            );
            false
        }
        TriggerEvent::TunnelSent => {
            debug!("\tqueue {}", TriggerEvent::TunnelRecv);
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
                let reporting_delay = recipient.reporting_delay();
                let reported = max(
                    next.time - next.delay + network.sample() + reporting_delay,
                    *current_time,
                );
                sq.push(
                    TriggerEvent::TunnelRecv,
                    !next.client,
                    false,
                    reported,
                    reporting_delay,
                    Reverse(reported),
                );

                return true;
            }

            // padding, less complicated
            debug!("\tqueue {}", TriggerEvent::TunnelRecv);
            let reporting_delay = recipient.reporting_delay();
            // action delay + network + recipient reporting delay
            let reported = next.time + next.delay + network.sample() + reporting_delay;
            sq.push(
                TriggerEvent::TunnelRecv,
                !next.client,
                true,
                reported,
                reporting_delay,
                Reverse(reported),
            );

            true
        }
        TriggerEvent::TunnelRecv => {
            // spawn NormalRecv or PaddingRecv
            if next.contains_padding {
                debug!("\tqueue {}", TriggerEvent::PaddingRecv);
                sq.push(
                    TriggerEvent::PaddingRecv,
                    next.client,
                    true,
                    next.time,
                    next.delay,
                    Reverse(next.time),
                );
            } else {
                debug!("\tqueue {}", TriggerEvent::NormalRecv);
                sq.push(
                    TriggerEvent::NormalRecv,
                    next.client,
                    false,
                    next.time,
                    next.delay,
                    Reverse(next.time),
                );
            }
            true
        }
        // all other events are not network activity
        _ => false,
    }
}
