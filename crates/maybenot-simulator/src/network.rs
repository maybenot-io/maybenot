//! For simulating network activity: sending and receiving packets between the
//! client and server.

use std::{
    cmp::{max, Reverse},
    time::{Duration, Instant},
};

use log::debug;
use maybenot::{event::Event, framework::TriggerEvent, machine::Machine};

use crate::{queue::SimQueue, SimEvent, SimState};

/// A model of the network between the client and server. TODO: make this more
/// than just a delay.
#[derive(Debug, Clone)]
pub struct Network {
    pub delay: Duration,
}

impl Network {
    pub fn new(delay: Duration) -> Self {
        Self { delay }
    }

    pub fn sample(&self) -> Duration {
        self.delay
    }
}

/// The network replace window is the time window in which we can replace
/// padding with existing padding or non-padding already queued (or about to be
/// queued up). The behavior here is tricky, since it'll differ how different
/// implementations handle it.
const NETWORK_REPLACE_WINDOW: Duration = Duration::from_micros(1);

// For (non-)padding sent, queue the corresponding padding recv event: in other
// words, where we simulate sending packets. The block below is actually the
// only place where the simulator simulates the entire network between the
// client and the server. Returns true if a (non-)padding packet was sent or
// received (i.e., there was network activity), false otherwise.
pub fn sim_network_activity<M: AsRef<[Machine]>>(
    next: &SimEvent,
    sq: &mut SimQueue,
    state: &SimState<M>,
    recipient: &SimState<M>,
    network: &Network,
    current_time: &Instant,
) -> bool {
    let side = if next.client { "client" } else { "server" }.to_string();

    match next.event {
        // easy: queue up the recv event on the other side
        TriggerEvent::NonPaddingSent { bytes_sent } => {
            debug!("\tqueue {}", Event::NonPaddingRecv);
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
                TriggerEvent::NonPaddingRecv {
                    bytes_recv: bytes_sent,
                },
                !next.client,
                reported,
                reporting_delay,
                Reverse(reported),
            );

            true
        }
        TriggerEvent::PaddingSent { bytes_sent, .. } => {
            if next.replace {
                // This is where it gets tricky: we MAY replace the padding with
                // existing padding or non-padding already queued (or about to
                // be queued up). The behavior here is tricky, since it'll
                // differ how different implementations handle it. When
                // replacing, we allow bytes of equal or less size, without
                // adjusting/compensating for the size difference. This is to
                // allow easy constant-rate defenses accounting for
                // variable-size packets. Note that replacing is the same as
                // skipping to queue the padding recv event below.

                // check if we can replace with last sent up to the network
                // replace window: this probably poorly simulates an egress
                // queue where it takes up to 1us to send the packet
                debug!(
                    "\treplace with earlier? {:?} <= {:?}",
                    next.time.duration_since(state.last_sent_time),
                    NETWORK_REPLACE_WINDOW
                );
                if next.time.duration_since(state.last_sent_time) <= NETWORK_REPLACE_WINDOW
                    && state.last_sent_size <= bytes_sent
                {
                    debug!("replacing padding sent with last sent @{}", side);
                    return false;
                }

                // can replace with nonpadding that's queued to be sent within
                // the network replace window? FIXME: here be bugs related to
                // integration delays. Once blocking is implemented, this code
                // needs to be reworked.
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
                    {
                        if let TriggerEvent::NonPaddingSent {
                            bytes_sent: queued_bytes_sent,
                        } = queued.event
                        {
                            if queued_bytes_sent <= bytes_sent {
                                debug!("replacing padding sent with queued non-padding @{}", side,);
                                // let the NonPaddingSent event bypass
                                // blocking by making a copy of the event
                                // with the appropriate flags set
                                let mut tmp = queued.clone();
                                tmp.bypass = true;
                                tmp.replace = false;
                                // we send the NonPadding now since it is queued
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
                }
            }

            // nothing to replace with (or we're not replacing), so queue up
            debug!("\tqueue {}", Event::PaddingRecv);
            let reporting_delay = recipient.reporting_delay();
            // action delay + network + recipient reporting delay
            let reported = next.time + next.delay + network.sample() + reporting_delay;
            sq.push(
                TriggerEvent::PaddingRecv {
                    bytes_recv: bytes_sent,
                },
                !next.client,
                reported,
                reporting_delay,
                Reverse(reported),
            );

            true
        }
        // receiving (non-)padding is receiving a packet
        TriggerEvent::NonPaddingRecv { .. } | TriggerEvent::PaddingRecv { .. } => true,
        _ => false,
    }
}
