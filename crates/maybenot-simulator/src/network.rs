//! For simulating the network stack and network between client and server.

// To use new Linktrace functionality inplace, rename NetowrkBottleneck
// and NetworkLinktraceBneck, to NetowrkBottleneckInactive and NetowrkBottleneck

use std::{
    cmp::{max, Ordering},
    collections::{BinaryHeap, VecDeque},
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use log::debug;
use maybenot::{Machine, TriggerEvent};

use crate::{
    delay::{agg_delay_on_padding_bypass_replace, should_delayed_packet_prop_agg_delay},
    linktrace::{mk_start_instant, LinkTrace},
    queue::SimQueue,
    RngSource, SimEvent, SimState,
};

/// A model of the network between the client and server.
#[derive(Debug, Clone, Copy)]
pub struct Network {
    // The delay between the client and server.
    pub delay: Duration,
    // The maximum number of packets/cells (depends on trace) per second before
    // adding delay due to a simulated bottleneck. None means trace limit.
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
            Some(pps) => write!(
                f,
                "Network {{ delay {:?}, bottleneck {:?}pps }}",
                self.delay, pps
            ),
            None => write!(f, "Network {{ delay {:?}, ∞ pps }}", self.delay),
        }
    }
}

// Labels for the Network configurartion which describes where Server, Client, Relay,
// Machines, Delay, and Bottlenecks are located in relation to each other. For future impl.
// At some later stage this could potentially be generalized to allow arbitrary
// composition of those elements.
#[allow(non_camel_case_types)]
pub enum NetworkConfiguration {
    SM_DB_MC,
    S_DB_RM_D_MC,
    S_D_RM_DB_MC,
}

// Labels for the different types of simulated networks there are,
// in terms of how the bottleneck is modeled
#[derive(Debug, Clone)]
pub enum ExtendedNetworkLabels {
    Bottleneck,
    Linktrace,
    //  LinkTraceHiRes,  // For future
    //  LinkTraceLoRes,  // For future
}

#[derive(Debug, Clone)]
pub enum ExtendedNetwork {
    Bottleneck(NetworkBottleneck),
    Linktrace(NetworkLinktrace),
}

impl ExtendedNetwork {
    pub fn new_bottleneck(network: Network, window: Duration, queue_pps: Option<usize>) -> Self {
        ExtendedNetwork::Bottleneck(NetworkBottleneck::new(network, window, queue_pps))
    }

    pub fn new_linktrace(network: Network, linktrace: Arc<LinkTrace>) -> Self {
        ExtendedNetwork::Linktrace(NetworkLinktrace::new(network, linktrace))
    }

    pub fn sample(
        &mut self,
        current_time: &Instant,
        is_client: bool,
    ) -> (Duration, Option<Duration>) {
        match self {
            ExtendedNetwork::Bottleneck(bn) => bn.sample(current_time, is_client),
            ExtendedNetwork::Linktrace(lt) => lt.sample(current_time, is_client),
        }
    }

    pub fn peek_aggregate_delay(&self, current_time: Instant) -> Duration {
        match self {
            ExtendedNetwork::Bottleneck(bn) => bn.peek_aggregate_delay(current_time),
            ExtendedNetwork::Linktrace(lt) => lt.peek_aggregate_delay(current_time),
        }
    }

    pub fn get_client_aggregate_base_delay(&self) -> Duration {
        match self {
            ExtendedNetwork::Bottleneck(bn) => bn.client_aggregate_base_delay,
            ExtendedNetwork::Linktrace(lt) => lt.client_aggregate_base_delay,
        }
    }

    pub fn get_server_aggregate_base_delay(&self) -> Duration {
        match self {
            ExtendedNetwork::Bottleneck(bn) => bn.server_aggregate_base_delay,
            ExtendedNetwork::Linktrace(lt) => lt.server_aggregate_base_delay,
        }
    }

    pub fn push_aggregate_delay(
        &mut self,
        delay: Duration,
        current_time: &Instant,
        reached_client: bool,
    ) {
        match self {
            ExtendedNetwork::Bottleneck(bn) => {
                bn.push_aggregate_delay(delay, current_time, reached_client)
            }
            ExtendedNetwork::Linktrace(lt) => {
                lt.push_aggregate_delay(delay, current_time, reached_client)
            }
        }
    }

    pub fn pop_aggregate_delay(&mut self) {
        match self {
            ExtendedNetwork::Bottleneck(bn) => bn.pop_aggregate_delay(),
            ExtendedNetwork::Linktrace(lt) => lt.pop_aggregate_delay(),
        }
    }
    pub fn get_pps_limit(&mut self) -> usize {
        match self {
            ExtendedNetwork::Bottleneck(bn) => bn.pps_limit,
            ExtendedNetwork::Linktrace(lt) => lt.pps_limit,
        }
    }
}

/// a network bottleneck that adds delay to packets above a certain packets per
/// window limit (default 1s window, so pps), and keeps track of the aggregate
/// delay to add to packets due to the bottleneck or accumulated blocking by
/// machines: used to shift the baseline trace time at both client and server
#[derive(Debug, Clone)]
pub struct NetworkBottleneck {
    // the aggregate delay for the client
    pub client_aggregate_base_delay: Duration,
    // the aggregate delay for the server
    pub server_aggregate_base_delay: Duration,
    // the pending aggregate delays to add to packets due to the bottleneck
    aggregate_delay_queue: BinaryHeap<PendingAggregateDelay>,
    // the network model
    network: Network,
    // window counts for the client and server
    client_window: WindowCount,
    server_window: WindowCount,
    // delay added to packets above the limit
    pps_added_delay: Duration,
    // packets per second limit
    pps_limit: usize,
}

impl NetworkBottleneck {
    pub fn new(network: Network, window: Duration, queue_pps: Option<usize>) -> Self {
        let pps = network.pps.unwrap_or(queue_pps.unwrap_or(usize::MAX));
        // average delay, based on window and limit
        let added_delay = window / pps as u32;

        Self {
            network,
            client_window: WindowCount::new(window),
            server_window: WindowCount::new(window),
            pps_added_delay: added_delay,
            client_aggregate_base_delay: Duration::default(),
            server_aggregate_base_delay: Duration::default(),
            aggregate_delay_queue: BinaryHeap::new(),
            pps_limit: pps,
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
        let delay = if count > self.pps_limit {
            self.pps_added_delay * (count - self.pps_limit) as u32
        } else {
            Duration::default()
        };
        if delay > Duration::default() {
            (delay + self.network.sample(), Some(delay))
        } else {
            (self.network.sample(), None)
        }
    }

    pub fn peek_aggregate_delay(&self, current_time: Instant) -> Duration {
        // for the peeked one, the duration since the current time is the
        // duration until the delay is in effect: if none is peeked, return
        // Duration::MAX
        self.aggregate_delay_queue
            .peek()
            .map(|d| d.time.duration_since(current_time))
            .unwrap_or(Duration::MAX)
    }

    pub fn push_aggregate_delay(
        &mut self,
        block_duration: Duration,
        current_time: &Instant,
        client_expiry: bool,
    ) {
        // TODO: refine the network model, for now, we sample the delay once and
        // assume it's the same delay in both directions as well as between
        // client-server and server-destination.
        let d = self.network.sample();

        // did the blocking expire at the client?
        let mut client = Duration::default();
        let mut server = Duration::default();
        match client_expiry {
            true => {
                // @client: max(4D-B, 0)
                if 4 * d > block_duration {
                    client = 4 * d - block_duration;
                };
                // @server: max(3D-B, 0)
                if 3 * d > block_duration {
                    server = 3 * d - block_duration;
                };
            }
            false => {
                // @client: max(D-B, 0)
                if d > block_duration {
                    client = d - block_duration;
                };
                // @server: max(4D-B, 0)
                if 4 * d > block_duration {
                    server = 4 * d - block_duration;
                };
            }
        };

        debug!(
            "\tpushing aggregate delay {:?} in {:?} at the client",
            block_duration, client
        );
        self.aggregate_delay_queue.push(PendingAggregateDelay {
            time: *current_time + client,
            delay: block_duration,
            client: true,
        });
        debug!(
            "\tpushing aggregate delay {:?} in {:?} at the server",
            block_duration, server
        );
        self.aggregate_delay_queue.push(PendingAggregateDelay {
            time: *current_time + server,
            delay: block_duration,
            client: false,
        });
    }

    pub fn pop_aggregate_delay(&mut self) {
        if let Some(aggregate) = self.aggregate_delay_queue.pop() {
            match aggregate.client {
                true => {
                    debug!("\tpopping aggregate delay at client {:?}", aggregate.delay);
                    self.client_aggregate_base_delay += aggregate.delay;
                }
                false => {
                    debug!("\tpopping aggregate delay at server {:?}", aggregate.delay);
                    self.server_aggregate_base_delay += aggregate.delay;
                }
            };
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingAggregateDelay {
    pub(crate) time: Instant,
    pub(crate) delay: Duration,
    pub(crate) client: bool,
}

impl Ord for PendingAggregateDelay {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.time.cmp(&other.time).reverse()
    }
}

impl PartialOrd for PendingAggregateDelay {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WindowCount {
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

/// a network that adds delay to packets according to the transmission delay
/// provided by a link trace.  Keeps track of the aggregate
/// delay to add to packets due to the bottleneck or accumulated blocking by
/// machines: used to shift the baseline trace time at both client and relay
#[derive(Debug, Clone)]
pub struct NetworkLinktrace {
    // the aggregate delay for the client
    pub client_aggregate_base_delay: Duration,
    // the aggregate delay for the server
    pub server_aggregate_base_delay: Duration,
    // the pending aggregate delays to add to packets due to the bottleneck
    aggregate_delay_queue: BinaryHeap<PendingAggregateDelay>,
    // the network model
    network: Network,
    // packets per second limit
    pps_limit: usize,
    linktrace: Arc<LinkTrace>,
    //linktrace: &'a LinkTrace,
    // The start instant used by parse_trace for the first event at the server side
    sim_trace_startinstant: Instant,
    next_busy_to: usize,
}

impl NetworkLinktrace {
    pub fn new(network: Network, linktrace: Arc<LinkTrace>) -> Self {
        Self {
            network,
            client_aggregate_base_delay: Duration::default(),
            server_aggregate_base_delay: Duration::default(),
            aggregate_delay_queue: BinaryHeap::new(),
            pps_limit: usize::MAX,
            linktrace,
            sim_trace_startinstant: mk_start_instant(),
            next_busy_to: 0,
        }
    }

    pub fn sample(
        &mut self,
        current_time: &Instant,
        _is_client: bool,
    ) -> (Duration, Option<Duration>) {
        // Need to some type conversion to make it work for busy_to matrix lookup ....
        let sim_relative_duration = current_time.duration_since(self.sim_trace_startinstant);
        let current_time_slot = sim_relative_duration.as_micros() as usize;

        let busy_to;
        let mut queueing_delay_duration = Duration::default();

        // Check if packet arrives after previous pakcet has finished, i.e after next_bust_to
        if self.next_busy_to <= current_time_slot {
            busy_to = self.linktrace.get_dl_busy_to(current_time_slot, 1500);
        // If previous packet is still being sent, get the end time for the new packet
        // based starting when the previous packet has finished, and add up the queueing delay
        } else {
            busy_to = self.linktrace.get_dl_busy_to(self.next_busy_to, 1500);
            queueing_delay_duration =
                Duration::from_micros((self.next_busy_to - current_time_slot) as u64);
        }
        // Make sure that we are not at the end of the link trace
        assert_ne!(
            busy_to, 0,
            "Packet to be scheduled outside of link trace end"
        );

        // update next_busy_to in preparation for the next packet
        self.next_busy_to = busy_to;

        let pkt_txdelay_duration = Duration::from_micros((busy_to - current_time_slot) as u64);
        if queueing_delay_duration > Duration::default() {
            (
                self.network.sample() + queueing_delay_duration,
                Some(queueing_delay_duration),
            )
        } else {
            (self.network.sample() + pkt_txdelay_duration, None)
        }
    }

    pub fn reset_linktrace(&mut self) {
        self.client_aggregate_base_delay = Duration::default();
        self.server_aggregate_base_delay = Duration::default();
        self.aggregate_delay_queue = BinaryHeap::new();
        self.sim_trace_startinstant = mk_start_instant();
        self.next_busy_to = 0
    }

    pub fn peek_aggregate_delay(&self, current_time: Instant) -> Duration {
        // for the peeked one, the duration since the current time is the
        // duration until the delay is in effect: if none is peeked, return
        // Duration::MAX
        self.aggregate_delay_queue
            .peek()
            .map(|d| d.time.duration_since(current_time))
            .unwrap_or(Duration::MAX)
    }

    pub fn push_aggregate_delay(
        &mut self,
        block_duration: Duration,
        current_time: &Instant,
        client_expiry: bool,
    ) {
        // TODO: refine the network model, for now, we sample the delay once and
        // assume it's the same delay in both directions as well as between
        // client-server and server-destination.
        let d = self.network.sample();

        // did the blocking expire at the client?
        let mut client = Duration::default();
        let mut server = Duration::default();
        match client_expiry {
            true => {
                // @client: max(4D-B, 0)
                if 4 * d > block_duration {
                    client = 4 * d - block_duration;
                };
                // @server: max(3D-B, 0)
                if 3 * d > block_duration {
                    server = 3 * d - block_duration;
                };
            }
            false => {
                // @client: max(D-B, 0)
                if d > block_duration {
                    client = d - block_duration;
                };
                // @server: max(4D-B, 0)
                if 4 * d > block_duration {
                    server = 4 * d - block_duration;
                };
            }
        };

        debug!(
            "\tpushing aggregate delay {:?} in {:?} at the client",
            block_duration, client
        );
        self.aggregate_delay_queue.push(PendingAggregateDelay {
            time: *current_time + client,
            delay: block_duration,
            client: true,
        });
        debug!(
            "\tpushing aggregate delay {:?} in {:?} at the server",
            block_duration, server
        );
        self.aggregate_delay_queue.push(PendingAggregateDelay {
            time: *current_time + server,
            delay: block_duration,
            client: false,
        });
    }

    pub fn pop_aggregate_delay(&mut self) {
        if let Some(aggregate) = self.aggregate_delay_queue.pop() {
            match aggregate.client {
                true => {
                    debug!("\tpopping aggregate delay at client {:?}", aggregate.delay);
                    self.client_aggregate_base_delay += aggregate.delay;
                }
                false => {
                    debug!("\tpopping aggregate delay at server {:?}", aggregate.delay);
                    self.server_aggregate_base_delay += aggregate.delay;
                }
            };
        }
    }
}

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
    network: &mut ExtendedNetwork,
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
                bypass: false,
                replace: false,
                debug_note: None,
            });
            false
        }
        // here we simulate sending the packet into the tunnel
        TriggerEvent::PaddingSent { .. } => {
            if next.replace {
                // replace flag is set: if we have a normal packet queued up /
                // blocked, we can replace the padding with that FIXME: here be
                // bugs related to integration delays
                if let (Some(queued), qid) =
                    sq.peek_blocking(state.blocking_bypassable, next.client)
                {
                    if queued.client == next.client
                        && TriggerEvent::TunnelSent == queued.event
                        && !queued.contains_padding
                    {
                        // two options:
                        // 1. the padding has the bypass flag set, so we need to
                        //    propagate the flag to the queued packet
                        // 2. the bypass flag is not set, which is also the case
                        //    for normal packets, so we do nothing
                        if !next.bypass {
                            debug!(
                                "\treplaced padding sent with blocked queued normal @{}",
                                side
                            );
                            return false;
                        }

                        // we need to remove and re-insert to get the packet
                        // into the correct internal queue with the new flags
                        let mut entry = sq
                            .pop_blocking(
                                qid,
                                state.blocking_bypassable,
                                next.client,
                                if next.client {
                                    network.get_client_aggregate_base_delay()
                                } else {
                                    network.get_server_aggregate_base_delay()
                                },
                            )
                            .unwrap();
                        entry.bypass = true;
                        entry.replace = false;
                        debug!(
                            "\treplaced bypassable padding sent with blocked queued normal TunnelSent @{}",
                            side
                        );
                        // queue any aggregate delay caused by the blocking
                        if let Some(block_duration) = agg_delay_on_padding_bypass_replace(
                            sq,
                            next.client,
                            *current_time,
                            &entry,
                            match next.client {
                                true => network.get_client_aggregate_base_delay(),
                                false => network.get_server_aggregate_base_delay(),
                            },
                        ) {
                            network.push_aggregate_delay(block_duration, current_time, next.client);
                        }

                        sq.push_sim(entry);
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
                debug_note: None,
            });
            false
        }
        TriggerEvent::TunnelSent => {
            let reporting_delay = recipient.reporting_delay();
            let (network_delay, baseline_delay) = network.sample(current_time, next.client);
            if let Some(pps_delay) = baseline_delay {
                if should_delayed_packet_prop_agg_delay(
                    sq,
                    next.client,
                    next,
                    network.get_client_aggregate_base_delay(),
                ) {
                    debug!(
                        "\tadding {:?} delay to packet due to {:?}pps limit",
                        pps_delay,
                        network.get_pps_limit()
                    );
                    network.push_aggregate_delay(pps_delay, current_time, next.client);
                }
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
                    debug_note: None,
                });
                debug!(
                    "\tqueue {:#?}, arriving at recipient in {:?}",
                    TriggerEvent::TunnelRecv,
                    reported - *current_time
                );
                return true;
            }

            // padding, less complicated: action delay + network + recipient
            // reporting delay
            let reported = next.time + next.integration_delay + network_delay + reporting_delay;
            sq.push_sim(SimEvent {
                event: TriggerEvent::TunnelRecv,
                time: reported,
                integration_delay: reporting_delay,
                client: !next.client,
                contains_padding: true,
                bypass: false,
                replace: false,
                debug_note: None,
            });
            debug!(
                "\tqueue {:#?}, arriving at recipient in {:?}",
                TriggerEvent::TunnelRecv,
                reported - *current_time
            );
            true
        }
        TriggerEvent::TunnelRecv => {
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
