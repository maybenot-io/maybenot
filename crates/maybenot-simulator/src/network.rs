//! For simulating the network stack and network between client and server.

// To use new Linktrace functionality inplace, rename NetowrkBottleneck
// and NetworkLinktraceBneck, to NetowrkBottleneckInactive and NetowrkBottleneck

use std::{
    cmp::{max, Ordering},
    collections::{BinaryHeap, VecDeque},
    fmt,
    //sync::Arc,
    time::{Duration, Instant},
};

use log::debug;
use maybenot::{Machine, TriggerEvent};

use crate::linktrace::{load_linktrace_from_file, mk_start_instant, LinkTrace};
use crate::{queue::SimQueue, RngSource, SimEvent, SimState};

/// A model of the network between the client and server.
#[derive(Debug, Clone)]
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

enum ExtendedNetwork<'a> {
    Bottleneck(NetworkBottleneck),
    Linktrace(NetworkLinktrace<'a>),
}

impl<'a> ExtendedNetwork<'a> {
    pub fn new_bottleneck(network: Network, window: Duration, queue_pps: Option<usize>) -> Self {
        ExtendedNetwork::Bottleneck(NetworkBottleneck::new(network, window, queue_pps))
    }

    pub fn new_linktrace(network: Network, linktrace: &'a LinkTrace) -> Self {
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
}

/// a network bottleneck that adds delay to packets above a certain packets per
/// window limit (default 1s window, so pps), and keeps track of the aggregate
/// delay to add to packets due to the bottleneck or accumulated blocking by
/// machines: used to shift the baseline trace time at both client and relay
#[derive(Debug, Clone)]
//pub struct NetworkBottleneckInactive {
pub struct NetworkBottleneck {
    // the current aggregate of delays to add to base packets due to the
    // bottleneck or accumulated blocking by machines: used to shift the
    // baseline trace time at both client and relay
    pub aggregate_base_delay: Duration,
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

//impl NetworkBottleneckInactive
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
            aggregate_base_delay: Duration::default(),
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
        delay: Duration,
        current_time: &Instant,
        reached_client: bool,
    ) {
        let active_delay = match reached_client {
            // the delay originates from a packet sent by the server that
            // reached the client: from here, the client would send the packet
            // to the application layer (because a client) nearly instant, so
            // the aggregated delay should be in effect right away
            true => Duration::default(),
            // The delay originates from a packet sent by the client that
            // reached the server. We make the ASSUMPTION that the server is in
            // the middle between client and destination, and that the RTT is
            // the same in both directions. From here, the server would send the
            // packet to the destination (taking network.sample() time). During
            // that transmission time, the destination may send further packets
            // to the server, up to the point in time when the packet arrives.
            // Therefore, the aggregated delay should be in effect after 2x
            // network.sample() time.
            false => self.network.sample() + self.network.sample(),
        };
        debug!(
            "\tpushing aggregate delay {:?} in {:?}",
            delay, active_delay
        );
        self.aggregate_delay_queue.push(PendingAggregateDelay {
            time: *current_time + active_delay,
            delay,
        });
    }

    pub fn pop_aggregate_delay(&mut self) {
        let a = self.aggregate_delay_queue.pop();
        if let Some(aggregate) = a {
            debug!("\tpopping aggregate delay {:?}", aggregate.delay);
            self.aggregate_base_delay += aggregate.delay;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingAggregateDelay {
    pub(crate) time: Instant,
    pub(crate) delay: Duration,
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
pub struct NetworkLinktrace<'a> {
    // the current aggregate of delays to add to base packets due to the
    // bottleneck or accumulated blocking by machines: used to shift the
    // baseline trace time at both client and relay
    pub aggregate_base_delay: Duration,
    // the pending aggregate delays to add to packets due to the bottleneck
    aggregate_delay_queue: BinaryHeap<PendingAggregateDelay>,
    // the network model
    network: Network,
    //linktrace: Arc<LinkTrace>,
    linktrace: &'a LinkTrace,
    // The start instant used by parse_trace for the first event at the server side
    sim_trace_startinstant: Instant,
    next_busy_to: usize,
}

impl<'a> NetworkLinktrace<'a> {
    pub fn new(network: Network, linktrace: &'a LinkTrace) -> Self {
        Self {
            network,
            aggregate_base_delay: Duration::default(),
            aggregate_delay_queue: BinaryHeap::new(),
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
        self.aggregate_base_delay = Duration::default();
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
        delay: Duration,
        current_time: &Instant,
        reached_client: bool,
    ) {
        let active_delay = match reached_client {
            // the delay originates from a packet sent by the server that
            // reached the client: from here, the client would send the packet
            // to the application layer (because a client) nearly instant, so
            // the aggregated delay should be in effect right away
            true => Duration::default(),
            // The delay originates from a packet sent by the client that
            // reached the server. We make the ASSUMPTION that the server is in
            // the middle between client and destination, and that the RTT is
            // the same in both directions. From here, the server would send the
            // packet to the destination (taking network.sample() time). During
            // that transmission time, the destination may send further packets
            // to the server, up to the point in time when the packet arrives.
            // Therefore, the aggregated delay should be in effect after 2x
            // network.sample() time.
            false => self.network.sample() + self.network.sample(),
        };
        debug!(
            "\tpushing aggregate delay {:?} in {:?}",
            delay, active_delay
        );
        self.aggregate_delay_queue.push(PendingAggregateDelay {
            time: *current_time + active_delay,
            delay,
        });
    }

    pub fn pop_aggregate_delay(&mut self) {
        let a = self.aggregate_delay_queue.pop();
        if let Some(aggregate) = a {
            debug!("\tpopping aggregate delay {:?}", aggregate.delay);
            self.aggregate_base_delay += aggregate.delay;
        }
    }
}

/// a network that adds delay to packets according to the transmission delay
/// provided by a link trace.  Keeps track of the aggregate
/// delay to add to packets due to the bottleneck or accumulated blocking by
/// machines: used to shift the baseline trace time at both client and relay
#[derive(Debug, Clone)]
pub struct NetworkLinktraceBneck {
    //pub struct NetworkBottleneck {
    // the current aggregate of delays to add to base packets due to the
    // bottleneck or accumulated blocking by machines: used to shift the
    // baseline trace time at both client and relay
    pub aggregate_base_delay: Duration,
    // the pending aggregate delays to add to packets due to the bottleneck
    aggregate_delay_queue: BinaryHeap<PendingAggregateDelay>,
    // the network model
    network: Network,
    // packets per second limit
    #[allow(dead_code)]
    pps_limit: usize,
    //linktrace: Arc<LinkTrace>,
    linktrace: LinkTrace,
    // The start instant used by parse_trace for the first event at the server side
    sim_trace_startinstant: Instant,
    next_busy_to: usize,
}

impl NetworkLinktraceBneck {
    //impl NetworkBottleneck {
    pub fn new(network: Network, _window: Duration, _queue_pps: Option<usize>) -> Self {
        let pps = usize::MAX;
        let linktrace = load_linktrace_from_file("ether100M_synth5M.ltbin")
            .expect("Failed to load LinkTrace ltbin from file");

        Self {
            network,
            aggregate_base_delay: Duration::default(),
            aggregate_delay_queue: BinaryHeap::new(),
            pps_limit: pps,
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
        // Compute the relative duration since the start
        let current_time_slot = current_time
            .duration_since(self.sim_trace_startinstant)
            .as_micros() as usize;

        // Initialize busy_to and queueing_delay_duration
        let (busy_to, queueing_delay_duration) = if self.next_busy_to <= current_time_slot {
            // Packet arrives after the previous packet has finished
            (
                self.linktrace.get_dl_busy_to(current_time_slot, 1500),
                Duration::ZERO,
            )
        } else {
            // Packet arrives before the previous packet has finished
            let busy_to = self.linktrace.get_dl_busy_to(self.next_busy_to, 1500);
            let queueing_delay = (self.next_busy_to - current_time_slot) as u64;
            (busy_to, Duration::from_micros(queueing_delay))
        };

        // Ensure the packet is within the valid range of the link trace
        assert_ne!(
            busy_to, 0,
            "Packet to be scheduled outside of link trace end"
        );

        // Update next_busy_to for the next packet
        self.next_busy_to = busy_to;

        // Compute packet transmission delay
        let pkt_txdelay_duration = Duration::from_micros((busy_to - current_time_slot) as u64);

        // Optimize the return logic by calling sample only once
        let network_delay = self.network.sample();

        if !queueing_delay_duration.is_zero() {
            (
                network_delay + queueing_delay_duration,
                Some(queueing_delay_duration),
            )
        } else {
            (network_delay + pkt_txdelay_duration, None)
        }
    }

    pub fn reset_linktrace(&mut self) {
        self.aggregate_base_delay = Duration::default();
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
        delay: Duration,
        current_time: &Instant,
        reached_client: bool,
    ) {
        let active_delay = match reached_client {
            // the delay originates from a packet sent by the server that
            // reached the client: from here, the client would send the packet
            // to the application layer (because a client) nearly instant, so
            // the aggregated delay should be in effect right away
            true => Duration::default(),
            // The delay originates from a packet sent by the client that
            // reached the server. We make the ASSUMPTION that the server is in
            // the middle between client and destination, and that the RTT is
            // the same in both directions. From here, the server would send the
            // packet to the destination (taking network.sample() time). During
            // that transmission time, the destination may send further packets
            // to the server, up to the point in time when the packet arrives.
            // Therefore, the aggregated delay should be in effect after 2x
            // network.sample() time.
            false => self.network.sample() + self.network.sample(),
        };
        debug!(
            "\tpushing aggregate delay {:?} in {:?}",
            delay, active_delay
        );
        self.aggregate_delay_queue.push(PendingAggregateDelay {
            time: *current_time + active_delay,
            delay,
        });
    }

    pub fn pop_aggregate_delay(&mut self) {
        let a = self.aggregate_delay_queue.pop();
        if let Some(aggregate) = a {
            debug!("\tpopping aggregate delay {:?}", aggregate.delay);
            self.aggregate_base_delay += aggregate.delay;
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
                bypass: false,
                replace: false,
                propagate_base_delay: None,
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
                                network.aggregate_base_delay,
                            )
                            .unwrap();
                        entry.bypass = true;
                        entry.replace = false;
                        // per definition, we are going to replace padding with
                        // a blocked queued normal packet that was either queued
                        // at the same time as the padding (recall: padding has
                        // lower priority than normal base events in the
                        // simulator) or has been queued for some time
                        entry.propagate_base_delay = if current_time > &entry.time {
                            // it was delayed, propagate the delay to the
                            // receiver
                            Some(*current_time - entry.time)
                        } else {
                            None
                        };
                        debug!(
                            "\treplaced bypassable padding sent with blocked queued normal TunnelSent @{}",
                            side
                        );
                        if let Some(delay) = entry.propagate_base_delay {
                            debug!(
                                "\tblocking delayed base TunnelSent by {:?}, propagating in event",
                                delay
                            );
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
                propagate_base_delay: None,
            });
            false
        }
        TriggerEvent::TunnelSent => {
            let reporting_delay = recipient.reporting_delay();
            let (network_delay, mut baseline_delay) = network.sample(current_time, next.client);
            if let Some(pps_delay) = baseline_delay {
                debug!(
                    "\tadding {:?} delay to packet due to {:?}pps limit",
                    pps_delay, network.pps_limit
                );
            }

            // blocked TunnelSent may have a base delay to propagate
            match (next.propagate_base_delay, baseline_delay) {
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
                    propagate_base_delay: baseline_delay,
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
                // NOTE: padding does not contribute to delaying the base trace
                // (beyond filling the bottleneck window)
                propagate_base_delay: baseline_delay,
            });
            debug!(
                "\tqueue {:#?}, arriving at recipient in {:?}",
                TriggerEvent::TunnelRecv,
                reported - *current_time
            );
            true
        }
        TriggerEvent::TunnelRecv => {
            if let Some(bottleneck) = next.propagate_base_delay {
                network.push_aggregate_delay(bottleneck, current_time, next.client);
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
