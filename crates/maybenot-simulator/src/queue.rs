//! The main queue of events in the simulator.

use std::{
    collections::BinaryHeap,
    time::{Duration, Instant},
};

use log::debug;
use maybenot::event::TriggerEvent;

use crate::{event_to_usize, SimEvent};

/// SimQueue represents the queue of events that are to be processed by the
/// simulator. It is a wrapper around an EventQueue for the client and an
/// EventQueue for the server. The goal is to never have to search through
/// any of the queues, but to be able to directly access the next event
/// that is to be processed with as little work as possible.
#[derive(Debug, Clone)]
pub struct SimQueue {
    client: EventQueue,
    server: EventQueue,
    // The maximum number of packets/cells (depends on trace) per second before
    // adding delay due to a simulated bottleneck. None means no limit.
    pub(crate) max_pps: Option<usize>,
}

impl Default for SimQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl SimQueue {
    pub fn new() -> SimQueue {
        SimQueue {
            client: EventQueue::new(),
            server: EventQueue::new(),
            max_pps: None,
        }
    }

    pub fn len(&self) -> usize {
        self.client.len() + self.server.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn push(
        &mut self,
        event: TriggerEvent,
        is_client: bool,
        contains_padding: bool,
        time: Instant,
        delay: Duration,
    ) {
        self.push_sim(SimEvent {
            event,
            time,
            integration_delay: delay,
            client: is_client,
            contains_padding,
            bypass: false,
            replace: false,
            debug_note: None,
        });
    }

    pub fn push_sim(&mut self, item: SimEvent) {
        match item.client {
            true => self.client.push(item),
            false => self.server.push(item),
        }
    }

    pub fn peek(
        &self,
        client_network_delay_sum: Duration,
        server_network_delay_sum: Duration,
        current_time: Instant,
    ) -> (Option<&SimEvent>, Queue, Duration) {
        match self.len() {
            0 => (None, Queue::Blocking, Duration::default()),
            _ => {
                // peek all, per def, it's one of them
                let (client, client_queue, client_duration) =
                    self.client.peek(client_network_delay_sum, current_time);
                let (server, server_queue, server_duration) =
                    self.server.peek(server_network_delay_sum, current_time);

                // if one of the queues is empty, return the other, otherwise
                // compare based on the smallest duration, and if equal, based
                // on the event type: this is needed due to peek() above
                // accounting for the network delay sum for base events
                match (client, server) {
                    (Some(_), None) => (client, client_queue, client_duration),
                    (None, Some(_)) => (server, server_queue, server_duration),
                    (None, None) => (None, Queue::Blocking, Duration::default()),
                    (Some(client_event), Some(server_event)) => {
                        let ordering = client_duration.cmp(&server_duration).then_with(|| {
                            event_to_usize(&client_event.event)
                                .cmp(&event_to_usize(&server_event.event))
                        });
                        if ordering == std::cmp::Ordering::Less
                            || ordering == std::cmp::Ordering::Equal
                        {
                            (client, client_queue, client_duration)
                        } else {
                            (server, server_queue, server_duration)
                        }
                    }
                }
            }
        }
    }

    pub fn pop(
        &mut self,
        q: Queue,
        is_client: bool,
        network_delay_sum: Duration,
    ) -> Option<SimEvent> {
        match is_client {
            true => self.client.pop(q, network_delay_sum),
            false => self.server.pop(q, network_delay_sum),
        }
    }

    pub fn peek_blocking(
        &self,
        active_blocking_bypassable: bool,
        is_client: bool,
    ) -> (Option<&SimEvent>, Queue) {
        match is_client {
            true => peek_blocking(&self.client, active_blocking_bypassable),
            false => peek_blocking(&self.server, active_blocking_bypassable),
        }
    }

    pub fn pop_blocking(
        &mut self,
        q: Queue,
        bypassable: bool,
        is_client: bool,
        network_delay_sum: Duration,
    ) -> Option<SimEvent> {
        if bypassable {
            match is_client {
                true => self.client.blocking.pop(),
                false => self.server.blocking.pop(),
            }
        } else {
            self.pop(q, is_client, network_delay_sum)
        }
    }

    pub fn peek_non_blocking(
        &self,
        bypassable: bool,
        is_client: bool,
        network_delay_sum: Duration,
    ) -> (Option<&SimEvent>, Queue) {
        match is_client {
            true => peek_non_blocking(&self.client, bypassable, network_delay_sum),
            false => peek_non_blocking(&self.server, bypassable, network_delay_sum),
        }
    }

    pub fn get_first_time(&self) -> Option<Instant> {
        let c = self.client.get_first_base_time();
        let s = self.server.get_first_base_time();

        match (c, s) {
            (Some(ct), Some(st)) => Some(ct.min(st)),
            (Some(ct), None) => Some(ct),
            (None, Some(st)) => Some(st),
            (None, None) => None,
        }
    }

    /// on blocking expiration, this function determines the duration, if any,
    /// that should be added as aggregated delay as a consequence of packets
    /// being blocked
    pub fn agg_delay_on_blocking_expire(
        &self,
        is_client: bool,
        expire_time: Instant,
        blocking_head: &SimEvent,
        aggregate_base_delay: Duration,
    ) -> Option<Duration> {
        // how far into the future in the ingress queue (base events of
        // NormalSent) to consider the blocking head event as part of a burst
        const BASE_WINDOW: Duration = Duration::from_millis(1);
        // the maximum duration of the hypothetical burst as part of the blocked
        // (buffered) TunnelSent events
        const BUFFER_WINDOW: Duration = Duration::from_millis(1);

        let (blocking, bypassable) = match is_client {
            true => (&self.client.blocking, &self.client.bypassable),
            false => (&self.server.blocking, &self.server.bypassable),
        };

        // we have a buffer of blocked packets
        let buffer_size = blocking.len() + bypassable.len();

        // and the packet to be sent next in the simulator (either at
        // expire_time or in the future)
        let base = match is_client {
            // at the client, it's the next packet from the application layer
            true => self.client.base.peek(),
            // at the server, it's the next packet on the ingress from the
            // destination
            false => self.server.base.peek(),
        };

        // we look for the tail of the buffered packets within the window
        let mut tail = blocking_head.time;
        if buffer_size > 2 {
            // many packets, note that the blocking_head has been blocked for
            // the longest duration of all blocked packets. We now check all the
            // blocked packets, determining the timestamp of the event with the
            // largest timestamp still within the window (the tail packet)
            blocking.iter().chain(bypassable.iter()).for_each(|e| {
                if e.time - blocking_head.time <= BUFFER_WINDOW && e.time > tail {
                    tail = e.time;
                }
            });
        }

        // edge case: no need to schedule 0 duration
        if expire_time == tail {
            return None;
        }

        match base {
            Some(base) => {
                let base_time = base.time + aggregate_base_delay;
                if base_time - blocking_head.time <= BASE_WINDOW {
                    debug!("base is within blocking head window");
                    // if the blocking head event (not the tail, or we get a
                    // sliding window) and the next base event are within the
                    // window, we assume that they are related and don't add any
                    // delay, instead any later blocking of the tail should
                    // cause delay, if any
                    None
                } else {
                    debug!("base is outside of the window");
                    // the base packet is outside of the window, this is a tail,
                    // compute the delay
                    Some(expire_time - tail)
                }
            }
            // no base, so use the found tail
            None => {
                debug!("no base");
                Some(expire_time - tail)
            }
        }
    }

    /// when a padding packet with bypass replace is sent through bypassable
    /// blocking, this function determines the duration, if any, that should be
    /// added as aggregated delay as a consequence of packets being blocked
    pub fn agg_delay_on_padding_bypass_replace(
        &self,
        is_client: bool,
        current_time: Instant,
        blocking_head: &SimEvent,
        aggregate_base_delay: Duration,
    ) -> Option<Duration> {
        const ADJACENT_WINDOW: Duration = Duration::from_millis(100);
        const BASE_WINDOW: Duration = Duration::from_millis(1);

        let (blocking, bypassable) = match is_client {
            true => (&self.client.blocking, &self.client.bypassable),
            false => (&self.server.blocking, &self.server.bypassable),
        };

        // and the packet to be sent next in the simulator (either at
        // current_time or in the future)
        let base = match is_client {
            // at the client, it's the next packet from the application layer
            true => self.client.base.peek(),
            // at the server, it's the next packet on the ingress from the
            // destination
            false => self.server.base.peek(),
        };

        // before calling agg_delay_on_padding_bypass_replace() in network.rs,
        // the blocking packet has been temporarily popped,so we look for any
        // adjacent packet either in the blocking or bypassable queues
        for e in blocking.iter().chain(bypassable.iter()) {
            if e.time - blocking_head.time <= ADJACENT_WINDOW {
                debug!("found adjacently blocked packet");
                return None;
            }
        }

        if let Some(base) = base {
            let base_time = base.time + aggregate_base_delay;
            if base_time - blocking_head.time <= BASE_WINDOW {
                debug!("base is within blocking head window");
                return None;
            }
            debug!("base is outside of the window");
        }

        Some(current_time - blocking_head.time)
    }
}

fn peek_blocking(
    queue: &EventQueue,
    active_blocking_bypassable: bool,
) -> (Option<&SimEvent>, Queue) {
    if active_blocking_bypassable {
        // only blocking events are then blocking
        (queue.peek_blocking(), Queue::Blocking)
    } else {
        // if the current blocking is not bypassable, then we need to
        // consider bypassable events as also blocking
        let b = queue.peek_blocking();
        let bb = queue.peek_bypassable();

        if b > bb {
            (b, Queue::Blocking)
        } else {
            (bb, Queue::Bypassable)
        }
    }
}

fn peek_non_blocking(
    queue: &EventQueue,
    bypassable: bool,
    network_delay_sum: Duration,
) -> (Option<&SimEvent>, Queue) {
    if bypassable {
        // if the current blocking is bypassable, then we need to consider
        // bypassable as non-blocking
        let bb = queue.peek_bypassable();
        let (n, nq) = queue.peek_non_blocking(network_delay_sum);

        if bb > n {
            (bb, Queue::Bypassable)
        } else {
            (n, nq)
        }
    } else {
        queue.peek_non_blocking(network_delay_sum)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Queue {
    Blocking,
    Bypassable,
    Internal,
    Base,
}

/// EventQueue represents the queue of events that are waiting to be processed
/// in order (time-wise). The queue is split into four parts:
/// - base: TriggerEvent::NormalSent events that are from the parsed base trace
/// - blocking: TunnelSent events that may be blocked by blocking machines
/// - bypassable: TunnelSent events that are blocked with bypassable blocking
/// - internal: all other events
#[derive(Debug, Clone)]
struct EventQueue {
    base: BinaryHeap<SimEvent>,
    blocking: BinaryHeap<SimEvent>,
    bypassable: BinaryHeap<SimEvent>,
    internal: BinaryHeap<SimEvent>,
}

impl EventQueue {
    fn new() -> EventQueue {
        EventQueue {
            // TriggerEvent::NormalSent is the only event in the base trace
            base: BinaryHeap::with_capacity(4096),
            // TriggerEvent::TunnelSent is the only event that can be blocking
            // or bypassable
            blocking: BinaryHeap::with_capacity(1024),
            bypassable: BinaryHeap::with_capacity(1024),
            // all events that are not TriggerEvent::TunnelSent or
            // TriggerEvent::NormalSent are internal
            internal: BinaryHeap::with_capacity(1024),
        }
    }

    fn len(&self) -> usize {
        self.blocking.len() + self.bypassable.len() + self.internal.len() + self.base.len()
    }

    fn push(&mut self, item: SimEvent) {
        match item.event {
            TriggerEvent::TunnelSent => {
                match item.bypass {
                    true => self.bypassable.push(item),
                    false => self.blocking.push(item),
                };
            }
            // from parse_trace_advanced(), the only place where we push
            // TriggerEvent::NormalSent from a base trace
            TriggerEvent::NormalSent => {
                self.base.push(item);
            }
            _ => {
                self.internal.push(item);
            }
        }
    }

    fn peek(
        &self,
        network_delay_sum: Duration,
        current_time: Instant,
    ) -> (Option<&SimEvent>, Queue, Duration) {
        match self.len() {
            0 => (None, Queue::Blocking, Duration::default()),
            _ => {
                // peek all, per def, it's one of them: we prioritize in order
                // of base, bypassable, blocking, and lastly internal
                let (mut first, mut q) = (self.bypassable.peek(), Queue::Bypassable);

                let n = self.blocking.peek();
                if n > first {
                    first = n;
                    q = Queue::Blocking;
                }

                let n = self.internal.peek();
                if n > first {
                    first = n;
                    q = Queue::Internal;
                }

                // for the base queue, we need to consider the network delay sum
                // to determine the actual time of the event
                let duration_since: Duration;
                let n = self.base.peek();
                if before(n, first, network_delay_sum) {
                    first = n;
                    q = Queue::Base;
                    duration_since =
                        (first.unwrap().time + network_delay_sum).duration_since(current_time);
                } else {
                    duration_since = first.unwrap().time.duration_since(current_time);
                }
                (first, q, duration_since)
            }
        }
    }

    /// remove an event from the queue
    fn pop(&mut self, q: Queue, network_delay_sum: Duration) -> Option<SimEvent> {
        match q {
            Queue::Blocking => self.blocking.pop(),
            Queue::Bypassable => self.bypassable.pop(),
            Queue::Internal => self.internal.pop(),
            Queue::Base => {
                if network_delay_sum == Duration::default() {
                    self.base.pop()
                } else {
                    let mut item = self.base.pop().unwrap();
                    item.time += network_delay_sum;
                    Some(item)
                }
            }
        }
    }

    /// peek the next blocking event
    fn peek_blocking(&self) -> Option<&SimEvent> {
        self.blocking.peek()
    }

    /// peek the next bypassable event
    fn peek_bypassable(&self) -> Option<&SimEvent> {
        self.bypassable.peek()
    }

    /// peek the next non-blocking event
    fn peek_non_blocking(&self, network_delay_sum: Duration) -> (Option<&SimEvent>, Queue) {
        let b = self.base.peek();
        let i = self.internal.peek();
        if before(b, i, network_delay_sum) {
            (b, Queue::Base)
        } else {
            (i, Queue::Internal)
        }
    }

    /// get the first time of the base queue: should only be used for the
    /// simulator's current time at startup
    pub fn get_first_base_time(&self) -> Option<Instant> {
        self.base.peek().map(|e| e.time)
    }
}

// determine if a, with network delay sum, is before or at b: uses the same
// ordering as the binary heap, from SimEvent::cmp()
fn before(a: Option<&SimEvent>, b: Option<&SimEvent>, a_network_delay_sum: Duration) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            let a_time = a.time + a_network_delay_sum;
            let b_time = b.time;
            let ordering = a_time
                .cmp(&b_time)
                .then_with(|| event_to_usize(&a.event).cmp(&event_to_usize(&b.event)));
            // prefer a if it's equal, since it's the base event
            ordering == std::cmp::Ordering::Less || ordering == std::cmp::Ordering::Equal
        }
        (Some(_), None) => true,
        _ => false,
    }
}
