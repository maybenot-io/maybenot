//! The main queue of events in the simulator.

use std::time::{Duration, Instant};

use maybenot::event::TriggerEvent;

use crate::{
    event_to_usize,
    queue_event::{EventQueue, Queue},
    SimEvent,
};

/// SimQueue represents the queue of events that are to be processed by the
/// simulator. It is a wrapper around an EventQueue for the client and an
/// EventQueue for the server. The goal is to never have to search through
/// any of the queues, but to be able to directly access the next event
/// that is to be processed with as little work as possible.
#[derive(Debug, Clone)]
pub struct SimQueue {
    pub(crate) client: EventQueue,
    pub(crate) server: EventQueue,
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
