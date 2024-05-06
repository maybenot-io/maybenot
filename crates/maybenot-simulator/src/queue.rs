//! The main queue of events in the simulator.

use std::{
    cmp::Reverse,
    time::{Duration, Instant},
};

use maybenot::framework::TriggerEvent;
use priority_queue::PriorityQueue;

use crate::SimEvent;

/// SimQueue represents the queue of events that are to be processed by the
/// simulator. It is a wrapper around an EventQueue for the client and an
/// EventQueue for the server. The goal is to never have to search through
/// any of the queues, but to be able to directly access the next event
/// that is to be processed with as little work as possible.
#[derive(Debug, Clone)]
pub struct SimQueue {
    client: EventQueue,
    server: EventQueue,
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
        time: Instant,
        delay: Duration,
        priority: Reverse<Instant>,
    ) {
        self.push_sim(
            SimEvent {
                event,
                time,
                delay,
                client: is_client,
                bypass: false,
                replace: false,
                fuzz: fastrand::i32(..),
            },
            priority,
        );
    }

    pub fn push_sim(&mut self, item: SimEvent, priority: Reverse<Instant>) {
        match item.client {
            true => self.client.push(item, priority),
            false => self.server.push(item, priority),
        }
    }

    pub fn peek(&self) -> Option<(&SimEvent, &Reverse<Instant>)> {
        match self.len() {
            0 => None,
            _ => {
                // peak all, per def, it's one of them
                let c = self.client.peek();
                let s = self.server.peek();

                match before(c, s) {
                    true => c,
                    false => s,
                }
            }
        }
    }

    pub fn remove(&mut self, item: &SimEvent) {
        match item.client {
            true => self.client.remove(item),
            false => self.server.remove(item),
        }
    }

    pub fn peek_blocking(
        &self,
        blocking_bypassable: bool,
        is_client: bool,
    ) -> Option<(&SimEvent, &Reverse<Instant>)> {
        match is_client {
            true => peak_blocking(&self.client, blocking_bypassable),
            false => peak_blocking(&self.server, blocking_bypassable),
        }
    }

    pub fn peek_nonblocking(
        &self,
        blocking_bypassable: bool,
        is_client: bool,
    ) -> Option<(&SimEvent, &Reverse<Instant>)> {
        match is_client {
            true => peak_nonblocking(&self.client, blocking_bypassable),
            false => peak_nonblocking(&self.server, blocking_bypassable),
        }
    }
}

fn peak_blocking(
    queue: &EventQueue,
    blocking_bypassable: bool,
) -> Option<(&SimEvent, &Reverse<Instant>)> {
    if blocking_bypassable {
        // only blocking events are then blocking
        queue.peek_blocking()
    } else {
        // if the current blocking is not bypassable, then we need to
        // consider blocking_bypassable events as also blocking
        let b = queue.peek_blocking();
        let bb = queue.peek_blocking_bypassable();

        match before(b, bb) {
            true => b,
            false => bb,
        }
    }
}

fn peak_nonblocking(
    queue: &EventQueue,
    blocking_bypassable: bool,
) -> Option<(&SimEvent, &Reverse<Instant>)> {
    if blocking_bypassable {
        // if the current blocking is not bypassable, then we need to
        // consider blocking_bypassable as a nonblocking event
        let bb = queue.peek_blocking_bypassable();
        let n = queue.peek_nonblocking();

        match before(bb, n) {
            true => bb,
            false => n,
        }
    } else {
        // only nonblocking events are then nonblocking
        queue.peek_nonblocking()
    }
}

/// EventQueue represents the queue of events that are waiting to be processed
/// in order (time-wise). The queue is split into three parts:
/// 1. blocking: events that are blocking, i.e., that must take blocking into
///    account.
/// 2. blocking_bypassable: events that are blocking, but that MAY be bypassed
///    (depending on the type of active blocking).
/// 3. nonblocking: events that are always not blocking.
#[derive(Debug, Clone)]
struct EventQueue {
    blocking: PriorityQueue<SimEvent, Reverse<Instant>>,
    blocking_bypassable: PriorityQueue<SimEvent, Reverse<Instant>>,
    nonblocking: PriorityQueue<SimEvent, Reverse<Instant>>,
}

impl EventQueue {
    pub fn new() -> EventQueue {
        EventQueue {
            blocking: PriorityQueue::new(),
            blocking_bypassable: PriorityQueue::new(),
            nonblocking: PriorityQueue::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.blocking.len() + self.blocking_bypassable.len() + self.nonblocking.len()
    }

    pub fn push(&mut self, item: SimEvent, priority: Reverse<Instant>) {
        match item.event {
            TriggerEvent::NonPaddingSent { .. } | TriggerEvent::PaddingSent { .. } => {
                match item.bypass {
                    true => self.blocking_bypassable.push(item, priority),
                    false => self.blocking.push(item, priority),
                };
            }
            _ => {
                self.nonblocking.push(item, priority);
            }
        }
    }

    pub fn peek(&self) -> Option<(&SimEvent, &Reverse<Instant>)> {
        match self.len() {
            0 => None,
            _ => {
                // peak all, per def, it's one of them
                let b = self.blocking.peek();
                let bb = self.blocking_bypassable.peek();
                let n = self.nonblocking.peek();

                // is b first?
                if before(b, bb) && before(b, n) {
                    b
                // is bb first?
                } else if before(bb, n) {
                    bb
                // has to be n then
                } else {
                    n
                }
            }
        }
    }

    pub fn remove(&mut self, item: &SimEvent) {
        match item.event {
            TriggerEvent::NonPaddingSent { .. } | TriggerEvent::PaddingSent { .. } => {
                match item.bypass {
                    true => self.blocking_bypassable.remove(item),
                    false => self.blocking.remove(item),
                };
            }
            _ => {
                self.nonblocking.remove(item);
            }
        }
    }

    pub fn peek_blocking(&self) -> Option<(&SimEvent, &Reverse<Instant>)> {
        self.blocking.peek()
    }

    pub fn peek_blocking_bypassable(&self) -> Option<(&SimEvent, &Reverse<Instant>)> {
        self.blocking_bypassable.peek()
    }

    pub fn peek_nonblocking(&self) -> Option<(&SimEvent, &Reverse<Instant>)> {
        self.nonblocking.peek()
    }
}

fn before(
    a: Option<(&SimEvent, &Reverse<Instant>)>,
    b: Option<(&SimEvent, &Reverse<Instant>)>,
) -> bool {
    // is a before b?
    match a {
        Some((_, ai)) => match b {
            Some((_, bi)) => ai.0.cmp(&bi.0).is_le(),
            None => true, // something is before nothing
        },
        None => false,
    }
}
