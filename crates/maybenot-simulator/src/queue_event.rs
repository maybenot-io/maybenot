use std::collections::BinaryHeap;

use maybenot::TriggerEvent;

use crate::{event_to_usize, SimEvent};

use std::time::{Duration, Instant};

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
pub struct EventQueue {
    pub(crate) base: BinaryHeap<SimEvent>,
    pub(crate) blocking: BinaryHeap<SimEvent>,
    pub(crate) bypassable: BinaryHeap<SimEvent>,
    pub(crate) internal: BinaryHeap<SimEvent>,
}

impl Default for EventQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl EventQueue {
    pub fn new() -> EventQueue {
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

    pub fn len(&self) -> usize {
        self.blocking.len() + self.bypassable.len() + self.internal.len() + self.base.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn push(&mut self, item: SimEvent) {
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

    pub fn peek(
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
    pub fn pop(&mut self, q: Queue, network_delay_sum: Duration) -> Option<SimEvent> {
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
    pub fn peek_blocking(&self) -> Option<&SimEvent> {
        self.blocking.peek()
    }

    /// peek the next bypassable event
    pub fn peek_bypassable(&self) -> Option<&SimEvent> {
        self.bypassable.peek()
    }

    /// peek the next non-blocking event
    pub fn peek_non_blocking(&self, network_delay_sum: Duration) -> (Option<&SimEvent>, Queue) {
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
