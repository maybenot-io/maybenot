//! Functions for peeking at the possible next events in the simulation.

use std::time::{Duration, Instant};

use log::debug;
use maybenot::{Machine, event::Event};

use crate::{RngSource, ScheduledAction, SimState, queue::SimQueue, queue_event::Queue};

pub(crate) fn peek_queue<M: AsRef<[Machine]>>(
    sq: &SimQueue,
    client: &SimState<M, RngSource>,
    server: &SimState<M, RngSource>,
    client_network_delay_sum: Duration,
    server_network_delay_sum: Duration,
    earliest: Duration,
    current_time: Instant,
) -> (Duration, Queue, bool) {
    // easy: no queue to consider
    if sq.is_empty() {
        return (Duration::MAX, Queue::Blocking, false);
    }

    // peek, taking any accumulated network delay into account, computing the
    // duration since the current time for the peeked event
    let (peek, queue, duration_since) = sq.peek(
        client_network_delay_sum,
        server_network_delay_sum,
        current_time,
    );
    let peek = peek.unwrap();

    // if the earliest peeked is *after* the earliest found by other peeks(),
    // then looking further is pointless as far as pick_next() is concerned
    if duration_since > earliest {
        return (Duration::MAX, Queue::Blocking, false);
    }

    // easy: non-delay event first
    if !peek.event.is_event(Event::PacketSent) {
        return (duration_since, queue, peek.client);
    }

    let client_delay = client.delay_until.is_some();
    let server_delay = server.delay_until.is_some();

    // easy: no active delay to consider
    if !client_delay && !server_delay {
        return (duration_since, queue, peek.client);
    }

    // lucky: peek not blocked means it's earliest
    if (peek.client && !client_delay) || (!peek.client && !server_delay) {
        return (duration_since, queue, peek.client);
    }

    // peek is blocked but the event is a bypassable PacketSent AND the delay
    // is bypassable
    if (peek.client
        && client_delay
        && client.delay_bypassable
        // bypassable PacketSent is the result of replaced decoy traffic
        && (peek.event.is_event(Event::PacketSent))
        && peek.bypass)
        || (!peek.client
            && server_delay
            && server.delay_bypassable
            // bypassable PacketSent is the result of replaced decoy traffic
            && (peek.event.is_event(Event::PacketSent))
            && peek.bypass)
    {
        return (duration_since, queue, peek.client);
    }

    // not lucky, things get ugly...we have to consider both sides: find
    // earliest client and server
    let (c_d, c_q, c_b) = peek_queue_earliest_side(
        sq,
        client.delay_until,
        client.delay_bypassable,
        current_time,
        client_network_delay_sum,
        true,
    );
    let (s_d, s_q, s_b) = peek_queue_earliest_side(
        sq,
        server.delay_until,
        server.delay_bypassable,
        current_time,
        server_network_delay_sum,
        false,
    );
    debug!("peek_queue: c_d={c_d:?}, c_q={c_q:?}, c_b={c_b}, s_d={s_d:?}, s_q={s_q:?}, s_b={s_b}");
    // pick earliest
    if c_d <= s_d {
        (c_d, c_q, c_b)
    } else {
        (s_d, s_q, s_b)
    }
}

// Here be dragons: surprisingly annoying function to get right and fast.
// Closely tied to how SimQueue is implemented.
fn peek_queue_earliest_side(
    sq: &SimQueue,
    delay_until: Option<Instant>,
    delay_bypassable: bool,
    current_time: Instant,
    network_delay_sum: Duration,
    is_client: bool,
) -> (Duration, Queue, bool) {
    debug!("peek_queue_earliest_side: is_client={is_client}");
    // OK, bummer, we have to peek for the next delay and non-delay: note
    // that this takes into account if delay is bypassable or not, picking
    // the earliest next event from the queue.
    let (peek_delay, delay_queue) = sq.peek_delay(delay_bypassable, is_client);
    let (peek_non_delay, non_delay_queue) =
        sq.peek_non_delay(delay_bypassable, is_client, network_delay_sum);

    // easy: no events to consider
    if peek_delay.is_none() && peek_non_delay.is_none() {
        return (Duration::MAX, Queue::Blocking, is_client);
    }

    // take the delay_until into account, if no set, use current time as a
    // placeholder
    let delay_until = delay_until.unwrap_or(current_time);

    // easy: only one event to consider
    if peek_delay.is_none() {
        // take network delay into account for non-delay events
        let peek_non_delay_time = match non_delay_queue {
            Queue::Base => peek_non_delay.unwrap().time + network_delay_sum,
            _ => peek_non_delay.unwrap().time,
        };
        return (
            peek_non_delay_time.duration_since(current_time),
            non_delay_queue,
            is_client,
        );
    }
    if peek_non_delay.is_none() {
        return (
            peek_delay
                .unwrap()
                .time
                .max(delay_until)
                .duration_since(current_time),
            delay_queue,
            is_client,
        );
    }

    // consider both events, taking delay into account
    let peek_delay = peek_delay.unwrap();
    let peek_non_delay = peek_non_delay.unwrap();

    debug!("\tpeek_queue_earliest_side: peek_delay={peek_delay:?}, delay_queue={delay_queue:?}");
    debug!(
        "\tpeek_queue_earliest_side: peek_non_delay={peek_non_delay:?}, non_delay_queue={non_delay_queue:?}"
    );

    // take network delay into account for non-delay events
    let peek_non_delay_time = match non_delay_queue {
        Queue::Base => peek_non_delay.time + network_delay_sum,
        _ => peek_non_delay.time,
    };

    // a bit verbose, but on equal, we want to prioritize the base queue while
    // not prioritizing the internal queue, which are both non-delay
    let delay_first = match peek_delay.time.max(delay_until).cmp(&peek_non_delay_time) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        // delay only if the queue is not the base queue
        std::cmp::Ordering::Equal => non_delay_queue != Queue::Base,
    };
    debug!("\tpeek_queue_earliest_side: delay_first={delay_first}");
    if delay_first {
        (
            peek_delay
                .time
                .max(delay_until)
                .duration_since(current_time),
            delay_queue,
            is_client,
        )
    } else {
        (
            peek_non_delay_time.duration_since(current_time),
            non_delay_queue,
            is_client,
        )
    }
}

pub fn peek_scheduled_action(
    scheduled_c: &[Option<ScheduledAction>],
    scheduled_s: &[Option<ScheduledAction>],
    current_time: Instant,
) -> Duration {
    // there are at most one scheduled action per machine, so we can just
    // iterate over all of them quickly
    let mut earliest = Duration::MAX;

    for a in scheduled_c.iter().flatten() {
        if a.time >= current_time && a.time.duration_since(current_time) < earliest {
            earliest = a.time.duration_since(current_time);
        }
    }
    for a in scheduled_s.iter().flatten() {
        if a.time >= current_time && a.time.duration_since(current_time) < earliest {
            earliest = a.time.duration_since(current_time);
        }
    }

    earliest
}

pub fn peek_scheduled_internal_timer(
    internal_c: &[Option<Instant>],
    internal_s: &[Option<Instant>],
    current_time: Instant,
) -> Duration {
    // there are at most one internal event per machine, so we can just
    // iterate over all of them quickly
    let mut earliest = Duration::MAX;

    for t in internal_c.iter().flatten() {
        if *t >= current_time && t.duration_since(current_time) < earliest {
            earliest = t.duration_since(current_time);
        }
    }
    for t in internal_s.iter().flatten() {
        if *t >= current_time && t.duration_since(current_time) < earliest {
            earliest = t.duration_since(current_time);
        }
    }

    earliest
}

pub fn peek_blocked_exp(
    delay_c: Option<Instant>,
    delay_s: Option<Instant>,
    current_time: Instant,
) -> (Duration, bool) {
    match (delay_c, delay_s) {
        (Some(c), Some(s)) => {
            if c < s {
                (c.duration_since(current_time), true)
            } else {
                (s.duration_since(current_time), false)
            }
        }
        (Some(c), None) => (c.duration_since(current_time), true),
        (None, Some(s)) => (s.duration_since(current_time), false),
        (None, None) => (Duration::MAX, true),
    }
}
