//! Functions for peeking at the possible next events in the simulation.

use std::time::{Duration, Instant};

use log::debug;
use maybenot::{event::Event, Machine};

use crate::{queue::SimQueue, queue_event::Queue, RngSource, ScheduledAction, SimState};

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

    // easy: non-blocking event first
    if !peek.event.is_event(Event::TunnelSent) {
        return (duration_since, queue, peek.client);
    }

    let client_blocking = client.blocking_until.is_some();
    let server_blocking = server.blocking_until.is_some();

    // easy: no active blocking to consider
    if !client_blocking && !server_blocking {
        return (duration_since, queue, peek.client);
    }

    // lucky: peek not blocked means it's earliest
    if (peek.client && !client_blocking) || (!peek.client && !server_blocking) {
        return (duration_since, queue, peek.client);
    }

    // peek is blocked but the event is a bypassable TunnelSent AND the blocking
    // is bypassable
    if (peek.client
        && client_blocking
        && client.blocking_bypassable
        // bypassable TunnelSent is the result of replaced padding
        && (peek.event.is_event(Event::TunnelSent))
        && peek.bypass)
        || (!peek.client
            && server_blocking
            && server.blocking_bypassable
            // bypassable TunnelSent is the result of replaced padding
            && (peek.event.is_event(Event::TunnelSent))
            && peek.bypass)
    {
        return (duration_since, queue, peek.client);
    }

    // not lucky, things get ugly...we have to consider both sides: find
    // earliest client and server
    let (c_d, c_q, c_b) = peek_queue_earliest_side(
        sq,
        client.blocking_until,
        client.blocking_bypassable,
        current_time,
        client_network_delay_sum,
        true,
    );
    let (s_d, s_q, s_b) = peek_queue_earliest_side(
        sq,
        server.blocking_until,
        server.blocking_bypassable,
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
    blocking_until: Option<Instant>,
    blocking_bypassable: bool,
    current_time: Instant,
    network_delay_sum: Duration,
    is_client: bool,
) -> (Duration, Queue, bool) {
    debug!("peek_queue_earliest_side: is_client={is_client}");
    // OK, bummer, we have to peek for the next blocking and non-blocking: note
    // that this takes into account if blocking is bypassable or not, picking
    // the earliest next event from the queue.
    let (peek_blocking, blocking_queue) = sq.peek_blocking(blocking_bypassable, is_client);
    let (peek_non_blocking, non_blocking_queue) =
        sq.peek_non_blocking(blocking_bypassable, is_client, network_delay_sum);

    // easy: no events to consider
    if peek_blocking.is_none() && peek_non_blocking.is_none() {
        return (Duration::MAX, Queue::Blocking, is_client);
    }

    // take the blocking_until into account, if no set, use current time as a
    // placeholder
    let blocking_until = blocking_until.unwrap_or(current_time);

    // easy: only one event to consider
    if peek_blocking.is_none() {
        // take network delay into account for non-blocking events
        let peek_non_blocking_time = match non_blocking_queue {
            Queue::Base => peek_non_blocking.unwrap().time + network_delay_sum,
            _ => peek_non_blocking.unwrap().time,
        };
        return (
            peek_non_blocking_time.duration_since(current_time),
            non_blocking_queue,
            is_client,
        );
    }
    if peek_non_blocking.is_none() {
        return (
            peek_blocking
                .unwrap()
                .time
                .max(blocking_until)
                .duration_since(current_time),
            blocking_queue,
            is_client,
        );
    }

    // consider both events, taking blocking into account
    let peek_blocking = peek_blocking.unwrap();
    let peek_non_blocking = peek_non_blocking.unwrap();

    debug!(
        "\tpeek_queue_earliest_side: peek_blocking={peek_blocking:?}, blocking_queue={blocking_queue:?}"
    );
    debug!(
        "\tpeek_queue_earliest_side: peek_non_blocking={peek_non_blocking:?}, non_blocking_queue={non_blocking_queue:?}"
    );

    // take network delay into account for non-blocking events
    let peek_non_blocking_time = match non_blocking_queue {
        Queue::Base => peek_non_blocking.time + network_delay_sum,
        _ => peek_non_blocking.time,
    };

    // a bit verbose, but on equal, we want to prioritize the base queue while
    // not prioritizing the internal queue, which are both non-blocking
    let blocking_first = match peek_blocking
        .time
        .max(blocking_until)
        .cmp(&peek_non_blocking_time)
    {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        // blocking only if the queue is not the base queue
        std::cmp::Ordering::Equal => non_blocking_queue != Queue::Base,
    };
    debug!("\tpeek_queue_earliest_side: blocking_first={blocking_first}");
    if blocking_first {
        (
            peek_blocking
                .time
                .max(blocking_until)
                .duration_since(current_time),
            blocking_queue,
            is_client,
        )
    } else {
        (
            peek_non_blocking_time.duration_since(current_time),
            non_blocking_queue,
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
    blocking_c: Option<Instant>,
    blocking_s: Option<Instant>,
    current_time: Instant,
) -> (Duration, bool) {
    match (blocking_c, blocking_s) {
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
