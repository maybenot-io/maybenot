//! Functions for peeking at the possible next events in the simulation.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use maybenot::{event::Event, Machine, MachineId};

use crate::{queue::SimQueue, RngSource, ScheduledAction, SimEvent, SimState};

pub(crate) fn peek_queue<M: AsRef<[Machine]>>(
    sq: &mut SimQueue,
    client: &mut SimState<M, RngSource>,
    server: &mut SimState<M, RngSource>,
    earliest: Duration,
    current_time: Instant,
) -> (Duration, Option<SimEvent>) {
    // easy: no queue to consider
    if sq.is_empty() {
        return (Duration::MAX, None);
    }
    let peek = sq.peek().unwrap().0.clone();

    // easy: non-blocking event first
    if !peek.event.is_event(Event::TunnelSent) {
        return (peek.time.duration_since(current_time), Some(peek));
    }

    let client_blocking = client.blocking_until > current_time;
    let server_blocking = server.blocking_until > current_time;

    // easy: no active blocking to consider
    if !client_blocking && !server_blocking {
        return (peek.time.duration_since(current_time), Some(peek));
    }

    // lucky: peek not blocked means it's earliest
    if (peek.client && !client_blocking) || (!peek.client && !server_blocking) {
        return (peek.time.duration_since(current_time), Some(peek));
    }

    // another way out: if the earliest peeked is *after* the earliest found by
    // peek_scheduled() and peek_blocked_exp(), then looking further is
    // pointless as far as pick_next() is concerned (note that this is OK
    // because blocking can only delay any event further)
    if peek.time.duration_since(current_time) > earliest {
        return (Duration::MAX, None);
    }

    // peek is blocked but the event is padding that should bypass blocking AND
    // the blocking is bypassable
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
        return (peek.time.duration_since(current_time), Some(peek));
    }

    // not lucky, things get ugly...we have to consider both sides: find
    // earliest client and server
    let (e_client_d, e_client_e) = peek_queue_earliest_side(
        sq,
        &client.blocking_until,
        client.blocking_bypassable,
        current_time,
        true,
    );
    let (e_server_d, e_server_e) = peek_queue_earliest_side(
        sq,
        &server.blocking_until,
        server.blocking_bypassable,
        current_time,
        false,
    );

    // pick earliest
    if e_client_d <= e_server_d {
        (e_client_d, e_client_e)
    } else {
        (e_server_d, e_server_e)
    }
}

// Here be dragons: surprisingly annoying function to get right and fast.
// Closely tied to how SimQueue is implemented.
fn peek_queue_earliest_side(
    sq: &mut SimQueue,
    blocking_until: &Instant,
    blocking_bypassable: bool,
    current_time: Instant,
    is_client: bool,
) -> (Duration, Option<SimEvent>) {
    // OK, bummer, we have to peek for the next blocking and non-blocking: note
    // that this takes into account if blocking is bypassable or not, picking the
    // earliest next event from the queue.
    let peek_blocking = sq
        .peek_blocking(blocking_bypassable, is_client)
        .map(|(e, _)| e.clone());
    let peek_non_blocking = sq
        .peek_non_blocking(blocking_bypassable, is_client)
        .map(|(e, _)| e.clone());

    // easy: no events to consider
    if peek_blocking.is_none() && peek_non_blocking.is_none() {
        return (Duration::MAX, None);
    }

    // easy: only one event to consider
    if peek_blocking.is_none() {
        return (
            peek_non_blocking
                .as_ref()
                .unwrap()
                .time
                .duration_since(current_time),
            peek_non_blocking,
        );
    }
    if peek_non_blocking.is_none() {
        return (
            peek_blocking
                .as_ref()
                .unwrap()
                .time
                .max(*blocking_until)
                .duration_since(current_time),
            peek_blocking,
        );
    }

    // consider both events, taking blocking into account
    let pb = peek_blocking.as_ref().unwrap();
    let pn = peek_non_blocking.as_ref().unwrap();
    if pb.time.max(*blocking_until) <= pn.time {
        (
            pb.time.max(*blocking_until).duration_since(current_time),
            peek_blocking,
        )
    } else {
        (pn.time.duration_since(current_time), peek_non_blocking)
    }
}

pub fn peek_scheduled(
    scheduled_c: &HashMap<MachineId, Option<ScheduledAction>>,
    scheduled_s: &HashMap<MachineId, Option<ScheduledAction>>,
    current_time: Instant,
) -> Duration {
    // there are at most one scheduled action per machine, so we can just
    // iterate over all of them quickly
    let mut earliest = Duration::MAX;

    for a in scheduled_c.values().flatten() {
        if a.time >= current_time && a.time.duration_since(current_time) < earliest {
            earliest = a.time.duration_since(current_time);
        }
    }
    for a in scheduled_s.values().flatten() {
        if a.time >= current_time && a.time.duration_since(current_time) < earliest {
            earliest = a.time.duration_since(current_time);
        }
    }

    earliest
}

pub fn peek_internal(
    internal_c: &HashMap<MachineId, Option<Instant>>,
    internal_s: &HashMap<MachineId, Option<Instant>>,
    current_time: Instant,
) -> Duration {
    // there are at most one internal event per machine, so we can just
    // iterate over all of them quickly
    let mut earliest = Duration::MAX;

    for t in internal_c.values().flatten() {
        if *t >= current_time && t.duration_since(current_time) < earliest {
            earliest = t.duration_since(current_time);
        }
    }
    for t in internal_s.values().flatten() {
        if *t >= current_time && t.duration_since(current_time) < earliest {
            earliest = t.duration_since(current_time);
        }
    }

    earliest
}

pub fn peek_blocked_exp(
    blocking_c: &Instant,
    blocking_s: &Instant,
    current_time: Instant,
) -> Duration {
    // no blocking?
    if current_time > *blocking_c && current_time > *blocking_s {
        return Duration::MAX;
    }
    // blocking on both sides?
    if *blocking_c >= current_time && *blocking_s >= current_time {
        // pick the blocking that'll end first
        return (*blocking_s.min(blocking_c)).duration_since(current_time);
    }
    // blocking on one side: the max timer is the one that's actually blocking
    (*blocking_s.max(blocking_c)).duration_since(current_time)
}
