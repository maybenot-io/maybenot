use crate::topology::NetworkTopology;
use crate::topology::maybenot_nodes::MaybenotNode;
use crate::topology::maybenot_nodes::{ActionProducer, MaybenotState, ScheduledAction};
use crate::{SimEvent, SimInfo, SimQueue, SimTime, SimulatorArgs};
use log::debug;
use maybenot::{Machine, Timer, TriggerAction, TriggerEvent};
use std::time::Duration;

/// Initialize Maybenot nodes with MaybenotState for simulation
pub fn initialize_maybenot_sim_states(
    topology: &NetworkTopology,
    machines_client: &[Machine],
    machines_server: &[Machine],
    current_time: Duration,
    args: &SimulatorArgs,
) {
    // Initialize Maybenot client-node using trait abstraction
    let client: &dyn MaybenotNode = topology.get_maybenot_client();
    let new_state = MaybenotState::new(
        machines_client.to_vec(),
        current_time,
        &args.decoy_limit_client,
        &args.delay_limit_client,
        args.drain_delayed_by_time,
        args.client_integration.clone(),
        args.insecure_rng_seed,
    );
    *client.get_sim_state().borrow_mut() = new_state;

    // Initialize Maybenot relay-node using trait abstraction
    let relay: &dyn MaybenotNode = topology.get_maybenot_relay();
    let new_state = MaybenotState::new(
        machines_server.to_vec(),
        current_time,
        &args.decoy_limit_server,
        &args.delay_limit_server,
        args.drain_delayed_by_time,
        args.server_integration.clone(),
        // if we have an insecure seed, we use the next number in the sequence
        // to avoid the same seed for both client and relay
        args.insecure_rng_seed.map(|seed| seed.wrapping_add(1)),
    );
    *relay.get_sim_state().borrow_mut() = new_state;
}

/// Initialize the Maybenot client/server nodes with caller-supplied
/// [`ActionProducer`]s instead of building a [`maybenot::Framework`]
/// internally. The simulator's scheduler, delay machinery, and integration
/// delays operate identically regardless of which producer is in use.
pub fn initialize_user_provided_sim_states(
    topology: &NetworkTopology,
    client_producer: Box<dyn ActionProducer>,
    server_producer: Box<dyn ActionProducer>,
    args: &SimulatorArgs,
) {
    let client: &dyn MaybenotNode = topology.get_maybenot_client();
    *client.get_sim_state().borrow_mut() = MaybenotState::with_producer(
        client_producer,
        args.drain_delayed_by_time,
        args.client_integration.clone(),
        args.insecure_rng_seed,
    );

    let relay: &dyn MaybenotNode = topology.get_maybenot_relay();
    *relay.get_sim_state().borrow_mut() = MaybenotState::with_producer(
        server_producer,
        args.drain_delayed_by_time,
        args.server_integration.clone(),
        args.insecure_rng_seed.map(|seed| seed.wrapping_add(1)),
    );
}

// Advanced event scheduling for Maybenot machines.
//
// This function implements the core scheduling algorithm that coordinates:
// 1. Network packet events from the simulation queue
// 2. Maybenot machine scheduled actions (decoy/delay)
// 3. Maybenot machine internal timers
// 4. Delay period expiry events
pub fn pick_next_maybenot(
    si: &SimInfo,
    sq: &mut SimQueue,
    topology: &NetworkTopology,
    current_time: Duration,
) -> Option<SimEvent> {
    let client_maybenot = topology.get_maybenot_client();
    let relay_maybenot = topology.get_maybenot_relay();

    // Read the cached minimums from both Maybenot nodes. These are O(1)
    // lookups — the `scheduled_action` / `scheduled_internal_timer` vectors
    // maintain their per-node min via the setter/clear helpers so we never
    // scan all machine slots on the main-loop fast path.
    let mut min_scheduled_action = Duration::MAX;
    let mut action_node = client_maybenot;
    let mut min_internal_timer = Duration::MAX;
    let mut timer_node = client_maybenot;

    let state = client_maybenot.get_sim_state().borrow();
    if let Some((t, _)) = state.peek_min_scheduled_action()
        && t >= current_time
    {
        min_scheduled_action = t - current_time;
    }
    if let Some((t, _)) = state.peek_min_scheduled_internal_timer()
        && t >= current_time
    {
        min_internal_timer = t - current_time;
    }
    let client_delay_until = state.delay_until;
    drop(state);

    let state = relay_maybenot.get_sim_state().borrow();
    if let Some((t, _)) = state.peek_min_scheduled_action()
        && t >= current_time
    {
        let duration = t - current_time;
        if duration < min_scheduled_action {
            min_scheduled_action = duration;
            action_node = relay_maybenot;
        }
    }
    if let Some((t, _)) = state.peek_min_scheduled_internal_timer()
        && t >= current_time
    {
        let duration = t - current_time;
        if duration < min_internal_timer {
            min_internal_timer = duration;
            timer_node = relay_maybenot;
        }
    }
    let server_delay_until = state.delay_until;
    drop(state);

    // Check delay expiry
    let (min_delay, delay_is_client) = match (client_delay_until, server_delay_until) {
        (Some(c), Some(s)) => {
            if c < s {
                (c.saturating_sub(current_time), true)
            } else {
                (s.saturating_sub(current_time), false)
            }
        }
        (Some(c), None) => (c.saturating_sub(current_time), true),
        (None, Some(s)) => (s.saturating_sub(current_time), false),
        (None, None) => (Duration::MAX, true),
    };

    // Check queue
    let queue_next = sq.peek();
    let queue_duration = match queue_next {
        Some(event) => event.time.saturating_sub(current_time),
        None => Duration::MAX,
    };

    // Debug output
    if min_scheduled_action == Duration::MAX {
        debug!("\tpick_next(): peek_scheduled_action = None");
    } else {
        debug!(
            "\tpick_next(): peek_scheduled_action = {:?}",
            min_scheduled_action
        );
    }

    if min_internal_timer == Duration::MAX {
        debug!("\tpick_next(): peek_scheduled_internal_timer = None");
    } else {
        debug!(
            "\tpick_next(): peek_scheduled_internal_timer = {:?}",
            min_internal_timer
        );
    }

    if min_delay == Duration::MAX {
        debug!("\tpick_next(): peek_delay_exp = None");
    } else {
        debug!("\tpick_next(): peek_delay_exp = {:?}", min_delay);
    }

    if queue_duration == Duration::MAX {
        debug!("\tpick_next(): peek_queue = None");
    } else {
        debug!(
            "\tpick_next(): peek_queue = {}",
            queue_next.unwrap().display_relative(si)
        );
    }

    // No next event?
    if min_scheduled_action == Duration::MAX
        && min_internal_timer == Duration::MAX
        && min_delay == Duration::MAX
        && queue_duration == Duration::MAX
    {
        return None;
    }

    // Pick the earliest event

    // Delay expiry is earliest
    if min_delay <= min_scheduled_action
        && min_delay <= min_internal_timer
        && min_delay <= queue_duration
    {
        debug!("\tpick_next(): picked delay");

        // Clear delay state from the appropriate node
        let node_state = if delay_is_client {
            client_maybenot.get_sim_state()
        } else {
            relay_maybenot.get_sim_state()
        };
        {
            let mut s = node_state.borrow_mut();
            s.delay_until = None;
            s.delay_max_packets = None;
        }

        let e = SimEvent {
            event: TriggerEvent::DelayEnd,
            time: current_time + min_delay,
            packet_id: usize::MAX,
            node_id: if delay_is_client {
                topology.mb_client
            } else {
                topology.mb_server
            },
            link_id: if delay_is_client {
                topology.nodes[topology.mb_client].get_coreside_out_id()
            } else {
                topology.nodes[topology.mb_server].get_edgeside_out_id()
            },
            bypass: false,
            replace: false,
            contains_decoy: false,
            is_client: false,
            q_sequence_nr: 0,
            #[cfg(debug_assertions)]
            debug_note: None,
        };
        return Some(e);
    }

    // Queue is next
    if queue_duration <= min_scheduled_action && queue_duration <= min_internal_timer {
        debug!("\tpick_next(): picked queue");
        return sq.pop();
    }

    // Internal timer is next
    if min_internal_timer <= min_scheduled_action {
        debug!("\tpick_next(): picked internal timer");
        let target_time = current_time + min_internal_timer;

        if let Some(event) = timer_node.do_internal_timer(target_time) {
            return Some(event);
        }
    }

    // Scheduled action is last (note, can None)
    debug!("\tpick_next(): picked scheduled action");
    let target_time = current_time + min_scheduled_action;
    action_node.do_scheduled_action(target_time, sq)
}

// Generic helper functions for Maybenot operations
pub fn maybenot_trigger_update<T: MaybenotNode>(
    node: &T,
    s_event: &SimEvent,
    current_time: &Duration,
    sq: &mut SimQueue,
    _topology: &NetworkTopology,
) {
    let node_id = node.node_id();
    let link_id = node.get_action_link_id();

    // Collect actions from the producer with a scoped borrow so we can
    // re-borrow `state` mutably below when scheduling each action.
    let actions: Vec<_> = {
        let mut state = node.get_sim_state().borrow_mut();
        state
            .action_producer
            .trigger_events(std::slice::from_ref(&s_event.event), SimTime(*current_time))
    };

    // Now process actions with a fresh borrow
    for action in actions {
        let mut state = node.get_sim_state().borrow_mut();
        let trigger_delay = state.trigger_delay();
        match action {
            TriggerAction::Cancel { machine, timer } => {
                debug!(
                    "\ttrigger_update(): cancel action {:?} {:?}",
                    machine, timer
                );
                // here we make a simplifying assumption of no trigger delay for
                // cancel actions
                match timer {
                    Timer::Action => {
                        state.clear_scheduled_action(machine);
                    }
                    Timer::Internal => {
                        state.clear_scheduled_internal_timer(machine);
                    }
                    Timer::All => {
                        state.clear_scheduled_action(machine);
                        state.clear_scheduled_internal_timer(machine);
                    }
                }
            }
            TriggerAction::DecoyTraffic {
                timeout, machine, ..
            } => {
                debug!(
                    "\ttrigger_update(): decoy traffic action {:?} {:?}",
                    timeout, machine
                );
                let time = *current_time + timeout + trigger_delay;
                state.set_scheduled_action(
                    machine,
                    ScheduledAction {
                        action: action.clone(),
                        time,
                    },
                );
            }
            TriggerAction::DelayTraffic {
                timeout, machine, ..
            } => {
                debug!(
                    "\ttrigger_update(): delay traffic action {:?} {:?}",
                    timeout, machine
                );
                let time = *current_time + timeout + trigger_delay;
                state.set_scheduled_action(
                    machine,
                    ScheduledAction {
                        action: action.clone(),
                        time,
                    },
                );
            }
            TriggerAction::UpdateTimer {
                duration,
                replace,
                machine,
            } => {
                debug!(
                    "\ttrigger_update(): update timer action {:?} {:?}",
                    duration, machine
                );
                // get current internal timer duration, if any
                let current = state
                    .get_scheduled_internal_timer(machine)
                    .unwrap_or(*current_time);

                // update the timer
                if replace || current < *current_time + duration {
                    state.set_scheduled_internal_timer(machine, *current_time + duration);
                    // TimerBegin event
                    sq.push(SimEvent {
                        event: TriggerEvent::TimerBegin { machine },
                        time: *current_time,
                        packet_id: usize::MAX,
                        node_id,
                        link_id,
                        bypass: false,
                        replace: false,
                        contains_decoy: false,
                        is_client: false,
                        q_sequence_nr: 0,
                        #[cfg(debug_assertions)]
                        debug_note: None,
                    });
                }
            }
        }
    }
}

pub fn maybenot_do_internal_timer<T: MaybenotNode>(node: &T, target: Duration) -> Option<SimEvent> {
    let mut state = node.get_sim_state().borrow_mut();
    // `pick_next_maybenot` already identified this node as owning the earliest
    // internal timer; we consume it directly instead of rescanning the slot
    // vector.
    let (machine, time) = state.take_min_scheduled_internal_timer()?;
    debug_assert_eq!(
        time, target,
        "internal timer min drifted from caller target"
    );

    Some(SimEvent {
        event: TriggerEvent::TimerEnd { machine },
        time,
        packet_id: usize::MAX,
        node_id: node.node_id(),
        link_id: node.get_action_link_id(),
        bypass: false,
        replace: false,
        contains_decoy: false,
        is_client: false,
        q_sequence_nr: 0,
        #[cfg(debug_assertions)]
        debug_note: None,
    })
}

pub fn maybenot_do_scheduled_action<T: MaybenotNode>(
    node: &T,
    target: Duration,
    sq: &mut SimQueue,
) -> Option<SimEvent> {
    let mut state = node.get_sim_state().borrow_mut();
    // Mirror of `maybenot_do_internal_timer`: `pick_next_maybenot` picked this
    // node because its cached min matches `target`, so we consume that entry
    // directly instead of rescanning.
    let (_machine, action) = state.take_min_scheduled_action()?;
    debug_assert_eq!(
        action.time, target,
        "scheduled action min drifted from caller target"
    );

    match action.action {
        TriggerAction::Cancel { .. } => {
            panic!("BUG: cancel action in scheduled action");
        }
        TriggerAction::UpdateTimer { .. } => {
            panic!("BUG: update timer action in scheduled action");
        }
        TriggerAction::DecoyTraffic {
            timeout: _,
            n,
            bypass,
            replace,
            machine,
        } => {
            if n == 0 {
                return None;
            }

            let node_id = node.node_id();
            let link_id = node.get_action_link_id();
            // all N decoys get the same action delay, such that they all happen
            // at the same time internally in the integration
            let action_delay = state.action_delay();

            let make_event = || SimEvent {
                event: TriggerEvent::DecoyQueued { machine },
                time: action.time + action_delay,
                packet_id: usize::MAX,
                node_id,
                link_id,
                bypass,
                replace,
                contains_decoy: true,
                is_client: false,
                q_sequence_nr: 0,
                #[cfg(debug_assertions)]
                debug_note: None,
            };

            // Push the extra N-1 decoy events onto the simulation queue so they
            // are processed with deterministic ordering; return the first event
            // directly so the main loop treats it like any other picked event.
            for _ in 1..n {
                sq.push(make_event());
            }

            Some(make_event())
        }
        TriggerAction::DelayTraffic {
            timeout: _,
            n,
            duration,
            bypass,
            replace,
            machine,
        } => {
            let new_delay_until = action.time + duration;

            if replace {
                state.delay_until = Some(new_delay_until);
                state.delay_max_packets = if n == 0 { None } else { Some(n) };
                state.delay_bypassable = bypass;
            } else {
                // take the max of the duration end and N-cap independently,
                // update bypass only if something is updated
                let current_end = state.delay_until.unwrap_or(action.time);
                if new_delay_until > current_end {
                    state.delay_until = Some(new_delay_until);
                    state.delay_bypassable = bypass;
                }
                if n > 0 {
                    let current_n = state.delay_max_packets.unwrap_or(0);
                    if n > current_n {
                        state.delay_max_packets = Some(n);
                        state.delay_bypassable = bypass;
                    }
                }
            }
            let event_bypass = state.delay_bypassable;

            Some(SimEvent {
                event: TriggerEvent::DelayBegin { machine },
                time: action.time + state.action_delay() + state.reporting_delay(),
                packet_id: usize::MAX,
                node_id: node.node_id(),
                link_id: node.get_action_link_id(),
                bypass: event_bypass,
                replace: false,
                contains_decoy: false,
                is_client: false,
                q_sequence_nr: 0,
                #[cfg(debug_assertions)]
                debug_note: None,
            })
        }
    }
}
