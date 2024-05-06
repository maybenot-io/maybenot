//! A simulator for the Maybenot framework. The [`Maybenot`](maybenot) framework
//! is intended for traffic analysis defenses that can be used to hide patterns
//! in encrypted communication. The goal of the simulator is to assist in the
//! development of such defenses.
//!
//! The simulator consists of two core functions: [`parse_trace`] and [`sim`].
//! The intended use is to first parse a trace (e.g., from a pcap file or a
//! Website Fingerprinting dataset) using [`parse_trace`], and then simulate the
//! trace using [`sim`] together with one or more Maybenot
//! [`Machines`](maybenot::machine::Machine) running at the client and/or
//! server. The output of the simulator can then be parsed to produce a
//! simulated trace that then in turn can be used to, e.g., train a Website
//! Fingerprinting attack.
//!
//! ## Example usage
//! ```
//! use maybenot::{framework::TriggerEvent, machine::Machine};
//! use maybenot_simulator::{parse_trace, network::Network, sim};
//! use std::{str::FromStr, time::Duration};
//!
//! // A trace of ten packets from the client's perspective when visiting
//! // google.com over WireGuard. The format is: "time,direction,size\n". The
//! // direction is either "s" (sent) or "r" (received). The time is in
//! // nanoseconds since the start of the trace. The size is in bytes.
//! let raw_trace = "0,s,52
//! 19714282,r,52
//! 183976147,s,52
//! 243699564,r,52
//! 1696037773,s,40
//! 2047985926,s,52
//! 2055955094,r,52
//! 9401039609,s,73
//! 9401094589,s,73
//! 9420892765,r,191";
//!
//! // The network model for simulating the network between the client and the
//! // server. Currently just a delay.
//! let network = Network::new(Duration::from_millis(10));
//!
//! // Parse the raw trace into a queue of events for the simulator. This uses
//! // the delay to generate a queue of events at the client and server in such
//! // a way that the client is ensured to get the packets in the same order and
//! // at the same time as in the raw trace.
//! let mut input_trace = parse_trace(raw_trace, &network);
//!
//! // A simple machine that sends one padding packet of 1000 bytes 20
//! // milliseconds after the first NonPaddingSent is sent.
//! let m = "789cedcfc10900200805506d82b6688c1caf5bc3b54823f4a1a2a453b7021ff8ff49\
//! 41261f685323426187f8d3f9cceb18039205b9facab8914adf9d6d9406142f07f0";
//! let m = Machine::from_str(m).unwrap();
//!
//! // Run the simulator with the machine at the client. Run the simulation up
//! // until 100 packets have been recorded (total, client and server).
//! let trace = sim(&[m], &[], &mut input_trace, network.delay, 100, true);
//!
//! // print packets from the client's perspective
//! let starting_time = trace[0].time;
//! trace
//!     .into_iter()
//!     .filter(|p| p.client)
//!     .for_each(|p| match p.event {
//!         TriggerEvent::NonPaddingSent { bytes_sent } => {
//!             println!(
//!                 "sent {} bytes at {} ms",
//!                 bytes_sent,
//!                 (p.time - starting_time).as_millis()
//!             );
//!         }
//!         TriggerEvent::PaddingSent { bytes_sent, .. } => {
//!             println!(
//!                 "sent {} bytes of padding at {} ms",
//!                 bytes_sent,
//!                 (p.time - starting_time).as_millis()
//!             );
//!         }
//!         TriggerEvent::NonPaddingRecv { bytes_recv } => {
//!             println!(
//!                 "received {} bytes at {} ms",
//!                 bytes_recv,
//!                 (p.time - starting_time).as_millis()
//!             );
//!         }
//!         TriggerEvent::PaddingRecv { bytes_recv, .. } => {
//!             println!(
//!                 "received {} bytes of padding at {} ms",
//!                 bytes_recv,
//!                 (p.time - starting_time).as_millis()
//!             );
//!         }
//!         _ => {}
//!     });
//!
//! ```
//!  Prints the following output:
//! ```text
//! sent 52 bytes at 0 ms
//! received 52 bytes at 19 ms
//! sent 1000 bytes of padding at 20 ms
//! sent 52 bytes at 183 ms
//! received 52 bytes at 243 ms
//! sent 40 bytes at 1696 ms
//! sent 52 bytes at 2047 ms
//! received 52 bytes at 2055 ms
//! sent 73 bytes at 9401 ms
//! sent 73 bytes at 9401 ms
//! received 191 bytes at 9420 ms
//! ```

pub mod integration;
pub mod network;
pub mod peek;
pub mod queue;

use std::{
    cmp::Reverse,
    collections::HashMap,
    time::{Duration, Instant},
};

use integration::Integration;
use log::debug;
use network::Network;
use queue::SimQueue;

use maybenot::{
    framework::{Action, Framework, MachineId, TriggerEvent},
    machine::Machine,
};

use crate::{
    network::sim_network_activity,
    peek::{peek_blocked_exp, peek_queue, peek_scheduled},
};

/// SimEvent represents an event in the simulator. It is used internally to
/// represent events that are to be processed by the simulator (in SimQueue) and
/// events that are produced by the simulator (the resulting trace).
#[derive(PartialEq, Hash, Eq, Clone, Debug)]
pub struct SimEvent {
    pub event: TriggerEvent,
    pub time: Instant,
    pub delay: Duration,
    pub client: bool,
    // internal flag to mark event as bypass
    bypass: bool,
    // internal flag to mark event as replace
    replace: bool,
    // prevents collisions in simulator queue (see remove() instead of pop())
    fuzz: i32,
}

/// ScheduledAction represents an action that is scheduled to be executed at a
/// certain time.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ScheduledAction {
    action: Option<Action>,
    time: Instant,
}

/// The state of the client or the server in the simulator.
pub struct SimState<M> {
    /// an instance of the Maybenot framework
    framework: Framework<M>,
    /// scheduled actions (timers)
    scheduled_action: HashMap<MachineId, ScheduledAction>,
    /// blocking time (active if in the future, relative to current_time)
    blocking_until: Instant,
    /// whether the active blocking bypassable or not
    blocking_bypassable: bool,
    /// time of the last sent packet
    last_sent_time: Instant,
    /// size of the last sent packet
    last_sent_size: u16,
    /// integration aspects for this state
    integration: Option<Integration>,
}

impl<M> SimState<M>
where
    M: AsRef<[Machine]>,
{
    pub fn new(
        machines: M,
        current_time: Instant,
        max_padding_frac: f64,
        max_blocking_frac: f64,
        mtu: u16,
        integration: Option<Integration>,
    ) -> Self {
        Self {
            framework: Framework::new(
                machines,
                max_padding_frac,
                max_blocking_frac,
                mtu,
                current_time,
            )
            .unwrap(),
            scheduled_action: HashMap::new(),
            // has to be in the past
            blocking_until: current_time.checked_sub(Duration::from_micros(1)).unwrap(),
            blocking_bypassable: false,
            // has to be far in the past
            last_sent_time: current_time
                .checked_sub(Duration::from_millis(1000))
                .unwrap(),
            last_sent_size: 0,
            integration,
        }
    }

    pub fn reporting_delay(&self) -> Duration {
        self.integration
            .as_ref()
            .map(|i| i.reporting_delay.sample())
            .unwrap_or(Duration::from_micros(0))
    }

    pub fn action_delay(&self) -> Duration {
        self.integration
            .as_ref()
            .map(|i| i.action_delay.sample())
            .unwrap_or(Duration::from_micros(0))
    }

    pub fn trigger_delay(&self) -> Duration {
        self.integration
            .as_ref()
            .map(|i| i.trigger_delay.sample())
            .unwrap_or(Duration::from_micros(0))
    }
}

/// The main simulator function.
///
/// Zero or more machines can concurrently be run on the client and server. The
/// machines can be different. The framework is designed to support many
/// machines.
///
/// The queue MUST have been created by [`parse_trace`] with the same delay. The
/// queue is modified by the simulator and should be re-created for each run of
/// the simulator or cloned.
///
/// If max_trace_length is > 0, the simulator will stop after max_trace_length
/// events have been *simulated* by the simulator and added to the simulating
/// output trace. Note that some machines may schedule infinite actions (e.g.,
/// schedule new padding after sending padding), so the simulator may never
/// stop. Use [`sim_advanced`] to set the maximum number of iterations to run
/// the simulator for and other advanced settings.
///
/// If only_network_activity is true, the simulator will only append events that
/// are related to network activity (i.e., packets sent and received) to the
/// output trace. This is recommended if you want to use the output trace for
/// traffic analysis without further (recursive) simulation.
pub fn sim(
    machines_client: &[Machine],
    machines_server: &[Machine],
    sq: &mut SimQueue,
    delay: Duration,
    max_trace_length: usize,
    only_network_activity: bool,
) -> Vec<SimEvent> {
    let network = Network::new(delay);
    let args = SimulatorArgs::new(&network, max_trace_length, only_network_activity);
    sim_advanced(machines_client, machines_server, sq, &args)
}

/// Arguments for [`sim_advanced`].
#[derive(Clone, Debug)]
pub struct SimulatorArgs<'a> {
    pub network: &'a Network,
    pub max_trace_length: usize,
    pub max_sim_iterations: usize,
    pub only_client_events: bool,
    pub only_network_activity: bool,
    pub max_padding_frac_client: f64,
    pub max_blocking_frac_client: f64,
    pub max_padding_frac_server: f64,
    pub max_blocking_frac_server: f64,
    pub mtu: u16,
    pub client_integration: Option<&'a Integration>,
    pub server_integration: Option<&'a Integration>,
}

impl<'a> SimulatorArgs<'a> {
    pub fn new(network: &'a Network, max_trace_length: usize, only_network_activity: bool) -> Self {
        Self {
            network,
            max_trace_length,
            max_sim_iterations: 0,
            only_client_events: false,
            only_network_activity,
            max_padding_frac_client: 0.0,
            max_blocking_frac_client: 0.0,
            max_padding_frac_server: 0.0,
            max_blocking_frac_server: 0.0,
            // WireGuard default MTU
            mtu: 1420,
            client_integration: None,
            server_integration: None,
        }
    }
}

/// Like [`sim`], but allows to (i) set the maximum padding and blocking
/// fractions for the client and server, (ii) specify the maximum number of
/// iterations to run the simulator for, and (iii) only returning client events.
pub fn sim_advanced(
    machines_client: &[Machine],
    machines_server: &[Machine],
    sq: &mut SimQueue,
    args: &SimulatorArgs,
) -> Vec<SimEvent> {
    // the resulting simulated trace
    let mut trace: Vec<SimEvent> = vec![];

    // put the mocked current time at the first event
    let mut current_time = sq.peek().unwrap().0.time;

    // the client and server states
    let mut client = SimState::new(
        machines_client,
        current_time,
        args.max_padding_frac_client,
        args.max_blocking_frac_client,
        args.mtu,
        args.client_integration.cloned(),
    );
    let mut server = SimState::new(
        machines_server,
        current_time,
        args.max_padding_frac_server,
        args.max_blocking_frac_server,
        args.mtu,
        args.server_integration.cloned(),
    );

    let mut sim_iterations = 0;
    let start_time = current_time;
    while let Some(next) = pick_next(sq, &mut client, &mut server, current_time) {
        debug!("#########################################################");
        debug!("sim(): main loop start, moving time forward");

        // move time forward
        if next.time < current_time {
            debug!("sim(): {:#?}", current_time);
            debug!("sim(): {:#?}", next.time);
            panic!("BUG: next event moves time backwards");
        }
        current_time = next.time;
        debug!(
            "sim(): at time {:#?}",
            current_time.duration_since(start_time)
        );
        if next.client {
            debug!("sim(): @client next\n{:#?}", next);
        } else {
            debug!("sim(): @server next\n{:#?}", next);
        }

        // if the client is blocked
        if client.blocking_until > current_time {
            debug!(
                "sim(): client is blocked until time {:#?}",
                client.blocking_until.duration_since(start_time)
            );
        }
        if server.blocking_until > current_time {
            debug!(
                "sim(): server is blocked until time {:#?}",
                server.blocking_until.duration_since(start_time)
            );
        }

        // For (non-)padding sent, queue the corresponding padding recv event:
        // in other words, where we simulate sending packets. The only place
        // where the simulator simulates the entire network between the client
        // and the server. TODO: make delay/network more realistic.
        let network_activity = if next.client {
            sim_network_activity(&next, sq, &client, &server, args.network, &current_time)
        } else {
            sim_network_activity(&next, sq, &server, &client, args.network, &current_time)
        };

        if network_activity {
            // update last packet stats in state
            match next.event {
                TriggerEvent::PaddingSent { bytes_sent, .. }
                | TriggerEvent::NonPaddingSent { bytes_sent } => {
                    if next.client {
                        client.last_sent_time = current_time;
                        client.last_sent_size = bytes_sent;
                    } else {
                        server.last_sent_time = current_time;
                        server.last_sent_size = bytes_sent;
                    }
                }
                _ => {}
            }
        }

        // get actions, update scheduled actions
        if next.client {
            debug!("sim(): trigger @client framework\n{:#?}", next.event);
            trigger_update(&mut client, &next, &current_time);
        } else {
            debug!("sim(): trigger @server framework\n{:#?}", next.event);
            trigger_update(&mut server, &next, &current_time);
        }

        // conditional save to resulting trace: only on network activity if set
        // in fn arg, and only on client activity if set in fn arg
        if (!args.only_network_activity || network_activity)
            && (!args.only_client_events || next.client)
        {
            // this should be a network trace: adjust timestamps based on any
            // integration delays
            let mut n = next.clone();
            match next.event {
                TriggerEvent::PaddingSent { .. } => {
                    // padding adds the action delay
                    n.time += n.delay;
                }
                TriggerEvent::PaddingRecv { .. }
                | TriggerEvent::NonPaddingRecv { .. }
                | TriggerEvent::NonPaddingSent { .. } => {
                    // reported events remove the reporting delay
                    n.time -= n.delay;
                }
                _ => {}
            }

            trace.push(n);
        }

        if args.max_trace_length > 0 && trace.len() >= args.max_trace_length {
            debug!(
                "sim(): we done, reached max trace length {}",
                args.max_trace_length
            );
            break;
        }

        // check if we should stop
        sim_iterations += 1;
        if args.max_sim_iterations > 0 && sim_iterations >= args.max_sim_iterations {
            debug!(
                "sim(): we done, reached max sim iterations {}",
                args.max_sim_iterations
            );
            break;
        }

        debug!("sim(): main loop end, more work?");
        debug!("#########################################################");
    }

    // sort the trace by time
    trace.sort_by(|a, b| a.time.cmp(&b.time));

    trace
}

fn pick_next<M: AsRef<[Machine]>>(
    sq: &mut SimQueue,
    client: &mut SimState<M>,
    server: &mut SimState<M>,
    current_time: Instant,
) -> Option<SimEvent> {
    // find the earliest scheduled, blocked, and queued events to determine the
    // next event
    let s = peek_scheduled(
        &client.scheduled_action,
        &server.scheduled_action,
        current_time,
    );
    debug!("\tpick_next(): peek_scheduled = {:?}", s);
    let b = peek_blocked_exp(&client.blocking_until, &server.blocking_until, current_time);
    debug!("\tpick_next(): peek_blocked_exp = {:?}", b);
    let (q, q_peek) = peek_queue(sq, client, server, s.min(b), current_time);
    debug!("\tpick_next(): peek_queue = {:?}", q);

    // no next?
    if s == Duration::MAX && b == Duration::MAX && q == Duration::MAX {
        return None;
    }

    // We prioritize the queue: in general, stuff happens faster outside the
    // framework than inside it. On overload, the user of the framework will
    // bulk trigger events in the framework.
    if q <= s && q <= b {
        debug!("\tpick_next(): picked queue");
        sq.remove(q_peek.as_ref().unwrap());

        // check if blocking moves the event forward in time
        let mut tmp = q_peek.unwrap();
        if current_time + q > tmp.time {
            tmp.time = current_time + q;
        }
        return Some(tmp);
    }

    // next is blocking expiry, happens outside of framework, so probably faster
    // than framework
    if b <= s {
        debug!("\tpick_next(): picked blocking");
        // create SimEvent and move blocking into (what soon will be) the past
        // to indicate that it has been processed
        let time: Instant;
        // ASSUMPTION: block outgoing is reported from integration
        let delay: Duration;
        let client_earliest =
            if client.blocking_until >= current_time && server.blocking_until >= current_time {
                client.blocking_until <= server.blocking_until
            } else {
                client.blocking_until >= current_time
            };

        if client_earliest {
            delay = client.reporting_delay();
            time = client.blocking_until + delay;
            client.blocking_until -= Duration::from_micros(1);
        } else {
            delay = server.reporting_delay();
            time = server.blocking_until + delay;
            server.blocking_until -= Duration::from_micros(1);
        }

        return Some(SimEvent {
            client: client_earliest,
            event: TriggerEvent::BlockingEnd,
            time,
            delay,
            fuzz: fastrand::i32(..),
            bypass: false,
            replace: false,
        });
    }

    // what's left is scheduled actions: find the action act on the action,
    // putting the event into the sim queue, and then recurse
    debug!("\tpick_next(): picked scheduled");
    let target = current_time + s;
    let act = do_scheduled(client, server, current_time, target);
    if let Some(a) = act {
        sq.push_sim(a.clone(), Reverse(a.time));
    }
    pick_next(sq, client, server, current_time)
}

fn do_scheduled<M: AsRef<[Machine]>>(
    client: &mut SimState<M>,
    server: &mut SimState<M>,
    current_time: Instant,
    target: Instant,
) -> Option<SimEvent> {
    // find the action
    let mut a = ScheduledAction {
        action: None,
        time: current_time,
    };
    let mut a_is_client = false;
    let mut a_is_found = false;

    client.scheduled_action.retain(|&_mi, sa| {
        if !a_is_found && sa.action.is_some() && sa.time == target {
            a = sa.clone();
            a_is_client = true;
            a_is_found = true;
            return false;
        };
        true
    });

    // cannot schedule a None action, so if we found one, done
    if a.action.is_none() {
        server.scheduled_action.retain(|&_mi, sa| {
            if !a_is_found && sa.action.is_some() && sa.time == target {
                a = sa.clone();
                a_is_client = false;
                a_is_found = true;
                return false;
            };
            true
        });
    }

    // no action found
    assert!(a_is_found, "BUG: no action found");

    // do the action
    match a.action? {
        Action::Cancel { .. } => {
            // by being selected we set the action to None already
            None
        }
        Action::InjectPadding {
            timeout: _,
            size,
            bypass,
            replace,
            machine,
        } => {
            let action_delay = if a_is_client {
                client.action_delay()
            } else {
                server.action_delay()
            };

            Some(SimEvent {
                event: TriggerEvent::PaddingSent {
                    bytes_sent: size,
                    machine,
                },
                time: a.time,
                delay: action_delay,
                client: a_is_client,
                bypass,
                replace,
                fuzz: fastrand::i32(..),
            })
        }
        Action::BlockOutgoing {
            timeout: _,
            duration,
            bypass,
            replace,
            machine,
        } => {
            let block = a.time + duration;
            let event_bypass;
            // ASSUMPTION: block outgoing reported from integration
            let total_delay = if a_is_client {
                client.action_delay() + client.reporting_delay()
            } else {
                server.action_delay() + server.reporting_delay()
            };
            let reported = a.time + total_delay;

            // should we update client/server blocking?
            if a_is_client {
                if replace || block > client.blocking_until {
                    client.blocking_until = block;
                    client.blocking_bypassable = bypass;
                }
                event_bypass = client.blocking_bypassable;
            } else {
                if replace || block > server.blocking_until {
                    server.blocking_until = block;
                    server.blocking_bypassable = bypass;
                }
                event_bypass = server.blocking_bypassable;
            }

            // event triggered regardless
            Some(SimEvent {
                event: TriggerEvent::BlockingBegin { machine },
                time: reported,
                delay: total_delay,
                client: a_is_client,
                bypass: event_bypass,
                replace: false,
                fuzz: fastrand::i32(..),
            })
        }
    }
}

fn trigger_update<M: AsRef<[Machine]>>(
    state: &mut SimState<M>,
    next: &SimEvent,
    current_time: &Instant,
) {
    let trigger_delay = state.trigger_delay();

    // parse actions and update
    for action in state
        .framework
        .trigger_events(&[next.event.clone()], *current_time)
    {
        match action {
            Action::Cancel { machine } => {
                state.scheduled_action.insert(
                    *machine,
                    ScheduledAction {
                        action: Some(action.clone()),
                        time: *current_time + trigger_delay,
                    },
                );
            }
            Action::InjectPadding {
                timeout,
                size: _,
                bypass: _,
                replace: _,
                machine,
            } => {
                state.scheduled_action.insert(
                    *machine,
                    ScheduledAction {
                        action: Some(action.clone()),
                        time: *current_time + *timeout + trigger_delay,
                    },
                );
            }
            Action::BlockOutgoing {
                timeout,
                duration: _,
                bypass: _,
                replace: _,
                machine,
            } => {
                state.scheduled_action.insert(
                    *machine,
                    ScheduledAction {
                        action: Some(action.clone()),
                        time: *current_time + *timeout + trigger_delay,
                    },
                );
            }
        };
    }
}

/// Parse a trace into a [`SimQueue`] for use with [`sim`].
///
/// The trace should contain one or more lines of the form
/// "time,direction,size\n", where time is in nanoseconds relative to the first
/// line, direction is either "s" for sent or "r" for received, and size is the
/// number of bytes sent or received. The delay is used to model the network
/// delay between the client and server. Returns a SimQueue with the events in
/// the trace for use with [`sim`].

pub fn parse_trace(trace: &str, network: &Network) -> SimQueue {
    parse_trace_advanced(trace, network, None, None)
}

pub fn parse_trace_advanced(
    trace: &str,
    network: &Network,
    client: Option<&Integration>,
    server: Option<&Integration>,
) -> SimQueue {
    let mut sq = SimQueue::new();

    // we just need a random starting time to make sure that we don't start from
    // absolute 0
    let starting_time = Instant::now();

    for l in trace.lines() {
        let parts: Vec<&str> = l.split(',').collect();
        if parts.len() == 3 {
            let timestamp =
                starting_time + Duration::from_nanos(parts[0].trim().parse::<u64>().unwrap());
            let size = parts[2].trim().parse::<u64>().unwrap();

            match parts[1] {
                "s" | "sn" => {
                    // client sent at the given time
                    let reporting_delay = client
                        .map(|i| i.reporting_delay.sample())
                        .unwrap_or(Duration::from_micros(0));
                    let reported = timestamp + reporting_delay;
                    sq.push(
                        TriggerEvent::NonPaddingSent {
                            bytes_sent: size as u16,
                        },
                        true,
                        reported,
                        reporting_delay,
                        Reverse(reported),
                    );
                }
                "r" | "rn" => {
                    // sent by server delay time ago
                    let sent = timestamp.checked_sub(network.delay).unwrap();
                    // but reported to the Maybenot framework at the server with delay
                    let reporting_delay = server
                        .map(|i| i.reporting_delay.sample())
                        .unwrap_or(Duration::from_micros(0));
                    let reported = sent + reporting_delay;
                    sq.push(
                        TriggerEvent::NonPaddingSent {
                            bytes_sent: size as u16,
                        },
                        false,
                        reported,
                        reporting_delay,
                        Reverse(reported),
                    );
                }
                "sp" | "rp" => {
                    // TODO: figure out of ignoring is the right thing to do
                }
                _ => {
                    panic!("invalid direction")
                }
            }
        }
    }

    sq
}
