//! A simulator for the Maybenot framework. The [`Maybenot`](maybenot) framework
//! is intended for traffic analysis defenses that can be used to hide patterns
//! in encrypted communication. The goal of the simulator is to assist in the
//! development of such defenses.
//!
//! The simulator consists of two core functions: [`parse_trace`] and [`sim`].
//! The intended use is to first parse a trace (e.g., from a pcap file or a
//! Website Fingerprinting dataset) using [`parse_trace`], and then simulate the
//! trace using [`sim`] together with one or more Maybenot
//! [`Machines`](maybenot::Machine) running at the client and/or
//! server. The output of the simulator can then be parsed to produce a
//! simulated trace that then in turn can be used to, e.g., train a Website
//! Fingerprinting attack.
//!
//! ## Example usage
//! ```
//! use maybenot::{event::TriggerEvent, Machine};
//! use maybenot_simulator::{network::Network, parse_trace, sim};
//! use std::{str::FromStr, time::Duration};
//!
//!
//! // The first ten packets of a network trace from the client's perspective
//! // when visiting google.com. The format is: "time,direction\n". The
//! // direction is either "s" (sent) or "r" (received). The time is in
//! // nanoseconds since the start of the trace.
//! let raw_trace = "0,s
//! 19714282,r
//! 183976147,s
//! 243699564,r
//! 1696037773,s
//! 2047985926,s
//! 2055955094,r
//! 9401039609,s
//! 9401094589,s
//! 9420892765,r";
//!
//! // The network model for simulating the network between the client and the
//! // server. Currently just a delay.
//! let network = Network::new(Duration::from_millis(10), None);
//!
//! // Parse the raw trace into a queue of events for the simulator. This uses
//! // the delay to generate a queue of events at the client and server in such
//! // a way that the client is ensured to get the packets in the same order and
//! // at the same time as in the raw trace.
//! let mut input_trace = parse_trace(raw_trace, &network);
//!
//! // A simple machine that sends one padding packet 20 milliseconds after the
//! // first normal packet is sent.
//! let m = "02eNptibEJAAAIw1of09Mc/c+HRMFFzFBoAlxkliTgurLfT6T9oQBWJgJi";
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
//!         TriggerEvent::TunnelSent => {
//!             if p.contains_padding {
//!                 println!(
//!                     "sent a padding packet at {} ms",
//!                     (p.time - starting_time).as_millis()
//!                 );
//!             } else {
//!                 println!(
//!                     "sent a normal packet at {} ms",
//!                     (p.time - starting_time).as_millis()
//!                 );
//!             }
//!         }
//!         TriggerEvent::TunnelRecv => {
//!             if p.contains_padding {
//!                 println!(
//!                     "received a padding packet at {} ms",
//!                     (p.time - starting_time).as_millis()
//!                 );
//!             } else {
//!                 println!(
//!                     "received a normal packet at {} ms",
//!                     (p.time - starting_time).as_millis()
//!                 );
//!             }
//!         }
//!         _ => {}
//!     });

//!
//! // Output:
//! // sent a normal packet at 0 ms
//! // received a normal packet at 19 ms
//! // sent a padding packet at 20 ms
//! // sent a normal packet at 183 ms
//! // received a normal packet at 243 ms
//! // sent a normal packet at 1696 ms
//! // sent a normal packet at 2047 ms
//! // received a normal packet at 2055 ms
//! // sent a normal packet at 9401 ms
//! // sent a normal packet at 9401 ms
//! // received a normal packet at 9420 ms
//! ```

pub mod integration;
pub mod network;
pub mod peek;
pub mod queue;

//for temp testing....
pub mod linktrace;
//pub mod network_linktr;

use std::{
    cmp::Ordering,
    time::{Duration, Instant},
};

use integration::Integration;
use linktrace::mk_start_instant;
use log::debug;
use network::{Network, NetworkBottleneck, WindowCount};
use queue::SimQueue;

use maybenot::{Framework, Machine, MachineId, Timer, TriggerAction, TriggerEvent};
use rand::{rngs::ThreadRng, RngCore};
use rand_xoshiro::rand_core::SeedableRng;
use rand_xoshiro::Xoshiro256StarStar;

use crate::{
    network::sim_network_stack,
    peek::{peek_blocked_exp, peek_queue, peek_scheduled_action, peek_scheduled_internal_timer},
};

// Enum to encapsulate different RngCore sources: in the Maybenot Framework, the
// RngCore trait is not ?Sized (unnecessary overhead for the framework), so we
// have to work around this by using an enum to support selecting rng source as
// a simulation option.
#[derive(Debug)]
enum RngSource {
    Thread(ThreadRng),
    Xoshiro(Xoshiro256StarStar),
}

impl RngCore for RngSource {
    fn next_u32(&mut self) -> u32 {
        match self {
            RngSource::Thread(rng) => rng.next_u32(),
            RngSource::Xoshiro(rng) => rng.next_u32(),
        }
    }

    fn next_u64(&mut self) -> u64 {
        match self {
            RngSource::Thread(rng) => rng.next_u64(),
            RngSource::Xoshiro(rng) => rng.next_u64(),
        }
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self {
            RngSource::Thread(rng) => rng.fill_bytes(dest),
            RngSource::Xoshiro(rng) => rng.fill_bytes(dest),
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        match self {
            RngSource::Thread(rng) => rng.try_fill_bytes(dest),
            RngSource::Xoshiro(rng) => rng.try_fill_bytes(dest),
        }
    }
}

/// SimEvent represents an event in the simulator. It is used internally to
/// represent events that are to be processed by the simulator (in SimQueue) and
/// events that are produced by the simulator (the resulting trace).
#[derive(PartialEq, Hash, Eq, Clone, Debug)]
pub struct SimEvent {
    /// the actual event
    pub event: TriggerEvent,
    /// the time of the event taking place
    pub time: Instant,
    /// the delay of the event due to integration
    pub integration_delay: Duration,
    /// flag to track if the event is from the client
    pub client: bool,
    /// flag to track padding or normal packet
    pub contains_padding: bool,
    /// internal flag to mark event as bypass
    bypass: bool,
    /// internal flag to mark event as replace
    replace: bool,
    /// internal duration to propagate base trace delay from one party to the
    /// other due to bottleneck and blocking
    propagate_base_delay: Option<Duration>,
}

/// Helper function to convert a TriggerEvent to a usize for sorting purposes.
fn event_to_usize(e: &TriggerEvent) -> usize {
    match e {
        // tunnel before normal before padding
        TriggerEvent::TunnelSent => 0,
        TriggerEvent::NormalSent => 1,
        TriggerEvent::PaddingSent { .. } => 2,
        TriggerEvent::TunnelRecv => 3,
        TriggerEvent::NormalRecv => 4,
        TriggerEvent::PaddingRecv => 5,
        // begin before end
        TriggerEvent::BlockingBegin { .. } => 6,
        TriggerEvent::BlockingEnd => 7,
        TriggerEvent::TimerBegin { .. } => 8,
        TriggerEvent::TimerEnd { .. } => 9,
    }
}

// for SimEvent, implement Ord and PartialOrd to allow for sorting by time
impl Ord for SimEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        // reverse order to get the smallest time first
        self.time
            .cmp(&other.time)
            .then_with(|| event_to_usize(&self.event).cmp(&event_to_usize(&other.event)))
            .reverse()
    }
}

impl PartialOrd for SimEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// ScheduledAction represents an action that is scheduled to be executed at a
/// certain time.
#[derive(PartialEq, Clone, Debug)]
pub struct ScheduledAction {
    action: TriggerAction,
    time: Instant,
}

/// The state of the client or the server in the simulator.
#[derive(Debug)]
pub struct SimState<M, R> {
    /// an instance of the Maybenot framework
    framework: Framework<M, R>,
    /// scheduled action timers
    scheduled_action: Vec<Option<ScheduledAction>>,
    /// scheduled internal timers
    scheduled_internal_timer: Vec<Option<Instant>>,
    /// blocking until time, active is set
    blocking_until: Option<Instant>,
    /// whether the active blocking bypassable or not
    blocking_bypassable: bool,
    /// integration aspects for this state
    integration: Option<Integration>,
}

impl<M> SimState<M, RngSource>
where
    M: AsRef<[Machine]>,
{
    pub fn new(
        machines: M,
        current_time: Instant,
        max_padding_frac: f64,
        max_blocking_frac: f64,
        integration: Option<Integration>,
        insecure_rng_seed: Option<u64>,
    ) -> Self {
        let rng = match insecure_rng_seed {
            // deterministic, insecure RNG
            Some(seed) => RngSource::Xoshiro(Xoshiro256StarStar::seed_from_u64(seed)),
            // secure RNG, default
            None => RngSource::Thread(rand::thread_rng()),
        };

        let num_machines = machines.as_ref().len();

        Self {
            framework: Framework::new(
                machines,
                max_padding_frac,
                max_blocking_frac,
                current_time,
                rng,
            )
            .unwrap(),
            scheduled_action: vec![None; num_machines],
            scheduled_internal_timer: vec![None; num_machines],
            blocking_until: None,
            blocking_bypassable: false,
            integration,
        }
    }

    pub fn reporting_delay(&self) -> Duration {
        self.integration
            .as_ref()
            .map(|i| i.reporting_delay())
            .unwrap_or(Duration::from_micros(0))
    }

    pub fn action_delay(&self) -> Duration {
        self.integration
            .as_ref()
            .map(|i| i.action_delay())
            .unwrap_or(Duration::from_micros(0))
    }

    pub fn trigger_delay(&self) -> Duration {
        self.integration
            .as_ref()
            .map(|i| i.trigger_delay())
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
    let network = Network::new(delay, None);
    let args = SimulatorArgs::new(&network, max_trace_length, only_network_activity);
    sim_advanced(machines_client, machines_server, sq, &args)
}

/// Arguments for [`sim_advanced`].
#[derive(Clone, Debug)]
pub struct SimulatorArgs<'a> {
    /// The network model for simulating the network between the client and the
    /// server.
    pub network: &'a Network,
    /// The maximum number of events to simulate.
    pub max_trace_length: usize,
    /// The maximum number of iterations to run the simulator for. If 0, the
    /// simulator will run until it stops.
    pub max_sim_iterations: usize,
    /// If true, only client events are returned in the output trace.
    pub only_client_events: bool,
    /// If true, only events that represent network packets are returned in the
    /// output trace.
    pub only_network_activity: bool,
    /// The maximum fraction of padding for the client's instance of the
    /// Maybenot framework.
    pub max_padding_frac_client: f64,
    /// The maximum fraction of blocking for the client's instance of the
    /// Maybenot framework.
    pub max_blocking_frac_client: f64,
    /// The maximum fraction of padding for the server's instance of the
    /// Maybenot framework.
    pub max_padding_frac_server: f64,
    /// The maximum fraction of blocking for the server's instance of the
    /// Maybenot framework.
    pub max_blocking_frac_server: f64,
    /// The seed for the deterministic (insecure) Xoshiro256StarStar RNG. If
    /// None, the simulator will use the cryptographically secure thread_rng().
    pub insecure_rng_seed: Option<u64>,
    /// Optional client integration delays.
    pub client_integration: Option<&'a Integration>,
    /// Optional server integration delays.
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
            insecure_rng_seed: None,
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
    args: &SimulatorArgs<'_>,
) -> Vec<SimEvent> {
    // the resulting simulated trace
    let expected_trace_len = if args.max_trace_length > 0 {
        args.max_trace_length
    } else {
        // a rough estimate of the number of events in the trace
        sq.len() * 2
    };
    let mut trace: Vec<SimEvent> = Vec::with_capacity(expected_trace_len);

    // put the mocked current time at the first event
    let mut current_time = sq.get_first_time().unwrap();

    let mut client = SimState::new(
        machines_client,
        current_time,
        args.max_padding_frac_client,
        args.max_blocking_frac_client,
        args.client_integration.cloned(),
        args.insecure_rng_seed,
    );
    let mut server = SimState::new(
        machines_server,
        current_time,
        args.max_padding_frac_server,
        args.max_blocking_frac_server,
        args.server_integration.cloned(),
        args.insecure_rng_seed,
    );
    debug!("sim(): client machines {}", machines_client.len());
    debug!("sim(): server machines {}", machines_server.len());

    let mut network =
        NetworkBottleneck::new(args.network.clone(), Duration::from_secs(1), sq.max_pps);

    let mut sim_iterations = 0;
    let start_time = current_time;
    while let Some(next) = pick_next(sq, &mut client, &mut server, &mut network, current_time) {
        debug!("#########################################################");
        debug!("sim(): main loop start");

        // move time forward?
        match next.time.cmp(&current_time) {
            Ordering::Less => {
                debug!("sim(): {:#?}", current_time);
                debug!("sim(): {:#?}", next.time);
                panic!("BUG: next event moves time backwards");
            }
            Ordering::Greater => {
                debug!("sim(): time moved forward {:#?}", next.time - current_time);
                current_time = next.time;
            }
            _ => {}
        }

        // status
        debug!(
            "sim(): at time {:#?}, aggregate network base delay {:#?}",
            current_time.duration_since(start_time),
            network.aggregate_base_delay
        );
        if next.client {
            debug!("sim(): @client next\n{:#?}", next);
        } else {
            debug!("sim(): @server next\n{:#?}", next);
        }
        if let Some(blocking_until) = client.blocking_until {
            debug!(
                "sim(): client is blocked until time {:#?}",
                blocking_until.duration_since(start_time)
            );
        }
        if let Some(blocking_until) = server.blocking_until {
            debug!(
                "sim(): server is blocked until time {:#?}",
                blocking_until.duration_since(start_time)
            );
        }

        // Where the simulator simulates the entire network between the client
        // and the server. Returns true if there was network activity (i.e., a
        // packet was sent or received over the network), false otherwise.
        let network_activity = if next.client {
            sim_network_stack(&next, sq, &client, &mut server, &mut network, &current_time)
        } else {
            sim_network_stack(&next, sq, &server, &mut client, &mut network, &current_time)
        };

        // get actions, update scheduled actions
        if next.client {
            debug!("sim(): trigger @client framework {:?}", next.event);
            trigger_update(&mut client, &next, &current_time, sq, true);
        } else {
            debug!("sim(): trigger @server framework {:?}", next.event);
            trigger_update(&mut server, &next, &current_time, sq, false);
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
                TriggerEvent::NormalSent => {
                    // remove the reporting delay
                    n.time -= n.integration_delay;
                }
                TriggerEvent::PaddingSent { .. } => {
                    // padding packet adds the action delay
                    n.time += n.integration_delay;
                }
                TriggerEvent::TunnelSent => {
                    if n.contains_padding {
                        // padding packet adds the action delay
                        n.time += n.integration_delay;
                    } else {
                        // normal packet removes the reporting delay
                        n.time -= n.integration_delay;
                    }
                }
                TriggerEvent::TunnelRecv | TriggerEvent::PaddingRecv | TriggerEvent::NormalRecv => {
                    // remove the reporting delay
                    n.time -= n.integration_delay;
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
    client: &mut SimState<M, RngSource>,
    server: &mut SimState<M, RngSource>,
    network: &mut NetworkBottleneck,
    current_time: Instant,
) -> Option<SimEvent> {
    // find the earliest scheduled action, internal timer, block expiry,
    // aggregate delay, and queued events to determine the next event
    let s = peek_scheduled_action(
        &client.scheduled_action,
        &server.scheduled_action,
        current_time,
    );
    debug!("\tpick_next(): peek_scheduled_action = {:?}", s);

    let i = peek_scheduled_internal_timer(
        &client.scheduled_internal_timer,
        &server.scheduled_internal_timer,
        current_time,
    );
    debug!("\tpick_next(): peek_scheduled_internal_timer = {:?}", i);

    let (b, b_is_client) =
        peek_blocked_exp(client.blocking_until, server.blocking_until, current_time);
    debug!("\tpick_next(): peek_blocked_exp = {:?}", b);

    let n = network.peek_aggregate_delay(current_time);
    debug!("\tpick_next(): peek_aggregate_delay = {:?}", n);

    let (q, qid, q_is_client) = peek_queue(
        sq,
        client,
        server,
        network.aggregate_base_delay,
        s.min(i).min(b).min(n),
        current_time,
    );
    debug!("\tpick_next(): peek_queue = {:?}", q);

    // no next?
    if s == Duration::MAX
        && i == Duration::MAX
        && b == Duration::MAX
        && n == Duration::MAX
        && q == Duration::MAX
    {
        return None;
    }

    // We prioritize the aggregate delay first: it is fundamental and may lead
    // to further delays for picked_queue
    if n <= s && n <= i && n <= b && n <= q {
        debug!("\tpick_next(): picked aggregate delay");
        network.pop_aggregate_delay();
        return pick_next(sq, client, server, network, current_time);
    }

    // We prioritize the queue next: in general, stuff happens faster outside
    // the framework than inside it. On overload, the user of the framework will
    // bulk trigger events in the framework.
    if q <= s && q <= i && q <= b {
        debug!(
            "\tpick_next(): picked queue, is_client {}, queue {:?}",
            q_is_client, qid
        );
        let mut tmp = sq
            .pop(qid, q_is_client, network.aggregate_base_delay)
            .unwrap();
        debug!("\tpick_next(): popped from queue {:?}", tmp);
        // check if blocking moves the event forward in time
        if current_time + q > tmp.time {
            if q > Duration::default() && !tmp.contains_padding {
                // NOTE: this blocking is also considered a delay, but only if
                // it moves time forward (otherwise, it's a question of sending
                // rate / pps) and it doesn't contain padding.
                tmp.propagate_base_delay = Some((current_time + q) - tmp.time);
                debug!(
                    "\tpick_next(): blocking delayed base TunnelSent by {:#?}, propagating in event",
                    tmp.propagate_base_delay.unwrap()
                );
            }

            // move the event forward in time
            tmp.time = current_time + q;
        }

        return Some(tmp);
    }

    // next is blocking expiry, happens outside of framework, so probably faster
    // than framework
    if b <= s && b <= i {
        debug!("\tpick_next(): picked blocking");
        // create SimEvent and move blocking into (what soon will be) the past
        // to indicate that it has been processed
        // ASSUMPTION: block outgoing is reported from integration
        let delay: Duration;
        if b_is_client {
            delay = client.reporting_delay();
            client.blocking_until = None;
        } else {
            delay = server.reporting_delay();
            server.blocking_until = None;
        }

        return Some(SimEvent {
            client: b_is_client,
            event: TriggerEvent::BlockingEnd,
            time: current_time + b + delay,
            integration_delay: delay,
            bypass: false,
            replace: false,
            contains_padding: false,
            propagate_base_delay: None,
        });
    }

    // next we pick internal events, which should be faster than scheduled
    // actions due to less work
    if i <= s {
        debug!("\tpick_next(): picked internal timer");
        let target = current_time + i;
        let act = do_internal_timer(client, server, target);
        if let Some(a) = act {
            sq.push_sim(a.clone());
        }
        return pick_next(sq, client, server, network, current_time);
    }

    // what's left is scheduled actions: find the action act on the action,
    // putting the event into the sim queue, and then recurse
    debug!("\tpick_next(): picked scheduled action");
    let target = current_time + s;
    let act = do_scheduled_action(client, server, target);
    if let Some(a) = act {
        sq.push_sim(a.clone());
    }
    pick_next(sq, client, server, network, current_time)
}

fn do_internal_timer<M: AsRef<[Machine]>>(
    client: &mut SimState<M, RngSource>,
    server: &mut SimState<M, RngSource>,
    target: Instant,
) -> Option<SimEvent> {
    let mut machine: Option<MachineId> = None;
    let mut is_client = false;

    for (id, opt) in client.scheduled_internal_timer.iter_mut().enumerate() {
        if let Some(a) = opt {
            if *a == target {
                machine = Some(MachineId::from_raw(id));
                is_client = true;
                *opt = None;
                break;
            }
        }
    }

    if machine.is_none() {
        for (id, opt) in server.scheduled_internal_timer.iter_mut().enumerate() {
            if let Some(a) = opt {
                if *a == target {
                    machine = Some(MachineId::from_raw(id));
                    is_client = false;
                    *opt = None;
                    break;
                }
            }
        }
    }

    assert!(machine.is_some(), "BUG: no internal action found");

    // create SimEvent with TimerEnd
    Some(SimEvent {
        client: is_client,
        event: TriggerEvent::TimerEnd {
            machine: machine.unwrap(),
        },
        time: target,
        integration_delay: Duration::from_micros(0), // TODO: is this correct?
        bypass: false,
        replace: false,
        contains_padding: false,
        propagate_base_delay: None,
    })
}

fn do_scheduled_action<M: AsRef<[Machine]>>(
    client: &mut SimState<M, RngSource>,
    server: &mut SimState<M, RngSource>,
    target: Instant,
) -> Option<SimEvent> {
    // find the action
    let mut a: Option<ScheduledAction> = None;
    let mut is_client = false;

    for opt in client.scheduled_action.iter_mut() {
        if let Some(sa) = opt {
            if sa.time == target {
                a = Some(sa.clone());
                is_client = true;
                *opt = None;
                break;
            }
        }
    }

    // cannot schedule a None action, so if we found one, done
    if a.is_none() {
        for opt in server.scheduled_action.iter_mut() {
            if let Some(sa) = opt {
                if sa.time == target {
                    a = Some(sa.clone());
                    is_client = false;
                    *opt = None;
                    break;
                }
            }
        }
    }

    // no action found
    assert!(a.is_some(), "BUG: no action found");
    let a = a.unwrap();

    // do the action
    match a.action {
        TriggerAction::Cancel { .. } => {
            // this should never happen, bug
            panic!("BUG: cancel action in scheduled action");
        }
        TriggerAction::UpdateTimer { .. } => {
            // this should never happen, bug
            panic!("BUG: update timer action in scheduled action");
        }
        TriggerAction::SendPadding {
            timeout: _,
            bypass,
            replace,
            machine,
        } => {
            let action_delay = if is_client {
                client.action_delay()
            } else {
                server.action_delay()
            };

            Some(SimEvent {
                event: TriggerEvent::PaddingSent { machine },
                time: a.time,
                integration_delay: action_delay,
                client: is_client,
                bypass,
                replace,
                contains_padding: true,
                propagate_base_delay: None,
            })
        }
        TriggerAction::BlockOutgoing {
            timeout: _,
            duration,
            bypass,
            replace,
            machine,
        } => {
            let block = a.time + duration;
            let event_bypass;
            // ASSUMPTION: block outgoing reported from integration
            let total_delay = if is_client {
                client.action_delay() + client.reporting_delay()
            } else {
                server.action_delay() + server.reporting_delay()
            };
            let reported = a.time + total_delay;

            // should we update client/server blocking?
            if is_client {
                if replace || block > client.blocking_until.unwrap_or(a.time) {
                    client.blocking_until = Some(block);
                    client.blocking_bypassable = bypass;
                }
                event_bypass = client.blocking_bypassable;
            } else {
                if replace || block > server.blocking_until.unwrap_or(a.time) {
                    server.blocking_until = Some(block);
                    server.blocking_bypassable = bypass;
                }
                event_bypass = server.blocking_bypassable;
            }

            // event triggered regardless
            Some(SimEvent {
                event: TriggerEvent::BlockingBegin { machine },
                time: reported,
                integration_delay: total_delay,
                client: is_client,
                bypass: event_bypass,
                replace: false,
                contains_padding: false,
                propagate_base_delay: None,
            })
        }
    }
}

fn trigger_update<M: AsRef<[Machine]>>(
    state: &mut SimState<M, RngSource>,
    next: &SimEvent,
    current_time: &Instant,
    sq: &mut SimQueue,
    is_client: bool,
) {
    let trigger_delay = state.trigger_delay();

    // parse actions and update
    for action in state
        .framework
        .trigger_events(&[next.event.clone()], *current_time)
    {
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
                        state.scheduled_action[machine.into_raw()] = None;
                    }
                    Timer::Internal => {
                        state.scheduled_internal_timer[machine.into_raw()] = None;
                    }
                    Timer::All => {
                        state.scheduled_action[machine.into_raw()] = None;
                        state.scheduled_internal_timer[machine.into_raw()] = None;
                    }
                }
            }
            TriggerAction::SendPadding {
                timeout,
                bypass: _,
                replace: _,
                machine,
            } => {
                debug!(
                    "\ttrigger_update(): send padding action {:?} {:?}",
                    timeout, machine
                );
                state.scheduled_action[machine.into_raw()] = Some(ScheduledAction {
                    action: action.clone(),
                    time: *current_time + *timeout + trigger_delay,
                });
            }
            TriggerAction::BlockOutgoing {
                timeout,
                duration: _,
                bypass: _,
                replace: _,
                machine,
            } => {
                debug!(
                    "\ttrigger_update(): block outgoing action {:?} {:?}",
                    timeout, machine
                );
                state.scheduled_action[machine.into_raw()] = Some(ScheduledAction {
                    action: action.clone(),
                    time: *current_time + *timeout + trigger_delay,
                });
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
                let current =
                    state.scheduled_internal_timer[machine.into_raw()].unwrap_or(*current_time);

                // update the timer
                if *replace || current < *current_time + *duration {
                    state.scheduled_internal_timer[machine.into_raw()] =
                        Some(*current_time + *duration);
                    // TimerBegin event
                    sq.push_sim(SimEvent {
                        client: is_client,
                        event: TriggerEvent::TimerBegin { machine: *machine },
                        time: *current_time,
                        integration_delay: Duration::from_micros(0), // TODO: is this correct?
                        bypass: false,
                        replace: false,
                        contains_padding: false,
                        propagate_base_delay: None,
                    });
                }
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
    let mut sent_window = WindowCount::new(Duration::from_secs(1));
    let mut recv_window = WindowCount::new(Duration::from_secs(1));
    let mut sent_max_pps = 0;
    let mut recv_max_pps = 0;

    // we just need a random starting time to make sure that we don't start from
    // absolute 0
    //let starting_time = Instant::now();

    // Use a common starting time for simqueue and linktrace indexing.
    // Adjust it to the subtraction of network delay made below to ensure
    // no negative indexes
    let starting_time = mk_start_instant() + network.delay;

    for l in trace.lines() {
        let parts: Vec<&str> = l.split(',').collect();
        if parts.len() >= 2 {
            let timestamp =
                starting_time + Duration::from_nanos(parts[0].trim().parse::<u64>().unwrap());
            // let size = parts[2].trim().parse::<u64>().unwrap();

            // NOTE: for supporting deterministic simulation with a seed, note
            // that once network is randomized and integration delays are used,
            // both need to be updated below. Unfortunately, users of the
            // simulator would have to take this parsing into account as well.
            match parts[1] {
                "s" | "sn" => {
                    // client sent at the given time
                    let reporting_delay = client
                        .map(|i| i.reporting_delay())
                        .unwrap_or(Duration::from_micros(0));
                    let reported = timestamp + reporting_delay;
                    sq.push(
                        TriggerEvent::NormalSent,
                        true,
                        false,
                        reported,
                        reporting_delay,
                    );

                    let m = sent_window.add(&timestamp);
                    if m > sent_max_pps {
                        sent_max_pps = m;
                    }
                }
                "r" | "rn" => {
                    // sent by server delay time ago
                    let sent = timestamp - network.delay;
                    // but reported to the Maybenot framework at the server with delay
                    let reporting_delay = server
                        .map(|i| i.reporting_delay())
                        .unwrap_or(Duration::from_micros(0));
                    let reported = sent + reporting_delay;
                    sq.push(
                        TriggerEvent::NormalSent,
                        false,
                        false,
                        reported,
                        reporting_delay,
                    );

                    let m = recv_window.add(&timestamp);
                    if m > recv_max_pps {
                        recv_max_pps = m;
                    }
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

    sq.max_pps = Some(sent_max_pps.max(recv_max_pps));

    sq
}
