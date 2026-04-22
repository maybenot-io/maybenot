pub mod integration;
pub mod limits;
pub mod links;
pub(crate) mod maybenot_helpers;
pub mod settings;
pub mod topology;
pub mod traffic_parse;

// re-export the core public API surface
pub use integration::Integration;
pub use limits::{DecoyLimitConfig, DelayLimitConfig, DynamicLimitDecoy, DynamicLimitDelay};
pub use links::LinkType;
pub use settings::{PACKET_SIZE_MAX, PACKET_SIZE_TOR, PACKET_SIZE_WG, Setting, SettingError};
pub use topology::maybenot_nodes::ActionProducer;
pub use topology::{NetworkLinkState, NetworkTopology};
pub use traffic_parse::{
    PARSE_ONE_WAY_DELAY_HTTPS, PARSE_ONE_WAY_DELAY_MULTIHOP, PARSE_ONE_WAY_DELAY_TOR,
    PARSE_ONE_WAY_DELAY_VPN, TraceParseError, parse_trace,
};

use std::{cmp::Ordering, collections::BinaryHeap, num::NonZeroUsize, time::Duration};

use log::debug;
use traffic_parse::EventKind;

use maybenot::{Machine, TriggerEvent};
use maybenot_helpers::{initialize_maybenot_sim_states, initialize_user_provided_sim_states};

use crate::maybenot_helpers::pick_next_maybenot;

/// Newtype wrapping a relative [`Duration`] so it can satisfy the
/// [`maybenot::time::Instant`] trait required by the `Framework` generic
/// parameter of [`DynamicLimitDecoy`] / [`DynamicLimitDelay`]. Used only at
/// the framework boundary; the simulator's public APIs expose plain
/// [`Duration`] for event timestamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimTime(pub Duration);

impl maybenot::time::Instant for SimTime {
    type Duration = Duration;

    #[inline(always)]
    fn saturating_duration_since(&self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
}

/// Represents a single network event in the Maybenot simulation.
///
/// `SimEvent` is the fundamental unit of simulation, representing packets being
/// sent/received, machine actions (decoy, delay), and internal timer events.
/// These events flow through the simulation priority queue and form the output
/// trace.
#[derive(PartialEq, Hash, Eq, Clone, Debug)]
pub struct SimEvent {
    /// the actual event
    pub event: TriggerEvent,
    /// the time of the event taking place, expressed as a duration from the
    /// simulation's time zero (the earliest event in the parsed trace).
    pub time: Duration,
    /// Packet ID for triggering dependent tx events
    pub packet_id: usize,
    /// Node index for the event for routing and processing
    pub node_id: usize,
    /// Convenience flag set on events returned in the output trace: `true` if
    /// [`node_id`] matches [`NetworkTopology::client`]. Internal events queued
    /// during simulation leave this `false` — only the events delivered to the
    /// caller by [`sim`] / [`sim_advanced`] are guaranteed to have it
    /// populated. Exists so callers can filter by client/server perspective
    /// without needing the topology at the filter site.
    ///
    /// [`node_id`]: Self::node_id
    pub is_client: bool,
    /// Link index for the event for routing and processing
    pub link_id: usize,
    /// sequence number for deterministic insertion ordering when timestamp is
    /// identical
    pub q_sequence_nr: u64,
    // Start of Maybenot specific fields
    /// flag to track decoy or normal packet
    pub contains_decoy: bool,
    /// internal flag to mark event as bypass
    bypass: bool,
    /// internal flag to mark event as replace
    replace: bool,
    // debug note
    #[cfg(debug_assertions)]
    pub debug_note: Option<String>,
}

impl SimEvent {
    /// Format event as compact string for column alignment
    fn format_event_compact(&self) -> String {
        match &self.event {
            TriggerEvent::NormalQueued => "NormalQueued".to_string(),
            TriggerEvent::NormalRecv => "NormalRecv".to_string(),
            TriggerEvent::PacketSent => "PacketSent".to_string(),
            TriggerEvent::PacketRecv => "PacketRecv".to_string(),
            TriggerEvent::DecoyQueued { machine } => format!("DecoyQueued-M{}", machine.into_raw()),
            TriggerEvent::DecoyRecv => "DecoyRecv".to_string(),
            TriggerEvent::DelayBegin { machine } => format!("DelayBeg-M{}", machine.into_raw()),
            TriggerEvent::DelayEnd => "DelayEnd".to_string(),
            TriggerEvent::TimerBegin { machine } => format!("TimerBeg-M{}", machine.into_raw()),
            TriggerEvent::TimerEnd { machine } => format!("TimerEnd-M{}", machine.into_raw()),
            TriggerEvent::Congestion => "Congestion".to_string(),
        }
    }

    /// Display SimEvent with time as microseconds since simulation time zero.
    pub fn display_relative(&self, si: &SimInfo) -> String {
        let time_since_zero = self.time.as_micros() as i64 - si.time_zero.as_micros() as i64;
        format!(
            "{:?} at {}μs (pkt {}, node {}, link {}) P:{} B:{} R:{}",
            self.event,
            time_since_zero,
            self.packet_id,
            if self.packet_id == usize::MAX {
                "MAX".to_string()
            } else {
                self.packet_id.to_string()
            },
            self.link_id,
            if self.contains_decoy { "T" } else { "F" },
            if self.bypass { "T" } else { "F" },
            if self.replace { "T" } else { "F" }
        )
    }

    /// Display SimEvent as display_relative but with shortform of nodetype
    /// string printed for each node, from - to nodeid for each link
    pub fn display_full(
        &self,
        si: &SimInfo,
        topology: &NetworkTopology,
        link_state: &NetworkLinkState,
    ) -> String {
        let time_since_zero = self.time.as_micros() as i64 - si.time_zero.as_micros() as i64;
        let link = link_state.get_link(self.link_id).unwrap();
        // Adjust formatting so field lengths are appropriate for example line
        // below NormalQueued at 25 μs (pkt 5, node 2 EndpointBasic, link 0
        // n2->n1) P:F B:F R:F
        format!(
            "{:<12} at{:>8} μs (pkt {:<5} node {:<2} {:<20} link {:<2} n{:<2}->n{:<2})   P:{} B:{} R:{}",
            self.format_event_compact(),
            time_since_zero,
            if self.packet_id == usize::MAX {
                "MAX".to_string()
            } else {
                self.packet_id.to_string()
            },
            self.node_id,
            topology.nodes[self.node_id].type_name(),
            self.link_id,
            link.from_node(),
            link.to_node(),
            if self.contains_decoy { "T" } else { "F" },
            if self.bypass { "T" } else { "F" },
            if self.replace { "T" } else { "F" }
        )
    }
}

// A display fmt for SimEvent that shows the event type, time, and packet index
// as one line and has D:T B:F R:T according to the booleans
impl std::fmt::Display for SimEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} at {:?} (pkt {}, node {}, link {}) D:{} B:{} R:{}",
            self.event,
            self.time,
            self.packet_id,
            self.node_id,
            self.link_id,
            if self.contains_decoy { "T" } else { "F" },
            if self.bypass { "T" } else { "F" },
            if self.replace { "T" } else { "F" }
        )
    }
}

// for SimEvent, implement Ord and PartialOrd to allow for sorting by time
impl Ord for SimEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        // reverse order to get the smallest time first
        self.time
            .cmp(&other.time)
            .then_with(|| event_to_usize(&self.event).cmp(&event_to_usize(&other.event)))
            .then_with(|| self.q_sequence_nr.cmp(&other.q_sequence_nr))
            .reverse()
    }
}

impl PartialOrd for SimEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug)]
pub struct SimInfo {
    /// Location of the original trace's t=0 within the simulation's shifted,
    /// non-negative timeline. Non-zero only when endpoint events land below
    /// zero after the client-delay adjustment in [`parse_trace`] and the
    /// timeline had to be pushed forward so every [`Duration`] stays
    /// non-negative.
    ///
    /// Purely a display/reporting aid — the simulator itself never reads this.
    /// Subtracting it from `SimEvent.time` reproduces the original
    /// trace-relative timestamp (which can be negative for server-initiated
    /// events). Kept on `SimInfo` so callers get back timestamps that line up
    /// with their input trace instead of the shifted timeline; the alternative
    /// (drop it, report shifted times) is simpler internally but forces every
    /// consumer and every hardcoded test expectation to think in post-shift
    /// coordinates.
    pub(crate) time_zero: Duration,
    pub(crate) dependent_tx: Vec<Vec<(usize, i64, EventKind)>>,
}

impl Default for SimInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl SimInfo {
    pub fn new() -> Self {
        Self {
            time_zero: Duration::ZERO,
            dependent_tx: Vec::new(),
        }
    }

    /// Read-only view of the dependency mapping built by [`parse_trace`].
    /// Intended for tests and debug inspection; the simulator consumes the
    /// field directly.
    pub fn dependent_tx(&self) -> &[Vec<(usize, i64, EventKind)>] {
        &self.dependent_tx
    }

    /// Offset between the original trace's t=0 and the simulation's
    /// non-negative timeline. Subtract from [`SimEvent::time`] to recover
    /// the timestamp a caller would have read off their input trace.
    pub fn time_zero(&self) -> Duration {
        self.time_zero
    }
}

#[derive(Clone, Debug)]
pub struct SimQueue {
    pub heap: BinaryHeap<SimEvent>,
    next_q_sequence_nr: u64,
}

impl Default for SimQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl SimQueue {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            next_q_sequence_nr: 0,
        }
    }

    pub fn push(&mut self, mut s_event: SimEvent) {
        s_event.q_sequence_nr = self.next_q_sequence_nr;
        self.next_q_sequence_nr += 1;
        self.heap.push(s_event);
    }

    pub fn pop(&mut self) -> Option<SimEvent> {
        self.heap.pop()
    }

    pub fn peek(&self) -> Option<&SimEvent> {
        self.heap.peek()
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    // This function is called for every processed event if
    // stop_after_all_normal_packets is true
    pub fn no_normal_packets(&self, topology: &topology::NetworkTopology) -> bool {
        // check main simulation queue, see if any of traffic trace packer are
        // in it
        if self.heap.iter().any(|e| e.packet_id < usize::MAX) {
            return false;
        }
        // check Maybenot node delaying queues if they exist
        if topology.has_mb {
            let client_maybenot = topology.get_maybenot_client();
            if !client_maybenot.get_queue_normal().borrow().is_empty() {
                return false;
            }

            let relay_maybenot = topology.get_maybenot_relay();
            if !relay_maybenot.get_queue_normal().borrow().is_empty() {
                return false;
            }
        }
        true
    }
}

/// Converts TriggerEvents to numeric priorities for deterministic event
/// ordering.
///
/// When multiple events occur at the same timestamp, this function provides
/// tie-breaking rules to ensure consistent simulation results:
///
/// - Packets > Control events
/// - For Packets, Packet (wire) > Normal > Decoy
/// - For Control events, Delay > Timer
///
/// This ordering ensures that network transmission completes before triggering
/// dependent events, which is useful for accurate simulation. XXX: we want
/// decoys after packet/normal since decoys are generated by the framework and
/// MAY have lower priority than normal/packet events in most integrations.
fn event_to_usize(e: &TriggerEvent) -> usize {
    match e {
        // wire-level before enqueue, normal before decoy
        TriggerEvent::PacketSent => 0,
        TriggerEvent::PacketRecv => 1,
        TriggerEvent::NormalQueued => 2,
        TriggerEvent::NormalRecv => 3,
        TriggerEvent::DecoyQueued { .. } => 4,
        TriggerEvent::DecoyRecv => 5,
        // begin before end
        TriggerEvent::DelayBegin { .. } => 6,
        TriggerEvent::DelayEnd => 7,
        TriggerEvent::TimerBegin { .. } => 8,
        TriggerEvent::TimerEnd { .. } => 9,
        TriggerEvent::Congestion => 10,
    }
}

/// Runs the Maybenot network traffic simulation.
///
/// This is the main simulation function that processes network events through a
/// topology with optional Maybenot defense machines running on client and
/// server nodes.
///
/// # Arguments
///
/// * `machines_client` - Slice of Maybenot [`Machine`]s to run on the client
///   side
/// * `machines_server` - Slice of Maybenot [`Machine`]s to run on the server
///   side
/// * `topology` - Network topology defining nodes, links and routing rules
/// * `link_state` - Mutable network link states for throughput/delay simulation
/// * `si` - Simulation info containing timing baselines and packet dependencies
/// * `sq` - Mutable simulation queue pre-loaded with traffic trace events
/// * `max_trace_length` - Maximum number of events to include in output (0 =
///   unlimited)
/// * `only_network_activity` - If true, only return wire-level packet
///   sent/received events
///
/// # Returns
///
/// A `Vec<SimEvent>` representing the simulated network trace with defense
/// modifications.
///
/// # Important Notes
///
/// - The simulation queue `sq` **must** be created by [`parse_trace`].
/// - The queue is consumed during simulation - clone it if you need to reuse it
/// - Some defense machines may generate infinite decoys, use `max_trace_length`
///   to limit output
/// - For traffic analysis, set `only_network_activity = true` to filter
///   internal events
///
/// # See Also
///
/// - [`sim_advanced`] for advanced configuration options
/// - [`parse_trace`] for creating the simulation queue from traffic traces
#[allow(clippy::too_many_arguments)]
pub fn sim(
    machines_client: &[Machine],
    machines_server: &[Machine],
    topology: &NetworkTopology,
    link_state: &mut NetworkLinkState,
    si: &SimInfo,
    sq: &mut SimQueue,
    max_trace_length: usize,
    only_network_activity: bool,
) -> Vec<SimEvent> {
    let args = SimulatorArgs::new(max_trace_length, only_network_activity);
    sim_advanced(
        machines_client,
        machines_server,
        topology,
        link_state,
        si,
        sq,
        &args,
    )
}

/// Configuration parameters for advanced network simulation.
///
/// `SimulatorArgs` provides comprehensive control over simulation behavior,
/// including termination conditions, output filtering, and Maybenot framework
/// parameters.
///
/// # Usage Patterns
///
/// ```rust
/// use maybenot_simulator::SimulatorArgs;
/// // Basic configuration
/// let args = SimulatorArgs::new(1000, true);  // 1K events, network activity only
///
/// // Advanced configuration
/// use maybenot_simulator::DecoyLimitConfig;
/// let mut args = SimulatorArgs::new(5000, false);
/// args.decoy_limit_client = DecoyLimitConfig::Frac { frac: 0.3 }; // Limit decoy overhead
/// args.insecure_rng_seed = Some(42);   // Reproducible results
/// args.only_client_events = true;     // Filter to client perspective
/// ```
///
/// # Termination Conditions
///
/// The simulator stops when **any** of these conditions are met:
/// - `max_trace_length` events added to output trace
/// - `max_sim_steps` processing iterations completed (when `Some`)
/// - All normal (non-decoy) packets processed (if
///   `stop_after_all_normal_packets = true`)
///
#[derive(Clone, Debug)]
pub struct SimulatorArgs {
    /// The maximum number of events to simulate.
    pub max_trace_length: usize,
    /// The maximum number of steps to run the simulator for. If `None`, the
    /// simulator will run until it stops for another reason.
    pub max_sim_steps: Option<NonZeroUsize>,
    /// If true, the simulator stops once all normal (non-decoy) packets have
    /// been processed.
    pub stop_after_all_normal_packets: bool,
    /// If true, only client events are returned in the output trace.
    pub only_client_events: bool,
    /// If true, only events that represent network packets are returned in the
    /// output trace.
    pub only_network_activity: bool,
    /// Decoy limit for the client's Maybenot framework instance.
    pub decoy_limit_client: DecoyLimitConfig,
    /// Delay limit for the client's Maybenot framework instance.
    pub delay_limit_client: DelayLimitConfig,
    /// Decoy limit for the server's Maybenot framework instance.
    pub decoy_limit_server: DecoyLimitConfig,
    /// Delay limit for the server's Maybenot framework instance.
    pub delay_limit_server: DelayLimitConfig,
    /// If true, delayed events will be drained based on their original
    /// timestamps. If false, all normal will be drained first, and then
    /// decoy.
    pub drain_delayed_by_time: bool,
    /// The seed for the deterministic (insecure) Xoshiro256StarStar RNG. If
    /// None, the simulator will use the cryptographically secure thread_rng().
    pub insecure_rng_seed: Option<u64>,
    /// Optional client integration delays.
    pub client_integration: Option<Integration>,
    /// Optional server integration delays.
    pub server_integration: Option<Integration>,
}

impl SimulatorArgs {
    pub fn new(max_trace_length: usize, only_network_activity: bool) -> Self {
        Self {
            max_trace_length,
            max_sim_steps: None,
            stop_after_all_normal_packets: false,
            only_client_events: false,
            only_network_activity,
            decoy_limit_client: DecoyLimitConfig::None,
            delay_limit_client: DelayLimitConfig::None,
            decoy_limit_server: DecoyLimitConfig::None,
            delay_limit_server: DelayLimitConfig::None,
            drain_delayed_by_time: false,
            insecure_rng_seed: None,
            client_integration: None,
            server_integration: None,
        }
    }
}

/// Advanced network simulation with extensive configuration options.
///
/// This function provides fine-grained control over the simulation through
/// [`SimulatorArgs`], including Maybenot framework parameters, output
/// filtering, and termination conditions.
///
/// # Arguments
///
/// * `machines_client` - Maybenot defense machines for the client node
/// * `machines_server` - Maybenot defense machines for the server/relay node  
/// * `topology` - Network topology configuration
/// * `link_state` - Mutable link states for network simulation
/// * `si` - Simulation timing and dependency information
/// * `sq` - Mutable event queue from parsed traffic trace
/// * `args` - Advanced simulation configuration parameters
///
/// # Returns
///
/// A `Vec<SimEvent>` containing the simulated network trace with applied
/// defenses.
///
/// # Key Configuration Options
///
/// - **Decoy/Delay limits**: Control maximum resource usage for defenses
/// - **Output filtering**: Return only client events or network activity  
/// - **Termination conditions**: Stop by trace length, iteration count, or
///   traffic completion
/// - **RNG control**: Use deterministic seeding for reproducible results
/// - **Integration delays**: Model real-world implementation latencies
///
/// # See Also
///
/// - [`sim`] for a simpler interface with common defaults
/// - [`SimulatorArgs`] for detailed parameter descriptions
pub fn sim_advanced(
    machines_client: &[Machine],
    machines_server: &[Machine],
    topology: &NetworkTopology,
    link_state: &mut NetworkLinkState,
    si: &SimInfo,
    sq: &mut SimQueue,
    args: &SimulatorArgs,
) -> Vec<SimEvent> {
    if topology.has_mb {
        initialize_maybenot_sim_states(
            topology,
            machines_client,
            machines_server,
            Duration::ZERO,
            args,
        );
    }
    debug!("sim(): client machines {}", machines_client.len());
    debug!("sim(): server machines {}", machines_server.len());
    run_sim(topology, link_state, si, sq, args)
}

/// Runs the simulation with caller-supplied [`ActionProducer`]s on both the
/// client and server Maybenot nodes, instead of constructing
/// [`maybenot::Framework`] instances internally with provided Maybenot
/// machines.
///
/// Use this when you want to swap out the standard Maybenot framework and
/// machines for something else, like a competing defense. The simulator's
/// scheduling, delay, integration-delay, and network machinery work identically
/// regardless of which producer is in use.
///
/// Both nodes must be supplied with a producer; mixing a user producer on one
/// side and the default framework on the other is not supported (use
/// [`sim_advanced`] for the all-framework case).
///
/// # Arguments mirroring `sim_advanced`
///
/// - `topology`, `link_state`, `si`, `sq` — same as [`sim_advanced`].
/// - `args` — only the trace-control fields (`max_trace_length`,
///   `max_sim_steps`, `stop_after_all_normal_packets`, `only_client_events`,
///   `only_network_activity`), the `drain_delayed_by_time` flag, and the
///   `client_integration` / `server_integration` integration-delay
///   distributions are honored. The `decoy_limit_*`, `delay_limit_*`, and
///   `insecure_rng_seed` fields are framework-construction concerns and are
///   ignored here — user producers own their own RNG and limits.
///
/// # Topology requirements
///
/// `topology.has_mb` must be true (i.e. the topology must declare Maybenot
/// nodes) — otherwise this function falls back to the no-defense path and the
/// producers are never consulted.
pub fn sim_user_provided(
    client_producer: Box<dyn ActionProducer>,
    server_producer: Box<dyn ActionProducer>,
    topology: &NetworkTopology,
    link_state: &mut NetworkLinkState,
    si: &SimInfo,
    sq: &mut SimQueue,
    args: &SimulatorArgs,
) -> Vec<SimEvent> {
    if topology.has_mb {
        initialize_user_provided_sim_states(topology, client_producer, server_producer, args);
    }
    debug!("sim(): user-provided producers installed on client and server");
    run_sim(topology, link_state, si, sq, args)
}

fn run_sim(
    topology: &NetworkTopology,
    link_state: &mut NetworkLinkState,
    si: &SimInfo,
    sq: &mut SimQueue,
    args: &SimulatorArgs,
) -> Vec<SimEvent> {
    let expected_trace_len = if args.max_trace_length > 0 {
        args.max_trace_length
    } else {
        // a rough estimate of the number of events in the trace
        sq.len() * 5
    };
    let mut trace: Vec<SimEvent> = Vec::with_capacity(expected_trace_len);

    // start the simulation clock at time zero (the earliest parsed event).
    let mut current_time = Duration::ZERO;

    let client_maybenot = topology.has_mb.then(|| topology.get_maybenot_client());
    let relay_maybenot = topology.has_mb.then(|| topology.get_maybenot_relay());

    let mut sim_iterations = 0;
    while let Some(next) = pick_next(si, sq, topology, current_time) {
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

        if let Some(client_maybenot) = client_maybenot {
            if let Some(delay_until) = client_maybenot.get_sim_state().borrow().delay_until {
                debug!(
                    "sim(): client outgoing traffic is delayed until time {:#?}",
                    delay_until
                );
            }
        }
        if let Some(relay_maybenot) = relay_maybenot {
            if let Some(delay_until) = relay_maybenot.get_sim_state().borrow().delay_until {
                debug!(
                    "sim(): server outgoing traffic is delayed until time {:#?}",
                    delay_until
                );
            }
        }

        debug!("sim(): next event: {}", next.display_relative(si));

        // Handle event at node
        topology.nodes[next.node_id].handle_event(&next, topology, link_state, si, sq);

        // Call trigger_update on Maybenot nodes after handling the event
        if topology.has_mb {
            if next.node_id == topology.mb_client {
                if let Some(client_maybenot) = client_maybenot {
                    debug!("sim(): trigger @client framework {:?}", next.event);
                    let reporting_delay = client_maybenot
                        .get_sim_state()
                        .borrow_mut()
                        .reporting_delay();
                    client_maybenot.trigger_update(
                        &next,
                        &(current_time + reporting_delay),
                        sq,
                        topology,
                    );
                }
            } else if next.node_id == topology.mb_server {
                if let Some(relay_maybenot) = relay_maybenot {
                    debug!("sim(): trigger @server framework {:?}", next.event);
                    let reporting_delay = relay_maybenot
                        .get_sim_state()
                        .borrow_mut()
                        .reporting_delay();
                    relay_maybenot.trigger_update(
                        &next,
                        &(current_time + reporting_delay),
                        sq,
                        topology,
                    );
                }
            }
        }

        // conditional save to resulting trace: only on network activity if set
        // in fn arg, and only on client activity if set in fn arg
        if (!args.only_client_events || next.node_id == topology.client)
            && (!args.only_network_activity
                || next.event == TriggerEvent::PacketRecv
                || next.event == TriggerEvent::PacketSent)
        {
            let mut out_event = next;
            out_event.is_client = out_event.node_id == topology.client;
            trace.push(out_event);
        }

        if args.max_trace_length > 0 && trace.len() >= args.max_trace_length {
            debug!(
                "sim(): we done, reached max trace length {}",
                args.max_trace_length
            );
            break;
        }
        sim_iterations += 1;
        if let Some(max) = args.max_sim_steps
            && sim_iterations >= max.get()
        {
            debug!("sim(): we done, reached max sim iterations {}", max);
            break;
        }
        if args.stop_after_all_normal_packets && sq.no_normal_packets(topology) {
            debug!("sim(): we done, all normal packets processed");
            debug!(" Heap: {:?}", sq.heap);
            break;
        }

        debug!("sim(): main loop end, more work?");
        debug!("#########################################################");
    }

    trace
}

// Selects the next event to process from multiple concurrent sources. This is
// the core scheduling logic that determines simulation event ordering.
fn pick_next(
    si: &SimInfo,
    sq: &mut SimQueue,
    topology: &NetworkTopology,
    current_time: Duration,
) -> Option<SimEvent> {
    if topology.has_mb {
        // Complex Maybenot scheduling: must consider queue, timers, and actions
        pick_next_maybenot(si, sq, topology, current_time)
    } else {
        // Simple case: just process queue events in timestamp order
        sq.pop()
    }
}
