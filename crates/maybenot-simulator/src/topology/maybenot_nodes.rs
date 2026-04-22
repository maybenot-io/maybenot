use crate::integration::Integration;
use crate::maybenot_helpers::{
    maybenot_do_internal_timer, maybenot_do_scheduled_action, maybenot_trigger_update,
};
use crate::topology::nodes::check_dependent_packets;
use crate::topology::{NetworkLinkState, NetworkTopology};
use crate::{
    DecoyLimitConfig, DelayLimitConfig, DynamicLimitDecoy, DynamicLimitDelay, SimEvent, SimInfo,
    SimQueue, SimTime,
};
use log::debug;
use maybenot::{
    Framework, LimitDecoyFrac, LimitDecoyFracWindowed, LimitDecoyNone, LimitDelayFrac,
    LimitDelayNone, Machine, TriggerAction, TriggerEvent,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::fmt::Debug;
use std::time::Duration;

use rand::{Rng, TryRng, rngs::ThreadRng};
use rand_xoshiro::Xoshiro256StarStar;
use rand_xoshiro::rand_core::SeedableRng;

// Enum to encapsulate different RngCore sources: in the Maybenot Framework, the
// RngCore trait is not ?Sized (unnecessary overhead for the framework), so we
// have to work around this by using an enum to support selecting rng source as
// a simulation option.
#[derive(Debug, Clone)]
pub enum RngSource {
    Thread(ThreadRng),
    Xoshiro(Xoshiro256StarStar),
}

impl TryRng for RngSource {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(match self {
            RngSource::Thread(rng) => rng.next_u32(),
            RngSource::Xoshiro(rng) => rng.next_u32(),
        })
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(match self {
            RngSource::Thread(rng) => rng.next_u64(),
            RngSource::Xoshiro(rng) => rng.next_u64(),
        })
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        match self {
            RngSource::Thread(rng) => rng.fill_bytes(dest),
            RngSource::Xoshiro(rng) => rng.fill_bytes(dest),
        }
        Ok(())
    }
}

/// Produces [`TriggerAction`]s in response to a batch of [`TriggerEvent`]s.
///
/// This is the simulator's extension point for replacing the default
/// [`maybenot::Framework`] with a user-supplied implementation. The simulator's
/// scheduling, delay, and integration-delay machinery is unchanged regardless
/// of which producer is in use.
///
/// Used via [`crate::sim_user_provided`], which installs a producer for both
/// the client and server Maybenot nodes.
///
/// # MachineId range
///
/// Returned action variants reference machines by [`maybenot::MachineId`].
/// Producers MUST only return ids in `0..self.num_machines()` — those are the
/// only valid slots in the simulator's per-machine schedulers. Using a larger
/// id will panic the simulation. `num_machines()` MUST stay constant for the
/// lifetime of the producer.
pub trait ActionProducer: Debug {
    /// Process a batch of events at `current_time` and return all actions
    /// the simulator should schedule. May be empty.
    fn trigger_events(
        &mut self,
        events: &[TriggerEvent],
        current_time: SimTime,
    ) -> Vec<TriggerAction<SimTime>>;

    /// Number of machine slots the simulator should preallocate for
    /// scheduled actions and internal timers.
    fn num_machines(&self) -> usize;
}

impl ActionProducer
    for Framework<Vec<Machine>, RngSource, SimTime, DynamicLimitDecoy, DynamicLimitDelay>
{
    fn trigger_events(
        &mut self,
        events: &[TriggerEvent],
        current_time: SimTime,
    ) -> Vec<TriggerAction<SimTime>> {
        Framework::trigger_events(self, events, current_time)
            .cloned()
            .collect()
    }

    fn num_machines(&self) -> usize {
        Framework::num_machines(self)
    }
}

/// ScheduledAction represents an action that is scheduled to be executed at a
/// certain time.
#[derive(PartialEq, Clone, Debug)]
pub struct ScheduledAction {
    pub action: TriggerAction<SimTime>,
    pub time: Duration,
}

/// The state of the client, or relay in the simulator.
#[derive(Debug)]
pub struct MaybenotState {
    /// produces actions in response to events. By default this wraps a
    /// [`maybenot::Framework`] (via the blanket [`ActionProducer`] impl);
    /// [`crate::sim_user_provided`] swaps in a caller-supplied producer.
    pub action_producer: Box<dyn ActionProducer>,
    /// scheduled action timers
    pub scheduled_action: Vec<Option<ScheduledAction>>,
    /// scheduled internal timers
    pub scheduled_internal_timer: Vec<Option<Duration>>,
    /// delay until time, active is set
    pub delay_until: Option<Duration>,
    /// whether the active delay is bypassable or not
    pub delay_bypassable: bool,
    /// remaining packets the current delay will drain before it ends (v3
    /// DelayTraffic N-cap). When this hits zero, the delay ends at the current
    /// simulation time.
    pub delay_max_packets: Option<usize>,
    /// whether to drain delayed packets by time or first all normal then
    /// decoy
    pub drain_delayed_by_time: bool,
    /// integration aspects for this state
    pub integration: Option<Integration>,
}

impl MaybenotState {
    /// Build a state around an arbitrary [`ActionProducer`]. Used by the
    /// `sim_user_provided` entry point and indirectly by [`Self::new`].
    pub(crate) fn with_producer(
        action_producer: Box<dyn ActionProducer>,
        drain_delayed_by_time: bool,
        integration: Option<Integration>,
    ) -> Self {
        let num_machines = action_producer.num_machines();
        Self {
            action_producer,
            scheduled_action: vec![None; num_machines],
            scheduled_internal_timer: vec![None; num_machines],
            delay_until: None,
            delay_bypassable: false,
            delay_max_packets: None,
            drain_delayed_by_time,
            integration,
        }
    }

    pub(crate) fn new(
        machines: Vec<Machine>,
        current_time: Duration,
        decoy_limit: &DecoyLimitConfig,
        delay_limit: &DelayLimitConfig,
        drain_delayed_by_time: bool,
        integration: Option<Integration>,
        insecure_rng_seed: Option<u64>,
    ) -> Self {
        let rng = match insecure_rng_seed {
            // deterministic, insecure RNG
            Some(seed) => RngSource::Xoshiro(Xoshiro256StarStar::seed_from_u64(seed)),
            // secure RNG, default
            None => RngSource::Thread(rand::rng()),
        };

        let decoy_limit = match decoy_limit {
            DecoyLimitConfig::None => DynamicLimitDecoy::None(LimitDecoyNone),
            DecoyLimitConfig::Frac { frac } => DynamicLimitDecoy::Frac(
                LimitDecoyFrac::new(*frac).expect("decoy frac must be in [0.0, 1.0]"),
            ),
            DecoyLimitConfig::FracWindowed {
                frac,
                window_ms,
                min_normal,
            } => DynamicLimitDecoy::FracWindowed(
                LimitDecoyFracWindowed::new(*frac, Duration::from_millis(*window_ms), *min_normal)
                    .expect("decoy frac windowed parameters invalid"),
            ),
        };

        let delay_limit = match delay_limit {
            DelayLimitConfig::None => DynamicLimitDelay::None(LimitDelayNone),
            DelayLimitConfig::Frac {
                frac,
                window_ms,
                max_packets,
            } => DynamicLimitDelay::Frac(
                LimitDelayFrac::new(*frac, Duration::from_millis(*window_ms), *max_packets)
                    .expect("delay frac must be in [0.0, 1.0]"),
            ),
        };

        let framework = Framework::new(
            machines,
            decoy_limit,
            delay_limit,
            SimTime(current_time),
            rng,
        )
        .unwrap();

        Self::with_producer(Box::new(framework), drain_delayed_by_time, integration)
    }

    pub(crate) fn reporting_delay(&self) -> Duration {
        self.integration
            .as_ref()
            .map(Integration::reporting_delay)
            .unwrap_or(Duration::from_micros(0))
    }

    pub(crate) fn action_delay(&self) -> Duration {
        self.integration
            .as_ref()
            .map(Integration::action_delay)
            .unwrap_or(Duration::from_micros(0))
    }

    pub(crate) fn trigger_delay(&self) -> Duration {
        self.integration
            .as_ref()
            .map(Integration::trigger_delay)
            .unwrap_or(Duration::from_micros(0))
    }
}

// Implements the core traffic shaping logic for Maybenot defenses.
//
// This function determines whether a packet (normal or decoy) should be:
// 1. Sent immediately (no delay active)
// 2. Queued for later (delayed, non-bypassable)
// 3. Bypassed through delay (delayed but bypassable)
// 4. Replaced with queued normal traffic (decoy with replace=true)
pub(crate) fn maybenot_handle_packet_sent_creation<T: MaybenotNode>(
    node: &T,
    s_event: SimEvent,
    sq: &mut SimQueue,
) {
    let sim_state = node.get_sim_state().borrow();
    let delay_bypassable = sim_state.delay_bypassable;
    let delay_until = sim_state.delay_until;
    drop(sim_state); // Release borrow before queuing

    // Check if we're currently delaying
    if let Some(delay_until) = delay_until {
        if s_event.time < delay_until {
            // We're in a delaying period

            if delay_bypassable && s_event.bypass {
                // The delay is bypassable

                // replace flag is set: if we have a normal packet queued up /
                // delayed, we can replace the decoy with that FIXME: here be
                // bugs related to integration delays
                if s_event.contains_decoy {
                    if s_event.replace {
                        // Check if we have a normal packet queued up
                        let mut normal_queue = node.get_queue_normal().borrow_mut();

                        if let Some(mut dequeued_normal_event) = normal_queue.pop_front() {
                            dequeued_normal_event.time = s_event.time;
                            dequeued_normal_event.bypass = true;
                            debug!(
                                "Replacing bypass decoy with normal event: {:?}",
                                dequeued_normal_event
                            );
                            sq.push(dequeued_normal_event);
                            return;
                        } else {
                            debug!("No normal to replace with, sending bypass decoy");
                        }
                    } else {
                        debug!("Sending bypass decoy, Replace not set");
                    }
                } else {
                    debug!("Sending bypass Normal packet");
                }
            // Below here we could not bypass
            } else if s_event.contains_decoy {
                if s_event.replace && !node.get_queue_normal().borrow().is_empty() {
                    // If decoy_replace and there is a delayed normal packet
                    // the decoy is replaced, i.e. not enqueued
                    debug!("Decoy replaced by delayed normal packet, nothing enqueued");
                    return;
                } else {
                    let event_time = s_event.time;
                    node.get_queue_decoy().borrow_mut().push_back(s_event);
                    debug!("Delayed Decoy enqueued");
                    decrement_delay_n_cap(node, event_time);
                    return;
                }
            } else {
                let event_time = s_event.time;
                node.get_queue_normal().borrow_mut().push_back(s_event);
                debug!("Delayed Normal enqued");
                decrement_delay_n_cap(node, event_time);
                return;
            }
        }
    }
    // Not delaying or past delaying time or bypass fallthrough - add to
    // simulation queue immediately
    debug!("TunnelSent immediately");
    sq.push(s_event);
}

// Decrements the active delay's per-action N-cap after a packet has been queued
// into the delay buffer. When the cap reaches zero the delay is collapsed to
// end at the current event's time so the next pick_next iteration emits
// DelayEnd via the existing duration-expiry path.
fn decrement_delay_n_cap<T: MaybenotNode>(node: &T, event_time: Duration) {
    let mut state = node.get_sim_state().borrow_mut();
    if let Some(remaining) = state.delay_max_packets {
        let new_remaining = remaining.saturating_sub(1);
        state.delay_max_packets = Some(new_remaining);
        if new_remaining == 0 {
            state.delay_until = Some(event_time);
        }
    }
}

// Releases all queued events when a delay period expires.
//
// Two drainage strategies are supported:
// 1. Time-ordered: Events drain in chronological order by original timestamp
// 2. Type-ordered: All normal packets first, then all decoy packets
pub(crate) fn maybenot_release_delayed_events<T: MaybenotNode>(
    node: &T,
    sq: &mut SimQueue,
    current_time: Duration,
    drain_delayed_by_time: bool,
) {
    // Release all events from both queues
    let mut decoy_events = node.get_queue_decoy().borrow_mut();
    let mut normal_events = node.get_queue_normal().borrow_mut();

    debug!(
        "Releasing {} decoy events and {} normal events",
        decoy_events.len(),
        normal_events.len()
    );

    if drain_delayed_by_time {
        // Time-wise draining: release packets in chronological order based on
        // their original timestamps
        loop {
            // Check the earliest event from each queue
            let earliest_decoy = decoy_events.front().map(|e| e.time);
            let earliest_normal = normal_events.front().map(|e| e.time);

            // Determine which queue has the earliest event
            let drain_decoy = match (earliest_decoy, earliest_normal) {
                (Some(p_time), Some(n_time)) => p_time <= n_time,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => break, // Both queues are empty
            };

            // Drain the earliest event and add it to simulation queue
            if drain_decoy {
                if let Some(mut event) = decoy_events.pop_front() {
                    debug!(
                        "Releasing decoy event (time-wise): {:?} originally at {:?}, now at {:?}",
                        event.event, event.time, current_time
                    );
                    event.time = current_time;
                    sq.push(event);
                }
            } else if let Some(mut event) = normal_events.pop_front() {
                debug!(
                    "Releasing normal event (time-wise): {:?} originally at {:?}, now at {:?}",
                    event.event, event.time, current_time
                );
                event.time = current_time;
                sq.push(event);
            }
        }
    } else {
        // Move all normal queue events to simulation queue with updated time
        for mut event in normal_events.drain(..) {
            debug!(
                "Releasing normal event: {:?} originally at {:?}, now at {:?}",
                event.event, event.time, current_time
            );
            event.time = current_time;
            sq.push(event);
        }

        // Move all decoy queue events to simulation queue with updated time
        for mut event in decoy_events.drain(..) {
            debug!(
                "Releasing decoy event: {:?} originally at {:?}, now at {:?}",
                event.event, event.time, current_time
            );
            event.time = current_time;
            sq.push(event);
        }
    }
}

/// Trait for Maybenot nodes to enable generic implementations.
///
/// # Internal API
///
/// This trait is exposed for testing. The `node_id()` method is the primary
/// public interface for identifying nodes in simulation output.
#[allow(private_interfaces)]
pub trait MaybenotNode {
    fn get_sim_state(&self) -> &RefCell<MaybenotState>;
    /// Returns the node ID for this Maybenot node.
    fn node_id(&self) -> usize;
    fn get_action_link_id(&self) -> usize; // Link used for actions (coreside for client, edgeside for relay)
    fn get_queue_decoy(&self) -> &RefCell<VecDeque<SimEvent>>;
    fn get_queue_normal(&self) -> &RefCell<VecDeque<SimEvent>>;

    // Methods needed for simulation
    fn trigger_update(
        &self,
        s_event: &SimEvent,
        current_time: &Duration,
        sq: &mut SimQueue,
        topology: &NetworkTopology,
    );
    fn do_internal_timer(&self, target: Duration) -> Option<SimEvent>;
    fn do_scheduled_action(&self, target: Duration, sq: &mut SimQueue) -> Option<SimEvent>;
}

/// A Maybenot-enabled client node that originates traffic with defense
/// mechanisms.
///
/// # Network Topology Directionality
///
/// In the simulator, nodes have directional links defined by their position in
/// the network:
/// - **coreside**: Links toward the endpoint (core of the network, away from
///   edge)
/// - **edgeside**: Links toward the client (edge of the network, back toward
///   origin)
///
/// Client nodes originate traffic and send defense actions (decoy, delay)
/// toward the endpoint, so they only have `coreside_out`.
///
/// # Defense Action Link
///
/// For ClientMaybenot, all Maybenot defense actions (decoy, delay) are
/// sent on the **coreside_out** link. This is returned by
/// `get_action_link_id()`.
#[derive(Debug)]
pub struct ClientMaybenot {
    pub id: usize,
    /// Link ID for outgoing traffic and defense actions toward the endpoint (forward direction)
    pub coreside_out: usize,
    pub sim_state: RefCell<MaybenotState>,
    pub queue_decoy: RefCell<VecDeque<SimEvent>>,
    pub queue_normal: RefCell<VecDeque<SimEvent>>,
}

impl MaybenotNode for ClientMaybenot {
    fn get_sim_state(&self) -> &RefCell<MaybenotState> {
        &self.sim_state
    }

    fn node_id(&self) -> usize {
        self.id
    }

    fn get_action_link_id(&self) -> usize {
        self.coreside_out
    }

    fn get_queue_decoy(&self) -> &RefCell<VecDeque<SimEvent>> {
        &self.queue_decoy
    }

    fn get_queue_normal(&self) -> &RefCell<VecDeque<SimEvent>> {
        &self.queue_normal
    }

    fn trigger_update(
        &self,
        s_event: &SimEvent,
        current_time: &Duration,
        sq: &mut SimQueue,
        topology: &NetworkTopology,
    ) {
        maybenot_trigger_update(self, s_event, current_time, sq, topology)
    }

    fn do_internal_timer(&self, target: Duration) -> Option<SimEvent> {
        maybenot_do_internal_timer(self, target)
    }

    fn do_scheduled_action(&self, target: Duration, sq: &mut SimQueue) -> Option<SimEvent> {
        maybenot_do_scheduled_action(self, target, sq)
    }
}

#[allow(clippy::too_many_arguments)]
impl ClientMaybenot {
    pub fn new(
        id: usize,
        coreside_out: usize,
        machines: Vec<Machine>,
        decoy_limit: &DecoyLimitConfig,
        delay_limit: &DelayLimitConfig,
        drain_delayed_by_time: bool,
        integration: Option<Integration>,
        insecure_rng_seed: Option<u64>,
    ) -> Self {
        let sim_state = RefCell::new(MaybenotState::new(
            machines,
            Duration::ZERO,
            decoy_limit,
            delay_limit,
            drain_delayed_by_time,
            integration,
            insecure_rng_seed,
        ));

        Self {
            id,
            coreside_out,
            sim_state,
            queue_decoy: RefCell::new(VecDeque::new()),
            queue_normal: RefCell::new(VecDeque::new()),
        }
    }

    pub fn handle_event(
        &self,
        s_event: &SimEvent,
        topology: &NetworkTopology,
        link_state: &mut NetworkLinkState,
        si: &SimInfo,
        sq: &mut SimQueue,
    ) {
        match &s_event.event {
            TriggerEvent::NormalQueued => {
                let forward_s_event = SimEvent {
                    event: TriggerEvent::PacketSent,
                    time: s_event.time,
                    packet_id: s_event.packet_id,
                    node_id: s_event.node_id,
                    link_id: s_event.link_id,
                    contains_decoy: false,
                    bypass: s_event.bypass,
                    replace: s_event.replace,
                    is_client: false,
                    q_sequence_nr: 0, // Will be overwritten by push()
                    #[cfg(debug_assertions)]
                    debug_note: None,
                };
                // Use delay-aware logic to decide whether to queue immediately
                // or delay
                maybenot_handle_packet_sent_creation(self, forward_s_event, sq);
            }

            TriggerEvent::DecoyQueued { .. } => {
                let forward_s_event = SimEvent {
                    event: TriggerEvent::PacketSent,
                    time: s_event.time,
                    packet_id: s_event.packet_id,
                    node_id: s_event.node_id,
                    link_id: s_event.link_id,
                    contains_decoy: true,
                    bypass: s_event.bypass,
                    replace: s_event.replace,
                    is_client: false,
                    q_sequence_nr: 0, // Will be overwritten by push()
                    #[cfg(debug_assertions)]
                    debug_note: None,
                };
                // Use delay-aware logic to decide whether to queue immediately
                // or delay
                maybenot_handle_packet_sent_creation(self, forward_s_event, sq);
            }

            TriggerEvent::PacketSent => {
                crate::topology::nodes::make_network_receive_from_sent(
                    s_event, topology, link_state, si, sq,
                );
            }

            TriggerEvent::PacketRecv => {
                let new_t_event = match &s_event.contains_decoy {
                    true => TriggerEvent::DecoyRecv,
                    false => TriggerEvent::NormalRecv,
                };
                let forward_s_event = SimEvent {
                    event: new_t_event,
                    time: s_event.time,
                    packet_id: s_event.packet_id,
                    node_id: s_event.node_id,
                    link_id: s_event.link_id,
                    contains_decoy: s_event.contains_decoy,
                    bypass: s_event.bypass,
                    replace: s_event.replace,
                    is_client: false,
                    q_sequence_nr: 0, // Will be overwritten by push()
                    #[cfg(debug_assertions)]
                    debug_note: None,
                };
                sq.push(forward_s_event);
            }

            TriggerEvent::NormalRecv => {
                let outgoing_link_id = topology.nodes[s_event.node_id].get_coreside_out_id();
                let outgoing_link = &link_state.links[outgoing_link_id];

                crate::topology::nodes::check_dependent_packets(s_event, si, sq, outgoing_link, 0);
            }

            TriggerEvent::DelayEnd => {
                let mut state = self.sim_state.borrow_mut();
                // Release any queued events with current time
                maybenot_release_delayed_events(
                    self,
                    sq,
                    s_event.time,
                    state.drain_delayed_by_time,
                );

                // Clear delay state
                state.delay_until = None;
                state.delay_bypassable = false;
                state.delay_max_packets = None;
            }
            _ => {}
        }
    }
}

/// A Maybenot-enabled relay node that forwards traffic bidirectionally with
/// defense mechanisms.
///
/// # Network Topology Directionality
///
/// Relay nodes sit in the middle of the network path and forward traffic
/// bidirectionally:
/// - **coreside_out**: Forwards traffic toward the endpoint (away from
///   client)
/// - **edgeside_in**: Receives traffic from coreside (from endpoint
///   direction)
/// - **edgeside_out**: Forwards traffic back toward the client (return path)
///
/// Traffic flow through a relay:
/// ```text
/// Client --> Relay --[coreside_out]--> Endpoint
///            Relay <-[edgeside_in]---- Endpoint
/// Client <-[edgeside_out]-- Relay <--- Endpoint
/// ```
///
/// # Defense Action Link
///
/// For RelayMaybenot, all Maybenot defense actions (decoy, delay) are sent
/// on the **edgeside_out** link (back toward the client). This is returned by
/// `get_action_link_id()`.
///
/// This is different from ClientMaybenot, which uses coreside_out for actions.
#[derive(Debug)]
pub struct RelayMaybenot {
    pub id: usize,
    /// Link ID for forwarding traffic toward the endpoint (forward
    /// direction)
    pub coreside_out: usize,
    /// Link ID for receiving traffic from the coreside (from endpoint
    /// direction)
    pub edgeside_in: usize,
    /// Link ID for forwarding traffic and defense actions back toward the
    /// client (return direction)
    pub edgeside_out: usize,
    pub sim_state: RefCell<MaybenotState>,
    pub queue_decoy: RefCell<VecDeque<SimEvent>>,
    pub queue_normal: RefCell<VecDeque<SimEvent>>,
}

impl MaybenotNode for RelayMaybenot {
    fn get_sim_state(&self) -> &RefCell<MaybenotState> {
        &self.sim_state
    }

    fn node_id(&self) -> usize {
        self.id
    }

    fn get_action_link_id(&self) -> usize {
        self.edgeside_out
    }

    fn get_queue_decoy(&self) -> &RefCell<VecDeque<SimEvent>> {
        &self.queue_decoy
    }

    fn get_queue_normal(&self) -> &RefCell<VecDeque<SimEvent>> {
        &self.queue_normal
    }

    fn trigger_update(
        &self,
        s_event: &SimEvent,
        current_time: &Duration,
        sq: &mut SimQueue,
        topology: &NetworkTopology,
    ) {
        maybenot_trigger_update(self, s_event, current_time, sq, topology)
    }

    fn do_internal_timer(&self, target: Duration) -> Option<SimEvent> {
        maybenot_do_internal_timer(self, target)
    }

    fn do_scheduled_action(&self, target: Duration, sq: &mut SimQueue) -> Option<SimEvent> {
        maybenot_do_scheduled_action(self, target, sq)
    }
}

impl RelayMaybenot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: usize,
        coreside_out: usize,
        edgeside_in: usize,
        edgeside_out: usize,
        machines: Vec<Machine>,
        decoy_limit: &DecoyLimitConfig,
        delay_limit: &DelayLimitConfig,
        drain_delayed_by_time: bool,
        integration: Option<Integration>,
        insecure_rng_seed: Option<u64>,
    ) -> Self {
        let sim_state = RefCell::new(MaybenotState::new(
            machines,
            Duration::ZERO,
            decoy_limit,
            delay_limit,
            drain_delayed_by_time,
            integration,
            insecure_rng_seed,
        ));

        Self {
            id,
            coreside_out,
            edgeside_in,
            edgeside_out,
            sim_state,
            queue_decoy: RefCell::new(VecDeque::new()),
            queue_normal: RefCell::new(VecDeque::new()),
        }
    }

    pub fn handle_event(
        &self,
        s_event: &SimEvent,
        topology: &NetworkTopology,
        link_state: &mut NetworkLinkState,
        si: &SimInfo,
        sq: &mut SimQueue,
    ) {
        match &s_event.event {
            TriggerEvent::PacketRecv => {
                let new_event = match &s_event.contains_decoy {
                    true => TriggerEvent::DecoyRecv,
                    false => TriggerEvent::NormalRecv,
                };
                let forward_event = SimEvent {
                    event: new_event,
                    time: s_event.time,
                    packet_id: s_event.packet_id,
                    node_id: s_event.node_id,
                    link_id: s_event.link_id,
                    contains_decoy: false,
                    bypass: false,
                    replace: false,
                    is_client: false,
                    q_sequence_nr: 0, // Will be overwritten by push()
                    #[cfg(debug_assertions)]
                    debug_note: None,
                };
                sq.push(forward_event);
            }

            TriggerEvent::NormalRecv => {
                let outlink = topology
                    .get_outlink(s_event.node_id, s_event.link_id)
                    .unwrap();
                if outlink == self.coreside_out {
                    crate::topology::nodes::forward_network_receive_from_receive(
                        s_event, topology, link_state, si, sq,
                    );
                } else if outlink == self.edgeside_out {
                    let new_s_event = SimEvent {
                        event: TriggerEvent::NormalQueued,
                        time: s_event.time,
                        packet_id: s_event.packet_id,
                        node_id: s_event.node_id,
                        link_id: outlink,
                        contains_decoy: false,
                        bypass: false,
                        replace: false,
                        is_client: false,
                        q_sequence_nr: 0, // Will be overwritten by push()
                        #[cfg(debug_assertions)]
                        debug_note: None,
                    };
                    sq.push(new_s_event);
                } else {
                    panic!(
                        "RelayMaybenot received NormalRecv on unexpected link index: {}",
                        s_event.link_id
                    );
                }
            }

            TriggerEvent::NormalQueued => {
                if s_event.link_id == self.coreside_out {
                    crate::topology::nodes::make_network_receive_from_sent(
                        s_event, topology, link_state, si, sq,
                    );
                } else if s_event.link_id == self.edgeside_out {
                    let forward_s_event = SimEvent {
                        event: TriggerEvent::PacketSent,
                        time: s_event.time,
                        packet_id: s_event.packet_id,
                        node_id: s_event.node_id,
                        link_id: s_event.link_id,
                        contains_decoy: false,
                        bypass: s_event.bypass,
                        replace: s_event.replace,
                        is_client: false,
                        q_sequence_nr: 0, // Will be overwritten by push()
                        #[cfg(debug_assertions)]
                        debug_note: None,
                    };
                    // Use delaying-aware logic to decide whether to queue immediately or delay
                    maybenot_handle_packet_sent_creation(self, forward_s_event, sq);
                } else {
                    panic!(
                        "RelayMaybenot received NormalRecv on unexpected link index: {}",
                        s_event.link_id
                    );
                }
            }

            TriggerEvent::DecoyQueued { .. } => {
                let forward_s_event = SimEvent {
                    event: TriggerEvent::PacketSent,
                    time: s_event.time,
                    packet_id: s_event.packet_id,
                    node_id: s_event.node_id,
                    link_id: s_event.link_id,
                    contains_decoy: true,
                    bypass: s_event.bypass,
                    replace: s_event.replace,
                    is_client: false,
                    q_sequence_nr: 0, // Will be overwritten by push()
                    #[cfg(debug_assertions)]
                    debug_note: None,
                };
                // Use delaying-aware logic to decide whether to queue immediately or delay
                maybenot_handle_packet_sent_creation(self, forward_s_event, sq);
            }

            TriggerEvent::PacketSent => {
                crate::topology::nodes::make_network_receive_from_sent(
                    s_event, topology, link_state, si, sq,
                );
            }

            TriggerEvent::DelayEnd => {
                let mut state = self.sim_state.borrow_mut();
                // Release any queued events with current time
                maybenot_release_delayed_events(
                    self,
                    sq,
                    s_event.time,
                    state.drain_delayed_by_time,
                );

                // Clear delay state
                state.delay_until = None;
                state.delay_bypassable = false;
                state.delay_max_packets = None;
            }
            _ => {}
        }
    }
}

/// A Maybenot-enabled relay+endpoint combined node that receives traffic and
/// responds with defenses.
///
/// # Network Topology Directionality
///
/// This node type combines relay and endpoint functionality. It sits at the
/// end of the network path (core side) and only handles traffic in the return
/// direction:
/// - **edgeside_in**: Receives traffic from the coreside (from prior hops)
/// - **edgeside_out**: Sends response traffic and defense actions back toward
///   the client
///
/// Traffic flow for a relay-endpoint:
/// ```text
/// Client --> ... --> RelayMaybenotEndpoint (receives on edgeside_in)
/// Client <-[edgeside_out]-- RelayMaybenotEndpoint (sends response + defense)
/// ```
///
/// # Defense Action Link
///
/// For RelayMaybenotEndpoint, all Maybenot defense actions (decoy,
/// delay) are sent on the **edgeside_out** link (back toward the client).
/// This is returned by `get_action_link_id()`.
///
/// # Implementation Note
///
/// Unlike EndpointBasic, this node includes an internal
/// `endpoint_prop_us` delay to simulate processing time at the endpoint
/// before responding.
#[derive(Debug)]
pub struct RelayMaybenotEndpoint {
    pub id: usize,
    /// Link ID for receiving traffic from prior network hops (forward
    /// direction)
    pub edgeside_in: usize,
    /// Link ID for sending response traffic and defense actions back toward the
    /// client (return direction)
    pub edgeside_out: usize,
    pub sim_state: RefCell<MaybenotState>,
    pub queue_decoy: RefCell<VecDeque<SimEvent>>,
    pub queue_normal: RefCell<VecDeque<SimEvent>>,
    /// Propagation delay simulating endpoint processing time
    pub endpoint_prop_us: Duration,
}

impl MaybenotNode for RelayMaybenotEndpoint {
    fn get_sim_state(&self) -> &RefCell<MaybenotState> {
        &self.sim_state
    }

    fn node_id(&self) -> usize {
        self.id
    }

    fn get_action_link_id(&self) -> usize {
        self.edgeside_out
    }

    fn get_queue_decoy(&self) -> &RefCell<VecDeque<SimEvent>> {
        &self.queue_decoy
    }

    fn get_queue_normal(&self) -> &RefCell<VecDeque<SimEvent>> {
        &self.queue_normal
    }

    fn trigger_update(
        &self,
        s_event: &SimEvent,
        current_time: &Duration,
        sq: &mut SimQueue,
        topology: &NetworkTopology,
    ) {
        maybenot_trigger_update(self, s_event, current_time, sq, topology)
    }

    fn do_internal_timer(&self, target: Duration) -> Option<SimEvent> {
        maybenot_do_internal_timer(self, target)
    }

    fn do_scheduled_action(&self, target: Duration, sq: &mut SimQueue) -> Option<SimEvent> {
        maybenot_do_scheduled_action(self, target, sq)
    }
}

impl RelayMaybenotEndpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: usize,
        edgeside_in: usize,
        edgeside_out: usize,
        machines: Vec<Machine>,
        decoy_limit: &DecoyLimitConfig,
        delay_limit: &DelayLimitConfig,
        drain_delayed_by_time: bool,
        integration: Option<Integration>,
        insecure_rng_seed: Option<u64>,
        endpoint_prop_us: Duration,
    ) -> Self {
        let sim_state = RefCell::new(MaybenotState::new(
            machines,
            Duration::ZERO,
            decoy_limit,
            delay_limit,
            drain_delayed_by_time,
            integration,
            insecure_rng_seed,
        ));

        Self {
            id,
            edgeside_in,
            edgeside_out,
            sim_state,
            queue_decoy: RefCell::new(VecDeque::new()),
            queue_normal: RefCell::new(VecDeque::new()),
            endpoint_prop_us,
        }
    }

    pub fn handle_event(
        &self,
        s_event: &SimEvent,
        topology: &NetworkTopology,
        link_state: &mut NetworkLinkState,
        si: &SimInfo,
        sq: &mut SimQueue,
    ) {
        match &s_event.event {
            TriggerEvent::PacketRecv => {
                let new_event = match &s_event.contains_decoy {
                    true => TriggerEvent::DecoyRecv,
                    false => TriggerEvent::NormalRecv,
                };
                let forward_event = SimEvent {
                    event: new_event,
                    time: s_event.time,
                    packet_id: s_event.packet_id,
                    node_id: s_event.node_id,
                    link_id: s_event.link_id,
                    contains_decoy: false,
                    bypass: false,
                    replace: false,
                    is_client: false,
                    q_sequence_nr: 0, // Will be overwritten by push()
                    #[cfg(debug_assertions)]
                    debug_note: None,
                };
                sq.push(forward_event);
            }

            TriggerEvent::NormalRecv => {
                debug!(
                    "\tqueue {:#?} tx_depend check RelayMaybenotEndpoint",
                    TriggerEvent::NormalRecv
                );
                let mut timeadjusted_event = s_event.clone();
                timeadjusted_event.time += self.endpoint_prop_us; // Add delay to endpoint
                let outgoing_link = &link_state.links[self.edgeside_out];
                check_dependent_packets(
                    &timeadjusted_event,
                    si,
                    sq,
                    outgoing_link,
                    self.endpoint_prop_us.as_micros() as u64,
                );
            }

            TriggerEvent::NormalQueued if s_event.link_id == self.edgeside_out => {
                let forward_s_event = SimEvent {
                    event: TriggerEvent::PacketSent,
                    time: s_event.time,
                    packet_id: s_event.packet_id,
                    node_id: s_event.node_id,
                    link_id: s_event.link_id,
                    contains_decoy: false,
                    bypass: s_event.bypass,
                    replace: s_event.replace,
                    is_client: false,
                    q_sequence_nr: 0, // Will be overwritten by push()
                    #[cfg(debug_assertions)]
                    debug_note: None,
                };
                maybenot_handle_packet_sent_creation(self, forward_s_event, sq);
            }
            TriggerEvent::NormalQueued => {
                // Ignore coreside NormalQueued (shouldn't happen)
            }

            TriggerEvent::DecoyQueued { .. } => {
                let forward_s_event = SimEvent {
                    event: TriggerEvent::PacketSent,
                    time: s_event.time,
                    packet_id: s_event.packet_id,
                    node_id: s_event.node_id,
                    link_id: s_event.link_id,
                    contains_decoy: true,
                    bypass: s_event.bypass,
                    replace: s_event.replace,
                    is_client: false,
                    q_sequence_nr: 0, // Will be overwritten by push()
                    #[cfg(debug_assertions)]
                    debug_note: None,
                };
                // Use delay-aware logic to decide whether to queue immediately
                // or delay
                maybenot_handle_packet_sent_creation(self, forward_s_event, sq);
            }

            TriggerEvent::PacketSent => {
                crate::topology::nodes::make_network_receive_from_sent(
                    s_event, topology, link_state, si, sq,
                );
            }

            TriggerEvent::DelayEnd => {
                let mut state = self.sim_state.borrow_mut();
                // Release any queued events with current time
                maybenot_release_delayed_events(
                    self,
                    sq,
                    s_event.time,
                    state.drain_delayed_by_time,
                );

                // Clear delaying state
                state.delay_until = None;
                state.delay_bypassable = false;
                state.delay_max_packets = None;
            }
            _ => {}
        }
    }
}
