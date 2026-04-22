use log::debug;
use std::time::Duration;

use crate::topology::NetworkTopology;
use crate::{SimEvent, SimInfo, SimQueue};
use maybenot::TriggerEvent;

/// Errors that can occur during traffic trace parsing.
#[derive(Debug, Clone)]
pub enum TraceParseError {
    /// Invalid timestamp in trace
    InvalidTimestamp(String),
    /// Invalid direction field in trace
    InvalidDirection(String),
    /// Malformed trace entry
    MalformedEntry(String),
    /// Decoy packet found in trace
    DecoyInTrace,
}

impl std::fmt::Display for TraceParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceParseError::InvalidTimestamp(s) => write!(f, "Invalid timestamp: {}", s),
            TraceParseError::InvalidDirection(s) => write!(f, "Invalid direction: {}", s),
            TraceParseError::MalformedEntry(s) => write!(f, "Malformed trace entry: {}", s),
            TraceParseError::DecoyInTrace => write!(f, "Decoy in trace, not supported"),
        }
    }
}

impl std::error::Error for TraceParseError {}

/// Parses a network traffic trace into simulation events.
///
/// This function converts raw network traces into [`SimInfo`] and [`SimQueue`]
/// objects ready for simulation. It performs dependency analysis to model
/// client-server (endpoint) request-response patterns.
///
/// # Traffic Trace Format
///
/// The trace should contain line-separated entries:
/// `"<time>,<direction>,<size>\n<time>,<direction>,<size>\n..."` where:
/// - **time**: nanoseconds relative to trace start (0-based)
/// - **direction**: `"s"` (sent by client) or `"r"` (received by client)
/// - **size**: packet size in bytes (currently unused, can be omitted)
///
/// # Arguments
///
/// * `trace` - Raw trace string in the format described above
/// * `topology` - Network topology for node/link mapping  
/// * `one_way_delay` - Estimated (or measured) network one-way delay between
///   client and server endpoint(s) when the original traffic trace was
///   captured, used to approximate packet dependencies. See
///   [`PARSE_ONE_WAY_DELAY_HTTPS`], [`PARSE_ONE_WAY_DELAY_VPN`],
///   [`PARSE_ONE_WAY_DELAY_MULTIHOP`], and [`PARSE_ONE_WAY_DELAY_TOR`] for
///   reasonable defaults. Depending on use-case, randomizing this value per
///   simulation run may improve realism.
///
/// # Returns
///
/// * `Ok((SimInfo, SimQueue))` - Timing baselines and priority queue on success
/// * `Err(TraceParseError)` - Error if trace parsing fails
///
/// # Errors
///
/// Returns `TraceParseError` if:
/// - Timestamp cannot be parsed as u64
/// - Invalid direction field in trace entry
/// - Instant underflow occurs during time calculation
///
/// # Dependency Analysis
///
/// The parser automatically identifies request-response patterns:
/// - Client sends followed by receives become dependent events
/// - Server responses are triggered by client requests with appropriate delays
///
/// # See Also
///
/// - [`traffic_trace_prepare`] for the core dependency analysis algorithm
/// - [`fill_simq`] for event queue population logic
pub fn parse_trace(
    trace: &str,
    topology: &NetworkTopology,
    one_way_delay: Duration,
) -> Result<(SimInfo, SimQueue), TraceParseError> {
    let mut si = SimInfo::new();
    let mut sq = SimQueue::new();

    let mut pkt_events: Vec<PacketEvent> = Vec::new();

    for l in trace.lines() {
        let parts: Vec<&str> = l.split(',').collect();
        if parts.len() < 2 {
            continue;
        }
        let time_ns = parts[0]
            .trim()
            .parse::<u64>()
            .map_err(|_| TraceParseError::InvalidTimestamp(parts[0].to_string()))?
            as i64;

        let kind = match parts[1] {
            // for "send", "send normal", and "normal queued"
            "s" | "sn" | "nq" => EventKind::ClientSend,
            // for "received", "received normal", and "normal received"
            "r" | "rn" | "nr" => EventKind::ClientRecv,
            // for "send padding", "receive padding", "decoy queued", and
            // "decoy received"
            "sp" | "rp" | "dq" | "dr" => {
                return Err(TraceParseError::DecoyInTrace);
            }
            _ => {
                return Err(TraceParseError::InvalidDirection(parts[1].to_string()));
            }
        };

        pkt_events.push(PacketEvent {
            packet_id: pkt_events.len(),
            time_ns,
            kind,
        });
    }

    let traffic_events = traffic_trace_prepare(&pkt_events, one_way_delay.as_nanos() as i64);

    fill_simq(&traffic_events, topology, &mut si, &mut sq)?;

    Ok((si, sq))
}

// We go for constants since virtually no datasets come with delay information
// and/or contain traffic mixed from multiple endpoints.

/// Reasonable constant for one-way delay between a fiber connected computer and
/// popular destinations common in network traces.
pub const PARSE_ONE_WAY_DELAY_HTTPS: Duration = Duration::from_millis(15);
/// Reasonable constant for one-way delay for a VPN (assumes a user that picks a
/// performant relay in the same country/region).
pub const PARSE_ONE_WAY_DELAY_VPN: Duration = Duration::from_millis(30);
/// Reasonable constant for one-way delay for a performant-focused use of a
/// multihop VPN.
pub const PARSE_ONE_WAY_DELAY_MULTIHOP: Duration = Duration::from_millis(45);
/// Reasonable constant for one-way delay of Tor circuits.
pub const PARSE_ONE_WAY_DELAY_TOR: Duration = Duration::from_millis(125);

// Code for reading in traffic trace, create dependent_tx, and prefill SimQueue

#[derive(Debug, Clone, Copy)]
struct PacketEvent {
    packet_id: usize,
    time_ns: i64,
    kind: EventKind,
}

/// Direction of a packet in a parsed trace. Exposed only so that tests and
/// debugging code can inspect [`SimInfo::dependent_tx`]; the simulator itself
/// treats this as an internal classification.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EventKind {
    ClientSend,
    ClientRecv,
}

/// Result of traffic trace dependency analysis.
///
/// This struct represents the parsed and analyzed traffic trace, separating
/// events into independent initial events and dependent request-response
/// chains.
///
/// # Structure
///
/// - **Independent events** go directly into simulation queue at trace start
/// - **Dependent events** are triggered by other events during simulation
/// - **Dependencies** are stored as `(packet_id, delay, kind)` tuples
///
/// # Usage in Simulation
///
/// 1. `client_simq_push` and `endpoint_simq_push` events seed the simulation
/// 2. When a receive event processes, it triggers its `dependent_tx` events
/// 3. Dependent events are scheduled with appropriate delays from their
///    triggers
#[derive(Debug, Clone)]
struct TrafficTraceData {
    /// Client send events that did not depend on any prior receive. These
    /// represent initial client requests that start new communication flows.
    client_simq_push: Vec<PacketEvent>,

    /// Client receive events that did not have a qualifying client send
    /// dependency. These represent server-initiated communications (pushes,
    /// notifications, etc.).
    endpoint_simq_push: Vec<PacketEvent>,

    /// Dependency mapping: `dependent_tx[recv_packet_id]` contains all events
    /// triggered by that receive. Each tuple is `(dependent_packet_id,
    /// time_delta_ns, event_kind)`.
    dependent_tx: Vec<Vec<(usize, i64, EventKind)>>,
}

/// Performs traffic dependency analysis for client-server communication.
///
/// Transforms an ordered list of parsed packet events into a dependency graph
/// modeling realistic client-server request-response patterns.
///
/// # Algorithm
///
/// For each client send event:
/// - **No prior receive**: Classified as initial request → goes to
///   `client_simq_push`.
/// - **Has prior receive**: Classified as response-triggered → recorded as
///   dependency on that receive.
///
/// For each client receive event:
/// - **Find matching send**: Search for a client send ≥
///   `2×ttrace_ts_to_c_delay_ns` before receive time.
/// - **Match found**: Server response depends on that client send → recorded as
///   dependency.
/// - **No match**: Server-initiated event → goes to `endpoint_simq_push`.
///
/// `pkt_events` must be ordered and each `packet_id` must equal its index in
/// the slice.
fn traffic_trace_prepare(
    pkt_events: &[PacketEvent],
    ttrace_ts_to_c_delay_ns: i64,
) -> TrafficTraceData {
    // Process client send events: for each send event, if there is a preceding
    // receive, record a dependency; otherwise, mark it as an initial simQ push.
    let mut client_simq_push = Vec::new();
    let mut dependent_tx = vec![Vec::new(); pkt_events.len()];
    let mut last_recv: Option<&PacketEvent> = None;
    for pkt_event in pkt_events {
        if pkt_event.kind == EventKind::ClientRecv {
            last_recv = Some(pkt_event);
        } else if pkt_event.kind == EventKind::ClientSend {
            if let Some(prev_recv) = last_recv {
                let delta = pkt_event.time_ns - prev_recv.time_ns;
                dependent_tx[prev_recv.packet_id].push((
                    pkt_event.packet_id,
                    delta,
                    pkt_event.kind,
                ));
            } else {
                client_simq_push.push(*pkt_event);
            }
        }
    }

    // Process endpoint events: for each client receive event, try to find
    // the most recent client send event that occurred at or before (recv time -
    // 2 * ttrace_ts_to_c_delay_ns). If found, record that as a dependency;
    // otherwise, mark the receive as a simQ push for endpoint.
    let client_sends: Vec<&PacketEvent> = pkt_events
        .iter()
        .filter(|e| e.kind == EventKind::ClientSend)
        .collect();
    let mut endpoint_simq_push = Vec::new();
    for pkt_event in pkt_events {
        if pkt_event.kind == EventKind::ClientRecv {
            let boundary = pkt_event.time_ns - (2 * ttrace_ts_to_c_delay_ns);
            let candidate = client_sends
                .iter()
                .filter(|&&e| e.time_ns <= boundary)
                .max_by_key(|&&e| e.time_ns);
            if let Some(&client_send) = candidate {
                if pkt_event.time_ns - client_send.time_ns >= 2 * ttrace_ts_to_c_delay_ns {
                    let delta =
                        (pkt_event.time_ns - client_send.time_ns) - 2 * ttrace_ts_to_c_delay_ns;
                    dependent_tx[client_send.packet_id].push((
                        pkt_event.packet_id,
                        delta,
                        pkt_event.kind,
                    ));
                } else {
                    let mut adjusted_event = *pkt_event;
                    adjusted_event.time_ns -= ttrace_ts_to_c_delay_ns;
                    endpoint_simq_push.push(adjusted_event);
                }
            } else {
                // Fix since some traces start with 0,r or time < which is messy,
                let mut adjusted_event = *pkt_event;
                adjusted_event.time_ns -= ttrace_ts_to_c_delay_ns;
                endpoint_simq_push.push(adjusted_event);
            }
        }
    }

    debug!(
        "{:#?}\n{:#?}\n{:#?}\n",
        client_simq_push, endpoint_simq_push, dependent_tx
    );
    TrafficTraceData {
        client_simq_push,
        endpoint_simq_push,
        dependent_tx,
    }
}

/// Converts a signed nanosecond offset into a [`Duration`] relative to the
/// simulation's time zero. `time_zero_ns` is the minimum `time_ns` across all
/// initial events — subtracting it ensures the result is always non-negative.
fn event_time(time_ns: i64, time_zero_ns: i64) -> Duration {
    let shifted = time_ns - time_zero_ns;
    debug_assert!(
        shifted >= 0,
        "event_time: shifted offset went negative ({} - {} = {})",
        time_ns,
        time_zero_ns,
        shifted
    );
    Duration::from_nanos(shifted as u64)
}

/// Populates the simulation queue with initial events from parsed traffic data.
///
/// This function takes the output of [`traffic_trace_prepare`] and converts the
/// initial (non-dependent) events into simulation events, populating the
/// `SimQueue`. Dependent events are stored in `SimInfo` for dynamic scheduling
/// during simulation.
fn fill_simq(
    traffic_events: &TrafficTraceData,
    topology: &NetworkTopology,
    si: &mut SimInfo,
    sq: &mut SimQueue,
) -> Result<(), TraceParseError> {
    // First pass: find the minimum timestamp across all initial events so we
    // can shift the timeline to start at Duration::ZERO. A negative minimum
    // means some endpoint events (after the trafserv_to_client_delay
    // adjustment) land before the first client event; shifting absorbs that.
    let min_time_ns = traffic_events
        .client_simq_push
        .iter()
        .chain(traffic_events.endpoint_simq_push.iter())
        .map(|e| e.time_ns)
        .min()
        .unwrap_or(0);

    if min_time_ns < 0 {
        debug!(
            "Note: Negative offset in traffic trace ({} ns). This may indicate that trafserv_to_client_delay is too low compared to the actual delay when the traffic trace was collected. Shifting timeline so earliest event is at t=0.",
            min_time_ns
        );
    }

    // Shift only when the earliest event is negative, so every `SimEvent.time`
    // stays a non-negative `Duration`. Record the shift on `si.time_zero` so
    // display code can subtract it back out and report timestamps relative to
    // the original trace rather than the shifted timeline — see
    // `SimInfo::time_zero` for the tradeoff.
    let shift_ns = (-min_time_ns).max(0);
    si.time_zero = Duration::from_nanos(shift_ns as u64);
    let time_zero_ns = -shift_ns;

    for event in &traffic_events.client_simq_push {
        let simul_event = SimEvent {
            event: TriggerEvent::NormalQueued,
            time: event_time(event.time_ns, time_zero_ns),
            packet_id: event.packet_id,
            node_id: topology.client, // Client node index
            link_id: topology.nodes[topology.client].get_coreside_out_id(), // Client->Relay link
            contains_decoy: false,
            bypass: false,
            replace: false,
            is_client: false,
            q_sequence_nr: 0, // Will be overwritten by push()
            #[cfg(debug_assertions)]
            debug_note: Some("Client initial send".to_string()),
        };
        sq.push(simul_event);
    }

    for event in &traffic_events.endpoint_simq_push {
        let simul_event = SimEvent {
            event: TriggerEvent::NormalQueued,
            time: event_time(event.time_ns, time_zero_ns),
            packet_id: event.packet_id,
            node_id: topology.endpoint, // Endpoint node index
            link_id: topology.nodes[topology.endpoint].get_edgeside_out_id(), // Endpoint->Relay link
            contains_decoy: false,
            bypass: false,
            replace: false,
            is_client: false,
            q_sequence_nr: 0, // Will be overwritten by push()
            #[cfg(debug_assertions)]
            debug_note: Some("WebServer initial send".to_string()),
        };
        sq.push(simul_event);
    }

    si.dependent_tx = traffic_events.dependent_tx.clone();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_parse_trace_decoy_error() {
        // Create a trace with decoy packet (sp)
        let trace_with_decoy = "0,s\n1000,sp\n2000,r\n";

        // Load a minimal topology for testing
        let (topology, _) =
            crate::topology::parse::load_topology_from_file("tests/cfg/basic_test.toml")
                .expect("Failed to load topology");

        let delay = Duration::from_millis(20);

        // This should return an error because of the decoy packet
        let result = parse_trace(trace_with_decoy, &topology, delay);

        assert!(result.is_err());
        match result {
            Err(TraceParseError::DecoyInTrace) => {
                // Expected error
            }
            _ => panic!("Expected DecoyInTrace error"),
        }
    }

    #[test]
    fn test_parse_trace_decoy_error_rp() {
        // Create a trace with decoy packet (rp)
        let trace_with_decoy = "0,s\n1000,r\n2000,rp\n";

        // Load a minimal topology for testing
        let (topology, _) =
            crate::topology::parse::load_topology_from_file("tests/cfg/basic_test.toml")
                .expect("Failed to load topology");

        let delay = Duration::from_millis(20);

        // This should return an error because of the decoy packet
        let result = parse_trace(trace_with_decoy, &topology, delay);

        assert!(result.is_err());
        match result {
            Err(TraceParseError::DecoyInTrace) => {
                // Expected error
            }
            _ => panic!("Expected DecoyInTrace error"),
        }
    }
}
