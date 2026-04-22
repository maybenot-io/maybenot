use crate::links::LinkType;
use crate::topology::maybenot_nodes::{ClientMaybenot, RelayMaybenot, RelayMaybenotEndpoint};
use crate::topology::{NetworkLinkState, NetworkTopology};
use crate::{SimEvent, SimInfo, SimQueue};
use log::debug;
use maybenot::TriggerEvent;
use std::time::Duration;

/// Internal node type dispatch enum.
///
/// # Internal API
///
/// This enum is exposed for testing and tooling. The structure may change between versions.
/// Most users should not need to interact with this directly.
#[derive(Debug)]
pub enum NodeType {
    ClientBasic(ClientBasic),
    RouterBasic(RouterBasic),
    EndpointBasic(EndpointBasic),
    ClientMaybenot(ClientMaybenot),
    RelayMaybenot(RelayMaybenot),
    RelayMaybenotEndpoint(RelayMaybenotEndpoint),
}

impl NodeType {
    pub fn handle_event(
        &self,
        s_event: &SimEvent,
        topology: &NetworkTopology,
        link_state: &mut NetworkLinkState,
        si: &SimInfo,
        sq: &mut SimQueue,
    ) {
        match self {
            NodeType::ClientBasic(node) => node.handle_event(s_event, topology, link_state, si, sq),
            NodeType::RouterBasic(node) => node.handle_event(s_event, topology, link_state, si, sq),
            NodeType::EndpointBasic(node) => {
                node.handle_event(s_event, topology, link_state, si, sq)
            }
            NodeType::ClientMaybenot(node) => {
                node.handle_event(s_event, topology, link_state, si, sq)
            }
            NodeType::RelayMaybenot(node) => {
                node.handle_event(s_event, topology, link_state, si, sq)
            }
            NodeType::RelayMaybenotEndpoint(node) => {
                node.handle_event(s_event, topology, link_state, si, sq)
            }
        }
    }

    pub fn node_id(&self) -> usize {
        match self {
            NodeType::ClientBasic(node) => node.id,
            NodeType::RouterBasic(node) => node.id,
            NodeType::EndpointBasic(node) => node.id,
            NodeType::ClientMaybenot(node) => node.id,
            NodeType::RelayMaybenot(node) => node.id,
            NodeType::RelayMaybenotEndpoint(node) => node.id,
        }
    }

    pub fn get_coreside_out_id(&self) -> usize {
        match self {
            NodeType::ClientBasic(node) => node.coreside_out,
            NodeType::RouterBasic(node) => node.coreside_out,
            NodeType::EndpointBasic(_) => {
                panic!("EndpointBasic does not have a coreside link")
            }
            NodeType::ClientMaybenot(node) => node.coreside_out,
            NodeType::RelayMaybenot(node) => node.coreside_out,
            NodeType::RelayMaybenotEndpoint(_) => {
                panic!("RelayMaybenotEndpoint does not have a coreside link")
            }
        }
    }

    pub fn get_edgeside_out_id(&self) -> usize {
        match self {
            NodeType::ClientBasic(_) => panic!("ClientBasic does not have an edgeside link"),
            NodeType::RouterBasic(node) => node.edgeside_out,
            NodeType::EndpointBasic(node) => node.edgeside_out,
            NodeType::ClientMaybenot(_) => panic!("ClientMaybenot does not have an edgeside link"),
            NodeType::RelayMaybenot(node) => node.edgeside_out,
            NodeType::RelayMaybenotEndpoint(node) => node.edgeside_out,
        }
    }

    pub fn get_edgeside_in_id(&self) -> usize {
        match self {
            NodeType::ClientBasic(_) => panic!("ClientBasic does not have an edgeside link"),
            NodeType::RouterBasic(_) => panic!("RouterBasic does not have edgeside_in"),
            NodeType::EndpointBasic(_) => {
                panic!("EndpointBasic does not have edgeside_in")
            }
            NodeType::ClientMaybenot(_) => panic!("ClientMaybenot does not have an edgeside link"),
            NodeType::RelayMaybenot(node) => node.edgeside_in,
            NodeType::RelayMaybenotEndpoint(node) => node.edgeside_in,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            NodeType::ClientBasic(_) => "ClientBasic",
            NodeType::RouterBasic(_) => "RouterBasic",
            NodeType::EndpointBasic(_) => "EndpointBasic",
            NodeType::ClientMaybenot(_) => "ClientMaybenot",
            NodeType::RelayMaybenot(_) => "RelayMaybenot",
            NodeType::RelayMaybenotEndpoint(_) => "RelayMaybenotEndpoint",
        }
    }
}

pub fn check_dependent_packets(
    s_event: &SimEvent,
    si: &SimInfo,
    sq: &mut SimQueue,
    outgoing_link: &LinkType,
    endpoint_to_relay_extra_us: u64,
) {
    debug!("\tqueue {:#?} tx_depend check", TriggerEvent::NormalRecv);

    if !si.dependent_tx[s_event.packet_id].is_empty() {
        let link_id = outgoing_link.link_id();

        for (new_pktidx, delta, event_kind) in &si.dependent_tx[s_event.packet_id] {
            debug!(
                "\tqueue tx_depend new_id: {:#?}   delta: {:#?}   kind: {:#?}",
                new_pktidx, delta, event_kind
            );
            let additional_duration =
                Duration::from_nanos(*delta as u64 + endpoint_to_relay_extra_us * 1000);

            sq.push(SimEvent {
                event: TriggerEvent::NormalQueued,
                time: s_event.time + additional_duration,
                packet_id: *new_pktidx,
                node_id: s_event.node_id,
                link_id,
                contains_decoy: false,
                bypass: false,
                replace: false,
                is_client: false,
                q_sequence_nr: 0, // Will be overwritten by push()
                #[cfg(debug_assertions)]
                debug_note: None,
            });
        }
    }
}

pub(crate) fn make_network_receive_from_sent(
    s_event: &SimEvent,
    _topology: &NetworkTopology,
    link_state: &mut NetworkLinkState,
    _si: &SimInfo,
    sq: &mut SimQueue,
) {
    let new_t_event = match s_event.event {
        TriggerEvent::NormalQueued => TriggerEvent::NormalRecv,
        TriggerEvent::PacketSent => TriggerEvent::PacketRecv,
        _ => panic!("Unexpected event type: {:?}", s_event.event),
    };
    let link_id = s_event.link_id;

    // Get values we need before mutable borrow
    let to_node = link_state.links[link_id].to_node();
    // s_event.time is already a Duration relative to simulation time zero, so
    // it doubles as the elapsed-time value that link sampling expects.
    let current_duration = s_event.time;
    let prop_us = if link_state.links[link_id].fixed_propagation() {
        link_state.links[link_id].get_prop_us_fixed()
    } else {
        let current_time_ms = current_duration.as_millis() as usize;
        link_state.links[link_id].get_prop_us_variable(current_time_ms)
    };

    debug!(
        "\tNode {} sending xxSent -> creating xxRecv at node via link {}",
        s_event.node_id, link_id
    );
    //debug!("\ts_event time: {:?}", s_event.time);

    // Now we can safely do the mutable borrow for sampling
    let transmission_delay =
        link_state.links[link_id].sample(current_duration, link_state.packet_size);

    let recv_s_event = SimEvent {
        event: new_t_event,
        time: s_event.time + transmission_delay + prop_us,
        packet_id: s_event.packet_id,
        node_id: to_node,
        link_id,
        contains_decoy: s_event.contains_decoy,
        bypass: false,
        replace: false,
        is_client: false,
        q_sequence_nr: 0, // Will be overwritten by push()
        #[cfg(debug_assertions)]
        debug_note: None,
    };
    sq.push(recv_s_event);
}

pub(crate) fn forward_network_receive_from_receive(
    s_event: &SimEvent,
    topology: &NetworkTopology,
    link_state: &mut NetworkLinkState,
    _si: &SimInfo,
    sq: &mut SimQueue,
) {
    let new_t_event = match s_event.event {
        TriggerEvent::NormalRecv => TriggerEvent::NormalRecv,
        TriggerEvent::PacketRecv => TriggerEvent::PacketRecv,
        _ => panic!("Unexpected event type: {:?}", s_event.event),
    };

    let outgoing_link_id = topology.routes[s_event.node_id][s_event.link_id].unwrap_or_else(|| {
        panic!(
            "No outgoing link found for node {} with link index {}",
            s_event.node_id, s_event.link_id
        );
    });

    // Get immutable data first
    let to_node = link_state.links[outgoing_link_id].to_node();
    // s_event.time is already a Duration relative to simulation time zero.
    let current_duration = s_event.time;

    let prop_us = if link_state.links[outgoing_link_id].fixed_propagation() {
        link_state.links[outgoing_link_id].get_prop_us_fixed()
    } else {
        let current_time_ms = current_duration.as_millis() as usize;
        link_state.links[outgoing_link_id].get_prop_us_variable(current_time_ms)
    };

    // Now do the mutable borrow for sampling
    let transmission_delay =
        link_state.links[outgoing_link_id].sample(current_duration, link_state.packet_size);

    debug!(
        "\tForwarding from node {} via link {} to node {}",
        s_event.node_id, outgoing_link_id, to_node
    );

    let recv_s_event = SimEvent {
        event: new_t_event,
        time: s_event.time + transmission_delay + prop_us,
        packet_id: s_event.packet_id,
        node_id: to_node,
        link_id: outgoing_link_id,
        contains_decoy: s_event.contains_decoy,
        bypass: false,
        replace: false,
        is_client: false,
        q_sequence_nr: 0, // Will be overwritten by push()
        #[cfg(debug_assertions)]
        debug_note: None,
    };
    sq.push(recv_s_event);
}

/// A basic client node that originates traffic toward an endpoint.
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
/// Traffic flow:
/// ```text
/// Client --[coreside]--> ... --[coreside]--> Endpoint
/// Client <-[edgeside]--- ... <-[edgeside]--- Endpoint
/// ```
///
/// Client nodes only send traffic toward the endpoint, so they only have
/// `coreside_out`.
#[derive(Debug, Copy, Clone)]
pub struct ClientBasic {
    pub id: usize,
    /// Link ID for outgoing traffic toward the endpoint (forward direction)
    pub coreside_out: usize,
}

impl ClientBasic {
    pub fn new(id: usize, coreside_out: usize) -> Self {
        Self { id, coreside_out }
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
                make_network_receive_from_sent(s_event, topology, link_state, si, sq);
            }
            TriggerEvent::NormalRecv => {
                let outgoing_link_id = topology.nodes[s_event.node_id].get_coreside_out_id();
                let outgoing_link = &link_state.links[outgoing_link_id];

                check_dependent_packets(s_event, si, sq, outgoing_link, 0);
            }
            _ => {
                panic!("ClientBasic cannot handle s_event: {:?}", s_event.event);
            }
        }
    }
}

/// A basic router node that forwards traffic in both directions.
///
/// # Network Topology Directionality
///
/// Router nodes sit in the middle of the network path and forward traffic
/// bidirectionally:
/// - **coreside_out**: Forwards traffic toward the endpoint (away from
///   client)
/// - **edgeside_in**: Receives traffic from coreside (from endpoint side)
/// - **edgeside_out**: Forwards traffic back toward the client (return path)
///
/// Traffic flow through a router:
/// ```text
/// Client --> Router --[coreside_out]--> Endpoint
///            Router <-[edgeside_in]---- Endpoint
/// Client <-[edgeside_out]-- Router <--- Endpoint
/// ```
///
/// Example: In a path Client -> WLAN -> Relay -> Endpoint, the WLAN node is
/// a router.
#[derive(Debug, Copy, Clone)]
pub struct RouterBasic {
    pub id: usize,
    /// Link ID for forwarding traffic toward the endpoint (forward
    /// direction)
    pub coreside_out: usize,
    /// Link ID for receiving traffic from the coreside (from endpoint
    /// direction)
    pub edgeside_in: usize,
    /// Link ID for forwarding traffic back toward the client (return direction)
    pub edgeside_out: usize,
}

impl RouterBasic {
    pub fn new(id: usize, coreside_out: usize, edgeside_in: usize, edgeside_out: usize) -> Self {
        Self {
            id,
            coreside_out,
            edgeside_in,
            edgeside_out,
        }
    }

    pub(crate) fn handle_event(
        &self,
        s_event: &SimEvent,
        topology: &NetworkTopology,
        link_state: &mut NetworkLinkState,
        si: &SimInfo,
        sq: &mut SimQueue,
    ) {
        match &s_event.event {
            TriggerEvent::NormalRecv => {
                forward_network_receive_from_receive(s_event, topology, link_state, si, sq);
            }
            TriggerEvent::PacketRecv => {
                forward_network_receive_from_receive(s_event, topology, link_state, si, sq);
            }
            TriggerEvent::DecoyQueued { .. } | TriggerEvent::DecoyRecv => {
                // Relay handles decoy traffic
            }
            _ => {
                panic!("RouterBasic cannot handle s_event: {:?}", s_event.event);
            }
        }
    }
}

/// A basic endpoint node that receives traffic and sends responses.
///
/// # Network Topology Directionality
///
/// Endpoint nodes are at the end of the network path (core side) and only
/// respond to received traffic by sending back toward the client:
/// - **edgeside_out**: Sends response traffic back toward the client (return
///   path)
///
/// Traffic flow for an endpoint:
/// ```text
/// Client --> ... --> Endpoint (receives on coreside, no explicit link needed)
/// Client <-[edgeside_out]-- Endpoint (sends response)
/// ```
///
/// Endpoint nodes only send back toward the client, so they only have
/// `edgeside_out`.
#[derive(Debug, Copy, Clone)]
pub struct EndpointBasic {
    pub id: usize,
    /// Link ID for sending response traffic back toward the client (return
    /// direction)
    pub edgeside_out: usize,
}

impl EndpointBasic {
    pub fn new(id: usize, edgeside_out: usize) -> Self {
        Self { id, edgeside_out }
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
            TriggerEvent::NormalRecv => {
                let outgoing_link_id = topology.nodes[s_event.node_id].get_edgeside_out_id();
                let outgoing_link = &link_state.links[outgoing_link_id];

                check_dependent_packets(s_event, si, sq, outgoing_link, 0);
            }
            TriggerEvent::NormalQueued => {
                make_network_receive_from_sent(s_event, topology, link_state, si, sq);
            }
            _ => {
                panic!("EndpointBasic cannot handle s_event: {:?}", s_event.event);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_node_factory() {
        use crate::topology::parse::create_node;
        use std::collections::HashMap;

        let empty_params = HashMap::new();

        let client = create_node("ClientBasic", 1, Some(0), None, None, &empty_params).unwrap();
        assert_eq!(client.node_id(), 1);
        assert_eq!(client.type_name(), "ClientBasic");

        let router =
            create_node("RouterBasic", 2, Some(0), Some(1), Some(1), &empty_params).unwrap();
        assert_eq!(router.node_id(), 2);
        assert_eq!(router.type_name(), "RouterBasic");

        let server = create_node("EndpointBasic", 3, None, None, Some(0), &empty_params).unwrap();
        assert_eq!(server.node_id(), 3);
        assert_eq!(server.type_name(), "EndpointBasic");

        // Test new Maybenot node types - these require current_time parameter
        let mut maybenot_params = HashMap::new();
        maybenot_params.insert("current_time".to_string(), "0".to_string()); // 0 nanoseconds from now

        let client_maybenot =
            create_node("ClientMaybenot", 4, Some(2), None, None, &maybenot_params).unwrap();
        assert_eq!(client_maybenot.node_id(), 4);
        assert_eq!(client_maybenot.type_name(), "ClientMaybenot");

        let relay_maybenot = create_node(
            "RelayMaybenot",
            5,
            Some(2),
            Some(3),
            Some(3),
            &maybenot_params,
        )
        .unwrap();
        assert_eq!(relay_maybenot.node_id(), 5);
        assert_eq!(relay_maybenot.type_name(), "RelayMaybenot");

        let invalid = create_node("InvalidType", 6, None, None, None, &empty_params);
        assert!(invalid.is_err());
    }
}
