// Submodules
pub mod maybenot_nodes;
pub mod nodes;
pub mod parse;

// Re-exports - public API items
pub use parse::{load_topology_from_file, load_topology_from_str};

// Internal types exposed for testing, tooling, and benchmarking
pub use maybenot_nodes::MaybenotNode;
pub use nodes::NodeType;
pub use parse::build_network_topology_from_config;

use crate::links::LinkType;
use crate::settings::PACKET_SIZE_WG;
use parse::NetworkConfig;
use rand::Rng;

#[derive(Debug, Clone)]
pub struct NetworkLinkState {
    pub links: Vec<LinkType>,
    /// Packet size in bytes used for transmission delay calculations.
    /// Default is 1500 (WireGuard MTU). Use 514 for Tor simulations.
    pub packet_size: usize,
}

impl Default for NetworkLinkState {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkLinkState {
    pub fn new() -> Self {
        Self {
            links: Vec::new(),
            packet_size: PACKET_SIZE_WG,
        }
    }

    pub fn add_link(&mut self, link: LinkType, id: usize) -> usize {
        assert_eq!(id, self.links.len(), "Link ID must match vector index");
        self.links.push(link);
        self.links.len() - 1
    }

    pub fn get_link(&self, link_index: usize) -> Option<&LinkType> {
        self.links.get(link_index)
    }

    pub fn get_link_mut(&mut self, link_index: usize) -> Option<&mut LinkType> {
        self.links.get_mut(link_index)
    }

    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    pub fn links(&self) -> &[LinkType] {
        &self.links
    }

    /// Clone this link-state and randomize all link parameters.
    ///
    /// This is the recommended method for parallel simulation runs where
    /// each run should have slightly different network conditions.
    ///
    /// The `factor` parameter controls the variation range (e.g., 0.2 = ±20%).
    /// For fixed throughput links, applies ±factor variation to throughput and propagation delay.
    /// For trace-based links, randomizes the starting offset in the trace.
    pub fn clone_randomized<R: Rng>(&self, rng: &mut R, factor: f64) -> Self {
        let mut cloned = self.clone();
        for link in &mut cloned.links {
            link.randomize(rng, factor);
        }
        cloned
    }
}

#[derive(Debug)]
pub struct NetworkTopology {
    pub network_config: NetworkConfig,
    pub nodes: Vec<NodeType>,
    pub routes: Vec<Vec<Option<usize>>>, // routes[node_id][inlink] = Some(outlink) or None
    pub client: usize,
    pub endpoint: usize,
    pub has_mb: bool,
    pub mb_client: usize,
    pub mb_server: usize,
}

impl NetworkTopology {
    pub fn new(network_config: NetworkConfig) -> Self {
        Self {
            network_config,
            nodes: Vec::new(),
            routes: Vec::new(),
            client: 0,
            endpoint: 0,
            has_mb: false,
            mb_client: 0,
            mb_server: 0,
        }
    }

    pub fn new_from_config(&self) -> Self {
        build_network_topology_from_config(&self.network_config)
            .expect("Failed to build network topology from config")
    }

    /// Get outgoing link for a node given an incoming link
    pub fn get_outlink(&self, node_id: usize, in_link: usize) -> Option<usize> {
        *self.routes.get(node_id)?.get(in_link)?
    }

    pub fn add_node(&mut self, node: NodeType, id: usize) -> usize {
        assert_eq!(id, self.nodes.len(), "Node ID must match vector index");
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    pub fn get_maybenot_client(&self) -> &dyn MaybenotNode {
        match &self.nodes[self.mb_client] {
            NodeType::ClientMaybenot(client) => client,
            _ => panic!("Maybenot client node not found or wrong type"),
        }
    }

    pub fn get_maybenot_relay(&self) -> &dyn MaybenotNode {
        match &self.nodes[self.mb_server] {
            NodeType::RelayMaybenot(server) => server,
            NodeType::RelayMaybenotEndpoint(server) => server,
            _ => panic!("Maybenot server node not found or wrong type"),
        }
    }
}
