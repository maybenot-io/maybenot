//! Settings module for creating pre-configured network simulation topologies.
//!
//! This module provides templates for common network topologies used in traffic
//! analysis defense simulations. Each template returns a (NetworkTopology, NetworkLinkState)
//! tuple that can be used directly with the simulator.
//!
//! # Example
//!
//! ```rust
//! use maybenot_simulator::settings::Setting;
//! use rand::rng;
//!
//! // Create topology and link-state from template
//! let (topology, link_state) = Setting::Vpn.create().unwrap();
//!
//! // Clone and randomize for parallel simulation runs (±20% variation)
//! let mut rng = rng();
//! let randomized_link_state = link_state.clone_randomized(&mut rng, 0.2);
//! ```

use crate::links::LinkType;
use crate::topology::{NetworkLinkState, NetworkTopology, load_topology_from_str};
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

/// Default packet size for WireGuard simulations (MTU).
pub const PACKET_SIZE_WG: usize = 1500;

/// Packet size for Tor cell simulations.
/// Note: Tor support in the simulator is planned for future work.
pub const PACKET_SIZE_TOR: usize = 514;

/// Maximum allowed packet size for simulations.
/// Set to jumbo frame MTU (9000 bytes) as a reasonable upper bound.
/// Standard Ethernet MTU is 1500, jumbo frames go up to 9000.
/// Values beyond this are unrealistic for network traffic simulation.
pub const PACKET_SIZE_MAX: usize = 9000;

/// Error type for setting creation failures.
#[derive(Debug)]
pub enum SettingError {
    /// The topology file was not found.
    FileNotFound(io::Error),
    /// Failed to read the topology file (permissions, I/O error, etc.)
    FileReadError(io::Error),
    /// The topology file content is invalid (parse error, invalid config, etc.)
    InvalidContent(String),
    /// Packet size is invalid (zero or exceeds PACKET_SIZE_MAX).
    InvalidPacketSize(usize),
}

impl fmt::Display for SettingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SettingError::FileNotFound(e) => write!(f, "topology file not found: {}", e),
            SettingError::FileReadError(e) => write!(f, "failed to read topology file: {}", e),
            SettingError::InvalidContent(msg) => write!(f, "invalid topology content: {}", msg),
            SettingError::InvalidPacketSize(size) => write!(
                f,
                "invalid packet size: {} (must be 1-{} bytes)",
                size, PACKET_SIZE_MAX
            ),
        }
    }
}

impl std::error::Error for SettingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SettingError::FileNotFound(e) | SettingError::FileReadError(e) => Some(e),
            SettingError::InvalidContent(_) | SettingError::InvalidPacketSize(_) => None,
        }
    }
}

impl From<io::Error> for SettingError {
    fn from(err: io::Error) -> Self {
        if err.kind() == io::ErrorKind::NotFound {
            SettingError::FileNotFound(err)
        } else {
            SettingError::FileReadError(err)
        }
    }
}

// Embed TOML files at compile time from templates subfolder
const VPN_TOML: &str = include_str!("templates/vpn.toml");
const MULTIHOP_GUARD_TOML: &str = include_str!("templates/multihop_guard.toml");
const MULTIHOP_EXIT_TOML: &str = include_str!("templates/multihop_exit.toml");

/// Available network topology settings for traffic analysis defense simulations.
///
/// Each setting creates a different network topology with varying numbers of
/// nodes and links. The topologies differ in where Maybenot defenses run.
///
/// # Example
///
/// ```rust
/// use maybenot_simulator::settings::Setting;
/// use rand::rng;
///
/// // Create topology and link-state
/// let (topology, link_state) = Setting::Vpn.create().unwrap();
///
/// // Clone and randomize for parallel runs (±20% variation)
/// let mut rng = rng();
/// let randomized_link_state = link_state.clone_randomized(&mut rng, 0.2);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// VPN topology: Client (Maybenot) ↔ Relay (Maybenot) ↔ Endpoint
    ///
    /// This creates a simple VPN topology with 3 nodes and 4 bidirectional links.
    /// The client and relay both run Maybenot defenses.
    ///
    /// # Topology
    ///
    /// - Node 0: ClientMaybenot
    /// - Node 1: RelayMaybenot
    /// - Node 2: EndpointBasic
    ///
    /// # Links (default parameters)
    ///
    /// - Links 0-1: Client ↔ Relay (100 Mbps, 10ms propagation)
    /// - Links 2-3: Relay ↔ Endpoint (1 Gbps, 5ms propagation)
    Vpn,

    /// VPN topology with custom client-relay link parameters.
    ///
    /// Same as `Vpn` but with user-specified throughput and round-trip time
    /// for the client ↔ relay link (links 0 and 1).
    VpnCustom {
        /// Throughput in megabits per second for client ↔ relay link
        mbps: u64,
        /// Round-trip time for client ↔ relay link (propagation = rtt/2)
        rtt: Duration,
    },

    /// Multi-hop topology with Maybenot on Guard node.
    ///
    /// This creates a 2-hop topology where the first hop (guard) runs Maybenot
    /// defenses. The topology has 4 nodes and 6 bidirectional links.
    ///
    /// # Topology
    ///
    /// - Node 0: ClientMaybenot
    /// - Node 1: RelayMaybenot (Guard/first hop)
    /// - Node 2: RouterBasic (Exit/second hop)
    /// - Node 3: EndpointBasic
    ///
    /// # Links (default parameters)
    ///
    /// - Links 0-1: Client ↔ Guard (100 Mbps, 10ms propagation)
    /// - Links 2-3: Guard ↔ Exit (1 Gbps, 5ms propagation)
    /// - Links 4-5: Exit ↔ Endpoint (1 Gbps, 5ms propagation)
    MultihopGuard,

    /// Multi-hop topology with Maybenot on Exit node.
    ///
    /// This creates a 2-hop topology where the second hop (exit) runs Maybenot
    /// defenses. The topology has 4 nodes and 6 bidirectional links.
    ///
    /// # Topology
    ///
    /// - Node 0: ClientMaybenot
    /// - Node 1: RouterBasic (Guard/first hop)
    /// - Node 2: RelayMaybenot (Exit/second hop)
    /// - Node 3: EndpointBasic
    ///
    /// # Links (default parameters)
    ///
    /// - Links 0-1: Client ↔ Guard (100 Mbps, 10ms propagation)
    /// - Links 2-3: Guard ↔ Exit (1 Gbps, 5ms propagation)
    /// - Links 4-5: Exit ↔ Endpoint (1 Gbps, 5ms propagation)
    MultihopExit,

    /// Custom topology loaded from a TOML file.
    ///
    /// This allows loading any custom network topology from a file path.
    /// The file must contain valid TOML configuration with Node and Link
    /// definitions.
    ///
    /// The `packet_size` field allows specifying non-default packet sizes,
    /// primarily to support Tor cell sizes (514 bytes) instead of the default
    /// WireGuard MTU (1500 bytes). More comprehensive Tor support is planned
    /// for future work.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use maybenot_simulator::settings::Setting;
    /// use std::path::PathBuf;
    ///
    /// let setting = Setting::Custom {
    ///     path: PathBuf::from("my_topology.toml"),
    ///     packet_size: 1500,  // Use 514 for Tor simulations
    /// };
    /// let (topology, link_state) = setting.create().unwrap();
    /// ```
    Custom {
        /// Path to the TOML topology file
        path: PathBuf,
        /// Packet size in bytes (default: 1500 for WireGuard, use 514 for Tor)
        packet_size: usize,
    },
}

impl Setting {
    /// Create a network topology and link-state with default parameters.
    ///
    /// Returns a Result containing a tuple of (NetworkTopology, NetworkLinkState)
    /// that can be used directly with the simulator. The link-state can be cloned
    /// and randomized for parallel simulation runs.
    ///
    /// # Errors
    ///
    /// - [`SettingError::FileNotFound`] - If the topology file does not exist
    ///   (`Custom` variant only)
    /// - [`SettingError::FileReadError`] - If the topology file cannot be read
    ///   (`Custom` variant only)
    /// - [`SettingError::InvalidContent`] - If the TOML configuration is invalid
    ///   or contains errors
    ///
    /// # Example
    ///
    /// ```rust
    /// use maybenot_simulator::settings::Setting;
    ///
    /// let (topology, link_state) = Setting::Vpn.create().unwrap();
    /// assert_eq!(link_state.link_count(), 4);
    ///
    /// let (topology, link_state) = Setting::MultihopGuard.create().unwrap();
    /// assert_eq!(link_state.link_count(), 6);
    /// ```
    pub fn create(&self) -> Result<(NetworkTopology, NetworkLinkState), SettingError> {
        match self {
            Setting::Vpn | Setting::VpnCustom { .. } => {
                let (topology, mut link_state) =
                    load_topology_from_str(VPN_TOML).map_err(SettingError::InvalidContent)?;

                // Apply custom parameters if VpnCustom
                if let Setting::VpnCustom { mbps, rtt } = self {
                    // Convert mbps to bps, rtt to one-way propagation delay
                    let tput_bps = mbps * 1_000_000;
                    let prop = *rtt / 2;

                    // Modify links 0 (client upstream) and 1 (client downstream)
                    for link_id in [0, 1] {
                        if let Some(LinkType::FixedTput(link)) = link_state.get_link_mut(link_id) {
                            link.tput_bps = tput_bps;
                            link.prop_us = prop;
                        }
                    }
                }
                Ok((topology, link_state))
            }
            Setting::MultihopGuard => {
                load_topology_from_str(MULTIHOP_GUARD_TOML).map_err(SettingError::InvalidContent)
            }
            Setting::MultihopExit => {
                load_topology_from_str(MULTIHOP_EXIT_TOML).map_err(SettingError::InvalidContent)
            }
            Setting::Custom { path, packet_size } => {
                // Validate packet_size
                if *packet_size == 0 || *packet_size > PACKET_SIZE_MAX {
                    return Err(SettingError::InvalidPacketSize(*packet_size));
                }

                let content = std::fs::read_to_string(path)?;
                let (topology, mut link_state) =
                    load_topology_from_str(&content).map_err(SettingError::InvalidContent)?;
                link_state.packet_size = *packet_size;
                Ok((topology, link_state))
            }
        }
    }
}
