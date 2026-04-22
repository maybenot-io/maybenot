use crate::links::{LinkType, load_linktrace_from_file};
use crate::topology::maybenot_nodes::{ClientMaybenot, RelayMaybenot, RelayMaybenotEndpoint};
use crate::topology::nodes::NodeType;
use crate::topology::{NetworkLinkState, NetworkTopology};
use crate::{DecoyLimitConfig, DelayLimitConfig};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;

// TOML configuration structures
#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    #[serde(rename = "Node")]
    pub nodes: Vec<NodeConfig>,
    #[serde(rename = "Link")]
    pub links: Vec<LinkConfig>,
    #[serde(rename = "Route", default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NodeConfig {
    pub id: usize,
    #[serde(rename = "type")]
    pub node_type: String,
    pub coreside_out: Option<usize>,
    pub edgeside_in: Option<usize>,
    pub edgeside_out: Option<usize>,
    #[serde(flatten)]
    pub params: HashMap<String, toml::Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LinkConfig {
    pub id: usize,
    pub from: usize,
    pub to: usize,
    #[serde(rename = "type")]
    pub link_type: String,
    #[serde(flatten)]
    pub params: HashMap<String, toml::Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouteConfig {
    pub node_id: usize,
    pub forwarding_rules: Vec<ForwardingRule>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ForwardingRule {
    pub in_link: usize,
    pub out_link: usize,
}

// Main parsing functions

/// Loads network topology and link configuration from a TOML file.
///
/// # Arguments
///
/// * `path` - File path to TOML configuration (supports any type implementing `AsRef<Path>`)
///
/// # Returns
///
/// * `Ok((NetworkTopology, NetworkLinkstate))` - Parsed network configuration and initial link states
/// * `Err(String)` - Detailed error message if file reading or parsing fails
///
/// # TOML Format
///
/// The configuration file should define nodes and links in TOML format:
///
/// ```toml
/// [[Node]]
/// id = 0
/// type = "ClientMaybenot"
/// coreside_out = 0
///
/// [[Link]]  
/// id = 0
/// from = 0
/// to = 1
/// type = "FixedTput"
/// tput_bps = 100_000_000
/// ```
///
/// # See Also
///
/// - [`load_topology_from_str`] to parse from string instead of file
/// - [`build_topology_from_config`] for programmatic topology construction
pub fn load_topology_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<(NetworkTopology, NetworkLinkState), String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Network error: Failed to read file: {}", e))?;

    load_topology_from_str(&content)
}

/// Parses network topology from a TOML configuration string.
///
/// This is the core parsing function that converts TOML configuration into
/// runnable network topology and link state objects.
///
/// # Arguments
///
/// * `toml_str` - TOML configuration string containing Node and Link
///   definitions
///
/// # Returns
///
/// * `Ok((NetworkTopology, NetworkLinkstate))` - Parsed and validated network
///   configuration
/// * `Err(String)` - Detailed error message with parsing failure details
///
/// # Error Conditions
///
/// - Invalid TOML syntax
/// - Missing required node/link parameters  
/// - Inconsistent node/link ID references
/// - Invalid node or link type specifications
/// - Link trace file loading failures
///
pub fn load_topology_from_str(
    toml_str: &str,
) -> Result<(NetworkTopology, NetworkLinkState), String> {
    let config: NetworkConfig = toml::from_str(toml_str)
        .map_err(|e| format!("Network error: Failed to parse TOML: {}", e))?;

    build_topology_from_config(config)
}

/// Create network from parsed configuration
pub fn build_topology_from_config(
    config: NetworkConfig,
) -> Result<(NetworkTopology, NetworkLinkState), String> {
    Ok((
        build_network_topology_from_config(&config)?,
        build_network_link_state_from_config(&config)?,
    ))
}

/// Create network from parsed configuration
pub fn build_network_topology_from_config(
    config: &NetworkConfig,
) -> Result<NetworkTopology, String> {
    let mut topology = NetworkTopology::new(config.clone());

    // Find and validate client and endpoint nodes
    let mut client_id: Option<usize> = None;
    let mut mb_server: Option<usize> = None;
    let mut endpoint_id: Option<usize> = None;

    for node_config in &config.nodes {
        match node_config.node_type.as_str() {
            "ClientBasic" => {
                if client_id.is_some() {
                    return Err(
                        "Network error: Multiple Client nodes found. Only one is allowed."
                            .to_string(),
                    );
                }
                client_id = Some(node_config.id);
            }
            "ClientMaybenot" => {
                if client_id.is_some() {
                    return Err(
                        "Network error: Multiple Client nodes found. Only one is allowed."
                            .to_string(),
                    );
                }
                client_id = Some(node_config.id);
                topology.mb_client = node_config.id;
            }
            "RelayMaybenot" => {
                if mb_server.is_some() {
                    return Err(
                        "Network error: Multiple RelayMaybenot nodes found. Only one is allowed."
                            .to_string(),
                    );
                }
                mb_server = Some(node_config.id);
            }

            "EndpointBasic" => {
                if endpoint_id.is_some() {
                    return Err(
                        "Network error: Multiple EndpointBasic nodes found. Only one is allowed."
                            .to_string(),
                    );
                }
                endpoint_id = Some(node_config.id);
            }

            "RelayMaybenotEndpoint" => {
                if mb_server.is_some() {
                    return Err(
                        "Network error: Multiple Maybenot server nodes found. Only one is allowed."
                            .to_string(),
                    );
                }
                if endpoint_id.is_some() {
                    return Err(
                        "Network error: Multiple endpoint nodes found. Only one is allowed."
                            .to_string(),
                    );
                }
                mb_server = Some(node_config.id);
                endpoint_id = Some(node_config.id); // RelayMaybenotEndpoint acts as both
            }

            _ => {} // Other node types are fine
        }
    }

    // Ensure we have exactly one client and one endpoint
    let client = client_id.ok_or_else(|| {
        "Network error: No Client node found. Exactly one is required.".to_string()
    })?;
    let endpoint = endpoint_id.ok_or_else(|| "Network error: No endpoint node found. Exactly one EndpointBasic or RelayMaybenotEndpoint is required.".to_string())?;

    // Set the client and endpoint IDs
    topology.client = client;
    topology.endpoint = endpoint;

    // Set MB fields
    if let Some(mb_server_id) = mb_server {
        topology.has_mb = true;
        topology.mb_server = mb_server_id;
    }

    // Create nodes
    for node_config in &config.nodes {
        // Convert TOML values to strings for the factory function
        let params = convert_toml_params(&node_config.params);

        let node = create_node(
            &node_config.node_type,
            node_config.id,
            node_config.coreside_out,
            node_config.edgeside_in,
            node_config.edgeside_out,
            &params,
        )
        .map_err(|e| {
            format!(
                "Network error: Failed to create node {}: {}",
                node_config.id, e
            )
        })?;
        topology.add_node(node, node_config.id);
    }

    // Build routing matrix
    let num_nodes = config.nodes.len();
    let num_links = config.links.len();

    // Initialize routing matrix with None values
    topology.routes = vec![vec![None; num_links]; num_nodes];

    // Fill routing matrix from config
    for route_config in &config.routes {
        let node_id = route_config.node_id;
        if node_id >= num_nodes {
            return Err(format!(
                "Network error: Invalid node_id {} in routes",
                node_id
            ));
        }

        for rule in &route_config.forwarding_rules {
            let in_link = rule.in_link;
            let out_link = rule.out_link;

            if in_link >= num_links {
                return Err(format!(
                    "Network error: Invalid in_link {} for node {}",
                    in_link, node_id
                ));
            }
            if out_link >= num_links {
                return Err(format!(
                    "Network error: Invalid out_link {} for node {}",
                    out_link, node_id
                ));
            }

            topology.routes[node_id][in_link] = Some(out_link);
        }
    }

    Ok(topology)
}

/// Create network from parsed configuration
pub fn build_network_link_state_from_config(
    config: &NetworkConfig,
) -> Result<NetworkLinkState, String> {
    let mut link_state = NetworkLinkState::new();

    // Create links
    for link_config in &config.links {
        // Convert TOML values to strings for the factory function
        let params = convert_toml_params(&link_config.params);

        let link = create_link(
            &link_config.link_type,
            link_config.id,
            link_config.from,
            link_config.to,
            &params,
        )
        .map_err(|e| {
            format!(
                "Network error: Failed to create link {}: {}",
                link_config.id, e
            )
        })?;

        link_state.add_link(link, link_config.id);
    }
    Ok(link_state)
}

// Helper function to convert TOML values to strings
pub fn convert_toml_params(params: &HashMap<String, toml::Value>) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for (key, value) in params {
        let value_str = match value {
            toml::Value::String(s) => s.clone(),
            toml::Value::Integer(i) => i.to_string(),
            toml::Value::Float(f) => f.to_string(),
            toml::Value::Boolean(b) => b.to_string(),
            _ => continue, // Skip unsupported parameter types
        };
        result.insert(key.clone(), value_str);
    }
    result
}

/// Load propagation delays from a text file, File format: one integer per line
/// representing microseconds of propagation delay Line number corresponds to
/// millisecond of simulation time (starting from 0)
pub fn load_propagation_file<P: AsRef<Path>>(path: P) -> Result<Vec<u64>, String> {
    let file = fs::File::open(&path).map_err(|e| {
        format!(
            "Failed to open propagation file '{}': {}",
            path.as_ref().display(),
            e
        )
    })?;

    let reader = BufReader::new(file);
    let mut propagation_values = Vec::new();

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(|e| {
            format!(
                "Failed to read line {} from propagation file '{}': {}",
                line_num + 1,
                path.as_ref().display(),
                e
            )
        })?;

        let line = line.trim();
        if line.is_empty() {
            continue; // Skip empty lines
        }

        let value = line.parse::<u64>().map_err(|e| {
            format!(
                "Invalid propagation value '{}' on line {} in file '{}': {}",
                line,
                line_num + 1,
                path.as_ref().display(),
                e
            )
        })?;

        propagation_values.push(value);
    }

    if propagation_values.is_empty() {
        return Err(format!(
            "Propagation file '{}' contains no valid values",
            path.as_ref().display()
        ));
    }

    Ok(propagation_values)
}

// Factory functions

// Factory function for creating nodes from TOML configuration
pub(crate) fn create_node(
    node_type: &str,
    id: usize,
    coreside_out: Option<usize>,
    edgeside_in: Option<usize>,
    edgeside_out: Option<usize>,
    params: &HashMap<String, String>,
) -> Result<NodeType, String> {
    use crate::topology::nodes::{ClientBasic, EndpointBasic, RouterBasic};

    match node_type {
        "ClientBasic" => {
            let coreside = coreside_out.ok_or("ClientBasic requires coreside_out")?;
            Ok(NodeType::ClientBasic(ClientBasic::new(id, coreside)))
        }
        "RouterBasic" => {
            let coreside_out_val = coreside_out.ok_or("RouterBasic requires coreside_out")?;
            let edgeside_in_val = edgeside_in.ok_or("RouterBasic requires edgeside_in")?;
            let edgeside_out_val = edgeside_out.ok_or("RouterBasic requires edgeside_out")?;
            Ok(NodeType::RouterBasic(RouterBasic::new(
                id,
                coreside_out_val,
                edgeside_in_val,
                edgeside_out_val,
            )))
        }
        "EndpointBasic" => {
            let edgeside = edgeside_out.ok_or("EndpointBasic requires edgeside_out")?;
            Ok(NodeType::EndpointBasic(EndpointBasic::new(id, edgeside)))
        }
        "ClientMaybenot" => {
            let coreside = coreside_out.ok_or("ClientMaybenot requires coreside_out")?;

            Ok(NodeType::ClientMaybenot(ClientMaybenot::new(
                id,
                coreside,
                Vec::new(),
                &DecoyLimitConfig::None,
                &DelayLimitConfig::None,
                false,
                None,
                None,
            )))
        }
        "RelayMaybenot" => {
            let coreside_out_val = coreside_out.ok_or("RelayMaybenot requires coreside_out")?;
            let edgeside_in_val = edgeside_in.ok_or("RelayMaybenot requires edgeside_in")?;
            let edgeside_out_val = edgeside_out.ok_or("RelayMaybenot requires edgeside_out")?;

            Ok(NodeType::RelayMaybenot(RelayMaybenot::new(
                id,
                coreside_out_val,
                edgeside_in_val,
                edgeside_out_val,
                Vec::new(),
                &DecoyLimitConfig::None,
                &DelayLimitConfig::None,
                false,
                None,
                None,
            )))
        }
        "RelayMaybenotEndpoint" => {
            // RelayMaybenotEndpoint uses edgeside_in and edgeside_out
            let edgeside_out_val =
                edgeside_out.ok_or("RelayMaybenotEndpoint requires edgeside_out")?;
            let edgeside_in_val =
                edgeside_in.ok_or("RelayMaybenotEndpoint requires edgeside_in")?;

            // Parse endpoint_prop_us parameter specific to
            // RelayMaybenotEndpoint
            let endpoint_prop_us = params
                .get("endpoint_prop_us")
                .and_then(|s| s.parse::<u64>().ok())
                .map(Duration::from_micros)
                .unwrap_or(Duration::from_micros(0)); // Default to 0us if not specified

            Ok(NodeType::RelayMaybenotEndpoint(RelayMaybenotEndpoint::new(
                id,
                edgeside_in_val,
                edgeside_out_val,
                Vec::new(),
                &DecoyLimitConfig::None,
                &DelayLimitConfig::None,
                false,
                None,
                None,
                endpoint_prop_us,
            )))
        }
        _ => Err(format!("Unknown node type: {}", node_type)),
    }
}

// Factory function for creating links from TOML configuration
pub fn create_link(
    link_type: &str,
    id: usize,
    from: usize,
    to: usize,
    params: &HashMap<String, String>,
) -> Result<LinkType, String> {
    use crate::links::{FixedTputLink, HiTraceTputLink, StdTraceTputLink};

    // Check for propagation parameters - exactly one must be present
    let has_prop_us = params.contains_key("prop_us");
    let has_prop_us_file = params.contains_key("prop_us_file");

    if !has_prop_us && !has_prop_us_file {
        return Err("Link must have either 'prop_us' or 'prop_us_file' parameter".to_string());
    }

    if has_prop_us && has_prop_us_file {
        return Err("Link cannot have both 'prop_us' and 'prop_us_file' parameters".to_string());
    }

    // Parse propagation configuration
    let (fixed_prop_us, prop_us_vec) = if has_prop_us {
        let prop_us = params
            .get("prop_us")
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_micros)
            .ok_or("Invalid prop_us value - must be a valid integer")?;
        (prop_us, Vec::new())
    } else {
        let prop_us_file = params.get("prop_us_file").unwrap();
        let prop_us_vec = load_propagation_file(prop_us_file)
            .map_err(|e| format!("Failed to load propagation file: {}", e))?;
        (Duration::default(), prop_us_vec)
    };

    match link_type {
        "FixedTput" => {
            // Simplex link - requires tput_bps parameter
            let tput = params
                .get("tput_bps")
                .ok_or("FixedTput requires tput_bps parameter")?
                .parse::<u64>()
                .map_err(|_| "Invalid tput_bps value - must be a valid u64")?;

            let fixed_propagation = prop_us_vec.is_empty();
            Ok(LinkType::FixedTput(FixedTputLink::new(
                id,
                from,
                to,
                fixed_prop_us,
                tput,
                fixed_propagation,
                prop_us_vec,
            )))
        }
        "HiTraceTput" => {
            let trace_file = params
                .get("trace_file")
                .ok_or("HiTraceTput requires trace_file parameter")?;

            let linktrace = load_linktrace_from_file(trace_file)
                .map_err(|e| format!("Failed to load trace file '{}': {}", trace_file, e))?;

            let fixed_propagation = prop_us_vec.is_empty();
            Ok(LinkType::HiTraceTput(HiTraceTputLink::new(
                id,
                from,
                to,
                fixed_prop_us,
                linktrace,
                fixed_propagation,
                prop_us_vec,
            )))
        }
        "StdTraceTput" => {
            let trace_file = params
                .get("trace_file")
                .ok_or("StdTraceTput requires trace_file parameter")?;

            let linktrace = load_linktrace_from_file(trace_file)
                .map_err(|e| format!("Failed to load trace file '{}': {}", trace_file, e))?;

            let fixed_propagation = prop_us_vec.is_empty();
            Ok(LinkType::StdTraceTput(StdTraceTputLink::new(
                id,
                from,
                to,
                fixed_prop_us,
                linktrace,
                fixed_propagation,
                prop_us_vec,
            )))
        }
        _ => Err(format!("Unknown link type: {}", link_type)),
    }
}
