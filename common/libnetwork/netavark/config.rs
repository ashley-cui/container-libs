use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;
use regex::Regex;
use ipnet::IpNet;
use rand::Rng;

// Error types
#[derive(Debug, Clone)]
pub enum NetworkError {
    InvalidArg(String),
    NetworkExists(String),
    InvalidName(String),
    NoSuchNetwork(String),
    Other(String),
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkError::InvalidArg(msg) => write!(f, "invalid argument: {}", msg),
            NetworkError::NetworkExists(msg) => write!(f, "network already exists: {}", msg),
            NetworkError::InvalidName(msg) => write!(f, "invalid name: {}", msg),
            NetworkError::NoSuchNetwork(msg) => write!(f, "network not found: {}", msg),
            NetworkError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for NetworkError {}

// Network types matching Go types
#[derive(Debug, Clone)]
pub struct Network {
    pub name: String,
    pub id: String,
    pub driver: String,
    pub network_interface: String,
    pub created: Option<SystemTime>,
    pub subnets: Vec<Subnet>,
    pub routes: Vec<Route>,
    pub ipv6_enabled: bool,
    pub internal: bool,
    pub dns_enabled: bool,
    pub network_dns_servers: Vec<String>,
    pub labels: HashMap<String, String>,
    pub options: HashMap<String, String>,
    pub ipam_options: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Subnet {
    pub subnet: IpNet,
    pub gateway: Option<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct Route {
    pub destination: IpNet,
    pub gateway: Option<IpAddr>,
}

// Constants matching Go constants
pub mod constants {
    pub const BRIDGE_NETWORK_DRIVER: &str = "bridge";
    pub const DEFAULT_NETWORK_DRIVER: &str = "bridge";
    pub const MACVLAN_NETWORK_DRIVER: &str = "macvlan";
    pub const IPVLAN_NETWORK_DRIVER: &str = "ipvlan";

    pub const DRIVER: &str = "driver";
    pub const HOST_LOCAL_IPAM_DRIVER: &str = "host-local";
    pub const DHCP_IPAM_DRIVER: &str = "dhcp";
    pub const NONE_IPAM_DRIVER: &str = "none";

    pub const BRIDGE_MODE_MANAGED: &str = "managed";
    pub const BRIDGE_MODE_UNMANAGED: &str = "unmanaged";

    pub const VLAN_OPTION: &str = "vlan";
    pub const MTU_OPTION: &str = "mtu";
    pub const MODE_OPTION: &str = "mode";
    pub const ISOLATE_OPTION: &str = "isolate";
    pub const METRIC_OPTION: &str = "metric";
    pub const NO_DEFAULT_ROUTE: &str = "no_default_route";
    pub const VRF_OPTION: &str = "vrf";

    pub const MAX_INTERFACE_NAME_LENGTH: usize = 15;
}

// Trait for network operations
pub trait NetworkUtil {
    fn get_network(&self, name_or_id: &str) -> Result<&Network, NetworkError>;
    fn network_exists(&self, name: &str) -> bool;
    fn get_free_device_name(&self) -> Result<String, NetworkError>;
    fn get_used_subnets(&self) -> Result<Vec<IpNet>, NetworkError>;
    fn get_bridge_interface_names(&self) -> Vec<String>;
    fn validate_interface_name(&self, name: &str) -> Result<(), NetworkError>;
    fn commit_network(&self, network: &Network) -> Result<(), NetworkError>;
    fn create_plugin(&self, network: &mut Network) -> Result<(), NetworkError>;
}

// Helper function to generate a non-cryptographic ID (64 hex characters)
fn generate_non_crypto_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    hex::encode(bytes)
}

// Helper function to validate IP address
fn parse_ip(ip_str: &str) -> Option<IpAddr> {
    ip_str.parse().ok()
}

// Name regex validation
fn name_regex() -> &'static Regex {
    use std::sync::OnceLock;
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$").unwrap())
}

// Validate IPAM driver
fn validate_ipam_driver(network: &Network) -> Result<(), NetworkError> {
    let driver = network.ipam_options
        .get(constants::DRIVER)
        .map(|s| s.as_str())
        .unwrap_or("");

    match driver {
        "" | constants::HOST_LOCAL_IPAM_DRIVER | constants::DHCP_IPAM_DRIVER | constants::NONE_IPAM_DRIVER => Ok(()),
        _ => Err(NetworkError::InvalidArg(format!("unsupported ipam driver: {}", driver))),
    }
}

// Create IPvLAN or MacVLAN network
fn create_ipvlan_or_macvlan(network: &mut Network, net_util: &dyn NetworkUtil) -> Result<(), NetworkError> {
    if !network.network_interface.is_empty() {
        // Validate that parent interface exists
        // This would need to be implemented based on system calls
        // For now, we'll skip this validation
    }

    // Always turn DNS off with macvlan/ipvlan
    network.dns_enabled = false;

    // Validate IPAM driver for ipvlan
    if network.driver == constants::IPVLAN_NETWORK_DRIVER {
        if let Some(driver) = network.ipam_options.get(constants::DRIVER) {
            if driver == constants::DHCP_IPAM_DRIVER {
                return Err(NetworkError::InvalidArg(
                    "ipam driver dhcp is not supported with ipvlan".to_string()
                ));
            }
        }
    }

    Ok(())
}

// Map Docker bridge driver options (placeholder - would need actual implementation)
fn map_docker_bridge_driver_options(_network: &mut Network) {
    // This would map Docker-specific options to netavark options
}

// Parse MTU option
fn parse_mtu(value: &str) -> Result<u32, NetworkError> {
    value.parse::<u32>()
        .map_err(|_| NetworkError::InvalidArg(format!("invalid MTU value: {}", value)))
}

// Parse VLAN option
fn parse_vlan(value: &str) -> Result<u16, NetworkError> {
    value.parse::<u16>()
        .map_err(|_| NetworkError::InvalidArg(format!("invalid VLAN value: {}", value)))
}

// Parse Isolate option
fn parse_isolate(value: &str) -> Result<String, NetworkError> {
    match value {
        "true" | "1" => Ok("true".to_string()),
        "false" | "0" => Ok("false".to_string()),
        _ => Err(NetworkError::InvalidArg(format!("invalid isolate value: {}", value))),
    }
}

// IPAM None disable DNS
fn ipam_none_disable_dns(network: &mut Network) {
    if network.ipam_options.get(constants::DRIVER) == Some(&constants::NONE_IPAM_DRIVER.to_string()) {
        network.dns_enabled = false;
    }
}

// Validate subnets (placeholder - would need actual implementation)
fn validate_subnets(
    network: &Network,
    add_gateway: bool,
    used_networks: &[IpNet],
) -> Result<(), NetworkError> {
    // This would validate subnets, check for conflicts, etc.
    // For now, just a placeholder
    Ok(())
}

// Validate routes (placeholder - would need actual implementation)
fn validate_routes(routes: &[Route]) -> Result<(), NetworkError> {
    // This would validate routes
    // For now, just a placeholder
    Ok(())
}

// Main network create function
pub fn network_create<N: NetworkUtil>(
    net_util: &N,
    mut new_network: Network,
    default_net: bool,
) -> Result<Network, NetworkError> {
    use constants::*;

    // If no driver is set, use the default one
    if new_network.driver.is_empty() {
        new_network.driver = DEFAULT_NETWORK_DRIVER.to_string();
    }

    if !default_net {
        // The caller is not allowed to set a specific ID
        if !new_network.id.is_empty() {
            return Err(NetworkError::InvalidArg(
                "ID can not be set for network create".to_string()
            ));
        }

        // Generate random network ID
        let mut found_id = false;
        for _ in 0..1000 {
            let id = generate_non_crypto_id();
            match net_util.get_network(&id) {
                Err(NetworkError::NoSuchNetwork(_)) => {
                    new_network.id = id;
                    found_id = true;
                    break;
                }
                _ => continue,
            }
        }

        if !found_id {
            return Err(NetworkError::Other("failed to create random network ID".to_string()));
        }
    }

    // Initialize maps if nil
    if new_network.labels.is_empty() {
        new_network.labels = HashMap::new();
    }
    if new_network.options.is_empty() {
        new_network.options = HashMap::new();
    }
    if new_network.ipam_options.is_empty() {
        new_network.ipam_options = HashMap::new();
    }

    // Validate the name when given
    if !new_network.name.is_empty() {
        if !name_regex().is_match(&new_network.name) {
            return Err(NetworkError::InvalidName(format!(
                "network name {} invalid: names must match [a-zA-Z0-9][a-zA-Z0-9_.-]*",
                new_network.name
            )));
        }
        if net_util.network_exists(&new_network.name) {
            return Err(NetworkError::NetworkExists(format!(
                "network name {} already used",
                new_network.name
            )));
        }
    } else {
        let name = net_util.get_free_device_name()?;
        new_network.name = name.clone();
        // Also use the name as interface name when we create a bridge network
        if new_network.driver == BRIDGE_NETWORK_DRIVER && new_network.network_interface.is_empty() {
            new_network.network_interface = name;
        }
    }

    // Validate interface name if specified
    if !new_network.network_interface.is_empty() {
        net_util.validate_interface_name(&new_network.network_interface)?;
    }

    // Validate IPAM driver
    validate_ipam_driver(&new_network)?;

    // Only get the used networks for validation if we do not create the default network
    let mut used_networks: Vec<IpNet> = Vec::new();
    if !default_net && new_network.driver == BRIDGE_NETWORK_DRIVER {
        used_networks = net_util.get_used_subnets()?;
    }

    // Handle different drivers
    match new_network.driver.as_str() {
        BRIDGE_NETWORK_DRIVER => {
            map_docker_bridge_driver_options(&mut new_network);

            let mut check_bridge_conflict = true;

            // Validate the given options
            let options_clone = new_network.options.clone();
            for (key, value) in options_clone {
                match key.as_str() {
                    MTU_OPTION => {
                        parse_mtu(&value)?;
                    }
                    VLAN_OPTION => {
                        parse_vlan(&value)?;
                        // Unset used networks when using VLAN
                        used_networks.clear();
                        check_bridge_conflict = false;
                    }
                    ISOLATE_OPTION => {
                        let val = parse_isolate(&value)?;
                        new_network.options.insert(ISOLATE_OPTION.to_string(), val);
                    }
                    METRIC_OPTION => {
                        value.parse::<u32>()
                            .map_err(|_| NetworkError::InvalidArg(format!("invalid metric value: {}", value)))?;
                    }
                    NO_DEFAULT_ROUTE => {
                        let val = value.parse::<bool>()
                            .map_err(|_| NetworkError::InvalidArg(format!("invalid no_default_route value: {}", value)))?;
                        // Rust only supports "true" or "false" while Go can parse 1 and 0 as well
                        new_network.options.insert(NO_DEFAULT_ROUTE.to_string(), val.to_string());
                    }
                    VRF_OPTION => {
                        if value.is_empty() {
                            return Err(NetworkError::InvalidArg("invalid vrf name".to_string()));
                        }
                    }
                    MODE_OPTION => {
                        match value.as_str() {
                            BRIDGE_MODE_MANAGED => {}
                            BRIDGE_MODE_UNMANAGED => {
                                // Unset used networks when using unmanaged mode
                                used_networks.clear();
                                check_bridge_conflict = false;
                            }
                            _ => {
                                return Err(NetworkError::InvalidArg(format!("unknown bridge mode {}", value)));
                            }
                        }
                    }
                    _ => {
                        return Err(NetworkError::InvalidArg(format!("unsupported bridge network option {}", key)));
                    }
                }
            }

            // Create bridge (this would call the bridge creation logic)
            // For now, we'll need to integrate with the existing bridge.rs module
            // This is a placeholder - actual implementation would call create_bridge from bridge.rs
            // crate::internal::util::bridge::create_bridge(
            //     &mut new_network,
            //     &used_networks,
            //     &[], // subnet_pools - would need to be passed in
            //     check_bridge_conflict,
            //     net_util,
            // )?;
        }
        MACVLAN_NETWORK_DRIVER | IPVLAN_NETWORK_DRIVER => {
            create_ipvlan_or_macvlan(&mut new_network, net_util)?;
        }
        _ => {
            // Try to create plugin network
            net_util.create_plugin(&mut new_network)?;
        }
    }

    // When we do not have IPAM, we must disable DNS
    ipam_none_disable_dns(&mut new_network);

    // Process NetworkDNSServers
    if !new_network.network_dns_servers.is_empty() && !new_network.dns_enabled {
        return Err(NetworkError::InvalidArg(
            "cannot set NetworkDNSServers if DNS is not enabled for the network".to_string()
        ));
    }

    // Validate IP addresses
    for dns_server in &new_network.network_dns_servers {
        if parse_ip(dns_server).is_none() {
            return Err(NetworkError::InvalidArg(format!(
                "unable to parse ip {} specified in NetworkDNSServers",
                dns_server
            )));
        }
    }

    // Add gateway when not internal or DNS enabled
    let add_gateway = !new_network.internal || new_network.dns_enabled;
    validate_subnets(&new_network, add_gateway, &used_networks)?;

    // Validate routes
    validate_routes(&new_network.routes)?;

    // Set created timestamp
    new_network.created = Some(SystemTime::now());

    if !default_net {
        net_util.commit_network(&new_network)?;
    }

    Ok(new_network)
}

