use std::net::IpAddr;
use std::collections::HashMap;
use regex::Regex;
use ipnet::IpNet;
use rand::Rng;

// Type definitions matching the Go types
#[derive(Debug, Clone)]
pub struct Network {
    pub name: String,
    pub id: String,
    pub driver: String,
    pub network_interface: String,
    pub subnets: Vec<Subnet>,
    pub ipv6_enabled: bool,
    pub ipam_options: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Subnet {
    pub subnet: IpNet,
    pub gateway: Option<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct SubnetPool {
    pub base: IpNet,
    pub size: u8,
}

// Trait for NetUtil interface
pub trait NetUtil {
    fn get_bridge_interface_names(&self) -> Vec<String>;
    fn get_free_device_name(&self) -> Result<String, String>;
    fn default_interface_name(&self) -> String;
}

// Constants matching Go constants
pub mod types {
    use std::sync::OnceLock;

    pub const DRIVER: &str = "driver";
    pub const HOST_LOCAL_IPAM_DRIVER: &str = "host-local";

    static NAME_REGEX: OnceLock<Regex> = OnceLock::new();

    pub fn name_regex() -> &'static Regex {
        NAME_REGEX.get_or_init(|| {
            Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$").unwrap()
        })
    }
}

// Helper functions
fn is_ipv6(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(_))
}

fn is_ipv4(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V4(_))
}

// CreateBridge handles bridge network creation logic.
// It validates the network interface name, handles IPAM driver configuration,
// and ensures proper subnet allocation for IPv4 and IPv6.
pub fn create_bridge<N: NetUtil>(
    network: &mut Network,
    used_networks: &[IpNet],
    subnet_pools: &[SubnetPool],
    check_bridge_conflict: bool,
    net_util: &N,
) -> Result<(), String> {
    // Handle network interface name
    if !network.network_interface.is_empty() {
        if check_bridge_conflict {
            let bridges = net_util.get_bridge_interface_names();
            if bridges.contains(&network.network_interface) {
                return Err(format!("bridge name {} already in use", network.network_interface));
            }
        }
        if !types::name_regex().is_match(&network.network_interface) {
            return Err(format!(
                "bridge name {} invalid: names must match [a-zA-Z0-9][a-zA-Z0-9_.-]*",
                network.network_interface
            ));
        }
    } else {
        network.network_interface = net_util.get_free_device_name()?;
    }

    // Get IPAM driver, default to empty string if not set
    let ipam_driver = network.ipam_options
        .get(types::DRIVER)
        .map(|s| s.as_str())
        .unwrap_or("");

    // Also do this when the driver is unset
    if ipam_driver.is_empty() || ipam_driver == types::HOST_LOCAL_IPAM_DRIVER {
        if network.subnets.is_empty() {
            let free_subnet = get_free_ipv4_network_subnet(used_networks, subnet_pools)?;
            network.subnets.push(free_subnet);
        }

        // IPv6 enabled means dual stack, check if we already have
        // an IPv4 or IPv6 subnet and add one if not.
        if network.ipv6_enabled {
            let mut has_ipv4 = false;
            let mut has_ipv6 = false;

            for subnet in &network.subnets {
                match subnet.subnet.addr() {
                    IpAddr::V4(_) => has_ipv4 = true,
                    IpAddr::V6(_) => has_ipv6 = true,
                }
            }

            if !has_ipv4 {
                let free_subnet = get_free_ipv4_network_subnet(used_networks, subnet_pools)?;
                network.subnets.push(free_subnet);
            }

            if !has_ipv6 {
                let free_subnet = get_free_ipv6_network_subnet(used_networks)?;
                network.subnets.push(free_subnet);
            }
        }

        network.ipam_options.insert(
            types::DRIVER.to_string(),
            types::HOST_LOCAL_IPAM_DRIVER.to_string(),
        );
    }

    Ok(())
}

// GetFreeIPv4NetworkSubnet returns an unused IPv4 subnet.
fn get_free_ipv4_network_subnet(
    used_networks: &[IpNet],
    subnet_pools: &[SubnetPool],
) -> Result<Subnet, String> {
    for pool in subnet_pools {
        // Create a network from the pool base with the specified size
        let mut network = IpNet::new(pool.base.addr(), pool.size)
            .map_err(|e| format!("invalid subnet pool: {}", e))?;

        // Ensure the network is within the pool base
        while pool.base.contains(&network.addr()) {
            if !network_intersects_with_networks(&network, used_networks) {
                return Ok(Subnet {
                    subnet: network,
                    gateway: None,
                });
            }

            // Move to next subnet
            network = next_subnet(&network)?;
        }
    }

    Err("could not find free subnet from subnet pools".to_string())
}

// GetFreeIPv6NetworkSubnet returns an unused IPv6 subnet.
// FIXME: Is 10000 fine as limit? We should prevent an endless loop.
fn get_free_ipv6_network_subnet(used_networks: &[IpNet]) -> Result<Subnet, String> {
    // RFC4193: Choose the IPv6 subnet random and NOT sequentially.
    for _ in 0..10000 {
        let network = get_random_ipv6_subnet()?;
        if !network_intersects_with_networks(&network, used_networks) {
            return Ok(Subnet {
                subnet: network,
                gateway: None,
            });
        }
    }

    Err("failed to get random ipv6 subnet".to_string())
}

// Helper function to increment a byte in the IP address (recursive)
fn inc_byte(bytes: &mut [u8], idx: usize, shift: u8) -> Result<(), String> {
    if idx >= bytes.len() {
        return Err("no more subnets left".to_string());
    }

    let increment = 1u8 << shift;
    // Check if adding increment would overflow
    if (bytes[idx] as u16) + (increment as u16) > 255 {
        // Recursively increment the previous byte
        if idx == 0 {
            return Err("no more subnets left".to_string());
        }
        inc_byte(bytes, idx - 1, 0)?;
    }
    bytes[idx] = bytes[idx].wrapping_add(increment);
    Ok(())
}

// Helper function to get next subnet
fn next_subnet(subnet: &IpNet) -> Result<IpNet, String> {
    let prefix_len = subnet.prefix_len();
    if prefix_len == 0 {
        return Err(format!("{} has only one subnet", subnet));
    }

    let addr = subnet.addr();
    match addr {
        IpAddr::V4(ipv4) => {
            let mut bytes = ipv4.octets();
            let bits = 32;
            let zeroes = bits - prefix_len;
            let shift = zeroes % 8;
            let idx = if prefix_len > 0 {
                ((prefix_len - 1) / 8) as usize
            } else {
                return Err("invalid prefix length".to_string());
            };

            inc_byte(&mut bytes, idx, shift as u8)?;

            let new_ip = std::net::Ipv4Addr::from(bytes);
            IpNet::new(IpAddr::V4(new_ip), prefix_len)
                .map_err(|e| format!("failed to create next subnet: {}", e))
        }
        IpAddr::V6(ipv6) => {
            let mut bytes = ipv6.octets();
            let bits = 128;
            let zeroes = bits - prefix_len;
            let shift = zeroes % 8;
            let idx = if prefix_len > 0 {
                ((prefix_len - 1) / 8) as usize
            } else {
                return Err("invalid prefix length".to_string());
            };

            inc_byte(&mut bytes, idx, shift as u8)?;

            let new_ip = std::net::Ipv6Addr::from(bytes);
            IpNet::new(IpAddr::V6(new_ip), prefix_len)
                .map_err(|e| format!("failed to create next subnet: {}", e))
        }
    }
}

// Helper function to check if network intersects with any networks in the list
fn network_intersects_with_networks(network: &IpNet, network_list: &[IpNet]) -> bool {
    network_list.iter().any(|nw| {
        nw.contains(&network.addr()) || network.contains(&nw.addr())
    })
}

// getRandomIPv6Subnet returns a random internal IPv6 subnet as described in RFC4193.
fn get_random_ipv6_subnet() -> Result<IpNet, String> {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];

    // First byte must be 0xfd as per RFC4193
    bytes[0] = 0xfd;
    // Fill bytes 1-8 with random data
    rng.fill(&mut bytes[1..9]);
    // Bytes 9-15 are already zero (add 8 zero bytes)

    let ip = std::net::Ipv6Addr::from(bytes);
    IpNet::new(IpAddr::V6(ip), 64)
        .map_err(|e| format!("failed to create IPv6 subnet: {}", e))
}

