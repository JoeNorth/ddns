use crate::pp::{self, PP};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

const PROXMOX_TIMEOUT: u64 = 30;

// TODO: Add IPv6/AAAA record support for VMs with IPv6 addresses on vmbr0
// TODO: Make bridge name configurable instead of hardcoded to vmbr0

/// A discovered Proxmox VM entry: domain name (from VM name) + its IPv4 address on vmbr0.
#[derive(Debug, Clone)]
pub struct ProxmoxEntry {
    pub domain: String,
    pub ip: IpAddr,
}

/// Configuration for connecting to the Proxmox API.
#[derive(Debug, Clone)]
pub struct ProxmoxConfig {
    pub api_url: String,
    pub api_token: String,
    pub tag: String,
}

/// Discover domains and IPs from Proxmox VMs tagged with the configured tag.
///
/// Uses the cluster-wide `/cluster/resources?type=vm` endpoint to discover VMs across all nodes
/// in a Proxmox VE cluster. Each VM result includes the `node` it resides on, which is then
/// used for the per-VM config and guest agent queries.
///
/// NOTE: This endpoint is assumed to work on standalone (non-clustered) single-node Proxmox
/// installations as well, since PVE always has cluster infrastructure internally. This has not
/// been confirmed against a non-clustered node and should be verified.
///
/// For each running VM with the tag:
/// 1. Uses the VM name as the domain
/// 2. Finds the MAC address of the NIC attached to vmbr0 from VM config
/// 3. Queries the QEMU guest agent for network interfaces
/// 4. Matches by MAC to find the IPv4 address
pub async fn discover_proxmox_domains(
    config: &ProxmoxConfig,
    ppfmt: &PP,
) -> Vec<ProxmoxEntry> {
    let client = match Client::builder()
        .timeout(Duration::from_secs(PROXMOX_TIMEOUT))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("Failed to create HTTP client for Proxmox: {e}"),
            );
            return Vec::new();
        }
    };

    let vms = match list_vms(&client, config, ppfmt).await {
        Some(v) => v,
        None => return Vec::new(),
    };

    let tagged: Vec<&VmEntry> = vms
        .iter()
        .filter(|vm| vm.status == "running" && has_tag(vm, &config.tag))
        .collect();

    if tagged.is_empty() {
        ppfmt.infof(
            pp::EMOJI_PROXMOX,
            &format!(
                "No running VMs found with tag '{}'",
                config.tag
            ),
        );
        return Vec::new();
    }

    let mut entries = Vec::new();

    for vm in tagged {
        let domain = vm.name.trim().to_lowercase();
        if domain.is_empty() {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("VM {} has empty name, skipping", vm.vmid),
            );
            continue;
        }

        // Find the MAC of the NIC attached to vmbr0
        let mac = match get_vmbr0_mac(&client, config, &vm.node, vm.vmid, ppfmt).await {
            Some(m) => m,
            None => {
                ppfmt.warningf(
                    pp::EMOJI_WARNING,
                    &format!(
                        "VM {} ({}): no NIC attached to vmbr0, skipping",
                        vm.vmid, domain
                    ),
                );
                continue;
            }
        };

        // Get the IP from the guest agent by matching MAC
        let ip = match get_ip_by_mac(&client, config, &vm.node, vm.vmid, &mac, ppfmt).await {
            Some(ip) => ip,
            None => {
                ppfmt.warningf(
                    pp::EMOJI_WARNING,
                    &format!(
                        "VM {} ({}): could not get IPv4 from guest agent for MAC {mac}, skipping",
                        vm.vmid, domain
                    ),
                );
                continue;
            }
        };

        entries.push(ProxmoxEntry {
            domain: domain.clone(),
            ip,
        });
    }

    if !entries.is_empty() {
        let summary: Vec<String> = entries
            .iter()
            .map(|e| format!("{} -> {}", e.domain, e.ip))
            .collect();
        ppfmt.infof(
            pp::EMOJI_PROXMOX,
            &format!(
                "Discovered {} domain(s) from Proxmox: {}",
                entries.len(),
                summary.join(", ")
            ),
        );
    }

    entries
}

// ============================================================
// Proxmox API types
// ============================================================

#[derive(Debug, Deserialize)]
struct ProxmoxResponse<T> {
    data: Option<T>,
}

#[derive(Debug, Deserialize)]
struct VmEntry {
    vmid: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    node: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    tags: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GuestInterface {
    #[allow(dead_code)]
    name: String,
    #[serde(rename = "hardware-address", default)]
    hardware_address: String,
    #[serde(rename = "ip-addresses", default)]
    ip_addresses: Vec<GuestIpAddress>,
}

#[derive(Debug, Deserialize)]
struct GuestIpAddress {
    #[serde(rename = "ip-address")]
    ip_address: String,
    #[serde(rename = "ip-address-type")]
    ip_address_type: String,
}

#[derive(Debug, Deserialize)]
struct GuestAgentResult {
    result: Option<Vec<GuestInterface>>,
}

// ============================================================
// API calls
// ============================================================

/// List all QEMU VMs across the cluster using the `/cluster/resources` endpoint.
///
/// NOTE: This endpoint is assumed to work on standalone (non-clustered) nodes. If it does not,
/// this will need to fall back to `/nodes/{node}/qemu` with a user-provided node name.
async fn list_vms(
    client: &Client,
    config: &ProxmoxConfig,
    ppfmt: &PP,
) -> Option<Vec<VmEntry>> {
    let url = format!(
        "{}/api2/json/cluster/resources?type=vm",
        config.api_url.trim_end_matches('/'),
    );

    let resp = client
        .get(&url)
        .header("Authorization", &config.api_token)
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            match r.json::<ProxmoxResponse<Vec<VmEntry>>>().await {
                Ok(parsed) => parsed.data,
                Err(e) => {
                    ppfmt.warningf(
                        pp::EMOJI_WARNING,
                        &format!("Failed to parse Proxmox VM list: {e}"),
                    );
                    None
                }
            }
        }
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("Proxmox API error listing VMs: {status} - {body}"),
            );
            None
        }
        Err(e) => {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("Failed to connect to Proxmox API: {e}"),
            );
            None
        }
    }
}

/// Parse VM config to find the MAC address of the NIC attached to vmbr0.
///
/// VM config has entries like: `net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1`
/// We scan all `netN` keys for one with `bridge=vmbr0` and extract the MAC.
async fn get_vmbr0_mac(
    client: &Client,
    config: &ProxmoxConfig,
    node: &str,
    vmid: u64,
    ppfmt: &PP,
) -> Option<String> {
    let url = format!(
        "{}/api2/json/nodes/{}/qemu/{}/config",
        config.api_url.trim_end_matches('/'),
        node,
        vmid
    );

    let resp = client
        .get(&url)
        .header("Authorization", &config.api_token)
        .send()
        .await;

    let data: HashMap<String, serde_json::Value> = match resp {
        Ok(r) if r.status().is_success() => {
            match r.json::<ProxmoxResponse<HashMap<String, serde_json::Value>>>().await {
                Ok(parsed) => parsed.data.unwrap_or_default(),
                Err(e) => {
                    ppfmt.warningf(
                        pp::EMOJI_WARNING,
                        &format!("Failed to parse VM {vmid} config: {e}"),
                    );
                    return None;
                }
            }
        }
        Ok(r) => {
            let status = r.status();
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("Proxmox API error getting VM {vmid} config: {status}"),
            );
            return None;
        }
        Err(e) => {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("Failed to get VM {vmid} config: {e}"),
            );
            return None;
        }
    };

    // Scan net0, net1, ... for bridge=vmbr0
    for i in 0..16 {
        let key = format!("net{i}");
        if let Some(serde_json::Value::String(val)) = data.get(&key) {
            if let Some(mac) = parse_net_device(val, "vmbr0") {
                return Some(mac);
            }
        }
    }

    None
}

/// Parse a Proxmox net device string like `virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1`
/// Returns the MAC address (lowercased) if the device is on the specified bridge.
fn parse_net_device(value: &str, bridge: &str) -> Option<String> {
    let parts: Vec<&str> = value.split(',').collect();

    let mut mac: Option<String> = None;
    let mut on_bridge = false;

    for part in &parts {
        if let Some(bridge_val) = part.strip_prefix("bridge=") {
            if bridge_val == bridge {
                on_bridge = true;
            }
        }
        // The first part is typically `driver=MAC` (e.g., `virtio=AA:BB:CC:DD:EE:FF`)
        if part.contains('=') && mac.is_none() {
            let kv: Vec<&str> = part.splitn(2, '=').collect();
            if kv.len() == 2 && looks_like_mac(kv[1]) {
                mac = Some(kv[1].to_lowercase());
            }
        }
    }

    if on_bridge {
        mac
    } else {
        None
    }
}

/// Simple check for MAC address format (XX:XX:XX:XX:XX:XX).
fn looks_like_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Query the QEMU guest agent for network interfaces and find the IPv4 address
/// matching the given MAC address.
async fn get_ip_by_mac(
    client: &Client,
    config: &ProxmoxConfig,
    node: &str,
    vmid: u64,
    mac: &str,
    ppfmt: &PP,
) -> Option<IpAddr> {
    let url = format!(
        "{}/api2/json/nodes/{}/qemu/{}/agent/network-get-interfaces",
        config.api_url.trim_end_matches('/'),
        node,
        vmid
    );

    let resp = client
        .get(&url)
        .header("Authorization", &config.api_token)
        .send()
        .await;

    let agent_result: GuestAgentResult = match resp {
        Ok(r) if r.status().is_success() => {
            match r.json::<ProxmoxResponse<GuestAgentResult>>().await {
                Ok(parsed) => parsed.data.unwrap_or(GuestAgentResult { result: None }),
                Err(e) => {
                    ppfmt.warningf(
                        pp::EMOJI_WARNING,
                        &format!("Failed to parse guest agent response for VM {vmid}: {e}"),
                    );
                    return None;
                }
            }
        }
        Ok(r) => {
            let status = r.status();
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!(
                    "Proxmox guest agent error for VM {vmid}: {status} (is qemu-guest-agent running?)"
                ),
            );
            return None;
        }
        Err(e) => {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("Failed to query guest agent for VM {vmid}: {e}"),
            );
            return None;
        }
    };

    let interfaces = agent_result.result.unwrap_or_default();

    for iface in &interfaces {
        if iface.hardware_address.to_lowercase() == mac.to_lowercase() {
            for addr in &iface.ip_addresses {
                if addr.ip_address_type == "ipv4" {
                    if let Ok(ip) = addr.ip_address.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }
    }

    None
}

/// Check whether a VM has a given tag.
/// Proxmox tags are semicolon-separated in the `tags` field.
fn has_tag(vm: &VmEntry, tag: &str) -> bool {
    vm.tags
        .as_deref()
        .map(|t| t.split(';').any(|s| s.trim() == tag))
        .unwrap_or(false)
}

/// Parse the Proxmox API token from environment format.
/// Accepts either:
/// - `PVEAPIToken=user@realm!tokenid=secret` (full header value)
/// - `user@realm!tokenid=secret` (just the credential, will be prefixed)
pub fn format_api_token(token: &str) -> String {
    if token.starts_with("PVEAPIToken=") {
        token.to_string()
    } else {
        format!("PVEAPIToken={token}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_net_device_virtio_vmbr0() {
        let val = "virtio=BC:24:11:AB:CD:EF,bridge=vmbr0,firewall=1";
        assert_eq!(
            parse_net_device(val, "vmbr0"),
            Some("bc:24:11:ab:cd:ef".to_string())
        );
    }

    #[test]
    fn test_parse_net_device_wrong_bridge() {
        let val = "virtio=BC:24:11:AB:CD:EF,bridge=vmbr1,firewall=1";
        assert_eq!(parse_net_device(val, "vmbr0"), None);
    }

    #[test]
    fn test_parse_net_device_no_bridge() {
        let val = "virtio=BC:24:11:AB:CD:EF";
        assert_eq!(parse_net_device(val, "vmbr0"), None);
    }

    #[test]
    fn test_parse_net_device_e1000() {
        let val = "e1000=AA:BB:CC:DD:EE:FF,bridge=vmbr0";
        assert_eq!(
            parse_net_device(val, "vmbr0"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn test_looks_like_mac_valid() {
        assert!(looks_like_mac("BC:24:11:AB:CD:EF"));
        assert!(looks_like_mac("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_looks_like_mac_invalid() {
        assert!(!looks_like_mac("not-a-mac"));
        assert!(!looks_like_mac("BC:24:11:AB:CD"));
        assert!(!looks_like_mac("BC:24:11:AB:CD:EF:00"));
        assert!(!looks_like_mac(""));
    }

    #[test]
    fn test_has_tag_single() {
        let vm = VmEntry {
            vmid: 100,
            name: "test".to_string(),
            node: "pve1".to_string(),
            status: "running".to_string(),
            tags: Some("dns".to_string()),
        };
        assert!(has_tag(&vm, "dns"));
        assert!(!has_tag(&vm, "web"));
    }

    #[test]
    fn test_has_tag_multiple() {
        let vm = VmEntry {
            vmid: 100,
            name: "test".to_string(),
            node: "pve1".to_string(),
            status: "running".to_string(),
            tags: Some("dns;web;prod".to_string()),
        };
        assert!(has_tag(&vm, "dns"));
        assert!(has_tag(&vm, "web"));
        assert!(has_tag(&vm, "prod"));
        assert!(!has_tag(&vm, "dev"));
    }

    #[test]
    fn test_has_tag_none() {
        let vm = VmEntry {
            vmid: 100,
            name: "test".to_string(),
            node: "pve1".to_string(),
            status: "running".to_string(),
            tags: None,
        };
        assert!(!has_tag(&vm, "dns"));
    }

    #[test]
    fn test_format_api_token_bare() {
        assert_eq!(
            format_api_token("user@pam!token=secret-uuid"),
            "PVEAPIToken=user@pam!token=secret-uuid"
        );
    }

    #[test]
    fn test_format_api_token_prefixed() {
        assert_eq!(
            format_api_token("PVEAPIToken=user@pam!token=secret-uuid"),
            "PVEAPIToken=user@pam!token=secret-uuid"
        );
    }

    // -------------------------------------------------------
    // Integration tests (wiremock)
    // -------------------------------------------------------

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config(base_url: &str) -> ProxmoxConfig {
        ProxmoxConfig {
            api_url: base_url.to_string(),
            api_token: "PVEAPIToken=test@pam!tok=secret".to_string(),
            tag: "dns".to_string(),
        }
    }

    fn ppfmt() -> PP {
        PP::new(false, true)
    }

    /// JSON for a cluster/resources response with the given VMs.
    fn vm_list_response(vms: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({ "data": vms })
    }

    /// JSON for a VM config response with the given key-value pairs.
    fn vm_config_response(config: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "data": config })
    }

    /// JSON for a guest agent network-get-interfaces response.
    fn guest_agent_response(interfaces: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({
            "data": {
                "result": interfaces
            }
        })
    }

    /// Full happy path: one running VM with dns tag, vmbr0 NIC, guest agent returns IP.
    #[tokio::test]
    async fn test_discover_single_vm_success() {
        let server = MockServer::start().await;
        let config = test_config(&server.uri());

        // List VMs via cluster resources
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_list_response(vec![
                serde_json::json!({
                    "vmid": 100,
                    "name": "web.example.com",
                    "node": "pve1",
                    "status": "running",
                    "tags": "dns"
                }),
            ])))
            .mount(&server)
            .await;

        // VM config with net0 on vmbr0
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_config_response(
                serde_json::json!({
                    "net0": "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1",
                    "cores": 2,
                    "memory": 4096
                }),
            )))
            .mount(&server)
            .await;

        // Guest agent returns IP matching the MAC
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces"))
            .respond_with(ResponseTemplate::new(200).set_body_json(guest_agent_response(vec![
                serde_json::json!({
                    "name": "eth0",
                    "hardware-address": "bc:24:11:aa:bb:cc",
                    "ip-addresses": [
                        { "ip-address": "10.0.0.50", "ip-address-type": "ipv4" }
                    ]
                }),
            ])))
            .mount(&server)
            .await;

        let entries = discover_proxmox_domains(&config, &ppfmt()).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "web.example.com");
        assert_eq!(entries[0].ip, "10.0.0.50".parse::<IpAddr>().unwrap());
    }

    /// Multiple VMs: only running ones with dns tag are included.
    #[tokio::test]
    async fn test_discover_filters_by_status_and_tag() {
        let server = MockServer::start().await;
        let config = test_config(&server.uri());

        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_list_response(vec![
                serde_json::json!({
                    "vmid": 100,
                    "name": "included.example.com",
                    "node": "pve1",
                    "status": "running",
                    "tags": "dns;prod"
                }),
                serde_json::json!({
                    "vmid": 101,
                    "name": "stopped-vm.example.com",
                    "node": "pve1",
                    "status": "stopped",
                    "tags": "dns"
                }),
                serde_json::json!({
                    "vmid": 102,
                    "name": "no-tag.example.com",
                    "node": "pve1",
                    "status": "running",
                    "tags": "web"
                }),
                serde_json::json!({
                    "vmid": 103,
                    "name": "no-tags-field.example.com",
                    "node": "pve1",
                    "status": "running"
                }),
            ])))
            .mount(&server)
            .await;

        // Only VM 100 should get config + agent queries
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_config_response(
                serde_json::json!({
                    "net0": "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0"
                }),
            )))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces"))
            .respond_with(ResponseTemplate::new(200).set_body_json(guest_agent_response(vec![
                serde_json::json!({
                    "name": "eth0",
                    "hardware-address": "aa:bb:cc:dd:ee:01",
                    "ip-addresses": [
                        { "ip-address": "10.0.0.10", "ip-address-type": "ipv4" }
                    ]
                }),
            ])))
            .mount(&server)
            .await;

        let entries = discover_proxmox_domains(&config, &ppfmt()).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "included.example.com");
    }

    /// VM with no NIC on vmbr0 is skipped gracefully.
    #[tokio::test]
    async fn test_discover_skips_vm_without_vmbr0() {
        let server = MockServer::start().await;
        let config = test_config(&server.uri());

        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_list_response(vec![
                serde_json::json!({
                    "vmid": 100,
                    "name": "novmbr0.example.com",
                    "node": "pve1",
                    "status": "running",
                    "tags": "dns"
                }),
            ])))
            .mount(&server)
            .await;

        // VM config has NIC on vmbr1, not vmbr0
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_config_response(
                serde_json::json!({
                    "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr1"
                }),
            )))
            .mount(&server)
            .await;

        let entries = discover_proxmox_domains(&config, &ppfmt()).await;
        assert!(entries.is_empty());
    }

    /// Guest agent unavailable (500 error) is handled gracefully.
    #[tokio::test]
    async fn test_discover_skips_vm_when_guest_agent_fails() {
        let server = MockServer::start().await;
        let config = test_config(&server.uri());

        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_list_response(vec![
                serde_json::json!({
                    "vmid": 100,
                    "name": "noagent.example.com",
                    "node": "pve1",
                    "status": "running",
                    "tags": "dns"
                }),
            ])))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_config_response(
                serde_json::json!({
                    "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"
                }),
            )))
            .mount(&server)
            .await;

        // Guest agent returns 500 (not running)
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces"))
            .respond_with(ResponseTemplate::new(500).set_body_string("QEMU guest agent is not running"))
            .mount(&server)
            .await;

        let entries = discover_proxmox_domains(&config, &ppfmt()).await;
        assert!(entries.is_empty());
    }

    /// API connection failure returns empty results, not a panic.
    #[tokio::test]
    async fn test_discover_handles_api_connection_failure() {
        // Point at a URL that will refuse connections
        let config = ProxmoxConfig {
            api_url: "http://127.0.0.1:1".to_string(),
            api_token: "PVEAPIToken=test@pam!tok=secret".to_string(),
            tag: "dns".to_string(),
        };

        let entries = discover_proxmox_domains(&config, &ppfmt()).await;
        assert!(entries.is_empty());
    }

    /// Empty VM list returns empty results.
    #[tokio::test]
    async fn test_discover_empty_vm_list() {
        let server = MockServer::start().await;
        let config = test_config(&server.uri());

        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_list_response(vec![])))
            .mount(&server)
            .await;

        let entries = discover_proxmox_domains(&config, &ppfmt()).await;
        assert!(entries.is_empty());
    }

    /// API returns 401 Unauthorized — handled gracefully.
    #[tokio::test]
    async fn test_discover_handles_auth_failure() {
        let server = MockServer::start().await;
        let config = test_config(&server.uri());

        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/resources"))
            .respond_with(ResponseTemplate::new(401).set_body_string("authentication failure"))
            .mount(&server)
            .await;

        let entries = discover_proxmox_domains(&config, &ppfmt()).await;
        assert!(entries.is_empty());
    }

    /// Multiple VMs discovered across different nodes: all with valid IPs are returned.
    #[tokio::test]
    async fn test_discover_multiple_vms() {
        let server = MockServer::start().await;
        let config = test_config(&server.uri());

        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_list_response(vec![
                serde_json::json!({
                    "vmid": 100,
                    "name": "web.example.com",
                    "node": "pve1",
                    "status": "running",
                    "tags": "dns"
                }),
                serde_json::json!({
                    "vmid": 101,
                    "name": "api.example.com",
                    "node": "pve2",
                    "status": "running",
                    "tags": "dns;prod"
                }),
            ])))
            .mount(&server)
            .await;

        // VM 100 on pve1: config + agent
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_config_response(
                serde_json::json!({ "net0": "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0" }),
            )))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces"))
            .respond_with(ResponseTemplate::new(200).set_body_json(guest_agent_response(vec![
                serde_json::json!({
                    "name": "eth0",
                    "hardware-address": "aa:bb:cc:dd:ee:01",
                    "ip-addresses": [{ "ip-address": "10.0.0.10", "ip-address-type": "ipv4" }]
                }),
            ])))
            .mount(&server)
            .await;

        // VM 101 on pve2: config + agent
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve2/qemu/101/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_config_response(
                serde_json::json!({ "net0": "virtio=AA:BB:CC:DD:EE:02,bridge=vmbr0" }),
            )))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve2/qemu/101/agent/network-get-interfaces"))
            .respond_with(ResponseTemplate::new(200).set_body_json(guest_agent_response(vec![
                serde_json::json!({
                    "name": "eth0",
                    "hardware-address": "aa:bb:cc:dd:ee:02",
                    "ip-addresses": [{ "ip-address": "10.0.0.11", "ip-address-type": "ipv4" }]
                }),
            ])))
            .mount(&server)
            .await;

        let entries = discover_proxmox_domains(&config, &ppfmt()).await;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].domain, "web.example.com");
        assert_eq!(entries[0].ip, "10.0.0.10".parse::<IpAddr>().unwrap());
        assert_eq!(entries[1].domain, "api.example.com");
        assert_eq!(entries[1].ip, "10.0.0.11".parse::<IpAddr>().unwrap());
    }

    /// VM name is lowercased and trimmed.
    #[tokio::test]
    async fn test_discover_normalizes_vm_name() {
        let server = MockServer::start().await;
        let config = test_config(&server.uri());

        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_list_response(vec![
                serde_json::json!({
                    "vmid": 100,
                    "name": "  Web.Example.COM  ",
                    "node": "pve1",
                    "status": "running",
                    "tags": "dns"
                }),
            ])))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_config_response(
                serde_json::json!({ "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0" }),
            )))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces"))
            .respond_with(ResponseTemplate::new(200).set_body_json(guest_agent_response(vec![
                serde_json::json!({
                    "name": "eth0",
                    "hardware-address": "aa:bb:cc:dd:ee:ff",
                    "ip-addresses": [{ "ip-address": "10.0.0.50", "ip-address-type": "ipv4" }]
                }),
            ])))
            .mount(&server)
            .await;

        let entries = discover_proxmox_domains(&config, &ppfmt()).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "web.example.com");
    }

    /// One VM succeeds and another fails (agent down) — the successful one is still returned.
    #[tokio::test]
    async fn test_discover_partial_failure_returns_successful_vms() {
        let server = MockServer::start().await;
        let config = test_config(&server.uri());

        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_list_response(vec![
                serde_json::json!({
                    "vmid": 100,
                    "name": "good.example.com",
                    "node": "pve1",
                    "status": "running",
                    "tags": "dns"
                }),
                serde_json::json!({
                    "vmid": 101,
                    "name": "bad.example.com",
                    "node": "pve1",
                    "status": "running",
                    "tags": "dns"
                }),
            ])))
            .mount(&server)
            .await;

        // VM 100: succeeds
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_config_response(
                serde_json::json!({ "net0": "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0" }),
            )))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces"))
            .respond_with(ResponseTemplate::new(200).set_body_json(guest_agent_response(vec![
                serde_json::json!({
                    "name": "eth0",
                    "hardware-address": "aa:bb:cc:dd:ee:01",
                    "ip-addresses": [{ "ip-address": "10.0.0.10", "ip-address-type": "ipv4" }]
                }),
            ])))
            .mount(&server)
            .await;

        // VM 101: guest agent fails
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/101/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_config_response(
                serde_json::json!({ "net0": "virtio=AA:BB:CC:DD:EE:02,bridge=vmbr0" }),
            )))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/101/agent/network-get-interfaces"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let entries = discover_proxmox_domains(&config, &ppfmt()).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "good.example.com");
        assert_eq!(entries[0].ip, "10.0.0.10".parse::<IpAddr>().unwrap());
    }

    /// Guest agent returns multiple interfaces — only the one matching vmbr0 MAC is used.
    #[tokio::test]
    async fn test_discover_matches_correct_interface_by_mac() {
        let server = MockServer::start().await;
        let config = test_config(&server.uri());

        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_list_response(vec![
                serde_json::json!({
                    "vmid": 100,
                    "name": "multi-nic.example.com",
                    "node": "pve1",
                    "status": "running",
                    "tags": "dns"
                }),
            ])))
            .mount(&server)
            .await;

        // net0 is on vmbr1 (wrong bridge), net1 is on vmbr0 (correct)
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vm_config_response(
                serde_json::json!({
                    "net0": "virtio=11:22:33:44:55:66,bridge=vmbr1",
                    "net1": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"
                }),
            )))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces"))
            .respond_with(ResponseTemplate::new(200).set_body_json(guest_agent_response(vec![
                serde_json::json!({
                    "name": "eth0",
                    "hardware-address": "11:22:33:44:55:66",
                    "ip-addresses": [{ "ip-address": "192.168.1.50", "ip-address-type": "ipv4" }]
                }),
                serde_json::json!({
                    "name": "eth1",
                    "hardware-address": "aa:bb:cc:dd:ee:ff",
                    "ip-addresses": [{ "ip-address": "10.0.0.99", "ip-address-type": "ipv4" }]
                }),
            ])))
            .mount(&server)
            .await;

        let entries = discover_proxmox_domains(&config, &ppfmt()).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "multi-nic.example.com");
        // Should pick the IP from the interface whose MAC matches the vmbr0 NIC
        assert_eq!(entries[0].ip, "10.0.0.99".parse::<IpAddr>().unwrap());
    }
}
