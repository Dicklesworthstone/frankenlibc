//! DNS resolver functions.
//!
//! Implements `<netdb.h>` functions for hostname resolution.
//! Supports numeric addresses and file-based backends (/etc/hosts, /etc/services).
//!
//! # Submodules
//!
//! - `config`: Parses /etc/resolv.conf configuration
//! - `dns`: DNS protocol message encoding/decoding

pub mod config;
pub mod dns;

pub use config::ResolverConfig;
pub use dns::{DnsHeader, DnsMessage, DnsQuestion, DnsRecord};

use std::net::{Ipv4Addr, Ipv6Addr};

/// Address information result (like `struct addrinfo`).
#[derive(Debug, Clone)]
pub struct AddrInfo {
    /// Address family (AF_INET, AF_INET6).
    pub ai_family: i32,
    /// Socket type (SOCK_STREAM, SOCK_DGRAM).
    pub ai_socktype: i32,
    /// Protocol number.
    pub ai_protocol: i32,
    /// Socket address in binary form.
    pub ai_addr: Vec<u8>,
    /// Canonical name of the host.
    pub ai_canonname: Option<Vec<u8>>,
}

/// EAI error codes (matching POSIX/libc values).
pub const EAI_NONAME: i32 = -2;
pub const EAI_SERVICE: i32 = -8;
pub const EAI_FAMILY: i32 = -6;

/// AF constants for family filtering.
pub const AF_UNSPEC: i32 = 0;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;

/// Snapshot of the locally configured address families used by `AI_ADDRCONFIG`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AddrConfigState {
    pub has_ipv4: bool,
    pub has_ipv6: bool,
}

impl AddrConfigState {
    #[must_use]
    pub fn supports_family(self, family: i32) -> bool {
        match family {
            AF_INET => self.has_ipv4,
            AF_INET6 => self.has_ipv6,
            _ => true,
        }
    }
}

/// Parsed `/etc/services` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEntry {
    /// Canonical service name.
    pub name: Vec<u8>,
    /// Service port in host byte order.
    pub port: u16,
    /// Transport protocol name.
    pub protocol: Vec<u8>,
    /// Additional aliases for the service name.
    pub aliases: Vec<Vec<u8>>,
}

/// Parse a single line from /etc/hosts.
///
/// Format: `<address> <hostname> [<alias>...]`
/// Ignores comments (#) and blank lines. Returns (address_bytes, hostnames).
pub fn parse_hosts_line(line: &[u8]) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
    // Strip comments
    let line = if let Some(pos) = line.iter().position(|&b| b == b'#') {
        &line[..pos]
    } else {
        line
    };

    let mut fields = line
        .split(|&b| b == b' ' || b == b'\t')
        .filter(|f| !f.is_empty());

    let addr_field = fields.next()?;
    let hostnames: Vec<Vec<u8>> = fields.map(|f| f.to_vec()).collect();
    if hostnames.is_empty() {
        return None;
    }

    // Validate the address is a real IP
    let addr_str = core::str::from_utf8(addr_field).ok()?;
    if addr_str.parse::<Ipv4Addr>().is_ok() || addr_str.parse::<Ipv6Addr>().is_ok() {
        Some((addr_field.to_vec(), hostnames))
    } else {
        None
    }
}

/// Look up a hostname in /etc/hosts content.
///
/// Returns all matching IP address strings for the given hostname.
pub fn lookup_hosts(content: &[u8], name: &[u8]) -> Vec<Vec<u8>> {
    let mut results = Vec::new();
    for line in content.split(|&b| b == b'\n') {
        if let Some((addr, hostnames)) = parse_hosts_line(line) {
            for hn in &hostnames {
                if eq_ignore_ascii_case(hn, name) {
                    results.push(addr.clone());
                    break;
                }
            }
        }
    }
    results
}

/// Reverse lookup: find hostnames for an IP address in /etc/hosts content.
pub fn reverse_lookup_hosts(content: &[u8], addr: &[u8]) -> Vec<Vec<u8>> {
    let mut results = Vec::new();
    for line in content.split(|&b| b == b'\n') {
        if let Some((line_addr, hostnames)) = parse_hosts_line(line)
            && line_addr == addr
        {
            for hn in hostnames {
                results.push(hn);
            }
            break; // First matching line wins for reverse
        }
    }
    results
}

/// Parse a single line from /etc/services.
///
/// Format: `<service-name> <port>/<protocol> [<alias>...]`
pub fn parse_services_line(line: &[u8]) -> Option<ServiceEntry> {
    let line = if let Some(pos) = line.iter().position(|&b| b == b'#') {
        &line[..pos]
    } else {
        line
    };

    let mut fields = line
        .split(|&b| b == b' ' || b == b'\t')
        .filter(|f| !f.is_empty());

    let name = fields.next()?;
    let port_proto = fields.next()?;
    let aliases: Vec<Vec<u8>> = fields.map(|field| field.to_vec()).collect();

    let slash_pos = port_proto.iter().position(|&b| b == b'/')?;
    let port_str = core::str::from_utf8(&port_proto[..slash_pos]).ok()?;
    let port: u16 = port_str.parse().ok()?;
    let proto = &port_proto[slash_pos + 1..];
    if proto.is_empty() {
        return None;
    }

    Some(ServiceEntry {
        name: name.to_vec(),
        port,
        protocol: proto.to_vec(),
        aliases,
    })
}

fn service_name_matches(entry: &ServiceEntry, name: &[u8]) -> bool {
    eq_ignore_ascii_case(&entry.name, name)
        || entry
            .aliases
            .iter()
            .any(|alias| eq_ignore_ascii_case(alias, name))
}

/// Look up a service name in /etc/services content.
///
/// Returns the port number for the given service name and optional protocol filter.
pub fn lookup_service(content: &[u8], name: &[u8], protocol: Option<&[u8]>) -> Option<u16> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_services_line(line)
            && service_name_matches(&entry, name)
        {
            if let Some(filter) = protocol {
                if eq_ignore_ascii_case(&entry.protocol, filter) {
                    return Some(entry.port);
                }
            } else {
                return Some(entry.port);
            }
        }
    }
    None
}

fn addrinfo_from_text_address(
    text_addr: &[u8],
    family: i32,
    socktype: i32,
    protocol: i32,
) -> Option<AddrInfo> {
    let text = core::str::from_utf8(text_addr).ok()?;
    if (family == AF_UNSPEC || family == AF_INET)
        && let Ok(v4) = text.parse::<Ipv4Addr>()
    {
        return Some(AddrInfo {
            ai_family: AF_INET,
            ai_socktype: socktype,
            ai_protocol: protocol,
            ai_addr: v4.octets().to_vec(),
            ai_canonname: None,
        });
    }
    if (family == AF_UNSPEC || family == AF_INET6)
        && let Ok(v6) = text.parse::<Ipv6Addr>()
    {
        return Some(AddrInfo {
            ai_family: AF_INET6,
            ai_socktype: socktype,
            ai_protocol: protocol,
            ai_addr: v6.octets().to_vec(),
            ai_canonname: None,
        });
    }
    None
}

/// Parse `/proc/net/route` content and report whether a non-loopback IPv4 route exists.
#[must_use]
pub fn parse_proc_net_route_has_ipv4(content: &[u8]) -> bool {
    for line in content.split(|&b| b == b'\n').skip(1) {
        let mut fields = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|field| !field.is_empty());
        let Some(iface) = fields.next() else {
            continue;
        };
        let _destination = fields.next();
        let _gateway = fields.next();
        let Some(flags) = fields.next() else {
            continue;
        };

        if iface == b"lo" {
            continue;
        }

        let Ok(flags) = core::str::from_utf8(flags)
            .ok()
            .and_then(|field| u32::from_str_radix(field, 16).ok())
            .ok_or(())
        else {
            continue;
        };
        if (flags & 0x1) != 0 {
            return true;
        }
    }
    false
}

/// Parse `/proc/net/if_inet6` content and report whether a non-loopback IPv6 address exists.
#[must_use]
pub fn parse_proc_net_if_inet6_has_ipv6(content: &[u8]) -> bool {
    for line in content.split(|&b| b == b'\n') {
        let mut fields = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|field| !field.is_empty());
        let Some(_addr) = fields.next() else {
            continue;
        };
        let _ifindex = fields.next();
        let _prefix_len = fields.next();
        let _scope = fields.next();
        let _flags = fields.next();
        let Some(iface) = fields.next() else {
            continue;
        };
        if iface != b"lo" {
            return true;
        }
    }
    false
}

/// Derive `AI_ADDRCONFIG` state from Linux procfs snapshots.
#[must_use]
pub fn addrconfig_state_from_procfs(
    route_content: &[u8],
    if_inet6_content: &[u8],
) -> AddrConfigState {
    AddrConfigState {
        has_ipv4: parse_proc_net_route_has_ipv4(route_content),
        has_ipv6: parse_proc_net_if_inet6_has_ipv6(if_inet6_content),
    }
}

/// Retain only address families permitted by the current `AI_ADDRCONFIG` state.
pub fn apply_addrconfig_filter(results: &mut Vec<AddrInfo>, state: AddrConfigState) {
    results.retain(|info| state.supports_family(info.ai_family));
}

/// Resolves a hostname and/or service name to a list of addresses.
///
/// Scope boundaries:
/// - Numeric addresses are always supported.
/// - Hosts-file lookups are supported only when `hosts_content` is provided.
/// - Networked DNS/NSS backends are intentionally out-of-scope in this core path.
pub fn getaddrinfo_with_hosts(
    node: Option<&[u8]>,
    service: Option<&[u8]>,
    hints: Option<&AddrInfo>,
    hosts_content: Option<&[u8]>,
) -> Result<Vec<AddrInfo>, i32> {
    let family = hints.map(|h| h.ai_family).unwrap_or(AF_UNSPEC);
    let socktype = hints.map(|h| h.ai_socktype).unwrap_or(0);
    let protocol = hints.map(|h| h.ai_protocol).unwrap_or(0);

    // Parse service/port
    let _port: u16 = if let Some(svc) = service {
        if let Ok(s) = core::str::from_utf8(svc) {
            s.parse().map_err(|_| EAI_SERVICE)?
        } else {
            return Err(EAI_SERVICE);
        }
    } else {
        0
    };

    let mut results = Vec::new();

    match node {
        Some(name) => {
            let name_str = core::str::from_utf8(name).map_err(|_| EAI_NONAME)?;

            // Try numeric IPv4
            if (family == AF_UNSPEC || family == AF_INET)
                && let Ok(v4) = name_str.parse::<Ipv4Addr>()
            {
                let mut addr = Vec::with_capacity(4);
                addr.extend_from_slice(&v4.octets());
                results.push(AddrInfo {
                    ai_family: AF_INET,
                    ai_socktype: socktype,
                    ai_protocol: protocol,
                    ai_addr: addr,
                    ai_canonname: None,
                });
                return Ok(results);
            }

            // Try numeric IPv6
            if (family == AF_UNSPEC || family == AF_INET6)
                && let Ok(v6) = name_str.parse::<Ipv6Addr>()
            {
                let mut addr = Vec::with_capacity(16);
                addr.extend_from_slice(&v6.octets());
                results.push(AddrInfo {
                    ai_family: AF_INET6,
                    ai_socktype: socktype,
                    ai_protocol: protocol,
                    ai_addr: addr,
                    ai_canonname: None,
                });
                return Ok(results);
            }

            if let Some(hosts) = hosts_content {
                for addr in lookup_hosts(hosts, name) {
                    if let Some(info) =
                        addrinfo_from_text_address(&addr, family, socktype, protocol)
                    {
                        results.push(info);
                    }
                }
                if !results.is_empty() {
                    return Ok(results);
                }
            }

            // Explicitly no DNS/NSS network fallback in this core implementation path.
            Err(EAI_NONAME)
        }
        None => {
            // No node: return wildcard address
            match family {
                AF_INET6 => {
                    results.push(AddrInfo {
                        ai_family: AF_INET6,
                        ai_socktype: socktype,
                        ai_protocol: protocol,
                        ai_addr: Ipv6Addr::UNSPECIFIED.octets().to_vec(),
                        ai_canonname: None,
                    });
                }
                _ => {
                    results.push(AddrInfo {
                        ai_family: AF_INET,
                        ai_socktype: socktype,
                        ai_protocol: protocol,
                        ai_addr: Ipv4Addr::UNSPECIFIED.octets().to_vec(),
                        ai_canonname: None,
                    });
                }
            }
            Ok(results)
        }
    }
}

/// Resolves a hostname and/or service name to a list of addresses.
///
/// Compatibility wrapper that preserves the historic core signature.
/// This path intentionally has no hosts-file input and therefore only supports
/// numeric/wildcard resolution.
pub fn getaddrinfo(
    node: Option<&[u8]>,
    service: Option<&[u8]>,
    hints: Option<&AddrInfo>,
) -> Result<Vec<AddrInfo>, i32> {
    getaddrinfo_with_hosts(node, service, hints, None)
}

/// Converts a socket address to a hostname and service name.
///
/// For numeric-only mode, formats the IP address and port as strings.
pub fn getnameinfo(addr: &[u8], _flags: i32) -> Result<(Vec<u8>, Vec<u8>), i32> {
    // Minimum: 2 bytes for family
    if addr.len() < 2 {
        return Err(EAI_FAMILY);
    }

    // Read family from first two bytes (little-endian on Linux)
    let family = u16::from_ne_bytes([addr[0], addr[1]]) as i32;

    match family {
        AF_INET => {
            if addr.len() < 8 {
                return Err(EAI_FAMILY);
            }
            // sockaddr_in layout: family(2) + port(2) + addr(4)
            let port = u16::from_be_bytes([addr[2], addr[3]]);
            let ip = Ipv4Addr::new(addr[4], addr[5], addr[6], addr[7]);
            Ok((ip.to_string().into_bytes(), port.to_string().into_bytes()))
        }
        AF_INET6 => {
            if addr.len() < 24 {
                return Err(EAI_FAMILY);
            }
            // sockaddr_in6 layout: family(2) + port(2) + flowinfo(4) + addr(16)
            let port = u16::from_be_bytes([addr[2], addr[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addr[8..24]);
            let ip = Ipv6Addr::from(octets);
            Ok((ip.to_string().into_bytes(), port.to_string().into_bytes()))
        }
        _ => Err(EAI_FAMILY),
    }
}

/// Case-insensitive byte comparison for ASCII hostnames.
fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_hosts_line ----

    #[test]
    fn parse_hosts_ipv4_single_name() {
        let (addr, names) = parse_hosts_line(b"127.0.0.1 localhost").unwrap();
        assert_eq!(addr, b"127.0.0.1");
        assert_eq!(names, vec![b"localhost".to_vec()]);
    }

    #[test]
    fn parse_hosts_ipv4_multiple_names() {
        let (addr, names) = parse_hosts_line(b"192.168.1.1  host1  host2  host3").unwrap();
        assert_eq!(addr, b"192.168.1.1");
        assert_eq!(names.len(), 3);
        assert_eq!(names[0], b"host1");
        assert_eq!(names[2], b"host3");
    }

    #[test]
    fn parse_hosts_ipv6() {
        let (addr, names) = parse_hosts_line(b"::1\tlocalhost6").unwrap();
        assert_eq!(addr, b"::1");
        assert_eq!(names, vec![b"localhost6".to_vec()]);
    }

    #[test]
    fn parse_hosts_comment_line() {
        assert!(parse_hosts_line(b"# This is a comment").is_none());
    }

    #[test]
    fn parse_hosts_inline_comment() {
        let (addr, names) = parse_hosts_line(b"10.0.0.1 myhost # my server").unwrap();
        assert_eq!(addr, b"10.0.0.1");
        assert_eq!(names, vec![b"myhost".to_vec()]);
    }

    #[test]
    fn parse_hosts_blank_line() {
        assert!(parse_hosts_line(b"").is_none());
        assert!(parse_hosts_line(b"   ").is_none());
    }

    #[test]
    fn parse_hosts_addr_only_no_name() {
        assert!(parse_hosts_line(b"127.0.0.1").is_none());
    }

    #[test]
    fn parse_hosts_invalid_addr() {
        assert!(parse_hosts_line(b"not-an-ip hostname").is_none());
    }

    // ---- lookup_hosts ----

    #[test]
    fn lookup_hosts_found() {
        let content = b"127.0.0.1 localhost\n192.168.1.1 myhost\n::1 localhost6";
        let addrs = lookup_hosts(content, b"myhost");
        assert_eq!(addrs, vec![b"192.168.1.1".to_vec()]);
    }

    #[test]
    fn lookup_hosts_case_insensitive() {
        let content = b"10.0.0.1 MyHost";
        let addrs = lookup_hosts(content, b"myhost");
        assert_eq!(addrs, vec![b"10.0.0.1".to_vec()]);
    }

    #[test]
    fn lookup_hosts_not_found() {
        let content = b"127.0.0.1 localhost";
        let addrs = lookup_hosts(content, b"nothere");
        assert!(addrs.is_empty());
    }

    #[test]
    fn lookup_hosts_multiple_matches() {
        let content = b"10.0.0.1 web\n10.0.0.2 web";
        let addrs = lookup_hosts(content, b"web");
        assert_eq!(addrs.len(), 2);
    }

    // ---- reverse_lookup_hosts ----

    #[test]
    fn reverse_lookup_found() {
        let content = b"127.0.0.1 localhost loopback";
        let names = reverse_lookup_hosts(content, b"127.0.0.1");
        assert_eq!(names, vec![b"localhost".to_vec(), b"loopback".to_vec()]);
    }

    #[test]
    fn reverse_lookup_not_found() {
        let content = b"127.0.0.1 localhost";
        let names = reverse_lookup_hosts(content, b"10.0.0.1");
        assert!(names.is_empty());
    }

    // ---- parse_services_line ----

    #[test]
    fn parse_services_tcp() {
        let entry = parse_services_line(b"http\t80/tcp").unwrap();
        assert_eq!(entry.name, b"http");
        assert_eq!(entry.port, 80);
        assert_eq!(entry.protocol, b"tcp");
        assert!(entry.aliases.is_empty());
    }

    #[test]
    fn parse_services_udp() {
        let entry = parse_services_line(b"dns  53/udp  domain").unwrap();
        assert_eq!(entry.name, b"dns");
        assert_eq!(entry.port, 53);
        assert_eq!(entry.protocol, b"udp");
        assert_eq!(entry.aliases, vec![b"domain".to_vec()]);
    }

    #[test]
    fn parse_services_comment() {
        assert!(parse_services_line(b"# comment").is_none());
    }

    #[test]
    fn parse_services_blank() {
        assert!(parse_services_line(b"").is_none());
    }

    #[test]
    fn parse_services_invalid_port() {
        assert!(parse_services_line(b"bad abc/tcp").is_none());
    }

    // ---- lookup_service ----

    #[test]
    fn lookup_service_found() {
        let content = b"http\t80/tcp\nhttps\t443/tcp\ndns\t53/udp";
        assert_eq!(lookup_service(content, b"https", Some(b"tcp")), Some(443));
    }

    #[test]
    fn lookup_service_no_proto_filter() {
        let content = b"ssh\t22/tcp";
        assert_eq!(lookup_service(content, b"ssh", None), Some(22));
    }

    #[test]
    fn lookup_service_wrong_proto() {
        let content = b"http\t80/tcp";
        assert_eq!(lookup_service(content, b"http", Some(b"udp")), None);
    }

    #[test]
    fn lookup_service_not_found() {
        let content = b"http\t80/tcp";
        assert_eq!(lookup_service(content, b"nonexistent", None), None);
    }

    #[test]
    fn lookup_service_case_insensitive() {
        let content = b"HTTP\t80/tcp";
        assert_eq!(lookup_service(content, b"http", None), Some(80));
    }

    #[test]
    fn lookup_service_matches_alias() {
        let content = b"http\t80/tcp\twww";
        assert_eq!(lookup_service(content, b"www", Some(b"tcp")), Some(80));
    }

    // ---- getaddrinfo ----

    #[test]
    fn getaddrinfo_numeric_ipv4() {
        let result = getaddrinfo(Some(b"192.168.1.1"), Some(b"80"), None).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ai_family, AF_INET);
        assert_eq!(result[0].ai_addr, [192, 168, 1, 1]);
    }

    #[test]
    fn getaddrinfo_numeric_ipv6() {
        let result = getaddrinfo(Some(b"::1"), Some(b"443"), None).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ai_family, AF_INET6);
        assert_eq!(result[0].ai_addr[15], 1); // ::1
    }

    #[test]
    fn getaddrinfo_no_node() {
        let result = getaddrinfo(None, Some(b"80"), None).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ai_family, AF_INET);
        assert_eq!(result[0].ai_addr, [0, 0, 0, 0]);
    }

    #[test]
    fn getaddrinfo_no_node_v6() {
        let hints = AddrInfo {
            ai_family: AF_INET6,
            ai_socktype: 0,
            ai_protocol: 0,
            ai_addr: vec![],
            ai_canonname: None,
        };
        let result = getaddrinfo(None, Some(b"80"), Some(&hints)).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ai_family, AF_INET6);
    }

    #[test]
    fn getaddrinfo_unknown_hostname() {
        let err = getaddrinfo(Some(b"unknown.host"), None, None).unwrap_err();
        assert_eq!(err, EAI_NONAME);
    }

    #[test]
    fn getaddrinfo_with_hosts_ipv4_lookup() {
        let hosts = b"127.0.0.1 localhost\n10.20.30.40 app.internal app\n";
        let result =
            getaddrinfo_with_hosts(Some(b"app"), Some(b"8080"), None, Some(hosts)).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ai_family, AF_INET);
        assert_eq!(result[0].ai_addr, [10, 20, 30, 40]);
    }

    #[test]
    fn getaddrinfo_with_hosts_respects_family_filter() {
        let hosts = b"2001:db8::1 appv6\n10.20.30.40 appv4\n";
        let hints = AddrInfo {
            ai_family: AF_INET6,
            ai_socktype: 0,
            ai_protocol: 0,
            ai_addr: vec![],
            ai_canonname: None,
        };
        let result = getaddrinfo_with_hosts(Some(b"appv6"), None, Some(&hints), Some(hosts))
            .expect("hosts lookup should resolve v6 entry");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ai_family, AF_INET6);
        assert_eq!(result[0].ai_addr.len(), 16);
    }

    #[test]
    fn getaddrinfo_with_hosts_case_insensitive_alias() {
        let hosts = b"10.8.0.7 API gateway\n";
        let result = getaddrinfo_with_hosts(Some(b"api"), None, None, Some(hosts))
            .expect("case-insensitive host alias should resolve");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ai_family, AF_INET);
        assert_eq!(result[0].ai_addr, [10, 8, 0, 7]);
    }

    #[test]
    fn parse_proc_net_route_requires_non_loopback_up_route() {
        let only_loopback =
            b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\nlo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n";
        assert!(!parse_proc_net_route_has_ipv4(only_loopback));

        let non_loopback =
            b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t01010101\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
        assert!(parse_proc_net_route_has_ipv4(non_loopback));
    }

    #[test]
    fn parse_proc_net_if_inet6_ignores_loopback() {
        let only_loopback = b"00000000000000000000000000000001 01 80 10 80       lo\n";
        assert!(!parse_proc_net_if_inet6_has_ipv6(only_loopback));

        let non_loopback = b"fe800000000000000000000000000001 02 40 20 80   eth0\n";
        assert!(parse_proc_net_if_inet6_has_ipv6(non_loopback));
    }

    #[test]
    fn apply_addrconfig_filter_retains_supported_families() {
        let mut results = vec![
            AddrInfo {
                ai_family: AF_INET,
                ai_socktype: 0,
                ai_protocol: 0,
                ai_addr: vec![127, 0, 0, 1],
                ai_canonname: None,
            },
            AddrInfo {
                ai_family: AF_INET6,
                ai_socktype: 0,
                ai_protocol: 0,
                ai_addr: Ipv6Addr::LOCALHOST.octets().to_vec(),
                ai_canonname: None,
            },
        ];

        apply_addrconfig_filter(
            &mut results,
            AddrConfigState {
                has_ipv4: true,
                has_ipv6: false,
            },
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ai_family, AF_INET);
    }

    #[test]
    fn getaddrinfo_with_hosts_no_network_fallback() {
        let hosts = b"127.0.0.1 localhost\n";
        let err = getaddrinfo_with_hosts(Some(b"missing.example"), None, None, Some(hosts))
            .expect_err("unknown host should not fall back to DNS in core path");
        assert_eq!(err, EAI_NONAME);
    }

    #[test]
    fn getaddrinfo_bad_service() {
        let err = getaddrinfo(Some(b"127.0.0.1"), Some(b"not-a-number"), None).unwrap_err();
        assert_eq!(err, EAI_SERVICE);
    }

    #[test]
    fn getaddrinfo_no_service() {
        let result = getaddrinfo(Some(b"10.0.0.1"), None, None).unwrap();
        assert_eq!(result.len(), 1);
    }

    // ---- getnameinfo ----

    #[test]
    fn getnameinfo_ipv4() {
        // sockaddr_in: family(2) + port(2) + addr(4)
        let mut addr = vec![0u8; 16];
        let family_bytes = (AF_INET as u16).to_ne_bytes();
        addr[0] = family_bytes[0];
        addr[1] = family_bytes[1];
        addr[2] = 0; // port 80 = 0x0050
        addr[3] = 80;
        addr[4] = 127;
        addr[5] = 0;
        addr[6] = 0;
        addr[7] = 1;

        let (host, serv) = getnameinfo(&addr, 0).unwrap();
        assert_eq!(host, b"127.0.0.1");
        assert_eq!(serv, b"80");
    }

    #[test]
    fn getnameinfo_ipv6() {
        let mut addr = vec![0u8; 28];
        let family_bytes = (AF_INET6 as u16).to_ne_bytes();
        addr[0] = family_bytes[0];
        addr[1] = family_bytes[1];
        addr[2] = 0x01; // port 443 = 0x01BB
        addr[3] = 0xBB;
        // addr[4..8] = flowinfo (0)
        // addr[8..24] = ::1
        addr[23] = 1;

        let (host, serv) = getnameinfo(&addr, 0).unwrap();
        assert_eq!(host, b"::1");
        assert_eq!(serv, b"443");
    }

    #[test]
    fn getnameinfo_too_short() {
        let err = getnameinfo(&[0], 0).unwrap_err();
        assert_eq!(err, EAI_FAMILY);
    }

    #[test]
    fn getnameinfo_unknown_family() {
        let mut addr = vec![0u8; 16];
        let family_bytes = (99u16).to_ne_bytes();
        addr[0] = family_bytes[0];
        addr[1] = family_bytes[1];
        let err = getnameinfo(&addr, 0).unwrap_err();
        assert_eq!(err, EAI_FAMILY);
    }
}
