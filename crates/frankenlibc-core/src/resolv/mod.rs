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

/// Parsed `/etc/protocols` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolEntry {
    /// Canonical protocol name.
    pub name: Vec<u8>,
    /// IP protocol number (e.g. 6 for tcp, 17 for udp).
    pub number: i32,
    /// Additional aliases for the protocol.
    pub aliases: Vec<Vec<u8>>,
}

/// Parse a single line from /etc/protocols.
///
/// Format: `<protocol-name> <number> [<alias>...]`
/// Comments (`#`) and blank lines yield `None`. The number is parsed as
/// signed decimal — glibc's protoent uses `int p_proto`.
pub fn parse_protocols_line(line: &[u8]) -> Option<ProtocolEntry> {
    let line = if let Some(pos) = line.iter().position(|&b| b == b'#') {
        &line[..pos]
    } else {
        line
    };
    let mut fields = line
        .split(|&b| b == b' ' || b == b'\t')
        .filter(|f| !f.is_empty());
    let name = fields.next()?;
    let number_str = core::str::from_utf8(fields.next()?).ok()?;
    let number: i32 = number_str.parse().ok()?;
    let aliases: Vec<Vec<u8>> = fields.map(|f| f.to_vec()).collect();
    Some(ProtocolEntry {
        name: name.to_vec(),
        number,
        aliases,
    })
}

fn protocol_name_matches(entry: &ProtocolEntry, name: &[u8]) -> bool {
    eq_ignore_ascii_case(&entry.name, name)
        || entry
            .aliases
            .iter()
            .any(|alias| eq_ignore_ascii_case(alias, name))
}

/// Look up a protocol entry by name in /etc/protocols content.
pub fn lookup_protocol_by_name(content: &[u8], name: &[u8]) -> Option<ProtocolEntry> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_protocols_line(line)
            && protocol_name_matches(&entry, name)
        {
            return Some(entry);
        }
    }
    None
}

/// Look up a protocol entry by number in /etc/protocols content.
pub fn lookup_protocol_by_number(content: &[u8], number: i32) -> Option<ProtocolEntry> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_protocols_line(line)
            && entry.number == number
        {
            return Some(entry);
        }
    }
    None
}

/// Parsed `/etc/networks` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEntry {
    /// Canonical network name.
    pub name: Vec<u8>,
    /// Network number in host byte order (per glibc `n_net`).
    pub number: u32,
    /// Additional aliases for the network.
    pub aliases: Vec<Vec<u8>>,
}

/// Parse a single line from /etc/networks.
///
/// Format: `<network-name> <number> [<alias>...]`
/// `<number>` may be a plain unsigned decimal or a partial-dotted-quad
/// (`a`, `a.b`, `a.b.c`, `a.b.c.d`) — glibc's historical
/// `inet_network` accepts each. A 1-octet form `n` produces `n << 24`,
/// 2-octet `a.b` produces `(a<<24)|(b<<16)`, etc. Octet values >255
/// are rejected (return `None`).
pub fn parse_networks_line(line: &[u8]) -> Option<NetworkEntry> {
    let line = if let Some(pos) = line.iter().position(|&b| b == b'#') {
        &line[..pos]
    } else {
        line
    };
    let mut fields = line
        .split(|&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r')
        .filter(|f| !f.is_empty());
    let name = fields.next()?;
    let num_str = core::str::from_utf8(fields.next()?).ok()?;
    let number = parse_network_number(num_str)?;
    let aliases: Vec<Vec<u8>> = fields.map(|f| f.to_vec()).collect();
    Some(NetworkEntry {
        name: name.to_vec(),
        number,
        aliases,
    })
}

/// Parse a /etc/networks number field.
///
/// Accepts either a plain unsigned decimal or partial dotted-quad.
/// Returns `None` if any octet exceeds 255 or non-numeric content
/// appears.
pub fn parse_network_number(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    if !s.contains('.') {
        return s.parse().ok();
    }
    let mut octets = [0u32; 4];
    let mut count = 0usize;
    for part in s.split('.') {
        if count >= 4 {
            return None;
        }
        let v: u32 = part.parse().ok()?;
        if v > 255 {
            return None;
        }
        octets[count] = v;
        count += 1;
    }
    Some(match count {
        1 => octets[0] << 24,
        2 => (octets[0] << 24) | (octets[1] << 16),
        3 => (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8),
        4 => (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3],
        _ => return None,
    })
}

fn network_name_matches(entry: &NetworkEntry, name: &[u8]) -> bool {
    eq_ignore_ascii_case(&entry.name, name)
        || entry
            .aliases
            .iter()
            .any(|alias| eq_ignore_ascii_case(alias, name))
}

/// Look up a network entry by name in /etc/networks content.
pub fn lookup_network_by_name(content: &[u8], name: &[u8]) -> Option<NetworkEntry> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_networks_line(line)
            && network_name_matches(&entry, name)
        {
            return Some(entry);
        }
    }
    None
}

/// Look up a network entry by number in /etc/networks content.
pub fn lookup_network_by_number(content: &[u8], number: u32) -> Option<NetworkEntry> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_networks_line(line)
            && entry.number == number
        {
            return Some(entry);
        }
    }
    None
}

/// Address family classification produced by [`parse_addr_binary`].
///
/// Maps to libc::AF_INET / AF_INET6 at the abi boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrFamily {
    /// IPv4 (4-byte address).
    Inet4,
    /// IPv6 (16-byte address).
    Inet6,
}

/// Length in bytes of the canonical address form for an [`AddrFamily`].
impl AddrFamily {
    pub fn addr_len(self) -> usize {
        match self {
            AddrFamily::Inet4 => 4,
            AddrFamily::Inet6 => 16,
        }
    }
}

/// Parse an IP address text representation into a fixed 16-byte buffer
/// plus its family / valid-length triple.
///
/// IPv4 addresses fill the first 4 bytes (remaining 12 bytes are
/// zeroed); IPv6 addresses fill all 16. Returns `None` for malformed
/// input — both standard `std::net::Ipv4Addr` and `std::net::Ipv6Addr`
/// parsers are tried in order.
///
/// Used by `gethostbyaddr` / `getaddrinfo` paths in the abi to convert
/// `/etc/hosts` text addresses into the binary form expected by
/// `struct hostent::h_addr_list`.
pub fn parse_addr_binary(text: &str) -> Option<([u8; 16], AddrFamily, usize)> {
    use core::net::{Ipv4Addr, Ipv6Addr};
    if let Ok(v4) = text.parse::<Ipv4Addr>() {
        let mut buf = [0u8; 16];
        buf[..4].copy_from_slice(&v4.octets());
        return Some((buf, AddrFamily::Inet4, 4));
    }
    if let Ok(v6) = text.parse::<Ipv6Addr>() {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&v6.octets());
        return Some((buf, AddrFamily::Inet6, 16));
    }
    None
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
    use proptest::prelude::*;
    use proptest::test_runner::Config as ProptestConfig;

    fn fuzz_proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("FRANKENLIBC_PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(default_cases);
        ProptestConfig {
            cases,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

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

    // -----------------------------------------------------------------
    // hosts(5) / RFC 952 / RFC 1123 conformance table (bd-x7jd)
    // -----------------------------------------------------------------
    //
    // Spec sources:
    //   • hosts(5) — /etc/hosts format and parsing semantics
    //   • RFC 952 — original hostname grammar
    //   • RFC 1123 §2.1 — hostname relaxation (digits as first char)
    //
    // Each entry cites the clause that motivates the expected parse
    // outcome. Reviewers can audit behavior by cross-referencing.

    struct HostsParseCase {
        id: &'static str,
        spec_ref: &'static str,
        input: &'static [u8],
        expected_addr: Option<&'static [u8]>,
        expected_names: &'static [&'static [u8]],
    }

    const HOSTS_PARSE_CONFORMANCE_TABLE: &[HostsParseCase] = &[
        // ---- Whitespace handling (hosts(5) "whitespace") ----
        HostsParseCase {
            id: "HOSTS-PARSE-001",
            spec_ref: "hosts(5) ¶Description — single space separator",
            input: b"127.0.0.1 localhost",
            expected_addr: Some(b"127.0.0.1"),
            expected_names: &[b"localhost"],
        },
        HostsParseCase {
            id: "HOSTS-PARSE-002",
            spec_ref: "hosts(5) ¶Description — tab separator",
            input: b"127.0.0.1\tlocalhost",
            expected_addr: Some(b"127.0.0.1"),
            expected_names: &[b"localhost"],
        },
        HostsParseCase {
            id: "HOSTS-PARSE-003",
            spec_ref: "hosts(5) ¶Description — mixed runs of spaces/tabs",
            input: b"127.0.0.1 \t  localhost\t \tloopback",
            expected_addr: Some(b"127.0.0.1"),
            expected_names: &[b"localhost", b"loopback"],
        },
        // ---- Address families ----
        HostsParseCase {
            id: "HOSTS-PARSE-010",
            spec_ref: "hosts(5) ¶IP_address — IPv4 dotted quad",
            input: b"192.0.2.1 example",
            expected_addr: Some(b"192.0.2.1"),
            expected_names: &[b"example"],
        },
        HostsParseCase {
            id: "HOSTS-PARSE-011",
            spec_ref: "hosts(5) ¶IP_address — IPv6 loopback",
            input: b"::1 localhost6 ip6-loopback",
            expected_addr: Some(b"::1"),
            expected_names: &[b"localhost6", b"ip6-loopback"],
        },
        HostsParseCase {
            id: "HOSTS-PARSE-012",
            spec_ref: "hosts(5) ¶IP_address — full IPv6 literal",
            input: b"2001:db8::1 ipv6host",
            expected_addr: Some(b"2001:db8::1"),
            expected_names: &[b"ipv6host"],
        },
        // ---- Comments & blank lines ----
        HostsParseCase {
            id: "HOSTS-PARSE-020",
            spec_ref: "hosts(5) ¶Description — '#' begins comment",
            input: b"# pure comment line",
            expected_addr: None,
            expected_names: &[],
        },
        HostsParseCase {
            id: "HOSTS-PARSE-021",
            spec_ref: "hosts(5) ¶Description — '#' terminates parseable content",
            input: b"10.0.0.1 host # trailing comment",
            expected_addr: Some(b"10.0.0.1"),
            expected_names: &[b"host"],
        },
        HostsParseCase {
            id: "HOSTS-PARSE-022",
            spec_ref: "hosts(5) ¶Description — blank line is ignored",
            input: b"",
            expected_addr: None,
            expected_names: &[],
        },
        HostsParseCase {
            id: "HOSTS-PARSE-023",
            spec_ref: "hosts(5) ¶Description — whitespace-only line is blank",
            input: b"   \t\t   ",
            expected_addr: None,
            expected_names: &[],
        },
        // ---- RFC 952 / RFC 1123 hostname character sets ----
        HostsParseCase {
            id: "HOSTS-PARSE-030",
            spec_ref: "RFC 1123 §2.1 — digits permitted as first char",
            input: b"10.0.0.5 3com.local",
            expected_addr: Some(b"10.0.0.5"),
            expected_names: &[b"3com.local"],
        },
        HostsParseCase {
            id: "HOSTS-PARSE-031",
            spec_ref: "RFC 952 — hyphens allowed interior",
            input: b"10.0.0.6 my-host-name",
            expected_addr: Some(b"10.0.0.6"),
            expected_names: &[b"my-host-name"],
        },
        HostsParseCase {
            id: "HOSTS-PARSE-032",
            spec_ref: "hosts(5) ¶alias — multiple aliases share a line",
            input: b"10.0.0.7 primary alias1 alias2 alias3",
            expected_addr: Some(b"10.0.0.7"),
            expected_names: &[b"primary", b"alias1", b"alias2", b"alias3"],
        },
        // ---- Malformed input rejection ----
        HostsParseCase {
            id: "HOSTS-PARSE-040",
            spec_ref: "hosts(5) ¶IP_address — non-IP first field rejected",
            input: b"not-an-ip hostname",
            expected_addr: None,
            expected_names: &[],
        },
        HostsParseCase {
            id: "HOSTS-PARSE-041",
            spec_ref: "hosts(5) ¶Description — IP without any name is rejected",
            input: b"127.0.0.1",
            expected_addr: None,
            expected_names: &[],
        },
        HostsParseCase {
            id: "HOSTS-PARSE-042",
            spec_ref: "hosts(5) ¶IP_address — IPv4 octet > 255 rejected",
            input: b"999.0.0.1 bad",
            expected_addr: None,
            expected_names: &[],
        },
    ];

    #[test]
    fn hosts_parse_conformance_table() {
        let mut fails = Vec::new();
        for case in HOSTS_PARSE_CONFORMANCE_TABLE {
            let actual = parse_hosts_line(case.input);
            let pass = match (&actual, case.expected_addr) {
                (None, None) => true,
                (Some((addr, names)), Some(expected_addr)) => {
                    addr == expected_addr
                        && names.len() == case.expected_names.len()
                        && names
                            .iter()
                            .zip(case.expected_names.iter())
                            .all(|(a, b)| a.as_slice() == *b)
                }
                _ => false,
            };
            if !pass {
                fails.push(format!(
                    "{} [{}]: expected addr={:?} names={:?}, got {:?}",
                    case.id,
                    case.spec_ref,
                    case.expected_addr
                        .map(|a| core::str::from_utf8(a).unwrap_or("<non-utf8>")),
                    case.expected_names
                        .iter()
                        .map(|n| core::str::from_utf8(n).unwrap_or("<non-utf8>"))
                        .collect::<Vec<_>>(),
                    actual,
                ));
            }
        }
        assert!(
            fails.is_empty(),
            "hosts(5) parse conformance failures:\n  {}",
            fails.join("\n  ")
        );
    }

    // ---- lookup_hosts conformance (case-insensitivity + multi-address) ----

    struct HostsLookupCase {
        id: &'static str,
        spec_ref: &'static str,
        content: &'static [u8],
        query: &'static [u8],
        expected: &'static [&'static [u8]],
    }

    const HOSTS_LOOKUP_CONFORMANCE_TABLE: &[HostsLookupCase] = &[
        HostsLookupCase {
            id: "HOSTS-LOOKUP-001",
            spec_ref: "RFC 1035 §2.3.3 — DNS is case-insensitive; hosts lookup mirrors it",
            content: b"10.0.0.1 MyHost\n",
            query: b"myhost",
            expected: &[b"10.0.0.1"],
        },
        HostsLookupCase {
            id: "HOSTS-LOOKUP-002",
            spec_ref: "RFC 1035 §2.3.3 — query case is also insensitive",
            content: b"10.0.0.2 myhost\n",
            query: b"MYHOST",
            expected: &[b"10.0.0.2"],
        },
        HostsLookupCase {
            id: "HOSTS-LOOKUP-003",
            spec_ref: "hosts(5) — alias entries match query",
            content: b"10.0.0.7 primary alias1 alias2\n",
            query: b"alias2",
            expected: &[b"10.0.0.7"],
        },
        HostsLookupCase {
            id: "HOSTS-LOOKUP-004",
            spec_ref: "hosts(5) — multiple lines may map same name to multiple IPs",
            content: b"10.0.0.1 web\n10.0.0.2 web\n",
            query: b"web",
            expected: &[b"10.0.0.1", b"10.0.0.2"],
        },
        HostsLookupCase {
            id: "HOSTS-LOOKUP-005",
            spec_ref: "hosts(5) — mixed IPv4/IPv6 entries for same name",
            content: b"127.0.0.1 localhost\n::1 localhost\n",
            query: b"localhost",
            expected: &[b"127.0.0.1", b"::1"],
        },
        HostsLookupCase {
            id: "HOSTS-LOOKUP-006",
            spec_ref: "hosts(5) — comment lines are skipped during lookup",
            content: b"# 10.0.0.1 fake\n10.0.0.2 real\n",
            query: b"fake",
            expected: &[],
        },
        HostsLookupCase {
            id: "HOSTS-LOOKUP-007",
            spec_ref: "hosts(5) — no match returns empty set",
            content: b"127.0.0.1 localhost\n",
            query: b"unknown.example",
            expected: &[],
        },
    ];

    #[test]
    fn hosts_lookup_conformance_table() {
        let mut fails = Vec::new();
        for case in HOSTS_LOOKUP_CONFORMANCE_TABLE {
            let actual = lookup_hosts(case.content, case.query);
            let pass = actual.len() == case.expected.len()
                && actual
                    .iter()
                    .zip(case.expected.iter())
                    .all(|(a, b)| a.as_slice() == *b);
            if !pass {
                fails.push(format!(
                    "{} [{}]: expected {:?}, got {:?}",
                    case.id,
                    case.spec_ref,
                    case.expected
                        .iter()
                        .map(|a| core::str::from_utf8(a).unwrap_or("<non-utf8>"))
                        .collect::<Vec<_>>(),
                    actual
                        .iter()
                        .map(|a| core::str::from_utf8(a).unwrap_or("<non-utf8>"))
                        .collect::<Vec<_>>(),
                ));
            }
        }
        assert!(
            fails.is_empty(),
            "hosts(5) lookup conformance failures:\n  {}",
            fails.join("\n  ")
        );
    }

    // -----------------------------------------------------------------
    // Smoke-fuzz proptests for parse_hosts_line (bd-s170, Archetype 1)
    // -----------------------------------------------------------------
    //
    // Oracle: the parser must never panic on arbitrary byte input, must
    // always terminate, and when it returns Some(_) the decoded output
    // must be a subset of the input bytes (no ghost data introduction).

    proptest! {
        #![proptest_config(fuzz_proptest_config(512))]

        /// Smoke fuzz: parse_hosts_line accepts any byte sequence without
        /// panicking. A parser that indexes with raw byte arithmetic on
        /// multibyte UTF-8 or trusts the '#' comment stripper to leave
        /// non-empty bytes could panic on crafted inputs — this sweep
        /// drives the parser through tens of thousands of garbage lines.
        #[test]
        fn fuzz_parse_hosts_line_never_panics(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let _ = parse_hosts_line(&bytes);
        }

        /// Structural invariant: when parse_hosts_line returns Some(addr, names),
        /// the addr bytes and every name bytes must each appear as a
        /// contiguous substring of the input (up to the first '#'
        /// comment marker). A regression that synthesized output from
        /// elsewhere — or that over-ran the comment strip — would be
        /// caught here.
        #[test]
        fn fuzz_parse_hosts_line_output_is_input_subset(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            if let Some((addr, names)) = parse_hosts_line(&bytes) {
                let pre_comment: &[u8] = match bytes.iter().position(|&b| b == b'#') {
                    Some(pos) => &bytes[..pos],
                    None => &bytes[..],
                };
                prop_assert!(
                    pre_comment.windows(addr.len()).any(|w| w == addr),
                    "addr {:?} not a substring of pre-comment input {:?}",
                    addr, pre_comment
                );
                for name in &names {
                    prop_assert!(
                        pre_comment.windows(name.len()).any(|w| w == name),
                        "name {:?} not a substring of pre-comment input {:?}",
                        name, pre_comment
                    );
                }
            }
        }

        /// Biased fuzz: inputs built from a small ASCII alphabet mixed
        /// with structural delimiters (spaces, tabs, '#', '.', ':',
        /// digits). Random bytes alone rarely produce a parseable first
        /// field, so they hit the early-reject path every time. This
        /// strategy reaches deeper into the parser by generating bytes
        /// that resemble IP addresses.
        #[test]
        fn fuzz_parse_hosts_line_structured_alphabet_never_panics(
            bytes in proptest::collection::vec(
                prop_oneof![
                    Just(b' '), Just(b'\t'), Just(b'#'), Just(b'.'),
                    Just(b':'), Just(b'0'), Just(b'1'), Just(b'2'),
                    Just(b'9'), Just(b'a'), Just(b'f'), Just(b'z'),
                    Just(b'A'), Just(b'Z'), Just(b'-'),
                    Just(0u8), Just(0xffu8),
                ],
                0..256,
            ),
        ) {
            let _ = parse_hosts_line(&bytes);
        }

        // -------------------------------------------------------------
        // Smoke-fuzz proptests for parse_services_line (bd-s170)
        //
        // Oracle:
        //   • Parser never panics on arbitrary bytes.
        //   • When Some(entry) is returned, the port field fits u16
        //     and the protocol field is non-empty (invariants the
        //     parser must uphold by construction).
        //   • Returned name/protocol/aliases must each be a substring
        //     of the pre-comment input (no ghost-data synthesis).
        // -------------------------------------------------------------

        #[test]
        fn fuzz_parse_services_line_never_panics(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let _ = parse_services_line(&bytes);
        }

        #[test]
        fn fuzz_parse_services_line_invariants(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            if let Some(entry) = parse_services_line(&bytes) {
                // Protocol must be non-empty (the parser rejects empty)
                prop_assert!(!entry.protocol.is_empty());
                prop_assert!(!entry.name.is_empty());

                // All decoded fields must be substrings of the
                // pre-comment input region.
                let pre_comment: &[u8] = match bytes.iter().position(|&b| b == b'#') {
                    Some(pos) => &bytes[..pos],
                    None => &bytes[..],
                };
                prop_assert!(pre_comment
                    .windows(entry.name.len())
                    .any(|w| w == entry.name));
                prop_assert!(pre_comment
                    .windows(entry.protocol.len())
                    .any(|w| w == entry.protocol));
                for alias in &entry.aliases {
                    prop_assert!(pre_comment.windows(alias.len()).any(|w| w == alias));
                }
            }
        }

        /// POSIX services(5) conformance — cited spec clauses below.
        /// Each case pins a specific documented behavior of the
        /// services-file parser. Keeps the invariant proptests
        /// (fuzz_parse_services_line_*) as the "does it crash / is
        /// output a subset" fence and adds spec provenance here.
        #[test]
        fn services_parse_conformance_table(
            // Use any() for proptest's boilerplate; we ignore the arg
            // and run the full const table once per iteration with
            // cases=1 effectively.
            _seed in any::<u8>(),
        ) {
            struct Case {
                id: &'static str,
                spec_ref: &'static str,
                input: &'static [u8],
                expected_name: Option<&'static [u8]>,
                expected_port: u16,
                expected_proto: &'static [u8],
                expected_aliases: &'static [&'static [u8]],
            }
            const TABLE: &[Case] = &[
                Case {
                    id: "SERVICES-PARSE-001",
                    spec_ref: "services(5) ¶Format — official_name port/protocol",
                    input: b"ssh\t22/tcp",
                    expected_name: Some(b"ssh"),
                    expected_port: 22,
                    expected_proto: b"tcp",
                    expected_aliases: &[],
                },
                Case {
                    id: "SERVICES-PARSE-002",
                    spec_ref: "services(5) ¶Format — multiple aliases allowed",
                    input: b"http  80/tcp  www www-http",
                    expected_name: Some(b"http"),
                    expected_port: 80,
                    expected_proto: b"tcp",
                    expected_aliases: &[b"www", b"www-http"],
                },
                Case {
                    id: "SERVICES-PARSE-003",
                    spec_ref: "services(5) ¶Format — udp protocol accepted",
                    input: b"dns 53/udp",
                    expected_name: Some(b"dns"),
                    expected_port: 53,
                    expected_proto: b"udp",
                    expected_aliases: &[],
                },
                Case {
                    id: "SERVICES-PARSE-004",
                    spec_ref: "services(5) ¶Description — '#' starts comment",
                    input: b"smtp 25/tcp mail  # Simple Mail Transfer",
                    expected_name: Some(b"smtp"),
                    expected_port: 25,
                    expected_proto: b"tcp",
                    expected_aliases: &[b"mail"],
                },
                Case {
                    id: "SERVICES-PARSE-005",
                    spec_ref: "services(5) ¶Description — pure comment line rejected",
                    input: b"# This is a comment",
                    expected_name: None,
                    expected_port: 0,
                    expected_proto: b"",
                    expected_aliases: &[],
                },
                Case {
                    id: "SERVICES-PARSE-006",
                    spec_ref: "services(5) ¶Description — blank line rejected",
                    input: b"",
                    expected_name: None,
                    expected_port: 0,
                    expected_proto: b"",
                    expected_aliases: &[],
                },
                Case {
                    id: "SERVICES-PARSE-007",
                    // services(5): port/protocol must include '/' separator.
                    spec_ref: "services(5) ¶Format — missing '/' in port/proto rejected",
                    input: b"bad 22tcp",
                    expected_name: None,
                    expected_port: 0,
                    expected_proto: b"",
                    expected_aliases: &[],
                },
                Case {
                    id: "SERVICES-PARSE-008",
                    // An empty protocol field after '/' is ill-formed.
                    spec_ref: "services(5) ¶Format — empty protocol rejected",
                    input: b"bad 22/",
                    expected_name: None,
                    expected_port: 0,
                    expected_proto: b"",
                    expected_aliases: &[],
                },
                Case {
                    id: "SERVICES-PARSE-009",
                    // Non-numeric port must be rejected (u16::parse fails).
                    spec_ref: "services(5) ¶Format — non-numeric port rejected",
                    input: b"bad abc/tcp",
                    expected_name: None,
                    expected_port: 0,
                    expected_proto: b"",
                    expected_aliases: &[],
                },
                Case {
                    id: "SERVICES-PARSE-010",
                    // Port > 65535 must be rejected (u16 overflow).
                    spec_ref: "services(5) ¶Format — port must fit u16 (0..=65535)",
                    input: b"bad 70000/tcp",
                    expected_name: None,
                    expected_port: 0,
                    expected_proto: b"",
                    expected_aliases: &[],
                },
                Case {
                    id: "SERVICES-PARSE-011",
                    spec_ref: "services(5) ¶Format — boundary: port 0 is valid",
                    input: b"nullport 0/tcp",
                    expected_name: Some(b"nullport"),
                    expected_port: 0,
                    expected_proto: b"tcp",
                    expected_aliases: &[],
                },
                Case {
                    id: "SERVICES-PARSE-012",
                    spec_ref: "services(5) ¶Format — boundary: port 65535 is valid",
                    input: b"maxport 65535/tcp",
                    expected_name: Some(b"maxport"),
                    expected_port: 65535,
                    expected_proto: b"tcp",
                    expected_aliases: &[],
                },
            ];

            let mut fails = Vec::new();
            for case in TABLE {
                let actual = parse_services_line(case.input);
                let pass = match (&actual, case.expected_name) {
                    (None, None) => true,
                    (Some(entry), Some(want_name)) => {
                        entry.name == want_name
                            && entry.port == case.expected_port
                            && entry.protocol == case.expected_proto
                            && entry.aliases.len() == case.expected_aliases.len()
                            && entry
                                .aliases
                                .iter()
                                .zip(case.expected_aliases.iter())
                                .all(|(a, b)| a == b)
                    }
                    _ => false,
                };
                if !pass {
                    fails.push(format!(
                        "{} [{}]: input={:?}, actual={:?}",
                        case.id,
                        case.spec_ref,
                        core::str::from_utf8(case.input).unwrap_or("<non-utf8>"),
                        actual,
                    ));
                }
            }
            prop_assert!(
                fails.is_empty(),
                "services(5) parse conformance failures:\n  {}",
                fails.join("\n  ")
            );
        }

        /// Biased alphabet containing the port-grammar delimiters
        /// ('/') and digit/alpha characters — a raw-byte fuzz almost
        /// never produces a '/' in the right spot to reach the port
        /// parsing branch, so this strategy is what actually exercises
        /// it.
        #[test]
        fn fuzz_parse_services_line_structured_alphabet_never_panics(
            bytes in proptest::collection::vec(
                prop_oneof![
                    Just(b' '), Just(b'\t'), Just(b'#'), Just(b'/'),
                    Just(b'0'), Just(b'1'), Just(b'9'),
                    Just(b'a'), Just(b'z'), Just(b'A'), Just(b'Z'),
                    Just(b'-'), Just(b'_'), Just(b'.'),
                    Just(0u8), Just(0xffu8),
                ],
                0..256,
            ),
        ) {
            let _ = parse_services_line(&bytes);
        }
    }

    // ---- parse_protocols_line ----

    #[test]
    fn protocol_basic_no_aliases() {
        let e = parse_protocols_line(b"tcp 6").unwrap();
        assert_eq!(e.name, b"tcp");
        assert_eq!(e.number, 6);
        assert!(e.aliases.is_empty());
    }

    #[test]
    fn protocol_with_aliases() {
        let e = parse_protocols_line(b"ip 0 IP # internet protocol").unwrap();
        assert_eq!(e.name, b"ip");
        assert_eq!(e.number, 0);
        assert_eq!(e.aliases, vec![b"IP".to_vec()]);
    }

    #[test]
    fn protocol_strips_inline_comment() {
        let e = parse_protocols_line(b"icmp 1 ICMP # internet control message").unwrap();
        assert_eq!(e.name, b"icmp");
        assert_eq!(e.number, 1);
        assert_eq!(e.aliases, vec![b"ICMP".to_vec()]);
    }

    #[test]
    fn protocol_skips_comment_only_line() {
        assert!(parse_protocols_line(b"# nothing here").is_none());
        assert!(parse_protocols_line(b"   # leading ws comment").is_none());
    }

    #[test]
    fn protocol_skips_blank_line() {
        assert!(parse_protocols_line(b"").is_none());
        assert!(parse_protocols_line(b"   \t  ").is_none());
    }

    #[test]
    fn protocol_rejects_non_numeric_number() {
        assert!(parse_protocols_line(b"foo bar").is_none());
    }

    #[test]
    fn protocol_lookup_by_name_case_insensitive() {
        let content = b"tcp 6 TCP\nudp 17 UDP\n";
        assert_eq!(lookup_protocol_by_name(content, b"TCP").unwrap().number, 6);
        assert_eq!(lookup_protocol_by_name(content, b"udp").unwrap().number, 17);
        assert_eq!(lookup_protocol_by_name(content, b"UDP").unwrap().number, 17);
    }

    #[test]
    fn protocol_lookup_by_number() {
        let content = b"tcp 6\nudp 17\nicmp 1\n";
        assert_eq!(lookup_protocol_by_number(content, 17).unwrap().name, b"udp");
        assert_eq!(lookup_protocol_by_number(content, 1).unwrap().name, b"icmp");
        assert!(lookup_protocol_by_number(content, 99).is_none());
    }

    #[test]
    fn protocol_alias_lookup_finds_main_entry() {
        let content = b"ip 0 IP\n";
        let e = lookup_protocol_by_name(content, b"ip").unwrap();
        assert_eq!(e.number, 0);
        let e = lookup_protocol_by_name(content, b"IP").unwrap();
        assert_eq!(e.name, b"ip");
    }

    // ---- parse_network_number ----

    #[test]
    fn netnum_plain_decimal() {
        assert_eq!(parse_network_number("0"), Some(0));
        assert_eq!(parse_network_number("42"), Some(42));
        assert_eq!(parse_network_number("4294967295"), Some(u32::MAX));
    }

    #[test]
    fn netnum_dotted_one_octet() {
        assert_eq!(parse_network_number("10."), None); // trailing empty octet
        assert_eq!(parse_network_number("10"), Some(10));
    }

    #[test]
    fn netnum_dotted_two_octet() {
        // 10.1 -> (10<<24)|(1<<16) = 0x0a010000
        assert_eq!(parse_network_number("10.1"), Some(0x0a01_0000));
    }

    #[test]
    fn netnum_dotted_three_octet() {
        // 192.168.1 -> (192<<24)|(168<<16)|(1<<8) = 0xc0a80100
        assert_eq!(parse_network_number("192.168.1"), Some(0xc0a8_0100));
    }

    #[test]
    fn netnum_dotted_four_octet() {
        // 127.0.0.1 -> 0x7f000001
        assert_eq!(parse_network_number("127.0.0.1"), Some(0x7f00_0001));
    }

    #[test]
    fn netnum_rejects_octet_over_255() {
        assert_eq!(parse_network_number("10.256"), None);
        assert_eq!(parse_network_number("256.1.1.1"), None);
    }

    #[test]
    fn netnum_rejects_non_numeric() {
        assert_eq!(parse_network_number("abc"), None);
        assert_eq!(parse_network_number("10.x.0.0"), None);
    }

    #[test]
    fn netnum_rejects_empty() {
        assert_eq!(parse_network_number(""), None);
    }

    #[test]
    fn netnum_rejects_too_many_octets() {
        assert_eq!(parse_network_number("1.2.3.4.5"), None);
    }

    // ---- parse_networks_line ----

    #[test]
    fn network_basic_plain_decimal() {
        // Plain decimal (no dots) is taken as-is, matching glibc's
        // inet_network("127") -> 127 behavior.
        let e = parse_networks_line(b"loopback 127").unwrap();
        assert_eq!(e.name, b"loopback");
        assert_eq!(e.number, 127);
        assert!(e.aliases.is_empty());
    }

    #[test]
    fn network_basic_dotted_full() {
        // Dotted full form 127.0.0.0 -> 0x7f000000 (the canonical loopback).
        let e = parse_networks_line(b"loopback 127.0.0.0").unwrap();
        assert_eq!(e.number, 0x7f00_0000);
    }

    #[test]
    fn network_with_dotted_quad() {
        let e = parse_networks_line(b"link-local 169.254").unwrap();
        assert_eq!(e.name, b"link-local");
        assert_eq!(e.number, (169u32 << 24) | (254 << 16));
    }

    #[test]
    fn network_with_aliases() {
        let e = parse_networks_line(b"loopback 127 lo localnet").unwrap();
        assert_eq!(e.name, b"loopback");
        assert_eq!(e.aliases.len(), 2);
        assert_eq!(e.aliases[0], b"lo");
        assert_eq!(e.aliases[1], b"localnet");
    }

    #[test]
    fn network_strips_inline_comment() {
        let e = parse_networks_line(b"loopback 127 lo # the loopback net").unwrap();
        assert_eq!(e.aliases, vec![b"lo".to_vec()]);
    }

    #[test]
    fn network_skips_comment_line() {
        assert!(parse_networks_line(b"# nothing").is_none());
    }

    #[test]
    fn network_skips_blank_line() {
        assert!(parse_networks_line(b"").is_none());
        assert!(parse_networks_line(b"  \t  ").is_none());
    }

    #[test]
    fn network_rejects_invalid_number() {
        assert!(parse_networks_line(b"foo bar").is_none());
        assert!(parse_networks_line(b"foo 256.0.0.0").is_none());
    }

    #[test]
    fn network_lookup_by_name_case_insensitive() {
        // Use dotted form so the number reflects the canonical
        // loopback / class-A network number.
        let content = b"loopback 127.0.0.0 lo\nclassA 10.0.0.0\n";
        assert_eq!(
            lookup_network_by_name(content, b"LOOPBACK").unwrap().number,
            0x7f00_0000
        );
        assert_eq!(
            lookup_network_by_name(content, b"lo").unwrap().name,
            b"loopback"
        );
    }

    #[test]
    fn network_lookup_by_number() {
        let content = b"loopback 127.0.0.0\nten 10.0.0.0\n";
        let e = lookup_network_by_number(content, 0x7f00_0000).unwrap();
        assert_eq!(e.name, b"loopback");
        let e = lookup_network_by_number(content, 0x0a00_0000).unwrap();
        assert_eq!(e.name, b"ten");
        assert!(lookup_network_by_number(content, 99).is_none());
    }

    #[test]
    fn network_lookup_alias_finds_canonical() {
        let content = b"loopback 127.0.0.0 lo localnet\n";
        let e = lookup_network_by_name(content, b"localnet").unwrap();
        assert_eq!(e.name, b"loopback");
        assert_eq!(e.number, 0x7f00_0000);
    }

    // ---- parse_addr_binary ----

    #[test]
    fn addr_family_addr_len() {
        assert_eq!(AddrFamily::Inet4.addr_len(), 4);
        assert_eq!(AddrFamily::Inet6.addr_len(), 16);
    }

    #[test]
    fn parse_addr_binary_ipv4_loopback() {
        let (buf, fam, len) = parse_addr_binary("127.0.0.1").unwrap();
        assert_eq!(fam, AddrFamily::Inet4);
        assert_eq!(len, 4);
        assert_eq!(&buf[..4], &[127, 0, 0, 1]);
        // Trailing 12 bytes should be zeroed.
        assert_eq!(&buf[4..], &[0; 12]);
    }

    #[test]
    fn parse_addr_binary_ipv4_arbitrary() {
        let (buf, fam, len) = parse_addr_binary("192.168.42.1").unwrap();
        assert_eq!(fam, AddrFamily::Inet4);
        assert_eq!(len, 4);
        assert_eq!(&buf[..4], &[192, 168, 42, 1]);
    }

    #[test]
    fn parse_addr_binary_ipv6_loopback_abbrev() {
        let (buf, fam, len) = parse_addr_binary("::1").unwrap();
        assert_eq!(fam, AddrFamily::Inet6);
        assert_eq!(len, 16);
        let mut expected = [0u8; 16];
        expected[15] = 1;
        assert_eq!(buf, expected);
    }

    #[test]
    fn parse_addr_binary_ipv6_full_form() {
        let (buf, fam, len) = parse_addr_binary("2001:db8::1").unwrap();
        assert_eq!(fam, AddrFamily::Inet6);
        assert_eq!(len, 16);
        let mut expected = [0u8; 16];
        expected[0] = 0x20;
        expected[1] = 0x01;
        expected[2] = 0x0d;
        expected[3] = 0xb8;
        expected[15] = 1;
        assert_eq!(buf, expected);
    }

    #[test]
    fn parse_addr_binary_ipv6_v4_mapped() {
        // ::ffff:127.0.0.1 — IPv4-mapped IPv6.
        let (buf, fam, len) = parse_addr_binary("::ffff:127.0.0.1").unwrap();
        assert_eq!(fam, AddrFamily::Inet6);
        assert_eq!(len, 16);
        // Last 4 bytes = 127.0.0.1, preceded by 0xFFFF.
        assert_eq!(&buf[10..12], &[0xff, 0xff]);
        assert_eq!(&buf[12..16], &[127, 0, 0, 1]);
    }

    #[test]
    fn parse_addr_binary_rejects_garbage() {
        assert_eq!(parse_addr_binary("not an address"), None);
        assert_eq!(parse_addr_binary("256.0.0.1"), None);
        assert_eq!(parse_addr_binary("foo::bar::baz"), None);
        assert_eq!(parse_addr_binary(""), None);
    }

    #[test]
    fn parse_addr_binary_rejects_trailing_text() {
        // std parsers require the entire input to be the address.
        assert_eq!(parse_addr_binary("127.0.0.1 extra"), None);
        assert_eq!(parse_addr_binary("::1 extra"), None);
    }

    #[test]
    fn parse_addr_binary_ipv4_zero_address() {
        let (buf, fam, len) = parse_addr_binary("0.0.0.0").unwrap();
        assert_eq!(fam, AddrFamily::Inet4);
        assert_eq!(len, 4);
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn parse_addr_binary_ipv4_max_octets() {
        let (buf, _, _) = parse_addr_binary("255.255.255.255").unwrap();
        assert_eq!(&buf[..4], &[0xff; 4]);
    }
}
