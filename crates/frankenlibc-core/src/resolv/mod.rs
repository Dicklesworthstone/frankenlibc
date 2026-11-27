//! DNS resolver functions.
//!
//! Implements `<netdb.h>` functions for hostname resolution.
//! Supports numeric addresses and file-based backends (/etc/hosts, /etc/services).
//!
//! # Submodules
//!
//! - `config`: Parses /etc/resolv.conf configuration
//! - `dns`: DNS protocol message encoding/decoding

pub mod b64;
pub mod config;
pub mod dns;
pub mod dns_name;
pub mod messages;

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

fn is_resolver_field_separator(b: u8) -> bool {
    b.is_ascii_whitespace()
}

/// Find a HOSTALIASES target without decoding the byte-oriented file as UTF-8.
///
/// GNU compares aliases case-insensitively and ignores unescaped trailing
/// dots. Leading whitespace does not introduce an alias. Unrelated malformed
/// rows are skipped, but the first matching row is authoritative, including
/// when its target is missing. The returned target is borrowed and is neither
/// expanded through the search list nor looked up as another alias.
pub fn lookup_hostalias<'a>(contents: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    fn separator(byte: u8) -> bool {
        // C isspace includes vertical tab, unlike u8::is_ascii_whitespace.
        byte.is_ascii_whitespace() || byte == b'\x0b'
    }

    fn without_root_dots(mut name: &[u8]) -> &[u8] {
        while name.last() == Some(&b'.') {
            let escapes = name[..name.len() - 1]
                .iter()
                .rev()
                .take_while(|&&byte| byte == b'\\')
                .count();
            if escapes % 2 != 0 {
                break;
            }
            name = &name[..name.len() - 1];
        }
        name
    }

    let name = without_root_dots(name);
    for line in contents.split_inclusive(|&byte| byte == b'\n') {
        // The GNU file reader uses an 8192-byte line buffer, including NUL.
        // Preserve its bounded records even when a physical line is longer.
        for part in line.chunks(8191) {
            let end = part
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(part.len());
            let part = &part[..end];
            let alias_end = part
                .iter()
                .position(|&byte| separator(byte))
                .unwrap_or(part.len());
            if !without_root_dots(&part[..alias_end]).eq_ignore_ascii_case(name) {
                continue;
            }
            return part[alias_end..]
                .split(|&byte| separator(byte))
                .find(|field| !field.is_empty());
        }
    }
    None
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
        .split(|&b| is_resolver_field_separator(b))
        .filter(|f| !f.is_empty());

    let addr_field = fields.next()?;
    let hostnames: Vec<Vec<u8>> = fields.map(|f| f.to_vec()).collect();
    if hostnames.is_empty() {
        return None;
    }

    // Validate the address is a real IP. IPv4 hosts rows dominate the hot
    // /etc/hosts path, so keep them on bytes and reserve UTF-8 parsing for IPv6.
    let valid_addr = is_valid_ipv4_addr_bytes(addr_field)
        || core::str::from_utf8(addr_field)
            .ok()
            .is_some_and(|addr| addr.parse::<Ipv6Addr>().is_ok());
    if valid_addr {
        Some((addr_field.to_vec(), hostnames))
    } else {
        None
    }
}

fn is_valid_ipv4_addr_bytes(bytes: &[u8]) -> bool {
    let mut index = 0usize;
    for part in 0..4 {
        let start = index;
        let mut value = 0u32;
        while let Some(&b) = bytes.get(index) {
            if b == b'.' {
                break;
            }
            if !b.is_ascii_digit() {
                return false;
            }
            value = value * 10 + u32::from(b - b'0');
            if value > 255 {
                return false;
            }
            index += 1;
        }
        if index == start {
            return false;
        }
        if index - start > 1 && bytes[start] == b'0' {
            return false;
        }
        if part == 3 {
            return index == bytes.len();
        }
        if bytes.get(index) != Some(&b'.') {
            return false;
        }
        index += 1;
    }
    false
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

/// Allocation-free analogue of [`lookup_hosts`]: calls `visit` with the address bytes of each
/// line whose hostname list contains `name` (ASCII case-insensitive), in file order, stopping
/// as soon as `visit` returns `true`.
///
/// Semantics are identical to `lookup_hosts` — same comment stripping, same field separators,
/// the same "non-empty hostname list AND valid IPv4/IPv6 address" acceptance test, and at most
/// one match per line. The difference is that nothing is allocated: `lookup_hosts` runs
/// `parse_hosts_line` on EVERY line, which builds an owned address `Vec` plus a `Vec<Vec<u8>>`
/// of hostnames, and then clones the matched address into a result `Vec<Vec<u8>>`. Here the
/// address slice simply aliases `content`.
pub fn for_each_hosts_match(content: &[u8], name: &[u8], mut visit: impl FnMut(&[u8]) -> bool) {
    for line in content.split(|&b| b == b'\n') {
        if let Some(addr) = hosts_line_match(line, name)
            && visit(addr)
        {
            return;
        }
    }
}

/// A borrowed matching `/etc/hosts` entry.
///
/// The first hostname is the canonical name; the remaining names are aliases.
/// All slices refer to the supplied hosts-file content.
#[derive(Clone, Copy, Debug)]
pub struct HostsMatch<'a> {
    address: &'a [u8],
    names: &'a [u8],
}

impl<'a> HostsMatch<'a> {
    /// The text form of the entry's IPv4 or IPv6 address.
    pub fn address(self) -> &'a [u8] {
        self.address
    }

    /// The entry's canonical hostname.
    pub fn canonical_name(self) -> &'a [u8] {
        self.names()
            .next()
            .expect("HostsMatch always contains a canonical hostname")
    }

    /// The entry's aliases, in file order.
    pub fn aliases(self) -> impl Iterator<Item = &'a [u8]> {
        self.names().skip(1)
    }

    fn names(self) -> impl Iterator<Item = &'a [u8]> {
        self.names
            .split(|&b| is_resolver_field_separator(b))
            .filter(|field| !field.is_empty())
    }
}

/// Allocation-free variant of [`for_each_hosts_match`] that preserves the
/// canonical hostname and aliases belonging to every matching entry.
pub fn for_each_hosts_match_entry(
    content: &[u8],
    name: &[u8],
    mut visit: impl FnMut(HostsMatch<'_>) -> bool,
) {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = hosts_line_match_entry(line, name)
            && visit(entry)
        {
            return;
        }
    }
}

/// Borrowed core of [`for_each_hosts_match`]: the address field of `line` iff `line` parses as a
/// hosts entry (per [`parse_hosts_line`]) and one of its hostnames equals `name`.
fn hosts_line_match<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    hosts_line_match_entry(line, name).map(HostsMatch::address)
}

/// Borrowed core of [`for_each_hosts_match_entry`].
fn hosts_line_match_entry<'a>(line: &'a [u8], name: &[u8]) -> Option<HostsMatch<'a>> {
    // Strip comments (as `parse_hosts_line`).
    let line = if let Some(pos) = line.iter().position(|&b| b == b'#') {
        &line[..pos]
    } else {
        line
    };

    let mut fields = line
        .split(|&b| is_resolver_field_separator(b))
        .filter(|f| !f.is_empty());

    let addr_field = fields.next()?;

    // `parse_hosts_line` rejects a line with no hostnames; `lookup_hosts` then accepts the line
    // only if some hostname matches. Both conditions must hold, so test them together.
    let names_start = (addr_field.as_ptr() as usize - line.as_ptr() as usize) + addr_field.len();
    let names = &line[names_start..];
    let mut names_iter = names
        .split(|&b| is_resolver_field_separator(b))
        .filter(|field| !field.is_empty());
    let canonical_name = names_iter.next()?;
    if !eq_ignore_ascii_case(canonical_name, name)
        && !names_iter.any(|field| eq_ignore_ascii_case(field, name))
    {
        return None;
    }

    // Same address validation as `parse_hosts_line`.
    let valid_addr = is_valid_ipv4_addr_bytes(addr_field)
        || core::str::from_utf8(addr_field)
            .ok()
            .is_some_and(|addr| addr.parse::<Ipv6Addr>().is_ok());
    valid_addr.then_some(HostsMatch {
        address: addr_field,
        names,
    })
}

/// Allocation-free analogue of [`reverse_lookup_hosts`] for the only shape its callers use: the
/// FIRST hostname of the FIRST line whose address denotes the same IP as `addr`.
///
/// `reverse_lookup_hosts` skips lines that fail [`parse_hosts_line`] (invalid address, or no
/// hostnames), takes the first line whose address matches, and returns that line's hostnames —
/// and every deployed caller then uses `[0]` / `.first()`. This preserves that order without
/// building an owned address `Vec`, a `Vec<Vec<u8>>` of hostnames per line, or the result vector.
/// The returned slice aliases `content`.
pub fn first_reverse_hosts_hostname<'a>(content: &'a [u8], addr: &[u8]) -> Option<&'a [u8]> {
    // Different IPv6 spellings denote the same address. Keep the direct byte
    // comparison, but do not let compression or case bypass a files entry.
    let parse = |bytes: &[u8]| {
        core::str::from_utf8(bytes)
            .ok()?
            .parse::<std::net::IpAddr>()
            .ok()
    };
    let address = parse(addr);
    for line in content.split(|&b| b == b'\n') {
        if let Some((line_addr, first_hostname)) = hosts_line_addr_and_first_hostname(line)
            && (line_addr == addr || (address.is_some() && parse(line_addr) == address))
        {
            return Some(first_hostname);
        }
    }
    None
}

/// Borrowed core of [`first_reverse_hosts_hostname`]: `(address, first hostname)` iff `line` is a
/// valid hosts entry per [`parse_hosts_line`] (valid IPv4/IPv6 address AND at least one hostname).
fn hosts_line_addr_and_first_hostname(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let line = if let Some(pos) = line.iter().position(|&b| b == b'#') {
        &line[..pos]
    } else {
        line
    };

    let mut fields = line
        .split(|&b| is_resolver_field_separator(b))
        .filter(|f| !f.is_empty());

    let addr_field = fields.next()?;
    let first_hostname = fields.next()?; // `parse_hosts_line` rejects an empty hostname list.

    let valid_addr = is_valid_ipv4_addr_bytes(addr_field)
        || core::str::from_utf8(addr_field)
            .ok()
            .is_some_and(|addr| addr.parse::<Ipv6Addr>().is_ok());
    valid_addr.then_some((addr_field, first_hostname))
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
    let (line, record) = parse_netdb_database_line(NssNetdbKind::Service, line)?;
    let NssNetdbValue::Service { port, protocol } = record.value else {
        return None;
    };
    Some(ServiceEntry {
        name: line[record.name].to_vec(),
        port,
        protocol: line[protocol].to_vec(),
        aliases: line[record.aliases]
            .split(|&byte| nss_netdb_space(byte))
            .filter(|alias| !alias.is_empty())
            .map(<[u8]>::to_vec)
            .collect(),
    })
}

/// Parse the bounded unsigned-decimal field used by the public RPC reader.
///
/// Whole services and protocols records use [`parse_nss_netdb_line`] instead,
/// including its unsigned-long sign and line-termination rules.
///
///   * an optional `+` is accepted; negative fields are rejected;
///   * the digits are read as UNSIGNED and must fit 32 bits: "2147483648" is
///     accepted and comes back as -2147483648, while "4294967296" and
///     "99999999999" are refused;
///   * anything non-decimal fails, including "0x6" and a trailing "8x".
#[must_use]
pub fn parse_nss_int32_field(field: &[u8]) -> Option<i32> {
    let digits = match field {
        [b'+', rest @ ..] => rest,
        other => other,
    };
    if digits.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
        if value > u64::from(u32::MAX) {
            return None;
        }
    }
    // Storing an unsigned 32-bit value in a signed int keeps the bit pattern.
    Some(value as u32 as i32)
}

fn service_name_matches(entry: &ServiceEntry, name: &[u8]) -> bool {
    entry.name == name || entry.aliases.iter().any(|alias| alias == name)
}

/// The GNU files-module parsers consume a writable line and return pointers
/// into that line. Public database readers share this grammar after removing
/// leading whitespace, which module callers have already removed. Services
/// accept C-style integer bases while protocols and RPC use decimal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NssNetdbKind {
    Ether,
    Network,
    Protocol,
    Rpc,
    Service,
}

#[derive(Debug, PartialEq, Eq)]
pub enum NssNetdbValue {
    Ether([u8; 6]),
    Network(u32),
    Protocol(i32),
    Rpc(i32),
    Service {
        port: u16,
        protocol: core::ops::Range<usize>,
    },
}

/// All ranges refer to the original immutable input. The ABI validates the
/// complete alias table before terminating any strings or publishing pointers.
#[derive(Debug, PartialEq, Eq)]
pub struct NssNetdbRecord {
    pub name: core::ops::Range<usize>,
    pub aliases: core::ops::Range<usize>,
    pub alias_count: usize,
    pub value: NssNetdbValue,
}

#[derive(Debug, PartialEq, Eq)]
pub struct NssNetdbParse {
    pub record: Option<NssNetdbRecord>,
    pub line_end: usize,
    /// GNU's unsigned-long conversion changes errno even on a skipped line.
    pub overflowed: bool,
}

fn nss_netdb_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn nss_netdb_word(line: &[u8], cursor: &mut usize) -> core::ops::Range<usize> {
    let start = *cursor;
    while *cursor < line.len() && !nss_netdb_space(line[*cursor]) {
        *cursor += 1;
    }
    start..*cursor
}

fn nss_netdb_skip_space(line: &[u8], cursor: &mut usize) {
    while *cursor < line.len() && nss_netdb_space(line[*cursor]) {
        *cursor += 1;
    }
}

/// Apply the files reader's leading-whitespace preparation before using the
/// same parser as reentrant lookups and enumeration. Owned caches must not
/// reinterpret numeric fields, NUL termination, or alias boundaries.
fn parse_netdb_database_line(kind: NssNetdbKind, input: &[u8]) -> Option<(&[u8], NssNetdbRecord)> {
    let mut leading = 0;
    nss_netdb_skip_space(input, &mut leading);
    let line = &input[leading..];
    let record = parse_nss_netdb_line(kind, line).record?;
    Some((line, record))
}

fn nss_netdb_unsigned(field: &[u8], base: u64) -> (Option<u64>, bool) {
    let negative = field.starts_with(b"-");
    let field = if negative || field.starts_with(b"+") {
        &field[1..]
    } else {
        field
    };
    let (digits, base) =
        if (base == 0 || base == 16) && (field.starts_with(b"0x") || field.starts_with(b"0X")) {
            (&field[2..], 16u64)
        } else if base == 0 && field.starts_with(b"0") {
            (field, 8)
        } else {
            (field, if base == 0 { 10 } else { base })
        };
    if digits.is_empty() {
        return (None, false);
    }
    let mut value = 0u64;
    let mut overflowed = false;
    for &byte in digits {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return (None, overflowed),
        };
        if digit >= base {
            return (None, overflowed);
        }
        if let Some(next) = value.checked_mul(base).and_then(|v| v.checked_add(digit)) {
            value = next;
        } else {
            overflowed = true;
        }
    }
    (
        (!overflowed).then(|| {
            if negative {
                value.wrapping_neg()
            } else {
                value
            }
        }),
        overflowed,
    )
}

fn nss_netdb_number(field: &[u8], auto_base: bool) -> (Option<u32>, bool) {
    let (value, overflowed) = nss_netdb_unsigned(field, if auto_base { 0 } else { 10 });
    (
        value.and_then(|number| u32::try_from(number).ok()),
        overflowed,
    )
}

/// Parse the five non-account `_nss_files_parse_*` contracts without pointers,
/// allocation, or input mutation. A bad network number is the GNU sentinel
/// INADDR_NONE in an otherwise valid record; it is not a skipped record.
#[must_use]
pub fn parse_nss_netdb_line(kind: NssNetdbKind, input: &[u8]) -> NssNetdbParse {
    let line_end = input
        .iter()
        .position(|&byte| matches!(byte, 0 | b'#' | b'\n'))
        .unwrap_or(input.len());
    let line = &input[..line_end];
    let mut parsed = NssNetdbParse {
        record: None,
        line_end,
        overflowed: false,
    };
    if line.is_empty() && kind != NssNetdbKind::Network {
        return parsed;
    }
    let mut cursor = 0;
    if kind == NssNetdbKind::Ether {
        let mut address = [0; 6];
        for (index, octet) in address.iter_mut().enumerate() {
            // GNU uses unsigned-long hexadecimal conversion for each octet:
            // leading zeroes, a sign, 0x, and whitespace after ':' are legal.
            nss_netdb_skip_space(line, &mut cursor);
            let start = cursor;
            let end = if index == 5 {
                nss_netdb_word(line, &mut cursor).end
            } else if let Some(colon) = line[start..].iter().position(|&byte| byte == b':') {
                cursor = start + colon + 1;
                start + colon
            } else {
                return parsed;
            };
            let (number, overflowed) = nss_netdb_unsigned(&line[start..end], 16);
            parsed.overflowed |= overflowed;
            let Some(number) = number.and_then(|value| u8::try_from(value).ok()) else {
                return parsed;
            };
            *octet = number;
        }
        nss_netdb_skip_space(line, &mut cursor);
        let name = nss_netdb_word(line, &mut cursor);
        parsed.record = Some(NssNetdbRecord {
            name,
            aliases: line_end..line_end,
            alias_count: 0,
            value: NssNetdbValue::Ether(address),
        });
        return parsed;
    }

    let name = nss_netdb_word(line, &mut cursor);
    nss_netdb_skip_space(line, &mut cursor);
    let field = nss_netdb_word(line, &mut cursor);
    let value = match kind {
        NssNetdbKind::Network => {
            let number = parse_network_number_components(&line[field.clone()])
                .map(|(value, components)| value << (8 * (4 - components)))
                .unwrap_or(u32::MAX);
            NssNetdbValue::Network(number)
        }
        NssNetdbKind::Protocol | NssNetdbKind::Rpc => {
            let (number, overflowed) = nss_netdb_number(&line[field], false);
            parsed.overflowed = overflowed;
            let Some(number) = number else {
                return parsed;
            };
            if kind == NssNetdbKind::Protocol {
                NssNetdbValue::Protocol(number as i32)
            } else {
                NssNetdbValue::Rpc(number as i32)
            }
        }
        NssNetdbKind::Service => {
            let separator = line[field.clone()].iter().position(|&b| b == b'/');
            let number_end = separator.map_or(field.end, |n| field.start + n);
            let (number, overflowed) = nss_netdb_number(&line[field.start..number_end], true);
            parsed.overflowed = overflowed;
            let Some(number) = number else {
                return parsed;
            };
            if separator.is_none() && field.end != line_end {
                return parsed;
            }
            NssNetdbValue::Service {
                port: number as u16,
                protocol: separator.map_or(field.end, |_| number_end + 1)..field.end,
            }
        }
        NssNetdbKind::Ether => unreachable!(),
    };
    nss_netdb_skip_space(line, &mut cursor);
    let aliases = cursor..line_end;
    let mut alias_count = 0;
    while cursor < line_end {
        let _ = nss_netdb_word(line, &mut cursor);
        alias_count += 1;
        nss_netdb_skip_space(line, &mut cursor);
    }
    parsed.record = Some(NssNetdbRecord {
        name,
        aliases,
        alias_count,
        value,
    });
    parsed
}

/// Terminate the already parsed aliases in place and report each start offset.
/// The caller has reserved `alias_count + 2` pointer slots before invoking this.
pub fn split_nss_netdb_aliases(
    text: &mut [u8],
    aliases: core::ops::Range<usize>,
    mut emit: impl FnMut(usize),
) {
    let mut cursor = aliases.start;
    while cursor < aliases.end {
        while cursor < aliases.end && nss_netdb_space(text[cursor]) {
            cursor += 1;
        }
        if cursor == aliases.end {
            break;
        }
        emit(cursor);
        while cursor < aliases.end && !nss_netdb_space(text[cursor]) {
            cursor += 1;
        }
        text[cursor] = 0;
        cursor += 1;
    }
}

#[cfg(test)]
mod nss_netdb_tests {
    use super::{NssNetdbKind as Kind, NssNetdbValue as Value, *};

    #[test]
    fn network_parser_keeps_invalid_number_records_and_classful_prefixes() {
        for (line, number) in [
            (&b"loop 127 lo"[..], 0x7f00_0000),
            (&b"local 0x7f.01 alias"[..], 0x7f01_0000),
            (&b"bad 09 alias"[..], u32::MAX),
            (&b"bad 256 alias"[..], u32::MAX),
            (&b"missing"[..], u32::MAX),
            (&b"# comment"[..], u32::MAX),
            (&b""[..], u32::MAX),
        ] {
            let record = parse_nss_netdb_line(Kind::Network, line).record.unwrap();
            assert_eq!(record.value, Value::Network(number), "{line:?}");
        }
    }

    #[test]
    fn protocol_and_rpc_numbers_preserve_unsigned_long_conversion() {
        for kind in [Kind::Protocol, Kind::Rpc] {
            for (field, expected) in [
                ("+6", 6),
                ("-0", 0),
                ("2147483648", i32::MIN),
                ("4294967295", -1),
                ("-18446744073709551615", 1),
            ] {
                let line = format!("name {field} alias");
                let parsed = parse_nss_netdb_line(kind, line.as_bytes());
                let record = parsed.record.unwrap();
                let value = match record.value {
                    Value::Protocol(value) | Value::Rpc(value) => value,
                    _ => panic!("wrong database value"),
                };
                assert_eq!(value, expected, "{line}");
                assert_eq!(record.alias_count, 1);
                assert!(!parsed.overflowed);
            }
            for field in ["-1", "4294967296", "0x6", "6garbage", ""] {
                assert!(
                    parse_nss_netdb_line(kind, format!("name {field}").as_bytes())
                        .record
                        .is_none()
                );
            }
            let parsed = parse_nss_netdb_line(kind, b"name 18446744073709551616junk");
            assert!(parsed.record.is_none());
            assert!(parsed.overflowed);
        }
    }

    #[test]
    fn service_parser_accepts_c_bases_and_preserves_protocol_boundaries() {
        for (line, port, protocol) in [
            (&b"http 0x50/tcp alias"[..], 80, &b"tcp"[..]),
            (&b"echo 010/udp"[..], 8, &b"udp"[..]),
            (&b"wrap 65536/tcp/extra"[..], 0, &b"tcp/extra"[..]),
            (&b"empty 80/ alias"[..], 80, &b""[..]),
            (&b"empty 80"[..], 80, &b""[..]),
            (&b"negative -0/tcp"[..], 0, &b"tcp"[..]),
        ] {
            let record = parse_nss_netdb_line(Kind::Service, line).record.unwrap();
            let Value::Service {
                port: actual_port,
                protocol: range,
            } = record.value
            else {
                panic!("wrong database value");
            };
            assert_eq!(actual_port, port);
            assert_eq!(&line[range], protocol);
        }
        for line in [
            &b"http 080/tcp"[..],
            b"http 80 ",
            b"http 80 /tcp",
            b"http /tcp",
        ] {
            assert!(
                parse_nss_netdb_line(Kind::Service, line).record.is_none(),
                "{line:?}"
            );
        }
    }

    #[test]
    fn ether_parser_uses_complete_hexadecimal_octets() {
        for line in [
            &b"000:001:002:003:004:005 host"[..],
            b"+0: 0x1:2:3:4:0005 host",
            b"-0:1:2:3:4:5 host ignored",
            b"0:1:2:3:4:5\x0bhost",
        ] {
            let record = parse_nss_netdb_line(Kind::Ether, line).record.unwrap();
            assert_eq!(record.value, Value::Ether([0, 1, 2, 3, 4, 5]));
            assert_eq!(&line[record.name], b"host");
            assert_eq!(record.alias_count, 0);
        }
        for line in [
            &b"0:1:2:3:4:100 host"[..],
            b"0:1:2:3:4:05x host",
            b"0 :1:2:3:4:5 host",
            b"0:1:2:3:4:5:6 host",
        ] {
            assert!(
                parse_nss_netdb_line(Kind::Ether, line).record.is_none(),
                "{line:?}"
            );
        }
        assert!(parse_nss_netdb_line(Kind::Ether, b"0:1:2:3:4:fffffffffffffffff host").overflowed);
    }

    #[test]
    fn comments_whitespace_and_alias_offsets_share_the_original_line() {
        let input = b"tcp\x0b6\x0cTCP\talt # ignored\nnext";
        let parsed = parse_nss_netdb_line(Kind::Protocol, input);
        let record = parsed.record.unwrap();
        assert_eq!(&input[record.name], b"tcp");
        assert_eq!(record.alias_count, 2);
        let mut storage = input.to_vec();
        storage.push(0);
        storage[parsed.line_end] = 0;
        let mut offsets = Vec::new();
        split_nss_netdb_aliases(&mut storage, record.aliases, |offset| offsets.push(offset));
        let words: Vec<_> = offsets
            .into_iter()
            .map(|offset| {
                let rest = &storage[offset..];
                &rest[..rest.iter().position(|&byte| byte == 0).unwrap()]
            })
            .collect();
        assert_eq!(words, [b"TCP".as_slice(), b"alt".as_slice()]);
    }
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
/// Comments (`#`) and blank lines yield `None`. The number is parsed from
/// ASCII decimal digits and stored as `int p_proto`.
pub fn parse_protocols_line(line: &[u8]) -> Option<ProtocolEntry> {
    let (line, record) = parse_netdb_database_line(NssNetdbKind::Protocol, line)?;
    let NssNetdbValue::Protocol(number) = record.value else {
        return None;
    };
    Some(ProtocolEntry {
        name: line[record.name].to_vec(),
        number,
        aliases: line[record.aliases]
            .split(|&byte| nss_netdb_space(byte))
            .filter(|alias| !alias.is_empty())
            .map(<[u8]>::to_vec)
            .collect(),
    })
}

fn protocol_name_matches(entry: &ProtocolEntry, name: &[u8]) -> bool {
    entry.name == name || entry.aliases.iter().any(|alias| alias == name)
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
        .split(|&b| is_resolver_field_separator(b))
        .filter(|f| !f.is_empty());
    let name = fields.next()?;
    // LEFT-ALIGN here, not in the helper. getnetent shifts the value up by one
    // byte per ABSENT component — "127" is 0x7f000000, not 0x7f — while
    // inet_network, which shares the fold below, returns the right-aligned
    // number. Putting the shift in the shared helper (f5317dccd) fixed this
    // path and broke that contract; see parse_network_number_components.
    let (raw, components) = parse_network_number_components(fields.next()?)?;
    let number = raw << (8 * (4 - components));
    let aliases: Vec<Vec<u8>> = fields.map(|f| f.to_vec()).collect();
    Some(NetworkEntry {
        name: name.to_vec(),
        number,
        aliases,
    })
}

/// Parse a /etc/networks number field, matching glibc's `inet_network`.
///
/// glibc's `nss_files` parser feeds the number token to `inet_network`,
/// so this must reproduce its exact semantics — NOT the left-padded
/// dotted-quad behavior of `inet_aton`:
///
/// * Each `.`-separated component is parsed in base-16 (`0x` prefix),
///   base-8 (leading `0`), or base-10, and must be `<= 0xff`.
/// * The result is LEFT-aligned: components are folded
///   `result = (result << 8) | component` in order and then shifted up by one
///   byte per absent component, so a single token `127` yields `0x7f00_0000`
///   (NOT `0x0000_007f`) and `127.0` also yields `0x7f00_0000`.
///
///   This doc previously stated the opposite, and the code implemented what it
///   said. `inet_network("127")` really is `0x0000_007f` — but the netent
///   parser is not `inet_network`, and getnetent reports `0x7f00_0000`. The
///   right-aligned rule was true of the function this one is named after and
///   false of the file format it parses.
/// * At most four components are allowed; empty components (e.g. a
///   trailing `.`) and out-of-range values reject the whole field.
pub fn parse_network_number(s: &str) -> Option<u32> {
    parse_network_number_bytes(s.as_bytes())
}

fn parse_network_number_bytes(bytes: &[u8]) -> Option<u32> {
    parse_network_number_components(bytes).map(|(value, _)| value)
}

/// The `inet_network` fold, plus how many dot-separated components it consumed.
///
/// RIGHT-ALIGNED, deliberately: this is `inet_network`'s contract and it is
/// pinned to the live function by conformance_diff_network_number.rs. The
/// component count exists so `parse_networks_line` can LEFT-align on top,
/// because getnetent does not report what inet_network returns:
///
///     token        inet_network   getnetent n_net
///     "127"         0x0000007f     0x7f000000
///     "192.168"     0x0000c0a8     0xc0a80000
///     "10.0.0"      0x000a0000     0x0a000000
///     "10.0.0.1"    0x0a000001     0x0a000001
///
/// Both measured on the host — the second column by calling inet_network, the
/// third by bind-mounting a synthetic /etc/networks and walking getnetent. Only
/// the full dotted quad agrees, and /etc/networks is conventionally written
/// short, so the two rules genuinely differ for almost every real entry.
///
/// The shift lived in THIS function briefly (f5317dccd) and that was wrong: it
/// fixed the netent path by breaking the inet_network contract the function is
/// named for and gated against. One helper, two callers, two rules — the shift
/// belongs to the caller that needs it.
fn parse_network_number_components(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.is_empty() {
        return None;
    }
    let mut result: u32 = 0;
    let mut components = 0u32;
    for part in bytes.split(|&b| b == b'.') {
        if components >= 4 {
            return None;
        }
        let v = parse_network_component_bytes(part)?;
        result = (result << 8) | v;
        components += 1;
    }
    Some((result, components))
}

/// Parse one `inet_network` component: base-16/8/10 with a `<= 0xff` cap.
fn parse_network_component_bytes(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let (radix, digits): (u32, &[u8]) =
        if bytes.len() >= 2 && bytes[0] == b'0' && (bytes[1] | 0x20) == b'x' {
            (16, &bytes[2..])
        } else if bytes.len() > 1 && bytes[0] == b'0' {
            (8, &bytes[1..])
        } else {
            (10, bytes)
        };
    if digits.is_empty() {
        return None;
    }
    let mut value: u32 = 0;
    for &c in digits {
        let digit = match c {
            b'0'..=b'9' => (c - b'0') as u32,
            b'a'..=b'f' => (c - b'a' + 10) as u32,
            b'A'..=b'F' => (c - b'A' + 10) as u32,
            _ => return None,
        };
        if digit >= radix {
            return None;
        }
        value = value.checked_mul(radix)?.checked_add(digit)?;
        if value > 0xff {
            return None;
        }
    }
    Some(value)
}

#[cfg(test)]
fn parse_ascii_decimal_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0u32;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(value)
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
                if entry.protocol == filter {
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
        let mut cursor = 0usize;
        let Some(iface) = next_procfs_space_tab_field(line, &mut cursor) else {
            continue;
        };
        let _destination = next_procfs_space_tab_field(line, &mut cursor);
        let _gateway = next_procfs_space_tab_field(line, &mut cursor);
        let Some(flags) = next_procfs_space_tab_field(line, &mut cursor) else {
            continue;
        };

        if iface == b"lo" {
            continue;
        }

        let Some(flags) = parse_proc_net_route_flags(flags) else {
            continue;
        };
        if (flags & 0x1) != 0 {
            return true;
        }
    }
    false
}

fn parse_proc_net_route_flags(field: &[u8]) -> Option<u32> {
    if field.is_empty() {
        return None;
    }

    let mut value = 0u32;
    for &b in field {
        let digit = match b {
            b'0'..=b'9' => u32::from(b - b'0'),
            b'a'..=b'f' => u32::from(b - b'a') + 10,
            b'A'..=b'F' => u32::from(b - b'A') + 10,
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(digit)?;
    }
    Some(value)
}

/// Parse `/proc/net/if_inet6` content and report whether a non-loopback IPv6 address exists.
#[must_use]
pub fn parse_proc_net_if_inet6_has_ipv6(content: &[u8]) -> bool {
    for line in content.split(|&b| b == b'\n') {
        let mut fields = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|field| !field.is_empty());
        let Some(addr) = fields.next() else {
            continue;
        };
        let Some(ifindex) = fields.next() else {
            continue;
        };
        let Some(prefix_len) = fields.next() else {
            continue;
        };
        let Some(scope) = fields.next() else {
            continue;
        };
        let Some(flags) = fields.next() else {
            continue;
        };
        let Some(iface) = fields.next() else {
            continue;
        };
        if fields.next().is_some()
            || !is_ascii_hex_exact_len(addr, 32)
            || !is_ascii_hex_nonempty(ifindex)
            || !is_ascii_hex_nonempty(prefix_len)
            || !is_ascii_hex_nonempty(scope)
            || !is_ascii_hex_nonempty(flags)
        {
            continue;
        }
        if iface != b"lo" {
            return true;
        }
    }
    false
}

fn next_procfs_space_tab_field<'a>(line: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    while *cursor < line.len() && (line[*cursor] == b' ' || line[*cursor] == b'\t') {
        *cursor += 1;
    }

    let start = *cursor;
    while *cursor < line.len() && line[*cursor] != b' ' && line[*cursor] != b'\t' {
        *cursor += 1;
    }

    (start != *cursor).then_some(&line[start..*cursor])
}

fn is_ascii_hex_exact_len(field: &[u8], len: usize) -> bool {
    field.len() == len && is_ascii_hex_nonempty(field)
}

fn is_ascii_hex_nonempty(field: &[u8]) -> bool {
    !field.is_empty() && field.iter().all(u8::is_ascii_hexdigit)
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

/// Derive `AI_ADDRCONFIG` from a complete Linux `RTM_GETADDR` dump.
///
/// Address availability is independent of the routing table: an address can
/// be configured without a route. Netlink integer fields use native byte
/// order, while `IFA_ADDRESS`/`IFA_LOCAL` payloads are network-order octets.
/// `IFA_LOCAL` takes precedence for point-to-point interfaces. Loopback and
/// unspecified addresses do not establish a configured family.
///
/// A partial, interrupted or failed dump is unknown, not evidence that an
/// address family is absent. Callers must leave their results unfiltered
/// when this returns `None`.
#[must_use]
pub fn addrconfig_state_from_netlink(data: &[u8]) -> Option<AddrConfigState> {
    const HEADER: usize = 16;
    const ADDRESS_HEADER: usize = 8;
    const NLMSG_DONE: u16 = 3;
    const RTM_NEWADDR: u16 = 20;
    const NLM_F_DUMP_INTR: u16 = 0x10;

    let mut state = AddrConfigState::default();
    let mut remaining = data;
    while !remaining.is_empty() {
        let header = remaining.get(..HEADER)?;
        let length = u32::from_ne_bytes(header[..4].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(header[4..6].try_into().ok()?);
        let flags = u16::from_ne_bytes(header[6..8].try_into().ok()?);
        if length < HEADER || flags & NLM_F_DUMP_INTR != 0 {
            return None;
        }
        let message = remaining.get(..length)?;
        let body = &message[HEADER..];
        if kind == NLMSG_DONE {
            // Modern kernels include an error code in NLMSG_DONE. Older
            // kernels can send just the header. Never credit a failed dump.
            if !body.is_empty() && i32::from_ne_bytes(body.get(..4)?.try_into().ok()?) != 0 {
                return None;
            }
            return (remaining.len() == length).then_some(state);
        }
        if matches!(kind, 2 | 4) {
            // NLMSG_ERROR / NLMSG_OVERRUN invalidate the entire snapshot.
            return None;
        }
        if kind == RTM_NEWADDR {
            let address_header = body.get(..ADDRESS_HEADER)?;
            let family = i32::from(address_header[0]);
            if matches!(family, AF_INET | AF_INET6) {
                let width = if family == AF_INET { 4 } else { 16 };
                let mut address = None;
                let mut local = None;
                let mut attributes = &body[ADDRESS_HEADER..];
                while !attributes.is_empty() {
                    let attr_header = attributes.get(..4)?;
                    let attr_length =
                        usize::from(u16::from_ne_bytes(attr_header[..2].try_into().ok()?));
                    let attr_kind = u16::from_ne_bytes(attr_header[2..4].try_into().ok()?);
                    if attr_length < 4 {
                        return None;
                    }
                    let attribute = attributes.get(..attr_length)?;
                    if matches!(attr_kind, 1 | 2) {
                        let value = &attribute[4..];
                        if value.len() != width {
                            return None;
                        }
                        if attr_kind == 2 {
                            local = Some(value);
                        } else {
                            address = Some(value);
                        }
                    }
                    let aligned = attr_length.checked_add(3)? & !3;
                    attributes = if attr_length == attributes.len() {
                        &[]
                    } else {
                        attributes.get(aligned..)?
                    };
                }
                let value = local.or(address)?;
                if family == AF_INET {
                    let ip = Ipv4Addr::from(<[u8; 4]>::try_from(value).ok()?);
                    state.has_ipv4 |= !ip.is_loopback() && !ip.is_unspecified();
                } else {
                    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(value).ok()?);
                    state.has_ipv6 |= !ip.is_loopback() && !ip.is_unspecified();
                }
            }
        }
        let aligned = length.checked_add(3)? & !3;
        remaining = remaining.get(aligned..)?;
    }
    // EOF without NLMSG_DONE may follow a failed recv or a truncated datagram.
    None
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

    #[test]
    fn hostaliases_skip_unrelated_bad_rows_and_preserve_target_bytes() {
        let file = b"\n# comment\nbroken\nother \xff\n alias wrong.test\nALIAS\x0bTarget.\xff\r\n";
        assert_eq!(
            lookup_hostalias(file, b"alias"),
            Some(b"Target.\xff".as_slice())
        );
        assert_eq!(lookup_hostalias(file, b"missing"), None);
        assert_eq!(
            lookup_hostalias(b"alias first\0ignored\nalias second\n", b"alias"),
            Some(b"first".as_slice())
        );
    }

    #[test]
    fn hostaliases_first_matching_row_is_authoritative() {
        for file in [
            b"alias\nalias later.test\n".as_slice(),
            b"alias \nalias later.test\n".as_slice(),
            b"alias\0 ignored\nalias later.test\n".as_slice(),
        ] {
            assert_eq!(lookup_hostalias(file, b"alias"), None);
        }
        assert_eq!(
            lookup_hostalias(b"alias first.test extra\nalias second.test\n", b"alias"),
            Some(b"first.test".as_slice())
        );
    }

    #[test]
    fn hostaliases_name_comparison_preserves_escapes() {
        assert_eq!(
            lookup_hostalias(b"ALIAS.. target.test\n", b"alias."),
            Some(b"target.test".as_slice())
        );
        assert_eq!(lookup_hostalias(br"alias\. target.test", br"alias\"), None);
        assert_eq!(lookup_hostalias(br"a\046b target.test", br"a\.b"), None);
        assert_eq!(
            lookup_hostalias(br"a\.b target.test", br"A\.B"),
            Some(b"target.test".as_slice())
        );
    }

    #[test]
    fn hostaliases_long_lines_observe_bounded_records() {
        let mut file = b"alias ".to_vec();
        file.extend(std::iter::repeat_n(b'x', 9000));
        file.push(b'\n');
        let target = lookup_hostalias(&file, b"alias").unwrap();
        assert_eq!(target.len(), 8191 - b"alias ".len());
        assert!(target.iter().all(|&byte| byte == b'x'));
        assert!(std::ptr::eq(
            target.as_ptr(),
            file[b"alias ".len()..].as_ptr()
        ));
    }

    #[test]
    fn reverse_hosts_accepts_equivalent_ipv6_spellings_in_file_order() {
        let content =
            b"2001:DB8:0000:0000:0000:0000:0000:0009 first.test alias\n2001:db8::9 later.test\n";
        assert_eq!(
            first_reverse_hosts_hostname(content, b"2001:db8::9"),
            Some(b"first.test".as_slice())
        );
        assert_eq!(first_reverse_hosts_hostname(content, b"2001:db8::a"), None);
    }

    #[test]
    fn reverse_hosts_keeps_family_identity_and_skips_invalid_rows() {
        let content = b"not-an-ip bad.test\n192.0.2.9\n::ffff:192.0.2.9 mapped.test\n192.0.2.9 v4.test alias\n";
        assert_eq!(
            first_reverse_hosts_hostname(content, b"192.0.2.9"),
            Some(b"v4.test".as_slice())
        );
        assert_eq!(
            first_reverse_hosts_hostname(content, b"::ffff:c000:209"),
            Some(b"mapped.test".as_slice())
        );
        assert_eq!(first_reverse_hosts_hostname(content, b"not-an-ip"), None);
    }

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
    fn ipv4_byte_validator_matches_std_plain_dotted_contract() {
        for sample in ["0.0.0.0", "127.0.0.1", "192.168.1.1", "255.255.255.255"] {
            assert!(sample.parse::<std::net::Ipv4Addr>().is_ok());
            assert!(is_valid_ipv4_addr_bytes(sample.as_bytes()));
        }

        for sample in [
            "",
            "1",
            "1.2.3",
            "1.2.3.4.5",
            "1..2.3",
            "256.0.0.1",
            "+1.2.3.4",
            "-1.2.3.4",
            "01.2.3.4",
            "1.02.3.4",
            "1.2.03.4",
            "1.2.3.004",
            "1.2.3.4x",
        ] {
            assert!(sample.parse::<std::net::Ipv4Addr>().is_err());
            assert!(!is_valid_ipv4_addr_bytes(sample.as_bytes()));
        }
    }

    #[test]
    fn parse_hosts_ipv6() {
        let (addr, names) = parse_hosts_line(b"::1\tlocalhost6").unwrap();
        assert_eq!(addr, b"::1");
        assert_eq!(names, vec![b"localhost6".to_vec()]);
    }

    #[test]
    fn parse_hosts_strips_crlf_line_ending() {
        let (addr, names) = parse_hosts_line(b"127.0.0.1 localhost\r").unwrap();
        assert_eq!(addr, b"127.0.0.1");
        assert_eq!(names, vec![b"localhost".to_vec()]);
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

    #[test]
    fn parse_hosts_rejects_non_utf8_non_ipv4_address() {
        assert!(parse_hosts_line(&[b'1', b'2', 0xff, b' ', b'h', b'o', b's', b't']).is_none());
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

    #[test]
    fn lookup_hosts_matches_crlf_database_rows() {
        let content = b"127.0.0.1 localhost\r\n192.0.2.10 fixture\r\n";
        let addrs = lookup_hosts(content, b"fixture");
        assert_eq!(addrs, vec![b"192.0.2.10".to_vec()]);
    }

    #[test]
    fn hosts_match_entry_preserves_canonical_name_and_all_aliases() {
        let content = b"::1 canon query-alias first\n127.0.0.1 other query-alias second\n";
        let mut entries = Vec::new();
        for_each_hosts_match_entry(content, b"QuErY-AlIaS", |entry| {
            entries.push((
                entry.address().to_vec(),
                entry.canonical_name().to_vec(),
                entry.aliases().map(ToOwned::to_owned).collect::<Vec<_>>(),
            ));
            false
        });
        assert_eq!(
            entries,
            vec![
                (
                    b"::1".to_vec(),
                    b"canon".to_vec(),
                    vec![b"query-alias".to_vec(), b"first".to_vec()],
                ),
                (
                    b"127.0.0.1".to_vec(),
                    b"other".to_vec(),
                    vec![b"query-alias".to_vec(), b"second".to_vec()],
                ),
            ]
        );
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
    fn parse_services_strips_crlf_line_ending() {
        let entry = parse_services_line(b"http 80/tcp\r").unwrap();
        assert_eq!(entry.name, b"http");
        assert_eq!(entry.port, 80);
        assert_eq!(entry.protocol, b"tcp");
        assert!(entry.aliases.is_empty());
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

    #[test]
    fn parse_services_extra_separator_belongs_to_the_protocol() {
        // This asserted `.is_none()` and was WRONG about the incumbent. Only the
        // FIRST '/' separates; everything after it is the protocol name.
        // Measured by binding a synthetic /etc/services over the real one and
        // walking getservent: "extraslash 87/tcp/x" comes back with protocol
        // "tcp/x", not skipped.
        let e = parse_services_line(b"bad 80/tcp/garbage").expect("glibc yields this entry");
        assert_eq!(e.port, 80);
        assert_eq!(e.protocol, b"tcp/garbage");
    }

    #[test]
    fn parse_services_missing_and_empty_protocol_are_accepted() {
        // Also measured against getservent: a missing '/' and an empty protocol
        // both yield an entry with an EMPTY protocol rather than a skipped line.
        let none = parse_services_line(b"noproto 84").expect("no slash is still an entry");
        assert_eq!((none.port, none.protocol.as_slice()), (84, &b""[..]));
        let empty = parse_services_line(b"emptyproto 85/").expect("empty protocol is an entry");
        assert_eq!((empty.port, empty.protocol.as_slice()), (85, &b""[..]));
    }

    #[test]
    fn parse_services_port_keeps_low_16_bits_and_accepts_a_plus() {
        // getservent reports "overflow 99999/tcp" as port 34463 (99999 - 65536),
        // because glibc stores the port through a uint16_t. It is NOT rejected.
        let wrapped = parse_services_line(b"overflow 99999/tcp").expect("wraps, not rejected");
        assert_eq!(wrapped.port, 34463);
        // A leading '+' is accepted; a '-' is not.
        assert_eq!(
            parse_services_line(b"plusport +86/tcp")
                .expect("'+' accepted")
                .port,
            86
        );
        assert!(parse_services_line(b"negport -1/tcp").is_none());
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
    fn lookup_service_requires_exact_name_alias_and_protocol() {
        let content = b"HTTP\t80/tcp www";
        assert_eq!(lookup_service(content, b"HTTP", Some(b"tcp")), Some(80));
        assert_eq!(lookup_service(content, b"www", Some(b"tcp")), Some(80));
        assert_eq!(lookup_service(content, b"http", None), None);
        assert_eq!(lookup_service(content, b"WWW", None), None);
        assert_eq!(lookup_service(content, b"HTTP", Some(b"TCP")), None);
    }

    #[test]
    fn lookup_service_matches_alias() {
        let content = b"http\t80/tcp\twww";
        assert_eq!(lookup_service(content, b"www", Some(b"tcp")), Some(80));
    }

    #[test]
    fn lookup_service_matches_crlf_database_rows() {
        let content = b"http 80/tcp\r\nfixture-svc 4242/tcp fixture\r\n";
        assert_eq!(
            lookup_service(content, b"fixture", Some(b"tcp")),
            Some(4242)
        );
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
    fn parse_proc_net_route_rejects_signed_hex_flags() {
        let signed_plus =
            b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t01010101\t+0001\t0\t0\t0\t00000000\t0\t0\t0\n";
        assert!(!parse_proc_net_route_has_ipv4(signed_plus));

        let signed_minus =
            b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t01010101\t-0001\t0\t0\t0\t00000000\t0\t0\t0\n";
        assert!(!parse_proc_net_route_has_ipv4(signed_minus));
    }

    #[test]
    fn parse_proc_net_route_field_scanner_edges() {
        let mixed_spacing =
            b"Iface\tDestination Gateway Flags\n  eth0\t00000000  \t01010101\t0001 extra fields ignored\n";
        assert!(parse_proc_net_route_has_ipv4(mixed_spacing));

        let missing_flags = b"Iface Destination Gateway Flags\neth0 00000000 01010101\n";
        assert!(!parse_proc_net_route_has_ipv4(missing_flags));

        let only_loopback =
            b"Iface Destination Gateway Flags\nlo 00000000 00000000 0001 trailing\n";
        assert!(!parse_proc_net_route_has_ipv4(only_loopback));

        let down_route = b"Iface Destination Gateway Flags\neth0 00000000 01010101 0000 trailing\n";
        assert!(!parse_proc_net_route_has_ipv4(down_route));
    }

    #[test]
    fn proc_net_route_flags_byte_parser_matches_u32_hex_contract() {
        assert_eq!(parse_proc_net_route_flags(b"0"), Some(0));
        assert_eq!(parse_proc_net_route_flags(b"0001"), Some(1));
        assert_eq!(parse_proc_net_route_flags(b"0003"), Some(3));
        assert_eq!(parse_proc_net_route_flags(b"00aF"), Some(0xaf));
        assert_eq!(parse_proc_net_route_flags(b"FFFFFFFF"), Some(u32::MAX));
        assert_eq!(parse_proc_net_route_flags(b""), None);
        assert_eq!(parse_proc_net_route_flags(b"+0001"), None);
        assert_eq!(parse_proc_net_route_flags(b"-0001"), None);
        assert_eq!(parse_proc_net_route_flags(b"000g"), None);
        assert_eq!(parse_proc_net_route_flags(b"100000000"), None);
        assert_eq!(parse_proc_net_route_flags(&[b'0', b'0', 0xff]), None);
    }

    #[test]
    fn parse_proc_net_if_inet6_ignores_loopback() {
        let only_loopback = b"00000000000000000000000000000001 01 80 10 80       lo\n";
        assert!(!parse_proc_net_if_inet6_has_ipv6(only_loopback));

        let non_loopback = b"fe800000000000000000000000000001 02 40 20 80   eth0\n";
        assert!(parse_proc_net_if_inet6_has_ipv6(non_loopback));
    }

    #[test]
    fn parse_proc_net_if_inet6_rejects_malformed_rows() {
        for row in [
            b"fe80000000000000000000000000001 02 40 20 80 eth0\n".as_slice(),
            b"fe80000000000000000000000000000z 02 40 20 80 eth0\n",
            b"fe800000000000000000000000000001 +02 40 20 80 eth0\n",
            b"fe800000000000000000000000000001 02 -40 20 80 eth0\n",
            b"fe800000000000000000000000000001 02 40 +20 80 eth0\n",
            b"fe800000000000000000000000000001 02 40 20 -80 eth0\n",
            b"fe800000000000000000000000000001 02 40 20 80 eth0 extra\n",
        ] {
            assert!(!parse_proc_net_if_inet6_has_ipv6(row));
        }
    }

    #[test]
    fn parse_proc_net_if_inet6_field_scanner_edges() {
        let mixed_spacing = b"fe800000000000000000000000000001\t02  \t40\t20 80\t eth0\n";
        assert!(parse_proc_net_if_inet6_has_ipv6(mixed_spacing));

        let loopback_then_global = b"00000000000000000000000000000001 01 80 10 80 lo\n\
fe800000000000000000000000000002 02 40 20 80 wlan0\n";
        assert!(parse_proc_net_if_inet6_has_ipv6(loopback_then_global));

        let extra_field = b"fe800000000000000000000000000001 02 40 20 80 eth0 tail\n";
        assert!(!parse_proc_net_if_inet6_has_ipv6(extra_field));

        let missing_flags = b"fe800000000000000000000000000001 02 40 20 eth0\n";
        assert!(!parse_proc_net_if_inet6_has_ipv6(missing_flags));
    }

    fn addrconfig_nl_message(kind: u16, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
        message.extend_from_slice(&kind.to_ne_bytes());
        message.extend_from_slice(&flags.to_ne_bytes());
        message.extend_from_slice(&1u32.to_ne_bytes());
        message.extend_from_slice(&0u32.to_ne_bytes());
        message.extend_from_slice(body);
        message.resize(message.len().next_multiple_of(4), 0);
        message
    }

    fn addrconfig_nl_address(family: u8, attributes: &[(u16, &[u8])]) -> Vec<u8> {
        // ifaddrmsg: family, prefix length, flags, scope, interface index.
        let mut body = vec![family, 0, 0, 0, 2, 0, 0, 0];
        for (kind, value) in attributes {
            body.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
            body.extend_from_slice(&kind.to_ne_bytes());
            body.extend_from_slice(value);
            body.resize(body.len().next_multiple_of(4), 0);
        }
        addrconfig_nl_message(20, 2, &body)
    }

    fn addrconfig_nl_dump(messages: &[Vec<u8>]) -> Vec<u8> {
        let mut data = messages.concat();
        data.extend(addrconfig_nl_message(3, 2, &0i32.to_ne_bytes()));
        data
    }

    #[test]
    fn addrconfig_netlink_counts_addresses_without_routes() {
        let ipv4 = addrconfig_nl_address(AF_INET as u8, &[(1, &[192, 0, 2, 1])]);
        let ipv6 = addrconfig_nl_address(
            AF_INET6 as u8,
            &[(
                1,
                &Ipv6Addr::from(0x20010db8000000000000000000000001u128).octets(),
            )],
        );
        for (messages, expected) in [
            (
                vec![ipv4.clone()],
                AddrConfigState {
                    has_ipv4: true,
                    has_ipv6: false,
                },
            ),
            (
                vec![ipv6.clone()],
                AddrConfigState {
                    has_ipv4: false,
                    has_ipv6: true,
                },
            ),
            (
                vec![ipv4, ipv6],
                AddrConfigState {
                    has_ipv4: true,
                    has_ipv6: true,
                },
            ),
        ] {
            assert_eq!(
                addrconfig_state_from_netlink(&addrconfig_nl_dump(&messages)),
                Some(expected)
            );
        }
    }

    #[test]
    fn addrconfig_netlink_ignores_loopback_and_unspecified_addresses() {
        let data = addrconfig_nl_dump(&[
            addrconfig_nl_address(AF_INET as u8, &[(1, &[127, 0, 0, 1])]),
            addrconfig_nl_address(AF_INET as u8, &[(1, &[127, 42, 0, 1])]),
            addrconfig_nl_address(AF_INET as u8, &[(1, &[0, 0, 0, 0])]),
            addrconfig_nl_address(AF_INET6 as u8, &[(1, &Ipv6Addr::LOCALHOST.octets())]),
            addrconfig_nl_address(AF_INET6 as u8, &[(1, &[0; 16])]),
        ]);
        assert_eq!(
            addrconfig_state_from_netlink(&data),
            Some(AddrConfigState::default())
        );
        assert_eq!(
            addrconfig_state_from_netlink(&addrconfig_nl_dump(&[])),
            Some(AddrConfigState::default())
        );

        let link_local = addrconfig_nl_dump(&[addrconfig_nl_address(
            AF_INET6 as u8,
            &[(
                1,
                &Ipv6Addr::from(0xfe800000000000000000000000000001u128).octets(),
            )],
        )]);
        assert_eq!(
            addrconfig_state_from_netlink(&link_local),
            Some(AddrConfigState {
                has_ipv4: false,
                has_ipv6: true,
            })
        );
    }

    #[test]
    fn addrconfig_netlink_prefers_local_point_to_point_address() {
        for (peer, local, configured) in [
            ([192, 0, 2, 1], [127, 0, 0, 1], false),
            ([127, 0, 0, 1], [192, 0, 2, 1], true),
        ] {
            // Unknown and unaligned attributes may appear between the two
            // address attributes; their padding is not another attribute.
            let data = addrconfig_nl_dump(&[addrconfig_nl_address(
                AF_INET as u8,
                &[(1, &peer), (99, &[42]), (2, &local)],
            )]);
            assert_eq!(
                addrconfig_state_from_netlink(&data),
                Some(AddrConfigState {
                    has_ipv4: configured,
                    has_ipv6: false,
                })
            );
        }
    }

    #[test]
    fn addrconfig_netlink_rejects_partial_or_failed_dumps() {
        let address = addrconfig_nl_address(AF_INET as u8, &[(1, &[192, 0, 2, 1])]);
        let data = addrconfig_nl_dump(std::slice::from_ref(&address));
        for end in 0..data.len() {
            assert_eq!(
                addrconfig_state_from_netlink(&data[..end]),
                None,
                "truncated at {end}"
            );
        }
        for trailer in [
            addrconfig_nl_message(2, 0, &(-5i32).to_ne_bytes()),
            addrconfig_nl_message(4, 0, &[]),
            addrconfig_nl_message(3, 0x12, &0i32.to_ne_bytes()),
            addrconfig_nl_message(3, 2, &(-4i32).to_ne_bytes()),
        ] {
            let mut failed = address.clone();
            failed.extend(trailer);
            assert_eq!(addrconfig_state_from_netlink(&failed), None);
        }
        let mut interrupted = data;
        interrupted[6..8].copy_from_slice(&0x12u16.to_ne_bytes());
        assert_eq!(addrconfig_state_from_netlink(&interrupted), None);
    }

    #[test]
    fn addrconfig_netlink_rejects_malformed_lengths_and_missing_address() {
        let data = addrconfig_nl_dump(&[addrconfig_nl_address(
            AF_INET as u8,
            &[(1, &[192, 0, 2, 1])],
        )]);
        for length in [0u32, 15, u32::MAX] {
            let mut malformed = data.clone();
            malformed[..4].copy_from_slice(&length.to_ne_bytes());
            assert_eq!(addrconfig_state_from_netlink(&malformed), None);
        }
        for length in [0u16, 3, 7, u16::MAX] {
            let mut malformed = data.clone();
            malformed[24..26].copy_from_slice(&length.to_ne_bytes());
            assert_eq!(addrconfig_state_from_netlink(&malformed), None);
        }
        let missing = addrconfig_nl_dump(&[addrconfig_nl_address(AF_INET as u8, &[])]);
        assert_eq!(addrconfig_state_from_netlink(&missing), None);
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
                // The protocol MAY be empty: getservent accepts both "noproto 84"
                // (no '/') and "emptyproto 85/" and reports an empty s_proto for
                // each, so "the parser rejects empty" is no longer true and was
                // never true of the incumbent.
                prop_assert!(!entry.name.is_empty());

                // All decoded fields must be substrings of the
                // pre-comment input region.
                let pre_comment: &[u8] = match bytes.iter().position(|&b| b == b'#') {
                    Some(pos) => &bytes[..pos],
                    None => &bytes[..],
                };
                // `windows(0)` PANICS ("window size must be non-zero"), and an
                // empty protocol is now a legal parse ("noproto 84",
                // "emptyproto 85/"), so the empty case has to be handled rather
                // than fed to windows(). An empty field is trivially a
                // substring. The fuzzer found this the moment the parser
                // started producing empty protocols -- the panic was in the
                // CHECK, not in the parser.
                let is_substring = |field: &[u8]| -> bool {
                    field.is_empty() || pre_comment.windows(field.len()).any(|w| w == field)
                };
                prop_assert!(is_substring(&entry.name));
                prop_assert!(is_substring(&entry.protocol));
                for alias in &entry.aliases {
                    prop_assert!(is_substring(alias));
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
                    // An empty protocol after '/' is ACCEPTED, not ill-formed:
                    // getservent reports "emptyproto 85/" with an empty s_proto
                    // rather than skipping the line. The old expectation came
                    // from reading services(5), not from the incumbent.
                    spec_ref: "measured: getservent over a bound /etc/services",
                    input: b"bad 22/",
                    expected_name: Some(b"bad"),
                    expected_port: 22,
                    expected_proto: b"",
                    expected_aliases: &[],
                },
                Case {
                    id: "SERVICES-PARSE-009",
                    // Non-numeric port must be rejected.
                    spec_ref: "services(5) ¶Format — non-numeric port rejected",
                    input: b"bad abc/tcp",
                    expected_name: None,
                    expected_port: 0,
                    expected_proto: b"",
                    expected_aliases: &[],
                },
                Case {
                    id: "SERVICES-PARSE-010",
                    // A leading '+' IS part of the grammar glibc implements --
                    // it reads the port with strtoul. Measured: getservent
                    // reports "plusport +86/tcp" as port 86. A leading '-' is
                    // still refused (SERVICES-PARSE-014).
                    spec_ref: "measured: getservent over a bound /etc/services",
                    input: b"bad +80/tcp",
                    expected_name: Some(b"bad"),
                    expected_port: 80,
                    expected_proto: b"tcp",
                    expected_aliases: &[],
                },
                Case {
                    id: "SERVICES-PARSE-011",
                    // A port past 65535 WRAPS, it is not rejected: glibc stores
                    // it through a uint16_t. Measured: "overflow 99999/tcp"
                    // comes back as 34463 (99999 - 65536), so 70000 is 4464.
                    spec_ref: "measured: getservent over a bound /etc/services",
                    input: b"bad 70000/tcp",
                    expected_name: Some(b"bad"),
                    expected_port: 4464,
                    expected_proto: b"tcp",
                    expected_aliases: &[],
                },
                Case {
                    id: "SERVICES-PARSE-012",
                    spec_ref: "services(5) ¶Format — boundary: port 0 is valid",
                    input: b"nullport 0/tcp",
                    expected_name: Some(b"nullport"),
                    expected_port: 0,
                    expected_proto: b"tcp",
                    expected_aliases: &[],
                },
                Case {
                    id: "SERVICES-PARSE-013",
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
    fn protocol_strips_crlf_line_ending() {
        let e = parse_protocols_line(b"tcp 6 TCP\r").unwrap();
        assert_eq!(e.name, b"tcp");
        assert_eq!(e.number, 6);
        assert_eq!(e.aliases, vec![b"TCP".to_vec()]);
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
    fn protocol_accepts_plus_and_rejects_minus() {
        // Only the MINUS is rejected. glibc reads the number with strtoul, so a
        // leading '+' is fine — measured by binding a synthetic /etc/protocols
        // over the real one and walking getprotoent: "plusnum +7" comes back as
        // protocol 7, while "negnum -1" is skipped. The old assertion rejected
        // both and dropped an entry the incumbent yields.
        assert_eq!(parse_protocols_line(b"foo +6").unwrap().number, 6);
        assert!(parse_protocols_line(b"foo -1").is_none());
    }

    #[test]
    fn protocol_number_keeps_low_32_bits() {
        // Also measured: "intmaxplus 2147483648" is accepted and comes back as
        // -2147483648 (the value is read unsigned and stored in an int), while
        // "overflow 4294967296" and "huge 99999999999" exceed 32 bits and are
        // refused. fl previously refused all three via i32::try_from.
        assert_eq!(
            parse_protocols_line(b"big 2147483648").unwrap().number,
            i32::MIN
        );
        assert!(parse_protocols_line(b"over 4294967296").is_none());
        assert!(parse_protocols_line(b"huge 99999999999").is_none());
    }

    #[test]
    fn protocol_lookup_by_exact_name_and_explicit_alias() {
        let content = b"tcp 6 TCP\nudp 17 UDP\n";
        assert_eq!(lookup_protocol_by_name(content, b"TCP").unwrap().number, 6);
        assert_eq!(lookup_protocol_by_name(content, b"udp").unwrap().number, 17);
        assert_eq!(lookup_protocol_by_name(content, b"UDP").unwrap().number, 17);
        assert!(lookup_protocol_by_name(content, b"TcP").is_none());
        assert!(lookup_protocol_by_name(content, b"Udp").is_none());
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
        // A single component is capped at 0xff, exactly like glibc's
        // inet_network("4294967295") -> INADDR_NONE.
        assert_eq!(parse_network_number("4294967295"), None);
        assert_eq!(parse_network_number("256"), None);
        // Base detection: leading 0 is octal, 0x is hex.
        assert_eq!(parse_network_number("0177"), Some(0x7f));
        assert_eq!(parse_network_number("0x7f"), Some(0x7f));
    }

    #[test]
    fn netnum_dotted_one_octet() {
        assert_eq!(parse_network_number("10."), None); // trailing empty octet
        assert_eq!(parse_network_number("10"), Some(10));
    }

    #[test]
    fn netnum_dotted_two_octet() {
        // inet_network is right-aligned: 10.1 -> (10<<8)|1 = 0x0a01.
        assert_eq!(parse_network_number("10.1"), Some(0x0a01));
    }

    #[test]
    fn netnum_dotted_three_octet() {
        // 192.168.1 -> (192<<16)|(168<<8)|1 = 0x00c0_a801.
        assert_eq!(parse_network_number("192.168.1"), Some(0x00c0_a801));
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
    fn netnum_rejects_signed_decimal() {
        assert_eq!(parse_network_number("+10"), None);
        assert_eq!(parse_network_number("-10"), None);
    }

    #[test]
    fn netnum_rejects_signed_dotted_octets() {
        assert_eq!(parse_network_number("+10.1"), None);
        assert_eq!(parse_network_number("10.+1"), None);
        assert_eq!(parse_network_number("10.-1"), None);
    }

    #[test]
    fn netnum_rejects_empty() {
        assert_eq!(parse_network_number(""), None);
    }

    #[test]
    fn netnum_byte_parser_matches_inet_network_ascii_contract() {
        assert_eq!(parse_network_number_bytes(b"0"), Some(0));
        assert_eq!(parse_network_number_bytes(b"0177"), Some(0x7f));
        assert_eq!(parse_network_number_bytes(b"0X7F"), Some(0x7f));
        assert_eq!(parse_network_number_bytes(b"10.1"), Some(0x0a01));
        assert_eq!(parse_network_number_bytes(b"127.0.0.1"), Some(0x7f00_0001));
        assert_eq!(parse_network_number_bytes(b""), None);
        assert_eq!(parse_network_number_bytes(b"10."), None);
        assert_eq!(parse_network_number_bytes(b"1.2.3.4.5"), None);
        assert_eq!(parse_network_number_bytes(b"+10"), None);
        assert_eq!(parse_network_number_bytes(b"10.-1"), None);
        assert_eq!(parse_network_number_bytes(b"10.256"), None);
        assert_eq!(parse_network_number_bytes(&[b'1', b'0', 0xff]), None);
    }

    #[test]
    fn decimal_u32_byte_parser_rejects_signs_non_digits_and_overflow() {
        assert_eq!(parse_ascii_decimal_u32(b"0"), Some(0));
        assert_eq!(parse_ascii_decimal_u32(b"80"), Some(80));
        assert_eq!(parse_ascii_decimal_u32(b"4294967295"), Some(u32::MAX));
        assert_eq!(parse_ascii_decimal_u32(b""), None);
        assert_eq!(parse_ascii_decimal_u32(b"+6"), None);
        assert_eq!(parse_ascii_decimal_u32(b"-1"), None);
        assert_eq!(parse_ascii_decimal_u32(b"6/tcp"), None);
        assert_eq!(parse_ascii_decimal_u32(b"4294967296"), None);
        assert_eq!(parse_ascii_decimal_u32(&[b'6', 0xff]), None);
    }

    #[test]
    fn netnum_rejects_too_many_octets() {
        assert_eq!(parse_network_number("1.2.3.4.5"), None);
    }

    // ---- parse_networks_line ----

    #[test]
    fn network_basic_plain_decimal() {
        // LEFT-aligned: "127" is 0x7f000000, not 127. The old assertion (and its
        // comment) described inet_network, which really does return 0x7f — but
        // the netent parser is not inet_network. Measured by binding a synthetic
        // /etc/networks over the real one and walking getnetent: n_net is
        // 0x7f000000.
        let e = parse_networks_line(b"loopback 127").unwrap();
        assert_eq!(e.name, b"loopback");
        assert_eq!(e.number, 0x7f00_0000);
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
        // Two components shift up by two bytes: 169.254 -> 0xa9fe0000, which is
        // the address a caller expects for a /16. inet_network("169.254") is
        // 0xa9fe and getnetent is not inet_network — measured on the host,
        // "withalias 192.168" comes back as 0xc0a80000.
        let e = parse_networks_line(b"link-local 169.254").unwrap();
        assert_eq!(e.name, b"link-local");
        assert_eq!(e.number, 0xa9fe_0000);
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
        assert!(parse_networks_line(&[b'f', b'o', b'o', b' ', b'1', b'0', 0xff]).is_none());
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

    // ===== glibc parity tests =====
    // Verified against glibc <netdb.h>

    #[test]
    fn glibc_eai_error_constants() {
        // EAI_* error codes must match glibc
        assert_eq!(EAI_NONAME, -2);
        assert_eq!(EAI_SERVICE, -8);
        assert_eq!(EAI_FAMILY, -6);
    }
}
