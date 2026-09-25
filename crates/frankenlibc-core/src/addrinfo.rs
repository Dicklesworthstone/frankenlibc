//! Address-family selection and numeric hosts for `getaddrinfo`.
//!
//! This is policy above DNS transport, not a second resolver. In particular,
//! AF_INET6 + AI_V4MAPPED completes the AAAA search before falling back to A;
//! querying both at once can incorrectly choose an earlier search suffix's A
//! record instead of a later suffix's native IPv6 address. AI_ALL requests both
//! searches. Callers supply interface lookup and the existing DNS engine.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::dns_transport::ResolveError;
use crate::resolv::dns::DnsResolution;

pub mod gai_policy;
pub mod hosts_policy;

use gai_policy::DestinationPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Unspecified,
    Inet,
    Inet6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericError {
    AddressFamily,
    InvalidScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumericAddress {
    pub address: IpAddr,
    pub scope_id: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct AddressPolicy {
    pub family: Family,
    mapped: bool,
    all: bool,
}

impl AddressPolicy {
    /// AI_ALL is ignored without AI_V4MAPPED, and both are ignored outside
    /// AF_INET6. Normalize once so files and DNS apply the same rules.
    pub fn new(family: Family, v4mapped: bool, all: bool) -> Self {
        let mapped = family == Family::Inet6 && v4mapped;
        Self {
            family,
            mapped,
            all: mapped && all,
        }
    }

    /// Parse a numeric host without DNS or service lookups. A nonnumeric host
    /// returns None. Invalid IPv6 zones and family mismatches are terminal.
    /// `interface_index` returns zero when the interface does not exist.
    pub fn numeric<F>(
        self,
        text: &str,
        mut interface_index: F,
    ) -> Result<Option<NumericAddress>, NumericError>
    where
        F: FnMut(&str) -> u32,
    {
        // inet_aton accepts trailing whitespace; getaddrinfo must consume the
        // whole host. Reject embedded NULs as well for safe Rust callers.
        if !text.bytes().any(|b| b == 0 || b.is_ascii_whitespace())
            && let Some(octets) = crate::inet::parse_ipv4_bsd(text.as_bytes())
        {
            let v4 = Ipv4Addr::from(octets);
            let address = match self.family {
                Family::Inet6 if self.mapped => IpAddr::V6(v4.to_ipv6_mapped()),
                Family::Inet6 => return Err(NumericError::AddressFamily),
                _ => IpAddr::V4(v4),
            };
            return Ok(Some(NumericAddress {
                address,
                scope_id: 0,
            }));
        }
        let (host, zone) = match text.split_once('%') {
            Some((host, zone)) => (host, Some(zone)),
            None => (text, None),
        };
        let Ok(v6) = host.parse::<Ipv6Addr>() else {
            return Ok(None);
        };
        // glibc diagnoses a genuine family mismatch before the zone suffix.
        let address = if self.family == Family::Inet {
            IpAddr::V4(v6.to_ipv4_mapped().ok_or(NumericError::AddressFamily)?)
        } else {
            IpAddr::V6(v6)
        };
        let scope_id = match zone {
            None => 0,
            Some(zone) => {
                if zone.is_empty() || zone.as_bytes().contains(&0) {
                    return Err(NumericError::InvalidScope);
                }
                let octets = v6.octets();
                let named_scope = (octets[0] == 0xfe && octets[1] & 0xc0 == 0x80)
                    || (octets[0] == 0xff && matches!(octets[1] & 0x0f, 1 | 2));
                let index = if named_scope {
                    interface_index(zone)
                } else {
                    0
                };
                if index != 0 {
                    index
                } else {
                    // Strict decimal: no signs, whitespace, base prefixes, or
                    // overflowing conversion from an unsigned long to u32.
                    if !zone.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(NumericError::InvalidScope);
                    }
                    zone.parse::<u32>()
                        .map_err(|_| NumericError::InvalidScope)?
                }
            }
        };
        Ok(Some(NumericAddress {
            address,
            scope_id: if address.is_ipv6() { scope_id } else { 0 },
        }))
    }

    /// Apply family policy to a complete backend result, preserving its order
    /// and multiplicity. Do not decide IPv4 fallback one hosts-file row at a
    /// time: a native IPv6 row may occur later in the same file.
    pub fn select(self, addresses: &[IpAddr]) -> Vec<IpAddr> {
        let has_v6 = addresses.iter().any(IpAddr::is_ipv6);
        addresses
            .iter()
            .filter_map(|address| match (self.family, *address) {
                (Family::Unspecified, address) => Some(address),
                (Family::Inet, IpAddr::V4(_)) | (Family::Inet6, IpAddr::V6(_)) => Some(*address),
                (Family::Inet6, IpAddr::V4(v4)) if self.mapped && (self.all || !has_v6) => {
                    Some(IpAddr::V6(v4.to_ipv6_mapped()))
                }
                _ => None,
            })
            .collect()
    }

    /// Resolve with an existing family-aware DNS engine. The callback's whole
    /// search/retry sequence finishes before mapped fallback starts. A positive
    /// result survives a failure of the other family; missing names are never
    /// replaced with loopback or another invented address.
    pub fn resolve_dns_with<F>(self, mut lookup: F) -> Result<DnsResolution, ResolveError>
    where
        F: FnMut(bool, bool) -> Result<DnsResolution, ResolveError>,
    {
        match self.family {
            Family::Unspecified => lookup(true, true),
            Family::Inet => lookup(true, false),
            Family::Inet6 if !self.mapped => lookup(false, true),
            Family::Inet6 => {
                let v6 = lookup(false, true);
                if !self.all && v6.as_ref().is_ok_and(|r| !r.ipv6.is_empty()) {
                    return v6;
                }
                let v4 = lookup(true, false);
                let mut result = DnsResolution::default();
                if let Ok(v6) = &v6 {
                    result.ipv6.extend_from_slice(&v6.ipv6);
                }
                if let Ok(v4) = &v4 {
                    result
                        .ipv6
                        .extend(v4.ipv4.iter().map(Ipv4Addr::to_ipv6_mapped));
                }
                if !result.ipv6.is_empty() {
                    return Ok(result);
                }
                // The current transport groups NXDOMAIN and NODATA together.
                // Preserve that existing error granularity. A definitive miss
                // takes precedence over the other family's transient failure.
                let e6 = v6.err().unwrap_or(ResolveError::NotFound);
                let e4 = v4.err().unwrap_or(ResolveError::NotFound);
                Err(
                    if e6 == ResolveError::NotFound || e4 == ResolveError::NotFound {
                        ResolveError::NotFound
                    } else if e6 == ResolveError::Temporary || e4 == ResolveError::Temporary {
                        ResolveError::Temporary
                    } else {
                        ResolveError::Failure
                    },
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Destination address selection (RFC 3484 / glibc's getaddrinfo sort)
// ---------------------------------------------------------------------------

/// One `getaddrinfo` result for [`destination_order`]: the destination,
/// the source address a connected UDP socket would use (`None` when the
/// destination is unreachable), and, for an IPv4 source, the prefix length
/// of the interface address it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DestinationCandidate {
    pub dest: IpAddr,
    pub source: Option<IpAddr>,
    pub source_prefix_len: Option<u8>,
}

/// (prefix, prefix length, value) in IPv6 space; IPv4 is matched as
/// `::ffff:a.b.c.d`. glibc's defaults (RFC 3484).
const PRECEDENCE: [([u8; 16], u8, u8); 5] = [
    ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128, 50),
    (
        [0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        16,
        30,
    ),
    ([0; 16], 96, 20),
    (
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0],
        96,
        10,
    ),
    ([0; 16], 0, 40),
];

const LABELS: [([u8; 16], u8, u8); 8] = [
    ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128, 0),
    (
        [0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        16,
        2,
    ),
    ([0; 16], 96, 3),
    (
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0],
        96,
        4,
    ),
    (
        [0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        10,
        5,
    ),
    ([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7, 6),
    (
        [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        32,
        7,
    ),
    ([0; 16], 0, 1),
];

fn as_v6_octets(addr: IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// The first entry of `table` whose prefix matches, in table order: the
/// tables list specific prefixes before `::/0`, and the more specific of
/// two overlapping prefixes (`::1/128` vs `::/96`) first.
fn table_lookup(table: &[([u8; 16], u8, u8)], addr: IpAddr) -> u8 {
    let a = as_v6_octets(addr);
    for (prefix, len, value) in table {
        let full = usize::from(*len / 8);
        let rem = len % 8;
        if a[..full] != prefix[..full] {
            continue;
        }
        if rem != 0 {
            let mask = 0xffu8 << (8 - rem);
            if a[full] & mask != prefix[full] & mask {
                continue;
            }
        }
        return *value;
    }
    0
}

fn precedence(addr: IpAddr) -> u8 {
    table_lookup(&PRECEDENCE, addr)
}

fn label(addr: IpAddr) -> u8 {
    table_lookup(&LABELS, addr)
}

/// RFC 3484 scope: link-local and loopback 2, site-local 5, multicast its
/// scope field, IPv4 169.254/16 and 127/8 link-local, anything else global.
fn scope(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V6(v6) => {
            let o = v6.octets();
            if o[0] == 0xff {
                o[1] & 0x0f
            } else if (o[0] == 0xfe && o[1] & 0xc0 == 0x80) || v6.is_loopback() {
                2
            } else if o[0] == 0xfe && o[1] & 0xc0 == 0xc0 {
                5
            } else {
                14
            }
        }
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if (o[0] == 169 && o[1] == 254) || o[0] == 127 {
                2
            } else {
                14
            }
        }
    }
}

/// Rule 9 score: larger means a longer source/destination common prefix.
/// IPv4 off-subnet destinations get zero, matching glibc's restriction of
/// longest-prefix sorting to the source subnet. Using the XOR's highest set
/// bit instead would also give off-subnet addresses zero, accidentally ranking
/// them ahead of every nonidentical on-link destination.
fn common_prefix_bits(candidate: &DestinationCandidate) -> Option<u32> {
    match (candidate.dest, candidate.source?) {
        (IpAddr::V4(destination), IpAddr::V4(source)) => {
            let (destination, source) = (u32::from(destination), u32::from(source));
            let length = u32::from(candidate.source_prefix_len.unwrap_or(0)).min(32);
            let mask = if length == 0 { 0 } else { u32::MAX << (32 - length) };
            Some(if source & mask == destination & mask {
                (destination ^ source).leading_zeros()
            } else {
                0
            })
        }
        (IpAddr::V6(destination), IpAddr::V6(source)) => {
            Some((u128::from(destination) ^ u128::from(source)).leading_zeros())
        }
        _ => None,
    }
}

fn compare_destinations(
    a: &DestinationCandidate,
    ia: usize,
    b: &DestinationCandidate,
    ib: usize,
    policy: &DestinationPolicy,
) -> std::cmp::Ordering {
    use std::cmp::Ordering as O;
    // Rule 1: avoid unusable destinations.
    match (a.source.is_some(), b.source.is_some()) {
        (true, false) => return O::Less,
        (false, true) => return O::Greater,
        _ => {}
    }
    if let (Some(sa), Some(sb)) = (a.source, b.source) {
        // Rule 2: prefer matching scope.
        let ma = policy.scope(a.dest) == policy.scope(sa);
        let mb = policy.scope(b.dest) == policy.scope(sb);
        if ma != mb {
            return if ma { O::Less } else { O::Greater };
        }
        // Rule 5: prefer matching label.
        let la = policy.label(a.dest) == policy.label(sa);
        let lb = policy.label(b.dest) == policy.label(sb);
        if la != lb {
            return if la { O::Less } else { O::Greater };
        }
    }
    // Rule 6: prefer higher precedence.
    let (pa, pb) = (policy.precedence(a.dest), policy.precedence(b.dest));
    if pa != pb {
        return pb.cmp(&pa);
    }
    // Rule 8: prefer smaller scope.
    let (ca, cb) = (policy.scope(a.dest), policy.scope(b.dest));
    if ca != cb {
        return ca.cmp(&cb);
    }
    // Rule 9: longest matching prefix (same family, both reachable).
    if a.dest.is_ipv4() == b.dest.is_ipv4()
        && let (Some(bits_a), Some(bits_b)) = (common_prefix_bits(a), common_prefix_bits(b))
        && bits_a != bits_b
    {
        return bits_b.cmp(&bits_a);
    }
    // Rule 10: keep the original order.
    ia.cmp(&ib)
}

/// The order in which glibc's `getaddrinfo` returns `candidates`: indices
/// into the slice, sorted by the destination address selection rules
/// (unusable last, matching scope and label, precedence, smaller scope,
/// longest matching prefix, then original order).
/// Uses one immutable `/etc/gai.conf` snapshot per call.
pub fn destination_order(candidates: &[DestinationCandidate]) -> Vec<usize> {
    if candidates.len() < 2 {
        return (0..candidates.len()).collect();
    }
    let policy = gai_policy::system_policy();
    destination_order_with_policy(candidates, &policy)
}

/// Deterministic address selection with an explicit policy, without file I/O.
pub fn destination_order_with_policy(
    candidates: &[DestinationCandidate],
    policy: &DestinationPolicy,
) -> Vec<usize> {
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by(|&i, &j| compare_destinations(&candidates[i], i, &candidates[j], j, policy));
    order
}

#[cfg(test)]
mod tests {
    use super::{DestinationCandidate, destination_order_with_policy};

    // Existing algorithm tests must not depend on the build host's gai.conf.
    fn destination_order(candidates: &[DestinationCandidate]) -> Vec<usize> {
        destination_order_with_policy(candidates, &DestinationPolicy::default())
    }

    fn cand(dest: &str, source: Option<&str>) -> DestinationCandidate {
        DestinationCandidate {
            dest: dest.parse().unwrap(),
            source: source.map(|s| s.parse().unwrap()),
            source_prefix_len: Some(32),
        }
    }

    #[test]
    fn glibc_destination_order_matches_observed_hosts() {
        // localhost: ::1 (precedence 50) before 127.0.0.1 (10).
        let c = [
            cand("127.0.0.1", Some("127.0.0.1")),
            cand("::1", Some("::1")),
        ];
        assert_eq!(destination_order(&c), [1, 0]);
        // Dual-stack global: IPv6 (40) before IPv4 (10); family order kept.
        let c = [
            cand("142.251.14.102", Some("178.104.77.29")),
            cand("142.251.14.139", Some("178.104.77.29")),
            cand("2a00:1450:4001:c15::71", Some("2a01:4f8:1c1e:8113::1")),
            cand("2a00:1450:4001:c15::65", Some("2a01:4f8:1c1e:8113::1")),
        ];
        assert_eq!(destination_order(&c), [2, 3, 0, 1]);
        // Unreachable destinations go last.
        let c = [
            cand("2001:db8::1", None),
            cand("192.0.2.1", Some("10.0.0.2")),
        ];
        assert_eq!(destination_order(&c), [1, 0]);
        // Rule 9: the IPv6 destination sharing a longer prefix with the source first.
        let c = [
            cand("2001:db8:ffff::1", Some("2001:db8::9")),
            cand("2001:db8::1", Some("2001:db8::9")),
        ];
        assert_eq!(destination_order(&c), [1, 0]);
    }

    use super::*;

    #[test]
    fn prefix_rule_prefers_on_link_over_off_link_in_either_input_order() {
        let mut on_link = cand("192.0.2.2", Some("192.0.2.1"));
        let mut off_link = cand("198.51.100.1", Some("192.0.2.1"));
        on_link.source_prefix_len = Some(24);
        off_link.source_prefix_len = Some(24);
        assert_eq!(common_prefix_bits(&on_link), Some(30));
        assert_eq!(common_prefix_bits(&off_link), Some(0));
        assert_eq!(destination_order(&[off_link, on_link]), [1, 0]);
        assert_eq!(destination_order(&[on_link, off_link]), [0, 1]);
    }

    #[test]
    fn prefix_rule_preserves_order_between_off_link_addresses() {
        let mut a = cand("198.51.100.1", Some("192.0.2.1"));
        let mut b = cand("203.0.113.1", Some("192.0.2.1"));
        a.source_prefix_len = Some(24);
        b.source_prefix_len = Some(24);
        assert_eq!(destination_order(&[a, b]), [0, 1]);
        assert_eq!(destination_order(&[b, a]), [0, 1]);
    }

    #[test]
    fn prefix_rule_counts_every_ipv4_bit_without_reversing_the_score() {
        let source = u32::from(Ipv4Addr::new(192, 0, 2, 1));
        for bit in 0..32 {
            let candidate = DestinationCandidate {
                dest: IpAddr::V4(Ipv4Addr::from(source ^ (1u32 << (31 - bit)))),
                source: Some(IpAddr::V4(Ipv4Addr::from(source))),
                source_prefix_len: Some(0),
            };
            assert_eq!(common_prefix_bits(&candidate), Some(bit));
        }
        let exact = cand("192.0.2.1", Some("192.0.2.1"));
        assert_eq!(common_prefix_bits(&exact), Some(32));
    }

    #[test]
    fn prefix_rule_handles_host_routes_and_unknown_prefixes() {
        let mut candidate = cand("192.0.2.2", Some("192.0.2.1"));
        assert_eq!(common_prefix_bits(&candidate), Some(0));
        candidate.source_prefix_len = None;
        assert_eq!(common_prefix_bits(&candidate), Some(30));
        candidate.source_prefix_len = Some(255);
        assert_eq!(common_prefix_bits(&candidate), Some(0));
        candidate.source = None;
        assert_eq!(common_prefix_bits(&candidate), None);
        candidate.source = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(common_prefix_bits(&candidate), None);
    }

    #[test]
    fn prefix_rule_counts_all_ipv6_words_and_exact_matches() {
        let source: Ipv6Addr = "2001:db8:1234:5678:abcd:ef01:2345:6789".parse().unwrap();
        for bit in 0..128 {
            let candidate = DestinationCandidate {
                dest: IpAddr::V6(Ipv6Addr::from(u128::from(source) ^ (1u128 << (127 - bit)))),
                source: Some(IpAddr::V6(source)),
                source_prefix_len: None,
            };
            assert_eq!(common_prefix_bits(&candidate), Some(bit));
        }
        let exact = cand("2001:db8::1", Some("2001:db8::1"));
        assert_eq!(common_prefix_bits(&exact), Some(128));
    }

    #[test]
    fn prefix_rule_orders_by_score_without_disturbing_equal_prefixes() {
        let source = Some("2001:db8::1");
        let candidates = [
            cand("2001:db8:8000::1", source),
            cand("2001:db8::8000:1", source),
            cand("2001:db8::3", source),
            cand("2001:db8::2", source),
            cand("2001:db8::1", source),
        ];
        assert_eq!(destination_order(&candidates), [4, 2, 3, 1, 0]);
    }

    fn policy(family: Family, mapped: bool, all: bool) -> AddressPolicy {
        AddressPolicy::new(family, mapped, all)
    }
    fn v4() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 7)
    }
    fn v6() -> Ipv6Addr {
        "2001:db8::7".parse().unwrap()
    }
    fn only_v4() -> DnsResolution {
        DnsResolution {
            ipv4: vec![v4()],
            ipv6: Vec::new(),
        }
    }
    fn only_v6() -> DnsResolution {
        DnsResolution {
            ipv4: Vec::new(),
            ipv6: vec![v6()],
        }
    }

    #[test]
    fn numeric_ipv4_mapping_requires_both_inet6_and_v4mapped() {
        for family in [Family::Unspecified, Family::Inet, Family::Inet6] {
            for mapped in [false, true] {
                for all in [false, true] {
                    let result = policy(family, mapped, all)
                        .numeric("192.0.2.7", |_| panic!("interface lookup"));
                    if family == Family::Inet6 && !mapped {
                        assert_eq!(result, Err(NumericError::AddressFamily));
                    } else {
                        let expected = if family == Family::Inet6 {
                            IpAddr::V6(v4().to_ipv6_mapped())
                        } else {
                            IpAddr::V4(v4())
                        };
                        assert_eq!(
                            result.unwrap(),
                            Some(NumericAddress {
                                address: expected,
                                scope_id: 0
                            })
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn bsd_ipv4_forms_are_numeric_but_trailing_junk_is_not() {
        let p = policy(Family::Inet, false, false);
        for text in ["127.1", "0x7f000001", "0177.0.0.1", "127.0.1", "2130706433"] {
            assert_eq!(
                p.numeric(text, |_| 0).unwrap().unwrap().address,
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            );
        }
        for text in [
            "127.1 ",
            "127.1\t",
            "127.1\0junk",
            "127.1junk",
            "256.0.0.1",
            "4294967296",
            "08.0.0.1",
            "host.test",
        ] {
            assert_eq!(
                p.numeric(text, |_| panic!("interface lookup")).unwrap(),
                None,
                "{text:?}"
            );
        }
    }

    #[test]
    fn ipv6_mapped_literal_can_be_requested_as_ipv4() {
        let p = policy(Family::Inet, false, false);
        let result = p.numeric("::ffff:192.0.2.7%2", |_| 0).unwrap().unwrap();
        assert_eq!(
            result,
            NumericAddress {
                address: IpAddr::V4(v4()),
                scope_id: 0
            }
        );
        assert_eq!(
            p.numeric("::1%bad", |_| 0),
            Err(NumericError::AddressFamily)
        );
        assert_eq!(
            p.numeric("::ffff:192.0.2.7%bad", |_| 0),
            Err(NumericError::InvalidScope)
        );
    }

    #[test]
    fn named_zones_are_limited_to_link_and_interface_scopes() {
        let p = policy(Family::Inet6, false, false);
        for host in ["fe80::1", "febf::1", "ff01::1", "ff02::1"] {
            let result = p
                .numeric(&format!("{host}%eth-test"), |name| {
                    assert_eq!(name, "eth-test");
                    17
                })
                .unwrap()
                .unwrap();
            assert_eq!(result.scope_id, 17);
        }
        for host in ["2001:db8::1", "::1", "ff05::1", "::ffff:192.0.2.7"] {
            assert_eq!(
                p.numeric(&format!("{host}%eth-test"), |_| panic!("not a named scope")),
                Err(NumericError::InvalidScope)
            );
        }
    }

    #[test]
    fn numeric_zone_bounds_and_syntax() {
        let p = policy(Family::Inet6, false, false);
        for (zone, expected) in [("0", 0), ("01", 1), ("4294967295", u32::MAX)] {
            assert_eq!(
                p.numeric(&format!("2001:db8::1%{zone}"), |_| 0)
                    .unwrap()
                    .unwrap()
                    .scope_id,
                expected
            );
        }
        for zone in [
            "",
            "-1",
            "+1",
            " 1",
            "1 ",
            "0x1",
            "4294967296",
            "1%2",
            "unknown",
            "1\0",
        ] {
            assert_eq!(
                p.numeric(&format!("fe80::1%{zone}"), |_| 0),
                Err(NumericError::InvalidScope),
                "{zone:?}"
            );
        }
    }

    #[test]
    fn hosts_ipv6_found_after_ipv4_suppresses_mapped_fallback() {
        let addresses = [IpAddr::V4(v4()), IpAddr::V6(v6()), IpAddr::V4(v4())];
        let p = policy(Family::Inet6, true, false);
        assert_eq!(p.select(&addresses), vec![IpAddr::V6(v6())]);
        assert_eq!(
            p.select(&addresses[..1]),
            vec![IpAddr::V6(v4().to_ipv6_mapped())]
        );
    }

    #[test]
    fn hosts_all_preserves_order_and_multiplicity() {
        let addresses = [IpAddr::V4(v4()), IpAddr::V6(v6()), IpAddr::V4(v4())];
        assert_eq!(
            policy(Family::Inet6, true, true).select(&addresses),
            vec![
                IpAddr::V6(v4().to_ipv6_mapped()),
                IpAddr::V6(v6()),
                IpAddr::V6(v4().to_ipv6_mapped())
            ]
        );
        assert_eq!(
            policy(Family::Unspecified, true, true).select(&addresses),
            addresses
        );
        assert_eq!(
            policy(Family::Inet, true, true).select(&addresses),
            vec![IpAddr::V4(v4()), IpAddr::V4(v4())]
        );
        assert_eq!(
            policy(Family::Inet6, false, true).select(&addresses),
            vec![IpAddr::V6(v6())]
        );
    }

    #[test]
    fn native_ipv6_avoids_a_query_entirely() {
        let mut calls = Vec::new();
        let result = policy(Family::Inet6, true, false)
            .resolve_dns_with(|a, aaaa| {
                calls.push((a, aaaa));
                assert_eq!((a, aaaa), (false, true));
                Ok(only_v6())
            })
            .unwrap();
        assert_eq!(calls, [(false, true)]);
        assert_eq!(result.ipv6, [v6()]);
    }

    #[test]
    fn mapped_fallback_runs_after_the_entire_aaaa_search() {
        let mut calls = Vec::new();
        let result = policy(Family::Inet6, true, false)
            .resolve_dns_with(|a, aaaa| {
                calls.push((a, aaaa));
                if aaaa {
                    Err(ResolveError::NotFound)
                } else {
                    Ok(only_v4())
                }
            })
            .unwrap();
        assert_eq!(calls, [(false, true), (true, false)]);
        assert!(result.ipv4.is_empty());
        assert_eq!(result.ipv6, [v4().to_ipv6_mapped()]);
    }

    #[test]
    fn mapped_fallback_can_recover_from_aaaa_failure() {
        for error in [
            ResolveError::NotFound,
            ResolveError::Temporary,
            ResolveError::Failure,
        ] {
            let result = policy(Family::Inet6, true, false)
                .resolve_dns_with(|_, aaaa| if aaaa { Err(error) } else { Ok(only_v4()) })
                .unwrap();
            assert_eq!(result.ipv6, [v4().to_ipv6_mapped()]);
        }
    }

    #[test]
    fn all_combines_native_and_mapped_addresses() {
        let mut calls = Vec::new();
        let result = policy(Family::Inet6, true, true)
            .resolve_dns_with(|a, aaaa| {
                calls.push((a, aaaa));
                Ok(if aaaa { only_v6() } else { only_v4() })
            })
            .unwrap();
        assert_eq!(calls, [(false, true), (true, false)]);
        assert!(result.ipv4.is_empty());
        assert_eq!(result.ipv6, [v6(), v4().to_ipv6_mapped()]);
    }

    #[test]
    fn all_preserves_aaaa_when_a_fails() {
        for error in [
            ResolveError::NotFound,
            ResolveError::Temporary,
            ResolveError::Failure,
        ] {
            let result = policy(Family::Inet6, true, true)
                .resolve_dns_with(|_, aaaa| if aaaa { Ok(only_v6()) } else { Err(error) })
                .unwrap();
            assert_eq!(result.ipv6, [v6()]);
        }
    }

    #[test]
    fn flags_ignored_outside_mapped_inet6_do_not_change_dns_queries() {
        for (family, expected) in [
            (Family::Inet, (true, false)),
            (Family::Unspecified, (true, true)),
            (Family::Inet6, (false, true)),
        ] {
            let mut calls = Vec::new();
            let _ = policy(family, false, true).resolve_dns_with(|a, aaaa| {
                calls.push((a, aaaa));
                Err(ResolveError::NotFound)
            });
            assert_eq!(calls, [expected]);
        }
    }

    #[test]
    fn both_failed_families_never_invent_an_address() {
        for e6 in [
            ResolveError::NotFound,
            ResolveError::Temporary,
            ResolveError::Failure,
        ] {
            for e4 in [
                ResolveError::NotFound,
                ResolveError::Temporary,
                ResolveError::Failure,
            ] {
                let result = policy(Family::Inet6, true, true)
                    .resolve_dns_with(|_, aaaa| Err(if aaaa { e6 } else { e4 }));
                assert!(result.is_err());
            }
        }
        assert!(
            policy(Family::Inet6, true, true)
                .resolve_dns_with(|_, _| Ok(DnsResolution::default()))
                .is_err()
        );
    }

    #[test]
    fn every_ipv4_octet_survives_mapping() {
        let p = policy(Family::Inet6, true, false);
        for byte in 0..=255 {
            let address = Ipv4Addr::new(byte, 255 - byte, byte, 255 - byte);
            let mapped = p.numeric(&address.to_string(), |_| 0).unwrap().unwrap();
            assert_eq!(mapped.address, IpAddr::V6(address.to_ipv6_mapped()));
            assert_eq!(p.select(&[IpAddr::V4(address)]), [mapped.address]);
        }
    }
}
