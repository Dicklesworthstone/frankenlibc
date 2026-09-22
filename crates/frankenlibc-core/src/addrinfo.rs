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
        Self { family, mapped, all: mapped && all }
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
            return Ok(Some(NumericAddress { address, scope_id: 0 }));
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
                let index = if named_scope { interface_index(zone) } else { 0 };
                if index != 0 {
                    index
                } else {
                    // Strict decimal: no signs, whitespace, base prefixes, or
                    // overflowing conversion from an unsigned long to u32.
                    if !zone.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(NumericError::InvalidScope);
                    }
                    zone.parse::<u32>().map_err(|_| NumericError::InvalidScope)?
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
        addresses.iter().filter_map(|address| match (self.family, *address) {
            (Family::Unspecified, address) => Some(address),
            (Family::Inet, IpAddr::V4(_)) | (Family::Inet6, IpAddr::V6(_)) => Some(*address),
            (Family::Inet6, IpAddr::V4(v4)) if self.mapped && (self.all || !has_v6) => {
                Some(IpAddr::V6(v4.to_ipv6_mapped()))
            }
            _ => None,
        }).collect()
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
                    result.ipv6.extend(v4.ipv4.iter().map(Ipv4Addr::to_ipv6_mapped));
                }
                if !result.ipv6.is_empty() {
                    return Ok(result);
                }
                // The current transport groups NXDOMAIN and NODATA together.
                // Preserve that existing error granularity. A definitive miss
                // takes precedence over the other family's transient failure.
                let e6 = v6.err().unwrap_or(ResolveError::NotFound);
                let e4 = v4.err().unwrap_or(ResolveError::NotFound);
                Err(if e6 == ResolveError::NotFound || e4 == ResolveError::NotFound {
                    ResolveError::NotFound
                } else if e6 == ResolveError::Temporary || e4 == ResolveError::Temporary {
                    ResolveError::Temporary
                } else {
                    ResolveError::Failure
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(family: Family, mapped: bool, all: bool) -> AddressPolicy {
        AddressPolicy::new(family, mapped, all)
    }
    fn v4() -> Ipv4Addr { Ipv4Addr::new(192, 0, 2, 7) }
    fn v6() -> Ipv6Addr { "2001:db8::7".parse().unwrap() }
    fn only_v4() -> DnsResolution {
        DnsResolution { ipv4: vec![v4()], ipv6: Vec::new() }
    }
    fn only_v6() -> DnsResolution {
        DnsResolution { ipv4: Vec::new(), ipv6: vec![v6()] }
    }

    #[test]
    fn numeric_ipv4_mapping_requires_both_inet6_and_v4mapped() {
        for family in [Family::Unspecified, Family::Inet, Family::Inet6] {
            for mapped in [false, true] {
                for all in [false, true] {
                    let result = policy(family, mapped, all).numeric("192.0.2.7", |_| panic!("interface lookup"));
                    if family == Family::Inet6 && !mapped {
                        assert_eq!(result, Err(NumericError::AddressFamily));
                    } else {
                        let expected = if family == Family::Inet6 { IpAddr::V6(v4().to_ipv6_mapped()) } else { IpAddr::V4(v4()) };
                        assert_eq!(result.unwrap(), Some(NumericAddress { address: expected, scope_id: 0 }));
                    }
                }
            }
        }
    }

    #[test]
    fn bsd_ipv4_forms_are_numeric_but_trailing_junk_is_not() {
        let p = policy(Family::Inet, false, false);
        for text in ["127.1", "0x7f000001", "0177.0.0.1", "127.0.1", "2130706433"] {
            assert_eq!(p.numeric(text, |_| 0).unwrap().unwrap().address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
        for text in ["127.1 ", "127.1\t", "127.1\0junk", "127.1junk", "256.0.0.1", "4294967296", "08.0.0.1", "host.test"] {
            assert_eq!(p.numeric(text, |_| panic!("interface lookup")).unwrap(), None, "{text:?}");
        }
    }

    #[test]
    fn ipv6_mapped_literal_can_be_requested_as_ipv4() {
        let p = policy(Family::Inet, false, false);
        let result = p.numeric("::ffff:192.0.2.7%2", |_| 0).unwrap().unwrap();
        assert_eq!(result, NumericAddress { address: IpAddr::V4(v4()), scope_id: 0 });
        assert_eq!(p.numeric("::1%bad", |_| 0), Err(NumericError::AddressFamily));
        assert_eq!(p.numeric("::ffff:192.0.2.7%bad", |_| 0), Err(NumericError::InvalidScope));
    }

    #[test]
    fn named_zones_are_limited_to_link_and_interface_scopes() {
        let p = policy(Family::Inet6, false, false);
        for host in ["fe80::1", "febf::1", "ff01::1", "ff02::1"] {
            let result = p.numeric(&format!("{host}%eth-test"), |name| { assert_eq!(name, "eth-test"); 17 }).unwrap().unwrap();
            assert_eq!(result.scope_id, 17);
        }
        for host in ["2001:db8::1", "::1", "ff05::1", "::ffff:192.0.2.7"] {
            assert_eq!(p.numeric(&format!("{host}%eth-test"), |_| panic!("not a named scope")), Err(NumericError::InvalidScope));
        }
    }

    #[test]
    fn numeric_zone_bounds_and_syntax() {
        let p = policy(Family::Inet6, false, false);
        for (zone, expected) in [("0", 0), ("01", 1), ("4294967295", u32::MAX)] {
            assert_eq!(p.numeric(&format!("2001:db8::1%{zone}"), |_| 0).unwrap().unwrap().scope_id, expected);
        }
        for zone in ["", "-1", "+1", " 1", "1 ", "0x1", "4294967296", "1%2", "unknown", "1\0"] {
            assert_eq!(p.numeric(&format!("fe80::1%{zone}"), |_| 0), Err(NumericError::InvalidScope), "{zone:?}");
        }
    }

    #[test]
    fn hosts_ipv6_found_after_ipv4_suppresses_mapped_fallback() {
        let addresses = [IpAddr::V4(v4()), IpAddr::V6(v6()), IpAddr::V4(v4())];
        let p = policy(Family::Inet6, true, false);
        assert_eq!(p.select(&addresses), vec![IpAddr::V6(v6())]);
        assert_eq!(p.select(&addresses[..1]), vec![IpAddr::V6(v4().to_ipv6_mapped())]);
    }

    #[test]
    fn hosts_all_preserves_order_and_multiplicity() {
        let addresses = [IpAddr::V4(v4()), IpAddr::V6(v6()), IpAddr::V4(v4())];
        assert_eq!(policy(Family::Inet6, true, true).select(&addresses), vec![IpAddr::V6(v4().to_ipv6_mapped()), IpAddr::V6(v6()), IpAddr::V6(v4().to_ipv6_mapped())]);
        assert_eq!(policy(Family::Unspecified, true, true).select(&addresses), addresses);
        assert_eq!(policy(Family::Inet, true, true).select(&addresses), vec![IpAddr::V4(v4()), IpAddr::V4(v4())]);
        assert_eq!(policy(Family::Inet6, false, true).select(&addresses), vec![IpAddr::V6(v6())]);
    }

    #[test]
    fn native_ipv6_avoids_a_query_entirely() {
        let mut calls = Vec::new();
        let result = policy(Family::Inet6, true, false).resolve_dns_with(|a, aaaa| {
            calls.push((a, aaaa));
            assert_eq!((a, aaaa), (false, true));
            Ok(only_v6())
        }).unwrap();
        assert_eq!(calls, [(false, true)]);
        assert_eq!(result.ipv6, [v6()]);
    }

    #[test]
    fn mapped_fallback_runs_after_the_entire_aaaa_search() {
        let mut calls = Vec::new();
        let result = policy(Family::Inet6, true, false).resolve_dns_with(|a, aaaa| {
            calls.push((a, aaaa));
            if aaaa { Err(ResolveError::NotFound) } else { Ok(only_v4()) }
        }).unwrap();
        assert_eq!(calls, [(false, true), (true, false)]);
        assert!(result.ipv4.is_empty());
        assert_eq!(result.ipv6, [v4().to_ipv6_mapped()]);
    }

    #[test]
    fn mapped_fallback_can_recover_from_aaaa_failure() {
        for error in [ResolveError::NotFound, ResolveError::Temporary, ResolveError::Failure] {
            let result = policy(Family::Inet6, true, false).resolve_dns_with(|_, aaaa| {
                if aaaa { Err(error) } else { Ok(only_v4()) }
            }).unwrap();
            assert_eq!(result.ipv6, [v4().to_ipv6_mapped()]);
        }
    }

    #[test]
    fn all_combines_native_and_mapped_addresses() {
        let mut calls = Vec::new();
        let result = policy(Family::Inet6, true, true).resolve_dns_with(|a, aaaa| {
            calls.push((a, aaaa));
            Ok(if aaaa { only_v6() } else { only_v4() })
        }).unwrap();
        assert_eq!(calls, [(false, true), (true, false)]);
        assert!(result.ipv4.is_empty());
        assert_eq!(result.ipv6, [v6(), v4().to_ipv6_mapped()]);
    }

    #[test]
    fn all_preserves_aaaa_when_a_fails() {
        for error in [ResolveError::NotFound, ResolveError::Temporary, ResolveError::Failure] {
            let result = policy(Family::Inet6, true, true).resolve_dns_with(|_, aaaa| {
                if aaaa { Ok(only_v6()) } else { Err(error) }
            }).unwrap();
            assert_eq!(result.ipv6, [v6()]);
        }
    }

    #[test]
    fn flags_ignored_outside_mapped_inet6_do_not_change_dns_queries() {
        for (family, expected) in [(Family::Inet, (true, false)), (Family::Unspecified, (true, true)), (Family::Inet6, (false, true))] {
            let mut calls = Vec::new();
            let _ = policy(family, false, true).resolve_dns_with(|a, aaaa| { calls.push((a, aaaa)); Err(ResolveError::NotFound) });
            assert_eq!(calls, [expected]);
        }
    }

    #[test]
    fn both_failed_families_never_invent_an_address() {
        for e6 in [ResolveError::NotFound, ResolveError::Temporary, ResolveError::Failure] {
            for e4 in [ResolveError::NotFound, ResolveError::Temporary, ResolveError::Failure] {
                let result = policy(Family::Inet6, true, true).resolve_dns_with(|_, aaaa| Err(if aaaa { e6 } else { e4 }));
                assert!(result.is_err());
            }
        }
        assert!(policy(Family::Inet6, true, true).resolve_dns_with(|_, _| Ok(DnsResolution::default())).is_err());
    }

    #[test]
    fn every_ipv4_octet_survives_mapping() {
        let p = policy(Family::Inet6, true, false);
        for byte in 0..=255 {
            let address = Ipv4Addr::new(byte, 255-byte, byte, 255-byte);
            let mapped = p.numeric(&address.to_string(), |_| 0).unwrap().unwrap();
            assert_eq!(mapped.address, IpAddr::V6(address.to_ipv6_mapped()));
            assert_eq!(p.select(&[IpAddr::V4(address)]), [mapped.address]);
        }
    }
}
