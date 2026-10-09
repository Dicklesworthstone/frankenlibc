//! Native resolver failover regressions. Backends are injected at the existing
//! transport boundary: no external DNS, host resolver, or clock sleeps are used.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use frankenlibc_core::dns_transport::{
    QueryError, QueryReply, ResolveError, resolve_with, resolve_with_canonical,
};
use frankenlibc_core::resolv::ResolverConfig;
use frankenlibc_core::resolv::dns::{DnsRecord, qclass, qtype, rcode};

fn config() -> ResolverConfig {
    let mut config = ResolverConfig::default();
    config.nameservers = vec![
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
    ];
    config.attempts = 3;
    config
}

fn refused() -> QueryError {
    QueryError::Io(io::ErrorKind::ConnectionRefused.into())
}

fn positive(owner: &[u8], kind: u16) -> QueryReply {
    let rdata = match kind {
        qtype::A => Ipv4Addr::new(192, 0, 2, 7).octets().to_vec(),
        qtype::AAAA => "2001:db8::7".parse::<Ipv6Addr>().unwrap().octets().to_vec(),
        _ => panic!("unexpected query type {kind}"),
    };
    QueryReply {
        records: vec![DnsRecord {
            name: owner.to_vec(),
            rtype: kind,
            rclass: qclass::IN,
            ttl: 60,
            rdata,
        }],
        rcode: rcode::NOERROR,
    }
}

#[test]
fn refused_primary_uses_fallback_for_ipv4_ipv6_and_dual_stack() {
    for (want_v4, want_v6) in [(true, false), (false, true), (true, true)] {
        for use_vc in [false, true] {
            let mut config = config();
            config.use_vc = use_vc;
            config.trust_ad = true;
            config.timeout = 7;
            let mut calls = Vec::new();
            let result = resolve_with_canonical(
                b"failover.test.",
                want_v4,
                want_v6,
                &config,
                |owner, kind, server, timeout, trust_ad, tcp| {
                    assert_eq!(owner, b"failover.test.");
                    assert_eq!(timeout, Duration::from_secs(7));
                    assert!(trust_ad);
                    assert_eq!(tcp, use_vc);
                    calls.push((server.ip(), kind));
                    if server.ip() == config.nameservers[0] {
                        Err(refused())
                    } else {
                        Ok(positive(b"failover.test", kind))
                    }
                },
            )
            .unwrap();
            assert_eq!(result.addresses.ipv4.len(), usize::from(want_v4));
            assert_eq!(result.addresses.ipv6.len(), usize::from(want_v6));
            assert_eq!(result.canonical_name, b"failover.test");
            let mut expected = vec![(
                config.nameservers[0],
                if want_v4 { qtype::A } else { qtype::AAAA },
            )];
            if want_v4 {
                expected.push((config.nameservers[1], qtype::A));
                assert_eq!(result.addresses.ipv4, [Ipv4Addr::new(192, 0, 2, 7)]);
            }
            if want_v6 {
                expected.push((config.nameservers[1], qtype::AAAA));
                assert_eq!(
                    result.addresses.ipv6,
                    ["2001:db8::7".parse::<Ipv6Addr>().unwrap()]
                );
            }
            assert_eq!(calls, expected);
        }
    }
}

#[test]
fn resolved_family_and_canonical_name_survive_other_family_refusals() {
    let config = config();
    let mut calls = Vec::new();
    let result = resolve_with_canonical(
        b"winner.test.",
        true,
        true,
        &config,
        |_, kind, server, _, _, _| {
            calls.push((server.ip(), kind));
            if kind == qtype::A {
                Ok(positive(b"winner.test", kind))
            } else {
                Err(refused())
            }
        },
    )
    .unwrap();
    assert_eq!(result.addresses.ipv4, [Ipv4Addr::new(192, 0, 2, 7)]);
    assert!(result.addresses.ipv6.is_empty());
    assert_eq!(result.canonical_name, b"winner.test");
    assert_eq!(
        calls,
        [
            (config.nameservers[0], qtype::A),
            (config.nameservers[0], qtype::AAAA),
            (config.nameservers[1], qtype::AAAA),
        ]
    );
}

#[test]
fn all_refused_servers_stop_search_without_retry_amplification() {
    let mut config = config();
    config.nameservers.push("127.0.0.3".parse().unwrap());
    config.search = vec!["first.test".into(), "never.test".into()];
    config.attempts = 5;
    let mut calls = Vec::new();
    let result = resolve_with(
        b"host",
        true,
        true,
        &config,
        |owner, kind, server, _, _, _| {
            assert_eq!(owner, b"host.first.test");
            assert_eq!(kind, qtype::A);
            calls.push(server.ip());
            Err(refused())
        },
    );
    assert_eq!(result.unwrap_err(), ResolveError::Temporary);
    assert_eq!(calls, config.nameservers);
}

#[test]
fn refused_server_is_not_retried_while_fallback_recovers_from_timeout() {
    let config = config();
    let mut calls = Vec::new();
    let mut fallback_attempts = 0;
    let result = resolve_with(
        b"host.test.",
        true,
        false,
        &config,
        |_, kind, server, _, _, _| {
            calls.push(server.ip());
            if server.ip() == config.nameservers[0] {
                return Err(refused());
            }
            fallback_attempts += 1;
            if fallback_attempts == 1 {
                Err(QueryError::Io(io::ErrorKind::TimedOut.into()))
            } else {
                Ok(positive(b"host.test", kind))
            }
        },
    )
    .unwrap();
    assert_eq!(result.ipv4, [Ipv4Addr::new(192, 0, 2, 7)]);
    assert_eq!(
        calls,
        [
            config.nameservers[0],
            config.nameservers[1],
            config.nameservers[1],
        ]
    );
}

#[test]
fn fallback_definitive_negative_supersedes_primary_refusal() {
    for code in [rcode::NOERROR, rcode::NXDOMAIN] {
        let config = config();
        let mut calls = Vec::new();
        let result = resolve_with(
            b"missing.test.",
            true,
            false,
            &config,
            |_, _, server, _, _, _| {
                calls.push(server.ip());
                if server.ip() == config.nameservers[0] {
                    Err(refused())
                } else {
                    Ok(QueryReply {
                        records: vec![],
                        rcode: code,
                    })
                }
            },
        );
        assert_eq!(result.unwrap_err(), ResolveError::NotFound);
        assert_eq!(calls, config.nameservers);
    }
}

#[test]
fn refusal_state_does_not_leak_to_the_next_search_candidate() {
    let mut config = config();
    config.search = vec!["missing.test".into(), "found.test".into()];
    let mut calls = Vec::new();
    let result = resolve_with(
        b"host",
        true,
        false,
        &config,
        |owner, kind, server, _, _, _| {
            calls.push((owner.to_vec(), server.ip()));
            if owner == b"host.missing.test" {
                if server.ip() == config.nameservers[0] {
                    Err(refused())
                } else {
                    Ok(QueryReply {
                        records: vec![],
                        rcode: rcode::NXDOMAIN,
                    })
                }
            } else {
                assert_eq!(owner, b"host.found.test");
                Ok(positive(owner, kind))
            }
        },
    )
    .unwrap();
    assert_eq!(result.ipv4, [Ipv4Addr::new(192, 0, 2, 7)]);
    assert_eq!(
        calls,
        [
            (b"host.missing.test".to_vec(), config.nameservers[0]),
            (b"host.missing.test".to_vec(), config.nameservers[1]),
            (b"host.found.test".to_vec(), config.nameservers[0]),
        ]
    );
}
