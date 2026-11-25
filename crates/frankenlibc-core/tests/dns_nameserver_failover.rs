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

fn cname_response(query: &[u8], targets: &[Vec<u8>], address: bool) -> Vec<u8> {
    use frankenlibc_core::resolv::dns::{DnsQuestion, encode_domain_name};
    // The public question decoder includes QTYPE and QCLASS in its consumed
    // length. Keep this integration target independent of private helpers.
    let (question, consumed) = DnsQuestion::decode(&query[12..], query).unwrap();
    let end = 12 + consumed;
    let kind = question.qtype;
    let mut response = query[..end].to_vec();
    response[2..4].copy_from_slice(&[0x81, 0x80]);
    response[6..12].fill(0);
    response[6..8].copy_from_slice(&((targets.len() + usize::from(address)) as u16).to_be_bytes());
    let mut owner = if !targets.is_empty() || !address {
        vec![0xc0, 12]
    } else {
        encode_domain_name(&question.qname).unwrap()
    };
    for target in targets {
        let target = encode_domain_name(target).unwrap();
        response.extend_from_slice(&owner);
        response.extend_from_slice(&[0, 5, 0, 1, 0, 0, 0, 60]);
        response.extend_from_slice(&(target.len() as u16).to_be_bytes());
        response.extend_from_slice(&target);
        owner = target;
    }
    if address {
        owner.make_ascii_uppercase();
        let data = if kind == qtype::A {
            vec![192, 0, 2, 7]
        } else {
            Ipv6Addr::LOCALHOST.octets().to_vec()
        };
        response.extend_from_slice(&owner);
        response.extend_from_slice(&kind.to_be_bytes());
        response.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(&data);
    }
    response
}

fn canonical_lookup(targets: Vec<Vec<u8>>, kind: u16, separate_packets: bool) -> Vec<u8> {
    use frankenlibc_core::dns_transport::{QueryOptions, query};
    use frankenlibc_core::resolv::dns::{DnsQuestion, encode_domain_name};
    let terminal = targets
        .last()
        .map(Vec::as_slice)
        .unwrap_or(b"origin.hostname.invalid");
    let mut terminal_wire = encode_domain_name(terminal).unwrap();
    terminal_wire.make_ascii_uppercase();
    terminal_wire.extend_from_slice(&kind.to_be_bytes());
    terminal_wire.extend_from_slice(&qclass::IN.to_be_bytes());
    let (expected_question, consumed) =
        DnsQuestion::decode(&terminal_wire, &terminal_wire).unwrap();
    assert_eq!(consumed, terminal_wire.len());
    let expected_owner = expected_question.qname;
    let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let endpoint = server.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let count = if separate_packets {
            targets.len() + 1
        } else {
            1
        };
        for index in 0..count {
            let mut sent = [0u8; 512];
            let (n, peer) = server.recv_from(&mut sent).unwrap();
            let answer = if separate_packets {
                let next = targets.get(index).map(std::slice::from_ref).unwrap_or(&[]);
                cname_response(&sent[..n], next, next.is_empty())
            } else {
                cname_response(&sent[..n], &targets, true)
            };
            server.send_to(&answer, peer).unwrap();
        }
    });
    let result = resolve_with_canonical(
        b"origin.hostname.invalid.",
        kind == qtype::A,
        kind == qtype::AAAA,
        &ResolverConfig::default(),
        |owner, kind, _, timeout, _, _| {
            let reply = query(owner, kind, endpoint, timeout, QueryOptions::default())?;
            assert_eq!(reply.records.len(), 1);
            assert_eq!(
                reply.records[0].name, expected_owner,
                "wire owner must remain unchanged"
            );
            Ok(reply)
        },
    );
    worker.join().unwrap();
    let result = result.unwrap();
    if kind == qtype::A {
        assert_eq!(result.addresses.ipv4, [Ipv4Addr::new(192, 0, 2, 7)]);
        assert!(result.addresses.ipv6.is_empty());
    } else {
        assert_eq!(result.addresses.ipv6, [Ipv6Addr::LOCALHOST]);
        assert!(result.addresses.ipv4.is_empty());
    }
    result.canonical_name
}

#[test]
fn canonical_name_retains_last_hostname_valid_cname_target() {
    // Executed GNU controls retain addresses bound to binary DNS names, while
    // keeping the previous hostname-valid canonical name. RFC 2181 section 11
    // separates DNS label syntax from application hostname requirements.
    for kind in [qtype::A, qtype::AAAA] {
        for invalid in [
            br"edge\.test".as_slice(),
            br"zero.a\000b",
            b"bad.x y",
            b"-bad.test",
            br"high.\255test",
        ] {
            for (targets, expected) in [
                (vec![invalid], b"origin.hostname.invalid".as_slice()),
                (
                    vec![b"Middle.test".as_slice(), invalid],
                    b"Middle.test".as_slice(),
                ),
                (
                    vec![invalid, b"Final.test".as_slice()],
                    b"Final.test".as_slice(),
                ),
            ] {
                let owned = targets.iter().map(|target| target.to_vec()).collect();
                assert_eq!(
                    canonical_lookup(owned, kind, false),
                    expected,
                    "targets={targets:?}"
                );
            }
        }
    }
}

#[test]
fn canonical_name_keeps_query_and_alias_case_and_valid_root() {
    for kind in [qtype::A, qtype::AAAA] {
        for target in [
            None,
            Some(b"Middle.test".as_slice()),
            Some(b".".as_slice()),
            Some(b"good.-part".as_slice()),
            Some(b"good._part".as_slice()),
        ] {
            let targets = target.into_iter().map(<[u8]>::to_vec).collect();
            assert_eq!(
                canonical_lookup(targets, kind, false),
                target.unwrap_or(b"origin.hostname.invalid")
            );
        }
    }
}

#[test]
fn canonical_name_survives_invalid_cross_packet_alias_target() {
    for kind in [qtype::A, qtype::AAAA] {
        let targets = vec![b"Middle.test".to_vec(), br"edge\.test".to_vec()];
        assert_eq!(canonical_lookup(targets, kind, true), b"Middle.test");
    }
}

fn config() -> ResolverConfig {
    ResolverConfig {
        nameservers: vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        ],
        attempts: 3,
        ..ResolverConfig::default()
    }
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
        canonical_name: Some(owner.to_vec()),
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
                        canonical_name: None,
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
                        canonical_name: None,
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

#[test]
fn scoped_nameservers_keep_their_interfaces_across_failover_and_reverse_queries() {
    use frankenlibc_core::dns_transport::{raw, reverse_with};
    use std::net::SocketAddr;

    let config = ResolverConfig::parse_with_interfaces(
        b"nameserver fe80::53%lan0\nnameserver fe80::53%7\nnameserver 192.0.2.53\noptions attempts:1\n",
        |zone| u32::from(zone == b"lan0") * 13,
    );
    let expected: [SocketAddr; 3] = [
        "[fe80::53%13]:53".parse().unwrap(),
        "[fe80::53%7]:53".parse().unwrap(),
        "192.0.2.53:53".parse().unwrap(),
    ];
    assert_eq!(raw::Config::from(&config).nameservers, expected);
    let mut forward = Vec::new();
    resolve_with(
        b"test.",
        true,
        false,
        &config,
        |owner, kind, server, _, _, _| {
            forward.push(server);
            if server == expected[2] {
                Ok(positive(owner, kind))
            } else {
                Err(refused())
            }
        },
    )
    .unwrap();
    assert_eq!(forward, expected);
    let mut reverse = Vec::new();
    let _ = reverse_with(
        "192.0.2.42".parse().unwrap(),
        &config,
        |_, _, server, _, _, _| {
            reverse.push(server);
            Err(refused())
        },
    );
    assert_eq!(reverse, expected);
}

#[test]
fn resolver_keeps_unknown_ipv6_zones_unscoped_but_rejects_zoned_ipv4() {
    use std::net::SocketAddr;
    let config = ResolverConfig::parse_with_interfaces(
        b"nameserver 192.0.2.99%3\nnameserver fe80::1%missing\nnameserver 2001:db8::1%lan0\nnameserver ff02::1%lan0\n",
        |zone| u32::from(zone == b"lan0") * 13,
    );
    let actual: Vec<_> = (0..config.nameservers.len())
        .map(|i| config.nameserver_endpoint(i))
        .collect();
    let expected: [SocketAddr; 3] = [
        "[fe80::1]:53".parse().unwrap(),
        "[2001:db8::1]:53".parse().unwrap(),
        "[ff02::1%13]:53".parse().unwrap(),
    ];
    assert_eq!(actual, expected);
}
