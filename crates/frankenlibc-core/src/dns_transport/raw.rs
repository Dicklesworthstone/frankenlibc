//! Raw resolver messages over the native DNS transport.
//!
//! Unlike address lookup, `res_send` returns the wire message (including
//! negative answers) and must retain whether UDP or TCP delivered it. A TCP
//! answer larger than the caller's buffer returns its full frame length and
//! marks the copied header truncated; UDP returns the number of copied bytes.
//! No host resolver is called and no socket survives an exchange.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::{QueryError, exchange_raw_until};
use crate::resolv::config::{DNS_PORT, ResolverConfig};
use crate::resolv::dns::{DNS_HEADER_SIZE, DnsHeader, DnsMessage, rcode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Debug)]
pub struct Reply {
    pub packet: Vec<u8>,
    pub transport: Transport,
}

impl Reply {
    pub(super) fn tcp(packet: Vec<u8>) -> Self {
        Self {
            packet,
            transport: Transport::Tcp,
        }
    }

    /// Copy a response into caller-owned storage with libresolv's wire-length
    /// contract. Output shorter than a DNS header is rejected without writing.
    /// The return value can exceed `answer.len()` for TCP: it is NOT a bound
    /// for reading the copied buffer.
    pub fn copy_answer(&self, answer: &mut [u8]) -> Result<usize, QueryError> {
        if answer.len() < DNS_HEADER_SIZE {
            return Err(QueryError::InvalidQuery);
        }
        if self.packet.len() < DNS_HEADER_SIZE || self.packet.len() > u16::MAX as usize {
            return Err(QueryError::InvalidResponse);
        }
        let copied = answer.len().min(self.packet.len());
        answer[..copied].copy_from_slice(&self.packet[..copied]);
        if self.transport == Transport::Tcp {
            if copied < self.packet.len() {
                answer[2] |= 0x02; // TC, in the copied header only.
            }
            Ok(self.packet.len())
        } else {
            Ok(copied)
        }
    }
}

/// Explicit configuration snapshot, including port numbers for per-client
/// resolvers. It owns its values; no mutable configuration borrow or lock is
/// held across socket I/O.
#[derive(Debug, Clone)]
pub struct Config {
    pub nameservers: Vec<SocketAddr>,
    pub timeout: Duration,
    pub attempts: u32,
    pub rotate: bool,
    pub use_vc: bool,
    pub ignore_truncation: bool,
    pub trust_ad: bool,
}

impl From<&ResolverConfig> for Config {
    fn from(config: &ResolverConfig) -> Self {
        Self {
            nameservers: config
                .nameservers
                .iter()
                .map(|&ip| SocketAddr::new(ip, DNS_PORT))
                .collect(),
            timeout: config.query_timeout(),
            attempts: config.attempts,
            rotate: config.rotate,
            use_vc: config.use_vc,
            ignore_truncation: false,
            trust_ad: config.trust_ad,
        }
    }
}

/// Exchange one preformatted, single-question QUERY, NOTIFY or UPDATE packet.
/// Replies must match the configured peer, ID, opcode, complete wire-format
/// question, QTYPE and QCLASS. Ignored packets and UDP-to-TCP fallback share
/// one deadline. The returned transport describes the actual final exchange.
pub fn exchange(
    server: SocketAddr,
    query: &[u8],
    timeout: Duration,
    use_vc: bool,
    ignore_truncation: bool,
) -> Result<Reply, QueryError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(QueryError::InvalidQuery)?;
    exchange_raw_until(server, query, deadline, use_vc, ignore_truncation)
}

/// Send a raw message using the configured nameserver/retry policy. Validated
/// UDP SERVFAIL/NOTIMP/REFUSED responses select another server. NXDOMAIN and
/// other wire responses remain raw responses, not invented address failures.
pub fn send(query: &[u8], config: &Config) -> Result<Reply, QueryError> {
    static NEXT_SERVER: AtomicUsize = AtomicUsize::new(0);
    let start = if config.rotate && !config.nameservers.is_empty() {
        NEXT_SERVER.fetch_add(1, Ordering::Relaxed) % config.nameservers.len()
    } else {
        0
    };
    send_with(query, config, start, exchange)
}

/// Higher-level query/search needs the last validated server rejection to
/// distinguish SERVFAIL from a transport timeout. Keep raw res_send's existing
/// error contract unchanged; never treat an unvalidated packet as a rejection.
pub fn send_for_query(query: &[u8], config: &Config) -> Result<Reply, QueryError> {
    static NEXT_SERVER: AtomicUsize = AtomicUsize::new(0);
    let start = if config.rotate && !config.nameservers.is_empty() {
        NEXT_SERVER.fetch_add(1, Ordering::Relaxed) % config.nameservers.len()
    } else { 0 };
    send_inner(query, config, start, exchange, true)
}

fn send_with<F>(
    query: &[u8],
    config: &Config,
    start: usize,
    exchange: F,
) -> Result<Reply, QueryError>
where
    F: FnMut(SocketAddr, &[u8], Duration, bool, bool) -> Result<Reply, QueryError>,
{
    send_inner(query, config, start, exchange, false)
}

fn send_inner<F>(
    query: &[u8], config: &Config, start: usize, mut exchange: F, retain_rejection: bool,
) -> Result<Reply, QueryError>
where
    F: FnMut(SocketAddr, &[u8], Duration, bool, bool) -> Result<Reply, QueryError>,
{
    if config.nameservers.is_empty() {
        return Err(QueryError::Io(io::ErrorKind::ConnectionRefused.into()));
    }
    let count = config.nameservers.len();
    let mut refused = vec![false; count];
    let mut last_error = QueryError::Io(io::ErrorKind::TimedOut.into());
    let mut last_rejection = None;
    for _ in 0..config.attempts.max(1) {
        for offset in 0..count {
            // `start` is bounded by `count` in production and by the tests.
            let index = (start + offset) % count;
            if refused[index] {
                continue;
            }
            match exchange(
                config.nameservers[index],
                query,
                config.timeout,
                config.use_vc,
                config.ignore_truncation,
            ) {
                Ok(mut reply) => {
                    let header =
                        DnsHeader::decode(&reply.packet).ok_or(QueryError::InvalidResponse)?;
                    if reply.transport == Transport::Udp
                        && matches!(
                            header.rcode(),
                            rcode::SERVFAIL | rcode::NOTIMP | rcode::REFUSED
                        )
                    {
                        // A malformed rejection must not influence failover.
                        DnsMessage::decode(&reply.packet).ok_or(QueryError::InvalidResponse)?;
                        last_error = QueryError::Io(io::ErrorKind::TimedOut.into());
                        if retain_rejection {
                            if !config.trust_ad { reply.packet[3] &= !0x20; }
                            last_rejection = Some(reply);
                        }
                        continue;
                    }
                    // AD is only meaningful when the application explicitly
                    // trusts the configured resolver. Do not assert validation.
                    if !config.trust_ad {
                        reply.packet[3] &= !0x20;
                    }
                    return Ok(reply);
                }
                Err(QueryError::InvalidQuery) => return Err(QueryError::InvalidQuery),
                Err(QueryError::Io(error)) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    refused[index] = true;
                    last_error = QueryError::Io(error);
                }
                Err(error) => last_error = error,
            }
        }
        if refused.iter().all(|&value| value) {
            break;
        }
    }
    if let Some(reply) = last_rejection {
        Ok(reply)
    } else {
        Err(last_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            nameservers: vec![
                "127.0.0.1:10053".parse().unwrap(),
                "[::1]:20053".parse().unwrap(),
            ],
            timeout: Duration::from_secs(3),
            attempts: 2,
            rotate: false,
            use_vc: false,
            ignore_truncation: false,
            trust_ad: false,
        }
    }

    fn reply(code: u8, transport: Transport) -> Reply {
        let mut packet = vec![0; DNS_HEADER_SIZE];
        packet[2] = 0x81;
        packet[3] = 0xa0 | code;
        Reply { packet, transport }
    }

    #[test]
    fn copy_contract_depends_on_final_transport_and_preserves_input() {
        for transport in [Transport::Udp, Transport::Tcp] {
            let mut r = reply(0, transport);
            r.packet.extend_from_slice(&[0xaa; 40]);
            let original = r.packet.clone();
            for capacity in [12usize, 13, 51, 52, 53] {
                let mut buffer = vec![0xcc; capacity + 2];
                let reported = r.copy_answer(&mut buffer[1..=capacity]).unwrap();
                let copied = capacity.min(r.packet.len());
                assert_eq!(
                    reported,
                    if transport == Transport::Tcp { r.packet.len() } else { copied }
                );
                assert_eq!(buffer[0], 0xcc);
                assert_eq!(buffer[capacity + 1], 0xcc);
                assert_eq!(&buffer[13..1 + copied], &r.packet[12..copied]);
                assert_eq!(
                    buffer[3] & 2 != 0,
                    transport == Transport::Tcp && capacity < r.packet.len()
                );
                assert_eq!(r.packet, original);
            }
        }
    }

    #[test]
    fn undersized_output_is_unchanged() {
        let r = reply(0, Transport::Tcp);
        for capacity in 0..DNS_HEADER_SIZE {
            let mut buffer = vec![0xa5; capacity];
            assert!(matches!(r.copy_answer(&mut buffer), Err(QueryError::InvalidQuery)));
            assert!(buffer.iter().all(|&byte| byte == 0xa5));
        }
    }

    #[test]
    fn udp_rejections_fail_over_but_nxdomain_and_tcp_codes_are_returned() {
        for code in [rcode::SERVFAIL, rcode::NOTIMP, rcode::REFUSED] {
            let cfg = config();
            let mut calls = Vec::new();
            let r = send_with(&[], &cfg, 0, |server, _, _, _, _| {
                calls.push(server);
                Ok(reply(if calls.len() == 1 { code } else { rcode::NXDOMAIN }, Transport::Udp))
            }).unwrap();
            assert_eq!(calls, cfg.nameservers);
            assert_eq!(r.packet[3] & 15, rcode::NXDOMAIN);
            let mut calls = 0;
            let r = send_with(&[], &cfg, 0, |_, _, _, _, _| {
                calls += 1;
                Ok(reply(code, Transport::Tcp))
            }).unwrap();
            assert_eq!(calls, 1);
            assert_eq!(r.packet[3] & 15, code);
        }
    }

    #[test]
    fn rejected_udp_packets_must_have_complete_declared_sections() {
        let mut calls = 0;
        let result = send_with(&[], &config(), 0, |_, _, _, _, _| {
            calls += 1;
            let mut r = reply(rcode::SERVFAIL, Transport::Udp);
            r.packet[7] = 1; // Declared answer missing.
            Ok(r)
        });
        assert!(matches!(result, Err(QueryError::InvalidResponse)));
        assert_eq!(calls, 1);
    }

    #[test]
    fn refused_server_is_skipped_while_other_server_retries() {
        let cfg = config();
        let mut calls = Vec::new();
        let mut second = 0;
        let result = send_with(&[], &cfg, 0, |server, _, _, _, _| {
            calls.push(server);
            if server == cfg.nameservers[0] {
                return Err(QueryError::Io(io::ErrorKind::ConnectionRefused.into()));
            }
            second += 1;
            if second == 1 {
                Err(QueryError::Io(io::ErrorKind::TimedOut.into()))
            } else {
                Ok(reply(0, Transport::Udp))
            }
        }).unwrap();
        assert_eq!(result.transport, Transport::Udp);
        assert_eq!(calls, [cfg.nameservers[0], cfg.nameservers[1], cfg.nameservers[1]]);
    }

    #[test]
    fn rotation_options_and_ad_policy_are_explicit() {
        for trust_ad in [false, true] {
            let mut cfg = config();
            cfg.trust_ad = trust_ad;
            cfg.use_vc = true;
            cfg.ignore_truncation = true;
            let r = send_with(b"query", &cfg, 1, |server, query, timeout, vc, igntc| {
                assert_eq!(server, cfg.nameservers[1]);
                assert_eq!(query, b"query");
                assert_eq!(timeout, cfg.timeout);
                assert!(vc && igntc);
                Ok(reply(0, Transport::Tcp))
            }).unwrap();
            assert_eq!(r.packet[3] & 0x20 != 0, trust_ad);
        }
    }

    #[test]
    fn permanent_input_failure_stops_without_retry_amplification() {
        let mut calls = 0;
        let result = send_with(&[], &config(), 0, |_, _, _, _, _| {
            calls += 1;
            Err(QueryError::InvalidQuery)
        });
        assert!(matches!(result, Err(QueryError::InvalidQuery)));
        assert_eq!(calls, 1);
        let mut cfg = config();
        cfg.nameservers.clear();
        let result = send_with(&[], &cfg, 0, |_, _, _, _, _| panic!("no server"));
        assert!(matches!(result, Err(QueryError::Io(error))
            if error.kind() == io::ErrorKind::ConnectionRefused));
    }
    #[test]
    fn query_rejections_remain_distinct_from_raw_send_and_transport_failure() {
        let mut config = config();
        config.attempts = 1;
        let result = send_inner(&[], &config, 0, |_, _, _, _, _| {
            Ok(reply(rcode::SERVFAIL, Transport::Udp))
        }, true).unwrap();
        assert_eq!(result.packet[3] & 15, rcode::SERVFAIL);
        assert_eq!(result.packet[3] & 0x20, 0);
        assert!(matches!(send_inner(&[], &config, 0, |_, _, _, _, _| {
            Err(QueryError::Io(io::ErrorKind::TimedOut.into()))
        }, true), Err(QueryError::Io(_))));
        assert!(matches!(send_with(&[], &config, 0, |_, _, _, _, _| {
            Ok(reply(rcode::SERVFAIL, Transport::Udp))
        }), Err(QueryError::Io(_))));
    }

    #[test]
    fn query_success_supersedes_an_earlier_server_rejection() {
        let config = config();
        let mut calls = 0;
        let result = send_inner(&[], &config, 0, |_, _, _, _, _| {
            calls += 1;
            Ok(reply(if calls == 1 { rcode::SERVFAIL } else { rcode::NXDOMAIN }, Transport::Udp))
        }, true).unwrap();
        assert_eq!(calls, 2);
        assert_eq!(result.packet[3] & 15, rcode::NXDOMAIN);
    }

}
