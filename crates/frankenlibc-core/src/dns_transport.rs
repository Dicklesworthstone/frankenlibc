//! DNS client transport and resolver retry policy.
//!
//! Connected UDP binds replies to the configured server. Transaction ID and
//! the complete wire-format question are checked before accepting a reply or
//! following TC to TCP (RFC 5452, RFC 7766). One monotonic deadline covers UDP,
//! TCP connection establishment, partial frame I/O, and discarded packets.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::resolv::config::{DNS_PORT, ResolverConfig};
use crate::resolv::dns::{
    DNS_HEADER_SIZE, DNS_MAX_UDP_SIZE, DnsHeader, DnsMessage, DnsRecord, DnsResolution,
    build_search_names, qtype, rcode,
};
use crate::resolv::dns_name::{NS_MAXCDNAME, name_unpack};

/// DNS-over-TCP's unsigned 16-bit message length, excluding the length prefix.
const MAX_MESSAGE: usize = u16::MAX as usize;
static NEXT_SERVER: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
pub enum QueryError {
    Io(io::Error),
    InvalidQuery,
    InvalidResponse,
    ResponseCode(u8),
}

impl From<io::Error> for QueryError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::WouldBlock {
            Self::Io(io::Error::new(io::ErrorKind::TimedOut, error))
        } else {
            Self::Io(error)
        }
    }
}

/// Negative replies remain distinct: NOERROR without addresses is not NXDOMAIN.
#[derive(Debug)]
pub struct QueryReply {
    pub records: Vec<DnsRecord>,
    pub rcode: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    NotFound,
    Temporary,
    Failure,
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "DNS query deadline expired"))
}

/// Expand into wire form rather than dotted text: a literal dot inside one
/// label must not compare equal to two separate labels. Padding is initialized
/// to zero, so the whole bounded array can be compared case-insensitively.
fn question(packet: &[u8]) -> Option<([u8; NS_MAXCDNAME], [u8; 4])> {
    let mut name = [0; NS_MAXCDNAME];
    let consumed = name_unpack(packet, DNS_HEADER_SIZE, &mut name).ok()?;
    let start = DNS_HEADER_SIZE.checked_add(consumed)?;
    let fields = packet.get(start..start.checked_add(4)?)?;
    Some((name, fields.try_into().ok()?))
}

fn response_matches(query: &[u8], packet: &[u8]) -> bool {
    let (Some(sent), Some(reply)) = (DnsHeader::decode(query), DnsHeader::decode(packet)) else {
        return false;
    };
    if sent.qdcount != 1
        || reply.qdcount != 1
        || sent.id != reply.id
        || !reply.is_response()
        || reply.flags & 0x7800 != sent.flags & 0x7800
    {
        return false;
    }
    match (question(query), question(packet)) {
        (Some((sent_name, sent_fields)), Some((reply_name, reply_fields))) => {
            sent_fields == reply_fields && sent_name.eq_ignore_ascii_case(&reply_name)
        }
        _ => false,
    }
}

fn tcp_write_all(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "DNS TCP write stopped")),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn tcp_read_exact(stream: &mut TcpStream, mut bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short DNS TCP frame")),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn tcp_exchange(server: SocketAddr, query: &[u8], deadline: Instant) -> Result<Vec<u8>, QueryError> {
    let mut stream = TcpStream::connect_timeout(&server, remaining(deadline)?)?;
    let mut frame = Vec::with_capacity(query.len() + 2);
    frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
    frame.extend_from_slice(query);
    tcp_write_all(&mut stream, &frame, deadline)?;

    loop {
        let mut prefix = [0; 2];
        tcp_read_exact(&mut stream, &mut prefix, deadline)?;
        let length = usize::from(u16::from_be_bytes(prefix));
        if length < DNS_HEADER_SIZE {
            return Err(QueryError::InvalidResponse);
        }
        let mut packet = vec![0; length];
        tcp_read_exact(&mut stream, &mut packet, deadline)?;
        if !response_matches(query, &packet) {
            continue;
        }
        if DnsHeader::decode(&packet).is_none_or(|header| header.is_truncated()) {
            return Err(QueryError::InvalidResponse);
        }
        return Ok(packet);
    }
}

/// Exchange one standard single-question DNS query. Only matching replies can
/// trigger fallback, and all fallback work consumes the original time budget.
pub fn exchange(
    server: SocketAddr,
    query: &[u8],
    timeout: Duration,
    use_vc: bool,
) -> Result<Vec<u8>, QueryError> {
    let header = DnsHeader::decode(query).ok_or(QueryError::InvalidQuery)?;
    if query.len() > MAX_MESSAGE
        || header.is_response()
        || header.flags & 0x7800 != 0
        || header.qdcount != 1
        || question(query).is_none()
    {
        return Err(QueryError::InvalidQuery);
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(QueryError::InvalidQuery)?;
    // Check zero budgets before opening a descriptor. SO_RCVTIMEO=0 means an
    // *unbounded* wait on Linux, not an immediate timeout.
    remaining(deadline)?;
    if use_vc || query.len() > DNS_MAX_UDP_SIZE {
        return tcp_exchange(server, query, deadline);
    }

    let local = match server.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(local)?;
    socket.connect(server)?;
    loop {
        socket.set_write_timeout(Some(remaining(deadline)?))?;
        match socket.send(query) {
            Ok(sent) if sent == query.len() => break,
            Ok(_) => return Err(QueryError::InvalidResponse),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    // Accommodate all legal UDP DNS datagrams. A 512-byte receive buffer can
    // silently discard the tail of a larger datagram without its TC bit set.
    let mut packet = vec![0; MAX_MESSAGE];
    loop {
        socket.set_read_timeout(Some(remaining(deadline)?))?;
        let received = match socket.recv(&mut packet) {
            Ok(received) => received,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        let reply = &packet[..received];
        if !response_matches(query, reply) {
            continue;
        }
        if DnsHeader::decode(reply).is_some_and(|header| header.is_truncated()) {
            // Do not decode the truncated answer section: it may end halfway
            // through an RR. The validated header + question are sufficient.
            return tcp_exchange(server, query, deadline);
        }
        packet.truncate(received);
        return Ok(packet);
    }
}

/// Query a configured server without any host resolver call-through. Linux's
/// entropy device supplies unpredictable IDs; clock/hash fallback is forbidden.
pub fn query(
    hostname: &[u8],
    record_type: u16,
    server: SocketAddr,
    timeout: Duration,
    trust_ad: bool,
    use_vc: bool,
) -> Result<QueryReply, QueryError> {
    let mut entropy = [0; 2];
    File::open("/dev/urandom")?.read_exact(&mut entropy)?;
    let message = DnsMessage::new_query_with_trust_ad(
        u16::from_ne_bytes(entropy), hostname, record_type, trust_ad,
    ).ok_or(QueryError::InvalidQuery)?;
    let mut wire = [0; DNS_MAX_UDP_SIZE];
    let length = message.encode(&mut wire).ok_or(QueryError::InvalidQuery)?;
    let packet = exchange(server, &wire[..length], timeout, use_vc)?;
    let message = DnsMessage::decode(&packet).ok_or(QueryError::InvalidResponse)?;
    match message.header.rcode() {
        rcode::NOERROR => Ok(QueryReply { records: message.answers, rcode: rcode::NOERROR }),
        rcode::NXDOMAIN => Ok(QueryReply { records: Vec::new(), rcode: rcode::NXDOMAIN }),
        code => Err(QueryError::ResponseCode(code)),
    }
}

/// Resolve each search candidate with independent per-family terminal states.
/// A definitive NOERROR/NODATA or NXDOMAIN is not retried at every server. A
/// transient failure is retried; an address already found is never queried
/// again. Results from different search candidates are never mixed.
pub fn resolve_with<F>(
    hostname: &[u8],
    want_v4: bool,
    want_v6: bool,
    config: &ResolverConfig,
    mut query: F,
) -> Result<DnsResolution, ResolveError>
where
    F: FnMut(&[u8], u16, SocketAddr, Duration, bool, bool) -> Result<QueryReply, QueryError>,
{
    if !want_v4 && !want_v6 {
        return Err(ResolveError::NotFound);
    }
    if config.nameservers.is_empty() {
        return Err(ResolveError::Temporary);
    }
    let start = if config.rotate {
        NEXT_SERVER.fetch_add(1, Ordering::Relaxed) % config.nameservers.len()
    } else { 0 };
    let timeout = Duration::from_secs(u64::from(config.timeout.max(1)));
    let mut saw_temporary = false;
    let mut saw_failure = false;
    for name in build_search_names(hostname, &config.search, config.ndots) {
        let mut result = DnsResolution::default();
        let mut done = [!want_v4, !want_v6];
        for _ in 0..config.attempts.max(1) {
            for offset in 0..config.nameservers.len() {
                let server = SocketAddr::new(
                    config.nameservers[(start + offset) % config.nameservers.len()], DNS_PORT,
                );
                for (index, record_type) in [qtype::A, qtype::AAAA].into_iter().enumerate() {
                    if done[index] { continue; }
                    match query(&name, record_type, server, timeout, config.trust_ad, config.use_vc) {
                        Ok(reply) => {
                            done[index] = true;
                            if reply.rcode == rcode::NOERROR {
                                for record in reply.records {
                                    if index == 0 {
                                        if let Some(address) = record.as_ipv4()
                                            && !result.ipv4.contains(&address)
                                        { result.ipv4.push(address); }
                                    } else if let Some(address) = record.as_ipv6()
                                        && !result.ipv6.contains(&address)
                                    { result.ipv6.push(address); }
                                }
                            }
                        }
                        Err(QueryError::Io(_)) | Err(QueryError::ResponseCode(rcode::SERVFAIL)) => {
                            saw_temporary = true;
                        }
                        Err(_) => { saw_failure = true; }
                    }
                }
                if done.iter().all(|&value| value) { break; }
            }
            if done.iter().all(|&value| value) { break; }
        }
        if !result.ipv4.is_empty() || !result.ipv6.is_empty() {
            return Ok(result);
        }
    }
    if saw_temporary { Err(ResolveError::Temporary) }
    else if saw_failure { Err(ResolveError::Failure) }
    else { Err(ResolveError::NotFound) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn query_wire() -> Vec<u8> {
        let mut bytes = vec![0; DNS_MAX_UDP_SIZE];
        let length = DnsMessage::new_query(0x1234, b"example.test", qtype::A)
            .unwrap().encode(&mut bytes).unwrap();
        bytes.truncate(length);
        bytes
    }

    fn answer(query: &[u8]) -> Vec<u8> {
        let mut bytes = query.to_vec();
        bytes[2] |= 0x80;
        bytes[3] = 0x80;
        bytes[7] = 1;
        bytes.extend_from_slice(&[
            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7,
        ]);
        bytes
    }

    fn read_query(stream: &mut TcpStream) -> Vec<u8> {
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut prefix = [0; 2];
        stream.read_exact(&mut prefix).unwrap();
        let mut bytes = vec![0; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn question_binding_checks_id_type_class_opcode_and_label_boundaries() {
        let sent = query_wire();
        let valid = answer(&sent);
        assert!(response_matches(&sent, &valid));
        for (index, mask) in [(0, 1), (2, 8), (5, 1), (13, 1), (sent.len()-1, 1), (sent.len()-3, 1)] {
            let mut wrong = valid.clone();
            wrong[index] ^= mask;
            assert!(!response_matches(&sent, &wrong), "byte {index}");
        }
        let mut upper = valid.clone();
        upper[13..20].make_ascii_uppercase();
        assert!(response_matches(&sent, &upper));
        // Literal dot inside a label is not a label separator.
        let mut dotted = vec![0; 512];
        let len = DnsMessage::new_query(0x1234, br"example\.test", qtype::A)
            .unwrap().encode(&mut dotted).unwrap();
        dotted.truncate(len);
        assert!(!response_matches(&sent, &answer(&dotted)));
    }

    #[test]
    fn udp_ignores_wrong_source_and_wrong_question_before_valid_reply() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let addr = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut buffer = [0; 512];
            let (len, peer) = server.recv_from(&mut buffer).unwrap();
            let good = answer(&buffer[..len]);
            let rogue = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut forged = good.clone();
            *forged.last_mut().unwrap() = 99;
            rogue.send_to(&forged, peer).unwrap();
            let mut wrong = good.clone();
            wrong[13] ^= 1;
            server.send_to(&wrong, peer).unwrap();
            server.send_to(&good, peer).unwrap();
        });
        let sent = query_wire();
        let reply = exchange(addr, &sent, Duration::from_secs(2), false).unwrap();
        assert_eq!(reply, answer(&sent));
        worker.join().unwrap();
    }

    #[test]
    fn truncated_udp_retries_tcp_and_handles_fragmented_large_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let udp = UdpSocket::bind(addr).unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let worker = thread::spawn(move || {
            let mut buffer = [0; 512];
            let (len, peer) = udp.recv_from(&mut buffer).unwrap();
            let mut truncated = answer(&buffer[..len]);
            truncated[2] |= 2;
            truncated.truncate(len + 1); // Intentionally incomplete RR.
            udp.send_to(&truncated, peer).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let query = read_query(&mut stream);
            let mut reply = answer(&query);
            // A legal additional TXT RR puts the complete reply above 512B.
            reply[11] = 1;
            reply.extend_from_slice(&[0, 0, 16, 0, 1, 0, 0, 0, 1, 2, 0]);
            reply.extend_from_slice(&[0; 512]);
            let prefix = (reply.len() as u16).to_be_bytes();
            stream.write_all(&prefix[..1]).unwrap();
            thread::sleep(Duration::from_millis(5));
            stream.write_all(&prefix[1..]).unwrap();
            for chunk in reply.chunks(7) { stream.write_all(chunk).unwrap(); }
        });
        let reply = exchange(addr, &query_wire(), Duration::from_secs(2), false).unwrap();
        assert!(reply.len() > 512);
        assert_eq!(DnsMessage::decode(&reply).unwrap().answers[0].as_ipv4(),
            Some(Ipv4Addr::new(192, 0, 2, 7)));
        worker.join().unwrap();
    }

    #[test]
    fn use_vc_uses_tcp_without_udp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let sent = read_query(&mut stream);
            let reply = answer(&sent);
            stream.write_all(&(reply.len() as u16).to_be_bytes()).unwrap();
            stream.write_all(&reply).unwrap();
        });
        assert!(exchange(addr, &query_wire(), Duration::from_secs(2), true).is_ok());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_short_frame_is_an_error_not_partial_success() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_query(&mut stream);
            stream.write_all(&[0, 30, 1, 2, 3]).unwrap();
        });
        assert!(matches!(exchange(addr, &query_wire(), Duration::from_secs(2), true),
            Err(QueryError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof));
        worker.join().unwrap();
    }

    #[test]
    fn zero_timeout_cannot_become_an_infinite_socket_wait() {
        let addr = "127.0.0.1:53".parse().unwrap();
        for use_vc in [false, true] {
            assert!(matches!(exchange(addr, &query_wire(), Duration::ZERO, use_vc),
                Err(QueryError::Io(error)) if error.kind() == io::ErrorKind::TimedOut));
        }
    }

    #[test]
    fn wrong_packets_cannot_extend_query_deadline() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let addr = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut buffer = [0; 512];
            let (len, peer) = server.recv_from(&mut buffer).unwrap();
            let mut wrong = answer(&buffer[..len]);
            wrong[0] ^= 1;
            for _ in 0..80 {
                let _ = server.send_to(&wrong, peer);
                thread::sleep(Duration::from_millis(5));
            }
        });
        let start = Instant::now();
        assert!(matches!(exchange(addr, &query_wire(), Duration::from_millis(80), false),
            Err(QueryError::Io(error)) if error.kind() == io::ErrorKind::TimedOut));
        assert!(start.elapsed() < Duration::from_secs(2));
        worker.join().unwrap();
    }

    fn address_reply() -> QueryReply {
        QueryReply { records: DnsMessage::decode(&answer(&query_wire())).unwrap().answers, rcode: 0 }
    }

    #[test]
    fn negative_family_is_not_retried_while_other_family_recovers() {
        let mut config = ResolverConfig::default();
        config.nameservers.push("127.0.0.2".parse().unwrap());
        config.attempts = 3;
        let mut calls = Vec::new();
        let mut a_attempts = 0;
        let result = resolve_with(b"example.test.", true, true, &config,
            |_, kind, server, _, _, _| {
                calls.push((kind, server));
                if kind == qtype::AAAA { return Ok(QueryReply { records: vec![], rcode: 0 }); }
                a_attempts += 1;
                if a_attempts == 1 { Err(QueryError::ResponseCode(rcode::SERVFAIL)) }
                else { Ok(address_reply()) }
            }).unwrap();
        assert_eq!(result.ipv4, vec![Ipv4Addr::new(192, 0, 2, 7)]);
        assert_eq!(calls.iter().filter(|(kind, _)| *kind == qtype::AAAA).count(), 1);
        assert_eq!(calls.len(), 3);
    }

    #[test]
    fn nxdomain_advances_search_and_success_stops_it() {
        let mut config = ResolverConfig::default();
        config.search = vec!["missing.test".to_owned(), "found.test".to_owned()];
        config.attempts = 4;
        let mut calls = Vec::new();
        let result = resolve_with(b"host", true, false, &config,
            |name, _, _, _, _, _| {
                calls.push(name.to_vec());
                if name.ends_with(b"missing.test") {
                    Ok(QueryReply { records: vec![], rcode: rcode::NXDOMAIN })
                } else { Ok(address_reply()) }
            }).unwrap();
        assert_eq!(result.ipv4.len(), 1);
        assert_eq!(calls, vec![b"host.missing.test".to_vec(), b"host.found.test".to_vec()]);
    }

    #[test]
    fn temporary_failure_is_not_reported_as_name_not_found() {
        let config = ResolverConfig::default();
        let result = resolve_with(b"example.test.", true, false, &config,
            |_, _, _, _, _, _| Err(QueryError::ResponseCode(rcode::SERVFAIL)));
        assert_eq!(result.unwrap_err(), ResolveError::Temporary);
        let result = resolve_with(b"example.test.", true, false, &config,
            |_, _, _, _, _, _| Ok(QueryReply { records: vec![], rcode: rcode::NXDOMAIN }));
        assert_eq!(result.unwrap_err(), ResolveError::NotFound);
    }

    #[test]
    fn transport_options_are_forwarded_to_each_attempt() {
        let mut config = ResolverConfig::default();
        config.use_vc = true;
        config.trust_ad = true;
        config.timeout = 7;
        let result = resolve_with(b"example.test.", true, false, &config,
            |_, _, _, timeout, trust_ad, use_vc| {
                assert_eq!(timeout, Duration::from_secs(7));
                assert!(trust_ad && use_vc);
                Ok(address_reply())
            });
        assert!(result.is_ok());
    }
}
