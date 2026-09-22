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
    build_search_names, qclass, qtype, rcode,
};
use crate::resolv::dns_name::{NS_MAXCDNAME, name_unpack};

/// DNS-over-TCP's unsigned 16-bit message length, excluding the length prefix.
const MAX_MESSAGE: usize = u16::MAX as usize;
const MAX_CNAME_HOPS: usize = 16;
type WireName = [u8; NS_MAXCDNAME];
static NEXT_SERVER: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
pub enum QueryError {
    Io(io::Error),
    InvalidQuery,
    InvalidResponse,
    ResponseCode(u8),
    /// A validated UDP SERVFAIL/NOTIMP/REFUSED asks the resolver to try
    /// another nameserver. Keep it distinct from a terminal TCP response.
    RetryableResponse(u8),
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
/// A/AAAA RDATA contains address bytes. PTR RDATA contains an uncompressed
/// wire name: message-relative pointers are expanded while the packet is
/// available, never interpreted relative to the copied RDATA buffer.
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
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "DNS TCP write stopped",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn tcp_read_exact(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short DNS TCP frame",
                ));
            }
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn tcp_exchange(
    server: SocketAddr,
    query: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, QueryError> {
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
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(QueryError::InvalidQuery)?;
    exchange_until(server, query, deadline, use_vc)
}

fn exchange_until(
    server: SocketAddr,
    query: &[u8],
    deadline: Instant,
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
        let code = DnsHeader::decode(reply)
            .ok_or(QueryError::InvalidResponse)?
            .rcode();
        if matches!(code, rcode::SERVFAIL | rcode::NOTIMP | rcode::REFUSED) {
            // A server rejection is not a timeout or a parse failure. Validate
            // all declared sections before allowing it to affect retry policy.
            DnsMessage::decode(reply).ok_or(QueryError::InvalidResponse)?;
            return Err(QueryError::RetryableResponse(code));
        }
        packet.truncate(received);
        return Ok(packet);
    }
}

struct AddressRecord {
    owner: WireName,
    target: Option<WireName>,
    record: DnsRecord,
}

enum AddressAnswer {
    Complete(QueryReply),
    Follow(WireName),
}

/// Return only address/PTR records owned by the queried name or its validated CNAME
/// chain. Keep names in wire form for identity checks; the generic decoder's
/// unescaped dotted names are display data, not a safe comparison key.
fn address_answer(
    sent: &[u8],
    packet: &[u8],
    record_type: u16,
    visited: &mut Vec<WireName>,
    ttl_limit: &mut u32,
) -> Result<AddressAnswer, QueryError> {
    if !response_matches(sent, packet) {
        return Err(QueryError::InvalidResponse);
    }
    let message = DnsMessage::decode(packet).ok_or(QueryError::InvalidResponse)?;
    if message.header.is_truncated() {
        return Err(QueryError::InvalidResponse);
    }
    match message.header.rcode() {
        rcode::NOERROR => {}
        rcode::NXDOMAIN => {
            return Ok(AddressAnswer::Complete(QueryReply {
                records: Vec::new(),
                rcode: rcode::NXDOMAIN,
            }));
        }
        code => return Err(QueryError::ResponseCode(code)),
    }
    let (mut owner, _) = question(sent).ok_or(QueryError::InvalidQuery)?;
    let mut scratch = [0; NS_MAXCDNAME];
    let question_len = name_unpack(packet, DNS_HEADER_SIZE, &mut scratch)
        .map_err(|_| QueryError::InvalidResponse)?;
    let mut pos = DNS_HEADER_SIZE + question_len + 4;
    let mut records = Vec::new();
    for mut record in message.answers {
        let mut name = [0; NS_MAXCDNAME];
        let name_len =
            name_unpack(packet, pos, &mut name).map_err(|_| QueryError::InvalidResponse)?;
        let data_start = pos + name_len + 10;
        // DnsMessage::decode has already checked the complete RR span. Use
        // the original packet offset, not the copied compressed RDATA, when
        // expanding CNAME targets. Compression offsets are message-relative.
        pos = data_start + record.rdata.len();
        if record.rclass != qclass::IN {
            continue;
        }
        let target = match record.rtype {
            qtype::CNAME => {
                let mut target = [0; NS_MAXCDNAME];
                let consumed = name_unpack(packet, data_start, &mut target)
                    .map_err(|_| QueryError::InvalidResponse)?;
                // An expanded target can be longer than RDLENGTH, but bytes
                // consumed in THIS RR must match it exactly. A missing root
                // must not be borrowed from the next record.
                if consumed != record.rdata.len() {
                    return Err(QueryError::InvalidResponse);
                }
                Some(target)
            }
            qtype::PTR if record_type == qtype::PTR => {
                let mut target = [0; NS_MAXCDNAME];
                let consumed = name_unpack(packet, data_start, &mut target)
                    .map_err(|_| QueryError::InvalidResponse)?;
                if consumed != record.rdata.len() {
                    return Err(QueryError::InvalidResponse);
                }
                // The unpacker validated label lengths and the 255-byte
                // expanded-name budget. Preserve the label boundaries.
                let mut end = 0;
                while target[end] != 0 {
                    end += usize::from(target[end]) + 1;
                }
                record.rdata = target[..=end].to_vec();
                None
            }
            qtype::A if record.rdata.len() == 4 => None,
            qtype::AAAA if record.rdata.len() == 16 => None,
            qtype::A | qtype::AAAA => return Err(QueryError::InvalidResponse),
            _ => continue,
        };
        records.push(AddressRecord {
            owner: name,
            target,
            record,
        });
    }

    let mut followed = false;
    loop {
        let mut target: Option<WireName> = None;
        let mut alias_ttl = u32::MAX;
        let mut addresses = Vec::new();
        let mut has_address = false;
        for entry in &records {
            if !owner.eq_ignore_ascii_case(&entry.owner) {
                continue;
            }
            if let Some(next) = entry.target {
                if target.is_some_and(|previous| !previous.eq_ignore_ascii_case(&next)) {
                    return Err(QueryError::InvalidResponse);
                }
                target = Some(next);
                alias_ttl = alias_ttl.min(entry.record.ttl);
            } else {
                has_address = true;
                if entry.record.rtype == record_type {
                    let mut record = entry.record.clone();
                    record.ttl = record.ttl.min(*ttl_limit);
                    addresses.push(record);
                }
            }
        }
        if let Some(next) = target {
            // A CNAME owner cannot simultaneously own address records, or
            // point at two different targets (RFC 2181 section 10.1).
            if has_address
                || visited.len() > MAX_CNAME_HOPS
                || visited.iter().any(|name| name.eq_ignore_ascii_case(&next))
            {
                return Err(QueryError::InvalidResponse);
            }
            visited.push(next);
            *ttl_limit = (*ttl_limit).min(alias_ttl);
            owner = next;
            followed = true;
        } else if !addresses.is_empty() || !followed {
            return Ok(AddressAnswer::Complete(QueryReply {
                records: addresses,
                rcode: rcode::NOERROR,
            }));
        } else {
            return Ok(AddressAnswer::Follow(owner));
        }
    }
}

/// Query addresses or PTR names at a server, following at most 16 CNAME links
/// across packets under one deadline. No host resolver call-through is used.
/// Linux's entropy device supplies IDs; clock/hash fallback is forbidden.
pub fn query(
    hostname: &[u8],
    record_type: u16,
    server: SocketAddr,
    timeout: Duration,
    trust_ad: bool,
    use_vc: bool,
) -> Result<QueryReply, QueryError> {
    query_with_exchange(
        hostname,
        record_type,
        timeout,
        trust_ad,
        |wire, deadline| exchange_until(server, wire, deadline, use_vc),
    )
}

fn query_with_exchange<F>(
    hostname: &[u8],
    record_type: u16,
    timeout: Duration,
    trust_ad: bool,
    mut exchange: F,
) -> Result<QueryReply, QueryError>
where
    F: FnMut(&[u8], Instant) -> Result<Vec<u8>, QueryError>,
{
    if !matches!(record_type, qtype::A | qtype::AAAA | qtype::PTR) {
        return Err(QueryError::InvalidQuery);
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(QueryError::InvalidQuery)?;
    remaining(deadline)?;
    let mut message = DnsMessage::new_query_with_trust_ad(0, hostname, record_type, trust_ad)
        .ok_or(QueryError::InvalidQuery)?;
    let mut initial = [0; NS_MAXCDNAME];
    initial[..message.questions[0].qname.len()].copy_from_slice(&message.questions[0].qname);
    let mut visited = vec![initial];
    let mut ttl_limit = u32::MAX;
    let mut random = File::open("/dev/urandom")?;
    loop {
        remaining(deadline)?;
        let mut entropy = [0; 2];
        random.read_exact(&mut entropy)?;
        message.header.id = u16::from_ne_bytes(entropy);
        let mut wire = [0; DNS_MAX_UDP_SIZE];
        let length = message.encode(&mut wire).ok_or(QueryError::InvalidQuery)?;
        let sent = &wire[..length];
        let packet = exchange(sent, deadline)?;
        match address_answer(sent, &packet, record_type, &mut visited, &mut ttl_limit)? {
            AddressAnswer::Complete(reply) => return Ok(reply),
            AddressAnswer::Follow(next) => {
                // Already validated, uncompressed wire name. Re-encode without
                // a presentation round trip so embedded dots/NULs retain their
                // label identity. CNAME targets are absolute, never searched.
                let mut end = 0;
                while next[end] != 0 {
                    end += usize::from(next[end]) + 1;
                }
                message.questions[0].qname = next[..=end].to_vec();
            }
        }
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
    } else {
        0
    };
    let timeout = Duration::from_secs(u64::from(config.timeout.max(1)));
    let mut saw_temporary = false;
    let mut saw_failure = false;
    for name in build_search_names(hostname, &config.search, config.ndots) {
        let mut result = DnsResolution::default();
        let mut done = [!want_v4, !want_v6];
        let mut failures = [None, None];
        for _ in 0..config.attempts.max(1) {
            for offset in 0..config.nameservers.len() {
                let server = SocketAddr::new(
                    config.nameservers[(start + offset) % config.nameservers.len()],
                    DNS_PORT,
                );
                for (index, record_type) in [qtype::A, qtype::AAAA].into_iter().enumerate() {
                    if done[index] {
                        continue;
                    }
                    match query(
                        &name,
                        record_type,
                        server,
                        timeout,
                        config.trust_ad,
                        config.use_vc,
                    ) {
                        Ok(reply) => {
                            done[index] = true;
                            failures[index] = None;
                            if reply.rcode == rcode::NOERROR {
                                for record in reply.records {
                                    if index == 0 {
                                        if let Some(address) = record.as_ipv4()
                                            && !result.ipv4.contains(&address)
                                        {
                                            result.ipv4.push(address);
                                        }
                                    } else if let Some(address) = record.as_ipv6()
                                        && !result.ipv6.contains(&address)
                                    {
                                        result.ipv6.push(address);
                                    }
                                }
                            }
                        }
                        Err(QueryError::Io(_) | QueryError::RetryableResponse(_)) => {
                            failures[index] = Some(ResolveError::Temporary);
                        }
                        Err(QueryError::ResponseCode(_)) => {
                            // The transport already separated retryable UDP
                            // errors. A terminal DNS failure is a negative
                            // lookup, not an invalid/malformed-response error.
                            done[index] = true;
                            failures[index] = None;
                        }
                        Err(_) => {
                            failures[index].get_or_insert(ResolveError::Failure);
                        }
                    }
                }
                if done.iter().all(|&value| value) {
                    break;
                }
            }
            if done.iter().all(|&value| value) {
                break;
            }
        }
        if !result.ipv4.is_empty() || !result.ipv6.is_empty() {
            return Ok(result);
        }
        // A successful definitive reply supersedes errors from earlier
        // attempts of that family. Only unresolved failures affect the result.
        saw_temporary |= failures.contains(&Some(ResolveError::Temporary));
        saw_failure |= failures.contains(&Some(ResolveError::Failure));
    }
    if saw_temporary {
        Err(ResolveError::Temporary)
    } else if saw_failure {
        Err(ResolveError::Failure)
    } else {
        Err(ResolveError::NotFound)
    }
}

/// Absolute reverse-lookup owner. IPv4-mapped IPv6 addresses use IN-ADDR.ARPA,
/// while native IPv6 addresses use all 32 reversed nibbles in IP6.ARPA.
pub fn reverse_name(address: IpAddr) -> Vec<u8> {
    let address = match address {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
        _ => address,
    };
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa.").into_bytes()
        }
        IpAddr::V6(ip) => {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut name = Vec::with_capacity(73);
            for byte in ip.octets().into_iter().rev() {
                name.extend_from_slice(&[
                    HEX[usize::from(byte & 15)],
                    b'.',
                    HEX[usize::from(byte >> 4)],
                    b'.',
                ]);
            }
            name.extend_from_slice(b"ip6.arpa.");
            name
        }
    }
}

/// Convert a normalized PTR wire name to an application hostname. DNS labels
/// allow binary data; hostnames do not. Validate bytes before presentation
/// conversion so an embedded dot or NUL cannot masquerade as a label boundary.
/// The root is the valid presentation ".". A leading hyphen is rejected at the
/// beginning of the name; later labels may begin with one, as in glibc res_hnok.
fn ptr_hostname(wire: &[u8]) -> Option<Vec<u8>> {
    if wire.len() > NS_MAXCDNAME {
        return None;
    }
    let mut pos = 0usize;
    let mut output = Vec::new();
    loop {
        let length = usize::from(*wire.get(pos)?);
        pos += 1;
        if length == 0 {
            if pos != wire.len() {
                return None;
            }
            if output.is_empty() {
                output.push(b'.');
            }
            return Some(output);
        }
        if length > 63 {
            return None;
        }
        let label = wire.get(pos..pos.checked_add(length)?)?;
        if (output.is_empty() && label[0] == b'-')
            || !label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
        {
            return None;
        }
        if !output.is_empty() {
            output.push(b'.');
        }
        output.extend_from_slice(label);
        pos += length;
    }
}

/// Resolve a PTR name without applying search domains. Reuse the same
/// query-bound UDP/TCP/CNAME engine as forward lookup and keep ABI evidence
/// accounting in the supplied query callback. A definitive negative reply
/// supersedes errors from earlier servers; exhausted transient failures do
/// not become a false successful numeric/name answer.
pub fn reverse_with<F>(
    address: IpAddr,
    config: &ResolverConfig,
    mut query: F,
) -> Result<Vec<u8>, ResolveError>
where
    F: FnMut(&[u8], u16, SocketAddr, Duration, bool, bool) -> Result<QueryReply, QueryError>,
{
    if config.nameservers.is_empty() {
        return Err(ResolveError::Temporary);
    }
    let name = reverse_name(address);
    let start = if config.rotate {
        NEXT_SERVER.fetch_add(1, Ordering::Relaxed) % config.nameservers.len()
    } else {
        0
    };
    let timeout = Duration::from_secs(u64::from(config.timeout.max(1)));
    let mut temporary = false;
    for _ in 0..config.attempts.max(1) {
        for offset in 0..config.nameservers.len() {
            let server = SocketAddr::new(
                config.nameservers[(start + offset) % config.nameservers.len()],
                DNS_PORT,
            );
            match query(
                &name,
                qtype::PTR,
                server,
                timeout,
                config.trust_ad,
                config.use_vc,
            ) {
                Ok(reply) if reply.rcode == rcode::NXDOMAIN => return Err(ResolveError::NotFound),
                Ok(reply) if reply.rcode == rcode::NOERROR => {
                    for record in reply.records {
                        if record.rtype != qtype::PTR || record.rclass != qclass::IN {
                            continue;
                        }
                        // The first owner-bound IN/PTR is authoritative for
                        // this result. Do not salvage an invalid first target
                        // by accepting a later one: glibc reports no name.
                        return ptr_hostname(&record.rdata).ok_or(ResolveError::NotFound);
                    }
                    return Err(ResolveError::NotFound);
                }
                Err(QueryError::Io(_) | QueryError::RetryableResponse(_))
                | Err(QueryError::ResponseCode(rcode::SERVFAIL)) => {
                    temporary = true;
                }
                _ => {}
            }
        }
    }
    Err(if temporary {
        ResolveError::Temporary
    } else {
        ResolveError::Failure
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn ptr_hostname_accepts_root_and_glibc_hostname_syntax() {
        for host in [
            b".".as_slice(),
            b"_service.Host-.test",
            b"host.-part.test",
            b"123.test",
        ] {
            assert_eq!(ptr_hostname(&name(host)), Some(host.to_vec()));
        }
    }

    #[test]
    fn ptr_hostname_rejects_binary_labels_and_malformed_wire_names() {
        for host in [
            br"server\.test".as_slice(),
            br"server\000.test",
            b"server test",
            b"-host.test",
        ] {
            assert_eq!(ptr_hostname(&name(host)), None, "{host:?}");
        }
        for wire in [
            vec![],
            vec![1, b'a'],
            vec![0, 0],
            vec![64; 66],
            vec![0xc0, 0],
        ] {
            assert_eq!(ptr_hostname(&wire), None);
        }
        let mut longest = Vec::new();
        for length in [63, 63, 63, 61] {
            longest.push(length);
            longest.extend(std::iter::repeat_n(b'a', usize::from(length)));
        }
        longest.push(0);
        assert_eq!(longest.len(), NS_MAXCDNAME);
        assert_eq!(ptr_hostname(&longest).unwrap().len(), 253);
        longest.insert(longest.len() - 1, b'a');
        assert_eq!(ptr_hostname(&longest), None);
    }

    #[test]
    fn reverse_ptr_root_and_first_target_policy_use_real_decoder() {
        let config = ResolverConfig::default();
        for (targets, expected) in [
            (vec![b".".as_slice()], Ok(b".".to_vec())),
            (
                vec![br"bad\.test".as_slice(), b"valid.test"],
                Err(ResolveError::NotFound),
            ),
            (
                vec![b"valid.test".as_slice(), br"bad\.test"],
                Ok(b"valid.test".to_vec()),
            ),
        ] {
            let mut calls = 0;
            let result = reverse_with(
                "192.0.2.230".parse().unwrap(),
                &config,
                |owner, kind, _, _, _, _| {
                    calls += 1;
                    query_with_exchange(owner, kind, Duration::from_secs(1), false, |sent, _| {
                        let records: Vec<_> = targets
                            .iter()
                            .map(|target| rr(&[0xc0, 12], qtype::PTR, 1, 60, &name(target)))
                            .collect();
                        Ok(response_with_records(sent, &records))
                    })
                },
            );
            assert_eq!(result, expected);
            assert_eq!(
                calls, 1,
                "a definitive target must not cause retry amplification"
            );
        }
    }

    #[test]
    fn reverse_owners_are_absolute_and_preserve_all_ipv6_nibbles() {
        assert_eq!(
            reverse_name("192.0.2.9".parse().unwrap()),
            b"9.2.0.192.in-addr.arpa."
        );
        assert_eq!(
            reverse_name("::ffff:192.0.2.9".parse().unwrap()),
            b"9.2.0.192.in-addr.arpa."
        );
        assert_eq!(
            reverse_name("2001:db8::9".parse().unwrap()),
            b"9.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
    }

    #[test]
    fn ptr_decoding_binds_owner_class_and_expands_compressed_rdata() {
        let reply = query_with_exchange(
            b"example.test",
            qtype::PTR,
            Duration::from_secs(2),
            false,
            |sent, _| {
                Ok(response_with_records(
                    sent,
                    &[
                        rr(
                            &name(b"foreign.test"),
                            qtype::PTR,
                            1,
                            60,
                            &name(b"bad.test"),
                        ),
                        rr(&[0xc0, 12], qtype::PTR, 3, 60, &name(b"wrong-class.test")),
                        rr(&[0xc0, 12], qtype::PTR, 1, 60, b"\x04edge\xc0\x14"),
                    ],
                ))
            },
        )
        .unwrap();
        assert_eq!(reply.records.len(), 1);
        assert_eq!(reply.records[0].rdata, name(b"edge.test"));
    }

    #[test]
    fn ptr_follows_cross_packet_cname_under_one_deadline() {
        let mut calls = 0;
        let mut budget = None;
        let reply = query_with_exchange(
            b"9.2.0.192.in-addr.arpa.",
            qtype::PTR,
            Duration::from_secs(2),
            false,
            |sent, deadline| {
                if let Some(first) = budget {
                    assert_eq!(first, deadline);
                }
                budget = Some(deadline);
                calls += 1;
                let record = if calls == 1 {
                    rr(&[0xc0, 12], qtype::CNAME, 1, 7, &name(b"delegated.test"))
                } else {
                    let message = DnsMessage::decode(sent).unwrap();
                    assert_eq!(message.questions[0].qname, b"delegated.test");
                    assert_eq!(message.questions[0].qtype, qtype::PTR);
                    rr(&[0xc0, 12], qtype::PTR, 1, 60, &name(b"host.test"))
                };
                Ok(response_with_records(sent, &[record]))
            },
        )
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(reply.records[0].rdata, name(b"host.test"));
        assert_eq!(reply.records[0].ttl, 7);
    }

    #[test]
    fn ptr_rejects_rdata_spilling_into_the_next_record() {
        for target in [vec![0xc0], vec![0xc0, 12, 0], vec![1, b'x']] {
            let result = query_with_exchange(
                b"example.test",
                qtype::PTR,
                Duration::from_secs(2),
                false,
                |sent, _| {
                    Ok(response_with_records(
                        sent,
                        &[
                            rr(&[0xc0, 12], qtype::PTR, 1, 60, &target),
                            rr(&[0], qtype::A, 1, 60, &[192, 0, 2, 9]),
                        ],
                    ))
                },
            );
            assert!(matches!(result, Err(QueryError::InvalidResponse)));
        }
    }

    #[test]
    fn ptr_alias_cycles_and_conflicting_data_are_not_names() {
        for kind in [qtype::CNAME, qtype::PTR] {
            let result = query_with_exchange(
                b"example.test",
                qtype::PTR,
                Duration::from_secs(2),
                false,
                |sent, _| {
                    Ok(response_with_records(
                        sent,
                        &[
                            rr(&[0xc0, 12], qtype::CNAME, 1, 60, &[0xc0, 12]),
                            rr(&[0xc0, 12], kind, 1, 60, &name(b"host.test")),
                        ],
                    ))
                },
            );
            assert!(matches!(result, Err(QueryError::InvalidResponse)));
        }
    }

    #[test]
    fn reverse_retry_preserves_options_without_search_suffixes() {
        let mut config = ResolverConfig::default();
        config.search = vec!["must-not-be-queried.test".to_owned()];
        config.attempts = 2;
        config.use_vc = true;
        config.trust_ad = true;
        let mut calls = 0;
        let result = reverse_with(
            "192.0.2.9".parse().unwrap(),
            &config,
            |owner, kind, _, _, trust_ad, use_vc| {
                assert_eq!(owner, b"9.2.0.192.in-addr.arpa.");
                assert_eq!(kind, qtype::PTR);
                assert!(trust_ad && use_vc);
                calls += 1;
                if calls == 1 {
                    return Err(QueryError::RetryableResponse(rcode::REFUSED));
                }
                Ok(QueryReply {
                    records: vec![],
                    rcode: rcode::NXDOMAIN,
                })
            },
        );
        assert_eq!(calls, 2);
        assert_eq!(result.unwrap_err(), ResolveError::NotFound);
    }

    #[test]
    fn reverse_distinguishes_missing_temporary_and_invalid_replies() {
        let config = ResolverConfig::default();
        let ip = "192.0.2.9".parse().unwrap();
        assert_eq!(
            reverse_with(ip, &config, |_, _, _, _, _, _| Err(
                QueryError::RetryableResponse(rcode::REFUSED)
            ))
            .unwrap_err(),
            ResolveError::Temporary
        );
        assert_eq!(
            reverse_with(ip, &config, |_, _, _, _, _, _| Err(
                QueryError::InvalidResponse
            ))
            .unwrap_err(),
            ResolveError::Failure
        );
        assert_eq!(
            reverse_with(ip, &config, |_, _, _, _, _, _| Ok(QueryReply {
                records: vec![],
                rcode: rcode::NOERROR
            }))
            .unwrap_err(),
            ResolveError::NotFound
        );
    }

    #[test]
    fn udp_rejections_are_retryable_but_tcp_response_codes_remain_explicit() {
        for code in [rcode::SERVFAIL, rcode::NOTIMP, rcode::REFUSED] {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let address = socket.local_addr().unwrap();
            let worker = thread::spawn(move || {
                let mut buffer = [0; 512];
                let (len, peer) = socket.recv_from(&mut buffer).unwrap();
                let mut reply = response_with_records(&buffer[..len], &[]);
                reply[3] |= code;
                socket.send_to(&reply, peer).unwrap();
            });
            let result = query(
                b"example.test",
                qtype::A,
                address,
                Duration::from_secs(2),
                false,
                false,
            );
            assert!(matches!(result, Err(QueryError::RetryableResponse(value)) if value == code));
            worker.join().unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let sent = read_query(&mut stream);
            let mut reply = response_with_records(&sent, &[]);
            reply[3] |= rcode::REFUSED;
            stream
                .write_all(&(reply.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&reply).unwrap();
        });
        let result = query(
            b"example.test",
            qtype::A,
            address,
            Duration::from_secs(2),
            false,
            true,
        );
        assert!(matches!(
            result,
            Err(QueryError::ResponseCode(rcode::REFUSED))
        ));
        worker.join().unwrap();
    }

    #[test]
    fn forward_retryable_and_terminal_dns_codes_are_not_conflated() {
        let config = ResolverConfig::default();
        for code in [rcode::SERVFAIL, rcode::NOTIMP, rcode::REFUSED] {
            let temporary = resolve_with(
                b"example.test.",
                true,
                false,
                &config,
                |_, _, _, _, _, _| Err(QueryError::RetryableResponse(code)),
            );
            assert_eq!(temporary.unwrap_err(), ResolveError::Temporary);
            let terminal = resolve_with(
                b"example.test.",
                true,
                false,
                &config,
                |_, _, _, _, _, _| Err(QueryError::ResponseCode(code)),
            );
            assert_eq!(terminal.unwrap_err(), ResolveError::NotFound);
        }
    }

    fn query_wire() -> Vec<u8> {
        let mut bytes = vec![0; DNS_MAX_UDP_SIZE];
        let length = DnsMessage::new_query(0x1234, b"example.test", qtype::A)
            .unwrap()
            .encode(&mut bytes)
            .unwrap();
        bytes.truncate(length);
        bytes
    }

    fn answer(query: &[u8]) -> Vec<u8> {
        let mut bytes = query.to_vec();
        bytes[2] |= 0x80;
        bytes[3] = 0x80;
        bytes[7] = 1;
        bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
        bytes
    }

    fn read_query(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
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
        for (index, mask) in [
            (0, 1),
            (2, 8),
            (5, 1),
            (13, 1),
            (sent.len() - 1, 1),
            (sent.len() - 3, 1),
        ] {
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
            .unwrap()
            .encode(&mut dotted)
            .unwrap();
        dotted.truncate(len);
        assert!(!response_matches(&sent, &answer(&dotted)));
    }

    #[test]
    fn udp_ignores_wrong_source_and_wrong_question_before_valid_reply() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
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
            for chunk in reply.chunks(7) {
                stream.write_all(chunk).unwrap();
            }
        });
        let reply = exchange(addr, &query_wire(), Duration::from_secs(2), false).unwrap();
        assert!(reply.len() > 512);
        assert_eq!(
            DnsMessage::decode(&reply).unwrap().answers[0].as_ipv4(),
            Some(Ipv4Addr::new(192, 0, 2, 7))
        );
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
            stream
                .write_all(&(reply.len() as u16).to_be_bytes())
                .unwrap();
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
        assert!(
            matches!(exchange(addr, &query_wire(), Duration::from_secs(2), true),
            Err(QueryError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof)
        );
        worker.join().unwrap();
    }

    #[test]
    fn zero_timeout_cannot_become_an_infinite_socket_wait() {
        let addr = "127.0.0.1:53".parse().unwrap();
        for use_vc in [false, true] {
            assert!(
                matches!(exchange(addr, &query_wire(), Duration::ZERO, use_vc),
                Err(QueryError::Io(error)) if error.kind() == io::ErrorKind::TimedOut)
            );
        }
    }

    #[test]
    fn wrong_packets_cannot_extend_query_deadline() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
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
        assert!(
            matches!(exchange(addr, &query_wire(), Duration::from_millis(80), false),
            Err(QueryError::Io(error)) if error.kind() == io::ErrorKind::TimedOut)
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        worker.join().unwrap();
    }

    fn address_reply() -> QueryReply {
        QueryReply {
            records: DnsMessage::decode(&answer(&query_wire())).unwrap().answers,
            rcode: 0,
        }
    }

    #[test]
    fn negative_family_is_not_retried_while_other_family_recovers() {
        let mut config = ResolverConfig::default();
        config.nameservers.push("127.0.0.2".parse().unwrap());
        config.attempts = 3;
        let mut calls = Vec::new();
        let mut a_attempts = 0;
        let result = resolve_with(
            b"example.test.",
            true,
            true,
            &config,
            |_, kind, server, _, _, _| {
                calls.push((kind, server));
                if kind == qtype::AAAA {
                    return Ok(QueryReply {
                        records: vec![],
                        rcode: 0,
                    });
                }
                a_attempts += 1;
                if a_attempts == 1 {
                    Err(QueryError::RetryableResponse(rcode::SERVFAIL))
                } else {
                    Ok(address_reply())
                }
            },
        )
        .unwrap();
        assert_eq!(result.ipv4, vec![Ipv4Addr::new(192, 0, 2, 7)]);
        assert_eq!(
            calls
                .iter()
                .filter(|(kind, _)| *kind == qtype::AAAA)
                .count(),
            1
        );
        assert_eq!(calls.len(), 3);
    }

    #[test]
    fn nxdomain_advances_search_and_success_stops_it() {
        let mut config = ResolverConfig::default();
        config.search = vec!["missing.test".to_owned(), "found.test".to_owned()];
        config.attempts = 4;
        let mut calls = Vec::new();
        let result = resolve_with(b"host", true, false, &config, |name, _, _, _, _, _| {
            calls.push(name.to_vec());
            if name.ends_with(b"missing.test") {
                Ok(QueryReply {
                    records: vec![],
                    rcode: rcode::NXDOMAIN,
                })
            } else {
                Ok(address_reply())
            }
        })
        .unwrap();
        assert_eq!(result.ipv4.len(), 1);
        assert_eq!(
            calls,
            vec![b"host.missing.test".to_vec(), b"host.found.test".to_vec()]
        );
    }

    #[test]
    fn temporary_failure_is_not_reported_as_name_not_found() {
        let config = ResolverConfig::default();
        let result = resolve_with(
            b"example.test.",
            true,
            false,
            &config,
            |_, _, _, _, _, _| Err(QueryError::RetryableResponse(rcode::SERVFAIL)),
        );
        assert_eq!(result.unwrap_err(), ResolveError::Temporary);
        let result = resolve_with(
            b"example.test.",
            true,
            false,
            &config,
            |_, _, _, _, _, _| {
                Ok(QueryReply {
                    records: vec![],
                    rcode: rcode::NXDOMAIN,
                })
            },
        );
        assert_eq!(result.unwrap_err(), ResolveError::NotFound);
    }

    #[test]
    fn transport_options_are_forwarded_to_each_attempt() {
        let mut config = ResolverConfig::default();
        config.use_vc = true;
        config.trust_ad = true;
        config.timeout = 7;
        let result = resolve_with(
            b"example.test.",
            true,
            false,
            &config,
            |_, _, _, timeout, trust_ad, use_vc| {
                assert_eq!(timeout, Duration::from_secs(7));
                assert!(trust_ad && use_vc);
                Ok(address_reply())
            },
        );
        assert!(result.is_ok());
    }

    fn response_with_records(sent: &[u8], records: &[Vec<u8>]) -> Vec<u8> {
        let mut packet = sent.to_vec();
        packet[2] |= 0x80;
        packet[3] = 0x80;
        packet[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        for record in records {
            packet.extend_from_slice(record);
        }
        packet
    }

    fn rr(owner: &[u8], kind: u16, class: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
        let mut bytes = owner.to_vec();
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&class.to_be_bytes());
        bytes.extend_from_slice(&ttl.to_be_bytes());
        bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(data);
        bytes
    }

    fn name(text: &[u8]) -> Vec<u8> {
        crate::resolv::dns::encode_domain_name(text).unwrap()
    }

    fn bound_answer(sent: &[u8], packet: &[u8]) -> Result<AddressAnswer, QueryError> {
        let (owner, fields) = question(sent).unwrap();
        address_answer(
            sent,
            packet,
            u16::from_be_bytes([fields[0], fields[1]]),
            &mut vec![owner],
            &mut u32::MAX,
        )
    }

    #[test]
    fn address_answer_excludes_unrelated_owner_class_and_family() {
        let sent = query_wire();
        let packet = response_with_records(
            &sent,
            &[
                rr(&name(b"foreign.test"), qtype::A, 1, 60, &[203, 0, 113, 99]),
                rr(&[0xc0, 12], qtype::A, 3, 60, &[203, 0, 113, 98]),
                rr(&[0xc0, 12], qtype::AAAA, 1, 60, &[0; 16]),
                rr(&[0xc0, 12], qtype::A, 1, 60, &[192, 0, 2, 7]),
            ],
        );
        let AddressAnswer::Complete(reply) = bound_answer(&sent, &packet).unwrap() else {
            panic!("direct address must complete");
        };
        assert_eq!(reply.records.len(), 1);
        assert_eq!(
            reply.records[0].as_ipv4(),
            Some(Ipv4Addr::new(192, 0, 2, 7))
        );
    }

    #[test]
    fn cname_chain_accepts_out_of_order_records_and_limits_ttl() {
        let sent = query_wire();
        // edge.test uses a compressed suffix pointer into example.test's
        // question: the four-byte "test" label begins at message offset 20.
        let edge = b"\x04edge\xc0\x14";
        let packet = response_with_records(
            &sent,
            &[
                rr(edge, qtype::A, 1, 600, &[192, 0, 2, 8]),
                rr(&name(b"middle.test"), qtype::CNAME, 1, 20, edge),
                rr(&[0xc0, 12], qtype::CNAME, 1, 40, &name(b"middle.test")),
                rr(&name(b"unrelated.test"), qtype::A, 1, 60, &[203, 0, 113, 7]),
            ],
        );
        let AddressAnswer::Complete(reply) = bound_answer(&sent, &packet).unwrap() else {
            panic!("in-packet chain must complete");
        };
        assert_eq!(reply.records.len(), 1);
        assert_eq!(
            reply.records[0].as_ipv4(),
            Some(Ipv4Addr::new(192, 0, 2, 8))
        );
        assert_eq!(reply.records[0].ttl, 20);
    }

    #[test]
    fn cname_targets_keep_label_identity() {
        let sent = query_wire();
        let literal_dot = name(br"edge\.test");
        let packet = response_with_records(
            &sent,
            &[
                rr(&[0xc0, 12], qtype::CNAME, 1, 60, &literal_dot),
                rr(&name(b"edge.test"), qtype::A, 1, 60, &[203, 0, 113, 7]),
                rr(&literal_dot, qtype::A, 1, 60, &[192, 0, 2, 8]),
            ],
        );
        let AddressAnswer::Complete(reply) = bound_answer(&sent, &packet).unwrap() else {
            panic!("literal-dot target must resolve");
        };
        assert_eq!(reply.records.len(), 1);
        assert_eq!(
            reply.records[0].as_ipv4(),
            Some(Ipv4Addr::new(192, 0, 2, 8))
        );
    }

    #[test]
    fn cname_rejects_cycles_conflicting_targets_and_address_coexistence() {
        let sent = query_wire();
        let edge = name(b"edge.test");
        let alias = rr(&[0xc0, 12], qtype::CNAME, 1, 60, &edge);
        for records in [
            vec![rr(&[0xc0, 12], qtype::CNAME, 1, 60, &[0xc0, 12])],
            vec![alias.clone(), rr(&edge, qtype::CNAME, 1, 60, &[0xc0, 12])],
            vec![
                alias.clone(),
                rr(&[0xc0, 12], qtype::CNAME, 1, 60, &name(b"other.test")),
            ],
            vec![alias, rr(&[0xc0, 12], qtype::A, 1, 60, &[192, 0, 2, 8])],
        ] {
            assert!(matches!(
                bound_answer(&sent, &response_with_records(&sent, &records)),
                Err(QueryError::InvalidResponse)
            ));
        }
    }

    #[test]
    fn cname_rdata_cannot_consume_a_name_outside_its_declared_span() {
        let sent = query_wire();
        for target in [vec![0xc0], vec![0xc0, 12, 0], vec![1, b'a']] {
            let packet = response_with_records(
                &sent,
                &[
                    rr(&[0xc0, 12], qtype::CNAME, 1, 60, &target),
                    // The following root byte must not terminate the previous RR.
                    rr(&[0], qtype::A, 1, 60, &[192, 0, 2, 8]),
                ],
            );
            assert!(matches!(
                bound_answer(&sent, &packet),
                Err(QueryError::InvalidResponse)
            ));
        }
    }

    #[test]
    fn cname_follows_across_packets_under_the_same_deadline() {
        let mut calls = 0;
        let mut first_deadline = None;
        let reply = query_with_exchange(
            b"example.test",
            qtype::A,
            Duration::from_secs(2),
            true,
            |sent, deadline| {
                calls += 1;
                assert_eq!(DnsHeader::decode(sent).unwrap().flags & 0x20, 0x20);
                if let Some(first) = first_deadline {
                    assert_eq!(deadline, first);
                } else {
                    first_deadline = Some(deadline);
                }
                if calls == 1 {
                    Ok(response_with_records(
                        sent,
                        &[rr(&[0xc0, 12], qtype::CNAME, 1, 9, &name(b"edge.test"))],
                    ))
                } else {
                    assert_eq!(
                        DnsMessage::decode(sent).unwrap().questions[0].qname,
                        b"edge.test"
                    );
                    Ok(answer(sent))
                }
            },
        )
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(
            reply.records[0].as_ipv4(),
            Some(Ipv4Addr::new(192, 0, 2, 7))
        );
        assert_eq!(reply.records[0].ttl, 9);
    }

    #[test]
    fn cname_cross_packet_loop_is_rejected_without_retry_explosion() {
        let mut calls = 0;
        let result = query_with_exchange(
            b"example.test",
            qtype::A,
            Duration::from_secs(2),
            false,
            |sent, _| {
                calls += 1;
                let next = if calls == 1 {
                    b"edge.test".as_slice()
                } else {
                    b"example.test".as_slice()
                };
                Ok(response_with_records(
                    sent,
                    &[rr(&[0xc0, 12], qtype::CNAME, 1, 60, &name(next))],
                ))
            },
        );
        assert!(matches!(result, Err(QueryError::InvalidResponse)));
        assert_eq!(calls, 2);
    }

    #[test]
    fn cname_hop_budget_applies_across_packets() {
        let mut calls = 0;
        let result = query_with_exchange(
            b"example.test",
            qtype::AAAA,
            Duration::from_secs(2),
            false,
            |sent, _| {
                calls += 1;
                let next = name(format!("hop{calls}.test").as_bytes());
                Ok(response_with_records(
                    sent,
                    &[rr(&[0xc0, 12], qtype::CNAME, 1, 60, &next)],
                ))
            },
        );
        assert!(matches!(result, Err(QueryError::InvalidResponse)));
        assert_eq!(calls, MAX_CNAME_HOPS + 1);
    }

    #[test]
    fn cname_can_resolve_ipv6_through_real_udp_followup() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let addr = server.local_addr().unwrap();
        let expected: Ipv6Addr = "2001:db8::1234".parse().unwrap();
        let worker = thread::spawn(move || {
            let mut buffer = [0; 512];
            for attempt in 0..2 {
                let (len, peer) = server.recv_from(&mut buffer).unwrap();
                let sent = &buffer[..len];
                let decoded = DnsMessage::decode(sent).unwrap();
                assert_eq!(decoded.questions[0].qtype, qtype::AAAA);
                let record = if attempt == 0 {
                    rr(&[0xc0, 12], qtype::CNAME, 1, 12, &name(b"v6.test"))
                } else {
                    assert_eq!(decoded.questions[0].qname, b"v6.test");
                    rr(&[0xc0, 12], qtype::AAAA, 1, 60, &expected.octets())
                };
                server
                    .send_to(&response_with_records(sent, &[record]), peer)
                    .unwrap();
            }
        });
        let reply = query(
            b"example.test",
            qtype::AAAA,
            addr,
            Duration::from_secs(2),
            false,
            false,
        )
        .unwrap();
        assert_eq!(reply.records.len(), 1);
        assert_eq!(reply.records[0].as_ipv6(), Some(expected));
        assert_eq!(reply.records[0].ttl, 12);
        worker.join().unwrap();
    }

    #[test]
    fn definitive_negative_supersedes_prior_transient_failure() {
        let config = ResolverConfig::default();
        let mut attempts = 0;
        let result = resolve_with(
            b"example.test.",
            true,
            false,
            &config,
            |_, _, _, _, _, _| {
                attempts += 1;
                if attempts == 1 {
                    Err(QueryError::RetryableResponse(rcode::SERVFAIL))
                } else {
                    Ok(QueryReply {
                        records: vec![],
                        rcode: rcode::NXDOMAIN,
                    })
                }
            },
        );
        assert_eq!(attempts, 2);
        assert_eq!(result.unwrap_err(), ResolveError::NotFound);
    }
}
