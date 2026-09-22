//! DNS protocol implementation.
//!
//! Clean-room implementation of DNS message encoding/decoding for resolver queries.
//! Supports A (IPv4) and AAAA (IPv6) record types with UDP transport.
//!
//! # DNS Message Format (RFC 1035)
//!
//! ```text
//! +---------------------+
//! |        Header       | 12 bytes
//! +---------------------+
//! |       Question      | variable
//! +---------------------+
//! |        Answer       | variable
//! +---------------------+
//! |      Authority      | variable
//! +---------------------+
//! |      Additional     | variable
//! +---------------------+
//! ```

use super::dns_name::{NS_MAXCDNAME, name_pton};
use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// DNS Constants
// ---------------------------------------------------------------------------

/// DNS header size in bytes
pub const DNS_HEADER_SIZE: usize = 12;

/// Maximum DNS message size for UDP
pub const DNS_MAX_UDP_SIZE: usize = 512;

/// DNS record types
pub mod qtype {
    /// IPv4 address
    pub const A: u16 = 1;
    /// Authoritative name server
    pub const NS: u16 = 2;
    /// Canonical name alias
    pub const CNAME: u16 = 5;
    /// Start of authority
    pub const SOA: u16 = 6;
    /// Pointer record
    pub const PTR: u16 = 12;
    /// Mail exchange
    pub const MX: u16 = 15;
    /// Text record
    pub const TXT: u16 = 16;
    /// IPv6 address
    pub const AAAA: u16 = 28;
    /// Any (wildcard)
    pub const ANY: u16 = 255;
}

/// DNS class codes
pub mod qclass {
    /// Internet
    pub const IN: u16 = 1;
}

/// DNS response codes (RCODE)
pub mod rcode {
    /// No error
    pub const NOERROR: u8 = 0;
    /// Format error
    pub const FORMERR: u8 = 1;
    /// Server failure
    pub const SERVFAIL: u8 = 2;
    /// Non-existent domain
    pub const NXDOMAIN: u8 = 3;
    /// Not implemented
    pub const NOTIMP: u8 = 4;
    /// Query refused
    pub const REFUSED: u8 = 5;
}

// ---------------------------------------------------------------------------
// DNS Header
// ---------------------------------------------------------------------------

/// DNS message header (12 bytes)
#[derive(Debug, Clone, Copy, Default)]
pub struct DnsHeader {
    /// Transaction ID
    pub id: u16,
    /// Flags: QR, Opcode, AA, TC, RD, RA, Z, RCODE
    pub flags: u16,
    /// Number of questions
    pub qdcount: u16,
    /// Number of answers
    pub ancount: u16,
    /// Number of authority records
    pub nscount: u16,
    /// Number of additional records
    pub arcount: u16,
}

impl DnsHeader {
    /// Create a new query header with the given transaction ID.
    pub fn new_query(id: u16) -> Self {
        // glibc's DEFAULT: QR=0 (query), RD=1 (recursion desired), AD=0.
        //
        // Callers that have a resolver configuration should use
        // `new_query_with_trust_ad` instead; this is the answer for a resolver
        // that has not been told otherwise.
        Self::new_query_with_trust_ad(id, false)
    }

    /// Build a query header, honouring the resolver's `trust-ad` option.
    ///
    /// THE AD BIT IS DERIVED, NOT CONSTANT, and this function exists because fl
    /// previously pinned it ON. Byte 3 of the header is
    /// RA(7) Z(6) AD(5) CD(4) RCODE(3..0), so AD contributes 0x0020.
    ///
    /// Measured against the live incumbent, glibc 2.42
    /// `res_mkquery(QUERY, "example.com", IN, A)`, reading the flag word:
    ///
    /// | /etc/resolv.conf              | glibc flags |
    /// |------------------------------|-------------|
    /// | `options edns0 trust-ad`     | `0x0120`    |
    /// | same, without `trust-ad`     | `0x0100`    |
    ///
    /// The second row was produced by bind-mounting a resolv.conf lacking the
    /// option over /etc/resolv.conf under bwrap. So `RES_TRUSTAD` is not in
    /// `RES_DEFAULT`; glibc reads it from the resolver configuration.
    ///
    /// The old constant `0x0120` was justified by the opposite claim and looked
    /// correct because every machine on the fleet it was written on runs
    /// systemd-resolved, which writes `trust-ad` into resolv.conf. It therefore
    /// agreed with the incumbent on every host anyone had measured and diverged
    /// on the DEFAULT configuration (bd-b275vh).
    pub fn new_query_with_trust_ad(id: u16, trust_ad: bool) -> Self {
        Self {
            id,
            flags: if trust_ad { 0x0120 } else { 0x0100 },
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    /// Encode the header to bytes.
    pub fn encode(&self, buf: &mut [u8]) -> Option<usize> {
        if buf.len() < DNS_HEADER_SIZE {
            return None;
        }
        buf[0..2].copy_from_slice(&self.id.to_be_bytes());
        buf[2..4].copy_from_slice(&self.flags.to_be_bytes());
        buf[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        buf[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        buf[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        buf[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        Some(DNS_HEADER_SIZE)
    }

    /// Decode the header from bytes.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < DNS_HEADER_SIZE {
            return None;
        }
        Some(Self {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            qdcount: u16::from_be_bytes([buf[4], buf[5]]),
            ancount: u16::from_be_bytes([buf[6], buf[7]]),
            nscount: u16::from_be_bytes([buf[8], buf[9]]),
            arcount: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }

    /// Check if this is a response (QR bit set).
    pub fn is_response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    /// Get the response code (RCODE).
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000f) as u8
    }

    /// Check if the response is truncated (TC bit).
    pub fn is_truncated(&self) -> bool {
        (self.flags & 0x0200) != 0
    }
}

// ---------------------------------------------------------------------------
// DNS Question
// ---------------------------------------------------------------------------

/// DNS question section entry.
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    /// Domain name (uncompressed)
    pub qname: Vec<u8>,
    /// Query type (A, AAAA, etc.)
    pub qtype: u16,
    /// Query class (usually IN)
    pub qclass: u16,
}

impl DnsQuestion {
    /// Create a new A record question for the given hostname.
    pub fn a_record(hostname: &[u8]) -> Option<Self> {
        Some(Self {
            qname: encode_domain_name(hostname)?,
            qtype: qtype::A,
            qclass: qclass::IN,
        })
    }

    /// Create a new AAAA record question for the given hostname.
    pub fn aaaa_record(hostname: &[u8]) -> Option<Self> {
        Some(Self {
            qname: encode_domain_name(hostname)?,
            qtype: qtype::AAAA,
            qclass: qclass::IN,
        })
    }

    /// Encode the question to bytes.
    pub fn encode(&self, buf: &mut [u8]) -> Option<usize> {
        let needed = self.qname.len() + 4;
        if buf.len() < needed {
            return None;
        }
        let mut pos = 0;
        buf[pos..pos + self.qname.len()].copy_from_slice(&self.qname);
        pos += self.qname.len();
        buf[pos..pos + 2].copy_from_slice(&self.qtype.to_be_bytes());
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&self.qclass.to_be_bytes());
        pos += 2;
        Some(pos)
    }

    /// Decode a question from bytes, returning bytes consumed.
    pub fn decode(buf: &[u8], full_msg: &[u8]) -> Option<(Self, usize)> {
        let (qname, name_len) = decode_domain_name(buf, full_msg)?;
        let remaining = &buf[name_len..];
        if remaining.len() < 4 {
            return None;
        }
        let qtype = u16::from_be_bytes([remaining[0], remaining[1]]);
        let qclass = u16::from_be_bytes([remaining[2], remaining[3]]);
        Some((
            Self {
                qname,
                qtype,
                qclass,
            },
            name_len + 4,
        ))
    }
}

// ---------------------------------------------------------------------------
// DNS Resource Record
// ---------------------------------------------------------------------------

/// DNS resource record.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// Domain name
    pub name: Vec<u8>,
    /// Record type
    pub rtype: u16,
    /// Record class
    pub rclass: u16,
    /// TTL in seconds
    pub ttl: u32,
    /// Record data
    pub rdata: Vec<u8>,
}

impl DnsRecord {
    /// Decode a resource record from bytes, returning bytes consumed.
    pub fn decode(buf: &[u8], full_msg: &[u8]) -> Option<(Self, usize)> {
        let (name, name_len) = decode_domain_name(buf, full_msg)?;
        let remaining = &buf[name_len..];
        if remaining.len() < 10 {
            return None;
        }

        let rtype = u16::from_be_bytes([remaining[0], remaining[1]]);
        let rclass = u16::from_be_bytes([remaining[2], remaining[3]]);
        let ttl = u32::from_be_bytes([remaining[4], remaining[5], remaining[6], remaining[7]]);
        let rdlength = u16::from_be_bytes([remaining[8], remaining[9]]) as usize;

        if remaining.len() < 10 + rdlength {
            return None;
        }

        let rdata = remaining[10..10 + rdlength].to_vec();

        Some((
            Self {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            },
            name_len + 10 + rdlength,
        ))
    }

    /// Try to extract an IPv4 address from an A record.
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        if self.rclass != qclass::IN || self.rtype != qtype::A || self.rdata.len() != 4 {
            return None;
        }
        Some(Ipv4Addr::new(
            self.rdata[0],
            self.rdata[1],
            self.rdata[2],
            self.rdata[3],
        ))
    }

    /// Try to extract an IPv6 address from an AAAA record.
    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        if self.rclass != qclass::IN || self.rtype != qtype::AAAA || self.rdata.len() != 16 {
            return None;
        }
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&self.rdata);
        Some(Ipv6Addr::from(octets))
    }
}

// ---------------------------------------------------------------------------
// DNS Message
// ---------------------------------------------------------------------------

/// A complete DNS message.
#[derive(Debug, Clone)]
pub struct DnsMessage {
    /// Message header
    pub header: DnsHeader,
    /// Question section
    pub questions: Vec<DnsQuestion>,
    /// Answer section
    pub answers: Vec<DnsRecord>,
    /// Authority section
    pub authorities: Vec<DnsRecord>,
    /// Additional section
    pub additionals: Vec<DnsRecord>,
}

impl DnsMessage {
    /// Create a new query message for the given hostname and record type.
    pub fn new_query(id: u16, hostname: &[u8], qtype: u16) -> Option<Self> {
        Self::new_query_with_trust_ad(id, hostname, qtype, false)
    }

    /// Build a query message, honouring the resolver's `trust-ad` option.
    ///
    /// See `DnsHeader::new_query_with_trust_ad` for why the AD bit is derived
    /// from the resolver configuration rather than pinned (bd-b275vh).
    pub fn new_query_with_trust_ad(
        id: u16,
        hostname: &[u8],
        qtype: u16,
        trust_ad: bool,
    ) -> Option<Self> {
        Some(Self {
            header: DnsHeader::new_query_with_trust_ad(id, trust_ad),
            questions: vec![DnsQuestion {
                qname: encode_domain_name(hostname)?,
                qtype,
                qclass: qclass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        })
    }

    /// Encode the message to bytes.
    pub fn encode(&self, buf: &mut [u8]) -> Option<usize> {
        let mut pos = self.header.encode(buf)?;

        for q in &self.questions {
            pos += q.encode(&mut buf[pos..])?;
        }

        Some(pos)
    }

    /// Decode a message from bytes.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        let header = DnsHeader::decode(buf)?;
        let mut pos = DNS_HEADER_SIZE;

        // Counts are supplied by the peer. Even a root-name question needs
        // five bytes, and a root-name RR with empty RDATA needs eleven. Reject
        // impossible counts BEFORE reserving vectors: a twelve-byte datagram
        // must not trigger allocations for tens of thousands of records.
        let record_count = usize::from(header.ancount)
            + usize::from(header.nscount)
            + usize::from(header.arcount);
        let minimum_body = usize::from(header.qdcount) * 5 + record_count * 11;
        if minimum_body > buf.len() - DNS_HEADER_SIZE {
            return None;
        }

        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            let (q, len) = DnsQuestion::decode(&buf[pos..], buf)?;
            questions.push(q);
            pos += len;
        }

        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            let (r, len) = DnsRecord::decode(&buf[pos..], buf)?;
            answers.push(r);
            pos += len;
        }

        let mut authorities = Vec::with_capacity(header.nscount as usize);
        for _ in 0..header.nscount {
            let (r, len) = DnsRecord::decode(&buf[pos..], buf)?;
            authorities.push(r);
            pos += len;
        }

        let mut additionals = Vec::with_capacity(header.arcount as usize);
        for _ in 0..header.arcount {
            let (r, len) = DnsRecord::decode(&buf[pos..], buf)?;
            additionals.push(r);
            pos += len;
        }

        Some(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

// ---------------------------------------------------------------------------
// Domain Name Encoding/Decoding
// ---------------------------------------------------------------------------

/// Encode a domain name in DNS wire format.
///
/// Converts "example.com" to "\x07example\x03com\x00"
pub fn encode_domain_name(name: &[u8]) -> Option<Vec<u8>> {
    let mut result = vec![0u8; NS_MAXCDNAME];
    let len = name_pton(name, &mut result).ok()?;
    result.truncate(len);
    Some(result)
}

/// Maximum number of compression pointer hops allowed before aborting.
/// Bounds work even for pointer-only chains which do not expand the name.
const MAX_POINTER_HOPS: usize = 64;

/// Decode a domain name from DNS wire format, handling compression.
///
/// Returns the decoded name (as "example.com") and bytes consumed.
fn decode_domain_name(buf: &[u8], full_msg: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut result = Vec::new();
    let mut source = buf;
    let mut pos = 0;
    let mut consumed = None;
    let mut pointer_hops = 0;
    // RFC 1035 counts label-length octets AND the final root octet, not
    // just the dotted presentation. Keep one budget across all pointers.
    let mut wire_len = 1usize;

    loop {
        let len = *source.get(pos)?;
        match len {
            0 => return Some((result, consumed.unwrap_or(pos + 1))),
            1..=63 => {
                let label_len = usize::from(len);
                wire_len += 1 + label_len;
                if wire_len > NS_MAXCDNAME {
                    return None;
                }
                let end = pos.checked_add(1 + label_len)?;
                let label = source.get(pos + 1..end)?;
                if !result.is_empty() {
                    result.push(b'.');
                }
                result.extend_from_slice(label);
                pos = end;
            }
            0xc0..=0xff => {
                let low = *source.get(pos.checked_add(1)?)?;
                let offset = (usize::from(len & 0x3f) << 8) | usize::from(low);
                pointer_hops += 1;
                if pointer_hops > MAX_POINTER_HOPS || (consumed.is_some() && offset >= pos) {
                    return None;
                }
                // Only the first pointer consumes bytes in the caller's
                // slice. Following pointers is iterative, never recursive.
                consumed.get_or_insert(pos + 2);
                source = full_msg;
                pos = offset;
            }
            // 01xxxxxx and 10xxxxxx are reserved label encodings, not
            // lengths of 64..191 bytes. Reject them before copying data.
            _ => return None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// DNS Resolution Result
// ---------------------------------------------------------------------------

/// Result of a DNS resolution attempt.
#[derive(Debug, Default)]
pub struct DnsResolution {
    /// Resolved IPv4 addresses.
    pub ipv4: Vec<Ipv4Addr>,
    /// Resolved IPv6 addresses.
    pub ipv6: Vec<Ipv6Addr>,
}

/// Parse a DNS response buffer and extract address records.
///
/// Used by the ABI layer's DNS stub resolver after receiving a UDP response.
/// Returns the answer records on success, empty vec on a complete NXDOMAIN,
/// and None on malformed, truncated, or unsuccessful replies. The transport
/// must handle TCP fallback; partial UDP answers are not a successful result.
pub fn parse_dns_response(recv_buf: &[u8], expected_id: u16) -> Option<Vec<DnsRecord>> {
    if recv_buf.len() < DNS_HEADER_SIZE {
        return None;
    }
    let header = DnsHeader::decode(recv_buf)?;
    if !header.is_response()
        || header.id != expected_id
        || header.is_truncated()
        || header.flags & 0x7800 != 0
    {
        return None;
    }
    // Validate all declared sections even for negative replies. Otherwise a
    // malformed NXDOMAIN can bypass decoding and look like a valid miss.
    let decoded = DnsMessage::decode(recv_buf)?;
    if header.rcode() == rcode::NXDOMAIN {
        return Some(Vec::new());
    }
    if header.rcode() != rcode::NOERROR {
        return None;
    }
    Some(decoded.answers)
}

/// Build the list of hostnames to try, applying search domains per resolv.conf.
///
/// `ndots` chooses the position of the unsuffixed name, not whether search
/// domains are tried. A name with enough dots is tried as-is first, then with
/// each suffix after a miss. A trailing dot explicitly disables suffix search.
pub fn build_search_names(hostname: &[u8], search_domains: &[String], ndots: u32) -> Vec<Vec<u8>> {
    if hostname.last() == Some(&b'.') {
        return vec![hostname.to_vec()];
    }

    let dot_count = hostname.iter().filter(|&&b| b == b'.').count();
    let absolute_first = dot_count >= ndots as usize;
    let mut names = Vec::with_capacity(search_domains.len() + 1);
    if absolute_first {
        names.push(hostname.to_vec());
    }
    names.extend(search_domains.iter().map(|domain| {
        let mut fqdn = hostname.to_vec();
        fqdn.push(b'.');
        fqdn.extend_from_slice(domain.as_bytes());
        fqdn
    }));
    if !absolute_first {
        names.push(hostname.to_vec());
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_domain_name() {
        let encoded = encode_domain_name(b"example.com").unwrap();
        assert_eq!(encoded, b"\x07example\x03com\x00");
    }

    #[test]
    fn test_encode_domain_name_single_label() {
        let encoded = encode_domain_name(b"localhost").unwrap();
        assert_eq!(encoded, b"\x09localhost\x00");
    }

    #[test]
    fn test_encode_domain_name_trailing_dot() {
        let encoded = encode_domain_name(b"example.com.").unwrap();
        assert_eq!(encoded, b"\x07example\x03com\x00");
    }

    #[test]
    fn test_encode_domain_name_rejects_invalid_labels() {
        assert!(encode_domain_name(&[b'a'; 64]).is_none());
        assert!(encode_domain_name(b"example..com").is_none());
    }

    #[test]
    fn test_decode_domain_name() {
        let msg = b"\x07example\x03com\x00";
        let (name, len) = decode_domain_name(msg, msg).unwrap();
        assert_eq!(name, b"example.com");
        assert_eq!(len, 13);
    }

    #[test]
    fn test_dns_header_encode_decode() {
        let header = DnsHeader::new_query(0x1234);
        let mut buf = [0u8; 64];
        let len = header.encode(&mut buf).unwrap();
        assert_eq!(len, 12);

        let decoded = DnsHeader::decode(&buf).unwrap();
        assert_eq!(decoded.id, 0x1234);
        assert_eq!(decoded.qdcount, 1);
        assert!(!decoded.is_response());
    }

    #[test]
    fn test_dns_question_encode() {
        let q = DnsQuestion::a_record(b"example.com").unwrap();
        let mut buf = [0u8; 64];
        let len = q.encode(&mut buf).unwrap();
        // 13 (name) + 4 (type + class) = 17
        assert_eq!(len, 17);
    }

    #[test]
    fn test_dns_message_encode_decode_query() {
        let msg = DnsMessage::new_query(0x5678, b"test.example.com", qtype::A).unwrap();
        let mut buf = [0u8; 512];
        let len = msg.encode(&mut buf).unwrap();

        assert!(len > 12);
        assert!(len < 100);

        // Verify header decoding
        let decoded_header = DnsHeader::decode(&buf).unwrap();
        assert_eq!(decoded_header.id, 0x5678);
        assert_eq!(decoded_header.qdcount, 1);
    }

    #[test]
    fn test_rcode_constants() {
        assert_eq!(rcode::NOERROR, 0);
        assert_eq!(rcode::NXDOMAIN, 3);
    }

    #[test]
    fn test_header_flags() {
        let mut header = DnsHeader::new_query(1);
        assert!(!header.is_response());
        assert!(!header.is_truncated());
        assert_eq!(header.rcode(), 0);

        // Set response bit
        header.flags |= 0x8000;
        assert!(header.is_response());

        // Set truncated bit
        header.flags |= 0x0200;
        assert!(header.is_truncated());

        // Set NXDOMAIN rcode
        header.flags |= 0x0003;
        assert_eq!(header.rcode(), 3);
    }

    fn wire_name(label_lengths: &[usize]) -> Vec<u8> {
        let mut wire = Vec::new();
        for &len in label_lengths {
            assert!((1..=63).contains(&len));
            wire.push(len as u8);
            wire.extend(std::iter::repeat_n(b'a', len));
        }
        wire.push(0);
        wire
    }

    #[test]
    fn test_decode_rejects_reserved_label_tags() {
        for tag in [0x40u8, 0x7f, 0x80, 0xbf] {
            let mut wire = vec![tag];
            wire.extend(std::iter::repeat_n(b'a', usize::from(tag)));
            wire.push(0);
            assert!(decode_domain_name(&wire, &wire).is_none());

            let start = wire.len();
            wire.extend_from_slice(&[0xc0, 0]);
            assert!(decode_domain_name(&wire[start..], &wire).is_none());
        }
    }

    #[test]
    fn test_decode_enforces_expanded_wire_name_limit() {
        let longest = wire_name(&[63, 63, 63, 61]);
        assert_eq!(longest.len(), 255);
        let (name, consumed) = decode_domain_name(&longest, &longest).unwrap();
        assert_eq!(name.len(), 253);
        assert_eq!(consumed, 255);

        let too_long = wire_name(&[63, 63, 63, 62]);
        assert_eq!(too_long.len(), 256);
        assert!(decode_domain_name(&too_long, &too_long).is_none());

        let many_labels = wire_name(&[1; 127]);
        assert!(decode_domain_name(&many_labels, &many_labels).is_some());
        let too_many_labels = wire_name(&[1; 128]);
        assert!(decode_domain_name(&too_many_labels, &too_many_labels).is_none());
    }

    #[test]
    fn test_decode_compressed_suffix_shares_name_budget() {
        for prefix_len in [61usize, 62] {
            let mut message = wire_name(&[63, 63, 63]);
            let start = message.len();
            message.push(prefix_len as u8);
            message.extend(std::iter::repeat_n(b'p', prefix_len));
            message.extend_from_slice(&[0xc0, 0, 0xaa, 0xbb]);
            let decoded = decode_domain_name(&message[start..], &message);
            if prefix_len == 61 {
                let (name, consumed) = decoded.unwrap();
                assert_eq!(name.len(), 253);
                assert_eq!(consumed, prefix_len + 3);
                assert_eq!(&name[..prefix_len], vec![b'p'; prefix_len]);
                assert_eq!(name[prefix_len], b'.');
            } else {
                assert!(decoded.is_none());
            }
        }
    }

    #[test]
    fn test_decode_pointer_chains_have_bounded_work() {
        let mut message = vec![0];
        let mut target = 0usize;
        for hops in 1..=MAX_POINTER_HOPS + 1 {
            let start = message.len();
            message.push(0xc0 | ((target >> 8) as u8));
            message.push(target as u8);
            let decoded = decode_domain_name(&message[start..], &message);
            if hops <= MAX_POINTER_HOPS {
                assert_eq!(decoded, Some((Vec::new(), 2)));
            } else {
                assert!(decoded.is_none());
            }
            target = start;
        }
    }

    #[test]
    fn test_decode_rejects_cycles_and_truncated_names() {
        for wire in [
            &b"\xc0\x00"[..],
            &b"\xc0\x02\xc0\x00"[..],
            &b"\x01a\xc0\x00"[..],
            &b"\xc0\xff"[..],
            &b"\xc0"[..],
            &b"\x03ab"[..],
            &b""[..],
        ] {
            assert!(decode_domain_name(wire, wire).is_none());
        }
    }

    #[test]
    fn test_decode_rejects_impossible_section_counts() {
        for count_offset in [4, 6, 8, 10] {
            let mut packet = [0u8; DNS_HEADER_SIZE];
            packet[count_offset..count_offset + 2].copy_from_slice(&u16::MAX.to_be_bytes());
            assert!(DnsMessage::decode(&packet).is_none());
        }

        // The lower bound must accept the smallest legal entries, including
        // a root question and empty-RDATA records in all three RR sections.
        let mut packet = vec![0u8; DNS_HEADER_SIZE + 5 + 3 * 11];
        for count_offset in [4, 6, 8, 10] {
            packet[count_offset + 1] = 1;
        }
        let decoded = DnsMessage::decode(&packet).unwrap();
        assert_eq!(decoded.questions.len(), 1);
        assert_eq!(decoded.answers.len(), 1);
        assert_eq!(decoded.authorities.len(), 1);
        assert_eq!(decoded.additionals.len(), 1);
    }

    fn address_response() -> Vec<u8> {
        b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01".to_vec()
    }

    #[test]
    fn test_parse_response_accepts_complete_compressed_answer() {
        let packet = address_response();
        let answers = parse_dns_response(&packet, 0x1234).unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].name, b"example.com");
        assert_eq!(answers[0].as_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));
        for end in 0..packet.len() {
            assert!(parse_dns_response(&packet[..end], 0x1234).is_none());
        }
        assert!(parse_dns_response(&packet, 0x4321).is_none());
    }

    #[test]
    fn test_parse_response_rejects_truncation_and_non_query_opcode() {
        for flag in [0x02, 0x08] {
            let mut packet = address_response();
            packet[2] |= flag;
            assert!(parse_dns_response(&packet, 0x1234).is_none());
        }
        let mut query = address_response();
        query[2] &= 0x7f;
        assert!(parse_dns_response(&query, 0x1234).is_none());
    }

    #[test]
    fn test_parse_response_validates_negative_reply_sections() {
        let mut packet = address_response();
        packet.truncate(29); // Header and complete question, no answers.
        packet[3] = 0x83;
        packet[7] = 0;
        assert!(parse_dns_response(&packet, 0x1234).unwrap().is_empty());
        assert!(parse_dns_response(&packet[..28], 0x1234).is_none());
        packet[7] = 1; // A declared but missing answer is not a valid miss.
        assert!(parse_dns_response(&packet, 0x1234).is_none());
    }

    #[test]
    fn test_address_extraction_requires_internet_class() {
        for (rtype, rdata) in [(qtype::A, vec![0; 4]), (qtype::AAAA, vec![0; 16])] {
            let mut record = DnsRecord {
                name: b"example.com".to_vec(),
                rtype,
                rclass: qclass::IN,
                ttl: 60,
                rdata,
            };
            assert!(record.as_ipv4().is_some() || record.as_ipv6().is_some());
            for rclass in [2, 3, 4, 255] {
                record.rclass = rclass;
                assert!(record.as_ipv4().is_none());
                assert!(record.as_ipv6().is_none());
            }
        }
    }

    #[test]
    fn test_search_names_single_label_searches_before_absolute() {
        let domains = vec!["corp.example".to_owned(), "lab.example".to_owned()];
        assert_eq!(
            build_search_names(b"printer", &domains, 1),
            vec![
                b"printer.corp.example".to_vec(),
                b"printer.lab.example".to_vec(),
                b"printer".to_vec(),
            ]
        );
    }

    #[test]
    fn test_search_names_dotted_name_keeps_suffix_fallback() {
        let domains = vec!["corp.example".to_owned(), "lab.example".to_owned()];
        assert_eq!(
            build_search_names(b"api.dev", &domains, 1),
            vec![
                b"api.dev".to_vec(),
                b"api.dev.corp.example".to_vec(),
                b"api.dev.lab.example".to_vec(),
            ]
        );
    }

    #[test]
    fn test_search_names_ndots_boundary_only_changes_order() {
        let domains = vec!["corp.example".to_owned()];
        assert_eq!(
            build_search_names(b"api.dev", &domains, 2),
            vec![b"api.dev.corp.example".to_vec(), b"api.dev".to_vec()]
        );
        assert_eq!(
            build_search_names(b"api.dev.test", &domains, 2),
            vec![
                b"api.dev.test".to_vec(),
                b"api.dev.test.corp.example".to_vec(),
            ]
        );
    }

    #[test]
    fn test_search_names_ndots_zero_tries_absolute_then_search() {
        let domains = vec!["corp.example".to_owned()];
        assert_eq!(
            build_search_names(b"printer", &domains, 0),
            vec![b"printer".to_vec(), b"printer.corp.example".to_vec()]
        );
    }

    #[test]
    fn test_search_names_trailing_dot_never_uses_search_domains() {
        let domains = vec!["corp.example".to_owned(), "lab.example".to_owned()];
        for hostname in [&b"api.dev."[..], &b"printer."[..], &b"."[..]] {
            for ndots in [0, 1, 2, 15, u32::MAX] {
                assert_eq!(
                    build_search_names(hostname, &domains, ndots),
                    vec![hostname.to_vec()]
                );
            }
        }
    }

    #[test]
    fn test_search_names_empty_search_list_keeps_absolute_once() {
        for hostname in [&b"printer"[..], &b"api.dev"[..], &b"api.dev."[..]] {
            for ndots in [0, 1, 2, 15, u32::MAX] {
                assert_eq!(
                    build_search_names(hostname, &[], ndots),
                    vec![hostname.to_vec()]
                );
            }
        }
    }

    #[test]
    fn test_search_names_preserves_configured_order_and_input() {
        let domains = vec!["Z.example".to_owned(), "A.example".to_owned()];
        let original = domains.clone();
        let names = build_search_names(b"API.dev", &domains, 1);
        assert_eq!(domains, original);
        assert_eq!(
            names,
            vec![
                b"API.dev".to_vec(),
                b"API.dev.Z.example".to_vec(),
                b"API.dev.A.example".to_vec(),
            ]
        );
    }

    // -----------------------------------------------------------------
    // Smoke-fuzz proptests for encode_domain_name (bd-s170, Archetype 1)
    // -----------------------------------------------------------------
    //
    // encode_domain_name turns "a.b.c" into DNS wire-format labels
    // `\x01a\x01b\x01c\x00`. Spec-bound output invariants:
    //   • Always terminates with the root label (single `0x00` byte)
    //   • Every length prefix is ≤63 (RFC 1035 §2.3.4)
    //   • Output length ≤ input length + number_of_labels + 1
    //   • Never panics on arbitrary byte input

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

    proptest! {
        #![proptest_config(fuzz_proptest_config(512))]

        #[test]
        fn fuzz_search_names_preserves_candidates_and_ndots_order(
            hostname in "[a-z]{1,16}(\\.[a-z]{1,16}){0,3}",
            domains in proptest::collection::vec("[a-z]{1,16}\\.[a-z]{1,16}", 0..8),
            ndots in 0u32..6,
        ) {
            let names = build_search_names(hostname.as_bytes(), &domains, ndots);
            let absolute_first = hostname.bytes().filter(|&b| b == b'.').count()
                >= ndots as usize;
            prop_assert_eq!(names.len(), domains.len() + 1);
            let absolute_index = if absolute_first { 0 } else { domains.len() };
            prop_assert_eq!(names[absolute_index].as_slice(), hostname.as_bytes());
            let suffix_start = usize::from(absolute_first);
            for (index, domain) in domains.iter().enumerate() {
                let expected = format!("{hostname}.{domain}").into_bytes();
                prop_assert_eq!(names[suffix_start + index].as_slice(), expected.as_slice());
            }
            let absolute = format!("{hostname}.");
            prop_assert_eq!(
                build_search_names(absolute.as_bytes(), &domains, ndots),
                vec![absolute.into_bytes()]
            );
        }

        #[test]
        fn fuzz_decode_domain_name_is_bounded(
            bytes in proptest::collection::vec(any::<u8>(), 0..2048),
        ) {
            if let Some((name, consumed)) = decode_domain_name(&bytes, &bytes) {
                prop_assert!(name.len() <= 253);
                prop_assert!((1..=bytes.len()).contains(&consumed));
            }
        }

        #[test]
        fn fuzz_decode_dns_message_never_panics(
            bytes in proptest::collection::vec(any::<u8>(), 0..2048),
        ) {
            let _ = DnsMessage::decode(&bytes);
            let _ = parse_dns_response(&bytes, 0x1234);
        }

        #[test]
        fn fuzz_encode_domain_name_never_panics(
            bytes in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let _ = encode_domain_name(&bytes);
        }

        /// Every encoded wire-form output must terminate with the root
        /// label — a single 0x00 byte. A regression that forgot the
        /// terminator would produce outputs the kernel refuses to
        /// dispatch.
        #[test]
        fn fuzz_encode_domain_name_ends_with_root_label(
            bytes in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let Some(out) = encode_domain_name(&bytes) else {
                return Ok(());
            };
            prop_assert!(!out.is_empty(), "output must be non-empty");
            prop_assert_eq!(
                *out.last().unwrap(),
                0u8,
                "encoded domain name must end with root label (0x00)"
            );
        }

        /// RFC 1035 §2.3.4: label length ≤ 63. Since the length prefix
        /// is a u8 capped at 63 by the encoder, every byte we read as a
        /// length prefix during a wire-format scan must satisfy this.
        /// Scan by interpreting each "label length byte" and advancing.
        #[test]
        fn fuzz_encode_domain_name_length_prefixes_under_64(
            bytes in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let Some(out) = encode_domain_name(&bytes) else {
                return Ok(());
            };
            let mut i = 0;
            while i < out.len() {
                let len = out[i] as usize;
                if len == 0 {
                    break; // root label
                }
                prop_assert!(
                    len <= 63,
                    "label length prefix {len} at offset {i} exceeds RFC 1035 §2.3.4 limit"
                );
                let end = i.checked_add(1).and_then(|j| j.checked_add(len));
                prop_assert!(end.is_some(), "label length at offset {i} overflows usize");
                let end = end.unwrap();
                prop_assert!(
                    end <= out.len(),
                    "label at offset {i} with length {len} extends past output buffer"
                );
                i = end;
            }
        }

        /// Output size is bounded: at most input_len + 2 (one length
        /// prefix per non-empty label plus one root terminator, and
        /// labels can't add more bytes than they consume from input
        /// plus the length prefixes). This rejects pathological
        /// expansion via label inflation bugs.
        #[test]
        fn fuzz_encode_domain_name_output_is_bounded(
            bytes in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let Some(out) = encode_domain_name(&bytes) else {
                return Ok(());
            };
            // Max non-empty labels = input.len() / 1 + 1 (worst case:
            // "a.a.a...a" with n 1-char labels uses n length prefixes
            // for n characters, plus 1 terminator).
            let max_prefixes = bytes.iter().filter(|&&b| b != b'.').count() + 1;
            let upper = bytes.len() + max_prefixes + 1;
            prop_assert!(
                out.len() <= upper,
                "output {} exceeds upper bound {} (input len {})",
                out.len(), upper, bytes.len()
            );
        }
    }
}
