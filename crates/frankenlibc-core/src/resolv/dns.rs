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
        Self {
            id,
            // QR=0 (query), RD=1 (recursion desired)
            flags: 0x0100,
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
    pub fn a_record(hostname: &[u8]) -> Self {
        Self {
            qname: encode_domain_name(hostname),
            qtype: qtype::A,
            qclass: qclass::IN,
        }
    }

    /// Create a new AAAA record question for the given hostname.
    pub fn aaaa_record(hostname: &[u8]) -> Self {
        Self {
            qname: encode_domain_name(hostname),
            qtype: qtype::AAAA,
            qclass: qclass::IN,
        }
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
        if self.rtype != qtype::A || self.rdata.len() != 4 {
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
        if self.rtype != qtype::AAAA || self.rdata.len() != 16 {
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
    pub fn new_query(id: u16, hostname: &[u8], qtype: u16) -> Self {
        Self {
            header: DnsHeader::new_query(id),
            questions: vec![DnsQuestion {
                qname: encode_domain_name(hostname),
                qtype,
                qclass: qclass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
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
pub fn encode_domain_name(name: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(name.len() + 2);

    for label in name.split(|&b| b == b'.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            // Label too long, truncate
            result.push(63);
            result.extend_from_slice(&label[..63]);
        } else {
            result.push(label.len() as u8);
            result.extend_from_slice(label);
        }
    }

    result.push(0); // Root label
    result
}

/// Maximum number of compression pointer hops allowed before aborting.
/// This prevents stack overflow from pointer loops (e.g., mutual back-references).
const MAX_POINTER_HOPS: usize = 64;

/// Decode a domain name from DNS wire format, handling compression.
///
/// Returns the decoded name (as "example.com") and bytes consumed.
fn decode_domain_name(buf: &[u8], full_msg: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut result = Vec::new();
    let mut pos = 0;

    loop {
        if pos >= buf.len() {
            return None;
        }

        let len = buf[pos];

        if len == 0 {
            // End of name
            return Some((result, pos + 1));
        }

        // Check for compression pointer (top 2 bits set)
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= buf.len() {
                return None;
            }
            let offset = (((len & 0x3F) as usize) << 8) | (buf[pos + 1] as usize);

            // Follow the pointer in full_msg, starting hop counter at 1
            return decode_domain_name_at_offset(full_msg, offset, &mut result, 1)
                .map(|_| (result, pos + 2));
        }

        // Normal label
        let label_len = len as usize;
        if pos + 1 + label_len > buf.len() {
            return None;
        }

        if !result.is_empty() {
            result.push(b'.');
        }
        result.extend_from_slice(&buf[pos + 1..pos + 1 + label_len]);
        pos += 1 + label_len;
    }
}

/// Helper for decoding a name at a specific offset (for compression).
///
/// `pointer_hops` tracks the total number of compression pointers followed
/// across all recursive calls. This prevents stack overflow from pointer loops
/// (e.g., offset A -> offset B -> offset A) that the simple `new_offset >= pos`
/// check cannot catch.
fn decode_domain_name_at_offset(
    msg: &[u8],
    offset: usize,
    result: &mut Vec<u8>,
    pointer_hops: usize,
) -> Option<()> {
    if pointer_hops > MAX_POINTER_HOPS {
        return None;
    }

    let mut pos = offset;
    let mut depth = 0;

    loop {
        if pos >= msg.len() || depth > 128 {
            return None;
        }

        let len = msg[pos];

        if len == 0 {
            break;
        }

        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= msg.len() {
                return None;
            }
            let new_offset = (((len & 0x3F) as usize) << 8) | (msg[pos + 1] as usize);
            if new_offset >= pos {
                // Forward pointer would cause infinite loop
                return None;
            }
            return decode_domain_name_at_offset(msg, new_offset, result, pointer_hops + 1);
        }

        let label_len = len as usize;
        if pos + 1 + label_len > msg.len() {
            return None;
        }

        if !result.is_empty() {
            result.push(b'.');
        }
        result.extend_from_slice(&msg[pos + 1..pos + 1 + label_len]);
        pos += 1 + label_len;
        depth += 1;
    }

    Some(())
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
/// Returns the answer records on success, empty vec on NXDOMAIN, None on error.
pub fn parse_dns_response(recv_buf: &[u8], expected_id: u16) -> Option<Vec<DnsRecord>> {
    if recv_buf.len() < DNS_HEADER_SIZE {
        return None;
    }
    let header = DnsHeader::decode(recv_buf)?;
    if !header.is_response() || header.id != expected_id {
        return None;
    }
    if header.rcode() == rcode::NXDOMAIN {
        return Some(Vec::new());
    }
    if header.rcode() != rcode::NOERROR {
        return None;
    }
    let decoded = DnsMessage::decode(recv_buf)?;
    Some(decoded.answers)
}

/// Build the list of hostnames to try, applying search domains per resolv.conf.
pub fn build_search_names(hostname: &[u8], search_domains: &[String], ndots: u32) -> Vec<Vec<u8>> {
    let dot_count = hostname.iter().filter(|&&b| b == b'.').count();
    if dot_count >= ndots as usize || hostname.last() == Some(&b'.') {
        vec![hostname.to_vec()]
    } else {
        let mut names: Vec<Vec<u8>> = search_domains
            .iter()
            .map(|domain| {
                let mut fqdn = hostname.to_vec();
                fqdn.push(b'.');
                fqdn.extend_from_slice(domain.as_bytes());
                fqdn
            })
            .collect();
        names.push(hostname.to_vec());
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_domain_name() {
        let encoded = encode_domain_name(b"example.com");
        assert_eq!(encoded, b"\x07example\x03com\x00");
    }

    #[test]
    fn test_encode_domain_name_single_label() {
        let encoded = encode_domain_name(b"localhost");
        assert_eq!(encoded, b"\x09localhost\x00");
    }

    #[test]
    fn test_encode_domain_name_trailing_dot() {
        let encoded = encode_domain_name(b"example.com.");
        assert_eq!(encoded, b"\x07example\x03com\x00");
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
        let q = DnsQuestion::a_record(b"example.com");
        let mut buf = [0u8; 64];
        let len = q.encode(&mut buf).unwrap();
        // 13 (name) + 4 (type + class) = 17
        assert_eq!(len, 17);
    }

    #[test]
    fn test_dns_message_encode_decode_query() {
        let msg = DnsMessage::new_query(0x5678, b"test.example.com", qtype::A);
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
            let out = encode_domain_name(&bytes);
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
            let out = encode_domain_name(&bytes);
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
            let out = encode_domain_name(&bytes);
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
