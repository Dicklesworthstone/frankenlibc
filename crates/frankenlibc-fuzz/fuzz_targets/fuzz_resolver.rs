#![no_main]
//! Structure-aware fuzz target for FrankenLibC DNS resolver and config parser.
//!
//! Exercises DNS message encoding/decoding with arbitrary binary packets
//! and resolv.conf parsing with arbitrary configuration text. The invariant:
//! no combination of input should panic, produce unbounded output, or
//! corrupt state.
//!
//! Coverage goals:
//! - DnsHeader: encode, decode, is_response, rcode, is_truncated
//! - DnsQuestion: encode, decode, a_record, aaaa_record
//! - DnsRecord: decode, as_ipv4, as_ipv6
//! - DnsMessage: encode, decode, new_query, round-trip
//! - encode_domain_name: all label patterns
//! - ResolverConfig::parse: all directives and edge cases
//!
//! Bead: bd-1oz.7

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::resolv::config::ResolverConfig;
use frankenlibc_core::resolv::dns::{
    DNS_HEADER_SIZE, DnsHeader, DnsMessage, DnsQuestion, DnsRecord, encode_domain_name,
};

/// Maximum input size to prevent OOM.
const MAX_INPUT: usize = 4096;

/// Maximum hostname length for encoding tests.
const MAX_HOSTNAME: usize = 253;

/// A structured fuzz input for the resolver.
#[derive(Debug, Arbitrary)]
struct ResolverFuzzInput {
    /// Raw bytes for DNS message decoding.
    dns_bytes: Vec<u8>,
    /// Raw bytes for resolv.conf parsing.
    config_bytes: Vec<u8>,
    /// Hostname bytes for domain name encoding.
    hostname: Vec<u8>,
    /// Query ID for message construction.
    query_id: u16,
    /// Query type selector.
    qtype_sel: u8,
    /// Operation selector.
    op: u8,
}

fuzz_target!(|input: ResolverFuzzInput| {
    if input.dns_bytes.len() > MAX_INPUT || input.config_bytes.len() > MAX_INPUT {
        return;
    }

    match input.op % 6 {
        0 => fuzz_dns_header_decode(&input),
        1 => fuzz_dns_message_decode(&input),
        2 => fuzz_dns_question_decode(&input),
        3 => fuzz_dns_record_decode(&input),
        4 => fuzz_resolv_conf_parse(&input),
        5 => fuzz_domain_name_roundtrip(&input),
        _ => unreachable!(),
    }
});

/// Fuzz DNS header decoding with arbitrary bytes.
fn fuzz_dns_header_decode(input: &ResolverFuzzInput) {
    let buf = &input.dns_bytes;

    // Decode arbitrary bytes — should never panic
    if let Some(header) = DnsHeader::decode(buf) {
        // Exercise all accessor methods
        let _ = header.is_response();
        let _ = header.rcode();
        let _ = header.is_truncated();

        // If we decoded successfully, re-encoding should produce valid output
        let mut encode_buf = [0u8; DNS_HEADER_SIZE];
        let encoded = header.encode(&mut encode_buf);
        assert!(
            encoded.is_some(),
            "re-encode of valid header should succeed"
        );
    }

    // Also test header round-trip with known-good construction
    let query_header = DnsHeader::new_query(input.query_id);
    let mut buf2 = [0u8; DNS_HEADER_SIZE];
    let len = query_header.encode(&mut buf2);
    assert!(len.is_some(), "query header encoding should succeed");
    if let Some(len) = len {
        assert_eq!(len, DNS_HEADER_SIZE);
        let decoded = DnsHeader::decode(&buf2);
        assert!(decoded.is_some(), "freshly encoded header should decode");
        if let Some(decoded) = decoded {
            assert_eq!(decoded.id, input.query_id);
            assert!(!decoded.is_response());
        }
    }
}

/// Fuzz full DNS message decoding with arbitrary binary data.
fn fuzz_dns_message_decode(input: &ResolverFuzzInput) {
    let buf = &input.dns_bytes;

    // Attempt to decode — should never panic regardless of input
    if let Some(msg) = DnsMessage::decode(buf) {
        // Exercise all fields
        let _ = msg.header.is_response();
        let _ = msg.header.rcode();
        let _ = msg.questions.len();
        let _ = msg.answers.len();

        // Check answer records
        for answer in &msg.answers {
            let _ = answer.as_ipv4();
            let _ = answer.as_ipv6();
            let _ = answer.rtype;
            let _ = answer.rclass;
            let _ = answer.ttl;
        }
    }

    // Also test encode/decode round-trip with known query
    let hostname = if input.hostname.is_empty() {
        b"example.com".as_slice()
    } else {
        &input.hostname[..input.hostname.len().min(MAX_HOSTNAME)]
    };

    let qtypes = [1u16, 28]; // A and AAAA
    let qtype = qtypes[(input.qtype_sel as usize) % qtypes.len()];
    let msg = DnsMessage::new_query(input.query_id, hostname, qtype);

    let mut encode_buf = [0u8; 512];
    if let Some(encoded_len) = msg.encode(&mut encode_buf) {
        assert!(encoded_len <= 512);
        // Decode our own encoding — should always succeed
        let decoded = DnsMessage::decode(&encode_buf[..encoded_len]);
        if let Some(d) = decoded {
            assert_eq!(d.header.id, input.query_id);
        }
    }
}

/// Fuzz DNS question decoding from arbitrary bytes.
fn fuzz_dns_question_decode(input: &ResolverFuzzInput) {
    let buf = &input.dns_bytes;

    // Decode question — buf is both the section and full message for compression
    let result = DnsQuestion::decode(buf, buf);
    if let Some((question, consumed)) = result {
        assert!(consumed <= buf.len());
        let _ = question.qname;
        let _ = question.qtype;
        let _ = question.qclass;
    }

    // Test with the buffer as both section and different full message
    if buf.len() > DNS_HEADER_SIZE {
        let section = &buf[DNS_HEADER_SIZE..];
        let result2 = DnsQuestion::decode(section, buf);
        if let Some((_, consumed)) = result2 {
            assert!(consumed <= section.len());
        }
    }
}

/// Fuzz DNS resource record decoding from arbitrary bytes.
fn fuzz_dns_record_decode(input: &ResolverFuzzInput) {
    let buf = &input.dns_bytes;

    let result = DnsRecord::decode(buf, buf);
    if let Some((record, consumed)) = result {
        assert!(consumed <= buf.len());
        let _ = record.as_ipv4();
        let _ = record.as_ipv6();
        let _ = record.name;
        let _ = record.rtype;
        let _ = record.rclass;
        let _ = record.ttl;
        let _ = record.rdata;
    }
}

/// Fuzz resolv.conf parsing with arbitrary text.
fn fuzz_resolv_conf_parse(input: &ResolverFuzzInput) {
    let content = &input.config_bytes;

    // Should never panic regardless of content
    let config = ResolverConfig::parse(content);

    // Exercise all accessor methods
    let _ = config.query_timeout();
    let _ = config.total_budget();
    let _ = config.nameservers.len();
    let _ = config.domain;
    let _ = config.search.len();
    let _ = config.ndots;
    let _ = config.timeout;
    let _ = config.attempts;
    let _ = config.rotate;
    let _ = config.use_vc;

    // should_try_absolute_first with a test name
    let _ = config.should_try_absolute_first("test.example.com");

    // Nameservers should always have at least the default
    assert!(
        !config.nameservers.is_empty(),
        "nameservers should never be empty after parse"
    );

    // Also test with well-formed resolv.conf fragments
    let well_formed = b"nameserver 8.8.8.8\nnameserver 8.8.4.4\noptions ndots:3 timeout:2\n";
    let cfg2 = ResolverConfig::parse(well_formed);
    assert_eq!(cfg2.nameservers.len(), 2);
    assert_eq!(cfg2.ndots, 3);
}

/// Fuzz domain name encoding with arbitrary hostnames.
fn fuzz_domain_name_roundtrip(input: &ResolverFuzzInput) {
    let hostname = &input.hostname[..input.hostname.len().min(MAX_HOSTNAME)];

    // Encoding should never panic
    let encoded = encode_domain_name(hostname);

    // Encoded name should end with a zero-length label (0x00)
    if !encoded.is_empty() {
        assert_eq!(
            encoded[encoded.len() - 1],
            0,
            "encoded domain name must end with null label"
        );
    }

    // Each label should be <=63 bytes (DNS label length limit)
    let mut pos = 0;
    while pos < encoded.len() {
        let label_len = encoded[pos] as usize;
        if label_len == 0 {
            break;
        }
        assert!(label_len <= 63, "DNS label length must be <= 63");
        pos += 1 + label_len;
    }

    // Test with specific patterns
    let _ = encode_domain_name(b"");
    let _ = encode_domain_name(b".");
    let _ = encode_domain_name(b"a");
    let _ = encode_domain_name(b"example.com");
    let _ = encode_domain_name(b"sub.domain.example.com");
    let _ = encode_domain_name(b"...");
    let _ = encode_domain_name(b"a.b.c.d.e.f.g.h.i.j");
}
