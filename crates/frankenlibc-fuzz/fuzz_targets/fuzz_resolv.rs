#![no_main]
//! Structure-aware fuzz target for FrankenLibC resolver (hosts/services parsing, getaddrinfo).
//!
//! Exercises parse_hosts_line, lookup_hosts, reverse_lookup_hosts,
//! parse_services_line, lookup_service, getaddrinfo_with_hosts, getnameinfo.
//! Invariants:
//! - No panics on any well-typed input
//! - Parsed results are internally consistent
//! - Lookups are deterministic
//! - getaddrinfo returns valid error codes
//!
//! Bead: bd-2hh.4

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::resolv;

#[derive(Debug, Arbitrary)]
struct ResolvFuzzInput {
    data: Vec<u8>,
    name: Vec<u8>,
    addr: Vec<u8>,
    protocol: Vec<u8>,
    family: i32,
    op: u8,
}

fuzz_target!(|input: ResolvFuzzInput| {
    match input.op % 7 {
        0 => fuzz_parse_hosts_line(&input),
        1 => fuzz_lookup_hosts(&input),
        2 => fuzz_reverse_lookup_hosts(&input),
        3 => fuzz_parse_services_line(&input),
        4 => fuzz_lookup_service(&input),
        5 => fuzz_getaddrinfo(&input),
        _ => fuzz_getnameinfo(&input),
    }
});

fn fuzz_parse_hosts_line(input: &ResolvFuzzInput) {
    let line = &input.data[..input.data.len().min(1024)];
    if let Some((addr, names)) = resolv::parse_hosts_line(line) {
        assert!(!addr.is_empty(), "parsed address should not be empty");
        // All names should be non-empty.
        for name in &names {
            assert!(!name.is_empty(), "parsed hostname should not be empty");
        }
    }
}

fn fuzz_lookup_hosts(input: &ResolvFuzzInput) {
    let content = &input.data[..input.data.len().min(4096)];
    let name = &input.name[..input.name.len().min(256)];
    let results = resolv::lookup_hosts(content, name);
    // All returned addresses should be non-empty.
    for addr in &results {
        assert!(!addr.is_empty(), "looked-up address should not be empty");
    }

    // Determinism check.
    let results2 = resolv::lookup_hosts(content, name);
    assert_eq!(results, results2, "lookup_hosts should be deterministic");
}

fn fuzz_reverse_lookup_hosts(input: &ResolvFuzzInput) {
    let content = &input.data[..input.data.len().min(4096)];
    let addr = &input.addr[..input.addr.len().min(256)];
    let results = resolv::reverse_lookup_hosts(content, addr);
    for name in &results {
        assert!(
            !name.is_empty(),
            "reverse-looked-up name should not be empty"
        );
    }
}

fn fuzz_parse_services_line(input: &ResolvFuzzInput) {
    let line = &input.data[..input.data.len().min(512)];
    if let Some(entry) = resolv::parse_services_line(line) {
        assert!(
            !entry.name.is_empty(),
            "parsed service name should not be empty"
        );
        assert!(entry.port > 0, "parsed port should be positive");
        assert!(
            !entry.protocol.is_empty(),
            "parsed protocol should not be empty"
        );
    }
}

fn fuzz_lookup_service(input: &ResolvFuzzInput) {
    let content = &input.data[..input.data.len().min(4096)];
    let name = &input.name[..input.name.len().min(256)];
    let proto = if input.protocol.is_empty() {
        None
    } else {
        Some(&input.protocol[..input.protocol.len().min(32)] as &[u8])
    };

    let r1 = resolv::lookup_service(content, name, proto);
    let r2 = resolv::lookup_service(content, name, proto);
    assert_eq!(r1, r2, "lookup_service should be deterministic");
}

fn fuzz_getaddrinfo(input: &ResolvFuzzInput) {
    let node = if input.name.is_empty() {
        None
    } else {
        Some(&input.name[..input.name.len().min(256)] as &[u8])
    };

    let service = if input.addr.is_empty() {
        None
    } else {
        Some(&input.addr[..input.addr.len().min(64)] as &[u8])
    };

    let hints = resolv::AddrInfo {
        ai_family: input.family,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addr: Vec::new(),
        ai_canonname: None,
    };

    let hosts_content = if input.data.is_empty() {
        None
    } else {
        Some(&input.data[..input.data.len().min(4096)] as &[u8])
    };

    // Should not panic; may return Ok or Err with a valid error code.
    match resolv::getaddrinfo_with_hosts(node, service, Some(&hints), hosts_content) {
        Ok(results) => {
            for ai in &results {
                // Family should be valid.
                assert!(
                    ai.ai_family == resolv::AF_INET
                        || ai.ai_family == resolv::AF_INET6
                        || ai.ai_family == resolv::AF_UNSPEC,
                    "unexpected address family: {}",
                    ai.ai_family
                );
            }
        }
        Err(code) => {
            // Error codes should be negative (EAI_*).
            assert!(code < 0 || code == 0, "unexpected error code: {code}");
        }
    }
}

fn fuzz_getnameinfo(input: &ResolvFuzzInput) {
    let addr = &input.addr[..input.addr.len().min(128)];
    // Should not panic regardless of input.
    let _ = resolv::getnameinfo(addr, 0);
}
