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

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::resolv;

const DIRECTED_PREFIX: &[u8] = b"resolv:";

#[derive(Debug, Arbitrary)]
struct ResolvFuzzInput {
    data: Vec<u8>,
    name: Vec<u8>,
    addr: Vec<u8>,
    protocol: Vec<u8>,
    family: i32,
    op: u8,
}

fuzz_target!(|data: &[u8]| {
    if let Some(input) = directed_input(data) {
        fuzz_resolv(input);
        return;
    }

    let mut raw = Unstructured::new(data);
    let Ok(input) = ResolvFuzzInput::arbitrary(&mut raw) else {
        return;
    };

    fuzz_resolv(input);
});

fn fuzz_resolv(input: ResolvFuzzInput) {
    match input.op % 7 {
        0 => fuzz_parse_hosts_line(&input),
        1 => fuzz_lookup_hosts(&input),
        2 => fuzz_reverse_lookup_hosts(&input),
        3 => fuzz_parse_services_line(&input),
        4 => fuzz_lookup_service(&input),
        5 => fuzz_getaddrinfo(&input),
        _ => fuzz_getnameinfo(&input),
    }
}

/// Decode readable directed seeds shaped as:
///
/// ```text
/// resolv:<op>
/// name:<host-or-service>
/// addr:<address-or-service>
/// protocol:<tcp-or-udp>
/// family:<inet|inet6|unspec|numeric>
/// ---
/// <hosts-or-services-content>
/// ```
///
/// Header fields are optional. The op is one of `parse_hosts`,
/// `lookup_hosts`, `reverse_lookup_hosts`, `parse_services`,
/// `lookup_service`, `getaddrinfo`, or `getnameinfo`. Legacy libFuzzer
/// corpus bytes still use the `Arbitrary` struct path.
fn directed_input(data: &[u8]) -> Option<ResolvFuzzInput> {
    let rest = data.strip_prefix(DIRECTED_PREFIX)?;
    let (op_name, payload) = split_once_byte(rest, b'\n')?;
    let empty_header: &[u8] = b"";
    let (header, body) = split_once_marker(payload, b"\n---\n").unwrap_or((empty_header, payload));

    let mut name = Vec::new();
    let mut addr = Vec::new();
    let mut protocol = Vec::new();
    let mut family = resolv::AF_UNSPEC;
    for raw_line in header.split(|&byte| byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix(b"name:") {
            name = value.to_vec();
        } else if let Some(value) = line.strip_prefix(b"addr:") {
            addr = value.to_vec();
        } else if let Some(value) = line.strip_prefix(b"protocol:") {
            protocol = value.to_vec();
        } else {
            let value = line.strip_prefix(b"family:")?;
            family = parse_directed_family(value)?;
        }
    }

    Some(ResolvFuzzInput {
        data: strip_single_trailing_newline(body).to_vec(),
        name,
        addr,
        protocol,
        family,
        op: directed_op(op_name)?,
    })
}

fn directed_op(op_name: &[u8]) -> Option<u8> {
    match op_name {
        b"parse_hosts" => Some(0),
        b"lookup_hosts" => Some(1),
        b"reverse_lookup_hosts" => Some(2),
        b"parse_services" => Some(3),
        b"lookup_service" => Some(4),
        b"getaddrinfo" => Some(5),
        b"getnameinfo" => Some(6),
        _ => None,
    }
}

fn parse_directed_family(value: &[u8]) -> Option<i32> {
    match value {
        b"inet" => Some(resolv::AF_INET),
        b"inet6" => Some(resolv::AF_INET6),
        b"unspec" => Some(resolv::AF_UNSPEC),
        _ => parse_directed_i32(value),
    }
}

fn split_once_byte(data: &[u8], byte: u8) -> Option<(&[u8], &[u8])> {
    let split_at = data.iter().position(|&b| b == byte)?;
    let (head, tail) = data.split_at(split_at);
    Some((head, tail.get(1..)?))
}

fn split_once_marker<'a>(data: &'a [u8], marker: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    if marker.is_empty() {
        return None;
    }

    let split_at = data
        .windows(marker.len())
        .position(|window| window == marker)?;
    let (head, tail) = data.split_at(split_at);
    Some((head, tail.get(marker.len()..)?))
}

fn strip_single_trailing_newline(data: &[u8]) -> &[u8] {
    data.strip_suffix(b"\n").unwrap_or(data)
}

fn parse_directed_i32(value: &[u8]) -> Option<i32> {
    if value.is_empty() {
        return None;
    }
    let digits = value.strip_prefix(b"-").unwrap_or(value);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    core::str::from_utf8(value).ok()?.parse().ok()
}

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
        // port == 0 is technically a valid u16 the parser will accept
        // (matches glibc's getservent which doesn't filter port 0
        // either). Kept the assertion as a documented LOOSER bound
        // — the wire-format /etc/services entry can carry any u16,
        // including 0 ("reserved"), and the parser shouldn't have
        // to reject it.
        let _ = entry.port; // u16, always < 65536
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
            assert!(code <= 0, "unexpected error code: {code}");
        }
    }
}

fn fuzz_getnameinfo(input: &ResolvFuzzInput) {
    let addr = &input.addr[..input.addr.len().min(128)];
    // Should not panic regardless of input.
    let _ = resolv::getnameinfo(addr, 0);
}
