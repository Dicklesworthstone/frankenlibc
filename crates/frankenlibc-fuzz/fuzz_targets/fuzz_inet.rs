#![no_main]
//! Structure-aware fuzz target for FrankenLibC inet address functions.
//!
//! Exercises `inet_addr`, `inet_pton`, `inet_ntop`, `inet_aton`,
//! `parse_ipv4`, `parse_ipv6`, byte-order helpers, and round-trips.
//!
//! Invariants:
//! - No function panics on any input
//! - inet_pton(AF_INET, inet_ntop(AF_INET, x)) round-trips
//! - inet_pton(AF_INET6, inet_ntop(AF_INET6, x)) round-trips
//! - htons/ntohs and htonl/ntohl are inverses
//! - parse_ipv4 and inet_addr agree
//!
//! Bead: bd-2hh.4

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::inet;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const DIRECTED_PREFIX: &[u8] = b"inet:";

#[derive(Debug, Arbitrary)]
struct InetFuzzInput {
    /// Raw bytes for address text input.
    data: Vec<u8>,
    /// 4 bytes for IPv4 binary input.
    ipv4_bytes: [u8; 4],
    /// 16 bytes for IPv6 binary input.
    ipv6_bytes: [u8; 16],
    /// 16-bit value for byte-order tests.
    val16: u16,
    /// 32-bit value for byte-order tests.
    val32: u32,
    /// Operation selector.
    op: u8,
}

const MAX_INPUT: usize = 256;

fuzz_target!(|data: &[u8]| {
    if let Some(input) = directed_input(data) {
        fuzz_inet(input);
        return;
    }

    let mut raw = Unstructured::new(data);
    let Ok(input) = InetFuzzInput::arbitrary(&mut raw) else {
        return;
    };

    fuzz_inet(input);
});

fn fuzz_inet(input: InetFuzzInput) {
    if input.data.len() > MAX_INPUT {
        return;
    }

    match input.op % 6 {
        0 => fuzz_inet_addr(&input),
        1 => fuzz_pton_ipv4(&input),
        2 => fuzz_pton_ipv6(&input),
        3 => fuzz_ntop_roundtrip(&input),
        4 => fuzz_byte_order(&input),
        5 => fuzz_parse_consistency(&input),
        _ => unreachable!(),
    }
}

/// Decode readable directed seeds shaped as:
///
/// ```text
/// inet:<op>
/// <address-text>
/// ```
///
/// The op is one of `addr`, `pton4`, `pton6`, `ntop`, `order`, or `parse`.
/// Legacy libFuzzer corpus bytes still use the `Arbitrary` struct path.
fn directed_input(data: &[u8]) -> Option<InetFuzzInput> {
    let rest = data.strip_prefix(DIRECTED_PREFIX)?;
    let (op_name, payload) = split_once_byte(rest, b'\n')?;
    let text = strip_single_trailing_newline(payload);
    if text.len() > MAX_INPUT {
        return None;
    }

    let ipv4_bytes = inet::parse_ipv4(text)
        .or_else(|| inet::parse_ipv4_bsd(text))
        .unwrap_or([0, 0, 0, 0]);
    let ipv6_bytes = inet::parse_ipv6(text).unwrap_or([0; 16]);

    Some(InetFuzzInput {
        data: text.to_vec(),
        ipv4_bytes,
        ipv6_bytes,
        val16: directed_u16(text),
        val32: directed_u32(text),
        op: directed_op(op_name)?,
    })
}

fn directed_op(op_name: &[u8]) -> Option<u8> {
    match op_name {
        b"addr" => Some(0),
        b"pton4" => Some(1),
        b"pton6" => Some(2),
        b"ntop" => Some(3),
        b"order" => Some(4),
        b"parse" => Some(5),
        _ => None,
    }
}

fn split_once_byte(data: &[u8], byte: u8) -> Option<(&[u8], &[u8])> {
    let split_at = data.iter().position(|&b| b == byte)?;
    let (head, tail) = data.split_at(split_at);
    Some((head, tail.get(1..)?))
}

fn strip_single_trailing_newline(data: &[u8]) -> &[u8] {
    data.strip_suffix(b"\n").unwrap_or(data)
}

fn directed_u16(data: &[u8]) -> u16 {
    u16::from_be_bytes([
        data.first().copied().unwrap_or(0x12),
        data.get(1).copied().unwrap_or(0x34),
    ])
}

fn directed_u32(data: &[u8]) -> u32 {
    u32::from_be_bytes([
        data.first().copied().unwrap_or(0x12),
        data.get(1).copied().unwrap_or(0x34),
        data.get(2).copied().unwrap_or(0x56),
        data.get(3).copied().unwrap_or(0x78),
    ])
}

/// Test inet_addr with arbitrary byte strings.
fn fuzz_inet_addr(input: &InetFuzzInput) {
    let result = inet::inet_addr(&input.data);

    // Determinism
    let result2 = inet::inet_addr(&input.data);
    assert_eq!(result, result2, "inet_addr not deterministic");

    // If valid, parse_ipv4 should agree
    if result != inet::INADDR_NONE
        && let Some(octets) = inet::parse_ipv4(&input.data)
    {
        assert_eq!(
            result.to_ne_bytes(),
            octets,
            "inet_addr and parse_ipv4 disagree"
        );
    }
}

/// Test inet_pton with AF_INET.
fn fuzz_pton_ipv4(input: &InetFuzzInput) {
    let mut dst = [0u8; 4];
    let rc = inet::inet_pton(AF_INET, &input.data, &mut dst);

    // Return value must be -1, 0, or 1
    assert!(
        rc == -1 || rc == 0 || rc == 1,
        "inet_pton returned unexpected value: {rc}"
    );

    // Determinism
    let mut dst2 = [0u8; 4];
    let rc2 = inet::inet_pton(AF_INET, &input.data, &mut dst2);
    assert_eq!(rc, rc2);
    if rc == 1 {
        assert_eq!(dst, dst2);
    }

    // Unsupported family should return -1
    let rc_bad = inet::inet_pton(99, &input.data, &mut dst);
    assert_eq!(rc_bad, -1, "unsupported AF should return -1");
}

/// Test inet_pton with AF_INET6.
fn fuzz_pton_ipv6(input: &InetFuzzInput) {
    let mut dst = [0u8; 16];
    let rc = inet::inet_pton(AF_INET6, &input.data, &mut dst);
    assert!(
        rc == -1 || rc == 0 || rc == 1,
        "inet_pton IPv6 returned unexpected value: {rc}"
    );

    if rc == 1 {
        // Round-trip: ntop then pton should reproduce
        if let Some(text) = inet::inet_ntop(AF_INET6, &dst) {
            let mut rt = [0u8; 16];
            let rc_rt = inet::inet_pton(AF_INET6, &text, &mut rt);
            assert_eq!(rc_rt, 1, "ntop→pton round-trip failed");
            assert_eq!(dst, rt, "IPv6 round-trip mismatch");
        }
    }
}

/// Test ntop → pton round-trips with binary addresses.
fn fuzz_ntop_roundtrip(input: &InetFuzzInput) {
    // IPv4 round-trip
    if let Some(text) = inet::inet_ntop(AF_INET, &input.ipv4_bytes) {
        let mut rt = [0u8; 4];
        let rc = inet::inet_pton(AF_INET, &text, &mut rt);
        assert_eq!(rc, 1, "IPv4 ntop→pton failed");
        assert_eq!(
            rt, input.ipv4_bytes,
            "IPv4 round-trip mismatch: {:?} → {:?} → {:?}",
            input.ipv4_bytes, text, rt
        );
    }

    // IPv6 round-trip
    if let Some(text) = inet::inet_ntop(AF_INET6, &input.ipv6_bytes) {
        let mut rt = [0u8; 16];
        let rc = inet::inet_pton(AF_INET6, &text, &mut rt);
        assert_eq!(rc, 1, "IPv6 ntop→pton failed");
        assert_eq!(rt, input.ipv6_bytes, "IPv6 round-trip mismatch");
    }
}

/// Test byte-order helpers are inverses.
fn fuzz_byte_order(input: &InetFuzzInput) {
    // htons/ntohs are inverses
    assert_eq!(
        inet::ntohs(inet::htons(input.val16)),
        input.val16,
        "ntohs(htons(x)) != x"
    );
    assert_eq!(
        inet::htons(inet::ntohs(input.val16)),
        input.val16,
        "htons(ntohs(x)) != x"
    );

    // htonl/ntohl are inverses
    assert_eq!(
        inet::ntohl(inet::htonl(input.val32)),
        input.val32,
        "ntohl(htonl(x)) != x"
    );
    assert_eq!(
        inet::htonl(inet::ntohl(input.val32)),
        input.val32,
        "htonl(ntohl(x)) != x"
    );

    // Double application is identity (these are involutions)
    assert_eq!(
        inet::htons(inet::htons(input.val16)),
        input.val16,
        "htons is not an involution? (only on big-endian)"
    );
}

/// Test strict IPv4 parsing and BSD inet_aton/inet_addr consistency.
fn fuzz_parse_consistency(input: &InetFuzzInput) {
    let parsed_strict = inet::parse_ipv4(&input.data);
    let parsed_bsd = inet::parse_ipv4_bsd(&input.data);
    let addr = inet::inet_addr(&input.data);

    let mut pton_dst = [0u8; 4];
    let pton_rc = inet::inet_pton(AF_INET, &input.data, &mut pton_dst);
    let mut aton_dst = [0u8; 4];
    let aton_rc = inet::inet_aton(&input.data, &mut aton_dst);

    if let Some(octets) = parsed_strict {
        assert_eq!(pton_rc, 1, "parse_ipv4 succeeded but inet_pton failed");
        assert_eq!(pton_dst, octets, "inet_pton and parse_ipv4 disagree");
    } else {
        assert_eq!(pton_rc, 0, "parse_ipv4 failed but inet_pton succeeded");
    }

    // inet_aton/inet_addr use the broader BSD numbers-and-dots grammar,
    // while parse_ipv4 is intentionally strict inet_pton grammar.
    if let Some(octets) = parsed_bsd {
        assert_eq!(aton_rc, 1, "parse_ipv4_bsd succeeded but inet_aton failed");
        assert_eq!(aton_dst, octets, "inet_aton and parse_ipv4_bsd disagree");
        assert_eq!(
            addr.to_ne_bytes(),
            octets,
            "inet_addr and parse_ipv4_bsd disagree"
        );
    } else {
        assert_eq!(aton_rc, 0, "parse_ipv4_bsd failed but inet_aton succeeded");
        assert_eq!(
            addr,
            inet::INADDR_NONE,
            "parse_ipv4_bsd failed but inet_addr succeeded"
        );
    }
}
