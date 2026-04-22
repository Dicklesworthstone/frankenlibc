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

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::inet;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;

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

fuzz_target!(|input: InetFuzzInput| {
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
});

/// Test inet_addr with arbitrary byte strings.
fn fuzz_inet_addr(input: &InetFuzzInput) {
    let result = inet::inet_addr(&input.data);

    // Determinism
    let result2 = inet::inet_addr(&input.data);
    assert_eq!(result, result2, "inet_addr not deterministic");

    // If valid, parse_ipv4 should agree
    if result != inet::INADDR_NONE {
        if let Some(octets) = inet::parse_ipv4(&input.data) {
            assert_eq!(
                result.to_ne_bytes(),
                octets,
                "inet_addr and parse_ipv4 disagree"
            );
        }
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

/// Test parse_ipv4 / inet_aton / inet_addr consistency.
fn fuzz_parse_consistency(input: &InetFuzzInput) {
    let parsed = inet::parse_ipv4(&input.data);
    let addr = inet::inet_addr(&input.data);

    let mut aton_dst = [0u8; 4];
    let aton_rc = inet::inet_aton(&input.data, &mut aton_dst);

    // If parse_ipv4 succeeds, inet_aton must also succeed
    if let Some(octets) = parsed {
        assert_eq!(aton_rc, 1, "parse_ipv4 succeeded but inet_aton failed");
        assert_eq!(aton_dst, octets, "inet_aton and parse_ipv4 disagree");
        // inet_addr stores in network byte order
        assert_eq!(
            addr.to_ne_bytes(),
            octets,
            "inet_addr and parse_ipv4 disagree"
        );
    }

    // If parse_ipv4 fails, inet_aton should fail too
    if parsed.is_none() {
        assert_eq!(aton_rc, 0, "parse_ipv4 failed but inet_aton succeeded");
    }
}
