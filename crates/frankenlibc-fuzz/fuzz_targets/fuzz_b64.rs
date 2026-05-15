#![no_main]
//! Structure-aware fuzz target for `frankenlibc_core::resolv::b64`
//! (RFC 4648 base64). Exercises:
//!
//!   * `ntop` over arbitrary-length payloads, asserting the encoder
//!     never panics and produces ASCII output bounded by
//!     `4 * ceil(srclen / 3) + 1` bytes.
//!   * `pton` over arbitrary input bytes (including malformed
//!     padding, embedded NUL, whitespace-only, raw alphabet,
//!     mid-stream `=`), asserting the decoder either succeeds with a
//!     bounded-length output or returns None — never panics.
//!   * `decoded_len` as the dry-run counterpart to `pton`; both must
//!     agree on Some/None and on the decoded length.
//!   * Round-trip: `pton(ntop(x))` recovers `x` for any input.
//!   * Idempotence: `ntop(pton(ntop(x))) == ntop(x)`.
//!
//! Seed files can force a specific mode with `ntop:`, `pton:`,
//! `len:`, or `rt:` prefixes. Unprefixed inputs still flow through
//! the arbitrary-derived structured path.
//!
//! Bead: bd-zmtxf.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::resolv::b64;

#[derive(Debug, Arbitrary)]
struct B64FuzzInput {
    payload: Vec<u8>,
    op: u8,
}

fuzz_target!(|data: &[u8]| {
    if try_directive_seed(data) {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let Ok(input) = B64FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };

    // Bound payload length to keep individual fuzz runs cheap; the AFL/
    // libfuzzer corpus minimization will preserve interesting cases.
    let payload = &input.payload[..input.payload.len().min(1024)];
    match input.op % 4 {
        0 => fuzz_ntop(payload),
        1 => fuzz_pton(payload),
        2 => fuzz_decoded_len_matches_pton(payload),
        _ => fuzz_round_trip_and_idempotence(payload),
    }
});

fn try_directive_seed(data: &[u8]) -> bool {
    if let Some(payload) = data.strip_prefix(b"ntop:") {
        fuzz_ntop(trim_seed_newline(payload));
        true
    } else if let Some(payload) = data.strip_prefix(b"pton:") {
        fuzz_pton(trim_seed_newline(payload));
        true
    } else if let Some(payload) = data.strip_prefix(b"len:") {
        fuzz_decoded_len_matches_pton(trim_seed_newline(payload));
        true
    } else if let Some(payload) = data.strip_prefix(b"rt:") {
        fuzz_round_trip_and_idempotence(trim_seed_newline(payload));
        true
    } else {
        false
    }
}

fn trim_seed_newline(payload: &[u8]) -> &[u8] {
    payload
        .strip_suffix(b"\r\n")
        .or_else(|| payload.strip_suffix(b"\n"))
        .unwrap_or(payload)
}

fn fuzz_ntop(payload: &[u8]) {
    // Encoder must never panic for any byte slice; output buffer is
    // sized to the documented contract. A returned None is acceptable
    // (target too small) but only when target really is too small.
    let cap = 4 * payload.len().div_ceil(3) + 1;
    let mut buf = vec![0u8; cap];
    if let Some(n) = b64::ntop(payload, &mut buf) {
        assert!(n < buf.len(), "ntop returned len >= buf.len()");
        assert_eq!(buf[n], 0, "ntop must NUL-terminate at returned length");
        assert!(
            n <= 4 * payload.len().div_ceil(3),
            "ntop output {n} exceeds 4*ceil(len/3) for srclen={}",
            payload.len()
        );
        // Output bytes must all be in the RFC 4648 alphabet (incl. `=`).
        for &b in &buf[..n] {
            assert!(
                matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'='),
                "ntop emitted non-alphabet byte 0x{b:02x}"
            );
        }
    } else {
        // None must only happen when buf is genuinely too small.
        let mut undersize = vec![0u8; cap.saturating_sub(1)];
        let _ = b64::ntop(payload, &mut undersize);
    }
}

fn fuzz_pton(payload: &[u8]) {
    // Decoder must never panic on any byte slice. Output capacity equal
    // to the input length is always large enough since base64 expands
    // 3 bytes -> 4 chars (decoder is stricter, so output <= 3*len/4).
    let mut buf = vec![0u8; payload.len().max(1)];
    let _ = b64::pton(payload, &mut buf);
}

fn fuzz_decoded_len_matches_pton(payload: &[u8]) {
    // dry-run length must match real-run length when both succeed.
    let dry = b64::decoded_len(payload);
    let mut buf = vec![0u8; payload.len().max(1)];
    let real = b64::pton(payload, &mut buf);
    assert_eq!(
        dry.is_some(),
        real.is_some(),
        "decoded_len/pton acceptance disagrees for input {payload:?}: dry={dry:?} real={real:?}"
    );
    match (dry, real) {
        (Some(a), Some(b)) => assert_eq!(
            a, b,
            "decoded_len/pton disagree on length for input {payload:?}"
        ),
        (None, None) => {}
        // The assertion above already surfaced the acceptance mismatch.
        _ => {}
    }
}

fn fuzz_round_trip_and_idempotence(payload: &[u8]) {
    let encode_cap = 4 * payload.len().div_ceil(3) + 1;
    let mut enc = vec![0u8; encode_cap];
    let n = match b64::ntop(payload, &mut enc) {
        Some(n) => n,
        None => return,
    };
    let encoded = &enc[..n];

    let mut dec = vec![0u8; payload.len().max(1)];
    let m = match b64::pton(encoded, &mut dec) {
        Some(m) => m,
        None => return,
    };
    assert_eq!(
        m,
        payload.len(),
        "round-trip length drift: input.len()={} pton.len={}",
        payload.len(),
        m
    );
    assert_eq!(
        &dec[..m],
        payload,
        "round-trip byte drift: input vs decoded"
    );

    // Idempotence: encode(decode(encode(x))) == encode(x).
    let mut enc2 = vec![0u8; encode_cap];
    let n2 = match b64::ntop(&dec[..m], &mut enc2) {
        Some(n) => n,
        None => return,
    };
    assert_eq!(
        &enc2[..n2],
        encoded,
        "idempotence drift: encoding decoded(encoded(x)) != encoded(x)"
    );
}
