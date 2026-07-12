//! Byte-identity gate for the BOUNDED path of `scan_c_string_last_byte`
//! (strrchr on a membrane-tracked buffer, where `known_remaining` supplies a
//! `Some(limit)`). A 32-byte portable-SIMD skip was added to that path mirroring
//! the already-proven unbounded skip; this test pins it against a scalar
//! reference across the head / SIMD-skip / SWAR-tail tiers and every NUL/target/
//! limit edge, so the SIMD path can never silently diverge.
//!
//! The unbounded (`None`) path is covered by `conformance_diff_strrchr_simd`;
//! this gate exists because the existing differential tests use untracked
//! buffers (which take the unbounded path) and so never exercise the bounded one.

use std::ffi::c_char;

use frankenlibc_abi::string_abi::bench_scan_c_string_last_byte;

/// Exact scalar spec for `scan_c_string_last_byte(.., Some(limit))`:
/// scan forward to the first NUL within `limit` (or to `limit`), tracking the
/// last `target`. At the NUL, `target` is checked BEFORE termination, so
/// `target == 0` reports the NUL index itself (matching glibc `strrchr(s,'\0')`).
fn scalar_last(buf: &[u8], target: u8, limit: usize) -> (Option<usize>, usize, bool) {
    let mut last = None;
    let mut i = 0usize;
    while i < limit {
        let b = buf[i];
        if b == target {
            last = Some(i);
        }
        if b == 0 {
            return (last, i, false);
        }
        i += 1;
    }
    (last, limit, true)
}

/// Deterministic xorshift so the test is reproducible without an RNG crate.
fn next(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn bounded_last_byte_matches_scalar_reference() {
    // Lengths span the head (<32), the 32B SIMD-skip tier, and the SWAR tail,
    // including the exact tier boundaries (31/32/33, 63/64/65).
    let lens = [
        0usize, 1, 2, 7, 8, 9, 15, 16, 31, 32, 33, 47, 63, 64, 65, 96, 127, 128, 200, 256, 257,
        512, 1000, 1024, 4096,
    ];
    // Targets include a low alphabet byte, a high byte, and NUL itself.
    let targets = [b'Z', b'a', 0u8, 0xFFu8, b'm'];
    let mut state = 0x9e37_79b9_7f4a_7c15u64;

    let mut total_cases = 0u64;
    for &len in &lens {
        // A handful of randomized fills per length to stress NUL/target placement.
        for _trial in 0..24 {
            let mut buf = vec![0u8; len + 64]; // padding so reads up to limit stay in-bounds
            for b in buf.iter_mut().take(len) {
                // Bias toward 'a' with occasional NULs and targets, like real C strings.
                let r = next(&mut state);
                *b = match r % 16 {
                    0 => 0u8,    // NUL
                    1 => b'Z',   // a common target
                    2 => 0xFFu8, // high byte
                    _ => b'a' + (r % 5) as u8,
                };
            }
            let p = buf.as_ptr().cast::<c_char>();
            for &target in &targets {
                // Test several limits: the full len, and shorter clamps that may
                // end mid-string before any NUL (hit_limit == true).
                for &limit in &[len, len / 2, len.saturating_sub(1), (len / 4) * 3] {
                    let want = scalar_last(&buf, target, limit);
                    // SAFETY: buf is valid for at least `limit` (<= len) bytes.
                    let got = unsafe { bench_scan_c_string_last_byte(p, target, Some(limit)) };
                    assert_eq!(
                        got, want,
                        "bounded scan_c_string_last_byte mismatch: len={len} limit={limit} \
                         target={target:#x}"
                    );
                    total_cases += 1;
                }
            }
        }
    }
    eprintln!("bounded strrchr scan: {total_cases} cases matched scalar reference");
    assert!(total_cases > 1000);
}

/// Explicit pinned edges: NUL exactly at a 32-byte panel boundary, target only
/// inside a skippable panel, target as the very last pre-NUL byte, and an
/// all-`target` buffer (every panel "hits" so the SIMD skip never fires).
#[test]
fn bounded_last_byte_panel_boundary_edges() {
    // 1) NUL at index 32 (start of the 2nd SIMD panel), target at 10 and 40.
    {
        let mut buf = vec![b'a'; 128];
        buf[10] = b'Z';
        buf[32] = 0;
        buf[40] = b'Z'; // after the NUL — must NOT be reported when limit > 32
        let p = buf.as_ptr().cast::<c_char>();
        let got = unsafe { bench_scan_c_string_last_byte(p, b'Z', Some(128)) };
        assert_eq!(got, (Some(10), 32, false));
    }
    // 2) target only inside an otherwise-skippable middle panel (no NUL within limit).
    {
        let mut buf = vec![b'a'; 256];
        buf[100] = b'Z';
        let p = buf.as_ptr().cast::<c_char>();
        let got = unsafe { bench_scan_c_string_last_byte(p, b'Z', Some(200)) };
        assert_eq!(got, (Some(100), 200, true));
    }
    // 3) target == NUL: strrchr(s,'\0') reports the terminator index.
    {
        let mut buf = vec![b'a'; 64];
        buf[50] = 0;
        let p = buf.as_ptr().cast::<c_char>();
        let got = unsafe { bench_scan_c_string_last_byte(p, 0, Some(64)) };
        assert_eq!(got, (Some(50), 50, false));
    }
    // 4) all-target buffer: last index is limit-1 (no NUL), every panel hits.
    {
        let buf = vec![b'Z'; 300];
        let p = buf.as_ptr().cast::<c_char>();
        let got = unsafe { bench_scan_c_string_last_byte(p, b'Z', Some(300)) };
        assert_eq!(got, (Some(299), 300, true));
    }
}
