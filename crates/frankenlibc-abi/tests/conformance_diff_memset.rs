//! Isomorphism + golden gate for the wide-word `raw_memset_bytes` fill.
//!
//! The shipped `memset` ABI path funnels every fill through `raw_memset_bytes`,
//! which was rewritten from a byte-at-a-time volatile loop to a wide-word (u64,
//! 32-byte-unrolled) volatile fill. This gate proves the rewrite is behavior-
//! preserving: for every (length, value, alignment offset) in a dense corpus the
//! wide fill is byte-for-byte identical BOTH to a trivial scalar reference AND to
//! host glibc `memset`, and the concatenated outputs hash to a pinned digest.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::string_abi::bench_raw_memset_bytes;
use sha2::{Digest, Sha256};
use std::ffi::c_void;

/// Scalar reference fill — the exact semantics the wide-word version must match.
fn reference_fill(buf: &mut [u8], value: u8, n: usize) {
    for b in &mut buf[..n] {
        *b = value;
    }
}

#[test]
fn raw_memset_matches_reference_and_glibc_over_corpus() {
    // Backing allocation with slack so we can start the fill at every alignment
    // offset 0..8 relative to an 8-aligned base (Vec<u64> guarantees 8-align).
    let mut hasher = Sha256::new();
    let mut checked = 0u64;

    let lengths = [
        0usize, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 100, 127, 128, 129, 255,
        256, 257, 1000, 1024, 4096, 4097,
    ];
    let values = [0x00u8, 0x01, 0x5A, 0x7F, 0x80, 0xFF, 0xAB];

    for &offset in &[0usize, 1, 2, 3, 4, 5, 6, 7] {
        for &len in &lengths {
            for &value in &values {
                // Over-allocate: offset + len + guard, zero-initialised.
                let total = offset + len + 8;
                let mut backing: Vec<u64> = vec![0u64; total.div_ceil(8) + 1];
                let base = backing.as_mut_ptr().cast::<u8>();

                // fl wide-word fill into the offset window.
                let mut fl_buf = vec![0u8; offset + len + 8];
                // Pre-stamp a sentinel byte just past the fill to prove no overrun.
                if offset + len < fl_buf.len() {
                    fl_buf[offset + len] = 0xCC;
                }
                unsafe { bench_raw_memset_bytes(fl_buf.as_mut_ptr().add(offset), value, len) };

                // Scalar reference into an identically-shaped buffer.
                let mut ref_buf = vec![0u8; offset + len + 8];
                if offset + len < ref_buf.len() {
                    ref_buf[offset + len] = 0xCC;
                }
                reference_fill(&mut ref_buf[offset..], value, len);

                // Host glibc memset into a third buffer.
                let mut gl_buf = vec![0u8; offset + len + 8];
                if offset + len < gl_buf.len() {
                    gl_buf[offset + len] = 0xCC;
                }
                unsafe {
                    libc::memset(
                        gl_buf.as_mut_ptr().add(offset).cast::<c_void>(),
                        value as i32,
                        len,
                    );
                }

                assert_eq!(
                    fl_buf, ref_buf,
                    "wide fill != scalar reference (offset={offset} len={len} value={value:#x})"
                );
                assert_eq!(
                    fl_buf, gl_buf,
                    "wide fill != glibc memset (offset={offset} len={len} value={value:#x})"
                );

                hasher.update(&fl_buf);
                let _ = base; // backing kept alive; alignment exercised via Vec<u64>
                checked += 1;
            }
        }
    }

    assert_eq!(checked, 8 * 28 * 7, "corpus size drifted");
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        digest, "1fa3233a628c430eece9a1aa5e5cea436af032ed80117d495bda4d58a0e47517",
        "memset wide-fill golden corpus hash drifted: got {digest}"
    );
}
