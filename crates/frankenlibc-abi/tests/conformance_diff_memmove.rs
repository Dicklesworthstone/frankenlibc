//! Isomorphism + golden gate for the wide-word overlap-aware `raw_memmove_bytes`.
//!
//! `memmove`'s ABI path funnels through `raw_memmove_bytes`, rewritten from a
//! byte-at-a-time volatile move to wide u128-block moves (forward for dst<=src,
//! backward in 16-byte read-then-write blocks for dst>src overlap). Overlap
//! correctness is the whole game here, so the corpus exercises every relative
//! src/dst displacement (including the tricky small-positive backward overlaps)
//! at every alignment and a wide range of lengths, asserting byte-for-byte
//! equality with host glibc `memmove` and pinning a golden digest.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::string_abi::bench_raw_memmove_bytes;
use sha2::{Digest, Sha256};
use std::ffi::c_void;

#[test]
fn raw_memmove_matches_glibc_over_overlap_corpus() {
    let mut hasher = Sha256::new();
    let mut checked = 0u64;

    let lengths = [
        0usize, 1, 2, 7, 8, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 100, 127, 128, 200, 256, 257,
        1000, 4096,
    ];
    // Signed displacement of dst relative to src within a shared scratch buffer:
    // negative => dst before src (forward), positive => dst after src (backward),
    // small magnitudes deliberately hit the within-block overlap edge cases.
    let displacements: [isize; 13] = [-64, -33, -16, -8, -3, -1, 1, 3, 8, 15, 16, 33, 64];

    for &len in &lengths {
        for &disp in &displacements {
            // Shared buffer big enough for src window, dst window and the shift.
            let pad = 64usize;
            let span = len + disp.unsigned_abs() + 2 * pad;

            // Deterministic source content.
            let content: Vec<u8> = (0..span)
                .map(|k| (k as u8).wrapping_mul(31).wrapping_add(7))
                .collect();

            // src starts at `pad`; dst at `pad + disp`.
            let src_off = pad;
            let dst_off = (pad as isize + disp) as usize;

            // fl move.
            let mut fl = content.clone();
            unsafe {
                let base = fl.as_mut_ptr();
                bench_raw_memmove_bytes(base.add(dst_off), base.add(src_off), len);
            }

            // glibc move over an identical fresh copy.
            let mut gl = content.clone();
            unsafe {
                let base = gl.as_mut_ptr();
                libc::memmove(
                    base.add(dst_off).cast::<c_void>(),
                    base.add(src_off).cast::<c_void>(),
                    len,
                );
            }

            assert_eq!(
                fl, gl,
                "raw_memmove != glibc memmove (len={len} disp={disp})"
            );
            hasher.update(&fl);
            checked += 1;
        }
    }

    assert_eq!(checked, 23 * 13, "corpus size drifted");
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        digest, "64e17e8879f1b8ba42f52cbc0992f5ecf8d4d67f17f677dafe2258d986045585",
        "memmove wide-move golden corpus hash drifted: got {digest}"
    );
}
