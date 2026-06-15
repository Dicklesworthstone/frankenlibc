//! Isomorphism + golden gate for the wide-word `raw_memcpy_bytes` bulk copy.
//!
//! `raw_memcpy_bytes` is the shared disjoint-copy primitive behind strcpy /
//! strcat / strncat and the string_abi copy paths. It was rewritten from a
//! byte-at-a-time volatile loop to wide u128-block copies (copy_unaligned_16/32)
//! plus a volatile-byte tail. This gate proves the rewrite is behavior-preserving:
//! for every (length, src alignment, dst alignment) in a dense corpus the wide
//! copy is byte-for-byte identical BOTH to a trivial scalar reference AND to host
//! glibc memcpy, and the concatenated outputs hash to a pinned digest.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::string_abi::bench_raw_memcpy_bytes;
use sha2::{Digest, Sha256};
use std::ffi::c_void;

#[test]
fn raw_memcpy_matches_reference_and_glibc_over_corpus() {
    let mut hasher = Sha256::new();
    let mut checked = 0u64;

    let lengths = [
        0usize, 1, 2, 7, 8, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65, 100, 127, 128, 129, 255,
        256, 257, 1000, 1024, 4096, 4097,
    ];

    // Independent src/dst alignment offsets (disjoint buffers) to exercise the
    // unaligned u128 loads/stores at every relative phase.
    for &src_off in &[0usize, 1, 3, 7] {
        for &dst_off in &[0usize, 1, 3, 7] {
            for &len in &lengths {
                // Deterministic source content; fresh dst per case.
                let src: Vec<u8> = (0..src_off + len)
                    .map(|k| (k as u8).wrapping_mul(37).wrapping_add(11))
                    .collect();

                let mut fl = vec![0xA5u8; dst_off + len + 4];
                let mut rf = vec![0xA5u8; dst_off + len + 4];
                let mut gl = vec![0xA5u8; dst_off + len + 4];

                unsafe {
                    bench_raw_memcpy_bytes(
                        fl.as_mut_ptr().add(dst_off),
                        src.as_ptr().add(src_off),
                        len,
                    );
                }
                // Scalar reference.
                rf[dst_off..(dst_off + len)].copy_from_slice(&src[src_off..(src_off + len)]);
                // Host glibc memcpy.
                unsafe {
                    libc::memcpy(
                        gl.as_mut_ptr().add(dst_off).cast::<c_void>(),
                        src.as_ptr().add(src_off).cast::<c_void>(),
                        len,
                    );
                }

                assert_eq!(
                    fl, rf,
                    "wide copy != scalar reference (src_off={src_off} dst_off={dst_off} len={len})"
                );
                assert_eq!(
                    fl, gl,
                    "wide copy != glibc memcpy (src_off={src_off} dst_off={dst_off} len={len})"
                );
                hasher.update(&fl);
                checked += 1;
            }
        }
    }

    assert_eq!(checked, 4 * 4 * 27, "corpus size drifted");
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        digest, "02c7b754d9fc0e1ef116009552a67f0bad4b5c8e072bd0158971f288240b3917",
        "memcpy wide-copy golden corpus hash drifted: got {digest}"
    );
}
