#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Isomorphism + golden gate for the 32-byte portable-SIMD NUL scan added to the
//! bounded path of `scan_c_string` (used by strnlen and the bounded/repair-path
//! length scans of strcmp/strcasecmp/strncmp/strncasecmp). Widened from 8-byte
//! SWAR to AVX width to close strnlen's ~1.79x throughput gap vs glibc.
//! 300000 random (buffer, NUL position, n) triples — with n straddling the
//! 32-byte panel and NULs at every offset — agree exactly with host glibc
//! strnlen; a golden sha256 of the length stream pins the behavior.

use std::os::raw::c_char;
use frankenlibc_abi::string_abi as fa;
use sha2::{Digest, Sha256};

unsafe extern "C" {
    fn strnlen(s: *const c_char, n: usize) -> usize;
}

#[test]
fn strnlen_matches_glibc() {
    let mut seed: u64 = 0x1357;
    let mut rng = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut h = Sha256::new();
    let mut div = 0u32;
    for _ in 0..300000 {
        let buflen = (rng() as usize) % 140;
        let mut buf: Vec<u8> = (0..buflen).map(|_| ((rng() % 90) + 33) as u8).collect();
        if rng() & 1 == 0 && buflen > 0 {
            let k = (rng() as usize) % buflen;
            buf[k] = 0;
        }
        buf.push(0); // guaranteed terminator
        let n = (rng() as usize) % (buflen + 40);
        let fl = unsafe { fa::strnlen(buf.as_ptr() as *const c_char, n) };
        let gl = unsafe { strnlen(buf.as_ptr() as *const c_char, n) };
        if fl != gl {
            div += 1;
            if div <= 5 {
                eprintln!("DIV n={n} buflen={buflen} fl={fl} gl={gl}");
            }
        }
        h.update((fl as u64).to_le_bytes());
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("strnlen golden sha256: {hex}");
    assert_eq!(div, 0, "strnlen diverged from glibc in {div} cases");
    assert_eq!(
        hex,
        "fc35325dad341a14ff0be7d64af0a429f9695a9d4ae7d5e8aed982e040848efe",
        "strnlen golden changed"
    );
}
