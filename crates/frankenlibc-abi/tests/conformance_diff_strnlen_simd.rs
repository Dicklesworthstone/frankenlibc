#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Isomorphism + golden gate for the 32-byte portable-SIMD NUL scan added to the
//! bounded path of `scan_c_string` (used by strnlen and the bounded/repair-path
//! length scans of strcmp/strcasecmp/strncmp/strncasecmp). Widened from 8-byte
//! SWAR to AVX width to close strnlen's ~1.79x throughput gap vs glibc.
//! 300000 random (buffer, NUL position, n) triples — with n straddling the
//! 32-byte panel and NULs at every offset — agree exactly with host glibc
//! strnlen; a golden sha256 of the length stream pins the behavior.

use frankenlibc_abi::string_abi as fa;
use sha2::{Digest, Sha256};
use std::os::raw::c_char;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

/// The host arm is resolved with `dlsym`, not declared at link time. fl exports
/// this symbol into this test binary, so a link-time reference can bind to fl
/// and leave BOTH arms as fl -- green while comparing nothing (bd-v0388t). That
/// matters especially here: this gate covers a hand-written SIMD kernel, whose
/// whole risk is diverging from the scalar contract at a vector boundary.

type StrnlenFn = unsafe extern "C" fn(*const c_char, usize) -> usize;

fn host_strnlen() -> StrnlenFn {
    // SAFETY: signature matches POSIX strnlen exactly.
    unsafe {
        dlsym_oracle::host_fn(
            c"strnlen",
            frankenlibc_abi::string_abi::strnlen as *const (),
        )
    }
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
        let gl = unsafe { host_strnlen()(buf.as_ptr() as *const c_char, n) };
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
        hex, "fc35325dad341a14ff0be7d64af0a429f9695a9d4ae7d5e8aed982e040848efe",
        "strnlen golden changed"
    );
}

/// Bounds of 256+ bytes and bounds that cross a page. In the baseline x86-64
/// build a bound under 256 that stays in its page is scanned inline; anything
/// else is split at page ends, and spans of 256+ go to the AVX2 twin of the
/// scanner on CPUs with AVX2 (bd-rc0923-epic-eeuy4f.13). Starts are placed
/// relative to a page boundary so the first span is 4096, 4095, 256, 255, 196,
/// 96 or 1 bytes long, i.e. on both sides of the threshold. Filler bytes are
/// nonzero but trip the SWAR zero test's candidates (0x80, 0x81, 0x01, 0xFF).
/// Every result must equal host glibc and `min(NUL index, n)`.
#[test]
fn strnlen_long_bounds_match_glibc() {
    const PAGE: usize = 4096;
    let filler = [0x80u8, 0xFF, 0x01, 0x7F, b'a', 0xFE, 0x81];
    let mut buf: Vec<u8> = (0..5 * PAGE).map(|i| filler[i % filler.len()]).collect();
    let page0 = (PAGE - (buf.as_ptr() as usize & (PAGE - 1))) & (PAGE - 1);
    let mut compared = 0usize;
    for page_off in [
        0usize,
        1,
        63,
        PAGE - 256,
        PAGE - 255,
        PAGE - 196,
        PAGE - 96,
        PAGE - 1,
    ] {
        let start = page0 + page_off;
        let avail = buf.len() - start;
        for nul in [
            None,
            Some(0usize),
            Some(1),
            Some(15),
            Some(16),
            Some(31),
            Some(32),
            Some(63),
            Some(64),
            Some(127),
            Some(128),
            Some(255),
            Some(256),
            Some(257),
            Some(1000),
            Some(4095),
            Some(4096),
            Some(5000),
        ] {
            if let Some(k) = nul {
                buf[start + k] = 0;
            }
            let mut bounds = vec![255usize, 256, 257, 300, 1024, 4096, 4097, 8000, avail];
            if nul.is_some() {
                // A terminator inside the buffer makes an unbounded ceiling legal.
                bounds.push(usize::MAX);
            }
            let p = buf[start..].as_ptr().cast::<c_char>();
            for n in bounds {
                let gl = unsafe { host_strnlen()(p, n) };
                let fl = unsafe { fa::strnlen(p, n) };
                let want = nul.map_or(n, |k| k.min(n));
                assert_eq!(
                    fl, gl,
                    "strnlen(page_off={page_off}, nul={nul:?}, n={n}): fl={fl} glibc={gl}"
                );
                assert_eq!(
                    fl, want,
                    "strnlen(page_off={page_off}, nul={nul:?}, n={n}) must be min(NUL, n)"
                );
                compared += 1;
            }
            if let Some(k) = nul {
                buf[start + k] = filler[(start + k) % filler.len()];
            }
        }
    }
    assert_eq!(compared, 8 * (9 + 17 * 10));
}
