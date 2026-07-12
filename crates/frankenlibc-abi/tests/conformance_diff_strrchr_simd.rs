#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Isomorphism + golden + page-safety gate for the 32-byte portable-SIMD skip
//! added to the unbounded path of scan_c_string_last_byte (strrchr). A 32-byte
//! panel containing NEITHER the target byte NOR a NUL cannot change the last-match
//! index or terminate the scan, so it is advanced whole; a panel with a target or
//! NUL (or one that would cross the page) drops to the 8-byte SWAR tail. Closes a
//! ~1.4-1.5x strrchr gap vs glibc to ~1.3x (residual is per-call membrane cost).

use frankenlibc_abi::string_abi as fa;
use sha2::{Digest, Sha256};
use std::os::raw::{c_char, c_int};

unsafe extern "C" {
    fn strrchr(s: *const c_char, c: c_int) -> *mut c_char;
}

#[test]
fn strrchr_matches_glibc() {
    let mut seed: u64 = 0x99;
    let mut rng = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut h = Sha256::new();
    let mut div = 0u32;
    for _ in 0..300000 {
        let len = (rng() as usize) % 160;
        let off = (rng() as usize) % 8;
        let body: Vec<u8> = (0..len)
            .map(|_| ((rng() % 5) + b'a' as u64) as u8)
            .collect();
        let mut backing = vec![b'q'; off];
        backing.extend_from_slice(&body);
        backing.push(0);
        let p = unsafe { backing.as_ptr().add(off) } as *const c_char;
        let targets = [b'a', b'c', b'e', b'z', 0u8];
        let t = targets[(rng() as usize) % targets.len()] as c_int;
        let fl = unsafe { fa::strrchr(p, t) };
        let gl = unsafe { strrchr(p, t) };
        let fo = if fl.is_null() {
            u64::MAX
        } else {
            fl as u64 - p as u64
        };
        let go = if gl.is_null() {
            u64::MAX
        } else {
            gl as u64 - p as u64
        };
        if fo != go {
            div += 1;
            if div <= 5 {
                eprintln!("DIV len={len} off={off} t={t} fo={fo} go={go}");
            }
        }
        h.update(fo.to_le_bytes());
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("strrchr golden sha256: {hex}");
    assert_eq!(div, 0, "strrchr diverged from glibc in {div} cases");
    assert_eq!(
        hex, "daae3e091dc8a78390ced1c2226429f78aa11026ff4827e294a7b358457b52fb",
        "strrchr golden changed"
    );
}

#[test]
fn strrchr_does_not_overread_past_guard_page() {
    let page = 4096usize;
    unsafe {
        let base = libc::mmap(
            std::ptr::null_mut(),
            page * 2,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(base, libc::MAP_FAILED, "mmap failed");
        let base = base.cast::<u8>();
        assert_eq!(
            libc::mprotect(base.add(page).cast(), page, libc::PROT_NONE),
            0,
            "mprotect failed"
        );
        for back in 1..=40usize {
            let start = base.add(page - back);
            for k in 0..(back - 1) {
                *start.add(k) = b'a';
            }
            *start.add(back - 1) = 0;
            // Search for an absent byte (full scan to the NUL against the guard).
            let r = fa::strrchr(start as *const c_char, b'z' as c_int);
            assert!(
                r.is_null(),
                "strrchr should miss near guard page (back={back})"
            );
            // And for a present byte.
            if back > 1 {
                let r2 = fa::strrchr(start as *const c_char, b'a' as c_int);
                assert_eq!(
                    r2 as usize,
                    start.add(back - 2) as usize,
                    "last 'a' (back={back})"
                );
            }
        }
        libc::munmap(base.cast(), page * 2);
    }
}
