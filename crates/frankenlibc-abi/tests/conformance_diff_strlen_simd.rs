#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Isomorphism + golden + page-safety gate for the 32-byte portable-SIMD NUL
//! scan added to the UNBOUNDED path of `scan_c_string` — the common strlen path
//! (`raw_lane_strlen_bytes`, taken for untracked strings in non-healing mode) and
//! the source-length scans of strcpy/mbstowcs/etc. Widened from the 8-byte
//! aligned SWAR loop to AVX width; strlen went from ~1.03x to ~0.73x vs glibc
//! (now faster). The 32-byte window is page-guarded: a read that would cross the
//! page boundary falls to the 8-byte aligned SWAR (which cannot cross), so it
//! never faults past a NUL into an unmapped page.

use std::os::raw::c_char;
use frankenlibc_abi::string_abi as fa;
use sha2::{Digest, Sha256};

unsafe extern "C" {
    fn strlen(s: *const c_char) -> usize;
}

#[test]
fn strlen_matches_glibc() {
    let mut seed: u64 = 0x2468;
    let mut rng = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut h = Sha256::new();
    let mut div = 0u32;
    for _ in 0..300000 {
        let len = (rng() as usize) % 150;
        let mut buf: Vec<u8> = (0..len).map(|_| ((rng() % 90) + 33) as u8).collect();
        buf.push(0);
        let off = (rng() as usize) % 8;
        let mut backing = vec![b'q'; off + buf.len()];
        backing[off..off + buf.len()].copy_from_slice(&buf);
        let p = unsafe { backing.as_ptr().add(off) } as *const c_char;
        let fl = unsafe { fa::strlen(p) };
        let gl = unsafe { strlen(p) };
        if fl != gl {
            div += 1;
            if div <= 5 {
                eprintln!("DIV len={len} off={off} fl={fl} gl={gl}");
            }
        }
        h.update((fl as u64).to_le_bytes());
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("strlen golden sha256: {hex}");
    assert_eq!(div, 0, "strlen diverged from glibc in {div} cases");
    assert_eq!(
        hex,
        "f42d28933b3e72a9bcf899510df30db5761c06f80d5d50ca113bb6535e3ca3e9",
        "strlen golden changed"
    );
}

#[test]
fn strlen_does_not_overread_past_guard_page() {
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
        // Make the second page unreadable: any read past the first page faults.
        assert_eq!(
            libc::mprotect(base.add(page).cast(), page, libc::PROT_NONE),
            0,
            "mprotect failed"
        );
        // Place NUL-terminated strings ending at every offset near the page end,
        // so the SIMD window sits right against the guard page.
        for back in 1..=40usize {
            let start = base.add(page - back);
            for k in 0..(back - 1) {
                *start.add(k) = b'a';
            }
            *start.add(back - 1) = 0;
            let len = fa::strlen(start as *const c_char);
            assert_eq!(len, back - 1, "strlen wrong near guard page (back={back})");
        }
        libc::munmap(base.cast(), page * 2);
    }
}
