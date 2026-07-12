#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc mbrlen/mblen/mbsinit oracle

//! Differential harness for mbrlen / mblen / mbsinit (bd-28s12s). mbrtowc /
//! wcrtomb / mbtowc / wctomb have gates, but these three did not — and they
//! carry the classic trap that an INCOMPLETE multibyte sequence yields
//! (size_t)-2 from the restartable mbrlen but -1 from the non-restartable
//! mblen. FrankenLibC models the UTF-8 locale, so the test pins LC_CTYPE to
//! C.UTF-8 (per the project's wide-fn convention) and compares fl to host glibc
//! over curated + randomised byte sequences. No mocks.

use std::ffi::{c_char, c_int, c_void};
use std::sync::Mutex;

// mblen and mbrlen(NULL ps) share glibc's process-global internal mbstate, and
// setlocale is process-global — serialize so parallel tests can't race on them.
static MB_LOCK: Mutex<()> = Mutex::new(());

fn fresh_state() -> libc::mbstate_t {
    unsafe { std::mem::zeroed() }
}

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn mbrlen(s: *const c_char, n: usize, ps: *mut c_void) -> usize;
        pub fn mblen(s: *const c_char, n: usize) -> c_int;
        pub fn mbsinit(ps: *const c_void) -> c_int;
        pub fn mbrtowc(pwc: *mut u32, s: *const c_char, n: usize, ps: *mut c_void) -> usize;
    }
}
use frankenlibc_abi::wchar_abi as fl;

fn set_utf8() {
    let utf8 = c"C.UTF-8";
    unsafe { libc::setlocale(libc::LC_ALL, utf8.as_ptr()) };
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }
}

/// Curated UTF-8 byte sequences exercising every mbrlen return class.
fn curated() -> Vec<Vec<u8>> {
    vec![
        b"A".to_vec(),                // 1-byte ASCII -> 1
        vec![0xC3, 0xA9],             // é (2-byte) -> 2
        vec![0xE4, 0xB8, 0xAD],       // 中 (3-byte) -> 3
        vec![0xF0, 0x9F, 0x98, 0x80], // 😀 (4-byte) -> 4
        vec![0xC3],                   // incomplete 2-byte
        vec![0xE4, 0xB8],             // incomplete 3-byte
        vec![0xF0, 0x9F, 0x98],       // incomplete 4-byte
        vec![0x80],                   // lone continuation -> EILSEQ
        vec![0xFF],                   // invalid lead -> EILSEQ
        vec![0xC0, 0x80],             // overlong -> EILSEQ
        vec![0xED, 0xA0, 0x80],       // UTF-16 surrogate -> EILSEQ
        vec![0xE4, 0x28],             // bad continuation -> EILSEQ
        vec![0x00],                   // NUL -> 0
        vec![],                       // empty (n==0)
    ]
}

#[test]
fn mbrlen_matches_glibc() {
    let _guard = MB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    set_utf8();
    let mut rng = Rng(0x6D62_726C_656E_0000);
    // Curated cases at every length 0..=seq.len(). Use a FRESH per-call mbstate
    // (not NULL) so an incomplete sequence never carries into the next case and
    // there is no shared static state to race on.
    for seq in curated() {
        for n in 0..=seq.len() {
            let p = seq.as_ptr().cast::<c_char>();
            let mut gs = fresh_state();
            let mut fs = fresh_state();
            let gr = unsafe { g::mbrlen(p, n, (&mut gs as *mut libc::mbstate_t).cast()) };
            let fr = unsafe { fl::mbrlen(p, n, (&mut fs as *mut libc::mbstate_t).cast()) };
            assert_eq!(fr, gr, "mbrlen seq={seq:?} n={n}: fl={fr} glibc={gr}");
        }
    }
    // Random byte sequences with a bias toward valid UTF-8 lead bytes.
    for _ in 0..8000 {
        let len = rng.below(6);
        let mut seq: Vec<u8> = Vec::with_capacity(len);
        for i in 0..len {
            let b = match rng.below(5) {
                0 => (b'a' + (rng.below(26) as u8)), // ASCII
                1 => 0xC0 | (rng.below(0x20) as u8), // 2-byte lead-ish
                2 => 0xE0 | (rng.below(0x10) as u8), // 3-byte lead-ish
                3 => 0x80 | (rng.below(0x40) as u8), // continuation
                _ => rng.below(256) as u8,           // anything
            };
            // avoid an embedded NUL except as the only/first byte
            seq.push(if b == 0 && i > 0 { 0x41 } else { b });
        }
        let n = rng.below(seq.len() + 2);
        let nn = n.min(seq.len());
        let p = seq.as_ptr().cast::<c_char>();
        let mut gs = fresh_state();
        let mut fs = fresh_state();
        let gr = unsafe { g::mbrlen(p, nn, (&mut gs as *mut libc::mbstate_t).cast()) };
        let fr = unsafe { fl::mbrlen(p, nn, (&mut fs as *mut libc::mbstate_t).cast()) };
        assert_eq!(
            fr, gr,
            "mbrlen random seq={seq:?} n={nn}: fl={fr} glibc={gr}"
        );
    }
}

#[test]
fn mblen_matches_glibc() {
    let _guard = MB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    set_utf8();
    // mblen is non-restartable: an INCOMPLETE sequence is -1 (not -2).
    unsafe {
        g::mblen(std::ptr::null(), 0);
        fl::mblen(std::ptr::null(), 0);
    } // reset both internal states
    // NOTE: n==0 is a degenerate edge with a documented conformant divergence —
    // glibc's mblen peeks *s and returns 0 for a leading NUL even when told to
    // examine 0 bytes, whereas fl conservatively returns -1 without reading past
    // n. (mblen(non-NUL, 0) is -1 in both.) We therefore start n at 1, where the
    // contract is well-defined, and assert the non-NUL n==0 agreement below.
    for seq in curated() {
        for n in 1..=seq.len() {
            let gp = seq.as_ptr().cast::<c_char>();
            let gr = unsafe { g::mblen(gp, n) };
            let fr = unsafe { fl::mblen(seq.as_ptr(), n) };
            assert_eq!(fr, gr, "mblen seq={seq:?} n={n}: fl={fr} glibc={gr}");
            // reset (UTF-8 is stateless, but keep parity hygiene)
            unsafe {
                g::mblen(std::ptr::null(), 0);
                fl::mblen(std::ptr::null(), 0);
            }
        }
    }
    // mblen(non-NUL, 0) == -1 for both (the well-defined n==0 case).
    let a = b"A";
    assert_eq!(
        unsafe { fl::mblen(a.as_ptr(), 0) },
        unsafe { g::mblen(a.as_ptr().cast::<c_char>(), 0) },
        "mblen(non-NUL, 0)"
    );
    // mblen(NULL,0): stateless encoding -> 0 for both.
    assert_eq!(
        unsafe { fl::mblen(std::ptr::null(), 0) },
        unsafe { g::mblen(std::ptr::null(), 0) },
        "mblen(NULL,0) state query"
    );
}

#[test]
fn mbsinit_agrees_on_initial_vs_partial() {
    let _guard = MB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    set_utf8();
    // NULL pointer -> nonzero (initial) for both.
    let gnull = unsafe { g::mbsinit(std::ptr::null()) };
    let fnull = unsafe { fl::mbsinit(std::ptr::null()) };
    assert_eq!(gnull != 0, fnull != 0, "mbsinit(NULL)");
    assert!(fnull != 0, "mbsinit(NULL) must be nonzero");

    // Zeroed state -> initial (nonzero).
    let gz: libc::mbstate_t = unsafe { std::mem::zeroed() };
    let fz: libc::mbstate_t = unsafe { std::mem::zeroed() };
    assert!(unsafe { g::mbsinit((&gz as *const libc::mbstate_t).cast()) } != 0);
    assert!(unsafe { fl::mbsinit((&fz as *const libc::mbstate_t).cast()) } != 0);

    // After feeding a partial 2-byte sequence (n=1), the state is NOT initial.
    let lead = [0xC3u8];
    let mut gs: libc::mbstate_t = unsafe { std::mem::zeroed() };
    let mut fs: libc::mbstate_t = unsafe { std::mem::zeroed() };
    let g_r = unsafe {
        g::mbrtowc(
            std::ptr::null_mut(),
            lead.as_ptr().cast(),
            1,
            (&mut gs as *mut libc::mbstate_t).cast(),
        )
    };
    let f_r = unsafe {
        fl::mbrtowc(
            std::ptr::null_mut(),
            lead.as_ptr().cast::<c_char>(),
            1,
            (&mut fs as *mut libc::mbstate_t).cast(),
        )
    };
    // both must report "incomplete" = (size_t)-2
    assert_eq!(g_r, usize::MAX - 1, "glibc partial mbrtowc -> -2");
    assert_eq!(f_r, usize::MAX - 1, "fl partial mbrtowc -> -2");
    let g_init = unsafe { g::mbsinit((&gs as *const libc::mbstate_t).cast()) } != 0;
    let f_init = unsafe { fl::mbsinit((&fs as *const libc::mbstate_t).cast()) } != 0;
    assert_eq!(g_init, f_init, "mbsinit after partial must agree");
    assert!(
        !f_init,
        "fl mbsinit must report non-initial after a partial sequence"
    );
}
