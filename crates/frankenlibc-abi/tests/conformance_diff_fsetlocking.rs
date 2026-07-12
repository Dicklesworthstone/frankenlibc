#![cfg(all(target_os = "linux", not(feature = "standalone")))]
#![allow(unsafe_code)] // live host-glibc __fsetlocking oracle + real FILE* streams

//! Differential gate for `__fsetlocking` (bd-zwtrcz). fl previously ignored the
//! `type` argument and the stream, always returning 2 (BYCALLER) — wrong: glibc
//! streams default to FSETLOCKING_INTERNAL (1), a QUERY(0) reports the current
//! mode, and an INTERNAL(1)/BYCALLER(2) set returns the PREVIOUS mode and is
//! sticky. This gate runs an identical query/set sequence on a fresh fl stream
//! and a fresh host-glibc stream and asserts the per-step result agrees.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

type File = c_void;
const QUERY: c_int = 0; // FSETLOCKING_QUERY
const INTERNAL: c_int = 1; // FSETLOCKING_INTERNAL
const BYCALLER: c_int = 2; // FSETLOCKING_BYCALLER

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(path: *const c_char, mode: *const c_char) -> *mut File;
        pub fn fclose(f: *mut File) -> c_int;
        pub fn __fsetlocking(f: *mut File, typ: c_int) -> c_int;
    }
}
use frankenlibc_abi::glibc_internal_abi::__fsetlocking as fl_fsetlocking;
use frankenlibc_abi::stdio_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);
fn temp_path() -> std::ffi::CString {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-fsetlk-{}-{}", std::process::id(), n));
    std::fs::write(&p, b"data\n").unwrap();
    std::ffi::CString::new(p.to_string_lossy().as_bytes()).unwrap()
}

/// Run a sequence of __fsetlocking `types` on a fresh stream of each impl and
/// return the per-step results (glibc, fl).
fn run_seq(types: &[c_int]) -> (Vec<c_int>, Vec<c_int>) {
    let cm = c"w+";
    let gp = temp_path();
    let fp = temp_path();
    let gs = unsafe { g::fopen(gp.as_ptr(), cm.as_ptr()) };
    let fs = unsafe { fl::fopen(fp.as_ptr().cast::<c_char>(), cm.as_ptr().cast::<c_char>()) };
    assert!(!gs.is_null() && !fs.is_null());
    let mut gv = Vec::new();
    let mut fv = Vec::new();
    for &t in types {
        gv.push(unsafe { g::__fsetlocking(gs, t) });
        fv.push(unsafe { fl_fsetlocking(fs, t) });
    }
    unsafe {
        g::fclose(gs);
        fl::fclose(fs);
    }
    (gv, fv)
}

#[test]
fn fsetlocking_default_is_internal() {
    let (g, f) = run_seq(&[QUERY]);
    assert_eq!(f, g, "query default: fl={f:?} glibc={g:?}");
    assert_eq!(
        f,
        vec![INTERNAL],
        "default locking mode must be INTERNAL(1)"
    );
}

#[test]
fn fsetlocking_set_returns_previous_and_is_sticky() {
    // query(1) -> set BYCALLER returns prev(1) -> query(2) -> set INTERNAL
    // returns prev(2) -> query(1).
    let seq = [QUERY, BYCALLER, QUERY, INTERNAL, QUERY];
    let (g, f) = run_seq(&seq);
    assert_eq!(f, g, "set/query sequence: fl={f:?} glibc={g:?}");
    assert_eq!(
        f,
        vec![INTERNAL, INTERNAL, BYCALLER, BYCALLER, INTERNAL],
        "fsetlocking set must return previous mode and stick"
    );
}

#[test]
fn fsetlocking_query_does_not_change_mode() {
    // Repeated QUERY never changes the mode; after BYCALLER it stays BYCALLER.
    let seq = [QUERY, QUERY, BYCALLER, QUERY, QUERY];
    let (g, f) = run_seq(&seq);
    assert_eq!(f, g, "query-stability seq: fl={f:?} glibc={g:?}");
    assert_eq!(f, vec![INTERNAL, INTERNAL, INTERNAL, BYCALLER, BYCALLER]);
}
