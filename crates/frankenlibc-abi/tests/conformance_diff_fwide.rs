#![cfg(all(target_os = "linux", not(feature = "standalone")))]
#![allow(unsafe_code)] // live host-glibc fwide oracle + real FILE* streams

//! Differential gate for `fwide` orientation (bd-ifu9ll). fwide previously
//! ignored `mode` and always returned 0 for regular streams — never setting
//! wide/byte orientation. glibc sets the orientation on the first fwide call
//! with a non-zero mode (wide for >0, byte for <0), it is sticky thereafter,
//! and a 0 mode only queries. This gate runs identical fwide sequences on a
//! fresh fl stream and a fresh host-glibc stream and asserts the orientation
//! SIGN agrees at each step (glibc may return any positive/negative value).

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

type File = c_void;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(path: *const c_char, mode: *const c_char) -> *mut File;
        pub fn fclose(f: *mut File) -> c_int;
        pub fn fwide(f: *mut File, mode: c_int) -> c_int;
    }
}
use frankenlibc_abi::glibc_internal_abi::fwide as fl_fwide;
use frankenlibc_abi::stdio_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);
fn temp_path() -> std::ffi::CString {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-fwide-{}-{}", std::process::id(), n));
    std::fs::write(&p, b"data\n").unwrap();
    std::ffi::CString::new(p.to_string_lossy().as_bytes()).unwrap()
}

fn sgn(x: c_int) -> i32 {
    x.signum()
}

/// Run a sequence of fwide `modes` on a fresh stream of each implementation and
/// return the per-step orientation SIGN for (glibc, fl).
fn run_seq(modes: &[c_int]) -> (Vec<i32>, Vec<i32>) {
    let cm = c"w+"; // read+write so neither direction is forced by open mode
    let gp = temp_path();
    let fp = temp_path();
    let gs = unsafe { g::fopen(gp.as_ptr(), cm.as_ptr()) };
    let fs = unsafe { fl::fopen(fp.as_ptr().cast::<c_char>(), cm.as_ptr().cast::<c_char>()) };
    assert!(!gs.is_null() && !fs.is_null());
    let mut gv = Vec::new();
    let mut fv = Vec::new();
    for &m in modes {
        gv.push(sgn(unsafe { g::fwide(gs, m) }));
        fv.push(sgn(unsafe { fl_fwide(fs, m) }));
    }
    unsafe {
        g::fclose(gs);
        fl::fclose(fs);
    }
    (gv, fv)
}

#[test]
fn fwide_query_on_fresh_stream_is_unset() {
    let (g, f) = run_seq(&[0]);
    assert_eq!(f, g, "fwide(0) on fresh: fl={f:?} glibc={g:?}");
    assert_eq!(f, vec![0], "fresh stream must be unoriented");
}

#[test]
fn fwide_sets_wide_and_is_sticky() {
    // set wide, re-query, try to flip to byte (must stay wide).
    let (g, f) = run_seq(&[1, 0, -1, 5]);
    assert_eq!(f, g, "wide-sticky seq: fl={f:?} glibc={g:?}");
    assert_eq!(f, vec![1, 1, 1, 1], "orientation must stay wide once set");
}

#[test]
fn fwide_sets_byte_and_is_sticky() {
    let (g, f) = run_seq(&[-1, 0, 1, -9]);
    assert_eq!(f, g, "byte-sticky seq: fl={f:?} glibc={g:?}");
    assert_eq!(
        f,
        vec![-1, -1, -1, -1],
        "orientation must stay byte once set"
    );
}

#[test]
fn fwide_matches_glibc_across_initial_modes() {
    for first in [-3, -1, 0, 1, 7] {
        let (g, f) = run_seq(&[first, 0]);
        assert_eq!(f, g, "fwide initial mode={first}: fl={f:?} glibc={g:?}");
    }
}
