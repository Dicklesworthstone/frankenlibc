#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc versionsort64/alphasort64 oracle

//! Differential gate for the LFS dirent64 comparators versionsort64/alphasort64
//! (bd-fpourd) — previously uncovered. versionsort64 orders by strverscmp
//! (numeric-aware: file9 < file10); alphasort64 by strcoll (lexical: file10 <
//! file9). For each name pair fl's comparator must return the SAME sign as host
//! glibc. dirent and dirent64 share a layout on x86-64. No mocks.

use std::ffi::{c_char, c_int, c_void};

// Host arms are resolved with `dlsym`, not declared at link time: fl exports
// its own versionsort64/alphasort64 into this binary, so a link-time reference
// can bind to fl and leave both arms as fl — green while proving nothing
// (bd-v0388t; conformance_diff_catopen was doing exactly that in a plain debug
// build and hiding a live errno defect).
type CmpFn = unsafe extern "C" fn(*mut *const libc::dirent64, *mut *const libc::dirent64) -> c_int;

fn host_symbol(name: &std::ffi::CStr, fl_addr: usize) -> *mut c_void {
    // SAFETY: libc.so.6 is the process host libc; flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    // SAFETY: the handle came from dlopen; name is NUL-terminated.
    let raw = unsafe { libc::dlsym(handle, name.as_ptr()) };
    assert!(!raw.is_null(), "dlsym {name:?}");
    assert_ne!(
        raw as usize, fl_addr,
        "the resolved oracle IS fl's {name:?} — this gate would compare fl to itself"
    );
    raw
}

fn host_versionsort64() -> CmpFn {
    // SAFETY: resolved symbol has glibc's documented versionsort64 signature.
    unsafe {
        std::mem::transmute::<_, CmpFn>(host_symbol(
            c"versionsort64",
            frankenlibc_abi::unistd_abi::versionsort64 as usize,
        ))
    }
}

fn host_alphasort64() -> CmpFn {
    // SAFETY: resolved symbol has glibc's documented alphasort64 signature.
    unsafe {
        std::mem::transmute::<_, CmpFn>(host_symbol(
            c"alphasort64",
            frankenlibc_abi::unistd_abi::alphasort64 as usize,
        ))
    }
}

fn make(name: &str) -> libc::dirent64 {
    let mut d: libc::dirent64 = unsafe { std::mem::zeroed() };
    for (i, b) in name.bytes().enumerate().take(255) {
        d.d_name[i] = b as c_char;
    }
    d
}

const PAIRS: &[(&str, &str)] = &[
    ("file9", "file10"),
    ("file10", "file9"),
    ("a", "a"),
    ("img2", "img2"),
    ("v1.9", "v1.10"),
    ("abc", "abd"),
    ("", "x"),
    ("file001", "file1"),
];

#[test]
fn versionsort64_matches_glibc_sign() {
    let versionsort64 = host_versionsort64();
    for &(na, nb) in PAIRS {
        let a = make(na);
        let b = make(nb);
        let pa: *const libc::dirent64 = &a;
        let pb: *const libc::dirent64 = &b;
        let g = unsafe { versionsort64(&pa as *const _ as *mut _, &pb as *const _ as *mut _) };
        let f = unsafe {
            frankenlibc_abi::unistd_abi::versionsort64(
                &pa as *const _ as *mut *const libc::dirent,
                &pb as *const _ as *mut *const libc::dirent,
            )
        };
        assert_eq!(
            f.signum(),
            g.signum(),
            "versionsort64({na:?},{nb:?}): fl={f} glibc={g}"
        );
    }
}

#[test]
fn alphasort64_matches_glibc_sign() {
    let alphasort64 = host_alphasort64();
    for &(na, nb) in PAIRS {
        let a = make(na);
        let b = make(nb);
        let pa: *const libc::dirent64 = &a;
        let pb: *const libc::dirent64 = &b;
        let g = unsafe { alphasort64(&pa as *const _ as *mut _, &pb as *const _ as *mut _) };
        let f = unsafe {
            frankenlibc_abi::unistd_abi::alphasort64(
                &pa as *const _ as *mut *const c_void,
                &pb as *const _ as *mut *const c_void,
            )
        };
        assert_eq!(
            f.signum(),
            g.signum(),
            "alphasort64({na:?},{nb:?}): fl={f} glibc={g}"
        );
    }
}
