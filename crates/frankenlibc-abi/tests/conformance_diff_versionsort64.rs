#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc versionsort64/alphasort64 oracle

//! Differential gate for the LFS dirent64 comparators versionsort64/alphasort64
//! (bd-fpourd) — previously uncovered. versionsort64 orders by strverscmp
//! (numeric-aware: file9 < file10); alphasort64 by strcoll (lexical: file10 <
//! file9). For each name pair fl's comparator must return the SAME sign as host
//! glibc. dirent and dirent64 share a layout on x86-64. No mocks.

use std::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
    fn versionsort64(a: *mut *const libc::dirent64, b: *mut *const libc::dirent64) -> c_int;
    fn alphasort64(a: *mut *const libc::dirent64, b: *mut *const libc::dirent64) -> c_int;
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
    for &(na, nb) in PAIRS {
        let a = make(na);
        let b = make(nb);
        let pa: *const libc::dirent64 = &a;
        let pb: *const libc::dirent64 = &b;
        let g = unsafe {
            versionsort64(&pa as *const _ as *mut _, &pb as *const _ as *mut _)
        };
        let f = unsafe {
            frankenlibc_abi::unistd_abi::versionsort64(
                &pa as *const _ as *mut *const libc::dirent,
                &pb as *const _ as *mut *const libc::dirent,
            )
        };
        assert_eq!(f.signum(), g.signum(), "versionsort64({na:?},{nb:?}): fl={f} glibc={g}");
    }
}

#[test]
fn alphasort64_matches_glibc_sign() {
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
        assert_eq!(f.signum(), g.signum(), "alphasort64({na:?},{nb:?}): fl={f} glibc={g}");
    }
}
