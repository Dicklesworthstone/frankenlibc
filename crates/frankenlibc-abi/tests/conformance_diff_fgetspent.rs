#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fgetspent oracle over a controlled temp file

//! Differential gate for fgetspent vs host glibc (bd-588bg4) — previously
//! fl-internal only (conformance_diff_sgetspent covers sgetspent, the STRING
//! parser; fgetspent is the distinct stream parser). Parses shadow-format
//! entries from a caller-provided stream (fully controlled, no root needed).
//! The bug-prone part is the eight long fields: empty numeric fields decode to
//! -1 (and the unsigned sp_flag to (unsigned long)-1). Each impl opens the same
//! temp file with its own fopen and iterates with its own fgetspent; entries
//! compared field-by-field. Strings copied before static-buffer reuse. No mocks.

use std::ffi::{c_char, c_long, c_void, CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};

#[repr(C)]
struct Spwd {
    sp_namp: *mut c_char,
    sp_pwdp: *mut c_char,
    sp_lstchg: c_long,
    sp_min: c_long,
    sp_max: c_long,
    sp_warn: c_long,
    sp_inact: c_long,
    sp_expire: c_long,
    sp_flag: u64,
}

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> i32;
        pub fn fgetspent(f: *mut c_void) -> *mut Spwd;
    }
}
use frankenlibc_abi::{stdio_abi as fls, unistd_abi as flu};

static CNT: AtomicU64 = AtomicU64::new(0);

const SHADOW: &str = "root:$6$abc$hash:19000:0:99999:7:::\n\
daemon:*:18000:0:99999:7:::\n\
user:!:19500:1:90:14:30:20000:\n\
allset:$1$x$y:100:5:200:10:15:25000:42\n";

#[derive(PartialEq, Eq, Debug, Clone)]
struct Sp {
    namp: String,
    pwdp: String,
    lstchg: c_long,
    min: c_long,
    max: c_long,
    warn: c_long,
    inact: c_long,
    expire: c_long,
    flag: u64,
}

unsafe fn s(p: *const c_char) -> String {
    if p.is_null() { String::new() } else { unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned() }
}

unsafe fn rec(sp: &Spwd) -> Sp {
    Sp {
        namp: unsafe { s(sp.sp_namp) },
        pwdp: unsafe { s(sp.sp_pwdp) },
        lstchg: sp.sp_lstchg,
        min: sp.sp_min,
        max: sp.sp_max,
        warn: sp.sp_warn,
        inact: sp.sp_inact,
        expire: sp.sp_expire,
        flag: sp.sp_flag,
    }
}

fn parse_fl(path: &CStr) -> Vec<Sp> {
    let mut out = Vec::new();
    unsafe {
        let f = fls::fopen(path.as_ptr(), c"r".as_ptr().cast());
        assert!(!f.is_null(), "fl fopen");
        loop {
            let p = flu::fgetspent(f) as *mut Spwd;
            if p.is_null() { break; }
            out.push(rec(&*p));
        }
        fls::fclose(f);
    }
    out
}

fn parse_glibc(path: &CStr) -> Vec<Sp> {
    let mut out = Vec::new();
    unsafe {
        let f = g::fopen(path.as_ptr(), c"r".as_ptr());
        assert!(!f.is_null(), "glibc fopen");
        loop {
            let p = g::fgetspent(f);
            if p.is_null() { break; }
            out.push(rec(&*p));
        }
        g::fclose(f);
    }
    out
}

#[test]
fn fgetspent_matches_glibc() {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-fgetspent-{}-{}", std::process::id(), n));
    std::fs::write(&p, SHADOW).unwrap();
    let cpath = CString::new(p.to_string_lossy().as_bytes()).unwrap();

    let fl_entries = parse_fl(&cpath);
    let g_entries = parse_glibc(&cpath);
    let _ = std::fs::remove_file(&p);

    assert_eq!(fl_entries.len(), g_entries.len(), "entry count: fl={} glibc={}", fl_entries.len(), g_entries.len());
    for (i, (f, gg)) in fl_entries.iter().zip(g_entries.iter()).enumerate() {
        assert_eq!(f, gg, "fgetspent entry {i}: fl={f:?} glibc={gg:?}");
    }
    assert_eq!(g_entries.len(), 4, "4 entries expected");
    // sanity: empty trailing numeric fields decode to -1.
    assert_eq!(g_entries[0].inact, -1, "empty sp_inact -> -1");
    assert_eq!(g_entries[0].expire, -1, "empty sp_expire -> -1");
}
