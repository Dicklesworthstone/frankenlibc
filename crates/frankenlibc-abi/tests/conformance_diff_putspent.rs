#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc putspent oracle; real temp files

//! Differential gate for putspent shadow serialization vs host glibc
//! (bd-6t592z) — previously fl-internal only (putpwent/putgrent have
//! conformance_diff_putpwent; putspent did not). putspent writes a shadow entry
//! as `name:pwd:lstchg:min:max:warn:inact:expire:flag\n`, where any long field
//! equal to -1 (and sp_flag == (unsigned long)-1) is emitted EMPTY. fl's byte
//! output must match glibc's, for a fully-populated entry and an all-unset one.
//! Each impl writes with its own fopen/putspent to a temp file; bytes compared.
//! No mocks.

use std::ffi::{c_char, c_long, c_void, CString};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> i32;
        pub fn putspent(sp: *const libc::spwd, f: *mut c_void) -> i32;
    }
}
use frankenlibc_abi::{stdio_abi as fls, unistd_abi as flu};

static CNT: AtomicU64 = AtomicU64::new(0);

struct Owned {
    _namp: CString,
    _pwdp: CString,
    sp: libc::spwd,
}

fn make(name: &str, pwd: &str, f: [c_long; 6], flag: u64) -> Owned {
    let namp = CString::new(name).unwrap();
    let pwdp = CString::new(pwd).unwrap();
    let sp = libc::spwd {
        sp_namp: namp.as_ptr() as *mut c_char,
        sp_pwdp: pwdp.as_ptr() as *mut c_char,
        sp_lstchg: f[0],
        sp_min: f[1],
        sp_max: f[2],
        sp_warn: f[3],
        sp_inact: f[4],
        sp_expire: f[5],
        sp_flag: flag,
    };
    Owned { _namp: namp, _pwdp: pwdp, sp }
}

fn tmp(tag: &str) -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-putspent-{}-{}-{}", std::process::id(), tag, n));
    let c = CString::new(p.to_string_lossy().as_bytes()).unwrap();
    (p, c)
}

fn fl_write(sp: &libc::spwd) -> Vec<u8> {
    let (path, c) = tmp("fl");
    unsafe {
        let f = fls::fopen(c.as_ptr().cast::<c_char>(), c"w".as_ptr().cast::<c_char>());
        assert!(!f.is_null());
        flu::putspent(sp, f.cast::<libc::FILE>());
        fls::fclose(f);
    }
    let b = std::fs::read(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    b
}

fn glibc_write(sp: &libc::spwd) -> Vec<u8> {
    let (path, c) = tmp("g");
    unsafe {
        let f = g::fopen(c.as_ptr(), c"w".as_ptr());
        assert!(!f.is_null());
        g::putspent(sp, f);
        g::fclose(f);
    }
    let b = std::fs::read(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    b
}

#[test]
fn putspent_matches_glibc() {
    let cases = [
        make("user", "$6$salt$hash", [19000, 0, 99999, 7, 30, 20000], 0),
        // all numeric fields unset (-1) -> emitted empty; flag = (unsigned long)-1 -> empty
        make("daemon", "*", [-1, -1, -1, -1, -1, -1], u64::MAX),
        // mixed: some set, some unset
        make("svc", "!", [18500, 1, -1, 14, -1, 25000], 0),
    ];
    for (i, o) in cases.iter().enumerate() {
        let fb = fl_write(&o.sp);
        let gb = glibc_write(&o.sp);
        assert_eq!(
            String::from_utf8_lossy(&fb),
            String::from_utf8_lossy(&gb),
            "putspent case {i}: fl={:?} glibc={:?}",
            String::from_utf8_lossy(&fb),
            String::from_utf8_lossy(&gb)
        );
    }
}
