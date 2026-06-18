#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc putpwent/putgrent oracle + real temp files

//! Differential gate for putpwent/putgrent line formatting (bd-1d6wij), pinning
//! the NIS +/- fixes (bd-nuuk1l, bd-0vv4zb). For an ordinary entry the line is
//! "name:passwd:uid:gid:gecos:dir:shell"; for a NIS-style entry whose name
//! begins with '+'/'-', glibc leaves the uid/gid (resp. gid) field EMPTY when
//! its value is 0. fl's output must match host glibc byte-for-byte. Uses real
//! FILE* streams (fl writes via fl's stdio, glibc via glibc's) and compares the
//! resulting files. No mocks.

use std::ffi::{c_char, c_int, c_void, CString};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn putpwent(pw: *const libc::passwd, f: *mut c_void) -> c_int;
        pub fn putgrent(gr: *const libc::group, f: *mut c_void) -> c_int;
    }
}
use frankenlibc_abi::glibc_internal_abi as fle;
use frankenlibc_abi::stdio_abi as flio;

static CNT: AtomicU64 = AtomicU64::new(0);
fn tmp(tag: &str) -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-putpw-{}-{}-{}", std::process::id(), tag, n));
    let c = CString::new(p.to_string_lossy().as_bytes()).unwrap();
    (p, c)
}

fn fl_write_pw(pw: &libc::passwd) -> Vec<u8> {
    let (path, c) = tmp("flp");
    let f = unsafe { flio::fopen(c.as_ptr().cast::<c_char>(), c"w".as_ptr().cast::<c_char>()) };
    assert!(!f.is_null());
    unsafe { fle::putpwent(pw as *const libc::passwd as *const c_void, f) };
    unsafe { flio::fclose(f) };
    let b = std::fs::read(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    b
}
fn g_write_pw(pw: &libc::passwd) -> Vec<u8> {
    let (path, c) = tmp("gp");
    let f = unsafe { g::fopen(c.as_ptr(), c"w".as_ptr()) };
    assert!(!f.is_null());
    unsafe { g::putpwent(pw, f) };
    unsafe { g::fclose(f) };
    let b = std::fs::read(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    b
}
fn fl_write_gr(gr: &libc::group) -> Vec<u8> {
    let (path, c) = tmp("flg");
    let f = unsafe { flio::fopen(c.as_ptr().cast::<c_char>(), c"w".as_ptr().cast::<c_char>()) };
    assert!(!f.is_null());
    unsafe { fle::putgrent(gr as *const libc::group as *const c_void, f) };
    unsafe { flio::fclose(f) };
    let b = std::fs::read(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    b
}
fn g_write_gr(gr: &libc::group) -> Vec<u8> {
    let (path, c) = tmp("gg");
    let f = unsafe { g::fopen(c.as_ptr(), c"w".as_ptr()) };
    assert!(!f.is_null());
    unsafe { g::putgrent(gr, f) };
    unsafe { g::fclose(f) };
    let b = std::fs::read(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    b
}

#[test]
fn putpwent_matches_glibc() {
    let cases: &[(&str, u32, u32)] = &[
        ("user", 1000, 1000), // ordinary
        ("+", 0, 0),          // NIS: uid+gid empty
        ("+nis", 0, 0),       // NIS: uid+gid empty
        ("-blocked", 0, 0),   // NIS minus
        ("+keep", 7, 0),      // NIS: uid kept, gid empty
    ];
    for &(name, uid, gid) in cases {
        let nm = CString::new(name).unwrap();
        let pwd = CString::new("x").unwrap();
        let empty = CString::new("").unwrap();
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        pw.pw_name = nm.as_ptr() as *mut c_char;
        pw.pw_passwd = pwd.as_ptr() as *mut c_char;
        pw.pw_uid = uid;
        pw.pw_gid = gid;
        pw.pw_gecos = empty.as_ptr() as *mut c_char;
        pw.pw_dir = empty.as_ptr() as *mut c_char;
        pw.pw_shell = empty.as_ptr() as *mut c_char;
        let f = fl_write_pw(&pw);
        let gg = g_write_pw(&pw);
        assert_eq!(f, gg, "putpwent(name={name:?}) fl={:?} glibc={:?}",
            String::from_utf8_lossy(&f), String::from_utf8_lossy(&gg));
    }
}

#[test]
fn putgrent_matches_glibc() {
    let cases: &[(&str, u32)] = &[
        ("staff", 50),  // ordinary
        ("+", 0),       // NIS: gid empty
        ("+nis", 0),    // NIS: gid empty
        ("-blk", 0),    // NIS minus
        ("+keep", 9),   // NIS: gid kept
    ];
    for &(name, gid) in cases {
        let nm = CString::new(name).unwrap();
        let pwd = CString::new("x").unwrap();
        let mut members: [*mut c_char; 1] = [std::ptr::null_mut()];
        let mut gr: libc::group = unsafe { std::mem::zeroed() };
        gr.gr_name = nm.as_ptr() as *mut c_char;
        gr.gr_passwd = pwd.as_ptr() as *mut c_char;
        gr.gr_gid = gid;
        gr.gr_mem = members.as_mut_ptr();
        let f = fl_write_gr(&gr);
        let gg = g_write_gr(&gr);
        assert_eq!(f, gg, "putgrent(name={name:?}) fl={:?} glibc={:?}",
            String::from_utf8_lossy(&f), String::from_utf8_lossy(&gg));
    }
}
