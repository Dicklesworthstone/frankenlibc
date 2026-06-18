#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fgetspent_r oracle; real temp files

//! Differential gate for fgetspent_r (bd-pij3nh) — the reentrant /etc/shadow
//! line parser had no differential gate. Distinct from pwd/grp via the nine
//! shadow fields, the long numeric ones (lstchg/min/max/warn/inact/expire/flag)
//! being -1 when empty. Parses shadow lines from a temp file into a caller
//! struct spwd + scratch buffer; compares each entry's name + the seven numeric
//! fields, the end-of-stream result (ENOENT + NULL), and the small-buffer
//! ERANGE path, vs glibc. No mocks.

use std::ffi::{c_char, c_int, c_long, c_void, CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn fgetspent_r(stream: *mut c_void, spbuf: *mut libc::spwd, buf: *mut c_char, buflen: usize, result: *mut *mut libc::spwd) -> c_int;
    }
}
use frankenlibc_abi::{stdio_abi as fls, unistd_abi as flu};

static CNT: AtomicU64 = AtomicU64::new(0);
fn tmp() -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-fgetspent-{}-{}", std::process::id(), n));
    // entry 1: several empty trailing fields -> -1; entry 2: all numeric set.
    std::fs::write(&p, b"root:$6$abc$hash:19000:0:99999:7:::\nsvc:!:18000:1:60000:14:30:25000:0\n").unwrap();
    (p.clone(), CString::new(p.to_string_lossy().as_bytes()).unwrap())
}

fn nums(sp: &libc::spwd) -> (String, c_long, c_long, c_long, c_long, c_long, c_long, c_long) {
    let name = if sp.sp_namp.is_null() { String::new() } else { unsafe { CStr::from_ptr(sp.sp_namp) }.to_string_lossy().into_owned() };
    (name, sp.sp_lstchg, sp.sp_min, sp.sp_max, sp.sp_warn, sp.sp_inact, sp.sp_expire, sp.sp_flag as c_long)
}

type Entry = (i32, bool, Option<(String, c_long, c_long, c_long, c_long, c_long, c_long, c_long)>);

fn glibc_parse(path: &CString) -> Vec<Entry> {
    let mut out = Vec::new();
    unsafe {
        let f = g::fopen(path.as_ptr(), c"r".as_ptr());
        assert!(!f.is_null());
        for _ in 0..3 {
            let mut sp: libc::spwd = std::mem::zeroed();
            let mut buf = [0u8; 1024];
            let mut res: *mut libc::spwd = std::ptr::null_mut();
            let rc = g::fgetspent_r(f, &mut sp, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res);
            out.push((rc, !res.is_null(), if !res.is_null() { Some(nums(&sp)) } else { None }));
        }
        g::fclose(f);
    }
    out
}
fn fl_parse(path: &CString) -> Vec<Entry> {
    let mut out = Vec::new();
    unsafe {
        let f = fls::fopen(path.as_ptr().cast(), c"r".as_ptr().cast());
        assert!(!f.is_null());
        for _ in 0..3 {
            let mut sp: libc::spwd = std::mem::zeroed();
            let mut buf = [0u8; 1024];
            let mut res: *mut libc::spwd = std::ptr::null_mut();
            let rc = flu::fgetspent_r(f.cast(), &mut sp, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res);
            out.push((rc, !res.is_null(), if !res.is_null() { Some(nums(&sp)) } else { None }));
        }
        fls::fclose(f);
    }
    out
}

#[test]
fn fgetspent_r_matches_glibc() {
    let (path, c) = tmp();
    let g = glibc_parse(&c);
    let f = fl_parse(&c);
    let _ = std::fs::remove_file(&path);
    assert_eq!(f, g, "fgetspent_r entries: fl={f:?} glibc={g:?}");
    // entry 1: inact/expire empty -> -1
    if let Some(t) = &g[0].2 {
        assert_eq!((t.0.as_str(), t.5, t.6), ("root", -1, -1), "empty fields -> -1");
    }
}

#[test]
fn fgetspent_r_small_buffer_matches_glibc() {
    let (path, c) = tmp();
    let g = unsafe {
        let f = g::fopen(c.as_ptr(), c"r".as_ptr());
        let mut sp: libc::spwd = std::mem::zeroed();
        let mut buf = [0u8; 4];
        let mut res: *mut libc::spwd = std::ptr::null_mut();
        let rc = g::fgetspent_r(f, &mut sp, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res);
        g::fclose(f);
        (rc, res.is_null())
    };
    let f = unsafe {
        let ff = fls::fopen(c.as_ptr().cast(), c"r".as_ptr().cast());
        let mut sp: libc::spwd = std::mem::zeroed();
        let mut buf = [0u8; 4];
        let mut res: *mut libc::spwd = std::ptr::null_mut();
        let rc = flu::fgetspent_r(ff.cast(), &mut sp, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res);
        fls::fclose(ff);
        (rc, res.is_null())
    };
    let _ = std::fs::remove_file(&path);
    assert_eq!(f, g, "fgetspent_r small buffer: fl={f:?} glibc={g:?}");
    assert_eq!(g.0, libc::ERANGE, "glibc returns ERANGE on small buffer");
}
