#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fgetpwent_r oracle; real temp files

//! Differential gate for fgetpwent_r (bd-k9lupq) — the reentrant passwd-line
//! parser had no differential gate. It parses successive "name:passwd:uid:gid:
//! gecos:dir:shell" lines from a stream into a caller-provided struct passwd +
//! scratch buffer. Compares, vs glibc: the parsed fields of each entry, the
//! end-of-stream result (ENOENT, *result == NULL), and the small-buffer ERANGE
//! path. Each impl uses its own fopen/fgetpwent_r. No mocks.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn fgetpwent_r(stream: *mut c_void, pwbuf: *mut libc::passwd, buf: *mut c_char, buflen: usize, result: *mut *mut libc::passwd) -> c_int;
    }
}
use frankenlibc_abi::{stdio_abi as fls, unistd_abi as flu};

static CNT: AtomicU64 = AtomicU64::new(0);
fn tmp() -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-fgetpwent-{}-{}", std::process::id(), n));
    std::fs::write(&p, b"root:x:0:0:root:/root:/bin/bash\nsvc:!:1000:1001:Service Acct:/home/svc:/usr/bin/sh\n").unwrap();
    (p.clone(), CString::new(p.to_string_lossy().as_bytes()).unwrap())
}

fn fields(pw: &libc::passwd) -> (String, u32, u32, String, String, String) {
    let s = |p: *const c_char| if p.is_null() { String::new() } else { unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned() };
    (s(pw.pw_name), pw.pw_uid, pw.pw_gid, s(pw.pw_gecos), s(pw.pw_dir), s(pw.pw_shell))
}

type Entry = (i32, bool, Option<(String, u32, u32, String, String, String)>);

/// Parse all entries + one past EOF; returns the sequence of (rc, result_nonnull, fields).
fn glibc_parse(path: &CString) -> Vec<Entry> {
    let mut out = Vec::new();
    unsafe {
        let f = g::fopen(path.as_ptr(), c"r".as_ptr());
        assert!(!f.is_null());
        for _ in 0..3 {
            let mut pw: libc::passwd = std::mem::zeroed();
            let mut buf = [0u8; 1024];
            let mut res: *mut libc::passwd = std::ptr::null_mut();
            let rc = g::fgetpwent_r(f, &mut pw, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res);
            out.push((rc, !res.is_null(), if !res.is_null() { Some(fields(&pw)) } else { None }));
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
            let mut pw: libc::passwd = std::mem::zeroed();
            let mut buf = [0u8; 1024];
            let mut res: *mut libc::passwd = std::ptr::null_mut();
            let rc = flu::fgetpwent_r(f.cast(), &mut pw, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res);
            out.push((rc, !res.is_null(), if !res.is_null() { Some(fields(&pw)) } else { None }));
        }
        fls::fclose(f);
    }
    out
}

#[test]
fn fgetpwent_r_matches_glibc() {
    let (path, c) = tmp();
    let g = glibc_parse(&c);
    let f = fl_parse(&c);
    let _ = std::fs::remove_file(&path);
    assert_eq!(f, g, "fgetpwent_r entries: fl={f:?} glibc={g:?}");
    // sanity: first entry is root/0/0
    assert_eq!(g[0].2.as_ref().map(|t| (t.0.as_str(), t.1, t.2)), Some(("root", 0, 0)));
}

#[test]
fn fgetpwent_r_small_buffer_matches_glibc() {
    let (path, c) = tmp();
    let g = unsafe {
        let f = g::fopen(c.as_ptr(), c"r".as_ptr());
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut buf = [0u8; 4]; // too small for "root:..."
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        let rc = g::fgetpwent_r(f, &mut pw, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res);
        g::fclose(f);
        (rc, res.is_null())
    };
    let f = unsafe {
        let ff = fls::fopen(c.as_ptr().cast(), c"r".as_ptr().cast());
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut buf = [0u8; 4];
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        let rc = flu::fgetpwent_r(ff.cast(), &mut pw, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res);
        fls::fclose(ff);
        (rc, res.is_null())
    };
    let _ = std::fs::remove_file(&path);
    assert_eq!(f, g, "fgetpwent_r small buffer: fl={f:?} glibc={g:?}");
    assert_eq!(g.0, libc::ERANGE, "glibc returns ERANGE on small buffer");
}
