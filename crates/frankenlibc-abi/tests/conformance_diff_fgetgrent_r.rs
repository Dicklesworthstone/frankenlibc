#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fgetgrent_r oracle; real temp files

//! Differential gate for fgetgrent_r (bd-v10nf1) — the reentrant group-line
//! parser had no differential gate. It parses "name:passwd:gid:m1,m2,..." lines
//! into a caller struct group + scratch buffer, including the NULL-terminated
//! gr_mem member-pointer array. Compares, vs glibc: each entry's name/gid/member
//! list, the end-of-stream result (ENOENT + NULL), and the small-buffer ERANGE
//! path. Each impl uses its own fopen/fgetgrent_r. No mocks.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn fgetgrent_r(stream: *mut c_void, grbuf: *mut libc::group, buf: *mut c_char, buflen: usize, result: *mut *mut libc::group) -> c_int;
    }
}
use frankenlibc_abi::{stdio_abi as fls, unistd_abi as flu};

static CNT: AtomicU64 = AtomicU64::new(0);
fn tmp() -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-fgetgrent-{}-{}", std::process::id(), n));
    std::fs::write(&p, b"wheel:x:10:root,admin,user\nnogroup:x:65534:\nsudo:!:27:alice\n").unwrap();
    (p.clone(), CString::new(p.to_string_lossy().as_bytes()).unwrap())
}

fn members(gr: &libc::group) -> Vec<String> {
    let mut v = Vec::new();
    if gr.gr_mem.is_null() { return v; }
    unsafe {
        let mut i = 0isize;
        loop {
            let p = *gr.gr_mem.offset(i);
            if p.is_null() { break; }
            v.push(CStr::from_ptr(p).to_string_lossy().into_owned());
            i += 1;
        }
    }
    v
}
fn name(gr: &libc::group) -> String {
    if gr.gr_name.is_null() { String::new() } else { unsafe { CStr::from_ptr(gr.gr_name) }.to_string_lossy().into_owned() }
}

type Entry = (i32, bool, Option<(String, u32, Vec<String>)>);

fn glibc_parse(path: &CString) -> Vec<Entry> {
    let mut out = Vec::new();
    unsafe {
        let f = g::fopen(path.as_ptr(), c"r".as_ptr());
        assert!(!f.is_null());
        for _ in 0..4 {
            let mut gr: libc::group = std::mem::zeroed();
            let mut buf = [0u8; 1024];
            let mut res: *mut libc::group = std::ptr::null_mut();
            let rc = g::fgetgrent_r(f, &mut gr, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res);
            out.push((rc, !res.is_null(), if !res.is_null() { Some((name(&gr), gr.gr_gid, members(&gr))) } else { None }));
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
        for _ in 0..4 {
            let mut gr: libc::group = std::mem::zeroed();
            let mut buf = [0u8; 1024];
            let mut res: *mut libc::group = std::ptr::null_mut();
            let rc = flu::fgetgrent_r(f.cast(), &mut gr, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res);
            out.push((rc, !res.is_null(), if !res.is_null() { Some((name(&gr), gr.gr_gid, members(&gr))) } else { None }));
        }
        fls::fclose(f);
    }
    out
}

#[test]
fn fgetgrent_r_matches_glibc() {
    let (path, c) = tmp();
    let g = glibc_parse(&c);
    let f = fl_parse(&c);
    let _ = std::fs::remove_file(&path);
    assert_eq!(f, g, "fgetgrent_r entries: fl={f:?} glibc={g:?}");
    assert_eq!(
        g[0].2.as_ref().map(|t| (t.0.as_str(), t.1, t.2.clone())),
        Some(("wheel", 10, vec!["root".into(), "admin".into(), "user".into()]))
    );
    assert_eq!(g[1].2.as_ref().map(|t| t.2.clone()), Some(vec![]), "empty member list");
}

#[test]
fn fgetgrent_r_small_buffer_matches_glibc() {
    let (path, c) = tmp();
    let g = unsafe {
        let f = g::fopen(c.as_ptr(), c"r".as_ptr());
        let mut gr: libc::group = std::mem::zeroed();
        let mut buf = [0u8; 4];
        let mut res: *mut libc::group = std::ptr::null_mut();
        let rc = g::fgetgrent_r(f, &mut gr, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res);
        g::fclose(f);
        (rc, res.is_null())
    };
    let f = unsafe {
        let ff = fls::fopen(c.as_ptr().cast(), c"r".as_ptr().cast());
        let mut gr: libc::group = std::mem::zeroed();
        let mut buf = [0u8; 4];
        let mut res: *mut libc::group = std::ptr::null_mut();
        let rc = flu::fgetgrent_r(ff.cast(), &mut gr, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res);
        fls::fclose(ff);
        (rc, res.is_null())
    };
    let _ = std::fs::remove_file(&path);
    assert_eq!(f, g, "fgetgrent_r small buffer: fl={f:?} glibc={g:?}");
    assert_eq!(g.0, libc::ERANGE, "glibc returns ERANGE on small buffer");
}
