#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fgetgrent oracle over a controlled temp file

//! Differential gate for fgetgrent vs host glibc (bd-rl6yev) — previously
//! fl-internal only. Parses group-format entries from a caller-provided stream
//! (fully controlled content, exact comparison, no NSS extras). Exercises the
//! gr_mem member list (NULL-terminated char* vector from comma-separated
//! members): no members, one member, several members, and empty fields. Each
//! impl opens the same temp file with its own fopen and iterates with its own
//! fgetgrent; entries compared field-by-field. Strings copied before
//! static-buffer reuse. No mocks.

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> i32;
        pub fn fgetgrent(f: *mut c_void) -> *mut libc::group;
    }
}
use frankenlibc_abi::{stdio_abi as fls, unistd_abi as flu};

static CNT: AtomicU64 = AtomicU64::new(0);

const GROUP: &str = "root:x:0:\n\
daemon:x:1:bin,sys\n\
wheel:*:10:alice\n\
staff:x:50:alice,bob,carol\n\
empty::99:\n";

#[derive(PartialEq, Eq, Debug, Clone)]
struct Gr {
    name: String,
    passwd: String,
    gid: u32,
    mem: Vec<String>,
}

unsafe fn s(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

unsafe fn members(mut pp: *mut *mut c_char) -> Vec<String> {
    let mut v = Vec::new();
    if pp.is_null() {
        return v;
    }
    unsafe {
        while !(*pp).is_null() {
            v.push(s(*pp));
            pp = pp.add(1);
        }
    }
    v
}

unsafe fn rec(gr: &libc::group) -> Gr {
    Gr {
        name: unsafe { s(gr.gr_name) },
        passwd: unsafe { s(gr.gr_passwd) },
        gid: gr.gr_gid,
        mem: unsafe { members(gr.gr_mem) },
    }
}

fn parse_fl(path: &CStr) -> Vec<Gr> {
    let mut out = Vec::new();
    unsafe {
        let f = fls::fopen(path.as_ptr(), c"r".as_ptr().cast());
        assert!(!f.is_null(), "fl fopen");
        loop {
            let p = flu::fgetgrent(f) as *mut libc::group;
            if p.is_null() {
                break;
            }
            out.push(rec(&*p));
        }
        fls::fclose(f);
    }
    out
}

fn parse_glibc(path: &CStr) -> Vec<Gr> {
    let mut out = Vec::new();
    unsafe {
        let f = g::fopen(path.as_ptr(), c"r".as_ptr());
        assert!(!f.is_null(), "glibc fopen");
        loop {
            let p = g::fgetgrent(f);
            if p.is_null() {
                break;
            }
            out.push(rec(&*p));
        }
        g::fclose(f);
    }
    out
}

#[test]
fn fgetgrent_matches_glibc() {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-fgetgrent-{}-{}", std::process::id(), n));
    std::fs::write(&p, GROUP).unwrap();
    let cpath = CString::new(p.to_string_lossy().as_bytes()).unwrap();

    let fl_entries = parse_fl(&cpath);
    let g_entries = parse_glibc(&cpath);
    let _ = std::fs::remove_file(&p);

    assert_eq!(
        fl_entries.len(),
        g_entries.len(),
        "entry count: fl={} glibc={}",
        fl_entries.len(),
        g_entries.len()
    );
    for (i, (f, gg)) in fl_entries.iter().zip(g_entries.iter()).enumerate() {
        assert_eq!(f, gg, "fgetgrent entry {i}: fl={f:?} glibc={gg:?}");
    }
    assert_eq!(g_entries.len(), 5, "5 entries expected");
}
