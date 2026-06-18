#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fgetpwent oracle over a controlled temp file

//! Differential gate for fgetpwent vs host glibc (bd-fctymz) — previously
//! fl-internal only. Unlike getpwent (system database + NSS), fgetpwent parses
//! passwd-format entries from a CALLER-PROVIDED stream, so the content is fully
//! controlled and the comparison is exact (no NSS extras). Each impl opens the
//! same temp file with its own fopen and iterates with its own fgetpwent;
//! entries are compared field-by-field, exercising empty fields (passwd/gecos/
//! dir/shell) and a gecos with commas. Strings copied before static-buffer
//! reuse. No mocks.

use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> i32;
        pub fn fgetpwent(f: *mut c_void) -> *mut libc::passwd;
    }
}
use frankenlibc_abi::{stdio_abi as fls, unistd_abi as flu};

static CNT: AtomicU64 = AtomicU64::new(0);

const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
daemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
fulluser:x:1000:1000:Full Name,Room 1,555-1234,:/home/fulluser:/bin/zsh\n\
emptypw::2:2::/var/empty:/bin/false\n\
noshell:x:3:3:gecos here::\n";

#[derive(PartialEq, Eq, Debug, Clone)]
struct Pw {
    name: String,
    passwd: String,
    uid: u32,
    gid: u32,
    gecos: String,
    dir: String,
    shell: String,
}

unsafe fn s(p: *const c_char) -> String {
    if p.is_null() { String::new() } else { unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned() }
}

unsafe fn rec(pw: &libc::passwd) -> Pw {
    Pw {
        name: unsafe { s(pw.pw_name) },
        passwd: unsafe { s(pw.pw_passwd) },
        uid: pw.pw_uid,
        gid: pw.pw_gid,
        gecos: unsafe { s(pw.pw_gecos) },
        dir: unsafe { s(pw.pw_dir) },
        shell: unsafe { s(pw.pw_shell) },
    }
}

fn parse_fl(path: &CStr) -> Vec<Pw> {
    let mut out = Vec::new();
    unsafe {
        let f = fls::fopen(path.as_ptr(), c"r".as_ptr().cast());
        assert!(!f.is_null(), "fl fopen");
        loop {
            let p = flu::fgetpwent(f) as *mut libc::passwd;
            if p.is_null() { break; }
            out.push(rec(&*p));
        }
        fls::fclose(f);
    }
    out
}

fn parse_glibc(path: &CStr) -> Vec<Pw> {
    let mut out = Vec::new();
    unsafe {
        let f = g::fopen(path.as_ptr(), c"r".as_ptr());
        assert!(!f.is_null(), "glibc fopen");
        loop {
            let p = g::fgetpwent(f);
            if p.is_null() { break; }
            out.push(rec(&*p));
        }
        g::fclose(f);
    }
    out
}

#[test]
fn fgetpwent_matches_glibc() {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-fgetpwent-{}-{}", std::process::id(), n));
    std::fs::write(&p, PASSWD).unwrap();
    let cpath = CString::new(p.to_string_lossy().as_bytes()).unwrap();

    let fl_entries = parse_fl(&cpath);
    let g_entries = parse_glibc(&cpath);
    let _ = std::fs::remove_file(&p);

    assert_eq!(fl_entries.len(), g_entries.len(), "entry count: fl={} glibc={}", fl_entries.len(), g_entries.len());
    for (i, (f, gg)) in fl_entries.iter().zip(g_entries.iter()).enumerate() {
        assert_eq!(f, gg, "fgetpwent entry {i}: fl={f:?} glibc={gg:?}");
    }
    assert_eq!(g_entries.len(), 5, "5 entries expected");
}
