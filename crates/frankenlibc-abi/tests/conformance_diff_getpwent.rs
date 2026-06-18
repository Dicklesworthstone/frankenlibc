#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc setpwent/getpwent oracle over the real /etc/passwd

//! Differential gate for the non-reentrant getpwent enumeration vs host glibc
//! (bd-mfdn65) — previously fl-internal only. Both read the system passwd
//! database, but glibc routes through NSS (nsswitch.conf) so it may return
//! ADDITIONAL non-file entries (e.g. systemd-userdb dynamic users) that fl's
//! file-based reader does not. The robust differential is therefore: every
//! entry fl returns must appear in glibc's enumeration UNDER THE SAME NAME with
//! identical fields (pw_passwd/uid/gid/gecos/dir/shell). This catches a parsing
//! divergence on /etc/passwd without falsely flagging glibc's NSS extras.
//! Strings copied before the static buffer is overwritten. No mocks.

use std::collections::HashMap;
use std::ffi::{c_char, CStr};

mod g {
    unsafe extern "C" {
        pub fn setpwent();
        pub fn getpwent() -> *mut libc::passwd;
        pub fn endpwent();
    }
}
use frankenlibc_abi::pwd_abi as fl;

#[derive(PartialEq, Eq, Debug, Clone)]
struct Pw {
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

unsafe fn rec(pw: &libc::passwd) -> (String, Pw) {
    (
        unsafe { s(pw.pw_name) },
        Pw {
            passwd: unsafe { s(pw.pw_passwd) },
            uid: pw.pw_uid,
            gid: pw.pw_gid,
            gecos: unsafe { s(pw.pw_gecos) },
            dir: unsafe { s(pw.pw_dir) },
            shell: unsafe { s(pw.pw_shell) },
        },
    )
}

fn enumerate_fl() -> Vec<(String, Pw)> {
    let mut out = Vec::new();
    unsafe {
        fl::setpwent();
        loop {
            let p = fl::getpwent();
            if p.is_null() { break; }
            out.push(rec(&*p));
        }
        fl::endpwent();
    }
    out
}

fn enumerate_glibc() -> HashMap<String, Pw> {
    let mut map = HashMap::new();
    unsafe {
        g::setpwent();
        loop {
            let p = g::getpwent();
            if p.is_null() { break; }
            let (n, v) = rec(&*p);
            map.entry(n).or_insert(v);
        }
        g::endpwent();
    }
    map
}

#[test]
fn getpwent_entries_match_glibc() {
    let fl_entries = enumerate_fl();
    let glibc = enumerate_glibc();

    assert!(!fl_entries.is_empty(), "fl getpwent returned no entries (expected at least root)");
    // root must be present and identical in both.
    assert!(fl_entries.iter().any(|(n, _)| n == "root"), "fl enumeration missing root");

    for (name, fpw) in &fl_entries {
        match glibc.get(name) {
            Some(gpw) => assert_eq!(fpw, gpw, "passwd entry {name:?}: fl={fpw:?} glibc={gpw:?}"),
            None => panic!("fl getpwent returned {name:?} not present in glibc enumeration"),
        }
    }
}
