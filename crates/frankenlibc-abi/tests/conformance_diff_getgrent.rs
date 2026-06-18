#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc setgrent/getgrent oracle over the real /etc/group

//! Differential gate for the non-reentrant getgrent enumeration vs host glibc
//! (bd-n0xx9y) — previously fl-internal only. Like getpwent, glibc routes
//! through NSS and may return additional non-file groups, so the robust check
//! is: every group fl returns must appear in glibc's enumeration under the same
//! name with identical gr_passwd, gr_gid, AND the gr_mem member list (a
//! NULL-terminated char* vector — a common parsing-divergence locus for the
//! comma-separated members). Strings copied before the static buffer is
//! overwritten. No mocks.

use std::collections::HashMap;
use std::ffi::{c_char, CStr};

mod g {
    unsafe extern "C" {
        pub fn setgrent();
        pub fn getgrent() -> *mut libc::group;
        pub fn endgrent();
    }
}
use frankenlibc_abi::grp_abi as fl;

#[derive(PartialEq, Eq, Debug, Clone)]
struct Gr {
    passwd: String,
    gid: u32,
    mem: Vec<String>,
}

unsafe fn s(p: *const c_char) -> String {
    if p.is_null() { String::new() } else { unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned() }
}

unsafe fn members(mut pp: *mut *mut c_char) -> Vec<String> {
    let mut v = Vec::new();
    if pp.is_null() { return v; }
    unsafe {
        while !(*pp).is_null() {
            v.push(s(*pp));
            pp = pp.add(1);
        }
    }
    v
}

unsafe fn rec(gr: &libc::group) -> (String, Gr) {
    (
        unsafe { s(gr.gr_name) },
        Gr {
            passwd: unsafe { s(gr.gr_passwd) },
            gid: gr.gr_gid,
            mem: unsafe { members(gr.gr_mem) },
        },
    )
}

fn enumerate_fl() -> Vec<(String, Gr)> {
    let mut out = Vec::new();
    unsafe {
        fl::setgrent();
        loop {
            let p = fl::getgrent();
            if p.is_null() { break; }
            out.push(rec(&*p));
        }
        fl::endgrent();
    }
    out
}

fn enumerate_glibc() -> HashMap<String, Gr> {
    let mut map = HashMap::new();
    unsafe {
        g::setgrent();
        loop {
            let p = g::getgrent();
            if p.is_null() { break; }
            let (n, v) = rec(&*p);
            map.entry(n).or_insert(v);
        }
        g::endgrent();
    }
    map
}

#[test]
fn getgrent_entries_match_glibc() {
    let fl_entries = enumerate_fl();
    let glibc = enumerate_glibc();

    assert!(!fl_entries.is_empty(), "fl getgrent returned no entries (expected at least root)");
    assert!(fl_entries.iter().any(|(n, _)| n == "root"), "fl enumeration missing root group");

    for (name, fgr) in &fl_entries {
        match glibc.get(name) {
            Some(ggr) => assert_eq!(fgr, ggr, "group entry {name:?}: fl={fgr:?} glibc={ggr:?}"),
            None => panic!("fl getgrent returned {name:?} not present in glibc enumeration"),
        }
    }
}
