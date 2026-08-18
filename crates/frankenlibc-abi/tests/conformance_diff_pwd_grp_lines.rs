#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fgetpwent/fgetgrent oracle

//! /etc/passwd and /etc/group line parsing, against the host's own parser.
//!
//! `fmemopen` turns a byte string into a `FILE*`, so host `fgetpwent` and
//! `fgetgrent` can be driven over synthetic lines with NOTHING written to disk
//! and no risk of touching the real /etc/passwd. That is what makes these
//! parsers differentiable at all — every previous test compared them against
//! expectations written by hand.
//!
//! The cases are deliberately malformed, because well-formed lines agree
//! trivially. Three rules that fl got wrong were found this way:
//!   * leading blanks are skipped before ANYTHING, the '#' test included;
//!   * an EMPTY name is a valid entry, not a reason to drop the line;
//!   * a '+' sign is accepted in the numeric field (strtoul), and /etc/group's
//!     copy of that helper had drifted from /etc/passwd's.

use std::ffi::{c_char, c_int, c_uint, c_void};

#[repr(C)]
struct CPasswd {
    pw_name: *const c_char,
    pw_passwd: *const c_char,
    pw_uid: c_uint,
    pw_gid: c_uint,
    pw_gecos: *const c_char,
    pw_dir: *const c_char,
    pw_shell: *const c_char,
}

#[repr(C)]
struct CGroup {
    gr_name: *const c_char,
    gr_passwd: *const c_char,
    gr_gid: c_uint,
    gr_mem: *const *const c_char,
}

unsafe extern "C" {
    fn fmemopen(buf: *mut c_void, size: usize, mode: *const c_char) -> *mut c_void;
    fn fclose(stream: *mut c_void) -> c_int;
    fn fgetpwent(stream: *mut c_void) -> *const CPasswd;
    fn fgetgrent(stream: *mut c_void) -> *const CGroup;
}

unsafe fn cstr(p: *const c_char) -> Option<Vec<u8>> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes().to_vec())
    }
}

fn with_stream<T>(line: &str, f: impl FnOnce(*mut c_void) -> T) -> T {
    let mut data = format!("{line}\n").into_bytes();
    let mode = c"r";
    let stream = unsafe { fmemopen(data.as_mut_ptr().cast(), data.len(), mode.as_ptr()) };
    assert!(!stream.is_null(), "fmemopen failed");
    let out = f(stream);
    unsafe { fclose(stream) };
    out
}

type PwTuple = (Vec<u8>, Vec<u8>, u32, u32, Vec<u8>, Vec<u8>, Vec<u8>);

/// Host answer, or None when glibc rejects the line. NIS "+"/"-" entries have
/// NULL fields; they are reported as such so the caller can skip them.
fn host_passwd(line: &str) -> Option<Option<PwTuple>> {
    with_stream(line, |s| {
        let p = unsafe { fgetpwent(s) };
        if p.is_null() {
            return Some(None);
        }
        let e = unsafe { &*p };
        // A NULL pw_passwd means the NIS special form, which fl does not model.
        let (name, passwd) = unsafe { (cstr(e.pw_name), cstr(e.pw_passwd)) };
        let passwd = passwd?;
        let (gecos, dir, shell) =
            unsafe { (cstr(e.pw_gecos)?, cstr(e.pw_dir)?, cstr(e.pw_shell)?) };
        Some(Some((name?, passwd, e.pw_uid, e.pw_gid, gecos, dir, shell)))
    })
}

fn host_group(line: &str) -> Option<Option<(Vec<u8>, Vec<u8>, u32, Vec<Vec<u8>>)>> {
    with_stream(line, |s| {
        let p = unsafe { fgetgrent(s) };
        if p.is_null() {
            return Some(None);
        }
        let e = unsafe { &*p };
        let name = unsafe { cstr(e.gr_name) }?;
        let passwd = unsafe { cstr(e.gr_passwd) }?;
        let mut members = Vec::new();
        if !e.gr_mem.is_null() {
            let mut i = 0isize;
            loop {
                let m = unsafe { *e.gr_mem.offset(i) };
                if m.is_null() {
                    break;
                }
                members.push(unsafe { cstr(m) }?);
                i += 1;
            }
        }
        Some(Some((name, passwd, e.gr_gid, members)))
    })
}

const PASSWD_CASES: &[&str] = &[
    "root:x:0:0:root:/root:/bin/bash",
    "u:p:1000:1000",
    "u:p:1000",
    "u:p",
    ":x:1:1:g:d:s",
    "u::1:1:g:d:s",
    "u:x::1:g:d:s",
    "u:x:1::g:d:s",
    "u:x:+5:1:g:d:s",
    "u:x:-1:1:g:d:s",
    "u:x:0x10:1:g:d:s",
    "u:x: 5:1:g:d:s",
    "u:x:5 :1:g:d:s",
    "u:x:4294967295:1:g:d:s",
    "u:x:4294967296:1:g:d:s",
    "u:x:1:1:g:d:s:extra:more",
    "u:x:1:1:g:d:",
    "# comment",
    "",
    "  u:x:1:1:g:d:s",
    "\tu:x:1:1:g:d:s",
    "   # c",
    "  ",
    ":::0:0::",
    "  :x:1:1:g:d:s",
];

const GROUP_CASES: &[&str] = &[
    "root:x:0:",
    "wheel:x:10:alice,bob",
    "g:x:5",
    "g:x",
    "  g:x:7:a",
    "\tg:x:7:a",
    ":x:7:a",
    "g::7:a",
    "g:x::a",
    "g:x:-1:a",
    "g:x:0x10:a",
    "g:x:4294967296:a",
    "g:x:7:",
    "g:x:7:,",
    "g:x:7:a,,b",
    "g:x:7:a,b,",
    "# comment",
    "",
    "   # c",
    "  ",
    "g:x:7:a:extra",
    "g:x:+7:a",
    "g:x:  7:a",
    "g:x:07:a",
];

#[test]
fn passwd_lines_match_glibc() {
    let mut compared = 0usize;
    let mut accepted = 0usize;
    let mut divergences = Vec::new();
    for &line in PASSWD_CASES {
        let Some(host) = host_passwd(line) else {
            continue; // NIS "+"/"-" form: fl does not model NULL fields
        };
        let ours = frankenlibc_core::pwd::parse_passwd_line(line.as_bytes()).map(|e| {
            (
                e.pw_name,
                e.pw_passwd,
                e.pw_uid,
                e.pw_gid,
                e.pw_gecos,
                e.pw_dir,
                e.pw_shell,
            )
        });
        compared += 1;
        if host.is_some() {
            accepted += 1;
        }
        if ours != host {
            divergences.push(format!("{line:?}: fl={ours:?} glibc={host:?}"));
        }
    }
    // A run where glibc rejected everything would make "fl also returned None"
    // look like agreement.
    assert!(
        accepted >= 8,
        "glibc accepted only {accepted} of {compared} passwd cases -- near-vacuous"
    );
    assert!(
        divergences.is_empty(),
        "passwd line divergences ({} of {compared}):\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );
}

#[test]
fn group_lines_match_glibc() {
    let mut compared = 0usize;
    let mut accepted = 0usize;
    let mut divergences = Vec::new();
    for &line in GROUP_CASES {
        let Some(host) = host_group(line) else {
            continue;
        };
        let ours = frankenlibc_core::grp::parse_group_line(line.as_bytes())
            .map(|g| (g.gr_name, g.gr_passwd, g.gr_gid, g.gr_mem));
        compared += 1;
        if host.is_some() {
            accepted += 1;
        }
        if ours != host {
            divergences.push(format!("{line:?}: fl={ours:?} glibc={host:?}"));
        }
    }
    assert!(
        accepted >= 8,
        "glibc accepted only {accepted} of {compared} group cases -- near-vacuous"
    );
    assert!(
        divergences.is_empty(),
        "group line divergences ({} of {compared}):\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );
}
