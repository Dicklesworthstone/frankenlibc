#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fgetspent oracle

//! /etc/shadow line parsing, against the host's own parser.
//!
//! Driven through `fmemopen`, so host `fgetspent` parses synthetic lines with
//! nothing written to disk — which matters more here than for passwd/group,
//! because /etc/shadow is root-only and a test that needed a real file could
//! not run unprivileged at all.
//!
//! Two rules fl had wrong, both found this way:
//!   * leading blanks belong to nobody — the parser computed a trimmed copy for
//!     its blank/comment test and then split the UNtrimmed line, so "  u:..."
//!     produced the name "  u";
//!   * a TENTH field rejects the entry. /etc/shadow has exactly nine, and glibc
//!     refuses anything longer; fl stopped reading after the flag field and
//!     silently accepted the rest.

use std::ffi::{c_char, c_int, c_long, c_ulong, c_void};

#[repr(C)]
struct CSpwd {
    sp_namp: *const c_char,
    sp_pwdp: *const c_char,
    sp_lstchg: c_long,
    sp_min: c_long,
    sp_max: c_long,
    sp_warn: c_long,
    sp_inact: c_long,
    sp_expire: c_long,
    sp_flag: c_ulong,
}

unsafe extern "C" {
    fn fmemopen(buf: *mut c_void, size: usize, mode: *const c_char) -> *mut c_void;
    fn fclose(stream: *mut c_void) -> c_int;
    fn fgetspent(stream: *mut c_void) -> *const CSpwd;
}

type ShadowTuple = (Vec<u8>, Vec<u8>, i64, i64, i64, i64, i64, i64, u64);

fn host_shadow(line: &str) -> Option<ShadowTuple> {
    let mut data = format!("{line}\n").into_bytes();
    let mode = c"r";
    let stream = unsafe { fmemopen(data.as_mut_ptr().cast(), data.len(), mode.as_ptr()) };
    assert!(!stream.is_null(), "fmemopen failed");
    let p = unsafe { fgetspent(stream) };
    let out = if p.is_null() {
        None
    } else {
        let e = unsafe { &*p };
        let name = unsafe { std::ffi::CStr::from_ptr(e.sp_namp) }
            .to_bytes()
            .to_vec();
        let pwd = unsafe { std::ffi::CStr::from_ptr(e.sp_pwdp) }
            .to_bytes()
            .to_vec();
        Some((
            name,
            pwd,
            e.sp_lstchg as i64,
            e.sp_min as i64,
            e.sp_max as i64,
            e.sp_warn as i64,
            e.sp_inact as i64,
            e.sp_expire as i64,
            e.sp_flag as u64,
        ))
    };
    unsafe { fclose(stream) };
    out
}

/// Each case defeats a different plausible reading of the format.
const CASES: &[&str] = &[
    "root:!:19000:0:99999:7:::", // the shape a real /etc/shadow uses
    "u:x:1:2:3:4:5:6:7",
    "u:x:::::::",      // every numeric empty -> -1, flag -> ~0
    "u:x::::::: ",     // a lone space is NOT an empty flag
    "u:x:1:2:3:4:5:6", // no flag field at all -> ~0
    "u:x:1:2:3:4:5",   // too few fields
    "u:x:1",
    "u:x",
    "  u:x:1:2:3:4:5:6:7", // leading blanks belong to nobody
    "\tu:x:1:2:3:4:5:6:7",
    ":x:1:2:3:4:5:6:7", // empty name is valid
    "u::1:2:3:4:5:6:7",
    "u:x:-1:2:3:4:5:6:7", // negative is REJECTED, not read as -1
    "u:x:+1:2:3:4:5:6:7", // but a '+' sign is accepted
    "u:x: 5:2:3:4:5:6:7", // leading blanks inside a numeric field
    "u:x:007:2:3:4:5:6:7",
    "u:x:abc:2:3:4:5:6:7",
    "u:x:0x10:2:3:4:5:6:7", // base 10, so "0" then junk -> reject
    "u:x:99999999999999999999:2:3:4:5:6:7",
    "u:x:1:2:3:4:5:6:7:extra", // a tenth field rejects the entry
    "# comment",
    "",
    "   # c",
    "  ",
];

#[test]
fn shadow_lines_match_glibc() {
    let mut accepted = 0usize;
    let mut divergences = Vec::new();
    for &line in CASES {
        let host = host_shadow(line);
        if host.is_some() {
            accepted += 1;
        }
        let ours = frankenlibc_core::pwd::shadow::parse_shadow_line(line.as_bytes()).map(|e| {
            (
                e.name, e.passwd, e.lstchg, e.min, e.max, e.warn, e.inact, e.expire, e.flag,
            )
        });
        if ours != host {
            divergences.push(format!("{line:?}: fl={ours:?} glibc={host:?}"));
        }
    }
    // Most of these cases are meant to be REJECTED, so "both said None" is the
    // common answer and could hide a parser that rejects everything. Require
    // that glibc accepted a real share of them.
    assert!(
        accepted >= 8,
        "glibc accepted only {accepted} of {} cases -- near-vacuous",
        CASES.len()
    );
    assert!(
        divergences.is_empty(),
        "shadow line divergences ({} of {}):\n  {}",
        divergences.len(),
        CASES.len(),
        divergences.join("\n  ")
    );
}
