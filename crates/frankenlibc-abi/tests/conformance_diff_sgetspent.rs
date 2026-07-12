//! Differential gate for sgetspent (shadow line parser) vs glibc.
//!
//! glibc parses the shadow numeric fields (lstchg/min/max/warn/inact/expire and
//! the optional flag) with strtoul and requires the whole field consumed: an
//! EMPTY field is the -1 "unset" sentinel, but a non-empty field must be a
//! non-negative decimal integer (leading '+'/whitespace allowed). A garbage
//! field ("abc"), a literal "-1", or trailing junk ("5x") makes glibc reject
//! the ENTIRE entry (NULL). fl previously mapped any unparseable field to -1 and
//! accepted the entry.
//!
//! fl is called via its Rust path; glibc via dlsym on libc.so.6.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::glibc_internal_abi as fl;
use std::ffi::{c_char, c_int, c_long, c_void};

const RTLD_NOW: c_int = 2;

#[repr(C)]
struct Spwd {
    sp_namp: *mut c_char,
    sp_pwdp: *mut c_char,
    sp_lstchg: c_long,
    sp_min: c_long,
    sp_max: c_long,
    sp_warn: c_long,
    sp_inact: c_long,
    sp_expire: c_long,
    sp_flag: u64,
}

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type SgetspFn = unsafe extern "C" fn(*const c_char) -> *mut Spwd;

fn snapshot(p: *const Spwd) -> Option<(c_long, c_long, c_long, c_long, c_long, c_long, u64)> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { &*p };
    Some((
        s.sp_lstchg,
        s.sp_min,
        s.sp_max,
        s.sp_warn,
        s.sp_inact,
        s.sp_expire,
        s.sp_flag,
    ))
}

#[test]
fn sgetspent_matches_glibc() {
    let h = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null());
    let gp = unsafe { dlsym(h, c"sgetspent".as_ptr()) };
    assert!(!gp.is_null(), "missing sgetspent");
    let g: SgetspFn = unsafe { core::mem::transmute(gp) };

    let lines: &[&std::ffi::CStr] = &[
        c"alice:!locked:19500:0:99999:7:::",
        c"u:x:19000:0:::::42",
        c"u:*:::::::",
        c"u:x:19000:0:99999:7:::",  // empty lstchg/etc edges
        c"u:x::0:99999:7:::",       // empty lstchg -> -1
        c"u:x:+5:0:99999:7:::",     // leading +
        c"u:x: 5:0:99999:7:::",     // leading space
        c"u:x:-1:0:99999:7:::",     // literal -1 -> NULL
        c"u:x:5x:0:99999:7:::",     // trailing junk -> NULL
        c"u:x:abc:0:99999:7:::",    // garbage -> NULL
        c"u:x:5:0:99999:7:8:9:abc", // garbage flag -> NULL
        c"u:x:5:0:99999:7:8:9:+3",  // +flag
    ];

    let mut div = Vec::new();
    for line in lines {
        let fv = snapshot(unsafe { fl::sgetspent(line.as_ptr()).cast::<Spwd>() });
        let gv = snapshot(unsafe { g(line.as_ptr()) });
        if fv != gv {
            div.push(format!(
                "{:?}: fl={fv:?} glibc={gv:?}",
                line.to_str().unwrap()
            ));
        }
    }
    assert!(
        div.is_empty(),
        "sgetspent divergences ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
