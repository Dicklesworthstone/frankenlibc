//! Differential gate for sgetsgent (gshadow line parser) vs glibc.
//!
//! glibc requires only a non-empty group name (passwd/admins/members optional),
//! absorbs extra colons into the member field, and drops empty admin/member
//! tokens (a name is never ""). fl previously demanded exactly four fields and
//! kept empty tokens from leading/trailing/doubled commas.
//!
//! fl is called via its Rust path; glibc via dlsym on libc.so.6.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::pwd_abi as fl;
use std::ffi::{CStr, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

#[repr(C)]
struct Sgrp {
    sg_namp: *mut c_char,
    sg_passwd: *mut c_char,
    sg_adm: *mut *mut c_char,
    sg_mem: *mut *mut c_char,
}

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type SgetsgFn = unsafe extern "C" fn(*const c_char) -> *mut Sgrp;

fn list(mut p: *mut *mut c_char) -> Vec<String> {
    let mut v = Vec::new();
    if p.is_null() {
        return v;
    }
    unsafe {
        while !(*p).is_null() {
            v.push(CStr::from_ptr(*p).to_string_lossy().into_owned());
            p = p.add(1);
        }
    }
    v
}
fn snap(p: *const Sgrp) -> Option<(String, String, Vec<String>, Vec<String>)> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { &*p };
    Some((
        unsafe { CStr::from_ptr(s.sg_namp) }.to_string_lossy().into_owned(),
        unsafe { CStr::from_ptr(s.sg_passwd) }.to_string_lossy().into_owned(),
        list(s.sg_adm),
        list(s.sg_mem),
    ))
}

#[test]
fn sgetsgent_matches_glibc() {
    let h = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null());
    let gp = unsafe { dlsym(h, c"sgetsgent".as_ptr()) };
    assert!(!gp.is_null(), "missing sgetsgent");
    let g: SgetsgFn = unsafe { core::mem::transmute(gp) };

    let lines: &[&CStr] = &[
        c"sudo:!:admin1,admin2:user1,user2",
        c"dev:x:alice:a,b,",     // trailing comma in members
        c"dev:x:a1,,a2:m",       // empty admin token
        c"g:x:adm",              // 3 fields
        c"g:x:a:b:c",            // 5 fields (colon absorb)
        c"g:x",                  // 2 fields
        c"root",                 // 1 field (name only)
        c"g:x:a,b:c,d",          // normal
        c"g:x::,m",              // empty admins, leading-comma member
        c"root:*:::extra",       // colon-absorbed member ":extra"
    ];

    let mut div = Vec::new();
    for line in lines {
        let fv = snap(unsafe { fl::sgetsgent(line.as_ptr()).cast::<Sgrp>() });
        let gv = snap(unsafe { g(line.as_ptr()) });
        if fv != gv {
            div.push(format!("{:?}: fl={fv:?} glibc={gv:?}", line.to_str().unwrap()));
        }
    }
    assert!(div.is_empty(), "sgetsgent divergences ({}):\n  {}", div.len(), div.join("\n  "));
}
