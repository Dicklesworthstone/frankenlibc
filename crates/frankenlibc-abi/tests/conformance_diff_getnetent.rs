//! Differential gate: getnetent / getnetbyname enumeration must match glibc,
//! including n_addrtype, n_net, and the alias list.
//!
//! fl's networks fill path previously discarded aliases entirely (the abi
//! parse_networks_line adapter dropped them) and getnetbyname did not match on
//! aliases. Both fl and glibc read the same /etc/networks, so this enumerates
//! getnetent in lockstep and re-queries each name via getnetbyname, comparing
//! against the live host glibc (via dlsym). (Most hosts ship a single,
//! alias-free /etc/networks entry, so this primarily guards against
//! regressions and pins n_addrtype / n_net / canonical-name parity; the alias
//! packing itself is covered by the servent/protoent gates that share the
//! same helper.)
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as flu;
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};

const RTLD_NOW: c_int = 2;

#[repr(C)]
struct NetEnt {
    n_name: *mut c_char,
    n_aliases: *mut *mut c_char,
    n_addrtype: c_int,
    n_net: u32,
}

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
unsafe fn sym(lib: *mut c_void, name: &CStr) -> *mut c_void {
    let p = unsafe { dlsym(lib, name.as_ptr()) };
    assert!(!p.is_null(), "dlsym {name:?} failed");
    p
}
fn cstr(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}
fn alias_vec(mut pp: *mut *mut c_char) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if pp.is_null() {
        return out;
    }
    unsafe {
        while !(*pp).is_null() {
            out.push(cstr(*pp));
            pp = pp.add(1);
        }
    }
    out
}
type Snap = (Vec<u8>, c_int, c_uint, Vec<Vec<u8>>);
fn snap(p: *const NetEnt) -> Option<Snap> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { &*p };
    Some((cstr(s.n_name), s.n_addrtype, s.n_net, alias_vec(s.n_aliases)))
}

#[test]
fn getnetent_getnetbyname_match_glibc() {
    let lib = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null(), "dlopen libc.so.6 failed");
    type Ent = extern "C" fn() -> *mut NetEnt;
    type Ctl = extern "C" fn(c_int);
    type End = extern "C" fn();
    type ByName = extern "C" fn(*const c_char) -> *mut NetEnt;

    let g_ent: Ent = unsafe { std::mem::transmute(sym(lib, c"getnetent")) };
    let g_set: Ctl = unsafe { std::mem::transmute(sym(lib, c"setnetent")) };
    let g_end: End = unsafe { std::mem::transmute(sym(lib, c"endnetent")) };
    let g_byname: ByName = unsafe { std::mem::transmute(sym(lib, c"getnetbyname")) };

    // Lockstep enumeration.
    let mut glist: Vec<Snap> = Vec::new();
    g_set(1);
    loop {
        let e = g_ent();
        match snap(e) {
            Some(s) => glist.push(s),
            None => break,
        }
        if glist.len() > 2000 {
            break;
        }
    }
    g_end();

    let mut flist: Vec<Snap> = Vec::new();
    unsafe { flu::setnetent(1) };
    loop {
        let e = unsafe { flu::getnetent().cast::<NetEnt>() };
        match snap(e) {
            Some(s) => flist.push(s),
            None => break,
        }
        if flist.len() > 2000 {
            break;
        }
    }
    unsafe { flu::endnetent() };

    assert_eq!(flist, glist, "getnetent enumeration diverged from glibc");

    // Re-query each canonical name via getnetbyname.
    for (name, _, _, _) in &glist {
        let cn = CString::new(name.clone()).unwrap();
        let g = snap(g_byname(cn.as_ptr()));
        let f = snap(unsafe { flu::getnetbyname(cn.as_ptr()).cast::<NetEnt>() });
        assert_eq!(f, g, "getnetbyname({name:?}) diverged from glibc");
    }
}
