//! Differential gate: getrpcent / getrpcbyname / getrpcbynumber must match
//! glibc, including r_aliases (/etc/rpc entries carry several aliases, e.g.
//! `portmapper 100000 portmap sunrpc rpcbind`).
//!
//! Both fl and glibc read the same /etc/rpc; glibc is reached via dlsym to
//! bypass fl's no_mangle interposition.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as flu;
use std::ffi::{CStr, CString, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

#[repr(C)]
struct RpcEnt {
    r_name: *mut c_char,
    r_aliases: *mut *mut c_char,
    r_number: c_int,
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
type Snap = (Vec<u8>, c_int, Vec<Vec<u8>>);
fn snap(p: *const RpcEnt) -> Option<Snap> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { &*p };
    Some((cstr(s.r_name), s.r_number, alias_vec(s.r_aliases)))
}

#[test]
fn getrpcent_matches_glibc() {
    let lib = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null(), "dlopen libc.so.6 failed");
    type Ent = extern "C" fn() -> *mut RpcEnt;
    type Ctl = extern "C" fn(c_int);
    type End = extern "C" fn();
    type ByName = extern "C" fn(*const c_char) -> *mut RpcEnt;
    type ByNum = extern "C" fn(c_int) -> *mut RpcEnt;

    let g_ent: Ent = unsafe { std::mem::transmute(sym(lib, c"getrpcent")) };
    let g_set: Ctl = unsafe { std::mem::transmute(sym(lib, c"setrpcent")) };
    let g_end: End = unsafe { std::mem::transmute(sym(lib, c"endrpcent")) };
    let g_byname: ByName = unsafe { std::mem::transmute(sym(lib, c"getrpcbyname")) };
    let g_bynum: ByNum = unsafe { std::mem::transmute(sym(lib, c"getrpcbynumber")) };

    // Lockstep enumeration.
    let mut glist: Vec<Snap> = Vec::new();
    g_set(1);
    loop {
        match snap(g_ent()) {
            Some(s) => glist.push(s),
            None => break,
        }
        if glist.len() > 2000 {
            break;
        }
    }
    g_end();

    let mut flist: Vec<Snap> = Vec::new();
    unsafe { flu::setrpcent(1) };
    loop {
        match snap(unsafe { flu::getrpcent().cast::<RpcEnt>() }) {
            Some(s) => flist.push(s),
            None => break,
        }
        if flist.len() > 2000 {
            break;
        }
    }
    unsafe { flu::endrpcent() };

    assert_eq!(flist, glist, "getrpcent enumeration diverged from glibc");

    // Re-query each name and number.
    for (name, num, _) in &glist {
        let cn = CString::new(name.clone()).unwrap();
        let g = snap(g_byname(cn.as_ptr()));
        let f = snap(unsafe { flu::getrpcbyname(cn.as_ptr()).cast::<RpcEnt>() });
        assert_eq!(f, g, "getrpcbyname({name:?}) diverged");

        let g = snap(g_bynum(*num));
        let f = snap(unsafe { flu::getrpcbynumber(*num).cast::<RpcEnt>() });
        assert_eq!(f, g, "getrpcbynumber({num}) diverged");
    }
}
