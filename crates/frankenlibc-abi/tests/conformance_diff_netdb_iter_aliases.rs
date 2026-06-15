//! Differential gate: getservent / getprotoent enumeration must yield the
//! same entries as glibc, INCLUDING aliases.
//!
//! fl's iterator fill path previously wrote an empty s_aliases/p_aliases
//! list. Both fl and glibc read the same /etc/services and /etc/protocols
//! in file order, so a full lockstep enumeration must agree entry-for-entry
//! (name, port/number, proto, aliases). glibc is reached via dlsym to bypass
//! fl's no_mangle interposition of the same symbols.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{CStr, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

#[repr(C)]
struct Servent {
    s_name: *mut c_char,
    s_aliases: *mut *mut c_char,
    s_port: c_int,
    s_proto: *mut c_char,
}
#[repr(C)]
struct Protoent {
    p_name: *mut c_char,
    p_aliases: *mut *mut c_char,
    p_proto: c_int,
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

type Snap = (Vec<u8>, c_int, Vec<u8>, Vec<Vec<u8>>);

#[test]
fn getservent_getprotoent_match_glibc_with_aliases() {
    let lib = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null(), "dlopen libc.so.6 failed");

    type Ent<T> = extern "C" fn() -> *mut T;
    type Ctl = extern "C" fn(c_int);
    type End = extern "C" fn();

    let g_sent: Ent<Servent> = unsafe { std::mem::transmute(sym(lib, c"getservent")) };
    let g_sset: Ctl = unsafe { std::mem::transmute(sym(lib, c"setservent")) };
    let g_send: End = unsafe { std::mem::transmute(sym(lib, c"endservent")) };
    let g_pent: Ent<Protoent> = unsafe { std::mem::transmute(sym(lib, c"getprotoent")) };
    let g_pset: Ctl = unsafe { std::mem::transmute(sym(lib, c"setprotoent")) };
    let g_pend: End = unsafe { std::mem::transmute(sym(lib, c"endprotoent")) };

    // ---- services
    let mut glibc_serv: Vec<Snap> = Vec::new();
    g_sset(1);
    loop {
        let e = g_sent();
        if e.is_null() {
            break;
        }
        let s = unsafe { &*e };
        glibc_serv.push((cstr(s.s_name), s.s_port, cstr(s.s_proto), alias_vec(s.s_aliases)));
        if glibc_serv.len() > 2000 {
            break;
        }
    }
    g_send();

    let mut fl_serv: Vec<Snap> = Vec::new();
    unsafe { fl::setservent(1) };
    loop {
        let e = unsafe { fl::getservent().cast::<Servent>() };
        if e.is_null() {
            break;
        }
        let s = unsafe { &*e };
        fl_serv.push((cstr(s.s_name), s.s_port, cstr(s.s_proto), alias_vec(s.s_aliases)));
        if fl_serv.len() > 2000 {
            break;
        }
    }
    unsafe { fl::endservent() };

    assert_eq!(
        fl_serv, glibc_serv,
        "getservent enumeration diverged from glibc (incl. aliases)"
    );

    // ---- protocols
    let mut glibc_proto: Vec<Snap> = Vec::new();
    g_pset(1);
    loop {
        let e = g_pent();
        if e.is_null() {
            break;
        }
        let s = unsafe { &*e };
        glibc_proto.push((cstr(s.p_name), s.p_proto, Vec::new(), alias_vec(s.p_aliases)));
        if glibc_proto.len() > 2000 {
            break;
        }
    }
    g_pend();

    let mut fl_proto: Vec<Snap> = Vec::new();
    unsafe { fl::setprotoent(1) };
    loop {
        let e = unsafe { fl::getprotoent().cast::<Protoent>() };
        if e.is_null() {
            break;
        }
        let s = unsafe { &*e };
        fl_proto.push((cstr(s.p_name), s.p_proto, Vec::new(), alias_vec(s.p_aliases)));
        if fl_proto.len() > 2000 {
            break;
        }
    }
    unsafe { fl::endprotoent() };

    assert_eq!(
        fl_proto, glibc_proto,
        "getprotoent enumeration diverged from glibc (incl. aliases)"
    );
}
