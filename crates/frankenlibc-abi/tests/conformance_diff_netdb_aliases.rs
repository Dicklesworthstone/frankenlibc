//! Differential gate: getservby*/getprotoby* must return the canonical name
//! AND the entry's aliases, exactly like glibc.
//!
//! fl previously returned an empty `s_aliases`/`p_aliases` list and, for
//! getservbyname, echoed the *queried* name instead of the canonical one. So
//! `getservbyname("www","tcp")` returned name="www" aliases=[] where glibc
//! returns name="http" aliases=["www"].
//!
//! Both fl and glibc read the same /etc/services and /etc/protocols, so this
//! compares fl directly against the live host glibc (reached via dlsym to
//! bypass fl's no_mangle interposition) field-for-field, over entries
//! enumerated from the host's real databases.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::resolv_abi as fl;
use std::ffi::{CStr, CString, c_char, c_int, c_void};

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

// (name, port/number, proto, aliases) extracted from a servent/protoent.
type Snap = (Vec<u8>, c_int, Vec<u8>, Vec<Vec<u8>>);

fn snap_serv(p: *const Servent) -> Option<Snap> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { &*p };
    Some((cstr(s.s_name), s.s_port, cstr(s.s_proto), alias_vec(s.s_aliases)))
}
fn snap_proto(p: *const Protoent) -> Option<Snap> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { &*p };
    Some((cstr(s.p_name), s.p_proto, Vec::new(), alias_vec(s.p_aliases)))
}

#[test]
fn getservby_and_getprotoby_match_glibc() {
    let lib = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null(), "dlopen libc.so.6 failed");

    type SByName = extern "C" fn(*const c_char, *const c_char) -> *mut Servent;
    type SByPort = extern "C" fn(c_int, *const c_char) -> *mut Servent;
    type SEnt = extern "C" fn() -> *mut Servent;
    type Set = extern "C" fn(c_int);
    type End = extern "C" fn();
    type PByName = extern "C" fn(*const c_char) -> *mut Protoent;
    type PEnt = extern "C" fn() -> *mut Protoent;

    let g_sbyname: SByName = unsafe { std::mem::transmute(sym(lib, c"getservbyname")) };
    let g_sbyport: SByPort = unsafe { std::mem::transmute(sym(lib, c"getservbyport")) };
    let g_sent: SEnt = unsafe { std::mem::transmute(sym(lib, c"getservent")) };
    let g_sset: Set = unsafe { std::mem::transmute(sym(lib, c"setservent")) };
    let g_send: End = unsafe { std::mem::transmute(sym(lib, c"endservent")) };
    let g_pbyname: PByName = unsafe { std::mem::transmute(sym(lib, c"getprotobyname")) };
    let g_pent: PEnt = unsafe { std::mem::transmute(sym(lib, c"getprotoent")) };
    let g_pset: Set = unsafe { std::mem::transmute(sym(lib, c"setprotoent")) };
    let g_pend: End = unsafe { std::mem::transmute(sym(lib, c"endprotoent")) };

    let mut mismatches = Vec::new();

    // ---- services: enumerate real entries, probe by name (canonical) + port.
    g_sset(1);
    let mut serv_probes: Vec<(Vec<u8>, Vec<u8>, c_int)> = Vec::new(); // (name, proto, port_nbo)
    loop {
        let e = g_sent();
        if e.is_null() {
            break;
        }
        let s = unsafe { &*e };
        let name = cstr(s.s_name);
        let proto = cstr(s.s_proto);
        serv_probes.push((name, proto, s.s_port));
        // Also probe via the first alias (canonical-name behavior).
        let aliases = alias_vec(s.s_aliases);
        if let Some(a) = aliases.first() {
            serv_probes.push((a.clone(), cstr(s.s_proto), s.s_port));
        }
        if serv_probes.len() > 120 {
            break;
        }
    }
    g_send();

    for (name, proto, port_nbo) in &serv_probes {
        let cn = CString::new(name.clone()).unwrap();
        let cp = CString::new(proto.clone()).unwrap();
        // by name + proto
        let g = snap_serv(g_sbyname(cn.as_ptr(), cp.as_ptr()));
        let f = snap_serv(unsafe {
            fl::getservbyname(cn.as_ptr(), cp.as_ptr()).cast::<Servent>()
        });
        if g != f {
            mismatches.push(format!("getservbyname({name:?},{proto:?}): glibc={g:?} fl={f:?}"));
        }
        // by port + proto
        let g = snap_serv(g_sbyport(*port_nbo, cp.as_ptr()));
        let f = snap_serv(unsafe {
            fl::getservbyport(*port_nbo, cp.as_ptr()).cast::<Servent>()
        });
        if g != f {
            mismatches.push(format!("getservbyport({port_nbo},{proto:?}): glibc={g:?} fl={f:?}"));
        }
    }

    // ---- protocols: enumerate real entries, probe by name (+ first alias).
    g_pset(1);
    let mut proto_names: Vec<Vec<u8>> = Vec::new();
    loop {
        let e = g_pent();
        if e.is_null() {
            break;
        }
        let s = unsafe { &*e };
        proto_names.push(cstr(s.p_name));
        let aliases = alias_vec(s.p_aliases);
        if let Some(a) = aliases.first() {
            proto_names.push(a.clone());
        }
        if proto_names.len() > 120 {
            break;
        }
    }
    g_pend();

    for name in &proto_names {
        let cn = CString::new(name.clone()).unwrap();
        let g = snap_proto(g_pbyname(cn.as_ptr()));
        let f = snap_proto(unsafe { fl::getprotobyname(cn.as_ptr()).cast::<Protoent>() });
        if g != f {
            mismatches.push(format!("getprotobyname({name:?}): glibc={g:?} fl={f:?}"));
        }
    }

    assert!(
        mismatches.is_empty(),
        "netdb getXbyY diverged from glibc ({} cases):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
