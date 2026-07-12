//! Differential gate: reentrant getservbyname_r / getservbyport_r /
//! getservent_r must return the canonical name, correct s_port byte order,
//! AND the entry's aliases, exactly like glibc.
//!
//! fl's reentrant servent path previously wrote an empty s_aliases list, and
//! getservent_r additionally computed s_port with a 32-bit byteswap (port 1
//! -> 16777216 instead of htons(1) = 256). Both fl and glibc read the same
//! /etc/services; glibc is reached via dlsym to bypass fl's no_mangle
//! interposition.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::inet_abi as fli;
use frankenlibc_abi::unistd_abi as flu;
use std::ffi::{CStr, CString, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

#[repr(C)]
struct Servent {
    s_name: *mut c_char,
    s_aliases: *mut *mut c_char,
    s_port: c_int,
    s_proto: *mut c_char,
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
fn snap(rc: c_int, res: *mut Servent) -> Option<Snap> {
    if rc != 0 || res.is_null() {
        return None;
    }
    let s = unsafe { &*res };
    Some((
        cstr(s.s_name),
        s.s_port,
        cstr(s.s_proto),
        alias_vec(s.s_aliases),
    ))
}

type ByNameR = extern "C" fn(
    *const c_char,
    *const c_char,
    *mut Servent,
    *mut c_char,
    usize,
    *mut *mut Servent,
) -> c_int;
type ByPortR = extern "C" fn(
    c_int,
    *const c_char,
    *mut Servent,
    *mut c_char,
    usize,
    *mut *mut Servent,
) -> c_int;
type EntR = extern "C" fn(*mut Servent, *mut c_char, usize, *mut *mut Servent) -> c_int;
type Ent = extern "C" fn() -> *mut Servent;
type Ctl = extern "C" fn(c_int);
type End = extern "C" fn();

#[test]
fn servent_reentrant_matches_glibc() {
    let lib = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null(), "dlopen libc.so.6 failed");
    let g_byname: ByNameR = unsafe { std::mem::transmute(sym(lib, c"getservbyname_r")) };
    let g_byport: ByPortR = unsafe { std::mem::transmute(sym(lib, c"getservbyport_r")) };
    let g_entr: EntR = unsafe { std::mem::transmute(sym(lib, c"getservent_r")) };
    let g_ent: Ent = unsafe { std::mem::transmute(sym(lib, c"getservent")) };
    let g_set: Ctl = unsafe { std::mem::transmute(sym(lib, c"setservent")) };
    let g_end: End = unsafe { std::mem::transmute(sym(lib, c"endservent")) };

    // Enumerate probe targets from the host db.
    let mut probes: Vec<(Vec<u8>, Vec<u8>, c_int)> = Vec::new();
    g_set(1);
    loop {
        let e = g_ent();
        if e.is_null() {
            break;
        }
        let s = unsafe { &*e };
        probes.push((cstr(s.s_name), cstr(s.s_proto), s.s_port));
        let al = alias_vec(s.s_aliases);
        if let Some(a) = al.first() {
            probes.push((a.clone(), cstr(s.s_proto), s.s_port));
        }
        if probes.len() > 120 {
            break;
        }
    }
    g_end();

    let mut mismatches = Vec::new();
    let mk = || -> (Servent, [c_char; 1024]) {
        (
            Servent {
                s_name: std::ptr::null_mut(),
                s_aliases: std::ptr::null_mut(),
                s_port: 0,
                s_proto: std::ptr::null_mut(),
            },
            [0; 1024],
        )
    };

    for (name, proto, port_nbo) in &probes {
        let cn = CString::new(name.clone()).unwrap();
        let cp = CString::new(proto.clone()).unwrap();

        // getservbyname_r
        let (mut ge, mut gb) = mk();
        let mut gres: *mut Servent = std::ptr::null_mut();
        let grc = g_byname(
            cn.as_ptr(),
            cp.as_ptr(),
            &mut ge,
            gb.as_mut_ptr(),
            gb.len(),
            &mut gres,
        );
        let g = snap(grc, gres);

        let (mut fe, mut fb) = mk();
        let mut fres: *mut Servent = std::ptr::null_mut();
        let frc = unsafe {
            fli::getservbyname_r(
                cn.as_ptr(),
                cp.as_ptr(),
                (&mut fe as *mut Servent).cast(),
                fb.as_mut_ptr(),
                fb.len(),
                (&mut fres as *mut *mut Servent).cast(),
            )
        };
        let f = snap(frc, fres);
        if g != f {
            mismatches.push(format!(
                "getservbyname_r({name:?},{proto:?}): glibc={g:?} fl={f:?}"
            ));
        }

        // getservbyport_r
        let (mut ge, mut gb) = mk();
        let mut gres: *mut Servent = std::ptr::null_mut();
        let grc = g_byport(
            *port_nbo,
            cp.as_ptr(),
            &mut ge,
            gb.as_mut_ptr(),
            gb.len(),
            &mut gres,
        );
        let g = snap(grc, gres);

        let (mut fe, mut fb) = mk();
        let mut fres: *mut Servent = std::ptr::null_mut();
        let frc = unsafe {
            fli::getservbyport_r(
                *port_nbo,
                cp.as_ptr(),
                (&mut fe as *mut Servent).cast(),
                fb.as_mut_ptr(),
                fb.len(),
                (&mut fres as *mut *mut Servent).cast(),
            )
        };
        let f = snap(frc, fres);
        if g != f {
            mismatches.push(format!(
                "getservbyport_r({port_nbo},{proto:?}): glibc={g:?} fl={f:?}"
            ));
        }
    }

    // getservent_r lockstep enumeration
    let mut glist = Vec::new();
    g_set(1);
    loop {
        let (mut e, mut b) = mk();
        let mut res: *mut Servent = std::ptr::null_mut();
        let rc = g_entr(&mut e, b.as_mut_ptr(), b.len(), &mut res);
        match snap(rc, res) {
            Some(s) => glist.push(s),
            None => break,
        }
        if glist.len() > 2000 {
            break;
        }
    }
    g_end();

    let mut flist = Vec::new();
    unsafe { flu::setservent(1) };
    loop {
        let (mut e, mut b) = mk();
        let mut res: *mut Servent = std::ptr::null_mut();
        let rc = unsafe {
            flu::getservent_r(
                (&mut e as *mut Servent).cast(),
                b.as_mut_ptr(),
                b.len(),
                (&mut res as *mut *mut Servent).cast(),
            )
        };
        match snap(rc, res) {
            Some(s) => flist.push(s),
            None => break,
        }
        if flist.len() > 2000 {
            break;
        }
    }
    unsafe { flu::endservent() };
    if flist != glist {
        mismatches.push(format!(
            "getservent_r enumeration diverged: fl_len={} glibc_len={}",
            flist.len(),
            glist.len()
        ));
    }

    assert!(
        mismatches.is_empty(),
        "reentrant servent diverged from glibc ({} cases):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
