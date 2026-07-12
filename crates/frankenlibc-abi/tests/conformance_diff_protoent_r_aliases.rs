//! Differential gate: reentrant getprotobyname_r / getprotobynumber_r /
//! getprotoent_r must return the canonical name and aliases like glibc.
//!
//! fl's reentrant protoent path wrote an empty p_aliases list, and
//! getprotobyname_r matched only the canonical name (not aliases) and echoed
//! it. Now all three route through the shared parser. glibc is reached via
//! dlsym to bypass fl's no_mangle interposition; both read /etc/protocols.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as flu;
use std::ffi::{CStr, CString, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

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
type Snap = (Vec<u8>, c_int, Vec<Vec<u8>>);
fn snap(rc: c_int, res: *mut Protoent) -> Option<Snap> {
    if rc != 0 || res.is_null() {
        return None;
    }
    let s = unsafe { &*res };
    Some((cstr(s.p_name), s.p_proto, alias_vec(s.p_aliases)))
}

type ByNameR =
    extern "C" fn(*const c_char, *mut Protoent, *mut c_char, usize, *mut *mut Protoent) -> c_int;
type ByNumR = extern "C" fn(c_int, *mut Protoent, *mut c_char, usize, *mut *mut Protoent) -> c_int;
type EntR = extern "C" fn(*mut Protoent, *mut c_char, usize, *mut *mut Protoent) -> c_int;
type Ent = extern "C" fn() -> *mut Protoent;
type Ctl = extern "C" fn(c_int);
type End = extern "C" fn();

#[test]
fn protoent_reentrant_matches_glibc() {
    let lib = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null(), "dlopen libc.so.6 failed");
    let g_byname: ByNameR = unsafe { std::mem::transmute(sym(lib, c"getprotobyname_r")) };
    let g_bynum: ByNumR = unsafe { std::mem::transmute(sym(lib, c"getprotobynumber_r")) };
    let g_entr: EntR = unsafe { std::mem::transmute(sym(lib, c"getprotoent_r")) };
    let g_ent: Ent = unsafe { std::mem::transmute(sym(lib, c"getprotoent")) };
    let g_set: Ctl = unsafe { std::mem::transmute(sym(lib, c"setprotoent")) };
    let g_end: End = unsafe { std::mem::transmute(sym(lib, c"endprotoent")) };

    let mk = || -> (Protoent, [c_char; 1024]) {
        (
            Protoent {
                p_name: std::ptr::null_mut(),
                p_aliases: std::ptr::null_mut(),
                p_proto: 0,
            },
            [0; 1024],
        )
    };

    // Enumerate probe names/numbers from host db (+ first alias of each).
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut nums: Vec<c_int> = Vec::new();
    g_set(1);
    loop {
        let e = g_ent();
        if e.is_null() {
            break;
        }
        let s = unsafe { &*e };
        names.push(cstr(s.p_name));
        nums.push(s.p_proto);
        let al = alias_vec(s.p_aliases);
        if let Some(a) = al.first() {
            names.push(a.clone());
        }
        if names.len() > 200 {
            break;
        }
    }
    g_end();

    let mut mismatches = Vec::new();

    for name in &names {
        let cn = CString::new(name.clone()).unwrap();
        let (mut ge, mut gb) = mk();
        let mut gres: *mut Protoent = std::ptr::null_mut();
        let grc = g_byname(cn.as_ptr(), &mut ge, gb.as_mut_ptr(), gb.len(), &mut gres);
        let g = snap(grc, gres);
        let (mut fe, mut fb) = mk();
        let mut fres: *mut Protoent = std::ptr::null_mut();
        let frc = unsafe {
            flu::getprotobyname_r(
                cn.as_ptr(),
                (&mut fe as *mut Protoent).cast(),
                fb.as_mut_ptr(),
                fb.len(),
                (&mut fres as *mut *mut Protoent).cast(),
            )
        };
        let f = snap(frc, fres);
        if g != f {
            mismatches.push(format!("getprotobyname_r({name:?}): glibc={g:?} fl={f:?}"));
        }
    }

    for &num in &nums {
        let (mut ge, mut gb) = mk();
        let mut gres: *mut Protoent = std::ptr::null_mut();
        let grc = g_bynum(num, &mut ge, gb.as_mut_ptr(), gb.len(), &mut gres);
        let g = snap(grc, gres);
        let (mut fe, mut fb) = mk();
        let mut fres: *mut Protoent = std::ptr::null_mut();
        let frc = unsafe {
            flu::getprotobynumber_r(
                num,
                (&mut fe as *mut Protoent).cast(),
                fb.as_mut_ptr(),
                fb.len(),
                (&mut fres as *mut *mut Protoent).cast(),
            )
        };
        let f = snap(frc, fres);
        if g != f {
            mismatches.push(format!("getprotobynumber_r({num}): glibc={g:?} fl={f:?}"));
        }
    }

    // getprotoent_r lockstep enumeration
    let mut glist = Vec::new();
    g_set(1);
    loop {
        let (mut e, mut b) = mk();
        let mut res: *mut Protoent = std::ptr::null_mut();
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
    unsafe { flu::setprotoent(1) };
    loop {
        let (mut e, mut b) = mk();
        let mut res: *mut Protoent = std::ptr::null_mut();
        let rc = unsafe {
            flu::getprotoent_r(
                (&mut e as *mut Protoent).cast(),
                b.as_mut_ptr(),
                b.len(),
                (&mut res as *mut *mut Protoent).cast(),
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
    unsafe { flu::endprotoent() };
    if flist != glist {
        mismatches.push(format!(
            "getprotoent_r enumeration diverged: fl_len={} glibc_len={}",
            flist.len(),
            glist.len()
        ));
    }

    assert!(
        mismatches.is_empty(),
        "reentrant protoent diverged from glibc ({} cases):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
