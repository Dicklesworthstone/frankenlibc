//! Differential gate: putsgent (gshadow writer) vs live host glibc.
//!
//! putsgent was a stub returning -1; glibc formats a `struct sgrp` as
//! `name:passwd:adm,joined:mem,joined\n` (NULL string fields render empty). Both
//! engines write into an `open_memstream` buffer (glibc reached via dlsym, fl
//! called directly since the test is a debug build with no no_mangle interpose)
//! and the produced bytes are compared exactly.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::pwd_abi as fl;
use std::ffi::{CString, c_char, c_int, c_void};

#[repr(C)]
struct Sgrp {
    sg_namp: *const c_char,
    sg_passwd: *const c_char,
    sg_adm: *const *const c_char,
    sg_mem: *const *const c_char,
}

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn open_memstream(ptr: *mut *mut c_char, sizeloc: *mut usize) -> *mut c_void;
    fn fflush(stream: *mut c_void) -> c_int;
    fn fclose(stream: *mut c_void) -> c_int;
    fn free(p: *mut c_void);
}
type PutFn = unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int;

fn glibc_putsgent() -> PutFn {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        std::mem::transmute(dlsym(h, c"putsgent".as_ptr()))
    }
}

/// Run a putsgent impl into an open_memstream and capture (rc, bytes).
fn run(f: PutFn, sg: &Sgrp) -> (c_int, Vec<u8>) {
    unsafe {
        let mut buf: *mut c_char = std::ptr::null_mut();
        let mut sz: usize = 0;
        let fp = open_memstream(&mut buf, &mut sz);
        assert!(!fp.is_null());
        let rc = f(sg as *const Sgrp as *const c_void, fp);
        fflush(fp);
        fclose(fp);
        let out = if buf.is_null() || sz == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(buf as *const u8, sz).to_vec()
        };
        if !buf.is_null() {
            free(buf as *mut c_void);
        }
        (rc, out)
    }
}

/// Build a NULL-terminated C string array, keeping the CStrings alive.
fn strlist(items: &[&str]) -> (Vec<CString>, Vec<*const c_char>) {
    let owned: Vec<CString> = items.iter().map(|s| CString::new(*s).unwrap()).collect();
    let mut ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    (owned, ptrs)
}

#[test]
fn putsgent_matches_glibc() {
    let g = glibc_putsgent();
    let fl_fn: PutFn = fl::putsgent;

    // (name, passwd_opt, adm names, mem names)
    let cases: &[(&str, Option<&str>, &[&str], &[&str])] = &[
        ("grp", Some("secret"), &["adm1", "adm2"], &["u1", "u2"]),
        ("g2", Some(""), &[], &[]),
        ("g3", None, &["only_adm"], &[]),
        ("g4", Some("x"), &[], &["m1", "m2", "m3"]),
        ("staff", Some("!"), &["root"], &["alice", "bob"]),
        ("empties", None, &[], &[]),
        ("single", Some("p"), &["a"], &["m"]),
    ];

    let mut mism = Vec::new();
    for (name, pw, adm, mem) in cases {
        let c_name = CString::new(*name).unwrap();
        let c_pw = pw.map(|s| CString::new(s).unwrap());
        let (_adm_own, adm_ptrs) = strlist(adm);
        let (_mem_own, mem_ptrs) = strlist(mem);
        let sg = Sgrp {
            sg_namp: c_name.as_ptr(),
            sg_passwd: c_pw.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            sg_adm: adm_ptrs.as_ptr(),
            sg_mem: mem_ptrs.as_ptr(),
        };
        let gr = run(g, &sg);
        let fr = run(fl_fn, &sg);
        if gr != fr {
            mism.push(format!(
                "{name:?}: glibc=({},{:02x?}) fl=({},{:02x?})",
                gr.0, gr.1, fr.0, fr.1
            ));
        }
    }
    assert!(mism.is_empty(), "putsgent diverged:\n{}", mism.join("\n"));
}
