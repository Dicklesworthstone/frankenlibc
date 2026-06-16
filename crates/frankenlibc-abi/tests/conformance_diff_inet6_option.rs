//! Differential gate: RFC 2292 inet6_option_* helpers vs live host glibc.
//!
//! These pure cmsghdr/ip6_ext buffer manipulators (deprecated by RFC 3542 but
//! still shipped & functional in glibc) were previously stubbed in fl. We now
//! port glibc's inet/inet6_option.c and pin every function byte-for-byte against
//! the host via dlsym (so glibc's symbols bypass fl's no_mangle interposition).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::glibc_internal_abi as fl;
use std::ffi::{c_int, c_void};

const RTLD_NOW: c_int = 2;
const HOPOPTS: c_int = 54;
const DSTOPTS: c_int = 59;

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
}

type SpaceFn = unsafe extern "C" fn(c_int) -> c_int;
type InitFn = unsafe extern "C" fn(*mut c_void, *mut *mut c_void, c_int) -> c_int;
type AppendFn = unsafe extern "C" fn(*mut c_void, *const u8, c_int, c_int) -> c_int;
type AllocFn = unsafe extern "C" fn(*mut c_void, c_int, c_int, c_int) -> *mut u8;
type NextFn = unsafe extern "C" fn(*const c_void, *mut *mut u8) -> c_int;
type FindFn = unsafe extern "C" fn(*const c_void, *mut *mut u8, c_int) -> c_int;

struct Glibc {
    space: SpaceFn,
    init: InitFn,
    append: AppendFn,
    alloc: AllocFn,
    next: NextFn,
    find: FindFn,
}
fn glibc() -> Glibc {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!h.is_null());
        let s = |n: &std::ffi::CStr| dlsym(h, n.as_ptr());
        Glibc {
            space: std::mem::transmute(s(c"inet6_option_space")),
            init: std::mem::transmute(s(c"inet6_option_init")),
            append: std::mem::transmute(s(c"inet6_option_append")),
            alloc: std::mem::transmute(s(c"inet6_option_alloc")),
            next: std::mem::transmute(s(c"inet6_option_next")),
            find: std::mem::transmute(s(c"inet6_option_find")),
        }
    }
}

#[test]
fn space_matches_glibc() {
    let g = glibc();
    for n in -4i32..512 {
        let gv = unsafe { (g.space)(n) };
        let fv = unsafe { fl::inet6_option_space(n) };
        assert_eq!(gv, fv, "inet6_option_space({n}): glibc={gv} fl={fv}");
    }
}

/// Build an option object with fl, returning (cmsg_len, buffer bytes).
fn build_fl(typ: c_int, appends: &[(Vec<u8>, c_int, c_int)]) -> Option<(usize, Vec<u8>)> {
    let mut buf = vec![0u8; 1024];
    let mut cmsgp: *mut c_void = std::ptr::null_mut();
    if unsafe { fl::inet6_option_init(buf.as_mut_ptr().cast(), &mut cmsgp, typ) } != 0 {
        return None;
    }
    for (opt, multx, plusy) in appends {
        if unsafe { fl::inet6_option_append(cmsgp, opt.as_ptr(), *multx, *plusy) } != 0 {
            return None;
        }
    }
    let clen = unsafe { (buf.as_ptr() as *const usize).read() };
    Some((clen, buf[..clen.min(1024)].to_vec()))
}
fn build_glibc_full(g: &Glibc, typ: c_int, appends: &[(Vec<u8>, c_int, c_int)]) -> Option<(usize, Vec<u8>)> {
    let mut buf = vec![0u8; 1024];
    let mut cmsgp: *mut c_void = std::ptr::null_mut();
    if unsafe { (g.init)(buf.as_mut_ptr().cast(), &mut cmsgp, typ) } != 0 {
        return None;
    }
    for (opt, multx, plusy) in appends {
        if unsafe { (g.append)(cmsgp, opt.as_ptr(), *multx, *plusy) } != 0 {
            return None;
        }
    }
    let clen = unsafe { (buf.as_ptr() as *const usize).read() };
    Some((clen, buf[..clen.min(1024)].to_vec()))
}

#[test]
fn init_append_byte_exact() {
    let g = glibc();
    // A spread of option payloads (type, len, data...) with assorted alignments.
    let opts: Vec<(Vec<u8>, c_int, c_int)> = vec![
        (vec![0x00], 1, 0),                          // Pad1
        (vec![0x01, 0x00], 1, 0),                    // PadN len 0
        (vec![0xC2, 0x04, 1, 2, 3, 4], 4, 2),        // jumbo-ish, align 4n+2
        (vec![0x05, 0x02, 0xAA, 0xBB], 2, 0),        // router-alert-ish, align 2
        (vec![0xC9, 0x03, 9, 8, 7], 8, 4),           // align 8n+4
        (vec![0x07, 0x01, 0x42], 1, 0),
    ];
    let mut mism = Vec::new();
    // Try every non-empty prefix of the option list, in both HOPOPTS/DSTOPTS.
    for typ in [HOPOPTS, DSTOPTS] {
        for k in 1..=opts.len() {
            let seq = &opts[..k];
            let gr = build_glibc_full(&g, typ, seq);
            let fr = build_fl(typ, seq);
            if gr != fr {
                mism.push(format!("typ={typ} k={k}: glibc={gr:02x?} fl={fr:02x?}"));
            }
        }
    }
    assert!(mism.is_empty(), "inet6 init/append diverged ({}):\n{}", mism.len(), mism.join("\n"));
}

#[test]
fn alloc_matches_append() {
    // inet6_option_alloc with bad alignment args must fail identically (NULL).
    let g = glibc();
    let mut gbuf = vec![0u8; 256];
    let mut fbuf = vec![0u8; 256];
    let mut gc: *mut c_void = std::ptr::null_mut();
    let mut fc: *mut c_void = std::ptr::null_mut();
    unsafe { (g.init)(gbuf.as_mut_ptr().cast(), &mut gc, HOPOPTS) };
    unsafe { fl::inet6_option_init(fbuf.as_mut_ptr().cast(), &mut fc, HOPOPTS) };
    for &(datalen, multx, plusy) in &[
        (4, 3, 0),  // bad multx -> NULL
        (4, 4, 8),  // bad plusy -> NULL
        (4, 4, -1), // bad plusy -> NULL
        (8, 8, 0),  // valid
        (2, 1, 0),  // valid
    ] {
        let gp = unsafe { (g.alloc)(gc, datalen, multx, plusy) };
        let fp = unsafe { fl::inet6_option_alloc(fc, datalen, multx, plusy) };
        // Compare null-ness and the relative offset into the buffer.
        let goff = if gp.is_null() { -1i64 } else { gp as i64 - gbuf.as_ptr() as i64 };
        let foff = if fp.is_null() { -1i64 } else { fp as i64 - fbuf.as_ptr() as i64 };
        assert_eq!(goff, foff, "alloc(datalen={datalen},multx={multx},plusy={plusy}) offset mismatch");
    }
}

#[test]
fn next_and_find_walk_identically() {
    let g = glibc();
    // Build a multi-option object with glibc, then walk it with both engines.
    let opts: Vec<(Vec<u8>, c_int, c_int)> = vec![
        (vec![0x05, 0x02, 0xAA, 0xBB], 2, 0),
        (vec![0xC2, 0x04, 1, 2, 3, 4], 4, 2),
        (vec![0x07, 0x01, 0x42], 1, 0),
    ];
    let mut buf = vec![0u8; 1024];
    let mut cmsgp: *mut c_void = std::ptr::null_mut();
    assert_eq!(unsafe { (g.init)(buf.as_mut_ptr().cast(), &mut cmsgp, HOPOPTS) }, 0);
    for (opt, multx, plusy) in &opts {
        assert_eq!(unsafe { (g.append)(cmsgp, opt.as_ptr(), *multx, *plusy) }, 0);
    }
    let base = buf.as_ptr() as i64;

    // Walk with inet6_option_next: collect (rc, offset) at each step.
    let walk_next = |f: NextFn| -> Vec<(c_int, i64)> {
        let mut out = Vec::new();
        let mut t: *mut u8 = std::ptr::null_mut();
        loop {
            let rc = unsafe { f(cmsgp, &mut t) };
            let off = if t.is_null() { -1 } else { t as i64 - base };
            out.push((rc, off));
            if rc != 0 {
                break;
            }
        }
        out
    };
    assert_eq!(walk_next(g.next), walk_next(fl::inet6_option_next), "next walk diverged");

    // Find each present type plus an absent one, from a fresh start.
    let find_one = |f: FindFn, typ: c_int| -> (c_int, i64) {
        let mut t: *mut u8 = std::ptr::null_mut();
        let rc = unsafe { f(cmsgp, &mut t, typ) };
        (rc, if t.is_null() { -1 } else { t as i64 - base })
    };
    for typ in [0x05, 0xC2, 0x07, 0x99, 0x00] {
        assert_eq!(
            find_one(g.find, typ),
            find_one(fl::inet6_option_find, typ),
            "find(type={typ:#x}) diverged"
        );
    }
}
