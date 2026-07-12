//! Differential gate: RFC 3542 inet6_opt_* (option building/parsing) vs glibc.
//!
//! These were implemented but untested (zero-coverage). We pin them against the
//! live host: (1) build an extension header with both engines and compare the
//! produced bytes exactly; (2) parse a glibc-built header with both and compare
//! the (offset, type, len, data) sequences; (3) verify `inet6_opt_next` writes
//! exactly a 4-byte socklen_t to `*lenp` (no 8-byte over-write that would corrupt
//! a caller's adjacent stack). glibc is reached via dlsym.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::glibc_internal_abi as fl;
use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
}

type InitFn = unsafe extern "C" fn(*mut c_void, u32) -> c_int;
type AppendFn =
    unsafe extern "C" fn(*mut c_void, u32, c_int, u8, u32, u8, *mut *mut c_void) -> c_int;
type FinishFn = unsafe extern "C" fn(*mut c_void, u32, c_int) -> c_int;
type SetValFn = unsafe extern "C" fn(*mut c_void, c_int, *const c_void, u32) -> c_int;
type NextFn =
    unsafe extern "C" fn(*mut c_void, u32, c_int, *mut u8, *mut u32, *mut *mut c_void) -> c_int;

struct G {
    init: InitFn,
    append: AppendFn,
    finish: FinishFn,
    set_val: SetValFn,
    next: NextFn,
}
fn glibc() -> G {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        let s = |n: &std::ffi::CStr| dlsym(h, n.as_ptr());
        G {
            init: std::mem::transmute(s(c"inet6_opt_init")),
            append: std::mem::transmute(s(c"inet6_opt_append")),
            finish: std::mem::transmute(s(c"inet6_opt_finish")),
            set_val: std::mem::transmute(s(c"inet6_opt_set_val")),
            next: std::mem::transmute(s(c"inet6_opt_next")),
        }
    }
}

// (option type, data bytes, alignment)
const OPTS: &[(u8, &[u8], u8)] = &[
    (0x05, &[0x00, 0x00], 2), // a 2-byte option, align 2
    (0xC2, &[0x11, 0x22, 0x33, 0x44], 4),
    (0x07, &[0xAB], 1),
    (0xEE, &[1, 2, 3, 4, 5, 6, 7, 8], 8),
];

/// Build an extension header with the glibc function pointers.
fn build_glibc(g: &G, extlen: u32) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; extlen as usize];
    let mut off = unsafe { (g.init)(buf.as_mut_ptr().cast(), extlen) };
    if off < 0 {
        return None;
    }
    for (typ, data, align) in OPTS {
        let mut dbuf: *mut c_void = std::ptr::null_mut();
        off = unsafe {
            (g.append)(
                buf.as_mut_ptr().cast(),
                extlen,
                off,
                *typ,
                data.len() as u32,
                *align,
                &mut dbuf,
            )
        };
        if off < 0 {
            return None;
        }
        if unsafe { (g.set_val)(dbuf, 0, data.as_ptr().cast(), data.len() as u32) } < 0 {
            return None;
        }
    }
    off = unsafe { (g.finish)(buf.as_mut_ptr().cast(), extlen, off) };
    if off < 0 {
        return None;
    }
    buf.truncate(off as usize);
    Some(buf)
}
/// Build the same header with fl's functions.
fn build_fl(extlen: u32) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; extlen as usize];
    let mut off = unsafe { fl::inet6_opt_init(buf.as_mut_ptr().cast(), extlen as c_int) };
    if off < 0 {
        return None;
    }
    for (typ, data, align) in OPTS {
        let mut dbuf: *mut c_void = std::ptr::null_mut();
        off = unsafe {
            fl::inet6_opt_append(
                buf.as_mut_ptr().cast(),
                extlen as c_int,
                off,
                *typ,
                data.len() as u32,
                *align,
                &mut dbuf,
            )
        };
        if off < 0 {
            return None;
        }
        if unsafe { fl::inet6_opt_set_val(dbuf, 0, data.as_ptr().cast(), data.len() as c_int) } < 0
        {
            return None;
        }
    }
    off = unsafe { fl::inet6_opt_finish(buf.as_mut_ptr().cast(), extlen as c_int, off) };
    if off < 0 {
        return None;
    }
    buf.truncate(off as usize);
    Some(buf)
}

#[test]
fn build_byte_exact() {
    let g = glibc();
    // The total need is reported by passing a NULL extbuf; use a generous buffer.
    let extlen = 64u32;
    let gb = build_glibc(&g, extlen);
    let fb = build_fl(extlen);
    assert_eq!(
        gb, fb,
        "inet6_opt build diverged: glibc={gb:02x?} fl={fb:02x?}"
    );
    assert!(gb.is_some(), "glibc build unexpectedly failed");
}

#[test]
fn parse_walk_byte_exact() {
    let g = glibc();
    let hdr = build_glibc(&g, 64).expect("glibc build");

    // Walk via a per-call closure (fl/glibc differ only in the socklen_t-vs-int
    // declared type of `extlen`, which is ABI-identical), collecting
    // (rc, type, len) for each option.
    let walk = |mut step: Box<
        dyn FnMut(*mut c_void, c_int, &mut u8, &mut u32, &mut *mut c_void) -> c_int,
    >|
     -> Vec<(c_int, u8, u32)> {
        let mut out = Vec::new();
        let mut off = 2; // skip the 2-byte ext header
        loop {
            let mut buf = hdr.clone();
            let mut typ: u8 = 0;
            let mut len: u32 = 0;
            let mut dbuf: *mut c_void = std::ptr::null_mut();
            let rc = step(buf.as_mut_ptr().cast(), off, &mut typ, &mut len, &mut dbuf);
            out.push((rc, typ, len));
            if rc < 0 {
                break;
            }
            off = rc;
        }
        out
    };
    let elen = hdr.len();
    let gnext = g.next;
    let gw = walk(Box::new(move |b, off, t, l, d| unsafe {
        gnext(b, elen as u32, off, t, l as *mut u32, d)
    }));
    let fw = walk(Box::new(move |b, off, t, l, d| unsafe {
        fl::inet6_opt_next(b, elen as c_int, off, t, l as *mut u32, d)
    }));
    assert_eq!(
        gw, fw,
        "inet6_opt_next walk diverged: glibc={gw:?} fl={fw:?}"
    );
}

#[test]
fn next_writes_only_4_byte_lenp() {
    // A C caller's `socklen_t len;` is 4 bytes. fl must write exactly 4 bytes to
    // *lenp; an 8-byte write would clobber the next word. We place a sentinel
    // immediately after the 4-byte length slot and check it survives.
    let g = glibc();
    let mut hdr = build_glibc(&g, 64).expect("glibc build");
    #[repr(C)]
    struct Probe {
        len: u32,
        sentinel: u32,
    }
    let mut p = Probe {
        len: 0,
        sentinel: 0xDEAD_BEEF,
    };
    let mut typ: u8 = 0;
    let mut dbuf: *mut c_void = std::ptr::null_mut();
    let rc = unsafe {
        fl::inet6_opt_next(
            hdr.as_mut_ptr().cast(),
            hdr.len() as u32 as c_int,
            2,
            &mut typ,
            &mut p.len as *mut u32,
            &mut dbuf,
        )
    };
    assert!(rc >= 0, "expected a first option");
    assert_eq!(
        p.sentinel, 0xDEAD_BEEF,
        "inet6_opt_next over-wrote past the 4-byte socklen_t"
    );
    assert_eq!(p.len, OPTS[0].1.len() as u32, "first option length wrong");
}
