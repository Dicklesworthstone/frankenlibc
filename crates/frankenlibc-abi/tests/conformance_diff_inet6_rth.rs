//! Differential gate: RFC 3542 inet6_rth_* (IPv6 routing header) vs live glibc.
//!
//! These were covered only by self-consistency tests (no glibc comparison). Here
//! we pin them against the host via dlsym: byte-exact build, segments/getaddr
//! agreement, and reverse() byte-exactness.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::glibc_internal_abi as fl;
use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
}
type SpaceFn = unsafe extern "C" fn(c_int, c_int) -> c_int;
type InitFn = unsafe extern "C" fn(*mut c_void, c_int, c_int, c_int) -> *mut c_void;
type AddFn = unsafe extern "C" fn(*mut c_void, *const c_void) -> c_int;
type SegFn = unsafe extern "C" fn(*const c_void) -> c_int;
type GetAddrFn = unsafe extern "C" fn(*const c_void, c_int) -> *const c_void;
type RevFn = unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int;

struct G {
    space: SpaceFn,
    init: InitFn,
    add: AddFn,
    seg: SegFn,
    getaddr: GetAddrFn,
    rev: RevFn,
}
fn glibc() -> G {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        let s = |n: &std::ffi::CStr| dlsym(h, n.as_ptr());
        G {
            space: std::mem::transmute(s(c"inet6_rth_space")),
            init: std::mem::transmute(s(c"inet6_rth_init")),
            add: std::mem::transmute(s(c"inet6_rth_add")),
            seg: std::mem::transmute(s(c"inet6_rth_segments")),
            getaddr: std::mem::transmute(s(c"inet6_rth_getaddr")),
            rev: std::mem::transmute(s(c"inet6_rth_reverse")),
        }
    }
}

fn addr(seed: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    for (i, b) in a.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    a
}

#[test]
fn space_matches_glibc() {
    let g = glibc();
    for typ in [-1, 0, 1, 2, 99] {
        for seg in [-1, 0, 1, 2, 5, 127, 128, 200] {
            let gv = unsafe { (g.space)(typ, seg) };
            let fv = unsafe { fl::inet6_rth_space(typ, seg) };
            assert_eq!(gv, fv, "space(type={typ},seg={seg}): glibc={gv} fl={fv}");
        }
    }
}

#[test]
fn build_byte_exact() {
    let g = glibc();
    for nseg in 0..=5usize {
        let blen = unsafe { (g.space)(0, nseg as c_int) };
        assert!(blen > 0 || nseg == 0);
        let build = |init: InitFn, add: AddFn| -> Option<Vec<u8>> {
            let mut buf = vec![0u8; blen.max(8) as usize];
            let bp = unsafe { init(buf.as_mut_ptr().cast(), blen, 0, nseg as c_int) };
            if bp.is_null() {
                return None;
            }
            for s in 0..nseg {
                let a = addr(s as u8 * 16 + 1);
                if unsafe { add(bp, a.as_ptr().cast()) } != 0 {
                    return None;
                }
            }
            Some(buf)
        };
        let gb = build(g.init, g.add);
        let fb = build(fl::inet6_rth_init, fl::inet6_rth_add);
        assert_eq!(gb, fb, "rth build nseg={nseg}: glibc={gb:02x?} fl={fb:02x?}");

        // One extra add() past capacity must fail on both.
        if nseg > 0 {
            let mut buf = vec![0u8; blen as usize];
            let bp = unsafe { (g.init)(buf.as_mut_ptr().cast(), blen, 0, nseg as c_int) };
            for s in 0..nseg {
                unsafe { (g.add)(bp, addr(s as u8).as_ptr().cast()) };
            }
            let over = addr(0xFF);
            let g_over = unsafe { (g.add)(bp, over.as_ptr().cast()) };
            let mut fbuf = vec![0u8; blen as usize];
            let fbp = unsafe { fl::inet6_rth_init(fbuf.as_mut_ptr().cast(), blen, 0, nseg as c_int) };
            for s in 0..nseg {
                unsafe { fl::inet6_rth_add(fbp, addr(s as u8).as_ptr().cast()) };
            }
            let f_over = unsafe { fl::inet6_rth_add(fbp, over.as_ptr().cast()) };
            assert_eq!(g_over.signum(), f_over.signum(), "over-capacity add nseg={nseg}");
        }
    }
}

#[test]
fn segments_getaddr_reverse_match() {
    let g = glibc();
    let nseg = 4usize;
    let blen = unsafe { (g.space)(0, nseg as c_int) };
    // Build the canonical header with glibc.
    let mut buf = vec![0u8; blen as usize];
    let bp = unsafe { (g.init)(buf.as_mut_ptr().cast(), blen, 0, nseg as c_int) };
    assert!(!bp.is_null());
    for s in 0..nseg {
        assert_eq!(unsafe { (g.add)(bp, addr(s as u8 * 16 + 3).as_ptr().cast()) }, 0);
    }

    // segments
    assert_eq!(
        unsafe { (g.seg)(buf.as_ptr().cast()) },
        unsafe { fl::inet6_rth_segments(buf.as_ptr().cast()) },
        "segments mismatch"
    );

    // getaddr per index (compare the 16 bytes pointed to), plus out-of-range.
    for i in 0..(nseg as c_int + 2) {
        let gp = unsafe { (g.getaddr)(buf.as_ptr().cast(), i) };
        let fp = unsafe { fl::inet6_rth_getaddr(buf.as_ptr().cast(), i) };
        assert_eq!(gp.is_null(), fp.is_null(), "getaddr({i}) null-ness");
        if !gp.is_null() {
            let ga = unsafe { std::slice::from_raw_parts(gp as *const u8, 16) };
            let fa = unsafe { std::slice::from_raw_parts(fp as *const u8, 16) };
            assert_eq!(ga, fa, "getaddr({i}) content");
        }
    }

    // reverse into a fresh buffer with each engine; compare bytes.
    let mut gout = vec![0u8; blen as usize];
    let mut fout = vec![0u8; blen as usize];
    let gr = unsafe { (g.rev)(buf.as_ptr().cast(), gout.as_mut_ptr().cast()) };
    let fr = unsafe { fl::inet6_rth_reverse(buf.as_ptr().cast(), fout.as_mut_ptr().cast()) };
    assert_eq!(gr.signum(), fr.signum(), "reverse rc");
    assert_eq!(gout, fout, "reverse bytes: glibc={gout:02x?} fl={fout:02x?}");
}
