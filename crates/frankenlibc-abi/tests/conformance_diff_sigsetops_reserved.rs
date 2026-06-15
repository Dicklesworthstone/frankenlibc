//! Differential gate for sigaddset/sigdelset/sigfillset handling of glibc's
//! reserved internal signals 32 (SIGCANCEL) and 33 (SIGSETXID) vs glibc.
//!
//! glibc reserves signals 32/33 (so SIGRTMIN == 34): sigaddset/sigdelset reject
//! them with -1/EINVAL, sigfillset leaves their bits CLEAR (word[0] ==
//! 0xfffffffe7fffffff), and sigismember reports 0 for them (no error). fl
//! previously accepted 32/33 in add/del and set their bits in sigfillset.
//!
//! fl is called via its Rust path; glibc via dlsym on libc.so.6. Note: fl's
//! __errno_location interposes glibc in-process, so the glibc side's errno write
//! lands in glibc's TLS and is not observable here — we compare return values
//! and the resulting sigset bits against glibc, and check fl's OWN errno is
//! EINVAL on its -1 returns (the value a standalone glibc oracle also sets).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::signal_abi as fl;
use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn __errno_location() -> *mut c_int;
}
type Op = unsafe extern "C" fn(*mut libc::sigset_t, c_int) -> c_int;
type Fill = unsafe extern "C" fn(*mut libc::sigset_t) -> c_int;

fn g(name: &std::ffi::CStr) -> *mut c_void {
    let h = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null());
    let p = unsafe { dlsym(h, name.as_ptr()) };
    assert!(!p.is_null(), "missing {name:?}");
    p
}

fn empty() -> libc::sigset_t {
    unsafe { std::mem::zeroed() }
}
fn word0(s: &libc::sigset_t) -> u64 {
    let mut w = [0u8; 8];
    unsafe { std::ptr::copy_nonoverlapping(s as *const _ as *const u8, w.as_mut_ptr(), 8) };
    u64::from_ne_bytes(w)
}

#[test]
fn sigsetops_reserved_signals_match_glibc() {
    let g_add: Op = unsafe { core::mem::transmute(g(c"sigaddset")) };
    let g_del: Op = unsafe { core::mem::transmute(g(c"sigdelset")) };
    let g_mem: Op = unsafe { core::mem::transmute(g(c"sigismember")) };
    let g_fill: Fill = unsafe { core::mem::transmute(g(c"sigfillset")) };

    let mut div = Vec::new();

    // fl's own errno after a -1 return must be EINVAL (matches a standalone
    // glibc oracle); the glibc-via-dlsym side's errno is not observable here.
    let check_fl_errno = |rc: c_int, e: c_int, label: &str, div: &mut Vec<String>| {
        if rc == -1 && e != libc::EINVAL {
            div.push(format!("{label}: fl rc=-1 but errno={e} (want EINVAL {})", libc::EINVAL));
        }
    };

    // add / del / ismember across the boundary signals.
    for sig in [0, 1, 31, 32, 33, 34, 64, 65] {
        // sigaddset on an empty set: compare rc + resulting bits vs glibc.
        let (mut fs, mut gs) = (empty(), empty());
        unsafe { *__errno_location() = 0 };
        let fr = unsafe { fl::sigaddset(&mut fs, sig) };
        let fe = unsafe { *__errno_location() };
        let gr = unsafe { g_add(&mut gs, sig) };
        if fr != gr || word0(&fs) != word0(&gs) {
            div.push(format!("sigaddset({sig}): fl=(rc{fr},w{:#x}) glibc=(rc{gr},w{:#x})", word0(&fs), word0(&gs)));
        }
        check_fl_errno(fr, fe, &format!("sigaddset({sig})"), &mut div);

        // sigdelset on a full set: compare rc + resulting bits vs glibc.
        let (mut fd, mut gd) = (empty(), empty());
        unsafe { fl::sigfillset(&mut fd) };
        unsafe { g_fill(&mut gd) };
        unsafe { *__errno_location() = 0 };
        let fr = unsafe { fl::sigdelset(&mut fd, sig) };
        let fe = unsafe { *__errno_location() };
        let gr = unsafe { g_del(&mut gd, sig) };
        if fr != gr || word0(&fd) != word0(&gd) {
            div.push(format!("sigdelset({sig}): fl=(rc{fr},w{:#x}) glibc=(rc{gr},w{:#x})", word0(&fd), word0(&gd)));
        }
        check_fl_errno(fr, fe, &format!("sigdelset({sig})"), &mut div);

        // sigismember on a full set: compare rc vs glibc.
        let (mut ff, mut gf) = (empty(), empty());
        unsafe { fl::sigfillset(&mut ff) };
        unsafe { g_fill(&mut gf) };
        unsafe { *__errno_location() = 0 };
        let fr = unsafe { fl::sigismember(&ff, sig) };
        let fe = unsafe { *__errno_location() };
        let gr = unsafe { g_mem(&mut gf, sig) };
        if fr != gr {
            div.push(format!("sigismember({sig}) on full: fl=rc{fr} glibc=rc{gr}"));
        }
        check_fl_errno(fr, fe, &format!("sigismember({sig})"), &mut div);
    }

    // sigfillset word 0 must match glibc exactly (reserved bits cleared).
    let (mut ff, mut gf) = (empty(), empty());
    unsafe { fl::sigfillset(&mut ff) };
    unsafe { g_fill(&mut gf) };
    if word0(&ff) != word0(&gf) {
        div.push(format!("sigfillset word0: fl={:#018x} glibc={:#018x}", word0(&ff), word0(&gf)));
    }

    assert!(div.is_empty(), "sigsetops divergences ({}):\n  {}", div.len(), div.join("\n  "));
}
