#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc getdomainname oracle

//! Differential gate for `getdomainname` vs live host glibc (bd-crp0rw).
//!
//! The bead asked for a gate proving `NULL` + nonzero length returns -1/EFAULT
//! "like glibc". Measured against live glibc 2.42 on this host, that premise is
//! false: glibc has NO null guard and **segfaults**. So this file does not
//! assert parity there. It splits into the two things that are actually true:
//!
//!   1. On every input where glibc has defined behaviour, fl must match it
//!      exactly -- including the subtle part, which is that glibc truncates
//!      like `strncpy` and NUL-terminates only when the terminator fits. A
//!      buffer of exactly `strlen(domain)` comes back WITHOUT a NUL.
//!   2. `NULL` is a deliberate TSM hardening divergence, not parity. fl returns
//!      -1/EFAULT where glibc dies. The gate proves glibc's side of that by
//!      running it in a forked child and requiring the child to die on SIGSEGV,
//!      so the divergence is a measured fact rather than a comment.
//!
//! No mocks; glibc is reached by dlsym and asserted to be a distinct entry
//! point from fl's.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_abi::unistd_abi as fl;

type GetDomainNameFn = unsafe extern "C" fn(*mut c_char, usize) -> c_int;

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
    fn fork() -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn _exit(code: c_int) -> !;
    fn __errno_location() -> *mut c_int;
}

const BUF: usize = 512;
const FILL: u8 = 0xAA;

fn glibc_getdomainname() -> GetDomainNameFn {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2 /* RTLD_NOW */);
        assert!(!h.is_null(), "dlopen(libc.so.6) failed");
        let s = dlsym(h, c"getdomainname".as_ptr());
        assert!(!s.is_null(), "dlsym(getdomainname) failed");
        assert_ne!(
            s as usize,
            fl::getdomainname as *const () as usize,
            "glibc getdomainname resolved to fl's own symbol — the arms are not distinct"
        );
        std::mem::transmute::<*mut c_void, GetDomainNameFn>(s)
    }
}

/// Call `f` into a poisoned buffer and report `(rc, errno, whole buffer)`.
/// The whole buffer is returned so the comparison catches a missing terminator
/// and a write past `len` alike.
fn call(f: GetDomainNameFn, len: usize) -> (c_int, c_int, Vec<u8>) {
    let mut buf = vec![FILL; BUF];
    unsafe { *__errno_location() = 0 };
    let rc = unsafe { f(buf.as_mut_ptr().cast::<c_char>(), len) };
    let err = unsafe { *__errno_location() };
    (rc, err, buf)
}

/// The host's NIS domain name, read through glibc with room to spare.
fn domain_len() -> usize {
    let (rc, _, buf) = call(glibc_getdomainname(), BUF);
    assert_eq!(rc, 0, "glibc getdomainname with a {BUF}-byte buffer failed");
    buf.iter()
        .position(|&b| b == 0)
        .expect("no NUL in domainname")
}

#[test]
fn getdomainname_matches_glibc_across_buffer_lengths() {
    let g = glibc_getdomainname();
    let dl = domain_len();

    // Around the boundary that decides whether the NUL fits, plus the degenerate
    // and generous ends.
    let mut lens = vec![0usize, 1, 2, BUF];
    for d in [dl.saturating_sub(1), dl, dl + 1, dl + 8] {
        lens.push(d);
    }
    lens.sort_unstable();
    lens.dedup();

    for len in lens {
        let (rc_g, err_g, buf_g) = call(g, len);
        let (rc_f, err_f, buf_f) = call(fl::getdomainname, len);
        assert_eq!(
            rc_f, rc_g,
            "getdomainname(len={len}) rc: fl={rc_f} glibc={rc_g}"
        );
        if rc_g == 0 {
            assert_eq!(
                err_f, err_g,
                "getdomainname(len={len}) errno: fl={err_f} glibc={err_g}"
            );
        }
        assert_eq!(
            buf_f,
            buf_g,
            "getdomainname(len={len}) wrote different bytes: fl={:?} glibc={:?}",
            &buf_f[..(len + 2).min(BUF)],
            &buf_g[..(len + 2).min(BUF)]
        );
    }
}

#[test]
fn getdomainname_exact_fit_is_not_nul_terminated_like_glibc() {
    // The easy thing to get wrong: with len == strlen(domain) glibc copies all
    // the bytes and leaves NO terminator, so the caller's buffer is not a C
    // string. Pinned separately because a "helpful" implementation that always
    // terminates would still pass a looser length sweep on other sizes.
    let g = glibc_getdomainname();
    let dl = domain_len();
    if dl == 0 {
        eprintln!("empty domainname on this host; nothing to fit exactly — skipping");
        return;
    }
    let (rc_g, _, buf_g) = call(g, dl);
    let (rc_f, _, buf_f) = call(fl::getdomainname, dl);
    assert_eq!(rc_g, 0);
    assert_eq!(rc_f, rc_g);
    assert_eq!(
        buf_g[dl], FILL,
        "glibc must not write a terminator at len==strlen(domain)"
    );
    assert_eq!(
        buf_f[dl], buf_g[dl],
        "fl wrote a terminator glibc did not, at len==strlen(domain)"
    );
    assert_eq!(&buf_f[..dl], &buf_g[..dl], "copied bytes differ");
}

/// Run `f(NULL, len)` in a forked child and report its wait status.
fn null_call_in_child(f: GetDomainNameFn, len: usize) -> c_int {
    unsafe {
        let child = fork();
        assert!(child >= 0, "fork failed");
        if child == 0 {
            // Don't litter the tree with a core file when the child dies.
            let no_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::setrlimit(libc::RLIMIT_CORE, &no_core);
            let rc = f(std::ptr::null_mut(), len);
            _exit(if rc == 0 { 0 } else { 1 });
        }
        let mut status: c_int = 0;
        assert_eq!(waitpid(child, &mut status, 0), child, "waitpid failed");
        status
    }
}

#[test]
fn getdomainname_null_is_a_deliberate_hardening_divergence() {
    // fl's side: a guarded, reportable failure.
    unsafe { *__errno_location() = 0 };
    let rc = unsafe { fl::getdomainname(std::ptr::null_mut(), 64) };
    let err = unsafe { *__errno_location() };
    assert_eq!(rc, -1, "fl getdomainname(NULL, 64) must fail, not crash");
    assert_eq!(err, libc::EFAULT, "fl getdomainname(NULL, 64) errno");

    // glibc's side, measured rather than assumed: it has no null guard, so the
    // child dies on SIGSEGV. This is why the arms above are NOT compared on
    // NULL -- there is no glibc behaviour there to be conformant to.
    let status = null_call_in_child(glibc_getdomainname(), 64);
    let signalled = (status & 0x7f) != 0 && (status & 0x7f) != 0x7f;
    assert!(
        signalled && (status & 0x7f) == libc::SIGSEGV,
        "expected live glibc getdomainname(NULL, 64) to die on SIGSEGV \
         (that is what makes fl's EFAULT a hardening divergence rather than a \
         conformance bug); wait status was {status:#x}. If glibc has since grown \
         a null guard, this gate should become a parity assertion instead."
    );
}
