#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc isastream oracle
//! Differential gate for `isastream` (bd-u0a562).
//!
//! Linux has no STREAMS, so the answer is always "no" — but glibc still
//! VALIDATES the descriptor and fails on a bad one, which is the part fl once
//! got wrong (it ignored `fd` and reported success for anything, including -1).
//! This pins both halves of that contract against the live host.
//!
//! The symbol is resolved with `dlvsym`, not `dlsym`: `isastream` is COMPAT-ONLY
//! in modern glibc, so a plain `dlsym` or a link-time declaration finds nothing
//! and the target goes silent instead of red (bd-86hcwh).

use frankenlibc_abi::{errno_abi, glibc_internal_abi as fl};
use std::ffi::{c_int, c_void};

const GLIBC_2_2_5: &std::ffi::CStr = c"GLIBC_2.2.5";
type IsastreamFn = unsafe extern "C" fn(c_int) -> c_int;

union IsastreamSymbol {
    raw: *mut c_void,
    function: IsastreamFn,
}

/// Resolve `isastream@GLIBC_2.2.5` from the host libc.
fn host_isastream() -> IsastreamFn {
    // SAFETY: libc.so.6 is the process host libc; flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    // SAFETY: handle came from dlopen; both C strings are NUL-terminated constants.
    let raw = unsafe { libc::dlvsym(handle, c"isastream".as_ptr(), GLIBC_2_2_5.as_ptr()) };
    assert!(
        !raw.is_null(),
        "dlvsym isastream@GLIBC_2.2.5 — compat-only symbols need dlvsym, not dlsym"
    );
    // SAFETY: the resolved symbol has glibc's documented isastream signature.
    unsafe { IsastreamSymbol { raw }.function }
}

/// (return value, errno) from one implementation, with errno seeded so a
/// spurious write is visible rather than hidden behind a zero.
const SENTINEL: c_int = 0x5eed;

fn host_call(f: IsastreamFn, fd: c_int) -> (c_int, c_int) {
    // SAFETY: errno location is always valid; isastream takes an int.
    unsafe {
        *libc::__errno_location() = SENTINEL;
        let rc = f(fd);
        (rc, *libc::__errno_location())
    }
}

fn fl_call(fd: c_int) -> (c_int, c_int) {
    // SAFETY: as above, against fl's implementation and fl's errno slot.
    unsafe {
        errno_abi::set_abi_errno(SENTINEL);
        let rc = fl::isastream(fd);
        (rc, *errno_abi::__errno_location())
    }
}

#[test]
fn isastream_matches_glibc_on_valid_and_invalid_descriptors() {
    let host = host_isastream();

    // Valid descriptors: Linux has no STREAMS so the answer is 0, and a
    // SUCCESSFUL call must not disturb errno — the sentinel has to survive.
    let devnull = std::ffi::CString::new("/dev/null").expect("no NUL");
    // SAFETY: opening /dev/null read-only.
    let opened = unsafe { libc::open(devnull.as_ptr(), libc::O_RDONLY) };
    assert!(opened >= 0, "opening /dev/null should succeed");

    for fd in [0, 1, opened] {
        let h = host_call(host, fd);
        let f = fl_call(fd);
        assert_eq!(
            h.0, 0,
            "oracle: Linux has no STREAMS, so isastream({fd}) should be 0 (got {h:?})"
        );
        assert_eq!(
            h.1, SENTINEL,
            "oracle: a successful isastream({fd}) should leave errno untouched (got {h:?})"
        );
        assert_eq!(f, h, "isastream({fd}) diverged: fl={f:?} glibc={h:?}");
    }

    // Invalid descriptors: glibc validates the fd and fails. This is the half fl
    // previously got wrong by reporting success for anything, so the errno is
    // compared too, not just the -1.
    for fd in [-1, 2048] {
        let h = host_call(host, fd);
        let f = fl_call(fd);
        assert_eq!(
            h.0, -1,
            "oracle: isastream({fd}) should reject a bad descriptor (got {h:?})"
        );
        assert_eq!(
            h.1,
            libc::EBADF,
            "oracle: a rejected descriptor should set EBADF (fd {fd}, got {h:?})"
        );
        assert_eq!(f, h, "isastream({fd}) diverged: fl={f:?} glibc={h:?}");
    }

    // SAFETY: opened is owned here and still valid.
    unsafe { libc::close(opened) };
}
