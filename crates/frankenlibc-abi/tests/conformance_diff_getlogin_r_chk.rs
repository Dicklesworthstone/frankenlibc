#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc oracle via dlsym

//! Does `__getlogin_r_chk(NULL, 0, 0)` report what glibc reports?
//!
//! A conformance fixture expects `ERANGE` (34) here, FrankenLibC returns
//! `EINVAL` (22), and the fixture compares against a RECORDED expectation rather
//! than a live glibc call — which is exactly the shape that lets an expectation
//! go stale without anyone noticing (bd-hdm1jg, split out of bd-u2daxd).
//!
//! Reading the code settles what fl does and cannot settle what glibc does:
//! `unistd_abi::getlogin_r` returns `EINVAL` from its first branch for a null
//! buffer or zero size, both `ERANGE` paths sit below it, and the membrane's
//! only early exit is `EPERM`. So 22 is the only value fl can produce for these
//! arguments. This asks the other side of the comparison directly instead of
//! trusting a stored number.
//!
//! Deliberately a live oracle, not another recorded constant: replacing one
//! stale expectation with another written from memory would repeat the defect.

use std::ffi::{c_char, c_int};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type GetloginRChk = unsafe extern "C" fn(*mut c_char, usize, usize) -> c_int;

#[test]
fn getlogin_r_chk_null_zero_matches_glibc() {
    // fl's own definition is handed to the oracle so it refuses to resolve back
    // to fl and compare it against itself.
    let host: GetloginRChk = unsafe {
        dlsym_oracle::host_fn(
            c"__getlogin_r_chk",
            frankenlibc_abi::fortify_abi::__getlogin_r_chk as *const (),
        )
    };

    // SAFETY: the C prototype is `int __getlogin_r_chk(char *, size_t, size_t)`,
    // and a null buffer with zero sizes is the documented degenerate query.
    let host_rc = unsafe { host(std::ptr::null_mut(), 0, 0) };
    // SAFETY: same call, FrankenLibC's implementation.
    let fl_rc = unsafe { frankenlibc_abi::fortify_abi::__getlogin_r_chk(std::ptr::null_mut(), 0, 0) };

    println!(
        "GETLOGIN_R_CHK_NULL_ZERO host_glibc={host_rc} fl={fl_rc} \
         (EINVAL={} ERANGE={})",
        libc::EINVAL,
        libc::ERANGE
    );

    assert_eq!(
        fl_rc, host_rc,
        "__getlogin_r_chk(NULL, 0, 0): fl returned {fl_rc}, host glibc returned \
         {host_rc}. If this fires, fl's getlogin_r takes its `buf.is_null() || \
         bufsize == 0 -> EINVAL` branch where glibc reports something else; the \
         conformance fixture that expects 34 is then right about glibc and fl is \
         the side to change (bd-hdm1jg)."
    );
}
