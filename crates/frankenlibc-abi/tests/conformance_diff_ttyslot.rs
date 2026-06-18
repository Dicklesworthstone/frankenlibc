#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc ttyslot oracle

//! `ttyslot` parity vs host glibc (bd-7179e0).
//!
//! glibc's ttyslot (misc/ttyslot.c, 4.3BSD) returns the 1-based index of the
//! controlling terminal in the /etc/ttys database, or **0** when the terminal
//! is not found. Linux has no /etc/ttys, so glibc always returns 0. fl
//! previously returned -1, breaking the documented not-found contract.
//!
//! This gate compares fl and glibc in the SAME process/environment: the return
//! value (the stable, documented contract) and the residual errno (which fl now
//! matches by mirroring glibc's ttyname_r(0/1/2) probe — ENOTTY when there is no
//! controlling terminal, as under cargo test).

use std::ffi::c_int;

unsafe extern "C" {
    fn ttyslot() -> c_int; // host glibc
    fn __errno_location() -> *mut c_int;
}

fn glibc_errno() -> c_int {
    unsafe { *__errno_location() }
}
fn set_glibc_errno(v: c_int) {
    unsafe { *__errno_location() = v };
}
fn fl_errno() -> c_int {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
}
fn set_fl_errno(v: c_int) {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = v };
}

#[test]
fn ttyslot_matches_glibc() {
    set_glibc_errno(0);
    let grc = unsafe { ttyslot() };
    let gerr = glibc_errno();

    set_fl_errno(0);
    let frc = unsafe { frankenlibc_abi::glibc_internal_abi::ttyslot() };
    let ferr = fl_errno();

    // Documented contract: not found -> 0 (never -1) on a Linux host.
    assert_eq!(grc, 0, "glibc ttyslot should return 0 on Linux");
    assert_eq!(frc, grc, "fl ttyslot rc {frc} != glibc {grc}");
    // Residual errno matches glibc in this environment (no controlling tty).
    assert_eq!(
        ferr, gerr,
        "fl ttyslot errno {ferr} != glibc {gerr} (same process env)"
    );
}
