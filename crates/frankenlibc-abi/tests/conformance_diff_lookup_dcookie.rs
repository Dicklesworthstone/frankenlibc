#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux `lookup_dcookie`.
//!
//! Invalid cookies fail without depending on audit cookie availability or
//! mutating filesystem state.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_addr;

/// `long syscall(long number, ...)`, matching glibc's declaration.
type SyscallFn = unsafe extern "C" fn(c_long, ...) -> c_long;

/// `int *__errno_location(void)`.
type ErrnoLocationFn = unsafe extern "C" fn() -> *mut c_int;

/// Host glibc's raw-syscall and errno accessors, resolved out of libc.so.6 and
/// proven not to be fl's own exports.
///
/// This gate's host arm was two LINK-TIME references: the raw syscall entry and
/// the errno accessor. fl defines both under
/// `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`. Confirmed on the
/// built artifact rather than assumed: `nm -D --defined-only` on a release
/// `libfrankenlibc_abi.so` lists `T __errno_location` and `T syscall` and lists
/// neither as undefined, so in a RELEASE test binary the linker prefers fl's
/// definitions and this "host" arm would call fl's own syscall wrapper and read
/// fl's errno slot — the gate comparing fl against itself and passing
/// unconditionally. Debug keeps the symbols mangled, which is why it has been
/// honest in the profile CI runs.
///
/// A collapsed SYSCALL arm cannot be caught by running the gate: unlike the
/// errno collapse, which made three gates fail `--release` with the host arm
/// reading errno 0 (bd-g1sjty), fl-vs-fl simply passes. `host_addr` aborts when
/// the resolved address equals fl's own definition, which is the only thing that
/// distinguishes it. See bd-0q7ba9.
fn host_syscall() -> SyscallFn {
    // SAFETY: resolved address is glibc's raw syscall entry, `long(long, ...)`.
    unsafe {
        let addr = host_addr(c"syscall", fl::syscall as SyscallFn as *const ());
        std::mem::transmute::<*mut std::ffi::c_void, SyscallFn>(addr)
    }
}

fn host_errno_ptr() -> *mut c_int {
    // SAFETY: resolved address is glibc's errno accessor, `int *(void)`.
    unsafe {
        let addr = host_addr(
            c"__errno_location",
            fl_errno_location as ErrnoLocationFn as *const (),
        );
        std::mem::transmute::<*mut std::ffi::c_void, ErrnoLocationFn>(addr)()
    }
}

use std::ffi::{c_char, c_int, c_long};
use std::ptr;

#[cfg(target_arch = "x86_64")]
const SYS_LOOKUP_DCOOKIE: c_long = 212;
#[cfg(target_arch = "aarch64")]
const SYS_LOOKUP_DCOOKIE: c_long = 18;

fn host_errno() -> c_int {
    unsafe { *host_errno_ptr() }
}

fn set_host_errno(value: c_int) {
    unsafe { *host_errno_ptr() = value };
}

fn fl_errno() -> c_int {
    unsafe { *fl_errno_location() }
}

fn set_fl_errno(value: c_int) {
    unsafe { *fl_errno_location() = value };
}

fn host_lookup_dcookie(cookie: u64, buffer: *mut c_char, len: usize) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_LOOKUP_DCOOKIE, cookie, buffer, len) };
    (rc as c_int, host_errno())
}

fn fl_lookup_dcookie(cookie: u64, buffer: *mut c_char, len: usize) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::lookup_dcookie(cookie, buffer, len) };
    (rc, fl_errno())
}

#[test]
fn lookup_dcookie_invalid_cookie_matches_host_syscall() {
    let null_host = host_lookup_dcookie(0, ptr::null_mut(), 0);
    let null_fl = fl_lookup_dcookie(0, ptr::null_mut(), 0);

    assert_eq!(
        null_fl, null_host,
        "lookup_dcookie(0,null,0): fl={null_fl:?} host={null_host:?}"
    );
    assert_eq!(null_fl.0, -1);

    let mut buffer = [0u8; 64];
    let host = host_lookup_dcookie(0, buffer.as_mut_ptr() as *mut c_char, buffer.len());
    let fl = fl_lookup_dcookie(0, buffer.as_mut_ptr() as *mut c_char, buffer.len());

    assert_eq!(
        fl, host,
        "lookup_dcookie(0,buffer,len): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
