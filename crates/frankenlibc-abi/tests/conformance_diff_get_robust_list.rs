#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux `get_robust_list`.
//!
//! Null output pointers fail without changing the caller's robust-list
//! registration.

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

use std::ffi::{c_int, c_long, c_void};
use std::ptr;

#[cfg(target_arch = "x86_64")]
const SYS_GET_ROBUST_LIST: c_long = 274;
#[cfg(target_arch = "aarch64")]
const SYS_GET_ROBUST_LIST: c_long = 100;

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

fn host_get_robust_list(
    pid: c_int,
    head_ptr: *mut *mut c_void,
    len_ptr: *mut usize,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_GET_ROBUST_LIST, pid, head_ptr, len_ptr) };
    (rc as c_int, host_errno())
}

fn fl_get_robust_list(
    pid: c_int,
    head_ptr: *mut *mut c_void,
    len_ptr: *mut usize,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::get_robust_list(pid, head_ptr, len_ptr) };
    (rc, fl_errno())
}

#[test]
fn get_robust_list_null_outputs_match_host_syscall() {
    let host = host_get_robust_list(0, ptr::null_mut(), ptr::null_mut());
    let fl = fl_get_robust_list(0, ptr::null_mut(), ptr::null_mut());

    assert_eq!(
        fl, host,
        "get_robust_list(0,null,null): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl, (-1, libc::EFAULT));
}

#[test]
fn get_robust_list_each_null_output_matches_host_syscall() {
    let mut len = 0usize;
    let host = host_get_robust_list(0, ptr::null_mut(), &mut len);
    let fl = fl_get_robust_list(0, ptr::null_mut(), &mut len);
    assert_eq!(
        fl, host,
        "get_robust_list(0,null,&mut len): fl={fl:?} host={host:?}"
    );
    assert_eq!(host, (-1, libc::EFAULT));

    let mut head = ptr::null_mut();
    let host = host_get_robust_list(0, &mut head, ptr::null_mut());
    let fl = fl_get_robust_list(0, &mut head, ptr::null_mut());
    assert_eq!(
        fl, host,
        "get_robust_list(0,&mut head,null): fl={fl:?} host={host:?}"
    );
    assert_eq!(host, (-1, libc::EFAULT));
}

#[test]
fn get_robust_list_invalid_pid_matches_host_without_writing_outputs() {
    let sentinel_head = 1usize as *mut c_void;
    let sentinel_len = usize::MAX;

    let mut host_head = sentinel_head;
    let mut host_len = sentinel_len;
    let host = host_get_robust_list(-1, &mut host_head, &mut host_len);

    let mut fl_head = sentinel_head;
    let mut fl_len = sentinel_len;
    let fl = fl_get_robust_list(-1, &mut fl_head, &mut fl_len);

    assert_eq!(fl, host, "get_robust_list(-1): fl={fl:?} host={host:?}");
    assert_eq!(host, (-1, libc::ESRCH));
    assert_eq!((host_head, host_len), (sentinel_head, sentinel_len));
    assert_eq!((fl_head, fl_len), (host_head, host_len));
}
