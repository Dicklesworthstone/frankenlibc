#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for deprecated Linux `remap_file_pages`.
//!
//! These invalid argument cases fail before any mapping change can occur.

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
const SYS_REMAP_FILE_PAGES: c_long = 216;
#[cfg(target_arch = "aarch64")]
const SYS_REMAP_FILE_PAGES: c_long = 234;

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

fn host_remap_file_pages(
    addr: *mut c_void,
    size: usize,
    prot: c_int,
    pgoff: usize,
    flags: c_int,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { host_syscall()(SYS_REMAP_FILE_PAGES, addr, size, prot, pgoff, flags) };
    (rc as c_int, host_errno())
}

fn fl_remap_file_pages(
    addr: *mut c_void,
    size: usize,
    prot: c_int,
    pgoff: usize,
    flags: c_int,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::remap_file_pages(addr, size, prot, pgoff, flags) };
    (rc, fl_errno())
}

#[test]
fn remap_file_pages_invalid_arguments_match_host_syscall() {
    let cases = [
        ("null zero size", ptr::null_mut(), 0, 0, 0, 0),
        ("null page size", ptr::null_mut(), 4096, 0, 0, 0),
        ("unaligned address", 1usize as *mut c_void, 4096, 0, 0, 0),
        ("invalid flags", ptr::null_mut(), 0, 0, 0, 1),
    ];

    for (name, addr, size, prot, pgoff, flags) in cases {
        let host = host_remap_file_pages(addr, size, prot, pgoff, flags);
        let fl = fl_remap_file_pages(addr, size, prot, pgoff, flags);

        assert_eq!(
            fl, host,
            "remap_file_pages({name}): fl={fl:?} host={host:?}"
        );
        assert_eq!(fl, (-1, libc::EINVAL), "remap_file_pages({name})");
    }
}
