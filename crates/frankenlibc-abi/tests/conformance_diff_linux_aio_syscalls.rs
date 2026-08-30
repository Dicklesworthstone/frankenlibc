#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux native AIO raw syscall exports.
//!
//! These invalid-context paths fail before creating an AIO context or issuing
//! I/O, so the host syscall oracle is deterministic and non-mutating.
//!
//! ## The oracle is resolved by `dlsym`, and that is load-bearing here
//!
//! The obvious spelling of the host arm is `libc::syscall(...)`, which is what
//! this gate used. That is a LINK-TIME declaration, and fl exports its own
//! `syscall` — `unistd_abi::syscall`, carrying
//! `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`. Under `cargo test`
//! the build is debug, the attribute is off, the symbol stays mangled and the
//! reference really does reach glibc, which is why this gate has been honest so
//! far. Build the same tests with `--release` and fl's `syscall` becomes a
//! `no_mangle` definition inside the test binary: the linker prefers it, both
//! arms become fl, and every assertion below passes unconditionally while
//! proving nothing.
//!
//! That is the bd-v0388t failure mode, already confirmed twice in this suite
//! (`fma`, `catopen`), and `common/dlsym_oracle.rs` exists to prevent it:
//! [`host_addr`] resolves the symbol out of `libc.so.6` itself and ABORTS if the
//! address it gets back equals fl's own definition. Using it makes the arm
//! correct in every build profile instead of correct by accident in one.

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

use dlsym_oracle::host_addr;
use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long, c_ulong, c_void};
use std::ptr;

/// `long syscall(long number, ...)`, matching glibc's declaration.
type SyscallFn = unsafe extern "C" fn(c_long, ...) -> c_long;

/// Host glibc's `syscall`, proven not to be fl's own export.
fn host_syscall() -> SyscallFn {
    // SAFETY: the resolved address is glibc's `syscall`, whose C declaration is
    // `long syscall(long, ...)`; `fl::syscall` is handed over so a collapsed
    // oracle aborts instead of comparing fl against itself.
    unsafe {
        let addr = host_addr(c"syscall", fl::syscall as SyscallFn as *const ());
        std::mem::transmute::<*mut c_void, SyscallFn>(addr)
    }
}

#[cfg(target_arch = "x86_64")]
const SYS_IO_DESTROY: c_long = 207;
#[cfg(target_arch = "aarch64")]
const SYS_IO_DESTROY: c_long = 1;

#[cfg(target_arch = "x86_64")]
const SYS_IO_SUBMIT: c_long = 209;
#[cfg(target_arch = "aarch64")]
const SYS_IO_SUBMIT: c_long = 2;

#[cfg(target_arch = "x86_64")]
const SYS_IO_CANCEL: c_long = 210;
#[cfg(target_arch = "aarch64")]
const SYS_IO_CANCEL: c_long = 3;

#[cfg(target_arch = "x86_64")]
const SYS_IO_GETEVENTS: c_long = 208;
#[cfg(target_arch = "aarch64")]
const SYS_IO_GETEVENTS: c_long = 4;

fn host_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn set_host_errno(value: c_int) {
    unsafe { *libc::__errno_location() = value };
}

fn fl_errno() -> c_int {
    unsafe { *fl_errno_location() }
}

fn set_fl_errno(value: c_int) {
    unsafe { *fl_errno_location() = value };
}

fn host_io_destroy(ctx_id: c_ulong) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_IO_DESTROY, ctx_id) };
    (rc as c_int, host_errno())
}

fn fl_io_destroy(ctx_id: c_ulong) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::io_destroy(ctx_id) };
    (rc, fl_errno())
}

fn host_io_submit(ctx_id: c_ulong, nr: c_long, iocbpp: *mut *mut c_void) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_IO_SUBMIT, ctx_id, nr, iocbpp) };
    (rc as c_int, host_errno())
}

fn fl_io_submit(ctx_id: c_ulong, nr: c_long, iocbpp: *mut *mut c_void) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::io_submit(ctx_id, nr, iocbpp) };
    (rc, fl_errno())
}

fn host_io_cancel(ctx_id: c_ulong, iocb: *mut c_void, result: *mut c_void) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_IO_CANCEL, ctx_id, iocb, result) };
    (rc as c_int, host_errno())
}

fn fl_io_cancel(ctx_id: c_ulong, iocb: *mut c_void, result: *mut c_void) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::io_cancel(ctx_id, iocb, result) };
    (rc, fl_errno())
}

fn host_io_getevents(
    ctx_id: c_ulong,
    min_nr: c_long,
    nr: c_long,
    events: *mut c_void,
    timeout: *mut libc::timespec,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { host_syscall()(SYS_IO_GETEVENTS, ctx_id, min_nr, nr, events, timeout) };
    (rc as c_int, host_errno())
}

fn fl_io_getevents(
    ctx_id: c_ulong,
    min_nr: c_long,
    nr: c_long,
    events: *mut c_void,
    timeout: *mut libc::timespec,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::io_getevents(ctx_id, min_nr, nr, events, timeout) };
    (rc, fl_errno())
}

#[test]
fn linux_aio_invalid_context_failures_match_host_syscall() {
    let host = host_io_destroy(0);
    let fl = fl_io_destroy(0);
    assert_eq!(fl, host, "io_destroy(0): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);

    let host = host_io_submit(0, 1, ptr::null_mut());
    let fl = fl_io_submit(0, 1, ptr::null_mut());
    assert_eq!(
        fl, host,
        "io_submit(invalid context, null iocb): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_io_cancel(0, ptr::null_mut(), ptr::null_mut());
    let fl = fl_io_cancel(0, ptr::null_mut(), ptr::null_mut());
    assert_eq!(
        fl, host,
        "io_cancel(invalid context, null result): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_io_getevents(0, 1, 1, ptr::null_mut(), ptr::null_mut());
    let fl = fl_io_getevents(0, 1, 1, ptr::null_mut(), ptr::null_mut());
    assert_eq!(
        fl, host,
        "io_getevents(invalid context, null events): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
