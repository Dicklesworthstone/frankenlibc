#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux native AIO raw syscall exports.
//!
//! These invalid-context paths fail before creating an AIO context or issuing
//! I/O, so the host syscall oracle is deterministic and non-mutating.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long, c_ulong, c_void};
use std::ptr;

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
    let rc = unsafe { libc::syscall(SYS_IO_DESTROY, ctx_id) as c_long };
    (rc as c_int, host_errno())
}

fn fl_io_destroy(ctx_id: c_ulong) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::io_destroy(ctx_id) };
    (rc, fl_errno())
}

fn host_io_submit(ctx_id: c_ulong, nr: c_long, iocbpp: *mut *mut c_void) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_IO_SUBMIT, ctx_id, nr, iocbpp) as c_long };
    (rc as c_int, host_errno())
}

fn fl_io_submit(ctx_id: c_ulong, nr: c_long, iocbpp: *mut *mut c_void) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::io_submit(ctx_id, nr, iocbpp) };
    (rc, fl_errno())
}

fn host_io_cancel(ctx_id: c_ulong, iocb: *mut c_void, result: *mut c_void) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_IO_CANCEL, ctx_id, iocb, result) as c_long };
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
        unsafe { libc::syscall(SYS_IO_GETEVENTS, ctx_id, min_nr, nr, events, timeout) as c_long };
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
