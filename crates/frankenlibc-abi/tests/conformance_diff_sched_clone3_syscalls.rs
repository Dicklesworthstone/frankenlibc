#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for scheduler extension and `clone3` syscall exports.
//!
//! The `clone3` case uses a non-null zero-size argument block, so the kernel
//! rejects it before creating a child.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long, c_uint, c_void};
use std::ptr;

const SYS_CLONE3: c_long = libc::SYS_clone3 as c_long;
const SYS_SCHED_SETATTR: c_long = libc::SYS_sched_setattr as c_long;
const SYS_SCHED_GETATTR: c_long = libc::SYS_sched_getattr as c_long;
const SCHED_ATTR_SIZE: usize = 56;
const UNSUPPORTED_SCHED_SETATTR_FLAG: c_uint = 1 << 31;

#[repr(C)]
struct SchedAttrInput {
    size: u32,
    rest: [u8; SCHED_ATTR_SIZE - std::mem::size_of::<u32>()],
}

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

fn host_clone3(args: *mut c_void, size: usize) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_CLONE3, args, size) as c_long };
    (rc as c_int, host_errno())
}

fn fl_clone3(args: *mut c_void, size: usize) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::clone3(args, size) };
    (rc, fl_errno())
}

fn host_sched_setattr(pid: libc::pid_t, attr: *mut c_void, flags: c_uint) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_SCHED_SETATTR, pid, attr, flags) as c_long };
    (rc as c_int, host_errno())
}

fn fl_sched_setattr(pid: libc::pid_t, attr: *mut c_void, flags: c_uint) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::sched_setattr(pid, attr, flags) };
    (rc, fl_errno())
}

fn host_sched_getattr(
    pid: libc::pid_t,
    attr: *mut c_void,
    size: c_uint,
    flags: c_uint,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_SCHED_GETATTR, pid, attr, size, flags) as c_long };
    (rc as c_int, host_errno())
}

fn fl_sched_getattr(
    pid: libc::pid_t,
    attr: *mut c_void,
    size: c_uint,
    flags: c_uint,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::sched_getattr(pid, attr, size, flags) };
    (rc, fl_errno())
}

#[test]
fn sched_and_clone3_invalid_failures_match_host_syscall() {
    let mut clone_args = [0_u8; 8];
    let args = clone_args.as_mut_ptr().cast::<c_void>();
    let host = host_clone3(args, 0);
    let fl = fl_clone3(args, 0);
    assert_eq!(
        fl, host,
        "clone3(non-null, size 0): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_sched_setattr(0, ptr::null_mut(), 0);
    let fl = fl_sched_setattr(0, ptr::null_mut(), 0);
    assert_eq!(
        fl, host,
        "sched_setattr(NULL attr): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    // The attr block is structurally valid, but the syscall flags contain a
    // bit Linux does not define.  This must be rejected before scheduler
    // state can change; comparing it separately from the NULL case prevents
    // an ABI wrapper from collapsing every failure to EFAULT.
    let mut attr = SchedAttrInput {
        size: SCHED_ATTR_SIZE as u32,
        rest: [0; SCHED_ATTR_SIZE - std::mem::size_of::<u32>()],
    };
    let attr = ptr::addr_of_mut!(attr).cast::<c_void>();
    let host = host_sched_setattr(0, attr, UNSUPPORTED_SCHED_SETATTR_FLAG);
    let fl = fl_sched_setattr(0, attr, UNSUPPORTED_SCHED_SETATTR_FLAG);
    assert_eq!(
        fl, host,
        "sched_setattr(unsupported flags): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
    assert_eq!(fl.1, libc::EINVAL);

    let host = host_sched_getattr(0, ptr::null_mut(), 0, 0);
    let fl = fl_sched_getattr(0, ptr::null_mut(), 0, 0);
    assert_eq!(
        fl, host,
        "sched_getattr(NULL attr): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
