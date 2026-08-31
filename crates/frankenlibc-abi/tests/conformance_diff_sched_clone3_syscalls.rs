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
/// This gate's host arm was LINK-TIME. fl defines both the raw syscall entry and
/// the errno accessor under
/// `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`. Confirmed on the
/// built artifact rather than argued from source: `nm -D --defined-only` on a
/// release `libfrankenlibc_abi.so` lists `T __errno_location` and `T syscall`
/// and lists neither as undefined, so in a RELEASE test binary the linker
/// prefers fl's definitions and this "host" arm would call fl's own syscall
/// wrapper and read fl's errno slot — the gate comparing fl against itself and
/// passing unconditionally. Debug keeps the symbols mangled, which is why it has
/// been honest in the profile CI runs.
///
/// A collapsed SYSCALL arm cannot be caught by running the gate: unlike the
/// errno collapse, which made three gates fail `--release` with the host arm
/// reading errno 0 (bd-g1sjty), fl-vs-fl simply passes. `host_addr` aborts when
/// the resolved address equals fl's own definition, which is the only thing that
/// distinguishes the two. See bd-0q7ba9.
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

fn host_clone3(args: *mut c_void, size: usize) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_CLONE3, args, size) };
    (rc as c_int, host_errno())
}

fn fl_clone3(args: *mut c_void, size: usize) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::clone3(args, size) };
    (rc, fl_errno())
}

fn host_sched_setattr(pid: libc::pid_t, attr: *mut c_void, flags: c_uint) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_SCHED_SETATTR, pid, attr, flags) };
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
    let rc = unsafe { host_syscall()(SYS_SCHED_GETATTR, pid, attr, size, flags) };
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
