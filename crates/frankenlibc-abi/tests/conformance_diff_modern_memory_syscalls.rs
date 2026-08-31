#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for newer Linux memory syscall exports.
//!
//! Invalid flag values fail before sealing memory, creating secret memfds, or
//! mapping a shadow stack. On older kernels this also pins ENOSYS parity.

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

const SYS_MEMFD_SECRET: c_long = 447;
const SYS_MAP_SHADOW_STACK: c_long = 453;
const SYS_MSEAL: c_long = 462;
const SYS_PROCESS_MADVISE: c_long = libc::SYS_process_madvise as c_long;

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

fn host_memfd_secret(flags: c_uint) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_MEMFD_SECRET, flags) };
    (rc as c_int, host_errno())
}

fn fl_memfd_secret(flags: c_uint) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::memfd_secret(flags) };
    (rc, fl_errno())
}

fn host_map_shadow_stack(addr: c_long, size: c_long, flags: c_uint) -> (c_long, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_MAP_SHADOW_STACK, addr, size, flags) };
    (rc, host_errno())
}

fn fl_map_shadow_stack(addr: c_long, size: c_long, flags: c_uint) -> (c_long, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::map_shadow_stack(addr as u64, size as u64, flags) };
    (rc, fl_errno())
}

fn host_mseal(addr: *mut c_void, len: usize, flags: c_uint) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_MSEAL, addr, len, flags) };
    (rc as c_int, host_errno())
}

fn fl_mseal(addr: *mut c_void, len: usize, flags: c_uint) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::mseal(addr, len, flags) };
    (rc, fl_errno())
}

fn host_process_madvise(
    pidfd: c_int,
    iovec: *const libc::iovec,
    vlen: usize,
    advice: c_int,
    flags: c_uint,
) -> (isize, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_PROCESS_MADVISE, pidfd, iovec, vlen, advice, flags) };
    (rc as isize, host_errno())
}

fn fl_process_madvise(
    pidfd: c_int,
    iovec: *const libc::iovec,
    vlen: usize,
    advice: c_int,
    flags: c_uint,
) -> (isize, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::process_madvise(pidfd, iovec, vlen, advice, flags) };
    (rc, fl_errno())
}

#[test]
fn modern_memory_invalid_flags_match_host_syscall() {
    let host = host_memfd_secret(c_uint::MAX);
    let fl = fl_memfd_secret(c_uint::MAX);
    assert_eq!(
        fl, host,
        "memfd_secret(invalid flags): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_map_shadow_stack(0, 0, c_uint::MAX);
    let fl = fl_map_shadow_stack(0, 0, c_uint::MAX);
    assert_eq!(
        fl, host,
        "map_shadow_stack(invalid flags): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_mseal(ptr::null_mut(), 0, c_uint::MAX);
    let fl = fl_mseal(ptr::null_mut(), 0, c_uint::MAX);
    assert_eq!(fl, host, "mseal(invalid flags): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);

    // A real iovec makes this distinct from a null-payload failure.  The
    // unsupported flags must reject before the invalid pidfd can resolve to a
    // process and before the kernel can apply the requested memory advice.
    let iovec = libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    };
    let host = host_process_madvise(-1, &iovec, 1, libc::MADV_NORMAL, c_uint::MAX);
    let fl = fl_process_madvise(-1, &iovec, 1, libc::MADV_NORMAL, c_uint::MAX);
    assert_eq!(
        fl, host,
        "process_madvise(invalid flags): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl, (-1, libc::EINVAL));
}
