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
use std::ffi::{c_int, c_long, c_uint, c_void};
use std::ptr;

const SYS_MEMFD_SECRET: c_long = 447;
const SYS_MAP_SHADOW_STACK: c_long = 453;
const SYS_MSEAL: c_long = 462;

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

fn host_memfd_secret(flags: c_uint) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_MEMFD_SECRET, flags) as c_long };
    (rc as c_int, host_errno())
}

fn fl_memfd_secret(flags: c_uint) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::memfd_secret(flags) };
    (rc, fl_errno())
}

fn host_map_shadow_stack(addr: c_long, size: c_long, flags: c_uint) -> (c_long, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_MAP_SHADOW_STACK, addr, size, flags) as c_long };
    (rc, host_errno())
}

fn fl_map_shadow_stack(addr: c_long, size: c_long, flags: c_uint) -> (c_long, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::map_shadow_stack(addr as u64, size as u64, flags) };
    (rc, fl_errno())
}

fn host_mseal(addr: *mut c_void, len: usize, flags: c_uint) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_MSEAL, addr, len, flags) as c_long };
    (rc as c_int, host_errno())
}

fn fl_mseal(addr: *mut c_void, len: usize, flags: c_uint) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::mseal(addr, len, flags) };
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
}
