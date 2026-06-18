#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux NUMA memory-policy raw syscall exports.
//!
//! These invalid argument paths fail before changing process policy or moving
//! pages, while still pinning the ABI return/errno contract to the host kernel.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long, c_ulong, c_void};
use std::ptr;

#[cfg(target_arch = "x86_64")]
const SYS_MBIND: c_long = 237;
#[cfg(target_arch = "aarch64")]
const SYS_MBIND: c_long = 235;

#[cfg(target_arch = "x86_64")]
const SYS_SET_MEMPOLICY: c_long = 238;
#[cfg(target_arch = "aarch64")]
const SYS_SET_MEMPOLICY: c_long = 237;

#[cfg(target_arch = "x86_64")]
const SYS_GET_MEMPOLICY: c_long = 239;
#[cfg(target_arch = "aarch64")]
const SYS_GET_MEMPOLICY: c_long = 236;

#[cfg(target_arch = "x86_64")]
const SYS_MIGRATE_PAGES: c_long = 256;
#[cfg(target_arch = "aarch64")]
const SYS_MIGRATE_PAGES: c_long = 238;

#[cfg(target_arch = "x86_64")]
const SYS_MOVE_PAGES: c_long = 279;
#[cfg(target_arch = "aarch64")]
const SYS_MOVE_PAGES: c_long = 239;

const SYS_SET_MEMPOLICY_HOME_NODE: c_long = 450;

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

fn host_set_mempolicy(
    mode: c_int,
    nodemask: *const c_ulong,
    maxnode: c_ulong,
) -> (c_long, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_SET_MEMPOLICY, mode, nodemask, maxnode) as c_long };
    (rc, host_errno())
}

fn fl_set_mempolicy(
    mode: c_int,
    nodemask: *const c_ulong,
    maxnode: c_ulong,
) -> (c_long, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::set_mempolicy(mode, nodemask, maxnode) };
    (rc, fl_errno())
}

fn host_get_mempolicy(
    mode: *mut c_int,
    nodemask: *mut c_ulong,
    maxnode: c_ulong,
    addr: *mut c_void,
    flags: c_ulong,
) -> (c_long, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(SYS_GET_MEMPOLICY, mode, nodemask, maxnode, addr, flags) as c_long };
    (rc, host_errno())
}

fn fl_get_mempolicy(
    mode: *mut c_int,
    nodemask: *mut c_ulong,
    maxnode: c_ulong,
    addr: *mut c_void,
    flags: c_ulong,
) -> (c_long, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::get_mempolicy(mode, nodemask, maxnode, addr, flags) };
    (rc, fl_errno())
}

fn host_mbind(
    addr: *mut c_void,
    len: c_ulong,
    mode: c_int,
    nodemask: *const c_ulong,
    maxnode: c_ulong,
    flags: c_int,
) -> (c_long, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(SYS_MBIND, addr, len, mode, nodemask, maxnode, flags) as c_long };
    (rc, host_errno())
}

fn fl_mbind(
    addr: *mut c_void,
    len: c_ulong,
    mode: c_int,
    nodemask: *const c_ulong,
    maxnode: c_ulong,
    flags: c_int,
) -> (c_long, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::mbind(addr, len, mode, nodemask, maxnode, flags as u32) };
    (rc, fl_errno())
}

fn host_migrate_pages(
    pid: c_int,
    maxnode: c_ulong,
    old_nodes: *const c_ulong,
    new_nodes: *const c_ulong,
) -> (c_long, c_int) {
    set_host_errno(0);
    let rc = unsafe {
        libc::syscall(SYS_MIGRATE_PAGES, pid, maxnode, old_nodes, new_nodes) as c_long
    };
    (rc, host_errno())
}

fn fl_migrate_pages(
    pid: c_int,
    maxnode: c_ulong,
    old_nodes: *const c_ulong,
    new_nodes: *const c_ulong,
) -> (c_long, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::migrate_pages(pid, maxnode, old_nodes, new_nodes) };
    (rc, fl_errno())
}

fn host_move_pages(
    pid: c_int,
    count: c_ulong,
    pages: *const *mut c_void,
    nodes: *const c_int,
    status: *mut c_int,
    flags: c_int,
) -> (c_long, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(SYS_MOVE_PAGES, pid, count, pages, nodes, status, flags) as c_long };
    (rc, host_errno())
}

fn fl_move_pages(
    pid: c_int,
    count: c_ulong,
    pages: *const *mut c_void,
    nodes: *const c_int,
    status: *mut c_int,
    flags: c_int,
) -> (c_long, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::move_pages(pid, count, pages, nodes, status, flags) };
    (rc, fl_errno())
}

fn host_set_mempolicy_home_node(
    start: c_ulong,
    len: c_ulong,
    home_node: c_ulong,
    flags: c_ulong,
) -> (c_long, c_int) {
    set_host_errno(0);
    let rc = unsafe {
        libc::syscall(SYS_SET_MEMPOLICY_HOME_NODE, start, len, home_node, flags) as c_long
    };
    (rc, host_errno())
}

fn fl_set_mempolicy_home_node(
    start: c_ulong,
    len: c_ulong,
    home_node: c_ulong,
    flags: c_ulong,
) -> (c_long, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::set_mempolicy_home_node(start, len, home_node, flags) };
    (rc, fl_errno())
}

#[test]
fn numa_mempolicy_invalid_failures_match_host_syscall() {
    let host = host_set_mempolicy(c_int::MAX, ptr::null(), 0);
    let fl = fl_set_mempolicy(c_int::MAX, ptr::null(), 0);
    assert_eq!(
        fl, host,
        "set_mempolicy(invalid mode): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_get_mempolicy(ptr::null_mut(), ptr::null_mut(), 0, ptr::null_mut(), 8);
    let fl = fl_get_mempolicy(ptr::null_mut(), ptr::null_mut(), 0, ptr::null_mut(), 8);
    assert_eq!(
        fl, host,
        "get_mempolicy(invalid flags): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_mbind(ptr::null_mut(), 0, c_int::MAX, ptr::null(), 0, 0);
    let fl = fl_mbind(ptr::null_mut(), 0, c_int::MAX, ptr::null(), 0, 0);
    assert_eq!(fl, host, "mbind(invalid mode): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);

    let host = host_migrate_pages(c_int::MAX, 0, ptr::null(), ptr::null());
    let fl = fl_migrate_pages(c_int::MAX, 0, ptr::null(), ptr::null());
    assert_eq!(
        fl, host,
        "migrate_pages(nonexistent pid): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_move_pages(0, 1, ptr::null(), ptr::null(), ptr::null_mut(), 0);
    let fl = fl_move_pages(0, 1, ptr::null(), ptr::null(), ptr::null_mut(), 0);
    assert_eq!(
        fl, host,
        "move_pages(null pages): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_set_mempolicy_home_node(0, 0, 0, 1);
    let fl = fl_set_mempolicy_home_node(0, 0, 0, 1);
    assert_eq!(
        fl, host,
        "set_mempolicy_home_node(invalid flags): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
