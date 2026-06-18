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
use std::ffi::{c_int, c_long, c_void};
use std::ptr;

#[cfg(target_arch = "x86_64")]
const SYS_REMAP_FILE_PAGES: c_long = 216;
#[cfg(target_arch = "aarch64")]
const SYS_REMAP_FILE_PAGES: c_long = 234;

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

fn host_remap_file_pages(
    addr: *mut c_void,
    size: usize,
    prot: c_int,
    pgoff: usize,
    flags: c_int,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(SYS_REMAP_FILE_PAGES, addr, size, prot, pgoff, flags) as c_long };
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
