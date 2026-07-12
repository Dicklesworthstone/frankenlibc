#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for privileged/control syscall ABI exports.
//!
//! These cases all fail before changing kernel state, but they still pin the
//! host kernel's exact errno precedence.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use std::ptr;

const SYS_FINIT_MODULE: c_long = libc::SYS_finit_module as c_long;
const SYS_QUOTACTL_FD: c_long = libc::SYS_quotactl_fd as c_long;
const SYS_BPF: c_long = libc::SYS_bpf as c_long;
const SYS_KEXEC_LOAD: c_long = libc::SYS_kexec_load as c_long;
const SYS_KEXEC_FILE_LOAD: c_long = libc::SYS_kexec_file_load as c_long;

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

fn host_finit_module(fd: c_int, param_values: *const c_char, flags: c_int) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_FINIT_MODULE, fd, param_values, flags) as c_long };
    (rc as c_int, host_errno())
}

fn fl_finit_module(fd: c_int, param_values: *const c_char, flags: c_int) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::finit_module(fd, param_values, flags) };
    (rc, fl_errno())
}

fn host_quotactl_fd(fd: c_uint, cmd: c_int, id: c_uint, addr: *mut c_void) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_QUOTACTL_FD, fd, cmd, id, addr) as c_long };
    (rc as c_int, host_errno())
}

fn fl_quotactl_fd(fd: c_uint, cmd: c_int, id: c_uint, addr: *mut c_void) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::quotactl_fd(fd, cmd, id, addr) };
    (rc, fl_errno())
}

fn host_bpf(cmd: c_int, attr: *mut c_void, size: c_uint) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_BPF, cmd, attr, size) as c_long };
    (rc as c_int, host_errno())
}

fn fl_bpf(cmd: c_int, attr: *mut c_void, size: c_uint) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::bpf(cmd, attr, size) };
    (rc, fl_errno())
}

fn host_kexec_load(
    entry: c_ulong,
    nr_segments: c_ulong,
    segments: *const c_void,
    flags: c_ulong,
) -> (c_long, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(SYS_KEXEC_LOAD, entry, nr_segments, segments, flags) as c_long };
    (rc, host_errno())
}

fn fl_kexec_load(
    entry: c_ulong,
    nr_segments: c_ulong,
    segments: *const c_void,
    flags: c_ulong,
) -> (c_long, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::kexec_load(entry, nr_segments, segments, flags) };
    (rc, fl_errno())
}

fn host_kexec_file_load(
    kernel_fd: c_int,
    initrd_fd: c_int,
    cmdline_len: c_ulong,
    cmdline: *const c_char,
    flags: c_ulong,
) -> (c_long, c_int) {
    set_host_errno(0);
    let rc = unsafe {
        libc::syscall(
            SYS_KEXEC_FILE_LOAD,
            kernel_fd,
            initrd_fd,
            cmdline_len,
            cmdline,
            flags,
        ) as c_long
    };
    (rc, host_errno())
}

fn fl_kexec_file_load(
    kernel_fd: c_int,
    initrd_fd: c_int,
    cmdline_len: c_ulong,
    cmdline: *const c_char,
    flags: c_ulong,
) -> (c_long, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::kexec_file_load(kernel_fd, initrd_fd, cmdline_len, cmdline, flags) };
    (rc, fl_errno())
}

#[test]
fn privileged_control_invalid_failures_match_host_syscall() {
    let host = host_finit_module(-1, ptr::null(), 0);
    let fl = fl_finit_module(-1, ptr::null(), 0);
    assert_eq!(
        fl, host,
        "finit_module(invalid fd): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_quotactl_fd(c_uint::MAX, 0, 0, ptr::null_mut());
    let fl = fl_quotactl_fd(c_uint::MAX, 0, 0, ptr::null_mut());
    assert_eq!(fl, host, "quotactl_fd(invalid fd): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);

    let host = host_bpf(1, ptr::null_mut(), 0);
    let fl = fl_bpf(1, ptr::null_mut(), 0);
    assert_eq!(fl, host, "bpf(size 0 null attr): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);

    let host = host_bpf(0, ptr::null_mut(), 16);
    let fl = fl_bpf(0, ptr::null_mut(), 16);
    assert_eq!(
        fl, host,
        "bpf(null attr positive size): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_kexec_load(0, 1, ptr::null(), 0);
    let fl = fl_kexec_load(0, 1, ptr::null(), 0);
    assert_eq!(
        fl, host,
        "kexec_load(null segments positive count): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_kexec_file_load(-1, -1, 0, ptr::null(), 0);
    let fl = fl_kexec_file_load(-1, -1, 0, ptr::null(), 0);
    assert_eq!(
        fl, host,
        "kexec_file_load(invalid fds): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
