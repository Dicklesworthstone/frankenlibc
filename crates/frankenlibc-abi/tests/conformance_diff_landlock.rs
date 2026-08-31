#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux Landlock syscalls.
//!
//! These cases do not install a Landlock policy. They cover the version-query
//! path plus invalid/error paths that fail before adding rules or restricting
//! the current process.

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

const SYS_LANDLOCK_CREATE_RULESET: c_long = 444;
const SYS_LANDLOCK_ADD_RULE: c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: c_long = 446;
const LANDLOCK_CREATE_RULESET_VERSION: c_uint = 1;

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

fn host_create_ruleset(attr: *const c_void, size: usize, flags: c_uint) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_LANDLOCK_CREATE_RULESET, attr, size, flags) };
    (rc as c_int, host_errno())
}

fn fl_create_ruleset(attr: *const c_void, size: usize, flags: c_uint) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::landlock_create_ruleset(attr, size, flags) };
    (rc, fl_errno())
}

fn host_add_rule(ruleset_fd: c_int, rule_type: c_int, flags: c_uint) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe {
        host_syscall()(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            rule_type,
            ptr::null::<c_void>(),
            flags,
        )
    };
    (rc as c_int, host_errno())
}

fn fl_add_rule(ruleset_fd: c_int, rule_type: c_int, flags: c_uint) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::landlock_add_rule(ruleset_fd, rule_type, ptr::null(), flags) };
    (rc, fl_errno())
}

fn host_restrict_self(ruleset_fd: c_int, flags: c_uint) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, flags) };
    (rc as c_int, host_errno())
}

fn fl_restrict_self(ruleset_fd: c_int, flags: c_uint) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::landlock_restrict_self(ruleset_fd, flags) };
    (rc, fl_errno())
}

#[test]
fn landlock_create_ruleset_version_query_matches_host_syscall() {
    let host = host_create_ruleset(ptr::null(), 0, LANDLOCK_CREATE_RULESET_VERSION);
    let fl = fl_create_ruleset(ptr::null(), 0, LANDLOCK_CREATE_RULESET_VERSION);

    assert_eq!(
        fl, host,
        "landlock_create_ruleset(version): fl={fl:?} host={host:?}"
    );
    if host.0 >= 0 {
        assert_eq!(host.1, 0);
        assert!(host.0 >= 1, "Landlock ABI version should be positive");
    }
}

#[test]
fn landlock_invalid_create_flags_match_host_syscall() {
    let host = host_create_ruleset(ptr::null(), 0, c_uint::MAX);
    let fl = fl_create_ruleset(ptr::null(), 0, c_uint::MAX);

    assert_eq!(
        fl, host,
        "landlock_create_ruleset(invalid flags): fl={fl:?} host={host:?}"
    );
    if host != (-1, libc::ENOSYS) {
        assert_eq!(fl, (-1, libc::EINVAL));
    }
}

#[test]
fn landlock_add_rule_invalid_fd_matches_host_syscall() {
    let host = host_add_rule(-1, 0, 0);
    let fl = fl_add_rule(-1, 0, 0);

    assert_eq!(
        fl, host,
        "landlock_add_rule(invalid fd): fl={fl:?} host={host:?}"
    );
    if host != (-1, libc::ENOSYS) {
        assert_eq!(fl, (-1, libc::EBADF));
    }
}

#[test]
fn landlock_restrict_self_failure_matches_host_syscall() {
    let host = host_restrict_self(-1, 0);
    let fl = fl_restrict_self(-1, 0);

    assert_eq!(
        fl, host,
        "landlock_restrict_self(invalid fd): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
