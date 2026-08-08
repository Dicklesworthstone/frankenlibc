#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc identity/table-size oracle

//! Host-differential gate for the scalar `unistd` wrappers that had no no-mock
//! parity coverage: the process/user/group identity calls (bd-8yf9w8) and
//! `getdtablesize` (bd-f93yol).
//!
//! These are raw-syscall ABI functions, so the interesting failure is not a
//! wrong algorithm but a wrong syscall, a wrong return width, or a wrapper that
//! quietly answers from somewhere other than the kernel. Only a live comparison
//! catches that, so every assertion here runs fl and host glibc in the SAME
//! process and compares. No mocks, no fixtures.
//!
//! Why the plain `extern "C"` block reaches GLIBC and not fl's own exports:
//! fl's definitions carry `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`,
//! so their `no_mangle` is switched OFF in debug builds. `cargo test` is a debug
//! build, so these symbols resolve to the host. That is the same mechanism the
//! neighbouring conformance_diff_* gates rely on.
//!
//! Note the deliberately weak-looking assertions on the identity calls: their
//! values are whatever this process happens to have, so the contract worth
//! pinning is fl == glibc, plus the few invariants that hold for ANY process.
//! Asserting a specific pid would be a test of the test runner, not of fl.

use std::ffi::c_int;

unsafe extern "C" {
    fn getpid() -> i32;
    fn getppid() -> i32;
    fn getuid() -> u32;
    fn geteuid() -> u32;
    fn getgid() -> u32;
    fn getegid() -> u32;
    fn getdtablesize() -> c_int;
    fn sysconf(name: c_int) -> libc::c_long;
}

const SC_OPEN_MAX: c_int = 4; // _SC_OPEN_MAX on Linux

#[test]
fn unistd_identity_scalars_match_glibc() {
    // Each pair is read fl-then-host, back to back. These values are stable for
    // the lifetime of the process, so an intervening change is not a hazard the
    // way it would be for, say, a clock.
    let fl_pid = unsafe { frankenlibc_abi::unistd_abi::getpid() };
    let h_pid = unsafe { getpid() };
    assert_eq!(fl_pid, h_pid, "getpid: fl={fl_pid} glibc={h_pid}");

    let fl_ppid = unsafe { frankenlibc_abi::unistd_abi::getppid() };
    let h_ppid = unsafe { getppid() };
    assert_eq!(fl_ppid, h_ppid, "getppid: fl={fl_ppid} glibc={h_ppid}");

    let fl_uid = unsafe { frankenlibc_abi::unistd_abi::getuid() };
    let h_uid = unsafe { getuid() };
    assert_eq!(fl_uid, h_uid, "getuid: fl={fl_uid} glibc={h_uid}");

    let fl_euid = unsafe { frankenlibc_abi::unistd_abi::geteuid() };
    let h_euid = unsafe { geteuid() };
    assert_eq!(fl_euid, h_euid, "geteuid: fl={fl_euid} glibc={h_euid}");

    let fl_gid = unsafe { frankenlibc_abi::unistd_abi::getgid() };
    let h_gid = unsafe { getgid() };
    assert_eq!(fl_gid, h_gid, "getgid: fl={fl_gid} glibc={h_gid}");

    let fl_egid = unsafe { frankenlibc_abi::unistd_abi::getegid() };
    let h_egid = unsafe { getegid() };
    assert_eq!(fl_egid, h_egid, "getegid: fl={fl_egid} glibc={h_egid}");

    // Invariants true of ANY live process, which catch a wrapper that returns a
    // plausible-looking constant or a truncated/sign-extended value. A pid of 0
    // or a negative pid would both slip past the equality checks above if BOTH
    // implementations were broken the same way.
    assert!(fl_pid > 0, "getpid must be positive, got {fl_pid}");
    assert!(fl_ppid > 0, "getppid must be positive, got {fl_ppid}");
    assert_eq!(
        fl_pid,
        std::process::id() as i32,
        "getpid must agree with the process's own id"
    );

    // Repeat calls must be stable: identity does not change under us here, so a
    // wrapper caching the wrong thing (or re-reading a clobbered errno slot)
    // shows up as drift.
    assert_eq!(
        fl_pid,
        unsafe { frankenlibc_abi::unistd_abi::getpid() },
        "getpid must be stable across calls"
    );
    assert_eq!(
        fl_uid,
        unsafe { frankenlibc_abi::unistd_abi::getuid() },
        "getuid must be stable across calls"
    );
}

#[test]
fn getdtablesize_matches_glibc_and_sysconf() {
    let fl = unsafe { frankenlibc_abi::unistd_abi::getdtablesize() };
    let host = unsafe { getdtablesize() };
    assert_eq!(fl, host, "getdtablesize: fl={fl} glibc={host}");

    // getdtablesize reads RLIMIT_NOFILE, which is the same soft limit
    // sysconf(_SC_OPEN_MAX) reports, so the two must agree. This is the arm that
    // would catch fl answering from a hardcoded constant (a stale OPEN_MAX of
    // 1024 would still equal glibc only if glibc were also wrong).
    let sc = unsafe { sysconf(SC_OPEN_MAX) };
    assert!(
        sc > 0,
        "host sysconf(_SC_OPEN_MAX) should be positive, got {sc}"
    );
    assert_eq!(
        i64::from(fl),
        i64::from(sc as i32),
        "getdtablesize ({fl}) must match sysconf(_SC_OPEN_MAX) ({sc})"
    );

    assert!(fl > 0, "getdtablesize must be positive, got {fl}");
}
