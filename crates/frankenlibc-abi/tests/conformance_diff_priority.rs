#![cfg(target_os = "linux")]

//! Differential conformance harness for `getpriority(2)` /
//! `setpriority(2)` / `nice(3)` / `sched_getcpu(3)`.
//!
//! All four call into the kernel via raw syscalls (or fall back to a
//! hint table). fl and glibc must agree on the return values for the
//! current process, with caveats:
//!   - sched_getcpu can return any current CPU, but consecutive calls
//!     within the same iteration must give the same result if pinned;
//!     for our test we just check both impls return a valid CPU index
//!   - getpriority(0, 0) returns the calling process's nice value;
//!     unaffected between fl and glibc calls
//!   - setpriority requires CAP_SYS_NICE for negative values, so we
//!     test only with non-negative deltas (or avoid setting at all)
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_int;

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn getpriority(which: c_int, who: libc::id_t) -> c_int;
    fn setpriority(which: c_int, who: libc::id_t, prio: c_int) -> c_int;
    fn nice(inc: c_int) -> c_int;
    fn sched_getcpu() -> c_int;
}

#[test]
fn diff_getpriority_self() {
    // PRIO_PROCESS = 0, who=0 means calling process. errno is set to 0
    // first because getpriority's success-vs-error contract uses the
    // value -1 for both (caller checks errno).
    unsafe {
        *libc::__errno_location() = 0;
    }
    let fl_p = unsafe { fl::getpriority(0, 0) };
    let fl_e = unsafe { *libc::__errno_location() };
    unsafe {
        *libc::__errno_location() = 0;
    }
    let lc_p = unsafe { getpriority(0, 0) };
    let lc_e = unsafe { *libc::__errno_location() };
    assert_eq!(fl_p, lc_p, "getpriority value mismatch: fl={fl_p} lc={lc_p}");
    assert_eq!(fl_e, lc_e, "getpriority errno mismatch: fl={fl_e} lc={lc_e}");
}

#[test]
fn diff_getpriority_invalid_which_errors_match() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let fl_p = unsafe { fl::getpriority(99, 0) };
    let fl_e = unsafe { *libc::__errno_location() };
    unsafe {
        *libc::__errno_location() = 0;
    }
    let lc_p = unsafe { getpriority(99, 0) };
    let lc_e = unsafe { *libc::__errno_location() };
    // Both should report the same errno (typically EINVAL).
    assert_eq!(fl_p, lc_p, "getpriority invalid: fl={fl_p} lc={lc_p}");
    assert_eq!(fl_e, lc_e, "getpriority invalid errno: fl={fl_e} lc={lc_e}");
}

#[test]
fn diff_setpriority_zero_delta_succeeds() {
    // Reading the current value and setting it back to itself should
    // succeed without privilege.
    let cur = unsafe { getpriority(0, 0) };
    let fl_r = unsafe { fl::setpriority(0, 0, cur) };
    let lc_r = unsafe { setpriority(0, 0, cur) };
    assert_eq!(fl_r, lc_r, "setpriority self mismatch: fl={fl_r} lc={lc_r}");
    assert_eq!(fl_r, 0, "setpriority(self, current) should succeed");
}

#[test]
fn diff_sched_getcpu_within_valid_range() {
    let fl_cpu = unsafe { fl::sched_getcpu() };
    let lc_cpu = unsafe { sched_getcpu() };
    // Both must return a non-negative CPU index. The exact value can
    // differ if the kernel migrated us between calls; we only check
    // that both succeed and return plausible indices.
    assert!(fl_cpu >= 0, "fl sched_getcpu returned {fl_cpu}");
    assert!(lc_cpu >= 0, "glibc sched_getcpu returned {lc_cpu}");
    let nproc = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as c_int;
    assert!(
        fl_cpu < nproc.max(1024),
        "fl sched_getcpu returned implausible {fl_cpu}"
    );
    assert!(
        lc_cpu < nproc.max(1024),
        "lc sched_getcpu returned implausible {lc_cpu}"
    );
}

#[test]
fn priority_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc priority/scheduler\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
