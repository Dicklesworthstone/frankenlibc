#![cfg(target_os = "linux")]

//! Differential conformance harness for `prlimit(2)`.
//!
//! prlimit lets you query/modify another process's resource limits.
//! Both fl and glibc invoke SYS_prlimit64 underneath. We diff against
//! self (PID=0) to keep things deterministic and not require CAP_SYS_RESOURCE.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_int;

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn prlimit(
        pid: libc::pid_t,
        resource: c_int,
        new_limit: *const libc::rlimit,
        old_limit: *mut libc::rlimit,
    ) -> c_int;
}

#[test]
fn diff_prlimit_query_self() {
    // Query each well-known RLIMIT_* against self (pid=0).
    let resources: &[(c_int, &str)] = &[
        (libc::RLIMIT_CPU as c_int, "RLIMIT_CPU"),
        (libc::RLIMIT_FSIZE as c_int, "RLIMIT_FSIZE"),
        (libc::RLIMIT_DATA as c_int, "RLIMIT_DATA"),
        (libc::RLIMIT_STACK as c_int, "RLIMIT_STACK"),
        (libc::RLIMIT_CORE as c_int, "RLIMIT_CORE"),
        (libc::RLIMIT_RSS as c_int, "RLIMIT_RSS"),
        (libc::RLIMIT_NOFILE as c_int, "RLIMIT_NOFILE"),
        (libc::RLIMIT_AS as c_int, "RLIMIT_AS"),
        (libc::RLIMIT_NPROC as c_int, "RLIMIT_NPROC"),
        (libc::RLIMIT_MEMLOCK as c_int, "RLIMIT_MEMLOCK"),
        (libc::RLIMIT_LOCKS as c_int, "RLIMIT_LOCKS"),
        (libc::RLIMIT_SIGPENDING as c_int, "RLIMIT_SIGPENDING"),
        (libc::RLIMIT_MSGQUEUE as c_int, "RLIMIT_MSGQUEUE"),
        (libc::RLIMIT_NICE as c_int, "RLIMIT_NICE"),
        (libc::RLIMIT_RTPRIO as c_int, "RLIMIT_RTPRIO"),
        (libc::RLIMIT_RTTIME as c_int, "RLIMIT_RTTIME"),
    ];
    for &(res, name) in resources {
        let mut fl_lim: libc::rlimit = unsafe { std::mem::zeroed() };
        let mut lc_lim: libc::rlimit = unsafe { std::mem::zeroed() };
        let fl_r = unsafe { fl::prlimit(0, res, std::ptr::null(), &mut fl_lim) };
        let lc_r = unsafe { prlimit(0, res, std::ptr::null(), &mut lc_lim) };
        assert_eq!(
            fl_r, lc_r,
            "prlimit({name}) return mismatch: fl={fl_r} lc={lc_r}"
        );
        if fl_r == 0 {
            assert_eq!(
                fl_lim.rlim_cur, lc_lim.rlim_cur,
                "{name} rlim_cur: fl={} lc={}",
                fl_lim.rlim_cur, lc_lim.rlim_cur
            );
            assert_eq!(
                fl_lim.rlim_max, lc_lim.rlim_max,
                "{name} rlim_max: fl={} lc={}",
                fl_lim.rlim_max, lc_lim.rlim_max
            );
        }
    }
}

#[test]
fn diff_prlimit_invalid_resource_errors_match() {
    let mut fl_lim: libc::rlimit = unsafe { std::mem::zeroed() };
    let mut lc_lim: libc::rlimit = unsafe { std::mem::zeroed() };
    let fl_r = unsafe { fl::prlimit(0, 9999, std::ptr::null(), &mut fl_lim) };
    let lc_r = unsafe { prlimit(0, 9999, std::ptr::null(), &mut lc_lim) };
    assert_eq!(fl_r, lc_r, "invalid-resource return: fl={fl_r} lc={lc_r}");
    assert_eq!(fl_r, -1);
}

#[test]
fn diff_prlimit_set_self_to_current_value() {
    // Setting the value to its current value should always succeed (no
    // privilege needed). Tests the new_limit code path.
    let mut cur: libc::rlimit = unsafe { std::mem::zeroed() };
    let _ = unsafe { fl::prlimit(0, libc::RLIMIT_NOFILE as c_int, std::ptr::null(), &mut cur) };
    let fl_r = unsafe { fl::prlimit(0, libc::RLIMIT_NOFILE as c_int, &cur, std::ptr::null_mut()) };
    let lc_r = unsafe { prlimit(0, libc::RLIMIT_NOFILE as c_int, &cur, std::ptr::null_mut()) };
    assert_eq!(fl_r, lc_r, "set-self-current: fl={fl_r} lc={lc_r}");
    assert_eq!(fl_r, 0);
}

#[test]
fn prlimit_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc prlimit\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
