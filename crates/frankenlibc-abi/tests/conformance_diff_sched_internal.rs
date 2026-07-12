#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc __sched_* oracle

//! Differential coverage for glibc's internal `__sched_*` aliases. These
//! aliases must preserve the public scheduler errno contract on syscall errors.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::glibc_internal_abi::{
    __sched_get_priority_max as fl_sched_get_priority_max,
    __sched_get_priority_min as fl_sched_get_priority_min, __sched_getparam as fl_sched_getparam,
    __sched_getscheduler as fl_sched_getscheduler, __sched_setscheduler as fl_sched_setscheduler,
    __sched_yield as fl_sched_yield,
};
use std::ffi::{c_int, c_void};

unsafe extern "C" {
    #[link_name = "__sched_get_priority_max"]
    fn host_sched_get_priority_max(policy: c_int) -> c_int;
    #[link_name = "__sched_get_priority_min"]
    fn host_sched_get_priority_min(policy: c_int) -> c_int;
    #[link_name = "__sched_getparam"]
    fn host_sched_getparam(pid: c_int, param: *mut libc::sched_param) -> c_int;
    #[link_name = "__sched_getscheduler"]
    fn host_sched_getscheduler(pid: c_int) -> c_int;
    #[link_name = "__sched_setscheduler"]
    fn host_sched_setscheduler(pid: c_int, policy: c_int, param: *const libc::sched_param)
    -> c_int;
    #[link_name = "__sched_yield"]
    fn host_sched_yield() -> c_int;
}

fn host_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn fl_errno() -> c_int {
    unsafe { *fl_errno_location() }
}

fn clear_host_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

fn clear_fl_errno() {
    unsafe { *fl_errno_location() = 0 };
}

#[test]
fn internal_sched_priority_bounds_match_host_policies() {
    for policy in [
        libc::SCHED_OTHER,
        libc::SCHED_FIFO,
        libc::SCHED_RR,
        libc::SCHED_BATCH,
        libc::SCHED_IDLE,
    ] {
        let host_min = unsafe { host_sched_get_priority_min(policy) };
        let fl_min = unsafe { fl_sched_get_priority_min(policy) };
        assert_eq!(
            fl_min, host_min,
            "__sched_get_priority_min({policy}) return mismatch"
        );

        let host_max = unsafe { host_sched_get_priority_max(policy) };
        let fl_max = unsafe { fl_sched_get_priority_max(policy) };
        assert_eq!(
            fl_max, host_max,
            "__sched_get_priority_max({policy}) return mismatch"
        );
    }
}

#[test]
fn internal_sched_priority_invalid_policy_matches_host_errno() {
    clear_host_errno();
    let host_min = unsafe { host_sched_get_priority_min(-1) };
    let host_min_err = host_errno();

    clear_fl_errno();
    let fl_min = unsafe { fl_sched_get_priority_min(-1) };
    let fl_min_err = fl_errno();

    assert_eq!(
        (fl_min, fl_min_err),
        (host_min, host_min_err),
        "__sched_get_priority_min(-1): fl=({fl_min}, {fl_min_err}) \
         glibc=({host_min}, {host_min_err})"
    );
    assert_eq!((fl_min, fl_min_err), (-1, libc::EINVAL));

    clear_host_errno();
    let host_max = unsafe { host_sched_get_priority_max(-1) };
    let host_max_err = host_errno();

    clear_fl_errno();
    let fl_max = unsafe { fl_sched_get_priority_max(-1) };
    let fl_max_err = fl_errno();

    assert_eq!(
        (fl_max, fl_max_err),
        (host_max, host_max_err),
        "__sched_get_priority_max(-1): fl=({fl_max}, {fl_max_err}) \
         glibc=({host_max}, {host_max_err})"
    );
    assert_eq!((fl_max, fl_max_err), (-1, libc::EINVAL));
}

#[test]
fn internal_sched_yield_matches_host_success_contract() {
    clear_host_errno();
    let host_result = unsafe { host_sched_yield() };

    clear_fl_errno();
    let fl_result = unsafe { fl_sched_yield() };

    assert_eq!(
        fl_result, host_result,
        "__sched_yield return mismatch: fl={fl_result} glibc={host_result}"
    );
    assert_eq!(fl_result, 0);
}

#[test]
fn internal_sched_getscheduler_invalid_pid_matches_host_errno() {
    clear_host_errno();
    let host_result = unsafe { host_sched_getscheduler(-1) };
    let host_err = host_errno();

    clear_fl_errno();
    let fl_result = unsafe { fl_sched_getscheduler(-1) };
    let fl_err = fl_errno();

    assert_eq!(
        (fl_result, fl_err),
        (host_result, host_err),
        "__sched_getscheduler(-1): fl=({fl_result}, {fl_err}) glibc=({host_result}, {host_err})"
    );
    assert_eq!((fl_result, fl_err), (-1, libc::EINVAL));
}

#[test]
fn internal_sched_getparam_invalid_pid_matches_host_errno() {
    let mut host_param = libc::sched_param { sched_priority: 0 };
    let mut fl_param = libc::sched_param { sched_priority: 0 };

    clear_host_errno();
    let host_result = unsafe { host_sched_getparam(-1, &mut host_param) };
    let host_err = host_errno();

    clear_fl_errno();
    let fl_result =
        unsafe { fl_sched_getparam(-1, (&mut fl_param as *mut libc::sched_param).cast()) };
    let fl_err = fl_errno();

    assert_eq!(
        (fl_result, fl_err),
        (host_result, host_err),
        "__sched_getparam(-1): fl=({fl_result}, {fl_err}) glibc=({host_result}, {host_err})"
    );
    assert_eq!((fl_result, fl_err), (-1, libc::EINVAL));
}

#[test]
fn internal_sched_setscheduler_invalid_pid_matches_host_errno() {
    let param = libc::sched_param { sched_priority: 0 };

    clear_host_errno();
    let host_result = unsafe { host_sched_setscheduler(-1, libc::SCHED_OTHER, &param) };
    let host_err = host_errno();

    clear_fl_errno();
    let fl_result = unsafe {
        fl_sched_setscheduler(
            -1,
            libc::SCHED_OTHER,
            (&param as *const libc::sched_param).cast::<c_void>(),
        )
    };
    let fl_err = fl_errno();

    assert_eq!(
        (fl_result, fl_err),
        (host_result, host_err),
        "__sched_setscheduler(-1): fl=({fl_result}, {fl_err}) glibc=({host_result}, {host_err})"
    );
    assert_eq!((fl_result, fl_err), (-1, libc::EINVAL));
}
