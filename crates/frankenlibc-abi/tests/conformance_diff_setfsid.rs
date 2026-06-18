#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc setfsuid/setfsgid oracle

//! Differential coverage for Linux fsuid/fsgid query calls. Passing `(uid_t)-1`
//! or `(gid_t)-1` returns the current filesystem credential without changing it,
//! which makes these checks safe to run in-process.

use frankenlibc_abi::glibc_internal_abi::{
    setfsgid as fl_setfsgid, setfsuid as fl_setfsuid,
};
use std::ffi::c_int;

unsafe extern "C" {
    #[link_name = "setfsgid"]
    fn host_setfsgid(fsgid: libc::gid_t) -> c_int;
    #[link_name = "setfsuid"]
    fn host_setfsuid(fsuid: libc::uid_t) -> c_int;
}

#[test]
fn setfsuid_minus_one_queries_current_fsuid_like_glibc() {
    let query = libc::uid_t::MAX;

    let host_before = unsafe { host_setfsuid(query) };
    let fl_result = unsafe { fl_setfsuid(query) };
    let host_after = unsafe { host_setfsuid(query) };

    assert_eq!(
        fl_result, host_before,
        "setfsuid((uid_t)-1) return mismatch: fl={fl_result} glibc={host_before}"
    );
    assert_eq!(
        host_after, host_before,
        "setfsuid((uid_t)-1) must not change the current fsuid"
    );
    assert!(fl_result >= 0, "setfsuid query must return a nonnegative fsuid");
}

#[test]
fn setfsgid_minus_one_queries_current_fsgid_like_glibc() {
    let query = libc::gid_t::MAX;

    let host_before = unsafe { host_setfsgid(query) };
    let fl_result = unsafe { fl_setfsgid(query) };
    let host_after = unsafe { host_setfsgid(query) };

    assert_eq!(
        fl_result, host_before,
        "setfsgid((gid_t)-1) return mismatch: fl={fl_result} glibc={host_before}"
    );
    assert_eq!(
        host_after, host_before,
        "setfsgid((gid_t)-1) must not change the current fsgid"
    );
    assert!(fl_result >= 0, "setfsgid query must return a nonnegative fsgid");
}
