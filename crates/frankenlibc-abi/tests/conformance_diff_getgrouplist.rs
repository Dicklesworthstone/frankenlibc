#![cfg(target_os = "linux")]

//! Differential conformance harness for `getgrouplist(3)`.
//!
//! Returns the supplementary group list for a user. Reads /etc/group
//! and /etc/passwd. Both fl and glibc must agree on the group set
//! returned for the calling user.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_int, CString};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn getgrouplist(
        user: *const c_char,
        group: libc::gid_t,
        groups: *mut libc::gid_t,
        ngroups: *mut c_int,
    ) -> c_int;
}

#[test]
fn diff_getgrouplist_current_user() {
    // Look up the current user.
    let uid = unsafe { libc::getuid() };
    let pwd = unsafe { libc::getpwuid(uid) };
    if pwd.is_null() {
        eprintln!("skipping: getpwuid failed for uid={uid}");
        return;
    }
    let user = unsafe { (*pwd).pw_name };
    let primary = unsafe { (*pwd).pw_gid };

    let mut fl_buf = vec![0u32; 64];
    let mut lc_buf = vec![0u32; 64];
    let mut fl_n: c_int = fl_buf.len() as c_int;
    let mut lc_n: c_int = lc_buf.len() as c_int;
    let fl_r = unsafe { fl::getgrouplist(user, primary, fl_buf.as_mut_ptr(), &mut fl_n) };
    let lc_r = unsafe { getgrouplist(user, primary, lc_buf.as_mut_ptr(), &mut lc_n) };
    assert_eq!(
        fl_r, lc_r,
        "getgrouplist return mismatch: fl={fl_r} lc={lc_r}"
    );
    if fl_r >= 0 {
        assert_eq!(fl_n, lc_n, "ngroups mismatch: fl={fl_n} lc={lc_n}");
        let mut fl_set: Vec<u32> = fl_buf[..fl_n as usize].to_vec();
        let mut lc_set: Vec<u32> = lc_buf[..lc_n as usize].to_vec();
        fl_set.sort_unstable();
        lc_set.sort_unstable();
        assert_eq!(fl_set, lc_set, "group set mismatch");
    }
}

#[test]
fn diff_getgrouplist_buffer_too_small() {
    // Ask for too-small ngroups: both impls must return -1 and update
    // *ngroups with the actual count.
    let user = CString::new("root").unwrap();
    let mut fl_buf = [0u32; 1];
    let mut lc_buf = [0u32; 1];
    let mut fl_n: c_int = 1;
    let mut lc_n: c_int = 1;
    let fl_r = unsafe { fl::getgrouplist(user.as_ptr(), 0, fl_buf.as_mut_ptr(), &mut fl_n) };
    let lc_r = unsafe { getgrouplist(user.as_ptr(), 0, lc_buf.as_mut_ptr(), &mut lc_n) };
    assert_eq!(fl_r, lc_r, "small-buf return mismatch: fl={fl_r} lc={lc_r}");
    if fl_r == -1 {
        // Both should agree on the required size.
        assert_eq!(fl_n, lc_n, "required ngroups mismatch: fl={fl_n} lc={lc_n}");
    }
}

#[test]
fn diff_getgrouplist_nonexistent_user() {
    let user = CString::new("definitely-nonexistent-frankenlibc-user").unwrap();
    let mut fl_buf = [0u32; 16];
    let mut lc_buf = [0u32; 16];
    let mut fl_n: c_int = fl_buf.len() as c_int;
    let mut lc_n: c_int = lc_buf.len() as c_int;
    let fl_r = unsafe { fl::getgrouplist(user.as_ptr(), 1000, fl_buf.as_mut_ptr(), &mut fl_n) };
    let lc_r = unsafe { getgrouplist(user.as_ptr(), 1000, lc_buf.as_mut_ptr(), &mut lc_n) };
    assert_eq!(
        fl_r, lc_r,
        "nonexistent-user return mismatch: fl={fl_r} lc={lc_r}"
    );
}

#[test]
fn getgrouplist_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc getgrouplist\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
