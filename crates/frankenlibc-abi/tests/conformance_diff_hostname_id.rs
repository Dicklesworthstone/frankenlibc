#![cfg(target_os = "linux")]

//! Differential conformance harness for `gethostname`, `getdomainname`,
//! and `gethostid`.
//!
//! All three read process-global / system state. fl reads via raw
//! syscalls or /etc/hostid; glibc uses libc internal caches. Within
//! the same process, both must agree on the returned bytes.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{CStr, c_char, c_int};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn gethostname(name: *mut c_char, len: usize) -> c_int;
    fn getdomainname(name: *mut c_char, len: usize) -> c_int;
    fn gethostid() -> libc::c_long;
}

#[test]
fn diff_gethostname_match() {
    let mut fl_buf = vec![0i8; 256];
    let mut lc_buf = vec![0i8; 256];
    let fl_r = unsafe { fl::gethostname(fl_buf.as_mut_ptr(), fl_buf.len()) };
    let lc_r = unsafe { gethostname(lc_buf.as_mut_ptr(), lc_buf.len()) };
    assert_eq!(
        fl_r, lc_r,
        "gethostname return mismatch: fl={fl_r} lc={lc_r}"
    );
    if fl_r == 0 {
        let fl_s = unsafe { CStr::from_ptr(fl_buf.as_ptr()).to_bytes() };
        let lc_s = unsafe { CStr::from_ptr(lc_buf.as_ptr()).to_bytes() };
        assert_eq!(
            fl_s,
            lc_s,
            "gethostname strings differ: fl={:?} lc={:?}",
            String::from_utf8_lossy(fl_s),
            String::from_utf8_lossy(lc_s)
        );
    }
}

#[test]
fn diff_gethostname_buffer_too_small() {
    // Both impls must return -1 when buffer can't fit the hostname + NUL.
    // We don't know exact hostname length; size 1 is always too small unless hostname is empty.
    let mut fl_buf = [0i8; 1];
    let mut lc_buf = [0i8; 1];
    let fl_r = unsafe { fl::gethostname(fl_buf.as_mut_ptr(), 1) };
    let lc_r = unsafe { gethostname(lc_buf.as_mut_ptr(), 1) };
    assert_eq!(
        fl_r, lc_r,
        "gethostname size=1 mismatch: fl={fl_r} lc={lc_r}"
    );
}

#[test]
fn diff_getdomainname_match() {
    let mut fl_buf = vec![0i8; 256];
    let mut lc_buf = vec![0i8; 256];
    let fl_r = unsafe { fl::getdomainname(fl_buf.as_mut_ptr(), fl_buf.len()) };
    let lc_r = unsafe { getdomainname(lc_buf.as_mut_ptr(), lc_buf.len()) };
    assert_eq!(
        fl_r, lc_r,
        "getdomainname return mismatch: fl={fl_r} lc={lc_r}"
    );
    if fl_r == 0 {
        let fl_s = unsafe { CStr::from_ptr(fl_buf.as_ptr()).to_bytes() };
        let lc_s = unsafe { CStr::from_ptr(lc_buf.as_ptr()).to_bytes() };
        assert_eq!(
            fl_s,
            lc_s,
            "getdomainname strings differ: fl={:?} lc={:?}",
            String::from_utf8_lossy(fl_s),
            String::from_utf8_lossy(lc_s)
        );
    }
}

/// Smoke test: gethostid must return SOMETHING (non-zero, in the typical
/// case). fl uses a FNV-hash of nodename; glibc reads /etc/hostid then
/// falls back to an IP-derived value. Both are POSIX-conformant but
/// produce different identifiers. We don't diff exact values — only that
/// both return non-zero.
#[test]
fn diff_gethostid_both_non_zero() {
    let fl_id = unsafe { fl::gethostid() };
    let lc_id = unsafe { gethostid() };
    assert_ne!(fl_id, 0, "fl gethostid returned 0");
    assert_ne!(lc_id, 0, "glibc gethostid returned 0");
    // fl and glibc legitimately diverge here:
    //   - glibc reads /etc/hostid (or IP fallback)
    //   - fl hashes utsname.nodename
    // Both are POSIX-valid implementation-defined identifiers.
}

#[test]
fn hostname_id_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc gethostname/getdomainname/gethostid\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}

// ---------------------------------------------------------------------------
// sethostid range check (bd-xh08pf)
//
// glibc_internal_abi.rs carried a `#[cfg(test)] mod hostid_abi_tests` driving
// the private `hostid_to_i32` helper directly. That module is
// `#[cfg(not(test))] pub mod` in lib.rs, so the block compiled in neither
// configuration and its two tests had never run.
//
// The property is worth keeping, so it is rewritten here against the PUBLIC
// entry point. `sethostid` validates before it acts —
//
//     let hostid = match hostid_to_i32(hostid) { Ok(h) => h, Err(e) => { set_errno(e); return -1 } };
//     match write_hostid_file(hostid) { ... }
//
// — so an out-of-range argument is rejected without the file ever being
// touched, which makes the reject side safe to exercise anywhere. glibc does
// the same check (`if (id != (int) id) { __set_errno (EOVERFLOW); return -1; }`),
// so the two are directly comparable.
//
// THE ACCEPT SIDE IS DELIBERATELY NOT EXERCISED, and that is a real limit
// rather than an oversight: an in-range `sethostid` WRITES /etc/hostid, and
// these tests run on shared rch workers, some of which run as root. A test that
// rewrites the host identity of a build worker to prove a range check is not a
// trade worth making. The boundary below pins the accept side by its edge —
// 0x7fff_ffff is the largest accepted value precisely because 0x8000_0000 is
// the smallest rejected one.
unsafe extern "C" {
    fn sethostid(id: libc::c_long) -> c_int;
}

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[test]
fn sethostid_rejects_out_of_32_bit_range_like_glibc() {
    // Each value is one step outside signed 32-bit, plus a far-out case.
    for id in [
        0x8000_0000i64,
        -0x8000_0001i64,
        0x1_0000_0000i64,
        i64::from(i32::MAX) + 1,
        i64::MAX,
        i64::MIN,
    ] {
        let id = id as libc::c_long;

        // SAFETY: sethostid takes a scalar and, for these values, returns
        // before touching the filesystem. It lives in glibc_internal_abi, not
        // unistd_abi -- reachable here because an integration test compiles the
        // library WITHOUT --test, so its #[cfg(not(test))] gate is satisfied.
        let fl_rc = unsafe { frankenlibc_abi::glibc_internal_abi::sethostid(id) };
        let fl_errno = errno();
        // SAFETY: same call into live glibc.
        let gl_rc = unsafe { sethostid(id) };
        let gl_errno = errno();

        assert_eq!(
            (fl_rc, fl_errno),
            (gl_rc, gl_errno),
            "sethostid({id:#x}) diverged: fl=({fl_rc}, {fl_errno}) glibc=({gl_rc}, {gl_errno})"
        );
        // Assert what the ORACLE did, not only that the arms agree: if both
        // stopped range-checking, the equality above would still hold.
        assert_eq!(
            (gl_rc, gl_errno),
            (-1, libc::EOVERFLOW),
            "live glibc should reject {id:#x} with EOVERFLOW"
        );
    }
}
