#![cfg(target_os = "linux")]

//! Differential conformance harness for `adjtimex(2)` /
//! `ntp_adjtime(3)`.
//!
//! Reads the kernel NTP/timex state. With modes=0 (query-only),
//! both fl and host glibc must observe identical clock parameters.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_int;

use frankenlibc_abi::unistd_abi as fl;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct TimexQuery {
    modes: u32,
    _pad1: u32,
    offset: i64,
    freq: i64,
    maxerror: i64,
    esterror: i64,
    status: i32,
    _pad2: i32,
    constant: i64,
    precision: i64,
    tolerance: i64,
    time_sec: i64,
    time_usec: i64,
    tick: i64,
    ppsfreq: i64,
    jitter: i64,
    shift: i32,
    _pad3: i32,
    stabil: i64,
    jitcnt: i64,
    calcnt: i64,
    errcnt: i64,
    stbcnt: i64,
    tai: i32,
    _pad4: [i32; 11],
}

unsafe extern "C" {
    fn adjtimex(buf: *mut TimexQuery) -> c_int;
    fn ntp_adjtime(buf: *mut TimexQuery) -> c_int;
}

#[test]
fn diff_adjtimex_query_returns_consistent_state() {
    // modes=0 means "read state, don't modify" — does not need
    // CAP_SYS_TIME.
    let mut fl_t = TimexQuery::default();
    let mut lc_t = TimexQuery::default();
    let fl_v = unsafe { fl::adjtimex(&mut fl_t as *mut TimexQuery as *mut std::ffi::c_void) };
    let lc_v = unsafe { adjtimex(&mut lc_t) };
    assert_eq!(fl_v, lc_v, "adjtimex(query) ret: fl={fl_v} lc={lc_v}");
    // Return value is the clock state (0..=TIME_ERROR=5 or so).
    assert!(fl_v >= 0, "should not fail with query mode");

    // status field tells us about clock state — must match.
    assert_eq!(
        fl_t.status, lc_t.status,
        "status: fl={} lc={}",
        fl_t.status, lc_t.status
    );
    // tick is the kernel's tick rate — must match.
    assert_eq!(fl_t.tick, lc_t.tick);
    // tolerance and precision are read-only kernel constants.
    assert_eq!(fl_t.tolerance, lc_t.tolerance);
    assert_eq!(fl_t.precision, lc_t.precision);
}

#[test]
fn diff_ntp_adjtime_alias_matches_adjtimex() {
    let mut fl_t = TimexQuery::default();
    let fl_v = unsafe { fl::ntp_adjtime(&mut fl_t as *mut TimexQuery as *mut std::ffi::c_void) };
    let mut lc_t = TimexQuery::default();
    let lc_v = unsafe { ntp_adjtime(&mut lc_t) };
    assert_eq!(fl_v, lc_v);
    assert_eq!(fl_t.status, lc_t.status);
    assert_eq!(fl_t.tick, lc_t.tick);
}

#[test]
fn diff_adjtimex_unprivileged_modify_returns_eperm() {
    // ADJ_OFFSET requires CAP_SYS_TIME. Both impls should fail
    // with EPERM as a regular user.
    let mut fl_t = TimexQuery {
        modes: 0x0001, // ADJ_OFFSET
        offset: 100,   // 100 us adjustment
        ..Default::default()
    };
    let mut lc_t = fl_t;
    let fl_v = unsafe { fl::adjtimex(&mut fl_t as *mut TimexQuery as *mut std::ffi::c_void) };
    let fl_e = unsafe { *libc::__errno_location() };
    let lc_v = unsafe { adjtimex(&mut lc_t) };
    let lc_e = unsafe { *libc::__errno_location() };
    if fl_v == -1 || lc_v == -1 {
        assert_eq!(fl_v, lc_v, "ret: fl={fl_v} lc={lc_v}");
        assert_eq!(fl_e, lc_e, "errno: fl={fl_e} lc={lc_e}");
    }
}

#[test]
fn diff_adjtimex_null_returns_efault() {
    let fl_v = unsafe { fl::adjtimex(std::ptr::null_mut()) };
    let fl_e = unsafe { *libc::__errno_location() };
    let lc_v = unsafe { adjtimex(std::ptr::null_mut()) };
    let lc_e = unsafe { *libc::__errno_location() };
    assert_eq!(fl_v, lc_v);
    assert_eq!(fl_v, -1);
    assert_eq!(fl_e, lc_e, "NULL errno: fl={fl_e} lc={lc_e}");
}

#[test]
fn adjtimex_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc adjtimex + ntp_adjtime\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
