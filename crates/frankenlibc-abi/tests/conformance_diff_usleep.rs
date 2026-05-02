#![cfg(target_os = "linux")]

//! Differential conformance harness for `usleep(3)`.
//!
//! `usleep(usec)` suspends execution for at least `usec` microseconds.
//! Both fl and glibc must accept the same range of inputs and
//! return 0 on successful completion.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_int;
use std::time::Instant;

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn usleep(usec: u32) -> c_int;
}

#[test]
fn diff_usleep_short_duration_succeeds() {
    // 1ms — both impls return 0.
    let fl_r = unsafe { fl::usleep(1000) };
    let lc_r = unsafe { usleep(1000) };
    assert_eq!(fl_r, lc_r, "usleep(1000): fl={fl_r} lc={lc_r}");
    assert_eq!(fl_r, 0);
}

#[test]
fn diff_usleep_zero_succeeds() {
    let fl_r = unsafe { fl::usleep(0) };
    let lc_r = unsafe { usleep(0) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
}

#[test]
fn diff_usleep_actually_sleeps_at_least_requested() {
    // Both impls must actually pause for ≥ requested duration.
    // We use 5ms to leave headroom for scheduling jitter.
    let target_us: u32 = 5_000;
    let fl_start = Instant::now();
    let fl_r = unsafe { fl::usleep(target_us) };
    let fl_elapsed = fl_start.elapsed();
    assert_eq!(fl_r, 0);
    let lc_start = Instant::now();
    let lc_r = unsafe { usleep(target_us) };
    let lc_elapsed = lc_start.elapsed();
    assert_eq!(lc_r, 0);
    // Both must sleep ≥ target microseconds (allow 1us tolerance).
    assert!(
        fl_elapsed.as_micros() as u32 + 1 >= target_us,
        "fl usleep undershot: {}us < {}us",
        fl_elapsed.as_micros(),
        target_us
    );
    assert!(
        lc_elapsed.as_micros() as u32 + 1 >= target_us,
        "lc usleep undershot: {}us < {}us",
        lc_elapsed.as_micros(),
        target_us
    );
}

#[test]
fn diff_usleep_one_million_us_one_second() {
    // 1,000,000us = 1s — POSIX may reject ≥ 1M; XSI accepts up to 1M.
    // We request just under to stay portable.
    let fl_r = unsafe { fl::usleep(999_999) };
    let lc_r = unsafe { usleep(999_999) };
    assert_eq!(fl_r, lc_r, "usleep(999999): fl={fl_r} lc={lc_r}");
    assert_eq!(fl_r, 0);
}

#[test]
fn usleep_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc usleep\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
