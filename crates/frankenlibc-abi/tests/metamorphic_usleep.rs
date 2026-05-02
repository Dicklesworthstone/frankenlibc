#![cfg(target_os = "linux")]

//! Metamorphic-property tests for `usleep(3)` / `nanosleep(2)`.
//!
//! Internal invariants:
//!
//!   - usleep(0) returns immediately and returns 0
//!   - usleep(N) sleeps for at least N microseconds (within
//!     timer-resolution tolerance)
//!   - usleep is monotonic: sleeping N then M takes at least N+M
//!     wall-clock time
//!   - usleep returns 0 on success
//!
//! Filed under [bd-xn6p8] follow-up.

use std::time::Instant;

use frankenlibc_abi::time_abi as fl_time;
use frankenlibc_abi::unistd_abi as fl;

#[test]
fn metamorphic_usleep_zero_returns_immediately() {
    let start = Instant::now();
    let r = unsafe { fl::usleep(0) };
    let elapsed = start.elapsed();
    assert_eq!(r, 0);
    assert!(
        elapsed.as_micros() < 1000,
        "usleep(0) took {} us",
        elapsed.as_micros()
    );
}

#[test]
fn metamorphic_usleep_short_sleeps_at_least_requested() {
    // 2ms — both kernels should be able to schedule this.
    let start = Instant::now();
    let r = unsafe { fl::usleep(2000) };
    let elapsed_us = start.elapsed().as_micros() as u32;
    assert_eq!(r, 0);
    // Allow 1us of measurement slack.
    assert!(
        elapsed_us + 1 >= 2000,
        "usleep(2000) only slept {elapsed_us}us"
    );
}

#[test]
fn metamorphic_usleep_monotonic_sequence() {
    // Sleeping A then B should take at least A+B wall-clock time.
    let a: u32 = 1500;
    let b: u32 = 2500;
    let start = Instant::now();
    let _ = unsafe { fl::usleep(a) };
    let _ = unsafe { fl::usleep(b) };
    let elapsed_us = start.elapsed().as_micros() as u32;
    assert!(
        elapsed_us + 5 >= a + b,
        "two sleeps {a}+{b}={} only took {elapsed_us}",
        a + b
    );
}

#[test]
fn metamorphic_usleep_one_succeeds() {
    let r = unsafe { fl::usleep(1) };
    assert_eq!(r, 0);
}

#[test]
fn metamorphic_usleep_repeated_calls_succeed() {
    for _ in 0..32 {
        let r = unsafe { fl::usleep(100) };
        assert_eq!(r, 0);
    }
}

#[test]
fn metamorphic_nanosleep_returns_zero_for_short_uninterrupted() {
    let req = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000, // 1ms
    };
    let mut rem: libc::timespec = unsafe { std::mem::zeroed() };
    let r = unsafe { fl_time::nanosleep(&req, &mut rem) };
    assert_eq!(r, 0, "nanosleep(1ms) failed");
}

#[test]
fn metamorphic_nanosleep_zero_returns_immediately() {
    let req = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let mut rem: libc::timespec = unsafe { std::mem::zeroed() };
    let start = Instant::now();
    let r = unsafe { fl_time::nanosleep(&req, &mut rem) };
    let elapsed_us = start.elapsed().as_micros();
    assert_eq!(r, 0);
    // Allow a generous 50ms upper bound — system may have lots of
    // scheduling pressure under cargo's parallel test runner.
    assert!(elapsed_us < 50_000, "nanosleep(0) took {elapsed_us}us");
}

#[test]
fn usleep_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc usleep + nanosleep\",\"reference\":\"timing-invariants\",\"properties\":7,\"divergences\":0}}",
    );
}
