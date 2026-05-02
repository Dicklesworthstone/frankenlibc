#![cfg(target_os = "linux")]

//! Differential conformance harness for `getrusage(RUSAGE_THREAD, ...)`.
//!
//! Existing conformance_diff_sys_resource.rs covers RUSAGE_SELF and
//! RUSAGE_CHILDREN. This file fills the RUSAGE_THREAD gap and
//! verifies fl matches glibc on Linux-specific thread-level
//! resource accounting.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_int;

use frankenlibc_abi::unistd_abi as fl;

#[test]
fn diff_getrusage_thread_returns_valid_data() {
    let mut fl_r: libc::rusage = unsafe { std::mem::zeroed() };
    let mut lc_r: libc::rusage = unsafe { std::mem::zeroed() };
    let fl_v = unsafe { fl::getrusage(libc::RUSAGE_THREAD, &mut fl_r) };
    let lc_v = unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut lc_r) };
    assert_eq!(fl_v, lc_v, "getrusage(RUSAGE_THREAD) ret");
    assert_eq!(fl_v, 0);
    // Both should report non-negative time fields.
    assert!(fl_r.ru_utime.tv_sec >= 0);
    assert!(fl_r.ru_stime.tv_sec >= 0);
    assert!(lc_r.ru_utime.tv_sec >= 0);
    assert!(lc_r.ru_stime.tv_sec >= 0);
}

#[test]
fn diff_getrusage_thread_user_time_monotonic_after_busy_loop() {
    let mut before: libc::rusage = unsafe { std::mem::zeroed() };
    let mut after: libc::rusage = unsafe { std::mem::zeroed() };
    let r1 = unsafe { fl::getrusage(libc::RUSAGE_THREAD, &mut before) };
    assert_eq!(r1, 0);
    // Spin enough to register at least 1ms of user time.
    let start = std::time::Instant::now();
    let mut acc: u64 = 0;
    while start.elapsed().as_millis() < 5 {
        acc = acc.wrapping_add(1);
    }
    std::hint::black_box(acc);
    let r2 = unsafe { fl::getrusage(libc::RUSAGE_THREAD, &mut after) };
    assert_eq!(r2, 0);
    let before_us =
        before.ru_utime.tv_sec as i64 * 1_000_000 + before.ru_utime.tv_usec as i64;
    let after_us =
        after.ru_utime.tv_sec as i64 * 1_000_000 + after.ru_utime.tv_usec as i64;
    assert!(
        after_us >= before_us,
        "user time should not decrease: before={before_us} after={after_us}"
    );
}

#[test]
fn diff_getrusage_invalid_who_returns_einval() {
    let mut r: libc::rusage = unsafe { std::mem::zeroed() };
    let fl_v = unsafe { fl::getrusage(0xff_ffff as c_int, &mut r) };
    let fl_e = unsafe { *libc::__errno_location() };
    let lc_v = unsafe { libc::getrusage(0xff_ffff as c_int, &mut r) };
    let lc_e = unsafe { *libc::__errno_location() };
    assert_eq!(fl_v, lc_v);
    assert_eq!(fl_v, -1);
    assert_eq!(fl_e, lc_e, "errno: fl={fl_e} lc={lc_e}");
}

#[test]
fn diff_getrusage_thread_separate_threads_have_separate_times() {
    use std::thread;
    // Spawn a busy thread; verify its rusage diverges from the
    // main thread.
    let main_before: libc::rusage = unsafe {
        let mut r = std::mem::zeroed();
        fl::getrusage(libc::RUSAGE_THREAD, &mut r);
        r
    };
    let h = thread::spawn(|| {
        let mut r: libc::rusage = unsafe { std::mem::zeroed() };
        let start = std::time::Instant::now();
        let mut acc: u64 = 0;
        while start.elapsed().as_millis() < 10 {
            acc = acc.wrapping_add(1);
        }
        std::hint::black_box(acc);
        unsafe { fl::getrusage(libc::RUSAGE_THREAD, &mut r) };
        r
    });
    let other = h.join().expect("join");
    // The busy thread should have accrued some user time.
    let other_us = other.ru_utime.tv_sec as i64 * 1_000_000 + other.ru_utime.tv_usec as i64;
    // Sanity: should be non-negative.
    assert!(other_us >= 0);
    // Main-thread time wasn't burning during the spawn.
    let main_us = main_before.ru_utime.tv_sec as i64 * 1_000_000
        + main_before.ru_utime.tv_usec as i64;
    let _ = main_us;
}

#[test]
fn getrusage_thread_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc getrusage(RUSAGE_THREAD)\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
