#![cfg(target_os = "linux")]

//! Integration tests for time_abi native implementations.
//!
//! Covers: time, clock_gettime, clock, localtime_r, gmtime_r, mktime, timegm,
//! difftime, gettimeofday, clock_getres, nanosleep, asctime_r, ctime_r,
//! strftime, gmtime, localtime, asctime, ctime, strptime, tzset,
//! timespec_get, timespec_getres.

use std::ffi::{c_char, c_void};

use frankenlibc_abi::time_abi;

// ---------------------------------------------------------------------------
// time
// ---------------------------------------------------------------------------

#[test]
fn time_returns_positive_value() {
    let t = unsafe { time_abi::time(std::ptr::null_mut()) };
    assert!(t > 0, "time() should return positive epoch, got {t}");
}

#[test]
fn time_writes_to_pointer() {
    let mut t: i64 = 0;
    let ret = unsafe { time_abi::time(&mut t) };
    assert!(ret > 0);
    assert_eq!(ret, t, "time() should write same value as returned");
}

// ---------------------------------------------------------------------------
// clock_gettime
// ---------------------------------------------------------------------------

#[test]
fn clock_gettime_realtime() {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { time_abi::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime(CLOCK_REALTIME) should succeed");
    assert!(ts.tv_sec > 0);
    assert!(ts.tv_nsec >= 0 && ts.tv_nsec < 1_000_000_000);
}

#[test]
fn clock_gettime_monotonic() {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { time_abi::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime(CLOCK_MONOTONIC) should succeed");
    assert!(ts.tv_nsec >= 0 && ts.tv_nsec < 1_000_000_000);
}

#[test]
fn clock_gettime_boottime() {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { time_abi::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime(CLOCK_BOOTTIME) should succeed");
    assert!(ts.tv_sec >= 0);
    assert!(ts.tv_nsec >= 0 && ts.tv_nsec < 1_000_000_000);
}

#[test]
fn clock_gettime_monotonic_is_non_decreasing() {
    let mut ts1: libc::timespec = unsafe { std::mem::zeroed() };
    let mut ts2: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe {
        time_abi::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts1);
        time_abi::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts2);
    }
    let t1 = ts1.tv_sec as u64 * 1_000_000_000 + ts1.tv_nsec as u64;
    let t2 = ts2.tv_sec as u64 * 1_000_000_000 + ts2.tv_nsec as u64;
    assert!(t2 >= t1, "CLOCK_MONOTONIC should be non-decreasing");
}

#[test]
fn clock_gettime_rejects_tracked_short_timespec() {
    let required = std::mem::size_of::<libc::timespec>();
    let raw = unsafe { malloc_tracked_zeroed_bytes(required - 1) };
    assert_known_short(raw, required);

    let rc = unsafe { time_abi::clock_gettime(libc::CLOCK_REALTIME, raw.cast()) };

    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::EFAULT);
    unsafe { free_tracked(raw) };
}

// ---------------------------------------------------------------------------
// clock
// ---------------------------------------------------------------------------

#[test]
fn clock_returns_nonnegative() {
    let c = unsafe { time_abi::clock() };
    // clock() returns -1 on error, otherwise processor time in CLOCKS_PER_SEC units
    assert!(c >= 0, "clock() should return non-negative, got {c}");
}

// ---------------------------------------------------------------------------
// gmtime_r / localtime_r
// ---------------------------------------------------------------------------

#[test]
fn gmtime_r_epoch_zero() {
    let epoch: i64 = 0;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe { time_abi::gmtime_r(&epoch, &mut tm) };
    assert!(!result.is_null());
    assert_eq!(tm.tm_year, 70); // 1970 - 1900
    assert_eq!(tm.tm_mon, 0); // January
    assert_eq!(tm.tm_mday, 1);
    assert_eq!(tm.tm_hour, 0);
    assert_eq!(tm.tm_min, 0);
    assert_eq!(tm.tm_sec, 0);
}

#[test]
fn gmtime_r_known_date() {
    // 2024-01-15 12:00:00 UTC = 1705320000
    let epoch: i64 = 1705320000;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe { time_abi::gmtime_r(&epoch, &mut tm) };
    assert!(!result.is_null());
    assert_eq!(tm.tm_year, 124); // 2024 - 1900
    assert_eq!(tm.tm_mon, 0); // January
    assert_eq!(tm.tm_mday, 15);
    assert_eq!(tm.tm_hour, 12);
}

#[test]
fn localtime_r_returns_nonnull() {
    let now = unsafe { time_abi::time(std::ptr::null_mut()) };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe { time_abi::localtime_r(&now, &mut tm) };
    assert!(!result.is_null());
    assert!(tm.tm_year >= 124, "year should be >= 2024");
}

// ---------------------------------------------------------------------------
// mktime / timegm
// ---------------------------------------------------------------------------

#[test]
fn mktime_roundtrips_with_localtime() {
    let now = unsafe { time_abi::time(std::ptr::null_mut()) };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { time_abi::localtime_r(&now, &mut tm) };

    let reconstructed = unsafe { time_abi::mktime(&mut tm) };
    // mktime should return a value close to now (within 1 second)
    assert!(
        (reconstructed - now).abs() <= 1,
        "mktime(localtime(t)) should roundtrip: {now} vs {reconstructed}"
    );
}

#[test]
fn timegm_roundtrips_with_gmtime() {
    let now = unsafe { time_abi::time(std::ptr::null_mut()) };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { time_abi::gmtime_r(&now, &mut tm) };

    let reconstructed = unsafe { time_abi::timegm(&mut tm) };
    assert_eq!(
        now, reconstructed,
        "timegm(gmtime(t)) should roundtrip exactly"
    );
}

#[test]
fn timegm_epoch_zero() {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = 70; // 1970
    tm.tm_mon = 0; // January
    tm.tm_mday = 1;
    let result = unsafe { time_abi::timegm(&mut tm) };
    assert_eq!(result, 0, "timegm(1970-01-01) should be 0");
}

// ---------------------------------------------------------------------------
// difftime
// ---------------------------------------------------------------------------

#[test]
fn difftime_positive() {
    let d = unsafe { time_abi::difftime(100, 50) };
    assert!((d - 50.0).abs() < 0.001);
}

#[test]
fn difftime_negative() {
    let d = unsafe { time_abi::difftime(50, 100) };
    assert!((d - (-50.0)).abs() < 0.001);
}

#[test]
fn difftime_zero() {
    let d = unsafe { time_abi::difftime(42, 42) };
    assert!((d - 0.0).abs() < 0.001);
}

// ---------------------------------------------------------------------------
// gettimeofday
// ---------------------------------------------------------------------------

#[test]
fn gettimeofday_returns_positive() {
    let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
    let rc = unsafe { time_abi::gettimeofday(&mut tv, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    assert!(tv.tv_sec > 0);
    assert!(tv.tv_usec >= 0 && tv.tv_usec < 1_000_000);
}

#[test]
fn gettimeofday_agrees_with_time() {
    let t = unsafe { time_abi::time(std::ptr::null_mut()) };
    let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
    unsafe { time_abi::gettimeofday(&mut tv, std::ptr::null_mut()) };
    // Should agree within 1 second
    assert!((tv.tv_sec - t).abs() <= 1);
}

#[test]
fn gettimeofday_rejects_tracked_short_timeval() {
    let required = std::mem::size_of::<libc::timeval>();
    let raw = unsafe { malloc_tracked_zeroed_bytes(required - 1) };
    assert_known_short(raw, required);

    let rc = unsafe { time_abi::gettimeofday(raw.cast(), std::ptr::null_mut()) };

    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::EFAULT);
    unsafe { free_tracked(raw) };
}

#[test]
fn vdso_fastpath_snapshot_reflects_mapping_presence() {
    let snapshot = time_abi::vdso_fastpath_snapshot();
    assert_eq!(
        snapshot.handle_opened,
        snapshot.clock_gettime_available || snapshot.gettimeofday_available
    );
    if snapshot.handle_opened {
        assert!(snapshot.mapping_present);
    }
}

#[test]
fn vdso_symbol_version_matches_target_arch() {
    let version = time_abi::__frankenlibc_vdso_symbol_version_name();
    #[cfg(target_arch = "x86_64")]
    assert_eq!(version, "LINUX_2.6");
    #[cfg(target_arch = "aarch64")]
    assert_eq!(version, "LINUX_2.6.39");
    #[cfg(target_arch = "riscv64")]
    assert_eq!(version, "LINUX_4.15");
}

#[test]
fn vdso_positive_rc_falls_back_instead_of_synthesizing_negative_errno() {
    assert_eq!(
        time_abi::__frankenlibc_classify_vdso_return(7),
        time_abi::VdsoCallOutcome::FallbackToSyscall
    );
    assert_eq!(
        time_abi::__frankenlibc_classify_vdso_return(-libc::EINVAL),
        time_abi::VdsoCallOutcome::Fail(libc::EINVAL)
    );
    assert_eq!(
        time_abi::__frankenlibc_classify_vdso_return(-libc::ENOSYS),
        time_abi::VdsoCallOutcome::FallbackToSyscall
    );
}

#[test]
fn vdso_classify_zero_is_success() {
    // Happy path: rc == 0 is the only Success outcome per the Linux vDSO
    // contract. Pinning this explicitly guards against a refactor that
    // reshuffles match arms.
    assert_eq!(
        time_abi::__frankenlibc_classify_vdso_return(0),
        time_abi::VdsoCallOutcome::Success
    );
}

#[test]
fn vdso_classify_boundary_positive_and_negative_rc() {
    // rc=1 is the smallest positive non-zero — must route to
    // FallbackToSyscall per the vDSO "positive means not-implemented"
    // convention. rc=i32::MAX exercises the same arm at the other end.
    assert_eq!(
        time_abi::__frankenlibc_classify_vdso_return(1),
        time_abi::VdsoCallOutcome::FallbackToSyscall
    );
    assert_eq!(
        time_abi::__frankenlibc_classify_vdso_return(i32::MAX),
        time_abi::VdsoCallOutcome::FallbackToSyscall
    );

    // rc=-1 is the smallest-magnitude negative (-EPERM) — must surface as
    // Fail(1), not FallbackToSyscall. A regression that collapsed the
    // "negative and not -ENOSYS" guard would flip this into a fallback.
    assert_eq!(
        time_abi::__frankenlibc_classify_vdso_return(-1),
        time_abi::VdsoCallOutcome::Fail(1)
    );
}

#[test]
fn vdso_classify_fail_errno_is_always_positive() {
    // Structural invariant: whenever classify_vdso_return returns
    // Fail(e), e must be strictly positive so it can legally be written
    // to errno. A bug that forgot to negate rc, or that mishandled
    // sign-extension on a future rt_sigreturn-style path, would emit a
    // non-positive errno and violate POSIX.
    for rc in [
        -1,
        -2,
        -libc::EINVAL,
        -libc::EPERM,
        -libc::ENOMEM,
        -libc::EFAULT,
    ] {
        if rc == -libc::ENOSYS {
            continue;
        }
        let observed = time_abi::__frankenlibc_classify_vdso_return(rc);
        assert!(
            matches!(observed, time_abi::VdsoCallOutcome::Fail(e) if e > 0),
            "rc={rc} expected Fail(e) with positive errno, got {observed:?}"
        );
    }
}

#[test]
fn clock_gettime_uses_vdso_fastpath_when_available() {
    let before = time_abi::vdso_fastpath_snapshot();
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { time_abi::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    assert_eq!(rc, 0);

    let after = time_abi::vdso_fastpath_snapshot();
    if before.clock_gettime_available {
        assert!(
            after.clock_gettime_hits > before.clock_gettime_hits,
            "clock_gettime should record a vDSO hit when the fastpath is available"
        );
    }
}

#[test]
fn gettimeofday_uses_vdso_fastpath_when_available() {
    let before = time_abi::vdso_fastpath_snapshot();
    let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
    let rc = unsafe { time_abi::gettimeofday(&mut tv, std::ptr::null_mut()) };
    assert_eq!(rc, 0);

    let after = time_abi::vdso_fastpath_snapshot();
    if before.gettimeofday_available {
        assert!(
            after.gettimeofday_hits > before.gettimeofday_hits,
            "gettimeofday should record a vDSO hit when the fastpath is available"
        );
    }
}

// ---------------------------------------------------------------------------
// vDSO fastpath parity + fallback coverage (bd-j946)
//
// The existing vdso_*_uses_vdso_fastpath_when_available tests confirm the
// fastpath is *invoked* but never verify it *agrees* with the syscall. These
// tests close that gap using raw_syscall::sys_clock_gettime as the
// ground-truth reference and exercise the unsupported-clock fallback path.
// ---------------------------------------------------------------------------

#[inline]
fn timespec_to_nanos(ts: libc::timespec) -> i128 {
    i128::from(ts.tv_sec) * 1_000_000_000 + i128::from(ts.tv_nsec)
}

#[test]
fn clock_realtime_vdso_agrees_with_raw_syscall() {
    use frankenlibc_core::syscall as raw_syscall;

    let mut syscall_before: libc::timespec = unsafe { std::mem::zeroed() };
    let mut vdso_mid: libc::timespec = unsafe { std::mem::zeroed() };
    let mut syscall_after: libc::timespec = unsafe { std::mem::zeroed() };

    // Bracket the vDSO-preferring call between two raw-syscall samples.
    // The vDSO-backed value must lie within the bracket (monotonic kernel
    // timekeeper guarantees a single source of truth across paths).
    unsafe {
        raw_syscall::sys_clock_gettime(
            libc::CLOCK_REALTIME,
            (&mut syscall_before as *mut libc::timespec).cast::<u8>(),
        )
        .expect("raw syscall before");
        time_abi::clock_gettime(libc::CLOCK_REALTIME, &mut vdso_mid);
        raw_syscall::sys_clock_gettime(
            libc::CLOCK_REALTIME,
            (&mut syscall_after as *mut libc::timespec).cast::<u8>(),
        )
        .expect("raw syscall after");
    }

    let before_ns = timespec_to_nanos(syscall_before);
    let mid_ns = timespec_to_nanos(vdso_mid);
    let after_ns = timespec_to_nanos(syscall_after);

    // CLOCK_REALTIME can step under NTP adjustment; allow 50ms slack.
    let slack_ns = 50_000_000_i128;
    assert!(
        mid_ns >= before_ns - slack_ns && mid_ns <= after_ns + slack_ns,
        "vDSO CLOCK_REALTIME diverged from syscall: mid={mid_ns}ns outside [{before_ns}, {after_ns}]ns + {slack_ns}ns slack"
    );
}

#[test]
fn clock_monotonic_vdso_agrees_with_raw_syscall() {
    use frankenlibc_core::syscall as raw_syscall;

    let mut syscall_before: libc::timespec = unsafe { std::mem::zeroed() };
    let mut vdso_mid: libc::timespec = unsafe { std::mem::zeroed() };
    let mut syscall_after: libc::timespec = unsafe { std::mem::zeroed() };

    unsafe {
        raw_syscall::sys_clock_gettime(
            libc::CLOCK_MONOTONIC,
            (&mut syscall_before as *mut libc::timespec).cast::<u8>(),
        )
        .expect("raw syscall before");
        time_abi::clock_gettime(libc::CLOCK_MONOTONIC, &mut vdso_mid);
        raw_syscall::sys_clock_gettime(
            libc::CLOCK_MONOTONIC,
            (&mut syscall_after as *mut libc::timespec).cast::<u8>(),
        )
        .expect("raw syscall after");
    }

    let before_ns = timespec_to_nanos(syscall_before);
    let mid_ns = timespec_to_nanos(vdso_mid);
    let after_ns = timespec_to_nanos(syscall_after);

    // CLOCK_MONOTONIC never steps back — the bracket must be exact.
    assert!(
        mid_ns >= before_ns,
        "vDSO CLOCK_MONOTONIC went backward relative to syscall: mid={mid_ns} < before={before_ns}"
    );
    assert!(
        mid_ns <= after_ns,
        "vDSO CLOCK_MONOTONIC ran ahead of syscall: mid={mid_ns} > after={after_ns}"
    );
}

// ---------------------------------------------------------------------------
// clock_getres
// ---------------------------------------------------------------------------

#[test]
fn clock_getres_realtime() {
    let mut res: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { time_abi::clock_getres(libc::CLOCK_REALTIME, &mut res) };
    assert_eq!(rc, 0, "clock_getres(CLOCK_REALTIME) should succeed");
    // Resolution should be positive and <= 1 second
    assert!(res.tv_sec == 0 || (res.tv_sec == 1 && res.tv_nsec == 0));
    assert!(res.tv_nsec >= 0);
}

#[test]
fn clock_getres_allows_null_res() {
    let rc = unsafe { time_abi::clock_getres(libc::CLOCK_REALTIME, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "clock_getres(CLOCK_REALTIME, NULL) should succeed");
}

#[test]
fn clock_getres_rejects_tracked_short_timespec() {
    let required = std::mem::size_of::<libc::timespec>();
    let raw = unsafe { malloc_tracked_zeroed_bytes(required - 1) };
    assert_known_short(raw, required);

    let rc = unsafe { time_abi::clock_getres(libc::CLOCK_REALTIME, raw.cast()) };

    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::EFAULT);
    unsafe { free_tracked(raw) };
}

// ---------------------------------------------------------------------------
// nanosleep
// ---------------------------------------------------------------------------

#[test]
fn nanosleep_short_sleep() {
    let req = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000, // 1ms
    };
    let mut rem: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { time_abi::nanosleep(&req, &mut rem) };
    assert_eq!(rc, 0, "nanosleep(1ms) should succeed");
}

#[test]
fn nanosleep_rejects_tracked_short_req() {
    let required = std::mem::size_of::<libc::timespec>();
    let raw = unsafe { malloc_tracked_zeroed_bytes(required - 1) };
    assert_known_short(raw, required);

    let rc = unsafe { time_abi::nanosleep(raw.cast(), std::ptr::null_mut()) };

    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::EFAULT);
    unsafe { free_tracked(raw) };
}

#[test]
fn nanosleep_rejects_tracked_short_rem() {
    let req = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let required = std::mem::size_of::<libc::timespec>();
    let raw = unsafe { malloc_tracked_zeroed_bytes(required - 1) };
    assert_known_short(raw, required);

    let rc = unsafe { time_abi::nanosleep(&req, raw.cast()) };

    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::EFAULT);
    unsafe { free_tracked(raw) };
}

// ---------------------------------------------------------------------------
// asctime_r / ctime_r
// ---------------------------------------------------------------------------

#[test]
fn asctime_r_formats_epoch() {
    let epoch: i64 = 0;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { time_abi::gmtime_r(&epoch, &mut tm) };

    let mut buf = [0u8; 26];
    let result = unsafe { time_abi::asctime_r(&tm, buf.as_mut_ptr() as *mut c_char) };
    assert!(!result.is_null());
    let s = unsafe { std::ffi::CStr::from_ptr(result) };
    let text = s.to_str().unwrap();
    assert!(
        text.contains("1970"),
        "asctime_r should show 1970, got: {text}"
    );
    assert!(
        text.contains("Jan"),
        "asctime_r should show Jan, got: {text}"
    );
}

#[test]
fn ctime_r_formats_current_time() {
    let now = unsafe { time_abi::time(std::ptr::null_mut()) };
    let mut buf = [0u8; 26];
    let result = unsafe { time_abi::ctime_r(&now, buf.as_mut_ptr() as *mut c_char) };
    assert!(!result.is_null());
    let s = unsafe { std::ffi::CStr::from_ptr(result) };
    let text = s.to_str().unwrap();
    assert!(
        text.contains("202"),
        "ctime_r should contain 202x year, got: {text}"
    );
}

#[test]
fn asctime_r_rejects_tracked_short_tm() {
    unsafe {
        let raw_tm = malloc_tracked_bytes(4).cast::<libc::tm>();
        let mut buf = [0x55_u8; 26];

        let result = time_abi::asctime_r(raw_tm, buf.as_mut_ptr().cast::<c_char>());

        assert!(result.is_null());
        assert_eq!(buf, [0x55_u8; 26]);
        frankenlibc_abi::malloc_abi::free(raw_tm.cast());
    }
}

#[test]
fn asctime_r_rejects_tracked_short_output_buffer() {
    unsafe {
        let epoch: i64 = 0;
        let mut tm: libc::tm = std::mem::zeroed();
        time_abi::gmtime_r(&epoch, &mut tm);
        let raw_buf = malloc_tracked_bytes(8);

        let result = time_abi::asctime_r(&tm, raw_buf);

        assert!(result.is_null());
        let observed = std::slice::from_raw_parts(raw_buf.cast::<u8>(), 8);
        assert_eq!(observed, [0x55_u8; 8]);
        frankenlibc_abi::malloc_abi::free(raw_buf.cast());
    }
}

#[test]
fn ctime_r_rejects_tracked_short_timer() {
    unsafe {
        let raw_timer = malloc_tracked_bytes(4).cast::<i64>();
        let mut buf = [0x55_u8; 26];

        let result = time_abi::ctime_r(raw_timer, buf.as_mut_ptr().cast::<c_char>());

        assert!(result.is_null());
        assert_eq!(buf, [0x55_u8; 26]);
        frankenlibc_abi::malloc_abi::free(raw_timer.cast());
    }
}

#[test]
fn ctime_r_rejects_tracked_short_output_buffer() {
    unsafe {
        let now = time_abi::time(std::ptr::null_mut());
        let raw_buf = malloc_tracked_bytes(8);

        let result = time_abi::ctime_r(&now, raw_buf);

        assert!(result.is_null());
        let observed = std::slice::from_raw_parts(raw_buf.cast::<u8>(), 8);
        assert_eq!(observed, [0x55_u8; 8]);
        frankenlibc_abi::malloc_abi::free(raw_buf.cast());
    }
}

// ---------------------------------------------------------------------------
// strftime
// ---------------------------------------------------------------------------

#[test]
fn strftime_iso_date() {
    let epoch: i64 = 0;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { time_abi::gmtime_r(&epoch, &mut tm) };

    let mut buf = [0u8; 64];
    let fmt = b"%Y-%m-%d\0";
    let len = unsafe {
        time_abi::strftime(
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            fmt.as_ptr() as *const c_char,
            &tm,
        )
    };
    assert!(len > 0);
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const c_char) };
    assert_eq!(s.to_bytes(), b"1970-01-01");
}

#[test]
fn strftime_time() {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_hour = 14;
    tm.tm_min = 30;
    tm.tm_sec = 45;

    let mut buf = [0u8; 64];
    let fmt = b"%H:%M:%S\0";
    let len = unsafe {
        time_abi::strftime(
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            fmt.as_ptr() as *const c_char,
            &tm,
        )
    };
    assert!(len > 0);
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const c_char) };
    assert_eq!(s.to_bytes(), b"14:30:45");
}

unsafe fn malloc_unterminated(bytes: &[u8]) -> *mut c_char {
    let raw = unsafe { frankenlibc_abi::malloc_abi::malloc(bytes.len()) }.cast::<u8>();
    assert!(!raw.is_null());
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), raw, bytes.len()) };
    raw.cast()
}

unsafe fn malloc_tracked_bytes(len: usize) -> *mut c_char {
    let raw = unsafe { frankenlibc_abi::malloc_abi::malloc(len) }.cast::<u8>();
    assert!(!raw.is_null());
    unsafe { std::ptr::write_bytes(raw, 0x55, len) };
    raw.cast()
}

unsafe fn malloc_tracked_zeroed_bytes(len: usize) -> *mut c_void {
    let raw = unsafe { frankenlibc_abi::malloc_abi::malloc(len) }.cast::<u8>();
    assert!(!raw.is_null());
    unsafe { std::ptr::write_bytes(raw, 0, len) };
    raw.cast()
}

fn assert_known_short(raw: *const c_void, required: usize) {
    let remaining =
        frankenlibc_abi::malloc_abi::malloc_known_remaining_for_tests(raw).unwrap_or(usize::MAX);
    assert_ne!(
        remaining,
        usize::MAX,
        "test allocation should be tracked by malloc metadata"
    );
    assert!(
        remaining < required,
        "test allocation should expose {remaining} tracked bytes, less than required {required}"
    );
}

fn errno_value() -> i32 {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
}

unsafe fn free_tracked(raw: *mut c_void) {
    unsafe { frankenlibc_abi::malloc_abi::free(raw) };
}

#[test]
fn strftime_rejects_tracked_unterminated_format() {
    unsafe {
        let raw_fmt = malloc_unterminated(b"%Y");
        let epoch: i64 = 0;
        let mut tm: libc::tm = std::mem::zeroed();
        time_abi::gmtime_r(&epoch, &mut tm);
        let mut buf = [0x55_u8; 16];

        let len = time_abi::strftime(buf.as_mut_ptr().cast::<c_char>(), buf.len(), raw_fmt, &tm);

        assert_eq!(len, 0);
        assert_eq!(buf, [0x55_u8; 16]);
        frankenlibc_abi::malloc_abi::free(raw_fmt.cast());
    }
}

// ---------------------------------------------------------------------------
// gmtime / localtime (non-reentrant)
// ---------------------------------------------------------------------------

#[test]
fn gmtime_returns_nonnull() {
    let now = unsafe { time_abi::time(std::ptr::null_mut()) };
    let result = unsafe { time_abi::gmtime(&now) };
    assert!(!result.is_null());
    let tm = unsafe { &*result };
    assert!(tm.tm_year >= 124); // >= 2024
}

#[test]
fn localtime_returns_nonnull() {
    let now = unsafe { time_abi::time(std::ptr::null_mut()) };
    let result = unsafe { time_abi::localtime(&now) };
    assert!(!result.is_null());
    let tm = unsafe { &*result };
    assert!(tm.tm_year >= 124);
}

// ---------------------------------------------------------------------------
// asctime / ctime (non-reentrant)
// ---------------------------------------------------------------------------

#[test]
fn asctime_returns_nonnull() {
    let epoch: i64 = 0;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { time_abi::gmtime_r(&epoch, &mut tm) };
    let result = unsafe { time_abi::asctime(&tm) };
    assert!(!result.is_null());
}

#[test]
fn ctime_returns_nonnull() {
    let now = unsafe { time_abi::time(std::ptr::null_mut()) };
    let result = unsafe { time_abi::ctime(&now) };
    assert!(!result.is_null());
}

// ---------------------------------------------------------------------------
// strptime tests (original)
// ---------------------------------------------------------------------------

#[test]
fn strptime_iso_date() {
    let input = b"2026-02-25\0";
    let fmt = b"%Y-%m-%d\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        time_abi::strptime(
            input.as_ptr() as *const c_char,
            fmt.as_ptr() as *const c_char,
            &mut tm,
        )
    };
    assert!(!result.is_null());
    assert_eq!(tm.tm_year, 126); // 2026 - 1900
    assert_eq!(tm.tm_mon, 1); // February (0-indexed)
    assert_eq!(tm.tm_mday, 25);
}

#[test]
fn strptime_time_24h() {
    let input = b"14:30:45\0";
    let fmt = b"%H:%M:%S\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        time_abi::strptime(
            input.as_ptr() as *const c_char,
            fmt.as_ptr() as *const c_char,
            &mut tm,
        )
    };
    assert!(!result.is_null());
    assert_eq!(tm.tm_hour, 14);
    assert_eq!(tm.tm_min, 30);
    assert_eq!(tm.tm_sec, 45);
}

#[test]
fn strptime_month_name() {
    let input = b"Jan 15\0";
    let fmt = b"%b %d\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        time_abi::strptime(
            input.as_ptr() as *const c_char,
            fmt.as_ptr() as *const c_char,
            &mut tm,
        )
    };
    assert!(!result.is_null());
    assert_eq!(tm.tm_mon, 0); // January
    assert_eq!(tm.tm_mday, 15);
}

#[test]
fn strptime_composite_t() {
    let input = b"09:15:30\0";
    let fmt = b"%T\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        time_abi::strptime(
            input.as_ptr() as *const c_char,
            fmt.as_ptr() as *const c_char,
            &mut tm,
        )
    };
    assert!(!result.is_null());
    assert_eq!(tm.tm_hour, 9);
    assert_eq!(tm.tm_min, 15);
    assert_eq!(tm.tm_sec, 30);
}

#[test]
fn strptime_am_pm() {
    let input = b"03:30 PM\0";
    let fmt = b"%I:%M %p\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        time_abi::strptime(
            input.as_ptr() as *const c_char,
            fmt.as_ptr() as *const c_char,
            &mut tm,
        )
    };
    assert!(!result.is_null());
    assert_eq!(tm.tm_hour, 15); // 3 PM = 15
    assert_eq!(tm.tm_min, 30);
}

#[test]
fn strptime_returns_null_on_mismatch() {
    let input = b"not-a-date\0";
    let fmt = b"%Y-%m-%d\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        time_abi::strptime(
            input.as_ptr() as *const c_char,
            fmt.as_ptr() as *const c_char,
            &mut tm,
        )
    };
    assert!(result.is_null());
}

#[test]
fn strptime_returns_position_after_parsed() {
    let input = b"2026-01-01 remaining\0";
    let fmt = b"%Y-%m-%d\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        time_abi::strptime(
            input.as_ptr() as *const c_char,
            fmt.as_ptr() as *const c_char,
            &mut tm,
        )
    };
    assert!(!result.is_null());
    let offset = unsafe { result.offset_from(input.as_ptr() as *const c_char) } as usize;
    assert_eq!(offset, 10); // "2026-01-01" = 10 chars
}

#[test]
fn strptime_rejects_tracked_unterminated_input() {
    unsafe {
        let raw_input = malloc_unterminated(b"2026");
        let fmt = b"%Y\0";
        let mut tm: libc::tm = std::mem::zeroed();

        let result = time_abi::strptime(raw_input, fmt.as_ptr().cast::<c_char>(), &mut tm);

        frankenlibc_abi::malloc_abi::free(raw_input.cast());
        assert!(result.is_null());
        assert_eq!(tm.tm_year, 0);
    }
}

#[test]
fn strptime_rejects_tracked_unterminated_format() {
    unsafe {
        let input = b"2026\0";
        let raw_fmt = malloc_unterminated(b"%Y");
        let mut tm: libc::tm = std::mem::zeroed();

        let result = time_abi::strptime(input.as_ptr().cast::<c_char>(), raw_fmt, &mut tm);

        frankenlibc_abi::malloc_abi::free(raw_fmt.cast());
        assert!(result.is_null());
        assert_eq!(tm.tm_year, 0);
    }
}

#[test]
fn strptime_weekday_name() {
    let input = b"Monday\0";
    let fmt = b"%A\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        time_abi::strptime(
            input.as_ptr() as *const c_char,
            fmt.as_ptr() as *const c_char,
            &mut tm,
        )
    };
    assert!(!result.is_null());
    assert_eq!(tm.tm_wday, 1); // Monday
}

// ---------------------------------------------------------------------------
// tzset
// ---------------------------------------------------------------------------

#[test]
fn tzset_does_not_crash() {
    // tzset just sets timezone globals; verify it doesn't crash
    unsafe { time_abi::tzset() };
}

// ---------------------------------------------------------------------------
// timespec_get / timespec_getres (C11)
// ---------------------------------------------------------------------------

#[test]
fn timespec_get_time_utc() {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // TIME_UTC = 1 in C11
    let rc = unsafe { time_abi::timespec_get(&mut ts, 1) };
    assert_eq!(rc, 1, "timespec_get with TIME_UTC should return TIME_UTC");
    assert!(ts.tv_sec > 0);
    assert!(ts.tv_nsec >= 0 && ts.tv_nsec < 1_000_000_000);
}

#[test]
fn timespec_get_rejects_tracked_short_timespec() {
    let required = std::mem::size_of::<libc::timespec>();
    let raw = unsafe { malloc_tracked_zeroed_bytes(required - 1) };
    assert_known_short(raw, required);

    let rc = unsafe { time_abi::timespec_get(raw.cast(), 1) };

    assert_eq!(rc, 0);
    unsafe { free_tracked(raw) };
}

#[test]
fn timespec_getres_time_utc() {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { time_abi::timespec_getres(&mut ts, 1) };
    assert_eq!(
        rc, 1,
        "timespec_getres with TIME_UTC should return TIME_UTC"
    );
    assert!(ts.tv_nsec >= 0);
}

#[test]
fn timespec_getres_allows_null_ts() {
    let rc = unsafe { time_abi::timespec_getres(std::ptr::null_mut(), 1) };
    assert_eq!(rc, 1);
}

#[test]
fn timespec_getres_rejects_tracked_short_timespec() {
    let required = std::mem::size_of::<libc::timespec>();
    let raw = unsafe { malloc_tracked_zeroed_bytes(required - 1) };
    assert_known_short(raw, required);

    let rc = unsafe { time_abi::timespec_getres(raw.cast(), 1) };

    assert_eq!(rc, 0);
    unsafe { free_tracked(raw) };
}

// ---------------------------------------------------------------------------
// __clock_settime / __clock_nanosleep (glibc reserved aliases)
// ---------------------------------------------------------------------------

#[test]
fn under_clock_nanosleep_zero_time_returns_zero() {
    let req = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe {
        time_abi::__clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &req, std::ptr::null_mut())
    };
    assert_eq!(rc, 0);
}

#[test]
fn under_clock_nanosleep_rejects_tracked_short_req() {
    let required = std::mem::size_of::<libc::timespec>();
    let raw = unsafe { malloc_tracked_zeroed_bytes(required - 1) };
    assert_known_short(raw, required);

    let rc = unsafe {
        time_abi::__clock_nanosleep(libc::CLOCK_MONOTONIC, 0, raw.cast(), std::ptr::null_mut())
    };

    assert_eq!(rc, libc::EFAULT);
    unsafe { free_tracked(raw) };
}

#[test]
fn under_clock_nanosleep_rejects_tracked_short_rem() {
    let req = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let required = std::mem::size_of::<libc::timespec>();
    let raw = unsafe { malloc_tracked_zeroed_bytes(required - 1) };
    assert_known_short(raw, required);

    let rc = unsafe { time_abi::__clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &req, raw.cast()) };

    assert_eq!(rc, libc::EFAULT);
    unsafe { free_tracked(raw) };
}

#[test]
fn under_clock_settime_invalid_clock_fails() {
    // Setting CLOCK_MONOTONIC is not allowed → __clock_settime returns -1.
    let ts = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let rc = unsafe { time_abi::__clock_settime(libc::CLOCK_MONOTONIC, &ts) };
    assert_eq!(rc, -1);
}

#[test]
fn under_clock_settime_rejects_tracked_short_timespec() {
    let required = std::mem::size_of::<libc::timespec>();
    let raw = unsafe { malloc_tracked_zeroed_bytes(required - 1) };
    assert_known_short(raw, required);

    let rc = unsafe { time_abi::__clock_settime(libc::CLOCK_REALTIME, raw.cast()) };

    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::EFAULT);
    unsafe { free_tracked(raw) };
}
