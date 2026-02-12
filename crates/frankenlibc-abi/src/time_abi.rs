//! ABI layer for `<time.h>` functions.
//!
//! Syscalls (`clock_gettime`, etc.) are invoked via `libc`. Pure arithmetic
//! (broken-down conversion) delegates to `frankenlibc_core::time`.

use std::ffi::c_int;

use frankenlibc_core::errno;
use frankenlibc_core::time as time_core;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

/// Set the ABI errno via `__errno_location`.
#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

// ---------------------------------------------------------------------------
// time
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn time(tloc: *mut i64) -> i64 {
    let (_, decision) = runtime_policy::decide(ApiFamily::Time, 0, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
        return -1;
    }

    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if rc != 0 {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 10, true);
        return -1;
    }
    let secs = ts.tv_sec as i64;
    if !tloc.is_null() {
        unsafe { *tloc = secs };
    }
    runtime_policy::observe(ApiFamily::Time, decision.profile, 10, false);
    secs
}

// ---------------------------------------------------------------------------
// clock_gettime
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_gettime(clock_id: c_int, tp: *mut libc::timespec) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Time, clock_id as usize, 0, false, true, 0);

    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
        return -1;
    }

    if tp.is_null() {
        if mode.heals_enabled() {
            runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
            return -1;
        }
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
        return -1;
    }

    let cid = if !time_core::valid_clock_id(clock_id) {
        if mode.heals_enabled() {
            libc::CLOCK_REALTIME
        } else {
            unsafe { set_abi_errno(errno::EINVAL) };
            runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
            return -1;
        }
    } else {
        clock_id
    };

    let rc = unsafe { libc::clock_gettime(cid, tp) };
    let adverse = rc != 0;
    if adverse {
        unsafe { set_abi_errno(errno::EINVAL) };
    }
    runtime_policy::observe(ApiFamily::Time, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// clock
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock() -> i64 {
    let (_, decision) = runtime_policy::decide(ApiFamily::Time, 0, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
        return -1;
    }

    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 10, true);
        return -1;
    }
    let ticks = ts.tv_sec as i64 * time_core::CLOCKS_PER_SEC
        + ts.tv_nsec as i64 / (1_000_000_000 / time_core::CLOCKS_PER_SEC);
    runtime_policy::observe(ApiFamily::Time, decision.profile, 10, false);
    ticks
}

// ---------------------------------------------------------------------------
// localtime_r
// ---------------------------------------------------------------------------

/// POSIX `localtime_r` — converts epoch seconds to broken-down UTC time.
///
/// Writes the result into `result` and returns a pointer to it on success.
/// Returns null on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn localtime_r(timer: *const i64, result: *mut libc::tm) -> *mut libc::tm {
    let (mode, decision) = runtime_policy::decide(ApiFamily::Time, 0, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    if timer.is_null() || result.is_null() {
        if mode.heals_enabled() {
            runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
            return std::ptr::null_mut();
        }
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    let epoch = unsafe { *timer };
    let bd = time_core::epoch_to_broken_down(epoch);

    unsafe {
        (*result).tm_sec = bd.tm_sec;
        (*result).tm_min = bd.tm_min;
        (*result).tm_hour = bd.tm_hour;
        (*result).tm_mday = bd.tm_mday;
        (*result).tm_mon = bd.tm_mon;
        (*result).tm_year = bd.tm_year;
        (*result).tm_wday = bd.tm_wday;
        (*result).tm_yday = bd.tm_yday;
        (*result).tm_isdst = bd.tm_isdst;
    }

    runtime_policy::observe(ApiFamily::Time, decision.profile, 15, false);
    result
}
