//! ABI layer for `<time.h>` functions.
//!
//! Syscalls (`clock_gettime`, etc.) are invoked via `libc`. Pure arithmetic
//! (broken-down conversion) delegates to `frankenlibc_core::time`.

use std::ffi::c_int;
use std::os::raw::c_long;

use frankenlibc_core::errno;
use frankenlibc_core::time as time_core;

/// Set the ABI errno via `__errno_location`.
#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

#[inline]
unsafe fn raw_clock_gettime(clock_id: c_int, tp: *mut libc::timespec) -> c_int {
    unsafe { libc::syscall(libc::SYS_clock_gettime as c_long, clock_id, tp) as c_int }
}

// ---------------------------------------------------------------------------
// time
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn time(tloc: *mut i64) -> i64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { raw_clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if rc != 0 {
        return -1;
    }
    let secs = ts.tv_sec as i64;
    if !tloc.is_null() {
        unsafe { *tloc = secs };
    }
    secs
}

// ---------------------------------------------------------------------------
// clock_gettime
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clock_gettime(clock_id: c_int, tp: *mut libc::timespec) -> c_int {
    if tp.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    if !time_core::valid_clock_id(clock_id) {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    let rc = unsafe { raw_clock_gettime(clock_id, tp) };
    if rc != 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
    }
    rc
}

// ---------------------------------------------------------------------------
// clock
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clock() -> i64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { raw_clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return -1;
    }
    ts.tv_sec as i64 * time_core::CLOCKS_PER_SEC
        + ts.tv_nsec as i64 / (1_000_000_000 / time_core::CLOCKS_PER_SEC)
}

// ---------------------------------------------------------------------------
// localtime_r
// ---------------------------------------------------------------------------

/// POSIX `localtime_r` — converts epoch seconds to broken-down UTC time.
///
/// Writes the result into `result` and returns a pointer to it on success.
/// Returns null on failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn localtime_r(timer: *const i64, result: *mut libc::tm) -> *mut libc::tm {
    if timer.is_null() || result.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
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

    result
}
