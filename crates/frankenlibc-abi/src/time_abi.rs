//! ABI layer for `<time.h>` functions.
//!
//! Syscalls (`clock_gettime`, etc.) are invoked via `libc`. Pure arithmetic
//! (broken-down conversion) delegates to `frankenlibc_core::time`.

use std::ffi::{c_int, c_void};
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

/// Fill a `libc::tm` from a `BrokenDownTime`.
#[inline]
unsafe fn write_tm(result: *mut libc::tm, bd: &time_core::BrokenDownTime) {
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
}

/// Read a `BrokenDownTime` from a `libc::tm`.
#[inline]
unsafe fn read_tm(tm: *const libc::tm) -> time_core::BrokenDownTime {
    unsafe {
        time_core::BrokenDownTime {
            tm_sec: (*tm).tm_sec,
            tm_min: (*tm).tm_min,
            tm_hour: (*tm).tm_hour,
            tm_mday: (*tm).tm_mday,
            tm_mon: (*tm).tm_mon,
            tm_year: (*tm).tm_year,
            tm_wday: (*tm).tm_wday,
            tm_yday: (*tm).tm_yday,
            tm_isdst: (*tm).tm_isdst,
        }
    }
}

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
    unsafe { write_tm(result, &bd) };
    result
}

// ---------------------------------------------------------------------------
// gmtime_r
// ---------------------------------------------------------------------------

/// POSIX `gmtime_r` — converts epoch seconds to broken-down UTC time.
///
/// Identical to `localtime_r` since we only support UTC.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gmtime_r(timer: *const i64, result: *mut libc::tm) -> *mut libc::tm {
    if timer.is_null() || result.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return std::ptr::null_mut();
    }

    let epoch = unsafe { *timer };
    let bd = time_core::epoch_to_broken_down(epoch);
    unsafe { write_tm(result, &bd) };
    result
}

// ---------------------------------------------------------------------------
// mktime
// ---------------------------------------------------------------------------

/// POSIX `mktime` — converts broken-down local time to epoch seconds.
///
/// Since we only support UTC, this is equivalent to `timegm`.
/// Normalizes the `tm` structure fields and fills in `tm_wday` and `tm_yday`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mktime(tm: *mut libc::tm) -> i64 {
    if tm.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    let bd = unsafe { read_tm(tm) };
    let epoch = time_core::broken_down_to_epoch(&bd);

    // Normalize: re-derive the full broken-down time and write back.
    let normalized = time_core::epoch_to_broken_down(epoch);
    unsafe { write_tm(tm, &normalized) };
    epoch
}

// ---------------------------------------------------------------------------
// timegm
// ---------------------------------------------------------------------------

/// `timegm` — converts broken-down UTC time to epoch seconds.
///
/// Non-standard but widely available (glibc, musl, BSDs).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timegm(tm: *mut libc::tm) -> i64 {
    unsafe { mktime(tm) }
}

// ---------------------------------------------------------------------------
// difftime
// ---------------------------------------------------------------------------

/// POSIX `difftime` — returns the difference between two `time_t` values.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn difftime(time1: i64, time0: i64) -> f64 {
    time_core::difftime(time1, time0)
}

// ---------------------------------------------------------------------------
// gettimeofday
// ---------------------------------------------------------------------------

/// POSIX `gettimeofday` — get time of day as seconds + microseconds.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gettimeofday(tv: *mut libc::timeval, tz: *mut c_void) -> c_int {
    let _ = tz; // tz is obsolete and ignored
    if tv.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { raw_clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if rc != 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    unsafe {
        (*tv).tv_sec = ts.tv_sec;
        (*tv).tv_usec = ts.tv_nsec / 1000;
    }
    0
}

// ---------------------------------------------------------------------------
// clock_getres
// ---------------------------------------------------------------------------

/// POSIX `clock_getres` — get the resolution of a clock.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clock_getres(clock_id: c_int, res: *mut libc::timespec) -> c_int {
    if !time_core::valid_clock_id(clock_id) && !time_core::valid_clock_id_extended(clock_id) {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_clock_getres as c_long, clock_id, res) as c_int };
    if rc != 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
    }
    rc
}

// ---------------------------------------------------------------------------
// nanosleep
// ---------------------------------------------------------------------------

/// POSIX `nanosleep` — high-resolution sleep.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nanosleep(req: *const libc::timespec, rem: *mut libc::timespec) -> c_int {
    if req.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_nanosleep as c_long, req, rem) as c_int };
    if rc != 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(errno::EINTR),
            )
        };
    }
    rc
}

// ---------------------------------------------------------------------------
// clock_nanosleep
// ---------------------------------------------------------------------------

/// POSIX `clock_nanosleep` — high-resolution sleep with specified clock.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clock_nanosleep(
    clock_id: c_int,
    flags: c_int,
    req: *const libc::timespec,
    rem: *mut libc::timespec,
) -> c_int {
    if req.is_null() {
        return errno::EFAULT;
    }

    if !time_core::valid_clock_id(clock_id) && !time_core::valid_clock_id_extended(clock_id) {
        return errno::EINVAL;
    }

    let rc = unsafe {
        libc::syscall(
            libc::SYS_clock_nanosleep as c_long,
            clock_id,
            flags,
            req,
            rem,
        ) as c_int
    };
    // clock_nanosleep returns the error number directly (not via errno).
    rc
}

// ---------------------------------------------------------------------------
// asctime_r
// ---------------------------------------------------------------------------

/// POSIX `asctime_r` — convert broken-down time to string.
///
/// Writes "Day Mon DD HH:MM:SS YYYY\n\0" into `buf` (must be >= 26 bytes).
/// Returns `buf` on success, null on failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asctime_r(
    tm: *const libc::tm,
    buf: *mut std::ffi::c_char,
) -> *mut std::ffi::c_char {
    if tm.is_null() || buf.is_null() {
        return std::ptr::null_mut();
    }

    let bd = unsafe { read_tm(tm) };
    let dst = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, 26) };
    let n = time_core::format_asctime(&bd, dst);
    if n == 0 {
        return std::ptr::null_mut();
    }
    buf
}

// ---------------------------------------------------------------------------
// ctime_r
// ---------------------------------------------------------------------------

/// POSIX `ctime_r` — convert epoch seconds to string.
///
/// Equivalent to `asctime_r(localtime_r(timer, &tmp), buf)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctime_r(
    timer: *const i64,
    buf: *mut std::ffi::c_char,
) -> *mut std::ffi::c_char {
    if timer.is_null() || buf.is_null() {
        return std::ptr::null_mut();
    }

    let epoch = unsafe { *timer };
    let bd = time_core::epoch_to_broken_down(epoch);
    let dst = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, 26) };
    let n = time_core::format_asctime(&bd, dst);
    if n == 0 {
        return std::ptr::null_mut();
    }
    buf
}

// ---------------------------------------------------------------------------
// strftime
// ---------------------------------------------------------------------------

/// POSIX `strftime` — format broken-down time into a string.
///
/// Writes at most `maxsize` bytes (including the NUL terminator) into `s`.
/// Returns the number of bytes written (excluding NUL), or 0 if the result
/// would exceed `maxsize`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strftime(
    s: *mut std::ffi::c_char,
    maxsize: usize,
    format: *const std::ffi::c_char,
    tm: *const libc::tm,
) -> usize {
    if s.is_null() || format.is_null() || tm.is_null() || maxsize == 0 {
        return 0;
    }

    // Read the format string as a byte slice.
    let fmt_len = unsafe { libc::strlen(format as *const _) };
    let fmt = unsafe { std::slice::from_raw_parts(format as *const u8, fmt_len) };

    // Read the broken-down time.
    let bd = unsafe { read_tm(tm) };

    // Format into the output buffer.
    let buf = unsafe { std::slice::from_raw_parts_mut(s as *mut u8, maxsize) };
    time_core::format_strftime(fmt, &bd, buf)
}

// ---------------------------------------------------------------------------
// Non-reentrant time wrappers (use thread-local static buffers)
// ---------------------------------------------------------------------------

std::thread_local! {
    static GMTIME_BUF: std::cell::UnsafeCell<libc::tm> = const { std::cell::UnsafeCell::new(unsafe { std::mem::zeroed() }) };
    static LOCALTIME_BUF: std::cell::UnsafeCell<libc::tm> = const { std::cell::UnsafeCell::new(unsafe { std::mem::zeroed() }) };
    static ASCTIME_BUF: std::cell::UnsafeCell<[u8; 26]> = const { std::cell::UnsafeCell::new([0u8; 26]) };
    static CTIME_BUF: std::cell::UnsafeCell<[u8; 26]> = const { std::cell::UnsafeCell::new([0u8; 26]) };
}

/// POSIX `gmtime` — convert time_t to broken-down UTC time (non-reentrant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gmtime(timer: *const i64) -> *mut libc::tm {
    if timer.is_null() {
        return std::ptr::null_mut();
    }
    GMTIME_BUF.with(|cell| {
        let ptr = cell.get();
        unsafe {
            gmtime_r(timer, ptr);
        }
        ptr
    })
}

/// POSIX `localtime` — convert time_t to broken-down local time (non-reentrant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn localtime(timer: *const i64) -> *mut libc::tm {
    if timer.is_null() {
        return std::ptr::null_mut();
    }
    LOCALTIME_BUF.with(|cell| {
        let ptr = cell.get();
        unsafe {
            localtime_r(timer, ptr);
        }
        ptr
    })
}

/// POSIX `asctime` — convert broken-down time to string (non-reentrant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asctime(tm: *const libc::tm) -> *mut std::ffi::c_char {
    if tm.is_null() {
        return std::ptr::null_mut();
    }
    ASCTIME_BUF.with(|cell| {
        let ptr = cell.get();
        unsafe {
            asctime_r(tm, (*ptr).as_mut_ptr() as *mut std::ffi::c_char);
        }
        unsafe { (*ptr).as_mut_ptr() as *mut std::ffi::c_char }
    })
}

/// POSIX `ctime` — convert time_t to string (non-reentrant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctime(timer: *const i64) -> *mut std::ffi::c_char {
    if timer.is_null() {
        return std::ptr::null_mut();
    }
    CTIME_BUF.with(|cell| {
        let ptr = cell.get();
        unsafe {
            ctime_r(timer, (*ptr).as_mut_ptr() as *mut std::ffi::c_char);
        }
        unsafe { (*ptr).as_mut_ptr() as *mut std::ffi::c_char }
    })
}

// ---------------------------------------------------------------------------
// strptime + tzset — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "strptime"]
    fn libc_strptime(s: *const std::ffi::c_char, fmt: *const std::ffi::c_char, tm: *mut libc::tm) -> *mut std::ffi::c_char;
    #[link_name = "tzset"]
    fn libc_tzset();
}

/// POSIX `strptime` — parse date/time string into broken-down time.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strptime(
    s: *const std::ffi::c_char,
    format: *const std::ffi::c_char,
    tm: *mut libc::tm,
) -> *mut std::ffi::c_char {
    if s.is_null() || format.is_null() || tm.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { libc_strptime(s, format, tm) }
}

/// POSIX `tzset` — initialize timezone conversion information.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tzset() {
    unsafe { libc_tzset() }
}
