//! ABI layer for `<time.h>` functions.
//!
//! `clock_gettime` and `gettimeofday` use raw syscalls in the preload-safe path.
//! vDSO mapping presence is still reported for diagnostics, but resolving vDSO
//! entrypoints through the dynamic linker is intentionally avoided because it can
//! re-enter glibc loader state from interposed startup paths. Pure arithmetic
//! (broken-down conversion) delegates to `frankenlibc_core::time`.

use std::ffi::{c_int, c_ulong, c_void};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_core::errno;
use frankenlibc_core::syscall as raw_syscall;
use frankenlibc_core::time as time_core;
use frankenlibc_membrane::MembraneAction;
use frankenlibc_membrane::runtime_math::ApiFamily;

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use crate::util::scan_c_string;

type VdsoClockGettimeFn = unsafe extern "C" fn(c_int, *mut libc::timespec) -> c_int;
type VdsoGettimeofdayFn = unsafe extern "C" fn(*mut libc::timeval, *mut libc::timezone) -> c_int;

const ASCTIME_R_BUF_BYTES: usize = 26;
const TIME_T_BYTES: usize = core::mem::size_of::<i64>();
const TM_BYTES: usize = core::mem::size_of::<libc::tm>();

fn tracked_region_fits(ptr: *const c_void, len: usize) -> bool {
    known_remaining(ptr as usize).is_none_or(|remaining| len <= remaining)
}

#[inline]
fn tracked_required_object_fits<T>(ptr: *const T) -> bool {
    !ptr.is_null() && tracked_region_fits(ptr.cast::<c_void>(), core::mem::size_of::<T>())
}

#[inline]
fn tracked_optional_object_fits<T>(ptr: *const T) -> bool {
    ptr.is_null() || tracked_required_object_fits(ptr)
}

#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdsoCallOutcome {
    Success,
    FallbackToSyscall,
    Fail(c_int),
}

#[derive(Debug, Clone, Copy, Default)]
struct VdsoSymbols {
    mapping_present: bool,
    handle_opened: bool,
    clock_gettime: Option<VdsoClockGettimeFn>,
    gettimeofday: Option<VdsoGettimeofdayFn>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VdsoFastpathSnapshot {
    pub mapping_present: bool,
    pub handle_opened: bool,
    pub clock_gettime_available: bool,
    pub gettimeofday_available: bool,
    pub clock_gettime_hits: u64,
    pub gettimeofday_hits: u64,
}

static VDSO_SYMBOLS: OnceLock<VdsoSymbols> = OnceLock::new();
static VDSO_CLOCK_GETTIME_HITS: AtomicU64 = AtomicU64::new(0);
static VDSO_GETTIMEOFDAY_HITS: AtomicU64 = AtomicU64::new(0);

const fn vdso_symbol_version_bytes() -> &'static [u8] {
    #[cfg(target_arch = "aarch64")]
    {
        b"LINUX_2.6.39\0"
    }
    #[cfg(target_arch = "riscv64")]
    {
        b"LINUX_4.15\0"
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
    {
        b"LINUX_2.6\0"
    }
}

#[inline]
fn classify_vdso_return(rc: c_int) -> VdsoCallOutcome {
    if rc == 0 {
        VdsoCallOutcome::Success
    } else if rc == -libc::ENOSYS || rc > 0 {
        VdsoCallOutcome::FallbackToSyscall
    } else {
        VdsoCallOutcome::Fail(-rc)
    }
}

#[doc(hidden)]
pub fn __frankenlibc_vdso_symbol_version_name() -> &'static str {
    let bytes = vdso_symbol_version_bytes();
    std::str::from_utf8(&bytes[..bytes.len() - 1]).unwrap_or("LINUX_2.6")
}

#[doc(hidden)]
pub fn __frankenlibc_classify_vdso_return(rc: c_int) -> VdsoCallOutcome {
    classify_vdso_return(rc)
}

#[inline]
fn last_host_errno(default: c_int) -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(default)
}

pub fn vdso_fastpath_snapshot() -> VdsoFastpathSnapshot {
    if !vdso_resolution_enabled() {
        let mapping_present =
            raw_getauxval(libc::AT_SYSINFO_EHDR as c_ulong).is_some_and(|value| value != 0);
        return VdsoFastpathSnapshot {
            mapping_present,
            clock_gettime_hits: VDSO_CLOCK_GETTIME_HITS.load(Ordering::Relaxed),
            gettimeofday_hits: VDSO_GETTIMEOFDAY_HITS.load(Ordering::Relaxed),
            ..VdsoFastpathSnapshot::default()
        };
    }

    let symbols = *VDSO_SYMBOLS.get_or_init(resolve_vdso_symbols);
    VdsoFastpathSnapshot {
        mapping_present: symbols.mapping_present,
        handle_opened: symbols.handle_opened,
        clock_gettime_available: symbols.clock_gettime.is_some(),
        gettimeofday_available: symbols.gettimeofday.is_some(),
        clock_gettime_hits: VDSO_CLOCK_GETTIME_HITS.load(Ordering::Relaxed),
        gettimeofday_hits: VDSO_GETTIMEOFDAY_HITS.load(Ordering::Relaxed),
    }
}

#[inline]
fn vdso_resolution_enabled() -> bool {
    runtime_policy::is_runtime_ready() && !crate::membrane_state::pipeline_initialization_active()
}

#[inline]
fn vdso_clock_supported(clock_id: c_int) -> bool {
    matches!(
        clock_id,
        libc::CLOCK_REALTIME
            | libc::CLOCK_MONOTONIC
            | libc::CLOCK_REALTIME_COARSE
            | libc::CLOCK_MONOTONIC_COARSE
            | libc::CLOCK_BOOTTIME
            | libc::CLOCK_TAI
    )
}

#[inline]
unsafe fn raw_clock_gettime_syscall(clock_id: c_int, tp: *mut libc::timespec) -> c_int {
    match unsafe { raw_syscall::sys_clock_gettime(clock_id, tp as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[inline]
unsafe fn raw_clock_gettime(clock_id: c_int, tp: *mut libc::timespec) -> c_int {
    if vdso_clock_supported(clock_id) && vdso_resolution_enabled() {
        let symbols = *VDSO_SYMBOLS.get_or_init(resolve_vdso_symbols);
        if let Some(vdso_clock_gettime) = symbols.clock_gettime {
            let rc = unsafe { vdso_clock_gettime(clock_id, tp) };
            match classify_vdso_return(rc) {
                VdsoCallOutcome::Success => {
                    VDSO_CLOCK_GETTIME_HITS.fetch_add(1, Ordering::Relaxed);
                    return 0;
                }
                VdsoCallOutcome::FallbackToSyscall => {}
                VdsoCallOutcome::Fail(err) => {
                    unsafe { set_abi_errno(err) };
                    return -1;
                }
            }
        }
    }

    unsafe { raw_clock_gettime_syscall(clock_id, tp) }
}

#[inline]
unsafe fn raw_gettimeofday(tv: *mut libc::timeval) -> c_int {
    if vdso_resolution_enabled() {
        let symbols = *VDSO_SYMBOLS.get_or_init(resolve_vdso_symbols);
        if let Some(vdso_gettimeofday) = symbols.gettimeofday {
            let rc = unsafe { vdso_gettimeofday(tv, std::ptr::null_mut()) };
            match classify_vdso_return(rc) {
                VdsoCallOutcome::Success => {
                    VDSO_GETTIMEOFDAY_HITS.fetch_add(1, Ordering::Relaxed);
                    return 0;
                }
                VdsoCallOutcome::FallbackToSyscall => {}
                VdsoCallOutcome::Fail(err) => {
                    unsafe { set_abi_errno(err) };
                    return -1;
                }
            }
        }
    }

    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { raw_clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if rc != 0 {
        return -1;
    }

    unsafe {
        (*tv).tv_sec = ts.tv_sec;
        (*tv).tv_usec = ts.tv_nsec / 1000;
    }
    0
}

fn resolve_vdso_symbols() -> VdsoSymbols {
    let mapping_present =
        raw_getauxval(libc::AT_SYSINFO_EHDR as c_ulong).is_some_and(|value| value != 0);
    VdsoSymbols {
        mapping_present,
        ..VdsoSymbols::default()
    }
}

fn raw_getauxval(typ: c_ulong) -> Option<c_ulong> {
    let fd = unsafe {
        raw_syscall::sys_openat(
            libc::AT_FDCWD,
            c"/proc/self/auxv".as_ptr() as *const u8,
            libc::O_RDONLY,
            0,
        )
    }
    .ok()? as c_int;
    let entry_size = 2 * std::mem::size_of::<c_ulong>();
    let mut buf = std::mem::MaybeUninit::<[u8; 4096]>::uninit();
    // SAFETY: the raw syscall writes at most the provided byte count into the
    // uninitialized stack buffer, and we only read the initialized prefix below.
    let read_result = unsafe { raw_syscall::sys_read(fd, buf.as_mut_ptr().cast::<u8>(), 4096) };
    let _ = raw_syscall::sys_close(fd);
    let bytes = read_result.ok()? as usize;
    // SAFETY: read(2) initialized exactly the returned prefix, bounded by the
    // requested 4096 bytes. The uninitialized tail is never observed.
    let auxv = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), bytes) };
    for chunk in auxv.chunks_exact(entry_size) {
        let at = c_ulong::from_ne_bytes(chunk[..8].try_into().ok()?);
        let av = c_ulong::from_ne_bytes(chunk[8..16].try_into().ok()?);
        if at == typ {
            return Some(av);
        }
        if at == 0 {
            break;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// time
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn time(tloc: *mut i64) -> i64 {
    if !tracked_optional_object_fits(tloc.cast_const()) {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { raw_clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if rc != 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
        return -1;
    }
    let secs = ts.tv_sec;
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

    if !tracked_required_object_fits(tp.cast_const()) {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    if !time_core::valid_clock_id(clock_id) && !time_core::valid_clock_id_extended(clock_id) {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    let rc = unsafe { raw_clock_gettime(clock_id, tp) };
    if rc != 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
    }
    rc
}

// ---------------------------------------------------------------------------
// clock
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clock() -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { raw_clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
        return -1;
    }
    ts.tv_sec * time_core::CLOCKS_PER_SEC + ts.tv_nsec / (1_000_000_000 / time_core::CLOCKS_PER_SEC)
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
        // glibc extension fields — required by Python, Ruby, and other runtimes
        // that check tm_gmtoff for timezone validity.
        (*result).tm_gmtoff = 0; // UTC offset in seconds
        (*result).tm_zone = c"UTC".as_ptr();
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
    if timer.is_null()
        || result.is_null()
        || !tracked_required_object_fits(timer)
        || !tracked_required_object_fits(result.cast_const())
    {
        unsafe { set_abi_errno(errno::EFAULT) };
        return std::ptr::null_mut();
    }

    let epoch = unsafe { *timer };
    let Some(bd) = time_core::epoch_to_broken_down_checked(epoch) else {
        // Year would overflow `tm_year` (c_int). Match glibc's NULL return.
        unsafe { set_abi_errno(errno::EOVERFLOW) };
        return std::ptr::null_mut();
    };
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
    if timer.is_null()
        || result.is_null()
        || !tracked_required_object_fits(timer)
        || !tracked_required_object_fits(result.cast_const())
    {
        unsafe { set_abi_errno(errno::EFAULT) };
        return std::ptr::null_mut();
    }

    let epoch = unsafe { *timer };
    let Some(bd) = time_core::epoch_to_broken_down_checked(epoch) else {
        // Year would overflow `tm_year` (c_int). Match glibc's NULL return.
        unsafe { set_abi_errno(errno::EOVERFLOW) };
        return std::ptr::null_mut();
    };
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
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Time,
        tm as usize,
        std::mem::size_of::<libc::tm>(),
        true,
        tm.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Time, decision.profile, 8, true);
        return -1;
    }

    if tm.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Time, decision.profile, 8, true);
        return -1;
    }
    if !tracked_required_object_fits(tm.cast_const()) {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Time, decision.profile, 8, true);
        return -1;
    }

    let bd = unsafe { read_tm(tm) };
    let epoch = time_core::broken_down_to_epoch(&bd);

    // Normalize: re-derive the full broken-down time and write back.
    let normalized = time_core::epoch_to_broken_down(epoch);
    unsafe { write_tm(tm, &normalized) };
    runtime_policy::observe(ApiFamily::Time, decision.profile, 8, false);
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

    if !tracked_required_object_fits(tv.cast_const()) {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    let rc = unsafe { raw_gettimeofday(tv) };
    if rc != 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
        return -1;
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

    if !tracked_optional_object_fits(res.cast_const()) {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    match unsafe { raw_syscall::sys_clock_getres(clock_id, res as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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

    if !tracked_required_object_fits(req) || !tracked_optional_object_fits(rem.cast_const()) {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    match unsafe { raw_syscall::sys_nanosleep(req as *const u8, rem as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Time,
        req as usize,
        std::mem::size_of::<libc::timespec>(),
        false,
        req.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 6, true);
        return errno::EPERM;
    }

    if req.is_null() {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 6, true);
        return errno::EFAULT;
    }

    if !tracked_required_object_fits(req) || !tracked_optional_object_fits(rem.cast_const()) {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 6, true);
        return errno::EFAULT;
    }

    if !time_core::valid_clock_id(clock_id) && !time_core::valid_clock_id_extended(clock_id) {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 6, true);
        return errno::EINVAL;
    }

    // clock_nanosleep returns the error number directly (not via errno).
    let result = match unsafe {
        raw_syscall::sys_clock_nanosleep(clock_id, flags, req as *const u8, rem as *mut u8)
    } {
        Ok(()) => 0,
        Err(e) => e, // Return error code directly, not via errno
    };
    runtime_policy::observe(ApiFamily::Time, decision.profile, 6, result != 0);
    result
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
    if tm.is_null()
        || buf.is_null()
        || !tracked_region_fits(tm.cast(), TM_BYTES)
        || !tracked_region_fits(buf.cast(), ASCTIME_R_BUF_BYTES)
    {
        return std::ptr::null_mut();
    }

    let bd = unsafe { read_tm(tm) };
    let dst = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, ASCTIME_R_BUF_BYTES) };
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
    if timer.is_null()
        || buf.is_null()
        || !tracked_region_fits(timer.cast(), TIME_T_BYTES)
        || !tracked_region_fits(buf.cast(), ASCTIME_R_BUF_BYTES)
    {
        return std::ptr::null_mut();
    }

    let epoch = unsafe { *timer };
    let Some(bd) = time_core::epoch_to_broken_down_checked(epoch) else {
        return std::ptr::null_mut();
    };
    let dst = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, ASCTIME_R_BUF_BYTES) };
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
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Time,
        s as usize,
        maxsize,
        true,
        s.is_null() || format.is_null() || tm.is_null() || maxsize == 0,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 6, true);
        return 0;
    }

    if s.is_null() || format.is_null() || tm.is_null() || maxsize == 0 {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 6, true);
        return 0;
    }

    if !tracked_region_fits(s.cast(), maxsize) || !tracked_required_object_fits(tm) {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 6, true);
        return 0;
    }

    // Read the format string as a byte slice.
    let (fmt_len, terminated) = unsafe { scan_c_string(format, known_remaining(format as usize)) };
    if !terminated {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 6, true);
        return 0;
    }
    let fmt = unsafe { std::slice::from_raw_parts(format as *const u8, fmt_len) };

    // Read the broken-down time.
    let bd = unsafe { read_tm(tm) };

    // Format into the output buffer.
    let buf = unsafe { std::slice::from_raw_parts_mut(s as *mut u8, maxsize) };
    let result = time_core::format_strftime(fmt, &bd, buf);
    runtime_policy::observe(ApiFamily::Time, decision.profile, 6, result == 0);
    result
}

// ---------------------------------------------------------------------------
// Non-reentrant time wrappers (use per-thread static buffers)
// ---------------------------------------------------------------------------

#[cfg(feature = "owned-tls-cache")]
struct TimeTls {
    gmtime_buf: libc::tm,
    localtime_buf: libc::tm,
    asctime_buf: [u8; ASCTIME_R_BUF_BYTES],
    ctime_buf: [u8; ASCTIME_R_BUF_BYTES],
}

// SAFETY: `TimeTls` is keyed by kernel thread id inside `OwnedTlsCache`. The
// `libc::tm` timezone pointer is opaque ABI scratch and is never dereferenced
// by the cache itself.
#[cfg(feature = "owned-tls-cache")]
unsafe impl Send for TimeTls {}

#[cfg(feature = "owned-tls-cache")]
fn new_time_tls() -> TimeTls {
    TimeTls {
        // SAFETY: `libc::tm` is a C POD struct; zero initialization matches the
        // static scratch-buffer initialization used by the default TLS path.
        gmtime_buf: unsafe { std::mem::zeroed() },
        // SAFETY: Same POD zero-initialization rationale as `gmtime_buf`.
        localtime_buf: unsafe { std::mem::zeroed() },
        asctime_buf: [0; ASCTIME_R_BUF_BYTES],
        ctime_buf: [0; ASCTIME_R_BUF_BYTES],
    }
}

#[cfg(feature = "owned-tls-cache")]
static TIME_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<TimeTls> =
    crate::owned_tls_cache::OwnedTlsCache::new(new_time_tls);

#[cfg(not(feature = "owned-tls-cache"))]
std::thread_local! {
    static GMTIME_BUF: std::cell::UnsafeCell<libc::tm> = const { std::cell::UnsafeCell::new(unsafe { std::mem::zeroed() }) };
    static LOCALTIME_BUF: std::cell::UnsafeCell<libc::tm> = const { std::cell::UnsafeCell::new(unsafe { std::mem::zeroed() }) };
    static ASCTIME_BUF: std::cell::UnsafeCell<[u8; ASCTIME_R_BUF_BYTES]> = const { std::cell::UnsafeCell::new([0u8; ASCTIME_R_BUF_BYTES]) };
    static CTIME_BUF: std::cell::UnsafeCell<[u8; ASCTIME_R_BUF_BYTES]> = const { std::cell::UnsafeCell::new([0u8; ASCTIME_R_BUF_BYTES]) };
}

#[inline]
fn with_gmtime_buf<R>(f: impl FnOnce(&mut libc::tm) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        TIME_OWNED_TLS.with(|tls| f(&mut tls.gmtime_buf))
    }

    #[cfg(not(feature = "owned-tls-cache"))]
    {
        GMTIME_BUF.with(|cell| {
            // SAFETY: The default path uses Rust thread-local storage, so this
            // mutable reference is scoped to the current thread's scratch slot.
            f(unsafe { &mut *cell.get() })
        })
    }
}

#[inline]
fn with_localtime_buf<R>(f: impl FnOnce(&mut libc::tm) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        TIME_OWNED_TLS.with(|tls| f(&mut tls.localtime_buf))
    }

    #[cfg(not(feature = "owned-tls-cache"))]
    {
        LOCALTIME_BUF.with(|cell| {
            // SAFETY: The default path uses Rust thread-local storage, so this
            // mutable reference is scoped to the current thread's scratch slot.
            f(unsafe { &mut *cell.get() })
        })
    }
}

#[inline]
fn with_asctime_buf<R>(f: impl FnOnce(&mut [u8; ASCTIME_R_BUF_BYTES]) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        TIME_OWNED_TLS.with(|tls| f(&mut tls.asctime_buf))
    }

    #[cfg(not(feature = "owned-tls-cache"))]
    {
        ASCTIME_BUF.with(|cell| {
            // SAFETY: The default path uses Rust thread-local storage, so this
            // mutable reference is scoped to the current thread's scratch slot.
            f(unsafe { &mut *cell.get() })
        })
    }
}

#[inline]
fn with_ctime_buf<R>(f: impl FnOnce(&mut [u8; ASCTIME_R_BUF_BYTES]) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        TIME_OWNED_TLS.with(|tls| f(&mut tls.ctime_buf))
    }

    #[cfg(not(feature = "owned-tls-cache"))]
    {
        CTIME_BUF.with(|cell| {
            // SAFETY: The default path uses Rust thread-local storage, so this
            // mutable reference is scoped to the current thread's scratch slot.
            f(unsafe { &mut *cell.get() })
        })
    }
}

/// POSIX `gmtime` — convert time_t to broken-down UTC time (non-reentrant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gmtime(timer: *const i64) -> *mut libc::tm {
    if timer.is_null() || !tracked_required_object_fits(timer) {
        return std::ptr::null_mut();
    }
    with_gmtime_buf(|buf| {
        let ptr = buf as *mut libc::tm;
        let result = unsafe { gmtime_r(timer, ptr) };
        if result.is_null() {
            std::ptr::null_mut()
        } else {
            ptr
        }
    })
}

/// POSIX `localtime` — convert time_t to broken-down local time (non-reentrant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn localtime(timer: *const i64) -> *mut libc::tm {
    if timer.is_null() || !tracked_required_object_fits(timer) {
        return std::ptr::null_mut();
    }
    with_localtime_buf(|buf| {
        let ptr = buf as *mut libc::tm;
        let result = unsafe { localtime_r(timer, ptr) };
        if result.is_null() {
            std::ptr::null_mut()
        } else {
            ptr
        }
    })
}

/// POSIX `asctime` — convert broken-down time to string (non-reentrant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asctime(tm: *const libc::tm) -> *mut std::ffi::c_char {
    if tm.is_null() || !tracked_required_object_fits(tm) {
        return std::ptr::null_mut();
    }
    with_asctime_buf(|buf| {
        let ptr = buf.as_mut_ptr() as *mut std::ffi::c_char;
        let result = unsafe { asctime_r(tm, ptr) };
        if result.is_null() {
            std::ptr::null_mut()
        } else {
            ptr
        }
    })
}

/// POSIX `ctime` — convert time_t to string (non-reentrant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctime(timer: *const i64) -> *mut std::ffi::c_char {
    if timer.is_null() || !tracked_required_object_fits(timer) {
        return std::ptr::null_mut();
    }
    with_ctime_buf(|buf| {
        let ptr = buf.as_mut_ptr() as *mut std::ffi::c_char;
        let result = unsafe { ctime_r(timer, ptr) };
        if result.is_null() {
            std::ptr::null_mut()
        } else {
            ptr
        }
    })
}

// ---------------------------------------------------------------------------
// strptime — native implementation
// ---------------------------------------------------------------------------

/// Parse at most `max_digits` decimal digits from `input[pos..]`, returning (value, new_pos).
/// Returns `None` if no digit is found at `pos`.
fn parse_digits(input: &[u8], pos: usize, max_digits: usize) -> Option<(i32, usize)> {
    let mut val: i32 = 0;
    let mut count = 0usize;
    let mut p = pos;
    while count < max_digits && p < input.len() {
        let ch = input[p];
        if ch.is_ascii_digit() {
            val = val * 10 + (ch - b'0') as i32;
            p += 1;
            count += 1;
        } else {
            break;
        }
    }
    if count == 0 { None } else { Some((val, p)) }
}

/// Skip leading ASCII whitespace from `input[pos..]`.
fn skip_ws(input: &[u8], mut pos: usize) -> usize {
    while input.get(pos).is_some_and(u8::is_ascii_whitespace) {
        pos += 1;
    }
    pos
}

/// Match a case-insensitive prefix from `input[pos..]` against `name`.
/// Returns new position after the match, or `None` if no match.
fn match_name(input: &[u8], pos: usize, name: &[u8]) -> Option<usize> {
    let end = pos.checked_add(name.len())?;
    let candidate = input.get(pos..end)?;
    for (&ch, &expected) in candidate.iter().zip(name) {
        if !ch.eq_ignore_ascii_case(&expected) {
            return None;
        }
    }
    Some(end)
}

static ABBR_MONTHS: [&[u8]; 12] = [
    b"jan", b"feb", b"mar", b"apr", b"may", b"jun", b"jul", b"aug", b"sep", b"oct", b"nov", b"dec",
];

static ABBR_DAYS: [&[u8]; 7] = [b"sun", b"mon", b"tue", b"wed", b"thu", b"fri", b"sat"];

/// POSIX `strptime` — parse date/time string into broken-down time.
///
/// Supports format specifiers: `%Y`, `%m`, `%d`, `%H`, `%M`, `%S`,
/// `%j`, `%b`/`%B`/`%h` (month name), `%a`/`%A` (weekday name),
/// `%n`/`%t` (whitespace), `%%` (literal `%`), `%C` (century),
/// `%y` (2-digit year), `%I` (12-hour), `%p` (AM/PM), `%e` (day with
/// leading space), `%D` (`%m/%d/%y`), `%T` (`%H:%M:%S`),
/// `%R` (`%H:%M`), `%F` (`%Y-%m-%d`), `%s` (seconds since epoch),
/// `%U`/`%W` (week number), `%V`/`%G`/`%g` (ISO week), `%z` (timezone offset).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strptime(
    s: *const std::ffi::c_char,
    format: *const std::ffi::c_char,
    tm: *mut libc::tm,
) -> *mut std::ffi::c_char {
    if s.is_null() || format.is_null() || tm.is_null() {
        return std::ptr::null_mut();
    }
    if !tracked_required_object_fits(tm.cast_const()) {
        return std::ptr::null_mut();
    }

    let (input_len, input_terminated) = unsafe { scan_c_string(s, known_remaining(s as usize)) };
    let (fmt_len, fmt_terminated) =
        unsafe { scan_c_string(format, known_remaining(format as usize)) };
    if !input_terminated || !fmt_terminated {
        return std::ptr::null_mut();
    }

    let input_ptr = s as *const u8;
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len) };
    let fmt = unsafe { std::slice::from_raw_parts(format as *const u8, fmt_len) };
    let mut si = 0usize; // position in input
    let mut fi = 0usize; // position in format
    let mut century: Option<i32> = None;
    let mut is_pm: Option<bool> = None;

    while fi < fmt.len() {
        let fc = fmt[fi];
        if fc == b'%' {
            fi += 1;
            let Some(&spec) = fmt.get(fi) else {
                return std::ptr::null_mut(); // trailing %
            };
            fi += 1;

            // glibc's strptime skips leading whitespace before numeric field
            // conversions (its `get_number` helper) and before `%z`'s sign, but
            // NOT before name conversions (%a/%A/%b/%B/%h/%p), %n/%t, or %%.
            // Composite conversions (%D/%T/%R/%F) recurse through this loop, so
            // their first numeric field is covered automatically.
            if matches!(
                spec,
                b'Y' | b'C'
                    | b'y'
                    | b'm'
                    | b'd'
                    | b'e'
                    | b'H'
                    | b'I'
                    | b'M'
                    | b'S'
                    | b'j'
                    | b's'
                    | b'U'
                    | b'W'
                    | b'V'
                    | b'G'
                    | b'g'
                    | b'z'
            ) {
                si = skip_ws(input, si);
            }

            match spec {
                b'Y' => {
                    // 4-digit year
                    if let Some((val, new_si)) = parse_digits(input, si, 4) {
                        unsafe { (*tm).tm_year = val - 1900 };
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'C' => {
                    // Century (first 2 digits of year)
                    if let Some((val, new_si)) = parse_digits(input, si, 2) {
                        century = Some(val);
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'y' => {
                    // 2-digit year within century
                    if let Some((val, new_si)) = parse_digits(input, si, 2) {
                        unsafe { (*tm).tm_year = val + if val < 69 { 100 } else { 0 } };
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'm' => {
                    // Month [01,12] — glibc rejects out-of-range numeric values.
                    if let Some((val, new_si)) = parse_digits(input, si, 2) {
                        if !(1..=12).contains(&val) {
                            return std::ptr::null_mut();
                        }
                        unsafe { (*tm).tm_mon = val - 1 };
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'd' | b'e' => {
                    // Day of month [01,31] (%e allows leading space).
                    // glibc rejects out-of-range numeric values.
                    si = skip_ws(input, si);
                    if let Some((val, new_si)) = parse_digits(input, si, 2) {
                        if !(1..=31).contains(&val) {
                            return std::ptr::null_mut();
                        }
                        unsafe { (*tm).tm_mday = val };
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'H' => {
                    // Hour (24-hour) [00,23] — glibc rejects 24..=99.
                    if let Some((val, new_si)) = parse_digits(input, si, 2) {
                        if !(0..=23).contains(&val) {
                            return std::ptr::null_mut();
                        }
                        unsafe { (*tm).tm_hour = val };
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'I' => {
                    // Hour (12-hour) [01,12]. glibc rejects 0 and 13..=99.
                    // We store `val % 12` so the AM/PM post-processing can
                    // simply add 12 for PM and leave AM unchanged: that
                    // gives 12 AM → 0 (midnight) and 12 PM → 12 (noon)
                    // without a special case at finalization.
                    if let Some((val, new_si)) = parse_digits(input, si, 2) {
                        if !(1..=12).contains(&val) {
                            return std::ptr::null_mut();
                        }
                        unsafe { (*tm).tm_hour = val % 12 };
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'p' => {
                    // AM/PM
                    if let Some(new_si) = match_name(input, si, b"am") {
                        is_pm = Some(false);
                        si = new_si;
                    } else if let Some(new_si) = match_name(input, si, b"pm") {
                        is_pm = Some(true);
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'M' => {
                    // Minute [00,59] — glibc rejects 60..=99.
                    if let Some((val, new_si)) = parse_digits(input, si, 2) {
                        if val > 59 {
                            return std::ptr::null_mut();
                        }
                        unsafe { (*tm).tm_min = val };
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'S' => {
                    // Second [00,61] — glibc accepts 0-61 (60-61 for leap seconds).
                    if let Some((val, new_si)) = parse_digits(input, si, 2) {
                        if val > 61 {
                            return std::ptr::null_mut();
                        }
                        unsafe { (*tm).tm_sec = val };
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'j' => {
                    // Day of year [001,366] — glibc rejects 000 and 367..=999.
                    if let Some((val, new_si)) = parse_digits(input, si, 3) {
                        if !(1..=366).contains(&val) {
                            return std::ptr::null_mut();
                        }
                        unsafe { (*tm).tm_yday = val - 1 };
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'b' | b'B' | b'h' => {
                    // Abbreviated or full month name
                    let mut found = false;
                    for (idx, name) in ABBR_MONTHS.iter().enumerate() {
                        if let Some(new_si) = match_name(input, si, name) {
                            unsafe { (*tm).tm_mon = idx as i32 };
                            si = new_si;
                            // Skip remaining alphabetic chars (for full month names)
                            while input.get(si).is_some_and(u8::is_ascii_alphabetic) {
                                si += 1;
                            }
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        return std::ptr::null_mut();
                    }
                }
                b'a' | b'A' => {
                    // Abbreviated or full weekday name
                    let mut found = false;
                    for (idx, name) in ABBR_DAYS.iter().enumerate() {
                        if let Some(new_si) = match_name(input, si, name) {
                            unsafe { (*tm).tm_wday = idx as i32 };
                            si = new_si;
                            while input.get(si).is_some_and(u8::is_ascii_alphabetic) {
                                si += 1;
                            }
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        return std::ptr::null_mut();
                    }
                }
                b'n' | b't' => {
                    // Any whitespace
                    si = skip_ws(input, si);
                }
                b'%' => {
                    // Literal %
                    if input.get(si).copied() != Some(b'%') {
                        return std::ptr::null_mut();
                    }
                    si += 1;
                }
                // Composite specifiers
                b'D' => {
                    // %m/%d/%y
                    let result = unsafe {
                        strptime(
                            input_ptr.add(si) as *const std::ffi::c_char,
                            c"%m/%d/%y".as_ptr(),
                            tm,
                        )
                    };
                    if result.is_null() {
                        return std::ptr::null_mut();
                    }
                    let consumed =
                        unsafe { result.offset_from(input_ptr.add(si) as *const std::ffi::c_char) };
                    if consumed < 0 {
                        return std::ptr::null_mut();
                    }
                    si = si.saturating_add(consumed as usize);
                    if si > input.len() {
                        return std::ptr::null_mut();
                    }
                }
                b'T' => {
                    // %H:%M:%S
                    let result = unsafe {
                        strptime(
                            input_ptr.add(si) as *const std::ffi::c_char,
                            c"%H:%M:%S".as_ptr(),
                            tm,
                        )
                    };
                    if result.is_null() {
                        return std::ptr::null_mut();
                    }
                    let consumed =
                        unsafe { result.offset_from(input_ptr.add(si) as *const std::ffi::c_char) };
                    if consumed < 0 {
                        return std::ptr::null_mut();
                    }
                    si = si.saturating_add(consumed as usize);
                    if si > input.len() {
                        return std::ptr::null_mut();
                    }
                }
                b'R' => {
                    // %H:%M
                    let result = unsafe {
                        strptime(
                            input_ptr.add(si) as *const std::ffi::c_char,
                            c"%H:%M".as_ptr(),
                            tm,
                        )
                    };
                    if result.is_null() {
                        return std::ptr::null_mut();
                    }
                    let consumed =
                        unsafe { result.offset_from(input_ptr.add(si) as *const std::ffi::c_char) };
                    if consumed < 0 {
                        return std::ptr::null_mut();
                    }
                    si = si.saturating_add(consumed as usize);
                    if si > input.len() {
                        return std::ptr::null_mut();
                    }
                }
                b'F' => {
                    // %Y-%m-%d
                    let result = unsafe {
                        strptime(
                            input_ptr.add(si) as *const std::ffi::c_char,
                            c"%Y-%m-%d".as_ptr(),
                            tm,
                        )
                    };
                    if result.is_null() {
                        return std::ptr::null_mut();
                    }
                    let consumed =
                        unsafe { result.offset_from(input_ptr.add(si) as *const std::ffi::c_char) };
                    if consumed < 0 {
                        return std::ptr::null_mut();
                    }
                    si = si.saturating_add(consumed as usize);
                    if si > input.len() {
                        return std::ptr::null_mut();
                    }
                }
                b's' => {
                    // Seconds since epoch (GNU extension, also in POSIX 2024).
                    // Parse digits and convert to broken-down time.
                    let start = si;
                    let mut epoch: i64 = 0;
                    let negative = input.get(si).copied() == Some(b'-');
                    if negative {
                        si += 1;
                    }
                    while si < input.len() && input[si].is_ascii_digit() {
                        epoch = epoch
                            .saturating_mul(10)
                            .saturating_add((input[si] - b'0') as i64);
                        si += 1;
                    }
                    if si == start || (negative && si == start + 1) {
                        return std::ptr::null_mut();
                    }
                    if negative {
                        // glibc rejects negative epoch
                        return std::ptr::null_mut();
                    }
                    // Convert epoch to tm (UTC)
                    let secs_per_min = 60i64;
                    let secs_per_hour = 3600i64;
                    let secs_per_day = 86400i64;
                    let mut days = epoch / secs_per_day;
                    let mut rem = epoch % secs_per_day;
                    unsafe {
                        (*tm).tm_hour = (rem / secs_per_hour) as i32;
                        rem %= secs_per_hour;
                        (*tm).tm_min = (rem / secs_per_min) as i32;
                        (*tm).tm_sec = (rem % secs_per_min) as i32;
                    }
                    // Days since 1970-01-01
                    let mut year = 1970i32;
                    loop {
                        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
                        {
                            366
                        } else {
                            365
                        };
                        if days < days_in_year as i64 {
                            break;
                        }
                        days -= days_in_year as i64;
                        year += 1;
                    }
                    unsafe {
                        (*tm).tm_year = year - 1900;
                        (*tm).tm_yday = days as i32;
                    }
                    // Convert yday to mon/mday
                    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
                    let mdays: [i32; 12] = if leap {
                        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
                    } else {
                        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
                    };
                    let mut yday_rem = days as i32;
                    let mut mon = 0;
                    while mon < 12 && yday_rem >= mdays[mon] {
                        yday_rem -= mdays[mon];
                        mon += 1;
                    }
                    unsafe {
                        (*tm).tm_mon = mon as i32;
                        (*tm).tm_mday = yday_rem + 1;
                        // wday: 1970-01-01 was Thursday (4)
                        (*tm).tm_wday = ((epoch / secs_per_day + 4) % 7) as i32;
                    }
                }
                b'U' => {
                    // Week number (Sunday-starting weeks, 00-53).
                    // glibc parses this but uses it in combination with weekday.
                    if let Some((val, new_si)) = parse_digits(input, si, 2) {
                        if val > 53 {
                            return std::ptr::null_mut();
                        }
                        // Store in tm for potential later use (not standard field)
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'W' => {
                    // Week number (Monday-starting weeks, 00-53).
                    if let Some((val, new_si)) = parse_digits(input, si, 2) {
                        if val > 53 {
                            return std::ptr::null_mut();
                        }
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'V' => {
                    // ISO week number (01-53).
                    if let Some((val, new_si)) = parse_digits(input, si, 2) {
                        if !(1..=53).contains(&val) {
                            return std::ptr::null_mut();
                        }
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'G' => {
                    // ISO week-based year (4 digits).
                    if let Some((_, new_si)) = parse_digits(input, si, 4) {
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'g' => {
                    // ISO week-based year (2 digits).
                    if let Some((_, new_si)) = parse_digits(input, si, 2) {
                        si = new_si;
                    } else {
                        return std::ptr::null_mut();
                    }
                }
                b'z' => {
                    // Timezone offset, matching glibc strptime exactly:
                    //   'Z'                 -> UTC (offset 0), consumes 1 byte
                    //   [+-]HH[[:]MM]       -> HH is EXACTLY two digits; MM is
                    //                          optional, exactly two digits, and
                    //                          validated < 60. A ':' before MM is
                    //                          only consumed when two minute digits
                    //                          actually follow. Hours are not
                    //                          range-validated. Leading whitespace
                    //                          was already skipped by the dispatch.
                    // Lowercase 'z' and named zones (GMT/UTC) are NOT accepted.
                    if input.get(si).copied() == Some(b'Z') {
                        si += 1;
                        #[cfg(target_os = "linux")]
                        unsafe {
                            (*tm).tm_gmtoff = 0;
                        }
                    } else {
                        let sign: i64 = match input.get(si).copied() {
                            Some(b'+') => 1,
                            Some(b'-') => -1,
                            _ => return std::ptr::null_mut(),
                        };
                        // Exactly two hour digits.
                        let (Some(h0), Some(h1)) =
                            (input.get(si + 1).copied(), input.get(si + 2).copied())
                        else {
                            return std::ptr::null_mut();
                        };
                        if !h0.is_ascii_digit() || !h1.is_ascii_digit() {
                            return std::ptr::null_mut();
                        }
                        let hh = ((h0 - b'0') as i64) * 10 + (h1 - b'0') as i64;
                        let mut end = si + 3;

                        // Optional minutes: optional ':' then exactly two digits.
                        let mm_start = if input.get(end).copied() == Some(b':') {
                            end + 1
                        } else {
                            end
                        };
                        let mut mm = 0i64;
                        if let (Some(m0), Some(m1)) =
                            (input.get(mm_start).copied(), input.get(mm_start + 1).copied())
                            && m0.is_ascii_digit()
                            && m1.is_ascii_digit()
                        {
                            mm = ((m0 - b'0') as i64) * 10 + (m1 - b'0') as i64;
                            if mm >= 60 {
                                return std::ptr::null_mut();
                            }
                            end = mm_start + 2;
                        }

                        #[cfg(target_os = "linux")]
                        unsafe {
                            (*tm).tm_gmtoff = sign * (hh * 3600 + mm * 60);
                        }
                        let _ = (sign, hh); // silence unused warnings on non-Linux
                        si = end;
                    }
                }
                _ => {
                    // Unknown specifier — fail
                    return std::ptr::null_mut();
                }
            }
        } else if fc.is_ascii_whitespace() {
            // Format whitespace matches any amount of input whitespace
            fi += 1;
            si = skip_ws(input, si);
        } else {
            // Literal character match
            if input.get(si).copied() != Some(fc) {
                return std::ptr::null_mut();
            }
            fi += 1;
            si += 1;
        }
    }

    // Post-processing: apply century override
    if let Some(c) = century {
        let year_in_century = unsafe { (*tm).tm_year + 1900 } % 100;
        unsafe { (*tm).tm_year = c * 100 + year_in_century - 1900 };
    }

    // Post-processing: apply AM/PM
    if let Some(pm) = is_pm
        && pm
    {
        let h = unsafe { (*tm).tm_hour };
        if h < 12 {
            unsafe { (*tm).tm_hour = h + 12 };
        }
    }

    unsafe { input_ptr.add(si) as *mut std::ffi::c_char }
}

// ---------------------------------------------------------------------------
// tzset — native implementation (UTC-only)
// ---------------------------------------------------------------------------

/// POSIX `tzset` — initialize timezone conversion information.
///
/// FrankenLibC operates in UTC-only mode: no timezone database is loaded,
/// `TZ` environment variable is not consulted, and all conversions assume UTC.
/// This is intentional — timezone support requires significant complexity
/// (Olson database parsing, DST rules) that is out of scope.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tzset() {
    // No-op: FrankenLibC is UTC-only.
}

// ---------------------------------------------------------------------------
// clock_settime — RawSyscall
// ---------------------------------------------------------------------------

/// POSIX `clock_settime` — set a clock.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clock_settime(
    clk_id: libc::clockid_t,
    tp: *const libc::timespec,
) -> std::ffi::c_int {
    if !tracked_required_object_fits(tp) {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    match unsafe { raw_syscall::sys_clock_settime(clk_id, tp as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// glibc reserved-namespace alias for [`clock_settime`].
///
/// # Safety
///
/// Same as [`clock_settime`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __clock_settime(
    clk_id: libc::clockid_t,
    tp: *const libc::timespec,
) -> std::ffi::c_int {
    unsafe { clock_settime(clk_id, tp) }
}

/// glibc reserved-namespace alias for [`clock_nanosleep`].
///
/// # Safety
///
/// Same as [`clock_nanosleep`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __clock_nanosleep(
    clk_id: libc::clockid_t,
    flags: std::ffi::c_int,
    req: *const libc::timespec,
    rem: *mut libc::timespec,
) -> std::ffi::c_int {
    unsafe { clock_nanosleep(clk_id, flags, req, rem) }
}

// ---------------------------------------------------------------------------
// timespec_get — Implemented (C11)
// ---------------------------------------------------------------------------

/// C11 `timespec_get` — get the current calendar time based on a given time base.
///
/// Returns `base` on success, 0 on failure.
/// TIME_UTC (1) maps to CLOCK_REALTIME.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timespec_get(ts: *mut libc::timespec, base: c_int) -> c_int {
    const TIME_UTC: c_int = 1;
    if ts.is_null() || base != TIME_UTC {
        return 0;
    }
    if !tracked_required_object_fits(ts.cast_const()) {
        return 0;
    }
    let rc = unsafe { raw_clock_gettime(libc::CLOCK_REALTIME, ts) };
    if rc == 0 { base } else { 0 }
}

// ---------------------------------------------------------------------------
// timespec_getres — Implemented (C23)
// ---------------------------------------------------------------------------

/// C23 `timespec_getres` — get the resolution for a time base.
///
/// Returns `base` on success, 0 on failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timespec_getres(ts: *mut libc::timespec, base: c_int) -> c_int {
    const TIME_UTC: c_int = 1;
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Time,
        ts as usize,
        std::mem::size_of::<libc::timespec>(),
        true,
        false, // null is allowed here
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
        return 0;
    }

    if base != TIME_UTC {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
        return 0;
    }
    if ts.is_null() {
        // Per spec, null ts is allowed — just verifies base is supported.
        runtime_policy::observe(ApiFamily::Time, decision.profile, 5, false);
        return base;
    }
    if !tracked_required_object_fits(ts.cast_const()) {
        runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
        return 0;
    }
    let result = match unsafe { raw_syscall::sys_clock_getres(libc::CLOCK_REALTIME, ts as *mut u8) }
    {
        Ok(()) => base,
        Err(_) => 0,
    };
    runtime_policy::observe(ApiFamily::Time, decision.profile, 5, result == 0);
    result
}

// Tests for time_abi are in crates/frankenlibc-abi/tests/time_abi_test.rs
// (time_abi module is #[cfg(not(test))] in lib.rs, so inline tests cannot run)
