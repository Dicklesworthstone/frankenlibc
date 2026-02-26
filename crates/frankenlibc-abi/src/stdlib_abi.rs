//! ABI stubs for stdlib functions.
//!
//! Implements numeric conversion functions (`atoi`, `atol`, `strtol`, `strtoul`),
//! environment variables (`getenv`, `setenv`, `unsetenv`),
//! process control (`exit`, `atexit`), and sorting/searching (`qsort`, `bsearch`)
//! with membrane validation.

use std::cell::Cell;
use std::ffi::{
    CStr, c_char, c_double, c_int, c_long, c_longlong, c_uint, c_ulong, c_ulonglong, c_void,
};
use std::ptr;

use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};
use libc::{intmax_t, uintmax_t};

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

unsafe extern "C" {
    #[link_name = "setenv@GLIBC_2.2.5"]
    fn native_setenv_sym(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int;
    #[link_name = "unsetenv@GLIBC_2.2.5"]
    fn native_unsetenv_sym(name: *const c_char) -> c_int;
    #[link_name = "putenv@GLIBC_2.2.5"]
    fn native_putenv_sym(string: *mut c_char) -> c_int;
    #[link_name = "__environ"]
    static mut HOST_ENVIRON: *mut *mut c_char;
}

#[inline]
unsafe fn native_getenv(name_bytes: &[u8]) -> *mut c_char {
    // SAFETY: HOST_ENVIRON is owned by libc; we only read pointers/bytes.
    unsafe {
        let mut cursor = HOST_ENVIRON;
        if cursor.is_null() {
            return ptr::null_mut();
        }
        while !(*cursor).is_null() {
            let entry = *cursor as *const u8;
            let mut i = 0usize;
            while i < name_bytes.len() && *entry.add(i) == name_bytes[i] {
                i += 1;
            }
            if i == name_bytes.len() && *entry.add(i) == b'=' {
                return entry.add(i + 1) as *mut c_char;
            }
            cursor = cursor.add(1);
        }
        ptr::null_mut()
    }
}

#[inline]
unsafe fn native_setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int {
    // SAFETY: direct call to host libc symbol.
    unsafe { native_setenv_sym(name, value, overwrite) }
}

#[inline]
unsafe fn native_unsetenv(name: *const c_char) -> c_int {
    // SAFETY: direct call to host libc symbol.
    unsafe { native_unsetenv_sym(name) }
}

// Helper: Check if repair is enabled for this decision
#[inline]
fn repair_enabled(heals_enabled: bool, action: MembraneAction) -> bool {
    heals_enabled || matches!(action, MembraneAction::Repair(_))
}

/// Scan a C string with an optional hard bound.
unsafe fn scan_c_string(ptr: *const c_char, bound: Option<usize>) -> (usize, bool) {
    match bound {
        Some(limit) => {
            for i in 0..limit {
                if unsafe { *ptr.add(i) } == 0 {
                    return (i, true);
                }
            }
            (limit, false)
        }
        None => {
            let mut i = 0usize;
            while unsafe { *ptr.add(i) } != 0 {
                i += 1;
            }
            (i, true)
        }
    }
}

// ---------------------------------------------------------------------------
// atoi
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atoi(nptr: *const c_char) -> c_int {
    if nptr.is_null() {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        nptr as usize,
        0,
        false,
        known_remaining(nptr as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return 0;
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(nptr as usize)
    } else {
        None
    };

    let (len, _terminated) = unsafe { scan_c_string(nptr, bound) };
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u8, len) };
    let result = frankenlibc_core::stdlib::atoi(slice);

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(7, len),
        false,
    );
    result
}

// ---------------------------------------------------------------------------
// atol
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atol(nptr: *const c_char) -> c_long {
    if nptr.is_null() {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        nptr as usize,
        0,
        false,
        known_remaining(nptr as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return 0;
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(nptr as usize)
    } else {
        None
    };

    let (len, _terminated) = unsafe { scan_c_string(nptr, bound) };
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u8, len) };
    let result = frankenlibc_core::stdlib::atol(slice);

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(7, len),
        false,
    );
    result as c_long
}

// ---------------------------------------------------------------------------
// atoll
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atoll(nptr: *const c_char) -> c_longlong {
    unsafe { atol(nptr) as c_longlong }
}

// ---------------------------------------------------------------------------
// strtol
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtol(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_long {
    if nptr.is_null() {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        nptr as usize,
        0,
        false,
        known_remaining(nptr as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return 0;
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(nptr as usize)
    } else {
        None
    };

    if !endptr.is_null() {
        let (_, end_decision) = runtime_policy::decide(
            ApiFamily::Stdlib,
            endptr as usize,
            std::mem::size_of::<*mut c_char>(),
            true,
            true,
            0,
        );
        if matches!(end_decision.action, MembraneAction::Deny) {
            return 0;
        }
    }

    let (len, _terminated) = unsafe { scan_c_string(nptr, bound) };
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u8, len) };

    let (val, consumed, status) = frankenlibc_core::stdlib::conversion::strtol_impl(slice, base);

    if status == frankenlibc_core::stdlib::conversion::ConversionStatus::Overflow
        || status == frankenlibc_core::stdlib::conversion::ConversionStatus::Underflow
    {
        unsafe { set_abi_errno(libc::ERANGE) };
    } else if status == frankenlibc_core::stdlib::conversion::ConversionStatus::InvalidBase {
        unsafe { set_abi_errno(libc::EINVAL) };
    }

    if !endptr.is_null() {
        unsafe {
            *endptr = (nptr as *mut c_char).add(consumed);
        }
    }

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(15, consumed),
        false,
    );

    val as c_long
}

// ---------------------------------------------------------------------------
// strtoimax
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoimax(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> intmax_t {
    if nptr.is_null() {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        nptr as usize,
        0,
        false,
        known_remaining(nptr as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return 0;
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(nptr as usize)
    } else {
        None
    };

    if !endptr.is_null() {
        let (_, end_decision) = runtime_policy::decide(
            ApiFamily::Stdlib,
            endptr as usize,
            std::mem::size_of::<*mut c_char>(),
            true,
            true,
            0,
        );
        if matches!(end_decision.action, MembraneAction::Deny) {
            return 0;
        }
    }

    let (len, _terminated) = unsafe { scan_c_string(nptr, bound) };
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u8, len) };

    let (val, consumed, status) = frankenlibc_core::stdlib::conversion::strtoimax_impl(slice, base);

    if status == frankenlibc_core::stdlib::conversion::ConversionStatus::Overflow
        || status == frankenlibc_core::stdlib::conversion::ConversionStatus::Underflow
    {
        unsafe { set_abi_errno(libc::ERANGE) };
    } else if status == frankenlibc_core::stdlib::conversion::ConversionStatus::InvalidBase {
        unsafe { set_abi_errno(libc::EINVAL) };
    }

    if !endptr.is_null() {
        unsafe {
            *endptr = (nptr as *mut c_char).add(consumed);
        }
    }

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(15, consumed),
        false,
    );

    val as intmax_t
}

// ---------------------------------------------------------------------------
// strtoll
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoll(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_longlong {
    unsafe { strtol(nptr, endptr, base) as c_longlong }
}

// ---------------------------------------------------------------------------
// strtoul
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoul(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulong {
    if nptr.is_null() {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        nptr as usize,
        0,
        false,
        known_remaining(nptr as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return 0;
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(nptr as usize)
    } else {
        None
    };

    if !endptr.is_null() {
        let (_, end_decision) = runtime_policy::decide(
            ApiFamily::Stdlib,
            endptr as usize,
            std::mem::size_of::<*mut c_char>(),
            true,
            true,
            0,
        );
        if matches!(end_decision.action, MembraneAction::Deny) {
            return 0;
        }
    }

    let (len, _terminated) = unsafe { scan_c_string(nptr, bound) };
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u8, len) };

    let (val, consumed, status) = frankenlibc_core::stdlib::conversion::strtoul_impl(slice, base);

    if status == frankenlibc_core::stdlib::conversion::ConversionStatus::Overflow
        || status == frankenlibc_core::stdlib::conversion::ConversionStatus::Underflow
    {
        unsafe { set_abi_errno(libc::ERANGE) };
    } else if status == frankenlibc_core::stdlib::conversion::ConversionStatus::InvalidBase {
        unsafe { set_abi_errno(libc::EINVAL) };
    }

    if !endptr.is_null() {
        unsafe {
            *endptr = (nptr as *mut c_char).add(consumed);
        }
    }

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(15, consumed),
        false,
    );

    val as c_ulong
}

// ---------------------------------------------------------------------------
// strtoumax
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoumax(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> uintmax_t {
    if nptr.is_null() {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        nptr as usize,
        0,
        false,
        known_remaining(nptr as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return 0;
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(nptr as usize)
    } else {
        None
    };

    if !endptr.is_null() {
        let (_, end_decision) = runtime_policy::decide(
            ApiFamily::Stdlib,
            endptr as usize,
            std::mem::size_of::<*mut c_char>(),
            true,
            true,
            0,
        );
        if matches!(end_decision.action, MembraneAction::Deny) {
            return 0;
        }
    }

    let (len, _terminated) = unsafe { scan_c_string(nptr, bound) };
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u8, len) };

    let (val, consumed, status) = frankenlibc_core::stdlib::conversion::strtoumax_impl(slice, base);

    if status == frankenlibc_core::stdlib::conversion::ConversionStatus::Overflow
        || status == frankenlibc_core::stdlib::conversion::ConversionStatus::Underflow
    {
        unsafe { set_abi_errno(libc::ERANGE) };
    } else if status == frankenlibc_core::stdlib::conversion::ConversionStatus::InvalidBase {
        unsafe { set_abi_errno(libc::EINVAL) };
    }

    if !endptr.is_null() {
        unsafe {
            *endptr = (nptr as *mut c_char).add(consumed);
        }
    }

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(15, consumed),
        false,
    );

    val as uintmax_t
}

// ---------------------------------------------------------------------------
// strtoull
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoull(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulonglong {
    unsafe { strtoul(nptr, endptr, base) as c_ulonglong }
}

// ---------------------------------------------------------------------------
// exit
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exit(status: c_int) -> ! {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, false, true, 0);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 100, false);
    frankenlibc_core::stdlib::exit(status)
}

// ---------------------------------------------------------------------------
// atexit
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atexit(func: Option<unsafe extern "C" fn()>) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, true);
        return -1;
    }

    let res = match func {
        Some(f) => {
            let safe_f: extern "C" fn() = unsafe { std::mem::transmute(f) };
            frankenlibc_core::stdlib::atexit(safe_f)
        }
        None => -1,
    };

    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 50, res != 0);
    res
}

// ---------------------------------------------------------------------------
// qsort
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn qsort(
    base: *mut c_void,
    nmemb: usize,
    size: usize,
    compar: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
) {
    if base.is_null() || nmemb == 0 || size == 0 {
        return;
    }
    let total_bytes = nmemb.checked_mul(size).unwrap_or(0);
    if total_bytes == 0 {
        return;
    }

    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        base as usize,
        total_bytes,
        true, // read-write (sorting modifies)
        known_remaining(base as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, true);
        return;
    }

    // Wrap comparator
    let Some(compar_fn) = compar else {
        return;
    };
    let wrapper = |a: &[u8], b: &[u8]| -> i32 {
        unsafe { compar_fn(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void) }
    };

    // SAFETY: We validated base for total_bytes.
    let slice = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, total_bytes) };

    frankenlibc_core::stdlib::sort::qsort(slice, size, wrapper);

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(10, total_bytes), // N log N cost ideally
        false,
    );
}

// ---------------------------------------------------------------------------
// bsearch
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bsearch(
    key: *const c_void,
    base: *const c_void,
    nmemb: usize,
    size: usize,
    compar: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
) -> *mut c_void {
    if key.is_null() || base.is_null() || nmemb == 0 || size == 0 {
        return ptr::null_mut();
    }
    let total_bytes = nmemb.checked_mul(size).unwrap_or(0);

    // Validate base
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        base as usize,
        total_bytes,
        false, // read-only
        known_remaining(base as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, true);
        return ptr::null_mut();
    }

    // Validate key (assume at least size bytes?)
    // This is heuristic.
    let (_, key_decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        key as usize,
        size,
        false,
        known_remaining(key as usize).is_none(),
        0,
    );
    if matches!(key_decision.action, MembraneAction::Deny) {
        return ptr::null_mut();
    }

    let Some(compar_fn) = compar else {
        return ptr::null_mut();
    };
    let wrapper = |a: &[u8], b: &[u8]| -> i32 {
        unsafe { compar_fn(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void) }
    };

    let slice = unsafe { std::slice::from_raw_parts(base as *const u8, total_bytes) };
    let key_slice = unsafe { std::slice::from_raw_parts(key as *const u8, size) };

    let result = frankenlibc_core::stdlib::sort::bsearch(key_slice, slice, size, wrapper);

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(5, nmemb), // log N cost
        false,
    );

    match result {
        Some(s) => s.as_ptr() as *mut c_void,
        None => ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// getenv
// ---------------------------------------------------------------------------

/// POSIX `getenv` — retrieve an environment variable value.
///
/// Returns a pointer to the value string, or null if the variable is not set.
/// The returned pointer belongs to the environment; callers must not free it.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    if name.is_null() {
        return ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        name as usize,
        0,
        false,
        known_remaining(name as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        return ptr::null_mut();
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(name as usize)
    } else {
        None
    };

    let (len, terminated) = unsafe { scan_c_string(name, bound) };
    if !terminated {
        // Unterminated names are always rejected to avoid passing non-C strings to libc.
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        return ptr::null_mut();
    }

    let name_slice = unsafe { std::slice::from_raw_parts(name as *const u8, len) };
    if !frankenlibc_core::stdlib::valid_env_name(name_slice) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        return ptr::null_mut();
    }

    // SAFETY: we only read libc's environment table and return pointer to existing value storage.
    let result = unsafe { native_getenv(name_slice) };
    let adverse = result.is_null();
    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(8, len),
        adverse,
    );
    result
}

// ---------------------------------------------------------------------------
// secure_getenv
// ---------------------------------------------------------------------------

/// GNU `secure_getenv` — getenv that returns null in secure execution mode.
///
/// We conservatively treat setuid/setgid transitions as secure execution and
/// return null in that context.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn secure_getenv(name: *const c_char) -> *mut c_char {
    let uid = unsafe { crate::unistd_abi::getuid() };
    let euid = unsafe { crate::unistd_abi::geteuid() };
    let gid = unsafe { crate::unistd_abi::getgid() };
    let egid = unsafe { crate::unistd_abi::getegid() };

    if uid != euid || gid != egid {
        return ptr::null_mut();
    }

    unsafe { getenv(name) }
}

// ---------------------------------------------------------------------------
// setenv
// ---------------------------------------------------------------------------

/// POSIX `setenv` — set an environment variable.
///
/// If `overwrite` is zero, an existing variable is not changed.
/// Returns 0 on success, -1 on error (with errno set).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setenv(
    name: *const c_char,
    value: *const c_char,
    overwrite: c_int,
) -> c_int {
    if name.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        name as usize,
        0,
        true, // write operation (modifying environment)
        known_remaining(name as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(name as usize)
    } else {
        None
    };

    let (name_len, name_terminated) = unsafe { scan_c_string(name, bound) };
    if !name_terminated {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let name_slice = unsafe { std::slice::from_raw_parts(name as *const u8, name_len) };
    if !frankenlibc_core::stdlib::valid_env_name(name_slice) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    // Validate value pointer.
    if value.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        return -1;
    }

    let value_bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(value as usize)
    } else {
        None
    };
    let (value_len, value_terminated) = unsafe { scan_c_string(value, value_bound) };
    if !value_terminated {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let value_slice = unsafe { std::slice::from_raw_parts(value as *const u8, value_len) };
    if !frankenlibc_core::stdlib::valid_env_value(value_slice) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    // SAFETY: validated NUL-terminated pointers.
    let rc = unsafe { native_setenv(name, value, overwrite) };
    if rc != 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
    }
    let adverse = rc != 0;
    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(15, name_len),
        adverse,
    );
    rc
}

// ---------------------------------------------------------------------------
// unsetenv
// ---------------------------------------------------------------------------

/// POSIX `unsetenv` — remove an environment variable.
///
/// Returns 0 on success, -1 on error (with errno set).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn unsetenv(name: *const c_char) -> c_int {
    if name.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        name as usize,
        0,
        true, // write operation (modifying environment)
        known_remaining(name as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(name as usize)
    } else {
        None
    };

    let (name_len, name_terminated) = unsafe { scan_c_string(name, bound) };
    if !name_terminated {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let name_slice = unsafe { std::slice::from_raw_parts(name as *const u8, name_len) };
    if !frankenlibc_core::stdlib::valid_env_name(name_slice) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    // SAFETY: validated NUL-terminated pointer.
    let rc = unsafe { native_unsetenv(name) };
    if rc != 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
    }
    let adverse = rc != 0;
    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(10, name_len),
        adverse,
    );
    rc
}

// ---------------------------------------------------------------------------
// abs / labs / llabs
// ---------------------------------------------------------------------------

/// C `abs` -- absolute value of an integer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn abs(n: c_int) -> c_int {
    frankenlibc_core::stdlib::abs(n)
}

/// C `labs` -- absolute value of a long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn labs(n: c_long) -> c_long {
    frankenlibc_core::stdlib::labs(n)
}

/// C `llabs` -- absolute value of a long long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn llabs(n: c_longlong) -> c_longlong {
    frankenlibc_core::stdlib::llabs(n)
}

// ---------------------------------------------------------------------------
// div / ldiv / lldiv
// ---------------------------------------------------------------------------

/// C `div_t` result type.
#[repr(C)]
pub struct CDiv {
    pub quot: c_int,
    pub rem: c_int,
}

/// C `ldiv_t` result type.
#[repr(C)]
pub struct CLdiv {
    pub quot: c_long,
    pub rem: c_long,
}

/// C `lldiv_t` result type.
#[repr(C)]
pub struct CLldiv {
    pub quot: c_longlong,
    pub rem: c_longlong,
}

/// C `div` -- integer division yielding quotient and remainder.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn div(numer: c_int, denom: c_int) -> CDiv {
    let r = frankenlibc_core::stdlib::div(numer, denom);
    CDiv {
        quot: r.quot,
        rem: r.rem,
    }
}

/// C `ldiv` -- long division yielding quotient and remainder.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn ldiv(numer: c_long, denom: c_long) -> CLdiv {
    let r = frankenlibc_core::stdlib::ldiv(numer, denom);
    CLdiv {
        quot: r.quot,
        rem: r.rem,
    }
}

/// C `lldiv` -- long long division yielding quotient and remainder.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn lldiv(numer: c_longlong, denom: c_longlong) -> CLldiv {
    let r = frankenlibc_core::stdlib::lldiv(numer, denom);
    CLldiv {
        quot: r.quot,
        rem: r.rem,
    }
}

// ---------------------------------------------------------------------------
// ffs / ffsl / ffsll
// ---------------------------------------------------------------------------

/// POSIX `ffs` -- find first set bit.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn ffs(i: c_int) -> c_int {
    frankenlibc_core::stdlib::ffs(i)
}

/// GNU `ffsl` -- find first set bit in long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn ffsl(i: c_long) -> c_int {
    frankenlibc_core::stdlib::ffsl(i)
}

/// GNU `ffsll` -- find first set bit in long long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn ffsll(i: c_longlong) -> c_int {
    frankenlibc_core::stdlib::ffsll(i)
}

// ---------------------------------------------------------------------------
// rand / srand / rand_r
// ---------------------------------------------------------------------------

/// C `rand` -- returns a pseudo-random integer in [0, RAND_MAX].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn rand() -> c_int {
    frankenlibc_core::stdlib::rand()
}

/// C `srand` -- seeds the pseudo-random number generator.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn srand(seed: c_uint) {
    frankenlibc_core::stdlib::srand(seed);
}

/// POSIX `rand_r` -- reentrant pseudo-random number generator.
///
/// # Safety
///
/// Caller must ensure `seedp` is a valid pointer to a `unsigned int`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rand_r(seedp: *mut c_uint) -> c_int {
    if seedp.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees seedp is valid.
    let seed = unsafe { &mut *seedp };
    frankenlibc_core::stdlib::rand_r(seed)
}

// ---------------------------------------------------------------------------
// atof / strtod / strtof
// ---------------------------------------------------------------------------

/// C `atof` -- converts string to double.
///
/// # Safety
///
/// Caller must ensure `nptr` is a valid null-terminated string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atof(nptr: *const c_char) -> f64 {
    if nptr.is_null() {
        return 0.0;
    }

    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        nptr as usize,
        0,
        false,
        known_remaining(nptr as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        return 0.0;
    }

    // SAFETY: caller guarantees nptr is valid NUL-terminated.
    let mut len = 0usize;
    unsafe {
        while *nptr.add(len) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(nptr.cast::<u8>(), len + 1) };
    let result = frankenlibc_core::stdlib::atof(slice);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, false);
    result
}

/// C `strtod` -- converts string to double with endptr.
///
/// # Safety
///
/// Caller must ensure `nptr` is a valid null-terminated string.
/// `endptr`, if non-null, will be set to point past the last parsed character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtod(nptr: *const c_char, endptr: *mut *mut c_char) -> f64 {
    if nptr.is_null() {
        if !endptr.is_null() {
            unsafe { *endptr = nptr as *mut c_char };
        }
        return 0.0;
    }

    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        nptr as usize,
        0,
        false,
        known_remaining(nptr as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        if !endptr.is_null() {
            unsafe { *endptr = nptr as *mut c_char };
        }
        return 0.0;
    }

    // SAFETY: caller guarantees nptr is valid NUL-terminated.
    let mut len = 0usize;
    unsafe {
        while *nptr.add(len) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(nptr.cast::<u8>(), len + 1) };
    let (val, consumed) = frankenlibc_core::stdlib::strtod(slice);
    if !endptr.is_null() {
        unsafe { *endptr = nptr.add(consumed) as *mut c_char };
    }
    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(5, consumed),
        false,
    );
    val
}

/// C `strtof` -- converts string to float with endptr.
///
/// # Safety
///
/// Same safety requirements as `strtod`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtof(nptr: *const c_char, endptr: *mut *mut c_char) -> f32 {
    // SAFETY: same contract as strtod.
    unsafe { strtod(nptr, endptr) as f32 }
}

// ---------------------------------------------------------------------------
// system
// ---------------------------------------------------------------------------

/// POSIX `system` — execute a shell command.
///
/// If `command` is NULL, returns non-zero to indicate a shell is available.
/// Otherwise, forks and executes `/bin/sh -c command`, returning the exit status.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn system(command: *const c_char) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 50, true);
        return -1;
    }

    if command.is_null() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, false);
        return 1; // shell is available
    }

    // SAFETY: fork via clone(SIGCHLD).
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone as c_long,
            libc::SIGCHLD as c_long,
            0 as c_long,
            0 as c_long,
            0 as c_long,
            0 as c_long,
        ) as i32
    };

    if pid < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOMEM);
        unsafe { set_abi_errno(e) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 50, true);
        return -1;
    }

    if pid == 0 {
        // Child process: exec /bin/sh -c command.
        let sh = c"/bin/sh".as_ptr();
        let dash_c = c"-c".as_ptr();
        let argv: [*const c_char; 4] = [sh, dash_c, command, ptr::null()];
        // SAFETY: argv is well-formed null-terminated array.
        unsafe {
            libc::syscall(
                libc::SYS_execve as c_long,
                sh,
                argv.as_ptr(),
                std::ptr::null::<*const c_char>(),
            );
            // If execve returns, exit with 127.
            libc::syscall(libc::SYS_exit_group as c_long, 127 as c_long);
            std::hint::unreachable_unchecked()
        }
    }

    // Parent: wait for child.
    let mut wstatus: c_int = 0;
    loop {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_wait4 as c_long,
                pid,
                &mut wstatus as *mut c_int,
                0,
                ptr::null::<c_void>(),
            )
        };
        if ret == pid as i64 {
            break;
        }
        if ret < 0 {
            let e = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINTR);
            if e != libc::EINTR {
                unsafe { set_abi_errno(e) };
                runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 50, true);
                return -1;
            }
        }
    }

    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 50, false);
    wstatus
}

// ---------------------------------------------------------------------------
// putenv
// ---------------------------------------------------------------------------

/// POSIX `putenv` — change or add an environment variable.
///
/// The string must be of the form `NAME=value`. Unlike `setenv`, the string
/// itself is stored in the environment (not a copy), so it must remain valid.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putenv(string: *mut c_char) -> c_int {
    if string.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, true);
        return -1;
    }

    // Find '=' to split name and value.
    let s = unsafe { std::ffi::CStr::from_ptr(string) };
    let bytes = s.to_bytes();
    if bytes.iter().position(|&b| b == b'=').is_none() {
        // No '=': unset the variable (glibc behavior).
        return unsafe { super::stdlib_abi::unsetenv(string) };
    }

    // Delegate to native putenv.
    let ret = unsafe { native_putenv_sym(string) };

    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, ret != 0);
    ret
}

// ---------------------------------------------------------------------------
// Additional stdlib — temp file helpers
// ---------------------------------------------------------------------------

const MKTEMP_SUFFIX_LEN: usize = 6;
const MKTEMP_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const MKOSTEMP_ALLOWED_FLAGS: c_int =
    libc::O_APPEND | libc::O_CLOEXEC | libc::O_SYNC | libc::O_DSYNC | libc::O_RSYNC;

static MKTEMP_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

unsafe fn mkostemps_inner(template: *mut c_char, suffixlen: c_int, flags: c_int) -> (c_int, bool) {
    if template.is_null() || suffixlen < 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
        return (-1, true);
    }
    if flags & !MKOSTEMP_ALLOWED_FLAGS != 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
        return (-1, true);
    }

    // SAFETY: `template` must be a writable, NUL-terminated byte string by ABI contract.
    let template_bytes = unsafe { std::ffi::CStr::from_ptr(template) }.to_bytes();
    let total_len = template_bytes.len();
    let suffix_len = suffixlen as usize;
    if total_len < MKTEMP_SUFFIX_LEN || suffix_len > total_len.saturating_sub(MKTEMP_SUFFIX_LEN) {
        unsafe { set_abi_errno(libc::EINVAL) };
        return (-1, true);
    }

    let x_start = total_len - suffix_len - MKTEMP_SUFFIX_LEN;
    if !template_bytes[x_start..x_start + MKTEMP_SUFFIX_LEN]
        .iter()
        .all(|&b| b == b'X')
    {
        unsafe { set_abi_errno(libc::EINVAL) };
        return (-1, true);
    }

    // SAFETY: `template` points to writable storage at least `total_len + 1` bytes long.
    let buf = unsafe { std::slice::from_raw_parts_mut(template as *mut u8, total_len) };
    let seed = mix64(
        (std::process::id() as u64).wrapping_shl(32)
            ^ (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0))
            ^ MKTEMP_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    );

    for attempt in 0_u64..256 {
        let mut state = mix64(seed ^ attempt.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        for idx in 0..MKTEMP_SUFFIX_LEN {
            state = mix64(state.wrapping_add(idx as u64));
            buf[x_start + idx] = MKTEMP_CHARS[(state as usize) % MKTEMP_CHARS.len()];
        }

        // SAFETY: `template` now names a candidate pathname and points to NUL-terminated bytes.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                template as *const c_char,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | flags,
                0o600,
            ) as c_int
        };
        if fd >= 0 {
            return (fd, false);
        }

        let err = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if err != libc::EEXIST {
            unsafe { set_abi_errno(err) };
            return (-1, true);
        }
    }

    unsafe { set_abi_errno(libc::EEXIST) };
    (-1, true)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn reallocarray(ptr: *mut c_void, nmemb: usize, size: usize) -> *mut c_void {
    let Some(total_size) = nmemb.checked_mul(size) else {
        // POSIX/glibc semantics: overflow is an allocation failure with ENOMEM.
        unsafe { set_abi_errno(libc::ENOMEM) };
        // Can't easily observe without a decision profile, but we can just return null.
        return ptr::null_mut();
    };

    let adverse_pointer = !ptr.is_null() && known_remaining(ptr as usize).is_none();
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        ptr as usize,
        total_size,
        true,
        adverse_pointer,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return ptr::null_mut();
    }

    // SAFETY: ABI contract matches realloc; overflow has already been checked.
    let out = unsafe { crate::malloc_abi::realloc(ptr, total_size) };
    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(8, total_size.max(1)),
        out.is_null(),
    );
    out
}

/// `strtold` — convert string to long double (on x86_64, same as f64).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtold(nptr: *const c_char, endptr: *mut *mut c_char) -> f64 {
    // SAFETY: ABI contract mirrors strtod and current ABI model treats long double as f64.
    unsafe { strtod(nptr, endptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemp(template: *mut c_char, flags: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        template as usize,
        0,
        true,
        template.is_null() || known_remaining(template as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        return -1;
    }

    let (fd, failed) = unsafe { mkostemps_inner(template, 0, flags) };
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 18, failed);
    fd
}

// ---------------------------------------------------------------------------
// mkstemps / mkostemps / clearenv
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemps(template: *mut c_char, suffixlen: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        template as usize,
        0,
        true,
        template.is_null() || known_remaining(template as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        return -1;
    }

    let (fd, failed) = unsafe { mkostemps_inner(template, suffixlen, 0) };
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 18, failed);
    fd
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemps(template: *mut c_char, suffixlen: c_int, flags: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        template as usize,
        0,
        true,
        template.is_null() || known_remaining(template as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        return -1;
    }

    let (fd, failed) = unsafe { mkostemps_inner(template, suffixlen, flags) };
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 18, failed);
    fd
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clearenv() -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return -1;
    }

    let mut names = Vec::<Vec<u8>>::new();
    // SAFETY: HOST_ENVIRON is owned by libc; we only read and copy entry names.
    unsafe {
        let mut cursor = HOST_ENVIRON;
        if !cursor.is_null() {
            while !(*cursor).is_null() {
                let entry = std::ffi::CStr::from_ptr(*cursor).to_bytes();
                if let Some(eq_pos) = entry.iter().position(|&b| b == b'=') {
                    let name = &entry[..eq_pos];
                    if frankenlibc_core::stdlib::valid_env_name(name) {
                        let mut owned = Vec::with_capacity(name.len() + 1);
                        owned.extend_from_slice(name);
                        owned.push(0);
                        names.push(owned);
                    }
                }
                cursor = cursor.add(1);
            }
        }
    }

    let mut had_error = false;
    for name in &names {
        // SAFETY: names are copied from environ keys and explicitly NUL-terminated.
        if unsafe { native_unsetenv(name.as_ptr() as *const c_char) } != 0 {
            had_error = true;
        }
    }

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(8, names.len()),
        had_error,
    );
    if had_error { -1 } else { 0 }
}

// ===========================================================================
// drand48 family (9 functions)
// ===========================================================================

/// `drand48` — return a double in [0.0, 1.0) using global 48-bit state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn drand48() -> c_double {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0.0;
    }
    let result = frankenlibc_core::stdlib::drand48();
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result
}

/// `erand48` — return a double in [0.0, 1.0) using caller-supplied state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erand48(xsubi: *mut u16) -> c_double {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        xsubi as usize,
        0,
        true,
        xsubi.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) || xsubi.is_null() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0.0;
    }
    let state = unsafe { &mut *(xsubi as *mut [u16; 3]) };
    let result = frankenlibc_core::stdlib::erand48(state);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result
}

/// `lrand48` — return non-negative long in [0, 2^31) using global state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrand48() -> c_long {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0;
    }
    let result = frankenlibc_core::stdlib::lrand48();
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result as c_long
}

/// `nrand48` — return non-negative long using caller-supplied state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nrand48(xsubi: *mut u16) -> c_long {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        xsubi as usize,
        0,
        true,
        xsubi.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) || xsubi.is_null() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0;
    }
    let state = unsafe { &mut *(xsubi as *mut [u16; 3]) };
    let result = frankenlibc_core::stdlib::nrand48(state);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result as c_long
}

/// `mrand48` — return signed long in [-2^31, 2^31) using global state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mrand48() -> c_long {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0;
    }
    let result = frankenlibc_core::stdlib::mrand48();
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result as c_long
}

/// `jrand48` — return signed long using caller-supplied state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jrand48(xsubi: *mut u16) -> c_long {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        xsubi as usize,
        0,
        true,
        xsubi.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) || xsubi.is_null() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0;
    }
    let state = unsafe { &mut *(xsubi as *mut [u16; 3]) };
    let result = frankenlibc_core::stdlib::jrand48(state);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result as c_long
}

/// `srand48` — seed the global 48-bit state from a single long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn srand48(seedval: c_long) {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return;
    }
    frankenlibc_core::stdlib::srand48(seedval);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
}

/// `seed48` — seed global state with three u16 values; return old seed.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn seed48(seed16v: *mut u16) -> *mut u16 {
    // Static buffer for returning old seed (matching glibc's static buffer approach).
    static mut OLD_SEED: [u16; 3] = [0; 3];

    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        seed16v as usize,
        0,
        true,
        seed16v.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) || seed16v.is_null() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return std::ptr::addr_of_mut!(OLD_SEED) as *mut u16;
    }
    let input = unsafe { &*(seed16v as *const [u16; 3]) };
    let old = frankenlibc_core::stdlib::seed48(input);
    unsafe {
        let p = std::ptr::addr_of_mut!(OLD_SEED);
        (*p) = old;
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
        p as *mut u16
    }
}

/// `lcong48` — set all 48-bit LCG parameters.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lcong48(param: *mut u16) {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        param as usize,
        0,
        true,
        param.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) || param.is_null() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return;
    }
    let p = unsafe { &*(param as *const [u16; 7]) };
    frankenlibc_core::stdlib::lcong48(p);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
}

// ===========================================================================
// System V random family (4 functions)
// ===========================================================================

/// `random` — return a pseudo-random number in [0, 2^31-1].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn random() -> c_long {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0;
    }
    let result = frankenlibc_core::stdlib::sv_random();
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result as c_long
}

/// `srandom` — seed the random number generator.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn srandom(seed: c_uint) {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return;
    }
    frankenlibc_core::stdlib::srandom(seed);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
}

/// `initstate` — initialize and return state buffer for random().
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn initstate(seed: c_uint, state: *mut c_char, size: usize) -> *mut c_char {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        state as usize,
        size,
        true,
        state.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) || state.is_null() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return ptr::null_mut();
    }
    let buf = unsafe { std::slice::from_raw_parts_mut(state as *mut u8, size) };
    let _ = frankenlibc_core::stdlib::initstate(seed, buf);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, false);
    state
}

/// `setstate` — restore random state from a previously saved buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setstate(state: *mut c_char) -> *mut c_char {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        state as usize,
        0,
        true,
        state.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) || state.is_null() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return ptr::null_mut();
    }
    // glibc setstate expects a buffer of at least 8 bytes; use a safe upper bound.
    let buf = unsafe { std::slice::from_raw_parts(state as *const u8, 128) };
    let _ = frankenlibc_core::stdlib::setstate(buf);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, false);
    state
}

// ===========================================================================
// qsort_r (1 function)
// ===========================================================================

/// `qsort_r` — sort array with reentrant comparator (GNU extension).
///
/// The comparator receives the context pointer as its third argument.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn qsort_r(
    base: *mut c_void,
    nmemb: usize,
    size: usize,
    compar: Option<unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int>,
    arg: *mut c_void,
) {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        base as usize,
        nmemb.saturating_mul(size),
        true,
        base.is_null() || compar.is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 12, true);
        return;
    }

    if base.is_null() || nmemb == 0 || size == 0 || compar.is_none() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
        return;
    }

    let cmp_fn = compar.unwrap();
    let total = nmemb.saturating_mul(size);
    let slice = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, total) };

    frankenlibc_core::stdlib::qsort(slice, size, |a, b| unsafe {
        cmp_fn(
            a.as_ptr() as *const c_void,
            b.as_ptr() as *const c_void,
            arg,
        )
    });

    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 12, false);
}

// ===========================================================================
// a64l / l64a (2 functions)
// ===========================================================================

/// `a64l` — convert base-64 encoded string to long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn a64l(s: *const c_char) -> c_long {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Stdlib, s as usize, 0, true, s.is_null(), 0);
    if matches!(decision.action, MembraneAction::Deny) || s.is_null() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0;
    }
    let (len, _) = unsafe { scan_c_string(s, Some(6)) };
    let slice = unsafe { std::slice::from_raw_parts(s as *const u8, len) };
    let result = frankenlibc_core::stdlib::a64l(slice);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result as c_long
}

/// `l64a` — convert long to base-64 encoded string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn l64a(value: c_long) -> *mut c_char {
    // Static buffer for returned string (matching glibc's static buffer).
    static mut BUF: [u8; 8] = [0; 8];

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        unsafe {
            let p = std::ptr::addr_of_mut!(BUF);
            (*p)[0] = 0;
            return p as *mut u8 as *mut c_char;
        }
    }
    let encoded = frankenlibc_core::stdlib::l64a(value);
    unsafe {
        let p = std::ptr::addr_of_mut!(BUF);
        let buf = &mut *p;
        let len = encoded.len().min(7);
        buf[..len].copy_from_slice(&encoded[..len]);
        buf[len] = 0;
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
        p as *mut u8 as *mut c_char
    }
}

// ===========================================================================
// ecvt / fcvt / gcvt (3 functions)
// ===========================================================================

/// `ecvt` — convert double to string (scientific notation digits).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ecvt(
    value: c_double,
    ndigit: c_int,
    decpt: *mut c_int,
    sign: *mut c_int,
) -> *mut c_char {
    // Static buffer (matching glibc's thread-unsafe static buffer).
    static mut BUF: [u8; 384] = [0; 384];

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        unsafe {
            let p = std::ptr::addr_of_mut!(BUF);
            (*p)[0] = 0;
            return p as *mut u8 as *mut c_char;
        }
    }

    let (digits, dp, neg) = frankenlibc_core::stdlib::ecvt(value, ndigit);
    unsafe {
        let p = std::ptr::addr_of_mut!(BUF);
        let buf = &mut *p;
        let len = digits.len().min(383);
        buf[..len].copy_from_slice(&digits[..len]);
        buf[len] = 0;
        if !decpt.is_null() {
            *decpt = dp;
        }
        if !sign.is_null() {
            *sign = if neg { 1 } else { 0 };
        }
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, false);
        p as *mut u8 as *mut c_char
    }
}

/// `fcvt` — convert double to string (fixed-point digits).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fcvt(
    value: c_double,
    ndigit: c_int,
    decpt: *mut c_int,
    sign: *mut c_int,
) -> *mut c_char {
    static mut BUF: [u8; 384] = [0; 384];

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        unsafe {
            let p = std::ptr::addr_of_mut!(BUF);
            (*p)[0] = 0;
            return p as *mut u8 as *mut c_char;
        }
    }

    let (digits, dp, neg) = frankenlibc_core::stdlib::fcvt(value, ndigit);
    unsafe {
        let p = std::ptr::addr_of_mut!(BUF);
        let buf = &mut *p;
        let len = digits.len().min(383);
        buf[..len].copy_from_slice(&digits[..len]);
        buf[len] = 0;
        if !decpt.is_null() {
            *decpt = dp;
        }
        if !sign.is_null() {
            *sign = if neg { 1 } else { 0 };
        }
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, false);
        p as *mut u8 as *mut c_char
    }
}

/// `gcvt` — convert double to string using general format.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gcvt(value: c_double, ndigit: c_int, buf: *mut c_char) -> *mut c_char {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Stdlib, buf as usize, 0, true, buf.is_null(), 0);
    if matches!(decision.action, MembraneAction::Deny) || buf.is_null() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        return buf;
    }

    // Assume caller's buffer is at least ndigit + 16 bytes (glibc doesn't bounds-check).
    let buf_size = (ndigit as usize).saturating_add(32).min(512);
    let slice = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, buf_size) };
    frankenlibc_core::stdlib::gcvt(value, ndigit, slice);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, false);
    buf
}

// ===========================================================================
// Process control (3 functions)
// ===========================================================================

/// `abort` — abnormal process termination.
///
/// Raises SIGABRT. If caught, re-raises after resetting the handler.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn abort() -> ! {
    // Flush stdout/stderr before aborting.
    let _ = unsafe { libc::fflush(ptr::null_mut()) };
    // Raise SIGABRT. If the signal handler returns, re-raise with default.
    unsafe {
        libc::raise(libc::SIGABRT);
        // If we get here, reset handler and raise again.
        libc::signal(libc::SIGABRT, libc::SIG_DFL);
        libc::raise(libc::SIGABRT);
    }
    // Should never reach here, but the compiler needs a diverging path.
    unsafe { libc::_exit(134) }
}

/// Exit handler entry for `on_exit` — stores function pointer + arg.
#[allow(dead_code)]
struct OnExitEntry {
    func: unsafe extern "C" fn(c_int, *mut c_void),
    arg: *mut c_void,
}

// SAFETY: on_exit entries are only accessed from the exit handler chain,
// which runs in a single-threaded context (process exit).
unsafe impl Send for OnExitEntry {}
unsafe impl Sync for OnExitEntry {}

static ON_EXIT_HANDLERS: std::sync::Mutex<Vec<OnExitEntry>> = std::sync::Mutex::new(Vec::new());

/// `on_exit` — register a function to be called at exit (with status and arg).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn on_exit(
    func: Option<unsafe extern "C" fn(c_int, *mut c_void)>,
    arg: *mut c_void,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, func.is_none(), 0);
    if matches!(decision.action, MembraneAction::Deny) || func.is_none() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return -1;
    }
    let f = func.unwrap();
    if let Ok(mut handlers) = ON_EXIT_HANDLERS.lock() {
        handlers.push(OnExitEntry { func: f, arg });
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
        0
    } else {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        -1
    }
}

/// Exit handler entries for `at_quick_exit`.
static QUICK_EXIT_HANDLERS: std::sync::Mutex<Vec<unsafe extern "C" fn()>> =
    std::sync::Mutex::new(Vec::new());

/// `at_quick_exit` — register a function to be called at quick_exit.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn at_quick_exit(func: Option<unsafe extern "C" fn()>) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, func.is_none(), 0);
    if matches!(decision.action, MembraneAction::Deny) || func.is_none() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return -1;
    }
    let f = func.unwrap();
    if let Ok(mut handlers) = QUICK_EXIT_HANDLERS.lock() {
        handlers.push(f);
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
        0
    } else {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        -1
    }
}

/// `quick_exit` — rapid process termination, calling at_quick_exit handlers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn quick_exit(status: c_int) -> ! {
    // Call registered quick_exit handlers in reverse order.
    if let Ok(handlers) = QUICK_EXIT_HANDLERS.lock() {
        for func in handlers.iter().rev() {
            unsafe { func() };
        }
    }
    unsafe { libc::_exit(status) }
}

// ===========================================================================
// getsubopt (1 function)
// ===========================================================================

/// `getsubopt` — parse suboption from comma-separated string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsubopt(
    optionp: *mut *mut c_char,
    tokens: *const *mut c_char,
    valuep: *mut *mut c_char,
) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        optionp as usize,
        0,
        true,
        optionp.is_null() || tokens.is_null() || valuep.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny)
        || optionp.is_null()
        || tokens.is_null()
        || valuep.is_null()
    {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        return -1;
    }

    let opt_ptr = unsafe { *optionp };
    if opt_ptr.is_null() || unsafe { *opt_ptr } == 0 {
        unsafe { *valuep = ptr::null_mut() };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
        return -1;
    }

    // Find end of this suboption (comma or NUL).
    let mut end = opt_ptr;
    unsafe {
        while *end != 0 && *end != b',' as c_char {
            end = end.add(1);
        }
    }

    // Find '=' for value separation.
    let mut eq = opt_ptr;
    let mut has_eq = false;
    unsafe {
        while eq < end {
            if *eq == b'=' as c_char {
                has_eq = true;
                break;
            }
            eq = eq.add(1);
        }
    }

    let name_end = if has_eq { eq } else { end };

    // Set valuep.
    unsafe {
        if has_eq {
            *valuep = eq.add(1);
        } else {
            *valuep = ptr::null_mut();
        }
    }

    // NUL-terminate the name portion temporarily if needed, then match.
    let saved = unsafe { *name_end };
    unsafe { *name_end = 0 };

    // Advance optionp past this suboption.
    unsafe {
        if *end == b',' as c_char {
            *optionp = end.add(1);
        } else {
            *optionp = end;
        }
    }

    // Match against token list.
    let mut idx = 0i32;
    let mut tok_ptr = tokens;
    unsafe {
        while !(*tok_ptr).is_null() {
            if libc::strcmp(opt_ptr, *tok_ptr) == 0 {
                *name_end = saved;
                runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, false);
                return idx;
            }
            tok_ptr = tok_ptr.add(1);
            idx += 1;
        }
    }

    // Restore original char.
    unsafe { *name_end = saved };
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, false);
    -1
}

// ---------------------------------------------------------------------------
// gnu_get_libc_version / gnu_get_libc_release
// ---------------------------------------------------------------------------

/// FrankenLibC version string reported via `gnu_get_libc_version()`.
///
/// We report glibc 2.38 compatibility to satisfy programs that check the
/// version string for minimum feature requirements.
static GNU_LIBC_VERSION: &[u8] = b"2.38\0";

/// GNU `gnu_get_libc_version` — return glibc-compatible version string.
///
/// Returns a static string like "2.38". Programs use this to detect glibc
/// features at runtime.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gnu_get_libc_version() -> *const c_char {
    GNU_LIBC_VERSION.as_ptr() as *const c_char
}

/// POSIX `confstr` — get configuration-dependent string variable.
///
/// Returns the length of the string value for the given `name`, or 0 on error.
/// If `buf` is non-null and `len` > 0, copies the value into `buf`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn confstr(name: c_int, buf: *mut c_char, len: usize) -> usize {
    // _CS_GNU_LIBC_VERSION = 2 on Linux/glibc
    // _CS_GNU_LIBPTHREAD_VERSION = 3
    // _CS_PATH = 0
    let value: &[u8] = match name {
        0 => b"/usr/bin\0",   // _CS_PATH
        2 => b"glibc 2.38\0", // _CS_GNU_LIBC_VERSION
        3 => b"NPTL 2.38\0",  // _CS_GNU_LIBPTHREAD_VERSION
        _ => {
            unsafe { set_abi_errno(libc::EINVAL) };
            return 0;
        }
    };

    let value_len = value.len(); // includes NUL
    if !buf.is_null() && len > 0 {
        let copy_len = std::cmp::min(len, value_len);
        unsafe {
            std::ptr::copy_nonoverlapping(value.as_ptr(), buf as *mut u8, copy_len);
        }
        // Ensure NUL termination if we truncated.
        if copy_len < value_len && len > 0 {
            unsafe { *buf.add(len - 1) = 0 };
        }
    }
    value_len
}

// ===========================================================================
// Batch: GNU hash table (hsearch) — Implemented
// ===========================================================================

use std::sync::Mutex;

unsafe extern "C" {
    static program_invocation_short_name: *const c_char;
}

/// POSIX hash action for `hsearch`.
#[repr(C)]
#[allow(non_camel_case_types, dead_code)]
pub enum HashAction {
    FIND = 0,
    ENTER = 1,
}

/// POSIX hash table entry.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct HashEntry {
    pub key: *mut c_char,
    pub data: *mut c_void,
}

/// Internal hash table slot.
struct HashSlot {
    key: String,
    data: *mut c_void,
}

// SAFETY: `data` is an opaque user pointer; the user is responsible for
// not racing on it.  We only access it under the global HTAB lock.
unsafe impl Send for HashSlot {}

static HTAB: Mutex<Option<Vec<Option<HashSlot>>>> = Mutex::new(None);

fn hash_key(key: &str, cap: usize) -> usize {
    // djb2 hash
    let mut h: u64 = 5381;
    for b in key.bytes() {
        h = h.wrapping_mul(33).wrapping_add(b as u64);
    }
    (h as usize) % cap
}

/// `hcreate` — create a POSIX hash table.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn hcreate(nel: usize) -> c_int {
    let cap = if nel == 0 { 128 } else { nel };
    let mut table: Vec<Option<HashSlot>> = Vec::with_capacity(cap);
    table.resize_with(cap, || None);
    let mut guard = HTAB.lock().unwrap();
    *guard = Some(table);
    1
}

/// `hdestroy` — destroy the POSIX hash table.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn hdestroy() {
    let mut guard = HTAB.lock().unwrap();
    *guard = None;
}

/// `hsearch` — search/insert in the POSIX hash table.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hsearch(item: HashEntry, action: HashAction) -> *mut HashEntry {
    let key_cstr = if item.key.is_null() {
        return ptr::null_mut();
    } else {
        unsafe { CStr::from_ptr(item.key) }
    };
    let key_str = match key_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let mut guard = HTAB.lock().unwrap();
    let table = match guard.as_mut() {
        Some(t) => t,
        None => return ptr::null_mut(),
    };

    let cap = table.len();
    let start = hash_key(key_str, cap);

    // Linear probing
    for i in 0..cap {
        let idx = (start + i) % cap;
        match &table[idx] {
            Some(slot) if slot.key == key_str => {
                // Found existing entry — return pointer to it
                let slot = table[idx].as_mut().unwrap();
                // We need to return a pointer to an ENTRY. Use a thread-local buffer.
                thread_local! {
                    static RESULT: std::cell::RefCell<HashEntry> = const {
                        std::cell::RefCell::new(HashEntry {
                            key: std::ptr::null_mut(),
                            data: std::ptr::null_mut(),
                        })
                    };
                }
                return RESULT.with(|r| {
                    let mut entry = r.borrow_mut();
                    entry.key = slot.key.as_ptr() as *mut c_char;
                    entry.data = slot.data;
                    &mut *entry as *mut HashEntry
                });
            }
            None => match action {
                HashAction::ENTER => {
                    table[idx] = Some(HashSlot {
                        key: key_str.to_string(),
                        data: item.data,
                    });
                    thread_local! {
                        static RESULT2: std::cell::RefCell<HashEntry> = const {
                            std::cell::RefCell::new(HashEntry {
                                key: std::ptr::null_mut(),
                                data: std::ptr::null_mut(),
                            })
                        };
                    }
                    let slot = table[idx].as_mut().unwrap();
                    return RESULT2.with(|r| {
                        let mut entry = r.borrow_mut();
                        entry.key = slot.key.as_ptr() as *mut c_char;
                        entry.data = slot.data;
                        &mut *entry as *mut HashEntry
                    });
                }
                HashAction::FIND => return ptr::null_mut(),
            },
            _ => {} // occupied by different key, continue probing
        }
    }

    // Table full
    unsafe { set_abi_errno(libc::ENOMEM) };
    ptr::null_mut()
}

/// Reentrant hash table data.
struct HashTableR {
    slots: Vec<Option<HashSlot>>,
}

/// `hcreate_r` — create a reentrant hash table.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hcreate_r(nel: usize, htab: *mut c_void) -> c_int {
    if htab.is_null() {
        return 0;
    }
    let cap = if nel == 0 { 128 } else { nel };
    let mut table: Vec<Option<HashSlot>> = Vec::with_capacity(cap);
    table.resize_with(cap, || None);
    let boxed = Box::new(HashTableR { slots: table });
    unsafe { *(htab as *mut *mut HashTableR) = Box::into_raw(boxed) };
    1
}

/// `hdestroy_r` — destroy a reentrant hash table.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hdestroy_r(htab: *mut c_void) {
    if htab.is_null() {
        return;
    }
    let ptr = unsafe { *(htab as *mut *mut HashTableR) };
    if !ptr.is_null() {
        let _ = unsafe { Box::from_raw(ptr) };
        unsafe { *(htab as *mut *mut HashTableR) = ptr::null_mut() };
    }
}

/// `hsearch_r` — reentrant hash table search/insert.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hsearch_r(
    item: HashEntry,
    action: HashAction,
    retval: *mut *mut HashEntry,
    htab: *mut c_void,
) -> c_int {
    if htab.is_null() || retval.is_null() {
        return 0;
    }
    let table_ptr = unsafe { *(htab as *mut *mut HashTableR) };
    if table_ptr.is_null() {
        return 0;
    }
    let table = unsafe { &mut *table_ptr };

    let key_cstr = if item.key.is_null() {
        return 0;
    } else {
        unsafe { CStr::from_ptr(item.key) }
    };
    let key_str = match key_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let cap = table.slots.len();
    let start = hash_key(key_str, cap);

    for i in 0..cap {
        let idx = (start + i) % cap;
        match &table.slots[idx] {
            Some(slot) if slot.key == key_str => {
                thread_local! {
                    static RET: std::cell::RefCell<HashEntry> = const {
                        std::cell::RefCell::new(HashEntry {
                            key: std::ptr::null_mut(),
                            data: std::ptr::null_mut(),
                        })
                    };
                }
                let slot = table.slots[idx].as_mut().unwrap();
                RET.with(|r| {
                    let mut entry = r.borrow_mut();
                    entry.key = slot.key.as_ptr() as *mut c_char;
                    entry.data = slot.data;
                    unsafe { *retval = &mut *entry as *mut HashEntry };
                });
                return 1;
            }
            None => match action {
                HashAction::ENTER => {
                    table.slots[idx] = Some(HashSlot {
                        key: key_str.to_string(),
                        data: item.data,
                    });
                    thread_local! {
                        static RET2: std::cell::RefCell<HashEntry> = const {
                            std::cell::RefCell::new(HashEntry {
                                key: std::ptr::null_mut(),
                                data: std::ptr::null_mut(),
                            })
                        };
                    }
                    let slot = table.slots[idx].as_mut().unwrap();
                    RET2.with(|r| {
                        let mut entry = r.borrow_mut();
                        entry.key = slot.key.as_ptr() as *mut c_char;
                        entry.data = slot.data;
                        unsafe { *retval = &mut *entry as *mut HashEntry };
                    });
                    return 1;
                }
                HashAction::FIND => {
                    unsafe { *retval = ptr::null_mut() };
                    unsafe { set_abi_errno(libc::ESRCH) };
                    return 0;
                }
            },
            _ => {}
        }
    }
    unsafe { set_abi_errno(libc::ENOMEM) };
    0
}

// ===========================================================================
// Batch: getloadavg — Implemented
// ===========================================================================

/// `getloadavg` — get system load averages from /proc/loadavg.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getloadavg(loadavg: *mut c_double, nelem: c_int) -> c_int {
    if loadavg.is_null() || nelem <= 0 {
        return -1;
    }
    let n = std::cmp::min(nelem, 3) as usize;
    let content = match std::fs::read_to_string("/proc/loadavg") {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 3 {
        return -1;
    }
    let mut filled = 0usize;
    for (i, part) in parts.iter().enumerate().take(n) {
        match part.parse::<f64>() {
            Ok(val) => {
                unsafe { *loadavg.add(i) = val };
                filled += 1;
            }
            Err(_) => break,
        }
    }
    filled as c_int
}

// ===========================================================================
// Batch: error / error_at_line — Implemented
// ===========================================================================

/// Global error message count (GNU extension).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static mut error_message_count: c_uint = 0;

/// `error` — GNU error reporting function.
///
/// Prints "progname: format_message" to stderr. If errnum != 0,
/// appends ": strerror(errnum)". If status != 0, calls exit(status).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn error(status: c_int, errnum: c_int, fmt: *const c_char, mut args: ...) {
    use std::io::Write;

    unsafe { error_message_count += 1 };

    let mut stderr = std::io::stderr().lock();

    // Try to get program name
    let progname = unsafe {
        let p = program_invocation_short_name;
        if !p.is_null() {
            CStr::from_ptr(p).to_str().unwrap_or("unknown")
        } else {
            "unknown"
        }
    };

    let _ = write!(stderr, "{progname}: ");

    // Format the message
    if !fmt.is_null() {
        let fmt_str = unsafe { CStr::from_ptr(fmt) };
        if let Ok(f) = fmt_str.to_str() {
            // Simple format: just print as-is for common case.
            // For full printf compatibility, delegate to our printf engine.
            let msg = unsafe {
                crate::stdio_abi::vprintf_extract_and_render(
                    f,
                    (&mut args) as *mut _ as *mut c_void,
                )
            };
            let _ = write!(stderr, "{msg}");
        }
    }

    if errnum != 0 {
        let err_msg = unsafe {
            let p = libc::strerror(errnum);
            if !p.is_null() {
                CStr::from_ptr(p).to_str().unwrap_or("Unknown error")
            } else {
                "Unknown error"
            }
        };
        let _ = write!(stderr, ": {err_msg}");
    }

    let _ = writeln!(stderr);

    if status != 0 {
        std::process::exit(status);
    }
}

/// `error_at_line` — GNU error reporting with file/line info.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn error_at_line(
    status: c_int,
    errnum: c_int,
    filename: *const c_char,
    linenum: c_uint,
    fmt: *const c_char,
    mut args: ...
) {
    use std::io::Write;

    unsafe { error_message_count += 1 };

    let mut stderr = std::io::stderr().lock();

    let progname = unsafe {
        let p = program_invocation_short_name;
        if !p.is_null() {
            CStr::from_ptr(p).to_str().unwrap_or("unknown")
        } else {
            "unknown"
        }
    };

    let _ = write!(stderr, "{progname}:");

    if !filename.is_null() {
        let fname = unsafe { CStr::from_ptr(filename) };
        if let Ok(f) = fname.to_str() {
            let _ = write!(stderr, "{f}:{linenum}: ");
        }
    }

    if !fmt.is_null() {
        let fmt_str = unsafe { CStr::from_ptr(fmt) };
        if let Ok(f) = fmt_str.to_str() {
            let msg = unsafe {
                crate::stdio_abi::vprintf_extract_and_render(
                    f,
                    (&mut args) as *mut _ as *mut c_void,
                )
            };
            let _ = write!(stderr, "{msg}");
        }
    }

    if errnum != 0 {
        let err_msg = unsafe {
            let p = libc::strerror(errnum);
            if !p.is_null() {
                CStr::from_ptr(p).to_str().unwrap_or("Unknown error")
            } else {
                "Unknown error"
            }
        };
        let _ = write!(stderr, ": {err_msg}");
    }

    let _ = writeln!(stderr);

    if status != 0 {
        std::process::exit(status);
    }
}

// ===========================================================================
// Batch: BSD err/warn family — Implemented
// ===========================================================================

/// `err` — BSD error exit with errno message.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn err(eval: c_int, fmt: *const c_char, mut args: ...) {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();

    let progname = unsafe {
        let p = program_invocation_short_name;
        if !p.is_null() {
            CStr::from_ptr(p).to_str().unwrap_or("unknown")
        } else {
            "unknown"
        }
    };
    let _ = write!(stderr, "{progname}: ");

    if !fmt.is_null() {
        let fmt_str = unsafe { CStr::from_ptr(fmt) };
        if let Ok(f) = fmt_str.to_str() {
            let msg = unsafe {
                crate::stdio_abi::vprintf_extract_and_render(
                    f,
                    (&mut args) as *mut _ as *mut c_void,
                )
            };
            let _ = write!(stderr, "{msg}: ");
        }
    }

    let errno_val = unsafe { *super::errno_abi::__errno_location() };
    let err_msg = unsafe {
        let p = libc::strerror(errno_val);
        if !p.is_null() {
            CStr::from_ptr(p).to_str().unwrap_or("Unknown error")
        } else {
            "Unknown error"
        }
    };
    let _ = writeln!(stderr, "{err_msg}");
    std::process::exit(eval);
}

/// `errx` — BSD error exit without errno message.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn errx(eval: c_int, fmt: *const c_char, mut args: ...) {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();

    let progname = unsafe {
        let p = program_invocation_short_name;
        if !p.is_null() {
            CStr::from_ptr(p).to_str().unwrap_or("unknown")
        } else {
            "unknown"
        }
    };
    let _ = write!(stderr, "{progname}: ");

    if !fmt.is_null() {
        let fmt_str = unsafe { CStr::from_ptr(fmt) };
        if let Ok(f) = fmt_str.to_str() {
            let msg = unsafe {
                crate::stdio_abi::vprintf_extract_and_render(
                    f,
                    (&mut args) as *mut _ as *mut c_void,
                )
            };
            let _ = write!(stderr, "{msg}");
        }
    }

    let _ = writeln!(stderr);
    std::process::exit(eval);
}

/// `warn` — BSD warning with errno message.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn warn(fmt: *const c_char, mut args: ...) {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();

    let progname = unsafe {
        let p = program_invocation_short_name;
        if !p.is_null() {
            CStr::from_ptr(p).to_str().unwrap_or("unknown")
        } else {
            "unknown"
        }
    };
    let _ = write!(stderr, "{progname}: ");

    if !fmt.is_null() {
        let fmt_str = unsafe { CStr::from_ptr(fmt) };
        if let Ok(f) = fmt_str.to_str() {
            let msg = unsafe {
                crate::stdio_abi::vprintf_extract_and_render(
                    f,
                    (&mut args) as *mut _ as *mut c_void,
                )
            };
            let _ = write!(stderr, "{msg}: ");
        }
    }

    let errno_val = unsafe { *super::errno_abi::__errno_location() };
    let err_msg = unsafe {
        let p = libc::strerror(errno_val);
        if !p.is_null() {
            CStr::from_ptr(p).to_str().unwrap_or("Unknown error")
        } else {
            "Unknown error"
        }
    };
    let _ = writeln!(stderr, "{err_msg}");
}

/// `warnx` — BSD warning without errno message.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn warnx(fmt: *const c_char, mut args: ...) {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();

    let progname = unsafe {
        let p = program_invocation_short_name;
        if !p.is_null() {
            CStr::from_ptr(p).to_str().unwrap_or("unknown")
        } else {
            "unknown"
        }
    };
    let _ = write!(stderr, "{progname}: ");

    if !fmt.is_null() {
        let fmt_str = unsafe { CStr::from_ptr(fmt) };
        if let Ok(f) = fmt_str.to_str() {
            let msg = unsafe {
                crate::stdio_abi::vprintf_extract_and_render(
                    f,
                    (&mut args) as *mut _ as *mut c_void,
                )
            };
            let _ = write!(stderr, "{msg}");
        }
    }

    let _ = writeln!(stderr);
}

/// `verr` — BSD error exit with errno, va_list variant.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn verr(eval: c_int, fmt: *const c_char, ap: *mut c_void) {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();
    let progname = unsafe {
        let p = program_invocation_short_name;
        if !p.is_null() {
            CStr::from_ptr(p).to_str().unwrap_or("unknown")
        } else {
            "unknown"
        }
    };
    let _ = write!(stderr, "{progname}: ");
    if !fmt.is_null() {
        let fmt_str = unsafe { CStr::from_ptr(fmt) };
        if let Ok(f) = fmt_str.to_str() {
            let msg = unsafe { crate::stdio_abi::vprintf_extract_and_render(f, ap) };
            let _ = write!(stderr, "{msg}: ");
        }
    }
    let errno_val = unsafe { *super::errno_abi::__errno_location() };
    let err_msg = unsafe {
        let p = libc::strerror(errno_val);
        if !p.is_null() {
            CStr::from_ptr(p).to_str().unwrap_or("Unknown error")
        } else {
            "Unknown error"
        }
    };
    let _ = writeln!(stderr, "{err_msg}");
    std::process::exit(eval);
}

/// `verrx` — BSD error exit without errno, va_list variant.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn verrx(eval: c_int, fmt: *const c_char, ap: *mut c_void) {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();
    let progname = unsafe {
        let p = program_invocation_short_name;
        if !p.is_null() {
            CStr::from_ptr(p).to_str().unwrap_or("unknown")
        } else {
            "unknown"
        }
    };
    let _ = write!(stderr, "{progname}: ");
    if !fmt.is_null() {
        let fmt_str = unsafe { CStr::from_ptr(fmt) };
        if let Ok(f) = fmt_str.to_str() {
            let msg = unsafe { crate::stdio_abi::vprintf_extract_and_render(f, ap) };
            let _ = write!(stderr, "{msg}");
        }
    }
    let _ = writeln!(stderr);
    std::process::exit(eval);
}

/// `vwarn` — BSD warning with errno, va_list variant.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vwarn(fmt: *const c_char, ap: *mut c_void) {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();
    let progname = unsafe {
        let p = program_invocation_short_name;
        if !p.is_null() {
            CStr::from_ptr(p).to_str().unwrap_or("unknown")
        } else {
            "unknown"
        }
    };
    let _ = write!(stderr, "{progname}: ");
    if !fmt.is_null() {
        let fmt_str = unsafe { CStr::from_ptr(fmt) };
        if let Ok(f) = fmt_str.to_str() {
            let msg = unsafe { crate::stdio_abi::vprintf_extract_and_render(f, ap) };
            let _ = write!(stderr, "{msg}: ");
        }
    }
    let errno_val = unsafe { *super::errno_abi::__errno_location() };
    let err_msg = unsafe {
        let p = libc::strerror(errno_val);
        if !p.is_null() {
            CStr::from_ptr(p).to_str().unwrap_or("Unknown error")
        } else {
            "Unknown error"
        }
    };
    let _ = writeln!(stderr, "{err_msg}");
}

/// `vwarnx` — BSD warning without errno, va_list variant.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vwarnx(fmt: *const c_char, ap: *mut c_void) {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();
    let progname = unsafe {
        let p = program_invocation_short_name;
        if !p.is_null() {
            CStr::from_ptr(p).to_str().unwrap_or("unknown")
        } else {
            "unknown"
        }
    };
    let _ = write!(stderr, "{progname}: ");
    if !fmt.is_null() {
        let fmt_str = unsafe { CStr::from_ptr(fmt) };
        if let Ok(f) = fmt_str.to_str() {
            let msg = unsafe { crate::stdio_abi::vprintf_extract_and_render(f, ap) };
            let _ = write!(stderr, "{msg}");
        }
    }
    let _ = writeln!(stderr);
}

// ===========================================================================
// Batch: GNU sysconf extensions — Implemented
// ===========================================================================

/// `get_nprocs` — return number of online processors.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn get_nprocs() -> c_int {
    // Read /sys/devices/system/cpu/online, parse range "0-N" → N+1
    if let Ok(content) = std::fs::read_to_string("/sys/devices/system/cpu/online") {
        let content = content.trim();
        // Format: "0-7" or "0" or "0-3,5-7"
        let mut count = 0i32;
        for range in content.split(',') {
            let parts: Vec<&str> = range.split('-').collect();
            if parts.len() == 2
                && let (Ok(lo), Ok(hi)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>())
            {
                count += hi - lo + 1;
            } else if parts.len() == 1 && parts[0].parse::<i32>().is_ok() {
                count += 1;
            }
        }
        if count > 0 {
            return count;
        }
    }
    1 // fallback
}

/// `get_nprocs_conf` — return number of configured processors.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn get_nprocs_conf() -> c_int {
    if let Ok(content) = std::fs::read_to_string("/sys/devices/system/cpu/present") {
        let content = content.trim();
        let mut count = 0i32;
        for range in content.split(',') {
            let parts: Vec<&str> = range.split('-').collect();
            if parts.len() == 2
                && let (Ok(lo), Ok(hi)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>())
            {
                count += hi - lo + 1;
            } else if parts.len() == 1 && parts[0].parse::<i32>().is_ok() {
                count += 1;
            }
        }
        if count > 0 {
            return count;
        }
    }
    1
}

/// `get_phys_pages` — return number of physical memory pages.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn get_phys_pages() -> c_long {
    if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                // MemTotal:       16384000 kB
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2
                    && let Ok(kb) = parts[1].parse::<c_long>()
                {
                    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
                    let page_size = if page_size > 0 { page_size } else { 4096 };
                    return (kb * 1024) / page_size;
                }
            }
        }
    }
    0
}

/// `get_avphys_pages` — return number of available physical memory pages.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn get_avphys_pages() -> c_long {
    if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if line.starts_with("MemAvailable:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2
                    && let Ok(kb) = parts[1].parse::<c_long>()
                {
                    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
                    let page_size = if page_size > 0 { page_size } else { 4096 };
                    return (kb * 1024) / page_size;
                }
            }
        }
    }
    0
}

// ===========================================================================
// Batch: POSIX binary search tree (tsearch family) — Implemented
// ===========================================================================

/// Internal binary tree node for tsearch.
struct TsearchNode {
    key: *const c_void,
    left: *mut TsearchNode,
    right: *mut TsearchNode,
}

/// `tsearch` — search/insert into a binary tree.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tsearch(
    key: *const c_void,
    rootp: *mut *mut c_void,
    compar: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
) -> *mut c_void {
    if rootp.is_null() {
        return ptr::null_mut();
    }

    let rootp = rootp as *mut *mut TsearchNode;
    let mut pp = rootp;

    while !unsafe { *pp }.is_null() {
        let node = unsafe { &mut **pp };
        let cmp = unsafe { compar(key, node.key) };
        if cmp < 0 {
            pp = &mut node.left;
        } else if cmp > 0 {
            pp = &mut node.right;
        } else {
            // Found: return pointer to the key pointer field
            return &mut node.key as *mut *const c_void as *mut c_void;
        }
    }

    // Not found: insert new node
    let new_node = Box::into_raw(Box::new(TsearchNode {
        key,
        left: ptr::null_mut(),
        right: ptr::null_mut(),
    }));
    unsafe { *pp = new_node };
    unsafe { &mut (*new_node).key as *mut *const c_void as *mut c_void }
}

/// `tfind` — search a binary tree without inserting.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tfind(
    key: *const c_void,
    rootp: *const *mut c_void,
    compar: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
) -> *mut c_void {
    if rootp.is_null() {
        return ptr::null_mut();
    }

    let mut node = unsafe { *(rootp as *const *mut TsearchNode) };

    while !node.is_null() {
        let n = unsafe { &*node };
        let cmp = unsafe { compar(key, n.key) };
        if cmp < 0 {
            node = n.left;
        } else if cmp > 0 {
            node = n.right;
        } else {
            return unsafe { &(*node).key as *const *const c_void as *mut c_void };
        }
    }

    ptr::null_mut()
}

/// `tdelete` — delete a node from a binary tree.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tdelete(
    key: *const c_void,
    rootp: *mut *mut c_void,
    compar: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
) -> *mut c_void {
    if rootp.is_null() {
        return ptr::null_mut();
    }

    let rootp = rootp as *mut *mut TsearchNode;
    let mut pp = rootp;
    let mut parent: *mut TsearchNode = ptr::null_mut();

    while !unsafe { *pp }.is_null() {
        let node = unsafe { &mut **pp };
        let cmp = unsafe { compar(key, node.key) };
        if cmp < 0 {
            parent = unsafe { *pp };
            pp = &mut node.left;
        } else if cmp > 0 {
            parent = unsafe { *pp };
            pp = &mut node.right;
        } else {
            // Found the node to delete
            let to_delete = unsafe { *pp };

            if node.left.is_null() {
                unsafe { *pp = node.right };
            } else if node.right.is_null() {
                unsafe { *pp = node.left };
            } else {
                // Two children: find in-order successor
                let mut succ_pp = &mut node.right as *mut *mut TsearchNode;
                while !unsafe { (**succ_pp).left }.is_null() {
                    succ_pp = unsafe { &mut (**succ_pp).left };
                }
                let succ = unsafe { *succ_pp };
                unsafe { *succ_pp = (*succ).right };
                unsafe {
                    (*succ).left = (*to_delete).left;
                    (*succ).right = (*to_delete).right;
                    *pp = succ;
                };
            }

            let _ = unsafe { Box::from_raw(to_delete) };

            // Return parent's key pointer (or NULL if root was deleted)
            if parent.is_null() {
                return ptr::null_mut();
            }
            return unsafe { &(*parent).key as *const *const c_void as *mut c_void };
        }
    }

    ptr::null_mut()
}

/// `twalk` — walk a binary tree in order.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn twalk(
    root: *const c_void,
    action: unsafe extern "C" fn(*const c_void, c_int, c_int),
) {
    // action(nodep, visit_order, depth) where visit_order: 0=preorder, 1=postorder, 2=endorder, 3=leaf
    unsafe fn walk(
        node: *const TsearchNode,
        action: unsafe extern "C" fn(*const c_void, c_int, c_int),
        depth: c_int,
    ) {
        if node.is_null() {
            return;
        }
        let n = unsafe { &*node };
        let nodep = &n.key as *const *const c_void as *const c_void;

        if n.left.is_null() && n.right.is_null() {
            // Leaf
            unsafe { action(nodep, 3, depth) };
        } else {
            unsafe { action(nodep, 0, depth) }; // preorder
            unsafe { walk(n.left, action, depth + 1) };
            unsafe { action(nodep, 1, depth) }; // postorder (inorder)
            unsafe { walk(n.right, action, depth + 1) };
            unsafe { action(nodep, 2, depth) }; // endorder
        }
    }

    unsafe { walk(root as *const TsearchNode, action, 0) };
}

/// `tdestroy` — destroy a binary tree, calling freefn for each node.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tdestroy(root: *mut c_void, freefn: unsafe extern "C" fn(*mut c_void)) {
    unsafe fn destroy_recursive(node: *mut TsearchNode, freefn: unsafe extern "C" fn(*mut c_void)) {
        if node.is_null() {
            return;
        }
        let n = unsafe { &*node };
        unsafe { destroy_recursive(n.left, freefn) };
        unsafe { destroy_recursive(n.right, freefn) };
        unsafe { freefn(n.key as *mut c_void) };
        let _ = unsafe { Box::from_raw(node) };
    }

    unsafe { destroy_recursive(root as *mut TsearchNode, freefn) };
}

// ===========================================================================
// Batch: lfind / lsearch — Implemented
// ===========================================================================

/// `lfind` — linear search an array.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lfind(
    key: *const c_void,
    base: *const c_void,
    nmemb: *mut usize,
    size: usize,
    compar: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
) -> *mut c_void {
    if key.is_null() || base.is_null() || nmemb.is_null() || size == 0 {
        return ptr::null_mut();
    }
    let n = unsafe { *nmemb };
    let base_bytes = base as *const u8;
    for i in 0..n {
        let elem = unsafe { base_bytes.add(i * size) as *const c_void };
        if unsafe { compar(key, elem) } == 0 {
            return elem as *mut c_void;
        }
    }
    ptr::null_mut()
}

/// `lsearch` — linear search an array, inserting if not found.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lsearch(
    key: *const c_void,
    base: *mut c_void,
    nmemb: *mut usize,
    size: usize,
    compar: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
) -> *mut c_void {
    if key.is_null() || base.is_null() || nmemb.is_null() || size == 0 {
        return ptr::null_mut();
    }
    let n = unsafe { *nmemb };
    let base_bytes = base as *mut u8;
    for i in 0..n {
        let elem = unsafe { base_bytes.add(i * size) as *const c_void };
        if unsafe { compar(key, elem) } == 0 {
            return elem as *mut c_void;
        }
    }
    // Not found: append
    let new_elem = unsafe { base_bytes.add(n * size) };
    unsafe {
        std::ptr::copy_nonoverlapping(key as *const u8, new_elem, size);
        *nmemb = n + 1;
    }
    new_elem as *mut c_void
}

// ===========================================================================
// Batch: getauxval — Implemented
// ===========================================================================

/// `getauxval` — retrieve a value from the auxiliary vector.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getauxval(type_: c_ulong) -> c_ulong {
    // Read from /proc/self/auxv (binary pairs of unsigned long)
    if let Ok(data) = std::fs::read("/proc/self/auxv") {
        let ptr_size = std::mem::size_of::<c_ulong>();
        let mut offset = 0;
        while offset + 2 * ptr_size <= data.len() {
            let at_type = c_ulong::from_ne_bytes(
                data[offset..offset + ptr_size].try_into().unwrap_or([0; 8]),
            );
            let at_val = c_ulong::from_ne_bytes(
                data[offset + ptr_size..offset + 2 * ptr_size]
                    .try_into()
                    .unwrap_or([0; 8]),
            );
            if at_type == 0 {
                break; // AT_NULL
            }
            if at_type == type_ {
                return at_val;
            }
            offset += 2 * ptr_size;
        }
    }
    unsafe { set_abi_errno(libc::ENOENT) };
    0
}

// ===========================================================================
// Batch: getusershell family — Implemented
// ===========================================================================

static VALID_SHELLS: &[&str] = &[
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "/bin/csh",
    "/bin/tcsh",
    "/bin/dash",
    "/bin/fish",
    "/usr/bin/bash",
    "/usr/bin/zsh",
    "/usr/bin/fish",
    "/usr/bin/tmux",
    "/bin/false",
    "/usr/sbin/nologin",
];

thread_local! {
    static SHELL_IDX: Cell<usize> = const { Cell::new(0) };
    static SHELL_CACHE: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// `getusershell` — get valid login shell from /etc/shells.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn getusershell() -> *mut c_char {
    SHELL_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.is_empty() {
            // Load from /etc/shells
            if let Ok(content) = std::fs::read_to_string("/etc/shells") {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        cache.push(format!("{line}\0"));
                    }
                }
            }
            if cache.is_empty() {
                // Fallback
                for s in VALID_SHELLS {
                    cache.push(format!("{s}\0"));
                }
            }
        }

        SHELL_IDX.with(|idx| {
            let i = idx.get();
            if i < cache.len() {
                idx.set(i + 1);
                cache[i].as_ptr() as *mut c_char
            } else {
                ptr::null_mut()
            }
        })
    })
}

/// `setusershell` — rewind the shell list iterator.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn setusershell() {
    SHELL_IDX.with(|idx| idx.set(0));
}

/// `endusershell` — close the shell list and free resources.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn endusershell() {
    SHELL_IDX.with(|idx| idx.set(0));
    SHELL_CACHE.with(|cache| cache.borrow_mut().clear());
}

// ===========================================================================
// Batch: gets / tmpnam_r — Implemented
// ===========================================================================

/// `gets` — read a line from stdin (DEPRECATED, insecure).
///
/// POSIX removed this in 2008; kept for legacy compatibility.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gets(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    let mut i = 0usize;
    loop {
        let mut ch: u8 = 0;
        let n = unsafe { libc::read(0, &mut ch as *mut u8 as *mut c_void, 1) };
        if n <= 0 {
            if i == 0 {
                return ptr::null_mut();
            }
            break;
        }
        if ch == b'\n' {
            break;
        }
        unsafe { *s.add(i) = ch as c_char };
        i += 1;
    }
    unsafe { *s.add(i) = 0 };
    s
}

/// `tmpnam_r` — generate unique temporary filename (reentrant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tmpnam_r(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    // Generate /tmp/tmpXXXXXX pattern and check uniqueness
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let pid = unsafe { libc::getpid() };
    let cnt = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!("/tmp/tmp{pid:06}{cnt:06}\0");
    let name_bytes = name.as_bytes();
    if name_bytes.len() > 20 {
        // Truncate to L_tmpnam
        unsafe {
            std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), s as *mut u8, 20);
            *s.add(19) = 0;
        }
    } else {
        unsafe {
            std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), s as *mut u8, name_bytes.len());
        }
    }
    s
}

// ===========================================================================
// Batch: cfmakeraw / cfsetspeed — Implemented
// ===========================================================================

/// `cfmakeraw` — set terminal attributes for raw mode.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfmakeraw(termios: *mut libc::termios) {
    if termios.is_null() {
        return;
    }
    unsafe { libc::cfmakeraw(termios) };
}

/// `cfsetspeed` — set both input and output baud rate.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetspeed(termios: *mut libc::termios, speed: libc::speed_t) -> c_int {
    if termios.is_null() {
        return -1;
    }
    let r1 = unsafe { libc::cfsetispeed(termios, speed) };
    let r2 = unsafe { libc::cfsetospeed(termios, speed) };
    if r1 < 0 || r2 < 0 { -1 } else { 0 }
}

// ===========================================================================
// Locale-aware _l variants — C/POSIX locale passthrough
// ===========================================================================

/// `strtod_l` — locale-aware string to double. C locale: delegates to strtod.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtod_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    _locale: *mut c_void,
) -> f64 {
    unsafe { strtod(nptr, endptr) }
}

/// `strtof_l` — locale-aware string to float.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtof_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    _locale: *mut c_void,
) -> f32 {
    unsafe { strtof(nptr, endptr) }
}

/// `strtold_l` — locale-aware string to long double.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtold_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    _locale: *mut c_void,
) -> f64 {
    unsafe { strtold(nptr, endptr) }
}

/// `strtol_l` — locale-aware string to long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtol_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_long {
    unsafe { strtol(nptr, endptr, base) }
}

/// `strtoul_l` — locale-aware string to unsigned long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoul_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_ulong {
    unsafe { strtoul(nptr, endptr, base) }
}

/// `strtoll_l` — locale-aware string to long long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoll_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_longlong {
    unsafe { strtoll(nptr, endptr, base) }
}

/// `strtoull_l` — locale-aware string to unsigned long long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoull_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_ulonglong {
    unsafe { strtoull(nptr, endptr, base) }
}

// ===========================================================================
// insque / remque — POSIX linked-list queue operations
// ===========================================================================

/// Doubly-linked queue element (matches glibc's expectation: two pointer fields at start).
#[repr(C)]
struct QElem {
    next: *mut QElem,
    prev: *mut QElem,
}

/// `insque` — insert element into a doubly-linked queue after `prev_elem`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn insque(elem: *mut c_void, prev_elem: *mut c_void) {
    if elem.is_null() {
        return;
    }
    let e = elem as *mut QElem;
    if prev_elem.is_null() {
        // Inserting as first element of new list
        unsafe {
            (*e).next = ptr::null_mut();
            (*e).prev = ptr::null_mut();
        }
    } else {
        let p = prev_elem as *mut QElem;
        unsafe {
            let next = (*p).next;
            (*e).next = next;
            (*e).prev = p;
            (*p).next = e;
            if !next.is_null() {
                (*next).prev = e;
            }
        }
    }
}

/// `remque` — remove element from a doubly-linked queue.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remque(elem: *mut c_void) {
    if elem.is_null() {
        return;
    }
    let e = elem as *mut QElem;
    unsafe {
        let prev = (*e).prev;
        let next = (*e).next;
        if !prev.is_null() {
            (*prev).next = next;
        }
        if !next.is_null() {
            (*next).prev = prev;
        }
    }
}

// ===========================================================================
// __xpg_strerror_r — POSIX strerror_r variant
// ===========================================================================

/// `__xpg_strerror_r` — XSI-compliant strerror_r (returns int, not char*).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __xpg_strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    if buf.is_null() || buflen == 0 {
        return libc::ERANGE;
    }
    let msg = frankenlibc_core::errno::strerror_message(errnum);
    let msg_bytes = msg.as_bytes();
    if msg_bytes.len() >= buflen {
        // Truncate and null-terminate
        unsafe {
            ptr::copy_nonoverlapping(msg_bytes.as_ptr(), buf as *mut u8, buflen - 1);
            *buf.add(buflen - 1) = 0;
        }
        return libc::ERANGE;
    }
    unsafe {
        ptr::copy_nonoverlapping(msg_bytes.as_ptr(), buf as *mut u8, msg_bytes.len());
        *buf.add(msg_bytes.len()) = 0;
    }
    0
}

// ===========================================================================
// gnu_get_libc_release — GNU libc version info
// ===========================================================================

/// `gnu_get_libc_release` — return the release of the C library.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gnu_get_libc_release() -> *const c_char {
    b"stable\0".as_ptr() as *const c_char
}
