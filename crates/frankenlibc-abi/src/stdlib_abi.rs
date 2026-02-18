//! ABI stubs for stdlib functions.
//!
//! Implements numeric conversion functions (`atoi`, `atol`, `strtol`, `strtoul`),
//! environment variables (`getenv`, `setenv`, `unsetenv`),
//! process control (`exit`, `atexit`), and sorting/searching (`qsort`, `bsearch`)
//! with membrane validation.

use std::ffi::{c_char, c_int, c_long, c_longlong, c_uint, c_ulong, c_ulonglong, c_void};
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

    let (val, consumed, _status) = frankenlibc_core::stdlib::conversion::strtol_impl(slice, base);

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

    let (val, consumed, _status) =
        frankenlibc_core::stdlib::conversion::strtoimax_impl(slice, base);

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

    let (val, consumed, _status) = frankenlibc_core::stdlib::conversion::strtoul_impl(slice, base);

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

    let (val, consumed, _status) =
        frankenlibc_core::stdlib::conversion::strtoumax_impl(slice, base);

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
    let compar_fn = compar.expect("qsort called with null comparator");
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

    let compar_fn = compar.expect("bsearch called with null comparator");
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
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, true);
        return -1;
    }

    // Find '=' to split name and value.
    let s = unsafe { std::ffi::CStr::from_ptr(string) };
    let bytes = s.to_bytes();
    let eq_pos = match bytes.iter().position(|&b| b == b'=') {
        Some(pos) => pos,
        None => {
            // No '=': unset the variable (glibc behavior).
            let name_cstr = s;
            return unsafe { super::stdlib_abi::unsetenv(name_cstr.as_ptr()) };
        }
    };

    // Extract name and value.
    let name = &bytes[..eq_pos];
    let value = &bytes[eq_pos + 1..];

    // Build C strings for setenv.
    let name_vec: Vec<u8> = name.iter().copied().chain(std::iter::once(0)).collect();
    let value_vec: Vec<u8> = value.iter().copied().chain(std::iter::once(0)).collect();

    // Delegate to setenv with overwrite=1.
    let ret = unsafe {
        super::stdlib_abi::setenv(
            name_vec.as_ptr() as *const c_char,
            value_vec.as_ptr() as *const c_char,
            1,
        )
    };

    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, ret != 0);
    ret
}

// ---------------------------------------------------------------------------
// Additional stdlib — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "reallocarray"]
    fn libc_reallocarray(ptr: *mut c_void, nmemb: usize, size: usize) -> *mut c_void;
    #[link_name = "strtold"]
    fn libc_strtold(nptr: *const c_char, endptr: *mut *mut c_char) -> f64;
    #[link_name = "mkostemp"]
    fn libc_mkostemp(template: *mut c_char, flags: c_int) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn reallocarray(ptr: *mut c_void, nmemb: usize, size: usize) -> *mut c_void {
    unsafe { libc_reallocarray(ptr, nmemb, size) }
}

/// `strtold` — convert string to long double (on x86_64, same as f64).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtold(nptr: *const c_char, endptr: *mut *mut c_char) -> f64 {
    unsafe { libc_strtold(nptr, endptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemp(template: *mut c_char, flags: c_int) -> c_int {
    unsafe { libc_mkostemp(template, flags) }
}
