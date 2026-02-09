//! ABI stubs for stdlib functions.
//!
//! Implements numeric conversion functions (`atoi`, `atol`, `strtol`, `strtoul`),
//! process control (`exit`, `atexit`), and sorting/searching (`qsort`, `bsearch`)
//! with membrane validation.

use std::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use std::ptr;

use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use glibc_rs_membrane::runtime_math::{ApiFamily, MembraneAction};

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

#[unsafe(no_mangle)]
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
    let result = glibc_rs_core::stdlib::atoi(slice);

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

#[unsafe(no_mangle)]
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
    let result = glibc_rs_core::stdlib::atol(slice);

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(7, len),
        false,
    );
    result as c_long
}

// ---------------------------------------------------------------------------
// strtol
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
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

    let (val, consumed, _status) = glibc_rs_core::stdlib::conversion::strtol_impl(slice, base);

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
// strtoul
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
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

    let (val, consumed, _status) = glibc_rs_core::stdlib::conversion::strtoul_impl(slice, base);

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
// exit
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn exit(status: c_int) -> ! {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, false, true, 0);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 100, false);
    glibc_rs_core::stdlib::exit(status)
}

// ---------------------------------------------------------------------------
// atexit
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn atexit(func: Option<unsafe extern "C" fn()>) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, true);
        return -1;
    }

    let res = match func {
        Some(f) => {
            let safe_f: extern "C" fn() = unsafe { std::mem::transmute(f) };
            glibc_rs_core::stdlib::atexit(safe_f)
        }
        None => -1,
    };

    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 50, res != 0);
    res
}

// ---------------------------------------------------------------------------
// qsort
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
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

    glibc_rs_core::stdlib::sort::qsort(slice, size, wrapper);

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

#[unsafe(no_mangle)]
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

    let result = glibc_rs_core::stdlib::sort::bsearch(key_slice, slice, size, wrapper);

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
