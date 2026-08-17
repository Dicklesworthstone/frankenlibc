//! ABI layer for ISO C99/C23 internal-linkage aliases.
//!
//! GCC and Clang emit `__isoc99_*` and `__isoc23_*` symbol references when
//! compiling with `-std=c99`/`-std=c23` (or later). These are ABI-identical to
//! their base counterparts; they exist solely for binary compatibility with
//! glibc's versioned symbol scheme.
//!
//! This module consolidates all 38 such wrappers in one place:
//!
//! - 12 narrow scanf variants (C23)
//! - 6 wide scanf variants (C23)
//! - 6 wide scanf variants (C99)
//! - 10 strtol-family variants (C23)
//! - 4 wcstol/wcstoul/wcstoll/wcstoull + imaxabs variants (C23, 6 total)
//! - 4 wcstol_l locale variants (C23)

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_long, c_longlong, c_void};

type c_ulong = u64;
type c_ulonglong = u64;

/// Wide character type — `wchar_t` is i32 on Linux/glibc (UTF-32).
type WcharT = i32;

// ---------------------------------------------------------------------------
// Base-function delegation.
//
// The ISO aliases must call FrankenLibC's local ABI modules directly. In debug
// test binaries these base names are not exported with no_mangle, so extern-C
// lookups can resolve to host libc and bypass the membrane.
// ---------------------------------------------------------------------------

// ===========================================================================
// C23 __isoc23_* narrow scanf aliases (6 variadic + 6 va_list)
// ===========================================================================

/// `__isoc23_scanf` — C23 alias for scanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_scanf(format: *const c_char, mut args: ...) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { crate::stdio_abi::vscanf(format, ap) }
}

/// `__isoc23_fscanf` — C23 alias for fscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_fscanf(
    stream: *mut c_void,
    format: *const c_char,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { crate::stdio_abi::vfscanf(stream, format, ap) }
}

/// The membrane decision a scanf fast path makes just before it serves.
///
/// `None` means DENY and the caller returns -1, having already observed. It is
/// called only after a format probe has ACCEPTED: deciding before that would
/// bill a second traversal to every call that falls through to `vsscanf`, which
/// decides for itself (463da8418).
///
/// # Safety
/// `s` is only read as an address for the membrane, never dereferenced here.
#[inline]
unsafe fn scanf_fastpath_profile(
    s: *const c_char,
) -> Option<frankenlibc_membrane::runtime_math::ValidationProfile> {
    let (_, decision) = crate::runtime_policy::decide(
        frankenlibc_membrane::runtime_math::ApiFamily::Stdio,
        s as usize,
        0,
        false,
        false,
        0,
    );
    if matches!(
        decision.action,
        frankenlibc_membrane::runtime_math::MembraneAction::Deny
    ) {
        crate::runtime_policy::observe(
            frankenlibc_membrane::runtime_math::ApiFamily::Stdio,
            decision.profile,
            15,
            true,
        );
        return None;
    }
    Some(decision.profile)
}

/// `__isoc23_sscanf` — C23 alias for sscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_sscanf(
    s: *const c_char,
    format: *const c_char,
    mut args: ...
) -> c_int {
    // FAST PATH, same as `sscanf`'s. This alias used to forward straight to
    // `vsscanf`, and that mattered more than it looks: a compiler emits calls to
    // THIS symbol, not to `sscanf` — <stdio.h> redirects them under -std=c23, as
    // it did to `__isoc99_sscanf` before. So every optimisation applied to
    // `sscanf` reached test code calling `sscanf` by name and no compiled C at
    // all. Measured by instruction count on `sscanf("42", "%d")`: 250
    // instructions per call through `sscanf`, 864 through this alias.
    //
    // ORDER MATTERS, and it is not `sscanf`'s. The membrane decision comes
    // AFTER the format test, not before it, because the fallback below delegates
    // to `vsscanf` — which runs its own `decide`. Deciding here as well billed
    // every engine-path call two membrane traversals, and the untouched
    // `string_token` control caught it: 132.6M instructions per 200k calls
    // became 147.1M, +72 per call, for a decision that was then made again.
    // Gating on the format first keeps the fast path's policy check exactly
    // `sscanf`'s while leaving the delegating path with the single decision it
    // always had. (The same double-membrane shape cost `reallocarray` 2.05x.)
    if !s.is_null()
        && !format.is_null()
        && crate::runtime_policy::strict_passthrough_active()
    {
        if let Some((fields, sep, kinds)) =
            unsafe { crate::stdio_abi::strict_decimal_int_format_count(format) }
            && crate::stdio_abi::strict_field_list_is_scannable(fields, sep, &kinds)
        {
            let Some(profile) = (unsafe { scanf_fastpath_profile(s) }) else {
                return -1;
            };
            // SAFETY: the probe accepted `fields` conversions, so the caller
            // passed that many pointers of the matching type. Fetching them
            // before the scan writes nothing, so an unmatched field's
            // destination stays untouched.
            let mut destinations =
                [core::ptr::null_mut::<c_void>(); crate::stdio_abi::STRICT_INT_LIST_MAX];
            for slot in destinations.iter_mut().take(fields) {
                *slot = unsafe { args.next_arg::<*mut c_void>() };
            }
            let fast = unsafe {
                crate::stdio_abi::strict_scan_decimal_ints(s, fields, sep, &kinds, &destinations)
            };
            crate::runtime_policy::observe(
                frankenlibc_membrane::runtime_math::ApiFamily::Stdio,
                profile,
                15,
                fast.input_failure,
            );
            return fast.count;
        }
        if unsafe { crate::stdio_abi::strict_single_string_format(format) } {
            let Some(profile) = (unsafe { scanf_fastpath_profile(s) }) else {
                return -1;
            };
            // SAFETY: the format is exactly `"%s"`, so the caller passed one
            // `char *` sized for the token plus its NUL.
            let dst = unsafe { args.next_arg::<*mut c_char>() };
            let rc = unsafe { crate::stdio_abi::strict_scan_single_string(s, dst) };
            crate::runtime_policy::observe(
                frankenlibc_membrane::runtime_math::ApiFamily::Stdio,
                profile,
                15,
                rc < 0,
            );
            return rc;
        }
        if let Some(delim) = unsafe { crate::stdio_abi::strict_single_negated_scanset(format) } {
            let Some(profile) = (unsafe { scanf_fastpath_profile(s) }) else {
                return -1;
            };
            // SAFETY: the format is exactly `"%[^X]"`, so the caller passed one
            // `char *` sized for the field plus its NUL.
            let dst = unsafe { args.next_arg::<*mut c_char>() };
            let rc = unsafe { crate::stdio_abi::strict_scan_negated_scanset(s, dst, delim) };
            crate::runtime_policy::observe(
                frankenlibc_membrane::runtime_math::ApiFamily::Stdio,
                profile,
                15,
                rc < 0,
            );
            return rc;
        }
    }
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { crate::stdio_abi::vsscanf(s, format, ap) }
}

/// `__isoc23_wscanf` — C23 alias for wscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wscanf(format: *const WcharT, mut args: ...) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { crate::wchar_abi::vwscanf(format.cast::<libc::wchar_t>(), ap) }
}

/// `__isoc23_fwscanf` — C23 alias for fwscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_fwscanf(
    stream: *mut c_void,
    format: *const WcharT,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { crate::wchar_abi::vfwscanf(stream, format.cast::<libc::wchar_t>(), ap) }
}

/// `__isoc23_swscanf` — C23 alias for swscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_swscanf(
    s: *const WcharT,
    format: *const WcharT,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe {
        crate::wchar_abi::vswscanf(
            s.cast::<libc::wchar_t>(),
            format.cast::<libc::wchar_t>(),
            ap,
        )
    }
}

/// `__isoc23_vscanf` — C23 alias for vscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_vscanf(format: *const c_char, ap: *mut c_void) -> c_int {
    unsafe { crate::stdio_abi::vscanf(format, ap) }
}

/// `__isoc23_vfscanf` — C23 alias for vfscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_vfscanf(
    stream: *mut c_void,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { crate::stdio_abi::vfscanf(stream, format, ap) }
}

/// `__isoc23_vsscanf` — C23 alias for vsscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_vsscanf(
    s: *const c_char,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { crate::stdio_abi::vsscanf(s, format, ap) }
}

/// `__isoc23_vwscanf` — C23 alias for vwscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_vwscanf(format: *const WcharT, ap: *mut c_void) -> c_int {
    unsafe { crate::wchar_abi::vwscanf(format.cast::<libc::wchar_t>(), ap) }
}

/// `__isoc23_vfwscanf` — C23 alias for vfwscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_vfwscanf(
    stream: *mut c_void,
    format: *const WcharT,
    ap: *mut c_void,
) -> c_int {
    unsafe { crate::wchar_abi::vfwscanf(stream, format.cast::<libc::wchar_t>(), ap) }
}

/// `__isoc23_vswscanf` — C23 alias for vswscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_vswscanf(
    s: *const WcharT,
    format: *const WcharT,
    ap: *mut c_void,
) -> c_int {
    unsafe {
        crate::wchar_abi::vswscanf(
            s.cast::<libc::wchar_t>(),
            format.cast::<libc::wchar_t>(),
            ap,
        )
    }
}

// ===========================================================================
// C23 __isoc23_* strtol family (6 base + 4 locale)
// ===========================================================================

/// `__isoc23_strtol` — C23 alias for strtol.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtol(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_long {
    unsafe { crate::stdlib_abi::strtol(nptr, endptr, base) }
}

/// `__isoc23_strtoul` — C23 alias for strtoul.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoul(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulong {
    unsafe { crate::stdlib_abi::strtoul(nptr, endptr, base) }
}

/// `__isoc23_strtoll` — C23 alias for strtoll.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoll(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_longlong {
    unsafe { crate::stdlib_abi::strtoll(nptr, endptr, base) }
}

/// `__isoc23_strtoull` — C23 alias for strtoull.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoull(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulonglong {
    unsafe { crate::stdlib_abi::strtoull(nptr, endptr, base) }
}

/// `__isoc23_strtoimax` — C23 alias for strtoimax.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoimax(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> i64 {
    unsafe { crate::stdlib_abi::strtoimax(nptr, endptr, base) }
}

/// `__isoc23_strtoumax` — C23 alias for strtoumax.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoumax(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> u64 {
    unsafe { crate::stdlib_abi::strtoumax(nptr, endptr, base) }
}

/// `__isoc23_strtol_l` — C23 locale alias for strtol (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtol_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_long {
    unsafe { crate::stdlib_abi::strtol(nptr, endptr, base) }
}

/// `__isoc23_strtoul_l` — C23 locale alias for strtoul (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoul_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_ulong {
    unsafe { crate::stdlib_abi::strtoul(nptr, endptr, base) }
}

/// `__isoc23_strtoll_l` — C23 locale alias for strtoll (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoll_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_longlong {
    unsafe { crate::stdlib_abi::strtoll(nptr, endptr, base) }
}

/// `__isoc23_strtoull_l` — C23 locale alias for strtoull (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoull_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_ulonglong {
    unsafe { crate::stdlib_abi::strtoull(nptr, endptr, base) }
}

// ===========================================================================
// C23 __isoc23_* wcstol family (6 base + 4 locale)
// ===========================================================================

/// `__isoc23_wcstol` — C23 alias for wcstol.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstol(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
) -> c_long {
    unsafe {
        crate::wchar_abi::wcstol(
            nptr.cast::<libc::wchar_t>(),
            endptr.cast::<*mut libc::wchar_t>(),
            base,
        )
    }
}

/// `__isoc23_wcstoul` — C23 alias for wcstoul.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoul(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
) -> c_ulong {
    unsafe {
        crate::wchar_abi::wcstoul(
            nptr.cast::<libc::wchar_t>(),
            endptr.cast::<*mut libc::wchar_t>(),
            base,
        )
    }
}

/// `__isoc23_wcstoll` — C23 alias for wcstoll.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoll(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
) -> c_longlong {
    unsafe {
        crate::wchar_abi::wcstoll(
            nptr.cast::<libc::wchar_t>(),
            endptr.cast::<*mut libc::wchar_t>(),
            base,
        )
    }
}

/// `__isoc23_wcstoull` — C23 alias for wcstoull.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoull(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
) -> c_ulonglong {
    unsafe {
        crate::wchar_abi::wcstoull(
            nptr.cast::<libc::wchar_t>(),
            endptr.cast::<*mut libc::wchar_t>(),
            base,
        )
    }
}

/// `__isoc23_wcstoimax` — C23 alias for wcstoimax.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoimax(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
) -> i64 {
    unsafe { crate::wchar_abi::wcstoimax(nptr.cast::<u32>(), endptr.cast::<*mut u32>(), base) }
}

/// `__isoc23_wcstoumax` — C23 alias for wcstoumax.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoumax(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
) -> u64 {
    unsafe { crate::wchar_abi::wcstoumax(nptr.cast::<u32>(), endptr.cast::<*mut u32>(), base) }
}

/// `__isoc23_wcstol_l` — C23 locale alias for wcstol (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstol_l(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
    _locale: *mut c_void,
) -> c_long {
    unsafe {
        crate::wchar_abi::wcstol(
            nptr.cast::<libc::wchar_t>(),
            endptr.cast::<*mut libc::wchar_t>(),
            base,
        )
    }
}

/// `__isoc23_wcstoul_l` — C23 locale alias for wcstoul (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoul_l(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
    _locale: *mut c_void,
) -> c_ulong {
    unsafe {
        crate::wchar_abi::wcstoul(
            nptr.cast::<libc::wchar_t>(),
            endptr.cast::<*mut libc::wchar_t>(),
            base,
        )
    }
}

/// `__isoc23_wcstoll_l` — C23 locale alias for wcstoll (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoll_l(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
    _locale: *mut c_void,
) -> c_longlong {
    unsafe {
        crate::wchar_abi::wcstoll(
            nptr.cast::<libc::wchar_t>(),
            endptr.cast::<*mut libc::wchar_t>(),
            base,
        )
    }
}

/// `__isoc23_wcstoull_l` — C23 locale alias for wcstoull (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoull_l(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
    _locale: *mut c_void,
) -> c_ulonglong {
    unsafe {
        crate::wchar_abi::wcstoull(
            nptr.cast::<libc::wchar_t>(),
            endptr.cast::<*mut libc::wchar_t>(),
            base,
        )
    }
}

// ===========================================================================
// C99 __isoc99_* wide scanf aliases (3 variadic + 3 va_list)
// ===========================================================================

/// `__isoc99_wscanf` — C99 alias for wscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_wscanf(format: *const WcharT, mut args: ...) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { crate::wchar_abi::vwscanf(format.cast::<libc::wchar_t>(), ap) }
}

/// `__isoc99_fwscanf` — C99 alias for fwscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_fwscanf(
    stream: *mut c_void,
    format: *const WcharT,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { crate::wchar_abi::vfwscanf(stream, format.cast::<libc::wchar_t>(), ap) }
}

/// `__isoc99_swscanf` — C99 alias for swscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_swscanf(
    s: *const WcharT,
    format: *const WcharT,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe {
        crate::wchar_abi::vswscanf(
            s.cast::<libc::wchar_t>(),
            format.cast::<libc::wchar_t>(),
            ap,
        )
    }
}

/// `__isoc99_vwscanf` — C99 alias for vwscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_vwscanf(format: *const WcharT, ap: *mut c_void) -> c_int {
    unsafe { crate::wchar_abi::vwscanf(format.cast::<libc::wchar_t>(), ap) }
}

/// `__isoc99_vfwscanf` — C99 alias for vfwscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_vfwscanf(
    stream: *mut c_void,
    format: *const WcharT,
    ap: *mut c_void,
) -> c_int {
    unsafe { crate::wchar_abi::vfwscanf(stream, format.cast::<libc::wchar_t>(), ap) }
}

/// `__isoc99_vswscanf` — C99 alias for vswscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_vswscanf(
    s: *const WcharT,
    format: *const WcharT,
    ap: *mut c_void,
) -> c_int {
    unsafe {
        crate::wchar_abi::vswscanf(
            s.cast::<libc::wchar_t>(),
            format.cast::<libc::wchar_t>(),
            ap,
        )
    }
}
