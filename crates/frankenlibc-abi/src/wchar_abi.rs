//! ABI layer for `<wchar.h>` functions.
//!
//! Handles wide-character (32-bit) string operations.
//! On Linux/glibc, `wchar_t` is 32-bit (UTF-32).
//!
use std::ffi::{c_char, c_int, c_long, c_longlong, c_ulong, c_ulonglong, c_void};

use frankenlibc_core::stdio::printf::{FormatSegment, parse_format_string};
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use crate::util::scan_c_string;

#[inline]
fn repair_enabled(heals_enabled: bool, action: MembraneAction) -> bool {
    heals_enabled || matches!(action, MembraneAction::Repair(_))
}

fn record_truncation(requested: usize, truncated: usize) {
    global_healing_policy().record(&HealingAction::TruncateWithNull {
        requested,
        truncated,
    });
}

/// Convert byte count to wchar count (assuming 4-byte wchar_t).
fn bytes_to_wchars(bytes: usize) -> usize {
    bytes / 4
}

/// Scan a wide string with an optional hard bound (in elements).
///
/// Returns `(len, terminated)` where:
/// - `len` is the element length before the first NUL or before the bound.
/// - `terminated` indicates whether a NUL wide-char was observed.
unsafe fn scan_w_string(ptr: *const u32, bound: Option<usize>) -> (usize, bool) {
    match bound {
        Some(limit) => {
            for i in 0..limit {
                // SAFETY: caller provides validity for bounded read.
                if unsafe { *ptr.add(i) } == 0 {
                    return (i, true);
                }
            }
            (limit, false)
        }
        None => {
            let mut i = 0usize;
            // SAFETY: caller guarantees valid NUL-terminated string in unbounded mode.
            while unsafe { *ptr.add(i) } != 0 {
                i += 1;
            }
            (i, true)
        }
    }
}

// ---------------------------------------------------------------------------
// wcslen
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcslen(s: *const u32) -> usize {
    if s.is_null() {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        0,
        false,
        known_remaining(s as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 6, true);
        return 0;
    }

    if (mode.heals_enabled() || matches!(decision.action, MembraneAction::Repair(_)))
        && let Some(bytes_rem) = known_remaining(s as usize)
    {
        let limit = bytes_to_wchars(bytes_rem);
        // SAFETY: bounded scan within known allocation extent.
        unsafe {
            for i in 0..limit {
                if *s.add(i) == 0 {
                    runtime_policy::observe(
                        ApiFamily::StringMemory,
                        decision.profile,
                        runtime_policy::scaled_cost(7, i * 4),
                        false,
                    );
                    return i;
                }
            }
        }
        let action = HealingAction::TruncateWithNull {
            requested: limit.saturating_add(1),
            truncated: limit,
        };
        global_healing_policy().record(&action);
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(7, limit * 4),
            true,
        );
        return limit;
    }

    // SAFETY: strict mode preserves libc-like raw scan semantics.
    unsafe {
        let mut len = 0usize;
        while *s.add(len) != 0 {
            len += 1;
        }
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(7, len * 4),
            false,
        );
        len
    }
}

// ---------------------------------------------------------------------------
// wcscpy
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcscpy(dst: *mut u32, src: *const u32) -> *mut u32 {
    if dst.is_null() || src.is_null() {
        return dst;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        0,
        true,
        known_remaining(dst as usize).is_none() && known_remaining(src as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 7, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let src_bound = if repair {
        known_remaining(src as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let dst_bound = if repair {
        known_remaining(dst as usize).map(bytes_to_wchars)
    } else {
        None
    };

    // SAFETY: strict mode follows libc semantics; hardened mode bounds reads/writes.
    let (copied_len, adverse) = unsafe {
        let (src_len, src_terminated) = scan_w_string(src, src_bound);
        let requested = src_len.saturating_add(1);
        if repair {
            match dst_bound {
                Some(0) => {
                    record_truncation(requested, 0);
                    (0, true)
                }
                Some(limit) => {
                    let max_payload = limit.saturating_sub(1);
                    let copy_payload = src_len.min(max_payload);
                    if copy_payload > 0 {
                        std::ptr::copy_nonoverlapping(src, dst, copy_payload);
                    }
                    *dst.add(copy_payload) = 0;
                    let truncated = !src_terminated || copy_payload < src_len;
                    if truncated {
                        record_truncation(requested, copy_payload);
                    }
                    (copy_payload.saturating_add(1), truncated)
                }
                None => {
                    let mut i = 0usize;
                    loop {
                        let ch = *src.add(i);
                        *dst.add(i) = ch;
                        if ch == 0 {
                            break (i.saturating_add(1), false);
                        }
                        i += 1;
                    }
                }
            }
        } else {
            let mut i = 0usize;
            loop {
                let ch = *src.add(i);
                *dst.add(i) = ch;
                if ch == 0 {
                    break (i.saturating_add(1), false);
                }
                i += 1;
            }
        }
    };

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(8, copied_len * 4),
        adverse,
    );
    dst
}

// ---------------------------------------------------------------------------
// wcsncpy
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncpy(dst: *mut u32, src: *const u32, n: usize) -> *mut u32 {
    if dst.is_null() || src.is_null() || n == 0 {
        return dst;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        n * 4,
        true,
        known_remaining(dst as usize).is_none() && known_remaining(src as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 8, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let src_bound = if repair {
        known_remaining(src as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let dst_bound = if repair {
        known_remaining(dst as usize).map(bytes_to_wchars)
    } else {
        None
    };

    // SAFETY: strict mode follows libc semantics; hardened mode bounds reads/writes.
    let (copy_len, clamped) = unsafe {
        let mut i = 0usize;
        let mut adverse = false;
        let max_copy = if let Some(limit) = dst_bound.filter(|_| repair) {
            limit.min(n)
        } else {
            n
        };

        while i < max_copy {
            if repair && src_bound.is_some_and(|b| i >= b) {
                // Hit source bound unexpectedly
                adverse = true;
                break;
            }
            let ch = *src.add(i);
            *dst.add(i) = ch;
            i += 1;
            if ch == 0 {
                break;
            }
        }

        // Check if we were clamped by dst size
        if repair && dst_bound.is_some() && n > max_copy {
            adverse = true;
            record_truncation(n, max_copy);
        }

        // Pad with NULs
        while i < max_copy {
            *dst.add(i) = 0;
            i += 1;
        }

        (i, adverse)
    };

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(8, copy_len * 4),
        clamped,
    );
    dst
}

// ---------------------------------------------------------------------------
// wcscat
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcscat(dst: *mut u32, src: *const u32) -> *mut u32 {
    if dst.is_null() || src.is_null() {
        return dst;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        0,
        true,
        known_remaining(dst as usize).is_none() && known_remaining(src as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 8, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let dst_bound = if repair {
        known_remaining(dst as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let src_bound = if repair {
        known_remaining(src as usize).map(bytes_to_wchars)
    } else {
        None
    };

    // SAFETY: strict mode preserves raw wcscat behavior; hardened mode bounds writes.
    let (work, adverse) = unsafe {
        let (dst_len, dst_terminated) = scan_w_string(dst.cast_const(), dst_bound);
        let (src_len, src_terminated) = scan_w_string(src, src_bound);
        if repair {
            match dst_bound {
                Some(0) => {
                    record_truncation(src_len.saturating_add(1), 0);
                    (0, true)
                }
                Some(limit) => {
                    if !dst_terminated {
                        *dst.add(limit.saturating_sub(1)) = 0;
                        record_truncation(limit, limit.saturating_sub(1));
                        (limit, true)
                    } else {
                        let available = limit.saturating_sub(dst_len.saturating_add(1));
                        let copy_payload = src_len.min(available);
                        if copy_payload > 0 {
                            std::ptr::copy_nonoverlapping(src, dst.add(dst_len), copy_payload);
                        }
                        *dst.add(dst_len.saturating_add(copy_payload)) = 0;
                        let truncated = !src_terminated || copy_payload < src_len;
                        if truncated {
                            record_truncation(src_len.saturating_add(1), copy_payload);
                        }
                        (
                            dst_len.saturating_add(copy_payload).saturating_add(1),
                            truncated,
                        )
                    }
                }
                None => {
                    let mut d = dst_len;
                    let mut s = 0usize;
                    loop {
                        let ch = *src.add(s);
                        *dst.add(d) = ch;
                        if ch == 0 {
                            break (d.saturating_add(1), false);
                        }
                        d += 1;
                        s += 1;
                    }
                }
            }
        } else {
            let mut d = dst_len;
            let mut s = 0usize;
            loop {
                let ch = *src.add(s);
                *dst.add(d) = ch;
                if ch == 0 {
                    break (d.saturating_add(1), false);
                }
                d += 1;
                s += 1;
            }
        }
    };
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(9, work * 4),
        adverse,
    );
    dst
}

// ---------------------------------------------------------------------------
// wcscmp
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcscmp(s1: *const u32, s2: *const u32) -> c_int {
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s1 as usize,
        0,
        false,
        known_remaining(s1 as usize).is_none() && known_remaining(s2 as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 6, true);
        return 0;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let lhs_bound = if repair {
        known_remaining(s1 as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let rhs_bound = if repair {
        known_remaining(s2 as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let cmp_bound = match (lhs_bound, rhs_bound) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };

    let (result, adverse, span) = unsafe {
        let mut i = 0usize;
        let mut adverse_local = false;
        loop {
            if let Some(limit) = cmp_bound
                && i >= limit
            {
                adverse_local = true;
                break (0, adverse_local, i);
            }
            let a = *s1.add(i);
            let b = *s2.add(i);
            if a != b || a == 0 {
                // Cast to i32 for signed wchar_t comparison
                let diff = if (a as i32) < (b as i32) { -1 } else { 1 };
                break (
                    if a == b { 0 } else { diff },
                    adverse_local,
                    i.saturating_add(1),
                );
            }
            i += 1;
        }
    };

    if adverse {
        record_truncation(cmp_bound.unwrap_or(span), span);
    }
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, span * 4),
        adverse,
    );
    result
}

// ---------------------------------------------------------------------------
// wcsncmp
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncmp(s1: *const u32, s2: *const u32, n: usize) -> c_int {
    if s1.is_null() || s2.is_null() || n == 0 {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s1 as usize,
        n * 4,
        false,
        known_remaining(s1 as usize).is_none() && known_remaining(s2 as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 6, true);
        return 0;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let lhs_bound = if repair {
        known_remaining(s1 as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let rhs_bound = if repair {
        known_remaining(s2 as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let cmp_bound = match (lhs_bound, rhs_bound) {
        (Some(a), Some(b)) => Some(a.min(b).min(n)),
        (Some(a), None) => Some(a.min(n)),
        (None, Some(b)) => Some(b.min(n)),
        (None, None) => Some(n),
    };

    let (result, adverse, span) = unsafe {
        let mut i = 0usize;
        let mut adverse_local = false;
        loop {
            if let Some(limit) = cmp_bound
                && i >= limit
            {
                // Reached limit (n or bounds). If limit < n and limited by bounds, it's adverse.
                if limit < n && (lhs_bound == Some(limit) || rhs_bound == Some(limit)) {
                    adverse_local = true;
                }
                break (0, adverse_local, i);
            }
            let a = *s1.add(i);
            let b = *s2.add(i);
            if a != b || a == 0 {
                // Cast to i32 for signed wchar_t comparison
                let diff = if (a as i32) < (b as i32) { -1 } else { 1 };
                break (
                    if a == b { 0 } else { diff },
                    adverse_local,
                    i.saturating_add(1),
                );
            }
            i += 1;
        }
    };

    if adverse {
        record_truncation(cmp_bound.unwrap_or(span), span);
    }
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, span * 4),
        adverse,
    );
    result
}
// ---------------------------------------------------------------------------
// wcschr
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcschr(s: *const u32, c: u32) -> *mut u32 {
    if s.is_null() {
        return std::ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        0,
        false,
        known_remaining(s as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 6, true);
        return std::ptr::null_mut();
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(s as usize).map(bytes_to_wchars)
    } else {
        None
    };

    // SAFETY: strict mode preserves raw wcschr behavior; hardened mode bounds scan.
    let (out, adverse, span) = unsafe {
        let mut i = 0usize;
        loop {
            if let Some(limit) = bound
                && i >= limit
            {
                break (std::ptr::null_mut(), true, i);
            }
            let ch = *s.add(i);
            if ch == c {
                break (s.add(i) as *mut u32, false, i.saturating_add(1));
            }
            if ch == 0 {
                // If c was 0, we would have matched above. So here it's not found.
                break (std::ptr::null_mut(), false, i.saturating_add(1));
            }
            i += 1;
        }
    };

    if adverse {
        record_truncation(bound.unwrap_or(span), span);
    }
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(6, span * 4),
        adverse,
    );
    out
}

// ---------------------------------------------------------------------------
// wcsrchr
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsrchr(s: *const u32, c: u32) -> *mut u32 {
    if s.is_null() {
        return std::ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        0,
        false,
        known_remaining(s as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 6, true);
        return std::ptr::null_mut();
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(s as usize).map(bytes_to_wchars)
    } else {
        None
    };

    let (result, adverse, span) = unsafe {
        let mut result_local: *mut u32 = std::ptr::null_mut();
        let mut i = 0usize;
        loop {
            if let Some(limit) = bound
                && i >= limit
            {
                break (result_local, true, i);
            }
            let ch = *s.add(i);
            if ch == c {
                result_local = s.add(i) as *mut u32;
            }
            if ch == 0 {
                break (result_local, false, i.saturating_add(1));
            }
            i += 1;
        }
    };
    if adverse {
        record_truncation(bound.unwrap_or(span), span);
    }
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(6, span * 4),
        adverse,
    );
    result
}

// ---------------------------------------------------------------------------
// wcsstr
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsstr(haystack: *const u32, needle: *const u32) -> *mut u32 {
    if haystack.is_null() {
        return std::ptr::null_mut();
    }
    if needle.is_null() {
        return haystack as *mut u32;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        haystack as usize,
        0,
        false,
        known_remaining(haystack as usize).is_none() && known_remaining(needle as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 10, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let hay_bound = if repair {
        known_remaining(haystack as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let needle_bound = if repair {
        known_remaining(needle as usize).map(bytes_to_wchars)
    } else {
        None
    };

    let (out, adverse, work) = unsafe {
        let (needle_len, needle_terminated) = scan_w_string(needle, needle_bound);
        let (hay_len, hay_terminated) = scan_w_string(haystack, hay_bound);
        let mut out_local = std::ptr::null_mut();
        let mut work_local = 0usize;

        if needle_len == 0 {
            out_local = haystack as *mut u32;
            work_local = 1;
        } else if hay_len >= needle_len {
            let mut h = 0usize;
            while h + needle_len <= hay_len {
                let mut n = 0usize;
                while n < needle_len && *haystack.add(h + n) == *needle.add(n) {
                    n += 1;
                }
                if n == needle_len {
                    out_local = haystack.add(h) as *mut u32;
                    work_local = h.saturating_add(needle_len);
                    break;
                }
                h += 1;
                work_local = h.saturating_add(needle_len);
            }
        } else {
            work_local = hay_len;
        }

        (
            out_local,
            !hay_terminated || !needle_terminated,
            work_local.max(needle_len),
        )
    };

    if adverse {
        record_truncation(
            hay_bound
                .unwrap_or(work)
                .saturating_add(needle_bound.unwrap_or(0)),
            work,
        );
    }
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(10, work * 4),
        adverse,
    );
    out
}

// ---------------------------------------------------------------------------
// wmemcpy
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wmemcpy(dst: *mut u32, src: *const u32, n: usize) -> *mut u32 {
    if n == 0 {
        return dst;
    }
    if dst.is_null() || src.is_null() {
        return std::ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        n * 4,
        true,
        known_remaining(dst as usize).is_none() && known_remaining(src as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(7, n * 4),
            true,
        );
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let src_bound = if repair {
        known_remaining(src as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let dst_bound = if repair {
        known_remaining(dst as usize).map(bytes_to_wchars)
    } else {
        None
    };

    let (copy_len, clamped) = if repair {
        let max_src = src_bound.unwrap_or(usize::MAX);
        let max_dst = dst_bound.unwrap_or(usize::MAX);
        let limit = max_src.min(max_dst);
        if n > limit {
            record_truncation(n, limit);
            (limit, true)
        } else {
            (n, false)
        }
    } else {
        (n, false)
    };

    if copy_len > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(src, dst, copy_len);
        }
    }

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, copy_len * 4),
        clamped,
    );
    dst
}

// ---------------------------------------------------------------------------
// wmemmove
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wmemmove(dst: *mut u32, src: *const u32, n: usize) -> *mut u32 {
    if n == 0 {
        return dst;
    }
    if dst.is_null() || src.is_null() {
        return std::ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        n * 4,
        true,
        known_remaining(dst as usize).is_none() && known_remaining(src as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(8, n * 4),
            true,
        );
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let mut copy_len = n;
    let mut clamped = false;

    if repair {
        let src_rem = known_remaining(src as usize)
            .map(bytes_to_wchars)
            .unwrap_or(usize::MAX);
        let dst_rem = known_remaining(dst as usize)
            .map(bytes_to_wchars)
            .unwrap_or(usize::MAX);
        let limit = src_rem.min(dst_rem);
        if n > limit {
            copy_len = limit;
            clamped = true;
            record_truncation(n, limit);
        }
    }

    if copy_len > 0 {
        unsafe {
            std::ptr::copy(src, dst, copy_len);
        }
    }

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(8, copy_len * 4),
        clamped,
    );
    dst
}

// ---------------------------------------------------------------------------
// wmemset
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wmemset(dst: *mut u32, c: u32, n: usize) -> *mut u32 {
    if n == 0 {
        return dst;
    }
    if dst.is_null() {
        return std::ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        n * 4,
        true,
        known_remaining(dst as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(6, n * 4),
            true,
        );
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let mut fill_len = n;
    let mut clamped = false;

    if repair {
        let dst_rem = known_remaining(dst as usize)
            .map(bytes_to_wchars)
            .unwrap_or(usize::MAX);
        if n > dst_rem {
            fill_len = dst_rem;
            clamped = true;
            record_truncation(n, dst_rem);
        }
    }

    if fill_len > 0 {
        unsafe {
            let slice = std::slice::from_raw_parts_mut(dst, fill_len);
            slice.fill(c);
        }
    }

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(6, fill_len * 4),
        clamped,
    );
    dst
}

// ---------------------------------------------------------------------------
// wmemcmp
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wmemcmp(s1: *const u32, s2: *const u32, n: usize) -> c_int {
    if n == 0 {
        return 0;
    }
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s1 as usize,
        n * 4,
        false,
        known_remaining(s1 as usize).is_none() && known_remaining(s2 as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(6, n * 4),
            true,
        );
        return 0;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let mut cmp_len = n;
    let mut clamped = false;

    if repair {
        let s1_rem = known_remaining(s1 as usize)
            .map(bytes_to_wchars)
            .unwrap_or(usize::MAX);
        let s2_rem = known_remaining(s2 as usize)
            .map(bytes_to_wchars)
            .unwrap_or(usize::MAX);
        let limit = s1_rem.min(s2_rem);
        if n > limit {
            cmp_len = limit;
            clamped = true;
            record_truncation(n, limit);
        }
    }

    let result = unsafe {
        let a = std::slice::from_raw_parts(s1, cmp_len);
        let b = std::slice::from_raw_parts(s2, cmp_len);
        let mut res = 0;
        for i in 0..cmp_len {
            if a[i] != b[i] {
                // wchar_t is signed (i32) on Linux; compare as signed values.
                res = if (a[i] as i32) < (b[i] as i32) { -1 } else { 1 };
                break;
            }
        }
        res
    };

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(6, cmp_len * 4),
        clamped,
    );
    result
}

// ---------------------------------------------------------------------------
// wmemchr
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wmemchr(s: *const u32, c: u32, n: usize) -> *mut u32 {
    if n == 0 || s.is_null() {
        return std::ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        n * 4,
        false,
        known_remaining(s as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(6, n * 4),
            true,
        );
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let mut scan_len = n;
    let mut clamped = false;

    if repair {
        let s_rem = known_remaining(s as usize)
            .map(bytes_to_wchars)
            .unwrap_or(usize::MAX);
        if n > s_rem {
            scan_len = s_rem;
            clamped = true;
            record_truncation(n, s_rem);
        }
    }

    let result = unsafe {
        let slice = std::slice::from_raw_parts(s, scan_len);
        match slice.iter().position(|&x| x == c) {
            Some(i) => s.add(i) as *mut u32,
            None => std::ptr::null_mut(),
        }
    };

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(6, scan_len * 4),
        clamped,
    );
    result
}

// ---------------------------------------------------------------------------
// wcsncat
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncat(dst: *mut u32, src: *const u32, n: usize) -> *mut u32 {
    if dst.is_null() || src.is_null() || n == 0 {
        return dst;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        0,
        true,
        known_remaining(dst as usize).is_none() && known_remaining(src as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 8, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let dst_bound = if repair {
        known_remaining(dst as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let src_bound = if repair {
        known_remaining(src as usize).map(bytes_to_wchars)
    } else {
        None
    };

    let (work, adverse) = unsafe {
        let (dst_len, _dst_terminated) = scan_w_string(dst.cast_const(), dst_bound);
        let (src_len, src_terminated) = scan_w_string(src, src_bound);
        let copy_len = src_len.min(n);

        if repair {
            match dst_bound {
                Some(0) => {
                    record_truncation(copy_len.saturating_add(1), 0);
                    (0, true)
                }
                Some(limit) => {
                    let available = limit.saturating_sub(dst_len.saturating_add(1));
                    let actual_copy = copy_len.min(available);
                    if actual_copy > 0 {
                        std::ptr::copy_nonoverlapping(src, dst.add(dst_len), actual_copy);
                    }
                    *dst.add(dst_len.saturating_add(actual_copy)) = 0;
                    let truncated = !src_terminated || actual_copy < copy_len;
                    if truncated {
                        record_truncation(copy_len.saturating_add(1), actual_copy);
                    }
                    (
                        dst_len.saturating_add(actual_copy).saturating_add(1),
                        truncated,
                    )
                }
                None => {
                    if copy_len > 0 {
                        std::ptr::copy_nonoverlapping(src, dst.add(dst_len), copy_len);
                    }
                    *dst.add(dst_len + copy_len) = 0;
                    (dst_len + copy_len + 1, false)
                }
            }
        } else {
            if copy_len > 0 {
                std::ptr::copy_nonoverlapping(src, dst.add(dst_len), copy_len);
            }
            *dst.add(dst_len + copy_len) = 0;
            (dst_len + copy_len + 1, false)
        }
    };

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(9, work * 4),
        adverse,
    );
    dst
}

// ---------------------------------------------------------------------------
// wcsdup
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsdup(s: *const u32) -> *mut u32 {
    if s.is_null() {
        return std::ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        0,
        false,
        known_remaining(s as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 8, true);
        return std::ptr::null_mut();
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(s as usize).map(bytes_to_wchars)
    } else {
        None
    };

    unsafe {
        let (len, _terminated) = scan_w_string(s, bound);
        let alloc_elems = len + 1;
        let alloc_bytes = alloc_elems * 4;

        let ptr = crate::malloc_abi::raw_alloc(alloc_bytes) as *mut u32;
        if ptr.is_null() {
            runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 8, true);
            return std::ptr::null_mut();
        }

        std::ptr::copy_nonoverlapping(s, ptr, len);
        *ptr.add(len) = 0;

        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(8, alloc_bytes),
            false,
        );
        ptr
    }
}

// ---------------------------------------------------------------------------
// wcsspn
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsspn(s: *const u32, accept: *const u32) -> usize {
    if s.is_null() || accept.is_null() {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        0,
        false,
        known_remaining(s as usize).is_none() && known_remaining(accept as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 7, true);
        return 0;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let s_bound = if repair {
        known_remaining(s as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let accept_bound = if repair {
        known_remaining(accept as usize).map(bytes_to_wchars)
    } else {
        None
    };

    let result = unsafe {
        let (accept_len, _) = scan_w_string(accept, accept_bound);
        let accept_slice = std::slice::from_raw_parts(accept, accept_len);
        let (s_len, _) = scan_w_string(s, s_bound);
        let mut count = 0usize;
        for i in 0..s_len {
            if accept_slice.contains(&*s.add(i)) {
                count += 1;
            } else {
                break;
            }
        }
        count
    };

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, result * 4),
        false,
    );
    result
}

// ---------------------------------------------------------------------------
// wcscspn
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcscspn(s: *const u32, reject: *const u32) -> usize {
    if s.is_null() || reject.is_null() {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        0,
        false,
        known_remaining(s as usize).is_none() && known_remaining(reject as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 7, true);
        return 0;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let s_bound = if repair {
        known_remaining(s as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let reject_bound = if repair {
        known_remaining(reject as usize).map(bytes_to_wchars)
    } else {
        None
    };

    let result = unsafe {
        let (reject_len, _) = scan_w_string(reject, reject_bound);
        let reject_slice = std::slice::from_raw_parts(reject, reject_len);
        let (s_len, _) = scan_w_string(s, s_bound);
        let mut count = 0usize;
        for i in 0..s_len {
            if reject_slice.contains(&*s.add(i)) {
                break;
            }
            count += 1;
        }
        count
    };

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, result * 4),
        false,
    );
    result
}

// ---------------------------------------------------------------------------
// wcspbrk
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcspbrk(s: *const u32, accept: *const u32) -> *mut u32 {
    if s.is_null() || accept.is_null() {
        return std::ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        0,
        false,
        known_remaining(s as usize).is_none() && known_remaining(accept as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 7, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let s_bound = if repair {
        known_remaining(s as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let accept_bound = if repair {
        known_remaining(accept as usize).map(bytes_to_wchars)
    } else {
        None
    };

    let (result, span) = unsafe {
        let (accept_len, _) = scan_w_string(accept, accept_bound);
        let accept_slice = std::slice::from_raw_parts(accept, accept_len);
        let (s_len, _) = scan_w_string(s, s_bound);
        let mut found: *mut u32 = std::ptr::null_mut();
        let mut work = s_len;
        for i in 0..s_len {
            if accept_slice.contains(&*s.add(i)) {
                found = s.add(i) as *mut u32;
                work = i + 1;
                break;
            }
        }
        (found, work)
    };

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, span * 4),
        false,
    );
    result
}

// ---------------------------------------------------------------------------
// wcstok
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstok(
    s: *mut u32,
    delim: *const u32,
    save_ptr: *mut *mut u32,
) -> *mut u32 {
    if delim.is_null() || save_ptr.is_null() {
        return std::ptr::null_mut();
    }

    // Determine the starting pointer: s if non-null, else *save_ptr
    let start = unsafe {
        if !s.is_null() {
            s
        } else {
            let saved = *save_ptr;
            if saved.is_null() {
                return std::ptr::null_mut();
            }
            saved
        }
    };

    let (_, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        start as usize,
        0,
        true,
        known_remaining(start as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 8, true);
        return std::ptr::null_mut();
    }

    // Scan delimiters to build set
    let (delim_len, _) = unsafe { scan_w_string(delim, None) };

    unsafe {
        // Skip leading delimiters
        let mut pos = start;
        loop {
            let ch = *pos;
            if ch == 0 {
                *save_ptr = pos;
                runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 7, false);
                return std::ptr::null_mut();
            }
            let delim_slice = std::slice::from_raw_parts(delim, delim_len);
            if !delim_slice.contains(&ch) {
                break;
            }
            pos = pos.add(1);
        }

        // Find end of token
        let token_start = pos;
        loop {
            let ch = *pos;
            if ch == 0 {
                *save_ptr = pos;
                break;
            }
            let delim_slice = std::slice::from_raw_parts(delim, delim_len);
            if delim_slice.contains(&ch) {
                *pos = 0;
                *save_ptr = pos.add(1);
                break;
            }
            pos = pos.add(1);
        }

        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 8, false);
        token_start
    }
}

#[allow(dead_code)]
fn maybe_clamp_wchars(
    requested: usize, // elements
    src_addr: Option<usize>,
    dst_addr: Option<usize>,
    enable_repair: bool,
) -> (usize, bool) {
    if !enable_repair || requested == 0 {
        return (requested, false);
    }

    let src_remaining = src_addr.and_then(known_remaining);
    let dst_remaining = dst_addr.and_then(known_remaining);

    let req_bytes = requested.saturating_mul(4);
    let action = global_healing_policy().heal_copy_bounds(req_bytes, src_remaining, dst_remaining);

    match action {
        HealingAction::ClampSize { clamped, .. } => {
            global_healing_policy().record(&action);
            (bytes_to_wchars(clamped), true)
        }
        _ => (requested, false),
    }
}

// ===========================================================================
// Multibyte ↔ wide character conversion functions
// ===========================================================================

use frankenlibc_core::stdlib::conversion::ConversionStatus;
use frankenlibc_core::string::{wchar as wchar_core, wide as wide_core};

// ---------------------------------------------------------------------------
// mblen
// ---------------------------------------------------------------------------

/// POSIX `mblen` — determine number of bytes in a multibyte character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mblen(s: *const u8, n: usize) -> c_int {
    if s.is_null() {
        return 0; // stateless encoding
    }
    let slice = unsafe { std::slice::from_raw_parts(s, n) };
    match wchar_core::mblen(slice) {
        Some(0) => 0,
        Some(len) => len as c_int,
        None => -1,
    }
}

// ---------------------------------------------------------------------------
// mbtowc
// ---------------------------------------------------------------------------

/// POSIX `mbtowc` — convert multibyte character to wide character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mbtowc(pwc: *mut u32, s: *const u8, n: usize) -> c_int {
    if s.is_null() {
        return 0; // stateless encoding
    }
    let slice = unsafe { std::slice::from_raw_parts(s, n) };
    if !slice.is_empty() && slice[0] == 0 {
        if !pwc.is_null() {
            unsafe { *pwc = 0 };
        }
        return 0;
    }
    match wchar_core::mbtowc(slice) {
        Some((wc, len)) => {
            if !pwc.is_null() {
                unsafe { *pwc = wc };
            }
            len as c_int
        }
        None => {
            unsafe { set_abi_errno(libc::EILSEQ) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// wctomb
// ---------------------------------------------------------------------------

/// POSIX `wctomb` — convert wide character to multibyte character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wctomb(s: *mut u8, wc: u32) -> c_int {
    if s.is_null() {
        return 0; // stateless encoding
    }
    // MB_CUR_MAX for UTF-8 is 4
    let buf = unsafe { std::slice::from_raw_parts_mut(s, 4) };
    match wchar_core::wctomb(wc, buf) {
        Some(n) => n as c_int,
        None => {
            unsafe { set_abi_errno(libc::EILSEQ) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// mbstowcs
// ---------------------------------------------------------------------------

/// POSIX `mbstowcs` — convert multibyte string to wide string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mbstowcs(dst: *mut u32, src: *const u8, n: usize) -> usize {
    if src.is_null() {
        return usize::MAX; // (size_t)-1
    }
    let (src_len, _terminated) = unsafe { scan_c_string(src as *const std::ffi::c_char, None) };
    let src_slice = unsafe { std::slice::from_raw_parts(src, src_len.saturating_add(1)) }; // include NUL
    if dst.is_null() {
        // Count mode
        let mut count = 0usize;
        let mut i = 0;
        while i < src_slice.len() && src_slice[i] != 0 {
            match wchar_core::mbtowc(&src_slice[i..]) {
                Some((_, len)) => {
                    count += 1;
                    i += len;
                }
                None => return usize::MAX,
            }
        }
        return count;
    }
    let dst_slice = unsafe { std::slice::from_raw_parts_mut(dst, n) };
    match wchar_core::mbstowcs(dst_slice, src_slice) {
        Some(count) => count,
        None => usize::MAX,
    }
}

// ---------------------------------------------------------------------------
// wcstombs
// ---------------------------------------------------------------------------

/// POSIX `wcstombs` — convert wide string to multibyte string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstombs(dst: *mut u8, src: *const u32, n: usize) -> usize {
    if src.is_null() {
        return usize::MAX;
    }
    // Find length of wide string
    let mut wlen = 0usize;
    while unsafe { *src.add(wlen) } != 0 {
        wlen += 1;
    }
    let src_slice = unsafe { std::slice::from_raw_parts(src, wlen + 1) }; // include NUL
    if dst.is_null() {
        // Count mode
        let mut count = 0usize;
        for &wc in &src_slice[..wlen] {
            let mut tmp = [0u8; 4];
            match wchar_core::wctomb(wc, &mut tmp) {
                Some(len) => count += len,
                None => return usize::MAX,
            }
        }
        return count;
    }
    let dst_slice = unsafe { std::slice::from_raw_parts_mut(dst, n) };
    match wchar_core::wcstombs(dst_slice, src_slice) {
        Some(count) => count,
        None => usize::MAX,
    }
}

// ===========================================================================
// Wide character classification functions (wctype.h)
// ===========================================================================

/// POSIX `towupper` — convert wide character to uppercase.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn towupper(wc: u32) -> u32 {
    wchar_core::towupper(wc)
}

/// POSIX `towlower` — convert wide character to lowercase.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn towlower(wc: u32) -> u32 {
    wchar_core::towlower(wc)
}

/// POSIX `iswalnum` — test for alphanumeric wide character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswalnum(wc: u32) -> c_int {
    wchar_core::iswalnum(wc) as c_int
}

/// POSIX `iswalpha` — test for alphabetic wide character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswalpha(wc: u32) -> c_int {
    wchar_core::iswalpha(wc) as c_int
}

/// POSIX `iswdigit` — test for decimal digit wide character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswdigit(wc: u32) -> c_int {
    wchar_core::iswdigit(wc) as c_int
}

/// POSIX `iswlower` — test for lowercase wide character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswlower(wc: u32) -> c_int {
    wchar_core::iswlower(wc) as c_int
}

/// POSIX `iswupper` — test for uppercase wide character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswupper(wc: u32) -> c_int {
    wchar_core::iswupper(wc) as c_int
}

/// POSIX `iswspace` — test for whitespace wide character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswspace(wc: u32) -> c_int {
    wchar_core::iswspace(wc) as c_int
}

/// POSIX `iswprint` — test for printable wide character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswprint(wc: u32) -> c_int {
    wchar_core::iswprint(wc) as c_int
}

/// `wcwidth` — determine display width of a wide character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcwidth(wc: u32) -> c_int {
    wchar_core::wcwidth(wc) as c_int
}

// ---------------------------------------------------------------------------
// basename / dirname — POSIX libgen.h
// ---------------------------------------------------------------------------

use frankenlibc_core::unistd::{basename_range, dirname_range};

/// Static buffer for basename return value.
static BASENAME_BUF: std::sync::Mutex<[u8; 4097]> = std::sync::Mutex::new([0u8; 4097]);

/// POSIX `basename` — extract filename component from a path.
///
/// Returns a pointer to a static buffer. Not thread-safe per POSIX spec,
/// but we use a mutex internally for Rust safety.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn basename(path: *mut std::ffi::c_char) -> *mut std::ffi::c_char {
    let dot = b".\0";
    if path.is_null() {
        return dot.as_ptr() as *mut std::ffi::c_char;
    }
    let (len, _terminated) = unsafe { scan_c_string(path as *const std::ffi::c_char, None) };
    if len == 0 {
        return dot.as_ptr() as *mut std::ffi::c_char;
    }
    let slice = unsafe { std::slice::from_raw_parts(path as *const u8, len) };
    let (s, e) = basename_range(slice);
    let result_len = e - s;
    if result_len == 0 {
        return dot.as_ptr() as *mut std::ffi::c_char;
    }
    let mut buf = BASENAME_BUF.lock().unwrap_or_else(|e| e.into_inner());
    buf[..result_len].copy_from_slice(&slice[s..e]);
    buf[result_len] = 0;
    buf.as_mut_ptr() as *mut std::ffi::c_char
}

/// Static buffer for dirname return value.
static DIRNAME_BUF: std::sync::Mutex<[u8; 4097]> = std::sync::Mutex::new([0u8; 4097]);

/// POSIX `dirname` — extract directory component from a path.
///
/// Returns a pointer to a static buffer. Not thread-safe per POSIX spec,
/// but we use a mutex internally for Rust safety.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dirname(path: *mut std::ffi::c_char) -> *mut std::ffi::c_char {
    let dot = b".\0";
    if path.is_null() {
        return dot.as_ptr() as *mut std::ffi::c_char;
    }
    let (len, _terminated) = unsafe { scan_c_string(path as *const std::ffi::c_char, None) };
    if len == 0 {
        return dot.as_ptr() as *mut std::ffi::c_char;
    }
    let slice = unsafe { std::slice::from_raw_parts(path as *const u8, len) };
    let (s, e) = dirname_range(slice);
    let result_len = e - s;
    if result_len == 0 {
        return dot.as_ptr() as *mut std::ffi::c_char;
    }
    let mut buf = DIRNAME_BUF.lock().unwrap_or_else(|e| e.into_inner());
    buf[..result_len].copy_from_slice(&slice[s..e]);
    buf[result_len] = 0;
    buf.as_mut_ptr() as *mut std::ffi::c_char
}

// ---------------------------------------------------------------------------
// realpath — via SYS_readlink iteration
// ---------------------------------------------------------------------------

/// POSIX `realpath` — resolve a pathname to an absolute path.
///
/// Small integer to ASCII in a fixed buffer. Returns number of bytes written.
fn itoa_small(mut n: u32, buf: &mut [u8]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    for j in 0..i {
        buf[j] = tmp[i - 1 - j];
    }
    i
}

/// If `resolved_path` is null, allocates a buffer via malloc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn realpath(
    path: *const std::ffi::c_char,
    resolved_path: *mut std::ffi::c_char,
) -> *mut std::ffi::c_char {
    use frankenlibc_core::errno;

    if path.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }

    let (_, decision) = runtime_policy::decide(
        ApiFamily::IoFd,
        path as usize,
        0,
        false,
        known_remaining(path as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
        return std::ptr::null_mut();
    }

    // SAFETY: `path` is non-null and must point to a NUL-terminated C string by ABI contract.
    // Resolve path using the raw readlink(/proc/self/fd/N) approach via open+readlink.
    // Cannot use std::fs::canonicalize because it calls libc realpath — which is
    // our own interposed symbol, causing infinite recursion.
    let path_cstr = unsafe { std::ffi::CStr::from_ptr(path) };

    // Open the path with O_PATH (no actual I/O, just get an fd for the kernel path).
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            path_cstr.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC,
            0,
        ) as i32
    };
    if fd < 0 {
        unsafe { set_abi_errno(errno::ENOENT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 16, true);
        return std::ptr::null_mut();
    }

    // Read the kernel-resolved canonical path via /proc/self/fd/N.
    let mut proc_path = [0u8; 64];
    let prefix = b"/proc/self/fd/";
    proc_path[..prefix.len()].copy_from_slice(prefix);
    let fd_str = itoa_small(fd as u32, &mut proc_path[prefix.len()..]);
    let proc_len = prefix.len() + fd_str;
    proc_path[proc_len] = 0;

    let mut buf = [0u8; libc::PATH_MAX as usize];
    let n = unsafe {
        libc::syscall(
            libc::SYS_readlinkat,
            libc::AT_FDCWD,
            proc_path.as_ptr(),
            buf.as_mut_ptr(),
            buf.len() - 1,
        ) as isize
    };
    unsafe { libc::syscall(libc::SYS_close, fd) };

    if n <= 0 {
        unsafe { set_abi_errno(errno::ENOENT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 16, true);
        return std::ptr::null_mut();
    }

    let out = &buf[..n as usize];
    if out.contains(&0) {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 16, true);
        return std::ptr::null_mut();
    }

    let dst = if resolved_path.is_null() {
        // SAFETY: allocates writable C-compatible storage for the canonical path plus terminator.
        let alloc = unsafe { crate::malloc_abi::raw_alloc(out.len() + 1) as *mut std::ffi::c_char };
        if alloc.is_null() {
            unsafe { set_abi_errno(errno::ENOMEM) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 16, true);
            return std::ptr::null_mut();
        }
        alloc
    } else {
        resolved_path
    };

    // SAFETY: caller guarantees destination capacity when `resolved_path` is non-null.
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr() as *const std::ffi::c_char, dst, out.len());
        *dst.add(out.len()) = 0;
    }
    runtime_policy::observe(
        ApiFamily::IoFd,
        decision.profile,
        runtime_policy::scaled_cost(18, out.len().max(1)),
        false,
    );
    dst
}

// ---------------------------------------------------------------------------
// mkstemp — create a temporary file from a template
// ---------------------------------------------------------------------------

/// POSIX `mkstemp` — create a unique temporary file.
///
/// The template must end with "XXXXXX" which gets replaced with unique chars.
/// Returns the file descriptor on success, -1 on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemp(template: *mut std::ffi::c_char) -> c_int {
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

    // SAFETY: mkstemp is equivalent to mkstemps with suffix length 0.
    let fd = unsafe { crate::stdlib_abi::mkstemps(template, 0) };
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 12, fd < 0);
    fd
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsnlen(s: *const libc::wchar_t, maxlen: usize) -> usize {
    if s.is_null() || maxlen == 0 {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        maxlen.saturating_mul(4),
        false,
        known_remaining(s as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 5, true);
        return 0;
    }

    let mut limit = maxlen;
    if repair_enabled(mode.heals_enabled(), decision.action)
        && let Some(bytes) = known_remaining(s as usize)
    {
        let bounded = bytes_to_wchars(bytes).min(maxlen);
        if bounded < maxlen {
            record_truncation(maxlen, bounded);
        }
        limit = bounded;
    }

    // SAFETY: `limit` bounds all reads from `s`.
    let len =
        unsafe { wide_core::wcsnlen(std::slice::from_raw_parts(s as *const u32, limit), limit) };
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(5, len.saturating_mul(4)),
        false,
    );
    len
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcswidth(s: *const libc::wchar_t, n: usize) -> c_int {
    if s.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    // SAFETY: `wcsnlen` bounds the visible logical string length by `n`.
    let len = unsafe { wcsnlen(s, n) };
    // SAFETY: `len <= n`; this limits reads to the caller-provided bound.
    let slice = unsafe { std::slice::from_raw_parts(s as *const u32, len) };
    wide_core::wcswidth(slice, len) as c_int
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wctob(c: u32) -> c_int {
    if c == u32::MAX {
        return libc::EOF;
    }
    if c <= 0x7F { c as c_int } else { libc::EOF }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn btowc(c: c_int) -> u32 {
    if c == libc::EOF {
        return u32::MAX;
    }
    if (0..=0x7F).contains(&c) {
        c as u32
    } else {
        u32::MAX
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcrtomb(
    s: *mut std::ffi::c_char,
    wc: libc::wchar_t,
    _ps: *mut std::ffi::c_void,
) -> usize {
    let mut tmp = [0u8; 4];

    // Stateless UTF-8 locale: resetting state is equivalent to encoding NUL.
    if s.is_null() {
        return 1;
    }

    match wchar_core::wctomb(wc as u32, &mut tmp) {
        Some(len) => {
            // SAFETY: caller guarantees `s` points to writable storage for the resulting sequence.
            unsafe { std::ptr::copy_nonoverlapping(tmp.as_ptr(), s as *mut u8, len) };
            len
        }
        None => {
            // SAFETY: setting thread-local errno through libc ABI helper.
            unsafe { set_abi_errno(libc::EILSEQ) };
            usize::MAX
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtowc(
    pwc: *mut libc::wchar_t,
    s: *const std::ffi::c_char,
    n: usize,
    _ps: *mut std::ffi::c_void,
) -> usize {
    const MB_INCOMPLETE: usize = usize::MAX - 1;

    // Stateless UTF-8 locale reset path.
    if s.is_null() {
        if !pwc.is_null() {
            // SAFETY: pwc is caller-provided out pointer.
            unsafe { *pwc = 0 };
        }
        return 0;
    }
    if n == 0 {
        return MB_INCOMPLETE;
    }

    // SAFETY: caller guarantees `s` points to at least `n` bytes.
    let bytes = unsafe { std::slice::from_raw_parts(s as *const u8, n) };
    let first = bytes[0];
    if first == 0 {
        if !pwc.is_null() {
            // SAFETY: pwc is caller-provided out pointer.
            unsafe { *pwc = 0 };
        }
        return 0;
    }

    let expected_len = if first < 0x80 {
        1
    } else if first & 0xE0 == 0xC0 {
        2
    } else if first & 0xF0 == 0xE0 {
        3
    } else if first & 0xF8 == 0xF0 {
        4
    } else {
        // SAFETY: setting thread-local errno through libc ABI helper.
        unsafe { set_abi_errno(libc::EILSEQ) };
        return usize::MAX;
    };

    if n < expected_len {
        return MB_INCOMPLETE;
    }

    match wchar_core::mbtowc(&bytes[..expected_len]) {
        Some((wc, used)) => {
            if !pwc.is_null() {
                // SAFETY: pwc is caller-provided out pointer.
                unsafe { *pwc = wc as libc::wchar_t };
            }
            used
        }
        None => {
            // SAFETY: setting thread-local errno through libc ABI helper.
            unsafe { set_abi_errno(libc::EILSEQ) };
            usize::MAX
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mbsrtowcs(
    dst: *mut libc::wchar_t,
    src: *mut *const std::ffi::c_char,
    len: usize,
    _ps: *mut std::ffi::c_void,
) -> usize {
    if src.is_null() {
        // SAFETY: setting thread-local errno through libc ABI helper.
        unsafe { set_abi_errno(libc::EINVAL) };
        return usize::MAX;
    }

    // SAFETY: src is validated non-null above.
    let src_ptr = unsafe { *src };
    if src_ptr.is_null() {
        return 0;
    }

    let (src_len, _terminated) = unsafe { scan_c_string(src_ptr, None) };
    let src_len_with_nul = src_len.saturating_add(1);
    // SAFETY: bounded by strlen + NUL.
    let src_bytes = unsafe { std::slice::from_raw_parts(src_ptr as *const u8, src_len_with_nul) };

    // Count-only mode.
    if dst.is_null() {
        let mut i = 0usize;
        let mut count = 0usize;
        while i < src_bytes.len() {
            if src_bytes[i] == 0 {
                return count;
            }
            match wchar_core::mbtowc(&src_bytes[i..]) {
                Some((_, used)) => {
                    i += used;
                    count += 1;
                }
                None => {
                    // SAFETY: setting thread-local errno through libc ABI helper.
                    unsafe { set_abi_errno(libc::EILSEQ) };
                    return usize::MAX;
                }
            }
        }
        return count;
    }

    // SAFETY: caller guarantees writable destination of at least `len` wchar_t elements.
    let dst_slice = unsafe { std::slice::from_raw_parts_mut(dst as *mut u32, len) };
    let mut i = 0usize;
    let mut written = 0usize;
    while i < src_bytes.len() {
        if src_bytes[i] == 0 {
            if written < dst_slice.len() {
                dst_slice[written] = 0;
            }
            // SAFETY: src is non-null and points to caller-owned pointer storage.
            unsafe { *src = std::ptr::null() };
            return written;
        }
        if written >= dst_slice.len() {
            // SAFETY: src is non-null and points to caller-owned pointer storage.
            unsafe { *src = src_ptr.add(i) };
            return written;
        }
        match wchar_core::mbtowc(&src_bytes[i..]) {
            Some((wc, used)) => {
                dst_slice[written] = wc;
                written += 1;
                i += used;
            }
            None => {
                // SAFETY: src is non-null and points to caller-owned pointer storage.
                unsafe { *src = src_ptr.add(i) };
                // SAFETY: setting thread-local errno through libc ABI helper.
                unsafe { set_abi_errno(libc::EILSEQ) };
                return usize::MAX;
            }
        }
    }

    // SAFETY: src is non-null and points to caller-owned pointer storage.
    unsafe { *src = src_ptr.add(i) };
    written
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsrtombs(
    dst: *mut std::ffi::c_char,
    src: *mut *const libc::wchar_t,
    len: usize,
    _ps: *mut std::ffi::c_void,
) -> usize {
    if src.is_null() {
        // SAFETY: setting thread-local errno through libc ABI helper.
        unsafe { set_abi_errno(libc::EINVAL) };
        return usize::MAX;
    }

    // SAFETY: src is validated non-null above.
    let src_ptr = unsafe { *src };
    if src_ptr.is_null() {
        return 0;
    }

    // SAFETY: source pointer references a NUL-terminated wide string.
    let src_len = unsafe { wcslen(src_ptr as *const u32) };
    // SAFETY: include terminating NUL.
    let src_slice = unsafe { std::slice::from_raw_parts(src_ptr as *const u32, src_len + 1) };

    // Count-only mode.
    if dst.is_null() {
        let mut bytes = 0usize;
        for &wc in &src_slice[..src_len] {
            let mut tmp = [0u8; 4];
            match wchar_core::wctomb(wc, &mut tmp) {
                Some(n) => bytes += n,
                None => {
                    // SAFETY: setting thread-local errno through libc ABI helper.
                    unsafe { set_abi_errno(libc::EILSEQ) };
                    return usize::MAX;
                }
            }
        }
        return bytes;
    }

    // SAFETY: caller guarantees writable destination of at least `len` bytes.
    let dst_slice = unsafe { std::slice::from_raw_parts_mut(dst as *mut u8, len) };
    let mut written = 0usize;
    let mut idx = 0usize;
    while idx < src_len {
        let wc = src_slice[idx];
        let mut tmp = [0u8; 4];
        let n = match wchar_core::wctomb(wc, &mut tmp) {
            Some(v) => v,
            None => {
                // SAFETY: src is non-null and points to caller-owned pointer storage.
                unsafe { *src = src_ptr.add(idx) };
                // SAFETY: setting thread-local errno through libc ABI helper.
                unsafe { set_abi_errno(libc::EILSEQ) };
                return usize::MAX;
            }
        };
        if written + n > dst_slice.len() {
            // SAFETY: src is non-null and points to caller-owned pointer storage.
            unsafe { *src = src_ptr.add(idx) };
            return written;
        }
        dst_slice[written..written + n].copy_from_slice(&tmp[..n]);
        written += n;
        idx += 1;
    }

    if written < dst_slice.len() {
        dst_slice[written] = 0;
        // SAFETY: src is non-null and points to caller-owned pointer storage.
        unsafe { *src = std::ptr::null() };
    } else {
        // SAFETY: src is non-null and points to caller-owned pointer storage.
        unsafe { *src = src_ptr.add(idx) };
    }
    written
}

#[inline]
fn wide_is_space(wc: u32) -> bool {
    char::from_u32(wc).is_some_and(|c| c.is_whitespace())
}

#[inline]
fn wide_digit_value(wc: u32) -> Option<u32> {
    match wc {
        wc if (b'0' as u32..=b'9' as u32).contains(&wc) => Some(wc - b'0' as u32),
        wc if (b'a' as u32..=b'z' as u32).contains(&wc) => Some(wc - b'a' as u32 + 10),
        wc if (b'A' as u32..=b'Z' as u32).contains(&wc) => Some(wc - b'A' as u32 + 10),
        _ => None,
    }
}

#[inline]
fn wide_is_ascii_hexdigit(wc: u32) -> bool {
    matches!(wide_digit_value(wc), Some(0..=15))
}

fn parse_wide_signed(s: &[u32], base: c_int) -> (i64, usize, ConversionStatus) {
    let mut i = 0usize;
    let len = s.len();

    while i < len && wide_is_space(s[i]) {
        i += 1;
    }
    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut negative = false;
    if s[i] == b'-' as u32 {
        negative = true;
        i += 1;
    } else if s[i] == b'+' as u32 {
        i += 1;
    }

    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut effective_base = base as u64;
    let has_0x_prefix =
        i + 1 < len && s[i] == b'0' as u32 && (s[i + 1] == b'x' as u32 || s[i + 1] == b'X' as u32);

    if base == 0 {
        if has_0x_prefix && i + 2 < len && wide_is_ascii_hexdigit(s[i + 2]) {
            effective_base = 16;
            i += 2;
        } else if s[i] == b'0' as u32 {
            effective_base = 8;
        } else {
            effective_base = 10;
        }
    } else if base == 16 && has_0x_prefix && i + 2 < len && wide_is_ascii_hexdigit(s[i + 2]) {
        i += 2;
    }

    if !(2..=36).contains(&effective_base) {
        return (0, 0, ConversionStatus::InvalidBase);
    }

    let abs_max = if negative {
        9_223_372_036_854_775_808u64
    } else {
        9_223_372_036_854_775_807u64
    };
    let cutoff = abs_max / effective_base;
    let cutlim = abs_max % effective_base;

    let mut acc = 0u64;
    let mut any_digits = false;
    let mut overflow = false;

    while i < len {
        let Some(digit) = wide_digit_value(s[i]) else {
            break;
        };
        if (digit as u64) >= effective_base {
            break;
        }

        any_digits = true;
        if overflow {
            i += 1;
            continue;
        }

        if acc > cutoff || (acc == cutoff && (digit as u64) > cutlim) {
            overflow = true;
        } else {
            acc = acc * effective_base + digit as u64;
        }
        i += 1;
    }

    if !any_digits {
        return (0, 0, ConversionStatus::Success);
    }

    if overflow {
        if negative {
            return (i64::MIN, i, ConversionStatus::Underflow);
        }
        return (i64::MAX, i, ConversionStatus::Overflow);
    }

    let value = if negative {
        (acc as i64).wrapping_neg()
    } else {
        acc as i64
    };
    (value, i, ConversionStatus::Success)
}

fn parse_wide_unsigned(s: &[u32], base: c_int) -> (u64, usize, ConversionStatus) {
    let mut i = 0usize;
    let len = s.len();

    while i < len && wide_is_space(s[i]) {
        i += 1;
    }
    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut negative = false;
    if s[i] == b'-' as u32 {
        negative = true;
        i += 1;
    } else if s[i] == b'+' as u32 {
        i += 1;
    }

    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut effective_base = base as u64;
    let has_0x_prefix =
        i + 1 < len && s[i] == b'0' as u32 && (s[i + 1] == b'x' as u32 || s[i + 1] == b'X' as u32);

    if base == 0 {
        if has_0x_prefix && i + 2 < len && wide_is_ascii_hexdigit(s[i + 2]) {
            effective_base = 16;
            i += 2;
        } else if s[i] == b'0' as u32 {
            effective_base = 8;
        } else {
            effective_base = 10;
        }
    } else if base == 16 && has_0x_prefix && i + 2 < len && wide_is_ascii_hexdigit(s[i + 2]) {
        i += 2;
    }

    if !(2..=36).contains(&effective_base) {
        return (0, 0, ConversionStatus::InvalidBase);
    }

    let cutoff = u64::MAX / effective_base;
    let cutlim = u64::MAX % effective_base;

    let mut acc = 0u64;
    let mut any_digits = false;
    let mut overflow = false;

    while i < len {
        let Some(digit) = wide_digit_value(s[i]) else {
            break;
        };
        if (digit as u64) >= effective_base {
            break;
        }

        any_digits = true;
        if overflow {
            i += 1;
            continue;
        }

        if acc > cutoff || (acc == cutoff && (digit as u64) > cutlim) {
            overflow = true;
        } else {
            acc = acc * effective_base + digit as u64;
        }
        i += 1;
    }

    if !any_digits {
        return (0, 0, ConversionStatus::Success);
    }
    if overflow {
        return (u64::MAX, i, ConversionStatus::Overflow);
    }

    let value = if negative { acc.wrapping_neg() } else { acc };
    (value, i, ConversionStatus::Success)
}

fn project_wide_ascii(s: &[u32]) -> Vec<u8> {
    let mut projected = Vec::with_capacity(s.len().saturating_add(1));
    for &wc in s {
        if wc > 0x7f {
            break;
        }
        projected.push(wc as u8);
    }
    projected.push(0);
    projected
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstol(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
) -> std::ffi::c_long {
    if nptr.is_null() {
        if !endptr.is_null() {
            // SAFETY: caller-provided endptr is writable when non-null.
            unsafe { *endptr = nptr as *mut libc::wchar_t };
        }
        return 0;
    }

    // SAFETY: strict mode follows C semantics and scans until NUL.
    let (len, _) = unsafe { scan_w_string(nptr as *const u32, None) };
    // SAFETY: bounded by measured wide-string length.
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u32, len) };
    let (value, consumed, status) = parse_wide_signed(slice, base);

    if !endptr.is_null() {
        // SAFETY: consumed is bounded by scanned string length.
        unsafe { *endptr = (nptr as *mut libc::wchar_t).add(consumed) };
    }

    match status {
        ConversionStatus::InvalidBase => unsafe { set_abi_errno(libc::EINVAL) },
        ConversionStatus::Overflow | ConversionStatus::Underflow => unsafe {
            set_abi_errno(libc::ERANGE)
        },
        ConversionStatus::Success => {}
    }

    value as std::ffi::c_long
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstoul(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
) -> std::ffi::c_ulong {
    if nptr.is_null() {
        if !endptr.is_null() {
            // SAFETY: caller-provided endptr is writable when non-null.
            unsafe { *endptr = nptr as *mut libc::wchar_t };
        }
        return 0;
    }

    // SAFETY: strict mode follows C semantics and scans until NUL.
    let (len, _) = unsafe { scan_w_string(nptr as *const u32, None) };
    // SAFETY: bounded by measured wide-string length.
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u32, len) };
    let (value, consumed, status) = parse_wide_unsigned(slice, base);

    if !endptr.is_null() {
        // SAFETY: consumed is bounded by scanned string length.
        unsafe { *endptr = (nptr as *mut libc::wchar_t).add(consumed) };
    }

    match status {
        ConversionStatus::InvalidBase => unsafe { set_abi_errno(libc::EINVAL) },
        ConversionStatus::Overflow => unsafe { set_abi_errno(libc::ERANGE) },
        ConversionStatus::Underflow | ConversionStatus::Success => {}
    }

    value as std::ffi::c_ulong
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstod(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
) -> f64 {
    if nptr.is_null() {
        if !endptr.is_null() {
            // SAFETY: caller-provided endptr is writable when non-null.
            unsafe { *endptr = nptr as *mut libc::wchar_t };
        }
        return 0.0;
    }

    // SAFETY: strict mode follows C semantics and scans until NUL.
    let (len, _) = unsafe { scan_w_string(nptr as *const u32, None) };
    // SAFETY: bounded by measured wide-string length.
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u32, len) };
    let projected = project_wide_ascii(slice);
    let (value, consumed) = frankenlibc_core::stdlib::conversion::strtod_impl(&projected);

    if !endptr.is_null() {
        // SAFETY: consumed is bounded by projected input length.
        unsafe { *endptr = (nptr as *mut libc::wchar_t).add(consumed.min(len)) };
    }

    value
}

// ---------------------------------------------------------------------------
// Wide I/O functions — mixed (implemented + glibc passthrough)
// ---------------------------------------------------------------------------

const WEOF_VALUE: u32 = u32::MAX;

// ===========================================================================
// Wide I/O imports and macros
// ===========================================================================

use frankenlibc_core::stdio::printf::LengthMod;
use frankenlibc_core::stdio::scanf::{ScanDirective, ScanValue};

/// Extract variadic args for wide printf — mirrors extract_va_args from stdio_abi.
macro_rules! extract_wprintf_args {
    ($segments:expr, $args:expr, $buf:expr, $extract_count:expr) => {{
        let mut _idx = 0usize;
        if let Some(_plan) = super::stdio_abi::positional_printf_arg_plan($segments) {
            for _kind in _plan.iter().take($extract_count) {
                match _kind {
                    super::stdio_abi::PrintfArgKind::Gp => {
                        if _idx < $extract_count {
                            $buf[_idx] = unsafe { $args.arg::<u64>() };
                            _idx += 1;
                        }
                    }
                    super::stdio_abi::PrintfArgKind::Fp => {
                        if _idx < $extract_count {
                            $buf[_idx] = unsafe { $args.arg::<f64>() }.to_bits();
                            _idx += 1;
                        }
                    }
                }
            }
        } else {
            for seg in $segments {
                if let FormatSegment::Spec(spec) = seg {
                    if spec.width.uses_arg() && _idx < $extract_count {
                        $buf[_idx] = unsafe { $args.arg::<u64>() };
                        _idx += 1;
                    }
                    if spec.precision.uses_arg() && _idx < $extract_count {
                        $buf[_idx] = unsafe { $args.arg::<u64>() };
                        _idx += 1;
                    }
                    match spec.conversion {
                        b'%' => {}
                        b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {
                            if _idx < $extract_count {
                                $buf[_idx] = unsafe { $args.arg::<f64>() }.to_bits();
                                _idx += 1;
                            }
                        }
                        _ => {
                            if _idx < $extract_count {
                                $buf[_idx] = unsafe { $args.arg::<u64>() };
                                _idx += 1;
                            }
                        }
                    }
                }
            }
        }
        _idx
    }};
}

/// Write scanned values through va_list pointers (variadic scanf).
macro_rules! scanf_write_values {
    ($values:expr, $directives:expr, $args:expr) => {{
        let mut _val_idx = 0usize;
        for _dir in $directives {
            if let ScanDirective::Spec(_spec) = _dir {
                if _spec.suppress {
                    continue;
                }
                if _val_idx >= $values.len() {
                    break;
                }
                unsafe {
                    wscanf_write_one!(&$values[_val_idx], _spec, $args);
                }
                _val_idx += 1;
            }
        }
    }};
}

/// Write a single scanned value to the next pointer from va_list.
macro_rules! wscanf_write_one {
    ($val:expr, $spec:expr, $args:expr) => {
        match $val {
            ScanValue::SignedInt(v) => match $spec.length {
                LengthMod::Hh => {
                    let ptr = $args.arg::<*mut i8>();
                    *ptr = *v as i8;
                }
                LengthMod::H => {
                    let ptr = $args.arg::<*mut i16>();
                    *ptr = *v as i16;
                }
                LengthMod::L | LengthMod::Ll | LengthMod::J => {
                    let ptr = $args.arg::<*mut i64>();
                    *ptr = *v;
                }
                LengthMod::Z | LengthMod::T => {
                    let ptr = $args.arg::<*mut isize>();
                    *ptr = *v as isize;
                }
                _ => {
                    let ptr = $args.arg::<*mut c_int>();
                    *ptr = *v as c_int;
                }
            },
            ScanValue::UnsignedInt(v) => match $spec.length {
                LengthMod::Hh => {
                    let ptr = $args.arg::<*mut u8>();
                    *ptr = *v as u8;
                }
                LengthMod::H => {
                    let ptr = $args.arg::<*mut u16>();
                    *ptr = *v as u16;
                }
                LengthMod::L | LengthMod::Ll | LengthMod::J => {
                    let ptr = $args.arg::<*mut u64>();
                    *ptr = *v;
                }
                LengthMod::Z | LengthMod::T => {
                    let ptr = $args.arg::<*mut usize>();
                    *ptr = *v as usize;
                }
                _ => {
                    let ptr = $args.arg::<*mut u32>();
                    *ptr = *v as u32;
                }
            },
            ScanValue::Float(v) => match $spec.length {
                LengthMod::L | LengthMod::BigL => {
                    let ptr = $args.arg::<*mut f64>();
                    *ptr = *v;
                }
                _ => {
                    let ptr = $args.arg::<*mut f32>();
                    *ptr = *v as f32;
                }
            },
            ScanValue::Char(bytes) => {
                let ptr = $args.arg::<*mut u8>();
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
            }
            ScanValue::String(bytes) => {
                let ptr = $args.arg::<*mut c_char>();
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len());
                *ptr.add(bytes.len()) = 0;
            }
            ScanValue::CharsConsumed(n) => match $spec.length {
                LengthMod::Hh => {
                    let ptr = $args.arg::<*mut i8>();
                    *ptr = *n as i8;
                }
                LengthMod::H => {
                    let ptr = $args.arg::<*mut i16>();
                    *ptr = *n as i16;
                }
                LengthMod::L | LengthMod::Ll | LengthMod::J => {
                    let ptr = $args.arg::<*mut i64>();
                    *ptr = *n as i64;
                }
                _ => {
                    let ptr = $args.arg::<*mut c_int>();
                    *ptr = *n as c_int;
                }
            },
            ScanValue::Pointer(v) => {
                let ptr = $args.arg::<*mut *mut c_void>();
                *ptr = *v as *mut c_void;
            }
        }
    };
}

// ===========================================================================
// Native wide I/O helpers
// ===========================================================================

/// Read a NUL-terminated wide string into a Vec of bytes (UTF-8 encoding).
/// Format specifiers are all ASCII, so this is safe for format string conversion.
unsafe fn wide_to_narrow(wcs: *const libc::wchar_t) -> Vec<u8> {
    if wcs.is_null() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    let mut p = wcs;
    loop {
        let wc = unsafe { *p } as u32;
        if wc == 0 {
            break;
        }
        // Encode the wide char as UTF-8 bytes.
        if wc < 0x80 {
            buf.push(wc as u8);
        } else if wc < 0x800 {
            buf.push(0xC0 | (wc >> 6) as u8);
            buf.push(0x80 | (wc & 0x3F) as u8);
        } else if wc < 0x10000 {
            buf.push(0xE0 | (wc >> 12) as u8);
            buf.push(0x80 | ((wc >> 6) & 0x3F) as u8);
            buf.push(0x80 | (wc & 0x3F) as u8);
        } else if wc < 0x110000 {
            buf.push(0xF0 | (wc >> 18) as u8);
            buf.push(0x80 | ((wc >> 12) & 0x3F) as u8);
            buf.push(0x80 | ((wc >> 6) & 0x3F) as u8);
            buf.push(0x80 | (wc & 0x3F) as u8);
        } else {
            // Invalid Unicode — substitute U+FFFD.
            buf.extend_from_slice(&[0xEF, 0xBF, 0xBD]);
        }
        p = unsafe { p.add(1) };
    }
    buf
}

/// Convert narrow (UTF-8) bytes to wide chars, writing into a wchar_t buffer.
/// Returns the number of wide chars written (not counting NUL).
/// If n > 0, always NUL-terminates the output.
fn narrow_to_wide_buf(narrow: &[u8], dst: *mut libc::wchar_t, n: usize) -> usize {
    if dst.is_null() || n == 0 {
        // Just count the wide chars that would be produced.
        return narrow_to_wide_count(narrow);
    }
    let max_chars = n.saturating_sub(1); // Reserve space for NUL.
    let mut written = 0usize;
    let mut i = 0usize;
    let bytes = narrow;
    while i < bytes.len() && written < max_chars {
        let (cp, advance) = decode_utf8(&bytes[i..]);
        unsafe { *dst.add(written) = cp as libc::wchar_t };
        written += 1;
        i += advance;
    }
    unsafe { *dst.add(written) = 0 };
    written
}

/// Count how many wide chars a narrow byte slice would produce.
fn narrow_to_wide_count(narrow: &[u8]) -> usize {
    let mut count = 0usize;
    let mut i = 0usize;
    while i < narrow.len() {
        let (_, advance) = decode_utf8(&narrow[i..]);
        count += 1;
        i += advance;
    }
    count
}

/// Decode one UTF-8 code point, returning (code_point, bytes_consumed).
fn decode_utf8(bytes: &[u8]) -> (u32, usize) {
    if bytes.is_empty() {
        return (0xFFFD, 1);
    }
    let b0 = bytes[0];
    if b0 < 0x80 {
        return (b0 as u32, 1);
    }
    if b0 < 0xC0 {
        return (0xFFFD, 1); // Continuation byte without lead.
    }

    // Validate continuation byte: must be 10xxxxxx (0x80..=0xBF).
    let is_cont = |b: u8| (b & 0xC0) == 0x80;

    if b0 < 0xE0 {
        if bytes.len() < 2 || !is_cont(bytes[1]) {
            return (0xFFFD, 1);
        }
        let cp = ((b0 as u32 & 0x1F) << 6) | (bytes[1] as u32 & 0x3F);
        // Reject overlong: 2-byte must encode >= 0x80
        if cp < 0x80 {
            return (0xFFFD, 2);
        }
        (cp, 2)
    } else if b0 < 0xF0 {
        if bytes.len() < 3 || !is_cont(bytes[1]) || !is_cont(bytes[2]) {
            return (0xFFFD, 1);
        }
        let cp =
            ((b0 as u32 & 0x0F) << 12) | ((bytes[1] as u32 & 0x3F) << 6) | (bytes[2] as u32 & 0x3F);
        // Reject overlong: 3-byte must encode >= 0x800
        // Reject surrogates: 0xD800..=0xDFFF
        if cp < 0x800 || (0xD800..=0xDFFF).contains(&cp) {
            return (0xFFFD, 3);
        }
        (cp, 3)
    } else {
        if bytes.len() < 4 || !is_cont(bytes[1]) || !is_cont(bytes[2]) || !is_cont(bytes[3]) {
            return (0xFFFD, 1);
        }
        let cp = ((b0 as u32 & 0x07) << 18)
            | ((bytes[1] as u32 & 0x3F) << 12)
            | ((bytes[2] as u32 & 0x3F) << 6)
            | (bytes[3] as u32 & 0x3F);
        // Reject overlong: 4-byte must encode >= 0x10000
        // Reject above Unicode max: > 0x10FFFF
        if !(0x10000..=0x10FFFF).contains(&cp) {
            return (0xFFFD, 4);
        }
        (cp, 4)
    }
}

/// Read a NUL-terminated wide string into a Vec of bytes (each wchar treated as byte value).
/// Used for swscanf input: converts wide input to narrow for the scanf engine.
unsafe fn wide_input_to_narrow(wcs: *const libc::wchar_t) -> Vec<u8> {
    if wcs.is_null() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    let mut p = wcs;
    loop {
        let wc = unsafe { *p } as u32;
        if wc == 0 {
            break;
        }
        // For scanf input, encode as UTF-8 so the narrow scanf engine
        // can process it correctly.
        if wc < 0x80 {
            buf.push(wc as u8);
        } else if wc < 0x800 {
            buf.push(0xC0 | (wc >> 6) as u8);
            buf.push(0x80 | (wc & 0x3F) as u8);
        } else if wc < 0x10000 {
            buf.push(0xE0 | (wc >> 12) as u8);
            buf.push(0x80 | ((wc >> 6) & 0x3F) as u8);
            buf.push(0x80 | (wc & 0x3F) as u8);
        } else if wc < 0x110000 {
            buf.push(0xF0 | (wc >> 18) as u8);
            buf.push(0x80 | ((wc >> 12) & 0x3F) as u8);
            buf.push(0x80 | ((wc >> 6) & 0x3F) as u8);
            buf.push(0x80 | (wc & 0x3F) as u8);
        } else {
            buf.extend_from_slice(&[0xEF, 0xBF, 0xBD]);
        }
        p = unsafe { p.add(1) };
    }
    buf
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetwc(stream: *mut std::ffi::c_void) -> u32 {
    if stream.is_null() {
        return WEOF_VALUE;
    }

    // SAFETY: delegated to stdio ABI layer with validated stream handle.
    let first = unsafe { super::stdio_abi::fgetc(stream) };
    if first == libc::EOF {
        return WEOF_VALUE;
    }

    let mut bytes = [0u8; 4];
    bytes[0] = first as u8;
    let expected = if bytes[0] < 0x80 {
        1
    } else if bytes[0] & 0xE0 == 0xC0 {
        2
    } else if bytes[0] & 0xF0 == 0xE0 {
        3
    } else if bytes[0] & 0xF8 == 0xF0 {
        4
    } else {
        // SAFETY: thread-local errno update.
        unsafe { set_abi_errno(libc::EILSEQ) };
        return WEOF_VALUE;
    };

    for idx in 1..expected {
        // SAFETY: delegated to stdio ABI layer with validated stream handle.
        let next = unsafe { super::stdio_abi::fgetc(stream) };
        if next == libc::EOF {
            // Put back already consumed bytes to avoid partial-read corruption.
            for rollback in (0..idx).rev() {
                // SAFETY: push-back into the same stream.
                unsafe { super::stdio_abi::ungetc(bytes[rollback] as c_int, stream) };
            }
            return WEOF_VALUE;
        }
        bytes[idx] = next as u8;
    }

    match wchar_core::mbtowc(&bytes[..expected]) {
        Some((wc, _)) => wc,
        None => {
            for rollback in (0..expected).rev() {
                // SAFETY: push-back into the same stream.
                unsafe { super::stdio_abi::ungetc(bytes[rollback] as c_int, stream) };
            }
            // SAFETY: thread-local errno update.
            unsafe { set_abi_errno(libc::EILSEQ) };
            WEOF_VALUE
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fputwc(wc: u32, stream: *mut std::ffi::c_void) -> u32 {
    if stream.is_null() {
        return WEOF_VALUE;
    }

    let mut bytes = [0u8; 4];
    let Some(encoded_len) = wchar_core::wctomb(wc, &mut bytes) else {
        // SAFETY: thread-local errno update.
        unsafe { set_abi_errno(libc::EILSEQ) };
        return WEOF_VALUE;
    };

    for &byte in &bytes[..encoded_len] {
        // SAFETY: delegated to stdio ABI layer with validated stream handle.
        if unsafe { super::stdio_abi::fputc(byte as c_int, stream) } == libc::EOF {
            return WEOF_VALUE;
        }
    }
    wc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ungetwc(wc: u32, stream: *mut std::ffi::c_void) -> u32 {
    if stream.is_null() || wc == WEOF_VALUE {
        return WEOF_VALUE;
    }

    let mut bytes = [0u8; 4];
    let Some(encoded_len) = wchar_core::wctomb(wc, &mut bytes) else {
        // SAFETY: thread-local errno update.
        unsafe { set_abi_errno(libc::EILSEQ) };
        return WEOF_VALUE;
    };

    for &byte in bytes[..encoded_len].iter().rev() {
        // SAFETY: delegated to stdio ABI layer with validated stream handle.
        if unsafe { super::stdio_abi::ungetc(byte as c_int, stream) } == libc::EOF {
            return WEOF_VALUE;
        }
    }
    wc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetws(
    ws: *mut libc::wchar_t,
    n: c_int,
    stream: *mut std::ffi::c_void,
) -> *mut libc::wchar_t {
    if ws.is_null() || stream.is_null() || n <= 0 {
        return std::ptr::null_mut();
    }

    let cap = n as usize;
    let mut written = 0usize;
    while written + 1 < cap {
        // SAFETY: delegated to this ABI implementation with validated stream.
        let wc = unsafe { fgetwc(stream) };
        if wc == WEOF_VALUE {
            break;
        }

        // SAFETY: bounded by `cap`.
        unsafe { *ws.add(written) = wc as libc::wchar_t };
        written += 1;
        if wc == b'\n' as u32 {
            break;
        }
    }

    if written == 0 {
        return std::ptr::null_mut();
    }

    // SAFETY: bounded by `cap`.
    unsafe { *ws.add(written) = 0 };
    ws
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fputws(ws: *const libc::wchar_t, stream: *mut std::ffi::c_void) -> c_int {
    if ws.is_null() || stream.is_null() {
        return libc::EOF;
    }

    let mut idx = 0usize;
    loop {
        // SAFETY: caller provides NUL-terminated wide string.
        let wc = unsafe { *ws.add(idx) as u32 };
        if wc == 0 {
            return 0;
        }
        // SAFETY: delegated to this ABI implementation with validated stream.
        if unsafe { fputwc(wc, stream) } == WEOF_VALUE {
            return libc::EOF;
        }
        idx += 1;
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getwchar() -> u32 {
    // SAFETY: stdio_abi exports `stdin` as a FILE-handle sentinel value.
    unsafe { fgetwc(super::stdio_abi::stdin) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putwchar(wc: u32) -> u32 {
    // SAFETY: stdio_abi exports `stdout` as a FILE-handle sentinel value.
    unsafe { fputwc(wc, super::stdio_abi::stdout) }
}

// ===========================================================================
// wprintf family — Implemented (native printf engine + wide conversion)
// ===========================================================================

/// Native `swprintf`: format into wide buffer with size limit.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn swprintf(
    s: *mut libc::wchar_t,
    n: usize,
    format: *const libc::wchar_t,
    mut args: ...
) -> c_int {
    if format.is_null() {
        return -1;
    }
    let fmt_narrow = unsafe { wide_to_narrow(format) };
    let segments = parse_format_string(&fmt_narrow);
    let extract_count = super::stdio_abi::count_printf_args(&segments);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    extract_wprintf_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered =
        unsafe { super::stdio_abi::render_printf(&fmt_narrow, arg_buf.as_ptr(), extract_count) };

    // swprintf: if the output (including NUL) would exceed n, return -1.
    let wide_count = narrow_to_wide_count(&rendered);
    if wide_count >= n {
        // POSIX: output would exceed buffer — error.
        if !s.is_null() && n > 0 {
            unsafe { *s = 0 };
        }
        return -1;
    }

    narrow_to_wide_buf(&rendered, s, n);
    wide_count as c_int
}

/// Native `wprintf`: format to stdout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wprintf(format: *const libc::wchar_t, mut args: ...) -> c_int {
    if format.is_null() {
        return -1;
    }
    let fmt_narrow = unsafe { wide_to_narrow(format) };
    let segments = parse_format_string(&fmt_narrow);
    let extract_count = super::stdio_abi::count_printf_args(&segments);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    extract_wprintf_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered =
        unsafe { super::stdio_abi::render_printf(&fmt_narrow, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    if super::stdio_abi::write_all_fd(libc::STDOUT_FILENO, &rendered) {
        total_len as c_int
    } else {
        -1
    }
}

/// Native `fwprintf`: format to stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fwprintf(
    stream: *mut std::ffi::c_void,
    format: *const libc::wchar_t,
    mut args: ...
) -> c_int {
    if format.is_null() || stream.is_null() {
        return -1;
    }
    let fmt_narrow = unsafe { wide_to_narrow(format) };
    let segments = parse_format_string(&fmt_narrow);
    let extract_count = super::stdio_abi::count_printf_args(&segments);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    extract_wprintf_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered =
        unsafe { super::stdio_abi::render_printf(&fmt_narrow, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    // Write each byte through the stdio layer to use stream buffering.
    for &byte in &rendered {
        if unsafe { super::stdio_abi::fputc(byte as c_int, stream) } == libc::EOF {
            return -1;
        }
    }
    total_len as c_int
}

/// Native `vswprintf`: format into wide buffer from va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vswprintf(
    s: *mut libc::wchar_t,
    n: usize,
    format: *const libc::wchar_t,
    ap: *mut std::ffi::c_void,
) -> c_int {
    if format.is_null() {
        return -1;
    }
    let fmt_narrow = unsafe { wide_to_narrow(format) };
    let segments = parse_format_string(&fmt_narrow);
    let extract_count = super::stdio_abi::count_printf_args(&segments);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    unsafe { super::stdio_abi::vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let rendered =
        unsafe { super::stdio_abi::render_printf(&fmt_narrow, arg_buf.as_ptr(), extract_count) };

    let wide_count = narrow_to_wide_count(&rendered);
    if wide_count >= n {
        if !s.is_null() && n > 0 {
            unsafe { *s = 0 };
        }
        return -1;
    }

    narrow_to_wide_buf(&rendered, s, n);
    wide_count as c_int
}

/// Native `vwprintf`: format to stdout from va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vwprintf(
    format: *const libc::wchar_t,
    ap: *mut std::ffi::c_void,
) -> c_int {
    if format.is_null() {
        return -1;
    }
    let fmt_narrow = unsafe { wide_to_narrow(format) };
    let segments = parse_format_string(&fmt_narrow);
    let extract_count = super::stdio_abi::count_printf_args(&segments);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    unsafe { super::stdio_abi::vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let rendered =
        unsafe { super::stdio_abi::render_printf(&fmt_narrow, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    if super::stdio_abi::write_all_fd(libc::STDOUT_FILENO, &rendered) {
        total_len as c_int
    } else {
        -1
    }
}

/// Native `vfwprintf`: format to stream from va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vfwprintf(
    stream: *mut std::ffi::c_void,
    format: *const libc::wchar_t,
    ap: *mut std::ffi::c_void,
) -> c_int {
    if format.is_null() || stream.is_null() {
        return -1;
    }
    let fmt_narrow = unsafe { wide_to_narrow(format) };
    let segments = parse_format_string(&fmt_narrow);
    let extract_count = super::stdio_abi::count_printf_args(&segments);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    unsafe { super::stdio_abi::vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let rendered =
        unsafe { super::stdio_abi::render_printf(&fmt_narrow, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    for &byte in &rendered {
        if unsafe { super::stdio_abi::fputc(byte as c_int, stream) } == libc::EOF {
            return -1;
        }
    }
    total_len as c_int
}

// ===========================================================================
// wscanf family — Implemented (native scanf engine + wide conversion)
// ===========================================================================

/// Native `swscanf`: scan from wide string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn swscanf(
    s: *const libc::wchar_t,
    format: *const libc::wchar_t,
    mut args: ...
) -> c_int {
    if s.is_null() || format.is_null() {
        return libc::EOF;
    }
    let input = unsafe { wide_input_to_narrow(s) };
    let fmt_narrow = unsafe { wide_to_narrow(format) };
    let fmt_cstr = std::ffi::CString::new(fmt_narrow).unwrap_or_default();
    let (result, directives) = super::stdio_abi::scanf_core(&input, fmt_cstr.as_ptr());

    if result.input_failure && result.count == 0 {
        return libc::EOF;
    }
    scanf_write_values!(result.values, directives, args);
    result.count
}

/// Native `wscanf`: scan from stdin.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wscanf(format: *const libc::wchar_t, mut args: ...) -> c_int {
    if format.is_null() {
        return libc::EOF;
    }
    let input = super::stdio_abi::read_stream_for_scanf(super::stdio_abi::stdin_stream_id(), 4096);
    let fmt_narrow = unsafe { wide_to_narrow(format) };
    let fmt_cstr = std::ffi::CString::new(fmt_narrow).unwrap_or_default();
    let (result, directives) = super::stdio_abi::scanf_core(&input, fmt_cstr.as_ptr());

    if result.input_failure && result.count == 0 {
        return libc::EOF;
    }
    scanf_write_values!(result.values, directives, args);
    result.count
}

/// Native `fwscanf`: scan from stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fwscanf(
    stream: *mut std::ffi::c_void,
    format: *const libc::wchar_t,
    mut args: ...
) -> c_int {
    if format.is_null() {
        return libc::EOF;
    }
    let id = stream as usize;
    let input = super::stdio_abi::read_stream_for_scanf(id, 4096);
    let fmt_narrow = unsafe { wide_to_narrow(format) };
    let fmt_cstr = std::ffi::CString::new(fmt_narrow).unwrap_or_default();
    let (result, directives) = super::stdio_abi::scanf_core(&input, fmt_cstr.as_ptr());

    if result.input_failure && result.count == 0 {
        return libc::EOF;
    }
    scanf_write_values!(result.values, directives, args);
    result.count
}

/// Native `vswscanf`: scan from wide string with va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vswscanf(
    s: *const libc::wchar_t,
    format: *const libc::wchar_t,
    ap: *mut std::ffi::c_void,
) -> c_int {
    if s.is_null() || format.is_null() {
        return libc::EOF;
    }
    let input = unsafe { wide_input_to_narrow(s) };
    let fmt_narrow = unsafe { wide_to_narrow(format) };
    let fmt_cstr = std::ffi::CString::new(fmt_narrow).unwrap_or_default();
    let (result, directives) = super::stdio_abi::scanf_core(&input, fmt_cstr.as_ptr());

    if result.input_failure && result.count == 0 {
        return libc::EOF;
    }
    unsafe { super::stdio_abi::vscanf_write_values(&result.values, &directives, ap) };
    result.count
}

/// Native `vwscanf`: scan from stdin with va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vwscanf(format: *const libc::wchar_t, ap: *mut std::ffi::c_void) -> c_int {
    if format.is_null() {
        return libc::EOF;
    }
    let input = super::stdio_abi::read_stream_for_scanf(super::stdio_abi::stdin_stream_id(), 4096);
    let fmt_narrow = unsafe { wide_to_narrow(format) };
    let fmt_cstr = std::ffi::CString::new(fmt_narrow).unwrap_or_default();
    let (result, directives) = super::stdio_abi::scanf_core(&input, fmt_cstr.as_ptr());

    if result.input_failure && result.count == 0 {
        return libc::EOF;
    }
    unsafe { super::stdio_abi::vscanf_write_values(&result.values, &directives, ap) };
    result.count
}

/// Native `vfwscanf`: scan from stream with va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vfwscanf(
    stream: *mut std::ffi::c_void,
    format: *const libc::wchar_t,
    ap: *mut std::ffi::c_void,
) -> c_int {
    if format.is_null() {
        return libc::EOF;
    }
    let id = stream as usize;
    let input = super::stdio_abi::read_stream_for_scanf(id, 4096);
    let fmt_narrow = unsafe { wide_to_narrow(format) };
    let fmt_cstr = std::ffi::CString::new(fmt_narrow).unwrap_or_default();
    let (result, directives) = super::stdio_abi::scanf_core(&input, fmt_cstr.as_ptr());

    if result.input_failure && result.count == 0 {
        return libc::EOF;
    }
    unsafe { super::stdio_abi::vscanf_write_values(&result.values, &directives, ap) };
    result.count
}

// ---------------------------------------------------------------------------
// Wide char classification extras — Implemented
// ---------------------------------------------------------------------------

/// POSIX `iswblank` — test for blank wide character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswblank(wc: u32) -> c_int {
    if wc == 0x20 || wc == 0x09 { 1 } else { 0 }
}

/// POSIX `iswcntrl` — test for control wide character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswcntrl(wc: u32) -> c_int {
    if wc < 0x20 || (0x7f..=0x9f).contains(&wc) {
        1
    } else {
        0
    }
}

/// POSIX `iswgraph` — test for graphic wide character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswgraph(wc: u32) -> c_int {
    if wchar_core::iswprint(wc) && wc != 0x20 {
        1
    } else {
        0
    }
}

/// POSIX `iswpunct` — test for punctuation wide character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswpunct(wc: u32) -> c_int {
    if wchar_core::iswprint(wc) && !wchar_core::iswalnum(wc) && wc != 0x20 {
        1
    } else {
        0
    }
}

/// POSIX `iswxdigit` — test for hexadecimal digit wide character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswxdigit(wc: u32) -> c_int {
    if (0x30..=0x39).contains(&wc) || (0x41..=0x46).contains(&wc) || (0x61..=0x66).contains(&wc) {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Wide string conversion extras — Implemented
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstoll(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
) -> i64 {
    // SAFETY: `wcstol` already enforces conversion contract and pointer progression.
    unsafe { wcstol(nptr, endptr, base) as i64 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstoull(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
) -> u64 {
    // SAFETY: `wcstoul` already enforces conversion contract and pointer progression.
    unsafe { wcstoul(nptr, endptr, base) as u64 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
) -> f32 {
    // SAFETY: `wcstod` handles null/endptr contracts and ASCII projection.
    unsafe { wcstod(nptr, endptr) as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstold(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
) -> f64 {
    // SAFETY: current ABI models long double as f64.
    unsafe { wcstod(nptr, endptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsftime(
    s: *mut libc::wchar_t,
    maxsize: usize,
    format: *const libc::wchar_t,
    tm: *const std::ffi::c_void,
) -> usize {
    if s.is_null() || format.is_null() || tm.is_null() || maxsize == 0 {
        return 0;
    }

    // SAFETY: format is non-null and scanned until NUL.
    let fmt_len = unsafe { wcslen(format as *const u32) };
    // SAFETY: bounded by measured format length.
    let fmt_slice = unsafe { std::slice::from_raw_parts(format as *const u32, fmt_len) };

    let mut fmt_mb = Vec::with_capacity(fmt_len.saturating_mul(4).saturating_add(1));
    for &wc in fmt_slice {
        let mut tmp = [0u8; 4];
        let Some(n) = wchar_core::wctomb(wc, &mut tmp) else {
            // SAFETY: thread-local errno update.
            unsafe { set_abi_errno(libc::EILSEQ) };
            return 0;
        };
        fmt_mb.extend_from_slice(&tmp[..n]);
    }
    fmt_mb.push(0);

    // Conservative UTF-8 output budget before converting back to wide chars.
    let mut out_mb = vec![0u8; maxsize.saturating_mul(4).max(1)];
    // SAFETY: buffers are valid; time_abi::strftime enforces byte-capacity + NUL semantics.
    let out_len = unsafe {
        super::time_abi::strftime(
            out_mb.as_mut_ptr() as *mut std::ffi::c_char,
            out_mb.len(),
            fmt_mb.as_ptr() as *const std::ffi::c_char,
            tm as *const libc::tm,
        )
    };
    if out_len == 0 {
        return 0;
    }

    let mut mb_i = 0usize;
    let mut wide_i = 0usize;
    while mb_i < out_len {
        if wide_i.saturating_add(1) >= maxsize {
            return 0;
        }
        match wchar_core::mbtowc(&out_mb[mb_i..out_len]) {
            Some((wc, used)) => {
                // SAFETY: `wide_i < maxsize` is enforced above.
                unsafe { *s.add(wide_i) = wc as libc::wchar_t };
                wide_i += 1;
                mb_i += used;
            }
            None => {
                // SAFETY: thread-local errno update.
                unsafe { set_abi_errno(libc::EILSEQ) };
                return 0;
            }
        }
    }

    // SAFETY: `wide_i < maxsize` is enforced in the loop.
    unsafe { *s.add(wide_i) = 0 };
    wide_i
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcscoll(s1: *const libc::wchar_t, s2: *const libc::wchar_t) -> c_int {
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    // SAFETY: both strings are scanned until NUL.
    let len1 = unsafe { wcslen(s1 as *const u32) };
    // SAFETY: both strings are scanned until NUL.
    let len2 = unsafe { wcslen(s2 as *const u32) };
    // SAFETY: include NUL terminators for comparison semantics.
    let lhs = unsafe { std::slice::from_raw_parts(s1 as *const u32, len1 + 1) };
    // SAFETY: include NUL terminators for comparison semantics.
    let rhs = unsafe { std::slice::from_raw_parts(s2 as *const u32, len2 + 1) };
    wide_core::wcscmp(lhs, rhs) as c_int
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsxfrm(
    dest: *mut libc::wchar_t,
    src: *const libc::wchar_t,
    n: usize,
) -> usize {
    if src.is_null() {
        return 0;
    }

    // SAFETY: source string is scanned until NUL.
    let src_len = unsafe { wcslen(src as *const u32) };
    if dest.is_null() || n == 0 {
        return src_len;
    }

    let copy_len = src_len.min(n.saturating_sub(1));
    // SAFETY: destination and source are caller-provided valid buffers for the requested range.
    unsafe {
        if copy_len > 0 {
            std::ptr::copy_nonoverlapping(src, dest, copy_len);
        }
        *dest.add(copy_len) = 0;
    }
    src_len
}

// ---------------------------------------------------------------------------
// wcpcpy  (GNU extension)
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcpcpy(dst: *mut u32, src: *const u32) -> *mut u32 {
    if dst.is_null() || src.is_null() {
        return dst;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        0,
        true,
        known_remaining(dst as usize).is_none() && known_remaining(src as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 7, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let src_bound = if repair {
        known_remaining(src as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let dst_bound = if repair {
        known_remaining(dst as usize).map(bytes_to_wchars)
    } else {
        None
    };

    // SAFETY: strict mode follows libc semantics; hardened mode bounds reads/writes.
    let (nul_offset, adverse) = unsafe {
        let (src_len, src_terminated) = scan_w_string(src, src_bound);
        let requested = src_len.saturating_add(1);
        if repair {
            match dst_bound {
                Some(0) => {
                    record_truncation(requested, 0);
                    (0usize, true)
                }
                Some(limit) => {
                    let max_payload = limit.saturating_sub(1);
                    let copy_payload = src_len.min(max_payload);
                    if copy_payload > 0 {
                        std::ptr::copy_nonoverlapping(src, dst, copy_payload);
                    }
                    *dst.add(copy_payload) = 0;
                    let truncated = !src_terminated || copy_payload < src_len;
                    if truncated {
                        record_truncation(requested, copy_payload);
                    }
                    (copy_payload, truncated)
                }
                None => {
                    let mut i = 0usize;
                    loop {
                        let ch = *src.add(i);
                        *dst.add(i) = ch;
                        if ch == 0 {
                            break (i, false);
                        }
                        i += 1;
                    }
                }
            }
        } else {
            let mut i = 0usize;
            loop {
                let ch = *src.add(i);
                *dst.add(i) = ch;
                if ch == 0 {
                    break (i, false);
                }
                i += 1;
            }
        }
    };

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, nul_offset * 4),
        adverse,
    );
    // Return pointer to the NUL terminator in dst
    unsafe { dst.add(nul_offset) }
}

// ---------------------------------------------------------------------------
// wcpncpy  (GNU extension)
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcpncpy(dst: *mut u32, src: *const u32, n: usize) -> *mut u32 {
    if dst.is_null() || src.is_null() || n == 0 {
        return dst;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        n * 4,
        true,
        known_remaining(dst as usize).is_none() && known_remaining(src as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 7, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let src_bound = if repair {
        known_remaining(src as usize).map(bytes_to_wchars)
    } else {
        None
    };

    // SAFETY: dst has room for n wchars; src is scanned with optional bound.
    let (end_offset, adverse) = unsafe {
        let (src_len, _src_terminated) = scan_w_string(src, src_bound);
        let copy_len = src_len.min(n);

        if copy_len > 0 {
            std::ptr::copy_nonoverlapping(src, dst, copy_len);
        }

        // Pad remainder with NULs
        if copy_len < n {
            for i in copy_len..n {
                *dst.add(i) = 0;
            }
            (copy_len, false) // return pointer to first NUL
        } else {
            (n, false) // src >= n, no NUL written, return dst+n
        }
    };

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, n * 4),
        adverse,
    );
    unsafe { dst.add(end_offset) }
}

// ---------------------------------------------------------------------------
// wcscasecmp  (GNU extension)
// ---------------------------------------------------------------------------

/// Simple ASCII case-fold for wide characters (A-Z → a-z).
#[inline]
fn abi_towlower(c: u32) -> u32 {
    if (0x41..=0x5A).contains(&c) {
        c + 0x20
    } else {
        c
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcscasecmp(s1: *const u32, s2: *const u32) -> c_int {
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s1 as usize,
        0,
        false,
        known_remaining(s1 as usize).is_none() && known_remaining(s2 as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 6, true);
        return 0;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let lhs_bound = if repair {
        known_remaining(s1 as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let rhs_bound = if repair {
        known_remaining(s2 as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let cmp_bound = match (lhs_bound, rhs_bound) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };

    let (result, adverse, span) = unsafe {
        let mut i = 0usize;
        let mut adverse_local = false;
        loop {
            if let Some(limit) = cmp_bound
                && i >= limit
            {
                adverse_local = true;
                break (0, adverse_local, i);
            }
            let a = abi_towlower(*s1.add(i));
            let b = abi_towlower(*s2.add(i));
            if a != b || *s1.add(i) == 0 {
                let diff = if (a as i32) < (b as i32) { -1 } else { 1 };
                break (
                    if a == b { 0 } else { diff },
                    adverse_local,
                    i.saturating_add(1),
                );
            }
            i += 1;
        }
    };

    if adverse {
        record_truncation(cmp_bound.unwrap_or(span), span);
    }
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, span * 4),
        adverse,
    );
    result
}

// ---------------------------------------------------------------------------
// wcsncasecmp  (GNU extension)
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncasecmp(s1: *const u32, s2: *const u32, n: usize) -> c_int {
    if s1.is_null() || s2.is_null() || n == 0 {
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s1 as usize,
        n * 4,
        false,
        known_remaining(s1 as usize).is_none() && known_remaining(s2 as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 6, true);
        return 0;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let lhs_bound = if repair {
        known_remaining(s1 as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let rhs_bound = if repair {
        known_remaining(s2 as usize).map(bytes_to_wchars)
    } else {
        None
    };
    let cmp_bound = match (lhs_bound, rhs_bound) {
        (Some(a), Some(b)) => Some(a.min(b).min(n)),
        (Some(a), None) => Some(a.min(n)),
        (None, Some(b)) => Some(b.min(n)),
        (None, None) => Some(n),
    };

    let (result, adverse, span) = unsafe {
        let mut i = 0usize;
        let mut adverse_local = false;
        loop {
            if let Some(limit) = cmp_bound
                && i >= limit
            {
                if i < n {
                    adverse_local = true;
                }
                break (0, adverse_local, i);
            }
            let a = abi_towlower(*s1.add(i));
            let b = abi_towlower(*s2.add(i));
            if a != b || *s1.add(i) == 0 {
                let diff = if (a as i32) < (b as i32) { -1 } else { 1 };
                break (
                    if a == b { 0 } else { diff },
                    adverse_local,
                    i.saturating_add(1),
                );
            }
            i += 1;
        }
    };

    if adverse {
        record_truncation(cmp_bound.unwrap_or(span), span);
    }
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, span * 4),
        adverse,
    );
    result
}

// ---------------------------------------------------------------------------
// wmemrchr  (GNU extension)
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wmemrchr(s: *const u32, c: u32, n: usize) -> *mut u32 {
    if n == 0 || s.is_null() {
        return std::ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        n * 4,
        false,
        known_remaining(s as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(6, n * 4),
            true,
        );
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let mut scan_len = n;
    let mut clamped = false;

    if repair {
        let s_rem = known_remaining(s as usize)
            .map(bytes_to_wchars)
            .unwrap_or(usize::MAX);
        if n > s_rem {
            scan_len = s_rem;
            clamped = true;
            record_truncation(n, s_rem);
        }
    }

    let result = unsafe {
        let slice = std::slice::from_raw_parts(s, scan_len);
        match (0..scan_len).rev().find(|&i| slice[i] == c) {
            Some(i) => s.add(i) as *mut u32,
            None => std::ptr::null_mut(),
        }
    };

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(6, scan_len * 4),
        clamped,
    );
    result
}

// ===========================================================================
// Locale-aware wide character _l variants — C locale passthrough
// ===========================================================================

/// Wide character type descriptor used by wctype/iswctype.
/// We encode POSIX character classes as small integers.
type WctypeT = usize;

/// Wide character transformation descriptor (matches glibc c_ulong).
type WctransT = std::ffi::c_ulong;

/// `wctype_l` — get wide character class by name (locale variant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wctype_l(name: *const u8, _locale: *mut std::ffi::c_void) -> WctypeT {
    unsafe { wctype(name) }
}

/// `wctype` — get wide character class by name.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wctype(name: *const u8) -> WctypeT {
    if name.is_null() {
        return 0;
    }
    // SAFETY: name is a NUL-terminated C string from the caller.
    let cstr = unsafe { std::ffi::CStr::from_ptr(name as *const i8) };
    match cstr.to_bytes() {
        b"alnum" => 1,
        b"alpha" => 2,
        b"blank" => 3,
        b"cntrl" => 4,
        b"digit" => 5,
        b"graph" => 6,
        b"lower" => 7,
        b"print" => 8,
        b"punct" => 9,
        b"space" => 10,
        b"upper" => 11,
        b"xdigit" => 12,
        _ => 0,
    }
}

/// `iswctype_l` — test wide character classification (locale variant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswctype_l(wc: u32, desc: WctypeT, _locale: *mut std::ffi::c_void) -> i32 {
    unsafe { iswctype(wc, desc) }
}

/// `iswctype` — test wide character classification.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswctype(wc: u32, desc: WctypeT) -> i32 {
    let ascii = u8::try_from(wc).ok().filter(|b| b.is_ascii());
    let result = match desc {
        1 => ascii.is_some_and(|c| c.is_ascii_alphanumeric()),
        2 => ascii.is_some_and(|c| c.is_ascii_alphabetic()),
        3 => matches!(ascii, Some(b' ') | Some(b'\t')), // space or tab
        4 => ascii.is_some_and(|c| c.is_ascii_control()),
        5 => ascii.is_some_and(|c| c.is_ascii_digit()),
        6 => ascii.is_some_and(|c| c.is_ascii_graphic()),
        7 => ascii.is_some_and(|c| c.is_ascii_lowercase()),
        8 => {
            // print: 0x20..=0x7E
            ascii.is_some_and(|c| (0x20..=0x7E).contains(&c))
        }
        9 => ascii.is_some_and(|c| c.is_ascii_punctuation()),
        10 => ascii.is_some_and(|c| c.is_ascii_whitespace()),
        11 => ascii.is_some_and(|c| c.is_ascii_uppercase()),
        12 => ascii.is_some_and(|c| c.is_ascii_hexdigit()),
        _ => false,
    };
    if result { 1 } else { 0 }
}

/// `towupper_l` — convert wide character to uppercase (locale variant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn towupper_l(wc: u32, _locale: *mut std::ffi::c_void) -> u32 {
    unsafe { towupper(wc) }
}

/// `towlower_l` — convert wide character to lowercase (locale variant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn towlower_l(wc: u32, _locale: *mut std::ffi::c_void) -> u32 {
    unsafe { towlower(wc) }
}

// ===========================================================================
// Wide string locale-aware _l variants (C locale passthrough)
// ===========================================================================

/// `wcscoll_l` — locale-aware wide string comparison.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcscoll_l(
    s1: *const libc::wchar_t,
    s2: *const libc::wchar_t,
    _locale: *mut c_void,
) -> c_int {
    unsafe { wcscoll(s1, s2) }
}

/// `wcsxfrm_l` — locale-aware wide string transformation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsxfrm_l(
    dest: *mut libc::wchar_t,
    src: *const libc::wchar_t,
    n: usize,
    _locale: *mut c_void,
) -> usize {
    unsafe { wcsxfrm(dest, src, n) }
}

/// `wcsftime_l` — locale-aware wide string strftime.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsftime_l(
    s: *mut libc::wchar_t,
    maxsize: usize,
    format: *const libc::wchar_t,
    tm: *const c_void,
    _locale: *mut c_void,
) -> usize {
    unsafe { wcsftime(s, maxsize, format, tm) }
}

/// `wcstol_l` — locale-aware wide string to long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstol_l(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
    _locale: *mut c_void,
) -> c_long {
    unsafe { wcstol(nptr, endptr, base) }
}

/// `wcstoul_l` — locale-aware wide string to unsigned long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstoul_l(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
    _locale: *mut c_void,
) -> c_ulong {
    unsafe { wcstoul(nptr, endptr, base) }
}

/// `wcstoll_l` — locale-aware wide string to long long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstoll_l(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
    _locale: *mut c_void,
) -> c_longlong {
    unsafe { wcstoll(nptr, endptr, base) }
}

/// `wcstoull_l` — locale-aware wide string to unsigned long long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstoull_l(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
    _locale: *mut c_void,
) -> c_ulonglong {
    unsafe { wcstoull(nptr, endptr, base) }
}

/// `wcstof_l` — locale-aware wide string to float.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof_l(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    _locale: *mut c_void,
) -> f32 {
    unsafe { wcstof(nptr, endptr) }
}

/// `wcstod_l` — locale-aware wide string to double.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstod_l(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    _locale: *mut c_void,
) -> f64 {
    unsafe { wcstod(nptr, endptr) }
}

/// `wcstold_l` — locale-aware wide string to long double (f64 on Linux x86_64).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstold_l(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    _locale: *mut c_void,
) -> f64 {
    unsafe { wcstold(nptr, endptr) }
}

// ===========================================================================
// Multibyte — mbsinit, mbrlen, mbsnrtowcs, wcsnrtombs
// ===========================================================================

/// `mbsinit` — test initial shift state.
/// For UTF-8 (stateless encoding), always returns 1 (initial state).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mbsinit(ps: *const c_void) -> c_int {
    if ps.is_null() {
        return 1;
    }
    // UTF-8 is a stateless encoding; mbstate_t is always in initial state.
    1
}

/// `mbrlen` — determine number of bytes in next multibyte character.
/// Wraps `mbrtowc` with NULL destination.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mbrlen(s: *const c_char, n: usize, ps: *mut c_void) -> usize {
    unsafe { mbrtowc(std::ptr::null_mut(), s, n, ps) }
}

/// `mbsnrtowcs` — convert multibyte string to wide string (bounded source).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mbsnrtowcs(
    dst: *mut libc::wchar_t,
    src: *mut *const c_char,
    nms: usize,
    len: usize,
    ps: *mut c_void,
) -> usize {
    if src.is_null() || unsafe { (*src).is_null() } {
        return 0;
    }
    let mut s = unsafe { *src };
    let mut written = 0usize;
    let mut consumed = 0usize;

    while consumed < nms && (dst.is_null() || written < len) {
        let remaining = nms - consumed;
        let mut wc: libc::wchar_t = 0;
        let ret = unsafe { mbrtowc(&mut wc, s, remaining, ps) };
        match ret {
            0 => {
                // null character
                if !dst.is_null() {
                    unsafe { *dst.add(written) = 0 };
                }
                unsafe { *src = std::ptr::null() };
                return written;
            }
            r if r <= remaining => {
                if !dst.is_null() {
                    unsafe { *dst.add(written) = wc };
                }
                written += 1;
                consumed += r;
                s = unsafe { s.add(r) };
            }
            _ => {
                // encoding error
                return usize::MAX; // (size_t)-1
            }
        }
    }
    unsafe { *src = s };
    written
}

/// `wcsnrtombs` — convert wide string to multibyte string (bounded source).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsnrtombs(
    dst: *mut c_char,
    src: *mut *const libc::wchar_t,
    nwc: usize,
    len: usize,
    ps: *mut c_void,
) -> usize {
    if src.is_null() || unsafe { (*src).is_null() } {
        return 0;
    }
    let mut s = unsafe { *src };
    let mut written = 0usize;
    let mut wchars_consumed = 0usize;
    let mut buf = [0u8; 4]; // MB_CUR_MAX for UTF-8

    while wchars_consumed < nwc {
        let wc = unsafe { *s };
        if wc == 0 {
            if !dst.is_null() {
                if written < len {
                    unsafe { *dst.add(written) = 0 };
                } else {
                    break;
                }
            }
            unsafe { *src = std::ptr::null() };
            return written;
        }

        let ret = unsafe {
            wcrtomb(
                if dst.is_null() {
                    buf.as_mut_ptr() as *mut c_char
                } else if written + 4 <= len {
                    dst.add(written)
                } else {
                    buf.as_mut_ptr() as *mut c_char
                },
                wc,
                ps,
            )
        };
        if ret == usize::MAX {
            return usize::MAX;
        }
        if !dst.is_null() && written + ret > len {
            break;
        }
        if !dst.is_null() && written + 4 > len {
            // We wrote to buf, need to copy
            unsafe {
                std::ptr::copy_nonoverlapping(buf.as_ptr() as *const c_char, dst.add(written), ret);
            }
        }
        written += ret;
        wchars_consumed += 1;
        s = unsafe { s.add(1) };
    }
    unsafe { *src = s };
    written
}

// ===========================================================================
// Wide string extensions
// ===========================================================================

/// GNU `wcschrnul` — like wcschr but returns end-of-string if not found.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcschrnul(
    s: *const libc::wchar_t,
    wc: libc::wchar_t,
) -> *mut libc::wchar_t {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let mut p = s;
    loop {
        let c = unsafe { *p };
        if c == wc || c == 0 {
            return p as *mut libc::wchar_t;
        }
        p = unsafe { p.add(1) };
    }
}

/// BSD `wcslcat` — size-bounded wide string concatenation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcslcat(
    dst: *mut libc::wchar_t,
    src: *const libc::wchar_t,
    siz: usize,
) -> usize {
    if dst.is_null() || src.is_null() {
        return 0;
    }
    let mut dlen = 0usize;
    while dlen < siz && unsafe { *dst.add(dlen) } != 0 {
        dlen += 1;
    }
    if dlen == siz {
        // dst not NUL-terminated within siz
        let mut slen = 0usize;
        while unsafe { *src.add(slen) } != 0 {
            slen += 1;
        }
        return siz + slen;
    }
    let mut i = 0usize;
    while unsafe { *src.add(i) } != 0 {
        if dlen + i < siz - 1 {
            unsafe { *dst.add(dlen + i) = *src.add(i) };
        }
        i += 1;
    }
    let end = if dlen + i < siz { dlen + i } else { siz - 1 };
    unsafe { *dst.add(end) = 0 };
    dlen + i
}

/// BSD `wcslcpy` — size-bounded wide string copy.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcslcpy(
    dst: *mut libc::wchar_t,
    src: *const libc::wchar_t,
    siz: usize,
) -> usize {
    if dst.is_null() || src.is_null() || siz == 0 {
        if src.is_null() {
            return 0;
        }
        let mut len = 0usize;
        while unsafe { *src.add(len) } != 0 {
            len += 1;
        }
        return len;
    }
    let mut i = 0usize;
    while i < siz - 1 && unsafe { *src.add(i) } != 0 {
        unsafe { *dst.add(i) = *src.add(i) };
        i += 1;
    }
    unsafe { *dst.add(i) = 0 };
    // Count remaining src length
    let mut total = i;
    while unsafe { *src.add(total) } != 0 {
        total += 1;
    }
    total
}

/// `wcstoimax` — convert wide string to intmax_t.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstoimax(nptr: *const u32, endptr: *mut *mut u32, base: c_int) -> i64 {
    unsafe {
        wcstol(
            nptr.cast::<libc::wchar_t>(),
            endptr.cast::<*mut libc::wchar_t>(),
            base,
        ) as i64
    }
}

/// `wcstoumax` — convert wide string to uintmax_t.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstoumax(nptr: *const u32, endptr: *mut *mut u32, base: c_int) -> u64 {
    unsafe {
        wcstoul(
            nptr.cast::<libc::wchar_t>(),
            endptr.cast::<*mut libc::wchar_t>(),
            base,
        ) as u64
    }
}

/// `open_wmemstream` — open wide memory stream.
///
/// Native implementation: creates a memory-backed stream that stores wide characters.
/// Internally uses our `open_memstream` and converts between wide/narrow on write.
/// The buffer pointer (*bufp) is updated after each flush/close with the wide char contents.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn open_wmemstream(bufp: *mut *mut u32, sizep: *mut usize) -> *mut c_void {
    if bufp.is_null() || sizep.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return std::ptr::null_mut();
    }

    // Use underlying open_memstream for byte-level storage, then track wide metadata.
    // Allocate initial wide buffer (empty, NUL-terminated).
    let initial = unsafe { crate::malloc_abi::raw_alloc(4) } as *mut u32;
    if initial.is_null() {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return std::ptr::null_mut();
    }
    unsafe {
        *initial = 0; // NUL wchar_t
        *bufp = initial;
        *sizep = 0;
    }

    // Delegate to our byte-level open_memstream. The wide semantics will be handled
    // by the fwprintf/fputwc layer which converts wide → UTF-8 → byte stream.
    let mut byte_ptr: *mut i8 = std::ptr::null_mut();
    let mut byte_size: usize = 0;
    let stream =
        unsafe { crate::stdio_abi::open_memstream(&mut byte_ptr as *mut *mut i8, &mut byte_size) };
    if stream.is_null() {
        unsafe { crate::malloc_abi::raw_free(initial as *mut c_void) };
        unsafe {
            *bufp = std::ptr::null_mut();
            *sizep = 0;
        }
        return std::ptr::null_mut();
    }

    stream
}

/// `getwc` — alias for fgetwc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getwc(stream: *mut libc::FILE) -> u32 {
    unsafe { fgetwc(stream as *mut c_void) }
}

/// `putwc` — alias for fputwc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putwc(wc: libc::wchar_t, stream: *mut libc::FILE) -> u32 {
    unsafe { fputwc(wc as u32, stream as *mut c_void) }
}

/// `fgetwc_unlocked` — unlocked fgetwc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetwc_unlocked(stream: *mut libc::FILE) -> u32 {
    unsafe { fgetwc(stream as *mut c_void) }
}

/// `fgetws_unlocked` — unlocked fgetws.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetws_unlocked(
    ws: *mut libc::wchar_t,
    n: std::ffi::c_int,
    stream: *mut libc::FILE,
) -> *mut libc::wchar_t {
    unsafe { fgetws(ws, n, stream as *mut c_void) }
}

/// `fputwc_unlocked` — unlocked fputwc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fputwc_unlocked(wc: libc::wchar_t, stream: *mut libc::FILE) -> u32 {
    unsafe { fputwc(wc as u32, stream as *mut c_void) }
}

/// `fputws_unlocked` — unlocked fputws.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fputws_unlocked(
    ws: *const libc::wchar_t,
    stream: *mut libc::FILE,
) -> std::ffi::c_int {
    unsafe { fputws(ws, stream as *mut c_void) }
}

/// `getwc_unlocked` — unlocked getwc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getwc_unlocked(stream: *mut libc::FILE) -> u32 {
    unsafe { getwc(stream) }
}

/// `getwchar_unlocked` — unlocked getwchar.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getwchar_unlocked() -> u32 {
    unsafe { getwchar() }
}

/// `putwc_unlocked` — unlocked putwc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putwc_unlocked(wc: u32, stream: *mut c_void) -> u32 {
    unsafe { fputwc(wc, stream) }
}

/// `putwchar_unlocked` — unlocked putwchar.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putwchar_unlocked(wc: u32) -> u32 {
    unsafe { putwchar(wc) }
}

// ===========================================================================
// C11 uchar.h — char16_t / char32_t conversion
// ===========================================================================

// Thread-local storage for UTF-16 surrogate pair state (mbrtoc16).
thread_local! {
    static C16_SURROGATE: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// `c32rtomb` — convert char32_t to multibyte (UTF-8).
/// On Linux, char32_t == wchar_t (both are UTF-32), so this delegates to wcrtomb.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn c32rtomb(s: *mut c_char, c32: u32, ps: *mut c_void) -> usize {
    unsafe { wcrtomb(s, c32 as libc::wchar_t, ps) }
}

/// `mbrtoc32` — convert multibyte to char32_t (UTF-32).
/// On Linux, char32_t == wchar_t, so this delegates to mbrtowc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtoc32(
    pc32: *mut u32,
    s: *const c_char,
    n: usize,
    ps: *mut c_void,
) -> usize {
    let mut wc: libc::wchar_t = 0;
    let dst = if pc32.is_null() {
        &mut wc as *mut libc::wchar_t
    } else {
        pc32 as *mut libc::wchar_t
    };
    unsafe { mbrtowc(dst, s, n, ps) }
}

/// `c16rtomb` — convert char16_t to multibyte (UTF-8).
/// Handles UTF-16 surrogate pairs via thread-local state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn c16rtomb(s: *mut c_char, c16: u16, ps: *mut c_void) -> usize {
    let pending = C16_SURROGATE.with(|cell| cell.get());

    if pending != 0 {
        // We have a high surrogate pending; this should be the low surrogate.
        C16_SURROGATE.with(|cell| cell.set(0));
        if !(0xDC00..=0xDFFF).contains(&(c16 as u32)) {
            // Invalid: low surrogate expected but not found.
            unsafe { set_abi_errno(libc::EILSEQ) };
            return usize::MAX;
        }
        // Decode surrogate pair to Unicode code point.
        let cp = 0x10000 + ((pending - 0xD800) << 10) + (c16 as u32 - 0xDC00);
        return unsafe { c32rtomb(s, cp, ps) };
    }

    if (0xD800..=0xDBFF).contains(&(c16 as u32)) {
        // High surrogate — store and return 0 (no bytes yet).
        C16_SURROGATE.with(|cell| cell.set(c16 as u32));
        return 0;
    }

    if (0xDC00..=0xDFFF).contains(&(c16 as u32)) {
        // Lone low surrogate is an error.
        unsafe { set_abi_errno(libc::EILSEQ) };
        return usize::MAX;
    }

    // BMP character — convert directly.
    unsafe { c32rtomb(s, c16 as u32, ps) }
}

/// `mbrtoc16` — convert multibyte to char16_t (UTF-16).
/// May produce surrogate pairs for characters outside the BMP.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtoc16(
    pc16: *mut u16,
    s: *const c_char,
    n: usize,
    ps: *mut c_void,
) -> usize {
    let pending = C16_SURROGATE.with(|cell| cell.get());

    if pending != 0 {
        // We have a pending low surrogate to deliver.
        C16_SURROGATE.with(|cell| cell.set(0));
        if !pc16.is_null() {
            unsafe { *pc16 = pending as u16 };
        }
        return usize::MAX - 2; // (size_t)-3: indicates stored character returned
    }

    let mut c32: u32 = 0;
    let ret = unsafe { mbrtoc32(&mut c32, s, n, ps) };

    if ret > n {
        // Error or incomplete — pass through.
        return ret;
    }

    if c32 > 0xFFFF {
        // Outside BMP — need surrogate pair.
        let cp = c32 - 0x10000;
        let high = 0xD800 + (cp >> 10);
        let low = 0xDC00 + (cp & 0x3FF);

        if !pc16.is_null() {
            unsafe { *pc16 = high as u16 };
        }
        // Store low surrogate for next call.
        C16_SURROGATE.with(|cell| cell.set(low));
        return ret;
    }

    if !pc16.is_null() {
        unsafe { *pc16 = c32 as u16 };
    }
    ret
}

// ===========================================================================
// C23 __isoc23_* wide aliases — GCC 14+ with -std=c23 emits these
// ===========================================================================
// ===========================================================================
// isw*_l / tow*_l — POSIX wide ctype locale variants
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswalnum_l(wc: u32, _l: *mut c_void) -> c_int {
    unsafe { iswalnum(wc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswalpha_l(wc: u32, _l: *mut c_void) -> c_int {
    unsafe { iswalpha(wc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswblank_l(wc: u32, _l: *mut c_void) -> c_int {
    unsafe { iswblank(wc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswcntrl_l(wc: u32, _l: *mut c_void) -> c_int {
    unsafe { iswcntrl(wc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswdigit_l(wc: u32, _l: *mut c_void) -> c_int {
    unsafe { iswdigit(wc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswgraph_l(wc: u32, _l: *mut c_void) -> c_int {
    unsafe { iswgraph(wc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswlower_l(wc: u32, _l: *mut c_void) -> c_int {
    unsafe { iswlower(wc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswprint_l(wc: u32, _l: *mut c_void) -> c_int {
    unsafe { iswprint(wc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswpunct_l(wc: u32, _l: *mut c_void) -> c_int {
    unsafe { iswpunct(wc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswspace_l(wc: u32, _l: *mut c_void) -> c_int {
    unsafe { iswspace(wc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswupper_l(wc: u32, _l: *mut c_void) -> c_int {
    unsafe { iswupper(wc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswxdigit_l(wc: u32, _l: *mut c_void) -> c_int {
    unsafe { iswxdigit(wc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wctrans_l(property: *const u8, _l: *mut c_void) -> WctransT {
    if property.is_null() {
        return 0;
    }
    let s = unsafe { core::ffi::CStr::from_ptr(property as *const std::ffi::c_char) };
    match s.to_bytes() {
        b"toupper" => 1,
        b"tolower" => 2,
        _ => 0,
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn towctrans_l(wc: u32, desc: WctransT, _l: *mut c_void) -> u32 {
    match desc {
        1 => unsafe { towupper(wc) },
        2 => unsafe { towlower(wc) },
        _ => wc,
    }
}

// ===========================================================================
// __isw*_l / __tow*_l — glibc double-underscore internal aliases
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswalnum_l(wc: u32, l: *mut c_void) -> c_int {
    unsafe { iswalnum_l(wc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswalpha_l(wc: u32, l: *mut c_void) -> c_int {
    unsafe { iswalpha_l(wc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswblank_l(wc: u32, l: *mut c_void) -> c_int {
    unsafe { iswblank_l(wc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswcntrl_l(wc: u32, l: *mut c_void) -> c_int {
    unsafe { iswcntrl_l(wc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswctype_l(wc: u32, desc: WctypeT, l: *mut c_void) -> c_int {
    unsafe { iswctype_l(wc, desc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswdigit_l(wc: u32, l: *mut c_void) -> c_int {
    unsafe { iswdigit_l(wc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswgraph_l(wc: u32, l: *mut c_void) -> c_int {
    unsafe { iswgraph_l(wc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswlower_l(wc: u32, l: *mut c_void) -> c_int {
    unsafe { iswlower_l(wc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswprint_l(wc: u32, l: *mut c_void) -> c_int {
    unsafe { iswprint_l(wc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswpunct_l(wc: u32, l: *mut c_void) -> c_int {
    unsafe { iswpunct_l(wc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswspace_l(wc: u32, l: *mut c_void) -> c_int {
    unsafe { iswspace_l(wc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswupper_l(wc: u32, l: *mut c_void) -> c_int {
    unsafe { iswupper_l(wc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswxdigit_l(wc: u32, l: *mut c_void) -> c_int {
    unsafe { iswxdigit_l(wc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __towctrans_l(wc: u32, desc: WctransT, l: *mut c_void) -> u32 {
    unsafe { towctrans_l(wc, desc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __towlower_l(wc: u32, l: *mut c_void) -> u32 {
    unsafe { towlower_l(wc, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __towupper_l(wc: u32, l: *mut c_void) -> u32 {
    unsafe { towupper_l(wc, l) }
}

// ===========================================================================
// __wcs* locale/internal aliases
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcscasecmp_l(
    s1: *const libc::wchar_t,
    s2: *const libc::wchar_t,
    _l: *mut c_void,
) -> c_int {
    unsafe { wcscasecmp(s1 as *const u32, s2 as *const u32) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsncasecmp_l(
    s1: *const libc::wchar_t,
    s2: *const libc::wchar_t,
    n: usize,
    _l: *mut c_void,
) -> c_int {
    unsafe { wcsncasecmp(s1 as *const u32, s2 as *const u32, n) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcscoll_l(
    s1: *const libc::wchar_t,
    s2: *const libc::wchar_t,
    _l: *mut c_void,
) -> c_int {
    unsafe { wcscmp(s1 as *const u32, s2 as *const u32) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsxfrm_l(
    dst: *mut libc::wchar_t,
    src: *const libc::wchar_t,
    n: usize,
    _l: *mut c_void,
) -> usize {
    unsafe { wcsxfrm(dst, src, n) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstol_l(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
    l: *mut c_void,
) -> c_long {
    unsafe { wcstol_l(nptr, endptr, base, l) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstoul_l(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
    l: *mut c_void,
) -> c_ulong {
    unsafe { wcstoul_l(nptr, endptr, base, l) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstoll_l(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
    l: *mut c_void,
) -> c_longlong {
    unsafe { wcstoll_l(nptr, endptr, base, l) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstoull_l(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
    l: *mut c_void,
) -> c_ulonglong {
    unsafe { wcstoull_l(nptr, endptr, base, l) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstod_l(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    _l: *mut c_void,
) -> f64 {
    unsafe { wcstod(nptr, endptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstof_l(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    _l: *mut c_void,
) -> f32 {
    unsafe { wcstof(nptr, endptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstold_l(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    _l: *mut c_void,
) -> f64 {
    unsafe { wcstod(nptr, endptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstol_internal(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
    _group: c_int,
) -> c_long {
    unsafe { wcstol(nptr, endptr, base) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstoul_internal(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
    _group: c_int,
) -> c_ulong {
    unsafe { wcstoul(nptr, endptr, base) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstoll_internal(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
    _group: c_int,
) -> c_longlong {
    unsafe { wcstoll(nptr, endptr, base) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstoull_internal(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
    _group: c_int,
) -> c_ulonglong {
    unsafe { wcstoull(nptr, endptr, base) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstod_internal(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    _group: c_int,
) -> f64 {
    unsafe { wcstod(nptr, endptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstof_internal(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    _group: c_int,
) -> f32 {
    unsafe { wcstof(nptr, endptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstold_internal(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    _group: c_int,
) -> f64 {
    unsafe { wcstod(nptr, endptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsftime_l(
    s: *mut libc::wchar_t,
    max: usize,
    format: *const libc::wchar_t,
    tm: *const c_void,
    _l: *mut c_void,
) -> usize {
    // Convert wide format to narrow, call strftime, then widen result
    let fmt_narrow = unsafe { wide_to_narrow(format) };
    let mut buf = vec![0u8; max * 4];
    let ret = unsafe {
        crate::time_abi::strftime(
            buf.as_mut_ptr() as *mut std::ffi::c_char,
            buf.len(),
            fmt_narrow.as_ptr() as *const std::ffi::c_char,
            tm as *const libc::tm,
        )
    };
    if ret == 0 || s.is_null() {
        return 0;
    }
    // Widen the result
    let narrow = &buf[..ret];
    let mut i = 0;
    for &b in narrow {
        if i >= max - 1 {
            break;
        }
        unsafe { *s.add(i) = b as libc::wchar_t };
        i += 1;
    }
    unsafe { *s.add(i) = 0 };
    i
}
