//! ABI layer for `<wchar.h>` functions.
//!
//! Handles wide-character (32-bit) string operations.
//! On Linux/glibc, `wchar_t` is 32-bit (UTF-32).
//!
use std::ffi::c_int;

use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::malloc_abi::known_remaining;
use crate::runtime_policy;

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
            if repair && src_bound.is_some() && i >= src_bound.unwrap() {
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
        _ => None,
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
        _ => Some(n),
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
                res = if a[i] < b[i] { -1 } else { 1 };
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

        // Use libc malloc for allocation
        let ptr = libc::malloc(alloc_bytes) as *mut u32;
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

use frankenlibc_core::string::wchar as wchar_core;

/// Set the ABI errno via `__errno_location`.
#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

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
        None => -1,
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
        None => -1,
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
    let src_len = unsafe { libc::strlen(src as *const _) + 1 }; // include NUL
    let src_slice = unsafe { std::slice::from_raw_parts(src, src_len) };
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
    let len = unsafe { libc::strlen(path as *const _) };
    if len == 0 {
        return dot.as_ptr() as *mut std::ffi::c_char;
    }
    let slice = unsafe { std::slice::from_raw_parts(path as *const u8, len) };
    let (s, e) = basename_range(slice);
    let result_len = e - s;
    if result_len == 0 {
        return dot.as_ptr() as *mut std::ffi::c_char;
    }
    let mut buf = BASENAME_BUF.lock().unwrap();
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
    let len = unsafe { libc::strlen(path as *const _) };
    if len == 0 {
        return dot.as_ptr() as *mut std::ffi::c_char;
    }
    let slice = unsafe { std::slice::from_raw_parts(path as *const u8, len) };
    let (s, e) = dirname_range(slice);
    let result_len = e - s;
    if result_len == 0 {
        return dot.as_ptr() as *mut std::ffi::c_char;
    }
    let mut buf = DIRNAME_BUF.lock().unwrap();
    buf[..result_len].copy_from_slice(&slice[s..e]);
    buf[result_len] = 0;
    buf.as_mut_ptr() as *mut std::ffi::c_char
}

// ---------------------------------------------------------------------------
// realpath — via SYS_readlink iteration
// ---------------------------------------------------------------------------

/// POSIX `realpath` — resolve a pathname to an absolute path.
///
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

    // Delegate to libc's realpath via syscall — this is a RawSyscall-style
    // implementation since path resolution requires kernel filesystem access.
    let result = unsafe { libc::realpath(path, resolved_path) };
    if result.is_null() {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::ENOENT);
        unsafe { set_abi_errno(e) };
    }
    result
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
    use frankenlibc_core::errno;

    if template.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    // Delegate to libc's mkstemp — this requires filesystem access
    let result = unsafe { libc::mkstemp(template) };
    if result < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EINVAL);
        unsafe { set_abi_errno(e) };
    }
    result
}

// ---------------------------------------------------------------------------
// Additional wide char / multibyte functions — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "wcsnlen"]
    fn libc_wcsnlen(s: *const libc::wchar_t, maxlen: usize) -> usize;
    #[link_name = "wcswidth"]
    fn libc_wcswidth(s: *const libc::wchar_t, n: usize) -> c_int;
    #[link_name = "wctob"]
    fn libc_wctob(c: u32) -> c_int;
    #[link_name = "btowc"]
    fn libc_btowc(c: c_int) -> u32;
    #[link_name = "wcrtomb"]
    fn libc_wcrtomb(s: *mut std::ffi::c_char, wc: libc::wchar_t, ps: *mut std::ffi::c_void) -> usize;
    #[link_name = "mbrtowc"]
    fn libc_mbrtowc(pwc: *mut libc::wchar_t, s: *const std::ffi::c_char, n: usize, ps: *mut std::ffi::c_void) -> usize;
    #[link_name = "mbsrtowcs"]
    fn libc_mbsrtowcs(dst: *mut libc::wchar_t, src: *mut *const std::ffi::c_char, len: usize, ps: *mut std::ffi::c_void) -> usize;
    #[link_name = "wcsrtombs"]
    fn libc_wcsrtombs(dst: *mut std::ffi::c_char, src: *mut *const libc::wchar_t, len: usize, ps: *mut std::ffi::c_void) -> usize;
    #[link_name = "wcstol"]
    fn libc_wcstol(nptr: *const libc::wchar_t, endptr: *mut *mut libc::wchar_t, base: c_int) -> std::ffi::c_long;
    #[link_name = "wcstoul"]
    fn libc_wcstoul(nptr: *const libc::wchar_t, endptr: *mut *mut libc::wchar_t, base: c_int) -> std::ffi::c_ulong;
    #[link_name = "wcstod"]
    fn libc_wcstod(nptr: *const libc::wchar_t, endptr: *mut *mut libc::wchar_t) -> f64;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsnlen(s: *const libc::wchar_t, maxlen: usize) -> usize {
    unsafe { libc_wcsnlen(s, maxlen) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcswidth(s: *const libc::wchar_t, n: usize) -> c_int {
    unsafe { libc_wcswidth(s, n) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wctob(c: u32) -> c_int {
    unsafe { libc_wctob(c) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn btowc(c: c_int) -> u32 {
    unsafe { libc_btowc(c) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcrtomb(s: *mut std::ffi::c_char, wc: libc::wchar_t, ps: *mut std::ffi::c_void) -> usize {
    unsafe { libc_wcrtomb(s, wc, ps) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtowc(
    pwc: *mut libc::wchar_t,
    s: *const std::ffi::c_char,
    n: usize,
    ps: *mut std::ffi::c_void,
) -> usize {
    unsafe { libc_mbrtowc(pwc, s, n, ps) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mbsrtowcs(
    dst: *mut libc::wchar_t,
    src: *mut *const std::ffi::c_char,
    len: usize,
    ps: *mut std::ffi::c_void,
) -> usize {
    unsafe { libc_mbsrtowcs(dst, src, len, ps) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsrtombs(
    dst: *mut std::ffi::c_char,
    src: *mut *const libc::wchar_t,
    len: usize,
    ps: *mut std::ffi::c_void,
) -> usize {
    unsafe { libc_wcsrtombs(dst, src, len, ps) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstol(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
) -> std::ffi::c_long {
    unsafe { libc_wcstol(nptr, endptr, base) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstoul(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
    base: c_int,
) -> std::ffi::c_ulong {
    unsafe { libc_wcstoul(nptr, endptr, base) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstod(
    nptr: *const libc::wchar_t,
    endptr: *mut *mut libc::wchar_t,
) -> f64 {
    unsafe { libc_wcstod(nptr, endptr) }
}
