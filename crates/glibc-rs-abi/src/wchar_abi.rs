//! ABI layer for `<wchar.h>` functions.
//!
//! Handles wide-character (32-bit) string operations.
//! On Linux/glibc, `wchar_t` is 32-bit (UTF-32).
//!
use std::ffi::c_int;

use glibc_rs_membrane::heal::{HealingAction, global_healing_policy};
use glibc_rs_membrane::runtime_math::{ApiFamily, MembraneAction};

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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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
