//! ABI layer for `<string.h>` functions.
//!
//! Each function is an `extern "C"` entry point that:
//! 1. Validates pointer arguments through the membrane pipeline
//! 2. In hardened mode, applies healing (bounds clamping, null truncation)
//! 3. Delegates to `frankenlibc-core` safe implementations or inline unsafe primitives

use std::cell::Cell;
use std::ffi::{c_char, c_int, c_void};

use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::malloc_abi::known_remaining;
use crate::runtime_policy;

thread_local! {
    static STRING_MEMBRANE_DEPTH: Cell<u32> = const { Cell::new(0) };
}

struct StringMembraneGuard;

impl Drop for StringMembraneGuard {
    fn drop(&mut self) {
        let _ = STRING_MEMBRANE_DEPTH.try_with(|depth| {
            let current = depth.get();
            depth.set(current.saturating_sub(1));
        });
    }
}

fn enter_string_membrane_guard() -> Option<StringMembraneGuard> {
    if runtime_policy::in_policy_reentry_context()
        || crate::malloc_abi::in_allocator_reentry_context()
        || crate::pthread_abi::in_threading_policy_context()
    {
        return None;
    }
    STRING_MEMBRANE_DEPTH
        .try_with(|depth| {
            let current = depth.get();
            if current > 0 {
                None
            } else {
                depth.set(current + 1);
                Some(StringMembraneGuard)
            }
        })
        .unwrap_or(None)
}

#[inline(never)]
unsafe fn raw_memcpy_bytes(dst: *mut u8, src: *const u8, n: usize) {
    let mut i = 0usize;
    while i < n {
        // SAFETY: caller guarantees valid non-overlapping regions for `n` bytes.
        unsafe {
            let byte = std::ptr::read_volatile(src.add(i));
            std::ptr::write_volatile(dst.add(i), byte);
        }
        i += 1;
    }
}

#[inline(never)]
unsafe fn raw_memmove_bytes(dst: *mut u8, src: *const u8, n: usize) {
    let dst_addr = dst as usize;
    let src_addr = src as usize;
    if dst_addr <= src_addr || dst_addr >= src_addr.saturating_add(n) {
        // SAFETY: forward copy is correct for non-overlap or forward-safe overlap.
        unsafe { raw_memcpy_bytes(dst, src, n) };
        return;
    }

    let mut i = n;
    while i > 0 {
        i -= 1;
        // SAFETY: caller guarantees valid regions for `n` bytes; backward copy handles overlap.
        unsafe {
            let byte = std::ptr::read_volatile(src.add(i));
            std::ptr::write_volatile(dst.add(i), byte);
        }
    }
}

#[inline(never)]
unsafe fn raw_memset_bytes(dst: *mut u8, value: u8, n: usize) {
    let mut i = 0usize;
    while i < n {
        // SAFETY: caller guarantees `dst` valid for `n` bytes.
        unsafe {
            std::ptr::write_volatile(dst.add(i), value);
        }
        i += 1;
    }
}

fn maybe_clamp_copy_len(
    requested: usize,
    src_addr: Option<usize>,
    dst_addr: Option<usize>,
    enable_repair: bool,
) -> (usize, bool) {
    if !enable_repair || requested == 0 {
        return (requested, false);
    }

    let src_remaining = src_addr.and_then(known_remaining);
    let dst_remaining = dst_addr.and_then(known_remaining);
    let action = global_healing_policy().heal_copy_bounds(requested, src_remaining, dst_remaining);
    match action {
        HealingAction::ClampSize {
            requested: _,
            clamped,
        } => {
            global_healing_policy().record(&action);
            (clamped, true)
        }
        _ => (requested, false),
    }
}

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

#[inline]
fn stage_index(ordering: &[CheckStage; 7], stage: CheckStage) -> usize {
    ordering.iter().position(|s| *s == stage).unwrap_or(0)
}

#[inline]
fn stage_context_one(addr: usize) -> (bool, bool, [CheckStage; 7]) {
    let aligned = (addr & 0x7) == 0;
    let recent_page = addr != 0 && known_remaining(addr).is_some();
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);
    (aligned, recent_page, ordering)
}

#[inline]
fn stage_context_two(addr1: usize, addr2: usize) -> (bool, bool, [CheckStage; 7]) {
    let aligned = ((addr1 | addr2) & 0x7) == 0;
    let recent_page = (addr1 != 0 && known_remaining(addr1).is_some())
        || (addr2 != 0 && known_remaining(addr2).is_some());
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);
    (aligned, recent_page, ordering)
}

#[inline]
fn record_string_stage_outcome(
    ordering: &[CheckStage; 7],
    aligned: bool,
    recent_page: bool,
    exit_stage: Option<usize>,
) {
    runtime_policy::note_check_order_outcome(
        ApiFamily::StringMemory,
        aligned,
        recent_page,
        ordering,
        exit_stage,
    );
}

/// Scan a C string with an optional hard bound.
///
/// Returns `(len, terminated)` where:
/// - `len` is the byte length before the first NUL or before the bound.
/// - `terminated` indicates whether a NUL byte was observed.
///
/// # Safety
///
/// `ptr` must be valid to read up to the discovered length (and bound when given).
unsafe fn scan_c_string(ptr: *const c_char, bound: Option<usize>) -> (usize, bool) {
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
// memcpy
// ---------------------------------------------------------------------------

/// POSIX `memcpy` -- copies `n` bytes from `src` to `dst`.
///
/// # Safety
///
/// Caller must ensure `src` and `dst` are valid for `n` bytes and do not overlap.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let Some(_membrane_guard) = enter_string_membrane_guard() else {
        if n == 0 {
            return dst;
        }
        if dst.is_null() || src.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: reentrant fallback avoids runtime-policy recursion and mirrors memcpy semantics.
        unsafe {
            raw_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), n);
        }
        return dst;
    };

    let aligned = ((dst as usize) | (src as usize)) & 0x7 == 0;
    let recent_page = (!dst.is_null() && known_remaining(dst as usize).is_some())
        || (!src.is_null() && known_remaining(src as usize).is_some());
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);

    if n == 0 {
        return dst;
    }
    if dst.is_null() || src.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return std::ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        n,
        true,
        known_remaining(dst as usize).is_none() && known_remaining(src as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(7, n),
            true,
        );
        return std::ptr::null_mut();
    }

    let (copy_len, clamped) = maybe_clamp_copy_len(
        n,
        Some(src as usize),
        Some(dst as usize),
        mode.heals_enabled() || matches!(decision.action, MembraneAction::Repair(_)),
    );
    if copy_len == 0 {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Bounds)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(7, n),
            clamped,
        );
        return dst;
    }

    // SAFETY: `copy_len` is either original `n` (strict) or clamped to known bounds.
    unsafe {
        raw_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), copy_len);
    }
    record_string_stage_outcome(&ordering, aligned, recent_page, None);
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, copy_len),
        clamped,
    );
    dst
}

// ---------------------------------------------------------------------------
// memmove
// ---------------------------------------------------------------------------

/// POSIX `memmove` -- copies `n` bytes from `src` to `dst`, handling overlap.
///
/// # Safety
///
/// Caller must ensure `src` and `dst` are valid for `n` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let Some(_membrane_guard) = enter_string_membrane_guard() else {
        if n == 0 {
            return dst;
        }
        if dst.is_null() || src.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: reentrant fallback avoids runtime-policy recursion and mirrors memmove semantics.
        unsafe {
            raw_memmove_bytes(dst.cast::<u8>(), src.cast::<u8>(), n);
        }
        return dst;
    };

    let aligned = ((dst as usize) | (src as usize)) & 0x7 == 0;
    let recent_page = (!dst.is_null() && known_remaining(dst as usize).is_some())
        || (!src.is_null() && known_remaining(src as usize).is_some());
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);

    if n == 0 {
        return dst;
    }
    if dst.is_null() || src.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return std::ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        n,
        true,
        known_remaining(dst as usize).is_none() && known_remaining(src as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(8, n),
            true,
        );
        return std::ptr::null_mut();
    }

    let (copy_len, clamped) = maybe_clamp_copy_len(
        n,
        Some(src as usize),
        Some(dst as usize),
        mode.heals_enabled() || matches!(decision.action, MembraneAction::Repair(_)),
    );
    if copy_len == 0 {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Bounds)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(8, n),
            clamped,
        );
        return dst;
    }

    // SAFETY: memmove handles overlap. `copy_len` may be clamped in hardened mode.
    unsafe {
        raw_memmove_bytes(dst.cast::<u8>(), src.cast::<u8>(), copy_len);
    }
    record_string_stage_outcome(&ordering, aligned, recent_page, None);
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(8, copy_len),
        clamped,
    );
    dst
}

// ---------------------------------------------------------------------------
// memset
// ---------------------------------------------------------------------------

/// POSIX `memset` -- fills `n` bytes of `dst` with byte value `c`.
///
/// # Safety
///
/// Caller must ensure `dst` is valid for `n` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn memset(dst: *mut c_void, c: c_int, n: usize) -> *mut c_void {
    let Some(_membrane_guard) = enter_string_membrane_guard() else {
        if n == 0 {
            return dst;
        }
        if dst.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: reentrant fallback avoids runtime-policy recursion and mirrors memset semantics.
        unsafe {
            raw_memset_bytes(dst.cast::<u8>(), c as u8, n);
        }
        return dst;
    };

    let aligned = (dst as usize) & 0x7 == 0;
    let recent_page = !dst.is_null() && known_remaining(dst as usize).is_some();
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);

    if n == 0 {
        return dst;
    }
    if dst.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return std::ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        n,
        true,
        known_remaining(dst as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(6, n),
            true,
        );
        return std::ptr::null_mut();
    }

    let (fill_len, clamped) = maybe_clamp_copy_len(
        n,
        None,
        Some(dst as usize),
        mode.heals_enabled() || matches!(decision.action, MembraneAction::Repair(_)),
    );
    if fill_len == 0 {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Bounds)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(6, n),
            clamped,
        );
        return dst;
    }

    // SAFETY: `fill_len` is either original `n` (strict) or clamped to known bounds.
    unsafe {
        raw_memset_bytes(dst.cast::<u8>(), c as u8, fill_len);
    }
    record_string_stage_outcome(&ordering, aligned, recent_page, None);
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(6, fill_len),
        clamped,
    );
    dst
}

// ---------------------------------------------------------------------------
// memcmp
// ---------------------------------------------------------------------------

/// POSIX `memcmp` -- compares `n` bytes of `s1` and `s2`.
///
/// Returns negative, zero, or positive integer.
///
/// # Safety
///
/// Caller must ensure `s1` and `s2` are valid for `n` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> c_int {
    let (aligned, recent_page, ordering) = stage_context_two(s1 as usize, s2 as usize);
    if n == 0 {
        return 0;
    }
    if s1.is_null() || s2.is_null() {
        // Membrane: null pointer in memcmp is UB in C. Return safe default.
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s1 as usize,
        n,
        false,
        known_remaining(s1 as usize).is_none() && known_remaining(s2 as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(6, n),
            true,
        );
        return 0;
    }

    let (cmp_len, _clamped) = maybe_clamp_copy_len(
        n,
        Some(s1 as usize),
        Some(s2 as usize),
        mode.heals_enabled() || matches!(decision.action, MembraneAction::Repair(_)),
    );
    if cmp_len == 0 {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Bounds)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(6, n),
            true,
        );
        return 0;
    }

    // SAFETY: `cmp_len` is either original `n` or clamped by known safe bounds.
    let out = unsafe {
        let a = std::slice::from_raw_parts(s1.cast::<u8>(), cmp_len);
        let b = std::slice::from_raw_parts(s2.cast::<u8>(), cmp_len);
        match frankenlibc_core::string::mem::memcmp(a, b, cmp_len) {
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Greater => 1,
        }
    };
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(6, cmp_len),
        cmp_len < n,
    );
    out
}

// ---------------------------------------------------------------------------
// memchr
// ---------------------------------------------------------------------------

/// POSIX `memchr` -- locates first occurrence of byte `c` in first `n` bytes of `s`.
///
/// Returns pointer to the matching byte, or null if not found.
///
/// # Safety
///
/// Caller must ensure `s` is valid for `n` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn memchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void {
    let (aligned, recent_page, ordering) = stage_context_one(s as usize);
    if n == 0 || s.is_null() {
        if s.is_null() {
            record_string_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Null)),
            );
        }
        return std::ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        n,
        false,
        known_remaining(s as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(6, n),
            true,
        );
        return std::ptr::null_mut();
    }

    let (scan_len, clamped) = maybe_clamp_copy_len(
        n,
        Some(s as usize),
        None,
        mode.heals_enabled() || matches!(decision.action, MembraneAction::Repair(_)),
    );
    if scan_len == 0 {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Bounds)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(6, n),
            true,
        );
        return std::ptr::null_mut();
    }

    // SAFETY: `scan_len` is either original `n` or clamped by known bounds.
    unsafe {
        let bytes = std::slice::from_raw_parts(s.cast::<u8>(), scan_len);
        if let Some(idx) = frankenlibc_core::string::mem::memchr(bytes, c as u8, scan_len) {
            record_string_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Bounds)),
            );
            runtime_policy::observe(
                ApiFamily::StringMemory,
                decision.profile,
                runtime_policy::scaled_cost(6, scan_len),
                clamped,
            );
            return (s as *mut u8).add(idx).cast();
        }
    }
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(6, scan_len),
        clamped,
    );
    std::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// memrchr
// ---------------------------------------------------------------------------

/// POSIX `memrchr` (GNU extension) -- locates last occurrence of byte `c` in first `n` bytes of `s`.
///
/// Returns pointer to the matching byte, or null if not found.
///
/// # Safety
///
/// Caller must ensure `s` is valid for `n` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn memrchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void {
    let (aligned, recent_page, ordering) = stage_context_one(s as usize);
    if n == 0 || s.is_null() {
        if s.is_null() {
            record_string_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Null)),
            );
        }
        return std::ptr::null_mut();
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        n,
        false,
        known_remaining(s as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(6, n),
            true,
        );
        return std::ptr::null_mut();
    }

    let (scan_len, clamped) = maybe_clamp_copy_len(
        n,
        Some(s as usize),
        None,
        mode.heals_enabled() || matches!(decision.action, MembraneAction::Repair(_)),
    );
    if scan_len == 0 {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Bounds)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(6, n),
            true,
        );
        return std::ptr::null_mut();
    }

    // SAFETY: `scan_len` is either original `n` or clamped by known bounds.
    unsafe {
        let bytes = std::slice::from_raw_parts(s.cast::<u8>(), scan_len);
        if let Some(idx) = frankenlibc_core::string::mem::memrchr(bytes, c as u8, scan_len) {
            record_string_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Bounds)),
            );
            runtime_policy::observe(
                ApiFamily::StringMemory,
                decision.profile,
                runtime_policy::scaled_cost(6, scan_len),
                clamped,
            );
            return (s as *mut u8).add(idx).cast();
        }
    }
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(6, scan_len),
        clamped,
    );
    std::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// strlen
// ---------------------------------------------------------------------------

/// POSIX `strlen` -- computes length of null-terminated string.
///
/// # Safety
///
/// Caller must ensure `s` points to a valid null-terminated string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    let aligned = (s as usize) & 0x7 == 0;
    let recent_page = !s.is_null() && known_remaining(s as usize).is_some();
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);

    if s.is_null() {
        // Membrane: null pointer in strlen is UB in C. Return safe default.
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
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
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 6, true);
        return 0;
    }

    if (mode.heals_enabled() || matches!(decision.action, MembraneAction::Repair(_)))
        && let Some(limit) = known_remaining(s as usize)
    {
        // SAFETY: bounded scan within known allocation extent.
        unsafe {
            for i in 0..limit {
                if *s.add(i) == 0 {
                    record_string_stage_outcome(
                        &ordering,
                        aligned,
                        recent_page,
                        Some(stage_index(&ordering, CheckStage::Bounds)),
                    );
                    runtime_policy::observe(
                        ApiFamily::StringMemory,
                        decision.profile,
                        runtime_policy::scaled_cost(7, i),
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
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Bounds)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(7, limit),
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
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Bounds)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(7, len),
            false,
        );
        len
    }
}

// ---------------------------------------------------------------------------
// strnlen
// ---------------------------------------------------------------------------

/// POSIX `strnlen` -- computes string length up to at most `n` bytes.
///
/// # Safety
///
/// Caller must ensure `s` points to readable memory for the compared span.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strnlen(s: *const c_char, n: usize) -> usize {
    if n == 0 {
        return 0;
    }

    let aligned = (s as usize) & 0x7 == 0;
    let recent_page = !s.is_null() && known_remaining(s as usize).is_some();
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);

    if s.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        n,
        false,
        known_remaining(s as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 6, true);
        return 0;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let mut scan_limit = n;
    let mut adverse = false;
    if repair
        && let Some(bound) = known_remaining(s as usize)
        && bound < scan_limit
    {
        scan_limit = bound;
        adverse = true;
    }

    // SAFETY: strict mode follows libc semantics; hardened mode bounds reads.
    let (len, span) = unsafe {
        let mut i = 0usize;
        loop {
            if i >= scan_limit {
                break (scan_limit, scan_limit);
            }
            if *s.add(i) == 0 {
                break (i, i);
            }
            i += 1;
        }
    };

    if adverse {
        record_truncation(n, scan_limit);
    }
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, span),
        adverse,
    );
    len
}

// ---------------------------------------------------------------------------
// strcmp
// ---------------------------------------------------------------------------

/// POSIX `strcmp` -- compares two null-terminated strings lexicographically.
///
/// # Safety
///
/// Caller must ensure both `s1` and `s2` point to valid null-terminated strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strcmp(s1: *const c_char, s2: *const c_char) -> c_int {
    let (aligned, recent_page, ordering) = stage_context_two(s1 as usize, s2 as usize);
    if s1.is_null() || s2.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
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
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 6, true);
        return 0;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let lhs_bound = if repair {
        known_remaining(s1 as usize)
    } else {
        None
    };
    let rhs_bound = if repair {
        known_remaining(s2 as usize)
    } else {
        None
    };
    let cmp_bound = match (lhs_bound, rhs_bound) {
        (Some(a), Some(b)) => Some(a.min(b)),
        _ => None,
    };

    // SAFETY: strict mode follows libc semantics; hardened mode bounds reads.
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
            let a = *s1.add(i) as u8;
            let b = *s2.add(i) as u8;
            if a != b || a == 0 {
                break (
                    (a as c_int) - (b as c_int),
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
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, span),
        adverse,
    );
    result
}

// ---------------------------------------------------------------------------
// strncmp
// ---------------------------------------------------------------------------

/// POSIX `strncmp` -- compares at most `n` bytes of two strings.
///
/// # Safety
///
/// Caller must ensure both `s1` and `s2` point to valid memory for the
/// compared span.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> c_int {
    if n == 0 {
        return 0;
    }

    let (aligned, recent_page, ordering) = stage_context_two(s1 as usize, s2 as usize);
    if s1.is_null() || s2.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return 0;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s1 as usize,
        n,
        false,
        known_remaining(s1 as usize).is_none() && known_remaining(s2 as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 6, true);
        return 0;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let lhs_bound = if repair {
        known_remaining(s1 as usize)
    } else {
        None
    };
    let rhs_bound = if repair {
        known_remaining(s2 as usize)
    } else {
        None
    };
    let cmp_limit = match (lhs_bound, rhs_bound) {
        (Some(a), Some(b)) => a.min(b).min(n),
        _ => n,
    };
    let adverse = repair && cmp_limit < n;

    // SAFETY: strict mode follows libc semantics; hardened mode bounds reads.
    let (result, span) = unsafe {
        let mut i = 0usize;
        loop {
            if i >= cmp_limit {
                break (0, i);
            }
            let a = *s1.add(i) as u8;
            let b = *s2.add(i) as u8;
            if a != b || a == 0 {
                break ((a as c_int) - (b as c_int), i.saturating_add(1));
            }
            i += 1;
        }
    };

    if adverse {
        record_truncation(n, cmp_limit);
    }
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, span),
        adverse,
    );
    result
}

// ---------------------------------------------------------------------------
// strcpy
// ---------------------------------------------------------------------------

/// POSIX `strcpy` -- copies the null-terminated string `src` into `dst`.
///
/// # Safety
///
/// Caller must ensure `dst` is large enough to hold `src` including the null terminator,
/// and that the buffers do not overlap.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    let (aligned, recent_page, ordering) = stage_context_two(dst as usize, src as usize);
    if dst.is_null() || src.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
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
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 7, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let src_bound = if repair {
        known_remaining(src as usize)
    } else {
        None
    };
    let dst_bound = if repair {
        known_remaining(dst as usize)
    } else {
        None
    };

    // SAFETY: strict mode follows libc semantics; hardened mode bounds reads/writes.
    let (copied_len, adverse) = unsafe {
        let (src_len, src_terminated) = scan_c_string(src, src_bound);
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
                        raw_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), copy_payload);
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
        runtime_policy::scaled_cost(8, copied_len),
        adverse,
    );
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    dst
}

// ---------------------------------------------------------------------------
// stpcpy
// ---------------------------------------------------------------------------

/// POSIX `stpcpy` -- copies `src` to `dst` and returns a pointer to the
/// trailing NUL byte in `dst`.
///
/// # Safety
///
/// Caller must ensure `dst` is large enough for `src` including NUL and that
/// both pointers are valid.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn stpcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    if dst.is_null() || src.is_null() {
        return dst;
    }

    // SAFETY: pointer validity and bounds are validated by the delegated ABI helper.
    let copied = unsafe { strcpy(dst, src) };
    if copied.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: `strcpy` above produced a NUL-terminated destination in non-deny paths.
    let len = unsafe { strlen(dst) };
    // SAFETY: `len` is measured from `dst`, so offset is within the destination string.
    unsafe { dst.add(len) }
}

// ---------------------------------------------------------------------------
// strncpy
// ---------------------------------------------------------------------------

/// POSIX `strncpy` -- copies at most `n` bytes from `src` to `dst`.
///
/// If `src` is shorter than `n`, the remainder of `dst` is filled with null bytes.
///
/// # Safety
///
/// Caller must ensure `dst` is at least `n` bytes and `src` is a valid string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strncpy(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    let (aligned, recent_page, ordering) = stage_context_two(dst as usize, src as usize);
    if dst.is_null() || src.is_null() || n == 0 {
        if dst.is_null() || src.is_null() {
            record_string_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Null)),
            );
        }
        return dst;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        n,
        true,
        known_remaining(dst as usize).is_none() && known_remaining(src as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(8, n),
            true,
        );
        return std::ptr::null_mut();
    }

    let (copy_len, clamped) = maybe_clamp_copy_len(
        n,
        Some(src as usize),
        Some(dst as usize),
        repair_enabled(mode.heals_enabled(), decision.action),
    );
    if copy_len == 0 {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Bounds)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(8, n),
            true,
        );
        return dst;
    }

    // SAFETY: bounded by copy_len, which is either n or clamped in hardened mode.
    unsafe {
        let mut i = 0usize;
        while i < copy_len {
            let ch = *src.add(i);
            *dst.add(i) = ch;
            i += 1;
            if ch == 0 {
                break;
            }
        }
        while i < copy_len {
            *dst.add(i) = 0;
            i += 1;
        }
    }
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(8, copy_len),
        clamped,
    );
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    dst
}

// ---------------------------------------------------------------------------
// stpncpy
// ---------------------------------------------------------------------------

/// POSIX `stpncpy` -- copies at most `n` bytes from `src` to `dst` and returns
/// the end pointer according to C `stpncpy` semantics.
///
/// # Safety
///
/// Caller must ensure `dst` is valid for at least `n` bytes and `src` is valid
/// for reads as required by `n`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn stpncpy(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    if n == 0 {
        return dst;
    }

    // SAFETY: pointer validity and copy bounds are validated by the delegated ABI helper.
    let copied = unsafe { strncpy(dst, src, n) };
    if copied.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: bounded scan by `n` matches `stpncpy` return contract.
    let src_prefix = unsafe { strnlen(src, n) };
    let offset = if src_prefix < n { src_prefix } else { n };
    // SAFETY: offset is bounded by `n`, the API contract's writable span.
    unsafe { dst.add(offset) }
}

// ---------------------------------------------------------------------------
// strcat
// ---------------------------------------------------------------------------

/// POSIX `strcat` -- appends `src` to the end of `dst`.
///
/// # Safety
///
/// Caller must ensure `dst` has enough space for the concatenated result
/// including null terminator, and that the buffers do not overlap.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strcat(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    let (aligned, recent_page, ordering) = stage_context_two(dst as usize, src as usize);
    if dst.is_null() || src.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
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
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 8, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let dst_bound = if repair {
        known_remaining(dst as usize)
    } else {
        None
    };
    let src_bound = if repair {
        known_remaining(src as usize)
    } else {
        None
    };

    // SAFETY: strict mode preserves raw strcat behavior; hardened mode bounds writes.
    let (work, adverse) = unsafe {
        let (dst_len, dst_terminated) = scan_c_string(dst.cast_const(), dst_bound);
        let (src_len, src_terminated) = scan_c_string(src, src_bound);
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
                            raw_memcpy_bytes(
                                dst.add(dst_len).cast::<u8>(),
                                src.cast::<u8>(),
                                copy_payload,
                            );
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
        runtime_policy::scaled_cost(9, work),
        adverse,
    );
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    dst
}

// ---------------------------------------------------------------------------
// strncat
// ---------------------------------------------------------------------------

/// POSIX `strncat` -- appends at most `n` bytes from `src` to `dst`.
///
/// Always null-terminates the result.
///
/// # Safety
///
/// Caller must ensure `dst` has enough space for the concatenated result
/// (up to `strlen(dst) + n + 1` bytes).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strncat(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    let (aligned, recent_page, ordering) = stage_context_two(dst as usize, src as usize);
    if dst.is_null() || src.is_null() || n == 0 {
        if dst.is_null() || src.is_null() {
            record_string_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Null)),
            );
        }
        return dst;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        n,
        true,
        known_remaining(dst as usize).is_none() && known_remaining(src as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(9, n),
            true,
        );
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let dst_bound = if repair {
        known_remaining(dst as usize)
    } else {
        None
    };
    let src_bound = if repair {
        known_remaining(src as usize)
    } else {
        None
    };

    // SAFETY: strict mode preserves raw strncat behavior; hardened mode bounds writes.
    let (work, adverse) = unsafe {
        let (dst_len, dst_terminated) = scan_c_string(dst.cast_const(), dst_bound);
        let src_scan_bound = src_bound.map(|v| v.min(n));
        let (src_len, src_terminated) = scan_c_string(src, src_scan_bound);
        if repair {
            match dst_bound {
                Some(0) => {
                    record_truncation(n.saturating_add(1), 0);
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
                            raw_memcpy_bytes(
                                dst.add(dst_len).cast::<u8>(),
                                src.cast::<u8>(),
                                copy_payload,
                            );
                        }
                        *dst.add(dst_len.saturating_add(copy_payload)) = 0;
                        let truncated = (!src_terminated && src_scan_bound == Some(src_len))
                            || copy_payload < src_len
                            || src_len == n;
                        if truncated {
                            record_truncation(n.saturating_add(1), copy_payload);
                        }
                        (
                            dst_len.saturating_add(copy_payload).saturating_add(1),
                            truncated,
                        )
                    }
                }
                None => {
                    let mut i = 0usize;
                    while i < n {
                        let ch = *src.add(i);
                        if ch == 0 {
                            break;
                        }
                        *dst.add(dst_len + i) = ch;
                        i += 1;
                    }
                    *dst.add(dst_len + i) = 0;
                    (dst_len.saturating_add(i).saturating_add(1), false)
                }
            }
        } else {
            let mut i = 0usize;
            while i < n {
                let ch = *src.add(i);
                if ch == 0 {
                    break;
                }
                *dst.add(dst_len + i) = ch;
                i += 1;
            }
            *dst.add(dst_len + i) = 0;
            (dst_len.saturating_add(i).saturating_add(1), false)
        }
    };
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(9, work),
        adverse,
    );
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    dst
}

// ---------------------------------------------------------------------------
// strchr
// ---------------------------------------------------------------------------

/// POSIX `strchr` -- locates the first occurrence of `c` in the string `s`.
///
/// Returns pointer to the first occurrence, or null if not found.
/// If `c` is '\0', returns pointer to the terminating null byte.
///
/// # Safety
///
/// Caller must ensure `s` is a valid null-terminated string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    let (aligned, recent_page, ordering) = stage_context_one(s as usize);
    if s.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return std::ptr::null_mut();
    }

    let target = c as c_char;
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        0,
        false,
        known_remaining(s as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 6, true);
        return std::ptr::null_mut();
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(s as usize)
    } else {
        None
    };

    // SAFETY: strict mode preserves raw strchr behavior; hardened mode bounds scan.
    let (out, adverse, span) = unsafe {
        let mut i = 0usize;
        loop {
            if let Some(limit) = bound
                && i >= limit
            {
                break (std::ptr::null_mut(), true, i);
            }
            let ch = *s.add(i);
            if ch == target {
                break (s.add(i) as *mut c_char, false, i.saturating_add(1));
            }
            if ch == 0 {
                break (std::ptr::null_mut(), false, i.saturating_add(1));
            }
            i += 1;
        }
    };

    if adverse {
        record_truncation(bound.unwrap_or(span), span);
    }
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(6, span),
        adverse,
    );
    out
}

// ---------------------------------------------------------------------------
// strchrnul
// ---------------------------------------------------------------------------

/// GNU `strchrnul` -- locates the first occurrence of `c` in `s`, returning
/// the string terminator when `c` is absent.
///
/// # Safety
///
/// Caller must ensure `s` is a valid null-terminated string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strchrnul(s: *const c_char, c: c_int) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: delegated ABI helper validates scan behavior through the membrane.
    let found = unsafe { strchr(s, c) };
    if !found.is_null() {
        return found;
    }

    // SAFETY: delegated ABI helper computes the terminating NUL index.
    let len = unsafe { strlen(s) };
    // SAFETY: len is measured from `s`, so the resulting pointer is within the string object.
    unsafe { s.add(len) as *mut c_char }
}

// ---------------------------------------------------------------------------
// strrchr
// ---------------------------------------------------------------------------

/// POSIX `strrchr` -- locates the last occurrence of `c` in the string `s`.
///
/// Returns pointer to the last occurrence, or null if not found.
///
/// # Safety
///
/// Caller must ensure `s` is a valid null-terminated string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strrchr(s: *const c_char, c: c_int) -> *mut c_char {
    let (aligned, recent_page, ordering) = stage_context_one(s as usize);
    if s.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return std::ptr::null_mut();
    }

    let target = c as c_char;
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        0,
        false,
        known_remaining(s as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 6, true);
        return std::ptr::null_mut();
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(s as usize)
    } else {
        None
    };
    // SAFETY: strict mode preserves raw strrchr behavior; hardened mode bounds scan.
    let (result, adverse, span) = unsafe {
        let mut result_local: *mut c_char = std::ptr::null_mut();
        let mut i = 0usize;
        loop {
            if let Some(limit) = bound
                && i >= limit
            {
                break (result_local, true, i);
            }
            let ch = *s.add(i);
            if ch == target {
                result_local = s.add(i) as *mut c_char;
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
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(6, span),
        adverse,
    );
    result
}

// ---------------------------------------------------------------------------
// strstr
// ---------------------------------------------------------------------------

/// POSIX `strstr` -- locates the first occurrence of substring `needle` in `haystack`.
///
/// Returns pointer to the beginning of the located substring, or null if not found.
/// If `needle` is empty, returns `haystack`.
///
/// # Safety
///
/// Caller must ensure both `haystack` and `needle` are valid null-terminated strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char {
    let (aligned, recent_page, ordering) = stage_context_two(haystack as usize, needle as usize);
    if haystack.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return std::ptr::null_mut();
    }
    if needle.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return haystack as *mut c_char;
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
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 10, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let hay_bound = if repair {
        known_remaining(haystack as usize)
    } else {
        None
    };
    let needle_bound = if repair {
        known_remaining(needle as usize)
    } else {
        None
    };

    // SAFETY: strict mode preserves raw strstr behavior; hardened mode bounds scan.
    let (out, adverse, work) = unsafe {
        let (needle_len, needle_terminated) = scan_c_string(needle, needle_bound);
        let (hay_len, hay_terminated) = scan_c_string(haystack, hay_bound);
        let mut out_local = std::ptr::null_mut();
        let mut work_local = 0usize;

        if needle_len == 0 {
            out_local = haystack as *mut c_char;
            work_local = 1;
        } else if hay_len >= needle_len {
            let mut h = 0usize;
            while h + needle_len <= hay_len {
                let mut n = 0usize;
                while n < needle_len && *haystack.add(h + n) == *needle.add(n) {
                    n += 1;
                }
                if n == needle_len {
                    out_local = haystack.add(h) as *mut c_char;
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
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(10, work),
        adverse,
    );
    out
}

// ---------------------------------------------------------------------------
// strtok
// ---------------------------------------------------------------------------

// Thread-local save pointer for strtok state.
thread_local! {
    static STRTOK_SAVE: std::cell::Cell<*mut c_char> = const { std::cell::Cell::new(std::ptr::null_mut()) };
}

/// POSIX `strtok` -- splits string into tokens delimited by characters in `delim`.
///
/// On the first call, `s` should point to the string to tokenize.
/// On subsequent calls, `s` should be null to continue tokenizing the same string.
///
/// # Safety
///
/// Caller must ensure `s` (if non-null) and `delim` are valid null-terminated strings.
/// Note: `strtok` modifies the source string and is not reentrant. Use `strtok_r` for
/// reentrant usage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtok(s: *mut c_char, delim: *const c_char) -> *mut c_char {
    let (aligned, recent_page, ordering) = stage_context_two(s as usize, delim as usize);
    if delim.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return std::ptr::null_mut();
    }

    let addr_hint = if s.is_null() { 0 } else { s as usize };
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        addr_hint,
        0,
        true,
        known_remaining(addr_hint).is_none() && known_remaining(delim as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 8, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);

    // SAFETY: Thread-local access; strtok is specified as non-reentrant per POSIX.
    let (token, adverse, work) = unsafe {
        let saved = STRTOK_SAVE.get();
        let current = if s.is_null() { saved } else { s };
        let mut work = 0usize;

        if current.is_null() {
            STRTOK_SAVE.set(std::ptr::null_mut());
            (std::ptr::null_mut(), false, work)
        } else {
            let bound = if repair {
                known_remaining(current as usize)
            } else {
                None
            };

            // Determine a safe scan limit for finding delimiters

            let (scan_limit, terminated) = scan_c_string(current, bound);

            // In hardened mode, we effectively clamp the slice to the known bound or the next null.

            // Only include the terminator byte in the slice if it was actually found.

            let slice_len = if terminated {
                scan_limit + 1
            } else {
                scan_limit
            };

            let s_slice = std::slice::from_raw_parts_mut(current as *mut u8, slice_len);

            // We also need a slice for delim.

            // Warning: `delim` might be unbounded. We scan it safely.

            let delim_bound = if repair {
                known_remaining(delim as usize)
            } else {
                None
            };

            let (delim_len, delim_terminated) = scan_c_string(delim, delim_bound);

            let delim_slice_len = if delim_terminated {
                delim_len + 1
            } else {
                delim_len
            };

            let delim_slice = std::slice::from_raw_parts(delim as *const u8, delim_slice_len);

            // Core `strtok` returns (start_idx, token_len). It modifies s_slice in place.

            match frankenlibc_core::string::strtok::strtok(s_slice, delim_slice) {
                Some((start, len)) => {
                    let token_start = current.add(start);
                    let token_end_idx = start + len;
                    // strtok puts a NUL at token_end_idx. The next token starts after that NUL.
                    // If we are at the end of the slice (NUL was already there), save_ptr is end.
                    // But core's strtok writes NUL if needed.
                    // We need to advance save pointer.
                    // The core logic doesn't return the "next" position directly, but we can infer it:
                    // it is token_start + len + 1.

                    let next_pos = if token_end_idx + 1 < s_slice.len() {
                        token_end_idx + 1
                    } else {
                        token_end_idx // End of string
                    };

                    // Update save pointer
                    STRTOK_SAVE.set(current.add(next_pos));
                    work = next_pos; // Approximate work
                    (token_start, false, work)
                }
                None => {
                    STRTOK_SAVE.set(std::ptr::null_mut());
                    work = scan_limit;
                    (std::ptr::null_mut(), false, work)
                }
            }
        }
    };

    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(8, work),
        adverse,
    );
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    token
}

// ---------------------------------------------------------------------------
// strtok_r
// ---------------------------------------------------------------------------

/// POSIX `strtok_r` -- reentrant version of `strtok`.
///
/// # Safety
///
/// Caller must ensure `s` (if non-null) and `delim` are valid null-terminated strings.
/// `saveptr` must be a valid pointer to a `char *`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtok_r(
    s: *mut c_char,
    delim: *const c_char,
    saveptr: *mut *mut c_char,
) -> *mut c_char {
    let (aligned, recent_page, ordering) = stage_context_two(s as usize, delim as usize);
    if delim.is_null() || saveptr.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return std::ptr::null_mut();
    }

    let addr_hint = if s.is_null() {
        unsafe { *saveptr as usize }
    } else {
        s as usize
    };

    // Membrane decision logic similar to strtok
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        addr_hint,
        0,
        true,
        known_remaining(addr_hint).is_none() && known_remaining(delim as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 8, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);

    unsafe {
        let current = if s.is_null() { *saveptr } else { s };

        if current.is_null() {
            *saveptr = std::ptr::null_mut();
            runtime_policy::observe(
                ApiFamily::StringMemory,
                decision.profile,
                runtime_policy::scaled_cost(8, 0),
                false,
            );
            record_string_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Null)),
            );
            return std::ptr::null_mut();
        }

        let bound = if repair {
            known_remaining(current as usize)
        } else {
            None
        };

        let (scan_limit, terminated) = scan_c_string(current, bound);

        // Create slice covering the string up to the terminator (or bound)

        let slice_len = if terminated {
            scan_limit + 1
        } else {
            scan_limit
        };

        let s_slice = std::slice::from_raw_parts_mut(current as *mut u8, slice_len);

        let delim_bound = if repair {
            known_remaining(delim as usize)
        } else {
            None
        };

        let (delim_len, delim_terminated) = scan_c_string(delim, delim_bound);

        let delim_slice_len = if delim_terminated {
            delim_len + 1
        } else {
            delim_len
        };

        let delim_slice = std::slice::from_raw_parts(delim as *const u8, delim_slice_len);

        // Core `strtok_r` returns (start, len, next_offset) relative to the slice start (0)

        match frankenlibc_core::string::strtok::strtok_r(s_slice, delim_slice, 0) {
            Some((start, _len, next_offset)) => {
                let token = current.add(start);
                *saveptr = current.add(next_offset);

                runtime_policy::observe(
                    ApiFamily::StringMemory,
                    decision.profile,
                    runtime_policy::scaled_cost(8, next_offset),
                    false,
                );
                record_string_stage_outcome(
                    &ordering,
                    aligned,
                    recent_page,
                    Some(stage_index(&ordering, CheckStage::Bounds)),
                );
                token
            }
            None => {
                *saveptr = std::ptr::null_mut();
                runtime_policy::observe(
                    ApiFamily::StringMemory,
                    decision.profile,
                    runtime_policy::scaled_cost(8, scan_limit),
                    false,
                );
                record_string_stage_outcome(
                    &ordering,
                    aligned,
                    recent_page,
                    Some(stage_index(&ordering, CheckStage::Bounds)),
                );
                std::ptr::null_mut()
            }
        }
    }
}
