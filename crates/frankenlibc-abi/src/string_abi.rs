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
                    if src_len > 0 {
                        raw_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), src_len);
                    }
                    *dst.add(src_len) = 0;
                    let truncated = !src_terminated;
                    if truncated {
                        record_truncation(requested, src_len);
                    }
                    (src_len.saturating_add(1), truncated)
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
                    if src_len > 0 {
                        raw_memcpy_bytes(dst.add(dst_len).cast::<u8>(), src.cast::<u8>(), src_len);
                    }
                    *dst.add(dst_len.saturating_add(src_len)) = 0;
                    let truncated = !src_terminated;
                    if truncated {
                        record_truncation(src_len.saturating_add(1), src_len);
                    }
                    (dst_len.saturating_add(src_len).saturating_add(1), truncated)
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
        let src_scan_bound = Some(src_bound.unwrap_or(usize::MAX).min(n));
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
                    if src_len > 0 {
                        raw_memcpy_bytes(dst.add(dst_len).cast::<u8>(), src.cast::<u8>(), src_len);
                    }
                    *dst.add(dst_len.saturating_add(src_len)) = 0;
                    let truncated = !src_terminated && src_scan_bound == Some(src_len);
                    if truncated {
                        record_truncation(n.saturating_add(1), src_len);
                    }
                    (dst_len.saturating_add(src_len).saturating_add(1), truncated)
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

// ---------------------------------------------------------------------------
// strcasecmp
// ---------------------------------------------------------------------------

/// POSIX `strcasecmp` -- case-insensitive comparison of two null-terminated strings.
///
/// # Safety
///
/// Caller must ensure both `s1` and `s2` point to valid null-terminated strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strcasecmp(s1: *const c_char, s2: *const c_char) -> c_int {
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

    // SAFETY: bounded scan within known limits.
    let (result, span) = unsafe {
        let (s1_len, _) = scan_c_string(s1, lhs_bound);
        let (s2_len, _) = scan_c_string(s2, rhs_bound);
        let s1_slice = std::slice::from_raw_parts(s1.cast::<u8>(), s1_len + 1);
        let s2_slice = std::slice::from_raw_parts(s2.cast::<u8>(), s2_len + 1);
        let r = frankenlibc_core::string::str::strcasecmp(s1_slice, s2_slice);
        (r, s1_len.max(s2_len))
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
        runtime_policy::scaled_cost(7, span),
        lhs_bound.is_some() || rhs_bound.is_some(),
    );
    result
}

// ---------------------------------------------------------------------------
// strncasecmp
// ---------------------------------------------------------------------------

/// POSIX `strncasecmp` -- case-insensitive comparison of at most `n` bytes.
///
/// # Safety
///
/// Caller must ensure both `s1` and `s2` point to valid memory for the compared span.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strncasecmp(s1: *const c_char, s2: *const c_char, n: usize) -> c_int {
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

    // SAFETY: bounded compare within cmp_limit.
    let result = unsafe {
        let mut i = 0usize;
        loop {
            if i >= cmp_limit {
                break 0;
            }
            let a = (*s1.add(i) as u8).to_ascii_lowercase();
            let b = (*s2.add(i) as u8).to_ascii_lowercase();
            if a != b {
                break (a as c_int) - (b as c_int);
            }
            if a == 0 {
                break 0;
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
        runtime_policy::scaled_cost(7, cmp_limit),
        adverse,
    );
    result
}

// ---------------------------------------------------------------------------
// strspn
// ---------------------------------------------------------------------------

/// POSIX `strspn` -- returns length of initial segment of `s` consisting of
/// bytes in `accept`.
///
/// # Safety
///
/// Caller must ensure both `s` and `accept` are valid null-terminated strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strspn(s: *const c_char, accept: *const c_char) -> usize {
    let (aligned, recent_page, ordering) = stage_context_two(s as usize, accept as usize);
    if s.is_null() || accept.is_null() {
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
        known_remaining(s as usize).is_none() && known_remaining(accept as usize).is_none(),
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
    let s_bound = if repair {
        known_remaining(s as usize)
    } else {
        None
    };
    let accept_bound = if repair {
        known_remaining(accept as usize)
    } else {
        None
    };

    // SAFETY: bounded scan.
    let (result, span) = unsafe {
        let (s_len, _) = scan_c_string(s, s_bound);
        let (accept_len, _) = scan_c_string(accept, accept_bound);
        let s_slice = std::slice::from_raw_parts(s.cast::<u8>(), s_len + 1);
        let accept_slice = std::slice::from_raw_parts(accept.cast::<u8>(), accept_len + 1);
        let r = frankenlibc_core::string::str::strspn(s_slice, accept_slice);
        (r, s_len)
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
        runtime_policy::scaled_cost(7, span),
        s_bound.is_some(),
    );
    result
}

// ---------------------------------------------------------------------------
// strcspn
// ---------------------------------------------------------------------------

/// POSIX `strcspn` -- returns length of initial segment of `s` consisting
/// entirely of bytes NOT in `reject`.
///
/// # Safety
///
/// Caller must ensure both `s` and `reject` are valid null-terminated strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strcspn(s: *const c_char, reject: *const c_char) -> usize {
    let (aligned, recent_page, ordering) = stage_context_two(s as usize, reject as usize);
    if s.is_null() || reject.is_null() {
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
        known_remaining(s as usize).is_none() && known_remaining(reject as usize).is_none(),
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
    let s_bound = if repair {
        known_remaining(s as usize)
    } else {
        None
    };
    let reject_bound = if repair {
        known_remaining(reject as usize)
    } else {
        None
    };

    // SAFETY: bounded scan.
    let (result, span) = unsafe {
        let (s_len, _) = scan_c_string(s, s_bound);
        let (reject_len, _) = scan_c_string(reject, reject_bound);
        let s_slice = std::slice::from_raw_parts(s.cast::<u8>(), s_len + 1);
        let reject_slice = std::slice::from_raw_parts(reject.cast::<u8>(), reject_len + 1);
        let r = frankenlibc_core::string::str::strcspn(s_slice, reject_slice);
        (r, s_len)
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
        runtime_policy::scaled_cost(7, span),
        s_bound.is_some(),
    );
    result
}

// ---------------------------------------------------------------------------
// strpbrk
// ---------------------------------------------------------------------------

/// POSIX `strpbrk` -- locates the first occurrence in `s` of any byte from `accept`.
///
/// Returns pointer to the matching byte, or null if not found.
///
/// # Safety
///
/// Caller must ensure both `s` and `accept` are valid null-terminated strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strpbrk(s: *const c_char, accept: *const c_char) -> *mut c_char {
    let (aligned, recent_page, ordering) = stage_context_two(s as usize, accept as usize);
    if s.is_null() || accept.is_null() {
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
        s as usize,
        0,
        false,
        known_remaining(s as usize).is_none() && known_remaining(accept as usize).is_none(),
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

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let s_bound = if repair {
        known_remaining(s as usize)
    } else {
        None
    };
    let accept_bound = if repair {
        known_remaining(accept as usize)
    } else {
        None
    };

    // SAFETY: bounded scan.
    let (result, span) = unsafe {
        let (s_len, _) = scan_c_string(s, s_bound);
        let (accept_len, _) = scan_c_string(accept, accept_bound);
        let s_slice = std::slice::from_raw_parts(s.cast::<u8>(), s_len + 1);
        let accept_slice = std::slice::from_raw_parts(accept.cast::<u8>(), accept_len + 1);
        match frankenlibc_core::string::str::strpbrk(s_slice, accept_slice) {
            Some(idx) => (s.add(idx) as *mut c_char, s_len),
            None => (std::ptr::null_mut(), s_len),
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
        runtime_policy::scaled_cost(7, span),
        s_bound.is_some(),
    );
    result
}

// ---------------------------------------------------------------------------
// strdup
// ---------------------------------------------------------------------------

/// POSIX `strdup` -- duplicates a null-terminated string into malloc'd memory.
///
/// Returns pointer to the new string, or null on failure.
///
/// # Safety
///
/// Caller must ensure `s` is a valid null-terminated string.
/// The returned pointer must be freed with `free`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strdup(s: *const c_char) -> *mut c_char {
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
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 7, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let bound = if repair {
        known_remaining(s as usize)
    } else {
        None
    };

    // SAFETY: scan string, allocate via malloc, copy.
    unsafe {
        let (s_len, _) = scan_c_string(s, bound);
        let alloc_size = s_len + 1;

        let dst = crate::malloc_abi::malloc(alloc_size);
        if dst.is_null() {
            record_string_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Bounds)),
            );
            runtime_policy::observe(
                ApiFamily::StringMemory,
                decision.profile,
                runtime_policy::scaled_cost(8, s_len),
                bound.is_some(),
            );
            return std::ptr::null_mut();
        }

        raw_memcpy_bytes(dst.cast::<u8>(), s.cast::<u8>(), s_len);
        *(dst as *mut u8).add(s_len) = 0;

        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Bounds)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(8, s_len),
            bound.is_some(),
        );
        dst.cast::<c_char>()
    }
}

// ---------------------------------------------------------------------------
// strndup
// ---------------------------------------------------------------------------

/// POSIX `strndup` -- duplicates at most `n` bytes of a null-terminated string
/// into malloc'd memory.
///
/// Always null-terminates the result.
///
/// # Safety
///
/// Caller must ensure `s` is a valid null-terminated string.
/// The returned pointer must be freed with `free`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strndup(s: *const c_char, n: usize) -> *mut c_char {
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
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 7, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let bound = if repair {
        known_remaining(s as usize).map(|b| b.min(n))
    } else {
        Some(n)
    };

    // SAFETY: scan string up to n, allocate via malloc, copy.
    unsafe {
        let (s_len, _) = scan_c_string(s, bound);
        let copy_len = s_len.min(n);
        let alloc_size = copy_len + 1;

        let dst = crate::malloc_abi::malloc(alloc_size);
        if dst.is_null() {
            record_string_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Bounds)),
            );
            runtime_policy::observe(
                ApiFamily::StringMemory,
                decision.profile,
                runtime_policy::scaled_cost(8, copy_len),
                bound.is_some() && bound != Some(n),
            );
            return std::ptr::null_mut();
        }

        if copy_len > 0 {
            raw_memcpy_bytes(dst.cast::<u8>(), s.cast::<u8>(), copy_len);
        }
        *(dst as *mut u8).add(copy_len) = 0;

        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Bounds)),
        );
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(8, copy_len),
            bound.is_some() && bound != Some(n),
        );
        dst.cast::<c_char>()
    }
}

// ---------------------------------------------------------------------------
// memmem
// ---------------------------------------------------------------------------

/// GNU `memmem` -- locates the first occurrence of `needle` (of `needle_len`
/// bytes) in `haystack` (of `haystack_len` bytes).
///
/// Returns pointer to the start of the match, or null if not found.
///
/// # Safety
///
/// Caller must ensure `haystack` is valid for `haystack_len` bytes and
/// `needle` is valid for `needle_len` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn memmem(
    haystack: *const c_void,
    haystack_len: usize,
    needle: *const c_void,
    needle_len: usize,
) -> *mut c_void {
    if needle_len == 0 {
        return haystack as *mut c_void;
    }

    let (aligned, recent_page, ordering) = stage_context_two(haystack as usize, needle as usize);
    if haystack.is_null() || needle.is_null() || haystack_len == 0 {
        if haystack.is_null() || needle.is_null() {
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
        haystack as usize,
        haystack_len,
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
        runtime_policy::observe(
            ApiFamily::StringMemory,
            decision.profile,
            runtime_policy::scaled_cost(10, haystack_len),
            true,
        );
        return std::ptr::null_mut();
    }

    let (hay_scan, clamped_h) = maybe_clamp_copy_len(
        haystack_len,
        Some(haystack as usize),
        None,
        repair_enabled(mode.heals_enabled(), decision.action),
    );
    let (needle_scan, _clamped_n) = maybe_clamp_copy_len(
        needle_len,
        Some(needle as usize),
        None,
        repair_enabled(mode.heals_enabled(), decision.action),
    );

    // SAFETY: bounded by clamped lengths.
    let result = unsafe {
        let h_bytes = std::slice::from_raw_parts(haystack.cast::<u8>(), hay_scan);
        let n_bytes = std::slice::from_raw_parts(needle.cast::<u8>(), needle_scan);
        match frankenlibc_core::string::mem::memmem(h_bytes, hay_scan, n_bytes, needle_scan) {
            Some(idx) => (haystack as *mut u8).add(idx).cast::<c_void>(),
            None => std::ptr::null_mut(),
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
        runtime_policy::scaled_cost(10, hay_scan),
        clamped_h,
    );
    result
}

// ---------------------------------------------------------------------------
// mempcpy
// ---------------------------------------------------------------------------

/// GNU `mempcpy` -- copies `n` bytes from `src` to `dst` and returns a pointer
/// to the byte after the last written byte.
///
/// # Safety
///
/// Caller must ensure `src` and `dst` are valid for `n` bytes and do not overlap.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mempcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let Some(_membrane_guard) = enter_string_membrane_guard() else {
        if n == 0 {
            return dst;
        }
        if dst.is_null() || src.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: reentrant fallback.
        unsafe {
            raw_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), n);
        }
        return unsafe { (dst as *mut u8).add(n).cast() };
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
    // SAFETY: copy_len <= n, pointer arithmetic within copied range.
    unsafe { (dst as *mut u8).add(copy_len).cast() }
}

// ---------------------------------------------------------------------------
// strcasestr
// ---------------------------------------------------------------------------

/// GNU `strcasestr` -- case-insensitive version of strstr.
///
/// Returns pointer to the first case-insensitive occurrence of `needle`
/// in `haystack`, or null if not found.
///
/// # Safety
///
/// Caller must ensure both `haystack` and `needle` are valid null-terminated strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strcasestr(haystack: *const c_char, needle: *const c_char) -> *mut c_char {
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

    // SAFETY: bounded scan.
    let (out, span) = unsafe {
        let (hay_len, _) = scan_c_string(haystack, hay_bound);
        let (needle_len, _) = scan_c_string(needle, needle_bound);
        let h_slice = std::slice::from_raw_parts(haystack.cast::<u8>(), hay_len + 1);
        let n_slice = std::slice::from_raw_parts(needle.cast::<u8>(), needle_len + 1);
        match frankenlibc_core::string::str::strcasestr(h_slice, n_slice) {
            Some(idx) => (haystack.add(idx) as *mut c_char, hay_len),
            None => (std::ptr::null_mut(), hay_len),
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
        runtime_policy::scaled_cost(10, span),
        hay_bound.is_some() || needle_bound.is_some(),
    );
    out
}

// ---------------------------------------------------------------------------
// strerror
// ---------------------------------------------------------------------------

// Thread-local buffer for strerror return values.
thread_local! {
    static STRERROR_BUF: std::cell::RefCell<[u8; 256]> = const { std::cell::RefCell::new([0u8; 256]) };
}

/// POSIX `strerror` -- returns a pointer to a string describing the error number.
///
/// The returned string is stored in a thread-local buffer and must not be freed.
///
/// # Safety
///
/// The returned pointer is valid until the next call to `strerror` on the same thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strerror(errnum: c_int) -> *mut c_char {
    let msg = frankenlibc_core::errno::strerror_message(errnum);
    STRERROR_BUF
        .try_with(|buf_cell| {
            let mut buf = buf_cell.borrow_mut();
            let msg_bytes = msg.as_bytes();
            let copy_len = msg_bytes.len().min(buf.len() - 1);
            buf[..copy_len].copy_from_slice(&msg_bytes[..copy_len]);
            buf[copy_len] = 0;
            buf.as_ptr() as *mut c_char
        })
        .unwrap_or(std::ptr::null_mut())
}

// ---------------------------------------------------------------------------
// strerror_r
// ---------------------------------------------------------------------------

/// POSIX `strerror_r` (XSI-compliant) -- fills `buf` with the error message for `errnum`.
///
/// Returns 0 on success, or an errno value on failure.
///
/// # Safety
///
/// Caller must ensure `buf` is valid for `buflen` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    if buf.is_null() || buflen == 0 {
        return frankenlibc_core::errno::EINVAL;
    }

    let msg = frankenlibc_core::errno::strerror_message(errnum);
    let msg_bytes = msg.as_bytes();
    let copy_len = msg_bytes.len().min(buflen - 1);

    // SAFETY: caller guarantees `buf` is valid for `buflen` bytes.
    unsafe {
        raw_memcpy_bytes(buf.cast::<u8>(), msg_bytes.as_ptr(), copy_len);
        *buf.add(copy_len) = 0;
    }

    if msg_bytes.len() >= buflen {
        frankenlibc_core::errno::ERANGE
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// memccpy
// ---------------------------------------------------------------------------

/// POSIX `memccpy` -- copies bytes from `src` to `dst` until byte `c` is found
/// or `n` bytes are copied.
///
/// Returns a pointer to the byte after `c` in `dst`, or null if `c` was not found.
///
/// # Safety
///
/// Caller must ensure `src` and `dst` are valid for `n` bytes and do not overlap.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn memccpy(
    dst: *mut c_void,
    src: *const c_void,
    c: c_int,
    n: usize,
) -> *mut c_void {
    let Some(_membrane_guard) = enter_string_membrane_guard() else {
        if n == 0 || dst.is_null() || src.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: reentrant fallback -- simple byte-by-byte copy.
        let c_byte = c as u8;
        unsafe {
            let s = src.cast::<u8>();
            let d = dst.cast::<u8>();
            for i in 0..n {
                let b = std::ptr::read_volatile(s.add(i));
                std::ptr::write_volatile(d.add(i), b);
                if b == c_byte {
                    return d.add(i + 1).cast();
                }
            }
        }
        return std::ptr::null_mut();
    };

    let aligned = ((dst as usize) | (src as usize)) & 0x7 == 0;
    let recent_page = (!dst.is_null() && known_remaining(dst as usize).is_some())
        || (!src.is_null() && known_remaining(src as usize).is_some());
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);

    if n == 0 || dst.is_null() || src.is_null() {
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

    // SAFETY: `copy_len` is original `n` or clamped to known bounds.
    let result = unsafe {
        let d_slice = std::slice::from_raw_parts_mut(dst.cast::<u8>(), copy_len);
        let s_slice = std::slice::from_raw_parts(src.cast::<u8>(), copy_len);
        match frankenlibc_core::string::memccpy(d_slice, s_slice, c as u8, copy_len) {
            Some(idx) => (dst as *mut u8).add(idx).cast(),
            None => std::ptr::null_mut(),
        }
    };

    record_string_stage_outcome(&ordering, aligned, recent_page, None);
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, copy_len),
        clamped,
    );
    result
}

// ---------------------------------------------------------------------------
// bzero
// ---------------------------------------------------------------------------

/// BSD `bzero` -- sets `n` bytes of `s` to zero.
///
/// # Safety
///
/// Caller must ensure `s` is valid for `n` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bzero(s: *mut c_void, n: usize) {
    let Some(_membrane_guard) = enter_string_membrane_guard() else {
        if n == 0 || s.is_null() {
            return;
        }
        // SAFETY: reentrant fallback.
        unsafe {
            raw_memset_bytes(s.cast::<u8>(), 0, n);
        }
        return;
    };

    let aligned = (s as usize) & 0x7 == 0;
    let recent_page = !s.is_null() && known_remaining(s as usize).is_some();
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);

    if n == 0 || s.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        n,
        true,
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
            runtime_policy::scaled_cost(5, n),
            true,
        );
        return;
    }

    let (set_len, clamped) = maybe_clamp_copy_len(
        n,
        None,
        Some(s as usize),
        mode.heals_enabled() || matches!(decision.action, MembraneAction::Repair(_)),
    );

    // SAFETY: `set_len` is original `n` or clamped to known bounds.
    unsafe {
        let slice = std::slice::from_raw_parts_mut(s.cast::<u8>(), set_len);
        frankenlibc_core::string::bzero(slice, set_len);
    }

    record_string_stage_outcome(&ordering, aligned, recent_page, None);
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(5, set_len),
        clamped,
    );
}

// ---------------------------------------------------------------------------
// explicit_bzero
// ---------------------------------------------------------------------------

/// POSIX `explicit_bzero` -- like bzero but guaranteed not to be optimized away.
///
/// # Safety
///
/// Caller must ensure `s` is valid for `n` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn explicit_bzero(s: *mut c_void, n: usize) {
    // Delegates to bzero which already uses black_box internally.
    // SAFETY: same contract as bzero.
    unsafe {
        bzero(s, n);
    }
}

// ---------------------------------------------------------------------------
// bcmp
// ---------------------------------------------------------------------------

/// BSD `bcmp` -- compares `n` bytes of `s1` and `s2`. Returns 0 if equal.
///
/// # Safety
///
/// Caller must ensure `s1` and `s2` are valid for `n` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bcmp(s1: *const c_void, s2: *const c_void, n: usize) -> c_int {
    if n == 0 {
        return 0;
    }
    if s1.is_null() || s2.is_null() {
        return if s1 == s2 { 0 } else { 1 };
    }

    // SAFETY: caller contract for bcmp requires both pointers valid for `n` bytes.
    unsafe {
        let a = std::slice::from_raw_parts(s1.cast::<u8>(), n);
        let b = std::slice::from_raw_parts(s2.cast::<u8>(), n);
        frankenlibc_core::string::bcmp(a, b, n)
    }
}

// ---------------------------------------------------------------------------
// bcopy
// ---------------------------------------------------------------------------

/// BSD `bcopy` -- copies `n` bytes from `src` to `dst` (handles overlap).
///
/// Note: argument order is (src, dst, n) unlike memcpy which is (dst, src, n).
///
/// # Safety
///
/// Caller must ensure `src` and `dst` are valid for `n` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bcopy(src: *const c_void, dst: *mut c_void, n: usize) {
    // bcopy is memmove with swapped argument order.
    // SAFETY: same contract, delegates to memmove.
    unsafe {
        memmove(dst, src, n);
    }
}

// ---------------------------------------------------------------------------
// swab
// ---------------------------------------------------------------------------

/// POSIX `swab` -- swaps adjacent bytes in pairs from `src` to `dst`.
///
/// # Safety
///
/// Caller must ensure `src` is valid for `n` bytes and `dst` for `n` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn swab(src: *const c_void, dst: *mut c_void, isize_n: isize) {
    // POSIX swab takes ssize_t; negative values are a no-op.
    if isize_n <= 0 {
        return;
    }
    let n = isize_n as usize;

    let Some(_membrane_guard) = enter_string_membrane_guard() else {
        if dst.is_null() || src.is_null() {
            return;
        }
        // SAFETY: reentrant fallback.
        unsafe {
            let s = std::slice::from_raw_parts(src.cast::<u8>(), n);
            let d = std::slice::from_raw_parts_mut(dst.cast::<u8>(), n);
            frankenlibc_core::string::swab(s, d, n);
        }
        return;
    };

    let aligned = ((dst as usize) | (src as usize)) & 0x7 == 0;
    let recent_page = (!dst.is_null() && known_remaining(dst as usize).is_some())
        || (!src.is_null() && known_remaining(src as usize).is_some());
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);

    if dst.is_null() || src.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return;
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
            runtime_policy::scaled_cost(5, n),
            true,
        );
        return;
    }

    let (swap_len, clamped) = maybe_clamp_copy_len(
        n,
        Some(src as usize),
        Some(dst as usize),
        mode.heals_enabled() || matches!(decision.action, MembraneAction::Repair(_)),
    );

    // SAFETY: `swap_len` is original `n` or clamped to known bounds.
    unsafe {
        let s = std::slice::from_raw_parts(src.cast::<u8>(), swap_len);
        let d = std::slice::from_raw_parts_mut(dst.cast::<u8>(), swap_len);
        frankenlibc_core::string::swab(s, d, swap_len);
    }

    record_string_stage_outcome(&ordering, aligned, recent_page, None);
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(5, swap_len),
        clamped,
    );
}

// ---------------------------------------------------------------------------
// strsep
// ---------------------------------------------------------------------------

/// BSD `strsep` -- extracts the next token from `*stringp` delimited by `delim`.
///
/// Updates `*stringp` to point past the delimiter. Returns pointer to the token
/// or null if `*stringp` is null.
///
/// # Safety
///
/// Caller must ensure `stringp` points to a valid `*char` pointer and `delim`
/// is a valid null-terminated string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strsep(stringp: *mut *mut c_char, delim: *const c_char) -> *mut c_char {
    if stringp.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: caller ensures stringp is valid.
    let s = unsafe { *stringp };
    if s.is_null() {
        return std::ptr::null_mut();
    }

    let (aligned, recent_page, ordering) = stage_context_two(s as usize, delim as usize);
    if delim.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        // No delimiters -- entire string is token, *stringp = NULL.
        unsafe { *stringp = std::ptr::null_mut() };
        return s;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        0,
        true,
        known_remaining(s as usize).is_none() && known_remaining(delim as usize).is_none(),
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

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let s_bound = if repair {
        known_remaining(s as usize)
    } else {
        None
    };
    let delim_bound = if repair {
        known_remaining(delim as usize)
    } else {
        None
    };

    // SAFETY: bounded scan.
    let (result, span) = unsafe {
        let (s_len, _) = scan_c_string(s, s_bound);
        let (delim_len, _) = scan_c_string(delim, delim_bound);
        let s_slice = std::slice::from_raw_parts_mut(s.cast::<u8>(), s_len + 1);
        let delim_slice = std::slice::from_raw_parts(delim.cast::<u8>(), delim_len + 1);
        match frankenlibc_core::string::str::strsep(s_slice, delim_slice) {
            Some((_start, next)) => {
                // Update *stringp to point past the delimiter.
                if next < s_len {
                    *stringp = s.add(next);
                } else {
                    *stringp = std::ptr::null_mut();
                }
                (s, s_len)
            }
            None => {
                *stringp = std::ptr::null_mut();
                (std::ptr::null_mut(), 0)
            }
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
        runtime_policy::scaled_cost(7, span),
        s_bound.is_some(),
    );
    result
}

// ---------------------------------------------------------------------------
// strlcpy
// ---------------------------------------------------------------------------

/// BSD `strlcpy` -- copies `src` into `dst` of size `dstsize`, always NUL-terminating.
///
/// Returns the length of `src` (not counting NUL).
///
/// # Safety
///
/// Caller must ensure `dst` is valid for `dstsize` bytes and `src` is NUL-terminated.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strlcpy(dst: *mut c_char, src: *const c_char, dstsize: usize) -> usize {
    let (aligned, recent_page, ordering) = stage_context_two(dst as usize, src as usize);
    if src.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return 0;
    }
    if dst.is_null() || dstsize == 0 {
        // Must still return strlen(src) even if dst is null/zero-sized.
        let src_bound = known_remaining(src as usize);
        let (src_len, _) = unsafe { scan_c_string(src, src_bound) };
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return src_len;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        dstsize,
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
            runtime_policy::scaled_cost(7, dstsize),
            true,
        );
        return 0;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let src_bound = if repair {
        known_remaining(src as usize)
    } else {
        None
    };

    // SAFETY: bounded scan.
    let (result, span) = unsafe {
        let (src_len, _) = scan_c_string(src, src_bound);
        let src_slice = std::slice::from_raw_parts(src.cast::<u8>(), src_len + 1);
        let dst_slice = std::slice::from_raw_parts_mut(dst.cast::<u8>(), dstsize);
        let r = frankenlibc_core::string::str::strlcpy(dst_slice, src_slice);
        (r, src_len.max(dstsize))
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
        runtime_policy::scaled_cost(7, span),
        src_bound.is_some(),
    );
    result
}

// ---------------------------------------------------------------------------
// strlcat
// ---------------------------------------------------------------------------

/// BSD `strlcat` -- appends `src` to `dst` of size `dstsize`, always NUL-terminating.
///
/// Returns the total length that would have resulted without truncation.
///
/// # Safety
///
/// Caller must ensure `dst` is valid for `dstsize` bytes and both are NUL-terminated.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strlcat(dst: *mut c_char, src: *const c_char, dstsize: usize) -> usize {
    let (aligned, recent_page, ordering) = stage_context_two(dst as usize, src as usize);
    if dst.is_null() || src.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return 0;
    }
    if dstsize == 0 {
        let src_bound = known_remaining(src as usize);
        let (src_len, _) = unsafe { scan_c_string(src, src_bound) };
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return dstsize + src_len;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        dstsize,
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
            runtime_policy::scaled_cost(7, dstsize),
            true,
        );
        return 0;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let src_bound = if repair {
        known_remaining(src as usize)
    } else {
        None
    };

    // SAFETY: bounded scan.
    let (result, span) = unsafe {
        let (src_len, _) = scan_c_string(src, src_bound);
        let src_slice = std::slice::from_raw_parts(src.cast::<u8>(), src_len + 1);
        let dst_slice = std::slice::from_raw_parts_mut(dst.cast::<u8>(), dstsize);
        let r = frankenlibc_core::string::str::strlcat(dst_slice, src_slice);
        (r, src_len + dstsize)
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
        runtime_policy::scaled_cost(7, span),
        src_bound.is_some(),
    );
    result
}

// ---------------------------------------------------------------------------
// strcoll
// ---------------------------------------------------------------------------

/// POSIX `strcoll` -- compares two strings using locale collation order.
///
/// In the C/POSIX locale, this is identical to `strcmp`.
///
/// # Safety
///
/// Caller must ensure both `s1` and `s2` are valid null-terminated strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strcoll(s1: *const c_char, s2: *const c_char) -> c_int {
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

    // SAFETY: bounded scan.
    let (result, span) = unsafe {
        let (s1_len, _) = scan_c_string(s1, lhs_bound);
        let (s2_len, _) = scan_c_string(s2, rhs_bound);
        let s1_slice = std::slice::from_raw_parts(s1.cast::<u8>(), s1_len + 1);
        let s2_slice = std::slice::from_raw_parts(s2.cast::<u8>(), s2_len + 1);
        let r = frankenlibc_core::string::str::strcoll(s1_slice, s2_slice);
        (r, s1_len.max(s2_len))
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
        runtime_policy::scaled_cost(7, span),
        lhs_bound.is_some() || rhs_bound.is_some(),
    );
    result
}

// ---------------------------------------------------------------------------
// strxfrm
// ---------------------------------------------------------------------------

/// POSIX `strxfrm` -- transforms `src` for locale-aware comparison into `dst`.
///
/// In C/POSIX locale, this is a plain copy. Returns the length needed
/// (not counting NUL).
///
/// # Safety
///
/// Caller must ensure `dst` is valid for `n` bytes and `src` is NUL-terminated.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strxfrm(dst: *mut c_char, src: *const c_char, n: usize) -> usize {
    let (aligned, recent_page, ordering) = stage_context_two(dst as usize, src as usize);
    if src.is_null() {
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
        dst as usize,
        n,
        true,
        known_remaining(src as usize).is_none(),
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
        return 0;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let src_bound = if repair {
        known_remaining(src as usize)
    } else {
        None
    };

    // SAFETY: bounded scan.
    let (result, span) = unsafe {
        let (src_len, _) = scan_c_string(src, src_bound);
        let src_slice = std::slice::from_raw_parts(src.cast::<u8>(), src_len + 1);
        if dst.is_null() || n == 0 {
            // Just return strlen(src).
            (src_len, src_len)
        } else {
            let dst_slice = std::slice::from_raw_parts_mut(dst.cast::<u8>(), n);
            let r = frankenlibc_core::string::str::strxfrm(dst_slice, src_slice, n);
            (r, src_len.max(n))
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
        runtime_policy::scaled_cost(7, span),
        src_bound.is_some(),
    );
    result
}

// ---------------------------------------------------------------------------
// index
// ---------------------------------------------------------------------------

/// BSD `index` -- equivalent to `strchr`.
///
/// # Safety
///
/// Caller must ensure `s` is a valid null-terminated string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn index(s: *const c_char, c: c_int) -> *mut c_char {
    // SAFETY: same contract as strchr.
    unsafe { strchr(s, c) }
}

// ---------------------------------------------------------------------------
// rindex
// ---------------------------------------------------------------------------

/// BSD `rindex` -- equivalent to `strrchr`.
///
/// # Safety
///
/// Caller must ensure `s` is a valid null-terminated string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rindex(s: *const c_char, c: c_int) -> *mut c_char {
    // SAFETY: same contract as strrchr.
    unsafe { strrchr(s, c) }
}

// ---------------------------------------------------------------------------
// regex — GlibcCallThrough (POSIX regex.h)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "regcomp"]
    fn libc_regcomp(preg: *mut c_void, pattern: *const c_char, cflags: c_int) -> c_int;
    #[link_name = "regexec"]
    fn libc_regexec(
        preg: *const c_void,
        string: *const c_char,
        nmatch: usize,
        pmatch: *mut c_void,
        eflags: c_int,
    ) -> c_int;
    #[link_name = "regfree"]
    fn libc_regfree(preg: *mut c_void);
    #[link_name = "regerror"]
    fn libc_regerror(
        errcode: c_int,
        preg: *const c_void,
        errbuf: *mut c_char,
        errbuf_size: usize,
    ) -> usize;
    #[link_name = "fnmatch"]
    fn libc_fnmatch(pattern: *const c_char, string: *const c_char, flags: c_int) -> c_int;
    #[link_name = "glob"]
    fn libc_glob(
        pattern: *const c_char,
        flags: c_int,
        errfunc: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
        pglob: *mut c_void,
    ) -> c_int;
    #[link_name = "globfree"]
    fn libc_globfree(pglob: *mut c_void);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn regcomp(
    preg: *mut c_void,
    pattern: *const c_char,
    cflags: c_int,
) -> c_int {
    unsafe { libc_regcomp(preg, pattern, cflags) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn regexec(
    preg: *const c_void,
    string: *const c_char,
    nmatch: usize,
    pmatch: *mut c_void,
    eflags: c_int,
) -> c_int {
    unsafe { libc_regexec(preg, string, nmatch, pmatch, eflags) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn regfree(preg: *mut c_void) {
    unsafe { libc_regfree(preg) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn regerror(
    errcode: c_int,
    preg: *const c_void,
    errbuf: *mut c_char,
    errbuf_size: usize,
) -> usize {
    unsafe { libc_regerror(errcode, preg, errbuf, errbuf_size) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fnmatch(
    pattern: *const c_char,
    string: *const c_char,
    flags: c_int,
) -> c_int {
    unsafe { libc_fnmatch(pattern, string, flags) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn glob(
    pattern: *const c_char,
    flags: c_int,
    errfunc: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
    pglob: *mut c_void,
) -> c_int {
    unsafe { libc_glob(pattern, flags, errfunc, pglob) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn globfree(pglob: *mut c_void) {
    unsafe { libc_globfree(pglob) }
}

// ---------------------------------------------------------------------------
// Signal/error description functions — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "strsignal"]
    fn libc_strsignal(sig: c_int) -> *mut c_char;
    #[link_name = "psignal"]
    fn libc_psignal(sig: c_int, s: *const c_char);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strsignal(sig: c_int) -> *mut c_char {
    unsafe { libc_strsignal(sig) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn psignal(sig: c_int, s: *const c_char) {
    unsafe { libc_psignal(sig, s) }
}
