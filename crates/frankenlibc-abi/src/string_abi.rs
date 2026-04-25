//! ABI layer for `<string.h>` functions.
//!
//! Each function is an `extern "C"` entry point that:
//! 1. Validates pointer arguments through the membrane pipeline
//! 2. In hardened mode, applies healing (bounds clamping, null truncation)
//! 3. Delegates to `frankenlibc-core` safe implementations or inline unsafe primitives

use std::cell::Cell;
use std::ffi::{CStr, c_char, c_int, c_long, c_longlong, c_ulong, c_ulonglong, c_void};
use std::sync::{
    Once,
    atomic::{AtomicU32, Ordering as AtomicOrdering},
};

use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::clifford::{
    SimdIsa, SimdStringOperation, certify_simd_string_operation,
};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::htm_fast_path::{HtmSite, HtmSiteSnapshot};
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use frankenlibc_core::syscall as raw_syscall;

thread_local! {
    static STRING_MEMBRANE_DEPTH: Cell<u32> = const { Cell::new(0) };
}

const MEMCPY_HTM_MAX_BYTES: usize = 256;
static MEMCPY_HTM_SITE: HtmSite = HtmSite::new("memcpy");
const SIMD_FEATURE_SSE42: u32 = 1 << 0;
const SIMD_FEATURE_AVX2: u32 = 1 << 1;
const SIMD_FEATURE_NEON: u32 = 1 << 2;
const SIMD_FEATURE_OVERRIDE_DISABLED: u32 = u32::MAX;
const SIMD_ISOMORPHISM_AUDIT_JSON: &str =
    include_str!(concat!(env!("OUT_DIR"), "/simd_isomorphism_audit.json"));

static STRING_SIMD_FEATURE_OVERRIDE: AtomicU32 = AtomicU32::new(SIMD_FEATURE_OVERRIDE_DISABLED);
static MEMCPY_SIMD_LOG_ONCE: Once = Once::new();
static MEMCMP_SIMD_LOG_ONCE: Once = Once::new();
static STRLEN_SIMD_LOG_ONCE: Once = Once::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StringSimdDispatch {
    isa: SimdIsa,
    label: &'static str,
    lane_bytes: usize,
}

impl StringSimdDispatch {
    const SCALAR: Self = Self {
        isa: SimdIsa::Scalar,
        label: "scalar",
        lane_bytes: 1,
    };

    const fn from_isa(isa: SimdIsa) -> Self {
        Self {
            isa,
            label: isa.label(),
            lane_bytes: isa.lane_bytes(),
        }
    }
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
        || frankenlibc_membrane::ptr_validator::in_validation_context()
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

fn active_string_simd_feature_mask() -> u32 {
    let override_mask = STRING_SIMD_FEATURE_OVERRIDE.load(AtomicOrdering::Relaxed);
    if override_mask != SIMD_FEATURE_OVERRIDE_DISABLED {
        return override_mask;
    }

    let mut mask = 0u32;
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("sse4.2") {
            mask |= SIMD_FEATURE_SSE42;
        }
        if std::is_x86_feature_detected!("avx2") {
            mask |= SIMD_FEATURE_AVX2;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            mask |= SIMD_FEATURE_NEON;
        }
    }
    mask
}

fn string_simd_feature_list(mask: u32) -> &'static str {
    match (
        mask & SIMD_FEATURE_AVX2 != 0,
        mask & SIMD_FEATURE_SSE42 != 0,
        mask & SIMD_FEATURE_NEON != 0,
    ) {
        (true, true, false) => "avx2,sse4.2",
        (true, false, false) => "avx2",
        (false, true, false) => "sse4.2",
        (false, false, true) => "neon",
        (true, false, true) => "avx2,neon",
        (false, true, true) => "sse4.2,neon",
        (true, true, true) => "avx2,sse4.2,neon",
        (false, false, false) => "scalar-only",
    }
}

fn log_string_simd_dispatch_once(function: &'static str, dispatch: StringSimdDispatch, mask: u32) {
    let once = match function {
        "memcpy" => &MEMCPY_SIMD_LOG_ONCE,
        "memcmp" => &MEMCMP_SIMD_LOG_ONCE,
        "strlen" => &STRLEN_SIMD_LOG_ONCE,
        _ => return,
    };
    once.call_once(|| {
        tracing::info!(
            target: "simd_dispatch",
            function,
            selected_impl = dispatch.label,
            cpu_features = string_simd_feature_list(mask),
            lane_bytes = dispatch.lane_bytes
        );
    });
}

fn dispatch_threshold(operation: SimdStringOperation, isa: SimdIsa) -> usize {
    match (operation, isa) {
        (_, SimdIsa::Scalar) => usize::MAX,
        (SimdStringOperation::Memcpy, SimdIsa::Avx2) => 128,
        (SimdStringOperation::Memcpy, SimdIsa::Sse42 | SimdIsa::Neon) => 32,
        (SimdStringOperation::Memcmp, SimdIsa::Avx2) => 64,
        (SimdStringOperation::Memcmp, SimdIsa::Sse42 | SimdIsa::Neon) => 16,
        (SimdStringOperation::Strlen, SimdIsa::Avx2) => 64,
        (SimdStringOperation::Strlen, SimdIsa::Sse42 | SimdIsa::Neon) => 16,
    }
}

fn regions_overlap(dst_addr: usize, src_addr: usize, len: usize) -> bool {
    if len == 0 {
        return false;
    }
    let dst_end = dst_addr.saturating_add(len);
    let src_end = src_addr.saturating_add(len);
    dst_addr < src_end && src_addr < dst_end
}

fn try_simd_dispatch_candidate(
    operation: SimdStringOperation,
    isa: SimdIsa,
    src_addr: usize,
    dst_addr: usize,
    len_hint: usize,
    overlap: bool,
) -> Option<StringSimdDispatch> {
    if len_hint < dispatch_threshold(operation, isa) {
        return None;
    }
    let certificate =
        certify_simd_string_operation(operation, isa, src_addr, dst_addr, len_hint, overlap);
    certificate
        .equivalent
        .then(|| StringSimdDispatch::from_isa(isa))
}

fn select_string_simd_dispatch(
    operation: SimdStringOperation,
    src_addr: usize,
    dst_addr: usize,
    len_hint: usize,
) -> StringSimdDispatch {
    let mask = active_string_simd_feature_mask();
    let overlap = matches!(operation, SimdStringOperation::Memcpy)
        && regions_overlap(dst_addr, src_addr, len_hint);

    let dispatch = if mask & SIMD_FEATURE_AVX2 != 0 {
        try_simd_dispatch_candidate(
            operation,
            SimdIsa::Avx2,
            src_addr,
            dst_addr,
            len_hint,
            overlap,
        )
    } else {
        None
    }
    .or_else(|| {
        if mask & SIMD_FEATURE_SSE42 != 0 {
            try_simd_dispatch_candidate(
                operation,
                SimdIsa::Sse42,
                src_addr,
                dst_addr,
                len_hint,
                overlap,
            )
        } else {
            None
        }
    })
    .or_else(|| {
        if mask & SIMD_FEATURE_NEON != 0 {
            try_simd_dispatch_candidate(
                operation,
                SimdIsa::Neon,
                src_addr,
                dst_addr,
                len_hint,
                overlap,
            )
        } else {
            None
        }
    })
    .unwrap_or(StringSimdDispatch::SCALAR);

    log_string_simd_dispatch_once(operation.symbol(), dispatch, mask);
    dispatch
}

#[doc(hidden)]
pub fn string_simd_swap_feature_mask_for_tests(mask: Option<u32>) -> u32 {
    STRING_SIMD_FEATURE_OVERRIDE.swap(
        mask.unwrap_or(SIMD_FEATURE_OVERRIDE_DISABLED),
        AtomicOrdering::SeqCst,
    )
}

#[doc(hidden)]
pub fn string_simd_restore_feature_mask_for_tests(previous: u32) {
    STRING_SIMD_FEATURE_OVERRIDE.store(previous, AtomicOrdering::SeqCst);
}

#[doc(hidden)]
pub const fn string_simd_feature_mask_sse42_for_tests() -> u32 {
    SIMD_FEATURE_SSE42
}

#[doc(hidden)]
pub const fn string_simd_feature_mask_avx2_for_tests() -> u32 {
    SIMD_FEATURE_AVX2
}

#[doc(hidden)]
pub const fn string_simd_feature_mask_neon_for_tests() -> u32 {
    SIMD_FEATURE_NEON
}

#[doc(hidden)]
pub const fn string_simd_feature_mask_avx2_sse42_for_tests() -> u32 {
    SIMD_FEATURE_AVX2 | SIMD_FEATURE_SSE42
}

#[doc(hidden)]
pub fn simd_isomorphism_audit_json_for_tests() -> &'static str {
    SIMD_ISOMORPHISM_AUDIT_JSON
}

#[doc(hidden)]
pub fn memcpy_dispatch_label_for_tests(dst_addr: usize, src_addr: usize, n: usize) -> &'static str {
    select_string_simd_dispatch(SimdStringOperation::Memcpy, src_addr, dst_addr, n).label
}

#[doc(hidden)]
pub fn memcmp_dispatch_label_for_tests(s1_addr: usize, s2_addr: usize, n: usize) -> &'static str {
    select_string_simd_dispatch(SimdStringOperation::Memcmp, s1_addr, s2_addr, n).label
}

#[doc(hidden)]
pub fn strlen_dispatch_label_for_tests(s_addr: usize, len_hint: usize) -> &'static str {
    select_string_simd_dispatch(SimdStringOperation::Strlen, s_addr, s_addr, len_hint).label
}

#[inline(never)]
unsafe fn raw_memcpy_bytes(dst: *mut u8, src: *const u8, n: usize) {
    // Byte-by-byte copy using volatile operations to prevent the compiler
    // from optimizing this into a memcpy call (which would recurse through
    // our interposed memcpy symbol).  Also avoids dlvsym during init.
    // SAFETY: caller guarantees dst/src are valid for n bytes.
    unsafe {
        let mut i = 0usize;
        while i < n {
            std::ptr::write_volatile(dst.add(i), std::ptr::read_volatile(src.add(i)));
            i += 1;
        }
    }
}

#[inline(never)]
unsafe fn raw_dispatch_memcpy_bytes(dst: *mut u8, src: *const u8, n: usize) {
    let dispatch =
        select_string_simd_dispatch(SimdStringOperation::Memcpy, src as usize, dst as usize, n);
    // SAFETY: caller guarantees memcpy preconditions for `n` bytes.
    unsafe {
        if dispatch.lane_bytes > 1 {
            raw_lane_memcpy_bytes(dst, src, n, dispatch.lane_bytes);
        } else {
            raw_memcpy_bytes(dst, src, n);
        }
    }
}

#[inline(never)]
unsafe fn raw_memmove_bytes(dst: *mut u8, src: *const u8, n: usize) {
    // Byte-by-byte move using volatile operations with overlap awareness.
    // Cannot use std::ptr::copy (compiles to memmove → our interposed symbol).
    // SAFETY: caller guarantees dst/src are valid for n bytes (may overlap).
    unsafe {
        let dst_addr = dst as usize;
        let src_addr = src as usize;
        if dst_addr <= src_addr || dst_addr >= src_addr.saturating_add(n) {
            // Non-overlapping or dst < src: forward copy
            let mut i = 0usize;
            while i < n {
                std::ptr::write_volatile(dst.add(i), std::ptr::read_volatile(src.add(i)));
                i += 1;
            }
        } else {
            // Overlapping with dst > src: backward copy
            let mut i = n;
            while i > 0 {
                i -= 1;
                std::ptr::write_volatile(dst.add(i), std::ptr::read_volatile(src.add(i)));
            }
        }
    }
}

/// Raw strstr without membrane validation. Used during early startup and
/// when called from within the membrane/allocator to prevent re-entrant deadlock.
unsafe fn raw_strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char {
    if haystack.is_null() {
        return std::ptr::null_mut();
    }
    if needle.is_null() {
        return haystack as *mut c_char;
    }
    // SAFETY: both pointers are valid NUL-terminated strings.
    unsafe {
        let needle_first = *needle;
        if needle_first == 0 {
            return haystack as *mut c_char;
        }
        let mut h = haystack;
        while *h != 0 {
            if *h == needle_first {
                let mut hi = h;
                let mut ni = needle;
                loop {
                    ni = ni.add(1);
                    if *ni == 0 {
                        return h as *mut c_char; // found
                    }
                    hi = hi.add(1);
                    if *hi == 0 || *hi != *ni {
                        break;
                    }
                }
            }
            h = h.add(1);
        }
        std::ptr::null_mut()
    }
}

#[inline(never)]
unsafe fn raw_memset_bytes(dst: *mut u8, value: u8, n: usize) {
    // Byte-by-byte fill using volatile writes to prevent the compiler
    // from optimizing this into a memset call (which would recurse through
    // our interposed memset symbol).
    // SAFETY: caller guarantees dst is valid for n bytes.
    unsafe {
        let mut i = 0usize;
        while i < n {
            std::ptr::write_volatile(dst.add(i), value);
            i += 1;
        }
    }
}

#[inline]
unsafe fn copy_unaligned_16(dst: *mut u8, src: *const u8) {
    // SAFETY: caller guarantees 16 readable/writable bytes.
    unsafe {
        let lane = std::ptr::read_unaligned(src.cast::<u128>());
        std::ptr::write_unaligned(dst.cast::<u128>(), lane);
    }
}

#[inline]
unsafe fn copy_unaligned_32(dst: *mut u8, src: *const u8) {
    // SAFETY: caller guarantees 32 readable/writable bytes.
    unsafe {
        copy_unaligned_16(dst, src);
        copy_unaligned_16(dst.add(16), src.add(16));
    }
}

#[inline(never)]
unsafe fn raw_lane_memcpy_bytes(dst: *mut u8, src: *const u8, n: usize, lane_bytes: usize) {
    // SAFETY: caller guarantees dst/src are valid for n bytes with memcpy semantics.
    unsafe {
        let mut i = 0usize;
        if lane_bytes >= 32 {
            while i + 32 <= n {
                copy_unaligned_32(dst.add(i), src.add(i));
                i += 32;
            }
        }
        if lane_bytes >= 16 {
            while i + 16 <= n {
                copy_unaligned_16(dst.add(i), src.add(i));
                i += 16;
            }
        }
        while i < n {
            std::ptr::write_volatile(dst.add(i), std::ptr::read_volatile(src.add(i)));
            i += 1;
        }
    }
}

#[inline]
unsafe fn chunk_equal_16(lhs: *const u8, rhs: *const u8) -> bool {
    // SAFETY: caller guarantees 16 readable bytes from each pointer.
    unsafe {
        std::ptr::read_unaligned(lhs.cast::<u128>()) == std::ptr::read_unaligned(rhs.cast::<u128>())
    }
}

#[inline]
unsafe fn chunk_equal_32(lhs: *const u8, rhs: *const u8) -> bool {
    // SAFETY: caller guarantees 32 readable bytes from each pointer.
    unsafe { chunk_equal_16(lhs, rhs) && chunk_equal_16(lhs.add(16), rhs.add(16)) }
}

#[inline(never)]
unsafe fn raw_lane_memcmp_bytes(
    s1: *const u8,
    s2: *const u8,
    n: usize,
    lane_bytes: usize,
) -> c_int {
    // SAFETY: caller guarantees both regions are readable for n bytes.
    unsafe {
        let mut i = 0usize;
        if lane_bytes >= 32 {
            while i + 32 <= n {
                if !chunk_equal_32(s1.add(i), s2.add(i)) {
                    let end = i + 32;
                    while i < end {
                        let av = *s1.add(i);
                        let bv = *s2.add(i);
                        if av != bv {
                            return if av < bv { -1 } else { 1 };
                        }
                        i += 1;
                    }
                } else {
                    i += 32;
                }
            }
        }
        if lane_bytes >= 16 {
            while i + 16 <= n {
                if !chunk_equal_16(s1.add(i), s2.add(i)) {
                    let end = i + 16;
                    while i < end {
                        let av = *s1.add(i);
                        let bv = *s2.add(i);
                        if av != bv {
                            return if av < bv { -1 } else { 1 };
                        }
                        i += 1;
                    }
                } else {
                    i += 16;
                }
            }
        }
        while i < n {
            let av = *s1.add(i);
            let bv = *s2.add(i);
            if av != bv {
                return if av < bv { -1 } else { 1 };
            }
            i += 1;
        }
        0
    }
}

#[inline(never)]
unsafe fn raw_dispatch_memcmp_bytes(s1: *const u8, s2: *const u8, n: usize) -> c_int {
    let dispatch =
        select_string_simd_dispatch(SimdStringOperation::Memcmp, s1 as usize, s2 as usize, n);
    // SAFETY: caller guarantees both regions are readable for `n` bytes.
    unsafe {
        if dispatch.lane_bytes > 1 {
            raw_lane_memcmp_bytes(s1, s2, n, dispatch.lane_bytes)
        } else {
            let lhs = std::slice::from_raw_parts(s1, n);
            let rhs = std::slice::from_raw_parts(s2, n);
            match frankenlibc_core::string::mem::memcmp(lhs, rhs, n) {
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Greater => 1,
            }
        }
    }
}

#[inline(never)]
unsafe fn raw_lane_strlen_bytes(s: *const c_char, lane_bytes: usize) -> usize {
    let step = lane_bytes.max(1);
    // SAFETY: caller guarantees a valid NUL-terminated string.
    unsafe {
        let mut len = 0usize;
        loop {
            let end = len + step;
            let mut idx = len;
            while idx < end {
                if *s.add(idx) == 0 {
                    return idx;
                }
                idx += 1;
            }
            len = end;
        }
    }
}

#[inline(never)]
unsafe fn raw_lane_strnlen_bytes(s: *const c_char, max: usize, lane_bytes: usize) -> (usize, bool) {
    let step = lane_bytes.max(1);
    // SAFETY: caller guarantees `s` readable up to `max`.
    unsafe {
        let mut len = 0usize;
        while len < max {
            let end = (len + step).min(max);
            let mut idx = len;
            while idx < end {
                if *s.add(idx) == 0 {
                    return (idx, true);
                }
                idx += 1;
            }
            len = end;
        }
        (max, false)
    }
}

fn try_memcpy_htm(dst: *mut u8, src: *const u8, n: usize) -> bool {
    if n > MEMCPY_HTM_MAX_BYTES {
        return false;
    }

    matches!(
        MEMCPY_HTM_SITE.run(|| {
            // SAFETY: callers only invoke the HTM helper after validating the
            // same preconditions as the raw memcpy fallback.
            unsafe { raw_memcpy_bytes(dst, src, n) };
        }),
        Ok(())
    )
}

#[doc(hidden)]
pub fn memcpy_htm_reset_for_tests() {
    MEMCPY_HTM_SITE.reset_for_tests();
}

#[doc(hidden)]
#[must_use]
pub fn memcpy_htm_snapshot_for_tests() -> HtmSiteSnapshot {
    MEMCPY_HTM_SITE.snapshot()
}

#[doc(hidden)]
pub fn signal_runtime_ready_for_tests() {
    runtime_policy::signal_runtime_ready();
}

#[doc(hidden)]
pub fn take_last_decision_gate_for_tests() -> Option<&'static str> {
    runtime_policy::take_last_explainability().map(|explain| explain.decision_gate)
}

fn maybe_clamp_copy_len(
    requested: usize,
    src_remaining: Option<usize>,
    dst_remaining: Option<usize>,
    enable_repair: bool,
) -> (usize, bool) {
    if !enable_repair || requested == 0 {
        return (requested, false);
    }

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

#[inline]
fn clamp_destination_size_for_repair(
    requested: usize,
    dst_remaining: Option<usize>,
    repair: bool,
) -> (usize, bool) {
    if !repair {
        return (requested, false);
    }
    match dst_remaining {
        Some(bound) if bound < requested => (bound, true),
        _ => (requested, false),
    }
}

#[doc(hidden)]
pub fn clamp_destination_size_for_tests(
    requested: usize,
    dst_remaining: Option<usize>,
    repair: bool,
) -> (usize, bool) {
    clamp_destination_size_for_repair(requested, dst_remaining, repair)
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
    let recent_page = addr != 0 && crate::malloc_abi::check_ownership(addr);
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);
    (aligned, recent_page, ordering)
}

#[inline]
fn stage_context_two(addr1: usize, addr2: usize) -> (bool, bool, [CheckStage; 7]) {
    let aligned = ((addr1 | addr2) & 0x7) == 0;
    let recent_page = (addr1 != 0 && crate::malloc_abi::check_ownership(addr1))
        || (addr2 != 0 && crate::malloc_abi::check_ownership(addr2));
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
    if n == 0 {
        return dst;
    }
    if dst.is_null() || src.is_null() {
        return std::ptr::null_mut();
    }
    let _trace_scope = runtime_policy::entrypoint_scope("memcpy");

    // Fast path during early startup: skip membrane entirely.
    if runtime_policy::bootstrap_passthrough_active() {
        if !(crate::htm_fast_path::htm_forced_mode_active_for_tests()
            && try_memcpy_htm(dst.cast::<u8>(), src.cast::<u8>(), n))
        {
            unsafe { raw_dispatch_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), n) };
        }
        return dst;
    }
    if !runtime_policy::mode().heals_enabled() {
        if runtime_policy::proof_carried_fast_path_active(ApiFamily::StringMemory, n, true, true) {
            let (_, decision) =
                runtime_policy::decide(ApiFamily::StringMemory, dst as usize, n, true, true, 0);
            if !try_memcpy_htm(dst.cast::<u8>(), src.cast::<u8>(), n) {
                unsafe { raw_dispatch_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), n) };
            }
            runtime_policy::observe(
                ApiFamily::StringMemory,
                decision.profile,
                runtime_policy::scaled_cost(7, n),
                false,
            );
            return dst;
        }
        if !try_memcpy_htm(dst.cast::<u8>(), src.cast::<u8>(), n) {
            unsafe { raw_dispatch_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), n) };
        }
        return dst;
    }

    let Some(_membrane_guard) = enter_string_membrane_guard() else {
        // SAFETY: reentrant fallback avoids runtime-policy recursion and mirrors memcpy semantics.
        unsafe {
            raw_dispatch_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), n);
        }
        return dst;
    };

    let dst_rem = known_remaining(dst as usize);
    let src_rem = known_remaining(src as usize);
    let aligned = ((dst as usize) | (src as usize)) & 0x7 == 0;
    let recent_page = dst_rem.is_some() || src_rem.is_some();
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        n,
        true,
        dst_rem.is_none() && src_rem.is_none(),
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
        src_rem,
        dst_rem,
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
    if !try_memcpy_htm(dst.cast::<u8>(), src.cast::<u8>(), copy_len) {
        unsafe {
            raw_dispatch_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), copy_len);
        }
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
    if n == 0 {
        return dst;
    }
    if dst.is_null() || src.is_null() {
        return std::ptr::null_mut();
    }

    // Fast path during early startup: skip membrane entirely.
    if runtime_policy::bootstrap_passthrough_active() {
        unsafe { raw_memmove_bytes(dst.cast::<u8>(), src.cast::<u8>(), n) };
        return dst;
    }

    let Some(_membrane_guard) = enter_string_membrane_guard() else {
        // SAFETY: reentrant fallback avoids runtime-policy recursion and mirrors memmove semantics.
        unsafe {
            raw_memmove_bytes(dst.cast::<u8>(), src.cast::<u8>(), n);
        }
        return dst;
    };

    let dst_rem = known_remaining(dst as usize);
    let src_rem = known_remaining(src as usize);
    let aligned = ((dst as usize) | (src as usize)) & 0x7 == 0;
    let recent_page = dst_rem.is_some() || src_rem.is_some();
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        n,
        true,
        dst_rem.is_none() && src_rem.is_none(),
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
        src_rem,
        dst_rem,
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
    if n == 0 {
        return dst;
    }
    if dst.is_null() {
        return std::ptr::null_mut();
    }

    // Fast path during early startup: skip membrane entirely.
    if runtime_policy::bootstrap_passthrough_active() {
        unsafe { raw_memset_bytes(dst.cast::<u8>(), c as u8, n) };
        return dst;
    }

    let Some(_membrane_guard) = enter_string_membrane_guard() else {
        // SAFETY: reentrant fallback avoids runtime-policy recursion and mirrors memset semantics.
        unsafe {
            raw_memset_bytes(dst.cast::<u8>(), c as u8, n);
        }
        return dst;
    };

    let dst_rem = known_remaining(dst as usize);
    let aligned = (dst as usize) & 0x7 == 0;
    let recent_page = dst_rem.is_some();
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        n,
        true,
        dst_rem.is_none(),
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
        dst_rem,
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
    let _trace_scope = runtime_policy::entrypoint_scope("memcmp");
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
        known_remaining(s1 as usize),
        known_remaining(s2 as usize),
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
    let out = unsafe { raw_dispatch_memcmp_bytes(s1.cast::<u8>(), s2.cast::<u8>(), cmp_len) };
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
        known_remaining(s as usize),
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
        known_remaining(s as usize),
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
    if s.is_null() {
        return 0;
    }
    let _trace_scope = runtime_policy::entrypoint_scope("strlen");

    // Fast path during early startup: skip membrane validation entirely.
    // The membrane's ValidationPipeline uses PageOracle (RwLock) and TLS,
    // which deadlock during init when called from dlvsym → strlen chains.
    if runtime_policy::bootstrap_passthrough_active() {
        unsafe {
            let mut len = 0usize;
            while *s.add(len) != 0 {
                len += 1;
            }
            return len;
        }
    }
    if !runtime_policy::mode().heals_enabled() {
        let dispatch =
            select_string_simd_dispatch(SimdStringOperation::Strlen, s as usize, s as usize, 64);
        return unsafe { raw_lane_strlen_bytes(s, dispatch.lane_bytes) };
    }

    let rem = known_remaining(s as usize);
    let aligned = (s as usize) & 0x7 == 0;
    let recent_page = rem.is_some();
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        0,
        false,
        rem.is_none(),
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
        && let Some(limit) = rem
    {
        let dispatch = select_string_simd_dispatch(
            SimdStringOperation::Strlen,
            s as usize,
            s as usize,
            limit.max(1),
        );
        // SAFETY: bounded scan within known allocation extent.
        let (len, terminated) = unsafe { raw_lane_strnlen_bytes(s, limit, dispatch.lane_bytes) };
        if terminated {
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
            return len;
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
    let dispatch =
        select_string_simd_dispatch(SimdStringOperation::Strlen, s as usize, s as usize, 64);
    unsafe {
        let len = raw_lane_strlen_bytes(s, dispatch.lane_bytes);
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
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
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
        (Some(a), None) => a.min(n),
        (None, Some(b)) => b.min(n),
        (None, None) => n,
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
        known_remaining(src as usize),
        known_remaining(dst as usize),
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
    // By measuring `dst` instead of `src`, we automatically respect any
    // bounds clamping that `strncpy` applied in hardened mode.
    let offset = unsafe { strnlen(dst, n) };
    // SAFETY: offset is bounded by `n` (and clamped membrane bounds).
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
                        let hit_src_alloc_bound =
                            !src_terminated && src_bound.is_some_and(|b| b < n && src_len == b);
                        let truncated = hit_src_alloc_bound || copy_payload < src_len;
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
                    let hit_src_alloc_bound =
                        !src_terminated && src_bound.is_some_and(|b| b < n && src_len == b);
                    let truncated = hit_src_alloc_bound;
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
    // Fast path: skip membrane during early startup or when called from
    // within the membrane/allocator (prevents re-entrant deadlock).
    if runtime_policy::bootstrap_passthrough_active() {
        return unsafe { raw_strstr(haystack, needle) };
    }

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
        let (s1_len, s1_term) = scan_c_string(s1, lhs_bound);
        let (s2_len, s2_term) = scan_c_string(s2, rhs_bound);
        let s1_slice_len = if s1_term { s1_len + 1 } else { s1_len };
        let s2_slice_len = if s2_term { s2_len + 1 } else { s2_len };
        let s1_slice = std::slice::from_raw_parts(s1.cast::<u8>(), s1_slice_len);
        let s2_slice = std::slice::from_raw_parts(s2.cast::<u8>(), s2_slice_len);
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
        (Some(a), None) => a.min(n),
        (None, Some(b)) => b.min(n),
        (None, None) => n,
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
        let (s_len, s_terminated) = scan_c_string(s, s_bound);
        let (accept_len, accept_terminated) = scan_c_string(accept, accept_bound);
        let s_slice_len = if s_terminated { s_len + 1 } else { s_len };
        let accept_slice_len = if accept_terminated {
            accept_len + 1
        } else {
            accept_len
        };
        let s_slice = std::slice::from_raw_parts(s.cast::<u8>(), s_slice_len);
        let accept_slice = std::slice::from_raw_parts(accept.cast::<u8>(), accept_slice_len);
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
        let (s_len, s_terminated) = scan_c_string(s, s_bound);
        let (reject_len, reject_terminated) = scan_c_string(reject, reject_bound);
        let s_slice_len = if s_terminated { s_len + 1 } else { s_len };
        let reject_slice_len = if reject_terminated {
            reject_len + 1
        } else {
            reject_len
        };
        let s_slice = std::slice::from_raw_parts(s.cast::<u8>(), s_slice_len);
        let reject_slice = std::slice::from_raw_parts(reject.cast::<u8>(), reject_slice_len);
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
        let (s_len, s_terminated) = scan_c_string(s, s_bound);
        let (accept_len, accept_terminated) = scan_c_string(accept, accept_bound);
        let s_slice_len = if s_terminated { s_len + 1 } else { s_len };
        let accept_slice_len = if accept_terminated {
            accept_len + 1
        } else {
            accept_len
        };
        let s_slice = std::slice::from_raw_parts(s.cast::<u8>(), s_slice_len);
        let accept_slice = std::slice::from_raw_parts(accept.cast::<u8>(), accept_slice_len);
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

    // SAFETY: scan string, allocate via libc::malloc, copy.
    //
    // Note: we use libc::malloc (not raw_alloc) so the alloc/free pair is
    // consistent with the caller's libc::free. raw_alloc routes through
    // native_libc_malloc which, under NATIVE_MALLOC_REENTRY contention,
    // falls back to the static BUMP_HEAP arena — returning pointers that
    // glibc's free cannot validate, aborting with "free(): invalid size".
    // Under LD_PRELOAD libc::malloc is our own interposed symbol (so
    // identical machinery); in debug test builds libc::malloc is glibc's
    // malloc (so pairs with glibc's libc::free). Either way, no
    // cross-allocator free.  bd-zgifl / bd-dqqh1 cluster.
    unsafe {
        let (s_len, _) = scan_c_string(s, bound);
        let alloc_size = s_len + 1;

        let dst = libc::malloc(alloc_size);
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

    // SAFETY: scan string up to n, allocate via libc::malloc (see strdup
    // comment on bd-zgifl for why not raw_alloc), copy.
    unsafe {
        let (s_len, _) = scan_c_string(s, bound);
        let copy_len = s_len.min(n);
        let alloc_size = copy_len + 1;

        let dst = libc::malloc(alloc_size);
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
        known_remaining(haystack as usize),
        None,
        repair_enabled(mode.heals_enabled(), decision.action),
    );
    let (needle_scan, _clamped_n) = maybe_clamp_copy_len(
        needle_len,
        known_remaining(needle as usize),
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
        known_remaining(src as usize),
        known_remaining(dst as usize),
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
        let (hay_len, hay_terminated) = scan_c_string(haystack, hay_bound);
        let (needle_len, needle_terminated) = scan_c_string(needle, needle_bound);
        let h_slice_len = if hay_terminated { hay_len + 1 } else { hay_len };
        let n_slice_len = if needle_terminated {
            needle_len + 1
        } else {
            needle_len
        };
        let h_slice = std::slice::from_raw_parts(haystack.cast::<u8>(), h_slice_len);
        let n_slice = std::slice::from_raw_parts(needle.cast::<u8>(), n_slice_len);
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
        known_remaining(src as usize),
        known_remaining(dst as usize),
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
        known_remaining(s as usize),
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
        known_remaining(src as usize),
        known_remaining(dst as usize),
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
        let (s_len, s_term) = scan_c_string(s, s_bound);
        let (delim_len, delim_term) = scan_c_string(delim, delim_bound);
        let s_slice_len = if s_term { s_len + 1 } else { s_len };
        let delim_slice_len = if delim_term { delim_len + 1 } else { delim_len };
        let s_slice = std::slice::from_raw_parts_mut(s.cast::<u8>(), s_slice_len);
        let delim_slice = std::slice::from_raw_parts(delim.cast::<u8>(), delim_slice_len);
        match frankenlibc_core::string::str::strsep(s_slice, delim_slice) {
            Some(idx) => {
                // Update *stringp to point past the delimiter.
                *stringp = s.add(idx + 1);
                (s, s_len)
            }
            None => {
                *stringp = std::ptr::null_mut();
                // Return the remaining string as the last token.
                (s, s_len)
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
    let dst_bound = if repair {
        known_remaining(dst as usize)
    } else {
        None
    };
    let (dst_limit, dst_clamped) = clamp_destination_size_for_repair(dstsize, dst_bound, repair);
    if dst_clamped {
        record_truncation(dstsize, dst_limit);
    }

    // SAFETY: bounded scan.
    let (result, span) = unsafe {
        let (src_len, src_terminated) = scan_c_string(src, src_bound);
        let src_slice_len = if src_terminated { src_len + 1 } else { src_len };
        let src_slice = std::slice::from_raw_parts(src.cast::<u8>(), src_slice_len);
        let dst_slice = std::slice::from_raw_parts_mut(dst.cast::<u8>(), dst_limit);
        let r = frankenlibc_core::string::str::strlcpy(dst_slice, src_slice);
        (r, src_len.max(dst_limit))
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
        src_bound.is_some() || dst_clamped,
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
    let dst_bound = if repair {
        known_remaining(dst as usize)
    } else {
        None
    };
    let (dst_limit, dst_clamped) = clamp_destination_size_for_repair(dstsize, dst_bound, repair);
    if dst_clamped {
        record_truncation(dstsize, dst_limit);
    }

    // SAFETY: bounded scan.
    let (result, span) = unsafe {
        let (src_len, src_terminated) = scan_c_string(src, src_bound);
        let src_slice_len = if src_terminated { src_len + 1 } else { src_len };
        let src_slice = std::slice::from_raw_parts(src.cast::<u8>(), src_slice_len);
        let dst_slice = std::slice::from_raw_parts_mut(dst.cast::<u8>(), dst_limit);
        let r = frankenlibc_core::string::str::strlcat(dst_slice, src_slice);
        (r, src_len + dst_limit)
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
        src_bound.is_some() || dst_clamped,
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
        let (s1_len, s1_terminated) = scan_c_string(s1, lhs_bound);
        let (s2_len, s2_terminated) = scan_c_string(s2, rhs_bound);
        let s1_slice_len = if s1_terminated { s1_len + 1 } else { s1_len };
        let s2_slice_len = if s2_terminated { s2_len + 1 } else { s2_len };
        let s1_slice = std::slice::from_raw_parts(s1.cast::<u8>(), s1_slice_len);
        let s2_slice = std::slice::from_raw_parts(s2.cast::<u8>(), s2_slice_len);
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
        let (src_len, src_terminated) = scan_c_string(src, src_bound);
        let src_slice_len = if src_terminated { src_len + 1 } else { src_len };
        let src_slice = std::slice::from_raw_parts(src.cast::<u8>(), src_slice_len);
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
// regex — Implemented (native POSIX regex.h via frankenlibc-core)
// ---------------------------------------------------------------------------

// glob/globfree — Implemented (native POSIX glob via frankenlibc-core)

/// Magic value to identify our regex_t vs a glibc-compiled one.
const FRANKEN_REGEX_MAGIC: u64 = 0x4652_4B4E_5245_4758; // "FRKNREGX"

const RE_BK_PLUS_QM: u64 = 1 << 1;
const RE_LIMITED_OPS: u64 = 1 << 10;
const RE_NO_BK_BRACES: u64 = 1 << 12;
const RE_NO_BK_PARENS: u64 = 1 << 13;
const RE_NO_BK_VBAR: u64 = 1 << 15;
const RE_ICASE: u64 = 1 << 22;
const RE_NO_SUB: u64 = 1 << 25;
const REGS_ALLOCATED_SHIFT: u8 = 1;
const REGS_ALLOCATED_MASK: u8 = 0b11 << REGS_ALLOCATED_SHIFT;
const REGS_UNALLOCATED: u8 = 0;
const REGS_FIXED: u8 = 2;
const REGEX_FLAG_FASTMAP_ACCURATE: u8 = 1 << 3;
const REGEX_FLAG_NO_SUB: u8 = 1 << 4;

#[repr(C)]
struct RegexHandle {
    magic: u64,
    compiled: *mut frankenlibc_core::string::regex::CompiledRegex,
}

#[repr(C)]
struct RegexBufferLayout {
    buffer: *mut c_void,
    allocated: libc::c_long,
    used: libc::c_long,
    syntax: u64,
    fastmap: *mut c_char,
    translate: *mut u8,
    re_nsub: usize,
    flags: u8,
    reserved: [u8; 7],
}

#[repr(C)]
struct LegacyReRegisters {
    num_regs: usize,
    start: *mut c_int,
    end: *mut c_int,
}

fn legacy_regex_syntax_to_cflags(syntax: u64) -> c_int {
    use frankenlibc_core::string::regex;

    let mut cflags = 0;
    let uses_extended_syntax = syntax & (RE_NO_BK_BRACES | RE_NO_BK_PARENS | RE_NO_BK_VBAR) != 0
        && syntax & RE_BK_PLUS_QM == 0
        && syntax & RE_LIMITED_OPS == 0;
    if uses_extended_syntax {
        cflags |= regex::REG_EXTENDED;
    }
    if syntax & RE_ICASE != 0 {
        cflags |= regex::REG_ICASE;
    }
    if syntax & RE_NO_SUB != 0 {
        cflags |= regex::REG_NOSUB;
    }
    cflags
}

unsafe fn regex_buffer_layout(buffer: *mut c_void) -> Option<&'static mut RegexBufferLayout> {
    if buffer.is_null() {
        return None;
    }
    Some(unsafe { &mut *(buffer as *mut RegexBufferLayout) })
}

unsafe fn regex_compiled_from_buffer(
    buffer: *const c_void,
) -> Option<&'static frankenlibc_core::string::regex::CompiledRegex> {
    if buffer.is_null() {
        return None;
    }
    let layout = unsafe { &*(buffer as *const RegexBufferLayout) };
    let handle = layout.buffer as *const RegexHandle;
    if handle.is_null() {
        return None;
    }
    let handle = unsafe { &*handle };
    if handle.magic != FRANKEN_REGEX_MAGIC || handle.compiled.is_null() {
        return None;
    }
    Some(unsafe { &*handle.compiled })
}

unsafe fn regex_release_buffer(layout: &mut RegexBufferLayout) {
    let handle_ptr = layout.buffer as *mut RegexHandle;
    if !handle_ptr.is_null() {
        // SAFETY: handle_ptr was allocated via Box::into_raw in regcomp/re_compile_pattern.
        let handle = unsafe { Box::from_raw(handle_ptr) };
        if !handle.compiled.is_null() {
            // SAFETY: compiled was allocated via Box::into_raw during compilation.
            let _ = unsafe { Box::from_raw(handle.compiled) };
        }
    }

    layout.buffer = core::ptr::null_mut();
    layout.allocated = 0;
    layout.used = 0;
    layout.syntax = 0;
    layout.fastmap = core::ptr::null_mut();
    layout.translate = core::ptr::null_mut();
    layout.re_nsub = 0;
    layout.flags = 0;
    layout.reserved = [0; 7];
}

fn regex_set_regs_allocated(flags: &mut u8, value: u8) {
    *flags =
        (*flags & !REGS_ALLOCATED_MASK) | ((value << REGS_ALLOCATED_SHIFT) & REGS_ALLOCATED_MASK);
}

fn legacy_regex_concat(
    string1: *const c_char,
    size1: c_int,
    string2: *const c_char,
    size2: c_int,
) -> Result<Vec<u8>, c_int> {
    if size1 < 0 || size2 < 0 {
        return Err(-2);
    }

    let size1 = size1 as usize;
    let size2 = size2 as usize;
    if size1 > 0 && string1.is_null() {
        return Err(-2);
    }
    if size2 > 0 && string2.is_null() {
        return Err(-2);
    }

    let mut haystack = Vec::with_capacity(size1 + size2);
    if size1 > 0 {
        // SAFETY: validated non-null above, length provided by caller contract.
        haystack
            .extend_from_slice(unsafe { core::slice::from_raw_parts(string1 as *const u8, size1) });
    }
    if size2 > 0 {
        // SAFETY: validated non-null above, length provided by caller contract.
        haystack
            .extend_from_slice(unsafe { core::slice::from_raw_parts(string2 as *const u8, size2) });
    }
    Ok(haystack)
}

unsafe fn legacy_regex_write_regs(
    regs: *mut c_void,
    matches: &[frankenlibc_core::string::regex::RegMatch],
    offset: c_int,
) {
    if regs.is_null() {
        return;
    }

    let regs = unsafe { &mut *(regs as *mut LegacyReRegisters) };
    let needed = matches.len().max(2);
    if regs.num_regs == 0 || regs.start.is_null() || regs.end.is_null() {
        // SAFETY: ABI calloc returns suitably aligned zeroed storage for c_int arrays.
        let starts = unsafe { crate::malloc_abi::calloc(needed, core::mem::size_of::<c_int>()) }
            as *mut c_int;
        // SAFETY: ABI calloc returns suitably aligned zeroed storage for c_int arrays.
        let ends = unsafe { crate::malloc_abi::calloc(needed, core::mem::size_of::<c_int>()) }
            as *mut c_int;
        if starts.is_null() || ends.is_null() {
            if !starts.is_null() {
                unsafe { crate::malloc_abi::free(starts.cast()) };
            }
            if !ends.is_null() {
                unsafe { crate::malloc_abi::free(ends.cast()) };
            }
            return;
        }
        regs.num_regs = needed;
        regs.start = starts;
        regs.end = ends;
    }

    for idx in 0..regs.num_regs {
        unsafe {
            *regs.start.add(idx) = -1;
            *regs.end.add(idx) = -1;
        }
    }

    for (idx, m) in matches.iter().enumerate().take(regs.num_regs) {
        if m.rm_so >= 0 {
            unsafe { *regs.start.add(idx) = offset.saturating_add(m.rm_so) };
        }
        if m.rm_eo >= 0 {
            unsafe { *regs.end.add(idx) = offset.saturating_add(m.rm_eo) };
        }
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn regcomp(
    preg: *mut c_void,
    pattern: *const c_char,
    cflags: c_int,
) -> c_int {
    use frankenlibc_core::string::regex;

    if preg.is_null() || pattern.is_null() {
        return regex::REG_BADPAT;
    }

    let Some(layout) = (unsafe { regex_buffer_layout(preg) }) else {
        return regex::REG_BADPAT;
    };
    unsafe { regex_release_buffer(layout) };

    // Read pattern as byte slice
    let pat = unsafe { std::ffi::CStr::from_ptr(pattern) };
    let pat_bytes = pat.to_bytes_with_nul();

    match regex::regex_compile(pat_bytes, cflags) {
        Ok(compiled) => {
            let re_nsub = compiled.num_regs().saturating_sub(1);
            let raw_ptr = Box::into_raw(compiled);
            let handle = Box::new(RegexHandle {
                magic: FRANKEN_REGEX_MAGIC,
                compiled: raw_ptr,
            });

            layout.buffer = Box::into_raw(handle).cast();
            layout.allocated = core::mem::size_of::<RegexHandle>() as libc::c_long;
            layout.used = layout.allocated;
            layout.syntax = if cflags & regex::REG_EXTENDED != 0 {
                RE_NO_BK_BRACES | RE_NO_BK_PARENS | RE_NO_BK_VBAR
            } else {
                0
            };
            layout.fastmap = core::ptr::null_mut();
            layout.translate = core::ptr::null_mut();
            layout.re_nsub = re_nsub;
            layout.flags = 0;
            if cflags & regex::REG_NOSUB != 0 {
                layout.flags |= REGEX_FLAG_NO_SUB;
            }
            regex_set_regs_allocated(&mut layout.flags, REGS_UNALLOCATED);
            0
        }
        Err(code) => code,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn regexec(
    preg: *const c_void,
    string: *const c_char,
    nmatch: usize,
    pmatch: *mut c_void,
    eflags: c_int,
) -> c_int {
    use frankenlibc_core::string::regex;

    if preg.is_null() || string.is_null() {
        return regex::REG_NOMATCH;
    }
    let Some(compiled) = (unsafe { regex_compiled_from_buffer(preg) }) else {
        return regex::REG_BADPAT;
    };
    let input = unsafe { std::ffi::CStr::from_ptr(string) };
    let input_bytes = input.to_bytes_with_nul();

    if nmatch == 0 || pmatch.is_null() {
        // No submatch extraction needed
        let mut dummy = [regex::RegMatch::default(); 1];
        regex::regex_exec(compiled, input_bytes, &mut dummy, eflags)
    } else {
        // Map pmatch to our RegMatch slice
        let pmatch_slice =
            unsafe { core::slice::from_raw_parts_mut(pmatch as *mut regex::RegMatch, nmatch) };
        regex::regex_exec(compiled, input_bytes, pmatch_slice, eflags)
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn regfree(preg: *mut c_void) {
    if preg.is_null() {
        return;
    }
    let Some(layout) = (unsafe { regex_buffer_layout(preg) }) else {
        return;
    };
    unsafe { regex_release_buffer(layout) };
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn regerror(
    errcode: c_int,
    _preg: *const c_void,
    errbuf: *mut c_char,
    errbuf_size: usize,
) -> usize {
    use frankenlibc_core::string::regex;

    let msg = regex::regex_error(errcode);
    let msg_bytes = msg.as_bytes();
    let needed = msg_bytes.len() + 1; // include null terminator

    if !errbuf.is_null() && errbuf_size > 0 {
        let copy_len = core::cmp::min(msg_bytes.len(), errbuf_size - 1);
        unsafe {
            core::ptr::copy_nonoverlapping(msg_bytes.as_ptr(), errbuf as *mut u8, copy_len);
            *errbuf.add(copy_len) = 0; // null terminator
        }
    }

    needed
}

const FNM_NOMATCH: c_int = 1;

/// POSIX `fnmatch` — match a filename against a shell wildcard pattern.
///
/// Thin shim over [`frankenlibc_core::string::fnmatch::fnmatch_match`]
/// (bd-fnm-2, epic bd-fnm-epic). The engine itself lives in core as a
/// pure-safe pattern matcher operating on byte slices; this layer
/// handles raw-pointer / NUL-terminated C string adaptation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fnmatch(
    pattern: *const c_char,
    string: *const c_char,
    flags: c_int,
) -> c_int {
    if pattern.is_null() || string.is_null() {
        return FNM_NOMATCH;
    }
    // Adapt NUL-terminated C strings to byte slices.
    let pat_bytes = unsafe { core::ffi::CStr::from_ptr(pattern) }.to_bytes();
    let str_bytes = unsafe { core::ffi::CStr::from_ptr(string) }.to_bytes();
    let core_flags = frankenlibc_core::string::fnmatch::FnmatchFlags::from_bits(flags as u32);
    if frankenlibc_core::string::fnmatch::fnmatch_match(pat_bytes, str_bytes, core_flags) {
        0
    } else {
        FNM_NOMATCH
    }
}

// (BracketShape, classify_bracket, fnmatch_impl moved into
// frankenlibc-core/src/string/fnmatch.rs by bd-fnm-1; the legacy
// inline implementation that lived here was deleted by bd-fnm-2.)

/// POSIX `glob` — expand pathname pattern.
///
/// Native implementation using frankenlibc-core's glob engine.
/// glob_t layout on x86_64:
///   offset 0: gl_pathc (size_t) — count of matched paths
///   gl_pathv (char**) — null-terminated array of path strings
///   gl_offs (size_t) — slots to reserve at start of gl_pathv
///
/// We define a minimal `#[repr(C)]` struct for the first three fields
/// instead of using raw byte offsets.
#[repr(C)]
struct GlobT {
    gl_pathc: usize,
    gl_pathv: *mut *mut c_char,
    gl_offs: usize,
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn glob(
    pattern: *const c_char,
    flags: c_int,
    _errfunc: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
    pglob: *mut c_void,
) -> c_int {
    use frankenlibc_core::string::glob as glob_core;

    if pattern.is_null() || pglob.is_null() {
        return glob_core::GLOB_NOMATCH;
    }

    let pat_bytes = unsafe { std::ffi::CStr::from_ptr(pattern) }.to_bytes_with_nul();

    let append = flags & glob_core::GLOB_APPEND != 0;

    let gt = pglob as *mut GlobT;

    // Read current state for GLOB_APPEND.
    let (existing_paths, existing_count) = if append {
        let pathc = unsafe { (*gt).gl_pathc };
        let pathv = unsafe { (*gt).gl_pathv };
        let mut paths: Vec<*mut c_char> = Vec::new();
        if !pathv.is_null() && pathc > 0 {
            for i in 0..pathc {
                let p = unsafe { *pathv.add(i) };
                if !p.is_null() {
                    paths.push(p);
                }
            }
        }
        (paths, pathc)
    } else {
        (Vec::new(), 0)
    };

    // Run the glob engine.
    let result = glob_core::glob_expand(pat_bytes, flags);

    match result {
        Ok(res) => {
            let dooffs = flags & glob_core::GLOB_DOOFFS != 0;
            let offs = if dooffs { unsafe { (*gt).gl_offs } } else { 0 };

            let new_count = res.paths.len();
            let total = existing_count + new_count;

            // Allocate pathv: offs + total + 1 (null terminator)
            let alloc_count = offs + total + 1;
            let pathv = unsafe {
                crate::malloc_abi::raw_alloc(alloc_count * std::mem::size_of::<*mut c_char>())
            } as *mut *mut c_char;
            if pathv.is_null() {
                return glob_core::GLOB_NOSPACE;
            }

            // Fill offset slots with null.
            for i in 0..offs {
                unsafe { *pathv.add(i) = std::ptr::null_mut() };
            }

            // Copy existing paths (for GLOB_APPEND).
            for (i, &p) in existing_paths.iter().enumerate() {
                unsafe { *pathv.add(offs + i) = p };
            }

            // Copy new paths as strdup'd C strings.
            for (i, path) in res.paths.iter().enumerate() {
                let len = path.len();
                let s = unsafe { crate::malloc_abi::raw_alloc(len + 1) } as *mut c_char;
                if s.is_null() {
                    // Free everything allocated so far.
                    for j in 0..i {
                        unsafe {
                            crate::malloc_abi::raw_free(
                                *pathv.add(offs + existing_count + j) as *mut c_void
                            )
                        };
                    }
                    unsafe { crate::malloc_abi::raw_free(pathv as *mut c_void) };
                    return glob_core::GLOB_NOSPACE;
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(path.as_ptr() as *const c_char, s, len);
                    *s.add(len) = 0; // null terminate
                    *pathv.add(offs + existing_count + i) = s;
                }
            }

            // Null-terminate.
            unsafe { *pathv.add(offs + total) = std::ptr::null_mut() };

            // Free old pathv array (not the strings — those were moved).
            if append {
                let old_pathv = unsafe { (*gt).gl_pathv };
                if !old_pathv.is_null() {
                    unsafe { crate::malloc_abi::raw_free(old_pathv.cast()) };
                }
            }

            // Write glob_t fields.
            unsafe {
                (*gt).gl_pathc = total;
                (*gt).gl_pathv = pathv;
            }

            0
        }
        Err(code) => code,
    }
}

/// POSIX `globfree` — free glob result.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn globfree(pglob: *mut c_void) {
    use frankenlibc_core::string::glob as glob_core;
    let _ = glob_core::GLOB_NOSPACE; // suppress unused import

    if pglob.is_null() {
        return;
    }

    let gt = pglob as *mut GlobT;
    let pathc = unsafe { (*gt).gl_pathc };
    let pathv = unsafe { (*gt).gl_pathv };

    if pathv.is_null() {
        return;
    }

    // gl_offs: number of reserved null slots at start
    let offs = unsafe { (*gt).gl_offs };

    // Free each path string (skip null offset slots).
    for i in offs..offs + pathc {
        let p = unsafe { *pathv.add(i) };
        if !p.is_null() {
            unsafe { crate::malloc_abi::raw_free(p as *mut c_void) };
        }
    }

    // Free the pathv array.
    unsafe { crate::malloc_abi::raw_free(pathv as *mut c_void) };

    // Zero out the glob_t.
    unsafe {
        (*gt).gl_pathc = 0;
        (*gt).gl_pathv = std::ptr::null_mut();
    }
}

// ---------------------------------------------------------------------------
// Signal/error description functions — native implementation
// ---------------------------------------------------------------------------

/// Signal name table (POSIX standard signals, Linux numbering).
fn signal_name(sig: c_int) -> &'static [u8] {
    match sig {
        1 => b"Hangup",
        2 => b"Interrupt",
        3 => b"Quit",
        4 => b"Illegal instruction",
        5 => b"Trace/breakpoint trap",
        6 => b"Aborted",
        7 => b"Bus error",
        8 => b"Floating point exception",
        9 => b"Killed",
        10 => b"User defined signal 1",
        11 => b"Segmentation fault",
        12 => b"User defined signal 2",
        13 => b"Broken pipe",
        14 => b"Alarm clock",
        15 => b"Terminated",
        16 => b"Stack fault",
        17 => b"Child exited",
        18 => b"Continued",
        19 => b"Stopped (signal)",
        20 => b"Stopped",
        21 => b"Stopped (tty input)",
        22 => b"Stopped (tty output)",
        23 => b"Urgent I/O condition",
        24 => b"CPU time limit exceeded",
        25 => b"File size limit exceeded",
        26 => b"Virtual timer expired",
        27 => b"Profiling timer expired",
        28 => b"Window changed",
        29 => b"I/O possible",
        30 => b"Power failure",
        31 => b"Bad system call",
        _ => b"Unknown signal",
    }
}

std::thread_local! {
    static STRSIGNAL_BUF: std::cell::RefCell<[u8; 64]> = const { std::cell::RefCell::new([0u8; 64]) };
}

/// POSIX `strsignal` — returns a string describing a signal number.
///
/// Returns a thread-local buffer with the signal description.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strsignal(sig: c_int) -> *mut c_char {
    STRSIGNAL_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        let name = signal_name(sig);
        let len = name.len().min(buf.len() - 1);
        buf[..len].copy_from_slice(&name[..len]);
        buf[len] = 0;
        buf.as_mut_ptr() as *mut c_char
    })
}

/// POSIX `psignal` — print a signal description to stderr.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn psignal(sig: c_int, s: *const c_char) {
    let name = signal_name(sig);

    // Build message: "s: signal_name\n" or "signal_name\n"
    let mut msg = Vec::with_capacity(256);
    if !s.is_null() {
        let prefix = unsafe { std::ffi::CStr::from_ptr(s) }.to_bytes();
        if !prefix.is_empty() {
            msg.extend_from_slice(prefix);
            msg.extend_from_slice(b": ");
        }
    }
    msg.extend_from_slice(name);
    msg.push(b'\n');

    // Write to stderr via native raw syscall (bd-h5x)
    let _ = unsafe { raw_syscall::sys_write(2, msg.as_ptr(), msg.len()) };
}

// ---------------------------------------------------------------------------
// GNU extensions: strverscmp, rawmemchr
// ---------------------------------------------------------------------------

/// GNU `strverscmp` — version-aware string comparison.
///
/// Compares two strings treating embedded digit sequences as numbers.
/// For example, "file10" > "file9" (unlike strcmp which gives "file10" < "file9").
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strverscmp(s1: *const c_char, s2: *const c_char) -> c_int {
    if s1.is_null() && s2.is_null() {
        return 0;
    }
    if s1.is_null() {
        return -1;
    }
    if s2.is_null() {
        return 1;
    }

    let mut i = 0usize;
    loop {
        let c1 = unsafe { *s1.add(i) } as u8;
        let c2 = unsafe { *s2.add(i) } as u8;

        // Both hit NUL: equal.
        if c1 == 0 && c2 == 0 {
            return 0;
        }

        // If both are digits, compare numerically.
        if c1.is_ascii_digit() && c2.is_ascii_digit() {
            // Check for leading zeros — strings with leading zeros compare
            // as if left-aligned (fractional comparison).
            let leading_zero = c1 == b'0' || c2 == b'0';
            if leading_zero {
                // Left-aligned comparison (treat as fraction after decimal point).
                loop {
                    let d1 = unsafe { *s1.add(i) } as u8;
                    let d2 = unsafe { *s2.add(i) } as u8;
                    let is_d1 = d1.is_ascii_digit();
                    let is_d2 = d2.is_ascii_digit();
                    if !is_d1 && !is_d2 {
                        break;
                    }
                    if !is_d1 {
                        return 1;
                    }
                    if !is_d2 {
                        return -1;
                    }
                    if d1 != d2 {
                        return (d1 as c_int) - (d2 as c_int);
                    }
                    i += 1;
                }
            } else {
                // Numeric comparison: longer digit sequence = larger number.
                let start = i;
                let mut len1 = 0usize;
                let mut len2 = 0usize;
                let mut diff = 0i32;

                // Walk both digit sequences simultaneously.
                loop {
                    let d1 = unsafe { *s1.add(start + len1) } as u8;
                    let d2 = unsafe { *s2.add(start + len2) } as u8;
                    let is_d1 = d1.is_ascii_digit();
                    let is_d2 = d2.is_ascii_digit();

                    if is_d1 {
                        len1 += 1;
                    }
                    if is_d2 {
                        len2 += 1;
                    }
                    if !is_d1 && !is_d2 {
                        break;
                    }
                    // Record first digit difference for equal-length sequences.
                    if is_d1 && is_d2 && diff == 0 {
                        diff = (d1 as i32) - (d2 as i32);
                    }
                    if !is_d1 || !is_d2 {
                        break;
                    }
                }

                // Longer digit sequence wins.
                if len1 != len2 {
                    return if len1 > len2 { 1 } else { -1 };
                }
                // Same length: first different digit wins.
                if diff != 0 {
                    return diff;
                }
                i = start + len1;
            }
            continue;
        }

        // Otherwise compare as bytes.
        if c1 != c2 {
            return (c1 as c_int) - (c2 as c_int);
        }
        i += 1;
    }
}

/// GNU `rawmemchr` — scan memory for a byte without a length limit.
///
/// Like `memchr` but assumes the byte WILL be found. If the byte is not
/// present, behavior is undefined (same as glibc). This implementation
/// scans until found.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rawmemchr(s: *const c_void, c: c_int) -> *mut c_void {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let needle = c as u8;
    let mut ptr = s as *const u8;
    loop {
        if unsafe { *ptr } == needle {
            return ptr as *mut c_void;
        }
        ptr = unsafe { ptr.add(1) };
    }
}

// ===========================================================================
// Batch: GNU error name extensions — Implemented
// ===========================================================================

/// GNU `strerrordesc_np` — return description for errno value (non-POSIX).
///
/// Returns a static string or null if errno is unknown.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn strerrordesc_np(errnum: c_int) -> *const c_char {
    let desc: &[u8] = match errnum {
        libc::EPERM => b"Operation not permitted\0",
        libc::ENOENT => b"No such file or directory\0",
        libc::ESRCH => b"No such process\0",
        libc::EINTR => b"Interrupted system call\0",
        libc::EIO => b"Input/output error\0",
        libc::ENXIO => b"No such device or address\0",
        libc::E2BIG => b"Argument list too long\0",
        libc::ENOEXEC => b"Exec format error\0",
        libc::EBADF => b"Bad file descriptor\0",
        libc::ECHILD => b"No child processes\0",
        libc::EAGAIN => b"Resource temporarily unavailable\0",
        libc::ENOMEM => b"Cannot allocate memory\0",
        libc::EACCES => b"Permission denied\0",
        libc::EFAULT => b"Bad address\0",
        libc::EBUSY => b"Device or resource busy\0",
        libc::EEXIST => b"File exists\0",
        libc::EXDEV => b"Invalid cross-device link\0",
        libc::ENODEV => b"No such device\0",
        libc::ENOTDIR => b"Not a directory\0",
        libc::EISDIR => b"Is a directory\0",
        libc::EINVAL => b"Invalid argument\0",
        libc::ENFILE => b"Too many open files in system\0",
        libc::EMFILE => b"Too many open files\0",
        libc::ENOTTY => b"Inappropriate ioctl for device\0",
        libc::ETXTBSY => b"Text file busy\0",
        libc::EFBIG => b"File too large\0",
        libc::ENOSPC => b"No space left on device\0",
        libc::ESPIPE => b"Illegal seek\0",
        libc::EROFS => b"Read-only file system\0",
        libc::EMLINK => b"Too many links\0",
        libc::EPIPE => b"Broken pipe\0",
        libc::EDOM => b"Numerical argument out of domain\0",
        libc::ERANGE => b"Numerical result out of range\0",
        libc::EDEADLK => b"Resource deadlock avoided\0",
        libc::ENAMETOOLONG => b"File name too long\0",
        libc::ENOLCK => b"No locks available\0",
        libc::ENOSYS => b"Function not implemented\0",
        libc::ENOTEMPTY => b"Directory not empty\0",
        libc::ELOOP => b"Too many levels of symbolic links\0",
        libc::ENODATA => b"No data available\0",
        libc::ETIME => b"Timer expired\0",
        libc::EOVERFLOW => b"Value too large for defined data type\0",
        libc::EILSEQ => b"Invalid or incomplete multibyte or wide character\0",
        libc::ENOTSOCK => b"Socket operation on non-socket\0",
        libc::EDESTADDRREQ => b"Destination address required\0",
        libc::EMSGSIZE => b"Message too long\0",
        libc::EPROTOTYPE => b"Protocol wrong type for socket\0",
        libc::ENOPROTOOPT => b"Protocol not available\0",
        libc::EPROTONOSUPPORT => b"Protocol not supported\0",
        libc::EAFNOSUPPORT => b"Address family not supported by protocol\0",
        libc::EADDRINUSE => b"Address already in use\0",
        libc::EADDRNOTAVAIL => b"Cannot assign requested address\0",
        libc::ENETDOWN => b"Network is down\0",
        libc::ENETUNREACH => b"Network is unreachable\0",
        libc::ECONNABORTED => b"Software caused connection abort\0",
        libc::ECONNRESET => b"Connection reset by peer\0",
        libc::ENOBUFS => b"No buffer space available\0",
        libc::EISCONN => b"Transport endpoint is already connected\0",
        libc::ENOTCONN => b"Transport endpoint is not connected\0",
        libc::ETIMEDOUT => b"Connection timed out\0",
        libc::ECONNREFUSED => b"Connection refused\0",
        libc::EHOSTUNREACH => b"No route to host\0",
        libc::EALREADY => b"Operation already in progress\0",
        libc::EINPROGRESS => b"Operation now in progress\0",
        _ => return std::ptr::null(),
    };
    desc.as_ptr() as *const c_char
}

/// GNU `strerrorname_np` — return symbolic errno name (non-POSIX).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn strerrorname_np(errnum: c_int) -> *const c_char {
    let name: &[u8] = match errnum {
        libc::EPERM => b"EPERM\0",
        libc::ENOENT => b"ENOENT\0",
        libc::ESRCH => b"ESRCH\0",
        libc::EINTR => b"EINTR\0",
        libc::EIO => b"EIO\0",
        libc::ENXIO => b"ENXIO\0",
        libc::E2BIG => b"E2BIG\0",
        libc::ENOEXEC => b"ENOEXEC\0",
        libc::EBADF => b"EBADF\0",
        libc::ECHILD => b"ECHILD\0",
        libc::EAGAIN => b"EAGAIN\0",
        libc::ENOMEM => b"ENOMEM\0",
        libc::EACCES => b"EACCES\0",
        libc::EFAULT => b"EFAULT\0",
        libc::EBUSY => b"EBUSY\0",
        libc::EEXIST => b"EEXIST\0",
        libc::EXDEV => b"EXDEV\0",
        libc::ENODEV => b"ENODEV\0",
        libc::ENOTDIR => b"ENOTDIR\0",
        libc::EISDIR => b"EISDIR\0",
        libc::EINVAL => b"EINVAL\0",
        libc::ENFILE => b"ENFILE\0",
        libc::EMFILE => b"EMFILE\0",
        libc::ENOTTY => b"ENOTTY\0",
        libc::EFBIG => b"EFBIG\0",
        libc::ENOSPC => b"ENOSPC\0",
        libc::ESPIPE => b"ESPIPE\0",
        libc::EROFS => b"EROFS\0",
        libc::EMLINK => b"EMLINK\0",
        libc::EPIPE => b"EPIPE\0",
        libc::EDOM => b"EDOM\0",
        libc::ERANGE => b"ERANGE\0",
        libc::EDEADLK => b"EDEADLK\0",
        libc::ENAMETOOLONG => b"ENAMETOOLONG\0",
        libc::ENOLCK => b"ENOLCK\0",
        libc::ENOSYS => b"ENOSYS\0",
        libc::ENOTEMPTY => b"ENOTEMPTY\0",
        libc::ELOOP => b"ELOOP\0",
        libc::EOVERFLOW => b"EOVERFLOW\0",
        libc::EILSEQ => b"EILSEQ\0",
        libc::ENOTSOCK => b"ENOTSOCK\0",
        libc::ECONNREFUSED => b"ECONNREFUSED\0",
        libc::ETIMEDOUT => b"ETIMEDOUT\0",
        libc::ECONNRESET => b"ECONNRESET\0",
        libc::EINPROGRESS => b"EINPROGRESS\0",
        _ => return std::ptr::null(),
    };
    name.as_ptr() as *const c_char
}

// ===========================================================================
// Batch: C23 float-to-string — Implemented
// ===========================================================================

/// C23 `strfromd` — convert double to string with format.
///
/// Writes at most `n` bytes (including null) to `s`.
/// Returns the number of bytes that would have been written (excluding null).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strfromd(
    s: *mut c_char,
    n: usize,
    format: *const c_char,
    value: f64,
) -> c_int {
    if format.is_null() {
        return -1;
    }
    // Parse format: must be "%[.<precision>]{f,e,g,a}" (C23 subset)
    let fmt = unsafe { std::ffi::CStr::from_ptr(format) };
    let fmt_str = match fmt.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let rendered = render_strfrom(fmt_str, value);
    let bytes = rendered.as_bytes();
    let len = bytes.len();

    if !s.is_null() && n > 0 {
        let copy_len = std::cmp::min(len, n - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), s as *mut u8, copy_len);
            *s.add(copy_len) = 0;
        }
    }
    len as c_int
}

/// C23 `strfromf` — convert float to string with format.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strfromf(
    s: *mut c_char,
    n: usize,
    format: *const c_char,
    value: f32,
) -> c_int {
    unsafe { strfromd(s, n, format, value as f64) }
}

/// C23 `strfroml` — convert long double to string with format.
///
/// On x86_64 Linux, long double is 80-bit extended but we use f64 approximation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strfroml(
    s: *mut c_char,
    n: usize,
    format: *const c_char,
    value: f64, // long double approximated as f64
) -> c_int {
    unsafe { strfromd(s, n, format, value) }
}

fn render_strfrom(fmt: &str, value: f64) -> String {
    // Parse "%[.<prec>]{f|e|g|a}"
    if !fmt.starts_with('%') {
        return format!("{value}");
    }
    let rest = &fmt[1..];
    let (precision, spec) = if let Some(after_dot) = rest.strip_prefix('.') {
        let num_end = after_dot
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after_dot.len());
        let prec: usize = after_dot[..num_end].parse().unwrap_or(6);
        (prec, &after_dot[num_end..])
    } else {
        (6, rest)
    };

    match spec {
        "f" | "F" => format!("{value:.precision$}"),
        "e" => format!("{value:.precision$e}"),
        "E" => format!("{value:.precision$E}"),
        "g" | "G" => {
            // %g: use shorter of %f or %e
            let f_str = format!("{value:.precision$}");
            let e_str = format!("{value:.precision$e}");
            if f_str.len() <= e_str.len() {
                f_str
            } else {
                e_str
            }
        }
        _ => format!("{value}"),
    }
}

// ===========================================================================
// Batch: argz family (GNU extensions) — Implemented
// ===========================================================================

/// `argz_create` — create an argz vector from argv.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argz_create(
    argv: *const *const c_char,
    argz: *mut *mut c_char,
    argz_len: *mut usize,
) -> c_int {
    if argz.is_null() || argz_len.is_null() {
        return libc::EINVAL;
    }
    if argv.is_null() {
        unsafe {
            *argz = std::ptr::null_mut();
            *argz_len = 0;
        }
        return 0;
    }

    let mut total_len = 0usize;
    let mut count = 0;
    let mut i = 0;
    loop {
        let p = unsafe { *argv.add(i) };
        if p.is_null() {
            break;
        }
        total_len += unsafe { crate::string_abi::strlen(p) } + 1;
        count += 1;
        i += 1;
    }

    if total_len == 0 {
        unsafe {
            *argz = std::ptr::null_mut();
            *argz_len = 0;
        }
        return 0;
    }

    // GNU argz contract: caller frees argz buffer via libc::free
    // (bd-zgifl); use libc::malloc for the alloc/free pair to match
    // in test (non-LD_PRELOAD) builds.
    let buf = unsafe { libc::malloc(total_len) as *mut c_char };
    if buf.is_null() {
        return libc::ENOMEM;
    }

    let mut offset = 0;
    for j in 0..count {
        let p = unsafe { *argv.add(j) };
        let slen = unsafe { crate::string_abi::strlen(p) };
        unsafe {
            std::ptr::copy_nonoverlapping(p as *const u8, buf.add(offset) as *mut u8, slen + 1);
        }
        offset += slen + 1;
    }

    unsafe {
        *argz = buf;
        *argz_len = total_len;
    }
    0
}

/// `argz_create_sep` — create argz from string with separator.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argz_create_sep(
    string: *const c_char,
    sep: c_int,
    argz: *mut *mut c_char,
    argz_len: *mut usize,
) -> c_int {
    if argz.is_null() || argz_len.is_null() {
        return libc::EINVAL;
    }
    if string.is_null() {
        unsafe {
            *argz = std::ptr::null_mut();
            *argz_len = 0;
        }
        return 0;
    }

    let s = unsafe { CStr::from_ptr(string) };
    let s_bytes = s.to_bytes();
    let sep_byte = sep as u8;
    let entries = argz_sep_entries(s_bytes, sep_byte);

    if entries.is_empty() {
        unsafe {
            *argz = std::ptr::null_mut();
            *argz_len = 0;
        }
        return 0;
    }

    let len: usize = entries.iter().map(|entry| entry.len() + 1).sum();
    // GNU argz: caller frees via libc::free (bd-zgifl).
    let ptr = unsafe { libc::malloc(len) as *mut c_char };
    if ptr.is_null() {
        return libc::ENOMEM;
    }
    let mut offset = 0usize;
    for entry in entries {
        unsafe {
            std::ptr::copy_nonoverlapping(entry.as_ptr(), ptr.add(offset) as *mut u8, entry.len());
            *ptr.add(offset + entry.len()) = 0;
        }
        offset += entry.len() + 1;
    }
    unsafe {
        *argz = ptr;
        *argz_len = len;
    }
    0
}

/// `argz_count` — count entries in an argz vector.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argz_count(argz: *const c_char, argz_len: usize) -> usize {
    if argz.is_null() || argz_len == 0 {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(argz as *const u8, argz_len) };
    slice.iter().filter(|&&b| b == 0).count()
}

/// `argz_next` — iterate to next entry in argz.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argz_next(
    argz: *const c_char,
    argz_len: usize,
    entry: *const c_char,
) -> *mut c_char {
    if argz.is_null() || argz_len == 0 {
        return std::ptr::null_mut();
    }
    if entry.is_null() {
        return argz as *mut c_char;
    }
    // Find end of current entry (next NUL) then advance past it
    let base = argz as usize;
    let ptr = entry as usize;
    let end = match base.checked_add(argz_len) {
        Some(end) => end,
        None => return std::ptr::null_mut(),
    };
    if ptr < base || ptr >= end {
        return std::ptr::null_mut();
    }
    let entry_offset = ptr - base;
    let remaining =
        &unsafe { std::slice::from_raw_parts(argz as *const u8, argz_len) }[entry_offset..];
    if let Some(nul_pos) = remaining.iter().position(|&b| b == 0) {
        let next_offset = entry_offset + nul_pos + 1;
        if next_offset < argz_len {
            return unsafe { argz.add(next_offset) as *mut c_char };
        }
    }
    std::ptr::null_mut()
}

fn argz_sep_entries(bytes: &[u8], sep: u8) -> Vec<&[u8]> {
    let mut entries = Vec::new();
    let mut pos = 0usize;

    while pos < bytes.len() {
        while pos < bytes.len() && bytes[pos] == sep {
            pos += 1;
        }
        if pos == bytes.len() {
            break;
        }

        let mut end = pos;
        while end < bytes.len() && bytes[end] != sep {
            end += 1;
        }
        entries.push(&bytes[pos..end]);
        pos = end;
    }

    if !bytes.is_empty() && bytes[bytes.len() - 1] == sep {
        entries.push(&[]);
    }

    entries
}

unsafe fn replace_owned_argz_buffer(
    argz: *mut *mut c_char,
    argz_len: *mut usize,
    new_buf: *mut c_char,
    new_len: usize,
) {
    let old_buf = unsafe { *argz };
    let old_len = unsafe { *argz_len };
    if !old_buf.is_null() && old_len > 0 {
        // Pair with libc::malloc used by argz_create / argz_add /
        // argz_append / argz_insert / argz_replace. (bd-zgifl)
        unsafe { libc::free(old_buf.cast()) };
    }
    unsafe {
        *argz = if new_len == 0 {
            std::ptr::null_mut()
        } else {
            new_buf
        };
        *argz_len = new_len;
    }
}

unsafe fn argz_entry_offset(
    argz: *const c_char,
    argz_len: usize,
    entry: *const c_char,
) -> Option<usize> {
    if argz.is_null() || entry.is_null() || argz_len == 0 {
        return None;
    }
    let base = argz as usize;
    let ptr = entry as usize;
    let end = base.checked_add(argz_len)?;
    if ptr < base || ptr >= end {
        return None;
    }
    let offset = ptr - base;
    if offset > 0 {
        let previous = unsafe { *(argz as *const u8).add(offset - 1) };
        if previous != 0 {
            return None;
        }
    }
    Some(offset)
}

/// `argz_add` — append a string to an argz vector.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argz_add(
    argz: *mut *mut c_char,
    argz_len: *mut usize,
    str_: *const c_char,
) -> c_int {
    if argz.is_null() || argz_len.is_null() || str_.is_null() {
        return libc::EINVAL;
    }
    let slen = unsafe { crate::string_abi::strlen(str_) };
    let old_len = unsafe { *argz_len };
    let new_len = old_len + slen + 1;
    let new_buf = unsafe { libc::malloc(new_len) as *mut c_char };
    if new_buf.is_null() {
        return libc::ENOMEM;
    }
    unsafe {
        if old_len > 0 && !(*argz).is_null() {
            std::ptr::copy_nonoverlapping(*argz as *const u8, new_buf as *mut u8, old_len);
        }
        std::ptr::copy_nonoverlapping(str_ as *const u8, new_buf.add(old_len) as *mut u8, slen + 1);
        replace_owned_argz_buffer(argz, argz_len, new_buf, new_len);
    }
    0
}

/// `argz_add_sep` — split string by separator and append to argz.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argz_add_sep(
    argz: *mut *mut c_char,
    argz_len: *mut usize,
    string: *const c_char,
    sep: c_int,
) -> c_int {
    if argz.is_null() || argz_len.is_null() || string.is_null() {
        return libc::EINVAL;
    }
    let s = unsafe { CStr::from_ptr(string) };
    let sep_byte = sep as u8;
    for part in argz_sep_entries(s.to_bytes(), sep_byte) {
        let part_str = std::ffi::CString::new(part).unwrap_or_default();
        let rc = unsafe { argz_add(argz, argz_len, part_str.as_ptr()) };
        if rc != 0 {
            return rc;
        }
    }
    0
}

/// `argz_append` — append argz2 to argz1.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argz_append(
    argz: *mut *mut c_char,
    argz_len: *mut usize,
    buf: *const c_char,
    buf_len: usize,
) -> c_int {
    if argz.is_null() || argz_len.is_null() {
        return libc::EINVAL;
    }
    if buf.is_null() || buf_len == 0 {
        return 0;
    }
    let old_len = unsafe { *argz_len };
    let new_len = old_len + buf_len;
    let new_buf = unsafe { libc::malloc(new_len) as *mut c_char };
    if new_buf.is_null() {
        return libc::ENOMEM;
    }
    unsafe {
        if old_len > 0 && !(*argz).is_null() {
            std::ptr::copy_nonoverlapping(*argz as *const u8, new_buf as *mut u8, old_len);
        }
        std::ptr::copy_nonoverlapping(buf as *const u8, new_buf.add(old_len) as *mut u8, buf_len);
        replace_owned_argz_buffer(argz, argz_len, new_buf, new_len);
    }
    0
}

/// `argz_delete` — remove an entry from argz.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argz_delete(
    argz: *mut *mut c_char,
    argz_len: *mut usize,
    entry: *mut c_char,
) {
    if argz.is_null() || argz_len.is_null() || entry.is_null() {
        return;
    }
    let az = unsafe { *argz };
    let len = unsafe { *argz_len };
    let Some(entry_offset) = (unsafe { argz_entry_offset(az, len, entry) }) else {
        return;
    };
    let entry_len = unsafe { crate::string_abi::strlen(entry) } + 1; // include NUL
    let remaining = len - entry_offset - entry_len;
    if remaining > 0 {
        unsafe {
            std::ptr::copy(
                az.add(entry_offset + entry_len) as *const u8,
                az.add(entry_offset) as *mut u8,
                remaining,
            );
        }
    }
    let new_len = len - entry_len;
    if new_len == 0 {
        unsafe {
            // Pair with libc::malloc used by argz_create. (bd-zgifl)
            libc::free(az.cast());
            *argz = std::ptr::null_mut();
            *argz_len = 0;
        }
    } else {
        unsafe { *argz_len = new_len };
    }
}

/// `argz_extract` — extract argz entries into an argv array.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argz_extract(
    argz: *const c_char,
    argz_len: usize,
    argv: *mut *mut c_char,
) {
    if argz.is_null() || argv.is_null() || argz_len == 0 {
        return;
    }
    let mut idx = 0;
    let mut entry: *const c_char = argz;
    let end = unsafe { argz.add(argz_len) };
    while entry < end {
        unsafe { *argv.add(idx) = entry as *mut c_char };
        idx += 1;
        // Skip to next NUL
        let slen = unsafe { crate::string_abi::strlen(entry) };
        entry = unsafe { entry.add(slen + 1) };
    }
    unsafe { *argv.add(idx) = std::ptr::null_mut() };
}

/// `argz_insert` — insert string before entry in argz.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argz_insert(
    argz: *mut *mut c_char,
    argz_len: *mut usize,
    before: *mut c_char,
    entry: *const c_char,
) -> c_int {
    if argz.is_null() || argz_len.is_null() || entry.is_null() {
        return libc::EINVAL;
    }
    if before.is_null() {
        // Append at end
        return unsafe { argz_add(argz, argz_len, entry) };
    }
    let slen = unsafe { crate::string_abi::strlen(entry) } + 1;
    let old_len = unsafe { *argz_len };
    let az = unsafe { *argz };
    let Some(before_offset) = (unsafe { argz_entry_offset(az, old_len, before) }) else {
        return libc::EINVAL;
    };
    let new_len = old_len + slen;

    let new_buf = unsafe { libc::malloc(new_len) as *mut c_char };
    if new_buf.is_null() {
        return libc::ENOMEM;
    }

    let tail_len = old_len - before_offset;
    unsafe {
        if before_offset > 0 {
            std::ptr::copy_nonoverlapping(az as *const u8, new_buf as *mut u8, before_offset);
        }
        std::ptr::copy_nonoverlapping(
            entry as *const u8,
            new_buf.add(before_offset) as *mut u8,
            slen,
        );
        if tail_len > 0 {
            std::ptr::copy_nonoverlapping(
                az.add(before_offset) as *const u8,
                new_buf.add(before_offset + slen) as *mut u8,
                tail_len,
            );
        }
        replace_owned_argz_buffer(argz, argz_len, new_buf, new_len);
    }
    0
}

/// `argz_replace` — replace all occurrences of str with with in argz.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argz_replace(
    argz: *mut *mut c_char,
    argz_len: *mut usize,
    str_: *const c_char,
    with: *const c_char,
    replace_count: *mut libc::c_uint,
) -> c_int {
    if argz.is_null() || argz_len.is_null() || str_.is_null() || with.is_null() {
        return libc::EINVAL;
    }
    let find_str = unsafe { CStr::from_ptr(str_) };
    let replace_cstr = unsafe { CStr::from_ptr(with) };

    // Rebuild the argz with replacements
    let az = unsafe { *argz };
    let len = unsafe { *argz_len };
    if az.is_null() || len == 0 {
        return 0;
    }
    let mut entries: Vec<Vec<u8>> = Vec::new();
    let mut replacements = 0_u32;
    let mut pos = 0usize;
    while pos < len {
        let entry = unsafe { CStr::from_ptr(az.add(pos)) };
        let entry_bytes = entry.to_bytes();
        if entry.to_bytes() == find_str.to_bytes() {
            replacements = replacements.wrapping_add(1);
            entries.push(replace_cstr.to_bytes().to_vec());
        } else {
            entries.push(entry_bytes.to_vec());
        }
        pos += entry_bytes.len() + 1;
    }
    if !replace_count.is_null() {
        unsafe {
            *replace_count = (*replace_count).wrapping_add(replacements);
        }
    }
    if replacements == 0 {
        return 0;
    }

    // Compute new length
    let new_len: usize = entries.iter().map(|e| e.len() + 1).sum();

    let new_buf = unsafe { libc::malloc(new_len) as *mut c_char };
    if new_buf.is_null() {
        return libc::ENOMEM;
    }
    let mut offset = 0;
    for e in &entries {
        unsafe {
            std::ptr::copy_nonoverlapping(e.as_ptr(), new_buf.add(offset) as *mut u8, e.len());
            *new_buf.add(offset + e.len()) = 0;
        }
        offset += e.len() + 1;
    }
    unsafe { replace_owned_argz_buffer(argz, argz_len, new_buf, new_len) };
    0
}

/// `argz_stringify` — convert argz to regular string (replace NULs with sep).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argz_stringify(argz: *mut c_char, argz_len: usize, sep: c_int) {
    if argz.is_null() || argz_len < 2 {
        return;
    }
    // Replace all interior NULs with sep, keep last NUL
    let slice = unsafe { std::slice::from_raw_parts_mut(argz as *mut u8, argz_len) };
    for b in &mut slice[..argz_len - 1] {
        if *b == 0 {
            *b = sep as u8;
        }
    }
}

// ===========================================================================
// Batch: envz family (GNU extensions) — Implemented
// ===========================================================================

/// `envz_entry` — find entry with given name in envz.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn envz_entry(
    envz: *const c_char,
    envz_len: usize,
    name: *const c_char,
) -> *mut c_char {
    if envz.is_null() || envz_len == 0 || name.is_null() {
        return std::ptr::null_mut();
    }
    let name_cstr = unsafe { CStr::from_ptr(name) };
    let name_bytes = name_cstr.to_bytes();

    let mut pos = 0usize;
    while pos < envz_len {
        let entry = unsafe { CStr::from_ptr(envz.add(pos)) };
        let entry_bytes = entry.to_bytes();
        // Check if entry starts with name and is followed by '=' or NUL
        if entry_bytes.len() >= name_bytes.len()
            && entry_bytes.starts_with(name_bytes)
            && (entry_bytes.len() == name_bytes.len() || entry_bytes[name_bytes.len()] == b'=')
        {
            return unsafe { envz.add(pos) as *mut c_char };
        }
        pos += entry_bytes.len() + 1;
    }
    std::ptr::null_mut()
}

/// `envz_get` — get value for name in envz.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn envz_get(
    envz: *const c_char,
    envz_len: usize,
    name: *const c_char,
) -> *const c_char {
    let entry = unsafe { envz_entry(envz, envz_len, name) };
    if entry.is_null() {
        return std::ptr::null();
    }
    let entry_cstr = unsafe { CStr::from_ptr(entry) };
    let entry_bytes = entry_cstr.to_bytes();
    if let Some(eq_pos) = entry_bytes.iter().position(|&b| b == b'=') {
        unsafe { entry.add(eq_pos + 1) as *const c_char }
    } else {
        std::ptr::null() // name without value
    }
}

/// `envz_add` — add/replace name=value in envz.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn envz_add(
    envz: *mut *mut c_char,
    envz_len: *mut usize,
    name: *const c_char,
    value: *const c_char,
) -> c_int {
    if envz.is_null() || envz_len.is_null() || name.is_null() {
        return libc::EINVAL;
    }
    // Remove existing entry if present
    unsafe { envz_remove(envz, envz_len, name) };

    // Build "name=value" or just "name"
    if value.is_null() {
        unsafe { argz_add(envz, envz_len, name) }
    } else {
        let name_s = unsafe { CStr::from_ptr(name) }.to_bytes();
        let val_s = unsafe { CStr::from_ptr(value) }.to_bytes();
        let mut entry = Vec::with_capacity(name_s.len() + 1 + val_s.len() + 1);
        entry.extend_from_slice(name_s);
        entry.push(b'=');
        entry.extend_from_slice(val_s);
        entry.push(0);
        let entry_cstr = std::ffi::CString::from_vec_with_nul(entry).unwrap_or_default();
        unsafe { argz_add(envz, envz_len, entry_cstr.as_ptr()) }
    }
}

/// `envz_merge` — merge envz2 into envz1.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn envz_merge(
    envz: *mut *mut c_char,
    envz_len: *mut usize,
    envz2: *const c_char,
    envz2_len: usize,
    override_: c_int,
) -> c_int {
    if envz.is_null() || envz_len.is_null() {
        return libc::EINVAL;
    }
    if envz2.is_null() || envz2_len == 0 {
        return 0;
    }

    let mut pos = 0usize;
    while pos < envz2_len {
        let entry = unsafe { CStr::from_ptr(envz2.add(pos)) };
        let entry_bytes = entry.to_bytes();

        // Parse name from entry
        let eq_pos = entry_bytes.iter().position(|&b| b == b'=');
        let name_end = eq_pos.unwrap_or(entry_bytes.len());
        let name_cstr = std::ffi::CString::new(&entry_bytes[..name_end]).unwrap_or_default();

        let existing = unsafe { envz_entry(*envz, *envz_len, name_cstr.as_ptr()) };
        if existing.is_null() || override_ != 0 {
            let value = eq_pos.map(|p| unsafe { envz2.add(pos + p + 1) });
            let rc = unsafe {
                envz_add(
                    envz,
                    envz_len,
                    name_cstr.as_ptr(),
                    value.unwrap_or(std::ptr::null()),
                )
            };
            if rc != 0 {
                return rc;
            }
        }

        pos += entry_bytes.len() + 1;
    }
    0
}

/// `envz_remove` — remove name from envz.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn envz_remove(
    envz: *mut *mut c_char,
    envz_len: *mut usize,
    name: *const c_char,
) {
    if envz.is_null() || envz_len.is_null() || name.is_null() {
        return;
    }
    let entry = unsafe { envz_entry(*envz, *envz_len, name) };
    if !entry.is_null() {
        unsafe { argz_delete(envz, envz_len, entry) };
    }
}

/// `envz_strip` — remove entries without values from envz.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn envz_strip(envz: *mut *mut c_char, envz_len: *mut usize) {
    if envz.is_null() || envz_len.is_null() {
        return;
    }
    // Rebuild keeping only entries with '='
    let az = unsafe { *envz };
    let len = unsafe { *envz_len };
    let mut entries_to_remove: Vec<usize> = Vec::new();

    let mut pos = 0usize;
    while pos < len {
        let entry = unsafe { CStr::from_ptr(az.add(pos)) };
        let entry_bytes = entry.to_bytes();
        if !entry_bytes.contains(&b'=') {
            entries_to_remove.push(pos);
        }
        pos += entry_bytes.len() + 1;
    }

    // Remove from end to start to keep offsets valid
    for &offset in entries_to_remove.iter().rev() {
        let entry_ptr = unsafe { az.add(offset) };
        unsafe { argz_delete(envz, envz_len, entry_ptr) };
    }
}

// ── GNU old regex API ───────────────────────────────────────────────────────
//
// The old POSIX.2 GNU regex interface (re_compile_pattern, re_search, re_match).
// Many legacy programs and GNU utilities use this API instead of the newer
// POSIX regcomp/regexec interface. We implement using our existing regex core.

/// Default syntax bits for the old GNU regex API.
static RE_SYNTAX: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `re_set_syntax` — set default syntax options for regex compilation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn re_set_syntax(syntax: u64) -> u64 {
    RE_SYNTAX.swap(syntax, std::sync::atomic::Ordering::Relaxed)
}

/// `re_compile_pattern` — compile a regex pattern (GNU old API).
/// Returns NULL on success, or a C string error message on failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn re_compile_pattern(
    pattern: *const c_char,
    length: usize,
    buffer: *mut c_void,
) -> *const c_char {
    use frankenlibc_core::string::regex;

    if pattern.is_null() || buffer.is_null() {
        return c"Invalid argument".as_ptr();
    }
    let Some(layout) = (unsafe { regex_buffer_layout(buffer) }) else {
        return c"Invalid argument".as_ptr();
    };
    unsafe { regex_release_buffer(layout) };

    let pat_slice = unsafe { core::slice::from_raw_parts(pattern as *const u8, length) };
    let syntax = RE_SYNTAX.load(std::sync::atomic::Ordering::Relaxed);
    let cflags = legacy_regex_syntax_to_cflags(syntax);

    match regex::regex_compile_bytes(pat_slice, cflags) {
        Ok(compiled) => {
            let re_nsub = compiled.num_regs().saturating_sub(1);
            let raw_ptr = Box::into_raw(compiled);
            let handle = Box::new(RegexHandle {
                magic: FRANKEN_REGEX_MAGIC,
                compiled: raw_ptr,
            });

            layout.buffer = Box::into_raw(handle).cast();
            layout.allocated = core::mem::size_of::<RegexHandle>() as libc::c_long;
            layout.used = layout.allocated;
            layout.syntax = syntax;
            layout.fastmap = core::ptr::null_mut();
            layout.translate = core::ptr::null_mut();
            layout.re_nsub = re_nsub;
            layout.flags = 0;
            if cflags & regex::REG_NOSUB != 0 {
                layout.flags |= REGEX_FLAG_NO_SUB;
            }
            regex_set_regs_allocated(&mut layout.flags, REGS_UNALLOCATED);
            core::ptr::null()
        }
        Err(_) => c"Invalid regular expression".as_ptr(),
    }
}

/// `re_compile_fastmap` — compute fastmap for compiled pattern.
/// Returns 0 on success, -2 on error. We no-op since our engine doesn't use fastmaps.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn re_compile_fastmap(buffer: *mut c_void) -> c_int {
    let Some(layout) = (unsafe { regex_buffer_layout(buffer) }) else {
        return -2;
    };
    if unsafe { regex_compiled_from_buffer(buffer) }.is_none() {
        return -2;
    }
    layout.flags |= REGEX_FLAG_FASTMAP_ACCURATE;
    0 // success — our engine doesn't need a fastmap
}

/// `re_search` — search for pattern in string (GNU old API).
/// Returns byte offset of match start, or -1 if no match, or -2 on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn re_search(
    buffer: *const c_void,
    string: *const c_char,
    length: c_int,
    start: c_int,
    range: c_int,
    regs: *mut c_void,
) -> c_int {
    unsafe {
        re_search_2(
            buffer,
            core::ptr::null(),
            0,
            string,
            length,
            start,
            range,
            regs,
            length,
        )
    }
}

/// `re_search_2` — search for pattern in split string (GNU old API).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn re_search_2(
    buffer: *const c_void,
    string1: *const c_char,
    size1: c_int,
    string2: *const c_char,
    size2: c_int,
    startpos: c_int,
    range: c_int,
    regs: *mut c_void,
    stop: c_int,
) -> c_int {
    use frankenlibc_core::string::regex;

    if buffer.is_null() {
        return -2;
    }
    let Some(compiled) = (unsafe { regex_compiled_from_buffer(buffer) }) else {
        return -2;
    };

    let haystack = match legacy_regex_concat(string1, size1, string2, size2) {
        Ok(haystack) => haystack,
        Err(code) => return code,
    };

    let search_start = startpos.max(0) as usize;
    if search_start > haystack.len() {
        return -1;
    }
    let stop_bound = (stop.max(0) as usize).min(haystack.len());
    let nosub = compiled.nosub();
    let reg_count = compiled.num_regs().max(2);

    if range >= 0 {
        let search_end = search_start
            .saturating_add(range as usize)
            .min(haystack.len());
        for pos in search_start..=search_end {
            let sub = &haystack[pos..];
            if nosub {
                if let Some((rm_so, rm_eo)) = regex::regex_match_bounds_bytes(compiled, sub, 0) {
                    let rel = rm_so.max(0) as usize;
                    let end = rm_eo.max(0) as usize;
                    if pos + end > stop_bound {
                        continue;
                    }
                    return (pos + rel) as c_int;
                }
            } else {
                let mut match_slots = vec![regex::RegMatch::default(); reg_count];
                if regex::regex_exec_bytes(compiled, sub, &mut match_slots, 0) == 0 {
                    let rel = match_slots[0].rm_so.max(0) as usize;
                    let end = match_slots[0].rm_eo.max(0) as usize;
                    if pos + end > stop_bound {
                        continue;
                    }
                    unsafe { legacy_regex_write_regs(regs, &match_slots, pos as c_int) };
                    return (pos + rel) as c_int;
                }
            }
        }
    } else {
        let search_end = search_start.saturating_sub(range.unsigned_abs() as usize);
        for pos in (search_end..=search_start).rev() {
            let sub = &haystack[pos..];
            if nosub {
                if let Some((rm_so, rm_eo)) = regex::regex_match_bounds_bytes(compiled, sub, 0) {
                    let rel = rm_so.max(0) as usize;
                    let end = rm_eo.max(0) as usize;
                    if pos + end > stop_bound {
                        continue;
                    }
                    return (pos + rel) as c_int;
                }
            } else {
                let mut match_slots = vec![regex::RegMatch::default(); reg_count];
                if regex::regex_exec_bytes(compiled, sub, &mut match_slots, 0) == 0 {
                    let rel = match_slots[0].rm_so.max(0) as usize;
                    let end = match_slots[0].rm_eo.max(0) as usize;
                    if pos + end > stop_bound {
                        continue;
                    }
                    unsafe { legacy_regex_write_regs(regs, &match_slots, pos as c_int) };
                    return (pos + rel) as c_int;
                }
            }
        }
    }
    -1
}

/// `re_match` — match pattern at exact position (GNU old API).
/// Returns length of match, -1 if no match, -2 on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn re_match(
    buffer: *const c_void,
    string: *const c_char,
    length: c_int,
    start: c_int,
    regs: *mut c_void,
) -> c_int {
    unsafe {
        re_match_2(
            buffer,
            core::ptr::null(),
            0,
            string,
            length,
            start,
            regs,
            length,
        )
    }
}

/// `re_match_2` — match pattern at exact position in split string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn re_match_2(
    buffer: *const c_void,
    string1: *const c_char,
    size1: c_int,
    string2: *const c_char,
    size2: c_int,
    start: c_int,
    regs: *mut c_void,
    stop: c_int,
) -> c_int {
    use frankenlibc_core::string::regex;

    if buffer.is_null() {
        return -2;
    }
    let Some(compiled) = (unsafe { regex_compiled_from_buffer(buffer) }) else {
        return -2;
    };

    let haystack = match legacy_regex_concat(string1, size1, string2, size2) {
        Ok(haystack) => haystack,
        Err(code) => return code,
    };
    let start_pos = start.max(0) as usize;
    if start_pos > haystack.len() {
        return -1;
    }
    let stop_bound = (stop.max(0) as usize).min(haystack.len());
    let nosub = compiled.nosub();

    let sub = &haystack[start_pos..];
    if nosub {
        let Some((rm_so, rm_eo)) = regex::regex_match_bounds_bytes(compiled, sub, 0) else {
            return -1;
        };
        if rm_so != 0 {
            return -1;
        }
        if start_pos + rm_eo.max(0) as usize > stop_bound {
            return -1;
        }
        return rm_eo;
    }

    let mut match_slots = vec![regex::RegMatch::default(); compiled.num_regs().max(2)];
    if regex::regex_exec_bytes(compiled, sub, &mut match_slots, 0) != 0 {
        return -1;
    }
    if match_slots[0].rm_so != 0 {
        return -1;
    }
    if start_pos + match_slots[0].rm_eo.max(0) as usize > stop_bound {
        return -1;
    }
    unsafe { legacy_regex_write_regs(regs, &match_slots, start_pos as c_int) };
    match_slots[0].rm_eo
}

/// `re_set_registers` — attach caller-managed register storage to a compiled pattern.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn re_set_registers(
    buffer: *mut c_void,
    regs: *mut c_void,
    num_regs: u32,
    starts: *mut c_int,
    ends: *mut c_int,
) {
    if regs.is_null() {
        return;
    }
    let regs = unsafe { &mut *(regs as *mut LegacyReRegisters) };
    regs.num_regs = num_regs as usize;
    regs.start = starts;
    regs.end = ends;

    if let Some(layout) = unsafe { regex_buffer_layout(buffer) } {
        regex_set_regs_allocated(
            &mut layout.flags,
            if starts.is_null() || ends.is_null() {
                REGS_UNALLOCATED
            } else {
                REGS_FIXED
            },
        );
    }
}

// ===========================================================================
// glibc __str* / __stp* / __mem* internal aliases
// ===========================================================================

// ── Simple forwarding aliases ───────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __stpcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    unsafe { stpcpy(dst, src) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __stpncpy(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    unsafe { stpncpy(dst, src, n) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcasecmp(s1: *const c_char, s2: *const c_char) -> c_int {
    unsafe { strcasecmp(s1, s2) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcasestr(
    haystack: *const c_char,
    needle: *const c_char,
) -> *mut c_char {
    unsafe { strcasestr(haystack, needle) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strdup(s: *const c_char) -> *mut c_char {
    unsafe { strdup(s) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strndup(s: *const c_char, n: usize) -> *mut c_char {
    unsafe { strndup(s, n) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtok_r(
    s: *mut c_char,
    delim: *const c_char,
    saveptr: *mut *mut c_char,
) -> *mut c_char {
    unsafe { strtok_r(s, delim, saveptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    unsafe { strerror_r(errnum, buf, buflen) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strverscmp(s1: *const c_char, s2: *const c_char) -> c_int {
    unsafe { strverscmp(s1, s2) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rawmemchr(s: *const c_void, c: c_int) -> *mut c_void {
    unsafe { rawmemchr(s, c) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __mempcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    unsafe { mempcpy(dst, src, n) }
}

/// `__memcmpeq` — glibc internal: returns 0 if equal, non-zero otherwise.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __memcmpeq(s1: *const c_void, s2: *const c_void, n: usize) -> c_int {
    unsafe { memcmp(s1, s2, n) }
}

// ── Locale aliases (ignore locale, forward to base) ─────────────────────────

/// `strcasecmp_l` — locale-aware case-insensitive string compare.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strcasecmp_l(
    s1: *const c_char,
    s2: *const c_char,
    _locale: *mut c_void,
) -> c_int {
    unsafe { strcasecmp(s1, s2) }
}

/// `strncasecmp_l` — locale-aware case-insensitive string compare with length.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strncasecmp_l(
    s1: *const c_char,
    s2: *const c_char,
    n: usize,
    _locale: *mut c_void,
) -> c_int {
    unsafe { strncasecmp(s1, s2, n) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcasecmp_l(
    s1: *const c_char,
    s2: *const c_char,
    l: *mut c_void,
) -> c_int {
    unsafe { strcasecmp_l(s1, s2, l) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strncasecmp_l(
    s1: *const c_char,
    s2: *const c_char,
    n: usize,
    l: *mut c_void,
) -> c_int {
    unsafe { strncasecmp_l(s1, s2, n, l) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcoll_l(
    s1: *const c_char,
    s2: *const c_char,
    _l: *mut c_void,
) -> c_int {
    unsafe { strcmp(s1, s2) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strxfrm_l(
    dst: *mut c_char,
    src: *const c_char,
    n: usize,
    _l: *mut c_void,
) -> usize {
    unsafe { strxfrm(dst, src, n) }
}

// ── GCC constant-optimized string function variants ─────────────────────────

/// `__strsep_g` — generic strsep (same as strsep).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strsep_g(
    stringp: *mut *mut c_char,
    delim: *const c_char,
) -> *mut c_char {
    unsafe { strsep(stringp, delim) }
}

/// `__strsep_1c` — strsep optimized for single-char delimiter.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strsep_1c(stringp: *mut *mut c_char, delim: c_char) -> *mut c_char {
    let buf: [c_char; 2] = [delim, 0];
    unsafe { strsep(stringp, buf.as_ptr()) }
}

/// `__strsep_2c` — strsep optimized for two-char delimiter.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strsep_2c(
    stringp: *mut *mut c_char,
    d1: c_char,
    d2: c_char,
) -> *mut c_char {
    let buf: [c_char; 3] = [d1, d2, 0];
    unsafe { strsep(stringp, buf.as_ptr()) }
}

/// `__strsep_3c` — strsep optimized for three-char delimiter.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strsep_3c(
    stringp: *mut *mut c_char,
    d1: c_char,
    d2: c_char,
    d3: c_char,
) -> *mut c_char {
    let buf: [c_char; 4] = [d1, d2, d3, 0];
    unsafe { strsep(stringp, buf.as_ptr()) }
}

/// `__strpbrk_c2` — strpbrk optimized for 2-char accept set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strpbrk_c2(s: *const c_char, a1: c_int, a2: c_int) -> *mut c_char {
    let accept: [c_char; 3] = [a1 as c_char, a2 as c_char, 0];
    unsafe { strpbrk(s, accept.as_ptr()) }
}

/// `__strpbrk_c3` — strpbrk optimized for 3-char accept set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strpbrk_c3(
    s: *const c_char,
    a1: c_int,
    a2: c_int,
    a3: c_int,
) -> *mut c_char {
    let accept: [c_char; 4] = [a1 as c_char, a2 as c_char, a3 as c_char, 0];
    unsafe { strpbrk(s, accept.as_ptr()) }
}

/// `__strcspn_c1` — strcspn optimized for 1-char reject set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcspn_c1(s: *const c_char, r: c_int) -> usize {
    let reject: [c_char; 2] = [r as c_char, 0];
    unsafe { strcspn(s, reject.as_ptr()) }
}

/// `__strcspn_c2` — strcspn optimized for 2-char reject set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcspn_c2(s: *const c_char, r1: c_int, r2: c_int) -> usize {
    let reject: [c_char; 3] = [r1 as c_char, r2 as c_char, 0];
    unsafe { strcspn(s, reject.as_ptr()) }
}

/// `__strcspn_c3` — strcspn optimized for 3-char reject set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcspn_c3(s: *const c_char, r1: c_int, r2: c_int, r3: c_int) -> usize {
    let reject: [c_char; 4] = [r1 as c_char, r2 as c_char, r3 as c_char, 0];
    unsafe { strcspn(s, reject.as_ptr()) }
}

/// `__strspn_c1` — strspn optimized for 1-char accept set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strspn_c1(s: *const c_char, a: c_int) -> usize {
    let accept: [c_char; 2] = [a as c_char, 0];
    unsafe { strspn(s, accept.as_ptr()) }
}

/// `__strspn_c2` — strspn optimized for 2-char accept set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strspn_c2(s: *const c_char, a1: c_int, a2: c_int) -> usize {
    let accept: [c_char; 3] = [a1 as c_char, a2 as c_char, 0];
    unsafe { strspn(s, accept.as_ptr()) }
}

/// `__strspn_c3` — strspn optimized for 3-char accept set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strspn_c3(s: *const c_char, a1: c_int, a2: c_int, a3: c_int) -> usize {
    let accept: [c_char; 4] = [a1 as c_char, a2 as c_char, a3 as c_char, 0];
    unsafe { strspn(s, accept.as_ptr()) }
}

/// `__strtok_r_1c` — strtok_r optimized for single-char delimiter.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtok_r_1c(
    s: *mut c_char,
    delim: c_char,
    saveptr: *mut *mut c_char,
) -> *mut c_char {
    let buf: [c_char; 2] = [delim, 0];
    unsafe { strtok_r(s, buf.as_ptr(), saveptr) }
}

/// `__strcpy_small` — glibc internal memcpy-based strcpy for small strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcpy_small(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    unsafe { strcpy(dst, src) }
}

/// `__stpcpy_small` — glibc internal stpcpy for small strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __stpcpy_small(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    unsafe { stpcpy(dst, src) }
}

// ── __strto*_internal — glibc internal conversion with group flag ───────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtol_internal(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _group: c_int,
) -> c_long {
    unsafe { crate::stdlib_abi::strtol(nptr, endptr, base) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtoul_internal(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _group: c_int,
) -> c_ulong {
    unsafe { crate::stdlib_abi::strtoul(nptr, endptr, base) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtoll_internal(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _group: c_int,
) -> c_longlong {
    unsafe { crate::stdlib_abi::strtoll(nptr, endptr, base) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtoull_internal(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _group: c_int,
) -> c_ulonglong {
    unsafe { crate::stdlib_abi::strtoull(nptr, endptr, base) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtod_internal(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    _group: c_int,
) -> f64 {
    unsafe { crate::stdlib_abi::strtod(nptr, endptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtof_internal(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    _group: c_int,
) -> f32 {
    unsafe { crate::stdlib_abi::strtof(nptr, endptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtold_internal(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    _group: c_int,
) -> f64 {
    // long double -> f64 on Rust (no f80 support)
    unsafe { crate::stdlib_abi::strtod(nptr, endptr) }
}

// ── __strto*_l — locale variants forwarding to existing _l functions ────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtol_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    l: *mut c_void,
) -> c_long {
    unsafe { crate::stdlib_abi::strtol_l(nptr, endptr, base, l) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtoul_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    l: *mut c_void,
) -> c_ulong {
    unsafe { crate::stdlib_abi::strtoul_l(nptr, endptr, base, l) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtoll_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    l: *mut c_void,
) -> c_longlong {
    unsafe { crate::stdlib_abi::strtoll_l(nptr, endptr, base, l) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtoull_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    l: *mut c_void,
) -> c_ulonglong {
    unsafe { crate::stdlib_abi::strtoull_l(nptr, endptr, base, l) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtod_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    _l: *mut c_void,
) -> f64 {
    unsafe { crate::stdlib_abi::strtod(nptr, endptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtof_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    _l: *mut c_void,
) -> f32 {
    unsafe { crate::stdlib_abi::strtof(nptr, endptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtold_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    _l: *mut c_void,
) -> f64 {
    unsafe { crate::stdlib_abi::strtod(nptr, endptr) }
}

/// `__strftime_l` — locale-aware strftime forwarding.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strftime_l(
    s: *mut c_char,
    max: usize,
    format: *const c_char,
    tm: *const c_void,
    _l: *mut c_void,
) -> usize {
    unsafe { crate::unistd_abi::strftime_l(s, max, format, tm, _l) }
}

/// `__strfmon_l` — locale-aware strfmon forwarding.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strfmon_l(
    s: *mut c_char,
    maxsize: usize,
    _l: *mut c_void,
    format: *const c_char,
    mut args: ...
) -> isize {
    if s.is_null() || format.is_null() || maxsize == 0 {
        return -1;
    }
    let val: f64 = unsafe { args.arg() };
    let formatted = format!("{val:.2}");
    let bytes = formatted.as_bytes();
    let copy_len = bytes.len().min(maxsize - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), s as *mut u8, copy_len);
        *s.add(copy_len) = 0;
    }
    copy_len as isize
}

// ---------------------------------------------------------------------------
// timingsafe_bcmp / timingsafe_memcmp
// ---------------------------------------------------------------------------
//
// OpenBSD-origin constant-time byte comparators (also exposed by glibc 2.39+).
// Both delegate the byte-level fold to `frankenlibc_core::string::timingsafe`,
// which is `#![deny(unsafe_code)]` and CT-by-construction.

/// OpenBSD `timingsafe_bcmp` — constant-time byte equality test.
///
/// Returns `0` iff the first `n` bytes of `b1` and `b2` are equal,
/// non-zero (specifically `1`) otherwise. Always touches every byte
/// regardless of where the inputs differ.
///
/// # Safety
///
/// Caller must ensure `b1` and `b2` are valid for `n` bytes each.
/// `n == 0` is always safe.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timingsafe_bcmp(b1: *const c_void, b2: *const c_void, n: usize) -> c_int {
    if n == 0 {
        return 0;
    }
    if b1.is_null() || b2.is_null() {
        return if b1 == b2 { 0 } else { 1 };
    }
    // SAFETY: caller contract requires both pointers valid for `n` bytes.
    unsafe {
        let a = std::slice::from_raw_parts(b1.cast::<u8>(), n);
        let b = std::slice::from_raw_parts(b2.cast::<u8>(), n);
        frankenlibc_core::string::timingsafe::bcmp(a, b, n)
    }
}

/// OpenBSD `timingsafe_memcmp` — constant-time, sign-preserving compare.
///
/// Returns `0` iff equal, negative if the first differing byte in `b1`
/// is less than the corresponding byte in `b2`, positive otherwise —
/// matching `memcmp` semantics, but with branch-free execution.
///
/// # Safety
///
/// Caller must ensure `b1` and `b2` are valid for `n` bytes each.
/// `n == 0` is always safe.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timingsafe_memcmp(
    b1: *const c_void,
    b2: *const c_void,
    n: usize,
) -> c_int {
    if n == 0 {
        return 0;
    }
    if b1.is_null() || b2.is_null() {
        if b1 == b2 {
            return 0;
        }
        return if b1.is_null() { -1 } else { 1 };
    }
    // SAFETY: caller contract requires both pointers valid for `n` bytes.
    unsafe {
        let a = std::slice::from_raw_parts(b1.cast::<u8>(), n);
        let b = std::slice::from_raw_parts(b2.cast::<u8>(), n);
        frankenlibc_core::string::timingsafe::memcmp(a, b, n)
    }
}

// ---------------------------------------------------------------------------
// strmode (BSD mode-bit-to-`ls -l`-style-string)
// ---------------------------------------------------------------------------

/// BSD `strmode(mode, p)` — write the 11-character `ls -l`-style
/// representation of `mode` into `p`, plus a trailing NUL (12 bytes
/// total). The byte-level work happens in
/// `frankenlibc_core::stat::strmode_bytes`; this shim only owns the
/// raw-pointer copy + NUL termination.
///
/// # Safety
///
/// Caller must ensure `p` is non-NULL and points to writable storage
/// of at least 12 bytes — the length BSD's strmode prototype implies.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strmode(mode: libc::mode_t, p: *mut c_char) {
    if p.is_null() {
        return;
    }
    let bytes = frankenlibc_core::stat::strmode_bytes(mode);
    // SAFETY: caller contract requires 12 writable bytes at `p`.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p as *mut u8, 11);
        *p.add(11) = 0;
    }
}
