//! ABI layer for `<string.h>` functions.
//!
//! Each function is an `extern "C"` entry point that:
//! 1. Validates pointer arguments through the membrane pipeline
//! 2. In hardened mode, applies healing (bounds clamping, null truncation)
//! 3. Delegates to `frankenlibc-core` safe implementations or inline unsafe primitives

use std::ffi::{c_char, c_int, c_long, c_longlong, c_ulong, c_ulonglong, c_void};
use std::fmt::Write as _;
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

#[cfg(feature = "owned-tls-cache")]
static STRING_MEMBRANE_DEPTH_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<u32> =
    crate::owned_tls_cache::OwnedTlsCache::new(|| 0);

#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static STRING_MEMBRANE_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
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
        #[cfg(feature = "owned-tls-cache")]
        {
            STRING_MEMBRANE_DEPTH_OWNED_TLS.with(|depth| {
                *depth = depth.saturating_sub(1);
            });
        }
        #[cfg(not(feature = "owned-tls-cache"))]
        let _ = STRING_MEMBRANE_DEPTH.try_with(|depth| {
            let current = depth.get();
            depth.set(current.saturating_sub(1));
        });
    }
}

fn enter_string_membrane_guard() -> Option<StringMembraneGuard> {
    if string_raw_passthrough_active() {
        return None;
    }
    if runtime_policy::is_runtime_ready() {
        if runtime_policy::in_policy_reentry_context() {
            return None;
        }
        if !crate::pthread_abi::pthread_tls_access_active()
            && crate::pthread_abi::in_threading_policy_context()
        {
            return None;
        }
    }
    #[cfg(feature = "owned-tls-cache")]
    {
        STRING_MEMBRANE_DEPTH_OWNED_TLS.with(|depth| {
            if *depth > 0 {
                None
            } else {
                *depth += 1;
                Some(StringMembraneGuard)
            }
        })
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
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
}

#[inline]
fn string_raw_passthrough_active() -> bool {
    runtime_policy::bootstrap_passthrough_active()
        || runtime_policy::runtime_policy_tls_access_active()
        || crate::pthread_abi::pthread_tls_access_active()
        || crate::malloc_abi::in_allocator_reentry_context()
        || frankenlibc_membrane::ptr_validator::in_validation_context()
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

#[cfg(feature = "runtime-tracing")]
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
        #[cfg(feature = "runtime-tracing")]
        tracing::info!(
            target: "simd_dispatch",
            function,
            selected_impl = dispatch.label,
            cpu_features = string_simd_feature_list(mask),
            lane_bytes = dispatch.lane_bytes
        );
        #[cfg(not(feature = "runtime-tracing"))]
        let _ = (dispatch, mask);
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
    // Strict mode: skip certification and assume SIMD operations are safe.
    // This avoids CliffordController overhead for trusted workloads.
    if runtime_policy::strict_passthrough_active() {
        return Some(StringSimdDispatch::from_isa(isa));
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

/// Recursion-safe overlapping power-of-2 forward copy for DISJOINT regions (memcpy
/// semantics). Explicit unaligned u128/u64/u32 loads+stores are never coalesced into an
/// `@llvm.memcpy` (which would resolve to this interposed symbol → self-recursion), so no
/// `volatile` is needed; the overlapping tail replaces the per-byte volatile tail. Each
/// store re-writes already-correct bytes at most (disjoint src), so the result is
/// byte-identical to the scalar copy. NOT for memmove (overlap-unsafe). `n >= 1`.
/// AVX2 128-byte-unrolled `vmovdqu` asm copy loop + minimal straight-line overlapping
/// 32-byte tail. Inline asm ⇒ never lowered to `@llvm.memcpy` (recursion-safe). Closes the
/// medium-copy gap: the Rust u128-pair loop emits 16-byte movups (half glibc's 32-byte
/// ymm); this matches glibc and beats it for n>=512. `vzeroupper` avoids the AVX↔SSE
/// transition penalty. Caller guarantees n >= 128 and AVX availability.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx")]
unsafe fn raw_avx_copy(dst: *mut u8, src: *const u8, n: usize) {
    unsafe {
        let mut d = dst;
        let mut s = src;
        let mut rem = n;
        core::arch::asm!(
            "2:",
            "vmovdqu ymm0, [{s}]",
            "vmovdqu ymm1, [{s}+32]",
            "vmovdqu ymm2, [{s}+64]",
            "vmovdqu ymm3, [{s}+96]",
            "vmovdqu [{d}], ymm0",
            "vmovdqu [{d}+32], ymm1",
            "vmovdqu [{d}+64], ymm2",
            "vmovdqu [{d}+96], ymm3",
            "add {s}, 128",
            "add {d}, 128",
            "sub {rem}, 128",
            "cmp {rem}, 128",
            "jae 2b",
            "vzeroupper",
            s = inout(reg) s,
            d = inout(reg) d,
            rem = inout(reg) rem,
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
            options(nostack),
        );
        let _ = (d, s);
        // rem ∈ [0,128): cover [n-rem,n) with the minimal count of straight-line,
        // overlapping 32-byte copies from the end (no loop ⇒ not @llvm.memcpy). n>=128.
        if rem > 96 {
            copy_unaligned_32(dst.add(n - 128), src.add(n - 128));
            copy_unaligned_32(dst.add(n - 96), src.add(n - 96));
            copy_unaligned_32(dst.add(n - 64), src.add(n - 64));
            copy_unaligned_32(dst.add(n - 32), src.add(n - 32));
        } else if rem > 64 {
            copy_unaligned_32(dst.add(n - 96), src.add(n - 96));
            copy_unaligned_32(dst.add(n - 64), src.add(n - 64));
            copy_unaligned_32(dst.add(n - 32), src.add(n - 32));
        } else if rem > 32 {
            copy_unaligned_32(dst.add(n - 64), src.add(n - 64));
            copy_unaligned_32(dst.add(n - 32), src.add(n - 32));
        } else if rem > 0 {
            copy_unaligned_32(dst.add(n - 32), src.add(n - 32));
        }
    }
}

#[inline]
unsafe fn raw_overlap_copy(dst: *mut u8, src: *const u8, n: usize) {
    unsafe {
        // Large copies: `rep movsb` (x86 ERMS) — glibc's large-memcpy path. Inline asm is
        // opaque to LLVM's loop-idiom recognizer, so (unlike a Rust copy loop) it is never
        // lowered to @llvm.memcpy into this interposed symbol — recursion-safe. Measured
        // 1.7x over the u128-pair copy loop and beats glibc for n in [4096,32768) (the
        // copy loop is ~1.5x slower than glibc there); below ~1024 ERMS startup loses, so
        // the threshold is 2048. DF=0 on entry (SysV ABI) ⇒ forward copy.
        #[cfg(target_arch = "x86_64")]
        if n >= 2048 {
            // SAFETY: copies exactly `n` bytes src→dst (caller-guaranteed disjoint & valid);
            // clobbers rcx/rsi/rdi/flags per the asm contract.
            core::arch::asm!(
                "rep movsb",
                inout("rcx") n => _,
                inout("rdi") dst => _,
                inout("rsi") src => _,
                options(nostack, preserves_flags),
            );
            return;
        }
        // Medium copies [128,2048): AVX2 vmovdqu loop (matches/beats glibc; the u128-pair
        // loop below emits only 16-byte movups). Gated on runtime AVX detection.
        #[cfg(target_arch = "x86_64")]
        if n >= 128 && std::is_x86_feature_detected!("avx") {
            // SAFETY: n>=128 and AVX confirmed available.
            raw_avx_copy(dst, src, n);
            return;
        }
        if n < 16 {
            if n >= 8 {
                std::ptr::write_unaligned(
                    dst.cast::<u64>(),
                    std::ptr::read_unaligned(src.cast::<u64>()),
                );
                std::ptr::write_unaligned(
                    dst.add(n - 8).cast::<u64>(),
                    std::ptr::read_unaligned(src.add(n - 8).cast::<u64>()),
                );
            } else if n >= 4 {
                std::ptr::write_unaligned(
                    dst.cast::<u32>(),
                    std::ptr::read_unaligned(src.cast::<u32>()),
                );
                std::ptr::write_unaligned(
                    dst.add(n - 4).cast::<u32>(),
                    std::ptr::read_unaligned(src.add(n - 4).cast::<u32>()),
                );
            } else {
                // n ∈ [1,3]: straight-line byte copies (no loop ⇒ not an @llvm.memcpy).
                *dst = *src;
                if n > 1 {
                    *dst.add(n - 1) = *src.add(n - 1);
                    *dst.add(n / 2) = *src.add(n / 2);
                }
            }
            return;
        }
        // n >= 16: 32-byte explicit copies for the bulk, then an overlapping 16-byte
        // copy for the [0,32) remainder (covers all of [i,n) without a volatile tail).
        let mut i = 0usize;
        while i + 32 <= n {
            copy_unaligned_32(dst.add(i), src.add(i));
            i += 32;
        }
        if i < n {
            if n - i > 16 {
                copy_unaligned_16(dst.add(i), src.add(i));
            }
            copy_unaligned_16(dst.add(n - 16), src.add(n - 16));
        }
    }
}

#[inline(never)]
unsafe fn raw_memcpy_bytes(dst: *mut u8, src: *const u8, n: usize) {
    // Wide-word forward copy (memcpy semantics: dst/src disjoint). We must not let
    // LLVM lower the copy to `@llvm.memcpy`, which in the shipped libc.so resolves
    // back to our own interposed `memcpy` symbol (self-recursion) and can pull in
    // dlvsym during init. The explicit u128 unaligned loads/stores in
    // `copy_unaligned_16/32` are never coalesced into an `@llvm.mem*` intrinsic, so
    // they stay recursion-safe while copying 16-32 bytes per step instead of one
    // volatile byte; the sub-16 tail stays volatile-byte. Pure pointer ops with no
    // SIMD-dispatch global state, so early-startup / reentrant callers are safe too.
    // This is the shared bulk-copy primitive behind strcpy/strcat/strncat and the
    // string_abi copy paths, so widening it here speeds all of them at once.
    // SAFETY: caller guarantees dst/src are valid for n bytes and do not overlap.
    unsafe {
        if n == 0 {
            return;
        }
        // Overlapping power-of-2 copy (recursion-safe; no per-byte volatile tail).
        // 1.5-2.5x over the old copy_unaligned+volatile-tail at small n; beats glibc
        // for n<32. Shared with raw_lane_memcpy_bytes.
        raw_overlap_copy(dst, src, n);
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
    // Wide-word overlap-aware move. `std::ptr::copy` compiles to `@llvm.memmove`,
    // which in the shipped libc.so resolves back to our own interposed `memmove`
    // symbol (self-recursion), so we move explicitly. Instead of one volatile byte
    // per step we use the same explicit u128 unaligned loads/stores as the memcpy
    // lane copier (`copy_unaligned_16/32`): LLVM does not coalesce those back into
    // an `@llvm.mem*` intrinsic, so they stay recursion-safe while moving 16-32
    // bytes per step (the sub-16 tail stays volatile-byte). These are pure pointer
    // ops with no SIMD-dispatch global state, so early-startup callers are safe too.
    // SAFETY: caller guarantees dst/src are valid for n bytes (may overlap).
    unsafe {
        let dst_addr = dst as usize;
        let src_addr = src as usize;
        // Disjoint regions (the common memmove case): route to the fast memcpy path
        // (overlapping small-n / AVX vmovdqu loop / rep movsb) — 1.4-2.5x over the
        // copy_unaligned+volatile loop, parity-to-win vs glibc memmove. Overlapping
        // copies are safe ONLY when truly disjoint, so the careful forward/backward
        // copy below still handles every overlapping case.
        if n != 0
            && (src_addr.saturating_add(n) <= dst_addr || dst_addr.saturating_add(n) <= src_addr)
        {
            raw_overlap_copy(dst, src, n);
            return;
        }
        if dst_addr <= src_addr || dst_addr >= src_addr.saturating_add(n) {
            // Forward copy (low -> high), safe when dst <= src or disjoint.
            // `copy_unaligned_32` reads each 16-byte half into a register before
            // storing it, and for dst <= src every store lands at an address <= the
            // address just read, so no source byte is overwritten before it is read.
            let mut i = 0usize;
            while i + 32 <= n {
                copy_unaligned_32(dst.add(i), src.add(i));
                i += 32;
            }
            if i + 16 <= n {
                copy_unaligned_16(dst.add(i), src.add(i));
                i += 16;
            }
            while i < n {
                std::ptr::write_volatile(dst.add(i), std::ptr::read_volatile(src.add(i)));
                i += 1;
            }
        } else {
            // Backward copy (high -> low) in 16-byte blocks for dst > src overlap.
            // `copy_unaligned_16` loads the whole block into one register before it
            // stores, so no unread source byte in the block is clobbered; processing
            // blocks top-down means any byte a store could overwrite belongs to an
            // already-copied higher block. The sub-16 low tail finishes byte-wise.
            let mut i = n;
            while i >= 16 {
                i -= 16;
                copy_unaligned_16(dst.add(i), src.add(i));
            }
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
        if *needle == 0 {
            return haystack as *mut c_char;
        }
        // Compute lengths with plain inline scalar scans (NO membrane / known_remaining
        // lookup) so this stays deadlock-safe on the early-startup / membrane-reentrant
        // path, then route the MATCH to the pure core Two-Way searcher instead of the old
        // naive O(hay*needle) double loop (a latent quadratic-DoS vector even here). core
        // memmem allocates nothing and holds no locks, so it is safe in this context.
        let mut hay_len = 0usize;
        while *haystack.add(hay_len) != 0 {
            hay_len += 1;
        }
        let mut needle_len = 0usize;
        while *needle.add(needle_len) != 0 {
            needle_len += 1;
        }
        if hay_len < needle_len {
            return std::ptr::null_mut();
        }
        let hay_slice = std::slice::from_raw_parts(haystack.cast::<u8>(), hay_len);
        let needle_slice = std::slice::from_raw_parts(needle.cast::<u8>(), needle_len);
        match frankenlibc_core::string::mem::memmem(hay_slice, hay_len, needle_slice, needle_len) {
            Some(idx) => haystack.add(idx) as *mut c_char,
            None => std::ptr::null_mut(),
        }
    }
}

/// AVX2 128-byte-unrolled `vmovdqu` STORE loop + minimal straight-line overlapping 32-byte
/// SSE tail. Inline asm ⇒ never lowered to `@llvm.memset` (recursion-safe). The volatile
/// u64 loop emits 8-byte stores (1/4 glibc's 32-byte ymm); this matches/beats glibc for
/// medium n. `vzeroupper` avoids the AVX↔SSE penalty (the tail is pure SSE). Caller
/// guarantees n >= 128 and AVX availability.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx")]
unsafe fn raw_avx_memset(dst: *mut u8, value: u8, n: usize) {
    use core::arch::x86_64::{__m128i, _mm256_set1_epi8, _mm_set1_epi8, _mm_storeu_si128};
    unsafe {
        let v = _mm256_set1_epi8(value as i8);
        let mut d = dst;
        let mut rem = n;
        core::arch::asm!(
            "2:",
            "vmovdqu [{d}], {v}",
            "vmovdqu [{d}+32], {v}",
            "vmovdqu [{d}+64], {v}",
            "vmovdqu [{d}+96], {v}",
            "add {d}, 128",
            "sub {rem}, 128",
            "cmp {rem}, 128",
            "jae 2b",
            "vzeroupper",
            d = inout(reg) d,
            rem = inout(reg) rem,
            v = in(ymm_reg) v,
            options(nostack),
        );
        let _ = d;
        // rem ∈ [0,128): minimal straight-line overlapping 32-byte SSE stores from the end.
        let vx = _mm_set1_epi8(value as i8);
        let set32 = |off: usize| {
            _mm_storeu_si128(dst.add(off).cast::<__m128i>(), vx);
            _mm_storeu_si128(dst.add(off + 16).cast::<__m128i>(), vx);
        };
        if rem > 96 {
            set32(n - 128);
            set32(n - 96);
            set32(n - 64);
            set32(n - 32);
        } else if rem > 64 {
            set32(n - 96);
            set32(n - 64);
            set32(n - 32);
        } else if rem > 32 {
            set32(n - 64);
            set32(n - 32);
        } else if rem > 0 {
            set32(n - 32);
        }
    }
}

#[inline(never)]
unsafe fn raw_memset_bytes(dst: *mut u8, value: u8, n: usize) {
    // Wide-word volatile fill. The fill MUST NOT lower to an `@llvm.memset`
    // intrinsic: in the shipped `libc.so` that intrinsic resolves to our own
    // interposed `memset` symbol, so a plain `for b { *b = value }` / `.fill()`
    // would self-recurse. Volatile stores are never coalesced by LLVM's loop-
    // idiom recognizer, so they stay recursion-safe — but a byte-at-a-time
    // volatile loop emits one store per byte (a 4 KiB fill = 4096 stores). Here
    // we broadcast the byte into a `u64` and store 8 bytes per volatile op
    // (32 bytes per unrolled iteration), an 8-32x reduction in store count that
    // produces byte-for-byte identical memory to the scalar loop.
    //
    // `write_volatile::<u64>` requires 8-byte alignment, so the leading bytes up
    // to the next 8-byte boundary (and the sub-8-byte tail) are filled byte-wise;
    // every wide store is therefore naturally aligned.
    // SAFETY: caller guarantees dst is valid for n bytes; the offsets below stay
    // within `0..n`, and each `*mut u64` store starts on an 8-aligned address.
    unsafe {
        if n == 0 {
            return;
        }

        // Straight-line overlapping-store small-n fast path. Unlike the volatile loop
        // below, these are NOT loops, so LLVM's loop-idiom recognizer cannot fold them
        // into an `@llvm.memset` call (which resolves to this interposed symbol and would
        // self-recurse) — so no `volatile` is needed and wide vector/word stores are
        // used directly. Measured 1.7-2.4x over the volatile path, parity-to-win vs glibc
        // for n < 32 (the common small-fill range; memset is the hottest libc fn).
        #[cfg(target_arch = "x86_64")]
        if (16..64).contains(&n) {
            use core::arch::x86_64::{__m128i, _mm_set1_epi8, _mm_storeu_si128};
            // SSE2 is baseline on x86_64. Explicit unaligned 16-byte stores covering the
            // head [0,32) and tail [n-32,n) (overlapping) set every byte to `value`,
            // byte-identical to the scalar fill. No loop ⇒ never lowered to @llvm.memset.
            // n∈[16,32): the head's 2nd store and the tail overlap; n∈[32,64): 4 stores.
            let v = _mm_set1_epi8(value as i8);
            _mm_storeu_si128(dst.cast::<__m128i>(), v);
            if n >= 32 {
                _mm_storeu_si128(dst.add(16).cast::<__m128i>(), v);
                _mm_storeu_si128(dst.add(n - 32).cast::<__m128i>(), v);
            }
            _mm_storeu_si128(dst.add(n - 16).cast::<__m128i>(), v);
            return;
        }
        if (8..16).contains(&n) {
            let word = (value as u64).wrapping_mul(0x0101_0101_0101_0101);
            // SAFETY: n>=8 so both 8-byte windows are within [0,n) (they may overlap).
            std::ptr::write_unaligned(dst.cast::<u64>(), word);
            std::ptr::write_unaligned(dst.add(n - 8).cast::<u64>(), word);
            return;
        }

        // Large fills: `rep stosb` (x86 ERMS) — glibc's own large-memset path. Inline
        // asm is opaque to LLVM's loop-idiom recognizer, so (unlike a Rust vector-store
        // loop) it is NEVER lowered to an @llvm.memset call into this interposed symbol —
        // recursion-safe without volatile. Measured 2.3x over the volatile u64 loop and
        // parity-to-win vs glibc for n>=1024 (beats glibc at 64 KiB); ERMS startup cost
        // makes it lose for smaller n, so the [64,1024) range keeps the volatile loop.
        #[cfg(target_arch = "x86_64")]
        if n >= 2048 {
            // SAFETY: fills exactly `n` bytes at `dst` with `value` (caller-guaranteed
            // valid for n writes); clobbers rcx/rdi/flags per the asm contract.
            core::arch::asm!(
                "rep stosb",
                inout("rcx") n => _,
                inout("rdi") dst => _,
                in("al") value,
                options(nostack, preserves_flags),
            );
            return;
        }
        // Medium fills [128,2048): AVX2 vmovdqu store loop (beats glibc; the volatile loop
        // below emits only 8-byte stores, and rep stosb loses here on ERMS startup). Gated
        // on runtime AVX detection.
        #[cfg(target_arch = "x86_64")]
        if n >= 128 && std::is_x86_feature_detected!("avx") {
            // SAFETY: n>=128 and AVX confirmed available.
            raw_avx_memset(dst, value, n);
            return;
        }

        let word = (value as u64).wrapping_mul(0x0101_0101_0101_0101);
        let mut i = 0usize;

        // Head: byte-fill until `dst + i` reaches an 8-byte boundary.
        let head = ((dst as usize).wrapping_neg() & 7).min(n);
        while i < head {
            std::ptr::write_volatile(dst.add(i), value);
            i += 1;
        }

        // Body: 32-byte unrolled aligned u64 volatile stores, then 8-byte stores.
        while i + 32 <= n {
            let p = dst.add(i).cast::<u64>();
            std::ptr::write_volatile(p, word);
            std::ptr::write_volatile(p.add(1), word);
            std::ptr::write_volatile(p.add(2), word);
            std::ptr::write_volatile(p.add(3), word);
            i += 32;
        }
        while i + 8 <= n {
            std::ptr::write_volatile(dst.add(i).cast::<u64>(), word);
            i += 8;
        }

        // Tail: remaining sub-8-byte bytes.
        while i < n {
            std::ptr::write_volatile(dst.add(i), value);
            i += 1;
        }
    }
}

/// Benchmark/test hook: exposes [`raw_memset_bytes`] under a stable name so the
/// `frankenlibc-bench` crate can measure the shipped wide-word fill against the
/// host `memset` without going through the no-mangle `memset` symbol (which
/// would collide with libc at link time). Not part of the public ABI.
///
/// # Safety
/// `dst` must be valid for `n` writes.
#[doc(hidden)]
pub unsafe fn bench_raw_memset_bytes(dst: *mut u8, value: u8, n: usize) {
    unsafe { raw_memset_bytes(dst, value, n) }
}

/// Benchmark/test hook for the shipped overlap-aware [`raw_memmove_bytes`] move.
/// Not part of the public ABI.
///
/// # Safety
/// `dst`/`src` must be valid for `n` bytes (may overlap).
#[doc(hidden)]
pub unsafe fn bench_raw_memmove_bytes(dst: *mut u8, src: *const u8, n: usize) {
    unsafe { raw_memmove_bytes(dst, src, n) }
}

/// Benchmark/test hook for the shared bulk-copy primitive [`raw_memcpy_bytes`]
/// (behind strcpy/strcat/strncat). Not part of the public ABI.
///
/// # Safety
/// `dst`/`src` must be valid for `n` bytes and must not overlap.
#[doc(hidden)]
pub unsafe fn bench_raw_memcpy_bytes(dst: *mut u8, src: *const u8, n: usize) {
    unsafe { raw_memcpy_bytes(dst, src, n) }
}

/// Benchmark/test hook for the SWAR [`scan_c_string`] NUL scanner (behind
/// strcpy/stpcpy/strncat). Not part of the public ABI.
///
/// # Safety
/// `ptr` must be NUL-terminated when `bound` is `None`, else valid for `bound`
/// bytes.
#[doc(hidden)]
pub unsafe fn bench_scan_c_string(ptr: *const c_char, bound: Option<usize>) -> (usize, bool) {
    unsafe { scan_c_string(ptr, bound) }
}

/// Benchmark/test hook for the SWAR [`scan_c_string_for_byte`] scanner (behind
/// strchr). Not part of the public ABI.
///
/// # Safety
/// `ptr` must be NUL-terminated when `bound` is `None`, else valid for `bound` bytes.
#[doc(hidden)]
pub unsafe fn bench_scan_c_string_for_byte(
    ptr: *const c_char,
    target: u8,
    bound: Option<usize>,
) -> (usize, bool, bool) {
    unsafe { scan_c_string_for_byte(ptr, target, bound) }
}

/// Benchmark/test hook for the SWAR [`scan_strcmp`] scanner (behind
/// strcmp/strncmp). Not part of the public ABI.
///
/// # Safety
/// `s1`/`s2` must be NUL-terminated, or valid for `bound` bytes.
#[doc(hidden)]
pub unsafe fn bench_scan_strcmp(
    s1: *const c_char,
    s2: *const c_char,
    bound: usize,
) -> (usize, bool) {
    unsafe { scan_strcmp(s1, s2, bound) }
}

/// Benchmark/test hook for the SWAR [`scan_c_string_last_byte`] scanner (behind
/// strrchr). Not part of the public ABI.
///
/// # Safety
/// `ptr` must be NUL-terminated when `bound` is `None`, else valid for `bound` bytes.
#[doc(hidden)]
pub unsafe fn bench_scan_c_string_last_byte(
    ptr: *const c_char,
    target: u8,
    bound: Option<usize>,
) -> (Option<usize>, usize, bool) {
    unsafe { scan_c_string_last_byte(ptr, target, bound) }
}

/// Test hook: per-lane SWAR ASCII lowercase, for exhaustive parity vs
/// `to_ascii_lowercase`. Not part of the public ABI.
#[doc(hidden)]
pub fn test_swar_ascii_lower(w: u64) -> u64 {
    swar_ascii_lower(w)
}

/// Benchmark/test hook for the fused SWAR [`scan_strcasecmp`] (behind
/// strcasecmp/strncasecmp). Not part of the public ABI.
///
/// # Safety
/// `s1`/`s2` must be NUL-terminated, or valid for `bound` bytes.
#[doc(hidden)]
pub unsafe fn bench_scan_strcasecmp(s1: *const c_char, s2: *const c_char, bound: usize) -> c_int {
    unsafe { scan_strcasecmp(s1, s2, bound).0 }
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
        if n == 0 {
            return;
        }
        if lane_bytes >= 16 {
            // Overlapping power-of-2 copy (recursion-safe, no per-byte volatile tail) —
            // the wide lane the dispatch selected. 1.5-2.5x over the old
            // copy_unaligned+volatile-tail at small n; beats glibc for n<32.
            raw_overlap_copy(dst, src, n);
            return;
        }
        // lane_bytes < 16 (raw passthrough): pure volatile byte copy, unchanged.
        let mut i = 0usize;
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
/// Sign of the first differing byte in `[lo, hi)` (`-1`/`+1`), or `0` if equal.
/// Only ever called on a window already known to contain a difference (the equal
/// case returns 0 harmlessly).
#[inline]
unsafe fn memcmp_first_diff(s1: *const u8, s2: *const u8, lo: usize, hi: usize) -> c_int {
    let mut j = lo;
    while j < hi {
        // SAFETY: caller guarantees `[lo, hi) ⊆ [0, n)` readable.
        let av = unsafe { *s1.add(j) };
        let bv = unsafe { *s2.add(j) };
        if av != bv {
            return if av < bv { -1 } else { 1 };
        }
        j += 1;
    }
    0
}

unsafe fn raw_lane_memcmp_bytes(
    s1: *const u8,
    s2: *const u8,
    n: usize,
    lane_bytes: usize,
) -> c_int {
    // SAFETY: caller guarantees both regions are readable for n bytes.
    unsafe {
        let mut i = 0usize;
        if lane_bytes >= 16 {
            // 32-byte main loop for the bulk. `chunk_equal_32` is two SSE2 u128
            // compares so this is valid for the whole lane_bytes>=16 path (no AVX
            // required); a 16-byte-lane dispatch still gets the wider stride here.
            while i + 32 <= n {
                if !chunk_equal_32(s1.add(i), s2.add(i)) {
                    return memcmp_first_diff(s1, s2, i, i + 32);
                }
                i += 32;
            }
            // glibc-style overlapping power-of-2 tail: after the 32-byte chunks the
            // remainder r = n - i is in [0, 32); one overlapping wide load per size
            // class replaces the per-byte scalar tail (n=31 was 1×16B + 15 scalar; now
            // 2×16B). Each window ends at n so it stays in bounds; the overlapped
            // prefix is already equal, so the first mismatch found is the true first
            // differing byte. `chunk_equal_32/16` are SSE2 (u128) so the 32-byte main
            // loop is valid even when the dispatch picked a 16-byte lane. (Was the
            // small-n memcmp floor: ~8x vs glibc → parity, bd string-scan vein.)
            if i == n {
                return 0;
            }
            let r = n - i;
            if r >= 16 {
                if !chunk_equal_16(s1.add(i), s2.add(i)) {
                    return memcmp_first_diff(s1, s2, i, i + 16);
                }
                let off = n - 16;
                if !chunk_equal_16(s1.add(off), s2.add(off)) {
                    return memcmp_first_diff(s1, s2, off, n);
                }
            } else if r >= 8 {
                if core::ptr::read_unaligned(s1.add(i).cast::<u64>()) != core::ptr::read_unaligned(s2.add(i).cast::<u64>())
                {
                    return memcmp_first_diff(s1, s2, i, i + 8);
                }
                let off = n - 8;
                if core::ptr::read_unaligned(s1.add(off).cast::<u64>())
                    != core::ptr::read_unaligned(s2.add(off).cast::<u64>())
                {
                    return memcmp_first_diff(s1, s2, off, n);
                }
            } else if r >= 4 {
                if core::ptr::read_unaligned(s1.add(i).cast::<u32>()) != core::ptr::read_unaligned(s2.add(i).cast::<u32>())
                {
                    return memcmp_first_diff(s1, s2, i, i + 4);
                }
                let off = n - 4;
                if core::ptr::read_unaligned(s1.add(off).cast::<u32>())
                    != core::ptr::read_unaligned(s2.add(off).cast::<u32>())
                {
                    return memcmp_first_diff(s1, s2, off, n);
                }
            } else {
                return memcmp_first_diff(s1, s2, i, n);
            }
            return 0;
        }
        // lane_bytes < 16 (raw passthrough): pure scalar, unchanged.
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
unsafe fn raw_lane_strlen_bytes(s: *const c_char, _lane_bytes: usize) -> usize {
    // SWAR word-at-a-time NUL scan via the shared, exhaustively-gated
    // `scan_c_string`. The old body chunked by `lane_bytes` but still compared
    // one byte at a time (data-dependent early return = unvectorizable); the SWAR
    // scan supersedes it (5-15x), so the dispatch hint is no longer needed.
    // SAFETY: caller guarantees a valid NUL-terminated string.
    unsafe { scan_c_string(s, None).0 }
}

#[inline(never)]
unsafe fn raw_lane_strnlen_bytes(
    s: *const c_char,
    max: usize,
    _lane_bytes: usize,
) -> (usize, bool) {
    // SWAR bounded NUL scan via the shared `scan_c_string`, which has the identical
    // `(index_of_nul_or_max, found_nul)` contract. Supersedes the old byte-chunked
    // loop with the proven word-at-a-time scan.
    // SAFETY: caller guarantees `s` readable up to `max`.
    unsafe { scan_c_string(s, Some(max)) }
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
/// SWAR zero-byte test: true iff any byte of `w` is 0. The classic
/// `(w - 0x01..) & ~w & 0x80..` haszero trick — a candidate that can false-flag
/// only when a high bit is set, so the caller resolves the exact index byte-wise.
#[inline(always)]
fn swar_word_has_zero(w: u64) -> bool {
    w.wrapping_sub(0x0101_0101_0101_0101) & !w & 0x8080_8080_8080_8080 != 0
}

/// Scan a C string for its terminating NUL, word-at-a-time (SWAR) instead of
/// byte-at-a-time. Returns `(index_of_nul_or_limit, found_nul)`.
///
/// Bounded mode reads only within `limit` (8-byte windows then a byte tail), so
/// it never over-reads. Unbounded mode aligns the pointer to 8 bytes first, then
/// reads *aligned* u64s: an 8-aligned 8-byte load never straddles a 4096-byte
/// page boundary, so it cannot fault past the NUL's own (mapped) page — the same
/// safety argument glibc/musl strlen rely on.
pub(crate) unsafe fn scan_c_string(ptr: *const c_char, bound: Option<usize>) -> (usize, bool) {
    let p = ptr.cast::<u8>();
    match bound {
        Some(limit) => {
            use core::simd::Simd;
            use core::simd::cmp::SimdPartialEq;
            // Small bounded scan in [16, 32): the 32-byte loop below can't run, so the
            // old code fell to an 8-byte SWAR + scalar tail (limit=31 = 3×8B SWAR + 7
            // scalar). glibc-style two OVERLAPPING 16-byte SIMD probes — `[0,16)` and
            // `[limit-16, limit)` — cover all `limit` bytes in-bounds (caller guarantees
            // `limit` readable bytes). First-NUL ordering holds: probe 0 owns `[0,16)`;
            // if empty, every NUL position < 16 is ruled out so probe 1's lowest set bit
            // is the true first NUL ≥ 16. Benefits strnlen + every bounded scan caller.
            if (16..32).contains(&limit) {
                let v0 = Simd::<u8, 16>::from_slice(unsafe {
                    core::slice::from_raw_parts(p, 16)
                });
                let m0 = v0.simd_eq(Simd::splat(0)).to_bitmask();
                if m0 != 0 {
                    return (m0.trailing_zeros() as usize, true);
                }
                let off = limit - 16;
                let v1 = Simd::<u8, 16>::from_slice(unsafe {
                    core::slice::from_raw_parts(p.add(off), 16)
                });
                let m1 = v1.simd_eq(Simd::splat(0)).to_bitmask();
                if m1 != 0 {
                    return (off + m1.trailing_zeros() as usize, true);
                }
                return (limit, false);
            }
            let mut i = 0usize;
            // Wide 32-byte portable-SIMD NUL scan (AVX width, like glibc's
            // strnlen). Bounded mode guarantees `limit` readable bytes, so a
            // 32-byte load is in-bounds whenever i+32 <= limit. NUL-free panels
            // advance 32; a panel containing a NUL drops to the 8-byte SWAR /
            // scalar tail below, which returns the exact NUL index unchanged.
            while i + 32 <= limit {
                use core::simd::Simd;
                use core::simd::cmp::SimdPartialEq;
                // SAFETY: [i, i+32) ⊆ [0, limit); `limit` bytes are readable.
                let v = Simd::<u8, 32>::from_slice(unsafe {
                    core::slice::from_raw_parts(p.add(i), 32)
                });
                // O(1) NUL index via the SIMD mask instead of breaking to the 8-byte SWAR
                // tail to re-locate the byte (same fix as wmemchr/memrchr).
                let mask = v.simd_eq(Simd::splat(0)).to_bitmask();
                if mask != 0 {
                    return (i + mask.trailing_zeros() as usize, true);
                }
                i += 32;
            }
            while i + 8 <= limit {
                // SAFETY: [i, i+8) ⊆ [0, limit); caller guarantees `limit` readable bytes.
                let w = unsafe { core::ptr::read_unaligned(p.add(i).cast::<u64>()) };
                if swar_word_has_zero(w) {
                    for j in 0..8 {
                        // SAFETY: i+j < limit.
                        if unsafe { *p.add(i + j) } == 0 {
                            return (i + j, true);
                        }
                    }
                }
                i += 8;
            }
            while i < limit {
                // SAFETY: i < limit.
                if unsafe { *p.add(i) } == 0 {
                    return (i, true);
                }
                i += 1;
            }
            (limit, false)
        }
        None => {
            use core::simd::Simd;
            use core::simd::cmp::SimdPartialEq;
            // glibc-style aligned-load-with-head-mask: align the pointer DOWN to a
            // 32-byte boundary and do one aligned load, masking off the `align`
            // bytes that precede `ptr`. A 32-byte-aligned 32-byte window is always
            // contained in a single 4 KiB page (32 | 4096), and the page holding
            // `ptr` is mapped, so reading the head bytes `base..ptr` (same page) is
            // safe. This eliminates BOTH the scalar head-align scan and the
            // per-iteration page-cross guard the old loop paid on every chunk — the
            // residual short-string floor identified in NEGATIVE_EVIDENCE.md.
            let align = (p as usize) & 31;
            // SAFETY: `base` is in the same mapped page as `p` (aligned down ≤ 31
            // bytes); the full 32-byte aligned window is in that page.
            let base = unsafe { p.sub(align) };
            let v0 = Simd::<u8, 32>::from_slice(unsafe {
                core::slice::from_raw_parts(base, 32)
            });
            // Clear the low `align` bits so head bytes before `p` can't match.
            let mask0 = v0.simd_eq(Simd::splat(0)).to_bitmask() & !((1u64 << align) - 1);
            if mask0 != 0 {
                // NUL at base+tz ⇒ length from p is tz-align (tz ≥ align by the mask).
                return (mask0.trailing_zeros() as usize - align, true);
            }
            // Continue from the next 32-aligned boundary (= base+32 = p + (32-align)).
            // Every subsequent load is 32-aligned ⇒ in-page, no guard needed.
            let mut i = 32 - align;
            // 32-byte tier: short strings (the common case) terminate here with no
            // unroll-setup cost. Escalate to the 128-byte unrolled tier only once the
            // string is confirmed long (i >= 256) AND `p+i` is 128-aligned (so the
            // 4×32B = 128-byte window stays within one 4 KiB page, 128 | 4096).
            while i < 256 || (p as usize + i) & 127 != 0 {
                // SAFETY: p+i is 32-aligned, so the 32-byte window stays in one page.
                let v = Simd::<u8, 32>::from_slice(unsafe {
                    core::slice::from_raw_parts(p.add(i), 32)
                });
                let mask = v.simd_eq(Simd::splat(0)).to_bitmask();
                if mask != 0 {
                    return (i + mask.trailing_zeros() as usize, true);
                }
                i += 32;
            }
            // 128-aligned 4×32B unrolled tier: ONE combined NUL check per 128 bytes
            // (glibc's structure — vs one movemask+branch per 32 B), then resolve the
            // exact panel/index only when a NUL is present. ~2-2.5x over the 32B loop
            // for long strings (parity-to-beat glibc at >=64 KiB).
            loop {
                // SAFETY: p+i is 128-aligned ⇒ [i, i+128) is within one mapped page.
                let a = Simd::<u8, 32>::from_slice(unsafe {
                    core::slice::from_raw_parts(p.add(i), 32)
                });
                let b = Simd::<u8, 32>::from_slice(unsafe {
                    core::slice::from_raw_parts(p.add(i + 32), 32)
                });
                let c = Simd::<u8, 32>::from_slice(unsafe {
                    core::slice::from_raw_parts(p.add(i + 64), 32)
                });
                let d = Simd::<u8, 32>::from_slice(unsafe {
                    core::slice::from_raw_parts(p.add(i + 96), 32)
                });
                let z = Simd::splat(0u8);
                // Combined NUL check via bytewise min: `min(a,b,c,d)` has a 0 lane iff at
                // least one of the four vectors has a 0 there — 3 vpminub + 1 vpcmpeqb,
                // cheaper than 4 vpcmpeqb + 3 mask-ORs (measured ~10-13% faster in the
                // L1/L2 range [4K,16K], taking strlen to parity-to-WIN vs glibc there).
                use core::simd::cmp::SimdOrd;
                if a.simd_min(b).simd_min(c.simd_min(d)).simd_eq(z).any() {
                    let ma = a.simd_eq(z).to_bitmask();
                    if ma != 0 {
                        return (i + ma.trailing_zeros() as usize, true);
                    }
                    let mb = b.simd_eq(z).to_bitmask();
                    if mb != 0 {
                        return (i + 32 + mb.trailing_zeros() as usize, true);
                    }
                    let mc = c.simd_eq(z).to_bitmask();
                    if mc != 0 {
                        return (i + 64 + mc.trailing_zeros() as usize, true);
                    }
                    return (i + 96 + d.simd_eq(z).to_bitmask().trailing_zeros() as usize, true);
                }
                i += 128;
            }
        }
    }
}

/// SWAR scan for the first byte equal to `target` OR a terminating NUL, within
/// `bound`. Returns `(index, found_target, hit_limit)`:
///   - `found_target == true`  → `index` points at a `target` byte;
///   - `hit_limit == true` (bounded only) → no target/NUL in `bound`, `index == bound`;
///   - otherwise → `index` points at the terminating NUL.
///
/// Each 8-byte window is tested for a zero byte AND for a `target` byte with two
/// exact haszero probes (`w` and `w ^ broadcast(target)`); the exact byte is then
/// resolved in scan order, so target-before-NUL vs NUL-before-target is decided
/// correctly. `target == 0` resolves to the NUL as a *found* target, matching
/// glibc `strchr(s, '\0')`. Same alignment/page-safety discipline as
/// [`scan_c_string`]: unbounded mode aligns to 8 so wide loads never fault past
/// the NUL's page; bounded mode reads only within `bound`.
unsafe fn scan_c_string_for_byte(
    ptr: *const c_char,
    target: u8,
    bound: Option<usize>,
) -> (usize, bool, bool) {
    let p = ptr.cast::<u8>();
    let bcast = (target as u64).wrapping_mul(0x0101_0101_0101_0101);
    match bound {
        Some(limit) => {
            let mut i = 0usize;
            while i + 8 <= limit {
                // SAFETY: [i, i+8) ⊆ [0, limit); caller guarantees `limit` bytes.
                let w = unsafe { core::ptr::read_unaligned(p.add(i).cast::<u64>()) };
                if swar_word_has_zero(w) || swar_word_has_zero(w ^ bcast) {
                    for j in 0..8 {
                        // SAFETY: i+j < limit.
                        let b = unsafe { *p.add(i + j) };
                        if b == target {
                            return (i + j, true, false);
                        }
                        if b == 0 {
                            return (i + j, false, false);
                        }
                    }
                }
                i += 8;
            }
            while i < limit {
                // SAFETY: i < limit.
                let b = unsafe { *p.add(i) };
                if b == target {
                    return (i, true, false);
                }
                if b == 0 {
                    return (i, false, false);
                }
                i += 1;
            }
            (limit, false, true)
        }
        None => {
            use core::simd::Simd;
            use core::simd::cmp::SimdPartialEq;
            // glibc-style aligned-load-with-head-mask for the FIRST vector: align
            // DOWN to a 32-byte boundary, do one aligned load, and mask off the
            // `align` bytes that precede `ptr`. A 32-aligned 32-byte window is
            // contained in one 4 KiB page (32 | 4096) and the page holding `ptr` is
            // mapped, so reading head bytes `base..ptr` is safe. Eliminates BOTH the
            // scalar head-align scan and the per-chunk page-cross guard the old loop
            // paid on every 32B chunk (same fix as scan_c_string's None path).
            let align = (p as usize) & 31;
            // SAFETY: `base` is in the same mapped page as `p` (aligned down ≤ 31).
            let base = unsafe { p.sub(align) };
            let v0 = Simd::<u8, 32>::from_slice(unsafe {
                core::slice::from_raw_parts(base, 32)
            });
            let headclear = !((1u64 << align) - 1);
            let nul0 = v0.simd_eq(Simd::splat(0)).to_bitmask() & headclear;
            let tgt0 = v0.simd_eq(Simd::splat(target)).to_bitmask() & headclear;
            let comb0 = nul0 | tgt0;
            if comb0 != 0 {
                let pos = comb0.trailing_zeros() as usize;
                // `target == 0` (strchr(s,'\0')) reports the NUL as a *found* target.
                let found = (tgt0 >> pos) & 1 == 1;
                return (pos - align, found, false);
            }
            // Continue from the next 32-aligned boundary (= base+32 = p + (32-align)).
            // Every subsequent load is 32-aligned ⇒ a 32-byte read stays in-page, so
            // the 32B tier needs no per-chunk guard; only the 128B folded tier (whose
            // window can straddle a page from a 32-aligned, non-128-aligned address)
            // keeps its guard.
            let mut i = 32 - align;
            loop {
                // Length-escalated folded 4x32 = 128-byte skip tier: one `.any()`
                // reduction per 128 bytes for the bulk of *long* strings. Gated on
                // `i >= 128` so short strings terminate in the 32-byte tier and never
                // pay the folded overhead (measured escalation guard, bd-4rxozm). A
                // folded hit falls through to the 32B tier, which resolves the exact
                // first match — index unchanged.
                if i >= 128 && (p as usize + i) & 0xFFF <= 0x1000 - 128 {
                    let tv = Simd::<u8, 32>::splat(target);
                    let zv = Simd::<u8, 32>::splat(0);
                    // SAFETY: [i, i+128) stays within the current mapped page.
                    let v1 = Simd::<u8, 32>::from_slice(unsafe {
                        core::slice::from_raw_parts(p.add(i), 32)
                    });
                    let v2 = Simd::<u8, 32>::from_slice(unsafe {
                        core::slice::from_raw_parts(p.add(i + 32), 32)
                    });
                    let v3 = Simd::<u8, 32>::from_slice(unsafe {
                        core::slice::from_raw_parts(p.add(i + 64), 32)
                    });
                    let v4 = Simd::<u8, 32>::from_slice(unsafe {
                        core::slice::from_raw_parts(p.add(i + 96), 32)
                    });
                    let any = (v1.simd_eq(tv) | v1.simd_eq(zv))
                        | (v2.simd_eq(tv) | v2.simd_eq(zv))
                        | (v3.simd_eq(tv) | v3.simd_eq(zv))
                        | (v4.simd_eq(tv) | v4.simd_eq(zv));
                    if !any.any() {
                        i += 128;
                        continue;
                    }
                }
                // SAFETY: p+i is 32-aligned, so this 32-byte window stays in one page;
                // the string is NUL-terminated within a mapped page. O(1) resolve via
                // the combined target|NUL bitmask (trailing_zeros).
                let v = Simd::<u8, 32>::from_slice(unsafe {
                    core::slice::from_raw_parts(p.add(i), 32)
                });
                let nul = v.simd_eq(Simd::splat(0)).to_bitmask();
                let tgt = v.simd_eq(Simd::splat(target)).to_bitmask();
                let comb = nul | tgt;
                if comb != 0 {
                    let pos = comb.trailing_zeros() as usize;
                    let found = (tgt >> pos) & 1 == 1;
                    return (i + pos, found, false);
                }
                i += 32;
            }
        }
    }
}

/// Builds the Langdale/Lemire 2-PSHUFB membership LUTs for an ALL-ASCII byte set
/// `[set, set+set_len)` (every byte `< 0x80`): `lo16[v&0xF] |= 1<<(v>>4)` per set
/// byte, `hi16[h] = 1<<h` for h<8. Membership of `b` iff `lo16[b&0xF] & hi16[b>>4]
/// != 0` (bytes `>= 0x80` and NUL map to non-members — exact). Scalar/cheap.
///
/// # Safety
/// `set` readable for `set_len` bytes.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn build_pshufb_lut(set: *const u8, set_len: usize) -> ([u8; 16], [u8; 16]) {
    let mut lo16 = [0u8; 16];
    let mut hi16 = [0u8; 16];
    let mut k = 0;
    while k < set_len {
        // SAFETY: k < set_len, caller guarantees readability.
        let v = unsafe { *set.add(k) };
        lo16[(v & 0x0F) as usize] |= 1u8 << (v >> 4);
        k += 1;
    }
    let mut h = 0;
    while h < 8 {
        hi16[h] = 1u8 << h;
        h += 1;
    }
    (lo16, hi16)
}

/// True iff all `len` bytes at `p` are ASCII (`< 0x80`) — the precondition for the
/// PSHUFB classifier (a set byte `>= 0x80` would be misclassified as a non-member).
///
/// # Safety
/// `p` readable for `len` bytes.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn all_bytes_ascii(p: *const u8, len: usize) -> bool {
    let mut k = 0;
    while k < len {
        // SAFETY: k < len, caller guarantees readability.
        if unsafe { *p.add(k) } >= 0x80 {
            return false;
        }
        k += 1;
    }
    true
}

/// Page-safe FUSED early-stop PSHUFB membership scan over a NUL-terminated string
/// for an arbitrary-size ALL-ASCII set (via the `lo16`/`hi16` LUTs from
/// [`build_pshufb_lut`]). The LARGE-set (>4-byte) analog of
/// [`scan_c_string_for_set4`]: ONE early-stopping AVX2 pass from the raw pointer
/// (2 vpshufb + compare per 32 bytes — classifier throughput, ~glibc), so a
/// tokenization loop / a strcspn over a >4-byte set stays O(n) with a fast body
/// scan (no O(n²) prescan, no scalar-bitmap long-run regression).
///
/// `stop_in_set == true` → strcspn (stop on member OR NUL); `false` → strspn (stop
/// on NON-member OR NUL). Byte-identical to `core::str::span_pshufb_ascii` (same
/// LUT + stop math), which the `span_pshufb_matches_scalar` proptest pins to the
/// scalar reference.
///
/// PAGE-SAFETY is identical to [`scan_c_string_for_set4`]: align DOWN to 32 and
/// head-mask the bytes before `ptr`, then every 32-aligned 32-byte load stays in
/// one 4 KiB page up to and including the NUL's page. The PSHUFB classify is pure
/// register arithmetic on the loaded vector — no extra memory access — so it adds
/// no page-crossing risk over the proven set4 loads.
///
/// # Safety
/// `ptr` must be a valid NUL-terminated C string; AVX2 is enabled crate-wide.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_c_string_pshufb(
    ptr: *const c_char,
    lo16: &[u8; 16],
    hi16: &[u8; 16],
    stop_in_set: bool,
) -> usize {
    use std::arch::x86_64::*;
    // SAFETY of every intrinsic below: AVX2 enabled crate-wide; loads are page-safe
    // per the doc comment (aligned-down first load + head-mask, 32-aligned after).
    unsafe {
        let lo_table = _mm256_broadcastsi128_si256(_mm_loadu_si128(lo16.as_ptr().cast()));
        let hi_table = _mm256_broadcastsi128_si256(_mm_loadu_si128(hi16.as_ptr().cast()));
        let zero = _mm256_setzero_si256();
        let low_mask = _mm256_set1_epi8(0x0F);
        let ones = _mm256_set1_epi8(-1i8);
        let p = ptr.cast::<u8>();

        #[inline(always)]
        unsafe fn window_stop_bits(
            lanes: std::arch::x86_64::__m256i,
            lo_table: std::arch::x86_64::__m256i,
            hi_table: std::arch::x86_64::__m256i,
            zero: std::arch::x86_64::__m256i,
            low_mask: std::arch::x86_64::__m256i,
            ones: std::arch::x86_64::__m256i,
            stop_in_set: bool,
        ) -> u32 {
            use std::arch::x86_64::*;
            unsafe {
                let lo = _mm256_and_si256(lanes, low_mask);
                let hi = _mm256_and_si256(_mm256_srli_epi16(lanes, 4), low_mask);
                let lo_bits = _mm256_shuffle_epi8(lo_table, lo);
                let hi_bits = _mm256_shuffle_epi8(hi_table, hi);
                let member = _mm256_and_si256(lo_bits, hi_bits);
                let nonmember = _mm256_cmpeq_epi8(member, zero); // 0xFF where NON-member
                let nul = _mm256_cmpeq_epi8(lanes, zero);
                let stop = if stop_in_set {
                    _mm256_or_si256(_mm256_andnot_si256(nonmember, ones), nul)
                } else {
                    _mm256_or_si256(nonmember, nul)
                };
                _mm256_movemask_epi8(stop) as u32
            }
        }

        // FIRST vector: aligned-down load + head-mask (page-safe).
        let align = (p as usize) & 31;
        let base = p.sub(align);
        let v0 = _mm256_loadu_si256(base.cast());
        let head_clear = if align == 0 { u32::MAX } else { !((1u32 << align) - 1) };
        let bits0 =
            window_stop_bits(v0, lo_table, hi_table, zero, low_mask, ones, stop_in_set) & head_clear;
        if bits0 != 0 {
            return bits0.trailing_zeros() as usize - align;
        }
        // Every subsequent 32-byte window is 32-aligned ⇒ within one page.
        let mut i = 32 - align;
        loop {
            let v = _mm256_loadu_si256(p.add(i).cast());
            let bits = window_stop_bits(v, lo_table, hi_table, zero, low_mask, ones, stop_in_set);
            if bits != 0 {
                return i + bits.trailing_zeros() as usize;
            }
            i += 32;
        }
    }
}

/// Page-safe FUSED early-stop membership scan over a NUL-terminated string for a
/// SMALL set of 1..=4 bytes (`set`, duplicate-filled to 4 — same membership set).
///
/// Returns the index of the first byte that satisfies the stop predicate:
///   - `complement == false` (strcspn / strpbrk): byte `== NUL` OR byte ∈ `set`;
///   - `complement == true`  (strspn):            byte `== NUL` OR byte ∉ `set`.
///
/// This is the *fused* analog of the ABI strict path's `scan_c_string(s)` pre-scan
/// + `core::str::{strspn,strcspn}` second pass: it makes ONE early-stopping SIMD
/// pass from the raw pointer, never scanning past the stop byte (glibc's structure).
/// Byte-identical to those core functions over the NUL-inclusive slice:
///   - strcspn(2..=4): first reject-member OR NUL == `find_any_of4_or_nul_fused`.
///   - strspn(2..=4):  first non-member  OR NUL == `find_non_any_of4_or_nul`
///     (NUL is never a set member — set bytes come from a C string — so `!member`
///     already covers the NUL stop).
///   - strpbrk(2..=4): same stop index; the caller reads the stop byte to map
///     member→pointer, NUL→null.
///
/// Page-safety is identical to [`scan_c_string`] / [`scan_c_string_for_byte`]:
/// align DOWN to a 32-byte boundary and head-mask the bytes before `ptr`, then
/// every subsequent 32-aligned 32-byte load stays within one 4 KiB page (32 | 4096)
/// up to and including the NUL's page. The 128-byte folded tier keeps the same
/// page-cross guard as `scan_c_string_for_byte`.
///
/// # Safety
///
/// `ptr` must be a valid NUL-terminated C string.
unsafe fn scan_c_string_for_set4(ptr: *const c_char, set: [u8; 4], complement: bool) -> usize {
    use core::simd::Simd;
    use core::simd::cmp::SimdPartialEq;
    let p = ptr.cast::<u8>();
    let s0 = Simd::<u8, 32>::splat(set[0]);
    let s1 = Simd::<u8, 32>::splat(set[1]);
    let s2 = Simd::<u8, 32>::splat(set[2]);
    let s3 = Simd::<u8, 32>::splat(set[3]);
    let zv = Simd::<u8, 32>::splat(0);
    // Computes the 32-lane "stop here" bitmask for a loaded window.
    let stop_bits = |v: Simd<u8, 32>| -> u64 {
        let member = v.simd_eq(s0) | v.simd_eq(s1) | v.simd_eq(s2) | v.simd_eq(s3);
        let stop = if complement { !member } else { member | v.simd_eq(zv) };
        stop.to_bitmask()
    };

    // FIRST vector: aligned-down load + head-mask (page-safe; see doc comment).
    let align = (p as usize) & 31;
    // SAFETY: `base` is in the same mapped page as `p` (aligned down ≤ 31 bytes).
    let base = unsafe { p.sub(align) };
    let v0 = Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(base, 32) });
    let headclear = !((1u64 << align) - 1);
    let bits0 = stop_bits(v0) & headclear;
    if bits0 != 0 {
        // Stop index is `pos - align` relative to `p` (pos ≥ align by the head mask).
        return bits0.trailing_zeros() as usize - align;
    }
    // Continue from the next 32-aligned boundary (= base+32 = p + (32-align)).
    let mut i = 32 - align;
    loop {
        // Length-escalated folded 4x32 = 128-byte skip tier for long strings; one
        // `.any()` reduction per 128 bytes. Gated on `i >= 128` (short strings stay
        // in the 32B tier) AND a page-cross guard (the 128B window from a 32-aligned,
        // non-128-aligned address can straddle a page). A folded hit falls through to
        // the 32B tier, which resolves the exact first stop index unchanged.
        if i >= 128 && (p as usize + i) & 0xFFF <= 0x1000 - 128 {
            // SAFETY: [i, i+128) stays within the current mapped page.
            let w1 = Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(p.add(i), 32) });
            let w2 =
                Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(p.add(i + 32), 32) });
            let w3 =
                Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(p.add(i + 64), 32) });
            let w4 =
                Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(p.add(i + 96), 32) });
            if (stop_bits(w1) | stop_bits(w2) | stop_bits(w3) | stop_bits(w4)) == 0 {
                i += 128;
                continue;
            }
        }
        // SAFETY: p+i is 32-aligned, so this 32-byte window stays in one page; the
        // string is NUL-terminated within a mapped page, so the scan stops at/before
        // the NUL (which is always a stop lane) — never reading a faulting page.
        let v = Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(p.add(i), 32) });
        let bits = stop_bits(v);
        if bits != 0 {
            return i + bits.trailing_zeros() as usize;
        }
        i += 32;
    }
}

/// SWAR scan for the LAST byte equal to `target` at or before the terminating
/// NUL (or `bound`). Returns `(last_match_index, stop_index, hit_limit)`:
///   - `last_match_index` = index of the last `target` (None if absent);
///   - `stop_index` = index of the terminating NUL, or `bound` if the limit was
///     reached first;
///   - `hit_limit` = the limit was reached with no NUL.
///
/// Each 8-byte window is probed for a NUL and a `target` byte with two exact
/// haszero tests. A NUL-free window with a target is resolved back-to-front for
/// the last match; the terminating window is resolved front-to-back (updating the
/// last match on each `target`, stopping at the NUL) so `target == 0` reports the
/// NUL itself — matching glibc `strrchr(s, '\0')`. Same alignment/page discipline
/// as [`scan_c_string`].
unsafe fn scan_c_string_last_byte(
    ptr: *const c_char,
    target: u8,
    bound: Option<usize>,
) -> (Option<usize>, usize, bool) {
    let p = ptr.cast::<u8>();
    let bcast = (target as u64).wrapping_mul(0x0101_0101_0101_0101);
    let mut last: Option<usize> = None;
    match bound {
        Some(limit) => {
            let mut i = 0usize;
            while i + 8 <= limit {
                // Wide 32-byte portable-SIMD skip, mirroring the unbounded (None)
                // path: a panel with NEITHER the target NOR a NUL cannot change
                // `last` or terminate, so advance it whole. Taken only when the
                // 32-byte window stays inside the bound (`i + 32 <= limit`) and the
                // current page; any panel with a target or NUL drops to the 8-byte
                // SWAR resolve below, which updates `last` and resolves the NUL
                // exactly — byte-identical. Closes the bounded-path gap where the
                // SWAR scan was ~7x slower than the SIMD unbounded path at 64 KiB.
                if i + 32 <= limit && (p as usize + i) & 0xFFF <= 0x1000 - 32 {
                    use core::simd::Simd;
                    use core::simd::cmp::SimdPartialEq;
                    // SAFETY: [i, i+32) ⊆ [0, limit) and within the current page.
                    let v = Simd::<u8, 32>::from_slice(unsafe {
                        core::slice::from_raw_parts(p.add(i), 32)
                    });
                    let hit = v.simd_eq(Simd::splat(target)) | v.simd_eq(Simd::splat(0));
                    if !hit.any() {
                        i += 32;
                        continue;
                    }
                }
                // SAFETY: [i, i+8) ⊆ [0, limit).
                let w = unsafe { core::ptr::read_unaligned(p.add(i).cast::<u64>()) };
                if swar_word_has_zero(w) {
                    for j in 0..8 {
                        // SAFETY: i+j < limit.
                        let b = unsafe { *p.add(i + j) };
                        if b == target {
                            last = Some(i + j);
                        }
                        if b == 0 {
                            return (last, i + j, false);
                        }
                    }
                } else if swar_word_has_zero(w ^ bcast) {
                    for j in (0..8).rev() {
                        // SAFETY: i+j < limit.
                        if unsafe { *p.add(i + j) } == target {
                            last = Some(i + j);
                            break;
                        }
                    }
                }
                i += 8;
            }
            while i < limit {
                // SAFETY: i < limit.
                let b = unsafe { *p.add(i) };
                if b == target {
                    last = Some(i);
                }
                if b == 0 {
                    return (last, i, false);
                }
                i += 1;
            }
            (last, limit, true)
        }
        None => {
            use core::simd::Simd;
            use core::simd::cmp::SimdPartialEq;
            // glibc-style aligned-load-with-head-mask: align DOWN to a 32-byte
            // boundary, do one aligned load, mask off the `align` bytes before
            // `ptr`. A 32-aligned 32-byte window is in one 4 KiB page (32 | 4096)
            // and the page holding `ptr` is mapped, so reading head bytes is safe.
            // Resolves the LAST target ≤ the terminating NUL via the per-block
            // target/NUL bitmasks (highest set bit = 63 - leading_zeros), dropping
            // the scalar head-align loop and the per-chunk page guard the old loop
            // paid on every 32B chunk. `target == 0` includes the NUL position so
            // strrchr(s,'\0') reports the NUL itself.
            let align = (p as usize) & 31;
            // SAFETY: `base` is in the same mapped page as `p` (aligned down ≤ 31).
            let base = unsafe { p.sub(align) };
            let headclear = !((1u64 << align) - 1);
            let v0 = Simd::<u8, 32>::from_slice(unsafe {
                core::slice::from_raw_parts(base, 32)
            });
            let nul0 = v0.simd_eq(Simd::splat(0)).to_bitmask() & headclear;
            let tgt0 = v0.simd_eq(Simd::splat(target)).to_bitmask() & headclear;
            if nul0 != 0 {
                let nul_pos = nul0.trailing_zeros();
                // Targets at or before the NUL (inclusive covers target==0).
                let upto = tgt0 & ((1u64 << (nul_pos + 1)) - 1);
                let last = if upto != 0 {
                    Some((63 - upto.leading_zeros()) as usize - align)
                } else {
                    None
                };
                return (last, nul_pos as usize - align, false);
            }
            // No NUL in the first block: record its last target, then continue from
            // the next 32-aligned boundary (all subsequent loads in-page, no guard).
            let mut last = if tgt0 != 0 {
                Some((63 - tgt0.leading_zeros()) as usize - align)
            } else {
                None
            };
            let mut i = 32 - align;
            loop {
                // SAFETY: p+i is 32-aligned ⇒ the 32-byte window stays in one page.
                let v = Simd::<u8, 32>::from_slice(unsafe {
                    core::slice::from_raw_parts(p.add(i), 32)
                });
                // Steady-state fast skip: ONE combined target|NUL reduction per panel
                // (matching the old loop's single `.any()` cost) — only split into the
                // two separate masks when a panel actually contains a target or NUL, so
                // long target-free runs pay no extra work vs the old skip.
                let hit = (v.simd_eq(Simd::splat(0)) | v.simd_eq(Simd::splat(target))).to_bitmask();
                if hit == 0 {
                    i += 32;
                    continue;
                }
                let nul = v.simd_eq(Simd::splat(0)).to_bitmask();
                let tgt = v.simd_eq(Simd::splat(target)).to_bitmask();
                if nul != 0 {
                    let nul_pos = nul.trailing_zeros();
                    let upto = tgt & ((1u64 << (nul_pos + 1)) - 1);
                    if upto != 0 {
                        last = Some(i + (63 - upto.leading_zeros()) as usize);
                    }
                    return (last, i + nul_pos as usize, false);
                }
                // hit != 0 with no NUL ⇒ tgt != 0 (hit == nul | tgt).
                last = Some(i + (63 - tgt.leading_zeros()) as usize);
                i += 32;
            }
        }
    }
}

/// True iff an 8-byte read starting at `addr` stays within `addr`'s own 4096-byte
/// page, so it cannot fault into an adjacent (possibly unmapped) page. Gates wide
/// reads in the dual-pointer strcmp/strncmp scan, where neither pointer can be
/// pre-aligned.
#[inline(always)]
fn wide_read_within_page(addr: usize) -> bool {
    (addr & 0xFFF) <= 0x1000 - 8
}

/// SWAR scan for the first index where two C strings differ or `s1` terminates,
/// within `bound`. Returns `(index, hit_limit)`:
///   - `hit_limit == true`  → the first `bound` bytes compared equal with no NUL;
///     `index == bound`.
///   - otherwise → `index` is the first position with `s1[i] != s2[i]` or
///     `s1[i] == 0`; the caller reads both bytes there to form the signed diff (a
///     shared NUL yields 0, a shorter `s1` yields a negative diff, etc.).
///
/// A wide 8-byte compare runs only when both reads stay inside their pages (no
/// fault past a NUL near a page boundary) AND within `bound`; otherwise a single
/// byte step is taken. A flagged window (words unequal OR containing a NUL) is
/// resolved byte-wise in scan order, so the exact first diff/NUL is returned —
/// byte-identical to the scalar loop it replaces.
unsafe fn scan_strcmp(s1: *const c_char, s2: *const c_char, bound: usize) -> (usize, bool) {
    let p1 = s1.cast::<u8>();
    let p2 = s2.cast::<u8>();
    let mut i = 0usize;
    loop {
        // Wide 32-byte portable-SIMD fast path: skip whole equal, NUL-free panels
        // at AVX width (glibc's strcmp/strncmp step 16-32 bytes; the 8-byte SWAR
        // below was the bottleneck — strncmp was ~1.5x slower). A flagged panel
        // falls through to the SWAR/scalar tail, which resolves the exact first
        // differing-or-NUL index, so the returned (index, hit_limit) is unchanged.
        if i + 32 <= bound
            && (p1 as usize + i) & 0xFFF <= 0x1000 - 32
            && (p2 as usize + i) & 0xFFF <= 0x1000 - 32
        {
            use core::simd::Simd;
            use core::simd::cmp::SimdPartialEq;
            // SAFETY: both 32-byte reads stay within their mapped pages and bound.
            let va =
                Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(p1.add(i), 32) });
            let vb =
                Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(p2.add(i), 32) });
            let flagged = (va.simd_ne(vb) | va.simd_eq(Simd::splat(0))).to_bitmask();
            if flagged == 0 {
                i += 32;
                continue;
            }
            // Flagged panel: the first set bit is the exact first
            // differing-or-s1-NUL byte (the same index the SWAR/scalar tail would
            // resolve to). Return it directly via trailing_zeros instead of
            // re-scanning the same 32 bytes with the 8-byte SWAR path below — the
            // same O(1) resolve used in scan_c_string/strchr. Byte-identical.
            return (i + flagged.trailing_zeros() as usize, false);
        }
        if i + 8 <= bound
            && wide_read_within_page(p1 as usize + i)
            && wide_read_within_page(p2 as usize + i)
        {
            // SAFETY: both 8-byte reads stay within their mapped pages and bound.
            let wa = unsafe { core::ptr::read_unaligned(p1.add(i).cast::<u64>()) };
            let wb = unsafe { core::ptr::read_unaligned(p2.add(i).cast::<u64>()) };
            if wa == wb && !swar_word_has_zero(wa) {
                i += 8;
                continue;
            }
            for j in 0..8 {
                // SAFETY: i+j < bound; within the just-read in-page window.
                let a = unsafe { *p1.add(i + j) };
                let b = unsafe { *p2.add(i + j) };
                if a != b || a == 0 {
                    return (i + j, false);
                }
            }
            i += 8; // defensive: a flagged window always returns above.
            continue;
        }
        if i >= bound {
            return (bound, true);
        }
        // SAFETY: i < bound.
        let a = unsafe { *p1.add(i) };
        let b = unsafe { *p2.add(i) };
        if a != b || a == 0 {
            return (i, false);
        }
        i += 1;
    }
}

/// Branchless SWAR ASCII lowercase: folds bytes in `'A'..='Z'` to `'a'..='z'`
/// and leaves every other byte (incl. non-ASCII `>= 0x80`) untouched — exactly C
/// `tolower` in the POSIX/C locale, applied to all 8 lanes at once.
///
/// Per-byte range test `0x41 <= b <= 0x5A`, made borrow-safe by forcing each
/// byte's high bit (`w | HIGHS`) so a within-byte borrow is absorbed by that
/// guard bit instead of leaking into the next lane. `ge_a`/`ge_5b` read the
/// surviving guard bit as `(b & 0x7F) >= 0x41` / `>= 0x5B`; `ascii` excludes
/// bytes `>= 0x80`. The resulting `0x80` flag is shifted to the `0x20` case bit.
#[inline(always)]
fn swar_ascii_lower(w: u64) -> u64 {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGHS: u64 = 0x8080_8080_8080_8080;
    let guarded = w | HIGHS;
    let ge_a = guarded.wrapping_sub(ONES.wrapping_mul(0x41)) & HIGHS; // (b&0x7F) >= 'A'
    let ge_5b = guarded.wrapping_sub(ONES.wrapping_mul(0x5B)) & HIGHS; // (b&0x7F) >= '['
    let ascii = !w & HIGHS; // b < 0x80
    let is_upper = ge_a & !ge_5b & ascii;
    w | (is_upper >> 2)
}

/// Fused single-pass SWAR case-insensitive compare of two C strings within
/// `bound`. Returns `(result, span)`: `result` is the signed difference of the
/// lowercased bytes at the first position that differs (0 if equal up to a shared
/// NUL or to `bound`); `span` is the compared extent (for cost accounting).
///
/// Equal-and-NUL-free 8-byte windows (after folding both via [`swar_ascii_lower`])
/// advance 8; any other window is resolved byte-wise with `to_ascii_lowercase`
/// (byte-identical to the scalar loop). The same page-cross guard as
/// [`scan_strcmp`] keeps the dual-pointer wide reads from faulting past a NUL.
unsafe fn scan_strcasecmp(s1: *const c_char, s2: *const c_char, bound: usize) -> (c_int, usize) {
    let p1 = s1.cast::<u8>();
    let p2 = s2.cast::<u8>();
    let mut i = 0usize;
    loop {
        // Wide 32-byte portable-SIMD fast path: skip whole panels that are equal
        // after ASCII case-folding and NUL-free, at AVX width (glibc's strcasecmp
        // steps 16-32 bytes; the 8-byte SWAR below was the bottleneck). A flagged
        // panel falls through to the SWAR/scalar tail, which resolves the exact
        // first differing-or-NUL index — so the returned result is unchanged.
        if i + 32 <= bound
            && (p1 as usize + i) & 0xFFF <= 0x1000 - 32
            && (p2 as usize + i) & 0xFFF <= 0x1000 - 32
        {
            use core::simd::cmp::{SimdPartialEq, SimdPartialOrd};
            use core::simd::{Select, Simd};
            // SAFETY: both 32-byte reads stay within their mapped pages and bound.
            let va =
                Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(p1.add(i), 32) });
            let vb =
                Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(p2.add(i), 32) });
            let fold = |v: Simd<u8, 32>| {
                let up = v.simd_ge(Simd::splat(b'A')) & v.simd_le(Simd::splat(b'Z'));
                up.select(v + Simd::splat(0x20), v)
            };
            let z = Simd::<u8, 32>::splat(0);
            let flagged = (fold(va).simd_ne(fold(vb)) | va.simd_eq(z)).to_bitmask();
            if flagged == 0 {
                i += 32;
                continue;
            }
            // Flagged panel: the first set bit is the exact first case-folded-differing
            // or s1-NUL byte (the same index the SWAR/scalar tail would resolve to).
            // Resolve it directly via trailing_zeros instead of re-scanning the same 32
            // bytes with the 8-byte SWAR path below — same O(1) resolve as scan_strcmp.
            // Byte-identical: at `k` either fold(a)!=fold(b) (return the case-folded
            // difference) or a==0 (a NUL; equal-so-far ⇒ return 0).
            let k = i + flagged.trailing_zeros() as usize;
            // SAFETY: k < bound (the flagged 32-byte window is within bound).
            let a = unsafe { *p1.add(k) };
            let b = unsafe { *p2.add(k) };
            let la = a.to_ascii_lowercase();
            let lb = b.to_ascii_lowercase();
            if la != lb {
                return ((la as c_int) - (lb as c_int), k + 1);
            }
            return (0, k + 1);
        }
        if i + 8 <= bound
            && wide_read_within_page(p1 as usize + i)
            && wide_read_within_page(p2 as usize + i)
        {
            // SAFETY: both 8-byte reads stay within their mapped pages and bound.
            let wa = unsafe { core::ptr::read_unaligned(p1.add(i).cast::<u64>()) };
            let wb = unsafe { core::ptr::read_unaligned(p2.add(i).cast::<u64>()) };
            if swar_ascii_lower(wa) == swar_ascii_lower(wb) && !swar_word_has_zero(wa) {
                i += 8;
                continue;
            }
            for j in 0..8 {
                // SAFETY: i+j < bound; within the just-read in-page window.
                let a = unsafe { *p1.add(i + j) };
                let b = unsafe { *p2.add(i + j) };
                let la = a.to_ascii_lowercase();
                let lb = b.to_ascii_lowercase();
                if la != lb {
                    return ((la as c_int) - (lb as c_int), i + j + 1);
                }
                if a == 0 {
                    return (0, i + j + 1);
                }
            }
            i += 8; // defensive: a flagged window always returns above.
            continue;
        }
        if i >= bound {
            return (0, bound);
        }
        // SAFETY: i < bound.
        let a = unsafe { *p1.add(i) };
        let b = unsafe { *p2.add(i) };
        let la = a.to_ascii_lowercase();
        let lb = b.to_ascii_lowercase();
        if la != lb {
            return ((la as c_int) - (lb as c_int), i + 1);
        }
        if a == 0 {
            return (0, i + 1);
        }
        i += 1;
    }
}

unsafe fn read_c_string_bytes(ptr: *const c_char) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    let (len, terminated) = unsafe { scan_c_string(ptr, known_remaining(ptr as usize)) };
    if !terminated {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    Some(bytes.to_vec())
}

unsafe fn read_c_string_bytes_with_nul(ptr: *const c_char) -> Option<Vec<u8>> {
    let bytes = unsafe { read_c_string_bytes(ptr) }?;
    let capacity = bytes.len().checked_add(1)?;
    let mut with_nul = Vec::with_capacity(capacity);
    with_nul.extend_from_slice(&bytes);
    with_nul.push(0);
    Some(with_nul)
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

    // Fast path during early startup: skip membrane entirely.
    if string_raw_passthrough_active() {
        if !(crate::htm_fast_path::htm_forced_mode_active_for_tests()
            && try_memcpy_htm(dst.cast::<u8>(), src.cast::<u8>(), n))
        {
            unsafe { raw_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), n) };
        }
        return dst;
    }

    // Strict-mode fast path (the DEFAULT deployed mode): strict passthrough forces
    // `decide()` Allow with no clamp/heal, so the result is exactly the raw copy. Skip the
    // entrypoint trace scope + proof-carried/observe machinery (byte-identical to the
    // `!heals_enabled` raw_dispatch path below), like the inet_strict family. Hardened mode
    // falls through to the full validating path.
    if runtime_policy::strict_passthrough_active() {
        if !try_memcpy_htm(dst.cast::<u8>(), src.cast::<u8>(), n) {
            unsafe { raw_dispatch_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), n) };
        }
        return dst;
    }

    let _trace_scope = runtime_policy::entrypoint_scope("memcpy");
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
    if string_raw_passthrough_active() {
        unsafe { raw_memmove_bytes(dst.cast::<u8>(), src.cast::<u8>(), n) };
        return dst;
    }

    // Strict-mode fast path (the DEFAULT deployed mode): strict passthrough forces
    // `decide()` Allow with no clamp/heal, so `copy_len == n` and the result is
    // exactly the raw overlap-safe move (byte-identical to the full path below).
    // Skip the membrane guard + decide + stage-trace + observe machinery, mirroring
    // the sibling `memcpy` strict fast path. Hardened mode falls through.
    if runtime_policy::strict_passthrough_active() {
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
    if string_raw_passthrough_active() {
        unsafe { raw_memset_bytes(dst.cast::<u8>(), c as u8, n) };
        return dst;
    }

    // Strict-mode fast path (the DEFAULT deployed mode): in strict passthrough the
    // StringMemory membrane is a no-op — `decide()` forces Allow (StringMemory is on the
    // strict fast-list) and no clamp/heal occurs, so the membrane's only output is a raw
    // memset. Skip the whole membrane (known_remaining + check_ordering + decide + record +
    // observe), exactly as the inet_strict family already does. Hardened mode
    // (`strict_passthrough_active() == false`) falls through to the full validating path.
    if runtime_policy::strict_passthrough_active() {
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
    if n == 0 {
        return 0;
    }
    if s1.is_null() || s2.is_null() {
        if string_raw_passthrough_active() {
            return 0;
        }
        let (aligned, recent_page, ordering) = stage_context_two(s1 as usize, s2 as usize);
        // Membrane: null pointer in memcmp is UB in C. Return safe default.
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return 0;
    }

    if string_raw_passthrough_active() {
        return unsafe { raw_lane_memcmp_bytes(s1.cast::<u8>(), s2.cast::<u8>(), n, 1) };
    }

    // Strict-mode fast path (the DEFAULT deployed mode): strict passthrough forces Allow
    // with no clamp (cmp_len == n), so the result is exactly the dispatched raw compare.
    // Skip entrypoint_scope + stage_context + decide + maybe_clamp + record + observe
    // (byte-identical to the strict full path below), like the inet_strict family. Hardened
    // mode keeps the full validating path.
    if runtime_policy::strict_passthrough_active() {
        return unsafe { raw_dispatch_memcmp_bytes(s1.cast::<u8>(), s2.cast::<u8>(), n) };
    }

    let _trace_scope = runtime_policy::entrypoint_scope("memcmp");
    let (aligned, recent_page, ordering) = stage_context_two(s1 as usize, s2 as usize);
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
    // Strict-mode fast path (the DEFAULT deployed mode): strict passthrough forces Allow
    // with no clamp (scan_len == n), so the result is exactly the SIMD core scan over the
    // caller-bounded `n` bytes. Skip stage_context + decide + maybe_clamp + record + observe
    // (byte-identical to the strict full path), like the inet_strict family. Hardened mode
    // keeps the full validating path.
    if runtime_policy::strict_passthrough_active() {
        if n == 0 || s.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: caller guarantees `s` is valid for `n` bytes (memchr's contract).
        let bytes = unsafe { std::slice::from_raw_parts(s.cast::<u8>(), n) };
        return match frankenlibc_core::string::mem::memchr(bytes, c as u8, n) {
            Some(idx) => unsafe { (s as *mut u8).add(idx).cast() },
            None => std::ptr::null_mut(),
        };
    }

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
    // Strict-mode fast path (DEFAULT deployed): strict passthrough has no clamp
    // (`scan_len == n`), byte-identical to the strict body — core memrchr over `n`,
    // returning `s+idx`/null. Skips stage_context + decide + observe + stage-trace.
    if runtime_policy::strict_passthrough_active() {
        if n == 0 || s.is_null() {
            return std::ptr::null_mut();
        }
        return unsafe {
            let bytes = std::slice::from_raw_parts(s.cast::<u8>(), n);
            match frankenlibc_core::string::mem::memrchr(bytes, c as u8, n) {
                Some(idx) => (s as *mut u8).add(idx).cast(),
                None => std::ptr::null_mut(),
            }
        };
    }

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

/// glibc reserved-namespace alias for [`memrchr`]. Some headers
/// and a few third-party callers link against the underscored
/// variant instead of the public name.
///
/// # Safety
///
/// Same as [`memrchr`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __memrchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void {
    unsafe { memrchr(s, c, n) }
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

    // Fast path during early startup: skip membrane validation entirely.
    // The membrane's ValidationPipeline uses PageOracle (RwLock) and TLS,
    // which deadlock during init when called from dlvsym → strlen chains.
    if string_raw_passthrough_active() {
        unsafe {
            let mut len = 0usize;
            while *s.add(len) != 0 {
                len += 1;
            }
            return len;
        }
    }

    // Strict-mode fast path (the DEFAULT deployed mode): strict passthrough does no
    // validation, so the result is exactly the raw page-safe SIMD scan to NUL. Skip
    // entrypoint_scope + known_remaining + the membrane (byte-identical to the existing
    // `!heals && rem.is_none()` path below, now also covering tracked pointers in strict),
    // like the inet_strict family. Hardened mode keeps the full validating path.
    if runtime_policy::strict_passthrough_active() {
        let dispatch =
            select_string_simd_dispatch(SimdStringOperation::Strlen, s as usize, s as usize, 64);
        return unsafe { raw_lane_strlen_bytes(s, dispatch.lane_bytes) };
    }

    let _trace_scope = runtime_policy::entrypoint_scope("strlen");
    let rem = known_remaining(s as usize);
    if !runtime_policy::mode().heals_enabled() && rem.is_none() {
        let dispatch =
            select_string_simd_dispatch(SimdStringOperation::Strlen, s as usize, s as usize, 64);
        return unsafe { raw_lane_strlen_bytes(s, dispatch.lane_bytes) };
    }

    let aligned = (s as usize) & 0x7 == 0;
    let recent_page = rem.is_some();
    let ordering = runtime_policy::check_ordering(ApiFamily::StringMemory, aligned, recent_page);

    let (_mode, decision) = runtime_policy::decide(
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

    if let Some(limit) = rem {
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

    // Strict-mode fast path (DEFAULT deployed): strict passthrough has no membrane
    // clamp (`repair` false → `scan_limit == n`), byte-identical to the strict full
    // path — the bounded SWAR NUL scan `scan_c_string(s, Some(n))`. Skips the
    // decide + observe + stage-trace bookkeeping. (Unlike `wcslen`, strnlen gates
    // its `known_remaining` clamp on `repair`, so strict is plain bounded scan.)
    if runtime_policy::strict_passthrough_active() {
        if s.is_null() {
            return 0;
        }
        return unsafe { scan_c_string(s, Some(n)).0 };
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
    // SWAR bounded NUL scan (shared scan_c_string): returns the NUL index or
    // `scan_limit`, identical to the old byte loop. `span` tracked the scanned
    // extent, which equals `len` in both branches.
    let len = unsafe { scan_c_string(s, Some(scan_limit)).0 };
    let span = len;

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
    // Strict-mode fast path (the DEFAULT deployed mode): strict passthrough does no
    // validation (cmp_bound == None), so the result is exactly the page-cross-guarded raw
    // SWAR compare. Skip stage_context + decide + record + observe (byte-identical to the
    // strict full path: scan_strcmp with no limit), like the inet_strict family. Hardened
    // mode keeps the full validating path.
    if runtime_policy::strict_passthrough_active() {
        if s1.is_null() || s2.is_null() {
            return 0;
        }
        // SAFETY: `scan_strcmp` with usize::MAX is the page-cross-guarded raw scan — the
        // identical call the strict full path makes (cmp_bound == None).
        let (i, _hit_limit) = unsafe { scan_strcmp(s1, s2, usize::MAX) };
        let a = unsafe { *s1.add(i) } as u8;
        let b = unsafe { *s2.add(i) } as u8;
        return (a as c_int) - (b as c_int);
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
    // SWAR word-at-a-time compare (shared scan_strcmp, page-cross guarded),
    // byte-identical to the old scalar loop. `cmp_bound == None` => no limit.
    let (result, adverse, span) = unsafe {
        let (i, hit_limit) = scan_strcmp(s1, s2, cmp_bound.unwrap_or(usize::MAX));
        if hit_limit {
            (0, true, i)
        } else {
            let a = *s1.add(i) as u8;
            let b = *s2.add(i) as u8;
            ((a as c_int) - (b as c_int), false, i.saturating_add(1))
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

    // Strict-mode fast path (the DEFAULT deployed mode): strict passthrough has no
    // membrane clamp (`cmp_limit == n`, not adverse), so this is byte-identical to
    // the strict full path — the page-guarded SWAR/SIMD `scan_strcmp` bounded by `n`.
    // Skips stage_context + decide + observe + stage-trace, mirroring the deployed
    // `strcmp` fast path and the shipped `wcsncmp` one. Hardened mode falls through.
    if runtime_policy::strict_passthrough_active() {
        if s1.is_null() || s2.is_null() {
            return 0;
        }
        let (i, hit_limit) = unsafe { scan_strcmp(s1, s2, n) };
        if hit_limit {
            return 0;
        }
        let a = unsafe { *s1.add(i) } as u8;
        let b = unsafe { *s2.add(i) } as u8;
        return (a as c_int) - (b as c_int);
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
    // SWAR word-at-a-time compare via the shared page-guarded scan_strcmp, bounded
    // by `cmp_limit`; byte-identical to the old scalar loop.
    let (result, span) = unsafe {
        let (i, hit_limit) = scan_strcmp(s1, s2, cmp_limit);
        if hit_limit {
            (0, i)
        } else {
            let a = *s1.add(i) as u8;
            let b = *s2.add(i) as u8;
            ((a as c_int) - (b as c_int), i.saturating_add(1))
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
/// Shared single-scan core for `strcpy`/`stpcpy`. Scans the source length once,
/// copies the payload, writes the terminator, and returns the END pointer (the
/// written NUL position, `dst + copied_payload` — the `stpcpy` result) wrapped in
/// `Some`. Returns `None` only when the membrane denies the call. `strcpy` then
/// returns the original `dst`; `stpcpy` returns the end pointer directly, so it no
/// longer re-scans the just-copied string with a second `strlen` pass.
unsafe fn strcpy_core(dst: *mut c_char, src: *const c_char) -> Option<*mut c_char> {
    let (aligned, recent_page, ordering) = stage_context_two(dst as usize, src as usize);
    if dst.is_null() || src.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return Some(dst);
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
        return None;
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
            // Common (non-repair) path: reuse the single source-length scan from
            // above (src_bound is None here, so the outer scan already computed the
            // exact length — re-scanning was redundant), then copy the payload with
            // the wide block memcpy and append the terminator. Byte-identical to the
            // byte-at-a-time fused loop for any NUL-terminated source.
            if src_len > 0 {
                raw_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), src_len);
            }
            *dst.add(src_len) = 0;
            (src_len.saturating_add(1), false)
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
    // End pointer = the written-NUL position (`stpcpy` result). copied_len counts
    // the payload plus the terminator, so the NUL sits at dst + (copied_len - 1).
    // SAFETY: `dst` was checked for null above and the copy wrote exactly
    // `copied_len` bytes, including the terminator at this offset.
    Some(unsafe { dst.add(copied_len.saturating_sub(1)) })
}

pub unsafe extern "C" fn strcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    match unsafe { strcpy_core(dst, src) } {
        Some(_) => dst,
        None => std::ptr::null_mut(),
    }
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
    // Single shared scan: `strcpy_core` already knows where it wrote the NUL, so
    // stpcpy no longer re-scans the copied string with a second strlen pass.
    match unsafe { strcpy_core(dst, src) } {
        Some(end) => end,
        None => std::ptr::null_mut(),
    }
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
/// Shared single-scan core for `strncpy`/`stpncpy`. Runs the membrane bookkeeping
/// and the source scan/copy/pad once and returns `Some(offset)`, where `offset` is
/// the index of the terminating NUL within the written region (== `strnlen(dst,n)`
/// in the common path) — the `stpncpy` result. Returns `None` only on membrane
/// deny. `strncpy` returns the original `dst`; `stpncpy` returns `dst + offset`, so
/// it no longer re-scans the just-written destination with a second `strnlen` pass.
unsafe fn strncpy_core(dst: *mut c_char, src: *const c_char, n: usize) -> Option<usize> {
    // Strict-mode fast path (the DEFAULT deployed mode): strict passthrough forces
    // `decide()` Allow with no clamp (`safe_dst_len == safe_src_len == n`), so this
    // is byte-identical to the strict full body — scan src (bounded by `n`), bulk
    // copy the prefix, NUL-pad the remainder. Skips stage_context + decide + observe
    // + stage-trace bookkeeping. Bounded-`n` write (caller-controlled extent), the
    // analog of the shipped `wcsncpy`/`memmove` fast paths and the deployed `memcpy`
    // one — NOT the unbounded strcpy/strcat builder class. Hardened mode falls through.
    if runtime_policy::strict_passthrough_active() {
        if dst.is_null() || src.is_null() || n == 0 {
            return Some(0);
        }
        let copy_len = unsafe {
            let k = scan_c_string(src, Some(n)).0;
            let copy_len = k.min(n);
            raw_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), copy_len);
            if copy_len < n {
                raw_memset_bytes(dst.add(copy_len).cast::<u8>(), 0, n - copy_len);
            }
            copy_len
        };
        return Some(copy_len);
    }

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
        return Some(0);
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
        return None;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let mut adverse = false;

    let safe_dst_len = if repair {
        match known_remaining(dst as usize) {
            Some(b) if b < n => {
                adverse = true;
                global_healing_policy().record(&HealingAction::ClampSize {
                    requested: n,
                    clamped: b,
                });
                b
            }
            _ => n,
        }
    } else {
        n
    };

    let safe_src_len = if repair {
        match known_remaining(src as usize) {
            Some(b) if b < n => {
                adverse = true;
                global_healing_policy().record(&HealingAction::ClampSize {
                    requested: n,
                    clamped: b,
                });
                b
            }
            _ => n,
        }
    } else {
        n
    };

    if safe_dst_len == 0 {
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
        return Some(0);
    }

    // SAFETY: bounded by safe_dst_len and safe_src_len.
    // SWAR scan for the NUL, then a wide block copy of the prefix and a wide NUL
    // pad of the remainder — composing the proven scan_c_string / raw_memcpy_bytes
    // / raw_memset_bytes primitives instead of the byte-at-a-time copy+pad loop.
    // `k` is the source NUL index (or safe_src_len if none within bound); the copy
    // is clamped to safe_dst_len, and everything after it is NUL-filled — exactly
    // what the scalar loop produced.
    let copy_len = unsafe {
        let k = scan_c_string(src, Some(safe_src_len)).0;
        let copy_len = k.min(safe_dst_len);
        raw_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), copy_len);
        if copy_len < safe_dst_len {
            raw_memset_bytes(dst.add(copy_len).cast::<u8>(), 0, safe_dst_len - copy_len);
        }
        copy_len
    };
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(8, safe_dst_len),
        adverse,
    );
    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    // Offset of the terminating NUL in the written region (== strnlen(dst, n) in
    // the common path): src NUL index clamped to the destination capacity.
    Some(copy_len)
}

pub unsafe extern "C" fn strncpy(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    match unsafe { strncpy_core(dst, src, n) } {
        Some(_) => dst,
        None => std::ptr::null_mut(),
    }
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

    // Single shared scan: `strncpy_core` returns the terminating-NUL offset it
    // just wrote, so stpncpy no longer re-scans the destination with strnlen.
    match unsafe { strncpy_core(dst, src, n) } {
        // SAFETY: offset is bounded by `n` (and any clamped membrane bound).
        Some(offset) => unsafe { dst.add(offset) },
        None => std::ptr::null_mut(),
    }
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
    // Strict-mode fast path (the DEFAULT deployed mode): strict passthrough forces
    // `decide()` Allow with no clamp, so this is byte-identical to the strict full
    // body — scan dst's NUL, append `min(strlen(src), n)` bytes, NUL-terminate (the
    // scalar copy loop becomes a bulk `raw_memcpy_bytes`, same bytes). Skips the
    // stage_context + decide + observe + stage-trace bookkeeping. Bounded-`n` write,
    // the narrow analog of the shipped `wcsncat` fast path. Hardened mode falls through.
    if runtime_policy::strict_passthrough_active() {
        if dst.is_null() || src.is_null() || n == 0 {
            return dst;
        }
        unsafe {
            let dst_len = scan_c_string(dst.cast_const(), None).0;
            let copy = scan_c_string(src, Some(n)).0;
            if copy > 0 {
                raw_memcpy_bytes(dst.add(dst_len).cast::<u8>(), src.cast::<u8>(), copy);
            }
            *dst.add(dst_len + copy) = 0;
        }
        return dst;
    }

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
/// Shared single-scan core for `strchr`/`strchrnul`. Runs the membrane
/// bookkeeping and the `target`-or-NUL scan exactly once and returns
/// `Some((located, found))`:
///   * `located` points at the first `target` byte, or at the terminating NUL
///     (or the bounded-truncation point) — i.e. the `strchrnul` result;
///   * `found` is true iff `located` is a real `target` byte (not the NUL/limit),
///     i.e. `strchr` returns `located` when `found`, else NULL.
///
/// Returns `None` only when `s` is NULL or the membrane denies the call (the
/// caller picks the fallback). Folding both entry points onto this eliminates
/// strchrnul's old strchr()+strlen() double scan on a miss.
unsafe fn strchr_locate(s: *const c_char, c: c_int) -> Option<(*mut c_char, bool)> {
    // Strict-mode fast path (the DEFAULT deployed mode): strict passthrough forces
    // `decide()` Allow with no repair, so `bound` is `None` and the result is exactly the
    // page-safe raw `target`-or-NUL scan below. Skip the stage context + decide + observe +
    // record machinery (byte-identical to the strict full path), like the inet_strict family.
    // Hardened mode (`strict_passthrough_active() == false`) keeps the full validating path.
    if runtime_policy::strict_passthrough_active() {
        if s.is_null() {
            return None;
        }
        let target = c as c_char;
        // SAFETY: `scan_c_string_for_byte` with no bound is the page-safe SIMD scan; this is
        // the identical call the strict full path makes (bound == None).
        let (i, found_target, _) = unsafe { scan_c_string_for_byte(s, target as u8, None) };
        return Some((unsafe { s.add(i) } as *mut c_char, found_target));
    }

    let (aligned, recent_page, ordering) = stage_context_one(s as usize);
    if s.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return None;
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
        return None;
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known_remaining(s as usize)
    } else {
        None
    };

    // SAFETY: strict mode preserves raw behavior; hardened mode bounds the scan.
    // SWAR scan for `target`-or-NUL (shared scan_c_string_for_byte), byte-identical
    // to the old loop including target=='\0' (returns the NUL).
    let (located, found, adverse, span) = unsafe {
        let (i, found_target, hit_limit) = scan_c_string_for_byte(s, target as u8, bound);
        // `s.add(i)` is the target / NUL / truncation position in every case.
        let ptr = s.add(i) as *mut c_char;
        if hit_limit {
            (ptr, false, true, i)
        } else {
            (ptr, found_target, false, i.saturating_add(1))
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
    Some((located, found))
}

pub unsafe extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    match unsafe { strchr_locate(s, c) } {
        Some((located, true)) => located,
        _ => std::ptr::null_mut(),
    }
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

    // Single shared scan: `strchr_locate` returns the target-or-NUL position
    // directly, so a miss no longer re-scans the whole string with strlen.
    match unsafe { strchr_locate(s, c) } {
        Some((located, _found)) => located,
        // Membrane-denied: preserve the previous degraded-mode result (the old
        // strchr()=>NULL then strlen()=>0 path returned `s`).
        None => s as *mut c_char,
    }
}

/// glibc reserved-namespace alias for [`strchrnul`]. Some headers
/// and a few third-party callers (notably glibc's own internal
/// headers and certain RH toolchain shims) link against the
/// underscored variant instead of the public name.
///
/// # Safety
///
/// Same as [`strchrnul`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strchrnul(s: *const c_char, c: c_int) -> *mut c_char {
    unsafe { strchrnul(s, c) }
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
    // SWAR last-match scan (shared scan_c_string_last_byte), byte-identical to the
    // old loop including target=='\0' (returns the terminating NUL).
    let (result, adverse, span) = unsafe {
        let (last_idx, stop_idx, hit_limit) = scan_c_string_last_byte(s, target as u8, bound);
        let result_local = match last_idx {
            Some(idx) => s.add(idx) as *mut c_char,
            None => std::ptr::null_mut(),
        };
        if hit_limit {
            (result_local, true, stop_idx)
        } else {
            (result_local, false, stop_idx.saturating_add(1))
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
    if string_raw_passthrough_active() {
        return unsafe { raw_strstr(haystack, needle) };
    }

    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict full
    // body's RETURN — scan needle + haystack (with the same ungated
    // `known_remaining` bounds), then core Two-Way `memmem`. Skips stage_context +
    // decide + observe + stage-trace (and `record_truncation`, a telemetry side
    // effect skipped on every strict fast path this session — return value unchanged).
    // Measured ~3.6x vs the full path (the bookkeeping here was ~60ns).
    if runtime_policy::strict_passthrough_active() {
        if haystack.is_null() {
            return std::ptr::null_mut();
        }
        if needle.is_null() {
            return haystack as *mut c_char;
        }
        return unsafe {
            let needle_bound = known_remaining(needle as usize);
            let hay_bound = known_remaining(haystack as usize);
            let (needle_len, _) = scan_c_string(needle, needle_bound);
            if needle_len == 0 {
                haystack as *mut c_char
            } else if needle_len == 1 {
                // strstr(h, [c]) == strchr(h, c): the page-safe early-stopping byte scan
                // stops at the FIRST match — no full-haystack pre-scan (the general path
                // pre-scans the whole haystack just to bound memmem). Byte-identical: same
                // `hay_bound`, first occurrence; NUL/not-found → null.
                let target = *(needle.cast::<u8>());
                let (i, found, _) = scan_c_string_for_byte(haystack, target, hay_bound);
                if found {
                    haystack.add(i) as *mut c_char
                } else {
                    std::ptr::null_mut()
                }
            } else {
                let (hay_len, _) = scan_c_string(haystack, hay_bound);
                if hay_len >= needle_len {
                    let hs = std::slice::from_raw_parts(haystack.cast::<u8>(), hay_len);
                    let ns = std::slice::from_raw_parts(needle.cast::<u8>(), needle_len);
                    match frankenlibc_core::string::mem::memmem(hs, hay_len, ns, needle_len) {
                        Some(idx) => haystack.add(idx) as *mut c_char,
                        None => std::ptr::null_mut(),
                    }
                } else {
                    std::ptr::null_mut()
                }
            }
        };
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

    let hay_known = known_remaining(haystack as usize);
    let needle_known = known_remaining(needle as usize);
    let (_mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        haystack as usize,
        0,
        false,
        hay_known.is_none() && needle_known.is_none(),
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

    let hay_bound = hay_known;
    let needle_bound = needle_known;

    // SAFETY: known allocations are scanned only within their live extent;
    // untracked strict-mode strings preserve raw libc scan semantics.
    let (out, adverse, work) = unsafe {
        let (needle_len, needle_terminated) = scan_c_string(needle, needle_bound);
        let (hay_len, hay_terminated) = scan_c_string(haystack, hay_bound);
        let mut out_local = std::ptr::null_mut();
        let mut work_local = 0usize;

        if needle_len == 0 {
            out_local = haystack as *mut c_char;
            work_local = 1;
        } else if hay_len >= needle_len {
            // Route the substring match to the core Two-Way searcher (O(hay+needle))
            // instead of the old naive O(hay_len * needle_len) double loop, which was
            // quadratic on adversarial inputs (e.g. hay="aaaa…", needle="aaa…c") —
            // measured 164-455x slower than core memmem and a CPU-DoS vector. core memmem
            // is pure (no global state), so it is safe on this strict/raw path.
            let hay_slice = std::slice::from_raw_parts(haystack.cast::<u8>(), hay_len);
            let needle_slice = std::slice::from_raw_parts(needle.cast::<u8>(), needle_len);
            match frankenlibc_core::string::mem::memmem(
                hay_slice, hay_len, needle_slice, needle_len,
            ) {
                Some(idx) => {
                    out_local = haystack.add(idx) as *mut c_char;
                    work_local = idx.saturating_add(needle_len);
                }
                None => {
                    work_local = hay_len;
                }
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

#[cfg(feature = "owned-tls-cache")]
static STRTOK_SAVE_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<usize> =
    crate::owned_tls_cache::OwnedTlsCache::new(|| 0);

#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static STRTOK_SAVE: std::cell::Cell<*mut c_char> = const { std::cell::Cell::new(std::ptr::null_mut()) };
}

fn strtok_saved_ptr() -> *mut c_char {
    #[cfg(feature = "owned-tls-cache")]
    {
        STRTOK_SAVE_OWNED_TLS.with(|saved| *saved as *mut c_char)
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        STRTOK_SAVE.get()
    }
}

fn set_strtok_saved_ptr(ptr: *mut c_char) {
    #[cfg(feature = "owned-tls-cache")]
    {
        STRTOK_SAVE_OWNED_TLS.with(|saved| *saved = ptr as usize);
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        STRTOK_SAVE.set(ptr);
    }
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
    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict body's
    // RETURN + thread-local saved-ptr update — mirrors the strtok_r fast path with
    // `strtok_saved_ptr()`/`set_strtok_saved_ptr()` and `core::strtok::strtok`.
    // Skips stage_context + decide + observe + stage-trace.
    if runtime_policy::strict_passthrough_active() {
        if delim.is_null() {
            return std::ptr::null_mut();
        }
        unsafe {
            let saved = strtok_saved_ptr();
            let current = if s.is_null() { saved } else { s };
            if current.is_null() {
                set_strtok_saved_ptr(std::ptr::null_mut());
                return std::ptr::null_mut();
            }
            let delim_bound = known_remaining(delim as usize);
            let (delim_len, delim_terminated) = scan_c_string(delim, delim_bound);
            if !delim_terminated {
                set_strtok_saved_ptr(std::ptr::null_mut());
                return std::ptr::null_mut();
            }
            // FUSED small delim set (1..=4): mirror the strtok_r fused path (skip
            // leading delimiters, find token end, NUL-write, advance the thread-local
            // saved ptr) — O(n²) full-tokenization loop → O(n). Byte-identical to
            // `core::str::strtok::strtok`.
            if (1..=4).contains(&delim_len) {
                let d = delim.cast::<u8>();
                let set = match delim_len {
                    1 => [*d, *d, *d, *d],
                    2 => [*d, *d.add(1), *d, *d.add(1)],
                    3 => [*d, *d.add(1), *d.add(2), *d.add(2)],
                    _ => [*d, *d.add(1), *d.add(2), *d.add(3)],
                };
                let start = scan_c_string_for_set4(current, set, true);
                if *current.add(start).cast::<u8>() == 0 {
                    set_strtok_saved_ptr(std::ptr::null_mut());
                    return std::ptr::null_mut();
                }
                let tok_len = scan_c_string_for_set4(current.add(start), set, false);
                let end = start + tok_len;
                let end_ptr = current.add(end).cast::<u8>();
                let next = if *end_ptr != 0 {
                    *end_ptr = 0;
                    end + 1
                } else {
                    end
                };
                set_strtok_saved_ptr(current.add(next));
                return current.add(start) as *mut c_char;
            }
            // Large ALL-ASCII delim set (>4): FUSED page-safe PSHUFB early-stop
            // (mirrors the strtok_r >4 path; thread-local saved ptr). O(n) loop.
            #[cfg(target_arch = "x86_64")]
            if delim_len > 4 && all_bytes_ascii(delim.cast::<u8>(), delim_len) {
                let (lo16, hi16) = build_pshufb_lut(delim.cast::<u8>(), delim_len);
                let start = scan_c_string_pshufb(current, &lo16, &hi16, false);
                if *current.add(start).cast::<u8>() == 0 {
                    set_strtok_saved_ptr(std::ptr::null_mut());
                    return std::ptr::null_mut();
                }
                let tok_len = scan_c_string_pshufb(current.add(start), &lo16, &hi16, true);
                let end = start + tok_len;
                let end_ptr = current.add(end).cast::<u8>();
                let next = if *end_ptr != 0 {
                    *end_ptr = 0;
                    end + 1
                } else {
                    end
                };
                set_strtok_saved_ptr(current.add(next));
                return current.add(start) as *mut c_char;
            }
            let (scan_limit, terminated) = scan_c_string(current, None);
            let slice_len = if terminated { scan_limit + 1 } else { scan_limit };
            let s_slice = std::slice::from_raw_parts_mut(current as *mut u8, slice_len);
            let delim_slice = std::slice::from_raw_parts(delim as *const u8, delim_len + 1);
            return match frankenlibc_core::string::strtok::strtok(s_slice, delim_slice) {
                Some((start, len)) => {
                    let token_start = current.add(start);
                    let token_end_idx = start + len;
                    let next_pos = if token_end_idx + 1 < s_slice.len() {
                        token_end_idx + 1
                    } else {
                        token_end_idx
                    };
                    set_strtok_saved_ptr(current.add(next_pos));
                    token_start
                }
                None => {
                    set_strtok_saved_ptr(std::ptr::null_mut());
                    std::ptr::null_mut()
                }
            };
        }
    }

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
        let saved = strtok_saved_ptr();
        let current = if s.is_null() { saved } else { s };
        let mut work = 0usize;

        if current.is_null() {
            set_strtok_saved_ptr(std::ptr::null_mut());
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

            let delim_bound = known_remaining(delim as usize);
            let (delim_len, delim_terminated) = scan_c_string(delim, delim_bound);
            if !delim_terminated {
                set_strtok_saved_ptr(std::ptr::null_mut());
                work = scan_limit.saturating_add(delim_len);
                (std::ptr::null_mut(), true, work)
            } else {
                let delim_slice_len = delim_len + 1;
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
                        set_strtok_saved_ptr(current.add(next_pos));
                        work = next_pos; // Approximate work
                        (token_start, false, work)
                    }
                    None => {
                        set_strtok_saved_ptr(std::ptr::null_mut());
                        work = scan_limit;
                        (std::ptr::null_mut(), false, work)
                    }
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
    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict body's
    // RETURN + `*saveptr` update — pick `current` (s or *saveptr), scan it (unbounded)
    // + delim (same ungated `known_remaining(delim)`), core `strtok_r`, advance
    // `*saveptr`. Skips stage_context + decide + observe + stage-trace (interleaved
    // telemetry, return/side-effects unchanged). strsep-style clean replication.
    if runtime_policy::strict_passthrough_active() {
        if delim.is_null() || saveptr.is_null() {
            return std::ptr::null_mut();
        }
        unsafe {
            let current = if s.is_null() { *saveptr } else { s };
            if current.is_null() {
                *saveptr = std::ptr::null_mut();
                return std::ptr::null_mut();
            }
            let delim_bound = known_remaining(delim as usize);
            let (delim_len, delim_terminated) = scan_c_string(delim, delim_bound);
            if !delim_terminated {
                *saveptr = std::ptr::null_mut();
                return std::ptr::null_mut();
            }
            // FUSED small delim set (1..=4): TWO early-stopping passes — skip leading
            // delimiters (strspn) then find the token end (strcspn) — instead of a
            // full `scan_c_string(current)` pre-scan + core pass. Byte-identical to
            // `core::str::strtok::strtok_r` (skip-leading via strspn_set, token end
            // via strcspn_set, NUL-write the trailing delimiter, advance save_ptr).
            // Turns a full tokenization loop from O(n²) into O(n) (see strsep).
            if (1..=4).contains(&delim_len) {
                let d = delim.cast::<u8>();
                let set = match delim_len {
                    1 => [*d, *d, *d, *d],
                    2 => [*d, *d.add(1), *d, *d.add(1)],
                    3 => [*d, *d.add(1), *d.add(2), *d.add(2)],
                    _ => [*d, *d.add(1), *d.add(2), *d.add(3)],
                };
                // Skip leading delimiters: first non-delim-or-NUL (strspn == complement).
                let start = scan_c_string_for_set4(current, set, true);
                if *current.add(start).cast::<u8>() == 0 {
                    // Only delimiters (or empty) remain → no token.
                    *saveptr = std::ptr::null_mut();
                    return std::ptr::null_mut();
                }
                // Token end from the token start: first delim-or-NUL (strcspn).
                let tok_len = scan_c_string_for_set4(current.add(start), set, false);
                let end = start + tok_len;
                let end_ptr = current.add(end).cast::<u8>();
                let next = if *end_ptr != 0 {
                    *end_ptr = 0; // replace the trailing delimiter with NUL (matches core)
                    end + 1
                } else {
                    end // token ran to the NUL; save_ptr points at it (next call → None)
                };
                *saveptr = current.add(next);
                return current.add(start) as *mut c_char;
            }
            // Large ALL-ASCII delim set (>4): FUSED page-safe PSHUFB early-stop for
            // BOTH scans (skip leading delims via strspn, token end via strcspn) —
            // classifier-throughput body scan, no prescan → O(n) loop, no scalar
            // long-token regression. Non-ASCII sets fall through to the slice path.
            #[cfg(target_arch = "x86_64")]
            if delim_len > 4 && all_bytes_ascii(delim.cast::<u8>(), delim_len) {
                let (lo16, hi16) = build_pshufb_lut(delim.cast::<u8>(), delim_len);
                let start = scan_c_string_pshufb(current, &lo16, &hi16, false);
                if *current.add(start).cast::<u8>() == 0 {
                    *saveptr = std::ptr::null_mut();
                    return std::ptr::null_mut();
                }
                let tok_len = scan_c_string_pshufb(current.add(start), &lo16, &hi16, true);
                let end = start + tok_len;
                let end_ptr = current.add(end).cast::<u8>();
                let next = if *end_ptr != 0 {
                    *end_ptr = 0;
                    end + 1
                } else {
                    end
                };
                *saveptr = current.add(next);
                return current.add(start) as *mut c_char;
            }
            let (scan_limit, terminated) = scan_c_string(current, None);
            let slice_len = if terminated { scan_limit + 1 } else { scan_limit };
            let s_slice = std::slice::from_raw_parts_mut(current as *mut u8, slice_len);
            let delim_slice = std::slice::from_raw_parts(delim as *const u8, delim_len + 1);
            return match frankenlibc_core::string::strtok::strtok_r(s_slice, delim_slice, 0) {
                Some((start, _len, next_offset)) => {
                    *saveptr = current.add(next_offset);
                    current.add(start)
                }
                None => {
                    *saveptr = std::ptr::null_mut();
                    std::ptr::null_mut()
                }
            };
        }
    }

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

        let delim_bound = known_remaining(delim as usize);
        let (delim_len, delim_terminated) = scan_c_string(delim, delim_bound);
        if !delim_terminated {
            *saveptr = std::ptr::null_mut();
            runtime_policy::observe(
                ApiFamily::StringMemory,
                decision.profile,
                runtime_policy::scaled_cost(8, scan_limit.saturating_add(delim_len)),
                true,
            );
            record_string_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Bounds)),
            );
            return std::ptr::null_mut();
        }

        let delim_slice_len = delim_len + 1;
        let delim_slice = std::slice::from_raw_parts(delim as *const u8, delim_slice_len);

        // Core `strtok_r` returns (start, len, next_offset) relative to the slice start (0)

        match frankenlibc_core::string::strtok::strtok_r(s_slice, delim_slice, 0) {
            Some((start, _len, next_offset)) => {
                let token = current.add(start); // ubs:ignore - substring pointer, not a secret
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
    // Strict-mode fast path (DEFAULT deployed): strict passthrough has no membrane
    // bound, byte-identical to the strict common branch — the fused SWAR
    // case-compare `scan_strcasecmp(.., usize::MAX)`. Skips stage_context + decide +
    // observe + stage-trace (read-family sibling of the strncmp fast path).
    if runtime_policy::strict_passthrough_active() {
        if s1.is_null() || s2.is_null() {
            return 0;
        }
        return unsafe { scan_strcasecmp(s1, s2, usize::MAX) }.0;
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
        if lhs_bound.is_none() && rhs_bound.is_none() {
            // Common path: one fused SWAR case-compare with early exit, instead of
            // two full length scans plus a separate compare pass.
            scan_strcasecmp(s1, s2, usize::MAX)
        } else {
            // Repair path: preserve the exact clamped-slice semantics (out-of-bound
            // bytes treated as NUL by the core comparator).
            let (s1_len, s1_term) = scan_c_string(s1, lhs_bound);
            let (s2_len, s2_term) = scan_c_string(s2, rhs_bound);
            let s1_slice_len = if s1_term { s1_len + 1 } else { s1_len };
            let s2_slice_len = if s2_term { s2_len + 1 } else { s2_len };
            let s1_slice = std::slice::from_raw_parts(s1.cast::<u8>(), s1_slice_len);
            let s2_slice = std::slice::from_raw_parts(s2.cast::<u8>(), s2_slice_len);
            let r = frankenlibc_core::string::str::strcasecmp(s1_slice, s2_slice);
            (r, s1_len.max(s2_len))
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

    // Strict-mode fast path (DEFAULT deployed): strict passthrough has no membrane
    // clamp (`cmp_limit == n`, not adverse), byte-identical to the strict full path —
    // the fused SWAR case-compare `scan_strcasecmp(.., n)`. Skips the bookkeeping.
    if runtime_policy::strict_passthrough_active() {
        if s1.is_null() || s2.is_null() {
            return 0;
        }
        return unsafe { scan_strcasecmp(s1, s2, n) }.0;
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
    // Fused SWAR case-compare (shared scan_strcasecmp), byte-identical to the old
    // scalar tolower loop; bounded by cmp_limit and page-cross guarded.
    let result = unsafe { scan_strcasecmp(s1, s2, cmp_limit).0 };

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
    // Strict-mode fast path (DEFAULT deployed): strict passthrough has no clamp, so
    // this is byte-identical to the strict full body — scan s + accept, core strspn.
    // Skips stage_context + decide + observe + stage-trace.
    if !s.is_null() && !accept.is_null() && runtime_policy::strict_passthrough_active() {
        return unsafe {
            let (accept_len, accept_terminated) = scan_c_string(accept, None);
            // Small accept set (1..=4): FUSED single early-stopping pass — stop at the
            // first byte NOT in the set (or NUL) — instead of a full pre-scan of `s` +
            // a second `core::str::strspn` pass. Byte-identical to the core span (NUL is
            // never a set member, so `!member` is exactly the strspn stop predicate),
            // same duplicate-fill of the membership set.
            if (1..=4).contains(&accept_len) {
                let a = accept.cast::<u8>();
                let set = match accept_len {
                    1 => [*a, *a, *a, *a],
                    2 => [*a, *a.add(1), *a, *a.add(1)],
                    3 => [*a, *a.add(1), *a.add(2), *a.add(2)],
                    _ => [*a, *a.add(1), *a.add(2), *a.add(3)],
                };
                return scan_c_string_for_set4(s, set, true);
            }
            let (s_len, s_terminated) = scan_c_string(s, None);
            let s_slice_len = if s_terminated { s_len + 1 } else { s_len };
            let accept_slice_len = if accept_terminated { accept_len + 1 } else { accept_len };
            let s_slice = std::slice::from_raw_parts(s.cast::<u8>(), s_slice_len);
            let accept_slice = std::slice::from_raw_parts(accept.cast::<u8>(), accept_slice_len);
            frankenlibc_core::string::str::strspn(s_slice, accept_slice)
        };
    }

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
    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict full
    // body — scan s + reject, core strcspn. Skips the membrane bookkeeping.
    if !s.is_null() && !reject.is_null() && runtime_policy::strict_passthrough_active() {
        return unsafe {
            let (reject_len, reject_terminated) = scan_c_string(reject, None);
            // Single-char reject: strcspn(s, [c]) == index of the first `c` (or strlen(s)
            // if none) — the page-safe early-stopping scan returns exactly that, with NO
            // full-haystack pre-scan. Byte-identical.
            if reject_len == 1 {
                let target = *(reject.cast::<u8>());
                let (i, _found, _) = scan_c_string_for_byte(s, target, None);
                return i;
            }
            // Small reject set (2..=4): FUSED single early-stopping pass from the raw
            // pointer instead of a full pre-scan of `s` + a second membership pass.
            // Byte-identical to `core::str::strcspn` over the NUL-inclusive slice
            // (`find_any_of4_or_nul_fused`), same duplicate-fill of the membership set.
            if (2..=4).contains(&reject_len) {
                let r = reject.cast::<u8>();
                let set = match reject_len {
                    2 => [*r, *r.add(1), *r, *r.add(1)],
                    3 => [*r, *r.add(1), *r.add(2), *r.add(2)],
                    _ => [*r, *r.add(1), *r.add(2), *r.add(3)],
                };
                return scan_c_string_for_set4(s, set, false);
            }
            let (s_len, s_terminated) = scan_c_string(s, None);
            let s_slice_len = if s_terminated { s_len + 1 } else { s_len };
            let reject_slice_len = if reject_terminated { reject_len + 1 } else { reject_len };
            let s_slice = std::slice::from_raw_parts(s.cast::<u8>(), s_slice_len);
            let reject_slice = std::slice::from_raw_parts(reject.cast::<u8>(), reject_slice_len);
            frankenlibc_core::string::str::strcspn(s_slice, reject_slice)
        };
    }

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
    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict full
    // body — scan s + accept, core strpbrk, map index to pointer. Skips bookkeeping.
    if !s.is_null() && !accept.is_null() && runtime_policy::strict_passthrough_active() {
        return unsafe {
            let (accept_len, accept_terminated) = scan_c_string(accept, None);
            // Single-char accept: strpbrk(s, [c]) == strchr(s, c) — the page-safe
            // early-stopping scan stops at the first `c` (NO full-haystack pre-scan).
            // Byte-identical: c found → s+i, NUL/not-found → null.
            if accept_len == 1 {
                let target = *(accept.cast::<u8>());
                let (i, found, _) = scan_c_string_for_byte(s, target, None);
                return if found {
                    s.add(i) as *mut c_char
                } else {
                    std::ptr::null_mut()
                };
            }
            // Small accept set (2..=4): FUSED single early-stopping pass. The stop
            // index is the first set-member OR the NUL; map member→pointer, NUL→null.
            // Byte-identical to `core::str::strpbrk` (`find_any_of4_or_nul` + the
            // `s[index] != 0` member test) over the NUL-inclusive slice.
            if (2..=4).contains(&accept_len) {
                let a = accept.cast::<u8>();
                let set = match accept_len {
                    2 => [*a, *a.add(1), *a, *a.add(1)],
                    3 => [*a, *a.add(1), *a.add(2), *a.add(2)],
                    _ => [*a, *a.add(1), *a.add(2), *a.add(3)],
                };
                let idx = scan_c_string_for_set4(s, set, false);
                return if *s.add(idx).cast::<u8>() != 0 {
                    s.add(idx) as *mut c_char
                } else {
                    std::ptr::null_mut()
                };
            }
            let (s_len, s_terminated) = scan_c_string(s, None);
            let s_slice_len = if s_terminated { s_len + 1 } else { s_len };
            let accept_slice_len = if accept_terminated { accept_len + 1 } else { accept_len };
            let s_slice = std::slice::from_raw_parts(s.cast::<u8>(), s_slice_len);
            let accept_slice = std::slice::from_raw_parts(accept.cast::<u8>(), accept_slice_len);
            match frankenlibc_core::string::str::strpbrk(s_slice, accept_slice) {
                Some(idx) => s.add(idx) as *mut c_char,
                None => std::ptr::null_mut(),
            }
        };
    }

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
    // Strict-mode fast path (DEFAULT deployed): strict passthrough has `bound == None`,
    // byte-identical to the strict full body — scan s, malloc(len+1), copy, NUL-terminate.
    // Skips stage_context + decide + observe + stage-trace. (malloc dominates strdup's
    // cost, so this is a smaller margin, but strdup is extremely hot.)
    if runtime_policy::strict_passthrough_active() {
        if s.is_null() {
            return std::ptr::null_mut();
        }
        return unsafe {
            let (s_len, _) = scan_c_string(s, None);
            let dst = crate::malloc_abi::malloc(s_len + 1);
            if dst.is_null() {
                return std::ptr::null_mut();
            }
            raw_memcpy_bytes(dst.cast::<u8>(), s.cast::<u8>(), s_len);
            *(dst as *mut u8).add(s_len) = 0;
            dst.cast::<c_char>()
        };
    }

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
    // Strict-mode fast path (DEFAULT deployed): strict passthrough has `bound ==
    // Some(n)` (repair false → no known-clamp), byte-identical to the strict body —
    // scan s bounded by n, malloc(copy_len+1), copy, NUL. Skips the membrane tax.
    if runtime_policy::strict_passthrough_active() {
        if s.is_null() {
            return std::ptr::null_mut();
        }
        return unsafe {
            let (s_len, _) = scan_c_string(s, Some(n));
            let copy_len = s_len.min(n);
            let dst = crate::malloc_abi::malloc(copy_len + 1);
            if dst.is_null() {
                return std::ptr::null_mut();
            }
            if copy_len > 0 {
                raw_memcpy_bytes(dst.cast::<u8>(), s.cast::<u8>(), copy_len);
            }
            *(dst as *mut u8).add(copy_len) = 0;
            dst.cast::<c_char>()
        };
    }

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

    // Strict-mode fast path (DEFAULT deployed): strict passthrough has no clamp
    // (`hay_scan == haystack_len`, `needle_scan == needle_len`), byte-identical to
    // the strict full body — core Two-Way `memmem` over the explicit lengths,
    // returning `haystack+idx`/null. Skips stage_context + decide + observe +
    // stage-trace. Explicit-length op (no NUL scan).
    if runtime_policy::strict_passthrough_active() {
        if haystack.is_null() || needle.is_null() || haystack_len == 0 {
            return std::ptr::null_mut();
        }
        return unsafe {
            let h_bytes = std::slice::from_raw_parts(haystack.cast::<u8>(), haystack_len);
            let n_bytes = std::slice::from_raw_parts(needle.cast::<u8>(), needle_len);
            match frankenlibc_core::string::mem::memmem(h_bytes, haystack_len, n_bytes, needle_len) {
                Some(idx) => (haystack as *mut u8).add(idx).cast::<c_void>(),
                None => std::ptr::null_mut(),
            }
        };
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
    // Strict-mode fast path (the DEFAULT deployed mode): strict passthrough forces
    // `decide()` Allow with no clamp, so the result is exactly the raw copy with the
    // end pointer `dst + n` (byte-identical to the full path). Skip the membrane
    // guard + decide + stage-trace + observe machinery, mirroring `memcpy`/`memmove`.
    if runtime_policy::strict_passthrough_active() {
        if n == 0 {
            return dst;
        }
        if dst.is_null() || src.is_null() {
            return std::ptr::null_mut();
        }
        unsafe { raw_memcpy_bytes(dst.cast::<u8>(), src.cast::<u8>(), n) };
        return unsafe { (dst as *mut u8).add(n).cast() };
    }

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
    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict full
    // body's RETURN — scan haystack + needle (same ungated `known_remaining` bounds),
    // then core case-insensitive `strcasestr` over the NUL-inclusive slices. Skips
    // stage_context + decide + observe + stage-trace (mirrors the strstr fast path).
    if runtime_policy::strict_passthrough_active() {
        if haystack.is_null() {
            return std::ptr::null_mut();
        }
        if needle.is_null() {
            return haystack as *mut c_char;
        }
        return unsafe {
            let hay_bound = known_remaining(haystack as usize);
            let needle_bound = known_remaining(needle as usize);
            let (hay_len, hay_terminated) = scan_c_string(haystack, hay_bound);
            let (needle_len, needle_terminated) = scan_c_string(needle, needle_bound);
            let h_slice_len = if hay_terminated { hay_len + 1 } else { hay_len };
            let n_slice_len = if needle_terminated { needle_len + 1 } else { needle_len };
            let h_slice = std::slice::from_raw_parts(haystack.cast::<u8>(), h_slice_len);
            let n_slice = std::slice::from_raw_parts(needle.cast::<u8>(), n_slice_len);
            match frankenlibc_core::string::str::strcasestr(h_slice, n_slice) {
                Some(idx) => haystack.add(idx) as *mut c_char,
                None => std::ptr::null_mut(),
            }
        };
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

    let hay_known = known_remaining(haystack as usize);
    let needle_known = known_remaining(needle as usize);
    let (_mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        haystack as usize,
        0,
        false,
        hay_known.is_none() && needle_known.is_none(),
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

    let hay_bound = hay_known;
    let needle_bound = needle_known;

    // SAFETY: known allocations are scanned only within their live extent;
    // untracked strict-mode strings preserve raw libc scan semantics.
    let (out, span, adverse) = unsafe {
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
            Some(idx) => (
                haystack.add(idx) as *mut c_char,
                hay_len,
                !hay_terminated || !needle_terminated,
            ),
            None => (
                std::ptr::null_mut(),
                hay_len,
                !hay_terminated || !needle_terminated,
            ),
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
        adverse,
    );
    out
}

// ---------------------------------------------------------------------------
// strerror
// ---------------------------------------------------------------------------

#[cfg(feature = "owned-tls-cache")]
static STRERROR_BUF_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<[u8; 256]> =
    crate::owned_tls_cache::OwnedTlsCache::new(|| [0; 256]);

#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static STRERROR_BUF: std::cell::RefCell<[u8; 256]> = const { std::cell::RefCell::new([0u8; 256]) };
}

pub(crate) fn rendered_strerror_message(errnum: c_int) -> (String, bool) {
    // Use `strerrordesc_np`'s description table, which is complete and glibc-exact
    // across the full Linux errno range (the previous core table was missing the
    // high errnos 102..=133 — ENETRESET, EHOSTUNREACH, ESTALE, EDQUOT, EOWNERDEAD,
    // ERFKILL, EHWPOISON, etc. — and rendered them as "Unknown error N"). Found by
    // strerror_scan_differential_fuzz.
    let desc = strerrordesc_np(errnum);
    if desc.is_null() {
        (format!("Unknown error {errnum}"), true)
    } else {
        // SAFETY: strerrordesc_np returns a static NUL-terminated string or null.
        let msg = unsafe { std::ffi::CStr::from_ptr(desc) }
            .to_string_lossy()
            .into_owned();
        (msg, false)
    }
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
    let (msg, _) = rendered_strerror_message(errnum);
    #[cfg(feature = "owned-tls-cache")]
    {
        STRERROR_BUF_OWNED_TLS.with(|buf| {
            let msg_bytes = msg.as_bytes();
            let copy_len = msg_bytes.len().min(buf.len() - 1);
            buf[..copy_len].copy_from_slice(&msg_bytes[..copy_len]);
            buf[copy_len] = 0;
            buf.as_mut_ptr() as *mut c_char
        })
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
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
}

#[cfg(feature = "owned-tls-cache")]
static STRSIGNAL_BUF_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<[u8; 64]> =
    crate::owned_tls_cache::OwnedTlsCache::new(|| [0; 64]);

#[cfg(not(feature = "owned-tls-cache"))]
std::thread_local! {
    static STRSIGNAL_BUF: std::cell::RefCell<[u8; 64]> = const { std::cell::RefCell::new([0u8; 64]) };
}

fn with_strsignal_buffer<R>(callback: impl FnOnce(&mut [u8; 64]) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        STRSIGNAL_BUF_OWNED_TLS.with(callback)
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        STRSIGNAL_BUF.with(|cell| {
            let mut buf = cell.borrow_mut();
            callback(&mut buf)
        })
    }
}

// ---------------------------------------------------------------------------
// strerror_r
// ---------------------------------------------------------------------------

/// GNU `strerror_r` -- returns a pointer to the error message for `errnum`.
///
/// This is glibc's default (`_GNU_SOURCE`) variant and the one exported under
/// the bare `strerror_r` symbol: it returns a `char *`, NOT an `int`. For a
/// known errno it returns a pointer to a static, immutable message string and
/// leaves `buf` untouched (matching glibc, which hands back the static string
/// and ignores `buf`); for an unknown errno it formats "Unknown error N" into
/// `buf` (truncated to `buflen`) and returns `buf`. The XSI/POSIX
/// int-returning variant is [`crate::stdlib_abi::__xpg_strerror_r`].
///
/// fl previously exported the XSI (int) behavior under this symbol, so a
/// `_GNU_SOURCE` caller (the common case) read the int return as a pointer and
/// got garbage. Verified against the host glibc.
///
/// # Safety
///
/// Caller must ensure `buf` is valid for `buflen` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> *mut c_char {
    // Known errno: return the static description pointer; `buf` is unused.
    let desc = strerrordesc_np(errnum);
    if !desc.is_null() {
        return desc as *mut c_char;
    }
    // Unknown errno: format "Unknown error N" into the caller buffer.
    if buf.is_null() || buflen == 0 {
        return buf;
    }
    let msg = format!("Unknown error {errnum}");
    let msg_bytes = msg.as_bytes();
    let copy_len = msg_bytes.len().min(buflen - 1);
    // SAFETY: caller guarantees `buf` is valid for `buflen` bytes.
    unsafe {
        raw_memcpy_bytes(buf.cast::<u8>(), msg_bytes.as_ptr(), copy_len);
        *buf.add(copy_len) = 0;
    }
    buf
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
    // Strict-mode fast path (DEFAULT deployed): strict passthrough has no clamp
    // (`copy_len == n`), byte-identical to the strict full body — core memccpy over
    // `n` bytes, returning `dst+idx` past the copied `c` or null. Skips the membrane
    // guard + decide + observe + stage-trace. Bounded-`n` op (fixed extent).
    if runtime_policy::strict_passthrough_active() {
        if n == 0 || dst.is_null() || src.is_null() {
            return std::ptr::null_mut();
        }
        return unsafe {
            let d_slice = std::slice::from_raw_parts_mut(dst.cast::<u8>(), n);
            let s_slice = std::slice::from_raw_parts(src.cast::<u8>(), n);
            match frankenlibc_core::string::memccpy(d_slice, s_slice, c as u8, n) {
                Some(idx) => (dst as *mut u8).add(idx).cast(),
                None => std::ptr::null_mut(),
            }
        };
    }

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
    // Strict-mode fast path (DEFAULT deployed): strict passthrough has no clamp
    // (`set_len == n`), byte-identical to the strict full body (`core::bzero` over
    // `n`). Skips the membrane guard + decide + observe + stage-trace. Fixed-`n`
    // write, mirroring the deployed `memset` fast path.
    if runtime_policy::strict_passthrough_active() {
        if n == 0 || s.is_null() {
            return;
        }
        // raw_memset_bytes(.., 0, n) zeros exactly `n` bytes — byte-identical to the
        // strict full body's `core::bzero` (same SIMD memset the reentrant fallback uses).
        unsafe { raw_memset_bytes(s.cast::<u8>(), 0, n) };
        return;
    }

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

/// NetBSD `explicit_memset(s, c, n) -> *s` — `memset` variant
/// guaranteed not to be optimized away. Companion to `explicit_bzero`
/// for non-zero fill values.
///
/// # Safety
///
/// `s` must be valid for `n` bytes; `c` is interpreted as `unsigned
/// char` and replicated across the buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn explicit_memset(s: *mut c_void, c: c_int, n: usize) -> *mut c_void {
    // Route through our ABI memset so explicit_memset gets the same
    // null handling, membrane accounting, and volatile byte path as memset.
    let out = unsafe { memset(s, c, n) };
    // Defeat dead-store elimination: ensure the compiler can't prove
    // the write is unused. black_box pins the address through an
    // optimization barrier.
    std::hint::black_box(s);
    out
}

/// C23 `memset_explicit(b, c, len) -> *b` — guaranteed non-elidable
/// byte fill. NetBSD exposes this as an alias of [`explicit_memset`].
///
/// # Safety
///
/// `b` must be valid for `len` bytes; `c` is interpreted as `unsigned
/// char` and replicated across the buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn memset_explicit(b: *mut c_void, c: c_int, len: usize) -> *mut c_void {
    unsafe { explicit_memset(b, c, len) }
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

    // Strict-mode fast path (DEFAULT deployed): strict passthrough has no clamp
    // (`swap_len == n`), byte-identical to the strict body — core swab over `n`.
    // Skips the membrane guard + decide + observe + stage-trace. Fixed-`n` write.
    if runtime_policy::strict_passthrough_active() {
        if dst.is_null() || src.is_null() {
            return;
        }
        unsafe {
            let s = std::slice::from_raw_parts(src.cast::<u8>(), n);
            let d = std::slice::from_raw_parts_mut(dst.cast::<u8>(), n);
            frankenlibc_core::string::swab(s, d, n);
        }
        return;
    }

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

    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict full
    // body's RETURN + `*stringp` update — scan s (unbounded) + delim (same ungated
    // `known_remaining(delim)` bound), then core `strsep` with the post-delimiter
    // `*stringp` advance. Skips stage_context + decide + observe + stage-trace.
    if runtime_policy::strict_passthrough_active() {
        if delim.is_null() {
            unsafe { *stringp = std::ptr::null_mut() };
            return s;
        }
        return unsafe {
            let delim_bound = known_remaining(delim as usize);
            let (delim_len, delim_term) = scan_c_string(delim, delim_bound);
            if !delim_term {
                return std::ptr::null_mut();
            }
            // Small delim set (1..=4): FUSED single early-stopping pass over `s`
            // instead of the full `scan_c_string(s)` pre-scan + core membership
            // pass. Byte-identical to `core::str::strsep` (first delim → NUL-write
            // it, advance `*stringp` past it; no delim → NUL stop → `*stringp` null;
            // returned token = original `s` either way). NOTE: a 1-char delim is
            // routed through set4 (`[d;4]`) too, NOT `scan_c_string_for_byte` — the
            // set4 scan ORs target|NUL in SIMD and does ONE movemask per window,
            // whereas for_byte takes two (nul, target) separately and MEASURED ~2x
            // worse fl/glibc here.
            if (1..=4).contains(&delim_len) {
                let d = delim.cast::<u8>();
                let set = match delim_len {
                    1 => [*d, *d, *d, *d],
                    2 => [*d, *d.add(1), *d, *d.add(1)],
                    3 => [*d, *d.add(1), *d.add(2), *d.add(2)],
                    _ => [*d, *d.add(1), *d.add(2), *d.add(3)],
                };
                let idx = scan_c_string_for_set4(s, set, false);
                let stop = s.add(idx).cast::<u8>();
                if *stop != 0 {
                    *stop = 0; // replace the delimiter with NUL (matches core strsep)
                    *stringp = s.add(idx + 1);
                } else {
                    *stringp = std::ptr::null_mut();
                }
                return s;
            }
            // Large ALL-ASCII delim set (>4): FUSED page-safe PSHUFB first-delimiter
            // scan (strcspn direction) — O(n) tokenization, classifier body scan.
            #[cfg(target_arch = "x86_64")]
            if delim_len > 4 && all_bytes_ascii(delim.cast::<u8>(), delim_len) {
                let (lo16, hi16) = build_pshufb_lut(delim.cast::<u8>(), delim_len);
                let idx = scan_c_string_pshufb(s, &lo16, &hi16, true);
                let stop = s.add(idx).cast::<u8>();
                if *stop != 0 {
                    *stop = 0;
                    *stringp = s.add(idx + 1);
                } else {
                    *stringp = std::ptr::null_mut();
                }
                return s;
            }
            let (s_len, s_term) = scan_c_string(s, None);
            let s_slice_len = if s_term { s_len + 1 } else { s_len };
            let s_slice = std::slice::from_raw_parts_mut(s.cast::<u8>(), s_slice_len);
            let delim_slice = std::slice::from_raw_parts(delim.cast::<u8>(), delim_len + 1);
            match frankenlibc_core::string::str::strsep(s_slice, delim_slice) {
                Some(idx) => {
                    *stringp = s.add(idx + 1);
                    s
                }
                None => {
                    *stringp = std::ptr::null_mut();
                    s
                }
            }
        };
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
    let delim_bound = known_remaining(delim as usize);

    // SAFETY: bounded scan.
    let (result, span, adverse) = unsafe {
        let (s_len, s_term) = scan_c_string(s, s_bound);
        let (delim_len, delim_term) = scan_c_string(delim, delim_bound);
        let s_slice_len = if s_term { s_len + 1 } else { s_len };
        if !delim_term {
            (std::ptr::null_mut(), s_len.saturating_add(delim_len), true)
        } else {
            let delim_slice_len = delim_len + 1;
            let s_slice = std::slice::from_raw_parts_mut(s.cast::<u8>(), s_slice_len);
            let delim_slice = std::slice::from_raw_parts(delim.cast::<u8>(), delim_slice_len);
            match frankenlibc_core::string::str::strsep(s_slice, delim_slice) {
                Some(idx) => {
                    // Update *stringp to point past the delimiter.
                    *stringp = s.add(idx + 1);
                    (s, s_len, s_bound.is_some())
                }
                None => {
                    *stringp = std::ptr::null_mut();
                    // Return the remaining string as the last token.
                    (s, s_len, s_bound.is_some())
                }
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
        adverse,
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
    // Strict-mode fast path (DEFAULT deployed) for the common case (valid dst): strict
    // passthrough has no clamp, so this is byte-identical to the strict full body —
    // scan src, copy `min(strlen, dstsize-1)` + NUL via the core, return strlen(src).
    // Skips stage_context + decide + observe + stage-trace. The null/zero-size edges
    // fall through to the full path (which returns strlen(src) per BSD contract).
    if !dst.is_null() && !src.is_null() && dstsize != 0 && runtime_policy::strict_passthrough_active()
    {
        return unsafe {
            let (src_len, src_terminated) = scan_c_string(src, None);
            let src_slice_len = if src_terminated { src_len + 1 } else { src_len };
            let src_slice = std::slice::from_raw_parts(src.cast::<u8>(), src_slice_len);
            let dst_slice = std::slice::from_raw_parts_mut(dst.cast::<u8>(), dstsize);
            frankenlibc_core::string::str::strlcpy(dst_slice, src_slice)
        };
    }

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
    // Strict-mode fast path (DEFAULT deployed) for the common case (valid dst): strict
    // passthrough has no clamp (`dst_limit == dstsize`), byte-identical to the strict
    // full body — scan src, core strlcat into `dst[..dstsize]`, return the BSD total
    // length. Skips stage_context + decide + observe + stage-trace. null/zero-size
    // edges fall through to the full path.
    if !dst.is_null() && !src.is_null() && dstsize != 0 && runtime_policy::strict_passthrough_active()
    {
        return unsafe {
            let (src_len, src_terminated) = scan_c_string(src, None);
            let src_slice_len = if src_terminated { src_len + 1 } else { src_len };
            let src_slice = std::slice::from_raw_parts(src.cast::<u8>(), src_slice_len);
            let dst_slice = std::slice::from_raw_parts_mut(dst.cast::<u8>(), dstsize);
            frankenlibc_core::string::str::strlcat(dst_slice, src_slice)
        };
    }

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
    // FrankenLibC uses the C/POSIX locale, where collation order IS byte order, so
    // strcoll is exactly strcmp (the core `strcoll` was already just `strcmp`).
    // Delegating to the strcmp ABI gives collation the fused single-pass
    // SWAR/32-byte-SIMD scan with early exit, instead of the old two full
    // length scans (scan_c_string x2) plus a separate compare pass — that triple
    // pass made strcoll ~4.4x slower than glibc strcoll on equal strings.
    unsafe { strcmp(s1, s2) }
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
    // Strict-mode fast path (DEFAULT deployed): strict passthrough has `src_bound ==
    // None`, byte-identical to the strict body — scan src; if dst null / n==0 return
    // strlen(src), else core `strxfrm` into `dst[..n]`. Skips the membrane tax.
    if runtime_policy::strict_passthrough_active() {
        if src.is_null() {
            return 0;
        }
        return unsafe {
            let (src_len, src_terminated) = scan_c_string(src, None);
            if dst.is_null() || n == 0 {
                src_len
            } else {
                let src_slice_len = if src_terminated { src_len + 1 } else { src_len };
                let src_slice = std::slice::from_raw_parts(src.cast::<u8>(), src_slice_len);
                let dst_slice = std::slice::from_raw_parts_mut(dst.cast::<u8>(), n);
                frankenlibc_core::string::str::strxfrm(dst_slice, src_slice, n)
            }
        };
    }

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

    let Some(pat_bytes) = (unsafe { read_c_string_bytes_with_nul(pattern) }) else {
        return regex::REG_BADPAT;
    };

    match regex::regex_compile(&pat_bytes, cflags) {
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

    // REG_STARTEND (BSD/GNU): the buffer is `string[rm_so..rm_eo]` — embedded
    // NULs allowed, no NUL terminator. The matched string logically ends at
    // rm_eo (`$` anchors there) and `^` still anchors at the true buffer start,
    // so a non-zero rm_so forces REG_NOTBOL; returned offsets are relative to
    // `string`, so rm_so is added back. (rm_so/rm_eo are read regardless of
    // nmatch, per the contract.)
    if eflags & regex::REG_STARTEND != 0 && !pmatch.is_null() {
        let first = unsafe { &*(pmatch as *const regex::RegMatch) };
        let (so, eo) = (first.rm_so, first.rm_eo);
        if so < 0 || eo < so {
            return regex::REG_NOMATCH;
        }
        let (so, eo) = (so as usize, eo as usize);
        // SAFETY: the caller guarantees `string[..eo]` is readable under the
        // REG_STARTEND contract (no NUL scan).
        let region = unsafe { core::slice::from_raw_parts(string as *const u8, eo) };
        let sub = &region[so..eo];

        let mut sub_eflags = eflags & !regex::REG_STARTEND;
        if so > 0 {
            // The slice's first position is `string + rm_so`. `^` matches there
            // only if it is a line start: under REG_NEWLINE with a `\n` just
            // before it (which then matches even if the caller set NOTBOL, since
            // NOTBOL only suppresses the true buffer-start BOL). Otherwise it is
            // not a BOL, so force NOTBOL.
            if compiled.newline_mode() && region.get(so - 1) == Some(&b'\n') {
                sub_eflags &= !regex::REG_NOTBOL;
            } else {
                sub_eflags |= regex::REG_NOTBOL;
            }
        }

        let rc = if nmatch == 0 {
            let mut dummy = [regex::RegMatch::default(); 1];
            regex::regex_exec_bytes(compiled, sub, &mut dummy, sub_eflags)
        } else {
            let pmatch_slice =
                unsafe { core::slice::from_raw_parts_mut(pmatch as *mut regex::RegMatch, nmatch) };
            let rc = regex::regex_exec_bytes(compiled, sub, pmatch_slice, sub_eflags);
            if rc == 0 {
                // Re-base sub-buffer-relative offsets onto `string`.
                let off = so as i32;
                for m in pmatch_slice.iter_mut() {
                    if m.rm_so >= 0 {
                        m.rm_so += off;
                    }
                    if m.rm_eo >= 0 {
                        m.rm_eo += off;
                    }
                }
            }
            rc
        };
        return rc;
    }

    let Some(input_bytes) = (unsafe { read_c_string_bytes_with_nul(string) }) else {
        return regex::REG_NOMATCH;
    };

    if nmatch == 0 || pmatch.is_null() {
        // No submatch extraction needed: only the boolean rc is observable.
        if regex::regex_is_match(compiled, &input_bytes, eflags) {
            0
        } else {
            regex::REG_NOMATCH
        }
    } else {
        // Map pmatch to our RegMatch slice
        let pmatch_slice =
            unsafe { core::slice::from_raw_parts_mut(pmatch as *mut regex::RegMatch, nmatch) };
        regex::regex_exec(compiled, &input_bytes, pmatch_slice, eflags)
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
    let Some(pat_bytes) = (unsafe { read_c_string_bytes(pattern) }) else {
        return FNM_NOMATCH;
    };
    let Some(str_bytes) = (unsafe { read_c_string_bytes(string) }) else {
        return FNM_NOMATCH;
    };
    let core_flags = frankenlibc_core::string::fnmatch::FnmatchFlags::from_bits(flags as u32);
    if frankenlibc_core::string::fnmatch::fnmatch_match(&pat_bytes, &str_bytes, core_flags) {
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
/// View over the caller's `glob_t`. Includes the GNU `GLOB_ALTDIRFUNC` function
/// pointers (only read when that flag is set); the layout matches glibc's
/// `<glob.h>` on x86_64 (`gl_flags` at offset 24, the five callbacks at 32..72).
#[repr(C)]
struct GlobT {
    gl_pathc: usize,
    gl_pathv: *mut *mut c_char,
    gl_offs: usize,
    gl_flags: c_int,
    gl_closedir: Option<unsafe extern "C" fn(*mut c_void)>,
    gl_readdir: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
    gl_opendir: Option<unsafe extern "C" fn(*const c_char) -> *mut c_void>,
    gl_lstat: Option<unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int>,
    gl_stat: Option<unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int>,
}

const GLOB_ALTDIRFUNC: c_int = 0x200;

/// A [`GlobFs`](frankenlibc_core::string::glob::GlobFs) backed by a caller's
/// `GLOB_ALTDIRFUNC` callbacks (`gl_opendir`/`gl_readdir`/`gl_closedir`/`gl_stat`).
struct AltDirGlobFs {
    opendir: Option<unsafe extern "C" fn(*const c_char) -> *mut c_void>,
    readdir: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
    closedir: Option<unsafe extern "C" fn(*mut c_void)>,
    stat: Option<unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int>,
}

impl frankenlibc_core::string::glob::GlobFs for AltDirGlobFs {
    fn read_dir(&self, dir_path: &[u8]) -> Result<Vec<Vec<u8>>, c_int> {
        let bytes = if dir_path.is_empty() {
            b".".to_vec()
        } else {
            dir_path.to_vec()
        };
        let Ok(cpath) = std::ffi::CString::new(bytes) else {
            return Err(frankenlibc_core::errno::ENOENT);
        };
        let (Some(opendir), Some(readdir)) = (self.opendir, self.readdir) else {
            return Err(frankenlibc_core::errno::ENOSYS);
        };
        // SAFETY: caller-supplied GLOB_ALTDIRFUNC callbacks; `cpath` is a valid
        // NUL-terminated C string and outlives the call.
        let dir = unsafe { opendir(cpath.as_ptr()) };
        if dir.is_null() {
            #[cfg(feature = "standalone")]
            let e = unsafe { *crate::errno_abi::__errno_location() };
            #[cfg(not(feature = "standalone"))]
            let e = crate::host_resolve::host_errno(frankenlibc_core::errno::ENOENT);
            return Err(if e != 0 {
                e
            } else {
                frankenlibc_core::errno::ENOENT
            });
        }
        let mut names = Vec::new();
        loop {
            // SAFETY: `dir` is a live handle from the caller's gl_opendir.
            let ent = unsafe { readdir(dir) };
            if ent.is_null() {
                break;
            }
            let d = ent as *const libc::dirent;
            // SAFETY: gl_readdir returns a `struct dirent *`; read its
            // NUL-terminated `d_name` (bounded by NAME_MAX + 1).
            let name_ptr = unsafe { (*d).d_name.as_ptr() };
            let mut name = Vec::new();
            let mut i = 0isize;
            loop {
                let c = unsafe { *name_ptr.offset(i) } as u8;
                if c == 0 || i > 4096 {
                    break;
                }
                name.push(c);
                i += 1;
            }
            // The engine re-introduces "." / ".." itself; exclude them here so
            // the GlobFs contract matches StdGlobFs (Rust read_dir omits them).
            if name != b"." && name != b".." {
                names.push(name);
            }
        }
        if let Some(closedir) = self.closedir {
            // SAFETY: `dir` is the live handle; closed exactly once.
            unsafe { closedir(dir) };
        }
        Ok(names)
    }

    fn stat_is_dir(&self, path: &[u8]) -> Option<bool> {
        let Ok(cpath) = std::ffi::CString::new(path.to_vec()) else {
            return None;
        };
        let stat_fn = self.stat?;
        // SAFETY: zero-initialized `libc::stat` is a valid output buffer; the
        // callback fills it. `cpath` outlives the call.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let r = unsafe { stat_fn(cpath.as_ptr(), &mut st as *mut libc::stat as *mut c_void) };
        if r != 0 {
            return None;
        }
        Some(st.st_mode & libc::S_IFMT == libc::S_IFDIR)
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn glob(
    pattern: *const c_char,
    flags: c_int,
    errfunc: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
    pglob: *mut c_void,
) -> c_int {
    use frankenlibc_core::string::glob as glob_core;
    use std::ffi::CString;

    if pattern.is_null() || pglob.is_null() {
        return glob_core::GLOB_NOMATCH;
    }

    let Some(pat_bytes) = (unsafe { read_c_string_bytes_with_nul(pattern) }) else {
        return glob_core::GLOB_NOMATCH;
    };

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

    // Error handler shared by both filesystem backends: marshal the path to a
    // CString and call the caller's errfunc (a NULL errfunc never aborts).
    let mut errfn = |path: &[u8], errno: i32| -> bool {
        match errfunc {
            Some(callback) => match CString::new(path) {
                // SAFETY: `epath` is a null-terminated CString alive for the call.
                Ok(epath) => unsafe { callback(epath.as_ptr(), errno as c_int) != 0 },
                Err(_) => true,
            },
            None => false,
        }
    };

    // GLOB_ALTDIRFUNC routes every directory/stat operation through the caller's
    // gl_opendir/gl_readdir/gl_closedir/gl_stat callbacks; otherwise use std::fs.
    let result = if flags & GLOB_ALTDIRFUNC != 0 {
        let alt = AltDirGlobFs {
            opendir: unsafe { (*gt).gl_opendir },
            readdir: unsafe { (*gt).gl_readdir },
            closedir: unsafe { (*gt).gl_closedir },
            stat: unsafe { (*gt).gl_stat },
        };
        glob_core::glob_expand_with_fs(&pat_bytes, flags, &mut errfn, &alt)
    } else {
        glob_core::glob_expand_with_fs(&pat_bytes, flags, &mut errfn, &glob_core::StdGlobFs)
    };

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

const GLIBC_SIGRTMIN: c_int = 34;
const GLIBC_SIGRTMAX: c_int = 64;

/// Render the strsignal/psignal description for `sig` into `dst`.
///
/// Single source of truth so `strsignal` and `psignal` always agree —
/// glibc backs both off a single description table; diverging here
/// means a tool that compares `strsignal(N)` to a captured psignal(N)
/// stderr line sees inconsistent text on real-time and unknown signals.
///
/// Exposed for integration tests so the strsignal/psignal description
/// contract can be asserted without capturing stderr.
pub fn signal_description_into(sig: c_int, dst: &mut Vec<u8>) {
    if (1..=31).contains(&sig) {
        dst.extend_from_slice(signal_name(sig));
        return;
    }
    let mut formatted = String::new();
    if (GLIBC_SIGRTMIN..=GLIBC_SIGRTMAX).contains(&sig) {
        let _ = write!(&mut formatted, "Real-time signal {}", sig - GLIBC_SIGRTMIN);
    } else {
        let _ = write!(&mut formatted, "Unknown signal {sig}");
    }
    dst.extend_from_slice(formatted.as_bytes());
}

/// POSIX `strsignal` — returns a string describing a signal number.
///
/// Returns a thread-local buffer with the signal description.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strsignal(sig: c_int) -> *mut c_char {
    with_strsignal_buffer(|buf| {
        let mut name = Vec::with_capacity(buf.len());
        signal_description_into(sig, &mut name);
        let len = name.len().min(buf.len() - 1);
        buf[..len].copy_from_slice(&name[..len]);
        buf[len] = 0;
        buf.as_mut_ptr() as *mut c_char
    })
}

/// Number of signal slots in `sys_siglist`. Matches Linux `NSIG`
/// on x86_64 (signals 0..64 inclusive). Indices 0 and 32..63 are
/// reserved or realtime-signal slots and point to a dedicated
/// placeholder string.
const SYS_SIGLIST_LEN: usize = 65;

// Per-signal description bytes, NUL-terminated so they can be
// served as `*const c_char` directly. The textual content matches
// the existing `signal_name()` table to avoid divergence between
// `strsignal(sig)` and `sys_siglist[sig]`.
const SIG_DESC_EMPTY: &[u8] = b"\0";
const SIG_DESC_HUP: &[u8] = b"Hangup\0";
const SIG_DESC_INT: &[u8] = b"Interrupt\0";
const SIG_DESC_QUIT: &[u8] = b"Quit\0";
const SIG_DESC_ILL: &[u8] = b"Illegal instruction\0";
const SIG_DESC_TRAP: &[u8] = b"Trace/breakpoint trap\0";
const SIG_DESC_ABRT: &[u8] = b"Aborted\0";
const SIG_DESC_BUS: &[u8] = b"Bus error\0";
const SIG_DESC_FPE: &[u8] = b"Floating point exception\0";
const SIG_DESC_KILL: &[u8] = b"Killed\0";
const SIG_DESC_USR1: &[u8] = b"User defined signal 1\0";
const SIG_DESC_SEGV: &[u8] = b"Segmentation fault\0";
const SIG_DESC_USR2: &[u8] = b"User defined signal 2\0";
const SIG_DESC_PIPE: &[u8] = b"Broken pipe\0";
const SIG_DESC_ALRM: &[u8] = b"Alarm clock\0";
const SIG_DESC_TERM: &[u8] = b"Terminated\0";
const SIG_DESC_STKFLT: &[u8] = b"Stack fault\0";
const SIG_DESC_CHLD: &[u8] = b"Child exited\0";
const SIG_DESC_CONT: &[u8] = b"Continued\0";
const SIG_DESC_STOP: &[u8] = b"Stopped (signal)\0";
const SIG_DESC_TSTP: &[u8] = b"Stopped\0";
const SIG_DESC_TTIN: &[u8] = b"Stopped (tty input)\0";
const SIG_DESC_TTOU: &[u8] = b"Stopped (tty output)\0";
const SIG_DESC_URG: &[u8] = b"Urgent I/O condition\0";
const SIG_DESC_XCPU: &[u8] = b"CPU time limit exceeded\0";
const SIG_DESC_XFSZ: &[u8] = b"File size limit exceeded\0";
const SIG_DESC_VTALRM: &[u8] = b"Virtual timer expired\0";
const SIG_DESC_PROF: &[u8] = b"Profiling timer expired\0";
const SIG_DESC_WINCH: &[u8] = b"Window changed\0";
const SIG_DESC_IO: &[u8] = b"I/O possible\0";
const SIG_DESC_PWR: &[u8] = b"Power failure\0";
const SIG_DESC_SYS: &[u8] = b"Bad system call\0";
const SIG_DESC_RT: &[u8] = b"Real-time signal\0";

/// `repr(transparent)` wrapper that lets us declare a `static`
/// holding raw pointers (which are not `Sync` on their own).
/// The Sync impl is sound because the wrapped array is initialized
/// once at program load and the contents — pointers to immutable
/// `&'static [u8]` literals — are never mutated.
#[repr(transparent)]
pub struct SysSigList(pub [*const c_char; SYS_SIGLIST_LEN]);
// SAFETY: see SysSigList docs above.
unsafe impl Sync for SysSigList {}

const SYS_SIGLIST_ENTRIES: [*const c_char; SYS_SIGLIST_LEN] = [
    SIG_DESC_EMPTY.as_ptr() as *const c_char,  // 0
    SIG_DESC_HUP.as_ptr() as *const c_char,    // 1 SIGHUP
    SIG_DESC_INT.as_ptr() as *const c_char,    // 2 SIGINT
    SIG_DESC_QUIT.as_ptr() as *const c_char,   // 3 SIGQUIT
    SIG_DESC_ILL.as_ptr() as *const c_char,    // 4 SIGILL
    SIG_DESC_TRAP.as_ptr() as *const c_char,   // 5 SIGTRAP
    SIG_DESC_ABRT.as_ptr() as *const c_char,   // 6 SIGABRT
    SIG_DESC_BUS.as_ptr() as *const c_char,    // 7 SIGBUS
    SIG_DESC_FPE.as_ptr() as *const c_char,    // 8 SIGFPE
    SIG_DESC_KILL.as_ptr() as *const c_char,   // 9 SIGKILL
    SIG_DESC_USR1.as_ptr() as *const c_char,   // 10 SIGUSR1
    SIG_DESC_SEGV.as_ptr() as *const c_char,   // 11 SIGSEGV
    SIG_DESC_USR2.as_ptr() as *const c_char,   // 12 SIGUSR2
    SIG_DESC_PIPE.as_ptr() as *const c_char,   // 13 SIGPIPE
    SIG_DESC_ALRM.as_ptr() as *const c_char,   // 14 SIGALRM
    SIG_DESC_TERM.as_ptr() as *const c_char,   // 15 SIGTERM
    SIG_DESC_STKFLT.as_ptr() as *const c_char, // 16 SIGSTKFLT
    SIG_DESC_CHLD.as_ptr() as *const c_char,   // 17 SIGCHLD
    SIG_DESC_CONT.as_ptr() as *const c_char,   // 18 SIGCONT
    SIG_DESC_STOP.as_ptr() as *const c_char,   // 19 SIGSTOP
    SIG_DESC_TSTP.as_ptr() as *const c_char,   // 20 SIGTSTP
    SIG_DESC_TTIN.as_ptr() as *const c_char,   // 21 SIGTTIN
    SIG_DESC_TTOU.as_ptr() as *const c_char,   // 22 SIGTTOU
    SIG_DESC_URG.as_ptr() as *const c_char,    // 23 SIGURG
    SIG_DESC_XCPU.as_ptr() as *const c_char,   // 24 SIGXCPU
    SIG_DESC_XFSZ.as_ptr() as *const c_char,   // 25 SIGXFSZ
    SIG_DESC_VTALRM.as_ptr() as *const c_char, // 26 SIGVTALRM
    SIG_DESC_PROF.as_ptr() as *const c_char,   // 27 SIGPROF
    SIG_DESC_WINCH.as_ptr() as *const c_char,  // 28 SIGWINCH
    SIG_DESC_IO.as_ptr() as *const c_char,     // 29 SIGIO
    SIG_DESC_PWR.as_ptr() as *const c_char,    // 30 SIGPWR
    SIG_DESC_SYS.as_ptr() as *const c_char,    // 31 SIGSYS
    // 32..=64: realtime signals — share a placeholder description.
    SIG_DESC_RT.as_ptr() as *const c_char, // 32
    SIG_DESC_RT.as_ptr() as *const c_char, // 33
    SIG_DESC_RT.as_ptr() as *const c_char, // 34
    SIG_DESC_RT.as_ptr() as *const c_char, // 35
    SIG_DESC_RT.as_ptr() as *const c_char, // 36
    SIG_DESC_RT.as_ptr() as *const c_char, // 37
    SIG_DESC_RT.as_ptr() as *const c_char, // 38
    SIG_DESC_RT.as_ptr() as *const c_char, // 39
    SIG_DESC_RT.as_ptr() as *const c_char, // 40
    SIG_DESC_RT.as_ptr() as *const c_char, // 41
    SIG_DESC_RT.as_ptr() as *const c_char, // 42
    SIG_DESC_RT.as_ptr() as *const c_char, // 43
    SIG_DESC_RT.as_ptr() as *const c_char, // 44
    SIG_DESC_RT.as_ptr() as *const c_char, // 45
    SIG_DESC_RT.as_ptr() as *const c_char, // 46
    SIG_DESC_RT.as_ptr() as *const c_char, // 47
    SIG_DESC_RT.as_ptr() as *const c_char, // 48
    SIG_DESC_RT.as_ptr() as *const c_char, // 49
    SIG_DESC_RT.as_ptr() as *const c_char, // 50
    SIG_DESC_RT.as_ptr() as *const c_char, // 51
    SIG_DESC_RT.as_ptr() as *const c_char, // 52
    SIG_DESC_RT.as_ptr() as *const c_char, // 53
    SIG_DESC_RT.as_ptr() as *const c_char, // 54
    SIG_DESC_RT.as_ptr() as *const c_char, // 55
    SIG_DESC_RT.as_ptr() as *const c_char, // 56
    SIG_DESC_RT.as_ptr() as *const c_char, // 57
    SIG_DESC_RT.as_ptr() as *const c_char, // 58
    SIG_DESC_RT.as_ptr() as *const c_char, // 59
    SIG_DESC_RT.as_ptr() as *const c_char, // 60
    SIG_DESC_RT.as_ptr() as *const c_char, // 61
    SIG_DESC_RT.as_ptr() as *const c_char, // 62
    SIG_DESC_RT.as_ptr() as *const c_char, // 63
    SIG_DESC_RT.as_ptr() as *const c_char, // 64
];

/// glibc `sys_siglist[NSIG]` — array of human-readable signal
/// descriptions indexed by signal number. Deprecated in favor of
/// [`strsignal`] / `sigdescr_np`, but many older programs still
/// reference this symbol directly. Each entry is a NUL-terminated
/// C string with the same wording as [`strsignal(n)`].
///
/// `sys_siglist[0]` is empty (no signal 0 description). Indices
/// 32..=64 cover the realtime-signal range and share a generic
/// placeholder description.
///
/// The wrapper around the inner `[*const c_char; 65]` is
/// `repr(transparent)`, so the symbol's ABI is identical to a
/// bare C `const char *sys_siglist[NSIG]`.
#[allow(non_upper_case_globals)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static sys_siglist: SysSigList = SysSigList(SYS_SIGLIST_ENTRIES);

/// glibc deprecated `_sys_siglist[NSIG]` alias. It must contain the
/// same populated signal-description table as `sys_siglist`, not a
/// null placeholder, because old C programs index this symbol directly.
#[allow(non_upper_case_globals)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static _sys_siglist: SysSigList = SysSigList(SYS_SIGLIST_ENTRIES);

// Per-signal short name bytes used by `sys_signame` — uppercase
// without the "SIG" prefix, matching the BSD convention used by
// killall(1), kill(1), and other signal-name tools.
const SIG_NAME_EMPTY: &[u8] = b"\0";
const SIG_NAME_HUP: &[u8] = b"HUP\0";
const SIG_NAME_INT: &[u8] = b"INT\0";
const SIG_NAME_QUIT: &[u8] = b"QUIT\0";
const SIG_NAME_ILL: &[u8] = b"ILL\0";
const SIG_NAME_TRAP: &[u8] = b"TRAP\0";
const SIG_NAME_ABRT: &[u8] = b"ABRT\0";
const SIG_NAME_BUS: &[u8] = b"BUS\0";
const SIG_NAME_FPE: &[u8] = b"FPE\0";
const SIG_NAME_KILL: &[u8] = b"KILL\0";
const SIG_NAME_USR1: &[u8] = b"USR1\0";
const SIG_NAME_SEGV: &[u8] = b"SEGV\0";
const SIG_NAME_USR2: &[u8] = b"USR2\0";
const SIG_NAME_PIPE: &[u8] = b"PIPE\0";
const SIG_NAME_ALRM: &[u8] = b"ALRM\0";
const SIG_NAME_TERM: &[u8] = b"TERM\0";
const SIG_NAME_STKFLT: &[u8] = b"STKFLT\0";
const SIG_NAME_CHLD: &[u8] = b"CHLD\0";
const SIG_NAME_CONT: &[u8] = b"CONT\0";
const SIG_NAME_STOP: &[u8] = b"STOP\0";
const SIG_NAME_TSTP: &[u8] = b"TSTP\0";
const SIG_NAME_TTIN: &[u8] = b"TTIN\0";
const SIG_NAME_TTOU: &[u8] = b"TTOU\0";
const SIG_NAME_URG: &[u8] = b"URG\0";
const SIG_NAME_XCPU: &[u8] = b"XCPU\0";
const SIG_NAME_XFSZ: &[u8] = b"XFSZ\0";
const SIG_NAME_VTALRM: &[u8] = b"VTALRM\0";
const SIG_NAME_PROF: &[u8] = b"PROF\0";
const SIG_NAME_WINCH: &[u8] = b"WINCH\0";
const SIG_NAME_IO: &[u8] = b"IO\0";
const SIG_NAME_PWR: &[u8] = b"PWR\0";
const SIG_NAME_SYS: &[u8] = b"SYS\0";
const SIG_NAME_RT: &[u8] = b"RT\0";

/// BSD `sys_signame[NSIG]` — array of short uppercase signal
/// names (no `"SIG"` prefix), indexed by signal number. Used by
/// killall(1), kill(1), and other signal-name tools that prefer
/// the abbreviated form ("HUP" rather than "Hangup"). Some BSD-
/// derived ports of Linux libraries (libbsd) provide this for
/// compatibility.
///
/// `sys_signame[0]` is empty. Indices 32..=64 share a generic
/// `"RT"` placeholder; callers wanting the full short form (e.g.
/// `"RTMIN+3"`) should call `sigabbrev_np` instead.
///
/// The wrapper around the inner `[*const c_char; 65]` is
/// `repr(transparent)`, so the symbol's ABI is identical to a
/// bare C `const char *sys_signame[NSIG]`.
#[allow(non_upper_case_globals)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static sys_signame: SysSigList = SysSigList([
    SIG_NAME_EMPTY.as_ptr() as *const c_char,  // 0
    SIG_NAME_HUP.as_ptr() as *const c_char,    // 1 SIGHUP
    SIG_NAME_INT.as_ptr() as *const c_char,    // 2 SIGINT
    SIG_NAME_QUIT.as_ptr() as *const c_char,   // 3 SIGQUIT
    SIG_NAME_ILL.as_ptr() as *const c_char,    // 4 SIGILL
    SIG_NAME_TRAP.as_ptr() as *const c_char,   // 5 SIGTRAP
    SIG_NAME_ABRT.as_ptr() as *const c_char,   // 6 SIGABRT
    SIG_NAME_BUS.as_ptr() as *const c_char,    // 7 SIGBUS
    SIG_NAME_FPE.as_ptr() as *const c_char,    // 8 SIGFPE
    SIG_NAME_KILL.as_ptr() as *const c_char,   // 9 SIGKILL
    SIG_NAME_USR1.as_ptr() as *const c_char,   // 10 SIGUSR1
    SIG_NAME_SEGV.as_ptr() as *const c_char,   // 11 SIGSEGV
    SIG_NAME_USR2.as_ptr() as *const c_char,   // 12 SIGUSR2
    SIG_NAME_PIPE.as_ptr() as *const c_char,   // 13 SIGPIPE
    SIG_NAME_ALRM.as_ptr() as *const c_char,   // 14 SIGALRM
    SIG_NAME_TERM.as_ptr() as *const c_char,   // 15 SIGTERM
    SIG_NAME_STKFLT.as_ptr() as *const c_char, // 16 SIGSTKFLT
    SIG_NAME_CHLD.as_ptr() as *const c_char,   // 17 SIGCHLD
    SIG_NAME_CONT.as_ptr() as *const c_char,   // 18 SIGCONT
    SIG_NAME_STOP.as_ptr() as *const c_char,   // 19 SIGSTOP
    SIG_NAME_TSTP.as_ptr() as *const c_char,   // 20 SIGTSTP
    SIG_NAME_TTIN.as_ptr() as *const c_char,   // 21 SIGTTIN
    SIG_NAME_TTOU.as_ptr() as *const c_char,   // 22 SIGTTOU
    SIG_NAME_URG.as_ptr() as *const c_char,    // 23 SIGURG
    SIG_NAME_XCPU.as_ptr() as *const c_char,   // 24 SIGXCPU
    SIG_NAME_XFSZ.as_ptr() as *const c_char,   // 25 SIGXFSZ
    SIG_NAME_VTALRM.as_ptr() as *const c_char, // 26 SIGVTALRM
    SIG_NAME_PROF.as_ptr() as *const c_char,   // 27 SIGPROF
    SIG_NAME_WINCH.as_ptr() as *const c_char,  // 28 SIGWINCH
    SIG_NAME_IO.as_ptr() as *const c_char,     // 29 SIGIO
    SIG_NAME_PWR.as_ptr() as *const c_char,    // 30 SIGPWR
    SIG_NAME_SYS.as_ptr() as *const c_char,    // 31 SIGSYS
    // 32..=64: realtime signals — share a placeholder name.
    SIG_NAME_RT.as_ptr() as *const c_char, // 32
    SIG_NAME_RT.as_ptr() as *const c_char, // 33
    SIG_NAME_RT.as_ptr() as *const c_char, // 34
    SIG_NAME_RT.as_ptr() as *const c_char, // 35
    SIG_NAME_RT.as_ptr() as *const c_char, // 36
    SIG_NAME_RT.as_ptr() as *const c_char, // 37
    SIG_NAME_RT.as_ptr() as *const c_char, // 38
    SIG_NAME_RT.as_ptr() as *const c_char, // 39
    SIG_NAME_RT.as_ptr() as *const c_char, // 40
    SIG_NAME_RT.as_ptr() as *const c_char, // 41
    SIG_NAME_RT.as_ptr() as *const c_char, // 42
    SIG_NAME_RT.as_ptr() as *const c_char, // 43
    SIG_NAME_RT.as_ptr() as *const c_char, // 44
    SIG_NAME_RT.as_ptr() as *const c_char, // 45
    SIG_NAME_RT.as_ptr() as *const c_char, // 46
    SIG_NAME_RT.as_ptr() as *const c_char, // 47
    SIG_NAME_RT.as_ptr() as *const c_char, // 48
    SIG_NAME_RT.as_ptr() as *const c_char, // 49
    SIG_NAME_RT.as_ptr() as *const c_char, // 50
    SIG_NAME_RT.as_ptr() as *const c_char, // 51
    SIG_NAME_RT.as_ptr() as *const c_char, // 52
    SIG_NAME_RT.as_ptr() as *const c_char, // 53
    SIG_NAME_RT.as_ptr() as *const c_char, // 54
    SIG_NAME_RT.as_ptr() as *const c_char, // 55
    SIG_NAME_RT.as_ptr() as *const c_char, // 56
    SIG_NAME_RT.as_ptr() as *const c_char, // 57
    SIG_NAME_RT.as_ptr() as *const c_char, // 58
    SIG_NAME_RT.as_ptr() as *const c_char, // 59
    SIG_NAME_RT.as_ptr() as *const c_char, // 60
    SIG_NAME_RT.as_ptr() as *const c_char, // 61
    SIG_NAME_RT.as_ptr() as *const c_char, // 62
    SIG_NAME_RT.as_ptr() as *const c_char, // 63
    SIG_NAME_RT.as_ptr() as *const c_char, // 64
]);

/// POSIX `psignal` — print a signal description to stderr.
///
/// Goes through `signal_description_into` for the same labeling as
/// `strsignal` — glibc backs both off a single description table, so a
/// user comparing `strsignal(34)` to a captured `psignal(34, ...)` line
/// sees consistent text on real-time and unknown signals.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn psignal(sig: c_int, s: *const c_char) {
    // Build message: "s: signal_name\n" or "signal_name\n"
    let mut msg = Vec::with_capacity(256);
    let prefix = if s.is_null() {
        None
    } else {
        unsafe { read_c_string_bytes(s) }
    };
    if let Some(prefix) = prefix.filter(|prefix| !prefix.is_empty()) {
        msg.extend_from_slice(&prefix);
        msg.extend_from_slice(b": ");
    }
    signal_description_into(sig, &mut msg);
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

    let s1_bytes = unsafe { read_c_string_bytes(s1) };
    let s2_bytes = unsafe { read_c_string_bytes(s2) };
    match (s1_bytes, s2_bytes) {
        (Some(s1_bytes), Some(s2_bytes)) => strverscmp_bytes(&s1_bytes, &s2_bytes),
        (None, Some(_)) => -1,
        (Some(_), None) => 1,
        (None, None) => 0,
    }
}

fn strvers_byte(bytes: &[u8], index: usize) -> u8 {
    bytes.get(index).copied().unwrap_or(0)
}

fn strverscmp_bytes(s1: &[u8], s2: &[u8]) -> c_int {
    let mut i = 0usize;
    loop {
        let c1 = strvers_byte(s1, i);
        let c2 = strvers_byte(s2, i);

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
                let mut seen_nonzero = false;
                loop {
                    let d1 = strvers_byte(s1, i);
                    let d2 = strvers_byte(s2, i);
                    let is_d1 = d1.is_ascii_digit();
                    let is_d2 = d2.is_ascii_digit();
                    if !is_d1 && !is_d2 {
                        break;
                    }
                    if !is_d1 {
                        return if seen_nonzero {
                            (d1 as c_int) - (d2 as c_int)
                        } else {
                            1
                        };
                    }
                    if !is_d2 {
                        return if seen_nonzero {
                            (d1 as c_int) - (d2 as c_int)
                        } else {
                            -1
                        };
                    }
                    if d1 != d2 {
                        return (d1 as c_int) - (d2 as c_int);
                    }
                    if d1 != b'0' {
                        seen_nonzero = true;
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
                    let d1 = strvers_byte(s1, start + len1);
                    let d2 = strvers_byte(s2, start + len2);
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
    use core::simd::Simd;
    use core::simd::cmp::SimdPartialEq;
    const LANES: usize = 32;

    if s.is_null() {
        return std::ptr::null_mut();
    }
    let needle = c as u8;
    let mut ptr = s as *const u8;

    // Scalar until 32-byte aligned, so every SIMD load below stays within one
    // page (a 32-byte-aligned 32-byte block never crosses a 4096-byte boundary)
    // — was a pure scalar byte loop, ~38x slower than glibc's AVX2 (bd-2g7oyh).
    while (ptr as usize) & (LANES - 1) != 0 {
        // SAFETY: the caller guarantees `needle` is present, so `ptr` stays within
        // the mapped buffer until it is found.
        if unsafe { *ptr } == needle {
            return ptr as *mut c_void;
        }
        ptr = unsafe { ptr.add(1) };
    }

    // Aligned 32-byte SIMD scan. The caller guarantees `needle` is present, so all
    // pages up to it are mapped, and each aligned 32-byte load is page-safe.
    let nv = Simd::<u8, LANES>::splat(needle);
    loop {
        // SAFETY: `ptr` is 32-byte aligned (load within one mapped page) and
        // `needle` is guaranteed present at or after `ptr`.
        let v = Simd::<u8, LANES>::from_slice(unsafe { core::slice::from_raw_parts(ptr, LANES) });
        let bits = v.simd_eq(nv).to_bitmask();
        if bits != 0 {
            return unsafe { ptr.add(bits.trailing_zeros() as usize) } as *mut c_void;
        }
        ptr = unsafe { ptr.add(LANES) };
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
        // glibc treats errno=0 as a valid input with description "Success",
        // returning a non-NULL pointer. Without this branch fl returned NULL.
        0 => b"Success\0",
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
        libc::ENOTBLK => b"Block device required\0",
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
        libc::ENOMSG => b"No message of desired type\0",
        libc::EIDRM => b"Identifier removed\0",
        libc::ECHRNG => b"Channel number out of range\0",
        libc::EL2NSYNC => b"Level 2 not synchronized\0",
        libc::EL3HLT => b"Level 3 halted\0",
        libc::EL3RST => b"Level 3 reset\0",
        libc::ELNRNG => b"Link number out of range\0",
        libc::EUNATCH => b"Protocol driver not attached\0",
        libc::ENOCSI => b"No CSI structure available\0",
        libc::EL2HLT => b"Level 2 halted\0",
        libc::EBADE => b"Invalid exchange\0",
        libc::EBADR => b"Invalid request descriptor\0",
        libc::EXFULL => b"Exchange full\0",
        libc::ENOANO => b"No anode\0",
        libc::EBADRQC => b"Invalid request code\0",
        libc::EBADSLT => b"Invalid slot\0",
        libc::EBFONT => b"Bad font file format\0",
        libc::ENOSTR => b"Device not a stream\0",
        libc::ENODATA => b"No data available\0",
        libc::ETIME => b"Timer expired\0",
        libc::ENOSR => b"Out of streams resources\0",
        libc::ENONET => b"Machine is not on the network\0",
        libc::ENOPKG => b"Package not installed\0",
        libc::EREMOTE => b"Object is remote\0",
        libc::ENOLINK => b"Link has been severed\0",
        libc::EADV => b"Advertise error\0",
        libc::ESRMNT => b"Srmount error\0",
        libc::ECOMM => b"Communication error on send\0",
        libc::EPROTO => b"Protocol error\0",
        libc::EMULTIHOP => b"Multihop attempted\0",
        libc::EDOTDOT => b"RFS specific error\0",
        libc::EBADMSG => b"Bad message\0",
        libc::EOVERFLOW => b"Value too large for defined data type\0",
        libc::ENOTUNIQ => b"Name not unique on network\0",
        libc::EBADFD => b"File descriptor in bad state\0",
        libc::EREMCHG => b"Remote address changed\0",
        libc::ELIBACC => b"Can not access a needed shared library\0",
        libc::ELIBBAD => b"Accessing a corrupted shared library\0",
        libc::ELIBSCN => b".lib section in a.out corrupted\0",
        libc::ELIBMAX => b"Attempting to link in too many shared libraries\0",
        libc::ELIBEXEC => b"Cannot exec a shared library directly\0",
        libc::EILSEQ => b"Invalid or incomplete multibyte or wide character\0",
        libc::ERESTART => b"Interrupted system call should be restarted\0",
        libc::ESTRPIPE => b"Streams pipe error\0",
        libc::EUSERS => b"Too many users\0",
        libc::ENOTSOCK => b"Socket operation on non-socket\0",
        libc::EDESTADDRREQ => b"Destination address required\0",
        libc::EMSGSIZE => b"Message too long\0",
        libc::EPROTOTYPE => b"Protocol wrong type for socket\0",
        libc::ENOPROTOOPT => b"Protocol not available\0",
        libc::EPROTONOSUPPORT => b"Protocol not supported\0",
        libc::ESOCKTNOSUPPORT => b"Socket type not supported\0",
        libc::EOPNOTSUPP => b"Operation not supported\0",
        libc::EPFNOSUPPORT => b"Protocol family not supported\0",
        libc::EAFNOSUPPORT => b"Address family not supported by protocol\0",
        libc::EADDRINUSE => b"Address already in use\0",
        libc::EADDRNOTAVAIL => b"Cannot assign requested address\0",
        libc::ENETDOWN => b"Network is down\0",
        libc::ENETUNREACH => b"Network is unreachable\0",
        libc::ENETRESET => b"Network dropped connection on reset\0",
        libc::ECONNABORTED => b"Software caused connection abort\0",
        libc::ECONNRESET => b"Connection reset by peer\0",
        libc::ENOBUFS => b"No buffer space available\0",
        libc::EISCONN => b"Transport endpoint is already connected\0",
        libc::ENOTCONN => b"Transport endpoint is not connected\0",
        libc::ESHUTDOWN => b"Cannot send after transport endpoint shutdown\0",
        libc::ETOOMANYREFS => b"Too many references: cannot splice\0",
        libc::ETIMEDOUT => b"Connection timed out\0",
        libc::ECONNREFUSED => b"Connection refused\0",
        libc::EHOSTDOWN => b"Host is down\0",
        libc::EHOSTUNREACH => b"No route to host\0",
        libc::EALREADY => b"Operation already in progress\0",
        libc::EINPROGRESS => b"Operation now in progress\0",
        libc::ESTALE => b"Stale file handle\0",
        libc::EUCLEAN => b"Structure needs cleaning\0",
        libc::ENOTNAM => b"Not a XENIX named type file\0",
        libc::ENAVAIL => b"No XENIX semaphores available\0",
        libc::EISNAM => b"Is a named type file\0",
        libc::EREMOTEIO => b"Remote I/O error\0",
        libc::EDQUOT => b"Disk quota exceeded\0",
        libc::ENOMEDIUM => b"No medium found\0",
        libc::EMEDIUMTYPE => b"Wrong medium type\0",
        libc::ECANCELED => b"Operation canceled\0",
        libc::ENOKEY => b"Required key not available\0",
        libc::EKEYEXPIRED => b"Key has expired\0",
        libc::EKEYREVOKED => b"Key has been revoked\0",
        libc::EKEYREJECTED => b"Key was rejected by service\0",
        libc::EOWNERDEAD => b"Owner died\0",
        libc::ENOTRECOVERABLE => b"State not recoverable\0",
        libc::ERFKILL => b"Operation not possible due to RF-kill\0",
        libc::EHWPOISON => b"Memory page has hardware error\0",
        _ => return std::ptr::null(),
    };
    desc.as_ptr() as *const c_char
}

/// GNU `strerrorname_np` — return symbolic errno name (non-POSIX).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn strerrorname_np(errnum: c_int) -> *const c_char {
    let name: &[u8] = match errnum {
        0 => b"0\0",
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
        libc::ENOTBLK => b"ENOTBLK\0",
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
        libc::ETXTBSY => b"ETXTBSY\0",
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
        libc::ENOMSG => b"ENOMSG\0",
        libc::EIDRM => b"EIDRM\0",
        libc::ECHRNG => b"ECHRNG\0",
        libc::EL2NSYNC => b"EL2NSYNC\0",
        libc::EL3HLT => b"EL3HLT\0",
        libc::EL3RST => b"EL3RST\0",
        libc::ELNRNG => b"ELNRNG\0",
        libc::EUNATCH => b"EUNATCH\0",
        libc::ENOCSI => b"ENOCSI\0",
        libc::EL2HLT => b"EL2HLT\0",
        libc::EBADE => b"EBADE\0",
        libc::EBADR => b"EBADR\0",
        libc::EXFULL => b"EXFULL\0",
        libc::ENOANO => b"ENOANO\0",
        libc::EBADRQC => b"EBADRQC\0",
        libc::EBADSLT => b"EBADSLT\0",
        libc::EBFONT => b"EBFONT\0",
        libc::ENOSTR => b"ENOSTR\0",
        libc::ENODATA => b"ENODATA\0",
        libc::ETIME => b"ETIME\0",
        libc::ENOSR => b"ENOSR\0",
        libc::ENONET => b"ENONET\0",
        libc::ENOPKG => b"ENOPKG\0",
        libc::EREMOTE => b"EREMOTE\0",
        libc::ENOLINK => b"ENOLINK\0",
        libc::EADV => b"EADV\0",
        libc::ESRMNT => b"ESRMNT\0",
        libc::ECOMM => b"ECOMM\0",
        libc::EPROTO => b"EPROTO\0",
        libc::EMULTIHOP => b"EMULTIHOP\0",
        libc::EDOTDOT => b"EDOTDOT\0",
        libc::EBADMSG => b"EBADMSG\0",
        libc::EOVERFLOW => b"EOVERFLOW\0",
        libc::ENOTUNIQ => b"ENOTUNIQ\0",
        libc::EBADFD => b"EBADFD\0",
        libc::EREMCHG => b"EREMCHG\0",
        libc::ELIBACC => b"ELIBACC\0",
        libc::ELIBBAD => b"ELIBBAD\0",
        libc::ELIBSCN => b"ELIBSCN\0",
        libc::ELIBMAX => b"ELIBMAX\0",
        libc::ELIBEXEC => b"ELIBEXEC\0",
        libc::EILSEQ => b"EILSEQ\0",
        libc::ERESTART => b"ERESTART\0",
        libc::ESTRPIPE => b"ESTRPIPE\0",
        libc::EUSERS => b"EUSERS\0",
        libc::ENOTSOCK => b"ENOTSOCK\0",
        libc::EDESTADDRREQ => b"EDESTADDRREQ\0",
        libc::EMSGSIZE => b"EMSGSIZE\0",
        libc::EPROTOTYPE => b"EPROTOTYPE\0",
        libc::ENOPROTOOPT => b"ENOPROTOOPT\0",
        libc::EPROTONOSUPPORT => b"EPROTONOSUPPORT\0",
        libc::ESOCKTNOSUPPORT => b"ESOCKTNOSUPPORT\0",
        libc::EOPNOTSUPP => b"EOPNOTSUPP\0",
        libc::EPFNOSUPPORT => b"EPFNOSUPPORT\0",
        libc::EAFNOSUPPORT => b"EAFNOSUPPORT\0",
        libc::EADDRINUSE => b"EADDRINUSE\0",
        libc::EADDRNOTAVAIL => b"EADDRNOTAVAIL\0",
        libc::ENETDOWN => b"ENETDOWN\0",
        libc::ENETUNREACH => b"ENETUNREACH\0",
        libc::ENETRESET => b"ENETRESET\0",
        libc::ECONNABORTED => b"ECONNABORTED\0",
        libc::ECONNREFUSED => b"ECONNREFUSED\0",
        libc::ECONNRESET => b"ECONNRESET\0",
        libc::ENOBUFS => b"ENOBUFS\0",
        libc::EISCONN => b"EISCONN\0",
        libc::ENOTCONN => b"ENOTCONN\0",
        libc::ESHUTDOWN => b"ESHUTDOWN\0",
        libc::ETOOMANYREFS => b"ETOOMANYREFS\0",
        libc::ETIMEDOUT => b"ETIMEDOUT\0",
        libc::EHOSTDOWN => b"EHOSTDOWN\0",
        libc::EHOSTUNREACH => b"EHOSTUNREACH\0",
        libc::EALREADY => b"EALREADY\0",
        libc::EINPROGRESS => b"EINPROGRESS\0",
        libc::ESTALE => b"ESTALE\0",
        libc::EUCLEAN => b"EUCLEAN\0",
        libc::ENOTNAM => b"ENOTNAM\0",
        libc::ENAVAIL => b"ENAVAIL\0",
        libc::EISNAM => b"EISNAM\0",
        libc::EREMOTEIO => b"EREMOTEIO\0",
        libc::EDQUOT => b"EDQUOT\0",
        libc::ENOMEDIUM => b"ENOMEDIUM\0",
        libc::EMEDIUMTYPE => b"EMEDIUMTYPE\0",
        libc::ECANCELED => b"ECANCELED\0",
        libc::ENOKEY => b"ENOKEY\0",
        libc::EKEYEXPIRED => b"EKEYEXPIRED\0",
        libc::EKEYREVOKED => b"EKEYREVOKED\0",
        libc::EKEYREJECTED => b"EKEYREJECTED\0",
        libc::EOWNERDEAD => b"EOWNERDEAD\0",
        libc::ENOTRECOVERABLE => b"ENOTRECOVERABLE\0",
        libc::ERFKILL => b"ERFKILL\0",
        libc::EHWPOISON => b"EHWPOISON\0",
        _ => return std::ptr::null(),
    };
    name.as_ptr() as *const c_char
}

// ===========================================================================
// Batch: C23 float-to-string — Implemented
// ===========================================================================

const MAX_STRFROM_PRECISION: usize = 512;

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
    let Some(fmt_bytes) = (unsafe { read_c_string_bytes(format) }) else {
        return -1;
    };
    // Parse format: must be "%[.<precision>]{f,e,g,a}" (C23 subset)
    let fmt_str = match std::str::from_utf8(&fmt_bytes) {
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
    // Parse "%[.<prec>]{f|e|g|a}". The default precision per C99 is 6
    // for f/e/g; printf doesn't accept a missing default precision for
    // %a (hexadecimal) so we use 6 as a sensible fallback there too.
    if !fmt.starts_with('%') {
        return format!("{value}");
    }
    let rest = &fmt[1..];
    let (precision, spec) = if let Some(after_dot) = rest.strip_prefix('.') {
        let num_end = after_dot
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after_dot.len());
        let prec = if num_end == 0 {
            0
        } else {
            after_dot[..num_end]
                .parse::<usize>()
                .map(|precision| precision.min(MAX_STRFROM_PRECISION))
                .unwrap_or(6)
        };
        (Some(prec), &after_dot[num_end..])
    } else {
        (None, rest)
    };
    let decimal_precision = precision.unwrap_or(6);

    // Non-finite values render as glibc spells them (NOT Rust's "NaN"/"inf"):
    // lowercase "nan"/"inf" for a/e/f/g, uppercase "NAN"/"INF" for A/E/F/G, with
    // a leading '-' when the sign bit is set; precision is ignored. Found by
    // strfromd_differential_fuzz.
    if matches!(spec, "a" | "A" | "e" | "E" | "f" | "F" | "g" | "G") && !value.is_finite() {
        let sign = if value.is_sign_negative() { "-" } else { "" };
        let body = if value.is_nan() { "nan" } else { "inf" };
        let out = format!("{sign}{body}");
        return if matches!(spec, "A" | "E" | "F" | "G") {
            out.to_ascii_uppercase()
        } else {
            out
        };
    }

    match spec {
        // %f / %F — fixed-point with `precision` fractional digits.
        // Rust's `{:.N$}` is bit-compatible with printf %f for f64.
        // `%f` of a FINITE value has no alphabetic chars, so `%F` == `%f`
        // (non-finite is handled above); the former `.to_ascii_uppercase()` was a
        // pure no-op extra allocation.
        "f" | "F" => format!("{value:.decimal_precision$}"),

        // %e — scientific with C-style `e+02` exponent (Rust's default
        // gives `e2` without sign or leading zeros, which doesn't match
        // glibc strfromd). Delegate to the shared helper that handles
        // the reshape.
        "e" => frankenlibc_core::stdlib::ecvt::render_pct_e(value, decimal_precision),
        "E" => {
            // %E is identical to %e but with uppercase `E`. The only lowercase
            // char render_pct_e emits is the 'e', so an in-place
            // `make_ascii_uppercase` does exactly that — no `.replace()` +
            // `.to_ascii_uppercase()` (two extra allocations).
            let mut s = frankenlibc_core::stdlib::ecvt::render_pct_e(value, decimal_precision);
            s.make_ascii_uppercase();
            s
        }

        // %g — uses *significant* digits (not fractional) and switches
        // between fixed and scientific based on the exponent. Trailing
        // zeros after the decimal point are stripped. The previous
        // length-based shorter-of-two heuristic was structurally
        // wrong: for value=0 with precision=6 it picked "0.000000"
        // instead of glibc's "0".
        "g" => frankenlibc_core::stdlib::ecvt::render_pct_g(value, decimal_precision),
        "G" => {
            // As %E: the only lowercase char is the optional 'e'; upper-case in
            // place instead of `.replace()` + `.to_ascii_uppercase()`.
            let mut s = frankenlibc_core::stdlib::ecvt::render_pct_g(value, decimal_precision);
            s.make_ascii_uppercase();
            s
        }

        "a" => render_hex_float(value, precision, false),
        "A" => render_hex_float(value, precision, true),

        _ => format!("{value}"),
    }
}

fn render_hex_float(value: f64, precision: Option<usize>, uppercase: bool) -> String {
    if value.is_nan() {
        return if uppercase {
            String::from("NAN")
        } else {
            String::from("nan")
        };
    }
    if value.is_infinite() {
        let inf = if uppercase { "INF" } else { "inf" };
        return if value.is_sign_negative() {
            format!("-{inf}")
        } else {
            inf.to_string()
        };
    }

    let prefix = if uppercase { "0X" } else { "0x" };
    let exponent_marker = if uppercase { 'P' } else { 'p' };
    let hex_digits = if uppercase {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let sign = if value.is_sign_negative() { "-" } else { "" };
    let bits = value.abs().to_bits();
    let exponent_bits = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1_u64 << 52) - 1);

    if exponent_bits == 0 && fraction == 0 {
        let mut out = format!("{sign}{prefix}0");
        if let Some(precision) = precision
            && precision != 0
        {
            out.push('.');
            out.extend(std::iter::repeat_n('0', precision));
        }
        out.push(exponent_marker);
        out.push_str("+0");
        return out;
    }

    let exponent = if exponent_bits == 0 {
        -1022
    } else {
        exponent_bits - 1023
    };
    let mantissa_units = if exponent_bits == 0 {
        fraction as u128
    } else {
        (1_u128 << 52) | fraction as u128
    };

    let mut out = String::new();
    out.push_str(sign);
    out.push_str(prefix);
    match precision {
        Some(precision) => {
            let integer;
            let fraction;
            if precision >= 13 {
                integer = mantissa_units >> 52;
                fraction = mantissa_units & ((1_u128 << 52) - 1);
            } else {
                let rounded = round_hex_mantissa(mantissa_units, precision);
                let scale = if precision == 0 {
                    1
                } else {
                    1_u128 << (4 * precision)
                };
                integer = rounded / scale;
                fraction = rounded % scale;
            }
            let _ = write!(out, "{integer:x}");
            if precision != 0 {
                out.push('.');
                if precision >= 13 {
                    let _ = write!(out, "{fraction:013x}");
                    out.extend(std::iter::repeat_n('0', precision - 13));
                } else {
                    let _ = write!(out, "{fraction:0precision$x}");
                }
            }
        }
        None => {
            let integer = mantissa_units >> 52;
            let fraction = mantissa_units & ((1_u128 << 52) - 1);
            let _ = write!(out, "{integer:x}");
            let mut digits = String::with_capacity(13);
            for idx in (0..13).rev() {
                let nibble = ((fraction >> (idx * 4)) & 0xf) as usize;
                digits.push(hex_digits[nibble] as char);
            }
            let trimmed = digits.trim_end_matches('0');
            if !trimmed.is_empty() {
                out.push('.');
                out.push_str(trimmed);
            }
        }
    }
    if uppercase {
        out = out.to_ascii_uppercase();
    }
    out.push(exponent_marker);
    if exponent >= 0 {
        let _ = write!(out, "+{exponent}");
    } else {
        let _ = write!(out, "{exponent}");
    }
    out
}

fn round_hex_mantissa(mantissa_units: u128, precision: usize) -> u128 {
    if precision >= 13 {
        return mantissa_units << (4 * (precision - 13));
    }
    let shift = 52 - (4 * precision);
    if shift == 0 {
        return mantissa_units;
    }
    let quotient = mantissa_units >> shift;
    let remainder = mantissa_units & ((1_u128 << shift) - 1);
    let half = 1_u128 << (shift - 1);
    if remainder > half || (remainder == half && quotient & 1 == 1) {
        quotient + 1
    } else {
        quotient
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
    let mut entries = Vec::new();
    let mut i = 0;
    loop {
        let p = unsafe { *argv.add(i) };
        if p.is_null() {
            break;
        }
        let Some(bytes) = (unsafe { read_c_string_bytes(p) }) else {
            return libc::EINVAL;
        };
        let Some(entry_len) = bytes.len().checked_add(1) else {
            return libc::ENOMEM;
        };
        let Some(next_total_len) = total_len.checked_add(entry_len) else {
            return libc::ENOMEM;
        };
        total_len = next_total_len;
        entries.push(bytes);
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
    let buf = unsafe { crate::malloc_abi::malloc(total_len) as *mut c_char };
    if buf.is_null() {
        return libc::ENOMEM;
    }

    let mut offset = 0;
    for bytes in entries {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.add(offset) as *mut u8, bytes.len());
            *buf.add(offset + bytes.len()) = 0;
        }
        offset += bytes.len() + 1;
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

    let Some(s_bytes) = (unsafe { read_c_string_bytes(string) }) else {
        return libc::EINVAL;
    };
    let sep_byte = sep as u8;
    let entries = argz_sep_entries(&s_bytes, sep_byte);

    if entries.is_empty() {
        unsafe {
            *argz = std::ptr::null_mut();
            *argz_len = 0;
        }
        return 0;
    }

    let len: usize = entries.iter().map(|entry| entry.len() + 1).sum();
    // GNU argz: caller frees via libc::free (bd-zgifl).
    let ptr = unsafe { crate::malloc_abi::malloc(len) as *mut c_char };
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
        unsafe { crate::malloc_abi::free(old_buf.cast()) };
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

unsafe fn argz_add_bytes(argz: *mut *mut c_char, argz_len: *mut usize, bytes: &[u8]) -> c_int {
    let old_buf = unsafe { *argz };
    let old_len = if old_buf.is_null() {
        0
    } else {
        unsafe { *argz_len }
    };
    let Some(entry_len) = bytes.len().checked_add(1) else {
        return libc::ENOMEM;
    };
    let Some(new_len) = old_len.checked_add(entry_len) else {
        return libc::ENOMEM;
    };
    let new_buf = unsafe { crate::malloc_abi::malloc(new_len) as *mut c_char };
    if new_buf.is_null() {
        return libc::ENOMEM;
    }
    unsafe {
        if old_len > 0 {
            std::ptr::copy_nonoverlapping(old_buf as *const u8, new_buf as *mut u8, old_len);
        }
        if !bytes.is_empty() {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                new_buf.add(old_len) as *mut u8,
                bytes.len(),
            );
        }
        *new_buf.add(old_len + bytes.len()) = 0;
        replace_owned_argz_buffer(argz, argz_len, new_buf, new_len);
    }
    0
}

unsafe fn argz_entry_len_at(argz: *const c_char, argz_len: usize, pos: usize) -> Option<usize> {
    if argz.is_null() || pos >= argz_len {
        return None;
    }
    let (entry_len, terminated) = unsafe { scan_c_string(argz.add(pos), Some(argz_len - pos)) };
    if !terminated {
        return None;
    }
    Some(entry_len)
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
    let Some(bytes) = (unsafe { read_c_string_bytes(str_) }) else {
        return libc::EINVAL;
    };
    unsafe { argz_add_bytes(argz, argz_len, &bytes) }
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
    let Some(s_bytes) = (unsafe { read_c_string_bytes(string) }) else {
        return libc::EINVAL;
    };
    let sep_byte = sep as u8;
    for part in argz_sep_entries(&s_bytes, sep_byte) {
        let rc = unsafe { argz_add_bytes(argz, argz_len, part) };
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
    let old_buf = unsafe { *argz };
    let old_len = if old_buf.is_null() {
        0
    } else {
        unsafe { *argz_len }
    };
    let Some(new_len) = old_len.checked_add(buf_len) else {
        return libc::ENOMEM;
    };
    let new_buf = unsafe { crate::malloc_abi::malloc(new_len) as *mut c_char };
    if new_buf.is_null() {
        return libc::ENOMEM;
    }
    unsafe {
        if old_len > 0 {
            std::ptr::copy_nonoverlapping(old_buf as *const u8, new_buf as *mut u8, old_len);
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
    let (entry_len, terminated) = unsafe { scan_c_string(entry, Some(len - entry_offset)) };
    if !terminated {
        return;
    }
    let entry_len = entry_len + 1; // include NUL
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
            crate::malloc_abi::free(az.cast());
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
    let mut idx = 0usize;
    let mut pos = 0usize;
    while pos < argz_len {
        let Some(entry_len) = (unsafe { argz_entry_len_at(argz, argz_len, pos) }) else {
            unsafe { *argv.add(idx) = std::ptr::null_mut() };
            return;
        };
        unsafe { *argv.add(idx) = argz.add(pos) as *mut c_char };
        idx += 1;
        pos += entry_len + 1;
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
    let Some(entry_bytes) = (unsafe { read_c_string_bytes(entry) }) else {
        return libc::EINVAL;
    };
    let Some(slen) = entry_bytes.len().checked_add(1) else {
        return libc::ENOMEM;
    };
    let old_len = unsafe { *argz_len };
    let az = unsafe { *argz };
    let Some(before_offset) = (unsafe { argz_entry_offset(az, old_len, before) }) else {
        return libc::EINVAL;
    };
    let Some(new_len) = old_len.checked_add(slen) else {
        return libc::ENOMEM;
    };

    let new_buf = unsafe { crate::malloc_abi::malloc(new_len) as *mut c_char };
    if new_buf.is_null() {
        return libc::ENOMEM;
    }

    let tail_len = old_len - before_offset;
    unsafe {
        if before_offset > 0 {
            std::ptr::copy_nonoverlapping(az as *const u8, new_buf as *mut u8, before_offset);
        }
        std::ptr::copy_nonoverlapping(
            entry_bytes.as_ptr(),
            new_buf.add(before_offset) as *mut u8,
            entry_bytes.len(),
        );
        *new_buf.add(before_offset + entry_bytes.len()) = 0;
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
    let Some(find_bytes) = (unsafe { read_c_string_bytes(str_) }) else {
        return libc::EINVAL;
    };
    let Some(replace_bytes) = (unsafe { read_c_string_bytes(with) }) else {
        return libc::EINVAL;
    };

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
        let (entry_len, entry_terminated) = unsafe { scan_c_string(az.add(pos), Some(len - pos)) };
        if !entry_terminated {
            return libc::EINVAL;
        }
        let entry_bytes =
            unsafe { std::slice::from_raw_parts(az.add(pos).cast::<u8>(), entry_len) };
        // glibc argz_replace replaces every SUBSTRING occurrence of `str`
        // within each entry (not whole-entry matches), counting each one — e.g.
        // replace("c"->"aac") turns the entry "ac" into "aaac". The old
        // whole-entry comparison missed all in-entry matches. Found by
        // argz_mutation_differential_fuzz (bd-2g7oyh.212).
        if find_bytes.is_empty() {
            entries.push(entry_bytes.to_vec());
        } else {
            let mut rebuilt = Vec::with_capacity(entry_bytes.len());
            let mut matched = false;
            let mut i = 0usize;
            while i < entry_bytes.len() {
                if entry_bytes[i..].starts_with(find_bytes.as_slice()) {
                    rebuilt.extend_from_slice(&replace_bytes);
                    i += find_bytes.len();
                    matched = true;
                } else {
                    rebuilt.push(entry_bytes[i]);
                    i += 1;
                }
            }
            // glibc increments replace_count ONCE per matching entry, even when
            // the entry contained several occurrences (all of which are
            // replaced in the bytes).
            if matched {
                replacements = replacements.wrapping_add(1);
            }
            entries.push(rebuilt);
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

    let new_buf = unsafe { crate::malloc_abi::malloc(new_len) as *mut c_char };
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
    let Some(name_bytes) = (unsafe { read_c_string_bytes(name) }) else {
        return std::ptr::null_mut();
    };

    let mut pos = 0usize;
    while pos < envz_len {
        let Some(entry_len) = (unsafe { argz_entry_len_at(envz, envz_len, pos) }) else {
            return std::ptr::null_mut();
        };
        let entry_bytes =
            unsafe { std::slice::from_raw_parts(envz.add(pos).cast::<u8>(), entry_len) };
        // Check if entry starts with name and is followed by '=' or NUL
        if entry_bytes.len() >= name_bytes.len()
            && entry_bytes.starts_with(&name_bytes)
            && (entry_bytes.len() == name_bytes.len() || entry_bytes[name_bytes.len()] == b'=')
        {
            return unsafe { envz.add(pos) as *mut c_char };
        }
        pos += entry_len + 1;
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
    let Some(entry_offset) = (unsafe { argz_entry_offset(envz, envz_len, entry) }) else {
        return std::ptr::null();
    };
    let Some(entry_len) = (unsafe { argz_entry_len_at(envz, envz_len, entry_offset) }) else {
        return std::ptr::null();
    };
    let entry_bytes = unsafe { std::slice::from_raw_parts(entry.cast::<u8>(), entry_len) };
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
    let Some(name_bytes) = (unsafe { read_c_string_bytes(name) }) else {
        return libc::EINVAL;
    };
    let value_bytes = if value.is_null() {
        None
    } else {
        let Some(bytes) = (unsafe { read_c_string_bytes(value) }) else {
            return libc::EINVAL;
        };
        Some(bytes)
    };

    unsafe { envz_add_bytes(envz, envz_len, &name_bytes, value_bytes.as_deref()) }
}

unsafe fn envz_add_bytes(
    envz: *mut *mut c_char,
    envz_len: *mut usize,
    name: &[u8],
    value: Option<&[u8]>,
) -> c_int {
    let Some(mut capacity) = name.len().checked_add(value.map_or(0, |v| v.len())) else {
        return libc::ENOMEM;
    };
    if value.is_some() {
        let Some(next) = capacity.checked_add(1) else {
            return libc::ENOMEM;
        };
        capacity = next;
    }

    let mut name_cstr = Vec::with_capacity(name.len() + 1);
    name_cstr.extend_from_slice(name);
    name_cstr.push(0);
    unsafe { envz_remove(envz, envz_len, name_cstr.as_ptr().cast()) };

    let mut entry = Vec::with_capacity(capacity);
    entry.extend_from_slice(name);
    if let Some(value) = value {
        entry.push(b'=');
        entry.extend_from_slice(value);
    }
    unsafe { argz_add_bytes(envz, envz_len, &entry) }
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
        let Some(entry_len) = (unsafe { argz_entry_len_at(envz2, envz2_len, pos) }) else {
            return libc::EINVAL;
        };
        let entry_bytes =
            unsafe { std::slice::from_raw_parts(envz2.add(pos).cast::<u8>(), entry_len) };

        // Parse name from entry
        let eq_pos = entry_bytes.iter().position(|&b| b == b'=');
        let name_end = eq_pos.unwrap_or(entry_bytes.len());
        let name_bytes = &entry_bytes[..name_end];

        let mut name_cstr = Vec::with_capacity(name_bytes.len() + 1);
        name_cstr.extend_from_slice(name_bytes);
        name_cstr.push(0);
        let existing = unsafe { envz_entry(*envz, *envz_len, name_cstr.as_ptr().cast()) };
        if existing.is_null() || override_ != 0 {
            let value = eq_pos.map(|p| &entry_bytes[p + 1..]);
            let rc = unsafe { envz_add_bytes(envz, envz_len, name_bytes, value) };
            if rc != 0 {
                return rc;
            }
        }

        pos += entry_len + 1;
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
    if az.is_null() || len == 0 {
        return;
    }
    let mut entries_to_remove: Vec<usize> = Vec::new();

    let mut pos = 0usize;
    while pos < len {
        let Some(entry_len) = (unsafe { argz_entry_len_at(az, len, pos) }) else {
            return;
        };
        let entry_bytes =
            unsafe { std::slice::from_raw_parts(az.add(pos).cast::<u8>(), entry_len) };
        if !entry_bytes.contains(&b'=') {
            entries_to_remove.push(pos);
        }
        pos += entry_len + 1;
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

/// glibc-internal `__strerror_r` — the GNU `char *`-returning alias of
/// `strerror_r` (NOT the XSI int variant, which is `__xpg_strerror_r`).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strerror_r(
    errnum: c_int,
    buf: *mut c_char,
    buflen: usize,
) -> *mut c_char {
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

#[derive(Clone, Copy)]
enum ConstSetScanMode {
    SpanAccepted,
    SpanRejected,
    FindMember,
}

#[inline]
fn const_set_from_args(args: &[c_int]) -> ([u8; 3], usize) {
    let mut set = [0u8; 3];
    let mut len = 0usize;
    for &arg in args {
        let byte = (arg as c_char) as u8;
        if byte == 0 {
            break;
        }
        set[len] = byte;
        len += 1;
    }
    (set, len)
}

#[inline]
fn const_set_contains(set: &[u8], byte: u8) -> bool {
    set.iter().any(|&candidate| candidate == byte)
}

#[inline]
unsafe fn scan_const_set(
    s: *const c_char,
    set: &[u8],
    mode: ConstSetScanMode,
    bound: Option<usize>,
) -> (usize, bool) {
    let mut index = 0usize;
    loop {
        if bound.is_some_and(|limit| index >= limit) {
            return (index, false);
        }

        // SAFETY: the caller supplied a C string pointer; when the allocation
        // is tracked, `bound` prevents reads beyond the known allocation.
        let byte = unsafe { *s.add(index) as u8 };
        if byte == 0 {
            return (index, false);
        }

        let member = const_set_contains(set, byte);
        match mode {
            ConstSetScanMode::SpanAccepted if !member => return (index, false),
            ConstSetScanMode::SpanRejected if member => return (index, true),
            ConstSetScanMode::FindMember if member => return (index, true),
            _ => {}
        }

        index += 1;
    }
}

#[inline]
unsafe fn const_set_span(s: *const c_char, set: &[u8], mode: ConstSetScanMode) -> usize {
    let (aligned, recent_page, ordering) = stage_context_one(s as usize);
    if s.is_null() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return 0;
    }

    if matches!(mode, ConstSetScanMode::SpanAccepted) && set.is_empty() {
        return 0;
    }

    let known_bound = known_remaining(s as usize);
    let (mode_config, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        0,
        false,
        known_bound.is_none(),
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

    let repair = repair_enabled(mode_config.heals_enabled(), decision.action);
    let (result, _) = unsafe { scan_const_set(s, set, mode, known_bound) };

    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, result),
        repair && known_bound.is_some(),
    );
    result
}

#[inline]
unsafe fn const_set_pbrk(s: *const c_char, set: &[u8]) -> *mut c_char {
    let (aligned, recent_page, ordering) = stage_context_one(s as usize);
    if s.is_null() || set.is_empty() {
        record_string_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return std::ptr::null_mut();
    }

    let known_bound = known_remaining(s as usize);
    let (mode_config, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        0,
        false,
        known_bound.is_none(),
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

    let repair = repair_enabled(mode_config.heals_enabled(), decision.action);
    let (index, found) =
        unsafe { scan_const_set(s, set, ConstSetScanMode::FindMember, known_bound) };

    record_string_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        Some(stage_index(&ordering, CheckStage::Bounds)),
    );
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, index),
        repair && known_bound.is_some(),
    );

    if found {
        // SAFETY: `scan_const_set` only returns `found` for an index it read
        // from the caller-provided C string.
        unsafe { s.add(index) as *mut c_char }
    } else {
        std::ptr::null_mut()
    }
}

/// `__strpbrk_c2` — strpbrk optimized for 2-char accept set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strpbrk_c2(s: *const c_char, a1: c_int, a2: c_int) -> *mut c_char {
    let (set, len) = const_set_from_args(&[a1, a2]);
    unsafe { const_set_pbrk(s, &set[..len]) }
}

/// `__strpbrk_c3` — strpbrk optimized for 3-char accept set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strpbrk_c3(
    s: *const c_char,
    a1: c_int,
    a2: c_int,
    a3: c_int,
) -> *mut c_char {
    let (set, len) = const_set_from_args(&[a1, a2, a3]);
    unsafe { const_set_pbrk(s, &set[..len]) }
}

/// `__strcspn_c1` — strcspn optimized for 1-char reject set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcspn_c1(s: *const c_char, r: c_int) -> usize {
    let (set, len) = const_set_from_args(&[r]);
    unsafe { const_set_span(s, &set[..len], ConstSetScanMode::SpanRejected) }
}

/// `__strcspn_c2` — strcspn optimized for 2-char reject set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcspn_c2(s: *const c_char, r1: c_int, r2: c_int) -> usize {
    let (set, len) = const_set_from_args(&[r1, r2]);
    unsafe { const_set_span(s, &set[..len], ConstSetScanMode::SpanRejected) }
}

/// `__strcspn_c3` — strcspn optimized for 3-char reject set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcspn_c3(s: *const c_char, r1: c_int, r2: c_int, r3: c_int) -> usize {
    let (set, len) = const_set_from_args(&[r1, r2, r3]);
    unsafe { const_set_span(s, &set[..len], ConstSetScanMode::SpanRejected) }
}

/// `__strspn_c1` — strspn optimized for 1-char accept set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strspn_c1(s: *const c_char, a: c_int) -> usize {
    let (set, len) = const_set_from_args(&[a]);
    unsafe { const_set_span(s, &set[..len], ConstSetScanMode::SpanAccepted) }
}

/// `__strspn_c2` — strspn optimized for 2-char accept set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strspn_c2(s: *const c_char, a1: c_int, a2: c_int) -> usize {
    let (set, len) = const_set_from_args(&[a1, a2]);
    unsafe { const_set_span(s, &set[..len], ConstSetScanMode::SpanAccepted) }
}

/// `__strspn_c3` — strspn optimized for 3-char accept set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strspn_c3(s: *const c_char, a1: c_int, a2: c_int, a3: c_int) -> usize {
    let (set, len) = const_set_from_args(&[a1, a2, a3]);
    unsafe { const_set_span(s, &set[..len], ConstSetScanMode::SpanAccepted) }
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
    unsafe { crate::unistd_abi::strfmon_emit(s, maxsize, format, || args.next_arg::<f64>()) }
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

/// NetBSD `consttime_memequal(b1, b2, len)` — constant-time byte
/// equality test. Returns `1` if the first `len` bytes of `b1` and
/// `b2` are byte-equal, `0` otherwise. Always touches every byte
/// regardless of where the inputs differ; used by crypto code (TLS
/// / SSH MAC verification) to compare hashes without timing leaks.
///
/// `len == 0` always returns `1` (NetBSD convention: empty buffers
/// trivially equal).
///
/// # Safety
///
/// Caller must ensure `b1` and `b2` are valid for `len` bytes
/// each. `len == 0` is always safe.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn consttime_memequal(
    b1: *const c_void,
    b2: *const c_void,
    len: usize,
) -> c_int {
    // Delegate to the established constant-time bcmp helper and
    // invert: bcmp returns 0 for equal / non-zero for not-equal;
    // consttime_memequal flips that to 1 for equal / 0 for not.
    let bcmp_res = unsafe { timingsafe_bcmp(b1, b2, len) };
    if bcmp_res == 0 { 1 } else { 0 }
}

/// NetBSD `consttime_bcmp(s1, s2, n) -> int` — constant-time byte
/// comparison returning 0 if equal, 1 if not. Convention matches
/// the shape of `bcmp` rather than the inverted-equality of
/// `consttime_memequal`.
///
/// # Safety
///
/// `s1` and `s2` must be valid for `n` bytes each. `n == 0` is
/// always safe.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn consttime_bcmp(s1: *const c_void, s2: *const c_void, n: usize) -> c_int {
    let bcmp_res = unsafe { timingsafe_bcmp(s1, s2, n) };
    if bcmp_res == 0 { 0 } else { 1 }
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

// ---------------------------------------------------------------------------
// strnstr (BSD bounded substring search)
// ---------------------------------------------------------------------------

/// BSD `strnstr(haystack, needle, n)` — like `strstr` but searches at
/// most `n` bytes of `haystack`. Returns a pointer to the first
/// occurrence of `needle` (still NUL-terminated) within
/// `haystack[..min(n, strlen(haystack))]`, or NULL if not found.
///
/// An empty `needle` returns `haystack` (same as `strstr` semantics).
/// `n == 0` with a non-empty needle returns NULL.
///
/// # Safety
///
/// Caller must ensure `haystack` and `needle` are valid NUL-terminated
/// C strings (or NULL — both NULL pointers and a NULL haystack with a
/// non-empty needle yield NULL).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strnstr(
    haystack: *const c_char,
    needle: *const c_char,
    n: usize,
) -> *mut c_char {
    if needle.is_null() {
        // Match strstr's well-trodden glibc/BSD behavior: NULL needle
        // is treated as the empty string and returns haystack.
        return haystack as *mut c_char;
    }
    if haystack.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: per BSD strnstr contract, the caller guarantees haystack
    // either contains a NUL within the first n bytes OR is valid for n
    // bytes of read; the bound applies whichever happens first. The
    // core `strnstr` walks a single pass that short-circuits on NUL and
    // is itself bounded by `min(n, slice.len())`, so giving it a slice
    // of length `n` lets the inner loop do the strnlen and the search
    // together — what the bd-ef934 perf slice was about.
    let hay_slice = unsafe { std::slice::from_raw_parts(haystack as *const u8, n) };
    let needle_len = unsafe { strlen(needle) };
    // SAFETY: needle_len is the strlen we just measured.
    let needle_slice = unsafe { std::slice::from_raw_parts(needle as *const u8, needle_len) };

    match frankenlibc_core::string::strnstr(hay_slice, needle_slice, n) {
        Some(off) => unsafe { haystack.add(off) as *mut c_char },
        None => std::ptr::null_mut(),
    }
}
