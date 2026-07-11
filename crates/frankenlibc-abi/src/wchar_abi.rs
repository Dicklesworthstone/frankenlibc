//! ABI layer for `<wchar.h>` functions.
//!
//! Handles wide-character (32-bit) string operations.
//! On Linux/glibc, `wchar_t` is 32-bit (UTF-32).
//!
use std::ffi::{c_char, c_int, c_long, c_longlong, c_ulong, c_ulonglong, c_void};
use std::mem::size_of;
use std::simd::{Select, Simd, cmp::SimdPartialEq, cmp::SimdPartialOrd};
use std::sync::{Mutex, OnceLock};

use frankenlibc_core::stdio::StdioStream;
use frankenlibc_core::stdio::printf::{FormatSegment, parse_format_string};
use frankenlibc_core::stdio::{ValueArgKind, count_printf_args, positional_printf_arg_plan};
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use crate::util::{ArtifactHashMap, artifact_hash_map, scan_c_string};

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

unsafe fn bounded_cstr_bytes<'a>(ptr: *const u8) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: ptr is a caller-provided C string; known_remaining limits scans
    // over tracked malloc-backed buffers before they can cross the allocation.
    let (len, terminated) =
        unsafe { scan_c_string(ptr.cast::<c_char>(), known_remaining(ptr as usize)) };
    if !terminated {
        return None;
    }
    // SAFETY: scan_c_string observed len readable bytes before the terminator.
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

#[derive(Clone, Copy)]
struct WideMemStreamSync {
    buf_loc: *mut *mut u32,
    size_loc: *mut usize,
}

// SAFETY: These raw pointers are only dereferenced while holding the registry
// mutex, and POSIX requires the caller-provided buf/size locations to remain
// valid for the lifetime of the open_wmemstream stream.
unsafe impl Send for WideMemStreamSync {}

fn wide_memstream_registry() -> &'static Mutex<Option<ArtifactHashMap<usize, WideMemStreamSync>>> {
    static REGISTRY: OnceLock<Mutex<Option<ArtifactHashMap<usize, WideMemStreamSync>>>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Some(artifact_hash_map())))
}

fn decode_wmemstream_bytes(data: &[u8]) -> Vec<u32> {
    match std::str::from_utf8(data) {
        Ok(s) => s.chars().map(|ch| ch as u32).collect(),
        Err(_) => String::from_utf8_lossy(data)
            .chars()
            .map(|ch| ch as u32)
            .collect(),
    }
}

pub(crate) unsafe fn sync_open_wmemstream_to_caller(id: usize, stream: &StdioStream) {
    let guard = wide_memstream_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(ref map) = *guard
        && let Some(info) = map.get(&id)
    {
        let Some(data) = stream.mem_data() else {
            return;
        };
        let wchars = decode_wmemstream_bytes(data);
        // POSIX: *sizeloc is the SMALLER of the content length and the current
        // file position (both in wide characters). After a backward seek the
        // reported size shrinks even though the tail wchars (and the NUL
        // terminator at the max extent) remain in the buffer. The position is
        // tracked in underlying (UTF-8) bytes, so convert the prefix to a wide
        // count. (Forward-only writes leave position == content length, a no-op.)
        let pos_bytes = (stream.offset().max(0) as usize).min(data.len());
        let pos_wchars = decode_wmemstream_bytes(&data[..pos_bytes]).len();
        let reported = wchars.len().min(pos_wchars);
        let alloc_size = (wchars.len() + 1) * size_of::<u32>();
        let buf = unsafe { crate::malloc_abi::raw_alloc(alloc_size) } as *mut u32;
        if buf.is_null() {
            return;
        }
        for (idx, wc) in wchars.iter().copied().enumerate() {
            unsafe { *buf.add(idx) = wc };
        }
        unsafe { *buf.add(wchars.len()) = 0 };
        let previous = unsafe { *info.buf_loc };
        unsafe {
            *info.buf_loc = buf;
            *info.size_loc = reported;
        }
        if !previous.is_null() {
            unsafe { crate::malloc_abi::raw_free(previous.cast::<c_void>()) };
        }
    }
}

pub(crate) fn unregister_open_wmemstream(id: usize) {
    let mut guard = wide_memstream_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(ref mut map) = *guard {
        map.remove(&id);
    }
}

pub(crate) fn fwide_orientation(stream: *mut c_void) -> Option<c_int> {
    let id = crate::stdio_abi::stream_id_from_handle(stream);
    let guard = wide_memstream_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .and_then(|map| map.contains_key(&id).then_some(1))
}

/// Scan a wide string with an optional hard bound (in elements).
///
/// Returns `(len, terminated)` where:
/// - `len` is the element length before the first NUL or before the bound.
/// - `terminated` indicates whether a NUL wide-char was observed.
unsafe fn scan_w_string(ptr: *const u32, bound: Option<usize>) -> (usize, bool) {
    match bound {
        Some(limit) => {
            // Bounded SIMD NUL scan (reads only within `limit`). Returns NUL index or limit.
            let r = unsafe { wide_strlen_bounded(ptr, limit) };
            (r, r < limit)
        }
        None => {
            // Page-safe SIMD NUL scan (aligned-head-mask + 128B min-combine unroll;
            // guard-page proven). 7-17x over the old scalar element loop — and this
            // helper feeds wcsspn/wcscspn/wcspbrk/wcstok + every unbounded wide caller.
            (unsafe { wide_strlen_unbounded(ptr) }, true)
        }
    }
}

unsafe fn scan_known_multibyte_string(ptr: *const std::ffi::c_char) -> Option<usize> {
    let (len, terminated) = unsafe { scan_c_string(ptr, known_remaining(ptr as usize)) };
    if terminated { Some(len) } else { None }
}

unsafe fn scan_known_wide_string(ptr: *const u32) -> Option<usize> {
    let bound = known_remaining(ptr as usize).map(bytes_to_wchars);
    let (len, terminated) = unsafe { scan_w_string(ptr, bound) };
    if terminated { Some(len) } else { None }
}

unsafe fn bounded_wide_len(ptr: *const u32) -> usize {
    let bound = known_remaining(ptr as usize).map(bytes_to_wchars);
    let (len, _) = unsafe { scan_w_string(ptr, bound) };
    len
}

// ---------------------------------------------------------------------------
// wcslen
// ---------------------------------------------------------------------------

/// Page-safe unbounded SIMD wcslen for raw (untracked) wide strings. Aligned-head-mask
/// (align the u32 pointer down to a 32-byte boundary, mask the head lanes that precede
/// `s`) + an escalated 128-byte (4×8-lane-u32) min-combine unroll. A 32-byte-aligned
/// 8-lane load and a 128-byte-aligned unroll load each stay within one 4 KiB page
/// (32|4096, 128|4096), so no per-chunk page guard is needed — the same discipline as
/// the byte `scan_c_string` None path (guard-page proven). ~7-17x over the scalar loop,
/// parity-to-WIN vs glibc wcslen for >=1024.
#[inline]
unsafe fn wide_strlen_unbounded(s: *const u32) -> usize {
    use std::simd::cmp::SimdOrd;
    let z = Simd::<u32, 8>::splat(0);
    let pb = s as usize;
    let align = (pb & 31) >> 2; // u32 elements before the 32-byte boundary (0..=7)
    // SAFETY: `base` is in the same mapped page as `s` (aligned down ≤ 28 bytes).
    let base = unsafe { s.sub(align) };
    let v0 = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(base, 8) });
    let m0 = v0.simd_eq(z).to_bitmask() & !((1u64 << align) - 1);
    if m0 != 0 {
        return m0.trailing_zeros() as usize - align;
    }
    let mut i = 8 - align; // s+i is 32-byte (8-u32) aligned
    // 8-lane tier: step 32 B/iter until `s+i` reaches the next 128-byte boundary, then
    // escalate to the 128B min-combine unroll. A short string terminates in this tier
    // before it ever reaches the boundary (each 8-lane load already probes 32 B), so we
    // no longer wait for the old i>=64 (256 B) gate that kept medium strings — the whole
    // 32..256-wchar band — stuck at 32 B/iter and losing to glibc's early 128 B loop.
    // 128-alignment keeps every 128 B window inside one page (128 | 4096), so this is
    // still page-safe for the untracked/unbounded scan.
    while (pb + i * 4) & 127 != 0 {
        // SAFETY: s+i is 32-byte aligned ⇒ the 32-byte window stays in one page.
        let v = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i), 8) });
        let m = v.simd_eq(z).to_bitmask();
        if m != 0 {
            return i + m.trailing_zeros() as usize;
        }
        i += 8;
    }
    loop {
        // SAFETY: s+i is 128-byte aligned ⇒ [i, i+32) (128 bytes) stays in one page.
        let a = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i), 8) });
        let b = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i + 8), 8) });
        let c = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i + 16), 8) });
        let d = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i + 24), 8) });
        if a.simd_min(b).simd_min(c.simd_min(d)).simd_eq(z).any() {
            let ma = a.simd_eq(z).to_bitmask();
            if ma != 0 {
                return i + ma.trailing_zeros() as usize;
            }
            let mb = b.simd_eq(z).to_bitmask();
            if mb != 0 {
                return i + 8 + mb.trailing_zeros() as usize;
            }
            let mc = c.simd_eq(z).to_bitmask();
            if mc != 0 {
                return i + 16 + mc.trailing_zeros() as usize;
            }
            return i + 24 + d.simd_eq(z).to_bitmask().trailing_zeros() as usize;
        }
        i += 32;
    }
}

/// Bounded SIMD wcslen within `limit` wide chars (tracked allocations): reads only within
/// `limit`, so no page guard is needed. Returns the NUL index or `limit`.
#[inline]
unsafe fn wide_strlen_bounded(s: *const u32, limit: usize) -> usize {
    use std::simd::cmp::SimdOrd;
    let z = Simd::<u32, 8>::splat(0);
    let mut i = 0usize;
    while i + 32 <= limit {
        let a = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i), 8) });
        let b = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i + 8), 8) });
        let c = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i + 16), 8) });
        let d = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i + 24), 8) });
        if a.simd_min(b).simd_min(c.simd_min(d)).simd_eq(z).any() {
            for j in 0..32 {
                if unsafe { *s.add(i + j) } == 0 {
                    return i + j;
                }
            }
        }
        i += 32;
    }
    while i + 8 <= limit {
        let v = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i), 8) });
        let m = v.simd_eq(z).to_bitmask();
        if m != 0 {
            return i + m.trailing_zeros() as usize;
        }
        i += 8;
    }
    while i < limit {
        if unsafe { *s.add(i) } == 0 {
            return i;
        }
        i += 1;
    }
    limit
}

/// Fused single-pass wcscpy for raw (untracked, strict-mode) wide strings: copies `src`
/// through its terminating NUL into `dst` in ONE pass, writing exactly `len + 1` wide
/// chars. Replaces the prior two-pass `scan_w_string` + `copy_nonoverlapping` (the copy
/// lowered to the interposed fl `memcpy` symbol — an ABI-entry + membrane call, ~6x
/// glibc at small sizes and ~2x the memory traffic at large). Aligned-load-down +
/// head-mask read discipline (32|4096 keeps each 8-lane read in one page); full NUL-free
/// 8-lane chunks are SIMD-stored, the NUL-containing tail is copied scalar up to and
/// including the NUL, so `dst` receives byte-for-byte the same `len + 1` chars as glibc.
///
/// Bounded wide copy of exactly `count` u32 chars (no NUL scan). 8-lane SIMD store loop
/// + scalar tail — never lowers to the interposed `memcpy` symbol (`copy_to_slice` is a
/// vector store), so an n-bounded wide copy skips the symbol round trip. dst/src disjoint.
///
/// # Safety
/// `src`/`dst` valid for `count` u32 reads/writes and non-overlapping.
#[inline]
unsafe fn wide_copy_n(dst: *mut u32, src: *const u32, count: usize) {
    // Large copies: a wide (u32) copy of `count` elements is byte-for-byte a forward
    // memcpy of `count*4` bytes — and every caller here is disjoint/forward (memcpy
    // semantics), never an overlapping move. For count >= 1024 (>= 4 KiB) delegate to the
    // shared byte-copy primitive, which has the tuned size dispatch (AVX vmovdqu loop for
    // mid-large / rep movsb only >=128 KiB). The inline 8-lane loop below emits only
    // 32 bytes/iter with a single accumulator and lost 1.28-1.66x to glibc's memcpy (==
    // what glibc's wmemcpy calls) from 4 KiB up (measured wmemcpy_ab); the byte primitive
    // brings 64 KiB to parity and 4-16 KiB from ~1.6x to ~1.3x. Below 4 KiB the inline
    // loop stays — it beats the byte primitive's per-call dispatch + small-size floor
    // (raw_overlap_copy is ~2.1x at 256 B). `count*4` cannot overflow for any real buffer.
    if count >= 1024 {
        unsafe {
            crate::string_abi::raw_overlap_copy(dst.cast::<u8>(), src.cast::<u8>(), count * 4)
        };
        return;
    }
    let mut i = 0usize;
    while i + 8 <= count {
        let v = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i), 8) });
        v.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i), 8) });
        i += 8;
    }
    while i < count {
        unsafe { *dst.add(i) = *src.add(i) };
        i += 1;
    }
}

/// Overlap-safe wide move of `count` u32 elements (the C `wmemmove` contract).
///
/// Self-contained so it does NOT route through the `memmove` symbol that
/// `std::ptr::copy` lowers to: in a binary that links frankenlibc, that symbol is
/// frankenlibc's own SIMD `memmove`, whose backward-overlap path was observed to
/// mis-copy the tail of an overlapping wide move under some builds (the
/// `conformance_diff_wcs_copy::wmemmove_overlap` failure; see NEGATIVE_EVIDENCE.md).
/// Here we pick the copy direction explicitly: a forward copy is safe whenever the
/// destination is not ahead of the source within the source extent (disjoint, or
/// dst <= src); otherwise we copy backward element-wise so no element is read after
/// it has been overwritten. Forward runs use the fast wide SIMD copy; the rarer
/// backward-overlap case takes a correct scalar loop.
///
/// # Safety
/// `src`/`dst` must be valid for `count` u32 reads/writes; they may overlap.
#[inline]
unsafe fn wide_move_n(dst: *mut u32, src: *const u32, count: usize) {
    if count == 0 {
        return;
    }
    let d = dst as usize;
    let s = src as usize;
    // dst strictly ahead of src and within [src, src+count) ⇒ forward would clobber
    // not-yet-read source elements. Copy backward (high→low) in that case only.
    if d > s && d < s + count * 4 {
        let mut k = count;
        while k > 0 {
            k -= 1;
            // SAFETY: k < count; both pointers valid for count elements.
            unsafe { *dst.add(k) = *src.add(k) };
        }
    } else {
        // Disjoint or dst behind src ⇒ a forward copy never reads an overwritten
        // element. `wide_copy_n` is forward-only and stays off the memmove symbol.
        unsafe { wide_copy_n(dst, src, count) };
    }
}

/// Returns the length copied (index of the terminating NUL), so `wcpcpy` can return the
/// end pointer `dst + len` without a second scan.
///
/// # Safety
/// `src` must be a valid NUL-terminated wide string and `dst` must have room for
/// `wcslen(src) + 1` wide chars (the caller's contract for C `wcscpy`/`wcpcpy`).
#[inline]
unsafe fn wide_fused_copy(dst: *mut u32, src: *const u32) -> usize {
    use std::simd::cmp::SimdOrd;
    let z = Simd::<u32, 8>::splat(0);
    let pb = src as usize;
    let align = (pb & 31) >> 2; // u32 elements before the 32-byte boundary (0..=7)
    // SAFETY: `base` is aligned down <= 28 bytes, in the same mapped page as `src`.
    let base = unsafe { src.sub(align) };
    let v0 = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(base, 8) });
    let m0 = v0.simd_eq(z).to_bitmask() & !((1u64 << align) - 1);
    if m0 != 0 {
        // NUL within the first (masked) window: copy src[0..=nul] inclusive.
        let nul = m0.trailing_zeros() as usize - align;
        for j in 0..=nul {
            // SAFETY: j <= nul < remaining string length; dst has room for len+1.
            unsafe { *dst.add(j) = *src.add(j) };
        }
        return nul;
    }
    // First (partial) chunk [src, base+8): (8 - align) elements, all confirmed non-NUL.
    let first = 8 - align;
    for j in 0..first {
        // SAFETY: within the just-read window; these lanes are non-NUL string chars.
        unsafe { *dst.add(j) = *src.add(j) };
    }
    let mut i = first; // src+i is 32-byte (8-u32) aligned

    // 8-lane step: reads/stores one 32-byte chunk at src+i (32-byte aligned ⇒ the load
    // never crosses a page). Copies through the NUL and returns its index if present,
    // else stores the full chunk and reports "advance 8".
    macro_rules! lane8 {
        () => {{
            // SAFETY: src+i is 32-byte aligned ⇒ this 8-lane (32-byte) load stays in-page.
            let v =
                Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i), 8) });
            let m = v.simd_eq(z).to_bitmask();
            if m != 0 {
                let nul = m.trailing_zeros() as usize;
                for j in 0..=nul {
                    // SAFETY: copies through the NUL; dst has room for len+1.
                    unsafe { *dst.add(i + j) = *src.add(i + j) };
                }
                return i + nul;
            }
            // No NUL: all 8 lanes are real chars ⇒ dst has room for [i, i+8).
            v.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i), 8) });
            i += 8;
        }};
    }

    // Prologue: two plain 8-lane chunks. Very short strings (<= ~24 wchars) reach their
    // NUL here and return before any wide read, so the 128-byte tier never over-reads a
    // short string's tail (which regressed small sizes when the tier ran unconditionally).
    // Long strings pay two trivial iterations, then reap the wide tier. Measured
    // (wfused_copy_ab, in-process new-vs-old): n=16 0.98x, n=64 0.92x, n=256 1.23x,
    // n=1024 1.89x, n=4096 1.49x — the deployed wcscpy/wcpcpy strict hot path.
    lane8!();
    lane8!();

    loop {
        // 128-byte (4×8-lane) tier, page-guarded: four 32-byte chunks per iteration, run
        // only while reading 128 bytes ahead stays within the current page. The min-reduce
        // `min(c0,c1,c2,c3)` has a zero lane iff some chunk holds a NUL; when clean we
        // bulk-store all 128 bytes and skip four separate NUL branches. Byte-identical to
        // the 8-lane loop (same chars copied, same NUL index returned).
        while (unsafe { src.add(i) } as usize & 0xFFF) <= 0x1000 - 128 {
            // SAFETY: guard guarantees [src+i, src+i+32 u32) is in the same mapped page.
            let c0 =
                Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i), 8) });
            let c1 = Simd::<u32, 8>::from_slice(unsafe {
                std::slice::from_raw_parts(src.add(i + 8), 8)
            });
            let c2 = Simd::<u32, 8>::from_slice(unsafe {
                std::slice::from_raw_parts(src.add(i + 16), 8)
            });
            let c3 = Simd::<u32, 8>::from_slice(unsafe {
                std::slice::from_raw_parts(src.add(i + 24), 8)
            });
            if c0.simd_min(c1).simd_min(c2.simd_min(c3)).simd_eq(z).any() {
                // A NUL is in these 128 bytes: copy each chunk exactly, stopping at it.
                for (k, c) in [c0, c1, c2, c3].iter().enumerate() {
                    let m = c.simd_eq(z).to_bitmask();
                    if m != 0 {
                        let nul = m.trailing_zeros() as usize;
                        let off = i + k * 8;
                        for j in 0..=nul {
                            // SAFETY: copies through the NUL; dst has room for len+1.
                            unsafe { *dst.add(off + j) = *src.add(off + j) };
                        }
                        return off + nul;
                    }
                    // SAFETY: this chunk is NUL-free ⇒ dst has room for [i+k*8, +8).
                    c.copy_to_slice(unsafe {
                        std::slice::from_raw_parts_mut(dst.add(i + k * 8), 8)
                    });
                }
                unreachable!("min-reduce reported a NUL that no chunk contained");
            }
            // No NUL in 128 bytes: bulk-store all four chunks (unaligned stores).
            c0.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i), 8) });
            c1.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + 8), 8) });
            c2.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + 16), 8) });
            c3.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + 24), 8) });
            i += 32;
        }
        // Near a page boundary the wide read could fault; the 8-lane step is always safe
        // (32-aligned 32-byte read) and keeps i 32-aligned, so a later iteration re-enters
        // the wide tier once past the boundary.
        lane8!();
    }
}

/// Fused bounded copy CORE for the wide n-copy/append family: copies the real (non-NUL)
/// chars of `src` into `dst` up to the terminating NUL or `n` wchars (whichever comes
/// first) in ONE page-guarded 128B (4×8-lane) pass, and returns `min(wcslen(src), n)` —
/// the number of chars written. It does NOT write a terminator or pad; the caller decides:
/// `wcsncpy`/`wcpncpy` zero-pad `[ret, n)`, `wcsncat` writes a single NUL at `dst[ret]`.
///
/// Replaces the deployed scan-then-copy two-pass (`scan_w_string` + `wide_copy_n`) which
/// reads the copied region twice and, for `n < 1024`, copies only 8 lanes/iter. Measured
/// (wcsncpy_fused_ab, in-process vs the old 8-lane two-pass) 1.03–2.34x. Byte-identical.
///
/// # Safety
/// `src` valid up to its NUL or `n` wchars; `dst` valid for `n` wchars. Disjoint.
#[inline]
unsafe fn wide_fused_ncopy(dst: *mut u32, src: *const u32, n: usize) -> usize {
    use std::simd::cmp::SimdOrd;
    let z = Simd::<u32, 8>::splat(0);
    let mut i = 0usize;
    // 128B tier: four 32-byte chunks per iter, only while a 128B read stays in-page AND
    // stays within the n-bounded window. min-reduce flags a NUL anywhere in the 128B.
    while i + 32 <= n && (unsafe { src.add(i) } as usize & 0xFFF) <= 0x1000 - 128 {
        let c0 = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i), 8) });
        let c1 =
            Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i + 8), 8) });
        let c2 =
            Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i + 16), 8) });
        let c3 =
            Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i + 24), 8) });
        if c0.simd_min(c1).simd_min(c2.simd_min(c3)).simd_eq(z).any() {
            // A NUL is in these 128 bytes: copy the real chars of each clean chunk, then on
            // the NUL-bearing chunk copy up to (not incl.) the NUL and return its index.
            for (k, c) in [c0, c1, c2, c3].iter().enumerate() {
                let m = c.simd_eq(z).to_bitmask();
                if m != 0 {
                    let nul = i + k * 8 + m.trailing_zeros() as usize;
                    for j in (i + k * 8)..nul {
                        // SAFETY: real (non-NUL) chars before the terminator.
                        unsafe { *dst.add(j) = *src.add(j) };
                    }
                    return nul;
                }
                // SAFETY: NUL-free chunk ⇒ dst has room for [i+k*8, +8).
                c.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + k * 8), 8) });
            }
            unreachable!("min-reduce reported a NUL that no chunk contained");
        }
        // No NUL in 128 bytes: bulk-store all four chunks.
        c0.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i), 8) });
        c1.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + 8), 8) });
        c2.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + 16), 8) });
        c3.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + 24), 8) });
        i += 32;
    }
    // 8-lane / scalar tail: within the last <128B (or near a page edge / n boundary).
    while i < n {
        // SAFETY: i < n ⇒ src+i / dst+i in-bounds.
        let c = unsafe { *src.add(i) };
        if c == 0 {
            return i;
        }
        unsafe { *dst.add(i) = c };
        i += 1;
    }
    n
}

/// `wcsncpy`/`wcpncpy` body: fused copy of `min(strlen,n)` chars then zero-pad `[ret, n)`.
/// Returns `min(wcslen(src), n)` — the `wcpncpy` end offset (`dst + ret`), ignored by
/// `wcsncpy`. Byte-identical to the old scan-then-copy-then-pad two-pass.
///
/// # Safety
/// `src` valid up to its NUL or `n` wchars; `dst` valid for `n` wchars. Disjoint.
#[inline]
unsafe fn wide_fused_copy_n(dst: *mut u32, src: *const u32, n: usize) -> usize {
    let copied = unsafe { wide_fused_ncopy(dst, src, n) };
    if copied < n {
        // SAFETY: [copied, n) in-bounds for dst; writes the NUL + pad.
        unsafe { std::slice::from_raw_parts_mut(dst.add(copied), n - copied).fill(0) };
    }
    copied
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcslen(s: *const u32) -> usize {
    if s.is_null() {
        return 0;
    }

    // Strict-mode fast path (DEFAULT deployed): the raw page-safe SIMD scan to NUL is
    // byte-identical to the strict full body for BOTH tracked and untracked pointers
    // (strict = no heal, so bounded and unbounded scans return the same length for a
    // valid string). Skips known_remaining + decide + observe entirely — mirroring the
    // narrow `strlen` fast path (which likewise covers tracked pointers in strict).
    // Hardened mode keeps the full validating/healing path below.
    if runtime_policy::strict_passthrough_active() {
        return unsafe { wide_strlen_unbounded(s) };
    }
    let known = known_remaining(s as usize);
    let (_mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        s as usize,
        0,
        false,
        known.is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 6, true);
        return 0;
    }

    if let Some(bytes_rem) = known {
        let limit = bytes_to_wchars(bytes_rem);
        // SAFETY: bounded SIMD scan within the known allocation extent (no page guard
        // needed — reads stay within `limit`). Returns the NUL index or `limit`.
        let found = unsafe { wide_strlen_bounded(s, limit) };
        if found < limit {
            runtime_policy::observe(
                ApiFamily::StringMemory,
                decision.profile,
                runtime_policy::scaled_cost(7, found * 4),
                false,
            );
            return found;
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

    // SAFETY: untracked raw wide string — page-safe SIMD scan (aligned-head-mask +
    // escalated 128B min-combine unroll; 32|4096 + 128|4096 aligned loads never cross a
    // page). 7-17x over the old scalar loop, parity-to-win vs glibc. Same libc-like
    // raw-scan semantics (first NUL).
    let len = unsafe { wide_strlen_unbounded(s) };
    runtime_policy::observe(
        ApiFamily::StringMemory,
        decision.profile,
        runtime_policy::scaled_cost(7, len * 4),
        false,
    );
    len
}

// ---------------------------------------------------------------------------
// wcscpy
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcscpy(dst: *mut u32, src: *const u32) -> *mut u32 {
    if dst.is_null() || src.is_null() {
        return dst;
    }

    // Strict-mode fast path (DEFAULT deployed): byte-identical to the unbounded
    // scalar copy branch below, but skips the (write) decide + observe membrane
    // path — which for the wide write family is ~655ns/call — and upgrades the
    // scalar wchar loop to a SIMD length scan + bulk copy.
    if runtime_policy::strict_passthrough_active() {
        // Fused single-pass copy-through-NUL: no scan_w_string + interposed-memcpy
        // round trip (that was ~6x glibc at small sizes / ~2x traffic at large).
        unsafe { wide_fused_copy(dst, src) };
        return dst;
    }

    let dst_bound = known_remaining(dst as usize).map(bytes_to_wchars);
    let src_bound = known_remaining(src as usize).map(bytes_to_wchars);
    let (_mode, decision) = runtime_policy::decide(
        ApiFamily::StringMemory,
        dst as usize,
        0,
        true,
        dst_bound.is_none() && src_bound.is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 7, true);
        return std::ptr::null_mut();
    }

    let bounded = dst_bound.is_some() || src_bound.is_some();

    // SAFETY: known allocations are read/written only within their live extent;
    // untracked strict-mode strings preserve raw libc copy semantics.
    let (copied_len, adverse) = unsafe {
        if bounded {
            let (src_len, src_terminated) = scan_w_string(src, src_bound);
            let requested = src_len.saturating_add(1);
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
                    if src_bound.is_some() {
                        if src_len > 0 {
                            std::ptr::copy_nonoverlapping(src, dst, src_len);
                        }
                        *dst.add(src_len) = 0;
                        if !src_terminated {
                            record_truncation(requested, src_len);
                        }
                        (requested, !src_terminated)
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

    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict
    // copy-then-NUL-pad body below — copy `min(strlen(src)+1, n)` wchars (through
    // the terminator if it fits), zero-pad the remainder to `n`. Skips the ~640ns
    // wide WRITE membrane full path (see wcscpy).
    if runtime_policy::strict_passthrough_active() {
        // Fused single-pass scan+copy+pad (128B tier) instead of the scan_w_string +
        // wide_copy_n two-pass (two reads of the copied region; 8-lane copy for n<1024).
        // Byte-identical; measured 1.12-1.43x (wcsncpy_fused_ab). See wide_fused_copy_n.
        unsafe { wide_fused_copy_n(dst, src, n) };
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

    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict
    // unbounded append below (scalar loop → SIMD scan + bulk copy), skipping the
    // ~640ns wide WRITE membrane full path (see wcscpy).
    if runtime_policy::strict_passthrough_active() {
        unsafe {
            // The dst-end scan is inherent to wcscat (find the append point); the src
            // side then fuses scan+copy in one pass (no scan_w_string + interposed
            // memcpy round trip — the wcscpy fix).
            let (dst_len, _) = scan_w_string(dst.cast_const(), None);
            wide_fused_copy(dst.add(dst_len), src);
        }
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

/// True iff a 32-byte read at `addr` stays within `addr`'s own 4096-byte page,
/// so a wide dual-pointer vector load cannot fault past a NUL near a page
/// boundary. Neither `s1` nor `s2` can be pre-aligned, hence the per-read guard.
#[inline(always)]
fn wide32_read_within_page(addr: usize) -> bool {
    (addr & 0xFFF) <= 0x1000 - 32
}

/// Fused portable-SIMD wide-string compare: 8 `u32` (wchar_t) lanes per 32-byte
/// window. `bound` is in elements. Returns `(result, span_elements, hit_limit)`:
/// `result` is the signed difference (`-1`/`0`/`+1`, wchar_t compared as i32) at
/// the first differing element or shared NUL; `hit_limit` means `bound` elements
/// compared equal with no NUL. Equal-and-NUL-free windows advance 8 elements;
/// others resolve element-wise (identical to the scalar loop). Wide reads are
/// page-cross guarded (dual pointers can't be pre-aligned). 8 lanes per window
/// amortise the guard cost — unlike a 2-lane u64-SWAR, which lost to scalar.
unsafe fn scan_wcscmp_simd(s1: *const u32, s2: *const u32, bound: usize) -> (c_int, usize, bool) {
    const WLANES: usize = 8;
    let zv = Simd::<u32, WLANES>::splat(0);
    let mut i = 0usize;
    loop {
        // 128-byte (32-wchar) unrolled fast path: the 32B/iter loop below re-ran the dual
        // page-guard + bounds check every 8 wchars — ~2.2x slower than glibc for long equal
        // wide strings (measured wcscmp_sweep, grows with n ⇒ per-element throughput, not
        // splits). One guard covers the full 128B window (both pointers in-page), four
        // 8-lane `(ne | eq-zero)` masks OR-combined so the all-equal case takes a SINGLE
        // branch and advances 32 wchars; a flagged window scalar-resolves the first
        // differing-or-NUL element (needed for the sign). Byte-identical to the 8-lane path.
        if i + 32 <= bound
            && (s1 as usize + i * 4) & 0xFFF <= 0x1000 - 128
            && (s2 as usize + i * 4) & 0xFFF <= 0x1000 - 128
        {
            // SAFETY: the 128B window [i, i+32) wchars stays within both pages and bound.
            let flag = |off: usize| -> u64 {
                let a = Simd::<u32, WLANES>::from_array(unsafe {
                    core::ptr::read(s1.add(i + off).cast::<[u32; WLANES]>())
                });
                let b = Simd::<u32, WLANES>::from_array(unsafe {
                    core::ptr::read(s2.add(i + off).cast::<[u32; WLANES]>())
                });
                (a.simd_ne(b) | a.simd_eq(zv)).to_bitmask()
            };
            let f0 = flag(0);
            let f1 = flag(8);
            let f2 = flag(16);
            let f3 = flag(24);
            if f0 | f1 | f2 | f3 == 0 {
                i += 32;
                continue;
            }
            let base = if f0 != 0 {
                i
            } else if f1 != 0 {
                i + 8
            } else if f2 != 0 {
                i + 16
            } else {
                i + 24
            };
            for j in 0..WLANES {
                // SAFETY: base+j < i+32 <= bound; within the just-read in-page window.
                let a = unsafe { *s1.add(base + j) };
                let b = unsafe { *s2.add(base + j) };
                if a != b {
                    return (
                        if (a as i32) < (b as i32) { -1 } else { 1 },
                        base + j + 1,
                        false,
                    );
                }
                if a == 0 {
                    return (0, base + j + 1, false);
                }
            }
            i += 32; // defensive: a flagged window always returns above.
            continue;
        }
        if i + WLANES <= bound
            && wide32_read_within_page(s1.wrapping_add(i) as usize)
            && wide32_read_within_page(s2.wrapping_add(i) as usize)
        {
            // SAFETY: both 32-byte reads stay within their pages and within bound.
            // Raw array loads (not Rust slices over C memory) mirror wcschr.
            let va = Simd::<u32, WLANES>::from_array(unsafe {
                core::ptr::read(s1.add(i).cast::<[u32; WLANES]>())
            });
            let vb = Simd::<u32, WLANES>::from_array(unsafe {
                core::ptr::read(s2.add(i).cast::<[u32; WLANES]>())
            });
            if va == vb && !va.simd_eq(zv).any() {
                i += WLANES;
                continue;
            }
            for j in 0..WLANES {
                // SAFETY: i+j < bound.
                let a = unsafe { *s1.add(i + j) };
                let b = unsafe { *s2.add(i + j) };
                if a != b {
                    return (
                        if (a as i32) < (b as i32) { -1 } else { 1 },
                        i + j + 1,
                        false,
                    );
                }
                if a == 0 {
                    return (0, i + j + 1, false);
                }
            }
            i += WLANES; // defensive: a flagged window always returns above.
            continue;
        }
        if i >= bound {
            return (0, bound, true);
        }
        // SAFETY: i < bound.
        let a = unsafe { *s1.add(i) };
        let b = unsafe { *s2.add(i) };
        if a != b {
            return (if (a as i32) < (b as i32) { -1 } else { 1 }, i + 1, false);
        }
        if a == 0 {
            return (0, i + 1, false);
        }
        i += 1;
    }
}

/// Benchmark/test hook for [`scan_wcscmp_simd`]. Not part of the public ABI.
///
/// # Safety
/// `s1`/`s2` must be NUL-terminated, or valid for `bound` elements.
#[doc(hidden)]
pub unsafe fn bench_scan_wcscmp_simd(s1: *const u32, s2: *const u32, bound: usize) -> c_int {
    unsafe { scan_wcscmp_simd(s1, s2, bound).0 }
}

// ---------------------------------------------------------------------------
// wcscmp
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcscmp(s1: *const u32, s2: *const u32) -> c_int {
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    // Strict-mode fast path (the DEFAULT deployed mode): strict passthrough does no
    // validation (cmp_bound == None), so the result is exactly the wide-SIMD core
    // compare. Skip decide + observe + known_remaining (byte-identical to the strict
    // full path: scan_wcscmp_simd with no limit), mirroring the narrow `strcmp` and
    // the math/ctype membrane fast paths. The wide-char family was omitted from this
    // optimization, paying a flat ~9-10ns membrane tax per call. Hardened mode keeps
    // the full validating path below.
    if runtime_policy::strict_passthrough_active() {
        let (r, _span, _hit) = unsafe { scan_wcscmp_simd(s1, s2, usize::MAX) };
        return r;
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

    // Fused portable-SIMD wide compare (shared scan_wcscmp_simd), byte-identical
    // to the old scalar element loop. `cmp_bound == None` => no limit; any
    // hit-limit is the membrane bound, so it maps directly to `adverse`.
    let (result, adverse, span) = unsafe {
        let (r, span, hit_limit) = scan_wcscmp_simd(s1, s2, cmp_bound.unwrap_or(usize::MAX));
        (r, hit_limit, span)
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

    // Strict-mode fast path (DEFAULT deployed): strict passthrough has no membrane
    // clamp (`cmp_bound == Some(n)`, `adverse` false), byte-identical to the strict
    // full path (core compare bounded by `n`); skips the decide + observe tax.
    if runtime_policy::strict_passthrough_active() {
        let (r, _span, _hit) = unsafe { scan_wcscmp_simd(s1, s2, n) };
        return r;
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

    // Fused portable-SIMD wide compare (shared scan_wcscmp_simd); `cmp_bound` is
    // always Some here. `adverse` only when the limit came from a membrane clamp
    // (not n), matching the old scalar loop exactly.
    let limit = cmp_bound.expect("wcsncmp cmp_bound is always Some");
    let (result, adverse, span) = unsafe {
        let (r, span, hit_limit) = scan_wcscmp_simd(s1, s2, limit);
        let adverse_local =
            hit_limit && limit < n && (lhs_bound == Some(limit) || rhs_bound == Some(limit));
        (r, adverse_local, span)
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

/// Portable-SIMD scan of a NUL-terminated wide string for the first element equal
/// to `c` OR the terminating NUL. Returns `(index, found_c)`; `c == 0` reports the
/// NUL as a found match (matching `wcschr(s, '\0')`). Probes 8 `u32` lanes at a
/// time with `simd_eq(c) | simd_eq(0)`, resolving the exact element only inside a
/// flagged window. The pointer is aligned to 32 bytes first so each vector load
/// stays within one page and cannot fault past the NUL — the wide analogue of the
/// align-to-8 discipline used by the narrow SWAR scans.
unsafe fn wide_find_or_nul_simd(s: *const u32, c: u32) -> (usize, bool) {
    use std::simd::cmp::SimdOrd;
    const LANES: usize = 8;
    let cv = Simd::<u32, LANES>::splat(c);
    let zv = Simd::<u32, LANES>::splat(0);
    let pb = s as usize;
    // Aligned-load-down + head-mask instead of an element-by-element scalar head
    // (was up to 7 scalar iters to reach 32-byte alignment): load the 8-lane panel
    // containing `s`, mask off lanes before `s`, and resolve in one SIMD step —
    // the same head trick that closed narrow strchr's short-string floor (847363e6e).
    // ~1.4-2.8x faster than the scalar head at small/medium wide strings.
    let align = (pb & 31) >> 2; // elements before the 32-byte boundary (0..=7)
    // SAFETY: `base` is aligned down <= 28 bytes, so it stays in the same mapped page
    // as `s`; the 32-byte load never crosses a page boundary.
    let base = unsafe { s.sub(align) };
    let v0 =
        Simd::<u32, LANES>::from_array(unsafe { core::ptr::read(base.cast::<[u32; LANES]>()) });
    // `min(v ^ c, v)` has a zero lane iff v == c (v^c == 0) OR v == 0 — collapses the
    // two-target (c-or-NUL) detection into a single compare, so the folded tier below
    // can min-combine 4 vectors into one reduction (the wcslen-style kernel).
    let m0 = ((v0 ^ cv).simd_min(v0)).simd_eq(zv).to_bitmask() & !((1u64 << align) - 1);
    if m0 != 0 {
        let pos = m0.trailing_zeros() as usize; // lane within the base window
        // SAFETY: `pos < LANES` within the just-read window.
        let is_c = unsafe { *base.add(pos) } == c;
        return (pos - align, is_c);
    }
    let mut i = LANES - align; // s+i is 32-byte (8-u32) aligned
    loop {
        // Length-escalated folded 4x8 = 32-lane (128-byte) tier: one combined
        // reduction per 128 bytes for the bulk of long wide strings, matching glibc's
        // unrolled wcschr. Gated on `i >= 32` so short strings (already resolved above
        // or in the 32-byte panel) never pay the folded overhead — the escalation
        // guard that kept strchr's folded-128 tier (bd-4rxozm) regression-free.
        // Page-guarded so the 128-byte read never crosses into an adjacent (possibly
        // unmapped) page; a folded hit falls through to the 32-byte/scalar resolve
        // below, which returns the exact first c-or-NUL index unchanged.
        if i >= 32 && (pb + i * 4) & 0xFFF <= 0x1000 - 128 {
            // SAFETY: the 128-byte window stays within the current mapped page.
            let b = unsafe { s.add(i) };
            let x0 = Simd::<u32, LANES>::from_array(unsafe {
                core::ptr::read(b.cast::<[u32; LANES]>())
            });
            let x1 = Simd::<u32, LANES>::from_array(unsafe {
                core::ptr::read(b.add(LANES).cast::<[u32; LANES]>())
            });
            let x2 = Simd::<u32, LANES>::from_array(unsafe {
                core::ptr::read(b.add(2 * LANES).cast::<[u32; LANES]>())
            });
            let x3 = Simd::<u32, LANES>::from_array(unsafe {
                core::ptr::read(b.add(3 * LANES).cast::<[u32; LANES]>())
            });
            let e0 = (x0 ^ cv).simd_min(x0);
            let e1 = (x1 ^ cv).simd_min(x1);
            let e2 = (x2 ^ cv).simd_min(x2);
            let e3 = (x3 ^ cv).simd_min(x3);
            if !e0.simd_min(e1).simd_min(e2.simd_min(e3)).simd_eq(zv).any() {
                i += 4 * LANES;
                continue;
            }
        }
        // SAFETY: `s + i` is 32-byte aligned, so this 32-byte load stays inside
        // the current page; the string is NUL-terminated within a mapped page.
        let v = Simd::<u32, LANES>::from_array(unsafe {
            core::ptr::read(s.add(i).cast::<[u32; LANES]>())
        });
        if (v ^ cv).simd_min(v).simd_eq(zv).any() {
            for j in 0..LANES {
                // SAFETY: within the just-read window; a c-or-NUL exists at/ before j==7.
                let ch = unsafe { *s.add(i + j) };
                if ch == c {
                    return (i + j, true);
                }
                if ch == 0 {
                    return (i + j, false);
                }
            }
        }
        i += LANES;
    }
}

/// Benchmark/test hook for [`wide_find_or_nul_simd`]. Not part of the public ABI.
///
/// # Safety
/// `s` must be a valid NUL-terminated wide string.
#[doc(hidden)]
pub unsafe fn bench_wide_find_or_nul_simd(s: *const u32, c: u32) -> (usize, bool) {
    unsafe { wide_find_or_nul_simd(s, c) }
}

/// Portable-SIMD scan for the last `c` before the first NUL in a wide string.
/// Returns `(last_index, span_including_nul)`. It uses the same aligned
/// c-or-NUL panel discipline as [`wide_find_or_nul_simd`] and only resolves
/// lanes scalar when a panel contains either the target or the terminator.
unsafe fn wide_last_before_nul_simd(s: *const u32, c: u32) -> (Option<usize>, usize) {
    if c == 0 {
        // SAFETY: caller guarantees a valid NUL-terminated string.
        let (idx, _) = unsafe { wide_find_or_nul_simd(s, 0) };
        return (Some(idx), idx.saturating_add(1));
    }

    const LANES: usize = 8;
    let mut last = None;
    let mut i = 0usize;
    let head = ((32 - ((s as usize) & 31)) & 31) / 4;
    while i < head {
        // SAFETY: caller guarantees a valid NUL-terminated string.
        let ch = unsafe { *s.add(i) };
        if ch == c {
            last = Some(i);
        }
        if ch == 0 {
            return (last, i.saturating_add(1));
        }
        i += 1;
    }

    let cv = Simd::<u32, LANES>::splat(c);
    let zv = Simd::<u32, LANES>::splat(0);
    loop {
        // SAFETY: `s + i` is 32-byte aligned, so this 32-byte load stays inside
        // the current page; the string is NUL-terminated within a mapped page.
        let words = unsafe { core::ptr::read(s.add(i).cast::<[u32; LANES]>()) };
        let v = Simd::<u32, LANES>::from_array(words);
        let eqc = v.simd_eq(cv);
        let eqz = v.simd_eq(zv);
        // Cheap skip test: nothing of interest in this 8-lane chunk ⇒ advance a full
        // panel. Only when a `c` or the terminator is present do we extract the exact
        // position(s) from the SIMD bitmasks — NEVER a scalar per-lane rescan. That
        // per-block rescan was what made wcsrchr 3-5x slower than glibc after the host
        // glibc 2.42 bump (the frequent-`c` case rescanned every block scalar); the
        // mask extraction removes it. Measured 1.28-2.35x over the old scan
        // (wcsrchr_fold_ab, in-process, byte-identical (last,span)). A folded 128B tier
        // was tried and lost (frequent-`c` degenerates to whole-string scalar rescan).
        if (eqc | eqz).any() {
            let zm = eqz.to_bitmask();
            if zm != 0 {
                // NUL present: the last `c` (if any) must lie strictly before it.
                let p = zm.trailing_zeros() as usize;
                let cm_before = eqc.to_bitmask() & ((1u64 << p) - 1);
                if cm_before != 0 {
                    last = Some(i + (63 - cm_before.leading_zeros() as usize));
                }
                return (last, i + p + 1);
            }
            // No NUL in this chunk ⇒ a `c` match is present; take its highest lane.
            last = Some(i + (63 - eqc.to_bitmask().leading_zeros() as usize));
        }
        i += LANES;
    }
}

/// Benchmark/test hook for [`wide_last_before_nul_simd`] (the wcsrchr scan).
/// Not part of the public ABI.
///
/// # Safety
/// `s` must be a valid NUL-terminated wide string.
#[doc(hidden)]
pub unsafe fn bench_wide_last_before_nul_simd(s: *const u32, c: u32) -> (Option<usize>, usize) {
    unsafe { wide_last_before_nul_simd(s, c) }
}

// ---------------------------------------------------------------------------
// wcschr
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcschr(s: *const u32, c: u32) -> *mut u32 {
    if s.is_null() {
        return std::ptr::null_mut();
    }

    // Strict-mode fast path (DEFAULT deployed): strict passthrough has `bound ==
    // None`, so this is byte-identical to the `bound.is_none()` branch below.
    // Skips the ~9-10ns decide + observe membrane tax, mirroring narrow `strchr`
    // and the math/ctype fast paths.
    if runtime_policy::strict_passthrough_active() {
        let (idx, found) = unsafe { wide_find_or_nul_simd(s, c) };
        return if found {
            unsafe { s.add(idx) as *mut u32 }
        } else {
            std::ptr::null_mut()
        };
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
        if bound.is_none() {
            // Common path: SIMD scan for `c`-or-NUL (byte-identical to the scalar
            // loop, including c=='\0' returning the terminator).
            let (idx, found) = wide_find_or_nul_simd(s, c);
            if found {
                (s.add(idx) as *mut u32, false, idx.saturating_add(1))
            } else {
                (std::ptr::null_mut(), false, idx.saturating_add(1))
            }
        } else {
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
                    break (std::ptr::null_mut(), false, i.saturating_add(1));
                }
                i += 1;
            }
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

    // Strict-mode fast path (DEFAULT deployed): strict passthrough has `bound ==
    // None`, byte-identical to the `bound.is_none()` branch below; skips the
    // decide + observe membrane tax.
    if runtime_policy::strict_passthrough_active() {
        let (last, _span) = unsafe { wide_last_before_nul_simd(s, c) };
        return last.map_or(std::ptr::null_mut(), |idx| unsafe {
            s.add(idx) as *mut u32
        });
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
        if bound.is_none() {
            let (last, span) = wide_last_before_nul_simd(s, c);
            (
                last.map_or(std::ptr::null_mut(), |idx| s.add(idx) as *mut u32),
                false,
                span,
            )
        } else {
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
/// FUSED wcsstr for a NUL-terminated wide haystack (2 <= needle_len <= 256): the
/// wide analog of the byte `substr_fused` — search the haystack one page-bounded
/// chunk at a time (`wide_core::wcsstr` per window with a `needle_len-1` carry-over),
/// returning at the first match, so an EARLY match never pre-scans the whole
/// haystack. After `FUSED_EARLY_WINDOW` wchars with no match, finish the tail with a
/// single `scan_w_string(None)` + one search (ORIG's shape → absent ~ORIG).
/// Byte-identical to `wide_core::wcsstr` over the full NUL-terminated haystack.
///
/// PAGE-SAFE: each chunk read is bounded to the wchars remaining in the CURRENT
/// (mapped) 4 KiB page (`(4096 - (addr & 0xFFF)) / 4`, exact since wchar_t* is
/// 4-aligned); if no NUL is found before the boundary the string continues, so the
/// next page is mapped. `known_remaining` is unused (the strict path already scans
/// with `None`), so no tracked-buffer bounding is dropped.
///
/// # Safety
/// `haystack` valid NUL-terminated wide string; `needle` readable for `needle_len`
/// wchars with `2 <= needle_len <= 256`.
unsafe fn wcsstr_fused(haystack: *const u32, needle: *const u32, needle_len: usize) -> *mut u32 {
    // SAFETY: needle readable for needle_len wchars (caller contract).
    let ns = unsafe { std::slice::from_raw_parts(needle, needle_len) };
    let n0 = ns[0];
    let mut pos = 0usize; // absolute wchar offset to resume the first-wchar scan
    let mut miss_work = 0usize;
    loop {
        // First occurrence of needle[0] at/after `pos`, or the terminating NUL —
        // ONE page-safe NUL-aware pass (wcschr's scanner; guard-page proven), no
        // separate per-chunk NUL scan (the old chunked path double-scanned).
        // SAFETY: page-safe wide scan.
        let (i, found) = unsafe { wide_find_or_nul_simd(haystack.add(pos), n0) };
        if !found {
            return std::ptr::null_mut(); // NUL before another needle[0]
        }
        let cand = pos + i;
        // Verify needle[1..] at cand+1; stop at first mismatch or NUL (needle has no
        // NUL). Page-safe: reads only up to the NUL, which is mapped.
        let mut k = 1usize;
        let mut matched = true;
        while k < needle_len {
            // SAFETY: cand+k <= wcslen while wchars match, so within the mapped string.
            if unsafe { *haystack.add(cand + k) } != ns[k] {
                matched = false;
                break;
            }
            k += 1;
        }
        if matched {
            return unsafe { haystack.add(cand) as *mut u32 };
        }
        miss_work += needle_len;
        pos = cand + 1;
        // O(n+m) Two-Way bailout once verify work outweighs the scan distance
        // (adversarial common first wchar).
        if miss_work > cand.max(256) {
            // SAFETY: page-safe scan to NUL, then a bounded slice search.
            let (rest, _) = unsafe { scan_w_string(haystack.add(cand), None) };
            let win = unsafe { std::slice::from_raw_parts(haystack.add(cand), rest) };
            return match wide_core::wcsstr(win, ns) {
                Some(idx) => unsafe { haystack.add(cand + idx) as *mut u32 },
                None => std::ptr::null_mut(),
            };
        }
    }
}

pub unsafe extern "C" fn wcsstr(haystack: *const u32, needle: *const u32) -> *mut u32 {
    if haystack.is_null() {
        return std::ptr::null_mut();
    }
    if needle.is_null() {
        return haystack as *mut u32;
    }

    // Strict-mode fast path (DEFAULT deployed): strict passthrough has both bounds
    // == None, so both scans terminate (not adverse) — byte-identical to the strict
    // full body below; skips the decide + observe membrane tax.
    if runtime_policy::strict_passthrough_active() {
        return unsafe {
            let (needle_len, _) = scan_w_string(needle, None);
            if needle_len == 0 {
                return haystack as *mut u32;
            }
            // FUSED page-chunked search — no whole-haystack pre-scan, returns at the
            // first match (mirrors the byte strstr fused path). The strict path already
            // scans with None (no tracked-buffer bound), so nothing is dropped.
            if (2..=256).contains(&needle_len) {
                return wcsstr_fused(haystack, needle, needle_len);
            }
            let (hay_len, _) = scan_w_string(haystack, None);
            if hay_len >= needle_len {
                let hay_slice = std::slice::from_raw_parts(haystack, hay_len);
                let needle_slice = std::slice::from_raw_parts(needle, needle_len);
                match wide_core::wcsstr(hay_slice, needle_slice) {
                    Some(idx) => haystack.add(idx) as *mut u32,
                    None => std::ptr::null_mut(),
                }
            } else {
                std::ptr::null_mut()
            }
        };
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
            // Route to the core wide Two-Way searcher (O(hay+needle)) instead of the
            // old SIMD-prefilter-then-verify / naive double loop, both of which were
            // O(hay_len * needle_len) on adversarial inputs (hay="aaaa…",
            // needle="aaa…c") — measured 16-32x slower than core wcsstr (and a CPU-DoS
            // vector). `hay_len`/`needle_len` already bake in any membrane clamp, so
            // the bounded slices are safe. Byte-identical leftmost match.
            let hay_slice = std::slice::from_raw_parts(haystack, hay_len);
            let needle_slice = std::slice::from_raw_parts(needle, needle_len);
            match wide_core::wcsstr(hay_slice, needle_slice) {
                Some(idx) => {
                    out_local = haystack.add(idx) as *mut u32;
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

    // Strict-mode fast path (DEFAULT deployed): strict passthrough does not clamp
    // (`copy_len == n`), byte-identical to the strict full path; skips the decide +
    // observe membrane tax (~9-10ns/call, see wcscmp).
    if runtime_policy::strict_passthrough_active() {
        // Inline SIMD copy instead of std::ptr::copy (which for a wide u32 copy lowers to
        // the interposed memmove symbol — measured ~34x glibc, 1408ns at n=1024). wmemcpy's
        // C contract is disjoint (memcpy semantics), so the forward wide_copy_n is correct.
        unsafe { wide_copy_n(dst, src, n) };
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

    // Strict-mode fast path (DEFAULT deployed): strict passthrough does not clamp
    // (`copy_len == n`), byte-identical to the strict full path; skips the decide +
    // observe membrane tax. Uses the self-contained overlap-safe move (NOT std::ptr::copy
    // → the buggy frankenlibc memmove symbol, see wide_move_n).
    if runtime_policy::strict_passthrough_active() {
        unsafe { wide_move_n(dst, src, n) };
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
        // Overlap-safe, self-contained (avoids the buggy memmove symbol std::ptr::copy
        // would call — see wide_move_n).
        unsafe {
            wide_move_n(dst, src, copy_len);
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

    // Strict-mode fast path (DEFAULT deployed): strict passthrough does not clamp
    // (`fill_len == n`), byte-identical to the strict full path; skips the decide +
    // observe membrane tax.
    if runtime_policy::strict_passthrough_active() {
        unsafe { std::slice::from_raw_parts_mut(dst, n).fill(c) };
        return dst;
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

    // Strict-mode fast path (DEFAULT deployed): strict passthrough has no clamp
    // (`cmp_len == n`), byte-identical to the strict body — SIMD core wmemcmp over
    // exactly `n` elements. Skips the decide + observe membrane tax.
    if runtime_policy::strict_passthrough_active() {
        return unsafe {
            let a = std::slice::from_raw_parts(s1, n);
            let b = std::slice::from_raw_parts(s2, n);
            frankenlibc_core::string::wide::wmemcmp(a, b, n)
        };
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

    // Delegate to the SIMD core wmemcmp (unrolled Simd<u32,N> equality panels)
    // instead of the scalar element loop; identical signed-wchar_t semantics
    // (-1/0/1 on the first differing element, all-equal => 0).
    let result = unsafe {
        let a = std::slice::from_raw_parts(s1, cmp_len);
        let b = std::slice::from_raw_parts(s2, cmp_len);
        frankenlibc_core::string::wide::wmemcmp(a, b, cmp_len)
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

    // Strict-mode fast path (DEFAULT deployed): strict passthrough does not clamp
    // (`repair` false → `scan_len == n`), so this is byte-identical to the strict
    // full path (core wmemchr over exactly `n` elements); skips the decide +
    // observe membrane tax (~9-10ns/call, see wcscmp).
    if runtime_policy::strict_passthrough_active() {
        return unsafe {
            let slice = std::slice::from_raw_parts(s, n);
            match frankenlibc_core::string::wide::wmemchr(slice, c, n) {
                Some(i) => s.add(i) as *mut u32,
                None => std::ptr::null_mut(),
            }
        };
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

    // Delegate to the SIMD core wmemchr (64-lane Simd<u32> panels + O(1) lane resolve)
    // instead of a scalar `iter().position()` element loop — identical first-match
    // semantics, but ~10x faster on a wide scan (matches the wmemcmp delegation above).
    let result = unsafe {
        let slice = std::slice::from_raw_parts(s, scan_len);
        match frankenlibc_core::string::wide::wmemchr(slice, c, scan_len) {
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

    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict
    // unbounded append below — append `min(strlen(src), n)` wchars at dst's end,
    // then NUL-terminate. Skips the ~640ns wide WRITE membrane full path (see wcscpy).
    if runtime_policy::strict_passthrough_active() {
        unsafe {
            // Append point (inherent dst-end scan), then FUSE the bounded src scan+copy in
            // one pass (128B tier) instead of the scan_w_string(Some(n)) + wide_copy_n
            // two-pass (two reads; 8-lane copy for n<1024). wide_fused_ncopy copies the
            // min(strlen(src),n) real chars and returns the count; we NUL-terminate. Byte-
            // identical; same fused kernel measured 1.03-2.34x for wcsncpy (wcsncpy_fused_ab).
            let (dst_len, _) = scan_w_string(dst.cast_const(), None);
            let copy_len = wide_fused_ncopy(dst.add(dst_len), src, n);
            *dst.add(dst_len + copy_len) = 0;
        }
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

    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict body
    // (repair=false → bound None → scan s, malloc(len+1), copy, NUL). Skips decide +
    // observe. Mirrors narrow `strdup` + `wcscpy` fast paths. (malloc dominates, so the
    // margin is smaller than the pure-scan fns, but wcsdup is hot in wide code.)
    if runtime_policy::strict_passthrough_active() {
        return unsafe {
            let (len, _) = scan_w_string(s, None);
            let ptr = crate::malloc_abi::malloc((len + 1) * 4) as *mut u32;
            if ptr.is_null() {
                return std::ptr::null_mut();
            }
            // Inline SIMD copy, not copy_nonoverlapping (wide u32 copy -> interposed
            // memcpy symbol, ~2 GB/s / up to 34x glibc at large len). `len` is already
            // known from the scan above, so wide_copy_n copies exactly it.
            wide_copy_n(ptr, s, len);
            *ptr.add(len) = 0;
            ptr
        };
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

        // Route through FrankenLibC's allocator entrypoint so replacement
        // builds do not retain a direct host libc allocation edge.
        let ptr = crate::malloc_abi::malloc(alloc_bytes) as *mut u32;
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

/// O(1)-lookup wide character set for wcsspn/wcscspn/wcspbrk. A 128-entry ASCII table
/// gives O(1) membership for the common ASCII case; non-ASCII set members fall back to a
/// linear scan of the original slice. Replaces the per-character linear `set.contains(c)`
/// (O(s_len * set_len)) — measured 1.8-4.5x over the scalar loop and 2.6-6.7x over glibc.
struct WideCharSet<'a> {
    ascii: [bool; 128],
    rest: &'a [u32],
    has_nonascii: bool,
}

impl<'a> WideCharSet<'a> {
    /// # Safety
    /// `set` must be valid for `len` elements.
    unsafe fn new(set: *const u32, len: usize) -> Self {
        let mut ascii = [false; 128];
        let mut has_nonascii = false;
        for k in 0..len {
            let a = unsafe { *set.add(k) };
            if a < 128 {
                ascii[a as usize] = true;
            } else {
                has_nonascii = true;
            }
        }
        let rest = unsafe { std::slice::from_raw_parts(set, len) };
        Self {
            ascii,
            rest,
            has_nonascii,
        }
    }

    #[inline]
    fn contains(&self, c: u32) -> bool {
        if c < 128 {
            self.ascii[c as usize]
        } else {
            self.has_nonascii && self.rest.contains(&c)
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsspn(s: *const u32, accept: *const u32) -> usize {
    if s.is_null() || accept.is_null() {
        return 0;
    }

    // Strict-mode fast path (DEFAULT deployed): strict passthrough has both bounds
    // == None, byte-identical to the strict full body below; skips the decide +
    // observe membrane tax (~9-10ns/call, see wcscmp).
    if runtime_policy::strict_passthrough_active() {
        return unsafe {
            let (accept_len, _) = scan_w_string(accept, None);
            let set = WideCharSet::new(accept, accept_len);
            let (s_len, _) = scan_w_string(s, None);
            let mut count = 0usize;
            for i in 0..s_len {
                if set.contains(*s.add(i)) {
                    count += 1;
                } else {
                    break;
                }
            }
            count
        };
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
        let set = WideCharSet::new(accept, accept_len);
        let (s_len, _) = scan_w_string(s, s_bound);
        let mut count = 0usize;
        for i in 0..s_len {
            if set.contains(*s.add(i)) {
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

    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict full
    // body below; skips the decide + observe membrane tax.
    if runtime_policy::strict_passthrough_active() {
        return unsafe {
            let (reject_len, _) = scan_w_string(reject, None);
            let set = WideCharSet::new(reject, reject_len);
            let (s_len, _) = scan_w_string(s, None);
            let mut count = 0usize;
            for i in 0..s_len {
                if set.contains(*s.add(i)) {
                    break;
                }
                count += 1;
            }
            count
        };
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
        let set = WideCharSet::new(reject, reject_len);
        let (s_len, _) = scan_w_string(s, s_bound);
        let mut count = 0usize;
        for i in 0..s_len {
            if set.contains(*s.add(i)) {
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

    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict full
    // body below; skips the decide + observe membrane tax.
    if runtime_policy::strict_passthrough_active() {
        return unsafe {
            let (accept_len, _) = scan_w_string(accept, None);
            let set = WideCharSet::new(accept, accept_len);
            let (s_len, _) = scan_w_string(s, None);
            let mut found: *mut u32 = std::ptr::null_mut();
            for i in 0..s_len {
                if set.contains(*s.add(i)) {
                    found = s.add(i) as *mut u32;
                    break;
                }
            }
            found
        };
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
        let set = WideCharSet::new(accept, accept_len);
        let (s_len, _) = scan_w_string(s, s_bound);
        let mut found: *mut u32 = std::ptr::null_mut();
        let mut work = s_len;
        for i in 0..s_len {
            if set.contains(*s.add(i)) {
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

    // Strict-mode fast path (DEFAULT deployed): byte-identical to the full body's
    // delim scan + skip-leading/find-end tokenize + `*save_ptr` update, but skips the
    // WRITE decide + observe membrane (the wide write family is ~655ns/call). Strict =
    // glibc semantics (no clamp), so the in-place NUL write is unchanged; hardened mode
    // keeps the full validating path below.
    if runtime_policy::strict_passthrough_active() {
        return unsafe {
            // Unbounded page-safe delim scan (valid delim is NUL-terminated), skipping
            // the per-token known_remaining touch — matches narrow strtok/strsep + the
            // wcslen fast path. (wcstok's delim-rejection test is #[ignore]'d / hardened
            // only.)
            let (delim_len, delim_terminated) = scan_w_string(delim, None);
            if !delim_terminated {
                return std::ptr::null_mut();
            }
            let delims = WideCharSet::new(delim, delim_len);
            let mut pos = start;
            loop {
                let ch = *pos;
                if ch == 0 {
                    *save_ptr = pos;
                    return std::ptr::null_mut();
                }
                if !delims.contains(ch) {
                    break;
                }
                pos = pos.add(1);
            }
            let token_start = pos;
            loop {
                let ch = *pos;
                if ch == 0 {
                    *save_ptr = pos;
                    break;
                }
                if delims.contains(ch) {
                    *pos = 0;
                    *save_ptr = pos.add(1);
                    break;
                }
                pos = pos.add(1);
            }
            token_start
        };
    }

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

    let delim_bound = known_remaining(delim as usize).map(bytes_to_wchars);
    let (delim_len, delim_terminated) = unsafe { scan_w_string(delim, delim_bound) };
    if !delim_terminated {
        runtime_policy::observe(ApiFamily::StringMemory, decision.profile, 8, true);
        return std::ptr::null_mut();
    }
    // O(1)-membership delimiter set (ASCII table + non-ASCII fallback) instead of a
    // per-char linear `delim_slice.contains(ch)` in both scan loops below — O(token_len *
    // delim_len) → O(token_len). Same lever as wcsspn (561d9d238).
    let delims = unsafe { WideCharSet::new(delim, delim_len) };

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
            if !delims.contains(ch) {
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
            if delims.contains(ch) {
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
        return 0; // state query: stateless encoding (returns 0)
    }
    if n == 0 {
        // Zero bytes cannot constitute a complete multibyte character.
        return -1;
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
        return 0; // state query: stateless encoding (returns 0)
    }
    if n == 0 {
        // Zero bytes cannot constitute a complete multibyte character.
        return -1;
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
    // glibc's UTF-8 MB_CUR_MAX is 6 (a historical size), so callers size the
    // destination for up to 6 bytes — but the codec itself is RFC 3629, i.e.
    // `wchar_core::wctomb` rejects surrogates and code points above U+10FFFF and
    // never emits more than 4 bytes (verified against glibc in
    // tests/conformance_diff_mbtowc_wctomb.rs).
    let buf = unsafe { std::slice::from_raw_parts_mut(s, 6) };
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
    let src_len = match unsafe { scan_known_multibyte_string(src.cast()) } {
        Some(src_len) => src_len,
        None => {
            unsafe { set_abi_errno(libc::EILSEQ) };
            return usize::MAX;
        }
    };
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
    let wlen = match unsafe { scan_known_wide_string(src) } {
        Some(wlen) => wlen,
        None => {
            unsafe { set_abi_errno(libc::EILSEQ) };
            return usize::MAX;
        }
    };
    let src_slice = unsafe { std::slice::from_raw_parts(src, wlen + 1) }; // include NUL
    if dst.is_null() {
        // Count mode: SIMD-sum the UTF-8 byte length over the char window (was a
        // scalar per-char `wctomb` length loop). Byte-identical — `wcs_encoded_len`
        // returns the same total and the same `None`-at-first-unrepresentable-char.
        return match wchar_core::wcs_encoded_len(&src_slice[..wlen]) {
            Some(count) => count,
            None => usize::MAX,
        };
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

// [End of wchar string functions]

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

    // Strict-mode fast path (DEFAULT deployed): strict passthrough gates the
    // `known_remaining` clamp on `repair` (false in strict) → `limit == maxlen`,
    // byte-identical to the strict full body (bounded wide NUL scan). Skips the
    // decide + observe membrane tax. (Wide analog of the strnlen fast path; unlike
    // `wcslen`, wcsnlen does NOT honor `known` ungated.)
    if runtime_policy::strict_passthrough_active() {
        return unsafe {
            wide_core::wcsnlen(std::slice::from_raw_parts(s as *const u32, maxlen), maxlen)
        };
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
    let mut tmp = [0u8; 6];

    // Stateless UTF-8 locale: resetting state is equivalent to encoding NUL.
    if s.is_null() {
        return 1;
    }

    // ASCII fast path: a wchar in 0x00..=0x7F encodes to the single byte equal to
    // its value in every supported locale (C and UTF-8 agree), so skip the encoder
    // and scratch buffer. `wc as u32` keeps negative wchars off this path.
    if (wc as u32) < 0x80 {
        // SAFETY: caller guarantees `s` points to writable storage for >= 1 byte.
        unsafe { *(s as *mut u8) = wc as u8 };
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
    ps: *mut std::ffi::c_void,
) -> usize {
    const MB_INCOMPLETE: usize = usize::MAX - 1;

    // s == NULL resets the conversion state (equivalent to mbrtowc(NULL,"",1,ps)).
    if s.is_null() {
        if !ps.is_null() {
            // SAFETY: ps is a valid mbstate_t per the C contract.
            unsafe { mbstate_partial_clear(ps) };
        }
        if !pwc.is_null() {
            // SAFETY: pwc is caller-provided out pointer.
            unsafe { *pwc = 0 };
        }
        return 0;
    }
    if n == 0 {
        return MB_INCOMPLETE;
    }

    // ASCII fast path: when there is NO pending partial sequence — `ps` is null OR holds
    // an empty state (count byte == 0) — a byte < 0x80 is a complete single-byte character
    // whose value equals its codepoint in every supported locale (C and UTF-8 agree on
    // 0x00..=0x7F). Skip the partial-state reassembly buffer and the RFC-3629 decoder.
    // Byte-identical to the full path: with an empty state the load is a no-op, ASCII
    // creates no partial, and clearing an already-empty state is a no-op. Extending this
    // beyond the `ps.is_null()` case is the common stateful hot path (partials only occur
    // at buffer boundaries), where it was previously paying load+copy+decode+clear.
    let no_pending = ps.is_null() || unsafe { *(ps as *const u8) } == 0;
    if no_pending {
        // SAFETY: caller guarantees `s` points to at least `n` (>= 1) bytes.
        let b0 = unsafe { *(s as *const u8) };
        if b0 < 0x80 {
            if !pwc.is_null() {
                // SAFETY: pwc is a caller-provided out pointer.
                unsafe { *pwc = b0 as libc::wchar_t };
            }
            return if b0 == 0 { 0 } else { 1 };
        }
    }

    // Reassemble any partial multibyte sequence stored in `ps` from a previous
    // call (POSIX requires resuming an incomplete sequence across calls), then
    // append up to a full char's worth of the new bytes. When there is NO pending
    // partial (the common case — `no_pending`, reused from the ASCII probe above),
    // decode DIRECTLY from `s`: skip the mbstate load and the reassembly-buffer copy
    // (nothing to reassemble). Byte-identical to the buffered path.
    let mut buf = [0u8; 8];
    let (decode_slice, pcount): (&[u8], usize) = if no_pending {
        // SAFETY: caller guarantees `s` points to at least `n` (>= n.min(8)) bytes.
        (
            unsafe { std::slice::from_raw_parts(s as *const u8, n.min(8)) },
            0,
        )
    } else {
        // SAFETY: ps is a valid mbstate_t per the C contract.
        let pc = unsafe { mbstate_partial_load(ps, &mut buf) };
        let take = n.min(8 - pc);
        // SAFETY: caller guarantees `s` points to at least `n` (>= take) bytes.
        let new_bytes = unsafe { std::slice::from_raw_parts(s as *const u8, take) };
        buf[pc..pc + take].copy_from_slice(new_bytes);
        (&buf[..pc + take], pc)
    };
    let total = decode_slice.len();

    // RFC 3629-strict decode: `Incomplete` (truncated-but-valid prefix) ->
    // accumulate and return (size_t)-2; `Invalid` -> EILSEQ. The decoder is the
    // single source of truth shared with mbtowc and the conformance harness.
    match wchar_core::utf8_decode_step(decode_slice) {
        wchar_core::Utf8Step::Char { wc, len } => {
            // `len` is the whole char length; bytes consumed FROM THIS CALL are
            // the ones beyond what `ps` already held.
            let from_call = len - pcount;
            // Only clear when a partial was actually consumed; an empty state (the
            // `no_pending`/`pcount == 0` path) is already clear, so the write is skipped.
            if !ps.is_null() && pcount > 0 {
                // SAFETY: ps is a valid mbstate_t per the C contract.
                unsafe { mbstate_partial_clear(ps) };
            }
            if !pwc.is_null() {
                // SAFETY: pwc is caller-provided out pointer.
                unsafe { *pwc = wc as libc::wchar_t };
            }
            // A NUL wide character yields a return of 0 per POSIX.
            if wc == 0 { 0 } else { from_call }
        }
        wchar_core::Utf8Step::Incomplete => {
            // Still a partial sequence: absorb the new bytes into `ps`. A valid
            // UTF-8 prefix is at most 5 bytes short of a 6-byte char (the
            // obsolete RFC 2279 forms fl decodes for C.UTF-8 parity), and an
            // `Incomplete` prefix never exceeds 5 bytes, so the partial region
            // ([0..6]) always has room.
            if !ps.is_null() && total <= 5 {
                // SAFETY: ps is a valid mbstate_t per the C contract.
                unsafe { mbstate_partial_store(ps, decode_slice) };
            }
            MB_INCOMPLETE
        }
        wchar_core::Utf8Step::Invalid => {
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

    let src_len = match unsafe { scan_known_multibyte_string(src_ptr) } {
        Some(src_len) => src_len,
        None => {
            // SAFETY: setting thread-local errno through libc ABI helper.
            unsafe { set_abi_errno(libc::EILSEQ) };
            return usize::MAX;
        }
    };
    let src_len_with_nul = src_len.saturating_add(1);
    // SAFETY: bounded by strlen + NUL.
    let src_bytes = unsafe { std::slice::from_raw_parts(src_ptr as *const u8, src_len_with_nul) };

    // Count-only mode.
    if dst.is_null() {
        let mut i = 0usize;
        let mut count = 0usize;
        while i < src_bytes.len() {
            // SIMD fast-forward the leading ASCII run (each ASCII byte is one
            // wide char), then resolve the NUL / multibyte boundary scalar-side.
            let k = wchar_core::ascii_prefix_len(&src_bytes[i..]);
            i += k;
            count += k;
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
        // SIMD fast-forward: widen the leading ASCII run straight into `dst`,
        // a vector at a time, then resolve the NUL / dest-full / multibyte
        // boundary with the unchanged scalar logic below.
        let k = wchar_core::mbs_ascii_prefix(&mut dst_slice[written..], &src_bytes[i..]);
        i += k;
        written += k;
        // Destination-full is checked BEFORE the terminating NUL: when exactly
        // `len` wide chars have been produced and the next source byte is the
        // NUL, glibc treats the stop as len-limited — it returns the count and
        // leaves *src pointing AT the NUL (one more call needed), rather than
        // consuming the NUL and nulling *src. Checking NUL first would wrongly
        // report completion. (bd-2g7oyh.185)
        if written >= dst_slice.len() {
            // SAFETY: src is non-null and points to caller-owned pointer storage.
            unsafe { *src = src_ptr.add(i) };
            return written;
        }
        if src_bytes[i] == 0 {
            // Room is guaranteed here (written < len), so store the terminator.
            dst_slice[written] = 0;
            // SAFETY: src is non-null and points to caller-owned pointer storage.
            unsafe { *src = std::ptr::null() };
            return written;
        }
        match wchar_core::mbtowc(&src_bytes[i..]) {
            Some((wc, used)) => {
                dst_slice[written] = wc;
                written += 1;
                i += used;
            }
            None => {
                // *src points at the START of the offending multibyte character
                // (the POSIX-specified position). glibc's exact byte differs in
                // a len-dependent, internally-inconsistent way on malformed input
                // (it reports the breaking byte at len==1 but the char start at
                // len>=2 for the same input) — FrankenLibC stays consistent and
                // does not mirror that quirk. (bd-2g7oyh.185)
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

    let src_len = match unsafe { scan_known_wide_string(src_ptr as *const u32) } {
        Some(src_len) => src_len,
        None => {
            unsafe { set_abi_errno(libc::EILSEQ) };
            return usize::MAX;
        }
    };
    // SAFETY: include terminating NUL.
    let src_slice = unsafe { std::slice::from_raw_parts(src_ptr as *const u32, src_len + 1) };

    // Count-only mode: SIMD-sum the UTF-8 byte length over the char window
    // (`src_slice[..src_len]` excludes the terminating NUL) — was a scalar
    // per-char loop. Byte-identical: `wcs_encoded_len` returns the same total and
    // the same EILSEQ at the first unrepresentable char.
    if dst.is_null() {
        return match wchar_core::wcs_encoded_len(&src_slice[..src_len]) {
            Some(bytes) => bytes,
            None => {
                // SAFETY: setting thread-local errno through libc ABI helper.
                unsafe { set_abi_errno(libc::EILSEQ) };
                usize::MAX
            }
        };
    }

    // SAFETY: caller guarantees writable destination of at least `len` bytes.
    let dst_slice = unsafe { std::slice::from_raw_parts_mut(dst as *mut u8, len) };
    let mut written = 0usize;
    let mut idx = 0usize;
    while idx < src_len {
        // SIMD fast-forward: encode the leading run of whole clean windows (ASCII
        // + 2/3/4-byte, gated) straight into `dst`, then resolve the dst-full /
        // multibyte boundary with the unchanged scalar logic below. `chars` (wide
        // chars consumed) and `bytes` (output bytes written) differ for multibyte,
        // so advance the two cursors independently. Bounded to `src_len` so the
        // terminating NUL is never consumed here. The helper only emits whole
        // validated windows, so this stays byte-for-byte identical to a per-char
        // `wctomb` loop — the same lever `wcstombs` uses — now vectorising
        // multibyte runs, not just the ASCII prefix.
        let (chars, bytes) =
            wchar_core::wcs_simd_prefix(&mut dst_slice[written..], &src_slice[idx..src_len]);
        idx += chars;
        written += bytes;
        if idx >= src_len {
            break;
        }
        // Stop when the destination is already full BEFORE evaluating the next
        // character: glibc reports the len-limit (return count, *src at the next
        // char) rather than an EILSEQ from a subsequent un-encodable wchar that
        // would never have been written anyway. (bd-2g7oyh.185)
        if written >= dst_slice.len() {
            // SAFETY: src is non-null and points to caller-owned pointer storage.
            unsafe { *src = src_ptr.add(idx) };
            return written;
        }
        let wc = src_slice[idx];
        let mut tmp = [0u8; 6];
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

// wide_is_space, wide_digit_value, wide_is_ascii_hexdigit,
// parse_wide_signed, parse_wide_unsigned all moved to
// frankenlibc_core::stdlib::conversion (wcstol_impl / wcstoul_impl).
// The wcstol / wcstoul abi shims below call the core functions
// directly.

/// Stack buffer size for the ASCII projection used by the wide float/int parsers. Covers
/// every realistic numeric string (even `0.` + ~500 digits) so the common case does ZERO
/// heap allocation; pathologically long inputs fall back to `heap`.
const WIDE_ASCII_STACK: usize = 512;

/// Initial bounded-scan window for the wide float parsers. Any non-pathological numeric string
/// (the longest normal f64 literal `-1.7976931348623157e+308` is 24 chars; hex floats similar)
/// fits within this, so the common case scans/projects O(window) not O(buffer). Numbers
/// (or leading-whitespace runs) that fill the whole window trigger a one-shot unbounded re-scan
/// in `wide_parse_float`, so correctness holds for arbitrarily long inputs.
const WIDE_FLOAT_SCAN: usize = 32;

/// Bound on the numeric-token scan for the wide integer parsers (`wide_numeric_token_len`).
/// Real tokens end far sooner (the scan stops at the first non-numeric char); this only caps a
/// pathologically long all-alnum run, which triggers a one-shot unbounded re-scan when it is a
/// genuine number. 512 covers e.g. base-2 u64 (64 digits) with generous headroom.
const WIDE_INT_SCAN: usize = 512;

/// Length of the leading run that could belong to a C numeric token: ASCII whitespace (skipped
/// by the parser) then a body of alphanumerics (digits in any base 2-36, plus inf/nan letters)
/// and the punctuation a number may contain (`+ - . ( )` — signs, radix point, `nan(seq)`
/// parens; `x`/`p` are letters). Stops at the first char outside that set (or NUL), returning
/// `(len, hit_bound)`. Deliberately OVER-inclusive: the parser returns the exact `consumed`, so
/// scanning a couple extra chars is harmless — the point is to be O(token), NOT O(buffer) like
/// the old `scan_w_string(None)` (which made a number in a long tail 2-10x slower than glibc).
unsafe fn wide_numeric_token_len(nptr: *const u32, bound: usize) -> (usize, bool) {
    let mut i = 0usize;
    // Leading ASCII whitespace (space, \t \n \v \f \r).
    while i < bound {
        let c = unsafe { *nptr.add(i) };
        if matches!(c, 0x09..=0x0d | 0x20) {
            i += 1;
        } else {
            break;
        }
    }
    // Numeric-token body.
    while i < bound {
        let c = unsafe { *nptr.add(i) };
        if c == 0 {
            return (i, false);
        }
        let in_body = c < 0x80 && {
            let b = c as u8;
            b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.' | b'(' | b')')
        };
        if in_body {
            i += 1;
        } else {
            return (i, false);
        }
    }
    (i, true) // hit the bound without a terminator
}

/// Scan a bounded float prefix. After the token has started, ASCII whitespace proves the
/// token boundary, so include one delimiter and stop instead of paying for the rest of a
/// long buffer tail.
unsafe fn scan_w_float_window(nptr: *const u32, limit: usize) -> (usize, bool) {
    let mut len = 0usize;
    let mut token_started = false;
    while len < limit {
        // SAFETY: caller promises a readable wide string; this bounded scanner reads at most
        // `limit` wide chars before returning.
        let wc = unsafe { *nptr.add(len) };
        if wc == 0 {
            return (len, true);
        }
        if wc > 0x7f {
            return (len, false);
        }
        let b = wc as u8;
        if !token_started {
            token_started = !b.is_ascii_whitespace();
        } else if b.is_ascii_whitespace() {
            return (len + 1, false);
        }
        len += 1;
    }
    (len, false)
}

/// Project the leading ASCII float prefix of `s` as NUL-terminated bytes, WITHOUT a per-call
/// heap allocation for the common short-numeric case. ASCII whitespace after the token has
/// started cannot extend a C float token, so it is left out of the projected parser input.
/// `stack` and `heap` must outlive the returned slice.
fn project_wide_ascii_into<'a>(
    s: &[u32],
    stack: &'a mut [u8; WIDE_ASCII_STACK],
    heap: &'a mut Vec<u8>,
) -> &'a [u8] {
    let mut n = 0usize;
    let mut token_started = false;
    while n < s.len() && s[n] <= 0x7f {
        let b = s[n] as u8;
        if !token_started {
            token_started = !b.is_ascii_whitespace();
        } else if b.is_ascii_whitespace() {
            break;
        }
        n += 1;
    }
    if n + 1 <= WIDE_ASCII_STACK {
        for i in 0..n {
            stack[i] = s[i] as u8;
        }
        stack[n] = 0;
        &stack[..=n]
    } else {
        heap.clear();
        heap.reserve(n + 1);
        for &wc in &s[..n] {
            heap.push(wc as u8);
        }
        heap.push(0);
        &heap[..]
    }
}

fn ascii_eq_ignore_case(a: u8, b: u8) -> bool {
    a.eq_ignore_ascii_case(&b)
}

fn starts_with_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len()
        && haystack
            .iter()
            .zip(needle.iter())
            .all(|(&a, &b)| ascii_eq_ignore_case(a, b))
}

fn float_stop_may_extend_at_bound(prefix: &[u8], consumed: usize) -> bool {
    let consumed = consumed.min(prefix.len());
    let mut token_start = 0usize;
    while token_start < prefix.len() && prefix[token_start].is_ascii_whitespace() {
        token_start += 1;
    }
    if token_start < prefix.len() && matches!(prefix[token_start], b'+' | b'-') {
        token_start += 1;
    }
    if token_start >= prefix.len() {
        return true;
    }

    let token = &prefix[token_start..];
    let suffix = &prefix[consumed..];
    if starts_with_ignore_case(token, b"inf")
        && consumed >= token_start + 3
        && suffix.len() < b"inity".len()
        && starts_with_ignore_case(b"inity", suffix)
    {
        return true;
    }
    if starts_with_ignore_case(token, b"nan") && consumed == token_start + 3 {
        return matches!(suffix.first(), Some(b'('))
            && suffix[1..]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'_');
    }

    if suffix.len() <= 2
        && matches!(suffix.first(), Some(b'e' | b'E' | b'p' | b'P'))
        && suffix.get(1).is_none_or(|b| matches!(*b, b'+' | b'-'))
    {
        return true;
    }
    consumed == token_start + 1
        && prefix[token_start] == b'0'
        && matches!(suffix, [b'x' | b'X'] | [b'x' | b'X', b'.'])
}

/// Shared body for the wide float parsers (`wcstod`/`wcstof`). Returns
/// `(value, consumed, is_erange)`; the caller writes `endptr`/`errno`.
///
/// KEY: scans the wide string BOUNDED to `WIDE_FLOAT_SCAN`, not to the NUL. glibc's wcstod
/// reads only the numeric prefix — O(number). fl's old `scan_w_string(None)` + full projection
/// was O(whole buffer), so a short number followed by a long tail (or repeated parsing across a
/// big buffer) was 16-125x slower than glibc (measured wcstod_longbuf_ab). A real number lives
/// in the bounded window; only if it fills the entire all-ASCII window with no NUL (i.e. it may
/// legitimately extend past the bound) do we re-scan unbounded for an exact value/endptr.
unsafe fn wide_parse_float<T: Copy>(
    nptr: *const libc::wchar_t,
    parse: impl Fn(&[u8]) -> (T, usize, bool),
    is_erange: impl Fn(T, &[u8], bool) -> bool,
) -> (T, usize, bool) {
    let mut ascii_stack = [0u8; WIDE_ASCII_STACK];
    let mut ascii_heap: Vec<u8> = Vec::new();
    // SAFETY: bounded scan; reads at most WIDE_FLOAT_SCAN wchars from a valid wide string.
    let (len, term) = unsafe { scan_w_float_window(nptr as *const u32, WIDE_FLOAT_SCAN) };
    // SAFETY: bounded by the measured length.
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u32, len) };
    let projected = project_wide_ascii_into(slice, &mut ascii_stack, &mut ascii_heap);
    let ascii_len = projected.len() - 1; // minus the terminating NUL
    let ascii_prefix = &projected[..ascii_len];
    let (value, consumed, exact) = parse(projected);
    // Extend only when the number MIGHT be truncated by the bound: the whole bounded window
    // was ASCII (projection reached `len`, not stopped early by a non-ASCII char), there was no
    // NUL within the bound (buffer continues), and the first window does not prove the token
    // boundary. Long ASCII tails after a short number stay on the bounded path.
    let need_extend = !term
        && ascii_len == len
        && (consumed == 0
            || consumed >= ascii_len
            || float_stop_may_extend_at_bound(ascii_prefix, consumed));
    let erange_short =
        consumed > 0 && is_erange(value, &projected[..consumed.min(projected.len())], exact);
    if need_extend {
        // SAFETY: unbounded scan of the same valid wide string.
        let (flen, _) = unsafe { scan_w_string(nptr as *const u32, None) };
        // SAFETY: bounded by the measured full length.
        let fslice = unsafe { std::slice::from_raw_parts(nptr as *const u32, flen) };
        let fprojected = project_wide_ascii_into(fslice, &mut ascii_stack, &mut ascii_heap);
        let (v, c, e) = parse(fprojected);
        let erange = c > 0 && is_erange(v, &fprojected[..c.min(fprojected.len())], e);
        return (v, c, erange);
    }
    (value, consumed, erange_short)
}

/// Shared body for the wide integer parsers (`wcstol`/`wcstoul`). Returns the parser's
/// `(value, consumed, status)`; the caller writes `endptr`/`errno` per its own status rules.
///
/// KEY (same as `wide_parse_float`): scans BOUNDED to `WIDE_INT_SCAN`, not to the NUL. The old
/// `scan_w_string(None)` was O(whole buffer) per call — a short integer followed by a long tail
/// was 2-10x slower than glibc (measured wcstol_longbuf_ab), quadratic across a buffer. The
/// integer lives in the bounded window; only if the parse consumes the ENTIRE window with no NUL
/// (it may legitimately extend — 64-digit base-2, long leading-zero/whitespace runs) do we
/// re-scan unbounded for an exact value+endptr.
/// Wide value of an ASCII digit `wc` in `base` (10 or 16), or `None`. Non-ASCII (wc >= 0x80)
/// is never a digit here (glibc's wide int parse only accepts ASCII 0-9/a-f/A-F).
#[inline]
fn wide_digit_value(wc: u32, base: c_int) -> Option<u32> {
    if wc >= 0x80 {
        return None;
    }
    let b = wc as u8;
    let v = match b {
        b'0'..=b'9' => (b - b'0') as u32,
        b'a'..=b'z' => (b - b'a') as u32 + 10,
        b'A'..=b'Z' => (b - b'A') as u32 + 10,
        _ => return None,
    };
    if v < base as u32 { Some(v) } else { None }
}

/// SIGNED single-pass wide integer parse for base 10/16 — the wide analog of
/// `stdlib_abi::parse_strtol_c_string_fast`, replacing the two-pass
/// `wide_numeric_token_len` + `wcstol_impl` (a pre-scan of the token followed by a re-parse
/// of the same chars) that made wcstol/wcstoll ~1.4-2.1x slower than glibc's single pass
/// (wcstol_survey). Byte-identical to `wcstol_impl` for base 10/16 (same whitespace/sign/
/// 0x-prefix/overflow-cutoff logic, mirrored from the deployed narrow fast path); returns
/// `None` for any other base so the caller falls back to the full core parser.
///
/// # Safety
/// `nptr` must point to a valid NUL-terminated wide string.
#[inline]
unsafe fn parse_wcstol_fast(
    nptr: *const u32,
    base: c_int,
) -> Option<(i64, usize, ConversionStatus)> {
    if base != 10 && base != 16 {
        return None;
    }
    let mut i = 0usize;
    // Leading ASCII whitespace (space, \t \n \v \f \r) — matches wcstol_impl's wide_is_space.
    loop {
        let c = unsafe { *nptr.add(i) };
        if matches!(c, 0x09..=0x0d | 0x20) {
            i += 1;
        } else {
            break;
        }
    }
    let mut c = unsafe { *nptr.add(i) };
    let negative = if c == b'-' as u32 {
        i += 1;
        c = unsafe { *nptr.add(i) };
        true
    } else if c == b'+' as u32 {
        i += 1;
        c = unsafe { *nptr.add(i) };
        false
    } else {
        false
    };
    let radix = base as u64;
    // Optional 0x/0X prefix for base 16 (only when a hex digit follows).
    if base == 16 && c == b'0' as u32 {
        let n = unsafe { *nptr.add(i + 1) };
        if n == b'x' as u32 || n == b'X' as u32 {
            let after = unsafe { *nptr.add(i + 2) };
            if wide_digit_value(after, 16).is_some() {
                i += 2;
                c = after;
            }
        }
    }
    let limit = if negative {
        (i64::MAX as u64) + 1
    } else {
        i64::MAX as u64
    };
    let cutoff = limit / radix;
    let cutlim = limit % radix;
    let mut acc = 0u64;
    let mut any_digits = false;
    let mut overflow = false;
    while let Some(digit) = wide_digit_value(c, base) {
        any_digits = true;
        if !overflow {
            if acc > cutoff || (acc == cutoff && digit as u64 > cutlim) {
                overflow = true;
            } else {
                acc = acc * radix + digit as u64;
            }
        }
        i += 1;
        c = unsafe { *nptr.add(i) };
    }
    if !any_digits {
        return Some((0, 0, ConversionStatus::Success));
    }
    if overflow {
        return Some(if negative {
            (i64::MIN, i, ConversionStatus::Underflow)
        } else {
            (i64::MAX, i, ConversionStatus::Overflow)
        });
    }
    let value = if negative {
        if acc == limit {
            i64::MIN
        } else {
            -(acc as i64)
        }
    } else {
        acc as i64
    };
    Some((value, i, ConversionStatus::Success))
}

/// UNSIGNED single-pass wide integer parse for base 10/16 — the wcstoul/wcstoull analog of
/// [`parse_wcstol_fast`], replacing the two-pass `wide_numeric_token_len` + `wcstoul_impl`.
/// Byte-identical to `wcstoul_impl` for base 10/16: same whitespace/sign/0x-prefix handling,
/// the same checked-arithmetic overflow (→ `u64::MAX`, ERANGE), and glibc's `-`-negation
/// (`acc.wrapping_neg()`). Returns `None` for base 0/other → the caller falls back.
///
/// # Safety
/// `nptr` must point to a valid NUL-terminated wide string.
#[inline]
unsafe fn parse_wcstoul_fast(
    nptr: *const u32,
    base: c_int,
) -> Option<(u64, usize, ConversionStatus)> {
    if base != 10 && base != 16 {
        return None;
    }
    let mut i = 0usize;
    loop {
        let c = unsafe { *nptr.add(i) };
        if matches!(c, 0x09..=0x0d | 0x20) {
            i += 1;
        } else {
            break;
        }
    }
    let mut c = unsafe { *nptr.add(i) };
    let negative = if c == b'-' as u32 {
        i += 1;
        c = unsafe { *nptr.add(i) };
        true
    } else if c == b'+' as u32 {
        i += 1;
        c = unsafe { *nptr.add(i) };
        false
    } else {
        false
    };
    if base == 16 && c == b'0' as u32 {
        let n = unsafe { *nptr.add(i + 1) };
        if n == b'x' as u32 || n == b'X' as u32 {
            let after = unsafe { *nptr.add(i + 2) };
            if wide_digit_value(after, 16).is_some() {
                i += 2;
                c = after;
            }
        }
    }
    let radix = base as u64;
    let mut acc = 0u64;
    let mut any_digits = false;
    let mut overflow = false;
    while let Some(digit) = wide_digit_value(c, base) {
        any_digits = true;
        if !overflow {
            match acc
                .checked_mul(radix)
                .and_then(|a| a.checked_add(digit as u64))
            {
                Some(v) => acc = v,
                None => overflow = true,
            }
        }
        i += 1;
        c = unsafe { *nptr.add(i) };
    }
    if !any_digits {
        return Some((0, 0, ConversionStatus::Success));
    }
    if overflow {
        return Some((u64::MAX, i, ConversionStatus::Overflow));
    }
    let value = if negative { acc.wrapping_neg() } else { acc };
    Some((value, i, ConversionStatus::Success))
}

/// Single-pass fast path for `wcstod`/`wcstold` when the token is a PLAIN base-10 integer
/// exactly representable in `f64` (|value| ≤ 2^53): `[ws][sign][digits]` with the stop char
/// NOT continuing the number (`.eExXpP`). Returns `(value, consumed)`; `None` (→ the full
/// `wide_parse_float` path) for anything else — floats, hex, inf/nan, or a magnitude past
/// 2^53. An exact integer is byte-identical to strtod's result and never sets ERANGE, so the
/// caller just writes `endptr` and returns. Skips the scan+ASCII-project+strtod machinery
/// that gave a ~26ns floor even on "0" (glibc fast-paths it to ~11ns; wcstod_survey).
///
/// # Safety
/// `nptr` must point to a valid NUL-terminated wide string.
#[inline]
unsafe fn parse_wcstod_integer_fast(nptr: *const u32) -> Option<(f64, usize)> {
    let mut i = 0usize;
    loop {
        let c = unsafe { *nptr.add(i) };
        if matches!(c, 0x09..=0x0d | 0x20) {
            i += 1;
        } else {
            break;
        }
    }
    let negative = {
        let c = unsafe { *nptr.add(i) };
        if c == b'-' as u32 {
            i += 1;
            true
        } else if c == b'+' as u32 {
            i += 1;
            false
        } else {
            false
        }
    };
    let digit_start = i;
    let mut acc = 0u64;
    loop {
        let c = unsafe { *nptr.add(i) };
        if !(b'0' as u32..=b'9' as u32).contains(&c) {
            break;
        }
        i += 1;
        acc = acc.wrapping_mul(10).wrapping_add((c - b'0' as u32) as u64);
        if acc > (1u64 << 53) {
            return None; // not exactly representable in f64 — take the full path
        }
    }
    if i == digit_start {
        return None; // no digits (sign-only, inf/nan, empty)
    }
    // A stop char that could continue the number means strtod would consume more (float
    // fraction/exponent, or a 0x/0Xp hex float) — defer to the full path for exactness.
    let stop = unsafe { *nptr.add(i) };
    if stop == b'.' as u32
        || stop == b'e' as u32
        || stop == b'E' as u32
        || stop == b'x' as u32
        || stop == b'X' as u32
        || stop == b'p' as u32
        || stop == b'P' as u32
    {
        return None;
    }
    let v = acc as f64;
    Some((if negative { -v } else { v }, i))
}

unsafe fn wide_parse_int<T: Copy>(
    nptr: *const libc::wchar_t,
    base: c_int,
    parse: impl Fn(&[u32], c_int) -> (T, usize, ConversionStatus),
) -> (T, usize, ConversionStatus) {
    // SAFETY: token scan reads at most WIDE_INT_SCAN wchars from a valid wide string.
    let (tlen, hit_bound) = unsafe { wide_numeric_token_len(nptr as *const u32, WIDE_INT_SCAN) };
    // SAFETY: bounded by the measured token length.
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u32, tlen) };
    let (value, consumed, status) = parse(slice, base);
    // The token was cut by the bound only if the scan filled the whole window AND the parse
    // consumed all of it (a genuine >512-char number). Re-scan unbounded for the exact result.
    if hit_bound && consumed >= tlen {
        // SAFETY: unbounded token scan of the same valid wide string.
        let (flen, _) = unsafe { wide_numeric_token_len(nptr as *const u32, usize::MAX) };
        // SAFETY: bounded by the measured full token length.
        let fslice = unsafe { std::slice::from_raw_parts(nptr as *const u32, flen) };
        return parse(fslice, base);
    }
    (value, consumed, status)
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

    // Single-pass fast path for base 10/16 (parse_wcstol_fast); the two-pass
    // wide_numeric_token_len + wcstol_impl fallback handles base 0 and other bases.
    let (value, consumed, status) = unsafe {
        match parse_wcstol_fast(nptr as *const u32, base) {
            Some(r) => r,
            None => wide_parse_int(
                nptr,
                base,
                frankenlibc_core::stdlib::conversion::wcstol_impl,
            ),
        }
    };

    // glibc leaves *endptr untouched on an invalid base (it validates the base
    // before any parsing); every other status writes the consumed position.
    if !endptr.is_null() && status != ConversionStatus::InvalidBase {
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

    // Single-pass fast path for base 10/16 (parse_wcstoul_fast); base 0/other fall back to
    // the two-pass wide_numeric_token_len + wcstoul_impl.
    let (value, consumed, status) = unsafe {
        match parse_wcstoul_fast(nptr as *const u32, base) {
            Some(r) => r,
            None => wide_parse_int(
                nptr,
                base,
                frankenlibc_core::stdlib::conversion::wcstoul_impl,
            ),
        }
    };

    // glibc leaves *endptr untouched on an invalid base (it validates the base
    // before any parsing); every other status writes the consumed position.
    if !endptr.is_null() && status != ConversionStatus::InvalidBase {
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

    // Fast path: a plain integer exactly representable in f64 (see parse_wcstod_integer_fast)
    // skips the scan+project+strtod machinery. Exact ⇒ no ERANGE; just write endptr + return.
    if let Some((value, consumed)) = unsafe { parse_wcstod_integer_fast(nptr as *const u32) } {
        if !endptr.is_null() {
            unsafe { *endptr = (nptr as *mut libc::wchar_t).add(consumed) };
        }
        return value;
    }

    // Bounded scan + zero-alloc projection (see wide_parse_float): O(number), not O(buffer).
    // glibc 2.38+ raises ERANGE on wide float over/underflow — wide_parse_float applies the
    // same rule strtod uses, over the consumed prefix. The projected ASCII is NUL-terminated,
    // so try narrow strtod's short-decimal/exact fast path on it FIRST — it wins exact
    // scientific/decimal tokens (e.g. "-1.5e10" was 1.71x glibc via the slow strtod_impl,
    // now parity/win). It only returns for exactly-representable values (never ERANGE, so
    // erange=false); anything else falls through to the full core parser. Byte-identical:
    // it is the same fast path narrow strtod uses over the same ASCII bytes.
    let (value, consumed, erange) = unsafe {
        wide_parse_float(
            nptr,
            |ascii: &[u8]| match crate::stdlib_abi::parse_strtod_short_decimal_c_string_fast(
                ascii.as_ptr() as *const std::ffi::c_char,
            ) {
                Some((v, c)) => (v, c, false),
                None => frankenlibc_core::stdlib::conversion::strtod_impl(ascii),
            },
            crate::stdlib_abi::strtod_result_is_erange,
        )
    };
    if !endptr.is_null() {
        // SAFETY: consumed is bounded by the parsed prefix length.
        unsafe { *endptr = (nptr as *mut libc::wchar_t).add(consumed) };
    }
    if erange {
        unsafe { set_abi_errno(libc::ERANGE) };
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
        if let Some(_plan) = positional_printf_arg_plan($segments) {
            for _kind in _plan.iter().take($extract_count) {
                match _kind {
                    ValueArgKind::Gp => {
                        if _idx < $extract_count {
                            $buf[_idx] = unsafe { $args.next_arg::<u64>() };
                            _idx += 1;
                        }
                    }
                    ValueArgKind::Fp => {
                        if _idx < $extract_count {
                            $buf[_idx] = unsafe { $args.next_arg::<f64>() }.to_bits();
                            _idx += 1;
                        }
                    }
                }
            }
        } else {
            for seg in $segments {
                if let FormatSegment::Spec(spec) = seg {
                    if spec.width.uses_arg() && _idx < $extract_count {
                        $buf[_idx] = unsafe { $args.next_arg::<u64>() };
                        _idx += 1;
                    }
                    if spec.precision.uses_arg() && _idx < $extract_count {
                        $buf[_idx] = unsafe { $args.next_arg::<u64>() };
                        _idx += 1;
                    }
                    match spec.conversion {
                        b'%' => {}
                        b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {
                            if _idx < $extract_count {
                                $buf[_idx] = unsafe { $args.next_arg::<f64>() }.to_bits();
                                _idx += 1;
                            }
                        }
                        _ => {
                            if _idx < $extract_count {
                                $buf[_idx] = unsafe { $args.next_arg::<u64>() };
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
                    let ptr = $args.next_arg::<*mut i8>();
                    *ptr = *v as i8;
                }
                LengthMod::H => {
                    let ptr = $args.next_arg::<*mut i16>();
                    *ptr = *v as i16;
                }
                LengthMod::L | LengthMod::Ll | LengthMod::J => {
                    let ptr = $args.next_arg::<*mut i64>();
                    *ptr = *v;
                }
                LengthMod::Z | LengthMod::T => {
                    let ptr = $args.next_arg::<*mut isize>();
                    *ptr = *v as isize;
                }
                _ => {
                    let ptr = $args.next_arg::<*mut c_int>();
                    *ptr = *v as c_int;
                }
            },
            ScanValue::UnsignedInt(v) => match $spec.length {
                LengthMod::Hh => {
                    let ptr = $args.next_arg::<*mut u8>();
                    *ptr = *v as u8;
                }
                LengthMod::H => {
                    let ptr = $args.next_arg::<*mut u16>();
                    *ptr = *v as u16;
                }
                LengthMod::L | LengthMod::Ll | LengthMod::J => {
                    let ptr = $args.next_arg::<*mut u64>();
                    *ptr = *v;
                }
                LengthMod::Z | LengthMod::T => {
                    let ptr = $args.next_arg::<*mut usize>();
                    *ptr = *v as usize;
                }
                _ => {
                    let ptr = $args.next_arg::<*mut u32>();
                    *ptr = *v as u32;
                }
            },
            ScanValue::Float(v) => match $spec.length {
                LengthMod::L | LengthMod::BigL => {
                    let ptr = $args.next_arg::<*mut f64>();
                    *ptr = *v;
                }
                _ => {
                    let ptr = $args.next_arg::<*mut f32>();
                    *ptr = *v as f32;
                }
            },
            ScanValue::Char(bytes) => match $spec.length {
                // `%lc`: the destination is a `wchar_t*`. Decode the matched
                // narrow (UTF-8) bytes back to wide characters; no NUL (like %c).
                LengthMod::L => {
                    let ptr = $args.next_arg::<*mut libc::wchar_t>();
                    let mut i = 0isize;
                    for ch in String::from_utf8_lossy(bytes).chars() {
                        *ptr.offset(i) = ch as u32 as libc::wchar_t;
                        i += 1;
                    }
                }
                _ => {
                    let ptr = $args.next_arg::<*mut u8>();
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
                }
            },
            ScanValue::String(bytes) => match $spec.length {
                // `%ls`: the destination is a `wchar_t*`. Decode the matched
                // narrow (UTF-8) token to wide characters and NUL-terminate.
                // (Writing the raw narrow bytes left a `wchar_t` array of
                // mangled half-characters.)
                LengthMod::L => {
                    let ptr = $args.next_arg::<*mut libc::wchar_t>();
                    let mut i = 0isize;
                    for ch in String::from_utf8_lossy(bytes).chars() {
                        *ptr.offset(i) = ch as u32 as libc::wchar_t;
                        i += 1;
                    }
                    *ptr.offset(i) = 0;
                }
                _ => {
                    // Narrow `%s`/`%[` destination in a WIDE scanf: glibc converts
                    // each matched wide char to multibyte then terminates by BOTH
                    // a `wcrtomb(L'\0')` (one NUL in UTF-8) AND an explicit string
                    // terminator — so it writes TWO trailing NUL bytes. Match it
                    // byte-for-byte.
                    let ptr = $args.next_arg::<*mut c_char>();
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len());
                    *ptr.add(bytes.len()) = 0;
                    *ptr.add(bytes.len() + 1) = 0;
                }
            },
            ScanValue::CharsConsumed(n) => match $spec.length {
                LengthMod::Hh => {
                    let ptr = $args.next_arg::<*mut i8>();
                    *ptr = *n as i8;
                }
                LengthMod::H => {
                    let ptr = $args.next_arg::<*mut i16>();
                    *ptr = *n as i16;
                }
                LengthMod::L | LengthMod::Ll | LengthMod::J => {
                    let ptr = $args.next_arg::<*mut i64>();
                    *ptr = *n as i64;
                }
                _ => {
                    let ptr = $args.next_arg::<*mut c_int>();
                    *ptr = *n as c_int;
                }
            },
            ScanValue::Pointer(v) => {
                let ptr = $args.next_arg::<*mut *mut c_void>();
                *ptr = *v as *mut c_void;
            }
        }
    };
}

// ===========================================================================
// Native wide I/O helpers
// ===========================================================================

thread_local! {
    static WPRINTF_FORMAT_BUF: std::cell::RefCell<Vec<u8>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

struct PooledWideFormat {
    buf: Vec<u8>,
}

impl PooledWideFormat {
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

impl Drop for PooledWideFormat {
    fn drop(&mut self) {
        let mut buf = std::mem::take(&mut self.buf);
        buf.clear();
        WPRINTF_FORMAT_BUF.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.capacity() < buf.capacity() {
                *slot = buf;
            }
        });
    }
}

/// Read a NUL-terminated wide string into UTF-8 bytes.
/// Format specifiers are all ASCII, so this is safe for format string conversion.
unsafe fn wide_to_narrow_into(wcs: *const libc::wchar_t, buf: &mut Vec<u8>) {
    buf.clear();
    if wcs.is_null() {
        return;
    }
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
}

/// Read a NUL-terminated wide string into a Vec of bytes (UTF-8 encoding).
unsafe fn wide_to_narrow(wcs: *const libc::wchar_t) -> Vec<u8> {
    let mut buf = Vec::new();
    unsafe { wide_to_narrow_into(wcs, &mut buf) };
    buf
}

unsafe fn wide_to_narrow_pooled(wcs: *const libc::wchar_t) -> PooledWideFormat {
    let mut buf = WPRINTF_FORMAT_BUF.with(|slot| std::mem::take(&mut *slot.borrow_mut()));
    unsafe { wide_to_narrow_into(wcs, &mut buf) };
    PooledWideFormat { buf }
}

#[cfg(test)]
mod wide_format_pool_tests {
    use super::*;

    fn wide(chars: &[u32]) -> Vec<libc::wchar_t> {
        let mut out: Vec<libc::wchar_t> = chars.iter().map(|&ch| ch as libc::wchar_t).collect();
        out.push(0);
        out
    }

    #[test]
    fn pooled_wide_format_matches_fresh_converter_and_reuses_capacity() {
        let fmt = wide(&[
            b'%' as u32,
            b'l' as u32,
            b's' as u32,
            b' ' as u32,
            0x03bb,
            b' ' as u32,
            b'%' as u32,
            b'd' as u32,
        ]);

        let fresh = unsafe { wide_to_narrow(fmt.as_ptr()) };
        let pooled = unsafe { wide_to_narrow_pooled(fmt.as_ptr()) };
        let pooled_cap = pooled.buf.capacity();
        assert_eq!(pooled.as_bytes(), fresh.as_slice());
        drop(pooled);

        let retained_cap = WPRINTF_FORMAT_BUF.with(|slot| slot.borrow().capacity());
        assert!(retained_cap >= fresh.len());
        assert!(retained_cap >= pooled_cap);
    }

    #[test]
    fn pooled_wide_format_preserves_invalid_codepoint_replacement() {
        let fmt = wide(&[b'<' as u32, 0x11_0000, b'>' as u32]);
        let fresh = unsafe { wide_to_narrow(fmt.as_ptr()) };
        let pooled = unsafe { wide_to_narrow_pooled(fmt.as_ptr()) };

        assert_eq!(fresh, b"<\xEF\xBF\xBD>");
        assert_eq!(pooled.as_bytes(), fresh.as_slice());
    }
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

#[inline]
unsafe fn is_exact_wide_percent_ls(format: *const libc::wchar_t) -> bool {
    unsafe {
        *format == b'%' as libc::wchar_t
            && *format.add(1) == b'l' as libc::wchar_t
            && *format.add(2) == b's' as libc::wchar_t
            && *format.add(3) == 0
    }
}

#[inline]
unsafe fn is_exact_wide_percent_d(format: *const libc::wchar_t) -> bool {
    // SAFETY: `swprintf` format pointers are required to reference a
    // NUL-terminated wide string. Short-circuiting avoids reading past the
    // terminator unless the prefix is exactly "%d".
    unsafe {
        *format == b'%' as libc::wchar_t
            && *format.add(1) == b'd' as libc::wchar_t
            && *format.add(2) == 0
    }
}

unsafe fn swprintf_direct_i32(dst: *mut libc::wchar_t, n: usize, value: c_int) -> c_int {
    let mut out = [0 as libc::wchar_t; 11];
    let mut len = 0usize;
    let signed = value as i64;
    let mut mag = if signed < 0 {
        out[0] = b'-' as libc::wchar_t;
        len = 1;
        signed.unsigned_abs()
    } else {
        signed as u64
    };

    let mut digits = [0u8; 10];
    let mut idx = digits.len();
    loop {
        idx -= 1;
        digits[idx] = b'0' + (mag % 10) as u8;
        mag /= 10;
        if mag == 0 {
            break;
        }
    }
    for &digit in &digits[idx..] {
        out[len] = digit as libc::wchar_t;
        len += 1;
    }

    if !dst.is_null() && n != 0 {
        let copy_len = len.min(n.saturating_sub(1));
        if copy_len != 0 {
            // SAFETY: `out[..copy_len]` was initialized above and `copy_len`
            // is bounded by the caller-provided destination capacity minus
            // the trailing NUL slot.
            unsafe { std::ptr::copy_nonoverlapping(out.as_ptr(), dst, copy_len) };
        }
        // SAFETY: `copy_len < n` when `n != 0`, so the terminator lands
        // within the destination object promised by the C ABI caller.
        unsafe { *dst.add(copy_len) = 0 };
    }

    if len >= n { -1 } else { len as c_int }
}

unsafe fn swprintf_direct_wide_string(
    dst: *mut libc::wchar_t,
    n: usize,
    src: *const libc::wchar_t,
) -> c_int {
    const NULL_WIDE: [libc::wchar_t; 6] = [
        b'(' as libc::wchar_t,
        b'n' as libc::wchar_t,
        b'u' as libc::wchar_t,
        b'l' as libc::wchar_t,
        b'l' as libc::wchar_t,
        b')' as libc::wchar_t,
    ];

    let (input, produced_len): (*const libc::wchar_t, usize) = if src.is_null() {
        (NULL_WIDE.as_ptr(), NULL_WIDE.len())
    } else {
        (src, unsafe { bounded_wide_len(src.cast::<u32>()) })
    };

    if !dst.is_null() && n != 0 {
        let copy_len = produced_len.min(n.saturating_sub(1));
        if copy_len != 0 {
            unsafe { std::ptr::copy_nonoverlapping(input, dst, copy_len) };
        }
        unsafe { *dst.add(copy_len) = 0 };
    }

    if produced_len >= n {
        -1
    } else {
        produced_len as c_int
    }
}

// decode_utf8 moved to frankenlibc_core::string::wchar::decode_utf8_lossy.
// Use the alias below at the two call sites so they read identically.
use frankenlibc_core::string::wchar::decode_utf8_lossy as decode_utf8;

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

    let mut bytes = [0u8; 6];
    bytes[0] = first as u8;
    let expected = if bytes[0] < 0x80 {
        1
    } else if bytes[0] & 0xE0 == 0xC0 {
        2
    } else if bytes[0] & 0xF0 == 0xE0 {
        3
    } else if bytes[0] & 0xF8 == 0xF0 {
        4
    } else if bytes[0] & 0xFC == 0xF8 {
        // 5-byte obsolete RFC 2279 lead (0xF8..=0xFB). `wchar_core::mbtowc`
        // decodes these for C.UTF-8 parity with glibc (and fl's own mbrtowc, see
        // bd-kryp2k), so read the continuations and let it validate/decode.
        5
    } else if bytes[0] & 0xFE == 0xFC {
        // 6-byte obsolete RFC 2279 lead (0xFC..=0xFD).
        6
    } else {
        // 0xC0/0xC1 (overlong 2-byte), 0xFE/0xFF, and continuation bytes are
        // never valid leads; reject at the lead.
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

    let mut bytes = [0u8; 6];
    let Some(encoded_len) = wchar_core::wctomb(wc, &mut bytes) else {
        // A wide char the C.UTF-8 encoder cannot represent (a surrogate, or a
        // value above U+7FFFFFFF). glibc's wide-stdio gconv substitutes the
        // single byte '?' and reports SUCCESS (returns `wc`, leaves errno) —
        // NOT C99's EILSEQ/WEOF (which its own `wcrtomb` returns). frankenlibc
        // is a glibc drop-in, so mirror that observable behaviour.
        return if unsafe { super::stdio_abi::fputc(b'?' as c_int, stream) } == libc::EOF {
            WEOF_VALUE
        } else {
            wc
        };
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

    let mut bytes = [0u8; 6];
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
    let max = cap - 1;
    if max > 0 {
        // SAFETY: `ws` is valid for `cap` wchar_t elements; `max == cap - 1`.
        let dst = unsafe { std::slice::from_raw_parts_mut(ws as *mut u32, max) };
        if let Some((read, had_error)) =
            unsafe { super::stdio_abi::read_cached_ascii_line_wide(stream, dst) }
        {
            if read == 0 || had_error {
                return std::ptr::null_mut();
            }
            // SAFETY: `read <= max < cap`, so the terminator is in bounds.
            unsafe { *ws.add(read) = 0 };
            return ws;
        }
    }

    let mut written = 0usize;
    let mut hit_eof = false;
    while written + 1 < cap {
        // SAFETY: delegated to this ABI implementation with validated stream.
        let wc = unsafe { fgetwc(stream) };
        if wc == WEOF_VALUE {
            hit_eof = true;
            break;
        }

        // SAFETY: bounded by `cap`.
        unsafe { *ws.add(written) = wc as libc::wchar_t };
        written += 1;
        if wc == b'\n' as u32 {
            break;
        }
    }

    // C99: return NULL only when EOF/error is encountered before ANY wide char
    // is read. A degenerate `n == 1` (cap-1 == 0, the loop never runs) is NOT an
    // EOF — glibc writes the terminating L'\0' and returns `ws` (an empty string).
    if written == 0 && hit_eof {
        return std::ptr::null_mut();
    }

    // SAFETY: bounded by `cap` (cap >= 1, so index 0 is in range).
    unsafe { *ws.add(written) = 0 };
    ws
}

/// Bench hook: ORIG per-wide-char fgetws loop (fgetwc per output char).
/// Not part of the ABI.
#[doc(hidden)]
pub unsafe fn bench_fgetws_percall(
    ws: *mut libc::wchar_t,
    n: c_int,
    stream: *mut std::ffi::c_void,
) -> *mut libc::wchar_t {
    if ws.is_null() || stream.is_null() || n <= 0 {
        return std::ptr::null_mut();
    }

    let cap = n as usize;
    let mut written = 0usize;
    let mut hit_eof = false;
    while written + 1 < cap {
        // SAFETY: delegated to the deployed wide-char reader.
        let wc = unsafe { fgetwc(stream) };
        if wc == WEOF_VALUE {
            hit_eof = true;
            break;
        }

        // SAFETY: bounded by `cap`.
        unsafe { *ws.add(written) = wc as libc::wchar_t };
        written += 1;
        if wc == b'\n' as u32 {
            break;
        }
    }

    if written == 0 && hit_eof {
        return std::ptr::null_mut();
    }

    // SAFETY: bounded by `cap` (cap >= 1, so index 0 is in range).
    unsafe { *ws.add(written) = 0 };
    ws
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fputws(ws: *const libc::wchar_t, stream: *mut std::ffi::c_void) -> c_int {
    if ws.is_null() || stream.is_null() {
        return libc::EOF;
    }

    unsafe { fputws_impl(ws, stream) }
}

/// Fast path: bulk SIMD `wcstombs` conversion of the whole (buffer-fitting, all-encodable)
/// wide string + ONE `fwrite`, matching glibc's single bulk conversion (fl was 9-212x on the
/// per-char `fputwc` loop). A single unencodable wchar (`wcstombs` -> None) or a string longer
/// than the stack buffer falls to the per-char loop, which does glibc's '?' substitution and
/// handles arbitrary length. Byte-identical: `wchar_core::wcstombs` is proven isomorphic to
/// per-char `wctomb` (conformance_diff_wcstombs_simd), so the fast path emits the same bytes;
/// the slow path is the original loop. NOTE: an earlier bulk-WRITE-only variant (still per-char
/// wctomb) REGRESSED 2.6-3.4x — the win requires bulk CONVERT (this SIMD wcstombs), not bulk
/// write. See NEGATIVE_EVIDENCE.md 2026-07-02.
#[inline]
unsafe fn fputws_impl(ws: *const libc::wchar_t, stream: *mut std::ffi::c_void) -> c_int {
    // Worst-case 6 bytes/wchar (wctomb RFC-2279), so a wlen<=CAP/6 string always fits without
    // wcstombs truncating on `dest` room. Longer strings drop to the per-char fallback.
    const CAP: usize = 1536;
    let max_wchars = CAP / 6;
    let mut wlen = 0usize;
    while wlen <= max_wchars {
        // SAFETY: caller provides a NUL-terminated wide string.
        if unsafe { *ws.add(wlen) } == 0 {
            break;
        }
        wlen += 1;
    }
    // Gate the bulk path on wlen >= 16: below the measured crossover the per-char loop is
    // faster (the stack-buffer + wcstombs setup exceeds a handful of fast fputc calls; wn=8
    // was 7% slower). At wlen>=16 bulk wins decisively (wn=64: 9.4x). Strict improvement.
    if (16..=max_wchars).contains(&wlen) {
        let mut buf = [0u8; CAP];
        // SAFETY: `ws` is valid for `wlen` wide chars (NUL found at `wlen`).
        let src = unsafe { std::slice::from_raw_parts(ws as *const u32, wlen) };
        if let Some(nbytes) = wchar_core::wcstombs(&mut buf, src) {
            if nbytes == 0 {
                return 0;
            }
            // SAFETY: valid stream; `buf[..nbytes]` initialized by wcstombs.
            return if unsafe { super::stdio_abi::fwrite(buf.as_ptr().cast(), 1, nbytes, stream) }
                == nbytes
            {
                0
            } else {
                libc::EOF
            };
        }
        // Unencodable wchar: fall through to the per-char loop (glibc '?' substitution).
    }
    // Per-char fallback: long strings (> CAP/6) or an unencodable wchar.
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

/// Bench hook: OLD per-wide-char fputws (fputwc loop). Not part of the ABI.
#[doc(hidden)]
pub unsafe fn bench_fputws_percall(
    ws: *const libc::wchar_t,
    stream: *mut std::ffi::c_void,
) -> c_int {
    if ws.is_null() || stream.is_null() {
        return libc::EOF;
    }
    let mut idx = 0usize;
    loop {
        let wc = unsafe { *ws.add(idx) as u32 };
        if wc == 0 {
            return 0;
        }
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
    if unsafe { is_exact_wide_percent_ls(format) } {
        let arg = unsafe { args.next_arg::<*const libc::wchar_t>() };
        return unsafe { swprintf_direct_wide_string(s, n, arg) };
    }
    // SAFETY: `format` is the same NUL-terminated wide string already
    // accepted by the surrounding `swprintf` path.
    if unsafe { is_exact_wide_percent_d(format) } {
        // SAFETY: the exact `%d` format consumes one promoted C `int` vararg.
        let arg = unsafe { args.next_arg::<c_int>() };
        // SAFETY: `swprintf_direct_i32` writes at most `n` wide characters to
        // the caller-provided destination and mirrors the generic truncation
        // contract for this exact format.
        return unsafe { swprintf_direct_i32(s, n, arg) };
    }
    let fmt_narrow = unsafe { wide_to_narrow_pooled(format) };
    let segments = parse_format_string(fmt_narrow.as_bytes());
    let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    extract_wprintf_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered =
        unsafe { super::stdio_abi::render_wprintf(&segments, arg_buf.as_ptr(), extract_count) };

    // swprintf: if the output (including NUL) would exceed n, return -1 — but
    // glibc still writes the TRUNCATED prefix (min(n-1, produced) wide chars)
    // followed by a NUL, exactly like the success path, rather than emptying the
    // buffer. narrow_to_wide_buf does precisely that (and no-ops for null/n==0).
    let wide_count = narrow_to_wide_count(&rendered);
    if wide_count >= n {
        narrow_to_wide_buf(&rendered, s, n);
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
    let fmt_narrow = unsafe { wide_to_narrow_pooled(format) };
    let segments = parse_format_string(fmt_narrow.as_bytes());
    let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    extract_wprintf_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered =
        unsafe { super::stdio_abi::render_wprintf(&segments, arg_buf.as_ptr(), extract_count) };
    // C: wprintf returns the number of WIDE CHARACTERS transmitted, not the byte
    // length of the (UTF-8) rendering — they differ for any multibyte output.
    let wide_count = narrow_to_wide_count(&rendered);

    if super::stdio_abi::write_all_fd(libc::STDOUT_FILENO, &rendered) {
        wide_count as c_int
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
    let fmt_narrow = unsafe { wide_to_narrow_pooled(format) };
    let segments = parse_format_string(fmt_narrow.as_bytes());
    let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    extract_wprintf_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered =
        unsafe { super::stdio_abi::render_wprintf(&segments, arg_buf.as_ptr(), extract_count) };
    // fwprintf returns the number of WIDE CHARACTERS written, not bytes.
    let wide_count = narrow_to_wide_count(&rendered);

    // Write each byte through the stdio layer to use stream buffering.
    for &byte in rendered.iter() {
        if unsafe { super::stdio_abi::fputc(byte as c_int, stream) } == libc::EOF {
            return -1;
        }
    }
    wide_count as c_int
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
    let fmt_narrow = unsafe { wide_to_narrow_pooled(format) };
    let segments = parse_format_string(fmt_narrow.as_bytes());
    let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    unsafe { super::stdio_abi::vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let rendered =
        unsafe { super::stdio_abi::render_wprintf(&segments, arg_buf.as_ptr(), extract_count) };

    // On truncation glibc writes the truncated prefix + NUL (not just an empty
    // buffer) and returns -1; mirror swprintf.
    let wide_count = narrow_to_wide_count(&rendered);
    if wide_count >= n {
        narrow_to_wide_buf(&rendered, s, n);
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
    let fmt_narrow = unsafe { wide_to_narrow_pooled(format) };
    let segments = parse_format_string(fmt_narrow.as_bytes());
    let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    unsafe { super::stdio_abi::vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let rendered =
        unsafe { super::stdio_abi::render_wprintf(&segments, arg_buf.as_ptr(), extract_count) };
    // vwprintf returns the number of WIDE CHARACTERS written, not bytes.
    let wide_count = narrow_to_wide_count(&rendered);

    if super::stdio_abi::write_all_fd(libc::STDOUT_FILENO, &rendered) {
        wide_count as c_int
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
    let fmt_narrow = unsafe { wide_to_narrow_pooled(format) };
    let segments = parse_format_string(fmt_narrow.as_bytes());
    let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    unsafe { super::stdio_abi::vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let rendered =
        unsafe { super::stdio_abi::render_wprintf(&segments, arg_buf.as_ptr(), extract_count) };
    // vfwprintf returns the number of WIDE CHARACTERS written, not bytes.
    let wide_count = narrow_to_wide_count(&rendered);

    for &byte in rendered.iter() {
        if unsafe { super::stdio_abi::fputc(byte as c_int, stream) } == libc::EOF {
            return -1;
        }
    }
    wide_count as c_int
}

// ===========================================================================
// wscanf family — Implemented (native scanf engine + wide conversion)
// ===========================================================================

unsafe fn wide_scanf_format_cstr(format: *const libc::wchar_t) -> Option<std::ffi::CString> {
    let fmt_narrow = unsafe { wide_to_narrow(format) };
    if fmt_narrow.is_empty() {
        None
    } else {
        Some(std::ffi::CString::new(fmt_narrow).unwrap_or_default())
    }
}

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
    let Some(fmt_cstr) = (unsafe { wide_scanf_format_cstr(format) }) else {
        return 0;
    };
    let input = unsafe { wide_input_to_narrow(s) };
    let Some((result, directives)) = super::stdio_abi::scanf_core_wide(&input, fmt_cstr.as_ptr())
    else {
        return libc::EOF;
    };

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
    let Some(fmt_cstr) = (unsafe { wide_scanf_format_cstr(format) }) else {
        return 0;
    };
    let sid = super::stdio_abi::stdin_stream_id();
    let (input, scanf_seek_base) = super::stdio_abi::read_stream_for_scanf(sid, 4096);
    let Some((result, directives)) = super::stdio_abi::scanf_core_wide(&input, fmt_cstr.as_ptr())
    else {
        super::stdio_abi::scanf_finish_consume(sid, scanf_seek_base, &input, 0);
        return libc::EOF;
    };
    super::stdio_abi::scanf_finish_consume(sid, scanf_seek_base, &input, result.consumed);

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
    if stream.is_null() || format.is_null() {
        return libc::EOF;
    }
    let Some(fmt_cstr) = (unsafe { wide_scanf_format_cstr(format) }) else {
        return 0;
    };
    let id = stream as usize;
    let (input, scanf_seek_base) = super::stdio_abi::read_stream_for_scanf(id, 4096);
    let Some((result, directives)) = super::stdio_abi::scanf_core_wide(&input, fmt_cstr.as_ptr())
    else {
        super::stdio_abi::scanf_finish_consume(id, scanf_seek_base, &input, 0);
        return libc::EOF;
    };
    super::stdio_abi::scanf_finish_consume(id, scanf_seek_base, &input, result.consumed);

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
    if s.is_null() || format.is_null() || ap.is_null() {
        return libc::EOF;
    }
    let Some(fmt_cstr) = (unsafe { wide_scanf_format_cstr(format) }) else {
        return 0;
    };
    let input = unsafe { wide_input_to_narrow(s) };
    let Some((result, directives)) = super::stdio_abi::scanf_core_wide(&input, fmt_cstr.as_ptr())
    else {
        return libc::EOF;
    };

    if result.input_failure && result.count == 0 {
        return libc::EOF;
    }
    unsafe { super::stdio_abi::vscanf_write_values(&result.values, &directives, ap) };
    result.count
}

/// Native `vwscanf`: scan from stdin with va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vwscanf(format: *const libc::wchar_t, ap: *mut std::ffi::c_void) -> c_int {
    if format.is_null() || ap.is_null() {
        return libc::EOF;
    }
    let Some(fmt_cstr) = (unsafe { wide_scanf_format_cstr(format) }) else {
        return 0;
    };
    let sid = super::stdio_abi::stdin_stream_id();
    let (input, scanf_seek_base) = super::stdio_abi::read_stream_for_scanf(sid, 4096);
    let Some((result, directives)) = super::stdio_abi::scanf_core_wide(&input, fmt_cstr.as_ptr())
    else {
        super::stdio_abi::scanf_finish_consume(sid, scanf_seek_base, &input, 0);
        return libc::EOF;
    };
    super::stdio_abi::scanf_finish_consume(sid, scanf_seek_base, &input, result.consumed);

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
    if stream.is_null() || format.is_null() || ap.is_null() {
        return libc::EOF;
    }
    let Some(fmt_cstr) = (unsafe { wide_scanf_format_cstr(format) }) else {
        return 0;
    };
    let id = stream as usize;
    let (input, scanf_seek_base) = super::stdio_abi::read_stream_for_scanf(id, 4096);
    let Some((result, directives)) = super::stdio_abi::scanf_core_wide(&input, fmt_cstr.as_ptr())
    else {
        super::stdio_abi::scanf_finish_consume(id, scanf_seek_base, &input, 0);
        return libc::EOF;
    };
    super::stdio_abi::scanf_finish_consume(id, scanf_seek_base, &input, result.consumed);

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
///
/// glibc-exact via the generated UTF-8 ctype table (bd-2g7oyh.254).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswblank(wc: u32) -> c_int {
    wchar_core::iswblank(wc) as c_int
}

/// POSIX `iswcntrl` — test for control wide character.
///
/// glibc-exact via the generated UTF-8 ctype table (bd-2g7oyh.254).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswcntrl(wc: u32) -> c_int {
    wchar_core::iswcntrl(wc) as c_int
}

/// POSIX `iswgraph` — test for graphic wide character.
///
/// glibc-exact via the generated UTF-8 ctype table (bd-2g7oyh.254).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswgraph(wc: u32) -> c_int {
    wchar_core::iswgraph(wc) as c_int
}

/// POSIX `iswpunct` — test for punctuation wide character.
///
/// glibc-exact via the generated UTF-8 ctype table (bd-2g7oyh.254).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswpunct(wc: u32) -> c_int {
    wchar_core::iswpunct(wc) as c_int
}

/// POSIX `iswxdigit` — test for hexadecimal digit wide character.
///
/// glibc-exact via the generated UTF-8 ctype table (bd-2g7oyh.254).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswxdigit(wc: u32) -> c_int {
    wchar_core::iswxdigit(wc) as c_int
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
    if nptr.is_null() {
        if !endptr.is_null() {
            // SAFETY: caller-provided endptr is writable when non-null.
            unsafe { *endptr = nptr as *mut libc::wchar_t };
        }
        return 0.0;
    }

    // Bounded scan + zero-alloc projection (see wide_parse_float): O(number), not O(buffer).
    let (value, consumed, erange) = unsafe {
        wide_parse_float(
            nptr,
            frankenlibc_core::stdlib::conversion::strtof_impl,
            crate::stdlib_abi::strtof_result_is_erange,
        )
    };
    if !endptr.is_null() {
        // SAFETY: consumed is bounded by the parsed prefix length.
        unsafe { *endptr = (nptr as *mut libc::wchar_t).add(consumed) };
    }
    if erange {
        unsafe { set_abi_errno(libc::ERANGE) };
    }
    value
}

#[inline]
fn wide_ascii_eq(wide: &[u32], ascii: &[u8]) -> bool {
    wide.len() == ascii.len()
        && wide
            .iter()
            .zip(ascii.iter())
            .all(|(&wc, &byte)| wc == u32::from(byte))
}

unsafe fn try_wcsftime_numeric_fast(
    s: *mut libc::wchar_t,
    maxsize: usize,
    format: &[u32],
    tm: *const libc::tm,
) -> Option<usize> {
    const YMD_HMS: u8 = 0;
    const HMS: u8 = 1;
    const HM: u8 = 2;
    const YMD: u8 = 3;

    let mode = if wide_ascii_eq(format, b"%Y-%m-%d %H:%M:%S") {
        YMD_HMS
    } else if wide_ascii_eq(format, b"%H:%M:%S") {
        HMS
    } else if wide_ascii_eq(format, b"%H:%M") {
        HM
    } else if wide_ascii_eq(format, b"%Y-%m-%d") {
        YMD
    } else {
        return None;
    };

    // SAFETY: caller already checked `tm` is non-null; these exact numeric
    // formats only need the scalar fields below and do not read tm_zone.
    let tm = unsafe { &*tm };
    let year = i64::from(tm.tm_year) + 1900;
    let needs_date = matches!(mode, YMD_HMS | YMD);
    let needs_time = matches!(mode, YMD_HMS | HMS | HM);
    if needs_date
        && (!(1000..=9999).contains(&year)
            || !(0..=11).contains(&tm.tm_mon)
            || !(1..=31).contains(&tm.tm_mday))
    {
        return None;
    }
    if needs_time
        && (!(0..=23).contains(&tm.tm_hour)
            || !(0..=59).contains(&tm.tm_min)
            || (mode != HM && !(0..=60).contains(&tm.tm_sec)))
    {
        return None;
    }

    let out_len = match mode {
        YMD_HMS => 19,
        HMS => 8,
        HM => 5,
        YMD => 10,
        _ => unreachable!(),
    };
    if maxsize <= out_len {
        return Some(0);
    }

    let mut out = [0u8; 19];
    let mut pos = 0usize;
    if needs_date {
        let year = year as u32;
        out[pos] = b'0' + ((year / 1000) % 10) as u8;
        out[pos + 1] = b'0' + ((year / 100) % 10) as u8;
        out[pos + 2] = b'0' + ((year / 10) % 10) as u8;
        out[pos + 3] = b'0' + (year % 10) as u8;
        out[pos + 4] = b'-';
        let month = (tm.tm_mon + 1) as u32;
        out[pos + 5] = b'0' + (month / 10) as u8;
        out[pos + 6] = b'0' + (month % 10) as u8;
        out[pos + 7] = b'-';
        let day = tm.tm_mday as u32;
        out[pos + 8] = b'0' + (day / 10) as u8;
        out[pos + 9] = b'0' + (day % 10) as u8;
        pos += 10;
        if mode == YMD_HMS {
            out[pos] = b' ';
            pos += 1;
        }
    }
    if needs_time {
        let hour = tm.tm_hour as u32;
        out[pos] = b'0' + (hour / 10) as u8;
        out[pos + 1] = b'0' + (hour % 10) as u8;
        out[pos + 2] = b':';
        let minute = tm.tm_min as u32;
        out[pos + 3] = b'0' + (minute / 10) as u8;
        out[pos + 4] = b'0' + (minute % 10) as u8;
        if mode != HM {
            out[pos + 5] = b':';
            let second = tm.tm_sec as u32;
            out[pos + 6] = b'0' + (second / 10) as u8;
            out[pos + 7] = b'0' + (second % 10) as u8;
        }
    }

    for (idx, &byte) in out[..out_len].iter().enumerate() {
        // SAFETY: `maxsize > out_len`, so all output chars and the terminator
        // fit in the caller-provided wide buffer.
        unsafe { *s.add(idx) = byte as libc::wchar_t };
    }
    // SAFETY: see loop safety above.
    unsafe { *s.add(out_len) = 0 };
    Some(out_len)
}

#[inline]
unsafe fn write_wide_ascii(s: *mut libc::wchar_t, maxsize: usize, bytes: &[u8]) -> usize {
    if maxsize <= bytes.len() {
        return 0;
    }
    for (idx, &byte) in bytes.iter().enumerate() {
        // SAFETY: `maxsize > bytes.len()`, so all chars and the terminator fit.
        unsafe { *s.add(idx) = byte as libc::wchar_t };
    }
    // SAFETY: see loop safety above.
    unsafe { *s.add(bytes.len()) = 0 };
    bytes.len()
}

unsafe fn try_wcsftime_name_fast(
    s: *mut libc::wchar_t,
    maxsize: usize,
    format: &[u32],
    tm: *const libc::tm,
) -> Option<usize> {
    const WDAY_ABBR: [&[u8]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
    const WDAY_FULL: [&[u8]; 7] = [
        b"Sunday",
        b"Monday",
        b"Tuesday",
        b"Wednesday",
        b"Thursday",
        b"Friday",
        b"Saturday",
    ];
    const MON_ABBR: [&[u8]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];
    const MON_FULL: [&[u8]; 12] = [
        b"January",
        b"February",
        b"March",
        b"April",
        b"May",
        b"June",
        b"July",
        b"August",
        b"September",
        b"October",
        b"November",
        b"December",
    ];

    let mode = if wide_ascii_eq(format, b"%A") {
        b'A'
    } else if wide_ascii_eq(format, b"%a") {
        b'a'
    } else if wide_ascii_eq(format, b"%B") {
        b'B'
    } else if wide_ascii_eq(format, b"%b") || wide_ascii_eq(format, b"%h") {
        b'b'
    } else {
        return None;
    };

    // SAFETY: caller already checked `tm` is non-null; exact C-locale name
    // formats only need the scalar weekday/month fields below.
    let tm = unsafe { &*tm };
    let bytes: &[u8] = match mode {
        b'A' => {
            if (0..=6).contains(&tm.tm_wday) {
                WDAY_FULL[tm.tm_wday as usize]
            } else {
                b"?"
            }
        }
        b'a' => {
            if (0..=6).contains(&tm.tm_wday) {
                WDAY_ABBR[tm.tm_wday as usize]
            } else {
                b"?"
            }
        }
        b'B' => {
            if (0..=11).contains(&tm.tm_mon) {
                MON_FULL[tm.tm_mon as usize]
            } else {
                b"?"
            }
        }
        b'b' => {
            if (0..=11).contains(&tm.tm_mon) {
                MON_ABBR[tm.tm_mon as usize]
            } else {
                b"?"
            }
        }
        _ => unreachable!(),
    };

    Some(unsafe { write_wide_ascii(s, maxsize, bytes) })
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

    if !fmt_slice.contains(&('%' as u32)) {
        if fmt_len >= maxsize {
            return 0;
        }
        for i in 0..fmt_len {
            // SAFETY: format has fmt_len readable wide chars; s has room for
            // fmt_len chars plus NUL because fmt_len < maxsize.
            unsafe { *s.add(i) = *format.add(i) };
        }
        // SAFETY: fmt_len < maxsize.
        unsafe { *s.add(fmt_len) = 0 };
        return fmt_len;
    }

    if let Some(n) = unsafe { try_wcsftime_name_fast(s, maxsize, fmt_slice, tm as *const libc::tm) }
    {
        return n;
    }

    if let Some(n) =
        unsafe { try_wcsftime_numeric_fast(s, maxsize, fmt_slice, tm as *const libc::tm) }
    {
        return n;
    }

    // Transcode the wide format to a multibyte C-string. Stack buffer for the
    // common short format (wcsftime_survey showed two heap Vec allocations
    // dominated the path). Heap only for a >85-char format.
    const FMT_STACK: usize = 512;
    let fmt_budget = fmt_len.saturating_mul(6).saturating_add(1);
    let mut fmt_stack = [0u8; FMT_STACK];
    let mut fmt_heap: Vec<u8> = Vec::new();
    let use_fmt_stack = fmt_budget <= FMT_STACK;
    {
        let buf: &mut [u8] = if use_fmt_stack {
            &mut fmt_stack[..]
        } else {
            fmt_heap = vec![0u8; fmt_budget];
            &mut fmt_heap[..]
        };
        let mut w = 0usize;
        for &wc in fmt_slice {
            // ASCII fast path: an ASCII wchar narrows 1:1 to its byte.
            if wc < 0x80 {
                buf[w] = wc as u8;
                w += 1;
                continue;
            }
            let mut tmp = [0u8; 6];
            let Some(n) = wchar_core::wctomb(wc, &mut tmp) else {
                // SAFETY: thread-local errno update.
                unsafe { set_abi_errno(libc::EILSEQ) };
                return 0;
            };
            buf[w..w + n].copy_from_slice(&tmp[..n]);
            w += n;
        }
        buf[w] = 0;
    }
    let fmt_ptr = if use_fmt_stack {
        fmt_stack.as_ptr()
    } else {
        fmt_heap.as_ptr()
    } as *const std::ffi::c_char;

    // Output buffer: try a stack buffer first; fall back to the conservative
    // `maxsize*6` heap budget only if the output would truncate and that budget
    // exceeds the stack.
    const OUT_STACK: usize = 1024;
    let out_budget = maxsize.saturating_mul(6).max(1);
    let mut out_stack = [0u8; OUT_STACK];
    let mut out_heap: Vec<u8>;
    let stack_cap = out_budget.min(OUT_STACK);
    // SAFETY: buffers are valid; time_abi::strftime enforces byte-capacity + NUL semantics.
    let mut out_len = unsafe {
        super::time_abi::strftime(
            out_stack.as_mut_ptr() as *mut std::ffi::c_char,
            stack_cap,
            fmt_ptr,
            tm as *const libc::tm,
        )
    };
    let out_ptr: *const u8 = if out_len > 0 {
        out_stack.as_ptr()
    } else if out_budget > OUT_STACK {
        // The stack may have been too small — retry with the full budget on the heap.
        out_heap = vec![0u8; out_budget];
        // SAFETY: heap buffer is valid for its length.
        out_len = unsafe {
            super::time_abi::strftime(
                out_heap.as_mut_ptr() as *mut std::ffi::c_char,
                out_heap.len(),
                fmt_ptr,
                tm as *const libc::tm,
            )
        };
        if out_len == 0 {
            return 0;
        }
        out_heap.as_ptr()
    } else {
        return 0;
    };
    // SAFETY: `out_ptr` is valid for `out_len` bytes (written by strftime).
    let out_mb = unsafe { std::slice::from_raw_parts(out_ptr, out_len) };

    let mut mb_i = 0usize;
    let mut wide_i = 0usize;
    while mb_i < out_len {
        if wide_i.saturating_add(1) >= maxsize {
            return 0;
        }
        // ASCII fast path: an ASCII output byte widens 1:1 to its codepoint.
        let b0 = out_mb[mb_i];
        if b0 < 0x80 {
            // SAFETY: `wide_i < maxsize` is enforced above.
            unsafe { *s.add(wide_i) = b0 as libc::wchar_t };
            wide_i += 1;
            mb_i += 1;
            continue;
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

    // glibc fills up to `n` wide chars of the transform and writes a NUL ONLY
    // when it fits (`copy_len < n`); for `n <= src_len` the written prefix is
    // left UNTERMINATED (POSIX: contents are indeterminate once the return value
    // is >= n, but glibc is deterministic and the narrow strxfrm already matches
    // this). The previous code reserved n-1 and always terminated, diverging.
    let copy_len = src_len.min(n);
    // SAFETY: destination and source are caller-provided valid buffers for the requested range.
    unsafe {
        if copy_len > 0 {
            // Inline SIMD copy, not copy_nonoverlapping: in this crate (which defines the
            // no_mangle memcpy) a wide copy_nonoverlapping compiles to a slow naive loop
            // (~2 GB/s / up to 34x glibc at large len — the wide-copy-symbol trap).
            wide_copy_n(dest.cast::<u32>(), src.cast::<u32>(), copy_len);
        }
        if copy_len < n {
            *dest.add(copy_len) = 0;
        }
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

    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict unbounded
    // copy body — SIMD length scan + bulk copy through the terminator — returning the
    // end pointer `dst + len` (at the NUL), the wide stpcpy result. Skips the membrane
    // tax (wide analog of the wcscpy fast path, returning the end ptr).
    if runtime_policy::strict_passthrough_active() {
        // Fused single-pass copy-through-NUL (see wide_fused_copy); returns the end
        // pointer dst+len (the wide stpcpy result) from the length it already found —
        // no scan_w_string + interposed-memcpy round trip.
        return unsafe { dst.add(wide_fused_copy(dst, src)) };
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

    // Strict-mode fast path (DEFAULT deployed): byte-identical to the strict body —
    // scan src (`src_bound==None`), copy `min(len,n)`, NUL-pad the remainder, return
    // the end pointer (first NUL, or dst+n). Skips the membrane tax (wide stpncpy).
    if runtime_policy::strict_passthrough_active() {
        // Fused single-pass scan+copy+pad; returns min(strlen,n) = the wcpncpy end offset
        // (dst+ret is the first NUL, or dst+n if truncated). Replaces the scan_w_string +
        // wide_copy_n two-pass. Byte-identical; measured 1.12-1.43x (wcsncpy_fused_ab).
        return unsafe { dst.add(wide_fused_copy_n(dst, src, n)) };
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

/// Branchless SIMD ASCII lowercase over 8 `u32` (wchar_t) lanes — folds only
/// `'A'..='Z'` to `'a'..='z'` (C/POSIX-locale `towlower`, matching
/// [`abi_towlower`]). SIMD lanes are independent, so the per-lane range test
/// `(0x41 <= v <= 0x5A)` needs no borrow-safety guard (unlike the narrow SWAR
/// case-fold): a mask selects `0x20` to add.
#[inline(always)]
fn wide_ascii_lower_simd(v: Simd<u32, 8>) -> Simd<u32, 8> {
    let is_upper = v.simd_ge(Simd::splat(0x41)) & v.simd_le(Simd::splat(0x5A));
    is_upper.select(v + Simd::splat(0x20), v)
}

/// Fused portable-SIMD wide case-insensitive compare: 8 `u32` lanes per 32-byte
/// window, ASCII-folded. `bound` in elements. Returns `(result, span, hit_limit)`
/// where `result` is the folded-codepoint difference `towlower(a)-towlower(b)` at
/// the first folded-differing element or NUL-stop (matching glibc's wint_t
/// arithmetic, not a bare sign). Equal-folded-and-NUL-free windows advance 8;
/// others resolve element-wise (identical to the scalar [`abi_towlower`] loop).
/// Dual-pointer reads are page-cross guarded like [`scan_wcscmp_simd`].
unsafe fn scan_wcscasecmp_simd(
    s1: *const u32,
    s2: *const u32,
    bound: usize,
) -> (c_int, usize, bool) {
    const WLANES: usize = 8;
    let zv = Simd::<u32, WLANES>::splat(0);
    let mut i = 0usize;
    loop {
        if i + WLANES <= bound
            && wide32_read_within_page(s1.wrapping_add(i) as usize)
            && wide32_read_within_page(s2.wrapping_add(i) as usize)
        {
            // SAFETY: both 32-byte reads stay within their pages and within bound.
            let va = Simd::<u32, WLANES>::from_array(unsafe {
                core::ptr::read(s1.add(i).cast::<[u32; WLANES]>())
            });
            let vb = Simd::<u32, WLANES>::from_array(unsafe {
                core::ptr::read(s2.add(i).cast::<[u32; WLANES]>())
            });
            if wide_ascii_lower_simd(va) == wide_ascii_lower_simd(vb) && !va.simd_eq(zv).any() {
                i += WLANES;
                continue;
            }
            for j in 0..WLANES {
                // SAFETY: i+j < bound.
                let raw = unsafe { *s1.add(i + j) };
                let a = abi_towlower(raw);
                let b = abi_towlower(unsafe { *s2.add(i + j) });
                if a != b || raw == 0 {
                    return (a.wrapping_sub(b) as i32, i + j + 1, false);
                }
            }
            i += WLANES; // defensive: a flagged window always returns above.
            continue;
        }
        if i >= bound {
            return (0, bound, true);
        }
        // SAFETY: i < bound.
        let raw = unsafe { *s1.add(i) };
        let a = abi_towlower(raw);
        let b = abi_towlower(unsafe { *s2.add(i) });
        if a != b || raw == 0 {
            return (a.wrapping_sub(b) as i32, i + 1, false);
        }
        i += 1;
    }
}

/// Benchmark/test hook for [`scan_wcscasecmp_simd`]. Not part of the public ABI.
///
/// # Safety
/// `s1`/`s2` must be NUL-terminated, or valid for `bound` elements.
#[doc(hidden)]
pub unsafe fn bench_scan_wcscasecmp_simd(s1: *const u32, s2: *const u32, bound: usize) -> c_int {
    unsafe { scan_wcscasecmp_simd(s1, s2, bound).0 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcscasecmp(s1: *const u32, s2: *const u32) -> c_int {
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    // Strict-mode fast path (DEFAULT deployed): strict passthrough has
    // `cmp_bound == None`, so this is byte-identical to the strict full path
    // (`scan_wcscasecmp_simd` with no limit); skips the decide + observe tax.
    if runtime_policy::strict_passthrough_active() {
        let (r, _span, _hit) = unsafe { scan_wcscasecmp_simd(s1, s2, usize::MAX) };
        return r;
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

    // Fused portable-SIMD ASCII-folded wide compare (shared scan_wcscasecmp_simd),
    // byte-identical to the old scalar abi_towlower loop. `cmp_bound == None` => no
    // limit; any hit-limit is the membrane bound, so it maps directly to `adverse`.
    let (result, adverse, span) = unsafe {
        let (r, span, hit_limit) = scan_wcscasecmp_simd(s1, s2, cmp_bound.unwrap_or(usize::MAX));
        (r, hit_limit, span)
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

    // Strict-mode fast path (DEFAULT deployed): strict passthrough has no membrane
    // clamp (`cmp_bound == Some(n)`, `adverse` false), byte-identical to the strict
    // full path (ASCII-folded core compare bounded by `n`); skips the decide +
    // observe tax.
    if runtime_policy::strict_passthrough_active() {
        let (r, _span, _hit) = unsafe { scan_wcscasecmp_simd(s1, s2, n) };
        return r;
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

    // Fused portable-SIMD ASCII-folded wide compare (shared scan_wcscasecmp_simd);
    // `cmp_bound` is always Some here. `adverse` only when the limit is reached
    // before n (a membrane clamp), matching the old scalar loop exactly.
    let limit = cmp_bound.expect("wcsncasecmp cmp_bound is always Some");
    let (result, adverse, span) = unsafe {
        let (r, span, hit_limit) = scan_wcscasecmp_simd(s1, s2, limit);
        (r, hit_limit && limit < n, span)
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

    // Strict-mode fast path (DEFAULT deployed): strict passthrough has no clamp
    // (`scan_len == n`), byte-identical to the strict body — reverse scan of `n`
    // elements for the last `c`. Skips the decide + observe membrane tax, while
    // reusing the core SIMD reverse scanner instead of a scalar ABI loop.
    if runtime_policy::strict_passthrough_active() {
        return unsafe {
            let slice = std::slice::from_raw_parts(s, n);
            match frankenlibc_core::string::wide::wmemrchr(slice, c, n) {
                Some(i) => s.add(i) as *mut u32,
                None => std::ptr::null_mut(),
            }
        };
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
        match frankenlibc_core::string::wide::wmemrchr(slice, c, scan_len) {
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
    let Some(name) = (unsafe { bounded_cstr_bytes(name) }) else {
        return 0;
    };
    match name {
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
///
/// Dispatches to the matching `iswX` routine so non-ASCII codepoints get the
/// same treatment as direct calls. The previous implementation restricted
/// classification to ASCII, which broke programs that asked
/// `iswctype(wctype("alpha"), 0x4E00)` for CJK or other non-Latin letters.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iswctype(wc: u32, desc: WctypeT) -> i32 {
    match desc {
        1 => unsafe { iswalnum(wc) },
        2 => unsafe { iswalpha(wc) },
        3 => unsafe { iswblank(wc) },
        4 => unsafe { iswcntrl(wc) },
        5 => unsafe { iswdigit(wc) },
        6 => unsafe { iswgraph(wc) },
        7 => unsafe { iswlower(wc) },
        8 => unsafe { iswprint(wc) },
        9 => unsafe { iswpunct(wc) },
        10 => unsafe { iswspace(wc) },
        11 => unsafe { iswupper(wc) },
        12 => unsafe { iswxdigit(wc) },
        _ => 0,
    }
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
/// Returns nonzero iff `ps` is in the initial conversion state (or is NULL).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mbsinit(ps: *const c_void) -> c_int {
    if ps.is_null() {
        return 1;
    }
    // UTF-8 itself is stateless, but FrankenLibC's restartable converters DO
    // accumulate cross-call state in `*ps`: mbrtowc stores a pending partial
    // multibyte prefix as a leading count byte at offset 0 (0 = none), and
    // mbrtoc16/c16rtomb store a pending UTF-16 high surrogate as a u16 in bytes
    // [6..8] (0 = none). glibc's mbsinit returns 0 ("not initial") whenever a
    // conversion is mid-sequence, so we must too — returning 1 unconditionally
    // was wrong and broke callers probing for incomplete input. bd-28s12s.
    // SAFETY: ps is a valid mbstate_t (>= 8 bytes) per the C contract.
    let raw = unsafe { (ps as *const u8).cast::<[u8; 8]>().read_unaligned() };
    let partial_pending = raw[0] != 0;
    let surrogate_pending = raw[6] != 0 || raw[7] != 0;
    if partial_pending || surrogate_pending {
        0
    } else {
        1
    }
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
    // The SIMD ASCII fast path is valid only from an INITIAL conversion state.
    // If a partial multibyte sequence is pending (from an earlier nms-truncated
    // call), the next byte must be a continuation (>= 0x80); an ASCII byte there
    // is EILSEQ, which only the scalar `mbrtowc` detects. With `ps == NULL` fl
    // keeps no partial across calls (see `mbrtowc`), so the state is always
    // initial; with `ps != NULL` the partial-count byte ([0]) is 0 when initial.
    // After any complete character the state returns to initial.
    // SAFETY: when non-null, `ps` is a valid `mbstate_t` (>= 8 bytes) per the C
    // contract, so byte 0 (the mbrtowc partial count) is readable.
    let mut state_initial = ps.is_null() || unsafe { *(ps as *const u8) == 0 };

    while consumed < nms && (dst.is_null() || written < len) {
        let remaining = nms - consumed;

        // SIMD-widen the leading ASCII run (each byte 0x01..=0x7F is exactly one
        // wide char), bounded by the nms window and destination capacity. This
        // bypasses the per-character ABI `mbrtowc` (membrane + state machinery)
        // for ASCII, which dominates real text. Byte-for-byte identical: only
        // bytes < 0x80 are consumed, which `mbrtowc` maps 1:1 to the same
        // codepoint, and the run stops at the first NUL / multibyte lead so every
        // terminator / multibyte / error case stays in the scalar step below.
        if state_initial {
            // SAFETY: `s` points to at least `remaining` readable bytes — the same
            // window `mbrtowc` is given below.
            let src_window = unsafe { std::slice::from_raw_parts(s as *const u8, remaining) };
            let k = if dst.is_null() {
                wchar_core::ascii_prefix_len(src_window)
            } else {
                // SAFETY: `dst` has >= `len` wchar_t slots and `written < len` here.
                let dst_window = unsafe {
                    std::slice::from_raw_parts_mut(dst.add(written) as *mut u32, len - written)
                };
                wchar_core::mbs_ascii_prefix(dst_window, src_window)
            };
            if k > 0 {
                consumed += k;
                written += k;
                s = unsafe { s.add(k) };
                continue;
            }
        }

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
                // A complete character was decoded: the conversion state is
                // initial again, so the SIMD fast path is valid next iteration.
                state_initial = true;
            }
            r if r == usize::MAX - 1 => {
                // MB_INCOMPLETE: the `nms`-byte source window ends in the middle
                // of a valid multibyte char. glibc is NOT an error here — it
                // CONSUMES the remaining window bytes (they carry into *ps as a
                // partial sequence), advances *src to the nms boundary, and
                // returns the count of fully converted characters. (bd-2g7oyh.186)
                unsafe { *src = s.add(remaining) };
                return written;
            }
            _ => {
                // genuine encoding error (EILSEQ)
                unsafe { *src = s };
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
    let mut buf = [0u8; 6]; // MB_CUR_MAX for UTF-8 (RFC 2279 form)
    let source_bound = known_remaining(s as usize).map(bytes_to_wchars);
    let max_wchars = source_bound.map(|bound| bound.min(nwc)).unwrap_or(nwc);

    while wchars_consumed < max_wchars {
        // SIMD-narrow the leading ASCII wide-char run (each 0x01..=0x7F wchar
        // encodes to exactly one byte), bounded by the source wchar window and
        // the destination byte capacity. wcrtomb is stateless per wchar for
        // UTF-8, so this is valid regardless of `ps`. It stops at the first NUL /
        // non-ASCII / dest-full, leaving those for the scalar step — so output is
        // byte-for-byte identical (an ASCII wchar narrows 1:1 to the same byte)
        // and the bd-2g7oyh.186 dest-full / EILSEQ-on-truncation logic is intact.
        let remaining_wc = max_wchars - wchars_consumed;
        // SAFETY: `s` points to at least `remaining_wc` readable wide chars.
        let src_window = unsafe { std::slice::from_raw_parts(s as *const u32, remaining_wc) };
        let (chars, bytes) = if dst.is_null() {
            // Count mode: bulk-count the ASCII run (1 byte / wchar); multibyte is
            // counted by the scalar `wcrtomb` step below.
            let k = wchar_core::wcs_ascii_prefix_len(src_window);
            (k, k)
        } else {
            // SAFETY: `dst` has >= `len` bytes; `written <= len`.
            let dst_window = unsafe {
                std::slice::from_raw_parts_mut(dst.add(written) as *mut u8, len - written)
            };
            // Encode the leading run of whole clean windows (ASCII + 2/3/4-byte,
            // gated) via the shared SIMD lever `wcstombs`/`wcsrtombs` use, so
            // contiguous multibyte runs vectorise, not just the ASCII prefix.
            // `chars` (wide chars consumed) and `bytes` (output bytes written)
            // differ for multibyte; the helper only emits whole validated windows
            // bounded by the source window and `len - written`, so it stays
            // byte-for-byte identical to the scalar `wcrtomb` loop.
            wchar_core::wcs_simd_prefix(dst_window, src_window)
        };
        if chars > 0 {
            written += bytes; // one byte per ASCII wchar; 2/3/4 for multibyte
            wchars_consumed += chars;
            s = unsafe { s.add(chars) };
            continue;
        }

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

        // When the destination is already full, stop BEFORE encoding the next
        // wide char: glibc reports the len-limit (count + *src at this char)
        // rather than an EILSEQ from a subsequent un-encodable wchar (e.g. a
        // surrogate) that would never have been written. (bd-2g7oyh.186)
        if !dst.is_null() && written >= len {
            break;
        }
        // Always encode into the scratch buffer first, then copy only what fits.
        // (The previous `written + 4 <= len` direct-write assumed a 4-byte max
        // and could overflow `dst` by up to 2 bytes for a 5/6-byte UTF-8 form —
        // fl's encoder emits up to MB_CUR_MAX==6 bytes. bd-2g7oyh.186)
        let ret = unsafe { wcrtomb(buf.as_mut_ptr() as *mut c_char, wc, ps) };
        if ret == usize::MAX {
            // un-encodable wide char (EILSEQ): leave *src at the offending char.
            unsafe { *src = s };
            return usize::MAX;
        }
        if !dst.is_null() {
            if written + ret > len {
                break; // the whole character does not fit — never split it
            }
            // SAFETY: bounds checked above; copying `ret` bytes within `dst[..len]`.
            unsafe {
                std::ptr::copy_nonoverlapping(buf.as_ptr() as *const c_char, dst.add(written), ret);
            }
        }
        written += ret;
        wchars_consumed += 1;
        s = unsafe { s.add(1) };
    }
    if source_bound.is_some_and(|bound| bound < nwc) && wchars_consumed == max_wchars {
        unsafe { set_abi_errno(libc::EILSEQ) };
        return usize::MAX;
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
    // SIMD scan for `wc`-or-NUL (was a scalar per-wide-char loop, ~1.47x slower than
    // glibc's scalar wcschrnul; the SIMD scan WINS ~5x). Byte-identical: returns the
    // first `wc`-or-NUL position (the NUL terminator when `wc` is not found), exactly
    // like the scalar `*p == wc || *p == 0` loop. bd-2g7oyh.
    let (idx, _found) = unsafe { wide_find_or_nul_simd(s as *const u32, wc as u32) };
    unsafe { (s as *const u32).add(idx) as *mut libc::wchar_t }
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
        let slen = unsafe { bounded_wide_len(src.cast::<u32>()) };
        return siz.saturating_add(slen);
    }
    let slen = unsafe { bounded_wide_len(src.cast::<u32>()) };
    let copy_len = slen.min(siz - dlen - 1);
    for i in 0..copy_len {
        unsafe { *dst.add(dlen + i) = *src.add(i) };
    }
    unsafe { *dst.add(dlen + copy_len) = 0 };
    dlen.saturating_add(slen)
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
        return unsafe { bounded_wide_len(src.cast::<u32>()) };
    }
    let src_len = unsafe { bounded_wide_len(src.cast::<u32>()) };
    let copy_len = src_len.min(siz - 1);
    for i in 0..copy_len {
        unsafe { *dst.add(i) = *src.add(i) };
    }
    unsafe { *dst.add(copy_len) = 0 };
    src_len
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

    // Allocate initial wide buffer (empty, NUL-terminated).
    let initial = unsafe { crate::malloc_abi::raw_alloc(size_of::<u32>()) } as *mut u32;
    if initial.is_null() {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return std::ptr::null_mut();
    }
    unsafe {
        *initial = 0; // NUL wchar_t
        *bufp = initial;
        *sizep = 0;
    }

    let handle = crate::stdio_abi::register_memory_stream_with_native_handle(
        frankenlibc_core::stdio::StdioStream::new_mem_dynamic(),
        crate::io_internal_abi::NativeFileBacking::MemoryGrowing {
            buf_ptr: bufp.cast::<*mut c_char>(),
            size_ptr: sizep,
            capacity: size_of::<u32>(),
            data: Vec::new(),
        },
        frankenlibc_core::stdio::OpenFlags {
            writable: true,
            ..Default::default()
        },
    );
    if handle.is_null() {
        unsafe {
            crate::malloc_abi::free(initial.cast::<c_void>());
            *bufp = std::ptr::null_mut();
            *sizep = 0;
        }
        return std::ptr::null_mut();
    }
    let id = crate::stdio_abi::stream_id_from_handle(handle);
    let mut guard = wide_memstream_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(artifact_hash_map);
    map.insert(
        id,
        WideMemStreamSync {
            buf_loc: bufp,
            size_loc: sizep,
        },
    );

    handle
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

#[cfg(feature = "owned-tls-cache")]
static C16_SURROGATE_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<u32> =
    crate::owned_tls_cache::OwnedTlsCache::new(|| 0);

// Thread-local storage for UTF-16 surrogate pair state (mbrtoc16).
#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static C16_SURROGATE: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[inline]
fn c16_surrogate_get() -> u32 {
    #[cfg(feature = "owned-tls-cache")]
    {
        C16_SURROGATE_OWNED_TLS.with(|pending| *pending)
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        C16_SURROGATE.with(|cell| cell.get())
    }
}

#[inline]
fn c16_surrogate_set(value: u32) {
    #[cfg(feature = "owned-tls-cache")]
    {
        C16_SURROGATE_OWNED_TLS.with(|pending| *pending = value);
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        C16_SURROGATE.with(|cell| cell.set(value));
    }
}

/// Read the pending UTF-16 surrogate for an `mbrtoc16`/`c16rtomb` stream. glibc
/// keeps this state in the caller's `mbstate_t` so independent conversion
/// streams never collide; when `ps` is non-null we do the same, reading the
/// surrogate as a `u16` from bytes [6..8] of the state (`0` = none — a pending
/// surrogate is always 0xD800..=0xDFFF, so it is never zero). mbrtowc's
/// partial-multibyte state lives in bytes [0..6] of the same `mbstate_t`; the
/// two never overlap *in practice* because a pending surrogate only exists
/// AFTER a complete character has decoded (cleared partial), and a UTF-16 stream
/// only ever decodes <=4-byte UTF-8 (partial <= 3 bytes, never reaching [4..6]).
/// When `ps` is null we fall back to the thread-local, matching glibc's internal
/// static state for that case.
#[inline]
unsafe fn c16_pending_get(ps: *const c_void) -> u32 {
    if ps.is_null() {
        return c16_surrogate_get();
    }
    // SAFETY: `ps` is a valid `mbstate_t` (>= 8 bytes) per the C contract.
    let raw = unsafe { (ps as *const u8).add(6).cast::<u16>().read_unaligned() };
    raw as u32
}

/// Store (or clear, with `value == 0`) the pending UTF-16 surrogate for a
/// stream — in the caller's `mbstate_t` when `ps` is non-null, else the
/// thread-local fallback. See [`c16_pending_get`].
#[inline]
unsafe fn c16_pending_set(ps: *mut c_void, value: u32) {
    if ps.is_null() {
        c16_surrogate_set(value);
        return;
    }
    // SAFETY: `ps` is a valid `mbstate_t` (>= 8 bytes) per the C contract.
    unsafe {
        (ps as *mut u8)
            .add(6)
            .cast::<u16>()
            .write_unaligned(value as u16)
    };
}

/// Load mbrtowc's partial-multibyte state from bytes [0..6] of `ps`: byte 0 is
/// the count (0..=5) of pending lead bytes, bytes [1..1+count] are those bytes.
/// Five bytes of headroom lets an obsolete 6-byte UTF-8 sequence (RFC 2279,
/// which fl decodes for C.UTF-8 parity with glibc) be reassembled across
/// incremental calls. Returns the count (clamped to 5) and copies the bytes into
/// `out`.
#[inline]
unsafe fn mbstate_partial_load(ps: *const c_void, out: &mut [u8; 8]) -> usize {
    // SAFETY: `ps` is a valid `mbstate_t` (>= 8 bytes) per the C contract.
    let raw = unsafe { (ps as *const u8).cast::<[u8; 6]>().read_unaligned() };
    let count = (raw[0] as usize).min(5);
    out[..count].copy_from_slice(&raw[1..1 + count]);
    count
}

/// Store `bytes` (len <= 5) as mbrtowc's pending partial-multibyte state into
/// bytes [0..6] of `ps`, without touching the surrogate slot in [6..8].
#[inline]
unsafe fn mbstate_partial_store(ps: *mut c_void, bytes: &[u8]) {
    let mut raw = [0u8; 6];
    raw[0] = bytes.len() as u8;
    raw[1..1 + bytes.len()].copy_from_slice(bytes);
    // SAFETY: `ps` is a valid `mbstate_t` (>= 8 bytes) per the C contract.
    unsafe { (ps as *mut u8).cast::<[u8; 6]>().write_unaligned(raw) };
}

/// Clear mbrtowc's partial-multibyte state (bytes [0..6] of `ps`), leaving the
/// surrogate slot in [6..8] untouched.
#[inline]
unsafe fn mbstate_partial_clear(ps: *mut c_void) {
    // SAFETY: `ps` is a valid `mbstate_t` (>= 8 bytes) per the C contract.
    unsafe { (ps as *mut u8).cast::<[u8; 6]>().write_unaligned([0u8; 6]) };
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
    let pending = unsafe { c16_pending_get(ps) };

    if pending != 0 {
        // We have a high surrogate pending; this should be the low surrogate.
        unsafe { c16_pending_set(ps, 0) };
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
        unsafe { c16_pending_set(ps, c16 as u32) };
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
    let pending = unsafe { c16_pending_get(ps) };

    if pending != 0 {
        // We have a pending low surrogate to deliver.
        unsafe { c16_pending_set(ps, 0) };
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
        unsafe { c16_pending_set(ps, low) };
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
    let Some(property) = (unsafe { bounded_cstr_bytes(property) }) else {
        return 0;
    };
    match property {
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
    // Delegate to the optimized C-locale `wcsftime` (stack buffers + ASCII bulk transcode),
    // exactly like `wcsftime_l` does. The old separate body heap-allocated a `max*4` buffer
    // per call AND widened the multibyte output byte-by-byte (`b as wchar_t`), which is also
    // WRONG for any non-ASCII output (wcsftime decodes it with mbtowc). So this is both a
    // large speedup (it had the pre-fix wcsftime's ~5-32x-glibc overhead) and a correctness fix.
    unsafe { wcsftime(s, max, format, tm) }
}

// ===========================================================================
// NetBSD libutil — fgetwln (wide-char counterpart of fgetln)
// ===========================================================================
//
// `wchar_t * fgetwln(FILE * restrict stream, size_t * restrict lenp);`
//
// Reads the next line from `stream` (up to and including the trailing
// L'\n', or to EOF) and returns a pointer into a thread-local buffer
// plus the line length, in wide characters, via `*lenp`. Returns NULL
// (with `*lenp = 0`) on EOF before any character is read or on error.
//
// The returned pointer remains valid until the next `fgetwln` call on
// the same thread. The buffer is NOT NUL-terminated and callers MUST
// NOT modify or `free()` it.
//
// Built atop our own `fgetwc`, which already handles UTF-8 decoding and
// pushback of incomplete sequences.

#[cfg(feature = "owned-tls-cache")]
static FGETWLN_BUFFER_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<Vec<libc::wchar_t>> =
    crate::owned_tls_cache::OwnedTlsCache::new(Vec::new);

#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static FGETWLN_BUFFER: std::cell::RefCell<Vec<libc::wchar_t>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn fgetwln_read_into_buffer(
    stream: *mut std::ffi::c_void,
    buf: &mut Vec<libc::wchar_t>,
) -> Option<(*mut libc::wchar_t, usize)> {
    buf.clear();
    loop {
        // SAFETY: stream is a valid FILE* per caller; fgetwc handles UTF-8
        // decode and pushback of incomplete sequences.
        let wc = unsafe { fgetwc(stream) };
        if wc == WEOF_VALUE {
            // EOF or decode error. If we already have characters, return them
            // (last line without trailing newline).
            if buf.is_empty() {
                return None;
            }
            break;
        }
        buf.push(wc as libc::wchar_t);
        if wc == 0x0A {
            break;
        }
    }
    let ptr = buf.as_mut_ptr();
    let n = buf.len();
    Some((ptr, n))
}

#[cfg(feature = "owned-tls-cache")]
fn fgetwln_current_buffer(stream: *mut std::ffi::c_void) -> Option<(*mut libc::wchar_t, usize)> {
    FGETWLN_BUFFER_OWNED_TLS.with(|buf| fgetwln_read_into_buffer(stream, buf))
}

#[cfg(not(feature = "owned-tls-cache"))]
fn fgetwln_current_buffer(stream: *mut std::ffi::c_void) -> Option<(*mut libc::wchar_t, usize)> {
    FGETWLN_BUFFER.with(|cell| {
        let mut buf = cell.borrow_mut();
        fgetwln_read_into_buffer(stream, &mut buf)
    })
}

/// NetBSD libutil `fgetwln(stream, *lenp)` — wide-character line
/// reader. See module-level comment for semantics.
///
/// # Safety
///
/// `stream` must be a valid `FILE *`. `lenp`, when non-NULL, must
/// point to writable `size_t` storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetwln(
    stream: *mut std::ffi::c_void,
    lenp: *mut usize,
) -> *mut libc::wchar_t {
    if stream.is_null() {
        if !lenp.is_null() {
            // SAFETY: caller-supplied writable slot.
            unsafe { *lenp = 0 };
        }
        return std::ptr::null_mut();
    }

    let result = fgetwln_current_buffer(stream);

    match result {
        Some((ptr, n)) => {
            if !lenp.is_null() {
                // SAFETY: caller-supplied writable slot.
                unsafe { *lenp = n };
            }
            ptr
        }
        None => {
            if !lenp.is_null() {
                // SAFETY: caller-supplied writable slot.
                unsafe { *lenp = 0 };
            }
            std::ptr::null_mut()
        }
    }
}
