//! Wide-character string operations: wcslen, wcscpy, wcscmp.
//!
//! Corresponds to `<wchar.h>` functions. These operate on `u32` slices
//! representing `wchar_t` strings (NUL-terminated with `0u32`).

use std::simd::{Select, Simd, cmp::SimdOrd, cmp::SimdPartialEq, cmp::SimdPartialOrd};

/// Number of `u32` wide characters processed per NUL-only scan panel.
const WIDE_NUL_SIMD_LANES: usize = 16;

/// Number of `u32` wide characters processed per char-or-NUL candidate panel.
const WIDE_FIND_SIMD_LANES: usize = 32;

/// Number of `u32` wide characters processed per long char-or-NUL candidate panel.
const WIDE_FIND_LONG_SIMD_LANES: usize = 64;

/// Minimum input length for the long char-or-NUL scan. Keep shorter searches on
/// the narrower panel to avoid overpaying for single-panel probes.
const WIDE_FIND_LONG_MIN_LEN: usize = WIDE_FIND_LONG_SIMD_LANES * 4;

/// Number of `u32` wide characters compared per `wmemcmp` equality panel.
const WIDE_COMPARE_SIMD_LANES: usize = 16;

/// Number of `u32` wide characters compared per unrolled `wmemcmp` step.
const WIDE_COMPARE_UNROLL_LANES: usize = WIDE_COMPARE_SIMD_LANES * 2;

/// Minimum scan length before paying to recognize contiguous membership sets.
const WIDE_RANGE_MEMBERSHIP_MIN_LEN: usize = WIDE_COMPARE_SIMD_LANES * 32;

/// Minimum scan length before paying to certify a repeated accepted wide char.
const WIDE_MEMBER_REPEAT_LANES: usize = WIDE_FIND_LONG_SIMD_LANES;
const WIDE_MEMBER_REPEAT_MIN_LEN: usize = WIDE_MEMBER_REPEAT_LANES * 4;

/// Minimum bounded case-fold compare length before paying to detect repeated
/// fold-equal wide-character pairs.
const WIDE_CASE_REPEAT_LANES: usize = WIDE_FIND_LONG_SIMD_LANES;
const WIDE_CASE_REPEAT_MIN_LEN: usize = WIDE_CASE_REPEAT_LANES * 4;

/// Minimum bounded exact compare length before paying for a no-NUL-needed
/// equality preflight.
const WIDE_EQUAL_PREFIX_LANES: usize = WIDE_FIND_LONG_SIMD_LANES;
const WIDE_EQUAL_PREFIX_MIN_LEN: usize = WIDE_EQUAL_PREFIX_LANES * 4;

/// Number of `u32` wide characters searched per forward `wmemchr` panel.
const WIDE_MEMCHR_SIMD_LANES: usize = 16;

/// Number of `u32` wide characters searched per reverse `wmemrchr` panel.
const WIDE_REVERSE_SIMD_LANES: usize = 16;
const WIDE_REVERSE_LONG_SIMD_LANES: usize = WIDE_FIND_LONG_SIMD_LANES;
const WIDE_REVERSE_LONG_MIN_LEN: usize = WIDE_REVERSE_LONG_SIMD_LANES * 4;

// (has_wide_or_nul_simd / has_wide_or_nul_long_simd removed: find_wide_or_nul,
// find_wide_or_nul_long and wcsrchr now compute the needle/NUL lane index directly
// via masks instead of a bool prefilter + scalar resolve, so the prefilters are
// unused. bd-2g7oyh.)

// (equal_and_no_nul_wide removed: wcscmp/wcsncmp now resolve the divergence lane
// inline via an event-mask, so the bool prefilter is unused. bd-2g7oyh.)

#[inline(always)]
fn equal_and_no_nul_wide_unrolled(a: &[u32], b: &[u32]) -> bool {
    debug_assert_eq!(a.len(), WIDE_COMPARE_UNROLL_LANES);
    debug_assert_eq!(b.len(), WIDE_COMPARE_UNROLL_LANES);
    let av = Simd::<u32, WIDE_COMPARE_UNROLL_LANES>::from_slice(a);
    let bv = Simd::<u32, WIDE_COMPARE_UNROLL_LANES>::from_slice(b);
    av.simd_eq(bv).all() && !av.simd_eq(Simd::splat(0)).any()
}

/// Branchless ASCII A-Z -> a-z fold of a `u32` panel, exactly matching
/// [`simple_towlower`] (only code units in `0x41..=0x5A` are shifted by `0x20`;
/// everything else, including NUL, is unchanged).
#[inline(always)]
fn fold_ascii_upper_wide(
    v: Simd<u32, WIDE_COMPARE_SIMD_LANES>,
) -> Simd<u32, WIDE_COMPARE_SIMD_LANES> {
    let is_upper = v.simd_ge(Simd::splat(0x41)) & v.simd_le(Simd::splat(0x5A));
    is_upper.select(v + Simd::splat(0x20), v)
}

// (fold_equal_and_no_nul_wide removed: wcscasecmp/wcsncasecmp now resolve the
// divergence lane inline via a fold-event-mask, so the bool prefilter is unused.
// bd-2g7oyh.)

/// Returns `true` when a 32-wide panel consists entirely of one non-NUL
/// code-unit pair whose ASCII-folded values are equal. This narrow fast path
/// handles long repeated case-equivalent runs (`A...` vs `a...`); every panel
/// that does not meet the certificate falls back to the regular fold/scalar
/// resolver without advancing.
#[inline(always)]
fn repeated_case_pair_equal_and_no_nul_wide(a: &[u32], b: &[u32]) -> bool {
    debug_assert_eq!(a.len(), WIDE_COMPARE_UNROLL_LANES);
    debug_assert_eq!(b.len(), WIDE_COMPARE_UNROLL_LANES);

    let first_a = a[0];
    let first_b = b[0];
    if first_a == 0 || simple_towlower(first_a) != simple_towlower(first_b) {
        return false;
    }

    let av = Simd::<u32, WIDE_COMPARE_UNROLL_LANES>::from_slice(a);
    let bv = Simd::<u32, WIDE_COMPARE_UNROLL_LANES>::from_slice(b);
    av.simd_eq(Simd::splat(first_a)).all() && bv.simd_eq(Simd::splat(first_b)).all()
}

/// The 64-wide variant of [`repeated_case_pair_equal_and_no_nul_wide`] for long
/// fold-equal runs. This is the same certificate over a wider panel: both
/// inputs must be one repeated non-NUL code unit and their ASCII folds must
/// match, otherwise the scalar resolver keeps the first-difference semantics.
#[inline(always)]
fn repeated_case_pair_equal_and_no_nul_wide_long(a: &[u32], b: &[u32]) -> bool {
    debug_assert_eq!(a.len(), WIDE_CASE_REPEAT_LANES);
    debug_assert_eq!(b.len(), WIDE_CASE_REPEAT_LANES);

    let first_a = a[0];
    let first_b = b[0];
    if first_a == 0 || simple_towlower(first_a) != simple_towlower(first_b) {
        return false;
    }

    let av = Simd::<u32, WIDE_CASE_REPEAT_LANES>::from_slice(a);
    let bv = Simd::<u32, WIDE_CASE_REPEAT_LANES>::from_slice(b);
    av.simd_eq(Simd::splat(first_a)).all() && bv.simd_eq(Simd::splat(first_b)).all()
}

/// Returns `true` when the first `n` wide code units are exactly equal.
/// `wcsncmp` can return zero immediately in that case, even when a shared NUL
/// appears before `n`; any mismatch falls back to the existing scalar resolver
/// to preserve the first-difference ordering.
#[inline(always)]
fn equal_prefix_wide(a: &[u32], b: &[u32], n: usize) -> bool {
    debug_assert!(n <= a.len());
    debug_assert!(n <= b.len());

    let mut i = 0;
    while i + WIDE_EQUAL_PREFIX_LANES <= n {
        let av =
            Simd::<u32, WIDE_EQUAL_PREFIX_LANES>::from_slice(&a[i..i + WIDE_EQUAL_PREFIX_LANES]);
        let bv =
            Simd::<u32, WIDE_EQUAL_PREFIX_LANES>::from_slice(&b[i..i + WIDE_EQUAL_PREFIX_LANES]);
        if !av.simd_eq(bv).all() {
            return false;
        }
        i += WIDE_EQUAL_PREFIX_LANES;
    }
    a[i..n]
        .iter()
        .zip(&b[i..n])
        .all(|(left, right)| left == right)
}

/// Returns `true` iff the two long `wmemcmp` panels are exactly equal. Unlike
/// the NUL-terminated compare helpers, this intentionally ignores NUL because
/// `wmemcmp` compares raw wide-code-unit arrays over an explicit length.
#[inline(always)]
fn equal_wide_long_panel(a: &[u32], b: &[u32]) -> bool {
    debug_assert_eq!(a.len(), WIDE_EQUAL_PREFIX_LANES);
    debug_assert_eq!(b.len(), WIDE_EQUAL_PREFIX_LANES);
    let av = Simd::<u32, WIDE_EQUAL_PREFIX_LANES>::from_slice(a);
    let bv = Simd::<u32, WIDE_EQUAL_PREFIX_LANES>::from_slice(b);
    av.simd_eq(bv).all()
}

#[inline(always)]
fn resolve_wmemcmp_panel(a_chunk: &[u32], b_chunk: &[u32]) -> Option<i32> {
    debug_assert_eq!(a_chunk.len(), b_chunk.len());
    debug_assert_eq!(a_chunk.len(), WIDE_COMPARE_SIMD_LANES);
    // First differing lane via the SIMD mask + trailing_zeros (O(1)) instead of a
    // scalar element-by-element re-scan of the panel (wmemcmp was ~6x slower than
    // glibc on a deep-in-panel difference; bd-2g7oyh). Callers always pass exactly
    // WIDE_COMPARE_SIMD_LANES (16) elements.
    let av = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(a_chunk);
    let bv = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(b_chunk);
    let diff = av.simd_ne(bv).to_bitmask();
    if diff != 0 {
        let j = diff.trailing_zeros() as usize;
        let a = a_chunk[j] as i32;
        let b = b_chunk[j] as i32;
        return Some(if a < b { -1 } else { 1 });
    }
    None
}

/// Returns the index of the first element of `s` equal to `needle` or `0`
/// (whichever comes first, left to right), or `s.len()` if neither is present.
///
/// `needle` must be non-zero so the two splat targets are distinct; callers in
/// this module only invoke it with a non-NUL first needle character.
fn find_wide_or_nul(s: &[u32], needle: u32) -> usize {
    debug_assert_ne!(needle, 0);
    let mut chunks = s.chunks_exact(WIDE_FIND_SIMD_LANES);
    let mut base = 0usize;

    for chunk in chunks.by_ref() {
        // First needle-or-NUL lane via the mask (O(1)) instead of detect + scalar
        // enumerate of the flagged 32-element chunk (bd-2g7oyh).
        let lanes = Simd::<u32, WIDE_FIND_SIMD_LANES>::from_slice(chunk);
        let m = (lanes.simd_eq(Simd::splat(needle)) | lanes.simd_eq(Simd::splat(0))).to_bitmask();
        if m != 0 {
            return base + m.trailing_zeros() as usize;
        }
        base += WIDE_FIND_SIMD_LANES;
    }

    // Sub-chunk remainder (1..LANES-1 elements). When the whole input is at least
    // one lane wide, finish it with ONE OVERLAPPING 32-lane load anchored at the
    // end instead of a scalar tail (which for e.g. 60 wc left ~half the input
    // scalar). The overlap region `[len-LANES .. base]` lies inside an
    // already-scanned chunk that held no needle/NUL, so the leftmost hit in the
    // window is exactly the first hit in the remainder — byte-identical.
    let rem = chunks.remainder();
    if !rem.is_empty() {
        if s.len() >= WIDE_FIND_SIMD_LANES {
            let start = s.len() - WIDE_FIND_SIMD_LANES;
            let lanes = Simd::<u32, WIDE_FIND_SIMD_LANES>::from_slice(&s[start..]);
            let m =
                (lanes.simd_eq(Simd::splat(needle)) | lanes.simd_eq(Simd::splat(0))).to_bitmask();
            if m != 0 {
                return start + m.trailing_zeros() as usize;
            }
        } else {
            for (j, &ch) in rem.iter().enumerate() {
                if ch == needle || ch == 0 {
                    return base + j;
                }
            }
        }
    }

    s.len()
}

fn find_wide_or_nul_long(s: &[u32], needle: u32) -> usize {
    debug_assert_ne!(needle, 0);
    // Fold four 64-lane panels per 256-element block into ONE horizontal
    // reduction (bd-2g7oyh.262 follow-up). For each lane, `min(x, x ^ needle)` is
    // `0` iff `x == 0` (NUL: `min(0, needle) == 0`) OR `x == needle`
    // (`min(needle, 0) == 0`), and strictly positive otherwise — so `simd_min` of
    // the four panels' `min(x, x ^ needle)` is `0` exactly when one panel holds a
    // NUL or the needle. One reduction per 256 wide chars instead of one per 64;
    // the scalar tail resolves the leftmost hit in a flagged block.
    const PANEL: usize = WIDE_FIND_LONG_SIMD_LANES; // 64
    const BLOCK: usize = WIDE_FIND_LONG_MIN_LEN; // PANEL * 4 == 256
    let target = Simd::<u32, PANEL>::splat(needle);
    let zero = Simd::<u32, PANEL>::splat(0);
    let mut base = 0usize;

    while base + BLOCK <= s.len() {
        let block = &s[base..base + BLOCK];
        let hit = |k: usize| {
            let p = Simd::<u32, PANEL>::from_slice(&block[k * PANEL..(k + 1) * PANEL]);
            p.simd_min(p ^ target)
        };
        let folded = hit(0).simd_min(hit(1)).simd_min(hit(2).simd_min(hit(3)));
        if folded.simd_eq(zero).any() {
            // Resolve the first needle-or-NUL panel + lane via masks (O(1)) instead
            // of a scalar enumerate of the 256-element block (bd-2g7oyh). `hit(k)` is
            // 0 exactly at needle/NUL lanes.
            let m0 = hit(0).simd_eq(zero).to_bitmask();
            if m0 != 0 {
                return base + m0.trailing_zeros() as usize;
            }
            let m1 = hit(1).simd_eq(zero).to_bitmask();
            if m1 != 0 {
                return base + PANEL + m1.trailing_zeros() as usize;
            }
            let m2 = hit(2).simd_eq(zero).to_bitmask();
            if m2 != 0 {
                return base + 2 * PANEL + m2.trailing_zeros() as usize;
            }
            let m3 = hit(3).simd_eq(zero).to_bitmask();
            return base + 3 * PANEL + m3.trailing_zeros() as usize;
        }
        base += BLOCK;
    }

    // Tail (< 256 wide chars): the 32-lane short-path scan over the remainder.
    base + find_wide_or_nul(&s[base..], needle)
}

/// Returns the length of a NUL-terminated wide string (not counting the NUL).
///
/// Equivalent to C `wcslen`. Scans `s` for the first `0u32` element.
/// If no NUL is found, returns the full slice length.
///
/// Scans `WIDE_NUL_SIMD_LANES` elements per step with a portable-SIMD NUL probe,
/// then resolves the exact index within the first matching panel left-to-right.
/// Behaviour is identical to a scalar `position(|&c| c == 0)` scan.
pub fn wcslen(s: &[u32]) -> usize {
    // Fold four 64-lane panels per 256-element block into ONE horizontal
    // reduction (mirroring the narrow `block_has_nul_256` for strlen). Because
    // `min(a, b) == 0` iff either lane is `0`, the folded vector has a zero lane
    // exactly when one of the four panels does, so the steady-state NUL-free scan
    // pays a single reduction per 256 wide chars instead of one per 16. The
    // scalar tail resolves the exact index inside a flagged block, so the
    // returned length is identical to the per-chunk scan (bd-2g7oyh).
    const PANEL: usize = WIDE_FIND_LONG_SIMD_LANES; // 64
    let zero = Simd::<u32, PANEL>::splat(0);
    let mut base = 0usize;

    // Direct 64-lane NUL mask scan: one `simd_eq(0).to_bitmask()` per panel, resolved
    // by `trailing_zeros`. The prior 256-block min-FOLD (3 `simd_min` + `.any()` on
    // 64-lane = 8 ymm each) did MORE vector work than a plain per-panel movemask and
    // measured 2.6x slower than glibc's wcslen; the direct mask scan removes the fold
    // overhead (same fix as wmemchr). Byte-identical: same leftmost NUL. bd-2g7oyh.
    while base + PANEL <= s.len() {
        let v = Simd::<u32, PANEL>::from_slice(&s[base..base + PANEL]);
        let m = v.simd_eq(zero).to_bitmask();
        if m != 0 {
            return base + m.trailing_zeros() as usize;
        }
        base += PANEL;
    }

    // Tail (< 256 wide chars): 16-lane chunks, then scalar.
    let mut chunks = s[base..].chunks_exact(WIDE_NUL_SIMD_LANES);
    for chunk in chunks.by_ref() {
        let lanes = Simd::<u32, WIDE_NUL_SIMD_LANES>::from_slice(chunk);
        // First NUL lane via the mask (O(1)) instead of a scalar enumerate of the
        // flagged 16-element chunk (bd-2g7oyh).
        let m = lanes.simd_eq(Simd::splat(0)).to_bitmask();
        if m != 0 {
            return base + m.trailing_zeros() as usize;
        }
        base += WIDE_NUL_SIMD_LANES;
    }

    for (j, &ch) in chunks.remainder().iter().enumerate() {
        if ch == 0 {
            return base + j;
        }
    }

    s.len()
}

/// Returns the length of a wide string, bounded by `maxlen`.
///
/// Equivalent to C `wcsnlen`.
pub fn wcsnlen(s: &[u32], maxlen: usize) -> usize {
    // Direct 64-lane NUL mask scan bounded by `maxlen`: one `simd_eq(0).to_bitmask()`
    // per panel, resolved by `trailing_zeros`. The prior 256-block min-FOLD did MORE
    // vector work than a plain per-panel movemask (same single-condition pessimization
    // as wcslen, which this mirrors). Byte-identical to the scalar
    // `position(NUL).unwrap_or(limit)` scan. bd-2g7oyh.
    const PANEL: usize = WIDE_FIND_LONG_SIMD_LANES; // 64
    let limit = maxlen.min(s.len());
    let scan = &s[..limit];
    let zero = Simd::<u32, PANEL>::splat(0);
    let mut base = 0usize;

    while base + PANEL <= limit {
        let v = Simd::<u32, PANEL>::from_slice(&scan[base..base + PANEL]);
        let m = v.simd_eq(zero).to_bitmask();
        if m != 0 {
            return base + m.trailing_zeros() as usize;
        }
        base += PANEL;
    }

    let mut chunks = scan[base..].chunks_exact(WIDE_NUL_SIMD_LANES);
    for chunk in chunks.by_ref() {
        let lanes = Simd::<u32, WIDE_NUL_SIMD_LANES>::from_slice(chunk);
        // First NUL lane via the mask (O(1)) instead of a scalar enumerate of the
        // flagged 16-element chunk (bd-2g7oyh).
        let m = lanes.simd_eq(Simd::splat(0)).to_bitmask();
        if m != 0 {
            return base + m.trailing_zeros() as usize;
        }
        base += WIDE_NUL_SIMD_LANES;
    }
    for (j, &ch) in chunks.remainder().iter().enumerate() {
        if ch == 0 {
            return base + j;
        }
    }
    limit
}

/// Computes the display width of up to `n` wide characters.
///
/// Equivalent to C `wcswidth`. Returns `-1` if any character is non-printable.
pub fn wcswidth(s: &[u32], n: usize) -> i32 {
    let mut total = 0_i32;
    for &wc in s.iter().take(n) {
        if wc == 0 {
            break;
        }
        let width = super::wchar::wcwidth(wc);
        if width < 0 {
            return -1;
        }
        total = total.saturating_add(width);
    }
    total
}

/// Copies a NUL-terminated wide string from `src` into `dest`.
///
/// Equivalent to C `wcscpy`. Copies elements from `src` until (and including)
/// the NUL terminator. Returns the number of elements copied (including NUL).
///
/// # Panics
///
/// Panics if `dest` is too small to hold `src` plus the NUL terminator.
pub fn wcscpy(dest: &mut [u32], src: &[u32]) -> usize {
    let src_len = wcslen(src);
    assert!(
        dest.len() > src_len,
        "wcscpy: destination buffer too small ({} elements for {} element string + NUL)",
        dest.len(),
        src_len
    );
    dest[..src_len].copy_from_slice(&src[..src_len]);
    dest[src_len] = 0;
    src_len + 1
}

/// Copies a wide string from `src` into `dest` with a size limit.
///
/// Equivalent to C `wcsncpy`. Copies at most `n` wide characters.
/// If `src` is shorter than `n`, the remaining elements in `dest` are filled with NULs.
/// If `src` is longer or equal to `n`, `dest` will NOT be NUL-terminated.
///
/// Returns `dest`.
///
/// # Panics
///
/// Panics if `dest` is smaller than `n`.
pub fn wcsncpy(dest: &mut [u32], src: &[u32], n: usize) {
    assert!(
        dest.len() >= n,
        "wcsncpy: destination buffer too small ({} elements for request {})",
        dest.len(),
        n
    );
    let src_len = wcslen(src);
    let copy_len = src_len.min(n);

    // Copy characters
    dest[..copy_len].copy_from_slice(&src[..copy_len]);

    // Pad with NULs if necessary
    if copy_len < n {
        dest[copy_len..n].fill(0);
    }
}

/// Appends the wide string `src` to the end of `dest`.
///
/// Equivalent to C `wcscat`. Finds the NUL terminator in `dest` and overwrites it
/// with the contents of `src` (including `src`'s NUL terminator).
///
/// Returns the new length of `dest` (including NUL).
///
/// # Panics
///
/// Panics if `dest` does not have enough space after its current NUL terminator
/// to hold `src`.
pub fn wcscat(dest: &mut [u32], src: &[u32]) -> usize {
    let dest_len = wcslen(dest);
    let src_len = wcslen(src);
    let needed = dest_len + src_len + 1;

    assert!(
        dest.len() >= needed,
        "wcscat: destination buffer too small ({} elements for {} needed)",
        dest.len(),
        needed
    );

    dest[dest_len..dest_len + src_len].copy_from_slice(&src[..src_len]);
    dest[dest_len + src_len] = 0;
    needed
}

/// Compares two NUL-terminated wide strings lexicographically.
///
/// Equivalent to C `wcscmp`. Compares element-by-element until a difference
/// is found or both strings reach a NUL terminator.
///
/// Returns a negative value if `s1 < s2`, zero if equal, positive if `s1 > s2`.
/// Performs signed comparison (treating `u32` as `i32`) to match Linux `wchar_t`.
pub fn wcscmp(s1: &[u32], s2: &[u32]) -> i32 {
    // SIMD fast path: stride WIDE_COMPARE_SIMD_LANES-element panels that are
    // element-for-element equal and NUL-free, bounded by the shorter slice.
    // The first panel that diverges OR holds a NUL drops to the scalar tail,
    // which resolves the exact index — identical result to the scalar scan.
    let bounded = s1.len().min(s2.len());
    let mut i = 0;
    while i + WIDE_COMPARE_SIMD_LANES <= bounded {
        let av = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(&s1[i..i + WIDE_COMPARE_SIMD_LANES]);
        let bv = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(&s2[i..i + WIDE_COMPARE_SIMD_LANES]);
        // First lane that differs OR is NUL in s1 — resolve the divergence index via
        // the SIMD mask (O(1)) instead of breaking to the scalar tail and re-scanning
        // the broken panel element-by-element (wcscmp was 3.25x slower than glibc on a
        // deep-in-panel difference; bd-2g7oyh). Matches equal_and_no_nul_wide's break
        // (`!(eq.all()) || nul-in-a`) and the scalar tail's `a!=b || a==0` resolution.
        let event = av.simd_ne(bv) | av.simd_eq(Simd::splat(0));
        let bits = event.to_bitmask();
        if bits != 0 {
            let j = i + bits.trailing_zeros() as usize;
            let a = s1[j];
            let b = s2[j];
            if a != b {
                // wchar_t is i32 on Linux, so we must compare as signed.
                return if (a as i32) < (b as i32) { -1 } else { 1 };
            }
            return 0; // shared NUL terminator
        }
        i += WIDE_COMPARE_SIMD_LANES;
    }

    loop {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };

        if a != b {
            // wchar_t is i32 on Linux, so we must compare as signed.
            if (a as i32) < (b as i32) {
                return -1;
            } else {
                return 1;
            }
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
}

/// Compares at most `n` wide characters of two strings.
///
/// Equivalent to C `wcsncmp`.
pub fn wcsncmp(s1: &[u32], s2: &[u32], n: usize) -> i32 {
    // SIMD fast path over equal, NUL-free panels within the n-bounded prefix
    // present in both slices; the scalar tail resolves the exact divergence/NUL
    // index and out-of-range (logical NUL) bytes, identical to the scalar scan.
    let bounded = n.min(s1.len()).min(s2.len());
    let mut i = 0;
    if n >= WIDE_EQUAL_PREFIX_MIN_LEN
        && n <= s1.len()
        && n <= s2.len()
        && equal_prefix_wide(s1, s2, n)
    {
        return 0;
    }
    while i + WIDE_COMPARE_UNROLL_LANES <= bounded {
        if !equal_and_no_nul_wide_unrolled(
            &s1[i..i + WIDE_COMPARE_UNROLL_LANES],
            &s2[i..i + WIDE_COMPARE_UNROLL_LANES],
        ) {
            break;
        }
        i += WIDE_COMPARE_UNROLL_LANES;
    }
    while i + WIDE_COMPARE_SIMD_LANES <= bounded {
        let av = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(&s1[i..i + WIDE_COMPARE_SIMD_LANES]);
        let bv = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(&s2[i..i + WIDE_COMPARE_SIMD_LANES]);
        // First lane that differs OR is NUL in s1 — O(1) divergence index via the
        // SIMD mask instead of breaking to the scalar tail and re-scanning the panel
        // (same fix as wcscmp; bd-2g7oyh). Matches equal_and_no_nul_wide's break and
        // the scalar tail's `a!=b || a==0`.
        let event = av.simd_ne(bv) | av.simd_eq(Simd::splat(0));
        let bits = event.to_bitmask();
        if bits != 0 {
            let j = i + bits.trailing_zeros() as usize;
            let a = s1[j];
            let b = s2[j];
            if a != b {
                return if (a as i32) < (b as i32) { -1 } else { 1 };
            }
            return 0;
        }
        i += WIDE_COMPARE_SIMD_LANES;
    }

    while i < n {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };

        if a != b {
            if (a as i32) < (b as i32) {
                return -1;
            } else {
                return 1;
            }
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
    0
}

/// Locates the first occurrence of wide character `c` in string `s`.
///
/// Equivalent to C `wcschr`. Returns the index of the character, or `None` if not found.
/// The terminating NUL character is considered part of the string.
///
/// Reuses the SIMD [`find_wide_or_nul`] panel scan: it locates the first
/// occurrence of `c` or a terminating NUL, whichever comes first. If that
/// position holds `c`, the scan reached `c` before any NUL; otherwise the
/// string ended first and `c` is absent. The `c == 0` case matches the
/// terminator via the SIMD [`wcslen`] scan. Behaviour is identical to a scalar
/// "return at first `c`, stop at NUL" loop.
pub fn wcschr(s: &[u32], c: u32) -> Option<usize> {
    if c == 0 {
        // wcschr(s, 0) returns the index of the terminating NUL, or None if the
        // slice has no NUL. `wcslen` returns `s.len()` when no NUL is present.
        let len = wcslen(s);
        return (len < s.len()).then_some(len);
    }

    // `find_wide_or_nul_long` already returns the first `c`-or-NUL position, and the
    // `s[pos]==c` check below rejects the not-found case — so the prior
    // `wmemchr(s, c, s.len())?` existence pre-scan was a redundant SECOND full pass
    // (and it scanned all of `s.len()` past the NUL). Removed (bd-2g7oyh).
    let pos = find_wide_or_nul_long(s, c);
    (pos < s.len() && s[pos] == c).then_some(pos)
}

/// Locates the last occurrence of wide character `c` in string `s`.
///
/// Equivalent to C `wcsrchr`. Returns the index of the character, or `None` if not found.
/// The terminating NUL character is considered part of the string.
pub fn wcsrchr(s: &[u32], c: u32) -> Option<usize> {
    if c == 0 {
        for (i, &ch) in s.iter().enumerate() {
            if ch == 0 {
                return Some(i);
            }
        }
        return Some(s.len());
    }

    // The scan below already returns the last `c` before the NUL (or None) — so the
    // prior `wmemrchr(s, c, s.len())?` existence pre-scan was a redundant SECOND full
    // pass (scanning all of `s.len()` past the NUL). Removed (bd-2g7oyh), same as wcschr.
    let mut last = None;
    if s.len() >= WIDE_FIND_LONG_SIMD_LANES {
        let mut chunks = s.chunks_exact(WIDE_FIND_LONG_SIMD_LANES);
        let mut base = 0usize;

        for chunk in chunks.by_ref() {
            // Last `c` before the first NUL in this 64-lane chunk via masks (O(1))
            // instead of a scalar element-by-element inner scan (bd-2g7oyh). If the
            // chunk holds a NUL, the answer is the highest `c` lane below the first
            // NUL lane (or `last` from prior chunks); else the highest `c` lane
            // updates `last`. `63 - leading_zeros` = highest set lane (last match).
            let lanes = Simd::<u32, WIDE_FIND_LONG_SIMD_LANES>::from_slice(chunk);
            let nul_m = lanes.simd_eq(Simd::splat(0));
            let c_m = lanes.simd_eq(Simd::splat(c));
            // Cheap combined prefilter (one reduction) keeps the NUL-free/c-free
            // throughput identical to the old has_wide_or_nul_long_simd gate; only
            // a flagged chunk pays the two movemasks below.
            if !(nul_m | c_m).any() {
                base += WIDE_FIND_LONG_SIMD_LANES;
                continue;
            }
            let nul_bits = nul_m.to_bitmask() as u64;
            let c_bits = c_m.to_bitmask() as u64;
            if nul_bits != 0 {
                let first_nul = nul_bits.trailing_zeros();
                let c_before = c_bits & ((1u64 << first_nul) - 1);
                if c_before != 0 {
                    return Some(base + 63 - c_before.leading_zeros() as usize);
                }
                return last;
            }
            // Gate fired with no NUL → c_bits != 0: highest `c` lane updates `last`.
            last = Some(base + 63 - c_bits.leading_zeros() as usize);
            base += WIDE_FIND_LONG_SIMD_LANES;
        }

        for (j, &ch) in chunks.remainder().iter().enumerate() {
            if ch == 0 {
                return last;
            }
            if ch == c {
                last = Some(base + j);
            }
        }

        return last;
    }

    let mut chunks = s.chunks_exact(WIDE_FIND_SIMD_LANES);
    let mut base = 0usize;

    for chunk in chunks.by_ref() {
        // Last `c` before the first NUL in this 32-lane chunk via masks (O(1)) —
        // same nul-before-c resolution as the 64-lane path above (bd-2g7oyh).
        let lanes = Simd::<u32, WIDE_FIND_SIMD_LANES>::from_slice(chunk);
        let nul_m = lanes.simd_eq(Simd::splat(0));
        let c_m = lanes.simd_eq(Simd::splat(c));
        if !(nul_m | c_m).any() {
            base += WIDE_FIND_SIMD_LANES;
            continue;
        }
        let nul_bits = nul_m.to_bitmask() as u64;
        let c_bits = c_m.to_bitmask() as u64;
        if nul_bits != 0 {
            let first_nul = nul_bits.trailing_zeros();
            let c_before = c_bits & ((1u64 << first_nul) - 1);
            if c_before != 0 {
                return Some(base + 63 - c_before.leading_zeros() as usize);
            }
            return last;
        }
        last = Some(base + 63 - c_bits.leading_zeros() as usize);
        base += WIDE_FIND_SIMD_LANES;
    }

    for (j, &ch) in chunks.remainder().iter().enumerate() {
        if ch == 0 {
            return last;
        }
        if ch == c {
            last = Some(base + j);
        }
    }

    last
}

/// Locates the first occurrence of substring `needle` in `haystack`.
///
/// Equivalent to C `wcsstr`. Returns the index of the start of the substring,
/// or `None` if not found.
/// Pure Two-Way (Crochemore–Perrin) substring search over wide chars: O(n+m)
/// time, O(1) space, leftmost match. The byte `memmem` Two-Way additionally
/// uses a 256-entry Horspool/byteset skip, which cannot apply to the 2^32 wide
/// alphabet, so this is the unaugmented core. Used by `wcsstr` to bound its
/// first-char-probe O(n*m) pathology. `ndl` is non-empty and `ndl.len() <=
/// hay.len()`. Returns the algorithm-independent leftmost match offset, so it
/// is output-equivalent to the naive scan.
fn two_way_search_wide(hay: &[u32], ndl: &[u32]) -> Option<usize> {
    let l = ndl.len();
    let li = l as isize;

    // Maximal suffix under "<=" (reverse=false) and ">=" (reverse=true); the
    // later critical position with the global period `p`.
    let max_suffix = |reverse: bool| -> (isize, isize) {
        let mut ip: isize = -1;
        let mut jp: isize = 0;
        let mut k: isize = 1;
        let mut p: isize = 1;
        while jp + k < li {
            let a = ndl[(ip + k) as usize];
            let b = ndl[(jp + k) as usize];
            let take = if reverse { a < b } else { a > b };
            if a == b {
                if k == p {
                    jp += p;
                    k = 1;
                } else {
                    k += 1;
                }
            } else if take {
                jp += k;
                k = 1;
                p = jp - ip;
            } else {
                ip = jp;
                jp += 1;
                k = 1;
                p = 1;
            }
        }
        (ip, p)
    };

    let (ms_le, p0) = max_suffix(false);
    let (ms_ge, p_ge) = max_suffix(true);
    let (ms, mut p) = if ms_ge > ms_le {
        (ms_ge, p_ge)
    } else {
        (ms_le, p0)
    };

    let suffix = (ms + 1) as usize;
    let periodic = (0..suffix).all(|i| ndl.get(p as usize + i) == Some(&ndl[i]));
    let mem0: isize = if periodic {
        li - p
    } else {
        p = core::cmp::max(ms, li - ms - 1) + 1;
        0
    };

    let mut mem: isize = 0;
    let mut pos: usize = 0;
    loop {
        if pos + l > hay.len() {
            return None;
        }

        // Right factor: compare from the critical position rightward.
        let mut k = (ms + 1) as usize;
        while k < l && ndl[k] == hay[pos + k] {
            k += 1;
        }
        if k < l {
            pos += (k as isize - ms) as usize;
            mem = 0;
            continue;
        }

        // Left factor: compare the head down to the remembered prefix.
        let mut j = ms + 1;
        while j > mem && ndl[(j - 1) as usize] == hay[pos + (j - 1) as usize] {
            j -= 1;
        }
        if j <= mem {
            return Some(pos);
        }
        pos += p as usize;
        mem = mem0;
    }
}

/// Static byte-frequency estimate for choosing the rarer wcsstr anchor char
/// (mirrors mem.rs `memmem_anchor_commonness`; ASCII English text frequencies,
/// non-ASCII wide chars treated as rare). Lower = rarer = better anchor.
fn wide_anchor_commonness(c: u32) -> u8 {
    if c >= 128 {
        return 1;
    }
    match (c as u8).to_ascii_lowercase() {
        b' ' | b'e' => 16,
        b'a' | b'i' | b'n' | b'o' | b'r' | b's' | b't' => 12,
        b'c' | b'd' | b'f' | b'g' | b'h' | b'l' | b'm' | b'p' | b'u' | b'w' | b'y' => 8,
        b'_' | b'-' | b'.' | b'/' | b'\t' | b'\n' | b'\r' => 6,
        b'0'..=b'9' => 5,
        b'!'..=b'~' => 4,
        0 => 2,
        _ => 1,
    }
}

pub fn wcsstr(haystack: &[u32], needle: &[u32]) -> Option<usize> {
    let needle_len = wcslen(needle);
    if needle_len == 0 {
        return Some(0);
    }
    let needle = &needle[..needle_len];
    let first = needle[0];
    // (Removed a redundant `wmemchr(haystack, first, haystack.len())?` existence
    // pre-scan — a full extra pass past the NUL. `find_wide_or_nul_long` below +
    // the `first_pos == len || haystack[first_pos] == 0` check already return None
    // when `first` does not occur before the terminator. bd-2g7oyh, as in wcschr.)
    let first_pos = find_wide_or_nul_long(haystack, first);
    if first_pos == haystack.len() || haystack[first_pos] == 0 {
        return None;
    }

    let h_len = first_pos + wcslen(&haystack[first_pos..]);
    let hay = &haystack[..h_len];
    if needle_len > h_len {
        return None;
    }

    let last = needle[needle_len - 1];

    // Dual-anchor fast path: a match at `start` requires both the first needle
    // char at `start` *and* the last needle char at `start + needle_len - 1`.
    // When the first char is common (e.g. L"aaaa…b" over an 'a' run) but the
    // last char is rare/absent, anchoring on the last char collapses the search
    // to a single SIMD pass — the previous first-char-only scan made every
    // position a candidate (O(n*m)). We anchor on the last char so its
    // (typically rarer) occurrences drive the scan; for each hit we confirm the
    // first char and full needle. Only valid when `first != last`; otherwise the
    // two anchors coincide and we fall back to the first-char scan below.
    // Only anchor on the last char when it is RARER than the first (else the
    // last-char scan visits more candidates than the first-char path — e.g. text
    // ending in common 'e'). Mirrors mem.rs's memmem rarity-aware anchor. The
    // chosen anchor changes only the search strategy, not the (leftmost) result.
    if first != last && wide_anchor_commonness(last) <= wide_anchor_commonness(first) {
        // The earliest possible match starts at `first_pos`, so its last-char
        // anchor sits at `first_pos + needle_len - 1`. `hay` has no interior NUL
        // (truncated by `wcslen`), so `find_wide_or_nul` resolves the last char.
        let mut anchor = first_pos + needle_len - 1;
        let mut miss_work = 0usize;
        while anchor < hay.len() {
            let scan = &hay[anchor..];
            let offset = find_wide_or_nul(scan, last);
            if offset == scan.len() {
                return None; // last char never recurs → no match
            }
            let last_pos = anchor + offset;
            let start = last_pos - (needle_len - 1);
            if hay[start] == first && hay[start..start + needle_len] == *needle {
                return Some(start);
            }
            miss_work += needle_len;
            anchor = last_pos + 1;
            if miss_work > hay.len() {
                return two_way_search_wide(&hay[start..], needle).map(|m| m + start);
            }
        }
        return None;
    }

    // Fast path: jump to each first-char candidate via the SIMD `find_wide_or_nul`
    // scan and verify the full needle there. To keep the O(n+m) worst case, bail
    // to the pure Two-Way once cumulative failed-candidate work exceeds the
    // haystack length — so a common needle first char (e.g. L"aaaa…a" over an
    // 'a' run, which previously made every position a candidate: O(n*m)) cannot
    // degrade. Both paths return the leftmost match. `wcslen` bounds both
    // operands before their terminating NUL, preserving wide-string semantics.
    let mut start = first_pos;
    let mut miss_work = 0usize;
    while start + needle_len <= hay.len() {
        let scan = &hay[start..];
        let offset = find_wide_or_nul(scan, first);
        if offset == scan.len() {
            return None; // first char does not occur again → no match
        }
        let cand = start + offset;
        if cand + needle_len > hay.len() {
            return None; // not enough room left for the needle
        }
        if hay[cand..cand + needle_len] == *needle {
            return Some(cand);
        }
        miss_work += needle_len;
        start = cand + 1;
        if miss_work > hay.len() {
            return two_way_search_wide(&hay[start..], needle).map(|m| m + start);
        }
    }
    None
}

/// Copies `n` wide characters from `src` to `dest`.
///
/// Equivalent to C `wmemcpy`.
pub fn wmemcpy(dest: &mut [u32], src: &[u32], n: usize) -> usize {
    let count = n.min(dest.len()).min(src.len());
    dest[..count].copy_from_slice(&src[..count]);
    count
}

/// Copies `n` wide characters from `src` to `dest`, handling overlap.
///
/// Equivalent to C `wmemmove`.
pub fn wmemmove(dest: &mut [u32], src: &[u32], n: usize) -> usize {
    let count = n.min(dest.len()).min(src.len());
    dest[..count].copy_from_slice(&src[..count]);
    count
}

/// Fills `n` wide characters of `dest` with `c`.
///
/// Equivalent to C `wmemset`.
pub fn wmemset(dest: &mut [u32], c: u32, n: usize) -> usize {
    let count = n.min(dest.len());
    dest[..count].fill(c);
    count
}

/// Compares `n` wide characters.
///
/// Equivalent to C `wmemcmp`.
/// Performs signed comparison (treating `u32` as `i32`) to match Linux `wchar_t`.
///
/// Skips long equal prefixes with a 64-wide portable-SIMD equality probe, then
/// scans `WIDE_COMPARE_SIMD_LANES` elements per step and resolves the first
/// differing index within the first mismatching panel left-to-right. Behaviour
/// is identical to the scalar element-by-element signed comparison over the
/// first `n.min(s1.len()).min(s2.len())` elements.
pub fn wmemcmp(s1: &[u32], s2: &[u32], n: usize) -> i32 {
    let count = n.min(s1.len()).min(s2.len());
    let a_all = &s1[..count];
    let b_all = &s2[..count];

    let mut equal_prefix = 0usize;
    if count >= WIDE_EQUAL_PREFIX_MIN_LEN {
        while equal_prefix + WIDE_EQUAL_PREFIX_LANES <= count {
            let next = equal_prefix + WIDE_EQUAL_PREFIX_LANES;
            if !equal_wide_long_panel(&a_all[equal_prefix..next], &b_all[equal_prefix..next]) {
                break;
            }
            equal_prefix = next;
        }
    }

    let mut a_pairs = a_all[equal_prefix..].chunks_exact(WIDE_COMPARE_UNROLL_LANES);
    let mut b_pairs = b_all[equal_prefix..].chunks_exact(WIDE_COMPARE_UNROLL_LANES);

    for (a_pair, b_pair) in a_pairs.by_ref().zip(b_pairs.by_ref()) {
        let (a_first, a_second) = a_pair.split_at(WIDE_COMPARE_SIMD_LANES);
        let (b_first, b_second) = b_pair.split_at(WIDE_COMPARE_SIMD_LANES);

        let av_first = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(a_first);
        let bv_first = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(b_first);
        let av_second = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(a_second);
        let bv_second = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(b_second);

        let first_equal = av_first.simd_eq(bv_first).all();
        let second_equal = av_second.simd_eq(bv_second).all();
        if first_equal && second_equal {
            continue;
        }

        if !first_equal && let Some(ordering) = resolve_wmemcmp_panel(a_first, b_first) {
            return ordering;
        }
        if let Some(ordering) = resolve_wmemcmp_panel(a_second, b_second) {
            return ordering;
        }
    }

    let mut a_chunks = a_pairs.remainder().chunks_exact(WIDE_COMPARE_SIMD_LANES);
    let mut b_chunks = b_pairs.remainder().chunks_exact(WIDE_COMPARE_SIMD_LANES);

    for (a_chunk, b_chunk) in a_chunks.by_ref().zip(b_chunks.by_ref()) {
        let av = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(a_chunk);
        let bv = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(b_chunk);
        if av.simd_eq(bv).all() {
            continue;
        }
        // Mismatch present in this panel; resolve the first differing index.
        if let Some(ordering) = resolve_wmemcmp_panel(a_chunk, b_chunk) {
            return ordering;
        }
    }

    for (a, b) in a_chunks.remainder().iter().zip(b_chunks.remainder().iter()) {
        let a = *a as i32;
        let b = *b as i32;
        if a != b {
            return if a < b { -1 } else { 1 };
        }
    }
    0
}

/// Locates the first occurrence of `c` in the first `n` wide characters of `s`.
///
/// Equivalent to C `wmemchr`.
///
/// Scans `WIDE_MEMCHR_SIMD_LANES` elements per step with a portable-SIMD equality
/// probe, then resolves the exact index within the first matching panel
/// left-to-right. Behaviour is identical to a scalar
/// `position(|&x| x == c)` scan over the first `n.min(s.len())` elements.
pub fn wmemchr(s: &[u32], c: u32, n: usize) -> Option<usize> {
    // Fold four 64-lane panels per 256-element block into ONE horizontal
    // reduction (bd-2g7oyh.262 follow-up; same lever as wcslen). `x ^ c == 0` iff
    // `x == c`, so `simd_min` of the per-panel `panel ^ c` is `0` exactly when one
    // of the four panels contains `c` — one reduction per 256 wide chars instead
    // of one per 16. The scalar tail resolves the leftmost match in a flagged
    // block, so the returned index is identical to the per-chunk scan.
    const PANEL: usize = WIDE_FIND_LONG_SIMD_LANES; // 64
    let count = n.min(s.len());
    let scan = &s[..count];
    let target = Simd::<u32, PANEL>::splat(c);
    let mut base = 0usize;

    // Direct 64-lane mask scan: one `simd_eq(c).to_bitmask()` per panel, resolved by
    // `trailing_zeros`. The prior 256-block min-FOLD (4 XOR + 3 simd_min + .any() per
    // block) did MORE vector work than a plain per-panel movemask and measured ~2.6x
    // slower than glibc's wmemchr; the direct mask scan (the find_byte_or_nul lesson)
    // removes the fold overhead. Byte-identical: same leftmost match. bd-2g7oyh.
    while base + PANEL <= count {
        let v = Simd::<u32, PANEL>::from_slice(&scan[base..base + PANEL]);
        let m = v.simd_eq(target).to_bitmask();
        if m != 0 {
            return Some(base + m.trailing_zeros() as usize);
        }
        base += PANEL;
    }

    // Tail (< 256 wide chars): 16-lane chunks, then scalar.
    let t16 = Simd::<u32, WIDE_MEMCHR_SIMD_LANES>::splat(c);
    let mut chunks = scan[base..].chunks_exact(WIDE_MEMCHR_SIMD_LANES);
    for chunk in chunks.by_ref() {
        let lanes = Simd::<u32, WIDE_MEMCHR_SIMD_LANES>::from_slice(chunk);
        // First matching lane via the mask (O(1)) instead of a scalar enumerate of
        // the flagged 16-element chunk (bd-2g7oyh).
        let m = lanes.simd_eq(t16).to_bitmask();
        if m != 0 {
            return Some(base + m.trailing_zeros() as usize);
        }
        base += WIDE_MEMCHR_SIMD_LANES;
    }

    for (j, &x) in chunks.remainder().iter().enumerate() {
        if x == c {
            return Some(base + j);
        }
    }

    None
}

/// Appends at most `n` wide characters from `src` to `dest`, plus a NUL terminator.
///
/// Equivalent to C `wcsncat`. Returns the new total length (including NUL).
///
/// # Panics
///
/// Panics if `dest` doesn't have enough space.
pub fn wcsncat(dest: &mut [u32], src: &[u32], n: usize) -> usize {
    let dest_len = wcslen(dest);
    let src_len = wcslen(src);
    let copy_len = src_len.min(n);
    let needed = dest_len + copy_len + 1;

    assert!(
        dest.len() >= needed,
        "wcsncat: destination buffer too small ({} elements for {} needed)",
        dest.len(),
        needed
    );

    dest[dest_len..dest_len + copy_len].copy_from_slice(&src[..copy_len]);
    dest[dest_len + copy_len] = 0;
    needed
}

/// Returns the bytes needed to duplicate a wide string (including NUL),
/// and the string length (excluding NUL).
///
/// This is the core of `wcsdup` — the ABI layer handles allocation.
pub fn wcsdup_len(s: &[u32]) -> usize {
    wcslen(s)
}

/// Returns the per-lane membership mask of a [`WIDE_COMPARE_SIMD_LANES`]-element
/// panel against a non-empty `set` (lane is `true` iff it equals some element).
#[inline(always)]
fn wide_panel_membership(
    lanes: Simd<u32, WIDE_COMPARE_SIMD_LANES>,
    set: &[u32],
) -> std::simd::Mask<i32, WIDE_COMPARE_SIMD_LANES> {
    debug_assert!(!set.is_empty());
    let mut member = lanes.simd_eq(Simd::splat(set[0]));
    for &c in &set[1..] {
        member |= lanes.simd_eq(Simd::splat(c));
    }
    member
}

#[inline(always)]
fn contiguous_wide_range(set: &[u32]) -> Option<(u32, u32)> {
    let mut min = u32::MAX;
    let mut max = 0;
    for &c in set {
        min = min.min(c);
        max = max.max(c);
    }

    let span = max.checked_sub(min)?.checked_add(1)?;
    let span = usize::try_from(span).ok()?;
    if span > set.len() {
        return None;
    }

    for candidate in min..=max {
        if !set.contains(&candidate) {
            return None;
        }
    }

    Some((min, max))
}

#[inline(always)]
fn wide_panel_all_range_members_no_nul(chunk: &[u32], min: u32, max: u32) -> bool {
    debug_assert_eq!(chunk.len(), WIDE_COMPARE_SIMD_LANES);
    debug_assert!(min > 0);
    let lanes = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(chunk);
    (lanes - Simd::splat(min))
        .simd_le(Simd::splat(max - min))
        .all()
}

/// `true` iff every lane of the panel is in `set` AND no lane is NUL — the
/// fast-advance condition for [`wcsspn`].
#[inline(always)]
fn wide_panel_all_members_no_nul(chunk: &[u32], set: &[u32]) -> bool {
    debug_assert_eq!(chunk.len(), WIDE_COMPARE_SIMD_LANES);
    let lanes = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(chunk);
    !lanes.simd_eq(Simd::splat(0)).any() && wide_panel_membership(lanes, set).all()
}

#[inline(always)]
fn wide_panel_no_range_members_no_nul(chunk: &[u32], min: u32, max: u32) -> bool {
    debug_assert_eq!(chunk.len(), WIDE_COMPARE_SIMD_LANES);
    let lanes = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(chunk);
    !lanes.simd_eq(Simd::splat(0)).any()
        && !(lanes.simd_ge(Simd::splat(min)) & lanes.simd_le(Simd::splat(max))).any()
}

/// `true` iff no lane of the panel is in `set` AND no lane is NUL — the
/// fast-advance condition for [`wcscspn`] and [`wcspbrk`].
#[inline(always)]
fn wide_panel_no_members_no_nul(chunk: &[u32], set: &[u32]) -> bool {
    debug_assert_eq!(chunk.len(), WIDE_COMPARE_SIMD_LANES);
    let lanes = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(chunk);
    !lanes.simd_eq(Simd::splat(0)).any() && !wide_panel_membership(lanes, set).any()
}

#[inline(always)]
fn repeated_wide_member_panel(chunk: &[u32], member: u32) -> bool {
    debug_assert_eq!(chunk.len(), WIDE_MEMBER_REPEAT_LANES);
    debug_assert_ne!(member, 0);
    let lanes = Simd::<u32, WIDE_MEMBER_REPEAT_LANES>::from_slice(chunk);
    lanes.simd_eq(Simd::splat(member)).all()
}

/// Returns the length of the initial segment of `s` consisting entirely of
/// wide characters in `accept`.
///
/// Equivalent to C `wcsspn`.
pub fn wcsspn(s: &[u32], accept: &[u32]) -> usize {
    let accept_len = wcslen(accept);
    let accept_set = &accept[..accept_len];
    // Empty accept set: the first character (if any) is a non-member, so the
    // initial accepted segment is empty — matches the scalar scan exactly.
    if accept_set.is_empty() {
        return 0;
    }

    let mut i = 0;
    if s.len() >= WIDE_MEMBER_REPEAT_MIN_LEN {
        let repeated = s[0];
        if repeated != 0 && accept_set.contains(&repeated) {
            while i + WIDE_MEMBER_REPEAT_LANES <= s.len() {
                if !repeated_wide_member_panel(&s[i..i + WIDE_MEMBER_REPEAT_LANES], repeated) {
                    break;
                }
                i += WIDE_MEMBER_REPEAT_LANES;
            }
        }
    }

    if s.len() >= WIDE_RANGE_MEMBERSHIP_MIN_LEN
        && let Some((min, max)) = contiguous_wide_range(accept_set)
    {
        while i + WIDE_COMPARE_SIMD_LANES <= s.len() {
            if !wide_panel_all_range_members_no_nul(&s[i..i + WIDE_COMPARE_SIMD_LANES], min, max) {
                break;
            }
            i += WIDE_COMPARE_SIMD_LANES;
        }
    } else {
        // SIMD fast path: stride panels whose lanes are all members and NUL-free.
        // The first panel that breaks either condition drops to the scalar tail,
        // which resolves the exact stop index identically to the scalar scan.
        while i + WIDE_COMPARE_SIMD_LANES <= s.len() {
            if !wide_panel_all_members_no_nul(&s[i..i + WIDE_COMPARE_SIMD_LANES], accept_set) {
                break;
            }
            i += WIDE_COMPARE_SIMD_LANES;
        }
    }

    while i < s.len() {
        let ch = s[i];
        if ch == 0 || !accept_set.contains(&ch) {
            return i;
        }
        i += 1;
    }
    s.len()
}

/// Returns the length of the initial segment of `s` consisting entirely of
/// wide characters NOT in `reject`.
///
/// Equivalent to C `wcscspn`.
pub fn wcscspn(s: &[u32], reject: &[u32]) -> usize {
    let reject_len = wcslen(reject);
    let reject_set = &reject[..reject_len];
    // Empty reject set: nothing stops the scan except NUL, so the result is the
    // index of the first NUL (or s.len()) — exactly `wcslen(s)`.
    if reject_set.is_empty() {
        return wcslen(s);
    }

    // SIMD fast path: stride panels with no rejected lanes and NUL-free.
    let mut i = 0;
    if s.len() >= WIDE_RANGE_MEMBERSHIP_MIN_LEN
        && let Some((min, max)) = contiguous_wide_range(reject_set)
    {
        while i + WIDE_COMPARE_SIMD_LANES <= s.len() {
            if !wide_panel_no_range_members_no_nul(&s[i..i + WIDE_COMPARE_SIMD_LANES], min, max) {
                break;
            }
            i += WIDE_COMPARE_SIMD_LANES;
        }
    } else {
        while i + WIDE_COMPARE_SIMD_LANES <= s.len() {
            if !wide_panel_no_members_no_nul(&s[i..i + WIDE_COMPARE_SIMD_LANES], reject_set) {
                break;
            }
            i += WIDE_COMPARE_SIMD_LANES;
        }
    }

    while i < s.len() {
        let ch = s[i];
        if ch == 0 || reject_set.contains(&ch) {
            return i;
        }
        i += 1;
    }
    s.len()
}

/// Locates the first occurrence in `s` of any wide character in `accept`.
///
/// Equivalent to C `wcspbrk`. Returns the index of the first match, or `None`.
pub fn wcspbrk(s: &[u32], accept: &[u32]) -> Option<usize> {
    let accept_len = wcslen(accept);
    let accept_set = &accept[..accept_len];
    // Empty accept set: no character can match, so there is never a hit.
    if accept_set.is_empty() {
        return None;
    }

    // SIMD fast path: stride panels with no accepted lanes and NUL-free.
    let mut i = 0;
    if s.len() >= WIDE_RANGE_MEMBERSHIP_MIN_LEN
        && let Some((min, max)) = contiguous_wide_range(accept_set)
    {
        while i + WIDE_COMPARE_SIMD_LANES <= s.len() {
            if !wide_panel_no_range_members_no_nul(&s[i..i + WIDE_COMPARE_SIMD_LANES], min, max) {
                break;
            }
            i += WIDE_COMPARE_SIMD_LANES;
        }
    } else {
        while i + WIDE_COMPARE_SIMD_LANES <= s.len() {
            if !wide_panel_no_members_no_nul(&s[i..i + WIDE_COMPARE_SIMD_LANES], accept_set) {
                break;
            }
            i += WIDE_COMPARE_SIMD_LANES;
        }
    }

    while i < s.len() {
        let ch = s[i];
        if ch == 0 {
            return None;
        }
        if accept_set.contains(&ch) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Tokenizes a wide string, similar to C `wcstok`.
///
/// Takes a mutable slice, a set of delimiter characters, and the offset to
/// resume from. Returns `Some((token_start, next_state))` or `None` if no
/// more tokens.
pub fn wcstok(s: &mut [u32], delim: &[u32], start: usize) -> Option<(usize, usize)> {
    let delim_len = wcslen(delim);
    let delim_set = &delim[..delim_len];

    // Skip leading delimiters
    let mut pos = start;
    while pos < s.len() && s[pos] != 0 && delim_set.contains(&s[pos]) {
        pos += 1;
    }

    if pos >= s.len() || s[pos] == 0 {
        return None;
    }

    let token_start = pos;

    // Find end of token
    while pos < s.len() && s[pos] != 0 && !delim_set.contains(&s[pos]) {
        pos += 1;
    }

    // NUL-terminate the token if we hit a delimiter
    if pos < s.len() && s[pos] != 0 {
        s[pos] = 0;
        pos += 1;
    }

    Some((token_start, pos))
}

/// Copies a NUL-terminated wide string from `src` into `dest`, returning the
/// index of the NUL terminator in `dest`.
///
/// Equivalent to GNU `wcpcpy`. Like `wcscpy` but returns a pointer to the end
/// of the destination string (the NUL terminator position).
///
/// # Panics
///
/// Panics if `dest` is too small to hold `src` plus the NUL terminator.
pub fn wcpcpy(dest: &mut [u32], src: &[u32]) -> usize {
    let src_len = wcslen(src);
    assert!(
        dest.len() > src_len,
        "wcpcpy: destination buffer too small ({} elements for {} element string + NUL)",
        dest.len(),
        src_len
    );
    dest[..src_len].copy_from_slice(&src[..src_len]);
    dest[src_len] = 0;
    src_len // index of the NUL terminator
}

/// Copies at most `n` wide characters from `src` into `dest`, returning the
/// index one past the last written character (or at the NUL if padded).
///
/// Equivalent to GNU `wcpncpy`. If `src` is shorter than `n`, remaining
/// elements in `dest` are NUL-padded. Returns the index of the first NUL
/// in the destination if padded, or `n` if no NUL was written.
///
/// # Panics
///
/// Panics if `dest` is smaller than `n`.
pub fn wcpncpy(dest: &mut [u32], src: &[u32], n: usize) -> usize {
    assert!(
        dest.len() >= n,
        "wcpncpy: destination buffer too small ({} elements for request {})",
        dest.len(),
        n
    );
    let src_len = wcslen(src);
    let copy_len = src_len.min(n);

    dest[..copy_len].copy_from_slice(&src[..copy_len]);

    if copy_len < n {
        dest[copy_len..n].fill(0);
        copy_len // index of first NUL
    } else {
        n // no NUL written
    }
}

/// Case-insensitive comparison of two NUL-terminated wide strings.
///
/// Equivalent to GNU `wcscasecmp`. Uses simple ASCII case-folding
/// (towlower) for comparison.
pub fn wcscasecmp(s1: &[u32], s2: &[u32]) -> i32 {
    // SIMD fast path: stride panels that are equal after ASCII case-folding and
    // NUL-free, bounded by the shorter slice. The first panel that diverges
    // (post-fold) or holds a NUL drops to the scalar tail for exact resolution.
    let bounded = s1.len().min(s2.len());
    let mut i = 0;
    if bounded >= WIDE_CASE_REPEAT_MIN_LEN {
        while i + WIDE_CASE_REPEAT_LANES <= bounded {
            if !repeated_case_pair_equal_and_no_nul_wide_long(
                &s1[i..i + WIDE_CASE_REPEAT_LANES],
                &s2[i..i + WIDE_CASE_REPEAT_LANES],
            ) {
                break;
            }
            i += WIDE_CASE_REPEAT_LANES;
        }
        while i + WIDE_COMPARE_UNROLL_LANES <= bounded {
            if !repeated_case_pair_equal_and_no_nul_wide(
                &s1[i..i + WIDE_COMPARE_UNROLL_LANES],
                &s2[i..i + WIDE_COMPARE_UNROLL_LANES],
            ) {
                break;
            }
            i += WIDE_COMPARE_UNROLL_LANES;
        }
    }
    while i + WIDE_COMPARE_SIMD_LANES <= bounded {
        let av = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(&s1[i..i + WIDE_COMPARE_SIMD_LANES]);
        let bv = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(&s2[i..i + WIDE_COMPARE_SIMD_LANES]);
        // First lane that case-folds-differently OR is NUL in s1 — O(1) divergence
        // index via the SIMD mask instead of breaking to the scalar tail and
        // re-folding the panel element-by-element (bd-2g7oyh). Both folds are
        // ASCII-only (fold_ascii_upper_wide here, simple_towlower in the tail), so
        // upper-fold inequality == lower-fold inequality == the scalar stop lane;
        // matches fold_equal_and_no_nul_wide's break and the tail's resolution.
        let event = fold_ascii_upper_wide(av).simd_ne(fold_ascii_upper_wide(bv))
            | av.simd_eq(Simd::splat(0));
        let bits = event.to_bitmask();
        if bits != 0 {
            let j = i + bits.trailing_zeros() as usize;
            let la = simple_towlower(s1[j]);
            let lb = simple_towlower(s2[j]);
            if la != lb {
                // glibc returns the folded-codepoint difference (towlower(c1) -
                // towlower(c2)) via wint_t arithmetic, NOT a bare ±1 sign.
                return la.wrapping_sub(lb) as i32;
            }
            return 0; // shared NUL after case-folding equal
        }
        i += WIDE_COMPARE_SIMD_LANES;
    }

    loop {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };

        let la = simple_towlower(a);
        let lb = simple_towlower(b);

        if la != lb {
            // glibc returns the folded-codepoint difference (towlower(c1) -
            // towlower(c2)) via wint_t arithmetic, NOT a bare ±1 sign.
            return la.wrapping_sub(lb) as i32;
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
}

/// Bounded case-insensitive comparison of two wide strings.
///
/// Equivalent to GNU `wcsncasecmp`. Compares at most `n` wide characters.
pub fn wcsncasecmp(s1: &[u32], s2: &[u32], n: usize) -> i32 {
    // SIMD fold-equal fast path over the n-bounded prefix present in both
    // slices; the scalar tail resolves the exact divergence/NUL index and
    // out-of-range (logical NUL) elements, identical to the scalar scan.
    let bounded = n.min(s1.len()).min(s2.len());
    let mut i = 0;
    if bounded >= WIDE_CASE_REPEAT_MIN_LEN {
        while i + WIDE_CASE_REPEAT_LANES <= bounded {
            if !repeated_case_pair_equal_and_no_nul_wide_long(
                &s1[i..i + WIDE_CASE_REPEAT_LANES],
                &s2[i..i + WIDE_CASE_REPEAT_LANES],
            ) {
                break;
            }
            i += WIDE_CASE_REPEAT_LANES;
        }
        while i + WIDE_COMPARE_UNROLL_LANES <= bounded {
            if !repeated_case_pair_equal_and_no_nul_wide(
                &s1[i..i + WIDE_COMPARE_UNROLL_LANES],
                &s2[i..i + WIDE_COMPARE_UNROLL_LANES],
            ) {
                break;
            }
            i += WIDE_COMPARE_UNROLL_LANES;
        }
    }
    while i + WIDE_COMPARE_SIMD_LANES <= bounded {
        let av = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(&s1[i..i + WIDE_COMPARE_SIMD_LANES]);
        let bv = Simd::<u32, WIDE_COMPARE_SIMD_LANES>::from_slice(&s2[i..i + WIDE_COMPARE_SIMD_LANES]);
        // First lane that case-folds-differently OR is NUL in s1 — O(1) divergence
        // index via the SIMD mask (same fix as wcscasecmp; bd-2g7oyh). Both folds
        // are ASCII-only, so this matches the scalar tail's stop lane + resolution.
        let event = fold_ascii_upper_wide(av).simd_ne(fold_ascii_upper_wide(bv))
            | av.simd_eq(Simd::splat(0));
        let bits = event.to_bitmask();
        if bits != 0 {
            let j = i + bits.trailing_zeros() as usize;
            let la = simple_towlower(s1[j]);
            let lb = simple_towlower(s2[j]);
            if la != lb {
                return la.wrapping_sub(lb) as i32;
            }
            return 0; // shared NUL after case-folding equal
        }
        i += WIDE_COMPARE_SIMD_LANES;
    }

    while i < n {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };

        let la = simple_towlower(a);
        let lb = simple_towlower(b);

        if la != lb {
            // glibc returns the folded-codepoint difference, not a ±1 sign.
            return la.wrapping_sub(lb) as i32;
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
    0
}

/// Locates the last occurrence of `c` in the first `n` wide characters of `s`.
///
/// Equivalent to GNU `wmemrchr`. Searches backwards.
///
/// Scans long inputs with 64-wide reverse panels, keeps short inputs on the
/// narrower reverse panel, then resolves the first (rear-most) candidate panel
/// right-to-left. Behaviour is identical to a
/// scalar `(0..n.min(s.len())).rev().find(|&i| s[i] == c)` reverse scan.
pub fn wmemrchr(s: &[u32], c: u32, n: usize) -> Option<usize> {
    let count = n.min(s.len());
    let scan = &s[..count];
    let mut end = count;

    if count >= WIDE_REVERSE_LONG_MIN_LEN {
        let target = Simd::<u32, WIDE_REVERSE_LONG_SIMD_LANES>::splat(c);
        for chunk in scan.rchunks_exact(WIDE_REVERSE_LONG_SIMD_LANES) {
            let start = end - WIDE_REVERSE_LONG_SIMD_LANES;
            let lanes = Simd::<u32, WIDE_REVERSE_LONG_SIMD_LANES>::from_slice(chunk);
            if lanes.simd_eq(target).any() {
                for j in (0..WIDE_REVERSE_LONG_SIMD_LANES).rev() {
                    if chunk[j] == c {
                        return Some(start + j);
                    }
                }
            }
            end = start;
        }
    }

    let target = Simd::<u32, WIDE_REVERSE_SIMD_LANES>::splat(c);
    for chunk in scan[..end].rchunks_exact(WIDE_REVERSE_SIMD_LANES) {
        let start = end - WIDE_REVERSE_SIMD_LANES;
        let lanes = Simd::<u32, WIDE_REVERSE_SIMD_LANES>::from_slice(chunk);
        if lanes.simd_eq(target).any() {
            for j in (0..WIDE_REVERSE_SIMD_LANES).rev() {
                if chunk[j] == c {
                    return Some(start + j);
                }
            }
        }
        end = start;
    }

    // Remainder occupies the front `[0, end)` of the slice.
    (0..end).rev().find(|&j| scan[j] == c)
}

/// Simple ASCII-range case folding for wide characters.
/// Maps A-Z to a-z, leaves everything else unchanged.
#[inline]
fn simple_towlower(c: u32) -> u32 {
    if (0x41..=0x5A).contains(&c) {
        c + 0x20
    } else {
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::Config as ProptestConfig;

    fn property_proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("FRANKENLIBC_PROPTEST_CASES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(default_cases);

        ProptestConfig {
            cases,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    fn to_wide_cstring(bytes: &[u8]) -> Vec<u32> {
        let mut out: Vec<u32> = bytes.iter().map(|&byte| byte as u32).collect();
        out.push(0);
        out
    }

    #[test]
    fn test_wcslen_basic() {
        assert_eq!(wcslen(&[b'h' as u32, b'i' as u32, 0]), 2);
        assert_eq!(wcslen(&[0]), 0);
        assert_eq!(wcslen(&[65, 66, 67]), 3); // no NUL found
    }

    #[test]
    fn test_wcsnlen_basic() {
        let value = [b'a' as u32, b'b' as u32, 0, b'c' as u32];
        assert_eq!(wcsnlen(&value, 8), 2);
        assert_eq!(wcsnlen(&value, 1), 1);
        assert_eq!(wcsnlen(&[b'a' as u32, b'b' as u32], 8), 2);
    }

    #[test]
    fn test_wcswidth_basic() {
        let value = [b'A' as u32, '界' as u32, 0];
        assert_eq!(wcswidth(&value, 8), 3);
        assert_eq!(wcswidth(&value, 1), 1);
        assert_eq!(wcswidth(&[0x07, 0], 8), -1);
    }

    #[test]
    fn test_wcscpy_basic() {
        let src = [b'H' as u32, b'i' as u32, 0];
        let mut dest = [0u32; 4];
        let n = wcscpy(&mut dest, &src);
        assert_eq!(n, 3);
        assert_eq!(&dest[..3], &[b'H' as u32, b'i' as u32, 0]);
    }

    #[test]
    fn test_wcsncpy_basic() {
        let src = [b'H' as u32, b'i' as u32, 0];
        let mut dest = [0u32; 6];
        // Copy 2 chars, no NUL
        wcsncpy(&mut dest, &src, 2);
        assert_eq!(dest[0], b'H' as u32);
        assert_eq!(dest[1], b'i' as u32);
        assert_eq!(dest[2], 0); // Originally initialized to 0

        // Copy more than src length, check padding
        let mut dest2 = [0xFFFFu32; 6];
        wcsncpy(&mut dest2, &src, 5);
        assert_eq!(dest2[0], b'H' as u32);
        assert_eq!(dest2[1], b'i' as u32);
        assert_eq!(dest2[2], 0); // NUL from src
        assert_eq!(dest2[3], 0); // Padding
        assert_eq!(dest2[4], 0); // Padding
        assert_eq!(dest2[5], 0xFFFF); // Untouched
    }

    #[test]
    fn test_wcscat_basic() {
        let mut dest = [0u32; 10];
        dest[0] = b'H' as u32;
        dest[1] = 0;
        let src = [b'i' as u32, b'!' as u32, 0];
        wcscat(&mut dest, &src);
        assert_eq!(dest[0], b'H' as u32);
        assert_eq!(dest[1], b'i' as u32);
        assert_eq!(dest[2], b'!' as u32);
        assert_eq!(dest[3], 0);
    }

    #[test]
    fn test_wcscmp_equal() {
        assert_eq!(wcscmp(&[65, 66, 0], &[65, 66, 0]), 0);
    }

    #[test]
    fn test_wcscmp_less() {
        assert!(wcscmp(&[65, 0], &[66, 0]) < 0);
    }

    #[test]
    fn test_wcscmp_greater() {
        assert!(wcscmp(&[66, 0], &[65, 0]) > 0);
    }

    #[test]
    fn test_wcscmp_prefix() {
        assert!(wcscmp(&[65, 0], &[65, 66, 0]) < 0);
        assert!(wcscmp(&[65, 66, 0], &[65, 0]) > 0);
    }

    #[test]
    fn test_wcsncmp_basic() {
        // "ABC" vs "ABD", n=2 => equal
        assert_eq!(wcsncmp(&[65, 66, 67, 0], &[65, 66, 68, 0], 2), 0);
        // "ABC" vs "ABD", n=3 => less
        assert!(wcsncmp(&[65, 66, 67, 0], &[65, 66, 68, 0], 3) < 0);
    }

    #[test]
    fn test_wcsncmp_equal_prefix_preflight_preserves_bounds_and_order() {
        let mut left = vec![b'Z' as u32; WIDE_EQUAL_PREFIX_MIN_LEN + WIDE_EQUAL_PREFIX_LANES];
        let mut right = left.clone();
        left.push(0);
        right.push(0);

        assert_eq!(wcsncmp(&left, &right, WIDE_EQUAL_PREFIX_MIN_LEN), 0);

        let diverge = WIDE_EQUAL_PREFIX_MIN_LEN + 3;
        left[diverge] = b'A' as u32;
        right[diverge] = b'B' as u32;
        assert_eq!(wcsncmp(&left, &right, diverge), 0);
        assert!(wcsncmp(&left, &right, diverge + 1) < 0);
    }

    #[test]
    fn test_wcschr_basic() {
        let s = [b'A' as u32, b'B' as u32, b'C' as u32, 0];
        assert_eq!(wcschr(&s, b'B' as u32), Some(1));
        assert_eq!(wcschr(&s, b'D' as u32), None);
        assert_eq!(wcschr(&s, 0), Some(3));
    }

    #[test]
    fn test_wcschr_long_panel_preserves_first_needle_or_nul() {
        let mut s = vec![b'A' as u32; WIDE_FIND_LONG_MIN_LEN + 80];
        s[WIDE_FIND_LONG_SIMD_LANES + 5] = b'Z' as u32;
        s[WIDE_FIND_LONG_SIMD_LANES * 2 + 7] = b'Z' as u32;
        s[WIDE_FIND_LONG_MIN_LEN + 16] = 0;
        assert_eq!(wcschr(&s, b'Z' as u32), Some(WIDE_FIND_LONG_SIMD_LANES + 5));

        let mut nul_first = vec![b'A' as u32; WIDE_FIND_LONG_MIN_LEN + 80];
        nul_first[WIDE_FIND_LONG_SIMD_LANES + 9] = 0;
        nul_first[WIDE_FIND_LONG_SIMD_LANES * 2 + 7] = b'Z' as u32;
        assert_eq!(wcschr(&nul_first, b'Z' as u32), None);
    }

    #[test]
    fn test_wcsrchr_basic() {
        let s = [b'A' as u32, b'B' as u32, b'A' as u32, 0];
        assert_eq!(wcsrchr(&s, b'A' as u32), Some(2));
        assert_eq!(wcsrchr(&s, b'C' as u32), None);
        assert_eq!(wcsrchr(&s, 0), Some(3));
    }

    #[test]
    fn test_wcsrchr_stops_at_terminator() {
        let s = [b'A' as u32, b'B' as u32, 0, b'B' as u32];
        assert_eq!(wcsrchr(&s, b'B' as u32), Some(1));
    }

    #[test]
    fn test_wcsrchr_chunk_scan_preserves_last_before_terminator() {
        let s = [
            b'A' as u32,
            b'B' as u32,
            b'A' as u32,
            b'C' as u32,
            b'B' as u32,
            0,
            b'B' as u32,
        ];
        assert_eq!(wcsrchr(&s, b'B' as u32), Some(4));
        assert_eq!(wcsrchr(&s, b'C' as u32), Some(3));
    }

    #[test]
    fn test_wcsrchr_skipped_chunks_resolve_candidate_order() {
        let s = [
            b'A' as u32,
            b'A' as u32,
            b'A' as u32,
            b'A' as u32,
            b'A' as u32,
            b'A' as u32,
            b'A' as u32,
            b'A' as u32,
            b'B' as u32,
            b'C' as u32,
            b'B' as u32,
            0,
            b'B' as u32,
        ];
        assert_eq!(wcsrchr(&s, b'B' as u32), Some(10));
        assert_eq!(wcsrchr(&s, b'C' as u32), Some(9));
        assert_eq!(wcsrchr(&s, b'D' as u32), None);
    }

    #[test]
    fn test_wcsrchr_panel_stops_at_nul_before_later_match() {
        let s = [
            b'A' as u32,
            b'A' as u32,
            b'B' as u32,
            b'A' as u32,
            b'A' as u32,
            b'A' as u32,
            b'A' as u32,
            b'A' as u32,
            b'A' as u32,
            0,
            b'B' as u32,
            b'B' as u32,
        ];
        assert_eq!(wcsrchr(&s, b'B' as u32), Some(2));
        assert_eq!(wcsrchr(&s, b'C' as u32), None);
    }

    #[test]
    fn test_wcsrchr_unterminated_returns_last_match() {
        let s = [b'A' as u32, b'B' as u32, b'A' as u32];
        assert_eq!(wcsrchr(&s, b'A' as u32), Some(2));
        assert_eq!(wcsrchr(&s, b'C' as u32), None);
        assert_eq!(wcsrchr(&s, 0), Some(3));
    }

    fn scalar_wcsstr_reference(haystack: &[u32], needle: &[u32]) -> Option<usize> {
        let needle_len = wcslen(needle);

        if needle_len == 0 {
            return Some(0);
        }

        let needle = &needle[..needle_len];
        let first = needle[0];

        for i in 0..haystack.len() {
            let ch = haystack[i];
            if ch == 0 {
                return None;
            }
            if ch != first {
                continue;
            }
            if i + needle_len > haystack.len() {
                return None;
            }

            let mut matched = true;
            for j in 1..needle_len {
                let candidate = haystack[i + j];
                if candidate == 0 {
                    return None;
                }
                if candidate != needle[j] {
                    matched = false;
                    break;
                }
            }
            if matched {
                return Some(i);
            }
        }

        None
    }

    #[test]
    fn golden_wide_absent_prefilter_corpus_sha256() {
        use sha2::{Digest, Sha256};

        fn scalar_wcschr_reference(s: &[u32], c: u32) -> Option<usize> {
            for (i, &ch) in s.iter().enumerate() {
                if ch == c {
                    return Some(i);
                }
                if ch == 0 {
                    return None;
                }
            }
            None
        }

        fn scalar_wcsrchr_reference(s: &[u32], c: u32) -> Option<usize> {
            if c == 0 {
                return s.iter().position(|&ch| ch == 0).or(Some(s.len()));
            }

            let mut last = None;
            for (i, &ch) in s.iter().enumerate() {
                if ch == 0 {
                    return last;
                }
                if ch == c {
                    last = Some(i);
                }
            }
            last
        }

        fn encode_option_index(hasher: &mut Sha256, value: Option<usize>) {
            hasher.update(value.map(|x| x as u64).unwrap_or(u64::MAX).to_le_bytes());
        }

        fn encode_slice(hasher: &mut Sha256, value: &[u32]) {
            hasher.update((value.len() as u64).to_le_bytes());
            for &item in value {
                hasher.update(item.to_le_bytes());
            }
        }

        const A: u32 = b'A' as u32;
        const B: u32 = b'B' as u32;
        const Q: u32 = b'Q' as u32;
        const Z: u32 = b'Z' as u32;
        const HI: u32 = 0xffff_fffe;

        let mut cases: Vec<Vec<u32>> = vec![
            vec![],
            vec![0],
            vec![A, B, 0],
            vec![A, 0, Z, Q, 0],
            vec![Z, Q, A, 0, Z, Q],
            vec![A, Z, A, Z, 0, Z],
            vec![HI, A, 0, HI],
            vec![A, B, Q],
        ];

        let mut long_absent = vec![A; 4096];
        long_absent.push(0);
        cases.push(long_absent);

        let mut long_present_before_nul = vec![A; 4096];
        long_present_before_nul[3071] = Z;
        long_present_before_nul[3072] = Q;
        long_present_before_nul.push(0);
        cases.push(long_present_before_nul);

        let mut long_present_after_nul = vec![A; 4096];
        long_present_after_nul[257] = 0;
        long_present_after_nul[3071] = Z;
        long_present_after_nul[3072] = Q;
        cases.push(long_present_after_nul);

        let mut long_multi_before_after_nul = vec![A; WIDE_FIND_LONG_MIN_LEN + 128];
        long_multi_before_after_nul[WIDE_FIND_LONG_SIMD_LANES + 3] = Z;
        long_multi_before_after_nul[WIDE_FIND_LONG_SIMD_LANES + 4] = Q;
        long_multi_before_after_nul[WIDE_FIND_LONG_SIMD_LANES * 2 + 11] = Z;
        long_multi_before_after_nul[WIDE_FIND_LONG_SIMD_LANES * 2 + 12] = Q;
        long_multi_before_after_nul[WIDE_FIND_LONG_MIN_LEN + 7] = 0;
        long_multi_before_after_nul[WIDE_FIND_LONG_MIN_LEN + 40] = Z;
        cases.push(long_multi_before_after_nul);

        let needles = [
            vec![Z, Q, 0],
            vec![B, 0],
            vec![HI, A, 0],
            vec![A, A, A, 0],
            vec![0],
        ];
        let chars = [Z, B, HI, 0, b'X' as u32];

        let mut hasher = Sha256::new();
        for haystack in &cases {
            encode_slice(&mut hasher, haystack);

            for &c in &chars {
                let chr = wcschr(haystack, c);
                let rchr = wcsrchr(haystack, c);
                assert_eq!(chr, scalar_wcschr_reference(haystack, c));
                assert_eq!(rchr, scalar_wcsrchr_reference(haystack, c));
                hasher.update(c.to_le_bytes());
                encode_option_index(&mut hasher, chr);
                encode_option_index(&mut hasher, rchr);
            }

            for needle in &needles {
                let found = wcsstr(haystack, needle);
                assert_eq!(found, scalar_wcsstr_reference(haystack, needle));
                encode_slice(&mut hasher, needle);
                encode_option_index(&mut hasher, found);
            }
        }

        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "5386e6e132c041340e2310b6c14834333ff391547e60e92f96a4da5b28f582ec",
            "wide absent-prefilter golden corpus hash drifted"
        );
    }

    #[test]
    fn test_wcsstr_basic() {
        let haystack = [b'A' as u32, b'B' as u32, b'C' as u32, b'D' as u32, 0];
        let needle = [b'B' as u32, b'C' as u32, 0];
        assert_eq!(wcsstr(&haystack, &needle), Some(1));

        let needle_not_found = [b'X' as u32, 0];
        assert_eq!(wcsstr(&haystack, &needle_not_found), None);

        let empty = [0u32];
        assert_eq!(wcsstr(&haystack, &empty), Some(0));
    }

    #[test]
    fn test_wcsstr_stops_at_terminator() {
        let haystack = [b'A' as u32, 0, b'B' as u32, b'C' as u32, 0];
        let needle = [b'B' as u32, b'C' as u32, 0];
        assert_eq!(wcsstr(&haystack, &needle), None);
    }

    #[test]
    fn test_wcsstr_unterminated_haystack_match() {
        let haystack = [b'A' as u32, b'B' as u32, b'C' as u32];
        let needle = [b'B' as u32, b'C' as u32, 0];
        assert_eq!(wcsstr(&haystack, &needle), Some(1));
    }

    #[test]
    fn test_wcsstr_unterminated_haystack_short_candidate() {
        let haystack = [b'A' as u32, b'B' as u32];
        let needle = [b'B' as u32, b'C' as u32, 0];
        assert_eq!(wcsstr(&haystack, &needle), None);
    }

    #[test]
    fn test_wcsstr_simd_panel_stops_at_nul_before_first_char_candidate() {
        // NUL appears before any later first-character candidate: search ends.
        let mut haystack = [b'A' as u32; 64];
        haystack[7] = 0;
        haystack[20] = b'Z' as u32;
        haystack[21] = b'Q' as u32;
        let needle = [b'Z' as u32, b'Q' as u32, 0];
        assert_eq!(wcsstr(&haystack, &needle), None);
    }

    #[test]
    fn test_wcsstr_simd_panel_resolves_candidate_before_nul() {
        // First-char candidate resolves to a full match before the NUL.
        let mut haystack = [b'A' as u32; 64];
        haystack[12] = b'Z' as u32;
        haystack[13] = b'Q' as u32;
        haystack[20] = 0;
        let needle = [b'Z' as u32, b'Q' as u32, 0];
        assert_eq!(wcsstr(&haystack, &needle), Some(12));
    }

    #[test]
    fn test_wcsstr_simd_failed_candidate_before_nul_blocks_later_match() {
        let haystack = [b'Z' as u32, b'A' as u32, 0, b'Z' as u32, b'Q' as u32, 0];
        let needle = [b'Z' as u32, b'Q' as u32, 0];
        assert_eq!(wcsstr(&haystack, &needle), None);
    }

    #[test]
    fn test_wcsstr_simd_panel_preserves_first_full_match() {
        // A failed first-char candidate (5) must not shadow the later real match (24).
        let mut haystack = [b'A' as u32; 64];
        haystack[5] = b'Z' as u32;
        haystack[6] = b'X' as u32;
        haystack[24] = b'Z' as u32;
        haystack[25] = b'Q' as u32;
        haystack[40] = 0;
        let needle = [b'Z' as u32, b'Q' as u32, 0];
        assert_eq!(wcsstr(&haystack, &needle), Some(24));
    }

    #[test]
    fn test_wcsstr_simd_panel_match_spans_panel_boundary() {
        // Candidate first char in one panel, match completing across the boundary.
        let mut haystack = [b'A' as u32; 64];
        haystack[7] = b'Z' as u32;
        haystack[8] = b'Q' as u32;
        haystack[9] = b'R' as u32;
        haystack[40] = 0;
        let needle = [b'Z' as u32, b'Q' as u32, b'R' as u32, 0];
        assert_eq!(wcsstr(&haystack, &needle), Some(7));
    }

    #[test]
    fn test_wcsstr_simd_tail_lengths_match_unterminated_scalar() {
        let needle = [b'Z' as u32, b'Q' as u32, 0];
        for len in 0..=15 {
            let mut haystack = vec![b'A' as u32; len];
            if len >= 2 {
                haystack[len - 2] = b'Z' as u32;
                haystack[len - 1] = b'Q' as u32;
            } else if len == 1 {
                haystack[0] = b'Z' as u32;
            }

            assert_eq!(
                wcsstr(&haystack, &needle),
                scalar_wcsstr_reference(&haystack, &needle),
                "tail len {len}"
            );
        }
    }

    #[test]
    fn test_wcsstr_simd_high_wide_chars() {
        // Non-ASCII wide code points exercised through the u32 SIMD lanes.
        let mut haystack = [0x1_0000u32; 40];
        haystack[30] = 0x1_F600;
        haystack[31] = 0x1_F601;
        haystack[35] = 0;
        let needle = [0x1_F600u32, 0x1_F601, 0];
        assert_eq!(wcsstr(&haystack, &needle), Some(30));
    }

    #[test]
    fn test_wcsstr_needle_internal_nul_matches_prefix() {
        let haystack = [b'A' as u32, b'Z' as u32, b'Q' as u32, 0];
        let needle = [b'Z' as u32, 0, b'Q' as u32];
        assert_eq!(wcsstr(&haystack, &needle), Some(1));
    }

    // Isomorphism: the work-counter-gated probe AND the pure Two-Way bail must
    // both equal a trivial NUL-bounded window search — including the common
    // first-char stress that forces the Two-Way bail.
    #[test]
    fn wcsstr_matches_naive_reference_incl_two_way_bail() {
        fn naive(haystack: &[u32], needle: &[u32]) -> Option<usize> {
            let h = &haystack[..haystack
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(haystack.len())];
            let n = &needle[..needle.iter().position(|&c| c == 0).unwrap_or(needle.len())];
            if n.is_empty() {
                return Some(0);
            }
            if n.len() > h.len() {
                return None;
            }
            (0..=h.len() - n.len()).find(|&i| &h[i..i + n.len()] == n)
        }
        let a = b'a' as u32;
        let b = b'b' as u32;
        // Long common-first-char run (forces miss_work > hay.len() -> Two-Way).
        let mut stress: Vec<u32> = vec![a; 300];
        let mut stress_hit = stress.clone();
        stress_hit.extend_from_slice(&[a, a, a, b]);
        stress.push(0);
        stress_hit.push(0);
        let mut long_needle: Vec<u32> = vec![a; 64];
        long_needle.push(b);
        long_needle.push(0);

        let haystacks: &[&[u32]] = &[
            &[0],
            &[a, 0],
            &[a, b, a, b, a, b, a, b, a, 0],
            &stress,
            &stress_hit,
            &[a, b, 0, a, b, b, 0], // embedded NUL bounds the haystack
        ];
        let needles: &[&[u32]] = &[
            &[0],
            &[a, 0],
            &[b, 0],
            &[a, a, a, a, b, 0], // common first char, mostly absent
            &[a, a, a, b, 0],
            &[a, b, a, b, 0],
            &[b, b, 0],   // only past an embedded NUL — must NOT match
            &long_needle, // 64 'a' + 'b' — longer than some haystacks
        ];
        for h in haystacks {
            for n in needles {
                assert_eq!(
                    wcsstr(h, n),
                    naive(h, n),
                    "wcsstr diverged from naive reference: h={h:?} n={n:?}"
                );
            }
        }
    }

    /// Golden sha256 over deterministic `wcsstr` outputs spanning absent first
    /// characters, NUL-bounded haystacks, late matches, high wide code units,
    /// unterminated slices, and the common-first-char Two-Way stress case.
    #[test]
    fn golden_wcsstr_corpus_sha256() {
        use sha2::{Digest, Sha256};

        const A: u32 = b'A' as u32;
        const B: u32 = b'B' as u32;
        const Q: u32 = b'Q' as u32;
        const Z: u32 = b'Z' as u32;
        const HI1: u32 = 0x1F600;
        const HI2: u32 = 0x1F601;

        let needles: Vec<Vec<u32>> = vec![
            vec![0],
            vec![Z, 0],
            vec![Z, Q, 0],
            vec![A, A, B, 0],
            vec![HI1, HI2, 0],
            vec![A, A, A, A, B, 0],
            vec![A, 0, Q],
        ];

        let mut haystacks: Vec<Vec<u32>> = Vec::new();
        for len in [
            0usize, 1, 2, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 257, 4096,
        ] {
            let mut terminated = vec![A; len];
            terminated.push(0);
            haystacks.push(terminated);
            haystacks.push(vec![A; len]);
        }
        for pos in [0usize, 1, 7, 15, 16, 31, 32, 63, 64, 127, 128, 255] {
            let mut h = vec![A; 300];
            h.push(0);
            h[pos] = Z;
            h[pos + 1] = Q;
            haystacks.push(h);
        }
        for (nul_pos, cand_pos) in [
            (3usize, 20usize),
            (20, 3),
            (31, 32),
            (32, 31),
            (64, 96),
            (96, 64),
        ] {
            let mut h = vec![A; 140];
            h.push(0);
            h[nul_pos] = 0;
            h[cand_pos] = Z;
            h[cand_pos + 1] = Q;
            haystacks.push(h);
        }
        let mut high = vec![HI1; 160];
        high.push(0);
        high[129] = HI1;
        high[130] = HI2;
        haystacks.push(high);

        let mut stress = vec![A; 300];
        stress.push(0);
        haystacks.push(stress);
        let mut stress_hit = vec![A; 300];
        stress_hit.extend_from_slice(&[A, A, A, B, 0]);
        haystacks.push(stress_hit);

        let mut hasher = Sha256::new();
        for h in &haystacks {
            for n in &needles {
                hasher.update((h.len() as u64).to_le_bytes());
                hasher.update((n.len() as u64).to_le_bytes());
                let pos = wcsstr(h, n).map(|p| p as i64).unwrap_or(-1);
                hasher.update(pos.to_le_bytes());
            }
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "ab630f290976e1203e3d24cef20b2269486b92ce1ca4e1949cdaf4d3f38a4837",
            "wide wcsstr golden corpus hash drifted"
        );
    }

    #[test]
    fn test_wcsstr_simd_matches_scalar_oracle_for_panel_positions() {
        let needle = [b'Z' as u32, b'Q' as u32, 0];

        for len in 0..=17 {
            for nul_pos in 0..=len {
                for cand_pos in 0..len {
                    let mut haystack = vec![b'A' as u32; len];
                    haystack[cand_pos] = b'Z' as u32;
                    if cand_pos + 1 < len {
                        haystack[cand_pos + 1] = if cand_pos % 2 == 0 {
                            b'Q' as u32
                        } else {
                            b'X' as u32
                        };
                    }
                    if nul_pos < len {
                        haystack[nul_pos] = 0;
                    }

                    assert_eq!(
                        wcsstr(&haystack, &needle),
                        scalar_wcsstr_reference(&haystack, &needle),
                        "len={len} nul_pos={nul_pos} cand_pos={cand_pos}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_wmemcpy_basic() {
        let src = [1u32, 2, 3, 4];
        let mut dest = [0u32; 4];
        assert_eq!(wmemcpy(&mut dest, &src, 4), 4);
        assert_eq!(dest, src);
    }

    #[test]
    fn test_wmemmove_basic() {
        let src = [1u32, 2, 3, 4];
        let mut dest = [0u32; 4];
        assert_eq!(wmemmove(&mut dest, &src, 4), 4);
        assert_eq!(dest, src);
    }

    #[test]
    fn test_wmemset_basic() {
        let mut dest = [0u32; 4];
        assert_eq!(wmemset(&mut dest, 0x1234, 4), 4);
        assert_eq!(dest, [0x1234; 4]);
    }

    #[test]
    fn test_wmemcmp_basic() {
        let a = [1u32, 2, 3];
        let b = [1u32, 2, 4];
        assert_eq!(wmemcmp(&a, &a, 3), 0);
        assert_eq!(wmemcmp(&a, &b, 3), -1);
        assert_eq!(wmemcmp(&b, &a, 3), 1);
    }

    #[test]
    fn test_wmemcmp_simd_panel_boundary_and_signedness() {
        // Equal across multiple full SIMD panels.
        let a: Vec<u32> = (0..20u32).collect();
        assert_eq!(wmemcmp(&a, &a, 20), 0);
        // Mismatch in the first panel, in a later panel, and in the remainder.
        for diff_at in [0usize, 3, 8, 15, 17, 19] {
            let mut b = a.clone();
            b[diff_at] = a[diff_at] + 1;
            assert_eq!(wmemcmp(&a, &b, 20), -1, "diff_at={diff_at}");
            assert_eq!(wmemcmp(&b, &a, 20), 1, "diff_at={diff_at}");
        }
        // Signed comparison: high bit set (>= 0x8000_0000) is negative as i32.
        let neg = [0x8000_0000u32];
        let pos = [0x0000_0001u32];
        assert_eq!(wmemcmp(&neg, &pos, 1), -1);
        assert_eq!(wmemcmp(&pos, &neg, 1), 1);
        // Bound: a mismatch beyond n must not be seen.
        let mut c = a.clone();
        c[10] = 999;
        assert_eq!(wmemcmp(&a, &c, 8), 0);
    }

    #[test]
    fn test_wmemcmp_long_equal_prefix_panel_boundary() {
        let len = WIDE_EQUAL_PREFIX_MIN_LEN + WIDE_EQUAL_PREFIX_LANES + 19;
        let a: Vec<u32> = (0..len)
            .map(|i| 0x1000_u32 + (i as u32 % 251))
            .collect();
        assert_eq!(wmemcmp(&a, &a, len), 0);

        for diff_at in [
            0usize,
            WIDE_EQUAL_PREFIX_LANES - 1,
            WIDE_EQUAL_PREFIX_LANES,
            WIDE_EQUAL_PREFIX_MIN_LEN - 1,
            WIDE_EQUAL_PREFIX_MIN_LEN,
            WIDE_EQUAL_PREFIX_MIN_LEN + WIDE_EQUAL_PREFIX_LANES - 1,
            len - 1,
        ] {
            let mut b = a.clone();
            b[diff_at] = a[diff_at] + 1;
            assert_eq!(wmemcmp(&a, &b, len), -1, "diff_at={diff_at}");
            assert_eq!(wmemcmp(&b, &a, len), 1, "diff_at={diff_at}");
        }

        let mut clipped = a.clone();
        clipped[WIDE_EQUAL_PREFIX_MIN_LEN + 5] = 0;
        assert_eq!(wmemcmp(&a, &clipped, WIDE_EQUAL_PREFIX_MIN_LEN), 0);
    }

    #[test]
    fn test_wmemchr_basic() {
        let haystack = [1u32, 2, 3, 4];
        assert_eq!(wmemchr(&haystack, 3, 4), Some(2));
        assert_eq!(wmemchr(&haystack, 5, 4), None);
    }

    #[test]
    fn test_wcsncat_basic() {
        let mut dest = [0u32; 10];
        dest[0] = b'H' as u32;
        dest[1] = 0;
        let src = [b'e' as u32, b'l' as u32, b'l' as u32, b'o' as u32, 0];
        wcsncat(&mut dest, &src, 2);
        assert_eq!(dest[0], b'H' as u32);
        assert_eq!(dest[1], b'e' as u32);
        assert_eq!(dest[2], b'l' as u32);
        assert_eq!(dest[3], 0);
    }

    #[test]
    fn test_wcsncat_full() {
        let mut dest = [0u32; 10];
        dest[0] = b'A' as u32;
        dest[1] = 0;
        let src = [b'B' as u32, b'C' as u32, 0];
        wcsncat(&mut dest, &src, 10); // n > src_len
        assert_eq!(dest[0], b'A' as u32);
        assert_eq!(dest[1], b'B' as u32);
        assert_eq!(dest[2], b'C' as u32);
        assert_eq!(dest[3], 0);
    }

    #[test]
    fn test_wcsdup_len() {
        let s = [b'H' as u32, b'i' as u32, 0];
        assert_eq!(wcsdup_len(&s), 2);
        assert_eq!(wcsdup_len(&[0u32]), 0);
    }

    #[test]
    fn test_wcsspn_basic() {
        let s = [b'a' as u32, b'b' as u32, b'c' as u32, b'x' as u32, 0];
        let accept = [b'a' as u32, b'b' as u32, b'c' as u32, 0];
        assert_eq!(wcsspn(&s, &accept), 3);
    }

    #[test]
    fn test_wcsspn_empty() {
        let s = [b'x' as u32, 0];
        let accept = [b'a' as u32, 0];
        assert_eq!(wcsspn(&s, &accept), 0);
    }

    #[test]
    fn test_wcsspn_repeated_member_run_stops_at_first_nonmember() {
        let mut s = vec![b'1' as u32; WIDE_MEMBER_REPEAT_MIN_LEN + WIDE_MEMBER_REPEAT_LANES];
        s.push(b'x' as u32);
        s.push(0);
        let accept = [b'0' as u32, b'1' as u32, b'2' as u32, b'3' as u32, 0];
        assert_eq!(
            wcsspn(&s, &accept),
            WIDE_MEMBER_REPEAT_MIN_LEN + WIDE_MEMBER_REPEAT_LANES
        );
    }

    #[test]
    fn test_wcsspn_repeated_member_folded_panel_boundary() {
        let mut s = vec![b'1' as u32; WIDE_MEMBER_REPEAT_MIN_LEN + WIDE_MEMBER_REPEAT_LANES];
        s.push(b'1' as u32);
        s.push(b'x' as u32);
        s.push(0);
        let accept = [b'0' as u32, b'1' as u32, b'2' as u32, b'3' as u32, 0];
        assert_eq!(
            wcsspn(&s, &accept),
            WIDE_MEMBER_REPEAT_MIN_LEN + WIDE_MEMBER_REPEAT_LANES + 1
        );

        s[WIDE_MEMBER_REPEAT_MIN_LEN + WIDE_MEMBER_REPEAT_LANES - 1] = b'x' as u32;
        assert_eq!(
            wcsspn(&s, &accept),
            WIDE_MEMBER_REPEAT_MIN_LEN + WIDE_MEMBER_REPEAT_LANES - 1
        );
    }

    #[test]
    fn test_wcscspn_basic() {
        let s = [b'a' as u32, b'b' as u32, b'c' as u32, b'x' as u32, 0];
        let reject = [b'x' as u32, b'y' as u32, 0];
        assert_eq!(wcscspn(&s, &reject), 3);
    }

    #[test]
    fn test_wcscspn_none_rejected() {
        let s = [b'a' as u32, b'b' as u32, 0];
        let reject = [b'x' as u32, 0];
        assert_eq!(wcscspn(&s, &reject), 2);
    }

    #[test]
    fn test_wcspbrk_basic() {
        let s = [b'a' as u32, b'b' as u32, b'c' as u32, 0];
        let accept = [b'c' as u32, b'd' as u32, 0];
        assert_eq!(wcspbrk(&s, &accept), Some(2));
    }

    #[test]
    fn test_wcspbrk_not_found() {
        let s = [b'a' as u32, b'b' as u32, 0];
        let accept = [b'x' as u32, 0];
        assert_eq!(wcspbrk(&s, &accept), None);
    }

    #[test]
    fn test_wcstok_basic() {
        let mut s = [
            b'h' as u32,
            b'e' as u32,
            b'l' as u32,
            b'l' as u32,
            b'o' as u32,
            b' ' as u32,
            b'w' as u32,
            b'o' as u32,
            b'r' as u32,
            b'l' as u32,
            b'd' as u32,
            0,
        ];
        let delim = [b' ' as u32, 0];

        // First token: "hello"
        let (start1, next1) = wcstok(&mut s, &delim, 0).unwrap();
        assert_eq!(start1, 0);
        assert_eq!(
            &s[start1..start1 + 5],
            &[
                b'h' as u32,
                b'e' as u32,
                b'l' as u32,
                b'l' as u32,
                b'o' as u32
            ]
        );

        // Second token: "world"
        let (start2, _) = wcstok(&mut s, &delim, next1).unwrap();
        assert_eq!(
            &s[start2..start2 + 5],
            &[
                b'w' as u32,
                b'o' as u32,
                b'r' as u32,
                b'l' as u32,
                b'd' as u32
            ]
        );
    }

    #[test]
    fn test_wcstok_no_more() {
        let mut s = [0u32];
        let delim = [b' ' as u32, 0];
        assert!(wcstok(&mut s, &delim, 0).is_none());
    }

    #[test]
    fn test_wcpcpy_basic() {
        let src = [b'H' as u32, b'i' as u32, 0];
        let mut dest = [0u32; 4];
        let nul_idx = wcpcpy(&mut dest, &src);
        assert_eq!(nul_idx, 2);
        assert_eq!(&dest[..3], &[b'H' as u32, b'i' as u32, 0]);
    }

    #[test]
    fn test_wcpcpy_empty() {
        let src = [0u32];
        let mut dest = [0xFFu32; 4];
        let nul_idx = wcpcpy(&mut dest, &src);
        assert_eq!(nul_idx, 0);
        assert_eq!(dest[0], 0);
    }

    #[test]
    fn test_wcpncpy_short_src() {
        let src = [b'A' as u32, 0];
        let mut dest = [0xFFu32; 6];
        let end_idx = wcpncpy(&mut dest, &src, 4);
        assert_eq!(end_idx, 1); // index of first NUL (padding)
        assert_eq!(dest[0], b'A' as u32);
        assert_eq!(dest[1], 0);
        assert_eq!(dest[2], 0);
        assert_eq!(dest[3], 0);
        assert_eq!(dest[4], 0xFF); // untouched
    }

    #[test]
    fn test_wcpncpy_exact() {
        let src = [b'A' as u32, b'B' as u32, b'C' as u32, 0];
        let mut dest = [0u32; 6];
        let end_idx = wcpncpy(&mut dest, &src, 3);
        assert_eq!(end_idx, 3); // no NUL written (n == src_len)
        assert_eq!(&dest[..3], &[b'A' as u32, b'B' as u32, b'C' as u32]);
    }

    #[test]
    fn test_wcscasecmp_equal() {
        let s1 = [
            b'H' as u32,
            b'e' as u32,
            b'L' as u32,
            b'l' as u32,
            b'O' as u32,
            0,
        ];
        let s2 = [
            b'h' as u32,
            b'E' as u32,
            b'l' as u32,
            b'L' as u32,
            b'o' as u32,
            0,
        ];
        assert_eq!(wcscasecmp(&s1, &s2), 0);
    }

    #[test]
    fn test_wcscasecmp_less() {
        let s1 = [b'a' as u32, 0];
        let s2 = [b'B' as u32, 0];
        assert!(wcscasecmp(&s1, &s2) < 0);
    }

    #[test]
    fn test_wcscasecmp_greater() {
        let s1 = [b'Z' as u32, 0];
        let s2 = [b'a' as u32, 0];
        assert!(wcscasecmp(&s1, &s2) > 0);
    }

    #[test]
    fn test_wcsncasecmp_partial() {
        let s1 = [b'A' as u32, b'B' as u32, b'x' as u32, 0];
        let s2 = [b'a' as u32, b'b' as u32, b'Y' as u32, 0];
        assert_eq!(wcsncasecmp(&s1, &s2, 2), 0);
        assert!(wcsncasecmp(&s1, &s2, 3) < 0);
    }

    #[test]
    fn test_wcsncasecmp_zero() {
        let s1 = [b'A' as u32, 0];
        let s2 = [b'Z' as u32, 0];
        assert_eq!(wcsncasecmp(&s1, &s2, 0), 0);
    }

    #[test]
    fn test_wcsncasecmp_repeated_case_pair_long_run() {
        let mut s1 = vec![b'A' as u32; WIDE_CASE_REPEAT_MIN_LEN + WIDE_COMPARE_UNROLL_LANES];
        let mut s2 = vec![b'a' as u32; WIDE_CASE_REPEAT_MIN_LEN + WIDE_COMPARE_UNROLL_LANES];
        s1.push(0);
        s2.push(0);
        assert_eq!(wcsncasecmp(&s1, &s2, s1.len()), 0);
        assert_eq!(wcscasecmp(&s1, &s2), 0);

        let diverge = WIDE_CASE_REPEAT_MIN_LEN + 3;
        s1[diverge] = b'B' as u32;
        s2[diverge] = b'C' as u32;
        assert!(wcsncasecmp(&s1, &s2, s1.len()) < 0);
        assert!(wcscasecmp(&s1, &s2) < 0);
    }

    /// Golden sha256 over deterministic `wcscasecmp`/`wcsncasecmp` outputs.
    /// The corpus spans 16/32/64-wide panel boundaries, NUL stop positions,
    /// fold-equal repeated runs, raw-equal runs, high wide code units, and
    /// early/late divergences. Every case is also checked against the scalar
    /// ASCII-fold oracle before hashing.
    #[test]
    fn golden_wide_casefold_compare_corpus_sha256() {
        use sha2::{Digest, Sha256};

        fn scalar_wcsncasecmp(s1: &[u32], s2: &[u32], n: usize) -> i32 {
            let mut i = 0;
            while i < n {
                let a = if i < s1.len() { s1[i] } else { 0 };
                let b = if i < s2.len() { s2[i] } else { 0 };
                let la = simple_towlower(a);
                let lb = simple_towlower(b);
                if la != lb {
                    return la.wrapping_sub(lb) as i32;
                }
                if a == 0 {
                    return 0;
                }
                i += 1;
            }
            0
        }

        fn scalar_wcscasecmp(s1: &[u32], s2: &[u32]) -> i32 {
            let mut i = 0;
            loop {
                let a = if i < s1.len() { s1[i] } else { 0 };
                let b = if i < s2.len() { s2[i] } else { 0 };
                let la = simple_towlower(a);
                let lb = simple_towlower(b);
                if la != lb {
                    return la.wrapping_sub(lb) as i32;
                }
                if a == 0 {
                    return 0;
                }
                i += 1;
            }
        }

        const A: u32 = b'A' as u32;
        const B: u32 = b'B' as u32;
        const C: u32 = b'C' as u32;
        const LOW_A: u32 = b'a' as u32;
        const LOW_B: u32 = b'b' as u32;
        const Z: u32 = b'Z' as u32;
        const HI1: u32 = 0x0101;
        const HI2: u32 = 0x1F600;

        let mut cases: Vec<(Vec<u32>, Vec<u32>, Vec<usize>)> = Vec::new();
        for len in [
            0usize, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256, 257, 4096,
        ] {
            let mut left = vec![A; len];
            let mut right = vec![LOW_A; len];
            left.push(0);
            right.push(0);
            cases.push((left, right, vec![0, len / 2, len, len + 3]));

            let mut raw_left = vec![LOW_B; len];
            let mut raw_right = vec![LOW_B; len];
            raw_left.push(0);
            raw_right.push(0);
            cases.push((raw_left, raw_right, vec![len, len + 1]));

            let mut mixed_left = Vec::with_capacity(len + 1);
            let mut mixed_right = Vec::with_capacity(len + 1);
            for i in 0..len {
                mixed_left.push(if i % 2 == 0 { A } else { LOW_B });
                mixed_right.push(if i % 2 == 0 { LOW_A } else { B });
            }
            mixed_left.push(0);
            mixed_right.push(0);
            cases.push((mixed_left, mixed_right, vec![len]));
        }

        for pos in [0usize, 1, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256] {
            let mut left = vec![A; 300];
            let mut right = vec![LOW_A; 300];
            left.push(0);
            right.push(0);
            left[pos] = Z;
            right[pos] = C;
            cases.push((left, right, vec![pos, pos + 1, 300]));
        }

        for (nul_pos, diff_pos) in [
            (3usize, 20usize),
            (20, 3),
            (31, 64),
            (64, 31),
            (127, 256),
            (256, 127),
        ] {
            let mut left = vec![A; 320];
            let mut right = vec![LOW_A; 320];
            left.push(0);
            right.push(0);
            left[nul_pos] = 0;
            right[nul_pos] = 0;
            left[diff_pos] = Z;
            right[diff_pos] = C;
            cases.push((left, right, vec![nul_pos, diff_pos, 320]));
        }

        let mut high_left = vec![HI1; 512];
        let mut high_right = vec![HI1; 512];
        high_left[400] = HI2;
        high_right[400] = HI1;
        high_left.push(0);
        high_right.push(0);
        cases.push((high_left, high_right, vec![399, 400, 512]));

        let mut hasher = Sha256::new();
        for (left, right, ns) in &cases {
            let casecmp = wcscasecmp(left, right);
            assert_eq!(casecmp, scalar_wcscasecmp(left, right));
            hasher.update((left.len() as u64).to_le_bytes());
            hasher.update((right.len() as u64).to_le_bytes());
            hasher.update(casecmp.to_le_bytes());

            for &n in ns {
                let bounded = wcsncasecmp(left, right, n);
                assert_eq!(bounded, scalar_wcsncasecmp(left, right, n));
                hasher.update((n as u64).to_le_bytes());
                hasher.update(bounded.to_le_bytes());
            }
        }

        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        // Updated when wcscasecmp/wcsncasecmp switched from a ±1 sign to glibc's
        // folded-codepoint difference (towlower(c1) - towlower(c2)).
        assert_eq!(
            digest, "f660faba1981f94c3fceb497d594dc1934255719102f356e0763379ce0aba5ac",
            "wide casefold compare golden corpus hash drifted"
        );
    }

    #[test]
    fn test_wmemrchr_found() {
        let s = [1u32, 2, 3, 2, 4];
        assert_eq!(wmemrchr(&s, 2, 5), Some(3));
    }

    #[test]
    fn test_wmemrchr_not_found() {
        let s = [1u32, 2, 3];
        assert_eq!(wmemrchr(&s, 5, 3), None);
    }

    #[test]
    fn test_wmemrchr_simd_panel_boundary_and_remainder() {
        // A short scan below the SIMD panel width must use the same scalar
        // oracle semantics as a long reverse panel scan.
        let mut s: Vec<u32> = vec![1u32; 20];
        // Last occurrence must win across panels and remainder.
        s[2] = 9; // remainder region
        s[10] = 9; // middle panel
        s[18] = 9; // rear panel
        assert_eq!(wmemrchr(&s, 9, 20), Some(18));
        // Bound below the last match: only earlier matches visible.
        assert_eq!(wmemrchr(&s, 9, 18), Some(10));
        assert_eq!(wmemrchr(&s, 9, 11), Some(10));
        assert_eq!(wmemrchr(&s, 9, 10), Some(2));
        // Absent over a full scan and a sub-panel scan.
        assert_eq!(wmemrchr(&s, 7, 20), None);
        assert_eq!(wmemrchr(&s, 7, 4), None);
        // Match only in the remainder.
        assert_eq!(wmemrchr(&s, 9, 4), Some(2));
    }

    #[test]
    fn test_wmemrchr_long_reverse_panel_boundary_and_remainder() {
        let mut s: Vec<u32> = vec![1u32; WIDE_REVERSE_LONG_SIMD_LANES * 2 + 5];
        let n = s.len();
        let front_remainder_hit = 3;
        let middle_panel_hit = WIDE_REVERSE_LONG_SIMD_LANES + 7;
        let rear_panel_hit = n - 2;
        s[front_remainder_hit] = 9;
        s[middle_panel_hit] = 9;
        s[rear_panel_hit] = 9;

        assert_eq!(wmemrchr(&s, 9, n), Some(rear_panel_hit));
        assert_eq!(wmemrchr(&s, 9, rear_panel_hit), Some(middle_panel_hit));
        assert_eq!(wmemrchr(&s, 9, middle_panel_hit), Some(front_remainder_hit));
        assert_eq!(wmemrchr(&s, 7, n), None);
    }

    #[test]
    fn test_wmemrchr_first_only() {
        let s = [7u32, 1, 2, 3];
        assert_eq!(wmemrchr(&s, 7, 4), Some(0));
    }

    proptest! {
        #![proptest_config(property_proptest_config(256))]

        // Isomorphism guard for the WIDE_SIMD_LANES NUL-panel scan: the result
        // must match the scalar `position`/slice-length oracle for every input.
        // Inputs run to 200 elements so the SIMD panel loop, the panel boundary,
        // and the scalar remainder are all exercised.
        #[test]
        fn prop_wcslen_matches_first_nul_or_slice_len(data in proptest::collection::vec(any::<u32>(), 0..200)) {
            let expected = data.iter().position(|&ch| ch == 0).unwrap_or(data.len());
            prop_assert_eq!(wcslen(&data), expected);
        }

        // Isomorphism guard for the SIMD wcschr (reuses find_wide_or_nul/wcslen).
        // Pins it to the scalar "return at first c, stop at NUL" oracle over inputs
        // that span multiple panels + boundary + remainder. Needle is drawn from a
        // tiny alphabet (incl. 0 and absent values) so present/absent/NUL-first/
        // c==0 cases all occur.
        #[test]
        fn prop_wcschr_matches_scalar_oracle(
            data in proptest::collection::vec(0u32..4, 0..200),
            c in 0u32..5
        ) {
            let expected = {
                let mut found = None;
                for (i, &ch) in data.iter().enumerate() {
                    if ch == c { found = Some(i); break; }
                    if ch == 0 { found = if c == 0 { Some(i) } else { None }; break; }
                }
                found
            };
            prop_assert_eq!(wcschr(&data, c), expected);
        }

        #[test]
        fn prop_wcsnlen_honors_explicit_bound(
            data in proptest::collection::vec(any::<u32>(), 0..64),
            maxlen in 0usize..96
        ) {
            let limit = maxlen.min(data.len());
            let expected = data.iter().take(limit).position(|&ch| ch == 0).unwrap_or(limit);
            prop_assert_eq!(wcsnlen(&data, maxlen), expected);
        }

        #[test]
        fn prop_wcscmp_is_antisymmetric(
            left in proptest::collection::vec(any::<u8>(), 0..64),
            right in proptest::collection::vec(any::<u8>(), 0..64)
        ) {
            let left_wide = to_wide_cstring(&left);
            let right_wide = to_wide_cstring(&right);
            let lr = wcscmp(&left_wide, &right_wide);
            let rl = wcscmp(&right_wide, &left_wide);
            prop_assert_eq!(lr.signum(), -rl.signum());
        }

        #[test]
        fn prop_wmemset_overwrites_prefix_only(
            seed in proptest::collection::vec(any::<u32>(), 0..64),
            value in any::<u32>(),
            n in 0usize..96
        ) {
            let mut dest = seed.clone();
            let written = wmemset(&mut dest, value, n);
            let expected = n.min(seed.len());
            prop_assert_eq!(written, expected);
            prop_assert!(dest.iter().take(expected).all(|&ch| ch == value));
            prop_assert_eq!(&dest[expected..], &seed[expected..]);
        }

        #[test]
        fn prop_wmemchr_matches_slice_position(
            haystack in proptest::collection::vec(any::<u32>(), 0..64),
            needle in any::<u32>(),
            n in 0usize..96
        ) {
            let limit = n.min(haystack.len());
            let expected = haystack[..limit].iter().position(|&ch| ch == needle);
            prop_assert_eq!(wmemchr(&haystack, needle, n), expected);
        }

        #[test]
        fn prop_wmemcmp_matches_scalar_oracle(
            s1 in proptest::collection::vec(any::<u32>(), 0..80),
            s2 in proptest::collection::vec(any::<u32>(), 0..80),
            n in 0usize..96
        ) {
            // Scalar oracle: signed element-by-element compare over the common bound.
            let count = n.min(s1.len()).min(s2.len());
            let mut expected = 0i32;
            for i in 0..count {
                let a = s1[i] as i32;
                let b = s2[i] as i32;
                if a != b {
                    expected = if a < b { -1 } else { 1 };
                    break;
                }
            }
            prop_assert_eq!(wmemcmp(&s1, &s2, n), expected);
        }

        #[test]
        fn prop_wmemrchr_matches_slice_rposition(
            haystack in proptest::collection::vec(any::<u32>(), 0..80),
            needle in any::<u32>(),
            n in 0usize..96
        ) {
            let limit = n.min(haystack.len());
            let expected = (0..limit).rev().find(|&i| haystack[i] == needle);
            prop_assert_eq!(wmemrchr(&haystack, needle, n), expected);
        }
    }

    #[test]
    fn test_wmemchr_simd_panel_boundary_and_remainder() {
        // Exercise the SIMD panel loop (multiples of WIDE_SIMD_LANES), the
        // panel boundary, and the scalar remainder, against the scalar oracle.
        let s: Vec<u32> = (0..20u32).map(|i| 100 + i).collect();
        for &c in &[100u32, 107, 108, 115, 119, 50] {
            let n = s.len();
            let expected = s[..n].iter().position(|&x| x == c);
            assert_eq!(wmemchr(&s, c, n), expected, "c={c}");
        }
        // n shorter than a full panel.
        assert_eq!(wmemchr(&s, 102, 4), Some(2));
        assert_eq!(wmemchr(&s, 107, 4), None);
        // n bounded below the slice length must not see later matches.
        assert_eq!(wmemchr(&s, 115, 10), None);
    }

    #[test]
    fn glibc_wcslen_empty_string() {
        // glibc: wcslen(L"") = 0
        let s: &[u32] = &[0];
        assert_eq!(wcslen(s), 0);
    }

    #[test]
    fn glibc_wcschr_finds_terminator() {
        // glibc: wcschr(L"hello", L'\0') returns pointer to terminating NUL
        let s = &[
            b'h' as u32,
            b'e' as u32,
            b'l' as u32,
            b'l' as u32,
            b'o' as u32,
            0,
        ];
        let result = wcschr(s, 0);
        assert!(result.is_some(), "wcschr should find NUL terminator");
        assert_eq!(result.unwrap(), 5, "NUL is at offset 5");
    }

    #[test]
    fn glibc_wcsrchr_finds_last_occurrence() {
        // glibc: wcsrchr(L"hello", L'l') returns pointer to last 'l'
        let s = &[
            b'h' as u32,
            b'e' as u32,
            b'l' as u32,
            b'l' as u32,
            b'o' as u32,
            0,
        ];
        let result = wcsrchr(s, b'l' as u32);
        assert!(result.is_some(), "wcsrchr should find 'l'");
        assert_eq!(result.unwrap(), 3, "last 'l' is at offset 3");
    }
}
