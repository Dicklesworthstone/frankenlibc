//! Memory operations: memcpy, memmove, memset, memcmp, memchr, memrchr.
//!
//! These are safe Rust implementations operating on byte slices.
//! They correspond to the `<string.h>` memory functions in POSIX/C.

use std::simd::{Simd, cmp::SimdPartialEq};

/// Copies `n` bytes from `src` to `dest`.
///
/// Equivalent to C `memcpy`. The source and destination slices must not overlap;
/// use [`memmove`] if they might. Only copies `min(n, src.len(), dest.len())` bytes.
///
/// Returns the number of bytes actually copied.
pub fn memcpy(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let count = n.min(dest.len()).min(src.len());
    dest[..count].copy_from_slice(&src[..count]);
    count
}

/// Copies `n` bytes from `src` to `dest`, handling overlapping regions correctly.
///
/// Equivalent to C `memmove`. Safe Rust slices never truly alias, so this
/// behaves identically to [`memcpy`] at the API level, but the implementation
/// uses `copy_within`-compatible logic.
///
/// Returns the number of bytes actually copied.
pub fn memmove(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let count = n.min(dest.len()).min(src.len());
    // In safe Rust with separate slices, copy_from_slice is fine.
    // For true overlapping (same buffer), callers should use slice::copy_within.
    dest[..count].copy_from_slice(&src[..count]);
    count
}

/// Fills the first `n` bytes of `dest` with the byte `value`.
///
/// Equivalent to C `memset(dest, c, n)`.
///
/// Returns the number of bytes actually set.
pub fn memset(dest: &mut [u8], value: u8, n: usize) -> usize {
    let count = n.min(dest.len());
    for byte in &mut dest[..count] {
        *byte = value;
    }
    count
}

/// Compares the first `n` bytes of `a` and `b`.
///
/// Equivalent to C `memcmp`. Returns:
/// - `Ordering::Less` if `a < b`
/// - `Ordering::Equal` if `a == b`
/// - `Ordering::Greater` if `a > b`
///
/// Only compares `min(n, a.len(), b.len())` bytes.
pub fn memcmp(a: &[u8], b: &[u8], n: usize) -> core::cmp::Ordering {
    let count = n.min(a.len()).min(b.len());

    let a = &a[..count];
    let b = &b[..count];

    // Index-based scan (mirrors the parity-class `strcmp` loop, which is faster
    // than the equivalent `chunks_exact().zip()` form): fold four 32-byte panels
    // into one equality probe per 128-byte block; an equal block is skipped
    // wholesale, and the first block holding any difference is resolved in
    // 32-byte panel order then byte order, preserving the exact first-difference
    // sign.
    let mut i = 0;
    while i + SIMD_FOLD_BYTES <= count {
        if ne_simd_folded_128(&a[i..i + SIMD_FOLD_BYTES], &b[i..i + SIMD_FOLD_BYTES]) {
            while i + SIMD_LANES <= count {
                if !eq_simd_32(&a[i..i + SIMD_LANES], &b[i..i + SIMD_LANES]) {
                    return compare_bytes(&a[i..i + SIMD_LANES], &b[i..i + SIMD_LANES]);
                }
                i += SIMD_LANES;
            }
        }
        i += SIMD_FOLD_BYTES;
    }

    // Remaining 32-byte panels.
    while i + SIMD_LANES <= count {
        if !eq_simd_32(&a[i..i + SIMD_LANES], &b[i..i + SIMD_LANES]) {
            return compare_bytes(&a[i..i + SIMD_LANES], &b[i..i + SIMD_LANES]);
        }
        i += SIMD_LANES;
    }

    // Tail: the sub-32B remainder, scanned 8 bytes at a time then byte-wise.
    while i + WORD <= count {
        if u64_from_chunk(&a[i..i + WORD]) != u64_from_chunk(&b[i..i + WORD]) {
            return compare_bytes(&a[i..i + WORD], &b[i..i + WORD]);
        }
        i += WORD;
    }

    compare_bytes(&a[i..], &b[i..])
}

/// True iff the two 32-byte panels are byte-for-byte equal. Safe portable SIMD
/// equality probe; both inputs must be exactly [`SIMD_LANES`] bytes long.
#[inline(always)]
fn eq_simd_32(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), SIMD_LANES);
    debug_assert_eq!(b.len(), SIMD_LANES);
    Simd::<u8, SIMD_LANES>::from_slice(a)
        .simd_eq(Simd::<u8, SIMD_LANES>::from_slice(b))
        .all()
}

/// True iff any byte differs across a 128-byte block. This amortizes the mask
/// reduction across four SIMD panels while leaving first-difference ordering to
/// the caller's panel/byte resolver.
#[inline(always)]
fn ne_simd_folded_128(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), SIMD_FOLD_BYTES);
    debug_assert_eq!(b.len(), SIMD_FOLD_BYTES);
    let a0 = Simd::<u8, SIMD_LANES>::from_slice(&a[..SIMD_LANES]);
    let b0 = Simd::<u8, SIMD_LANES>::from_slice(&b[..SIMD_LANES]);
    let a1 = Simd::<u8, SIMD_LANES>::from_slice(&a[SIMD_LANES..SIMD_LANES * 2]);
    let b1 = Simd::<u8, SIMD_LANES>::from_slice(&b[SIMD_LANES..SIMD_LANES * 2]);
    let a2 = Simd::<u8, SIMD_LANES>::from_slice(&a[SIMD_LANES * 2..SIMD_LANES * 3]);
    let b2 = Simd::<u8, SIMD_LANES>::from_slice(&b[SIMD_LANES * 2..SIMD_LANES * 3]);
    let a3 = Simd::<u8, SIMD_LANES>::from_slice(&a[SIMD_LANES * 3..SIMD_FOLD_BYTES]);
    let b3 = Simd::<u8, SIMD_LANES>::from_slice(&b[SIMD_LANES * 3..SIMD_FOLD_BYTES]);
    (a0.simd_ne(b0) | a1.simd_ne(b1) | a2.simd_ne(b2) | a3.simd_ne(b3)).any()
}

#[inline]
fn u64_from_chunk(chunk: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(chunk);
    u64::from_ne_bytes(bytes)
}

/// SWAR word size (8 bytes), matching the `chunks_exact(8)` scans in this module.
const WORD: usize = size_of::<u64>();
const SIMD_LANES: usize = 32;
const SIMD_FOLD_PANELS: usize = 4;
const SIMD_FOLD_BYTES: usize = SIMD_LANES * SIMD_FOLD_PANELS;
const MEMCHR_FOLD_PANELS: usize = 8;
const MEMCHR_FOLD_BYTES: usize = SIMD_LANES * MEMCHR_FOLD_PANELS;

const LO_U64: u64 = u64::from_ne_bytes([0x01; WORD]);
const HI_U64: u64 = u64::from_ne_bytes([0x80; WORD]);

/// Mycroft's zero-in-word test: true iff any byte of `word` is `0x00`.
#[inline(always)]
fn zero_byte_u64(word: u64) -> bool {
    word.wrapping_sub(LO_U64) & !word & HI_U64 != 0
}

/// True iff any byte of `word` equals `byte`. XOR-folds `byte` to zero, then
/// reuses the zero-byte test. Exact (no false positives), endianness-agnostic.
#[inline(always)]
fn has_byte_u64(word: u64, byte: u8) -> bool {
    zero_byte_u64(word ^ u64::from_ne_bytes([byte; WORD]))
}

#[inline(always)]
fn has_byte_simd_32(chunk: &[u8], byte: u8) -> bool {
    debug_assert_eq!(chunk.len(), SIMD_LANES);
    Simd::<u8, SIMD_LANES>::from_slice(chunk)
        .simd_eq(Simd::splat(byte))
        .any()
}

#[inline(always)]
fn byte_mask_simd_32(chunk: &[u8], byte: u8) -> u64 {
    debug_assert_eq!(chunk.len(), SIMD_LANES);
    Simd::<u8, SIMD_LANES>::from_slice(chunk)
        .simd_eq(Simd::splat(byte))
        .to_bitmask()
}

#[inline(always)]
fn first_byte_simd_32(chunk: &[u8], byte: u8) -> Option<usize> {
    let mask = byte_mask_simd_32(chunk, byte);
    if mask == 0 {
        None
    } else {
        Some(mask.trailing_zeros() as usize)
    }
}

#[inline(always)]
fn has_byte_simd_folded(block: &[u8], byte: u8) -> bool {
    debug_assert_eq!(block.len(), SIMD_FOLD_BYTES);
    let needle = Simd::splat(byte);
    let p0 = Simd::<u8, SIMD_LANES>::from_slice(&block[..SIMD_LANES]).simd_eq(needle);
    let p1 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES..SIMD_LANES * 2]).simd_eq(needle);
    let p2 =
        Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 2..SIMD_LANES * 3]).simd_eq(needle);
    let p3 =
        Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 3..SIMD_FOLD_BYTES]).simd_eq(needle);
    (p0 | p1 | p2 | p3).any()
}

#[inline(always)]
fn has_byte_memchr_folded(block: &[u8], byte: u8) -> bool {
    debug_assert_eq!(block.len(), MEMCHR_FOLD_BYTES);
    let needle = Simd::splat(byte);
    let p0 = Simd::<u8, SIMD_LANES>::from_slice(&block[..SIMD_LANES]).simd_eq(needle);
    let p1 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES..SIMD_LANES * 2]).simd_eq(needle);
    let p2 =
        Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 2..SIMD_LANES * 3]).simd_eq(needle);
    let p3 =
        Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 3..SIMD_LANES * 4]).simd_eq(needle);
    let p4 =
        Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 4..SIMD_LANES * 5]).simd_eq(needle);
    let p5 =
        Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 5..SIMD_LANES * 6]).simd_eq(needle);
    let p6 =
        Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 6..SIMD_LANES * 7]).simd_eq(needle);
    let p7 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 7..MEMCHR_FOLD_BYTES])
        .simd_eq(needle);
    (p0 | p1 | p2 | p3 | p4 | p5 | p6 | p7).any()
}

#[inline]
fn compare_bytes(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    for (&av, &bv) in a.iter().zip(b.iter()) {
        if av != bv {
            return if av < bv {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Greater
            };
        }
    }
    core::cmp::Ordering::Equal
}

/// Scans the first `n` bytes of `haystack` for the byte `needle`.
///
/// Equivalent to C `memchr`. Returns the index of the first occurrence,
/// or `None` if not found.
///
/// Scans absent-heavy prefixes as folded 256-byte SIMD blocks, then resolves
/// the exact index within the first matching panel low-to-high. Behaviour is
/// identical to a byte-at-a-time `position` scan.
pub fn memchr(haystack: &[u8], needle: u8, n: usize) -> Option<usize> {
    let count = n.min(haystack.len());
    let hs = &haystack[..count];
    let mut simd_blocks = hs.chunks_exact(MEMCHR_FOLD_BYTES);
    let mut simd_base = 0usize;

    for block in simd_blocks.by_ref() {
        if has_byte_memchr_folded(block, needle) {
            for (panel_index, chunk) in block.chunks_exact(SIMD_LANES).enumerate() {
                if let Some(j) = first_byte_simd_32(chunk, needle) {
                    return Some(simd_base + panel_index * SIMD_LANES + j);
                }
            }
        }
        simd_base += MEMCHR_FOLD_BYTES;
    }

    let hs = simd_blocks.remainder();
    let mut simd_chunks = hs.chunks_exact(SIMD_LANES);

    for chunk in simd_chunks.by_ref() {
        if let Some(j) = first_byte_simd_32(chunk, needle) {
            return Some(simd_base + j);
        }
        simd_base += SIMD_LANES;
    }

    let hs = simd_chunks.remainder();
    let mut chunks = hs.chunks_exact(WORD);
    let mut base = simd_base;

    for chunk in chunks.by_ref() {
        if has_byte_u64(u64_from_chunk(chunk), needle) {
            // The SWAR probe is exact, so this lookup always resolves.
            if let Some(j) = chunk.iter().position(|&b| b == needle) {
                return Some(base + j);
            }
        }
        base += WORD;
    }

    chunks
        .remainder()
        .iter()
        .position(|&b| b == needle)
        .map(|j| base + j)
}

/// Scans the first `n` bytes of `haystack` for the last occurrence of `needle`.
///
/// Equivalent to C `memrchr`. Returns the index of the last occurrence,
/// or `None` if not found.
///
/// Reverse counterpart of [`memchr`]: scans 8 bytes per step from the end with
/// the SWAR probe, resolving the exact index within the last matching word
/// high-to-low. Behaviour is identical to a byte-at-a-time `rposition` scan.
pub fn memrchr(haystack: &[u8], needle: u8, n: usize) -> Option<usize> {
    let count = n.min(haystack.len());
    let hs = &haystack[..count];
    let mut simd_blocks = hs.rchunks_exact(SIMD_FOLD_BYTES);
    let mut end = count;

    for block in simd_blocks.by_ref() {
        if has_byte_simd_folded(block, needle) {
            let mut panel_end = end;
            for chunk in block.rchunks_exact(SIMD_LANES) {
                if has_byte_simd_32(chunk, needle)
                    && let Some(j) = chunk.iter().rposition(|&b| b == needle)
                {
                    return Some(panel_end - SIMD_LANES + j);
                }
                panel_end -= SIMD_LANES;
            }
        }
        end -= SIMD_FOLD_BYTES;
    }

    let hs = simd_blocks.remainder();
    let mut simd_chunks = hs.rchunks_exact(SIMD_LANES);

    for chunk in simd_chunks.by_ref() {
        if has_byte_simd_32(chunk, needle)
            && let Some(j) = chunk.iter().rposition(|&b| b == needle)
        {
            return Some(end - SIMD_LANES + j);
        }
        end -= SIMD_LANES;
    }

    let hs = simd_chunks.remainder();
    let mut chunks = hs.rchunks_exact(WORD);

    for chunk in chunks.by_ref() {
        if has_byte_u64(u64_from_chunk(chunk), needle) {
            // The SWAR probe is exact, so this lookup always resolves.
            if let Some(j) = chunk.iter().rposition(|&b| b == needle) {
                return Some(end - WORD + j);
            }
        }
        end -= WORD;
    }

    // `rchunks_exact` leaves its remainder at the front (indices `0..rem_len`).
    chunks.remainder().iter().rposition(|&b| b == needle)
}

/// Searches `haystack` (first `n` bytes) for the byte sequence `needle` (of length `needle_len`).
///
/// Equivalent to GNU `memmem`. Returns the index of the first occurrence,
/// or `None` if not found.
pub fn memmem(haystack: &[u8], n: usize, needle: &[u8], needle_len: usize) -> Option<usize> {
    let h_count = n.min(haystack.len());
    let n_count = needle_len.min(needle.len());

    if n_count == 0 {
        return Some(0);
    }
    if n_count > h_count {
        return None;
    }

    let hay = &haystack[..h_count];
    let ndl = &needle[..n_count];

    // Single-byte needle: defer to the SIMD memchr scan.
    if n_count == 1 {
        return memchr(hay, ndl[0], h_count);
    }

    // Fast path: jump to each first-byte candidate with the SIMD `memchr` scan
    // and verify the full needle there (a SIMD slice compare), instead of the
    // scalar byte-at-a-time shift loop in Two-Way. This is the common case for
    // real text where the needle's first byte is uncommon.
    //
    // To keep the documented O(n+m) worst-case guarantee against adversarial
    // input (many first-byte hits that fail to match, e.g. "aa…ab" in "aa…a"),
    // bail to `two_way_search` once cumulative verification work (failed
    // candidates x needle length) exceeds the haystack length — at which point
    // Two-Way is at least as good. Both paths return the leftmost match, so the
    // result is identical.
    let first = ndl[0];
    let last = ndl[n_count - 1];

    // Dual-anchor fast path: a match at `cand` requires BOTH the first needle
    // byte at `cand` and the last needle byte at `cand + n_count - 1`. When the
    // first byte is common (e.g. "aaaa…b" over an 'a' run) but the last byte is
    // rare/absent, anchoring the SIMD `memchr` scan on the last byte collapses
    // the search to a single pass — the first-byte-only scan below makes every
    // position a candidate (O(n·m) before the Two-Way bailout). We scan for the
    // last byte; each hit confirms the first byte and a full compare. Only valid
    // when `first != last`; otherwise the anchors coincide and we use the
    // first-byte scan. The O(n+m) Two-Way bailout and leftmost-match semantics
    // are preserved (last-byte hits are visited left to right, so candidate
    // starts increase monotonically). Mirrors the wide `wcsstr` dual-anchor.
    if first != last {
        let mut anchor = n_count - 1;
        let mut miss_work = 0usize;
        while anchor < hay.len() {
            let scan = &hay[anchor..];
            let Some(off) = memchr(scan, last, scan.len()) else {
                return None; // last byte never recurs → no match
            };
            let last_pos = anchor + off;
            let cand = last_pos - (n_count - 1);
            if hay[cand] == first && hay[cand..cand + n_count] == *ndl {
                return Some(cand);
            }
            miss_work += n_count;
            anchor = last_pos + 1;
            if miss_work > hay.len() {
                return two_way_search(&hay[cand..], ndl).map(|m| m + cand);
            }
        }
        return None;
    }

    let mut start = 0usize;
    let mut miss_work = 0usize;
    while start + n_count <= hay.len() {
        let scan = &hay[start..];
        let Some(off) = memchr(scan, first, scan.len()) else {
            return None; // first byte does not occur again → no match
        };
        let cand = start + off;
        if cand + n_count > hay.len() {
            return None; // not enough room left for the needle
        }
        if hay[cand..cand + n_count] == *ndl {
            return Some(cand);
        }
        miss_work += n_count;
        start = cand + 1;
        if miss_work > hay.len() {
            // Too many failed candidates: finish with the guaranteed O(n+m)
            // search over the remaining suffix (everything before `start` has
            // already been ruled out, so the leftmost match lies in `start..`).
            return two_way_search(&hay[start..], ndl).map(|m| m + start);
        }
    }
    None
}

/// Linear-time substring search via the Two-Way (Crochemore–Perrin)
/// algorithm — the same complexity class glibc's `memmem`/`strstr` use.
///
/// The naive `windows().position()` scan is O(n·m) in the worst case
/// (a quadratic blow-up an adversary can trigger with repetitive input,
/// e.g. `"aaa…ab"` searched for `"aaa…ab"`). Two-Way runs in O(n+m) time
/// with O(1) auxiliary space: it computes a *critical factorization* of
/// the needle (via the maximal suffix under both byte orderings), then
/// scans the haystack comparing the right factor first and shifting by
/// the needle's period on a match — augmented here with a Boyer–Moore–
/// Horspool last-byte shift and a 256-bit membership set so typical text
/// skips ahead rather than inspecting every byte.
///
/// Returns the offset of the leftmost match within `hay`, which is
/// algorithm-independent, so this is bit-for-bit output-equivalent to the
/// naive scan (and to glibc). `ndl` must be non-empty and no longer than
/// `hay`. Ported from musl's `twoway_memmem`; every index is bounds-safe.
/// Case-fold helper threaded through Two-Way: identity when `ICASE` is false
/// (the case-sensitive path stays bit-for-bit unchanged and the branch compiles
/// away), ASCII lowercase when true.
#[inline(always)]
fn fold_case<const ICASE: bool>(b: u8) -> u8 {
    if ICASE { b.to_ascii_lowercase() } else { b }
}

fn two_way_search(hay: &[u8], ndl: &[u8]) -> Option<usize> {
    two_way_search_impl::<false>(hay, ndl)
}

/// Case-insensitive (ASCII) Two-Way search. Folds every needle and haystack
/// byte to lowercase inline, so it is allocation-free and returns the leftmost
/// case-insensitive match — used by `strcasestr` to bound its O(n*m) probe
/// pathology to O(n+m), exactly as `memmem` does for `strstr`.
pub(crate) fn two_way_search_icase(hay: &[u8], ndl: &[u8]) -> Option<usize> {
    two_way_search_impl::<true>(hay, ndl)
}

fn two_way_search_impl<const ICASE: bool>(hay: &[u8], ndl: &[u8]) -> Option<usize> {
    let l = ndl.len();
    let li = l as isize;

    // Membership set + Horspool last-occurrence shift table for the (folded) needle.
    let mut byteset = [0u64; 4];
    let mut shift = [0usize; 256];
    for (i, &raw) in ndl.iter().enumerate() {
        let b = fold_case::<ICASE>(raw);
        byteset[(b >> 6) as usize] |= 1u64 << (b & 63);
        shift[b as usize] = i + 1;
    }
    let in_needle = |b: u8| byteset[(b >> 6) as usize] & (1u64 << (b & 63)) != 0;

    // Maximal suffix under "<=" (max_suffix) and under ">=" (max_suffix_rev);
    // the later critical position together with the global period `p`.
    let max_suffix = |reverse: bool| -> (isize, isize) {
        let mut ip: isize = -1;
        let mut jp: isize = 0;
        let mut k: isize = 1;
        let mut p: isize = 1;
        while jp + k < li {
            let a = fold_case::<ICASE>(ndl[(ip + k) as usize]);
            let b = fold_case::<ICASE>(ndl[(jp + k) as usize]);
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

    // Is the needle periodic with period `p`? Compare the head ndl[0..ms+1]
    // against ndl[p..]. `.get()` keeps this panic-free; if the (in-practice
    // unreachable) bound is exceeded we conservatively treat it as the
    // general, non-periodic case, which Two-Way handles correctly.
    let suffix = (ms + 1) as usize;
    let periodic = (0..suffix).all(|i| {
        ndl.get(p as usize + i).map(|&b| fold_case::<ICASE>(b)) == Some(fold_case::<ICASE>(ndl[i]))
    });
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

        // Boyer–Moore–Horspool: examine the window's last byte first. If it
        // is absent from the needle, skip a whole needle length; otherwise
        // shift so that byte aligns with its last needle occurrence.
        let last = fold_case::<ICASE>(hay[pos + l - 1]);
        if !in_needle(last) {
            pos += l;
            mem = 0;
            continue;
        }
        let skip = l - shift[last as usize];
        if skip != 0 {
            pos += if (skip as isize) < mem {
                mem as usize
            } else {
                skip
            };
            mem = 0;
            continue;
        }

        // Right factor: compare from the critical position rightward.
        let mut k = (ms + 1) as usize;
        while k < l && fold_case::<ICASE>(ndl[k]) == fold_case::<ICASE>(hay[pos + k]) {
            k += 1;
        }
        if k < l {
            // ms may be -1 (critical position 0), so advance in signed space.
            pos += (k as isize - ms) as usize;
            mem = 0;
            continue;
        }

        // Left factor: compare the head down to the remembered prefix.
        let mut j = ms + 1;
        while j > mem
            && fold_case::<ICASE>(ndl[(j - 1) as usize])
                == fold_case::<ICASE>(hay[pos + (j - 1) as usize])
        {
            j -= 1;
        }
        if j <= mem {
            return Some(pos);
        }
        pos += p as usize;
        mem = mem0;
    }
}

/// Copies `n` bytes from `src` to `dest` and returns the index one past the
/// last byte written.
///
/// Equivalent to GNU `mempcpy`. Only copies `min(n, src.len(), dest.len())` bytes.
///
/// Returns the number of bytes copied (which is also the index of the next
/// unwritten byte in `dest`).
pub fn mempcpy(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let count = n.min(dest.len()).min(src.len());
    dest[..count].copy_from_slice(&src[..count]);
    count
}

/// Copies bytes from `src` to `dest` until byte `c` is found or `n` bytes copied.
///
/// Equivalent to POSIX `memccpy`. Returns the index one past the copied byte `c`,
/// or `None` if `c` was not found within `n` bytes.
pub fn memccpy(dest: &mut [u8], src: &[u8], c: u8, n: usize) -> Option<usize> {
    let count = n.min(dest.len()).min(src.len());

    if count < SIMD_LANES {
        for i in 0..count {
            dest[i] = src[i];
            if src[i] == c {
                return Some(i + 1);
            }
        }
        return None;
    }

    // Locate `c` with the SIMD memchr scan, then copy the resulting prefix in
    // one bulk move (lowered to the memcpy intrinsic) instead of a byte loop.
    // Behaviour is identical: if `c` occurs at index `p < count`, bytes
    // `0..=p` are copied and `Some(p + 1)` returned; otherwise all `count`
    // bytes are copied and `None` returned.
    match memchr(&src[..count], c, count) {
        Some(p) => {
            dest[..=p].copy_from_slice(&src[..=p]);
            Some(p + 1)
        }
        None => {
            dest[..count].copy_from_slice(&src[..count]);
            None
        }
    }
}

/// Sets `n` bytes of `dest` to zero, guaranteed not to be optimized away.
///
/// Equivalent to `explicit_bzero` / `bzero`.
pub fn bzero(dest: &mut [u8], n: usize) {
    let count = n.min(dest.len());
    for byte in &mut dest[..count] {
        // Use volatile-like write to prevent optimization.
        *byte = 0;
    }
    // Prevent the compiler from optimizing away the zeroing.
    std::hint::black_box(&dest[..count]);
}

/// Compares `n` bytes of `a` and `b`. Returns 0 if equal, non-zero otherwise.
///
/// Equivalent to legacy BSD `bcmp`.
pub fn bcmp(a: &[u8], b: &[u8], n: usize) -> i32 {
    let count = n.min(a.len()).min(b.len());
    let a = &a[..count];
    let b = &b[..count];

    if count < SIMD_LANES {
        for (x, y) in a.iter().zip(b.iter()) {
            if x != y {
                return 1;
            }
        }
        return 0;
    }

    // Equality-only SIMD scan: fold 128-byte blocks, then 32-byte panels, then
    // the byte tail. Unlike memcmp, bcmp never reports ordering, so the first
    // differing block can return `1` immediately without resolving which byte.
    let mut a_blocks = a.chunks_exact(SIMD_FOLD_BYTES);
    let mut b_blocks = b.chunks_exact(SIMD_FOLD_BYTES);
    for (a_block, b_block) in a_blocks.by_ref().zip(b_blocks.by_ref()) {
        if ne_simd_folded_128(a_block, b_block) {
            return 1;
        }
    }

    let mut a_panels = a_blocks.remainder().chunks_exact(SIMD_LANES);
    let mut b_panels = b_blocks.remainder().chunks_exact(SIMD_LANES);
    for (a_chunk, b_chunk) in a_panels.by_ref().zip(b_panels.by_ref()) {
        if !eq_simd_32(a_chunk, b_chunk) {
            return 1;
        }
    }

    for (x, y) in a_panels.remainder().iter().zip(b_panels.remainder().iter()) {
        if x != y {
            return 1;
        }
    }
    0
}

/// Swaps adjacent bytes in pairs from `src` into `dest`.
///
/// Equivalent to POSIX `swab`. Processes `n` bytes (n should be even).
pub fn swab(src: &[u8], dest: &mut [u8], n: usize) -> usize {
    let pairs = n.min(src.len()).min(dest.len()) / 2;
    for i in 0..pairs {
        dest[2 * i] = src[2 * i + 1];
        dest[2 * i + 1] = src[2 * i];
    }
    pairs * 2
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

    // Naive reference: leftmost substring match (the algorithm-independent
    // result memmem must reproduce).
    fn memmem_naive(hay: &[u8], ndl: &[u8]) -> Option<usize> {
        if ndl.is_empty() {
            return Some(0);
        }
        if ndl.len() > hay.len() {
            return None;
        }
        (0..=hay.len() - ndl.len()).find(|&i| &hay[i..i + ndl.len()] == ndl)
    }

    #[test]
    fn memmem_simd_prefilter_isomorphic_to_naive() {
        // Deterministic mix: small alphabets make first-byte hits (and false
        // candidates) common, exercising both the fast path and the Two-Way
        // fallback; the adversarial block targets the O(n+m) guard directly.
        let mut state: u64 = 0x51F0_A3C5_9E2B_7D11;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };
        for _ in 0..20_000 {
            let alpha = 1 + (next() % 4) as u8; // alphabet size 1..=4
            let hlen = (next() % 64) as usize;
            let nlen = 1 + (next() % 8) as usize;
            let hay: Vec<u8> = (0..hlen)
                .map(|_| b'a' + (next() % alpha as u64) as u8)
                .collect();
            let ndl: Vec<u8> = (0..nlen)
                .map(|_| b'a' + (next() % alpha as u64) as u8)
                .collect();
            let got = memmem(&hay, hay.len(), &ndl, ndl.len());
            let want = memmem_naive(&hay, &ndl);
            assert_eq!(got, want, "memmem mismatch hay={hay:?} ndl={ndl:?}");
        }
        // Adversarial: "aa…ab" needle in "aa…a" haystack (every position is a
        // first-byte candidate that fails) — must still find / not-find correctly.
        for n in [4usize, 16, 64, 256] {
            let hay = vec![b'a'; n];
            let mut ndl = vec![b'a'; n.min(8)];
            *ndl.last_mut().unwrap() = b'b';
            assert_eq!(
                memmem(&hay, hay.len(), &ndl, ndl.len()),
                memmem_naive(&hay, &ndl),
                "adversarial mismatch n={n}"
            );
            // And a guaranteed match at the tail.
            let mut hay2 = vec![b'a'; n];
            let tail = ndl.len().min(n);
            hay2[n - tail..].copy_from_slice(&ndl[..tail]);
            assert_eq!(
                memmem(&hay2, hay2.len(), &ndl, ndl.len()),
                memmem_naive(&hay2, &ndl),
                "adversarial-tail mismatch n={n}"
            );
        }
    }

    #[test]
    fn test_memcpy_basic() {
        let src = b"hello";
        let mut dest = [0u8; 5];
        let n = memcpy(&mut dest, src, 5);
        assert_eq!(n, 5);
        assert_eq!(&dest, b"hello");
    }

    #[test]
    fn test_memcpy_partial() {
        let src = b"hello world";
        let mut dest = [0u8; 5];
        let n = memcpy(&mut dest, src, 5);
        assert_eq!(n, 5);
        assert_eq!(&dest, b"hello");
    }

    #[test]
    fn test_memset_basic() {
        let mut buf = [0u8; 8];
        memset(&mut buf, b'A', 8);
        assert_eq!(&buf, b"AAAAAAAA");
    }

    #[test]
    fn test_memset_partial() {
        let mut buf = [0u8; 8];
        memset(&mut buf, b'X', 3);
        assert_eq!(&buf, b"XXX\0\0\0\0\0");
    }

    #[test]
    fn test_memcmp_equal() {
        assert_eq!(memcmp(b"abc", b"abc", 3), core::cmp::Ordering::Equal);
    }

    #[test]
    fn test_memcmp_less() {
        assert_eq!(memcmp(b"abc", b"abd", 3), core::cmp::Ordering::Less);
    }

    #[test]
    fn test_memcmp_greater() {
        assert_eq!(memcmp(b"abd", b"abc", 3), core::cmp::Ordering::Greater);
    }

    #[test]
    fn test_memcmp_preserves_ordering_after_equal_prefix() {
        assert_eq!(
            memcmp(b"abcdefgh1", b"abcdefgh2", 9),
            core::cmp::Ordering::Less
        );
        assert_eq!(
            memcmp(b"abcdXfgh", b"abcdEfgh", 8),
            core::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_memcmp_preserves_first_difference_inside_bulk_chunk() {
        assert_eq!(
            memcmp(b"abZdefgh", b"acAdefgh", 8),
            core::cmp::Ordering::Less
        );
        assert_eq!(
            memcmp(b"abcdefgh\xfftail", b"abcdefgh\x00tail", 13),
            core::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_memchr_found() {
        assert_eq!(memchr(b"hello", b'l', 5), Some(2));
    }

    #[test]
    fn test_memchr_not_found() {
        assert_eq!(memchr(b"hello", b'z', 5), None);
    }

    #[test]
    fn test_memrchr_found() {
        assert_eq!(memrchr(b"hello", b'l', 5), Some(3));
    }

    #[test]
    fn test_memrchr_not_found() {
        assert_eq!(memrchr(b"hello", b'z', 5), None);
    }

    #[test]
    fn test_memchr_simd_chunk_resolves_first_match() {
        let mut haystack = vec![b'A'; 96];
        haystack[39] = b'Z';
        haystack[72] = b'Z';
        assert_eq!(memchr(&haystack, b'Z', haystack.len()), Some(39));
    }

    #[test]
    fn test_memchr_folded_simd_block_resolves_first_match() {
        let mut haystack = vec![b'A'; MEMCHR_FOLD_BYTES + SIMD_LANES];
        haystack[SIMD_LANES * 5 + 5] = b'Z';
        haystack[SIMD_LANES * 7 + 11] = b'Z';
        assert_eq!(
            memchr(&haystack, b'Z', haystack.len()),
            Some(SIMD_LANES * 5 + 5)
        );
    }

    #[test]
    fn test_memrchr_simd_chunk_resolves_last_match() {
        let mut haystack = vec![b'A'; 96];
        haystack[23] = b'Z';
        haystack[65] = b'Z';
        assert_eq!(memrchr(&haystack, b'Z', haystack.len()), Some(65));
    }

    #[test]
    fn test_memrchr_folded_simd_block_resolves_last_match() {
        let mut haystack = vec![b'A'; SIMD_FOLD_BYTES + SIMD_LANES];
        haystack[SIMD_LANES + 9] = b'Z';
        haystack[SIMD_LANES * 3 + 17] = b'Z';
        assert_eq!(
            memrchr(&haystack, b'Z', haystack.len()),
            Some(SIMD_LANES * 3 + 17)
        );
    }

    #[test]
    fn test_memmem_found() {
        assert_eq!(memmem(b"hello world", 11, b"world", 5), Some(6));
    }

    #[test]
    fn test_memmem_not_found() {
        assert_eq!(memmem(b"hello world", 11, b"xyz", 3), None);
    }

    #[test]
    fn test_memmem_empty_needle() {
        assert_eq!(memmem(b"hello", 5, b"", 0), Some(0));
    }

    #[test]
    fn test_memmem_needle_longer() {
        assert_eq!(memmem(b"hi", 2, b"hello", 5), None);
    }

    #[test]
    fn test_mempcpy_basic() {
        let src = b"hello";
        let mut dest = [0u8; 8];
        let end = mempcpy(&mut dest, src, 5);
        assert_eq!(end, 5);
        assert_eq!(&dest[..5], b"hello");
    }

    #[test]
    fn test_memccpy_found() {
        let src = b"hello world";
        let mut dest = [0u8; 16];
        let result = memccpy(&mut dest, src, b' ', 11);
        assert_eq!(result, Some(6)); // index past the space
        assert_eq!(&dest[..6], b"hello ");
    }

    #[test]
    fn test_memccpy_not_found() {
        let src = b"helloworld";
        let mut dest = [0u8; 16];
        let result = memccpy(&mut dest, src, b' ', 10);
        assert_eq!(result, None);
        assert_eq!(&dest[..10], b"helloworld");
    }

    #[test]
    fn test_memccpy_sub_simd_gate_matches_copy_until_contract() {
        for len in 0..SIMD_LANES {
            let mut src = vec![0x51; len];
            let mut dest = vec![0xA7; len + 1];
            assert_eq!(memccpy(&mut dest, &src, 0x42, len), None);
            assert_eq!(&dest[..len], &src[..]);
            assert_eq!(dest[len], 0xA7);

            for pos in 0..len {
                src[pos] = 0x42;
                dest.fill(0xA7);

                assert_eq!(memccpy(&mut dest, &src, 0x42, len), Some(pos + 1));
                assert_eq!(&dest[..=pos], &src[..=pos]);
                assert!(dest[pos + 1..].iter().all(|byte| *byte == 0xA7));

                src[pos] = 0x51;
            }

            if len > 0 {
                dest.fill(0xA7);
                assert_eq!(memccpy(&mut dest, &src, 0x42, len - 1), None);
                assert_eq!(&dest[..len - 1], &src[..len - 1]);
                assert_eq!(dest[len - 1], 0xA7);
            }
        }
    }

    #[test]
    fn test_bzero_basic() {
        let mut buf = [0xFFu8; 8];
        bzero(&mut buf, 8);
        assert_eq!(&buf, &[0u8; 8]);
    }

    #[test]
    fn test_bzero_partial() {
        let mut buf = [0xFFu8; 8];
        bzero(&mut buf, 3);
        assert_eq!(&buf, &[0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_bcmp_equal() {
        assert_eq!(bcmp(b"abc", b"abc", 3), 0);
    }

    #[test]
    fn test_bcmp_not_equal() {
        assert_ne!(bcmp(b"abc", b"abd", 3), 0);
    }

    #[test]
    fn test_bcmp_sub_simd_gate_matches_equality_contract() {
        for len in 0..SIMD_LANES {
            let mut left = vec![0xA5; len];
            let mut right = left.clone();
            assert_eq!(bcmp(&left, &right, len), 0);

            for pos in 0..len {
                right[pos] ^= 0xFF;
                assert_eq!(bcmp(&left, &right, len), 1);
                right[pos] = left[pos];
            }

            left.push(0x11);
            right.push(0x22);
            assert_eq!(bcmp(&left, &right, len), 0);
        }
    }

    #[test]
    fn test_swab_basic() {
        let src = b"BADCFE";
        let mut dest = [0u8; 6];
        let n = swab(src, &mut dest, 6);
        assert_eq!(n, 6);
        assert_eq!(&dest, b"ABCDEF");
    }

    #[test]
    fn test_swab_odd_length() {
        let src = b"BADCX";
        let mut dest = [0u8; 5];
        let n = swab(src, &mut dest, 5);
        assert_eq!(n, 4); // only 2 pairs (4 bytes)
        assert_eq!(&dest[..4], b"ABCD");
    }

    proptest! {
        #![proptest_config(property_proptest_config(256))]

        #[test]
        fn prop_memcpy_matches_prefix_copy(
            src in proptest::collection::vec(any::<u8>(), 0..128),
            dest_seed in proptest::collection::vec(any::<u8>(), 0..128),
            n in 0usize..256
        ) {
            let mut dest = dest_seed.clone();
            let original_dest = dest.clone();

            let copied = memcpy(&mut dest, &src, n);
            let expected = n.min(src.len()).min(original_dest.len());

            prop_assert_eq!(copied, expected);
            prop_assert_eq!(&dest[..expected], &src[..expected]);
            prop_assert_eq!(&dest[expected..], &original_dest[expected..]);
        }

        #[test]
        fn prop_memcmp_is_antisymmetric(
            left in proptest::collection::vec(any::<u8>(), 0..128),
            right in proptest::collection::vec(any::<u8>(), 0..128),
            n in 0usize..256
        ) {
            let lr = memcmp(&left, &right, n);
            let rl = memcmp(&right, &left, n);
            prop_assert_eq!(lr, rl.reverse());
        }

        /// Isomorphism guard for the 32-byte SIMD-panel scan: the result must
        /// match std's lexicographic (unsigned byte) ordering over the compared
        /// prefix for every input, including those spanning multiple panels and
        /// differing at any byte offset. Inputs run to 200 bytes so the SIMD
        /// panel loop, the 8-byte tail, and the byte tail are all exercised.
        #[test]
        fn prop_memcmp_matches_std_lexicographic(
            left in proptest::collection::vec(any::<u8>(), 0..200),
            right in proptest::collection::vec(any::<u8>(), 0..200),
            n in 0usize..256
        ) {
            let count = n.min(left.len()).min(right.len());
            let expected = left[..count].cmp(&right[..count]);
            prop_assert_eq!(memcmp(&left, &right, n), expected);
        }

        #[test]
        fn prop_memset_only_mutates_requested_prefix(
            original in proptest::collection::vec(any::<u8>(), 0..128),
            value in any::<u8>(),
            n in 0usize..256
        ) {
            let mut buf = original.clone();
            let set = memset(&mut buf, value, n);
            let expected = n.min(original.len());

            prop_assert_eq!(set, expected);
            prop_assert!(buf.iter().take(expected).all(|b| *b == value));
            prop_assert_eq!(&buf[expected..], &original[expected..]);
        }

        // Isomorphism: the SWAR scan must return the exact index a byte-at-a-time
        // `position` scan would. `0..200` spans the chunk size (8) and unaligned
        // remainders; `n` ranges past the length to exercise the clamp.
        #[test]
        fn prop_memchr_matches_scalar_position(
            haystack in proptest::collection::vec(any::<u8>(), 0..200),
            needle in any::<u8>(),
            n in 0usize..256
        ) {
            let count = n.min(haystack.len());
            let expected = haystack[..count].iter().position(|&b| b == needle);
            prop_assert_eq!(memchr(&haystack, needle, n), expected);
        }

        #[test]
        fn prop_memrchr_matches_scalar_rposition(
            haystack in proptest::collection::vec(any::<u8>(), 0..200),
            needle in any::<u8>(),
            n in 0usize..256
        ) {
            let count = n.min(haystack.len());
            let expected = haystack[..count].iter().rposition(|&b| b == needle);
            prop_assert_eq!(memrchr(&haystack, needle, n), expected);
        }
    }

    // ===== glibc parity tests =====
    // Verified against glibc via scripts/c_probes/probe_string_edge.c

    #[test]
    fn memchr_golden_output_sha256() {
        use sha2::{Digest, Sha256};

        let mut cases: Vec<(Vec<u8>, u8, usize)> = vec![
            (Vec::new(), 0, 0),
            (b"abc".to_vec(), b'a', 0),
            (b"abc".to_vec(), b'a', 1),
            (b"abc".to_vec(), b'b', 1),
            (b"abc".to_vec(), b'b', 2),
            (b"abc".to_vec(), b'z', 99),
            (vec![b'a'; 4096], b'z', 4096),
            (vec![b'a'; 4096], b'z', 2048),
        ];
        for pos in [0usize, 1, 7, 8, 31, 32, 63, 64, 127, 128, 255, 256, 4095] {
            let mut hay = vec![b'a'; 4096];
            hay[pos] = b'z';
            cases.push((hay, b'z', 4096));
        }

        let mut hasher = Sha256::new();
        for (hay, needle, n) in cases {
            hasher.update((hay.len() as u64).to_le_bytes());
            hasher.update((n as u64).to_le_bytes());
            hasher.update([needle]);
            match memchr(&hay, needle, n) {
                Some(index) => {
                    hasher.update([1]);
                    hasher.update((index as u64).to_le_bytes());
                }
                None => hasher.update([0]),
            }
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "04930b6afad5d9eb3047ad0fd21c4db13061e93ee506bcf740787790f8ae3500",
            "memchr golden output corpus changed"
        );
    }

    #[test]
    fn glibc_memchr_n_zero_returns_none() {
        // memchr("hello", 'h', 0) = NULL even though 'h' is at position 0
        assert_eq!(memchr(b"hello", b'h', 0), None);
    }

    #[test]
    fn glibc_memcmp_n_zero_returns_equal() {
        // memcmp("a", "b", 0) = 0 regardless of content
        assert_eq!(memcmp(b"a", b"b", 0), core::cmp::Ordering::Equal);
        assert_eq!(memcmp(b"xyz", b"abc", 0), core::cmp::Ordering::Equal);
    }

    #[test]
    fn glibc_memcmp_partial_compare() {
        // memcmp("abc", "abx", 2) = 0 (only compares first 2 bytes)
        assert_eq!(memcmp(b"abc", b"abx", 2), core::cmp::Ordering::Equal);
    }

    #[test]
    fn glibc_memmem_empty_needle_returns_zero() {
        // memmem(haystack, 11, "", 0) returns start of haystack
        assert_eq!(memmem(b"hello world", 11, b"", 0), Some(0));
    }

    #[test]
    fn glibc_memrchr_finds_last_occurrence() {
        // memrchr("hello", 'l', 5) = offset 3 (last 'l')
        assert_eq!(memrchr(b"hello", b'l', 5), Some(3));
    }

    // -- Two-Way memmem isomorphism vs the naive reference --------------------

    /// Reference O(n·m) scan — the leftmost match an algorithm-independent
    /// `memmem` must reproduce. Used as the differential oracle.
    fn naive_memmem(hay: &[u8], ndl: &[u8]) -> Option<usize> {
        if ndl.is_empty() {
            return Some(0);
        }
        if ndl.len() > hay.len() {
            return None;
        }
        hay.windows(ndl.len()).position(|w| w == ndl)
    }

    fn check_isomorphic(hay: &[u8], ndl: &[u8]) {
        let got = memmem(hay, hay.len(), ndl, ndl.len());
        let want = naive_memmem(hay, ndl);
        assert_eq!(
            got, want,
            "memmem divergence\n hay={hay:?}\n ndl={ndl:?}\n two_way={got:?} naive={want:?}"
        );
    }

    #[test]
    fn memmem_matches_naive_on_adversarial_corpus() {
        // Repetitive / periodic inputs are exactly where naive goes quadratic
        // and where Two-Way's critical-factorization shifts must stay correct.
        let cases: &[(&[u8], &[u8])] = &[
            (b"aaaaaaaaab", b"aaaab"),
            (b"aaaaaaaaaa", b"aaaab"),
            (b"abababababab", b"ababab"),
            (b"abababababab", b"ababa"),
            (b"abcabcabcabcabc", b"abcabcd"),
            (b"mississippi", b"issi"),
            (b"mississippi", b"ssippi"),
            (b"the quick brown fox", b"quick"),
            (b"the quick brown fox", b"fox"),
            (b"the quick brown fox", b"the"),
            (b"aaa", b"aa"),
            (b"ba", b"aa"),
            (b"xy", b"xy"),
            (b"", b"a"),
            (b"a", b""),
            (b"abc", b"abcd"),
            (b"\x00\x00\x01\x00\x00", b"\x01\x00\x00"),
        ];
        for (hay, ndl) in cases {
            check_isomorphic(hay, ndl);
        }
    }

    #[test]
    fn memmem_matches_naive_on_dense_periodic_alphabet() {
        // Small alphabet → many partial matches → maximal Two-Way stress.
        for period in 1..=6usize {
            let mut hay = Vec::new();
            for i in 0..400 {
                hay.push(b'a' + (i % period) as u8);
            }
            for nlen in 1..=24usize {
                let ndl = &hay[3..(3 + nlen).min(hay.len())];
                check_isomorphic(&hay, ndl);
                // A needle that almost-but-not-quite matches the period.
                let mut bad = ndl.to_vec();
                if let Some(last) = bad.last_mut() {
                    *last = b'z';
                }
                check_isomorphic(&hay, &bad);
            }
        }
    }

    proptest! {
        #![proptest_config(property_proptest_config(2048))]

        /// Over random small-alphabet haystacks/needles, Two-Way must return
        /// the exact same leftmost offset as the naive reference.
        #[test]
        fn prop_memmem_matches_naive(
            hay in proptest::collection::vec(0u8..4, 0..64),
            ndl in proptest::collection::vec(0u8..4, 0..12),
        ) {
            let got = memmem(&hay, hay.len(), &ndl, ndl.len());
            let want = naive_memmem(&hay, &ndl);
            prop_assert_eq!(got, want);
        }

        /// Needles that genuinely occur must be located (and at the leftmost
        /// position), exercising the matched-and-shift paths.
        #[test]
        fn prop_memmem_finds_embedded_needle(
            prefix in proptest::collection::vec(0u8..3, 0..40),
            ndl in proptest::collection::vec(0u8..3, 1..10),
            suffix in proptest::collection::vec(0u8..3, 0..40),
        ) {
            let mut hay = prefix.clone();
            hay.extend_from_slice(&ndl);
            hay.extend_from_slice(&suffix);
            let got = memmem(&hay, hay.len(), &ndl, ndl.len());
            let want = naive_memmem(&hay, &ndl);
            prop_assert_eq!(got, want);
            prop_assert!(got.is_some());
        }
    }

    /// Golden SHA-256 over a deterministic (haystack, needle) result corpus.
    /// Locks the externally observable output so any future change to the
    /// search internals that perturbs a returned offset is caught.
    #[test]
    fn memmem_golden_output_sha256() {
        use std::fmt::Write as _;

        // Deterministic LCG corpus across several alphabets and lengths.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };

        let mut transcript = String::new();
        for alphabet in [2u32, 4, 16, 256] {
            for _ in 0..256 {
                let hlen = (next() % 96) as usize;
                let nlen = (next() % 12) as usize;
                let hay: Vec<u8> = (0..hlen).map(|_| (next() % alphabet) as u8).collect();
                let ndl: Vec<u8> = (0..nlen).map(|_| (next() % alphabet) as u8).collect();
                let got = memmem(&hay, hay.len(), &ndl, ndl.len());
                // Cross-check the oracle inline so the golden value can only
                // ever encode correct answers.
                assert_eq!(got, naive_memmem(&hay, &ndl));
                let _ = write!(transcript, "{got:?};");
            }
        }

        // FNV-1a digest (no extra deps) over the transcript — stable across
        // platforms, pinned to the correct-by-construction result stream.
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for b in transcript.as_bytes() {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        assert_eq!(
            hash, GOLDEN_MEMMEM_FNV1A,
            "memmem golden transcript changed: {hash:#018x}"
        );
    }

    // Pinned after first green run; recomputed deterministically above.
    const GOLDEN_MEMMEM_FNV1A: u64 = 0xbfed_48b0_dbd8_cc1e;

    /// Before/after wall-clock proof for the Two-Way swing. Ignored by
    /// default (it is a benchmark, not a unit test); run explicitly with
    /// `cargo test -p frankenlibc-core --lib string::mem::tests::memmem_perf \
    ///  -- --ignored --nocapture`.
    #[test]
    #[ignore = "perf benchmark; run with --ignored --nocapture"]
    fn memmem_perf_two_way_vs_naive() {
        use std::time::Instant;

        fn time<F: FnMut() -> Option<usize>>(iters: u32, mut f: F) -> f64 {
            // warm up
            for _ in 0..3 {
                std::hint::black_box(f());
            }
            let t = Instant::now();
            for _ in 0..iters {
                std::hint::black_box(f());
            }
            t.elapsed().as_secs_f64() / iters as f64 * 1e9 // ns/call
        }

        // --- Adversarial: O(n·m) trap. Needle's trailing 'b' forces naive to
        //     rescan the full needle at every haystack offset. ---
        let hay = vec![b'a'; 50_000];
        let mut ndl = vec![b'a'; 2_000];
        ndl.push(b'b'); // absent → worst case
        let naive_adv = time(20, || naive_memmem(&hay, &ndl));
        let tw_adv = time(20, || memmem(&hay, hay.len(), &ndl, ndl.len()));

        // --- Typical: 64 KiB pseudo-text, 16-byte needle near the end. ---
        let mut text = vec![0u8; 65_536];
        let mut s: u64 = 0x1234_5678;
        for b in text.iter_mut() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = b' ' + ((s >> 40) as u8 % 95);
        }
        let hay = text;
        let ndl_typ = hay[65_500..65_516].to_vec();
        let naive_typ = time(2_000, || naive_memmem(&hay, &ndl_typ));
        let tw_typ = time(2_000, || memmem(&hay, hay.len(), &ndl_typ, ndl_typ.len()));

        eprintln!(
            "memmem adversarial: naive={naive_adv:.0}ns two_way={tw_adv:.0}ns score={:.1}x",
            naive_adv / tw_adv
        );
        eprintln!(
            "memmem typical:     naive={naive_typ:.0}ns two_way={tw_typ:.0}ns score={:.2}x",
            naive_typ / tw_typ
        );

        // The complexity-class win must be enormous on the adversarial case
        // and must not regress the typical case.
        assert!(
            naive_adv / tw_adv >= 2.0,
            "adversarial Score must clear 2.0"
        );
        assert!(
            tw_typ <= naive_typ * 1.5,
            "typical case must not regress materially"
        );
    }
}
