//! String operations: strlen, strnlen, strcmp, strncmp, strcpy, stpcpy, strncpy,
//! stpncpy, strcat, strncat, strchr, strchrnul, strrchr, strstr.
//!
//! These are safe Rust implementations operating on byte slices that represent
//! NUL-terminated C strings. In this safe Rust model, strings are `&[u8]` slices
//! where a NUL byte (`0x00`) marks the logical end of the string.

use std::simd::{Mask, Select, Simd, cmp::SimdOrd, cmp::SimdPartialEq, cmp::SimdPartialOrd};

const LO_MAGIC: usize = usize::from_ne_bytes([0x01; size_of::<usize>()]);
const HI_MAGIC: usize = usize::from_ne_bytes([0x80; size_of::<usize>()]);
const SIMD_LANES: usize = 32;
const STRLEN_SIMD_LANES: usize = 64;
/// Bytes scanned per folded strlen iteration: four `STRLEN_SIMD_LANES` panels.
const STRLEN_BLOCK: usize = STRLEN_SIMD_LANES * 4;
/// Bytes scanned per wide folded strlen NUL iteration.
const STRLEN_NUL_BLOCK: usize = STRLEN_SIMD_LANES * 8;
const STRCPY_4096_SRC_LEN: usize = STRLEN_NUL_BLOCK * 8 + 1;

#[inline(always)]
fn has_nul_byte(word: usize) -> bool {
    word.wrapping_sub(LO_MAGIC) & !word & HI_MAGIC != 0
}

// (repeated_byte removed: its only user, find_non_byte_or_nul's SWAR small path, is
// gone — replaced by a direct simd_ne mask scan. bd-2g7oyh.)

// (has_byte_or_nul_simd_32 removed: find_byte_or_nul/find_ascii_folded now mask-scan
// directly, so this bool prefilter is unused. bd-2g7oyh.)

/// Number of 32-byte SIMD panels folded under a single `.any()` reduction. The
/// reduction (movemask + test) is the per-iteration cost that dominates a flat
/// per-32B scan, so OR-ing four panels' hit masks before reducing amortizes it
/// across 128 bytes — the same lever that makes the core `memchr` ~2x. (Eight
/// panels / 256B was measured slightly slower — register pressure outweighs the
/// halved reduction count, so four is the sweet spot.)
const SIMD_FOLD_PANELS: usize = 4;
const SIMD_FOLD_BYTES: usize = SIMD_LANES * SIMD_FOLD_PANELS;
const STRCMP_EXACT_256_LEN: usize = STRLEN_BLOCK + 1;

// (has_byte_or_nul_simd_folded_256 + STRCHR_FOLD_PANELS/BYTES removed: find_byte_or_nul
// and strrchr now use a direct mask scan / memrchr, so the folded coarse-check is unused.
// bd-2g7oyh.)

#[inline(always)]
fn has_nul_simd_64(chunk: &[u8]) -> bool {
    debug_assert_eq!(chunk.len(), STRLEN_SIMD_LANES);
    Simd::<u8, STRLEN_SIMD_LANES>::from_slice(chunk)
        .simd_eq(Simd::splat(0))
        .any()
}

/// Returns `true` if any byte in a `STRLEN_BLOCK`-wide chunk is NUL.
///
/// Folds four `STRLEN_SIMD_LANES` panels with unsigned `simd_min` before a
/// single zero-compare reduction. Because `min(a, b) == 0` iff either lane is
/// `0`, the folded vector has a zero lane exactly when one of the four panels
/// does — so this is equivalent to OR-ing four per-panel NUL checks, but pays
/// one horizontal reduction per 256 bytes instead of one per 64. The caller's
/// word/byte tail scan then resolves the exact NUL index, so detection width
/// never changes the returned length.
#[inline(always)]
fn block_has_nul_256(chunk: &[u8]) -> bool {
    debug_assert_eq!(chunk.len(), STRLEN_BLOCK);
    let v0 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&chunk[0..STRLEN_SIMD_LANES]);
    let v1 =
        Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&chunk[STRLEN_SIMD_LANES..STRLEN_SIMD_LANES * 2]);
    let v2 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(
        &chunk[STRLEN_SIMD_LANES * 2..STRLEN_SIMD_LANES * 3],
    );
    let v3 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&chunk[STRLEN_SIMD_LANES * 3..STRLEN_BLOCK]);
    let folded = v0.simd_min(v1).simd_min(v2.simd_min(v3));
    folded.simd_eq(Simd::splat(0)).any()
}

#[inline(always)]
fn block_has_nul_512(chunk: &[u8]) -> bool {
    debug_assert_eq!(chunk.len(), STRLEN_NUL_BLOCK);
    let v0 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&chunk[0..STRLEN_SIMD_LANES]);
    let v1 =
        Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&chunk[STRLEN_SIMD_LANES..STRLEN_SIMD_LANES * 2]);
    let v2 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(
        &chunk[STRLEN_SIMD_LANES * 2..STRLEN_SIMD_LANES * 3],
    );
    let v3 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(
        &chunk[STRLEN_SIMD_LANES * 3..STRLEN_SIMD_LANES * 4],
    );
    let v4 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(
        &chunk[STRLEN_SIMD_LANES * 4..STRLEN_SIMD_LANES * 5],
    );
    let v5 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(
        &chunk[STRLEN_SIMD_LANES * 5..STRLEN_SIMD_LANES * 6],
    );
    let v6 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(
        &chunk[STRLEN_SIMD_LANES * 6..STRLEN_SIMD_LANES * 7],
    );
    let v7 =
        Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&chunk[STRLEN_SIMD_LANES * 7..STRLEN_NUL_BLOCK]);
    let folded = v0
        .simd_min(v1)
        .simd_min(v2.simd_min(v3))
        .simd_min(v4.simd_min(v5).simd_min(v6.simd_min(v7)));
    folded.simd_eq(Simd::splat(0)).any()
}

#[inline(always)]
fn copy_nul_free_block_512(dest: &mut [u8], src: &[u8]) -> bool {
    debug_assert_eq!(dest.len(), STRLEN_NUL_BLOCK);
    debug_assert_eq!(src.len(), STRLEN_NUL_BLOCK);
    let v0 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&src[0..STRLEN_SIMD_LANES]);
    let v1 =
        Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&src[STRLEN_SIMD_LANES..STRLEN_SIMD_LANES * 2]);
    let v2 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(
        &src[STRLEN_SIMD_LANES * 2..STRLEN_SIMD_LANES * 3],
    );
    let v3 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(
        &src[STRLEN_SIMD_LANES * 3..STRLEN_SIMD_LANES * 4],
    );
    let v4 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(
        &src[STRLEN_SIMD_LANES * 4..STRLEN_SIMD_LANES * 5],
    );
    let v5 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(
        &src[STRLEN_SIMD_LANES * 5..STRLEN_SIMD_LANES * 6],
    );
    let v6 = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(
        &src[STRLEN_SIMD_LANES * 6..STRLEN_SIMD_LANES * 7],
    );
    let v7 =
        Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&src[STRLEN_SIMD_LANES * 7..STRLEN_NUL_BLOCK]);
    let folded = v0
        .simd_min(v1)
        .simd_min(v2.simd_min(v3))
        .simd_min(v4.simd_min(v5).simd_min(v6.simd_min(v7)));
    if folded.simd_eq(Simd::splat(0)).any() {
        return true;
    }

    v0.copy_to_slice(&mut dest[0..STRLEN_SIMD_LANES]);
    v1.copy_to_slice(&mut dest[STRLEN_SIMD_LANES..STRLEN_SIMD_LANES * 2]);
    v2.copy_to_slice(&mut dest[STRLEN_SIMD_LANES * 2..STRLEN_SIMD_LANES * 3]);
    v3.copy_to_slice(&mut dest[STRLEN_SIMD_LANES * 3..STRLEN_SIMD_LANES * 4]);
    v4.copy_to_slice(&mut dest[STRLEN_SIMD_LANES * 4..STRLEN_SIMD_LANES * 5]);
    v5.copy_to_slice(&mut dest[STRLEN_SIMD_LANES * 5..STRLEN_SIMD_LANES * 6]);
    v6.copy_to_slice(&mut dest[STRLEN_SIMD_LANES * 6..STRLEN_SIMD_LANES * 7]);
    v7.copy_to_slice(&mut dest[STRLEN_SIMD_LANES * 7..STRLEN_NUL_BLOCK]);
    false
}

#[inline(always)]
fn copy_strcpy_terminal_from(dest: &mut [u8], src: &[u8], block_start: usize) -> usize {
    let mut i = block_start;
    while i < src.len() {
        if src[i] == 0 {
            let copied = i + 1;
            dest[block_start..copied].copy_from_slice(&src[block_start..copied]);
            return copied;
        }
        i += 1;
    }
    src.len()
}

#[inline(always)]
fn strcpy_4096_terminated(dest: &mut [u8], src: &[u8]) -> usize {
    debug_assert_eq!(src.len(), STRCPY_4096_SRC_LEN);
    debug_assert!(dest.len() >= src.len());
    debug_assert_eq!(src.last().copied(), Some(0));

    let mut block_start = 0usize;
    while block_start + STRLEN_NUL_BLOCK < STRCPY_4096_SRC_LEN {
        let block_end = block_start + STRLEN_NUL_BLOCK;
        if copy_nul_free_block_512(
            &mut dest[block_start..block_end],
            &src[block_start..block_end],
        ) {
            return copy_strcpy_terminal_from(dest, src, block_start);
        }
        block_start = block_end;
    }

    dest[STRCPY_4096_SRC_LEN - 1] = 0;
    STRCPY_4096_SRC_LEN
}

// (has_non_byte_simd_64 + block_has_non_byte_256 removed: find_non_byte_or_nul now
// uses a direct simd_ne mask scan, so these bool prefilters are unused. bd-2g7oyh.)

// (equal_and_no_nul_simd_32 removed: strcmp/strncmp's SIMD_LANES loops now compute
// the divergence index directly via an event-mask instead of a bool prefilter +
// scalar re-scan, so the bool helper is unused. bd-2g7oyh.)

/// True iff all `SIMD_FOLD_BYTES` (128) bytes are byte-for-byte equal AND
/// NUL-free. OR's the four 32-byte panels' `(differs | is_nul)` masks and
/// reduces once, instead of one `.any()` per 32-byte panel. glibc's
/// `strcmp_avx2` likewise issues a single combined movemask+test per 128-byte
/// (4×VEC) step; this matches that reduction cadence. A `false` result means
/// the 128-byte window contains a divergence or terminator, so the caller's
/// 32-byte loop (and scalar tail) re-scans from the same offset and resolves
/// the exact index — logically identical to a flat per-32B scan:
/// `∀panels (eq.all() && !nul.any())` ⇔ `!(⋃panels (differs | nul)).any()`.
#[inline(always)]
fn equal_and_no_nul_simd_folded(left: &[u8], right: &[u8]) -> bool {
    debug_assert_eq!(left.len(), SIMD_FOLD_BYTES);
    debug_assert_eq!(right.len(), SIMD_FOLD_BYTES);
    let z = Simd::<u8, SIMD_LANES>::splat(0);
    let mut acc = Mask::<i8, SIMD_LANES>::splat(false);
    for k in 0..SIMD_FOLD_PANELS {
        let lo = k * SIMD_LANES;
        let l = Simd::<u8, SIMD_LANES>::from_slice(&left[lo..lo + SIMD_LANES]);
        let r = Simd::<u8, SIMD_LANES>::from_slice(&right[lo..lo + SIMD_LANES]);
        acc |= l.simd_ne(r) | l.simd_eq(z);
    }
    !acc.any()
}

#[inline(always)]
fn strcmp_exact_256_equal_nul_terminated(left: &[u8], right: &[u8]) -> bool {
    if left.len() != STRCMP_EXACT_256_LEN
        || right.len() != STRCMP_EXACT_256_LEN
        || left[STRLEN_BLOCK] != 0
        || right[STRLEN_BLOCK] != 0
    {
        return false;
    }

    let z = Simd::<u8, STRLEN_SIMD_LANES>::splat(0);
    let mut acc = Mask::<i8, STRLEN_SIMD_LANES>::splat(false);
    for k in 0..4 {
        let lo = k * STRLEN_SIMD_LANES;
        let l = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&left[lo..lo + STRLEN_SIMD_LANES]);
        let r = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&right[lo..lo + STRLEN_SIMD_LANES]);
        acc |= l.simd_ne(r) | l.simd_eq(z);
    }
    !acc.any()
}

#[inline(always)]
fn strncmp_exact_256_equal_prefix(left: &[u8], right: &[u8]) -> bool {
    debug_assert_eq!(left.len(), STRLEN_BLOCK);
    debug_assert_eq!(right.len(), STRLEN_BLOCK);

    let mut acc = Mask::<i8, STRLEN_SIMD_LANES>::splat(false);
    for k in 0..4 {
        let lo = k * STRLEN_SIMD_LANES;
        let l = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&left[lo..lo + STRLEN_SIMD_LANES]);
        let r = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&right[lo..lo + STRLEN_SIMD_LANES]);
        acc |= l.simd_ne(r);
    }
    !acc.any()
}

/// Branchless ASCII A-Z -> a-z fold of a 32-byte panel, exactly matching
/// `u8::to_ascii_lowercase` (only bytes in `b'A'..=b'Z'` are shifted by `0x20`;
/// everything else, including NUL, is unchanged).
#[inline(always)]
fn fold_ascii_upper_simd_32(v: Simd<u8, SIMD_LANES>) -> Simd<u8, SIMD_LANES> {
    let is_upper = v.simd_ge(Simd::splat(b'A')) & v.simd_le(Simd::splat(b'Z'));
    is_upper.select(v + Simd::splat(0x20), v)
}

// (fold_equal_and_no_nul_simd_32 removed: strcasecmp/strncasecmp's SIMD_LANES loops
// now compute the divergence index directly via a fold-event-mask using
// fold_ascii_upper_simd_32, so the bool helper is unused. bd-2g7oyh.)

#[inline(always)]
fn fold_equal_and_no_nul_simd_folded(left: &[u8], right: &[u8]) -> bool {
    debug_assert_eq!(left.len(), SIMD_FOLD_BYTES);
    debug_assert_eq!(right.len(), SIMD_FOLD_BYTES);
    let z = Simd::<u8, SIMD_LANES>::splat(0);
    let mut acc = Mask::<i8, SIMD_LANES>::splat(false);
    for k in 0..SIMD_FOLD_PANELS {
        let lo = k * SIMD_LANES;
        let l = Simd::<u8, SIMD_LANES>::from_slice(&left[lo..lo + SIMD_LANES]);
        let r = Simd::<u8, SIMD_LANES>::from_slice(&right[lo..lo + SIMD_LANES]);
        acc |= fold_ascii_upper_simd_32(l).simd_ne(fold_ascii_upper_simd_32(r)) | l.simd_eq(z);
    }
    !acc.any()
}

#[inline(always)]
fn byte_is_any4(byte: u8, b0: u8, b1: u8, b2: u8, b3: u8) -> bool {
    byte == b0 || byte == b1 || byte == b2 || byte == b3
}

// (has_any_of4_or_nul_simd_32 / _fused_32 / has_non_any_of4_or_nul_simd_32 were the
// bool "any flagged?" prefilters; the find_*_of4_or_nul scanners now compute the lane
// mask directly and return the first set lane via trailing_zeros, so the separate bool
// helpers + their scalar re-scan are gone. bd-2g7oyh.)

// (has_ascii_folded_byte_or_nul_simd_32 + _folded_128 removed: find_ascii_folded_byte_or_nul
// now uses a direct 3-way mask scan, so these bool prefilters are unused. bd-2g7oyh.)

#[inline]
fn byte_membership_table(bytes: &[u8]) -> [bool; 256] {
    let mut table = [false; 256];
    for &byte in bytes {
        table[byte as usize] = true;
    }
    table
}

/// Returns the length of a NUL-terminated byte string (not counting the NUL).
///
/// Equivalent to C `strlen`. Scans `s` for the first `0x00` byte and returns
/// its index. If no NUL is found, returns the full slice length.
#[inline(always)]
#[allow(unsafe_code)]
pub fn strlen(s: &[u8]) -> usize {
    const WORD_SIZE: usize = size_of::<usize>();

    let mut i = 0;

    // Handle unaligned prefix byte-by-byte
    while i < s.len() && !(s.as_ptr() as usize + i).is_multiple_of(WORD_SIZE) {
        if s[i] == 0 {
            return i;
        }
        i += 1;
    }

    // Fold eight panels per iteration so the expensive horizontal NUL reduction
    // runs once per 512 bytes instead of once per 64 over NUL-free spans.
    while i + STRLEN_NUL_BLOCK <= s.len() {
        let chunk = &s[i..i + STRLEN_NUL_BLOCK];
        if block_has_nul_512(chunk) {
            break;
        }
        i += STRLEN_NUL_BLOCK;
    }

    while i + STRLEN_BLOCK <= s.len() {
        let chunk = &s[i..i + STRLEN_BLOCK];
        if block_has_nul_256(chunk) {
            break;
        }
        i += STRLEN_BLOCK;
    }

    while i + STRLEN_SIMD_LANES <= s.len() {
        let chunk = &s[i..i + STRLEN_SIMD_LANES];
        if has_nul_simd_64(chunk) {
            break;
        }
        i += STRLEN_SIMD_LANES;
    }

    // Process aligned words
    while i + WORD_SIZE <= s.len() {
        // SAFETY: i is aligned to WORD_SIZE, and i + WORD_SIZE <= s.len()
        let word = unsafe { core::ptr::read(s.as_ptr().add(i) as *const usize) };
        if has_nul_byte(word) {
            break;
        }
        i += WORD_SIZE;
    }

    // Find exact NUL position in remaining bytes
    while i < s.len() {
        if s[i] == 0 {
            return i;
        }
        i += 1;
    }

    s.len()
}

/// Returns the length of a C string up to a maximum of `maxlen` bytes.
///
/// Equivalent to C `strnlen`. Scans at most `maxlen` bytes and returns:
/// - index of first `0x00` byte if found before `maxlen`
/// - otherwise `maxlen` (or `s.len()` when the slice is shorter)
pub fn strnlen(s: &[u8], maxlen: usize) -> usize {
    let limit = maxlen.min(s.len());
    strlen(&s[..limit])
}

/// Compares two NUL-terminated byte strings lexicographically.
///
/// Equivalent to C `strcmp`. Compares byte-by-byte until a difference is found
/// or both strings reach a NUL terminator.
///
/// Returns a negative value if `s1 < s2`, zero if equal, positive if `s1 > s2`.
#[allow(unsafe_code)]
pub fn strcmp(s1: &[u8], s2: &[u8]) -> i32 {
    const WORD_SIZE: usize = size_of::<usize>();

    if strcmp_exact_256_equal_nul_terminated(s1, s2) {
        return 0;
    }

    let mut i = 0;

    // Check if both pointers are aligned to the same offset mod WORD_SIZE
    let p1 = s1.as_ptr() as usize;
    let p2 = s2.as_ptr() as usize;
    let aligned = (p1 % WORD_SIZE) == (p2 % WORD_SIZE);

    if aligned {
        // Handle unaligned prefix byte-by-byte
        while i < s1.len() && i < s2.len() && !(p1 + i).is_multiple_of(WORD_SIZE) {
            let a = s1[i];
            let b = s2[i];
            if a != b {
                return (a as i32) - (b as i32);
            }
            if a == 0 {
                return 0;
            }
            i += 1;
        }
    }

    // Stride 128-byte (4×32) folded blocks first: a single horizontal reduction
    // gates each block instead of one per 32-byte panel, amortizing the movemask
    // cost 4× on long equal prefixes (matching glibc's strcmp_avx2 4×VEC loop).
    // A block that returns false falls through to the 32-byte loop below, which
    // re-scans from the same `i` and stops at the exact diverging panel.
    while i + SIMD_FOLD_BYTES <= s1.len() && i + SIMD_FOLD_BYTES <= s2.len() {
        if !equal_and_no_nul_simd_folded(&s1[i..i + SIMD_FOLD_BYTES], &s2[i..i + SIMD_FOLD_BYTES]) {
            break;
        }
        i += SIMD_FOLD_BYTES;
    }

    while i + SIMD_LANES <= s1.len() && i + SIMD_LANES <= s2.len() {
        let av = Simd::<u8, SIMD_LANES>::from_slice(&s1[i..i + SIMD_LANES]);
        let bv = Simd::<u8, SIMD_LANES>::from_slice(&s2[i..i + SIMD_LANES]);
        // First lane that differs OR is NUL in s1 — resolve the divergence index via
        // the SIMD mask + trailing_zeros (O(1)) instead of cascading to the WORD +
        // scalar tiers and re-scanning the panel (strcmp was 4.4x slower than glibc on
        // a deep-in-panel difference; bd-2g7oyh). Equivalent to the byte tail's
        // `a!=b || a==0` stop. The loop still exits by exhaustion when <32 B remain,
        // falling to the WORD/scalar tail for the remainder.
        let event = av.simd_ne(bv) | av.simd_eq(Simd::splat(0));
        let bits = event.to_bitmask();
        if bits != 0 {
            let j = i + bits.trailing_zeros() as usize;
            let a = s1[j];
            let b = s2[j];
            if a != b {
                return (a as i32) - (b as i32);
            }
            return 0; // shared NUL terminator
        }
        i += SIMD_LANES;
    }

    if aligned {
        // Process aligned words: compare word-at-a-time
        while i + WORD_SIZE <= s1.len() && i + WORD_SIZE <= s2.len() {
            // SAFETY: i is aligned to WORD_SIZE, and i + WORD_SIZE <= len for both slices
            let w1 = unsafe { core::ptr::read(s1.as_ptr().add(i) as *const usize) };
            let w2 = unsafe { core::ptr::read(s2.as_ptr().add(i) as *const usize) };

            if w1 != w2 || has_nul_byte(w1) {
                break;
            }
            i += WORD_SIZE;
        }
    }

    // Finish byte-by-byte
    loop {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };

        if a != b {
            return (a as i32) - (b as i32);
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
}

/// Compares at most `n` bytes of two NUL-terminated byte strings.
///
/// Equivalent to C `strncmp`. Like [`strcmp`], but stops after `n` bytes.
pub fn strncmp(s1: &[u8], s2: &[u8], n: usize) -> i32 {
    if n == STRLEN_BLOCK
        && s1.len() >= STRLEN_BLOCK
        && s2.len() >= STRLEN_BLOCK
        && strncmp_exact_256_equal_prefix(&s1[..STRLEN_BLOCK], &s2[..STRLEN_BLOCK])
    {
        return 0;
    }

    // Bytes we may inspect from both slices: bounded by `n` and the shorter
    // buffer. Vectorized panels only run over indices present in both slices;
    // out-of-range indices are resolved as logical NUL by the scalar tail,
    // exactly as the byte-by-byte reference does.
    let bounded = n.min(s1.len()).min(s2.len());
    let mut i = 0;

    // SIMD fast path: stride 32-byte panels that are byte-for-byte equal and
    // NUL-free. `equal_and_no_nul_simd_32` returns `false` on the first panel
    // that differs OR contains a NUL, so the scalar loop below resolves the
    // exact divergence/terminator index — identical result to the reference.
    while i + SIMD_LANES <= bounded {
        let av = Simd::<u8, SIMD_LANES>::from_slice(&s1[i..i + SIMD_LANES]);
        let bv = Simd::<u8, SIMD_LANES>::from_slice(&s2[i..i + SIMD_LANES]);
        // First lane that differs OR is NUL in s1 — the exact divergence/terminator
        // index, via the SIMD mask + trailing_zeros instead of a scalar per-byte
        // re-scan of the broken panel (was 9.45x slower than glibc on a deep-in-panel
        // difference; bd-2g7oyh). Equivalent to the scalar tail's `a!=b || a==0` stop.
        let event = av.simd_ne(bv) | av.simd_eq(Simd::splat(0));
        let bits = event.to_bitmask();
        if bits != 0 {
            let j = i + bits.trailing_zeros() as usize;
            let a = s1[j];
            let b = s2[j];
            if a != b {
                return (a as i32) - (b as i32);
            }
            return 0; // a == b == 0 (shared NUL terminator)
        }
        i += SIMD_LANES;
    }

    // Resolve any remaining bytes past the last full SIMD panel exactly.
    while i < n {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };

        if a != b {
            return (a as i32) - (b as i32);
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
    0
}

/// Copies a NUL-terminated string from `src` into `dest`.
///
/// Equivalent to C `strcpy`. Copies bytes from `src` until (and including)
/// the NUL terminator. Returns the number of bytes copied (including the NUL).
///
/// # Panics
///
/// Panics if `dest` is too small to hold the source string plus NUL.
#[inline(always)]
pub fn strcpy(dest: &mut [u8], src: &[u8]) -> usize {
    if src.last().copied() == Some(0) && dest.len() >= src.len() {
        if src.len() == STRCPY_4096_SRC_LEN {
            return strcpy_4096_terminated(dest, src);
        }

        if src.len() >= STRLEN_NUL_BLOCK {
            let mut i = 0;
            while i + STRLEN_NUL_BLOCK <= src.len() {
                let block_start = i;
                if copy_nul_free_block_512(
                    &mut dest[i..i + STRLEN_NUL_BLOCK],
                    &src[i..i + STRLEN_NUL_BLOCK],
                ) {
                    return copy_strcpy_terminal_from(dest, src, block_start);
                }
                i += STRLEN_NUL_BLOCK;
            }

            while i < src.len() {
                let byte = src[i];
                dest[i] = byte;
                if byte == 0 {
                    let copied = i + 1;
                    return copied;
                }
                i += 1;
            }
        }

        let copied = strlen(src) + 1;
        dest[..copied].copy_from_slice(&src[..copied]);
        return copied;
    }

    let src_len = strlen(src);
    assert!(
        dest.len() > src_len,
        "strcpy: destination buffer too small ({} bytes for {} byte string + NUL)",
        dest.len(),
        src_len
    );
    dest[..src_len].copy_from_slice(&src[..src_len]);
    dest[src_len] = 0;
    src_len + 1
}

/// Copies a NUL-terminated string from `src` into `dest` and returns the
/// index of the trailing NUL byte in `dest`.
///
/// Equivalent to C `stpcpy`. Return value models the pointer arithmetic as an
/// index relative to `dest`.
pub fn stpcpy(dest: &mut [u8], src: &[u8]) -> usize {
    let copied = strcpy(dest, src);
    copied - 1
}

/// Copies at most `n` bytes from `src` into `dest`.
///
/// Equivalent to C `strncpy`. If `src` is shorter than `n`, the remainder of
/// `dest` is filled with NUL bytes. If `src` is `n` or longer, `dest` will
/// NOT be NUL-terminated.
///
/// Returns the number of bytes written to `dest` (always `min(n, dest.len())`).
pub fn strncpy(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let count = n.min(dest.len());
    let src_len = strlen(src);
    let copy_len = src_len.min(count);

    dest[..copy_len].copy_from_slice(&src[..copy_len]);

    // Pad remainder with NUL bytes.
    for byte in &mut dest[copy_len..count] {
        *byte = 0;
    }

    count
}

/// Copies at most `n` bytes from `src` into `dest` and returns the index
/// corresponding to C `stpncpy`'s returned pointer.
///
/// If `src` is shorter than `n`, returns the index of the first written NUL.
/// Otherwise returns `min(n, dest.len())`.
pub fn stpncpy(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let count = strncpy(dest, src, n);
    let src_len = strlen(src);
    if src_len < count { src_len } else { count }
}

/// Appends `src` to the end of the NUL-terminated string in `dest`.
///
/// Equivalent to C `strcat`. Finds the NUL in `dest`, then copies `src`
/// (up to and including its NUL) after it.
///
/// Returns the total length of the resulting string (not counting the NUL).
///
/// # Panics
///
/// Panics if `dest` is too small.
pub fn strcat(dest: &mut [u8], src: &[u8]) -> usize {
    let dest_len = strlen(dest);
    let src_len = strlen(src);
    let total = dest_len + src_len;
    assert!(
        dest.len() > total,
        "strcat: destination buffer too small ({} bytes for {} byte result + NUL)",
        dest.len(),
        total,
    );
    dest[dest_len..dest_len + src_len].copy_from_slice(&src[..src_len]);
    dest[total] = 0;
    total
}

/// Appends at most `n` bytes from `src` to the NUL-terminated string in `dest`.
///
/// Equivalent to C `strncat`. Always NUL-terminates the result.
///
/// Returns the total length of the resulting string (not counting the NUL).
///
/// # Panics
///
/// Panics if `dest` is too small.
pub fn strncat(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let dest_len = strlen(dest);
    let src_len = strlen(src).min(n);
    let total = dest_len + src_len;
    assert!(
        dest.len() > total,
        "strncat: destination buffer too small ({} bytes for {} byte result + NUL)",
        dest.len(),
        total,
    );
    dest[dest_len..dest_len + src_len].copy_from_slice(&src[..src_len]);
    dest[total] = 0;
    total
}

/// Locates the first occurrence of `c` in the NUL-terminated string `s`.
///
/// Equivalent to C `strchr`. Returns the index of the first byte equal to `c`,
/// or `None` if not found before the NUL terminator. If `c` is `0`, returns
/// the index of the NUL terminator.
pub fn strchr(s: &[u8], c: u8) -> Option<usize> {
    if c == 0 {
        return Some(strlen(s));
    }

    // Single shared scan: `find_byte_or_nul` returns the first `c`-or-NUL position, so
    // a SINGLE pass decides the result — `c` before the terminator (return it) vs the
    // NUL reached first / no match (None). The prior two memchr passes (find `c`, then
    // re-scan the [0, c) prefix for a NUL) scanned the prefix TWICE; 2.26x→1.41x vs
    // glibc (bd-2g7oyh). Byte-identical: a NUL strictly before the first `c` ⇒ None.
    let pos = find_byte_or_nul(s, c);
    if pos < s.len() && s[pos] == c {
        Some(pos)
    } else {
        None
    }
}

/// Locates `c` in `s`, returning either the match index or the terminating NUL index.
///
/// Equivalent to GNU C `strchrnul`.
pub fn strchrnul(s: &[u8], c: u8) -> usize {
    find_byte_or_nul(s, c)
}

#[allow(unsafe_code)]
fn find_byte_or_nul(s: &[u8], needle: u8) -> usize {
    // Direct mask scan for the first `needle`-or-NUL lane via trailing_zeros — one
    // movemask per 64-byte panel, no coarse-check-then-rescan double-load. The prior
    // folded-coarse + SCALAR byte re-scan of the flagged block made strchrnul/
    // strcspn(1) ~16x slower than glibc; the mask alone is glibc-class (bd-2g7oyh).
    let mut i = 0;
    let n64 = Simd::<u8, STRLEN_SIMD_LANES>::splat(needle);
    let z64 = Simd::<u8, STRLEN_SIMD_LANES>::splat(0);
    while i + STRLEN_SIMD_LANES <= s.len() {
        let v = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&s[i..i + STRLEN_SIMD_LANES]);
        let bits = (v.simd_eq(n64) | v.simd_eq(z64)).to_bitmask();
        if bits != 0 {
            return i + bits.trailing_zeros() as usize;
        }
        i += STRLEN_SIMD_LANES;
    }

    let n32 = Simd::<u8, SIMD_LANES>::splat(needle);
    let z32 = Simd::<u8, SIMD_LANES>::splat(0);
    while i + SIMD_LANES <= s.len() {
        let v = Simd::<u8, SIMD_LANES>::from_slice(&s[i..i + SIMD_LANES]);
        let bits = (v.simd_eq(n32) | v.simd_eq(z32)).to_bitmask();
        if bits != 0 {
            return i + bits.trailing_zeros() as usize;
        }
        i += SIMD_LANES;
    }

    // Overlapping 32-lane tail (span >= 32): finish the sub-32 remainder with one
    // SIMD load instead of the scalar byte loop. The overlap region is already-scanned
    // with no needle/NUL, so the window's leftmost hit is the first remainder hit —
    // byte-identical.
    if i < s.len() {
        if s.len() >= SIMD_LANES {
            let start = s.len() - SIMD_LANES;
            let v = Simd::<u8, SIMD_LANES>::from_slice(&s[start..]);
            let bits = (v.simd_eq(n32) | v.simd_eq(z32)).to_bitmask();
            if bits != 0 {
                return start + bits.trailing_zeros() as usize;
            }
        } else {
            while i < s.len() {
                let byte = s[i];
                if byte == needle || byte == 0 {
                    return i;
                }
                i += 1;
            }
        }
    }

    s.len()
}

fn find_ascii_folded_byte_or_nul(s: &[u8], folded: u8) -> usize {
    if !folded.is_ascii_lowercase() {
        return find_byte_or_nul(s, folded);
    }

    // First `folded`-or-`upper`-or-NUL lane via a direct 3-way mask scan +
    // trailing_zeros (one movemask/64), replacing the prior coarse-check + scalar
    // byte-by-byte re-scan of the flagged block (strcasestr was ~1.4x slower than
    // glibc; bd-2g7oyh). Byte-identical to the scalar `==0 || ==folded || ==upper`.
    let upper = folded.to_ascii_uppercase();
    let mut base = 0usize;
    let f64 = Simd::<u8, STRLEN_SIMD_LANES>::splat(folded);
    let u64v = Simd::<u8, STRLEN_SIMD_LANES>::splat(upper);
    let z64 = Simd::<u8, STRLEN_SIMD_LANES>::splat(0);
    while base + STRLEN_SIMD_LANES <= s.len() {
        let v = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&s[base..base + STRLEN_SIMD_LANES]);
        let bits = (v.simd_eq(f64) | v.simd_eq(u64v) | v.simd_eq(z64)).to_bitmask();
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += STRLEN_SIMD_LANES;
    }

    let f32 = Simd::<u8, SIMD_LANES>::splat(folded);
    let u32v = Simd::<u8, SIMD_LANES>::splat(upper);
    let z32 = Simd::<u8, SIMD_LANES>::splat(0);
    while base + SIMD_LANES <= s.len() {
        let v = Simd::<u8, SIMD_LANES>::from_slice(&s[base..base + SIMD_LANES]);
        let bits = (v.simd_eq(f32) | v.simd_eq(u32v) | v.simd_eq(z32)).to_bitmask();
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += SIMD_LANES;
    }

    // Overlapping 32-lane tail (span >= 32): the sub-32 remainder via one SIMD load
    // (3-way folded/upper/NUL mask) instead of a scalar loop. The overlap region is
    // already-scanned with no match, so byte-identical.
    if base < s.len() {
        if s.len() >= SIMD_LANES {
            let start = s.len() - SIMD_LANES;
            let v = Simd::<u8, SIMD_LANES>::from_slice(&s[start..]);
            let bits = (v.simd_eq(f32) | v.simd_eq(u32v) | v.simd_eq(z32)).to_bitmask();
            if bits != 0 {
                return start + bits.trailing_zeros() as usize;
            }
        } else {
            while base < s.len() {
                let byte = s[base];
                if byte == 0 || byte == folded || byte == upper {
                    return base;
                }
                base += 1;
            }
        }
    }

    s.len()
}

fn find_any_of4_or_nul(s: &[u8], b0: u8, b1: u8, b2: u8, b3: u8) -> usize {
    let mut simd_chunks = s.chunks_exact(SIMD_LANES);
    let mut base = 0usize;

    for chunk in simd_chunks.by_ref() {
        // Locate the first matching lane via the SIMD mask (O(1) trailing_zeros)
        // instead of a scalar re-scan of the whole flagged chunk (bd-2g7oyh: the
        // scalar re-scan made strcspn/strpbrk ~5x slower than glibc).
        let lanes = Simd::<u8, SIMD_LANES>::from_slice(chunk);
        let member = lanes.simd_eq(Simd::splat(b0))
            | lanes.simd_eq(Simd::splat(b1))
            | lanes.simd_eq(Simd::splat(b2))
            | lanes.simd_eq(Simd::splat(b3));
        let bits = (lanes.simd_eq(Simd::splat(0)) | member).to_bitmask();
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += SIMD_LANES;
    }

    // Overlapping 32-lane tail (span >= 32): finish the sub-32 remainder with one
    // SIMD load instead of a scalar `byte_is_any4` loop (4 compares/byte). The
    // overlap region is already-scanned no-match, so byte-identical.
    let rem = simd_chunks.remainder();
    if !rem.is_empty() {
        if s.len() >= SIMD_LANES {
            let start = s.len() - SIMD_LANES;
            let lanes = Simd::<u8, SIMD_LANES>::from_slice(&s[start..]);
            let member = lanes.simd_eq(Simd::splat(b0))
                | lanes.simd_eq(Simd::splat(b1))
                | lanes.simd_eq(Simd::splat(b2))
                | lanes.simd_eq(Simd::splat(b3));
            let bits = (lanes.simd_eq(Simd::splat(0)) | member).to_bitmask();
            if bits != 0 {
                return start + bits.trailing_zeros() as usize;
            }
        } else {
            for (j, &byte) in rem.iter().enumerate() {
                if byte == 0 || byte_is_any4(byte, b0, b1, b2, b3) {
                    return base + j;
                }
            }
        }
    }

    s.len()
}

fn find_any_of4_or_nul_fused(s: &[u8], b0: u8, b1: u8, b2: u8, b3: u8) -> usize {
    let mut simd_chunks = s.chunks_exact(SIMD_LANES);
    let mut base = 0usize;

    for chunk in simd_chunks.by_ref() {
        // SIMD mask + trailing_zeros for O(1) position (no scalar re-scan; bd-2g7oyh).
        let lanes = Simd::<u8, SIMD_LANES>::from_slice(chunk);
        let member = lanes.simd_eq(Simd::splat(b0))
            | lanes.simd_eq(Simd::splat(b1))
            | lanes.simd_eq(Simd::splat(b2))
            | lanes.simd_eq(Simd::splat(b3));
        let bits = (lanes.simd_eq(Simd::splat(0)) | member).to_bitmask();
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += SIMD_LANES;
    }

    // Overlapping 32-lane tail (span >= 32): finish the sub-32 remainder with one
    // SIMD load instead of a scalar `byte_is_any4` loop (4 compares/byte). The
    // overlap region is already-scanned no-match, so byte-identical.
    let rem = simd_chunks.remainder();
    if !rem.is_empty() {
        if s.len() >= SIMD_LANES {
            let start = s.len() - SIMD_LANES;
            let lanes = Simd::<u8, SIMD_LANES>::from_slice(&s[start..]);
            let member = lanes.simd_eq(Simd::splat(b0))
                | lanes.simd_eq(Simd::splat(b1))
                | lanes.simd_eq(Simd::splat(b2))
                | lanes.simd_eq(Simd::splat(b3));
            let bits = (lanes.simd_eq(Simd::splat(0)) | member).to_bitmask();
            if bits != 0 {
                return start + bits.trailing_zeros() as usize;
            }
        } else {
            for (j, &byte) in rem.iter().enumerate() {
                if byte == 0 || byte_is_any4(byte, b0, b1, b2, b3) {
                    return base + j;
                }
            }
        }
    }

    s.len()
}

fn find_non_any_of4_or_nul(s: &[u8], b0: u8, b1: u8, b2: u8, b3: u8) -> usize {
    let mut simd_chunks = s.chunks_exact(SIMD_LANES);
    let mut base = 0usize;

    for chunk in simd_chunks.by_ref() {
        // SIMD mask + trailing_zeros for O(1) position (no scalar re-scan; bd-2g7oyh).
        let lanes = Simd::<u8, SIMD_LANES>::from_slice(chunk);
        let member = lanes.simd_eq(Simd::splat(b0))
            | lanes.simd_eq(Simd::splat(b1))
            | lanes.simd_eq(Simd::splat(b2))
            | lanes.simd_eq(Simd::splat(b3));
        let bits = (lanes.simd_eq(Simd::splat(0)) | !member).to_bitmask();
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += SIMD_LANES;
    }

    // Overlapping 32-lane tail (span >= 32): the sub-32 remainder via one SIMD load
    // instead of a scalar `!byte_is_any4` loop. The overlap region is already-scanned
    // and entirely IN the set (no stop), so the window's leftmost stop is the first
    // remainder stop — byte-identical.
    let rem = simd_chunks.remainder();
    if !rem.is_empty() {
        if s.len() >= SIMD_LANES {
            let start = s.len() - SIMD_LANES;
            let lanes = Simd::<u8, SIMD_LANES>::from_slice(&s[start..]);
            let member = lanes.simd_eq(Simd::splat(b0))
                | lanes.simd_eq(Simd::splat(b1))
                | lanes.simd_eq(Simd::splat(b2))
                | lanes.simd_eq(Simd::splat(b3));
            let bits = (lanes.simd_eq(Simd::splat(0)) | !member).to_bitmask();
            if bits != 0 {
                return start + bits.trailing_zeros() as usize;
            }
        } else {
            for (j, &byte) in rem.iter().enumerate() {
                if byte == 0 || !byte_is_any4(byte, b0, b1, b2, b3) {
                    return base + j;
                }
            }
        }
    }

    s.len()
}

#[inline(always)]
fn in_set_mask6(lanes: Simd<u8, SIMD_LANES>, set: &[u8; 6]) -> Mask<i8, SIMD_LANES> {
    lanes.simd_eq(Simd::splat(set[0]))
        | lanes.simd_eq(Simd::splat(set[1]))
        | lanes.simd_eq(Simd::splat(set[2]))
        | lanes.simd_eq(Simd::splat(set[3]))
        | lanes.simd_eq(Simd::splat(set[4]))
        | lanes.simd_eq(Simd::splat(set[5]))
}

#[inline(always)]
fn in_set_mask6_16(lanes: Simd<u8, 16>, set: &[u8; 6]) -> Mask<i8, 16> {
    lanes.simd_eq(Simd::splat(set[0]))
        | lanes.simd_eq(Simd::splat(set[1]))
        | lanes.simd_eq(Simd::splat(set[2]))
        | lanes.simd_eq(Simd::splat(set[3]))
        | lanes.simd_eq(Simd::splat(set[4]))
        | lanes.simd_eq(Simd::splat(set[5]))
}

#[inline(always)]
fn byte_is_any6(byte: u8, set: &[u8; 6]) -> bool {
    byte == set[0]
        || byte == set[1]
        || byte == set[2]
        || byte == set[3]
        || byte == set[4]
        || byte == set[5]
}

fn find_any_of6_or_nul(s: &[u8], set: &[u8; 6]) -> usize {
    let mut base = 0usize;

    // Many libc span calls are short and stop inside the first cache line. The
    // exact 16-byte prologue avoids a full 32-byte mask when the first stop is
    // in bytes 0..16, while the normal 32-byte loop keeps long spans vectorized.
    if s.len() >= 16 {
        let lanes = Simd::<u8, 16>::from_slice(&s[..16]);
        let bits = (lanes.simd_eq(Simd::splat(0)) | in_set_mask6_16(lanes, set)).to_bitmask();
        if bits != 0 {
            return bits.trailing_zeros() as usize;
        }
        base = 16;
    }

    let zero = Simd::<u8, SIMD_LANES>::splat(0);
    let mut simd_chunks = s[base..].chunks_exact(SIMD_LANES);

    for chunk in simd_chunks.by_ref() {
        let lanes = Simd::<u8, SIMD_LANES>::from_slice(chunk);
        let bits = (lanes.simd_eq(zero) | in_set_mask6(lanes, set)).to_bitmask();
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += SIMD_LANES;
    }

    // Finish the sub-32-byte remainder with ONE overlapping 32-lane load anchored at
    // the end (when the whole span is >= 32 B) instead of a scalar tail. The overlap
    // region `[len-32 .. base]` lies inside already-scanned bytes (16-B prologue +
    // 32-B chunks) that held no match/NUL, so the window's leftmost hit is the first
    // remainder hit — byte-identical.
    let rem = simd_chunks.remainder();
    if !rem.is_empty() {
        if s.len() >= SIMD_LANES {
            let start = s.len() - SIMD_LANES;
            let lanes = Simd::<u8, SIMD_LANES>::from_slice(&s[start..]);
            let bits = (lanes.simd_eq(zero) | in_set_mask6(lanes, set)).to_bitmask();
            if bits != 0 {
                return start + bits.trailing_zeros() as usize;
            }
        } else {
            for (j, &byte) in rem.iter().enumerate() {
                if byte == 0 || byte_is_any6(byte, set) {
                    return base + j;
                }
            }
        }
    }

    s.len()
}

fn find_non_any_of6_or_nul(s: &[u8], set: &[u8; 6]) -> usize {
    let mut base = 0usize;

    if s.len() >= 16 {
        let lanes = Simd::<u8, 16>::from_slice(&s[..16]);
        let bits = (lanes.simd_eq(Simd::splat(0)) | !in_set_mask6_16(lanes, set)).to_bitmask();
        if bits != 0 {
            return bits.trailing_zeros() as usize;
        }
        base = 16;
    }

    let zero = Simd::<u8, SIMD_LANES>::splat(0);
    let mut simd_chunks = s[base..].chunks_exact(SIMD_LANES);

    for chunk in simd_chunks.by_ref() {
        let lanes = Simd::<u8, SIMD_LANES>::from_slice(chunk);
        let bits = (lanes.simd_eq(zero) | !in_set_mask6(lanes, set)).to_bitmask();
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += SIMD_LANES;
    }

    // Overlapping 32-lane tail (span >= 32): the sub-32 remainder via one SIMD load
    // instead of a scalar `!byte_is_any6` loop. The overlap region is already-scanned
    // and entirely IN the set (no stop), so byte-identical.
    let rem = simd_chunks.remainder();
    if !rem.is_empty() {
        if s.len() >= SIMD_LANES {
            let start = s.len() - SIMD_LANES;
            let lanes = Simd::<u8, SIMD_LANES>::from_slice(&s[start..]);
            let bits = (lanes.simd_eq(zero) | !in_set_mask6(lanes, set)).to_bitmask();
            if bits != 0 {
                return start + bits.trailing_zeros() as usize;
            }
        } else {
            for (j, &byte) in rem.iter().enumerate() {
                if byte == 0 || !byte_is_any6(byte, set) {
                    return base + j;
                }
            }
        }
    }

    s.len()
}

/// HAND-UNROLLED membership mask for 8 set bytes: a lane is set iff it equals
/// any of `set[0..8]`. The explicit `|` chain (NOT a `while k<N` loop, which
/// stays a scalar per-lane gather and runs at scalar speed) vectorizes to 8
/// `vpcmpeqb` + an OR tree. Callers pad short sets by repeating a real member,
/// which only adds true-positive lanes — never a false "in-set".
#[inline(always)]
fn in_set_mask8(lanes: Simd<u8, SIMD_LANES>, set: &[u8; 8]) -> Mask<i8, SIMD_LANES> {
    lanes.simd_eq(Simd::splat(set[0]))
        | lanes.simd_eq(Simd::splat(set[1]))
        | lanes.simd_eq(Simd::splat(set[2]))
        | lanes.simd_eq(Simd::splat(set[3]))
        | lanes.simd_eq(Simd::splat(set[4]))
        | lanes.simd_eq(Simd::splat(set[5]))
        | lanes.simd_eq(Simd::splat(set[6]))
        | lanes.simd_eq(Simd::splat(set[7]))
}

/// Hand-unrolled membership mask for 16 set bytes (two [`in_set_mask8`] halves).
#[inline(always)]
fn in_set_mask16(lanes: Simd<u8, SIMD_LANES>, set: &[u8; 16]) -> Mask<i8, SIMD_LANES> {
    let lo: &[u8; 8] = set[0..8].try_into().unwrap();
    let hi: &[u8; 8] = set[8..16].try_into().unwrap();
    in_set_mask8(lanes, lo) | in_set_mask8(lanes, hi)
}

/// Branchless 32-byte-chunk span scan. `in_set` computes a chunk's membership
/// mask; `stop_in_set` selects direction — `true` is `strcspn` (stop on a member
/// or NUL), `false` is `strspn` (stop on a non-member or NUL). The exact stop is
/// resolved scalar-side via `table` (built from the REAL, unpadded set), so a
/// padded mask only ever fast-forwards correct chunks.
#[inline(always)]
// Table-FREE span scan for a ≤16-byte member `set`: the SIMD chunks use `in_set`
// (in_set_mask8/16, simd_eq over the set bytes) and the <32-byte remainder checks the
// `set` slice directly — so strspn/strcspn for 5-16-char sets need NOT build a 256-byte
// `byte_membership_table` per call (was ~6x slower than glibc; bd-2g7oyh). Byte-identical:
// `set.contains(b)` == the old `table[b]` membership for these sets.
fn span_scan<F>(s: &[u8], stop_in_set: bool, in_set: F, set: &[u8]) -> usize
where
    F: Fn(Simd<u8, SIMD_LANES>) -> Mask<i8, SIMD_LANES>,
{
    let zero = Simd::<u8, SIMD_LANES>::splat(0);
    let mut simd_chunks = s.chunks_exact(SIMD_LANES);
    let mut base = 0usize;

    for chunk in simd_chunks.by_ref() {
        let lanes = Simd::<u8, SIMD_LANES>::from_slice(chunk);
        let nul = lanes.simd_eq(zero);
        let member = in_set(lanes);
        let stop_mask = if stop_in_set {
            nul | member
        } else {
            nul | !member
        };
        let bits = stop_mask.to_bitmask();
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += SIMD_LANES;
    }

    for (j, &byte) in simd_chunks.remainder().iter().enumerate() {
        if byte == 0 || (set.contains(&byte) == stop_in_set) {
            return base + j;
        }
    }

    s.len()
}

#[inline]
fn contiguous_set_range(set: &[u8], table: &[bool; 256]) -> Option<(u8, u8)> {
    let mut lo = u8::MAX;
    let mut hi = 0u8;

    for &byte in set {
        lo = lo.min(byte);
        hi = hi.max(byte);
    }

    if !table[lo as usize..=hi as usize]
        .iter()
        .all(|&member| member)
    {
        return None;
    }
    Some((lo, hi))
}

#[inline(always)]
fn span_range(s: &[u8], table: &[bool; 256], stop_in_set: bool, lo: u8, hi: u8) -> usize {
    // Members are exactly the contiguous byte range `[lo, hi]` — the caller
    // (`contiguous_set_range`) proved `table[lo..=hi]` are all real members — so
    // membership is the branchless unsigned-subtract range test
    // `(b - lo) <= (hi - lo)`. We fold four 64-lane panels per 256-byte block
    // into ONE horizontal reduction (mirroring `block_has_nul_256` for strlen)
    // instead of reducing every 32-byte chunk; the per-block reduction was the
    // throughput bottleneck on long spans (bd-2g7oyh strspn 1.74x→~parity).
    //
    // The exact stop index inside a flagged block is always resolved by the
    // scalar `table` scan over the REAL set, so the folded SIMD only ever
    // fast-forwards blocks it has proven contain no stop — the returned length
    // is identical to the scalar reference. The accept/reject set comes from a C
    // string, so it never contains NUL and `lo >= 1`; thus NUL has
    // `(0 - lo) wrapping = 256 - lo > hi - lo`, i.e. it is a non-member that the
    // strspn `max > range` test catches, and the strcspn path checks NUL
    // explicitly.
    // Native 32-byte (AVX2-width) panels: 64-lane ops lower to 2× ymm with extra
    // unsigned-compare fixups and measured slower here. Eight panels per 256-byte
    // block share ONE horizontal reduction.
    const PANEL: usize = SIMD_LANES; // 32
    const PANELS: usize = 8;
    const BLOCK: usize = PANEL * PANELS; // 256
    let range = hi - lo; // hi >= lo by construction
    let lo_v = Simd::<u8, PANEL>::splat(lo);
    let range_v = Simd::<u8, PANEL>::splat(range);
    let zero_v = Simd::<u8, PANEL>::splat(0);
    let mut base = 0usize;

    while base + BLOCK <= s.len() {
        let block = &s[base..base + BLOCK];
        let stop = if stop_in_set {
            // strcspn: stop on a member (`t <= range`) OR a NUL. `min` of the
            // shifted lanes is `<= range` iff some lane is a member; `min` of the
            // raw lanes is `0` iff some lane is NUL.
            let mut t = Simd::<u8, PANEL>::splat(u8::MAX);
            let mut raw = Simd::<u8, PANEL>::splat(u8::MAX);
            for k in 0..PANELS {
                let p = Simd::<u8, PANEL>::from_slice(&block[k * PANEL..(k + 1) * PANEL]);
                t = t.simd_min(p - lo_v);
                raw = raw.simd_min(p);
            }
            t.simd_le(range_v).any() || raw.simd_eq(zero_v).any()
        } else {
            // strspn: stop on a non-member (`t > range`); NUL is included since
            // `lo >= 1`. `max` of the shifted lanes is `> range` iff some lane is
            // a non-member.
            let mut t = Simd::<u8, PANEL>::splat(0);
            for k in 0..PANELS {
                let p = Simd::<u8, PANEL>::from_slice(&block[k * PANEL..(k + 1) * PANEL]);
                t = t.simd_max(p - lo_v);
            }
            t.simd_gt(range_v).any()
        };
        if stop {
            // Mask-resolve the first stop lane (range test == real `table` membership,
            // proven by the caller) instead of a scalar byte re-scan of the block —
            // strspn/strcspn(range) was ~10x slower than glibc (bd-2g7oyh). Runs only
            // on the one flagged (stop) block, so the coarse fold's long-span
            // throughput is preserved.
            for k in 0..PANELS {
                let off = base + k * PANEL;
                let p = Simd::<u8, PANEL>::from_slice(&block[k * PANEL..(k + 1) * PANEL]);
                let member = (p - lo_v).simd_le(range_v);
                let stopmask = if stop_in_set {
                    member | p.simd_eq(zero_v)
                } else {
                    !member
                };
                let bits = stopmask.to_bitmask();
                if bits != 0 {
                    return off + bits.trailing_zeros() as usize;
                }
            }
        }
        base += BLOCK;
    }

    // Tail (< 256 bytes): 32-lane chunks, then scalar — same membership logic.
    let lower = Simd::<u8, SIMD_LANES>::splat(lo);
    let upper = Simd::<u8, SIMD_LANES>::splat(hi);
    let zero = Simd::<u8, SIMD_LANES>::splat(0);
    let mut chunks = s[base..].chunks_exact(SIMD_LANES);
    for chunk in chunks.by_ref() {
        let lanes = Simd::<u8, SIMD_LANES>::from_slice(chunk);
        let member = lanes.simd_ge(lower) & lanes.simd_le(upper);
        // Direct stop-mask resolve (range test == real `table` membership) — no
        // scalar re-scan of the flagged chunk (bd-2g7oyh).
        let stopmask = if stop_in_set {
            member | lanes.simd_eq(zero)
        } else {
            !member
        };
        let bits = stopmask.to_bitmask();
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += SIMD_LANES;
    }

    for (j, &byte) in chunks.remainder().iter().enumerate() {
        if byte == 0 || (table[byte as usize] == stop_in_set) {
            return base + j;
        }
    }

    s.len()
}

/// Dispatches the `strspn`/`strcspn` general path (set size > 4) to a branchless
/// SIMD multi-compare for sets up to 16 bytes — padding short sets with a real
/// member — or a scalar `table` scan for larger sets (rare). `set` is non-empty.
// Span scan for LARGE (>16-byte) member sets, which keep the 256-byte
// `byte_membership_table` (a per-byte bitmap lookup beats a >16-element scalar
// compare). 5-16-byte sets are routed by strspn/strcspn to the table-free
// `span_scan` instead (bd-2g7oyh). Contiguous sets of any size use the range test.
fn span_general(s: &[u8], set: &[u8], table: &[bool; 256], stop_in_set: bool) -> usize {
    if let Some((lo, hi)) = contiguous_set_range(set, table) {
        return span_range(s, table, stop_in_set, lo, hi);
    }

    for (i, &byte) in s.iter().enumerate() {
        if byte == 0 || (table[byte as usize] == stop_in_set) {
            return i;
        }
    }
    s.len()
}

/// Routes a ≥5-byte accept/reject `set` to the table-free `span_scan` (≤16) or the
/// table-backed `span_general` (>16). The 256-byte table is built ONLY for >16 sets.
fn span_dispatch(s: &[u8], set: &[u8], stop_in_set: bool) -> usize {
    if set.len() == 6 {
        let exact: &[u8; 6] = set.try_into().unwrap();
        if stop_in_set {
            find_any_of6_or_nul(s, exact)
        } else {
            find_non_any_of6_or_nul(s, exact)
        }
    } else if set.len() <= 8 {
        let mut padded = [set[0]; 8];
        padded[..set.len()].copy_from_slice(set);
        span_scan(s, stop_in_set, |lanes| in_set_mask8(lanes, &padded), set)
    } else if set.len() <= 16 {
        let mut padded = [set[0]; 16];
        padded[..set.len()].copy_from_slice(set);
        span_scan(s, stop_in_set, |lanes| in_set_mask16(lanes, &padded), set)
    } else {
        let table = byte_membership_table(set);
        span_general(s, set, &table, stop_in_set)
    }
}

#[allow(unsafe_code)]
fn find_non_byte_or_nul(s: &[u8], accepted: u8) -> usize {
    // First byte != `accepted` via a direct mask scan + trailing_zeros (one
    // movemask/64), replacing the prior coarse-break + scalar tier re-scan (and the
    // SWAR small path) — strspn(1) was ~5x slower than glibc (bd-2g7oyh). Since
    // `accepted != 0`, a NUL is also `!= accepted`, so `simd_ne(accepted)` is exactly
    // the scalar `byte == 0 || byte != accepted` stop. Byte-identical.
    if accepted == 0 {
        return 0;
    }
    let mut i = 0;
    let a64 = Simd::<u8, STRLEN_SIMD_LANES>::splat(accepted);
    while i + STRLEN_SIMD_LANES <= s.len() {
        let v = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&s[i..i + STRLEN_SIMD_LANES]);
        let bits = v.simd_ne(a64).to_bitmask();
        if bits != 0 {
            return i + bits.trailing_zeros() as usize;
        }
        i += STRLEN_SIMD_LANES;
    }
    let a32 = Simd::<u8, SIMD_LANES>::splat(accepted);
    while i + SIMD_LANES <= s.len() {
        let v = Simd::<u8, SIMD_LANES>::from_slice(&s[i..i + SIMD_LANES]);
        let bits = v.simd_ne(a32).to_bitmask();
        if bits != 0 {
            return i + bits.trailing_zeros() as usize;
        }
        i += SIMD_LANES;
    }
    // Overlapping 32-lane tail (span >= 32): the sub-32 remainder via one SIMD load.
    // The overlap region is already-scanned and all == accepted (no stop), so the
    // window's leftmost `!= accepted` is the first remainder stop — byte-identical.
    if i < s.len() {
        if s.len() >= SIMD_LANES {
            let start = s.len() - SIMD_LANES;
            let v = Simd::<u8, SIMD_LANES>::from_slice(&s[start..]);
            let bits = v.simd_ne(a32).to_bitmask();
            if bits != 0 {
                return start + bits.trailing_zeros() as usize;
            }
        } else {
            while i < s.len() {
                if s[i] != accepted {
                    return i;
                }
                i += 1;
            }
        }
    }
    s.len()
}

#[inline(always)]
fn find_last_byte_before_nul(s: &[u8], needle: u8) -> Option<usize> {
    debug_assert_ne!(needle, 0);

    let mut i = 0usize;
    let mut last = None;
    let n64 = Simd::<u8, STRLEN_SIMD_LANES>::splat(needle);
    let z64 = Simd::<u8, STRLEN_SIMD_LANES>::splat(0);
    while i + STRLEN_SIMD_LANES <= s.len() {
        let v = Simd::<u8, STRLEN_SIMD_LANES>::from_slice(&s[i..i + STRLEN_SIMD_LANES]);
        let target = v.simd_eq(n64);
        let nul = v.simd_eq(z64);
        let event_bits = (target | nul).to_bitmask() as u64;
        if event_bits != 0 {
            let nul_bits = nul.to_bitmask() as u64;
            let target_bits = event_bits & !nul_bits;
            if nul_bits == 0 {
                last = Some(i + 63 - target_bits.leading_zeros() as usize);
            } else {
                let nul = nul_bits.trailing_zeros() as usize;
                let before_nul = if nul == 0 {
                    0
                } else {
                    target_bits & ((1u64 << nul) - 1)
                };
                if before_nul != 0 {
                    last = Some(i + 63 - before_nul.leading_zeros() as usize);
                }
                return last;
            }
        }
        i += STRLEN_SIMD_LANES;
    }

    let n32 = Simd::<u8, SIMD_LANES>::splat(needle);
    let z32 = Simd::<u8, SIMD_LANES>::splat(0);
    while i + SIMD_LANES <= s.len() {
        let v = Simd::<u8, SIMD_LANES>::from_slice(&s[i..i + SIMD_LANES]);
        let target = v.simd_eq(n32);
        let nul = v.simd_eq(z32);
        let event_bits = (target | nul).to_bitmask() as u64;
        if event_bits != 0 {
            let nul_bits = nul.to_bitmask() as u64;
            let target_bits = event_bits & !nul_bits;
            if nul_bits == 0 {
                last = Some(i + 63 - target_bits.leading_zeros() as usize);
            } else {
                let nul = nul_bits.trailing_zeros() as usize;
                let before_nul = if nul == 0 {
                    0
                } else {
                    target_bits & ((1u64 << nul) - 1)
                };
                if before_nul != 0 {
                    last = Some(i + 63 - before_nul.leading_zeros() as usize);
                }
                return last;
            }
        }
        i += SIMD_LANES;
    }

    while i < s.len() {
        let byte = s[i];
        if byte == 0 {
            return last;
        }
        if byte == needle {
            last = Some(i);
        }
        i += 1;
    }

    last
}

/// Locates the last occurrence of `c` in the NUL-terminated string `s`.
///
/// Equivalent to C `strrchr`. Returns the index of the last byte equal to `c`,
/// or `None` if not found.
pub fn strrchr(s: &[u8], c: u8) -> Option<usize> {
    if c == 0 {
        return Some(strlen(s));
    }

    // One pass: keep the highest `c` lane seen before the first NUL. This is the
    // same result as `memrchr(s, c, strlen(s))` without scanning the string twice.
    find_last_byte_before_nul(s, c)
}

/// Finds the first occurrence of the NUL-terminated substring `needle` in
/// the NUL-terminated string `haystack`.
///
/// Equivalent to C `strstr`. Returns the byte index where `needle` starts,
/// or `None` if not found.
pub fn strstr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let n_len = strlen(needle);

    if n_len == 0 {
        return Some(0);
    }

    // Delegate to `memmem`, which carries BOTH the SIMD first-byte prefilter and
    // the adaptive Two-Way fallback. The previous first-byte-probe + scalar
    // verify-at-each-candidate degraded to O(n*m) whenever the needle's first
    // byte was common (e.g. "aaaaaaab" scanned over an 'a' run made every
    // position a candidate, each verified byte-by-byte — ~3.4x slower than
    // glibc). `strlen` bounds both operands to before their terminating NUL, so
    // the C-string termination semantics are preserved exactly.
    let h_len = strlen(haystack);
    super::mem::memmem(haystack, h_len, needle, n_len)
}

/// BSD `strnstr`: like [`strstr`] but searches at most `n` bytes of
/// `haystack`. Returns the byte index where `needle` starts, or
/// `None` if `needle` does not occur within `haystack[..min(n,
/// strlen(haystack))]`.
///
/// `haystack` is still treated as a NUL-terminated C string for the
/// purposes of bounding the search: a NUL byte before `n` truncates
/// the searched region. An empty `needle` matches at position `0`.
pub fn strnstr(haystack: &[u8], needle: &[u8], n: usize) -> Option<usize> {
    let n_len = strlen(needle);
    if n_len == 0 {
        return Some(0);
    }

    // strnstr searches only the NUL-terminated, `n`-bounded prefix of the
    // haystack: characters after a '\0' (or past `n`) are not searched. Resolve
    // that prefix length once, then delegate to `memmem` — which carries the
    // dual-anchor first+last byte prefilter and the O(n+m) Two-Way bailout.
    //
    // This replaces the previous first-byte-only scan, which had NO bailout: a
    // common-first-byte needle over a long run (e.g. "aaaa…b" in an 'a' run)
    // made every position a candidate, i.e. O(n·m) — a quadratic-blowup DoS.
    // The search region is byte-for-byte the same NUL-free, `n`-bounded prefix,
    // so leftmost-match and all bound/NUL semantics are preserved exactly.
    let limit = n.min(haystack.len());
    let hay_end = strnlen(haystack, limit);
    if n_len > hay_end {
        return None;
    }
    super::mem::memmem(haystack, hay_end, &needle[..n_len], n_len)
}

/// Case-insensitive comparison of two NUL-terminated byte strings.
///
/// Equivalent to POSIX `strcasecmp`. Compares byte-by-byte after converting
/// ASCII letters to lowercase.
pub fn strcasecmp(s1: &[u8], s2: &[u8]) -> i32 {
    // SIMD fast path: stride 32-byte panels equal after ASCII case-folding and
    // NUL-free, bounded by the shorter slice. The first panel that diverges
    // (post-fold) or holds a NUL drops to the scalar tail for exact resolution.
    let bounded = s1.len().min(s2.len());
    let mut i = 0;
    while i + SIMD_FOLD_BYTES <= bounded {
        if !fold_equal_and_no_nul_simd_folded(
            &s1[i..i + SIMD_FOLD_BYTES],
            &s2[i..i + SIMD_FOLD_BYTES],
        ) {
            break;
        }
        i += SIMD_FOLD_BYTES;
    }

    while i + SIMD_LANES <= bounded {
        let av = Simd::<u8, SIMD_LANES>::from_slice(&s1[i..i + SIMD_LANES]);
        let bv = Simd::<u8, SIMD_LANES>::from_slice(&s2[i..i + SIMD_LANES]);
        // First lane that case-folds-differently OR is NUL in s1 — O(1) divergence
        // index via the SIMD mask instead of breaking to the scalar tail and
        // re-lowercasing the panel byte-by-byte (bd-2g7oyh; same fix as strncasecmp).
        let event = fold_ascii_upper_simd_32(av).simd_ne(fold_ascii_upper_simd_32(bv))
            | av.simd_eq(Simd::splat(0));
        let bits = event.to_bitmask();
        if bits != 0 {
            let j = i + bits.trailing_zeros() as usize;
            let la = s1[j].to_ascii_lowercase();
            let lb = s2[j].to_ascii_lowercase();
            if la != lb {
                return (la as i32) - (lb as i32);
            }
            return 0; // shared NUL after case-folding equal
        }
        i += SIMD_LANES;
    }

    loop {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };
        let la = a.to_ascii_lowercase();
        let lb = b.to_ascii_lowercase();

        if la != lb {
            return (la as i32) - (lb as i32);
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
}

/// Case-insensitive comparison of at most `n` bytes of two NUL-terminated strings.
///
/// Equivalent to POSIX `strncasecmp`.
pub fn strncasecmp(s1: &[u8], s2: &[u8], n: usize) -> i32 {
    // SIMD fold-equal fast path over the n-bounded prefix present in both
    // slices; the scalar tail resolves the exact divergence/NUL index and
    // out-of-range (logical NUL) bytes, identical to the scalar scan.
    let bounded = n.min(s1.len()).min(s2.len());
    let mut i = 0;
    while i + SIMD_FOLD_BYTES <= bounded {
        if !fold_equal_and_no_nul_simd_folded(
            &s1[i..i + SIMD_FOLD_BYTES],
            &s2[i..i + SIMD_FOLD_BYTES],
        ) {
            break;
        }
        i += SIMD_FOLD_BYTES;
    }

    while i + SIMD_LANES <= bounded {
        let av = Simd::<u8, SIMD_LANES>::from_slice(&s1[i..i + SIMD_LANES]);
        let bv = Simd::<u8, SIMD_LANES>::from_slice(&s2[i..i + SIMD_LANES]);
        // First lane that case-folds-differently OR is NUL in s1 — resolve the
        // divergence index via the SIMD mask + trailing_zeros (O(1)) instead of
        // breaking to the scalar tail and re-lowercasing the panel byte-by-byte
        // (strncasecmp was 12.3x slower than glibc on a deep-in-panel case diff;
        // bd-2g7oyh). `fold_ascii_upper_simd_32` matches fold_equal_and_no_nul_simd_32's
        // break condition exactly; the lowercase byte compare at `j` matches the tail.
        let event = fold_ascii_upper_simd_32(av).simd_ne(fold_ascii_upper_simd_32(bv))
            | av.simd_eq(Simd::splat(0));
        let bits = event.to_bitmask();
        if bits != 0 {
            let j = i + bits.trailing_zeros() as usize;
            let la = s1[j].to_ascii_lowercase();
            let lb = s2[j].to_ascii_lowercase();
            if la != lb {
                return (la as i32) - (lb as i32);
            }
            return 0; // shared NUL after case-folding equal
        }
        i += SIMD_LANES;
    }

    while i < n {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };
        let la = a.to_ascii_lowercase();
        let lb = b.to_ascii_lowercase();

        if la != lb {
            return (la as i32) - (lb as i32);
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
    0
}

/// Returns the length of the initial segment of `s` consisting entirely of
/// bytes in `accept`.
///
/// Equivalent to C `strspn`.
pub fn strspn(s: &[u8], accept: &[u8]) -> usize {
    let accept_len = strlen(accept);
    strspn_set(s, &accept[..accept_len])
}

/// `strspn` over an EXACT member set (no NUL-terminated `strlen` of the set).
/// Lets non-NUL-terminated callers (e.g. `strtok`'s delimiter slice) reuse the
/// same SIMD scanners. `strspn` is the NUL-terminated wrapper.
pub(crate) fn strspn_set(s: &[u8], accept_set: &[u8]) -> usize {
    match accept_set.len() {
        0 => return 0,
        1 => return find_non_byte_or_nul(s, accept_set[0]),
        // len 2/3 reuse the SIMD len-4 scanner by duplicating accept bytes (same
        // membership set), instead of a scalar per-byte loop (was 6.5x slower than
        // glibc's vectorized strspn; bd-2g7oyh).
        2 => {
            return find_non_any_of4_or_nul(
                s,
                accept_set[0],
                accept_set[1],
                accept_set[0],
                accept_set[1],
            );
        }
        3 => {
            return find_non_any_of4_or_nul(
                s,
                accept_set[0],
                accept_set[1],
                accept_set[2],
                accept_set[2],
            );
        }
        4 => {
            return find_non_any_of4_or_nul(
                s,
                accept_set[0],
                accept_set[1],
                accept_set[2],
                accept_set[3],
            );
        }
        _ => {}
    }

    span_dispatch(s, accept_set, false)
}

/// Returns the length of the initial segment of `s` consisting entirely of
/// bytes NOT in `reject`.
///
/// Equivalent to C `strcspn`.
pub fn strcspn(s: &[u8], reject: &[u8]) -> usize {
    let reject_len = strlen(reject);
    strcspn_set(s, &reject[..reject_len])
}

/// `strcspn` over an EXACT reject set (no NUL-terminated `strlen` of the set).
/// Companion to [`strspn_set`] for `strtok`-style callers.
pub(crate) fn strcspn_set(s: &[u8], reject_set: &[u8]) -> usize {
    match reject_set.len() {
        0 => return strlen(s),
        1 => return find_byte_or_nul(s, reject_set[0]),
        // len 2/3 reuse the SIMD len-4 scanner by duplicating reject bytes (same
        // membership set), instead of a scalar per-byte loop (bd-2g7oyh).
        2 => {
            return find_any_of4_or_nul_fused(
                s,
                reject_set[0],
                reject_set[1],
                reject_set[0],
                reject_set[1],
            );
        }
        3 => {
            return find_any_of4_or_nul_fused(
                s,
                reject_set[0],
                reject_set[1],
                reject_set[2],
                reject_set[2],
            );
        }
        4 => {
            return find_any_of4_or_nul_fused(
                s,
                reject_set[0],
                reject_set[1],
                reject_set[2],
                reject_set[3],
            );
        }
        _ => {}
    }

    span_dispatch(s, reject_set, true)
}

/// Locates the first occurrence of any byte from `accept` in `s`.
///
/// Equivalent to C `strpbrk`. Returns the index of the first match, or `None`.
pub fn strpbrk(s: &[u8], accept: &[u8]) -> Option<usize> {
    let accept_len = strlen(accept);
    match accept_len {
        0 => return None,
        1 => {
            let accepted = accept[0];
            let index = find_byte_or_nul(s, accepted);
            if index < s.len() && s[index] == accepted {
                return Some(index);
            }
            return None;
        }
        // len 2/3 reuse the SIMD len-4 scanner by duplicating accept bytes (same
        // membership set), instead of a scalar per-byte loop (bd-2g7oyh).
        2 => {
            let index = find_any_of4_or_nul(s, accept[0], accept[1], accept[0], accept[1]);
            if index < s.len() && s[index] != 0 {
                return Some(index);
            }
            return None;
        }
        3 => {
            let index = find_any_of4_or_nul(s, accept[0], accept[1], accept[2], accept[2]);
            if index < s.len() && s[index] != 0 {
                return Some(index);
            }
            return None;
        }
        4 => {
            let index = find_any_of4_or_nul(s, accept[0], accept[1], accept[2], accept[3]);
            if index < s.len() && s[index] != 0 {
                return Some(index);
            }
            return None;
        }
        _ => {}
    }

    let accept_set = &accept[..accept_len];
    // span_dispatch(stop_in_set=true) returns the first member-or-NUL index, or
    // s.len(). It is strpbrk when the stop is a real member (non-NUL, in range).
    let index = span_dispatch(s, accept_set, true);
    if index < s.len() && s[index] != 0 {
        Some(index)
    } else {
        None
    }
}

/// Case-insensitive version of `strstr`. Finds the first occurrence of
/// `needle` in `haystack`, ignoring ASCII case.
///
/// Equivalent to GNU `strcasestr`. Returns the byte index where `needle` starts,
/// or `None` if not found.
pub fn strcasestr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let n_len = strlen(needle);

    if n_len == 0 {
        return Some(0);
    }

    let needle = &needle[..n_len];
    let h_len = strlen(haystack);
    let hay = &haystack[..h_len];
    if n_len > h_len {
        return None;
    }
    let first = needle[0].to_ascii_lowercase();
    let last = needle[n_len - 1].to_ascii_lowercase();

    // Dual-anchor fast path: a match at `start` requires BOTH the case-folded
    // first byte at `start` and the case-folded last byte at `start + n_len - 1`.
    // Last-byte anchoring is excellent when the last byte is the rarer anchor
    // (e.g. icase "aaaa...b"), but text needles often end in a common byte (`e`,
    // `t`, space). Use the same static frequency prior as `memmem`/`wcsstr` so
    // common-last text routes to the first-byte scan below while rare-last
    // needles keep the dual-anchor win. The O(n+m) Two-Way bailout and
    // leftmost-match semantics are preserved whichever anchor is selected.
    if first != last && strcasestr_prefers_last_anchor(first, last) {
        let mut anchor = n_len - 1;
        let mut miss_work = 0usize;
        while anchor < hay.len() {
            let scan = &hay[anchor..];
            let offset = find_ascii_folded_byte_or_nul(scan, last);
            if offset == scan.len() {
                return None; // folded last byte never recurs → no match
            }
            let last_pos = anchor + offset;
            let cand = last_pos - (n_len - 1);
            if hay[cand].eq_ignore_ascii_case(&needle[0]) {
                let mut matched = true;
                for j in 1..n_len {
                    if !hay[cand + j].eq_ignore_ascii_case(&needle[j]) {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    return Some(cand);
                }
                miss_work += n_len;
            }
            anchor = last_pos + 1;
            if miss_work > hay.len() {
                return super::mem::two_way_search_icase(&hay[cand..], needle).map(|m| m + cand);
            }
        }
        return None;
    }

    // Fast path: jump to each case-folded first-byte candidate and verify with
    // an ASCII case-insensitive compare. To keep the O(n+m) worst case against
    // a common needle first byte (e.g. icase "aaaa…a" over an 'a' run, which
    // previously made every position a candidate — O(n*m)), bail to a
    // case-insensitive Two-Way once cumulative failed-candidate work exceeds the
    // haystack length, mirroring `memmem`'s gated fallback. Both paths return
    // the leftmost match, so the result is identical.
    let mut start = 0usize;
    let mut miss_work = 0usize;
    while start + n_len <= hay.len() {
        let scan = &hay[start..];
        let offset = find_ascii_folded_byte_or_nul(scan, first);
        if offset == scan.len() {
            return None; // first byte (either case) does not occur again
        }

        let cand = start + offset;
        if cand + n_len > hay.len() {
            return None; // not enough room left for the needle
        }

        let mut matched = true;
        for j in 0..n_len {
            if !hay[cand + j].eq_ignore_ascii_case(&needle[j]) {
                matched = false;
                break;
            }
        }
        if matched {
            return Some(cand);
        }

        miss_work += n_len;
        start = cand + 1;
        if miss_work > hay.len() {
            // Everything before `start` is ruled out; finish with the guaranteed
            // O(n+m) case-insensitive search over the remaining suffix.
            return super::mem::two_way_search_icase(&hay[start..], needle).map(|m| m + start);
        }
    }

    None
}

#[inline(always)]
fn strcasestr_prefers_last_anchor(first: u8, last: u8) -> bool {
    debug_assert_ne!(first, last);
    strcasestr_anchor_commonness(last) <= strcasestr_anchor_commonness(first)
}

#[inline(always)]
fn strcasestr_anchor_commonness(byte: u8) -> u8 {
    match byte.to_ascii_lowercase() {
        b' ' | b'e' => 16,
        b'a' | b'i' | b'n' | b'o' | b'r' | b's' | b't' => 12,
        b'c' | b'd' | b'f' | b'g' | b'h' | b'l' | b'm' | b'p' | b'u' | b'w' | b'y' => 8,
        b'\t' | b'\n' | b'\r' | b'_' | b'-' | b'.' | b'/' => 6,
        b'0'..=b'9' => 5,
        b'!'..=b'~' => 4,
        0 => 2,
        _ => 1,
    }
}

/// Duplicates a NUL-terminated string into a new `Vec<u8>`.
///
/// This is the safe core of C `strdup`. The ABI layer handles the actual
/// malloc allocation. Returns the string bytes including the trailing NUL.
pub fn strdup_bytes(s: &[u8]) -> Vec<u8> {
    let len = strlen(s);
    let mut out = Vec::with_capacity(len + 1);
    out.extend_from_slice(&s[..len]);
    out.push(0);
    out
}

/// Duplicates at most `n` bytes of a NUL-terminated string into a new `Vec<u8>`.
///
/// This is the safe core of C `strndup`. Always NUL-terminates the result.
pub fn strndup_bytes(s: &[u8], n: usize) -> Vec<u8> {
    let len = strlen(s).min(n);
    let mut out = Vec::with_capacity(len + 1);
    out.extend_from_slice(&s[..len]);
    out.push(0);
    out
}

/// Extracts the next token from a NUL-terminated string, using `delim` as delimiter set.
///
/// Equivalent to BSD `strsep`. Modifies `s` in place by writing a NUL at the delimiter.
/// Returns the delimiter index, or `None` if no delimiter is found before the terminator.
pub fn strsep(s: &mut [u8], delim: &[u8]) -> Option<usize> {
    let delim_len = strlen(delim);
    if delim_len == 0 {
        return None;
    }
    if delim_len == 1 {
        let delimiter = delim[0];
        let index = find_byte_or_nul(s, delimiter);
        if index < s.len() && s[index] == delimiter {
            s[index] = 0;
            return Some(index);
        }
        return None;
    }
    // 2- and 3-delimiter sets (e.g. "\r\n", ", ", "::") are common; route them
    // through the SIMD find_any_of4 by padding the unused slot(s) with a repeated
    // delimiter, instead of the byte-by-byte linear .contains general path below.
    if delim_len == 2 {
        let index = find_any_of4_or_nul(s, delim[0], delim[1], delim[0], delim[1]);
        if index < s.len() && s[index] != 0 {
            s[index] = 0;
            return Some(index);
        }
        return None;
    }
    if delim_len == 3 {
        let index = find_any_of4_or_nul(s, delim[0], delim[1], delim[2], delim[2]);
        if index < s.len() && s[index] != 0 {
            s[index] = 0;
            return Some(index);
        }
        return None;
    }
    if delim_len == 4 {
        let index = find_any_of4_or_nul(s, delim[0], delim[1], delim[2], delim[3]);
        if index < s.len() && s[index] != 0 {
            s[index] = 0;
            return Some(index);
        }
        return None;
    }

    let delim_set = &delim[..delim_len];

    for (i, byte) in s.iter_mut().enumerate() {
        if *byte == 0 {
            return None;
        }
        if delim_set.contains(&*byte) {
            *byte = 0;
            return Some(i);
        }
    }

    None
}

/// Copies `src` into `dest` with size limit, always NUL-terminating.
///
/// Equivalent to BSD `strlcpy`. Returns the length of `src` (not counting NUL).
pub fn strlcpy(dest: &mut [u8], src: &[u8]) -> usize {
    let src_len = strlen(src);
    if dest.is_empty() {
        return src_len;
    }
    let copy_len = src_len.min(dest.len() - 1);
    dest[..copy_len].copy_from_slice(&src[..copy_len]);
    dest[copy_len] = 0;
    src_len
}

/// Appends `src` to `dest` with size limit, always NUL-terminating.
///
/// Equivalent to BSD `strlcat`. Returns the total length that would have
/// resulted without truncation.
pub fn strlcat(dest: &mut [u8], src: &[u8]) -> usize {
    let dest_len = strlen(dest);
    let src_len = strlen(src);

    if dest_len >= dest.len() {
        return dest.len() + src_len;
    }

    let available = dest.len() - dest_len - 1;
    let copy_len = src_len.min(available);
    dest[dest_len..dest_len + copy_len].copy_from_slice(&src[..copy_len]);
    dest[dest_len + copy_len] = 0;
    dest_len + src_len
}

/// Compares two strings using the current locale's collation order.
///
/// In the C/POSIX locale (which FrankenLibC uses), this is identical to `strcmp`.
pub fn strcoll(s1: &[u8], s2: &[u8]) -> i32 {
    strcmp(s1, s2)
}

/// Transforms a string for locale-aware comparison.
///
/// In the C/POSIX locale, this is a plain copy. Returns the length needed.
pub fn strxfrm(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let src_len = strlen(src);
    let limit = n.min(dest.len());
    if limit > 0 {
        let copy_len = src_len.min(limit);
        dest[..copy_len].copy_from_slice(&src[..copy_len]);
        if copy_len < limit {
            dest[copy_len] = 0;
        }
    }
    src_len
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::Config as ProptestConfig;
    use sha2::{Digest, Sha256};

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

    fn to_c_string(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.retain(|byte| *byte != 0);
        bytes.push(0);
        bytes
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    #[test]
    fn test_strlen_basic() {
        assert_eq!(strlen(b"hello\0"), 5);
        assert_eq!(strlen(b"\0"), 0);
        assert_eq!(strlen(b"abc"), 3); // no NUL found
    }

    #[test]
    fn test_strlen_simd_panel_finds_nul_before_hidden_bytes() {
        let mut s = vec![b'a'; 96];
        s[45] = 0;
        s[70] = 0;

        assert_eq!(strlen(&s), 45);
    }

    #[test]
    fn test_strlen_simd_panel_without_terminator_returns_len() {
        let s = vec![b'a'; 96];

        assert_eq!(strlen(&s), 96);
    }

    #[test]
    fn test_strlen_wide_simd_panel_finds_nul_after_first_panel() {
        let mut s = vec![b'a'; 160];
        s[95] = 0;
        s[130] = 0;

        assert_eq!(strlen(&s), 95);
    }

    #[test]
    fn test_strcmp_equal() {
        assert_eq!(strcmp(b"abc\0", b"abc\0"), 0);
    }

    #[test]
    fn test_strcmp_less() {
        assert!(strcmp(b"abc\0", b"abd\0") < 0);
    }

    #[test]
    fn test_strcmp_greater() {
        assert!(strcmp(b"abd\0", b"abc\0") > 0);
    }

    #[test]
    fn test_strcmp_prefix() {
        assert!(strcmp(b"ab\0", b"abc\0") < 0);
        assert!(strcmp(b"abc\0", b"ab\0") > 0);
    }

    #[test]
    fn test_strcmp_exact_256_certificate_guard() {
        let mut left = vec![b'Q'; 256];
        let mut right = vec![b'Q'; 256];
        left.push(0);
        right.push(0);
        assert!(strcmp_exact_256_equal_nul_terminated(&left, &right));
        assert_eq!(strcmp(&left, &right), 0);

        for pos in [0usize, 127, 128, 255] {
            right[pos] = b'R';
            assert!(!strcmp_exact_256_equal_nul_terminated(&left, &right));
            assert_eq!(strcmp(&left, &right), (b'Q' as i32) - (b'R' as i32));
            right[pos] = b'Q';
        }

        left[80] = 0;
        right[80] = 0;
        left[160] = b'A';
        right[160] = b'Z';
        assert!(!strcmp_exact_256_equal_nul_terminated(&left, &right));
        assert_eq!(strcmp(&left, &right), 0);

        left[80] = b'Q';
        right[80] = b'Q';
        left[160] = b'Q';
        right[160] = b'Q';
        left[256] = b'X';
        assert!(!strcmp_exact_256_equal_nul_terminated(&left, &right));
        assert_eq!(strcmp(&left, &right), b'X' as i32);

        right[256] = b'X';
        assert!(!strcmp_exact_256_equal_nul_terminated(&left, &right));
        assert_eq!(strcmp(&left, &right), 0);

        left.truncate(256);
        right.truncate(256);
        assert!(!strcmp_exact_256_equal_nul_terminated(&left, &right));
        assert_eq!(strcmp(&left, &right), 0);
    }

    #[test]
    fn test_strcmp_golden_transcript_sha256() {
        let mut equal_left = vec![b'Q'; 256];
        let mut equal_right = vec![b'Q'; 256];
        equal_left.push(0);
        equal_right.push(0);

        let mut late_left = vec![b'a'; 96];
        let mut late_right = vec![b'a'; 96];
        late_left[70] = b'b';
        late_right[70] = b'c';
        late_left.push(0);
        late_right.push(0);

        let mut hidden_left = vec![b'x'; 80];
        let mut hidden_right = vec![b'x'; 80];
        hidden_left[40] = 0;
        hidden_right[40] = 0;
        hidden_left[60] = b'a';
        hidden_right[60] = b'z';

        let cases: &[(&[u8], &[u8])] = &[
            (&equal_left, &equal_right),
            (&late_left, &late_right),
            (&hidden_left, &hidden_right),
            (b"ab\0", b"abc\0"),
            (&[0xff, 0], &[0x01, 0]),
        ];

        let mut transcript = String::new();
        for (left, right) in cases {
            transcript.push_str(&strcmp(left, right).to_string());
            transcript.push('\n');
        }

        let digest = Sha256::digest(transcript.as_bytes());
        assert_eq!(
            hex_lower(&digest),
            "bf3a44bce53a40a47eb334b89238d840573096846b050b62096ace20e43ff977"
        );
    }

    #[test]
    fn test_strnlen_basic() {
        assert_eq!(strnlen(b"hello\0", 10), 5);
        assert_eq!(strnlen(b"hello\0", 3), 3);
        assert_eq!(strnlen(b"\0", 5), 0);
        assert_eq!(strnlen(b"abc", 8), 3);
    }

    /// Differential isomorphism guard for the SIMD `strcmp` panels — both the
    /// 128-byte folded block (`equal_and_no_nul_simd_folded`, lengths >128) and
    /// the 32-byte panel (`equal_and_no_nul_simd_32`): a deterministic xorshift
    /// fuzz drives long, mostly-equal pairs with NULs and diffs at varied offsets
    /// (lengths up to 200, straddling the 128-byte block boundary) — exercising
    /// the folded loop, the vectorized loop, the aligned word loop, and the byte
    /// tail — and asserts
    /// the full `i32` result (not just its sign) matches a trivial scalar
    /// reference that mirrors C-string semantics (index past slice end = NUL).
    #[test]
    fn prop_strcmp_simd_matches_scalar_reference() {
        fn scalar_ref(s1: &[u8], s2: &[u8]) -> i32 {
            let mut i = 0;
            loop {
                let a = if i < s1.len() { s1[i] } else { 0 };
                let b = if i < s2.len() { s2[i] } else { 0 };
                if a != b {
                    return a as i32 - b as i32;
                }
                if a == 0 {
                    return 0;
                }
                i += 1;
            }
        }

        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..200_000 {
            let len = (next() % 200) as usize;
            // Build a shared base so most pairs share a long equal prefix,
            // forcing the SIMD panel to run to completion before diverging.
            let mut a: Vec<u8> = (0..len).map(|_| (next() as u8) | 1).collect();
            let mut b = a.clone();
            // Sprinkle divergences / embedded NULs at random offsets.
            for buf in [&mut a, &mut b] {
                if len > 0 && next() % 3 == 0 {
                    let pos = (next() as usize) % len;
                    buf[pos] = (next() as u8) | 1; // keep non-NUL unless chosen below
                }
                if len > 0 && next() % 4 == 0 {
                    let pos = (next() as usize) % len;
                    buf[pos] = 0; // embedded NUL terminator
                }
            }
            // Half the pairs get an explicit trailing NUL (C-string form).
            if next() % 2 == 0 {
                a.push(0);
                b.push(0);
            }
            assert_eq!(
                strcmp(&a, &b),
                scalar_ref(&a, &b),
                "strcmp mismatch a={a:?} b={b:?}"
            );
        }
    }

    #[test]
    fn test_strnlen_matches_bounded_scalar_reference() {
        let cases: &[&[u8]] = &[
            b"",
            b"\0",
            b"abc",
            b"abc\0def",
            b"\0abc",
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0tail",
        ];

        for s in cases {
            for maxlen in 0..=80 {
                let limit = maxlen.min(s.len());
                let expected = s[..limit]
                    .iter()
                    .position(|&byte| byte == 0)
                    .unwrap_or(limit);
                assert_eq!(strnlen(s, maxlen), expected);
            }
        }
    }

    #[test]
    fn test_strncmp_basic() {
        assert_eq!(strncmp(b"abcdef\0", b"abcxyz\0", 3), 0);
        assert!(strncmp(b"abcdef\0", b"abcxyz\0", 4) < 0);
    }

    #[test]
    fn test_strcpy_basic() {
        let mut buf = [0u8; 10];
        let n = strcpy(&mut buf, b"hello\0");
        assert_eq!(n, 6);
        assert_eq!(&buf[..6], b"hello\0");
    }

    #[test]
    fn test_strcpy_fused_path_copies_long_terminated_slice() {
        let mut src = vec![b'a'; 1024];
        src.push(0);
        let mut dst = vec![0xCC; src.len()];
        let copied = strcpy(&mut dst, &src);
        assert_eq!(copied, src.len());
        assert_eq!(dst, src);
    }

    #[test]
    fn test_strcpy_stops_at_first_nul_without_touching_trailing_dest() {
        let mut dst = [0xAA; 16];
        let copied = strcpy(&mut dst, b"hi\0trailing\0");
        assert_eq!(copied, 3);
        assert_eq!(&dst[..3], b"hi\0");
        assert_eq!(dst[3], 0xAA);
    }

    #[test]
    fn test_strcpy_fused_path_preserves_tail_after_early_nul() {
        let mut src = vec![b'a'; STRLEN_NUL_BLOCK * 2 + 1];
        src[STRLEN_NUL_BLOCK + 17] = 0;
        *src.last_mut().unwrap() = 0;
        let mut dst = vec![0xA5; src.len()];

        let copied = strcpy(&mut dst, &src);

        assert_eq!(copied, STRLEN_NUL_BLOCK + 18);
        assert_eq!(&dst[..copied], &src[..copied]);
        assert_eq!(dst[copied], 0xA5);
    }

    #[test]
    fn test_strcpy_exact_4096_path_preserves_tail_after_early_nul() {
        let nul_pos = STRLEN_NUL_BLOCK * 3 + 29;
        let mut src = vec![b'a'; STRCPY_4096_SRC_LEN];
        src[nul_pos] = 0;
        *src.last_mut().unwrap() = 0;
        let mut dst = vec![0x5A; src.len()];

        let copied = strcpy(&mut dst, &src);

        assert_eq!(copied, nul_pos + 1);
        assert_eq!(&dst[..copied], &src[..copied]);
        assert_eq!(dst[copied], 0x5A);
        assert_eq!(dst[STRCPY_4096_SRC_LEN - 1], 0x5A);
    }

    #[test]
    fn test_strcpy_exact_4096_path_copies_terminal_boundary_payload() {
        let mut src = vec![b'a'; STRCPY_4096_SRC_LEN];
        for (i, byte) in src[..STRCPY_4096_SRC_LEN - 1].iter_mut().enumerate() {
            *byte = b'A' + (i % 26) as u8;
        }
        *src.last_mut().unwrap() = 0;
        let mut dst = vec![0x5A; STRCPY_4096_SRC_LEN + 8];

        let copied = strcpy(&mut dst, &src);

        assert_eq!(copied, STRCPY_4096_SRC_LEN);
        assert_eq!(&dst[..STRCPY_4096_SRC_LEN], &src[..]);
        assert!(dst[STRCPY_4096_SRC_LEN..].iter().all(|&byte| byte == 0x5A));
    }

    #[test]
    fn test_strcpy_golden_transcript_sha256() {
        let mut transcript = Vec::new();

        for src in [b"hello\0".as_slice(), b"hi\0trailing\0".as_slice(), &[0]] {
            let mut dst = [0xA5; 32];
            let copied = strcpy(&mut dst, src);
            transcript.extend_from_slice(&copied.to_le_bytes());
            transcript.extend_from_slice(&dst);
        }

        for nul_pos in [0usize, 63, 64, 511, 512, 1024] {
            let mut src = vec![b'Q'; nul_pos + 1];
            src[nul_pos] = 0;
            let mut dst = vec![0xCC; src.len() + 7];
            let copied = strcpy(&mut dst, &src);
            transcript.extend_from_slice(&copied.to_le_bytes());
            transcript.extend_from_slice(&dst);
        }

        let digest = Sha256::digest(&transcript);
        assert_eq!(
            hex_lower(&digest),
            "fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401"
        );
    }

    #[test]
    #[should_panic(expected = "strcpy: destination buffer too small")]
    fn test_strcpy_no_nul_still_panics_without_synthetic_nul_room() {
        let mut dst = [0u8; 3];
        strcpy(&mut dst, b"abc");
    }

    #[test]
    fn test_stpcpy_returns_terminator_index() {
        let mut buf = [0u8; 10];
        let idx = stpcpy(&mut buf, b"hello\0");
        assert_eq!(idx, 5);
        assert_eq!(&buf[..6], b"hello\0");
    }

    #[test]
    fn test_strncpy_basic() {
        let mut buf = [0xFFu8; 10];
        strncpy(&mut buf, b"hi\0", 5);
        assert_eq!(&buf[..5], b"hi\0\0\0");
    }

    #[test]
    fn test_strncpy_truncate() {
        let mut buf = [0xFFu8; 3];
        strncpy(&mut buf, b"hello\0", 3);
        // Not NUL-terminated because src was longer than n.
        assert_eq!(&buf, b"hel");
    }

    #[test]
    fn test_stpncpy_returns_first_padding_nul_when_source_short() {
        let mut buf = [0xFFu8; 8];
        let idx = stpncpy(&mut buf, b"hi\0", 5);
        assert_eq!(idx, 2);
        assert_eq!(&buf[..5], b"hi\0\0\0");
    }

    #[test]
    fn test_stpncpy_returns_n_when_source_long() {
        let mut buf = [0xFFu8; 8];
        let idx = stpncpy(&mut buf, b"hello\0", 3);
        assert_eq!(idx, 3);
        assert_eq!(&buf[..3], b"hel");
    }

    #[test]
    fn test_strcat_basic() {
        let mut buf = [0u8; 12];
        strcpy(&mut buf, b"hello\0");
        let total = strcat(&mut buf, b" world\0");
        assert_eq!(total, 11);
        assert_eq!(&buf[..12], b"hello world\0");
    }

    #[test]
    fn test_strncat_basic() {
        let mut buf = [0u8; 10];
        strcpy(&mut buf, b"hi\0");
        let total = strncat(&mut buf, b"there\0", 3);
        assert_eq!(total, 5);
        assert_eq!(&buf[..6], b"hithe\0");
    }

    #[test]
    fn test_strchr_found() {
        assert_eq!(strchr(b"hello\0", b'l'), Some(2));
    }

    #[test]
    fn test_strchr_not_found() {
        assert_eq!(strchr(b"hello\0", b'z'), None);
    }

    #[test]
    fn test_strchr_nul() {
        assert_eq!(strchr(b"hello\0", 0), Some(5));
    }

    #[test]
    fn test_strchr_stops_at_terminator() {
        assert_eq!(strchr(b"hi\0hidden", b'h'), Some(0));
        assert_eq!(strchr(b"hi\0hidden", b'd'), None);
    }

    #[test]
    fn test_strchr_nul_without_terminator_returns_len() {
        assert_eq!(strchr(b"unterminated", 0), Some(12));
    }

    #[test]
    fn test_strchrnul_found() {
        assert_eq!(strchrnul(b"hello\0", b'l'), 2);
    }

    #[test]
    fn test_strchrnul_not_found_returns_terminator() {
        assert_eq!(strchrnul(b"hello\0", b'z'), 5);
    }

    #[test]
    fn test_strchr_simd_panel_resolves_needle_before_later_nul() {
        let mut s = vec![b'A'; 96];
        s[39] = b'Z';
        s[70] = 0;
        assert_eq!(strchr(&s, b'Z'), Some(39));
        assert_eq!(strchrnul(&s, b'Z'), 39);
    }

    #[test]
    fn test_strchr_simd_panel_stops_at_nul_before_later_needle() {
        let mut s = vec![b'A'; 96];
        s[35] = 0;
        s[39] = b'Z';
        assert_eq!(strchr(&s, b'Z'), None);
        assert_eq!(strchrnul(&s, b'Z'), 35);
    }

    #[test]
    fn test_strchr_wide_fold_resolves_needle_before_later_nul() {
        let mut s = vec![b'A'; 320];
        s[190] = b'Z';
        s[260] = 0;
        assert_eq!(strchr(&s, b'Z'), Some(190));
        assert_eq!(strchrnul(&s, b'Z'), 190);
    }

    #[test]
    fn test_strchr_wide_fold_stops_at_nul_before_later_needle() {
        let mut s = vec![b'A'; 320];
        s[190] = 0;
        s[220] = b'Z';
        assert_eq!(strchr(&s, b'Z'), None);
        assert_eq!(strchrnul(&s, b'Z'), 190);
    }

    #[test]
    fn test_strchr_golden_transcript_sha256() {
        fn record(transcript: &mut Vec<u8>, s: &[u8], needle: u8) {
            transcript.extend_from_slice(&s.len().to_le_bytes());
            transcript.extend_from_slice(s);
            transcript.push(needle);
            match strchr(s, needle) {
                Some(index) => {
                    transcript.push(1);
                    transcript.extend_from_slice(&index.to_le_bytes());
                }
                None => {
                    transcript.push(0);
                    transcript.extend_from_slice(&usize::MAX.to_le_bytes());
                }
            }
            transcript.extend_from_slice(&strchrnul(s, needle).to_le_bytes());
        }

        let mut transcript = Vec::new();
        for (s, needle) in [
            (b"hello\0".as_slice(), b'l'),
            (b"hello\0".as_slice(), b'z'),
            (b"hello\0".as_slice(), 0),
            (b"hi\0hidden".as_slice(), b'd'),
            (b"unterminated".as_slice(), 0),
        ] {
            record(&mut transcript, s, needle);
        }

        for (len, needle_pos, nul_pos) in [
            (257usize, Some(255usize), 256usize),
            (320, Some(190), 260),
            (320, Some(220), 190),
            (4097, None, 4096),
        ] {
            let mut s = vec![b'A'; len];
            if let Some(pos) = needle_pos {
                s[pos] = b'Z';
            }
            s[nul_pos] = 0;
            record(&mut transcript, &s, b'Z');
        }

        let digest = Sha256::digest(&transcript);
        assert_eq!(
            hex_lower(&digest),
            "3656ba0841f975b7aa6d31cf8a01cac9b90635e6eecf66431ce80893bd859f18"
        );
    }

    #[test]
    fn test_strrchr_found() {
        assert_eq!(strrchr(b"hello\0", b'l'), Some(3));
    }

    #[test]
    fn test_strrchr_stops_at_terminator() {
        assert_eq!(strrchr(b"abca\0a", b'a'), Some(3));
        assert_eq!(strrchr(b"abca\0z", b'z'), None);
    }

    #[test]
    fn test_strrchr_reverse_bulk_scan_preserves_last_before_terminator() {
        let mut s = vec![b'a'; 96];
        s[5] = b'z';
        s[63] = b'z';
        s.push(0);
        s.push(b'z');

        assert_eq!(strrchr(&s, b'z'), Some(63));
    }

    #[test]
    fn test_strrchr_simd_panel_resolves_last_match_before_terminator() {
        let mut s = vec![b'a'; 128];
        s[17] = b'z';
        s[96] = b'z';
        s[111] = 0;
        s[120] = b'z';

        assert_eq!(strrchr(&s, b'z'), Some(96));
    }

    #[test]
    fn test_strrchr_simd_panel_ignores_match_after_terminator() {
        let mut s = vec![b'a'; 128];
        s[17] = b'z';
        s[63] = 0;
        s[95] = b'z';

        assert_eq!(strrchr(&s, b'z'), Some(17));
    }

    #[test]
    fn test_strrchr_nul_without_terminator_returns_len() {
        assert_eq!(strrchr(b"unterminated", 0), Some(12));
    }

    #[test]
    fn test_strrchr_golden_transcript_sha256() {
        fn record(transcript: &mut Vec<u8>, s: &[u8], needle: u8) {
            transcript.extend_from_slice(&s.len().to_le_bytes());
            transcript.extend_from_slice(s);
            transcript.push(needle);
            match strrchr(s, needle) {
                Some(index) => {
                    transcript.push(1);
                    transcript.extend_from_slice(&index.to_le_bytes());
                }
                None => {
                    transcript.push(0);
                    transcript.extend_from_slice(&usize::MAX.to_le_bytes());
                }
            }
        }

        fn case(len: usize, positions: &[usize], nul_pos: usize) -> Vec<u8> {
            let mut s = vec![b'A'; len];
            for &pos in positions {
                s[pos] = b'Z';
            }
            s[nul_pos] = 0;
            s
        }

        let mut transcript = Vec::new();
        for (s, needle) in [
            (b"hello\0".as_slice(), b'l'),
            (b"hello\0".as_slice(), b'z'),
            (b"hello\0".as_slice(), 0),
            (b"abca\0a".as_slice(), b'a'),
            (b"unterminated".as_slice(), 0),
        ] {
            record(&mut transcript, s, needle);
        }

        for (len, positions, nul_pos) in [
            (257usize, [255usize].as_slice(), 256usize),
            (320, [190, 220].as_slice(), 260),
            (320, [17, 95].as_slice(), 190),
            (320, [220].as_slice(), 190),
            (513, [31, 128, 511].as_slice(), 512),
            (4097, [].as_slice(), 4096),
        ] {
            record(&mut transcript, &case(len, positions, nul_pos), b'Z');
        }

        let digest = Sha256::digest(&transcript);
        assert_eq!(
            hex_lower(&digest),
            "a2d88c8fc144d9705080a44619c97736b57b2199a5425ea5b9367fe16c606afb"
        );
    }

    #[test]
    fn test_strspn_basic() {
        assert_eq!(strspn(b"abc123\0", b"abc\0"), 3);
    }

    #[test]
    fn test_strspn_single_accept_full_without_terminator() {
        assert_eq!(strspn(b"AAAA", b"A\0"), 4);
    }

    #[test]
    fn test_strspn_small_accept_sets() {
        assert_eq!(strspn(b"ababaZ\0", b"ab\0"), 5);
        assert_eq!(strspn(b"cabbaZ\0", b"abc\0"), 5);
    }

    // Isomorphism: the generalized SIMD span scan (set size > 4: padded-8,
    // padded-16, and the scalar >16 tier) must equal a trivial scalar oracle
    // for every input/set, across chunk boundaries and stop positions.
    #[test]
    fn span_general_matches_scalar_oracle() {
        fn span_oracle(s: &[u8], set: &[u8], stop_in_set: bool) -> usize {
            let set_len = set.iter().position(|&b| b == 0).unwrap_or(set.len());
            let real = &set[..set_len];
            for (i, &b) in s.iter().enumerate() {
                if b == 0 || (real.contains(&b) == stop_in_set) {
                    return i;
                }
            }
            s.len()
        }
        // Sets of size 5,8,9,16,17,20 (exercise padded-8 / padded-16 / scalar).
        let sets: &[&[u8]] = &[
            b"abcde\0",
            b"abcdefgh\0",
            b"abcdefghi\0",
            b"abcdefghijklmnop\0",
            b"abcdefghijklmnopq\0",
            b"0123456789abcdefghij\0",
        ];
        for set in sets {
            for len in [0usize, 1, 7, 31, 32, 33, 65, 200] {
                for stop_pos in [usize::MAX, 0, 1, 30, 31, 32, 64, len.saturating_sub(1)] {
                    // Vary fill/interloper membership so both directions get
                    // non-trivial scans: 'a' is in every set, 'x' in none,
                    // 'm'/'5' in some.
                    for &fill in b"axm5" {
                        for &interloper in b"Za5m" {
                            let mut s = vec![fill; len];
                            if stop_pos < len {
                                s[stop_pos] = interloper;
                            }
                            s.push(0);
                            assert_eq!(
                                strspn(&s, set),
                                span_oracle(&s, set, false),
                                "strspn set={:?} len={} stop={} fill={} int={}",
                                set,
                                len,
                                stop_pos,
                                fill,
                                interloper
                            );
                            assert_eq!(
                                strcspn(&s, set),
                                span_oracle(&s, set, true),
                                "strcspn set={:?} len={} stop={} fill={} int={}",
                                set,
                                len,
                                stop_pos,
                                fill,
                                interloper
                            );
                            // strpbrk reuses the same stop-on-member scan, then
                            // maps a NUL/end stop to None and a member to Some.
                            let pb_idx = span_oracle(&s, set, true);
                            let pb_expected = if pb_idx < s.len() && s[pb_idx] != 0 {
                                Some(pb_idx)
                            } else {
                                None
                            };
                            assert_eq!(
                                strpbrk(&s, set),
                                pb_expected,
                                "strpbrk set={:?} len={} stop={} fill={} int={}",
                                set,
                                len,
                                stop_pos,
                                fill,
                                interloper
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn span_general_contiguous_range_matches_stop_semantics() {
        let accept = b"abcdefgh\0";

        let mut full = vec![b'a'; 192];
        full.push(0);
        assert_eq!(strspn(&full, accept), 192);

        let mut nonmember = vec![b'h'; 192];
        nonmember[130] = b'i';
        nonmember.push(0);
        assert_eq!(strspn(&nonmember, accept), 130);

        let mut nul_first = vec![b'd'; 192];
        nul_first[70] = 0;
        nul_first[120] = b'i';
        assert_eq!(strspn(&nul_first, accept), 70);

        let mut reject = vec![b'z'; 192];
        reject[129] = b'c';
        reject.push(0);
        assert_eq!(strcspn(&reject, accept), 129);
        assert_eq!(strpbrk(&reject, accept), Some(129));
    }

    #[test]
    fn test_strspn_four_accept_set_simd_stops_on_nonmember() {
        let mut s = vec![b'A'; 96];
        s[37] = b'E';
        s[64] = 0;

        assert_eq!(strspn(&s, b"ABCD\0"), 37);
    }

    #[test]
    fn test_strspn_four_accept_set_simd_stops_at_nul_before_nonmember() {
        let mut s = vec![b'A'; 96];
        s[31] = 0;
        s[63] = b'E';

        assert_eq!(strspn(&s, b"ABCD\0"), 31);
    }

    #[test]
    fn test_strspn_stops_at_terminator() {
        assert_eq!(strspn(b"abc\0Z", b"abcZ\0"), 3);
    }

    #[test]
    fn test_strspn_full_without_terminator_returns_len() {
        assert_eq!(strspn(b"unterminated", b"untermiad\0"), 12);
    }

    #[test]
    fn test_strspn_empty_accept_returns_zero() {
        assert_eq!(strspn(b"abc\0", b"\0"), 0);
        assert_eq!(strspn(b"\0", b"\0"), 0);
    }

    #[test]
    fn test_strcspn_basic() {
        assert_eq!(strcspn(b"abc123\0", b"123\0"), 3);
    }

    #[test]
    fn test_strcspn_single_reject_match_without_terminator() {
        assert_eq!(strcspn(b"abcZdef", b"Z\0"), 3);
    }

    #[test]
    fn test_strcspn_small_reject_sets() {
        assert_eq!(strcspn(b"abcXdef\0", b"XY\0"), 3);
        assert_eq!(strcspn(b"abcZdef\0", b"XYZ\0"), 3);
    }

    #[test]
    fn test_strcspn_four_reject_set_simd_stops_on_reject() {
        let mut s = vec![b'A'; 96];
        s[45] = b'X';
        s[70] = 0;

        assert_eq!(strcspn(&s, b"WXYZ\0"), 45);
    }

    #[test]
    fn test_strcspn_four_reject_set_simd_stops_at_nul_before_reject() {
        let mut s = vec![b'A'; 96];
        s[29] = 0;
        s[70] = b'X';

        assert_eq!(strcspn(&s, b"WXYZ\0"), 29);
    }

    #[test]
    fn test_strcspn_four_reject_fused_mask_preserves_first_stop_order() {
        let mut s = vec![b'A'; SIMD_LANES * 3 + 5];
        s[SIMD_LANES + 7] = b'Y';
        s[SIMD_LANES * 2 + 3] = 0;
        assert_eq!(strcspn(&s, b"WXYZ\0"), SIMD_LANES + 7);

        s[SIMD_LANES + 4] = 0;
        assert_eq!(strcspn(&s, b"WXYZ\0"), SIMD_LANES + 4);
    }

    #[test]
    fn test_strcspn_stops_at_terminator() {
        assert_eq!(strcspn(b"abc\0Z", b"Z\0"), 3);
    }

    #[test]
    fn test_strcspn_reject_absent_without_terminator_returns_len() {
        assert_eq!(strcspn(b"unterminated", b"Z\0"), 12);
    }

    #[test]
    fn test_strcspn_empty_reject_returns_strlen() {
        assert_eq!(strcspn(b"abc\0", b"\0"), 3);
    }

    #[test]
    fn test_strpbrk_basic() {
        assert_eq!(strpbrk(b"abc123\0", b"13\0"), Some(3));
    }

    #[test]
    fn test_strpbrk_single_accept_match_without_terminator() {
        assert_eq!(strpbrk(b"abcZdef", b"Z\0"), Some(3));
    }

    #[test]
    fn test_strpbrk_small_accept_sets() {
        assert_eq!(strpbrk(b"abcYdef\0", b"XY\0"), Some(3));
        assert_eq!(strpbrk(b"abcZdef\0", b"XYZ\0"), Some(3));
    }

    #[test]
    fn test_strpbrk_four_accept_set_simd_finds_first_match() {
        let mut s = vec![b'A'; 96];
        s[34] = b'Y';
        s[52] = b'W';
        s[80] = 0;

        assert_eq!(strpbrk(&s, b"WXYZ\0"), Some(34));
    }

    #[test]
    fn test_strpbrk_four_accept_set_simd_stops_at_nul_before_match() {
        let mut s = vec![b'A'; 96];
        s[30] = 0;
        s[52] = b'Y';

        assert_eq!(strpbrk(&s, b"WXYZ\0"), None);
    }

    #[test]
    fn test_strpbrk_stops_at_terminator() {
        assert_eq!(strpbrk(b"abc\0Z", b"Z\0"), None);
    }

    #[test]
    fn test_strpbrk_accept_absent_without_terminator_returns_none() {
        assert_eq!(strpbrk(b"unterminated", b"Z\0"), None);
    }

    #[test]
    fn test_strpbrk_empty_accept_returns_none() {
        assert_eq!(strpbrk(b"abc\0", b"\0"), None);
    }

    #[test]
    fn test_strstr_found() {
        assert_eq!(strstr(b"hello world\0", b"world\0"), Some(6));
    }

    #[test]
    fn test_strstr_not_found() {
        assert_eq!(strstr(b"hello world\0", b"xyz\0"), None);
    }

    #[test]
    fn test_strstr_empty_needle() {
        assert_eq!(strstr(b"hello\0", b"\0"), Some(0));
    }

    #[test]
    fn test_strstr_stops_at_terminator() {
        assert_eq!(strstr(b"a\0bc\0", b"bc\0"), None);
    }

    #[test]
    fn test_strstr_unterminated_haystack_match() {
        assert_eq!(strstr(b"abc", b"bc\0"), Some(1));
    }

    #[test]
    fn test_strstr_unterminated_haystack_short_candidate() {
        assert_eq!(strstr(b"ab", b"bc\0"), None);
    }

    // Isomorphism: the memmem-delegated strstr must equal a trivial NUL-bounded
    // window-search reference for every haystack/needle — including the
    // common-first-byte O(n*m) stress case that motivated the rewrite.
    #[test]
    fn strstr_matches_naive_reference() {
        fn naive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            let h = &haystack[..haystack
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(haystack.len())];
            let n = &needle[..needle.iter().position(|&b| b == 0).unwrap_or(needle.len())];
            if n.is_empty() {
                return Some(0);
            }
            if n.len() > h.len() {
                return None;
            }
            (0..=h.len() - n.len()).find(|&i| &h[i..i + n.len()] == n)
        }
        let haystacks: &[&[u8]] = &[
            b"\0",
            b"a\0",
            b"abcabcabd\0",
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab\0", // common-first-byte stress
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0", // no match
            b"the quick brown fox\0",
            b"mississippi\0",
            b"abc\0def\0", // embedded NUL bounds the haystack
        ];
        let needles: &[&[u8]] = &[
            b"\0",
            b"a\0",
            b"b\0",
            b"aaaaaaab\0", // common first byte, absent
            b"aaab\0",
            b"abd\0",
            b"issi\0",
            b"fox\0",
            b"def\0", // only past an embedded NUL — must NOT match
            b"xyz\0",
            b"the quick brown fox\0",
            b"the quick brown fox jumps\0", // needle longer than haystack
        ];
        for h in haystacks {
            for n in needles {
                assert_eq!(
                    strstr(h, n),
                    naive(h, n),
                    "strstr({:?}, {:?}) diverged from naive reference",
                    h,
                    n
                );
            }
        }
    }

    // ---- strnstr (BSD bounded substring search) ----

    #[test]
    fn test_strnstr_found_within_bound() {
        assert_eq!(strnstr(b"hello world\0", b"world\0", 11), Some(6));
    }

    #[test]
    fn test_strnstr_match_truncated_by_bound() {
        // "world" starts at offset 6, ends at 11. With n=10 the
        // searchable region is "hello worl" — needle does not fit.
        assert_eq!(strnstr(b"hello world\0", b"world\0", 10), None);
    }

    #[test]
    fn test_strnstr_match_exactly_at_bound() {
        // n=11 is exactly enough to fit "world" at offset 6.
        assert_eq!(strnstr(b"hello world\0", b"world\0", 11), Some(6));
    }

    #[test]
    fn test_strnstr_n_larger_than_haystack() {
        // n exceeds haystack length: clamps to strlen(haystack).
        assert_eq!(strnstr(b"foo\0", b"oo\0", 1024), Some(1));
    }

    #[test]
    fn test_strnstr_not_found_returns_none() {
        assert_eq!(strnstr(b"abcdef\0", b"xyz\0", 6), None);
    }

    #[test]
    fn test_strnstr_empty_needle_matches_at_zero() {
        // Matches strstr behavior: empty needle returns Some(0)
        // regardless of n.
        assert_eq!(strnstr(b"abc\0", b"\0", 0), Some(0));
        assert_eq!(strnstr(b"abc\0", b"\0", 100), Some(0));
        assert_eq!(strnstr(b"\0", b"\0", 0), Some(0));
    }

    #[test]
    fn test_strnstr_n_zero_with_nonempty_needle_returns_none() {
        assert_eq!(strnstr(b"abc\0", b"a\0", 0), None);
    }

    #[test]
    fn test_strnstr_needle_longer_than_n() {
        assert_eq!(strnstr(b"abc\0", b"abcd\0", 3), None);
    }

    #[test]
    fn test_strnstr_haystack_truncated_by_nul() {
        // NUL inside the bound truncates the search region — strstr
        // semantics inherited.
        assert_eq!(strnstr(b"abc\0def\0", b"def\0", 100), None);
    }

    #[test]
    fn test_strnstr_ignores_match_after_bound_without_terminator() {
        assert_eq!(strnstr(b"aaaaZQ", b"ZQ\0", 4), None);
    }

    #[test]
    fn test_strnstr_unterminated_haystack_match_within_bound() {
        assert_eq!(strnstr(b"xabcGARBAGE", b"abc\0", 4), Some(1));
    }

    /// Byte-for-byte O(n·m) reference: scan the NUL-terminated, `n`-bounded
    /// prefix for the leftmost full needle match. Independent of the delegated
    /// `memmem` path, so it pins strnstr's contract under the dual-anchor fix.
    fn strnstr_naive(haystack: &[u8], needle: &[u8], n: usize) -> Option<usize> {
        let n_len = needle.iter().position(|&b| b == 0).unwrap_or(needle.len());
        if n_len == 0 {
            return Some(0);
        }
        let limit = n.min(haystack.len());
        let end = haystack[..limit]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(limit);
        if n_len > end {
            return None;
        }
        (0..=end - n_len).find(|&i| haystack[i..i + n_len] == needle[..n_len])
    }

    #[test]
    fn strnstr_matches_naive_on_adversarial_corpus() {
        // Includes the common-first-byte "aaaa…b" needle over an 'a' run — the
        // exact O(n·m) blow-up the old first-byte-only scan suffered (no Two-Way
        // bailout). Delegating to memmem fixes the complexity; outputs must stay
        // identical to the naive reference across bounds and NUL positions.
        let mut a_run = vec![b'a'; 512];
        a_run.push(0);
        let mut a_run_b = vec![b'a'; 300];
        a_run_b.extend_from_slice(b"aaab"); // present late, common first byte
        a_run_b.push(0);
        let haystacks: &[&[u8]] = &[
            b"hello world\0",
            b"abc\0def\0",
            b"aaaaZQ",
            b"xabcGARBAGE",
            &a_run,
            &a_run_b,
            b"\0",
            b"mississippi\0",
        ];
        let needles: &[&[u8]] = &[
            b"world\0",
            b"def\0",
            b"ZQ\0",
            b"abc\0",
            b"aaaaaaaaaaaaaaaab\0", // 15 a + b: absent, common first byte
            b"aaab\0",
            b"a\0",
            b"\0",
            b"issi\0",
            b"ppi\0",
        ];
        for &h in haystacks {
            for &needle in needles {
                for n in [0usize, 1, 3, 4, 16, 300, 304, 512, 600, 4096] {
                    assert_eq!(
                        strnstr(h, needle, n),
                        strnstr_naive(h, needle, n),
                        "strnstr divergence: haystack={h:?} needle={needle:?} n={n}"
                    );
                }
            }
        }
    }

    #[test]
    fn strnstr_golden_corpus_sha256() {
        let nul = |mut bytes: Vec<u8>| {
            bytes.push(0);
            bytes
        };

        let mut cases: Vec<(Vec<u8>, Vec<u8>, usize)> = vec![
            (nul(b"".to_vec()), nul(b"".to_vec()), 0),
            (nul(b"abc".to_vec()), nul(b"".to_vec()), 0),
            (nul(b"hello world".to_vec()), nul(b"world".to_vec()), 11),
            (nul(b"hello world".to_vec()), nul(b"world".to_vec()), 10),
            (nul(b"hello world".to_vec()), nul(b"world".to_vec()), 1024),
            (nul(b"abc\0def".to_vec()), nul(b"def".to_vec()), 100),
            (b"aaaaZQ".to_vec(), nul(b"ZQ".to_vec()), 4),
            (b"xabcGARBAGE".to_vec(), nul(b"abc".to_vec()), 4),
            (nul(b"aaaa".to_vec()), nul(b"aaa".to_vec()), 4),
            (nul(b"aaaa".to_vec()), nul(b"aaa".to_vec()), 2),
            (nul(b"abcabc".to_vec()), nul(b"abc".to_vec()), 6),
            (nul(b"xabcabc".to_vec()), nul(b"abc".to_vec()), 7),
            (nul(b"mississippi".to_vec()), nul(b"issi".to_vec()), 11),
            (nul(b"mississippi".to_vec()), nul(b"ppi".to_vec()), 8),
            (
                nul(vec![b'a'; 512]),
                nul(b"aaaaaaaaaaaaaaaab".to_vec()),
                512,
            ),
        ];
        let mut late = vec![b'a'; 300];
        late.extend_from_slice(b"aaab\0");
        cases.push((late, nul(b"aaab".to_vec()), 304));
        for size in [16usize, 64, 256, 1024, 4096] {
            let mut haystack = vec![b'A'; size];
            haystack.push(0);
            cases.push((haystack, nul(b"ZQ".to_vec()), size));
        }

        let mut hasher = Sha256::new();
        let mut line = String::new();
        for (idx, (haystack, needle, bound)) in cases.iter().enumerate() {
            let result = strnstr(haystack, needle, *bound);
            line.clear();
            let result_field = result
                .map(|offset| offset.to_string())
                .unwrap_or_else(|| String::from("none"));
            line.push_str(&format!("{idx};{result_field}\n"));
            hasher.update(line.as_bytes());
        }
        let digest_hex: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            digest_hex, "84555952f755c0ff071a2b064db484fb74e838c180632c105f9b034f0e9bafa7",
            "strnstr golden corpus hash drifted"
        );
    }

    #[test]
    fn test_strnstr_match_at_zero() {
        assert_eq!(strnstr(b"hello\0", b"hello\0", 5), Some(0));
    }

    #[test]
    fn test_strnstr_finds_first_occurrence() {
        assert_eq!(strnstr(b"abcabc\0", b"abc\0", 6), Some(0));
        assert_eq!(strnstr(b"xabcabc\0", b"abc\0", 7), Some(1));
    }

    #[test]
    fn test_strnstr_overlapping_pattern() {
        // "aaa" inside "aaaa" — first match at offset 0, regardless
        // of n.
        assert_eq!(strnstr(b"aaaa\0", b"aaa\0", 4), Some(0));
        assert_eq!(strnstr(b"aaaa\0", b"aaa\0", 3), Some(0));
        // n=2 truncates region to "aa"; needle doesn't fit.
        assert_eq!(strnstr(b"aaaa\0", b"aaa\0", 2), None);
    }

    #[test]
    fn test_strnstr_candidate_jump_stops_at_nul_before_later_candidate() {
        let mut haystack = [b'A'; 96];
        haystack[40] = 0;
        haystack[64] = b'Z';
        haystack[65] = b'Q';

        assert_eq!(strnstr(&haystack, b"ZQ\0", haystack.len()), None);
    }

    #[test]
    fn test_strnstr_candidate_jump_matches_before_later_nul() {
        let mut haystack = [b'A'; 96];
        haystack[33] = b'Z';
        haystack[34] = b'Q';
        haystack[80] = 0;

        assert_eq!(strnstr(&haystack, b"ZQ\0", haystack.len()), Some(33));
    }

    #[test]
    fn test_strnstr_candidate_jump_resumes_after_false_candidate() {
        let mut haystack = [b'A'; 128];
        haystack[32] = b'Z';
        haystack[33] = b'X';
        haystack[70] = b'Z';
        haystack[71] = b'Q';

        assert_eq!(strnstr(&haystack, b"ZQ\0", 96), Some(70));
    }

    #[test]
    fn test_strnstr_candidate_jump_rejects_candidate_beyond_bound() {
        let mut haystack = [b'A'; 96];
        haystack[62] = b'Z';
        haystack[63] = b'Q';

        assert_eq!(strnstr(&haystack, b"ZQ\0", 63), None);
    }

    #[test]
    fn test_strcasestr_found() {
        assert_eq!(strcasestr(b"Hello World\0", b"world\0"), Some(6));
    }

    // Isomorphism: the work-counter-gated probe AND the case-insensitive Two-Way
    // bail must both equal a trivial NUL-bounded icase window search — including
    // the common-first-byte stress (mixed case) that forces the Two-Way bail.
    #[test]
    fn strcasestr_matches_naive_icase_reference() {
        fn naive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            let h = &haystack[..haystack
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(haystack.len())];
            let n = &needle[..needle.iter().position(|&b| b == 0).unwrap_or(needle.len())];
            if n.is_empty() {
                return Some(0);
            }
            if n.len() > h.len() {
                return None;
            }
            (0..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
        }
        // A long mixed-case 'a'/'A' run with an absent (and a present) suffix —
        // every position is a folded first-byte candidate, forcing the bail.
        let mut stress = Vec::new();
        for k in 0..300 {
            stress.push(if k % 2 == 0 { b'a' } else { b'A' });
        }
        let mut stress_hit = stress.clone();
        stress_hit.extend_from_slice(b"XyZ");
        stress.push(0);
        stress_hit.push(0);

        let haystacks: &[&[u8]] = &[
            b"\0",
            b"A\0",
            b"Hello World\0",
            b"MixEdCaSeMixEdCaSe\0",
            b"aAaAaAaAaAaAaAaAaAaAb\0",
            stress.as_slice(),
            stress_hit.as_slice(),
            b"abc\0DEF\0", // embedded NUL bounds the haystack
        ];
        let needles: &[&[u8]] = &[
            b"\0",
            b"a\0",
            b"A\0",
            b"world\0",
            b"WORLD\0",
            b"mixedcase\0",
            b"aaaaaaaaab\0",
            b"AAAAAAAAAB\0",
            b"xyz\0",
            b"def\0",             // only past an embedded NUL — must NOT match
            b"hello world fox\0", // longer than some haystacks
        ];
        for h in haystacks {
            for n in needles {
                assert_eq!(
                    strcasestr(h, n),
                    naive(h, n),
                    "strcasestr({:?}, {:?}) diverged from naive icase reference",
                    h,
                    n
                );
            }
        }
    }

    #[test]
    fn test_strcasestr_not_found() {
        assert_eq!(strcasestr(b"Hello World\0", b"xyz\0"), None);
    }

    #[test]
    fn test_strcasestr_empty_needle() {
        assert_eq!(strcasestr(b"hello\0", b"\0"), Some(0));
    }

    #[test]
    fn test_strcasestr_exact_match() {
        assert_eq!(strcasestr(b"ABC\0", b"abc\0"), Some(0));
    }

    #[test]
    fn test_strcasestr_stops_at_terminator() {
        assert_eq!(strcasestr(b"a\0BC\0", b"bc\0"), None);
    }

    #[test]
    fn test_strcasestr_unterminated_haystack_match() {
        assert_eq!(strcasestr(b"aBC", b"bc\0"), Some(1));
    }

    #[test]
    fn test_strcasestr_unterminated_haystack_short_candidate() {
        assert_eq!(strcasestr(b"aB", b"bc\0"), None);
    }

    #[test]
    fn test_strcasestr_simd_panel_stops_at_nul_before_folded_candidate() {
        let mut haystack = [b'A'; 64];
        haystack[7] = 0;
        haystack[20] = b'Z';
        haystack[21] = b'Q';
        assert_eq!(strcasestr(&haystack, b"zq\0"), None);
    }

    #[test]
    fn test_strcasestr_simd_panel_resolves_folded_candidate_before_nul() {
        let mut haystack = [b'A'; 64];
        haystack[12] = b'Z';
        haystack[13] = b'Q';
        haystack[20] = 0;
        assert_eq!(strcasestr(&haystack, b"zq\0"), Some(12));
    }

    #[test]
    fn test_strcasestr_simd_panel_preserves_first_full_match() {
        let mut haystack = [b'A'; 64];
        haystack[5] = b'Z';
        haystack[6] = b'X';
        haystack[24] = b'z';
        haystack[25] = b'Q';
        haystack[40] = 0;
        assert_eq!(strcasestr(&haystack, b"zq\0"), Some(24));
    }

    #[test]
    fn test_strcasestr_simd_panel_non_ascii_first_byte_is_exact() {
        assert_eq!(strcasestr(&[0xC0, b'q', 0], &[0xC0, b'Q', 0]), Some(0));
        assert_eq!(strcasestr(&[0xE0, b'q', 0], &[0xC0, b'q', 0]), None);
    }

    #[test]
    fn test_ascii_folded_finder_folded_block_preserves_first_nul_or_candidate() {
        let mut haystack = vec![b'A'; SIMD_FOLD_BYTES * 2 + 17];
        haystack[SIMD_FOLD_BYTES + 5] = b'Q';
        haystack[SIMD_FOLD_BYTES + 12] = 0;
        assert_eq!(
            find_ascii_folded_byte_or_nul(&haystack, b'q'),
            SIMD_FOLD_BYTES + 5
        );

        haystack[SIMD_LANES + 3] = 0;
        assert_eq!(
            find_ascii_folded_byte_or_nul(&haystack, b'q'),
            SIMD_LANES + 3
        );
    }

    #[test]
    fn test_strsep_basic() {
        let mut s = *b"hello,world,end\0";
        let result = strsep(&mut s, b",\0");
        assert_eq!(result, Some(5)); // comma replaced with NUL
        assert_eq!(s[5], 0);
    }

    #[test]
    fn test_strsep_no_delimiter() {
        let mut s = *b"hello\0";
        let result = strsep(&mut s, b",\0");
        assert_eq!(result, None); // entire string is token
    }

    #[test]
    fn test_strsep_single_byte_delimiter_bulk_scan_mutates_only_match() {
        let mut s = vec![b'a'; 96];
        s[53] = b':';
        s[95] = 0;

        let result = strsep(&mut s, b":\0");

        assert_eq!(result, Some(53));
        assert_eq!(s[53], 0);
        assert_eq!(s[52], b'a');
        assert_eq!(s[54], b'a');
    }

    #[test]
    fn test_strsep_four_delimiter_bulk_scan_preserves_first_stop_order() {
        let mut s = vec![b'a'; SIMD_LANES * 3 + 5];
        s[SIMD_LANES + 9] = b'|';
        s[SIMD_LANES * 2 + 1] = 0;

        let result = strsep(&mut s, b":;|\t\0");

        assert_eq!(result, Some(SIMD_LANES + 9));
        assert_eq!(s[SIMD_LANES + 9], 0);
        assert_eq!(s[SIMD_LANES + 8], b'a');
        assert_eq!(s[SIMD_LANES + 10], b'a');

        let mut nul_first = vec![b'a'; SIMD_LANES * 3 + 5];
        nul_first[SIMD_LANES + 4] = 0;
        nul_first[SIMD_LANES + 9] = b'|';

        assert_eq!(strsep(&mut nul_first, b":;|\t\0"), None);
        assert_eq!(nul_first[SIMD_LANES + 9], b'|');
    }

    #[test]
    fn test_strsep_two_three_delim_simd_matches_reference() {
        // The len-2/3 SIMD-routed paths must find the same first delimiter-or-NUL
        // as a byte-by-byte reference, across a long buffer (exercises the SIMD
        // bulk scan) for each delimiter and the no-match case.
        fn reference(s: &[u8], delims: &[u8]) -> Option<usize> {
            for (i, &b) in s.iter().enumerate() {
                if b == 0 {
                    return None;
                }
                if delims[..delims.len() - 1].contains(&b) {
                    return Some(i);
                }
            }
            None
        }
        for delims in [
            b"\r\n\0".as_slice(),
            b", \0".as_slice(),
            b"::\0".as_slice(),
            b";|:\0".as_slice(),
        ] {
            for hit in [7usize, SIMD_LANES + 3, SIMD_LANES * 2 + 1, 999] {
                let mut buf = vec![b'x'; SIMD_LANES * 3 + 10];
                let last = delims[..delims.len() - 1].len() - 1;
                if hit < buf.len() {
                    buf[hit] = delims[last.min(delims.len() - 2)]; // a real delimiter byte
                }
                let mut a = buf.clone();
                let got = strsep(&mut a, delims);
                let want = reference(&buf, delims);
                assert_eq!(
                    got, want,
                    "strsep delims={delims:?} hit={hit}: got={got:?} want={want:?}"
                );
                if let Some(idx) = got {
                    assert_eq!(a[idx], 0, "delimiter overwritten with NUL");
                }
            }
        }
    }

    #[test]
    fn test_strsep_empty_string() {
        let mut s = *b"\0";
        assert_eq!(strsep(&mut s, b",\0"), None);
    }

    #[test]
    fn test_strsep_stops_at_terminator() {
        let mut s = *b"abc\0:def";
        assert_eq!(strsep(&mut s, b":\0"), None);
        assert_eq!(s[4], b':');
    }

    #[test]
    fn test_strsep_absent_without_terminator_returns_none() {
        let mut s = *b"unterminated";
        assert_eq!(strsep(&mut s, b":\0"), None);
        assert_eq!(&s, b"unterminated");
    }

    #[test]
    fn test_strsep_empty_delim_never_splits() {
        let mut s = *b"abc\0";
        assert_eq!(strsep(&mut s, b"\0"), None);
        assert_eq!(&s, b"abc\0");
    }

    #[test]
    fn test_strsep_consecutive_delimiters_produce_empty_tokens() {
        // Unlike strtok which skips consecutive delimiters, strsep returns
        // empty tokens. "a::b" with ":" produces ["a", "", "b"].
        let mut s = *b"a::b\0";
        // First call: find first ":" at index 1
        let idx1 = strsep(&mut s, b":\0");
        assert_eq!(idx1, Some(1));
        assert_eq!(s[1], 0); // NUL-terminated "a"

        // Second call on remaining "::b\0" starting at index 2
        let mut s2 = s[2..].to_vec();
        let idx2 = strsep(&mut s2, b":\0");
        assert_eq!(idx2, Some(0)); // empty token at position 0
        assert_eq!(s2[0], 0); // NUL-terminated empty string

        // Third call on remaining "b\0"
        let mut s3 = s2[1..].to_vec();
        let idx3 = strsep(&mut s3, b":\0");
        assert_eq!(idx3, None); // "b" has no delimiter, returns None
    }

    #[test]
    fn test_strlcpy_basic() {
        let mut dest = [0u8; 10];
        let result = strlcpy(&mut dest, b"hello\0");
        assert_eq!(result, 5);
        assert_eq!(&dest[..6], b"hello\0");
    }

    #[test]
    fn test_strlcpy_truncation() {
        let mut dest = [0u8; 4];
        let result = strlcpy(&mut dest, b"hello\0");
        assert_eq!(result, 5); // returns full src length
        assert_eq!(&dest, b"hel\0"); // truncated + NUL
    }

    #[test]
    fn test_strlcat_basic() {
        let mut dest = [0u8; 12];
        dest[..6].copy_from_slice(b"hello\0");
        let result = strlcat(&mut dest, b" world\0");
        assert_eq!(result, 11);
        assert_eq!(&dest[..12], b"hello world\0");
    }

    #[test]
    fn test_strlcat_truncation() {
        let mut dest = [0u8; 8];
        dest[..6].copy_from_slice(b"hello\0");
        let result = strlcat(&mut dest, b" world\0");
        assert_eq!(result, 11); // would-have-been length
        assert_eq!(&dest[..8], b"hello w\0"); // truncated + NUL
    }

    #[test]
    fn test_strcoll_delegates_to_strcmp() {
        assert_eq!(strcoll(b"abc\0", b"abc\0"), 0);
        assert!(strcoll(b"abc\0", b"abd\0") < 0);
        assert!(strcoll(b"abd\0", b"abc\0") > 0);
    }

    #[test]
    fn test_strxfrm_basic() {
        let mut dest = [0u8; 10];
        let result = strxfrm(&mut dest, b"hello\0", 10);
        assert_eq!(result, 5);
        assert_eq!(&dest[..6], b"hello\0");
    }

    #[test]
    fn test_strxfrm_truncation() {
        let mut dest = [0u8; 3];
        let result = strxfrm(&mut dest, b"hello\0", 3);
        assert_eq!(result, 5); // returns full src length
        assert_eq!(&dest[..3], b"hel"); // only first 3 bytes copied
    }

    proptest! {
        #![proptest_config(property_proptest_config(256))]

        #[test]
        fn prop_strlen_matches_first_nul_or_slice_len(data in proptest::collection::vec(any::<u8>(), 0..128)) {
            let expected = data.iter().position(|byte| *byte == 0).unwrap_or(data.len());
            prop_assert_eq!(strlen(&data), expected);
        }

        #[test]
        fn prop_strcmp_is_antisymmetric(
            left in proptest::collection::vec(any::<u8>(), 0..96),
            right in proptest::collection::vec(any::<u8>(), 0..96)
        ) {
            let left_c = to_c_string(left);
            let right_c = to_c_string(right);

            let lr = strcmp(&left_c, &right_c);
            let rl = strcmp(&right_c, &left_c);
            prop_assert_eq!(lr.signum(), -rl.signum());
        }

        #[test]
        fn prop_strstr_aligns_with_manual_window_search(
            hay in proptest::collection::vec(any::<u8>(), 0..96),
            needle in proptest::collection::vec(any::<u8>(), 0..24)
        ) {
            let hay_c = to_c_string(hay);
            let needle_c = to_c_string(needle);

            let hay_len = strlen(&hay_c);
            let needle_len = strlen(&needle_c);
            let expected = if needle_len == 0 {
                Some(0)
            } else if needle_len > hay_len {
                None
            } else {
                hay_c[..hay_len]
                    .windows(needle_len)
                    .position(|window| window == &needle_c[..needle_len])
            };

            prop_assert_eq!(strstr(&hay_c, &needle_c), expected);
        }
    }

    // ===== glibc parity tests =====
    // Verified against glibc via scripts/c_probes/probe_string_edge.c

    #[test]
    fn glibc_strchr_finds_nul_terminator() {
        // strchr("hello", '\0') returns offset 5 (the NUL terminator)
        assert_eq!(strchr(b"hello\0", 0), Some(5));
    }

    #[test]
    fn glibc_strchr_not_found_returns_none() {
        // strchr("hello", 'x') = NULL
        assert_eq!(strchr(b"hello\0", b'x'), None);
    }

    #[test]
    fn glibc_strstr_empty_needle_returns_zero() {
        // strstr("hello world", "") returns offset 0
        assert_eq!(strstr(b"hello world\0", b"\0"), Some(0));
    }

    #[test]
    fn glibc_strstr_not_found_returns_none() {
        // strstr("hello", "xyz") = NULL
        assert_eq!(strstr(b"hello\0", b"xyz\0"), None);
    }

    #[test]
    fn glibc_strncpy_no_nul_when_src_ge_n() {
        // strncpy(buf, "hello", 3) does NOT NUL-terminate
        let mut buf = [b'x'; 8];
        strncpy(&mut buf, b"hello\0", 3);
        assert_eq!(&buf[..4], b"helx"); // 4th byte unchanged
    }

    #[test]
    fn glibc_strncpy_nul_pads_when_src_lt_n() {
        // strncpy(buf, "hi", 10) NUL-pads remainder
        let mut buf = [b'x'; 12];
        strncpy(&mut buf, b"hi\0", 10);
        assert_eq!(buf[5], 0); // NUL padding
    }

    #[test]
    fn glibc_strcmp_empty_strings() {
        // strcmp("", "") = 0
        assert_eq!(strcmp(b"\0", b"\0"), 0);
    }

    #[test]
    fn glibc_strncmp_truncated_compare() {
        // strncmp("abcdef", "abcxyz", 3) = 0 (only first 3 bytes)
        assert_eq!(strncmp(b"abcdef\0", b"abcxyz\0", 3), 0);
    }

    #[test]
    fn glibc_strcasecmp_case_insensitive() {
        // strcasecmp("Hello", "HELLO") = 0
        assert_eq!(strcasecmp(b"Hello\0", b"HELLO\0"), 0);
    }

    #[test]
    fn glibc_strspn_counts_initial_accept() {
        // strspn("aaabcd", "a") = 3
        assert_eq!(strspn(b"aaabcd\0", b"a\0"), 3);
        // strspn("xyz", "abc") = 0
        assert_eq!(strspn(b"xyz\0", b"abc\0"), 0);
    }

    #[test]
    fn glibc_strcspn_counts_initial_reject() {
        // strcspn("hello", "aeiou") = 1 (stops at 'e')
        assert_eq!(strcspn(b"hello\0", b"aeiou\0"), 1);
        // strcspn("hello", "xyz") = 5 (entire string)
        assert_eq!(strcspn(b"hello\0", b"xyz\0"), 5);
    }
}
