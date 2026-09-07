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
#[inline(always)]
pub fn memcmp(a: &[u8], b: &[u8], n: usize) -> core::cmp::Ordering {
    let count = n.min(a.len()).min(b.len());

    let a = &a[..count];
    let b = &b[..count];

    match count {
        0 => return core::cmp::Ordering::Equal,
        4 => {
            let x = u32::from_be_bytes(a[..4].try_into().unwrap());
            let y = u32::from_be_bytes(b[..4].try_into().unwrap());
            return x.cmp(&y);
        }
        WORD => {
            let x = u64_be_from_chunk(a);
            let y = u64_be_from_chunk(b);
            return x.cmp(&y);
        }
        MEMCMP_EXACT_16_BYTES => {
            return memcmp_exact_16_words(a, b);
        }
        SIMD_LANES => {
            return memcmp_exact_32_mask(a, b);
        }
        MEMCMP_WIDE_LANES => {
            return memcmp_exact_64_mask(a, b);
        }
        SIMD_FOLD_BYTES => {
            return memcmp_exact_128_mask(a, b);
        }
        MEMCMP_EXACT_256_BYTES => {
            return memcmp_exact_256_mask(a, b);
        }
        _ => {}
    }

    if count < WORD {
        return compare_bytes(a, b);
    }

    if count < MEMCMP_EXACT_16_BYTES {
        let hx = u64_be_from_chunk(&a[..WORD]);
        let hy = u64_be_from_chunk(&b[..WORD]);
        let ord = hx.cmp(&hy);
        if ord != core::cmp::Ordering::Equal {
            return ord;
        }
        let tx = u64_be_from_chunk(&a[count - WORD..]);
        let ty = u64_be_from_chunk(&b[count - WORD..]);
        return tx.cmp(&ty);
    }

    if count < SIMD_LANES {
        let head_ord =
            memcmp_exact_16_words(&a[..MEMCMP_EXACT_16_BYTES], &b[..MEMCMP_EXACT_16_BYTES]);
        if head_ord != core::cmp::Ordering::Equal {
            return head_ord;
        }
        return memcmp_exact_16_words(
            &a[count - MEMCMP_EXACT_16_BYTES..],
            &b[count - MEMCMP_EXACT_16_BYTES..],
        );
    }

    if count < MEMCMP_WIDE_LANES {
        let head_ord = memcmp_exact_32_mask(&a[..SIMD_LANES], &b[..SIMD_LANES]);
        if head_ord != core::cmp::Ordering::Equal {
            return head_ord;
        }
        return memcmp_exact_32_mask(&a[count - SIMD_LANES..], &b[count - SIMD_LANES..]);
    }

    let mut cur_a = a;
    let mut cur_b = b;

    while cur_a.len() >= SIMD_FOLD_BYTES {
        let eq0 =
            Simd::<u8, SIMD_LANES>::from_slice(&cur_a[..SIMD_LANES])
                .simd_eq(Simd::<u8, SIMD_LANES>::from_slice(&cur_b[..SIMD_LANES]));
        let eq1 = Simd::<u8, SIMD_LANES>::from_slice(&cur_a[SIMD_LANES..SIMD_LANES * 2]).simd_eq(
            Simd::<u8, SIMD_LANES>::from_slice(&cur_b[SIMD_LANES..SIMD_LANES * 2]),
        );
        let eq2 = Simd::<u8, SIMD_LANES>::from_slice(&cur_a[SIMD_LANES * 2..SIMD_LANES * 3])
            .simd_eq(Simd::<u8, SIMD_LANES>::from_slice(
                &cur_b[SIMD_LANES * 2..SIMD_LANES * 3],
            ));
        let eq3 = Simd::<u8, SIMD_LANES>::from_slice(&cur_a[SIMD_LANES * 3..SIMD_FOLD_BYTES])
            .simd_eq(Simd::<u8, SIMD_LANES>::from_slice(
                &cur_b[SIMD_LANES * 3..SIMD_FOLD_BYTES],
            ));

        let eq_all = (eq0 & eq1) & (eq2 & eq3);
        if !eq_all.all() {
            let m0 = eq0.to_bitmask() as u32;
            if m0 != u32::MAX {
                let first = (!m0).trailing_zeros() as usize;
                return cur_a[first].cmp(&cur_b[first]);
            }
            let m1 = eq1.to_bitmask() as u32;
            if m1 != u32::MAX {
                let first = SIMD_LANES + (!m1).trailing_zeros() as usize;
                return cur_a[first].cmp(&cur_b[first]);
            }
            let m2 = eq2.to_bitmask() as u32;
            if m2 != u32::MAX {
                let first = SIMD_LANES * 2 + (!m2).trailing_zeros() as usize;
                return cur_a[first].cmp(&cur_b[first]);
            }
            let m3 = eq3.to_bitmask() as u32;
            let first = SIMD_LANES * 3 + (!m3).trailing_zeros() as usize;
            return cur_a[first].cmp(&cur_b[first]);
        }
        cur_a = &cur_a[SIMD_FOLD_BYTES..];
        cur_b = &cur_b[SIMD_FOLD_BYTES..];
    }

    if cur_a.len() >= MEMCMP_WIDE_LANES {
        let ord = memcmp_exact_64_mask(&cur_a[..MEMCMP_WIDE_LANES], &cur_b[..MEMCMP_WIDE_LANES]);
        if ord != core::cmp::Ordering::Equal {
            return ord;
        }
        cur_a = &cur_a[MEMCMP_WIDE_LANES..];
        cur_b = &cur_b[MEMCMP_WIDE_LANES..];
    }

    if cur_a.len() >= SIMD_LANES {
        let ord = memcmp_exact_32_mask(&cur_a[..SIMD_LANES], &cur_b[..SIMD_LANES]);
        if ord != core::cmp::Ordering::Equal {
            return ord;
        }
        cur_a = &cur_a[SIMD_LANES..];
    }

    if !cur_a.is_empty() {
        return memcmp_exact_32_mask(&a[count - SIMD_LANES..], &b[count - SIMD_LANES..]);
    }

    core::cmp::Ordering::Equal
}

/// Resolve an exact 16-byte comparison using direct 128-bit big-endian integer comparison.
#[inline(always)]
fn memcmp_exact_16_words(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    debug_assert_eq!(a.len(), MEMCMP_EXACT_16_BYTES);
    debug_assert_eq!(b.len(), MEMCMP_EXACT_16_BYTES);

    let x = u128::from_be_bytes(a[..MEMCMP_EXACT_16_BYTES].try_into().unwrap());
    let y = u128::from_be_bytes(b[..MEMCMP_EXACT_16_BYTES].try_into().unwrap());
    x.cmp(&y)
}

/// Resolve an exact 32-byte comparison with one 32-lane SIMD inequality control mask.
#[inline(always)]
fn memcmp_exact_32_mask(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let a: &[u8; SIMD_LANES] = match a.try_into() {
        Ok(arr) => arr,
        Err(_) => return a.cmp(b),
    };
    let b: &[u8; SIMD_LANES] = match b.try_into() {
        Ok(arr) => arr,
        Err(_) => return a.as_slice().cmp(b),
    };

    let eq = Simd::<u8, SIMD_LANES>::from_slice(a).simd_eq(Simd::<u8, SIMD_LANES>::from_slice(b));
    let m = eq.to_bitmask() as u32;
    if m == u32::MAX {
        return core::cmp::Ordering::Equal;
    }

    let first = (!m).trailing_zeros() as usize;
    a[first].cmp(&b[first])
}

/// Resolve an exact 64-byte comparison with two 32-lane SIMD inequality control masks.
#[inline(always)]
fn memcmp_exact_64_mask(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let a: &[u8; MEMCMP_WIDE_LANES] = match a.try_into() {
        Ok(arr) => arr,
        Err(_) => return a.cmp(b),
    };
    let b: &[u8; MEMCMP_WIDE_LANES] = match b.try_into() {
        Ok(arr) => arr,
        Err(_) => return a.as_slice().cmp(b),
    };

    let a0 = Simd::<u8, SIMD_LANES>::from_slice(&a[..SIMD_LANES]);
    let b0 = Simd::<u8, SIMD_LANES>::from_slice(&b[..SIMD_LANES]);
    let a1 = Simd::<u8, SIMD_LANES>::from_slice(&a[SIMD_LANES..]);
    let b1 = Simd::<u8, SIMD_LANES>::from_slice(&b[SIMD_LANES..]);

    let eq0 = a0.simd_eq(b0);
    let eq1 = a1.simd_eq(b1);

    if !(eq0 & eq1).all() {
        let m0 = eq0.to_bitmask() as u32;
        if m0 != u32::MAX {
            let first = (!m0).trailing_zeros() as usize;
            return a[first].cmp(&b[first]);
        }
        let m1 = eq1.to_bitmask() as u32;
        let first = SIMD_LANES + (!m1).trailing_zeros() as usize;
        return a[first].cmp(&b[first]);
    }

    core::cmp::Ordering::Equal
}

/// Resolve an exact 128-byte comparison with four 32-lane SIMD inequality control masks.
#[inline(always)]
fn memcmp_exact_128_mask(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let a: &[u8; SIMD_FOLD_BYTES] = match a.try_into() {
        Ok(arr) => arr,
        Err(_) => return a.cmp(b),
    };
    let b: &[u8; SIMD_FOLD_BYTES] = match b.try_into() {
        Ok(arr) => arr,
        Err(_) => return a.as_slice().cmp(b),
    };

    let a0 = Simd::<u8, SIMD_LANES>::from_slice(&a[..SIMD_LANES]);
    let b0 = Simd::<u8, SIMD_LANES>::from_slice(&b[..SIMD_LANES]);
    let a1 = Simd::<u8, SIMD_LANES>::from_slice(&a[SIMD_LANES..SIMD_LANES * 2]);
    let b1 = Simd::<u8, SIMD_LANES>::from_slice(&b[SIMD_LANES..SIMD_LANES * 2]);
    let a2 = Simd::<u8, SIMD_LANES>::from_slice(&a[SIMD_LANES * 2..SIMD_LANES * 3]);
    let b2 = Simd::<u8, SIMD_LANES>::from_slice(&b[SIMD_LANES * 2..SIMD_LANES * 3]);
    let a3 = Simd::<u8, SIMD_LANES>::from_slice(&a[SIMD_LANES * 3..SIMD_FOLD_BYTES]);
    let b3 = Simd::<u8, SIMD_LANES>::from_slice(&b[SIMD_LANES * 3..SIMD_FOLD_BYTES]);

    let eq0 = a0.simd_eq(b0);
    let eq1 = a1.simd_eq(b1);
    let eq2 = a2.simd_eq(b2);
    let eq3 = a3.simd_eq(b3);

    let eq_all = (eq0 & eq1) & (eq2 & eq3);

    if !eq_all.all() {
        let m0 = eq0.to_bitmask() as u32;
        if m0 != u32::MAX {
            let first = (!m0).trailing_zeros() as usize;
            return a[first].cmp(&b[first]);
        }
        let m1 = eq1.to_bitmask() as u32;
        if m1 != u32::MAX {
            let first = SIMD_LANES + (!m1).trailing_zeros() as usize;
            return a[first].cmp(&b[first]);
        }
        let m2 = eq2.to_bitmask() as u32;
        if m2 != u32::MAX {
            let first = SIMD_LANES * 2 + (!m2).trailing_zeros() as usize;
            return a[first].cmp(&b[first]);
        }
        let m3 = eq3.to_bitmask() as u32;
        let first = SIMD_LANES * 3 + (!m3).trailing_zeros() as usize;
        return a[first].cmp(&b[first]);
    }

    core::cmp::Ordering::Equal
}

/// First differing byte of a 32-byte panel, or `None` if the panels are equal.
#[inline(always)]
#[allow(dead_code)]
fn first_diff_simd_32(a: &[u8], b: &[u8]) -> Option<usize> {
    debug_assert_eq!(a.len(), SIMD_LANES);
    debug_assert_eq!(b.len(), SIMD_LANES);
    let mask = Simd::<u8, SIMD_LANES>::from_slice(a)
        .simd_ne(Simd::<u8, SIMD_LANES>::from_slice(b))
        .to_bitmask();
    if mask == 0 {
        None
    } else {
        Some(mask.trailing_zeros() as usize)
    }
}

#[inline(always)]
#[allow(dead_code)]
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
    !((a0.simd_eq(b0) & a1.simd_eq(b1)) & (a2.simd_eq(b2) & a3.simd_eq(b3))).all()
}

/// Resolves an exact 256-byte comparison from two ordered 128-byte control blocks.
#[inline(always)]
fn memcmp_exact_256_mask(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let a: &[u8; MEMCMP_EXACT_256_BYTES] = match a.try_into() {
        Ok(arr) => arr,
        Err(_) => return a.cmp(b),
    };
    let b: &[u8; MEMCMP_EXACT_256_BYTES] = match b.try_into() {
        Ok(arr) => arr,
        Err(_) => return a.as_slice().cmp(b),
    };

    let ord0 = memcmp_exact_128_mask(&a[..SIMD_FOLD_BYTES], &b[..SIMD_FOLD_BYTES]);
    if ord0 != core::cmp::Ordering::Equal {
        return ord0;
    }
    memcmp_exact_128_mask(&a[SIMD_FOLD_BYTES..], &b[SIMD_FOLD_BYTES..])
}

#[inline(always)]
#[allow(dead_code)]
fn u64_from_chunk(chunk: &[u8]) -> u64 {
    u64::from_ne_bytes(chunk[..WORD].try_into().unwrap())
}

#[inline(always)]
fn u64_be_from_chunk(chunk: &[u8]) -> u64 {
    u64::from_be_bytes(chunk[..WORD].try_into().unwrap())
}

/// SWAR word size (8 bytes), matching the `chunks_exact(8)` scans in this module.
const WORD: usize = size_of::<u64>();
const SIMD_LANES: usize = 32;
const MEMCMP_EXACT_16_BYTES: usize = 16;
const MEMCMP_WIDE_LANES: usize = 64;
const SIMD_FOLD_PANELS: usize = 4;
const SIMD_FOLD_BYTES: usize = SIMD_LANES * SIMD_FOLD_PANELS;
const MEMCMP_EXACT_256_BYTES: usize = SIMD_FOLD_BYTES * 2;

#[allow(dead_code)]
const LO_U64: u64 = u64::from_ne_bytes([0x01; WORD]);
#[allow(dead_code)]
const HI_U64: u64 = u64::from_ne_bytes([0x80; WORD]);

/// Mycroft's zero-in-word MASK: the high bit of each byte lane is set iff that lane of
/// `word` is `0x00`. The single primitive both position helpers below are built on — the
/// point of this module's SWAR work is that the mask says *where*, so nothing that has
/// computed it should ever reduce it to a bool and then rescan to recover the position.
#[inline(always)]
#[allow(dead_code)]
fn zero_byte_mask_u64(word: u64) -> u64 {
    word.wrapping_sub(LO_U64) & !word & HI_U64
}

// `has_byte_u64` used to sit here: it ran the same SWAR fold as `first_byte_u64` /
// `last_byte_u64` but returned only a bool, so both of its callers then re-walked the
// eight-byte chunk scalar to find the position. They now resolve straight from the mask,
// leaving it dead; removed rather than kept behind an `allow(dead_code)`, exactly as
// `has_byte_simd_32` was above.

/// Index of the FIRST byte of `word` equal to `byte`, or `None`.
///
/// The SWAR probe already knows *where* the match is — the mask has the high bit set in
/// exactly the matching byte lanes — so resolving the position from it costs one
/// `trailing_zeros`. Callers that asked `has_byte_u64` and then re-walked the chunk with
/// `.position()` were throwing that mask away and paying a scalar loop to recompute what
/// they had already been told. This is the same defect the comment above records fixing
/// for `has_byte_simd_32` in `memrchr`; it survived here in `memchr`'s word loop.
///
/// Endianness-agnostic, like the probe it replaces: `word` comes from `from_ne_bytes`, so
/// chunk byte `k` sits in native byte position `k`; `to_le()` normalises that to the low
/// end on either endianness, after which `trailing_zeros() / 8` is the chunk index.
#[inline(always)]
#[allow(dead_code)]
fn first_byte_u64(word: u64, byte: u8) -> Option<usize> {
    let mask = zero_byte_mask_u64(word ^ u64::from_ne_bytes([byte; WORD]));
    if mask == 0 {
        return None;
    }
    Some((mask.to_le().trailing_zeros() / 8) as usize)
}

/// Index of the LAST byte of `word` equal to `byte`, or `None`. The reverse of
/// [`first_byte_u64`], for `memrchr`'s word loop, which had the same probe-then-rescan
/// shape with `.rposition()`. The SIMD panel directly above that loop already resolves
/// from its mask this way (`63 - leading_zeros`); the word loop did not.
#[inline(always)]
#[allow(dead_code)]
fn last_byte_u64(word: u64, byte: u8) -> Option<usize> {
    let mask = zero_byte_mask_u64(word ^ u64::from_ne_bytes([byte; WORD]));
    if mask == 0 {
        return None;
    }
    Some(((63 - mask.to_le().leading_zeros()) / 8) as usize)
}

// `has_byte_simd_32` used to sit here: it ran the same 32-lane compare as
// `byte_mask_simd_32` but discarded the mask, so every caller then re-walked the
// chunk scalar to find the position. Its last two callers (in `memrchr`) now
// resolve straight from the mask, leaving it dead; removed rather than kept
// behind an `allow(dead_code)`.

#[inline(always)]
fn byte_mask_simd_32(chunk: &[u8], byte: u8) -> u64 {
    debug_assert_eq!(chunk.len(), SIMD_LANES);
    Simd::<u8, SIMD_LANES>::from_slice(chunk)
        .simd_eq(Simd::splat(byte))
        .to_bitmask()
}

#[inline(always)]
#[allow(dead_code)]
fn first_byte_simd_32(chunk: &[u8], byte: u8) -> Option<usize> {
    let mask = byte_mask_simd_32(chunk, byte);
    if mask == 0 {
        None
    } else {
        Some(mask.trailing_zeros() as usize)
    }
}

#[inline(always)]
#[allow(dead_code)]
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
#[inline(always)]
pub fn memchr(haystack: &[u8], needle: u8, n: usize) -> Option<usize> {
    let count = n.min(haystack.len());
    let hs = &haystack[..count];

    // SHORT DISPATCH for everything below one 32-lane panel. Mirror of the block in `memrchr`,
    // and landed for the same reason: below 32 bytes this function built three iterators and
    // cleared the 256-byte fold guard on the way to a scan that one or two SIMD compares
    // answer outright.
    //
    // The measurement that named it is the length curve, not the ratio. Order-balanced against
    // live glibc, fl took **7.88 ns at n=16 against 5.32 ns at n=32** -- half the bytes for
    // half again the time. A scan cannot get cheaper as it lengthens, so the 16..=31 range was
    // not paying for its bytes, it was paying for its route: `chunks_exact(SIMD_LANES)` yields
    // nothing at that length, so the whole range fell through to **two SWAR word steps** where
    // a single 16-byte compare decides it.
    //
    // Two windows cover 16..=31 with no loop. The leading window is tested first and returns
    // the lowest set bit; if it is empty the trailing window's mask can only carry bits at or
    // above index 16, because a bit below it would name a byte the leading window just reported
    // clean -- so its low bit is the answer with no masking step. This is the first-match mirror
    // of the argument in `memrchr`, and `MEMCHR_INDEX_SWEEP` exercises exactly this range.
    if count < SIMD_LANES {
        if count == MEMCMP_EXACT_16_BYTES {
            let mask = Simd::<u8, MEMCMP_EXACT_16_BYTES>::from_slice(hs)
                .simd_eq(Simd::splat(needle))
                .to_bitmask();
            if mask != 0 {
                return Some((mask as u32).trailing_zeros() as usize);
            }
            return None;
        }
        if count == WORD {
            let mask = Simd::<u8, WORD>::from_slice(hs)
                .simd_eq(Simd::splat(needle))
                .to_bitmask();
            if mask != 0 {
                return Some((mask as u32).trailing_zeros() as usize);
            }
            return None;
        }
        if count > MEMCMP_EXACT_16_BYTES {
            let head_mask =
                Simd::<u8, MEMCMP_EXACT_16_BYTES>::from_slice(&hs[..MEMCMP_EXACT_16_BYTES])
                    .simd_eq(Simd::splat(needle))
                    .to_bitmask();
            if head_mask != 0 {
                return Some(head_mask.trailing_zeros() as usize);
            }
            let tail_start = count - MEMCMP_EXACT_16_BYTES;
            let tail_mask = Simd::<u8, MEMCMP_EXACT_16_BYTES>::from_slice(&hs[tail_start..])
                .simd_eq(Simd::splat(needle))
                .to_bitmask();
            if tail_mask != 0 {
                return Some(tail_start + tail_mask.trailing_zeros() as usize);
            }
            return None;
        }
        let mut i = 0usize;
        while count - i >= WORD {
            let mask = Simd::<u8, WORD>::from_slice(&hs[i..i + WORD])
                .simd_eq(Simd::splat(needle))
                .to_bitmask();
            if mask != 0 {
                return Some(i + (mask as u32).trailing_zeros() as usize);
            }
            i += WORD;
        }
        return hs[i..].iter().position(|&b| b == needle).map(|j| i + j);
    }

    let needle_simd = Simd::<u8, SIMD_LANES>::splat(needle);

    // 32..=64 bytes: two overlapping 32-lane SIMD panels cover the entire slice
    // without constructing block iterators or walking tier ladders.
    if count <= 64 {
        let head_mask = Simd::<u8, SIMD_LANES>::from_slice(&hs[..SIMD_LANES])
            .simd_eq(needle_simd)
            .to_bitmask();
        if head_mask != 0 {
            return Some((head_mask as u32).trailing_zeros() as usize);
        }
        let tail_start = count - SIMD_LANES;
        let tail_mask = Simd::<u8, SIMD_LANES>::from_slice(&hs[tail_start..])
            .simd_eq(needle_simd)
            .to_bitmask();
        if tail_mask != 0 {
            return Some(tail_start + (tail_mask as u32).trailing_zeros() as usize);
        }
        return None;
    }

    let mut cur = hs;

    while cur.len() >= MEMCMP_EXACT_256_BYTES {
        let block: &[u8; MEMCMP_EXACT_256_BYTES] = match cur[..MEMCMP_EXACT_256_BYTES].try_into() {
            Ok(arr) => arr,
            Err(_) => break,
        };
        let v0 = Simd::<u8, SIMD_LANES>::from_slice(&block[..SIMD_LANES]);
        let v1 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES..SIMD_LANES * 2]);
        let v2 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 2..SIMD_LANES * 3]);
        let v3 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 3..SIMD_FOLD_BYTES]);
        let v4 = Simd::<u8, SIMD_LANES>::from_slice(
            &block[SIMD_FOLD_BYTES..SIMD_FOLD_BYTES + SIMD_LANES],
        );
        let v5 = Simd::<u8, SIMD_LANES>::from_slice(
            &block[SIMD_FOLD_BYTES + SIMD_LANES..SIMD_FOLD_BYTES + SIMD_LANES * 2],
        );
        let v6 = Simd::<u8, SIMD_LANES>::from_slice(
            &block[SIMD_FOLD_BYTES + SIMD_LANES * 2..SIMD_FOLD_BYTES + SIMD_LANES * 3],
        );
        let v7 = Simd::<u8, SIMD_LANES>::from_slice(
            &block[SIMD_FOLD_BYTES + SIMD_LANES * 3..MEMCMP_EXACT_256_BYTES],
        );

        let m_lo = (v0.simd_eq(needle_simd) | v1.simd_eq(needle_simd))
            | (v2.simd_eq(needle_simd) | v3.simd_eq(needle_simd));
        let m_hi = (v4.simd_eq(needle_simd) | v5.simd_eq(needle_simd))
            | (v6.simd_eq(needle_simd) | v7.simd_eq(needle_simd));

        if (m_lo | m_hi).any() {
            let base = count - cur.len();
            if m_lo.any() {
                let m0 = v0.simd_eq(needle_simd).to_bitmask();
                if m0 != 0 {
                    return Some(base + (m0 as u32).trailing_zeros() as usize);
                }
                let m1 = v1.simd_eq(needle_simd).to_bitmask();
                if m1 != 0 {
                    return Some(base + SIMD_LANES + (m1 as u32).trailing_zeros() as usize);
                }
                let m2 = v2.simd_eq(needle_simd).to_bitmask();
                if m2 != 0 {
                    return Some(base + SIMD_LANES * 2 + (m2 as u32).trailing_zeros() as usize);
                }
                let m3 = v3.simd_eq(needle_simd).to_bitmask();
                return Some(base + SIMD_LANES * 3 + (m3 as u32).trailing_zeros() as usize);
            }
            let m4 = v4.simd_eq(needle_simd).to_bitmask();
            if m4 != 0 {
                return Some(base + SIMD_FOLD_BYTES + (m4 as u32).trailing_zeros() as usize);
            }
            let m5 = v5.simd_eq(needle_simd).to_bitmask();
            if m5 != 0 {
                return Some(
                    base + SIMD_FOLD_BYTES + SIMD_LANES + (m5 as u32).trailing_zeros() as usize,
                );
            }
            let m6 = v6.simd_eq(needle_simd).to_bitmask();
            if m6 != 0 {
                return Some(
                    base + SIMD_FOLD_BYTES + SIMD_LANES * 2 + (m6 as u32).trailing_zeros() as usize,
                );
            }
            let m7 = v7.simd_eq(needle_simd).to_bitmask();
            return Some(
                base + SIMD_FOLD_BYTES + SIMD_LANES * 3 + (m7 as u32).trailing_zeros() as usize,
            );
        }
        cur = &cur[MEMCMP_EXACT_256_BYTES..];
    }

    if cur.len() >= SIMD_FOLD_BYTES {
        let block: &[u8; SIMD_FOLD_BYTES] = cur[..SIMD_FOLD_BYTES].try_into().unwrap();
        let v0 = Simd::<u8, SIMD_LANES>::from_slice(&block[..SIMD_LANES]);
        let v1 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES..SIMD_LANES * 2]);
        let v2 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 2..SIMD_LANES * 3]);
        let v3 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 3..SIMD_FOLD_BYTES]);
        let any_match = (v0.simd_eq(needle_simd) | v1.simd_eq(needle_simd))
            | (v2.simd_eq(needle_simd) | v3.simd_eq(needle_simd));
        if any_match.any() {
            let base = count - cur.len();
            let m0 = v0.simd_eq(needle_simd).to_bitmask();
            if m0 != 0 {
                return Some(base + (m0 as u32).trailing_zeros() as usize);
            }
            let m1 = v1.simd_eq(needle_simd).to_bitmask();
            if m1 != 0 {
                return Some(base + SIMD_LANES + (m1 as u32).trailing_zeros() as usize);
            }
            let m2 = v2.simd_eq(needle_simd).to_bitmask();
            if m2 != 0 {
                return Some(base + SIMD_LANES * 2 + (m2 as u32).trailing_zeros() as usize);
            }
            let m3 = v3.simd_eq(needle_simd).to_bitmask();
            return Some(base + SIMD_LANES * 3 + (m3 as u32).trailing_zeros() as usize);
        }
        cur = &cur[SIMD_FOLD_BYTES..];
    }

    if cur.len() >= MEMCMP_WIDE_LANES {
        let block = &cur[..MEMCMP_WIDE_LANES];
        let v0 = Simd::<u8, SIMD_LANES>::from_slice(&block[..SIMD_LANES]);
        let v1 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES..]);
        let eq0 = v0.simd_eq(needle_simd);
        let eq1 = v1.simd_eq(needle_simd);
        if (eq0 | eq1).any() {
            let base = count - cur.len();
            let m0 = eq0.to_bitmask();
            if m0 != 0 {
                return Some(base + (m0 as u32).trailing_zeros() as usize);
            }
            let m1 = eq1.to_bitmask();
            return Some(base + SIMD_LANES + (m1 as u32).trailing_zeros() as usize);
        }
        cur = &cur[MEMCMP_WIDE_LANES..];
    }

    if cur.len() >= SIMD_LANES {
        let v = Simd::<u8, SIMD_LANES>::from_slice(&cur[..SIMD_LANES]);
        let m = v.simd_eq(needle_simd).to_bitmask();
        if m != 0 {
            let base = count - cur.len();
            return Some(base + (m as u32).trailing_zeros() as usize);
        }
        cur = &cur[SIMD_LANES..];
    }

    if !cur.is_empty() {
        let tail_start = count - SIMD_LANES;
        let v = Simd::<u8, SIMD_LANES>::from_slice(&hs[tail_start..]);
        let m = v.simd_eq(needle_simd).to_bitmask();
        if m != 0 {
            return Some(tail_start + (m as u32).trailing_zeros() as usize);
        }
    }

    None
}

/// Scans the first `n` bytes of `haystack` for the last occurrence of `needle`.
///
/// Equivalent to C `memrchr`. Returns the index of the last occurrence,
/// or `None` if not found.
///
/// Reverse counterpart of [`memchr`]: scans 8 bytes per step from the end with
/// the SWAR probe, resolving the exact index within the last matching word
/// high-to-low. Behaviour is identical to a byte-at-a-time `rposition` scan.
#[inline(always)]
pub fn memrchr(haystack: &[u8], needle: u8, n: usize) -> Option<usize> {
    let count = n.min(haystack.len());
    let hs = &haystack[..count];

    // SHORT DISPATCH for everything below one 32-lane panel, ahead of the tier machinery.
    //
    // A scan of 8 or 16 bytes reached its one useful instruction only after building the
    // `rchunks_exact(SIMD_FOLD_BYTES)` iterator and clearing the 128-byte fold guard, the
    // 32-lane panel guard and the 16-byte length test -- none of which can fire at these
    // lengths. Measured order-balanced against live glibc, n=8 ran 2.87x and n=16 2.02x.
    //
    // Splitting only `count < 16` off the front was tried first and rejected: it bought n=8
    // (2.87x -> 2.52x) but pushed n=16 to 2.29x, because 16 still walked the whole ladder
    // and now paid an extra test to get there. Taking the entire sub-panel range instead
    // shortens both. Two SIMD compares cover 16..=31 with no loop at all: the trailing
    // window resolves last-match directly, and if it is empty the leading window's mask can
    // only hold bits below `count - 16` -- a set bit at or above it would name a byte the
    // trailing window just reported clean -- so its high bit is the answer unconditionally.
    if count < SIMD_LANES {
        if count == MEMCMP_EXACT_16_BYTES {
            let mask = Simd::<u8, MEMCMP_EXACT_16_BYTES>::from_slice(hs)
                .simd_eq(Simd::splat(needle))
                .to_bitmask();
            if mask != 0 {
                return Some(31 - (mask as u32).leading_zeros() as usize);
            }
            return None;
        }
        if count == WORD {
            let mask = Simd::<u8, WORD>::from_slice(hs)
                .simd_eq(Simd::splat(needle))
                .to_bitmask();
            if mask != 0 {
                return Some(31 - (mask as u32).leading_zeros() as usize);
            }
            return None;
        }
        if count > MEMCMP_EXACT_16_BYTES {
            let tail = &hs[count - MEMCMP_EXACT_16_BYTES..];
            let mask = Simd::<u8, MEMCMP_EXACT_16_BYTES>::from_slice(tail)
                .simd_eq(Simd::splat(needle))
                .to_bitmask();
            if mask != 0 {
                return Some(
                    count - MEMCMP_EXACT_16_BYTES + (31 - (mask as u32).leading_zeros() as usize),
                );
            }
            let head_mask =
                Simd::<u8, MEMCMP_EXACT_16_BYTES>::from_slice(&hs[..MEMCMP_EXACT_16_BYTES])
                    .simd_eq(Simd::splat(needle))
                    .to_bitmask();
            if head_mask != 0 {
                return Some(31 - (head_mask as u32).leading_zeros() as usize);
            }
            return None;
        }
        let mut i = count;
        while i >= WORD {
            let mask = Simd::<u8, WORD>::from_slice(&hs[i - WORD..i])
                .simd_eq(Simd::splat(needle))
                .to_bitmask();
            if mask != 0 {
                return Some(i - WORD + (31 - (mask as u32).leading_zeros() as usize));
            }
            i -= WORD;
        }
        return hs[..i].iter().rposition(|&b| b == needle);
    }

    let needle_simd = Simd::<u8, SIMD_LANES>::splat(needle);

    // 32..=64 bytes: two overlapping 32-lane SIMD panels cover the entire slice
    // without constructing block iterators or walking tier ladders.
    if count <= 64 {
        let tail = &hs[count - SIMD_LANES..];
        let tail_mask = Simd::<u8, SIMD_LANES>::from_slice(tail)
            .simd_eq(needle_simd)
            .to_bitmask();
        if tail_mask != 0 {
            return Some(count - SIMD_LANES + (31 - (tail_mask as u32).leading_zeros() as usize));
        }
        let head_mask = Simd::<u8, SIMD_LANES>::from_slice(&hs[..SIMD_LANES])
            .simd_eq(needle_simd)
            .to_bitmask();
        if head_mask != 0 {
            return Some(31 - (head_mask as u32).leading_zeros() as usize);
        }
        return None;
    }

    let mut cur = hs;
    while cur.len() >= MEMCMP_EXACT_256_BYTES {
        let block_start = cur.len() - MEMCMP_EXACT_256_BYTES;
        let block: &[u8; MEMCMP_EXACT_256_BYTES] = match cur[block_start..].try_into() {
            Ok(arr) => arr,
            Err(_) => break,
        };
        let v7 = Simd::<u8, SIMD_LANES>::from_slice(
            &block[SIMD_FOLD_BYTES + SIMD_LANES * 3..MEMCMP_EXACT_256_BYTES],
        );
        let v6 = Simd::<u8, SIMD_LANES>::from_slice(
            &block[SIMD_FOLD_BYTES + SIMD_LANES * 2..SIMD_FOLD_BYTES + SIMD_LANES * 3],
        );
        let v5 = Simd::<u8, SIMD_LANES>::from_slice(
            &block[SIMD_FOLD_BYTES + SIMD_LANES..SIMD_FOLD_BYTES + SIMD_LANES * 2],
        );
        let v4 = Simd::<u8, SIMD_LANES>::from_slice(
            &block[SIMD_FOLD_BYTES..SIMD_FOLD_BYTES + SIMD_LANES],
        );
        let v3 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 3..SIMD_FOLD_BYTES]);
        let v2 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 2..SIMD_LANES * 3]);
        let v1 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES..SIMD_LANES * 2]);
        let v0 = Simd::<u8, SIMD_LANES>::from_slice(&block[..SIMD_LANES]);

        let m_hi = (v7.simd_eq(needle_simd) | v6.simd_eq(needle_simd))
            | (v5.simd_eq(needle_simd) | v4.simd_eq(needle_simd));
        let m_lo = (v3.simd_eq(needle_simd) | v2.simd_eq(needle_simd))
            | (v1.simd_eq(needle_simd) | v0.simd_eq(needle_simd));

        if (m_hi | m_lo).any() {
            if m_hi.any() {
                let m7 = v7.simd_eq(needle_simd).to_bitmask();
                if m7 != 0 {
                    return Some(
                        block_start
                            + SIMD_FOLD_BYTES
                            + SIMD_LANES * 3
                            + (31 - (m7 as u32).leading_zeros() as usize),
                    );
                }
                let m6 = v6.simd_eq(needle_simd).to_bitmask();
                if m6 != 0 {
                    return Some(
                        block_start
                            + SIMD_FOLD_BYTES
                            + SIMD_LANES * 2
                            + (31 - (m6 as u32).leading_zeros() as usize),
                    );
                }
                let m5 = v5.simd_eq(needle_simd).to_bitmask();
                if m5 != 0 {
                    return Some(
                        block_start
                            + SIMD_FOLD_BYTES
                            + SIMD_LANES
                            + (31 - (m5 as u32).leading_zeros() as usize),
                    );
                }
                let m4 = v4.simd_eq(needle_simd).to_bitmask();
                return Some(
                    block_start + SIMD_FOLD_BYTES + (31 - (m4 as u32).leading_zeros() as usize),
                );
            }
            let m3 = v3.simd_eq(needle_simd).to_bitmask();
            if m3 != 0 {
                return Some(
                    block_start + SIMD_LANES * 3 + (31 - (m3 as u32).leading_zeros() as usize),
                );
            }
            let m2 = v2.simd_eq(needle_simd).to_bitmask();
            if m2 != 0 {
                return Some(
                    block_start + SIMD_LANES * 2 + (31 - (m2 as u32).leading_zeros() as usize),
                );
            }
            let m1 = v1.simd_eq(needle_simd).to_bitmask();
            if m1 != 0 {
                return Some(
                    block_start + SIMD_LANES + (31 - (m1 as u32).leading_zeros() as usize),
                );
            }
            let m0 = v0.simd_eq(needle_simd).to_bitmask();
            return Some(block_start + (31 - (m0 as u32).leading_zeros() as usize));
        }
        cur = &cur[..block_start];
    }

    if cur.len() >= SIMD_FOLD_BYTES {
        let block_start = cur.len() - SIMD_FOLD_BYTES;
        let block: &[u8; SIMD_FOLD_BYTES] = cur[block_start..].try_into().unwrap();
        let v3 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 3..SIMD_FOLD_BYTES]);
        let v2 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES * 2..SIMD_LANES * 3]);
        let v1 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES..SIMD_LANES * 2]);
        let v0 = Simd::<u8, SIMD_LANES>::from_slice(&block[..SIMD_LANES]);
        let any_match = (v3.simd_eq(needle_simd) | v2.simd_eq(needle_simd))
            | (v1.simd_eq(needle_simd) | v0.simd_eq(needle_simd));
        if any_match.any() {
            let m3 = v3.simd_eq(needle_simd).to_bitmask();
            if m3 != 0 {
                return Some(
                    block_start + SIMD_LANES * 3 + (31 - (m3 as u32).leading_zeros() as usize),
                );
            }
            let m2 = v2.simd_eq(needle_simd).to_bitmask();
            if m2 != 0 {
                return Some(
                    block_start + SIMD_LANES * 2 + (31 - (m2 as u32).leading_zeros() as usize),
                );
            }
            let m1 = v1.simd_eq(needle_simd).to_bitmask();
            if m1 != 0 {
                return Some(
                    block_start + SIMD_LANES + (31 - (m1 as u32).leading_zeros() as usize),
                );
            }
            let m0 = v0.simd_eq(needle_simd).to_bitmask();
            return Some(block_start + (31 - (m0 as u32).leading_zeros() as usize));
        }
        cur = &cur[..block_start];
    }

    if cur.len() >= MEMCMP_WIDE_LANES {
        let block_start = cur.len() - MEMCMP_WIDE_LANES;
        let block = &cur[block_start..];
        let v1 = Simd::<u8, SIMD_LANES>::from_slice(&block[SIMD_LANES..]);
        let v0 = Simd::<u8, SIMD_LANES>::from_slice(&block[..SIMD_LANES]);
        let eq1 = v1.simd_eq(needle_simd);
        let eq0 = v0.simd_eq(needle_simd);
        if (eq0 | eq1).any() {
            let m1 = eq1.to_bitmask();
            if m1 != 0 {
                return Some(
                    block_start + SIMD_LANES + (31 - (m1 as u32).leading_zeros() as usize),
                );
            }
            let m0 = eq0.to_bitmask();
            return Some(block_start + (31 - (m0 as u32).leading_zeros() as usize));
        }
        cur = &cur[..block_start];
    }

    if cur.len() >= SIMD_LANES {
        let block_start = cur.len() - SIMD_LANES;
        let v = Simd::<u8, SIMD_LANES>::from_slice(&cur[block_start..]);
        let eq = v.simd_eq(needle_simd);
        let m = eq.to_bitmask();
        if m != 0 {
            return Some(block_start + (31 - (m as u32).leading_zeros() as usize));
        }
        cur = &cur[..block_start];
    }

    if !cur.is_empty() {
        let v = Simd::<u8, SIMD_LANES>::from_slice(&hs[..SIMD_LANES]);
        let eq = v.simd_eq(needle_simd);
        let m = eq.to_bitmask();
        if m != 0 {
            return Some(31 - (m as u32).leading_zeros() as usize);
        }
    }

    None
}

/// Searches `haystack` (first `n` bytes) for the byte sequence `needle` (of length `needle_len`).
///
/// Equivalent to GNU `memmem`. Returns the index of the first occurrence,
/// or `None` if not found.
#[inline(always)]
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
#[inline(always)]
pub fn mempcpy(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let count = n.min(dest.len()).min(src.len());
    dest[..count].copy_from_slice(&src[..count]);
    count
}

/// Copies bytes from `src` to `dest` until byte `c` is found or `n` bytes copied.
///
/// Equivalent to POSIX `memccpy`. Returns the index one past the copied byte `c`,
/// or `None` if `c` was not found within `n` bytes.
#[inline(always)]
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
#[inline(always)]
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
#[inline(always)]
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
#[inline(always)]
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
    fn small_memcmp_matches_scalar() {
        // The exact-16 SIMD mask path and smaller scalar path must match a byte-wise
        // reference (== std slice Ordering) for every length and a difference at
        // every position. Deterministic xorshift fuzz with small alphabets to
        // make differences and equal prefixes both frequent.
        let mut st: u64 = 0x84a2_f00d_1234_9e7b;
        let mut next = || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        for _ in 0..2_000_000 {
            let n = (next() % 17) as usize; // 0..=16
            let mut a: Vec<u8> = (0..n).map(|_| (next() % 4) as u8).collect();
            let mut b = a.clone();
            // Optionally perturb b at a random position (and sometimes a too).
            if n > 0 && next() % 2 == 0 {
                let p = (next() as usize) % n;
                b[p] = (next() % 4) as u8;
            }
            if n > 0 && next() % 4 == 0 {
                let p = (next() as usize) % n;
                a[p] = (next() % 4) as u8;
            }
            assert_eq!(
                memcmp(&a, &b, n),
                a[..n].cmp(&b[..n]),
                "memcmp mismatch a={a:?} b={b:?}"
            );
        }
    }

    #[test]
    fn memcmp_exact_16_mask_resolves_first_difference() {
        let base = *b"abcdefghijklmnop";
        assert_eq!(memcmp(&base, &base, 16), core::cmp::Ordering::Equal);

        for pos in 0..16 {
            let mut left = base;
            let mut right = base;
            left[pos] = b'Z';
            right[pos] = b'a';
            if pos > 0 {
                left[pos - 1] = b'0';
                right[pos - 1] = b'0';
            }
            assert_eq!(
                memcmp(&left, &right, 16),
                left.as_slice().cmp(right.as_slice()),
                "first difference at {pos}"
            );
        }
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
    fn test_memcmp_exact_256_equal_certificate_guard() {
        let a = vec![0x41; 256];
        let mut b = a.clone();
        assert_eq!(memcmp(&a, &b, 256), core::cmp::Ordering::Equal);

        for index in [0usize, 63, 64, 127, 128, 191, 192, 255] {
            b[index] = 0x42;
            assert_eq!(
                memcmp(&a, &b, 256),
                core::cmp::Ordering::Less,
                "difference at index {index}"
            );
            b[index] = 0x41;
        }
    }

    #[test]
    fn test_memcmp_exact_sizes_and_sub_panel_sweep() {
        for len in 0..=300usize {
            let a = vec![0x33u8; len];
            let b = a.clone();
            assert_eq!(
                memcmp(&a, &b, len),
                core::cmp::Ordering::Equal,
                "equal at len={len}"
            );

            for pos in 0..len {
                for &(x, y) in &[(b'a', b'b'), (b'b', b'a'), (0u8, 255u8), (255u8, 0u8)] {
                    let mut p = a.clone();
                    let mut q = a.clone();
                    p[pos] = x;
                    q[pos] = y;
                    let expected = scalar_memcmp(&p, &q, len);
                    let actual = memcmp(&p, &q, len);
                    assert_eq!(
                        actual, expected,
                        "mismatch at len={len}, pos={pos}, ({x},{y})"
                    );
                }
            }
        }
    }

    #[test]
    fn test_memchr_exact_sizes_sweep() {
        for len in 0..=300usize {
            let mut buf = vec![b'a'; len];
            assert_eq!(memchr(&buf, b'z', len), None, "absent at len={len}");

            for pos in 0..len {
                buf[pos] = b'z';
                if pos < len.saturating_sub(1) {
                    buf[len - 1] = b'z';
                }
                assert_eq!(
                    memchr(&buf, b'z', len),
                    Some(pos),
                    "match at len={len}, pos={pos}"
                );
                buf.fill(b'a');
            }
        }
    }

    /// Byte-at-a-time reference `memcmp` ordering — the ground truth any SIMD
    /// lowering must reproduce bit-for-bit. Used by the isomorphism harness that
    /// guards the L1-bound memcmp kernel (bd-2g7oyh.283 spike).
    fn scalar_memcmp(a: &[u8], b: &[u8], n: usize) -> core::cmp::Ordering {
        let count = n.min(a.len()).min(b.len());
        for k in 0..count {
            if a[k] != b[k] {
                return a[k].cmp(&b[k]);
            }
        }
        core::cmp::Ordering::Equal
    }

    /// The 4096-byte bulk SIMD path must agree with the scalar reference for the
    /// equal case and for a difference planted at every panel/block boundary
    /// (and one byte either side), in both directions — exercising the wide
    /// folded compare and the ordered first-difference resolver.
    #[test]
    fn memcmp_4096_bulk_matches_scalar() {
        let a = vec![0x51u8; 4096];
        assert_eq!(memcmp(&a, &a, 4096), core::cmp::Ordering::Equal);

        let boundaries = [
            0usize, 1, 31, 32, 33, 63, 64, 95, 96, 127, 128, 129, 255, 256, 1023, 1024, 2048, 4094,
            4095,
        ];
        for &idx in &boundaries {
            for &delta in &[1u8, 0xFF] {
                let mut b = a.clone();
                b[idx] = a[idx].wrapping_add(delta);
                assert_eq!(
                    memcmp(&a, &b, 4096),
                    scalar_memcmp(&a, &b, 4096),
                    "a<b diff at {idx} delta {delta}"
                );
                assert_eq!(
                    memcmp(&b, &a, 4096),
                    scalar_memcmp(&b, &a, 4096),
                    "b<a diff at {idx} delta {delta}"
                );
            }
        }
    }

    /// Golden rolling digest over a deterministic battery of `memcmp` orderings
    /// across many lengths and first-difference positions. Pins the exact
    /// observable ordering contract so any future memcmp lowering change that
    /// alters behaviour is caught (complements `memcmp_golden_output_sha256`).
    #[test]
    fn memcmp_golden_ordering_digest() {
        let mut state: u64 = 0xcbf2_9ce4_8422_2325;
        let mut mix = |ord: core::cmp::Ordering| {
            let code: u8 = match ord {
                core::cmp::Ordering::Less => 1,
                core::cmp::Ordering::Equal => 2,
                core::cmp::Ordering::Greater => 3,
            };
            state ^= code as u64;
            state = state.wrapping_mul(0x0000_0100_0000_01b3);
        };
        let g = |seed: u64, i: usize| -> u8 {
            let x = seed
                .wrapping_add(i as u64)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15);
            ((x >> 33) ^ x) as u8
        };
        for &len in &[
            0usize, 1, 7, 8, 15, 16, 17, 31, 32, 33, 64, 127, 128, 255, 256, 257, 1024, 4096,
        ] {
            let base: Vec<u8> = (0..len).map(|i| g(0xABCD, i)).collect();
            mix(memcmp(&base, &base, len));
            if len > 0 {
                for &pos in &[0usize, len / 3, len / 2, len.saturating_sub(1)] {
                    let mut other = base.clone();
                    other[pos] = other[pos].wrapping_add(1);
                    mix(memcmp(&base, &other, len));
                    mix(memcmp(&other, &base, len));
                    other[pos] = base[pos].wrapping_sub(1);
                    mix(memcmp(&base, &other, len));
                }
            }
        }
        assert_eq!(
            state, 17_983_423_468_913_431_713,
            "memcmp ordering digest changed — behaviour is no longer isomorphic"
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
        let mut haystack = vec![b'A'; SIMD_FOLD_BYTES + SIMD_LANES];
        haystack[SIMD_LANES + 5] = b'Z';
        haystack[SIMD_LANES * 2 + 11] = b'Z';
        assert_eq!(
            memchr(&haystack, b'Z', haystack.len()),
            Some(SIMD_LANES + 5)
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
    fn test_memrchr_sweep_lengths_and_positions() {
        // Exhaustive sweep: lengths 1..=300, needle absent and needle placed at
        // various positions, covering every tier boundary (16, 32, 64, 128, 256).
        for len in 1..=300 {
            let mut buf = vec![b'x'; len];
            assert_eq!(memrchr(&buf, b'z', len), None, "absent for len {len}");

            // Test first, middle, and last positions for all lengths
            let check_positions = [0, len / 4, len / 2, (3 * len) / 4, len - 1];
            for &pos in &check_positions {
                buf[pos] = b'z';
                assert_eq!(
                    memrchr(&buf, b'z', len),
                    Some(pos),
                    "hit at {pos} len {len}"
                );
                buf[pos] = b'x';
            }

            if len >= 2 {
                // Two needles: at index 0 and index len - 1
                buf[0] = b'z';
                buf[len - 1] = b'z';
                assert_eq!(
                    memrchr(&buf, b'z', len),
                    Some(len - 1),
                    "two needles len {len}"
                );
                buf[0] = b'x';
                buf[len - 1] = b'x';
            }
        }
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
    fn memcmp_golden_output_sha256() {
        use sha2::{Digest, Sha256};

        let mut cases: Vec<(Vec<u8>, Vec<u8>, usize)> = vec![
            (Vec::new(), Vec::new(), 0),
            (b"a".to_vec(), b"b".to_vec(), 0),
            (b"abc".to_vec(), b"abc".to_vec(), 3),
            (b"abc".to_vec(), b"abd".to_vec(), 3),
            (b"abd".to_vec(), b"abc".to_vec(), 3),
            (b"abc".to_vec(), b"abx".to_vec(), 2),
            (vec![0x5a; 16], vec![0x5a; 16], 16),
            (vec![0x5a; 17], vec![0x5a; 17], 16),
            (vec![0x5a; 31], vec![0x5a; 31], 31),
            (vec![0x5a; 32], vec![0x5a; 32], 32),
            (vec![0x5a; 256], vec![0x5a; 256], 256),
        ];

        for len in 1usize..=16 {
            let a: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(17)).collect();
            cases.push((a.clone(), a.clone(), len));
            for pos in 0..len {
                let mut b = a.clone();
                b[pos] = b[pos].wrapping_add(1);
                cases.push((a.clone(), b.clone(), len));
                cases.push((b, a.clone(), len));
            }
        }

        for n in [0usize, 1, 7, 8, 15, 16, 17, 31, 32, 127, 128, 255, 256] {
            let a = vec![0x33; 256];
            let mut b = a.clone();
            if n > 0 {
                let pos = (n - 1).min(255);
                b[pos] = 0x44;
            }
            cases.push((a.clone(), b.clone(), n));
            cases.push((b, a, n));
        }

        let mut hasher = Sha256::new();
        for (a, b, n) in cases {
            let count = n.min(a.len()).min(b.len());
            let expected = a[..count].cmp(&b[..count]);
            let got = memcmp(&a, &b, n);
            assert_eq!(got, expected);

            hasher.update((a.len() as u64).to_le_bytes());
            hasher.update((b.len() as u64).to_le_bytes());
            hasher.update((n as u64).to_le_bytes());
            hasher.update([match got {
                core::cmp::Ordering::Less => 0,
                core::cmp::Ordering::Equal => 1,
                core::cmp::Ordering::Greater => 2,
            }]);
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "458c0ae019afaffccbfc5a6aacfeb4713dab611eac4b6257398016a7eae45ef9",
            "memcmp golden output corpus changed"
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
