//! Constant-time byte comparison helpers.
//!
//! Pure-safe Rust port of the OpenBSD `timingsafe_bcmp` and
//! `timingsafe_memcmp` primitives (now also exposed by glibc 2.39+).
//! These functions defeat timing side-channel attacks on cryptographic
//! material such as HMAC tags, session tokens, or password hashes by
//! always touching every byte of both inputs and avoiding any data-
//! dependent branches.
//!
//! ## Semantics
//!
//! * [`bcmp`] returns `0` if the two slices are equal byte-for-byte
//!   over the requested length, and a non-zero value otherwise. The
//!   exact non-zero value is unspecified (matching OpenBSD), but is
//!   computed as the bitwise OR of every per-byte XOR so that no
//!   information about *which* bytes differ leaks via the return.
//! * [`memcmp`] additionally returns the sign of the first byte that
//!   differs, in `(b1 - b2)` order, matching the standard `memcmp`
//!   convention. Despite the value being position-dependent, the
//!   number of CPU operations performed is independent of the input
//!   contents.
//!
//! Both functions accept slices whose length is at least `n`; the
//! callers in `frankenlibc-abi` are responsible for slicing the raw
//! pointer ranges into safe references first.

/// Constant-time byte equality test.
///
/// Returns `0` iff the first `n` bytes of `a` and `b` are identical,
/// non-zero otherwise. Always touches all `n` bytes regardless of
/// where (or whether) the inputs differ.
///
/// `n` is clamped to `min(a.len(), b.len())` defensively. Callers
/// must ensure both slices already span at least `n` bytes if a
/// strict OpenBSD-equivalent contract is desired.
pub fn bcmp(a: &[u8], b: &[u8], n: usize) -> i32 {
    let count = n.min(a.len()).min(b.len());
    let mut acc: u8 = 0;
    let mut i = 0usize;
    while i < count {
        acc |= a[i] ^ b[i];
        i += 1;
    }
    // Fold the 8-bit accumulator into a deterministic non-zero return
    // when any byte differed. Use the OpenBSD trick: ((acc - 1) >> 8) - 1
    // performed in u32 land. Equivalent to `if acc == 0 { 0 } else { 1 }`
    // but written branchlessly so that callers (including JITs) can't
    // reintroduce a timing leak. Result is normalized to {0, 1}.
    let widened = acc as u32;
    // (widened | widened.wrapping_neg()) >> 31 is 0 iff widened == 0,
    // 1 otherwise. Casts through i32 are safe since the value is in
    // {0, 1}.
    ((widened | widened.wrapping_neg()) >> 31) as i32
}

/// Constant-time, sign-preserving byte comparison.
///
/// Returns `0` iff the first `n` bytes of `b1` and `b2` are equal,
/// a negative value if the first differing byte in `b1` is less than
/// the corresponding byte in `b2`, and a positive value otherwise —
/// matching the standard `memcmp` convention. The number of CPU
/// operations is independent of the input contents.
///
/// `n` is clamped to `min(b1.len(), b2.len())` defensively.
pub fn memcmp(b1: &[u8], b2: &[u8], n: usize) -> i32 {
    let count = n.min(b1.len()).min(b2.len());
    // Track the first differing pair (high byte = b1, low byte = b2)
    // using a constant-time fold. `done` flips from 0 to !0 once the
    // first difference is observed and pins the captured pair from
    // then on; subsequent bytes still execute the same operations
    // but their values are masked away.
    let mut hi: u32 = 0;
    let mut lo: u32 = 0;
    let mut done: u32 = 0;
    let mut i = 0usize;
    while i < count {
        let av = b1[i] as u32;
        let bv = b2[i] as u32;
        let diff = av ^ bv;
        // mask = 0xffff_ffff iff this byte differs AND no earlier
        // byte differed; 0 otherwise. Computed without branches.
        let neq = ct_nonzero_mask(diff);
        let first = neq & !done;
        hi |= av & first;
        lo |= bv & first;
        done |= first;
        i += 1;
    }
    // Sign-preserving fold: (hi as i32) - (lo as i32) yields a value
    // in [-255, 255]; positive means b1 > b2, negative means b1 < b2,
    // zero means the slices are equal over `count` bytes. Done as i32
    // arithmetic to avoid wraparound surprises.
    (hi as i32) - (lo as i32)
}

/// Returns `0xffff_ffff` if `v` is non-zero, `0` otherwise. Branch-
/// and table-free so the result depends only on bit positions, not
/// on the value's magnitude.
#[inline]
fn ct_nonzero_mask(v: u32) -> u32 {
    // (v | -v) >> 31 yields 0 iff v == 0, 1 otherwise.
    // Subtracting 1 from {0, 1} yields {!0, 0} which when negated
    // (via bitwise NOT) gives the desired {0, !0} mask without
    // introducing any data-dependent branch.
    let one_bit = (v | v.wrapping_neg()) >> 31;
    one_bit.wrapping_neg()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- bcmp ----

    #[test]
    fn bcmp_equal_returns_zero() {
        assert_eq!(bcmp(b"hello", b"hello", 5), 0);
    }

    #[test]
    fn bcmp_zero_length_returns_zero_for_anything() {
        assert_eq!(bcmp(b"abc", b"xyz", 0), 0);
        assert_eq!(bcmp(&[], &[], 0), 0);
    }

    #[test]
    fn bcmp_different_first_byte_returns_nonzero() {
        assert_ne!(bcmp(b"abc", b"xbc", 3), 0);
    }

    #[test]
    fn bcmp_different_last_byte_returns_nonzero() {
        assert_ne!(bcmp(b"abc", b"abx", 3), 0);
    }

    #[test]
    fn bcmp_short_input_clamps() {
        // Asking for 100 bytes of 3-byte slices clamps to 3.
        assert_eq!(bcmp(b"abc", b"abc", 100), 0);
        assert_ne!(bcmp(b"abc", b"abx", 100), 0);
    }

    #[test]
    fn bcmp_only_compares_first_n_bytes() {
        // Bytes past `n` differ but should not affect the result.
        assert_eq!(bcmp(b"abcXYZ", b"abcQRS", 3), 0);
    }

    #[test]
    fn bcmp_normalized_return_is_one() {
        // Non-zero return is normalized to exactly 1, never the raw XOR.
        assert_eq!(bcmp(b"\x00\xff", b"\x00\x00", 2), 1);
        assert_eq!(bcmp(b"\xff\xff\xff\xff", b"\x00\x00\x00\x00", 4), 1);
    }

    #[test]
    fn bcmp_all_byte_values() {
        // For every single-byte pair (a, b), result is 0 iff a == b.
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let buf_a = [a];
                let buf_b = [b];
                let r = bcmp(&buf_a, &buf_b, 1);
                if a == b {
                    assert_eq!(r, 0, "bcmp({a:#x},{b:#x}) should be 0");
                } else {
                    assert_eq!(r, 1, "bcmp({a:#x},{b:#x}) should be 1");
                }
            }
        }
    }

    #[test]
    fn bcmp_empty_slices() {
        assert_eq!(bcmp(&[], &[], 5), 0);
    }

    // ---- memcmp ----

    #[test]
    fn memcmp_equal_returns_zero() {
        assert_eq!(memcmp(b"hello", b"hello", 5), 0);
    }

    #[test]
    fn memcmp_zero_length_returns_zero() {
        assert_eq!(memcmp(b"abc", b"xyz", 0), 0);
    }

    #[test]
    fn memcmp_first_less_returns_negative() {
        assert!(memcmp(b"abc", b"xbc", 3) < 0);
    }

    #[test]
    fn memcmp_first_greater_returns_positive() {
        assert!(memcmp(b"xbc", b"abc", 3) > 0);
    }

    #[test]
    fn memcmp_returns_sign_of_first_difference() {
        // The first differing byte at index 3 pins the sign:
        // 'y' (0x79) > '_' (0x5f), so b1 > b2 → positive.
        // The trailing bytes (equal here) and any later differences
        // must not contaminate the sign.
        assert!(memcmp(b"abxyz", b"abx_z", 5) > 0); // y > _
        assert!(memcmp(b"abx_z", b"abxyz", 5) < 0); // _ < y
    }

    #[test]
    fn memcmp_unsigned_byte_comparison() {
        // memcmp treats bytes as unsigned: 0xff > 0x00.
        assert!(memcmp(b"\xff", b"\x00", 1) > 0);
        assert!(memcmp(b"\x00", b"\xff", 1) < 0);
    }

    #[test]
    fn memcmp_short_input_clamps() {
        assert_eq!(memcmp(b"abc", b"abc", 100), 0);
        assert!(memcmp(b"abc", b"abx", 100) < 0);
    }

    #[test]
    fn memcmp_only_compares_first_n_bytes() {
        // Past `n` differ; result should not reflect it.
        assert_eq!(memcmp(b"abcXYZ", b"abcQRS", 3), 0);
    }

    #[test]
    fn memcmp_first_difference_pins_result() {
        // Two differences: byte 1 (b<c) and byte 3 (z>a). Result
        // should reflect only the first one (negative).
        assert!(memcmp(b"abXz", b"acXa", 4) < 0);
    }

    #[test]
    fn memcmp_all_single_byte_pairs_match_std_memcmp() {
        // Cross-check against std slice comparison for every pair.
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let buf_a = [a];
                let buf_b = [b];
                let ours = memcmp(&buf_a, &buf_b, 1);
                let expected = (a as i32) - (b as i32);
                assert_eq!(
                    ours, expected,
                    "memcmp({a:#x},{b:#x}) = {ours} expected {expected}"
                );
            }
        }
    }

    #[test]
    fn memcmp_consistent_with_bcmp_for_equality() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"", b""),
            (b"x", b"x"),
            (b"hello world", b"hello world"),
            (b"\x00\x01\x02", b"\x00\x01\x02"),
            (b"abc", b"abd"),
            (b"abc", b"axc"),
            (b"\xff\x00", b"\x00\xff"),
        ];
        for (a, b) in cases {
            let n = a.len().max(b.len());
            let mc = memcmp(a, b, n);
            let bc = bcmp(a, b, n);
            // bcmp == 0 iff memcmp == 0.
            assert_eq!(
                mc == 0,
                bc == 0,
                "bcmp/memcmp disagree on equality for {a:?} vs {b:?}"
            );
        }
    }

    #[test]
    fn memcmp_empty_slices() {
        assert_eq!(memcmp(&[], &[], 5), 0);
    }

    #[test]
    fn memcmp_full_slice_difference_at_end() {
        // 32-byte slices differing only in the last byte.
        let mut a = [0xaau8; 32];
        let mut b = [0xaau8; 32];
        b[31] = 0xab;
        assert!(memcmp(&a, &b, 32) < 0);
        b[31] = 0xa9;
        assert!(memcmp(&a, &b, 32) > 0);
        // Restore equality.
        b[31] = 0xaa;
        a[0] = 0xaa;
        assert_eq!(memcmp(&a, &b, 32), 0);
    }

    #[test]
    fn ct_nonzero_mask_is_zero_for_zero_only() {
        assert_eq!(ct_nonzero_mask(0), 0);
        for shift in 0..32 {
            assert_eq!(ct_nonzero_mask(1u32 << shift), u32::MAX);
        }
        assert_eq!(ct_nonzero_mask(u32::MAX), u32::MAX);
        assert_eq!(ct_nonzero_mask(0x8000_0000), u32::MAX);
    }
}
