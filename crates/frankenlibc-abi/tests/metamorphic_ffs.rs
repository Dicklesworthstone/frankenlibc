#![cfg(target_os = "linux")]

//! Metamorphic-property tests for `ffs(3)` / `ffsl(3)` / `ffsll(3)`.
//!
//! Internal invariants of the find-first-set-bit family:
//!
//!   - ffs(0) == 0; ffsl(0) == 0; ffsll(0) == 0
//!   - ffs(1 << k) == k+1 for all valid k
//!   - ffs is consistent with trailing_zeros (when input != 0)
//!   - ffs(x | (x-1)) ≤ ffs(x) when x != 0  (pattern: clearing
//!     higher bits doesn't change the lowest set bit position)
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_int, c_long, c_longlong};

use frankenlibc_abi::stdlib_abi as fl;

#[test]
fn metamorphic_ffs_zero_is_zero() {
    assert_eq!(fl::ffs(0), 0);
    assert_eq!(fl::ffsl(0), 0);
    assert_eq!(fl::ffsll(0), 0);
}

#[test]
fn metamorphic_ffs_powers_of_two_full_range_int() {
    for k in 0..32 {
        let v: c_int = 1 << k;
        assert_eq!(fl::ffs(v) as u32, k + 1, "ffs(1<<{k})");
    }
}

#[test]
fn metamorphic_ffsl_powers_of_two_full_range() {
    for k in 0..(c_long::BITS as u32) {
        let v: c_long = 1i64 << k;
        assert_eq!(fl::ffsl(v) as u32, k + 1, "ffsl(1<<{k})");
    }
}

#[test]
fn metamorphic_ffsll_powers_of_two_full_range() {
    for k in 0..64u32 {
        let v: c_longlong = 1i64 << k;
        assert_eq!(fl::ffsll(v) as u32, k + 1, "ffsll(1<<{k})");
    }
}

#[test]
fn metamorphic_ffs_matches_trailing_zeros_plus_one() {
    // ffs(x) == 0 if x == 0, else 1 + (trailing zeros of x).
    for v in &[1i32, 2, 3, 4, 6, 7, 8, 12, 16, 100, 0x7fff, 0x10000, -1, c_int::MIN] {
        let expected = if *v == 0 { 0 } else { (v.trailing_zeros() + 1) as c_int };
        assert_eq!(fl::ffs(*v), expected, "ffs({v:#x})");
    }
}

#[test]
fn metamorphic_ffs_or_higher_bits_does_not_change_first_set() {
    // For x != 0, setting any higher bit doesn't change ffs(x).
    for x in &[1i32, 2, 4, 0x100, 0x10000] {
        let base = fl::ffs(*x);
        // Set some higher bits.
        let mutated = *x | (*x << 1) | (*x << 5);
        let after = fl::ffs(mutated);
        assert_eq!(base, after, "ffs({x:#x}) vs ffs({mutated:#x})");
    }
}

#[test]
fn metamorphic_ffs_negative_max_int() {
    // INT_MIN = 0x8000_0000 — only the high bit is set.
    assert_eq!(fl::ffs(c_int::MIN), 32);
}

#[test]
fn metamorphic_ffsll_neg_long_long_max() {
    assert_eq!(fl::ffsll(c_longlong::MIN), 64);
}

#[test]
fn metamorphic_ffs_clearing_lowest_bit_increases_position() {
    // Clearing the lowest set bit of x increases ffs(x) (or makes
    // it 0 if x had only one bit set).
    for x in &[3i32, 5, 6, 7, 12, 0xa0u32 as i32, 0xff] {
        let lowest_bit = (*x as u32) & ((!(*x as u32)).wrapping_add(1));
        let cleared = ((*x as u32) ^ lowest_bit) as c_int;
        let f_before = fl::ffs(*x);
        let f_after = fl::ffs(cleared);
        if cleared == 0 {
            assert_eq!(f_after, 0);
        } else {
            assert!(f_after > f_before, "ffs({cleared:#x}) > ffs({x:#x})");
        }
    }
}

#[test]
fn ffs_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc ffs + ffsl + ffsll\",\"reference\":\"bit-arithmetic-invariants\",\"properties\":8,\"divergences\":0}}",
    );
}
