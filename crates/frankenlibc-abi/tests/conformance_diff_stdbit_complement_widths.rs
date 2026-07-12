#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc C23 stdbit oracle (glibc >= 2.39)

//! Differential gate for the C23 stdbit complement/zero functions across the
//! 8/16/64-bit width paths vs host glibc 2.42 (bd-1bq3x3). bd-kcrt1e gated the
//! 32-bit (_ui) complement fns; this completes the narrow (_uc/_us) and 64-bit
//! (_ull) width paths, each carrying its own width constant (count_zeros_ull(0)
//! must be 64, count_zeros_uc(0) must be 8, leading_ones_us over 16 bits). All
//! six fns return unsigned int regardless of input width. Exact comparison.
//! Verified all 18 symbols exist in fl + glibc. No mocks.

use std::ffi::{c_uchar, c_uint, c_ulonglong, c_ushort};

unsafe extern "C" {
    fn stdc_count_zeros_uc(v: c_uchar) -> c_uint;
    fn stdc_leading_ones_uc(v: c_uchar) -> c_uint;
    fn stdc_trailing_ones_uc(v: c_uchar) -> c_uint;
    fn stdc_first_leading_zero_uc(v: c_uchar) -> c_uint;
    fn stdc_first_trailing_one_uc(v: c_uchar) -> c_uint;
    fn stdc_first_trailing_zero_uc(v: c_uchar) -> c_uint;

    fn stdc_count_zeros_us(v: c_ushort) -> c_uint;
    fn stdc_leading_ones_us(v: c_ushort) -> c_uint;
    fn stdc_trailing_ones_us(v: c_ushort) -> c_uint;
    fn stdc_first_leading_zero_us(v: c_ushort) -> c_uint;
    fn stdc_first_trailing_one_us(v: c_ushort) -> c_uint;
    fn stdc_first_trailing_zero_us(v: c_ushort) -> c_uint;

    fn stdc_count_zeros_ull(v: c_ulonglong) -> c_uint;
    fn stdc_leading_ones_ull(v: c_ulonglong) -> c_uint;
    fn stdc_trailing_ones_ull(v: c_ulonglong) -> c_uint;
    fn stdc_first_leading_zero_ull(v: c_ulonglong) -> c_uint;
    fn stdc_first_trailing_one_ull(v: c_ulonglong) -> c_uint;
    fn stdc_first_trailing_zero_ull(v: c_ulonglong) -> c_uint;
}

const UC: &[c_uchar] = &[0, 0x01, 0x0F, 0x80, 0x7F, 0xF0, 0xFE, 0xFF];
const US: &[c_ushort] = &[0, 0x0001, 0x00FF, 0xFF00, 0x8000, 0x7FFF, 0xFFFE, 0xFFFF];
const ULL: &[c_ulonglong] = &[
    0,
    1,
    0xFF,
    0x1_0000_0000,
    0x8000_0000_0000_0000,
    0x7FFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
];

#[test]
fn stdbit_complement_uc_match_glibc() {
    use frankenlibc_abi::stdbit_abi as s;
    for &v in UC {
        assert_eq!(
            s::stdc_count_zeros_uc(v),
            unsafe { stdc_count_zeros_uc(v) },
            "count_zeros_uc({v:#x})"
        );
        assert_eq!(
            s::stdc_leading_ones_uc(v),
            unsafe { stdc_leading_ones_uc(v) },
            "leading_ones_uc({v:#x})"
        );
        assert_eq!(
            s::stdc_trailing_ones_uc(v),
            unsafe { stdc_trailing_ones_uc(v) },
            "trailing_ones_uc({v:#x})"
        );
        assert_eq!(
            s::stdc_first_leading_zero_uc(v),
            unsafe { stdc_first_leading_zero_uc(v) },
            "first_leading_zero_uc({v:#x})"
        );
        assert_eq!(
            s::stdc_first_trailing_one_uc(v),
            unsafe { stdc_first_trailing_one_uc(v) },
            "first_trailing_one_uc({v:#x})"
        );
        assert_eq!(
            s::stdc_first_trailing_zero_uc(v),
            unsafe { stdc_first_trailing_zero_uc(v) },
            "first_trailing_zero_uc({v:#x})"
        );
    }
}

#[test]
fn stdbit_complement_us_match_glibc() {
    use frankenlibc_abi::stdbit_abi as s;
    for &v in US {
        assert_eq!(
            s::stdc_count_zeros_us(v),
            unsafe { stdc_count_zeros_us(v) },
            "count_zeros_us({v:#x})"
        );
        assert_eq!(
            s::stdc_leading_ones_us(v),
            unsafe { stdc_leading_ones_us(v) },
            "leading_ones_us({v:#x})"
        );
        assert_eq!(
            s::stdc_trailing_ones_us(v),
            unsafe { stdc_trailing_ones_us(v) },
            "trailing_ones_us({v:#x})"
        );
        assert_eq!(
            s::stdc_first_leading_zero_us(v),
            unsafe { stdc_first_leading_zero_us(v) },
            "first_leading_zero_us({v:#x})"
        );
        assert_eq!(
            s::stdc_first_trailing_one_us(v),
            unsafe { stdc_first_trailing_one_us(v) },
            "first_trailing_one_us({v:#x})"
        );
        assert_eq!(
            s::stdc_first_trailing_zero_us(v),
            unsafe { stdc_first_trailing_zero_us(v) },
            "first_trailing_zero_us({v:#x})"
        );
    }
}

#[test]
fn stdbit_complement_ull_match_glibc() {
    use frankenlibc_abi::stdbit_abi as s;
    for &v in ULL {
        assert_eq!(
            s::stdc_count_zeros_ull(v),
            unsafe { stdc_count_zeros_ull(v) },
            "count_zeros_ull({v:#018x})"
        );
        assert_eq!(
            s::stdc_leading_ones_ull(v),
            unsafe { stdc_leading_ones_ull(v) },
            "leading_ones_ull({v:#018x})"
        );
        assert_eq!(
            s::stdc_trailing_ones_ull(v),
            unsafe { stdc_trailing_ones_ull(v) },
            "trailing_ones_ull({v:#018x})"
        );
        assert_eq!(
            s::stdc_first_leading_zero_ull(v),
            unsafe { stdc_first_leading_zero_ull(v) },
            "first_leading_zero_ull({v:#018x})"
        );
        assert_eq!(
            s::stdc_first_trailing_one_ull(v),
            unsafe { stdc_first_trailing_one_ull(v) },
            "first_trailing_one_ull({v:#018x})"
        );
        assert_eq!(
            s::stdc_first_trailing_zero_ull(v),
            unsafe { stdc_first_trailing_zero_ull(v) },
            "first_trailing_zero_ull({v:#018x})"
        );
    }
}
