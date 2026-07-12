#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc C23 stdbit oracle (glibc >= 2.39)

//! Differential gate for the C23 stdbit complement/zero functions vs host glibc
//! 2.42 (bd-kcrt1e). The earlier stdbit gates covered the count-ones / leading-
//! zeros family; these six are DISTINCT functions with their own logic and were
//! differentially uncovered: count_zeros, leading_ones, trailing_ones,
//! first_leading_zero, first_trailing_one, first_trailing_zero. The first_*
//! functions are 1-indexed and return 0 when the searched bit is absent — an
//! easy off-by-one / wrong-sentinel locus. Exact comparison over edge inputs.
//! Verified glibc exports these symbols. No mocks.

use std::ffi::c_uint;

unsafe extern "C" {
    fn stdc_count_zeros_ui(v: c_uint) -> c_uint;
    fn stdc_leading_ones_ui(v: c_uint) -> c_uint;
    fn stdc_trailing_ones_ui(v: c_uint) -> c_uint;
    fn stdc_first_leading_zero_ui(v: c_uint) -> c_uint;
    fn stdc_first_trailing_one_ui(v: c_uint) -> c_uint;
    fn stdc_first_trailing_zero_ui(v: c_uint) -> c_uint;
}

const CASES: &[c_uint] = &[
    0,
    1,
    2,
    3,
    0xFF,
    0xFF00_0000, // leading ones
    0x0000_00FF, // trailing ones
    0x7FFF_FFFF, // MSB zero -> first_leading_zero=1
    0x8000_0000,
    0xFFFF_FFFF, // all ones: count_zeros=0, first_*_zero=0
    0xFFFF_FFFE, // trailing zero at bit 0
    0xDEAD_BEEF,
    0x5555_5555,
    0xAAAA_AAAA,
    0x0000_0008, // first_trailing_one=4
];

#[test]
fn stdbit_complement_ui_match_glibc() {
    use frankenlibc_abi::stdbit_abi as s;
    for &v in CASES {
        assert_eq!(
            s::stdc_count_zeros_ui(v),
            unsafe { stdc_count_zeros_ui(v) },
            "count_zeros({v:#x})"
        );
        assert_eq!(
            s::stdc_leading_ones_ui(v),
            unsafe { stdc_leading_ones_ui(v) },
            "leading_ones({v:#x})"
        );
        assert_eq!(
            s::stdc_trailing_ones_ui(v),
            unsafe { stdc_trailing_ones_ui(v) },
            "trailing_ones({v:#x})"
        );
        assert_eq!(
            s::stdc_first_leading_zero_ui(v),
            unsafe { stdc_first_leading_zero_ui(v) },
            "first_leading_zero({v:#x})"
        );
        assert_eq!(
            s::stdc_first_trailing_one_ui(v),
            unsafe { stdc_first_trailing_one_ui(v) },
            "first_trailing_one({v:#x})"
        );
        assert_eq!(
            s::stdc_first_trailing_zero_ui(v),
            unsafe { stdc_first_trailing_zero_ui(v) },
            "first_trailing_zero({v:#x})"
        );
    }
}
