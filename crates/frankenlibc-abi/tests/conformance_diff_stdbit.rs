#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc C23 stdbit oracle (glibc >= 2.39)

//! Differential gate for the C23 stdbit _ui functions vs host glibc 2.42
//! (bd-94wnpb). These were exercised only by an fl-internal test (asserting
//! fl's own expected values), which cannot catch a spec MISUNDERSTANDING — an
//! impl and self-test that are wrong-but-consistent. Comparing against the
//! glibc reference does. Covers the bit-count / bit-width / bit-floor-ceil /
//! first-one / single-bit functions over edge inputs (0, 1, all-ones, high
//! bit, boundaries). Exact unsigned comparison. No mocks.

use std::ffi::c_uint;

unsafe extern "C" {
    fn stdc_leading_zeros_ui(v: c_uint) -> c_uint;
    fn stdc_trailing_zeros_ui(v: c_uint) -> c_uint;
    fn stdc_count_ones_ui(v: c_uint) -> c_uint;
    fn stdc_first_leading_one_ui(v: c_uint) -> c_uint;
    fn stdc_bit_width_ui(v: c_uint) -> c_uint;
    fn stdc_bit_floor_ui(v: c_uint) -> c_uint;
    fn stdc_bit_ceil_ui(v: c_uint) -> c_uint;
    fn stdc_has_single_bit_ui(v: c_uint) -> bool;
}

const CASES: &[c_uint] = &[
    0,
    1,
    2,
    3,
    7,
    8,
    0xFF,
    0x100,
    0x7FFF_FFFF,
    0x8000_0000,
    0xFFFF_FFFF,
    0x0001_0000,
    0xDEAD_BEEF,
    0x5555_5555,
    0xAAAA_AAAA,
    0x4000_0000,
];

#[test]
fn stdbit_ui_match_glibc() {
    use frankenlibc_abi::stdbit_abi as s;
    for &v in CASES {
        assert_eq!(s::stdc_leading_zeros_ui(v), unsafe { stdc_leading_zeros_ui(v) }, "leading_zeros({v:#x})");
        assert_eq!(s::stdc_trailing_zeros_ui(v), unsafe { stdc_trailing_zeros_ui(v) }, "trailing_zeros({v:#x})");
        assert_eq!(s::stdc_count_ones_ui(v), unsafe { stdc_count_ones_ui(v) }, "count_ones({v:#x})");
        assert_eq!(s::stdc_first_leading_one_ui(v), unsafe { stdc_first_leading_one_ui(v) }, "first_leading_one({v:#x})");
        assert_eq!(s::stdc_bit_width_ui(v), unsafe { stdc_bit_width_ui(v) }, "bit_width({v:#x})");
        assert_eq!(s::stdc_bit_floor_ui(v), unsafe { stdc_bit_floor_ui(v) }, "bit_floor({v:#x})");
        assert_eq!(s::stdc_bit_ceil_ui(v), unsafe { stdc_bit_ceil_ui(v) }, "bit_ceil({v:#x})");
        assert_eq!(s::stdc_has_single_bit_ui(v), unsafe { stdc_has_single_bit_ui(v) }, "has_single_bit({v:#x})");
    }
}
