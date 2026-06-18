#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc C23 stdbit oracle (glibc >= 2.39)

//! Differential gate for the 64-bit C23 stdbit functions (_ull) vs host glibc
//! 2.42 (bd-ifrm1v). The _ui gate (bd-94wnpb) covers the 32-bit path; the _ull
//! variants exercise a DISTINCT 64-bit width path where a wrong width constant
//! (e.g. leading_zeros of 0 must be 64 not 32) or a 32-bit truncation would be
//! invisible to the _ui gate. Note the return widths differ: bit_floor/bit_ceil
//! return unsigned long long, the rest return unsigned int. Verified glibc
//! exports these symbols. Exact comparison. No mocks.

use std::ffi::{c_uint, c_ulonglong};

unsafe extern "C" {
    fn stdc_leading_zeros_ull(v: c_ulonglong) -> c_uint;
    fn stdc_trailing_zeros_ull(v: c_ulonglong) -> c_uint;
    fn stdc_count_ones_ull(v: c_ulonglong) -> c_uint;
    fn stdc_first_leading_one_ull(v: c_ulonglong) -> c_uint;
    fn stdc_bit_width_ull(v: c_ulonglong) -> c_uint;
    fn stdc_bit_floor_ull(v: c_ulonglong) -> c_ulonglong;
    fn stdc_bit_ceil_ull(v: c_ulonglong) -> c_ulonglong;
    fn stdc_has_single_bit_ull(v: c_ulonglong) -> bool;
}

const CASES: &[c_ulonglong] = &[
    0,
    1,
    2,
    0xFF,
    0x1_0000_0000,            // bit 32 — beyond the 32-bit range
    0x7FFF_FFFF_FFFF_FFFF,
    0x8000_0000_0000_0000,    // bit 63
    0xFFFF_FFFF_FFFF_FFFF,    // all 64 ones
    0xDEAD_BEEF_CAFE_BABE,
    0x5555_5555_5555_5555,
    0xAAAA_AAAA_AAAA_AAAA,
    0x0000_0001_0000_0000,
    0x4000_0000_0000_0000,
];

#[test]
fn stdbit_ull_match_glibc() {
    use frankenlibc_abi::stdbit_abi as s;
    for &v in CASES {
        assert_eq!(s::stdc_leading_zeros_ull(v), unsafe { stdc_leading_zeros_ull(v) }, "leading_zeros_ull({v:#018x})");
        assert_eq!(s::stdc_trailing_zeros_ull(v), unsafe { stdc_trailing_zeros_ull(v) }, "trailing_zeros_ull({v:#018x})");
        assert_eq!(s::stdc_count_ones_ull(v), unsafe { stdc_count_ones_ull(v) }, "count_ones_ull({v:#018x})");
        assert_eq!(s::stdc_first_leading_one_ull(v), unsafe { stdc_first_leading_one_ull(v) }, "first_leading_one_ull({v:#018x})");
        assert_eq!(s::stdc_bit_width_ull(v), unsafe { stdc_bit_width_ull(v) }, "bit_width_ull({v:#018x})");
        assert_eq!(s::stdc_bit_floor_ull(v), unsafe { stdc_bit_floor_ull(v) }, "bit_floor_ull({v:#018x})");
        assert_eq!(s::stdc_bit_ceil_ull(v), unsafe { stdc_bit_ceil_ull(v) }, "bit_ceil_ull({v:#018x})");
        assert_eq!(s::stdc_has_single_bit_ull(v), unsafe { stdc_has_single_bit_ull(v) }, "has_single_bit_ull({v:#018x})");
    }
}
