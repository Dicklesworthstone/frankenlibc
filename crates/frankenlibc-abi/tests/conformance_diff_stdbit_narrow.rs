#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc C23 stdbit oracle (glibc >= 2.39)

//! Differential gate for the 8-bit (_uc) and 16-bit (_us) C23 stdbit functions
//! vs host glibc 2.42 (bd-br2tua). The _ui (32-bit) and _ull (64-bit) gates
//! cover the wide paths; the narrow variants have their own width constants
//! (leading_zeros_uc(0) must be 8, leading_zeros_us(0) must be 16) and their
//! own return widths (bit_floor/bit_ceil return the narrow type). A wrong narrow
//! width constant would be invisible to the wider-variant gates. Exact
//! comparison over narrow edge inputs. Verified glibc exports these symbols.
//! No mocks.

use std::ffi::{c_uchar, c_uint, c_ushort};

unsafe extern "C" {
    fn stdc_leading_zeros_uc(v: c_uchar) -> c_uint;
    fn stdc_trailing_zeros_uc(v: c_uchar) -> c_uint;
    fn stdc_count_ones_uc(v: c_uchar) -> c_uint;
    fn stdc_first_leading_one_uc(v: c_uchar) -> c_uint;
    fn stdc_bit_width_uc(v: c_uchar) -> c_uint;
    fn stdc_bit_floor_uc(v: c_uchar) -> c_uchar;
    fn stdc_bit_ceil_uc(v: c_uchar) -> c_uchar;
    fn stdc_has_single_bit_uc(v: c_uchar) -> bool;

    fn stdc_leading_zeros_us(v: c_ushort) -> c_uint;
    fn stdc_trailing_zeros_us(v: c_ushort) -> c_uint;
    fn stdc_count_ones_us(v: c_ushort) -> c_uint;
    fn stdc_first_leading_one_us(v: c_ushort) -> c_uint;
    fn stdc_bit_width_us(v: c_ushort) -> c_uint;
    fn stdc_bit_floor_us(v: c_ushort) -> c_ushort;
    fn stdc_bit_ceil_us(v: c_ushort) -> c_ushort;
    fn stdc_has_single_bit_us(v: c_ushort) -> bool;
}

const UC: &[c_uchar] = &[0, 1, 2, 0x0F, 0x10, 0x55, 0xAA, 0x7F, 0x80, 0xFF];
const US: &[c_ushort] = &[0, 1, 0xFF, 0x100, 0x5555, 0xAAAA, 0x7FFF, 0x8000, 0xFFFF, 0x0001];

#[test]
fn stdbit_uc_match_glibc() {
    use frankenlibc_abi::stdbit_abi as s;
    for &v in UC {
        assert_eq!(s::stdc_leading_zeros_uc(v), unsafe { stdc_leading_zeros_uc(v) }, "leading_zeros_uc({v:#x})");
        assert_eq!(s::stdc_trailing_zeros_uc(v), unsafe { stdc_trailing_zeros_uc(v) }, "trailing_zeros_uc({v:#x})");
        assert_eq!(s::stdc_count_ones_uc(v), unsafe { stdc_count_ones_uc(v) }, "count_ones_uc({v:#x})");
        assert_eq!(s::stdc_first_leading_one_uc(v), unsafe { stdc_first_leading_one_uc(v) }, "first_leading_one_uc({v:#x})");
        assert_eq!(s::stdc_bit_width_uc(v), unsafe { stdc_bit_width_uc(v) }, "bit_width_uc({v:#x})");
        assert_eq!(s::stdc_bit_floor_uc(v), unsafe { stdc_bit_floor_uc(v) }, "bit_floor_uc({v:#x})");
        assert_eq!(s::stdc_bit_ceil_uc(v), unsafe { stdc_bit_ceil_uc(v) }, "bit_ceil_uc({v:#x})");
        assert_eq!(s::stdc_has_single_bit_uc(v), unsafe { stdc_has_single_bit_uc(v) }, "has_single_bit_uc({v:#x})");
    }
}

#[test]
fn stdbit_us_match_glibc() {
    use frankenlibc_abi::stdbit_abi as s;
    for &v in US {
        assert_eq!(s::stdc_leading_zeros_us(v), unsafe { stdc_leading_zeros_us(v) }, "leading_zeros_us({v:#x})");
        assert_eq!(s::stdc_trailing_zeros_us(v), unsafe { stdc_trailing_zeros_us(v) }, "trailing_zeros_us({v:#x})");
        assert_eq!(s::stdc_count_ones_us(v), unsafe { stdc_count_ones_us(v) }, "count_ones_us({v:#x})");
        assert_eq!(s::stdc_first_leading_one_us(v), unsafe { stdc_first_leading_one_us(v) }, "first_leading_one_us({v:#x})");
        assert_eq!(s::stdc_bit_width_us(v), unsafe { stdc_bit_width_us(v) }, "bit_width_us({v:#x})");
        assert_eq!(s::stdc_bit_floor_us(v), unsafe { stdc_bit_floor_us(v) }, "bit_floor_us({v:#x})");
        assert_eq!(s::stdc_bit_ceil_us(v), unsafe { stdc_bit_ceil_us(v) }, "bit_ceil_us({v:#x})");
        assert_eq!(s::stdc_has_single_bit_us(v), unsafe { stdc_has_single_bit_us(v) }, "has_single_bit_us({v:#x})");
    }
}
