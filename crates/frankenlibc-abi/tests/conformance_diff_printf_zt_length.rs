#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc snprintf oracle

//! `printf` `z`/`t` length-modifier parity vs host glibc
//! (bd-printf-zt-length-trunc-z9x8t9).
//!
//! `size_t`/`ssize_t` (`z`) and `ptrdiff_t` (`t`) are 64-bit on LP64, so the
//! integer conversions `%zd %zi %zu %zo %zx` and `%td %ti %tu %to %tx` must read
//! and render the argument at 64 bits. fl's `render_value_arg` length match
//! routed `LengthMod::Z` and `::T` through the `int` default, truncating any
//! value past 32 bits — `%zd` of 5_000_000_000 printed 705032704, `%tu` of -5
//! printed 4294967291 instead of 18446744073709551611. The scanf side was
//! already correct; this gate pins the printf side against glibc.

use frankenlibc_abi::stdio_abi as fl;
use std::ffi::{CString, c_char};

unsafe extern "C" {
    fn snprintf(b: *mut c_char, s: usize, f: *const c_char, ...) -> i32;
}

fn render(eng: u8, fmt: &str, a: i64) -> String {
    let cf = CString::new(fmt).unwrap();
    let mut b = [0u8; 96];
    let n = if eng == 0 {
        unsafe { fl::snprintf(b.as_mut_ptr() as *mut c_char, 96, cf.as_ptr(), a) }
    } else {
        unsafe { snprintf(b.as_mut_ptr() as *mut c_char, 96, cf.as_ptr(), a) }
    };
    // include the returned length so a wrong-width render is also caught
    format!("[{n}]{}", String::from_utf8_lossy(&b[..n.max(0) as usize]))
}

#[test]
fn printf_zt_length_matches_glibc() {
    // Values spanning the 32-bit boundary, both signs, plus 64-bit extremes.
    let vals: &[i64] = &[
        0,
        -1,
        -1234,
        1234,
        5_000_000_000, // > u32::MAX
        -5_000_000_000,
        0xffff_ffff,    // u32::MAX
        0x1_0000_0000,  // u32::MAX + 1
        0xffff_ffff_ff, // 40-bit
        i64::MIN,
        i64::MAX,
        -5,
    ];

    // The full d/i/o/u/x/X conversion set under both z and t, with a few
    // flag/width combinations layered on to exercise padding around the
    // widened value.
    let fmts = [
        "%zd", "%zi", "%zu", "%zo", "%zx", "%zX", "%td", "%ti", "%tu", "%to", "%tx", "%tX", "%+zd",
        "%020zd", "% td", "%-20tu|", "%#zx", "%#to", "%015td", "%+.6zd", "%.0zd", "%20zx",
    ];

    for fmt in fmts {
        for &v in vals {
            let a = render(0, fmt, v);
            let b = render(1, fmt, v);
            assert_eq!(a, b, "snprintf({fmt:?}, {v}): fl={a:?} glibc={b:?}");
        }
    }
}
