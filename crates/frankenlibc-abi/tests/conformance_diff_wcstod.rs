#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcstod/wcstof oracle
//! `wcstod` / `wcstof` parity vs host glibc over the same rich float-parse corpus
//! as `conformance_diff_strtod_edges`, but driving the WIDE path: this exercises
//! the wide-string scan, the ASCII projection, and the endptr computed in
//! wchar_t units (distinct code from narrow strtod). Compares the parsed value
//! bits, the consumed length (endptr offset in wide units), and errno.
//!
//! Note: glibc's wcstod does NOT raise ERANGE on overflow/underflow on this
//! platform (unlike strtod, which does) — fl mirrors that asymmetry, and this
//! gate pins it.

use frankenlibc_abi::wchar_abi as fl;
use std::ffi::c_int;

unsafe extern "C" {
    fn wcstod(nptr: *const i32, endptr: *mut *mut i32) -> f64;
    fn wcstof(nptr: *const i32, endptr: *mut *mut i32) -> f32;
    fn __errno_location() -> *mut c_int;
}
fn errno() -> c_int { unsafe { *__errno_location() } }
fn clr() { unsafe { *__errno_location() = 0; } }
fn wide(s: &str) -> Vec<i32> {
    s.chars().map(|c| c as i32).chain(std::iter::once(0)).collect()
}

const INPUTS: &[&str] = &[
    "0", "-0", "1", "-1", "3.14159265358979323846", "  42.5xyz", "1e10", "1E-10",
    "0x1p0", "0x1.8p1", "-0x1.fffffffffffffp+1023", "0x1p-1074", "0X1.0P0",
    "0x0.0000000000001p-1022", "0x1.0000000000001p0", "0xAbCp-4",
    "1.0000000000000002", "0.99999999999999994", "2.2250738585072014e-308",
    "9007199254740993", "9007199254740992.5",
    "1e309", "-1e309", "1e-400", "-1e-400", "1e-323", "4.9406564584124654e-324",
    "1.7976931348623159e308", "1e1000000", "1e-1000000",
    "2.4703282292062327e-324", "2.4703282292062328e-324",
    "inf", "-inf", "infinity", "INFINITY", "nan", "-nan", "NAN", "nan(123)",
    "   \t  -3.5", "+.5", ".5", "5.", "+", "-", ".", "e5", "0x", "1.5e", "1.5e+",
    "0.10000000000000000000000000000000000000001",
    "12345678901234567890123456789012345678901234567890e-50",
    "000123.456", "1e+00", "0e0",
];

fn run_f64(eng: u8, w: &[i32]) -> (u64, isize, c_int) {
    let mut end: *mut i32 = std::ptr::null_mut();
    clr();
    let v = if eng == 0 {
        unsafe { fl::wcstod(w.as_ptr(), &mut end) }
    } else {
        unsafe { wcstod(w.as_ptr(), &mut end) }
    };
    let consumed = if end.is_null() { 0 } else { (end as isize - w.as_ptr() as isize) / 4 };
    let bits = if v.is_nan() { f64::NAN.to_bits() } else { v.to_bits() };
    (bits, consumed, if errno() == libc::ERANGE { libc::ERANGE } else { 0 })
}
fn run_f32(eng: u8, w: &[i32]) -> (u32, isize, c_int) {
    let mut end: *mut i32 = std::ptr::null_mut();
    clr();
    let v = if eng == 0 {
        unsafe { fl::wcstof(w.as_ptr(), &mut end) }
    } else {
        unsafe { wcstof(w.as_ptr(), &mut end) }
    };
    let consumed = if end.is_null() { 0 } else { (end as isize - w.as_ptr() as isize) / 4 };
    let bits = if v.is_nan() { f32::NAN.to_bits() } else { v.to_bits() };
    (bits, consumed, if errno() == libc::ERANGE { libc::ERANGE } else { 0 })
}

#[test]
fn wcstod_wcstof_parity_vs_glibc() {
    let mut div = Vec::new();
    for s in INPUTS {
        let w = wide(s);
        let (fb, fc, fe) = run_f64(0, &w);
        let (gb, gc, ge) = run_f64(1, &w);
        if fb != gb || fc != gc || fe != ge {
            div.push(format!(
                "wcstod({s:?}): fl=(bits {fb:#018x}={:?}, consumed {fc}, errno {fe}) glibc=(bits {gb:#018x}={:?}, consumed {gc}, errno {ge})",
                f64::from_bits(fb), f64::from_bits(gb)));
        }
        let (ffb, ffc, ffe) = run_f32(0, &w);
        let (gfb, gfc, gfe) = run_f32(1, &w);
        if ffb != gfb || ffc != gfc || ffe != gfe {
            div.push(format!(
                "wcstof({s:?}): fl=(bits {ffb:#010x}={:?}, consumed {ffc}, errno {ffe}) glibc=(bits {gfb:#010x}={:?}, consumed {gfc}, errno {gfe})",
                f32::from_bits(ffb), f32::from_bits(gfb)));
        }
    }
    assert!(div.is_empty(), "wcstod/wcstof divergences vs glibc:\n  {}", div.join("\n  "));
}
