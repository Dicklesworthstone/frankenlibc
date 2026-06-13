#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use frankenlibc_abi::stdlib_abi as fl;
use std::ffi::{CString, c_char};

unsafe extern "C" {
    fn strtod(nptr: *const c_char, endptr: *mut *mut c_char) -> f64;
    fn __errno_location() -> *mut i32;
}
fn errno() -> i32 { unsafe { *__errno_location() } }
fn clear_errno() { unsafe { *__errno_location() = 0; } }

// (bits, consumed_len, errno) for a parse via engine `eng` (0=fl, 1=glibc).
fn parse(eng: u8, s: &CString) -> (u64, isize, i32) {
    let mut end: *mut c_char = std::ptr::null_mut();
    clear_errno();
    let v = if eng == 0 {
        unsafe { fl::strtod(s.as_ptr(), &mut end) }
    } else {
        unsafe { strtod(s.as_ptr(), &mut end) }
    };
    let consumed = (end as isize) - (s.as_ptr() as isize);
    let e = errno();
    // NaN payloads/signs are unspecified across impls — canonicalize to one NaN.
    let bits = if v.is_nan() { f64::NAN.to_bits() } else { v.to_bits() };
    (bits, consumed, if e == libc::ERANGE { libc::ERANGE } else { 0 })
}

#[test]
fn strtod_edge_parity_vs_glibc() {
    let inputs: &[&str] = &[
        // basics
        "0", "-0", "1", "-1", "3.14159265358979323846", "  42.5xyz", "1e10", "1E-10",
        // hex floats
        "0x1p0", "0x1.8p1", "-0x1.fffffffffffffp+1023", "0x1p-1074", "0X1.0P0",
        "0x0.0000000000001p-1022", "0x1.0000000000001p0", "0xAbCp-4",
        // round-to-even ties (17-digit boundary)
        "1.0000000000000002", "0.99999999999999994", "2.2250738585072014e-308",
        "9007199254740993", "9007199254740992.5",
        // overflow / underflow (ERANGE)
        "1e309", "-1e309", "1e-400", "-1e-400", "1e-323", "4.9406564584124654e-324",
        "1.7976931348623159e308", "1e1000000", "1e-1000000",
        // subnormal round boundaries
        "2.4703282292062327e-324", "2.4703282292062328e-324", "7.4109846876186981e-323",
        // specials
        "inf", "-inf", "infinity", "INFINITY", "nan", "-nan", "NAN", "nan(123)", "nan(0xff)",
        // whitespace / signs / junk
        "   \t  -3.5", "+.5", ".5", "5.", "+", "-", ".", "e5", "0x", "1.5e", "1.5e+",
        // very long digit strings (precision stress)
        "0.10000000000000000000000000000000000000001",
        "12345678901234567890123456789012345678901234567890e-50",
        // leading zeros, exponent edges
        "000123.456", "1e+00", "0e0", "0.0e999999",
    ];
    let mut div = Vec::new();
    for s in inputs {
        let cs = CString::new(*s).unwrap();
        let (fb, fc, fe) = parse(0, &cs);
        let (gb, gc, ge) = parse(1, &cs);
        if fb != gb || fc != gc || fe != ge {
            div.push(format!(
                "strtod({s:?}): fl=(bits {fb:#018x}={:?}, consumed {fc}, errno {fe}) glibc=(bits {gb:#018x}={:?}, consumed {gc}, errno {ge})",
                f64::from_bits(fb), f64::from_bits(gb)
            ));
        }
    }
    if !div.is_empty() {
        eprintln!("STRTOD EDGE DIVERGENCES ({}):", div.len());
        for d in div.iter().take(120) { eprintln!("  {d}"); }
    }
    assert!(div.is_empty(), "{} strtod edge divergences vs glibc", div.len());
}
