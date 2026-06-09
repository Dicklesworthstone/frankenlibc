#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sscanf oracle

//! Differential test for `sscanf %f` on float edge cases vs host glibc, focused
//! on the exponent/hex-prefix rewind semantics: unlike strtod (which backs up
//! over an incomplete exponent), scanf COMMITS once it consumes the exponent
//! marker, so "1e", "1e+", "0x1p", "0x", "1.5e" are all MATCHING FAILURES
//! (return 0), not a successful read of the mantissa. Compares return value,
//! the converted value (bit-exact), and the consumed length (`%n`).

use std::ffi::CString;

use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn sscanf(s: *const libc::c_char, format: *const libc::c_char, ...) -> libc::c_int;
    fn strtof(s: *const libc::c_char, end: *mut *mut libc::c_char) -> f32;
    fn strtod(s: *const libc::c_char, end: *mut *mut libc::c_char) -> f64;
}

fn run_fl(input: &str) -> (i32, u32, i32) {
    let cs = CString::new(input).unwrap();
    let fmt = CString::new("%f%n").unwrap();
    let mut f: f32 = -9.0;
    let mut n: i32 = -1;
    let r = unsafe {
        fl::sscanf(cs.as_ptr(), fmt.as_ptr(), &mut f as *mut f32, &mut n as *mut i32)
    };
    (r, f.to_bits(), n)
}

fn run_glibc(input: &str) -> (i32, u32, i32) {
    let cs = CString::new(input).unwrap();
    let fmt = CString::new("%f%n").unwrap();
    let mut f: f32 = -9.0;
    let mut n: i32 = -1;
    let r = unsafe { sscanf(cs.as_ptr(), fmt.as_ptr(), &mut f as *mut f32, &mut n as *mut i32) };
    (r, f.to_bits(), n)
}

#[test]
fn sscanf_float_edges_match_glibc() {
    let cases = [
        "1e", "1e+", "1e+5", "1.", ".5", ".", "+", "-.", "0x1p", "0x1.8p3", "0x", "inf",
        "infinity", "nan", "nan(1)", "1.5e", "12e-", "  -3.5x", "0X1P+2", "1e10000", "1E5",
        "123.456", "-0.0", "+.0e0", "1e-", "0x.8p0", "0x1.", ".e5", "1..2",
        // NaN payloads: glibc encodes strtoull(seq, base 0) into the significand.
        "nan(0)", "nan(2)", "nan(255)", "nan(0x1ff)", "nan(abc)", "-nan(1)", "nan(99999999)",
        "nan(0x7fffff)", "nan()", "nan(0xffffffffffffffff)",
    ];
    let mut fails = Vec::new();
    for input in cases {
        let (rf, bf, nf) = run_fl(input);
        let (rg, bg, ng) = run_glibc(input);
        // Compare return + consumed-n always; compare the value only when both assigned.
        let val_mismatch = rf == 1 && rg == 1 && bf != bg;
        if rf != rg || nf != ng || val_mismatch {
            fails.push(format!(
                "%f {input:?}: fl=(ret={rf}, bits={bf:#x}, n={nf}) glibc=(ret={rg}, bits={bg:#x}, n={ng})"
            ));
        }

        // Also exercise the strtof / strtod parsers directly (no scanf layer).
        let cs = CString::new(input).unwrap();
        let ff = unsafe { frankenlibc_abi::stdlib_abi::strtof(cs.as_ptr(), std::ptr::null_mut()) }.to_bits();
        let fg = unsafe { strtof(cs.as_ptr(), std::ptr::null_mut()) }.to_bits();
        if ff != fg {
            fails.push(format!("strtof {input:?}: fl={ff:#x} glibc={fg:#x}"));
        }
        let df = unsafe { frankenlibc_abi::stdlib_abi::strtod(cs.as_ptr(), std::ptr::null_mut()) }.to_bits();
        let dg = unsafe { strtod(cs.as_ptr(), std::ptr::null_mut()) }.to_bits();
        if df != dg {
            fails.push(format!("strtod {input:?}: fl={df:#x} glibc={dg:#x}"));
        }
    }
    assert!(fails.is_empty(), "float edges diverged from glibc:\n{}", fails.join("\n"));
}
