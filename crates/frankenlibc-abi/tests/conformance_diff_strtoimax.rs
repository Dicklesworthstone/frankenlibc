#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strtoimax/strtoumax/atof oracle

//! Differential gate for strtoimax / strtoumax (which had zero tests) and atof
//! (ungated) — bd-2k6gn5. strtoimax/strtoumax parse with the strtol grammar
//! (whitespace, sign, 0x/0 prefix, base) and saturate to INTMAX/UINTMAX limits
//! with ERANGE on overflow. The (return value, endptr offset, errno) triple is
//! compared with glibc; atof's f64 result is compared bitwise. No mocks.

use std::ffi::{CString, c_char, c_int};

unsafe extern "C" {
    fn strtoimax(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int) -> i64;
    fn strtoumax(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int) -> u64;
    fn atof(nptr: *const c_char) -> f64;
    fn __errno_location() -> *mut c_int;
}

fn errno_set(v: c_int) {
    unsafe { *__errno_location() = v }
}
fn errno_get() -> c_int {
    unsafe { *__errno_location() }
}

macro_rules! diff_strto {
    ($glibc:path, $fl:path, $ty:ty, $input:expr, $base:expr) => {{
        let c = CString::new($input).unwrap();
        // glibc
        errno_set(0);
        let mut ge: *mut c_char = std::ptr::null_mut();
        let gv: $ty = unsafe { $glibc(c.as_ptr(), &mut ge, $base) };
        let goff = (ge as usize).wrapping_sub(c.as_ptr() as usize);
        let ger = errno_get();
        // fl
        errno_set(0);
        let mut fe: *mut c_char = std::ptr::null_mut();
        let fv: $ty = unsafe { $fl(c.as_ptr(), &mut fe, $base) };
        let foff = (fe as usize).wrapping_sub(c.as_ptr() as usize);
        let fer = errno_get();
        assert_eq!(
            (fv, foff, fer),
            (gv, goff, ger),
            "{}({:?}, base {}): fl=({},off{},errno{}) glibc=({},off{},errno{})",
            stringify!($glibc),
            $input,
            $base,
            fv,
            foff,
            fer,
            gv,
            goff,
            ger
        );
    }};
}

#[test]
fn strtoimax_matches_glibc() {
    use frankenlibc_abi::stdlib_abi::strtoimax as f;
    let cases: &[(&str, c_int)] = &[
        ("123", 10),
        ("-456", 10),
        ("  +99", 10),
        ("0x1F", 0),
        ("0x1F", 16),
        ("0777", 0),
        ("0777", 8),
        ("101", 2),
        ("abc", 10),
        ("12ab", 10),
        ("", 10),
        ("9223372036854775807", 10),  // INTMAX_MAX
        ("9223372036854775808", 10),  // overflow -> MAX + ERANGE
        ("-9223372036854775808", 10), // INTMAX_MIN
        ("-9223372036854775809", 10), // underflow -> MIN + ERANGE
        ("zzz", 36),
        ("  -0X10", 0),
    ];
    for &(input, base) in cases {
        diff_strto!(strtoimax, f, i64, input, base);
    }
}

#[test]
fn strtoumax_matches_glibc() {
    use frankenlibc_abi::stdlib_abi::strtoumax as f;
    let cases: &[(&str, c_int)] = &[
        ("123", 10),
        ("0xFFFF", 0),
        ("18446744073709551615", 10), // UINTMAX_MAX
        ("18446744073709551616", 10), // overflow -> MAX + ERANGE
        ("-1", 10),                   // glibc wraps: UINTMAX_MAX
        ("  +0", 10),
        ("abc", 10),
        ("777", 8),
    ];
    for &(input, base) in cases {
        diff_strto!(strtoumax, f, u64, input, base);
    }
}

#[test]
fn atof_matches_glibc() {
    for input in [
        "3.14", "-2.5e3", "  1.5", "inf", "-inf", "nan", "0x1p4", "abc", "1.5xyz", "", ".5",
        "1e999",
    ] {
        let c = CString::new(input).unwrap();
        let g = unsafe { atof(c.as_ptr()) };
        let f = unsafe { frankenlibc_abi::stdlib_abi::atof(c.as_ptr()) };
        assert_eq!(
            f.to_bits(),
            g.to_bits(),
            "atof({input:?}): fl={f} glibc={g}"
        );
    }
}
