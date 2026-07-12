//! Differential gate: fl's strtof128 matches glibc on value (bits), endptr, and
//! errno across the strtod grammar (bd-nkr0ga). glibc's strtof128 returns
//! _Float128 correctly; fl is the Rust symbol (debug build is not no_mangle).
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::glibc_internal_abi as fl;
use std::ffi::{CString, c_char, c_int};

unsafe extern "C" {
    fn strtof128(nptr: *const c_char, endptr: *mut *mut c_char) -> f128;
    fn wcstof128(nptr: *const i32, endptr: *mut *mut i32) -> f128;
}

fn errno_loc() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

/// (bits, endptr offset from start, errno).
fn glibc(s: &CString) -> (u128, isize, c_int) {
    let mut end: *mut c_char = std::ptr::null_mut();
    unsafe { *errno_loc() = 0 };
    let v = unsafe { strtof128(s.as_ptr(), &mut end) };
    let off = end as isize - s.as_ptr() as isize;
    (v.to_bits(), off, unsafe { *errno_loc() })
}
fn frank(s: &CString) -> (u128, isize, c_int) {
    let mut end: *mut c_char = std::ptr::null_mut();
    unsafe { *errno_loc() = 0 };
    let v = unsafe { fl::strtof128(s.as_ptr(), &mut end) };
    let off = end as isize - s.as_ptr() as isize;
    (v.to_bits(), off, unsafe { *errno_loc() })
}

fn check(s: &str, mism: &mut Vec<String>) {
    let cs = CString::new(s).unwrap();
    let g = glibc(&cs);
    let f = frank(&cs);
    if g != f {
        mism.push(format!(
            "{s:?}: glibc=(bits={:#034x},off={},e={}) fl=(bits={:#034x},off={},e={})",
            g.0, g.1, g.2, f.0, f.1, f.2
        ));
    }
}

#[test]
fn strtof128_matches_glibc() {
    let mut mism = Vec::new();
    let curated = [
        "1",
        "1.0",
        "0.5",
        "0.1",
        "3.14159",
        "2.5",
        "-1.5",
        "+2.25",
        "  12.5",
        "\t-0.0",
        "1e10",
        "1e-10",
        "1.23456789012345678901234567890123456e20",
        "9".repeat(40).leak(),
        "123456789.987654321e-5",
        "0",
        "-0",
        "0.0",
        "00.00",
        ".5",
        "5.",
        "+.25",
        // exponent / trailing edges
        "1e",
        "1e+",
        "1.5e3xyz",
        "1.5.6",
        "12abc",
        "1e1000",
        "abc",
        "",
        "  ",
        "+",
        "-",
        ".",
        // overflow / underflow
        "1e5000",
        "-1e5000",
        "1e4932",
        "1e4933",
        "1e-4966",
        "1e-5000",
        "2e-4970",
        // specials
        "inf",
        "INF",
        "-inf",
        "+infinity",
        "Infinity",
        "nan",
        "NAN",
        "-nan",
        "nan(123)",
        "naX",
        "infi",
        "infinityX",
        // hex
        "0x1p0",
        "0x1.8p1",
        "-0x1.0p-3",
        "0X1.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp+4",
        "0x",
        "0x.8p0",
        "0x1p",
        "0x1.8",
        "0xg",
        "0x10p-4",
    ];
    for s in curated {
        check(s, &mut mism);
    }

    // Deterministic random decimal strings (fully consumed) over a wide range.
    let mut st: u64 = 0xa5a5_1234_dead_0001;
    let mut rng = || {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        st
    };
    for _ in 0..600 {
        let len = 1 + (rng() % 36) as usize;
        let mut d = String::new();
        if rng() & 1 == 0 {
            d.push('-');
        }
        d.push((b'1' + (rng() % 9) as u8) as char);
        for _ in 1..len {
            d.push((b'0' + (rng() % 10) as u8) as char);
        }
        let dexp = (rng() % 9900) as i64 - 4950;
        d.push('e');
        d.push_str(&dexp.to_string());
        check(&d, &mut mism);
        if mism.len() > 40 {
            break;
        }
    }
    assert!(
        mism.is_empty(),
        "strtof128 diverged ({}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}

fn wide(s: &str) -> Vec<i32> {
    s.bytes()
        .map(|b| b as i32)
        .chain(std::iter::once(0))
        .collect()
}
fn gw(w: &[i32]) -> (u128, isize, c_int) {
    let mut end: *mut i32 = std::ptr::null_mut();
    unsafe { *errno_loc() = 0 };
    let v = unsafe { wcstof128(w.as_ptr(), &mut end) };
    let off = (end as isize - w.as_ptr() as isize) / 4;
    (v.to_bits(), off, unsafe { *errno_loc() })
}
fn fw(w: &[i32]) -> (u128, isize, c_int) {
    let mut end: *mut i32 = std::ptr::null_mut();
    unsafe { *errno_loc() = 0 };
    let v = unsafe { fl::wcstof128(w.as_ptr(), &mut end) };
    let off = (end as isize - w.as_ptr() as isize) / 4;
    (v.to_bits(), off, unsafe { *errno_loc() })
}

#[test]
fn wcstof128_matches_glibc() {
    let mut mism = Vec::new();
    for s in [
        "1",
        "0.5",
        "0.1",
        "-3.14159e2",
        "  +12.5xyz",
        "1e-4949",
        "1e5000",
        "inf",
        "-nan(7)",
        "0x1.8p3",
        "abc",
        "",
        "42.0",
        "123456789012345678901234567890e-15",
    ] {
        let w = wide(s);
        let g = gw(&w);
        let f = fw(&w);
        if g != f {
            mism.push(format!(
                "{s:?}: glibc=(b={:#034x},off={},e={}) fl=(b={:#034x},off={},e={})",
                g.0, g.1, g.2, f.0, f.1, f.2
            ));
        }
    }
    assert!(
        mism.is_empty(),
        "wcstof128 diverged ({}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}
