#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc wcstol/wcstoul oracle (libc)

//! Randomized live differential fuzzer for the WIDE `wcstol_impl` /
//! `wcstoul_impl` (`&[u32]` code points) vs host glibc `wcstol`/`wcstoul`. The
//! wide family has its own parser; the byte strtol family is verified clean
//! (bd-2g7oyh.251), so this targets the wide-specific risk: in the C locale
//! glibc's `iswdigit`/`iswspace` accept ONLY ASCII, so non-ASCII "digits"
//! (fullwidth U+FF1x, Arabic-Indic U+066x) and Unicode whitespace (U+00A0,
//! U+2003, U+3000) must NOT be treated as digits/space. Inputs deliberately mix
//! ASCII with those code points; we compare the value, the consumed wide-char
//! count (endptr), and overflow (ERANGE).

use std::ffi::{c_int};

use frankenlibc_core::stdlib::conversion::{ConversionStatus, wcstol_impl, wcstoul_impl};

unsafe extern "C" {
    fn wcstol(nptr: *const c_int, endptr: *mut *mut c_int, base: c_int) -> std::ffi::c_long;
    fn wcstoul(nptr: *const c_int, endptr: *mut *mut c_int, base: c_int) -> std::ffi::c_ulong;
    fn __errno_location() -> *mut c_int;
}

/// ERANGE on Linux.
const ERANGE: c_int = 34;

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

/// A single code point, biased toward ASCII numeric syntax but reaching the
/// non-ASCII "digit"/"space" lookalikes glibc must reject in the C locale.
fn gen_cp(r: &mut Lcg) -> u32 {
    const ASCII: &[u8] = b"0123456789abcdefABCDEFxXbB+- \t.gG_";
    match r.next() % 12 {
        0 => 0x00A0,                          // no-break space
        1 => 0x2003,                          // em space
        2 => 0x3000,                          // ideographic space
        3 => 0xFF10 + (r.next() % 10) as u32, // fullwidth digit 0-9
        4 => 0x0660 + (r.next() % 10) as u32, // Arabic-Indic digit 0-9
        5 => 0x0100 + (r.next() % 0x400) as u32, // misc non-ASCII
        _ => ASCII[(r.next() as usize) % ASCII.len()] as u32,
    }
}

fn gen_input(r: &mut Lcg) -> Vec<u32> {
    let len = (r.next() % 14) as usize;
    let mut v: Vec<u32> = Vec::with_capacity(len + 2);
    // Occasionally lead with a structured prefix.
    match r.next() % 6 {
        0 => v.extend([b'0' as u32, b'x' as u32]),
        1 => v.extend([b'-' as u32, b'0' as u32, b'b' as u32]),
        2 => v.extend([b' ' as u32, b'+' as u32]),
        _ => {}
    }
    v.extend((0..len).map(|_| gen_cp(r)));
    v
}

/// fl deliberately accepts the C23 `0b`/`0B` binary prefix (base 0 or 2) as an
/// extension that the host glibc does not — a known parity-policy divergence
/// (cf. bd-2g7oyh.203 for scanf `%i`). Skip those so the fuzzer validates the
/// glibc-parity behavior rather than the intentional extension.
fn triggers_0b_extension(input: &[u32], base: c_int) -> bool {
    if base != 0 && base != 2 {
        return false;
    }
    let mut i = 0;
    while i < input.len() && matches!(input[i], 0x20 | 0x09..=0x0D) {
        i += 1;
    }
    if i < input.len() && (input[i] == b'+' as u32 || input[i] == b'-' as u32) {
        i += 1;
    }
    i + 2 < input.len()
        && input[i] == b'0' as u32
        && (input[i + 1] == b'b' as u32 || input[i + 1] == b'B' as u32)
        && (input[i + 2] == b'0' as u32 || input[i + 2] == b'1' as u32)
}

fn gen_base(r: &mut Lcg) -> c_int {
    match r.next() % 8 {
        0 => 0,
        1 => 16,
        2 => 8,
        3 => 2,
        4 => 10,
        _ => (2 + r.next() % 35) as c_int,
    }
}

fn host_wcstol(input: &[u32], base: c_int) -> (i64, usize, bool) {
    let mut w: Vec<c_int> = input.iter().map(|&c| c as c_int).collect();
    w.push(0); // NUL terminate
    let mut end: *mut c_int = w.as_ptr() as *mut c_int;
    unsafe {
        *__errno_location() = 0;
        let v = wcstol(w.as_ptr(), &mut end as *mut *mut c_int, base);
        let consumed = (end as usize - w.as_ptr() as usize) / std::mem::size_of::<c_int>();
        let erange = *__errno_location() == ERANGE;
        (v, consumed, erange)
    }
}

fn host_wcstoul(input: &[u32], base: c_int) -> (u64, usize, bool) {
    let mut w: Vec<c_int> = input.iter().map(|&c| c as c_int).collect();
    w.push(0);
    let mut end: *mut c_int = w.as_ptr() as *mut c_int;
    unsafe {
        *__errno_location() = 0;
        let v = wcstoul(w.as_ptr(), &mut end as *mut *mut c_int, base);
        let consumed = (end as usize - w.as_ptr() as usize) / std::mem::size_of::<c_int>();
        let erange = *__errno_location() == ERANGE;
        (v as u64, consumed, erange)
    }
}

#[test]
fn wcstol_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x57c5_70a7_5ee0_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..300_000 {
        let input = gen_input(&mut r);
        let base = gen_base(&mut r);
        if triggers_0b_extension(&input, base) {
            continue;
        }
        let unsigned = r.next() & 1 == 0;

        if unsigned {
            let (fv, fc, fs) = wcstoul_impl(&input, base);
            let fl = (fv, fc, matches!(fs, ConversionStatus::Overflow));
            let host = host_wcstoul(&input, base);
            compared += 1;
            if fl != host && divs.len() < 40 {
                divs.push(format!(
                    "wcstoul base={base} input={:x?}\n    fl   ={fl:?}\n    glibc={host:?}",
                    input
                ));
            }
        } else {
            let (fv, fc, fs) = wcstol_impl(&input, base);
            let fl = (
                fv,
                fc,
                matches!(fs, ConversionStatus::Overflow | ConversionStatus::Underflow),
            );
            let host = host_wcstol(&input, base);
            compared += 1;
            if fl != host && divs.len() < 40 {
                divs.push(format!(
                    "wcstol base={base} input={:x?}\n    fl   ={fl:?}\n    glibc={host:?}",
                    input
                ));
            }
        }
    }

    assert!(
        divs.is_empty(),
        "wcstol/wcstoul diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("wcstol/wcstoul fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
