//! Live differential probe: FrankenLibC `strtod`/`strtof` vs the host glibc
//! `strtod`/`strtof`, comparing the parsed value (exact IEEE-754 bits), the
//! `endptr` offset, AND `errno == ERANGE`. The decimal path delegates to a
//! correctly-rounded parser, but the overflow/underflow ERANGE decision is a
//! bespoke heuristic (`finite_float_underflowed_*`) and the hex-float path is
//! hand-written — so this sweeps the subnormal/overflow boundaries, hex floats,
//! and assorted syntax edges where divergences are most likely.
//!
//! fl mirrors errno to the host slot in interpose mode, so the host
//! `__errno_location` reflects both implementations.
#![allow(unsafe_code)]

use std::ffi::CString;

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn strtod(nptr: *const libc::c_char, endptr: *mut *mut libc::c_char) -> f64;
    fn strtof(nptr: *const libc::c_char, endptr: *mut *mut libc::c_char) -> f32;
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}
fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct DOut {
    bits: u64,
    is_nan: bool,
    off: isize,
    erange: bool,
}
#[derive(Debug, PartialEq, Eq, Clone)]
struct FOut {
    bits: u32,
    is_nan: bool,
    off: isize,
    erange: bool,
}

fn d_host(c: &CString) -> DOut {
    clear_errno();
    let mut end: *mut libc::c_char = std::ptr::null_mut();
    let v = unsafe { strtod(c.as_ptr(), &mut end) };
    DOut {
        bits: v.to_bits(),
        is_nan: v.is_nan(),
        off: unsafe { end.offset_from(c.as_ptr()) },
        erange: errno() == libc::ERANGE,
    }
}
fn d_fl(c: &CString) -> DOut {
    clear_errno();
    let mut end: *mut libc::c_char = std::ptr::null_mut();
    let v = unsafe { fl::strtod(c.as_ptr(), &mut end) };
    DOut {
        bits: v.to_bits(),
        is_nan: v.is_nan(),
        off: unsafe { end.offset_from(c.as_ptr()) },
        erange: errno() == libc::ERANGE,
    }
}
fn f_host(c: &CString) -> FOut {
    clear_errno();
    let mut end: *mut libc::c_char = std::ptr::null_mut();
    let v = unsafe { strtof(c.as_ptr(), &mut end) };
    FOut {
        bits: v.to_bits(),
        is_nan: v.is_nan(),
        off: unsafe { end.offset_from(c.as_ptr()) },
        erange: errno() == libc::ERANGE,
    }
}
fn f_fl(c: &CString) -> FOut {
    clear_errno();
    let mut end: *mut libc::c_char = std::ptr::null_mut();
    let v = unsafe { fl::strtof(c.as_ptr(), &mut end) };
    FOut {
        bits: v.to_bits(),
        is_nan: v.is_nan(),
        off: unsafe { end.offset_from(c.as_ptr()) },
        erange: errno() == libc::ERANGE,
    }
}

/// Equality with NaN normalised (payload/sign unspecified by C). ERANGE is now
/// asserted at the subnormal boundary for BOTH strtod and strtof — exact
/// subnormals no longer over-set it (bd-2g7oyh.187 fixed for f64 and f32).
fn d_eq(a: &DOut, b: &DOut) -> bool {
    a.off == b.off
        && a.erange == b.erange
        && if a.is_nan || b.is_nan {
            a.is_nan == b.is_nan
        } else {
            a.bits == b.bits
        }
}
fn f_eq(a: &FOut, b: &FOut) -> bool {
    a.off == b.off
        && a.erange == b.erange
        && if a.is_nan || b.is_nan {
            a.is_nan == b.is_nan
        } else {
            a.bits == b.bits
        }
}

/// Deterministic LCG so the fuzz corpus is reproducible without a rand dep.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
}

fn gen_decimal(r: &mut Lcg) -> String {
    let mut s = String::new();
    if r.next() & 1 == 0 {
        s.push(if r.next() & 1 == 0 { '-' } else { '+' });
    }
    let int_digits = (r.next() % 4) as usize;
    for _ in 0..int_digits {
        s.push((b'0' + (r.next() % 10) as u8) as char);
    }
    if r.next() & 1 == 0 {
        s.push('.');
        let frac = (r.next() % 20) as usize;
        for _ in 0..frac {
            s.push((b'0' + (r.next() % 10) as u8) as char);
        }
    }
    if s.is_empty() || s == "+" || s == "-" {
        s.push('1');
    }
    if r.next() & 1 == 0 {
        s.push(if r.next() & 1 == 0 { 'e' } else { 'E' });
        if r.next() & 1 == 0 {
            s.push('-');
        }
        let exp = r.next() % 360; // span overflow + underflow boundaries
        s.push_str(&exp.to_string());
    }
    s
}

fn gen_hex(r: &mut Lcg) -> String {
    let mut s = String::from(if r.next() & 1 == 0 { "0x" } else { "0X" });
    let hexd = b"0123456789abcdefABCDEF";
    let int_digits = 1 + (r.next() % 16) as usize; // long significands stress rounding
    for _ in 0..int_digits {
        s.push(hexd[(r.next() % 22) as usize] as char);
    }
    if r.next() & 1 == 0 {
        s.push('.');
        let frac = (r.next() % 16) as usize;
        for _ in 0..frac {
            s.push(hexd[(r.next() % 22) as usize] as char);
        }
    }
    s.push(if r.next() & 1 == 0 { 'p' } else { 'P' });
    if r.next() & 1 == 0 {
        s.push('-');
    }
    s.push_str(&(r.next() % 80).to_string());
    s
}

#[test]
fn strtod_strtof_live_vs_glibc() {
    // Boundary battery: subnormal / DBL_MIN / overflow / FLT_MIN edges + syntax.
    let battery: &[&str] = &[
        "0", "-0", "1", "-1", "  +1.5e3xyz", ".5", "5.", "1.e3", "0x", "0x1p", "1e",
        "+", "-.e5", "inf", "-inf", "infinity", "nan", "nan(0xff)", "1.0", "0.0",
        // overflow
        "1e308", "1e309", "1e400", "-1e400", "1.7976931348623157e308",
        "1.7976931348623159e308", "2e308",
        // f64 underflow / subnormal boundary
        "2.2250738585072014e-308", "1e-308", "1e-310", "1e-320", "1e-323",
        "4.9406564584124654e-324", "2.4703282292062327e-324", "1e-324", "1e-325",
        "5e-324", "1e-400",
        // f32 boundaries (for strtof)
        "1.17549435e-38", "1e-38", "1e-40", "1.4e-45", "7e-46", "1e-46",
        "3.4028235e38", "3.4028236e38", "1e39", "1e40",
        // hex
        "0x1p0", "0x1.fffffffffffffp0", "0x1.0000001p0", "0x1p-1074", "0x1p1024",
        "0x1.fffffffffffff8p0",
        // f32 subnormal boundary (exact vs inexact, for strtof)
        "0x1p-149", "0x3p-149", "0x1p-150", "0x1.8p-149", "0x1p-126", "0x1p-127",
        // long decimals (rounding / round-half-to-even)
        "9007199254740993", "0.1", "0.2", "0.3", "1.005", "2.5e-324",
        "1234567890123456789012345678901234567890",
    ];

    let mut d_div: Vec<(String, DOut, DOut)> = Vec::new();
    let mut f_div: Vec<(String, FOut, FOut)> = Vec::new();
    let mut compared = 0u64;

    let mut check = |s: &str| {
        let Ok(c) = CString::new(s) else { return };
        let (dh, df) = (d_host(&c), d_fl(&c));
        if !d_eq(&dh, &df) {
            d_div.push((s.to_string(), dh, df));
        }
        let (fh, ff) = (f_host(&c), f_fl(&c));
        if !f_eq(&fh, &ff) {
            f_div.push((s.to_string(), fh, ff));
        }
        compared += 1;
    };

    for s in battery {
        check(s);
    }
    let mut r = Lcg(0x1234_5678_9abc_def0);
    for _ in 0..4000 {
        let s = gen_decimal(&mut r);
        check(&s);
    }
    for _ in 0..4000 {
        let s = gen_hex(&mut r);
        check(&s);
    }

    let mut msg = String::new();
    if !d_div.is_empty() {
        msg.push_str(&format!(
            "strtod diverged on {} cases (up to 25):\n{:#?}\n",
            d_div.len(),
            &d_div[..d_div.len().min(25)]
        ));
    }
    if !f_div.is_empty() {
        msg.push_str(&format!(
            "strtof diverged on {} cases (up to 25):\n{:#?}\n",
            f_div.len(),
            &f_div[..f_div.len().min(25)]
        ));
    }
    assert!(msg.is_empty(), "{compared} compared.\n{msg}");
    eprintln!("strtod/strtof: {compared} inputs, 0 divergences vs host glibc");
}
