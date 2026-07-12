//! Differential gate for the C23 power functions rootn/compoundn/powr (+ f32)
//! vs host glibc.
//!
//! These were implemented naively over `pow`, which is wrong for:
//!   - rootn(-x, odd n): the real n-th root exists (rootn(-8,3)=-2) but
//!     pow(-8, 1/3)=NaN; even root of a negative / n==0 are domain errors.
//!   - compoundn(x, n): x < -1 is a domain error (NaN+INVALID), not a value.
//!   - powr(x, y): NaN propagates in both args (powr(NaN,0)=NaN, not 1) and the
//!     indeterminate forms 0^0, inf^0, 1^±inf are domain errors.
//!
//! fl is called via Rust paths; glibc is reached through dlsym on libm.so.6 so
//! the fn pointer bypasses fl's no_mangle interposition of the same symbol. FP
//! exception flags are hardware (MXCSR), read with fetestexcept directly.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as fl;
use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;
const HARD: c_int = 0x1D;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn feclearexcept(e: c_int) -> c_int;
    fn fetestexcept(e: c_int) -> c_int;
}

fn sym(h: *mut c_void, name: &std::ffi::CStr) -> *mut c_void {
    let p = unsafe { dlsym(h, name.as_ptr()) };
    assert!(!p.is_null(), "missing libm symbol {name:?}");
    p
}
fn ulp_ok(a: f64, b: f64) -> bool {
    if b.is_nan() {
        return a.is_nan();
    }
    if !b.is_finite() || b == 0.0 {
        return a.to_bits() == b.to_bits();
    }
    if a.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
        return false;
    }
    ((a.to_bits() as i64) - (b.to_bits() as i64)).unsigned_abs() <= 4
}

#[test]
fn c23_pow_matches_glibc() {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null(), "dlopen libm failed");
    let g_rootn: extern "C" fn(f64, i64) -> f64 = unsafe { core::mem::transmute(sym(h, c"rootn")) };
    let g_compoundn: extern "C" fn(f64, i64) -> f64 =
        unsafe { core::mem::transmute(sym(h, c"compoundn")) };
    let g_powr: extern "C" fn(f64, f64) -> f64 = unsafe { core::mem::transmute(sym(h, c"powr")) };

    let mut div: Vec<String> = Vec::new();
    let inf = f64::INFINITY;
    let nan = f64::NAN;

    macro_rules! cmp_n {
        ($name:literal, $flf:path, $gf:expr, $x:expr, $n:expr) => {{
            let x: f64 = $x;
            let n: i64 = $n;
            unsafe { feclearexcept(HARD) };
            let fv = unsafe { $flf(x, n) };
            let ff = unsafe { fetestexcept(HARD) } & HARD;
            unsafe { feclearexcept(HARD) };
            let gv = $gf(x, n);
            let gff = unsafe { fetestexcept(HARD) } & HARD;
            if !ulp_ok(fv, gv) || ff != gff {
                div.push(format!(
                    "{}({},{}): fl={:016x}/fl{:#x} glibc={:016x}/fl{:#x}",
                    $name,
                    x,
                    n,
                    fv.to_bits(),
                    ff,
                    gv.to_bits(),
                    gff
                ));
            }
        }};
    }
    macro_rules! cmp_y {
        ($name:literal, $flf:path, $gf:expr, $x:expr, $y:expr) => {{
            let x: f64 = $x;
            let y: f64 = $y;
            unsafe { feclearexcept(HARD) };
            let fv = unsafe { $flf(x, y) };
            let ff = unsafe { fetestexcept(HARD) } & HARD;
            unsafe { feclearexcept(HARD) };
            let gv = $gf(x, y);
            let gff = unsafe { fetestexcept(HARD) } & HARD;
            if !ulp_ok(fv, gv) || ff != gff {
                div.push(format!(
                    "{}({},{}): fl={:016x}/fl{:#x} glibc={:016x}/fl{:#x}",
                    $name,
                    x,
                    y,
                    fv.to_bits(),
                    ff,
                    gv.to_bits(),
                    gff
                ));
            }
        }};
    }

    // rootn
    for &(x, n) in &[
        (-8.0, 3),
        (-27.0, 3),
        (8.0, 3),
        (-4.0, 2),
        (16.0, 4),
        (-1.0, 3),
        (0.0, 3),
        (-0.0, 3),
        (2.0, 0),
        (-0.0, -3),
        (0.0, -3),
        (-0.0, -2),
        (8.0, -3),
        (-8.0, -3),
        (nan, 3),
        (inf, 3),
        (-inf, 3),
        (-inf, 2),
        (0.0, 5),
        (-32.0, 5),
        (1024.0, 5),
        (-0.0, 2),
        (3.0, 1),
        (-3.0, 1),
        (2.0, -1),
    ] {
        cmp_n!("rootn", fl::rootn, g_rootn, x, n);
    }
    // compoundn
    for &(x, n) in &[
        (-2.0, 2),
        (-3.0, 1),
        (1.0, 3),
        (-1.0, 2),
        (-1.0, -1),
        (0.5, 0),
        (-5.0, 0),
        (nan, 0),
        (nan, 5),
        (inf, 0),
        (inf, 2),
        (-1.0, 0),
        (0.0, 0),
        (-0.5, 4),
        (2.0, -3),
        (-1.0, 3),
        (-inf, 2),
        (0.25, 10),
    ] {
        cmp_n!("compoundn", fl::compoundn, g_compoundn, x, n);
    }
    // powr
    for &(x, y) in &[
        (0.0, 0.0),
        (-0.0, 0.0),
        (2.0, 3.0),
        (-1.0, 2.0),
        (1.0, inf),
        (0.0, -1.0),
        (0.0, 2.0),
        (inf, 0.0),
        (1.0, 0.0),
        (1.0, -inf),
        (nan, 0.0),
        (2.0, nan),
        (inf, 2.0),
        (0.0, inf),
        (3.0, 0.0),
        (-2.0, 0.5),
        (4.0, 0.5),
        (2.0, 0.5),
        (10.0, -2.0),
        (0.5, 3.0),
    ] {
        cmp_y!("powr", fl::powr, g_powr, x, y);
    }

    // --- f32 variants (same logic; <=4 ULP tolerance) ---
    let g_rootnf: extern "C" fn(f32, i64) -> f32 =
        unsafe { core::mem::transmute(sym(h, c"rootnf")) };
    let g_compoundnf: extern "C" fn(f32, i64) -> f32 =
        unsafe { core::mem::transmute(sym(h, c"compoundnf")) };
    let g_powrf: extern "C" fn(f32, f32) -> f32 = unsafe { core::mem::transmute(sym(h, c"powrf")) };
    let inff = f32::INFINITY;
    let nanf = f32::NAN;
    let ulp_ok_f32 = |a: f32, b: f32| -> bool {
        if b.is_nan() {
            return a.is_nan();
        }
        if !b.is_finite() || b == 0.0 {
            return a.to_bits() == b.to_bits();
        }
        if a.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
            return false;
        }
        ((a.to_bits() as i32) - (b.to_bits() as i32)).unsigned_abs() <= 4
    };
    macro_rules! cmp_nf {
        ($name:literal, $flf:path, $gf:expr, $x:expr, $n:expr) => {{
            let x: f32 = $x;
            let n: i64 = $n;
            unsafe { feclearexcept(HARD) };
            let fv = unsafe { $flf(x, n) };
            let ff = unsafe { fetestexcept(HARD) } & HARD;
            unsafe { feclearexcept(HARD) };
            let gv = $gf(x, n);
            let gff = unsafe { fetestexcept(HARD) } & HARD;
            if !ulp_ok_f32(fv, gv) || ff != gff {
                div.push(format!(
                    "{}({},{}): fl={:08x}/fl{:#x} glibc={:08x}/fl{:#x}",
                    $name,
                    x,
                    n,
                    fv.to_bits(),
                    ff,
                    gv.to_bits(),
                    gff
                ));
            }
        }};
    }
    macro_rules! cmp_yf {
        ($name:literal, $flf:path, $gf:expr, $x:expr, $y:expr) => {{
            let x: f32 = $x;
            let y: f32 = $y;
            unsafe { feclearexcept(HARD) };
            let fv = unsafe { $flf(x, y) };
            let ff = unsafe { fetestexcept(HARD) } & HARD;
            unsafe { feclearexcept(HARD) };
            let gv = $gf(x, y);
            let gff = unsafe { fetestexcept(HARD) } & HARD;
            if !ulp_ok_f32(fv, gv) || ff != gff {
                div.push(format!(
                    "{}({},{}): fl={:08x}/fl{:#x} glibc={:08x}/fl{:#x}",
                    $name,
                    x,
                    y,
                    fv.to_bits(),
                    ff,
                    gv.to_bits(),
                    gff
                ));
            }
        }};
    }
    for &(x, n) in &[
        (-8.0f32, 3i64),
        (8.0, 3),
        (-4.0, 2),
        (-0.0, 3),
        (0.0, 3),
        (2.0, 0),
        (-8.0, -3),
        (-27.0, 3),
        (16.0, 4),
        (nanf, 3),
        (-inff, 2),
    ] {
        cmp_nf!("rootnf", fl::rootnf, g_rootnf, x, n);
    }
    for &(x, n) in &[
        (-2.0f32, 2i64),
        (-3.0, 1),
        (1.0, 3),
        (-1.0, 2),
        (-1.0, -1),
        (0.5, 0),
        (-5.0, 0),
        (nanf, 0),
        (inff, 2),
    ] {
        cmp_nf!("compoundnf", fl::compoundnf, g_compoundnf, x, n);
    }
    for &(x, y) in &[
        (0.0f32, 0.0f32),
        (2.0, 3.0),
        (-1.0, 2.0),
        (1.0, inff),
        (0.0, -1.0),
        (0.0, 2.0),
        (inff, 0.0),
        (nanf, 0.0),
        (4.0, 0.5),
    ] {
        cmp_yf!("powrf", fl::powrf, g_powrf, x, y);
    }

    assert!(
        div.is_empty(),
        "C23 pow-family divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
