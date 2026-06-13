//! Differential gate for the C23 narrowing arithmetic fadd/fsub/fmul/fdiv/fsqrt
//! vs host glibc. These must round the EXACT result of the f64 operation a
//! SINGLE time to f32; the naive `(x OP y) as f32` double-rounds (f64 then f32)
//! and disagrees near f32 halfway points. fl uses Boldo–Melquiond round-to-odd.
//! glibc reached via dlsym (bypasses fl's no_mangle interposition).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use frankenlibc_abi::math_abi as fl;
use std::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
    fn dlopen(f: *const c_char, fl: c_int) -> *mut c_void;
    fn dlsym(h: *mut c_void, s: *const c_char) -> *mut c_void;
}
fn sym2(h: *mut c_void, n: &std::ffi::CStr) -> extern "C" fn(f64, f64) -> f32 {
    let p = unsafe { dlsym(h, n.as_ptr()) };
    assert!(!p.is_null(), "missing {n:?}");
    unsafe { core::mem::transmute(p) }
}
fn sym1(h: *mut c_void, n: &std::ffi::CStr) -> extern "C" fn(f64) -> f32 {
    let p = unsafe { dlsym(h, n.as_ptr()) };
    assert!(!p.is_null(), "missing {n:?}");
    unsafe { core::mem::transmute(p) }
}
fn sym3(h: *mut c_void, n: &std::ffi::CStr) -> extern "C" fn(f64, f64, f64) -> f32 {
    let p = unsafe { dlsym(h, n.as_ptr()) };
    assert!(!p.is_null(), "missing {n:?}");
    unsafe { core::mem::transmute(p) }
}
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
    fn f64_near1(&mut self) -> f64 {
        // value in ~[0.5,2) with full 52-bit mantissa entropy
        let m = self.next() & ((1u64 << 52) - 1);
        f64::from_bits((0x3FEu64 << 52) | m) // [0.5,1)
            * if self.next() & 1 == 0 { 1.0 } else { 2.0 }
    }
    fn tiny(&mut self) -> f64 {
        // small perturbation 2^-30..2^-20 with full entropy, random sign
        let m = self.next() & ((1u64 << 52) - 1);
        let e = 0x3E0 + (self.next() % 11); // 2^-31 .. 2^-21
        let v = f64::from_bits((e << 52) | m);
        if self.next() & 1 == 0 { v } else { -v }
    }
}

#[test]
fn c23_narrow_matches_glibc() {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), 2) };
    assert!(!h.is_null());
    let g_fadd = sym2(h, c"fadd");
    let g_fsub = sym2(h, c"fsub");
    let g_fmul = sym2(h, c"fmul");
    let g_fdiv = sym2(h, c"fdiv");
    let g_fsqrt = sym1(h, c"fsqrt");
    let g_ffma = sym3(h, c"ffma");

    let mut div: Vec<String> = Vec::new();
    macro_rules! chk2 {
        ($name:literal, $flf:path, $gf:expr, $x:expr, $y:expr) => {{
            let fv = unsafe { $flf($x, $y) };
            let gv = $gf($x, $y);
            if fv.to_bits() != gv.to_bits() && !(fv.is_nan() && gv.is_nan()) {
                div.push(format!("{}({:e},{:e}): fl={:08x} glibc={:08x}", $name, $x, $y, fv.to_bits(), gv.to_bits()));
            }
        }};
    }
    macro_rules! chk1 {
        ($name:literal, $flf:path, $gf:expr, $x:expr) => {{
            let fv = unsafe { $flf($x) };
            let gv = $gf($x);
            if fv.to_bits() != gv.to_bits() && !(fv.is_nan() && gv.is_nan()) {
                div.push(format!("{}({:e}): fl={:08x} glibc={:08x}", $name, $x, fv.to_bits(), gv.to_bits()));
            }
        }};
    }
    macro_rules! chk3 {
        ($name:literal, $flf:path, $gf:expr, $x:expr, $y:expr, $z:expr) => {{
            let fv = unsafe { $flf($x, $y, $z) };
            let gv = $gf($x, $y, $z);
            if fv.to_bits() != gv.to_bits() && !(fv.is_nan() && gv.is_nan()) {
                div.push(format!("{}({:e},{:e},{:e}): fl={:08x} glibc={:08x}", $name, $x, $y, $z, fv.to_bits(), gv.to_bits()));
            }
        }};
    }

    // Hand-constructed double-rounding witnesses.
    chk2!("fadd", fl::fadd, g_fadd, 1.0 + (2f64.powi(-24)), (2f64.powi(-53)));
    chk2!("fadd", fl::fadd, g_fadd, 1.0 + (2f64.powi(-23)) + (2f64.powi(-24)), (2f64.powi(-53)));
    chk2!("fsub", fl::fsub, g_fsub, 1.0 + (2f64.powi(-23)), (2f64.powi(-24)) + (2f64.powi(-53)));
    chk2!("fmul", fl::fmul, g_fmul, 1.0 + (2f64.powi(-24)), 1.0 + (2f64.powi(-24)));
    chk2!("fdiv", fl::fdiv, g_fdiv, 1.0, 3.0);
    chk1!("fsqrt", fl::fsqrt, g_fsqrt, 2.0);
    // ffma witness: x*y+z = 1 + 2^-24 + 2^-53 (the fma double-rounds to 1.0).
    chk3!("ffma", fl::ffma, g_ffma, 1.0, 1.0, (2f64.powi(-24)) + (2f64.powi(-53)));
    chk3!("ffma", fl::ffma, g_ffma, 1.0 + (2f64.powi(-24)), 1.0 + (2f64.powi(-24)), -1.0);

    // Special values.
    let sv = [0.0f64, -0.0, 1.0, -1.0, f64::INFINITY, f64::NEG_INFINITY, f64::NAN, 1e300, 4.0, 0.25];
    for &a in &sv {
        for &b in &sv {
            chk2!("fadd", fl::fadd, g_fadd, a, b);
            chk2!("fsub", fl::fsub, g_fsub, a, b);
            chk2!("fmul", fl::fmul, g_fmul, a, b);
            chk2!("fdiv", fl::fdiv, g_fdiv, a, b);
            chk3!("ffma", fl::ffma, g_ffma, a, b, 1.0);
            chk3!("ffma", fl::ffma, g_ffma, a, 1.0, b);
        }
        chk1!("fsqrt", fl::fsqrt, g_fsqrt, a);
    }

    // Targeted fuzz: results biased to land near f32 halfways (3M each op).
    let mut r = Lcg(0x9E3779B97F4A7C15);
    for _ in 0..3_000_000 {
        let x = r.f64_near1();
        let y = r.tiny();
        chk2!("fadd", fl::fadd, g_fadd, x, y);
        chk2!("fsub", fl::fsub, g_fsub, x, y);
        let x2 = r.f64_near1();
        let y2 = 1.0 + r.tiny();
        chk2!("fmul", fl::fmul, g_fmul, x2, y2);
        chk2!("fdiv", fl::fdiv, g_fdiv, x2, y2);
        let xs = r.f64_near1();
        chk1!("fsqrt", fl::fsqrt, g_fsqrt, xs);
        // ffma: x*y near 1, z a tiny perturbation → results near f32 halfways.
        let fx = r.f64_near1();
        let fy = 1.0 + r.tiny();
        let fz = r.tiny();
        chk3!("ffma", fl::ffma, g_ffma, fx, fy, fz);
        if div.len() > 20 {
            break;
        }
    }

    assert!(div.is_empty(), "C23 narrowing divergences vs glibc ({}):\n  {}", div.len(), div.join("\n  "));
}
