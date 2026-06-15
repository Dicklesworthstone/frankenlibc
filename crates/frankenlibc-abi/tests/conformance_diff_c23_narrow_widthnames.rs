//! Differential gate: the explicit-width C23 narrowing ops (f32addf64,
//! f32subf64, f32mulf64, f32divf64, f32sqrtf64, f32fmaf64) must be byte-exact
//! with glibc — i.e. single correctly-rounded f32 results, NOT the
//! double-rounding `(x OP y) as f32`.
//!
//! These are the same operations as fadd/fsub/fmul/fdiv/fsqrt/ffma under the
//! explicit `_FromType`-suffixed spellings; fl previously left them as naive
//! double-rounding while the generic names used Boldo-Melquiond round-to-odd.
//! glibc is reached via an explicit libm.so.6 handle (bypassing fl's no_mangle
//! interposition).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as fl;
use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type B = extern "C" fn(f64, f64) -> f32;
type U = extern "C" fn(f64) -> f32;
type T = extern "C" fn(f64, f64, f64) -> f32;

unsafe fn s<F>(h: *mut c_void, n: &std::ffi::CStr) -> F
where
    F: Copy,
{
    let p = unsafe { dlsym(h, n.as_ptr()) };
    assert!(!p.is_null(), "dlsym {n:?} failed");
    assert_eq!(std::mem::size_of::<F>(), std::mem::size_of::<*mut c_void>());
    unsafe { *(&p as *const *mut c_void as *const F) }
}
fn eqb(a: f32, b: f32) -> bool {
    a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan())
}

// Deterministic LCG over f64 bit patterns drawn from a "interesting" set.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
    fn f64(&mut self) -> f64 {
        // Bias toward small exponents so sums/products land near f32 halfways.
        let m = self.next() & 0x000F_FFFF_FFFF_FFFF;
        let e = (self.next() % 80 + 984) << 52; // exponents around 1.0
        let s = (self.next() & 1) << 63;
        f64::from_bits(s | e | m)
    }
}

#[test]
fn c23_narrow_widthnames_match_glibc() {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null(), "dlopen libm.so.6 failed");
    let g_add: B = unsafe { s(h, c"f32addf64") };
    let g_sub: B = unsafe { s(h, c"f32subf64") };
    let g_mul: B = unsafe { s(h, c"f32mulf64") };
    let g_div: B = unsafe { s(h, c"f32divf64") };
    let g_sqrt: U = unsafe { s(h, c"f32sqrtf64") };
    let g_fma: T = unsafe { s(h, c"f32fmaf64") };

    let mut mismatches: Vec<String> = Vec::new();
    macro_rules! ck {
        ($ok:expr, $m:expr) => {
            if !$ok {
                mismatches.push($m);
            }
        };
    }

    // Documented double-rounding witness for add (round-to-odd vs (x+y) as f32).
    let wx = 1.0 + 2f64.powi(-24);
    let wy = 2f64.powi(-53);
    ck!(eqb(unsafe { fl::f32addf64(wx, wy) }, g_add(wx, wy)), "witness add".into());

    let mut r = Rng(0x1234_5678_9abc_def0);
    for _ in 0..2_000_000 {
        let a = r.f64();
        let b = r.f64();
        let c = r.f64();
        ck!(eqb(unsafe { fl::f32addf64(a, b) }, g_add(a, b)), format!("add({a:e},{b:e})"));
        ck!(eqb(unsafe { fl::f32subf64(a, b) }, g_sub(a, b)), format!("sub({a:e},{b:e})"));
        ck!(eqb(unsafe { fl::f32mulf64(a, b) }, g_mul(a, b)), format!("mul({a:e},{b:e})"));
        ck!(eqb(unsafe { fl::f32divf64(a, b) }, g_div(a, b)), format!("div({a:e},{b:e})"));
        ck!(eqb(unsafe { fl::f32sqrtf64(a.abs()) }, g_sqrt(a.abs())), format!("sqrt({a:e})"));
        ck!(eqb(unsafe { fl::f32fmaf64(a, b, c) }, g_fma(a, b, c)), format!("fma({a:e},{b:e},{c:e})"));
        if !mismatches.is_empty() {
            break;
        }
    }

    // Specials.
    let sp = [
        0.0f64, -0.0, 1.0, -1.0, f64::INFINITY, f64::NEG_INFINITY, f64::NAN,
        f64::MIN_POSITIVE, f64::MAX, 3.5, -2.25, 1e300, 1e-300,
    ];
    for &a in &sp {
        for &b in &sp {
            ck!(eqb(unsafe { fl::f32addf64(a, b) }, g_add(a, b)), format!("add sp({a},{b})"));
            ck!(eqb(unsafe { fl::f32subf64(a, b) }, g_sub(a, b)), format!("sub sp({a},{b})"));
            ck!(eqb(unsafe { fl::f32mulf64(a, b) }, g_mul(a, b)), format!("mul sp({a},{b})"));
            ck!(eqb(unsafe { fl::f32divf64(a, b) }, g_div(a, b)), format!("div sp({a},{b})"));
            ck!(eqb(unsafe { fl::f32sqrtf64(a) }, g_sqrt(a)), format!("sqrt sp({a})"));
        }
    }

    assert!(
        mismatches.is_empty(),
        "width-named C23 narrowing diverged from glibc ({} cases); first: {}",
        mismatches.len(),
        mismatches.first().map(String::as_str).unwrap_or("")
    );
}
