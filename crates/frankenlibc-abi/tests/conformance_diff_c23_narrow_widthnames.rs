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
#![feature(f128)]
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
type B128 = extern "C" fn(f128, f128) -> f32;
type U128 = extern "C" fn(f128) -> f32;
type T128 = extern "C" fn(f128, f128, f128) -> f32;

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
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
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
    ck!(
        eqb(unsafe { fl::f32addf64(wx, wy) }, g_add(wx, wy)),
        "witness add".into()
    );

    let mut r = Rng(0x1234_5678_9abc_def0);
    for _ in 0..2_000_000 {
        let a = r.f64();
        let b = r.f64();
        let c = r.f64();
        ck!(
            eqb(unsafe { fl::f32addf64(a, b) }, g_add(a, b)),
            format!("add({a:e},{b:e})")
        );
        ck!(
            eqb(unsafe { fl::f32subf64(a, b) }, g_sub(a, b)),
            format!("sub({a:e},{b:e})")
        );
        ck!(
            eqb(unsafe { fl::f32mulf64(a, b) }, g_mul(a, b)),
            format!("mul({a:e},{b:e})")
        );
        ck!(
            eqb(unsafe { fl::f32divf64(a, b) }, g_div(a, b)),
            format!("div({a:e},{b:e})")
        );
        ck!(
            eqb(unsafe { fl::f32sqrtf64(a.abs()) }, g_sqrt(a.abs())),
            format!("sqrt({a:e})")
        );
        ck!(
            eqb(unsafe { fl::f32fmaf64(a, b, c) }, g_fma(a, b, c)),
            format!("fma({a:e},{b:e},{c:e})")
        );
        if !mismatches.is_empty() {
            break;
        }
    }

    // Specials.
    let sp = [
        0.0f64,
        -0.0,
        1.0,
        -1.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        f64::MIN_POSITIVE,
        f64::MAX,
        3.5,
        -2.25,
        1e300,
        1e-300,
    ];
    for &a in &sp {
        for &b in &sp {
            ck!(
                eqb(unsafe { fl::f32addf64(a, b) }, g_add(a, b)),
                format!("add sp({a},{b})")
            );
            ck!(
                eqb(unsafe { fl::f32subf64(a, b) }, g_sub(a, b)),
                format!("sub sp({a},{b})")
            );
            ck!(
                eqb(unsafe { fl::f32mulf64(a, b) }, g_mul(a, b)),
                format!("mul sp({a},{b})")
            );
            ck!(
                eqb(unsafe { fl::f32divf64(a, b) }, g_div(a, b)),
                format!("div sp({a},{b})")
            );
            ck!(
                eqb(unsafe { fl::f32sqrtf64(a) }, g_sqrt(a)),
                format!("sqrt sp({a})")
            );
        }
    }

    assert!(
        mismatches.is_empty(),
        "width-named C23 narrowing diverged from glibc ({} cases); first: {}",
        mismatches.len(),
        mismatches.first().map(String::as_str).unwrap_or("")
    );
}

/// _Float32x is `double` on x86_64, so the f32*f32x narrowing spellings are
/// exactly the f64-source operation and ARE comparable against glibc (no
/// extended-precision limitation). They must be byte-exact, not double-rounded.
#[test]
fn widthnames_f32x_match_glibc() {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null(), "dlopen libm.so.6 failed");
    let g_add: B = unsafe { s(h, c"f32addf32x") };
    let g_sub: B = unsafe { s(h, c"f32subf32x") };
    let g_mul: B = unsafe { s(h, c"f32mulf32x") };
    let g_div: B = unsafe { s(h, c"f32divf32x") };
    let g_sqrt: U = unsafe { s(h, c"f32sqrtf32x") };
    let g_fma: T = unsafe { s(h, c"f32fmaf32x") };

    let mut bad: Vec<String> = Vec::new();
    let mut r = Rng(0x0bad_c0ffee_u64.wrapping_mul(2654435761));
    for _ in 0..1_500_000 {
        let a = r.f64();
        let b = r.f64();
        let c = r.f64();
        macro_rules! ck2 {
            ($ok:expr, $m:expr) => {
                if !$ok {
                    bad.push($m);
                }
            };
        }
        ck2!(
            eqb(unsafe { fl::f32addf32x(a, b) }, g_add(a, b)),
            format!("add32x({a:e},{b:e})")
        );
        ck2!(
            eqb(unsafe { fl::f32subf32x(a, b) }, g_sub(a, b)),
            format!("sub32x({a:e},{b:e})")
        );
        ck2!(
            eqb(unsafe { fl::f32mulf32x(a, b) }, g_mul(a, b)),
            format!("mul32x({a:e},{b:e})")
        );
        ck2!(
            eqb(unsafe { fl::f32divf32x(a, b) }, g_div(a, b)),
            format!("div32x({a:e},{b:e})")
        );
        ck2!(
            eqb(unsafe { fl::f32sqrtf32x(a.abs()) }, g_sqrt(a.abs())),
            format!("sqrt32x({a:e})")
        );
        ck2!(
            eqb(unsafe { fl::f32fmaf32x(a, b, c) }, g_fma(a, b, c)),
            format!("fma32x({a:e},{b:e},{c:e})")
        );
        if !bad.is_empty() {
            break;
        }
    }
    assert!(
        bad.is_empty(),
        "f32x narrowing diverged from glibc; first: {}",
        bad.first().map(String::as_str).unwrap_or("")
    );
}

/// The `_FromType` = f64x spellings narrow from the same f64 representation as
/// the f64-source spellings in fl. The f128 spellings use the true binary128 ABI
/// and are checked directly against glibc's libm symbols.
#[test]
fn widthnames_f64x_match_f64_siblings_and_f128_matches_glibc() {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null(), "dlopen libm.so.6 failed");
    let g_add128: B128 = unsafe { s(h, c"f32addf128") };
    let g_sub128: B128 = unsafe { s(h, c"f32subf128") };
    let g_mul128: B128 = unsafe { s(h, c"f32mulf128") };
    let g_div128: B128 = unsafe { s(h, c"f32divf128") };
    let g_sqrt128: U128 = unsafe { s(h, c"f32sqrtf128") };
    let g_fma128: T128 = unsafe { s(h, c"f32fmaf128") };

    let mut bad: Vec<String> = Vec::new();
    let mut r = Rng(0xfeed_face_dead_beef);
    for _ in 0..1_000_000 {
        let a = r.f64();
        let b = r.f64();
        let c = r.f64();
        let aq = a as f128;
        let bq = b as f128;
        let cq = c as f128;
        unsafe {
            if !eqb(fl::f32addf64x(a, b), fl::f32addf64(a, b)) {
                bad.push(format!("addf64x({a:e},{b:e})"));
            }
            if !eqb(fl::f32addf128(aq, bq), g_add128(aq, bq)) {
                bad.push(format!("addf128({a:e},{b:e})"));
            }
            if !eqb(fl::f32subf64x(a, b), fl::f32subf64(a, b)) {
                bad.push(format!("subf64x({a:e},{b:e})"));
            }
            if !eqb(fl::f32subf128(aq, bq), g_sub128(aq, bq)) {
                bad.push(format!("subf128({a:e},{b:e})"));
            }
            if !eqb(fl::f32mulf64x(a, b), fl::f32mulf64(a, b)) {
                bad.push(format!("mulf64x({a:e},{b:e})"));
            }
            if !eqb(fl::f32mulf128(aq, bq), g_mul128(aq, bq)) {
                bad.push(format!("mulf128({a:e},{b:e})"));
            }
            if !eqb(fl::f32divf64x(a, b), fl::f32divf64(a, b)) {
                bad.push(format!("divf64x({a:e},{b:e})"));
            }
            if !eqb(fl::f32divf128(aq, bq), g_div128(aq, bq)) {
                bad.push(format!("divf128({a:e},{b:e})"));
            }
            if !eqb(fl::f32sqrtf64x(a.abs()), fl::f32sqrtf64(a.abs())) {
                bad.push(format!("sqrtf64x({a:e})"));
            }
            if !eqb(fl::f32sqrtf128(aq.abs()), g_sqrt128(aq.abs())) {
                bad.push(format!("sqrtf128({a:e})"));
            }
            if !eqb(fl::f32fmaf64x(a, b, c), fl::f32fmaf64(a, b, c)) {
                bad.push(format!("fmaf64x({a:e},{b:e},{c:e})"));
            }
            if !eqb(fl::f32fmaf128(aq, bq, cq), g_fma128(aq, bq, cq)) {
                bad.push(format!("fmaf128({a:e},{b:e},{c:e})"));
            }
        }
        if !bad.is_empty() {
            break;
        }
    }
    assert!(
        bad.is_empty(),
        "f64x/f128 narrowing gate failed; first: {}",
        bad.first().map(String::as_str).unwrap_or("")
    );
}
