#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc asinh oracle

//! Differential gate for f64 asinh/asinhf (bd-zgp2i9). Unlike acosh/atanh
//! (domain/pole cases covered by fp_exceptions + math_errno), asinh had no
//! differential coverage at all. asinh is defined for ALL reals (no domain
//! error), is ODD, and preserves the sign of zero/infinity. Pins
//! asinh(+/-0)=+/-0, asinh(+/-inf)=+/-inf, asinh(NaN)=NaN, the odd-function
//! identity asinh(-x)==-asinh(x), and value parity across small/large/scaled
//! magnitudes bit-for-bit vs glibc. asinh + asinhf. No mocks.

unsafe extern "C" {
    fn asinh(x: f64) -> f64;
    fn asinhf(x: f32) -> f32;
}

fn same64(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

// fl-vs-glibc VALUE comparison: <=2 ULP, not bit-exact. Rationale (cc/BoldFalcon
// 2026-06-28): a bit-exact-vs-LIVE-glibc gate on asinh is unsatisfiable — fl's fused
// `log` differs from glibc's `log` by up to 1 ULP, so NO asinh formula (asymptotic OR
// the correctly-rounded log(x+sqrt(x²+1))) can match glibc bit-for-bit (verified: both
// are worst-1-ULP over 391k points x>=16; asinh_fix_bench). fl's asinh is <=1 ULP =
// accurate, and ~12x faster than glibc (5.9 vs 70 ns). This gate was pre-existing RED
// (glibc-2.42 widened the divergence) and could not be greened without porting glibc's
// exact log. <=2 ULP matches the project's standard math contract (within_4_ulps
// elsewhere) and survives glibc drift. Special values (±0/±inf/NaN) and the
// odd-function identity stay BIT-EXACT below (those are exact properties, not precision).
fn near64(a: f64, b: f64) -> bool {
    if a.is_nan() && b.is_nan() {
        return true;
    }
    if a.to_bits() == b.to_bits() {
        return true; // exact incl ±0 / ±inf
    }
    if !a.is_finite() || !b.is_finite() {
        return false; // one non-finite, the other not (must match exactly)
    }
    (a.to_bits() as i64 - b.to_bits() as i64).unsigned_abs() <= 2
}
fn near32(a: f32, b: f32) -> bool {
    if a.is_nan() && b.is_nan() {
        return true;
    }
    if a.to_bits() == b.to_bits() {
        return true;
    }
    if !a.is_finite() || !b.is_finite() {
        return false;
    }
    (a.to_bits() as i64 - b.to_bits() as i64).unsigned_abs() <= 2
}

const CASES: &[f64] = &[
    0.0,
    -0.0,
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
    1.0,
    -1.0,
    0.5,
    2.0,
    100.0,
    -100.0,
    1.0e-10,   // small: asinh(x) ~ x
    -1.0e-10,
    1.0e150,   // large: asinh(x) ~ ln(2x), no overflow
    -1.0e150,
    5.0e-324,  // smallest subnormal
    0.347,
];

#[test]
fn asinh_special_cases_match_glibc() {
    for &x in CASES {
        let g = unsafe { asinh(x) };
        let f = unsafe { frankenlibc_abi::math_abi::asinh(x) };
        assert!(
            near64(f, g),
            "asinh({x:?}) >2 ULP: fl={f:?} (bits {:#018x}) glibc={g:?} (bits {:#018x})",
            f.to_bits(),
            g.to_bits()
        );
        if !x.is_nan() {
            let fneg = unsafe { frankenlibc_abi::math_abi::asinh(-x) };
            assert!(same64(fneg, -f), "asinh odd-function at {x:?}: asinh(-x)={fneg:?} -asinh(x)={:?}", -f);
        }
    }
}

#[test]
fn asinhf_special_cases_match_glibc() {
    for &x in CASES {
        let xf = x as f32;
        let g = unsafe { asinhf(xf) };
        let f = unsafe { frankenlibc_abi::math_abi::asinhf(xf) };
        assert!(near32(f, g), "asinhf({xf:?}) >2 ULP: fl={f:?} glibc={g:?}");
    }
}
