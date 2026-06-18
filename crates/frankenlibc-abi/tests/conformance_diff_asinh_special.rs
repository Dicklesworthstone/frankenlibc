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
fn same32(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
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
            same64(f, g),
            "asinh({x:?}): fl={f:?} (bits {:#018x}) glibc={g:?} (bits {:#018x})",
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
        assert!(same32(f, g), "asinhf({xf:?}): fl={f:?} glibc={g:?}");
    }
}
