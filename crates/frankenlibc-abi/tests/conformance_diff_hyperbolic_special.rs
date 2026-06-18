#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sinh/cosh/tanh oracle

//! Differential gate for f64/f32 sinh/cosh/tanh special cases (bd-diienf). The
//! hyperbolic trio was tested over value ranges but not at the special
//! arguments. Pins the C99 F.10.2 cases: sinh(+/-0)=+/-0, cosh(+/-0)=1,
//! tanh(+/-0)=+/-0; sinh(+/-inf)=+/-inf, cosh(+/-inf)=+inf, tanh(+/-inf)=+/-1;
//! NaN propagation; overflow (sinh/cosh of a large magnitude -> +/-inf); tanh
//! saturation; plus parity (sinh/tanh odd, cosh even). Bit-for-bit NaN-aware
//! (so +0 vs -0 enforced) vs host glibc. sinh/cosh/tanh + f32. No mocks.

unsafe extern "C" {
    fn sinh(x: f64) -> f64;
    fn cosh(x: f64) -> f64;
    fn tanh(x: f64) -> f64;
    fn sinhf(x: f32) -> f32;
    fn coshf(x: f32) -> f32;
    fn tanhf(x: f32) -> f32;
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
    20.0,   // tanh saturates to ~1
    -20.0,
    710.0,  // sinh/cosh overflow -> +inf
    -710.0,
    1.0e-10, // small: sinh(x)~x, tanh(x)~x, cosh(x)~1
];

#[test]
fn sinh_cosh_tanh_special_match_glibc() {
    for &x in CASES {
        let (gs, gc, gt) = unsafe { (sinh(x), cosh(x), tanh(x)) };
        let fs = unsafe { frankenlibc_abi::math_abi::sinh(x) };
        let fc = unsafe { frankenlibc_abi::math_abi::cosh(x) };
        let ft = unsafe { frankenlibc_abi::math_abi::tanh(x) };
        assert!(same64(fs, gs), "sinh({x:?}): fl={fs:?} glibc={gs:?}");
        assert!(same64(fc, gc), "cosh({x:?}): fl={fc:?} glibc={gc:?}");
        assert!(same64(ft, gt), "tanh({x:?}): fl={ft:?} glibc={gt:?}");

        // Parity (fl-internal): sinh/tanh odd, cosh even.
        if !x.is_nan() {
            let fs_n = unsafe { frankenlibc_abi::math_abi::sinh(-x) };
            let fc_n = unsafe { frankenlibc_abi::math_abi::cosh(-x) };
            let ft_n = unsafe { frankenlibc_abi::math_abi::tanh(-x) };
            assert!(same64(fs_n, -fs), "sinh odd at {x:?}: sinh(-x)={fs_n:?} -sinh(x)={:?}", -fs);
            assert!(same64(fc_n, fc), "cosh even at {x:?}");
            assert!(same64(ft_n, -ft), "tanh odd at {x:?}");
        }
    }
}

#[test]
fn sinhf_coshf_tanhf_special_match_glibc() {
    for &x in CASES {
        let xf = x as f32;
        let (gs, gc, gt) = unsafe { (sinhf(xf), coshf(xf), tanhf(xf)) };
        let fs = unsafe { frankenlibc_abi::math_abi::sinhf(xf) };
        let fc = unsafe { frankenlibc_abi::math_abi::coshf(xf) };
        let ft = unsafe { frankenlibc_abi::math_abi::tanhf(xf) };
        assert!(same32(fs, gs), "sinhf({xf:?}): fl={fs:?} glibc={gs:?}");
        assert!(same32(fc, gc), "coshf({xf:?}): fl={fc:?} glibc={gc:?}");
        assert!(same32(ft, gt), "tanhf({xf:?}): fl={ft:?} glibc={gt:?}");
    }
}
