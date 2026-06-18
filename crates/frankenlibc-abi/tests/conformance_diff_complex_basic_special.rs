#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc cabs/carg/cproj/conj oracle

//! Differential gate for the f64 complex primitives cabs/carg/cproj/conj
//! special cases (bd-qxgf4x). cexp/clog/csqrt/cpow are fuzzed; these four were
//! uncovered. `double _Complex` is SSE,SSE on SysV AMD64 == repr(C){re,im}, so
//! CDoubleComplex passes by value. Pins the Annex G cases:
//!   cabs(+/-inf, any)=+inf incl NaN; cabs(NaN, finite)=NaN; cabs(0,0)=+0
//!   carg(z) == atan2(im, re) over the quadrant/sign matrix
//!   cproj: infinite part collapses to (+inf, copysign(0, im)); else identity
//!   conj(re, im) == (re, -im), sign flipped exactly (incl +/-0, NaN)
//! Bit-for-bit NaN-aware vs host glibc. No mocks.

use frankenlibc_abi::math_abi::{self as fl, CDoubleComplex as C};

unsafe extern "C" {
    fn cabs(z: C) -> f64;
    fn carg(z: C) -> f64;
    fn cproj(z: C) -> C;
    fn conj(z: C) -> C;
}

fn same64(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}
fn samec(a: C, b: C) -> bool {
    same64(a.re, b.re) && same64(a.im, b.im)
}

const N: f64 = f64::NAN;
const I: f64 = f64::INFINITY;

const PARTS: &[(f64, f64)] = &[
    (0.0, 0.0),
    (-0.0, 0.0),
    (0.0, -0.0),
    (3.0, 4.0),
    (-3.0, 4.0),
    (3.0, -4.0),
    (1.0, 0.0),
    (0.0, 1.0),
    (-1.0, 0.0),
    (0.0, -1.0),
    (I, 2.0),
    (2.0, I),
    (-I, 2.0),
    (2.0, -I),
    (I, I),
    (I, N),
    (N, I),
    (N, 2.0),
    (2.0, N),
    (N, N),
    (I, -0.0),
];

#[test]
fn cabs_carg_match_glibc() {
    for &(re, im) in PARTS {
        let z = C { re, im };
        let ga = unsafe { cabs(z) };
        let fa = unsafe { fl::cabs(z) };
        assert!(same64(fa, ga), "cabs({re:?},{im:?}): fl={fa:?} glibc={ga:?}");
        let gg = unsafe { carg(z) };
        let fg = unsafe { fl::carg(z) };
        assert!(same64(fg, gg), "carg({re:?},{im:?}): fl={fg:?} glibc={gg:?}");
    }
}

#[test]
fn cproj_conj_match_glibc() {
    for &(re, im) in PARTS {
        let z = C { re, im };
        let gp = unsafe { cproj(z) };
        let fp = unsafe { fl::cproj(z) };
        assert!(samec(fp, gp), "cproj({re:?},{im:?}): fl=({:?},{:?}) glibc=({:?},{:?})", fp.re, fp.im, gp.re, gp.im);
        let gc = unsafe { conj(z) };
        let fc = unsafe { fl::conj(z) };
        assert!(samec(fc, gc), "conj({re:?},{im:?}): fl=({:?},{:?}) glibc=({:?},{:?})", fc.re, fc.im, gc.re, gc.im);
    }
}
