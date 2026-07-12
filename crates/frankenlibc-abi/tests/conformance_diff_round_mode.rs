#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc round-family oracle under fesetround
//! rint/nearbyint/lrint/llrint (+ f32) must round to integer using the CURRENT
//! rounding mode (fesetround), matching glibc, NOT a fixed round-ties-even. fl's
//! libm-backed rint lowers to the hardware roundsd (honours MXCSR), so it tracks
//! the mode today; this gate pins that subtle, important behaviour against a
//! future regression to a software round-ties-even (which would silently break
//! numerical code under FE_UPWARD/FE_DOWNWARD/FE_TOWARDZERO).

use frankenlibc_abi::math_abi as fl;
use std::ffi::c_int;
unsafe extern "C" {
    fn rint(x: f64) -> f64;
    fn nearbyint(x: f64) -> f64;
    fn lrint(x: f64) -> i64;
    fn llrint(x: f64) -> i64;
    fn rintf(x: f32) -> f32;
    fn nearbyintf(x: f32) -> f32;
    fn lrintf(x: f32) -> i64;
    fn llrintf(x: f32) -> i64;
    fn fesetround(m: c_int) -> c_int;
}
const MODES: &[(&str, c_int)] = &[
    ("TONEAREST", 0x000),
    ("DOWNWARD", 0x400),
    ("UPWARD", 0x800),
    ("TOWARDZERO", 0xC00),
];

#[test]
fn round_family_respects_fesetround_vs_glibc() {
    let vals: &[f64] = &[
        2.3,
        2.5,
        2.7,
        -2.3,
        -2.5,
        -2.7,
        0.5,
        -0.5,
        1.5,
        3.5,
        0.1,
        -0.1,
        100.5,
        -100.5,
        0.0,
        -0.0,
        4.5,
        -4.5,
        1e15 + 0.5,
        123456.5,
        -123456.5,
        2.9999999999,
        -2.9999999999,
    ];
    let mut div = Vec::new();
    for &(mn, m) in MODES {
        for &x in vals {
            // f64
            unsafe {
                fesetround(m);
            }
            let (fr, fnb, flr, fllr) =
                unsafe { (fl::rint(x), fl::nearbyint(x), fl::lrint(x), fl::llrint(x)) };
            unsafe {
                fesetround(m);
            }
            let (gr, gnb, glr, gllr) = unsafe { (rint(x), nearbyint(x), lrint(x), llrint(x)) };
            // f32
            let xf = x as f32;
            unsafe {
                fesetround(m);
            }
            let (frf, fnbf, flrf, fllrf) = unsafe {
                (
                    fl::rintf(xf),
                    fl::nearbyintf(xf),
                    fl::lrintf(xf),
                    fl::llrintf(xf),
                )
            };
            unsafe {
                fesetround(m);
            }
            let (grf, gnbf, glrf, gllrf) =
                unsafe { (rintf(xf), nearbyintf(xf), lrintf(xf), llrintf(xf)) };
            unsafe {
                fesetround(0x000);
            }
            if fr.to_bits() != gr.to_bits() {
                div.push(format!("rint[{mn}]({x}): fl={fr} glibc={gr}"));
            }
            if fnb.to_bits() != gnb.to_bits() {
                div.push(format!("nearbyint[{mn}]({x}): fl={fnb} glibc={gnb}"));
            }
            if flr != glr {
                div.push(format!("lrint[{mn}]({x}): fl={flr} glibc={glr}"));
            }
            if fllr != gllr {
                div.push(format!("llrint[{mn}]({x}): fl={fllr} glibc={gllr}"));
            }
            if frf.to_bits() != grf.to_bits() {
                div.push(format!("rintf[{mn}]({xf}): fl={frf} glibc={grf}"));
            }
            if fnbf.to_bits() != gnbf.to_bits() {
                div.push(format!("nearbyintf[{mn}]({xf}): fl={fnbf} glibc={gnbf}"));
            }
            if flrf != glrf {
                div.push(format!("lrintf[{mn}]({xf}): fl={flrf} glibc={glrf}"));
            }
            if fllrf != gllrf {
                div.push(format!("llrintf[{mn}]({xf}): fl={fllrf} glibc={gllrf}"));
            }
        }
    }
    assert!(
        div.is_empty(),
        "round-family rounding-mode divergences vs glibc:\n  {}",
        div.join("\n  ")
    );
}
