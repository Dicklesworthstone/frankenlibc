//! Differential gate: f128 rint/nearbyint/lrint/llrint (in all 4 rounding
//! modes), lround/llround, and __iseqsigf128 match glibc bit-for-bit incl.
//! errno (bd-9z5ikz batch 9). Previously broken f64 ABI.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::{c_int, c_long};

unsafe extern "C" {
    fn rintf128(x: f128) -> f128;
    fn nearbyintf128(x: f128) -> f128;
    fn lrintf128(x: f128) -> c_long;
    fn llrintf128(x: f128) -> i64;
    fn lroundf128(x: f128) -> c_long;
    fn llroundf128(x: f128) -> i64;
    fn __iseqsigf128(x: f128, y: f128) -> c_int;
    fn fesetround(m: c_int) -> c_int;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        0.5,
        -0.5,
        1.5,
        2.5,
        -2.5,
        3.5,
        1.0,
        -1.0,
        2.4,
        2.6,
        -2.4,
        -2.6,
        1e30f128,
        -1e30f128,
        123.456f128,
        -7.5f128,
        8.5f128,
        f128::from_bits(0x7fff_u128 << 112), // +inf
        f128::from_bits(0xffff_u128 << 112), // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
        f128::from_bits(1),                  // smallest subnormal
        9007199254740993.0f128,              // 2^53+1 (exact in f128)
    ];
    let mut st: u64 = 0x2468_ace0_1357_9bdf;
    for _ in 0..20 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let ef = 0x3fe0u128 + (hi as u128 % 0x40); // moderate so rounding matters
        let mant = (((hi as u128) << 64) | st as u128) & ((1u128 << 112) - 1);
        v.push(f128::from_bits(
            ((hi as u128 >> 9 & 1) << 127) | (ef << 112) | mant,
        ));
    }
    v
}

#[test]
fn f128_rint_lround_iseqsig_match_glibc() {
    let vals = values();
    let mut mism = Vec::new();

    // Mode-independent: lround / llround.
    for &x in &vals {
        let (g, f) = (unsafe { lroundf128(x) }, unsafe { ma::lroundf128(x) });
        if g != f {
            mism.push(format!("lround x={:#034x}: glibc={g} fl={f}", x.to_bits()));
        }
        let (g, f) = (unsafe { llroundf128(x) }, unsafe { ma::llroundf128(x) });
        if g != f {
            mism.push(format!("llround x={:#034x}: glibc={g} fl={f}", x.to_bits()));
        }
    }

    // Mode-dependent: rint/nearbyint/lrint/llrint in each FE_* mode.
    for &mode in &[0, 0x400, 0x800, 0xc00] {
        unsafe { fesetround(mode) };
        for &x in &vals {
            let (g, f) = (
                unsafe { rintf128(x) }.to_bits(),
                unsafe { ma::rintf128(x) }.to_bits(),
            );
            if g != f {
                mism.push(format!(
                    "rint[{mode:#x}] x={:#034x}: glibc={g:#034x} fl={f:#034x}",
                    x.to_bits()
                ));
            }
            let (g, f) = (
                unsafe { nearbyintf128(x) }.to_bits(),
                unsafe { ma::nearbyintf128(x) }.to_bits(),
            );
            if g != f {
                mism.push(format!(
                    "nearbyint[{mode:#x}] x={:#034x}: glibc={g:#034x} fl={f:#034x}",
                    x.to_bits()
                ));
            }
            let (g, f) = (unsafe { lrintf128(x) }, unsafe { ma::lrintf128(x) });
            if g != f {
                mism.push(format!(
                    "lrint[{mode:#x}] x={:#034x}: glibc={g} fl={f}",
                    x.to_bits()
                ));
            }
            let (g, f) = (unsafe { llrintf128(x) }, unsafe { ma::llrintf128(x) });
            if g != f {
                mism.push(format!(
                    "llrint[{mode:#x}] x={:#034x}: glibc={g} fl={f}",
                    x.to_bits()
                ));
            }
        }
    }
    unsafe { fesetround(0) }; // restore FE_TONEAREST

    // __iseqsig: value + errno.
    for &x in &vals {
        for &y in &vals {
            unsafe { *el() = 0 };
            let g = unsafe { __iseqsigf128(x, y) };
            let ge = unsafe { *el() };
            unsafe { *el() = 0 };
            let f = unsafe { ma::__iseqsigf128(x, y) };
            let fe = unsafe { *el() };
            if g != f || ge != fe {
                mism.push(format!(
                    "iseqsig x={:#034x} y={:#034x}: glibc=({g},e={ge}) fl=({f},e={fe})",
                    x.to_bits(),
                    y.to_bits()
                ));
            }
        }
    }

    assert!(
        mism.is_empty(),
        "f128 rint/lround/iseqsig diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
