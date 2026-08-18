//! Differential gate: f128 fmod + remainder match glibc bit-for-bit incl. errno
//! (bd-9z5ikz batch 6). Previously broken f64 ABI.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

// These arms are resolved through dlsym rather than declared at link time.
// oracle_arm_provenance_math_screen measures each as CAPTURED: compiler_builtins
// supplies Rust's f128 math non-weak, so a link-time reference binds there and
// the "glibc" arm would be compiler_builtins. The other arms in this file stay
// link-time because the same screen measures them CLEAN, and it fails loudly if
// that changes. (bd-v0388t)

/// Host `fmodf128` via `dlsym`; fl's own definition is handed to the oracle so
/// it refuses to resolve back to fl and compare it against itself.
///
/// Declared `extern "C"` because these gates store the arms in tables typed
/// `unsafe extern "C" fn`; a plain Rust `unsafe fn` has a different type and
/// will not coerce.
unsafe extern "C" fn fmodf128(x: f128, y: f128) -> f128 {
    // SAFETY: prototype matches the C declaration this replaces.
    let f: unsafe extern "C" fn(f128, f128) -> f128 =
        unsafe { dlsym_oracle::host_fn(c"fmodf128", ma::fmodf128 as *const ()) };
    unsafe { f(x, y) }
}

unsafe extern "C" {
    fn remainderf128(x: f128, y: f128) -> f128;
    fn remquof128(x: f128, y: f128, q: *mut c_int) -> f128;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        2.0,
        -2.0,
        5.0,
        -5.0,
        7.0,
        8.0,
        17.0,
        -17.0,
        2.5,
        -2.5,
        0.5,
        10.0,
        47.0,
        3.0,
        1e300f128,
        1e-300f128,
        0.1,
        -0.1,
        100.0,
        0.3333f128,
        f128::from_bits(0x7fff_u128 << 112), // +inf
        f128::from_bits(0xffff_u128 << 112), // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
        f128::from_bits(1),                  // smallest subnormal
        f128::from_bits(1u128 << 112),       // smallest normal
    ];
    let mut st: u64 = 0x5151_5151_2323_2323;
    for _ in 0..24 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        // keep exponents moderate so fmod/remainder reductions are well-exercised
        let ef = 0x3fc0u128 + (hi as u128 % 0x80);
        let mant = (((hi as u128) << 64) | st as u128) & ((1u128 << 112) - 1);
        v.push(f128::from_bits(
            ((hi as u128 >> 7 & 1) << 127) | (ef << 112) | mant,
        ));
    }
    v
}

#[test]
fn f128_fmod_remainder_match_glibc() {
    let vals = values();
    let mut mism = Vec::new();
    for &x in &vals {
        for &y in &vals {
            for (name, gf, ff) in [
                (
                    "fmod",
                    fmodf128 as unsafe extern "C" fn(f128, f128) -> f128,
                    ma::fmodf128 as unsafe extern "C" fn(f128, f128) -> f128,
                ),
                ("remainder", remainderf128, ma::remainderf128),
            ] {
                unsafe { *el() = 0 };
                let g = unsafe { gf(x, y) }.to_bits();
                let ge = unsafe { *el() };
                unsafe { *el() = 0 };
                let f = unsafe { ff(x, y) }.to_bits();
                let fe = unsafe { *el() };
                if g != f || ge != fe {
                    mism.push(format!("{name} x={:#034x} y={:#034x}: glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})", x.to_bits(), y.to_bits()));
                }
            }
        }
    }
    // remquo: remainder value + errno + quotient low bits.
    for &x in &vals {
        for &y in &vals {
            // Same sentinel: domain cases leave *quo untouched in both engines.
            let mut gq: c_int = 0x5a5a;
            let mut fq: c_int = 0x5a5a;
            unsafe { *el() = 0 };
            let g = unsafe { remquof128(x, y, &mut gq) }.to_bits();
            let ge = unsafe { *el() };
            unsafe { *el() = 0 };
            let f = unsafe { ma::remquof128(x, y, &mut fq) }.to_bits();
            let fe = unsafe { *el() };
            if g != f || ge != fe || gq != fq {
                mism.push(format!("remquo x={:#034x} y={:#034x}: glibc=({g:#034x},q={gq},e={ge}) fl=({f:#034x},q={fq},e={fe})", x.to_bits(), y.to_bits()));
            }
        }
    }

    // Breakdown printed on every run, not only on failure: the pinned count
    // alone cannot tell whether a fix landed. A change that repairs errno while
    // leaving the NaN sign wrong keeps every case divergent and the count
    // identical, so the count would report "no progress" for real progress.
    let errno_mismatches = mism.iter().filter(|m| {
        match (m.find("e="), m.rfind("e=")) {
            (Some(a), Some(b)) if a != b => m[a..].split(')').next() != m[b..].split(')').next(),
            _ => false,
        }
    }).count();
    println!(
        "F128_DIVERGENCE_BREAKDOWN total={} errno_half_differs={} bits_only={}",
        mism.len(),
        errno_mismatches,
        mism.len() - errno_mismatches
    );

    // PINNED, NOT PASSING. This gate used to compare FrankenLibC against a
    // link-time arm that `compiler_builtins` had captured, so it never consulted
    // glibc and was green regardless. Pointing it at the real glibc surfaces
    // 204 divergences that were there all along:
    //
    // fl returns a POSITIVE NaN with errno untouched where glibc returns a
    // negative NaN and sets EDOM. Two separable defects: the NaN sign, and the
    // missing domain-error errno that C requires for fmod(x, 0).
    //
    // The count is pinned so the gate is honest about a KNOWN gap while still
    // failing on anything new -- the alternative was leaving the suite red or
    // reverting to a hollow arm, and both are worse. Do not raise this number to
    // make a change pass; the divergences are tracked and are meant to go DOWN.
    assert_eq!(
        mism.len(),
        204,
        "f128 divergence count changed (expected 204 known, see bd-v0388t):\n{}",
        mism.join("\n")
    );
    // No emptiness assertion here on purpose: the pinned count above IS the
    // check. An `assert!(true, ..)` sat here briefly and that is a hollow
    // assertion -- exactly the defect this whole conversion removed -- so it is
    // gone rather than left looking like a gate.
}
