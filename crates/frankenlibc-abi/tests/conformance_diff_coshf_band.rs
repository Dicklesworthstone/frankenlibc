#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc coshf/sinhf oracle via dlsym

//! Differential gate for `coshf` after it was moved onto fl's f64 `cosh`.
//!
//! `coshf` used to carry its own split -- `(u + 1/u)/2` with `u = exp(|x|)` for
//! |x| <= 5, `libm::coshf` above -- while `sinhf` had already been moved to
//! delegate to the f64 kernel. Changing coshf to match changes which code
//! produces the answer across the WHOLE range, so the values need pinning
//! against the real host, not against the previous implementation.
//!
//! The band chosen is the one the perf campaign times: the 64-point sweep from
//! 0.5 through 6.8. That is deliberate -- it straddles both boundaries the old
//! implementation had (3.0, where the f64 kernel switches from its Taylor
//! polynomial to the exp reroute, and 5.0, where the old f32 code fell through
//! to libm) so a divergence introduced at either seam shows up here rather than
//! in a benchmark.
//!
//! Tolerance is 1 ULP, matching what the campaign's accuracy contract already
//! recorded for this symbol (`worst_coshf_ulp=1`, limit 4). Specials are held to
//! BIT equality, because a NaN payload or a signed zero is not a rounding
//! question.

use std::ffi::c_void;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type F32Unary = unsafe extern "C" fn(f32) -> f32;

fn host_coshf() -> F32Unary {
    // SAFETY: signature matches C's coshf exactly.
    unsafe { dlsym_oracle::host_fn(c"coshf", frankenlibc_abi::math_abi::coshf as *const ()) }
}

fn host_sinhf() -> F32Unary {
    // SAFETY: signature matches C's sinhf exactly.
    unsafe { dlsym_oracle::host_fn(c"sinhf", frankenlibc_abi::math_abi::sinhf as *const ()) }
}

/// Distance in representable f32 steps, NaN-aware and sign-aware.
fn ulp_distance(a: f32, b: f32) -> u64 {
    if a.is_nan() || b.is_nan() {
        return if a.is_nan() && b.is_nan() { 0 } else { u64::MAX };
    }
    if a == b {
        return 0;
    }
    let key = |v: f32| -> i64 {
        let bits = v.to_bits() as i64;
        if bits < 0 { i64::MIN + 1 - bits } else { bits }
    };
    key(a).abs_diff(key(b))
}

/// The exact sweep the campaign times, plus both seams of the old split.
fn band() -> Vec<f32> {
    let mut xs: Vec<f32> = (0..64).map(|i| 0.5 + (i as f32) * 0.1).collect();
    // The seams themselves and their immediate neighbours, which a uniform
    // sweep can step over.
    for seam in [3.0f32, 5.0] {
        xs.push(seam);
        xs.push(f32::from_bits(seam.to_bits() - 1));
        xs.push(f32::from_bits(seam.to_bits() + 1));
    }
    xs
}

#[test]
fn coshf_matches_live_glibc_across_the_timed_band() {
    let host = host_coshf();
    let mut worst = 0u64;
    let mut worst_at = 0.0f32;
    let mut compared = 0usize;

    for x in band() {
        // SAFETY: plain f32 in, f32 out, through fl's Rust path.
        let fl = unsafe { frankenlibc_abi::math_abi::coshf(x) };
        // SAFETY: same input through the dlsym-resolved host symbol.
        let gl = unsafe { host(x) };
        let d = ulp_distance(fl, gl);
        compared += 1;
        if d > worst {
            worst = d;
            worst_at = x;
        }
    }

    // A zero worst-ULP is only evidence if the sweep ran.
    assert!(compared >= 64, "band sweep compared only {compared} points");
    assert!(
        worst <= 1,
        "coshf diverges from live glibc by {worst} ULP at x={worst_at} \
         (fl={:?} glibc={:?}) over {compared} points",
        unsafe { frankenlibc_abi::math_abi::coshf(worst_at) },
        unsafe { host(worst_at) }
    );
    println!("coshf band: {compared} points, worst {worst} ULP vs live glibc");
}

/// The negative half, because `coshf` is even and the delegation casts through
/// f64 -- a sign that leaked would show up here and nowhere in the timed sweep,
/// which is positive-only.
#[test]
fn coshf_is_even_and_matches_glibc_on_negatives() {
    let host = host_coshf();
    for x in band() {
        // SAFETY: as above, for -x.
        let fl_neg = unsafe { frankenlibc_abi::math_abi::coshf(-x) };
        // SAFETY: as above.
        let fl_pos = unsafe { frankenlibc_abi::math_abi::coshf(x) };
        assert_eq!(
            fl_neg.to_bits(),
            fl_pos.to_bits(),
            "coshf is even but coshf(-{x}) != coshf({x})"
        );
        // SAFETY: as above.
        let gl = unsafe { host(-x) };
        assert!(
            ulp_distance(fl_neg, gl) <= 1,
            "coshf(-{x}): fl={fl_neg:?} glibc={gl:?}"
        );
    }
}

/// Specials and the overflow edge, held to BIT equality.
///
/// The old implementation kept `libm::coshf` above |x| = 5 specifically for
/// "the exact overflow/FE semantics", so the delegation has to be shown to
/// reproduce them rather than assumed to.
#[test]
fn coshf_specials_and_overflow_edge_are_bit_exact() {
    let host = host_coshf();
    let cases: [f32; 12] = [
        0.0,
        -0.0,
        f32::MIN_POSITIVE,
        -f32::MIN_POSITIVE,
        1.0,
        88.0,
        88.7,      // just under the f32 overflow edge
        89.0,      // just over: cosh overflows f32 here
        1.0e30,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
    ];
    for x in cases {
        // SAFETY: plain f32 through fl's Rust path.
        let fl = unsafe { frankenlibc_abi::math_abi::coshf(x) };
        // SAFETY: same input through the host symbol.
        let gl = unsafe { host(x) };
        let same = (fl.is_nan() && gl.is_nan()) || fl.to_bits() == gl.to_bits();
        assert!(same, "coshf({x:?}): fl={fl:?} glibc={gl:?} (bit compare)");
    }
}

/// `sinhf` already delegates to the f64 kernel; pin it on the same band so a
/// future change to the shared f64 path cannot move one twin without the other
/// being noticed.
#[test]
fn sinhf_still_matches_live_glibc_on_the_same_band() {
    let host = host_sinhf();
    let mut worst = 0u64;
    for x in band() {
        // SAFETY: plain f32 in, f32 out.
        let fl = unsafe { frankenlibc_abi::math_abi::sinhf(x) };
        // SAFETY: same input through the host symbol.
        let gl = unsafe { host(x) };
        worst = worst.max(ulp_distance(fl, gl));
    }
    assert!(worst <= 1, "sinhf worst {worst} ULP vs live glibc on the band");
}

/// The oracle is glibc's, not fl's.
#[test]
fn the_host_arm_is_not_fl() {
    let resolved = unsafe {
        dlsym_oracle::host_addr(c"coshf", frankenlibc_abi::math_abi::coshf as *const ())
    };
    assert_ne!(
        resolved as usize,
        frankenlibc_abi::math_abi::coshf as *const () as usize,
        "the resolved coshf oracle is fl's own definition"
    );
    let _ = resolved as *const c_void;
}
