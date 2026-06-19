#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc math oracle

//! Differential gate for the GENERAL `powf` fast path (bd-z8p3mx).
//!
//! fl `powf` previously deferred its general/irrational case to `libm::powf`.
//! The lever routes positive-base, finite-exponent inputs through
//! `exp(y*ln(x))` in f64 (fl's own fast f64 `exp`/`log`), accepting the result
//! only when it rounds to a finite normal f32; overflow/underflow/subnormal
//! defer to `libm::powf`. The existing `diff_powf_profile_exp_1_337_within_4_ulps`
//! gate only covers exponent 1.337, so this gate covers the general domain:
//! a dense grid of positive bases that EXIT the medium [0.5,2.5) box, paired
//! with several non-special irrational exponents, asserted within the 4-ULP
//! glibc parity contract. Overflow/underflow boundary inputs are checked for
//! exact value parity (inf / 0) so the errno-setting ABI layer stays correct.

mod g {
    unsafe extern "C" {
        pub fn powf(x: f32, y: f32) -> f32;
    }
}
use frankenlibc_abi::math_abi as fl;

fn ulp_diff(a: f32, b: f32) -> u64 {
    if a == b {
        return 0;
    }
    if a.is_nan() && b.is_nan() {
        return 0;
    }
    if a.is_nan() || b.is_nan() || a.is_infinite() || b.is_infinite() {
        return u64::MAX;
    }
    let ai = a.to_bits() as i64;
    let bi = b.to_bits() as i64;
    // Map to a monotonic ordering across the sign boundary.
    let am = if ai < 0 { i64::MIN - ai } else { ai };
    let bm = if bi < 0 { i64::MIN - bi } else { bi };
    am.abs_diff(bm)
}

#[test]
fn general_powf_within_4_ulps_vs_glibc() {
    // Bases that exit the medium box on both sides, spanning several decades.
    let mut bases: Vec<f32> = Vec::new();
    // (0, 0.5): below the medium box.
    let mut x = 0.001_f32;
    while x < 0.5 {
        bases.push(x);
        x *= 1.07;
    }
    // (2.5, 1e6): above the medium box, dense low end then sparse high end.
    let mut x = 2.5001_f32;
    while x < 1.0e6 {
        bases.push(x);
        x *= 1.03;
    }
    // A few exact integer/half bases for good measure.
    bases.extend_from_slice(&[3.0, 4.0, 7.0, 10.0, 100.0, 0.1, 0.25, 0.3]);

    // Non-special irrational exponents (and a couple modest integers/fractions),
    // kept small enough that most (base,exp) pairs stay in the finite-normal f32
    // range that the fast path serves.
    let exps: &[f32] = &[
        0.3,
        0.5001,
        1.0,
        1.337,
        1.7,
        2.0,
        2.5,
        std::f32::consts::E,
        std::f32::consts::PI,
        -0.7,
        -1.3,
        -2.1,
        3.3,
    ];

    let mut worst = 0u64;
    let mut worst_desc = String::new();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0u64;

    for &base in &bases {
        for &exp in exps {
            let got = unsafe { fl::powf(base, exp) };
            let want = unsafe { g::powf(base, exp) };

            // Skip pairs that overflow/underflow out of the finite-normal range:
            // those are served by libm via the deferral guard and (by the ABI
            // layer) carry their own errno/exception handling. Require exact
            // agreement on inf/zero so the boundary classification matches.
            if !want.is_finite() || want == 0.0 || want.abs() < f32::MIN_POSITIVE {
                assert_eq!(
                    got.is_finite() && got != 0.0 && got.abs() >= f32::MIN_POSITIVE,
                    want.is_finite() && want != 0.0 && want.abs() >= f32::MIN_POSITIVE,
                    "powf({base},{exp}) finite/normal classification mismatch fl={got:?} glibc={want:?}"
                );
                if want.is_infinite() || want == 0.0 {
                    assert_eq!(
                        got, want,
                        "powf({base},{exp}) boundary value mismatch fl={got:?} glibc={want:?}"
                    );
                }
                continue;
            }

            checked += 1;
            let u = ulp_diff(got, want);
            if u > worst {
                worst = u;
                worst_desc = format!("powf({base},{exp}) fl={got:?} glibc={want:?} ({u} ULP)");
            }
            if u > 4 {
                failures.push(format!(
                    "powf({base},{exp}) fl={got:?} glibc={want:?} ({u} ULP)"
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} general powf inputs exceeded 4 ULP (of {checked} checked); worst {worst_desc}:\n{}",
        failures.len(),
        failures
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        checked > 500,
        "expected a dense grid, only checked {checked}"
    );
    eprintln!("general powf: {checked} inputs within 4 ULP, worst = {worst_desc}");
}
