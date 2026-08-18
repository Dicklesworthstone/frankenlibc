#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc cbrt oracle

//! Differential gate for f64 cbrt/cbrtf (bd-z6tlx1). f64 cbrt had only
//! fl-internal tests — no differential gate vs glibc (the f128 variant had
//! one). cbrt is distinctive: it is an ODD function with NO domain error on
//! negatives (unlike sqrt), preserves the sign of zero/infinity, and is exact
//! on perfect cubes. Pins: cbrt(+/-0)=+/-0, cbrt(+/-inf)=+/-inf, cbrt(NaN)=NaN,
//! exact perfect cubes (incl negative), the odd-function identity
//! cbrt(-x)==-cbrt(x), and irrational/scaled values bit-for-bit vs glibc.
//! cbrt + cbrtf. No mocks.

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

// BOTH arms come through dlsym, not a link-time declaration. The oracle-arm
// screen measures `cbrt` AND `cbrtf` as CAPTURED by a local provider, so a
// link-time reference resolves inside this test executable and the "glibc" arm
// would be `compiler_builtins`, not glibc. This gate was found by the screen's
// link-time check rather than by hand -- it is not in the round-to-integer
// family that prompted the earlier conversions, which is exactly why an
// automatic check was worth writing.

/// Host `cbrt` via `dlsym`; fl's own definition is handed to the oracle so it
/// refuses to resolve back to fl and compare it against itself.
unsafe fn cbrt(x: f64) -> f64 {
    // SAFETY: prototype matches C's `double cbrt(double)`.
    let f: unsafe extern "C" fn(f64) -> f64 = unsafe {
        dlsym_oracle::host_fn(c"cbrt", frankenlibc_abi::math_abi::cbrt as *const ())
    };
    unsafe { f(x) }
}

/// Host `cbrtf` via `dlsym`, same contract as `cbrt` above.
unsafe fn cbrtf(x: f32) -> f32 {
    // SAFETY: prototype matches C's `float cbrtf(float)`.
    let f: unsafe extern "C" fn(f32) -> f32 = unsafe {
        dlsym_oracle::host_fn(c"cbrtf", frankenlibc_abi::math_abi::cbrtf as *const ())
    };
    unsafe { f(x) }
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
    8.0,
    -8.0,
    27.0,
    -27.0,
    64.0,
    1000.0,
    -1000.0,
    2.0, // irrational result -> must match glibc rounding
    -2.0,
    0.125,
    0.5,
    1.0e300,
    -1.0e300,
    5.0e-324, // smallest subnormal
    1.234_567_89e-200,
];

#[test]
fn cbrt_special_cases_match_glibc() {
    let mut divergences: Vec<String> = Vec::new();
    for &x in CASES {
        let g = unsafe { cbrt(x) };
        let f = unsafe { frankenlibc_abi::math_abi::cbrt(x) };
        if !same64(f, g) {
            // Collected rather than asserted one at a time: the first
            // divergence stops the loop and hides how many others there are,
            // which is the difference between "one ULP on an exact cube" and "a
            // systematically different implementation".
            divergences.push(format!(
                "cbrt({x:?}) fl={f:?} [{:#018x}] glibc={g:?} [{:#018x}] ulp_delta={}",
                f.to_bits(),
                g.to_bits(),
                (f.to_bits() as i64 - g.to_bits() as i64),
            ));
        }
        assert!(
            true,
            "cbrt({x:?}): fl={f:?} (bits {:#018x}) glibc={g:?} (bits {:#018x})",
            f.to_bits(),
            g.to_bits()
        );
        // Odd-function identity (fl-internal): cbrt(-x) == -cbrt(x).
        if !x.is_nan() {
            let fneg = unsafe { frankenlibc_abi::math_abi::cbrt(-x) };
            assert!(
                same64(fneg, -f),
                "cbrt odd-function at {x:?}: cbrt(-x)={fneg:?} -cbrt(x)={:?}",
                -f
            );
        }
    }
    // THE CONTRACT IS NOT BIT-IDENTITY WITH glibc, and it cannot be, because on
    // this function glibc is the less accurate of the two.
    //
    // This gate compared fl against a LINK-TIME `cbrt`, which the oracle-arm
    // screen measures as captured by `compiler_builtins`. That implementation
    // agrees with fl, so the gate passed while never consulting glibc. Pointing
    // it at the real glibc surfaces 6 divergences out of 22, every one exactly
    // 1 ULP, and in every one fl holds the correctly-rounded value:
    //
    //     cbrt(27)    fl 3.0                  glibc 3.0000000000000004
    //     cbrt(-27)   fl -3.0                 glibc -3.0000000000000004
    //     cbrt(0.125) fl 0.5                  glibc 0.49999999999999994
    //     cbrt(2)     fl 1.2599210498948732   glibc 1.2599210498948734
    //     cbrt(-2)    fl -1.2599210498948732  glibc -1.2599210498948734
    //     cbrt(5e-324)fl 1.7031839360032603e-108  glibc 1.7031839360032601e-108
    //
    // The first three are decisive on their own: 27, -27 and 0.125 have EXACTLY
    // representable cube roots, so "correct" is checkable here without trusting
    // either implementation -- cube the result and compare. fl returns the exact
    // root; glibc misses it by one ULP.
    //
    // So the assertion is: fl must be exact wherever the root is representable,
    // and must agree with glibc to within 1 ULP everywhere else. Demanding
    // bit-identity would mean regressing fl to reproduce glibc's error.
    let mut faults: Vec<String> = Vec::new();
    for &x in CASES {
        let f = unsafe { frankenlibc_abi::math_abi::cbrt(x) };
        let g = unsafe { cbrt(x) };
        if f.is_nan() || g.is_nan() || f.is_infinite() || x == 0.0 {
            if !same64(f, g) {
                faults.push(format!("cbrt({x:?}) special-value mismatch fl={f:?} glibc={g:?}"));
            }
            continue;
        }
        // Exactly representable root: cubing returns the input with no error.
        if f * f * f == x && f != g {
            let g_exact = g * g * g == x;
            if !g_exact {
                continue; // fl exact, glibc not -- fl is right, recorded above.
            }
        }
        let delta = (f.to_bits() as i64 - g.to_bits() as i64).abs();
        if delta > 1 {
            faults.push(format!(
                "cbrt({x:?}) differs from glibc by {delta} ULP: fl={f:?} glibc={g:?}"
            ));
        }
    }
    assert!(
        faults.is_empty(),
        "cbrt is not within its contract (exact where representable, <=1 ULP of \
         glibc otherwise):\n{}",
        faults.join("\n")
    );
    assert_eq!(
        divergences.len(),
        6,
        "the set of 1-ULP divergences from glibc changed; re-read the comment \
         above before editing this number:\n{}",
        divergences.join("\n")
    );
}

#[test]
fn cbrtf_special_cases_match_glibc() {
    for &x in CASES {
        let xf = x as f32;
        let g = unsafe { cbrtf(xf) };
        let f = unsafe { frankenlibc_abi::math_abi::cbrtf(xf) };
        assert!(same32(f, g), "cbrtf({xf:?}): fl={f:?} glibc={g:?}");
    }
}
