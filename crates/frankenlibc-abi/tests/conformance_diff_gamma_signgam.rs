#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

//! Differential conformance gate for the BSD `gamma`/`gammaf` `signgam`
//! side-effect. glibc's `gamma`/`gammaf` are aliases of `lgamma`/`lgammaf`: they
//! return log|Γ(x)| AND set the global `signgam` to the sign of Γ(x). fl computed
//! the value correctly but left `signgam` STALE — code using the classic
//! `r = gamma(x); if (signgam < 0) r = -r;` pattern got the wrong sign. This test
//! pins the value (within a tight tolerance) and the exact `signgam` against host
//! glibc across positive, fractional, and negative-fractional arguments (where
//! Γ alternates sign).

use frankenlibc_abi::math_abi::{gamma as fl_gamma, gammaf as fl_gammaf, signgam as fl_signgam};

unsafe extern "C" {
    fn gamma(x: f64) -> f64;
    fn gammaf(x: f32) -> f32;
    static mut signgam: i32;
}

const XS: &[f64] = &[
    0.5, 1.0, 1.5, 2.5, 3.0, 5.0, 0.1, 0.9, 4.2, 10.0, 100.0, -0.5, -1.5, -2.5, -3.5, -0.1, -0.9,
    -2.1, -4.7, -0.001,
];

#[test]
fn gamma_signgam_matches_glibc() {
    let _guard = GAMMA_LOCK.lock().unwrap();
    let mut div: Vec<String> = Vec::new();
    for &x in XS {
        // Host glibc gamma + its signgam.
        let (hv, hs) = unsafe {
            signgam = 0x5a5a;
            let v = gamma(x);
            (v, signgam)
        };
        // fl gamma + fl's signgam.
        let (fv, fs) = unsafe {
            fl_signgam = 0x5a5a;
            let v = fl_gamma(x);
            (v, fl_signgam)
        };
        if fs != hs {
            div.push(format!("gamma({x}): fl signgam={fs}, glibc signgam={hs}"));
        }
        // Value must agree (lgamma is transcendental; allow a few ULP).
        let tol = 1e-12 * hv.abs().max(1.0);
        if !fv.is_finite() || !hv.is_finite() || (fv - hv).abs() > tol {
            div.push(format!("gamma({x}) value: fl={fv:.17e}, glibc={hv:.17e}"));
        }
    }

    // gammaf
    for &x in XS {
        let xf = x as f32;
        let (hv, hs) = unsafe {
            signgam = 0x5a5a;
            let v = gammaf(xf);
            (v, signgam)
        };
        let (fv, fs) = unsafe {
            fl_signgam = 0x5a5a;
            let v = fl_gammaf(xf);
            (v, fl_signgam)
        };
        if fs != hs {
            div.push(format!("gammaf({xf}): fl signgam={fs}, glibc signgam={hs}"));
        }
        let tol = 1e-5 * hv.abs().max(1.0);
        if !fv.is_finite() || !hv.is_finite() || (fv - hv).abs() > tol {
            div.push(format!("gammaf({xf}) value: fl={fv:.9e}, glibc={hv:.9e}"));
        }
    }

    assert!(
        div.is_empty(),
        "gamma/gammaf signgam divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}

// The non-reentrant API writes process-global signgam; tests in this binary
// must not race one another while observing that side effect.
static GAMMA_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn gammaf_alias_matches_lgammaf_value_and_state() {
    use frankenlibc_abi::{errno_abi, math_abi as fl};

    let _guard = GAMMA_LOCK.lock().unwrap();
    let observe = |f: unsafe extern "C" fn(f32) -> f32, x: f32| {
        // SAFETY: scalar calls accept every input; the lock serializes signgam.
        unsafe {
            fl::signgam = 123;
            fl::__signgam = 123;
            errno_abi::set_abi_errno(libc::E2BIG);
            let value = f(x);
            (
                value.to_bits(),
                fl::signgam,
                fl::__signgam,
                *errno_abi::__errno_location(),
            )
        }
    };
    for x in [
        0.1,
        0.9,
        1.5,
        4.2,
        10.0,
        21.0,
        -0.5,
        -1.5,
        -2.5,
        -2.457_024_8,
        -2.747_682_6,
        0.0,
        -0.0,
        -1.0,
        f32::MAX,
        f32::INFINITY,
        f32::NEG_INFINITY,
    ] {
        assert_eq!(
            observe(fl::gammaf, x),
            observe(fl::lgammaf, x),
            "GNU gammaf alias contract for {:#010x}",
            x.to_bits()
        );
    }
    let mut state = 0x1234_5678_u32;
    for _ in 0..4096 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let x = f32::from_bits(state);
        assert_eq!(
            observe(fl::gammaf, x),
            observe(fl::lgammaf, x),
            "GNU gammaf alias contract for {state:#010x}"
        );
    }
}

#[test]
fn lgammaf_reentrant_poles_and_overflow_set_erange() {
    use frankenlibc_abi::{errno_abi, math_abi as fl};

    let _guard = GAMMA_LOCK.lock().unwrap();
    for x in [0.0, -0.0, -1.0, -2.0, -16_777_216.0, f32::MAX] {
        for initial in [0, libc::E2BIG] {
            let mut sign = 0;
            // SAFETY: sign is writable, and no concurrent test uses signgam.
            let (value, error, global) = unsafe {
                fl::signgam = 123;
                fl::__signgam = 456;
                errno_abi::set_abi_errno(initial);
                let value = fl::lgammaf_r(x, &mut sign);
                (
                    value,
                    *errno_abi::__errno_location(),
                    (fl::signgam, fl::__signgam),
                )
            };
            assert_eq!(value, f32::INFINITY, "lgammaf_r({x})");
            assert_eq!(error, libc::ERANGE, "lgammaf_r({x})");
            assert_eq!(sign, if x.is_sign_negative() { -1 } else { 1 });
            assert_eq!(global, (123, 456), "reentrant calls must not set signgam");
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn lgammaf_reentrant_nan_preserves_payload_errno_and_exception_kind() {
    use frankenlibc_abi::{errno_abi, math_abi as fl};

    unsafe extern "C" {
        fn feclearexcept(excepts: i32) -> i32;
        fn fetestexcept(excepts: i32) -> i32;
    }

    let _guard = GAMMA_LOCK.lock().unwrap();
    for bits in [0x7fc0_0123, 0xffc0_0123, 0x7fa0_0123, 0xffa0_0123] {
        let mut sign = 0;
        // SAFETY: the fenv mask is x86 FE_ALL_EXCEPT; sign is a live C int.
        let (value, error, flags) = unsafe {
            assert_eq!(feclearexcept(0x3d), 0);
            errno_abi::set_abi_errno(libc::E2BIG);
            let value = fl::lgammaf_r(f32::from_bits(bits), &mut sign);
            let error = *errno_abi::__errno_location();
            (value.to_bits(), error, fetestexcept(0x3d))
        };
        assert_eq!(value, bits | 0x0040_0000, "NaN payload must be retained");
        assert_eq!(error, libc::E2BIG);
        assert_eq!(sign, 1);
        assert_eq!(flags, i32::from(bits & 0x0040_0000 == 0));
    }
}
