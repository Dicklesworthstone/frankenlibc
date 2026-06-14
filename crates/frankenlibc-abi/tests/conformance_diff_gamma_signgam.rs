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
    0.5, 1.0, 1.5, 2.5, 3.0, 5.0, 0.1, 0.9, 4.2, 10.0, 100.0,
    -0.5, -1.5, -2.5, -3.5, -0.1, -0.9, -2.1, -4.7, -0.001,
];

#[test]
fn gamma_signgam_matches_glibc() {
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
            *(&raw mut fl_signgam) = 0x5a5a;
            let v = fl_gamma(x);
            (v, *(&raw const fl_signgam))
        };
        if fs != hs {
            div.push(format!("gamma({x}): fl signgam={fs}, glibc signgam={hs}"));
        }
        // Value must agree (lgamma is transcendental; allow a few ULP).
        let tol = 1e-12 * hv.abs().max(1.0);
        if (fv - hv).abs() > tol && !(fv.is_infinite() && hv.is_infinite()) {
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
            *(&raw mut fl_signgam) = 0x5a5a;
            let v = fl_gammaf(xf);
            (v, *(&raw const fl_signgam))
        };
        if fs != hs {
            div.push(format!("gammaf({xf}): fl signgam={fs}, glibc signgam={hs}"));
        }
        let tol = 1e-5 * hv.abs().max(1.0);
        if (fv - hv).abs() > tol && !(fv.is_infinite() && hv.is_infinite()) {
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
