//! Differential gate for the IEEE 754-2019 / C23 minimum/maximum family
//! (fmaximum/fminimum, *_num, *_mag, *_mag_num, and the older fmaxmag/fminmag)
//! and f32, vs host glibc, over the full pairwise matrix of signed zeros, signed
//! infinities, NaN, and assorted finite values. These selection functions have
//! intricate NaN-propagation and signed-zero semantics and had NO differential
//! coverage. glibc reached via dlsym (bypasses fl's no_mangle interposition).
//!
//! Pinned a real fix: fmaxmag/fminmag used fmax/fmin on an equal-magnitude tie,
//! so fmaxmag(+0,-0) returned +0 where glibc returns -0 (the larger/smaller
//! VALUE, `if x>y`, not fmax).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use frankenlibc_abi::math_abi as fl;
use std::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
    fn dlopen(f: *const c_char, fl: c_int) -> *mut c_void;
    fn dlsym(h: *mut c_void, s: *const c_char) -> *mut c_void;
}

type HostBinaryFn = extern "C" fn(f64, f64) -> f64;
type FlBinaryFn = fn(f64, f64) -> f64;
type BinaryCase = (&'static str, FlBinaryFn);

fn gsym(h: *mut c_void, n: &str) -> Option<HostBinaryFn> {
    let mut nm = n.as_bytes().to_vec();
    nm.push(0);
    let p = unsafe { dlsym(h, nm.as_ptr() as *const c_char) };
    if p.is_null() {
        None
    } else {
        Some(unsafe { core::mem::transmute::<*mut c_void, HostBinaryFn>(p) })
    }
}

#[test]
fn fmaxmin_family_matches_glibc() {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), 2) };
    assert!(!h.is_null(), "dlopen libm failed");
    let vals = [
        0.0f64,
        -0.0,
        1.0,
        -1.0,
        2.0,
        -2.0,
        0.5,
        -3.0,
        1e300,
        -1e300,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        -f64::NAN,
    ];
    let funcs: &[BinaryCase] = &[
        ("fmaximum", |a, b| unsafe { fl::fmaximum(a, b) }),
        ("fminimum", |a, b| unsafe { fl::fminimum(a, b) }),
        ("fmaximum_num", |a, b| unsafe { fl::fmaximum_num(a, b) }),
        ("fminimum_num", |a, b| unsafe { fl::fminimum_num(a, b) }),
        ("fmaximum_mag", |a, b| unsafe { fl::fmaximum_mag(a, b) }),
        ("fminimum_mag", |a, b| unsafe { fl::fminimum_mag(a, b) }),
        ("fmaximum_mag_num", |a, b| unsafe {
            fl::fmaximum_mag_num(a, b)
        }),
        ("fminimum_mag_num", |a, b| unsafe {
            fl::fminimum_mag_num(a, b)
        }),
        ("fmaxmag", |a, b| unsafe { fl::fmaxmag(a, b) }),
        ("fminmag", |a, b| unsafe { fl::fminmag(a, b) }),
    ];
    let mut div: Vec<String> = Vec::new();
    let mut covered = 0;
    for (name, flf) in funcs {
        let Some(gf) = gsym(h, name) else {
            panic!("glibc is missing {name} — cannot run differential gate");
        };
        covered += 1;
        for &a in &vals {
            for &b in &vals {
                let fv = flf(a, b);
                let gv = gf(a, b);
                let ok = if gv.is_nan() {
                    fv.is_nan()
                } else {
                    fv.to_bits() == gv.to_bits()
                };
                if !ok {
                    div.push(format!(
                        "{}({:+},{:+}): fl={:016x} glibc={:016x}",
                        name,
                        a,
                        b,
                        fv.to_bits(),
                        gv.to_bits()
                    ));
                }
            }
        }
    }
    assert_eq!(
        covered, 10,
        "expected all 10 family members present in glibc"
    );
    assert!(
        div.is_empty(),
        "fmax/fmin-family divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
