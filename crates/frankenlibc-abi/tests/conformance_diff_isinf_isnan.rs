#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc isinf/isnan oracle

//! Differential gate for the isinf/isnan FUNCTION forms (bd-4i38y1) — these had
//! zero tests. glibc's bare isinf returns a SIGNED result (+1 for +inf, -1 for
//! -inf, 0 otherwise), and isnan returns 1 for NaN else 0. fl must match exactly
//! across the float lattice (±inf, NaN, ±0, finite, DBL_MAX, subnormal). No mocks.

use std::ffi::c_int;

unsafe extern "C" {
    fn isinf(x: f64) -> c_int;
    fn isnan(x: f64) -> c_int;
}

#[test]
fn isinf_isnan_match_glibc() {
    let vals: [f64; 11] = [
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        -f64::NAN,
        0.0,
        -0.0,
        1.0,
        -1.0,
        f64::MAX,
        f64::MIN_POSITIVE, // smallest normal
        f64::from_bits(1), // smallest subnormal
    ];
    for &v in &vals {
        let gi = unsafe { isinf(v) };
        let fi = unsafe { frankenlibc_abi::unistd_abi::isinf(v) };
        assert_eq!(
            fi,
            gi,
            "isinf({v}) [{:#018x}]: fl={fi} glibc={gi}",
            v.to_bits()
        );

        let gn = unsafe { isnan(v) };
        let fnn = unsafe { frankenlibc_abi::unistd_abi::isnan(v) };
        assert_eq!(
            fnn,
            gn,
            "isnan({v}) [{:#018x}]: fl={fnn} glibc={gn}",
            v.to_bits()
        );
    }
    // Pin the signed-isinf contract.
    assert_eq!(unsafe { isinf(f64::INFINITY) }, 1, "glibc isinf(+inf) = +1");
    assert_eq!(
        unsafe { isinf(f64::NEG_INFINITY) },
        -1,
        "glibc isinf(-inf) = -1"
    );
}
