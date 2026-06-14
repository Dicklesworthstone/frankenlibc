#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc totalorder oracle

//! IEEE-754 `totalorder`/`totalordermag` parity vs host glibc.
//!
//! These C23/IEEE predicates take their operands BY POINTER in modern glibc
//! (`int totalorder(const double *x, const double *y)`), not by value — an ABI
//! that changed from the original by-value form. frankenlibc mirrors the
//! pointer convention; this gate pins both that convention AND the total-order
//! semantics (the sign bit orders -NaN < -inf < ... < +inf < +NaN, and -0 < +0),
//! so a future "simplification" to by-value args — which would silently corrupt
//! every C caller by reading a float register as a pointer — is caught here.
//!
//! Both engines run in-process over an exhaustive special-value matrix
//! (quiet/signalling NaNs of both signs, ±0, ±inf, subnormals) where the
//! ordering quirks live.

use frankenlibc_abi::math_abi as fl;

unsafe extern "C" {
    fn totalorder(x: *const f64, y: *const f64) -> i32;
    fn totalordermag(x: *const f64, y: *const f64) -> i32;
    fn totalorderf(x: *const f32, y: *const f32) -> i32;
    fn totalordermagf(x: *const f32, y: *const f32) -> i32;
}

fn vals64() -> Vec<f64> {
    vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        2.5,
        -2.5,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::from_bits(0x7ff8_0000_0000_0000), // +qNaN
        f64::from_bits(0xfff8_0000_0000_0000), // -qNaN
        f64::from_bits(0x7ff0_0000_0000_0001), // +sNaN
        f64::from_bits(0xfff0_0000_0000_0001), // -sNaN
        f64::from_bits(0x7ff4_0000_0000_0000), // +sNaN (other payload)
        f64::from_bits(0xfff4_0000_0000_0000), // -sNaN (other payload)
        f64::MIN_POSITIVE,
        -f64::MIN_POSITIVE,
        5e-324,  // +smallest subnormal
        -5e-324, // -smallest subnormal
        1e300,
        -1e300,
    ]
}

#[test]
fn totalorder_matches_glibc_over_special_matrix() {
    let xs = vals64();
    let mut diffs = Vec::new();
    for &x in &xs {
        for &y in &xs {
            let h = unsafe { totalorder(&x, &y) };
            let f = unsafe { fl::totalorder(&x, &y) };
            if (h != 0) != (f != 0) {
                diffs.push(format!(
                    "totalorder({:#018x},{:#018x}): glibc={h} fl={f}",
                    x.to_bits(),
                    y.to_bits()
                ));
            }
            let hm = unsafe { totalordermag(&x, &y) };
            let fm = unsafe { fl::totalordermag(&x, &y) };
            if (hm != 0) != (fm != 0) {
                diffs.push(format!(
                    "totalordermag({:#018x},{:#018x}): glibc={hm} fl={fm}",
                    x.to_bits(),
                    y.to_bits()
                ));
            }

            let xf = x as f32;
            let yf = y as f32;
            let hf = unsafe { totalorderf(&xf, &yf) };
            let ff = unsafe { fl::totalorderf(&xf, &yf) };
            if (hf != 0) != (ff != 0) {
                diffs.push(format!(
                    "totalorderf({:#010x},{:#010x}): glibc={hf} fl={ff}",
                    xf.to_bits(),
                    yf.to_bits()
                ));
            }
            let hmf = unsafe { totalordermagf(&xf, &yf) };
            let fmf = unsafe { fl::totalordermagf(&xf, &yf) };
            if (hmf != 0) != (fmf != 0) {
                diffs.push(format!(
                    "totalordermagf({:#010x},{:#010x}): glibc={hmf} fl={fmf}",
                    xf.to_bits(),
                    yf.to_bits()
                ));
            }
        }
    }
    assert!(
        diffs.is_empty(),
        "totalorder family diverged from glibc:\n{}",
        diffs.join("\n")
    );
}

/// The `l`/`f32`/`f64`/`f64x` aliases must resolve to the same predicate as the
/// base symbols (they delegate to the same impl) and keep the pointer ABI.
#[test]
fn totalorder_aliases_agree_with_base() {
    let probe: &[(f64, f64)] = &[
        (0.0, -0.0),
        (-0.0, 0.0),
        (f64::from_bits(0xfff8_0000_0000_0000), f64::NEG_INFINITY),
        (f64::INFINITY, f64::from_bits(0x7ff8_0000_0000_0000)),
        (1.0, 1.0),
        (-1.0, 1.0),
    ];
    for &(x, y) in probe {
        let base = unsafe { fl::totalorder(&x, &y) };
        assert_eq!(unsafe { fl::totalorderl(&x, &y) }, base, "totalorderl");
        assert_eq!(unsafe { fl::totalorderf64(&x, &y) }, base, "totalorderf64");
        assert_eq!(
            unsafe { fl::totalorderf64x(&x, &y) },
            base,
            "totalorderf64x"
        );
        let basem = unsafe { fl::totalordermag(&x, &y) };
        assert_eq!(
            unsafe { fl::totalordermagl(&x, &y) },
            basem,
            "totalordermagl"
        );
    }
}
