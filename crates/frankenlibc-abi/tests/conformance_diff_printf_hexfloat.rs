#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use frankenlibc_abi::stdio_abi as fl;
use std::ffi::{CString, c_char};

unsafe extern "C" {
    fn snprintf(b: *mut c_char, s: usize, f: *const c_char, ...) -> i32;
}

fn render(eng: u8, fmt: &CString, x: f64) -> String {
    let mut b = [0u8; 128];
    let n = if eng == 0 {
        unsafe { fl::snprintf(b.as_mut_ptr() as *mut c_char, 128, fmt.as_ptr(), x) }
    } else {
        unsafe { snprintf(b.as_mut_ptr() as *mut c_char, 128, fmt.as_ptr(), x) }
    };
    String::from_utf8_lossy(&b[..n.max(0) as usize]).into_owned()
}

#[test]
fn printf_hexfloat_a_matches_glibc() {
    let vals: &[f64] = &[
        0.0,
        -0.0,
        1.0,
        -1.0,
        2.0,
        0.5,
        0.25,
        1.5,
        3.0,
        0.1,
        -0.1,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        -f64::NAN,
        f64::MIN_POSITIVE,
        -f64::MIN_POSITIVE,
        f64::MAX,
        f64::MIN,
        5e-324,
        -5e-324,
        4.9e-324,
        1e-323,
        2.2250738585072014e-308, // subnormals + boundary
        1.0000000000000002,
        0.9999999999999999,
        123.875,
        -123.875,
        std::f64::consts::PI,
        std::f64::consts::E,
        1e300,
        1e-300,
        65504.0,
        // values exercising round-to-even at various precisions
        1.0009765625,
        1.00048828125,
        1.000244140625,
        255.5,
        0.000030517578125,
    ];
    // %a/%A with width/precision/flags — the hard part is precision rounding,
    // the implicit leading digit, the p-exponent, and subnormal normalization.
    let fmts = [
        "%a", "%A", "%.0a", "%.1a", "%.2a", "%.3a", "%.5a", "%.13a", "%.20a", "%20a", "%-20a|",
        "%020a", "%+a", "% a", "%#a", "%#.0a", "%+.2a", "%30.10a", "%-30.4A|", "%.0A", "%#.0A",
    ];
    let mut div = Vec::new();
    for fmt in fmts {
        let cf = CString::new(fmt).unwrap();
        for &x in vals {
            let a = render(0, &cf, x);
            let b = render(1, &cf, x);
            if a != b {
                div.push(format!("snprintf({fmt:?}, {x:e}): fl={a:?} glibc={b:?}"));
            }
        }
    }
    if !div.is_empty() {
        eprintln!("PRINTF %a/%A DIVERGENCES ({}):", div.len());
        for d in div.iter().take(120) {
            eprintln!("  {d}");
        }
    }
    assert!(
        div.is_empty(),
        "{} printf %a/%A divergences vs glibc",
        div.len()
    );
}
