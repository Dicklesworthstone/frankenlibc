#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Focused differential guard for the printf composite fast paths shipped this
//! perf campaign — bare `%s` (bd-0ft0w3/bd-zum5jm), pure-literal no-`%`
//! (bd-zexi06), and bare `%f` (bd-ifl0s9). Each fast path must be byte-identical
//! to glibc, and crucially must match the *general* render path on the exact
//! triggers (precision>=1 + no width for `%f`; exact `%s`; no `%` for literals)
//! as well as the cases that deliberately fall back (NULL `%s`, `%%`, width,
//! precision 0, `%e`/`%g`). Compares fl's snprintf against the host glibc.

use frankenlibc_abi::stdio_abi as fl;
use std::ffi::{CString, c_char};

unsafe extern "C" {
    fn snprintf(b: *mut c_char, s: usize, f: *const c_char, ...) -> i32;
}

fn render_f(eng: u8, fmt: &CString, x: f64) -> String {
    let mut b = [0u8; 256];
    let n = if eng == 0 {
        unsafe { fl::snprintf(b.as_mut_ptr() as *mut c_char, 256, fmt.as_ptr(), x) }
    } else {
        unsafe { snprintf(b.as_mut_ptr() as *mut c_char, 256, fmt.as_ptr(), x) }
    };
    String::from_utf8_lossy(&b[..n.max(0) as usize]).into_owned()
}

fn render_s(eng: u8, fmt: &CString, s: *const c_char) -> String {
    let mut b = [0u8; 256];
    let n = if eng == 0 {
        unsafe { fl::snprintf(b.as_mut_ptr() as *mut c_char, 256, fmt.as_ptr(), s) }
    } else {
        unsafe { snprintf(b.as_mut_ptr() as *mut c_char, 256, fmt.as_ptr(), s) }
    };
    String::from_utf8_lossy(&b[..n.max(0) as usize]).into_owned()
}

fn render_lit(eng: u8, fmt: &CString) -> String {
    let mut b = [0u8; 256];
    let n = if eng == 0 {
        unsafe { fl::snprintf(b.as_mut_ptr() as *mut c_char, 256, fmt.as_ptr()) }
    } else {
        unsafe { snprintf(b.as_mut_ptr() as *mut c_char, 256, fmt.as_ptr()) }
    };
    String::from_utf8_lossy(&b[..n.max(0) as usize]).into_owned()
}

#[test]
fn bare_f_fastpath_matches_glibc() {
    // Mix of fast-path triggers (precision>=1, no width) and deliberate
    // fall-backs (precision 0, width, force/space sign, %e/%g).
    let fmts = [
        "%f", "%.2f", "%.6f", "%.1f", "%.0f", "%+.2f", "% .2f", "%8.2f", "%-8.2f",
        "%012.3f", "%.10f", "%e", "%.3e", "%g", "%.3g",
    ];
    let vals: &[f64] = &[
        0.0,
        -0.0,
        1.0,
        -1.0,
        3.14,
        -3.14,
        0.5,
        2.0,
        123.875,
        -123.875,
        0.1,
        -0.1,
        1000000.5,
        0.0009999,
        std::f64::consts::PI,
        -std::f64::consts::E,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        1e15,
        1e-7,
    ];
    for f in fmts {
        let fmt = CString::new(f).unwrap();
        for &x in vals {
            assert_eq!(
                render_f(0, &fmt, x),
                render_f(1, &fmt, x),
                "fl != glibc for fmt {f:?} value {x:?}"
            );
        }
    }
}

#[test]
fn bare_s_fastpath_matches_glibc() {
    let strings = ["hello", "", "x", "a longer string with spaces", "tab\tand\nnewline"];
    // Exact "%s" (fast path) plus surrounding-literal forms (general path).
    let fmts = ["%s", "[%s]", "%s\n", "prefix %s", "%10s", "%-10s", "%.3s"];
    for f in fmts {
        let fmt = CString::new(f).unwrap();
        for s in strings {
            let cs = CString::new(s).unwrap();
            assert_eq!(
                render_s(0, &fmt, cs.as_ptr()),
                render_s(1, &fmt, cs.as_ptr()),
                "fl != glibc for fmt {f:?} string {s:?}"
            );
        }
    }
    // NULL argument must fall back to render → glibc "(null)".
    let fmt = CString::new("%s").unwrap();
    assert_eq!(
        render_s(0, &fmt, std::ptr::null()),
        render_s(1, &fmt, std::ptr::null()),
        "fl != glibc for %s with NULL"
    );
}

#[test]
fn pure_literal_fastpath_matches_glibc() {
    // No-`%` formats take the verbatim fast path; `%%` must still fall back and
    // collapse to a single `%`.
    let fmts = [
        "plain text",
        "no percent here\n",
        "",
        "tab\tnewline\n",
        "100%% done",
        "%% leading",
        "trailing %%",
        "unicode: café ☃",
    ];
    for f in fmts {
        let fmt = CString::new(f).unwrap();
        assert_eq!(
            render_lit(0, &fmt),
            render_lit(1, &fmt),
            "fl != glibc for literal fmt {f:?}"
        );
    }
}
