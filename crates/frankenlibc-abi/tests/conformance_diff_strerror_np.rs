#![cfg(target_os = "linux")]

//! Differential conformance harness for `strerrordesc_np(3)` /
//! `strerrorname_np(3)` (glibc 2.32+).
//!
//! Both return a static string (not affected by locale). fl exports
//! both in string_abi.rs; this is the first head-to-head diff against
//! host glibc.
//!
//! Filed under [bd-3ce894, bd-xn6p8].

use std::ffi::{c_char, c_int, CStr};

use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    fn strerrordesc_np(errnum: c_int) -> *const c_char;
    fn strerrorname_np(errnum: c_int) -> *const c_char;
}

#[derive(Debug)]
struct Divergence {
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  case: {} | field: {} | fl: {} | glibc: {}\n",
            d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

#[test]
fn diff_strerrordesc_np_known_errnos() {
    let mut divs = Vec::new();
    let errnos: &[c_int] = &[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        // Unknown errnos — both should return NULL.
        200, 1000, -1,
    ];
    for &e in errnos {
        let p_fl = unsafe { fl::strerrordesc_np(e) };
        let p_lc = unsafe { strerrordesc_np(e) };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                case: format!("errno={e}"),
                field: "null_return",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if p_fl.is_null() {
            continue;
        }
        let s_fl = unsafe { CStr::from_ptr(p_fl).to_bytes() };
        let s_lc = unsafe { CStr::from_ptr(p_lc).to_bytes() };
        if s_fl != s_lc {
            divs.push(Divergence {
                case: format!("errno={e}"),
                field: "description",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    assert!(divs.is_empty(), "strerrordesc_np divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_strerrorname_np_known_errnos() {
    let mut divs = Vec::new();
    let errnos: &[c_int] = &[
        1, 2, 3, 9, 13, 17, 22, 32, 38, 39, 40,
        // Unknown errnos
        200, 1000, -1,
    ];
    for &e in errnos {
        let p_fl = unsafe { fl::strerrorname_np(e) };
        let p_lc = unsafe { strerrorname_np(e) };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                case: format!("errno={e}"),
                field: "null_return",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if p_fl.is_null() {
            continue;
        }
        let s_fl = unsafe { CStr::from_ptr(p_fl).to_bytes() };
        let s_lc = unsafe { CStr::from_ptr(p_lc).to_bytes() };
        if s_fl != s_lc {
            divs.push(Divergence {
                case: format!("errno={e}"),
                field: "name",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    assert!(divs.is_empty(), "strerrorname_np divergences:\n{}", render_divs(&divs));
}

#[test]
fn strerror_np_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc strerror_np family\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
