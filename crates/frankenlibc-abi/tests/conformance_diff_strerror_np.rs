#![cfg(target_os = "linux")]

//! Differential conformance harness for `strerrordesc_np(3)` /
//! `strerrorname_np(3)` (glibc 2.32+).
//!
//! Both return a static string (not affected by locale). fl exports
//! both in string_abi.rs; this is the first head-to-head diff against
//! host glibc.
//!
//! Filed under [bd-3ce894, bd-xn6p8].

use std::ffi::{CStr, c_char, c_int};

use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    fn strerrordesc_np(errnum: c_int) -> *const c_char;
    fn strerrorname_np(errnum: c_int) -> *const c_char;
}

/// Linux/glibc errno values for which glibc 2.32+ returns non-NULL
/// `strerrordesc_np` and `strerrorname_np` strings on x86_64.
///
/// The gaps at 41 and 58 are intentionally absent: glibc returns NULL
/// for both of those numeric slots.
const GLIBC_LINUX_ERRNO_CASES: &[c_int] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75,
    76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
    100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
    119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133,
];

const GLIBC_NULL_ERRNO_CASES: &[c_int] = &[41, 58, 134, 200, 1000, -1];

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
    for &e in GLIBC_LINUX_ERRNO_CASES.iter().chain(GLIBC_NULL_ERRNO_CASES) {
        let p_fl = fl::strerrordesc_np(e);
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
    assert!(
        divs.is_empty(),
        "strerrordesc_np divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_strerrorname_np_known_errnos() {
    let mut divs = Vec::new();
    for &e in GLIBC_LINUX_ERRNO_CASES.iter().chain(GLIBC_NULL_ERRNO_CASES) {
        let p_fl = fl::strerrorname_np(e);
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
    assert!(
        divs.is_empty(),
        "strerrorname_np divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn strerror_np_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc strerror_np family\",\"reference\":\"glibc\",\"functions\":2,\"errno_cases\":{},\"null_cases\":{},\"divergences\":0}}",
        GLIBC_LINUX_ERRNO_CASES.len(),
        GLIBC_NULL_ERRNO_CASES.len(),
    );
}
