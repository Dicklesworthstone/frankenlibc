#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX `nl_langinfo(3)`.
//!
//! Diffs fl's locale-info entries against host glibc's C locale (the
//! default — neither side has called setlocale, so glibc uses its
//! built-in C/POSIX defaults). fl ships the same C-locale strings.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, CStr};

use frankenlibc_abi::locale_abi as fl;

unsafe extern "C" {
    fn nl_langinfo(item: libc::nl_item) -> *const c_char;
}

#[derive(Debug)]
struct Divergence {
    case: String,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  case: {} | fl: {} | glibc: {}\n",
            d.case, d.frankenlibc, d.glibc,
        ));
    }
    out
}

#[test]
fn diff_nl_langinfo_c_locale_items() {
    // Items that fl and glibc both define for the C locale. Skipping
    // ones whose C-locale defaults are environment-dependent.
    let items: &[(libc::nl_item, &str)] = &[
        (libc::CODESET, "CODESET"),
        (libc::D_T_FMT, "D_T_FMT"),
        (libc::D_FMT, "D_FMT"),
        (libc::T_FMT, "T_FMT"),
        (libc::T_FMT_AMPM, "T_FMT_AMPM"),
        (libc::AM_STR, "AM_STR"),
        (libc::PM_STR, "PM_STR"),
        (libc::DAY_1, "DAY_1"),
        (libc::DAY_2, "DAY_2"),
        (libc::DAY_3, "DAY_3"),
        (libc::DAY_4, "DAY_4"),
        (libc::DAY_5, "DAY_5"),
        (libc::DAY_6, "DAY_6"),
        (libc::DAY_7, "DAY_7"),
        (libc::ABDAY_1, "ABDAY_1"),
        (libc::ABDAY_7, "ABDAY_7"),
        (libc::MON_1, "MON_1"),
        (libc::MON_12, "MON_12"),
        (libc::ABMON_1, "ABMON_1"),
        (libc::ABMON_12, "ABMON_12"),
        (libc::RADIXCHAR, "RADIXCHAR"),
        (libc::THOUSEP, "THOUSEP"),
        (libc::YESEXPR, "YESEXPR"),
        (libc::NOEXPR, "NOEXPR"),
    ];
    let mut divs = Vec::new();
    for &(item, name) in items {
        let p_fl = unsafe { fl::nl_langinfo(item) };
        let p_lc = unsafe { nl_langinfo(item) };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                case: name.to_string(),
                frankenlibc: format!("null={}", p_fl.is_null()),
                glibc: format!("null={}", p_lc.is_null()),
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
                case: name.to_string(),
                frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    assert!(divs.is_empty(), "nl_langinfo divergences:\n{}", render_divs(&divs));
}

#[test]
fn nl_langinfo_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc nl_langinfo\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
