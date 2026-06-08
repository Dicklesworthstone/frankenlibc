#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc isw* oracle (libc)

//! Differential scan of fl's wide character classifiers vs host glibc isw*,
//! over the full code-point range, in both the C and C.UTF-8 locales.
//!
//! fl's classifiers are locale-independent and driven by a generated, glibc-
//! exact UTF-8 ctype table (`wctype_table`, bd-2g7oyh.254), so they
//! intentionally diverge from glibc's *C-locale* (ASCII-only) isw* and match
//! glibc's *C.UTF-8* locale exactly. This test asserts ZERO divergences for all
//! twelve predicates in C.UTF-8 (regression guard for the table), and prints the
//! C-locale divergence counts as characterization (those are by-design: fl is
//! always UTF-8, like musl).

use std::ffi::{c_char, c_int};

use frankenlibc_core::string::wchar::{
    iswalnum as fl_iswalnum, iswalpha as fl_iswalpha, iswblank as fl_iswblank,
    iswcntrl as fl_iswcntrl, iswdigit as fl_iswdigit, iswgraph as fl_iswgraph,
    iswlower as fl_iswlower, iswprint as fl_iswprint, iswpunct as fl_iswpunct,
    iswspace as fl_iswspace, iswupper as fl_iswupper, iswxdigit as fl_iswxdigit,
};

unsafe extern "C" {
    fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
    fn iswalnum(wc: u32) -> c_int;
    fn iswalpha(wc: u32) -> c_int;
    fn iswblank(wc: u32) -> c_int;
    fn iswcntrl(wc: u32) -> c_int;
    fn iswdigit(wc: u32) -> c_int;
    fn iswgraph(wc: u32) -> c_int;
    fn iswlower(wc: u32) -> c_int;
    fn iswprint(wc: u32) -> c_int;
    fn iswpunct(wc: u32) -> c_int;
    fn iswspace(wc: u32) -> c_int;
    fn iswupper(wc: u32) -> c_int;
    fn iswxdigit(wc: u32) -> c_int;
}

const LC_CTYPE: c_int = 0;

type FlFn = fn(u32) -> bool;
type HostFn = unsafe extern "C" fn(u32) -> c_int;

#[allow(clippy::type_complexity)]
const FNS: &[(&str, FlFn, HostFn)] = &[
    ("iswalnum", fl_iswalnum, iswalnum),
    ("iswalpha", fl_iswalpha, iswalpha),
    ("iswblank", fl_iswblank, iswblank),
    ("iswcntrl", fl_iswcntrl, iswcntrl),
    ("iswdigit", fl_iswdigit, iswdigit),
    ("iswgraph", fl_iswgraph, iswgraph),
    ("iswlower", fl_iswlower, iswlower),
    ("iswprint", fl_iswprint, iswprint),
    ("iswpunct", fl_iswpunct, iswpunct),
    ("iswspace", fl_iswspace, iswspace),
    ("iswupper", fl_iswupper, iswupper),
    ("iswxdigit", fl_iswxdigit, iswxdigit),
];

/// Count fl-vs-glibc divergences for one classifier over the full code-point
/// range (skipping the surrogate block, which is never a valid wide char).
fn divergences(flf: FlFn, hostf: HostFn) -> (u64, String) {
    let mut div = 0u64;
    let mut first = String::new();
    for cp in 0u32..0x11_0000 {
        if (0xD800..=0xDFFF).contains(&cp) {
            continue;
        }
        let fl = flf(cp);
        let host = unsafe { hostf(cp) != 0 };
        if fl != host {
            div += 1;
            if first.is_empty() {
                first = format!("U+{cp:04X} fl={fl} glibc={host}");
            }
        }
    }
    (div, first)
}

fn set_locale(locale: &str) -> bool {
    let c = std::ffi::CString::new(locale).unwrap();
    !unsafe { setlocale(LC_CTYPE, c.as_ptr()) }.is_null()
}

#[test]
fn iswctype_differential_scan_vs_glibc() {
    for locale in ["C", "C.UTF-8"] {
        if !set_locale(locale) {
            eprintln!("=== locale {locale:?} unavailable, skipping ===");
            continue;
        }
        eprintln!("=== locale {locale:?} ===");
        for (name, flf, hostf) in FNS {
            let (div, first) = divergences(*flf, *hostf);
            eprintln!("  {name:<9} divergences={div:<7} first={first}");
        }
    }

    // Regression guard: in the C.UTF-8 locale every predicate is glibc-exact via
    // the generated ctype table (bd-2g7oyh.254).
    assert!(set_locale("C.UTF-8"), "C.UTF-8 locale required for the exactness guard");
    let mut failures = Vec::new();
    for (name, flf, hostf) in FNS {
        let (div, first) = divergences(*flf, *hostf);
        if div != 0 {
            failures.push(format!("{name}: {div} divergences (first {first})"));
        }
    }
    assert!(
        failures.is_empty(),
        "wide ctype classifiers diverge from glibc C.UTF-8:\n{}",
        failures.join("\n")
    );
}
