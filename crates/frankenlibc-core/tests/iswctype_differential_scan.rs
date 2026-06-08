#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc isw* oracle (libc)

//! Differential scan of fl's wide character classifiers
//! (iswalnum/iswalpha/iswdigit/iswlower/iswupper/iswspace/iswprint) vs host
//! glibc isw*, over the full code-point range, in both the C and C.UTF-8
//! locales.
//!
//! fl's classifiers are locale-independent and Unicode-aware (Rust's Unicode
//! tables), so they intentionally diverge from glibc's *C-locale* (ASCII-only)
//! isw*. The meaningful comparison is against glibc's *C.UTF-8* locale, which
//! is also Unicode-aware. There fl's `iswdigit` (ASCII '0'-'9' only, matching
//! glibc) and `iswspace` are exact; the remaining classifiers (iswalnum,
//! iswalpha, iswlower, iswupper, iswprint) still diverge because Rust's Unicode
//! version and category rules differ from glibc's UTF-8 ctype tables — tracked
//! as a deeper table-generation effort (bd-2g7oyh.254, same shape as the
//! wcwidth table fix bd-2g7oyh.194). This test asserts the two exact classifiers
//! and prints the others' divergence counts as characterization.

use std::ffi::{c_char, c_int};

use frankenlibc_core::string::wchar::{
    iswalnum as fl_iswalnum, iswalpha as fl_iswalpha, iswdigit as fl_iswdigit,
    iswlower as fl_iswlower, iswprint as fl_iswprint, iswspace as fl_iswspace,
    iswupper as fl_iswupper,
};

unsafe extern "C" {
    fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
    fn iswalnum(wc: c_int) -> c_int;
    fn iswalpha(wc: c_int) -> c_int;
    fn iswdigit(wc: c_int) -> c_int;
    fn iswlower(wc: c_int) -> c_int;
    fn iswupper(wc: c_int) -> c_int;
    fn iswspace(wc: c_int) -> c_int;
    fn iswprint(wc: c_int) -> c_int;
}

const LC_CTYPE: c_int = 0;

type FlFn = fn(u32) -> bool;
type HostFn = unsafe extern "C" fn(c_int) -> c_int;

#[allow(clippy::type_complexity)]
const FNS: &[(&str, FlFn, HostFn)] = &[
    ("iswalnum", fl_iswalnum, iswalnum),
    ("iswalpha", fl_iswalpha, iswalpha),
    ("iswdigit", fl_iswdigit, iswdigit),
    ("iswlower", fl_iswlower, iswlower),
    ("iswupper", fl_iswupper, iswupper),
    ("iswspace", fl_iswspace, iswspace),
    ("iswprint", fl_iswprint, iswprint),
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
        let host = unsafe { hostf(cp as c_int) != 0 };
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

    // Regression guards: in the C.UTF-8 locale fl's iswdigit and iswspace are
    // exact vs glibc. iswspace excludes U+2007 FIGURE SPACE (bd-2g7oyh.254);
    // iswdigit is ASCII '0'-'9' only, matching glibc.
    assert!(set_locale("C.UTF-8"), "C.UTF-8 locale required for the exact-classifier guards");
    let (digit_div, digit_first) = divergences(fl_iswdigit, iswdigit);
    assert_eq!(digit_div, 0, "iswdigit must match glibc C.UTF-8; first {digit_first}");
    let (space_div, space_first) = divergences(fl_iswspace, iswspace);
    assert_eq!(space_div, 0, "iswspace must match glibc C.UTF-8; first {space_first}");
}
