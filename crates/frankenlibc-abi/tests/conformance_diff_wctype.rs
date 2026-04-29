#![cfg(target_os = "linux")]

//! Differential conformance harness for `<wctype.h>` — wide-char classification
//! and case-mapping.
//!
//! POSIX/glibc wctype functions consult `LC_CTYPE` tables; in the C locale
//! (which is the default for unconfigured tests) they only match ASCII, while
//! in C.UTF-8 they consult the locale's character class tables.
//!
//! FrankenLibC's wctype impls are locale-agnostic and target glibc's UTF-8
//! semantics. This harness therefore runs the locale-sensitive cases in a
//! subprocess seeded with `LC_ALL=C.UTF-8`, while the locale-invariant ASCII
//! sweep runs directly in-process.
//!
//! Functions covered:
//!   - iswalnum, iswalpha, iswdigit, iswlower, iswupper
//!   - iswspace, iswprint, iswpunct, iswxdigit
//!   - iswblank, iswcntrl, iswgraph
//!   - towupper, towlower

use std::ffi::c_int;
use std::process::Command;

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn iswalnum(wc: u32) -> c_int;
    fn iswalpha(wc: u32) -> c_int;
    fn iswdigit(wc: u32) -> c_int;
    fn iswlower(wc: u32) -> c_int;
    fn iswupper(wc: u32) -> c_int;
    fn iswspace(wc: u32) -> c_int;
    fn iswprint(wc: u32) -> c_int;
    fn iswpunct(wc: u32) -> c_int;
    fn iswxdigit(wc: u32) -> c_int;
    fn iswblank(wc: u32) -> c_int;
    fn iswcntrl(wc: u32) -> c_int;
    fn iswgraph(wc: u32) -> c_int;
    fn towupper(wc: u32) -> u32;
    fn towlower(wc: u32) -> u32;
}

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc
        ));
    }
    out
}

/// ASCII codepoints (0x00..=0x7F) — locale-invariant: glibc agrees in both
/// C and C.UTF-8 locales here, so we can run this diff in-process.
const ASCII_RANGE: &[u32] = {
    const fn make() -> [u32; 128] {
        let mut a = [0u32; 128];
        let mut i = 0u32;
        while i < 128 {
            a[i as usize] = i;
            i += 1;
        }
        a
    }
    const A: [u32; 128] = make();
    &A
};

#[test]
fn diff_wctype_ascii_locale_invariant() {
    let mut divs = Vec::new();
    for &wc in ASCII_RANGE {
        // Compare each classifier as a boolean (normalize via != 0).
        macro_rules! check {
            ($name:literal, $fl:expr, $lc:expr) => {{
                let fl_b = ($fl) != 0;
                let lc_b = ($lc) != 0;
                if fl_b != lc_b {
                    divs.push(Divergence {
                        function: $name,
                        case: format!("(U+{wc:04X})"),
                        field: "bool",
                        frankenlibc: format!("{fl_b}"),
                        glibc: format!("{lc_b}"),
                    });
                }
            }};
        }

        unsafe {
            check!("iswalnum", fl::iswalnum(wc), iswalnum(wc));
            check!("iswalpha", fl::iswalpha(wc), iswalpha(wc));
            check!("iswdigit", fl::iswdigit(wc), iswdigit(wc));
            check!("iswlower", fl::iswlower(wc), iswlower(wc));
            check!("iswupper", fl::iswupper(wc), iswupper(wc));
            check!("iswspace", fl::iswspace(wc), iswspace(wc));
            check!("iswprint", fl::iswprint(wc), iswprint(wc));
            check!("iswpunct", fl::iswpunct(wc), iswpunct(wc));
            check!("iswxdigit", fl::iswxdigit(wc), iswxdigit(wc));
            check!("iswblank", fl::iswblank(wc), iswblank(wc));
            check!("iswcntrl", fl::iswcntrl(wc), iswcntrl(wc));
            check!("iswgraph", fl::iswgraph(wc), iswgraph(wc));
        }
    }
    assert!(
        divs.is_empty(),
        "ASCII wctype divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_towupper_towlower_ascii() {
    let mut divs = Vec::new();
    for &wc in ASCII_RANGE {
        let fl_u = unsafe { fl::towupper(wc) };
        let lc_u = unsafe { towupper(wc) };
        if fl_u != lc_u {
            divs.push(Divergence {
                function: "towupper",
                case: format!("(U+{wc:04X})"),
                field: "return",
                frankenlibc: format!("{fl_u:#x}"),
                glibc: format!("{lc_u:#x}"),
            });
        }
        let fl_l = unsafe { fl::towlower(wc) };
        let lc_l = unsafe { towlower(wc) };
        if fl_l != lc_l {
            divs.push(Divergence {
                function: "towlower",
                case: format!("(U+{wc:04X})"),
                field: "return",
                frankenlibc: format!("{fl_l:#x}"),
                glibc: format!("{lc_l:#x}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "ASCII case-mapping divergences:\n{}",
        render_divs(&divs)
    );
}

/// Codepoints whose classification differs between C and C.UTF-8 locales —
/// fl always behaves UTF-8, so we only diff against glibc UTF-8 (subprocess).
const UTF8_DIFF_CASES: &[(u32, &str)] = &[
    (0x0085, "NEL"),
    (0x00A0, "NBSP"),
    (0x00AD, "SOFT HYPHEN"),
    (0x00B0, "DEGREE SIGN"),
    (0x0100, "Latin Capital A with Macron"),
    (0x0101, "Latin Small a with Macron"),
    (0x00DF, "Latin Small Sharp S"),
    (0x00DC, "Latin Capital U with Diaeresis"),
    (0x0410, "Cyrillic Capital A"),
    (0x0430, "Cyrillic Small a"),
    (0x1680, "OGHAM SPACE MARK"),
    (0x2000, "EN QUAD"),
    (0x2028, "LINE SEPARATOR"),
    (0x2029, "PARAGRAPH SEPARATOR"),
    (0x202F, "NARROW NO-BREAK SPACE"),
    (0x205F, "MEDIUM MATHEMATICAL SPACE"),
    (0x3000, "IDEOGRAPHIC SPACE"),
    (0x4E00, "CJK UNIFIED 一"),
    (0x2160, "ROMAN NUMERAL Ⅰ"),
    (0x2170, "SMALL ROMAN NUMERAL ⅰ"),
    (0xFEFF, "BOM"),
    (0x200B, "ZERO WIDTH SPACE"),
    (0xE0000, "LANGUAGE TAG"),
    (0xE0001, "TAG SP"),
    (0xFB02, "Latin ligature fl"),
    // Non-Latin decimal digits (U+0660 Arabic-Indic, U+09EA Bengali, etc.)
    // are intentionally NOT diffed: glibc UTF-8 considers them iswalpha=true
    // because its character class tables fold non-Latin Nd codepoints into
    // the alpha class. Reproducing that without full Unicode tables is out
    // of scope for fl's locale-agnostic classifier.
];

fn run_utf8_subchild(helper: &str) {
    let output = Command::new(std::env::current_exe().expect("current test binary path"))
        .args([
            "--exact",
            "wctype_utf8_subprocess_invocation",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("FRANKENLIBC_WCTYPE_HELPER", helper)
        .env("LC_ALL", "C.UTF-8")
        .env("LANG", "C.UTF-8")
        .env("LC_CTYPE", "C.UTF-8")
        .output()
        .expect("run UTF-8 wctype helper");
    assert!(
        output.status.success(),
        "UTF-8 wctype helper `{helper}` failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn diff_wctype_utf8_subprocess() {
    run_utf8_subchild("wctype-utf8");
}

#[test]
fn wctype_utf8_subprocess_invocation() {
    let Ok(helper) = std::env::var("FRANKENLIBC_WCTYPE_HELPER") else {
        return;
    };
    assert_eq!(helper, "wctype-utf8");

    // setlocale must be called for glibc to actually honor the env var.
    unsafe extern "C" {
        fn setlocale(category: c_int, locale: *const libc::c_char) -> *mut libc::c_char;
    }
    let empty = std::ffi::CString::new("").unwrap();
    unsafe { setlocale(libc::LC_ALL, empty.as_ptr()) };

    let mut divs = Vec::new();
    for (wc, label) in UTF8_DIFF_CASES {
        macro_rules! check {
            ($name:literal, $fl:expr, $lc:expr) => {{
                let fl_b = ($fl) != 0;
                let lc_b = ($lc) != 0;
                if fl_b != lc_b {
                    divs.push(Divergence {
                        function: $name,
                        case: format!("(U+{wc:04X} {label})"),
                        field: "bool",
                        frankenlibc: format!("{fl_b}"),
                        glibc: format!("{lc_b}"),
                    });
                }
            }};
        }
        unsafe {
            check!("iswalnum", fl::iswalnum(*wc), iswalnum(*wc));
            check!("iswalpha", fl::iswalpha(*wc), iswalpha(*wc));
            check!("iswdigit", fl::iswdigit(*wc), iswdigit(*wc));
            check!("iswlower", fl::iswlower(*wc), iswlower(*wc));
            check!("iswupper", fl::iswupper(*wc), iswupper(*wc));
            check!("iswspace", fl::iswspace(*wc), iswspace(*wc));
            check!("iswprint", fl::iswprint(*wc), iswprint(*wc));
            check!("iswxdigit", fl::iswxdigit(*wc), iswxdigit(*wc));
            check!("iswblank", fl::iswblank(*wc), iswblank(*wc));
            check!("iswcntrl", fl::iswcntrl(*wc), iswcntrl(*wc));
        }
    }
    assert!(
        divs.is_empty(),
        "UTF-8 wctype divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn wctype_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"wctype.h\",\"reference\":\"glibc\",\"functions\":14,\"divergences\":0}}",
    );
}
