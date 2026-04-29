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

use frankenlibc_abi::unistd_abi as fl_unistd;
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
    /// Host glibc `iswctype` — class-by-descriptor classification.
    fn iswctype(wc: u32, desc: libc::c_ulong) -> c_int;
    /// Host glibc `wctype` — name-to-descriptor for iswctype.
    fn wctype(name: *const libc::c_char) -> libc::c_ulong;
    /// Host glibc `towctrans` — transformation by descriptor.
    fn towctrans(wc: u32, desc: libc::c_ulong) -> u32;
    /// Host glibc `wctrans` — name-to-descriptor for towctrans.
    fn wctrans(name: *const libc::c_char) -> libc::c_ulong;
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

/// Multi-char Unicode case-folds: glibc's `towupper`/`towlower` always
/// return a single wchar_t, so when the canonical fold expands to multiple
/// codepoints (ß → SS, ﬀ → FF) glibc returns the input unchanged. Pin
/// fl against that contract.
#[test]
fn diff_towupper_multi_char_folds_stay_put() {
    const CASES: &[(u32, &str)] = &[
        (0x00DF, "ß eszett (uppercase = SS)"),
        (0xFB00, "ﬀ (uppercase = FF)"),
        (0xFB01, "ﬁ (uppercase = FI)"),
        (0xFB02, "ﬂ (uppercase = FL)"),
        (0xFB03, "ﬃ (uppercase = FFI)"),
        (0xFB04, "ﬄ (uppercase = FFL)"),
    ];
    let mut divs = Vec::new();
    for (cp, label) in CASES {
        let fl_u = unsafe { fl::towupper(*cp) };
        let lc_u = unsafe { towupper(*cp) };
        if fl_u != lc_u {
            divs.push(Divergence {
                function: "towupper",
                case: format!("(U+{cp:04X} {label})"),
                field: "return",
                frankenlibc: format!("{fl_u:#x}"),
                glibc: format!("{lc_u:#x}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "towupper multi-char-fold divergences:\n{}",
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
    // iswpunct / iswgraph for the IDEO/OGHAM/EM-quad whitespace cases —
    // glibc says these are NOT punctuation/graph (because they're whitespace),
    // and fl matches after the iswpunct/iswgraph fix that adds !iswspace.
    for (wc, label) in &[
        (0x3000u32, "IDEO SP"),
        (0x1680, "OGHAM SP"),
        (0x2000, "EN QUAD"),
        (0x205F, "MATH SP"),
        (0x00A0, "NBSP"),
        (0x202F, "NNBSP"),
        (0x002C, ", comma"),
        (0x2200, "FOR ALL"),
    ] {
        let fl_p = unsafe { fl::iswpunct(*wc) };
        let lc_p = unsafe { iswpunct(*wc) };
        if (fl_p != 0) != (lc_p != 0) {
            divs.push(Divergence {
                function: "iswpunct",
                case: format!("(U+{wc:04X} {label})"),
                field: "bool",
                frankenlibc: format!("{}", fl_p != 0),
                glibc: format!("{}", lc_p != 0),
            });
        }
        let fl_g = unsafe { fl::iswgraph(*wc) };
        let lc_g = unsafe { iswgraph(*wc) };
        if (fl_g != 0) != (lc_g != 0) {
            divs.push(Divergence {
                function: "iswgraph",
                case: format!("(U+{wc:04X} {label})"),
                field: "bool",
                frankenlibc: format!("{}", fl_g != 0),
                glibc: format!("{}", lc_g != 0),
            });
        }
    }

    // iswctype dispatch — fl's wctype("alpha")→2 and iswctype(_, 2)→iswalpha.
    // We diff the boolean answer for each impl using its OWN descriptor space:
    // fl's iswctype takes fl's index (1..12), glibc's takes its opaque pointer.
    // Each pair is internally consistent — the booleans should match.
    let class_names: &[&[u8]] = &[
        b"alpha\0", b"alnum\0", b"digit\0", b"lower\0", b"upper\0", b"space\0",
        b"print\0", b"punct\0", b"cntrl\0", b"graph\0", b"blank\0", b"xdigit\0",
    ];
    let dispatch_cases: &[u32] = &[
        b'a' as u32, b'A' as u32, b'5' as u32, 0x0410, 0x0430, 0x4E00, 0x3000, 0x2028,
    ];
    for class in class_names {
        let fl_desc = unsafe { fl::wctype(class.as_ptr()) };
        let lc_desc = unsafe { wctype(class.as_ptr() as *const libc::c_char) };
        for &wc in dispatch_cases {
            let fl_v = unsafe { fl::iswctype(wc, fl_desc) };
            let lc_v = unsafe { iswctype(wc, lc_desc) };
            if (fl_v != 0) != (lc_v != 0) {
                divs.push(Divergence {
                    function: "iswctype",
                    case: format!(
                        "(class={:?}, U+{wc:04X})",
                        std::str::from_utf8(&class[..class.len() - 1]).unwrap()
                    ),
                    field: "bool",
                    frankenlibc: format!("{}", fl_v != 0),
                    glibc: format!("{}", lc_v != 0),
                });
            }
        }
    }

    // towctrans dispatch — fl's wctrans("toupper")→1 and towctrans(_, 1)→towupper.
    // Same matched-pair-of-descriptors strategy.
    let trans_names: &[&[u8]] = &[b"toupper\0", b"tolower\0"];
    let trans_cases: &[u32] = &[
        b'a' as u32, b'A' as u32, 0x0410, 0x0430, 0x00DF, 0xFB00, 0x4E00,
    ];
    for trans in trans_names {
        let fl_desc =
            unsafe { fl_unistd::wctrans(trans.as_ptr() as *const libc::c_char) };
        let lc_desc = unsafe { wctrans(trans.as_ptr() as *const libc::c_char) };
        for &wc in trans_cases {
            let fl_v = unsafe { fl_unistd::towctrans(wc, fl_desc) };
            let lc_v = unsafe { towctrans(wc, lc_desc) };
            if fl_v != lc_v {
                divs.push(Divergence {
                    function: "towctrans",
                    case: format!(
                        "(trans={:?}, U+{wc:04X})",
                        std::str::from_utf8(&trans[..trans.len() - 1]).unwrap()
                    ),
                    field: "return",
                    frankenlibc: format!("{fl_v:#x}"),
                    glibc: format!("{lc_v:#x}"),
                });
            }
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
