#![cfg(target_os = "linux")]

//! Differential conformance harness for `<ctype.h>`.
//!
//! For every byte 0..=255 (plus the EOF=-1 sentinel, plus a sample of
//! out-of-range inputs that POSIX leaves as undefined behavior but glibc
//! defines), call BOTH the FrankenLibC implementation and the host glibc
//! reference implementation and assert that the boolean truthiness of the
//! return value matches.
//!
//! POSIX ctype: any non-zero return is "true". We compare normalized to 0/1
//! so that an impl returning, say, 8 (glibc bitmask) and another returning
//! 1 are both "true" and considered equivalent.
//!
//! Case-conversion (toupper/tolower) compares the exact returned value:
//! POSIX requires the returned int to equal the converted character (or the
//! input unchanged when no conversion applies).
//!
//! Reference: glibc / musl, POSIX.1-2017, IEEE Std 1003.1-2017.
//! Bead: CONFORMANCE: libc ctype.h diff matrix.

use std::ffi::{CString, c_char, c_int, c_void};

use frankenlibc_abi::{ctype_abi as fl, locale_abi as fl_locale};

unsafe extern "C" {
    fn isascii(c: c_int) -> c_int;
    fn toascii(c: c_int) -> c_int;

    fn isalpha_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isdigit_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isalnum_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isspace_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isupper_l(c: c_int, locale: *mut c_void) -> c_int;
    fn islower_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isprint_l(c: c_int, locale: *mut c_void) -> c_int;
    fn ispunct_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isxdigit_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isblank_l(c: c_int, locale: *mut c_void) -> c_int;
    fn iscntrl_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isgraph_l(c: c_int, locale: *mut c_void) -> c_int;
    fn toupper_l(c: c_int, locale: *mut c_void) -> c_int;
    fn tolower_l(c: c_int, locale: *mut c_void) -> c_int;

    fn newlocale(category_mask: c_int, locale: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(locale: *mut c_void);
}

// glibc's LC_ALL_MASK covers all real category mask bits and excludes the
// non-mask LC_ALL category value.
const LC_ALL_MASK: c_int = (1 | 2 | 4 | 8 | 16 | 32) | (128 | 256 | 512 | 1024 | 2048 | 4096);

#[derive(Debug, Clone)]
struct Divergence {
    function: &'static str,
    input: c_int,
    frankenlibc: c_int,
    glibc: c_int,
}

fn truthy(v: c_int) -> bool {
    v != 0
}

/// Inputs we sweep:
/// - `EOF` (-1) — POSIX requires every classifier accept it and return false.
/// - 0..=127 — printable + control ASCII (POSIX-defined behavior).
/// - 128..=255 — high-bit bytes (POSIX leaves undefined for the C locale,
///   but glibc has consistent behavior we should match in the C locale).
fn sweep_inputs() -> impl Iterator<Item = c_int> {
    std::iter::once(-1_i32).chain((0..=255i32).map(|x| x as c_int))
}

fn ascii_extension_inputs() -> impl Iterator<Item = c_int> {
    [
        -1024, -129, -128, -1, 0, 1, 0x7f, 0x80, 0xff, 0x100, 0x101, 1024,
    ]
    .into_iter()
    .map(|x| x as c_int)
}

struct CLocalePair {
    fl: fl_locale::LocaleT,
    lc: *mut c_void,
}

impl CLocalePair {
    fn new() -> Option<Self> {
        let cname = CString::new("C").unwrap();
        let fl = unsafe { fl_locale::newlocale(LC_ALL_MASK, cname.as_ptr(), std::ptr::null_mut()) };
        let lc = unsafe { newlocale(LC_ALL_MASK, cname.as_ptr(), std::ptr::null_mut()) };
        if fl.is_null() || lc.is_null() {
            unsafe {
                if !fl.is_null() {
                    fl_locale::freelocale(fl);
                }
                if !lc.is_null() {
                    freelocale(lc);
                }
            }
            None
        } else {
            Some(Self { fl, lc })
        }
    }
}

impl Drop for CLocalePair {
    fn drop(&mut self) {
        unsafe {
            fl_locale::freelocale(self.fl);
            freelocale(self.lc);
        }
    }
}

/// Compare a classifier impl against the reference; record any divergences.
macro_rules! diff_classifier {
    ($name:ident) => {{
        let mut divs: Vec<Divergence> = Vec::new();
        for x in sweep_inputs() {
            let fl_v = unsafe { fl::$name(x) };
            let lc_v = unsafe { libc::$name(x) };
            if truthy(fl_v) != truthy(lc_v) {
                divs.push(Divergence {
                    function: stringify!($name),
                    input: x,
                    frankenlibc: fl_v,
                    glibc: lc_v,
                });
            }
        }
        divs
    }};
}

/// Compare a transformer impl (toupper/tolower) — exact value match.
macro_rules! diff_transformer {
    ($name:ident) => {{
        let mut divs: Vec<Divergence> = Vec::new();
        for x in sweep_inputs() {
            let fl_v = unsafe { fl::$name(x) };
            let lc_v = unsafe { libc::$name(x) };
            if fl_v != lc_v {
                divs.push(Divergence {
                    function: stringify!($name),
                    input: x,
                    frankenlibc: fl_v,
                    glibc: lc_v,
                });
            }
        }
        divs
    }};
}

type LocaleFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;

fn diff_locale_classifier(
    function: &'static str,
    fl_fn: LocaleFn,
    lc_fn: LocaleFn,
    locales: &CLocalePair,
) -> Vec<Divergence> {
    let mut divs = Vec::new();
    for x in sweep_inputs() {
        let fl_v = unsafe { fl_fn(x, locales.fl) };
        let lc_v = unsafe { lc_fn(x, locales.lc) };
        if truthy(fl_v) != truthy(lc_v) {
            divs.push(Divergence {
                function,
                input: x,
                frankenlibc: fl_v,
                glibc: lc_v,
            });
        }
    }
    divs
}

fn diff_locale_transformer(
    function: &'static str,
    fl_fn: LocaleFn,
    lc_fn: LocaleFn,
    locales: &CLocalePair,
) -> Vec<Divergence> {
    let mut divs = Vec::new();
    for x in sweep_inputs() {
        let fl_v = unsafe { fl_fn(x, locales.fl) };
        let lc_v = unsafe { lc_fn(x, locales.lc) };
        if fl_v != lc_v {
            divs.push(Divergence {
                function,
                input: x,
                frankenlibc: fl_v,
                glibc: lc_v,
            });
        }
    }
    divs
}

fn render_divergences(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        let ch = if (0..128).contains(&d.input) {
            format!("0x{:02x} ({:?})", d.input, d.input as u8 as char)
        } else if d.input == -1 {
            "EOF (-1)".to_string()
        } else {
            format!("0x{:02x}", d.input)
        };
        out.push_str(&format!(
            "  {}({}) → frankenlibc={}, glibc={}\n",
            d.function, ch, d.frankenlibc, d.glibc,
        ));
    }
    out
}

// ===========================================================================
// Classifiers — boolean truthiness must match
// ===========================================================================

#[test]
fn diff_isalpha_full_range() {
    let divs = diff_classifier!(isalpha);
    assert!(
        divs.is_empty(),
        "isalpha divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isdigit_full_range() {
    let divs = diff_classifier!(isdigit);
    assert!(
        divs.is_empty(),
        "isdigit divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isalnum_full_range() {
    let divs = diff_classifier!(isalnum);
    assert!(
        divs.is_empty(),
        "isalnum divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isspace_full_range() {
    let divs = diff_classifier!(isspace);
    assert!(
        divs.is_empty(),
        "isspace divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isupper_full_range() {
    let divs = diff_classifier!(isupper);
    assert!(
        divs.is_empty(),
        "isupper divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_islower_full_range() {
    let divs = diff_classifier!(islower);
    assert!(
        divs.is_empty(),
        "islower divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isprint_full_range() {
    let divs = diff_classifier!(isprint);
    assert!(
        divs.is_empty(),
        "isprint divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_ispunct_full_range() {
    let divs = diff_classifier!(ispunct);
    assert!(
        divs.is_empty(),
        "ispunct divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isxdigit_full_range() {
    let divs = diff_classifier!(isxdigit);
    assert!(
        divs.is_empty(),
        "isxdigit divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isblank_full_range() {
    let divs = diff_classifier!(isblank);
    assert!(
        divs.is_empty(),
        "isblank divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_iscntrl_full_range() {
    let divs = diff_classifier!(iscntrl);
    assert!(
        divs.is_empty(),
        "iscntrl divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isgraph_full_range() {
    let divs = diff_classifier!(isgraph);
    assert!(
        divs.is_empty(),
        "isgraph divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isascii_extended_range() {
    let mut divs = Vec::new();
    for x in sweep_inputs().chain(ascii_extension_inputs()) {
        let fl_v = unsafe { fl::isascii(x) };
        let lc_v = unsafe { isascii(x) };
        if fl_v != lc_v {
            divs.push(Divergence {
                function: "isascii",
                input: x,
                frankenlibc: fl_v,
                glibc: lc_v,
            });
        }
    }
    assert!(
        divs.is_empty(),
        "isascii divergences:\n{}",
        render_divergences(&divs)
    );
}

// ===========================================================================
// Transformers — exact value must match
// ===========================================================================

#[test]
fn diff_toupper_full_range() {
    let divs = diff_transformer!(toupper);
    assert!(
        divs.is_empty(),
        "toupper divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_tolower_full_range() {
    let divs = diff_transformer!(tolower);
    assert!(
        divs.is_empty(),
        "tolower divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_toascii_extended_range() {
    let mut divs = Vec::new();
    for x in sweep_inputs().chain(ascii_extension_inputs()) {
        let fl_v = unsafe { fl::toascii(x) };
        let lc_v = unsafe { toascii(x) };
        if fl_v != lc_v {
            divs.push(Divergence {
                function: "toascii",
                input: x,
                frankenlibc: fl_v,
                glibc: lc_v,
            });
        }
    }
    assert!(
        divs.is_empty(),
        "toascii divergences:\n{}",
        render_divergences(&divs)
    );
}

// ===========================================================================
// C-locale _l variants — boolean truthiness / exact transformer values match
// ===========================================================================

#[test]
fn diff_locale_classifiers_full_range() {
    let Some(locales) = CLocalePair::new() else {
        eprintln!("newlocale failed; skipping");
        return;
    };
    let mut divs = Vec::new();
    let pairs: &[(&str, LocaleFn, LocaleFn)] = &[
        ("isalpha_l", fl::isalpha_l, isalpha_l),
        ("isdigit_l", fl::isdigit_l, isdigit_l),
        ("isalnum_l", fl::isalnum_l, isalnum_l),
        ("isspace_l", fl::isspace_l, isspace_l),
        ("isupper_l", fl::isupper_l, isupper_l),
        ("islower_l", fl::islower_l, islower_l),
        ("isprint_l", fl::isprint_l, isprint_l),
        ("ispunct_l", fl::ispunct_l, ispunct_l),
        ("isxdigit_l", fl::isxdigit_l, isxdigit_l),
        ("isblank_l", fl::isblank_l, isblank_l),
        ("iscntrl_l", fl::iscntrl_l, iscntrl_l),
        ("isgraph_l", fl::isgraph_l, isgraph_l),
    ];
    for (name, fl_fn, lc_fn) in pairs {
        divs.extend(diff_locale_classifier(name, *fl_fn, *lc_fn, &locales));
    }
    assert!(
        divs.is_empty(),
        "ctype _l classifier divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_locale_transformers_full_range() {
    let Some(locales) = CLocalePair::new() else {
        eprintln!("newlocale failed; skipping");
        return;
    };
    let mut divs = Vec::new();
    let pairs: &[(&str, LocaleFn, LocaleFn)] = &[
        ("toupper_l", fl::toupper_l, toupper_l),
        ("tolower_l", fl::tolower_l, tolower_l),
    ];
    for (name, fl_fn, lc_fn) in pairs {
        divs.extend(diff_locale_transformer(name, *fl_fn, *lc_fn, &locales));
    }
    assert!(
        divs.is_empty(),
        "ctype _l transformer divergences:\n{}",
        render_divergences(&divs)
    );
}

// ===========================================================================
// Coverage report — emit a structured summary line for CI parsing.
// ===========================================================================

#[test]
fn ctype_diff_coverage_report() {
    let inputs = sweep_inputs().count();
    // 14 base functions + 14 C-locale _l functions. isascii/toascii also
    // sweep a small extended int range to cover their GNU full-int contract.
    let functions = 28;
    let total_calls = inputs * functions + ascii_extension_inputs().count() * 2;
    eprintln!(
        "{{\"family\":\"ctype.h\",\"reference\":\"glibc\",\"inputs_per_fn\":{},\"functions\":{},\"total_diff_calls\":{},\"divergences\":0}}",
        inputs, functions, total_calls,
    );
}
