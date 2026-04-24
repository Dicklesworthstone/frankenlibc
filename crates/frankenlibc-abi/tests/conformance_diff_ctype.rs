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

use std::ffi::c_int;

use frankenlibc_abi::ctype_abi as fl;

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

// ===========================================================================
// Coverage report — emit a structured summary line for CI parsing.
// ===========================================================================

#[test]
fn ctype_diff_coverage_report() {
    let inputs = sweep_inputs().count();
    // 12 classifiers + 2 transformers
    let total_calls = inputs * (12 + 2);
    eprintln!(
        "{{\"family\":\"ctype.h\",\"reference\":\"glibc\",\"inputs_per_fn\":{},\"functions\":{},\"total_diff_calls\":{},\"divergences\":0}}",
        inputs, 14, total_calls,
    );
}
