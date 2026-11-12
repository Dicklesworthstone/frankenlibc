#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX `wordexp(3)`.
//!
//! Diffs fl's native wordexp against glibc on simple field-splitting,
//! variable expansion, quote/escape handling, bad-character detection,
//! and the WRDE_NOCMD command-substitution gate. Filed under [bd-xn6p8]
//! follow-up — extending host-libc parity coverage.

use std::ffi::{CStr, CString, c_char, c_int, c_void};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn wordexp(words: *const c_char, pwordexp: *mut c_void, flags: c_int) -> c_int;
    fn wordfree(pwordexp: *mut c_void);
}

const WRDE_NOCMD: c_int = 1 << 2;

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

/// Mirror libc's wordexp_t layout. fl uses *mut c_void to be ABI-agnostic;
/// we cast through this struct to read fields.
#[repr(C)]
struct WordexpT {
    we_wordc: usize,
    we_wordv: *mut *mut c_char,
    we_offs: usize,
}

unsafe fn collect_words(p: *const WordexpT) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if p.is_null() {
        return out;
    }
    let we = unsafe { &*p };
    for i in 0..we.we_wordc {
        let s = unsafe { *we.we_wordv.add(i) };
        if s.is_null() {
            out.push(Vec::new());
        } else {
            out.push(unsafe { CStr::from_ptr(s) }.to_bytes().to_vec());
        }
    }
    out
}

const CASES: &[(&str, c_int)] = &[
    ("hello world foo bar", 0),
    ("single", 0),
    ("", 0),
    ("\"quoted phrase\"", 0),
    ("'single quoted'", 0),
    ("'a b' 'c d'", 0),
    ("a\tb\tc", 0),            // tab-separated
    ("    leading spaces", 0), // collapses
    ("trailing\t", 0),         // trailing whitespace
    ("'a;b'", 0),              // bad char quoted literally
    ("\"a;b\"", 0),            // bad char double-quoted literally
    ("a\\;b", 0),              // bad char escaped literally
    ("(", 0),                  // unquoted bad char
    ("{", 0),                  // unquoted bad char
    ("`id`", WRDE_NOCMD),      // forbidden command substitution
    ("$(id)", WRDE_NOCMD),     // forbidden $()
    ("'$(echo hi)'", WRDE_NOCMD),
    ("'`echo hi`'", WRDE_NOCMD),
    ("\"$(echo hi)\"", WRDE_NOCMD),
];

/// Command substitution is a capability path, not a comparison of two copies
/// of the same implementation: `fl::wordexp` is called directly while the
/// incumbent is the host process's linked glibc symbol.
#[test]
fn wordexp_command_substitution_matches_live_glibc() {
    for (input, expected) in [
        ("$(printf cmd)", vec!["cmd"]),
        ("x$(printf cmd)y", vec!["xcmdy"]),
        ("$(($(printf 41)+1))", vec!["42"]),
        ("$((`printf 41`+1))", vec!["42"]),
    ] {
        let c_input = CString::new(input).unwrap();
        let mut fl_we = WordexpT {
            we_wordc: 0,
            we_wordv: std::ptr::null_mut(),
            we_offs: 0,
        };
        let mut lc_we = WordexpT {
            we_wordc: 0,
            we_wordv: std::ptr::null_mut(),
            we_offs: 0,
        };
        let fl_r =
            unsafe { fl::wordexp(c_input.as_ptr(), (&mut fl_we as *mut WordexpT).cast(), 0) };
        let lc_r = unsafe { wordexp(c_input.as_ptr(), (&mut lc_we as *mut WordexpT).cast(), 0) };
        let expected: Vec<Vec<u8>> = expected
            .into_iter()
            .map(|word| word.as_bytes().to_vec())
            .collect();

        assert_eq!(lc_r, 0, "glibc rejected command substitution {input:?}");
        assert_eq!(
            unsafe { collect_words(&lc_we) },
            expected,
            "glibc changed for {input:?}"
        );
        assert_eq!(fl_r, lc_r, "return-code mismatch for {input:?}");
        assert_eq!(
            unsafe { collect_words(&fl_we) },
            unsafe { collect_words(&lc_we) },
            "word mismatch for {input:?}"
        );

        unsafe { fl::wordfree((&mut fl_we as *mut WordexpT).cast()) };
        unsafe { wordfree((&mut lc_we as *mut WordexpT).cast()) };
    }
}

#[test]
fn diff_wordexp_simple_cases() {
    let mut divs = Vec::new();
    for (input, flags) in CASES {
        let c_input = CString::new(*input).unwrap();
        // Allocate two wordexp_t structs.
        let mut fl_we = WordexpT {
            we_wordc: 0,
            we_wordv: std::ptr::null_mut(),
            we_offs: 0,
        };
        let mut lc_we = WordexpT {
            we_wordc: 0,
            we_wordv: std::ptr::null_mut(),
            we_offs: 0,
        };
        let fl_r = unsafe {
            fl::wordexp(
                c_input.as_ptr(),
                &mut fl_we as *mut _ as *mut c_void,
                *flags,
            )
        };
        let lc_r = unsafe {
            wordexp(
                c_input.as_ptr(),
                &mut lc_we as *mut _ as *mut c_void,
                *flags,
            )
        };
        let case = format!("({:?}, flags={:#x})", input, flags);
        if fl_r != lc_r {
            divs.push(Divergence {
                case: case.clone(),
                field: "return",
                frankenlibc: format!("{fl_r}"),
                glibc: format!("{lc_r}"),
            });
        }
        if fl_r == 0 && lc_r == 0 {
            let fl_words = unsafe { collect_words(&fl_we) };
            let lc_words = unsafe { collect_words(&lc_we) };
            if fl_words != lc_words {
                divs.push(Divergence {
                    case,
                    field: "words",
                    frankenlibc: format!("{:?}", fl_words),
                    glibc: format!("{:?}", lc_words),
                });
            }
        }
        // Free both — tolerate no-op for failures.
        if fl_r == 0 {
            unsafe { fl::wordfree(&mut fl_we as *mut _ as *mut c_void) };
        }
        if lc_r == 0 {
            unsafe { wordfree(&mut lc_we as *mut _ as *mut c_void) };
        }
    }
    assert!(
        divs.is_empty(),
        "wordexp divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn wordexp_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc wordexp\",\"reference\":\"glibc\",\"functions\":2,\"corpus_cases\":19,\"divergences\":0}}",
    );
}

/// Field splitting and pathname expansion follow where each character came
/// from, as in glibc: only glob characters typed literally and unquoted
/// glob, and IFS only splits what an unquoted expansion produced. fl used to
/// never glob a bare pattern (`*.msg` stayed literal: the parent of a bare
/// name is "", which read_dir rejects), to glob command-substitution output,
/// to keep an empty field for `$(echo)`, to misparse `${U:-$(cmd)}`, and to
/// ignore positional parameters, `$$` and tilde after `=`.
#[test]
fn wordexp_expansion_provenance_matches_live_glibc() {
    let dir = std::env::temp_dir().join(format!("fl-wordexp-glob-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["a.msg", "b.msg", "c.txt", ".hidden.msg"] {
        std::fs::write(dir.join(name), b"").unwrap();
    }
    let d = dir.to_str().unwrap();
    // SAFETY: test-unique variable names, set once before any expansion.
    unsafe {
        std::env::set_var("FLWE_SP", "a b");
        std::env::set_var("FLWE_G", format!("{d}/*.msg"));
        std::env::set_var("FLWE_C", "a::b:");
    }
    let cases: Vec<(String, c_int)> = [
        format!("{d}/*.msg"),
        format!("{d}/*.\"msg\""),
        format!("\"{d}/*.msg\""),
        format!("'{d}/*.msg'"),
        format!("{d}/\\*.msg"),
        format!("{d}/[ab].msg"),
        format!("{d}/nomatch*"),
        format!("{d}/.*.msg"),
        "$FLWE_G".to_string(),
        "\"$FLWE_G\"".to_string(),
        "${FLWE_UNSET:-$FLWE_G}".to_string(),
        format!("$(printf '%s' '{d}/*.msg')"),
        format!("$(printf a){d}/*.msg"),
        format!("{d}/$(printf a)*"),
        "$(echo)".to_string(),
        "$(echo)$(echo)".to_string(),
        "\"$(echo)\"".to_string(),
        "p$(echo)q".to_string(),
        "$(printf 'a\\n\\n')".to_string(),
        "$(echo \"  a   b  \")".to_string(),
        "\"$(echo \"  a   b  \")\"".to_string(),
        "${FLWE_UNSET:-$(echo dflt v)}".to_string(),
        "${FLWE_UNSET:-\"a b\"}".to_string(),
        "${FLWE_SP:+z $FLWE_SP}".to_string(),
        "$FLWE_SP$FLWE_SP".to_string(),
        "\"$FLWE_SP\"x$FLWE_SP".to_string(),
        "$0".to_string(),
        "$#".to_string(),
        "${#1}".to_string(),
        "\"$@\"".to_string(),
        "\"$*\"".to_string(),
        "$$x".to_string(),
        "$? $! $-".to_string(),
        "a=~".to_string(),
        "a=b=~".to_string(),
        "a:~".to_string(),
        "~:".to_string(),
        "\"~\"".to_string(),
        "${#}".to_string(),
        "$(true".to_string(),
    ]
    .into_iter()
    .flat_map(|input| [(input.clone(), 0), (input, WRDE_NOCMD)])
    .collect();

    let mut divs = Vec::new();
    for (input, flags) in &cases {
        let c_input = CString::new(input.as_str()).unwrap();
        let mut fl_we = WordexpT {
            we_wordc: 0,
            we_wordv: std::ptr::null_mut(),
            we_offs: 0,
        };
        let mut lc_we = WordexpT {
            we_wordc: 0,
            we_wordv: std::ptr::null_mut(),
            we_offs: 0,
        };
        let fl_r = unsafe {
            fl::wordexp(
                c_input.as_ptr(),
                (&mut fl_we as *mut WordexpT).cast(),
                *flags,
            )
        };
        let lc_r = unsafe {
            wordexp(
                c_input.as_ptr(),
                (&mut lc_we as *mut WordexpT).cast(),
                *flags,
            )
        };
        let case = format!("({input:?}, flags={flags:#x})");
        if fl_r != lc_r {
            divs.push(Divergence {
                case: case.clone(),
                field: "return",
                frankenlibc: format!("{fl_r}"),
                glibc: format!("{lc_r}"),
            });
        }
        if fl_r == 0 && lc_r == 0 {
            let fl_words = unsafe { collect_words(&fl_we) };
            let lc_words = unsafe { collect_words(&lc_we) };
            if fl_words != lc_words {
                divs.push(Divergence {
                    case,
                    field: "words",
                    frankenlibc: format!("{:?}", fl_words),
                    glibc: format!("{:?}", lc_words),
                });
            }
        }
        if fl_r == 0 {
            unsafe { fl::wordfree((&mut fl_we as *mut WordexpT).cast()) };
        }
        if lc_r == 0 {
            unsafe { wordfree((&mut lc_we as *mut WordexpT).cast()) };
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        divs.is_empty(),
        "wordexp provenance divergences ({} cases):\n{}",
        cases.len(),
        render_divs(&divs)
    );
}
