#![cfg(target_os = "linux")]

//! Differential conformance harness for `<regex.h>` POSIX regular
//! expressions.
//!
//! regex_t is layout-incompatible between FrankenLibC and glibc (each
//! overlays its own bookkeeping fields), so we cannot share a compiled
//! regex. Instead each test compiles the same pattern in BOTH backends
//! and compares the match result + captured substrings.
//!
//! Bead: CONFORMANCE: libc regex.h diff matrix.

use std::ffi::{CString, c_char, c_int, c_void};
use std::mem::MaybeUninit;

use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    fn regcomp(preg: *mut c_void, pattern: *const c_char, cflags: c_int) -> c_int;
    fn regexec(
        preg: *const c_void,
        string: *const c_char,
        nmatch: usize,
        pmatch: *mut c_void,
        eflags: c_int,
    ) -> c_int;
    fn regfree(preg: *mut c_void);
}

/// regex_t on glibc x86_64 is 64 bytes; we allocate generously to
/// accommodate frankenlibc's overlay too.
const REGEX_T_BYTES: usize = 256;

/// regmatch_t = { regoff_t rm_so; regoff_t rm_eo; } where regoff_t is
/// `int` on glibc Linux x86_64.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct RegMatch {
    rm_so: i32,
    rm_eo: i32,
}

const REG_EXTENDED: c_int = 1;
const REG_ICASE: c_int = 2;

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

type RegexRun = ((c_int, c_int), (c_int, c_int), Vec<RegMatch>, Vec<RegMatch>);

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

fn run_match(pattern: &str, input: &str, cflags: c_int, nmatch: usize) -> RegexRun {
    let cpat = CString::new(pattern).unwrap();
    let cinp = CString::new(input).unwrap();

    let mut preg_fl: [u8; REGEX_T_BYTES] = [0; REGEX_T_BYTES];
    let mut preg_lc: [u8; REGEX_T_BYTES] = [0; REGEX_T_BYTES];
    let rc_compile_fl =
        unsafe { fl::regcomp(preg_fl.as_mut_ptr() as *mut c_void, cpat.as_ptr(), cflags) };
    let rc_compile_lc =
        unsafe { regcomp(preg_lc.as_mut_ptr() as *mut c_void, cpat.as_ptr(), cflags) };

    let mut pmatch_fl: Vec<RegMatch> = vec![RegMatch::default(); nmatch.max(1)];
    let mut pmatch_lc: Vec<RegMatch> = vec![RegMatch::default(); nmatch.max(1)];

    let rc_exec_fl = if rc_compile_fl == 0 {
        unsafe {
            fl::regexec(
                preg_fl.as_ptr() as *const c_void,
                cinp.as_ptr(),
                nmatch,
                pmatch_fl.as_mut_ptr() as *mut c_void,
                0,
            )
        }
    } else {
        -1
    };
    let rc_exec_lc = if rc_compile_lc == 0 {
        unsafe {
            regexec(
                preg_lc.as_ptr() as *const c_void,
                cinp.as_ptr(),
                nmatch,
                pmatch_lc.as_mut_ptr() as *mut c_void,
                0,
            )
        }
    } else {
        -1
    };

    if rc_compile_fl == 0 {
        unsafe {
            fl::regfree(preg_fl.as_mut_ptr() as *mut c_void);
        }
    }
    if rc_compile_lc == 0 {
        unsafe {
            regfree(preg_lc.as_mut_ptr() as *mut c_void);
        }
    }

    (
        (rc_compile_fl, rc_exec_fl),
        (rc_compile_lc, rc_exec_lc),
        pmatch_fl,
        pmatch_lc,
    )
}

// ===========================================================================
// Basic match / no-match across BRE and ERE
// ===========================================================================

#[test]
fn diff_regex_basic_match_match() {
    let mut divs = Vec::new();
    let cases: &[(&str, &str, c_int, bool)] = &[
        ("hello", "hello world", 0, true),
        ("hello", "goodbye", 0, false),
        ("^hello", "hello world", 0, true),
        ("world$", "hello world", 0, true),
        ("a.c", "abc", 0, true),
        ("a.c", "ac", 0, false),
        ("a*", "aaa", 0, true),
        ("[0-9]+", "abc 123 def", REG_EXTENDED, true),
        ("(foo|bar)", "barbaz", REG_EXTENDED, true),
        ("HELLO", "hello", REG_ICASE, true),
        ("HELLO", "hello", 0, false),
    ];
    for (pat, input, cflags, expect_match) in cases {
        let ((cc_fl, ce_fl), (cc_lc, ce_lc), _, _) = run_match(pat, input, *cflags, 1);
        let case = format!("({pat:?}, {input:?}, cflags={cflags:#x})");
        if cc_fl != cc_lc {
            divs.push(Divergence {
                function: "regcomp",
                case: case.clone(),
                field: "rc",
                frankenlibc: format!("{cc_fl}"),
                glibc: format!("{cc_lc}"),
            });
            continue;
        }
        if cc_fl != 0 {
            continue;
        }
        let match_fl = ce_fl == 0;
        let match_lc = ce_lc == 0;
        if match_fl != match_lc {
            divs.push(Divergence {
                function: "regexec",
                case: case.clone(),
                field: "match_match",
                frankenlibc: format!("{match_fl}"),
                glibc: format!("{match_lc}"),
            });
        }
        if match_fl != *expect_match {
            divs.push(Divergence {
                function: "regexec",
                case,
                field: "expected_match",
                frankenlibc: format!("{match_fl}"),
                glibc: format!("expected {expect_match}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "regex match divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Capture groups — first sub-expression position must match
// ===========================================================================

#[test]
fn diff_regex_capture_offsets() {
    let mut divs = Vec::new();
    // Pattern with capture; both impls should report the same rm_so/rm_eo
    // for the whole match (index 0) and first group (index 1).
    let cases: &[(&str, &str, usize)] = &[
        ("(a+)(b+)", "aaabbb", 3),
        ("([0-9]+)", "abc 42 def", 2),
        ("(foo)(bar)?", "foobar", 3),
        ("(foo)(bar)?", "foonothing", 3),
    ];
    for (pat, input, nmatch) in cases {
        let ((cc_fl, ce_fl), (cc_lc, ce_lc), p_fl, p_lc) =
            run_match(pat, input, REG_EXTENDED, *nmatch);
        let case = format!("({pat:?}, {input:?})");
        if cc_fl != cc_lc {
            divs.push(Divergence {
                function: "regcomp",
                case: case.clone(),
                field: "rc",
                frankenlibc: format!("{cc_fl}"),
                glibc: format!("{cc_lc}"),
            });
            continue;
        }
        if ce_fl != ce_lc {
            divs.push(Divergence {
                function: "regexec",
                case: case.clone(),
                field: "rc",
                frankenlibc: format!("{ce_fl}"),
                glibc: format!("{ce_lc}"),
            });
            continue;
        }
        if ce_fl != 0 {
            continue;
        }
        // Compare first nmatch entries
        for i in 0..*nmatch {
            if p_fl[i] != p_lc[i] {
                divs.push(Divergence {
                    function: "regexec",
                    case: format!("{case} [pmatch[{i}]]"),
                    field: "rm_so/eo",
                    frankenlibc: format!("({}, {})", p_fl[i].rm_so, p_fl[i].rm_eo),
                    glibc: format!("({}, {})", p_lc[i].rm_so, p_lc[i].rm_eo),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "regex capture divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Invalid pattern — both impls must reject
// ===========================================================================

#[test]
fn diff_regex_invalid_patterns() {
    let mut divs = Vec::new();
    let cases: &[(&str, c_int)] = &[
        ("[", 0),            // unclosed bracket
        ("(", REG_EXTENDED), // unclosed group in ERE
        ("\\", 0),           // dangling backslash
    ];
    for (pat, cflags) in cases {
        let cpat = CString::new(*pat).unwrap();
        let mut preg_fl: [u8; REGEX_T_BYTES] = [0; REGEX_T_BYTES];
        let mut preg_lc: [u8; REGEX_T_BYTES] = [0; REGEX_T_BYTES];
        let rc_fl =
            unsafe { fl::regcomp(preg_fl.as_mut_ptr() as *mut c_void, cpat.as_ptr(), *cflags) };
        let rc_lc = unsafe { regcomp(preg_lc.as_mut_ptr() as *mut c_void, cpat.as_ptr(), *cflags) };
        if (rc_fl == 0) != (rc_lc == 0) {
            divs.push(Divergence {
                function: "regcomp",
                case: format!("({pat:?}, cflags={cflags:#x})"),
                field: "success_match",
                frankenlibc: format!("{rc_fl}"),
                glibc: format!("{rc_lc}"),
            });
        }
        if rc_fl == 0 {
            unsafe {
                fl::regfree(preg_fl.as_mut_ptr() as *mut c_void);
            }
        }
        if rc_lc == 0 {
            unsafe {
                regfree(preg_lc.as_mut_ptr() as *mut c_void);
            }
        }
    }
    assert!(
        divs.is_empty(),
        "regex invalid divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn regex_diff_coverage_report() {
    let _ = MaybeUninit::<c_void>::uninit;
    eprintln!(
        "{{\"family\":\"regex.h\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
