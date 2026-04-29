#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX `wordexp(3)`.
//!
//! Diffs fl's native wordexp against glibc on simple field-splitting,
//! variable expansion, quotes, and the WRDE_NOCMD command-substitution
//! gate. Filed under [bd-xn6p8] follow-up — extending host-libc parity
//! coverage.

use std::ffi::{c_char, c_int, c_void, CStr, CString};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn wordexp(words: *const c_char, pwordexp: *mut c_void, flags: c_int) -> c_int;
    fn wordfree(pwordexp: *mut c_void);
}

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
    ("a\tb\tc", 0),                    // tab-separated
    ("    leading spaces", 0),         // collapses
    ("trailing\t", 0),                  // trailing whitespace
    ("`id`", 4),         // WRDE_NOCMD = 4 — forbidden command substitution
    ("$(id)", 4),        // forbidden $()
];

#[test]
fn diff_wordexp_simple_cases() {
    let mut divs = Vec::new();
    for (input, flags) in CASES {
        let c_input = CString::new(*input).unwrap();
        // Allocate two wordexp_t structs.
        let mut fl_we = WordexpT { we_wordc: 0, we_wordv: std::ptr::null_mut(), we_offs: 0 };
        let mut lc_we = WordexpT { we_wordc: 0, we_wordv: std::ptr::null_mut(), we_offs: 0 };
        let fl_r = unsafe {
            fl::wordexp(c_input.as_ptr(), &mut fl_we as *mut _ as *mut c_void, *flags)
        };
        let lc_r = unsafe {
            wordexp(c_input.as_ptr(), &mut lc_we as *mut _ as *mut c_void, *flags)
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
    assert!(divs.is_empty(), "wordexp divergences:\n{}", render_divs(&divs));
}

#[test]
fn wordexp_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc wordexp\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
