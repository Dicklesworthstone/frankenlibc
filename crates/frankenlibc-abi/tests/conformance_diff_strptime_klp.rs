#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strptime oracle

//! Differential gate for the GNU strptime directives %k / %l / %P (bd-p6qy8j):
//! %k = blank-padded 24h hour (like %H), %l = blank-padded 12h hour (like %I),
//! %P = am/pm (like %p). These weren't covered; fl must AGREE with glibc on
//! whether each is accepted and, when accepted, the parsed tm field — whatever
//! glibc does (accept or reject), fl must match. This resolves the uncertain
//! parity in the batch run. No mocks.

use std::ffi::{CString, c_char, c_int};

unsafe extern "C" {
    fn strptime(s: *const c_char, format: *const c_char, tm: *mut libc::tm) -> *mut c_char;
}

/// (parsed-ok?, consumed-len, tm_hour) for one impl.
fn run(
    strp: unsafe extern "C" fn(*const c_char, *const c_char, *mut libc::tm) -> *mut c_char,
    input: &str,
    fmt: &str,
) -> (bool, isize, c_int) {
    let ic = CString::new(input).unwrap();
    let fc = CString::new(fmt).unwrap();
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe { strp(ic.as_ptr(), fc.as_ptr(), &mut tm) };
    if r.is_null() {
        (false, -1, 0)
    } else {
        ((true), r as isize - ic.as_ptr() as isize, tm.tm_hour)
    }
}

#[test]
fn strptime_klp_match_glibc() {
    let g = strptime;
    let f: unsafe extern "C" fn(*const c_char, *const c_char, *mut libc::tm) -> *mut c_char =
        frankenlibc_abi::time_abi::strptime;

    let cases: &[(&str, &str)] = &[
        ("14", "%k"),
        (" 4", "%k"),
        ("4", "%k"),
        ("3", "%l"),
        (" 3", "%l"),
        ("11", "%l"),
        ("pm", "%P"),
        ("am", "%P"),
        ("PM", "%P"),
        (" 9:30", "%k:%M"),
        ("3 pm", "%l %P"),
    ];
    for &(inp, fmt) in cases {
        let gr = run(g, inp, fmt);
        let fr = run(f, inp, fmt);
        assert_eq!(
            fr, gr,
            "strptime({inp:?}, {fmt:?}): fl=(ok {},consumed {},hour {}) glibc=(ok {},consumed {},hour {})",
            fr.0, fr.1, fr.2, gr.0, gr.1, gr.2
        );
    }
}
