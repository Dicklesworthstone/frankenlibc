#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc swscanf oracle

//! Differential test for `swscanf`'s RETURN VALUE vs host glibc, focused on the
//! EOF-vs-matching-failure distinction: scanf returns EOF (-1) only when an
//! input failure (end of input) occurs BEFORE any conversion succeeds; a
//! conversion that fails to match returns the count of prior successful
//! assignments (0 if none). `%n` does not count as a conversion.

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn swscanf(s: *const libc::wchar_t, format: *const libc::wchar_t, ...) -> libc::c_int;
    fn setlocale(category: libc::c_int, locale: *const libc::c_char) -> *const libc::c_char;
}

fn w(s: &str) -> Vec<libc::wchar_t> {
    let mut v: Vec<libc::wchar_t> = s.chars().map(|c| c as libc::wchar_t).collect();
    v.push(0);
    v
}

#[test]
fn swscanf_return_matches_glibc() {
    unsafe {
        let utf8 = std::ffi::CString::new("C.UTF-8").unwrap();
        setlocale(6, utf8.as_ptr());
    }
    let mut fails: Vec<String> = Vec::new();

    macro_rules! one_int {
        ($label:expr, $input:expr, $fmt:expr) => {{
            let inp = w($input);
            let fmt = w($fmt);
            let mut af: i32 = 99;
            let mut ag: i32 = 99;
            let rf = unsafe { fl::swscanf(inp.as_ptr(), fmt.as_ptr(), &mut af as *mut i32) };
            let rg = unsafe { swscanf(inp.as_ptr(), fmt.as_ptr(), &mut ag as *mut i32) };
            // Compare return; compare the assigned value only when both assigned.
            if rf != rg || (rf >= 1 && af != ag) {
                fails.push(format!(
                    "{}: input={:?} fmt={:?} fl=(ret={rf},a={af}) glibc=(ret={rg},a={ag})",
                    $label, $input, $fmt
                ));
            }
        }};
    }
    macro_rules! two_int {
        ($label:expr, $input:expr, $fmt:expr) => {{
            let inp = w($input);
            let fmt = w($fmt);
            let (mut af, mut bf) = (99i32, 99i32);
            let (mut ag, mut bg) = (99i32, 99i32);
            let rf = unsafe {
                fl::swscanf(inp.as_ptr(), fmt.as_ptr(), &mut af as *mut i32, &mut bf as *mut i32)
            };
            let rg = unsafe {
                swscanf(inp.as_ptr(), fmt.as_ptr(), &mut ag as *mut i32, &mut bg as *mut i32)
            };
            if rf != rg || (rf >= 1 && af != ag) || (rf >= 2 && bf != bg) {
                fails.push(format!(
                    "{}: input={:?} fmt={:?} fl=(ret={rf},a={af},b={bf}) glibc=(ret={rg},a={ag},b={bg})",
                    $label, $input, $fmt
                ));
            }
        }};
    }

    one_int!("empty/%d", "", "%d");
    one_int!("nonnum/%d", "xyz", "%d");
    one_int!("ws-only/%d", "   ", "%d");
    one_int!("n-only", "abc", "%n");
    one_int!("leading-ws", "   42", "%d");
    one_int!("plain", "42", "%d");
    two_int!("12 x", "12 x", "%d %d");
    two_int!("12-eof", "12", "%d %d");
    two_int!("both", "3 4", "%d %d");
    two_int!("first-fail", "x 4", "%d %d");

    assert!(fails.is_empty(), "swscanf return diverged from glibc:\n{}", fails.join("\n"));
}
