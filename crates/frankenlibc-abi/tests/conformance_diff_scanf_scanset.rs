#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use frankenlibc_abi::stdio_abi as fl;
use std::ffi::{CString, c_char, c_int};
unsafe extern "C" {
    fn sscanf(s: *const c_char, f: *const c_char, ...) -> c_int;
}
// scan one string field into a 64-byte buf; return (ret, captured-string)
fn scan1(eng: u8, input: &CString, fmt: &CString) -> (c_int, String) {
    let mut buf = [0u8; 64];
    let r = if eng == 0 {
        unsafe {
            fl::sscanf(
                input.as_ptr(),
                fmt.as_ptr(),
                buf.as_mut_ptr() as *mut c_char,
            )
        }
    } else {
        unsafe {
            sscanf(
                input.as_ptr(),
                fmt.as_ptr(),
                buf.as_mut_ptr() as *mut c_char,
            )
        }
    };
    let s = buf
        .iter()
        .position(|&b| b == 0)
        .map(|n| String::from_utf8_lossy(&buf[..n]).into_owned())
        .unwrap_or_default();
    (r, s)
}
#[test]
fn scanf_scanset_parity() {
    // (input, format) pairs exercising scanset edge cases
    let cases: &[(&str, &str)] = &[
        ("abc123", "%[a-c]"),
        ("abc123", "%[^0-9]"),
        ("abc123", "%[abc]"),
        ("]abc", "%[]a]"),
        ("a]bc", "%[]a]"),
        ("^abc", "%[^]"),   // ] handling
        ("abc", "%[^]abc"), // unterminated set
        ("a-c", "%[a-c]"),
        ("-abc", "%[-a]"),
        ("abc-", "%[a-]"), // - at ends
        ("HELLOworld", "%[A-Z]"),
        ("12.5e3", "%[0-9.eE+-]"),
        ("aaabbb", "%3[a]"),
        ("   abc", "%[^ ]"),
        ("  abc", "%[ a-c]"),
        ("xyz", "%[^xyz]"),
        ("", "%[a-z]"),
        ("ZZ", "%[A-Za-z]"),
        ("a1b2c3", "%[a-c0-9]"),
        ("Hello, World!", "%[^,]"),
        ("\t\nabc", "%[^a]"),
        ("ABCabc", "%[A-z]"), // A-z spans punctuation
        ("123abc456", "%[0-9]"),
        ("...", "%[.]"),
        ("a]]b", "%[]a]"),
        ("ccba", "%[c-a]"), // reversed range (glibc: only 'c'? or empty?)
    ];
    let mut div = Vec::new();
    for (inp, fmt) in cases {
        let ci = CString::new(*inp).unwrap();
        let cf = CString::new(*fmt).unwrap();
        let f = scan1(0, &ci, &cf);
        let g = scan1(1, &ci, &cf);
        if f != g {
            div.push(format!(
                "sscanf({inp:?}, {fmt:?}): fl=(ret {},{:?}) glibc=(ret {},{:?})",
                f.0, f.1, g.0, g.1
            ));
        }
    }
    if !div.is_empty() {
        eprintln!("SCANF SCANSET DIVERGENCES ({}):", div.len());
        for d in &div {
            eprintln!("  {d}");
        }
    }
    assert!(div.is_empty(), "{} scanf scanset divergences", div.len());
}
