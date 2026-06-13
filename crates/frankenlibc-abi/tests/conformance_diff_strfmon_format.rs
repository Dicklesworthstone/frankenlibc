#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strfmon oracle
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{CStr, CString, c_char, c_double};
unsafe extern "C" {
    fn strfmon(s: *mut c_char, max: usize, fmt: *const c_char, ...) -> isize;
    fn setlocale(cat: i32, loc: *const c_char) -> *mut c_char;
}
fn render(eng: u8, fmt: &CString, v: c_double) -> (isize, String) {
    let mut b = [0u8; 128];
    let n = if eng == 0 { unsafe { fl::strfmon(b.as_mut_ptr() as *mut c_char, 128, fmt.as_ptr(), v) } }
            else { unsafe { strfmon(b.as_mut_ptr() as *mut c_char, 128, fmt.as_ptr(), v) } };
    let s = if n < 0 { String::new() } else { unsafe { CStr::from_ptr(b.as_ptr() as *const c_char) }.to_string_lossy().into_owned() };
    (n, s)
}
#[test]
fn strfmon_format_matrix_parity_vs_glibc() {
    // C locale (default). strfmon in C locale uses minimal formatting.
    unsafe { setlocale(6 /*LC_ALL*/, b"C\0".as_ptr() as *const c_char); }
    let fmts = ["%n", "%i", "%.2n", "%.0n", "%#5n", "%#5.2n", "%=*#6n", "%^n",
                "%(n", "%!n", "%-14#5.4n", "%11.2n", "%.4i", "%+n", "%(#8n",
                "100%% of %n", "%15n|", "%-15n|"];
    let vals: &[f64] = &[0.0, -0.0, 1.0, -1.0, 1234.567, -1234.567, 0.005, -0.005,
                         1000000.0, 0.5, -0.5, 99.995, 0.001, 123456789.99];
    let mut div = Vec::new();
    for fmt in fmts {
        let cf = match CString::new(fmt) { Ok(c)=>c, Err(_)=>continue };
        for &v in vals {
            let f = render(0, &cf, v);
            let g = render(1, &cf, v);
            if f != g { div.push(format!("strfmon({fmt:?}, {v}): fl=(ret {},{:?}) glibc=(ret {},{:?})", f.0, f.1, g.0, g.1)); }
        }
    }
    if !div.is_empty() { eprintln!("STRFMON DIVERGENCES ({}):", div.len()); for d in div.iter().take(80) { eprintln!("  {d}"); } }
    assert!(div.is_empty(), "{} strfmon divergences", div.len());
}
