#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strfmon oracle

//! `strfmon` sign handling parity vs host glibc (bd-2g7oyh.307), with emphasis
//! on negative zero. glibc classifies negativity with a STRICT `value < 0.0`,
//! so `-0.0` is positive for the parenthesis / sign-placement decision while
//! its `-` still appears (rendered from the value's own sign). fl previously
//! used `is_sign_negative()` + `abs()`, wrongly parenthesising `-0.0` (e.g.
//! `%(n` -> "(0.00)" vs glibc "-0.00") and mis-placing its sign under `#`/`=`.
//! Drives both engines over a flag matrix in the C locale and compares the
//! return length + output bytes.

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{CString, c_char};

unsafe extern "C" {
    fn strfmon(s: *mut c_char, m: usize, f: *const c_char, ...) -> isize;
    fn setlocale(c: i32, l: *const c_char) -> *mut c_char;
}

fn render(eng: u8, fmt: &str, v: f64) -> (isize, String) {
    let cf = CString::new(fmt).unwrap();
    let mut b = [0u8; 128];
    let n = if eng == 0 {
        unsafe { fl::strfmon(b.as_mut_ptr() as *mut c_char, 128, cf.as_ptr(), v) }
    } else {
        unsafe { strfmon(b.as_mut_ptr() as *mut c_char, 128, cf.as_ptr(), v) }
    };
    let s = if n < 0 {
        String::new()
    } else {
        String::from_utf8_lossy(&b[..n as usize]).into_owned()
    };
    (n, s)
}

#[test]
fn strfmon_sign_matches_glibc() {
    let loc = CString::new("C").unwrap();
    unsafe { setlocale(6, loc.as_ptr()) };

    let vals = [
        -0.0f64, 0.0, -1234.567, 1234.567, -0.001, 0.001, -1.0, 1.0, -0.5, 0.5, 99.999,
    ];
    let fmts = [
        "%n",
        "%i",
        "%.0n",
        "%.4n",
        "%(n",
        "%+n",
        "%!n",
        "%!i",
        "%=*#8n",
        "%=04n",
        "%^n",
        "%(#12.2n",
        "%-15n|",
        "%15n",
        "%#10.3n",
        "%!(n",
        "%(!n",
        "%.0i",
        "%^!(#14.2n",
        "%=*8n",
    ];
    for fmt in fmts {
        for &v in &vals {
            let a = render(0, fmt, v);
            let b = render(1, fmt, v);
            assert_eq!(a, b, "strfmon({fmt:?}, {v}): fl={a:?} glibc={b:?}");
        }
    }
}
