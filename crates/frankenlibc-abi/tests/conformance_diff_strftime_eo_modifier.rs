#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strftime oracle

//! `strftime` `%E`/`%O` locale-modifier parity vs host glibc (bd-2g7oyh.NEW).
//!
//! glibc applies the `E`/`O` modifier to a recognised conversion — including
//! the format-control specifiers `%`, `n`, `t` — and renders the whole
//! directive literally otherwise. fl handled `%En`/`%Et` but not `%E%`/`%O%`,
//! which it printed as a literal "%E%" instead of glibc's "%". This gate
//! compares the rendered output across the modifier × specifier matrix
//! (recognised, format-control, and rejected combinations).

use std::ffi::{CString, c_char};
use frankenlibc_abi::time_abi as fl;

unsafe extern "C" {
    fn strftime(s: *mut c_char, m: usize, f: *const c_char, tm: *const libc::tm) -> usize;
    fn gmtime_r(t: *const i64, tm: *mut libc::tm) -> *mut libc::tm;
    fn setlocale(c: i32, l: *const c_char) -> *mut c_char;
}

fn render(eng: u8, fmt: &str, tm: &libc::tm) -> Vec<u8> {
    let cf = CString::new(fmt).unwrap();
    let mut b = [0u8; 96];
    let n = if eng == 0 {
        unsafe { fl::strftime(b.as_mut_ptr() as *mut c_char, 96, cf.as_ptr(), tm) }
    } else {
        unsafe { strftime(b.as_mut_ptr() as *mut c_char, 96, cf.as_ptr(), tm) }
    };
    b[..n.min(96)].to_vec()
}

#[test]
fn strftime_eo_modifier_matches_glibc() {
    let loc = CString::new("C").unwrap();
    unsafe { setlocale(6, loc.as_ptr()) };
    let t = 1_718_450_000i64;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { gmtime_r(&t, &mut tm) };

    let fmts = [
        // Format-control specifiers under E/O — the fixed cases.
        "%E%", "%O%", "%En", "%On", "%Et", "%Ot", "%E%Y", "%O%m",
        // Recognised date specifiers under E/O (C-locale no-op -> base).
        "%EY", "%Ey", "%EC", "%Ec", "%Ex", "%EX", "%Od", "%Oe", "%OH", "%Om",
        "%OM", "%OS", "%OU", "%OV", "%Ow", "%OW", "%Oy", "%Eu",
        // Rejected combinations -> rendered literally.
        "%EE", "%OO", "%Ea", "%EQ", "%Oq", "%E ", "%O.", "%E", "%O",
        // A normal embedding.
        "%Y-%Om-%OdT%OH:%OM:%OS", "literal %E% here",
    ];
    for fmt in fmts {
        let a = render(0, fmt, &tm);
        let b = render(1, fmt, &tm);
        assert_eq!(
            a,
            b,
            "strftime({fmt:?}): fl={:?} glibc={:?}",
            String::from_utf8_lossy(&a),
            String::from_utf8_lossy(&b)
        );
    }
}
