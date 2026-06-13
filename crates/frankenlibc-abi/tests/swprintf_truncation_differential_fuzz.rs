#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc swprintf oracle

//! Differential fuzzer for `swprintf` truncation semantics vs host glibc.
//! glibc swprintf returns -1 when the result (plus NUL) does not fit in `n`
//! (unlike snprintf, which returns the would-be length) — AND on truncation it
//! still writes the truncated prefix followed by a NUL (it does NOT just empty
//! the buffer). This sweeps `n` from 0 past the produced length for a battery of
//! concrete format/arg cases, comparing BOTH the return value and the exact
//! destination buffer against glibc.

use std::ffi::CString;

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn swprintf(s: *mut libc::wchar_t, n: usize, format: *const libc::wchar_t, ...) -> libc::c_int;
}

fn widen(s: &str) -> Vec<libc::wchar_t> {
    let mut v: Vec<libc::wchar_t> = s.chars().map(|c| c as libc::wchar_t).collect();
    v.push(0);
    v
}

const SENT: libc::wchar_t = 0x7e7e;

/// Run both engines for a given concrete (fmt, invoke) over n in 0..=produced+2
/// and collect divergences.
fn sweep<F1, F2>(label: &str, produced: usize, fl_call: F1, lc_call: F2, divs: &mut Vec<String>)
where
    F1: Fn(*mut libc::wchar_t, usize) -> libc::c_int,
    F2: Fn(*mut libc::wchar_t, usize) -> libc::c_int,
{
    for n in 0..=produced + 2 {
        let cap = n.max(1) + 4;
        let mut bf = vec![SENT; cap];
        let mut bg = vec![SENT; cap];
        let rf = fl_call(bf.as_mut_ptr(), n);
        let rg = lc_call(bg.as_mut_ptr(), n);
        if (rf != rg || bf != bg) && divs.len() < 40 {
            divs.push(format!(
                "{label} n={n}: fl=(ret={rf},buf={:x?}) glibc=(ret={rg},buf={:x?})",
                &bf[..cap.min(8)],
                &bg[..cap.min(8)],
            ));
        }
    }
}

#[test]
fn swprintf_truncation_differential_fuzz_vs_glibc() {
    let mut divs: Vec<String> = Vec::new();

    // Each case: a wide format + the concrete args, invoked identically on both.
    macro_rules! case {
        ($label:expr, $produced:expr, $fmt:expr $(, $arg:expr)*) => {{
            let fmt = widen($fmt);
            sweep(
                $label,
                $produced,
                |s, n| unsafe { fl::swprintf(s, n, fmt.as_ptr() $(, $arg)*) },
                |s, n| unsafe { swprintf(s, n, fmt.as_ptr() $(, $arg)*) },
                &mut divs,
            );
        }};
    }

    case!("hello", 5, "hello");
    case!("empty", 0, "");
    case!("int", 5, "%d", 12345i32);
    case!("two-int", 7, "x%d-%d", 42i32, 9i32);
    case!("neg", 4, "%d", -123i32);
    case!("char", 3, "a%cb", 'Z' as i32);
    case!("hex", 4, "%x", 0xbeefu32);
    case!("pct", 3, "1%%2");
    let s = CString::new("wld").unwrap();
    case!("str", 7, "hi-%s!", s.as_ptr());

    assert!(
        divs.is_empty(),
        "swprintf truncation diverged from glibc:\n{}",
        divs.join("\n")
    );
    eprintln!("swprintf truncation fuzz: 0 divergences vs host glibc");
}
