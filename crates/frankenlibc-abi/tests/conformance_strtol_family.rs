//! Conformance gate: the integer string-parse family (strtol/strtoul/strtoll/
//! strtoull/strtoimax/strtoumax + wide wcstol/wcstoul/wcstoll/wcstoull) matches
//! host glibc on the intricate edges — value clamping (LONG_MAX/MIN, ULONG_MAX),
//! endptr advancement (incl. past overflowing digits), base-0 prefix detection
//! (0x / leading-0 octal / invalid-octal-digit), sign + whitespace handling,
//! `strtoul("-1")` unsigned wraparound, and ERANGE / EINVAL errno.
//!
//! Expected values are GROUND TRUTH captured from a standalone gcc program
//! linked against this host's glibc (`-lm`), recorded inline. fl is called via
//! Rust paths and its errno read in-process (its own slot) — reliable for
//! string-argument functions (no const-folding, and the Rust-path call reaches
//! fl's body). long == long long == 64-bit on this target, so the *ll and
//! intmax variants share the golden values.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::errno_abi;
use frankenlibc_abi::stdlib_abi as sa;
use frankenlibc_abi::wchar_abi as wa;
use std::ffi::{CString, c_char, c_int};

const ERANGE: c_int = 34;

fn clr() {
    unsafe { errno_abi::set_abi_errno(0) };
}
fn rd() -> c_int {
    unsafe { *errno_abi::__errno_location() }
}
fn wbuf(s: &str) -> Vec<i32> {
    let mut v: Vec<i32> = s.chars().map(|c| c as i32).collect();
    v.push(0);
    v
}

/// (input, base, want_value, want_endptr_offset, want_errno)
type SCase = (&'static str, c_int, i64, isize, c_int);
type UCase = (&'static str, c_int, u64, isize, c_int);

// Verified against gcc/glibc (see header). Shared by strtol/strtoll/strtoimax.
const SIGNED: &[SCase] = &[
    ("99999999999999999999999", 10, i64::MAX, 23, ERANGE),
    ("9223372036854775807", 10, 9223372036854775807, 19, 0),
    ("9223372036854775808", 10, i64::MAX, 19, ERANGE),
    ("-9223372036854775808", 10, i64::MIN, 20, 0),
    ("-9223372036854775809", 10, i64::MIN, 20, ERANGE),
    ("0x1F", 0, 31, 4, 0),
    ("010", 0, 8, 3, 0),
    ("08", 0, 0, 1, 0),
    ("0", 0, 0, 1, 0),
    ("0x", 0, 0, 1, 0),
    ("  +42", 10, 42, 5, 0),
    ("  -42", 10, -42, 5, 0),
    ("+", 10, 0, 0, 0),
    ("-", 10, 0, 0, 0),
    ("", 10, 0, 0, 0),
    ("z", 36, 35, 1, 0),
    ("Zz", 36, 1295, 2, 0),
    ("42abc", 10, 42, 2, 0),
    ("ffff", 16, 65535, 4, 0),
    ("0x7fffffffffffffff", 0, 9223372036854775807, 18, 0),
    ("-0x10", 0, -16, 5, 0),
    ("  0X1f", 0, 31, 6, 0),
    ("+0x1F", 16, 31, 5, 0),
    ("1010", 2, 10, 4, 0),
    ("777", 8, 511, 3, 0),
];

// Shared by strtoul/strtoull/strtoumax.
const UNSIGNED: &[UCase] = &[
    ("-1", 10, u64::MAX, 2, 0),
    ("18446744073709551615", 10, u64::MAX, 20, 0),
    ("18446744073709551616", 10, u64::MAX, 20, ERANGE),
    ("-0x1", 0, u64::MAX, 4, 0),
    ("0xFFFFFFFFFFFFFFFF", 0, u64::MAX, 18, 0),
    ("99999999999999999999999", 10, u64::MAX, 23, ERANGE),
    ("-18446744073709551615", 10, 1, 21, 0),
];

#[test]
fn strtol_family_matches_glibc() {
    let mut div: Vec<String> = Vec::new();

    macro_rules! run_signed {
        ($fn:path, $tag:literal) => {
            for &(s, base, wv, woff, we) in SIGNED {
                let c = CString::new(s).unwrap();
                let p = c.as_ptr();
                let mut e: *mut c_char = std::ptr::null_mut();
                clr();
                let v = unsafe { $fn(p, &mut e, base) } as i64;
                let off = (e as usize).wrapping_sub(p as usize) as isize;
                let er = rd();
                if v != wv || off != woff || er != we {
                    div.push(format!(
                        "{}({:?},{}): got (v={},end=+{},errno={}) want (v={},end=+{},errno={})",
                        $tag, s, base, v, off, er, wv, woff, we
                    ));
                }
            }
        };
    }
    macro_rules! run_unsigned {
        ($fn:path, $tag:literal) => {
            for &(s, base, wv, woff, we) in UNSIGNED {
                let c = CString::new(s).unwrap();
                let p = c.as_ptr();
                let mut e: *mut c_char = std::ptr::null_mut();
                clr();
                let v = unsafe { $fn(p, &mut e, base) } as u64;
                let off = (e as usize).wrapping_sub(p as usize) as isize;
                let er = rd();
                if v != wv || off != woff || er != we {
                    div.push(format!(
                        "{}({:?},{}): got (v={},end=+{},errno={}) want (v={},end=+{},errno={})",
                        $tag, s, base, v, off, er, wv, woff, we
                    ));
                }
            }
        };
    }

    run_signed!(sa::strtol, "strtol");
    run_signed!(sa::strtoll, "strtoll");
    run_signed!(sa::strtoimax, "strtoimax");
    run_unsigned!(sa::strtoul, "strtoul");
    run_unsigned!(sa::strtoull, "strtoull");
    run_unsigned!(sa::strtoumax, "strtoumax");

    // Wide variants share the same golden table.
    macro_rules! run_wsigned {
        ($fn:path, $tag:literal) => {
            for &(s, base, wv, woff, we) in SIGNED {
                let mut buf = wbuf(s);
                let p = buf.as_mut_ptr();
                let mut e: *mut i32 = std::ptr::null_mut();
                clr();
                let v = unsafe { $fn(p, &mut e, base) } as i64;
                let off = ((e as usize).wrapping_sub(p as usize) / 4) as isize;
                let er = rd();
                if v != wv || off != woff || er != we {
                    div.push(format!(
                        "{}({:?},{}): got (v={},end=+{},errno={}) want (v={},end=+{},errno={})",
                        $tag, s, base, v, off, er, wv, woff, we
                    ));
                }
            }
        };
    }
    macro_rules! run_wunsigned {
        ($fn:path, $tag:literal) => {
            for &(s, base, wv, woff, we) in UNSIGNED {
                let mut buf = wbuf(s);
                let p = buf.as_mut_ptr();
                let mut e: *mut i32 = std::ptr::null_mut();
                clr();
                let v = unsafe { $fn(p, &mut e, base) } as u64;
                let off = ((e as usize).wrapping_sub(p as usize) / 4) as isize;
                let er = rd();
                if v != wv || off != woff || er != we {
                    div.push(format!(
                        "{}({:?},{}): got (v={},end=+{},errno={}) want (v={},end=+{},errno={})",
                        $tag, s, base, v, off, er, wv, woff, we
                    ));
                }
            }
        };
    }
    run_wsigned!(wa::wcstol, "wcstol");
    run_wsigned!(wa::wcstoll, "wcstoll");
    run_wunsigned!(wa::wcstoul, "wcstoul");
    run_wunsigned!(wa::wcstoull, "wcstoull");

    assert!(
        div.is_empty(),
        "strtol-family divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
