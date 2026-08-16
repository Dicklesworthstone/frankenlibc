#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sscanf oracle via dlsym

//! Differential gate for `%f` after the decimal-float token stopped being copied.
//!
//! `scan_float` used to accumulate the accepted token into a
//! `Vec::with_capacity(64)` -- prepending `'-'` when the sign was negative --
//! purely so it could hand a slice to `str::parse`. The token is contiguous in
//! the input, so it is now parsed in place and the sign is applied to the parsed
//! MAGNITUDE afterwards.
//!
//! That swap moves two things that a value test would not obviously catch: where
//! the sign comes from, and where the token ends. So this gate pins both against
//! the running glibc rather than against the previous implementation:
//!
//!   - signed zero, where `-0.0` and negating `+0.0` must agree;
//!   - a leading `'+'`, which the old buffer DROPPED and the in-place slice
//!     KEEPS -- `str::parse` accepts it, and glibc says what the answer is;
//!   - overflow and underflow with a sign, where negating the magnitude has to
//!     match parsing the signed text (`-1e400`, `-1e-400`);
//!   - `"03.1.5"`, whose second `'.'` ends the token -- the case a fuzz run
//!     found once already and which the comment in `scan_float` still cites;
//!   - `"1e"` and `"1e+"`, where the exponent marker is consumed but no digits
//!     follow, which is the one place the accepted slice and a "valid float"
//!     disagree;
//!   - width-limited conversions, which end the token early and therefore change
//!     where the in-place slice stops.
//!
//! Both the VALUE and the CONSUMED COUNT are compared, because a token-end
//! change shows up in the count first.

use std::ffi::{CString, c_char, c_int};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type SscanfFn = unsafe extern "C" fn(*const c_char, *const c_char, ...) -> c_int;

/// glibc routes `sscanf` through `__isoc23_sscanf` on this platform; fall back to
/// the plain name so the gate still runs where it does not.
fn host_sscanf() -> SscanfFn {
    let fl = frankenlibc_abi::stdio_abi::sscanf as *const ();
    // SAFETY: both names have C's sscanf signature.
    unsafe {
        let addr = dlsym_oracle::host_addr_optional(c"__isoc23_sscanf", fl)
            .unwrap_or_else(|| dlsym_oracle::host_addr(c"sscanf", fl));
        std::mem::transmute::<*mut std::ffi::c_void, SscanfFn>(addr)
    }
}

/// Run one `%f`-shaped case through both arms and compare value bits and count.
fn compare(input: &str, format: &str) {
    let host = host_sscanf();
    let cin = CString::new(input).unwrap();
    let cfmt = CString::new(format).unwrap();

    let mut fl_val: f32 = 7.5;
    let mut fl_consumed: c_int = -1;
    // SAFETY: the format supplies exactly one %f and one %n for these pointers.
    let fl_rc = unsafe {
        frankenlibc_abi::stdio_abi::sscanf(
            cin.as_ptr(),
            cfmt.as_ptr(),
            &mut fl_val as *mut f32,
            &mut fl_consumed as *mut c_int,
        )
    };

    let mut gl_val: f32 = 7.5;
    let mut gl_consumed: c_int = -1;
    // SAFETY: same format and argument shape through the host symbol.
    let gl_rc = unsafe {
        host(
            cin.as_ptr(),
            cfmt.as_ptr(),
            &mut gl_val as *mut f32,
            &mut gl_consumed as *mut c_int,
        )
    };

    assert_eq!(
        fl_rc, gl_rc,
        "sscanf({input:?}, {format:?}) return: fl={fl_rc} glibc={gl_rc}"
    );
    // Only compare the value when both arms say they assigned one.
    if fl_rc >= 1 {
        assert_eq!(
            fl_val.to_bits(),
            gl_val.to_bits(),
            "sscanf({input:?}, {format:?}) value: fl={fl_val:?} glibc={gl_val:?} \
             (bit compare, so signed zero counts)"
        );
    }
    assert_eq!(
        fl_consumed, gl_consumed,
        "sscanf({input:?}, {format:?}) consumed: fl={fl_consumed} glibc={gl_consumed} \
         — a token-end change shows up here before it shows up in the value"
    );
}

#[test]
fn float_sign_and_zero_match_glibc() {
    for input in ["-0.0", "+0.0", "0.0", "-0", "+0"] {
        compare(input, "%f%n");
    }
}

#[test]
fn float_leading_plus_matches_glibc() {
    // The old buffer dropped a leading '+' and the in-place slice keeps it.
    for input in ["+1.5", "+12345.6789", "+.5", "+1e3"] {
        compare(input, "%f%n");
    }
}

#[test]
fn float_signed_overflow_and_underflow_match_glibc() {
    // Negating the parsed magnitude has to agree with parsing the signed text.
    for input in ["-1e400", "1e400", "-1e-400", "1e-400", "-3.4e38", "-3.5e38"] {
        compare(input, "%f%n");
    }
}

#[test]
fn float_token_end_rules_match_glibc() {
    // The second '.' ends the token; so does a bare exponent marker.
    for input in ["03.1.5", "1.2.3", "1e", "1e+", "1e-", "1.e5", ".5", "-.5"] {
        compare(input, "%f%n");
    }
}

#[test]
fn float_width_limited_matches_glibc() {
    for (input, format) in [
        ("-1.5", "%3f%n"),
        ("-1.5", "%2f%n"),
        ("12345", "%3f%n"),
        ("1e5", "%2f%n"),
        ("-0.0", "%2f%n"),
    ] {
        compare(input, format);
    }
}

#[test]
fn float_leading_whitespace_and_garbage_match_glibc() {
    for input in ["   -2.5", "\t+3.5", "abc", "", "-", "+", "."] {
        compare(input, "%f%n");
    }
}
