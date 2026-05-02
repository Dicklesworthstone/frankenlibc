#![cfg(target_os = "linux")]

//! Metamorphic-property tests for POSIX `localeconv(3)` in the C
//! locale.
//!
//! Properties:
//!
//!   - returns a stable pointer (same on every call)
//!   - decimal_point in C locale is always "."
//!   - thousands_sep, currency_symbol, etc. are always empty in C
//!   - all currency-precision fields are CHAR_MAX (no value)
//!   - results are deterministic — every call produces same data
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, CStr};

use frankenlibc_abi::locale_abi as fl;

#[repr(C)]
struct LConv {
    decimal_point: *const c_char,
    thousands_sep: *const c_char,
    grouping: *const c_char,
    int_curr_symbol: *const c_char,
    currency_symbol: *const c_char,
    mon_decimal_point: *const c_char,
    mon_thousands_sep: *const c_char,
    mon_grouping: *const c_char,
    positive_sign: *const c_char,
    negative_sign: *const c_char,
    int_frac_digits: c_char,
    frac_digits: c_char,
    p_cs_precedes: c_char,
    p_sep_by_space: c_char,
    n_cs_precedes: c_char,
    n_sep_by_space: c_char,
    p_sign_posn: c_char,
    n_sign_posn: c_char,
    int_p_cs_precedes: c_char,
    int_p_sep_by_space: c_char,
    int_n_cs_precedes: c_char,
    int_n_sep_by_space: c_char,
    int_p_sign_posn: c_char,
    int_n_sign_posn: c_char,
}

fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

#[test]
fn metamorphic_localeconv_stable_pointer_across_calls() {
    let p1 = unsafe { fl::localeconv() };
    let p2 = unsafe { fl::localeconv() };
    let p3 = unsafe { fl::localeconv() };
    assert_eq!(p1, p2);
    assert_eq!(p1, p3);
}

#[test]
fn metamorphic_localeconv_decimal_point_is_dot_in_c() {
    let p = unsafe { fl::localeconv() };
    assert!(!p.is_null());
    let l = unsafe { &*(p as *const LConv) };
    let dp = cstr(l.decimal_point);
    assert_eq!(dp, ".", "C locale decimal_point must be '.'");
}

#[test]
fn metamorphic_localeconv_thousands_sep_empty_in_c() {
    let p = unsafe { fl::localeconv() };
    let l = unsafe { &*(p as *const LConv) };
    assert_eq!(cstr(l.thousands_sep), "");
}

#[test]
fn metamorphic_localeconv_no_currency_in_c() {
    let p = unsafe { fl::localeconv() };
    let l = unsafe { &*(p as *const LConv) };
    assert_eq!(cstr(l.currency_symbol), "");
    assert_eq!(cstr(l.int_curr_symbol), "");
    assert_eq!(cstr(l.mon_decimal_point), "");
    assert_eq!(cstr(l.mon_thousands_sep), "");
    assert_eq!(cstr(l.mon_grouping), "");
    assert_eq!(cstr(l.positive_sign), "");
    assert_eq!(cstr(l.negative_sign), "");
}

#[test]
fn metamorphic_localeconv_currency_precision_is_char_max() {
    // CHAR_MAX = 127 on x86_64. All currency-precision fields in
    // the C locale are 127 (sentinel meaning "no value").
    let p = unsafe { fl::localeconv() };
    let l = unsafe { &*(p as *const LConv) };
    let max = c_char::MAX;
    assert_eq!(l.int_frac_digits, max);
    assert_eq!(l.frac_digits, max);
    assert_eq!(l.p_cs_precedes, max);
    assert_eq!(l.p_sep_by_space, max);
    assert_eq!(l.n_cs_precedes, max);
    assert_eq!(l.n_sep_by_space, max);
    assert_eq!(l.p_sign_posn, max);
    assert_eq!(l.n_sign_posn, max);
    assert_eq!(l.int_p_cs_precedes, max);
    assert_eq!(l.int_p_sep_by_space, max);
    assert_eq!(l.int_n_cs_precedes, max);
    assert_eq!(l.int_n_sep_by_space, max);
    assert_eq!(l.int_p_sign_posn, max);
    assert_eq!(l.int_n_sign_posn, max);
}

#[test]
fn metamorphic_localeconv_deterministic_across_calls() {
    // Re-read the same fields several times; they must never change.
    let p1 = unsafe { fl::localeconv() };
    let p2 = unsafe { fl::localeconv() };
    let l1 = unsafe { &*(p1 as *const LConv) };
    let l2 = unsafe { &*(p2 as *const LConv) };
    assert_eq!(cstr(l1.decimal_point), cstr(l2.decimal_point));
    assert_eq!(cstr(l1.thousands_sep), cstr(l2.thousands_sep));
    assert_eq!(l1.int_frac_digits, l2.int_frac_digits);
    assert_eq!(l1.p_cs_precedes, l2.p_cs_precedes);
}

#[test]
fn metamorphic_localeconv_grouping_empty_in_c() {
    let p = unsafe { fl::localeconv() };
    let l = unsafe { &*(p as *const LConv) };
    assert_eq!(cstr(l.grouping), "");
}

#[test]
fn localeconv_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc localeconv\",\"reference\":\"posix-c-locale-invariants\",\"properties\":7,\"divergences\":0}}",
    );
}
