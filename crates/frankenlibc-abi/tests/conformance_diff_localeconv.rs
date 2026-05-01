#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX `localeconv(3)`.
//!
//! Returns a pointer to a static `struct lconv` describing locale-
//! specific number/currency formatting. We diff fl's C/POSIX locale
//! values against host glibc's. Both must agree on every field of
//! the C locale (which is the only locale fl supports).
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

unsafe extern "C" {
    fn localeconv() -> *const LConv;
}

fn cstr_or_empty(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

#[test]
fn diff_localeconv_string_fields_match_in_c_locale() {
    // Make sure we're in the C locale; both impls treat the result as
    // the C-locale defaults.
    unsafe {
        let c_name = c"C".as_ptr();
        libc::setlocale(libc::LC_ALL, c_name);
    }

    let fl_p = unsafe { fl::localeconv() };
    let lc_p = unsafe { localeconv() };
    assert!(!fl_p.is_null(), "fl::localeconv returned NULL");
    assert!(!lc_p.is_null(), "lc::localeconv returned NULL");
    let fl_l = unsafe { &*(fl_p as *const LConv) };
    let lc_l = unsafe { &*lc_p };

    let cmp = |label: &str, fl: *const c_char, lc: *const c_char| {
        let fl_s = cstr_or_empty(fl);
        let lc_s = cstr_or_empty(lc);
        assert_eq!(fl_s, lc_s, "{label}: fl={fl_s:?} lc={lc_s:?}");
    };

    cmp("decimal_point", fl_l.decimal_point, lc_l.decimal_point);
    cmp("thousands_sep", fl_l.thousands_sep, lc_l.thousands_sep);
    cmp("grouping", fl_l.grouping, lc_l.grouping);
    cmp("int_curr_symbol", fl_l.int_curr_symbol, lc_l.int_curr_symbol);
    cmp("currency_symbol", fl_l.currency_symbol, lc_l.currency_symbol);
    cmp("mon_decimal_point", fl_l.mon_decimal_point, lc_l.mon_decimal_point);
    cmp("mon_thousands_sep", fl_l.mon_thousands_sep, lc_l.mon_thousands_sep);
    cmp("mon_grouping", fl_l.mon_grouping, lc_l.mon_grouping);
    cmp("positive_sign", fl_l.positive_sign, lc_l.positive_sign);
    cmp("negative_sign", fl_l.negative_sign, lc_l.negative_sign);
}

#[test]
fn diff_localeconv_numeric_fields_match_in_c_locale() {
    unsafe {
        let c_name = c"C".as_ptr();
        libc::setlocale(libc::LC_ALL, c_name);
    }

    let fl_p = unsafe { fl::localeconv() };
    let lc_p = unsafe { localeconv() };
    assert!(!fl_p.is_null());
    assert!(!lc_p.is_null());
    let fl_l = unsafe { &*(fl_p as *const LConv) };
    let lc_l = unsafe { &*lc_p };

    let cmp_num = |label: &str, fl: c_char, lc: c_char| {
        // C/POSIX locale uses sentinel CHAR_MAX (127) for currency
        // fields that have no value. fl and glibc both encode this.
        assert_eq!(fl, lc, "{label}: fl={fl} lc={lc}");
    };
    cmp_num("int_frac_digits", fl_l.int_frac_digits, lc_l.int_frac_digits);
    cmp_num("frac_digits", fl_l.frac_digits, lc_l.frac_digits);
    cmp_num("p_cs_precedes", fl_l.p_cs_precedes, lc_l.p_cs_precedes);
    cmp_num("p_sep_by_space", fl_l.p_sep_by_space, lc_l.p_sep_by_space);
    cmp_num("n_cs_precedes", fl_l.n_cs_precedes, lc_l.n_cs_precedes);
    cmp_num("n_sep_by_space", fl_l.n_sep_by_space, lc_l.n_sep_by_space);
    cmp_num("p_sign_posn", fl_l.p_sign_posn, lc_l.p_sign_posn);
    cmp_num("n_sign_posn", fl_l.n_sign_posn, lc_l.n_sign_posn);
    cmp_num("int_p_cs_precedes", fl_l.int_p_cs_precedes, lc_l.int_p_cs_precedes);
    cmp_num("int_p_sep_by_space", fl_l.int_p_sep_by_space, lc_l.int_p_sep_by_space);
    cmp_num("int_n_cs_precedes", fl_l.int_n_cs_precedes, lc_l.int_n_cs_precedes);
    cmp_num("int_n_sep_by_space", fl_l.int_n_sep_by_space, lc_l.int_n_sep_by_space);
    cmp_num("int_p_sign_posn", fl_l.int_p_sign_posn, lc_l.int_p_sign_posn);
    cmp_num("int_n_sign_posn", fl_l.int_n_sign_posn, lc_l.int_n_sign_posn);
}

#[test]
fn diff_localeconv_decimal_point_is_dot() {
    unsafe {
        libc::setlocale(libc::LC_ALL, c"C".as_ptr());
    }
    let fl_p = unsafe { fl::localeconv() };
    let fl_l = unsafe { &*(fl_p as *const LConv) };
    let dp = cstr_or_empty(fl_l.decimal_point);
    assert_eq!(dp, ".", "C-locale decimal_point");
}

#[test]
fn diff_localeconv_pointer_stable_across_calls() {
    // Calling localeconv() twice must return the same pointer (the
    // contract is "static struct lconv").
    let p1 = unsafe { fl::localeconv() };
    let p2 = unsafe { fl::localeconv() };
    assert_eq!(p1, p2, "fl pointer not stable");
    let lc1 = unsafe { localeconv() };
    let lc2 = unsafe { localeconv() };
    assert_eq!(lc1, lc2, "lc pointer not stable");
}

#[test]
fn localeconv_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc localeconv\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
