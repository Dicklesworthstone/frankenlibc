#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc locale oracle

//! Per-category `setlocale` state, and the `LC_ALL` composite string.
//!
//! fl tracked ONE charset for the whole process, so two things were wrong and
//! neither was visible from a single-category test:
//!
//! * `setlocale(LC_NUMERIC, "C.UTF-8")` moved the multibyte codec, even though
//!   POSIX puts conversion under `LC_CTYPE`. A program that localises only its
//!   number formatting got a different `mbrtowc`.
//! * `setlocale(LC_ALL, NULL)` could only ever answer a single name. glibc
//!   answers a twelve-field composite when the categories disagree, and
//!   real code compares that string.
//!
//! fl also stopped at `LC_ALL` (6). glibc has six GNU categories ABOVE it and
//! accepts all of them — measured by sweeping `setlocale(cat, NULL)` over
//! -2..=14: 0..=12 answer `"C"`, while -1, -2, 13 and 14 return NULL with
//! EINVAL. `setlocale(LC_PAPER, NULL)` is a conforming call that fl failed.
//!
//! Every arm below moves BOTH libraries and restores the startup locale, since
//! `setlocale` is process-global in each.

use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::{Mutex, OnceLock};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

use frankenlibc_abi::locale_abi::{
    locale_reset_active_charset_for_tests, setlocale as fl_setlocale,
};

type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *const c_char;

const LC_CTYPE: c_int = 0;
const LC_NUMERIC: c_int = 1;
const LC_ALL: c_int = 6;
const LC_PAPER: c_int = 7;
const LC_IDENTIFICATION: c_int = 12;

fn locale_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn host() -> SetlocaleFn {
    // SAFETY: `char *setlocale(int, const char *)`, with fl's own definition
    // supplied so the oracle refuses to resolve back to fl (bd-v0388t).
    unsafe { host_fn(c"setlocale", fl_setlocale as *const ()) }
}

fn text(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: non-null and NUL-terminated by the C contract.
    Some(
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Set one category in BOTH libraries and return the two answers.
fn set_both(cat: c_int, name: &CStr) -> (Option<String>, Option<String>) {
    // SAFETY: NUL-terminated name, live for the call.
    let host_out = unsafe { host()(cat, name.as_ptr()) };
    // SAFETY: same.
    let fl_out = unsafe { fl_setlocale(cat, name.as_ptr()) };
    (text(fl_out), text(host_out))
}

/// Query one category in BOTH libraries.
fn query_both(cat: c_int) -> (Option<String>, Option<String>) {
    // SAFETY: a NULL name queries without mutating.
    let host_out = unsafe { host()(cat, std::ptr::null()) };
    // SAFETY: same.
    let fl_out = unsafe { fl_setlocale(cat, std::ptr::null()) };
    (text(fl_out), text(host_out))
}

/// Put both libraries back to the startup locale.
struct Restore;

impl Drop for Restore {
    fn drop(&mut self) {
        // SAFETY: NUL-terminated literal.
        unsafe { host()(LC_ALL, c"C".as_ptr()) };
        locale_reset_active_charset_for_tests();
    }
}

/// glibc accepts categories 0..=12 and refuses everything else.
#[test]
fn category_range_matches_glibc() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = Restore;
    // SAFETY: NUL-terminated literal.
    unsafe { host()(LC_ALL, c"C".as_ptr()) };
    locale_reset_active_charset_for_tests();

    for cat in -2..=14 {
        let (fl_out, host_out) = query_both(cat);
        assert_eq!(
            fl_out.is_some(),
            host_out.is_some(),
            "category {cat}: fl={fl_out:?} glibc={host_out:?}"
        );
    }
    // Spot-check the two ends of the GNU range that fl used to reject outright.
    assert!(
        query_both(LC_PAPER).0.is_some(),
        "LC_PAPER must be accepted"
    );
    assert!(
        query_both(LC_IDENTIFICATION).0.is_some(),
        "LC_IDENTIFICATION must be accepted"
    );
}

/// Setting one category must not move the others.
#[test]
fn a_single_category_moves_alone() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = Restore;
    // SAFETY: NUL-terminated literal.
    unsafe { host()(LC_ALL, c"C".as_ptr()) };
    locale_reset_active_charset_for_tests();

    let (fl_set, host_set) = set_both(LC_NUMERIC, c"C.UTF-8");
    assert_eq!(fl_set, host_set, "setlocale(LC_NUMERIC, C.UTF-8)");

    let (fl_ctype, host_ctype) = query_both(LC_CTYPE);
    assert_eq!(fl_ctype, host_ctype, "LC_CTYPE after moving LC_NUMERIC");
    assert_eq!(
        fl_ctype.as_deref(),
        Some("C"),
        "LC_CTYPE must NOT follow LC_NUMERIC — conversion is LC_CTYPE's category"
    );

    let (fl_numeric, host_numeric) = query_both(LC_NUMERIC);
    assert_eq!(fl_numeric, host_numeric);
    assert_eq!(fl_numeric.as_deref(), Some("C.UTF-8"));
}

/// `LC_ALL` answers a bare name when the categories agree and glibc's
/// composite when they do not.
#[test]
fn lc_all_reports_a_composite_when_categories_differ() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = Restore;
    // SAFETY: NUL-terminated literal.
    unsafe { host()(LC_ALL, c"C".as_ptr()) };
    locale_reset_active_charset_for_tests();

    let (fl_uniform, host_uniform) = query_both(LC_ALL);
    assert_eq!(fl_uniform, host_uniform, "uniform LC_ALL");
    assert_eq!(
        fl_uniform.as_deref(),
        Some("C"),
        "a bare name when all agree"
    );

    let _ = set_both(LC_CTYPE, c"C.UTF-8");
    let (fl_mixed, host_mixed) = query_both(LC_ALL);
    assert_eq!(fl_mixed, host_mixed, "composite LC_ALL");

    let composite = fl_mixed.expect("a composite string");
    assert!(
        composite.starts_with("LC_CTYPE=C.UTF-8;LC_NUMERIC=C;"),
        "field order is glibc's, not the numeric category order: {composite}"
    );
    assert_eq!(
        composite.matches(';').count(),
        11,
        "twelve fields means eleven separators and no trailing one: {composite}"
    );
    assert!(
        !composite.contains("LC_ALL="),
        "LC_ALL is a pseudo-category and must not appear in its own composite"
    );
}

/// Setting `LC_ALL` collapses the composite back to a single name.
#[test]
fn setting_lc_all_makes_the_report_uniform_again() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = Restore;
    // SAFETY: NUL-terminated literal.
    unsafe { host()(LC_ALL, c"C".as_ptr()) };
    locale_reset_active_charset_for_tests();

    let _ = set_both(LC_CTYPE, c"C.UTF-8");
    assert!(
        query_both(LC_ALL).0.unwrap().contains(';'),
        "should be mixed"
    );

    let _ = set_both(LC_ALL, c"C.UTF-8");
    let (fl_out, host_out) = query_both(LC_ALL);
    assert_eq!(fl_out, host_out);
    assert_eq!(fl_out.as_deref(), Some("C.UTF-8"), "uniform again");
}
