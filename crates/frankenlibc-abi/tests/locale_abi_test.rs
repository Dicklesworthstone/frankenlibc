#![cfg(target_os = "linux")]

//! Integration tests for `<locale.h>` ABI entrypoints.
//!
//! Covers: setlocale, localeconv, nl_langinfo, gettext/dgettext/ngettext,
//! textdomain, bindtextdomain, newlocale, uselocale, freelocale, duplocale,
//! nl_langinfo_l, catopen/catgets/catclose.

use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::sync::Mutex;

use frankenlibc_abi::locale_abi::{
    bindtextdomain, catclose, catgets, catopen, dgettext, duplocale, freelocale, gettext,
    locale_reset_gettext_state_for_tests, localeconv, newlocale, ngettext, nl_langinfo,
    nl_langinfo_l, setlocale, textdomain, uselocale,
};

static GETTEXT_STATE_GUARD: Mutex<()> = Mutex::new(());

fn reset_gettext_state() {
    locale_reset_gettext_state_for_tests();
}

// ---------------------------------------------------------------------------
// setlocale
// ---------------------------------------------------------------------------

#[test]
fn setlocale_query_returns_c() {
    let result = unsafe { setlocale(libc::LC_ALL, ptr::null()) };
    assert!(!result.is_null());
    let name = unsafe { CStr::from_ptr(result) };
    assert_eq!(name.to_bytes(), b"C");
}

#[test]
fn setlocale_set_c_locale() {
    let c_name = CString::new("C").unwrap();
    let result = unsafe { setlocale(libc::LC_ALL, c_name.as_ptr()) };
    assert!(!result.is_null());
    let name = unsafe { CStr::from_ptr(result) };
    assert_eq!(name.to_bytes(), b"C");
}

#[test]
fn setlocale_set_posix_locale() {
    let posix = CString::new("POSIX").unwrap();
    let result = unsafe { setlocale(libc::LC_ALL, posix.as_ptr()) };
    assert!(!result.is_null());
    let name = unsafe { CStr::from_ptr(result) };
    assert_eq!(name.to_bytes(), b"C");
}

#[test]
fn setlocale_set_empty_string() {
    let empty = CString::new("").unwrap();
    let result = unsafe { setlocale(libc::LC_ALL, empty.as_ptr()) };
    assert!(!result.is_null());
}

#[test]
fn setlocale_lc_ctype_query() {
    let result = unsafe { setlocale(libc::LC_CTYPE, ptr::null()) };
    assert!(!result.is_null());
}

#[test]
fn setlocale_lc_numeric_query() {
    let result = unsafe { setlocale(libc::LC_NUMERIC, ptr::null()) };
    assert!(!result.is_null());
}

// ---------------------------------------------------------------------------
// localeconv
// ---------------------------------------------------------------------------

#[test]
fn localeconv_returns_nonnull() {
    let conv = unsafe { localeconv() };
    assert!(!conv.is_null(), "localeconv should return non-null pointer");
}

#[test]
fn localeconv_stable_pointer() {
    let conv1 = unsafe { localeconv() };
    let conv2 = unsafe { localeconv() };
    assert_eq!(
        conv1, conv2,
        "localeconv should return the same static pointer"
    );
}

// ---------------------------------------------------------------------------
// nl_langinfo
// ---------------------------------------------------------------------------

#[test]
fn nl_langinfo_codeset() {
    let result = unsafe { nl_langinfo(libc::CODESET) };
    assert!(!result.is_null());
    let val = unsafe { CStr::from_ptr(result) };
    assert_eq!(val.to_bytes(), b"ANSI_X3.4-1968");
}

#[test]
fn nl_langinfo_radixchar() {
    let result = unsafe { nl_langinfo(libc::RADIXCHAR) };
    assert!(!result.is_null());
    let val = unsafe { CStr::from_ptr(result) };
    assert_eq!(val.to_bytes(), b".");
}

#[test]
fn nl_langinfo_thousep() {
    let result = unsafe { nl_langinfo(libc::THOUSEP) };
    assert!(!result.is_null());
    let val = unsafe { CStr::from_ptr(result) };
    assert_eq!(val.to_bytes(), b"");
}

#[test]
fn nl_langinfo_unknown_item() {
    let result = unsafe { nl_langinfo(99999) };
    assert!(!result.is_null());
    let val = unsafe { CStr::from_ptr(result) };
    assert_eq!(
        val.to_bytes(),
        b"",
        "unknown items should return empty string"
    );
}

// ---------------------------------------------------------------------------
// gettext / dgettext / ngettext
// ---------------------------------------------------------------------------

#[test]
fn gettext_identity() {
    let msg = CString::new("Hello, world!").unwrap();
    let result = unsafe { gettext(msg.as_ptr()) };
    assert_eq!(result as *const c_char, msg.as_ptr());
}

#[test]
fn dgettext_identity() {
    let domain = CString::new("myapp").unwrap();
    let msg = CString::new("test message").unwrap();
    let result = unsafe { dgettext(domain.as_ptr(), msg.as_ptr()) };
    assert_eq!(result as *const c_char, msg.as_ptr());
}

#[test]
fn ngettext_singular() {
    let singular = CString::new("item").unwrap();
    let plural = CString::new("items").unwrap();
    let result = unsafe { ngettext(singular.as_ptr(), plural.as_ptr(), 1) };
    assert_eq!(result as *const c_char, singular.as_ptr());
}

#[test]
fn ngettext_plural() {
    let singular = CString::new("item").unwrap();
    let plural = CString::new("items").unwrap();
    let result = unsafe { ngettext(singular.as_ptr(), plural.as_ptr(), 2) };
    assert_eq!(result as *const c_char, plural.as_ptr());
}

#[test]
fn ngettext_zero_is_plural() {
    let singular = CString::new("item").unwrap();
    let plural = CString::new("items").unwrap();
    let result = unsafe { ngettext(singular.as_ptr(), plural.as_ptr(), 0) };
    assert_eq!(result as *const c_char, plural.as_ptr());
}

// ---------------------------------------------------------------------------
// textdomain / bindtextdomain
// ---------------------------------------------------------------------------

#[test]
fn textdomain_null_returns_default() {
    let _guard = GETTEXT_STATE_GUARD.lock().unwrap();
    reset_gettext_state();
    let result = unsafe { textdomain(ptr::null()) };
    assert!(!result.is_null());
    let domain = unsafe { CStr::from_ptr(result) };
    assert_eq!(domain.to_bytes(), b"messages");
}

#[test]
fn textdomain_set_returns_name() {
    let _guard = GETTEXT_STATE_GUARD.lock().unwrap();
    reset_gettext_state();
    let name = CString::new("myapp").unwrap();
    let result = unsafe { textdomain(name.as_ptr()) };
    let domain = unsafe { CStr::from_ptr(result) };
    assert_eq!(domain.to_bytes(), b"myapp");
}

#[test]
fn textdomain_query_reflects_previous_set() {
    let _guard = GETTEXT_STATE_GUARD.lock().unwrap();
    reset_gettext_state();
    let name = CString::new("frankenlibc-test-domain").unwrap();
    let set_result = unsafe { textdomain(name.as_ptr()) };
    let set_name = unsafe { CStr::from_ptr(set_result) };
    assert_eq!(set_name.to_bytes(), b"frankenlibc-test-domain");

    let query = unsafe { textdomain(ptr::null()) };
    let queried = unsafe { CStr::from_ptr(query) };
    assert_eq!(queried.to_bytes(), b"frankenlibc-test-domain");
}

#[test]
fn textdomain_empty_resets_to_default() {
    let _guard = GETTEXT_STATE_GUARD.lock().unwrap();
    reset_gettext_state();
    let empty = CString::new("").unwrap();
    let result = unsafe { textdomain(empty.as_ptr()) };
    let domain = unsafe { CStr::from_ptr(result) };
    assert_eq!(domain.to_bytes(), b"messages");
}

#[test]
fn bindtextdomain_null_dirname_returns_default() {
    let _guard = GETTEXT_STATE_GUARD.lock().unwrap();
    reset_gettext_state();
    let domain = CString::new("myapp-default-query").unwrap();
    let result = unsafe { bindtextdomain(domain.as_ptr(), ptr::null()) };
    assert!(!result.is_null());
    let dir = unsafe { CStr::from_ptr(result) };
    assert_eq!(dir.to_bytes(), b"/usr/share/locale");
}

#[test]
fn bindtextdomain_null_domain_returns_null() {
    let _guard = GETTEXT_STATE_GUARD.lock().unwrap();
    reset_gettext_state();
    let dirname = CString::new("/tmp/frankenlibc-locale").unwrap();
    let result = unsafe { bindtextdomain(ptr::null(), dirname.as_ptr()) };
    assert!(
        result.is_null(),
        "bindtextdomain(NULL, ...) should reject a missing domain name"
    );
}

#[test]
fn bindtextdomain_empty_domain_returns_null() {
    let _guard = GETTEXT_STATE_GUARD.lock().unwrap();
    reset_gettext_state();
    let domain = CString::new("").unwrap();
    let dirname = CString::new("/tmp/frankenlibc-locale").unwrap();
    let result = unsafe { bindtextdomain(domain.as_ptr(), dirname.as_ptr()) };
    assert!(
        result.is_null(),
        "bindtextdomain(\"\", ...) should reject an empty domain name"
    );
}

#[test]
fn bindtextdomain_set_dirname() {
    let _guard = GETTEXT_STATE_GUARD.lock().unwrap();
    reset_gettext_state();
    let domain = CString::new("myapp").unwrap();
    let dirname = CString::new("/opt/locale").unwrap();
    let result = unsafe { bindtextdomain(domain.as_ptr(), dirname.as_ptr()) };
    let dir = unsafe { CStr::from_ptr(result) };
    assert_eq!(dir.to_bytes(), b"/opt/locale");
}

#[test]
fn bindtextdomain_query_reflects_previous_set() {
    let _guard = GETTEXT_STATE_GUARD.lock().unwrap();
    reset_gettext_state();
    let domain = CString::new("myapp").unwrap();
    let dirname = CString::new("/tmp/frankenlibc-locale").unwrap();
    let set_result = unsafe { bindtextdomain(domain.as_ptr(), dirname.as_ptr()) };
    let set_dir = unsafe { CStr::from_ptr(set_result) };
    assert_eq!(set_dir.to_bytes(), b"/tmp/frankenlibc-locale");

    let query = unsafe { bindtextdomain(domain.as_ptr(), ptr::null()) };
    let queried = unsafe { CStr::from_ptr(query) };
    assert_eq!(queried.to_bytes(), b"/tmp/frankenlibc-locale");
}

#[test]
fn bindtextdomain_keeps_domains_separate() {
    let _guard = GETTEXT_STATE_GUARD.lock().unwrap();
    reset_gettext_state();
    let domain_a = CString::new("app-a").unwrap();
    let domain_b = CString::new("app-b").unwrap();
    let dir_a = CString::new("/tmp/frankenlibc-locale-a").unwrap();
    let dir_b = CString::new("/tmp/frankenlibc-locale-b").unwrap();

    let result_a = unsafe { bindtextdomain(domain_a.as_ptr(), dir_a.as_ptr()) };
    let result_b = unsafe { bindtextdomain(domain_b.as_ptr(), dir_b.as_ptr()) };

    let bound_a = unsafe { CStr::from_ptr(result_a) };
    let bound_b = unsafe { CStr::from_ptr(result_b) };
    assert_eq!(bound_a.to_bytes(), b"/tmp/frankenlibc-locale-a");
    assert_eq!(bound_b.to_bytes(), b"/tmp/frankenlibc-locale-b");

    let query_a = unsafe { bindtextdomain(domain_a.as_ptr(), ptr::null()) };
    let query_b = unsafe { bindtextdomain(domain_b.as_ptr(), ptr::null()) };
    let queried_a = unsafe { CStr::from_ptr(query_a) };
    let queried_b = unsafe { CStr::from_ptr(query_b) };
    assert_eq!(queried_a.to_bytes(), b"/tmp/frankenlibc-locale-a");
    assert_eq!(queried_b.to_bytes(), b"/tmp/frankenlibc-locale-b");
}

// ---------------------------------------------------------------------------
// setlocale — per-category queries
// ---------------------------------------------------------------------------

#[test]
fn setlocale_lc_time_query() {
    let result = unsafe { setlocale(libc::LC_TIME, ptr::null()) };
    assert!(!result.is_null());
}

#[test]
fn setlocale_lc_collate_query() {
    let result = unsafe { setlocale(libc::LC_COLLATE, ptr::null()) };
    assert!(!result.is_null());
}

#[test]
fn setlocale_lc_monetary_query() {
    let result = unsafe { setlocale(libc::LC_MONETARY, ptr::null()) };
    assert!(!result.is_null());
}

#[test]
fn setlocale_lc_messages_query() {
    let result = unsafe { setlocale(libc::LC_MESSAGES, ptr::null()) };
    assert!(!result.is_null());
}

// ---------------------------------------------------------------------------
// nl_langinfo — day/month names
// ---------------------------------------------------------------------------

#[test]
fn nl_langinfo_day_1_returns_non_null() {
    let result = unsafe { nl_langinfo(libc::DAY_1) };
    assert!(!result.is_null());
    // Implementation may return "Sunday" or empty string
}

#[test]
fn nl_langinfo_mon_1_returns_non_null() {
    let result = unsafe { nl_langinfo(libc::MON_1) };
    assert!(!result.is_null());
}

#[test]
fn nl_langinfo_yesexpr_returns_non_null() {
    let result = unsafe { nl_langinfo(libc::YESEXPR) };
    assert!(!result.is_null());
}

// ---------------------------------------------------------------------------
// ngettext — edge cases
// ---------------------------------------------------------------------------

#[test]
fn ngettext_large_count_is_plural() {
    let singular = CString::new("file").unwrap();
    let plural = CString::new("files").unwrap();
    let result = unsafe { ngettext(singular.as_ptr(), plural.as_ptr(), 1_000_000) };
    assert_eq!(result as *const c_char, plural.as_ptr());
}

// ---------------------------------------------------------------------------
// gettext — null safety
// ---------------------------------------------------------------------------

#[test]
fn gettext_null_returns_null() {
    let result = unsafe { gettext(ptr::null()) };
    assert!(result.is_null(), "gettext(NULL) should return NULL");
}

#[test]
fn dgettext_null_msg_returns_null() {
    let domain = CString::new("test").unwrap();
    let result = unsafe { dgettext(domain.as_ptr(), ptr::null()) };
    assert!(result.is_null(), "dgettext(_, NULL) should return NULL");
}

// ---------------------------------------------------------------------------
// POSIX 2008 thread-local locale
// ---------------------------------------------------------------------------

#[test]
fn newlocale_c_locale_succeeds() {
    let c_name = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, c_name.as_ptr(), ptr::null_mut()) };
    assert!(!loc.is_null());
}

#[test]
fn newlocale_posix_locale_succeeds() {
    let posix = CString::new("POSIX").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, posix.as_ptr(), ptr::null_mut()) };
    assert!(!loc.is_null());
}

#[test]
fn newlocale_empty_string_succeeds() {
    let empty = CString::new("").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, empty.as_ptr(), ptr::null_mut()) };
    assert!(!loc.is_null());
}

#[test]
fn newlocale_null_locale_succeeds() {
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, ptr::null(), ptr::null_mut()) };
    assert!(!loc.is_null());
}

#[test]
fn newlocale_invalid_name_with_base_still_fails() {
    let c_name = CString::new("C").unwrap();
    let base = unsafe { newlocale(libc::LC_ALL_MASK, c_name.as_ptr(), ptr::null_mut()) };
    assert!(!base.is_null());

    let invalid = CString::new("en_US.UTF-8").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, invalid.as_ptr(), base) };
    assert!(
        loc.is_null(),
        "unsupported locale names must not succeed merely because base is non-null"
    );
}

#[test]
fn uselocale_returns_handle() {
    let loc = unsafe { uselocale(ptr::null_mut()) };
    assert!(!loc.is_null());
}

#[test]
fn duplocale_returns_same_handle() {
    let c_name = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, c_name.as_ptr(), ptr::null_mut()) };
    let dup = unsafe { duplocale(loc) };
    assert!(!dup.is_null());
    assert_eq!(dup, loc);
}

#[test]
fn freelocale_is_noop() {
    let c_name = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, c_name.as_ptr(), ptr::null_mut()) };
    // Should not crash
    unsafe { freelocale(loc) };
}

// ---------------------------------------------------------------------------
// nl_langinfo_l
// ---------------------------------------------------------------------------

#[test]
fn nl_langinfo_l_codeset() {
    let c_name = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, c_name.as_ptr(), ptr::null_mut()) };
    let result = unsafe { nl_langinfo_l(libc::CODESET, loc) };
    assert!(!result.is_null());
    let val = unsafe { CStr::from_ptr(result) };
    assert_eq!(val.to_bytes(), b"ANSI_X3.4-1968");
}

// ---------------------------------------------------------------------------
// catopen / catgets / catclose (ENOSYS stubs)
// ---------------------------------------------------------------------------

#[test]
fn catopen_returns_error() {
    let name = CString::new("test.cat").unwrap();
    let catd = unsafe { catopen(name.as_ptr(), 0) };
    assert_eq!(catd, -1, "catopen should return -1 (not supported)");
}

#[test]
fn catgets_returns_default_string() {
    let default_str = CString::new("default").unwrap();
    let result = unsafe { catgets(-1, 1, 1, default_str.as_ptr()) };
    assert_eq!(result, default_str.as_ptr());
}

#[test]
fn catclose_returns_error() {
    let rc = unsafe { catclose(-1) };
    assert_eq!(rc, -1, "catclose should return -1");
}
