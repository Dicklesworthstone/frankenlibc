#![cfg(target_os = "linux")]

//! Integration tests for `<locale.h>` ABI entrypoints.
//!
//! Covers: setlocale, localeconv, nl_langinfo, gettext/dgettext/ngettext,
//! textdomain, bindtextdomain, newlocale, uselocale, freelocale, duplocale,
//! nl_langinfo_l, catopen/catgets/catclose.

use std::ffi::{CStr, CString, c_char};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenlibc_abi::locale_abi::{
    bindtextdomain, catclose, catgets, catopen, dgettext, duplocale, freelocale, gettext,
    locale_reset_catalog_state_for_tests, locale_reset_gettext_state_for_tests, localeconv,
    newlocale, ngettext, nl_langinfo, nl_langinfo_l, setlocale, textdomain, uselocale,
};

static GETTEXT_STATE_GUARD: Mutex<()> = Mutex::new(());
static CATALOG_STATE_GUARD: Mutex<()> = Mutex::new(());

fn reset_gettext_state() {
    locale_reset_gettext_state_for_tests();
}

unsafe fn load_host_symbol(name: &str) -> Option<*mut libc::c_void> {
    let libc_name = CString::new("libc.so.6").unwrap();
    let handle = unsafe { libc::dlopen(libc_name.as_ptr(), libc::RTLD_NOW) };
    if handle.is_null() {
        return None;
    }
    let sym = CString::new(name).unwrap();
    let ptr = unsafe { libc::dlsym(handle, sym.as_ptr()) };
    if ptr.is_null() { None } else { Some(ptr) }
}

type HostCatopenFn = unsafe extern "C" fn(*const c_char, libc::c_int) -> *mut libc::c_void;
type HostCatgetsFn =
    unsafe extern "C" fn(*mut libc::c_void, libc::c_int, libc::c_int, *const c_char) -> *mut c_char;
type HostCatcloseFn = unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int;

fn temp_catalog_path(tag: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("frankenlibc_{tag}_{unique}.cat"))
}

fn build_test_catalog(entries: &[(u32, u32, &str)]) -> Vec<u8> {
    const MAGIC: u32 = 0x9604_08de;

    let mut string_blob = Vec::new();
    let mut stored = Vec::with_capacity(entries.len());
    for &(set_id, msg_id, text) in entries {
        let offset = string_blob.len() as u32;
        string_blob.extend_from_slice(text.as_bytes());
        string_blob.push(0);
        stored.push((set_id + 1, msg_id, offset));
    }

    let mut plane_size = entries.len().max(1);
    loop {
        let mut seen = std::collections::HashSet::new();
        if stored.iter().all(|&(set_id, msg_id, _)| {
            seen.insert((set_id as usize * msg_id as usize) % plane_size)
        }) {
            break;
        }
        plane_size += 1;
    }

    let mut table = vec![0u32; plane_size * 3];
    for &(set_id, msg_id, offset) in &stored {
        let idx = ((set_id as usize * msg_id as usize) % plane_size) * 3;
        table[idx] = set_id;
        table[idx + 1] = msg_id;
        table[idx + 2] = offset;
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC.to_le_bytes());
    bytes.extend_from_slice(&(plane_size as u32).to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    for word in &table {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    for word in &table {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes.extend_from_slice(&string_blob);
    bytes
}

fn host_invalid_catalog() -> *mut libc::c_void {
    usize::MAX as *mut libc::c_void
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
// catopen / catgets / catclose
// ---------------------------------------------------------------------------

#[test]
fn catopen_missing_catalog_matches_host_errno() {
    let _guard = CATALOG_STATE_GUARD.lock().unwrap();
    locale_reset_catalog_state_for_tests();

    let Some(host_catopen_ptr) = (unsafe { load_host_symbol("catopen") }) else {
        return;
    };
    let host_catopen: HostCatopenFn = unsafe { std::mem::transmute(host_catopen_ptr) };

    let path = temp_catalog_path("missing_catalog");
    let path_c = CString::new(path.as_os_str().as_bytes()).unwrap();

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_catd = unsafe { host_catopen(path_c.as_ptr(), 0) };
    let host_errno = unsafe { *libc::__errno_location() };

    let abi_catd = unsafe { catopen(path_c.as_ptr(), 0) };
    let abi_errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };

    assert_eq!(host_catd, host_invalid_catalog());
    assert_eq!(abi_catd, -1);
    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::ENOENT);
}

#[test]
fn catgets_failed_open_descriptor_returns_default_like_host() {
    let _guard = CATALOG_STATE_GUARD.lock().unwrap();
    locale_reset_catalog_state_for_tests();

    let Some(host_catgets_ptr) = (unsafe { load_host_symbol("catgets") }) else {
        return;
    };
    let host_catgets: HostCatgetsFn = unsafe { std::mem::transmute(host_catgets_ptr) };

    let default_str = CString::new("default").unwrap();

    unsafe {
        *libc::__errno_location() = 777;
    }
    let host_result = unsafe { host_catgets(host_invalid_catalog(), 1, 1, default_str.as_ptr()) };
    let host_errno = unsafe { *libc::__errno_location() };

    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 777;
    }
    let abi_result = unsafe { catgets(-1, 1, 1, default_str.as_ptr()) };
    let abi_errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };

    assert_eq!(host_result, default_str.as_ptr() as *mut c_char);
    assert_eq!(abi_result, default_str.as_ptr());
    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, 777);
}

#[test]
fn generated_catalog_hit_miss_and_close_match_host() {
    let _guard = CATALOG_STATE_GUARD.lock().unwrap();
    locale_reset_catalog_state_for_tests();

    let Some(host_catopen_ptr) = (unsafe { load_host_symbol("catopen") }) else {
        return;
    };
    let Some(host_catgets_ptr) = (unsafe { load_host_symbol("catgets") }) else {
        return;
    };
    let Some(host_catclose_ptr) = (unsafe { load_host_symbol("catclose") }) else {
        return;
    };
    let host_catopen: HostCatopenFn = unsafe { std::mem::transmute(host_catopen_ptr) };
    let host_catgets: HostCatgetsFn = unsafe { std::mem::transmute(host_catgets_ptr) };
    let host_catclose: HostCatcloseFn = unsafe { std::mem::transmute(host_catclose_ptr) };

    let path = temp_catalog_path("message_catalog");
    let bytes = build_test_catalog(&[(1, 1, "translated"), (1, 3, "fallback-hit")]);
    fs::write(&path, bytes).unwrap();
    let path_c = CString::new(path.as_os_str().as_bytes()).unwrap();
    let default_str = CString::new("default").unwrap();

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_catd = unsafe { host_catopen(path_c.as_ptr(), 0) };
    let host_open_errno = unsafe { *libc::__errno_location() };
    assert_ne!(
        host_catd,
        host_invalid_catalog(),
        "host catopen should succeed"
    );
    assert_eq!(host_open_errno, 0);

    let abi_catd = unsafe { catopen(path_c.as_ptr(), 0) };
    let abi_open_errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_ne!(abi_catd, -1, "ABI catopen should succeed");
    assert_eq!(abi_open_errno, 0);

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_hit = unsafe { host_catgets(host_catd, 1, 1, default_str.as_ptr()) };
    let host_hit_errno = unsafe { *libc::__errno_location() };

    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
    }
    let abi_hit = unsafe { catgets(abi_catd, 1, 1, default_str.as_ptr()) };
    let abi_hit_errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };

    assert_eq!(
        unsafe { CStr::from_ptr(host_hit) }.to_bytes(),
        b"translated"
    );
    assert_eq!(unsafe { CStr::from_ptr(abi_hit) }.to_bytes(), b"translated");
    assert_eq!(abi_hit_errno, host_hit_errno);

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_miss = unsafe { host_catgets(host_catd, 1, 2, default_str.as_ptr()) };
    let host_miss_errno = unsafe { *libc::__errno_location() };

    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
    }
    let abi_miss = unsafe { catgets(abi_catd, 1, 2, default_str.as_ptr()) };
    let abi_miss_errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };

    assert_eq!(host_miss, default_str.as_ptr() as *mut c_char);
    assert_eq!(abi_miss, default_str.as_ptr());
    assert_eq!(abi_miss_errno, host_miss_errno);
    assert_eq!(abi_miss_errno, libc::ENOMSG);

    let host_close = unsafe { host_catclose(host_catd) };
    let host_close_errno = unsafe { *libc::__errno_location() };
    let abi_close = unsafe { catclose(abi_catd) };
    let abi_close_errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };

    assert_eq!(abi_close, host_close);
    assert_eq!(abi_close_errno, host_close_errno);
    assert_eq!(abi_close, 0);
}

#[test]
fn catclose_invalid_descriptor_matches_host_ebadf() {
    let _guard = CATALOG_STATE_GUARD.lock().unwrap();
    locale_reset_catalog_state_for_tests();

    let Some(host_catclose_ptr) = (unsafe { load_host_symbol("catclose") }) else {
        return;
    };
    let host_catclose: HostCatcloseFn = unsafe { std::mem::transmute(host_catclose_ptr) };

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { host_catclose(host_invalid_catalog()) };
    let host_errno = unsafe { *libc::__errno_location() };

    let abi_rc = unsafe { catclose(-1) };
    let abi_errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };

    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EBADF);
}
