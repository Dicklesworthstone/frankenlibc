//! ABI layer for `<locale.h>` functions.
//!
//! Bootstrap provides the POSIX "C"/"POSIX" locale only. `setlocale` accepts
//! these names and rejects all others. `localeconv` returns C-locale defaults.

use std::ffi::{CStr, c_char, c_int};

use frankenlibc_core::locale as locale_core;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

/// Static C-locale name string.
static C_LOCALE_NAME: &[u8] = b"C\0";
/// POSIX C-locale character encoding string.
static C_LOCALE_CODESET: &[u8] = b"ANSI_X3.4-1968\0";
/// POSIX C-locale radix character.
static C_LOCALE_RADIX: &[u8] = b".\0";
/// POSIX C-locale thousands separator (empty string).
static C_LOCALE_THOUSEP: &[u8] = b"\0";
/// Generic empty locale string result.
static EMPTY_LOCALE_STR: &[u8] = b"\0";

/// Static `struct lconv` for the C locale.
///
/// POSIX specifies that localeconv() returns a pointer to a static struct
/// that is overwritten by subsequent calls. We keep a single global instance.
static LCONV: LConv = LConv {
    decimal_point: b".\0" as *const u8 as *const c_char,
    thousands_sep: b"\0" as *const u8 as *const c_char,
    grouping: b"\0" as *const u8 as *const c_char,
    int_curr_symbol: b"\0" as *const u8 as *const c_char,
    currency_symbol: b"\0" as *const u8 as *const c_char,
    mon_decimal_point: b"\0" as *const u8 as *const c_char,
    mon_thousands_sep: b"\0" as *const u8 as *const c_char,
    mon_grouping: b"\0" as *const u8 as *const c_char,
    positive_sign: b"\0" as *const u8 as *const c_char,
    negative_sign: b"\0" as *const u8 as *const c_char,
    int_frac_digits: 127, // CHAR_MAX
    frac_digits: 127,
    p_cs_precedes: 127,
    p_sep_by_space: 127,
    n_cs_precedes: 127,
    n_sep_by_space: 127,
    p_sign_posn: 127,
    n_sign_posn: 127,
};

/// C-compatible `struct lconv`.
#[repr(C)]
pub struct LConv {
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
}

// SAFETY: LConv contains only static pointers and scalars, all read-only.
unsafe impl Sync for LConv {}

// ---------------------------------------------------------------------------
// setlocale
// ---------------------------------------------------------------------------

/// POSIX `setlocale`.
///
/// Bootstrap: only the "C" and "POSIX" locales are supported. Querying
/// (null `locale` pointer) returns `"C"`. Setting to "C", "POSIX", or ""
/// succeeds. All other locale names fail and return null.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setlocale(category: c_int, locale: *const c_char) -> *const c_char {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Locale, category as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 5, true);
        return std::ptr::null();
    }

    // Validate category.
    if !locale_core::valid_category(category) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 5, true);
        return std::ptr::null();
    }

    // Query mode: locale is NULL.
    if locale.is_null() {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 5, false);
        return C_LOCALE_NAME.as_ptr() as *const c_char;
    }

    // Parse the locale name.
    let name = unsafe { CStr::from_ptr(locale) }.to_bytes();

    if locale_core::is_c_locale(name) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, false);
        C_LOCALE_NAME.as_ptr() as *const c_char
    } else if mode.heals_enabled() {
        // Hardened: fall back to C locale instead of failing.
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, true);
        C_LOCALE_NAME.as_ptr() as *const c_char
    } else {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, true);
        std::ptr::null()
    }
}

// ---------------------------------------------------------------------------
// localeconv
// ---------------------------------------------------------------------------

/// POSIX `localeconv`.
///
/// Returns a pointer to a static `struct lconv` with C-locale defaults.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn localeconv() -> *const LConv {
    let (_, decision) = runtime_policy::decide(ApiFamily::Locale, 0, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 4, true);
        return std::ptr::null();
    }
    runtime_policy::observe(ApiFamily::Locale, decision.profile, 4, false);
    &LCONV
}

// ---------------------------------------------------------------------------
// nl_langinfo
// ---------------------------------------------------------------------------

/// POSIX `nl_langinfo`.
///
/// Bootstrap supports a minimal C-locale subset:
/// - `CODESET` -> `"ANSI_X3.4-1968"`
/// - `RADIXCHAR` -> `"."`
/// - `THOUSEP` -> `""`
///   Unsupported items return `""`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nl_langinfo(item: libc::nl_item) -> *const c_char {
    let (_, decision) = runtime_policy::decide(ApiFamily::Locale, item as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        return std::ptr::null();
    }

    let value = if item == libc::CODESET {
        C_LOCALE_CODESET
    } else if item == libc::RADIXCHAR {
        C_LOCALE_RADIX
    } else if item == libc::THOUSEP {
        C_LOCALE_THOUSEP
    } else {
        EMPTY_LOCALE_STR
    };
    runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, false);
    value.as_ptr() as *const c_char
}

// ---------------------------------------------------------------------------
// gettext family — native C-locale implementation
// ---------------------------------------------------------------------------
//
// FrankenLibC supports only the C/POSIX locale. In the C locale, the gettext
// family acts as identity functions — no message catalog is loaded, so msgid
// is returned unmodified. This is the correct POSIX behavior when no
// translations are installed.

/// GNU `gettext` — returns msgid unchanged (C locale: no translation).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gettext(msgid: *const c_char) -> *mut c_char {
    msgid as *mut c_char
}

/// GNU `dgettext` — returns msgid unchanged (C locale: domain ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dgettext(_domainname: *const c_char, msgid: *const c_char) -> *mut c_char {
    msgid as *mut c_char
}

/// GNU `ngettext` — returns singular or plural form (C locale: no translation).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ngettext(
    msgid: *const c_char,
    msgid_plural: *const c_char,
    n: libc::c_ulong,
) -> *mut c_char {
    if n == 1 {
        msgid as *mut c_char
    } else {
        msgid_plural as *mut c_char
    }
}

/// Default text domain name.
static DEFAULT_TEXT_DOMAIN: &[u8] = b"messages\0";
/// Default locale directory.
static DEFAULT_LOCALE_DIR: &[u8] = b"/usr/share/locale\0";

/// GNU `textdomain` — set/query current text domain.
///
/// In C-locale mode, the domain is irrelevant since no translations are loaded.
/// Returns the domain name for API compatibility.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn textdomain(domainname: *const c_char) -> *mut c_char {
    if domainname.is_null() {
        DEFAULT_TEXT_DOMAIN.as_ptr() as *mut c_char
    } else {
        domainname as *mut c_char
    }
}

/// GNU `bindtextdomain` — bind a text domain to a locale directory.
///
/// In C-locale mode, no catalog lookup occurs. Returns the dirname for
/// API compatibility.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bindtextdomain(
    _domainname: *const c_char,
    dirname: *const c_char,
) -> *mut c_char {
    if dirname.is_null() {
        DEFAULT_LOCALE_DIR.as_ptr() as *mut c_char
    } else {
        dirname as *mut c_char
    }
}
