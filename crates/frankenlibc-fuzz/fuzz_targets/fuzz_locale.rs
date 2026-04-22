#![no_main]
//! Structure-aware fuzz target for FrankenLibC locale APIs.
//!
//! Exercises the narrow locale input-processing boundaries:
//! - category validation and C-locale name recognition
//! - setlocale/newlocale/uselocale with arbitrary category selectors and names
//! - nl_langinfo / nl_langinfo_l item selection
//! - gettext/textdomain/bindtextdomain state transitions
//! - catopen/catgets/catclose missing-catalog and default-string semantics
//!
//! Bead: bd-wzud

use std::{
    ffi::{CStr, CString, c_char},
    ptr,
    sync::Once,
};

use arbitrary::Arbitrary;
use frankenlibc_abi::{
    errno_abi::__errno_location,
    locale_abi::{
        LocaleT, bindtextdomain, catclose, catgets, catopen, dgettext, duplocale, freelocale,
        gettext, locale_reset_catalog_state_for_tests, locale_reset_gettext_state_for_tests,
        localeconv, newlocale, ngettext, nl_langinfo, nl_langinfo_l, setlocale, textdomain,
        uselocale,
    },
};
use frankenlibc_core::locale;
use libfuzzer_sys::fuzz_target;

const MAX_LOCALE_NAME: usize = 64;
const MAX_DOMAIN_NAME: usize = 64;
const MAX_DIRECTORY_NAME: usize = 128;
const MAX_MESSAGE_LEN: usize = 128;

#[derive(Debug, Arbitrary)]
struct LocaleFuzzInput {
    locale_name: Vec<u8>,
    domain_name: Vec<u8>,
    directory_name: Vec<u8>,
    msgid: Vec<u8>,
    plural_msgid: Vec<u8>,
    category: i32,
    category_mask: i32,
    nl_item_selector: u8,
    count: u8,
    op: u8,
    use_null_locale_name: bool,
    use_null_domain_name: bool,
    use_null_directory_name: bool,
}

fn init_strict_locale_mode() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        // SAFETY: the fuzz target fixes the process-global runtime mode before
        // the first ABI entrypoint executes and never mutates it afterwards.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "strict");
        }
    });
}

fn sanitize_bytes(bytes: &[u8], limit: usize) -> Vec<u8> {
    bytes
        .iter()
        .copied()
        .take(limit)
        .filter(|byte| *byte != 0)
        .collect()
}

fn sanitize_cstring(bytes: &[u8], limit: usize) -> CString {
    let sanitized = sanitize_bytes(bytes, limit);
    CString::new(sanitized).unwrap_or_default()
}

fn read_c_string(ptr: *const c_char) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }

    // SAFETY: callers only pass pointers returned by the locale ABI or by a
    // live CString owned for the duration of the call.
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes().to_vec();
    Some(bytes)
}

fn select_nl_item(selector: u8) -> libc::nl_item {
    const KNOWN_ITEMS: [libc::nl_item; 16] = [
        libc::CODESET,
        libc::RADIXCHAR,
        libc::THOUSEP,
        libc::DAY_1,
        libc::ABDAY_1,
        libc::MON_1,
        libc::ABMON_1,
        libc::AM_STR,
        libc::PM_STR,
        libc::D_T_FMT,
        libc::D_FMT,
        libc::T_FMT,
        libc::T_FMT_AMPM,
        libc::YESEXPR,
        libc::NOEXPR,
        libc::CRNCYSTR,
    ];

    let index = usize::from(selector);
    if index < KNOWN_ITEMS.len() {
        KNOWN_ITEMS[index]
    } else {
        (0x7000 + i32::from(selector)) as libc::nl_item
    }
}

fn fuzz_core_locale_helpers(input: &LocaleFuzzInput) {
    let locale_name = sanitize_bytes(&input.locale_name, MAX_LOCALE_NAME);
    let expected_c_locale = matches!(locale_name.as_slice(), b"C" | b"POSIX" | b"");

    assert_eq!(
        locale::valid_category(input.category),
        (locale::LC_MIN..=locale::LC_MAX).contains(&input.category)
    );
    assert_eq!(locale::is_c_locale(&locale_name), expected_c_locale);

    let c_locale = locale::c_locale_conv();
    assert_eq!(c_locale.decimal_point, b".");
    assert!(c_locale.thousands_sep.is_empty());
    assert!(c_locale.mon_thousands_sep.is_empty());
    assert_eq!(c_locale.int_frac_digits, 127);
    assert_eq!(c_locale.n_sign_posn, 127);
}

fn fuzz_setlocale(input: &LocaleFuzzInput) {
    let locale_name = sanitize_cstring(&input.locale_name, MAX_LOCALE_NAME);
    let query = unsafe { setlocale(input.category, ptr::null()) };

    if locale::valid_category(input.category) {
        assert_eq!(read_c_string(query).as_deref(), Some(b"C".as_slice()));
    } else {
        assert!(query.is_null());
    }

    let result = unsafe { setlocale(input.category, locale_name.as_ptr()) };
    let accepted =
        locale::valid_category(input.category) && locale::is_c_locale(locale_name.as_bytes());

    if accepted {
        assert_eq!(read_c_string(result).as_deref(), Some(b"C".as_slice()));
    } else {
        assert!(result.is_null());
    }
}

fn fuzz_thread_locale_handles(input: &LocaleFuzzInput) {
    let locale_name = sanitize_cstring(&input.locale_name, MAX_LOCALE_NAME);
    let locale_ptr = if input.use_null_locale_name {
        ptr::null()
    } else {
        locale_name.as_ptr()
    };

    let handle = unsafe { newlocale(input.category_mask, locale_ptr, ptr::null_mut()) };
    let accepted = input.use_null_locale_name || locale::is_c_locale(locale_name.as_bytes());

    if accepted {
        assert!(!handle.is_null());
    } else {
        assert!(handle.is_null());
    }

    let query = unsafe { uselocale(ptr::null_mut()) };
    assert!(!query.is_null());

    let installed = unsafe { uselocale(handle) };
    assert!(!installed.is_null());

    let duplicated = unsafe { duplocale(installed) };
    assert_eq!(duplicated, installed);

    unsafe { freelocale(duplicated) };
}

fn fuzz_langinfo(input: &LocaleFuzzInput) {
    let item = select_nl_item(input.nl_item_selector);
    let plain = read_c_string(unsafe { nl_langinfo(item) });

    let locale_handle: LocaleT =
        unsafe { newlocale(input.category_mask, ptr::null(), ptr::null_mut()) };
    assert!(!locale_handle.is_null());

    let localized = read_c_string(unsafe { nl_langinfo_l(item, locale_handle) });
    assert_eq!(plain, localized);

    match item {
        libc::CODESET => {
            assert_eq!(plain.as_deref(), Some(b"ANSI_X3.4-1968".as_slice()));
        }
        libc::RADIXCHAR => {
            assert_eq!(plain.as_deref(), Some(b".".as_slice()));
        }
        libc::THOUSEP | libc::CRNCYSTR => {
            assert_eq!(plain.as_deref(), Some(b"".as_slice()));
        }
        _ => {}
    }

    let conv_a = unsafe { localeconv() };
    let conv_b = unsafe { localeconv() };
    assert!(!conv_a.is_null());
    assert_eq!(conv_a, conv_b);
}

fn fuzz_gettext_domain_state(input: &LocaleFuzzInput) {
    locale_reset_gettext_state_for_tests();

    let domain_name = sanitize_cstring(&input.domain_name, MAX_DOMAIN_NAME);
    let directory_name = sanitize_cstring(&input.directory_name, MAX_DIRECTORY_NAME);
    let msgid = sanitize_cstring(&input.msgid, MAX_MESSAGE_LEN);
    let plural_msgid = sanitize_cstring(&input.plural_msgid, MAX_MESSAGE_LEN);

    let initial = read_c_string(unsafe { textdomain(ptr::null()) });
    assert_eq!(initial.as_deref(), Some(b"messages".as_slice()));

    let domain_ptr = if input.use_null_domain_name {
        ptr::null()
    } else {
        domain_name.as_ptr()
    };
    let set_domain = read_c_string(unsafe { textdomain(domain_ptr) });
    let expected_domain = if input.use_null_domain_name || domain_name.as_bytes().is_empty() {
        b"messages".as_slice()
    } else {
        domain_name.as_bytes()
    };
    assert_eq!(set_domain.as_deref(), Some(expected_domain));

    let queried_domain = read_c_string(unsafe { textdomain(ptr::null()) });
    assert_eq!(queried_domain.as_deref(), Some(expected_domain));

    let directory_ptr = if input.use_null_directory_name {
        ptr::null()
    } else {
        directory_name.as_ptr()
    };
    let bound = unsafe { bindtextdomain(domain_ptr, directory_ptr) };

    if input.use_null_domain_name || domain_name.as_bytes().is_empty() {
        assert!(bound.is_null());
    } else {
        let expected_directory = if input.use_null_directory_name {
            b"/usr/share/locale".as_slice()
        } else {
            directory_name.as_bytes()
        };
        assert_eq!(read_c_string(bound).as_deref(), Some(expected_directory));

        let queried_directory =
            read_c_string(unsafe { bindtextdomain(domain_name.as_ptr(), ptr::null()) });
        assert_eq!(queried_directory.as_deref(), Some(expected_directory));
    }

    assert_eq!(
        unsafe { gettext(msgid.as_ptr()) },
        msgid.as_ptr() as *mut c_char
    );
    assert_eq!(
        unsafe { dgettext(domain_name.as_ptr(), msgid.as_ptr()) },
        msgid.as_ptr() as *mut c_char
    );

    let expected_plural = if input.count == 1 {
        msgid.as_ptr()
    } else {
        plural_msgid.as_ptr()
    };
    assert_eq!(
        unsafe { ngettext(msgid.as_ptr(), plural_msgid.as_ptr(), input.count.into()) },
        expected_plural as *mut c_char
    );
}

fn fuzz_message_catalog_backend(input: &LocaleFuzzInput) {
    locale_reset_catalog_state_for_tests();

    let domain_name = sanitize_cstring(&input.domain_name, MAX_DOMAIN_NAME);
    let msgid = sanitize_cstring(&input.msgid, MAX_MESSAGE_LEN);
    let path_name = if input.use_null_domain_name || domain_name.as_bytes().is_empty() {
        CString::new("/tmp/frankenlibc_missing_catalog_fuzz.cat").unwrap()
    } else {
        let mut path = b"/tmp/frankenlibc_missing_catalog_".to_vec();
        path.extend(
            domain_name
                .as_bytes()
                .iter()
                .map(|byte| if byte.is_ascii_alphanumeric() { *byte } else { b'_' }),
        );
        path.extend_from_slice(b".cat");
        CString::new(path).unwrap()
    };

    let errno_ptr = unsafe { __errno_location() };
    if errno_ptr.is_null() {
        return;
    }

    unsafe { *errno_ptr = 0 };

    let catalog = unsafe { catopen(path_name.as_ptr(), 0) };
    assert_eq!(catalog, -1);
    assert_eq!(unsafe { *errno_ptr }, libc::ENOENT);

    let fallback = unsafe { catgets(catalog, 1, 1, msgid.as_ptr()) };
    assert_eq!(fallback, msgid.as_ptr());

    let close_rc = unsafe { catclose(catalog) };
    assert_eq!(close_rc, -1);
    assert_eq!(unsafe { *errno_ptr }, libc::EBADF);
}

fuzz_target!(|input: LocaleFuzzInput| {
    init_strict_locale_mode();

    match input.op % 6 {
        0 => fuzz_core_locale_helpers(&input),
        1 => fuzz_setlocale(&input),
        2 => fuzz_thread_locale_handles(&input),
        3 => fuzz_langinfo(&input),
        4 => fuzz_gettext_domain_state(&input),
        _ => fuzz_message_catalog_backend(&input),
    }
});
