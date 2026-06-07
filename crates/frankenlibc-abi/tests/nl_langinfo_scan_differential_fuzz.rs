#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc nl_langinfo oracle (libc, linked by std)

//! Exhaustive differential scan of `nl_langinfo(item)` over the full item-value
//! range vs host glibc in the C locale. The existing conformance_diff_nl_langinfo
//! checks only a named subset; this sweeps every item value to find ones fl gets
//! wrong (notably items that fall through to "" where glibc returns a real
//! string). Glibc-internal `_NL_*` items (which carry binary/implementation data,
//! not a portable contract) are excluded by range.

use std::ffi::{CStr, c_char, c_int};

use frankenlibc_abi::locale_abi::nl_langinfo as fl_nl_langinfo;

unsafe extern "C" {
    fn nl_langinfo(item: libc::nl_item) -> *const c_char;
    fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
}

fn s(p: *const c_char) -> String {
    if p.is_null() {
        return "<null>".into();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// Public, portable nl_item values (the standard POSIX/glibc items). We avoid
/// glibc's `_NL_*` internal items (interleaved between the public categories),
/// which return non-string/implementation data and are not a parity contract.
fn portable_items() -> Vec<(libc::nl_item, &'static str)> {
    vec![
        (libc::CODESET, "CODESET"),
        (libc::D_T_FMT, "D_T_FMT"),
        (libc::D_FMT, "D_FMT"),
        (libc::T_FMT, "T_FMT"),
        (libc::T_FMT_AMPM, "T_FMT_AMPM"),
        (libc::AM_STR, "AM_STR"),
        (libc::PM_STR, "PM_STR"),
        (libc::DAY_1, "DAY_1"),
        (libc::DAY_2, "DAY_2"),
        (libc::DAY_3, "DAY_3"),
        (libc::DAY_4, "DAY_4"),
        (libc::DAY_5, "DAY_5"),
        (libc::DAY_6, "DAY_6"),
        (libc::DAY_7, "DAY_7"),
        (libc::ABDAY_1, "ABDAY_1"),
        (libc::ABDAY_2, "ABDAY_2"),
        (libc::ABDAY_3, "ABDAY_3"),
        (libc::ABDAY_4, "ABDAY_4"),
        (libc::ABDAY_5, "ABDAY_5"),
        (libc::ABDAY_6, "ABDAY_6"),
        (libc::ABDAY_7, "ABDAY_7"),
        (libc::MON_1, "MON_1"),
        (libc::MON_2, "MON_2"),
        (libc::MON_3, "MON_3"),
        (libc::MON_4, "MON_4"),
        (libc::MON_5, "MON_5"),
        (libc::MON_6, "MON_6"),
        (libc::MON_7, "MON_7"),
        (libc::MON_8, "MON_8"),
        (libc::MON_9, "MON_9"),
        (libc::MON_10, "MON_10"),
        (libc::MON_11, "MON_11"),
        (libc::MON_12, "MON_12"),
        (libc::ABMON_1, "ABMON_1"),
        (libc::ABMON_2, "ABMON_2"),
        (libc::ABMON_3, "ABMON_3"),
        (libc::ABMON_4, "ABMON_4"),
        (libc::ABMON_5, "ABMON_5"),
        (libc::ABMON_6, "ABMON_6"),
        (libc::ABMON_7, "ABMON_7"),
        (libc::ABMON_8, "ABMON_8"),
        (libc::ABMON_9, "ABMON_9"),
        (libc::ABMON_10, "ABMON_10"),
        (libc::ABMON_11, "ABMON_11"),
        (libc::ABMON_12, "ABMON_12"),
        (libc::ERA, "ERA"),
        (libc::ERA_D_FMT, "ERA_D_FMT"),
        (libc::ERA_D_T_FMT, "ERA_D_T_FMT"),
        (libc::ERA_T_FMT, "ERA_T_FMT"),
        (libc::ALT_DIGITS, "ALT_DIGITS"),
        (libc::RADIXCHAR, "RADIXCHAR"),
        (libc::THOUSEP, "THOUSEP"),
        (libc::YESEXPR, "YESEXPR"),
        (libc::NOEXPR, "NOEXPR"),
        (libc::CRNCYSTR, "CRNCYSTR"),
    ]
}

#[test]
fn nl_langinfo_matches_host_glibc_c_locale() {
    unsafe { setlocale(libc::LC_ALL, c"C".as_ptr()) };
    let mut divs: Vec<String> = Vec::new();
    for (item, name) in portable_items() {
        let fl = s(unsafe { fl_nl_langinfo(item) });
        let host = s(unsafe { nl_langinfo(item) });
        if fl != host {
            divs.push(format!("{name} (item={item}): fl={fl:?} glibc={host:?}"));
        }
    }
    assert!(
        divs.is_empty(),
        "nl_langinfo diverged from host glibc (C locale) on {} item(s):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("nl_langinfo scan: {} portable items, 0 divergences", portable_items().len());
}
