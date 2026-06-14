//! Differential conformance gate for `nl_langinfo(3)` in the C/POSIX locale.
//!
//! frankenlibc supports only the C locale, so its langinfo strings are fixed.
//! This gate pins them against host glibc (the bare `extern "C"` symbol in the
//! test binary resolves to the system libc) after forcing the host into the C
//! locale, plus a few hard golden anchors so the test stays meaningful even if
//! the host langinfo data ever shifted.
//!
//! Regression covered (fixed alongside this gate): the eight char-valued
//! LC_MONETARY items (INT_FRAC_DIGITS=262151 .. N_SIGN_POSN=262158) must return
//! a pointer to a single CHAR_MAX byte (0xFF) meaning "unspecified", mirroring
//! the matching `char` fields of `struct lconv`. fl previously returned an empty
//! string, so a caller read 0 ("0 fractional digits") instead of the sentinel.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

unsafe extern "C" {
    fn nl_langinfo(item: c_int) -> *const c_char;
    fn setlocale(cat: c_int, name: *const c_char) -> *mut c_char;
}
use frankenlibc_abi::locale_abi::nl_langinfo as fl_langinfo;

fn bytes(p: *const c_char) -> Option<Vec<u8>> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
    }
}

/// Public POSIX/XSI nl_item codes (category<<16 | index), authoritative values
/// captured from glibc <langinfo.h>.
const ITEMS: &[(&str, i32)] = &[
    ("CODESET", 14),
    ("D_T_FMT", 131112), ("D_FMT", 131113), ("T_FMT", 131114), ("T_FMT_AMPM", 131115),
    ("AM_STR", 131110), ("PM_STR", 131111),
    ("DAY_1", 131079), ("DAY_2", 131080), ("DAY_3", 131081), ("DAY_4", 131082),
    ("DAY_5", 131083), ("DAY_6", 131084), ("DAY_7", 131085),
    ("ABDAY_1", 131072), ("ABDAY_7", 131078),
    ("MON_1", 131098), ("MON_12", 131109), ("ABMON_1", 131086), ("ABMON_12", 131097),
    ("ERA", 131116), ("ERA_D_FMT", 131118), ("ERA_D_T_FMT", 131120), ("ERA_T_FMT", 131121),
    ("ALT_DIGITS", 131119),
    ("RADIXCHAR", 65536), ("THOUSEP", 65537),
    ("YESEXPR", 327680), ("NOEXPR", 327681), ("YESSTR", 327682), ("NOSTR", 327683),
    ("CRNCYSTR", 262159),
    ("INT_CURR_SYMBOL", 262144), ("CURRENCY_SYMBOL", 262145),
    ("MON_DECIMAL_POINT", 262146), ("MON_THOUSANDS_SEP", 262147), ("MON_GROUPING", 262148),
    ("POSITIVE_SIGN", 262149), ("NEGATIVE_SIGN", 262150),
    ("INT_FRAC_DIGITS", 262151), ("FRAC_DIGITS", 262152),
    ("P_CS_PRECEDES", 262153), ("P_SEP_BY_SPACE", 262154),
    ("N_CS_PRECEDES", 262155), ("N_SEP_BY_SPACE", 262156),
    ("P_SIGN_POSN", 262157), ("N_SIGN_POSN", 262158),
    ("DECIMAL_POINT", 65536), ("THOUSANDS_SEP", 65537), ("GROUPING", 65538),
];

#[test]
fn nl_langinfo_matches_glibc_c_locale() {
    // Force the host into the C locale so its langinfo matches fl's tables.
    unsafe { setlocale(libc::LC_ALL, b"C\0".as_ptr() as *const c_char) };
    let mut mismatches = Vec::new();
    for (name, code) in ITEMS {
        let host = bytes(unsafe { nl_langinfo(*code) });
        let fl = bytes(unsafe { fl_langinfo(*code) });
        if host != fl {
            mismatches.push(format!("{name} ({code}): host={host:?} fl={fl:?}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "nl_langinfo diverged from glibc on {} item(s):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn nl_langinfo_char_valued_monetary_items_are_charmax() {
    // The eight char-valued LC_MONETARY items return a single 0xFF byte in the C
    // locale (CHAR_MAX = "unspecified"), not an empty string.
    for code in 262151..=262158 {
        let v = bytes(unsafe { fl_langinfo(code) });
        assert_eq!(
            v,
            Some(vec![0xffu8]),
            "nl_langinfo({code}) must be a single CHAR_MAX (0xFF) byte"
        );
    }
}

#[test]
fn nl_langinfo_golden_anchors() {
    // Hard anchors independent of the live host.
    let anchor = |code: i32| bytes(unsafe { fl_langinfo(code) });
    assert_eq!(anchor(14), Some(b"ANSI_X3.4-1968".to_vec()), "CODESET");
    assert_eq!(anchor(131079), Some(b"Sunday".to_vec()), "DAY_1");
    assert_eq!(anchor(131098), Some(b"January".to_vec()), "MON_1");
    assert_eq!(anchor(131114), Some(b"%H:%M:%S".to_vec()), "T_FMT");
    assert_eq!(anchor(327680), Some(b"^[yY]".to_vec()), "YESEXPR");
    assert_eq!(anchor(65536), Some(b".".to_vec()), "RADIXCHAR");
    assert_eq!(anchor(262152), Some(vec![0xffu8]), "FRAC_DIGITS");
}
