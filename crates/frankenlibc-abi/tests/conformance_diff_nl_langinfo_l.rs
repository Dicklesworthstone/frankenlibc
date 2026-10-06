#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live glibc oracle

//! `nl_langinfo_l` against live glibc, per locale HANDLE.
//!
//! bd-lofdvp: only fl-internal coverage. The question this answers is whether
//! fl's two `locale_t` sentinels actually select different answers, which is
//! what `nl_langinfo_l` exists for and what a single shared handle made
//! impossible before the per-category work.
//!
//! ## Only CODESET moves between C and C.UTF-8
//!
//! Probed against glibc 2.42 over sixteen documented items under both handles:
//!
//! ```text
//!   CODESET     C = "ANSI_X3.4-1968"        C.UTF-8 = "UTF-8"      <-- differs
//!   RADIXCHAR   "."                          "."
//!   DAY_1       "Sunday"                     "Sunday"
//!   D_T_FMT     "%a %b %e %H:%M:%S %Y"       (same)
//!   D_FMT       "%m/%d/%y"                   (same)
//!   T_FMT_AMPM  "%I:%M:%S %p"                (same)
//!   YESEXPR     "^[yY]"                      (same)
//! ```
//!
//! Fifteen of sixteen agree, so a gate that only checked CODESET would pass on
//! an implementation that returned the C answer for everything — and one that
//! only checked the other fifteen would pass on an implementation that ignored
//! the handle entirely. Both are asserted.
//!
//! ## `nl_item` is `(category << 16) | index`, and guessing crashes
//!
//! A first attempt swept a bare `0..132` range and SEGFAULTED glibc: those are
//! not item numbers, and an out-of-range index walks off the end of a category's
//! string table. The constants below are built from the documented encoding.
//! Do not "simplify" them back into a numeric range.
//!
//! ## `LC_ALL_MASK` excludes bit 6
//!
//! `newlocale(0x1FFF, "C", NULL)` returns NULL with EINVAL. `LC_ALL` is a
//! pseudo-category at 6 with no mask of its own, so the real value is `0x1FBF`
//! — checked against `/usr/include/locale.h` and against the `libc` crate's
//! definition, which composes the same twelve masks. That hole is the same one
//! `locale_core::category_slot` exists to skip.

use std::ffi::{CStr, c_char, c_int, c_void};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

type NlLanginfoLFn = unsafe extern "C" fn(c_int, *mut c_void) -> *const c_char;
type NewlocaleFn = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> *mut c_void;

/// `nl_item` for `(category, index)`.
const fn item(category: c_int, index: c_int) -> c_int {
    (category << 16) | index
}

const CODESET: c_int = item(0, 14);

/// Items that must NOT vary between the two locales fl ships.
const INVARIANT: &[(&str, c_int, &str)] = &[
    ("RADIXCHAR", item(1, 0), "."),
    ("THOUSEP", item(1, 1), ""),
    ("ABDAY_1", item(2, 0), "Sun"),
    ("DAY_1", item(2, 7), "Sunday"),
    ("ABMON_1", item(2, 14), "Jan"),
    ("MON_1", item(2, 26), "January"),
    ("AM_STR", item(2, 38), "AM"),
    ("PM_STR", item(2, 39), "PM"),
    ("D_T_FMT", item(2, 40), "%a %b %e %H:%M:%S %Y"),
    ("D_FMT", item(2, 41), "%m/%d/%y"),
    ("T_FMT", item(2, 42), "%H:%M:%S"),
    ("T_FMT_AMPM", item(2, 43), "%I:%M:%S %p"),
    ("YESEXPR", item(5, 0), "^[yY]"),
    ("NOEXPR", item(5, 1), "^[nN]"),
];

fn host_nl_langinfo_l() -> NlLanginfoLFn {
    // SAFETY: `char *nl_langinfo_l(nl_item, locale_t)`, fl's own export as guard.
    unsafe {
        host_fn(
            c"nl_langinfo_l",
            frankenlibc_abi::locale_abi::nl_langinfo_l as *const (),
        )
    }
}

fn host_newlocale() -> NewlocaleFn {
    // SAFETY: `locale_t newlocale(int, const char *, locale_t)`.
    unsafe {
        host_fn(
            c"newlocale",
            frankenlibc_abi::locale_abi::newlocale as *const (),
        )
    }
}

fn text(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: non-null and NUL-terminated by the C contract.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

/// `(fl_handle, host_handle)` for a locale name.
fn handles(name: &CStr) -> (*mut c_void, *mut c_void) {
    // SAFETY: NUL-terminated name, no base locale.
    unsafe {
        let fl = frankenlibc_abi::locale_abi::newlocale(
            libc::LC_ALL_MASK,
            name.as_ptr(),
            std::ptr::null_mut(),
        );
        let host = host_newlocale()(libc::LC_ALL_MASK, name.as_ptr(), std::ptr::null_mut());
        (fl, host)
    }
}

/// CODESET is the one item that must follow the handle.
#[test]
fn codeset_follows_the_locale_handle() {
    let host = host_nl_langinfo_l();
    for (name, expected) in [(c"C", "ANSI_X3.4-1968"), (c"C.UTF-8", "UTF-8")] {
        let (fl_loc, host_loc) = handles(name);
        assert!(!fl_loc.is_null(), "fl newlocale({name:?}) must succeed");
        assert!(!host_loc.is_null(), "host newlocale({name:?}) must succeed");

        // SAFETY: valid handles from newlocale.
        let host_out = text(unsafe { host(CODESET, host_loc) });
        assert_eq!(
            host_out, expected,
            "host glibc no longer reports the recorded CODESET for {name:?}"
        );
        // SAFETY: same.
        let fl_out = text(unsafe { frankenlibc_abi::locale_abi::nl_langinfo_l(CODESET, fl_loc) });
        assert_eq!(fl_out, host_out, "CODESET for handle {name:?}");
    }
}

/// The other fifteen must NOT move. A gate that checked only CODESET would pass
/// an implementation returning the C answer for everything.
#[test]
fn the_unlocalised_items_are_identical_under_both_handles() {
    let host = host_nl_langinfo_l();
    let (fl_c, host_c) = handles(c"C");
    let (fl_u, host_u) = handles(c"C.UTF-8");

    let mut divergences = Vec::new();
    for (label, nl_item, expected) in INVARIANT {
        // SAFETY: valid handles.
        let (hc, hu) = unsafe { (text(host(*nl_item, host_c)), text(host(*nl_item, host_u))) };
        assert_eq!(hc, hu, "{label} moved between locales on the HOST");
        assert_eq!(
            hc, *expected,
            "host {label} no longer matches the recorded value"
        );

        // SAFETY: same items through fl.
        let (fc, fu) = unsafe {
            (
                text(frankenlibc_abi::locale_abi::nl_langinfo_l(*nl_item, fl_c)),
                text(frankenlibc_abi::locale_abi::nl_langinfo_l(*nl_item, fl_u)),
            )
        };
        if fc != hc || fu != hu {
            divergences.push(format!(
                "  {label}: fl C={fc:?} C.UTF-8={fu:?} / glibc {hc:?}"
            ));
        }
    }
    assert!(
        divergences.is_empty(),
        "nl_langinfo_l divergences:\n{}",
        divergences.join("\n")
    );
}

/// `LC_ALL_MASK` has a hole at bit 6, and `newlocale` rejects a mask that fills
/// it. Pinned because "all categories" reads like `(1 << 13) - 1`.
#[test]
fn newlocale_rejects_a_mask_covering_the_lc_all_bit() {
    let with_lc_all_bit = libc::LC_ALL_MASK | (1 << 6);
    assert_ne!(
        with_lc_all_bit,
        libc::LC_ALL_MASK,
        "LC_ALL_MASK already contains bit 6; this arm assumes it does not"
    );

    // SAFETY: NUL-terminated name, no base locale.
    let host_out =
        unsafe { host_newlocale()(with_lc_all_bit, c"C".as_ptr(), std::ptr::null_mut()) };
    assert!(
        host_out.is_null(),
        "host glibc should reject a mask containing the LC_ALL bit"
    );

    // SAFETY: same.
    let fl_out = unsafe {
        frankenlibc_abi::locale_abi::newlocale(with_lc_all_bit, c"C".as_ptr(), std::ptr::null_mut())
    };
    assert!(
        fl_out.is_null(),
        "fl must reject the same mask — LC_ALL is a pseudo-category with no mask"
    );
}

/// glibc's word-valued items: `nl_langinfo` returns the number itself as the
/// pointer. Measured against host glibc 2.39 by scanning every item of every
/// category for values below 2^32 under C, C.UTF-8 and six compiled locales.
const WORD_ITEMS: &[(c_int, &[c_int])] = &[
    (
        0,
        &[
            13, 17, 18, 19, 30, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 66, 68, 70, 71,
        ],
    ),
    (1, &[3, 4]),
    (2, &[50, 102]),
    (3, &[0, 13]),
    (4, &[38, 39, 40, 41, 43, 44]),
    (7, &[0, 1]),
    (9, &[6]),
];

/// The low 32 bits: glibc stores a loaded locale's word into a pointer-sized
/// union with a 32-bit store, so the upper half of the returned pointer is
/// whatever the slot held before (seen under C.UTF-8).
fn word(ptr: *const c_char) -> u32 {
    ptr as usize as u32
}

/// Word items under compiled locales were pointers into the locale data, so
/// `locale -k` printed ctype-mb-cur-max as an address and util-linux `cal`
/// read `_NL_TIME_WEEK_1STDAY` as one. Every word item of every installed
/// test locale must be the value glibc reports.
#[test]
fn word_items_are_values_not_pointers() {
    let host = host_nl_langinfo_l();
    let names: &[&CStr] = &[
        c"C",
        c"C.UTF-8",
        c"en_US.UTF-8",
        c"de_DE.UTF-8",
        c"fr_FR.UTF-8",
        c"ja_JP.UTF-8",
        c"ru_RU.UTF-8",
        c"tr_TR.UTF-8",
    ];
    let mut divergences = Vec::new();
    let mut compared = 0;
    let mut named_locales = 0;
    for name in names {
        let (fl_loc, host_loc) = handles(name);
        if host_loc.is_null() {
            continue;
        }
        assert!(
            !fl_loc.is_null(),
            "fl newlocale({name:?}) failed where glibc's succeeded"
        );
        let builtin = name.to_bytes().starts_with(b"C");
        if !builtin {
            named_locales += 1;
        }
        for &(category, indices) in WORD_ITEMS {
            for &index in indices {
                // fl does not ship transliteration tables for its built-in
                // locales, so it reports an empty one rather than glibc's size.
                if builtin && (category, index) == (0, 61) {
                    continue;
                }
                let nl_item = item(category, index);
                // SAFETY: valid handles from newlocale.
                let (f, g) = unsafe {
                    (
                        word(frankenlibc_abi::locale_abi::nl_langinfo_l(nl_item, fl_loc)),
                        word(host(nl_item, host_loc)),
                    )
                };
                if f != g {
                    divergences.push(format!("  {name:?} {category}.{index}: fl {f} / glibc {g}"));
                }
                compared += 1;
            }
        }
    }
    assert!(compared >= 2 * 35, "only {compared} word items compared");
    eprintln!("compared {compared} word items, {named_locales} compiled locales");
    assert!(
        divergences.is_empty(),
        "word item divergences:\n{}",
        divergences.join("\n")
    );
}

/// The C and C.UTF-8 string items of LC_CTYPE, LC_NUMERIC, LC_COLLATE,
/// LC_MONETARY and LC_MESSAGES that `locale -k` prints: class and map name
/// lists, digit strings, each category's CODESET, the CHAR_MAX monetary
/// fields and the conversion rate. fl returned "" for most of them.
#[test]
fn builtin_string_items_match_glibc() {
    #[derive(Clone, Copy)]
    enum Kind {
        Str,
        List,
        Wide,
        Words(usize),
        Byte,
    }
    let mut items: Vec<(c_int, c_int, Kind)> = vec![
        (0, 10, Kind::List),
        (0, 11, Kind::List),
        (0, 67, Kind::Wide),
        (1, 0, Kind::Str),
        (1, 1, Kind::Str),
        (1, 2, Kind::Str),
        (1, 5, Kind::Str),
        (3, 18, Kind::Str),
        (4, 42, Kind::Words(2)),
        (4, 45, Kind::Str),
    ];
    items.extend((20..=29).chain(41..=50).map(|i| (0, i, Kind::Str)));
    // The wide digits are _NL_CTYPE_INDIGITS_WC_LEN (1) characters each, not
    // NUL-terminated strings: glibc's compiled C.UTF-8 packs them back to back.
    items.extend((31..=40).map(|i| (0, i, Kind::Words(1))));
    // LC_MONETARY's char-valued fields are single bytes (CHAR_MAX here), not
    // strings: glibc's compiled C.UTF-8 packs them back to back.
    items.extend((0..=37).map(|i| {
        let byte = matches!(i, 7..=14 | 16..=21 | 24..=37);
        (4, i, if byte { Kind::Byte } else { Kind::Str })
    }));
    items.extend((0..=4).map(|i| (5, i, Kind::Str)));

    let render = |kind: Kind, ptr: *const c_char| -> String {
        if ptr.is_null() {
            return "<null>".into();
        }
        match kind {
            Kind::Str => format!("{:?}", text(ptr)),
            Kind::List => {
                let mut out = Vec::new();
                let mut p = ptr;
                // SAFETY: a run of NUL-terminated strings ended by an empty one.
                while unsafe { *p } != 0 && out.len() < 32 {
                    let s = unsafe { CStr::from_ptr(p) };
                    out.push(s.to_string_lossy().into_owned());
                    p = unsafe { p.add(s.to_bytes().len() + 1) };
                }
                out.join(";")
            }
            Kind::Wide => {
                let w = ptr.cast::<u32>();
                let mut out = Vec::new();
                // SAFETY: a NUL-terminated wchar_t string.
                while unsafe { *w.add(out.len()) } != 0 && out.len() < 64 {
                    out.push(unsafe { *w.add(out.len()) });
                }
                format!("{out:?}")
            }
            // SAFETY: a single char-valued item.
            Kind::Byte => format!("byte {}", unsafe { *ptr.cast::<u8>() }),
            Kind::Words(n) => {
                // SAFETY: an array of n 32-bit words.
                let w = (0..n).map(|k| unsafe { *ptr.cast::<u32>().add(k) });
                format!("{:?}", w.collect::<Vec<_>>())
            }
        }
    };

    let host = host_nl_langinfo_l();
    let mut divergences = Vec::new();
    for name in [c"C", c"C.UTF-8"] {
        let (fl_loc, host_loc) = handles(name);
        assert!(
            !fl_loc.is_null() && !host_loc.is_null(),
            "newlocale({name:?})"
        );
        for &(category, index, kind) in &items {
            let nl_item = item(category, index);
            // SAFETY: valid handles from newlocale.
            let (f, g) = unsafe {
                (
                    render(
                        kind,
                        frankenlibc_abi::locale_abi::nl_langinfo_l(nl_item, fl_loc),
                    ),
                    render(kind, host(nl_item, host_loc)),
                )
            };
            if f != g {
                divergences.push(format!("  {name:?} {category}.{index}: fl {f} / glibc {g}"));
            }
        }
    }
    assert!(
        divergences.is_empty(),
        "built-in item divergences:\n{}",
        divergences.join("\n")
    );
}
