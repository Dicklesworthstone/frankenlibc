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
