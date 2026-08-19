#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live glibc oracle

//! `wcsftime_l` against live glibc: wide output, and the size contract.
//!
//! bd-jksmc2: only fl-internal coverage. Like `strftime_l`, fl's `wcsftime_l`
//! ignores its `locale_t` and delegates — defensible while every locale fl ships
//! renders these fields identically, and asserted here rather than assumed.
//!
//! ## `maxsize` counts WIDE CHARACTERS and includes the terminator
//!
//! Measured on glibc 2.42 with `"%Y-%m-%d"`, which produces ten characters:
//!
//! ```text
//!   size 11 -> returns 10, "2026-08-18"
//!   size 10 -> returns 0        <-- ten characters do NOT fit in ten
//!   size  9 -> returns 0
//!   size  1 -> returns 0
//!   size  0 -> returns 0
//! ```
//!
//! The `size 10 -> 0` row is the one worth having: an implementation that
//! treats `maxsize` as "characters available for output" rather than "including
//! the NUL" is off by exactly one and passes every test that does not sit on
//! the boundary.
//!
//! ## Overflow buffer contents are deliberately NOT asserted
//!
//! glibc partially fills the destination before discovering the result does not
//! fit — at sizes 5..=10 the first cell already held `'2'`, while at sizes 0 and
//! 1 the buffer was untouched. POSIX leaves the contents indeterminate on
//! overflow, so pinning those bytes would encode an implementation detail as a
//! contract and produce a gate that breaks on a legal glibc change. Only the
//! RETURN VALUE and the boundary are asserted.

use std::ffi::{c_int, c_void};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

/// The `tm` parameter is typed `*const c_void` rather than `*const libc::tm`
/// so that fl's export and glibc's both unify with this one alias: fl declares
/// it `*const c_void`. The two are ABI-identical -- a pointer argument is a
/// pointer argument -- and the value passed still points at a real `libc::tm`.
type WcsftimeLFn = unsafe extern "C" fn(
    *mut libc::wchar_t,
    usize,
    *const libc::wchar_t,
    *const c_void,
    *mut c_void,
) -> usize;
type NewlocaleFn = unsafe extern "C" fn(c_int, *const std::ffi::c_char, *mut c_void) -> *mut c_void;

fn host_wcsftime_l() -> WcsftimeLFn {
    // SAFETY: matches `size_t wcsftime_l(wchar_t *, size_t, const wchar_t *,
    // const struct tm *, locale_t)`; fl's own export is the oracle guard.
    unsafe {
        host_fn(
            c"wcsftime_l",
            frankenlibc_abi::wchar_abi::wcsftime_l as *const (),
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

/// 2026-08-18 14:52:17, a Tuesday.
fn fixture() -> libc::tm {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_sec = 17;
    tm.tm_min = 52;
    tm.tm_hour = 14;
    tm.tm_mday = 18;
    tm.tm_mon = 7;
    tm.tm_year = 126;
    tm.tm_wday = 2;
    tm.tm_yday = 229;
    tm.tm_gmtoff = 0;
    tm.tm_zone = c"UTC".as_ptr();
    tm
}

fn wide(s: &str) -> Vec<libc::wchar_t> {
    s.chars()
        .map(|c| c as libc::wchar_t)
        .chain(std::iter::once(0))
        .collect()
}

fn pin_utc() {
    // GLIBC's `tzset`, deliberately. `libc::tzset` does not exist -- the crate
    // does not export it, which is what broke this file's compile -- and
    // rustc's suggested `frankenlibc_abi::time_abi::tzset` would be the wrong
    // one: it updates FL's zone state, while the arm that actually reads the
    // process zone here is GLIBC's `%Z`. fl is UTC-only and needs no tzset, so
    // pinning glibc's is both necessary and sufficient.
    //
    // SAFETY: `void tzset(void)`; setenv with NUL-terminated literals. fl's own
    // export is passed so a collapsed oracle aborts (bd-v0388t).
    unsafe {
        let host_tzset: unsafe extern "C" fn() =
            host_fn(c"tzset", frankenlibc_abi::time_abi::tzset as *const ());
        libc::setenv(c"TZ".as_ptr(), c"UTC".as_ptr(), 1);
        host_tzset();
    }
}

/// `(returned, rendered)` for one library.
fn render(
    f: WcsftimeLFn,
    fmt: &[libc::wchar_t],
    tm: &libc::tm,
    size: usize,
    loc: *mut c_void,
) -> (usize, String) {
    let mut buf = vec![0 as libc::wchar_t; 256];
    // SAFETY: `size <= buf.len()`, format is NUL-terminated, `tm` is live.
    let n = unsafe {
        f(
            buf.as_mut_ptr(),
            size,
            fmt.as_ptr(),
            std::ptr::from_ref(tm).cast::<c_void>(),
            loc,
        )
    };
    let text = buf[..n]
        .iter()
        .filter_map(|&c| char::from_u32(c as u32))
        .collect();
    (n, text)
}

const FORMATS: &[(&str, &str)] = &[
    ("%Y-%m-%d", "2026-08-18"),
    ("%A %B", "Tuesday August"),
    ("%c", "Tue Aug 18 14:52:17 2026"),
    ("%H:%M:%S", "14:52:17"),
    ("%j", "230"),
    ("%z", "+0000"),
    ("%Z", "UTC"),
    ("%%", "%"),
];

#[test]
fn wcsftime_l_matches_glibc() {
    pin_utc();
    let tm = fixture();
    let host = host_wcsftime_l();
    // SAFETY: NUL-terminated name, no base locale.
    let loc = unsafe { host_newlocale()(libc::LC_ALL_MASK, c"C".as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null(), "host newlocale(C) must succeed");

    let mut divergences = Vec::new();
    for (fmt, expected) in FORMATS {
        let wfmt = wide(fmt);
        let (host_n, host_text) = render(host, &wfmt, &tm, 256, loc);
        assert_eq!(
            host_text, *expected,
            "host glibc no longer produces the recorded output for {fmt}"
        );

        let (fl_n, fl_text) = render(frankenlibc_abi::wchar_abi::wcsftime_l, &wfmt, &tm, 256, loc);
        if (fl_n, &fl_text) != (host_n, &host_text) {
            divergences.push(format!(
                "  {fmt}: fl ({fl_n}, {fl_text:?}) glibc ({host_n}, {host_text:?})"
            ));
        }
    }
    assert!(
        divergences.is_empty(),
        "wcsftime_l divergences:\n{}",
        divergences.join("\n")
    );
}

/// The off-by-one that matters: ten characters do not fit in `maxsize` ten.
#[test]
fn maxsize_counts_wide_chars_including_the_terminator() {
    pin_utc();
    let tm = fixture();
    let host = host_wcsftime_l();
    let wfmt = wide("%Y-%m-%d"); // ten characters of output
    // SAFETY: NUL-terminated name.
    let loc = unsafe { host_newlocale()(libc::LC_ALL_MASK, c"C".as_ptr(), std::ptr::null_mut()) };

    for (size, expected) in [(11usize, 10usize), (10, 0), (9, 0), (5, 0), (1, 0), (0, 0)] {
        let (host_n, _) = render(host, &wfmt, &tm, size, loc);
        assert_eq!(
            host_n, expected,
            "host glibc no longer returns {expected} at maxsize {size}"
        );
        let (fl_n, _) = render(
            frankenlibc_abi::wchar_abi::wcsftime_l,
            &wfmt,
            &tm,
            size,
            loc,
        );
        assert_eq!(
            fl_n, host_n,
            "maxsize {size}: fl returned {fl_n}, glibc {host_n} — maxsize counts \
             wide characters INCLUDING the terminator, so ten output characters \
             need eleven"
        );
    }
}

/// fl ignores the `locale_t`; assert the premise on the HOST, so the day a
/// locale makes these differ, this fails rather than fl's output silently does.
#[test]
fn the_locale_handle_does_not_change_c_locale_output() {
    pin_utc();
    let tm = fixture();
    let host = host_wcsftime_l();
    // SAFETY: NUL-terminated names, no base locale.
    let (c_loc, utf8_loc) = unsafe {
        (
            host_newlocale()(libc::LC_ALL_MASK, c"C".as_ptr(), std::ptr::null_mut()),
            host_newlocale()(libc::LC_ALL_MASK, c"C.UTF-8".as_ptr(), std::ptr::null_mut()),
        )
    };
    assert!(
        !c_loc.is_null() && !utf8_loc.is_null(),
        "both handles must resolve"
    );

    for (fmt, _) in FORMATS {
        let wfmt = wide(fmt);
        assert_eq!(
            render(host, &wfmt, &tm, 256, c_loc),
            render(host, &wfmt, &tm, 256, utf8_loc),
            "{fmt} differs between C and C.UTF-8 on the HOST — fl's wcsftime_l \
             ignores its locale_t, which stops being safe the moment this fails"
        );
    }
}
