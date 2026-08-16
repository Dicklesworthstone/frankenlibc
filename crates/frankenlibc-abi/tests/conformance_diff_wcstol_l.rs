#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcsto*_l oracle

//! Differential gate for the wide-parser locale variants wcstol_l/wcstoul_l/
//! wcstoll_l/wcstoull_l (bd-j21cpb) — previously uncovered. With a "C" locale
//! they parse exactly like wcstol/etc. fl delegates to the base parsers; for
//! each wide input + base fl must match host glibc on value, endptr consumed-
//! length (in wide chars), and errno. No mocks.

use std::ffi::{CString, c_char, c_int, c_long, c_ulong, c_void};

use libc::wchar_t;

unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
}

// Host arms are resolved with `dlsym`, not declared at link time: fl exports
// the whole wcsto*_l family plus newlocale/freelocale into this binary, so
// link-time references can bind to fl and leave both arms as fl — green while
// proving nothing (bd-v0388t; conformance_diff_catopen was doing exactly that
// in a plain debug build and hiding a live errno defect).
//
// The locale is part of the same problem: this gate built ONE locale_t from the
// link-time `newlocale` and passed it to BOTH implementations, so whichever did
// not create it received a foreign handle. Each arm now builds and frees its
// own. That matters more here than elsewhere, because these functions read
// locale state to decide what counts as a digit.
type WcstolLFn =
    unsafe extern "C" fn(*const wchar_t, *mut *mut wchar_t, c_int, *mut c_void) -> c_long;
type WcstoulLFn =
    unsafe extern "C" fn(*const wchar_t, *mut *mut wchar_t, c_int, *mut c_void) -> c_ulong;
type WcstollLFn =
    unsafe extern "C" fn(*const wchar_t, *mut *mut wchar_t, c_int, *mut c_void) -> i64;
type WcstoullLFn =
    unsafe extern "C" fn(*const wchar_t, *mut *mut wchar_t, c_int, *mut c_void) -> u64;
type NewlocaleFn = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> *mut c_void;
type FreelocaleFn = unsafe extern "C" fn(*mut c_void);

fn host_symbol(name: &std::ffi::CStr, fl_addr: usize) -> *mut c_void {
    // SAFETY: libc.so.6 is the process host libc; flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    // SAFETY: the handle came from dlopen; name is NUL-terminated.
    let raw = unsafe { libc::dlsym(handle, name.as_ptr()) };
    assert!(!raw.is_null(), "dlsym {name:?}");
    assert_ne!(
        raw as usize, fl_addr,
        "the resolved oracle IS fl's {name:?} — this gate would compare fl to itself"
    );
    raw
}

/// Build a C locale from each implementation. Returned as (host, fl).
fn c_locales() -> (*mut c_void, *mut c_void) {
    let cloc = CString::new("C").unwrap();
    // SAFETY: resolved symbol has POSIX's documented newlocale signature.
    let newlocale = unsafe {
        std::mem::transmute::<_, NewlocaleFn>(host_symbol(
            c"newlocale",
            frankenlibc_abi::locale_abi::newlocale as usize,
        ))
    };
    // SAFETY: LC_ALL_MASK with a valid name and no base locale.
    let host = unsafe { newlocale(libc::LC_ALL_MASK, cloc.as_ptr(), std::ptr::null_mut()) };
    assert!(!host.is_null(), "host newlocale(C) failed");
    // SAFETY: as above, against fl.
    let fl = unsafe {
        frankenlibc_abi::locale_abi::newlocale(
            libc::LC_ALL_MASK,
            cloc.as_ptr(),
            std::ptr::null_mut(),
        )
    };
    assert!(!fl.is_null(), "fl newlocale(C) failed");
    (host, fl)
}

fn host_freelocale() -> FreelocaleFn {
    // SAFETY: paired with the host newlocale above — freeing a glibc locale_t
    // through fl's freelocale would be a cross-implementation free, not a test.
    unsafe {
        std::mem::transmute::<_, FreelocaleFn>(host_symbol(
            c"freelocale",
            frankenlibc_abi::locale_abi::freelocale as usize,
        ))
    }
}

fn wide(s: &str) -> Vec<wchar_t> {
    s.chars()
        .map(|c| c as wchar_t)
        .chain(std::iter::once(0))
        .collect()
}
fn consumed(end: *mut wchar_t, base: *const wchar_t) -> isize {
    (end as isize - base as isize) / std::mem::size_of::<wchar_t>() as isize
}

const SIGNED_CASES: &[(&str, c_int)] = &[
    ("123", 10),
    ("  -42xy", 10),
    ("0x1F", 16),
    ("777", 8),
    ("0", 0),
    ("abc", 10),
    ("9223372036854775808", 10), // overflow
    ("-9223372036854775809", 10),
];
const UNSIGNED_CASES: &[(&str, c_int)] = &[
    ("123", 10),
    ("0xFFFFFFFFFFFFFFFF", 0),
    ("-1", 10),
    ("18446744073709551616", 10), // overflow
    ("zz", 36),
];

#[test]
fn wcstol_l_family_matches_glibc() {
    // SAFETY: each resolved symbol has its documented POSIX signature.
    let wcstol_l = unsafe {
        std::mem::transmute::<_, WcstolLFn>(host_symbol(
            c"wcstol_l",
            frankenlibc_abi::wchar_abi::wcstol_l as usize,
        ))
    };
    // SAFETY: as above.
    let wcstoul_l = unsafe {
        std::mem::transmute::<_, WcstoulLFn>(host_symbol(
            c"wcstoul_l",
            frankenlibc_abi::wchar_abi::wcstoul_l as usize,
        ))
    };
    // SAFETY: as above.
    let wcstoll_l = unsafe {
        std::mem::transmute::<_, WcstollLFn>(host_symbol(
            c"wcstoll_l",
            frankenlibc_abi::wchar_abi::wcstoll_l as usize,
        ))
    };
    // SAFETY: as above.
    let wcstoull_l = unsafe {
        std::mem::transmute::<_, WcstoullLFn>(host_symbol(
            c"wcstoull_l",
            frankenlibc_abi::wchar_abi::wcstoull_l as usize,
        ))
    };
    let freelocale = host_freelocale();
    let (loc, fl_loc) = c_locales();

    for &(s, base) in SIGNED_CASES {
        let w = wide(s);
        let mut ge: *mut wchar_t = std::ptr::null_mut();
        let mut fe: *mut wchar_t = std::ptr::null_mut();
        unsafe { *__errno_location() = 0 };
        let g = unsafe { wcstol_l(w.as_ptr(), &mut ge, base, loc) };
        let gerr = unsafe { *__errno_location() };
        unsafe { *__errno_location() = 0 };
        let f = unsafe {
            frankenlibc_abi::wchar_abi::wcstol_l(w.as_ptr(), &mut fe, base, fl_loc as *mut c_void)
        };
        let ferr = unsafe { *__errno_location() };
        assert_eq!(f, g, "wcstol_l({s:?},{base}) value");
        assert_eq!(
            consumed(fe, w.as_ptr()),
            consumed(ge, w.as_ptr()),
            "wcstol_l({s:?}) endptr"
        );
        assert_eq!(ferr, gerr, "wcstol_l({s:?}) errno");

        // wcstoll_l (i64) — same i64 width on x86-64.
        let mut ge2: *mut wchar_t = std::ptr::null_mut();
        let mut fe2: *mut wchar_t = std::ptr::null_mut();
        unsafe { *__errno_location() = 0 };
        let g2 = unsafe { wcstoll_l(w.as_ptr(), &mut ge2, base, loc) };
        let _ = unsafe { *__errno_location() };
        let f2 = unsafe {
            frankenlibc_abi::wchar_abi::wcstoll_l(w.as_ptr(), &mut fe2, base, fl_loc as *mut c_void)
        };
        assert_eq!(f2, g2, "wcstoll_l({s:?},{base}) value");
    }

    for &(s, base) in UNSIGNED_CASES {
        let w = wide(s);
        let mut ge: *mut wchar_t = std::ptr::null_mut();
        let mut fe: *mut wchar_t = std::ptr::null_mut();
        unsafe { *__errno_location() = 0 };
        let g = unsafe { wcstoul_l(w.as_ptr(), &mut ge, base, loc) };
        let gerr = unsafe { *__errno_location() };
        unsafe { *__errno_location() = 0 };
        let f = unsafe {
            frankenlibc_abi::wchar_abi::wcstoul_l(w.as_ptr(), &mut fe, base, fl_loc as *mut c_void)
        };
        let ferr = unsafe { *__errno_location() };
        assert_eq!(f, g, "wcstoul_l({s:?},{base}) value");
        assert_eq!(
            consumed(fe, w.as_ptr()),
            consumed(ge, w.as_ptr()),
            "wcstoul_l({s:?}) endptr"
        );
        assert_eq!(ferr, gerr, "wcstoul_l({s:?}) errno");

        let mut ge2: *mut wchar_t = std::ptr::null_mut();
        let mut fe2: *mut wchar_t = std::ptr::null_mut();
        let g2 = unsafe { wcstoull_l(w.as_ptr(), &mut ge2, base, loc) };
        let f2 = unsafe {
            frankenlibc_abi::wchar_abi::wcstoull_l(
                w.as_ptr(),
                &mut fe2,
                base,
                fl_loc as *mut c_void,
            )
        };
        assert_eq!(f2, g2, "wcstoull_l({s:?},{base}) value");
    }
    unsafe { freelocale(loc) };
    unsafe { frankenlibc_abi::locale_abi::freelocale(fl_loc) };
}
