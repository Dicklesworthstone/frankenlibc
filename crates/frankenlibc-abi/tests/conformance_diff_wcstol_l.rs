#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcsto*_l oracle

//! Differential gate for the wide integer family in C and C.UTF-8 locales.
//! Explicit locale objects, the active thread locale, and the process locale
//! must select LC_CTYPE whitespace independently, including C23 binary prefixes.
//! Every comparison checks value, endptr (in wide chars), and errno against
//! independently resolved glibc entrypoints and separately owned locale handles.

use std::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use std::sync::Mutex;

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
type UselocaleFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char;
type ErrnoFn = unsafe extern "C" fn() -> *mut c_int;

static LOCALE_LOCK: Mutex<()> = Mutex::new(());

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

/// Build the same named locale independently. Returned as (host, fl).
fn locales(name: &CStr) -> (*mut c_void, *mut c_void) {
    // SAFETY: resolved symbol has POSIX's documented newlocale signature.
    let newlocale = unsafe {
        std::mem::transmute::<*mut c_void, NewlocaleFn>(host_symbol(
            c"newlocale",
            frankenlibc_abi::locale_abi::newlocale as *const () as usize,
        ))
    };
    // SAFETY: LC_ALL_MASK with a valid name and no base locale.
    let host = unsafe { newlocale(libc::LC_ALL_MASK, name.as_ptr(), std::ptr::null_mut()) };
    assert!(!host.is_null(), "host newlocale({name:?}) failed");
    // SAFETY: as above, against fl.
    let fl = unsafe {
        frankenlibc_abi::locale_abi::newlocale(
            libc::LC_ALL_MASK,
            name.as_ptr(),
            std::ptr::null_mut(),
        )
    };
    assert!(!fl.is_null(), "fl newlocale({name:?}) failed");
    (host, fl)
}

fn host_freelocale() -> FreelocaleFn {
    // SAFETY: paired with the host newlocale above — freeing a glibc locale_t
    // through fl's freelocale would be a cross-implementation free, not a test.
    unsafe {
        std::mem::transmute::<*mut c_void, FreelocaleFn>(host_symbol(
            c"freelocale",
            frankenlibc_abi::locale_abi::freelocale as *const () as usize,
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
    let _lock = LOCALE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    // SAFETY: each resolved symbol has its documented POSIX signature.
    let wcstol_l = unsafe {
        std::mem::transmute::<*mut c_void, WcstolLFn>(host_symbol(
            c"wcstol_l",
            frankenlibc_abi::wchar_abi::wcstol_l as *const () as usize,
        ))
    };
    // SAFETY: as above.
    let wcstoul_l = unsafe {
        std::mem::transmute::<*mut c_void, WcstoulLFn>(host_symbol(
            c"wcstoul_l",
            frankenlibc_abi::wchar_abi::wcstoul_l as *const () as usize,
        ))
    };
    // SAFETY: as above.
    let wcstoll_l = unsafe {
        std::mem::transmute::<*mut c_void, WcstollLFn>(host_symbol(
            c"wcstoll_l",
            frankenlibc_abi::wchar_abi::wcstoll_l as *const () as usize,
        ))
    };
    // SAFETY: as above.
    let wcstoull_l = unsafe {
        std::mem::transmute::<*mut c_void, WcstoullLFn>(host_symbol(
            c"wcstoull_l",
            frankenlibc_abi::wchar_abi::wcstoull_l as *const () as usize,
        ))
    };
    let freelocale = host_freelocale();
    let (loc, fl_loc) = locales(c"C");

    for &(s, base) in SIGNED_CASES {
        let w = wide(s);
        let mut ge: *mut wchar_t = std::ptr::null_mut();
        let mut fe: *mut wchar_t = std::ptr::null_mut();
        unsafe { *__errno_location() = 0 };
        let g = unsafe { wcstol_l(w.as_ptr(), &mut ge, base, loc) };
        let gerr = unsafe { *__errno_location() };
        unsafe { *__errno_location() = 0 };
        let f = unsafe { frankenlibc_abi::wchar_abi::wcstol_l(w.as_ptr(), &mut fe, base, fl_loc) };
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
        let f2 =
            unsafe { frankenlibc_abi::wchar_abi::wcstoll_l(w.as_ptr(), &mut fe2, base, fl_loc) };
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
        let f = unsafe { frankenlibc_abi::wchar_abi::wcstoul_l(w.as_ptr(), &mut fe, base, fl_loc) };
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
        let f2 =
            unsafe { frankenlibc_abi::wchar_abi::wcstoull_l(w.as_ptr(), &mut fe2, base, fl_loc) };
        assert_eq!(f2, g2, "wcstoull_l({s:?},{base}) value");
    }
    unsafe { freelocale(loc) };
    unsafe { frankenlibc_abi::locale_abi::freelocale(fl_loc) };
}

fn parse_result<T>(
    input: &[wchar_t],
    errno: ErrnoFn,
    parse: impl FnOnce(*const wchar_t, *mut *mut wchar_t) -> T,
) -> (T, isize, c_int) {
    // A valid-base no-conversion result must replace this sentinel with the
    // original input, while an invalid base must leave it untouched.
    let mut end = input.as_ptr().wrapping_add(1).cast_mut();
    // SAFETY: each implementation returns its current thread's writable errno.
    unsafe { *errno() = 1234 };
    let value = parse(input.as_ptr(), &mut end);
    // SAFETY: same thread-local errno cell as before the conversion.
    (value, consumed(end, input.as_ptr()), unsafe { *errno() })
}

fn record_difference<T: std::fmt::Debug + PartialEq>(
    differences: &mut Vec<String>,
    label: &str,
    actual: T,
    expected: T,
) {
    if actual != expected {
        differences.push(format!("{label}: candidate={actual:?}, glibc={expected:?}"));
    }
}

#[test]
#[cfg(target_pointer_width = "64")]
fn wide_integer_locales_match_glibc_for_legacy_and_c23() {
    use frankenlibc_abi::{errno_abi, isoc_abi as c23, locale_abi, wchar_abi as fl};

    let _lock = LOCALE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let signed: [(&CStr, WcstolLFn); 4] = [
        (c"wcstol_l", fl::wcstol_l),
        (c"wcstoll_l", fl::wcstoll_l),
        (c"__isoc23_wcstol_l", c23::__isoc23_wcstol_l),
        (c"__isoc23_wcstoll_l", c23::__isoc23_wcstoll_l),
    ];
    let unsigned: [(&CStr, WcstoulLFn); 4] = [
        (c"wcstoul_l", fl::wcstoul_l),
        (c"wcstoull_l", fl::wcstoull_l),
        (c"__isoc23_wcstoul_l", c23::__isoc23_wcstoul_l),
        (c"__isoc23_wcstoull_l", c23::__isoc23_wcstoull_l),
    ];
    type Signed = unsafe extern "C" fn(*const wchar_t, *mut *mut wchar_t, c_int) -> c_long;
    type Unsigned = unsafe extern "C" fn(*const wchar_t, *mut *mut wchar_t, c_int) -> c_ulong;
    let active_signed: [(&CStr, Signed); 4] = [
        (c"wcstol", fl::wcstol),
        (c"wcstoll", fl::wcstoll),
        (c"__isoc23_wcstol", c23::__isoc23_wcstol),
        (c"__isoc23_wcstoll", c23::__isoc23_wcstoll),
    ];
    let active_unsigned: [(&CStr, Unsigned); 4] = [
        (c"wcstoul", fl::wcstoul),
        (c"wcstoull", fl::wcstoull),
        (c"__isoc23_wcstoul", c23::__isoc23_wcstoul),
        (c"__isoc23_wcstoull", c23::__isoc23_wcstoull),
    ];
    // SAFETY: every symbol uses the documented C signature. Linux LP64 long
    // and long long have the same representation and calling convention.
    let host_signed = signed.map(|(name, candidate)| unsafe {
        std::mem::transmute::<*mut c_void, WcstolLFn>(host_symbol(name, candidate as usize))
    });
    // SAFETY: same documented signatures for the unsigned locale family.
    let host_unsigned = unsigned.map(|(name, candidate)| unsafe {
        std::mem::transmute::<*mut c_void, WcstoulLFn>(host_symbol(name, candidate as usize))
    });
    // SAFETY: the active-locale functions omit only the locale_t argument.
    let host_active_signed = active_signed.map(|(name, candidate)| unsafe {
        std::mem::transmute::<*mut c_void, Signed>(host_symbol(name, candidate as usize))
    });
    // SAFETY: same documented signatures for the unsigned active family.
    let host_active_unsigned = active_unsigned.map(|(name, candidate)| unsafe {
        std::mem::transmute::<*mut c_void, Unsigned>(host_symbol(name, candidate as usize))
    });
    // SAFETY: these three functions have their documented locale/errno ABIs.
    let (host_use, host_set, host_errno) = unsafe {
        (
            std::mem::transmute::<*mut c_void, UselocaleFn>(host_symbol(
                c"uselocale",
                locale_abi::uselocale as usize,
            )),
            std::mem::transmute::<*mut c_void, SetlocaleFn>(host_symbol(
                c"setlocale",
                locale_abi::setlocale as usize,
            )),
            std::mem::transmute::<*mut c_void, ErrnoFn>(host_symbol(
                c"__errno_location",
                errno_abi::__errno_location as usize,
            )),
        )
    };
    let fl_errno = errno_abi::__errno_location;
    let c = locales(c"C");
    let utf8 = locales(c"C.UTF-8");
    let mut cases: Vec<(String, c_int)> = SIGNED_CASES
        .iter()
        .chain(UNSIGNED_CASES)
        .map(|&(text, base)| (text.to_owned(), base))
        .collect();
    for (text, base) in [
        ("\u{2003}-42!", 10),
        ("\u{3000}+0xff!", 16),
        ("\u{2000}\t-077!", 0),
        ("\u{205f}zz!", 36),
        ("\u{2003}-0B101!", 0),
        ("\u{2003}+0b11!", 2),
        ("\u{2003}0x!", 0),
        ("\u{2003}-!", 10),
        ("\u{2003}\u{3000}", 10),
        ("\u{00a0}42!", 10),
        ("\u{2007}42!", 10),
        ("\u{202f}42!", 10),
        ("\u{2003}\u{ff14}\u{ff12}!", 10),
        ("\u{2003}9223372036854775808!", 10),
        ("\u{2003}-9223372036854775809!", 10),
        ("\u{2003}18446744073709551616!", 10),
        ("\u{2003}-1!", 10),
        ("\u{2003}42!", 1),
        ("\u{2003}42!", 37),
        ("", 10),
    ] {
        cases.push((text.to_owned(), base));
    }
    cases.push((format!("{}-42!", "\u{2003} ".repeat(300)), 0));
    cases.push((format!("\u{2003}{}0B101!", " ".repeat(511)), 0));
    let mut differences = Vec::new();
    let mut comparisons = 0;

    // SAFETY: locale queries return retained NUL-terminated names. Every
    // selection below uses the matching implementation's live locale object.
    let (old_host, old_fl, old_global_host, old_global_fl) = unsafe {
        (
            host_use(std::ptr::null_mut()),
            locale_abi::uselocale(std::ptr::null_mut()),
            CStr::from_ptr(host_set(libc::LC_CTYPE, std::ptr::null())).to_owned(),
            CStr::from_ptr(locale_abi::setlocale(libc::LC_CTYPE, std::ptr::null())).to_owned(),
        )
    };
    for (name, explicit, ambient) in [(c"C", c, utf8), (c"C.UTF-8", utf8, c)] {
        // Give each explicit call the opposite ambient locale. This rejects
        // implementations that ignore the supplied object or temporarily
        // change process-global state instead of snapshotting LC_CTYPE.
        // SAFETY: all handles remain live until after restoration below.
        unsafe {
            host_use(ambient.0);
            locale_abi::uselocale(ambient.1);
        }
        for (text, base) in &cases {
            let input = wide(text);
            for ((symbol, candidate), host) in signed.iter().zip(host_signed) {
                let label = format!("{symbol:?}/{name:?}/{text:?}/base={base}");
                let expected = parse_result(&input, host_errno, |ptr, end| {
                    // SAFETY: valid wide input/endptr and host-owned locale.
                    unsafe { host(ptr, end, *base, explicit.0) }
                });
                let actual = parse_result(&input, fl_errno, |ptr, end| {
                    // SAFETY: same input contract and candidate-owned locale.
                    unsafe { candidate(ptr, end, *base, explicit.1) }
                });
                record_difference(&mut differences, &label, actual, expected);
                comparisons += 1;
            }
            for ((symbol, candidate), host) in unsigned.iter().zip(host_unsigned) {
                let label = format!("{symbol:?}/{name:?}/{text:?}/base={base}");
                let expected = parse_result(&input, host_errno, |ptr, end| {
                    // SAFETY: valid wide input/endptr and host-owned locale.
                    unsafe { host(ptr, end, *base, explicit.0) }
                });
                let actual = parse_result(&input, fl_errno, |ptr, end| {
                    // SAFETY: same input contract and candidate-owned locale.
                    unsafe { candidate(ptr, end, *base, explicit.1) }
                });
                record_difference(&mut differences, &label, actual, expected);
                comparisons += 1;
            }
        }
        // SAFETY: null queries the current selection without changing it.
        assert_eq!(unsafe { host_use(std::ptr::null_mut()) }, ambient.0);
        assert_eq!(
            unsafe { locale_abi::uselocale(std::ptr::null_mut()) },
            ambient.1
        );

        // Exercise both sources of the ordinary functions' active locale:
        // explicit per-thread selection and LC_GLOBAL_LOCALE after setlocale.
        for use_global in [false, true] {
            // SAFETY: the GNU sentinel selects the live process locale; all
            // other selections are owned handles. Set only LC_CTYPE.
            unsafe {
                if use_global {
                    host_set(libc::LC_CTYPE, name.as_ptr());
                    locale_abi::setlocale(libc::LC_CTYPE, name.as_ptr());
                }
                let global = (-1isize) as *mut c_void;
                host_use(if use_global { global } else { explicit.0 });
                locale_abi::uselocale(if use_global { global } else { explicit.1 });
            }
            for (text, base) in &cases {
                let input = wide(text);
                for ((symbol, candidate), host) in active_signed.iter().zip(host_active_signed) {
                    let label = format!("{symbol:?}/{name:?}/global={use_global}/{text:?}/{base}");
                    let expected = parse_result(&input, host_errno, |ptr, end| {
                        // SAFETY: valid terminated input and writable endptr.
                        unsafe { host(ptr, end, *base) }
                    });
                    let actual = parse_result(&input, fl_errno, |ptr, end| {
                        // SAFETY: same live input and writable endptr.
                        unsafe { candidate(ptr, end, *base) }
                    });
                    record_difference(&mut differences, &label, actual, expected);
                    comparisons += 1;
                }
                for ((symbol, candidate), host) in active_unsigned.iter().zip(host_active_unsigned)
                {
                    let label = format!("{symbol:?}/{name:?}/global={use_global}/{text:?}/{base}");
                    let expected = parse_result(&input, host_errno, |ptr, end| {
                        // SAFETY: valid terminated input and writable endptr.
                        unsafe { host(ptr, end, *base) }
                    });
                    let actual = parse_result(&input, fl_errno, |ptr, end| {
                        // SAFETY: same live input and writable endptr.
                        unsafe { candidate(ptr, end, *base) }
                    });
                    record_difference(&mut differences, &label, actual, expected);
                    comparisons += 1;
                }
            }
        }
    }
    // SAFETY: restore the original selections before retiring any test handle.
    unsafe {
        host_use(old_host);
        locale_abi::uselocale(old_fl);
        host_set(libc::LC_CTYPE, old_global_host.as_ptr());
        locale_abi::setlocale(libc::LC_CTYPE, old_global_fl.as_ptr());
        let free = host_freelocale();
        free(c.0);
        free(utf8.0);
        locale_abi::freelocale(c.1);
        locale_abi::freelocale(utf8.1);
    }
    assert!(
        comparisons >= 1_500,
        "the locale matrix must actually execute"
    );
    assert!(
        differences.is_empty(),
        "{} differences in {comparisons} comparisons; first failures:\n{}",
        differences.len(),
        differences
            .iter()
            .take(16)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
    );
}
