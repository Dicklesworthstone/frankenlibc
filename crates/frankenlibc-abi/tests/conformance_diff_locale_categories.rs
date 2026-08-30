#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc locale oracle

//! Per-category `setlocale` state, and the `LC_ALL` composite string.
//!
//! fl tracked ONE charset for the whole process, so two things were wrong and
//! neither was visible from a single-category test:
//!
//! * `setlocale(LC_NUMERIC, "C.UTF-8")` moved the multibyte codec, even though
//!   POSIX puts conversion under `LC_CTYPE`. A program that localises only its
//!   number formatting got a different `mbrtowc`.
//! * `setlocale(LC_ALL, NULL)` could only ever answer a single name. glibc
//!   answers a twelve-field composite when the categories disagree, and
//!   real code compares that string.
//!
//! fl also stopped at `LC_ALL` (6). glibc has six GNU categories ABOVE it and
//! accepts all of them — measured by sweeping `setlocale(cat, NULL)` over
//! -2..=14: 0..=12 answer `"C"`, while -1, -2, 13 and 14 return NULL with
//! EINVAL. `setlocale(LC_PAPER, NULL)` is a conforming call that fl failed.
//!
//! Every arm below moves BOTH libraries and restores the startup locale, since
//! `setlocale` is process-global in each.

use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::{Mutex, OnceLock};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::{host_addr, host_fn};

/// `int *__errno_location(void)`.
type ErrnoLocationFn = unsafe extern "C" fn() -> *mut c_int;

/// Host glibc's `__errno_location`, resolved out of libc.so.6 and proven not to
/// be fl's own export.
///
/// The host FUNCTION arms here are already dlsym-resolved; the errno arm was
/// not. fl exports `__errno_location` under
/// `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`, so in a release test
/// binary the link-time `libc::__errno_location` bound to FL's slot and the host
/// half of `run_swprintf` zeroed fl's errno and read back its own zero instead
/// of what glibc set.
///
/// Debug hid it for a specific reason worth recording: `errno_abi::set_abi_errno`
/// mirrors every value into the HOST errno slot as well (interpose mode), so with
/// fl's symbol mangled both arms happened to read the same live slot. Release
/// breaks that coincidence. Measured: this gate failed `--release` with
/// `errno for utf-8 e-acute under "C" left: 84 right: 0` — fl's EILSEQ against a
/// host errno of 0 — while passing in debug. See bd-g1sjty.
fn host_errno_location() -> ErrnoLocationFn {
    // SAFETY: the resolved address is glibc's `__errno_location`, declared
    // `int *__errno_location(void)`; fl's own export is handed over so a
    // collapsed oracle aborts instead of silently reading fl's errno.
    unsafe {
        let addr = host_addr(
            c"__errno_location",
            frankenlibc_abi::errno_abi::__errno_location as ErrnoLocationFn as *const (),
        );
        std::mem::transmute::<*mut std::ffi::c_void, ErrnoLocationFn>(addr)
    }
}

use frankenlibc_abi::locale_abi::{
    locale_reset_active_charset_for_tests, setlocale as fl_setlocale,
};

type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *const c_char;

const LC_CTYPE: c_int = 0;
const LC_NUMERIC: c_int = 1;
const LC_ALL: c_int = 6;
const LC_PAPER: c_int = 7;
const LC_IDENTIFICATION: c_int = 12;

fn locale_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn host() -> SetlocaleFn {
    // SAFETY: `char *setlocale(int, const char *)`, with fl's own definition
    // supplied so the oracle refuses to resolve back to fl (bd-v0388t).
    unsafe { host_fn(c"setlocale", fl_setlocale as *const ()) }
}

fn text(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: non-null and NUL-terminated by the C contract.
    Some(
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Set one category in BOTH libraries and return the two answers.
fn set_both(cat: c_int, name: &CStr) -> (Option<String>, Option<String>) {
    // SAFETY: NUL-terminated name, live for the call.
    let host_out = unsafe { host()(cat, name.as_ptr()) };
    // SAFETY: same.
    let fl_out = unsafe { fl_setlocale(cat, name.as_ptr()) };
    (text(fl_out), text(host_out))
}

/// Query one category in BOTH libraries.
fn query_both(cat: c_int) -> (Option<String>, Option<String>) {
    // SAFETY: a NULL name queries without mutating.
    let host_out = unsafe { host()(cat, std::ptr::null()) };
    // SAFETY: same.
    let fl_out = unsafe { fl_setlocale(cat, std::ptr::null()) };
    (text(fl_out), text(host_out))
}

/// Put both libraries back to the startup locale.
struct Restore;

impl Drop for Restore {
    fn drop(&mut self) {
        // SAFETY: NUL-terminated literal.
        unsafe { host()(LC_ALL, c"C".as_ptr()) };
        locale_reset_active_charset_for_tests();
    }
}

/// glibc accepts categories 0..=12 and refuses everything else.
#[test]
fn category_range_matches_glibc() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = Restore;
    // SAFETY: NUL-terminated literal.
    unsafe { host()(LC_ALL, c"C".as_ptr()) };
    locale_reset_active_charset_for_tests();

    for cat in -2..=14 {
        let (fl_out, host_out) = query_both(cat);
        assert_eq!(
            fl_out.is_some(),
            host_out.is_some(),
            "category {cat}: fl={fl_out:?} glibc={host_out:?}"
        );
    }
    // Spot-check the two ends of the GNU range that fl used to reject outright.
    assert!(
        query_both(LC_PAPER).0.is_some(),
        "LC_PAPER must be accepted"
    );
    assert!(
        query_both(LC_IDENTIFICATION).0.is_some(),
        "LC_IDENTIFICATION must be accepted"
    );
}

/// Setting one category must not move the others.
#[test]
fn a_single_category_moves_alone() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = Restore;
    // SAFETY: NUL-terminated literal.
    unsafe { host()(LC_ALL, c"C".as_ptr()) };
    locale_reset_active_charset_for_tests();

    let (fl_set, host_set) = set_both(LC_NUMERIC, c"C.UTF-8");
    assert_eq!(fl_set, host_set, "setlocale(LC_NUMERIC, C.UTF-8)");

    let (fl_ctype, host_ctype) = query_both(LC_CTYPE);
    assert_eq!(fl_ctype, host_ctype, "LC_CTYPE after moving LC_NUMERIC");
    assert_eq!(
        fl_ctype.as_deref(),
        Some("C"),
        "LC_CTYPE must NOT follow LC_NUMERIC — conversion is LC_CTYPE's category"
    );

    let (fl_numeric, host_numeric) = query_both(LC_NUMERIC);
    assert_eq!(fl_numeric, host_numeric);
    assert_eq!(fl_numeric.as_deref(), Some("C.UTF-8"));
}

/// `LC_ALL` answers a bare name when the categories agree and glibc's
/// composite when they do not.
#[test]
fn lc_all_reports_a_composite_when_categories_differ() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = Restore;
    // SAFETY: NUL-terminated literal.
    unsafe { host()(LC_ALL, c"C".as_ptr()) };
    locale_reset_active_charset_for_tests();

    let (fl_uniform, host_uniform) = query_both(LC_ALL);
    assert_eq!(fl_uniform, host_uniform, "uniform LC_ALL");
    assert_eq!(
        fl_uniform.as_deref(),
        Some("C"),
        "a bare name when all agree"
    );

    let _ = set_both(LC_CTYPE, c"C.UTF-8");
    let (fl_mixed, host_mixed) = query_both(LC_ALL);
    assert_eq!(fl_mixed, host_mixed, "composite LC_ALL");

    let composite = fl_mixed.expect("a composite string");
    assert!(
        composite.starts_with("LC_CTYPE=C.UTF-8;LC_NUMERIC=C;"),
        "field order is glibc's, not the numeric category order: {composite}"
    );
    assert_eq!(
        composite.matches(';').count(),
        11,
        "twelve fields means eleven separators and no trailing one: {composite}"
    );
    assert!(
        !composite.contains("LC_ALL="),
        "LC_ALL is a pseudo-category and must not appear in its own composite"
    );
}

/// Setting `LC_ALL` collapses the composite back to a single name.
#[test]
fn setting_lc_all_makes_the_report_uniform_again() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = Restore;
    // SAFETY: NUL-terminated literal.
    unsafe { host()(LC_ALL, c"C".as_ptr()) };
    locale_reset_active_charset_for_tests();

    let _ = set_both(LC_CTYPE, c"C.UTF-8");
    assert!(
        query_both(LC_ALL).0.unwrap().contains(';'),
        "should be mixed"
    );

    let _ = set_both(LC_ALL, c"C.UTF-8");
    let (fl_out, host_out) = query_both(LC_ALL);
    assert_eq!(fl_out, host_out);
    assert_eq!(fl_out.as_deref(), Some("C.UTF-8"), "uniform again");
}

// ---------------------------------------------------------------------------
// The widen path: swprintf %s must honour LC_CTYPE and fail with EILSEQ
// ---------------------------------------------------------------------------

type SwprintfFn =
    unsafe extern "C" fn(*mut libc::wchar_t, usize, *const libc::wchar_t, ...) -> c_int;

fn host_swprintf() -> SwprintfFn {
    // SAFETY: `int swprintf(wchar_t *, size_t, const wchar_t *, ...)`, with fl's
    // own definition supplied so the oracle refuses to resolve back to fl.
    unsafe {
        host_fn(
            c"swprintf",
            frankenlibc_abi::wchar_abi::swprintf as *const (),
        )
    }
}

fn wide_format_percent_s() -> Vec<libc::wchar_t> {
    vec![b'%' as libc::wchar_t, b's' as libc::wchar_t, 0]
}

/// `(rc, errno, contents)` from one library's `swprintf(buf, 64, L"%s", narrow)`.
fn run_swprintf(which: Option<SwprintfFn>, narrow: &CStr) -> (c_int, c_int, String) {
    let fmt = wide_format_percent_s();
    let mut buf = [0 as libc::wchar_t; 64];
    // SAFETY: 64-element buffer, NUL-terminated wide format, one narrow arg.
    unsafe {
        match which {
            Some(host) => {
                let host_errno = host_errno_location();
                *host_errno() = 0;
                let rc = host(buf.as_mut_ptr(), 64, fmt.as_ptr(), narrow.as_ptr());
                let err = *host_errno();
                (rc, err, wide_to_string(&buf, rc))
            }
            None => {
                *frankenlibc_abi::errno_abi::__errno_location() = 0;
                let rc = frankenlibc_abi::wchar_abi::swprintf(
                    buf.as_mut_ptr(),
                    64,
                    fmt.as_ptr(),
                    narrow.as_ptr(),
                );
                let err = *frankenlibc_abi::errno_abi::__errno_location();
                (rc, err, wide_to_string(&buf, rc))
            }
        }
    }
}

fn wide_to_string(buf: &[libc::wchar_t], rc: c_int) -> String {
    if rc <= 0 {
        return String::new();
    }
    buf.iter()
        .take_while(|&&c| c != 0)
        .filter_map(|&c| char::from_u32(c as u32))
        .collect()
}

/// The widen path used to answer U+FFFD for anything it could not convert,
/// which SUCCEEDED on two inputs glibc rejects.
#[test]
fn swprintf_percent_s_honours_lc_ctype() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = Restore;

    let cases: &[(&CStr, &str)] = &[
        (c"hello", "ascii"),
        (c"caf\xc3\xa9", "utf-8 e-acute"),
        (c"a\x80b", "lone continuation byte"),
    ];

    for locale in [c"C", c"C.UTF-8"] {
        // SAFETY: NUL-terminated names.
        unsafe { host()(LC_ALL, locale.as_ptr()) };
        let _ = unsafe { fl_setlocale(LC_ALL, locale.as_ptr()) };

        for (narrow, label) in cases {
            let host_out = run_swprintf(Some(host_swprintf()), narrow);
            let fl_out = run_swprintf(None, narrow);
            assert_eq!(
                (fl_out.0, fl_out.2.clone()),
                (host_out.0, host_out.2.clone()),
                "swprintf %s of {label} under {locale:?}"
            );
            if host_out.0 < 0 {
                assert_eq!(
                    fl_out.1, host_out.1,
                    "errno for {label} under {locale:?} — a conversion failure \
                     must be EILSEQ, not a silent replacement character"
                );
            }
        }
    }
}
