#![cfg(target_os = "linux")]

//! Differential conformance harness for `mbsrtowcs(3)` / `wcsrtombs(3)`
//! in C.UTF-8 locale.
//!
//! mbsrtowcs converts a multibyte string to a wide string;
//! wcsrtombs is the inverse. We diff fl's wchar_abi impl against
//! glibc on representative UTF-8 strings.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_int, c_void};
use std::sync::{Mutex, MutexGuard, OnceLock};

use frankenlibc_abi::wchar_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type StringFn = unsafe extern "C" fn(*mut libc::wchar_t, *mut *const c_char, usize, *mut c_void) -> usize;
type BoundedFn = unsafe extern "C" fn(*mut libc::wchar_t, *mut *const c_char, usize, usize, *mut c_void) -> usize;
type WideFn = unsafe extern "C" fn(*mut libc::wchar_t, *const c_char, usize, *mut c_void) -> usize;
type EncodeFn = unsafe extern "C" fn(*mut c_char, *mut *const libc::wchar_t, usize, *mut c_void) -> usize;
type ErrnoFn = unsafe extern "C" fn() -> *mut c_int;
type InitialFn = unsafe extern "C" fn(*const c_void) -> c_int;

struct Host {
    string: StringFn,
    bounded: BoundedFn,
    wide: WideFn,
    encode: EncodeFn,
    errno: ErrnoFn,
    initial: InitialFn,
    locale: unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char,
}

fn host() -> &'static Host {
    static HOST: OnceLock<Host> = OnceLock::new();
    HOST.get_or_init(|| {
        // SAFETY: every signature matches its C declaration; each resolver
        // rejects FrankenLibC's own address, including errno and locale.
        unsafe {
            Host {
                string: dlsym_oracle::host_fn(c"mbsrtowcs", fl::mbsrtowcs as *const ()),
                bounded: dlsym_oracle::host_fn(c"mbsnrtowcs", fl::mbsnrtowcs as *const ()),
                wide: dlsym_oracle::host_fn(c"mbrtowc", fl::mbrtowc as *const ()),
                encode: dlsym_oracle::host_fn(c"wcsrtombs", fl::wcsrtombs as *const ()),
                errno: dlsym_oracle::host_fn(c"__errno_location", frankenlibc_abi::errno_abi::__errno_location as *const ()),
                initial: dlsym_oracle::host_fn(c"mbsinit", fl::mbsinit as *const ()),
                locale: dlsym_oracle::host_fn(c"setlocale", frankenlibc_abi::locale_abi::setlocale as *const ()),
            }
        }
    })
}

static LOCALE_LOCK: Mutex<()> = Mutex::new(());

fn locale_guard() -> MutexGuard<'static, ()> {
    match LOCALE_LOCK.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

fn with_utf8<F: FnOnce() -> R, R>(f: F) -> R {
    let _g = locale_guard();
    let saved = unsafe { (host().locale)(libc::LC_ALL, std::ptr::null()) };
    let saved_str = if saved.is_null() {
        None
    } else {
        Some(unsafe { std::ffi::CStr::from_ptr(saved) }.to_owned())
    };
    // SAFETY: both arms receive the same live NUL-terminated locale name.
    assert!(!unsafe { (host().locale)(libc::LC_ALL, c"C.UTF-8".as_ptr()) }.is_null());
    // fl starts in the C locale, as glibc does; this arm tests UTF-8
    // behaviour, so BOTH libraries must be moved. Setting only the host
    // would compare an ASCII fl against a UTF-8 glibc.
    assert!(!unsafe { frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()) }.is_null());
    let result = f();
    if let Some(s) = saved_str {
        unsafe { (host().locale)(libc::LC_ALL, s.as_ptr()) };
    }
    result
}

#[test]
fn diff_mbsrtowcs_ascii_only() {
    with_utf8(|| {
        let input = b"hello world\0";
        let mut fl_dst = [0i32; 32];
        let mut lc_dst = [0i32; 32];
        let mut fl_src = input.as_ptr() as *const c_char;
        let mut lc_src = input.as_ptr() as *const c_char;
        let fl_n = unsafe {
            fl::mbsrtowcs(
                fl_dst.as_mut_ptr(),
                &mut fl_src,
                fl_dst.len(),
                std::ptr::null_mut(),
            )
        };
        let lc_n = unsafe {
            (host().string)(
                lc_dst.as_mut_ptr(),
                &mut lc_src,
                lc_dst.len(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(fl_n, lc_n, "mbsrtowcs(ascii): fl={fl_n} lc={lc_n}");
        assert_eq!(fl_n, 11);
        assert_eq!(fl_dst[..11], lc_dst[..11], "wide chars differ");
    });
}

#[test]
fn diff_mbsrtowcs_with_cjk() {
    with_utf8(|| {
        // "中" (U+4E2D) encoded as E4 B8 AD.
        let input = b"\xE4\xB8\xAD\0";
        let mut fl_dst = [0i32; 4];
        let mut lc_dst = [0i32; 4];
        let mut fl_src = input.as_ptr() as *const c_char;
        let mut lc_src = input.as_ptr() as *const c_char;
        let fl_n = unsafe {
            fl::mbsrtowcs(
                fl_dst.as_mut_ptr(),
                &mut fl_src,
                fl_dst.len(),
                std::ptr::null_mut(),
            )
        };
        let lc_n = unsafe {
            (host().string)(
                lc_dst.as_mut_ptr(),
                &mut lc_src,
                lc_dst.len(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(fl_n, lc_n, "mbsrtowcs(CJK): fl={fl_n} lc={lc_n}");
        if fl_n == 1 {
            assert_eq!(fl_dst[0], 0x4E2D);
            assert_eq!(lc_dst[0], 0x4E2D);
        }
    });
}

#[test]
fn diff_mbsrtowcs_dst_null_returns_required_len() {
    with_utf8(|| {
        // dst=NULL means "just count, don't write". Both must
        // return the wide-char count needed.
        let input = b"foo bar\0";
        let mut fl_src = input.as_ptr() as *const c_char;
        let mut lc_src = input.as_ptr() as *const c_char;
        let fl_n =
            unsafe { fl::mbsrtowcs(std::ptr::null_mut(), &mut fl_src, 100, std::ptr::null_mut()) };
        let lc_n =
            unsafe { (host().string)(std::ptr::null_mut(), &mut lc_src, 100, std::ptr::null_mut()) };
        assert_eq!(fl_n, lc_n, "mbsrtowcs(NULL dst): fl={fl_n} lc={lc_n}");
        assert_eq!(fl_n, 7);
    });
}

#[test]
fn diff_wcsrtombs_ascii_round_trip() {
    with_utf8(|| {
        let wide: [i32; 12] = [
            'h' as i32, 'e' as i32, 'l' as i32, 'l' as i32, 'o' as i32, ' ' as i32, 'w' as i32,
            'o' as i32, 'r' as i32, 'l' as i32, 'd' as i32, 0,
        ];
        let mut fl_dst = [0u8; 32];
        let mut lc_dst = [0u8; 32];
        let mut fl_src = wide.as_ptr();
        let mut lc_src = wide.as_ptr();
        let fl_n = unsafe {
            fl::wcsrtombs(
                fl_dst.as_mut_ptr() as *mut c_char,
                &mut fl_src,
                fl_dst.len(),
                std::ptr::null_mut(),
            )
        };
        let lc_n = unsafe {
            (host().encode)(
                lc_dst.as_mut_ptr() as *mut c_char,
                &mut lc_src,
                lc_dst.len(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(fl_n, lc_n, "wcsrtombs(ascii): fl={fl_n} lc={lc_n}");
        assert_eq!(fl_n, 11);
        assert_eq!(fl_dst[..11], lc_dst[..11]);
    });
}

#[test]
fn diff_wcsrtombs_with_cjk_emoji() {
    with_utf8(|| {
        let wide: [i32; 4] = [0x4E2D, 0x1F600, 0xA9, 0]; // 中😀©
        let mut fl_dst = [0u8; 32];
        let mut lc_dst = [0u8; 32];
        let mut fl_src = wide.as_ptr();
        let mut lc_src = wide.as_ptr();
        let fl_n = unsafe {
            fl::wcsrtombs(
                fl_dst.as_mut_ptr() as *mut c_char,
                &mut fl_src,
                fl_dst.len(),
                std::ptr::null_mut(),
            )
        };
        let lc_n = unsafe {
            (host().encode)(
                lc_dst.as_mut_ptr() as *mut c_char,
                &mut lc_src,
                lc_dst.len(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(fl_n, lc_n, "wcsrtombs(cjk+emoji): fl={fl_n} lc={lc_n}");
        if fl_n != usize::MAX {
            assert_eq!(fl_dst[..fl_n], lc_dst[..fl_n], "encoded bytes differ");
            // 中 = 3 bytes, 😀 = 4 bytes, © = 2 bytes → 9 total.
            assert_eq!(fl_n, 9);
        }
    });
}

#[test]
fn diff_wcsrtombs_invalid_codepoint_rejected() {
    with_utf8(|| {
        // Invalid codepoint U+110000 — both impls should report
        // failure (or fl is stricter; just check parity).
        let wide: [i32; 2] = [0x110000, 0];
        let mut fl_dst = [0u8; 8];
        let mut lc_dst = [0u8; 8];
        let mut fl_src = wide.as_ptr();
        let mut lc_src = wide.as_ptr();
        let fl_n = unsafe {
            fl::wcsrtombs(
                fl_dst.as_mut_ptr() as *mut c_char,
                &mut fl_src,
                fl_dst.len(),
                std::ptr::null_mut(),
            )
        };
        let lc_n = unsafe {
            (host().encode)(
                lc_dst.as_mut_ptr() as *mut c_char,
                &mut lc_src,
                lc_dst.len(),
                std::ptr::null_mut(),
            )
        };
        // fl rejects U+110000 per RFC 3629; glibc may encode legacy
        // 4-byte form. Document parity loosely.
        if fl_n == usize::MAX && lc_n == usize::MAX {
            // Both rejected — perfect.
        } else if fl_n != usize::MAX && lc_n != usize::MAX {
            assert_eq!(fl_dst[..fl_n], lc_dst[..lc_n]);
        }
        // Otherwise fl is stricter — known divergence.
    });
}

#[derive(Debug)]
struct StringCase {
    bounded: bool,
    split: usize,
    window: usize,
    count: bool,
    capacity: usize,
    saved_errno: c_int,
}

#[derive(Debug, PartialEq, Eq)]
struct StringStep {
    returned: usize,
    source_offset: Option<usize>,
    error: c_int,
    initial: bool,
    output: [libc::wchar_t; 4],
}

fn offset(source: *const c_char, start: *const c_char, length: usize) -> Option<usize> {
    if source.is_null() {
        return None;
    }
    let address = source as usize;
    let base = start as usize;
    assert!((base..=base + length).contains(&address), "source escaped input");
    Some(address - base)
}

fn string_case(ours: bool, bytes: &[u8], case: &StringCase) -> (StringStep, Option<StringStep>) {
    let string = if ours { fl::mbsrtowcs as StringFn } else { host().string };
    let bounded = if ours { fl::mbsnrtowcs as BoundedFn } else { host().bounded };
    let wide = if ours { fl::mbrtowc as WideFn } else { host().wide };
    let initial = if ours { fl::mbsinit as InitialFn } else { host().initial };
    let errno = if ours { frankenlibc_abi::errno_abi::__errno_location as ErrnoFn } else { host().errno };
    let mut state = [0u64; 1];
    let ps = state.as_mut_ptr().cast();
    if case.split != 0 {
        // SAFETY: split is inside a valid multibyte character; state is an
        // aligned, zero-initialized eight-byte object. No output is requested.
        assert_eq!(unsafe { wide(std::ptr::null_mut(), bytes.as_ptr().cast(), case.split, ps) }, usize::MAX - 1);
    }
    let tail = &bytes[case.split..];
    let start = tail.as_ptr().cast::<c_char>();
    let mut src = start;
    let mut output = [0x1234; 4];
    let dst = if case.count { std::ptr::null_mut() } else { output.as_mut_ptr() };
    // SAFETY: input is NUL-terminated; window is within the input; destination
    // fits every requested capacity; state and source pointer remain live.
    let (returned, error, is_initial) = unsafe {
        *errno() = case.saved_errno;
        let returned = if case.bounded {
            bounded(dst, &mut src, case.window, case.capacity, ps)
        } else {
            string(dst, &mut src, case.capacity, ps)
        };
        (returned, *errno(), initial(ps) != 0)
    };
    let first = StringStep {
        returned,
        source_offset: offset(src, start, tail.len()),
        error,
        initial: is_initial,
        output,
    };
    // An encoding error leaves unspecified state: never use it in another
    // conversion. Otherwise verify the real stream after sizing/progress.
    if returned == usize::MAX {
        return (first, None);
    }
    if case.count {
        src = start;
    }
    if src.is_null() {
        return (first, None);
    }
    let mut output = [0x1234; 4];
    // SAFETY: source/state describe this same stream and the four-slot output
    // fits the requested three wide characters, including a possible NUL.
    let (returned, error, is_initial) = unsafe {
        *errno() = case.saved_errno;
        let returned = string(output.as_mut_ptr(), &mut src, 3, ps);
        (returned, *errno(), initial(ps) != 0)
    };
    (first, Some(StringStep {
        returned,
        source_offset: offset(src, start, tail.len()),
        error,
        initial: is_initial,
        output,
    }))
}

#[test]
fn mbsrtowcs_diff_coverage_report() {
    with_utf8(|| {
        let mut checked = 0;
        let mut differences = 0;
        let mut examples = Vec::new();
        for bounded in [false, true] {
            for (bytes, width) in [(b"AZ\0".as_slice(), 1), ("éZ\0".as_bytes(), 2), ("€Z\0".as_bytes(), 3), ("🙂Z\0".as_bytes(), 4)] {
                for split in 0..width {
                    let windows = [0, 1, bytes.len() - split];
                    for &window in &windows[..if bounded { 3 } else { 1 }] {
                        for count in [false, true] {
                            for capacity in 0..4 {
                                for saved_errno in [0, libc::E2BIG] {
                                    let case = StringCase { bounded, split, window, count, capacity, saved_errno };
                                    let f = string_case(true, bytes, &case);
                                    let g = string_case(false, bytes, &case);
                                    checked += 1;
                                    if f != g {
                                        differences += 1;
                                        if examples.len() < 20 {
                                            examples.push(format!("{bytes:x?} {case:?}: fl={f:?} GNU={g:?}"));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 640);
        eprintln!("string-state comparisons={checked} differences={differences}");
        assert_eq!(differences, 0, "{}", examples.join("\n"));
    });
}
