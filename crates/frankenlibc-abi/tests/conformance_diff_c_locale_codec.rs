#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc locale oracle

//! Selecting the POSIX C locale must change the CODEC, not just the strings.
//!
//! a25c7a310 split `Charset::{Ascii,Utf8}` apart so that the name `setlocale`
//! reports, `nl_langinfo(CODESET)`, `MB_CUR_MAX` and the multibyte conversion
//! all derive from one selector. It shipped with nothing that could fail if the
//! codec half were reverted: `locale_abi_test` checks the two strings, and every
//! mb/wc differential runs in `C.UTF-8`, where the ASCII arm is never taken. A
//! gate that cannot fail is not evidence, so this is the gate.
//!
//! Each assertion is differential against live host glibc with BOTH libraries
//! switched to the same locale — the point being that fl's C locale agrees with
//! glibc's C locale, which a hand-written expectation could not establish.
//!
//! ## The measured contract
//!
//! Probed against host glibc 2.42 (`ldd (Ubuntu GLIBC 2.42-0ubuntu3.1)`):
//!
//! ```text
//!   LC_ALL=C        -> "C"        CODESET=ANSI_X3.4-1968  MB_CUR_MAX=1
//!   LC_ALL=POSIX    -> "C"        (canonicalises to "C")
//!   LC_ALL=C.UTF-8  -> "C.UTF-8"  CODESET=UTF-8           MB_CUR_MAX=6
//!     C:       'A'->1   0xC3,0xA9->-1 EILSEQ   0x80->-1 EILSEQ   0x7F->1
//!     C.UTF-8: 'A'->1   0xC3,0xA9->2/U+00E9    0x80->-1 EILSEQ
//! ```
//!
//! Note the shape of the C-locale rejection: a well-formed UTF-8 lead byte is
//! refused AT THE LEAD rather than consumed, so the answer is `-1` and not a
//! partial decode.
//!
//! ## Why the state resets are not optional
//!
//! `mbtowc` carries an internal shift state, and a probe that leaves a partial
//! sequence in it poisons the NEXT probe across a `setlocale`. That is not
//! hypothetical: while measuring the contract above, an unreset run reported
//! `mbtowc("A")` failing with `EILSEQ` in a UTF-8 locale, purely because the
//! preceding probe had fed it a lone `0xE9` lead. Every probe below resets with
//! `mbtowc(NULL, NULL, 0)` first.
//!
//! The locale is also process-global for both libraries, so the whole file runs
//! under one mutex and restores what it found.

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
/// The codec function arms here are already dlsym-resolved; the errno arm was
/// not, and fl exports `__errno_location` under the same
/// `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`. In a release test
/// binary the link-time `libc::__errno_location` bound to FL's slot, so the host
/// half of `decode_both` zeroed fl's errno and then read back that zero instead
/// of what glibc's `mbtowc` set. Measured: this gate failed `--release` with
/// `mbtowc([c3, a9]) under LC_ALL=C left: (-1, 57005, 84) right: (-1, 57005, 0)`
/// — fl's EILSEQ against a host errno of 0 — while passing in debug, where the
/// attribute is off and the reference really does reach glibc. See bd-g1sjty.
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

use frankenlibc_abi::glibc_internal_abi::__ctype_get_mb_cur_max as fl_mb_cur_max;
use frankenlibc_abi::locale_abi::{
    locale_reset_active_charset_for_tests, nl_langinfo as fl_nl_langinfo, setlocale as fl_setlocale,
};
use frankenlibc_abi::wchar_abi::{mbtowc as fl_mbtowc, wctomb as fl_wctomb};

type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *const c_char;
type NlLanginfoFn = unsafe extern "C" fn(c_int) -> *const c_char;
type MbCurMaxFn = unsafe extern "C" fn() -> usize;
type MbtowcFn = unsafe extern "C" fn(*mut u32, *const u8, usize) -> c_int;
type MblenFn = unsafe extern "C" fn(*const u8, usize) -> c_int;
type MbrtowcFn =
    unsafe extern "C" fn(*mut libc::wchar_t, *const c_char, usize, *mut std::ffi::c_void) -> usize;
type WctombFn = unsafe extern "C" fn(*mut u8, u32) -> c_int;
type MbstowcsFn = unsafe extern "C" fn(*mut u32, *const u8, usize) -> usize;
type WcstombsFn = unsafe extern "C" fn(*mut u8, *const u32, usize) -> usize;

/// `CODESET` is `_NL_CTYPE_CODESET_NAME` on Linux.
const CODESET: c_int = 14;

/// Serialises the whole file: `setlocale` mutates process-global state in BOTH
/// libraries, so two arms running on different libtest threads would interleave
/// their selections and read each other's.
fn locale_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct Host {
    setlocale: SetlocaleFn,
    nl_langinfo: NlLanginfoFn,
    mb_cur_max: MbCurMaxFn,
    mbtowc: MbtowcFn,
    mblen: MblenFn,
    mbrtowc: MbrtowcFn,
    wctomb: WctombFn,
    mbstowcs: MbstowcsFn,
    wcstombs: WcstombsFn,
}

fn host() -> &'static Host {
    static H: OnceLock<Host> = OnceLock::new();
    H.get_or_init(|| {
        // SAFETY: each signature matches the C declaration of the symbol named
        // beside it, and fl's own definition is passed so the oracle refuses to
        // hand back fl and compare it against itself.
        unsafe {
            Host {
                setlocale: host_fn(c"setlocale", fl_setlocale as *const ()),
                nl_langinfo: host_fn(c"nl_langinfo", fl_nl_langinfo as *const ()),
                mb_cur_max: host_fn(c"__ctype_get_mb_cur_max", fl_mb_cur_max as *const ()),
                mbtowc: host_fn(c"mbtowc", fl_mbtowc as *const ()),
                mblen: host_fn(c"mblen", frankenlibc_abi::wchar_abi::mblen as *const ()),
                mbrtowc: host_fn(c"mbrtowc", frankenlibc_abi::wchar_abi::mbrtowc as *const ()),
                wctomb: host_fn(c"wctomb", fl_wctomb as *const ()),
                mbstowcs: host_fn(
                    c"mbstowcs",
                    frankenlibc_abi::wchar_abi::mbstowcs as *const (),
                ),
                wcstombs: host_fn(
                    c"wcstombs",
                    frankenlibc_abi::wchar_abi::wcstombs as *const (),
                ),
            }
        }
    })
}

/// Reset both libraries' `mbtowc` shift state. See the module docs.
fn reset_shift_state() {
    // SAFETY: `mbtowc(NULL, NULL, 0)` is the documented state reset.
    unsafe {
        (host().mbtowc)(std::ptr::null_mut(), std::ptr::null(), 0);
        fl_mbtowc(std::ptr::null_mut(), std::ptr::null(), 0);
    }
}

fn text(ptr: *const c_char) -> Vec<u8> {
    assert!(!ptr.is_null(), "locale query returned NULL");
    // SAFETY: non-null and NUL-terminated by the C contract.
    unsafe { CStr::from_ptr(ptr) }.to_bytes().to_vec()
}

/// Select `name` in BOTH libraries and return the two canonical names.
fn select_both(name: &CStr) -> (Vec<u8>, Vec<u8>) {
    // SAFETY: LC_ALL with a NUL-terminated name.
    let host_name = unsafe { (host().setlocale)(libc::LC_ALL, name.as_ptr()) };
    let fl_name = unsafe { fl_setlocale(libc::LC_ALL, name.as_ptr()) };
    reset_shift_state();
    (text(fl_name), text(host_name))
}

/// `(return, errno)` from each library's `mbtowc` for one input window.
fn decode_both(bytes: &[u8]) -> ((c_int, u32, c_int), (c_int, u32, c_int)) {
    reset_shift_state();
    let mut host_wc = 0xDEADu32;
    let mut fl_wc = 0xDEADu32;
    // SAFETY: both pointers are live locals and `bytes` is a live slice.
    unsafe {
        let host_errno = host_errno_location();
        *host_errno() = 0;
        let host_rc = (host().mbtowc)(&mut host_wc, bytes.as_ptr(), bytes.len());
        let host_err = *host_errno();

        reset_shift_state();
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
        let fl_rc = fl_mbtowc(&mut fl_wc, bytes.as_ptr(), bytes.len());
        let fl_err = *frankenlibc_abi::errno_abi::__errno_location();

        ((fl_rc, fl_wc, fl_err), (host_rc, host_wc, host_err))
    }
}

/// `(return, bytes)` from each library's `wctomb` for one wide character.
fn encode_both(wc: u32) -> ((c_int, Vec<u8>), (c_int, Vec<u8>)) {
    let mut host_buf = [0u8; 16];
    let mut fl_buf = [0u8; 16];
    // SAFETY: both buffers are 16 bytes, comfortably over MB_CUR_MAX.
    unsafe {
        let host_rc = (host().wctomb)(host_buf.as_mut_ptr(), wc);
        let fl_rc = fl_wctomb(fl_buf.as_mut_ptr(), wc);
        let take = |rc: c_int, buf: &[u8]| -> Vec<u8> {
            if rc > 0 {
                buf[..rc as usize].to_vec()
            } else {
                Vec::new()
            }
        };
        (
            (fl_rc, take(fl_rc, &fl_buf)),
            (host_rc, take(host_rc, &host_buf)),
        )
    }
}

/// Restores whatever locale was active when the guard was taken.
struct LocaleRestore(Option<CString>);

impl Drop for LocaleRestore {
    fn drop(&mut self) {
        if let Some(saved) = &self.0 {
            // SAFETY: `saved` is a live NUL-terminated name.
            unsafe { (host().setlocale)(libc::LC_ALL, saved.as_ptr()) };
        }
        locale_reset_active_charset_for_tests();
    }
}

fn save_locale() -> LocaleRestore {
    // SAFETY: NULL queries the current name without changing it.
    let saved = unsafe { (host().setlocale)(libc::LC_ALL, std::ptr::null()) };
    LocaleRestore(if saved.is_null() {
        None
    } else {
        // SAFETY: non-null and NUL-terminated.
        Some(unsafe { CStr::from_ptr(saved) }.to_owned())
    })
}

#[test]
fn legacy_single_character_boundaries_and_errno_match_glibc() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = save_locale();
    let inputs: &[&[u8]] = &[
        b"",
        b"",
        b"A",
        b"\x7f",
        b"\x80",
        b"\xff",
        b"\xc3\xa9",
        b"\xe2\x82\xac",
        b"\xf0\x9f\x99\x82",
        b"\xc3",
        b"\xe2\x82",
        b"\xc3A",
        b"\xed\xa0\x80",
        b"\xf4\x90\x80\x80",
    ];
    let mut observed = 0;
    for locale in [c"C", c"POSIX", c"C.UTF-8"] {
        let (fl_name, host_name) = select_both(locale);
        assert_eq!(fl_name, host_name);
        for (sample, bytes) in inputs.iter().enumerate() {
            let mut input = [0u8; 8];
            input[..bytes.len()].copy_from_slice(bytes);
            let source = if sample == 0 {
                std::ptr::null()
            } else {
                input.as_ptr()
            };
            for n in 0..7 {
                for kind in 0..3 {
                    for saved in [0, libc::E2BIG] {
                        let mut results = Vec::new();
                        for (length, wide, error) in [
                            (host().mblen, host().mbtowc, host_errno_location()),
                            (
                                frankenlibc_abi::wchar_abi::mblen as MblenFn,
                                fl_mbtowc as MbtowcFn,
                                frankenlibc_abi::errno_abi::__errno_location as ErrnoLocationFn,
                            ),
                        ] {
                            let mut wc = 0x1234;
                            let out = if kind == 2 {
                                std::ptr::null_mut()
                            } else {
                                &mut wc
                            };
                            // SAFETY: exact resolved signatures, eight initialized input
                            // bytes, a writable output, or documented NULL/reset arguments.
                            unsafe {
                                length(std::ptr::null(), 0);
                                wide(std::ptr::null_mut(), std::ptr::null(), 0);
                                *error() = saved;
                                let r = if kind == 0 {
                                    length(source, n)
                                } else {
                                    wide(out, source, n)
                                };
                                results.push((r, *error(), wc));
                            }
                        }
                        assert_eq!(
                            results[0], results[1],
                            "{locale:?} sample={sample} n={n} kind={kind} saved={saved}"
                        );
                        observed += 1;
                    }
                }
            }
        }
    }
    assert_eq!(observed, 1764, "the declared matrix must actually execute");
}

#[test]
fn legacy_split_state_reset_and_isolation_match_glibc() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = save_locale();
    let (fl_name, host_name) = select_both(c"C.UTF-8");
    assert_eq!(fl_name, host_name);
    let mut observed = 0;
    for input in [b"\xc3\xa9".as_slice(), b"\xe2\x82\xac", b"\xf0\x9f\x99\x82"] {
        for split in 1..input.len() {
            for discard in [false, true] {
                for saved in [0, libc::E2BIG] {
                    let mut results = Vec::new();
                    for (length, wide, restart, error) in [
                        (
                            host().mblen,
                            host().mbtowc,
                            host().mbrtowc,
                            host_errno_location(),
                        ),
                        (
                            frankenlibc_abi::wchar_abi::mblen as MblenFn,
                            fl_mbtowc as MbtowcFn,
                            frankenlibc_abi::wchar_abi::mbrtowc as MbrtowcFn,
                            frankenlibc_abi::errno_abi::__errno_location as ErrnoLocationFn,
                        ),
                    ] {
                        let mut sequence = Vec::new();
                        // SAFETY: NULL source resets the legacy stream without output.
                        unsafe { wide(std::ptr::null_mut(), std::ptr::null(), 0) };
                        for phase in 0..10 {
                            let mut wc = 0x1234;
                            let out = if discard {
                                std::ptr::null_mut()
                            } else {
                                &mut wc
                            };
                            // SAFETY: inputs are live through their stated bounds, outputs
                            // are writable locals, and the implicit streams finish or reset.
                            unsafe {
                                *error() = saved;
                                let r = match phase {
                                    0 | 7 => wide(out, input.as_ptr(), split) as i64,
                                    1 => length(input.as_ptr(), split) as i64,
                                    2 => restart(
                                        out.cast(),
                                        c"\xc2".as_ptr(),
                                        1,
                                        std::ptr::null_mut(),
                                    ) as i64,
                                    3 => wide(out, b"A".as_ptr(), 0) as i64,
                                    4 => wide(out, c"".as_ptr().cast(), 0) as i64,
                                    5 => wide(out, input[split..].as_ptr(), input.len() - split)
                                        as i64,
                                    6 => restart(
                                        out.cast(),
                                        c"\xa3".as_ptr(),
                                        1,
                                        std::ptr::null_mut(),
                                    ) as i64,
                                    8 => wide(out, std::ptr::null(), 0) as i64,
                                    _ => wide(out, b"A".as_ptr(), 1) as i64,
                                };
                                sequence.push((r, *error(), wc));
                            }
                        }
                        results.push(sequence);
                    }
                    assert_eq!(
                        results[0], results[1],
                        "input={input:x?} split={split} discard={discard} saved={saved}"
                    );
                    observed += 1;
                }
            }
        }
    }
    assert_eq!(
        observed, 24,
        "each split, output and saved-errno arm must execute"
    );
}

#[test]
fn c_locale_reports_ascii_and_decodes_ascii_only() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = save_locale();

    let (fl_name, host_name) = select_both(c"C");
    assert_eq!(fl_name, host_name, "setlocale(LC_ALL,\"C\") name");
    assert_eq!(fl_name, b"C", "glibc canonicalises the C locale to \"C\"");

    // SAFETY: scalar selector, no pointer arguments.
    let (fl_cs, host_cs) = unsafe {
        (
            text(fl_nl_langinfo(CODESET)),
            text((host().nl_langinfo)(CODESET)),
        )
    };
    assert_eq!(fl_cs, host_cs, "CODESET under LC_ALL=C");
    assert_eq!(fl_cs, b"ANSI_X3.4-1968");

    // SAFETY: no arguments.
    let (fl_max, host_max) = unsafe { (fl_mb_cur_max(), (host().mb_cur_max)()) };
    assert_eq!(fl_max, host_max, "MB_CUR_MAX under LC_ALL=C");
    assert_eq!(fl_max, 1, "the C locale is single-byte");

    // THE CODEC HALF. Everything above is a string; these are the assertions a
    // revert of the conversion routing would have to survive.
    for byte in [b'A', 0x7F] {
        let (fl, host) = decode_both(&[byte]);
        assert_eq!(fl, host, "mbtowc({byte:#04x}) under LC_ALL=C");
        assert_eq!(fl.0, 1, "ASCII must decode as one byte");
        assert_eq!(fl.1, u32::from(byte));
    }
    for seq in [&[0xC3u8, 0xA9][..], &[0x80][..], &[0xE9][..]] {
        let (fl, host) = decode_both(seq);
        assert_eq!(fl, host, "mbtowc({seq:02x?}) under LC_ALL=C");
        assert_eq!(
            (fl.0, fl.2),
            (-1, libc::EILSEQ),
            "the C locale refuses every byte >= 0x80, at the lead: {seq:02x?}"
        );
    }

    let (fl, host) = encode_both(u32::from(b'A'));
    assert_eq!(fl, host, "wctomb(U+0041) under LC_ALL=C");
    assert_eq!(fl, (1, b"A".to_vec()));
    for wc in [0x00E9u32, 0x20AC] {
        let (fl, host) = encode_both(wc);
        assert_eq!(fl, host, "wctomb(U+{wc:04X}) under LC_ALL=C");
        assert_eq!(fl.0, -1, "U+{wc:04X} is not representable in ASCII");
    }
}

#[test]
fn posix_locale_is_the_c_locale() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = save_locale();

    let (fl_name, host_name) = select_both(c"POSIX");
    assert_eq!(fl_name, host_name, "setlocale(LC_ALL,\"POSIX\") name");
    assert_eq!(
        fl_name, b"C",
        "\"POSIX\" canonicalises to \"C\" — it does not report itself back"
    );

    // SAFETY: no arguments / scalar selector.
    let (fl_max, host_max) = unsafe { (fl_mb_cur_max(), (host().mb_cur_max)()) };
    assert_eq!(fl_max, host_max);
    assert_eq!(fl_max, 1);

    let (fl, host) = decode_both(&[0xC3, 0xA9]);
    assert_eq!(fl, host, "mbtowc(UTF-8) under LC_ALL=POSIX");
    assert_eq!((fl.0, fl.2), (-1, libc::EILSEQ));
}

#[test]
fn c_utf8_locale_still_decodes_utf8() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = save_locale();

    let (fl_name, host_name) = select_both(c"C.UTF-8");
    assert_eq!(fl_name, host_name, "setlocale(LC_ALL,\"C.UTF-8\") name");
    assert_eq!(fl_name, b"C.UTF-8");

    // SAFETY: scalar selector / no arguments.
    let (fl_cs, host_cs) = unsafe {
        (
            text(fl_nl_langinfo(CODESET)),
            text((host().nl_langinfo)(CODESET)),
        )
    };
    assert_eq!(fl_cs, host_cs, "CODESET under LC_ALL=C.UTF-8");
    assert_eq!(fl_cs, b"UTF-8");

    // LC_TIME names are static C-locale table entries, not LC_CTYPE data.
    // This guards the strict fast path that returns them before consulting the
    // active charset used by CODESET and the multibyte codec.
    let (fl_day, host_day) = unsafe {
        (
            text(fl_nl_langinfo(libc::DAY_1)),
            text((host().nl_langinfo)(libc::DAY_1)),
        )
    };
    assert_eq!(fl_day, host_day, "DAY_1 under LC_ALL=C.UTF-8");
    assert_eq!(fl_day, b"Sunday");

    // SAFETY: no arguments.
    let (fl_max, host_max) = unsafe { (fl_mb_cur_max(), (host().mb_cur_max)()) };
    assert_eq!(fl_max, host_max, "MB_CUR_MAX under LC_ALL=C.UTF-8");
    assert_eq!(
        fl_max, 6,
        "glibc's UTF-8 MB_CUR_MAX is the historical RFC 2279 six, not four"
    );

    let (fl, host) = decode_both(&[0xC3, 0xA9]);
    assert_eq!(fl, host, "mbtowc(U+00E9 as UTF-8) under LC_ALL=C.UTF-8");
    assert_eq!((fl.0, fl.1), (2, 0x00E9));

    let (fl, host) = encode_both(0x20AC);
    assert_eq!(fl, host, "wctomb(U+20AC) under LC_ALL=C.UTF-8");
    assert_eq!(fl, (3, vec![0xE2, 0x82, 0xAC]));
}

/// The selector has to be re-readable, not one-way.
///
/// A build that latched `Ascii` on the first `setlocale(LC_ALL,"C")` would pass
/// every arm above and still be broken for any program that switches back.
#[test]
fn switching_between_locales_moves_the_codec_both_ways() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = save_locale();

    for (name, expect_max, expect_utf8_decode) in [
        (c"C.UTF-8", 6usize, true),
        (c"C", 1, false),
        (c"C.UTF-8", 6, true),
        (c"POSIX", 1, false),
    ] {
        let (fl_name, host_name) = select_both(name);
        assert_eq!(fl_name, host_name, "round-trip name for {name:?}");

        // SAFETY: no arguments.
        let (fl_max, host_max) = unsafe { (fl_mb_cur_max(), (host().mb_cur_max)()) };
        assert_eq!(fl_max, host_max, "round-trip MB_CUR_MAX for {name:?}");
        assert_eq!(fl_max, expect_max, "MB_CUR_MAX for {name:?}");

        let (fl, host) = decode_both(&[0xC3, 0xA9]);
        assert_eq!(fl, host, "round-trip mbtowc for {name:?}");
        if expect_utf8_decode {
            assert_eq!((fl.0, fl.1), (2, 0x00E9), "{name:?} must decode UTF-8");
        } else {
            assert_eq!(
                (fl.0, fl.2),
                (-1, libc::EILSEQ),
                "{name:?} must refuse UTF-8"
            );
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CapacityResult {
    returned: usize,
    error: c_int,
    wide: [u32; 32],
    bytes: [u8; 32],
}

fn capacity_result(
    ours: bool,
    encode: bool,
    input: &[u8],
    wide_input: &[u32],
    capacity: usize,
    count_only: bool,
    saved_errno: c_int,
) -> CapacityResult {
    let (decode, encode_fn, errno) = if ours {
        (
            frankenlibc_abi::wchar_abi::mbstowcs as MbstowcsFn,
            frankenlibc_abi::wchar_abi::wcstombs as WcstombsFn,
            frankenlibc_abi::errno_abi::__errno_location as ErrnoLocationFn,
        )
    } else {
        (host().mbstowcs, host().wcstombs, host_errno_location())
    };
    let mut wide = [0x1234; 32];
    let mut bytes = [0x5a; 32];
    // SAFETY: both sources have a live NUL terminator; both initialized output
    // arrays fit every capacity. Null output requests sizing without writes.
    let (returned, error) = unsafe {
        *errno() = saved_errno;
        let returned = if encode {
            encode_fn(
                if count_only {
                    std::ptr::null_mut()
                } else {
                    bytes.as_mut_ptr()
                },
                wide_input.as_ptr(),
                capacity,
            )
        } else {
            decode(
                if count_only {
                    std::ptr::null_mut()
                } else {
                    wide.as_mut_ptr()
                },
                input.as_ptr(),
                capacity,
            )
        };
        (returned, *errno())
    };
    CapacityResult {
        returned,
        error,
        wide,
        bytes,
    }
}

#[test]
fn string_conversion_capacity_matches_live_gnu() {
    let _lock = locale_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _restore = save_locale();
    let samples: [(&[u8], u32); 5] = [
        (b"", 0),
        ("é".as_bytes(), 0xe9),
        ("🙂".as_bytes(), 0x1f642),
        (&[0xff], 0xd800),
        (&[0xe2, 0x82], 0x8000_0000),
    ];
    let mut checked = 0;
    let mut differences = 0;
    let mut examples = Vec::new();
    for (locale, expected_max) in [(c"C", 1), (c"POSIX", 1), (c"C.UTF-8", 6)] {
        let (ours, gnu) = select_both(locale);
        assert_eq!(ours, gnu);
        // SAFETY: scalar charset queries; both live providers were selected.
        assert_eq!(unsafe { fl_mb_cur_max() }, expected_max);
        assert_eq!(unsafe { (host().mb_cur_max)() }, expected_max);
        for encode in [false, true] {
            for (sample, &(suffix, unit)) in samples.iter().enumerate() {
                for prefix in [0, 1, 16] {
                    let mut input = vec![b'A'; prefix];
                    input.extend_from_slice(suffix);
                    input.push(0);
                    let mut wide_input = vec![u32::from(b'A'); prefix];
                    wide_input.push(unit);
                    wide_input.push(0);
                    for capacity in [0, 1, 2, 3, 4, 6, 16, 24] {
                        for count_only in [false, true] {
                            for saved_errno in [0, libc::E2BIG] {
                                let ours = capacity_result(
                                    true,
                                    encode,
                                    &input,
                                    &wide_input,
                                    capacity,
                                    count_only,
                                    saved_errno,
                                );
                                let gnu = capacity_result(
                                    false,
                                    encode,
                                    &input,
                                    &wide_input,
                                    capacity,
                                    count_only,
                                    saved_errno,
                                );
                                checked += 1;
                                if ours != gnu {
                                    differences += 1;
                                    if examples.len() < 12 {
                                        examples.push(format!("{locale:?} encode={encode} sample={sample} prefix={prefix} capacity={capacity} count={count_only} errno={saved_errno}: fl={ours:?} GNU={gnu:?}"));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(checked, 2880);
    eprintln!("capacity comparisons={checked} differences={differences}");
    assert_eq!(differences, 0, "{}", examples.join("\n"));
}

mod single_byte_named_locales {
    use super::*;
    use std::ffi::c_void;
    use std::path::{Path, PathBuf};

    use frankenlibc_abi::locale_abi as fl_locale;
    use frankenlibc_abi::wchar_abi as fl;

    const CHILD: &str = "FRANKENLIBC_SINGLE_BYTE_LOCALE_CHILD";
    const BYTE_CANARY: u8 = 0xa5;
    const WIDE_CANARY: u32 = 0x1234_abcd;
    const SAVED_ERRNO: c_int = libc::E2BIG;

    #[derive(Clone, Copy)]
    struct Case {
        name: &'static CStr,
        codeset: &'static [u8],
        ascii_compatible: bool,
        probe: (u8, u32),
        sample: &'static [u32],
    }

    const CASES: [Case; 5] = [
        Case {
            name: c"fl_test_latin1",
            codeset: b"ISO-8859-1",
            ascii_compatible: true,
            probe: (0xe9, 0x00e9),
            sample: &[0x41, 0xe9, 0xff, 0x20, 0x42],
        },
        Case {
            name: c"fl_test_latin15",
            codeset: b"ISO-8859-15",
            ascii_compatible: true,
            probe: (0xa4, 0x20ac),
            sample: &[0x41, 0x20ac, 0x0153, 0xe9],
        },
        Case {
            name: c"fl_test_cp1251",
            codeset: b"CP1251",
            ascii_compatible: true,
            probe: (0xcf, 0x041f),
            sample: &[0x41, 0x041f, 0x0440, 0x0438, 0x20, 0x20ac],
        },
        Case {
            name: c"fl_test_koi8u",
            codeset: b"KOI8-U",
            ascii_compatible: true,
            probe: (0xf0, 0x041f),
            sample: &[0x41, 0x041f, 0x0440, 0x0438, 0x0432, 0x0435],
        },
        Case {
            name: c"fl_test_ibm037",
            codeset: b"IBM037",
            ascii_compatible: false,
            probe: (0x40, 0x20),
            sample: &[0x41, 0x61, 0x30, 0x20, 0xe9, 0xa3],
        },
    ];

    fn blob_word(bytes: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn read_ctype(name: &str, expected_codeset: &[u8]) -> Vec<u8> {
        let path = Path::new("/usr/lib/locale").join(name).join("LC_CTYPE");
        let bytes = std::fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "required host locale fixture {} is unavailable: {error}",
                path.display()
            )
        });
        assert_eq!(blob_word(&bytes, 0), 0x2009_0720);
        assert!(blob_word(&bytes, 4) > 14);
        let offset = blob_word(&bytes, 8 + CODESET as usize * 4) as usize;
        let codeset = bytes[offset..].split(|&byte| byte == 0).next().unwrap();
        assert_eq!(codeset, expected_codeset, "host fixture {}", path.display());
        bytes
    }

    fn write_ctype(root: &Path, name: &CStr, source: &[u8], codeset: Option<&[u8]>) {
        let mut bytes = source.to_vec();
        if let Some(codeset) = codeset {
            // Conversion-only fixture: retain an installed, valid LC_CTYPE
            // container and change its CODESET item. Host glibc independently
            // opens that item through its own gconv codec. The inherited
            // classification/case tables are deliberately not under test.
            let offset = u32::try_from(bytes.len()).unwrap();
            bytes.extend_from_slice(codeset);
            bytes.push(0);
            let item = 8 + CODESET as usize * 4;
            bytes[item..item + 4].copy_from_slice(&offset.to_ne_bytes());
        }
        let directory = root.join(name.to_str().unwrap());
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("LC_CTYPE"), bytes).unwrap();
    }

    fn fixtures(test: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "frankenlibc-single-byte-{}-{test}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let latin1 = read_ctype("fr_FR", b"ISO-8859-1");
        let cp1251 = read_ctype("bg_BG", b"CP1251");
        let koi8u = read_ctype("ru_UA", b"KOI8-U");
        let gb2312 = read_ctype("zh_CN", b"GB2312");
        write_ctype(&root, CASES[0].name, &latin1, None);
        write_ctype(&root, CASES[1].name, &latin1, Some(CASES[1].codeset));
        write_ctype(&root, CASES[2].name, &cp1251, None);
        write_ctype(&root, CASES[3].name, &koi8u, None);
        write_ctype(&root, CASES[4].name, &latin1, Some(CASES[4].codeset));
        write_ctype(&root, c"fl_test_gb2312", &gb2312, None);
        root
    }

    fn isolated(test: &str) -> bool {
        if std::env::var(CHILD).as_deref() == Ok(test) {
            assert!(matches!(
                std::env::var("FRANKENLIBC_MODE").as_deref(),
                Ok("strict" | "hardened")
            ));
            return true;
        }
        // Only the child sees LOCPATH or a different runtime mode. Existing
        // tests and the host's installed locale files remain independent.
        let directory = fixtures(test);
        for mode in ["strict", "hardened"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!("single_byte_named_locales::{test}"),
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, test)
                .env("FRANKENLIBC_MODE", mode)
                .env("LOCPATH", &directory)
                .env("LC_ALL", "C")
                .env("LANG", "C")
                .env_remove("LC_CTYPE")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{test}/{mode}:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "child filter did not execute {test}/{mode}"
            );
            eprintln!("{test}/{mode}: {}", String::from_utf8_lossy(&output.stderr));
        }
        false
    }

    type WcrtombFn = unsafe extern "C" fn(*mut c_char, libc::wchar_t, *mut c_void) -> usize;
    type MbsrtowcsFn =
        unsafe extern "C" fn(*mut libc::wchar_t, *mut *const c_char, usize, *mut c_void) -> usize;
    type MbsnrtowcsFn = unsafe extern "C" fn(
        *mut libc::wchar_t,
        *mut *const c_char,
        usize,
        usize,
        *mut c_void,
    ) -> usize;
    type WcsrtombsFn =
        unsafe extern "C" fn(*mut c_char, *mut *const libc::wchar_t, usize, *mut c_void) -> usize;
    type WcsnrtombsFn = unsafe extern "C" fn(
        *mut c_char,
        *mut *const libc::wchar_t,
        usize,
        usize,
        *mut c_void,
    ) -> usize;

    #[derive(Clone, Copy)]
    struct Api {
        mbtowc: MbtowcFn,
        mbrtowc: MbrtowcFn,
        wctomb: WctombFn,
        wcrtomb: WcrtombFn,
        btowc: unsafe extern "C" fn(c_int) -> u32,
        wctob: unsafe extern "C" fn(u32) -> c_int,
        mbstowcs: MbstowcsFn,
        wcstombs: WcstombsFn,
        mbsrtowcs: MbsrtowcsFn,
        mbsnrtowcs: MbsnrtowcsFn,
        wcsrtombs: WcsrtombsFn,
        wcsnrtombs: WcsnrtombsFn,
        initial: unsafe extern "C" fn(*const c_void) -> c_int,
        errno: ErrnoLocationFn,
    }

    fn api(ours: bool) -> Api {
        if ours {
            return Api {
                mbtowc: fl::mbtowc,
                mbrtowc: fl::mbrtowc,
                wctomb: fl::wctomb,
                wcrtomb: fl::wcrtomb,
                btowc: fl::btowc,
                wctob: fl::wctob,
                mbstowcs: fl::mbstowcs,
                wcstombs: fl::wcstombs,
                mbsrtowcs: fl::mbsrtowcs,
                mbsnrtowcs: fl::mbsnrtowcs,
                wcsrtombs: fl::wcsrtombs,
                wcsnrtombs: fl::wcsnrtombs,
                initial: fl::mbsinit,
                errno: frankenlibc_abi::errno_abi::__errno_location,
            };
        }
        static HOST: OnceLock<Api> = OnceLock::new();
        *HOST.get_or_init(|| unsafe {
            // Every oracle resolves from host libc and rejects our own export.
            Api {
                mbtowc: host().mbtowc,
                mbrtowc: host().mbrtowc,
                wctomb: host().wctomb,
                wcrtomb: host_fn(c"wcrtomb", fl::wcrtomb as *const ()),
                btowc: host_fn(c"btowc", fl::btowc as *const ()),
                wctob: host_fn(c"wctob", fl::wctob as *const ()),
                mbstowcs: host().mbstowcs,
                wcstombs: host().wcstombs,
                mbsrtowcs: host_fn(c"mbsrtowcs", fl::mbsrtowcs as *const ()),
                mbsnrtowcs: host_fn(c"mbsnrtowcs", fl::mbsnrtowcs as *const ()),
                wcsrtombs: host_fn(c"wcsrtombs", fl::wcsrtombs as *const ()),
                wcsnrtombs: host_fn(c"wcsnrtombs", fl::wcsnrtombs as *const ()),
                initial: host_fn(c"mbsinit", fl::mbsinit as *const ()),
                errno: host_errno_location(),
            }
        })
    }

    fn select(case: Case) {
        unsafe {
            let gnu = (host().setlocale)(libc::LC_CTYPE, case.name.as_ptr());
            assert!(!gnu.is_null(), "host must load {:?}", case.name);
            assert_eq!(text((host().nl_langinfo)(CODESET)), case.codeset);
            assert_eq!((host().mb_cur_max)(), 1);
            let ours = fl_setlocale(libc::LC_CTYPE, case.name.as_ptr());
            assert!(!ours.is_null(), "native locale must load {:?}", case.name);
            assert_eq!(text(ours), text(gnu));
            assert_active(case);
        }
        reset_shift_state();
    }

    fn assert_active(case: Case) {
        unsafe {
            assert_eq!(text(fl_nl_langinfo(CODESET)), case.codeset);
            assert_eq!(text((host().nl_langinfo)(CODESET)), case.codeset);
            assert_eq!(fl_mb_cur_max(), 1);
            assert_eq!((host().mb_cur_max)(), 1);
        }
        for functions in [api(false), api(true)] {
            let result = decode_character(functions, &[case.probe.0, 0], 1, true, false);
            assert_eq!((result.returned, result.wide[1]), (1, case.probe.1));
        }
    }

    #[repr(C, align(8))]
    struct State {
        before: [u8; 8],
        bytes: [u8; std::mem::size_of::<libc::mbstate_t>()],
        after: [u8; 8],
    }

    impl State {
        fn new() -> Self {
            Self {
                before: [BYTE_CANARY; 8],
                bytes: [0; std::mem::size_of::<libc::mbstate_t>()],
                after: [BYTE_CANARY; 8],
            }
        }

        fn pointer(&mut self) -> *mut c_void {
            self.bytes.as_mut_ptr().cast()
        }

        fn check(&self) {
            assert_eq!(self.before, [BYTE_CANARY; 8]);
            assert_eq!(self.after, [BYTE_CANARY; 8]);
        }

        fn initial(&self, functions: Api) -> bool {
            unsafe { (functions.initial)(self.bytes.as_ptr().cast()) != 0 }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct CharacterResult {
        returned: isize,
        error: c_int,
        wide: [u32; 3],
        bytes: [u8; 10],
        initial: Option<bool>,
    }

    fn decode_character(
        functions: Api,
        input: &[u8],
        length: usize,
        restart: bool,
        discard: bool,
    ) -> CharacterResult {
        let mut wide = [WIDE_CANARY; 3];
        let mut state = State::new();
        let output = if discard {
            std::ptr::null_mut()
        } else {
            unsafe { wide.as_mut_ptr().add(1) }
        };
        let (returned, error) = unsafe {
            (functions.mbtowc)(std::ptr::null_mut(), std::ptr::null(), 0);
            *(functions.errno)() = SAVED_ERRNO;
            let returned = if restart {
                (functions.mbrtowc)(
                    output.cast(),
                    input.as_ptr().cast(),
                    length,
                    state.pointer(),
                ) as isize
            } else {
                (functions.mbtowc)(output, input.as_ptr(), length) as isize
            };
            (returned, *(functions.errno)())
        };
        assert_eq!(wide[0], WIDE_CANARY);
        assert_eq!(wide[2], WIDE_CANARY);
        state.check();
        CharacterResult {
            returned,
            error,
            wide,
            bytes: [BYTE_CANARY; 10],
            initial: (restart && returned != -1).then(|| state.initial(functions)),
        }
    }

    fn encode_character(functions: Api, wc: u32, restart: bool, reset: bool) -> CharacterResult {
        let mut bytes = [BYTE_CANARY; 10];
        let mut state = State::new();
        let output = if reset {
            std::ptr::null_mut()
        } else {
            unsafe { bytes.as_mut_ptr().add(1) }
        };
        let (returned, error) = unsafe {
            (functions.wctomb)(std::ptr::null_mut(), 0);
            *(functions.errno)() = SAVED_ERRNO;
            let returned = if restart {
                (functions.wcrtomb)(output.cast(), wc as libc::wchar_t, state.pointer()) as isize
            } else {
                (functions.wctomb)(output, wc) as isize
            };
            (returned, *(functions.errno)())
        };
        assert_eq!(bytes[0], BYTE_CANARY);
        assert_eq!(&bytes[2..], &[BYTE_CANARY; 8]);
        state.check();
        CharacterResult {
            returned,
            error,
            wide: [WIDE_CANARY; 3],
            bytes,
            initial: (restart && returned != -1).then(|| state.initial(functions)),
        }
    }

    fn reference_btowc(case: Case, byte: u8) -> u32 {
        if case.ascii_compatible {
            return unsafe { (api(false).btowc)(c_int::from(byte)) };
        }
        // Host btowc/wctob assume ASCII for low values even when the synthetic
        // IBM037 fixture selects a non-ASCII gconv codec. Its actual mb/wc
        // converters do honor that codec, so those are the independent oracle
        // for this conversion-only fixture. Real locales use btowc directly.
        let result = decode_character(api(false), &[byte, 0], 1, true, false);
        if result.returned >= 0 {
            result.wide[1]
        } else {
            u32::MAX
        }
    }

    fn reference_wctob(case: Case, wc: u32) -> c_int {
        if case.ascii_compatible {
            return unsafe { (api(false).wctob)(wc) };
        }
        let result = encode_character(api(false), wc, true, false);
        if result.returned == 1 {
            c_int::from(result.bytes[1])
        } else {
            libc::EOF
        }
    }

    #[test]
    fn global_single_byte_character_matrix() {
        if !isolated("global_single_byte_character_matrix") {
            return;
        }
        let ours = api(true);
        let gnu = api(false);
        let mut decoded = 0;
        let mut encoded = 0;
        for case in CASES {
            select(case);
            let mut valid = 0;
            for byte in 0u8..=u8::MAX {
                let input = [byte, 0];
                for restart in [false, true] {
                    for length in [0, 1, 2] {
                        for discard in [false, true] {
                            assert_eq!(
                                decode_character(ours, &input, length, restart, discard),
                                decode_character(gnu, &input, length, restart, discard),
                                "{:?} byte={byte:#x} n={length} restart={restart} discard={discard}",
                                case.name
                            );
                            decoded += 1;
                        }
                    }
                }
                let wc = reference_btowc(case, byte);
                assert_eq!(unsafe { (ours.btowc)(c_int::from(byte)) }, wc);
                assert_eq!(unsafe { (ours.wctob)(wc) }, reference_wctob(case, wc));
                if wc != u32::MAX {
                    valid += 1;
                    for restart in [false, true] {
                        assert_eq!(
                            encode_character(ours, wc, restart, false),
                            encode_character(gnu, wc, restart, false),
                            "{:?} wc={wc:#x} restart={restart}",
                            case.name
                        );
                        encoded += 1;
                    }
                }
            }
            assert!(
                valid >= 128,
                "fixture {:?} exercised too few valid bytes",
                case.name
            );
            for input in [libc::EOF, -2, 256] {
                assert_eq!(unsafe { (ours.btowc)(input) }, unsafe {
                    (gnu.btowc)(input)
                });
            }
            for wc in [
                0,
                0x41,
                0xe9,
                0x20ac,
                0x041f,
                0x4f60,
                0xd800,
                0x110000,
                u32::MAX,
            ] {
                assert_eq!(unsafe { (ours.wctob)(wc) }, reference_wctob(case, wc));
                for restart in [false, true] {
                    for reset in [false, true] {
                        assert_eq!(
                            encode_character(ours, wc, restart, reset),
                            encode_character(gnu, wc, restart, reset),
                            "{:?} wc={wc:#x} restart={restart} reset={reset}",
                            case.name
                        );
                        encoded += 1;
                    }
                }
            }
        }
        assert_eq!(decoded, 15_360);
        assert!(encoded >= 1_460);
        eprintln!(
            "single-byte character comparisons: decode={decoded}, encode={encoded}, locales=5"
        );
    }

    #[derive(Clone, Copy, Debug)]
    enum Family {
        Legacy,
        Restart,
        Bounded,
    }

    #[derive(Debug)]
    struct StringRequest<'a> {
        family: Family,
        encode: bool,
        input: &'a [u8],
        wide_input: &'a [u32],
        capacity: usize,
        bound: usize,
        count_only: bool,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct StringResult {
        returned: usize,
        error: c_int,
        wide: [u32; 20],
        bytes: [u8; 20],
        source: Option<usize>,
        initial: Option<bool>,
    }

    fn cursor<T>(pointer: *const T, base: *const T, length: usize) -> Option<usize> {
        if pointer.is_null() {
            return None;
        }
        let byte_offset = (pointer as usize)
            .checked_sub(base as usize)
            .expect("source moved before input");
        assert_eq!(byte_offset % std::mem::size_of::<T>(), 0);
        let offset = byte_offset / std::mem::size_of::<T>();
        assert!(
            offset <= length,
            "source escaped input: {offset} > {length}"
        );
        Some(offset)
    }

    fn string_step(
        functions: Api,
        request: &StringRequest<'_>,
        byte_source: &mut *const c_char,
        wide_source: &mut *const libc::wchar_t,
        state: &mut State,
    ) -> StringResult {
        assert!(request.capacity <= 16);
        let mut wide = [WIDE_CANARY; 20];
        let mut bytes = [BYTE_CANARY; 20];
        let (returned, error) = unsafe {
            let wide_dst: *mut libc::wchar_t = if request.count_only {
                std::ptr::null_mut()
            } else {
                wide.as_mut_ptr().add(1).cast()
            };
            let byte_dst: *mut c_char = if request.count_only {
                std::ptr::null_mut()
            } else {
                bytes.as_mut_ptr().add(1).cast()
            };
            *(functions.errno)() = SAVED_ERRNO;
            let returned = match (request.family, request.encode) {
                (Family::Legacy, false) => {
                    (functions.mbstowcs)(wide_dst.cast(), request.input.as_ptr(), request.capacity)
                }
                (Family::Legacy, true) => (functions.wcstombs)(
                    byte_dst.cast(),
                    request.wide_input.as_ptr(),
                    request.capacity,
                ),
                (Family::Restart, false) => {
                    (functions.mbsrtowcs)(wide_dst, byte_source, request.capacity, state.pointer())
                }
                (Family::Restart, true) => {
                    (functions.wcsrtombs)(byte_dst, wide_source, request.capacity, state.pointer())
                }
                (Family::Bounded, false) => (functions.mbsnrtowcs)(
                    wide_dst,
                    byte_source,
                    request.bound,
                    request.capacity,
                    state.pointer(),
                ),
                (Family::Bounded, true) => (functions.wcsnrtombs)(
                    byte_dst,
                    wide_source,
                    request.bound,
                    request.capacity,
                    state.pointer(),
                ),
            };
            (returned, *(functions.errno)())
        };
        assert_eq!(wide[0], WIDE_CANARY);
        assert_eq!(bytes[0], BYTE_CANARY);
        assert!(
            wide[request.capacity + 1..]
                .iter()
                .all(|&wc| wc == WIDE_CANARY)
        );
        assert!(
            bytes[request.capacity + 1..]
                .iter()
                .all(|&byte| byte == BYTE_CANARY)
        );
        if request.count_only {
            assert_eq!(wide, [WIDE_CANARY; 20]);
            assert_eq!(bytes, [BYTE_CANARY; 20]);
            assert!(state.bytes.iter().all(|&byte| byte == 0));
        }
        state.check();
        let source = if request.encode {
            cursor(
                *wide_source,
                request.wide_input.as_ptr().cast(),
                request.wide_input.len(),
            )
        } else {
            cursor(
                *byte_source,
                request.input.as_ptr().cast(),
                request.input.len(),
            )
        };
        StringResult {
            returned,
            error,
            wide,
            bytes,
            source,
            initial: (!matches!(request.family, Family::Legacy) && returned != usize::MAX)
                .then(|| state.initial(functions)),
        }
    }

    fn string_result(functions: Api, request: &StringRequest<'_>) -> StringResult {
        let mut byte_source = request.input.as_ptr().cast();
        let mut wide_source = request.wide_input.as_ptr().cast();
        let mut state = State::new();
        string_step(
            functions,
            request,
            &mut byte_source,
            &mut wide_source,
            &mut state,
        )
    }

    fn sample(case: Case) -> (Vec<u8>, Vec<u32>) {
        let mut input = Vec::new();
        let mut wide = case.sample.to_vec();
        for &wc in case.sample {
            let result = encode_character(api(false), wc, true, false);
            assert_eq!(
                result.returned, 1,
                "host fixture {:?} cannot encode {wc:#x}",
                case.name
            );
            input.push(result.bytes[1]);
        }
        input.push(0);
        wide.push(0);
        (input, wide)
    }

    fn compare_string_matrix(case: Case, input: &[u8], wide_input: &[u32], encode: bool) -> usize {
        let mut observed = 0;
        let source_len = if encode {
            wide_input.len()
        } else {
            input.len()
        };
        let bounds = [0, 1, source_len - 1, source_len];
        for family in [Family::Legacy, Family::Restart, Family::Bounded] {
            let selected_bounds = if matches!(family, Family::Bounded) {
                &bounds[..]
            } else {
                &bounds[3..]
            };
            for &bound in selected_bounds {
                for capacity in [0, 1, 2, 4, 16] {
                    for count_only in [false, true] {
                        let request = StringRequest {
                            family,
                            encode,
                            input,
                            wide_input,
                            capacity,
                            bound,
                            count_only,
                        };
                        assert_eq!(
                            string_result(api(true), &request),
                            string_result(api(false), &request),
                            "{:?}: {request:?}",
                            case.name
                        );
                        observed += 1;
                    }
                }
            }
        }
        observed
    }

    fn stream(
        functions: Api,
        family: Family,
        input: &[u8],
        wide_input: &[u32],
        encode: bool,
        capacity: usize,
    ) -> Vec<StringResult> {
        let mut byte_source = input.as_ptr().cast();
        let mut wide_source = wide_input.as_ptr().cast();
        let mut state = State::new();
        let mut trace = Vec::new();
        loop {
            assert!(
                trace.len() <= wide_input.len(),
                "converter did not make progress"
            );
            let bound = if encode {
                wide_input.len()
                    - cursor(wide_source, wide_input.as_ptr().cast(), wide_input.len()).unwrap()
            } else {
                input.len() - cursor(byte_source, input.as_ptr().cast(), input.len()).unwrap()
            };
            let request = StringRequest {
                family,
                encode,
                input,
                wide_input,
                capacity,
                bound,
                count_only: false,
            };
            let result = string_step(
                functions,
                &request,
                &mut byte_source,
                &mut wide_source,
                &mut state,
            );
            assert_ne!(
                result.returned,
                usize::MAX,
                "valid string conversion failed"
            );
            let complete = result.source.is_none();
            trace.push(result);
            if complete {
                break;
            }
        }
        trace
    }

    #[test]
    fn single_byte_string_capacity_count_and_restart_matrix() {
        if !isolated("single_byte_string_capacity_count_and_restart_matrix") {
            return;
        }
        let mut observed = 0;
        let mut streamed = 0;
        let mut sparse = 0;
        for case in CASES {
            select(case);
            let (input, wide) = sample(case);
            for encode in [false, true] {
                observed += compare_string_matrix(case, &input, &wide, encode);
                for family in [Family::Restart, Family::Bounded] {
                    for capacity in [1, 2] {
                        assert_eq!(
                            stream(api(true), family, &input, &wide, encode, capacity),
                            stream(api(false), family, &input, &wide, encode, capacity),
                            "{:?}: {family:?} encode={encode} capacity={capacity}",
                            case.name
                        );
                        streamed += 1;
                    }
                }
            }
            let mut invalid_wide = wide.clone();
            invalid_wide[1] = 0x1f642;
            observed += compare_string_matrix(case, &input, &invalid_wide, true);
            if case.codeset == b"CP1251" {
                let mut invalid = input.clone();
                invalid[1] = 0x98;
                observed += compare_string_matrix(case, &invalid, &wide, false);
                sparse += 1;
            }
        }
        assert_eq!(observed, 960);
        assert_eq!(streamed, 40);
        assert_eq!(sparse, 1);
        eprintln!(
            "single-byte string comparisons={observed}, persistent-state streams={streamed}, sparse codecs={sparse}"
        );
    }

    type NewlocaleFn = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> *mut c_void;
    type UselocaleFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
    type FreelocaleFn = unsafe extern "C" fn(*mut c_void);

    struct HostLocales {
        new: NewlocaleFn,
        select: UselocaleFn,
        duplicate: UselocaleFn,
        free: FreelocaleFn,
    }

    fn host_locales() -> &'static HostLocales {
        static LOCALES: OnceLock<HostLocales> = OnceLock::new();
        LOCALES.get_or_init(|| unsafe {
            HostLocales {
                new: host_fn(c"newlocale", fl_locale::newlocale as *const ()),
                select: host_fn(c"uselocale", fl_locale::uselocale as *const ()),
                duplicate: host_fn(c"duplocale", fl_locale::duplocale as *const ()),
                free: host_fn(c"freelocale", fl_locale::freelocale as *const ()),
            }
        })
    }

    fn set_global(name: &CStr) {
        unsafe {
            let gnu = (host().setlocale)(libc::LC_CTYPE, name.as_ptr());
            assert!(!gnu.is_null(), "host setlocale({name:?})");
            let ours = fl_setlocale(libc::LC_CTYPE, name.as_ptr());
            assert!(!ours.is_null(), "native setlocale({name:?})");
            assert_eq!(text(ours), text(gnu));
        }
    }

    fn new_pair(name: &CStr) -> (*mut c_void, *mut c_void) {
        unsafe {
            let gnu =
                (host_locales().new)(libc::LC_CTYPE_MASK, name.as_ptr(), std::ptr::null_mut());
            let ours =
                fl_locale::newlocale(libc::LC_CTYPE_MASK, name.as_ptr(), std::ptr::null_mut());
            assert!(!gnu.is_null(), "host newlocale({name:?})");
            assert!(!ours.is_null(), "native newlocale({name:?})");
            (ours, gnu)
        }
    }

    fn assert_utf8() {
        unsafe {
            assert_eq!(text(fl_nl_langinfo(CODESET)), b"UTF-8");
            assert_eq!(text((host().nl_langinfo)(CODESET)), b"UTF-8");
            assert_eq!(fl_mb_cur_max(), 6);
            assert_eq!((host().mb_cur_max)(), 6);
        }
        let ours = decode_character(api(true), b"\xc3\xa9", 2, true, false);
        let gnu = decode_character(api(false), b"\xc3\xa9", 2, true, false);
        assert_eq!(ours, gnu);
        assert_eq!((ours.returned, ours.wide[1]), (2, 0xe9));
    }

    #[test]
    fn named_single_byte_locale_objects_are_thread_local_snapshots() {
        if !isolated("named_single_byte_locale_objects_are_thread_local_snapshots") {
            return;
        }
        let mut observed = 0;
        for case in CASES {
            set_global(c"C");
            let original = new_pair(case.name);
            let duplicate = unsafe {
                let ours = fl_locale::duplocale(original.0);
                let gnu = (host_locales().duplicate)(original.1);
                assert!(!ours.is_null() && !gnu.is_null());
                fl_locale::freelocale(original.0);
                (host_locales().free)(original.1);
                (ours, gnu)
            };
            // Creating/duplicating objects must not select them, and freeing
            // the original must not invalidate the duplicate's codec data.
            unsafe {
                assert_eq!(text(fl_nl_langinfo(CODESET)), b"ANSI_X3.4-1968");
                assert_eq!(text((host().nl_langinfo)(CODESET)), b"ANSI_X3.4-1968");
            }
            let previous = unsafe {
                (
                    fl_locale::uselocale(duplicate.0),
                    (host_locales().select)(duplicate.1),
                )
            };
            assert_eq!(previous.0 as usize, usize::MAX);
            assert_eq!(previous.1 as usize, usize::MAX);
            assert_active(case);

            // Hold a different locale active on a second live thread. Channels
            // also make setup failures terminate instead of deadlocking a barrier.
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let local = new_pair(c"C.UTF-8");
                let previous = unsafe {
                    (
                        fl_locale::uselocale(local.0),
                        (host_locales().select)(local.1),
                    )
                };
                assert_utf8();
                ready_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                assert_utf8();
                unsafe {
                    fl_locale::uselocale(previous.0);
                    (host_locales().select)(previous.1);
                    fl_locale::freelocale(local.0);
                    (host_locales().free)(local.1);
                }
            });
            ready_rx
                .recv()
                .expect("other thread could not select UTF-8");
            assert_active(case);
            release_tx.send(()).unwrap();
            worker.join().unwrap();

            // A global change is visible only after this thread restores
            // LC_GLOBAL_LOCALE; its explicit named snapshot remains active.
            set_global(c"C.UTF-8");
            assert_active(case);
            unsafe {
                assert_eq!(
                    text(fl_setlocale(libc::LC_CTYPE, std::ptr::null())),
                    text((host().setlocale)(libc::LC_CTYPE, std::ptr::null()))
                );
                assert_eq!(fl_locale::uselocale(previous.0), duplicate.0);
                assert_eq!((host_locales().select)(previous.1), duplicate.1);
                fl_locale::freelocale(duplicate.0);
                (host_locales().free)(duplicate.1);
            }
            assert_utf8();
            observed += 1;
        }
        assert_eq!(observed, 5);
        eprintln!("named locale snapshot/lifetime/thread-isolation cases={observed}");
    }

    #[test]
    fn unsupported_multibyte_locale_rejection_preserves_state() {
        if !isolated("unsupported_multibyte_locale_rejection_preserves_state") {
            return;
        }
        let baseline = CASES[0];
        select(baseline);
        let before = unsafe { text(fl_setlocale(libc::LC_CTYPE, std::ptr::null())) };

        // Establish that the same fixture is valid for the independent host.
        // Native rejection must mean unsupported conversion, not a missing file.
        unsafe {
            assert!(!(host().setlocale)(libc::LC_CTYPE, c"fl_test_gb2312".as_ptr()).is_null());
            assert_eq!(text((host().nl_langinfo)(CODESET)), b"GB2312");
            assert_eq!((host().mb_cur_max)(), 2);
        }
        let decoded = decode_character(api(false), b"\xc4\xe3", 2, true, false);
        assert_eq!((decoded.returned, decoded.wide[1]), (2, 0x4f60));
        unsafe {
            assert!(fl_setlocale(libc::LC_CTYPE, c"fl_test_gb2312".as_ptr()).is_null());
            assert_eq!(text(fl_setlocale(libc::LC_CTYPE, std::ptr::null())), before);
            assert_eq!(text(fl_nl_langinfo(CODESET)), baseline.codeset);
            assert_eq!(fl_mb_cur_max(), 1);
            assert!(!(host().setlocale)(libc::LC_CTYPE, baseline.name.as_ptr()).is_null());
        }
        assert_active(baseline);

        let base = new_pair(baseline.name);
        unsafe {
            assert!(
                fl_locale::newlocale(
                    libc::LC_CTYPE_MASK,
                    c"fl_test_gb2312".as_ptr(),
                    std::ptr::null_mut(),
                )
                .is_null()
            );
            assert!(
                fl_locale::newlocale(libc::LC_CTYPE_MASK, c"fl_test_gb2312".as_ptr(), base.0,)
                    .is_null()
            );
        }
        // A failed newlocale must leave its supplied base valid and unchanged.
        let previous = unsafe {
            (
                fl_locale::uselocale(base.0),
                (host_locales().select)(base.1),
            )
        };
        assert!(!previous.0.is_null() && !previous.1.is_null());
        assert_active(baseline);
        unsafe {
            fl_locale::uselocale(previous.0);
            (host_locales().select)(previous.1);
            fl_locale::freelocale(base.0);
            (host_locales().free)(base.1);
        }
        assert_active(baseline);
        eprintln!(
            "unsupported locale checks: host GB2312 decode, setlocale rollback, newlocale empty/base rollback"
        );
    }

    type C8rtombFn = unsafe extern "C" fn(*mut c_char, u8, *mut c_void) -> usize;
    type Mbrtoc8Fn = unsafe extern "C" fn(*mut u8, *const c_char, usize, *mut c_void) -> usize;

    #[derive(Clone, Copy)]
    struct Char8Api {
        encode: C8rtombFn,
        decode: Mbrtoc8Fn,
        base: Api,
    }

    fn char8_api(ours: bool) -> Char8Api {
        use frankenlibc_abi::unistd_abi as fl8;
        if ours {
            return Char8Api {
                encode: fl8::c8rtomb,
                decode: fl8::mbrtoc8,
                base: api(true),
            };
        }
        static HOST: OnceLock<Char8Api> = OnceLock::new();
        *HOST.get_or_init(|| unsafe {
            // A host lacking C23 entrypoints is an explicit missing oracle,
            // never a reason to silently skip the new locale coverage.
            Char8Api {
                encode: host_fn(c"c8rtomb", fl8::c8rtomb as *const ()),
                decode: host_fn(c"mbrtoc8", fl8::mbrtoc8 as *const ()),
                base: api(false),
            }
        })
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Char8Result {
        returned: usize,
        error: c_int,
        output: [u8; 10],
        initial: Option<bool>,
    }

    fn encode8_step(
        functions: Char8Api,
        state: &mut State,
        unit: u8,
        reset: bool,
        width: usize,
    ) -> Char8Result {
        let mut output = [BYTE_CANARY; 10];
        let (returned, error) = unsafe {
            *(functions.base.errno)() = SAVED_ERRNO;
            let destination = if reset {
                std::ptr::null_mut()
            } else {
                output.as_mut_ptr().add(1).cast()
            };
            let returned = (functions.encode)(destination, unit, state.pointer());
            (returned, *(functions.base.errno)())
        };
        assert_eq!(output[0], BYTE_CANARY);
        // width=1 is the actual capacity promised by a single-byte locale.
        // Copying the accumulated UTF-8 sequence would corrupt these canaries.
        assert!(output[width + 1..].iter().all(|&byte| byte == BYTE_CANARY));
        state.check();
        Char8Result {
            returned,
            error,
            output,
            initial: (returned != usize::MAX).then(|| state.initial(functions.base)),
        }
    }

    fn decode8_step(
        functions: Char8Api,
        state: &mut State,
        input: Option<&[u8]>,
        length: usize,
        discard: bool,
    ) -> Char8Result {
        let mut output = [BYTE_CANARY; 10];
        let (returned, error) = unsafe {
            *(functions.base.errno)() = SAVED_ERRNO;
            let destination = if discard {
                std::ptr::null_mut()
            } else {
                output.as_mut_ptr().add(1)
            };
            let source = input.map_or(std::ptr::null(), |bytes| bytes.as_ptr().cast());
            let returned = (functions.decode)(destination, source, length, state.pointer());
            (returned, *(functions.base.errno)())
        };
        assert_eq!(output[0], BYTE_CANARY);
        assert_eq!(&output[2..], &[BYTE_CANARY; 8]);
        state.check();
        Char8Result {
            returned,
            error,
            output,
            initial: (returned != usize::MAX).then(|| state.initial(functions.base)),
        }
    }

    fn compare_encode8(
        states: &mut [State; 2],
        unit: u8,
        reset: bool,
        width: usize,
        count: &mut usize,
    ) -> Char8Result {
        let ours = encode8_step(char8_api(true), &mut states[0], unit, reset, width);
        let gnu = encode8_step(char8_api(false), &mut states[1], unit, reset, width);
        assert_eq!(
            ours, gnu,
            "c8rtomb unit={unit:#x} reset={reset} width={width}"
        );
        *count += 1;
        ours
    }

    fn compare_decode8(
        states: &mut [State; 2],
        input: Option<&[u8]>,
        length: usize,
        discard: bool,
        count: &mut usize,
    ) -> Char8Result {
        let ours = decode8_step(char8_api(true), &mut states[0], input, length, discard);
        let gnu = decode8_step(char8_api(false), &mut states[1], input, length, discard);
        assert_eq!(
            ours, gnu,
            "mbrtoc8 input={input:x?} n={length} discard={discard}"
        );
        *count += 1;
        ours
    }

    #[test]
    fn char8_conversions_follow_the_external_locale() {
        if !isolated("char8_conversions_follow_the_external_locale") {
            return;
        }
        let mut encoded = 0;
        let mut decoded = 0;
        let mut external_bytes = 0;
        let mut queued = 0;
        let mut invalid = 0;
        for case in CASES {
            select(case);
            eprintln!("char8_t locale {:?}", case.name);
            for byte in 0u8..=u8::MAX {
                external_bytes += 1;
                let external = [byte];
                let wc = reference_btowc(case, byte);
                if wc == u32::MAX {
                    let mut states = [State::new(), State::new()];
                    let empty =
                        compare_decode8(&mut states, Some(&external), 0, false, &mut decoded);
                    assert_eq!(
                        (empty.returned, empty.initial),
                        (usize::MAX - 1, Some(true))
                    );
                    let rejected =
                        compare_decode8(&mut states, Some(&external), 1, false, &mut decoded);
                    assert_eq!(
                        (rejected.returned, rejected.error),
                        (usize::MAX, libc::EILSEQ)
                    );
                    invalid += 1;
                    continue;
                }
                let mut utf8 = [0; 4];
                let units = char::from_u32(wc)
                    .unwrap()
                    .encode_utf8(&mut utf8)
                    .as_bytes();
                let mut states = [State::new(), State::new()];
                for (index, &unit) in units.iter().enumerate() {
                    let result = compare_encode8(&mut states, unit, false, 1, &mut encoded);
                    if index + 1 == units.len() {
                        assert_eq!((result.returned, result.initial), (1, Some(true)));
                        assert_eq!(c_int::from(result.output[1]), reference_wctob(case, wc));
                    } else {
                        assert_eq!((result.returned, result.initial), (0, Some(false)));
                        assert_eq!(result.output, [BYTE_CANARY; 10]);
                    }
                }
                for discard in [false, true] {
                    for null_drain in [false, true] {
                        let mut states = [State::new(), State::new()];
                        let first =
                            compare_decode8(&mut states, Some(&external), 1, discard, &mut decoded);
                        assert_eq!(first.returned, usize::from(byte != 0));
                        assert_eq!(first.initial, Some(units.len() == 1));
                        if !discard {
                            assert_eq!(first.output[1], units[0]);
                        }
                        for (index, &unit) in units.iter().enumerate().skip(1) {
                            // Queued UTF-8 output is independent of the next
                            // external input, even when n=0 or s=NULL.
                            let source = if null_drain {
                                None
                            } else {
                                Some(b"A".as_slice())
                            };
                            let next =
                                compare_decode8(&mut states, source, 0, discard, &mut decoded);
                            assert_eq!(next.returned, usize::MAX - 2);
                            assert_eq!(next.initial, Some(index + 1 == units.len()));
                            if !discard {
                                assert_eq!(next.output[1], unit);
                            }
                            queued += 1;
                        }
                        let reset = compare_decode8(&mut states, None, 0, false, &mut decoded);
                        assert_eq!((reset.returned, reset.initial), (0, Some(true)));
                        assert_eq!(reset.output, [BYTE_CANARY; 10]);
                        let empty =
                            compare_decode8(&mut states, Some(&external), 0, false, &mut decoded);
                        assert_eq!(
                            (empty.returned, empty.initial),
                            (usize::MAX - 1, Some(true))
                        );
                    }
                }
            }
            // A complete but unrepresentable Unicode scalar must fail without
            // writing a UTF-8 sequence into the one-byte external buffer.
            let mut states = [State::new(), State::new()];
            let mut last = None;
            for &unit in b"\xf0\x9f\x99\x82" {
                last = Some(compare_encode8(&mut states, unit, false, 1, &mut encoded));
            }
            let last = last.unwrap();
            assert_eq!((last.returned, last.error), (usize::MAX, libc::EILSEQ));
            assert_eq!(last.output, [BYTE_CANARY; 10]);
            assert!(states[0].initial(api(true)));
            assert!(states[1].initial(api(false)));
        }

        for locale in [c"C", c"C.UTF-8"] {
            set_global(locale);
            let width = unsafe { fl_mb_cur_max() };
            let mut initial = [State::new(), State::new()];
            let reset = compare_encode8(&mut initial, 0xff, true, width, &mut encoded);
            assert_eq!((reset.returned, reset.initial), (1, Some(true)));
            let nul = compare_encode8(&mut initial, 0, false, width, &mut encoded);
            assert_eq!(
                (nul.returned, nul.output[1], nul.initial),
                (1, 0, Some(true))
            );
            let mut states = [State::new(), State::new()];
            compare_encode8(&mut states, 0xc3, false, width, &mut encoded);
            let completed = compare_encode8(&mut states, 0xa9, false, width, &mut encoded);
            if locale == c"C" {
                assert_eq!(
                    (completed.returned, completed.error),
                    (usize::MAX, libc::EILSEQ)
                );
            } else {
                assert_eq!((completed.returned, completed.initial), (2, Some(true)));
                assert_eq!(&completed.output[1..3], b"\xc3\xa9");
            }
            let mut pending = [State::new(), State::new()];
            let lead = compare_encode8(&mut pending, 0xc3, false, width, &mut encoded);
            assert_eq!((lead.returned, lead.initial), (0, Some(false)));
            let reset = compare_encode8(&mut pending, 0, true, width, &mut encoded);
            assert_eq!((reset.returned, reset.error), (usize::MAX, libc::EILSEQ));
            assert!(!pending[0].initial(api(true)));
            assert!(!pending[1].initial(api(false)));
            let malformed: &[&[u8]] = &[
                b"\x80",
                b"\xc0",
                b"\xff",
                b"\xe2(",
                b"\xed\xa0\x80",
                b"\xf4\x90\x80\x80",
                b"\xc3\0",
            ];
            for &input in malformed {
                let mut states = [State::new(), State::new()];
                let mut rejected = false;
                for &unit in input {
                    let result = compare_encode8(&mut states, unit, false, width, &mut encoded);
                    if result.returned == usize::MAX {
                        assert_eq!(result.error, libc::EILSEQ);
                        rejected = true;
                        break;
                    }
                }
                assert!(rejected, "malformed UTF-8 was accepted: {input:x?}");
            }
        }
        set_global(c"C");
        let mut states = [State::new(), State::new()];
        let result = compare_decode8(&mut states, Some(b"\xc3\xa9"), 2, false, &mut decoded);
        assert_eq!((result.returned, result.error), (usize::MAX, libc::EILSEQ));

        set_global(c"C.UTF-8");
        let mut states = [State::new(), State::new()];
        let lead = compare_decode8(&mut states, Some(b"\xc3"), 1, false, &mut decoded);
        assert_eq!((lead.returned, lead.initial), (usize::MAX - 1, Some(false)));
        let empty = compare_decode8(&mut states, Some(b"\xa9"), 0, false, &mut decoded);
        assert_eq!(
            (empty.returned, empty.initial),
            (usize::MAX - 1, Some(false))
        );
        let resumed = compare_decode8(&mut states, Some(b"\xa9"), 1, false, &mut decoded);
        assert_eq!(
            (resumed.returned, resumed.output[1], resumed.initial),
            (1, 0xc3, Some(false))
        );
        let tail = compare_decode8(&mut states, None, 0, false, &mut decoded);
        assert_eq!(
            (tail.returned, tail.output[1], tail.initial),
            (usize::MAX - 2, 0xa9, Some(true))
        );
        let mut states = [State::new(), State::new()];
        compare_decode8(&mut states, Some(b"\xc3"), 1, true, &mut decoded);
        let reset = compare_decode8(&mut states, None, 0, false, &mut decoded);
        assert_eq!((reset.returned, reset.error), (usize::MAX, libc::EILSEQ));

        // glibc accepts historical external UTF-8 beyond Unicode, consumes the
        // complete scalar, and emits no char8_t. Preserve that GNU behavior
        // without manufacturing a trailing-output queue or overflowing it.
        for &input in [
            b"\xf4\x90\x80\x80".as_slice(),
            b"\xf8\x88\x80\x80\x80",
            b"\xfc\x84\x80\x80\x80\x80",
        ]
        .iter()
        {
            let mut states = [State::new(), State::new()];
            let lead = compare_decode8(&mut states, Some(&input[..1]), 1, false, &mut decoded);
            assert_eq!(lead.returned, usize::MAX - 1);
            let tail = compare_decode8(
                &mut states,
                Some(&input[1..]),
                input.len() - 1,
                false,
                &mut decoded,
            );
            assert_eq!((tail.returned, tail.initial), (input.len() - 1, Some(true)));
            assert_eq!(tail.output, [BYTE_CANARY; 10]);
        }
        assert_eq!(external_bytes, 1_280);
        assert_eq!(invalid, 1);
        assert!(encoded > 1_280 && decoded > 10_000 && queued > 1_000);
        eprintln!(
            "char8_t comparisons: encode={encoded}, decode={decoded}, queued={queued}, external-bytes={external_bytes}, invalid={invalid}"
        );
    }
}
