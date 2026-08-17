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
use dlsym_oracle::host_fn;

use frankenlibc_abi::glibc_internal_abi::__ctype_get_mb_cur_max as fl_mb_cur_max;
use frankenlibc_abi::locale_abi::{
    locale_reset_active_charset_for_tests, nl_langinfo as fl_nl_langinfo,
    setlocale as fl_setlocale,
};
use frankenlibc_abi::wchar_abi::{mbtowc as fl_mbtowc, wctomb as fl_wctomb};

type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *const c_char;
type NlLanginfoFn = unsafe extern "C" fn(c_int) -> *const c_char;
type MbCurMaxFn = unsafe extern "C" fn() -> usize;
type MbtowcFn = unsafe extern "C" fn(*mut u32, *const u8, usize) -> c_int;
type WctombFn = unsafe extern "C" fn(*mut u8, u32) -> c_int;

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
    wctomb: WctombFn,
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
                mb_cur_max: host_fn(
                    c"__ctype_get_mb_cur_max",
                    fl_mb_cur_max as *const (),
                ),
                mbtowc: host_fn(c"mbtowc", fl_mbtowc as *const ()),
                wctomb: host_fn(c"wctomb", fl_wctomb as *const ()),
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
        *libc::__errno_location() = 0;
        let host_rc = (host().mbtowc)(&mut host_wc, bytes.as_ptr(), bytes.len());
        let host_err = *libc::__errno_location();

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
            assert_eq!((fl.0, fl.2), (-1, libc::EILSEQ), "{name:?} must refuse UTF-8");
        }
    }
}
