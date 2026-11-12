#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc c16rtomb oracle

//! C11 `c16rtomb` (char16_t -> multibyte) surrogate-pair parity vs host glibc
//! (bd-2g7oyh.NEW — coverage). The decode side (`mbrtoc16`) is fuzzed, but the
//! stateful surrogate-pair *encoder* had no vs-glibc differential. This gate
//! drives a sequence of UTF-16 code units through both engines with a shared
//! mbstate and compares each call's (return value, errno, emitted bytes) over:
//! BMP characters, astral characters as high+low surrogate pairs, a lone high
//! surrogate (pends, returns 0), and the EILSEQ cases (lone low surrogate, a
//! high surrogate not followed by a low one).

use frankenlibc_abi::wchar_abi as fl;
use std::ffi::{c_char, c_int, c_void};
use std::sync::{Mutex, OnceLock};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Encode = unsafe extern "C" fn(*mut c_char, u16, *mut c_void) -> usize;
type Decode16 = unsafe extern "C" fn(*mut u16, *const c_char, usize, *mut c_void) -> usize;
type Decode32 = unsafe extern "C" fn(*mut u32, *const c_char, usize, *mut c_void) -> usize;
type DecodeWide =
    unsafe extern "C" fn(*mut libc::wchar_t, *const c_char, usize, *mut c_void) -> usize;
type Length = unsafe extern "C" fn(*const c_char, usize, *mut c_void) -> usize;
type Bounded = unsafe extern "C" fn(
    *mut libc::wchar_t,
    *mut *const c_char,
    usize,
    usize,
    *mut c_void,
) -> usize;
type Errno = unsafe extern "C" fn() -> *mut c_int;

struct Host {
    encode: Encode,
    utf16: Decode16,
    utf32: Decode32,
    wide: DecodeWide,
    length: Length,
    bounded: Bounded,
    errno: Errno,
    locale: unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char,
}

fn host() -> &'static Host {
    static HOST: OnceLock<Host> = OnceLock::new();
    HOST.get_or_init(|| {
        // SAFETY: signatures match the named C functions. Each oracle rejects
        // the corresponding FrankenLibC address, including errno and locale.
        unsafe {
            Host {
                encode: dlsym_oracle::host_fn(c"c16rtomb", fl::c16rtomb as *const ()),
                utf16: dlsym_oracle::host_fn(c"mbrtoc16", fl::mbrtoc16 as *const ()),
                utf32: dlsym_oracle::host_fn(c"mbrtoc32", fl::mbrtoc32 as *const ()),
                wide: dlsym_oracle::host_fn(c"mbrtowc", fl::mbrtowc as *const ()),
                length: dlsym_oracle::host_fn(c"mbrlen", fl::mbrlen as *const ()),
                bounded: dlsym_oracle::host_fn(c"mbsnrtowcs", fl::mbsnrtowcs as *const ()),
                errno: dlsym_oracle::host_fn(
                    c"__errno_location",
                    frankenlibc_abi::errno_abi::__errno_location as *const (),
                ),
                locale: dlsym_oracle::host_fn(
                    c"setlocale",
                    frankenlibc_abi::locale_abi::setlocale as *const (),
                ),
            }
        }
    })
}

static LOCALE_LOCK: Mutex<()> = Mutex::new(());

fn select_utf8() {
    // SAFETY: LC_ALL and a live NUL-terminated locale name. Missing locale is
    // a broken prerequisite, never a successful zero-comparison skip.
    unsafe {
        assert!(!(host().locale)(libc::LC_ALL, c"C.UTF-8".as_ptr()).is_null());
        assert!(
            !frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()).is_null()
        );
    }
}

fn errno_slot(eng: u8) -> *mut c_int {
    // SAFETY: both functions return a live thread-local errno slot.
    unsafe {
        if eng == 0 {
            frankenlibc_abi::errno_abi::__errno_location()
        } else {
            (host().errno)()
        }
    }
}

fn step(
    eng: u8,
    c16: u16,
    st: *mut c_void,
    null_output: bool,
    initial: c_int,
) -> (i64, i32, Vec<u8>) {
    let mut buf = [0u8; 8];
    let out = if null_output {
        std::ptr::null_mut()
    } else {
        buf.as_mut_ptr().cast()
    };
    // SAFETY: output is NULL or an eight-byte buffer, state is NULL or a live
    // aligned zero-initialized mbstate object; char16_t accepts every u16.
    unsafe { *errno_slot(eng) = initial };
    let r = if eng == 0 {
        unsafe { fl::c16rtomb(out, c16, st) }
    } else {
        unsafe { (host().encode)(out, c16, st) }
    };
    // SAFETY: read the same engine's errno before any formatting/allocation.
    let e = unsafe { *errno_slot(eng) };
    let written = if r == usize::MAX || null_output { 0 } else { r };
    assert!(written <= buf.len(), "encoder exceeded MB_CUR_MAX storage");
    (r as isize as i64, e, buf[..written].to_vec())
}

fn seq(eng: u8, units: &[u16]) -> Vec<(i64, i32, Vec<u8>)> {
    let mut st = [0u64; 1];
    let p = st.as_mut_ptr() as *mut c_void;
    units.iter().map(|&u| step(eng, u, p, false, 0)).collect()
}

#[test]
fn c16rtomb_matches_glibc() {
    let _guard = LOCALE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    select_utf8();

    let cases: &[&[u16]] = &[
        &[0x0041],                 // 'A'
        &[0x00E9],                 // é (2-byte)
        &[0x20AC],                 // € (3-byte)
        &[0xD800, 0xDC00],         // U+10000 (surrogate pair, 4-byte)
        &[0xD83D, 0xDE00],         // U+1F600 emoji
        &[0xDBFF, 0xDFFF],         // U+10FFFF (max)
        &[0xDC00],                 // lone low surrogate -> EILSEQ
        &[0xD800, 0x0041],         // high then non-low -> EILSEQ
        &[0xD800, 0xD800],         // high then high -> EILSEQ
        &[0xD800],                 // lone high (incomplete) -> returns 0
        &[0xDBFF],                 // lone high
        &[0x20AC, 0xD83D, 0xDE00], // BMP then astral pair
        &[0x0041, 0xDC00],         // ascii then lone low -> EILSEQ
        &[0xD800, 0xDC00, 0x0042], // pair then ascii
    ];
    for units in cases {
        let a = seq(0, units);
        let b = seq(1, units);
        assert_eq!(a, b, "c16rtomb sequence {units:04x?}: fl={a:?} glibc={b:?}");
    }

    // s == NULL resets the conversion state and returns 1 (a single NUL); pin it.
    let mut st = [0u64; 1];
    let p = st.as_mut_ptr() as *mut c_void;
    let fr = unsafe { fl::c16rtomb(std::ptr::null_mut(), 0, p) };
    let mut st2 = [0u64; 1];
    let p2 = st2.as_mut_ptr() as *mut c_void;
    let gr = unsafe { (host().encode)(std::ptr::null_mut(), 0, p2) };
    assert_eq!(fr, gr, "c16rtomb(NULL) reset return");
}

fn decode(kind: usize, eng: u8, bytes: &[u8], state: *mut c_void) -> (i64, u32, c_int) {
    let mut value = 0x1234u32;
    let mut unit = 0x1234u16;
    let s = bytes.as_ptr().cast();
    // SAFETY: the input is a live slice; outputs are aligned scalar locals;
    // state is NULL or a live aligned eight-byte mbstate, kept per stream.
    let (ret, error) = unsafe {
        *errno_slot(eng) = libc::E2BIG;
        let ret = match (kind, eng) {
            (0, 0) => fl::mbrtowc((&mut value as *mut u32).cast(), s, bytes.len(), state),
            (0, _) => (host().wide)((&mut value as *mut u32).cast(), s, bytes.len(), state),
            (1, 0) => fl::mbrlen(s, bytes.len(), state),
            (1, _) => (host().length)(s, bytes.len(), state),
            (2, 0) => fl::mbrtoc32(&mut value, s, bytes.len(), state),
            (2, _) => (host().utf32)(&mut value, s, bytes.len(), state),
            (3, 0) => fl::mbrtoc16(&mut unit, s, bytes.len(), state),
            (3, _) => (host().utf16)(&mut unit, s, bytes.len(), state),
            _ => unreachable!("unknown decoder"),
        };
        (ret, *errno_slot(eng))
    };
    (
        ret as isize as i64,
        if kind == 3 { u32::from(unit) } else { value },
        error,
    )
}

#[test]
fn restartable_decoders_resume_implicit_state() {
    let _guard = LOCALE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    select_utf8();
    let mut checked = 0;
    let mut differences = Vec::new();
    for kind in 0..4 {
        for explicit in [false, true] {
            for bytes in ["é".as_bytes(), "€".as_bytes(), "🙂".as_bytes()] {
                for split in 1..bytes.len() {
                    let mut fs = [0u64; 1];
                    let mut gs = [0u64; 1];
                    let fp = if explicit {
                        fs.as_mut_ptr().cast()
                    } else {
                        std::ptr::null_mut()
                    };
                    let gp = if explicit {
                        gs.as_mut_ptr().cast()
                    } else {
                        std::ptr::null_mut()
                    };
                    let mut parts = vec![&bytes[..split], &bytes[split..split], &bytes[split..]];
                    if kind == 3 && bytes.len() == 4 {
                        parts.push(b"A"); // pending low surrogate consumes no input
                    }
                    for part in parts {
                        let f = decode(kind, 0, part, fp);
                        let g = decode(kind, 1, part, gp);
                        checked += 1;
                        if f != g {
                            differences.push(format!("kind={kind} explicit={explicit} bytes={bytes:x?} split={split} part={part:x?}: fl={f:?} GNU={g:?}"));
                        }
                    }
                }
            }
        }
    }
    assert_eq!(checked, 150);
    eprintln!(
        "restartable split-input comparisons={checked} differences={}",
        differences.len()
    );
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

#[test]
fn implicit_decoder_states_are_independent() {
    let _guard = LOCALE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    select_utf8();
    let replay = |eng| {
        let bytes = [
            "é".as_bytes(),
            "€".as_bytes(),
            "𐀀".as_bytes(),
            "🙂".as_bytes(),
        ];
        let mut out = Vec::new();
        for (kind, b) in bytes.iter().enumerate() {
            out.push(decode(kind, eng, &b[..1], std::ptr::null_mut()));
        }
        for (kind, b) in bytes.iter().enumerate().rev() {
            out.push(decode(kind, eng, &b[1..], std::ptr::null_mut()));
        }
        out.push(decode(3, eng, b"A", std::ptr::null_mut()));
        out
    };
    let f = replay(0);
    let g = replay(1);
    assert_eq!(f.len(), 9);
    assert_eq!(f, g, "independent implicit decoder streams");
}

#[test]
fn implicit_utf16_directions_are_independent() {
    let _guard = LOCALE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    select_utf8();
    for decode_first in [false, true] {
        let replay = |eng| {
            let mut out = Vec::new();
            for decoder in [decode_first, !decode_first, false, true] {
                if decoder {
                    let bytes = if out.len() == 3 {
                        b"A".as_slice()
                    } else {
                        "🙂".as_bytes()
                    };
                    out.push(format!("{:?}", decode(3, eng, bytes, std::ptr::null_mut())));
                } else {
                    let unit = if out.len() == 2 { 0xde00 } else { 0xd83d };
                    out.push(format!(
                        "{:?}",
                        step(eng, unit, std::ptr::null_mut(), false, libc::E2BIG)
                    ));
                }
            }
            out
        };
        assert_eq!(replay(0), replay(1), "decode_first={decode_first}");
    }
}

#[test]
fn c16rtomb_null_output_ignores_code_unit() {
    let _guard = LOCALE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    select_utf8();
    let mut checked = 0;
    for pending in [false, true] {
        for ignored in [0, b'A' as u16, 0xd800, 0xdc00] {
            for initial in [0, libc::E2BIG] {
                let mut fs = [0u64; 1];
                let mut gs = [0u64; 1];
                let fp = fs.as_mut_ptr().cast();
                let gp = gs.as_mut_ptr().cast();
                if pending {
                    assert_eq!(
                        step(0, 0xd83d, fp, false, initial),
                        step(1, 0xd83d, gp, false, initial)
                    );
                }
                let f = step(0, ignored, fp, true, initial);
                let g = step(1, ignored, gp, true, initial);
                checked += 1;
                assert_eq!(
                    f, g,
                    "pending={pending} ignored={ignored:x} initial={initial}"
                );
            }
        }
    }
    assert_eq!(checked, 16);
}

#[test]
fn bounded_converter_keeps_own_implicit_state() {
    let _guard = LOCALE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    select_utf8();
    for explicit in [false, true] {
        let replay = |eng| {
            let mut state = [0u64; 1];
            let ps = if explicit {
                state.as_mut_ptr().cast()
            } else {
                std::ptr::null_mut()
            };
            let mut result = vec![format!(
                "{:?}",
                decode(0, eng, &[0xc3], std::ptr::null_mut())
            )];
            for bytes in [&[0xe2][..], &[0x82, 0xac][..]] {
                let mut src = bytes.as_ptr().cast::<c_char>();
                let mut wc = 0x1234;
                // SAFETY: one output slot and exactly bytes.len() readable
                // input bytes; independent state belongs to this bounded stream.
                let (ret, error) = unsafe {
                    *errno_slot(eng) = libc::E2BIG;
                    let f = if eng == 0 {
                        fl::mbsnrtowcs
                    } else {
                        host().bounded
                    };
                    let ret = f(&mut wc, &mut src, bytes.len(), 1, ps);
                    (ret, *errno_slot(eng))
                };
                // Both pointers stay within the same input slice or its end.
                let used = src as usize - bytes.as_ptr() as usize;
                result.push(format!("{ret},{wc:x},{used},{error}"));
                if result.len() == 2 {
                    result.push(format!(
                        "{:?}",
                        decode(0, eng, &[0xa9], std::ptr::null_mut())
                    ));
                }
            }
            result
        };
        assert_eq!(replay(0), replay(1), "explicit={explicit}");
    }
}
