#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wide-stdio oracle

//! Wide-stdio WRITE-side + ungetwc parity vs host glibc C.UTF-8
//! (bd-2g7oyh.287). `fputwc`/`fputws` byte-encoding (incl. obsolete 5/6-byte
//! RFC-2279 and the unconvertible-char '?' substitution glibc's gconv emits)
//! and `ungetwc` push-back are compared against the live glibc oracle by
//! writing/reading the SAME on-disk file with each engine.

use std::ffi::{CString, c_char, c_int, c_void};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};

use frankenlibc_abi::stdio_abi as flio;
use frankenlibc_abi::wchar_abi as flw;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

struct HostWideApi {
    open: unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void,
    close: unsafe extern "C" fn(*mut c_void) -> c_int,
    putwc: unsafe extern "C" fn(u32, *mut c_void) -> u32,
    putwc_unlocked: unsafe extern "C" fn(u32, *mut c_void) -> u32,
    putws: unsafe extern "C" fn(*const i32, *mut c_void) -> c_int,
    putws_unlocked: unsafe extern "C" fn(*const i32, *mut c_void) -> c_int,
    format: unsafe extern "C" fn(*mut c_void, *const i32, ...) -> c_int,
    orient: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
    set_buffer: unsafe extern "C" fn(*mut c_void, *mut c_char, c_int, usize) -> c_int,
    flush: unsafe extern "C" fn(*mut c_void) -> c_int,
    error: unsafe extern "C" fn(*mut c_void) -> c_int,
    getwc: unsafe extern "C" fn(*mut c_void) -> u32,
    ungetwc: unsafe extern "C" fn(u32, *mut c_void) -> u32,
    getwc_unlocked: unsafe extern "C" fn(*mut c_void) -> u32,
    getwc_alias: unsafe extern "C" fn(*mut c_void) -> u32,
    getwc_alias_unlocked: unsafe extern "C" fn(*mut c_void) -> u32,
    getws: unsafe extern "C" fn(*mut i32, c_int, *mut c_void) -> *mut i32,
    getws_unlocked: unsafe extern "C" fn(*mut i32, c_int, *mut c_void) -> *mut i32,
    scan: unsafe extern "C" fn(*mut c_void, *const i32, ...) -> c_int,
    eof: unsafe extern "C" fn(*mut c_void) -> c_int,
    seek: unsafe extern "C" fn(*mut c_void, libc::c_long, c_int) -> c_int,
    tell: unsafe extern "C" fn(*mut c_void) -> libc::c_long,
    getpos: unsafe extern "C" fn(*mut c_void, *mut libc::fpos_t) -> c_int,
    setpos: unsafe extern "C" fn(*mut c_void, *const libc::fpos_t) -> c_int,
    rewind: unsafe extern "C" fn(*mut c_void),
    purge: unsafe extern "C" fn(*mut c_void),
    setlocale: unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char,
    errno: unsafe extern "C" fn() -> *mut c_int,
}

fn host_api() -> &'static HostWideApi {
    static API: std::sync::OnceLock<HostWideApi> = std::sync::OnceLock::new();
    API.get_or_init(|| {
        // SAFETY: every function type matches the corresponding C declaration.
        // Resolution also rejects a host address equal to the native export.
        unsafe {
            HostWideApi {
                open: dlsym_oracle::host_fn(c"fopen", flio::fopen as *const ()),
                close: dlsym_oracle::host_fn(c"fclose", flio::fclose as *const ()),
                putwc: dlsym_oracle::host_fn(c"fputwc", flw::fputwc as *const ()),
                putwc_unlocked: dlsym_oracle::host_fn(
                    c"fputwc_unlocked",
                    flw::fputwc_unlocked as *const (),
                ),
                putws: dlsym_oracle::host_fn(c"fputws", flw::fputws as *const ()),
                putws_unlocked: dlsym_oracle::host_fn(
                    c"fputws_unlocked",
                    flw::fputws_unlocked as *const (),
                ),
                format: dlsym_oracle::host_fn(c"fwprintf", flw::fwprintf as *const ()),
                orient: dlsym_oracle::host_fn(
                    c"fwide",
                    frankenlibc_abi::glibc_internal_abi::fwide as *const (),
                ),
                set_buffer: dlsym_oracle::host_fn(c"setvbuf", flio::setvbuf as *const ()),
                flush: dlsym_oracle::host_fn(c"fflush", flio::fflush as *const ()),
                error: dlsym_oracle::host_fn(c"ferror", flio::ferror as *const ()),
                getwc: dlsym_oracle::host_fn(c"fgetwc", flw::fgetwc as *const ()),
                ungetwc: dlsym_oracle::host_fn(c"ungetwc", flw::ungetwc as *const ()),
                getwc_unlocked: dlsym_oracle::host_fn(
                    c"fgetwc_unlocked",
                    flw::fgetwc_unlocked as *const (),
                ),
                getwc_alias: dlsym_oracle::host_fn(c"getwc", flw::getwc as *const ()),
                getwc_alias_unlocked: dlsym_oracle::host_fn(
                    c"getwc_unlocked",
                    flw::getwc_unlocked as *const (),
                ),
                getws: dlsym_oracle::host_fn(c"fgetws", flw::fgetws as *const ()),
                getws_unlocked: dlsym_oracle::host_fn(
                    c"fgetws_unlocked",
                    flw::fgetws_unlocked as *const (),
                ),
                scan: dlsym_oracle::host_fn(c"fwscanf", flw::fwscanf as *const ()),
                eof: dlsym_oracle::host_fn(c"feof", flio::feof as *const ()),
                seek: dlsym_oracle::host_fn(c"fseek", flio::fseek as *const ()),
                tell: dlsym_oracle::host_fn(c"ftell", flio::ftell as *const ()),
                getpos: dlsym_oracle::host_fn(c"fgetpos", flio::fgetpos as *const ()),
                setpos: dlsym_oracle::host_fn(c"fsetpos", flio::fsetpos as *const ()),
                rewind: dlsym_oracle::host_fn(c"rewind", flio::rewind as *const ()),
                purge: dlsym_oracle::host_fn(
                    c"__fpurge",
                    frankenlibc_abi::glibc_internal_abi::__fpurge as *const (),
                ),
                setlocale: dlsym_oracle::host_fn(
                    c"setlocale",
                    frankenlibc_abi::locale_abi::setlocale as *const (),
                ),
                errno: dlsym_oracle::host_fn(
                    c"__errno_location",
                    frankenlibc_abi::errno_abi::__errno_location as *const (),
                ),
            }
        }
    })
}
const WEOF: u32 = 0xFFFF_FFFF;

fn open(path: &str, mode: &str, host: bool) -> *mut c_void {
    let cp = CString::new(path).unwrap();
    let m = CString::new(mode).unwrap();
    if host {
        unsafe { (host_api().open)(cp.as_ptr(), m.as_ptr()) }
    } else {
        unsafe { flio::fopen(cp.as_ptr(), m.as_ptr()) }
    }
}
fn close(s: *mut c_void, host: bool) {
    if host {
        unsafe { (host_api().close)(s) };
    } else {
        unsafe { flio::fclose(s) };
    }
}

/// (return-value-sequence, resulting-file-bytes) for writing `chars` via fputwc.
fn putwc_run(chars: &[u32], host: bool) -> (Vec<i64>, Vec<u8>) {
    let p = format!("/tmp/fl_wsw_{}_{}.bin", std::process::id(), host as u8);
    let s = open(&p, "w", host);
    assert!(!s.is_null());
    let mut rets = vec![];
    for &c in chars {
        let r = if host {
            unsafe { (host_api().putwc)(c, s) }
        } else {
            unsafe { flw::fputwc(c, s) }
        };
        rets.push(r as i32 as i64);
    }
    close(s, host);
    let b = std::fs::read(&p).unwrap_or_default();
    let _ = std::fs::remove_file(&p);
    (rets, b)
}

fn putws_bytes(ws: &[i32], host: bool) -> Vec<u8> {
    let p = format!("/tmp/fl_wsw2_{}_{}.bin", std::process::id(), host as u8);
    let s = open(&p, "w", host);
    assert!(!s.is_null());
    let mut v = ws.to_vec();
    v.push(0);
    if host {
        unsafe { (host_api().putws)(v.as_ptr(), s) };
    } else {
        unsafe { flw::fputws(v.as_ptr(), s) };
    }
    close(s, host);
    let b = std::fs::read(&p).unwrap_or_default();
    let _ = std::fs::remove_file(&p);
    b
}

fn unget_script(content: &[u8], host: bool) -> Vec<i64> {
    let p = format!("/tmp/fl_wsu_{}_{}.bin", std::process::id(), host as u8);
    std::fs::write(&p, content).unwrap();
    let s = open(&p, "r", host);
    assert!(!s.is_null());
    let g = |s: *mut c_void| {
        if host {
            unsafe { (host_api().getwc)(s) }
        } else {
            unsafe { flw::fgetwc(s) }
        }
    };
    let u = |wc: u32, s: *mut c_void| {
        if host {
            unsafe { (host_api().ungetwc)(wc, s) }
        } else {
            unsafe { flw::ungetwc(wc, s) }
        }
    };
    let mut out = vec![];
    let c1 = g(s);
    out.push(c1 as i32 as i64);
    out.push(u(c1, s) as i32 as i64); // push back -> returns the char
    out.push(g(s) as i32 as i64); // re-read c1
    out.push(u(b'Z' as u32, s) as i32 as i64); // push a different char
    out.push(g(s) as i32 as i64); // read Z
    out.push(u(WEOF, s) as i32 as i64); // push WEOF -> WEOF (no-op)
    out.push(g(s) as i32 as i64); // continue normally
    close(s, host);
    let _ = std::fs::remove_file(&p);
    out
}

#[test]
fn wide_stdio_write_matches_glibc() {
    let loc = CString::new("C.UTF-8").unwrap();
    // Each provider needs its own locale. The oracle is resolved explicitly
    // from glibc, while native FrankenLibC starts in the POSIX C locale.
    // SAFETY: same NUL-terminated locale name, same category, as below.
    unsafe { frankenlibc_abi::locale_abi::setlocale(0, loc.as_ptr()) };
    if unsafe { (host_api().setlocale)(0, loc.as_ptr()) }.is_null() {
        eprintln!("C.UTF-8 unavailable; skipping");
        return;
    }
    // fputwc byte encoding + return values, incl. obsolete 5/6-byte and the
    // unconvertible-char '?' substitution.
    let char_cases: &[&[u32]] = &[
        &[97, 98, 10],
        &[0xE9, 0x20AC, 0x10348],
        &[0x110000],           // > U+10FFFF, still a valid 4-byte RFC-2279 form
        &[0x200000],           // 5-byte
        &[0x4000000],          // 6-byte
        &[0x7FFF_FFFF],        // max 6-byte
        &[0xD800],             // surrogate -> '?'
        &[0x8000_0000],        // > U+7FFFFFFF -> '?'
        &[0x41, 0xD800, 0x42], // valid, '?', valid in one stream
    ];
    for chars in char_cases {
        assert_eq!(
            putwc_run(chars, false),
            putwc_run(chars, true),
            "fputwc {chars:x?}"
        );
    }

    for ws in [
        &[104i32, 105][..],
        &[0x20AC, 0x10348][..],
        &[0x41, 0xD800, 0x42][..],
    ] {
        assert_eq!(
            putws_bytes(ws, false),
            putws_bytes(ws, true),
            "fputws {ws:x?}"
        );
    }

    for content in [&b"abc"[..], "\u{20ac}x".as_bytes(), &b"a\nb"[..]] {
        assert_eq!(
            unget_script(content, false),
            unget_script(content, true),
            "ungetwc {content:x?}"
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum WideWriter {
    Character,
    CharacterUnlocked,
    String,
    StringUnlocked,
    Formatted,
}

const WIDE_WRITERS: [WideWriter; 5] = [
    WideWriter::Character,
    WideWriter::CharacterUnlocked,
    WideWriter::String,
    WideWriter::StringUnlocked,
    WideWriter::Formatted,
];

fn isolated_wide_write_test(name: &str) -> bool {
    const CHILD: &str = "FRANKENLIBC_WIDE_TRANSLIT_CHILD";
    if std::env::var_os(CHILD).is_some() {
        // SAFETY: the watchdog applies only to this isolated test process.
        unsafe { libc::alarm(30) };
        return false;
    }
    // Locale changes must not race the older C.UTF-8 test in this binary.
    for mode in ["strict", "hardened"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads", "1"])
            .env(CHILD, "1")
            .env("FRANKENLIBC_MODE", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{name} {mode}: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    }
    true
}

fn wide_write_locale(name: &str, host: bool) {
    let name = CString::new(name).unwrap();
    // SAFETY: the locale name is terminated and live for the call; every new
    // test that changes LC_CTYPE runs in a separate, single-test process.
    let result = unsafe {
        if host {
            (host_api().setlocale)(libc::LC_CTYPE, name.as_ptr())
        } else {
            frankenlibc_abi::locale_abi::setlocale(libc::LC_CTYPE, name.as_ptr())
        }
    };
    assert!(!result.is_null(), "LC_CTYPE {name:?}, host={host}");
}

fn wide_write_errno(host: bool) -> *mut c_int {
    // SAFETY: each provider returns the current thread's live errno cell.
    unsafe {
        if host {
            (host_api().errno)()
        } else {
            frankenlibc_abi::errno_abi::__errno_location()
        }
    }
}

fn unbuffered_wide_stream(path: &str, mode: &str, host: bool) -> *mut c_void {
    let stream = open(path, mode, host);
    assert!(!stream.is_null(), "fopen {path} {mode}, host={host}");
    // SAFETY: stream belongs to the selected provider and is still open.
    unsafe {
        let result = if host {
            (host_api().set_buffer)(stream, std::ptr::null_mut(), libc::_IONBF, 0)
        } else {
            flio::setvbuf(stream, std::ptr::null_mut(), libc::_IONBF, 0)
        };
        assert_eq!(result, 0, "setvbuf _IONBF, host={host}");
        let orientation = if host {
            (host_api().orient)(stream, 1)
        } else {
            frankenlibc_abi::glibc_internal_abi::fwide(stream, 1)
        };
        assert!(orientation > 0, "wide orientation, host={host}");
    }
    stream
}

fn write_wide_units(
    stream: *mut c_void,
    units: &[i32],
    writer: WideWriter,
    host: bool,
) -> Vec<i64> {
    let mut terminated = units.to_vec();
    terminated.push(0);
    // SAFETY: the selected provider owns the stream, and both wide strings
    // are terminated and remain live through their respective calls.
    unsafe {
        match writer {
            WideWriter::Character | WideWriter::CharacterUnlocked => units
                .iter()
                .map(|&wc| {
                    let result = match (host, writer) {
                        (true, WideWriter::Character) => (host_api().putwc)(wc as u32, stream),
                        (true, _) => (host_api().putwc_unlocked)(wc as u32, stream),
                        (false, WideWriter::Character) => flw::fputwc(wc as u32, stream),
                        (false, _) => flw::fputwc_unlocked(wc, stream.cast()),
                    };
                    i64::from(result as i32)
                })
                .collect(),
            WideWriter::String | WideWriter::StringUnlocked => {
                let result = match (host, writer) {
                    (true, WideWriter::String) => (host_api().putws)(terminated.as_ptr(), stream),
                    (true, _) => (host_api().putws_unlocked)(terminated.as_ptr(), stream),
                    (false, WideWriter::String) => flw::fputws(terminated.as_ptr(), stream),
                    (false, _) => flw::fputws_unlocked(terminated.as_ptr(), stream.cast()),
                };
                // The magnitude of a successful fputws result is unspecified.
                vec![if result < 0 { -1 } else { 0 }]
            }
            WideWriter::Formatted => {
                let format = [b'%' as i32, b'l' as i32, b's' as i32, 0];
                let result = if host {
                    (host_api().format)(stream, format.as_ptr(), terminated.as_ptr())
                } else {
                    flw::fwprintf(stream, format.as_ptr(), terminated.as_ptr())
                };
                vec![i64::from(result)]
            }
        }
    }
}

#[derive(Debug, PartialEq)]
struct WideWriteObservation {
    returns: Vec<i64>,
    errno: c_int,
    error: bool,
    bytes: Vec<u8>,
}

fn unbuffered_transliteration_run(
    initial_locale: &str,
    write_locale: &str,
    mode: &str,
    units: &[i32],
    writer: WideWriter,
    host: bool,
) -> WideWriteObservation {
    wide_write_locale(initial_locale, host);
    // SAFETY: a fresh anonymous file is owned by File after the successful call.
    let fd = unsafe { libc::memfd_create(c"wide-transliteration".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(fd >= 0);
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let path = format!("/proc/self/fd/{}", file.as_raw_fd());
    let stream = unbuffered_wide_stream(&path, mode, host);
    wide_write_locale(write_locale, host);
    // SAFETY: update only this thread's errno in the selected provider.
    unsafe { *wide_write_errno(host) = 0 };
    let returns = write_wide_units(stream, units, writer, host);
    let errno = unsafe { *wide_write_errno(host) };
    let error = unsafe {
        if host {
            (host_api().error)(stream) != 0
        } else {
            flio::ferror(stream) != 0
        }
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    // _IONBF converts during the write: changing the locale before fflush
    // must neither change nor add any bytes already observed in the file.
    wide_write_locale(if write_locale == "C" { "C.UTF-8" } else { "C" }, host);
    let flush = unsafe {
        if host {
            (host_api().flush)(stream)
        } else {
            flio::fflush(stream)
        }
    };
    assert_eq!(flush, 0, "fflush, host={host}");
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut flushed_bytes = Vec::new();
    file.read_to_end(&mut flushed_bytes).unwrap();
    assert_eq!(bytes, flushed_bytes, "_IONBF must write before fflush");
    close(stream, host);
    WideWriteObservation {
        returns,
        errno,
        error,
        bytes,
    }
}

#[test]
fn unbuffered_wide_transliteration_matches_glibc() {
    if isolated_wide_write_test("unbuffered_wide_transliteration_matches_glibc") {
        return;
    }
    let units = [
        0x20ac, 0x7c, 0xe9, 0x7c, 0xdf, 0x7c, 0x2014, 0x7c, 0x1f642, 0x7c, 0x010c, 0x7c, 0x0301,
        0x7c, 0x200b, 0x7c, 0xa0, 0x7c, 0x0370,
    ];
    for (initial, current, mode) in [
        ("C", "C", "w+"),
        ("C", "C.UTF-8", "w+"),
        ("C.UTF-8", "C", "w+"),
        ("C.UTF-8", "C", "w+,ccs=ASCII"),
        ("C.UTF-8", "C.UTF-8", "w+,ccs=ASCII"),
        ("C", "C.UTF-8", "w+,ccs=ISO-8859-1"),
        ("C.UTF-8", "C", "w+,ccs=ISO-8859-1"),
        ("C", "C.UTF-8", "w+,ccs=IBM1047"),
        ("C", "C.UTF-8", "w+,ccs=UCS-2BE"),
    ] {
        for writer in WIDE_WRITERS {
            let host = unbuffered_transliteration_run(initial, current, mode, &units, writer, true);
            let native =
                unbuffered_transliteration_run(initial, current, mode, &units, writer, false);
            assert!(!host.error);
            assert_eq!(
                native, host,
                "{writer:?}, initial={initial}, current={current}, {mode}"
            );
        }
    }
}

#[test]
fn unbuffered_wide_transliteration_chunk_boundaries_match_glibc() {
    if isolated_wide_write_test("unbuffered_wide_transliteration_chunk_boundaries_match_glibc") {
        return;
    }
    // Expansion crosses the 1024-byte formatter staging boundary; dropped
    // combining marks must consume their wide units even with no output.
    let expanding = [0x20ac, 0xa9, 0x0301, 0x7c].repeat(700);
    let disappearing = vec![0x0301; 2048];
    for units in [&expanding[..], &disappearing[..]] {
        for writer in [WideWriter::String, WideWriter::Formatted] {
            for mode in ["w+,ccs=ASCII", "w+,ccs=UCS-2BE"] {
                let host =
                    unbuffered_transliteration_run("C", "C.UTF-8", mode, units, writer, true);
                let native =
                    unbuffered_transliteration_run("C", "C.UTF-8", mode, units, writer, false);
                assert_eq!(
                    native,
                    host,
                    "{writer:?}, {mode}, {} wide units",
                    units.len()
                );
            }
        }
    }
}

#[test]
fn unbuffered_wide_transliteration_errors_match_glibc() {
    if isolated_wide_write_test("unbuffered_wide_transliteration_errors_match_glibc") {
        return;
    }
    for writer in WIDE_WRITERS {
        let mut observed = Vec::new();
        for host in [true, false] {
            wide_write_locale("C", host);
            let stream = unbuffered_wide_stream("/dev/full", "w", host);
            wide_write_locale("C.UTF-8", host);
            // SAFETY: provider-local errno and an open provider-owned stream.
            unsafe { *wide_write_errno(host) = 0 };
            let returns = write_wide_units(stream, &[0x20ac], writer, host);
            let errno = unsafe { *wide_write_errno(host) };
            let error = unsafe {
                if host {
                    (host_api().error)(stream)
                } else {
                    flio::ferror(stream)
                }
            };
            assert_eq!(errno, libc::ENOSPC, "{writer:?}, host={host}");
            assert_ne!(error, 0, "{writer:?}, host={host}");
            assert_eq!(returns, [-1], "{writer:?}, host={host}");
            observed.push((returns, errno, error != 0));
            close(stream, host);
        }
        assert_eq!(observed[0], observed[1], "{writer:?}");
    }
    // A combining mark disappears under C.UTF-8 -> ASCII, but is still a
    // write operation: reject a read-only FILE, and do no descriptor write
    // at all for a writable /dev/full stream whose encoding emits no bytes.
    for (path, mode, expected_errno) in [
        ("/dev/null", "r", libc::EBADF),
        ("/dev/null", "w", 0),
        ("/dev/full", "w", 0),
    ] {
        for writer in WIDE_WRITERS {
            let mut observed = Vec::new();
            for host in [true, false] {
                wide_write_locale("C", host);
                let stream = unbuffered_wide_stream(path, mode, host);
                wide_write_locale("C.UTF-8", host);
                // SAFETY: provider-local errno and an open provider-owned FILE.
                unsafe { *wide_write_errno(host) = 0 };
                let returns = write_wide_units(stream, &[0x0301], writer, host);
                let errno = unsafe { *wide_write_errno(host) };
                let error = unsafe {
                    if host {
                        (host_api().error)(stream)
                    } else {
                        flio::ferror(stream)
                    }
                };
                assert_eq!(
                    errno, expected_errno,
                    "{writer:?}, {path}, {mode}, host={host}"
                );
                assert_eq!(error != 0, expected_errno != 0);
                let expected_return = if expected_errno != 0 {
                    -1
                } else {
                    match writer {
                        WideWriter::Character | WideWriter::CharacterUnlocked => 0x0301,
                        WideWriter::String | WideWriter::StringUnlocked => 0,
                        WideWriter::Formatted => 1,
                    }
                };
                assert_eq!(returns, [expected_return]);
                observed.push((returns, errno, error != 0));
                close(stream, host);
            }
            assert_eq!(observed[0], observed[1], "{writer:?}, {path}, {mode}");
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum WideReader {
    Character,
    CharacterUnlocked,
    CharacterAlias,
    CharacterAliasUnlocked,
    Line,
    LineUnlocked,
    Formatted,
}

const WIDE_READERS: [WideReader; 7] = [
    WideReader::Character,
    WideReader::CharacterUnlocked,
    WideReader::CharacterAlias,
    WideReader::CharacterAliasUnlocked,
    WideReader::Line,
    WideReader::LineUnlocked,
    WideReader::Formatted,
];

/// Separate provider-owned FILEs read an anonymous file, so neither the
/// oracle nor the candidate can obtain its character data from the other.
struct WideInput {
    file: std::fs::File,
    stream: *mut c_void,
    host: bool,
}

impl WideInput {
    fn new(bytes: &[u8], host: bool, unbuffered: bool) -> Self {
        // SAFETY: a successful memfd is transferred to File exactly once.
        let fd = unsafe { libc::memfd_create(c"wide-pushback".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(bytes).unwrap();
        let path = format!("/proc/self/fd/{}", file.as_raw_fd());
        let stream = if unbuffered {
            unbuffered_wide_stream(&path, "r", host)
        } else {
            open(&path, "r", host)
        };
        assert!(!stream.is_null());
        Self { file, stream, host }
    }

    fn get(&self) -> u32 {
        // SAFETY: this object owns a live FILE from the chosen provider.
        unsafe {
            if self.host {
                (host_api().getwc)(self.stream)
            } else {
                flw::fgetwc(self.stream)
            }
        }
    }

    fn push(&self, value: u32) -> u32 {
        // SAFETY: ungetwc accepts any wint_t and a live FILE.
        unsafe {
            if self.host {
                (host_api().ungetwc)(value, self.stream)
            } else {
                flw::ungetwc(value, self.stream)
            }
        }
    }

    fn status(&self) -> (bool, bool) {
        // SAFETY: both status queries are for the same live FILE.
        unsafe {
            if self.host {
                (
                    (host_api().eof)(self.stream) != 0,
                    (host_api().error)(self.stream) != 0,
                )
            } else {
                (flio::feof(self.stream) != 0, flio::ferror(self.stream) != 0)
            }
        }
    }

    fn tell(&self) -> libc::c_long {
        // SAFETY: this object owns a live FILE from the chosen provider.
        unsafe {
            if self.host {
                (host_api().tell)(self.stream)
            } else {
                flio::ftell(self.stream)
            }
        }
    }

    fn unchanged_bytes(&mut self, expected: &[u8]) {
        self.file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        self.file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, expected, "pushback never changes external storage");
    }
}

impl Drop for WideInput {
    fn drop(&mut self) {
        close(self.stream, self.host);
    }
}

fn read_three_wide(input: &WideInput, reader: WideReader) -> [u32; 3] {
    let mut out = [0x5555_5555i32; 4];
    // SAFETY: all destinations have their declared capacity, the format is
    // terminated, and the selected FILE remains live for the entire operation.
    unsafe {
        match reader {
            WideReader::Character
            | WideReader::CharacterUnlocked
            | WideReader::CharacterAlias
            | WideReader::CharacterAliasUnlocked => {
                for value in &mut out[..3] {
                    let wc = match (input.host, reader) {
                        (true, WideReader::Character) => (host_api().getwc)(input.stream),
                        (true, WideReader::CharacterUnlocked) => {
                            (host_api().getwc_unlocked)(input.stream)
                        }
                        (true, WideReader::CharacterAlias) => {
                            (host_api().getwc_alias)(input.stream)
                        }
                        (true, _) => (host_api().getwc_alias_unlocked)(input.stream),
                        (false, WideReader::Character) => flw::fgetwc(input.stream),
                        (false, WideReader::CharacterUnlocked) => {
                            flw::fgetwc_unlocked(input.stream.cast())
                        }
                        (false, WideReader::CharacterAlias) => flw::getwc(input.stream.cast()),
                        (false, _) => flw::getwc_unlocked(input.stream.cast()),
                    };
                    *value = wc as i32;
                }
                assert_eq!(out[3], 0x5555_5555);
            }
            WideReader::Line | WideReader::LineUnlocked => {
                let result = match (input.host, reader) {
                    (true, WideReader::Line) => {
                        (host_api().getws)(out.as_mut_ptr(), 4, input.stream)
                    }
                    (true, _) => (host_api().getws_unlocked)(out.as_mut_ptr(), 4, input.stream),
                    (false, WideReader::Line) => flw::fgetws(out.as_mut_ptr(), 4, input.stream),
                    (false, _) => flw::fgetws_unlocked(out.as_mut_ptr(), 4, input.stream.cast()),
                };
                assert_eq!(result, out.as_mut_ptr(), "{reader:?}, host={}", input.host);
                assert_eq!(out[3], 0);
            }
            WideReader::Formatted => {
                let format = [
                    b'%' as i32,
                    b'3' as i32,
                    b'l' as i32,
                    b'c' as i32,
                    b'%' as i32,
                    b'n' as i32,
                    0,
                ];
                let mut consumed: c_int = -1;
                let result = if input.host {
                    (host_api().scan)(
                        input.stream,
                        format.as_ptr(),
                        out.as_mut_ptr(),
                        &mut consumed as *mut c_int,
                    )
                } else {
                    flw::fwscanf(
                        input.stream,
                        format.as_ptr(),
                        out.as_mut_ptr(),
                        &mut consumed as *mut c_int,
                    )
                };
                assert_eq!(result, 1);
                assert_eq!(consumed, 3, "%n counts wide input characters");
                assert_eq!(out[3], 0x5555_5555);
            }
        }
    }
    [out[0] as u32, out[1] as u32, out[2] as u32]
}

#[test]
fn wide_pushback_values_reach_all_readers() {
    if isolated_wide_write_test("wide_pushback_values_reach_all_readers") {
        return;
    }
    // GNU preserves every non-WEOF wint_t here, including values that cannot
    // be encoded in the stream's bound locale. This is a compatibility check,
    // separate from the standard's guarantee for a read-back character.
    for locale in ["C", "C.UTF-8"] {
        for unbuffered in [false, true] {
            for value in [
                0,
                0x41,
                0x20ac,
                0xd800,
                0x8000_0000,
                0x7fff_ffff,
                0xffff_fffe,
            ] {
                for reader in WIDE_READERS {
                    let mut observations = Vec::new();
                    for host in [true, false] {
                        wide_write_locale(locale, host);
                        let mut input = WideInput::new(b"AB\n", host, unbuffered);
                        assert_eq!(input.get(), u32::from(b'A'));
                        // SAFETY: modify only the selected provider's errno.
                        unsafe { *wide_write_errno(host) = libc::EBUSY };
                        let pushed = input.push(value);
                        let push_errno = unsafe { *wide_write_errno(host) };
                        assert_eq!(pushed, value, "{locale}, {reader:?}, host={host}");
                        assert_eq!(push_errno, libc::EBUSY);
                        let values = read_three_wide(&input, reader);
                        assert_eq!(values, [value, u32::from(b'B'), u32::from(b'\n')]);
                        // GNU UTF-8 can report offset 2 after substituting NUL
                        // for A while its original wide buffer remains active.
                        // Compare that intermediate position only for original A.
                        if !host || value == u32::from(b'A') {
                            assert_eq!(input.tell(), 3);
                        }
                        assert_eq!(input.status(), (false, false));
                        assert_eq!(input.get(), WEOF);
                        assert_eq!(input.tell(), 3);
                        observations.push((pushed, push_errno, values, input.status()));
                        input.unchanged_bytes(b"AB\n");
                    }
                    assert_eq!(
                        observations[0], observations[1],
                        "{locale}, {reader:?}, value={value:#x}, unbuffered={unbuffered}"
                    );
                }
            }
        }
    }
}

#[test]
fn wide_pushback_lifo_eof_errors_and_failed_seek() {
    if isolated_wide_write_test("wide_pushback_lifo_eof_errors_and_failed_seek") {
        return;
    }
    for locale in ["C", "C.UTF-8"] {
        for unbuffered in [false, true] {
            for host in [true, false] {
                wide_write_locale(locale, host);
                let mut input = WideInput::new(b"AB", host, unbuffered);
                assert_eq!(input.get(), u32::from(b'A'));
                assert_eq!(input.tell(), 1);
                let values = [0xd800, 0x41, 0x20ac, 0, 0x8000_0000];
                for value in values {
                    assert_eq!(input.push(value), value);
                }
                // WEOF and an invalid seek must not discard any pending value.
                unsafe { *wide_write_errno(host) = libc::EBUSY };
                assert_eq!(input.push(WEOF), WEOF);
                assert_eq!(unsafe { *wide_write_errno(host) }, libc::EBUSY);
                let seek = unsafe {
                    if host {
                        (host_api().seek)(input.stream, 0, -123)
                    } else {
                        flio::fseek(input.stream, 0, -123)
                    }
                };
                assert_eq!(seek, -1);
                assert_eq!(unsafe { *wide_write_errno(host) }, libc::EINVAL);
                for value in values.into_iter().rev() {
                    assert_eq!(input.get(), value);
                }
                // The native offset is restored now; compare both providers
                // after EOF retires GNU's original wide buffer.
                assert_eq!(input.get(), u32::from(b'B'));
                if !host {
                    assert_eq!(input.tell(), 2);
                }
                assert_eq!(input.get(), WEOF);
                assert_eq!(input.status(), (true, false));
                assert_eq!(input.tell(), 2);
                unsafe { *wide_write_errno(host) = libc::EBUSY };
                assert_eq!(input.push(0xd800), 0xd800);
                assert_eq!(unsafe { *wide_write_errno(host) }, libc::EBUSY);
                assert_eq!(input.status(), (false, false));
                assert_eq!(input.get(), 0xd800);
                assert_eq!(input.get(), WEOF);
                assert_eq!(input.status(), (true, false));
                input.unchanged_bytes(b"AB");

                let broken = WideInput::new(&[0xff], host, unbuffered);
                assert_eq!(broken.get(), WEOF);
                assert_eq!(unsafe { *wide_write_errno(host) }, libc::EILSEQ);
                assert_eq!(broken.status(), (false, true));
                assert_eq!(broken.push(0x20ac), 0x20ac);
                assert_eq!(unsafe { *wide_write_errno(host) }, libc::EILSEQ);
                assert_eq!(broken.status(), (false, true));
                assert_eq!(broken.get(), 0x20ac);
                assert_eq!(broken.status(), (false, true));

                // A scanner must restore complete lookahead characters. A
                // numeric mismatch and a numeric suffix both leave the exact
                // wchar_t pending, even when no external encoding exists.
                for value in [0x20ac, 0xd800, 0x8000_0000] {
                    for prefix in [false, true] {
                        let lookahead = WideInput::new(b"AB", host, unbuffered);
                        assert_eq!(lookahead.get(), u32::from(b'A'));
                        assert_eq!(lookahead.push(value), value);
                        if prefix {
                            assert_eq!(lookahead.push(u32::from(b'7')), u32::from(b'7'));
                        }
                        let format = [b'%' as i32, b'd' as i32, b'%' as i32, b'n' as i32, 0];
                        let mut number: c_int = -123;
                        let mut consumed: c_int = -123;
                        // SAFETY: the format and both matching destinations
                        // remain live, and the FILE is owned by this test.
                        let count = unsafe {
                            if host {
                                (host_api().scan)(
                                    lookahead.stream,
                                    format.as_ptr(),
                                    &mut number as *mut c_int,
                                    &mut consumed as *mut c_int,
                                )
                            } else {
                                flw::fwscanf(
                                    lookahead.stream,
                                    format.as_ptr(),
                                    &mut number as *mut c_int,
                                    &mut consumed as *mut c_int,
                                )
                            }
                        };
                        if prefix {
                            assert_eq!((count, number, consumed), (1, 7, 1));
                        } else {
                            assert_eq!((count, number, consumed), (0, -123, -123));
                        }
                        assert_eq!(lookahead.status(), (false, false));
                        assert_eq!(lookahead.get(), value);
                        assert_eq!(lookahead.get(), u32::from(b'B'));
                        assert_eq!(lookahead.get(), WEOF);
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum WideReposition {
    AbsoluteSeek,
    SavedPosition,
    Rewind,
    Purge,
}

#[test]
fn wide_pushback_is_discarded_by_positioning_and_purge() {
    if isolated_wide_write_test("wide_pushback_is_discarded_by_positioning_and_purge") {
        return;
    }
    for locale in ["C", "C.UTF-8"] {
        for unbuffered in [false, true] {
            for action in [
                WideReposition::AbsoluteSeek,
                WideReposition::SavedPosition,
                WideReposition::Rewind,
                WideReposition::Purge,
            ] {
                let mut results = Vec::new();
                for host in [true, false] {
                    wide_write_locale(locale, host);
                    let mut input = WideInput::new(b"AB\n", host, unbuffered);
                    assert_eq!(input.get(), u32::from(b'A'));
                    // SAFETY: fpos_t is writable opaque storage; it is queried
                    // before pushback, when its position has a defined value.
                    let mut saved = std::mem::MaybeUninit::<libc::fpos_t>::zeroed();
                    let rc = unsafe {
                        if host {
                            (host_api().getpos)(input.stream, saved.as_mut_ptr())
                        } else {
                            flio::fgetpos(input.stream, saved.as_mut_ptr())
                        }
                    };
                    assert_eq!(rc, 0);
                    // One successfully read character has a defined external
                    // representation; positioning must discard its backup.
                    // Arbitrary-value cleanup is covered by the core tests.
                    assert_eq!(input.push(u32::from(b'A')), u32::from(b'A'));
                    // SAFETY: saved belongs to this FILE and all target offsets
                    // are valid absolute positions in the same input file.
                    unsafe {
                        match (host, action) {
                            (true, WideReposition::AbsoluteSeek) => {
                                assert_eq!((host_api().seek)(input.stream, 0, libc::SEEK_SET), 0);
                            }
                            (false, WideReposition::AbsoluteSeek) => {
                                assert_eq!(flio::fseek(input.stream, 0, libc::SEEK_SET), 0);
                            }
                            (true, WideReposition::SavedPosition) => {
                                assert_eq!((host_api().setpos)(input.stream, saved.as_ptr()), 0);
                            }
                            (false, WideReposition::SavedPosition) => {
                                assert_eq!(flio::fsetpos(input.stream, saved.as_ptr()), 0);
                            }
                            (true, WideReposition::Rewind) => (host_api().rewind)(input.stream),
                            (false, WideReposition::Rewind) => flio::rewind(input.stream),
                            (true, WideReposition::Purge) => (host_api().purge)(input.stream),
                            (false, WideReposition::Purge) => {
                                frankenlibc_abi::glibc_internal_abi::__fpurge(input.stream);
                            }
                        }
                    }
                    let value = input.get();
                    match action {
                        WideReposition::AbsoluteSeek | WideReposition::Rewind => {
                            assert_eq!(value, u32::from(b'A'));
                        }
                        WideReposition::SavedPosition => assert_eq!(value, u32::from(b'B')),
                        WideReposition::Purge => {
                            assert!(value == u32::from(b'B') || value == WEOF);
                        }
                    }
                    results.push((value, input.status()));
                    input.unchanged_bytes(b"AB\n");
                }
                assert_eq!(results[0], results[1], "{locale}, {action:?}, {unbuffered}");
            }
        }
    }
}
