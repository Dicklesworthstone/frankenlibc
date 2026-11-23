#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wide-stdio oracle

//! Wide-stdio (`fgetwc`/`fgetws`) decode parity vs host glibc C.UTF-8
//! (bd-2g7oyh.286). Reads the SAME on-disk file with fl's and glibc's stream
//! readers and compares the wide-char sequences, covering: ASCII/2/3/4-byte
//! UTF-8, obsolete RFC-2279 5/6-byte leads (which glibc C.UTF-8 and fl's own
//! mbrtowc decode — bd-kryp2k), invalid/incomplete/truncated sequences,
//! embedded NUL, `fgetws` newline retention + buffer clipping, and the
//! degenerate `n == 1` (read 0 chars, return an empty string, not NULL).

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io::Write;

use frankenlibc_abi::stdio_abi as flio;
use frankenlibc_abi::wchar_abi as flw;

unsafe extern "C" {
    fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
    fn fclose(s: *mut c_void) -> c_int;
    fn fgetwc(s: *mut c_void) -> u32;
    fn fgetws(b: *mut i32, n: c_int, s: *mut c_void) -> *mut i32;
    fn setlocale(c: c_int, l: *const c_char) -> *mut c_char;
}
const WEOF: u32 = 0xFFFF_FFFF;

fn mkfile(tag: &str, bytes: &[u8]) -> String {
    let p = format!("/tmp/fl_wstdio_{}_{tag}.bin", std::process::id());
    std::fs::File::create(&p).unwrap().write_all(bytes).unwrap();
    p
}

fn seq(path: &str, host: bool) -> Vec<i64> {
    let cp = CString::new(path).unwrap();
    let m = CString::new("r").unwrap();
    let s = if host {
        unsafe { fopen(cp.as_ptr(), m.as_ptr()) }
    } else {
        unsafe { flio::fopen(cp.as_ptr(), m.as_ptr()) }
    };
    assert!(!s.is_null(), "fopen failed for {path}");
    let mut out = vec![];
    loop {
        let c = if host {
            unsafe { fgetwc(s) }
        } else {
            unsafe { flw::fgetwc(s) }
        };
        out.push(c as i32 as i64);
        if c == WEOF || out.len() > 256 {
            break;
        }
    }
    if host {
        unsafe { fclose(s) }
    } else {
        unsafe { flio::fclose(s) }
    };
    out
}

fn lines(path: &str, n: c_int, host: bool, cap: usize) -> Vec<Vec<i64>> {
    let cp = CString::new(path).unwrap();
    let m = CString::new("r").unwrap();
    let s = if host {
        unsafe { fopen(cp.as_ptr(), m.as_ptr()) }
    } else {
        unsafe { flio::fopen(cp.as_ptr(), m.as_ptr()) }
    };
    assert!(!s.is_null());
    let mut out = vec![];
    loop {
        let mut buf = vec![0i32; n as usize + 2];
        let r = if host {
            unsafe { fgetws(buf.as_mut_ptr(), n, s) }
        } else {
            unsafe { flw::fgetws(buf.as_mut_ptr(), n, s) }
        };
        if r.is_null() {
            break;
        }
        out.push(
            buf.iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as i64)
                .collect(),
        );
        if out.len() >= cap {
            break;
        }
    }
    if host {
        unsafe { fclose(s) }
    } else {
        unsafe { flio::fclose(s) }
    };
    out
}

#[test]
fn wide_stdio_decode_matches_glibc() {
    let loc = CString::new("C.UTF-8").unwrap();
    // fl needs the same locale, not just the oracle. `setlocale` below is a
    // link-time symbol, so in a debug test it binds GLIBC's and moves the
    // oracle alone; fl has started in POSIX C since b5aef5e3a. Set fl's first,
    // unconditionally -- if the host switch then fails the arm skips anyway.
    // SAFETY: same NUL-terminated locale name, same category, as below.
    unsafe { frankenlibc_abi::locale_abi::setlocale(0, loc.as_ptr()) };
    if unsafe { setlocale(0, loc.as_ptr()) }.is_null() {
        eprintln!("C.UTF-8 unavailable; skipping");
        return;
    }
    let cases: &[(&str, Vec<u8>)] = &[
        ("ascii_nl", b"ab\ncd\n".to_vec()),
        (
            "multibyte",
            "a\u{e9}\u{20ac}\n\u{10348}x".as_bytes().to_vec(),
        ),
        ("no_final_nl", b"xyz".to_vec()),
        ("empty", b"".to_vec()),
        ("invalid", vec![b'a', 0xFF, 0xFE, b'b']),
        ("incomplete_eof", vec![b'a', 0xE2, 0x82]),
        ("lone_cont", vec![0x80, 0x80]),
        ("nul_mid", vec![b'a', 0, b'b', b'\n']),
        ("five_byte", vec![0xF8, 0x88, 0x80, 0x80, 0x80, b'\n']),
        ("six_byte", vec![0xFC, 0x84, 0x80, 0x80, 0x80, 0x80, b'\n']),
    ];
    for (tag, bytes) in cases {
        let p = mkfile(tag, bytes);
        assert_eq!(seq(&p, false), seq(&p, true), "fgetwc diverged on {tag}");
        let _ = std::fs::remove_file(&p);
    }

    for (tag, body, n) in [
        ("lines", "a\u{e9}\u{20ac}\n\u{10348}x\ny", 5),
        ("clip", "abcdef\n", 4),
        ("n1", "ab\n", 1),
        ("n2", "ab\n", 2),
    ] {
        let p = mkfile(tag, body.as_bytes());
        // n == 1 returns an empty string forever (consumes nothing); cap the loop.
        let cap = if n == 1 { 8 } else { 50 };
        assert_eq!(
            lines(&p, n, false, cap),
            lines(&p, n, true, cap),
            "fgetws diverged on {tag} n={n}"
        );
        let _ = std::fs::remove_file(&p);
    }
}

type CcsOpen = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type CcsReopen =
    unsafe extern "C-unwind" fn(*const c_char, *const c_char, *mut c_void) -> *mut c_void;
type CcsStreamInt = unsafe extern "C-unwind" fn(*mut c_void) -> c_int;
type CcsRead = unsafe extern "C-unwind" fn(*mut c_void) -> u32;
type CcsWrite = unsafe extern "C-unwind" fn(u32, *mut c_void) -> u32;
type CcsOrientation = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type CcsLocale = unsafe extern "C" fn(c_int, *const c_char) -> *const c_char;
type CcsErrno = unsafe extern "C" fn() -> *mut c_int;

struct CcsApi {
    name: &'static str,
    open: CcsOpen,
    reopen: CcsReopen,
    close: CcsStreamInt,
    flush: CcsStreamInt,
    fileno: CcsStreamInt,
    error: CcsStreamInt,
    eof: CcsStreamInt,
    read: CcsRead,
    write: CcsWrite,
    orientation: CcsOrientation,
    locale: CcsLocale,
    errno: CcsErrno,
}

fn ccs_native_api() -> CcsApi {
    CcsApi {
        name: "native",
        open: flio::fopen,
        reopen: flio::freopen,
        close: flio::fclose,
        flush: flio::fflush,
        fileno: flio::fileno,
        error: flio::ferror,
        eof: flio::feof,
        read: flw::fgetwc,
        write: flw::fputwc,
        orientation: frankenlibc_abi::glibc_internal_abi::fwide,
        locale: frankenlibc_abi::locale_abi::setlocale,
        errno: frankenlibc_abi::errno_abi::__errno_location,
    }
}

fn ccs_host_api() -> CcsApi {
    // Resolve each oracle explicitly: release builds may export native symbols
    // into the test binary, making link-time libc calls compare fl to itself.
    // SAFETY: the named system library is retained until this child exits.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    macro_rules! resolve {
        ($name:expr, $ty:ty, $candidate:path) => {{
            // SAFETY: live dlopen handle and a static NUL-terminated name;
            // every requested signature matches that GNU libc entrypoint.
            let symbol = unsafe { libc::dlsym(handle, $name.as_ptr()) };
            assert!(!symbol.is_null(), "dlsym {:?}", $name);
            assert_ne!(symbol as usize, $candidate as *const () as usize);
            unsafe { std::mem::transmute::<*mut c_void, $ty>(symbol) }
        }};
    }
    CcsApi {
        name: "glibc",
        open: resolve!(c"fopen", CcsOpen, flio::fopen),
        reopen: resolve!(c"freopen", CcsReopen, flio::freopen),
        close: resolve!(c"fclose", CcsStreamInt, flio::fclose),
        flush: resolve!(c"fflush", CcsStreamInt, flio::fflush),
        fileno: resolve!(c"fileno", CcsStreamInt, flio::fileno),
        error: resolve!(c"ferror", CcsStreamInt, flio::ferror),
        eof: resolve!(c"feof", CcsStreamInt, flio::feof),
        read: resolve!(c"fgetwc", CcsRead, flw::fgetwc),
        write: resolve!(c"fputwc", CcsWrite, flw::fputwc),
        orientation: resolve!(
            c"fwide",
            CcsOrientation,
            frankenlibc_abi::glibc_internal_abi::fwide
        ),
        locale: resolve!(
            c"setlocale",
            CcsLocale,
            frankenlibc_abi::locale_abi::setlocale
        ),
        errno: resolve!(
            c"__errno_location",
            CcsErrno,
            frankenlibc_abi::errno_abi::__errno_location
        ),
    }
}

fn ccs_locale(api: &CcsApi, name: &CStr) {
    // SAFETY: LC_CTYPE and a static locale name; each engine owns its locale.
    let result = unsafe { (api.locale)(libc::LC_CTYPE, name.as_ptr()) };
    assert!(!result.is_null(), "{} setlocale({name:?})", api.name);
}

fn ccs_open(api: &CcsApi, path: &str, mode: &CStr) -> *mut c_void {
    let path = CString::new(path).unwrap();
    // SAFETY: both strings are live and NUL-terminated.
    let stream = unsafe { (api.open)(path.as_ptr(), mode.as_ptr()) };
    assert!(!stream.is_null(), "{} fopen({mode:?})", api.name);
    stream
}

fn ccs_read(api: &CcsApi, stream: *mut c_void, expected: &[u32], label: &str) {
    // SAFETY: the caller passes a live readable stream owned by this engine.
    unsafe {
        for (index, &value) in expected.iter().enumerate() {
            assert_eq!((api.read)(stream), value, "{} {label}[{index}]", api.name);
        }
        assert_eq!((api.read)(stream), WEOF, "{} {label} EOF", api.name);
        assert_ne!((api.eof)(stream), 0, "{} {label} EOF flag", api.name);
        assert_eq!((api.error)(stream), 0, "{} {label} error flag", api.name);
    }
}

fn ccs_write(api: &CcsApi, stream: *mut c_void, values: &[u32], label: &str) {
    // SAFETY: the caller passes a live writable stream owned by this engine.
    unsafe {
        for (index, &value) in values.iter().enumerate() {
            assert_eq!(
                (api.write)(value, stream),
                value,
                "{} {label}[{index}]",
                api.name
            );
        }
        assert_eq!((api.flush)(stream), 0, "{} {label} flush", api.name);
        assert_eq!((api.error)(stream), 0, "{} {label} error flag", api.name);
    }
}

fn ccs_close(api: &CcsApi, stream: *mut c_void) {
    // SAFETY: the caller transfers its live stream to its owning engine.
    assert_eq!(unsafe { (api.close)(stream) }, 0, "{} fclose", api.name);
}

fn ccs_codec_roundtrips(api: &CcsApi) {
    let unicode = vec![0x41, 0, 0xe9, 0x20ac, 0x1f642, 0x0a, 0x5a];
    let bmp = vec![0x41, 0, 0xe9, 0x20ac, 0x0a, 0x5a];
    let cases = [
        ("ASCII", vec![0x41, 0, 0x0a, 0x5a], b"A\0\nZ".to_vec()),
        (
            "UTF-8",
            unicode.clone(),
            "A\0\u{e9}\u{20ac}\u{1f642}\nZ".as_bytes().to_vec(),
        ),
        (
            "ISO-8859-1",
            vec![0x41, 0, 0xe9, 0xa3, 0x0a, 0x5a],
            vec![0x41, 0, 0xe9, 0xa3, 0x0a, 0x5a],
        ),
        (
            "IBM037",
            vec![0x41, 0, 0xe9, 0xa3, 0x0a, 0x5a],
            vec![0xc1, 0, 0x51, 0xb1, 0x25, 0xe9],
        ),
        (
            "SHIFT_JIS",
            vec![0x41, 0, 0x3042, 0x6f22, 0x0a, 0x5a],
            vec![0x41, 0, 0x82, 0xa0, 0x8a, 0xbf, 0x0a, 0x5a],
        ),
        (
            "UTF-16LE",
            unicode.clone(),
            vec![
                0x41, 0, 0, 0, 0xe9, 0, 0xac, 0x20, 0x3d, 0xd8, 0x42, 0xde, 0x0a, 0, 0x5a, 0,
            ],
        ),
        (
            "UTF-16BE",
            unicode.clone(),
            vec![
                0, 0x41, 0, 0, 0, 0xe9, 0x20, 0xac, 0xd8, 0x3d, 0xde, 0x42, 0, 0x0a, 0, 0x5a,
            ],
        ),
        (
            "UTF-32LE",
            unicode.clone(),
            unicode
                .iter()
                .flat_map(|value: &u32| value.to_le_bytes())
                .collect(),
        ),
        (
            "UTF-32BE",
            unicode.clone(),
            unicode
                .iter()
                .flat_map(|value| value.to_be_bytes())
                .collect(),
        ),
        (
            "UCS-2LE",
            bmp.clone(),
            bmp.iter()
                .flat_map(|&value| (value as u16).to_le_bytes())
                .collect(),
        ),
        (
            "UCS-2BE",
            bmp.clone(),
            bmp.iter()
                .flat_map(|&value| (value as u16).to_be_bytes())
                .collect(),
        ),
    ];
    for (encoding, values, bytes) in cases {
        let read_path = mkfile(&format!("ccs_{}_{encoding}_read", api.name), &bytes);
        let read_mode = CString::new(format!("r,ccs={encoding}")).unwrap();
        ccs_locale(api, c"C");
        let stream = ccs_open(api, &read_path, &read_mode);
        // Orientation and codec must be bound by fopen itself, before the
        // first wide operation and before a subsequent locale change.
        // SAFETY: live stream from this engine, mode 0 queries orientation.
        assert!(
            unsafe { (api.orientation)(stream, 0) } > 0,
            "{} {encoding}",
            api.name
        );
        ccs_locale(api, c"C.UTF-8");
        ccs_read(api, stream, &values, encoding);
        ccs_close(api, stream);

        let write_path = mkfile(
            &format!("ccs_{}_{encoding}_write", api.name),
            b"old contents",
        );
        let write_mode = CString::new(format!("w,ccs={encoding}")).unwrap();
        ccs_locale(api, c"C.UTF-8");
        let stream = ccs_open(api, &write_path, &write_mode);
        // SAFETY: an explicit byte request cannot reverse a wide orientation.
        assert!(
            unsafe { (api.orientation)(stream, -1) } > 0,
            "{} {encoding}",
            api.name
        );
        ccs_locale(api, c"C");
        ccs_write(api, stream, &values, encoding);
        ccs_close(api, stream);
        assert_eq!(
            std::fs::read(&write_path).unwrap(),
            bytes,
            "{} {encoding} bytes",
            api.name
        );
        std::fs::remove_file(read_path).unwrap();
        std::fs::remove_file(write_path).unwrap();
    }
}

fn ccs_reopen_codecs(api: &CcsApi) {
    let first = mkfile(
        &format!("ccs_{}_reopen_first", api.name),
        "A\u{e9}".as_bytes(),
    );
    let second = mkfile(
        &format!("ccs_{}_reopen_second", api.name),
        &[0, 0xe9, 0, 0, 0, 0x5a],
    );
    let output = mkfile(&format!("ccs_{}_reopen_output", api.name), b"old contents");
    ccs_locale(api, c"C");
    let stream = ccs_open(api, &first, c"r,ccs=UTF-8");
    // SAFETY: all operations use the same live FILE and matching engine.
    unsafe {
        let fd = (api.fileno)(stream);
        assert!(fd >= 0);
        // Populate the input buffer/cache, leaving a non-ASCII character in
        // the old stream, so reopening also has to discard conversion state.
        assert_eq!((api.read)(stream), u32::from(b'A'));
        let path = CString::new(second.as_str()).unwrap();
        assert_eq!(
            (api.reopen)(path.as_ptr(), c"r,ccs=UTF-16BE".as_ptr(), stream),
            stream
        );
        assert_eq!((api.fileno)(stream), fd, "{} reopen fd", api.name);
        assert!((api.orientation)(stream, 0) > 0);
        ccs_locale(api, c"C.UTF-8");
        ccs_read(api, stream, &[0xe9, 0, 0x5a], "freopen UTF-16BE");

        let path = CString::new(output.as_str()).unwrap();
        assert_eq!(
            (api.reopen)(path.as_ptr(), c"w,ccs=ISO-8859-1".as_ptr(), stream),
            stream
        );
        assert_eq!((api.fileno)(stream), fd);
        assert!((api.orientation)(stream, 0) > 0);
        ccs_write(api, stream, &[0xe9, 0, 0xa3], "freopen Latin-1");
        assert_eq!(std::fs::read(&output).unwrap(), [0xe9, 0, 0xa3]);

        // Plain freopen resets both the prior orientation and the explicit
        // encoding. Its first wide operation now binds the active locale.
        assert_eq!((api.reopen)(path.as_ptr(), c"w".as_ptr(), stream), stream);
        assert_eq!((api.fileno)(stream), fd);
        assert_eq!((api.orientation)(stream, 0), 0);
        ccs_write(api, stream, &[0xe9], "freopen default UTF-8");
        assert_eq!(std::fs::read(&output).unwrap(), [0xc3, 0xa9]);

        // The GNU pathname=NULL branch must rebind the codec too.
        assert_eq!(
            (api.reopen)(std::ptr::null(), c"w,ccs=UTF-16LE".as_ptr(), stream),
            stream
        );
        assert_eq!((api.fileno)(stream), fd);
        assert!((api.orientation)(stream, 0) > 0);
        ccs_locale(api, c"C");
        ccs_write(api, stream, &[0xe9, 0, 0x5a], "freopen NULL UTF-16LE");
        assert_eq!(std::fs::read(&output).unwrap(), [0xe9, 0, 0, 0, 0x5a, 0]);
    }
    ccs_close(api, stream);
    for path in [first, second, output] {
        std::fs::remove_file(path).unwrap();
    }
}

fn ccs_mode_errors(api: &CcsApi) {
    for (index, mode) in [
        c"w,ccs=",
        c"w,ccs=NO-SUCH-ENCODING",
        c"w,ccs=UTF-8//IGNORE",
        c"w,ccs=UTF-8//TRANSLIT",
    ]
    .into_iter()
    .enumerate()
    {
        for existing in [false, true] {
            let path = format!(
                "/tmp/fl_wstdio_{}_ccs_{}_bad_{index}_{existing}.bin",
                std::process::id(),
                api.name
            );
            if existing {
                std::fs::write(&path, b"must be truncated").unwrap();
            }
            let cpath = CString::new(path.as_str()).unwrap();
            // GNU opens/creates/truncates before rejecting the codec. Capture
            // errno before making assertions or inspecting filesystem state.
            // SAFETY: valid strings and this engine's thread-local errno.
            let (stream, error) = unsafe {
                *(api.errno)() = libc::EDOM;
                let stream = (api.open)(cpath.as_ptr(), mode.as_ptr());
                (stream, *(api.errno)())
            };
            assert!(stream.is_null(), "{} accepted {mode:?}", api.name);
            assert_eq!(error, libc::EINVAL, "{} {mode:?}", api.name);
            assert_eq!(
                std::fs::read(&path).unwrap(),
                b"",
                "{} {mode:?} create/truncate",
                api.name
            );
            std::fs::remove_file(path).unwrap();
        }
    }

    let original = mkfile(&format!("ccs_{}_bad_reopen_source", api.name), b"source");
    let destination = mkfile(&format!("ccs_{}_bad_reopen_dest", api.name), b"destination");
    let stream = ccs_open(api, &original, c"r");
    let path = CString::new(destination.as_str()).unwrap();
    // SAFETY: reopening consumes the live FILE even when codec setup fails;
    // neither the FILE nor its descriptor is used after that failure.
    let (fd, result, error) = unsafe {
        let fd = (api.fileno)(stream);
        *(api.errno)() = libc::EDOM;
        let result = (api.reopen)(path.as_ptr(), c"w,ccs=NO-SUCH-ENCODING".as_ptr(), stream);
        (fd, result, *(api.errno)())
    };
    assert!(result.is_null(), "{} accepted invalid freopen", api.name);
    assert_eq!(error, libc::EINVAL, "{} freopen errno", api.name);
    assert_eq!(std::fs::read(&destination).unwrap(), b"");
    let closed = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap_err();
    assert_eq!(
        closed.kind(),
        std::io::ErrorKind::NotFound,
        "{} failed freopen must close the old fd",
        api.name
    );
    std::fs::remove_file(original).unwrap();
    std::fs::remove_file(destination).unwrap();

    // A comma ends the codec name; whitespace inside the value is normalized.
    for (index, mode) in [c"w,ccs=UTF-16LE,ignored", c"w,ccs= UTF-16LE "]
        .into_iter()
        .enumerate()
    {
        let path = mkfile(&format!("ccs_{}_syntax_{index}", api.name), b"");
        let stream = ccs_open(api, &path, mode);
        ccs_write(api, stream, &[0xe9], "ccs mode syntax");
        ccs_close(api, stream);
        assert_eq!(std::fs::read(&path).unwrap(), [0xe9, 0]);
        std::fs::remove_file(path).unwrap();
    }
    for (index, mode) in [c"w,CCS=UTF-8", c"w, ccs=UTF-8"].into_iter().enumerate() {
        let path = mkfile(&format!("ccs_{}_ignored_key_{index}", api.name), b"");
        let stream = ccs_open(api, &path, mode);
        // SAFETY: querying a live FILE; only the literal ',ccs=' is special.
        assert_eq!(
            unsafe { (api.orientation)(stream, 0) },
            0,
            "{} {mode:?}",
            api.name
        );
        ccs_close(api, stream);
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn wide_stdio_ccs_modes_match_glibc() {
    const NAME: &str = "wide_stdio_ccs_modes_match_glibc";
    const CHILD: &str = "FRANKENLIBC_WIDE_STDIO_CCS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // Process isolation keeps changes to both engines' LC_CTYPE away
        // from other integration tests and fixes the policy before startup.
        for mode in ["strict", "hardened"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture"])
                .env(CHILD, "1")
                .env("FRANKENLIBC_MODE", mode)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{mode}: {:?}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        }
        return;
    }
    // SAFETY: a watchdog affects only this isolated test child.
    unsafe { libc::alarm(30) };
    for api in [ccs_host_api(), ccs_native_api()] {
        ccs_codec_roundtrips(&api);
        ccs_reopen_codecs(&api);
        ccs_mode_errors(&api);
    }
    unsafe { libc::alarm(0) };
}
