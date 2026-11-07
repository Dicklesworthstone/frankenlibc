#![cfg(target_os = "linux")]
#![feature(c_variadic)]
#![allow(unsafe_code)] // real variadic and va_list entrypoints, independent host oracle
//! Differential conformance for `swscanf` vs glibc, focused on the wide-specific
//! conversions: `%ls`/`%S` (wide-string) and `%lc`/`%C` (wide-char) write into a
//! `wchar_t*`, not a `char*`; plus numeric/scanset parsing from wide input and
//! the matched-item count.

use std::ffi::c_int;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

use frankenlibc_abi::wchar_abi as fl;

type Wc = libc::wchar_t;

type SwscanfFn = unsafe extern "C" fn(*const Wc, *const Wc, ...) -> c_int;

fn host_swscanf() -> SwscanfFn {
    static HOST: std::sync::OnceLock<SwscanfFn> = std::sync::OnceLock::new();
    *HOST.get_or_init(|| unsafe { dlsym_oracle::host_fn(c"swscanf", fl::swscanf as *const ()) })
}

fn w(s: &str) -> Vec<Wc> {
    let mut v: Vec<Wc> = s.chars().map(|c| c as u32 as Wc).collect();
    v.push(0);
    v
}

fn wbuf_to_string(buf: &[Wc]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    buf[..end]
        .iter()
        .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
        .collect()
}

#[test]
fn diff_swscanf_int() {
    let inp = w("42 -7 0x1F");
    let fmt = w("%d %d %x");
    let (mut a, mut b, mut c) = (0i32, 0i32, 0i32);
    let (mut a2, mut b2, mut c2) = (0i32, 0i32, 0i32);
    let n_fl = unsafe { fl::swscanf(inp.as_ptr(), fmt.as_ptr(), &mut a, &mut b, &mut c) };
    let n_lc = unsafe { host_swscanf()(inp.as_ptr(), fmt.as_ptr(), &mut a2, &mut b2, &mut c2) };
    assert_eq!(
        (n_fl, a, b, c),
        (n_lc, a2, b2, c2),
        "swscanf int mismatch vs glibc"
    );
}

#[test]
fn diff_swscanf_wide_string() {
    // (input, format) producing one %ls token.
    let cases: &[(&str, &str)] = &[
        ("hello world", "%ls"),
        ("  spaced", "%ls"),
        ("héllo rest", "%ls"), // multibyte wide token (whole token, no width)
        ("日本語 x", "%ls"),
        ("abcdef", "%3ls"),   // ASCII width caps at 3 wide chars
        ("token rest", "%S"), // SVID alias for %ls
        ("café x", "%S"),     // multibyte whole token via %S
                              // NOTE: multibyte %Nls width (wide-char-aware) still tracked in bd-2g7oyh.146.
    ];
    let mut fails = Vec::new();
    for (input, fmt) in cases {
        let inp = w(input);
        let f = w(fmt);
        let mut fb = vec![0 as Wc; 64];
        let mut lb = vec![0 as Wc; 64];
        let n_fl = unsafe { fl::swscanf(inp.as_ptr(), f.as_ptr(), fb.as_mut_ptr()) };
        let n_lc = unsafe { host_swscanf()(inp.as_ptr(), f.as_ptr(), lb.as_mut_ptr()) };
        let sf = wbuf_to_string(&fb);
        let sl = wbuf_to_string(&lb);
        if n_fl != n_lc || (n_fl == 1 && sf != sl) {
            fails.push(format!(
                "  input={input:?} fmt={fmt:?}: fl=(n={n_fl}, {sf:?}) glibc=(n={n_lc}, {sl:?})"
            ));
        }
    }
    assert!(
        fails.is_empty(),
        "swscanf %ls divergences:\n{}",
        fails.join("\n")
    );
}

#[test]
fn diff_swscanf_wide_char() {
    let cases: &[(&str, &str)] = &[
        ("Axyz", "%lc"),
        ("Z 9", "%lc"),
        ("Qrs", "%C"),
        ("éabc", "%lc"), // multibyte wide char -> U+00E9
        ("中a", "%C"),   // -> U+4E2D
        ("😀x", "%lc"),  // supplementary plane
    ];
    let mut fails = Vec::new();
    for (input, fmt) in cases {
        let inp = w(input);
        let f = w(fmt);
        let mut fc: Wc = 0;
        let mut lc: Wc = 0;
        let n_fl = unsafe { fl::swscanf(inp.as_ptr(), f.as_ptr(), &mut fc) };
        let n_lc = unsafe { host_swscanf()(inp.as_ptr(), f.as_ptr(), &mut lc) };
        if n_fl != n_lc || (n_fl == 1 && fc != lc) {
            fails.push(format!(
                "  input={input:?} fmt={fmt:?}: fl=(n={n_fl}, {:#x}) glibc=(n={n_lc}, {:#x})",
                fc as u32, lc as u32
            ));
        }
    }
    assert!(
        fails.is_empty(),
        "swscanf %lc divergences:\n{}",
        fails.join("\n")
    );
}

mod locale_scanning {
    use super::{SwscanfFn, Wc, dlsym_oracle::host_fn, fl, host_swscanf, w};
    use frankenlibc_abi::{
        errno_abi, glibc_internal_abi, isoc_abi, locale_abi, malloc_abi, stdio_abi,
    };
    use std::ffi::{CStr, c_char, c_int, c_void};
    use std::sync::OnceLock;

    type ErrnoFn = unsafe extern "C" fn() -> *mut c_int;
    type FreeFn = unsafe extern "C" fn(*mut c_void);
    type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *const c_char;
    const SENTINEL: c_int = -771;

    struct Host {
        errno: ErrnoFn,
        free: FreeFn,
        setlocale: SetlocaleFn,
    }

    fn host() -> &'static Host {
        static HOST: OnceLock<Host> = OnceLock::new();
        HOST.get_or_init(|| unsafe {
            Host {
                errno: host_fn(c"__errno_location", errno_abi::__errno_location as *const ()),
                free: host_fn(c"free", malloc_abi::free as *const ()),
                setlocale: host_fn(c"setlocale", locale_abi::setlocale as *const ()),
            }
        })
    }

    // Each child owns both process-global locales and its runtime mode. A
    // missing named locale is a failed prerequisite, never a skipped matrix.
    fn isolated(test: &str) -> bool {
        const CHILD: &str = "FRANKENLIBC_WIDE_SCANF_CHILD";
        if std::env::var(CHILD).as_deref() == Ok(test) {
            return true;
        }
        for mode in ["strict", "hardened"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!("locale_scanning::{test}"),
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, test)
                .env("FRANKENLIBC_MODE", mode)
                .env("LC_ALL", "C")
                .env("LANG", "C")
                .env_remove("LOCPATH")
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
                "the child filter did not execute {test}/{mode}"
            );
        }
        false
    }

    fn select(name: &CStr) {
        unsafe {
            assert!(
                !(host().setlocale)(libc::LC_CTYPE, name.as_ptr()).is_null(),
                "host locale {name:?} unavailable; install locales-all"
            );
            assert!(
                !locale_abi::setlocale(libc::LC_CTYPE, name.as_ptr()).is_null(),
                "native locale {name:?} unavailable"
            );
        }
    }

    unsafe extern "C" fn call_vswscanf(
        input: *const Wc,
        format: *const Wc,
        mut args: ...
    ) -> c_int {
        unsafe { fl::vswscanf(input, format, std::ptr::addr_of_mut!(args).cast()) }
    }

    unsafe extern "C" fn call_c99_vswscanf(
        input: *const Wc,
        format: *const Wc,
        mut args: ...
    ) -> c_int {
        unsafe {
            isoc_abi::__isoc99_vswscanf(
                input.cast(),
                format.cast(),
                std::ptr::addr_of_mut!(args).cast(),
            )
        }
    }

    unsafe extern "C" fn call_c23_vswscanf(
        input: *const Wc,
        format: *const Wc,
        mut args: ...
    ) -> c_int {
        unsafe {
            isoc_abi::__isoc23_vswscanf(
                input.cast(),
                format.cast(),
                std::ptr::addr_of_mut!(args).cast(),
            )
        }
    }

    #[derive(Clone, Copy)]
    struct Engine {
        name: &'static str,
        scan: SwscanfFn,
        errno: ErrnoFn,
        free: FreeFn,
    }

    fn engines() -> [Engine; 7] {
        let native = |name, scan| Engine {
            name,
            scan,
            errno: errno_abi::__errno_location,
            free: malloc_abi::free,
        };
        [
            Engine {
                name: "host",
                scan: host_swscanf(),
                errno: host().errno,
                free: host().free,
            },
            native("swscanf", fl::swscanf as SwscanfFn),
            native("__isoc99_swscanf", isoc_abi::__isoc99_swscanf as SwscanfFn),
            native("__isoc23_swscanf", isoc_abi::__isoc23_swscanf as SwscanfFn),
            native("vswscanf", call_vswscanf as SwscanfFn),
            native("__isoc99_vswscanf", call_c99_vswscanf as SwscanfFn),
            native("__isoc23_vswscanf", call_c23_vswscanf as SwscanfFn),
        ]
    }

    type OpenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
    type StreamFn = unsafe extern "C-unwind" fn(*mut c_void) -> c_int;
    type SeekFn = unsafe extern "C-unwind" fn(*mut c_void, libc::c_long, c_int) -> c_int;
    type TellFn = unsafe extern "C-unwind" fn(*mut c_void) -> libc::c_long;
    type FwideFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
    type WideReadFn = unsafe extern "C-unwind" fn(*mut c_void) -> u32;
    type WideWriteFn = unsafe extern "C-unwind" fn(u32, *mut c_void) -> u32;
    type WideUngetFn = unsafe extern "C" fn(u32, *mut c_void) -> u32;
    type WideGetsFn = unsafe extern "C-unwind" fn(*mut Wc, c_int, *mut c_void) -> *mut Wc;
    type WidePutsFn = unsafe extern "C-unwind" fn(*const Wc, *mut c_void) -> c_int;
    type WctombFn = unsafe extern "C" fn(*mut u8, u32) -> c_int;

    #[derive(Clone, Copy)]
    struct WideIoEngine {
        name: &'static str,
        errno: ErrnoFn,
        open: OpenFn,
        close: StreamFn,
        orient: FwideFn,
        get: WideReadFn,
        unget: WideUngetFn,
        gets: WideGetsFn,
        put: WideWriteFn,
        puts: WidePutsFn,
        flush: StreamFn,
        seek: SeekFn,
        tell: TellFn,
        eof: StreamFn,
        error: StreamFn,
        convert: WctombFn,
    }

    fn wide_io_engines() -> [WideIoEngine; 2] {
        static HOST: OnceLock<WideIoEngine> = OnceLock::new();
        let host = *HOST.get_or_init(|| unsafe {
            WideIoEngine {
                name: "host",
                errno: host().errno,
                open: host_fn(c"fopen", stdio_abi::fopen as *const ()),
                close: host_fn(c"fclose", stdio_abi::fclose as *const ()),
                orient: host_fn(c"fwide", glibc_internal_abi::fwide as *const ()),
                get: host_fn(c"fgetwc", fl::fgetwc as *const ()),
                unget: host_fn(c"ungetwc", fl::ungetwc as *const ()),
                gets: host_fn(c"fgetws", fl::fgetws as *const ()),
                put: host_fn(c"fputwc", fl::fputwc as *const ()),
                puts: host_fn(c"fputws", fl::fputws as *const ()),
                flush: host_fn(c"fflush", stdio_abi::fflush as *const ()),
                seek: host_fn(c"fseek", stdio_abi::fseek as *const ()),
                tell: host_fn(c"ftell", stdio_abi::ftell as *const ()),
                eof: host_fn(c"feof", stdio_abi::feof as *const ()),
                error: host_fn(c"ferror", stdio_abi::ferror as *const ()),
                convert: host_fn(c"wctomb", fl::wctomb as *const ()),
            }
        });
        [
            host,
            WideIoEngine {
                name: "native",
                errno: errno_abi::__errno_location,
                open: stdio_abi::fopen,
                close: stdio_abi::fclose,
                orient: glibc_internal_abi::fwide,
                get: fl::fgetwc,
                unget: fl::ungetwc,
                gets: fl::fgetws,
                put: fl::fputwc,
                puts: fl::fputws,
                flush: stdio_abi::fflush,
                seek: stdio_abi::fseek,
                tell: stdio_abi::ftell,
                eof: stdio_abi::feof,
                error: stdio_abi::ferror,
                convert: fl::wctomb,
            },
        ]
    }

    fn wide_stream_path(label: &str, bytes: &[u8]) -> (std::path::PathBuf, std::ffi::CString) {
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "frankenlibc-wide-codec-{}-{stamp}-{}-{label}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        drop(file);
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // Retain the unique file as failure evidence; no shared path or cleanup
        // can remove another concurrent child's input or output.
        (path, c_path)
    }

    fn assert_current_multibyte_codec(engine: WideIoEngine, locale: &CStr) {
        let mut bytes = [0xa5u8; 8];
        let (rc, error) = unsafe {
            *(engine.errno)() = 0;
            let rc = (engine.convert)(bytes.as_mut_ptr(), 0xe9);
            (rc, *(engine.errno)())
        };
        match locale.to_bytes() {
            b"C" => assert_eq!(
                (rc, error),
                (-1, libc::EILSEQ),
                "{} current C codec",
                engine.name
            ),
            b"fr_FR" => {
                assert_eq!((rc, error), (1, 0), "{} current Latin1", engine.name);
                assert_eq!(bytes[0], 0xe9);
                assert!(bytes[1..].iter().all(|&byte| byte == 0xa5));
            }
            b"C.UTF-8" => {
                assert_eq!((rc, error), (2, 0), "{} current UTF8", engine.name);
                assert_eq!(&bytes[..2], b"\xc3\xa9");
                assert!(bytes[2..].iter().all(|&byte| byte == 0xa5));
            }
            _ => unreachable!("the binding matrix names its codecs explicitly"),
        }
    }

    #[test]
    fn wide_stream_codec_survives_locale_changes() {
        if !isolated("wide_stream_codec_survives_locale_changes") {
            return;
        }
        for (bound, active, input, encoded) in [
            (c"C.UTF-8", c"fr_FR", "éAé\n".as_bytes(), b"\xc3\xa9".as_slice()),
            (c"C.UTF-8", c"C", "éAé\n".as_bytes(), b"\xc3\xa9".as_slice()),
            (c"fr_FR", c"C.UTF-8", b"\xe9A\xe9\n".as_slice(), b"\xe9".as_slice()),
        ] {
            for engine in wide_io_engines() {
                select(bound);
                let (_, path) = wide_stream_path(engine.name, input);
                let stream = unsafe { (engine.open)(path.as_ptr(), c"r".as_ptr()) };
                assert!(!stream.is_null(), "{} input FILE", engine.name);
                assert!(unsafe { (engine.orient)(stream, 1) } > 0);
                select(active);
                assert_current_multibyte_codec(engine, active);

                unsafe {
                    assert_eq!((engine.get)(stream), 0xe9, "{} bound read", engine.name);
                    assert_eq!((engine.tell)(stream), encoded.len() as libc::c_long);
                    assert_eq!((engine.unget)(0xe9, stream), 0xe9);
                    assert_eq!((engine.get)(stream), 0xe9, "{} bound pushback", engine.name);
                    assert_eq!((engine.tell)(stream), encoded.len() as libc::c_long);

                    let mut line = [SENTINEL as Wc; 8];
                    assert_eq!(
                        (engine.gets)(line.as_mut_ptr(), line.len() as c_int, stream),
                        line.as_mut_ptr(),
                        "{} bound line",
                        engine.name
                    );
                    assert_eq!(&line[..4], &[0x41, 0xe9, 0x0a, 0]);
                    assert!(line[4..].iter().all(|&wc| wc == SENTINEL));
                    assert_eq!((engine.tell)(stream), input.len() as libc::c_long);
                    assert_eq!((engine.error)(stream), 0);

                    *(engine.errno)() = 23;
                    assert_eq!((engine.get)(stream), u32::MAX);
                    assert_ne!((engine.eof)(stream), 0);
                    assert_eq!((engine.error)(stream), 0);
                    assert_eq!(*(engine.errno)(), 23);
                    assert_current_multibyte_codec(engine, active);

                    assert_eq!((engine.seek)(stream, 0, libc::SEEK_SET), 0);
                    assert_eq!((engine.eof)(stream), 0);
                    assert!((engine.orient)(stream, 0) > 0);
                    assert_eq!((engine.get)(stream), 0xe9, "{} binding after seek", engine.name);
                    assert_eq!((engine.close)(stream), 0);
                }

                select(bound);
                let (output_path, path) = wide_stream_path(engine.name, b"");
                let stream = unsafe { (engine.open)(path.as_ptr(), c"r+".as_ptr()) };
                assert!(!stream.is_null(), "{} output FILE", engine.name);
                assert!(unsafe { (engine.orient)(stream, 1) } > 0);
                select(active);
                // At least sixteen wide characters exercise the bulk fputws
                // conversion as well as the single-character output entrypoint.
                let text = w("abcdefghijklmnopéééé\n");
                unsafe {
                    assert_eq!((engine.put)(0xe9, stream), 0xe9);
                    assert!((engine.puts)(text.as_ptr(), stream) >= 0);
                    assert_eq!((engine.flush)(stream), 0);
                    assert_eq!((engine.error)(stream), 0);
                }
                let mut expected = encoded.to_vec();
                expected.extend_from_slice(b"abcdefghijklmnop");
                for _ in 0..4 {
                    expected.extend_from_slice(encoded);
                }
                expected.push(b'\n');
                assert_eq!(
                    std::fs::read(&output_path).unwrap(),
                    expected,
                    "{bound:?} -> {active:?}/{} encoded output",
                    engine.name
                );
                assert_current_multibyte_codec(engine, active);
                unsafe {
                    assert_eq!((engine.seek)(stream, 0, libc::SEEK_SET), 0);
                    assert_eq!((engine.get)(stream), 0xe9, "{} update FILE", engine.name);
                    assert_eq!((engine.close)(stream), 0);
                }
            }
        }
    }

    #[test]
    fn wide_stream_invalid_encoding_is_not_consumed() {
        if !isolated("wide_stream_invalid_encoding_is_not_consumed") {
            return;
        }
        for active in [c"C.UTF-8", c"fr_FR", c"C"] {
            for (input, prefix) in [
                (b"\xffZ".as_slice(), 0),
                (b"\xc3XZ".as_slice(), 0),
                (b"A\xffZ".as_slice(), 1),
                (b"A\xc3XZ".as_slice(), 1),
            ] {
                for engine in wide_io_engines() {
                    select(c"C.UTF-8");
                    let (_, path) = wide_stream_path(engine.name, input);
                    let stream = unsafe { (engine.open)(path.as_ptr(), c"r".as_ptr()) };
                    assert!(!stream.is_null(), "{} invalid-input FILE", engine.name);
                    assert!(unsafe { (engine.orient)(stream, 1) } > 0);
                    select(active);
                    unsafe {
                        if prefix != 0 {
                            assert_eq!((engine.get)(stream), u32::from(b'A'));
                        }
                        // Complete invalid sequences stay at the same logical
                        // position and fail repeatedly, independent of LC_CTYPE
                        // changes after orientation. Truncated EOF is separate.
                        for attempt in 0..3 {
                            *(engine.errno)() = 0;
                            let wc = (engine.get)(stream);
                            let error = *(engine.errno)();
                            assert_eq!(
                                (wc, error),
                                (u32::MAX, libc::EILSEQ),
                                "{active:?}/{} attempt {attempt}",
                                engine.name
                            );
                            assert_ne!((engine.error)(stream), 0);
                            assert_eq!((engine.eof)(stream), 0);
                            assert_eq!((engine.tell)(stream), prefix as libc::c_long);
                        }
                        // Seeking clears EOF but retains the earlier error.
                        // A new clean-EOF line must not become a false failure
                        // merely because that error indicator is still set.
                        assert_eq!(
                            (engine.seek)(stream, (input.len() - 1) as libc::c_long, libc::SEEK_SET),
                            0
                        );
                        assert_ne!((engine.error)(stream), 0);
                        let mut recovered = [SENTINEL as Wc; 4];
                        assert_eq!(
                            (engine.gets)(recovered.as_mut_ptr(), 4, stream),
                            recovered.as_mut_ptr(),
                            "{} clean EOF after an earlier error",
                            engine.name
                        );
                        assert_eq!(recovered, [Wc::from(b'Z'), 0, SENTINEL, SENTINEL]);
                        assert_ne!((engine.eof)(stream), 0);
                        assert_ne!((engine.error)(stream), 0);
                        assert_eq!((engine.close)(stream), 0);
                    }
                }
            }
        }

        // Read/encoding errors return NULL even after a valid prefix. The
        // supplied array is then indeterminate (C23 7.31.3.2p3), so compare
        // result/status/position and only guards outside its capacity.
        // Nonempty clean EOF must still return a terminated prefix.
        for active in [c"C.UTF-8", c"fr_FR", c"C"] {
            for (input, read_error) in [
                (b"A\xffZ".as_slice(), true),
                (b"A\xc3XZ".as_slice(), true),
                (b"A".as_slice(), false),
            ] {
                let mut oracle = None;
                for engine in wide_io_engines() {
                    select(c"C.UTF-8");
                    let (_, path) = wide_stream_path(engine.name, input);
                    let stream = unsafe { (engine.open)(path.as_ptr(), c"r".as_ptr()) };
                    assert!(!stream.is_null(), "{} fgetws FILE", engine.name);
                    assert!(unsafe { (engine.orient)(stream, 1) } > 0);
                    select(active);
                    let mut line = [SENTINEL as Wc; 10];
                    let observed = unsafe {
                        *(engine.errno)() = 0;
                        let result = (engine.gets)(line.as_mut_ptr(), 8, stream);
                        let error = *(engine.errno)();
                        if !result.is_null() {
                            assert_eq!(result, line.as_mut_ptr());
                        }
                        let observed = (
                            result.is_null(),
                            error,
                            (engine.error)(stream) != 0,
                            (engine.eof)(stream) != 0,
                            (engine.tell)(stream),
                        );
                        assert_eq!((engine.close)(stream), 0);
                        observed
                    };
                    assert_eq!(observed.0, read_error, "{} fgetws result", engine.name);
                    assert_eq!(observed.1, if read_error { libc::EILSEQ } else { 0 });
                    assert_eq!((observed.2, observed.3), (read_error, !read_error));
                    assert!(line[8..].iter().all(|&wc| wc == SENTINEL));
                    if !read_error {
                        assert_eq!(observed.4, 1);
                        assert_eq!(&line[..2], &[Wc::from(b'A'), 0]);
                        assert!(line[2..].iter().all(|&wc| wc == SENTINEL));
                    }
                    if let Some(expected) = oracle.as_ref() {
                        assert_eq!(
                            &observed,
                            expected,
                            "{active:?}/{} fgetws result/status/position",
                            engine.name
                        );
                    } else {
                        oracle = Some(observed);
                    }
                }
            }
        }
    }

    type FwprintfFn = unsafe extern "C-unwind" fn(*mut c_void, *const Wc, ...) -> c_int;
    type VfwprintfFn =
        unsafe extern "C-unwind" fn(*mut c_void, *const Wc, *mut c_void) -> c_int;

    fn host_fwprintf() -> FwprintfFn {
        static HOST: OnceLock<FwprintfFn> = OnceLock::new();
        *HOST.get_or_init(|| unsafe { host_fn(c"fwprintf", fl::fwprintf as *const ()) })
    }

    fn host_vfwprintf() -> VfwprintfFn {
        static HOST: OnceLock<VfwprintfFn> = OnceLock::new();
        *HOST.get_or_init(|| unsafe { host_fn(c"vfwprintf", fl::vfwprintf as *const ()) })
    }

    unsafe extern "C-unwind" fn call_vfwprintf(
        stream: *mut c_void,
        format: *const Wc,
        mut args: ...
    ) -> c_int {
        unsafe { fl::vfwprintf(stream, format, std::ptr::addr_of_mut!(args).cast()) }
    }

    unsafe extern "C-unwind" fn call_host_vfwprintf(
        stream: *mut c_void,
        format: *const Wc,
        mut args: ...
    ) -> c_int {
        unsafe { host_vfwprintf()(stream, format, std::ptr::addr_of_mut!(args).cast()) }
    }

    #[test]
    fn formatted_wide_streams_keep_bound_codec() {
        if !isolated("formatted_wide_streams_keep_bound_codec") {
            return;
        }
        const PREFIX_LEN: usize = 2047;
        let prefix = w(&"é".repeat(PREFIX_LEN));
        let suffix = w("éX");
        let format = w("%ls%lc%ls%s");
        for (bound, active, encoded, narrow) in [
            (
                c"C.UTF-8",
                c"fr_FR",
                b"\xc3\xa9".as_slice(),
                b"\xe9".as_slice(),
            ),
            (
                c"C.UTF-8",
                c"C",
                b"\xc3\xa9".as_slice(),
                b"A".as_slice(),
            ),
            (
                c"fr_FR",
                c"C.UTF-8",
                b"\xe9".as_slice(),
                b"\xc3\xa9".as_slice(),
            ),
        ] {
            let narrow = std::ffi::CString::new(narrow).unwrap();
            for engine in wide_io_engines() {
                let entries: [(&str, FwprintfFn); 2] = if engine.name == "host" {
                    [("fwprintf", host_fwprintf()), ("vfwprintf", call_host_vfwprintf)]
                } else {
                    [("fwprintf", fl::fwprintf), ("vfwprintf", call_vfwprintf)]
                };
                for (entry, print) in entries {
                    select(bound);
                    let (output_path, path) = wide_stream_path(engine.name, b"");
                    let stream = unsafe { (engine.open)(path.as_ptr(), c"r+".as_ptr()) };
                    assert!(!stream.is_null(), "{} {entry} FILE", engine.name);
                    assert!(unsafe { (engine.orient)(stream, 1) } > 0);
                    select(active);
                    let rc = unsafe {
                        print(
                            stream,
                            format.as_ptr(),
                            prefix.as_ptr(),
                            0u32,
                            suffix.as_ptr(),
                            narrow.as_ptr(),
                        )
                    };
                    // Count wide characters, including the embedded NUL, not
                    // external bytes or the internal UTF8 transport length.
                    assert_eq!(
                        rc,
                        (PREFIX_LEN + 4) as c_int,
                        "{bound:?} -> {active:?}/{} {entry} wide count",
                        engine.name
                    );
                    unsafe {
                        assert_eq!((engine.flush)(stream), 0);
                        assert_eq!((engine.error)(stream), 0);
                    }
                    let mut expected = encoded.repeat(PREFIX_LEN);
                    expected.push(0);
                    expected.extend_from_slice(encoded);
                    expected.push(b'X');
                    if active == c"C" {
                        expected.push(b'A');
                    } else {
                        expected.extend_from_slice(encoded);
                    }
                    // The wide argument exceeds 1024 characters. In Latin1,
                    // NUL ends the second 1024-byte chunk; both following wide
                    // characters and the active-locale %s must survive it.
                    assert_eq!(
                        std::fs::read(&output_path).unwrap(),
                        expected,
                        "{bound:?} -> {active:?}/{} {entry} output bytes",
                        engine.name
                    );
                    assert_current_multibyte_codec(engine, active);
                    unsafe { assert_eq!((engine.close)(stream), 0) };
                }
            }
        }
    }

    #[test]
    fn narrow_destinations_follow_locale_and_width() {
        if !isolated("narrow_destinations_follow_locale_and_width") {
            return;
        }
        for (locale, input, bytes, max_width) in [
            (c"C", "AAX", b"AA".as_slice(), 1),
            (c"C.UTF-8", "ééX", "éé".as_bytes(), 6),
            (c"fr_FR", "ééX", b"\xe9\xe9".as_slice(), 1),
        ] {
            select(locale);
            for (format, terminated) in [
                ("%2s%n", true),
                ("%2c%n", false),
                ("%2[^X]%n", true),
            ] {
                for engine in engines() {
                    let input = w(input);
                    let format = w(format);
                    let mut out = [0xa5u8; 32];
                    let mut n = SENTINEL;
                    let (rc, error) = unsafe {
                        *(engine.errno)() = 0;
                        let rc = (engine.scan)(
                            input.as_ptr(),
                            format.as_ptr(),
                            out.as_mut_ptr(),
                            &mut n,
                        );
                        (rc, *(engine.errno)())
                    };
                    assert_eq!((rc, n, error), (1, 2, 0), "{locale:?}/{}", engine.name);
                    assert_eq!(&out[..bytes.len()], bytes, "{locale:?}/{}", engine.name);
                    if terminated {
                        assert_eq!(out[bytes.len()], 0, "{} terminator", engine.name);
                    }
                    // Host glibc 2.41 writes an extra NUL after %s/%[. Compare
                    // the defined string above; independently enforce native
                    // width*MB_CUR_MAX plus one terminator, with a canary.
                    if engine.name != "host" {
                        let capacity = 2 * max_width + usize::from(terminated);
                        assert!(
                            out[capacity..].iter().all(|&b| b == 0xa5),
                            "{} capacity",
                            engine.name
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn wide_destinations_scansets_and_counts() {
        if !isolated("wide_destinations_scansets_and_counts") {
            return;
        }
        for locale in [c"C", c"C.UTF-8", c"fr_FR"] {
            select(locale);
            for (input, format, expected, count, terminated) in [
                ("é€X", "%2ls%n", "é€", 2, true),
                ("é€X", "%2lc%n", "é€", 2, false),
                ("é€X", "%2l[é€]%n", "é€", 2, true),
                ("éêX", "%2l[é-ê]%n", "éê", 2, true),
                ("é€X", "é%lc%n", "€", 2, false),
                ("😀éX", "%2ls%n", "😀é", 2, true),
            ] {
                let input = w(input);
                let format = w(format);
                let expected = w(expected);
                let len = expected.len() - 1;
                for engine in engines() {
                    let mut out = [0x1234_5678 as Wc; 8];
                    let mut n = SENTINEL;
                    let rc = unsafe {
                        (engine.scan)(input.as_ptr(), format.as_ptr(), out.as_mut_ptr(), &mut n)
                    };
                    assert_eq!((rc, n), (1, count), "{locale:?}/{}", engine.name);
                    assert_eq!(
                        &out[..len],
                        &expected[..len],
                        "{} wide output",
                        engine.name
                    );
                    if terminated {
                        assert_eq!(out[len], 0);
                    }
                    assert!(
                        out[len + usize::from(terminated)..]
                            .iter()
                            .all(|&wc| wc == 0x1234_5678)
                    );
                }
            }
            // Different scalars with a shared UTF-8 prefix must not partially
            // match a literal or make a later %n count internal bytes.
            for engine in engines() {
                let mut n = SENTINEL;
                let rc = unsafe {
                    (engine.scan)(w("êX").as_ptr(), w("é%n").as_ptr(), &mut n)
                };
                assert_eq!(
                    (rc, n),
                    (0, SENTINEL),
                    "{} scalar literal",
                    engine.name
                );
            }
        }
    }

    #[test]
    fn encoding_failure_stops_later_assignments() {
        if !isolated("encoding_failure_stops_later_assignments") {
            return;
        }
        for (locale, token, prefix) in [(c"C", "AéX", b'A'), (c"fr_FR", "é€X", 0xe9)] {
            select(locale);
            for (conversion, failure) in [("3s", 0), ("3c", libc::EOF), ("3[^ ]", 0)] {
                for prior in [false, true] {
                    let input = w(&format!(
                        "{}{token} 9",
                        if prior { "7 " } else { "" }
                    ));
                    let format = w(&format!(
                        "{}%{conversion}%n%d",
                        if prior { "%d " } else { "" }
                    ));
                    for engine in engines() {
                        let mut out = [0xa5u8; 24];
                        let (mut first, mut n, mut last) = (SENTINEL, SENTINEL, SENTINEL);
                        let (rc, error) = unsafe {
                            *(engine.errno)() = 0;
                            let rc = if prior {
                                (engine.scan)(
                                    input.as_ptr(),
                                    format.as_ptr(),
                                    &mut first,
                                    out.as_mut_ptr(),
                                    &mut n,
                                    &mut last,
                                )
                            } else {
                                (engine.scan)(
                                    input.as_ptr(),
                                    format.as_ptr(),
                                    out.as_mut_ptr(),
                                    &mut n,
                                    &mut last,
                                )
                            };
                            (rc, *(engine.errno)())
                        };
                        assert_eq!(
                            rc,
                            if prior { 1 } else { failure },
                            "{} {conversion}",
                            engine.name
                        );
                        assert_eq!(error, libc::EILSEQ, "{} {conversion}", engine.name);
                        assert_eq!(first, if prior { 7 } else { SENTINEL });
                        assert_eq!(
                            (n, last),
                            (SENTINEL, SENTINEL),
                            "{} failure boundary",
                            engine.name
                        );
                        assert_eq!(out[0], prefix, "{} partial output", engine.name);
                        assert!(
                            out[1..].iter().all(|&b| b == 0xa5),
                            "{} untouched suffix",
                            engine.name
                        );
                    }
                }
            }
            // Suppressed text conversions never attempt destination encoding.
            for engine in engines() {
                let (mut value, mut n) = (SENTINEL, SENTINEL);
                let rc = unsafe {
                    (engine.scan)(
                        w("é€X 9").as_ptr(),
                        w("%*3s%d%n").as_ptr(),
                        &mut value,
                        &mut n,
                    )
                };
                assert_eq!(
                    (rc, value, n),
                    (1, 9, 5),
                    "{} suppression",
                    engine.name
                );
            }
        }
    }

    #[test]
    fn positional_and_allocated_destinations() {
        if !isolated("positional_and_allocated_destinations") {
            return;
        }
        select(c"fr_FR");
        for engine in engines() {
            let (mut number, mut n) = (SENTINEL, SENTINEL);
            let mut narrow: *mut c_char = std::ptr::null_mut();
            let rc = unsafe {
                (engine.scan)(
                    w("éé 17").as_ptr(),
                    w("%2$ms %1$d%3$n").as_ptr(),
                    &mut number,
                    &mut narrow,
                    &mut n,
                )
            };
            assert_eq!(
                (rc, number, n),
                (2, 17, 5),
                "{} positional narrow",
                engine.name
            );
            assert!(!narrow.is_null());
            unsafe {
                assert_eq!(CStr::from_ptr(narrow).to_bytes(), b"\xe9\xe9");
                (engine.free)(narrow.cast());
            }

            let mut wide: *mut Wc = std::ptr::null_mut();
            let rc = unsafe {
                (engine.scan)(
                    w("é€ 17").as_ptr(),
                    w("%2$mls %1$d%3$n").as_ptr(),
                    &mut number,
                    &mut wide,
                    &mut n,
                )
            };
            assert_eq!(
                (rc, number, n),
                (2, 17, 5),
                "{} positional wide",
                engine.name
            );
            assert!(!wide.is_null());
            unsafe {
                assert_eq!(std::slice::from_raw_parts(wide, 3), &[0xe9, 0x20ac, 0]);
                (engine.free)(wide.cast());
            }

            // Reusing an indexed destination must not advance a second,
            // unrelated va_list cursor. %n does not increase the match count.
            let rc = unsafe {
                (engine.scan)(
                    w("7 8").as_ptr(),
                    w("%1$d %1$d%2$n").as_ptr(),
                    &mut number,
                    &mut n,
                )
            };
            assert_eq!(
                (rc, number, n),
                (2, 8, 3),
                "{} repeated index",
                engine.name
            );

            // Index seven crosses the register/stack boundary and the
            // inline pointer-cache capacity without assigning skipped slots.
            let mut indexed = [SENTINEL; 7];
            let args = indexed.as_mut_ptr();
            let rc = unsafe {
                (engine.scan)(
                    w("7 8").as_ptr(),
                    w("%7$d %6$d%1$n").as_ptr(),
                    args,
                    args.add(1),
                    args.add(2),
                    args.add(3),
                    args.add(4),
                    args.add(5),
                    args.add(6),
                )
            };
            assert_eq!(rc, 2, "{} stack arguments", engine.name);
            assert_eq!(
                indexed,
                [3, SENTINEL, SENTINEL, SENTINEL, SENTINEL, 8, 7],
                "{} skipped argument destinations",
                engine.name
            );

            let mut pointer = std::ptr::without_provenance_mut::<c_char>(1);
            n = SENTINEL;
            let rc = unsafe {
                (engine.scan)(
                    w("").as_ptr(),
                    w("%n%mc").as_ptr(),
                    &mut n,
                    &mut pointer,
                )
            };
            assert_eq!((rc, n), (libc::EOF, 0), "{} prefix %n", engine.name);
            assert!(pointer.is_null(), "{} reached empty %mc", engine.name);

            // EILSEQ in a later allocation must retain the earlier allocation
            // and its contents; ENOMEM has a different cleanup contract.
            let mut first: *mut c_char = std::ptr::null_mut();
            let mut second = std::ptr::without_provenance_mut::<c_char>(1);
            n = SENTINEL;
            let (rc, error) = unsafe {
                *(engine.errno)() = 0;
                let rc = (engine.scan)(
                    w("é é€X").as_ptr(),
                    w("%ms %ms%n").as_ptr(),
                    &mut first,
                    &mut second,
                    &mut n,
                );
                (rc, *(engine.errno)())
            };
            assert_eq!(
                (rc, error, n),
                (1, libc::EILSEQ, SENTINEL),
                "{} prior allocation",
                engine.name
            );
            assert!(!first.is_null());
            assert!(second.is_null());
            unsafe {
                assert_eq!(CStr::from_ptr(first).to_bytes(), b"\xe9");
                (engine.free)(first.cast());
            }

            for (input, format, expected_rc, error) in [
                ("é€X", "%ms%n", 0, libc::EILSEQ),
                ("é€X", "%3mc%n", libc::EOF, libc::EILSEQ),
                ("é€X", "%m[^X]%n", 0, libc::EILSEQ),
                ("", "%ms%n", libc::EOF, 0),
                ("X", "%m[é]%n", 0, 0),
            ] {
                // A reached failed %m writes NULL, while unreached %n stays
                // untouched. Never read or free the sentinel pointer.
                let mut pointer = std::ptr::without_provenance_mut::<c_char>(1);
                n = SENTINEL;
                let (rc, observed_error) = unsafe {
                    *(engine.errno)() = 0;
                    let rc = (engine.scan)(
                        w(input).as_ptr(),
                        w(format).as_ptr(),
                        &mut pointer,
                        &mut n,
                    );
                    (rc, *(engine.errno)())
                };
                assert_eq!(
                    (rc, observed_error, n),
                    (expected_rc, error, SENTINEL),
                    "{} {format}",
                    engine.name
                );
                assert!(
                    pointer.is_null(),
                    "{} failed {format} destination",
                    engine.name
                );
            }
        }
    }
}
