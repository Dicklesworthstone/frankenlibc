#![cfg(target_os = "linux")]
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
                errno: host_fn(
                    c"__errno_location",
                    errno_abi::__errno_location as *const (),
                ),
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
        let mut locale_path =
            std::env::var_os("FRANKENLIBC_TEST_LOCALE_PATH").map(std::path::PathBuf::from);
        if let Some(path) = &locale_path {
            assert!(
                path.is_absolute() && path.is_dir(),
                "FRANKENLIBC_TEST_LOCALE_PATH must name an existing absolute directory: {path:?}"
            );
        } else if !std::path::Path::new("/usr/lib/locale/fr_FR/LC_CTYPE").is_file() {
            static COMPILED_LOCALE_PATH: std::sync::OnceLock<std::path::PathBuf> =
                std::sync::OnceLock::new();
            let compiled = COMPILED_LOCALE_PATH.get_or_init(|| {
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let dir = std::env::temp_dir().join(format!(
                    "frankenlibc-swscanf-localedef-{}-{stamp}",
                    std::process::id()
                ));
                std::fs::create_dir_all(&dir).expect("create swscanf localedef directory");
                let output = std::process::Command::new("localedef")
                    .args(["--no-archive", "-i", "fr_FR", "-f", "ISO-8859-1"])
                    .arg(dir.join("fr_FR"))
                    .output()
                    .expect("swscanf locale gate requires localedef");
                assert!(
                    output.status.success(),
                    "localedef fr_FR (ISO-8859-1) failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                dir
            });
            locale_path = Some(compiled.clone());
        }
        for mode in ["strict", "hardened"] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
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
                .env_remove("LOCPATH");
            if let Some(path) = &locale_path {
                command.env("LOCPATH", path);
            }
            let output = command.output().unwrap();
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
    type FdopenFn = unsafe extern "C" fn(c_int, *const c_char) -> *mut c_void;
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
        fdopen: FdopenFn,
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
                fdopen: host_fn(c"fdopen", stdio_abi::fdopen as *const ()),
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
                fdopen: stdio_abi::fdopen,
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

    type FwscanfFn = unsafe extern "C-unwind" fn(*mut c_void, *const Wc, ...) -> c_int;
    type VfwscanfFn = unsafe extern "C-unwind" fn(*mut c_void, *const Wc, *mut c_void) -> c_int;

    unsafe extern "C-unwind" fn call_vfwscanf(
        stream: *mut c_void,
        format: *const Wc,
        mut args: ...
    ) -> c_int {
        unsafe { fl::vfwscanf(stream, format, std::ptr::addr_of_mut!(args).cast()) }
    }

    unsafe extern "C-unwind" fn call_c99_vfwscanf(
        stream: *mut c_void,
        format: *const Wc,
        mut args: ...
    ) -> c_int {
        unsafe {
            isoc_abi::__isoc99_vfwscanf(stream, format.cast(), std::ptr::addr_of_mut!(args).cast())
        }
    }

    unsafe extern "C-unwind" fn call_c23_vfwscanf(
        stream: *mut c_void,
        format: *const Wc,
        mut args: ...
    ) -> c_int {
        unsafe {
            isoc_abi::__isoc23_vfwscanf(stream, format.cast(), std::ptr::addr_of_mut!(args).cast())
        }
    }

    unsafe extern "C-unwind" fn call_host_vfwscanf(
        stream: *mut c_void,
        format: *const Wc,
        mut args: ...
    ) -> c_int {
        static HOST: OnceLock<VfwscanfFn> = OnceLock::new();
        let scan = *HOST.get_or_init(|| unsafe { host_fn(c"vfwscanf", fl::vfwscanf as *const ()) });
        unsafe { scan(stream, format, std::ptr::addr_of_mut!(args).cast()) }
    }

    #[derive(Clone, Copy)]
    struct StreamScanEngine {
        name: &'static str,
        io: WideIoEngine,
        scan: FwscanfFn,
        free: FreeFn,
    }

    fn stream_scan_engines() -> [StreamScanEngine; 8] {
        let [host_io, native_io] = wide_io_engines();
        let native = |name, scan| StreamScanEngine {
            name,
            io: native_io,
            scan,
            free: malloc_abi::free,
        };
        [
            StreamScanEngine {
                name: "host_fwscanf",
                io: host_io,
                scan: unsafe { host_fn(c"fwscanf", fl::fwscanf as *const ()) },
                free: host().free,
            },
            StreamScanEngine {
                name: "host_vfwscanf",
                io: host_io,
                scan: call_host_vfwscanf,
                free: host().free,
            },
            native("fwscanf", fl::fwscanf as FwscanfFn),
            native("__isoc99_fwscanf", isoc_abi::__isoc99_fwscanf as FwscanfFn),
            native("__isoc23_fwscanf", isoc_abi::__isoc23_fwscanf as FwscanfFn),
            native("vfwscanf", call_vfwscanf as FwscanfFn),
            native("__isoc99_vfwscanf", call_c99_vfwscanf as FwscanfFn),
            native("__isoc23_vfwscanf", call_c23_vfwscanf as FwscanfFn),
        ]
    }

    fn scan_stream(
        engine: StreamScanEngine,
        bytes: &[u8],
        bound: &CStr,
        active: &CStr,
    ) -> *mut c_void {
        select(bound);
        let (_, path) = wide_stream_path(engine.name, bytes);
        let stream = unsafe { (engine.io.open)(path.as_ptr(), c"r".as_ptr()) };
        assert!(!stream.is_null(), "{} input FILE", engine.name);
        assert!(unsafe { (engine.io.orient)(stream, 1) } > 0);
        select(active);
        stream
    }

    #[test]
    fn wide_file_scanning_crosses_refills_and_preserves_positional_allocations() {
        if !isolated("wide_file_scanning_crosses_refills_and_preserves_positional_allocations") {
            return;
        }
        const LENGTH: usize = 10_007;
        for engine in stream_scan_engines() {
            for (bound, active, external, expected) in [
                (c"C.UTF-8", c"fr_FR", &b"\xc3\xa9"[..], &b"\xe9"[..]),
                (c"fr_FR", c"C.UTF-8", &b"\xe9"[..], &b"\xc3\xa9"[..]),
            ] {
                let mut input = external.repeat(LENGTH);
                input.extend_from_slice(b" 27#Z");
                let stream = scan_stream(engine, &input, bound, active);
                let mut text: *mut c_char = std::ptr::null_mut();
                let (mut count, mut number, mut tail) = (SENTINEL, SENTINEL, SENTINEL);
                let mut skipped = [SENTINEL; 4];
                let args = skipped.as_mut_ptr();
                let format = w("%8$ms%1$n %2$d%3$lc");
                let (rc, error) = unsafe {
                    *(engine.io.errno)() = 23;
                    let rc = (engine.scan)(
                        stream,
                        format.as_ptr(),
                        &mut count,
                        &mut number,
                        &mut tail,
                        args,
                        args.add(1),
                        args.add(2),
                        args.add(3),
                        &mut text,
                    );
                    (rc, *(engine.io.errno)())
                };
                assert_eq!(
                    (rc, error, count, number, tail),
                    (3, 23, LENGTH as c_int, 27, b'#' as Wc),
                    "{} {bound:?}->{active:?}",
                    engine.name
                );
                assert_eq!(skipped, [SENTINEL; 4], "{} unused arguments", engine.name);
                assert!(!text.is_null(), "{} allocated field", engine.name);
                unsafe {
                    assert_eq!(CStr::from_ptr(text).to_bytes(), expected.repeat(LENGTH));
                    (engine.free)(text.cast());
                    assert_eq!((engine.io.tell)(stream), (input.len() - 1) as libc::c_long);
                    assert_eq!((engine.io.error)(stream), 0);
                    assert_eq!((engine.io.eof)(stream), 0);
                    assert_eq!((engine.io.get)(stream), b'Z' as u32);
                    assert_eq!((engine.io.close)(stream), 0);
                }
            }
        }
    }

    #[test]
    fn wide_file_destination_errors_stop_before_later_reads_and_assignments() {
        if !isolated("wide_file_destination_errors_stop_before_later_reads_and_assignments") {
            return;
        }
        for engine in stream_scan_engines() {
            for (format, expected) in [("%s%n%d", 0), ("%3c%n%d", libc::EOF), ("%[^X]%n%d", 0)] {
                let stream = scan_stream(engine, "é€X 23".as_bytes(), c"C.UTF-8", c"fr_FR");
                let mut output = [0xa5u8; 16];
                let (mut count, mut number) = (SENTINEL, SENTINEL);
                let (rc, error) = unsafe {
                    *(engine.io.errno)() = 23;
                    let rc = (engine.scan)(
                        stream,
                        w(format).as_ptr(),
                        output.as_mut_ptr(),
                        &mut count,
                        &mut number,
                    );
                    (rc, *(engine.io.errno)())
                };
                assert_eq!(
                    (rc, error, count, number),
                    (expected, libc::EILSEQ, SENTINEL, SENTINEL),
                    "{} {format}",
                    engine.name
                );
                assert_eq!(output[0], 0xe9, "{} completed prefix", engine.name);
                assert!(output[1..].iter().all(|&byte| byte == 0xa5));
                unsafe {
                    assert_eq!(
                        (engine.io.tell)(stream),
                        5,
                        "{} failing scalar consumed",
                        engine.name
                    );
                    assert_eq!(
                        (engine.io.error)(stream),
                        0,
                        "destination error is not FILE error"
                    );
                    assert_eq!((engine.io.eof)(stream), 0);
                    assert_eq!((engine.io.get)(stream), b'X' as u32);
                    assert_eq!((engine.io.close)(stream), 0);
                }
            }

            let stream = scan_stream(engine, "é é€X".as_bytes(), c"C.UTF-8", c"fr_FR");
            let mut first: *mut c_char = std::ptr::null_mut();
            let mut second = std::ptr::without_provenance_mut::<c_char>(1);
            let mut count = SENTINEL;
            let (rc, error) = unsafe {
                *(engine.io.errno)() = 23;
                let rc = (engine.scan)(
                    stream,
                    w("%ms %ms%n").as_ptr(),
                    &mut first,
                    &mut second,
                    &mut count,
                );
                (rc, *(engine.io.errno)())
            };
            assert_eq!(
                (rc, error, count),
                (1, libc::EILSEQ, SENTINEL),
                "{} %m failure",
                engine.name
            );
            assert!(!first.is_null());
            assert!(second.is_null());
            unsafe {
                assert_eq!(CStr::from_ptr(first).to_bytes(), b"\xe9");
                (engine.free)(first.cast());
                assert_eq!((engine.io.tell)(stream), 8);
                assert_eq!((engine.io.get)(stream), b'X' as u32);
                assert_eq!((engine.io.close)(stream), 0);
            }
        }
    }

    #[test]
    fn wide_file_source_failures_keep_completed_fields() {
        if !isolated("wide_file_source_failures_keep_completed_fields") {
            return;
        }
        for engine in stream_scan_engines() {
            for input in [
                &b"A\xffX"[..],
                &b"A\xc3X"[..],
                &b"A"[..],
                &b"AB"[..],
                &b"ABA"[..],
            ] {
                let invalid = input.iter().any(|&byte| byte >= 0x80);
                let prefix = input.iter().take_while(|byte| byte.is_ascii()).count();
                for format in ["%s%n", "%[AB]%n", "%3c%n"] {
                    let characters = format == "%3c%n";
                    let complete = !characters || prefix == 3;
                    let stream = scan_stream(engine, input, c"C.UTF-8", c"C.UTF-8");
                    let mut output = [0xa5u8; 16];
                    let mut count = SENTINEL;
                    let (rc, error) = unsafe {
                        *(engine.io.errno)() = 23;
                        let rc = (engine.scan)(
                            stream,
                            w(format).as_ptr(),
                            output.as_mut_ptr(),
                            &mut count,
                        );
                        (rc, *(engine.io.errno)())
                    };
                    assert_eq!(
                        (rc, error, count),
                        (
                            if complete { 1 } else { libc::EOF },
                            if invalid { libc::EILSEQ } else { 23 },
                            if complete { prefix as c_int } else { SENTINEL },
                        ),
                        "{} {input:?} {format}",
                        engine.name
                    );
                    assert_eq!(&output[..prefix], &input[..prefix]);
                    if format == "%3c%n" {
                        assert!(output[prefix..].iter().all(|&byte| byte == 0xa5));
                    } else {
                        assert_eq!(output[prefix], 0);
                    }
                    unsafe {
                        assert_eq!((engine.io.tell)(stream), prefix as libc::c_long);
                        assert_eq!((engine.io.error)(stream) != 0, invalid);
                        assert_eq!(
                            (engine.io.eof)(stream) != 0,
                            !invalid && !(characters && complete)
                        );
                        assert_eq!((engine.io.close)(stream), 0);
                    }
                }

                for (format, wide, terminated) in [
                    ("%3mc%n", false, false),
                    ("%3mlc%n", true, false),
                    ("%ms%n", false, true),
                ] {
                    let complete = terminated || prefix == 3;
                    let stream = scan_stream(engine, input, c"C.UTF-8", c"C.UTF-8");
                    let mut narrow_pointer = std::ptr::without_provenance_mut::<c_char>(1);
                    let mut wide_pointer = std::ptr::without_provenance_mut::<Wc>(1);
                    let mut count = SENTINEL;
                    let (rc, error) = unsafe {
                        *(engine.io.errno)() = 23;
                        let rc = if wide {
                            (engine.scan)(stream, w(format).as_ptr(), &mut wide_pointer, &mut count)
                        } else {
                            (engine.scan)(
                                stream,
                                w(format).as_ptr(),
                                &mut narrow_pointer,
                                &mut count,
                            )
                        };
                        (rc, *(engine.io.errno)())
                    };
                    let pointer = if wide {
                        wide_pointer.cast::<u8>()
                    } else {
                        narrow_pointer.cast::<u8>()
                    };
                    assert_eq!(
                        (rc, error, count),
                        (
                            if complete { 1 } else { libc::EOF },
                            if invalid { libc::EILSEQ } else { 23 },
                            if complete { prefix as c_int } else { SENTINEL },
                        ),
                        "{} {input:?} {format}",
                        engine.name
                    );
                    if complete {
                        assert!(!pointer.is_null() && pointer.addr() != 1);
                        // SAFETY: a completed assignment owns at least prefix
                        // output elements, and a string also owns its NUL.
                        unsafe {
                            if wide {
                                let expected: Vec<Wc> =
                                    input[..prefix].iter().map(|byte| Wc::from(*byte)).collect();
                                assert_eq!(
                                    std::slice::from_raw_parts(pointer.cast::<Wc>(), prefix),
                                    expected
                                );
                            } else {
                                assert_eq!(
                                    std::slice::from_raw_parts(pointer, prefix),
                                    &input[..prefix]
                                );
                                if terminated {
                                    assert_eq!(*pointer.add(prefix), 0);
                                }
                            }
                            (engine.free)(pointer.cast());
                        }
                    } else {
                        assert!(
                            pointer.is_null(),
                            "{} unfinished field cleared",
                            engine.name
                        );
                    }
                    // SAFETY: the same FILE remains live through these queries.
                    unsafe {
                        assert_eq!((engine.io.tell)(stream), prefix as libc::c_long);
                        assert_eq!((engine.io.error)(stream) != 0, invalid);
                        assert_eq!(
                            (engine.io.eof)(stream) != 0,
                            !invalid && (terminated || !complete)
                        );
                        assert_eq!((engine.io.close)(stream), 0);
                    }
                }
            }

            // An unfinished character conversion preserves earlier assignments
            // and its written prefix, without reaching the following %n.
            for input in [b"7 A\xffX".as_slice(), b"7 A".as_slice()] {
                let invalid = input.contains(&0xff);
                for (format, complete) in [("%d %s%n", true), ("%d %3c%n", false)] {
                    let stream = scan_stream(engine, input, c"C.UTF-8", c"C.UTF-8");
                    let mut output = [0xa5u8; 16];
                    let (mut integer, mut count) = (SENTINEL, SENTINEL);
                    // SAFETY: live FILE and terminated format; the argument
                    // pointers own their integer and sixteen-byte destinations.
                    unsafe {
                        *(engine.io.errno)() = 23;
                        let rc = (engine.scan)(
                            stream,
                            w(format).as_ptr(),
                            &mut integer,
                            output.as_mut_ptr(),
                            &mut count,
                        );
                        assert_eq!(
                            (rc, *(engine.io.errno)(), integer, count),
                            (
                                if complete { 2 } else { 1 },
                                if invalid { libc::EILSEQ } else { 23 },
                                7,
                                if complete { 3 } else { SENTINEL },
                            ),
                            "{} {input:?} {format}",
                            engine.name
                        );
                        assert_eq!(output[0], b'A');
                        let guards = if complete {
                            assert_eq!(output[1], 0);
                            if engine.name.starts_with("host_") {
                                // GNU writes both the initial-state encoding
                                // terminator and a final NUL. Native output ends
                                // after its one NUL; check each engine's tail.
                                assert_eq!(output[2], 0);
                                &output[3..]
                            } else {
                                &output[2..]
                            }
                        } else {
                            &output[1..]
                        };
                        assert!(
                            guards.iter().all(|&byte| byte == 0xa5),
                            "{} {input:?} {format} output={output:?}",
                            engine.name
                        );
                        assert_eq!((engine.io.tell)(stream), 3);
                        assert_eq!((engine.io.error)(stream) != 0, invalid);
                        assert_eq!((engine.io.eof)(stream) != 0, !invalid);
                        assert_eq!((engine.io.close)(stream), 0);
                    }
                }
            }

            for (
                format,
                expected_result,
                expected_count,
                expected_error,
                expected_flag,
                position,
            ) in [
                ("%n", 0, 0, 23, false, 0),
                ("A %n", 0, 1, 23, true, 1),
                ("%*3c%n", libc::EOF, SENTINEL, libc::EILSEQ, true, 1),
            ] {
                let stream = scan_stream(engine, b"A\xffX", c"C.UTF-8", c"C.UTF-8");
                let mut count = SENTINEL;
                let (rc, error) = unsafe {
                    *(engine.io.errno)() = 23;
                    let rc = (engine.scan)(stream, w(format).as_ptr(), &mut count);
                    (rc, *(engine.io.errno)())
                };
                assert_eq!(
                    (rc, error, count),
                    (expected_result, expected_error, expected_count),
                    "{} {format}",
                    engine.name
                );
                unsafe {
                    assert_eq!((engine.io.error)(stream) != 0, expected_flag);
                    assert_eq!((engine.io.eof)(stream), 0);
                    assert_eq!((engine.io.tell)(stream), position);
                    assert_eq!((engine.io.close)(stream), 0);
                }
            }

            let stream = scan_stream(engine, b"\xffX", c"C.UTF-8", c"C.UTF-8");
            let mut pointer = std::ptr::without_provenance_mut::<c_char>(1);
            let mut count = SENTINEL;
            let (rc, error) = unsafe {
                *(engine.io.errno)() = 23;
                let rc = (engine.scan)(stream, w("%ms%n").as_ptr(), &mut pointer, &mut count);
                (rc, *(engine.io.errno)())
            };
            assert_eq!(
                (rc, error, count),
                (libc::EOF, libc::EILSEQ, SENTINEL),
                "{} empty %m",
                engine.name
            );
            assert!(pointer.is_null());
            unsafe {
                assert_eq!((engine.io.tell)(stream), 0);
                assert_ne!((engine.io.error)(stream), 0);
                assert_eq!((engine.io.close)(stream), 0);
            }
        }
    }

    #[test]
    fn wide_file_finite_fields_do_not_wait_for_pipe_eof() {
        if !isolated("wide_file_finite_fields_do_not_wait_for_pipe_eof") {
            return;
        }
        use std::io::Write;
        use std::os::fd::FromRawFd;
        use std::time::Duration;

        for engine in stream_scan_engines() {
            for (format, input, wide, expected_count, expected_rc, expected_error) in [
                ("%1s%n", "é", false, 1, 1, 23),
                ("%1[é]%n", "é", false, 1, 1, 23),
                ("%1lc%n", "é", true, 1, 1, 23),
                ("é%n", "é", false, 1, 0, 23),
                ("%n", "", false, 0, 0, 23),
                ("%s%n", "é€", false, SENTINEL, 0, libc::EILSEQ),
                ("%3c%n", "é€", false, SENTINEL, libc::EOF, libc::EILSEQ),
            ] {
                select(c"C.UTF-8");
                let mut descriptors = [-1; 2];
                assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
                // The write end stays open until the scanner reports its
                // result. Closing it after timeout releases a defective read
                // before the assertion, so a failure cannot hang the suite.
                let mut write = unsafe { std::fs::File::from_raw_fd(descriptors[1]) };
                write.write_all(input.as_bytes()).unwrap();
                let stream = unsafe { (engine.io.fdopen)(descriptors[0], c"r".as_ptr()) };
                assert!(!stream.is_null());
                assert!(unsafe { (engine.io.orient)(stream, 1) } > 0);
                select(c"fr_FR");
                let stream_address = stream as usize;
                let (sender, receiver) = std::sync::mpsc::channel();
                let worker = std::thread::spawn(move || {
                    let stream = stream_address as *mut c_void;
                    let mut narrow = [0xa5u8; 16];
                    let mut wide_output = [SENTINEL; 4];
                    let mut count = SENTINEL;
                    let observed = unsafe {
                        *(engine.io.errno)() = 23;
                        let rc = if format == "%n" || format == "é%n" {
                            (engine.scan)(stream, w(format).as_ptr(), &mut count)
                        } else if wide {
                            (engine.scan)(
                                stream,
                                w(format).as_ptr(),
                                wide_output.as_mut_ptr(),
                                &mut count,
                            )
                        } else {
                            (engine.scan)(
                                stream,
                                w(format).as_ptr(),
                                narrow.as_mut_ptr(),
                                &mut count,
                            )
                        };
                        (
                            rc,
                            *(engine.io.errno)(),
                            count,
                            (engine.io.error)(stream),
                            (engine.io.eof)(stream),
                            narrow,
                            wide_output,
                        )
                    };
                    sender.send(observed).unwrap();
                    unsafe { assert_eq!((engine.io.close)(stream), 0) };
                });
                let observed = receiver.recv_timeout(Duration::from_secs(3));
                drop(write);
                worker.join().unwrap();
                let (rc, error, count, file_error, eof, narrow, wide_output) = observed
                    .unwrap_or_else(|error| {
                        panic!("{} {format} waited for pipe EOF: {error}", engine.name)
                    });
                assert_eq!(
                    (rc, error, count, file_error, eof),
                    (expected_rc, expected_error, expected_count, 0, 0),
                    "{} live pipe {format}",
                    engine.name
                );
                if wide {
                    assert_eq!(wide_output, [0xe9, SENTINEL, SENTINEL, SENTINEL]);
                } else if format.starts_with('%') && format != "%n" {
                    assert_eq!(narrow[0], 0xe9);
                    if expected_error == libc::EILSEQ {
                        assert!(narrow[1..].iter().all(|&byte| byte == 0xa5));
                    } else {
                        assert_eq!(narrow[1], 0);
                    }
                }
            }
        }
    }

    #[test]
    fn wide_file_scanning_uses_active_numeric_and_space_categories() {
        if !isolated("wide_file_scanning_uses_active_numeric_and_space_categories") {
            return;
        }
        for engine in stream_scan_engines() {
            unsafe {
                assert!(!(host().setlocale)(libc::LC_NUMERIC, c"fr_FR".as_ptr()).is_null());
                assert!(!locale_abi::setlocale(libc::LC_NUMERIC, c"fr_FR".as_ptr()).is_null());
            }
            let stream = scan_stream(engine, b"1,5 8X", c"C.UTF-8", c"C.UTF-8");
            let (mut value, mut count, mut integer) = (-1.0f64, SENTINEL, SENTINEL);
            let (rc, error) = unsafe {
                *(engine.io.errno)() = 23;
                let rc = (engine.scan)(
                    stream,
                    w("%lf%n %d").as_ptr(),
                    &mut value,
                    &mut count,
                    &mut integer,
                );
                (rc, *(engine.io.errno)())
            };
            assert_eq!(
                (rc, error, value, count, integer),
                (2, 23, 1.5, 3, 8),
                "{} numeric locale",
                engine.name
            );
            unsafe {
                assert_eq!((engine.io.tell)(stream), 5);
                assert_eq!((engine.io.get)(stream), b'X' as u32);
                assert_eq!((engine.io.close)(stream), 0);
                assert!(!(host().setlocale)(libc::LC_NUMERIC, c"C".as_ptr()).is_null());
                assert!(!locale_abi::setlocale(libc::LC_NUMERIC, c"C".as_ptr()).is_null());
            }

            for active in [c"C", c"C.UTF-8"] {
                let unicode_space = active == c"C.UTF-8";
                let stream = scan_stream(engine, b"A", c"C.UTF-8", active);
                let (mut character, mut count) = (SENTINEL, SENTINEL);
                let rc = unsafe {
                    (engine.scan)(
                        stream,
                        w("\u{2003}%lc%n").as_ptr(),
                        &mut character,
                        &mut count,
                    )
                };
                assert_eq!(
                    (rc, character, count),
                    if unicode_space {
                        (1, b'A' as Wc, 1)
                    } else {
                        (0, SENTINEL, SENTINEL)
                    },
                    "{} {active:?} format whitespace",
                    engine.name
                );
                unsafe {
                    assert_eq!((engine.io.tell)(stream), if unicode_space { 1 } else { 0 });
                    assert_eq!((engine.io.close)(stream), 0);
                }

                let stream = scan_stream(engine, "\u{2003}A ".as_bytes(), c"C.UTF-8", active);
                let mut output = [SENTINEL; 8];
                let mut count = SENTINEL;
                let rc = unsafe {
                    (engine.scan)(stream, w("%ls%n").as_ptr(), output.as_mut_ptr(), &mut count)
                };
                assert_eq!(
                    (rc, count),
                    (1, 2),
                    "{} {active:?} input whitespace",
                    engine.name
                );
                let expected = if unicode_space {
                    w("A")
                } else {
                    w("\u{2003}A")
                };
                assert_eq!(&output[..expected.len()], expected);
                assert!(output[expected.len()..].iter().all(|&wc| wc == SENTINEL));
                unsafe {
                    assert_eq!((engine.io.tell)(stream), 4);
                    assert_eq!((engine.io.get)(stream), b' ' as u32);
                    assert_eq!((engine.io.close)(stream), 0);
                }
            }
        }
    }

    #[test]
    fn wide_file_large_character_width_preserves_completed_fields() {
        if !isolated("wide_file_large_character_width_preserves_completed_fields") {
            return;
        }
        // Prepare the native allocator before restricting the address space;
        // the ordinary prefix allocation must remain available in both modes.
        let warm = unsafe { malloc_abi::malloc(64) };
        assert!(!warm.is_null());
        unsafe { malloc_abi::free(warm) };
        let formats = [
            w("%d %ms%n %1000000000mc%n"),
            w("%d %ms%n %1000000000mlc%n"),
        ];
        for engine in stream_scan_engines() {
            for (index, format) in formats.iter().enumerate() {
                let wide = index == 1;
                let stream = scan_stream(engine, b"7 A B", c"C.UTF-8", c"C.UTF-8");
                let mut first: *mut c_char = std::ptr::null_mut();
                let mut failed_narrow = std::ptr::without_provenance_mut::<c_char>(1);
                let mut failed_wide = std::ptr::without_provenance_mut::<Wc>(1);
                let (mut integer, mut prefix_count, mut count) = (SENTINEL, SENTINEL, SENTINEL);

                // Field width limits input, rather than requiring a width-sized
                // allocation before reading. Keep little address-space headroom
                // to reject an eager billion-character allocation on short input.
                let status = std::fs::read_to_string("/proc/self/status").unwrap();
                let vm_kib = status
                    .lines()
                    .find(|line| line.starts_with("VmSize:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .expect("Linux supplies VmSize")
                    .parse::<libc::rlim_t>()
                    .unwrap();
                let ceiling = vm_kib
                    .checked_mul(1024)
                    .and_then(|bytes| bytes.checked_add(64 * 1024 * 1024))
                    .unwrap();
                let mut previous = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                assert_eq!(
                    unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut previous) },
                    0
                );
                let constrained = libc::rlimit {
                    rlim_cur: ceiling.min(previous.rlim_cur),
                    rlim_max: previous.rlim_max,
                };
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &constrained) }, 0);

                // No formatting, file preparation, or assertions run under the
                // temporary limit. Record the result and restore first.
                let (rc, error) = unsafe {
                    *(engine.io.errno)() = 23;
                    let rc = if wide {
                        (engine.scan)(
                            stream,
                            format.as_ptr(),
                            &mut integer,
                            &mut first,
                            &mut prefix_count,
                            &mut failed_wide,
                            &mut count,
                        )
                    } else {
                        (engine.scan)(
                            stream,
                            format.as_ptr(),
                            &mut integer,
                            &mut first,
                            &mut prefix_count,
                            &mut failed_narrow,
                            &mut count,
                        )
                    };
                    (rc, *(engine.io.errno)())
                };
                let restored = unsafe { libc::setrlimit(libc::RLIMIT_AS, &previous) };
                assert_eq!(restored, 0, "restore address-space limit");
                // SAFETY: the FILE stays live until close and status queries
                // do not consume input or release the completed allocation.
                let status = unsafe {
                    (
                        (engine.io.tell)(stream),
                        (engine.io.error)(stream) != 0,
                        (engine.io.eof)(stream) != 0,
                    )
                };
                unsafe { assert_eq!((engine.io.close)(stream), 0) };
                assert_eq!(
                    (rc, error, integer, prefix_count, count),
                    (2, 23, 7, 3, SENTINEL),
                    "{} {} incomplete character field",
                    engine.name,
                    if wide { "%mlc" } else { "%mc" }
                );
                assert_eq!(status, (5, false, true));
                assert!(
                    !first.is_null(),
                    "{} prior allocation retained",
                    engine.name
                );
                // SAFETY: the earlier completed %ms assigned "A" and its NUL;
                // its allocation remains caller-owned after the later failure.
                unsafe {
                    assert_eq!(std::slice::from_raw_parts(first.cast::<u8>(), 2), b"A\0");
                    (engine.free)(first.cast());
                }
                assert!(
                    if wide {
                        failed_wide.is_null()
                    } else {
                        failed_narrow.is_null()
                    },
                    "{} failed destination cleared",
                    engine.name
                );
            }
        }
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
            (
                c"C.UTF-8",
                c"fr_FR",
                "éAé\n".as_bytes(),
                b"\xc3\xa9".as_slice(),
            ),
            (c"C.UTF-8", c"C", "éAé\n".as_bytes(), b"\xc3\xa9".as_slice()),
            (
                c"fr_FR",
                c"C.UTF-8",
                b"\xe9A\xe9\n".as_slice(),
                b"\xe9".as_slice(),
            ),
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
                    assert_eq!(
                        (engine.get)(stream),
                        0xe9,
                        "{} binding after seek",
                        engine.name
                    );
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

    // Every stream in this matrix is opened, oriented and inspected through
    // GNU. Only the I/O operation changes provider. A native-created FILE would
    // miss the foreign-buffer and retained-conversion-state contract entirely.
    fn foreign_wide_io_engines() -> [WideIoEngine; 5] {
        unsafe extern "C-unwind" fn get_unlocked(stream: *mut c_void) -> u32 {
            unsafe { fl::fgetwc_unlocked(stream.cast()) }
        }
        unsafe extern "C-unwind" fn get_alias(stream: *mut c_void) -> u32 {
            unsafe { fl::getwc(stream.cast()) }
        }
        unsafe extern "C-unwind" fn get_alias_unlocked(stream: *mut c_void) -> u32 {
            unsafe { fl::getwc_unlocked(stream.cast()) }
        }
        unsafe extern "C-unwind" fn put_unlocked(wc: u32, stream: *mut c_void) -> u32 {
            unsafe { fl::fputwc_unlocked(wc as Wc, stream.cast()) }
        }
        unsafe extern "C-unwind" fn put_alias(wc: u32, stream: *mut c_void) -> u32 {
            unsafe { fl::putwc(wc as Wc, stream.cast()) }
        }
        unsafe extern "C-unwind" fn gets_unlocked(
            ws: *mut Wc,
            n: c_int,
            stream: *mut c_void,
        ) -> *mut Wc {
            unsafe { fl::fgetws_unlocked(ws, n, stream.cast()) }
        }
        unsafe extern "C-unwind" fn puts_unlocked(ws: *const Wc, stream: *mut c_void) -> c_int {
            unsafe { fl::fputws_unlocked(ws, stream.cast()) }
        }

        let [host, _] = wide_io_engines();
        let locked = WideIoEngine {
            name: "foreign_locked",
            errno: errno_abi::__errno_location,
            get: fl::fgetwc,
            unget: fl::ungetwc,
            gets: fl::fgetws,
            put: fl::fputwc,
            puts: fl::fputws,
            ..host
        };
        let unlocked = WideIoEngine {
            name: "foreign_unlocked",
            get: get_unlocked,
            gets: gets_unlocked,
            put: put_unlocked,
            puts: puts_unlocked,
            ..locked
        };
        [
            host,
            locked,
            unlocked,
            WideIoEngine {
                name: "foreign_alias",
                get: get_alias,
                put: put_alias,
                ..locked
            },
            WideIoEngine {
                name: "foreign_alias_unlocked",
                get: get_alias_unlocked,
                put: fl::putwc_unlocked,
                ..unlocked
            },
        ]
    }

    #[test]
    fn foreign_wide_streams_keep_orientation_and_codec() {
        if !isolated("foreign_wide_streams_keep_orientation_and_codec") {
            return;
        }
        for engine in foreign_wide_io_engines() {
            for (bound, active, input, encoded) in [
                (
                    c"C.UTF-8",
                    c"fr_FR",
                    "éAé\n".as_bytes(),
                    b"\xc3\xa9".as_slice(),
                ),
                (c"C.UTF-8", c"C", "éAé\n".as_bytes(), b"\xc3\xa9".as_slice()),
                (
                    c"fr_FR",
                    c"C.UTF-8",
                    b"\xe9A\xe9\n".as_slice(),
                    b"\xe9".as_slice(),
                ),
            ] {
                select(bound);
                let (_, path) = wide_stream_path(engine.name, input);
                // SAFETY: GNU owns the FILE until its matching close. Every
                // buffer below has the stated capacity, and the scalar values
                // are representable in the codec bound before the locale change.
                let stream = unsafe { (engine.open)(path.as_ptr(), c"r".as_ptr()) };
                assert!(!stream.is_null(), "{} foreign input", engine.name);
                assert!(unsafe { (engine.orient)(stream, 1) } > 0);
                select(active);
                unsafe {
                    *(engine.errno)() = 23;
                    assert_eq!((engine.get)(stream), 0xe9, "{} bound read", engine.name);
                    assert_eq!((engine.tell)(stream), encoded.len() as libc::c_long);
                    assert_eq!((engine.unget)(0xe9, stream), 0xe9, "{} pushback", engine.name);
                    assert_eq!((engine.get)(stream), 0xe9);
                    assert_eq!((engine.tell)(stream), encoded.len() as libc::c_long);
                    let mut line = [SENTINEL as Wc; 8];
                    assert_eq!(
                        (engine.gets)(line.as_mut_ptr(), line.len() as c_int, stream),
                        line.as_mut_ptr(),
                        "{} bound line",
                        engine.name
                    );
                    assert_eq!(&line[..4], &[Wc::from(b'A'), 0xe9, Wc::from(b'\n'), 0]);
                    assert!(line[4..].iter().all(|&wc| wc == SENTINEL));
                    assert_eq!((engine.tell)(stream), input.len() as libc::c_long);
                    assert!((engine.orient)(stream, 0) > 0, "{} host orientation", engine.name);
                    assert_eq!((engine.error)(stream), 0);
                    assert_eq!(*(engine.errno)(), 23, "{} success errno", engine.name);
                    assert_eq!((engine.get)(stream), u32::MAX);
                    assert_ne!((engine.eof)(stream), 0);
                    assert_eq!((engine.error)(stream), 0);
                    assert_eq!(*(engine.errno)(), 23, "{} clean EOF errno", engine.name);
                    line.fill(SENTINEL);
                    assert!((engine.gets)(line.as_mut_ptr(), 8, stream).is_null());
                    assert_eq!(line, [SENTINEL; 8]);
                    assert_eq!((engine.close)(stream), 0);
                }

                select(bound);
                let (output_path, path) = wide_stream_path(engine.name, b"");
                let stream = unsafe { (engine.open)(path.as_ptr(), c"w".as_ptr()) };
                assert!(!stream.is_null(), "{} foreign output", engine.name);
                assert!(unsafe { (engine.orient)(stream, 1) } > 0);
                select(active);
                let line = w("abcdefghijklmnopéé\n");
                unsafe {
                    *(engine.errno)() = 23;
                    assert_eq!((engine.put)(0xe9, stream), 0xe9, "{} bound write", engine.name);
                    assert!(
                        (engine.puts)(line.as_ptr(), stream) >= 0,
                        "{} bound string",
                        engine.name
                    );
                    assert_eq!((engine.flush)(stream), 0);
                    assert!((engine.orient)(stream, 0) > 0);
                    assert_eq!((engine.error)(stream), 0);
                    assert_eq!(*(engine.errno)(), 23, "{} output errno", engine.name);
                    assert_eq!((engine.close)(stream), 0);
                }
                let mut expected = encoded.to_vec();
                expected.extend_from_slice(b"abcdefghijklmnop");
                expected.extend_from_slice(encoded);
                expected.extend_from_slice(encoded);
                expected.push(b'\n');
                assert_eq!(
                    std::fs::read(output_path).unwrap(),
                    expected,
                    "{} {bound:?}->{active:?} host bytes",
                    engine.name
                );
            }

            // The first wide call must orient the actual host FILE, not only
            // decode bytes in a temporary native context.
            select(c"C.UTF-8");
            let (_, path) = wide_stream_path(engine.name, "é".as_bytes());
            unsafe {
                let stream = (engine.open)(path.as_ptr(), c"r".as_ptr());
                assert!(!stream.is_null());
                assert_eq!((engine.orient)(stream, 0), 0);
                assert_eq!((engine.get)(stream), 0xe9, "{} initial read", engine.name);
                assert!((engine.orient)(stream, 0) > 0);
                assert_eq!((engine.close)(stream), 0);
            }
            let (output_path, path) = wide_stream_path(engine.name, b"");
            unsafe {
                let stream = (engine.open)(path.as_ptr(), c"w".as_ptr());
                assert!(!stream.is_null());
                assert_eq!((engine.orient)(stream, 0), 0);
                assert_eq!((engine.put)(0xe9, stream), 0xe9, "{} initial write", engine.name);
                assert!((engine.orient)(stream, 0) > 0);
                assert_eq!((engine.close)(stream), 0);
            }
            assert_eq!(std::fs::read(output_path).unwrap(), "é".as_bytes());
        }
    }

    #[test]
    fn foreign_wide_streams_preserve_error_state() {
        if !isolated("foreign_wide_streams_preserve_error_state") {
            return;
        }
        for engine in foreign_wide_io_engines() {
            select(c"C.UTF-8");
            let (_, path) = wide_stream_path(engine.name, b"A\xffZ");
            let stream = unsafe { (engine.open)(path.as_ptr(), c"r".as_ptr()) };
            assert!(!stream.is_null());
            assert!(unsafe { (engine.orient)(stream, 1) } > 0);
            // 0xff is valid Latin-1 but invalid in this FILE's retained UTF-8
            // codec. Using the active locale would silently consume it.
            select(c"fr_FR");
            // SAFETY: the host FILE and each destination remain live throughout
            // the read/error/recovery sequence. GNU queries inspect its state.
            unsafe {
                *(engine.errno)() = 23;
                assert_eq!((engine.get)(stream), u32::from(b'A'));
                assert_eq!((engine.get)(stream), u32::MAX, "{} invalid encoding", engine.name);
                assert_eq!(*(engine.errno)(), libc::EILSEQ);
                assert_ne!((engine.error)(stream), 0);
                assert_eq!((engine.eof)(stream), 0);
                assert_eq!((engine.tell)(stream), 1);
                assert_eq!((engine.seek)(stream, 2, libc::SEEK_SET), 0);
                assert_ne!((engine.error)(stream), 0, "{} sticky error", engine.name);

                *(engine.errno)() = 23;
                let mut line = [SENTINEL as Wc; 4];
                assert_eq!(
                    (engine.gets)(line.as_mut_ptr(), 4, stream),
                    line.as_mut_ptr(),
                    "{} recovery after seek",
                    engine.name
                );
                assert_eq!(line, [Wc::from(b'Z'), 0, SENTINEL, SENTINEL]);
                assert_ne!((engine.error)(stream), 0);
                assert_ne!((engine.eof)(stream), 0);
                assert_eq!(*(engine.errno)(), 23);
                assert_eq!((engine.close)(stream), 0);
            }

            // A foreign write-only FILE must report the host's read error,
            // without consuming its descriptor or silently returning clean EOF.
            let (_, path) = wide_stream_path(engine.name, b"");
            unsafe {
                let stream = (engine.open)(path.as_ptr(), c"w".as_ptr());
                assert!(!stream.is_null());
                assert!((engine.orient)(stream, 1) > 0);
                *(engine.errno)() = 23;
                assert_eq!((engine.get)(stream), u32::MAX);
                assert_eq!(*(engine.errno)(), libc::EBADF, "{} access error", engine.name);
                assert_ne!((engine.error)(stream), 0);
                assert_eq!((engine.eof)(stream), 0);
                assert_eq!((engine.tell)(stream), 0);
                assert_eq!((engine.close)(stream), 0);
            }
        }
    }

    #[test]
    fn wide_character_read_checks_stream_mode() {
        use std::os::fd::IntoRawFd;

        if !isolated("wide_character_read_checks_stream_mode") {
            return;
        }
        for line_read in [false, true] {
            for (mode, readable) in [(c"w", false), (c"r+", true)] {
                for engine in wide_io_engines() {
                    select(c"C.UTF-8");
                    let (backing, _) = wide_stream_path(engine.name, b"Z");
                    let file = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(backing)
                        .unwrap();
                    let fd = file.into_raw_fd();
                    // SAFETY: fd is live and transferred to a successful fdopen;
                    // mode is terminated, line buffers have four writable slots,
                    // and the FILE remains live until close.
                    unsafe {
                        let stream = (engine.fdopen)(fd, mode.as_ptr());
                        assert!(!stream.is_null());
                        assert!((engine.orient)(stream, 1) > 0);
                        *(engine.errno)() = 0;
                        if line_read {
                            let mut line = [SENTINEL as Wc; 4];
                            let result = (engine.gets)(line.as_mut_ptr(), 4, stream);
                            if readable {
                                assert_eq!(result, line.as_mut_ptr());
                                assert_eq!(line, [Wc::from(b'Z'), 0, SENTINEL, SENTINEL]);
                                assert_ne!((engine.eof)(stream), 0);
                            } else {
                                assert!(result.is_null());
                                assert_eq!(line, [SENTINEL; 4]);
                                assert_eq!((engine.eof)(stream), 0);
                            }
                        } else {
                            let wc = (engine.get)(stream);
                            assert_eq!(
                                wc,
                                if readable { u32::from(b'Z') } else { u32::MAX },
                                "{} stream mode {mode:?}",
                                engine.name
                            );
                            assert_eq!((engine.eof)(stream), 0);
                        }
                        assert_eq!(
                            *(engine.errno)(),
                            if readable { 0 } else { libc::EBADF },
                            "{} line_read={line_read} stream mode {mode:?}",
                            engine.name
                        );
                        assert_eq!((engine.error)(stream) != 0, !readable);
                        assert_eq!(
                            frankenlibc_core::syscall::sys_lseek(fd, 0, libc::SEEK_CUR),
                            Ok(i64::from(readable)),
                            "{} denied reads must not consume descriptor bytes",
                            engine.name
                        );
                        assert_eq!((engine.close)(stream), 0);
                    }
                }
            }
        }
    }

    #[test]
    fn wide_line_after_error_reaches_clean_eof() {
        if !isolated("wide_line_after_error_reaches_clean_eof") {
            return;
        }
        for (input, prefix, recovery, expected) in [
            (b"\xffZ".as_slice(), false, 1, Wc::from(b'Z')),
            (b"A\xffZ".as_slice(), true, 2, Wc::from(b'Z')),
            (b"\xc3XZ".as_slice(), false, 2, Wc::from(b'Z')),
            (b"A\xc3XZ".as_slice(), true, 3, Wc::from(b'Z')),
            (b"\xff\xc3\xa9".as_slice(), false, 1, 0xe9),
        ] {
            for capacity in [2, 4] {
                for engine in wide_io_engines() {
                    select(c"C.UTF-8");
                    let (_, path) = wide_stream_path(engine.name, input);
                    // SAFETY: path/mode are terminated; successful open owns a
                    // live FILE through close, and output capacities fit line.
                    unsafe {
                        let stream = (engine.open)(path.as_ptr(), c"r".as_ptr());
                        assert!(!stream.is_null(), "{} recovery FILE", engine.name);
                        assert!((engine.orient)(stream, 1) > 0);
                        if prefix {
                            assert_eq!((engine.get)(stream), u32::from(b'A'));
                        }
                        *(engine.errno)() = 0;
                        assert_eq!((engine.get)(stream), u32::MAX);
                        assert_eq!(*(engine.errno)(), libc::EILSEQ);
                        assert_ne!((engine.error)(stream), 0);
                        assert_eq!((engine.eof)(stream), 0);
                        assert_eq!((engine.tell)(stream), libc::c_long::from(prefix));
                        assert_eq!((engine.seek)(stream, recovery, libc::SEEK_SET), 0);
                        assert_ne!((engine.error)(stream), 0);

                        let mut line = [SENTINEL as Wc; 5];
                        assert_eq!(
                            (engine.gets)(line.as_mut_ptr(), capacity, stream),
                            line.as_mut_ptr(),
                            "{} recovery capacity {capacity}",
                            engine.name
                        );
                        assert_eq!(line, [expected, 0, SENTINEL, SENTINEL, SENTINEL]);
                        assert_eq!((engine.tell)(stream), input.len() as libc::c_long);
                        assert_eq!(
                            (engine.eof)(stream) != 0,
                            capacity > 2,
                            "{} only an attempted read past the tail sets EOF",
                            engine.name
                        );
                        assert_ne!((engine.error)(stream), 0);
                        assert!((engine.gets)(line.as_mut_ptr(), capacity, stream).is_null());
                        assert_ne!((engine.eof)(stream), 0);
                        assert_ne!((engine.error)(stream), 0);
                        assert_eq!((engine.close)(stream), 0);
                    }
                }
            }
        }

        // A fresh decoding error still fails after a valid prefix. Only the
        // guards beyond the supplied capacity are defined after that failure.
        for input in [b"A\xffZ".as_slice(), b"A\xc3XZ".as_slice()] {
            for engine in wide_io_engines() {
                select(c"C.UTF-8");
                let (_, path) = wide_stream_path(engine.name, input);
                // SAFETY: live FILE, terminated path/mode and four writable
                // wchar_t slots followed by two untouched guard slots.
                unsafe {
                    let stream = (engine.open)(path.as_ptr(), c"r".as_ptr());
                    assert!(!stream.is_null());
                    assert!((engine.orient)(stream, 1) > 0);
                    let mut line = [SENTINEL as Wc; 6];
                    *(engine.errno)() = 0;
                    assert!((engine.gets)(line.as_mut_ptr(), 4, stream).is_null());
                    assert_eq!(*(engine.errno)(), libc::EILSEQ);
                    assert_ne!((engine.error)(stream), 0);
                    assert_eq!((engine.eof)(stream), 0);
                    assert_eq!((engine.tell)(stream), 1);
                    assert_eq!(&line[4..], &[SENTINEL, SENTINEL]);
                    assert_eq!((engine.close)(stream), 0);
                }
            }
        }
    }

    #[test]
    fn wide_line_eof_blocks_appended_data_until_seek() {
        use std::io::Write;

        if !isolated("wide_line_eof_blocks_appended_data_until_seek") {
            return;
        }
        for engine in wide_io_engines() {
            select(c"C.UTF-8");
            let (backing, path) = wide_stream_path(engine.name, b"Z");
            // SAFETY: successful open owns a live FILE until close; line has
            // the four writable wchar_t slots passed to every line read.
            unsafe {
                let stream = (engine.open)(path.as_ptr(), c"r".as_ptr());
                assert!(!stream.is_null());
                assert!((engine.orient)(stream, 1) > 0);
                let mut line = [SENTINEL as Wc; 4];
                assert_eq!(
                    (engine.gets)(line.as_mut_ptr(), 4, stream),
                    line.as_mut_ptr()
                );
                assert_eq!(line, [Wc::from(b'Z'), 0, SENTINEL, SENTINEL]);
                assert_ne!((engine.eof)(stream), 0);
                assert_eq!((engine.error)(stream), 0);
                let mut writer = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&backing)
                    .unwrap();
                writer.write_all(b"Q\n").unwrap();
                drop(writer);

                line.fill(SENTINEL);
                assert!(
                    (engine.gets)(line.as_mut_ptr(), 4, stream).is_null(),
                    "{} EOF must block appended data",
                    engine.name
                );
                assert_eq!(line, [SENTINEL; 4]);
                assert_eq!((engine.tell)(stream), 1);
                assert_ne!((engine.eof)(stream), 0);
                assert_eq!((engine.error)(stream), 0);

                assert_eq!((engine.seek)(stream, 1, libc::SEEK_SET), 0);
                assert_eq!((engine.eof)(stream), 0);
                assert_eq!(
                    (engine.gets)(line.as_mut_ptr(), 4, stream),
                    line.as_mut_ptr()
                );
                assert_eq!(line, [Wc::from(b'Q'), Wc::from(b'\n'), 0, SENTINEL]);
                assert_eq!((engine.eof)(stream), 0);
                assert_eq!((engine.error)(stream), 0);
                assert_eq!((engine.tell)(stream), 3);
                assert!((engine.gets)(line.as_mut_ptr(), 4, stream).is_null());
                assert_ne!((engine.eof)(stream), 0);
                assert_eq!((engine.close)(stream), 0);
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
                            (engine.seek)(
                                stream,
                                (input.len() - 1) as libc::c_long,
                                libc::SEEK_SET
                            ),
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
                            &observed, expected,
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
    type VfwprintfFn = unsafe extern "C-unwind" fn(*mut c_void, *const Wc, *mut c_void) -> c_int;

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
            (c"C.UTF-8", c"C", b"\xc3\xa9".as_slice(), b"A".as_slice()),
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
                    [
                        ("fwprintf", host_fwprintf()),
                        ("vfwprintf", call_host_vfwprintf),
                    ]
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

    type SnprintfFn = unsafe extern "C-unwind" fn(*mut c_char, usize, *const c_char, ...) -> c_int;
    type VsnprintfFn =
        unsafe extern "C-unwind" fn(*mut c_char, usize, *const c_char, *mut c_void) -> c_int;

    unsafe extern "C-unwind" fn call_vsnprintf(
        output: *mut c_char,
        capacity: usize,
        format: *const c_char,
        mut args: ...
    ) -> c_int {
        // SAFETY: the caller's promoted arguments match this live va_list.
        unsafe {
            stdio_abi::vsnprintf(
                output,
                capacity,
                format,
                std::ptr::addr_of_mut!(args).cast(),
            )
        }
    }

    unsafe extern "C-unwind" fn call_host_vsnprintf(
        output: *mut c_char,
        capacity: usize,
        format: *const c_char,
        mut args: ...
    ) -> c_int {
        static PRINT: OnceLock<VsnprintfFn> = OnceLock::new();
        let print = *PRINT.get_or_init(|| {
            // SAFETY: resolve the independent GNU function with this exact ABI.
            unsafe { host_fn(c"vsnprintf", stdio_abi::vsnprintf as *const ()) }
        });
        // SAFETY: the arguments and receiving buffer belong to this call.
        unsafe {
            print(
                output,
                capacity,
                format,
                std::ptr::addr_of_mut!(args).cast(),
            )
        }
    }

    #[test]
    fn narrow_output_wide_arguments_use_active_codec() {
        if !isolated("narrow_output_wide_arguments_use_active_codec") {
            return;
        }
        // Both APIs use the shared renderer, with distinct variadic extraction.
        let entries: [(&str, SnprintfFn, SnprintfFn); 2] = [
            (
                "snprintf",
                // SAFETY: the independent host symbol has this exact ABI.
                unsafe { host_fn(c"snprintf", stdio_abi::snprintf as *const ()) },
                stdio_abi::snprintf,
            ),
            ("vsnprintf", call_host_vsnprintf, call_vsnprintf),
        ];
        for locale in [c"C.UTF-8", c"fr_FR", c"C"] {
            select(locale);
            for (entry, host_print, native_print) in entries {
                for capacity in [0, 1, 4, 64] {
                    for width in [-5, 0, 5] {
                        for precision in [0, 1, 2, 3, 6, -1] {
                            for input in [
                                [0xe9, 0x41, 0, 0],
                                [0x41, 0xd800, 0x42, 0],
                                [0x41, 0x110000, 0x42, 0],
                                [0, 0, 0, 0],
                            ] {
                                let mut expected = None;
                                for (print, errno) in [
                                    (host_print, host().errno),
                                    (native_print, errno_abi::__errno_location as ErrnoFn),
                                ] {
                                    let mut output = [0xa5u8; 64];
                                    let (mut before, mut after) = (SENTINEL, SENTINEL);
                                    // SAFETY: the format matches two %n pointers,
                                    // two promoted ints and a terminated wchar array;
                                    // capacity fits the entire writable output.
                                    let observed = unsafe {
                                        *errno() = 23;
                                        let rc = print(
                                            output.as_mut_ptr().cast(),
                                            capacity,
                                            c"P%n%*.*ls%nQ".as_ptr(),
                                            &mut before,
                                            width,
                                            precision,
                                            input.as_ptr(),
                                            &mut after,
                                        );
                                        (rc, *errno(), before, after, output)
                                    };
                                    if let Some(expected) = expected {
                                        assert_eq!(
                                            observed, expected,
                                            "{locale:?}/{entry} cap={capacity} width={width} precision={precision} input={input:?}"
                                        );
                                    } else {
                                        expected = Some(observed);
                                    }
                                }
                            }
                        }
                        for wc in [0u32, 0xe9, 0x20ac, 0xd800, 0x110000, 0x80000000] {
                            let mut expected = None;
                            for (print, errno) in [
                                (host_print, host().errno),
                                (native_print, errno_abi::__errno_location as ErrnoFn),
                            ] {
                                let mut output = [0xa5u8; 64];
                                let (mut before, mut after) = (SENTINEL, SENTINEL);
                                // SAFETY: each %n owns its int, %lc takes the
                                // promoted wint_t, and capacity fits output.
                                let observed = unsafe {
                                    *errno() = 23;
                                    let rc = print(
                                        output.as_mut_ptr().cast(),
                                        capacity,
                                        c"P%n%*lc%nQ".as_ptr(),
                                        &mut before,
                                        width,
                                        wc,
                                        &mut after,
                                    );
                                    (rc, *errno(), before, after, output)
                                };
                                if let Some(expected) = expected {
                                    assert_eq!(
                                        observed, expected,
                                        "{locale:?}/{entry} cap={capacity} width={width} wc={wc:#x}"
                                    );
                                } else {
                                    expected = Some(observed);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn descriptor_output_errors_are_scoped_to_call() {
        if !isolated("descriptor_output_errors_are_scoped_to_call") {
            return;
        }
        select(c"C");
        type DprintfFn = unsafe extern "C-unwind" fn(c_int, *const c_char, ...) -> c_int;
        type VdprintfFn = unsafe extern "C-unwind" fn(c_int, *const c_char, *mut c_void) -> c_int;

        unsafe extern "C-unwind" fn native_vdprintf(
            fd: c_int,
            format: *const c_char,
            mut args: ...
        ) -> c_int {
            // SAFETY: the promoted arguments match the live va_list and format.
            unsafe { stdio_abi::vdprintf(fd, format, std::ptr::addr_of_mut!(args).cast()) }
        }

        unsafe extern "C-unwind" fn host_vdprintf(
            fd: c_int,
            format: *const c_char,
            mut args: ...
        ) -> c_int {
            static PRINT: OnceLock<VdprintfFn> = OnceLock::new();
            let print = *PRINT.get_or_init(|| {
                // SAFETY: this independent GNU provider has the declared ABI.
                unsafe { host_fn(c"vdprintf", stdio_abi::vdprintf as *const ()) }
            });
            // SAFETY: the descriptor and promoted arguments belong to this call.
            unsafe { print(fd, format, std::ptr::addr_of_mut!(args).cast()) }
        }

        // SAFETY: each GNU symbol has this exact variadic C ABI.
        let host_dprintf: DprintfFn =
            unsafe { host_fn(c"dprintf", stdio_abi::dprintf as *const ()) };
        let host_snprintf: SnprintfFn =
            unsafe { host_fn(c"snprintf", stdio_abi::snprintf as *const ()) };
        for (entry, host_print, native_print, access) in [
            (
                "dprintf",
                host_dprintf,
                stdio_abi::dprintf as DprintfFn,
                libc::O_RDONLY,
            ),
            (
                "vdprintf",
                host_vdprintf as DprintfFn,
                native_vdprintf as DprintfFn,
                libc::O_RDONLY,
            ),
            (
                "dprintf",
                host_dprintf,
                stdio_abi::dprintf as DprintfFn,
                libc::O_WRONLY,
            ),
            (
                "vdprintf",
                host_vdprintf as DprintfFn,
                native_vdprintf as DprintfFn,
                libc::O_WRONLY,
            ),
        ] {
            for format in [c"P%lc", c"P%2147483648d", c"P%d"] {
                for next_format in [c"OK", c"%s", c"%s\n"] {
                    let mut expected = None;
                    for (engine, print, next_print, errno) in [
                        ("host", host_print, host_snprintf, host().errno),
                        (
                            "native",
                            native_print,
                            stdio_abi::snprintf as SnprintfFn,
                            errno_abi::__errno_location as ErrnoFn,
                        ),
                    ] {
                        // SAFETY: open the existing device without O_CREAT or
                        // O_TRUNC. Each live fd is closed after both calls and
                        // before any assertion; no file is created or removed.
                        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), access) };
                        assert!(fd >= 0);
                        let mut output = [0xa5u8; 16];
                        // SAFETY: the first call's promoted argument matches
                        // its format, and the next call owns a live destination.
                        // Extra variadic arguments to a literal format are legal.
                        let (first_result, first_error, next_result, next_error) = unsafe {
                            *errno() = 23;
                            let rc = if format == c"P%lc" {
                                print(fd, format.as_ptr(), 0xe9u32)
                            } else {
                                print(fd, format.as_ptr(), 7 as c_int)
                            };
                            let error = *errno();
                            *errno() = 23;
                            let next = next_print(
                                output.as_mut_ptr().cast(),
                                output.len(),
                                next_format.as_ptr(),
                                c"OK".as_ptr(),
                            );
                            (rc, error, next, *errno())
                        };
                        // SAFETY: fd is the still-live descriptor opened above;
                        // neither printf call owns or closes it.
                        assert_eq!(unsafe { libc::close(fd) }, 0);
                        let observed = (first_result, first_error, next_result, next_error, output);
                        eprintln!(
                            "{entry}/{engine} access={access} {format:?} then {next_format:?}: {observed:?}"
                        );
                        if let Some(expected) = expected.as_ref() {
                            assert_eq!(
                                &observed, expected,
                                "{entry}/{engine} access={access} {format:?} then {next_format:?}"
                            );
                        } else {
                            let expected_first_call = if format == c"P%lc" {
                                (-1, libc::EILSEQ)
                            } else if format == c"P%2147483648d" {
                                (-1, libc::EOVERFLOW)
                            } else if access == libc::O_RDONLY {
                                (-1, libc::EBADF)
                            } else {
                                (2, 23)
                            };
                            assert_eq!((first_result, first_error), expected_first_call);
                            assert!(next_result > 0);
                            assert_eq!(next_error, 23);
                            expected = Some(observed);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn allocated_output_failure_stops_later_count_stores() {
        if !isolated("allocated_output_failure_stops_later_count_stores") {
            return;
        }
        type AsprintfFn =
            unsafe extern "C-unwind" fn(*mut *mut c_char, *const c_char, ...) -> c_int;
        // SAFETY: resolve the independent GNU provider before imposing the
        // temporary address-space limit; its signature matches asprintf.
        let host_print: AsprintfFn =
            unsafe { host_fn(c"asprintf", stdio_abi::asprintf as *const ()) };
        let entries = [
            ("host", host_print, host().errno, host().free),
            (
                "native",
                stdio_abi::asprintf as AsprintfFn,
                errno_abi::__errno_location as ErrnoFn,
                malloc_abi::free as FreeFn,
            ),
        ];
        // Small valid fields warm both allocators and prove the count stores
        // work. Large fields, literals, and strings need more output memory
        // than the additional mappings allowed for either actual call.
        for width in [4, 128 * 1024 * 1024] {
            for left in [false, true] {
                let kinds: &[&str] = if left {
                    &["d", "s"]
                } else {
                    &["d", "s", "literal", "bare_s", "precision_s"]
                };
                for &kind in kinds {
                    let text = if kind == "literal" {
                        format!("P%n{}%nQ", "A".repeat(width))
                    } else if kind == "bare_s" {
                        "P%n%s%nQ".to_owned()
                    } else if kind == "precision_s" {
                        format!("P%n%.{width}s%nQ")
                    } else {
                        format!("P%n%{}{width}{kind}%nQ", if left { "-" } else { "" })
                    };
                    let format = std::ffi::CString::new(text.as_bytes()).unwrap();
                    // Allocate the large input before imposing the limit. Only
                    // the formatter's output growth should fail, including
                    // the literal and bare-%s paths that skip the field code.
                    let string = matches!(kind, "bare_s" | "precision_s")
                        .then(|| std::ffi::CString::new(vec![b'A'; width]).unwrap());
                    let mut expected = None;
                    for (engine, print, errno, free) in entries {
                        let (mut before, mut after) = (SENTINEL, SENTINEL);
                        let mut output = std::ptr::null_mut();
                        let status = std::fs::read_to_string("/proc/self/status").unwrap();
                        let vm_kib = status
                            .lines()
                            .find(|line| line.starts_with("VmSize:"))
                            .and_then(|line| line.split_whitespace().nth(1))
                            .expect("Linux supplies VmSize")
                            .parse::<libc::rlim_t>()
                            .unwrap();
                        let ceiling = vm_kib
                            .checked_mul(1024)
                            .and_then(|bytes| bytes.checked_add(64 * 1024 * 1024))
                            .unwrap();
                        let mut previous = libc::rlimit {
                            rlim_cur: 0,
                            rlim_max: 0,
                        };
                        // SAFETY: the limit structures are initialized and
                        // writable. Restore the exact previous limit before
                        // allocating observations, asserting, or unwinding.
                        assert_eq!(
                            unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut previous) },
                            0
                        );
                        let constrained = libc::rlimit {
                            rlim_cur: ceiling.min(previous.rlim_cur),
                            rlim_max: previous.rlim_max,
                        };
                        // SAFETY: the initialized limit keeps the previous hard
                        // ceiling; this isolated child owns its process limits.
                        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &constrained) }, 0);
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            // SAFETY: each promoted argument matches its
                            // terminated format and all count slots are live.
                            unsafe {
                                *errno() = 23;
                                let rc = if kind == "d" {
                                    print(
                                        &mut output,
                                        format.as_ptr(),
                                        &mut before,
                                        7 as c_int,
                                        &mut after,
                                    )
                                } else if kind == "literal" {
                                    print(&mut output, format.as_ptr(), &mut before, &mut after)
                                } else {
                                    print(
                                        &mut output,
                                        format.as_ptr(),
                                        &mut before,
                                        string.as_deref().unwrap_or(c"A").as_ptr(),
                                        &mut after,
                                    )
                                };
                                (rc, *errno(), before, after)
                            }
                        }));
                        // SAFETY: previous is the exact limit read above; only
                        // the soft ceiling changed during the call.
                        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &previous) }, 0);
                        let result =
                            result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
                        // Failed GNU asprintf leaves the out-pointer unspecified.
                        // Compare successful bytes only. Release successful
                        // GNU output and every native block with its own
                        // allocator; do not use GNU's unspecified error output.
                        let bytes = if result.0 >= 0 {
                            assert!(!output.is_null());
                            // SAFETY: a successful provider result owns a live,
                            // NUL-terminated string until its matching free.
                            unsafe { CStr::from_ptr(output).to_bytes().to_vec() }
                        } else {
                            Vec::new()
                        };
                        if !output.is_null() && (result.0 >= 0 || engine == "native") {
                            // SAFETY: free matches this provider. Native returns
                            // its owned block even if rendering had failed.
                            unsafe { free(output.cast()) };
                        }
                        eprintln!("{engine} width={width} left={left} kind={kind}: {result:?}");
                        if engine == "host" && width != 4 {
                            assert_eq!(
                                result,
                                (-1, libc::ENOMEM, 1, SENTINEL),
                                "GNU width={width} left={left} kind={kind}"
                            );
                        }
                        let observed = (result, bytes);
                        if let Some(expected) = expected.as_ref() {
                            assert_eq!(
                                &observed, expected,
                                "{engine} width={width} left={left} kind={kind}"
                            );
                        } else {
                            expected = Some(observed);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn formatted_output_field_overflow_keeps_completed_prefix() {
        if !isolated("formatted_output_field_overflow_keeps_completed_prefix") {
            return;
        }
        select(c"C.UTF-8");
        type SwprintfFn = unsafe extern "C-unwind" fn(*mut Wc, usize, *const Wc, ...) -> c_int;
        #[derive(Clone, Copy)]
        enum Print {
            Narrow(SnprintfFn),
            Wide(SwprintfFn),
        }
        // SAFETY: each independent GNU symbol has the declared variadic ABI.
        let entries = unsafe {
            [
                (
                    "swprintf",
                    Print::Wide(host_fn(c"swprintf", fl::swprintf as *const ())),
                    Print::Wide(fl::swprintf),
                ),
                (
                    "snprintf",
                    Print::Narrow(host_fn(c"snprintf", stdio_abi::snprintf as *const ())),
                    Print::Narrow(stdio_abi::snprintf),
                ),
                (
                    "vsnprintf",
                    Print::Narrow(call_host_vsnprintf),
                    Print::Narrow(call_vsnprintf),
                ),
            ]
        };
        // Warm the native allocator before a temporary, per-call limit. The
        // limit prevents a regression from reserving gigabytes for padding.
        let warm = unsafe { malloc_abi::malloc(64) };
        assert!(!warm.is_null());
        unsafe { malloc_abi::free(warm) };
        for field in [
            "18446744073709551615",
            "2147483648",
            "18446744073709551616",
            "4",
        ] {
            for precision in [false, true] {
                for kind in ["lc", "ls", "s", "d"] {
                    for counts in [true, false] {
                        let conversion =
                            format!("%{}{field}{kind}", if precision { "." } else { "" });
                        let text = if counts {
                            format!("P%n{conversion}%nQ")
                        } else {
                            format!("P{conversion}Q")
                        };
                        let narrow_format = std::ffi::CString::new(text.as_bytes()).unwrap();
                        let wide_format = w(&text);
                        let input = [0x110000u32, 0];
                        for (entry, host_print, native_print) in entries {
                            let mut expected = None;
                            for (engine, print, errno) in [
                                ("host", host_print, host().errno),
                                (
                                    "native",
                                    native_print,
                                    errno_abi::__errno_location as ErrnoFn,
                                ),
                            ] {
                                let (mut before, mut after) = (SENTINEL, SENTINEL);
                                let mut narrow_output = [0xa5u8; 64];
                                let mut wide_output = [SENTINEL as Wc; 64];
                                let status = std::fs::read_to_string("/proc/self/status").unwrap();
                                let vm_kib = status
                                    .lines()
                                    .find(|line| line.starts_with("VmSize:"))
                                    .and_then(|line| line.split_whitespace().nth(1))
                                    .expect("Linux supplies VmSize")
                                    .parse::<libc::rlim_t>()
                                    .unwrap();
                                let ceiling = vm_kib
                                    .checked_mul(1024)
                                    .and_then(|bytes| bytes.checked_add(64 * 1024 * 1024))
                                    .unwrap();
                                let mut previous = libc::rlimit {
                                    rlim_cur: 0,
                                    rlim_max: 0,
                                };
                                assert_eq!(
                                    unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut previous) },
                                    0
                                );
                                let constrained = libc::rlimit {
                                    rlim_cur: ceiling.min(previous.rlim_cur),
                                    rlim_max: previous.rlim_max,
                                };
                                assert_eq!(
                                    unsafe { libc::setrlimit(libc::RLIMIT_AS, &constrained) },
                                    0
                                );
                                // Keep the actual promoted argument types, including
                                // the optional count pointers, for every format.
                                macro_rules! invoke {
                                    ($print:expr, $output:expr, $format:expr) => {
                                        match (counts, kind) {
                                            (true, "lc") => $print(
                                                $output,
                                                64,
                                                $format,
                                                &mut before,
                                                input[0],
                                                &mut after,
                                            ),
                                            (true, "ls") => $print(
                                                $output,
                                                64,
                                                $format,
                                                &mut before,
                                                input.as_ptr(),
                                                &mut after,
                                            ),
                                            (true, "s") => $print(
                                                $output,
                                                64,
                                                $format,
                                                &mut before,
                                                c"A".as_ptr(),
                                                &mut after,
                                            ),
                                            (true, _) => $print(
                                                $output,
                                                64,
                                                $format,
                                                &mut before,
                                                7 as c_int,
                                                &mut after,
                                            ),
                                            (false, "lc") => $print($output, 64, $format, input[0]),
                                            (false, "ls") => {
                                                $print($output, 64, $format, input.as_ptr())
                                            }
                                            (false, "s") => {
                                                $print($output, 64, $format, c"A".as_ptr())
                                            }
                                            (false, _) => $print($output, 64, $format, 7 as c_int),
                                        }
                                    };
                                }
                                // SAFETY: buffers, terminated formats and promoted
                                // arguments match each provider. Restore the limit
                                // even if native Rust reports an arithmetic panic.
                                let result = std::panic::catch_unwind(
                                    std::panic::AssertUnwindSafe(|| unsafe {
                                        *errno() = 23;
                                        let rc = match print {
                                            Print::Narrow(print) => invoke!(
                                                print,
                                                narrow_output.as_mut_ptr().cast(),
                                                narrow_format.as_ptr()
                                            ),
                                            Print::Wide(print) => invoke!(
                                                print,
                                                wide_output.as_mut_ptr(),
                                                wide_format.as_ptr()
                                            ),
                                        };
                                        (rc, *errno(), before, after)
                                    }),
                                );
                                assert_eq!(
                                    unsafe { libc::setrlimit(libc::RLIMIT_AS, &previous) },
                                    0
                                );
                                let result = result.unwrap_or_else(|panic| {
                                    eprintln!("{entry}/{engine} format={text:?}");
                                    std::panic::resume_unwind(panic)
                                });
                                let output: Vec<u32> = match print {
                                    Print::Narrow(_) => {
                                        narrow_output.iter().copied().map(u32::from).collect()
                                    }
                                    Print::Wide(_) => {
                                        wide_output.iter().map(|&wc| wc as u32).collect()
                                    }
                                };
                                let observed = (result, output);
                                if let Some(expected) = expected.as_ref() {
                                    assert_eq!(
                                        &observed, expected,
                                        "{entry}/{engine} format={text:?}"
                                    );
                                } else {
                                    if field != "4" {
                                        assert_eq!(result.0, -1, "GNU {entry} format={text:?}");
                                        assert_eq!(
                                            result.1,
                                            libc::EOVERFLOW,
                                            "GNU {entry} format={text:?}"
                                        );
                                    }
                                    expected = Some(observed);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn wide_output_preserves_extended_wide_arguments() {
        if !isolated("wide_output_preserves_extended_wide_arguments") {
            return;
        }
        type SwprintfFn = unsafe extern "C-unwind" fn(*mut Wc, usize, *const Wc, ...) -> c_int;
        type OpenWideMemoryFn = unsafe extern "C" fn(*mut *mut u32, *mut usize) -> *mut c_void;
        // SAFETY: the GNU symbol has this exact variadic ABI.
        let host_print: SwprintfFn = unsafe { host_fn(c"swprintf", fl::swprintf as *const ()) };
        // SAFETY: both providers expose the same pointer/size ABI.
        let host_open: OpenWideMemoryFn =
            unsafe { host_fn(c"open_wmemstream", fl::open_wmemstream as *const ()) };
        for locale in [c"C.UTF-8", c"fr_FR", c"C"] {
            select(locale);
            for wc in [0x110000, 0x200000, 0x4000000, 0x7fffffff] {
                for width in [0, -4, 4] {
                    let input = [wc, Wc::from(b'A'), 0];
                    let format = w("P%*.*ls%*lc%nQ");
                    let mut expected = None;
                    for (print, errno) in [
                        (host_print, host().errno),
                        (
                            fl::swprintf as SwprintfFn,
                            errno_abi::__errno_location as ErrnoFn,
                        ),
                    ] {
                        let mut output = [SENTINEL as Wc; 32];
                        let mut count = SENTINEL;
                        // SAFETY: format and input are terminated wchar arrays;
                        // the argument types match, with a live count and buffer.
                        let observed = unsafe {
                            *errno() = 23;
                            let rc = print(
                                output.as_mut_ptr(),
                                output.len(),
                                format.as_ptr(),
                                width,
                                1,
                                input.as_ptr(),
                                width,
                                wc as u32,
                                &mut count,
                            );
                            (rc, *errno(), count, output)
                        };
                        if let Some(expected) = expected {
                            assert_eq!(observed, expected, "{locale:?} width={width} wc={wc:#x}");
                        } else {
                            assert_eq!(observed.0, if width == 0 { 4 } else { 10 });
                            expected = Some(observed);
                        }
                    }
                    // Public wide memory streams use the buffered callback
                    // sink, unlike the bounded swprintf sink above.
                    for entry in ["fwprintf", "vfwprintf"] {
                        let mut expected = None;
                        for engine in wide_io_engines() {
                            let (open, free, print): (OpenWideMemoryFn, FreeFn, FwprintfFn) =
                                if engine.name == "host" {
                                    (
                                        host_open,
                                        host().free,
                                        if entry == "fwprintf" {
                                            host_fwprintf()
                                        } else {
                                            call_host_vfwprintf
                                        },
                                    )
                                } else {
                                    (
                                        fl::open_wmemstream,
                                        malloc_abi::free,
                                        if entry == "fwprintf" {
                                            fl::fwprintf
                                        } else {
                                            call_vfwprintf
                                        },
                                    )
                                };
                            let (mut output, mut length) = (std::ptr::null_mut(), 0);
                            let mut count = SENTINEL;
                            // SAFETY: this provider owns the stream and output
                            // allocation through close, then its matching free.
                            // The format and promoted varargs match the call.
                            let observed = unsafe {
                                let stream = open(&mut output, &mut length);
                                assert!(!stream.is_null());
                                *(engine.errno)() = 23;
                                let rc = print(
                                    stream,
                                    format.as_ptr(),
                                    width,
                                    1,
                                    input.as_ptr(),
                                    width,
                                    wc as u32,
                                    &mut count,
                                );
                                let error = *(engine.errno)();
                                assert_eq!((engine.close)(stream), 0);
                                assert!(!output.is_null());
                                let contents =
                                    std::slice::from_raw_parts(output, length + 1).to_vec();
                                free(output.cast());
                                (rc, error, count, length, contents)
                            };
                            if let Some(expected) = expected.as_ref() {
                                assert_eq!(
                                    &observed, expected,
                                    "{locale:?}/{entry} width={width} wc={wc:#x}"
                                );
                            } else {
                                assert_eq!(observed.0, if width == 0 { 4 } else { 10 });
                                expected = Some(observed);
                            }
                        }
                    }
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
            for (format, terminated) in [("%2s%n", true), ("%2c%n", false), ("%2[^X]%n", true)] {
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
                    assert_eq!(&out[..len], &expected[..len], "{} wide output", engine.name);
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
                let rc = unsafe { (engine.scan)(w("êX").as_ptr(), w("é%n").as_ptr(), &mut n) };
                assert_eq!((rc, n), (0, SENTINEL), "{} scalar literal", engine.name);
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
                    let input = w(&format!("{}{token} 9", if prior { "7 " } else { "" }));
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
                assert_eq!((rc, value, n), (1, 9, 5), "{} suppression", engine.name);
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
            assert_eq!((rc, number, n), (2, 8, 3), "{} repeated index", engine.name);

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
            let rc =
                unsafe { (engine.scan)(w("").as_ptr(), w("%n%mc").as_ptr(), &mut n, &mut pointer) };
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
                    let rc =
                        (engine.scan)(w(input).as_ptr(), w(format).as_ptr(), &mut pointer, &mut n);
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
