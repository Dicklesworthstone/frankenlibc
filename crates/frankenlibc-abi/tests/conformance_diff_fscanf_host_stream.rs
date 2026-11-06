#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // variadic scanf calls against a foreign FILE*

//! `fscanf` and `__isoc99_fscanf` must do the same thing to a HOST-owned `FILE*`.
//!
//! ## The split this gate exists for
//!
//! `<stdio.h>` redirects every compiled `fscanf` call to `__isoc99_fscanf` (or
//! `__isoc23_fscanf` under a C23 default), and fl's aliases forward to
//! `vfscanf`. But `vfscanf` and `fscanf` are two SEPARATE implementations here,
//! and only one of them carries the host-delegation path:
//!
//! ```ignore
//! // vfscanf, and NOT fscanf:
//! if may_delegate_to_host(stream, id) && let Some(host) = host_vfscanf_fn() {
//!     return host(stream, format, ap);
//! }
//! ```
//!
//! `may_delegate_to_host` is true exactly when the stream is NOT in fl's
//! registry — a `FILE*` fl did not create. So for a stream opened by host glibc:
//!
//! - a C program, which reaches `__isoc99_fscanf` -> `vfscanf`, is served by
//!   host glibc and parses correctly;
//! - anything calling `fscanf` by name gets fl's engine pointed at a stream it
//!   knows nothing about.
//!
//! The tested path was not the shipped path, in the direction that hides
//! trouble: fl's whole fscanf suite calls `fscanf` by name, so it exercises the
//! engine, while every real caller was quietly getting glibc. This is the same
//! redirected-symbol class as the `sscanf` fast path (6ee799f05), found by
//! following it to the rest of the family (bd-r8hpym).
//!
//! ## Why the oracle is a host stream and not an fl one
//!
//! An fl-created `FILE*` IS in the registry, so `may_delegate_to_host` is false
//! and both paths run the engine — identical, and the divergence invisible.
//! Only a foreign stream separates them, which is why this gate opens its input
//! with host glibc's `fopen` and closes it with host glibc's `fclose`.

use std::ffi::{CString, c_char, c_int, c_void};
use std::io::Write;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

type FscanfFn = unsafe extern "C-unwind" fn(*mut c_void, *const c_char, ...) -> c_int;
type FopenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type FcloseFn = unsafe extern "C-unwind" fn(*mut c_void) -> c_int;

/// What one arm produced: the return code and both destinations.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    rc: c_int,
    word: String,
    num: c_int,
}

/// The result sequence from repeated exact `%c` conversions.
#[derive(Debug, PartialEq, Eq)]
struct CharOutcome {
    results: [(c_int, u8); 3],
}

/// Open the file with HOST glibc, run `f` over it, close it with HOST glibc.
///
/// Each arm gets its own open so no arm inherits another's file position.
fn run_arm(f: FscanfFn, path: &CString, fopen: FopenFn, fclose: FcloseFn) -> Outcome {
    let mode = CString::new("r").expect("mode has NUL");
    // SAFETY: both strings are NUL-terminated.
    let stream = unsafe { fopen(path.as_ptr(), mode.as_ptr()) };
    assert!(!stream.is_null(), "host fopen failed");

    let fmt = CString::new("%s %d").expect("format has NUL");
    let mut word = [0u8; 64];
    let mut num: c_int = -777;
    // SAFETY: the format takes one `char *` and one `int *`, and both are
    // supplied; `word` is far larger than the token in the file.
    let rc = unsafe {
        f(
            stream,
            fmt.as_ptr(),
            word.as_mut_ptr().cast::<c_char>(),
            &mut num as *mut c_int,
        )
    };
    // SAFETY: `stream` came from the host `fopen` above and is closed once.
    unsafe { fclose(stream) };

    let end = word.iter().position(|&b| b == 0).unwrap_or(word.len());
    Outcome {
        rc,
        word: String::from_utf8_lossy(&word[..end]).into_owned(),
        num,
    }
}

/// Open a provider-owned stream and run two exact character conversions plus
/// the EOF probe. Each arm owns its own stream, so its cursor cannot be
/// inherited from the other provider.
fn run_char_arm(f: FscanfFn, path: &CString, fopen: FopenFn, fclose: FcloseFn) -> CharOutcome {
    let stream = unsafe { fopen(path.as_ptr(), c"r".as_ptr()) };
    assert!(!stream.is_null(), "provider fopen failed");

    let mut first = 0u8;
    let mut second = 0u8;
    let mut eof = 0u8;
    let results = unsafe {
        [
            (
                f(
                    stream,
                    c"%c".as_ptr(),
                    (&mut first as *mut u8).cast::<c_char>(),
                ),
                first,
            ),
            (
                f(
                    stream,
                    c"%c".as_ptr(),
                    (&mut second as *mut u8).cast::<c_char>(),
                ),
                second,
            ),
            (
                f(
                    stream,
                    c"%c".as_ptr(),
                    (&mut eof as *mut u8).cast::<c_char>(),
                ),
                eof,
            ),
        ]
    };
    assert_eq!(unsafe { fclose(stream) }, 0, "provider fclose failed");
    CharOutcome { results }
}

#[test]
fn fscanf_and_its_isoc_aliases_agree_on_a_host_owned_stream() {
    let dir = std::env::temp_dir().join("fl_fscanf_host_stream");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("input.txt");
    {
        let mut f = std::fs::File::create(&path).expect("create input");
        writeln!(f, "hello 42").expect("write input");
    }
    let cpath = CString::new(path.to_str().expect("utf-8 path")).expect("path has NUL");

    // The host arms. `host_fn` asserts each resolved address is NOT fl's own, so
    // a collapsed oracle fails loudly instead of comparing fl against itself.
    let fopen: FopenFn =
        unsafe { host_fn(c"fopen", frankenlibc_abi::stdio_abi::fopen as *const ()) };
    let fclose: FcloseFn =
        unsafe { host_fn(c"fclose", frankenlibc_abi::stdio_abi::fclose as *const ()) };
    let glibc_fscanf: FscanfFn = unsafe {
        host_fn(
            c"__isoc23_fscanf",
            frankenlibc_abi::isoc_abi::__isoc23_fscanf as *const (),
        )
    };

    let want = run_arm(glibc_fscanf, &cpath, fopen, fclose);
    println!("glibc __isoc23_fscanf -> {want:?}");

    // Assert the oracle actually parsed, so the comparison below cannot be
    // satisfied by three arms all failing the same way.
    assert_eq!(
        want,
        Outcome {
            rc: 2,
            word: "hello".to_string(),
            num: 42
        },
        "the host oracle did not parse the file, so this gate is comparing nothing"
    );

    for (name, arm) in [
        ("fscanf", frankenlibc_abi::stdio_abi::fscanf as FscanfFn),
        (
            "__isoc99_fscanf",
            frankenlibc_abi::stdio_abi::__isoc99_fscanf as FscanfFn,
        ),
        (
            "__isoc23_fscanf",
            frankenlibc_abi::isoc_abi::__isoc23_fscanf as FscanfFn,
        ),
    ] {
        let got = run_arm(arm, &cpath, fopen, fclose);
        println!("fl {name} -> {got:?}");
        assert_eq!(
            got, want,
            "fl {name} on a HOST-owned FILE* produced {got:?}, host glibc produced {want:?}. \
             The aliases delegate a foreign stream to the host and `fscanf` did not, so the \
             symbol a compiler emits and the symbol fl's own tests call were two different \
             implementations (bd-r8hpym)."
        );
    }
}

#[test]
fn fscanf_exact_char_on_an_fl_owned_stream_matches_glibc_cursor_and_eof() {
    let dir = std::env::temp_dir().join("fl_fscanf_exact_char_stream");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("input.txt");
    std::fs::write(&path, b"xy").expect("write input");
    let cpath = CString::new(path.to_str().expect("utf-8 path")).expect("path has NUL");

    let host_fopen: FopenFn =
        unsafe { host_fn(c"fopen", frankenlibc_abi::stdio_abi::fopen as *const ()) };
    let host_fclose: FcloseFn =
        unsafe { host_fn(c"fclose", frankenlibc_abi::stdio_abi::fclose as *const ()) };
    let glibc_fscanf: FscanfFn = unsafe {
        host_fn(
            c"__isoc23_fscanf",
            frankenlibc_abi::isoc_abi::__isoc23_fscanf as *const (),
        )
    };

    let want = run_char_arm(glibc_fscanf, &cpath, host_fopen, host_fclose);
    assert_eq!(
        want,
        CharOutcome {
            results: [(1, b'x'), (1, b'y'), (libc::EOF, 0)],
        },
        "the host oracle did not prove ordinary two-byte cursor and EOF behaviour"
    );

    let got = run_char_arm(
        frankenlibc_abi::stdio_abi::fscanf as FscanfFn,
        &cpath,
        frankenlibc_abi::stdio_abi::fopen as FopenFn,
        frankenlibc_abi::stdio_abi::fclose as FcloseFn,
    );
    assert_eq!(
        got, want,
        "FL-owned stream exact %c sequence diverged from glibc: got {got:?}, want {want:?}"
    );
}

#[test]
fn scanf_and_its_isoc_aliases_exact_char_matches_glibc_on_stdin() {
    type ScanfFn = unsafe extern "C-unwind" fn(*const c_char, ...) -> c_int;

    let glibc_scanf: ScanfFn = unsafe {
        host_fn(
            c"__isoc23_scanf",
            frankenlibc_abi::isoc_abi::__isoc23_scanf as *const (),
        )
    };

    fn child_verdict(child: impl FnOnce() -> bool) -> bool {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let ok = child();
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut status: c_int = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(w, pid, "waitpid failed");
        assert!(libc::WIFEXITED(status), "child did not exit normally");
        libc::WEXITSTATUS(status) == 0
    }

    let run_arm = |s_fn: ScanfFn| -> bool {
        child_verdict(|| {
            let mut pipe_fds = [0i32; 2];
            if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
                return false;
            }
            let input = b"xy";
            if unsafe { libc::write(pipe_fds[1], input.as_ptr().cast(), input.len()) }
                != input.len() as isize
            {
                return false;
            }
            unsafe { libc::close(pipe_fds[1]) };
            if unsafe { libc::dup2(pipe_fds[0], libc::STDIN_FILENO) } != libc::STDIN_FILENO {
                return false;
            }
            unsafe { libc::close(pipe_fds[0]) };

            let mut first = 0u8;
            let mut second = 0u8;
            let mut eof = 0u8;
            let r1 = unsafe { s_fn(c"%c".as_ptr(), (&mut first as *mut u8).cast::<c_char>()) };
            let r2 = unsafe { s_fn(c"%c".as_ptr(), (&mut second as *mut u8).cast::<c_char>()) };
            let r3 = unsafe { s_fn(c"%c".as_ptr(), (&mut eof as *mut u8).cast::<c_char>()) };
            r1 == 1 && first == b'x' && r2 == 1 && second == b'y' && r3 == libc::EOF
        })
    };

    assert!(run_arm(glibc_scanf), "glibc scanf oracle failed");
    assert!(
        run_arm(frankenlibc_abi::stdio_abi::scanf as ScanfFn),
        "fl scanf failed"
    );
    assert!(
        run_arm(frankenlibc_abi::stdio_abi::__isoc99_scanf as ScanfFn),
        "fl __isoc99_scanf failed"
    );
    assert!(
        run_arm(frankenlibc_abi::isoc_abi::__isoc23_scanf as ScanfFn),
        "fl __isoc23_scanf failed"
    );
}

// Actual C va_list forwarding for every narrow/wide stream and string shape.
// Functions are passed in by the test, so the C compiler cannot redirect the
// named legacy/C99/C23 symbol or silently replace the independent host oracle.
const DIALECT_BRIDGE: &str = r#"
#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>
#define STREAM_CALL(T, P, V) \
    (kind == 0 ? ((int (*)(FILE *, const T *, ...))fn)(s, format, V, n) : \
     kind == 1 ? P##_file_v(fn, s, format, V, n) : \
     kind == 2 ? ((int (*)(const T *, ...))fn)(format, V, n) : \
     kind == 3 ? P##_input_v(fn, format, V, n) : -999)
#define STRING_CALL(T, P, V) \
    (is_v ? P##_string_v(fn, input, format, V, n, tail) : \
     ((int (*)(const T *, const T *, ...))fn)(input, format, V, n, tail))
#define BRIDGE(T, P) \
static int P##_binary_format(const T *format) { \
    /* This bridge only receives the numeric formats in the matrix below. */ \
    for (; *format; ++format) if (*format == 'b') return 1; \
    return 0; \
} \
static int P##_file_v(void *fn, FILE *s, const T *format, ...) { \
    va_list ap; va_start(ap, format); \
    int rc = ((int (*)(FILE *, const T *, va_list))fn)(s, format, ap); \
    va_end(ap); return rc; \
} \
static int P##_input_v(void *fn, const T *format, ...) { \
    va_list ap; va_start(ap, format); \
    int rc = ((int (*)(const T *, va_list))fn)(format, ap); \
    va_end(ap); return rc; \
} \
static int P##_string_v(void *fn, const T *input, const T *format, ...) { \
    va_list ap; va_start(ap, format); \
    int rc = ((int (*)(const T *, const T *, va_list))fn)(input, format, ap); \
    va_end(ap); return rc; \
} \
int P##_stream(void *fn, int kind, FILE *s, const T *format, int *value, int *n) { \
    if (P##_binary_format(format)) { \
        unsigned int binary_value = (unsigned int)*value; \
        int rc = STREAM_CALL(T, P, &binary_value); \
        *value = (int)binary_value; return rc; \
    } \
    return STREAM_CALL(T, P, value); \
} \
int P##_string(void *fn, int is_v, const T *input, const T *format, \
               int *value, int *n, T *tail) { \
    if (P##_binary_format(format)) { \
        unsigned int binary_value = (unsigned int)*value; \
        int rc = STRING_CALL(T, P, &binary_value); \
        *value = (int)binary_value; return rc; \
    } \
    return STRING_CALL(T, P, value); \
}
BRIDGE(char, narrow)
BRIDGE(wchar_t, wide)
"#;

type StreamBridge<T> = unsafe extern "C" fn(
    *mut c_void,
    c_int,
    *mut c_void,
    *const T,
    *mut c_int,
    *mut c_int,
) -> c_int;
type StringBridge<T> = unsafe extern "C" fn(
    *mut c_void,
    c_int,
    *const T,
    *const T,
    *mut c_int,
    *mut c_int,
    *mut T,
) -> c_int;
type FtelloFn = unsafe extern "C-unwind" fn(*mut c_void) -> libc::off_t;
type FgetcFn = unsafe extern "C-unwind" fn(*mut c_void) -> c_int;
type FgetwcFn = unsafe extern "C-unwind" fn(*mut c_void) -> u32;

#[derive(Clone, Copy)]
struct ScanFiles {
    open: FopenFn,
    close: FcloseFn,
    tell: FtelloFn,
    get_byte: FgetcFn,
    get_wide: FgetwcFn,
    stdin_cell: *mut *mut c_void,
}

struct ScanDialect {
    prefix: &'static str,
    narrow: [*const (); 4],
    wide: [*const (); 4],
    narrow_string: [*const (); 2],
    wide_string: [*const (); 2],
}

#[derive(Debug, PartialEq, Eq)]
struct PrefixOutcome {
    result: c_int,
    value: c_int,
    consumed: c_int,
    position: libc::off_t,
    tail: c_int,
}

fn run_prefix_stream<T>(
    bridge: StreamBridge<T>,
    target: *mut c_void,
    kind: c_int,
    format: *const T,
    path: &CString,
    files: ScanFiles,
    wide: bool,
) -> PrefixOutcome {
    let stream = unsafe { (files.open)(path.as_ptr(), c"r".as_ptr()) };
    assert!(!stream.is_null(), "provider fopen failed");
    let saved_stdin = unsafe { files.stdin_cell.read() };
    if kind >= 2 {
        unsafe { files.stdin_cell.write(stream) };
    }
    let mut out = PrefixOutcome {
        result: -999,
        value: 917,
        consumed: -1,
        position: -1,
        tail: -999,
    };
    out.result = unsafe {
        bridge(
            target,
            kind,
            stream,
            format,
            &mut out.value,
            &mut out.consumed,
        )
    };
    if kind >= 2 {
        unsafe { files.stdin_cell.write(saved_stdin) };
    }
    out.position = unsafe { (files.tell)(stream) };
    out.tail = if wide {
        unsafe { (files.get_wide)(stream) as c_int }
    } else {
        unsafe { (files.get_byte)(stream) }
    };
    assert_eq!(unsafe { (files.close)(stream) }, 0);
    out
}

#[test]
fn scanf_dialects_match_gnu_on_owned_and_foreign_narrow_and_wide_streams() {
    use frankenlibc_abi::{dlfcn_abi as dl, isoc_abi as iso, stdio_abi as io, wchar_abi as wc};
    use std::os::unix::ffi::OsStrExt;
    use std::process::Command;

    // Redirected stdin is process state. An exact-test child prevents this
    // matrix from changing the stdin seen by concurrently running tests.
    const TEST: &str = "scanf_dialects_match_gnu_on_owned_and_foreign_narrow_and_wide_streams";
    const CHILD: &str = "FRANKENLIBC_SCANF_DIALECT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .expect("run isolated dialect matrix");
        assert!(
            output.status.success(),
            "dialect child failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }

    let dir = std::env::temp_dir().join(format!("fl_scanf_dialects_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("bridge.c");
    let library = dir.join("bridge.so");
    std::fs::write(&source, DIALECT_BRIDGE).unwrap();
    let output = Command::new("cc")
        .args([
            "-shared",
            "-fPIC",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-nostdlib",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&library)
        .output()
        .expect("compile C va_list bridge");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
    type Symbol = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
    type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
    let open: Open = unsafe { host_fn(c"dlopen", dl::dlopen as *const ()) };
    let symbol: Symbol = unsafe { host_fn(c"dlsym", dl::dlsym as *const ()) };
    let close: Close = unsafe { host_fn(c"dlclose", dl::dlclose as *const ()) };
    let path = CString::new(library.as_os_str().as_bytes()).unwrap();
    let handle = unsafe { open(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "host dlopen of bridge failed");
    let resolve = |name: &std::ffi::CStr| {
        let address = unsafe { symbol(handle, name.as_ptr()) };
        assert!(!address.is_null(), "missing C bridge {name:?}");
        address
    };
    // SAFETY: DIALECT_BRIDGE defines narrow_stream with this exact C signature;
    // resolve rejects null and the bridge handle stays open until after all calls.
    let narrow: StreamBridge<c_char> = unsafe { std::mem::transmute(resolve(c"narrow_stream")) };
    // SAFETY: the same bridge defines wide_stream with wchar_t pointers, matching
    // libc::wchar_t on this Linux target, and its handle remains open below.
    let wide: StreamBridge<libc::wchar_t> = unsafe { std::mem::transmute(resolve(c"wide_stream")) };
    // SAFETY: narrow_string uses exactly StringBridge<char>'s signature and
    // the bridge handle stays open throughout the calls below.
    let narrow_string: StringBridge<c_char> =
        unsafe { std::mem::transmute(resolve(c"narrow_string")) };
    // SAFETY: wide_string has exactly StringBridge<wchar_t>'s seven arguments;
    // its non-null address remains valid until close(handle) after the matrix.
    let wide_string: StringBridge<libc::wchar_t> =
        unsafe { std::mem::transmute(resolve(c"wide_string")) };
    let native_stdin = std::ptr::addr_of_mut!(io::stdin);
    let host_stdin = unsafe {
        dlsym_oracle::host_addr(c"stdin", native_stdin.cast::<()>()).cast::<*mut c_void>()
    };
    let native = ScanFiles {
        open: io::fopen,
        close: io::fclose,
        tell: io::ftello,
        get_byte: io::fgetc,
        get_wide: wc::fgetwc,
        stdin_cell: native_stdin,
    };
    let host = ScanFiles {
        open: unsafe { host_fn(c"fopen", io::fopen as *const ()) },
        close: unsafe { host_fn(c"fclose", io::fclose as *const ()) },
        tell: unsafe { host_fn(c"ftello", io::ftello as *const ()) },
        get_byte: unsafe { host_fn(c"fgetc", io::fgetc as *const ()) },
        get_wide: unsafe { host_fn(c"fgetwc", wc::fgetwc as *const ()) },
        stdin_cell: host_stdin,
    };
    let wchar = |text: &str| {
        text.chars()
            .map(|c| c as libc::wchar_t)
            .chain([0])
            .collect::<Vec<_>>()
    };
    let cases = [
        ("0b101!", "%i%n"),
        ("-0B101!", "%i%n"),
        ("0b!", "%i%n"),
        ("0b2!", "%i%n"),
        ("0b", "%i%n"),
        ("0b101!", "%1i%n"),
        ("0b101!", "%2i%n"),
        ("0b101!", "%3i%n"),
        ("0x!", "%i%n"),
        ("-0X!", "%i%n"),
        ("0x", "%i%n"),
        ("123!", "%i%n"),
        ("?", "%i%n"),
        ("", "%i%n"),
        ("101!", "%b%n"),
        ("0b101!", "%b%n"),
        ("-0B101!", "%b%n"),
        ("+0b101!", "%b%n"),
        ("0b!", "%b%n"),
        ("0b2!", "%b%n"),
        ("0b", "%b%n"),
        ("0b101!", "%1b%n"),
        ("0b101!", "%2b%n"),
        ("0b101!", "%3b%n"),
        ("2!", "%b%n"),
        ("", "%b%n"),
        (" 101!", "%b%n"),
        ("1012!", "%b%n"),
    ];
    let arms = [
        ScanDialect {
            prefix: "",
            narrow: [
                io::fscanf as *const (),
                io::vfscanf as *const (),
                io::scanf as *const (),
                io::vscanf as *const (),
            ],
            wide: [
                wc::fwscanf as *const (),
                wc::vfwscanf as *const (),
                wc::wscanf as *const (),
                wc::vwscanf as *const (),
            ],
            narrow_string: [io::sscanf as *const (), io::vsscanf as *const ()],
            wide_string: [wc::swscanf as *const (), wc::vswscanf as *const ()],
        },
        ScanDialect {
            prefix: "__isoc99_",
            narrow: [
                io::__isoc99_fscanf as *const (),
                io::__isoc99_vfscanf as *const (),
                io::__isoc99_scanf as *const (),
                io::__isoc99_vscanf as *const (),
            ],
            wide: [
                iso::__isoc99_fwscanf as *const (),
                iso::__isoc99_vfwscanf as *const (),
                iso::__isoc99_wscanf as *const (),
                iso::__isoc99_vwscanf as *const (),
            ],
            narrow_string: [
                io::__isoc99_sscanf as *const (),
                io::__isoc99_vsscanf as *const (),
            ],
            wide_string: [
                iso::__isoc99_swscanf as *const (),
                iso::__isoc99_vswscanf as *const (),
            ],
        },
        ScanDialect {
            prefix: "__isoc23_",
            narrow: [
                iso::__isoc23_fscanf as *const (),
                iso::__isoc23_vfscanf as *const (),
                iso::__isoc23_scanf as *const (),
                iso::__isoc23_vscanf as *const (),
            ],
            wide: [
                iso::__isoc23_fwscanf as *const (),
                iso::__isoc23_vfwscanf as *const (),
                iso::__isoc23_wscanf as *const (),
                iso::__isoc23_vwscanf as *const (),
            ],
            narrow_string: [
                iso::__isoc23_sscanf as *const (),
                iso::__isoc23_vsscanf as *const (),
            ],
            wide_string: [
                iso::__isoc23_swscanf as *const (),
                iso::__isoc23_vswscanf as *const (),
            ],
        },
    ];
    let file = dir.join("input");
    let file_name = CString::new(file.as_os_str().as_bytes()).unwrap();
    let mut comparisons = 0;
    for ScanDialect {
        prefix,
        narrow: narrow_arms,
        wide: wide_arms,
        narrow_string: narrow_string_arms,
        wide_string: string_arms,
    } in arms
    {
        for (kind, (narrow_name, wide_name)) in [
            ("fscanf", "fwscanf"),
            ("vfscanf", "vfwscanf"),
            ("scanf", "wscanf"),
            ("vscanf", "vwscanf"),
        ]
        .into_iter()
        .enumerate()
        {
            let narrow_name = CString::new(format!("{prefix}{narrow_name}")).unwrap();
            let wide_name = CString::new(format!("{prefix}{wide_name}")).unwrap();
            let host_narrow = unsafe { dlsym_oracle::host_addr(&narrow_name, narrow_arms[kind]) };
            let host_wide = unsafe { dlsym_oracle::host_addr(&wide_name, wide_arms[kind]) };
            for (input, format) in cases {
                std::fs::write(&file, input).unwrap();
                let fmt = CString::new(format).unwrap();
                let wfmt = wchar(format);
                let expected_narrow = run_prefix_stream(
                    narrow,
                    host_narrow,
                    kind as c_int,
                    fmt.as_ptr(),
                    &file_name,
                    host,
                    false,
                );
                let expected_wide = run_prefix_stream(
                    wide,
                    host_wide,
                    kind as c_int,
                    wfmt.as_ptr(),
                    &file_name,
                    host,
                    true,
                );
                assert_eq!(
                    expected_narrow, expected_wide,
                    "GNU narrow/wide ASCII prefix parity"
                );
                for (owner, files) in [
                    ("native", native),
                    (
                        "foreign",
                        ScanFiles {
                            stdin_cell: native_stdin,
                            ..host
                        },
                    ),
                ] {
                    let got = run_prefix_stream(
                        narrow,
                        narrow_arms[kind].cast_mut().cast(),
                        kind as c_int,
                        fmt.as_ptr(),
                        &file_name,
                        files,
                        false,
                    );
                    assert_eq!(
                        got, expected_narrow,
                        "{narrow_name:?} {owner}: {input:?} {format:?}"
                    );
                    let got = run_prefix_stream(
                        wide,
                        wide_arms[kind].cast_mut().cast(),
                        kind as c_int,
                        wfmt.as_ptr(),
                        &file_name,
                        files,
                        true,
                    );
                    assert_eq!(
                        got, expected_wide,
                        "{wide_name:?} {owner}: {input:?} {format:?}"
                    );
                    comparisons += 2;
                }
            }
        }
        for (is_v, suffix) in ["sscanf", "vsscanf"].into_iter().enumerate() {
            let name = CString::new(format!("{prefix}{suffix}")).unwrap();
            // SAFETY: each exact name has the same signature as its native arm;
            // the oracle rejects self resolution and host libc stays loaded.
            let expected = unsafe { dlsym_oracle::host_addr(&name, narrow_string_arms[is_v]) };
            for (input, format) in cases {
                let text = CString::new(input).unwrap();
                let fmt = CString::new(format!("{format}%c")).unwrap();
                let scan = |target| {
                    let (mut value, mut consumed, mut tail) = (917, -1, b'?' as c_char);
                    // SAFETY: the resolved bridge has this exact signature.
                    // Both strings are NUL-terminated and its three output slots
                    // remain live; each format scans one integer, %n and %c.
                    let rc = unsafe {
                        narrow_string(
                            target,
                            is_v as c_int,
                            text.as_ptr(),
                            fmt.as_ptr(),
                            &mut value,
                            &mut consumed,
                            &mut tail,
                        )
                    };
                    (rc, value, consumed, tail)
                };
                assert_eq!(
                    scan(narrow_string_arms[is_v].cast_mut().cast()),
                    scan(expected),
                    "{name:?}: {input:?} {format:?}"
                );
                comparisons += 1;
            }
        }
        for (is_v, suffix) in ["swscanf", "vswscanf"].into_iter().enumerate() {
            let name = CString::new(format!("{prefix}{suffix}")).unwrap();
            let expected = unsafe { dlsym_oracle::host_addr(&name, string_arms[is_v]) };
            for (input, format) in cases {
                let text = wchar(input);
                let fmt = wchar(&format!("{format}%lc"));
                let scan = |target| {
                    let (mut value, mut consumed, mut tail) = (917, -1, '?' as libc::wchar_t);
                    let rc = unsafe {
                        wide_string(
                            target,
                            is_v as c_int,
                            text.as_ptr(),
                            fmt.as_ptr(),
                            &mut value,
                            &mut consumed,
                            &mut tail,
                        )
                    };
                    (rc, value, consumed, tail)
                };
                assert_eq!(
                    scan(string_arms[is_v].cast_mut().cast()),
                    scan(expected),
                    "{name:?}: {input:?} {format:?}"
                );
                comparisons += 1;
            }
        }
    }
    assert_eq!(comparisons, 1680);
    println!("scanf dialect matrix: {comparisons} exact-symbol GNU comparisons");
    assert_eq!(unsafe { close(handle) }, 0);
}
