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
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
_Static_assert(sizeof(uintptr_t) == 8 && sizeof(void *) == 8, "Linux LP64 bridge");
#define STREAM_CALL(T, P, V) \
    (kind == 0 ? ((int (*)(FILE *, const T *, ...))fn)(s, format, V, n) : \
     kind == 1 ? P##_file_v(fn, s, format, V, n) : \
     kind == 2 ? ((int (*)(const T *, ...))fn)(format, V, n) : \
     kind == 3 ? P##_input_v(fn, format, V, n) : -999)
#define STRING_CALL(T, P, V) \
    (is_v ? P##_string_v(fn, input, format, V, n, tail) : \
     ((int (*)(const T *, const T *, ...))fn)(input, format, V, n, tail))
#define BRIDGE(T, P) \
static int P##_numeric_kind(const T *format) { \
    /* This bridge only receives the numeric formats in the matrix below. */ \
    for (; *format; ++format) { \
        if (*format == 'b') return 1; \
        if (*format == 'p') return 2; \
    } \
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
int P##_stream(void *fn, int kind, FILE *s, const T *format, uint64_t *value, int *n) { \
    int target_kind = P##_numeric_kind(format); \
    if (target_kind == 2) { \
        void *pointer_value = (void *)(uintptr_t)*value; \
        int rc = STREAM_CALL(T, P, &pointer_value); \
        *value = (uint64_t)(uintptr_t)pointer_value; return rc; \
    } \
    if (target_kind == 1) { \
        unsigned int binary_value = (unsigned int)*value; \
        int rc = STREAM_CALL(T, P, &binary_value); \
        *value = binary_value; return rc; \
    } \
    int signed_value = (int)*value; \
    int rc = STREAM_CALL(T, P, &signed_value); \
    *value = (uint64_t)(int64_t)signed_value; return rc; \
} \
int P##_string(void *fn, int is_v, const T *input, const T *format, \
               uint64_t *value, int *n, T *tail) { \
    int target_kind = P##_numeric_kind(format); \
    if (target_kind == 2) { \
        void *pointer_value = (void *)(uintptr_t)*value; \
        int rc = STRING_CALL(T, P, &pointer_value); \
        *value = (uint64_t)(uintptr_t)pointer_value; return rc; \
    } \
    if (target_kind == 1) { \
        unsigned int binary_value = (unsigned int)*value; \
        int rc = STRING_CALL(T, P, &binary_value); \
        *value = binary_value; return rc; \
    } \
    int signed_value = (int)*value; \
    int rc = STRING_CALL(T, P, &signed_value); \
    *value = (uint64_t)(int64_t)signed_value; return rc; \
}
BRIDGE(char, narrow)
BRIDGE(wchar_t, wide)
"#;

type StreamBridge<T> =
    unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, *const T, *mut u64, *mut c_int) -> c_int;
type StringBridge<T> = unsafe extern "C" fn(
    *mut c_void,
    c_int,
    *const T,
    *const T,
    *mut u64,
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
    value: u64,
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
        ("123!", "%p%n"),
        ("0!", "%p%n"),
        ("0x123!", "%p%n"),
        ("ABCdef!", "%p%n"),
        ("-1!", "%p%n"),
        ("+0Xabc!", "%p%n"),
        ("0xffffffffffffffff!", "%p%n"),
        ("8000000000000001!", "%p%n"),
        ("0x!", "%p%n"),
        ("(nil)!", "%p%n"),
        ("(NIL)!", "%p%n"),
        ("(nIl)!", "%p%n"),
        ("(ni!", "%p%n"),
        ("(nil", "%p%n"),
        ("(", "%p%n"),
        ("(nix)!", "%p%n"),
        ("(nil)!", "%3p%n"),
        ("0x1!", "%1p%n"),
        ("0x1!", "%2p%n"),
        ("0x1!", "%3p%n"),
        (" \t123!", "%p%n"),
        ("!", "%p%n"),
        ("", "%p%n"),
        ("0x", "%p%n"),
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
                    let (mut value, mut consumed, mut tail) = (917u64, -1, b'?' as c_char);
                    // SAFETY: the resolved bridge has this exact signature.
                    // Both strings are NUL-terminated and its three output slots
                    // remain live; each format scans one numeric/pointer item,
                    // %n and %c, using typed C temporaries in the bridge.
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
                    let (mut value, mut consumed, mut tail) = (917u64, -1, '?' as libc::wchar_t);
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
    assert_eq!(comparisons, 3120);
    println!("scanf dialect matrix: {comparisons} exact-symbol GNU comparisons");
    assert_eq!(unsafe { close(handle) }, 0);
}

/// These streams are owned by the provider under test. In particular, the
/// native arm cannot silently delegate its FILE to the independent GNU oracle.
mod streaming_narrow {
    use super::{FcloseFn, FscanfFn, host_fn};
    use frankenlibc_abi::{errno_abi, isoc_abi, malloc_abi, stdio_abi as fl};
    use std::ffi::{CStr, c_char, c_int, c_long, c_void};

    type ErrnoFn = unsafe extern "C" fn() -> *mut c_int;
    type CookieOpen =
        unsafe extern "C" fn(*mut c_void, *const c_char, fl::CookieIoFuncs) -> *mut c_void;

    struct Api {
        mem: unsafe extern "C" fn(*mut c_void, usize, *const c_char) -> *mut c_void,
        fd: unsafe extern "C" fn(c_int, *const c_char) -> *mut c_void,
        cookie: CookieOpen,
        close: FcloseFn,
        getc: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
        tell: unsafe extern "C-unwind" fn(*mut c_void) -> c_long,
        eof: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
        error: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
        errno: ErrnoFn,
        free: unsafe extern "C" fn(*mut c_void),
    }

    impl Api {
        fn native() -> Self {
            Self {
                mem: fl::fmemopen,
                fd: fl::fdopen,
                cookie: fl::fopencookie,
                close: fl::fclose,
                getc: fl::fgetc,
                tell: fl::ftell,
                eof: fl::feof,
                error: fl::ferror,
                errno: errno_abi::__errno_location,
                free: malloc_abi::free,
            }
        }

        fn host() -> Self {
            // SAFETY: each signature matches its C symbol, and host_fn rejects
            // addresses equal to the native implementation being tested.
            unsafe {
                Self {
                    mem: host_fn(c"fmemopen", fl::fmemopen as *const ()),
                    fd: host_fn(c"fdopen", fl::fdopen as *const ()),
                    cookie: host_fn(c"fopencookie", fl::fopencookie as *const ()),
                    close: host_fn(c"fclose", fl::fclose as *const ()),
                    getc: host_fn(c"fgetc", fl::fgetc as *const ()),
                    tell: host_fn(c"ftell", fl::ftell as *const ()),
                    eof: host_fn(c"feof", fl::feof as *const ()),
                    error: host_fn(c"ferror", fl::ferror as *const ()),
                    errno: host_fn(
                        c"__errno_location",
                        errno_abi::__errno_location as *const (),
                    ),
                    free: host_fn(c"free", malloc_abi::free as *const ()),
                }
            }
        }

        fn status(&self, stream: *mut c_void) -> (c_int, bool, bool) {
            // SAFETY: callers retain this provider's live FILE for the query.
            unsafe {
                (
                    *(self.errno)(),
                    (self.eof)(stream) != 0,
                    (self.error)(stream) != 0,
                )
            }
        }
    }

    fn arms() -> [(&'static CStr, FscanfFn, FscanfFn); 3] {
        [
            (c"fscanf", fl::fscanf as FscanfFn),
            (c"__isoc99_fscanf", fl::__isoc99_fscanf as FscanfFn),
            (c"__isoc23_fscanf", isoc_abi::__isoc23_fscanf as FscanfFn),
        ]
        .map(|(name, native)| {
            // SAFETY: all three symbols have the fscanf variadic signature.
            (name, native, unsafe { host_fn(name, native as *const ()) })
        })
    }

    #[test]
    fn long_fields_and_leading_whitespace_cross_refills_without_losing_bytes() {
        let (native, host) = (Api::native(), Api::host());
        for (name, native_scan, host_scan) in arms() {
            let run = |api: &Api, scan: FscanfFn| {
                let mut input = vec![b' '; 9_000];
                input.extend_from_slice(&vec![0xff; 20_000]);
                input.push(b' ');
                input.extend_from_slice(&vec![b'a'; 12_000]);
                input.push(b'!');
                // SAFETY: input's allocation stays live through fclose.
                let stream =
                    unsafe { (api.mem)(input.as_mut_ptr().cast(), input.len(), c"r".as_ptr()) };
                assert!(!stream.is_null());
                let mut fixed = vec![0xa5u8; 20_001];
                let mut allocated: *mut u8 = std::ptr::null_mut();
                let (mut first_count, mut second_count, mut tail) = (-1, -1, 0u8);
                // SAFETY: destinations match %s, %n, %m[, %n, and %c and have
                // enough capacity for their known input, including terminators.
                let rc = unsafe {
                    *(api.errno)() = 0;
                    scan(
                        stream,
                        c"%s%n %m[^!]%n%c".as_ptr(),
                        fixed.as_mut_ptr(),
                        &mut first_count,
                        &mut allocated,
                        &mut second_count,
                        &mut tail,
                    )
                };
                let state = api.status(stream);
                assert!(
                    !allocated.is_null(),
                    "{name:?} did not allocate its scanset"
                );
                // SAFETY: a published %m[ field is NUL-terminated. Reading to
                // that terminator also keeps a truncation regression bounded
                // by its actual allocation before the length assertions fail.
                let allocated_bytes = unsafe {
                    CStr::from_ptr(allocated.cast())
                        .to_bytes_with_nul()
                        .to_vec()
                };
                let position = unsafe { (api.tell)(stream) };
                unsafe { (api.free)(allocated.cast()) };
                assert_eq!(unsafe { (api.close)(stream) }, 0);
                (
                    rc,
                    first_count,
                    second_count,
                    tail,
                    position,
                    fixed,
                    allocated_bytes,
                    state,
                )
            };
            let expected = run(&host, host_scan);
            assert_eq!(
                (expected.0, expected.1, expected.2, expected.3, expected.4),
                (3, 29_000, 41_001, b'!', 41_002)
            );
            assert_eq!(&expected.5[..20_000], vec![0xff; 20_000]);
            assert_eq!(expected.5[20_000], 0);
            assert_eq!(&expected.6[..12_000], vec![b'a'; 12_000]);
            assert_eq!(expected.6[12_000], 0);
            assert_eq!(expected.7, (0, false, false));
            assert_eq!(run(&native, native_scan), expected, "{name:?}");

            for format in [c"%20000c%n%c", c"%20000s%n%c", c"%20000[^Z]%n%c"] {
                let bounded = |api: &Api, scan: FscanfFn| {
                    let mut input = vec![0xfe; 20_000];
                    input.push(b'Z');
                    let stream =
                        unsafe { (api.mem)(input.as_mut_ptr().cast(), input.len(), c"r".as_ptr()) };
                    assert!(!stream.is_null());
                    let (mut output, mut count, mut tail) = (vec![0xa5u8; 20_001], -1, 0u8);
                    // SAFETY: all three formats have a char buffer, int*, char*.
                    let rc = unsafe {
                        scan(
                            stream,
                            format.as_ptr(),
                            output.as_mut_ptr(),
                            &mut count,
                            &mut tail,
                        )
                    };
                    let position = unsafe { (api.tell)(stream) };
                    assert_eq!(unsafe { (api.close)(stream) }, 0);
                    (rc, count, tail, position, output)
                };
                let expected = bounded(&host, host_scan);
                assert_eq!(
                    (expected.0, expected.1, expected.2, expected.3),
                    (2, 20_000, b'Z', 20_001)
                );
                assert_eq!(
                    bounded(&native, native_scan),
                    expected,
                    "{name:?} {format:?}"
                );
            }
        }
    }

    struct ShortRead {
        input: Vec<u8>,
        position: usize,
        maximum: usize,
        end_error: bool,
        errno: ErrnoFn,
    }

    unsafe extern "C-unwind" fn short_read(
        cookie: *mut c_void,
        out: *mut c_char,
        len: usize,
    ) -> isize {
        // SAFETY: each FILE borrows a live ShortRead until it is closed, and
        // its callback destination is writable for len bytes.
        let source = unsafe { &mut *cookie.cast::<ShortRead>() };
        let count = len
            .min(source.maximum)
            .min(source.input.len() - source.position);
        if count == 0 && source.end_error {
            unsafe { *(source.errno)() = libc::EIO };
            return -1;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                source.input.as_ptr().add(source.position),
                out.cast(),
                count,
            )
        };
        source.position += count;
        count as isize
    }

    fn open_short(api: &Api, source: &mut ShortRead) -> *mut c_void {
        // SAFETY: the caller keeps source live and closes the FILE before it
        // leaves scope; the callback never assumes a seekable backing.
        let stream = unsafe {
            (api.cookie)(
                (source as *mut ShortRead).cast(),
                c"r".as_ptr(),
                fl::CookieIoFuncs {
                    read: Some(short_read),
                    ..fl::CookieIoFuncs::default()
                },
            )
        };
        assert!(!stream.is_null());
        stream
    }

    #[test]
    fn short_cookie_reads_do_not_end_numbers_or_text_fields() {
        let (native, host) = (Api::native(), Api::host());
        for (name, native_scan, host_scan) in arms() {
            for maximum in [1, 3, 7] {
                let run = |api: &Api, scan: FscanfFn| {
                    let mut source = ShortRead {
                        input: b"123 456 abcdef!".to_vec(),
                        position: 0,
                        maximum,
                        end_error: false,
                        errno: api.errno,
                    };
                    let stream = open_short(api, &mut source);
                    let (mut first, mut second, mut count, mut tail) = (-1, -1, -1, 0u8);
                    let mut allocated: *mut u8 = std::ptr::null_mut();
                    // SAFETY: each argument matches the format's destination.
                    let rc = unsafe {
                        *(api.errno)() = 0;
                        scan(
                            stream,
                            c"%d %d %m[^!]%n%c".as_ptr(),
                            &mut first,
                            &mut second,
                            &mut allocated,
                            &mut count,
                            &mut tail,
                        )
                    };
                    assert!(!allocated.is_null());
                    let text = unsafe { CStr::from_ptr(allocated.cast()).to_bytes().to_vec() };
                    let state = api.status(stream);
                    unsafe { (api.free)(allocated.cast()) };
                    assert_eq!(unsafe { (api.close)(stream) }, 0);
                    (rc, first, second, count, tail, text, state)
                };
                let expected = run(&host, host_scan);
                assert_eq!(
                    expected,
                    (4, 123, 456, 14, b'!', b"abcdef".to_vec(), (0, false, false))
                );
                assert_eq!(
                    run(&native, native_scan),
                    expected,
                    "{name:?} short read {maximum}"
                );
            }
        }
    }

    #[test]
    fn open_pipe_uses_buffered_tokens_and_count_only_formats_without_refilling() {
        let (native, host) = (Api::native(), Api::host());
        for (name, native_scan, host_scan) in arms() {
            let run = |api: &Api, scan: FscanfFn| {
                let mut descriptors = [-1; 2];
                // O_NONBLOCK turns a speculative refill into a visible EAGAIN
                // instead of hanging the test with its writer deliberately open.
                assert_eq!(
                    unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_NONBLOCK) },
                    0
                );
                let stream = unsafe { (api.fd)(descriptors[0], c"r".as_ptr()) };
                assert!(!stream.is_null());
                let mut observations = Vec::new();
                for format in [c"", c"%n"] {
                    let mut value = -1;
                    let rc = unsafe {
                        *(api.errno)() = 0;
                        scan(stream, format.as_ptr(), &mut value)
                    };
                    observations.push((rc, value, api.status(stream)));
                }
                assert_eq!(
                    unsafe { libc::write(descriptors[1], b"12 34 tail".as_ptr().cast(), 10) },
                    10
                );
                for _ in 0..2 {
                    let mut value = -1;
                    let rc = unsafe {
                        *(api.errno)() = 0;
                        scan(stream, c"%d".as_ptr(), &mut value)
                    };
                    observations.push((rc, value, api.status(stream)));
                }
                let remaining: Vec<_> = (0..5).map(|_| unsafe { (api.getc)(stream) }).collect();
                assert_eq!(unsafe { (api.close)(stream) }, 0);
                assert_eq!(unsafe { libc::close(descriptors[1]) }, 0);
                (observations, remaining)
            };
            let expected = run(&host, host_scan);
            assert_eq!(
                expected.0,
                [
                    (0, -1, (0, false, false)),
                    (0, 0, (0, false, false)),
                    (1, 12, (0, false, false)),
                    (1, 34, (0, false, false))
                ]
            );
            assert_eq!(
                expected.1,
                b" tail".iter().map(|&b| c_int::from(b)).collect::<Vec<_>>()
            );
            assert_eq!(run(&native, native_scan), expected, "{name:?}");
        }
    }

    #[test]
    fn count_only_formats_reject_write_only_streams_before_assigning() {
        let (native, host) = (Api::native(), Api::host());
        for (name, native_scan, host_scan) in arms() {
            for mode in [c"w", c"a"] {
                for format in [c"", c"%n", c"%*n", c"%"] {
                    let run = |api: &Api, scan: FscanfFn| {
                        let mut input = [0u8; 4];
                        let stream = unsafe {
                            (api.mem)(input.as_mut_ptr().cast(), input.len(), mode.as_ptr())
                        };
                        assert!(!stream.is_null());
                        let mut count = -777;
                        // SAFETY: only %n uses the one live int*; all other
                        // formats ignore it and must reject the FILE first.
                        let rc = unsafe {
                            *(api.errno)() = 0;
                            scan(stream, format.as_ptr(), &mut count)
                        };
                        let state = api.status(stream);
                        assert_eq!(unsafe { (api.close)(stream) }, 0);
                        (rc, count, state)
                    };
                    let expected = run(&host, host_scan);
                    assert_eq!(expected, (libc::EOF, -777, (libc::EBADF, false, false)));
                    assert_eq!(
                        run(&native, native_scan),
                        expected,
                        "{name:?} {mode:?} {format:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn incomplete_character_fields_fail_and_release_allocations_on_eof_or_error() {
        // The repository targets GNU's corrected full-width %c contract.
        // Older host glibc releases accepted partial fields, so this regression
        // checks that existing contract directly instead of using an old oracle.
        let native = Api::native();
        for (name, native_scan, _) in arms() {
            for end_error in [false, true] {
                for allocated in [false, true] {
                    let run = |api: &Api, scan: FscanfFn| {
                        let mut source = ShortRead {
                            input: b"ab".to_vec(),
                            position: 0,
                            maximum: 1,
                            end_error,
                            errno: api.errno,
                        };
                        let stream = open_short(api, &mut source);
                        let (mut output, mut pointer, mut count) =
                            ([0xa5u8; 3], std::ptr::null_mut::<u8>(), -1);
                        let (format, destination) = if allocated {
                            (c"%3mc%n", (&mut pointer as *mut *mut u8).cast::<c_void>())
                        } else {
                            (c"%3c%n", output.as_mut_ptr().cast::<c_void>())
                        };
                        // SAFETY: destination is char** only for %mc, char* for
                        // %c; failed partial conversions must not reach %n.
                        let rc = unsafe {
                            *(api.errno)() = 0;
                            scan(stream, format.as_ptr(), destination, &mut count)
                        };
                        let state = api.status(stream);
                        let bytes = if allocated {
                            assert!(
                                pointer.is_null(),
                                "an incomplete %mc must not publish storage"
                            );
                            Vec::new()
                        } else {
                            assert_eq!(output[2], 0xa5, "%c must not append a terminator");
                            output[..2].to_vec()
                        };
                        assert_eq!(unsafe { (api.close)(stream) }, 0);
                        (rc, count, bytes, state)
                    };
                    let expected = (
                        libc::EOF,
                        -1,
                        if allocated {
                            Vec::new()
                        } else {
                            b"ab".to_vec()
                        },
                        (if end_error { libc::EIO } else { 0 }, !end_error, end_error),
                    );
                    assert_eq!(
                        run(&native, native_scan),
                        expected,
                        "{name:?} allocated={allocated} error={end_error}"
                    );
                }
            }
        }
    }

    struct Utf8Locale {
        native: *mut c_void,
        native_previous: *mut c_void,
        host: *mut c_void,
        host_previous: *mut c_void,
        host_use: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
        host_free: unsafe extern "C" fn(*mut c_void),
    }

    impl Utf8Locale {
        fn select() -> Self {
            use frankenlibc_abi::locale_abi as locale;
            type NewLocale = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> *mut c_void;
            // SAFETY: both locale implementations own separate thread-local
            // selections; every resolved signature matches its POSIX symbol.
            unsafe {
                let host_new: NewLocale = host_fn(c"newlocale", locale::newlocale as *const ());
                let host_use: unsafe extern "C" fn(*mut c_void) -> *mut c_void =
                    host_fn(c"uselocale", locale::uselocale as *const ());
                let host_free = host_fn(c"freelocale", locale::freelocale as *const ());
                let native =
                    locale::newlocale(libc::LC_ALL_MASK, c"C.UTF-8".as_ptr(), std::ptr::null_mut());
                let host = host_new(libc::LC_ALL_MASK, c"C.UTF-8".as_ptr(), std::ptr::null_mut());
                assert!(
                    !native.is_null() && !host.is_null(),
                    "C.UTF-8 locale required"
                );
                let native_previous = locale::uselocale(native);
                let host_previous = host_use(host);
                assert!(!native_previous.is_null() && !host_previous.is_null());
                Self {
                    native,
                    native_previous,
                    host,
                    host_previous,
                    host_use,
                    host_free,
                }
            }
        }
    }

    impl Drop for Utf8Locale {
        fn drop(&mut self) {
            // SAFETY: restore each provider's live previous selection before
            // freeing the locale object this guard allocated with it.
            unsafe {
                frankenlibc_abi::locale_abi::uselocale(self.native_previous);
                (self.host_use)(self.host_previous);
                frankenlibc_abi::locale_abi::freelocale(self.native);
                (self.host_free)(self.host);
            }
        }
    }

    #[test]
    fn byte_stream_wide_fields_decode_characters_but_count_and_restore_bytes() {
        let _locale = Utf8Locale::select();
        let (native, host) = (Api::native(), Api::host());
        for (name, native_scan, host_scan) in arms() {
            let run = |api: &Api, scan: FscanfFn| {
                let mut input = "7é中日本!".as_bytes().to_vec();
                let stream =
                    unsafe { (api.mem)(input.as_mut_ptr().cast(), input.len(), c"r".as_ptr()) };
                assert!(!stream.is_null());
                let (mut number, mut chars, mut text) = (-1, [-777i32; 3], [-777i32; 4]);
                let (mut first_count, mut second_count, mut tail) = (-1, -1, 0u8);
                // SAFETY: narrow %lc/%ls require wchar_t destinations; all
                // fields have their format's capacity, with string terminator.
                let rc = unsafe {
                    *(api.errno)() = 0;
                    scan(
                        stream,
                        c"%d%2lc%n%2ls%n%c".as_ptr(),
                        &mut number,
                        chars.as_mut_ptr(),
                        &mut first_count,
                        text.as_mut_ptr(),
                        &mut second_count,
                        &mut tail,
                    )
                };
                let state = api.status(stream);
                let position = unsafe { (api.tell)(stream) };
                assert_eq!(unsafe { (api.close)(stream) }, 0);
                (
                    rc,
                    number,
                    chars,
                    text,
                    first_count,
                    second_count,
                    tail,
                    position,
                    state,
                )
            };
            let expected = run(&host, host_scan);
            assert_eq!(
                expected,
                (
                    4,
                    7,
                    [0xe9, 0x4e2d, -777],
                    [0x65e5, 0x672c, 0, -777],
                    6,
                    12,
                    b'!',
                    13,
                    (0, false, false)
                )
            );
            assert_eq!(run(&native, native_scan), expected, "{name:?} UTF-8 fields");

            for (
                bytes,
                format,
                expected_rc,
                expected_count,
                expected_position,
                expected_next,
                expected_errno,
            ) in [
                ("é中".as_bytes(), c"%2lc%n", 1, 5, 5, libc::EOF, 0),
                (
                    &b"a\xffZ"[..],
                    c"%2lc%n",
                    0,
                    -1,
                    2,
                    c_int::from(b'Z'),
                    libc::EILSEQ,
                ),
                (&b"a\xc3"[..], c"%2lc%n", 0, -1, 2, libc::EOF, libc::EILSEQ),
                ("êZ".as_bytes(), c"%l[é]%n", 0, -1, 1, 0xaa, libc::EILSEQ),
            ] {
                let run = |api: &Api, scan: FscanfFn| {
                    let mut input = bytes.to_vec();
                    let stream =
                        unsafe { (api.mem)(input.as_mut_ptr().cast(), input.len(), c"r".as_ptr()) };
                    assert!(!stream.is_null());
                    let (mut output, mut count) = ([-777i32; 4], -1);
                    let rc = unsafe {
                        *(api.errno)() = 0;
                        scan(stream, format.as_ptr(), output.as_mut_ptr(), &mut count)
                    };
                    let state = api.status(stream);
                    let position = unsafe { (api.tell)(stream) };
                    let next = unsafe { (api.getc)(stream) };
                    assert_eq!(unsafe { (api.close)(stream) }, 0);
                    (rc, count, output, position, next, state)
                };
                let expected = run(&host, host_scan);
                assert_eq!(
                    (expected.0, expected.1, expected.3, expected.4, expected.5.0),
                    (
                        expected_rc,
                        expected_count,
                        expected_position,
                        expected_next,
                        expected_errno
                    )
                );
                assert_eq!(
                    run(&native, native_scan),
                    expected,
                    "{name:?} {format:?} {bytes:?}"
                );
            }
        }
    }
}
