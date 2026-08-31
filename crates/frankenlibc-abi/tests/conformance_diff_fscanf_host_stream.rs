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

type FscanfFn = unsafe extern "C" fn(*mut c_void, *const c_char, ...) -> c_int;
type FopenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type FcloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;

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
                f(stream, c"%c".as_ptr(), (&mut first as *mut u8).cast::<c_char>()),
                first,
            ),
            (
                f(stream, c"%c".as_ptr(), (&mut second as *mut u8).cast::<c_char>()),
                second,
            ),
            (
                f(stream, c"%c".as_ptr(), (&mut eof as *mut u8).cast::<c_char>()),
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
        (
            "fscanf",
            frankenlibc_abi::stdio_abi::fscanf as FscanfFn,
        ),
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
