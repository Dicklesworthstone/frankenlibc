#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // foreign FILE* handling compared against the host

//! Every stdio entry point must treat a HOST-owned `FILE*` the way glibc does.
//!
//! ## Why this gate exists, and what it is replacing
//!
//! `fscanf` was found returning -1 with nothing written on a stream fl did not
//! create, where glibc returned 2 (fixed in 7672ef04f). `vfscanf` delegated such
//! a stream to the host and `fscanf` had no host path at all — and since
//! `<stdio.h>` redirects compiled calls to `__isoc99_fscanf` -> `vfscanf`, only
//! callers of the plain symbol ever saw it. fl's own fscanf suite could not:
//! every stream it opens is fl's own, and an fl-created stream is IN the
//! registry, so both paths run the engine and agree.
//!
//! I then claimed that defect was the head of a family and named `fgetc`,
//! `getc`, `ftello64`, `fseeko64` and the whole write side as exposed. **That
//! was wrong and is retracted** (bd-r8hpym). The audit behind it keyed on one
//! predicate, `may_delegate_to_host`, and that is not the only way an entry
//! point reaches the host: `fgetc` delegates when `stream_cell(id)` MISSES,
//! calling `host_fgetc_fn()`. Counting every `host_*_fn()` call and closing
//! transitively over callers, 63 of 64 stream entry points reach a host path.
//!
//! But "reaches a host path" is strictly weaker than "delegates under the same
//! conditions as its twin", and the difference is where the fscanf defect lived.
//! A narrow branch satisfies source reading and still diverges. Only execution
//! settles it, so this gate executes it: one foreign stream, one operation, fl's
//! symbol against the host's.
//!
//! ## Design notes that are load-bearing
//!
//! - The stream MUST come from host `fopen`. An fl-created stream is in fl's
//!   registry, no delegation predicate fires, and every arm agrees for the wrong
//!   reason — the exact blind spot that hid the fscanf defect for as long as it
//!   existed.
//! - Each arm gets its OWN open, so no arm inherits another's file position or
//!   buffered state.
//! - Every op asserts what the HOST produced before comparing, so a comparison
//!   cannot be satisfied by both arms failing identically. A zero only counts if
//!   the runner was seen doing work.
//! - The file content is fixed and asymmetric ("hello 42\nsecond line\n") so a
//!   truncated or mis-positioned read cannot coincidentally match.
//!
//! ## STATUS: WRITTEN BUT NEVER COMPILED OR RUN
//!
//! Authored while the host was at 100% disk with builds, tests and benchmarks
//! forbidden. Nothing here has been through a compiler. Run it before trusting
//! any conclusion from it: a red arm is a finding to be confirmed, and a
//! compile error is mine, not a defect in fl.

use std::ffi::{CString, c_char, c_int, c_long, c_void};
use std::io::Write;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

type FopenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type FcloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type FgetcFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type FgetsFn = unsafe extern "C" fn(*mut c_char, c_int, *mut c_void) -> *mut c_char;
type FreadFn = unsafe extern "C" fn(*mut c_void, usize, usize, *mut c_void) -> usize;
type FtellFn = unsafe extern "C" fn(*mut c_void) -> c_long;
type FeofFn = unsafe extern "C" fn(*mut c_void) -> c_int;

const CONTENT: &str = "hello 42\nsecond line\n";

/// Open the fixture with HOST glibc, hand the stream to `body`, close it with
/// HOST glibc, and return whatever `body` observed.
fn with_host_stream<T>(
    path: &CString,
    fopen: FopenFn,
    fclose: FcloseFn,
    body: impl FnOnce(*mut c_void) -> T,
) -> T {
    let mode = CString::new("r").expect("mode has NUL");
    // SAFETY: both strings are NUL-terminated for the duration of the call.
    let stream = unsafe { fopen(path.as_ptr(), mode.as_ptr()) };
    assert!(!stream.is_null(), "host fopen failed");
    let out = body(stream);
    // SAFETY: `stream` came from the host `fopen` above and is closed exactly once.
    unsafe { fclose(stream) };
    out
}

fn fixture() -> CString {
    let dir = std::env::temp_dir().join("fl_host_stream_family");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("input.txt");
    {
        let mut f = std::fs::File::create(&path).expect("create fixture");
        f.write_all(CONTENT.as_bytes()).expect("write fixture");
    }
    CString::new(path.to_str().expect("utf-8 path")).expect("path has NUL")
}

/// `(fl, host)` pairs, resolved once. `host_fn` asserts each resolved address is
/// NOT fl's own definition, so a collapsed oracle fails loudly rather than
/// comparing fl against itself.
struct Arms {
    path: CString,
    fopen: FopenFn,
    fclose: FcloseFn,
    host_fgetc: FgetcFn,
    host_fgets: FgetsFn,
    host_fread: FreadFn,
    host_ftell: FtellFn,
    host_feof: FeofFn,
}

fn arms() -> Arms {
    Arms {
        path: fixture(),
        // SAFETY: each name is NUL-terminated and paired with fl's own definition
        // of the same symbol, which is what makes a collapsed arm detectable.
        fopen: unsafe { host_fn(c"fopen", frankenlibc_abi::stdio_abi::fopen as *const ()) },
        fclose: unsafe { host_fn(c"fclose", frankenlibc_abi::stdio_abi::fclose as *const ()) },
        host_fgetc: unsafe { host_fn(c"fgetc", frankenlibc_abi::stdio_abi::fgetc as *const ()) },
        host_fgets: unsafe { host_fn(c"fgets", frankenlibc_abi::stdio_abi::fgets as *const ()) },
        host_fread: unsafe { host_fn(c"fread", frankenlibc_abi::stdio_abi::fread as *const ()) },
        host_ftell: unsafe { host_fn(c"ftell", frankenlibc_abi::stdio_abi::ftell as *const ()) },
        host_feof: unsafe { host_fn(c"feof", frankenlibc_abi::stdio_abi::feof as *const ()) },
    }
}

#[test]
fn fgetc_reads_a_host_owned_stream_the_way_the_host_does() {
    let a = arms();
    let read_three = |f: FgetcFn| {
        with_host_stream(&a.path, a.fopen, a.fclose, |s| {
            // SAFETY: `s` is a live FILE* from host fopen.
            unsafe { [f(s), f(s), f(s)] }
        })
    };

    let want = read_three(a.host_fgetc);
    assert_eq!(
        want,
        [b'h' as c_int, b'e' as c_int, b'l' as c_int],
        "the host arm did not read the fixture, so this gate compares nothing"
    );

    let got = read_three(frankenlibc_abi::stdio_abi::fgetc as FgetcFn);
    assert_eq!(
        got, want,
        "fl fgetc on a HOST-owned FILE* returned {got:?}, host glibc returned {want:?}"
    );
}

#[test]
fn fgets_reads_a_host_owned_stream_the_way_the_host_does() {
    let a = arms();
    let first_line = |f: FgetsFn| {
        with_host_stream(&a.path, a.fopen, a.fclose, |s| {
            let mut buf = [0u8; 64];
            // SAFETY: `buf` is 64 bytes and that length is what is passed.
            let rc = unsafe { f(buf.as_mut_ptr().cast::<c_char>(), 64, s) };
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            (
                rc.is_null(),
                String::from_utf8_lossy(&buf[..end]).into_owned(),
            )
        })
    };

    let want = first_line(a.host_fgets);
    assert_eq!(
        want,
        (false, "hello 42\n".to_string()),
        "the host arm did not read the fixture, so this gate compares nothing"
    );

    let got = first_line(frankenlibc_abi::stdio_abi::fgets as FgetsFn);
    assert_eq!(
        got, want,
        "fl fgets on a HOST-owned FILE* returned {got:?}, host glibc returned {want:?}"
    );
}

#[test]
fn fread_reads_a_host_owned_stream_the_way_the_host_does() {
    let a = arms();
    let read_five = |f: FreadFn| {
        with_host_stream(&a.path, a.fopen, a.fclose, |s| {
            let mut buf = [0u8; 5];
            // SAFETY: exactly 5 bytes are requested into a 5-byte buffer.
            let n = unsafe { f(buf.as_mut_ptr().cast::<c_void>(), 1, 5, s) };
            (n, String::from_utf8_lossy(&buf).into_owned())
        })
    };

    let want = read_five(a.host_fread);
    assert_eq!(
        want,
        (5usize, "hello".to_string()),
        "the host arm did not read the fixture, so this gate compares nothing"
    );

    let got = read_five(frankenlibc_abi::stdio_abi::fread as FreadFn);
    assert_eq!(
        got, want,
        "fl fread on a HOST-owned FILE* returned {got:?}, host glibc returned {want:?}"
    );
}

/// Position after a read, which is where a stream fl is not tracking would drift.
///
/// This pairs two entry points deliberately: the bytes are consumed with the
/// HOST's `fgetc` in both arms, and only `ftell` differs. So a divergence here is
/// `ftell`'s alone and cannot be blamed on a different number of bytes consumed.
#[test]
fn ftell_reports_a_host_owned_stream_position_the_way_the_host_does() {
    let a = arms();
    let position_after_three = |f: FtellFn| {
        with_host_stream(&a.path, a.fopen, a.fclose, |s| {
            // SAFETY: `s` is a live FILE* from host fopen; three bytes are
            // consumed through the HOST's fgetc in every arm.
            unsafe {
                (a.host_fgetc)(s);
                (a.host_fgetc)(s);
                (a.host_fgetc)(s);
                f(s)
            }
        })
    };

    let want = position_after_three(a.host_ftell);
    assert_eq!(
        want, 3,
        "the host arm did not advance the fixture, so this gate compares nothing"
    );

    let got = position_after_three(frankenlibc_abi::stdio_abi::ftell as FtellFn);
    assert_eq!(
        got, want,
        "fl ftell on a HOST-owned FILE* returned {got}, host glibc returned {want}"
    );
}

/// End-of-file after the host has drained the stream.
///
/// Same construction as `ftell`: the draining is done by the HOST in both arms,
/// so only the `feof` implementation varies.
#[test]
fn feof_reports_a_host_owned_stream_the_way_the_host_does() {
    let a = arms();
    let eof_after_drain = |f: FeofFn| {
        with_host_stream(&a.path, a.fopen, a.fclose, |s| {
            // SAFETY: reads through the host's own fgetc until it reports EOF;
            // the loop is bounded by the fixture's length plus one.
            unsafe {
                for _ in 0..CONTENT.len() + 1 {
                    if (a.host_fgetc)(s) == libc::EOF {
                        break;
                    }
                }
                f(s)
            }
        })
    };

    let want = eof_after_drain(a.host_feof);
    assert!(
        want != 0,
        "the host arm did not reach EOF on the fixture, so this gate compares nothing"
    );

    let got = eof_after_drain(frankenlibc_abi::stdio_abi::feof as FeofFn);
    assert_eq!(
        got != 0,
        want != 0,
        "fl feof on a HOST-owned FILE* returned {got}, host glibc returned {want}"
    );
}
