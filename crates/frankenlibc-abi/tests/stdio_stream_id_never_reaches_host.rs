#![cfg(all(target_os = "linux", not(feature = "standalone")))]
#![allow(unsafe_code)] // exercises the real fl stdio ABI with real FILE* handles

//! fl must never hand one of its own synthetic stream ids to host glibc
//! (bd-u2daxd).
//!
//! fl does not return real `FILE *` pointers. `stdin`/`stdout`/`stderr` are the
//! sentinels `0x1000_0001..=0x1000_0003` and every `fopen` gets an id from
//! `alloc_stream_id`, counting up from `0x1000_0010`. Any stdio entry point that
//! cannot find an id in fl's registry used to conclude the handle must belong to
//! the host and pass it to glibc, which dereferences it as a `FILE *`.
//!
//! bd-0ftdgt fixed that for the three standard sentinels. It left every ORDINARY
//! id exposed, and the window is simply "the registry no longer holds this id" —
//! reached by a double close, or by `fcloseall` racing another thread's close.
//! Caught under gdb on the conformance suite at `--test-threads 16`:
//!
//! ```text
//! Thread 165 received signal SIGSEGV, Segmentation fault.
//! #0  _IO_new_fclose (fp=0x10000044) at ./libio/iofclose.c:48
//! #1  frankenlibc_abi::stdio_abi::fclose (stream=0x10000044)
//! #2  frankenlibc_abi::stdio_abi::fcloseall ()
//! ```
//!
//! `0x1000_0044` is an `alloc_stream_id` value, not an address.
//!
//! Every assertion here is a NEGATIVE case: before the fix each one drove glibc
//! into dereferencing a small integer, so the pre-fix failure is a SIGSEGV, not
//! a wrong return value. A run that merely completes already proves something.

use std::ffi::{CString, c_int, c_void};

type File = c_void;

// Call fl through its Rust paths, NOT through `extern "C"` declarations.
//
// In a debug build `#[unsafe(no_mangle)]` is disabled on these entry points
// (`#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`), so an
// `unsafe extern "C" { fn fopen(..); }` block in a test binds to HOST glibc
// instead. The first draft of this gate did exactly that and reported a real
// glibc pointer (`0x7335040039b0`) where an fl id was expected — it was testing
// glibc's stdio against fl's invariants. `fl_fopen_returns_a_synthetic_handle`
// below keeps that failure mode visible rather than silent.
use frankenlibc_abi::stdio_abi as fl;

const EOF: c_int = -1;

/// fl hands out ids from `0x1000_0001`; the first `fopen` id is `0x1000_0010`.
/// Anything in this window is a synthetic handle, never a real pointer.
fn is_synthetic_handle(p: *mut File) -> bool {
    let v = p as usize;
    (0x1000_0001..0x2000_0000).contains(&v)
}

fn open_devnull() -> *mut File {
    let path = CString::new("/dev/null").unwrap();
    let mode = CString::new("r").unwrap();
    let f = unsafe { fl::fopen(path.as_ptr(), mode.as_ptr()) };
    assert!(!f.is_null(), "fl fopen(/dev/null) returned NULL");
    f
}

#[test]
fn fl_fopen_returns_a_synthetic_handle_not_a_pointer() {
    // The premise the rest of this file rests on. If fl ever starts returning
    // real pointers, these gates stop testing what they claim to, and this
    // assertion says so out loud rather than passing vacuously.
    let f = open_devnull();
    assert!(
        is_synthetic_handle(f),
        "expected an fl synthetic stream id, got {f:p}; the rest of this gate \
         assumes fl handles are ids and must be revisited"
    );
    assert_eq!(unsafe { fl::fclose(f) }, 0, "first fclose should succeed");
}

#[test]
fn double_fclose_reports_eof_instead_of_reaching_glibc() {
    let f = open_devnull();
    assert!(is_synthetic_handle(f));

    assert_eq!(unsafe { fl::fclose(f) }, 0, "first fclose should succeed");

    // Pre-fix this call segfaulted inside _IO_new_fclose: the id was gone from
    // the registry, so may_delegate_to_host said "host handle" and glibc
    // dereferenced it.
    let second = unsafe { fl::fclose(f) };
    assert_eq!(
        second, EOF,
        "closing an already-closed fl stream must report EOF from fl's own \
         registry path, never be forwarded to the host as a FILE *"
    );
}

#[test]
fn fclose_after_fcloseall_reports_eof_instead_of_reaching_glibc() {
    // fcloseall closes every non-standard stream. Any handle a caller still
    // holds is now an id the registry does not contain -- the exact state that
    // used to be misread as "this must be a host FILE *".
    let a = open_devnull();
    let b = open_devnull();
    assert!(is_synthetic_handle(a) && is_synthetic_handle(b));

    assert_eq!(unsafe { fl::fcloseall() }, 0, "fcloseall should report 0");

    for (name, f) in [("a", a), ("b", b)] {
        assert_eq!(
            unsafe { fl::fclose(f) },
            EOF,
            "fclose on stream {name}, already closed by fcloseall, must report \
             EOF rather than hand its id to glibc"
        );
    }

    // The standard streams must still be usable afterwards (bd-0ftdgt).
    assert_eq!(
        unsafe { fl::fflush(std::ptr::null_mut()) },
        0,
        "fflush(NULL) must stay safe after fcloseall"
    );
}

#[test]
fn repeated_fcloseall_is_safe() {
    // The second fcloseall walks a registry whose non-standard entries are gone.
    let _ = open_devnull();
    assert_eq!(unsafe { fl::fcloseall() }, 0);
    assert_eq!(
        unsafe { fl::fcloseall() },
        0,
        "second fcloseall must be safe"
    );
    assert_eq!(unsafe { fl::fflush(std::ptr::null_mut()) }, 0);
}
