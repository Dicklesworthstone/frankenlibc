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
use std::sync::{Mutex, MutexGuard};

/// Serialise the arms in this file.
///
/// Every one of them calls `fcloseall`, or holds a stream while a sibling
/// might, and `fcloseall` closes EVERY non-standard stream in the process --
/// including one another's. Run in parallel they close each other's handles and
/// report failures that say nothing about the invariant under test. Observed
/// while writing this gate: 4 passed at `--test-threads 1`, 2 failed at the
/// default. That was the arms, not fl.
fn gate_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

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

const SEEK_SET: c_int = 0;

const EOF: c_int = -1;

/// fl hands out ids from `0x1000_0001`; the first `fopen` id is `0x1000_0010`.
/// Anything in this window is a synthetic handle, never a real pointer.
fn is_synthetic_handle(p: *mut File) -> bool {
    let v = p as usize;
    (0x1000_0001..0x2000_0000).contains(&v)
}

/// `/dev/null` opened read-write, so both the read and write entry points have
/// a legitimately usable stream before it is invalidated.
fn open_devnull_rw() -> *mut File {
    let path = CString::new("/dev/null").unwrap();
    let mode = CString::new("r+").unwrap();
    let f = unsafe { fl::fopen(path.as_ptr(), mode.as_ptr()) };
    assert!(!f.is_null(), "fl fopen(/dev/null, r+) returned NULL");
    f
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
    let _guard = gate_lock();
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
    let _guard = gate_lock();
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
    let _guard = gate_lock();
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
    let _guard = gate_lock();
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

/// Every stdio entry point must refuse a stale fl handle, not just `fclose`.
///
/// This is the production sequence bd-u2daxd crashed on, reduced to three
/// lines. One conformance test called `fcloseall()` while a sibling held a live
/// `tmpfile()` stream; `fcloseall` legitimately closes every non-standard
/// stream, so the sibling's handle became an id the registry no longer held,
/// and its next `fputs` was forwarded to glibc:
///
/// ```text
/// #0  __GI__IO_fwrite (buf=..., size=1, count=4, fp=0x10000012)
/// #1  frankenlibc_abi::stdio_abi::write_bytes_without_runtime_policy (id=268435474, _stream=0x10000012)
/// #2  frankenlibc_abi::stdio_abi::fputs (stream=0x10000012)
/// #3  frankenlibc_abi::stdio_abi::fputs_unlocked
/// ```
///
/// `fclose` consulted `may_delegate_to_host`; these paths each made their own
/// bare "not in the registry, therefore the host's" decision. Fixing only
/// `fclose` moved the crash from one door to the next, which is why this arm
/// sweeps the whole family rather than the one that was caught.
#[test]
fn every_stdio_entry_point_refuses_a_stale_fl_handle() {
    let _guard = gate_lock();

    // A helper per entry point: reopen, invalidate with fcloseall, then poke.
    // Each closure is the NEGATIVE case -- pre-fix it reached glibc with a
    // small integer for a FILE * and took the process down.
    fn stale_handle() -> *mut File {
        let f = open_devnull_rw();
        assert!(is_synthetic_handle(f));
        assert_eq!(unsafe { fl::fcloseall() }, 0, "fcloseall should report 0");
        f
    }

    let text = CString::new("abcd").unwrap();
    let mut buf = [0u8; 8];

    // fputs / fputs_unlocked -> write_bytes_without_runtime_policy -> host fwrite
    let f = stale_handle();
    assert_eq!(
        unsafe { fl::fputs(text.as_ptr(), f) },
        EOF,
        "fputs on a stale fl handle must report EOF, not reach glibc"
    );

    let f = stale_handle();
    assert_eq!(
        unsafe { fl::fputs_unlocked(text.as_ptr(), f) },
        EOF,
        "fputs_unlocked on a stale fl handle must report EOF, not reach glibc"
    );

    // fwrite
    let f = stale_handle();
    assert_eq!(
        unsafe { fl::fwrite(text.as_ptr().cast(), 1, 4, f) },
        0,
        "fwrite on a stale fl handle must write nothing, not reach glibc"
    );

    // fputc
    let f = stale_handle();
    assert_eq!(
        unsafe { fl::fputc(b'x' as c_int, f) },
        EOF,
        "fputc on a stale fl handle must report EOF, not reach glibc"
    );

    // fgetc
    let f = stale_handle();
    assert_eq!(
        unsafe { fl::fgetc(f) },
        EOF,
        "fgetc on a stale fl handle must report EOF, not reach glibc"
    );

    // fread
    let f = stale_handle();
    assert_eq!(
        unsafe { fl::fread(buf.as_mut_ptr().cast(), 1, buf.len(), f) },
        0,
        "fread on a stale fl handle must read nothing, not reach glibc"
    );

    // fflush on the handle itself
    let f = stale_handle();
    let rc = unsafe { fl::fflush(f) };
    assert_eq!(
        rc, EOF,
        "fflush on a stale fl handle must report EOF, not reach glibc"
    );

    // fseek / ftell
    let f = stale_handle();
    assert_eq!(
        unsafe { fl::fseek(f, 0, SEEK_SET) },
        -1,
        "fseek on a stale fl handle must fail, not reach glibc"
    );

    // The locking family classified a stale id as Foreign and handed it to
    // host_flockfile/ftrylockfile/funlockfile. These must simply not crash.
    let f = stale_handle();
    unsafe { fl::flockfile(f) };
    let _ = unsafe { fl::ftrylockfile(f) };
    unsafe { fl::funlockfile(f) };

    // And the standard streams must still work after all of that.
    assert_eq!(
        unsafe { fl::fflush(std::ptr::null_mut()) },
        0,
        "fflush(NULL) must stay safe"
    );
}
