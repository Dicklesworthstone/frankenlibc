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
//! The stale-id cases must reject handles without dereferencing a small integer.
//! The positive mixed-provider case also requires real I/O through both native
//! ids and host FILE pointers; refusing every foreign handle is not a solution.

use std::ffi::{CString, c_int, c_void};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::fs::FileExt;
use std::sync::{Mutex, MutexGuard};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

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
fn native_and_host_streams_perform_real_io_through_fl() {
    let _guard = gate_lock();
    exercise_native_and_host_stream_io(false);
    // Explicitly test the initialized path too. This hook is not evidence that
    // a deployed C program reaches runtime readiness through its startup code.
    fl::signal_runtime_ready_for_tests();
    exercise_native_and_host_stream_io(true);
}

fn exercise_native_and_host_stream_io(runtime_ready: bool) {
    type Fdopen = unsafe extern "C" fn(c_int, *const libc::c_char) -> *mut File;
    // SAFETY: Fdopen matches the C signature; the resolver rejects fl's address.
    let host_fdopen: Fdopen = unsafe { dlsym_oracle::host_fn(c"fdopen", fl::fdopen as *const ()) };

    for (provider, open, synthetic) in [
        ("native", fl::fdopen as Fdopen, true),
        ("host", host_fdopen, false),
    ] {
        // SAFETY: memfd_create takes a terminated name and valid flags. The
        // anonymous backing object avoids creating or deleting filesystem paths.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                c"stdio-provider-gate".as_ptr(),
                libc::MFD_CLOEXEC,
            )
        };
        assert!(fd >= 0, "{provider}: memfd_create failed");
        // SAFETY: the successful syscall returned a new owned descriptor.
        let backing = unsafe { std::fs::File::from_raw_fd(fd as c_int) };
        let stream_fd = backing.try_clone().expect("duplicate backing descriptor");
        let _ = fl::take_last_decision_gate_for_tests();
        // SAFETY: stream_fd is live and read/write; the mode is terminated.
        let stream = unsafe { open(stream_fd.as_raw_fd(), c"w+".as_ptr()) };
        assert!(!stream.is_null(), "{provider}: fdopen failed");
        let bound_fd = stream_fd.into_raw_fd(); // the successful stream owns it
        assert_eq!(is_synthetic_handle(stream), synthetic, "{provider}");
        if runtime_ready
            && synthetic
            && std::env::var("FRANKENLIBC_MODE").as_deref() == Ok("hardened")
        {
            assert!(
                fl::take_last_decision_gate_for_tests().is_some(),
                "initialized hardened fdopen must record a policy decision"
            );
        }
        // SAFETY: stream is a live handle from the selected provider.
        assert_eq!(unsafe { fl::fileno(stream) }, bound_fd, "{provider}");

        let written = b"stdio-provider";
        // SAFETY: written is readable for its length and stream is writable.
        assert_eq!(
            unsafe { fl::fwrite(written.as_ptr().cast(), 1, written.len(), stream) },
            written.len(),
            "{provider}: fwrite"
        );
        // SAFETY: stream is still live; flushing exposes bytes to the backing fd.
        assert_eq!(unsafe { fl::fflush(stream) }, 0, "{provider}: fflush");
        let mut actual = [0u8; 14];
        backing.read_exact_at(&mut actual, 0).expect("read backing");
        assert_eq!(&actual, written, "{provider}: physical write bytes");

        let replacement = b"physical-bytes";
        backing.write_all_at(replacement, 0).expect("write backing");
        // SAFETY: the live stream supports seeking; this also switches to reading.
        assert_eq!(unsafe { fl::fseek(stream, 0, SEEK_SET) }, 0, "{provider}");
        actual.fill(0);
        // SAFETY: actual is writable for its length and stream is readable.
        assert_eq!(
            unsafe { fl::fread(actual.as_mut_ptr().cast(), 1, actual.len(), stream) },
            actual.len(),
            "{provider}: fread"
        );
        assert_eq!(&actual, replacement, "{provider}: physical read bytes");
        // SAFETY: close the stream exactly once; backing owns a distinct fd.
        assert_eq!(unsafe { fl::fclose(stream) }, 0, "{provider}: fclose");
        // SAFETY: F_GETFD only queries the descriptor; it cannot dereference it.
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_fcntl, bound_fd, libc::F_GETFD, 0usize) },
            -1,
            "{provider}: fclose must actually close its descriptor"
        );
    }
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

    assert_eq!(fl::fcloseall(), 0, "fcloseall should report 0");

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
    assert_eq!(fl::fcloseall(), 0);
    assert_eq!(fl::fcloseall(), 0, "second fcloseall must be safe");
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
        assert_eq!(fl::fcloseall(), 0, "fcloseall should report 0");
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
