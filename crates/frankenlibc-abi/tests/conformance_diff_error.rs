#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // fd redirection + live glibc oracle

//! GNU `error()` against live glibc, by capturing stderr.
//!
//! bd-xke0zv: only fl-internal coverage. `error_at_line` already has a gate
//! (`conformance_diff_error_at_line`); plain `error()` had none, even though it
//! carries three pieces of state that are easy to get subtly wrong.
//!
//! ## The measured contract
//!
//! ```text
//!   error(0, 0,    "plain")          python3: plain
//!   error(0, 2,    "with errno")     python3: with errno: No such file or directory
//!   error(0, 13,   "perm")           python3: perm: Permission denied
//!   error(0, 9999, "bogus errno")    python3: bogus errno: Unknown error 9999
//!   error(0, 0,    "fmt %d and %s")  python3: fmt 42 and str
//! ```
//!
//! `errnum == 0` suppresses the suffix entirely rather than appending
//! `strerror(0)`, which is `"Success"` and would read as a diagnostic claiming
//! nothing went wrong.
//!
//! ## `error_print_progname` REPLACES the prefix
//!
//! With the hook set, glibc emits `HOOK!hooked` — the hook's own bytes, then
//! the message, with NO `": "` inserted between them. A reading of "the hook
//! supplies the program name" would add the separator and be wrong.
//!
//! ## `error_message_count` counts MESSAGES, not calls
//!
//! Measured with `error_one_per_line = 1`: three `error_at_line` calls at
//! locations 7, 7, 8 produced two messages and advanced the counter by TWO.
//! The suppressed call does not increment. fl already orders its increment
//! after the dedup check and says so; this gate is what makes that ordering
//! enforceable.

use std::ffi::{CString, c_char, c_int, c_uint};
use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::sync::{Mutex, MutexGuard};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::{host_addr, host_fn};

#[path = "common/fd_capture.rs"]
mod fd_capture;

type ErrorFn = unsafe extern "C" fn(c_int, c_int, *const c_char, ...);

/// `error`, `error_at_line`, and the fd-2 capture all use process-global
/// state. Keep one entire differential scenario exclusive: locking only one
/// `capture_stderr` call would still let another test change the program-name
/// or message-count state between the glibc and FrankenLibC halves.
static ERROR_GLOBALS_LOCK: Mutex<()> = Mutex::new(());

fn error_globals_lock() -> MutexGuard<'static, ()> {
    ERROR_GLOBALS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn host_error() -> ErrorFn {
    // SAFETY: `void error(int, int, const char *, ...)`, with fl's own export
    // supplied so the oracle refuses to resolve back to fl (bd-v0388t).
    unsafe { host_fn(c"error", frankenlibc_abi::stdlib_abi::error as *const ()) }
}

/// Run `body` with stderr redirected and return the bytes it wrote.
///
/// At the FILE DESCRIPTOR level: fl and glibc reach stderr by different routes
/// and a higher-level capture would miss one of them.
fn capture_stderr(body: impl FnOnce()) -> Vec<u8> {
    // SAFETY: pipe/dup/dup2 on descriptors owned for this call.
    unsafe {
        let mut fds = [0 as c_int; 2];
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0, "pipe failed");
        let (read_fd, write_fd) = (fds[0], fds[1]);
        // Restored by a Drop guard, INCLUDING on unwind: a panic in `body()`
        // would skip a straight-line restore and leave this process's stderr
        // pointed at the pipe for the rest of the run, swallowing libtest's
        // report of that very failure (bd-ug42ol). Block-scoped so fd 2 is
        // restored BEFORE the read: while redirected it holds a second
        // reference to the pipe's WRITE end and the reader never sees EOF.
        {
            let _restore = fd_capture::StdFdRestore::new(2);
            assert!(libc::dup2(write_fd, 2) >= 0, "dup2 onto stderr failed");
            libc::close(write_fd);

            body();
            libc::fflush(std::ptr::null_mut());
        }

        let mut file = std::fs::File::from_raw_fd(read_fd);
        let mut out = Vec::new();
        let _ = file.read_to_end(&mut out);
        out
    }
}

/// The program name glibc prefixes with, read from the LIVE glibc global so the
/// expectations do not hardcode a test-runner name.
///
/// Resolved through `dlsym`, for two reasons. `libc::program_invocation_name`
/// does not exist — the crate does not export it, which is what broke this
/// file's compile. And rustc's suggested replacement,
/// `frankenlibc_abi::startup_abi::program_invocation_name`, would have been
/// worse than the error: it is fl's own `AtomicPtr`, stored by fl's startup
/// code, which never runs in a test process. It is null here, so `prog` would
/// be empty and every prefix assertion below would compare `""` against `""`
/// and pass while proving nothing.
fn program_name() -> String {
    // SAFETY: `program_invocation_name` is a `char *` global, so `host_addr`
    // returns the address OF the pointer and one deref yields the string. fl's
    // own definition is passed so a collapsed oracle aborts (bd-v0388t).
    let name = unsafe {
        let slot = host_addr(
            c"program_invocation_name",
            (&raw const frankenlibc_abi::startup_abi::program_invocation_name).cast::<()>(),
        );
        let ptr = *slot.cast::<*const c_char>();
        if ptr.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    };
    // An empty prefix would make every expectation below vacuous, and it is
    // exactly what the two wrong readings of this global produce. Fail as a
    // broken probe instead of passing as evidence.
    assert!(
        !name.is_empty(),
        "glibc's program_invocation_name is empty — the oracle is broken, so \
         this gate cannot run. Do NOT read this as agreement about fl."
    );
    name
}

#[test]
fn error_matches_live_glibc_on_stderr() {
    let _globals = error_globals_lock();
    let host = host_error();
    let prog = program_name();
    let mut divergences = Vec::new();

    // `(errnum, format, expected tail after "<prog>: ")`
    let cases: &[(c_int, &str, &str)] = &[
        (0, "plain", "plain\n"),
        (2, "with errno", "with errno: No such file or directory\n"),
        (13, "perm", "perm: Permission denied\n"),
        (9999, "bogus errno", "bogus errno: Unknown error 9999\n"),
    ];

    for (errnum, fmt, tail) in cases {
        let cfmt = CString::new(*fmt).expect("format has no NUL");
        let expected = format!("{prog}: {tail}");

        // SAFETY: status 0 means error() returns rather than exiting; the
        // format is NUL-terminated and takes no arguments.
        let host_out = capture_stderr(|| unsafe { host(0, *errnum, cfmt.as_ptr()) });
        assert_eq!(
            String::from_utf8_lossy(&host_out),
            expected,
            "host glibc no longer produces the recorded output for errnum {errnum}"
        );

        // SAFETY: same call through fl.
        let fl_out = capture_stderr(|| unsafe {
            frankenlibc_abi::stdlib_abi::error(0, *errnum, cfmt.as_ptr())
        });

        if fl_out != host_out {
            divergences.push(format!(
                "  errnum {errnum} fmt {fmt:?}\n    fl    = {:?}\n    glibc = {:?}",
                String::from_utf8_lossy(&fl_out),
                String::from_utf8_lossy(&host_out),
            ));
        }
    }
    assert!(
        divergences.is_empty(),
        "error() divergences from live glibc:\n{}",
        divergences.join("\n")
    );
}

/// `errnum == 0` must suppress the suffix rather than appending
/// `strerror(0)` — which is "Success", and would read as a diagnostic
/// announcing that nothing went wrong.
#[test]
fn errnum_zero_appends_nothing() {
    let _globals = error_globals_lock();
    let prog = program_name();
    let fmt = c"no errno here";
    // SAFETY: status 0, NUL-terminated format, no varargs.
    let out = capture_stderr(|| unsafe { frankenlibc_abi::stdlib_abi::error(0, 0, fmt.as_ptr()) });
    let text = String::from_utf8_lossy(&out).into_owned();
    assert_eq!(text, format!("{prog}: no errno here\n"));
    assert!(
        !text.contains("Success"),
        "errnum 0 must not append strerror(0): {text}"
    );
}

/// printf conversions in the format string are honoured.
#[test]
fn format_arguments_are_expanded() {
    let _globals = error_globals_lock();
    let host = host_error();
    let prog = program_name();
    let fmt = c"fmt %d and %s";
    let arg_s = c"str";

    // SAFETY: the format names one int and one string, matching the arguments.
    let host_out = capture_stderr(|| unsafe { host(0, 0, fmt.as_ptr(), 42, arg_s.as_ptr()) });
    assert_eq!(
        String::from_utf8_lossy(&host_out),
        format!("{prog}: fmt 42 and str\n")
    );

    // SAFETY: same.
    let fl_out = capture_stderr(|| unsafe {
        frankenlibc_abi::stdlib_abi::error(0, 0, fmt.as_ptr(), 42, arg_s.as_ptr())
    });
    assert_eq!(fl_out, host_out, "printf expansion inside error()");
}

/// The counter tracks MESSAGES. A suppressed `error_at_line` must not bump it,
/// which is why fl orders the increment after the dedup check.
#[test]
fn error_message_count_skips_suppressed_messages() {
    let _globals = error_globals_lock();
    // SAFETY: both are plain globals fl exports.
    unsafe {
        frankenlibc_abi::glibc_internal_abi::error_one_per_line = 1;
        frankenlibc_abi::stdlib_abi::error_message_count = 0;
    }
    let file = c"f.c";
    let msg = c"dup";

    // SAFETY: status 0, NUL-terminated file and format.
    let first = capture_stderr(|| unsafe {
        frankenlibc_abi::stdlib_abi::error_at_line(0, 0, file.as_ptr(), 7 as c_uint, msg.as_ptr())
    });
    // SAFETY: same location — must be suppressed.
    let second = capture_stderr(|| unsafe {
        frankenlibc_abi::stdlib_abi::error_at_line(0, 0, file.as_ptr(), 7 as c_uint, msg.as_ptr())
    });
    // SAFETY: different line — must print again.
    let third = capture_stderr(|| unsafe {
        frankenlibc_abi::stdlib_abi::error_at_line(0, 0, file.as_ptr(), 8 as c_uint, msg.as_ptr())
    });

    assert!(!first.is_empty(), "the first message must print");
    assert!(
        second.is_empty(),
        "a repeat at the same location must be suppressed"
    );
    assert!(!third.is_empty(), "a different line must print again");

    // SAFETY: reading the global back.
    let count = unsafe { frankenlibc_abi::stdlib_abi::error_message_count };
    assert_eq!(
        count, 2,
        "three calls, two messages — the suppressed one must NOT increment \
         error_message_count (measured against glibc)"
    );

    // SAFETY: restore, so this arm cannot leak dedup state into another.
    unsafe {
        frankenlibc_abi::glibc_internal_abi::error_one_per_line = 0;
    }
}
