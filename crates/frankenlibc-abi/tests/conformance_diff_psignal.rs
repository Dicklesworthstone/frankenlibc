#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // fd redirection + live glibc oracle

//! `psignal` against live glibc, by capturing what each writes to stderr.
//!
//! bd-rfd32s: fl had only self-referential coverage. The interesting content is
//! not the happy path — it is a divergence INSIDE glibc that an implementer
//! would naturally "fix" and thereby break.
//!
//! ## `psignal` and `strsignal` disagree about real-time signals
//!
//! Measured on glibc 2.42:
//!
//! ```text
//!   sig  strsignal                psignal
//!   31   "Bad system call"        "p: Bad system call"
//!   32   "Unknown signal 32"      "p: Unknown signal 32"
//!   34   "Real-time signal 0"     "p: Unknown signal 34"     <-- disagree
//!   64   "Real-time signal 30"    "p: Unknown signal 64"     <-- disagree
//! ```
//!
//! `strsignal` names RT signals; `psignal` does not. Routing `psignal` through
//! `strsignal` — the obvious simplification, and the one a reviewer is most
//! likely to suggest — silently breaks parity for every RT signal. fl already
//! gets this right (`psignal_description_into` names only 1..=31) and says so in
//! a comment; this gate is what makes that comment enforceable.
//!
//! ## Prefix handling
//!
//! A NULL prefix and an EMPTY prefix both suppress the `": "` separator
//! entirely rather than emitting a bare colon — measured, and the two are
//! separate arms because a `!s.is_null()` check alone passes the first and
//! fails the second.

use std::ffi::{CStr, CString, c_char, c_int};
use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::sync::Mutex;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

#[path = "common/fd_capture.rs"]
mod fd_capture;

type PsignalFn = unsafe extern "C" fn(c_int, *const c_char);

fn host_psignal() -> PsignalFn {
    // SAFETY: `void psignal(int, const char *)`, with fl's own export supplied
    // so the oracle refuses to resolve back to fl (bd-v0388t).
    unsafe {
        host_fn(
            c"psignal",
            frankenlibc_abi::string_abi::psignal as *const (),
        )
    }
}

/// Run `body` with stderr redirected to a pipe and return what it wrote.
///
/// fl writes through a raw `write(2)` syscall and glibc through stdio, so the
/// capture has to be at the FILE DESCRIPTOR level; capturing Rust's `io::stderr`
/// would see neither.
/// Serialises the fd-2 redirect window below.
///
/// `capture_stderr` redirects PROCESS-GLOBAL file descriptor 2, and libtest runs
/// this file's tests on parallel threads by default. Two concurrent captures
/// interleave: one test's `dup2(saved, 2)` restores stderr while another is
/// still inside its window, so that test's bytes go to the real stderr instead
/// of its pipe, and a reader can be left blocked in `read_to_end` on a pipe
/// whose write end is still held open through fd 2 by the other thread.
///
/// Both failure modes were observed, not theorised. Under default parallelism
/// this file produced `strsignal_names_real_time_signals_where_psignal_does_not
/// ... FAILED` with the expected text visible on the RUN'S OWN stderr — proving
/// it had escaped the capture — while `psignal_matches_live_glibc_on_stderr`
/// hung until rch killed the run at its 1800s SSH timeout. With
/// `--test-threads=1` both pass in 0.00s. bd-rfd32s.
///
/// Eight sibling stderr-capturing gates in this directory already take a lock
/// exactly like this one (`conformance_diff_herror`, `_err_h`, `_error`,
/// `_error_at_line`, `_psiginfo`, `_syslog_mask`, and the two `_long_double_live`
/// pair); this file and two others were the ones that did not.
static CAPTURE_LOCK: Mutex<()> = Mutex::new(());

fn capture_stderr(body: impl FnOnce()) -> Vec<u8> {
    let _guard = CAPTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: pipe/dup/dup2 on descriptors this function owns for its duration.
    unsafe {
        let mut fds = [0 as c_int; 2];
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0, "pipe failed");
        let (read_fd, write_fd) = (fds[0], fds[1]);
        // Restored by a Drop guard, INCLUDING on unwind: a panic in `body()` would
        // skip a straight-line restore and leave this process's stderr pointed at
        // the pipe for the rest of the run, swallowing libtest's report of that
        // very failure (bd-ug42ol). Block-scoped so fd 2 is restored BEFORE the
        // read below: while redirected it holds a second reference to the pipe's
        // WRITE end and the reader would never see EOF.
        {
            let _restore = fd_capture::StdFdRestore::new(2);

            assert!(libc::dup2(write_fd, 2) >= 0, "dup2 onto stderr failed");
            libc::close(write_fd);

            body();
            // glibc buffers; flush before restoring or the bytes arrive too late.
            libc::fflush(std::ptr::null_mut());
        }

        let mut file = std::fs::File::from_raw_fd(read_fd);
        let mut out = Vec::new();
        let _ = file.read_to_end(&mut out);
        out
    }
}

/// `(signal, prefix, expected)` — probed from live glibc.
const VECTORS: &[(c_int, Option<&str>, &str)] = &[
    (11, Some("boom"), "boom: Segmentation fault\n"),
    (1, Some("p"), "p: Hangup\n"),
    (31, Some("p"), "p: Bad system call\n"),
    // An empty prefix suppresses the separator, exactly like NULL.
    (11, Some(""), "Segmentation fault\n"),
    (11, None, "Segmentation fault\n"),
    // Out of range in both directions.
    (0, Some("p"), "p: Unknown signal 0\n"),
    (-1, Some("p"), "p: Unknown signal -1\n"),
    (32, Some("p"), "p: Unknown signal 32\n"),
    (33, Some("p"), "p: Unknown signal 33\n"),
    // THE TRAP: real-time signals. strsignal names these; psignal does not.
    (34, Some("p"), "p: Unknown signal 34\n"),
    (40, Some("p"), "p: Unknown signal 40\n"),
    (64, Some("p"), "p: Unknown signal 64\n"),
    (999, Some("p"), "p: Unknown signal 999\n"),
];

#[test]
fn psignal_matches_live_glibc_on_stderr() {
    let host = host_psignal();
    let mut divergences = Vec::new();

    for (sig, prefix, expected) in VECTORS {
        let owned = prefix.map(|p| CString::new(p).expect("prefix has no NUL"));
        let ptr = owned.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());

        // SAFETY: `ptr` is NULL or NUL-terminated and outlives the call.
        let host_out = capture_stderr(|| unsafe { host(*sig, ptr) });
        assert_eq!(
            String::from_utf8_lossy(&host_out),
            *expected,
            "host glibc no longer produces the recorded output for signal {sig}"
        );

        // SAFETY: same arguments through fl's entry point.
        let fl_out = capture_stderr(|| unsafe { frankenlibc_abi::string_abi::psignal(*sig, ptr) });

        if fl_out != host_out {
            divergences.push(format!(
                "  signal {sig} prefix {prefix:?}\n    fl    = {:?}\n    glibc = {:?}",
                String::from_utf8_lossy(&fl_out),
                String::from_utf8_lossy(&host_out),
            ));
        }
    }
    assert!(
        divergences.is_empty(),
        "psignal divergences from live glibc:\n{}",
        divergences.join("\n")
    );
}

/// Pin the asymmetry itself, so the reason `psignal` may not simply call
/// `strsignal` is enforced rather than only documented.
#[test]
fn strsignal_names_real_time_signals_where_psignal_does_not() {
    type StrsignalFn = unsafe extern "C" fn(c_int) -> *const c_char;
    // SAFETY: `char *strsignal(int)`, fl's own export supplied as the guard.
    let host_strsignal: StrsignalFn = unsafe {
        host_fn(
            c"strsignal",
            frankenlibc_abi::string_abi::strsignal as *const (),
        )
    };

    for sig in [34, 40, 64] {
        // SAFETY: the resolved symbol with a scalar argument.
        let named = unsafe { CStr::from_ptr(host_strsignal(sig)) }
            .to_string_lossy()
            .into_owned();
        assert!(
            named.starts_with("Real-time signal"),
            "glibc strsignal({sig}) should name the RT signal, got {named:?}"
        );

        let printed = capture_stderr(|| {
            // SAFETY: NUL-terminated literal prefix.
            unsafe { frankenlibc_abi::string_abi::psignal(sig, c"p".as_ptr()) }
        });
        assert_eq!(
            String::from_utf8_lossy(&printed),
            format!("p: Unknown signal {sig}\n"),
            "fl psignal({sig}) must NOT borrow strsignal's RT naming — glibc's \
             psignal does not name real-time signals (bd-rfd32s)"
        );
    }
}
