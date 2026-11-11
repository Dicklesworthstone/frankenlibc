//! Differential gate: system() ignores SIGINT/SIGQUIT in the caller while the
//! command runs, matching glibc (POSIX).
//!
//! POSIX requires system() to set SIGINT and SIGQUIT to ignored in the calling
//! process for the duration of the command (glibc does this via posix_spawn
//! SETSIGDEF). fl previously left the caller's handlers active, so a SIGINT
//! raised during system() wrongly fired them.
//!
//! Deterministic check: install a SIGINT handler that sets a flag, then run a
//! command that sends SIGINT back to the parent (`kill -INT $PPID`) before
//! exiting 7. A conforming system() discards that SIGINT (flag stays 0) and
//! still returns exit status 7. We require fl to match the host's system()
//! (libc::system) on both the flag and the exit status.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::stdlib_abi as fl;
use std::ffi::{c_char, c_int};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

static SIGINT_FIRED: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_sigint(_sig: c_int) {
    SIGINT_FIRED.fetch_add(1, Ordering::SeqCst);
}

/// Signal state is process-global. Run each case in its own bounded process
/// instead of changing the libtest runner's dispositions under other tests.
fn isolated(name: &str, case: impl FnOnce()) {
    if std::env::var("FRANKENLIBC_SYSTEM_SIGNAL_TEST").as_deref() == Ok(name) {
        case();
        return;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("FRANKENLIBC_SYSTEM_SIGNAL_TEST", name)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{name}: {}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            break;
        }
        if Instant::now() >= deadline {
            // SAFETY: this subprocess owns a new process group; include its
            // shell so a failing system wait cannot leave an orphan behind.
            unsafe { libc::kill(-(child.id() as c_int), libc::SIGKILL) };
            let _ = child.wait();
            panic!("{name}: system test exceeded its deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

struct SignalRestore(c_int, libc::sigaction);

impl SignalRestore {
    fn install(signal: c_int, handler: libc::sighandler_t) -> Self {
        // SAFETY: sigaction receives initialized actions and owned output.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            let mut old: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler;
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(libc::sigaction(signal, &action, &mut old), 0);
            Self(signal, old)
        }
    }
}

impl Drop for SignalRestore {
    fn drop(&mut self) {
        // SAFETY: restore the complete action captured for this signal.
        unsafe { libc::sigaction(self.0, &self.1, std::ptr::null_mut()) };
    }
}

/// Run `sys` on a command that signals the parent, returning (fired, status).
fn run(sys: impl Fn(*const c_char) -> c_int) -> (i32, c_int) {
    let _signal = SignalRestore::install(libc::SIGINT, on_sigint as *const () as usize);
    SIGINT_FIRED.store(0, Ordering::SeqCst);
    // The shell ($PPID == this process) signals us, then exits 7.
    let cmd = c"kill -INT $PPID; exit 7";
    let status = sys(cmd.as_ptr());
    let fired = SIGINT_FIRED.load(Ordering::SeqCst);
    (fired, status)
}

#[test]
fn system_ignores_sigint_in_caller_like_glibc() {
    isolated("system_ignores_sigint_in_caller_like_glibc", || {
        // glibc reference.
        // SAFETY: a NUL-terminated command string.
        let (g_fired, g_status) = run(|cmd| unsafe { libc::system(cmd) });
        assert_eq!(
            g_fired, 0,
            "glibc system() should keep SIGINT ignored in the caller"
        );
        assert!(
            libc::WIFEXITED(g_status) && libc::WEXITSTATUS(g_status) == 7,
            "glibc system() should return exit status 7, got {g_status:#x}"
        );

        // fl must match.
        // fl's system is extern "C-unwind" (a cancellation point, 7660478f3).
        // SAFETY: as above.
        let (f_fired, f_status) = run(|cmd| unsafe { fl::system(cmd) });
        assert_eq!(
            f_fired, g_fired,
            "fl system() let SIGINT through to the caller (fired={f_fired}, glibc={g_fired})"
        );
        assert_eq!(
            libc::WEXITSTATUS(f_status),
            libc::WEXITSTATUS(g_status),
            "fl system() exit status diverged: fl={:#x} glibc={:#x}",
            f_status,
            g_status
        );
    });
}

#[test]
fn system_preserves_ignored_signals_in_shell_like_glibc() {
    isolated(
        "system_preserves_ignored_signals_in_shell_like_glibc",
        || {
            for (signal, command) in [
                (libc::SIGINT, c"kill -INT $$; exit 31"),
                (libc::SIGQUIT, c"kill -QUIT $$; exit 31"),
            ] {
                let _signal = SignalRestore::install(signal, libc::SIG_IGN);
                // SAFETY: both providers receive the same terminated shell input.
                let reference = unsafe { libc::system(command.as_ptr()) };
                let actual = unsafe { fl::system(command.as_ptr()) };
                assert!(libc::WIFEXITED(reference));
                assert_eq!(libc::WEXITSTATUS(reference), 31);
                assert_eq!(actual, reference, "signal {signal} lost inherited SIG_IGN");
                // SAFETY: query the process disposition into owned storage.
                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                assert_eq!(
                    unsafe { libc::sigaction(signal, std::ptr::null(), &mut action) },
                    0
                );
                assert_eq!(action.sa_sigaction, libc::SIG_IGN);
            }
        },
    );
}
