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
use std::sync::atomic::{AtomicI32, Ordering};

static SIGINT_FIRED: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_sigint(_sig: c_int) {
    SIGINT_FIRED.fetch_add(1, Ordering::SeqCst);
}

type SystemFn = unsafe extern "C" fn(*const c_char) -> c_int;

fn install_sigint_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigint as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
}

/// Run `sys` on a command that signals the parent, returning (fired, status).
fn run(sys: SystemFn) -> (i32, c_int) {
    install_sigint_handler();
    SIGINT_FIRED.store(0, Ordering::SeqCst);
    // The shell ($PPID == this process) signals us, then exits 7.
    let cmd = c"kill -INT $PPID; exit 7";
    let status = unsafe { sys(cmd.as_ptr()) };
    let fired = SIGINT_FIRED.load(Ordering::SeqCst);
    (fired, status)
}

#[test]
fn system_ignores_sigint_in_caller_like_glibc() {
    // glibc reference.
    let (g_fired, g_status) = run(libc::system);
    assert_eq!(g_fired, 0, "glibc system() should keep SIGINT ignored in the caller");
    assert!(
        libc::WIFEXITED(g_status) && libc::WEXITSTATUS(g_status) == 7,
        "glibc system() should return exit status 7, got {g_status:#x}"
    );

    // fl must match.
    let (f_fired, f_status) = run(fl::system);
    assert_eq!(
        f_fired, g_fired,
        "fl system() let SIGINT through to the caller (fired={f_fired}, glibc={g_fired})"
    );
    assert_eq!(
        libc::WEXITSTATUS(f_status),
        libc::WEXITSTATUS(g_status),
        "fl system() exit status diverged: fl={:#x} glibc={:#x}",
        f_status, g_status
    );
}
