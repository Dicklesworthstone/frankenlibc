#![cfg(target_os = "linux")]

//! Integration tests for `<signal.h>` ABI entrypoints.

use std::sync::Mutex;

use frankenlibc_abi::signal_abi::{sigaction, signal};

type SigHandler = unsafe extern "C" fn(libc::c_int);

static TEST_GUARD: Mutex<()> = Mutex::new(());

unsafe extern "C" fn noop_handler(_: libc::c_int) {}

#[test]
fn sigaction_query_sigpipe_succeeds() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    let mut old = unsafe { std::mem::zeroed::<libc::sigaction>() };

    let rc = unsafe {
        sigaction(
            libc::SIGPIPE,
            std::ptr::null(),
            &mut old as *mut libc::sigaction,
        )
    };
    assert_eq!(rc, 0, "sigaction(SIGPIPE, NULL, old) must succeed");
}

#[test]
fn signal_sigpipe_install_and_restore_succeeds() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    let sig_err: SigHandler = unsafe { std::mem::transmute(-1isize) };

    let previous = unsafe { signal(libc::SIGPIPE, noop_handler) };
    assert_ne!(
        previous as usize, sig_err as usize,
        "signal(SIGPIPE, handler) should not return SIG_ERR"
    );

    let restore = unsafe { signal(libc::SIGPIPE, previous) };
    assert_ne!(
        restore as usize, sig_err as usize,
        "restoring previous SIGPIPE handler should not return SIG_ERR"
    );
}
