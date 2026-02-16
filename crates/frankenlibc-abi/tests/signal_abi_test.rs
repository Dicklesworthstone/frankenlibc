#![cfg(target_os = "linux")]

//! Integration tests for `<signal.h>` ABI entrypoints.

use std::sync::Mutex;

use frankenlibc_abi::signal_abi::{sigaction, signal};

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
    let sig_err = libc::SIG_ERR;

    let previous = unsafe {
        signal(
            libc::SIGPIPE,
            noop_handler as *const () as libc::sighandler_t,
        )
    };
    assert_ne!(
        previous, sig_err,
        "signal(SIGPIPE, handler) should not return SIG_ERR"
    );

    let restore = unsafe { signal(libc::SIGPIPE, previous) };
    assert_ne!(
        restore, sig_err,
        "restoring previous SIGPIPE handler should not return SIG_ERR"
    );
}

#[test]
fn signal_sigpipe_ign_roundtrip_succeeds() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");

    let previous = unsafe { signal(libc::SIGPIPE, libc::SIG_IGN) };
    assert_ne!(
        previous,
        libc::SIG_ERR,
        "signal(SIGPIPE, SIG_IGN) should not return SIG_ERR"
    );

    let restore = unsafe { signal(libc::SIGPIPE, previous) };
    assert_ne!(
        restore,
        libc::SIG_ERR,
        "restoring previous SIGPIPE disposition should not return SIG_ERR"
    );
}
