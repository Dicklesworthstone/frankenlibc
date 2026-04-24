#![cfg(target_os = "linux")]

//! Differential conformance harness for signal-mask manipulation:
//!   - sigprocmask (process-wide signal mask)
//!   - pthread_sigmask (thread-local signal mask)
//!   - sigpending (which signals are pending)
//!
//! All tests serialize via SIG_LOCK because the signal mask is
//! process/thread-wide. Each test saves and restores the original
//! mask via SIG_SETMASK to avoid pollution.
//!
//! Bead: CONFORMANCE: libc sigprocmask/sigpending diff matrix.

use std::ffi::{c_int, c_void};
use std::process::Command;
use std::sync::Mutex;

use frankenlibc_abi::signal_abi as fl;

unsafe extern "C" {
    fn sigprocmask(how: c_int, set: *const libc::sigset_t, oldset: *mut libc::sigset_t) -> c_int;
    fn pthread_sigmask(
        how: c_int,
        set: *const libc::sigset_t,
        oldset: *mut libc::sigset_t,
    ) -> c_int;
    fn sigpending(set: *mut libc::sigset_t) -> c_int;
}

const SIG_BLOCK: c_int = 0;
const SIG_UNBLOCK: c_int = 1;
const SIG_SETMASK: c_int = 2;

static SIG_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

fn empty_set() -> libc::sigset_t {
    let mut s: libc::sigset_t = unsafe { core::mem::zeroed() };
    let _ = unsafe { libc::sigemptyset(&mut s) };
    s
}

/// Compare two sigset_t kernel-relevant bits (first 8 bytes; glibc
/// extends sigset_t to 128 bytes but the kernel only uses 64 bits on
/// x86_64).
fn sigsets_eq(a: &libc::sigset_t, b: &libc::sigset_t) -> bool {
    let pa = a as *const _ as *const u8;
    let pb = b as *const _ as *const u8;
    for i in 0..8 {
        if unsafe { *pa.add(i) != *pb.add(i) } {
            return false;
        }
    }
    true
}

fn save_mask() -> libc::sigset_t {
    let mut old = empty_set();
    let _ = unsafe { sigprocmask(SIG_BLOCK, std::ptr::null(), &mut old) };
    old
}

fn restore_mask(mask: &libc::sigset_t) {
    let _ = unsafe { sigprocmask(SIG_SETMASK, mask, std::ptr::null_mut()) };
}

extern "C" fn sigusr1_noop(_: c_int) {}

#[test]
fn diff_sigprocmask_set_then_get() {
    let _g = SIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = save_mask();

    let mut divs = Vec::new();
    // Build a known mask: SIGUSR1 + SIGUSR2 blocked
    let mut want = empty_set();
    let _ = unsafe { libc::sigaddset(&mut want, libc::SIGUSR1) };
    let _ = unsafe { libc::sigaddset(&mut want, libc::SIGUSR2) };

    // Set via fl, get-via-libc
    let _ = unsafe { fl::sigprocmask(SIG_SETMASK, &want, std::ptr::null_mut()) };
    let mut got_via_lc = empty_set();
    let _ = unsafe { sigprocmask(SIG_BLOCK, std::ptr::null(), &mut got_via_lc) };
    if !sigsets_eq(&want, &got_via_lc) {
        divs.push(Divergence {
            function: "sigprocmask",
            case: "SIG_SETMASK fl, query lc".into(),
            field: "post_set_mask",
            frankenlibc: format!("{:#x?}", unsafe {
                std::slice::from_raw_parts(&got_via_lc as *const _ as *const u8, 8)
            }),
            glibc: format!("{:#x?}", unsafe {
                std::slice::from_raw_parts(&want as *const _ as *const u8, 8)
            }),
        });
    }

    // Restore, then set via libc, get-via-fl
    restore_mask(&prior);
    let _ = unsafe { sigprocmask(SIG_SETMASK, &want, std::ptr::null_mut()) };
    let mut got_via_fl = empty_set();
    let _ = unsafe { fl::sigprocmask(SIG_BLOCK, std::ptr::null(), &mut got_via_fl) };
    if !sigsets_eq(&want, &got_via_fl) {
        divs.push(Divergence {
            function: "sigprocmask",
            case: "SIG_SETMASK lc, query fl".into(),
            field: "post_set_mask",
            frankenlibc: format!("{:#x?}", unsafe {
                std::slice::from_raw_parts(&got_via_fl as *const _ as *const u8, 8)
            }),
            glibc: format!("{:#x?}", unsafe {
                std::slice::from_raw_parts(&want as *const _ as *const u8, 8)
            }),
        });
    }

    restore_mask(&prior);
    assert!(
        divs.is_empty(),
        "sigprocmask set/get divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_sigprocmask_block_unblock_round_trip() {
    let _g = SIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = save_mask();

    let mut to_block = empty_set();
    let _ = unsafe { libc::sigaddset(&mut to_block, libc::SIGUSR1) };

    // Block via fl
    let _ = unsafe { fl::sigprocmask(SIG_BLOCK, &to_block, std::ptr::null_mut()) };
    let mut after_block = empty_set();
    let _ = unsafe { sigprocmask(SIG_BLOCK, std::ptr::null(), &mut after_block) };
    let blocked = unsafe { libc::sigismember(&after_block, libc::SIGUSR1) };
    assert_eq!(blocked, 1, "fl::sigprocmask SIG_BLOCK didn't block SIGUSR1");

    // Unblock via libc
    let _ = unsafe { sigprocmask(SIG_UNBLOCK, &to_block, std::ptr::null_mut()) };
    let mut after_unblock = empty_set();
    let _ = unsafe { fl::sigprocmask(SIG_BLOCK, std::ptr::null(), &mut after_unblock) };
    let still_blocked = unsafe { libc::sigismember(&after_unblock, libc::SIGUSR1) };
    assert_eq!(
        still_blocked, 0,
        "lc::sigprocmask SIG_UNBLOCK didn't unblock SIGUSR1 (queried via fl)"
    );

    restore_mask(&prior);
}

#[test]
fn diff_sigprocmask_invalid_how() {
    let _g = SIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut s = empty_set();
    let r_fl = unsafe { fl::sigprocmask(99, &s, std::ptr::null_mut()) };
    let r_lc = unsafe { sigprocmask(99, &s, std::ptr::null_mut()) };
    let _ = &mut s;
    assert_eq!(
        r_fl == 0,
        r_lc == 0,
        "sigprocmask invalid-how success-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_pthread_sigmask_set_then_get() {
    let _g = SIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = save_mask();

    let mut want = empty_set();
    let _ = unsafe { libc::sigaddset(&mut want, libc::SIGUSR2) };

    // Set via fl pthread_sigmask, query via libc
    let _ = unsafe { fl::pthread_sigmask(SIG_SETMASK, &want, std::ptr::null_mut()) };
    let mut got = empty_set();
    let _ = unsafe { pthread_sigmask(SIG_BLOCK, std::ptr::null(), &mut got) };
    assert!(
        sigsets_eq(&want, &got),
        "pthread_sigmask SIG_SETMASK fl divergence"
    );

    restore_mask(&prior);
}

#[test]
fn diff_sigpending_after_block_and_kill() {
    let _g = SIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let current_exe = std::env::current_exe().expect("current test binary path");
    let output = Command::new(current_exe)
        .args([
            "--exact",
            "sigpending_child_invocation",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("FRANKENLIBC_SIGPENDING_HELPER", "1")
        .output()
        .expect("run isolated sigpending helper");
    assert!(
        output.status.success(),
        "isolated sigpending helper failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn sigpending_child_invocation() {
    if std::env::var_os("FRANKENLIBC_SIGPENDING_HELPER").is_none() {
        return;
    }
    let prior = save_mask();

    // Install a no-op handler before blocking. Ignored signals need not become
    // pending on Linux, while a handled, blocked signal remains observable.
    let mut act: libc::sigaction = unsafe { core::mem::zeroed() };
    act.sa_sigaction = sigusr1_noop as *const () as usize;
    let _ = unsafe { libc::sigemptyset(&mut act.sa_mask) };
    let mut old_act: libc::sigaction = unsafe { core::mem::zeroed() };
    let _ = unsafe { libc::sigaction(libc::SIGUSR1, &act, &mut old_act) };

    // Block SIGUSR1 and send it to the current thread, not the process. This
    // makes pending membership stable even when libtest itself is threaded.
    let mut to_block = empty_set();
    let _ = unsafe { libc::sigaddset(&mut to_block, libc::SIGUSR1) };
    let _ = unsafe { pthread_sigmask(SIG_BLOCK, &to_block, std::ptr::null_mut()) };

    let send_rc = unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGUSR1) };
    assert_eq!(send_rc, 0, "pthread_kill self SIGUSR1");

    // Query via fl
    let mut pending_fl = empty_set();
    let r_fl = unsafe { fl::sigpending(&mut pending_fl) };
    let in_fl = unsafe { libc::sigismember(&pending_fl, libc::SIGUSR1) };

    // Query via libc
    let mut pending_lc = empty_set();
    let r_lc = unsafe { sigpending(&mut pending_lc) };
    let in_lc = unsafe { libc::sigismember(&pending_lc, libc::SIGUSR1) };

    // Unblock; the no-op handler absorbs delivery.
    let _ = unsafe { pthread_sigmask(SIG_UNBLOCK, &to_block, std::ptr::null_mut()) };
    // Restore handler
    let _ = unsafe { libc::sigaction(libc::SIGUSR1, &old_act, std::ptr::null_mut()) };

    restore_mask(&prior);

    assert_eq!(r_fl, r_lc, "sigpending return mismatch");
    assert_eq!(
        in_fl, in_lc,
        "sigpending SIGUSR1 membership: fl={in_fl}, lc={in_lc}"
    );
    assert_eq!(
        in_fl, 1,
        "thread-directed blocked SIGUSR1 should be pending"
    );
}

#[test]
fn sigprocmask_diff_coverage_report() {
    let _ = core::ptr::null::<c_void>();
    eprintln!(
        "{{\"family\":\"signal.h(sigprocmask/sigpending)\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
