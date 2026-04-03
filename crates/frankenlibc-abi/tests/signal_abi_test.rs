#![cfg(target_os = "linux")]

//! Integration tests for `<signal.h>` ABI entrypoints.
//!
//! Covers: sigemptyset, sigfillset, sigaddset, sigdelset, sigismember,
//! sigandset, sigorset, sigisemptyset, sigabbrev_np, sigdescr_np,
//! __libc_current_sigrtmin/max, sigprocmask, sigpending, signal, sigaction,
//! kill, sighold, sigrelse, sigignore.

use std::ffi::c_int;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::signal_abi::{
    __libc_current_sigrtmax, __libc_current_sigrtmin, SIGNAL_SAFETY_MAP, SignalCriticalSectionKind,
    SignalSafetyClassification, current_signal_classification_for_test,
    enter_signal_critical_section, invoke_signal_handler_for_test, kill,
    reset_signal_delivery_metrics_for_test, sigabbrev_np, sigaction, sigaddset, sigandset,
    sigdelset, sigdescr_np, sigemptyset, sigfillset, sighold, sigignore, siginterrupt,
    sigisemptyset, sigismember, signal, signal_delivery_metrics_for_test, sigorset, sigpending,
    sigprocmask, sigrelse,
};
use frankenlibc_core::errno;

static TEST_GUARD: Mutex<()> = Mutex::new(());
static DEFERRED_HANDLER_COUNT: AtomicUsize = AtomicUsize::new(0);
static LIVE_HANDLER_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn noop_handler(_: c_int) {}
unsafe extern "C" fn counting_handler(_: c_int) {
    DEFERRED_HANDLER_COUNT.fetch_add(1, Ordering::Relaxed);
}
unsafe extern "C" fn live_counting_handler(_: c_int) {
    LIVE_HANDLER_COUNT.fetch_add(1, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// sigemptyset / sigfillset
// ---------------------------------------------------------------------------

#[test]
fn sigemptyset_zeros_set() {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // Fill first to ensure sigemptyset actually clears
    let _ = unsafe { sigfillset(&mut set) };
    let rc = unsafe { sigemptyset(&mut set) };
    assert_eq!(rc, 0);
    // Verify SIGUSR1 is not a member
    assert_eq!(unsafe { sigismember(&set, libc::SIGUSR1) }, 0);
}

#[test]
fn sigemptyset_null_returns_neg1() {
    unsafe { *__errno_location() = 0 };
    let rc = unsafe { sigemptyset(std::ptr::null_mut()) };
    assert_eq!(rc, -1);
    assert_eq!(unsafe { *__errno_location() }, errno::EINVAL);
}

#[test]
fn sigfillset_sets_all_bits() {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigfillset(&mut set) };
    assert_eq!(rc, 0);
    // Several signals should be members
    assert_eq!(unsafe { sigismember(&set, libc::SIGUSR1) }, 1);
    assert_eq!(unsafe { sigismember(&set, libc::SIGUSR2) }, 1);
    assert_eq!(unsafe { sigismember(&set, libc::SIGTERM) }, 1);
    assert_eq!(unsafe { sigismember(&set, libc::SIGHUP) }, 1);
}

#[test]
fn sigfillset_null_returns_neg1() {
    unsafe { *__errno_location() = 0 };
    let rc = unsafe { sigfillset(std::ptr::null_mut()) };
    assert_eq!(rc, -1);
    assert_eq!(unsafe { *__errno_location() }, errno::EINVAL);
}

// ---------------------------------------------------------------------------
// sigaddset / sigdelset / sigismember
// ---------------------------------------------------------------------------

#[test]
fn sigaddset_and_sigismember() {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { sigemptyset(&mut set) };

    assert_eq!(unsafe { sigismember(&set, libc::SIGUSR1) }, 0);
    let rc = unsafe { sigaddset(&mut set, libc::SIGUSR1) };
    assert_eq!(rc, 0);
    assert_eq!(unsafe { sigismember(&set, libc::SIGUSR1) }, 1);
    // Other signals should still be absent
    assert_eq!(unsafe { sigismember(&set, libc::SIGUSR2) }, 0);
}

#[test]
fn sigdelset_removes_signal() {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { sigfillset(&mut set) };

    assert_eq!(unsafe { sigismember(&set, libc::SIGUSR1) }, 1);
    let rc = unsafe { sigdelset(&mut set, libc::SIGUSR1) };
    assert_eq!(rc, 0);
    assert_eq!(unsafe { sigismember(&set, libc::SIGUSR1) }, 0);
    // SIGUSR2 should still be set
    assert_eq!(unsafe { sigismember(&set, libc::SIGUSR2) }, 1);
}

#[test]
fn sigaddset_invalid_signal_returns_neg1() {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { sigemptyset(&mut set) };
    let rc = unsafe { sigaddset(&mut set, 0) };
    assert_eq!(rc, -1);
}

#[test]
fn sigdelset_invalid_signal_returns_neg1() {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { sigfillset(&mut set) };
    let rc = unsafe { sigdelset(&mut set, 0) };
    assert_eq!(rc, -1);
}

#[test]
fn sigismember_invalid_signal_returns_neg1() {
    let set: libc::sigset_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigismember(&set, 0) };
    assert_eq!(rc, -1);
}

#[test]
fn sigaddset_multiple_signals() {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { sigemptyset(&mut set) };

    let signals = [libc::SIGUSR1, libc::SIGUSR2, libc::SIGTERM, libc::SIGHUP];
    for &sig in &signals {
        assert_eq!(unsafe { sigaddset(&mut set, sig) }, 0);
    }
    for &sig in &signals {
        assert_eq!(unsafe { sigismember(&set, sig) }, 1);
    }
    // SIGINT should not be set
    assert_eq!(unsafe { sigismember(&set, libc::SIGINT) }, 0);
}

// ---------------------------------------------------------------------------
// sigandset / sigorset / sigisemptyset
// ---------------------------------------------------------------------------

#[test]
fn sigandset_intersection() {
    let mut a: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut b: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut result: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        sigemptyset(&mut a);
        sigemptyset(&mut b);
        sigaddset(&mut a, libc::SIGUSR1);
        sigaddset(&mut a, libc::SIGUSR2);
        sigaddset(&mut b, libc::SIGUSR2);
        sigaddset(&mut b, libc::SIGTERM);
    }
    let rc = unsafe { sigandset(&mut result, &a, &b) };
    assert_eq!(rc, 0);
    // Intersection: only SIGUSR2
    assert_eq!(unsafe { sigismember(&result, libc::SIGUSR1) }, 0);
    assert_eq!(unsafe { sigismember(&result, libc::SIGUSR2) }, 1);
    assert_eq!(unsafe { sigismember(&result, libc::SIGTERM) }, 0);
}

#[test]
fn sigorset_union() {
    let mut a: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut b: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut result: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        sigemptyset(&mut a);
        sigemptyset(&mut b);
        sigaddset(&mut a, libc::SIGUSR1);
        sigaddset(&mut b, libc::SIGUSR2);
    }
    let rc = unsafe { sigorset(&mut result, &a, &b) };
    assert_eq!(rc, 0);
    assert_eq!(unsafe { sigismember(&result, libc::SIGUSR1) }, 1);
    assert_eq!(unsafe { sigismember(&result, libc::SIGUSR2) }, 1);
    assert_eq!(unsafe { sigismember(&result, libc::SIGTERM) }, 0);
}

#[test]
fn sigisemptyset_empty() {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { sigemptyset(&mut set) };
    assert_eq!(unsafe { sigisemptyset(&set) }, 1);
}

#[test]
fn sigisemptyset_nonempty() {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        sigemptyset(&mut set);
        sigaddset(&mut set, libc::SIGUSR1);
    }
    assert_eq!(unsafe { sigisemptyset(&set) }, 0);
}

#[test]
fn sigisemptyset_null_returns_neg1() {
    unsafe { *__errno_location() = 0 };
    let rc = unsafe { sigisemptyset(std::ptr::null()) };
    assert_eq!(rc, -1);
    assert_eq!(unsafe { *__errno_location() }, errno::EINVAL);
}

#[test]
fn sigandset_null_returns_neg1() {
    let set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { *__errno_location() = 0 };
    let rc = unsafe { sigandset(std::ptr::null_mut(), &set, &set) };
    assert_eq!(rc, -1);
    assert_eq!(unsafe { *__errno_location() }, errno::EINVAL);
}

// ---------------------------------------------------------------------------
// sigabbrev_np / sigdescr_np
// ---------------------------------------------------------------------------

#[test]
fn sigabbrev_np_known_signals() {
    let check = |sig: c_int, expected: &[u8]| {
        let ptr = unsafe { sigabbrev_np(sig) };
        assert!(!ptr.is_null(), "sigabbrev_np({sig}) should not be null");
        let s = unsafe { std::ffi::CStr::from_ptr(ptr) };
        assert_eq!(s.to_bytes(), expected, "sigabbrev_np({sig})");
    };
    check(libc::SIGHUP, b"HUP");
    check(libc::SIGINT, b"INT");
    check(libc::SIGQUIT, b"QUIT");
    check(libc::SIGKILL, b"KILL");
    check(libc::SIGSEGV, b"SEGV");
    check(libc::SIGTERM, b"TERM");
    check(libc::SIGPIPE, b"PIPE");
    check(libc::SIGUSR1, b"USR1");
    check(libc::SIGUSR2, b"USR2");
}

#[test]
fn sigabbrev_np_invalid_returns_null() {
    assert!(unsafe { sigabbrev_np(-1) }.is_null());
    assert!(unsafe { sigabbrev_np(100) }.is_null());
}

#[test]
fn sigdescr_np_known_signals() {
    let check = |sig: c_int, needle: &[u8]| {
        let ptr = unsafe { sigdescr_np(sig) };
        assert!(!ptr.is_null(), "sigdescr_np({sig}) should not be null");
        let s = unsafe { std::ffi::CStr::from_ptr(ptr) };
        assert!(
            !s.to_bytes().is_empty(),
            "sigdescr_np({sig}) should not be empty"
        );
        // Just check it contains the expected substring
        let text = s.to_bytes();
        let found = text
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle));
        assert!(
            found,
            "sigdescr_np({sig}) = {:?} should contain {:?}",
            std::str::from_utf8(text),
            std::str::from_utf8(needle),
        );
    };
    check(libc::SIGHUP, b"Hangup");
    check(libc::SIGINT, b"Interrupt");
    check(libc::SIGKILL, b"Kill");
    check(libc::SIGSEGV, b"Segmentation");
    check(libc::SIGTERM, b"Terminat");
}

#[test]
fn sigdescr_np_invalid_returns_null() {
    assert!(unsafe { sigdescr_np(-1) }.is_null());
    assert!(unsafe { sigdescr_np(100) }.is_null());
}

// ---------------------------------------------------------------------------
// __libc_current_sigrtmin / __libc_current_sigrtmax
// ---------------------------------------------------------------------------

#[test]
fn sigrtmin_returns_valid_value() {
    let rtmin = unsafe { __libc_current_sigrtmin() };
    // On Linux, SIGRTMIN after NPTL reservation is typically 34 or 35
    assert!(
        (32..=40).contains(&rtmin),
        "SIGRTMIN should be in [32,40], got {rtmin}"
    );
}

#[test]
fn sigrtmax_returns_64() {
    let rtmax = unsafe { __libc_current_sigrtmax() };
    assert_eq!(rtmax, 64, "SIGRTMAX on x86_64 Linux should be 64");
}

#[test]
fn sigrtmin_less_than_sigrtmax() {
    let rtmin = unsafe { __libc_current_sigrtmin() };
    let rtmax = unsafe { __libc_current_sigrtmax() };
    assert!(rtmin < rtmax);
}

// ---------------------------------------------------------------------------
// sigaction tests
// ---------------------------------------------------------------------------

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
fn sigaction_install_and_restore() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");

    // Save the original handler
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigaction(libc::SIGUSR1, std::ptr::null(), &mut old) };
    assert_eq!(rc, 0);

    // Install our handler
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = noop_handler as *const () as usize;
    let mut prev: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigaction(libc::SIGUSR1, &act, &mut prev) };
    assert_eq!(rc, 0);

    // Restore original
    let rc = unsafe { sigaction(libc::SIGUSR1, &old, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
}

// ---------------------------------------------------------------------------
// signal tests
// ---------------------------------------------------------------------------

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

#[test]
fn signal_safety_map_covers_allocator_and_membrane_ranges() {
    assert!(
        SIGNAL_SAFETY_MAP.len() >= 10,
        "expected at least 10 critical sections"
    );
    assert!(SIGNAL_SAFETY_MAP.iter().any(|range| {
        range.range_label == "malloc.arena_lock_acquire"
            && range.classification == SignalSafetyClassification::MaskRequired
    }));
    assert!(SIGNAL_SAFETY_MAP.iter().any(|range| {
        range.range_label == "membrane.arena_lookup"
            && range.classification == SignalSafetyClassification::DeferSignal
    }));
}

#[test]
fn signal_delivery_is_deferred_inside_critical_section() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    DEFERRED_HANDLER_COUNT.store(0, Ordering::Relaxed);

    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigaction(libc::SIGUSR1, std::ptr::null(), &mut old) };
    assert_eq!(rc, 0, "must capture original SIGUSR1 disposition");

    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = counting_handler as *const () as usize;
    let rc = unsafe { sigaction(libc::SIGUSR1, &act, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "must install counting handler");

    {
        let _critical =
            enter_signal_critical_section(SignalCriticalSectionKind::MallocArenaLockAcquire);
        assert_eq!(
            current_signal_classification_for_test(),
            SignalSafetyClassification::MaskRequired
        );
        unsafe { invoke_signal_handler_for_test(libc::SIGUSR1) };
        assert_eq!(
            DEFERRED_HANDLER_COUNT.load(Ordering::Relaxed),
            0,
            "SIGUSR1 should stay deferred until the critical section exits"
        );
    }

    assert_eq!(
        DEFERRED_HANDLER_COUNT.load(Ordering::Relaxed),
        1,
        "deferred signal must flush on critical section exit"
    );

    let rc = unsafe { sigaction(libc::SIGUSR1, &old, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "must restore original SIGUSR1 disposition");
}

#[test]
fn signal_delivery_remains_immediate_for_safe_classification() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    DEFERRED_HANDLER_COUNT.store(0, Ordering::Relaxed);

    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigaction(libc::SIGUSR1, std::ptr::null(), &mut old) };
    assert_eq!(rc, 0, "must capture original SIGUSR1 disposition");

    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = counting_handler as *const () as usize;
    let rc = unsafe { sigaction(libc::SIGUSR1, &act, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "must install counting handler");

    {
        let _critical =
            enter_signal_critical_section(SignalCriticalSectionKind::PtrValidatorTlsCache);
        assert_eq!(
            current_signal_classification_for_test(),
            SignalSafetyClassification::Safe
        );
        unsafe { invoke_signal_handler_for_test(libc::SIGUSR1) };
        assert_eq!(
            DEFERRED_HANDLER_COUNT.load(Ordering::Relaxed),
            1,
            "safe classifications should dispatch immediately"
        );
    }

    let rc = unsafe { sigaction(libc::SIGUSR1, &old, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "must restore original SIGUSR1 disposition");
}

#[test]
#[ignore = "async signal storm prototype currently segfaults under real pthread_kill delivery"]
fn malloc_storm_defers_reentrant_signal_handler_until_safe_exit() {
    let _guard = TEST_GUARD
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    DEFERRED_HANDLER_COUNT.store(0, Ordering::Relaxed);
    reset_signal_delivery_metrics_for_test();
    frankenlibc_abi::malloc_abi::prewarm_host_allocator_symbols_for_test();
    assert!(
        frankenlibc_abi::malloc_abi::host_allocator_symbols_prewarmed_for_test(),
        "host allocator delegates must prewarm before live signal delivery begins"
    );

    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigaction(libc::SIGUSR1, std::ptr::null(), &mut old) };
    assert_eq!(rc, 0, "must capture original SIGUSR1 disposition");

    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = counting_handler as *const () as usize;
    let rc = unsafe { sigaction(libc::SIGUSR1, &act, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "must install SIGUSR1 handler");

    let (pthread_tx, pthread_rx) = mpsc::channel::<usize>();
    let (done_tx, done_rx) = mpsc::channel::<usize>();

    let worker = thread::spawn(move || {
        let tid = unsafe { libc::pthread_self() as usize };
        pthread_tx.send(tid).expect("must publish pthread_t");
        for iter in 0..20_000usize {
            let size = 32 + (iter % 257);
            let ptr = unsafe { frankenlibc_abi::malloc_abi::malloc(size) };
            assert!(
                !ptr.is_null(),
                "malloc storm allocation {iter} must succeed"
            );
            // SAFETY: abi_malloc(size) returned a live allocation of at least size bytes.
            unsafe {
                std::ptr::write_bytes(ptr.cast::<u8>(), (iter & 0xFF) as u8, size);
                frankenlibc_abi::malloc_abi::free(ptr);
            }
        }
        done_tx
            .send(20_000)
            .expect("must publish worker completion");
    });

    let worker_tid = pthread_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker must publish pthread_t promptly");

    let signaler = thread::spawn(move || {
        for _ in 0..8_000 {
            let rc = unsafe { libc::pthread_kill(worker_tid as libc::pthread_t, libc::SIGUSR1) };
            if rc == libc::ESRCH {
                break;
            }
            assert_eq!(rc, 0, "pthread_kill to storm target must succeed");
        }
    });

    let completed = done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("malloc storm should complete without deadlock");
    worker.join().expect("worker must not panic");
    signaler.join().expect("signaler must not panic");

    let metrics = signal_delivery_metrics_for_test();
    assert_eq!(completed, 20_000);
    assert!(
        DEFERRED_HANDLER_COUNT.load(Ordering::Relaxed) > 0,
        "signal storm should deliver at least one handler invocation"
    );
    assert!(
        metrics.deferred > 0,
        "malloc storm should observe at least one deferred signal delivery"
    );
    assert!(
        metrics.flushed >= metrics.deferred,
        "all deferred deliveries should flush after exiting critical sections"
    );

    let rc = unsafe { sigaction(libc::SIGUSR1, &old, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "must restore original SIGUSR1 disposition");
}

#[test]
fn pthread_kill_delivers_sigusr1_without_allocator_pressure() {
    let _guard = TEST_GUARD
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    LIVE_HANDLER_COUNT.store(0, Ordering::Relaxed);

    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigaction(libc::SIGUSR1, std::ptr::null(), &mut old) };
    assert_eq!(rc, 0, "must capture original SIGUSR1 disposition");

    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = live_counting_handler as *const () as usize;
    let rc = unsafe { sigaction(libc::SIGUSR1, &act, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "must install SIGUSR1 handler");

    let (pthread_tx, pthread_rx) = mpsc::channel::<usize>();
    let (done_tx, done_rx) = mpsc::channel::<()>();

    let worker = thread::spawn(move || {
        let tid = unsafe { libc::pthread_self() as usize };
        pthread_tx.send(tid).expect("must publish pthread_t");
        for _ in 0..200 {
            if LIVE_HANDLER_COUNT.load(Ordering::Relaxed) != 0 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        done_tx.send(()).expect("must report worker exit");
    });

    let worker_tid = pthread_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker must publish pthread_t promptly");
    let rc = unsafe { libc::pthread_kill(worker_tid as libc::pthread_t, libc::SIGUSR1) };
    assert_eq!(rc, 0, "pthread_kill must succeed");

    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker must exit without hanging");
    worker.join().expect("worker must not panic");
    assert_eq!(
        LIVE_HANDLER_COUNT.load(Ordering::Relaxed),
        1,
        "real pthread_kill delivery should invoke the installed SIGUSR1 handler exactly once"
    );

    let rc = unsafe { sigaction(libc::SIGUSR1, &old, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "must restore original SIGUSR1 disposition");
}

// ---------------------------------------------------------------------------
// kill
// ---------------------------------------------------------------------------

#[test]
fn kill_zero_checks_process_exists() {
    // kill(pid, 0) is a process existence check — should succeed for self
    let pid = unsafe { libc::getpid() };
    let rc = unsafe { kill(pid, 0) };
    assert_eq!(rc, 0, "kill(self, 0) should succeed");
}

#[test]
fn kill_nonexistent_pid_fails() {
    // PID -1 with signal 0 should fail (we can't send to all processes)
    let rc = unsafe { kill(i32::MAX, 0) };
    assert_eq!(rc, -1, "kill(MAX_PID, 0) should fail");
}

// ---------------------------------------------------------------------------
// sigprocmask
// ---------------------------------------------------------------------------

#[test]
fn sigprocmask_query_current_mask() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    let mut oldset: libc::sigset_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut oldset) };
    assert_eq!(rc, 0, "sigprocmask query should succeed");
}

#[test]
fn sigprocmask_block_and_unblock_sigusr1() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");

    // Save current mask
    let mut oldmask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut oldmask) };

    // Block SIGUSR1
    let mut blockset: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        sigemptyset(&mut blockset);
        sigaddset(&mut blockset, libc::SIGUSR1);
    }
    let rc = unsafe { sigprocmask(libc::SIG_BLOCK, &blockset, std::ptr::null_mut()) };
    assert_eq!(rc, 0);

    // Restore original mask
    let rc = unsafe { sigprocmask(libc::SIG_SETMASK, &oldmask, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
}

// ---------------------------------------------------------------------------
// sigpending
// ---------------------------------------------------------------------------

#[test]
fn sigpending_returns_set() {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigpending(&mut set) };
    assert_eq!(rc, 0, "sigpending should succeed");
}

// ---------------------------------------------------------------------------
// sighold / sigrelse / sigignore / siginterrupt
// ---------------------------------------------------------------------------

#[test]
fn sighold_and_sigrelse_sigusr1() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    let rc = unsafe { sighold(libc::SIGUSR1) };
    assert_eq!(rc, 0, "sighold(SIGUSR1) should succeed");
    let rc = unsafe { sigrelse(libc::SIGUSR1) };
    assert_eq!(rc, 0, "sigrelse(SIGUSR1) should succeed");
}

#[test]
fn sigignore_sigusr1() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    // Save current disposition
    let prev = unsafe { signal(libc::SIGUSR1, libc::SIG_DFL) };

    let rc = unsafe { sigignore(libc::SIGUSR1) };
    assert_eq!(rc, 0, "sigignore(SIGUSR1) should succeed");

    // Restore
    unsafe { signal(libc::SIGUSR1, prev) };
}

#[test]
fn siginterrupt_sigusr1() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    // siginterrupt modifies SA_RESTART flag; just verify it doesn't fail
    let rc = unsafe { siginterrupt(libc::SIGUSR1, 1) };
    assert_eq!(rc, 0, "siginterrupt(SIGUSR1, 1) should succeed");
    let rc = unsafe { siginterrupt(libc::SIGUSR1, 0) };
    assert_eq!(rc, 0, "siginterrupt(SIGUSR1, 0) should succeed");
}
