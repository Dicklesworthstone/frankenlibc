#![cfg(target_os = "linux")]

//! Integration tests for `<signal.h>` ABI entrypoints.
//!
//! Covers: sigemptyset, sigfillset, sigaddset, sigdelset, sigismember,
//! sigandset, sigorset, sigisemptyset, sigabbrev_np, sigdescr_np,
//! __libc_current_sigrtmin/max, sigprocmask, sigpending, signal, sigaction,
//! kill, sighold, sigrelse, sigignore.

use std::ffi::c_int;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::signal_abi::{
    __libc_current_sigrtmax, __libc_current_sigrtmin, SIGNAL_SAFETY_MAP, SignalCriticalSectionKind,
    SignalSafetyClassification, current_signal_classification_for_test,
    enter_signal_critical_section, invoke_signal_handler_for_test, kill, raise_default_signal,
    reset_signal_delivery_metrics_for_test, sigabbrev_np, sigaction, sigaddset, sigandset,
    sigdelset, sigdescr_np, sigemptyset, sigfillset, sighold, sigignore, siginterrupt,
    sigisemptyset, sigismember, signal, signal_delivery_metrics_for_test, sigorset, sigpending,
    sigprocmask, sigrelse,
};
use frankenlibc_core::errno;

static TEST_GUARD: Mutex<()> = Mutex::new(());
static DEFERRED_HANDLER_COUNT: AtomicUsize = AtomicUsize::new(0);
static LIVE_HANDLER_COUNT: AtomicUsize = AtomicUsize::new(0);
static SIGINFO_HANDLER_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_SIGINFO_NONNULL: AtomicUsize = AtomicUsize::new(0);
static LAST_UCONTEXT_NONNULL: AtomicUsize = AtomicUsize::new(0);
static LAST_SIGINFO_CODE: AtomicUsize = AtomicUsize::new(0);
static LAST_SIGINFO_SIGNO: AtomicUsize = AtomicUsize::new(0);
static LAST_SIGINFO_VALUE_BITS: AtomicUsize = AtomicUsize::new(0);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SA_RESTORER_FLAG: c_int = 0x04000000;

unsafe extern "C" fn noop_handler(_: c_int) {}
unsafe extern "C" fn counting_handler(_: c_int) {
    DEFERRED_HANDLER_COUNT.fetch_add(1, Ordering::Relaxed);
}
unsafe extern "C" fn live_counting_handler(_: c_int) {
    LIVE_HANDLER_COUNT.fetch_add(1, Ordering::Relaxed);
}
unsafe extern "C" fn siginfo_counting_handler(
    signum: c_int,
    info: *mut libc::siginfo_t,
    context: *mut std::ffi::c_void,
) {
    SIGINFO_HANDLER_COUNT.fetch_add(1, Ordering::Relaxed);
    LAST_SIGINFO_SIGNO.store(signum as usize, Ordering::Relaxed);
    LAST_SIGINFO_NONNULL.store((!info.is_null()) as usize, Ordering::Relaxed);
    LAST_UCONTEXT_NONNULL.store((!context.is_null()) as usize, Ordering::Relaxed);
    if !info.is_null() {
        // SAFETY: the kernel or deferred replay hands the handler a valid
        // `siginfo_t` snapshot for the current delivery.
        let info_ref = unsafe { &*info };
        let value = unsafe { info_ref.si_value() };
        LAST_SIGINFO_CODE.store(info_ref.si_code as usize, Ordering::Relaxed);
        LAST_SIGINFO_SIGNO.store(info_ref.si_signo as usize, Ordering::Relaxed);
        LAST_SIGINFO_VALUE_BITS.store(value.sival_ptr as usize, Ordering::Relaxed);
    }
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
    check(libc::SIGVTALRM, b"VTALRM");
    check(libc::SIGPROF, b"PROF");
    check(libc::SIGWINCH, b"WINCH");
    check(libc::SIGSYS, b"SYS");
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

#[test]
fn sigaction_pending_signal_invokes_newly_installed_handler() {
    // REVIEW round 2: pin the handler-install ordering. Before the fix,
    // sys_rt_sigaction installed the trampoline before our slot was
    // updated; a signal already pending at install time could be
    // dispatched against a stale handler (or dropped entirely if the
    // slot was zero). After the fix, the slot is written first, so any
    // signal delivered through the trampoline observes the new handler.
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");

    static FIRST_HITS: AtomicI32 = AtomicI32::new(0);
    static SECOND_HITS: AtomicI32 = AtomicI32::new(0);
    FIRST_HITS.store(0, Ordering::SeqCst);
    SECOND_HITS.store(0, Ordering::SeqCst);

    unsafe extern "C" fn first_handler(_sig: c_int) {
        FIRST_HITS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn second_handler(_sig: c_int) {
        SECOND_HITS.fetch_add(1, Ordering::SeqCst);
    }

    let mut saved: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigaction(libc::SIGUSR2, std::ptr::null(), &mut saved) };
    assert_eq!(rc, 0);

    // Install first handler.
    let mut act_a: libc::sigaction = unsafe { std::mem::zeroed() };
    act_a.sa_sigaction = first_handler as *const () as usize;
    assert_eq!(
        unsafe { sigaction(libc::SIGUSR2, &act_a, std::ptr::null_mut()) },
        0,
    );

    // Block SIGUSR2 so we can queue a pending signal.
    let mut block: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        sigemptyset(&mut block);
        sigaddset(&mut block, libc::SIGUSR2);
    }
    let mut prior_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { sigprocmask(libc::SIG_BLOCK, &block, &mut prior_mask) },
        0,
    );

    // Queue SIGUSR2 -- it stays pending while blocked.
    assert_eq!(unsafe { libc::raise(libc::SIGUSR2) }, 0);

    // Replace the handler while the signal is pending. After the fix,
    // the slot is updated before sys_rt_sigaction completes, so when
    // we unblock the signal it must dispatch through second_handler.
    let mut act_b: libc::sigaction = unsafe { std::mem::zeroed() };
    act_b.sa_sigaction = second_handler as *const () as usize;
    assert_eq!(
        unsafe { sigaction(libc::SIGUSR2, &act_b, std::ptr::null_mut()) },
        0,
    );

    // Unblock to allow delivery.
    assert_eq!(
        unsafe { sigprocmask(libc::SIG_SETMASK, &prior_mask, std::ptr::null_mut()) },
        0,
    );

    // Give the kernel a brief window to deliver, then assert.
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert_eq!(
        SECOND_HITS.load(Ordering::SeqCst),
        1,
        "pending SIGUSR2 must dispatch through the newly installed handler",
    );
    assert_eq!(
        FIRST_HITS.load(Ordering::SeqCst),
        0,
        "previously installed handler must not run after replacement",
    );

    // Restore original disposition.
    assert_eq!(
        unsafe { sigaction(libc::SIGUSR2, &saved, std::ptr::null_mut()) },
        0,
    );
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
fn malloc_storm_prewarm_prevents_lazy_host_allocator_resolution_during_live_signal_delivery() {
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
    frankenlibc_abi::malloc_abi::reset_host_allocator_resolution_metrics_for_test();

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
    let resolution = frankenlibc_abi::malloc_abi::host_allocator_resolution_metrics_for_test();
    assert_eq!(completed, 20_000);
    assert!(
        DEFERRED_HANDLER_COUNT.load(Ordering::Relaxed) > 0,
        "signal storm should deliver at least one handler invocation"
    );
    assert!(
        resolution.raw_host_fallback_hits == 0,
        "allocator path must not re-enter raw host fallback after prewarm: {resolution:?}"
    );
    assert!(
        resolution.direct_dlvsym_fallback_hits == 0,
        "allocator path must not re-enter direct dlvsym fallback after prewarm: {resolution:?}"
    );
    assert_eq!(
        metrics.deferred, metrics.flushed,
        "all deferred deliveries should flush once the storm quiesces: {metrics:?}"
    );
    assert_eq!(
        DEFERRED_HANDLER_COUNT.load(Ordering::Relaxed) as u64,
        metrics.immediate + metrics.flushed,
        "handler invocation accounting should match immediate+flushed deliveries: {metrics:?}"
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

#[test]
fn sigaction_query_preserves_user_handler_and_restorer_metadata() {
    let _guard = TEST_GUARD
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());

    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigaction(libc::SIGUSR1, std::ptr::null(), &mut old) };
    assert_eq!(rc, 0, "must capture original SIGUSR1 disposition");

    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = counting_handler as *const () as usize;
    let rc = unsafe { sigaction(libc::SIGUSR1, &act, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "must install SIGUSR1 handler");

    let mut queried: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigaction(libc::SIGUSR1, std::ptr::null(), &mut queried) };
    assert_eq!(rc, 0, "must query installed SIGUSR1 disposition");
    assert_eq!(
        queried.sa_sigaction, counting_handler as *const () as usize,
        "query path must rewrite the trampoline back to the user handler"
    );
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        assert_ne!(
            queried.sa_flags & SA_RESTORER_FLAG,
            0,
            "query path should preserve kernel restorer metadata"
        );
        assert!(
            queried.sa_restorer.is_some(),
            "query path should surface the restorer trampoline address"
        );
    }

    let rc = unsafe { sigaction(libc::SIGUSR1, &old, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "must restore original SIGUSR1 disposition");
}

#[test]
fn pthread_kill_is_deferred_inside_live_critical_section_until_exit() {
    let _guard = TEST_GUARD
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    DEFERRED_HANDLER_COUNT.store(0, Ordering::Relaxed);
    reset_signal_delivery_metrics_for_test();

    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigaction(libc::SIGUSR1, std::ptr::null(), &mut old) };
    assert_eq!(rc, 0, "must capture original SIGUSR1 disposition");

    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = counting_handler as *const () as usize;
    let rc = unsafe { sigaction(libc::SIGUSR1, &act, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "must install SIGUSR1 handler");

    let (pthread_tx, pthread_rx) = mpsc::channel::<usize>();
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<()>();

    let worker = thread::spawn(move || {
        let tid = unsafe { libc::pthread_self() as usize };
        pthread_tx.send(tid).expect("must publish pthread_t");
        {
            let _critical =
                enter_signal_critical_section(SignalCriticalSectionKind::MallocArenaLockAcquire);
            entered_tx
                .send(())
                .expect("must publish critical-section entry");
            release_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("test must release worker from critical section");
        }
        done_tx.send(()).expect("worker must report exit");
    });

    let worker_tid = pthread_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker must publish pthread_t promptly");
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker must enter the critical section promptly");

    let rc = unsafe { libc::pthread_kill(worker_tid as libc::pthread_t, libc::SIGUSR1) };
    assert_eq!(rc, 0, "pthread_kill must succeed while worker is critical");

    let deferred_seen = (0..200).any(|_| {
        let metrics = signal_delivery_metrics_for_test();
        if metrics.deferred != 0 {
            return true;
        }
        thread::sleep(Duration::from_millis(1));
        false
    });
    assert!(
        deferred_seen,
        "real pthread_kill delivery should enter the deferred path while the worker is critical"
    );

    let metrics = signal_delivery_metrics_for_test();
    assert_eq!(
        DEFERRED_HANDLER_COUNT.load(Ordering::Relaxed),
        0,
        "handler must remain deferred until the critical section exits"
    );
    assert_eq!(
        metrics.immediate, 0,
        "masked critical-section delivery should not dispatch immediately: {metrics:?}"
    );
    assert_eq!(
        metrics.deferred, 1,
        "one real SIGUSR1 delivery should be queued while the worker is critical: {metrics:?}"
    );

    release_tx
        .send(())
        .expect("main thread must release the critical-section worker");
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker must exit the critical section without hanging");
    worker.join().expect("worker must not panic");

    let metrics = signal_delivery_metrics_for_test();
    assert_eq!(
        DEFERRED_HANDLER_COUNT.load(Ordering::Relaxed),
        1,
        "deferred real-kernel delivery should replay exactly once on exit"
    );
    assert_eq!(
        metrics.deferred, 1,
        "deferred delivery count should remain stable after replay: {metrics:?}"
    );
    assert_eq!(
        metrics.flushed, 1,
        "deferred delivery should flush once the worker exits the critical section: {metrics:?}"
    );
    assert_eq!(
        metrics.immediate, 0,
        "the critical-section signal should never be recorded as immediate: {metrics:?}"
    );

    let rc = unsafe { sigaction(libc::SIGUSR1, &old, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "must restore original SIGUSR1 disposition");
}

#[test]
fn pthread_sigqueue_preserves_siginfo_and_ucontext_after_deferred_replay() {
    let _guard = TEST_GUARD
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    SIGINFO_HANDLER_COUNT.store(0, Ordering::Relaxed);
    LAST_SIGINFO_NONNULL.store(0, Ordering::Relaxed);
    LAST_UCONTEXT_NONNULL.store(0, Ordering::Relaxed);
    LAST_SIGINFO_CODE.store(0, Ordering::Relaxed);
    LAST_SIGINFO_SIGNO.store(0, Ordering::Relaxed);
    LAST_SIGINFO_VALUE_BITS.store(0, Ordering::Relaxed);
    reset_signal_delivery_metrics_for_test();

    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigaction(libc::SIGUSR1, std::ptr::null(), &mut old) };
    assert_eq!(rc, 0, "must capture original SIGUSR1 disposition");

    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = siginfo_counting_handler as *const () as usize;
    act.sa_flags = libc::SA_SIGINFO;
    let rc = unsafe { sigaction(libc::SIGUSR1, &act, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "must install SIGUSR1 SA_SIGINFO handler");

    let (pthread_tx, pthread_rx) = mpsc::channel::<usize>();
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<()>();

    let worker = thread::spawn(move || {
        let tid = unsafe { libc::pthread_self() as usize };
        pthread_tx.send(tid).expect("must publish pthread_t");
        {
            let _critical =
                enter_signal_critical_section(SignalCriticalSectionKind::MallocArenaLockAcquire);
            entered_tx
                .send(())
                .expect("must publish critical-section entry");
            release_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("test must release worker from critical section");
        }
        done_tx.send(()).expect("worker must report exit");
    });

    let worker_tid = pthread_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker must publish pthread_t promptly");
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker must enter the critical section promptly");

    let payload = 0x1234usize;
    let sigval = libc::sigval {
        sival_ptr: payload as *mut std::ffi::c_void,
    };
    let rc = unsafe {
        frankenlibc_abi::pthread_abi::pthread_sigqueue(
            worker_tid as libc::pthread_t,
            libc::SIGUSR1,
            sigval,
        )
    };
    assert_eq!(
        rc, 0,
        "pthread_sigqueue must succeed while the worker is critical"
    );

    let deferred_seen = (0..200).any(|_| {
        let metrics = signal_delivery_metrics_for_test();
        if metrics.deferred != 0 {
            return true;
        }
        thread::sleep(Duration::from_millis(1));
        false
    });
    assert!(
        deferred_seen,
        "queued live-kernel SIGUSR1 delivery should enter the deferred path"
    );
    assert_eq!(
        SIGINFO_HANDLER_COUNT.load(Ordering::Relaxed),
        0,
        "SA_SIGINFO handler must remain deferred until the critical section exits"
    );

    release_tx
        .send(())
        .expect("main thread must release the critical-section worker");
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker must exit the critical section without hanging");
    worker.join().expect("worker must not panic");

    let metrics = signal_delivery_metrics_for_test();
    assert_eq!(
        SIGINFO_HANDLER_COUNT.load(Ordering::Relaxed),
        1,
        "deferred queued delivery should replay exactly once on exit"
    );
    assert_eq!(
        LAST_SIGINFO_NONNULL.load(Ordering::Relaxed),
        1,
        "deferred SA_SIGINFO replay must preserve non-null siginfo metadata"
    );
    assert_eq!(
        LAST_UCONTEXT_NONNULL.load(Ordering::Relaxed),
        1,
        "deferred SA_SIGINFO replay must preserve non-null delivery context"
    );
    assert_eq!(
        LAST_SIGINFO_CODE.load(Ordering::Relaxed) as c_int,
        libc::SI_QUEUE,
        "queued delivery should preserve SI_QUEUE metadata"
    );
    assert_eq!(
        LAST_SIGINFO_SIGNO.load(Ordering::Relaxed) as c_int,
        libc::SIGUSR1,
        "queued delivery should preserve the original signal number metadata"
    );
    assert_eq!(
        LAST_SIGINFO_VALUE_BITS.load(Ordering::Relaxed),
        payload,
        "queued delivery should preserve the original sigqueue payload value"
    );
    assert_eq!(
        metrics.deferred, 1,
        "deferred delivery count should remain stable after replay: {metrics:?}"
    );
    assert_eq!(
        metrics.flushed, 1,
        "deferred queued delivery should flush once the worker exits the critical section: {metrics:?}"
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

// ---------------------------------------------------------------------------
// raise — null signal semantics (bd-gii3)
// ---------------------------------------------------------------------------

#[test]
fn raise_null_signal_succeeds() {
    // POSIX: raise(0) must not send a signal; it performs only the permission
    // and thread-existence checks (tgkill with sig=0). Host glibc returns 0.
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    unsafe { *__errno_location() = 0 };
    let rc = unsafe { frankenlibc_abi::signal_abi::raise(0) };
    let err = unsafe { *__errno_location() };
    assert_eq!(rc, 0, "raise(0) null-signal should return 0");
    assert_eq!(err, 0, "raise(0) must not set errno");
}

#[test]
fn raise_negative_signal_rejected() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    unsafe { *__errno_location() = 0 };
    let rc = unsafe { frankenlibc_abi::signal_abi::raise(-1) };
    let err = unsafe { *__errno_location() };
    assert_eq!(rc, -1, "raise(-1) must fail");
    assert_eq!(err, errno::EINVAL, "raise(-1) must set EINVAL");
}

#[test]
fn raise_above_max_signal_rejected() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    unsafe { *__errno_location() = 0 };
    let rc = unsafe { frankenlibc_abi::signal_abi::raise(65) };
    let err = unsafe { *__errno_location() };
    assert_eq!(rc, -1, "raise(65) must fail");
    assert_eq!(err, errno::EINVAL, "raise(65) must set EINVAL");
}

// ---------------------------------------------------------------------------
// raise_default_signal (NetBSD libutil graceful-shutdown helper)
// ---------------------------------------------------------------------------

static RDS_HANDLER_INVOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn rds_handler(_sig: c_int) {
    RDS_HANDLER_INVOCATIONS.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn raise_default_signal_with_ignore_default_returns_zero_and_restores_handler() {
    // SIGURG and SIGCHLD have SIG_DFL == "ignore" — perfect for
    // testing that raise_default_signal returns control after the
    // queued signal is delivered under the default action.
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    RDS_HANDLER_INVOCATIONS.store(0, Ordering::SeqCst);

    // Install our counting handler so we can verify it's restored
    // after raise_default_signal returns.
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    let mut prev: libc::sigaction = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut act.sa_mask) };
    act.sa_flags = 0;
    act.sa_sigaction = rds_handler as *const () as libc::sighandler_t;
    let install_rc = unsafe { sigaction(libc::SIGURG, &act, &mut prev) };
    assert_eq!(install_rc, 0, "install handler must succeed");

    // Call raise_default_signal: SIG_DFL of SIGURG is ignore, so
    // we expect to get back control with rc==0.
    let rc = unsafe { raise_default_signal(libc::SIGURG) };
    assert_eq!(rc, 0, "raise_default_signal must succeed for SIGURG");

    // Our handler must NOT have been invoked (delivery happened
    // under SIG_DFL).
    assert_eq!(
        RDS_HANDLER_INVOCATIONS.load(Ordering::SeqCst),
        0,
        "custom handler must not fire — SIG_DFL took over"
    );

    // Verify our handler is back in place by raising SIGURG via
    // libc::raise (using our normal sigaction path).
    let raise_rc = unsafe { libc::raise(libc::SIGURG) };
    assert_eq!(raise_rc, 0);
    // Give the kernel a moment to deliver synchronously (raise is
    // synchronous, so this is just a defensive yield).
    std::thread::sleep(Duration::from_millis(5));
    assert!(
        RDS_HANDLER_INVOCATIONS.load(Ordering::SeqCst) >= 1,
        "handler should be restored and fire on next raise"
    );

    // Restore the original sigaction.
    unsafe { sigaction(libc::SIGURG, &prev, std::ptr::null_mut()) };
}

#[test]
fn raise_default_signal_invalid_signum_returns_minus_one_einval() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    unsafe { *__errno_location() = 0 };
    let rc = unsafe { raise_default_signal(99999) };
    assert_eq!(rc, -1, "out-of-range signal must fail");
    assert_eq!(
        unsafe { *__errno_location() },
        errno::EINVAL,
        "must set EINVAL"
    );
}

#[test]
fn raise_default_signal_zero_signal_is_invalid() {
    // POSIX raise(0) is the null signal (only permission/existence
    // check); raise_default_signal has no meaningful "default
    // action" for the null signal, so it must reject it.
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    unsafe { *__errno_location() = 0 };
    let rc = unsafe { raise_default_signal(0) };
    assert_eq!(rc, -1);
    assert_eq!(unsafe { *__errno_location() }, errno::EINVAL);
}

// ---------------------------------------------------------------------------
// glibc reserved-namespace aliases:
// __sigprocmask / __sigwait / __pause / __raise / __kill / __killpg /
// __sigignore / __sighold / __sigrelse
// ---------------------------------------------------------------------------

use frankenlibc_abi::signal_abi::{
    __kill, __killpg, __raise, __sighold, __sigignore, __sigprocmask, __sigrelse,
};

#[test]
fn under_sigprocmask_swap_round_trip() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    let mut empty: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { sigemptyset(&mut empty) };
    let mut blocked: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { sigemptyset(&mut blocked) };
    unsafe { sigaddset(&mut blocked, libc::SIGUSR1) };

    let mut prev: libc::sigset_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { __sigprocmask(libc::SIG_BLOCK, &blocked, &mut prev) };
    assert_eq!(rc, 0);

    // Restore.
    let rc = unsafe { __sigprocmask(libc::SIG_SETMASK, &prev, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
}

#[test]
fn under_kill_with_signal_zero_returns_zero_for_self() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    let me = unsafe { libc::getpid() };
    let rc = unsafe { __kill(me, 0) };
    assert_eq!(rc, 0);
}

#[test]
fn under_killpg_signal_zero_returns_zero_for_self() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    let pgrp = unsafe { libc::getpgrp() };
    let rc = unsafe { __killpg(pgrp, 0) };
    assert_eq!(rc, 0);
}

#[test]
fn under_raise_invalid_signal_returns_minus_one() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    unsafe { *__errno_location() = 0 };
    let rc = unsafe { __raise(99999) };
    assert_eq!(rc, -1);
}

#[test]
fn under_sigignore_sighold_sigrelse_round_trip() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    // SIGUSR2 is a safe signal to ignore briefly. Save the current
    // disposition first (via a temporary sigaction read), then
    // exercise __sigignore/__sighold/__sigrelse and restore.
    let mut prev: libc::sigaction = unsafe { std::mem::zeroed() };
    let nullact: *const libc::sigaction = std::ptr::null();
    let _ = unsafe { sigaction(libc::SIGUSR2, nullact, &mut prev) };

    // __sighold + __sigrelse: block then unblock.
    assert_eq!(unsafe { __sighold(libc::SIGUSR2) }, 0);
    assert_eq!(unsafe { __sigrelse(libc::SIGUSR2) }, 0);

    // __sigignore: install SIG_IGN. (Verifying via getting+restoring
    // is enough to exercise the alias path.)
    assert_eq!(unsafe { __sigignore(libc::SIGUSR2) }, 0);

    // Restore the original disposition so subsequent tests aren't
    // affected.
    let _ = unsafe { sigaction(libc::SIGUSR2, &prev, std::ptr::null_mut()) };
}

#[test]
fn under_sigaltstack_query_only_succeeds() {
    let _guard = TEST_GUARD.lock().expect("test guard lock should succeed");
    use frankenlibc_abi::signal_abi::__sigaltstack;
    // Query-only call (NULL ss) — must succeed without disturbing
    // any installed altstack.
    let mut old: libc::stack_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { __sigaltstack(std::ptr::null(), &mut old) };
    assert_eq!(rc, 0);
}
