//! Integration tests for phase-0 startup ABI behavior (bd-1ff3).

use std::ffi::{CString, c_char, c_int, c_void};
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use frankenlibc_abi::errno_abi::__errno_location;
#[cfg(debug_assertions)]
use frankenlibc_abi::startup_abi::__frankenlibc_set_startup_host_delegate_for_tests;
use frankenlibc_abi::startup_abi::{
    __frankenlibc_startup_phase0, __frankenlibc_startup_snapshot, __libc_start_main,
    StartupFailureReason, StartupInvariantSnapshot, StartupInvariantStatus, StartupPolicyDecision,
    StartupPolicySnapshot, startup_policy_snapshot_for_tests,
};
use frankenlibc_abi::startup_helpers::{
    AT_NULL, AT_SECURE, MAX_STARTUP_SCAN, SecureModeState, StartupCheckpoint,
};

type MainFn = unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) -> c_int;
type HookFn = unsafe extern "C" fn();

static INIT_CALLS: AtomicUsize = AtomicUsize::new(0);
static FINI_CALLS: AtomicUsize = AtomicUsize::new(0);
static RTLD_FINI_CALLS: AtomicUsize = AtomicUsize::new(0);
static MAIN_ARGC: AtomicUsize = AtomicUsize::new(usize::MAX);
static MAIN_ENVP_NONNULL: AtomicU8 = AtomicU8::new(0);
static HOST_DELEGATE_CALLS: AtomicUsize = AtomicUsize::new(0);
static HOST_DELEGATE_LAST_ARGC: AtomicUsize = AtomicUsize::new(usize::MAX);
static LOG_SEQ: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());
const STARTUP_TEST_SEED: u64 = 0x5A17_11AB_1EC7_2026;

unsafe fn abi_errno() -> c_int {
    // SAFETY: ABI helper returns thread-local errno storage.
    let p = unsafe { __errno_location() };
    // SAFETY: pointer from __errno_location is valid for this thread.
    unsafe { *p }
}

unsafe extern "C" fn test_init() {
    INIT_CALLS.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn test_fini() {
    FINI_CALLS.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn test_rtld_fini() {
    RTLD_FINI_CALLS.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn test_host_start_main(
    _main: Option<MainFn>,
    argc: c_int,
    _ubp_av: *mut *mut c_char,
    _init: Option<HookFn>,
    _fini: Option<HookFn>,
    _rtld_fini: Option<HookFn>,
    _stack_end: *mut c_void,
) -> c_int {
    HOST_DELEGATE_CALLS.fetch_add(1, Ordering::Relaxed);
    HOST_DELEGATE_LAST_ARGC.store(if argc < 0 { 0 } else { argc as usize }, Ordering::Relaxed);
    211
}

unsafe extern "C" fn test_main(
    argc: c_int,
    _argv: *mut *mut c_char,
    envp: *mut *mut c_char,
) -> c_int {
    MAIN_ARGC.store(if argc < 0 { 0 } else { argc as usize }, Ordering::Relaxed);
    MAIN_ENVP_NONNULL.store(u8::from(!envp.is_null()), Ordering::Relaxed);
    7
}

fn reset_test_counters() {
    INIT_CALLS.store(0, Ordering::Relaxed);
    FINI_CALLS.store(0, Ordering::Relaxed);
    RTLD_FINI_CALLS.store(0, Ordering::Relaxed);
    MAIN_ARGC.store(usize::MAX, Ordering::Relaxed);
    MAIN_ENVP_NONNULL.store(0, Ordering::Relaxed);
    HOST_DELEGATE_CALLS.store(0, Ordering::Relaxed);
    HOST_DELEGATE_LAST_ARGC.store(usize::MAX, Ordering::Relaxed);
}

fn reset_host_delegate_override() {
    #[cfg(debug_assertions)]
    unsafe {
        // SAFETY: test-only hook is used under TEST_LOCK to keep env/delegate mutation serialized.
        __frankenlibc_set_startup_host_delegate_for_tests(None);
    }
}

fn install_host_delegate_override() {
    #[cfg(debug_assertions)]
    unsafe {
        // SAFETY: test-only hook is used under TEST_LOCK to keep env/delegate mutation serialized.
        __frankenlibc_set_startup_host_delegate_for_tests(Some(test_host_start_main));
    }
}

fn with_host_delegate_override<R>(f: impl FnOnce() -> R) -> R {
    install_host_delegate_override();
    let result = f();
    reset_host_delegate_override();
    result
}

fn with_startup_phase0_env<R>(enabled: bool, f: impl FnOnce() -> R) -> R {
    let key = "FRANKENLIBC_STARTUP_PHASE0";
    let previous = std::env::var_os(key);

    // SAFETY: tests serialize env mutation with TEST_LOCK, avoiding concurrent env access.
    unsafe {
        if enabled {
            std::env::set_var(key, "1");
        } else {
            std::env::remove_var(key);
        }
    }

    let result = f();

    // SAFETY: same serialization argument as above.
    unsafe {
        if let Some(value) = previous {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }

    result
}

fn startup_trace_log_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("target/conformance/bd-11nb_startup_phase0.log.jsonl")
}

fn append_startup_trace(scenario: &str, rc: c_int, errno: c_int, policy: StartupPolicySnapshot) {
    let path = startup_trace_log_path();
    if let Some(parent) = path.parent() {
        create_dir_all(parent).expect("startup trace log parent directory should exist");
    }
    let seq = LOG_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
    let outcome = if rc >= 0 { "pass" } else { "fail" };
    let line = format!(
        "{{\"timestamp\":\"2026-02-15T00:00:00Z\",\"trace_id\":\"bd-11nb::startup::{seq:03}\",\"level\":\"info\",\"event\":\"startup_decision\",\"bead_id\":\"bd-11nb\",\"mode\":\"strict\",\"api_family\":\"process\",\"symbol\":\"__libc_start_main\",\"decision\":\"{:?}\",\"decision_path\":\"{:?}\",\"outcome\":\"{}\",\"errno\":{},\"latency_ns\":{},\"artifact_refs\":[\"crates/frankenlibc-abi/tests/startup_abi_contract_test.rs\"],\"scenario\":\"{}\"}}\n",
        policy.decision, policy.last_phase, outcome, errno, policy.latency_ns, scenario,
    );
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("startup trace log should be writable");
    file.write_all(line.as_bytes())
        .expect("startup trace log append should succeed");
}

struct StartupContractCase {
    subsystem: &'static str,
    clause: &'static str,
    evidence_path: &'static str,
    rc: c_int,
    errno: c_int,
    expected_errno: c_int,
}

fn assert_startup_errno_contract(case: StartupContractCase) {
    assert_eq!(
        case.rc, -1,
        "[{}] {} expected rc=-1 ({})",
        case.subsystem, case.clause, case.evidence_path
    );
    assert_eq!(
        case.errno, case.expected_errno,
        "[{}] {} expected errno={} ({})",
        case.subsystem, case.clause, case.expected_errno, case.evidence_path
    );
}

fn seeded_cstring(label: &str, index: usize) -> CString {
    CString::new(format!("{label}-{STARTUP_TEST_SEED:016x}-{index:04x}"))
        .expect("seeded test cstring should not contain interior nul")
}

fn acquire_test_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .expect("startup ABI contract test mutex should not be poisoned")
}

#[test]
fn startup_phase0_executes_main_and_captures_invariants() {
    let _guard = acquire_test_lock();
    reset_test_counters();
    let arg0 = CString::new("prog").unwrap();
    let arg1 = CString::new("arg1").unwrap();
    let env0 = CString::new("K=V").unwrap();

    let mut argv_env = vec![
        arg0.as_ptr().cast_mut(),
        arg1.as_ptr().cast_mut(),
        ptr::null_mut(),
        env0.as_ptr().cast_mut(),
        ptr::null_mut(),
    ];
    let mut auxv = vec![AT_SECURE, 1usize, AT_NULL, 0usize];

    // SAFETY: all pointers are valid for the duration of this call; arrays are
    // explicitly null-terminated according to startup ABI expectations.
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main as MainFn),
            2,
            argv_env.as_mut_ptr(),
            Some(test_init as HookFn),
            Some(test_fini as HookFn),
            Some(test_rtld_fini as HookFn),
            auxv.as_mut_ptr().cast::<c_void>(),
        )
    };
    assert_eq!(rc, 7);
    assert_eq!(INIT_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(FINI_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(RTLD_FINI_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(MAIN_ARGC.load(Ordering::Relaxed), 2);
    assert_eq!(MAIN_ENVP_NONNULL.load(Ordering::Relaxed), 1);

    let mut snapshot = StartupInvariantSnapshot {
        argc: 0,
        argv_count: 0,
        env_count: 0,
        auxv_count: 0,
        secure_mode: 0,
    };
    // SAFETY: snapshot pointer is valid and writable.
    let snap_rc = unsafe { __frankenlibc_startup_snapshot(&mut snapshot) };
    assert_eq!(snap_rc, 0);
    assert_eq!(snapshot.argc, 2);
    assert_eq!(snapshot.argv_count, 2);
    assert_eq!(snapshot.env_count, 1);
    assert_eq!(snapshot.auxv_count, 1);
    assert_eq!(snapshot.secure_mode, 1);

    let policy = startup_policy_snapshot_for_tests();
    assert_eq!(policy.decision, StartupPolicyDecision::Allow);
    assert_eq!(policy.invariant_status, StartupInvariantStatus::Valid);
    assert_eq!(policy.failure_reason, StartupFailureReason::None);
    assert_eq!(policy.secure_mode_state, SecureModeState::Secure);
    assert_eq!(policy.last_phase, StartupCheckpoint::Complete);
    assert!(policy.dag_valid);
    assert!(policy.latency_ns > 0);
}

#[test]
fn startup_phase0_rejects_missing_main() {
    let _guard = acquire_test_lock();
    let arg0 = CString::new("prog").unwrap();
    let mut argv_env = vec![arg0.as_ptr().cast_mut(), ptr::null_mut(), ptr::null_mut()];
    let mut auxv = vec![AT_NULL, 0usize];

    // SAFETY: input buffers are valid and null-terminated.
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            None,
            1,
            argv_env.as_mut_ptr(),
            None,
            None,
            None,
            auxv.as_mut_ptr().cast::<c_void>(),
        )
    };
    assert_eq!(rc, -1);
    // SAFETY: reading thread-local errno after ABI failure.
    assert_eq!(unsafe { abi_errno() }, libc::EINVAL);

    let policy = startup_policy_snapshot_for_tests();
    assert_eq!(policy.decision, StartupPolicyDecision::Deny);
    assert_eq!(policy.invariant_status, StartupInvariantStatus::Invalid);
    assert_eq!(policy.failure_reason, StartupFailureReason::MissingMain);
    assert_eq!(policy.secure_mode_state, SecureModeState::Unknown);
    assert_eq!(policy.last_phase, StartupCheckpoint::Deny);
    assert!(policy.dag_valid);
}

#[test]
fn startup_phase0_rejects_argc_argv_mismatch() {
    let _guard = acquire_test_lock();
    let arg0 = CString::new("prog").unwrap();
    let mut argv_env = vec![arg0.as_ptr().cast_mut(), ptr::null_mut(), ptr::null_mut()];
    let mut auxv = vec![AT_NULL, 0usize];

    // SAFETY: input buffers are valid and null-terminated.
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main as MainFn),
            2,
            argv_env.as_mut_ptr(),
            None,
            None,
            None,
            auxv.as_mut_ptr().cast::<c_void>(),
        )
    };
    assert_eq!(rc, -1);
    // SAFETY: reading thread-local errno after ABI failure.
    assert_eq!(unsafe { abi_errno() }, libc::EINVAL);

    let policy = startup_policy_snapshot_for_tests();
    assert_eq!(policy.decision, StartupPolicyDecision::Deny);
    assert_eq!(policy.invariant_status, StartupInvariantStatus::Invalid);
    assert_eq!(policy.failure_reason, StartupFailureReason::ArgcOutOfBounds);
    assert_eq!(policy.last_phase, StartupCheckpoint::Deny);
    assert!(policy.dag_valid);
}

#[test]
fn startup_snapshot_rejects_null_output() {
    let _guard = acquire_test_lock();
    // SAFETY: explicit null pointer validates EFAULT error path.
    let rc = unsafe { __frankenlibc_startup_snapshot(ptr::null_mut()) };
    // SAFETY: reading thread-local errno after ABI failure.
    let errno = unsafe { abi_errno() };
    assert_eq!(rc, -1);
    // SAFETY: reading thread-local errno after ABI failure.
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn startup_phase0_rejects_unterminated_argv_scan_window() {
    let _guard = acquire_test_lock();
    let arg0 = seeded_cstring("arg", 0);
    let mut argv_env = vec![arg0.as_ptr().cast_mut(); MAX_STARTUP_SCAN];
    let mut auxv = vec![AT_NULL, 0usize];

    // SAFETY: argv slots are valid pointers; this case intentionally omits a null terminator.
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main as MainFn),
            1,
            argv_env.as_mut_ptr(),
            None,
            None,
            None,
            auxv.as_mut_ptr().cast::<c_void>(),
        )
    };
    // SAFETY: reading thread-local errno after ABI failure.
    let errno = unsafe { abi_errno() };
    assert_startup_errno_contract(StartupContractCase {
        subsystem: "startup",
        clause: "argv-vector-must-be-null-terminated",
        evidence_path: "crates/frankenlibc-abi/tests/startup_abi_contract_test.rs",
        rc,
        errno,
        expected_errno: libc::E2BIG,
    });

    let policy = startup_policy_snapshot_for_tests();
    assert_eq!(policy.decision, StartupPolicyDecision::Deny);
    assert_eq!(policy.invariant_status, StartupInvariantStatus::Invalid);
    assert_eq!(
        policy.failure_reason,
        StartupFailureReason::UnterminatedArgv
    );
    assert_eq!(policy.last_phase, StartupCheckpoint::Deny);
    assert!(policy.dag_valid);
}

#[test]
fn startup_phase0_rejects_unterminated_envp_scan_window() {
    let _guard = acquire_test_lock();
    let arg0 = seeded_cstring("arg", 1);
    let env0 = seeded_cstring("env", 1);
    let mut argv_env = Vec::with_capacity(2 + MAX_STARTUP_SCAN);
    argv_env.push(arg0.as_ptr().cast_mut());
    argv_env.push(ptr::null_mut());
    for _ in 0..MAX_STARTUP_SCAN {
        argv_env.push(env0.as_ptr().cast_mut());
    }
    let mut auxv = vec![AT_NULL, 0usize];

    // SAFETY: argv is null-terminated; envp region intentionally omits a null terminator.
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main as MainFn),
            1,
            argv_env.as_mut_ptr(),
            None,
            None,
            None,
            auxv.as_mut_ptr().cast::<c_void>(),
        )
    };
    // SAFETY: reading thread-local errno after ABI failure.
    let errno = unsafe { abi_errno() };
    assert_startup_errno_contract(StartupContractCase {
        subsystem: "startup",
        clause: "envp-vector-must-be-null-terminated",
        evidence_path: "crates/frankenlibc-abi/tests/startup_abi_contract_test.rs",
        rc,
        errno,
        expected_errno: libc::E2BIG,
    });

    let policy = startup_policy_snapshot_for_tests();
    assert_eq!(policy.decision, StartupPolicyDecision::Deny);
    assert_eq!(policy.invariant_status, StartupInvariantStatus::Invalid);
    assert_eq!(
        policy.failure_reason,
        StartupFailureReason::UnterminatedEnvp
    );
    assert_eq!(policy.last_phase, StartupCheckpoint::Deny);
    assert!(policy.dag_valid);
}

#[test]
fn startup_phase0_rejects_unterminated_auxv_scan_window() {
    let _guard = acquire_test_lock();
    let arg0 = seeded_cstring("arg", 9);
    let env0 = seeded_cstring("env", 9);
    let mut argv_env = vec![
        arg0.as_ptr().cast_mut(),
        ptr::null_mut(),
        env0.as_ptr().cast_mut(),
        ptr::null_mut(),
    ];
    let mut auxv = Vec::with_capacity(MAX_STARTUP_SCAN.saturating_mul(2));
    for _ in 0..MAX_STARTUP_SCAN {
        auxv.push(1usize);
        auxv.push(0usize);
    }

    // SAFETY: argv/envp are null-terminated; auxv intentionally omits AT_NULL terminator.
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main as MainFn),
            1,
            argv_env.as_mut_ptr(),
            None,
            None,
            None,
            auxv.as_mut_ptr().cast::<c_void>(),
        )
    };
    // SAFETY: reading thread-local errno after ABI failure.
    let errno = unsafe { abi_errno() };
    assert_startup_errno_contract(StartupContractCase {
        subsystem: "startup",
        clause: "auxv-vector-must-be-null-terminated",
        evidence_path: "crates/frankenlibc-abi/tests/startup_abi_contract_test.rs",
        rc,
        errno,
        expected_errno: libc::E2BIG,
    });

    let policy = startup_policy_snapshot_for_tests();
    assert_eq!(policy.decision, StartupPolicyDecision::Deny);
    assert_eq!(policy.invariant_status, StartupInvariantStatus::Invalid);
    assert_eq!(
        policy.failure_reason,
        StartupFailureReason::UnterminatedAuxv
    );
    assert_eq!(policy.secure_mode_state, SecureModeState::NonSecure);
    assert_eq!(policy.last_phase, StartupCheckpoint::Deny);
    assert!(policy.dag_valid);
}

#[test]
fn startup_phase0_negative_argc_normalizes_to_zero() {
    let _guard = acquire_test_lock();
    reset_test_counters();
    let env0 = seeded_cstring("env", 2);
    let mut argv_env = vec![ptr::null_mut(), env0.as_ptr().cast_mut(), ptr::null_mut()];
    let mut auxv = vec![AT_NULL, 0usize];

    // SAFETY: vectors are valid and null-terminated for the phase-0 contract.
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main as MainFn),
            -7,
            argv_env.as_mut_ptr(),
            Some(test_init as HookFn),
            None,
            None,
            auxv.as_mut_ptr().cast::<c_void>(),
        )
    };
    assert_eq!(rc, 7);
    assert_eq!(INIT_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(MAIN_ARGC.load(Ordering::Relaxed), 0);
    assert_eq!(MAIN_ENVP_NONNULL.load(Ordering::Relaxed), 1);

    let mut snapshot = StartupInvariantSnapshot {
        argc: usize::MAX,
        argv_count: usize::MAX,
        env_count: usize::MAX,
        auxv_count: usize::MAX,
        secure_mode: -1,
    };
    // SAFETY: snapshot pointer is valid and writable.
    let snap_rc = unsafe { __frankenlibc_startup_snapshot(&mut snapshot) };
    assert_eq!(snap_rc, 0);
    assert_eq!(snapshot.argc, 0);
    assert_eq!(snapshot.argv_count, 0);
    assert_eq!(snapshot.env_count, 1);
    assert_eq!(snapshot.auxv_count, 0);
    assert_eq!(snapshot.secure_mode, 0);

    let policy = startup_policy_snapshot_for_tests();
    assert_eq!(policy.decision, StartupPolicyDecision::Allow);
    assert_eq!(policy.invariant_status, StartupInvariantStatus::Valid);
    assert_eq!(policy.failure_reason, StartupFailureReason::None);
    assert_eq!(policy.secure_mode_state, SecureModeState::NonSecure);
    assert_eq!(policy.last_phase, StartupCheckpoint::Complete);
    assert!(policy.dag_valid);
}

#[test]
fn libc_start_main_phase0_disabled_delegates_to_host() {
    let _guard = acquire_test_lock();
    reset_test_counters();
    let arg0 = seeded_cstring("arg", 20);
    let env0 = seeded_cstring("env", 20);
    let mut argv_env = vec![
        arg0.as_ptr().cast_mut(),
        ptr::null_mut(),
        env0.as_ptr().cast_mut(),
        ptr::null_mut(),
    ];
    let mut auxv = vec![AT_NULL, 0usize];

    let rc = with_host_delegate_override(|| {
        with_startup_phase0_env(false, || {
            // SAFETY: host delegation is replaced by deterministic test hook.
            unsafe {
                __libc_start_main(
                    Some(test_main as MainFn),
                    1,
                    argv_env.as_mut_ptr(),
                    None,
                    None,
                    None,
                    auxv.as_mut_ptr().cast::<c_void>(),
                )
            }
        })
    });

    assert_eq!(rc, 211);
    assert_eq!(HOST_DELEGATE_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(HOST_DELEGATE_LAST_ARGC.load(Ordering::Relaxed), 1);
    let policy = startup_policy_snapshot_for_tests();
    assert_eq!(policy.decision, StartupPolicyDecision::FallbackHost);
    assert_eq!(policy.failure_reason, StartupFailureReason::None);
    assert_eq!(policy.last_phase, StartupCheckpoint::FallbackHost);
    append_startup_trace(
        "phase0-disabled-host-delegate",
        rc,
        unsafe { abi_errno() },
        policy,
    );
}

#[test]
fn libc_start_main_phase0_unsafe_path_falls_back_to_host() {
    let _guard = acquire_test_lock();
    reset_test_counters();
    let arg0 = seeded_cstring("arg", 21);
    let env0 = seeded_cstring("env", 21);
    let mut argv_env = Vec::with_capacity(2 + MAX_STARTUP_SCAN);
    argv_env.push(arg0.as_ptr().cast_mut());
    argv_env.push(ptr::null_mut());
    for _ in 0..MAX_STARTUP_SCAN {
        argv_env.push(env0.as_ptr().cast_mut());
    }
    let mut auxv = vec![AT_NULL, 0usize];

    let rc = with_host_delegate_override(|| {
        with_startup_phase0_env(true, || {
            // SAFETY: pointers remain valid for call duration; envp is intentionally
            // unterminated in phase-0 scan window to trigger deterministic fallback.
            unsafe {
                __libc_start_main(
                    Some(test_main as MainFn),
                    1,
                    argv_env.as_mut_ptr(),
                    None,
                    None,
                    None,
                    auxv.as_mut_ptr().cast::<c_void>(),
                )
            }
        })
    });

    assert_eq!(rc, 211);
    assert_eq!(HOST_DELEGATE_CALLS.load(Ordering::Relaxed), 1);
    let policy = startup_policy_snapshot_for_tests();
    assert_eq!(policy.decision, StartupPolicyDecision::FallbackHost);
    assert_eq!(
        policy.failure_reason,
        StartupFailureReason::UnterminatedEnvp
    );
    assert_eq!(policy.last_phase, StartupCheckpoint::FallbackHost);
    append_startup_trace(
        "phase0-unsafe-envp-fallback-host",
        rc,
        unsafe { abi_errno() },
        policy,
    );
}

#[test]
fn libc_start_main_phase0_missing_main_does_not_fallback() {
    let _guard = acquire_test_lock();
    reset_test_counters();
    let arg0 = seeded_cstring("arg", 22);
    let mut argv_env = vec![arg0.as_ptr().cast_mut(), ptr::null_mut(), ptr::null_mut()];
    let mut auxv = vec![AT_NULL, 0usize];

    let rc = with_host_delegate_override(|| {
        with_startup_phase0_env(true, || {
            // SAFETY: vectors are valid/null-terminated; missing main validates deny path.
            unsafe {
                __libc_start_main(
                    None,
                    1,
                    argv_env.as_mut_ptr(),
                    None,
                    None,
                    None,
                    auxv.as_mut_ptr().cast::<c_void>(),
                )
            }
        })
    });

    // SAFETY: reading thread-local errno after ABI failure.
    let errno = unsafe { abi_errno() };
    assert_eq!(rc, -1);
    assert_eq!(errno, libc::EINVAL);
    assert_eq!(HOST_DELEGATE_CALLS.load(Ordering::Relaxed), 0);

    let policy = startup_policy_snapshot_for_tests();
    assert_eq!(policy.decision, StartupPolicyDecision::Deny);
    assert_eq!(policy.failure_reason, StartupFailureReason::MissingMain);
    assert_eq!(policy.last_phase, StartupCheckpoint::Deny);
    append_startup_trace("phase0-missing-main-no-fallback", rc, errno, policy);
}
