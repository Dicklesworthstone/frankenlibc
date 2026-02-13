//! Integration tests for phase-0 startup ABI behavior (bd-1ff3).

use std::ffi::{CString, c_char, c_int, c_void};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::startup_abi::{
    __frankenlibc_startup_phase0, __frankenlibc_startup_snapshot, StartupInvariantSnapshot,
};
use frankenlibc_abi::startup_helpers::{AT_NULL, AT_SECURE, MAX_STARTUP_SCAN};

type MainFn = unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) -> c_int;
type HookFn = unsafe extern "C" fn();

static INIT_CALLS: AtomicUsize = AtomicUsize::new(0);
static FINI_CALLS: AtomicUsize = AtomicUsize::new(0);
static RTLD_FINI_CALLS: AtomicUsize = AtomicUsize::new(0);
static MAIN_ARGC: AtomicUsize = AtomicUsize::new(usize::MAX);
static MAIN_ENVP_NONNULL: AtomicU8 = AtomicU8::new(0);
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
}

#[test]
fn startup_snapshot_rejects_null_output() {
    let _guard = acquire_test_lock();
    // SAFETY: explicit null pointer validates EFAULT error path.
    let rc = unsafe { __frankenlibc_startup_snapshot(ptr::null_mut()) };
    assert_eq!(rc, -1);
    // SAFETY: reading thread-local errno after ABI failure.
    assert_eq!(unsafe { abi_errno() }, libc::EFAULT);
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
}
