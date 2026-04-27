//! Phase-0 CRT bootstrap ABI plumbing.
//!
//! This module exposes a constrained startup path for controlled fixtures.
//! `__libc_start_main` delegates to host libc by default to avoid hijacking
//! normal process bootstrap in LD_PRELOAD mode.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::Instant;

use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use crate::startup_helpers::{
    AT_NULL, MAX_STARTUP_SCAN, SecureModeState, StartupCheckpoint, StartupInvariants,
    build_invariants, classify_secure_mode, normalize_argc, startup_path_respects_dag,
};
use crate::util::scan_c_string;

type MainFn = unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) -> c_int;
type HookFn = unsafe extern "C" fn();
type HostStartMainFn = unsafe extern "C" fn(
    Option<MainFn>,
    c_int,
    *mut *mut c_char,
    Option<HookFn>,
    Option<HookFn>,
    Option<HookFn>,
    *mut c_void,
) -> c_int;

const PROGRAM_NAME_SCAN_LIMIT: usize = MAX_STARTUP_SCAN * 32;

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

// ===========================================================================
// program_invocation_name / __progname — GNU program name globals
// ===========================================================================
//
// These are global writable pointers that GNU C programs reference as
// `extern char *program_invocation_name;`. We export them via AtomicPtr
// and provide #[no_mangle] accessor stubs for the linker.

use std::sync::atomic::AtomicPtr;

/// Internal storage for program_invocation_name (full argv[0]).
#[allow(non_upper_case_globals)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static program_invocation_name: AtomicPtr<c_char> = AtomicPtr::new(std::ptr::null_mut());

/// Internal storage for program_invocation_short_name (basename of argv[0]).
#[allow(non_upper_case_globals)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static program_invocation_short_name: AtomicPtr<c_char> = AtomicPtr::new(std::ptr::null_mut());

/// Internal storage for __progname (alias for program_invocation_short_name).
#[allow(non_upper_case_globals)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static __progname: AtomicPtr<c_char> = AtomicPtr::new(std::ptr::null_mut());

#[inline]
fn program_name_scan_bound(ptr: *const c_char) -> usize {
    known_remaining(ptr as usize)
        .map(|remaining| remaining.min(PROGRAM_NAME_SCAN_LIMIT))
        .unwrap_or(PROGRAM_NAME_SCAN_LIMIT)
}

unsafe fn basename_within_c_string(ptr: *const c_char) -> Option<*mut c_char> {
    let (len, terminated) = unsafe { scan_c_string(ptr, Some(program_name_scan_bound(ptr))) };
    if !terminated {
        return None;
    }

    // SAFETY: `scan_c_string` observed a terminator at `len`, so the preceding
    // byte range is readable under the same bound.
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    let offset = bytes
        .iter()
        .rposition(|&byte| byte == b'/')
        .map_or(0, |idx| idx.saturating_add(1));
    Some(unsafe { (ptr as *mut c_char).add(offset) })
}

/// Set program name globals from argv[0] during startup.
pub(crate) fn init_program_name(argv: *mut *mut c_char) {
    if argv.is_null() {
        return;
    }
    // SAFETY: argv[0] is validated by startup_phase0_impl before this is called.
    let argv0 = unsafe { *argv };
    if argv0.is_null() {
        return;
    }

    let Some(base) = (unsafe { basename_within_c_string(argv0) }) else {
        return;
    };

    program_invocation_name.store(argv0, Ordering::Release);
    program_invocation_short_name.store(base, Ordering::Release);
    __progname.store(base, Ordering::Release);
    // SAFETY: startup publishes caller-owned argv[0] as glibc-compatible
    // process metadata for the remainder of process lifetime.
    unsafe {
        crate::glibc_internal_abi::__progname_full = argv0;
    }
}

pub(crate) fn init_environment_globals(envp: *mut *mut c_char) {
    let published = if envp.is_null() {
        // SAFETY: host libc owns the process environment vector.
        unsafe { environ }
    } else {
        envp
    };

    // SAFETY: glibc-compatible aliases all point at the active environment.
    unsafe {
        crate::glibc_internal_abi::__environ = published;
        crate::glibc_internal_abi::_environ = published;
        crate::glibc_internal_abi::environ = published;
    }

    // Transfer environ ownership to FrankenLibC so setenv/unsetenv can safely
    // realloc without conflicting with glibc's crt0-allocated environ (bd-zh1y.6.1).
    crate::stdlib_abi::take_environ_ownership();
}

#[inline]
fn init_process_globals(argv: *mut *mut c_char, envp: *mut *mut c_char) {
    init_program_name(argv);
    init_environment_globals(envp);
}

#[inline]
unsafe fn resolve_startup_envp(
    argc: c_int,
    argv: *mut *mut c_char,
    envp: *mut *mut c_char,
) -> *mut *mut c_char {
    if !envp.is_null() {
        return envp;
    }

    if !argv.is_null() {
        // SAFETY: startup callers provide the original argv vector; envp lives
        // immediately after argv[argc] in the initial process stack layout.
        return unsafe { argv.add(normalize_argc(argc).saturating_add(1)) };
    }

    // SAFETY: host libc owns the process environment vector.
    unsafe { environ }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupPolicyDecision {
    Unknown = 0,
    Allow = 1,
    Deny = 2,
    FallbackHost = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupInvariantStatus {
    Unknown = 0,
    Valid = 1,
    Invalid = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupFailureReason {
    None = 0,
    MembraneDenied = 1,
    MissingMain = 2,
    NullArgv = 3,
    UnterminatedArgv = 4,
    ArgcOutOfBounds = 5,
    UnterminatedEnvp = 6,
    UnterminatedAuxv = 7,
    HostDelegateUnavailable = 8,
}

static LAST_ARGC: AtomicUsize = AtomicUsize::new(0);
static LAST_ARGV_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_ENV_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_AUXV_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_SECURE_MODE: AtomicU8 = AtomicU8::new(0);
static LAST_POLICY_DECISION: AtomicU8 = AtomicU8::new(StartupPolicyDecision::Unknown as u8);
static LAST_INVARIANT_STATUS: AtomicU8 = AtomicU8::new(StartupInvariantStatus::Unknown as u8);
static LAST_FAILURE_REASON: AtomicU8 = AtomicU8::new(StartupFailureReason::None as u8);
static LAST_SECURE_MODE_STATE: AtomicU8 = AtomicU8::new(SecureModeState::Unknown as u8);
static LAST_DAG_VALID: AtomicU8 = AtomicU8::new(0);
static LAST_PHASE: AtomicU8 = AtomicU8::new(StartupCheckpoint::Entry as u8);
static LAST_POLICY_LATENCY_NS: AtomicUsize = AtomicUsize::new(0);
#[cfg(debug_assertions)]
static HOST_START_MAIN_OVERRIDE: AtomicUsize = AtomicUsize::new(0);
static HOST_DELEGATED_MAIN: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
pub struct StartupInvariantSnapshot {
    pub argc: usize,
    pub argv_count: usize,
    pub env_count: usize,
    pub auxv_count: usize,
    pub secure_mode: c_int,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupPolicySnapshot {
    pub decision: StartupPolicyDecision,
    pub invariant_status: StartupInvariantStatus,
    pub failure_reason: StartupFailureReason,
    pub secure_mode_state: SecureModeState,
    pub dag_valid: bool,
    pub last_phase: StartupCheckpoint,
    pub latency_ns: usize,
}

fn store_invariants(inv: StartupInvariants) {
    LAST_ARGC.store(inv.argc, Ordering::Relaxed);
    LAST_ARGV_COUNT.store(inv.argv_count, Ordering::Relaxed);
    LAST_ENV_COUNT.store(inv.env_count, Ordering::Relaxed);
    LAST_AUXV_COUNT.store(inv.auxv_count, Ordering::Relaxed);
    LAST_SECURE_MODE.store(u8::from(inv.secure_mode), Ordering::Relaxed);
}

#[inline]
fn decode_policy_decision(raw: u8) -> StartupPolicyDecision {
    match raw {
        x if x == StartupPolicyDecision::Allow as u8 => StartupPolicyDecision::Allow,
        x if x == StartupPolicyDecision::Deny as u8 => StartupPolicyDecision::Deny,
        x if x == StartupPolicyDecision::FallbackHost as u8 => StartupPolicyDecision::FallbackHost,
        _ => StartupPolicyDecision::Unknown,
    }
}

#[inline]
fn decode_invariant_status(raw: u8) -> StartupInvariantStatus {
    match raw {
        x if x == StartupInvariantStatus::Valid as u8 => StartupInvariantStatus::Valid,
        x if x == StartupInvariantStatus::Invalid as u8 => StartupInvariantStatus::Invalid,
        _ => StartupInvariantStatus::Unknown,
    }
}

#[inline]
fn decode_failure_reason(raw: u8) -> StartupFailureReason {
    match raw {
        x if x == StartupFailureReason::MembraneDenied as u8 => {
            StartupFailureReason::MembraneDenied
        }
        x if x == StartupFailureReason::MissingMain as u8 => StartupFailureReason::MissingMain,
        x if x == StartupFailureReason::NullArgv as u8 => StartupFailureReason::NullArgv,
        x if x == StartupFailureReason::UnterminatedArgv as u8 => {
            StartupFailureReason::UnterminatedArgv
        }
        x if x == StartupFailureReason::ArgcOutOfBounds as u8 => {
            StartupFailureReason::ArgcOutOfBounds
        }
        x if x == StartupFailureReason::UnterminatedEnvp as u8 => {
            StartupFailureReason::UnterminatedEnvp
        }
        x if x == StartupFailureReason::UnterminatedAuxv as u8 => {
            StartupFailureReason::UnterminatedAuxv
        }
        x if x == StartupFailureReason::HostDelegateUnavailable as u8 => {
            StartupFailureReason::HostDelegateUnavailable
        }
        _ => StartupFailureReason::None,
    }
}

#[inline]
fn decode_secure_mode_state(raw: u8) -> SecureModeState {
    match raw {
        x if x == SecureModeState::NonSecure as u8 => SecureModeState::NonSecure,
        x if x == SecureModeState::Secure as u8 => SecureModeState::Secure,
        _ => SecureModeState::Unknown,
    }
}

#[inline]
fn decode_checkpoint(raw: u8) -> StartupCheckpoint {
    match raw {
        x if x == StartupCheckpoint::MembraneGate as u8 => StartupCheckpoint::MembraneGate,
        x if x == StartupCheckpoint::ValidateMainPointer as u8 => {
            StartupCheckpoint::ValidateMainPointer
        }
        x if x == StartupCheckpoint::ValidateArgvPointer as u8 => {
            StartupCheckpoint::ValidateArgvPointer
        }
        x if x == StartupCheckpoint::ScanArgvVector as u8 => StartupCheckpoint::ScanArgvVector,
        x if x == StartupCheckpoint::ValidateArgcBound as u8 => {
            StartupCheckpoint::ValidateArgcBound
        }
        x if x == StartupCheckpoint::ScanEnvpVector as u8 => StartupCheckpoint::ScanEnvpVector,
        x if x == StartupCheckpoint::ScanAuxvVector as u8 => StartupCheckpoint::ScanAuxvVector,
        x if x == StartupCheckpoint::ClassifySecureMode as u8 => {
            StartupCheckpoint::ClassifySecureMode
        }
        x if x == StartupCheckpoint::CaptureInvariants as u8 => {
            StartupCheckpoint::CaptureInvariants
        }
        x if x == StartupCheckpoint::CallInitHook as u8 => StartupCheckpoint::CallInitHook,
        x if x == StartupCheckpoint::CallMain as u8 => StartupCheckpoint::CallMain,
        x if x == StartupCheckpoint::CallFiniHook as u8 => StartupCheckpoint::CallFiniHook,
        x if x == StartupCheckpoint::CallRtldFiniHook as u8 => StartupCheckpoint::CallRtldFiniHook,
        x if x == StartupCheckpoint::Complete as u8 => StartupCheckpoint::Complete,
        x if x == StartupCheckpoint::Deny as u8 => StartupCheckpoint::Deny,
        x if x == StartupCheckpoint::FallbackHost as u8 => StartupCheckpoint::FallbackHost,
        _ => StartupCheckpoint::Entry,
    }
}

fn store_policy_snapshot(
    decision: StartupPolicyDecision,
    invariant_status: StartupInvariantStatus,
    failure_reason: StartupFailureReason,
    secure_mode_state: SecureModeState,
    dag_valid: bool,
    last_phase: StartupCheckpoint,
    latency_ns: usize,
) {
    LAST_POLICY_DECISION.store(decision as u8, Ordering::Relaxed);
    LAST_INVARIANT_STATUS.store(invariant_status as u8, Ordering::Relaxed);
    LAST_FAILURE_REASON.store(failure_reason as u8, Ordering::Relaxed);
    LAST_SECURE_MODE_STATE.store(secure_mode_state as u8, Ordering::Relaxed);
    LAST_DAG_VALID.store(u8::from(dag_valid), Ordering::Relaxed);
    LAST_PHASE.store(last_phase as u8, Ordering::Relaxed);
    LAST_POLICY_LATENCY_NS.store(latency_ns, Ordering::Relaxed);
}

fn saturating_nanos(started: Instant) -> usize {
    let nanos = started.elapsed().as_nanos();
    nanos.min(usize::MAX as u128) as usize
}

#[inline]
const fn startup_failure_allows_host_fallback(reason: StartupFailureReason) -> bool {
    matches!(
        reason,
        StartupFailureReason::MembraneDenied
            | StartupFailureReason::UnterminatedArgv
            | StartupFailureReason::UnterminatedEnvp
            | StartupFailureReason::UnterminatedAuxv
    )
}

fn record_phase0_outcome(
    path: &[StartupCheckpoint],
    decision: StartupPolicyDecision,
    invariant_status: StartupInvariantStatus,
    failure_reason: StartupFailureReason,
    secure_mode_state: SecureModeState,
    started: Instant,
) {
    let dag_valid = startup_path_respects_dag(path);
    let last_phase = path.last().copied().unwrap_or(StartupCheckpoint::Entry);
    store_policy_snapshot(
        decision,
        invariant_status,
        failure_reason,
        secure_mode_state,
        dag_valid,
        last_phase,
        saturating_nanos(started),
    );
}

#[must_use]
pub fn startup_policy_snapshot_for_tests() -> StartupPolicySnapshot {
    StartupPolicySnapshot {
        decision: decode_policy_decision(LAST_POLICY_DECISION.load(Ordering::Relaxed)),
        invariant_status: decode_invariant_status(LAST_INVARIANT_STATUS.load(Ordering::Relaxed)),
        failure_reason: decode_failure_reason(LAST_FAILURE_REASON.load(Ordering::Relaxed)),
        secure_mode_state: decode_secure_mode_state(LAST_SECURE_MODE_STATE.load(Ordering::Relaxed)),
        dag_valid: LAST_DAG_VALID.load(Ordering::Relaxed) != 0,
        last_phase: decode_checkpoint(LAST_PHASE.load(Ordering::Relaxed)),
        latency_ns: LAST_POLICY_LATENCY_NS.load(Ordering::Relaxed),
    }
}

fn startup_phase0_env_enabled() -> bool {
    const KEY_EQ: &[u8] = b"FRANKENLIBC_STARTUP_PHASE0=";
    const MAX_SCAN: usize = 4096;

    // Read process environment directly from `environ` to avoid calling any
    // interposed ABI symbol (notably getenv/strlen/memcpy) during startup.
    let mut envp = unsafe { environ };
    if envp.is_null() {
        return false;
    }

    for _ in 0..MAX_SCAN {
        // SAFETY: `envp` is a null-terminated vector of C string pointers.
        let entry = unsafe { *envp };
        if entry.is_null() {
            return false;
        }

        let mut matched = true;
        for (idx, want) in KEY_EQ.iter().enumerate() {
            // SAFETY: `entry` points to a NUL-terminated string; reading prefix
            // bytes is valid until mismatch or NUL.
            let got = unsafe { *entry.add(idx) as u8 };
            if got != *want {
                matched = false;
                break;
            }
        }

        if matched {
            // Accept only exact value `1`.
            // SAFETY: KEY_EQ matched exactly; value bytes are in-bounds.
            let value = unsafe { *entry.add(KEY_EQ.len()) as u8 };
            // SAFETY: same as above.
            let terminator = unsafe { *entry.add(KEY_EQ.len() + 1) as u8 };
            return value == b'1' && terminator == 0;
        }

        // SAFETY: advance to next env pointer slot.
        envp = unsafe { envp.add(1) };
    }

    false
}

unsafe extern "C" fn host_delegate_main_wrapper(
    argc: c_int,
    argv: *mut *mut c_char,
    envp: *mut *mut c_char,
) -> c_int {
    let resolved_envp = unsafe { resolve_startup_envp(argc, argv, envp) };
    init_process_globals(argv, resolved_envp);
    crate::host_resolve::bootstrap_host_symbols();
    unsafe { crate::io_internal_abi::bootstrap_host_libio_exports() };
    crate::stdio_abi::init_host_stdio_streams();
    crate::unistd_abi::init_stack_canary();
    crate::pthread_abi::prewarm_host_thread_symbols();
    crate::malloc_abi::prewarm_host_allocator_symbols();
    crate::runtime_policy::signal_runtime_ready();

    let main_ptr = HOST_DELEGATED_MAIN.load(Ordering::Acquire);
    if main_ptr == 0 {
        return 0;
    }

    // SAFETY: `HOST_DELEGATED_MAIN` is set from a valid `MainFn` immediately
    // before delegating into host `__libc_start_main`.
    let main_fn: MainFn =
        unsafe { std::mem::transmute::<*const c_void, MainFn>(main_ptr as *const c_void) };
    // SAFETY: host `__libc_start_main` invokes the wrapper with the user
    // process entrypoint ABI and argument vectors.
    unsafe { main_fn(argc, argv, resolved_envp) }
}

unsafe fn delegate_to_host_libc_start_main(
    main: Option<MainFn>,
    argc: c_int,
    ubp_av: *mut *mut c_char,
    init: Option<HookFn>,
    fini: Option<HookFn>,
    rtld_fini: Option<HookFn>,
    stack_end: *mut c_void,
) -> Option<c_int> {
    let resolved_envp = unsafe { resolve_startup_envp(argc, ubp_av, environ) };
    init_process_globals(ubp_av, resolved_envp);
    crate::host_resolve::bootstrap_host_symbols();
    crate::stdio_abi::init_host_stdio_streams();
    unsafe { crate::io_internal_abi::bootstrap_host_libio_exports() };
    let delegated_main = main.map_or(0usize, |f| f as usize);
    HOST_DELEGATED_MAIN.store(delegated_main, Ordering::Release);
    let wrapped_main = if delegated_main == 0 {
        None
    } else {
        Some(host_delegate_main_wrapper as MainFn)
    };

    #[cfg(debug_assertions)]
    {
        let override_ptr = HOST_START_MAIN_OVERRIDE.load(Ordering::Relaxed);
        if override_ptr != 0 {
            // SAFETY: debug-test override stores a valid HostStartMainFn pointer.
            let host_fn: HostStartMainFn = unsafe {
                std::mem::transmute::<*const c_void, HostStartMainFn>(override_ptr as *const c_void)
            };
            // SAFETY: forwards startup ABI arguments to deterministic test delegate.
            return Some(unsafe {
                host_fn(wrapped_main, argc, ubp_av, init, fini, rtld_fini, stack_end)
            });
        }
    }

    // Use raw ELF lookup here. Calling host `dlvsym` before glibc has finished
    // TLS/dlerror initialization can crash during loader startup.
    let ptr = crate::host_resolve::resolve_host_symbol_raw("__libc_start_main")
        .map(|addr| addr as *mut c_void)
        .unwrap_or(std::ptr::null_mut());
    if ptr.is_null() {
        return None;
    }

    // SAFETY: symbol is expected to match HostStartMainFn ABI and signature.
    let host_fn: HostStartMainFn =
        unsafe { std::mem::transmute::<*mut c_void, HostStartMainFn>(ptr) };
    // SAFETY: forwards original startup ABI arguments to host libc.
    Some(unsafe { host_fn(wrapped_main, argc, ubp_av, init, fini, rtld_fini, stack_end) })
}

/// Test-only hook for overriding host `__libc_start_main` delegation.
#[cfg(debug_assertions)]
pub unsafe extern "C" fn __frankenlibc_set_startup_host_delegate_for_tests(
    delegate: Option<HostStartMainFn>,
) {
    let raw = delegate.map_or(0usize, |f| f as usize);
    HOST_START_MAIN_OVERRIDE.store(raw, Ordering::Relaxed);
}

unsafe fn count_c_string_vector(base: *mut *mut c_char, max_entries: usize) -> Option<usize> {
    if base.is_null() {
        return None;
    }

    for idx in 0..max_entries {
        // SAFETY: caller guarantees `base` points to readable pointer slots.
        let p = unsafe { *base.add(idx) };
        if p.is_null() {
            return Some(idx);
        }
    }

    None
}

unsafe fn read_auxv_pairs(stack_end: *mut c_void, max_pairs: usize) -> Vec<(usize, usize)> {
    if stack_end.is_null() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let auxv_ptr = stack_end.cast::<usize>();

    for idx in 0..max_pairs {
        let off = idx.saturating_mul(2);
        // SAFETY: caller provides a readable auxv-like key/value array in phase-0 fixtures.
        let key = unsafe { *auxv_ptr.add(off) };
        // SAFETY: same as above; key/value pairs are adjacent entries.
        let value = unsafe { *auxv_ptr.add(off + 1) };
        out.push((key, value));
        if key == AT_NULL {
            break;
        }
    }

    out
}

unsafe fn startup_phase0_impl(
    main: Option<MainFn>,
    argc: c_int,
    ubp_av: *mut *mut c_char,
    init: Option<HookFn>,
    fini: Option<HookFn>,
    rtld_fini: Option<HookFn>,
    stack_end: *mut c_void,
) -> c_int {
    let started = Instant::now();
    let mut path = Vec::with_capacity(16);
    path.push(StartupCheckpoint::Entry);
    let normalized_argc = normalize_argc(argc);
    path.push(StartupCheckpoint::MembraneGate);
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Process,
        ubp_av as usize,
        normalized_argc,
        true,
        ubp_av.is_null() || main.is_none(),
        0,
    );

    let membrane_denied = matches!(decision.action, MembraneAction::Deny);
    if membrane_denied {
        path.push(StartupCheckpoint::Deny);
        // SAFETY: writes TLS errno.
        unsafe { set_abi_errno(libc::EACCES) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 20, true);
        record_phase0_outcome(
            &path,
            StartupPolicyDecision::Deny,
            StartupInvariantStatus::Invalid,
            StartupFailureReason::MembraneDenied,
            SecureModeState::Unknown,
            started,
        );
        return -1;
    }

    path.push(StartupCheckpoint::ValidateMainPointer);
    let Some(main_fn) = main else {
        path.push(StartupCheckpoint::Deny);
        // SAFETY: writes TLS errno.
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 20, true);
        record_phase0_outcome(
            &path,
            StartupPolicyDecision::Deny,
            StartupInvariantStatus::Invalid,
            StartupFailureReason::MissingMain,
            SecureModeState::Unknown,
            started,
        );
        return -1;
    };

    path.push(StartupCheckpoint::ValidateArgvPointer);
    if ubp_av.is_null() {
        path.push(StartupCheckpoint::Deny);
        // SAFETY: writes TLS errno.
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 20, true);
        record_phase0_outcome(
            &path,
            StartupPolicyDecision::Deny,
            StartupInvariantStatus::Invalid,
            StartupFailureReason::NullArgv,
            SecureModeState::Unknown,
            started,
        );
        return -1;
    }

    path.push(StartupCheckpoint::ScanArgvVector);
    // SAFETY: `ubp_av` is validated non-null above.
    let argv_count = match unsafe { count_c_string_vector(ubp_av, MAX_STARTUP_SCAN) } {
        Some(v) => v,
        None => {
            path.push(StartupCheckpoint::Deny);
            // SAFETY: writes TLS errno.
            unsafe { set_abi_errno(libc::E2BIG) };
            runtime_policy::observe(ApiFamily::Process, decision.profile, 20, true);
            record_phase0_outcome(
                &path,
                StartupPolicyDecision::Deny,
                StartupInvariantStatus::Invalid,
                StartupFailureReason::UnterminatedArgv,
                SecureModeState::Unknown,
                started,
            );
            return -1;
        }
    };

    path.push(StartupCheckpoint::ValidateArgcBound);
    if argv_count < normalized_argc {
        path.push(StartupCheckpoint::Deny);
        // SAFETY: writes TLS errno.
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 20, true);
        record_phase0_outcome(
            &path,
            StartupPolicyDecision::Deny,
            StartupInvariantStatus::Invalid,
            StartupFailureReason::ArgcOutOfBounds,
            SecureModeState::Unknown,
            started,
        );
        return -1;
    }

    // SAFETY: argv_count >= normalized_argc and argv vector has a terminating null.
    let envp = unsafe { ubp_av.add(normalized_argc.saturating_add(1)) };
    path.push(StartupCheckpoint::ScanEnvpVector);
    // SAFETY: `envp` points at the null-terminated env vector in phase-0 fixtures.
    let env_count = match unsafe { count_c_string_vector(envp, MAX_STARTUP_SCAN) } {
        Some(v) => v,
        None => {
            path.push(StartupCheckpoint::Deny);
            // SAFETY: writes TLS errno.
            unsafe { set_abi_errno(libc::E2BIG) };
            runtime_policy::observe(ApiFamily::Process, decision.profile, 20, true);
            record_phase0_outcome(
                &path,
                StartupPolicyDecision::Deny,
                StartupInvariantStatus::Invalid,
                StartupFailureReason::UnterminatedEnvp,
                SecureModeState::Unknown,
                started,
            );
            return -1;
        }
    };

    path.push(StartupCheckpoint::ScanAuxvVector);
    // SAFETY: `stack_end` is treated as an auxv key/value array in controlled fixtures.
    let auxv_pairs = unsafe { read_auxv_pairs(stack_end, MAX_STARTUP_SCAN) };
    let secure_evidence = classify_secure_mode(&auxv_pairs, MAX_STARTUP_SCAN);
    if secure_evidence.truncated {
        path.push(StartupCheckpoint::Deny);
        // SAFETY: writes TLS errno.
        unsafe { set_abi_errno(libc::E2BIG) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 20, true);
        record_phase0_outcome(
            &path,
            StartupPolicyDecision::Deny,
            StartupInvariantStatus::Invalid,
            StartupFailureReason::UnterminatedAuxv,
            secure_evidence.state,
            started,
        );
        return -1;
    }
    path.push(StartupCheckpoint::ClassifySecureMode);

    let auxv_count = secure_evidence.scanned_pairs;
    let secure_mode = secure_evidence.state.is_secure();

    let inv = build_invariants(argc, argv_count, env_count, auxv_count, secure_mode);
    path.push(StartupCheckpoint::CaptureInvariants);
    store_invariants(inv);

    path.push(StartupCheckpoint::ResolveEnvp);
    let resolved_envp = unsafe { resolve_startup_envp(argc, ubp_av, envp) };
    path.push(StartupCheckpoint::BindProcessGlobals);
    init_process_globals(ubp_av, resolved_envp);
    path.push(StartupCheckpoint::BootstrapHostSymbols);
    crate::host_resolve::bootstrap_host_symbols();
    path.push(StartupCheckpoint::InitHostStdio);
    crate::stdio_abi::init_host_stdio_streams();
    path.push(StartupCheckpoint::BootstrapHostLibio);
    unsafe { crate::io_internal_abi::bootstrap_host_libio_exports() };
    path.push(StartupCheckpoint::PrewarmThreadSymbols);
    crate::pthread_abi::prewarm_host_thread_symbols();
    path.push(StartupCheckpoint::PrewarmAllocatorSymbols);
    crate::malloc_abi::prewarm_host_allocator_symbols();
    path.push(StartupCheckpoint::SignalRuntimeReady);
    crate::runtime_policy::signal_runtime_ready();

    if let Some(init_fn) = init {
        path.push(StartupCheckpoint::CallInitHook);
        // SAFETY: callback pointer provided by caller.
        unsafe { init_fn() };
    }

    path.push(StartupCheckpoint::CallMain);
    // SAFETY: callback pointer + argv/envp pointers are validated for phase-0 fixture usage.
    let rc = unsafe { main_fn(normalized_argc as c_int, ubp_av, resolved_envp) };

    if let Some(fini_fn) = fini {
        path.push(StartupCheckpoint::CallFiniHook);
        // SAFETY: callback pointer provided by caller.
        unsafe { fini_fn() };
    }
    if let Some(rtld_fini_fn) = rtld_fini {
        path.push(StartupCheckpoint::CallRtldFiniHook);
        // SAFETY: callback pointer provided by caller.
        unsafe { rtld_fini_fn() };
    }

    path.push(StartupCheckpoint::Complete);
    runtime_policy::observe(ApiFamily::Process, decision.profile, 20, membrane_denied);
    record_phase0_outcome(
        &path,
        StartupPolicyDecision::Allow,
        StartupInvariantStatus::Valid,
        StartupFailureReason::None,
        secure_evidence.state,
        started,
    );
    rc
}

/// libc-compatible startup symbol. Delegates to host libc unless phase-0 mode is explicitly enabled.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_start_main(
    main: Option<MainFn>,
    argc: c_int,
    ubp_av: *mut *mut c_char,
    init: Option<HookFn>,
    fini: Option<HookFn>,
    rtld_fini: Option<HookFn>,
    stack_end: *mut c_void,
) -> c_int {
    // Keep loader/init in bootstrap passthrough mode and flip runtime-ready at
    // the wrapped `main` boundary after host libc initialization completes.

    if startup_phase0_env_enabled() {
        // SAFETY: explicit phase-0 opt-in path.
        let phase0_rc =
            unsafe { startup_phase0_impl(main, argc, ubp_av, init, fini, rtld_fini, stack_end) };
        if phase0_rc >= 0 {
            return phase0_rc;
        }

        let phase0 = startup_policy_snapshot_for_tests();
        if startup_failure_allows_host_fallback(phase0.failure_reason)
            && let Some(host_rc) = unsafe {
                delegate_to_host_libc_start_main(
                    main, argc, ubp_av, init, fini, rtld_fini, stack_end,
                )
            }
        {
            store_policy_snapshot(
                StartupPolicyDecision::FallbackHost,
                phase0.invariant_status,
                phase0.failure_reason,
                phase0.secure_mode_state,
                true,
                StartupCheckpoint::FallbackHost,
                phase0.latency_ns,
            );
            return host_rc;
        }

        if startup_failure_allows_host_fallback(phase0.failure_reason) {
            // SAFETY: writes TLS errno.
            unsafe { set_abi_errno(libc::ENOSYS) };
            store_policy_snapshot(
                StartupPolicyDecision::Deny,
                StartupInvariantStatus::Invalid,
                StartupFailureReason::HostDelegateUnavailable,
                phase0.secure_mode_state,
                true,
                StartupCheckpoint::FallbackHost,
                phase0.latency_ns,
            );
            return -1;
        }

        return phase0_rc;
    }

    // SAFETY: forwards to host libc startup for normal LD_PRELOAD operation.
    if let Some(rc) = unsafe {
        delegate_to_host_libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end)
    } {
        store_policy_snapshot(
            StartupPolicyDecision::FallbackHost,
            StartupInvariantStatus::Unknown,
            StartupFailureReason::None,
            SecureModeState::Unknown,
            true,
            StartupCheckpoint::FallbackHost,
            0,
        );
        return rc;
    }

    // Host delegation failed (dlvsym couldn't find host __libc_start_main).
    // Fall back to calling main() directly with minimal init.
    // This is sufficient for most LD_PRELOAD scenarios.
    if let Some(init_fn) = init {
        // SAFETY: init is the .init function from the ELF; call it for C++ constructors etc.
        unsafe { init_fn() };
    }
    let envp = unsafe { resolve_startup_envp(argc, ubp_av, environ) };
    init_process_globals(ubp_av, envp);
    crate::host_resolve::bootstrap_host_symbols();
    unsafe { crate::io_internal_abi::bootstrap_host_libio_exports() };
    crate::stdio_abi::init_host_stdio_streams();
    crate::unistd_abi::init_stack_canary();
    crate::pthread_abi::prewarm_host_thread_symbols();
    crate::malloc_abi::prewarm_host_allocator_symbols();
    crate::runtime_policy::signal_runtime_ready();
    let rc = match main {
        Some(main_fn) => unsafe { main_fn(argc, ubp_av, envp) },
        None => 0,
    };
    if let Some(fini_fn) = fini {
        // SAFETY: fini is the .fini function.
        unsafe { fini_fn() };
    }
    // __libc_start_main must NEVER return to _start — the crt0 stub
    // assumes it diverges.
    // SAFETY: raw syscall exit after main() completes.
    frankenlibc_core::syscall::sys_exit_group(rc)
}

/// Test-hook alias that always executes the phase-0 startup path.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __frankenlibc_startup_phase0(
    main: Option<MainFn>,
    argc: c_int,
    ubp_av: *mut *mut c_char,
    init: Option<HookFn>,
    fini: Option<HookFn>,
    rtld_fini: Option<HookFn>,
    stack_end: *mut c_void,
) -> c_int {
    // SAFETY: dedicated fixture path invokes the same validated implementation.
    unsafe { startup_phase0_impl(main, argc, ubp_av, init, fini, rtld_fini, stack_end) }
}

// ===========================================================================
// __cxa_thread_atexit_impl — thread-local destructor registration
// ===========================================================================

/// Thread-local at-exit destructor entry.
struct TlsAtExitEntry {
    dtor: unsafe extern "C" fn(*mut c_void),
    obj: *mut c_void,
    // _dso_handle ignored — we don't track DSO unloading
}

type HostCxaThreadAtExitImplFn =
    unsafe extern "C" fn(unsafe extern "C" fn(*mut c_void), *mut c_void, *mut c_void) -> c_int;

// SAFETY: pointers are only accessed by the thread that registered them.
unsafe impl Send for TlsAtExitEntry {}

std::thread_local! {
    static TLS_ATEXIT_LIST: std::cell::RefCell<Vec<TlsAtExitEntry>> = const {
        std::cell::RefCell::new(Vec::new())
    };
    static TLS_ATEXIT_CAPTURE_FOR_TESTS: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static TLS_ATEXIT_REENTRY: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

// Cached pointer to the host's __cxa_thread_atexit_impl. Encoded as:
//   0                  = unresolved (try lookup)
//   usize::MAX         = resolved-but-absent (host doesn't export the symbol)
//   any other value    = resolved function pointer
//
// Using a plain AtomicUsize (not OnceLock) is required because the resolver
// path may indirectly re-enter `__cxa_thread_atexit_impl` during dynamic
// loader/TLS bring-up; a OnceLock would wedge in its RUNNING state and the
// recursive call would futex-wait on itself.
static HOST_CXA_THREAD_ATEXIT_IMPL: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
const HOST_CXA_THREAD_ATEXIT_IMPL_SENTINEL_NULL: usize = usize::MAX;

std::thread_local! {
    static HOST_CXA_LOOKUP_REENTRY: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

unsafe fn host_cxa_thread_atexit_impl() -> Option<HostCxaThreadAtExitImplFn> {
    use std::sync::atomic::Ordering;

    let cached = HOST_CXA_THREAD_ATEXIT_IMPL.load(Ordering::Acquire);
    if cached == HOST_CXA_THREAD_ATEXIT_IMPL_SENTINEL_NULL {
        return None;
    }
    if cached != 0 {
        return Some(unsafe { std::mem::transmute::<usize, HostCxaThreadAtExitImplFn>(cached) });
    }

    // Reentry guard: if the resolver recurses back into us before the lookup
    // completes, return None so the caller falls through to the in-Rust TLS
    // fallback list. Without this guard the recursive path would re-enter
    // dlsym and either hang the loader lock or stack-overflow.
    let entered = HOST_CXA_LOOKUP_REENTRY
        .try_with(|c| {
            if c.get() {
                false
            } else {
                c.set(true);
                true
            }
        })
        .unwrap_or(false);
    if !entered {
        return None;
    }

    let resolved =
        crate::host_resolve::resolve_host_symbol_raw("__cxa_thread_atexit_impl").unwrap_or(0);

    let _ = HOST_CXA_LOOKUP_REENTRY.try_with(|c| c.set(false));

    let to_store = if resolved == 0 {
        HOST_CXA_THREAD_ATEXIT_IMPL_SENTINEL_NULL
    } else {
        resolved
    };
    // First-writer-wins: any concurrent resolver returns the same dlsym
    // result, so losing the race is fine.
    let _ = HOST_CXA_THREAD_ATEXIT_IMPL.compare_exchange(
        0,
        to_store,
        Ordering::Release,
        Ordering::Acquire,
    );

    if resolved == 0 {
        None
    } else {
        Some(unsafe { std::mem::transmute::<usize, HostCxaThreadAtExitImplFn>(resolved) })
    }
}

/// `__cxa_thread_atexit_impl` — register a thread-local destructor.
/// Called by C++ for thread_local objects with non-trivial destructors.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_thread_atexit_impl(
    dtor: unsafe extern "C" fn(*mut c_void),
    obj: *mut c_void,
    _dso_handle: *mut c_void,
) -> c_int {
    if !TLS_ATEXIT_CAPTURE_FOR_TESTS.with(|capture| capture.get())
        && let Some(host) = unsafe { host_cxa_thread_atexit_impl() }
    {
        return unsafe { host(dtor, obj, _dso_handle) };
    }

    // Break recursion: first TLS access triggers __cxa_thread_atexit_impl
    // to register Rust's own TLS destructor.  We cannot use dlsym(RTLD_NEXT)
    // because our interposed dlsym also accesses TLS, creating another cycle.
    // On reentry, silently succeed without registering — the dropped destructor
    // is Rust's own TLS cleanup which is harmless to skip during init.
    if TLS_ATEXIT_REENTRY.with(|reentry| {
        if reentry.get() {
            true
        } else {
            reentry.set(true);
            false
        }
    }) {
        return 0; // Silently drop reentrant registration
    }
    let result = TLS_ATEXIT_LIST.with(|list| {
        list.borrow_mut().push(TlsAtExitEntry { dtor, obj });
        0
    });
    TLS_ATEXIT_REENTRY.with(|reentry| reentry.set(false));
    result
}

/// Drain and invoke all registered thread-local destructors in LIFO order.
///
/// Called by `__call_tls_dtors` in `glibc_internal_abi`. Each destructor is
/// invoked exactly once with its registered object pointer, then removed.
pub(crate) fn invoke_tls_dtors() {
    TLS_ATEXIT_LIST.with(|list| {
        // Drain in reverse (LIFO) order, matching glibc behavior.
        let mut entries = list.borrow_mut();
        while let Some(entry) = entries.pop() {
            // SAFETY: caller registered a valid function pointer and object.
            unsafe { (entry.dtor)(entry.obj) };
        }
    });
}

#[doc(hidden)]
pub unsafe fn register_tls_dtor_for_tests(
    dtor: unsafe extern "C" fn(*mut c_void),
    obj: *mut c_void,
) -> c_int {
    TLS_ATEXIT_CAPTURE_FOR_TESTS.with(|capture| {
        let previous = capture.replace(true);
        let result = unsafe { __cxa_thread_atexit_impl(dtor, obj, std::ptr::null_mut()) };
        capture.set(previous);
        result
    })
}

#[doc(hidden)]
pub fn clear_tls_dtors_for_tests() {
    TLS_ATEXIT_LIST.with(|list| list.borrow_mut().clear());
}

// ===========================================================================
// __stack_chk_fail — stack protection
// ===========================================================================
/// Returns the last captured startup invariants from `startup_phase0_impl`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __frankenlibc_startup_snapshot(
    out: *mut StartupInvariantSnapshot,
) -> c_int {
    if out.is_null() {
        // SAFETY: writes TLS errno.
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }

    let snapshot = StartupInvariantSnapshot {
        argc: LAST_ARGC.load(Ordering::Relaxed),
        argv_count: LAST_ARGV_COUNT.load(Ordering::Relaxed),
        env_count: LAST_ENV_COUNT.load(Ordering::Relaxed),
        auxv_count: LAST_AUXV_COUNT.load(Ordering::Relaxed),
        secure_mode: i32::from(LAST_SECURE_MODE.load(Ordering::Relaxed) != 0),
    };

    // SAFETY: `out` is validated non-null above.
    unsafe { *out = snapshot };
    0
}

// ===========================================================================
// getprogname / setprogname — BSD program-name accessors
// ===========================================================================
//
// NetBSD/OpenBSD-origin (glibc 2.41 also exposes them) for tools and
// libraries that want to query or override the basename of argv[0]
// without depending on the GNU-specific `program_invocation_short_name`
// global. Backing storage is the same `program_invocation_short_name`
// AtomicPtr that the existing err.h family already consults — so the
// three vocabularies (BSD, GNU, __progname) stay in sync.

/// BSD `getprogname()` — return a pointer to the cached program
/// short name, or an empty static C string if startup hasn't yet
/// published one.
///
/// The returned pointer is owned by the runtime; callers must not
/// free it. For the lifetime contract, see `setprogname`: if the
/// program supplied its own buffer through setprogname, that buffer
/// is what we hand back, so the caller is responsible for keeping
/// it alive (matching the NetBSD documented behavior).
///
/// # Safety
///
/// No caller obligations — the function is `extern "C"` only because
/// it is part of the public C ABI.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getprogname() -> *const c_char {
    static EMPTY: [u8; 1] = [0];
    let p = program_invocation_short_name.load(Ordering::Acquire);
    if p.is_null() {
        EMPTY.as_ptr() as *const c_char
    } else {
        p as *const c_char
    }
}

/// BSD `setprogname(progname)` — store the basename (last `/`
/// component) of `progname` as the cached program short name.
/// Subsequent calls to `getprogname`, the err.h family, and the
/// glibc `program_invocation_short_name` / `__progname` aliases all
/// observe the new value.
///
/// `progname == NULL` is a no-op (matches NetBSD).
///
/// The caller retains ownership of the buffer. Per the NetBSD
/// `setprogname(3)` contract, the runtime stores the supplied
/// pointer directly (after walking it to the basename) — it does
/// **not** copy the bytes. Callers that pass stack-allocated or
/// freed storage are responsible for the resulting use-after-free.
///
/// # Safety
///
/// Caller must ensure `progname`, when non-NULL, is a valid
/// NUL-terminated C string with static or program-lifetime storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setprogname(progname: *const c_char) {
    if progname.is_null() {
        return;
    }

    let Some(base) = (unsafe { basename_within_c_string(progname) }) else {
        return;
    };

    program_invocation_short_name.store(base, Ordering::Release);
    __progname.store(base, Ordering::Release);
}
