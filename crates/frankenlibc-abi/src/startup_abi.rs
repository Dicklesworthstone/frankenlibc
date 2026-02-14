//! Phase-0 CRT bootstrap ABI plumbing.
//!
//! This module exposes a constrained startup path for controlled fixtures.
//! `__libc_start_main` delegates to host libc by default to avoid hijacking
//! normal process bootstrap in LD_PRELOAD mode.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::Instant;

use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;
use crate::startup_helpers::{
    AT_NULL, MAX_STARTUP_SCAN, SecureModeState, StartupCheckpoint, StartupInvariants,
    build_invariants, classify_secure_mode, normalize_argc, startup_path_respects_dag,
};

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

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
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

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    // SAFETY: `__errno_location` returns a valid TLS errno pointer.
    let p = unsafe { super::errno_abi::__errno_location() };
    // SAFETY: errno pointer is valid for writes on this thread.
    unsafe { *p = val };
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

unsafe fn delegate_to_host_libc_start_main(
    main: Option<MainFn>,
    argc: c_int,
    ubp_av: *mut *mut c_char,
    init: Option<HookFn>,
    fini: Option<HookFn>,
    rtld_fini: Option<HookFn>,
    stack_end: *mut c_void,
) -> Option<c_int> {
    let symbol = b"__libc_start_main\0";
    let glibc_v34 = b"GLIBC_2.34\0";
    let glibc_v225 = b"GLIBC_2.2.5\0";
    // SAFETY: versioned lookup via host dynamic loader, bypassing our interposed
    // dlsym symbol to avoid recursive startup-resolution loops.
    let mut ptr = unsafe {
        libc::dlvsym(
            libc::RTLD_NEXT,
            symbol.as_ptr().cast::<c_char>(),
            glibc_v34.as_ptr().cast::<c_char>(),
        )
    };
    if ptr.is_null() {
        // SAFETY: fallback to older glibc symbol version when 2.34 alias is absent.
        ptr = unsafe {
            libc::dlvsym(
                libc::RTLD_NEXT,
                symbol.as_ptr().cast::<c_char>(),
                glibc_v225.as_ptr().cast::<c_char>(),
            )
        };
    }
    if ptr.is_null() {
        return None;
    }

    // SAFETY: symbol is expected to match HostStartMainFn ABI and signature.
    let host_fn: HostStartMainFn = unsafe { std::mem::transmute(ptr) };
    // SAFETY: forwards original startup ABI arguments to host libc.
    Some(unsafe { host_fn(main, argc, ubp_av, init, fini, rtld_fini, stack_end) })
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

    if let Some(init_fn) = init {
        path.push(StartupCheckpoint::CallInitHook);
        // SAFETY: callback pointer provided by caller.
        unsafe { init_fn() };
    }

    path.push(StartupCheckpoint::CallMain);
    // SAFETY: callback pointer + argv/envp pointers are validated for phase-0 fixture usage.
    let rc = unsafe { main_fn(normalized_argc as c_int, ubp_av, envp) };

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
    if startup_phase0_env_enabled() {
        // SAFETY: explicit phase-0 opt-in path.
        return unsafe {
            startup_phase0_impl(main, argc, ubp_av, init, fini, rtld_fini, stack_end)
        };
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

    // SAFETY: writes TLS errno.
    unsafe { set_abi_errno(libc::ENOSYS) };
    store_policy_snapshot(
        StartupPolicyDecision::Deny,
        StartupInvariantStatus::Invalid,
        StartupFailureReason::HostDelegateUnavailable,
        SecureModeState::Unknown,
        true,
        StartupCheckpoint::FallbackHost,
        0,
    );
    -1
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
