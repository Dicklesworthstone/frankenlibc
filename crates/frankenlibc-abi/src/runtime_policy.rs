//! Runtime policy bridge for ABI entrypoints.
//!
//! This module centralizes access to the membrane RuntimeMathKernel so ABI
//! functions can cheaply obtain per-call decisions and publish observations
//! without duplicating orchestration code.

#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::ffi::c_char;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Mutex;
use std::sync::atomic::{AtomicPtr, AtomicU8, AtomicU32, AtomicU64, Ordering as AtomicOrdering};

use frankenlibc_core::syscall;
use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::config::SafetyLevel;
use frankenlibc_membrane::decision_contract::{
    DecisionAction as DecisionContractAction, DecisionContractMachine,
    DecisionEvent as DecisionContractEvent, TsmState,
};
use frankenlibc_membrane::runtime_math::{
    ApiFamily, MembraneAction, RuntimeContext, RuntimeDecision, RuntimeEvidenceContractSnapshot,
    RuntimeKernelSnapshot, RuntimeMathKernel, ValidationProfile,
};
use frankenlibc_membrane::util::now_utc_iso_like;

// Kernel lifecycle states.
const STATE_UNINIT: u8 = 0;
const STATE_INITIALIZING: u8 = 1;
const STATE_READY: u8 = 2;
const STATE_BROKEN: u8 = 3;
const MODE_UNRESOLVED: u8 = 0;
const MODE_STRICT: u8 = 1;
const MODE_HARDENED: u8 = 2;
const MODE_OFF: u8 = 3;
const MODE_RESOLVING: u8 = 255;
const PANIC_HOOK_UNSET: u8 = 0;
const PANIC_HOOK_INSTALLED: u8 = 1;
const PANIC_HOOK_WRITE_IDLE: u8 = 0;
const PANIC_HOOK_WRITE_ACTIVE: u8 = 1;
const PANIC_HOOK_LOG_LIMIT: u32 = 64;
const TRACE_UNKNOWN_SYMBOL: &str = "unknown";
const CONTROLLER_ID_RUNTIME_MATH: &str = "runtime_math_kernel.v1";
const DECISION_GATE_RUNTIME_POLICY: &str = "runtime_policy.decide";
const DECISION_CONTRACT_CLEAR_THRESHOLD: u16 = 3;
const MODE_SWITCH_CHECK_STRIDE: u64 = 4096;
const MODE_LOG_CAPACITY: usize = 256;
// Export helpers are non-hotpath and should tolerate cross-thread kernel init.
const KERNEL_EXPORT_RETRY_ATTEMPTS: usize = 5_000;
const CONTROLLER_ID_RUNTIME_MODE: &str = "runtime_policy.mode.v1";
const MODE_LOG_ARTIFACT: &str = "crates/frankenlibc-abi/src/runtime_policy.rs";

// Manual init guard that avoids OnceLock's internal futex.
// OnceLock::get_or_init uses a futex wait when it sees init-in-progress,
// which causes deadlock if a reentrant call from the same thread arrives
// during RuntimeMathKernel::new(). Instead, we use a simple atomic state
// machine: UNINIT -> INITIALIZING -> READY, and any reentrant call that
// sees INITIALIZING returns None (passthrough).
static KERNEL_STATE: AtomicU8 = AtomicU8::new(STATE_UNINIT);
static KERNEL_PTR: AtomicPtr<RuntimeMathKernel> = AtomicPtr::new(std::ptr::null_mut());
static MODE_STATE: AtomicU8 = AtomicU8::new(MODE_UNRESOLVED);
static PANIC_HOOK_STATE: AtomicU8 = AtomicU8::new(PANIC_HOOK_UNSET);
static PANIC_HOOK_WRITE_STATE: AtomicU8 = AtomicU8::new(PANIC_HOOK_WRITE_IDLE);
static PANIC_HOOK_LOG_COUNT: AtomicU32 = AtomicU32::new(0);
static MODE_SWITCH_CHECK_COUNTER: AtomicU64 = AtomicU64::new(0);
static MODE_LOG_DECISION_SEQ: AtomicU64 = AtomicU64::new(0);
static MODE_EVENT_LOGS: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

fn mode_to_u8(level: SafetyLevel) -> u8 {
    match level {
        SafetyLevel::Strict => MODE_STRICT,
        SafetyLevel::Hardened => MODE_HARDENED,
        SafetyLevel::Off => MODE_OFF,
    }
}

fn u8_to_mode(v: u8) -> SafetyLevel {
    match v {
        MODE_HARDENED => SafetyLevel::Hardened,
        MODE_OFF => SafetyLevel::Off,
        _ => SafetyLevel::Strict,
    }
}

#[cfg(test)]
fn parse_mode_value(raw: &str) -> SafetyLevel {
    match raw.to_ascii_lowercase().as_str() {
        "hardened" | "repair" | "tsm" | "full" => SafetyLevel::Hardened,
        "strict" | "default" | "abi" => SafetyLevel::Strict,
        // Runtime contract is strict|hardened only. Keep benchmark-only Off
        // reachable through direct API use, not env parsing.
        _ => SafetyLevel::Strict,
    }
}

#[inline]
unsafe fn cstr_eq_ignore_ascii_case(ptr: *const c_char, expected: &[u8]) -> bool {
    for (idx, want) in expected.iter().enumerate() {
        // SAFETY: caller guarantees a valid NUL-terminated C string pointer.
        let got = unsafe { *ptr.add(idx) as u8 };
        if got == 0 || !got.eq_ignore_ascii_case(want) {
            return false;
        }
    }
    // SAFETY: same as above.
    unsafe { *ptr.add(expected.len()) as u8 == 0 }
}

fn parse_mode_from_environ() -> Result<Option<SafetyLevel>, ()> {
    const KEY_EQ: &[u8] = b"FRANKENLIBC_MODE=";
    const MAX_SCAN: usize = 4096;

    // SAFETY: process-owned env pointer table, expected to be NUL-terminated.
    let mut envp = unsafe { environ };
    if envp.is_null() {
        return Err(());
    }

    for _ in 0..MAX_SCAN {
        // SAFETY: envp points to a readable pointer slot in env vector.
        let entry = unsafe { *envp };
        if entry.is_null() {
            return Ok(None);
        }

        let mut matched = true;
        for (idx, want) in KEY_EQ.iter().enumerate() {
            // SAFETY: entry points to a NUL-terminated env string.
            let got = unsafe { *entry.add(idx) as u8 };
            if got != *want {
                matched = false;
                break;
            }
        }

        if matched {
            // SAFETY: KEY_EQ matched exactly; value pointer is in-bounds.
            let value = unsafe { entry.add(KEY_EQ.len()) };
            // Hardened aliases are accepted case-insensitively.
            // SAFETY: value is a valid C string tail of entry.
            if unsafe {
                cstr_eq_ignore_ascii_case(value, b"hardened")
                    || cstr_eq_ignore_ascii_case(value, b"repair")
                    || cstr_eq_ignore_ascii_case(value, b"tsm")
                    || cstr_eq_ignore_ascii_case(value, b"full")
            } {
                return Ok(Some(SafetyLevel::Hardened));
            }
            // Unrecognized values fall back to strict by contract.
            return Ok(Some(SafetyLevel::Strict));
        }

        // SAFETY: advance to next env vector slot.
        envp = unsafe { envp.add(1) };
    }

    Ok(None)
}

fn mode_name(level: SafetyLevel) -> &'static str {
    match level {
        SafetyLevel::Strict => "strict",
        SafetyLevel::Hardened => "hardened",
        SafetyLevel::Off => "off",
    }
}

/// Deferred mode event log flag.  During early startup the heap may not be
/// available (pre-TLS, bump allocator active).  `format!()` would trigger
/// allocation → OOM → rust_oom → write(stderr) → runtime_policy::decide →
/// mode() → push_mode_event → format!() → infinite recursion.
///
/// We suppress logging until the mode is fully resolved and stored.
/// Events generated during resolution are dropped — an acceptable trade-off
/// for preventing a startup crash.
static MODE_LOG_READY: AtomicU8 = AtomicU8::new(0);

fn push_mode_event(
    level: &'static str,
    event: &'static str,
    resolved_mode: SafetyLevel,
    requested_mode: Option<SafetyLevel>,
) {
    // Suppress logging during early startup to prevent allocation recursion.
    // MODE_LOG_READY is set to 1 after the first successful mode resolution.
    if MODE_LOG_READY.load(AtomicOrdering::Relaxed) == 0 {
        return;
    }

    let decision_id = MODE_LOG_DECISION_SEQ.fetch_add(1, AtomicOrdering::Relaxed) + 1;
    let trace_id = format!("runtime_policy::mode::{decision_id:016x}");
    let requested_mode = requested_mode
        .map(|mode| format!("\"{}\"", mode_name(mode)))
        .unwrap_or_else(|| "null".to_string());
    let timestamp = now_utc_iso_like();
    let line = format!(
        "{{\"timestamp\":\"{timestamp}\",\"trace_id\":\"{trace_id}\",\"decision_id\":{decision_id},\"level\":\"{level}\",\"event\":\"{event}\",\"controller_id\":\"{CONTROLLER_ID_RUNTIME_MODE}\",\"decision_path\":\"mode->cache->immutable\",\"mode\":\"{}\",\"requested_mode\":{requested_mode},\"artifact_refs\":[\"{MODE_LOG_ARTIFACT}\"]}}",
        mode_name(resolved_mode),
    );

    if let Ok(mut logs) = MODE_EVENT_LOGS.lock() {
        if logs.len() >= MODE_LOG_CAPACITY {
            let _ = logs.pop_front();
        }
        logs.push_back(line);
    }
}

fn maybe_log_mode_switch_attempt(cached_mode: SafetyLevel) {
    let sequence = MODE_SWITCH_CHECK_COUNTER.fetch_add(1, AtomicOrdering::Relaxed) + 1;
    if !sequence.is_multiple_of(MODE_SWITCH_CHECK_STRIDE) {
        return;
    }

    match parse_mode_from_environ() {
        Ok(Some(requested_mode)) if requested_mode != cached_mode => {
            push_mode_event(
                "error",
                "runtime_mode_switch_attempt",
                cached_mode,
                Some(requested_mode),
            );
        }
        Ok(_) => {}
        Err(_) => {
            push_mode_event("warn", "runtime_mode_env_unavailable", cached_mode, None);
        }
    }
}

#[must_use]
pub(crate) fn export_mode_event_log_jsonl() -> String {
    MODE_EVENT_LOGS
        .lock()
        .ok()
        .map(|logs| logs.iter().cloned().collect::<Vec<_>>().join("\n"))
        .unwrap_or_default()
}

pub(crate) fn clear_mode_event_log() {
    if let Ok(mut logs) = MODE_EVENT_LOGS.lock() {
        logs.clear();
    }
}

fn load_thread_local_mode_cache() -> Option<SafetyLevel> {
    MODE_THREAD_LOCAL_CACHE
        .try_with(|cache| {
            let cached = cache.get();
            if cached != MODE_UNRESOLVED && cached != MODE_RESOLVING {
                Some(u8_to_mode(cached))
            } else {
                None
            }
        })
        .ok()
        .flatten()
}

fn store_thread_local_mode_cache(level: SafetyLevel) {
    let mode = mode_to_u8(level);
    let _ = MODE_THREAD_LOCAL_CACHE.try_with(|cache| cache.set(mode));
}

fn clear_thread_local_mode_cache() {
    let _ = MODE_THREAD_LOCAL_CACHE.try_with(|cache| cache.set(MODE_UNRESOLVED));
}

#[must_use]
pub(crate) fn mode() -> SafetyLevel {
    if let Some(resolved) = load_thread_local_mode_cache() {
        maybe_log_mode_switch_attempt(resolved);
        return resolved;
    }

    let cached = MODE_STATE.load(AtomicOrdering::Relaxed);

    if cached != MODE_UNRESOLVED && cached != MODE_RESOLVING {
        let resolved = u8_to_mode(cached);
        store_thread_local_mode_cache(resolved);
        maybe_log_mode_switch_attempt(resolved);
        return resolved;
    }

    if cached == MODE_RESOLVING {
        push_mode_event(
            "warn",
            "runtime_mode_resolution_reentrant",
            SafetyLevel::Strict,
            None,
        );
        return SafetyLevel::Strict;
    }

    if MODE_STATE
        .compare_exchange(
            MODE_UNRESOLVED,
            MODE_RESOLVING,
            AtomicOrdering::SeqCst,
            AtomicOrdering::Relaxed,
        )
        .is_err()
    {
        let v = MODE_STATE.load(AtomicOrdering::Relaxed);
        return if v != MODE_UNRESOLVED && v != MODE_RESOLVING {
            let resolved = u8_to_mode(v);
            store_thread_local_mode_cache(resolved);
            maybe_log_mode_switch_attempt(resolved);
            resolved
        } else {
            push_mode_event(
                "warn",
                "runtime_mode_resolution_race",
                SafetyLevel::Strict,
                None,
            );
            SafetyLevel::Strict
        };
    }

    let result = match parse_mode_from_environ() {
        Ok(Some(level)) => {
            MODE_STATE.store(mode_to_u8(level), AtomicOrdering::Release);
            store_thread_local_mode_cache(level);
            level
        }
        Ok(None) => {
            MODE_STATE.store(MODE_STRICT, AtomicOrdering::Release);
            store_thread_local_mode_cache(SafetyLevel::Strict);
            SafetyLevel::Strict
        }
        Err(_) => {
            MODE_STATE.store(MODE_UNRESOLVED, AtomicOrdering::Release);
            SafetyLevel::Strict
        }
    };
    // Enable mode event logging on a LATER call, not this one.
    // The first push_mode_event would allocate via format!(), which can
    // trigger OOM → write(stderr) → runtime_policy::decide → mode() →
    // push_mode_event → infinite recursion during early startup.
    // MODE_LOG_READY is set to 1 by decide() once its first successful
    // call completes, ensuring the heap is operational before logging.
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TraceContext {
    trace_seq: u64,
    symbol: &'static str,
    parent_span_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DecisionExplainability {
    pub trace_seq: u64,
    pub span_seq: u64,
    pub parent_span_seq: u64,
    pub symbol: &'static str,
    pub controller_id: &'static str,
    pub decision_gate: &'static str,
    pub mode: SafetyLevel,
    pub family: ApiFamily,
    pub profile: ValidationProfile,
    pub action: MembraneAction,
    pub contract_state: TsmState,
    pub contract_event: DecisionContractEvent,
    pub contract_action: DecisionContractAction,
    pub policy_id: u32,
    pub risk_upper_bound_ppm: u32,
    pub requested_bytes: usize,
    pub addr_hint: usize,
    pub is_write: bool,
    pub bloom_negative: bool,
    pub contention_hint: u16,
    pub evidence_seqno: u64,
}

impl DecisionExplainability {
    #[must_use]
    pub fn trace_id(self) -> String {
        format!("abi::{}::{:016x}", self.symbol, self.trace_seq)
    }

    #[must_use]
    pub fn span_id(self) -> String {
        format!("abi::{}::decision::{:016x}", self.symbol, self.span_seq)
    }

    #[must_use]
    pub fn parent_span_id(self) -> String {
        format!("abi::{}::entry::{:016x}", self.symbol, self.parent_span_seq)
    }

    #[must_use]
    pub const fn decision_action(self) -> &'static str {
        match self.action {
            MembraneAction::Allow => "Allow",
            MembraneAction::FullValidate => "FullValidate",
            MembraneAction::Repair(_) => "Repair",
            MembraneAction::Deny => "Deny",
        }
    }
}

thread_local! {
    static MODE_THREAD_LOCAL_CACHE: Cell<u8> = const { Cell::new(MODE_UNRESOLVED) };
    static TRACE_COUNTER: Cell<u64> = const { Cell::new(0) };
    static DECISION_COUNTER: Cell<u64> = const { Cell::new(0) };
    static TRACE_CONTEXT: Cell<Option<TraceContext>> = const { Cell::new(None) };
    static LAST_EXPLAINABILITY: RefCell<Option<DecisionExplainability>> = const { RefCell::new(None) };
    static POLICY_REENTRY_DEPTH: Cell<u32> = const { Cell::new(0) };
    static DECISION_CONTRACT_MACHINE: RefCell<DecisionContractMachine> =
        const { RefCell::new(DecisionContractMachine::new(DECISION_CONTRACT_CLEAR_THRESHOLD)) };
}

pub(crate) struct EntrypointTraceGuard {
    previous: Option<TraceContext>,
}

impl Drop for EntrypointTraceGuard {
    fn drop(&mut self) {
        let _ = TRACE_CONTEXT.try_with(|slot| slot.set(self.previous));
    }
}

struct PolicyReentryGuard;

impl Drop for PolicyReentryGuard {
    fn drop(&mut self) {
        let _ = POLICY_REENTRY_DEPTH.try_with(|depth| {
            let current = depth.get();
            depth.set(current.saturating_sub(1));
        });
    }
}

#[inline]
fn enter_policy_reentry_guard() -> Option<PolicyReentryGuard> {
    POLICY_REENTRY_DEPTH
        .try_with(|depth| {
            let current = depth.get();
            if current > 0 {
                None
            } else {
                depth.set(current + 1);
                Some(PolicyReentryGuard)
            }
        })
        .unwrap_or(None)
}

#[must_use]
pub(crate) fn in_policy_reentry_context() -> bool {
    POLICY_REENTRY_DEPTH
        .try_with(|depth| depth.get() > 0)
        .unwrap_or(false)
}

#[must_use]
pub(crate) fn entrypoint_scope(symbol: &'static str) -> EntrypointTraceGuard {
    let trace_seq = next_trace_seq();

    let context = TraceContext {
        trace_seq,
        symbol,
        parent_span_seq: trace_seq,
    };

    let previous = TRACE_CONTEXT
        .try_with(|slot| {
            let prev = slot.get();
            slot.set(Some(context));
            prev
        })
        .ok()
        .flatten();

    EntrypointTraceGuard { previous }
}

#[must_use]
pub(crate) fn take_last_explainability() -> Option<DecisionExplainability> {
    LAST_EXPLAINABILITY
        .try_with(|slot| slot.borrow_mut().take())
        .ok()
        .flatten()
}

#[must_use]
pub(crate) fn peek_last_explainability() -> Option<DecisionExplainability> {
    LAST_EXPLAINABILITY
        .try_with(|slot| *slot.borrow())
        .ok()
        .flatten()
}

fn next_decision_span_seq() -> u64 {
    DECISION_COUNTER
        .try_with(|counter| {
            let next = counter.get().wrapping_add(1);
            counter.set(next);
            next
        })
        .unwrap_or(0)
}

fn next_trace_seq() -> u64 {
    TRACE_COUNTER
        .try_with(|counter| {
            let next = counter.get().wrapping_add(1);
            counter.set(next);
            next
        })
        .unwrap_or(0)
}

fn fallback_trace_context() -> TraceContext {
    let trace_seq = TRACE_COUNTER
        .try_with(|counter| {
            let next = counter.get().wrapping_add(1);
            counter.set(next);
            next
        })
        .unwrap_or(0);
    TraceContext {
        trace_seq,
        symbol: TRACE_UNKNOWN_SYMBOL,
        parent_span_seq: trace_seq,
    }
}

fn mark_kernel_broken() {
    KERNEL_STATE.store(STATE_BROKEN, AtomicOrdering::Release);
}

fn ensure_minimal_panic_hook() {
    // In test mode the standard test harness owns the panic hook. Installing our
    // custom hook would poison the kernel on normal assertion failures, cascading
    // into false failures in subsequent kernel-dependent tests.
    #[cfg(not(test))]
    {
        if PANIC_HOOK_STATE
            .compare_exchange(
                PANIC_HOOK_UNSET,
                PANIC_HOOK_INSTALLED,
                AtomicOrdering::SeqCst,
                AtomicOrdering::Relaxed,
            )
            .is_err()
        {
            return;
        }

        panic::set_hook(Box::new(|info| {
            const MSG: &[u8] = b"frankenlibc: runtime kernel panic (fallback)\n";
            mark_kernel_broken();

            let seen = PANIC_HOOK_LOG_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
            if seen >= PANIC_HOOK_LOG_LIMIT {
                return;
            }

            if PANIC_HOOK_WRITE_STATE
                .compare_exchange(
                    PANIC_HOOK_WRITE_IDLE,
                    PANIC_HOOK_WRITE_ACTIVE,
                    AtomicOrdering::AcqRel,
                    AtomicOrdering::Relaxed,
                )
                .is_err()
            {
                return;
            }

            // SAFETY: direct raw syscall write avoids libc indirection and is
            // async-signal-safe enough for panic reporting.
            let _ = unsafe { syscall::sys_write(libc::STDERR_FILENO, MSG.as_ptr(), MSG.len()) };
            if seen == 0 {
                const PREFIX: &[u8] = b"frankenlibc: panic location: ";
                let _ = unsafe {
                    syscall::sys_write(libc::STDERR_FILENO, PREFIX.as_ptr(), PREFIX.len())
                };
                if let Some(location) = info.location() {
                    let _ = unsafe {
                        syscall::sys_write(
                            libc::STDERR_FILENO,
                            location.file().as_bytes().as_ptr(),
                            location.file().len(),
                        )
                    };
                    let _ = unsafe { syscall::sys_write(libc::STDERR_FILENO, b":".as_ptr(), 1) };
                    write_u32_stderr(location.line());
                } else {
                    let _ =
                        unsafe { syscall::sys_write(libc::STDERR_FILENO, b"unknown".as_ptr(), 7) };
                }
                let _ = unsafe { syscall::sys_write(libc::STDERR_FILENO, b"\n".as_ptr(), 1) };

                const PAYLOAD_PREFIX: &[u8] = b"frankenlibc: panic payload: ";
                let _ = unsafe {
                    syscall::sys_write(
                        libc::STDERR_FILENO,
                        PAYLOAD_PREFIX.as_ptr(),
                        PAYLOAD_PREFIX.len(),
                    )
                };
                if let Some(payload) = info.payload().downcast_ref::<&str>() {
                    let payload_bytes = payload.as_bytes();
                    let payload_len = payload_bytes.len().min(512);
                    let _ = unsafe {
                        syscall::sys_write(libc::STDERR_FILENO, payload_bytes.as_ptr(), payload_len)
                    };
                } else if let Some(payload) = info.payload().downcast_ref::<String>() {
                    let payload_bytes = payload.as_bytes();
                    let payload_len = payload_bytes.len().min(512);
                    let _ = unsafe {
                        syscall::sys_write(libc::STDERR_FILENO, payload_bytes.as_ptr(), payload_len)
                    };
                } else {
                    let _ = unsafe {
                        syscall::sys_write(libc::STDERR_FILENO, b"<non-string>".as_ptr(), 12)
                    };
                }
                let _ = unsafe { syscall::sys_write(libc::STDERR_FILENO, b"\n".as_ptr(), 1) };
            }
            PANIC_HOOK_WRITE_STATE.store(PANIC_HOOK_WRITE_IDLE, AtomicOrdering::Release);
        }));
    }
}

fn write_u32_stderr(mut value: u32) {
    let mut buf = [0u8; 10];
    let mut idx = buf.len();

    if value == 0 {
        let _ = unsafe { syscall::sys_write(libc::STDERR_FILENO, b"0".as_ptr(), 1) };
        return;
    }

    while value > 0 {
        idx -= 1;
        buf[idx] = b'0' + (value % 10) as u8;
        value /= 10;
    }

    let _ = unsafe {
        syscall::sys_write(
            libc::STDERR_FILENO,
            buf[idx..].as_ptr(),
            buf.len().saturating_sub(idx),
        )
    };
}

fn active_trace_context() -> TraceContext {
    TRACE_CONTEXT
        .try_with(|slot| slot.get())
        .ok()
        .flatten()
        .unwrap_or_else(fallback_trace_context)
}

fn decision_contract_event_for_runtime_decision(
    decision: RuntimeDecision,
) -> DecisionContractEvent {
    match decision.action {
        MembraneAction::Allow => {
            if matches!(decision.profile, ValidationProfile::Full) {
                DecisionContractEvent::SoftAnomaly
            } else {
                DecisionContractEvent::CheckPass
            }
        }
        MembraneAction::FullValidate => DecisionContractEvent::SoftAnomaly,
        MembraneAction::Repair(_) | MembraneAction::Deny => DecisionContractEvent::HardViolation,
    }
}

fn apply_decision_contract(
    mode: SafetyLevel,
    decision: RuntimeDecision,
) -> (TsmState, DecisionContractEvent, DecisionContractAction) {
    let mut event = decision_contract_event_for_runtime_decision(decision);
    DECISION_CONTRACT_MACHINE
        .try_with(|slot| {
            let mut machine = slot.borrow_mut();
            let mut transition = machine.observe(event, mode);

            // Hardened repairs require an explicit completion edge from Unsafe -> Safe.
            if matches!(decision.action, MembraneAction::Repair(_)) {
                event = DecisionContractEvent::RepairComplete;
                transition = machine.observe(event, mode);
            }

            (transition.to, event, transition.action)
        })
        .unwrap_or((
            TsmState::Safe,
            DecisionContractEvent::CheckPass,
            DecisionContractAction::Log,
        ))
}

fn record_last_explainability(mode: SafetyLevel, ctx: RuntimeContext, decision: RuntimeDecision) {
    let trace = active_trace_context();
    let (contract_state, contract_event, contract_action) = apply_decision_contract(mode, decision);
    let explainability = DecisionExplainability {
        trace_seq: trace.trace_seq,
        span_seq: next_decision_span_seq(),
        parent_span_seq: trace.parent_span_seq,
        symbol: trace.symbol,
        controller_id: CONTROLLER_ID_RUNTIME_MATH,
        decision_gate: DECISION_GATE_RUNTIME_POLICY,
        mode,
        family: ctx.family,
        profile: decision.profile,
        action: decision.action,
        contract_state,
        contract_event,
        contract_action,
        policy_id: decision.policy_id,
        risk_upper_bound_ppm: decision.risk_upper_bound_ppm,
        requested_bytes: ctx.requested_bytes,
        addr_hint: ctx.addr_hint,
        is_write: ctx.is_write,
        bloom_negative: ctx.bloom_negative,
        contention_hint: ctx.contention_hint,
        evidence_seqno: decision.evidence_seqno,
    };

    let _ = LAST_EXPLAINABILITY.try_with(|slot| {
        *slot.borrow_mut() = Some(explainability);
    });
}

fn kernel() -> Option<&'static RuntimeMathKernel> {
    let state = KERNEL_STATE.load(AtomicOrdering::Acquire);

    if state == STATE_READY {
        // Fast path: already initialized.
        // SAFETY: once READY, KERNEL_PTR is valid and never changes.
        let ptr = KERNEL_PTR.load(AtomicOrdering::Acquire);
        return Some(unsafe { &*ptr });
    }

    if state == STATE_BROKEN {
        return None;
    }

    if state == STATE_INITIALIZING {
        // Reentrant call during init — passthrough to raw C behavior.
        return None;
    }

    // Try to claim the init slot.
    if KERNEL_STATE
        .compare_exchange(
            STATE_UNINIT,
            STATE_INITIALIZING,
            AtomicOrdering::SeqCst,
            AtomicOrdering::Relaxed,
        )
        .is_err()
    {
        // Another thread won the race. If it's still INITIALIZING, passthrough.
        // If it transitioned to READY, retry.
        return if KERNEL_STATE.load(AtomicOrdering::Acquire) == STATE_READY {
            let ptr = KERNEL_PTR.load(AtomicOrdering::Acquire);
            Some(unsafe { &*ptr })
        } else {
            None
        };
    }

    // We own the init. Allocate kernel on heap (leaked, lives forever).
    ensure_minimal_panic_hook();
    let kernel = match panic::catch_unwind(AssertUnwindSafe(RuntimeMathKernel::new)) {
        Ok(k) => Box::new(k),
        Err(_) => {
            mark_kernel_broken();
            return None;
        }
    };
    let ptr = Box::into_raw(kernel);
    KERNEL_PTR.store(ptr, AtomicOrdering::Release);
    KERNEL_STATE.store(STATE_READY, AtomicOrdering::Release);
    // NOTE: Do NOT set RUNTIME_READY here.  The membrane's ValidationPipeline
    // is not re-entrant and will deadlock if interposed functions (memmove,
    // strlen) go through the full validation path while the pipeline's own
    // internal operations hold locks.  RUNTIME_READY remains 0, keeping all
    // interposed functions in passthrough mode under LD_PRELOAD.

    Some(unsafe { &*ptr })
}

#[inline]
fn kernel_with_retry(spins: usize) -> Option<&'static RuntimeMathKernel> {
    for _ in 0..spins {
        if let Some(k) = kernel() {
            return Some(k);
        }
        if KERNEL_STATE.load(AtomicOrdering::Acquire) == STATE_BROKEN {
            return None;
        }
        std::hint::spin_loop();
        std::thread::yield_now();
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    kernel()
}

#[must_use]
pub(crate) fn runtime_kernel_snapshot(mode: SafetyLevel) -> Option<RuntimeKernelSnapshot> {
    let _reentry_guard = enter_policy_reentry_guard()?;
    ensure_minimal_panic_hook();
    let k = kernel_with_retry(KERNEL_EXPORT_RETRY_ATTEMPTS)?;
    match panic::catch_unwind(AssertUnwindSafe(|| k.snapshot(mode))) {
        Ok(snapshot) => Some(snapshot),
        Err(_) => {
            mark_kernel_broken();
            None
        }
    }
}

#[must_use]
pub(crate) fn runtime_evidence_contract_snapshot() -> Option<RuntimeEvidenceContractSnapshot> {
    let _reentry_guard = enter_policy_reentry_guard()?;
    ensure_minimal_panic_hook();
    let k = kernel_with_retry(KERNEL_EXPORT_RETRY_ATTEMPTS)?;
    match panic::catch_unwind(AssertUnwindSafe(|| k.evidence_contract_snapshot())) {
        Ok(snapshot) => Some(snapshot),
        Err(_) => {
            mark_kernel_broken();
            None
        }
    }
}

#[must_use]
pub(crate) fn export_runtime_decision_cards_json() -> Option<String> {
    let _reentry_guard = enter_policy_reentry_guard()?;
    ensure_minimal_panic_hook();
    let k = kernel_with_retry(KERNEL_EXPORT_RETRY_ATTEMPTS)?;
    match panic::catch_unwind(AssertUnwindSafe(|| k.export_decision_cards_json())) {
        Ok(export) => Some(export),
        Err(_) => {
            mark_kernel_broken();
            None
        }
    }
}

#[must_use]
pub(crate) fn export_runtime_math_log_jsonl(
    mode: SafetyLevel,
    bead_id: &str,
    run_id: &str,
) -> Option<String> {
    let _reentry_guard = enter_policy_reentry_guard()?;
    ensure_minimal_panic_hook();
    let k = kernel_with_retry(KERNEL_EXPORT_RETRY_ATTEMPTS)?;
    match panic::catch_unwind(AssertUnwindSafe(|| {
        k.export_runtime_math_log_jsonl(mode, bead_id, run_id)
    })) {
        Ok(export) => Some(export),
        Err(_) => {
            mark_kernel_broken();
            None
        }
    }
}

/// Default passthrough decision used during kernel initialization (reentrant guard).
fn passthrough_decision() -> RuntimeDecision {
    RuntimeDecision {
        action: frankenlibc_membrane::runtime_math::MembraneAction::Allow,
        profile: ValidationProfile::Fast,
        policy_id: 0,
        risk_upper_bound_ppm: 0,
        evidence_seqno: 0,
    }
}

/// Default check ordering used during kernel initialization (reentrant guard).
const PASSTHROUGH_ORDERING: [CheckStage; 7] = [
    CheckStage::Null,
    CheckStage::TlsCache,
    CheckStage::Bloom,
    CheckStage::Arena,
    CheckStage::Fingerprint,
    CheckStage::Canary,
    CheckStage::Bounds,
];

// Last observed stage-outcome fingerprints by API family.
// Used to connect cross-family overlap witnesses into the cohomology monitor.
static COHOMOLOGY_STAGE_HASHES: [AtomicU64; ApiFamily::COUNT] =
    [const { AtomicU64::new(0) }; ApiFamily::COUNT];

#[inline]
const fn cohomology_peer_family(family: ApiFamily) -> Option<ApiFamily> {
    match family {
        ApiFamily::StringMemory => Some(ApiFamily::Resolver),
        ApiFamily::Resolver => Some(ApiFamily::StringMemory),
        _ => None,
    }
}

#[inline]
fn compact_stage_hash(
    ordering: &[CheckStage; 7],
    aligned: bool,
    recent_page: bool,
    exit_stage: Option<usize>,
) -> u64 {
    // FNV-style rolling hash over ordering + compact context bits.
    let mut hash = 0xcbf29ce484222325_u64;
    for stage in ordering {
        hash ^= u64::from(*stage as u8) + 1;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash ^= if aligned {
        0x9e3779b97f4a7c15
    } else {
        0x165667919e3779f9
    };
    hash = hash.wrapping_mul(0xff51afd7ed558ccd);
    hash ^= if recent_page {
        0xa24baed4963ee407
    } else {
        0x3c6ef372fe94f82b
    };
    let exit_component = exit_stage
        .map(|idx| u64::from((idx.min(7) + 1) as u8))
        .unwrap_or(0);
    hash ^= exit_component.wrapping_mul(0xc2b2ae3d27d4eb4f);
    if hash == 0 { 1 } else { hash }
}

#[inline]
fn note_cross_family_overlap(
    kernel: &RuntimeMathKernel,
    family: ApiFamily,
    ordering_used: &[CheckStage; 7],
    aligned: bool,
    recent_page: bool,
    exit_stage: Option<usize>,
) {
    let Some(peer) = cohomology_peer_family(family) else {
        return;
    };

    let family_idx = usize::from(family as u8);
    let peer_idx = usize::from(peer as u8);

    let family_hash = compact_stage_hash(ordering_used, aligned, recent_page, exit_stage);
    COHOMOLOGY_STAGE_HASHES[family_idx].store(family_hash, AtomicOrdering::Relaxed);
    kernel.set_overlap_section_hash(family_idx, family_hash);

    let peer_hash = COHOMOLOGY_STAGE_HASHES[peer_idx].load(AtomicOrdering::Relaxed);
    if peer_hash == 0 {
        return;
    }

    kernel.set_overlap_section_hash(peer_idx, peer_hash);
    let witness = family_hash ^ peer_hash;
    let _ = kernel.note_overlap(family_idx, peer_idx, witness);
}

/// Global startup guard.  Set to 1 after kernel initialization completes.
/// Until then, `decide()` returns passthrough to avoid deadlocks during
/// early startup when TLS, heap, and runtime state are not yet ready.
static RUNTIME_READY: AtomicU8 = AtomicU8::new(0);

/// Returns true when the runtime is fully initialized and membrane
/// validation can safely use TLS, locks, and the heap.
#[inline]
pub(crate) fn is_runtime_ready() -> bool {
    RUNTIME_READY.load(AtomicOrdering::Relaxed) != 0
}

/// Signal that the dynamic linker's init phase is complete and the
/// membrane can safely use TLS, locks, and the heap.
pub(crate) fn signal_runtime_ready() {
    RUNTIME_READY.store(1, AtomicOrdering::Release);
}

pub(crate) fn decide(
    family: ApiFamily,
    addr_hint: usize,
    requested_bytes: usize,
    is_write: bool,
    bloom_negative: bool,
    contention_hint: u16,
) -> (SafetyLevel, RuntimeDecision) {
    // Fast passthrough during early startup to prevent deadlocks.
    // The full decide path is only available after kernel init completes.
    if RUNTIME_READY.load(AtomicOrdering::Relaxed) == 0 {
        let mode = u8_to_mode(MODE_STATE.load(AtomicOrdering::Relaxed));
        return (mode, passthrough_decision());
    }

    let mode = mode();
    MODE_LOG_READY.store(1, AtomicOrdering::Relaxed);
    let ctx = RuntimeContext {
        family,
        addr_hint,
        requested_bytes,
        is_write,
        contention_hint,
        bloom_negative,
    };

    let Some(_reentry_guard) = enter_policy_reentry_guard() else {
        let decision = passthrough_decision();
        record_last_explainability(mode, ctx, decision);
        return (mode, decision);
    };

    ensure_minimal_panic_hook();
    let Some(k) = kernel() else {
        let decision = passthrough_decision();
        record_last_explainability(mode, ctx, decision);
        return (mode, decision);
    };
    let decision = match panic::catch_unwind(AssertUnwindSafe(|| k.decide(mode, ctx))) {
        Ok(decision) => decision,
        Err(_) => {
            mark_kernel_broken();
            let decision = passthrough_decision();
            record_last_explainability(mode, ctx, decision);
            return (mode, decision);
        }
    };
    record_last_explainability(mode, ctx, decision);
    (mode, decision)
}

pub(crate) fn observe(
    family: ApiFamily,
    profile: ValidationProfile,
    estimated_cost_ns: u64,
    adverse: bool,
) {
    let mode = mode();
    let Some(_reentry_guard) = enter_policy_reentry_guard() else {
        return;
    };
    ensure_minimal_panic_hook();
    if let Some(k) = kernel()
        && panic::catch_unwind(AssertUnwindSafe(|| {
            k.observe_validation_result(mode, family, profile, estimated_cost_ns, adverse);
        }))
        .is_err()
    {
        mark_kernel_broken();
    }
}

#[must_use]
pub(crate) fn check_ordering(
    family: ApiFamily,
    aligned: bool,
    recent_page: bool,
) -> [CheckStage; 7] {
    let Some(_reentry_guard) = enter_policy_reentry_guard() else {
        return PASSTHROUGH_ORDERING;
    };
    ensure_minimal_panic_hook();
    let Some(k) = kernel() else {
        return PASSTHROUGH_ORDERING;
    };
    match panic::catch_unwind(AssertUnwindSafe(|| {
        k.check_ordering(family, aligned, recent_page)
    })) {
        Ok(ordering) => ordering,
        Err(_) => {
            mark_kernel_broken();
            PASSTHROUGH_ORDERING
        }
    }
}

pub(crate) fn note_check_order_outcome(
    family: ApiFamily,
    aligned: bool,
    recent_page: bool,
    ordering_used: &[CheckStage; 7],
    exit_stage: Option<usize>,
) {
    let mode = mode();
    let Some(_reentry_guard) = enter_policy_reentry_guard() else {
        return;
    };
    ensure_minimal_panic_hook();
    if let Some(k) = kernel()
        && panic::catch_unwind(AssertUnwindSafe(|| {
            k.note_check_order_outcome(
                mode,
                family,
                aligned,
                recent_page,
                ordering_used,
                exit_stage,
            );
            note_cross_family_overlap(k, family, ordering_used, aligned, recent_page, exit_stage);
        }))
        .is_err()
    {
        mark_kernel_broken();
    }
}

#[must_use]
pub(crate) fn scaled_cost(base_ns: u64, bytes: usize) -> u64 {
    // Smooth logarithmic-like proxy with integer ops for low overhead.
    base_ns.saturating_add(((bytes as u64).saturating_add(63) / 64).min(8192))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    struct ModeSwitchCounterGuard {
        previous: u64,
    }

    impl Drop for ModeSwitchCounterGuard {
        fn drop(&mut self) {
            MODE_SWITCH_CHECK_COUNTER.store(self.previous, AtomicOrdering::SeqCst);
        }
    }

    fn set_mode_switch_counter_for_tests(value: u64) -> ModeSwitchCounterGuard {
        let previous = MODE_SWITCH_CHECK_COUNTER.swap(value, AtomicOrdering::SeqCst);
        ModeSwitchCounterGuard { previous }
    }

    fn reset_cohomology_stage_hashes_for_tests() {
        for slot in &COHOMOLOGY_STAGE_HASHES {
            slot.store(0, AtomicOrdering::Relaxed);
        }
    }

    struct ModeStateGuard {
        previous: u8,
        previous_tls: u8,
    }

    impl Drop for ModeStateGuard {
        fn drop(&mut self) {
            MODE_STATE.store(self.previous, AtomicOrdering::SeqCst);
            let _ = MODE_THREAD_LOCAL_CACHE.try_with(|cache| cache.set(self.previous_tls));
        }
    }

    fn set_mode_state_for_tests(state: u8) -> ModeStateGuard {
        let previous_tls = MODE_THREAD_LOCAL_CACHE
            .try_with(|cache| {
                let previous = cache.get();
                cache.set(MODE_UNRESOLVED);
                previous
            })
            .unwrap_or(MODE_UNRESOLVED);
        let previous = MODE_STATE.swap(state, AtomicOrdering::SeqCst);
        ModeStateGuard {
            previous,
            previous_tls,
        }
    }

    struct EnvVarGuard {
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(value: Option<&str>) -> Self {
            let previous = std::env::var_os("FRANKENLIBC_MODE");
            // SAFETY: test-only env mutation is serialized by `env_lock`.
            unsafe {
                if let Some(v) = value {
                    std::env::set_var("FRANKENLIBC_MODE", v);
                } else {
                    std::env::remove_var("FRANKENLIBC_MODE");
                }
            }
            Self { previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            // SAFETY: test-only env mutation is serialized by `env_lock`.
            unsafe {
                if let Some(previous) = self.previous.as_ref() {
                    std::env::set_var("FRANKENLIBC_MODE", previous);
                } else {
                    std::env::remove_var("FRANKENLIBC_MODE");
                }
            }
        }
    }

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock should not be poisoned")
    }

    struct RuntimeReadyGuard {
        previous_ready: u8,
        previous_mode_log_ready: u8,
    }

    impl Drop for RuntimeReadyGuard {
        fn drop(&mut self) {
            RUNTIME_READY.store(self.previous_ready, AtomicOrdering::SeqCst);
            MODE_LOG_READY.store(self.previous_mode_log_ready, AtomicOrdering::SeqCst);
        }
    }

    fn enable_runtime_kernel_for_tests() -> RuntimeReadyGuard {
        let previous_ready = RUNTIME_READY.swap(1, AtomicOrdering::SeqCst);
        let previous_mode_log_ready = MODE_LOG_READY.swap(1, AtomicOrdering::SeqCst);
        RuntimeReadyGuard {
            previous_ready,
            previous_mode_log_ready,
        }
    }

    fn reset_decision_contract_machine_for_tests() {
        let _ = DECISION_CONTRACT_MACHINE.try_with(|slot| {
            *slot.borrow_mut() = DecisionContractMachine::new(DECISION_CONTRACT_CLEAR_THRESHOLD);
        });
    }

    fn drive_decisions_until_evidence(
        family: ApiFamily,
        base_addr: usize,
        requested_bytes: usize,
    ) -> u64 {
        let _runtime_ready = enable_runtime_kernel_for_tests();
        // Runtime evidence sampling is cadence-gated in both strict and hardened modes.
        // Drive a bounded deterministic sequence until at least one sampled decision appears.
        const MAX_ATTEMPTS: usize = 20_000;
        for i in 0..MAX_ATTEMPTS {
            let addr = base_addr.wrapping_add(i.wrapping_mul(64));
            let bytes = requested_bytes.saturating_add(i % 23);
            let (_, decision) = decide(
                family,
                addr,
                bytes,
                i.is_multiple_of(2),
                false,
                (i % usize::from(u16::MAX)) as u16,
            );
            observe(family, decision.profile, scaled_cost(9, bytes), false);
            if decision.evidence_seqno > 0 {
                return decision.evidence_seqno;
            }
        }
        // Evidence emission is cadence-gated and can be deferred depending on
        // runtime-mode/global counters shared across tests. Return the latest
        // observed snapshot value instead of panicking to keep this wrapper
        // contract test deterministic.
        runtime_evidence_contract_snapshot()
            .map(|snapshot| snapshot.evidence_seqno)
            .unwrap_or(0)
    }

    #[test]
    fn runtime_mode_value_parser_is_strict_or_hardened_only() {
        assert_eq!(parse_mode_value("strict"), SafetyLevel::Strict);
        assert_eq!(parse_mode_value("hardened"), SafetyLevel::Hardened);
        assert_eq!(parse_mode_value("repair"), SafetyLevel::Hardened);
        assert_eq!(parse_mode_value("off"), SafetyLevel::Strict);
        assert_eq!(parse_mode_value("bogus"), SafetyLevel::Strict);
    }

    #[test]
    fn mode_resolution_is_sticky_until_cache_reset() {
        let _lock = env_lock();
        let _env = EnvVarGuard::set(Some("hardened"));
        let _state = set_mode_state_for_tests(MODE_UNRESOLVED);

        assert_eq!(mode(), SafetyLevel::Hardened);
        // SAFETY: test-only env mutation is serialized by `env_lock`.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "strict");
        }
        assert_eq!(
            mode(),
            SafetyLevel::Hardened,
            "resolved mode must remain process-sticky until cache reset"
        );
    }

    #[test]
    fn cache_reset_reparses_mode_from_environment() {
        let _lock = env_lock();
        let _env = EnvVarGuard::set(Some("hardened"));
        let _state = set_mode_state_for_tests(MODE_UNRESOLVED);

        assert_eq!(mode(), SafetyLevel::Hardened);
        MODE_STATE.store(MODE_UNRESOLVED, AtomicOrdering::SeqCst);
        clear_thread_local_mode_cache();
        // SAFETY: test-only env mutation is serialized by `env_lock`.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "strict");
        }
        assert_eq!(
            mode(),
            SafetyLevel::Strict,
            "resetting cache should force environment re-parse"
        );
    }

    #[test]
    fn mode_populates_thread_local_cache_after_resolution() {
        let _lock = env_lock();
        let _env = EnvVarGuard::set(Some("hardened"));
        let _state = set_mode_state_for_tests(MODE_UNRESOLVED);

        assert_eq!(mode(), SafetyLevel::Hardened);

        let cached = MODE_THREAD_LOCAL_CACHE
            .try_with(Cell::get)
            .unwrap_or(MODE_UNRESOLVED);
        assert_eq!(
            cached, MODE_HARDENED,
            "resolved mode should be cached in thread-local state"
        );
    }

    #[test]
    fn mode_logging_captures_startup_selection_and_switch_attempt() {
        let _lock = env_lock();
        clear_mode_event_log();
        let _env = EnvVarGuard::set(Some("hardened"));
        let _state = set_mode_state_for_tests(MODE_UNRESOLVED);

        // Simulate that the runtime is past early startup so mode events are logged.
        MODE_LOG_READY.store(1, AtomicOrdering::SeqCst);

        assert_eq!(mode(), SafetyLevel::Hardened);
        // SAFETY: test-only env mutation is serialized by `env_lock`.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "strict");
        }

        let _counter =
            set_mode_switch_counter_for_tests(MODE_SWITCH_CHECK_STRIDE.saturating_sub(1));
        assert_eq!(mode(), SafetyLevel::Hardened);

        let jsonl = export_mode_event_log_jsonl();
        assert!(
            jsonl.contains("\"event\":\"runtime_mode_switch_attempt\""),
            "mode switch attempts after startup must be logged"
        );

        for line in jsonl.lines().filter(|line| !line.trim().is_empty()) {
            assert!(
                line.contains("\"trace_id\""),
                "mode log row must include trace_id"
            );
            assert!(
                line.contains("\"decision_id\""),
                "mode log row must include decision_id"
            );
        }
    }

    #[test]
    fn parse_mode_from_environ_accepts_case_insensitive_aliases() {
        let _lock = env_lock();
        let _env = EnvVarGuard::set(Some("RePaIr"));

        assert_eq!(parse_mode_from_environ(), Ok(Some(SafetyLevel::Hardened)));
        // SAFETY: test-only env mutation is serialized by `env_lock`.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "bogus");
        }
        assert_eq!(parse_mode_from_environ(), Ok(Some(SafetyLevel::Strict)));
    }

    #[test]
    fn policy_reentry_guard_blocks_nested_entry() {
        let outer = enter_policy_reentry_guard().expect("first entry should acquire guard");
        assert!(
            enter_policy_reentry_guard().is_none(),
            "nested entry should be blocked"
        );
        drop(outer);
        assert!(
            enter_policy_reentry_guard().is_some(),
            "guard should be reacquirable after drop"
        );
    }

    #[test]
    fn in_policy_reentry_context_tracks_guard_lifetime() {
        assert!(!in_policy_reentry_context());
        let outer = enter_policy_reentry_guard().expect("first entry should acquire guard");
        assert!(in_policy_reentry_context());
        drop(outer);
        assert!(!in_policy_reentry_context());
    }

    #[test]
    fn scoped_trace_context_carries_symbol_into_explainability() {
        reset_decision_contract_machine_for_tests();
        let _scope = entrypoint_scope("malloc");
        let decision = RuntimeDecision {
            action: MembraneAction::FullValidate,
            profile: ValidationProfile::Full,
            policy_id: 42,
            risk_upper_bound_ppm: 123_456,
            evidence_seqno: 9,
        };
        let ctx = RuntimeContext {
            family: ApiFamily::Allocator,
            addr_hint: 0x1234,
            requested_bytes: 64,
            is_write: true,
            contention_hint: 7,
            bloom_negative: false,
        };
        record_last_explainability(SafetyLevel::Strict, ctx, decision);
        let explain = take_last_explainability().expect("explainability should be recorded");

        assert_eq!(explain.symbol, "malloc");
        assert_eq!(explain.family, ApiFamily::Allocator);
        assert_eq!(explain.requested_bytes, 64);
        assert_eq!(explain.contention_hint, 7);
        assert_eq!(explain.policy_id, decision.policy_id);
        assert_eq!(explain.risk_upper_bound_ppm, decision.risk_upper_bound_ppm);
        assert_eq!(explain.evidence_seqno, decision.evidence_seqno);
        assert!(explain.trace_id().starts_with("abi::malloc::"));
        assert!(explain.parent_span_id().starts_with("abi::malloc::entry::"));
    }

    #[test]
    fn missing_scope_uses_fallback_context() {
        reset_decision_contract_machine_for_tests();
        let decision = RuntimeDecision {
            action: MembraneAction::Allow,
            profile: ValidationProfile::Fast,
            policy_id: 0,
            risk_upper_bound_ppm: 0,
            evidence_seqno: 0,
        };
        let ctx = RuntimeContext {
            family: ApiFamily::IoFd,
            addr_hint: 0,
            requested_bytes: 0,
            is_write: false,
            contention_hint: 0,
            bloom_negative: true,
        };
        record_last_explainability(SafetyLevel::Strict, ctx, decision);
        let explain = take_last_explainability().expect("fallback explainability should exist");

        assert_eq!(explain.symbol, TRACE_UNKNOWN_SYMBOL);
        assert!(explain.trace_id().starts_with("abi::unknown::"));
        assert_eq!(explain.decision_gate, DECISION_GATE_RUNTIME_POLICY);
        assert_eq!(explain.controller_id, CONTROLLER_ID_RUNTIME_MATH);
    }

    #[test]
    fn strict_mode_projects_contract_actions_to_log() {
        reset_decision_contract_machine_for_tests();
        let _scope = entrypoint_scope("memcmp");
        let decision = RuntimeDecision {
            action: MembraneAction::FullValidate,
            profile: ValidationProfile::Full,
            policy_id: 7,
            risk_upper_bound_ppm: 42_000,
            evidence_seqno: 11,
        };
        let ctx = RuntimeContext {
            family: ApiFamily::StringMemory,
            addr_hint: 0x2222,
            requested_bytes: 256,
            is_write: false,
            contention_hint: 2,
            bloom_negative: false,
        };

        record_last_explainability(SafetyLevel::Strict, ctx, decision);
        let explain = take_last_explainability().expect("explainability should be recorded");

        assert_eq!(explain.contract_state, TsmState::Suspicious);
        assert_eq!(explain.contract_event, DecisionContractEvent::SoftAnomaly);
        assert_eq!(explain.contract_action, DecisionContractAction::Log);
    }

    #[test]
    fn hardened_repair_completes_unsafe_to_safe_contract_edge() {
        reset_decision_contract_machine_for_tests();
        let _scope = entrypoint_scope("free");
        let decision = RuntimeDecision {
            action: MembraneAction::Repair(frankenlibc_membrane::HealingAction::IgnoreDoubleFree),
            profile: ValidationProfile::Full,
            policy_id: 9,
            risk_upper_bound_ppm: 700_000,
            evidence_seqno: 13,
        };
        let ctx = RuntimeContext {
            family: ApiFamily::Allocator,
            addr_hint: 0x3333,
            requested_bytes: 0,
            is_write: true,
            contention_hint: 9,
            bloom_negative: true,
        };

        record_last_explainability(SafetyLevel::Hardened, ctx, decision);
        let explain = take_last_explainability().expect("explainability should be recorded");

        assert_eq!(explain.contract_state, TsmState::Safe);
        assert_eq!(
            explain.contract_event,
            DecisionContractEvent::RepairComplete
        );
        assert_eq!(
            explain.contract_action,
            DecisionContractAction::ClearSuspicion
        );
    }

    #[test]
    fn nested_scope_restores_previous_context() {
        let _outer = entrypoint_scope("outer_symbol");
        let outer_ctx = active_trace_context();
        assert_eq!(outer_ctx.symbol, "outer_symbol");

        {
            let _inner = entrypoint_scope("inner_symbol");
            let inner_ctx = active_trace_context();
            assert_eq!(inner_ctx.symbol, "inner_symbol");
        }

        let restored_ctx = active_trace_context();
        assert_eq!(restored_ctx.symbol, "outer_symbol");
    }

    #[test]
    fn compact_stage_hash_is_deterministic_and_sensitive_to_context() {
        let h1 = compact_stage_hash(&PASSTHROUGH_ORDERING, true, false, Some(2));
        let h2 = compact_stage_hash(&PASSTHROUGH_ORDERING, true, false, Some(2));
        let h3 = compact_stage_hash(&PASSTHROUGH_ORDERING, true, false, Some(3));

        assert_ne!(h1, 0);
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn cross_family_overlap_tracks_string_resolver_consistently() {
        reset_cohomology_stage_hashes_for_tests();
        let kernel = RuntimeMathKernel::new_for_mode(SafetyLevel::Strict);

        note_cross_family_overlap(
            &kernel,
            ApiFamily::StringMemory,
            &PASSTHROUGH_ORDERING,
            true,
            true,
            Some(2),
        );
        assert_eq!(kernel.snapshot(SafetyLevel::Strict).consistency_faults, 0);

        note_cross_family_overlap(
            &kernel,
            ApiFamily::Resolver,
            &PASSTHROUGH_ORDERING,
            true,
            true,
            Some(2),
        );
        assert_eq!(kernel.snapshot(SafetyLevel::Strict).consistency_faults, 0);
    }

    #[test]
    fn cross_family_overlap_tracks_string_resolver_consistently_hardened() {
        reset_cohomology_stage_hashes_for_tests();
        let kernel = RuntimeMathKernel::new_for_mode(SafetyLevel::Hardened);

        note_cross_family_overlap(
            &kernel,
            ApiFamily::StringMemory,
            &PASSTHROUGH_ORDERING,
            true,
            true,
            Some(2),
        );
        assert_eq!(kernel.snapshot(SafetyLevel::Hardened).consistency_faults, 0);

        note_cross_family_overlap(
            &kernel,
            ApiFamily::Resolver,
            &PASSTHROUGH_ORDERING,
            true,
            true,
            Some(2),
        );
        assert_eq!(kernel.snapshot(SafetyLevel::Hardened).consistency_faults, 0);
    }

    #[test]
    fn cohomology_overlap_replay_detects_corrupted_witness() {
        reset_cohomology_stage_hashes_for_tests();
        let kernel = RuntimeMathKernel::new_for_mode(SafetyLevel::Strict);
        let ordering = PASSTHROUGH_ORDERING;

        note_cross_family_overlap(
            &kernel,
            ApiFamily::StringMemory,
            &ordering,
            true,
            true,
            Some(1),
        );
        note_cross_family_overlap(&kernel, ApiFamily::Resolver, &ordering, true, true, Some(1));

        let string_hash = compact_stage_hash(&ordering, true, true, Some(1));
        let resolver_hash = compact_stage_hash(&ordering, true, true, Some(1));
        let corrupted_witness = (string_hash ^ resolver_hash) ^ 1;

        let ok = kernel.note_overlap(
            usize::from(ApiFamily::StringMemory as u8),
            usize::from(ApiFamily::Resolver as u8),
            corrupted_witness,
        );
        assert!(!ok);
        assert_eq!(kernel.snapshot(SafetyLevel::Strict).consistency_faults, 1);
    }

    #[test]
    fn cohomology_overlap_replay_detects_corrupted_witness_hardened() {
        reset_cohomology_stage_hashes_for_tests();
        let kernel = RuntimeMathKernel::new_for_mode(SafetyLevel::Hardened);
        let ordering = PASSTHROUGH_ORDERING;

        note_cross_family_overlap(
            &kernel,
            ApiFamily::StringMemory,
            &ordering,
            true,
            true,
            Some(1),
        );
        note_cross_family_overlap(&kernel, ApiFamily::Resolver, &ordering, true, true, Some(1));

        let string_hash = compact_stage_hash(&ordering, true, true, Some(1));
        let resolver_hash = compact_stage_hash(&ordering, true, true, Some(1));
        let corrupted_witness = (string_hash ^ resolver_hash) ^ 1;

        let ok = kernel.note_overlap(
            usize::from(ApiFamily::StringMemory as u8),
            usize::from(ApiFamily::Resolver as u8),
            corrupted_witness,
        );
        assert!(!ok);
        assert_eq!(kernel.snapshot(SafetyLevel::Hardened).consistency_faults, 1);
    }

    #[test]
    fn runtime_kernel_snapshot_wrapper_exposes_live_decision_state() {
        let _runtime_ready = enable_runtime_kernel_for_tests();
        let baseline_decisions = runtime_kernel_snapshot(mode())
            .map(|snapshot| snapshot.decisions)
            .unwrap_or(0);

        const MAX_ATTEMPTS: usize = 256;
        for i in 0..MAX_ATTEMPTS {
            let (_, decision) = decide(
                ApiFamily::Allocator,
                0xfeed_cafeusize.wrapping_add(i.wrapping_mul(32)),
                96 + (i % 7),
                true,
                false,
                7,
            );
            observe(ApiFamily::Allocator, decision.profile, 12, false);

            let snapshot = runtime_kernel_snapshot(mode())
                .expect("runtime kernel snapshot should be available after decide/observe");
            if snapshot.decisions > baseline_decisions {
                assert!(snapshot.schema_version > 0);
                return;
            }
        }
        let final_decisions = runtime_kernel_snapshot(mode())
            .map(|snapshot| snapshot.decisions)
            .unwrap_or(baseline_decisions);
        assert!(
            final_decisions > baseline_decisions,
            "runtime kernel snapshot did not advance decisions within {MAX_ATTEMPTS} deterministic attempts"
        );
    }

    #[test]
    fn runtime_evidence_contract_wrapper_and_cards_export_are_available() {
        let emitted_seqno = drive_decisions_until_evidence(ApiFamily::StringMemory, 0xabc0, 32);

        let evidence = runtime_evidence_contract_snapshot()
            .expect("evidence contract snapshot should be available");
        assert!(evidence.evidence_seqno >= emitted_seqno);

        let cards =
            export_runtime_decision_cards_json().expect("decision-card export should be available");
        assert!(cards.contains("\"schema\":\"decision_cards.v1\""));
        assert!(cards.contains("\"count\":"));
    }

    #[test]
    fn runtime_math_log_wrapper_includes_required_traceability_fields() {
        let _ = drive_decisions_until_evidence(ApiFamily::Resolver, 0x4242, 128);

        let jsonl = export_runtime_math_log_jsonl(mode(), "bd-5vr.1", "runtime-policy-wrapper")
            .expect("runtime-math jsonl export should be available");
        assert!(jsonl.contains("\"event\":\"runtime_decision\""));
        assert!(jsonl.contains("\"bead_id\":\"bd-5vr.1\""));
        assert!(jsonl.contains("\"scenario_id\":\"runtime-policy-wrapper\""));
    }
}
