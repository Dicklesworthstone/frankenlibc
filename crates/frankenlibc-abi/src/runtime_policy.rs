//! Runtime policy bridge for ABI entrypoints.
//!
//! This module centralizes access to the membrane RuntimeMathKernel so ABI
//! functions can cheaply obtain per-call decisions and publish observations
//! without duplicating orchestration code.

#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::ffi::c_char;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicPtr, AtomicU8, AtomicU32, Ordering as AtomicOrdering};

use frankenlibc_core::syscall;
use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::config::SafetyLevel;
use frankenlibc_membrane::decision_contract::{
    DecisionAction as DecisionContractAction, DecisionContractMachine,
    DecisionEvent as DecisionContractEvent, TsmState,
};
use frankenlibc_membrane::runtime_math::{
    ApiFamily, MembraneAction, RuntimeContext, RuntimeDecision, RuntimeMathKernel,
    ValidationProfile,
};

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

fn parse_mode_from_environ() -> Option<SafetyLevel> {
    const KEY_EQ: &[u8] = b"FRANKENLIBC_MODE=";
    const MAX_SCAN: usize = 4096;

    // SAFETY: process-owned env pointer table, expected to be NUL-terminated.
    let mut envp = unsafe { environ };
    if envp.is_null() {
        return None;
    }

    for _ in 0..MAX_SCAN {
        // SAFETY: envp points to a readable pointer slot in env vector.
        let entry = unsafe { *envp };
        if entry.is_null() {
            return None;
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
                return Some(SafetyLevel::Hardened);
            }
            // Unrecognized values fall back to strict by contract.
            return Some(SafetyLevel::Strict);
        }

        // SAFETY: advance to next env vector slot.
        envp = unsafe { envp.add(1) };
    }

    None
}

#[must_use]
pub(crate) fn mode() -> SafetyLevel {
    let cached = MODE_STATE.load(AtomicOrdering::Relaxed);

    if cached != MODE_UNRESOLVED && cached != MODE_RESOLVING {
        return u8_to_mode(cached);
    }

    if cached == MODE_RESOLVING {
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
            u8_to_mode(v)
        } else {
            SafetyLevel::Strict
        };
    }

    let resolved = parse_mode_from_environ().unwrap_or(SafetyLevel::Strict);
    MODE_STATE.store(mode_to_u8(resolved), AtomicOrdering::Release);
    resolved
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
            let _ =
                unsafe { syscall::sys_write(libc::STDERR_FILENO, PREFIX.as_ptr(), PREFIX.len()) };
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
                let _ = unsafe { syscall::sys_write(libc::STDERR_FILENO, b"unknown".as_ptr(), 7) };
            }
            let _ = unsafe { syscall::sys_write(libc::STDERR_FILENO, b"\n".as_ptr(), 1) };
        }
        PANIC_HOOK_WRITE_STATE.store(PANIC_HOOK_WRITE_IDLE, AtomicOrdering::Release);
    }));
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

    Some(unsafe { &*ptr })
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

pub(crate) fn decide(
    family: ApiFamily,
    addr_hint: usize,
    requested_bytes: usize,
    is_write: bool,
    bloom_negative: bool,
    contention_hint: u16,
) -> (SafetyLevel, RuntimeDecision) {
    let mode = mode();
    let ctx = RuntimeContext {
        family,
        addr_hint,
        requested_bytes,
        is_write,
        contention_hint,
        bloom_negative,
    };

    // Scoped mitigation: allocator/string families currently run in passthrough
    // policy mode under LD_PRELOAD to prevent recursive runtime-kernel lock
    // paths during hot bootstrap operations.
    if matches!(
        family,
        ApiFamily::Allocator | ApiFamily::StringMemory | ApiFamily::Stdio | ApiFamily::Threading
    ) {
        let decision = passthrough_decision();
        record_last_explainability(mode, ctx, decision);
        return (mode, decision);
    }

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
    // Temporary preload safety mitigation: runtime-math feedback updates can
    // recurse into allocator/lock paths and deadlock under heavy interposition.
    // Keep decision path active, but suppress observe-side state mutation.
    let _ = (family, profile, estimated_cost_ns, adverse);
}

#[must_use]
pub(crate) fn check_ordering(
    family: ApiFamily,
    aligned: bool,
    recent_page: bool,
) -> [CheckStage; 7] {
    if matches!(
        family,
        ApiFamily::Allocator | ApiFamily::StringMemory | ApiFamily::Stdio | ApiFamily::Threading
    ) {
        return PASSTHROUGH_ORDERING;
    }
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
    if matches!(
        family,
        ApiFamily::Allocator | ApiFamily::StringMemory | ApiFamily::Stdio | ApiFamily::Threading
    ) {
        return;
    }
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

    struct ModeStateGuard {
        previous: u8,
    }

    impl Drop for ModeStateGuard {
        fn drop(&mut self) {
            MODE_STATE.store(self.previous, AtomicOrdering::SeqCst);
        }
    }

    fn set_mode_state_for_tests(state: u8) -> ModeStateGuard {
        let previous = MODE_STATE.swap(state, AtomicOrdering::SeqCst);
        ModeStateGuard { previous }
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

    fn reset_decision_contract_machine_for_tests() {
        let _ = DECISION_CONTRACT_MACHINE.try_with(|slot| {
            *slot.borrow_mut() = DecisionContractMachine::new(DECISION_CONTRACT_CLEAR_THRESHOLD);
        });
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
    fn parse_mode_from_environ_accepts_case_insensitive_aliases() {
        let _lock = env_lock();
        let _env = EnvVarGuard::set(Some("RePaIr"));

        assert_eq!(parse_mode_from_environ(), Some(SafetyLevel::Hardened));
        // SAFETY: test-only env mutation is serialized by `env_lock`.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "bogus");
        }
        assert_eq!(parse_mode_from_environ(), Some(SafetyLevel::Strict));
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
}
