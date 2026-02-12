//! Runtime policy bridge for ABI entrypoints.
//!
//! This module centralizes access to the membrane RuntimeMathKernel so ABI
//! functions can cheaply obtain per-call decisions and publish observations
//! without duplicating orchestration code.

#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicPtr, AtomicU8, Ordering as AtomicOrdering};

use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::config::{SafetyLevel, safety_level};
use frankenlibc_membrane::runtime_math::{
    ApiFamily, MembraneAction, RuntimeContext, RuntimeDecision, RuntimeMathKernel,
    ValidationProfile,
};

// Kernel lifecycle states.
const STATE_UNINIT: u8 = 0;
const STATE_INITIALIZING: u8 = 1;
const STATE_READY: u8 = 2;
const TRACE_UNKNOWN_SYMBOL: &str = "unknown";
const CONTROLLER_ID_RUNTIME_MATH: &str = "runtime_math_kernel.v1";
const DECISION_GATE_RUNTIME_POLICY: &str = "runtime_policy.decide";

// Manual init guard that avoids OnceLock's internal futex.
// OnceLock::get_or_init uses a futex wait when it sees init-in-progress,
// which causes deadlock if a reentrant call from the same thread arrives
// during RuntimeMathKernel::new(). Instead, we use a simple atomic state
// machine: UNINIT -> INITIALIZING -> READY, and any reentrant call that
// sees INITIALIZING returns None (passthrough).
static KERNEL_STATE: AtomicU8 = AtomicU8::new(STATE_UNINIT);
static KERNEL_PTR: AtomicPtr<RuntimeMathKernel> = AtomicPtr::new(std::ptr::null_mut());

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
}

pub(crate) struct EntrypointTraceGuard {
    previous: Option<TraceContext>,
}

impl Drop for EntrypointTraceGuard {
    fn drop(&mut self) {
        TRACE_CONTEXT.with(|slot| slot.set(self.previous));
    }
}

#[must_use]
pub(crate) fn entrypoint_scope(symbol: &'static str) -> EntrypointTraceGuard {
    let trace_seq = TRACE_COUNTER.with(|counter| {
        let next = counter.get().wrapping_add(1);
        counter.set(next);
        next
    });

    let context = TraceContext {
        trace_seq,
        symbol,
        parent_span_seq: trace_seq,
    };

    let previous = TRACE_CONTEXT.with(|slot| {
        let prev = slot.get();
        slot.set(Some(context));
        prev
    });

    EntrypointTraceGuard { previous }
}

#[must_use]
pub(crate) fn take_last_explainability() -> Option<DecisionExplainability> {
    LAST_EXPLAINABILITY.with(|slot| slot.borrow_mut().take())
}

#[must_use]
pub(crate) fn peek_last_explainability() -> Option<DecisionExplainability> {
    LAST_EXPLAINABILITY.with(|slot| *slot.borrow())
}

fn next_decision_span_seq() -> u64 {
    DECISION_COUNTER.with(|counter| {
        let next = counter.get().wrapping_add(1);
        counter.set(next);
        next
    })
}

fn fallback_trace_context() -> TraceContext {
    let trace_seq = TRACE_COUNTER.with(|counter| {
        let next = counter.get().wrapping_add(1);
        counter.set(next);
        next
    });
    TraceContext {
        trace_seq,
        symbol: TRACE_UNKNOWN_SYMBOL,
        parent_span_seq: trace_seq,
    }
}

fn active_trace_context() -> TraceContext {
    TRACE_CONTEXT
        .with(|slot| slot.get())
        .unwrap_or_else(fallback_trace_context)
}

fn record_last_explainability(mode: SafetyLevel, ctx: RuntimeContext, decision: RuntimeDecision) {
    let trace = active_trace_context();
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
        policy_id: decision.policy_id,
        risk_upper_bound_ppm: decision.risk_upper_bound_ppm,
        requested_bytes: ctx.requested_bytes,
        addr_hint: ctx.addr_hint,
        is_write: ctx.is_write,
        bloom_negative: ctx.bloom_negative,
        contention_hint: ctx.contention_hint,
        evidence_seqno: decision.evidence_seqno,
    };

    LAST_EXPLAINABILITY.with(|slot| {
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
    let kernel = Box::new(RuntimeMathKernel::new());
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
    let mode = safety_level();
    let ctx = RuntimeContext {
        family,
        addr_hint,
        requested_bytes,
        is_write,
        contention_hint,
        bloom_negative,
    };
    let Some(k) = kernel() else {
        let decision = passthrough_decision();
        record_last_explainability(mode, ctx, decision);
        return (mode, decision);
    };
    let decision = k.decide(mode, ctx);
    record_last_explainability(mode, ctx, decision);
    (mode, decision)
}

pub(crate) fn observe(
    family: ApiFamily,
    profile: ValidationProfile,
    estimated_cost_ns: u64,
    adverse: bool,
) {
    if let Some(k) = kernel() {
        k.observe_validation_result(family, profile, estimated_cost_ns, adverse);
    }
}

#[must_use]
pub(crate) fn check_ordering(
    family: ApiFamily,
    aligned: bool,
    recent_page: bool,
) -> [CheckStage; 7] {
    let Some(k) = kernel() else {
        return PASSTHROUGH_ORDERING;
    };
    k.check_ordering(family, aligned, recent_page)
}

pub(crate) fn note_check_order_outcome(
    family: ApiFamily,
    aligned: bool,
    recent_page: bool,
    ordering_used: &[CheckStage; 7],
    exit_stage: Option<usize>,
) {
    if let Some(k) = kernel() {
        k.note_check_order_outcome(family, aligned, recent_page, ordering_used, exit_stage);
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

    #[test]
    fn scoped_trace_context_carries_symbol_into_explainability() {
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
