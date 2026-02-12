//! Runtime policy bridge for ABI entrypoints.
//!
//! This module centralizes access to the membrane RuntimeMathKernel so ABI
//! functions can cheaply obtain per-call decisions and publish observations
//! without duplicating orchestration code.

#![allow(dead_code)]

use std::sync::atomic::{AtomicPtr, AtomicU8, Ordering as AtomicOrdering};

use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::config::{SafetyLevel, safety_level};
use frankenlibc_membrane::runtime_math::{
    ApiFamily, RuntimeContext, RuntimeDecision, RuntimeMathKernel, ValidationProfile,
};

// Kernel lifecycle states.
const STATE_UNINIT: u8 = 0;
const STATE_INITIALIZING: u8 = 1;
const STATE_READY: u8 = 2;

// Manual init guard that avoids OnceLock's internal futex.
// OnceLock::get_or_init uses a futex wait when it sees init-in-progress,
// which causes deadlock if a reentrant call from the same thread arrives
// during RuntimeMathKernel::new(). Instead, we use a simple atomic state
// machine: UNINIT -> INITIALIZING -> READY, and any reentrant call that
// sees INITIALIZING returns None (passthrough).
static KERNEL_STATE: AtomicU8 = AtomicU8::new(STATE_UNINIT);
static KERNEL_PTR: AtomicPtr<RuntimeMathKernel> = AtomicPtr::new(std::ptr::null_mut());

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
    let Some(k) = kernel() else {
        return (mode, passthrough_decision());
    };
    let decision = k.decide(
        mode,
        RuntimeContext {
            family,
            addr_hint,
            requested_bytes,
            is_write,
            contention_hint,
            bloom_negative,
        },
    );
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
