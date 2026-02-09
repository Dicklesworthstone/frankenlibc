//! Runtime policy bridge for ABI entrypoints.
//!
//! This module centralizes access to the membrane RuntimeMathKernel so ABI
//! functions can cheaply obtain per-call decisions and publish observations
//! without duplicating orchestration code.

#![allow(dead_code)]

use std::sync::OnceLock;

use glibc_rs_membrane::check_oracle::CheckStage;
use glibc_rs_membrane::config::{SafetyLevel, safety_level};
use glibc_rs_membrane::runtime_math::{
    ApiFamily, RuntimeContext, RuntimeDecision, RuntimeMathKernel, ValidationProfile,
};

fn kernel() -> &'static RuntimeMathKernel {
    static KERNEL: OnceLock<RuntimeMathKernel> = OnceLock::new();
    KERNEL.get_or_init(RuntimeMathKernel::new)
}

pub(crate) fn decide(
    family: ApiFamily,
    addr_hint: usize,
    requested_bytes: usize,
    is_write: bool,
    bloom_negative: bool,
    contention_hint: u16,
) -> (SafetyLevel, RuntimeDecision) {
    let mode = safety_level();
    let decision = kernel().decide(
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
    kernel().observe_validation_result(family, profile, estimated_cost_ns, adverse);
}

#[must_use]
pub(crate) fn check_ordering(
    family: ApiFamily,
    aligned: bool,
    recent_page: bool,
) -> [CheckStage; 7] {
    kernel().check_ordering(family, aligned, recent_page)
}

pub(crate) fn note_check_order_outcome(
    family: ApiFamily,
    aligned: bool,
    recent_page: bool,
    ordering_used: &[CheckStage; 7],
    exit_stage: Option<usize>,
) {
    kernel().note_check_order_outcome(family, aligned, recent_page, ordering_used, exit_stage);
}

#[must_use]
pub(crate) fn scaled_cost(base_ns: u64, bytes: usize) -> u64 {
    // Smooth logarithmic-like proxy with integer ops for low overhead.
    base_ns.saturating_add(((bytes as u64).saturating_add(63) / 64).min(8192))
}
