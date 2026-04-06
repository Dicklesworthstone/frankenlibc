//! Full pointer validation pipeline.
//!
//! Pipeline stages (with approximate latency budgets):
//! 1. Null check (~1ns)
//! 2. TLS cache lookup (~5ns)
//! 3. Bloom filter pre-check (~10ns)
//! 4. Arena lookup (~30ns)
//! 5. Fingerprint verification (~20ns)
//! 6. Canary verification (~10ns)
//! 7. Bounds computation (~5ns)
//!
//! Fast exits at each stage. Budget: Fast mode <20ns, Full mode <200ns.

#![allow(unsafe_code)]

use crate::arena::{AllocationArena, ArenaSlot, FreeResult};
use crate::bloom::PointerBloomFilter;
use crate::check_oracle::CheckStage;
use crate::config::safety_level;
use crate::fingerprint::{AllocationFingerprint, CANARY_SIZE, FINGERPRINT_SIZE};
use crate::galois::PointerAbstraction;
use crate::ids::{DecisionId, MEMBRANE_SCHEMA_VERSION, TraceId};
use crate::metrics::{MembraneMetrics, global_metrics};
use crate::page_oracle::PageOracle;
use crate::runtime_math::{ApiFamily, RuntimeContext, RuntimeMathKernel, ValidationProfile};
use crate::tls_cache::{CachedValidation, with_tls_cache};
use crate::util::now_utc_iso_like;
use parking_lot::Mutex;
use serde::Serialize;
use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const VALIDATION_LOG_CAPACITY: usize = 2048;
const STRICT_VALIDATION_BUDGET_NS: u64 = 20;
const HARDENED_VALIDATION_BUDGET_NS: u64 = 200;
#[cfg(test)]
const MAX_LEVEL_LABEL_CARDINALITY: usize = 5;
#[cfg(test)]
const MAX_STAGE_LABEL_CARDINALITY: usize = 16;

#[derive(Debug, Clone, Serialize)]
struct ValidationLogRow {
    timestamp: String,
    trace_id: String,
    span_id: String,
    parent_span_id: String,
    decision_id: u64,
    schema_version: String,
    level: &'static str,
    event: &'static str,
    controller_id: &'static str,
    decision_path: &'static str,
    decision_action: &'static str,
    outcome: &'static str,
    mode: &'static str,
    api_family: &'static str,
    symbol: &'static str,
    stage: &'static str,
    security_context: &'static str,
    capability_scope: &'static str,
    security_verdict: &'static str,
    latency_ns: u64,
    policy_id: u32,
    risk_upper_bound_ppm: u32,
    evidence_seqno: u64,
    stage_inputs: ValidationLogInputs,
    artifact_refs: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct ValidationLogInputs {
    aligned: bool,
    recent_page: bool,
    bloom_negative: bool,
    cache_hit: bool,
}

#[derive(Debug, Clone)]
struct ValidationTraceContext {
    decision_id: DecisionId,
    trace_id: TraceId,
    span_id: String,
    parent_span_id: String,
    security_context: &'static str,
    capability_scope: &'static str,
    security_verdict: &'static str,
}

impl ValidationTraceContext {
    #[must_use]
    fn disabled() -> Self {
        Self {
            decision_id: DecisionId::from_raw(0),
            trace_id: TraceId::empty(),
            span_id: String::new(),
            parent_span_id: String::new(),
            security_context: "",
            capability_scope: "",
            security_verdict: "",
        }
    }

    #[must_use]
    fn enabled(decision_id: DecisionId, security_context: ValidationSecurityContext) -> Self {
        let trace_id = decision_id.scoped_trace_id("tsm::pointer_validation");
        let span_id = format!(
            "tsm::pointer_validation::decision::{:016x}",
            decision_id.as_u64()
        );
        let parent_span_id = format!(
            "tsm::pointer_validation::entry::{:016x}",
            decision_id.as_u64()
        );
        Self {
            decision_id,
            trace_id,
            span_id,
            parent_span_id,
            security_context: security_context.label(),
            capability_scope: "pointer_validation",
            security_verdict: if security_context.allows_pointer_validation() {
                "allow"
            } else {
                "deny"
            },
        }
    }

    #[must_use]
    const fn is_enabled(&self) -> bool {
        self.decision_id.is_assigned()
    }
}

/// Result of running a pointer through the validation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// Pointer is null.
    Null,
    /// Pointer validated from TLS cache (fastest path).
    CachedValid(PointerAbstraction),
    /// Pointer validated via full pipeline.
    Validated(PointerAbstraction),
    /// Pointer is not ours (foreign) — allow with unknown state.
    Foreign(PointerAbstraction),
    /// Pointer belongs to a freed/quarantined allocation.
    TemporalViolation(PointerAbstraction),
    /// Pointer belongs to our allocation metadata but fails bounds admissibility.
    Invalid(PointerAbstraction),
    /// Pointer validation denied by security context before pipeline execution.
    Denied(PointerAbstraction),
    /// Validation skipped (SafetyLevel::Off).
    Bypassed,
}

impl ValidationOutcome {
    /// Extract the pointer abstraction if available.
    #[must_use]
    pub fn abstraction(&self) -> Option<PointerAbstraction> {
        match self {
            Self::CachedValid(a)
            | Self::Validated(a)
            | Self::Foreign(a)
            | Self::TemporalViolation(a)
            | Self::Invalid(a)
            | Self::Denied(a) => Some(*a),
            Self::Null => Some(PointerAbstraction::null()),
            Self::Bypassed => None,
        }
    }

    /// Returns true if the pointer can be safely used for reads.
    #[must_use]
    pub fn can_read(&self) -> bool {
        match self {
            Self::CachedValid(a) | Self::Validated(a) => a.state.can_read(),
            Self::Foreign(_) => true, // Allow foreign pointers (Galois property)
            Self::Bypassed => true,
            Self::Null | Self::TemporalViolation(_) | Self::Invalid(_) | Self::Denied(_) => false,
        }
    }

    /// Returns true if the pointer can be safely used for writes.
    #[must_use]
    pub fn can_write(&self) -> bool {
        match self {
            Self::CachedValid(a) | Self::Validated(a) => a.state.can_write(),
            Self::Foreign(_) => true,
            Self::Bypassed => true,
            Self::Null | Self::TemporalViolation(_) | Self::Invalid(_) | Self::Denied(_) => false,
        }
    }
}

/// Default-deny security context for membrane validation entrypoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationSecurityContext {
    pointer_validation_allowed: bool,
    label: &'static str,
}

impl ValidationSecurityContext {
    /// Allow pointer validation through the membrane.
    #[must_use]
    pub const fn allow_pointer_validation() -> Self {
        Self {
            pointer_validation_allowed: true,
            label: "default_allow",
        }
    }

    /// Deny all membrane pointer validation operations.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            pointer_validation_allowed: false,
            label: "deny_all",
        }
    }

    #[must_use]
    pub const fn allows_pointer_validation(self) -> bool {
        self.pointer_validation_allowed
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        self.label
    }
}

use crate::ebr::QuarantineEbr;
use std::sync::Arc;

/// The validation pipeline with all backing data structures.
pub struct ValidationPipeline {
    /// The allocation arena.
    pub arena: AllocationArena,
    /// Bloom filter for quick ownership check.
    pub bloom: PointerBloomFilter,
    /// Page-level ownership oracle.
    pub page_oracle: PageOracle,
    /// Runtime math kernel for online validation-depth/risk decisions.
    pub runtime_math: RuntimeMathKernel,
    /// EBR collector for safe deferred deallocation.
    pub collector: Arc<QuarantineEbr>,
    /// Whether structured validation logging is enabled.
    validation_logging_enabled: AtomicBool,
    /// Monotone decision id for validation logs.
    validation_log_decision_seq: AtomicU64,
    /// Bounded in-memory JSONL buffer for validation traces.
    validation_logs: Mutex<VecDeque<String>>,
}

thread_local! {
    /// Per-thread EBR handle for pinning epochs during validation.
    ///
    /// The handle is keyed by collector identity so tests and auxiliary
    /// pipelines do not accidentally reuse a registration from a different
    /// `ValidationPipeline` on the same thread.
    ///
    /// We store the Arc<QuarantineEbr> alongside the handle to ensure the
    /// collector remains alive as long as the handle is cached, preventing
    /// Use-After-Free if the original ValidationPipeline is dropped.
    static EBR_HANDLE: std::cell::RefCell<Option<(std::sync::Arc<crate::ebr::QuarantineEbr>, crate::ebr::EbrHandle<'static>)>> = const { std::cell::RefCell::new(None) };
    static VALIDATION_DEPTH: Cell<u32> = const { Cell::new(0) };
}

struct ValidationExecutionGuard;

impl Drop for ValidationExecutionGuard {
    fn drop(&mut self) {
        let _ = VALIDATION_DEPTH.try_with(|depth| {
            depth.set(depth.get().saturating_sub(1));
        });
    }
}

fn enter_validation_execution_context() -> ValidationExecutionGuard {
    let _ = VALIDATION_DEPTH.try_with(|depth| {
        depth.set(depth.get().saturating_add(1));
    });
    ValidationExecutionGuard
}

#[must_use]
pub fn in_validation_context() -> bool {
    VALIDATION_DEPTH
        .try_with(|depth| depth.get() > 0)
        .unwrap_or(false)
}

impl ValidationPipeline {
    /// Create a new validation pipeline.
    #[must_use]
    pub fn new() -> Self {
        let logging_enabled = std::env::var_os("FRANKENLIBC_LOG").is_some();
        let collector = std::sync::Arc::new(crate::ebr::QuarantineEbr::new(4));
        Self {
            arena: AllocationArena::new_with_collector(Some(std::sync::Arc::clone(&collector))),
            bloom: PointerBloomFilter::new(),
            page_oracle: PageOracle::new(),
            runtime_math: RuntimeMathKernel::new(),
            collector,
            validation_logging_enabled: AtomicBool::new(logging_enabled),
            validation_log_decision_seq: AtomicU64::new(0),
            validation_logs: Mutex::new(VecDeque::with_capacity(VALIDATION_LOG_CAPACITY)),
        }
    }

    /// Pin the EBR epoch for the duration of validation.
    fn pin_epoch(&self) -> crate::ebr::EbrGuard<'_> {
        let collector_id = std::sync::Arc::as_ptr(&self.collector) as usize;
        EBR_HANDLE.with(|cell| {
            let mut cached = cell.borrow_mut();
            let needs_refresh = !matches!(
                cached.as_ref(),
                Some((cached_collector, _)) if std::sync::Arc::as_ptr(cached_collector) as usize == collector_id
            );
            if needs_refresh {
                let handle = {
                    // SAFETY: The returned handle is stored thread-locally alongside
                    // a strong reference (Arc) to the collector. This ensures the
                    // collector stays alive and at the same address as long as the
                    // handle is cached. Swapping the cached tuple releases the
                    // previous registration and Arc first.
                    unsafe {
                        std::mem::transmute::<crate::ebr::EbrHandle<'_>, crate::ebr::EbrHandle<'static>>(
                            self.collector.register(),
                        )
                    }
                };
                *cached = Some((std::sync::Arc::clone(&self.collector), handle));
            }
            cached
                .as_ref()
                .expect("EBR handle cache initialized")
                .1
                .pin()
        })
    }

    /// Enable or disable structured validation logging.
    pub fn set_validation_logging_enabled(&self, enabled: bool) {
        self.validation_logging_enabled
            .store(enabled, Ordering::Relaxed);
    }

    /// Clear buffered validation log rows.
    pub fn clear_validation_logs(&self) {
        self.validation_logs.lock().clear();
    }

    /// Export buffered validation logs as deterministic JSONL.
    #[must_use]
    pub fn export_validation_log_jsonl(&self) -> String {
        self.validation_logs
            .lock()
            .iter()
            .fold(String::new(), |mut out, line| {
                out.push_str(line);
                out.push('\n');
                out
            })
    }

    #[must_use]
    fn begin_validation_trace(
        &self,
        security_context: ValidationSecurityContext,
    ) -> ValidationTraceContext {
        if !self.validation_logging_enabled.load(Ordering::Relaxed) {
            return ValidationTraceContext::disabled();
        }

        let decision_id = DecisionId::from_raw(
            self.validation_log_decision_seq
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1),
        );
        ValidationTraceContext::enabled(decision_id, security_context)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_validation_log(
        &self,
        trace: &ValidationTraceContext,
        mode: crate::config::SafetyLevel,
        level: &'static str,
        event: &'static str,
        stage: &'static str,
        decision_path: &'static str,
        decision_action: &'static str,
        outcome: &'static str,
        latency_ns: u64,
        aligned: bool,
        recent_page: bool,
        bloom_negative: bool,
        cache_hit: bool,
        policy_id: u32,
        risk_upper_bound_ppm: u32,
        evidence_seqno: u64,
    ) {
        if !trace.is_enabled() {
            return;
        }
        debug_assert!(matches!(
            level,
            "trace" | "debug" | "info" | "warn" | "error"
        ));
        debug_assert!(matches!(
            stage,
            "safety_level"
                | "stage_ordering"
                | "security_context"
                | "null_check"
                | "tls_cache"
                | "bloom"
                | "arena_lookup"
                | "fingerprint"
                | "canary"
                | "bounds"
                | "post_pipeline"
        ));

        let row = ValidationLogRow {
            timestamp: now_utc_iso_like(),
            trace_id: trace.trace_id.as_str().to_string(),
            span_id: trace.span_id.clone(),
            parent_span_id: trace.parent_span_id.clone(),
            decision_id: trace.decision_id.as_u64(),
            schema_version: MEMBRANE_SCHEMA_VERSION.to_string(),
            level,
            event,
            controller_id: "tsm_validation_pipeline.v1",
            decision_path,
            decision_action,
            outcome,
            mode: Self::mode_name(mode),
            api_family: "pointer_validation",
            symbol: "membrane::ptr_validator::validate",
            stage,
            security_context: trace.security_context,
            capability_scope: trace.capability_scope,
            security_verdict: trace.security_verdict,
            latency_ns,
            policy_id,
            risk_upper_bound_ppm,
            evidence_seqno,
            stage_inputs: ValidationLogInputs {
                aligned,
                recent_page,
                bloom_negative,
                cache_hit,
            },
            artifact_refs: vec!["crates/frankenlibc-membrane/src/ptr_validator.rs"],
        };

        if let Ok(line) = serde_json::to_string(&row) {
            self.push_validation_log_line(line);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_terminal_transition(
        &self,
        trace: &ValidationTraceContext,
        mode: crate::config::SafetyLevel,
        stage: &'static str,
        decision_path: &'static str,
        decision_action: &'static str,
        outcome: &'static str,
        latency_ns: u64,
        aligned: bool,
        recent_page: bool,
        bloom_negative: bool,
        cache_hit: bool,
        policy_id: u32,
        risk_upper_bound_ppm: u32,
        evidence_seqno: u64,
        invariant_violation: bool,
    ) {
        let level = if invariant_violation { "error" } else { "info" };
        self.emit_validation_log(
            trace,
            mode,
            level,
            "validation_transition",
            stage,
            decision_path,
            decision_action,
            outcome,
            latency_ns,
            aligned,
            recent_page,
            bloom_negative,
            cache_hit,
            policy_id,
            risk_upper_bound_ppm,
            evidence_seqno,
        );
        self.emit_budget_warning_if_needed(
            trace,
            mode,
            stage,
            decision_path,
            decision_action,
            latency_ns,
            aligned,
            recent_page,
            bloom_negative,
            cache_hit,
            policy_id,
            risk_upper_bound_ppm,
            evidence_seqno,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_budget_warning_if_needed(
        &self,
        trace: &ValidationTraceContext,
        mode: crate::config::SafetyLevel,
        stage: &'static str,
        decision_path: &'static str,
        decision_action: &'static str,
        latency_ns: u64,
        aligned: bool,
        recent_page: bool,
        bloom_negative: bool,
        cache_hit: bool,
        policy_id: u32,
        risk_upper_bound_ppm: u32,
        evidence_seqno: u64,
    ) {
        let budget = match mode {
            crate::config::SafetyLevel::Strict => STRICT_VALIDATION_BUDGET_NS,
            crate::config::SafetyLevel::Hardened => HARDENED_VALIDATION_BUDGET_NS,
            crate::config::SafetyLevel::Off => return,
        };

        if latency_ns <= budget {
            return;
        }

        self.emit_validation_log(
            trace,
            mode,
            "warn",
            "validation_budget_overrun",
            stage,
            decision_path,
            decision_action,
            "BudgetExceeded",
            latency_ns,
            aligned,
            recent_page,
            bloom_negative,
            cache_hit,
            policy_id,
            risk_upper_bound_ppm,
            evidence_seqno,
        );
    }

    fn push_validation_log_line(&self, line: String) {
        if !self.validation_logging_enabled.load(Ordering::Relaxed) {
            return;
        }
        let mut logs = self.validation_logs.lock();
        while logs.len() >= VALIDATION_LOG_CAPACITY {
            let _ = logs.pop_front();
        }
        logs.push_back(line);
    }

    #[must_use]
    fn mode_name(mode: crate::config::SafetyLevel) -> &'static str {
        match mode {
            crate::config::SafetyLevel::Strict => "strict",
            crate::config::SafetyLevel::Hardened => "hardened",
            crate::config::SafetyLevel::Off => "off",
        }
    }

    #[must_use]
    fn stage_label(stage: CheckStage) -> &'static str {
        match stage {
            CheckStage::Null => "null_check",
            CheckStage::TlsCache => "tls_cache",
            CheckStage::Bloom => "bloom",
            CheckStage::Arena => "arena_lookup",
            CheckStage::Fingerprint => "fingerprint",
            CheckStage::Canary => "canary",
            CheckStage::Bounds => "bounds",
        }
    }

    #[must_use]
    fn stage_path(stage: CheckStage) -> &'static str {
        match stage {
            CheckStage::Null => "pipeline::stage1::null_check",
            CheckStage::TlsCache => "pipeline::stage2::tls_cache",
            CheckStage::Bloom => "pipeline::stage3::bloom",
            CheckStage::Arena => "pipeline::stage4::arena",
            CheckStage::Fingerprint => "pipeline::stage5::fingerprint",
            CheckStage::Canary => "pipeline::stage6::canary",
            CheckStage::Bounds => "pipeline::stage7::bounds",
        }
    }

    /// Prepare for a fork by acquiring all internal locks.
    /// Returns a guard that, when dropped, releases the locks.
    pub fn atfork_prepare(&self) -> crate::arena::ArenaAtforkGuard<'_> {
        self.arena.atfork_prepare()
    }

    /// Run a pointer through the validation pipeline.
    ///
    /// @separation-pre: `Owns(TsmMeta) * Readable(addr)`; caller memory outside membrane
    /// metadata is represented as frame `F`.
    /// @separation-post: `Owns(TsmMeta') * Outcome(addr)` and frame `F` is preserved.
    /// @separation-frame: `F` (caller-owned heap and non-membrane regions remain untouched).
    /// @separation-alias: `validate_pointer`.
    pub fn validate(&self, addr: usize) -> ValidationOutcome {
        self.validate_with_security_context(
            addr,
            ValidationSecurityContext::allow_pointer_validation(),
        )
    }

    /// Run a pointer through the validation pipeline under an explicit security context.
    pub fn validate_with_security_context(
        &self,
        addr: usize,
        security_context: ValidationSecurityContext,
    ) -> ValidationOutcome {
        let _validation_context = enter_validation_execution_context();
        let _guard = self.pin_epoch();
        let metrics = global_metrics();
        MembraneMetrics::inc(&metrics.validations);
        let mode = safety_level();
        let trace = self.begin_validation_trace(security_context);

        self.emit_validation_log(
            &trace,
            mode,
            "trace",
            "validation_stage",
            "security_context",
            "pipeline::stage0::security_context",
            "Observe",
            "Continue",
            0,
            false,
            false,
            false,
            false,
            0,
            0,
            0,
        );

        if !security_context.allows_pointer_validation() {
            self.emit_terminal_transition(
                &trace,
                mode,
                "security_context",
                "pipeline::stage0::security_context",
                "Deny",
                "CapabilityDenied",
                0,
                false,
                false,
                false,
                false,
                0,
                0,
                0,
                false, // invariant_violation = false (policy decision, not corruption)
            );
            return ValidationOutcome::Denied(PointerAbstraction {
                addr,
                state: crate::lattice::SafetyState::Invalid,
                alloc_base: None,
                remaining: None,
                generation: None,
            });
        }

        // Stage 0: Safety level check
        if !mode.validation_enabled() {
            self.emit_terminal_transition(
                &trace,
                mode,
                "safety_level",
                "pipeline::stage0::safety_level",
                "Allow",
                "Bypassed",
                0,
                false,
                false,
                false,
                false,
                0,
                0,
                0,
                false,
            );
            return ValidationOutcome::Bypassed;
        }

        // Snapshot the cache epoch before validation starts.
        // This prevents a TOCTOU race where a concurrent free() bumps the epoch
        // *after* we look up the pointer's valid state in the arena but *before* we
        // insert the CachedValid entry.
        let validation_epoch = crate::tls_cache::current_epoch();

        let aligned = addr & 0x7 == 0;
        let recent_page = self.page_oracle.query(addr);
        let raw_order =
            self.runtime_math
                .check_ordering(ApiFamily::PointerValidation, aligned, recent_page);
        let ordering = Self::dependency_safe_order(raw_order);

        // Stage 1: Null check (~1ns)
        self.emit_validation_log(
            &trace,
            mode,
            "trace",
            "validation_stage",
            "null_check",
            "pipeline::stage1::null_check",
            "Observe",
            "Continue",
            1,
            false,
            false,
            false,
            false,
            0,
            0,
            0,
        );
        if addr == 0 {
            self.runtime_math.observe_validation_result(
                mode,
                ApiFamily::PointerValidation,
                ValidationProfile::Fast,
                1,
                false,
            );
            // Report outcome to bandit even for early exit (stage 0)
            self.runtime_math.note_check_order_outcome(
                mode,
                ApiFamily::PointerValidation,
                aligned,
                recent_page,
                &ordering,
                Some(0),
            );
            self.emit_terminal_transition(
                &trace,
                mode,
                "null_check",
                "pipeline::stage1::null_check",
                "Deny",
                "Null",
                1,
                false,
                false,
                false,
                false,
                0,
                0,
                0,
                false,
            );
            return ValidationOutcome::Null;
        }

        if raw_order != ordering {
            self.emit_validation_log(
                &trace,
                mode,
                "warn",
                "validation_order_rewrite",
                "stage_ordering",
                "pipeline::order::dependency_safe_rewrite",
                "Observe",
                "OrderRewritten",
                1,
                aligned,
                recent_page,
                false,
                false,
                0,
                0,
                0,
            );
        }

        let mut elapsed_ns = 1_u64;
        let mut slot: Option<ArenaSlot> = None;
        let mut bloom_negative = false;
        let mut saw_fingerprint = false;
        let mut saw_canary = false;

        for (idx, stage) in ordering.iter().enumerate() {
            self.emit_validation_log(
                &trace,
                mode,
                "trace",
                "validation_stage",
                Self::stage_label(*stage),
                Self::stage_path(*stage),
                "Observe",
                "Continue",
                elapsed_ns,
                aligned,
                recent_page,
                bloom_negative,
                false,
                0,
                0,
                0,
            );
            match *stage {
                CheckStage::Null => {}
                CheckStage::TlsCache => {
                    elapsed_ns =
                        elapsed_ns.saturating_add(u64::from(CheckStage::TlsCache.cost_ns()));
                    let cached = with_tls_cache(|cache| cache.lookup(addr));
                    if let Some(cv) = cached {
                        MembraneMetrics::inc(&metrics.tls_cache_hits);
                        self.emit_validation_log(
                            &trace,
                            mode,
                            "debug",
                            "validation_cache_hit",
                            "tls_cache",
                            "pipeline::stage2::tls_cache",
                            "Allow",
                            "CacheHit",
                            elapsed_ns,
                            aligned,
                            recent_page,
                            bloom_negative,
                            true,
                            0,
                            0,
                            0,
                        );
                        let (remaining, state) = if addr >= cv.user_base
                            && addr < cv.user_base.saturating_add(cv.user_size)
                        {
                            (
                                cv.user_base
                                    .saturating_add(cv.user_size)
                                    .saturating_sub(addr),
                                cv.state,
                            )
                        } else {
                            (0, crate::lattice::SafetyState::Invalid)
                        };
                        let abs = PointerAbstraction::validated(
                            addr,
                            state,
                            cv.user_base,
                            remaining,
                            cv.generation,
                        );
                        self.runtime_math.note_check_order_outcome(
                            mode,
                            ApiFamily::PointerValidation,
                            aligned,
                            recent_page,
                            &ordering,
                            Some(idx),
                        );
                        self.runtime_math.observe_validation_result(
                            mode,
                            ApiFamily::PointerValidation,
                            ValidationProfile::Fast,
                            elapsed_ns,
                            false,
                        );
                        self.emit_terminal_transition(
                            &trace,
                            mode,
                            "tls_cache",
                            "pipeline::stage2::tls_cache",
                            "Allow",
                            "CachedValid",
                            elapsed_ns,
                            aligned,
                            recent_page,
                            bloom_negative,
                            true,
                            0,
                            0,
                            0,
                            false,
                        );
                        return ValidationOutcome::CachedValid(abs);
                    }
                    MembraneMetrics::inc(&metrics.tls_cache_misses);
                    self.emit_validation_log(
                        &trace,
                        mode,
                        "debug",
                        "validation_cache_miss",
                        "tls_cache",
                        "pipeline::stage2::tls_cache",
                        "Observe",
                        "CacheMiss",
                        elapsed_ns,
                        aligned,
                        recent_page,
                        bloom_negative,
                        false,
                        0,
                        0,
                        0,
                    );
                }
                CheckStage::Bloom => {
                    if slot.is_some() {
                        continue;
                    }
                    elapsed_ns = elapsed_ns.saturating_add(u64::from(CheckStage::Bloom.cost_ns()));
                    if !self.bloom.might_contain(addr) {
                        bloom_negative = true;
                        MembraneMetrics::inc(&metrics.bloom_misses);
                        self.emit_validation_log(
                            &trace,
                            mode,
                            "debug",
                            "validation_bloom_miss",
                            "bloom",
                            "pipeline::stage3::bloom",
                            "Observe",
                            "BloomMiss",
                            elapsed_ns,
                            aligned,
                            recent_page,
                            bloom_negative,
                            false,
                            0,
                            0,
                            0,
                        );
                        // Bloom membership is keyed on allocation bases. Interior pointers can
                        // legitimately miss here, so page-oracle ownership must arbitrate before
                        // we classify this address as foreign.
                        let page_hit = self.page_oracle.query(addr);
                        elapsed_ns = elapsed_ns.saturating_add(6);
                        if page_hit {
                            self.emit_validation_log(
                                &trace,
                                mode,
                                "debug",
                                "validation_bloom_page_override",
                                "bloom",
                                "pipeline::stage3::bloom",
                                "Observe",
                                "PageOwned",
                                elapsed_ns,
                                aligned,
                                recent_page,
                                bloom_negative,
                                false,
                                0,
                                0,
                                0,
                            );
                            continue;
                        }

                        let pre_decision = self
                            .runtime_math
                            .decide(mode, RuntimeContext::pointer_validation(addr, true));
                        self.emit_validation_log(
                            &trace,
                            mode,
                            "trace",
                            "validation_runtime_decision",
                            "bloom",
                            "pipeline::stage3::bloom::runtime_decide",
                            match pre_decision.action {
                                crate::runtime_math::MembraneAction::Allow => "Allow",
                                crate::runtime_math::MembraneAction::FullValidate => "FullValidate",
                                crate::runtime_math::MembraneAction::Repair(_) => "Repair",
                                crate::runtime_math::MembraneAction::Deny => "Deny",
                            },
                            "RuntimeDecision",
                            elapsed_ns,
                            aligned,
                            recent_page,
                            bloom_negative,
                            false,
                            pre_decision.policy_id,
                            pre_decision.risk_upper_bound_ppm,
                            pre_decision.evidence_seqno,
                        );

                        // Runtime-math selected fast path for foreign pointers.
                        if !pre_decision.requires_full_validation() && !mode.heals_enabled() {
                            self.runtime_math.note_check_order_outcome(
                                mode,
                                ApiFamily::PointerValidation,
                                aligned,
                                recent_page,
                                &ordering,
                                Some(idx),
                            );
                            self.runtime_math.observe_validation_result(
                                mode,
                                ApiFamily::PointerValidation,
                                pre_decision.profile,
                                elapsed_ns,
                                false,
                            );
                            self.emit_terminal_transition(
                                &trace,
                                mode,
                                "bloom",
                                "pipeline::stage3::bloom",
                                "Allow",
                                "Foreign",
                                elapsed_ns,
                                aligned,
                                recent_page,
                                bloom_negative,
                                false,
                                pre_decision.policy_id,
                                pre_decision.risk_upper_bound_ppm,
                                pre_decision.evidence_seqno,
                                false,
                            );
                            return ValidationOutcome::Foreign(PointerAbstraction::unknown(addr));
                        }

                        // No page ownership evidence: classify as foreign regardless of profile.
                        self.runtime_math.note_check_order_outcome(
                            mode,
                            ApiFamily::PointerValidation,
                            aligned,
                            recent_page,
                            &ordering,
                            Some(idx),
                        );
                        self.runtime_math.observe_validation_result(
                            mode,
                            ApiFamily::PointerValidation,
                            pre_decision.profile,
                            elapsed_ns,
                            false,
                        );
                        self.emit_terminal_transition(
                            &trace,
                            mode,
                            "bloom",
                            "pipeline::stage3::bloom",
                            "Allow",
                            "Foreign",
                            elapsed_ns,
                            aligned,
                            recent_page,
                            bloom_negative,
                            false,
                            pre_decision.policy_id,
                            pre_decision.risk_upper_bound_ppm,
                            pre_decision.evidence_seqno,
                            false,
                        );
                        return ValidationOutcome::Foreign(PointerAbstraction::unknown(addr));
                    } else {
                        MembraneMetrics::inc(&metrics.bloom_hits);
                        self.emit_validation_log(
                            &trace,
                            mode,
                            "debug",
                            "validation_bloom_hit",
                            "bloom",
                            "pipeline::stage3::bloom",
                            "Observe",
                            "BloomHit",
                            elapsed_ns,
                            aligned,
                            recent_page,
                            bloom_negative,
                            false,
                            0,
                            0,
                            0,
                        );
                    }
                }
                CheckStage::Arena => {
                    if slot.is_some() {
                        continue;
                    }
                    elapsed_ns = elapsed_ns.saturating_add(u64::from(CheckStage::Arena.cost_ns()));
                    MembraneMetrics::inc(&metrics.arena_lookups);
                    let Some(found) = self.arena.lookup(addr) else {
                        self.runtime_math.note_check_order_outcome(
                            mode,
                            ApiFamily::PointerValidation,
                            aligned,
                            recent_page,
                            &ordering,
                            Some(idx),
                        );
                        self.runtime_math.observe_validation_result(
                            mode,
                            ApiFamily::PointerValidation,
                            ValidationProfile::Fast,
                            elapsed_ns,
                            false,
                        );
                        self.emit_terminal_transition(
                            &trace,
                            mode,
                            "arena_lookup",
                            "pipeline::stage4::arena",
                            "Allow",
                            "Foreign",
                            elapsed_ns,
                            aligned,
                            recent_page,
                            bloom_negative,
                            false,
                            0,
                            0,
                            0,
                            false,
                        );
                        return ValidationOutcome::Foreign(PointerAbstraction::unknown(addr));
                    };
                    if !found.state.is_live() {
                        let abs = self.abstraction_from_slot(addr, &found);
                        self.runtime_math.note_check_order_outcome(
                            mode,
                            ApiFamily::PointerValidation,
                            aligned,
                            recent_page,
                            &ordering,
                            Some(idx),
                        );
                        self.runtime_math.observe_validation_result(
                            mode,
                            ApiFamily::PointerValidation,
                            ValidationProfile::Full,
                            elapsed_ns,
                            true,
                        );
                        self.emit_terminal_transition(
                            &trace,
                            mode,
                            "arena_lookup",
                            "pipeline::stage4::arena",
                            "Deny",
                            "TemporalViolation",
                            elapsed_ns,
                            aligned,
                            recent_page,
                            bloom_negative,
                            false,
                            0,
                            0,
                            0,
                            true,
                        );
                        return ValidationOutcome::TemporalViolation(abs);
                    }
                    slot = Some(found);
                }
                CheckStage::Fingerprint => {
                    if let Some(s) = slot {
                        elapsed_ns =
                            elapsed_ns.saturating_add(u64::from(CheckStage::Fingerprint.cost_ns()));
                        let mut fp_bytes = [0u8; FINGERPRINT_SIZE];
                        // SAFETY: Valid memory within our allocation header.
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                (s.user_base - FINGERPRINT_SIZE) as *const u8,
                                fp_bytes.as_mut_ptr(),
                                FINGERPRINT_SIZE,
                            );
                        }
                        let fp = AllocationFingerprint::from_bytes(&fp_bytes);
                        if fp.generation != s.generation
                            || fp.size != s.user_size as u64
                            || !fp.verify(s.user_base)
                        {
                            let abs = self.abstraction_from_slot(addr, &s);
                            self.runtime_math.note_check_order_outcome(
                                mode,
                                ApiFamily::PointerValidation,
                                aligned,
                                recent_page,
                                &ordering,
                                Some(idx),
                            );
                            self.runtime_math.observe_validation_result(
                                mode,
                                ApiFamily::PointerValidation,
                                ValidationProfile::Full,
                                elapsed_ns,
                                true,
                            );
                            self.emit_terminal_transition(
                                &trace,
                                mode,
                                "fingerprint",
                                "pipeline::stage5::fingerprint",
                                "Deny",
                                "TemporalViolation",
                                elapsed_ns,
                                aligned,
                                recent_page,
                                bloom_negative,
                                false,
                                0,
                                0,
                                0,
                                true,
                            );
                            return ValidationOutcome::TemporalViolation(abs);
                        }
                        MembraneMetrics::inc(&metrics.fingerprint_passes);
                        self.emit_validation_log(
                            &trace,
                            mode,
                            "trace",
                            "validation_fingerprint_pass",
                            "fingerprint",
                            "pipeline::stage5::fingerprint",
                            "Observe",
                            "FingerprintPass",
                            elapsed_ns,
                            aligned,
                            recent_page,
                            bloom_negative,
                            false,
                            0,
                            0,
                            0,
                        );
                        saw_fingerprint = true;
                    }
                }
                CheckStage::Canary => {
                    if let Some(s) = slot {
                        elapsed_ns =
                            elapsed_ns.saturating_add(u64::from(CheckStage::Canary.cost_ns()));
                        let fp = AllocationFingerprint::compute(
                            s.user_base,
                            s.user_size as u64,
                            s.generation,
                        );
                        let expected_canary = fp.canary();
                        let canary_addr = s.user_base + s.user_size;
                        let mut actual = [0u8; CANARY_SIZE];
                        // SAFETY: Valid memory within the allocation's total size.
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                canary_addr as *const u8,
                                actual.as_mut_ptr(),
                                CANARY_SIZE,
                            );
                        }
                        if !expected_canary.verify(&actual) {
                            let abs = self.abstraction_from_slot(addr, &s);
                            self.runtime_math.note_check_order_outcome(
                                mode,
                                ApiFamily::PointerValidation,
                                aligned,
                                recent_page,
                                &ordering,
                                Some(idx),
                            );
                            self.runtime_math.observe_validation_result(
                                mode,
                                ApiFamily::PointerValidation,
                                ValidationProfile::Full,
                                elapsed_ns,
                                true,
                            );
                            self.emit_terminal_transition(
                                &trace,
                                mode,
                                "canary",
                                "pipeline::stage6::canary",
                                "Deny",
                                "TemporalViolation",
                                elapsed_ns,
                                aligned,
                                recent_page,
                                bloom_negative,
                                false,
                                0,
                                0,
                                0,
                                true,
                            );
                            return ValidationOutcome::TemporalViolation(abs);
                        }
                        MembraneMetrics::inc(&metrics.canary_passes);
                        self.emit_validation_log(
                            &trace,
                            mode,
                            "trace",
                            "validation_canary_pass",
                            "canary",
                            "pipeline::stage6::canary",
                            "Observe",
                            "CanaryPass",
                            elapsed_ns,
                            aligned,
                            recent_page,
                            bloom_negative,
                            false,
                            0,
                            0,
                            0,
                        );
                        saw_canary = true;
                    }
                }
                CheckStage::Bounds => {
                    if let Some(s) = slot {
                        elapsed_ns =
                            elapsed_ns.saturating_add(u64::from(CheckStage::Bounds.cost_ns()));
                        let end = s.user_base.saturating_add(s.user_size);
                        if addr < s.user_base || addr >= end {
                            let abs = self.abstraction_from_slot(addr, &s);
                            self.runtime_math.note_check_order_outcome(
                                mode,
                                ApiFamily::PointerValidation,
                                aligned,
                                recent_page,
                                &ordering,
                                Some(idx),
                            );
                            self.runtime_math.observe_validation_result(
                                mode,
                                ApiFamily::PointerValidation,
                                ValidationProfile::Full,
                                elapsed_ns,
                                true,
                            );
                            self.emit_terminal_transition(
                                &trace,
                                mode,
                                "bounds",
                                "pipeline::stage7::bounds",
                                "Deny",
                                "Invalid",
                                elapsed_ns,
                                aligned,
                                recent_page,
                                bloom_negative,
                                false,
                                0,
                                0,
                                0,
                                false,
                            );
                            return ValidationOutcome::Invalid(abs);
                        }
                        self.emit_validation_log(
                            &trace,
                            mode,
                            "trace",
                            "validation_bounds_accounted",
                            "bounds",
                            "pipeline::stage7::bounds",
                            "Observe",
                            "BoundsAccounted",
                            elapsed_ns,
                            aligned,
                            recent_page,
                            bloom_negative,
                            false,
                            0,
                            0,
                            0,
                        );
                    }
                }
            }
        }

        let Some(slot) = slot else {
            self.runtime_math.note_check_order_outcome(
                mode,
                ApiFamily::PointerValidation,
                aligned,
                recent_page,
                &ordering,
                None,
            );
            self.runtime_math.observe_validation_result(
                mode,
                ApiFamily::PointerValidation,
                ValidationProfile::Fast,
                elapsed_ns,
                false,
            );
            self.emit_terminal_transition(
                &trace,
                mode,
                "post_pipeline",
                "pipeline::post::no_slot",
                "Allow",
                "Foreign",
                elapsed_ns,
                aligned,
                recent_page,
                bloom_negative,
                false,
                0,
                0,
                0,
                false,
            );
            return ValidationOutcome::Foreign(PointerAbstraction::unknown(addr));
        };

        let deep_decision = self.runtime_math.decide(
            mode,
            RuntimeContext::pointer_validation(addr, bloom_negative),
        );
        let deep_action = match deep_decision.action {
            crate::runtime_math::MembraneAction::Allow => "Allow",
            crate::runtime_math::MembraneAction::FullValidate => "FullValidate",
            crate::runtime_math::MembraneAction::Repair(_) => "Repair",
            crate::runtime_math::MembraneAction::Deny => "Deny",
        };
        self.emit_validation_log(
            &trace,
            mode,
            "trace",
            "validation_runtime_decision",
            "post_pipeline",
            "pipeline::post::runtime_decide",
            deep_action,
            "RuntimeDecision",
            elapsed_ns,
            aligned,
            recent_page,
            bloom_negative,
            false,
            deep_decision.policy_id,
            deep_decision.risk_upper_bound_ppm,
            deep_decision.evidence_seqno,
        );

        // Runtime-math fast profile in strict mode skips deep integrity checks.
        if !deep_decision.requires_full_validation() && !mode.heals_enabled() {
            let abs = self.abstraction_from_slot(addr, &slot);
            self.cache_validation(addr, &slot, validation_epoch);
            self.runtime_math.note_check_order_outcome(
                mode,
                ApiFamily::PointerValidation,
                aligned,
                recent_page,
                &ordering,
                None,
            );
            self.runtime_math.observe_validation_result(
                mode,
                ApiFamily::PointerValidation,
                deep_decision.profile,
                elapsed_ns,
                false,
            );
            self.emit_terminal_transition(
                &trace,
                mode,
                "post_pipeline",
                "pipeline::post::fast_accept",
                "Allow",
                "Validated",
                elapsed_ns,
                aligned,
                recent_page,
                bloom_negative,
                false,
                deep_decision.policy_id,
                deep_decision.risk_upper_bound_ppm,
                deep_decision.evidence_seqno,
                false,
            );
            return ValidationOutcome::Validated(abs);
        }

        // If full path is required and these stages were delayed by ordering,
        // force their accounting now so integrity checks remain complete.
        if !saw_fingerprint {
            elapsed_ns = elapsed_ns.saturating_add(u64::from(CheckStage::Fingerprint.cost_ns()));
            let mut fp_bytes = [0u8; FINGERPRINT_SIZE];
            // SAFETY: Valid memory within our allocation header.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (slot.user_base - FINGERPRINT_SIZE) as *const u8,
                    fp_bytes.as_mut_ptr(),
                    FINGERPRINT_SIZE,
                );
            }
            let fp = AllocationFingerprint::from_bytes(&fp_bytes);
            if fp.generation != slot.generation
                || fp.size != slot.user_size as u64
                || !fp.verify(slot.user_base)
            {
                let abs = self.abstraction_from_slot(addr, &slot);
                self.runtime_math.note_check_order_outcome(
                    mode,
                    ApiFamily::PointerValidation,
                    aligned,
                    recent_page,
                    &ordering,
                    None,
                );
                self.runtime_math.observe_validation_result(
                    mode,
                    ApiFamily::PointerValidation,
                    deep_decision.profile,
                    elapsed_ns,
                    true,
                );
                self.emit_terminal_transition(
                    &trace,
                    mode,
                    "fingerprint",
                    "pipeline::post::fingerprint_forced",
                    "Deny",
                    "TemporalViolation",
                    elapsed_ns,
                    aligned,
                    recent_page,
                    bloom_negative,
                    false,
                    deep_decision.policy_id,
                    deep_decision.risk_upper_bound_ppm,
                    deep_decision.evidence_seqno,
                    true,
                );
                return ValidationOutcome::TemporalViolation(abs);
            }
            MembraneMetrics::inc(&metrics.fingerprint_passes);
            self.emit_validation_log(
                &trace,
                mode,
                "trace",
                "validation_fingerprint_pass",
                "fingerprint",
                "pipeline::post::fingerprint_forced",
                "Observe",
                "FingerprintPass",
                elapsed_ns,
                aligned,
                recent_page,
                bloom_negative,
                false,
                deep_decision.policy_id,
                deep_decision.risk_upper_bound_ppm,
                deep_decision.evidence_seqno,
            );
        }
        if !saw_canary {
            elapsed_ns = elapsed_ns.saturating_add(u64::from(CheckStage::Canary.cost_ns()));
            let fp = AllocationFingerprint::compute(
                slot.user_base,
                slot.user_size as u64,
                slot.generation,
            );
            let expected_canary = fp.canary();
            let canary_addr = slot.user_base + slot.user_size;
            let mut actual = [0u8; CANARY_SIZE];
            // SAFETY: Valid memory within the allocation's total size.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    canary_addr as *const u8,
                    actual.as_mut_ptr(),
                    CANARY_SIZE,
                );
            }
            if !expected_canary.verify(&actual) {
                let abs = self.abstraction_from_slot(addr, &slot);
                self.runtime_math.note_check_order_outcome(
                    mode,
                    ApiFamily::PointerValidation,
                    aligned,
                    recent_page,
                    &ordering,
                    None,
                );
                self.runtime_math.observe_validation_result(
                    mode,
                    ApiFamily::PointerValidation,
                    deep_decision.profile,
                    elapsed_ns,
                    true,
                );
                self.emit_terminal_transition(
                    &trace,
                    mode,
                    "canary",
                    "pipeline::post::canary_forced",
                    "Deny",
                    "TemporalViolation",
                    elapsed_ns,
                    aligned,
                    recent_page,
                    bloom_negative,
                    false,
                    deep_decision.policy_id,
                    deep_decision.risk_upper_bound_ppm,
                    deep_decision.evidence_seqno,
                    true,
                );
                return ValidationOutcome::TemporalViolation(abs);
            }
            MembraneMetrics::inc(&metrics.canary_passes);
            self.emit_validation_log(
                &trace,
                mode,
                "trace",
                "validation_canary_pass",
                "canary",
                "pipeline::post::canary_forced",
                "Observe",
                "CanaryPass",
                elapsed_ns,
                aligned,
                recent_page,
                bloom_negative,
                false,
                deep_decision.policy_id,
                deep_decision.risk_upper_bound_ppm,
                deep_decision.evidence_seqno,
            );
        }

        let abs = self.abstraction_from_slot(addr, &slot);
        self.cache_validation(addr, &slot, validation_epoch);
        self.runtime_math.note_check_order_outcome(
            mode,
            ApiFamily::PointerValidation,
            aligned,
            recent_page,
            &ordering,
            None,
        );
        self.runtime_math.observe_validation_result(
            mode,
            ApiFamily::PointerValidation,
            deep_decision.profile,
            elapsed_ns,
            false,
        );
        self.emit_terminal_transition(
            &trace,
            mode,
            "post_pipeline",
            "pipeline::post::validated",
            deep_action,
            "Validated",
            elapsed_ns,
            aligned,
            recent_page,
            bloom_negative,
            false,
            deep_decision.policy_id,
            deep_decision.risk_upper_bound_ppm,
            deep_decision.evidence_seqno,
            false,
        );
        ValidationOutcome::Validated(abs)
    }

    /// Register a new allocation in all backing structures.
    pub fn register_allocation(&self, user_base: usize, raw_base: usize, total_size: usize) {
        self.bloom.insert(user_base);
        self.page_oracle.insert(raw_base, total_size);
    }

    /// Allocate memory and register it with the safety model.
    pub fn allocate(&self, size: usize) -> Option<*mut u8> {
        let res = self.arena.allocate(size)?;
        self.register_allocation(res.user_base, res.raw_base, res.total_size);
        Some(res.ptr)
    }

    /// Allocate aligned memory and register it with the safety model.
    pub fn allocate_aligned(&self, size: usize, align: usize) -> Option<*mut u8> {
        let res = self.arena.allocate_aligned(size, align)?;
        self.register_allocation(res.user_base, res.raw_base, res.total_size);
        Some(res.ptr)
    }

    /// Deregister an allocation from backing structures (PageOracle only).
    pub fn deregister_allocation(&self, raw_base: usize, total_size: usize) {
        self.page_oracle.remove(raw_base, total_size);
    }

    /// Free an allocation and update the safety model.
    ///
    /// This handles the actual freeing in the arena and updates the page oracle
    /// for any blocks that were fully deallocated (drained from quarantine).
    pub fn free(&self, ptr: *mut u8) -> FreeResult {
        let (result, drained) = self.arena.free(ptr);

        for entry in drained {
            self.deregister_allocation(entry.raw_base, entry.total_size);
        }

        result
    }

    /// Deterministically corrupt the trailing canary for a user allocation.
    ///
    /// This is a testing/tooling hook used by reusable fault-injection workflows
    /// so the harness can exercise corruption paths without using `unsafe` code.
    /// The address is treated as an opaque allocation identifier; the pipeline
    /// validates ownership and exact size before touching the trailing canary.
    #[must_use]
    pub fn inject_trailing_canary_corruption(
        &self,
        addr: usize,
        user_size: usize,
        fill_byte: u8,
    ) -> bool {
        if addr == 0 {
            return false;
        }

        let Some(slot) = self.arena.lookup(addr) else {
            return false;
        };
        if slot.user_base != addr || slot.user_size != user_size || !slot.state.is_live() {
            return false;
        }

        // SAFETY: `lookup` returned a live slot for the exact user allocation, and the canary
        // immediately follows the user region for this allocation by construction.
        unsafe { Self::overwrite_trailing_canary(slot.user_base + slot.user_size, fill_byte) };
        true
    }

    unsafe fn overwrite_trailing_canary(canary_addr: usize, fill_byte: u8) {
        // SAFETY: caller guarantees `canary_addr..canary_addr+CANARY_SIZE` points to the live
        // trailing canary bytes for a membrane-owned allocation.
        unsafe {
            std::ptr::write_bytes(canary_addr as *mut u8, fill_byte, CANARY_SIZE);
        }
    }

    /// Cheaply check if an address is likely owned by the membrane.
    ///
    /// This only queries the page oracle and does not perform full validation.
    /// Useful for heuristic stage ordering in the ABI layer.
    #[must_use]
    pub fn check_ownership(&self, addr: usize) -> bool {
        self.page_oracle.query(addr)
    }

    fn abstraction_from_slot(&self, addr: usize, slot: &ArenaSlot) -> PointerAbstraction {
        let (remaining, state) =
            if addr >= slot.user_base && addr < slot.user_base.saturating_add(slot.user_size) {
                (
                    slot.user_base
                        .saturating_add(slot.user_size)
                        .saturating_sub(addr),
                    slot.state,
                )
            } else {
                (0, crate::lattice::SafetyState::Invalid)
            };
        PointerAbstraction::validated(addr, state, slot.user_base, remaining, slot.generation)
    }

    fn cache_validation(&self, addr: usize, slot: &ArenaSlot, epoch: u64) {
        with_tls_cache(|cache| {
            cache.insert(
                addr,
                CachedValidation {
                    user_base: slot.user_base,
                    user_size: slot.user_size,
                    generation: slot.generation,
                    state: slot.state,
                },
                epoch,
            );
        });
    }

    fn dependency_safe_order(ordering: [CheckStage; 7]) -> [CheckStage; 7] {
        let mut out = [CheckStage::Null; 7];
        let mut n = 0_usize;
        let mut seen_mask = 0u8;

        // Stage 0: Always Null check first (cheapest, mandatory)
        out[n] = CheckStage::Null;
        n += 1;
        seen_mask |= 1 << (CheckStage::Null as u8);

        // Group 1: Lookup stages (must happen before integrity checks if we need the slot)
        for stage in ordering.iter().copied() {
            if matches!(
                stage,
                CheckStage::TlsCache | CheckStage::Bloom | CheckStage::Arena
            ) {
                let mask = 1 << (stage as u8);
                if seen_mask & mask == 0 {
                    out[n] = stage;
                    n += 1;
                    seen_mask |= mask;
                }
            }
        }

        // Group 2: Integrity and bounds stages
        for stage in ordering.iter().copied() {
            if matches!(
                stage,
                CheckStage::Fingerprint | CheckStage::Canary | CheckStage::Bounds
            ) {
                let mask = 1 << (stage as u8);
                if seen_mask & mask == 0 {
                    out[n] = stage;
                    n += 1;
                    seen_mask |= mask;
                }
            }
        }

        // Self-healing: if any stages were missing from the input ordering,
        // add them now in default order to ensure we return a complete permutation.
        if n < 7 {
            for stage in [
                CheckStage::TlsCache,
                CheckStage::Bloom,
                CheckStage::Arena,
                CheckStage::Fingerprint,
                CheckStage::Canary,
                CheckStage::Bounds,
            ] {
                let mask = 1 << (stage as u8);
                if seen_mask & mask == 0 {
                    out[n] = stage;
                    n += 1;
                    seen_mask |= mask;
                }
            }
        }

        debug_assert_eq!(n, 7);
        out
    }
}

impl Default for ValidationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check_oracle::CheckStage;
    use crate::lattice::SafetyState;
    use crate::tls_cache::lock_tls_cache_epoch_for_tests;
    use proptest::prelude::*;
    use proptest::test_runner::Config as ProptestConfig;
    use serde_json::Value;
    use std::collections::HashSet;

    fn property_proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("FRANKENLIBC_PROPTEST_CASES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(default_cases);

        ProptestConfig {
            cases,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    fn collected_stage_labels(jsonl: &str) -> HashSet<String> {
        let mut stages = HashSet::new();
        for line in jsonl.lines().filter(|line| !line.trim().is_empty()) {
            let row: Value = serde_json::from_str(line).expect("row must be valid JSON");
            if let Some(stage) = row.get("stage").and_then(Value::as_str) {
                stages.insert(stage.to_string());
            }
        }
        stages
    }

    #[test]
    fn null_pointer_detected() {
        let pipeline = ValidationPipeline::new();
        let outcome = pipeline.validate(0);
        assert!(matches!(outcome, ValidationOutcome::Null));
        assert!(!outcome.can_read());
        assert!(!outcome.can_write());
    }

    #[test]
    fn thread_local_ebr_handle_switches_collectors_between_pipelines() {
        let pipeline_a = ValidationPipeline::new();
        let pipeline_b = ValidationPipeline::new();

        let _ = pipeline_a.validate(0);
        assert_eq!(pipeline_a.collector.diagnostics().active_threads, 1);
        assert_eq!(pipeline_b.collector.diagnostics().active_threads, 0);

        let _ = pipeline_b.validate(0);
        assert_eq!(
            pipeline_b.collector.diagnostics().active_threads,
            1,
            "second pipeline should register its own collector handle",
        );
        assert_eq!(
            pipeline_a.collector.diagnostics().active_threads,
            0,
            "switching pipelines on one thread must release the stale collector handle",
        );
    }

    #[test]
    fn civil_date_from_unix_days_handles_epoch_and_leap_day() {
        use crate::util::civil_date_from_unix_days;
        assert_eq!(civil_date_from_unix_days(0), (1970, 1, 1));
        assert_eq!(civil_date_from_unix_days(11_016), (2000, 2, 29));
        assert_eq!(civil_date_from_unix_days(20_147), (2025, 2, 28));
    }

    #[test]
    fn foreign_pointer_allowed() {
        let pipeline = ValidationPipeline::new();
        let outcome = pipeline.validate(0xDEAD_BEEF);
        // Foreign pointers are allowed (Galois property), but must remain Unknown/unbounded.
        assert!(matches!(outcome, ValidationOutcome::Foreign(_)));
        assert!(outcome.can_read());
        assert!(outcome.can_write());
        let abs = outcome.abstraction().expect("foreign abstraction");
        assert_eq!(abs.state, SafetyState::Unknown);
        assert!(abs.alloc_base.is_none());
        assert!(abs.remaining.is_none());
        assert!(abs.generation.is_none());
    }

    #[test]
    fn allocated_pointer_validates() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.allocate(256).expect("alloc");
        let addr = ptr as usize;

        let outcome = pipeline.validate(addr);
        assert!(outcome.can_read());
        assert!(outcome.can_write());

        if let Some(abs) = outcome.abstraction() {
            assert_eq!(abs.state, SafetyState::Valid);
            assert_eq!(abs.remaining, Some(256));
        } else {
            panic!("expected abstraction");
        }

        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::Freed);
    }

    #[test]
    fn interior_pointer_on_owned_page_is_not_misclassified_as_foreign() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.allocate(256).expect("alloc");
        let base = ptr as usize;
        let interior = base + 17;
        let metrics = global_metrics();
        let before_miss = MembraneMetrics::get(&metrics.bloom_misses);

        let outcome = pipeline.validate(interior);
        assert!(
            !matches!(outcome, ValidationOutcome::Foreign(_)),
            "interior pointer on an owned page must not be classified as foreign"
        );
        assert!(outcome.can_read());
        assert!(outcome.can_write());
        let abs = outcome.abstraction().expect("validated abstraction");
        assert_eq!(abs.alloc_base, Some(base));
        assert_eq!(abs.remaining, Some(256 - 17));

        let after_miss = MembraneMetrics::get(&metrics.bloom_misses);
        assert!(
            after_miss > before_miss,
            "expected bloom miss accounting for interior pointer validation"
        );

        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::Freed);
    }

    #[test]
    fn freed_pointer_detected() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.allocate(128).expect("alloc");
        let addr = ptr as usize;

        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::Freed);

        let outcome = pipeline.validate(addr);
        assert!(!outcome.can_read());
        assert!(!outcome.can_write());
    }

    #[test]
    fn cached_validation_faster_on_second_call() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.allocate(512).expect("alloc");
        let addr = ptr as usize;

        {
            // Guard against unrelated concurrent frees in other tests bumping the epoch
            // and causing flaky cache-hit expectations.
            let _epoch_guard = lock_tls_cache_epoch_for_tests();
            // First call — full pipeline
            let _ = pipeline.validate(addr);
            // Second call — should hit TLS cache
            let outcome = pipeline.validate(addr);
            assert!(matches!(outcome, ValidationOutcome::CachedValid(_)));
        }

        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::Freed);
    }

    #[test]
    fn tls_cache_does_not_allow_uaf_after_free() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.allocate(64).expect("alloc");
        let addr = ptr as usize;

        {
            let _epoch_guard = lock_tls_cache_epoch_for_tests();
            // Populate TLS cache.
            let _ = pipeline.validate(addr);
            let cached = pipeline.validate(addr);
            assert!(
                matches!(cached, ValidationOutcome::CachedValid(_)),
                "expected TLS cache hit on second validate()"
            );
        }

        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::Freed);

        // After free, the TLS cache must not report a stale valid pointer.
        let outcome = pipeline.validate(addr);
        assert!(
            !matches!(outcome, ValidationOutcome::CachedValid(_)),
            "TLS cache returned CachedValid for freed pointer"
        );
        assert!(!outcome.can_read());
        assert!(!outcome.can_write());
    }

    #[test]
    fn foreign_free_reported() {
        let pipeline = ValidationPipeline::new();
        let local = 42_u64;
        let ptr = std::ptr::addr_of!(local) as *mut u64 as *mut u8;
        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::ForeignPointer);
    }

    #[test]
    fn double_free_reported() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.allocate(32).expect("alloc");

        let first = pipeline.free(ptr);
        assert_eq!(first, FreeResult::Freed);

        let second = pipeline.free(ptr);
        assert_eq!(second, FreeResult::DoubleFree);
    }

    #[test]
    fn canary_corruption_detected_via_pipeline_free() {
        let pipeline = ValidationPipeline::new();
        let size = 32_usize;
        let ptr = pipeline.allocate(size).expect("alloc");
        let addr = ptr as usize;

        assert!(pipeline.inject_trailing_canary_corruption(addr, size, 0xFF));

        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::FreedWithCanaryCorruption);

        // Canary corruption is still a free; pointer is quarantined and must not be readable/writable.
        let outcome = pipeline.validate(addr);
        assert!(!outcome.can_read());
        assert!(!outcome.can_write());
        assert!(
            !matches!(outcome, ValidationOutcome::CachedValid(_)),
            "must not yield CachedValid for freed/corrupted pointer"
        );
    }

    #[test]
    fn one_past_end_pointer_is_denied_as_invalid() {
        let pipeline = ValidationPipeline::new();
        let size = 64_usize;
        let ptr = pipeline.allocate(size).expect("alloc");
        let base = ptr as usize;
        let one_past_end = base + size;

        let outcome = pipeline.validate(one_past_end);
        assert!(matches!(outcome, ValidationOutcome::Invalid(_)));
        assert!(!outcome.can_read());
        assert!(!outcome.can_write());
        let abs = outcome.abstraction().expect("invalid abstraction");
        assert_eq!(abs.alloc_base, Some(base));
        assert_eq!(abs.state, SafetyState::Invalid);
        assert_eq!(abs.remaining, Some(0));

        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::Freed);
    }

    #[test]
    fn header_pointer_is_denied_as_invalid() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.allocate(64).expect("alloc");
        let base = ptr as usize;
        let header_addr = base.saturating_sub(1);

        let outcome = pipeline.validate(header_addr);
        assert!(matches!(outcome, ValidationOutcome::Invalid(_)));
        assert!(!outcome.can_read());
        assert!(!outcome.can_write());
        let abs = outcome.abstraction().expect("invalid abstraction");
        assert_eq!(abs.alloc_base, Some(base));
        assert_eq!(abs.state, SafetyState::Invalid);

        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::Freed);
    }

    #[test]
    fn null_pointer_early_exit_does_not_reach_later_stages() {
        let pipeline = ValidationPipeline::new();
        pipeline.set_validation_logging_enabled(true);
        pipeline.clear_validation_logs();

        let outcome = pipeline.validate(0);
        assert!(matches!(outcome, ValidationOutcome::Null));

        let stages = collected_stage_labels(&pipeline.export_validation_log_jsonl());
        assert!(!stages.contains("safety_level"));
        assert!(stages.contains("null_check"));
        assert!(!stages.contains("tls_cache"));
        assert!(!stages.contains("bloom"));
        assert!(!stages.contains("arena_lookup"));
        assert!(!stages.contains("fingerprint"));
        assert!(!stages.contains("canary"));
        assert!(!stages.contains("bounds"));
    }

    #[test]
    fn foreign_pointer_early_exit_skips_deep_integrity_stages() {
        let pipeline = ValidationPipeline::new();
        pipeline.set_validation_logging_enabled(true);
        pipeline.clear_validation_logs();

        let outcome = pipeline.validate(0x6FFF_0000_0000usize);
        assert!(matches!(outcome, ValidationOutcome::Foreign(_)));

        let stages = collected_stage_labels(&pipeline.export_validation_log_jsonl());
        assert!(!stages.contains("fingerprint"));
        assert!(!stages.contains("canary"));
        assert!(!stages.contains("bounds"));
    }

    #[test]
    fn bloom_false_positives_do_not_classify_foreign_as_validated() {
        let pipeline = ValidationPipeline::new();
        let mut allocated = Vec::new();
        for _ in 0..256 {
            let ptr = pipeline.allocate(64).expect("alloc");
            allocated.push(ptr);
        }

        for i in 0..4096usize {
            let addr = 0x6FFF_0000_0000usize + i * 0x1000;
            let outcome = pipeline.validate(addr);
            assert!(
                !matches!(
                    outcome,
                    ValidationOutcome::CachedValid(_) | ValidationOutcome::Validated(_)
                ),
                "foreign address {addr:#x} must not validate as owned"
            );
        }

        for ptr in allocated {
            assert_eq!(pipeline.free(ptr), FreeResult::Freed);
        }
    }

    #[test]
    fn validation_log_export_includes_trace_and_decision_ids() {
        let pipeline = ValidationPipeline::new();
        pipeline.set_validation_logging_enabled(true);
        pipeline.clear_validation_logs();

        let ptr = pipeline.allocate(64).expect("alloc");
        let addr = ptr as usize;
        let _ = pipeline.validate(addr);
        let _ = pipeline.validate(addr);
        let _ = pipeline.validate(0xDEAD_BEEF);
        let _ = pipeline.free(ptr);

        let jsonl = pipeline.export_validation_log_jsonl();
        assert!(
            !jsonl.trim().is_empty(),
            "expected structured validation logs"
        );

        for line in jsonl.lines().filter(|line| !line.trim().is_empty()) {
            let row: Value = serde_json::from_str(line).expect("row must be valid JSON");
            let trace_id = row
                .get("trace_id")
                .and_then(Value::as_str)
                .expect("trace_id must be present");
            assert!(
                trace_id.starts_with("tsm::pointer_validation::"),
                "trace_id must use canonical pointer-validation scope"
            );
            assert!(row.get("decision_id").and_then(Value::as_u64).is_some());
            assert_eq!(
                row.get("schema_version").and_then(Value::as_str),
                Some("1.0")
            );
            assert!(row.get("decision_path").and_then(Value::as_str).is_some());
            assert!(row.get("level").and_then(Value::as_str).is_some());
            assert!(row.get("stage").and_then(Value::as_str).is_some());
            assert!(
                row.get("security_context")
                    .and_then(Value::as_str)
                    .is_some()
            );
            assert!(
                row.get("capability_scope")
                    .and_then(Value::as_str)
                    .is_some()
            );
            assert!(
                row.get("security_verdict")
                    .and_then(Value::as_str)
                    .is_some()
            );
        }
    }

    #[test]
    fn security_context_default_deny_is_fail_closed() {
        let pipeline = ValidationPipeline::new();
        pipeline.set_validation_logging_enabled(true);
        pipeline.clear_validation_logs();

        let ptr = pipeline.allocate(64).expect("alloc");
        let outcome = pipeline
            .validate_with_security_context(ptr as usize, ValidationSecurityContext::deny_all());
        assert!(matches!(outcome, ValidationOutcome::Denied(_)));
        assert!(!outcome.can_read());
        assert!(!outcome.can_write());

        let stages = collected_stage_labels(&pipeline.export_validation_log_jsonl());
        assert!(stages.contains("security_context"));
        assert!(!stages.contains("null_check"));
        assert!(!stages.contains("tls_cache"));

        let _ = pipeline.free(ptr);
    }

    #[test]
    #[allow(unsafe_code)]
    fn validation_logging_level_mapping_covers_spec_levels() {
        let pipeline = ValidationPipeline::new();
        pipeline.set_validation_logging_enabled(true);
        pipeline.clear_validation_logs();

        let ptr = pipeline.allocate(64).expect("alloc");
        let addr = ptr as usize;

        // Full validation path (strict) should produce info + warn + trace.
        let _ = pipeline.validate(addr);
        // Cache hit path should produce debug.
        let _ = pipeline.validate(addr);

        // Corrupt canary before free so validator emits an invariant-violation error.
        // SAFETY: Intentional corruption to exercise validation error logging.
        unsafe {
            std::ptr::write_bytes(ptr.add(64), 0xAB, CANARY_SIZE);
        }
        crate::tls_cache::bump_tls_cache_epoch();
        let _ = pipeline.validate(addr);

        let jsonl = pipeline.export_validation_log_jsonl();
        let mut levels = HashSet::new();
        for line in jsonl.lines().filter(|line| !line.trim().is_empty()) {
            let row: Value = serde_json::from_str(line).expect("row must be valid JSON");
            if let Some(level) = row.get("level").and_then(Value::as_str) {
                levels.insert(level.to_string());
            }
        }

        assert!(levels.contains("trace"));
        assert!(levels.contains("debug"));
        assert!(levels.contains("info"));
        assert!(levels.contains("warn"));
        assert!(levels.contains("error"));
    }

    #[test]
    fn validation_logging_cardinality_budget_is_bounded() {
        let pipeline = ValidationPipeline::new();
        pipeline.set_validation_logging_enabled(true);
        pipeline.clear_validation_logs();

        let ptr = pipeline.allocate(32).expect("alloc");
        let addr = ptr as usize;
        let _ = pipeline.validate(addr);
        let _ = pipeline.validate(0);
        let _ = pipeline.validate(0xA11CE);
        let _ = pipeline.free(ptr);

        let jsonl = pipeline.export_validation_log_jsonl();
        let mut levels = HashSet::new();
        let mut stages = HashSet::new();

        for line in jsonl.lines().filter(|line| !line.trim().is_empty()) {
            let row: Value = serde_json::from_str(line).expect("row must be valid JSON");
            if let Some(level) = row.get("level").and_then(Value::as_str) {
                levels.insert(level.to_string());
            }
            if let Some(stage) = row.get("stage").and_then(Value::as_str) {
                stages.insert(stage.to_string());
            }
        }

        assert!(
            levels.len() <= MAX_LEVEL_LABEL_CARDINALITY,
            "level label cardinality exceeded: {} > {}",
            levels.len(),
            MAX_LEVEL_LABEL_CARDINALITY
        );
        assert!(
            stages.len() <= MAX_STAGE_LABEL_CARDINALITY,
            "stage label cardinality exceeded: {} > {}",
            stages.len(),
            MAX_STAGE_LABEL_CARDINALITY
        );
    }

    #[test]
    fn dependency_safe_order_delays_deep_checks_until_after_arena() {
        let scrambled = [
            CheckStage::Null,
            CheckStage::Fingerprint,
            CheckStage::Canary,
            CheckStage::Bounds,
            CheckStage::TlsCache,
            CheckStage::Bloom,
            CheckStage::Arena,
        ];
        let ordered = ValidationPipeline::dependency_safe_order(scrambled);
        let arena_idx = ordered
            .iter()
            .position(|s| matches!(s, CheckStage::Arena))
            .expect("arena in ordering");
        let fingerprint_idx = ordered
            .iter()
            .position(|s| matches!(s, CheckStage::Fingerprint))
            .expect("fingerprint in ordering");
        let canary_idx = ordered
            .iter()
            .position(|s| matches!(s, CheckStage::Canary))
            .expect("canary in ordering");
        let bounds_idx = ordered
            .iter()
            .position(|s| matches!(s, CheckStage::Bounds))
            .expect("bounds in ordering");
        assert!(arena_idx < fingerprint_idx);
        assert!(arena_idx < canary_idx);
        assert!(arena_idx < bounds_idx);
    }

    proptest! {
        #![proptest_config(property_proptest_config(256))]

        #[test]
        fn allocated_pointer_property_validates_as_live(size in 1usize..2049) {
            let pipeline = ValidationPipeline::new();
            let ptr = pipeline.allocate(size).expect("allocation must succeed");
            let addr = ptr as usize;

            let outcome = pipeline.validate(addr);
            prop_assert!(matches!(
                outcome,
                ValidationOutcome::Validated(_) | ValidationOutcome::CachedValid(_)
            ));
            prop_assert!(outcome.can_read());
            prop_assert!(outcome.can_write());

            let abs = outcome.abstraction().expect("validated allocation abstraction");
            prop_assert_eq!(abs.state, SafetyState::Valid);
            prop_assert_eq!(abs.alloc_base, Some(addr));
            prop_assert_eq!(abs.remaining, Some(size));

            prop_assert_eq!(pipeline.free(ptr), FreeResult::Freed);
        }

        #[test]
        fn freed_pointer_property_becomes_temporal_violation(size in 1usize..2049) {
            let pipeline = ValidationPipeline::new();
            let ptr = pipeline.allocate(size).expect("allocation must succeed");
            let addr = ptr as usize;

            prop_assert_eq!(pipeline.free(ptr), FreeResult::Freed);

            let outcome = pipeline.validate(addr);
            prop_assert!(matches!(outcome, ValidationOutcome::TemporalViolation(_)));
            prop_assert!(!outcome.can_read());
            prop_assert!(!outcome.can_write());

            let abs = outcome.abstraction().expect("temporal violation abstraction");
            prop_assert_eq!(abs.alloc_base, Some(addr));
            prop_assert!(matches!(
                abs.state,
                SafetyState::Quarantined | SafetyState::Freed
            ));
        }

        #[test]
        fn dependency_safe_order_property_holds(random_keys in proptest::array::uniform7(any::<u16>())) {
            let all_stages = [
                CheckStage::Null,
                CheckStage::TlsCache,
                CheckStage::Bloom,
                CheckStage::Arena,
                CheckStage::Fingerprint,
                CheckStage::Canary,
                CheckStage::Bounds,
            ];

            let mut keyed = all_stages
                .into_iter()
                .enumerate()
                .map(|(idx, stage)| (random_keys[idx], idx, stage))
                .collect::<Vec<_>>();
            keyed.sort_by_key(|(key, idx, _)| (*key, *idx));

            let mut scrambled = [CheckStage::Null; 7];
            for (idx, (_, _, stage)) in keyed.into_iter().enumerate() {
                scrambled[idx] = stage;
            }

            let ordered = ValidationPipeline::dependency_safe_order(scrambled);
            let input_set = scrambled.into_iter().collect::<HashSet<_>>();
            let output_set = ordered.into_iter().collect::<HashSet<_>>();
            prop_assert_eq!(input_set, output_set);

            let arena_idx = ordered
                .iter()
                .position(|s| matches!(s, CheckStage::Arena))
                .expect("arena in ordering");
            let fingerprint_idx = ordered
                .iter()
                .position(|s| matches!(s, CheckStage::Fingerprint))
                .expect("fingerprint in ordering");
            let canary_idx = ordered
                .iter()
                .position(|s| matches!(s, CheckStage::Canary))
                .expect("canary in ordering");
            let bounds_idx = ordered
                .iter()
                .position(|s| matches!(s, CheckStage::Bounds))
                .expect("bounds in ordering");
            prop_assert!(arena_idx < fingerprint_idx);
            prop_assert!(arena_idx < canary_idx);
            prop_assert!(arena_idx < bounds_idx);

            let reordered = ValidationPipeline::dependency_safe_order(ordered);
            prop_assert_eq!(reordered, ordered);
        }
    }
}
