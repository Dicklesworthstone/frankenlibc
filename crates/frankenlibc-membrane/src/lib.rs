//! Transparent Safety Membrane (TSM) for frankenlibc.
//!
//! This crate implements the core innovation: a validation pipeline that sits
//! between C ABI entry points and safe Rust implementations. It dynamically
//! validates, sanitizes, and mechanically fixes invalid operations so memory
//! unsafety cannot propagate through libc calls.
//!
//! # Architecture
//!
//! The membrane consists of:
//! - **Safety lattice** (`lattice`): Formal state model with monotonic join/meet
//! - **Galois connection** (`galois`): Maps between C flat model and rich safety model
//! - **Allocation fingerprints** (`fingerprint`): SipHash-based integrity verification
//! - **Generational arena** (`arena`): Temporal safety via generation counters
//! - **Bloom filter** (`bloom`): O(1) "is this pointer ours?" pre-check
//! - **TLS cache** (`tls_cache`): Thread-local validation cache (avoids global lock)
//! - **Page oracle** (`page_oracle`): Two-level page bitmap for ownership queries
//! - **Self-healing engine** (`heal`): Deterministic repair policies
//! - **Pointer validator** (`ptr_validator`): Full validation pipeline
//! - **Configuration** (`config`): Runtime safety level control
//! - **Metrics** (`metrics`): Atomic counters for observability

#![deny(unsafe_code)]

#[cfg(not(feature = "runtime-math-production"))]
compile_error!(
    "frankenlibc-membrane requires the `runtime-math-production` feature (runtime math kernel is mandatory)."
);

pub mod alien_cs_metrics;
pub mod arena;
pub mod bloom;
pub mod bravo;
pub mod check_oracle;
pub mod config;
pub mod decision_contract;
pub mod ebr;
pub mod evidence_ledger;
pub mod fingerprint;
pub mod flat_combining;
pub mod galois;
#[path = "runtime_math/grobner.rs"]
pub mod grobner;
pub mod heal;
pub mod hji_reachability;
pub mod ids;
pub mod large_deviations;
pub mod lattice;
pub mod left_right;
pub mod mean_field_game;
pub mod metrics;
pub mod padic_valuation;
pub mod page_oracle;
pub mod persistence;
pub mod pressure_sensor;
pub mod ptr_validator;
pub mod quarantine_controller;
pub mod rcu;
pub mod risk_engine;
pub mod rough_path;
pub mod runtime_math;
pub mod schrodinger_bridge;
pub mod seqlock;
pub mod spectral_monitor;
pub mod symplectic_reduction;
pub mod tls_cache;
pub mod tropical_latency;
pub mod util;

pub use bravo::{BravoReadPath, BravoRwLock, BravoRwLockDiagnostics};
pub use config::SafetyLevel;
pub use decision_contract::{
    DecisionAction as DecisionContractAction, DecisionContractMachine,
    DecisionEvent as DecisionContractEvent, DecisionTransition, TsmState,
};
pub use evidence_ledger::{
    EvidenceCategory, EvidenceLedger, EvidenceLevel, EvidenceRecord, OtlpExportSummary,
    RedactionPolicy, ValidationEvidence, global_evidence_ledger,
};
pub use heal::{HealingAction, HealingPolicy};
pub use ids::{DecisionId, MEMBRANE_SCHEMA_VERSION, PolicyId, SchemaVersion, TraceId};
pub use lattice::SafetyState;
pub use left_right::{LeftRight, LeftRightDiagnostics, LeftRightReader};
pub use metrics::MembraneMetrics;
pub use pressure_sensor::{PressureSensor, PressureSignals, SystemRegime};
pub use ptr_validator::{ValidationOutcome, ValidationPipeline, ValidationSecurityContext};
pub use runtime_math::{
    ApiFamily, MembraneAction, RuntimeContext, RuntimeDecision, RuntimeMathKernel,
    ValidationProfile,
};

#[cfg(test)]
mod memory_model_audit_tests {
    use serde_json::Value;

    const MEMORY_MODEL_AUDIT_JSON: &str =
        include_str!(concat!(env!("OUT_DIR"), "/memory_model_audit.json"));

    #[test]
    fn memory_model_audit_meets_minimum_site_count() {
        let parsed: Value =
            serde_json::from_str(MEMORY_MODEL_AUDIT_JSON).expect("memory-model audit JSON parses");
        let minimum = parsed["minimum_required_sites"]
            .as_u64()
            .expect("minimum_required_sites must be u64");
        let total = parsed["summary"]["total_atomic_sites"]
            .as_u64()
            .expect("summary.total_atomic_sites must be u64");
        let verified = parsed["summary"]["verified_count"]
            .as_u64()
            .expect("summary.verified_count must be u64");

        assert!(
            total >= minimum,
            "barrier map total sites ({total}) must satisfy minimum ({minimum})"
        );
        assert_eq!(
            total, verified,
            "every audited atomic site must be verified in barrier map"
        );
    }

    #[test]
    fn memory_model_audit_includes_tsm_and_futex_domains() {
        let parsed: Value =
            serde_json::from_str(MEMORY_MODEL_AUDIT_JSON).expect("memory-model audit JSON parses");
        let sites = parsed["sites"]
            .as_array()
            .expect("sites must be an array in memory-model audit");
        let has_tsm = sites.iter().any(|site| {
            site["domain"]
                .as_str()
                .is_some_and(|domain| domain == "tsm")
        });
        let has_futex = sites.iter().any(|site| {
            site["domain"]
                .as_str()
                .is_some_and(|domain| domain == "futex")
        });
        let has_seqcst = sites.iter().any(|site| {
            site["ordering"]
                .as_str()
                .is_some_and(|ordering| ordering == "SeqCst")
        });

        assert!(has_tsm, "memory-model audit must include tsm atomic sites");
        assert!(
            has_futex,
            "memory-model audit must include futex atomic sites"
        );
        assert!(
            has_seqcst,
            "memory-model audit should capture seq-cst orderings when present"
        );
    }
}
