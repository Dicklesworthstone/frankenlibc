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

pub mod arena;
pub mod bloom;
pub mod check_oracle;
pub mod config;
pub mod fingerprint;
pub mod galois;
#[path = "runtime_math/grobner.rs"]
pub mod grobner;
pub mod heal;
pub mod hji_reachability;
pub mod large_deviations;
pub mod lattice;
pub mod mean_field_game;
pub mod metrics;
pub mod padic_valuation;
pub mod page_oracle;
pub mod persistence;
pub mod pressure_sensor;
pub mod ptr_validator;
pub mod quarantine_controller;
pub mod risk_engine;
pub mod rough_path;
pub mod runtime_math;
pub mod schrodinger_bridge;
pub mod spectral_monitor;
pub mod symplectic_reduction;
pub mod tls_cache;
pub mod tropical_latency;

pub use config::SafetyLevel;
pub use heal::{HealingAction, HealingPolicy};
pub use lattice::SafetyState;
pub use metrics::MembraneMetrics;
pub use pressure_sensor::{PressureSensor, PressureSignals, SystemRegime};
pub use ptr_validator::{ValidationOutcome, ValidationPipeline};
pub use runtime_math::{
    ApiFamily, MembraneAction, RuntimeContext, RuntimeDecision, RuntimeMathKernel,
    ValidationProfile,
};
