//! Conformance testing harness for frankenlibc.
//!
//! This crate provides:
//! - Fixture capture: record host glibc behavior as JSON reference data
//! - Fixture verify: compare our implementation against captured fixtures
//! - Traceability: map tests to POSIX/C11 spec sections + TSM policy sections
//! - Healing oracle: intentionally trigger unsafe conditions, verify healing
//! - Report generation: human-readable + machine-readable conformance reports

#![forbid(unsafe_code)]

#[cfg(feature = "asupersync-tooling")]
pub mod asupersync_orchestrator;
pub mod capture;
pub mod conformance_matrix;
pub mod diff;
pub mod evidence_compliance;
pub mod evidence_decode;
pub mod evidence_decode_render;
pub mod fixtures;
pub mod healing_oracle;
pub mod kernel_regression_report;
pub mod kernel_snapshot;
pub mod membrane_tests;
pub mod report;
pub mod runner;
pub mod runtime_math_determinism_proofs;
pub mod runtime_math_divergence_bounds;
pub mod runtime_math_linkage_proofs;
pub mod setjmp_contract;
pub mod snapshot_diff;
pub mod structured_log;
pub mod traceability;
pub mod verify;

pub use fixtures::{FixtureCase, FixtureSet};
pub use report::{ConformanceReport, RealityReport};
pub use runner::TestRunner;
pub use verify::VerificationResult;
