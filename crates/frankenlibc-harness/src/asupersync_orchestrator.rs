//! Deterministic harness orchestration using /dp/asupersync tooling.
//!
//! This module is build/test tooling only. It is intentionally compiled behind
//! the `asupersync-tooling` feature so `libc.so` runtime crates never depend on
//! Asupersync.
//!
//! Goals:
//! - Deterministic scheduling: stable ordering of fixture sets and cases.
//! - Traceability IDs: stable per-execution identifiers.
//! - Structured evidence: checkpoints + structured events per case execution.

#![cfg(feature = "asupersync-tooling")]

use std::time::Instant;

use asupersync_conformance::logging::{ConformanceTestLogger, with_test_logger};
use asupersync_conformance::{Checkpoint, SuiteResult, SuiteTestResult, TestCategory, TestResult};
use frankenlibc_conformance::execute_fixture_case;
use serde_json::json;

use crate::diff;
use crate::fixtures::{FixtureCase, FixtureSet};
use crate::verify::VerificationResult;

/// Outputs from a deterministic fixture verification run.
#[derive(Debug)]
pub struct OrchestratedRun {
    /// Per-case verification results (for legacy markdown/json reporting).
    pub verification_results: Vec<VerificationResult>,
    /// Structured suite result (for tooling + evidence capture).
    pub suite: SuiteResult,
}

/// Run a fixture verification campaign deterministically and capture asupersync-style evidence.
#[must_use]
pub fn run_fixture_verification(campaign: &str, fixture_sets: &[FixtureSet]) -> OrchestratedRun {
    let suite_start = Instant::now();
    let mut suite = SuiteResult::new(format!("glibc-rs-harness:{campaign}"));
    let mut verification_results = Vec::new();

    let mut sets: Vec<&FixtureSet> = fixture_sets.iter().collect();
    sets.sort_by(|a, b| {
        a.family
            .cmp(&b.family)
            .then_with(|| a.captured_at.cmp(&b.captured_at))
            .then_with(|| a.version.cmp(&b.version))
    });

    for set in sets {
        let mut cases: Vec<&FixtureCase> = set.cases.iter().collect();
        cases.sort_by(|a, b| {
            a.function
                .cmp(&b.function)
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| a.mode.cmp(&b.mode))
        });

        for case in cases {
            for exec_mode in case_execution_modes(&case.mode) {
                let (verification, suite_item) =
                    run_one_case(campaign, set, case, exec_mode.as_str());

                if suite_item.result.passed {
                    suite.passed += 1;
                } else {
                    suite.failed += 1;
                }
                suite.results.push(suite_item);
                verification_results.push(verification);
            }
        }
    }

    suite.total = suite.results.len();
    suite.duration_ms = suite_start.elapsed().as_millis() as u64;

    OrchestratedRun {
        verification_results,
        suite,
    }
}

fn case_execution_modes(mode: &str) -> Vec<String> {
    if mode.eq_ignore_ascii_case("both") {
        return vec![String::from("strict"), String::from("hardened")];
    }
    vec![mode.to_string()]
}

fn category_for_family(family: &str) -> TestCategory {
    let family = family.to_ascii_lowercase();
    if family.contains("pthread") {
        return TestCategory::Sync;
    }
    if family.starts_with("time") {
        return TestCategory::Time;
    }
    if family.starts_with("signal") {
        return TestCategory::Cancel;
    }
    TestCategory::IO
}

fn run_one_case(
    campaign: &str,
    set: &FixtureSet,
    case: &FixtureCase,
    exec_mode: &str,
) -> (VerificationResult, SuiteTestResult) {
    let trace_id = format!(
        "{campaign}::{family}::{function}::{mode}::{case_name}",
        campaign = campaign,
        family = set.family,
        function = case.function,
        mode = exec_mode,
        case_name = case.name
    );

    let display_case_name = if case.mode.eq_ignore_ascii_case("both") {
        format!("{} [{}]", case.name, exec_mode)
    } else {
        case.name.clone()
    };

    let logger = ConformanceTestLogger::new(&display_case_name, &case.spec_section);
    logger.phase("execute");

    let start = Instant::now();
    let evidence = with_test_logger(&logger, || {
        execute_case_with_evidence(&trace_id, set, case, exec_mode)
    });
    let duration_ms = start.elapsed().as_millis() as u64;

    let verification = VerificationResult {
        case_name: display_case_name.clone(),
        spec_section: case.spec_section.clone(),
        passed: evidence.passed,
        expected: case.expected_output.clone(),
        actual: evidence.actual.clone(),
        diff: evidence.diff.clone(),
    };

    let mut result = if evidence.passed {
        TestResult::passed()
    } else {
        let msg = evidence
            .diff
            .clone()
            .unwrap_or_else(|| String::from("mismatch"));
        TestResult::failed(msg)
    };
    result.duration_ms = Some(duration_ms);
    result.checkpoints = evidence.checkpoints;

    let suite_item = SuiteTestResult {
        test_id: trace_id,
        test_name: display_case_name,
        category: category_for_family(&set.family),
        expected: case.expected_output.clone(),
        result,
        events: logger.events(),
    };

    (verification, suite_item)
}

#[derive(Debug)]
struct CaseEvidence {
    actual: String,
    diff: Option<String>,
    passed: bool,
    checkpoints: Vec<Checkpoint>,
}

fn execute_case_with_evidence(
    trace_id: &str,
    set: &FixtureSet,
    case: &FixtureCase,
    exec_mode: &str,
) -> CaseEvidence {
    // Evidence event stream (asupersync_conformance::logging thread-local).
    asupersync_conformance::checkpoint(
        "fixture.meta",
        json!({
            "trace_id": trace_id,
            "campaign": trace_id.split("::").next().unwrap_or(""),
            "family": &set.family,
            "function": &case.function,
            "case": &case.name,
            "mode": exec_mode,
            "spec_section": &case.spec_section,
        }),
    );
    asupersync_conformance::checkpoint(
        "fixture.inputs",
        json!({
            "inputs": &case.inputs,
            "expected_errno": case.expected_errno,
        }),
    );

    let mut checkpoints = Vec::new();
    checkpoints.push(Checkpoint::new(
        "meta",
        json!({
            "trace_id": trace_id,
            "family": &set.family,
            "function": &case.function,
            "case": &case.name,
            "mode": exec_mode,
            "spec_section": &case.spec_section,
        }),
    ));
    checkpoints.push(Checkpoint::new(
        "inputs",
        json!({
            "inputs": &case.inputs,
            "expected_errno": case.expected_errno,
        }),
    ));

    let execution = execute_fixture_case(&case.function, &case.inputs, exec_mode);
    match execution {
        Ok(run) => {
            let mut notes = Vec::new();
            if exec_mode.eq_ignore_ascii_case("strict") && !run.host_parity {
                notes.push(format!(
                    "strict host parity mismatch: host={}, impl={}",
                    run.host_output, run.impl_output
                ));
            }
            if let Some(note) = run.note.clone() {
                notes.push(note);
            }

            let mut diff_out = None;
            if run.impl_output != case.expected_output {
                diff_out = Some(diff::render_diff(&case.expected_output, &run.impl_output));
            } else if !notes.is_empty() {
                diff_out = Some(notes.join("\n"));
            }

            checkpoints.push(Checkpoint::new(
                "execution",
                json!({
                    "host_output": &run.host_output,
                    "impl_output": &run.impl_output,
                    "host_parity": run.host_parity,
                    "note": &run.note,
                    "notes": notes,
                    "diff": &diff_out,
                }),
            ));

            if let Some(diff_text) = diff_out.as_ref() {
                asupersync_conformance::checkpoint(
                    "fixture.diff",
                    json!({
                        "diff": diff_text,
                    }),
                );
            }

            CaseEvidence {
                actual: run.impl_output.clone(),
                diff: diff_out,
                passed: run.impl_output == case.expected_output,
                checkpoints,
            }
        }
        Err(err) => {
            let actual = format!("unsupported:{err}");
            let diff_out = Some(diff::render_diff(&case.expected_output, &actual));

            checkpoints.push(Checkpoint::new(
                "execution_error",
                json!({
                    "error": &err,
                }),
            ));

            if let Some(diff_text) = diff_out.as_ref() {
                asupersync_conformance::checkpoint(
                    "fixture.error",
                    json!({
                        "error": &err,
                        "diff": diff_text,
                    }),
                );
            }

            CaseEvidence {
                actual,
                diff: diff_out,
                passed: false,
                checkpoints,
            }
        }
    }
}
