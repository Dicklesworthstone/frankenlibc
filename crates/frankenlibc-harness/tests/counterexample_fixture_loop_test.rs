//! Integration test: counterexample-to-fixture loop gate (bd-bp8fl.9.1)
//!
//! Validates that proof, parity, runtime-math, and conformance counterexamples
//! are converted into deterministic replay fixtures or explicitly blocked.

use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn Error>>;

const REQUIRED_SOURCES: &[&str] = &[
    "proof_failure",
    "differential_mismatch",
    "runtime_math_alarm",
    "conformance_failure",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "counterexample_id",
    "symbol",
    "api_family",
    "minimization_state",
    "fixture_id",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(test_error(message))
    }
}

fn ensure_eq<T>(actual: T, expected: T, context: impl Into<String>) -> TestResult
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(test_error(format!(
            "{}: expected {:?}, got {:?}",
            context.into(),
            expected,
            actual
        )))
    }
}

fn as_array<'a>(value: &'a Value, context: &str) -> Result<&'a Vec<Value>, Box<dyn Error>> {
    value
        .as_array()
        .ok_or_else(|| test_error(format!("{context} must be an array")))
}

fn as_str<'a>(value: &'a Value, context: &str) -> Result<&'a str, Box<dyn Error>> {
    value
        .as_str()
        .ok_or_else(|| test_error(format!("{context} must be a string")))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn load_loop_artifact() -> Result<Value, Box<dyn Error>> {
    load_json(&workspace_root().join("tests/conformance/counterexample_fixture_loop.v1.json"))
}

fn run_script(args: &[&str]) -> Result<Output, Box<dyn Error>> {
    let root = workspace_root();
    Command::new("bash")
        .arg(root.join("scripts/check_counterexample_fixture_loop.sh"))
        .args(args)
        .current_dir(&root)
        .output()
        .map_err(|err| {
            test_error(format!(
                "counterexample fixture loop script failed to run: {err}"
            ))
        })
}

fn ensure_success(output: &Output, context: &str) -> TestResult {
    ensure(
        output.status.success(),
        format!(
            "{context} failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

#[test]
fn artifact_declares_required_sources_and_log_contract() -> TestResult {
    let artifact = load_loop_artifact()?;
    ensure_eq(
        artifact["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(artifact["bead"].as_str(), Some("bd-bp8fl.9.1"), "bead")?;
    ensure(
        artifact["counterexamples"].is_array(),
        "counterexamples must be an array",
    )?;
    ensure(
        artifact["negative_tests"].is_array(),
        "negative_tests must be an array",
    )?;

    let mut sources = HashSet::new();
    for source in as_array(&artifact["required_sources"], "required_sources")? {
        sources.insert(as_str(source, "required_sources[]")?);
    }
    for source in REQUIRED_SOURCES {
        ensure(sources.contains(source), format!("missing source {source}"))?;
    }

    let mut fields = Vec::new();
    for field in as_array(&artifact["required_log_fields"], "required_log_fields")? {
        fields.push(as_str(field, "required_log_fields[]")?);
    }
    ensure_eq(fields, REQUIRED_LOG_FIELDS.to_vec(), "required_log_fields")
}

#[test]
fn counterexample_rows_are_unique_replayable_or_explicitly_blocked() -> TestResult {
    let root = workspace_root();
    let artifact = load_loop_artifact()?;
    let rows = as_array(&artifact["counterexamples"], "counterexamples")?;
    ensure_eq(rows.len(), 5_usize, "counterexample row count")?;

    let mut ids = HashSet::new();
    let mut generated_fixture_ids = HashSet::new();
    let mut source_counts: HashMap<&str, usize> = HashMap::new();
    let mut has_pass_replay = false;
    let mut has_fail_replay = false;
    let mut has_blocked = false;

    for row in rows {
        let id = as_str(&row["id"], "counterexample.id")?;
        ensure(ids.insert(id), format!("duplicate counterexample id {id}"))?;
        let source = as_str(&row["source"], "counterexample.source")?;
        *source_counts.entry(source).or_default() += 1;
        ensure(
            REQUIRED_SOURCES.contains(&source),
            format!("{id}: invalid source {source}"),
        )?;

        let proof_link = as_str(&row["proof_link"], "counterexample.proof_link")?;
        ensure(
            root.join(proof_link).exists(),
            format!("{id}: proof_link must exist: {proof_link}"),
        )?;
        for artifact_ref in as_array(&row["artifact_refs"], "counterexample.artifact_refs")? {
            let artifact_ref = as_str(artifact_ref, "counterexample.artifact_refs[]")?;
            ensure(
                root.join(artifact_ref).exists(),
                format!("{id}: artifact ref must exist: {artifact_ref}"),
            )?;
        }

        let generation = as_str(
            &row["fixture_generation"],
            "counterexample.fixture_generation",
        )?;
        let state = as_str(
            &row["minimization_state"],
            "counterexample.minimization_state",
        )?;
        match generation {
            "generate" => {
                let fixture_id = as_str(&row["fixture_id"], "counterexample.fixture_id")?;
                ensure(
                    generated_fixture_ids.insert(fixture_id),
                    format!("duplicate fixture id {fixture_id}"),
                )?;
                ensure(
                    !as_array(&row["replay_command"], "counterexample.replay_command")?.is_empty(),
                    format!("{id}: generated fixture requires replay command"),
                )?;
            }
            "plan_only" => {
                ensure(
                    row["fixture_id"].as_str().is_some(),
                    format!("{id}: plan-only fixture still needs a fixture id"),
                )?;
            }
            "blocked" => {
                has_blocked = true;
                ensure_eq(
                    state,
                    "unsupported",
                    format!("{id}: blocked rows must be unsupported"),
                )?;
                ensure(
                    row["fixture_id"].is_null(),
                    format!("{id}: blocked rows must not emit fixtures"),
                )?;
            }
            other => {
                return Err(test_error(format!(
                    "{id}: unexpected fixture_generation {other}"
                )));
            }
        }

        match as_str(
            &row["expected_replay_result"],
            "counterexample.expected_replay_result",
        )? {
            "pass" => has_pass_replay = true,
            "fail" => has_fail_replay = true,
            "blocked" => has_blocked = true,
            other => {
                return Err(test_error(format!(
                    "{id}: unexpected replay result {other}"
                )));
            }
        }
    }

    for source in REQUIRED_SOURCES {
        ensure(
            source_counts.contains_key(source),
            format!("counterexamples must cover {source}"),
        )?;
    }
    ensure(has_pass_replay, "at least one replay fixture must pass")?;
    ensure(
        has_fail_replay,
        "at least one replay fixture must preserve failure",
    )?;
    ensure(
        has_blocked,
        "unsupported counterexamples must be represented",
    )
}

#[test]
fn gate_materializes_fixtures_report_and_structured_log() -> TestResult {
    let root = workspace_root();
    let output = run_script(&[])?;
    ensure_success(&output, "counterexample fixture loop gate")?;

    let report_path = root.join("target/conformance/counterexample_fixture_loop.report.json");
    let log_path = root.join("target/conformance/counterexample_fixture_loop.log.jsonl");
    let report = load_json(&report_path)?;
    ensure_eq(
        report["schema_version"].as_str(),
        Some("v1"),
        "report schema_version",
    )?;
    ensure_eq(report["bead"].as_str(), Some("bd-bp8fl.9.1"), "report bead")?;
    ensure_eq(report["status"].as_str(), Some("pass"), "report status")?;
    ensure_eq(
        report["counterexample_count"].as_u64(),
        Some(5),
        "counterexample_count",
    )?;
    ensure_eq(
        report["generated_fixture_count"].as_u64(),
        Some(2),
        "generated_fixture_count",
    )?;

    let materialized = as_array(&report["materialized_fixtures"], "materialized_fixtures")?;
    ensure_eq(materialized.len(), 2_usize, "materialized fixture count")?;
    for path in materialized {
        let path = root.join(as_str(path, "materialized_fixtures[]")?);
        let fixture = load_json(&path)?;
        ensure_eq(
            fixture["schema_version"].as_str(),
            Some("v1"),
            "fixture schema_version",
        )?;
        ensure_eq(
            fixture["bead"].as_str(),
            Some("bd-bp8fl.9.1"),
            "fixture bead",
        )?;
        ensure(
            fixture["counterexample_id"].as_str().is_some(),
            "fixture counterexample_id must exist",
        )?;
        ensure(
            fixture["source_commit"].as_str().is_some(),
            "fixture source_commit must exist",
        )?;
    }

    let log = std::fs::read_to_string(log_path)
        .map_err(|err| test_error(format!("structured log should exist: {err}")))?;
    let mut event_count = 0_usize;
    for line in log.lines() {
        let event: Value = serde_json::from_str(line)
            .map_err(|err| test_error(format!("structured log line should parse: {err}")))?;
        event_count += 1;
        for field in REQUIRED_LOG_FIELDS {
            ensure(
                event.get(*field).is_some(),
                format!("structured log missing field {field}"),
            )?;
        }
    }
    ensure_eq(event_count, 5_usize, "structured log event count")
}

#[test]
fn replay_commands_verify_pass_fail_and_blocked_outcomes() -> TestResult {
    let gate_output = run_script(&[])?;
    ensure_success(&gate_output, "gate before replay")?;

    let pass = run_script(&["--replay", "ce-diff-strlen-empty", "--expect", "pass"])?;
    ensure_success(&pass, "pass replay")?;

    let fail = run_script(&[
        "--replay",
        "ce-runtime-math-eprocess-alarm",
        "--expect",
        "fail",
    ])?;
    ensure_success(&fail, "fail replay")?;

    let blocked = run_script(&[
        "--replay",
        "ce-unsupported-rtld-hwcaps",
        "--expect",
        "blocked",
    ])?;
    ensure_success(&blocked, "blocked replay")
}

#[test]
fn negative_tests_cover_duplicate_stale_unsupported_and_replay_regressions() -> TestResult {
    let artifact = load_loop_artifact()?;
    let negatives = as_array(&artifact["negative_tests"], "negative_tests")?;
    let mut signatures = HashSet::new();
    for row in negatives {
        signatures.insert(as_str(
            &row["expected_failure_signature"],
            "negative_tests[].expected_failure_signature",
        )?);
    }
    for signature in [
        "duplicate_fixture_id",
        "missing_proof_link",
        "unsupported_counterexample_generated",
        "missing_replay_command",
    ] {
        ensure(
            signatures.contains(signature),
            format!("missing negative test signature {signature}"),
        )?;
    }
    Ok(())
}
