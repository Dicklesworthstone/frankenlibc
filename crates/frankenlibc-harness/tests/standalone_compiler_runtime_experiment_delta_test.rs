//! Integration test: standalone compiler-runtime experiment delta (bd-zyck1.96).
//!
//! The panic-abort experiment is useful but partial: it removes two unwind
//! symbols and still leaves the artifact claim-blocked. This test keeps that
//! limitation explicit so future work cannot promote the lane by implication.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_standalone_compiler_runtime_experiment_delta.sh")
}

fn delta_manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("standalone_compiler_runtime_experiment_delta.v1.json")
}

fn experiment_manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("standalone_compiler_runtime_experiment.v1.json")
}

fn owned_unwinder_manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("standalone_owned_unwinder_symbol_surface.v1.json")
}

fn version_burndown_manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("standalone_host_version_requirement_burndown.v1.json")
}

fn load_json_path(path: &Path) -> TestResult<Value> {
    let content =
        std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("{}: {err}", path.display()))
}

fn json_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Value> {
    value
        .get(field)
        .ok_or_else(|| format!("{field} must be present"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    json_field(value, field)?
        .as_array()
        .ok_or_else(|| format!("{field} must be an array"))
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    json_field(value, field)?
        .as_str()
        .ok_or_else(|| format!("{field} must be a string"))
}

fn string_set(value: &Value, field: &str) -> TestResult<BTreeSet<String>> {
    json_array(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} entries must be strings"))
        })
        .collect()
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn run_checker(root: &Path, delta: &Path, label: &str) -> TestResult<(Output, PathBuf)> {
    let report = root.join("target/conformance").join(format!(
        "standalone_compiler_runtime_experiment_delta.{label}.report.json"
    ));
    let output = Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_STANDALONE_COMPILER_RUNTIME_DELTA", delta)
        .env(
            "FRANKENLIBC_STANDALONE_COMPILER_RUNTIME_DELTA_REPORT",
            &report,
        )
        .current_dir(root)
        .output()
        .map_err(|err| format!("failed to run compiler-runtime delta checker: {err}"))?;
    Ok((output, report))
}

fn format_output(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn expect_checker_failure(delta: &Path, label: &str, expected_error: &str) -> TestResult {
    let root = workspace_root()?;
    let (output, report) = run_checker(&root, delta, label)?;
    require(
        !output.status.success(),
        format!("checker unexpectedly passed\n{}", format_output(&output)),
    )?;
    let report_json = load_json_path(&report)?;
    let errors = json_array(&report_json, "errors")?;
    require(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains(expected_error)),
        format!("expected error {expected_error:?}; report={report_json:?}"),
    )
}

fn unique_label(prefix: &str) -> TestResult<String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system time before UNIX_EPOCH: {err}"))?
        .as_nanos();
    Ok(format!("{prefix}-{}-{nanos}", std::process::id()))
}

fn write_mutated_delta(
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let root = workspace_root()?;
    let mut delta = load_json_path(&delta_manifest_path(&root))?;
    mutate(&mut delta)?;
    let dir = root.join("target/conformance/mutated-compiler-runtime-deltas");
    std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    let path = dir.join(format!("{}.json", unique_label(label)?));
    let content = serde_json::to_string_pretty(&delta)
        .map_err(|err| format!("failed to serialize mutated delta: {err}"))?;
    std::fs::write(&path, format!("{content}\n"))
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(path)
}

fn set_object_field(value: &mut Value, field: &str, replacement: Value) -> TestResult {
    value
        .as_object_mut()
        .ok_or_else(|| "value must be an object".to_string())?
        .insert(field.to_owned(), replacement);
    Ok(())
}

fn observation_mut(delta: &mut Value) -> TestResult<&mut Value> {
    delta
        .get_mut("observation")
        .ok_or_else(|| "observation must be present".to_string())
}

#[test]
fn delta_manifest_records_partial_panic_abort_improvement() -> TestResult {
    let root = workspace_root()?;
    let delta = load_json_path(&delta_manifest_path(&root))?;
    let experiment = load_json_path(&experiment_manifest_path(&root))?;
    let owned = load_json_path(&owned_unwinder_manifest_path(&root))?;
    let version = load_json_path(&version_burndown_manifest_path(&root))?;

    require(
        json_string(&delta, "manifest_id")? == "standalone-compiler-runtime-experiment-delta",
        "manifest id",
    )?;
    require(json_string(&delta, "bead")? == "bd-zyck1.96", "bead")?;
    let observation = json_field(&delta, "observation")?;
    require(
        json_string(observation, "baseline_lane")?
            == json_string(json_field(&experiment, "summary")?, "baseline_lane")?,
        "baseline lane",
    )?;
    require(
        json_string(observation, "experiment_lane")?
            == json_string(json_field(&experiment, "summary")?, "experiment_lane")?,
        "experiment lane",
    )?;
    require(
        json_string(observation, "delta_classification")? == "improvement",
        "delta classification",
    )?;

    let owned_symbols: BTreeSet<_> = json_array(&owned, "symbol_rows")?
        .iter()
        .map(|row| json_string(row, "symbol").map(str::to_owned))
        .collect::<TestResult<_>>()?;
    let removed = string_set(observation, "removed_undefined_unwind_symbols")?;
    let remaining = string_set(observation, "remaining_undefined_unwind_symbols")?;
    require(
        removed
            == BTreeSet::from([
                "_Unwind_DeleteException@GCC_3.0".to_owned(),
                "_Unwind_RaiseException@GCC_3.0".to_owned(),
            ]),
        "removed unwind set",
    )?;
    require(
        remaining == owned_symbols.difference(&removed).cloned().collect(),
        "remaining unwind set",
    )?;
    let version_ids: BTreeSet<_> = json_array(&version, "version_requirement_matrix")?
        .iter()
        .map(|row| json_string(row, "requirement_id").map(str::to_owned))
        .collect::<TestResult<_>>()?;
    require(
        string_set(observation, "version_requirements_still_present")? == version_ids,
        "version requirements must remain fully present",
    )?;
    require(
        string_set(observation, "removed_version_requirements")?.is_empty(),
        "removed version requirements must stay empty",
    )?;
    require(
        json_field(json_field(&delta, "summary")?, "standalone_claim_status")?.as_str()
            == Some("claim_blocked"),
        "standalone claim status",
    )
}

#[test]
fn checker_materializes_delta_report() -> TestResult {
    let root = workspace_root()?;
    let delta = delta_manifest_path(&root);
    let (output, report) = run_checker(&root, &delta, "canonical")?;
    require(
        output.status.success(),
        format!("checker failed\n{}", format_output(&output)),
    )?;
    let report = load_json_path(&report)?;
    require(
        json_string(&report, "status")? == "pass",
        "report status must pass",
    )?;
    require(
        json_string(&report, "claim_status")? == "report_only",
        "experiment claim status",
    )?;
    require(
        json_string(&report, "standalone_claim_status")? == "claim_blocked",
        "standalone claim status",
    )?;
    require(
        json_array(&report, "removed_undefined_unwind_symbols")?.len() == 2,
        "removed unwind count",
    )?;
    require(
        json_array(&report, "remaining_undefined_unwind_symbols")?.len() == 10,
        "remaining unwind count",
    )?;
    require(
        json_array(&report, "version_requirements_still_present")?.len() == 4,
        "remaining version count",
    )
}

#[test]
fn checker_rejects_missing_removed_symbol() -> TestResult {
    let mutated = write_mutated_delta("missing-removed-symbol", |delta| {
        let observation = observation_mut(delta)?;
        set_object_field(
            observation,
            "removed_undefined_unwind_symbols",
            Value::Array(vec![Value::String(
                "_Unwind_DeleteException@GCC_3.0".to_owned(),
            )]),
        )
    })?;
    expect_checker_failure(
        &mutated,
        "missing-removed-symbol",
        "removed_undefined_unwind_symbols must record only the two observed panic-abort removals",
    )
}

#[test]
fn checker_rejects_remaining_symbol_drift() -> TestResult {
    let mutated = write_mutated_delta("remaining-symbol-drift", |delta| {
        let observation = observation_mut(delta)?;
        let rows = observation
            .get_mut("remaining_undefined_unwind_symbols")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "remaining_undefined_unwind_symbols must be an array".to_string())?;
        rows.retain(|value| value.as_str() != Some("_Unwind_SetIP@GCC_3.0"));
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "remaining-symbol-drift",
        "remaining_undefined_unwind_symbols must equal owned unwinder baseline symbols minus removed symbols",
    )
}

#[test]
fn checker_rejects_version_requirement_overclaim() -> TestResult {
    let mutated = write_mutated_delta("version-overclaim", |delta| {
        let observation = observation_mut(delta)?;
        set_object_field(
            observation,
            "removed_version_requirements",
            Value::Array(vec![Value::String("libgcc_s.so.1:GCC_3.0".to_owned())]),
        )
    })?;
    expect_checker_failure(
        &mutated,
        "version-overclaim",
        "observation.removed_version_requirements must stay empty",
    )
}

#[test]
fn checker_rejects_standalone_promotion_claim() -> TestResult {
    let mutated = write_mutated_delta("promotion-overclaim", |delta| {
        let summary = delta
            .get_mut("summary")
            .ok_or_else(|| "summary must be present".to_string())?;
        set_object_field(
            summary,
            "standalone_claim_status",
            Value::String("standalone_evidence_passed".to_owned()),
        )
    })?;
    expect_checker_failure(
        &mutated,
        "promotion-overclaim",
        "summary.standalone_claim_status must be claim_blocked",
    )
}

#[test]
fn checker_rejects_stale_source_commit() -> TestResult {
    let mutated = write_mutated_delta("stale-source", |delta| {
        set_object_field(
            delta,
            "source_commit",
            Value::String("0000000000000000000000000000000000000000".to_owned()),
        )
    })?;
    expect_checker_failure(
        &mutated,
        "stale-source",
        "delta source_commit must be 'current' or match current git HEAD",
    )
}
