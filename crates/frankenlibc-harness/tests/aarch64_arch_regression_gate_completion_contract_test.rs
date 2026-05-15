//! Completion contract tests for bd-1gg.4.1 aarch64 arch regression evidence.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static CHECKER_LOCK: Mutex<()> = Mutex::new(());

fn workspace_root() -> TestResult<PathBuf> {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory should have workspace parent")?;
    let root = crate_dir
        .parent()
        .ok_or("workspace parent should have repo parent")?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/aarch64_arch_regression_gate_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_aarch64_arch_regression_gate_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "aarch64-arch-regression-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_AARCH64_ARCH_REGRESSION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_AARCH64_ARCH_REGRESSION_REPORT",
            out_dir.join("aarch64_arch_regression_gate_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_AARCH64_ARCH_REGRESSION_LOG",
            out_dir.join("aarch64_arch_regression_gate_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_passing_checker(root: &Path, label: &str) -> TestResult<PathBuf> {
    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let out_dir = unique_out_dir(root, label)?;
    let output = run_checker(root, &contract_path(root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));
    Ok(out_dir)
}

fn value_array<'a>(value: &'a Value, context: &str) -> TestResult<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| format!("{context} must be an array").into())
}

fn value_object<'a>(
    value: &'a Value,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| format!("{context} must be an object").into())
}

fn value_str<'a>(value: &'a Value, context: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| format!("{context} must be a string").into())
}

fn string_set(value: &Value, context: &str) -> TestResult<BTreeSet<String>> {
    value_array(value, context)?
        .iter()
        .enumerate()
        .map(|(index, value)| Ok(value_str(value, &format!("{context}[{index}]"))?.to_string()))
        .collect()
}

#[test]
fn manifest_binds_all_completion_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("aarch64_arch_regression_gate_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-1gg.4"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-1gg.4.1")
    );

    let item_ids: BTreeSet<String> =
        value_array(&manifest["missing_item_bindings"], "missing_item_bindings")?
            .iter()
            .enumerate()
            .map(|(index, item)| {
                Ok(
                    value_str(&item["id"], &format!("missing_item_bindings[{index}].id"))?
                        .to_string(),
                )
            })
            .collect::<TestResult<_>>()?;
    assert_eq!(
        item_ids,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.fuzz.primary".to_string(),
            "tests.conformance.primary".to_string(),
            "telemetry.primary".to_string(),
        ])
    );

    assert!(value_object(&manifest["source_artifacts"], "source_artifacts")?.len() >= 15);
    assert_eq!(
        value_array(
            &manifest["deterministic_fuzz_seeds"],
            "deterministic_fuzz_seeds",
        )?
        .len(),
        5
    );
    assert_eq!(
        manifest["required_source_contract"]["conformance_matrix"]["minimum_total_cases"].as_u64(),
        Some(1700)
    );

    let telemetry_events = string_set(
        &manifest["required_source_contract"]["telemetry"]["required_events"],
        "required_source_contract.telemetry.required_events",
    )?;
    for required in [
        "aarch64_arch_regression_completion.source_artifact_bound",
        "aarch64_arch_regression_completion.matrix_bound",
        "aarch64_arch_regression_completion.perf_bound",
        "aarch64_arch_regression_completion.crosscompile_gate_bound",
        "aarch64_arch_regression_completion.fuzz_seed_replayed",
        "aarch64_arch_regression_completion.validated",
    ] {
        assert!(telemetry_events.contains(required));
    }

    Ok(())
}

#[test]
fn checker_passes_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "pass")?;

    let report =
        read_json(&out_dir.join("aarch64_arch_regression_gate_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["schema_version"].as_str(),
        Some("aarch64_arch_regression_gate_completion_contract.report.v1")
    );
    assert_eq!(report["source_bead"].as_str(), Some("bd-1gg.4"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-1gg.4.1"));
    assert!(
        report["summary"]["environment"]["aarch64_rows"]
            .as_u64()
            .unwrap_or_default()
            >= 1
    );
    assert!(
        report["summary"]["conformance"]["case_count"]
            .as_u64()
            .unwrap_or_default()
            >= 1700
    );
    assert_eq!(report["summary"]["performance"]["issues"].as_u64(), Some(0));
    assert_eq!(
        report["summary"]["deterministic_fuzz"]["seed_count"].as_u64(),
        Some(5)
    );

    let rows =
        read_jsonl(&out_dir.join("aarch64_arch_regression_gate_completion_contract.log.jsonl"))?;
    let events: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row["event"].as_str().map(str::to_owned))
        .collect();
    for required in [
        "aarch64_arch_regression_completion.source_artifact_bound",
        "aarch64_arch_regression_completion.matrix_bound",
        "aarch64_arch_regression_completion.perf_bound",
        "aarch64_arch_regression_completion.crosscompile_gate_bound",
        "aarch64_arch_regression_completion.fuzz_seed_replayed",
        "aarch64_arch_regression_completion.validated",
    ] {
        assert!(
            events.contains(required),
            "missing telemetry event {required}: {events:?}"
        );
    }

    for row in rows {
        for field in [
            "timestamp",
            "trace_id",
            "event",
            "bead_id",
            "original_bead",
            "completion_debt_bead",
            "status",
            "outcome",
            "arch",
            "suite",
            "perf_delta",
            "conformance_delta",
            "verdict",
            "artifact_refs",
            "source_commit",
            "runtime_mode",
            "failure_signature",
        ] {
            assert!(row.get(field).is_some(), "log row missing {field}: {row}");
        }
    }

    Ok(())
}

#[test]
fn source_refs_resolve_to_nonblank_lines() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    let refs = manifest["completion_debt_evidence"]["implementation_refs"]
        .as_array()
        .ok_or("implementation_refs must be array")?;

    for item in refs {
        let path = root.join(item["path"].as_str().ok_or("ref path")?);
        let line = item["line"].as_u64().ok_or("ref line")? as usize;
        let required = item["required_text"].as_str().ok_or("required text")?;
        let text = std::fs::read_to_string(&path)?;
        let actual = text
            .lines()
            .nth(line - 1)
            .ok_or_else(|| format!("{}:{} past EOF", path.display(), line))?;
        assert!(
            !actual.trim().is_empty(),
            "{}:{} should be nonblank",
            path.display(),
            line
        );
        assert!(
            actual.contains(required),
            "{}:{} missing required text {required:?}: {actual}",
            path.display(),
            line
        );
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_architecture_requirement() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "missing-arch")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_source_contract"]["environment_matrix"]["required_architectures"]
        .as_array_mut()
        .ok_or("required_architectures")?
        .push(json!("riscv64"));
    let mutated = out_dir.join("contract_missing_architecture.json");
    write_json(&mutated, &manifest)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly passed:\n{}",
        output_text(&output)
    );
    let report =
        read_json(&out_dir.join("aarch64_arch_regression_gate_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        value_array(&report["errors"], "errors")?
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("riscv64")),
        "expected missing architecture error: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_fuzz_seed_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "missing-fuzz-seeds")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["deterministic_fuzz_seeds"] = json!([]);
    let mutated = out_dir.join("contract_missing_fuzz_seed.json");
    write_json(&mutated, &manifest)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly passed:\n{}",
        output_text(&output)
    );
    let report =
        read_json(&out_dir.join("aarch64_arch_regression_gate_completion_contract.report.json"))?;
    assert!(
        value_array(&report["errors"], "errors")?
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("fuzz seed count")),
        "expected fuzz seed count error: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_unknown_telemetry_field() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "unknown-telemetry")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_source_contract"]["telemetry"]["required_log_fields"]
        .as_array_mut()
        .ok_or("required_log_fields")?
        .push(json!("not_emitted_by_completion_checker"));
    let mutated = out_dir.join("contract_unknown_telemetry.json");
    write_json(&mutated, &manifest)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly passed:\n{}",
        output_text(&output)
    );
    let report =
        read_json(&out_dir.join("aarch64_arch_regression_gate_completion_contract.report.json"))?;
    assert!(
        value_array(&report["errors"], "errors")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("not_emitted_by_completion_checker")),
        "expected telemetry field error: {report}"
    );

    Ok(())
}
