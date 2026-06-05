use serde_json::{Value, json};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| invalid_data("crate directory has workspace parent"))?
        .parent()
        .ok_or_else(|| invalid_data("workspace parent has repo parent"))?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/v1_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_v1_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "v1_completion_contract_{label}_{}_{}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn repo_relative(root: &Path, path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/"))
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_V1_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_V1_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_V1_COMPLETION_REPORT",
            out_dir.join("v1_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_V1_COMPLETION_LOG",
            out_dir.join("v1_completion_contract.log.jsonl"),
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

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn json_array<'a>(value: &'a Value, name: &str) -> TestResult<&'a [Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid_data(format!("{name} must be array")).into())
}

fn json_str<'a>(value: &'a Value, name: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| invalid_data(format!("{name} must be string")).into())
}

fn json_u64(value: &Value, name: &str) -> TestResult<u64> {
    value
        .as_u64()
        .ok_or_else(|| invalid_data(format!("{name} must be u64")).into())
}

fn function_exists(root: &Path, source_path: &str, name: &str) -> TestResult<bool> {
    let text = std::fs::read_to_string(root.join(source_path))?;
    Ok(text.contains(&format!("fn {name}(")) || text.contains(&format!("fn {name}<")))
}

#[test]
fn manifest_binds_v1_completion_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("v1_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-2uro"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-2uro.1"));
    assert!(
        json_u64(
            &manifest["next_audit_score_threshold"],
            "next_audit_score_threshold"
        )? >= 800
    );

    let artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;
    for (artifact_id, path) in artifacts {
        let path = path.as_str().ok_or("artifact path must be string")?;
        assert!(
            root.join(path).exists(),
            "source artifact {artifact_id} missing at {path}"
        );
    }

    let bindings = json_array(&manifest["missing_item_bindings"], "missing_item_bindings")?;
    let mut item_ids: Vec<&str> = bindings
        .iter()
        .filter_map(|binding| binding["id"].as_str())
        .collect();
    item_ids.sort_unstable();
    assert_eq!(
        item_ids,
        vec![
            "telemetry.primary",
            "tests.conformance.primary",
            "tests.e2e.primary",
            "tests.fuzz.primary",
            "tests.unit.primary"
        ]
    );

    let support = &manifest["claimed_closure_contract"]["support_matrix"];
    assert_eq!(support["expected_total_exported"].as_u64(), Some(4119));
    assert_eq!(support["expected_native_total"].as_u64(), Some(2809));
    assert_eq!(support["expected_glibc_callthrough"].as_u64(), Some(0));
    assert_eq!(support["expected_stub"].as_u64(), Some(0));

    let smoke = &manifest["claimed_closure_contract"]["ld_preload_smoke"];
    assert_eq!(smoke["expected_total_cases"].as_u64(), Some(64));
    assert_eq!(smoke["expected_passes"].as_u64(), Some(60));
    assert_eq!(smoke["expected_fails"].as_u64(), Some(0));
    assert_eq!(smoke["expected_skips"].as_u64(), Some(4));

    for binding in bindings {
        for test_ref in json_array(&binding["required_test_refs"], "required_test_refs")? {
            let source_id = json_str(&test_ref["source"], "required_test_refs.source")?;
            let name = json_str(&test_ref["name"], "required_test_refs.name")?;
            let source_path = artifacts
                .get(source_id)
                .ok_or_else(|| invalid_data(format!("missing source artifact {source_id}")))
                .and_then(|artifact| {
                    artifact.as_str().ok_or_else(|| {
                        invalid_data(format!("source artifact {source_id} must be string"))
                    })
                })?;
            assert!(
                function_exists(&root, source_path, name)?,
                "missing test ref {source_id}::{name}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("v1_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("v1_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-2uro"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-2uro.1"));
    assert_eq!(
        report["summaries"]["bindings"]["binding_count"].as_u64(),
        Some(5)
    );
    assert_eq!(
        report["summaries"]["claims"]["native_total"].as_u64(),
        Some(2809)
    );
    assert_eq!(
        report["summaries"]["claims"]["smoke_passes"].as_u64(),
        Some(60)
    );
    assert_eq!(
        report["summaries"]["claims"]["proof_valid_obligations"].as_u64(),
        Some(24)
    );

    let rows = read_jsonl(&out_dir.join("v1_completion_contract.log.jsonl"))?;
    let events: Vec<&str> = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect();
    for expected in [
        "v1_completion_sources_bound",
        "v1_completion_missing_items_bound",
        "v1_completion_claims_validated",
        "v1_completion_telemetry_validated",
        "v1_completion_contract_pass",
    ] {
        assert!(events.contains(&expected), "missing event {expected}");
    }
    for row in rows {
        for field in [
            "timestamp",
            "event",
            "source_bead",
            "completion_debt_bead",
            "status",
            "artifact_refs",
            "failure_signature",
            "details",
        ] {
            assert!(!row[field].is_null(), "log record missing {field}: {row}");
        }
    }

    Ok(())
}

#[test]
fn checker_rejects_support_matrix_callthrough_drift() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "support_drift")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let mut support = read_json(&root.join("support_matrix.json"))?;
    support["summary"]["glibc_call_through"] = json!(1);
    let support_path = out_dir.join("mutated_support_matrix.json");
    write_json(&support_path, &support)?;
    manifest["source_artifacts"]["support_matrix"] = json!(repo_relative(&root, &support_path)?);
    let mutated = out_dir.join("contract_support_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject support-matrix callthrough drift:\n{}",
        output_text(&output)
    );
    let report = read_json(&out_dir.join("v1_completion_contract.report.json"))?;
    let errors = json_array(&report["errors"], "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or("")
            .contains("support_matrix.glibc_call_through drift")),
        "expected support-matrix callthrough drift error, got {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_bare_cargo_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "bare_cargo")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["missing_item_bindings"][0]["required_commands"][0] =
        json!("cargo test -p frankenlibc-harness --test v1_completion_contract_test");
    let mutated = out_dir.join("contract_bare_cargo.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject bare cargo command:\n{}",
        output_text(&output)
    );
    let report = read_json(&out_dir.join("v1_completion_contract.report.json"))?;
    let errors = json_array(&report["errors"], "errors")?;
    assert!(
        errors
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("bare cargo")),
        "expected bare cargo error, got {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_required_event() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "event_drift")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let events = manifest["telemetry_contract"]["required_events"]
        .as_array_mut()
        .ok_or("required_events must be array")?;
    events.retain(|event| event.as_str() != Some("v1_completion_claims_validated"));
    let mutated = out_dir.join("contract_event_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry event:\n{}",
        output_text(&output)
    );
    let report = read_json(&out_dir.join("v1_completion_contract.report.json"))?;
    let errors = json_array(&report["errors"], "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or("")
            .contains("telemetry_contract.required_events mismatch")),
        "expected telemetry event drift error, got {errors:?}"
    );

    Ok(())
}
