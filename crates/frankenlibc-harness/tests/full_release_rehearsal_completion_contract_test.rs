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
    root.join("tests/release/full_release_rehearsal_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_full_release_rehearsal_completion_contract.sh")
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

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/release").join(format!(
        "full_release_rehearsal_completion_contract_{label}_{}_{}",
        std::process::id(),
        stamp
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
        .env(
            "FRANKENLIBC_FULL_RELEASE_REHEARSAL_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_FULL_RELEASE_REHEARSAL_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_FULL_RELEASE_REHEARSAL_COMPLETION_REPORT",
            out_dir.join("full_release_rehearsal_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_FULL_RELEASE_REHEARSAL_COMPLETION_LOG",
            out_dir.join("full_release_rehearsal_completion_contract.log.jsonl"),
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

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()?)
}

fn function_name_exists(root: &Path, source_path: &str, name: &str) -> TestResult<bool> {
    let text = std::fs::read_to_string(root.join(source_path))?;
    Ok(text.contains(&format!("fn {name}(")) || text.contains(&format!("fn {name}<")))
}

#[test]
fn manifest_binds_full_release_rehearsal_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("full_release_rehearsal_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-226"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-226.1"));
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
            "tests.conformance.primary",
            "tests.e2e.primary",
            "tests.unit.primary"
        ]
    );

    let sequence = manifest["required_rehearsal_contract"]["release_gate_sequence"]
        .as_array()
        .ok_or("release_gate_sequence must be array")?;
    assert_eq!(sequence.len(), 9);

    let smoke = &manifest["required_rehearsal_contract"]["ld_preload_smoke"];
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
                function_name_exists(&root, source_path, name)?,
                "missing test ref {source_id}::{name}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_emits_release_rehearsal_report_and_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        read_json(&out_dir.join("full_release_rehearsal_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("full_release_rehearsal_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-226"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-226.1"));
    assert_eq!(
        report["summaries"]["bindings"]["binding_count"].as_u64(),
        Some(3)
    );
    assert_eq!(report["summaries"]["dag"]["gate_count"].as_u64(), Some(9));
    assert_eq!(
        report["summaries"]["smoke"]["summary"]["passes"].as_u64(),
        Some(60)
    );
    assert_eq!(
        report["command_results"]["replacement_levels_checker"]["status"].as_str(),
        Some("pass")
    );

    let rows = read_jsonl(&out_dir.join("full_release_rehearsal_completion_contract.log.jsonl"))?;
    let events: Vec<&str> = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect();
    for expected in [
        "full_release_rehearsal_sources_bound",
        "full_release_rehearsal_dag_replayed",
        "full_release_rehearsal_dossier_bound",
        "full_release_rehearsal_smoke_bound",
        "full_release_rehearsal_completion_contract_pass",
    ] {
        assert!(events.contains(&expected), "missing event {expected}");
    }
    for row in rows {
        for field in [
            "event",
            "source_bead",
            "completion_debt_bead",
            "status",
            "artifact_refs",
            "failure_signature",
        ] {
            assert!(!row[field].is_null(), "log record missing {field}: {row}");
        }
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_smoke_pass_count() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "smoke_drift")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let mut smoke = read_json(&root.join("tests/conformance/ld_preload_smoke_summary.v1.json"))?;
    smoke["summary"]["passes"] = json!(57);
    let smoke_path = out_dir.join("mutated_ld_preload_smoke_summary.v1.json");
    write_json(&smoke_path, &smoke)?;
    manifest["source_artifacts"]["ld_preload_smoke_summary"] =
        json!(repo_relative(&root, &smoke_path)?);
    let mutated = out_dir.join("contract_smoke_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject smoke pass-count drift:\n{}",
        output_text(&output)
    );
    let report =
        read_json(&out_dir.join("full_release_rehearsal_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = json_array(&report["errors"], "errors")?;
    assert!(
        errors
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("passes drift")),
        "expected smoke passes drift error, got {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_dossier_artifact_floor_drift() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "dossier_floor")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_rehearsal_contract"]["dossier"]["min_total_artifacts"] = json!(9999);
    let mutated = out_dir.join("contract_dossier_floor.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject dossier artifact floor drift:\n{}",
        output_text(&output)
    );
    let report =
        read_json(&out_dir.join("full_release_rehearsal_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = json_array(&report["errors"], "errors")?;
    assert!(
        errors.iter().any(|error| {
            error
                .as_str()
                .unwrap_or("")
                .contains("total_artifacts below contract floor")
        }),
        "expected dossier floor error, got {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_completion_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_binding")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let bindings = manifest["missing_item_bindings"]
        .as_array_mut()
        .ok_or("missing_item_bindings must be array")?;
    bindings.retain(|binding| binding["id"].as_str() != Some("tests.e2e.primary"));
    let mutated = out_dir.join("contract_missing_binding.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing completion binding:\n{}",
        output_text(&output)
    );
    let report =
        read_json(&out_dir.join("full_release_rehearsal_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = json_array(&report["errors"], "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or("")
            .contains("missing_item_bindings ids mismatch")),
        "expected binding mismatch error, got {errors:?}"
    );

    Ok(())
}
