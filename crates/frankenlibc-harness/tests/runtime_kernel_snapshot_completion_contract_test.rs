use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory must have workspace parent")?
        .parent()
        .ok_or("workspace parent must have repo root")?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/runtime_kernel_snapshot_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_kernel_snapshot_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
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
    let path = root.join("target/conformance").join(format!(
        "runtime-kernel-snapshot-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_RUNTIME_KERNEL_SNAPSHOT_CONTRACT", contract)
        .env("FRANKENLIBC_RUNTIME_KERNEL_SNAPSHOT_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_RUNTIME_KERNEL_SNAPSHOT_REPORT",
            out_dir.join("runtime_kernel_snapshot_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RUNTIME_KERNEL_SNAPSHOT_LOG",
            out_dir.join("runtime_kernel_snapshot_completion_contract.log.jsonl"),
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

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let values = value.as_array().ok_or("value must be an array")?;
    values
        .iter()
        .map(|item| {
            Ok(item
                .as_str()
                .ok_or("array item must be a string")?
                .to_string())
        })
        .collect()
}

fn assert_checker_failed(output: &Output) {
    assert!(
        !output.status.success(),
        "checker unexpectedly passed:\n{}",
        output_text(output)
    );
}

#[test]
fn manifest_binds_runtime_kernel_snapshot_unit_and_e2e_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("runtime_kernel_snapshot_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-oai.2"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-oai.2.1")
    );
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
        ])
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;
    for (artifact_id, path) in source_artifacts {
        let rel = path.as_str().ok_or("source artifact path must be string")?;
        assert!(
            root.join(rel).is_file(),
            "source artifact {artifact_id} missing at {rel}"
        );
    }

    let contract = &manifest["required_snapshot_contract"];
    assert_eq!(contract["minimum_snapshot_fields"].as_u64(), Some(154));
    assert_eq!(contract["current_snapshot_fields"].as_u64(), Some(188));
    assert_eq!(contract["snapshot_schema_version"].as_u64(), Some(2));
    assert_eq!(
        contract["scenario"]["id"].as_str(),
        Some("runtime_math_kernel_snapshot_smoke")
    );
    assert_eq!(contract["scenario"]["steps"].as_u64(), Some(512));
    assert_eq!(contract["modes"], json!(["strict", "hardened"]));

    let unit_names: BTreeSet<_> =
        manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"]
            .as_array()
            .ok_or("unit required test refs must be array")?
            .iter()
            .map(|entry| {
                Ok(entry["name"]
                    .as_str()
                    .ok_or("unit test ref name must be string")?
                    .to_string())
            })
            .collect::<TestResult<_>>()?;
    for name in [
        "runtime_kernel_snapshot_schema_and_literal_cover_all_fields",
        "snapshot_literal_never_relocks_summary_mutexes",
        "fixture_serializes_structured_snapshot_payload",
        "diff_kernel_snapshots_uses_structured_snapshot_payloads",
    ] {
        assert!(unit_names.contains(name), "missing unit binding {name}");
    }

    let e2e_names: BTreeSet<_> =
        manifest["completion_debt_evidence"]["e2e_primary"]["required_test_refs"]
            .as_array()
            .ok_or("e2e required test refs must be array")?
            .iter()
            .map(|entry| {
                Ok(entry["name"]
                    .as_str()
                    .ok_or("e2e test ref name must be string")?
                    .to_string())
            })
            .collect::<TestResult<_>>()?;
    assert!(e2e_names.contains("runtime_math_kernel_snapshot_golden_checksum_matches_manifest"));
    assert!(e2e_names.contains("checker_rejects_golden_hash_drift"));

    Ok(())
}

#[test]
fn checker_validates_snapshot_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "valid")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        read_json(&out_dir.join("runtime_kernel_snapshot_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("runtime_kernel_snapshot_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-oai.2"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-oai.2.1"));
    assert_eq!(
        report["snapshot_contract"]["struct_field_count"].as_u64(),
        Some(188)
    );
    assert_eq!(
        report["snapshot_contract"]["strict_field_count"].as_u64(),
        Some(188)
    );
    assert_eq!(
        report["snapshot_contract"]["hardened_field_count"].as_u64(),
        Some(188)
    );
    assert_eq!(
        report["snapshot_contract"]["sha256"].as_str(),
        Some("90ee952d0398f187d583ce552014cad53d102c5102118ab6e83b6e1b788a7651")
    );
    assert_eq!(report["events"].as_array().map(Vec::len), Some(4));

    let rows = read_jsonl(&out_dir.join("runtime_kernel_snapshot_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .map(|row| {
            Ok(row["event"]
                .as_str()
                .ok_or("log row event must be string")?
                .to_string())
        })
        .collect::<TestResult<_>>()?;
    for event in [
        "runtime_kernel_snapshot_unit_bindings_verified",
        "runtime_kernel_snapshot_golden_verified",
        "runtime_kernel_snapshot_e2e_bindings_verified",
        "runtime_kernel_snapshot_completion_contract_pass",
    ] {
        assert!(events.contains(event), "missing event {event}");
    }
    for row in rows {
        for field in [
            "timestamp",
            "trace_id",
            "event",
            "bead_id",
            "source_bead",
            "completion_debt_bead",
            "source_commit",
            "status",
            "outcome",
            "artifact_refs",
            "failure_signature",
            "details",
        ] {
            assert!(!row[field].is_null(), "log row missing {field}: {row}");
        }
    }

    Ok(())
}

#[test]
fn checker_rejects_snapshot_field_floor_drift() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "field-floor")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_snapshot_contract"]["minimum_snapshot_fields"] = json!(9999);
    let mutated = out_dir.join("runtime_kernel_snapshot_field_floor_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("runtime_kernel_snapshot_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("field count is below contract minimum"),
        "report should cite field floor drift: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_unit_test_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-unit")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"]
        .as_array_mut()
        .ok_or("unit refs must be a mutable array")?
        .retain(|entry| {
            entry["name"].as_str()
                != Some("runtime_kernel_snapshot_schema_and_literal_cover_all_fields")
        });
    let mutated = out_dir.join("runtime_kernel_snapshot_missing_unit_binding.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("runtime_kernel_snapshot_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"].to_string().contains("required_test_refs"),
        "report should cite stale unit binding: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_golden_hash_drift() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "hash-drift")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_snapshot_contract"]["expected_sha256"] =
        json!("0000000000000000000000000000000000000000000000000000000000000000");
    let mutated = out_dir.join("runtime_kernel_snapshot_hash_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("runtime_kernel_snapshot_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"].to_string().contains("sha256 drift"),
        "report should cite golden hash drift: {report}"
    );

    Ok(())
}
