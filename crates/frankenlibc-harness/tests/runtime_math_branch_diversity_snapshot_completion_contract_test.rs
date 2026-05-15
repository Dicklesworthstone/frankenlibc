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
    root.join(
        "tests/conformance/runtime_math_branch_diversity_snapshot_completion_contract.v1.json",
    )
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_math_branch_diversity_snapshot_completion_contract.sh")
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
        "runtime-math-branch-snapshot-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_BRANCH_SNAPSHOT_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_BRANCH_SNAPSHOT_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_BRANCH_SNAPSHOT_COMPLETION_REPORT",
            out_dir.join("runtime_math_branch_diversity_snapshot_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_BRANCH_SNAPSHOT_COMPLETION_LOG",
            out_dir.join("runtime_math_branch_diversity_snapshot_completion_contract.log.jsonl"),
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
fn manifest_binds_branch_diversity_snapshot_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("runtime_math_branch_diversity_snapshot_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-5vr.7"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-5vr.7.1")
    );
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.golden.primary".to_string(),
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

    let contract = &manifest["required_runtime_math_branch_snapshot_contract"];
    assert_eq!(
        contract["scenario_id"].as_str(),
        Some("bd-5vr.7-runtime-math-branch-diversity-snapshot-e2e")
    );
    assert_eq!(contract["required_modes"], json!(["strict", "hardened"]));
    assert_eq!(
        contract["branch_diversity"]["minimum_active_families"].as_u64(),
        Some(3)
    );
    assert_eq!(
        contract["snapshot_capture"]["snapshot_schema_version"].as_u64(),
        Some(2)
    );
    assert_eq!(
        contract["multi_kernel_interaction"]["minimum_decision_steps"].as_u64(),
        Some(128)
    );
    assert_eq!(
        contract["golden_snapshot"]["expected_filename"].as_str(),
        Some("kernel_snapshot_smoke.v1.json")
    );

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
    for name in [
        "e2e_branch_diversity_healthy_with_balanced_family_mix",
        "e2e_snapshot_captures_schema_version_and_core_fields",
        "e2e_independent_kernels_produce_consistent_results_under_concurrent_scenario",
        "e2e_framework_decision_cards_export_contains_all_decisions",
    ] {
        assert!(e2e_names.contains(name), "missing e2e binding {name}");
    }

    let golden_names: BTreeSet<_> =
        manifest["completion_debt_evidence"]["golden_primary"]["required_test_refs"]
            .as_array()
            .ok_or("golden required test refs must be array")?
            .iter()
            .map(|entry| {
                Ok(entry["name"]
                    .as_str()
                    .ok_or("golden test ref name must be string")?
                    .to_string())
            })
            .collect::<TestResult<_>>()?;
    for name in [
        "e2e_snapshot_serialization_contains_all_core_fields",
        "e2e_snapshot_golden_replay_field_stability",
        "runtime_math_kernel_snapshot_golden_checksum_matches_manifest",
    ] {
        assert!(golden_names.contains(name), "missing golden binding {name}");
    }

    Ok(())
}

#[test]
fn checker_validates_branch_diversity_snapshot_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "valid")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(
        &out_dir.join("runtime_math_branch_diversity_snapshot_completion_contract.report.json"),
    )?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("runtime_math_branch_diversity_snapshot_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-5vr.7"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-5vr.7.1"));
    assert_eq!(report["e2e_bindings"].as_array().map(Vec::len), Some(10));
    assert_eq!(report["golden_bindings"].as_array().map(Vec::len), Some(4));
    assert_eq!(report["events"].as_array().map(Vec::len), Some(4));
    assert_eq!(
        report["branch_snapshot_contract"]["golden_sha256"].as_str(),
        Some("90ee952d0398f187d583ce552014cad53d102c5102118ab6e83b6e1b788a7651")
    );

    let rows = read_jsonl(
        &out_dir.join("runtime_math_branch_diversity_snapshot_completion_contract.log.jsonl"),
    )?;
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
        "runtime_math_branch_snapshot_unit_bindings_verified",
        "runtime_math_branch_snapshot_e2e_bindings_verified",
        "runtime_math_branch_snapshot_golden_verified",
        "runtime_math_branch_snapshot_completion_contract_pass",
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
fn checker_rejects_missing_branch_diversity_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-branch")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let refs = manifest["completion_debt_evidence"]["e2e_primary"]["required_test_refs"]
        .as_array_mut()
        .ok_or("e2e refs must be a mutable array")?;
    refs.retain(|entry| {
        entry["name"].as_str() != Some("e2e_branch_diversity_healthy_with_balanced_family_mix")
    });
    let mutated = out_dir.join("runtime_math_branch_snapshot_missing_branch.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(
        &out_dir.join("runtime_math_branch_diversity_snapshot_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("e2e_primary.required_test_refs missing required bindings"),
        "report should cite missing branch-diversity binding: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_golden_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-golden")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let refs = manifest["completion_debt_evidence"]["golden_primary"]["required_test_refs"]
        .as_array_mut()
        .ok_or("golden refs must be a mutable array")?;
    refs.retain(|entry| {
        entry["name"].as_str() != Some("e2e_snapshot_golden_replay_field_stability")
    });
    let mutated = out_dir.join("runtime_math_branch_snapshot_missing_golden.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(
        &out_dir.join("runtime_math_branch_diversity_snapshot_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("golden_primary.required_test_refs missing required bindings"),
        "report should cite missing golden binding: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_golden_hash_drift() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "hash-drift")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_runtime_math_branch_snapshot_contract"]["golden_snapshot"]["expected_sha256"] =
        json!("0000000000000000000000000000000000000000000000000000000000000000");
    let mutated = out_dir.join("runtime_math_branch_snapshot_hash_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(
        &out_dir.join("runtime_math_branch_diversity_snapshot_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("golden snapshot hash drift"),
        "report should cite golden hash drift: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "non-rch")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["e2e_primary"]["required_commands"][0] =
        json!("cargo test -p frankenlibc-membrane --test runtime_math_dual_mode_e2e_test");
    let mutated = out_dir.join("runtime_math_branch_snapshot_non_rch_command.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(
        &out_dir.join("runtime_math_branch_diversity_snapshot_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("cargo command must be rch-backed"),
        "report should cite non-rch cargo command: {report}"
    );

    Ok(())
}
