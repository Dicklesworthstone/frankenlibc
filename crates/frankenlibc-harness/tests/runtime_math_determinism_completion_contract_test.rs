use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has workspace parent")
        .parent()
        .expect("workspace parent has repo root")
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/runtime_math_determinism_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_math_determinism_completion_contract.sh")
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
        "runtime-math-determinism-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_RUNTIME_MATH_DETERMINISM_CONTRACT", contract)
        .env("FRANKENLIBC_RUNTIME_MATH_DETERMINISM_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_RUNTIME_MATH_DETERMINISM_REPORT",
            out_dir.join("runtime_math_determinism_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_DETERMINISM_LOG",
            out_dir.join("runtime_math_determinism_completion_contract.log.jsonl"),
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

fn string_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("expected array")
        .iter()
        .map(|item| item.as_str().expect("expected string").to_string())
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
fn manifest_binds_runtime_math_determinism_unit_and_integration_items() -> TestResult {
    let root = repo_root();
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("runtime_math_determinism_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-1fk1"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-1fk1.1"));
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"]),
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.integration.primary".to_string(),
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

    let contract = &manifest["required_determinism_contract"];
    assert_eq!(contract["seed"].as_u64(), Some(0xDEAD_BEEF));
    assert_eq!(contract["seed_literal"].as_str(), Some("0xDEAD_BEEF"));
    assert_eq!(contract["steps"].as_u64(), Some(512));
    assert_eq!(contract["modes"], json!(["strict", "hardened"]));

    let unit_names: BTreeSet<_> =
        manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"]
            .as_array()
            .ok_or("unit required test refs must be array")?
            .iter()
            .map(|entry| entry["name"].as_str().expect("test name").to_string())
            .collect();
    for name in [
        "runtime_kernel_snapshot_schema_doc_matches_constant",
        "snapshot_decision_and_evidence_counters_are_monotone",
        "deterministic_replay_produces_identical_decisions_and_evidence",
    ] {
        assert!(unit_names.contains(name), "missing unit binding {name}");
    }

    let integration_names: BTreeSet<_> =
        manifest["completion_debt_evidence"]["integration_primary"]["required_test_refs"]
            .as_array()
            .ok_or("integration required test refs must be array")?
            .iter()
            .map(|entry| entry["name"].as_str().expect("test name").to_string())
            .collect();
    assert!(integration_names.contains("gate_script_emits_logs_and_report"));
    assert!(
        integration_names
            .contains("checker_validates_runtime_math_determinism_contract_and_emits_report_log")
    );

    Ok(())
}

#[test]
fn checker_validates_runtime_math_determinism_contract_and_emits_report_log() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "valid")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        read_json(&out_dir.join("runtime_math_determinism_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("runtime_math_determinism_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-1fk1"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-1fk1.1"));
    assert_eq!(
        report["determinism_contract"]["seed"].as_u64(),
        Some(0xDEAD_BEEF)
    );
    assert_eq!(report["determinism_contract"]["steps"].as_u64(), Some(512));
    assert_eq!(report["unit_bindings"].as_array().map(Vec::len), Some(4));
    assert_eq!(
        report["integration_bindings"].as_array().map(Vec::len),
        Some(8)
    );
    assert_eq!(
        report["determinism_contract"]["source_text"]["checked_tokens"].as_u64(),
        Some(31)
    );
    assert_eq!(report["events"].as_array().map(Vec::len), Some(4));

    let rows = read_jsonl(&out_dir.join("runtime_math_determinism_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .map(|row| row["event"].as_str().unwrap().to_string())
        .collect();
    for event in [
        "runtime_math_determinism_unit_bindings_verified",
        "runtime_math_determinism_integration_bindings_verified",
        "runtime_math_determinism_contract_verified",
        "runtime_math_determinism_completion_contract_pass",
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
fn checker_rejects_missing_observe_binding() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing-observe")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_determinism_contract"]["required_source_text"]
        ["determinism_proof_source"]
        .as_array_mut()
        .expect("proof source needles array")
        .push(json!(
            "k1.observe_validation_result(mode, ctx.family, d1.profile, estimated_cost_ns, adverse, missing_observe_guard)"
        ));
    let mutated = out_dir.join("runtime_math_determinism_missing_observe.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("runtime_math_determinism_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("observe_validation_result"),
        "report should cite missing observe binding: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_unit_test_binding() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing-unit")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"]
        .as_array_mut()
        .expect("unit refs array")
        .retain(|entry| {
            entry["name"].as_str()
                != Some("deterministic_replay_produces_identical_decisions_and_evidence")
        });
    let mutated = out_dir.join("runtime_math_determinism_missing_unit.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("runtime_math_determinism_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"].to_string().contains("required_test_refs"),
        "report should cite missing unit binding: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_local_cargo_command() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "local-cargo")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["integration_primary"]["required_commands"] =
        json!(["cargo test -p frankenlibc-harness --test runtime_math_determinism_proofs_test"]);
    let mutated = out_dir.join("runtime_math_determinism_local_cargo.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("runtime_math_determinism_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"].to_string().contains("rch-backed"),
        "report should cite local cargo command drift: {report}"
    );

    Ok(())
}
