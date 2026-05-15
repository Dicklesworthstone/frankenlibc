use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory should have workspace parent")?;
    let root = crate_dir
        .parent()
        .ok_or("workspace parent should have repo root")?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/dual_mode_e2e_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_dual_mode_e2e_completion_contract.sh")
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
        "dual-mode-e2e-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_DUAL_MODE_E2E_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_DUAL_MODE_E2E_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_DUAL_MODE_E2E_COMPLETION_REPORT",
            out_dir.join("dual_mode_e2e_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_DUAL_MODE_E2E_COMPLETION_LOG",
            out_dir.join("dual_mode_e2e_completion_contract.log.jsonl"),
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

fn string_set(value: &Value, context: &str) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| format!("{context} must be an array"))?
        .iter()
        .enumerate()
        .map(|(index, item)| -> TestResult<String> {
            Ok(item
                .as_str()
                .ok_or_else(|| format!("{context}[{index}] must be a string"))?
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
fn manifest_binds_dual_mode_e2e_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("dual_mode_e2e_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-oai.5"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-oai.5.1")
    );
    assert_eq!(
        string_set(
            &manifest["completion_debt_evidence"]["missing_items_closed"],
            "completion_debt_evidence.missing_items_closed"
        )?,
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

    let contract = &manifest["required_dual_mode_e2e_contract"];
    assert_eq!(
        contract["scenario_id"].as_str(),
        Some("bd-oai.5-dual-mode-runtime-math-e2e")
    );
    assert_eq!(contract["required_modes"], json!(["strict", "hardened"]));
    assert_eq!(contract["deterministic_replay_steps"].as_u64(), Some(96));
    assert_eq!(contract["strict_divergence_rows"].as_u64(), Some(64));
    assert_eq!(contract["hardened_divergence_rows"].as_u64(), Some(64));
    assert_eq!(contract["gapless_repair_rows"].as_u64(), Some(96));
    assert_eq!(contract["hash_linked_records"].as_u64(), Some(64));
    assert_eq!(contract["strict_expected_action"].as_str(), Some("Deny"));
    assert_eq!(
        contract["hardened_expected_action"].as_str(),
        Some("Repair")
    );
    assert_eq!(
        contract["hardened_expected_healing_action"].as_str(),
        Some("ReturnSafeDefault")
    );

    let fields = string_set(
        &contract["required_structured_fields"],
        "required_dual_mode_e2e_contract.required_structured_fields",
    )?;
    for field in [
        "trace_id",
        "mode",
        "api_family",
        "symbol",
        "decision_path",
        "healing_action",
        "errno",
        "latency_ns",
        "artifact_refs",
        "decision_action",
        "evidence_seqno",
    ] {
        assert!(fields.contains(field), "missing structured field {field}");
    }

    let e2e_names: BTreeSet<_> =
        manifest["completion_debt_evidence"]["e2e_primary"]["required_test_refs"]
            .as_array()
            .ok_or("e2e required test refs must be array")?
            .iter()
            .enumerate()
            .map(|(index, entry)| -> TestResult<String> {
                Ok(entry["name"]
                    .as_str()
                    .ok_or_else(|| format!("e2e required test refs[{index}].name must be string"))?
                    .to_string())
            })
            .collect::<TestResult<_>>()?;
    for name in [
        "e2e_deterministic_replay_emits_identical_decisions_and_logs",
        "e2e_mode_behavioral_divergence_is_stable_and_structured",
        "e2e_hardened_repair_evidence_chain_is_complete_and_gapless",
        "e2e_hash_linked_repair_chain_verifies_record_integrity",
    ] {
        assert!(e2e_names.contains(name), "missing e2e binding {name}");
    }

    Ok(())
}

#[test]
fn checker_validates_dual_mode_e2e_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "valid")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("dual_mode_e2e_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("dual_mode_e2e_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-oai.5"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-oai.5.1"));
    assert_eq!(
        report["dual_mode_contract"]["strict_expected_action"].as_str(),
        Some("Deny")
    );
    assert_eq!(
        report["dual_mode_contract"]["hardened_expected_action"].as_str(),
        Some("Repair")
    );
    assert_eq!(report["e2e_bindings"].as_array().map(Vec::len), Some(8));
    assert_eq!(report["events"].as_array().map(Vec::len), Some(4));

    let rows = read_jsonl(&out_dir.join("dual_mode_e2e_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .enumerate()
        .map(|(index, row)| -> TestResult<String> {
            Ok(row["event"]
                .as_str()
                .ok_or_else(|| format!("log row {index} missing string event"))?
                .to_string())
        })
        .collect::<TestResult<_>>()?;
    for event in [
        "dual_mode_e2e_unit_bindings_verified",
        "dual_mode_e2e_source_contract_verified",
        "dual_mode_e2e_bindings_verified",
        "dual_mode_e2e_completion_contract_pass",
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
fn checker_rejects_missing_structured_field_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-field")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_dual_mode_e2e_contract"]["required_structured_fields"] =
        json!(["trace_id", "mode", "api_family"]);
    let mutated = out_dir.join("dual_mode_e2e_missing_structured_field.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("dual_mode_e2e_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("required_structured_fields missing required bindings"),
        "report should cite missing structured fields: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_required_e2e_test_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-e2e")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let refs = manifest["completion_debt_evidence"]["e2e_primary"]["required_test_refs"]
        .as_array_mut()
        .ok_or("e2e required test refs must be array")?;
    refs.retain(|entry| {
        entry["name"].as_str() != Some("e2e_hash_linked_repair_chain_verifies_record_integrity")
    });
    let mutated = out_dir.join("dual_mode_e2e_missing_required_test.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("dual_mode_e2e_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("e2e_primary.required_test_refs missing required bindings"),
        "report should cite missing e2e binding: {report}"
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
    let mutated = out_dir.join("dual_mode_e2e_non_rch_command.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("dual_mode_e2e_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("cargo command must be rch-backed"),
        "report should cite non-rch cargo command: {report}"
    );

    Ok(())
}
