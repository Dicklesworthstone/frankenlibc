use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .ok_or_else(|| format!("crate directory has no workspace parent: {manifest}"))?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("workspace parent has no repo parent: {manifest}").into())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/support_reality_regeneration_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_support_reality_regeneration_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
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
    let out = root.join("target/conformance").join(format!(
        "support_reality_regeneration_completion_contract_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_SUPPORT_REALITY_REGEN_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_SUPPORT_REALITY_REGEN_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_SUPPORT_REALITY_REGEN_COMPLETION_REPORT",
            out_dir.join("support_reality_regeneration_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_SUPPORT_REALITY_REGEN_COMPLETION_LOG",
            out_dir.join("support_reality_regeneration_completion_contract.log.jsonl"),
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

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

fn string_values(value: &Value) -> TestResult<Vec<String>> {
    let array = value.as_array().ok_or("expected array")?;
    let mut values = Vec::with_capacity(array.len());
    for item in array {
        values.push(item.as_str().ok_or("expected string item")?.to_string());
    }
    Ok(values)
}

#[test]
fn manifest_binds_conformance_completion_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("support_reality_regeneration_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-0agsk.3"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-0agsk.3.1")
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts object")?;
    for (source_id, path) in source_artifacts {
        let path = path.as_str().ok_or("source path string")?;
        assert!(
            root.join(path).exists(),
            "source artifact {source_id} missing at {path}"
        );
    }

    let pair = &manifest["completion_debt_evidence"]["required_pair_contract"];
    assert_eq!(
        pair["schema_version"].as_str(),
        Some("support_reality_regeneration.v1")
    );
    assert_eq!(pair["generated_by_bead"].as_str(), Some("bd-0agsk.3"));
    assert_eq!(pair["mode"].as_str(), Some("validate_only"));
    let pair_ids = string_values(&pair["required_artifact_ids"])?;
    assert!(pair_ids.iter().any(|value| value == "support_matrix"));
    assert!(pair_ids.iter().any(|value| value == "reality_report"));

    let source_contract =
        load_json(&root.join("tests/conformance/support_reality_regeneration.v1.json"))?;
    assert_eq!(
        source_contract["schema_version"].as_str(),
        Some("support_reality_regeneration.v1")
    );
    assert_eq!(
        source_contract["generated_by_bead"].as_str(),
        Some("bd-0agsk.3")
    );
    assert_eq!(
        source_contract["paired_update_policy"]["single_artifact_update"].as_str(),
        Some("forbidden")
    );

    let binding = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings array")?
        .iter()
        .find(|item| item["id"].as_str() == Some("tests.conformance.primary"))
        .ok_or("tests.conformance.primary binding")?;
    for artifact in binding["required_artifacts"]
        .as_array()
        .ok_or("required_artifacts array")?
    {
        let path = artifact.as_str().ok_or("artifact string")?;
        assert!(
            root.join(path).exists(),
            "required artifact missing: {path}"
        );
    }

    for implementation_ref in manifest["completion_debt_evidence"]["implementation_refs"]
        .as_array()
        .ok_or("implementation refs array")?
    {
        let path = implementation_ref["path"]
            .as_str()
            .ok_or("implementation path")?;
        let text = std::fs::read_to_string(root.join(path))?;
        for needle in implementation_ref["required_text"]
            .as_array()
            .ok_or("required_text array")?
        {
            let needle = needle.as_str().ok_or("needle string")?;
            assert!(text.contains(needle), "{path} missing {needle}");
        }
    }

    Ok(())
}

#[test]
fn checker_validates_support_reality_regeneration_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("support_reality_regeneration_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-0agsk.3"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-0agsk.3.1")
    );
    assert_eq!(report["summary"]["required_checks"].as_u64(), Some(6));
    assert_eq!(report["summary"]["support_total"].as_u64(), Some(4119));
    assert_eq!(report["summary"]["reality_total"].as_u64(), Some(4119));

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl_with_conformance_rows() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("support_reality_regeneration_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("support_reality_regeneration_completion_contract.report.v1")
    );
    let events = string_values(&report["events"])?;
    for event in [
        "support_reality_regeneration_completion_summary",
        "support_reality_regeneration_source_bindings",
        "support_reality_regeneration_conformance_bindings",
        "support_reality_regeneration_completion_contract_pass",
    ] {
        assert!(events.iter().any(|value| value == event), "missing {event}");
    }

    let rows =
        read_jsonl(&out_dir.join("support_reality_regeneration_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 4, "checker should emit four telemetry rows");
    for row in rows {
        for field in [
            "timestamp",
            "event",
            "bead_id",
            "source_bead",
            "completion_debt_bead",
            "status",
            "outcome",
            "source_commit",
            "schema_version",
            "required_checks",
            "test_refs",
            "artifact_refs",
            "failure_signature",
        ] {
            assert!(!row[field].is_null(), "log row missing {field}: {row}");
        }
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert_eq!(row["failure_signature"].as_str(), Some("none"));
    }

    Ok(())
}

#[test]
fn checker_rejects_required_command_without_remote_requirement() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_rch_remote")?;
    let mut manifest = load_json(&contract_path(&root))?;
    let commands = manifest["missing_item_bindings"]
        .as_array_mut()
        .ok_or("missing_item_bindings array")?
        .iter_mut()
        .find(|item| item["id"].as_str() == Some("tests.conformance.primary"))
        .ok_or("tests.conformance.primary binding")?["required_commands"]
        .as_array_mut()
        .ok_or("required_commands array")?;
    let command = commands
        .iter_mut()
        .find(|entry| {
            entry
                .as_str()
                .is_some_and(|value| value.contains("support_reality_regeneration_test"))
        })
        .ok_or("source harness cargo command")?;
    let command_text = command
        .as_str()
        .ok_or("source harness command string")?
        .replacen("RCH_REQUIRE_REMOTE=1 ", "", 1);
    *command = json!(command_text);

    let mutated = out_dir.join("missing_rch_remote_contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing remote requirement:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("support_reality_regeneration_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("RCH_REQUIRE_REMOTE=1")),
        "report should name missing RCH_REQUIRE_REMOTE=1: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_required_command_without_target_dir() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_cargo_target_dir")?;
    let mut manifest = load_json(&contract_path(&root))?;
    let commands = manifest["missing_item_bindings"]
        .as_array_mut()
        .ok_or("missing_item_bindings array")?
        .iter_mut()
        .find(|item| item["id"].as_str() == Some("tests.conformance.primary"))
        .ok_or("tests.conformance.primary binding")?["required_commands"]
        .as_array_mut()
        .ok_or("required_commands array")?;
    let command = commands
        .iter_mut()
        .find(|entry| {
            entry.as_str().is_some_and(|value| {
                value.contains("support_reality_regeneration_completion_contract_test")
            })
        })
        .ok_or("completion harness cargo command")?;
    let command_text = command
        .as_str()
        .ok_or("completion harness command string")?
        .replacen("env CARGO_TARGET_DIR=<target> ", "", 1);
    *command = json!(command_text);

    let mutated = out_dir.join("missing_cargo_target_dir_contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing target dir:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("support_reality_regeneration_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("CARGO_TARGET_DIR")),
        "report should name missing CARGO_TARGET_DIR: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_pair_artifact_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_pair")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["required_pair_contract"]["required_artifact_ids"] =
        json!(["support_matrix"]);
    let mutated = out_dir.join("missing_pair_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing pair binding:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("support_reality_regeneration_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("reality_report")),
        "report should name missing reality_report binding: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_source_test_ref() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_test_ref")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["test_sources"]["source_harness_test"]
        ["required_test_refs"]
        .as_array_mut()
        .ok_or("required_test_refs array")?
        .push(json!("missing_support_reality_regeneration_test_ref"));
    let mutated = out_dir.join("missing_test_ref_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing test ref:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("support_reality_regeneration_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("missing_support_reality_regeneration_test_ref")),
        "report should name missing test ref: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_event")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["telemetry_contract"]["required_events"]
        .as_array_mut()
        .ok_or("required_events array")?
        .push(json!(
            "missing_support_reality_regeneration_completion_event"
        ));
    let mutated = out_dir.join("missing_event_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing event:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("support_reality_regeneration_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("missing_support_reality_regeneration_completion_event")),
        "report should name missing event: {report}"
    );

    Ok(())
}
