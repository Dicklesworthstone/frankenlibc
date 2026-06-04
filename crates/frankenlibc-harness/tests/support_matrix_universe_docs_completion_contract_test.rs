use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory must have workspace parent")?
        .parent()
        .ok_or("workspace parent must have repo parent")?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/support_matrix_universe_docs_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_support_matrix_universe_docs_completion_contract.sh")
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
        "support_matrix_universe_docs_completion_contract_{label}_{}_{}",
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
            "FRANKENLIBC_SUPPORT_MATRIX_UNIVERSE_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_SUPPORT_MATRIX_UNIVERSE_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_SUPPORT_MATRIX_UNIVERSE_COMPLETION_REPORT",
            out_dir.join("support_matrix_universe_docs_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_SUPPORT_MATRIX_UNIVERSE_COMPLETION_LOG",
            out_dir.join("support_matrix_universe_docs_completion_contract.log.jsonl"),
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
fn manifest_binds_symbol_universe_completion_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("support_matrix_universe_docs_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-2vv.16"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-2vv.16.1")
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

    let expected = &manifest["expected_symbol_universe"];
    assert_eq!(
        expected["generated_at_utc"].as_str(),
        Some("2026-06-03T21:45:00Z")
    );
    assert_eq!(expected["total_symbols"].as_u64(), Some(4119));
    assert_eq!(
        expected["status_counts"]["Implemented"].as_u64(),
        Some(2384)
    );
    assert_eq!(expected["status_counts"]["RawSyscall"].as_u64(), Some(414));
    assert_eq!(
        expected["status_counts"]["WrapsHostLibc"].as_u64(),
        Some(1321)
    );
    assert_eq!(
        expected["status_counts"]["GlibcCallThrough"].as_u64(),
        Some(0)
    );

    let support = load_json(&root.join("support_matrix.json"))?;
    assert_eq!(support["total_exported"].as_u64(), Some(4119));
    assert_eq!(
        support["symbols"]
            .as_array()
            .ok_or("support symbols array")?
            .len(),
        4119
    );

    let forbidden = string_values(&expected["legacy_snapshots_forbidden"])?;
    let readme = std::fs::read_to_string(root.join("README.md"))?;
    let feature = std::fs::read_to_string(root.join("FEATURE_PARITY.md"))?;
    for needle in forbidden {
        assert!(!readme.contains(&needle), "README still contains {needle}");
        assert!(
            !feature.contains(&needle),
            "FEATURE_PARITY still contains {needle}"
        );
    }

    Ok(())
}

#[test]
fn checker_validates_symbol_universe_docs_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("support_matrix_universe_docs_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-2vv.16"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-2vv.16.1"));
    assert_eq!(report["summary"]["docs_checked"].as_u64(), Some(2));
    assert_eq!(report["summary"]["total_symbols"].as_u64(), Some(4119));
    assert_eq!(
        report["summary"]["status_counts"]["Implemented"].as_u64(),
        Some(2384)
    );
    assert_eq!(
        report["summary"]["status_counts"]["RawSyscall"].as_u64(),
        Some(414)
    );
    assert_eq!(
        report["summary"]["status_counts"]["WrapsHostLibc"].as_u64(),
        Some(1321)
    );

    Ok(())
}

#[test]
fn checker_emits_universe_report_and_jsonl_rows() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("support_matrix_universe_docs_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("support_matrix_universe_docs_completion_contract.report.v1")
    );
    let events = string_values(&report["events"])?;
    for event in [
        "support_matrix_universe_completion_summary",
        "support_matrix_universe_source_bindings",
        "support_matrix_universe_conformance_bindings",
        "support_matrix_universe_completion_contract_pass",
    ] {
        assert!(events.iter().any(|value| value == event), "missing {event}");
    }

    let rows =
        read_jsonl(&out_dir.join("support_matrix_universe_docs_completion_contract.log.jsonl"))?;
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
            "artifact_refs",
            "test_refs",
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
fn checker_rejects_symbol_universe_total_drift() -> TestResult {
    let root = repo_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["expected_symbol_universe"]["total_symbols"] = json!(4120);

    let out_dir = unique_out_dir(&root, "total_drift")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expected total_symbols differs"),
        "{}",
        output_text(&output)
    );

    Ok(())
}

#[test]
fn checker_rejects_legacy_snapshot_text() -> TestResult {
    let root = repo_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["universe_join_requirements"]["docs"][0]["required_text"][0] =
        json!("1277/898/358/21/0");

    let out_dir = unique_out_dir(&root, "legacy_text")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing required universe text"),
        "{}",
        output_text(&output)
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_completion_test_ref() -> TestResult {
    let root = repo_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    let refs = manifest["completion_debt_evidence"]["test_sources"]["completion_harness_test"]
        ["required_test_refs"]
        .as_array_mut()
        .ok_or("required_test_refs array")?;
    refs.retain(|value| value.as_str() != Some("checker_rejects_legacy_snapshot_text"));

    let out_dir = unique_out_dir(&root, "missing_test_ref")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("completion test refs missing checker_rejects_legacy_snapshot_text"),
        "{}",
        output_text(&output)
    );

    Ok(())
}
