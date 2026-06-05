use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = crate_dir
        .parent()
        .ok_or("crate directory has workspace parent")?;
    let root = workspace
        .parent()
        .ok_or("workspace parent has repo parent")?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/reality_snapshot_parity_docs_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_reality_snapshot_parity_docs_completion_contract.sh")
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
        "reality_snapshot_parity_docs_completion_contract_{label}_{}_{}",
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
            "FRANKENLIBC_REALITY_SNAPSHOT_DOCS_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_REALITY_SNAPSHOT_DOCS_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_REALITY_SNAPSHOT_DOCS_COMPLETION_REPORT",
            out_dir.join("reality_snapshot_parity_docs_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_REALITY_SNAPSHOT_DOCS_COMPLETION_LOG",
            out_dir.join("reality_snapshot_parity_docs_completion_contract.log.jsonl"),
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
fn manifest_binds_docs_reality_conformance_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("reality_snapshot_parity_docs_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-2vv.13"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-2vv.13.1")
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

    let snapshot = &manifest["expected_reality_snapshot"];
    let reality = load_json(&root.join("tests/conformance/reality_report.v1.json"))?;
    assert!(
        snapshot["generated_at_utc"].as_str().is_some(),
        "snapshot must pin generated_at_utc"
    );
    assert!(
        snapshot["total_exported"].as_u64().unwrap_or(0) > 0,
        "snapshot must pin total_exported"
    );
    for key in [
        "implemented",
        "raw_syscall",
        "wraps_host_libc",
        "glibc_call_through",
        "stub",
    ] {
        assert!(
            snapshot["counts"][key].as_u64().is_some(),
            "snapshot must pin {key}"
        );
    }

    assert_eq!(reality["generated_at_utc"], snapshot["generated_at_utc"]);
    assert_eq!(reality["total_exported"], snapshot["total_exported"]);
    assert_eq!(
        reality["counts"]["implemented"],
        snapshot["counts"]["implemented"]
    );
    assert_eq!(
        reality["counts"]["raw_syscall"],
        snapshot["counts"]["raw_syscall"]
    );
    assert_eq!(
        reality["counts"]["wraps_host_libc"],
        snapshot["counts"]["wraps_host_libc"]
    );
    assert_eq!(
        reality["counts"]["glibc_call_through"],
        snapshot["counts"]["glibc_call_through"]
    );
    assert_eq!(reality["counts"]["stub"], snapshot["counts"]["stub"]);

    for doc in manifest["doc_snapshot_requirements"]["docs"]
        .as_array()
        .ok_or("docs array")?
    {
        let path = doc["path"].as_str().ok_or("doc path")?;
        let text = std::fs::read_to_string(root.join(path))?;
        for needle in doc["required_text"]
            .as_array()
            .ok_or("required_text array")?
        {
            let needle = needle.as_str().ok_or("needle string")?;
            assert!(text.contains(needle), "{path} missing {needle}");
        }
    }

    let binding = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings array")?
        .iter()
        .find(|item| item["id"].as_str() == Some("tests.conformance.primary"))
        .ok_or("tests.conformance.primary binding")?;
    assert_eq!(binding["kind"].as_str(), Some("conformance"));

    Ok(())
}

#[test]
fn checker_validates_docs_reality_snapshot_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("reality_snapshot_parity_docs_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-2vv.13"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-2vv.13.1"));
    assert_eq!(report["summary"]["docs_checked"].as_u64(), Some(2));
    let manifest = load_json(&contract_path(&root))?;
    let snapshot = &manifest["expected_reality_snapshot"];
    assert_eq!(
        report["summary"]["total_exported"],
        snapshot["total_exported"]
    );
    assert_eq!(
        report["summary"]["implemented"],
        snapshot["counts"]["implemented"]
    );
    assert_eq!(
        report["summary"]["raw_syscall"],
        snapshot["counts"]["raw_syscall"]
    );
    assert_eq!(
        report["summary"]["wraps_host_libc"],
        snapshot["counts"]["wraps_host_libc"]
    );

    Ok(())
}

#[test]
fn checker_emits_conformance_report_and_jsonl_rows() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("reality_snapshot_parity_docs_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("reality_snapshot_parity_docs_completion_contract.report.v1")
    );
    let events = string_values(&report["events"])?;
    for event in [
        "docs_reality_snapshot_completion_summary",
        "docs_reality_snapshot_source_bindings",
        "docs_reality_snapshot_conformance_bindings",
        "docs_reality_snapshot_completion_contract_pass",
    ] {
        assert!(events.iter().any(|value| value == event), "missing {event}");
    }

    let rows =
        read_jsonl(&out_dir.join("reality_snapshot_parity_docs_completion_contract.log.jsonl"))?;
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
fn checker_rejects_missing_readme_reality_source() -> TestResult {
    let root = repo_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["doc_snapshot_requirements"]["docs"][0]["required_text"][0] =
        json!("missing README reality source marker");

    let out_dir = unique_out_dir(&root, "missing_readme_source")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing required docs text"),
        "{}",
        output_text(&output)
    );

    Ok(())
}

#[test]
fn checker_rejects_reality_count_drift() -> TestResult {
    let root = repo_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["expected_reality_snapshot"]["total_exported"] = json!(4120);

    let out_dir = unique_out_dir(&root, "count_drift")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expected_reality_snapshot differs"),
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
    refs.retain(|value| value.as_str() != Some("checker_rejects_reality_count_drift"));

    let out_dir = unique_out_dir(&root, "missing_test_ref")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("completion test refs missing checker_rejects_reality_count_drift"),
        "{}",
        output_text(&output)
    );

    Ok(())
}
