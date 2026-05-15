use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = crate_dir
        .parent()
        .ok_or("crate directory has workspace parent")?;
    let repo_dir = workspace_dir
        .parent()
        .ok_or("workspace parent has repo parent")?;
    Ok(repo_dir.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/architecture_ledger_live_evidence_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_architecture_ledger_live_evidence_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
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
    let out = root.join("target/conformance").join(format!(
        "architecture_ledger_live_evidence_completion_contract_{label}_{}_{}",
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
        .env("FRANKENLIBC_ARCH_LEDGER_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_ARCH_LEDGER_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_ARCH_LEDGER_COMPLETION_REPORT",
            out_dir.join("architecture_ledger_live_evidence_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_ARCH_LEDGER_COMPLETION_LOG",
            out_dir.join("architecture_ledger_live_evidence_completion_contract.log.jsonl"),
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

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = value.as_array().ok_or("expected array")?;
    let mut result = BTreeSet::new();
    for item in array {
        result.insert(item.as_str().ok_or("expected string")?.to_owned());
    }
    Ok(result)
}

fn mutated_manifest(root: &Path, label: &str, manifest: &Value) -> TestResult<(PathBuf, PathBuf)> {
    let out_dir = unique_out_dir(root, label)?;
    let path = out_dir.join(format!("{label}.json"));
    write_json(&path, manifest)?;
    Ok((path, out_dir))
}

fn report_errors(out_dir: &Path) -> TestResult<Vec<String>> {
    let report = load_json(
        &out_dir.join("architecture_ledger_live_evidence_completion_contract.report.json"),
    )?;
    Ok(report["errors"]
        .as_array()
        .ok_or("errors array")?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect())
}

#[test]
fn manifest_binds_architecture_ledger_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("architecture_ledger_live_evidence_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-0agsk"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-0agsk.19")
    );
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items"])?,
        BTreeSet::from([
            "migrations.primary".to_string(),
            "tests.conformance.primary".to_string(),
            "tests.golden.primary".to_string(),
            "theater.todo_wording.primary".to_string(),
        ])
    );

    let children = manifest["required_parent_closeout"]["required_child_beads"]
        .as_array()
        .ok_or("child beads array")?;
    assert_eq!(children.len(), 18);

    for path in manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts object")?
        .values()
    {
        let path = path.as_str().ok_or("source artifact path")?;
        assert!(root.join(path).exists(), "source artifact missing: {path}");
    }

    let child_artifacts = manifest["completion_debt_evidence"]["child_evidence_artifacts"]
        .as_array()
        .ok_or("child_evidence_artifacts array")?;
    assert!(child_artifacts.len() >= 14);

    let mut coverage = BTreeSet::new();
    for artifact in child_artifacts {
        let path = artifact["path"].as_str().ok_or("artifact path")?;
        assert!(root.join(path).is_file(), "child artifact missing: {path}");
        for item in artifact["covers"].as_array().ok_or("covers array")? {
            coverage.insert(item.as_str().ok_or("covers item")?.to_owned());
        }
    }
    for item in [
        "tests.golden.primary",
        "tests.conformance.primary",
        "migrations.primary",
        "theater.todo_wording.primary",
    ] {
        assert!(coverage.contains(item), "missing coverage for {item}");
    }

    Ok(())
}

#[test]
fn checker_validates_architecture_ledger_live_evidence_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(
        &out_dir.join("architecture_ledger_live_evidence_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-0agsk"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-0agsk.19"));
    assert_eq!(report["summary"]["child_bead_count"].as_u64(), Some(18));
    assert_eq!(report["summary"]["closed_child_count"].as_u64(), Some(18));
    assert!(
        report["summary"]["child_artifact_count"]
            .as_u64()
            .is_some_and(|count| count >= 14)
    );

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl_for_all_missing_items() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(
        &out_dir.join("architecture_ledger_live_evidence_completion_contract.report.json"),
    )?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("architecture_ledger_live_evidence_completion_contract.report.v1")
    );
    let events = string_set(&report["events"])?;
    for event in [
        "architecture_ledger_live_evidence_summary",
        "architecture_ledger_live_evidence_golden_validated",
        "architecture_ledger_live_evidence_conformance_validated",
        "architecture_ledger_live_evidence_migration_validated",
        "architecture_ledger_live_evidence_theater_validated",
        "architecture_ledger_live_evidence_contract_pass",
    ] {
        assert!(events.contains(event), "missing event {event}");
    }

    let rows = read_jsonl(
        &out_dir.join("architecture_ledger_live_evidence_completion_contract.log.jsonl"),
    )?;
    assert_eq!(rows.len(), 6);
    let missing_items: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row["missing_item_id"].as_str())
        .collect();
    for item in [
        "summary",
        "tests.golden.primary",
        "tests.conformance.primary",
        "migrations.primary",
        "theater.todo_wording.primary",
    ] {
        assert!(missing_items.contains(item), "missing log item {item}");
    }
    for row in rows {
        for field in [
            "timestamp",
            "trace_id",
            "event",
            "source_bead",
            "completion_debt_bead",
            "status",
            "source_commit",
            "missing_item_id",
            "child_bead_count",
            "child_artifact_count",
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
fn checker_rejects_missing_child_closeout_binding() -> TestResult {
    let root = repo_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_parent_closeout"]["required_child_beads"]
        .as_array_mut()
        .ok_or("children array")?
        .retain(|child| child.as_str() != Some("bd-0agsk.18"));
    let (path, out_dir) = mutated_manifest(&root, "missing_child", &manifest)?;

    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let errors = report_errors(&out_dir)?;
    assert!(
        errors
            .iter()
            .any(|error| error.contains("must list 18 child beads")),
        "report should cite child closeout drift: {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_golden_binding() -> TestResult {
    let root = repo_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["golden_primary"]["required_artifacts"]
        .as_array_mut()
        .ok_or("golden artifacts")?
        .retain(|artifact| artifact.as_str() != Some("tests/conformance/golden/sha256sums.txt"));
    let (path, out_dir) = mutated_manifest(&root, "missing_golden", &manifest)?;

    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let errors = report_errors(&out_dir)?;
    assert!(
        errors.iter().any(|error| error.contains("sha256sums.txt")),
        "report should cite missing golden checksum binding: {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_theater_resolution_drift() -> TestResult {
    let root = repo_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["theater_resolution"]["resolution_policy"] =
        json!("TODO wording is itself proof of implementation");
    let (path, out_dir) = mutated_manifest(&root, "theater_drift", &manifest)?;

    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let errors = report_errors(&out_dir)?;
    assert!(
        errors.iter().any(|error| error.contains("theater")),
        "report should cite theater policy drift: {errors:?}"
    );

    Ok(())
}
