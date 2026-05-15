use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_BINDINGS: &[&str] = &[
    "tests.unit.primary",
    "tests.e2e.primary",
    "migrations.primary",
    "telemetry.primary",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
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
];

fn repo_root() -> TestResult<PathBuf> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory should have workspace parent")?;
    let root = workspace
        .parent()
        .ok_or("workspace parent should have repo parent")?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/math_retirement_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_math_retirement_completion_contract.sh")
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

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "math_retirement_completion_contract_{label}_{}_{}",
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
        .env("FRANKENLIBC_MATH_RETIREMENT_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_MATH_RETIREMENT_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_MATH_RETIREMENT_COMPLETION_REPORT",
            out_dir.join("math_retirement_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_MATH_RETIREMENT_COMPLETION_LOG",
            out_dir.join("math_retirement_completion_contract.log.jsonl"),
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

fn binding_ids(manifest: &Value) -> TestResult<BTreeSet<String>> {
    manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be an array")?
        .iter()
        .map(|binding| {
            binding["id"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "binding id must be a string".into())
        })
        .collect()
}

#[test]
fn manifest_binds_existing_math_retirement_surfaces() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("math_retirement_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-545"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-545.1"));

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be an object")?;
    for (source_id, path) in source_artifacts {
        let path = path.as_str().ok_or("source path must be string")?;
        assert!(
            root.join(path).is_file(),
            "source artifact {source_id} missing at {path}"
        );
    }

    let ids = binding_ids(&manifest)?;
    assert_eq!(
        ids,
        REQUIRED_BINDINGS
            .iter()
            .map(|item| item.to_string())
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        manifest["retirement_gate_contract"]["required_rule_ids"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    assert_eq!(
        manifest["retirement_gate_contract"]["required_stage_order"]
            .as_array()
            .map(Vec::len),
        Some(4)
    );
    Ok(())
}

#[test]
fn policy_summary_matches_live_policy() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;
    let policy = load_json(&root.join("tests/conformance/math_retirement_policy.json"))?;
    assert_eq!(manifest["expected_policy_summary"], policy["summary"]);
    assert_eq!(
        manifest["migration_contract"]["expected_research_only_modules"].as_u64(),
        Some(44)
    );
    assert_eq!(
        manifest["migration_contract"]["expected_total_modules_to_migrate"].as_u64(),
        Some(0)
    );
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_report() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out_dir.join("math_retirement_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-545"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-545.1"));
    assert_eq!(
        report["summary"]["policy"]["production_modules"].as_u64(),
        Some(25)
    );
    assert_eq!(
        report["summary"]["policy"]["research_only_modules"].as_u64(),
        Some(44)
    );
    assert_eq!(
        report["summary"]["policy"]["total_modules_to_migrate"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["summary"]["bindings"]["binding_count"].as_u64(),
        Some(4)
    );
    Ok(())
}

#[test]
fn checker_emits_jsonl_rows_with_required_fields() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let rows = read_jsonl(&out_dir.join("math_retirement_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 6, "checker should emit six pass telemetry rows");
    let events = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect::<BTreeSet<_>>();
    assert!(events.contains("math_retirement_completion_summary"));
    assert!(events.contains("math_retirement_migration_binding"));
    assert!(events.contains("math_retirement_completion_contract_pass"));

    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(!row[field].is_null(), "log row missing {field}: {row}");
        }
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert_eq!(row["failure_signature"].as_str(), Some("none"));
    }
    Ok(())
}

#[test]
fn checker_rejects_migration_summary_drift() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "bad_migration")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["migration_contract"]["expected_total_modules_to_migrate"] = json!(1);
    let mutated = out_dir.join("contract_bad_migration.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject migration drift:\n{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("math_retirement_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("expected_total_modules_to_migrate drifted")),
        "expected migration drift failure, got {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_required_rule() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "bad_rule")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["retirement_gate_contract"]["required_rule_ids"] = json!(["RC-1", "RC-3"]);
    let mutated = out_dir.join("contract_bad_rule.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject bad rule list:\n{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("math_retirement_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("required_rule_ids must match canonical")),
        "expected rule-list failure, got {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_bare_cargo_required_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "bare_cargo")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["missing_item_bindings"][0]["required_commands"][0] =
        json!("cargo test -p frankenlibc-harness --test math_retirement_test -- --nocapture");
    let mutated = out_dir.join("contract_bare_cargo.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject bare cargo command:\n{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("math_retirement_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("cargo validation command must use rch")),
        "expected rch-routing failure, got {report}"
    );
    Ok(())
}
