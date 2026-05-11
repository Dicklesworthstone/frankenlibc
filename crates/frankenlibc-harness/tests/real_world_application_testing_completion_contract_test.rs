//! Completion-debt contract tests for bd-33xi / bd-33xi.1 real-world application testing.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const TIER1: &[&str] = &["bash", "coreutils", "curl", "git", "python3"];
const TIER2: &[&str] = &[
    "go-programs",
    "nginx",
    "nodejs",
    "postgresql",
    "redis-server",
];
const REQUIRED_SCENARIOS: &[&str] = &[
    "basic_functionality",
    "error_condition_handling",
    "graceful_shutdown",
    "high_load_stress",
    "long_running_operation",
];
const VALIDATION_DIMENSIONS: &[&str] = &[
    "functional_correctness",
    "memory_bounded_overhead",
    "performance_budget",
    "stability_no_crash_or_hang",
];
const MISSING_ITEMS: &[&str] = &[
    "tests.e2e.primary",
    "tests.integration.primary",
    "tests.unit.primary",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest must have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest must live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/real_world_application_testing_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_real_world_application_testing_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "real_world_application_testing_completion_{label}_{}_{}",
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
        .env("FRANKENLIBC_REAL_WORLD_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_REAL_WORLD_COMPLETION_REPORT",
            out_dir.join("real_world_application_testing_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_REAL_WORLD_COMPLETION_LOG",
            out_dir.join("real_world_application_testing_completion_contract.log.jsonl"),
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

fn strings(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string").into())
                .map(str::to_owned)
        })
        .collect()
}

fn expected(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &str) -> TestResult {
    let (path, line) = file_line_ref.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "file-line ref should contain ':'",
        )
    })?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "file-line ref line must be positive");
    let full_path = root.join(path);
    assert!(
        full_path.exists(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let file_text = std::fs::read_to_string(&full_path)?;
    let lines: Vec<_> = file_text.lines().collect();
    assert!(
        line_no <= lines.len(),
        "file-line ref outside file: {file_line_ref}"
    );
    assert!(
        !lines[line_no - 1].trim().is_empty(),
        "file-line ref should not cite a blank line: {file_line_ref}"
    );
    Ok(())
}

fn application_rows(contract: &Value) -> TestResult<Vec<&Value>> {
    Ok(
        contract["completion_debt_evidence"]["real_world_contract"]["application_rows"]
            .as_array()
            .ok_or("application_rows should be array")?
            .iter()
            .collect(),
    )
}

fn source_texts(root: &Path, manifest: &Value) -> TestResult<HashMap<String, String>> {
    let mut result = HashMap::new();
    let sources = manifest["completion_debt_evidence"]["test_sources"]
        .as_object()
        .ok_or("test_sources should be object")?;
    for (key, path) in sources {
        let path = path.as_str().ok_or("test source path string")?;
        result.insert(key.to_owned(), std::fs::read_to_string(root.join(path))?);
    }
    Ok(result)
}

#[test]
fn manifest_binds_unit_integration_and_e2e_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("real_world_application_testing_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-33xi.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-33xi"));

    for path in manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts should be object")?
        .values()
    {
        let path = path.as_str().ok_or("source artifact path string")?;
        assert!(root.join(path).exists(), "source artifact missing: {path}");
    }

    let bindings: BTreeSet<_> = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings should be array")?
        .iter()
        .map(|binding| {
            binding["missing_item_id"]
                .as_str()
                .ok_or("missing_item_id")
                .map(str::to_owned)
        })
        .collect::<Result<_, _>>()?;
    assert_eq!(bindings, expected(MISSING_ITEMS));

    let source_texts = source_texts(&root, &manifest)?;
    for section in ["unit_primary", "integration_primary", "e2e_primary"] {
        let refs = manifest["completion_debt_evidence"][section]["required_test_refs"]
            .as_array()
            .ok_or("required_test_refs should be array")?;
        assert!(!refs.is_empty(), "{section} should bind at least one test");
        for test_ref in refs {
            let source = test_ref["source"].as_str().ok_or("source string")?;
            let name = test_ref["name"].as_str().ok_or("name string")?;
            let text = source_texts.get(source).ok_or("declared source")?;
            assert!(
                text.contains(&format!("fn {name}")),
                "{section} references missing test {source}::{name}"
            );
        }
    }

    let refs = manifest["completion_debt_evidence"]["implementation_refs"]
        .as_array()
        .ok_or("implementation_refs should be array")?;
    assert!(refs.len() >= 20, "implementation refs should be broad");
    for file_line_ref in refs {
        assert_file_line_ref_exists(&root, file_line_ref.as_str().ok_or("ref string")?)?;
    }

    Ok(())
}

#[test]
fn application_tiers_preserve_parent_bead_scope_and_claim_block_gaps() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&contract_path(&root))?;
    let contract = &manifest["completion_debt_evidence"]["real_world_contract"];
    assert_eq!(
        strings(&contract["required_tier1_applications"])?,
        expected(TIER1)
    );
    assert_eq!(
        strings(&contract["required_tier2_applications"])?,
        expected(TIER2)
    );
    assert_eq!(
        strings(&contract["required_scenarios"])?,
        expected(REQUIRED_SCENARIOS)
    );
    assert_eq!(
        strings(&contract["validation_dimensions"])?,
        expected(VALIDATION_DIMENSIONS)
    );

    let workload_matrix = load_json(&root.join("tests/conformance/workload_matrix.json"))?;
    let workload_binaries: BTreeSet<_> = workload_matrix["workloads"]
        .as_array()
        .ok_or("workloads should be array")?
        .iter()
        .filter_map(|row| row["binary"].as_str().map(str::to_owned))
        .collect();

    let rows = application_rows(&manifest)?;
    assert_eq!(
        rows.len(),
        10,
        "must retain all original bd-33xi applications"
    );
    let mut row_ids = BTreeSet::new();
    let mut blocked_gaps = BTreeSet::new();
    for row in rows {
        let app = row["application_id"].as_str().ok_or("application_id")?;
        row_ids.insert(app.to_owned());
        assert_eq!(
            strings(&row["runtime_modes"])?,
            expected(&["hardened", "strict"])
        );
        assert_eq!(strings(&row["scenarios"])?, expected(REQUIRED_SCENARIOS));
        assert_eq!(
            strings(&row["validation_dimensions"])?,
            expected(VALIDATION_DIMENSIONS)
        );

        match row["claim_status"].as_str() {
            Some("evidence_bound") => {
                let binary = row["workload_matrix_binary"]
                    .as_str()
                    .ok_or("evidence_bound workload_matrix_binary")?;
                assert!(
                    workload_binaries.contains(binary),
                    "{app}: evidence_bound binary must exist in workload_matrix"
                );
                assert_eq!(row["failure_signature"].as_str(), Some("none"));
                assert_eq!(row["support_claimed"].as_bool(), Some(true));
            }
            Some("claim_blocked_gap") => {
                blocked_gaps.insert(app.to_owned());
                assert_eq!(row["failure_signature"].as_str(), Some("source_matrix_gap"));
                assert_eq!(row["support_claimed"].as_bool(), Some(false));
                assert!(
                    row["source_matrix_gap_reason"]
                        .as_str()
                        .is_some_and(|reason| reason.contains("not present")),
                    "{app}: gap reason should explain missing exact source row"
                );
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{app}: unexpected claim_status {other:?}"),
                )
                .into());
            }
        }
    }

    assert_eq!(row_ids, expected(&[TIER1, TIER2].concat()));
    assert_eq!(
        blocked_gaps,
        expected(&["go-programs", "nodejs", "postgresql"])
    );
    Ok(())
}

#[test]
fn checker_emits_report_and_structured_log_row() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("real_world_application_testing_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("real_world_application_testing_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-33xi.1"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-33xi"));
    assert_eq!(strings(&report["missing_items"])?, expected(MISSING_ITEMS));
    assert_eq!(strings(&report["tier1_applications"])?, expected(TIER1));
    assert_eq!(strings(&report["tier2_applications"])?, expected(TIER2));
    assert_eq!(
        strings(&report["claim_blocked_applications"])?,
        expected(&["go-programs", "nodejs", "postgresql"])
    );

    let log_text = std::fs::read_to_string(
        out_dir.join("real_world_application_testing_completion_contract.log.jsonl"),
    )?;
    let row: Value = serde_json::from_str(log_text.trim())?;
    assert_eq!(
        row["event"].as_str(),
        Some("real_world_application_testing_completion_contract_validated")
    );
    assert_eq!(row["outcome"].as_str(), Some("pass"));
    assert!(
        validate_log_line(log_text.trim(), 1).is_ok(),
        "completion log row must satisfy structured_log validator"
    );

    Ok(())
}

#[test]
fn checker_rejects_removed_tier2_application() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "missing-tier2")?;
    let mut manifest = load_json(&contract_path(&root))?;
    let rows = manifest["completion_debt_evidence"]["real_world_contract"]["application_rows"]
        .as_array_mut()
        .ok_or("application_rows should be array")?;
    rows.retain(|row| row["application_id"].as_str() != Some("nodejs"));
    let mutated = out_dir.join("missing_nodejs.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly passed: {}",
        output_text(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("application_rows must include exactly the original 10 applications")
            || stderr.contains("application set mismatch"),
        "stderr should identify the missing application: {stderr}"
    );
    Ok(())
}

#[test]
fn checker_rejects_unblocked_gap_application() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "unblocked-gap")?;
    let mut manifest = load_json(&contract_path(&root))?;
    let rows = manifest["completion_debt_evidence"]["real_world_contract"]["application_rows"]
        .as_array_mut()
        .ok_or("application_rows should be array")?;
    let postgresql = rows
        .iter_mut()
        .find(|row| row["application_id"].as_str() == Some("postgresql"))
        .ok_or("postgresql row")?;
    postgresql["claim_status"] = json!("evidence_bound");
    postgresql["support_claimed"] = json!(true);
    postgresql["failure_signature"] = json!("none");
    let mutated = out_dir.join("unblocked_gap.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly passed: {}",
        output_text(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("evidence_bound rows must include workload_matrix_binary"),
        "stderr should identify missing exact source evidence: {stderr}"
    );
    Ok(())
}
