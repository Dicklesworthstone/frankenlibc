//! Contract tests for bd-vfl.1 README/FEATURE_PARITY support-taxonomy completion.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_MISSING_ITEMS: &[(&str, &str)] = &[
    ("unit_primary", "tests.unit.primary"),
    ("e2e_primary", "tests.e2e.primary"),
    ("telemetry_primary", "telemetry.primary"),
];

const EXPECTED_EVENTS: &[&str] = &[
    "docs_support_taxonomy_completion_contract_validated",
    "docs_support_taxonomy_summary",
    "docs_semantic_claims_gate_replayed",
    "claim_reconciliation_gate_replayed",
    "replacement_levels_gate_replayed",
];

const EXPECTED_FIELDS: &[&str] = &[
    "timestamp",
    "trace_id",
    "event",
    "level",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "status",
    "source_commit",
    "missing_items_bound",
    "test_refs",
    "docs_summary",
    "docs_semantic_report",
    "claim_reconciliation_report",
    "replacement_levels_report",
    "artifact_refs",
    "failure_signature",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest should have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest should live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/docs_support_taxonomy_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_docs_support_taxonomy_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
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
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string array"))?;
    let mut set = BTreeSet::new();
    for item in array {
        set.insert(
            item.as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))?
                .to_string(),
        );
    }
    Ok(set)
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "docs-support-taxonomy-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_DOCS_SUPPORT_TAXONOMY_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_DOCS_SUPPORT_TAXONOMY_COMPLETION_REPORT",
            out_dir.join("docs_support_taxonomy_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_DOCS_SUPPORT_TAXONOMY_COMPLETION_LOG",
            out_dir.join("docs_support_taxonomy_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_DOCS_SUPPORT_TAXONOMY_CLAIM_REPORT",
            out_dir.join("docs_support_taxonomy_completion.claim_reconciliation.report.json"),
        )
        .env(
            "FRANKENLIBC_DOCS_SUPPORT_TAXONOMY_LEVELS_REPORT",
            out_dir.join("docs_support_taxonomy_completion.replacement_levels.report.json"),
        )
        .env(
            "FRANKENLIBC_DOCS_SUPPORT_TAXONOMY_LEVELS_LOG",
            out_dir.join("docs_support_taxonomy_completion.replacement_levels.log.jsonl"),
        )
        .output()?)
}

fn checker_output_message(output: &std::process::Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_passing_checker(root: &Path, label: &str) -> TestResult<PathBuf> {
    let out_dir = unique_output_dir(root, label)?;
    let output = run_checker(root, &contract_path(root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass:\n{}",
        checker_output_message(&output)
    );
    Ok(out_dir)
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &str) -> TestResult {
    let (path, line) = file_line_ref.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "file-line ref should contain ':'",
        )
    })?;
    let line_no: usize = line.parse()?;
    let full_path = root.join(path);
    assert!(
        full_path.is_file(),
        "missing file-line path: {file_line_ref}"
    );
    let text = std::fs::read_to_string(full_path)?;
    let lines: Vec<_> = text.lines().collect();
    assert!(line_no > 0 && line_no <= lines.len());
    assert!(!lines[line_no - 1].trim().is_empty());
    Ok(())
}

fn source_texts(root: &Path, manifest: &Value) -> TestResult<BTreeMap<String, String>> {
    let sources = manifest["completion_debt_evidence"]["test_sources"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_sources object"))?;
    let mut texts = BTreeMap::new();
    for (key, path) in sources {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source path string"))?;
        texts.insert(key.clone(), std::fs::read_to_string(root.join(path))?);
    }
    Ok(texts)
}

fn assert_test_refs_exist(
    section_name: &str,
    section: &Value,
    sources: &BTreeMap<String, String>,
) -> TestResult {
    let refs = section["required_test_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test refs array"))?;
    assert!(!refs.is_empty(), "{section_name} should name test refs");
    for test_ref in refs {
        let source = test_ref["source"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source string"))?;
        let name = test_ref["name"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test name string"))?;
        let text = sources
            .get(source)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source declared"))?;
        assert!(
            text.contains(&format!("fn {name}")) || text.contains(&format!("def {name}")),
            "{section_name} references missing test {source}::{name}"
        );
    }
    Ok(())
}

#[test]
fn manifest_binds_unit_e2e_and_telemetry_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    let readme = std::fs::read_to_string(root.join("README.md"))?;
    let feature_parity = std::fs::read_to_string(root.join("FEATURE_PARITY.md"))?;

    assert_eq!(manifest["bead"].as_str(), Some("bd-vfl"));
    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-vfl.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-vfl"));

    let refs = evidence["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation refs"))?;
    assert!(refs.len() >= 30);
    for file_line in refs {
        assert_file_line_ref_exists(
            &root,
            file_line
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "file line string"))?,
        )?;
    }

    let sources = source_texts(&root, &manifest)?;
    for (section_name, missing_item) in EXPECTED_MISSING_ITEMS {
        let section = &evidence[*section_name];
        assert_eq!(section["missing_item_id"].as_str(), Some(*missing_item));
        assert_test_refs_exist(section_name, section, &sources)?;
        for command in section["required_commands"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "commands array"))?
        {
            let command = command
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "command string"))?;
            assert!(!command.contains("cargo ") || command.contains("rch exec --"));
        }
    }

    let truth = &evidence["required_docs_truth"];
    assert_eq!(truth["required_claim_field_count"].as_u64(), Some(8));
    assert_eq!(truth["semantic_parity_blocker_count"].as_u64(), Some(18));
    assert_eq!(truth["taxonomy_semantic_conflict_count"].as_u64(), Some(18));
    assert_eq!(truth["forbidden_claim_count"].as_u64(), Some(0));
    for phrase in truth["required_readme_phrases"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "readme phrases"))?
    {
        assert!(readme.contains(phrase.as_str().unwrap_or_default()));
    }
    for phrase in truth["required_feature_parity_phrases"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "feature phrases"))?
    {
        assert!(feature_parity.contains(phrase.as_str().unwrap_or_default()));
    }
    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "report")?;
    let report = read_json(&out_dir.join("docs_support_taxonomy_completion_contract.report.json"))?;
    let log = read_jsonl(&out_dir.join("docs_support_taxonomy_completion_contract.log.jsonl"))?;

    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-vfl.1"));
    assert_eq!(
        string_set(&report["missing_items_bound"])?,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|(_, item)| item.to_string())
            .collect()
    );
    assert_eq!(
        report["docs_summary"]["docs_semantic"]["forbidden_claim_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["docs_summary"]["claim_reconciliation"]["errors"].as_u64(),
        Some(0)
    );

    let events: BTreeSet<_> = log
        .iter()
        .filter_map(|row| row["event"].as_str())
        .map(str::to_string)
        .collect();
    for expected in EXPECTED_EVENTS {
        assert!(events.contains(*expected), "missing event {expected}");
    }
    for row in &log {
        for field in EXPECTED_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
    }
    Ok(())
}

#[test]
fn checker_replays_docs_claim_gates_and_preserves_current_scope() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "gates")?;
    let report = read_json(&out_dir.join("docs_support_taxonomy_completion_contract.report.json"))?;
    let claim_report = read_json(
        &out_dir.join("docs_support_taxonomy_completion.claim_reconciliation.report.json"),
    )?;
    let levels_report = read_json(
        &out_dir.join("docs_support_taxonomy_completion.replacement_levels.report.json"),
    )?;
    let docs_report = read_json(&root.join("target/conformance/docs_semantic_claims.report.json"))?;

    assert_eq!(docs_report["status"].as_str(), Some("pass"));
    assert_eq!(
        docs_report["summary"]["forbidden_claim_count"].as_u64(),
        Some(0)
    );
    assert_eq!(claim_report["status"].as_str(), Some("pass"));
    assert_eq!(claim_report["summary"]["errors"].as_u64(), Some(0));
    assert_eq!(claim_report["summary"]["warnings"].as_u64(), Some(0));
    assert_eq!(levels_report["status"].as_str(), Some("pass"));
    assert_eq!(levels_report["current_level"].as_str(), Some("L1"));
    assert_eq!(report["docs_summary"]["current_level"].as_str(), Some("L1"));
    Ok(())
}

#[test]
fn checker_rejects_bare_cargo_required_command() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_commands"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "commands array"))?
        .push(Value::String(
            "cargo test -p frankenlibc-harness --test docs_support_taxonomy_completion_contract_test"
                .to_string(),
        ));
    let out_dir = unique_output_dir(&root, "bare-cargo")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success());
    assert!(checker_output_message(&output).contains("contract_validation_failed"));
    Ok(())
}

#[test]
fn checker_rejects_missing_required_event_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    let events = manifest["completion_debt_evidence"]["telemetry_primary"]["required_events"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "events array"))?;
    events.retain(|event| event.as_str() != Some("claim_reconciliation_gate_replayed"));
    let out_dir = unique_output_dir(&root, "missing-event")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success());
    assert!(checker_output_message(&output).contains("contract_validation_failed"));
    Ok(())
}

#[test]
fn checker_rejects_stale_file_line_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["implementation_refs"][0] =
        Value::String("README.md:999999".to_string());
    let out_dir = unique_output_dir(&root, "stale-ref")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success());
    assert!(checker_output_message(&output).contains("contract_validation_failed"));
    Ok(())
}
