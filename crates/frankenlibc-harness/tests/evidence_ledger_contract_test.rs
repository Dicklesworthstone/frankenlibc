//! Integration tests for the evidence ledger contract checker.
//!
//! The checker pins JSONL replay, OTLP-shaped telemetry, correlation IDs,
//! redaction policy, and the completion-debt bindings for `bd-28tf.1`.

use serde_json::Value;
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTRACT_REL: &str = "tests/conformance/evidence_ledger_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_evidence_ledger_contract.sh";
const JSONL_REQUIRED_FIELDS: &[&str] = &[
    "timestamp",
    "evidence_seqno",
    "trace_id",
    "decision_id",
    "policy_id",
    "schema_version",
    "category",
    "level",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "outcome",
    "healing_action",
    "errno",
    "latency_ns",
    "details",
    "artifact_refs",
    "redaction_policy",
];
const OTLP_LOG_ATTRIBUTES: &[&str] = &[
    "frankenlibc.trace_id",
    "frankenlibc.evidence_seqno",
    "frankenlibc.decision_id",
    "frankenlibc.policy_id",
    "frankenlibc.schema_version",
    "frankenlibc.category",
    "frankenlibc.level",
    "frankenlibc.mode",
    "frankenlibc.api_family",
    "frankenlibc.symbol",
    "frankenlibc.decision_path",
    "frankenlibc.outcome",
    "frankenlibc.healing_action",
    "frankenlibc.errno",
    "frankenlibc.latency_ns",
    "frankenlibc.details",
    "frankenlibc.artifact_refs",
    "frankenlibc.redaction_policy",
];
const TELEMETRY_LOG_FIELDS: &[&str] = &[
    "timestamp",
    "trace_id",
    "bead_id",
    "completion_debt_bead",
    "event",
    "status",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
    "failure_signature",
];
const REQUIRED_CATEGORIES: &[&str] = &[
    "metrics_snapshot",
    "healing_action",
    "validation_decision",
    "conformance_result",
    "runtime_math_decision",
];
const COMPLETION_SECTIONS: &[&str] = &[
    "conformance_primary",
    "e2e_primary",
    "telemetry_primary",
    "unit_primary",
];

fn repo_root() -> TestResult<PathBuf> {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| io::Error::other("crate directory should have workspace parent"))?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| io::Error::other("workspace parent should have repo parent"))?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join(CONTRACT_REL)
}

fn checker_path(root: &Path) -> PathBuf {
    root.join(CHECKER_REL)
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
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

fn string_set(value: &Value, field: &str) -> TestResult<BTreeSet<String>> {
    let values = value
        .get(field)
        .ok_or_else(|| io::Error::other(format!("{field} must be present")))?
        .as_array()
        .ok_or_else(|| io::Error::other(format!("{field} must be an array")))?;
    values
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| io::Error::other(format!("{field} entries must be strings")).into())
        })
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "evidence_ledger_contract_{label}_{}_{}",
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
        .env("FRANKENLIBC_EVIDENCE_LEDGER_CONTRACT", contract)
        .env(
            "FRANKENLIBC_EVIDENCE_LEDGER_REPORT",
            out_dir.join("evidence_ledger_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_EVIDENCE_LEDGER_LOG",
            out_dir.join("evidence_ledger_contract.log.jsonl"),
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

fn assert_file_line_ref(root: &Path, reference: &str) -> TestResult {
    let (path, line) = reference
        .rsplit_once(':')
        .ok_or_else(|| io::Error::other(format!("{reference} must be file:line")))?;
    let line_number: usize = line.parse()?;
    let text = std::fs::read_to_string(root.join(path))?;
    let line_text = text
        .lines()
        .nth(line_number.saturating_sub(1))
        .ok_or_else(|| io::Error::other(format!("{reference} points past EOF")))?;
    assert!(
        !line_text.trim().is_empty(),
        "{reference} must not point at a blank line"
    );
    Ok(())
}

fn assert_log_row_has_required_fields(row: &Value) {
    for field in TELEMETRY_LOG_FIELDS {
        assert!(row.get(*field).is_some(), "log row missing {field}");
    }
}

#[test]
fn contract_pins_jsonl_otlp_redaction_and_completion_debt() -> TestResult {
    let root = repo_root()?;
    let contract = load_json(&contract_path(&root))?;

    assert_eq!(
        contract["schema_version"].as_str(),
        Some("evidence_ledger_contract.v1")
    );
    assert_eq!(
        contract["manifest_id"].as_str(),
        Some("evidence-ledger-contract")
    );
    assert_eq!(contract["bead"].as_str(), Some("bd-28tf"));
    assert_eq!(contract["canonical_checker"].as_str(), Some(CHECKER_REL));
    assert!(checker_path(&root).is_file(), "{CHECKER_REL} must exist");

    for source in contract["source_modules"]
        .as_array()
        .ok_or_else(|| io::Error::other("source_modules must be an array"))?
    {
        let source = source
            .as_str()
            .ok_or_else(|| io::Error::other("source module must be a string"))?;
        assert!(
            root.join(source).is_file(),
            "source module missing: {source}"
        );
    }

    assert_eq!(
        string_set(&contract["jsonl_contract"], "required_fields")?,
        JSONL_REQUIRED_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        string_set(&contract["jsonl_contract"], "required_categories")?,
        REQUIRED_CATEGORIES
            .iter()
            .map(|category| (*category).to_owned())
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        contract["otlp_contract"]["schema"].as_str(),
        Some("logs/v1")
    );
    assert_eq!(
        string_set(&contract["otlp_contract"], "required_log_attributes")?,
        OTLP_LOG_ATTRIBUTES
            .iter()
            .map(|field| (*field).to_owned())
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        string_set(&contract["telemetry_contract"], "required_log_fields")?,
        TELEMETRY_LOG_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        contract["privacy_redaction_policy"]["default_policy"].as_str(),
        Some("redact_pointers")
    );

    let completion = &contract["completion_debt_evidence"];
    assert_eq!(completion["bead"].as_str(), Some("bd-28tf.1"));
    assert_eq!(completion["original_bead"].as_str(), Some("bd-28tf"));
    assert_eq!(completion["next_audit_score_threshold"].as_u64(), Some(800));

    let test_source = completion["test_source"]
        .as_str()
        .ok_or_else(|| io::Error::other("test_source must be present"))?;
    let test_source_text = std::fs::read_to_string(root.join(test_source))?;
    for section in COMPLETION_SECTIONS {
        let required_test_names = completion[*section]["required_test_names"]
            .as_array()
            .ok_or_else(|| io::Error::other(format!("{section}.required_test_names missing")))?;
        for test_name in required_test_names {
            let test_name = test_name
                .as_str()
                .ok_or_else(|| io::Error::other("required test name must be a string"))?;
            assert!(
                test_source_text.contains(&format!("fn {test_name}(")),
                "{section} references missing test {test_name}"
            );
        }
    }
    for reference in completion["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::other("implementation_refs must be an array"))?
    {
        let reference = reference
            .as_str()
            .ok_or_else(|| io::Error::other("implementation ref must be a string"))?;
        assert_file_line_ref(&root, reference)?;
    }

    Ok(())
}

#[test]
fn checker_emits_pass_report_and_jsonl_telemetry() -> TestResult {
    let root = repo_root()?;
    let out = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out.join("evidence_ledger_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("evidence_ledger_contract.report.v1")
    );
    assert_eq!(report["bead"].as_str(), Some("bd-28tf"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-28tf.1"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));
    assert!(report["errors"].as_array().unwrap().is_empty());
    assert_eq!(
        report["summary"]["jsonl_required_field_count"].as_u64(),
        Some(JSONL_REQUIRED_FIELDS.len() as u64)
    );
    assert_eq!(
        report["summary"]["otlp_required_log_attribute_count"].as_u64(),
        Some(OTLP_LOG_ATTRIBUTES.len() as u64)
    );

    let sections = report["summary"]["completion_debt_sections"]
        .as_array()
        .ok_or_else(|| io::Error::other("completion sections must be an array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(sections, COMPLETION_SECTIONS.iter().copied().collect());

    let rows = read_jsonl(&out.join("evidence_ledger_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_log_row_has_required_fields(row);
    assert_eq!(
        row["event"].as_str(),
        Some("evidence_ledger_contract_validated")
    );
    assert_eq!(row["status"].as_str(), Some("pass"));
    assert_eq!(row["failure_signature"].as_str(), Some("none"));
    assert_eq!(row["bead_id"].as_str(), Some("bd-28tf"));
    assert_eq!(row["completion_debt_bead"].as_str(), Some("bd-28tf.1"));
    assert_eq!(row["errno"].as_i64(), Some(0));
    assert!(
        row["artifact_refs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|artifact| artifact.as_str() == Some(CONTRACT_REL)),
        "log should cite the canonical contract"
    );

    Ok(())
}

#[test]
fn checker_rejects_stale_test_binding_and_logs_failure() -> TestResult {
    let root = repo_root()?;
    let out = unique_out_dir(&root, "stale")?;
    let mut contract = load_json(&contract_path(&root))?;
    let stale_source = out.join("stale_evidence_ledger_source.rs");
    std::fs::write(
        &stale_source,
        "#[test]\nfn unrelated_stale_placeholder() {}\n",
    )?;
    let stale_source_rel = stale_source
        .strip_prefix(&root)?
        .to_string_lossy()
        .replace('\\', "/");
    contract["completion_debt_evidence"]["test_source"] = Value::String(stale_source_rel);

    let stale_contract = out.join("evidence_ledger_contract.stale.json");
    write_json(&stale_contract, &contract)?;
    let output = run_checker(&root, &stale_contract, &out)?;
    assert!(!output.status.success(), "{}", output_text(&output));

    let report = load_json(&out.join("evidence_ledger_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some("evidence_ledger_contract_invalid")
    );
    let errors = report["errors"]
        .as_array()
        .ok_or_else(|| io::Error::other("errors must be an array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("references missing test")),
        "expected stale test-source binding error, got {errors:?}"
    );

    let rows = read_jsonl(&out.join("evidence_ledger_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_log_row_has_required_fields(row);
    assert_eq!(
        row["event"].as_str(),
        Some("evidence_ledger_contract_failed")
    );
    assert_eq!(row["status"].as_str(), Some("fail"));
    assert_eq!(
        row["failure_signature"].as_str(),
        Some("evidence_ledger_contract_invalid")
    );
    assert_eq!(row["errno"].as_i64(), Some(22));

    Ok(())
}
