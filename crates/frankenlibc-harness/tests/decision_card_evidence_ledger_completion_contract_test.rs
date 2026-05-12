//! Contract tests for bd-3h1u.2.1 decision-card EvidenceLedger completion evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    message.into().into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("cannot resolve workspace root"))?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/decision_card_evidence_ledger_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_decision_card_evidence_ledger_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| test_error("value should be array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("array item should be string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "decision-card-evidence-ledger-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .env(
            "FRANKENLIBC_DECISION_CARD_EVIDENCE_LEDGER_CONTRACT",
            manifest,
        )
        .env("FRANKENLIBC_DECISION_CARD_EVIDENCE_LEDGER_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_DECISION_CARD_EVIDENCE_LEDGER_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_DECISION_CARD_EVIDENCE_LEDGER_LOG",
            out_dir.join("events.jsonl"),
        )
        .env(
            "FRANKENLIBC_DECISION_CARD_EVIDENCE_LEDGER_REPLAY_REPORT",
            out_dir.join("evidence_ledger_report.json"),
        )
        .env(
            "FRANKENLIBC_DECISION_CARD_EVIDENCE_LEDGER_REPLAY_LOG",
            out_dir.join("evidence_ledger_events.jsonl"),
        )
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn read_log_events(path: &Path) -> TestResult<BTreeSet<String>> {
    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let row: Value = serde_json::from_str(line)?;
            row["event"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("log row missing event"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn assert_file_line_ref_exists(root: &Path, value: &str) -> TestResult {
    let (path, line) = value
        .rsplit_once(':')
        .ok_or_else(|| test_error("file line ref should contain ':'"))?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "line ref must be positive");
    let full_path = root.join(path);
    assert!(full_path.is_file(), "file-line ref missing path {value}");
    let text = fs::read_to_string(full_path)?;
    let line_count = text.lines().count();
    assert!(line_no <= line_count, "file-line ref outside file: {value}");
    assert!(
        text.lines()
            .nth(line_no - 1)
            .is_some_and(|line| !line.trim().is_empty()),
        "file-line ref points at blank line: {value}"
    );
    Ok(())
}

#[test]
fn contract_anchors_golden_and_telemetry_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("decision_card_evidence_ledger_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-3h1u.2"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-3h1u.2.1")
    );
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.golden.primary".to_string(),
            "telemetry.primary".to_string(),
        ])
    );
    assert!(
        manifest["audit_reference"]["score_threshold"]
            .as_u64()
            .unwrap_or(0)
            >= 800
    );
    for reference in manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| test_error("implementation refs should be array"))?
    {
        assert_file_line_ref_exists(
            &root,
            reference
                .as_str()
                .ok_or_else(|| test_error("implementation ref should be string"))?,
        )?;
    }
    Ok(())
}

#[test]
fn source_artifacts_bind_existing_decision_card_surfaces() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let sources = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source artifacts should be array"))?;
    let ids = sources
        .iter()
        .map(|source| {
            source["id"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("source id should be string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(
        ids,
        BTreeSet::from([
            "completion_checker".to_string(),
            "completion_harness".to_string(),
            "evidence_ledger_checker".to_string(),
            "evidence_ledger_contract".to_string(),
            "runtime_math_evidence".to_string(),
            "runtime_math_mod".to_string(),
            "unified_evidence_ledger".to_string(),
        ])
    );

    for source in sources {
        let path = source["path"]
            .as_str()
            .ok_or_else(|| test_error("source path should be string"))?;
        let text = fs::read_to_string(root.join(path))?;
        for needle in source["required_needles"]
            .as_array()
            .ok_or_else(|| test_error("required needles should be array"))?
        {
            let needle = needle
                .as_str()
                .ok_or_else(|| test_error("needle should be string"))?;
            assert!(
                text.contains(needle),
                "{path} should contain required needle {needle}"
            );
        }
    }
    Ok(())
}

#[test]
fn golden_contract_binds_decision_card_export_and_replay_tests() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let golden = &manifest["golden_primary"];
    assert_eq!(
        golden["missing_item_id"].as_str(),
        Some("tests.golden.primary")
    );
    assert_eq!(
        golden["required_export_schema"].as_str(),
        Some("decision_cards.v1")
    );
    let export_fields = string_set(&golden["required_export_fields"])?;
    for field in [
        "schema",
        "count",
        "cards",
        "decision_id",
        "trace_id",
        "decision_type",
        "mode",
        "symbol",
        "context_hash",
        "reason_hash",
        "outcome_hash",
        "counterfactual_hash",
    ] {
        assert!(
            export_fields.contains(field),
            "missing export field {field}"
        );
    }

    let runtime_math_evidence =
        fs::read_to_string(root.join("crates/frankenlibc-membrane/src/runtime_math/evidence.rs"))?;
    let runtime_math_mod =
        fs::read_to_string(root.join("crates/frankenlibc-membrane/src/runtime_math/mod.rs"))?;
    for test_name in string_set(&golden["required_runtime_math_tests"])? {
        let needle = format!("fn {test_name}(");
        assert!(
            runtime_math_evidence.contains(&needle) || runtime_math_mod.contains(&needle),
            "missing runtime math test {test_name}"
        );
    }
    for test_name in string_set(&golden["required_telemetry_smoke_tests"])? {
        let needle = format!("fn {test_name}(");
        assert!(
            runtime_math_evidence.contains(&needle),
            "missing telemetry smoke test {test_name}"
        );
    }
    for prefix in string_set(&golden["required_stdout_prefixes"])? {
        assert!(
            runtime_math_evidence.contains(&prefix),
            "missing stdout prefix {prefix}"
        );
    }
    Ok(())
}

#[test]
fn telemetry_contract_replays_unified_evidence_ledger_gate() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let telemetry = &manifest["telemetry_primary"];
    assert_eq!(
        telemetry["missing_item_id"].as_str(),
        Some("telemetry.primary")
    );
    let completion_events = string_set(&telemetry["required_completion_events"])?;
    for event in [
        "decision_card_evidence.source_artifacts_validated",
        "decision_card_evidence.golden_validated",
        "decision_card_evidence.telemetry_validated",
        "decision_card_evidence.evidence_ledger_gate_replayed",
        "decision_card_evidence.completion_contract_validated",
        "decision_card_evidence.completion_contract_failed",
    ] {
        assert!(completion_events.contains(event), "missing event {event}");
    }
    let evidence_events = string_set(&telemetry["required_evidence_ledger_events"])?;
    assert!(evidence_events.contains("evidence_ledger_contract_validated"));
    assert!(evidence_events.contains("evidence_ledger_contract_failed"));
    let report_fields = string_set(&telemetry["required_report_fields"])?;
    for field in [
        "source_commit",
        "runtime_math_test_count",
        "telemetry_smoke_test_count",
        "evidence_ledger_report",
        "evidence_ledger_log",
        "failure_signature",
    ] {
        assert!(
            report_fields.contains(field),
            "missing report field {field}"
        );
    }
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("decision_card_evidence_ledger_completion_contract: PASS"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("decision_card_evidence_ledger_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-3h1u.2.1"));
    assert_eq!(report["source_count"].as_u64(), Some(7));
    assert_eq!(report["runtime_math_test_count"].as_u64(), Some(4));
    assert_eq!(report["telemetry_smoke_test_count"].as_u64(), Some(2));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));

    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    assert!(events.contains("decision_card_evidence.source_artifacts_validated"));
    assert!(events.contains("decision_card_evidence.golden_validated"));
    assert!(events.contains("decision_card_evidence.telemetry_validated"));
    assert!(events.contains("decision_card_evidence.evidence_ledger_gate_replayed"));
    assert!(events.contains("decision_card_evidence.completion_contract_validated"));

    let replay_report = load_json(&out_dir.join("evidence_ledger_report.json"))?;
    assert_eq!(replay_report["status"].as_str(), Some("pass"));
    let replay_events = read_log_events(&out_dir.join("evidence_ledger_events.jsonl"))?;
    assert!(replay_events.contains("evidence_ledger_contract_validated"));
    Ok(())
}

#[test]
fn checker_rejects_missing_golden_export_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let fields = manifest["golden_primary"]["required_export_fields"]
        .as_array_mut()
        .ok_or_else(|| test_error("required export fields should be array"))?;
    fields.retain(|field| field.as_str() != Some("trace_id"));

    let out_dir = unique_output_dir(&root, "missing-field")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject mutated contract"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("golden export fields missing"),
        "unexpected stderr: {}",
        output_text(&output)
    );
    Ok(())
}
