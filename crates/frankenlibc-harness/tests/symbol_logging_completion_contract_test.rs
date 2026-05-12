use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "symbol_logging_source_gate",
    "symbol_logging_sample_gate",
    "symbol_logging_report_gate",
    "symbol_logging_telemetry_gate",
    "symbol_logging_completion_contract_validated",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has workspace parent")
        .parent()
        .expect("workspace parent has repo parent")
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/symbol_logging_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_symbol_logging_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    Ok(fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()?)
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "symbol_logging_completion_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_SYMBOL_LOGGING_CONTRACT", contract)
        .env(
            "FRANKENLIBC_SYMBOL_LOGGING_REPORT",
            out_dir.join("symbol_logging_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_SYMBOL_LOGGING_LOG",
            out_dir.join("symbol_logging_completion_contract.log.jsonl"),
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

#[test]
fn manifest_binds_symbol_logging_completion_items() -> TestResult {
    let root = repo_root();
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("symbol_logging_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-ldj.8"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-ldj.8.1")
    );

    let missing_items: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|binding| binding["id"].as_str())
        .collect();
    assert_eq!(
        missing_items,
        BTreeSet::from(["telemetry.primary", "tests.conformance.primary"])
    );

    let contract = &manifest["symbol_logging_contract"];
    assert_eq!(contract["runtime_event"].as_str(), Some("runtime_decision"));
    assert!(
        contract["required_runtime_decision_fields"]
            .as_array()
            .is_some_and(|fields| fields.len() >= 12)
    );
    assert_eq!(
        contract["expected_controller_id"].as_str(),
        Some("runtime_math_kernel.v1")
    );
    Ok(())
}

#[test]
fn source_anchors_cover_entrypoint_trace_report_and_schema() -> TestResult {
    let root = repo_root();
    let manifest = read_json(&contract_path(&root))?;
    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;

    for (source_key, anchors) in manifest["source_anchors"]
        .as_object()
        .ok_or("source_anchors must be object")?
    {
        let path = source_artifacts[source_key]
            .as_str()
            .ok_or("source path must be string")?;
        let text = fs::read_to_string(root.join(path))?;
        for anchor in anchors.as_array().ok_or("anchors must be array")? {
            let anchor = anchor.as_str().ok_or("anchor must be string")?;
            assert!(
                text.contains(anchor),
                "{source_key} source is missing anchor: {anchor}"
            );
        }
    }
    Ok(())
}

#[test]
fn sample_runtime_decisions_are_joinable_per_symbol_rows() -> TestResult {
    let root = repo_root();
    let manifest = read_json(&contract_path(&root))?;
    let samples = manifest["sample_runtime_decision_rows"]
        .as_array()
        .ok_or("sample rows must be array")?;
    assert!(samples.len() >= 2);

    let mut symbols = BTreeSet::new();
    for sample in samples {
        let symbol = sample["symbol"].as_str().ok_or("sample symbol missing")?;
        symbols.insert(symbol);
        assert_eq!(sample["event"].as_str(), Some("runtime_decision"));
        assert_eq!(
            sample["controller_id"].as_str(),
            Some("runtime_math_kernel.v1")
        );
        assert!(
            sample["trace_id"]
                .as_str()
                .is_some_and(|trace_id| trace_id.starts_with(&format!("abi::{symbol}::")))
        );
        assert!(
            sample["span_id"]
                .as_str()
                .is_some_and(|span_id| span_id.starts_with(&format!("abi::{symbol}::decision::")))
        );
        assert!(
            sample["parent_span_id"].as_str().is_some_and(
                |parent_span_id| parent_span_id.starts_with(&format!("abi::{symbol}::entry::"))
            )
        );
        assert!(sample["decision_id"].as_u64().is_some_and(|id| id > 0));
        assert!(sample["risk_inputs"].is_object());
    }
    assert_eq!(symbols, BTreeSet::from(["free", "malloc"]));
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("symbol_logging_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("symbol_logging_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));
    assert_eq!(report["summary"]["missing_item_count"].as_u64(), Some(2));
    assert_eq!(report["summary"]["sample_count"].as_u64(), Some(2));

    let log_rows = read_jsonl(&out_dir.join("symbol_logging_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = log_rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect();
    for event in REQUIRED_EVENTS {
        assert!(events.contains(event), "telemetry log missing {event}");
    }
    assert!(
        log_rows
            .iter()
            .any(|row| row["symbol"].as_str() == Some("free")),
        "telemetry should include the free sample"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_join_field() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing-join-field")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["sample_runtime_decision_rows"][0]
        .as_object_mut()
        .expect("sample row should be object")
        .remove("parent_span_id");
    let bad_contract = out_dir.join("missing_parent_span.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing parent_span_id"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("parent_span_id"));
    Ok(())
}

#[test]
fn checker_rejects_missing_source_anchor() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing-source-anchor")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["source_anchors"]["runtime_policy"] =
        serde_json::json!(["definitely_missing_symbol_logging_anchor"]);
    let bad_contract = out_dir.join("missing_anchor.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing source anchor"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("definitely_missing_symbol_logging_anchor"));
    Ok(())
}
