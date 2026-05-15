use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "evidence_symbol_records_source_gate",
    "evidence_symbol_records_layout_gate",
    "evidence_symbol_records_redundancy_gate",
    "evidence_symbol_records_sample_gate",
    "evidence_symbol_records_telemetry_gate",
    "evidence_symbol_records_completion_contract_validated",
];

fn repo_root() -> TestResult<PathBuf> {
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
    root.join("tests/conformance/evidence_symbol_records_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_evidence_symbol_records_completion_contract.sh")
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
        "evidence_symbol_records_completion_{label}_{}_{}",
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
        .env(
            "FRANKENLIBC_EVIDENCE_SYMBOL_RECORDS_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_EVIDENCE_SYMBOL_RECORDS_COMPLETION_REPORT",
            out_dir.join("evidence_symbol_records_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_EVIDENCE_SYMBOL_RECORDS_COMPLETION_LOG",
            out_dir.join("evidence_symbol_records_completion_contract.log.jsonl"),
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
fn manifest_binds_unit_e2e_and_telemetry_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("evidence_symbol_records_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-oai.3"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-oai.3.1")
    );

    let missing_items: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|binding| binding["id"].as_str())
        .collect();
    assert_eq!(
        missing_items,
        BTreeSet::from([
            "telemetry.primary",
            "tests.e2e.primary",
            "tests.unit.primary"
        ])
    );

    let layout = &manifest["evidence_symbol_record_contract"];
    assert_eq!(layout["record_magic"].as_str(), Some("EVR1"));
    assert_eq!(layout["payload_magic"].as_str(), Some("EVP1"));
    assert_eq!(layout["record_size_bytes"].as_u64(), Some(256));
    assert_eq!(layout["payload_size_t_bytes"].as_u64(), Some(128));
    assert_eq!(layout["max_k_source"].as_u64(), Some(256));
    assert_eq!(
        layout["raptorq_redundancy_model"]["decode_algorithm"].as_str(),
        Some("peeling_decode")
    );
    Ok(())
}

#[test]
fn source_anchors_cover_record_decoder_and_e2e_surfaces() -> TestResult {
    let root = repo_root()?;
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
fn sample_decode_proofs_model_redundancy_and_corruption_paths() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;
    let samples = manifest["sample_decode_proofs"]
        .as_array()
        .ok_or("sample_decode_proofs must be array")?;
    assert!(samples.len() >= 3);

    let mut statuses = BTreeSet::new();
    let mut recovered_loss = false;
    let mut detected_corruption = false;
    for sample in samples {
        let status = sample["status"].as_str().ok_or("status must be string")?;
        statuses.insert(status);
        let k_source = sample["k_source"].as_u64().ok_or("k_source missing")?;
        let systematic = sample["systematic_records"]
            .as_u64()
            .ok_or("systematic_records missing")?;
        let repairs = sample["repair_records"]
            .as_u64()
            .ok_or("repair_records missing")?;
        let records_total = sample["records_total"]
            .as_u64()
            .ok_or("records_total missing")?;
        assert_eq!(records_total, systematic + repairs);
        assert!(repairs > 0);
        assert!(sample["decoded_systematic"].as_u64().unwrap_or(0) <= k_source);

        recovered_loss |= systematic < k_source
            && sample["missing_systematic"].as_u64() == Some(0)
            && sample["chain_hash_mismatches"].as_u64().unwrap_or(0) > 0;
        detected_corruption |= sample["payload_hash_mismatches"].as_u64().unwrap_or(0) > 0
            && sample["missing_systematic"].as_u64().unwrap_or(0) > 0;
    }
    assert!(statuses.contains("Success"));
    assert!(statuses.contains("Partial"));
    assert!(
        recovered_loss,
        "samples must include loss recovered by repairs"
    );
    assert!(
        detected_corruption,
        "samples must include detected corruption"
    );
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        read_json(&out_dir.join("evidence_symbol_records_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("evidence_symbol_records_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));
    assert_eq!(report["summary"]["missing_item_count"].as_u64(), Some(3));
    assert_eq!(report["summary"]["sample_count"].as_u64(), Some(3));
    assert_eq!(report["summary"]["record_size_bytes"].as_u64(), Some(256));

    let log_rows =
        read_jsonl(&out_dir.join("evidence_symbol_records_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = log_rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect();
    for event in REQUIRED_EVENTS {
        assert!(events.contains(event), "telemetry log missing {event}");
    }
    assert!(
        log_rows.iter().any(|row| row["event"].as_str()
            == Some("evidence_symbol_records_sample_gate")
            && row["label"].as_str() == Some("payload_corruption_detected")),
        "telemetry should include the corruption sample"
    );
    Ok(())
}

#[test]
fn checker_rejects_record_size_drift() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "bad-record-size")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["evidence_symbol_record_contract"]["record_size_bytes"] = serde_json::json!(128);
    let bad_contract = out_dir.join("bad_record_size.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted bad record size"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("record_size_bytes"));
    Ok(())
}

#[test]
fn checker_rejects_missing_source_anchor() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-source-anchor")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["source_anchors"]["evidence_impl"] =
        serde_json::json!(["definitely_missing_evidence_symbol_anchor"]);
    let bad_contract = out_dir.join("missing_anchor.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing source anchor"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("definitely_missing_evidence_symbol_anchor"));
    Ok(())
}
