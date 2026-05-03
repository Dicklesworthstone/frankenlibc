//! Integration test: user-visible semantic and mode-decision diagnostics (bd-bp8fl.10.5)
//!
//! Validates the diagnostic catalog, redaction/claim-blocking policy, stable
//! user-visible output examples, and deterministic gate behavior.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_TYPES: &[&str] = &[
    "native_behavior",
    "host_delegation",
    "raw_syscall",
    "deterministic_fallback",
    "hardened_repair",
    "denial",
    "unsupported_symbol",
    "noop_fallback",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "scenario_id",
    "symbol",
    "api_family",
    "runtime_mode",
    "replacement_level",
    "decision_path",
    "healing_action",
    "diagnostic_code",
    "user_message_id",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const CLAIM_BLOCKED_TYPES: &[&str] = &[
    "host_delegation",
    "deterministic_fallback",
    "denial",
    "unsupported_symbol",
    "noop_fallback",
];

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn load_catalog() -> serde_json::Value {
    load_json(&workspace_root().join("tests/conformance/user_visible_diagnostics.v1.json"))
}

fn run_gate(
    mode: &str,
    prefix: &str,
    artifact_override: Option<&Path>,
) -> (PathBuf, PathBuf, PathBuf, PathBuf, std::process::Output) {
    let root = workspace_root();
    let temp = unique_temp_dir(prefix);
    let out_dir = temp.join("outputs");
    let report = temp.join("user_visible_diagnostics.report.json");
    let log = temp.join("user_visible_diagnostics.log.jsonl");
    let mut command = Command::new(root.join("scripts/check_user_visible_diagnostics.sh"));
    command
        .arg(mode)
        .current_dir(&root)
        .env("FLC_USER_DIAGNOSTICS_OUT_DIR", &out_dir)
        .env("FLC_USER_DIAGNOSTICS_REPORT", &report)
        .env("FLC_USER_DIAGNOSTICS_LOG", &log);
    if let Some(path) = artifact_override {
        command.env("FLC_USER_DIAGNOSTICS_ARTIFACT", path);
    }
    let output = command
        .output()
        .expect("user-visible diagnostics gate should execute");
    (temp, out_dir, report, log, output)
}

#[test]
fn catalog_declares_required_types_log_fields_and_policies() {
    let catalog = load_catalog();
    assert_eq!(catalog["schema_version"].as_str(), Some("v1"));
    assert_eq!(catalog["bead"].as_str(), Some("bd-bp8fl.10.5"));
    assert_eq!(
        catalog["diagnostic_policy"]["support_taxonomy_alone_is_not_semantic_parity"].as_bool(),
        Some(true)
    );
    assert_eq!(
        catalog["diagnostic_policy"]["unsupported_or_blocked_claims_support"].as_bool(),
        Some(false)
    );

    let types: HashSet<_> = catalog["diagnostic_types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(types, REQUIRED_TYPES.iter().copied().collect());

    let log_fields: Vec<_> = catalog["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);
}

#[test]
fn records_cover_diagnostic_classes_and_do_not_leak_internal_details() {
    let root = workspace_root();
    let catalog = load_catalog();
    let type_by_id: HashMap<_, _> = catalog["diagnostic_types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| (row["id"].as_str().unwrap(), row))
        .collect();
    let blocked: HashSet<_> = CLAIM_BLOCKED_TYPES.iter().copied().collect();
    let mut seen_types = HashSet::new();
    let mut seen_modes = HashSet::new();
    let mut seen_levels = HashSet::new();
    let mut support_never = 0_u64;

    for record in catalog["records"].as_array().unwrap() {
        let scenario_id = record["scenario_id"].as_str().unwrap();
        let diagnostic_type = record["diagnostic_type"].as_str().unwrap();
        seen_types.insert(diagnostic_type);
        seen_modes.insert(record["runtime_mode"].as_str().unwrap());
        seen_levels.insert(record["replacement_level"].as_str().unwrap());

        let type_row = type_by_id.get(diagnostic_type).unwrap();
        assert_eq!(
            record["diagnostic_code"].as_str(),
            type_row["diagnostic_code"].as_str(),
            "{scenario_id}: diagnostic code"
        );
        assert_eq!(
            record["user_message_id"].as_str(),
            type_row["user_message_id"].as_str(),
            "{scenario_id}: user message id"
        );

        let user_message = record["user_message"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase();
        for forbidden in [
            "0x",
            "raw pointer",
            "heap address",
            "secret",
            "token",
            "password",
        ] {
            assert!(
                !user_message.contains(forbidden),
                "{scenario_id}: leaked forbidden fragment {forbidden}"
            );
        }

        let expected = format!(
            "{} {} {} {}: {}",
            record["diagnostic_code"].as_str().unwrap(),
            record["symbol"].as_str().unwrap(),
            record["runtime_mode"].as_str().unwrap(),
            record["replacement_level"].as_str().unwrap(),
            record["user_message"].as_str().unwrap()
        );
        assert_eq!(
            record["expected_output"].as_str(),
            Some(expected.as_str()),
            "{scenario_id}: stable output template"
        );

        for artifact_ref in record["artifact_refs"].as_array().unwrap() {
            let rel = artifact_ref.as_str().unwrap().split('#').next().unwrap();
            assert!(root.join(rel).exists(), "{scenario_id}: missing {rel}");
        }

        if blocked.contains(diagnostic_type) {
            assert_eq!(
                record["support_claim"].as_str(),
                Some("never"),
                "{scenario_id}: blocked diagnostics must never claim support"
            );
            support_never += 1;
        }
    }

    assert_eq!(seen_types, REQUIRED_TYPES.iter().copied().collect());
    assert!(seen_modes.contains("strict"));
    assert!(seen_modes.contains("hardened"));
    assert!(seen_levels.contains("L0"));
    assert!(seen_levels.contains("L1"));
    assert_eq!(
        catalog["summary"]["support_claim_never_count"].as_u64(),
        Some(support_never)
    );
}

#[test]
fn semantic_overlay_and_mode_pair_rules_are_explicit() {
    let root = workspace_root();
    let catalog = load_catalog();
    let semantic_join =
        load_json(&root.join("tests/conformance/semantic_contract_symbol_join.v1.json"));
    let semantic_by_id: HashMap<_, _> = semantic_join["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| (row["inventory_id"].as_str().unwrap(), row))
        .collect();
    let records_by_id: HashMap<_, _> = catalog["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| (row["scenario_id"].as_str().unwrap(), row))
        .collect();

    for record in catalog["records"].as_array().unwrap() {
        if let Some(semantic_id) = record["semantic_join_inventory_id"].as_str() {
            assert!(
                semantic_by_id.contains_key(semantic_id),
                "missing semantic row {semantic_id}"
            );
            let semantic_row = semantic_by_id[semantic_id];
            assert_eq!(
                record["semantic_class"].as_str(),
                semantic_row["semantic_class"].as_str()
            );
            let symbols: HashSet<_> = semantic_row["symbol_refs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect();
            assert!(
                symbols.contains(record["symbol"].as_str().unwrap()),
                "{semantic_id}: semantic row should include record symbol"
            );
        }
    }

    for pair in catalog["mode_pairs"].as_array().unwrap() {
        let strict = records_by_id[pair["strict_record"].as_str().unwrap()];
        let hardened = records_by_id[pair["hardened_record"].as_str().unwrap()];
        assert_eq!(strict["symbol"], hardened["symbol"]);
        assert_eq!(strict["runtime_mode"].as_str(), Some("strict"));
        assert_eq!(hardened["runtime_mode"].as_str(), Some("hardened"));
        assert_ne!(strict["decision_path"], hardened["decision_path"]);
        assert_eq!(strict["healing_action"].as_str(), Some("None"));
        assert_ne!(hardened["healing_action"].as_str(), Some("None"));
    }
}

#[test]
fn gate_emits_report_log_and_stable_user_outputs() {
    let (_temp, out_dir, report_path, log_path, output) =
        run_gate("--emit-fixtures", "user-visible-diag", None);
    assert!(
        output.status.success(),
        "diagnostic gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    let catalog = load_catalog();
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.10.5"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    for check in [
        "artifact_shape",
        "input_artifacts_exist",
        "required_record_fields",
        "required_log_fields",
        "diagnostic_type_coverage",
        "record_ids_unique",
        "record_contracts",
        "record_type_coverage",
        "strict_hardened_difference",
        "negative_claim_tests",
        "summary_matches_records",
        "structured_log_rows",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "checks.{check}"
        );
    }

    let records = catalog["records"].as_array().unwrap();
    assert_eq!(
        report["summary"]["emitted_output_files"].as_u64(),
        Some(records.len() as u64)
    );
    for record in records {
        let scenario_id = record["scenario_id"].as_str().unwrap();
        let output_path = out_dir.join(format!("{scenario_id}.txt"));
        assert!(output_path.exists(), "missing {}", output_path.display());
        let output_text = std::fs::read_to_string(&output_path).unwrap();
        assert_eq!(
            output_text.trim_end(),
            record["expected_output"].as_str().unwrap()
        );
    }

    let log_rows: Vec<_> = std::fs::read_to_string(&log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect();
    assert_eq!(log_rows.len(), records.len());
    for row in log_rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(!row[*field].is_null(), "log row missing {field}");
        }
    }
}

#[test]
fn gate_rejects_stale_source_and_blocked_claim_promotion() {
    let catalog = load_catalog();

    let stale_temp = unique_temp_dir("user-visible-diag-stale");
    let stale_artifact = stale_temp.join("user_visible_diagnostics.stale.json");
    let mut stale_catalog = catalog.clone();
    stale_catalog["records"][0]["source_commit"] = serde_json::Value::String("old-head".into());
    std::fs::write(
        &stale_artifact,
        serde_json::to_string_pretty(&stale_catalog).unwrap(),
    )
    .unwrap();
    let (_temp, _out_dir, _report, _log, output) = run_gate(
        "--validate-only",
        "user-visible-diag-stale-run",
        Some(&stale_artifact),
    );
    assert!(
        !output.status.success(),
        "stale source_commit should fail validation"
    );

    let claim_temp = unique_temp_dir("user-visible-diag-claim");
    let claim_artifact = claim_temp.join("user_visible_diagnostics.claim.json");
    let mut claim_catalog = catalog;
    for record in claim_catalog["records"].as_array_mut().unwrap() {
        if record["scenario_id"].as_str() == Some("diag_denial_iconv_hardened") {
            record["support_claim"] = serde_json::Value::String("on_current_evidence".into());
        }
    }
    std::fs::write(
        &claim_artifact,
        serde_json::to_string_pretty(&claim_catalog).unwrap(),
    )
    .unwrap();
    let (_temp, _out_dir, _report, _log, output) = run_gate(
        "--validate-only",
        "user-visible-diag-claim-run",
        Some(&claim_artifact),
    );
    assert!(
        !output.status.success(),
        "claim-blocked denial diagnostic should not promote support"
    );
}
