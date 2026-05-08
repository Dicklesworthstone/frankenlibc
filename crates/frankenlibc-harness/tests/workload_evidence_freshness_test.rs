//! Integration test: workload evidence freshness gate (bd-fp4tm.2).
//!
//! Validates the bd-fp4tm.1 freshness contract, the fail-closed checker, and
//! negative evidence mutations for stale commits, future timestamps, missing
//! artifact references, and compatibility claims without replay evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "source_id",
    "workload_id",
    "source_artifact",
    "freshness_state",
    "source_commit",
    "generated_at_utc",
    "max_age_policy",
    "validation_command",
    "artifact_refs",
    "failure_signature",
    "next_safe_action",
    "status",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn contract_path() -> PathBuf {
    workspace_root().join("tests/conformance/workload_evidence_freshness_contract.v1.json")
}

fn script_path() -> PathBuf {
    workspace_root().join("scripts/check_workload_evidence_freshness.sh")
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-{prefix}-{stamp}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn load_json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).expect("json file should be readable");
    serde_json::from_str(&text).expect("json should parse")
}

fn write_contract_variant(name: &str, mutate: impl FnOnce(&mut Value)) -> (PathBuf, Value) {
    let mut contract = load_json(&contract_path());
    mutate(&mut contract);
    let dir = unique_temp_dir(name);
    let path = dir.join("workload_evidence_freshness_contract.v1.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&contract).expect("variant should serialize") + "\n",
    )
    .expect("variant should write");
    (path, contract)
}

fn run_gate(contract: &Path, prefix: &str) -> (PathBuf, PathBuf, Output) {
    let root = workspace_root();
    let out_dir = unique_temp_dir(prefix);
    let report = out_dir.join("workload_evidence_freshness.report.json");
    let log = out_dir.join("workload_evidence_freshness.log.jsonl");
    let output = Command::new("bash")
        .arg(script_path())
        .current_dir(&root)
        .env("FRANKENLIBC_WORKLOAD_EVIDENCE_CONTRACT", contract)
        .env("FRANKENLIBC_WORKLOAD_EVIDENCE_OUT_DIR", &out_dir)
        .env("FRANKENLIBC_WORKLOAD_EVIDENCE_REPORT", &report)
        .env("FRANKENLIBC_WORKLOAD_EVIDENCE_LOG", &log)
        .output()
        .expect("freshness gate should execute");
    (report, log, output)
}

fn assert_gate_fails_with(contract: &Path, prefix: &str, expected_failure: &str) -> Value {
    let (report_path, _log_path, output) = run_gate(contract, prefix);
    assert!(
        !output.status.success(),
        "gate should fail with {expected_failure}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&report_path);
    assert_eq!(report["status"].as_str(), Some("fail"));
    let signatures = report["failure_signatures"]
        .as_array()
        .expect("failure_signatures should be array");
    assert!(
        signatures.iter().any(|value| value
            .as_str()
            .is_some_and(|actual| actual == expected_failure)),
        "expected failure marker {expected_failure}; report={report:#?}"
    );
    report
}

#[test]
fn contract_declares_required_sources_policies_and_claim_refs() {
    let root = workspace_root();
    let contract = load_json(&contract_path());
    assert_eq!(contract["schema_version"].as_str(), Some("v1"));
    assert_eq!(contract["bead"].as_str(), Some("bd-fp4tm.1"));
    assert_eq!(contract["source_commit"].as_str(), Some("current"));

    let required_fields = contract["required_evidence_source_fields"]
        .as_array()
        .expect("required_evidence_source_fields should be array");
    for field in [
        "id",
        "owner_family",
        "claim_scope",
        "claim_refs",
        "source_artifact",
        "artifact_refs",
        "validation_command",
        "freshness_policy",
        "stale_failure_signature",
        "next_safe_action",
    ] {
        assert!(
            required_fields
                .iter()
                .any(|value| value.as_str() == Some(field)),
            "required field list should include {field}"
        );
    }

    let claim_refs = contract["claim_refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value["id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert!(claim_refs.contains("readme-interpose-many-workloads"));
    assert!(claim_refs.contains("readme-smoke-summary"));
    assert!(claim_refs.contains("feature-parity-strict-hardened-evidence"));

    let sources = contract["evidence_sources"].as_array().unwrap();
    assert_eq!(sources.len(), 12);
    let source_ids = sources
        .iter()
        .map(|source| source["id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    for expected in [
        "claim-field-contract",
        "ld-preload-smoke-summary",
        "user-workload-acceptance-matrix",
        "user-workload-replay-manifest",
        "real-program-smoke-suite",
        "readme-example-workload-gate",
        "replacement-level-current-claim",
        "release-gate-dag",
        "runtime-evidence-replay-gate",
        "workload-performance-budget",
        "standalone-link-run-smoke",
        "workload-failure-dashboard",
    ] {
        assert!(source_ids.contains(expected), "missing source {expected}");
    }

    for source in sources {
        let id = source["id"].as_str().unwrap();
        for claim_ref in source["claim_refs"].as_array().unwrap() {
            let claim_ref = claim_ref.as_str().unwrap();
            assert!(
                claim_refs.contains(claim_ref),
                "{id}: unknown claim ref {claim_ref}"
            );
        }
        let source_artifact = source["source_artifact"].as_str().unwrap();
        assert!(
            root.join(source_artifact).exists(),
            "{id}: source artifact {source_artifact} must exist"
        );
        let policy = &source["freshness_policy"];
        for field in [
            "policy_kind",
            "source_commit_policy",
            "generated_at_policy",
            "artifact_refs_policy",
            "refresh_triggers",
        ] {
            assert!(
                policy.get(field).is_some(),
                "{id}: freshness policy missing {field}"
            );
        }
        assert!(
            !source["stale_failure_signature"]
                .as_str()
                .unwrap()
                .is_empty(),
            "{id}: stale failure signature must be non-empty"
        );
        assert!(
            !source["next_safe_action"].as_str().unwrap().is_empty(),
            "{id}: next safe action must be non-empty"
        );
    }
}

#[test]
fn gate_passes_and_emits_report_and_jsonl_log() {
    let script = script_path();
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_workload_evidence_freshness.sh must be executable"
        );
    }

    let (report_path, log_path, output) = run_gate(&contract_path(), "workload-evidence-pass");
    assert!(
        output.status.success(),
        "freshness gate should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&report_path);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-fp4tm.2"));
    assert_eq!(report["source_contract_bead"].as_str(), Some("bd-fp4tm.1"));
    assert_eq!(
        report["summary"]["evidence_source_count"].as_u64(),
        Some(12)
    );
    assert_eq!(report["summary"]["failed_source_count"].as_u64(), Some(0));
    assert!(
        report["summary"]["accepted_static_baseline_count"]
            .as_u64()
            .unwrap()
            > 0,
        "positive path must explicitly record accepted static baselines"
    );
    assert!(report["errors"].as_array().unwrap().is_empty());

    let log_text = std::fs::read_to_string(&log_path).expect("log should exist");
    let rows = log_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("log row should parse"))
        .collect::<Vec<_>>();
    assert!(rows.len() >= 70, "expected one row per covered workload");
    for row in &rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
        assert_eq!(row["bead_id"].as_str(), Some("bd-fp4tm.2"));
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert_eq!(row["failure_signature"].as_str(), Some("none"));
    }
}

#[test]
fn gate_fails_closed_on_stale_source_commit() {
    let (path, _contract) = write_contract_variant("workload-evidence-stale-commit", |contract| {
        contract["source_commit"] =
            Value::String("0000000000000000000000000000000000000000".to_owned());
    });

    assert_gate_fails_with(
        &path,
        "workload-evidence-stale-commit-run",
        "stale_source_commit",
    );
}

#[test]
fn gate_fails_closed_on_future_generated_timestamp() {
    let (path, _contract) = write_contract_variant("workload-evidence-future-time", |contract| {
        contract["generated_at_utc"] = Value::String("2999-01-01T00:00:00Z".to_owned());
    });

    assert_gate_fails_with(
        &path,
        "workload-evidence-future-time-run",
        "future_generated_at",
    );
}

#[test]
fn gate_fails_closed_on_missing_artifact_ref() {
    let (path, _contract) = write_contract_variant("workload-evidence-missing-ref", |contract| {
        let sources = contract["evidence_sources"].as_array_mut().unwrap();
        sources[0]["artifact_refs"]
            .as_array_mut()
            .unwrap()
            .push(Value::String(
                "tests/conformance/definitely_missing_workload_evidence.v1.json".to_owned(),
            ));
    });

    assert_gate_fails_with(
        &path,
        "workload-evidence-missing-ref-run",
        "missing_artifact_ref",
    );
}

#[test]
fn gate_fails_closed_on_compatibility_claim_without_replay_evidence() {
    let (path, _contract) = write_contract_variant("workload-evidence-no-replay", |contract| {
        let sources = contract["evidence_sources"].as_array_mut().unwrap();
        let claim_source = sources
            .iter_mut()
            .find(|source| source["id"].as_str() == Some("claim-field-contract"))
            .expect("claim-field-contract source should exist");
        let refs = claim_source["artifact_refs"].as_array_mut().unwrap();
        refs.retain(|value| {
            let text = value.as_str().unwrap_or_default();
            !text.contains("user_workload_replay_manifest")
                && !text.contains("run_user_workload_replay_traces")
        });
    });

    assert_gate_fails_with(
        &path,
        "workload-evidence-no-replay-run",
        "compatibility_claim_without_replay_evidence",
    );
}
