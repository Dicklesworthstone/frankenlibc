//! Integration test: claim gate positive/negative coverage matrix (bd-bp8fl.7.6)

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "claim_gate_id",
    "scenario_id",
    "claim_surface",
    "expected_decision",
    "actual_decision",
    "evidence_refs",
    "source_commit",
    "target_dir",
    "freshness_state",
    "contradiction_state",
    "failure_signature",
];

const REQUIRED_NEGATIVE_KINDS: &[&str] = &[
    "missing_artifact",
    "stale_artifact",
    "contradictory_artifact",
    "wrong_source_commit",
    "insufficient_replacement_level",
    "skipped_runtime_mode",
    "unsupported_workload",
    "prose_only_advancement",
];

const REQUIRED_EVIDENCE_CATEGORIES: &[&str] = &[
    "source_artifact",
    "generated_artifact",
    "user_visible_claim_type",
    "replacement_level",
    "runtime_mode",
    "oracle_kind",
    "owner_bead",
];

const EXPECTED_CLAIM_GATES: &[&str] = &[
    "feature-parity-claim-evidence",
    "fpg-claim-control",
    "release-readme-example-workload",
    "replacement-levels",
    "user-workload-acceptance",
    "claim-reconciliation",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn matrix_path() -> PathBuf {
    workspace_root().join("tests/conformance/claim_gate_positive_negative_matrix.v1.json")
}

fn script_path() -> PathBuf {
    workspace_root().join("scripts/check_claim_gate_positive_negative_matrix.sh")
}

fn load_json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).expect("json artifact should be readable");
    serde_json::from_str(&text).expect("json artifact should parse")
}

fn unique_temp_dir(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("frankenlibc-{name}-{stamp}-{}", std::process::id()))
}

fn run_gate(config: Option<&Path>, out_dir: &Path) -> std::process::Output {
    let root = workspace_root();
    let mut command = Command::new("bash");
    command
        .arg(script_path())
        .current_dir(&root)
        .env("FRANKENLIBC_CLAIM_GATE_MATRIX_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_CLAIM_GATE_MATRIX_REPORT",
            out_dir.join("claim-gate-matrix.report.json"),
        )
        .env(
            "FRANKENLIBC_CLAIM_GATE_MATRIX_LOG",
            out_dir.join("claim-gate-matrix.log.jsonl"),
        );
    if let Some(config) = config {
        command.env("FRANKENLIBC_CLAIM_GATE_MATRIX", config);
    }
    command
        .output()
        .expect("failed to run claim gate positive/negative matrix")
}

#[test]
fn matrix_lists_every_claim_gate_with_positive_and_negative_coverage() {
    let root = workspace_root();
    let matrix = load_json(&matrix_path());
    assert_eq!(matrix["schema_version"].as_str(), Some("v1"));
    assert_eq!(matrix["bead"].as_str(), Some("bd-bp8fl.7.6"));
    assert_eq!(
        matrix["required_log_fields"].as_array().unwrap(),
        &REQUIRED_LOG_FIELDS
            .iter()
            .map(|field| Value::String((*field).to_owned()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        matrix["required_negative_kinds"].as_array().unwrap(),
        &REQUIRED_NEGATIVE_KINDS
            .iter()
            .map(|kind| Value::String((*kind).to_owned()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        matrix["required_evidence_categories"].as_array().unwrap(),
        &REQUIRED_EVIDENCE_CATEGORIES
            .iter()
            .map(|category| Value::String((*category).to_owned()))
            .collect::<Vec<_>>()
    );

    let ci = matrix["ci_integration"].as_object().unwrap();
    assert_eq!(ci["required"].as_bool(), Some(true));
    let ci_file = ci["ci_file"].as_str().unwrap();
    let gate_script = ci["gate_script"].as_str().unwrap();
    assert!(root.join(gate_script).exists(), "{gate_script} must exist");
    let ci_text = std::fs::read_to_string(root.join(ci_file)).unwrap();
    assert!(
        ci_text.contains(gate_script),
        "{ci_file} must invoke {gate_script}"
    );

    let gates = matrix["claim_gates"].as_array().unwrap();
    assert_eq!(gates.len(), EXPECTED_CLAIM_GATES.len());
    let gate_ids = gates
        .iter()
        .map(|gate| gate["claim_gate_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        gate_ids,
        EXPECTED_CLAIM_GATES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    );

    for gate in gates {
        let gate_id = gate["claim_gate_id"].as_str().unwrap();
        for path_key in [
            "source_artifact",
            "generated_artifact",
            "gate_script",
            "harness_test",
        ] {
            let path = gate[path_key].as_str().unwrap();
            assert!(
                root.join(path).exists(),
                "{gate_id}: {path_key} {path} must exist"
            );
        }

        let categories = gate["evidence_categories"].as_object().unwrap();
        for category in REQUIRED_EVIDENCE_CATEGORIES {
            assert!(
                categories
                    .get(*category)
                    .and_then(Value::as_array)
                    .map(|values| !values.is_empty())
                    .unwrap_or(false),
                "{gate_id}: missing evidence category {category}"
            );
        }

        assert!(
            !gate["positive_tests"].as_array().unwrap().is_empty(),
            "{gate_id}: must include positive tests"
        );
        let negative_tests = gate["negative_tests"].as_object().unwrap();
        let negative_kinds = negative_tests
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            negative_kinds,
            REQUIRED_NEGATIVE_KINDS
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            "{gate_id}: must cover every negative kind"
        );
        for (kind, test) in negative_tests {
            assert_eq!(
                test["expected_decision"].as_str(),
                Some("block"),
                "{gate_id}:{kind}: negative test must block"
            );
            assert!(
                test["failure_signature"]
                    .as_str()
                    .unwrap()
                    .starts_with("claim_gate_"),
                "{gate_id}:{kind}: failure signature should be claim-gate scoped"
            );
        }
    }

    let summary = &matrix["summary"];
    assert_eq!(summary["claim_gate_count"].as_u64(), Some(6));
    assert_eq!(summary["positive_test_count"].as_u64(), Some(11));
    assert_eq!(summary["negative_test_count"].as_u64(), Some(48));
}

#[test]
fn gate_script_passes_and_emits_report_and_jsonl_log() {
    let script = script_path();
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_claim_gate_positive_negative_matrix.sh must be executable"
        );
    }

    let out_dir = unique_temp_dir("claim-gate-matrix-pass");
    let output = run_gate(None, &out_dir);
    assert!(
        output.status.success(),
        "gate should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("claim-gate-matrix.report.json"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.7.6"));
    assert_eq!(report["summary"]["claim_gate_count"].as_u64(), Some(6));
    assert_eq!(report["summary"]["positive_test_count"].as_u64(), Some(11));
    assert_eq!(report["summary"]["negative_test_count"].as_u64(), Some(48));
    assert!(report["errors"].as_array().unwrap().is_empty());

    let log_text = std::fs::read_to_string(out_dir.join("claim-gate-matrix.log.jsonl")).unwrap();
    let mut rows = Vec::new();
    for line in log_text.lines().filter(|line| !line.trim().is_empty()) {
        rows.push(serde_json::from_str::<Value>(line).expect("log row should parse"));
    }
    assert_eq!(
        rows.len(),
        59,
        "expected one row per positive/negative test"
    );
    let mut decisions = BTreeSet::new();
    let mut signatures = BTreeSet::new();
    for row in &rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
        decisions.insert(row["actual_decision"].as_str().unwrap());
        signatures.insert(row["failure_signature"].as_str().unwrap());
        assert_eq!(row["bead_id"].as_str(), Some("bd-bp8fl.7.6"));
    }
    assert!(decisions.contains("allow"));
    assert!(decisions.contains("block"));
    for suffix in [
        "missing_artifact",
        "stale_artifact",
        "contradictory_artifact",
        "wrong_source_commit",
        "insufficient_replacement_level",
        "skipped_runtime_mode",
        "unsupported_workload",
        "prose_only_advancement",
    ] {
        let expected = format!("claim_gate_{suffix}");
        assert!(
            signatures.contains(expected.as_str()),
            "log must include {expected}"
        );
    }
}

#[test]
fn gate_fails_closed_when_a_claim_gate_loses_negative_coverage() {
    let mut matrix = load_json(&matrix_path());
    let gates = matrix["claim_gates"].as_array_mut().unwrap();
    let gate = gates
        .iter_mut()
        .find(|gate| gate["claim_gate_id"].as_str() == Some("release-readme-example-workload"))
        .expect("release README gate must exist");
    gate["negative_tests"]
        .as_object_mut()
        .unwrap()
        .remove("unsupported_workload");

    let out_dir = unique_temp_dir("claim-gate-matrix-missing-negative");
    std::fs::create_dir_all(&out_dir).unwrap();
    let mutated = out_dir.join("mutated-claim-gate-matrix.json");
    std::fs::write(&mutated, serde_json::to_string_pretty(&matrix).unwrap()).unwrap();

    let output = run_gate(Some(&mutated), &out_dir);
    assert!(
        !output.status.success(),
        "gate should fail when negative coverage is removed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&out_dir.join("claim-gate-matrix.report.json"));
    let errors = report["errors"].as_array().unwrap();
    assert!(
        errors.iter().any(|error| {
            error
                .as_str()
                .unwrap_or_default()
                .contains("claim_gate_missing_negative_coverage")
        }),
        "missing negative coverage must be reported"
    );
}

#[test]
fn gate_fails_closed_when_positive_or_negative_evidence_ref_is_missing() {
    let mut matrix = load_json(&matrix_path());
    let gates = matrix["claim_gates"].as_array_mut().unwrap();
    let gate = gates
        .iter_mut()
        .find(|gate| gate["claim_gate_id"].as_str() == Some("feature-parity-claim-evidence"))
        .expect("feature parity gate must exist");
    gate["negative_tests"]["missing_artifact"]["evidence_refs"] =
        Value::Array(vec![Value::String(
            "tests/conformance/does_not_exist_claim_gate_ref.json".to_owned(),
        )]);

    let out_dir = unique_temp_dir("claim-gate-matrix-missing-ref");
    std::fs::create_dir_all(&out_dir).unwrap();
    let mutated = out_dir.join("mutated-claim-gate-matrix.json");
    std::fs::write(&mutated, serde_json::to_string_pretty(&matrix).unwrap()).unwrap();

    let output = run_gate(Some(&mutated), &out_dir);
    assert!(
        !output.status.success(),
        "gate should fail when an evidence ref is missing"
    );
    let report = load_json(&out_dir.join("claim-gate-matrix.report.json"));
    let errors = report["errors"].as_array().unwrap();
    assert!(
        errors.iter().any(|error| {
            error
                .as_str()
                .unwrap_or_default()
                .contains("claim_gate_missing_evidence_ref")
        }),
        "missing evidence ref must be reported"
    );
}
