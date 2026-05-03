//! Integration test: feature parity claim-evidence CI gate (bd-bp8fl.3.4)

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "claim_surface",
    "claim_id",
    "expected_decision",
    "actual_decision",
    "evidence_refs",
    "source_commit",
    "failure_signature",
];

const EXPECTED_CLAIM_IDS: &[&str] = &[
    "readme-current-source-of-truth",
    "feature-parity-current-reality",
    "feature-parity-macro-targets",
    "support-taxonomy-counts",
    "semantic-overlay-blocker",
    "replacement-level-current-l0",
    "compatibility-reality-report",
    "generated-claim-control-gate",
];

const EXPECTED_BLOCK_SIGNATURES: &[&str] = &[
    "claim_advancement_missing_evidence",
    "claim_advancement_stale_evidence",
    "claim_advancement_contradictory_evidence",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn gate_path() -> PathBuf {
    workspace_root().join("tests/conformance/feature_parity_claim_evidence_gate.v1.json")
}

fn script_path() -> PathBuf {
    workspace_root().join("scripts/check_feature_parity_claim_evidence.sh")
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
        .env("FRANKENLIBC_CLAIM_EVIDENCE_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_CLAIM_EVIDENCE_REPORT",
            out_dir.join("claim-evidence.report.json"),
        )
        .env(
            "FRANKENLIBC_CLAIM_EVIDENCE_LOG",
            out_dir.join("claim-evidence.log.jsonl"),
        );
    if let Some(config) = config {
        command.env("FRANKENLIBC_CLAIM_EVIDENCE_GATE", config);
    }
    command
        .output()
        .expect("failed to run feature parity claim-evidence gate")
}

#[test]
fn artifact_binds_claim_surfaces_to_machine_evidence() {
    let root = workspace_root();
    let gate = load_json(&gate_path());
    assert_eq!(gate["schema_version"].as_str(), Some("v1"));
    assert_eq!(gate["bead"].as_str(), Some("bd-bp8fl.3.4"));
    assert_eq!(
        gate["required_log_fields"].as_array().unwrap(),
        &REQUIRED_LOG_FIELDS
            .iter()
            .map(|field| Value::String((*field).to_owned()))
            .collect::<Vec<_>>()
    );

    let ci = gate["ci_integration"].as_object().unwrap();
    assert_eq!(ci["required"].as_bool(), Some(true));
    let ci_file = ci["ci_file"].as_str().unwrap();
    let gate_script = ci["gate_script"].as_str().unwrap();
    assert!(root.join(gate_script).exists(), "{gate_script} must exist");
    let ci_text = std::fs::read_to_string(root.join(ci_file)).unwrap();
    assert!(
        ci_text.contains(gate_script),
        "{ci_file} must invoke {gate_script}"
    );

    let blocked = gate["claim_policy"]["blocked_signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    for signature in [
        "claim_advancement_missing_evidence",
        "claim_advancement_stale_evidence",
        "claim_advancement_contradictory_evidence",
        "claim_surface_missing_binding",
        "ci_hook_missing",
    ] {
        assert!(
            blocked.contains(signature),
            "blocked signatures must include {signature}"
        );
    }

    let claim_surfaces = gate["claim_surfaces"].as_array().unwrap();
    assert_eq!(claim_surfaces.len(), 8);
    let claim_ids = claim_surfaces
        .iter()
        .map(|surface| surface["claim_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        claim_ids,
        EXPECTED_CLAIM_IDS.iter().copied().collect::<BTreeSet<_>>()
    );

    for surface in claim_surfaces {
        let claim_id = surface["claim_id"].as_str().unwrap();
        let path = surface["claim_surface"].as_str().unwrap();
        let surface_text =
            std::fs::read_to_string(root.join(path)).expect("claim surface should be readable");
        for required_fragment in surface["required_tokens"].as_array().unwrap() {
            let required_fragment = required_fragment.as_str().unwrap();
            assert!(
                surface_text.contains(required_fragment),
                "{claim_id} surface {path} must contain fragment {required_fragment:?}"
            );
        }
        for evidence in surface["evidence_refs"].as_array().unwrap() {
            let evidence = evidence.as_str().unwrap();
            assert!(
                root.join(evidence).exists(),
                "{claim_id} evidence ref {evidence} must exist"
            );
        }
    }

    let scenarios = gate["scenarios"].as_array().unwrap();
    assert_eq!(scenarios.len(), 6);
    let allowed = scenarios
        .iter()
        .filter(|scenario| scenario["expected_decision"].as_str() == Some("allow"))
        .count();
    let blocked = scenarios
        .iter()
        .filter(|scenario| scenario["expected_decision"].as_str() == Some("block"))
        .count();
    assert_eq!(allowed, 2);
    assert_eq!(blocked, 4);
    let signatures = scenarios
        .iter()
        .map(|scenario| scenario["expected_failure_signature"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    for signature in EXPECTED_BLOCK_SIGNATURES {
        assert!(
            signatures.contains(signature),
            "scenario set must exercise {signature}"
        );
    }

    let summary = &gate["summary"];
    assert_eq!(summary["claim_surface_count"].as_u64(), Some(8));
    assert_eq!(summary["scenario_count"].as_u64(), Some(6));
    assert_eq!(summary["blocked_scenario_count"].as_u64(), Some(4));
    assert_eq!(summary["allowed_scenario_count"].as_u64(), Some(2));
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
            "check_feature_parity_claim_evidence.sh must be executable"
        );
    }

    let out_dir = unique_temp_dir("claim-evidence-pass");
    let output = run_gate(None, &out_dir);
    assert!(
        output.status.success(),
        "gate should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("claim-evidence.report.json"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.3.4"));
    assert_eq!(report["summary"]["claim_surface_count"].as_u64(), Some(8));
    assert_eq!(report["summary"]["scenario_count"].as_u64(), Some(6));
    assert_eq!(
        report["summary"]["blocked_scenario_count"].as_u64(),
        Some(4)
    );
    assert_eq!(
        report["summary"]["allowed_scenario_count"].as_u64(),
        Some(2)
    );
    assert!(report["errors"].as_array().unwrap().is_empty());

    let log_text = std::fs::read_to_string(out_dir.join("claim-evidence.log.jsonl")).unwrap();
    let mut rows = Vec::new();
    for line in log_text.lines().filter(|line| !line.trim().is_empty()) {
        rows.push(serde_json::from_str::<Value>(line).expect("log row should parse"));
    }
    assert!(rows.len() >= 14, "expected surface and scenario log rows");
    let mut actual_decisions = BTreeSet::new();
    let mut failure_signatures = BTreeSet::new();
    for row in &rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
        actual_decisions.insert(row["actual_decision"].as_str().unwrap());
        failure_signatures.insert(row["failure_signature"].as_str().unwrap());
    }
    assert!(actual_decisions.contains("allow"));
    assert!(actual_decisions.contains("block"));
    for signature in EXPECTED_BLOCK_SIGNATURES {
        assert!(
            failure_signatures.contains(signature),
            "log must include {signature}"
        );
    }
}

#[test]
fn gate_fails_closed_when_claim_advances_without_required_evidence() {
    let mut gate = load_json(&gate_path());
    let scenarios = gate["scenarios"].as_array_mut().unwrap();
    let scenario = scenarios
        .iter_mut()
        .find(|scenario| {
            scenario["scenario_id"].as_str() == Some("evidence-backed-current-claim-allowed")
        })
        .expect("canonical allowed scenario must exist");
    scenario["evidence_refs"] = Value::Array(Vec::new());

    let out_dir = unique_temp_dir("claim-evidence-fail");
    std::fs::create_dir_all(&out_dir).unwrap();
    let mutated_gate = out_dir.join("mutated-feature-parity-claim-evidence.json");
    std::fs::write(&mutated_gate, serde_json::to_string_pretty(&gate).unwrap()).unwrap();

    let output = run_gate(Some(&mutated_gate), &out_dir);
    assert!(
        !output.status.success(),
        "gate should fail on missing evidence\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("claim-evidence.report.json"));
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = report["errors"].as_array().unwrap();
    assert!(
        errors.iter().any(|error| {
            error
                .as_str()
                .unwrap_or_default()
                .contains("claim_advancement_missing_evidence")
                || error
                    .as_str()
                    .unwrap_or_default()
                    .contains("decision mismatch")
        }),
        "missing evidence must be reported as a fail-closed claim mismatch"
    );
}
