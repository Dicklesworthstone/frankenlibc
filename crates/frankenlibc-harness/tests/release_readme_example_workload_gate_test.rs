//! Integration test: README/release example workload evidence gate (bd-bp8fl.10.4)

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "claim_id",
    "doc_surface",
    "workload_id",
    "replacement_level",
    "runtime_mode",
    "expected_decision",
    "actual_decision",
    "evidence_refs",
    "source_commit",
    "failure_signature",
];

const EXPECTED_CLAIM_IDS: &[&str] = &[
    "readme-quickstart-ld-preload-echo",
    "readme-hardened-ld-preload-echo",
    "readme-coreutils-smoke-battery",
    "readme-dynamic-runtime-smoke-battery",
    "readme-standalone-replacement-known-limitation",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn gate_path() -> PathBuf {
    workspace_root().join("tests/conformance/release_readme_example_workload_gate.v1.json")
}

fn script_path() -> PathBuf {
    workspace_root().join("scripts/check_release_readme_example_workload_gate.sh")
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
        .env("FRANKENLIBC_RELEASE_README_EXAMPLE_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_RELEASE_README_EXAMPLE_REPORT",
            out_dir.join("release-readme-example.report.json"),
        )
        .env(
            "FRANKENLIBC_RELEASE_README_EXAMPLE_LOG",
            out_dir.join("release-readme-example.log.jsonl"),
        );
    if let Some(config) = config {
        command.env("FRANKENLIBC_RELEASE_README_EXAMPLE_GATE", config);
    }
    command
        .output()
        .expect("failed to run release README example workload gate")
}

#[test]
fn artifact_maps_readme_examples_to_workload_evidence() {
    let root = workspace_root();
    let gate = load_json(&gate_path());
    assert_eq!(gate["schema_version"].as_str(), Some("v1"));
    assert_eq!(gate["bead"].as_str(), Some("bd-bp8fl.10.4"));
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

    let policy = gate["claim_policy"].as_object().unwrap();
    assert_eq!(
        policy["default_supported_example_decision"].as_str(),
        Some("block_until_workload_evidence_current")
    );
    let blocked = policy["blocked_signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    for signature in [
        "release_example_missing_workload_row",
        "release_example_missing_doc_token",
        "release_example_stale_smoke_evidence",
        "release_example_unsupported_replacement_level",
        "release_example_missing_support_matrix_row",
        "release_example_missing_semantic_overlay_row",
        "release_example_missing_compatibility_report",
    ] {
        assert!(
            blocked.contains(signature),
            "blocked signatures must include {signature}"
        );
    }

    let mappings = gate["claim_mappings"].as_array().unwrap();
    assert_eq!(mappings.len(), 5);
    let claim_ids = mappings
        .iter()
        .map(|mapping| mapping["claim_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        claim_ids,
        EXPECTED_CLAIM_IDS.iter().copied().collect::<BTreeSet<_>>()
    );

    for mapping in mappings {
        let claim_id = mapping["claim_id"].as_str().unwrap();
        let path = mapping["doc_surface"].as_str().unwrap();
        let surface_text =
            std::fs::read_to_string(root.join(path)).expect("claim surface should be readable");
        for required_fragment in mapping["required_tokens"].as_array().unwrap() {
            let required_fragment = required_fragment.as_str().unwrap();
            assert!(
                surface_text.contains(required_fragment),
                "{claim_id} surface {path} must contain token {required_fragment:?}"
            );
        }

        assert!(
            mapping["workload_id"].as_str().unwrap().starts_with("uwm-"),
            "{claim_id} must map to a user-workload row"
        );
        assert!(
            !mapping["support_matrix_symbols"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{claim_id} must name support_matrix symbol rows"
        );
        assert!(
            !mapping["semantic_overlay_ids"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{claim_id} must name semantic overlay rows"
        );
        for evidence in mapping["evidence_refs"].as_array().unwrap() {
            let evidence = evidence.as_str().unwrap();
            assert!(
                root.join(evidence).exists(),
                "{claim_id} evidence ref {evidence} must exist"
            );
        }
    }

    let summary = &gate["summary"];
    assert_eq!(summary["claim_mapping_count"].as_u64(), Some(5));
    assert_eq!(summary["allowed_supported_count"].as_u64(), Some(4));
    assert_eq!(summary["allowed_known_limitation_count"].as_u64(), Some(1));
    assert_eq!(summary["blocked_scenario_count"].as_u64(), Some(4));
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
            "check_release_readme_example_workload_gate.sh must be executable"
        );
    }

    let out_dir = unique_temp_dir("release-readme-example-pass");
    let output = run_gate(None, &out_dir);
    assert!(
        output.status.success(),
        "gate should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("release-readme-example.report.json"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.10.4"));
    assert_eq!(report["summary"]["claim_mapping_count"].as_u64(), Some(5));
    assert_eq!(
        report["summary"]["allowed_supported_count"].as_u64(),
        Some(4)
    );
    assert_eq!(
        report["summary"]["allowed_known_limitation_count"].as_u64(),
        Some(1)
    );
    assert!(report["errors"].as_array().unwrap().is_empty());

    let log_text = std::fs::read_to_string(out_dir.join("release-readme-example.log.jsonl"))
        .expect("log should exist");
    let mut rows = Vec::new();
    for line in log_text.lines().filter(|line| !line.trim().is_empty()) {
        rows.push(serde_json::from_str::<Value>(line).expect("log row should parse"));
    }
    assert!(rows.len() >= 8, "expected one row per mapping/runtime mode");
    let mut decisions = BTreeSet::new();
    for row in &rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
        decisions.insert(row["actual_decision"].as_str().unwrap());
        assert_eq!(row["bead_id"].as_str(), Some("bd-bp8fl.10.4"));
    }
    assert!(decisions.contains("allow"));
    assert!(decisions.contains("allow_known_limitation"));
}

#[test]
fn gate_fails_closed_when_workload_evidence_is_missing() {
    let mut gate = load_json(&gate_path());
    let mappings = gate["claim_mappings"].as_array_mut().unwrap();
    let mapping = mappings
        .iter_mut()
        .find(|mapping| mapping["claim_id"].as_str() == Some("readme-quickstart-ld-preload-echo"))
        .expect("quickstart mapping must exist");
    mapping["workload_id"] = Value::String("uwm-missing-row".to_owned());

    let out_dir = unique_temp_dir("release-readme-example-missing-workload");
    std::fs::create_dir_all(&out_dir).unwrap();
    let mutated_gate = out_dir.join("mutated-release-readme-example.json");
    std::fs::write(&mutated_gate, serde_json::to_string_pretty(&gate).unwrap()).unwrap();

    let output = run_gate(Some(&mutated_gate), &out_dir);
    assert!(
        !output.status.success(),
        "gate should fail on missing workload evidence\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&out_dir.join("release-readme-example.report.json"));
    let errors = report["errors"].as_array().unwrap();
    assert!(
        errors.iter().any(|error| {
            error
                .as_str()
                .unwrap_or_default()
                .contains("release_example_missing_workload_row")
                || error
                    .as_str()
                    .unwrap_or_default()
                    .contains("decision mismatch")
        }),
        "missing workload row must be reported"
    );
}

#[test]
fn gate_fails_closed_for_stale_or_overlevel_supported_examples() {
    let mut stale_gate = load_json(&gate_path());
    let mappings = stale_gate["claim_mappings"].as_array_mut().unwrap();
    let mapping = mappings
        .iter_mut()
        .find(|mapping| mapping["claim_id"].as_str() == Some("readme-hardened-ld-preload-echo"))
        .expect("hardened mapping must exist");
    mapping["freshness_state"] = Value::String("stale".to_owned());

    let stale_out = unique_temp_dir("release-readme-example-stale");
    std::fs::create_dir_all(&stale_out).unwrap();
    let stale_path = stale_out.join("mutated-stale-release-readme-example.json");
    std::fs::write(
        &stale_path,
        serde_json::to_string_pretty(&stale_gate).unwrap(),
    )
    .unwrap();
    let stale_output = run_gate(Some(&stale_path), &stale_out);
    assert!(
        !stale_output.status.success(),
        "gate should fail on stale smoke evidence"
    );
    let stale_report = load_json(&stale_out.join("release-readme-example.report.json"));
    assert!(
        stale_report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| {
                error
                    .as_str()
                    .unwrap_or_default()
                    .contains("release_example_stale_smoke_evidence")
                    || error
                        .as_str()
                        .unwrap_or_default()
                        .contains("decision mismatch")
            }),
        "stale evidence must be reported"
    );

    let mut overlevel_gate = load_json(&gate_path());
    let mappings = overlevel_gate["claim_mappings"].as_array_mut().unwrap();
    let mapping = mappings
        .iter_mut()
        .find(|mapping| {
            mapping["claim_id"].as_str() == Some("readme-standalone-replacement-known-limitation")
        })
        .expect("standalone limitation mapping must exist");
    mapping["advertises_support"] = Value::Bool(true);
    mapping["expected_decision"] = Value::String("block".to_owned());
    mapping["expected_failure_signature"] =
        Value::String("release_example_unsupported_replacement_level".to_owned());

    let overlevel_out = unique_temp_dir("release-readme-example-overlevel");
    std::fs::create_dir_all(&overlevel_out).unwrap();
    let overlevel_path = overlevel_out.join("mutated-overlevel-release-readme-example.json");
    std::fs::write(
        &overlevel_path,
        serde_json::to_string_pretty(&overlevel_gate).unwrap(),
    )
    .unwrap();
    let overlevel_output = run_gate(Some(&overlevel_path), &overlevel_out);
    assert!(
        !overlevel_output.status.success(),
        "gate should fail overall because the summary no longer permits a supported L2 example"
    );
    let overlevel_report = load_json(&overlevel_out.join("release-readme-example.report.json"));
    assert!(
        overlevel_report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| {
                error
                    .as_str()
                    .unwrap_or_default()
                    .contains("release_example_unsupported_replacement_level")
                    || error
                        .as_str()
                        .unwrap_or_default()
                        .contains("allowed_known_limitation_count mismatch")
            }),
        "unsupported L2 support claim must be reported"
    );
}
