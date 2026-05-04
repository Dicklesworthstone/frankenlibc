//! Integration test: README/FEATURE_PARITY semantic claim gate (bd-bp8fl.1.4)
//!
//! Verifies that docs separate support taxonomy from semantic parity and fail
//! closed when prose tries to advance unsupported replacement claims.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_FIELDS: &[&str] = &[
    "symbol_status",
    "semantic_parity_status",
    "oracle_kind",
    "replacement_level",
    "evidence_artifact",
    "freshness_state",
    "known_limitation",
    "user_recommendation",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "doc_surface",
    "symbol_or_section",
    "previous_claim",
    "generated_claim",
    "evidence_refs",
    "source_commit",
    "failure_signature",
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

fn unique_temp_path(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("frankenlibc-{name}-{stamp}-{}", std::process::id()))
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn parse_stdout_report(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(
        parsed.is_ok(),
        "failed to parse gate stdout as JSON: {}\nstdout={stdout}\nstderr={stderr}",
        parsed.err().unwrap()
    );
    serde_json::from_str(&stdout).expect("gate stdout JSON parse was checked above")
}

fn run_gate_with_env(envs: &[(&str, &Path)]) -> Output {
    let root = workspace_root();
    let script = root.join("scripts/check_docs_semantic_claims.sh");
    let mut command = Command::new(&script);
    command.current_dir(&root);
    for (key, value) in envs {
        command.env(key, value);
    }
    command
        .output()
        .expect("failed to run docs semantic claims gate")
}

#[test]
fn artifact_declares_claim_fields_inputs_replays_and_log_contract() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/docs_semantic_claims.v1.json"));
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-bp8fl.1.4"));

    for key in [
        "readme",
        "feature_parity",
        "support_matrix",
        "support_semantic_overlay",
        "semantic_contract_inventory",
        "semantic_contract_symbol_join",
        "oracle_precedence",
        "replacement_levels",
    ] {
        let rel = artifact["inputs"][key].as_str().expect("input path");
        assert!(root.join(rel).exists(), "missing input {key}: {rel}");
    }

    let fields: HashSet<_> = artifact["required_claim_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(fields, REQUIRED_FIELDS.iter().copied().collect());

    let log_fields: Vec<_> = artifact["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);

    let replay_kinds: HashSet<_> = artifact["replay_cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        replay_kinds,
        [
            "clean",
            "forbidden_claim",
            "missing_field",
            "stale_artifact"
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn gate_passes_current_docs_and_emits_report_and_log() {
    let root = workspace_root();
    let script = root.join("scripts/check_docs_semantic_claims.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_docs_semantic_claims.sh must be executable"
        );
    }

    let output = run_gate_with_env(&[]);
    assert!(
        output.status.success(),
        "docs semantic claims gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = parse_stdout_report(&output);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["required_claim_field_count"].as_u64(),
        Some(8)
    );
    assert_eq!(
        report["summary"]["semantic_parity_blocker_count"].as_u64(),
        Some(18)
    );
    assert_eq!(
        report["summary"]["taxonomy_semantic_conflict_count"].as_u64(),
        Some(18)
    );
    assert_eq!(report["summary"]["forbidden_claim_count"].as_u64(), Some(0));

    let log_path = root.join("target/conformance/docs_semantic_claims.log.jsonl");
    assert!(log_path.exists(), "missing {}", log_path.display());
    let log_line = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should contain at least one row")
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&log_line).expect("log row should parse");
    for key in REQUIRED_LOG_FIELDS {
        assert!(event.get(*key).is_some(), "log row missing {key}");
    }
}

#[test]
fn missing_claim_field_fails() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("README.md")).unwrap();
    let mutated = source.replace("| `user_recommendation` |", "| `user_guidance` |");
    let readme = unique_temp_path("docs-semantic-missing-field.md");
    std::fs::write(&readme, mutated).expect("failed to write README fixture");

    let output = run_gate_with_env(&[("FLC_DOCS_SEMANTIC_README", &readme)]);
    assert!(
        !output.status.success(),
        "missing claim field should fail:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_report(&output);
    assert_eq!(report["checks"]["docs_claim_fields"].as_str(), Some("fail"));
    assert!(report["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error
            .as_str()
            .unwrap_or_default()
            .contains("user_recommendation")));
}

#[test]
fn forbidden_full_replacement_claim_fails() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("FEATURE_PARITY.md")).unwrap();
    let mutated = format!("{source}\n\nStub: 0 proves full standalone replacement today.\n");
    let feature = unique_temp_path("docs-semantic-forbidden-claim.md");
    std::fs::write(&feature, mutated).expect("failed to write FEATURE fixture");

    let output = run_gate_with_env(&[("FLC_DOCS_SEMANTIC_FEATURE_PARITY", &feature)]);
    assert!(
        !output.status.success(),
        "forbidden replacement claim should fail:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_report(&output);
    assert_eq!(
        report["checks"]["forbidden_claim_patterns"].as_str(),
        Some("fail")
    );
    assert!(
        report["summary"]["forbidden_claim_count"].as_u64().unwrap() >= 1,
        "forbidden claim fixture should produce at least one finding"
    );
}

#[test]
fn stale_semantic_join_fails() {
    let root = workspace_root();
    let canonical = root.join("tests/conformance/semantic_contract_symbol_join.v1.json");
    let mut join = load_json(&canonical);
    join["summary"]["semantic_parity_blocker_count"] = serde_json::json!(0);
    let stale = unique_temp_path("docs-semantic-stale-join.json");
    std::fs::write(&stale, serde_json::to_string_pretty(&join).unwrap() + "\n")
        .expect("failed to write stale join fixture");

    let output = run_gate_with_env(&[("FLC_DOCS_SEMANTIC_JOIN", &stale)]);
    assert!(
        !output.status.success(),
        "stale semantic join should fail:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_report(&output);
    assert_eq!(
        report["checks"]["semantic_evidence_freshness"].as_str(),
        Some("fail")
    );
}
