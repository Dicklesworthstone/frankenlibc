//! Integration test: fixture dual-runner gate (bd-bp8fl.4.2).

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_MANIFEST_FIELDS: &[&str] = &[
    "direct_runner",
    "isolated_runner",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "expected",
    "timeout_ms",
    "environment",
    "cleanup",
    "artifact_paths",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "fixture_id",
    "runner_kind",
    "runtime_mode",
    "replacement_level",
    "expected",
    "actual",
    "errno",
    "duration_ms",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const EXPECTED_FIXTURES: &[&str] = &[
    "ctype_ops",
    "dirent_ops",
    "memory_ops",
    "socket_ops",
    "time_ops",
    "wide_string_ops",
];

const EXPECTED_FAILURES: &[&str] = &[
    "direct_runner_mismatch",
    "isolated_runner_timeout",
    "stale_artifact",
    "isolated_runner_missing",
    "env_cleanup_missing",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn gate_path() -> PathBuf {
    workspace_root().join("tests/conformance/fixture_dual_runner_gate.v1.json")
}

fn script_path() -> PathBuf {
    workspace_root().join("scripts/check_fixture_dual_runner_gate.sh")
}

fn load_json(path: &Path) -> Value {
    let content = std::fs::read_to_string(path).expect("json artifact should be readable");
    serde_json::from_str(&content).expect("json artifact should parse")
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
        .env("FRANKENLIBC_FIXTURE_DUAL_RUNNER_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_FIXTURE_DUAL_RUNNER_REPORT",
            out_dir.join("fixture-dual-runner.report.json"),
        )
        .env(
            "FRANKENLIBC_FIXTURE_DUAL_RUNNER_LOG",
            out_dir.join("fixture-dual-runner.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_FIXTURE_DUAL_RUNNER_TARGET_DIR",
            "test-target-dir",
        );
    if let Some(config) = config {
        command.env("FRANKENLIBC_FIXTURE_DUAL_RUNNER_GATE", config);
    }
    command
        .output()
        .expect("failed to run fixture dual-runner gate")
}

#[test]
fn artifact_requires_direct_and_isolated_fixture_paths() {
    let root = workspace_root();
    let gate = load_json(&gate_path());
    assert_eq!(gate["schema_version"].as_str(), Some("v1"));
    assert_eq!(gate["bead"].as_str(), Some("bd-bp8fl.4.2"));
    assert_eq!(
        gate["required_manifest_fields"].as_array().unwrap(),
        &REQUIRED_MANIFEST_FIELDS
            .iter()
            .map(|field| Value::String((*field).to_owned()))
            .collect::<Vec<_>>()
    );
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

    let fixtures = gate["fixture_families"].as_array().unwrap();
    assert_eq!(fixtures.len(), EXPECTED_FIXTURES.len());
    let ids = fixtures
        .iter()
        .map(|family| family["fixture_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ids,
        EXPECTED_FIXTURES.iter().copied().collect::<BTreeSet<_>>()
    );

    for family in fixtures {
        let fixture_id = family["fixture_id"].as_str().unwrap();
        for field in REQUIRED_MANIFEST_FIELDS {
            assert!(family.get(*field).is_some(), "{fixture_id} missing {field}");
        }
        let modes = family["runtime_modes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|mode| mode.as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(modes, ["hardened", "strict"].into_iter().collect());

        let fixture_manifest = family["fixture_manifest"].as_str().unwrap();
        let fixture_doc = load_json(&root.join(fixture_manifest));
        assert!(
            !fixture_doc["cases"].as_array().unwrap().is_empty(),
            "{fixture_id} fixture cases must not be empty"
        );

        let test_file = family["test_file"].as_str().unwrap();
        let test_text = std::fs::read_to_string(root.join(test_file)).unwrap();
        for fragment in family["required_direct_tokens"].as_array().unwrap() {
            let fragment = fragment.as_str().unwrap();
            assert!(
                test_text.contains(fragment),
                "{fixture_id} missing direct fragment {fragment:?}"
            );
        }
        for fragment in family["required_isolated_tokens"].as_array().unwrap() {
            let fragment = fragment.as_str().unwrap();
            assert!(
                test_text.contains(fragment),
                "{fixture_id} missing isolated fragment {fragment:?}"
            );
        }
    }

    let scenarios = gate["replay_scenarios"].as_array().unwrap();
    assert_eq!(scenarios.len(), 6);
    let allowed = scenarios
        .iter()
        .filter(|scenario| scenario["expected_decision"].as_str() == Some("allow"))
        .count();
    let blocked = scenarios
        .iter()
        .filter(|scenario| scenario["expected_decision"].as_str() == Some("block"))
        .count();
    assert_eq!(allowed, 1);
    assert_eq!(blocked, 5);
    let failures = scenarios
        .iter()
        .map(|scenario| scenario["expected_failure_signature"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    for failure in EXPECTED_FAILURES {
        assert!(
            failures.contains(failure),
            "scenario set must exercise {failure}"
        );
    }
}

#[test]
fn gate_script_passes_and_emits_dual_runner_log_rows() {
    let script = script_path();
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_fixture_dual_runner_gate.sh must be executable"
        );
    }

    let out_dir = unique_temp_dir("fixture-dual-runner-pass");
    let output = run_gate(None, &out_dir);
    assert!(
        output.status.success(),
        "gate should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("fixture-dual-runner.report.json"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["fixture_family_count"].as_u64(), Some(6));
    assert_eq!(report["summary"]["scenario_count"].as_u64(), Some(6));
    assert_eq!(
        report["summary"]["allowed_scenario_count"].as_u64(),
        Some(1)
    );
    assert_eq!(
        report["summary"]["blocked_scenario_count"].as_u64(),
        Some(5)
    );
    assert!(report["errors"].as_array().unwrap().is_empty());

    let log_text = std::fs::read_to_string(out_dir.join("fixture-dual-runner.log.jsonl")).unwrap();
    let mut rows = Vec::new();
    for line in log_text.lines().filter(|line| !line.trim().is_empty()) {
        rows.push(serde_json::from_str::<Value>(line).expect("log row should parse"));
    }
    assert!(rows.len() >= 18, "family and replay rows must be logged");
    let mut runner_kinds = BTreeSet::new();
    let mut failure_signatures = BTreeSet::new();
    for row in &rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
        runner_kinds.insert(row["runner_kind"].as_str().unwrap());
        failure_signatures.insert(row["failure_signature"].as_str().unwrap());
        assert_eq!(row["bead_id"].as_str(), Some("bd-bp8fl.4.2"));
        assert_eq!(row["target_dir"].as_str(), Some("test-target-dir"));
    }
    assert!(runner_kinds.contains("direct"));
    assert!(runner_kinds.contains("isolated"));
    assert!(runner_kinds.contains("direct+isolated"));
    for failure in EXPECTED_FAILURES {
        assert!(
            failure_signatures.contains(failure),
            "log must include {failure}"
        );
    }
}

#[test]
fn gate_fails_closed_when_isolated_runner_binding_disappears() {
    let mut gate = load_json(&gate_path());
    let families = gate["fixture_families"].as_array_mut().unwrap();
    let family = families
        .iter_mut()
        .find(|family| family["fixture_id"].as_str() == Some("memory_ops"))
        .expect("memory_ops fixture family must exist");
    family["required_isolated_tokens"] = Value::Array(vec![Value::String(
        "missing-isolated-subprocess-fragment".to_owned(),
    )]);

    let out_dir = unique_temp_dir("fixture-dual-runner-fail");
    std::fs::create_dir_all(&out_dir).unwrap();
    let mutated_gate = out_dir.join("mutated-fixture-dual-runner.json");
    std::fs::write(&mutated_gate, serde_json::to_string_pretty(&gate).unwrap()).unwrap();

    let output = run_gate(Some(&mutated_gate), &out_dir);
    assert!(
        !output.status.success(),
        "gate should fail when isolated runner evidence disappears\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&out_dir.join("fixture-dual-runner.report.json"));
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = report["errors"].as_array().unwrap();
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or_default()
            .contains("isolated_runner_missing")),
        "missing isolated subprocess evidence must fail closed"
    );
}
