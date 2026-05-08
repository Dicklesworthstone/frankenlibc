//! Integration test: workload compatibility dossier (bd-fp4tm.5).

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_DOSSIER_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "workload_id",
    "claim_scope",
    "replacement_level",
    "strict_status",
    "hardened_status",
    "freshness_state",
    "perf_state",
    "failure_signature",
    "user_recommendation",
    "artifact_refs",
    "exact_reproduction_command",
    "source_commit",
    "next_safe_action",
];

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn json_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("missing JSON field {key}")))
}

fn unique_output_dir(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let dir = root
        .join("target/conformance")
        .join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

struct FixturePaths {
    acceptance: PathBuf,
    freshness: PathBuf,
    reproducer: PathBuf,
    latency: PathBuf,
    smoke: PathBuf,
    release: PathBuf,
    replacement: PathBuf,
    user_compat: PathBuf,
}

fn base_fixtures(dir: &Path) -> TestResult<FixturePaths> {
    let paths = FixturePaths {
        acceptance: dir.join("acceptance.json"),
        freshness: dir.join("freshness.json"),
        reproducer: dir.join("reproducer.json"),
        latency: dir.join("latency.json"),
        smoke: dir.join("smoke.json"),
        release: dir.join("release.json"),
        replacement: dir.join("replacement.json"),
        user_compat: dir.join("user_compat.json"),
    };
    write_json(
        &paths.acceptance,
        &json!({
            "schema_version": "v1",
            "claim_rows": [
                {
                    "workload_id": "ready-coreutils",
                    "claim_scope": "readme quickstart",
                    "replacement_level": "L0",
                    "strict_status": "pass",
                    "hardened_status": "pass",
                    "artifact_refs": [
                        "tests/conformance/user_workload_acceptance_matrix.v1.json",
                        "target/conformance/workload_evidence_freshness.report.json"
                    ]
                },
                {
                    "workload_id": "hardened-degraded-python",
                    "claim_scope": "runtime smoke",
                    "replacement_level": "L0",
                    "strict_status": "pass",
                    "hardened_status": "fail",
                    "artifact_refs": [
                        "tests/conformance/user_workload_acceptance_matrix.v1.json",
                        "target/conformance/workload_reproducer_manifest.v1.json"
                    ]
                },
                {
                    "workload_id": "unsupported-service",
                    "claim_scope": "threaded service",
                    "replacement_level": "L0",
                    "strict_status": "fail",
                    "hardened_status": "fail",
                    "failure_signature": "unsupported_workload",
                    "unsupported": "true",
                    "artifact_refs": [
                        "tests/conformance/user_workload_acceptance_matrix.v1.json",
                        "target/conformance/workload_reproducer_manifest.v1.json"
                    ]
                }
            ]
        }),
    )?;
    write_json(
        &paths.freshness,
        &json!({
            "schema_version": "v1",
            "status": "pass",
            "workload_rows": [
                {"workload_id": "ready-coreutils", "freshness_state": "current", "artifact_refs": ["target/conformance/workload_evidence_freshness.report.json"]},
                {"workload_id": "hardened-degraded-python", "freshness_state": "current", "artifact_refs": ["target/conformance/workload_evidence_freshness.report.json"]},
                {"workload_id": "unsupported-service", "freshness_state": "current", "artifact_refs": ["target/conformance/workload_evidence_freshness.report.json"]}
            ]
        }),
    )?;
    write_json(
        &paths.reproducer,
        &json!({
            "schema_version": "v1",
            "status": "pass",
            "reproducers": [
                {
                    "workload_id": "hardened-degraded-python",
                    "failure_signature": "startup_perf_regression",
                    "reproduction_command": "FRANKENLIBC_MODE=hardened /usr/bin/python3 -c 'print(1)'",
                    "artifact_refs": ["target/conformance/workload_reproducer_manifest.v1.json"]
                },
                {
                    "workload_id": "unsupported-service",
                    "failure_signature": "unsupported_workload",
                    "reproduction_command": "",
                    "artifact_refs": ["target/conformance/workload_reproducer_manifest.v1.json"]
                }
            ]
        }),
    )?;
    write_json(
        &paths.latency,
        &json!({
            "schema_version": "v1",
            "status": "pass",
            "workload_latency_rows": [
                {"workload_id": "ready-coreutils", "mode": "strict", "perf_state": "within_budget", "decision": "pass", "failure_signature": "none"},
                {"workload_id": "ready-coreutils", "mode": "hardened", "perf_state": "within_budget", "decision": "pass", "failure_signature": "none"},
                {"workload_id": "hardened-degraded-python", "mode": "strict", "perf_state": "within_budget", "decision": "pass", "failure_signature": "none"}
            ]
        }),
    )?;
    write_json(
        &paths.smoke,
        &json!({
            "schema_version": "v1",
            "summary": {"overall_failed": false},
            "modes": {"strict": {"status": "green"}, "hardened": {"status": "green"}}
        }),
    )?;
    write_json(
        &paths.release,
        &json!({"schema_version": "v1", "claim_mappings": []}),
    )?;
    write_json(
        &paths.replacement,
        &json!({"schema_version": 1, "current_level": "L0", "release_tag_policy": {"current_release_level": "L0"}}),
    )?;
    write_json(
        &paths.user_compat,
        &json!({"schema_version": "v1", "status": "pass"}),
    )?;
    Ok(paths)
}

fn run_gate(root: &Path, dir: &Path, fixtures: &FixturePaths) -> TestResult<std::process::Output> {
    let output = Command::new("bash")
        .arg(root.join("scripts/check_workload_compatibility_dossier.sh"))
        .current_dir(root)
        .env(
            "FRANKENLIBC_WORKLOAD_DOSSIER_ACCEPTANCE",
            &fixtures.acceptance,
        )
        .env(
            "FRANKENLIBC_WORKLOAD_DOSSIER_FRESHNESS",
            &fixtures.freshness,
        )
        .env(
            "FRANKENLIBC_WORKLOAD_DOSSIER_REPRODUCER",
            &fixtures.reproducer,
        )
        .env("FRANKENLIBC_WORKLOAD_DOSSIER_LATENCY", &fixtures.latency)
        .env("FRANKENLIBC_WORKLOAD_DOSSIER_SMOKE", &fixtures.smoke)
        .env("FRANKENLIBC_WORKLOAD_DOSSIER_RELEASE", &fixtures.release)
        .env(
            "FRANKENLIBC_WORKLOAD_DOSSIER_REPLACEMENT",
            &fixtures.replacement,
        )
        .env(
            "FRANKENLIBC_WORKLOAD_DOSSIER_USER_COMPAT",
            &fixtures.user_compat,
        )
        .env("FRANKENLIBC_WORKLOAD_DOSSIER_OUT_DIR", dir)
        .env(
            "FRANKENLIBC_WORKLOAD_DOSSIER_REPORT",
            dir.join("dossier.report.json"),
        )
        .env(
            "FRANKENLIBC_WORKLOAD_DOSSIER_MARKDOWN",
            dir.join("dossier.md"),
        )
        .env(
            "FRANKENLIBC_WORKLOAD_DOSSIER_LOG",
            dir.join("dossier.log.jsonl"),
        )
        .output()?;
    Ok(output)
}

#[test]
fn contract_declares_dossier_schema() -> TestResult {
    let root = workspace_root()?;
    let contract =
        load_json(&root.join("tests/conformance/workload_compatibility_dossier.v1.json"))?;
    assert_eq!(contract["schema_version"].as_str(), Some("v1"));
    assert_eq!(contract["bead"].as_str(), Some("bd-fp4tm.5"));
    let fields: BTreeSet<_> = json_field(&contract, "required_dossier_fields")?
        .as_array()
        .ok_or_else(|| test_error("required_dossier_fields should be array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for field in REQUIRED_DOSSIER_FIELDS {
        assert!(fields.contains(field), "missing dossier field {field}");
    }
    Ok(())
}

#[test]
fn gate_script_is_executable() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_workload_compatibility_dossier.sh");
    assert!(script.exists(), "missing {}", script.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)?.permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_workload_compatibility_dossier.sh must be executable"
        );
    }
    Ok(())
}

#[test]
fn dossier_separates_ready_degraded_and_unsupported_recommendations() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-dossier-pass")?;
    let fixtures = base_fixtures(&dir)?;
    let output = run_gate(&root, &dir, &fixtures)?;
    assert!(
        output.status.success(),
        "dossier gate failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&dir.join("dossier.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["workload_count"].as_u64(), Some(3));
    for recommendation in [
        "ready_l0_interpose",
        "hardened_only_degraded",
        "unsupported_workload",
    ] {
        assert!(
            report["summary"]["recommendation_counts"][recommendation]
                .as_u64()
                .unwrap_or(0)
                >= 1,
            "missing recommendation {recommendation}"
        );
    }
    let rows = json_field(&report, "dossier_rows")?
        .as_array()
        .ok_or_else(|| test_error("dossier_rows should be array"))?;
    let mut trace_ids = BTreeSet::new();
    for row in rows {
        for field in REQUIRED_DOSSIER_FIELDS {
            assert!(row.get(*field).is_some(), "dossier row missing {field}");
        }
        let trace_id = json_field(row, "trace_id")?
            .as_str()
            .ok_or_else(|| test_error("trace_id should be string"))?;
        assert!(trace_ids.insert(trace_id), "duplicate trace_id {trace_id}");
        if json_field(row, "user_recommendation")?.as_str() == Some("ready_l0_interpose") {
            assert!(
                matches!(
                    json_field(row, "perf_state")?.as_str(),
                    Some("within_budget" | "overloaded_skip")
                ),
                "ready row should have latency-budget evidence"
            );
        }
    }
    let degraded = rows
        .iter()
        .find(|row| {
            row.get("workload_id").and_then(Value::as_str) == Some("hardened-degraded-python")
        })
        .ok_or_else(|| test_error("missing degraded row"))?;
    assert_eq!(
        json_field(degraded, "user_recommendation")?.as_str(),
        Some("hardened_only_degraded")
    );
    assert!(
        json_field(degraded, "exact_reproduction_command")?
            .as_str()
            .is_some_and(|command| command.contains("FRANKENLIBC_MODE=hardened"))
    );
    let markdown = std::fs::read_to_string(dir.join("dossier.md"))?;
    assert!(markdown.contains("ready-coreutils"));
    let log_rows = std::fs::read_to_string(dir.join("dossier.log.jsonl"))?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(log_rows.len(), 3);
    Ok(())
}

#[test]
fn ready_recommendation_without_latency_budget_is_blocked() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-dossier-missing-latency")?;
    let fixtures = base_fixtures(&dir)?;
    write_json(
        &fixtures.acceptance,
        &json!({
            "schema_version": "v1",
            "claim_rows": [{
                "workload_id": "ready-without-latency",
                "claim_scope": "runtime smoke",
                "replacement_level": "L0",
                "strict_status": "pass",
                "hardened_status": "pass",
                "artifact_refs": [
                    "tests/conformance/user_workload_acceptance_matrix.v1.json",
                    "target/conformance/workload_evidence_freshness.report.json"
                ]
            }]
        }),
    )?;
    write_json(
        &fixtures.latency,
        &json!({
            "schema_version": "v1",
            "status": "pass",
            "workload_latency_rows": []
        }),
    )?;
    let output = run_gate(&root, &dir, &fixtures)?;
    assert!(
        output.status.success(),
        "dossier generation should succeed while blocking the row\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&dir.join("dossier.report.json"))?;
    let rows = json_field(&report, "dossier_rows")?
        .as_array()
        .ok_or_else(|| test_error("dossier_rows should be array"))?;
    let row = rows
        .first()
        .ok_or_else(|| test_error("missing dossier row"))?;
    assert_eq!(
        json_field(row, "user_recommendation")?.as_str(),
        Some("replacement_blocked")
    );
    assert_eq!(
        json_field(row, "failure_signature")?.as_str(),
        Some("workload_latency_missing_evidence")
    );
    Ok(())
}

#[test]
fn ready_recommendation_from_prose_only_fails_closed() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-dossier-prose-only")?;
    let fixtures = base_fixtures(&dir)?;
    write_json(
        &fixtures.acceptance,
        &json!({
            "schema_version": "v1",
            "claim_rows": [{
                "workload_id": "ready-from-prose",
                "claim_scope": "readme prose",
                "replacement_level": "L0",
                "strict_status": "pass",
                "hardened_status": "pass",
                "artifact_refs": ["README.md"]
            }]
        }),
    )?;
    write_json(
        &fixtures.latency,
        &json!({
            "schema_version": "v1",
            "status": "pass",
            "workload_latency_rows": [
                {"workload_id": "ready-from-prose", "mode": "strict", "perf_state": "within_budget", "decision": "pass", "failure_signature": "none"},
                {"workload_id": "ready-from-prose", "mode": "hardened", "perf_state": "within_budget", "decision": "pass", "failure_signature": "none"}
            ]
        }),
    )?;
    let output = run_gate(&root, &dir, &fixtures)?;
    assert!(!output.status.success(), "prose-only ready row should fail");
    let report = load_json(&dir.join("dossier.report.json"))?;
    assert!(
        report["failure_signatures"]
            .as_array()
            .ok_or_else(|| test_error("failure_signatures should be array"))?
            .iter()
            .any(|item| item.as_str() == Some("dossier_ready_from_prose_only"))
    );
    Ok(())
}

#[test]
fn ready_recommendation_from_stale_evidence_fails_closed() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-dossier-stale")?;
    let fixtures = base_fixtures(&dir)?;
    write_json(
        &fixtures.freshness,
        &json!({
            "schema_version": "v1",
            "status": "pass",
            "workload_rows": [{
                "workload_id": "ready-coreutils",
                "freshness_state": "stale",
                "artifact_refs": ["target/conformance/workload_evidence_freshness.report.json"]
            }]
        }),
    )?;
    let output = run_gate(&root, &dir, &fixtures)?;
    assert!(!output.status.success(), "stale ready row should fail");
    let report = load_json(&dir.join("dossier.report.json"))?;
    assert!(
        report["failure_signatures"]
            .as_array()
            .ok_or_else(|| test_error("failure_signatures should be array"))?
            .iter()
            .any(|item| item.as_str() == Some("dossier_ready_from_stale_evidence"))
    );
    Ok(())
}
