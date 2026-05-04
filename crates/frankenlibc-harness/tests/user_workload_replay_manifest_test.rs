//! Integration test: user workload replay manifest gate (bd-b92jd.3.1).
//!
//! Validates the safe baseline/strict/hardened replay manifest, the checker
//! script, deterministic optional skips, and fail-closed negative fixtures.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_MODES: &[&str] = &["baseline", "strict", "hardened"];
const REQUIRED_CATEGORIES: &[&str] = &[
    "coreutils",
    "shell_pipeline",
    "dynamic_runtime",
    "c_fixture",
    "optional_tool",
];
const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "workload_id",
    "category",
    "runtime_mode",
    "command_kind",
    "command_argv",
    "env_overlay",
    "timeout_ms",
    "expected_exit",
    "expected_stdout_kind",
    "optional",
    "skip_reason",
    "artifact_refs",
    "source_commit",
    "target_dir",
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

fn manifest_path() -> PathBuf {
    workspace_root().join("tests/conformance/user_workload_replay_manifest.v1.json")
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json file should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn load_manifest() -> serde_json::Value {
    load_json(&manifest_path())
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

fn run_gate_with_manifest(
    manifest: &Path,
    prefix: &str,
) -> (PathBuf, PathBuf, std::process::Output) {
    let root = workspace_root();
    let temp = unique_temp_dir(prefix);
    let report = temp.join("user_workload_replay_manifest.report.json");
    let log = temp.join("user_workload_replay_manifest.log.jsonl");
    let output = Command::new(root.join("scripts/check_user_workload_replay_manifest.sh"))
        .arg("--dry-run")
        .env("USER_WORKLOAD_REPLAY_MANIFEST", manifest)
        .env("USER_WORKLOAD_REPLAY_REPORT", &report)
        .env("USER_WORKLOAD_REPLAY_LOG", &log)
        .env("USER_WORKLOAD_REPLAY_TARGET_DIR", temp.join("target"))
        .current_dir(&root)
        .output()
        .expect("gate script should execute");
    (report, log, output)
}

fn write_manifest_variant(
    original: &serde_json::Value,
    prefix: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> PathBuf {
    let mut value = original.clone();
    mutate(&mut value);
    let dir = unique_temp_dir(prefix);
    let path = dir.join("user_workload_replay_manifest.v1.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&value).expect("variant manifest should serialize"),
    )
    .expect("variant manifest should write");
    path
}

fn assert_gate_fails_with(manifest: &Path, prefix: &str, expected_signature: &str) {
    let (report_path, _log_path, output) = run_gate_with_manifest(manifest, prefix);
    assert!(
        !output.status.success(),
        "gate unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&report_path);
    let signatures = report["failure_signatures"]
        .as_array()
        .expect("failure_signatures should be array");
    assert!(
        signatures
            .iter()
            .any(|signature| signature.as_str() == Some(expected_signature)),
        "expected failure signature {expected_signature}; report={report:#?}"
    );
}

#[test]
fn manifest_exists_and_declares_replay_contract() {
    let manifest = load_manifest();
    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-b92jd.3.1"));
    assert!(manifest["inputs"].is_object(), "inputs must be object");
    assert_eq!(
        manifest["freshness_policy"]["source_commit"].as_str(),
        Some("current")
    );

    let modes: Vec<_> = manifest["runtime_mode_policy"]["required_modes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|mode| mode.as_str().unwrap())
        .collect();
    assert_eq!(modes, REQUIRED_MODES);

    let categories: Vec<_> = manifest["workload_contract"]["required_categories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|category| category.as_str().unwrap())
        .collect();
    assert_eq!(categories, REQUIRED_CATEGORIES);

    let fields: Vec<_> = manifest["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(fields, REQUIRED_LOG_FIELDS);
}

#[test]
fn workloads_cover_categories_command_shapes_env_and_timeouts() {
    let manifest = load_manifest();
    let max_timeout = manifest["timeout_policy"]["max_timeout_ms"]
        .as_u64()
        .unwrap();
    let mut categories = std::collections::BTreeSet::new();
    let workloads = manifest["workloads"].as_array().unwrap();

    for workload in workloads {
        let id = workload["workload_id"].as_str().unwrap();
        categories.insert(workload["category"].as_str().unwrap().to_owned());
        let timeout = workload["timeout_ms"].as_u64().unwrap();
        assert!(
            timeout > 0 && timeout <= max_timeout,
            "{id}: timeout must be bounded"
        );

        let command = &workload["command"];
        let kind = command["kind"].as_str().unwrap();
        assert!(
            matches!(kind, "argv" | "dynamic_runtime" | "pipeline" | "c_fixture"),
            "{id}: unexpected command kind {kind}"
        );
        match kind {
            "argv" | "dynamic_runtime" => {
                assert!(
                    !command["argv"].as_array().unwrap().is_empty(),
                    "{id}: argv command must have arguments"
                );
            }
            "pipeline" => {
                assert!(
                    command["stages"].as_array().unwrap().len() >= 2,
                    "{id}: pipeline must have at least two stages"
                );
            }
            "c_fixture" => {
                let source = command["source"].as_str().unwrap();
                assert!(
                    workspace_root().join(source).exists(),
                    "{id}: c_fixture source must exist"
                );
                assert!(
                    !command["build_argv"].as_array().unwrap().is_empty(),
                    "{id}: c_fixture build_argv must be present"
                );
            }
            _ => {}
        }

        let expectations = workload["mode_expectations"].as_object().unwrap();
        for runtime_mode in REQUIRED_MODES {
            let env_overlay = expectations[*runtime_mode]["env_overlay"]
                .as_object()
                .unwrap();
            if *runtime_mode == "baseline" {
                assert!(
                    !env_overlay.contains_key("LD_PRELOAD")
                        && !env_overlay.contains_key("FRANKENLIBC_MODE"),
                    "{id}: baseline must not inject FrankenLibC env"
                );
            } else {
                assert_eq!(
                    env_overlay
                        .get("LD_PRELOAD")
                        .and_then(|value| value.as_str()),
                    Some("${FRANKENLIBC_ABI_LIB}"),
                    "{id}: {runtime_mode} must define LD_PRELOAD"
                );
                assert_eq!(
                    env_overlay
                        .get("FRANKENLIBC_MODE")
                        .and_then(|value| value.as_str()),
                    Some(*runtime_mode),
                    "{id}: FRANKENLIBC_MODE must match runtime mode"
                );
            }
        }
    }

    for category in REQUIRED_CATEGORIES {
        assert!(
            categories.contains(*category),
            "manifest must cover category {category}"
        );
    }
}

#[test]
fn optional_tool_probe_has_deterministic_skip_reason() {
    let manifest = load_manifest();
    let optional = manifest["workloads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|workload| workload["optional"].as_bool() == Some(true))
        .expect("at least one optional workload");
    assert_eq!(
        optional["workload_id"].as_str(),
        Some("optional_sqlite_version_probe")
    );
    assert_eq!(
        optional["skip_policy"]["deterministic_skip_reason"].as_str(),
        Some("optional_tool_missing:sqlite3")
    );
}

#[test]
fn gate_script_passes_and_emits_report_and_jsonl_rows() {
    let root = workspace_root();
    let script = root.join("scripts/check_user_workload_replay_manifest.sh");
    assert!(script.exists(), "gate script must exist");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_user_workload_replay_manifest.sh must be executable"
        );
    }

    let (report_path, log_path, output) =
        run_gate_with_manifest(&manifest_path(), "workload-replay-pass");
    assert!(
        output.status.success(),
        "gate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-b92jd.3.1"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["workload_count"].as_u64(), Some(5));
    assert_eq!(report["matrix_row_count"].as_u64(), Some(15));
    for check in [
        "json_parse",
        "top_level_shape",
        "required_log_fields",
        "runtime_mode_policy",
        "artifact_freshness",
        "required_categories",
        "workload_rows",
        "timeout_policy",
        "optional_skip_policy",
        "category_coverage",
        "summary_counts",
        "structured_log_rows",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "checks.{check} should pass"
        );
    }

    let log_content = std::fs::read_to_string(&log_path).expect("log should be readable");
    let rows: Vec<serde_json::Value> = log_content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log row should parse"))
        .collect();
    assert_eq!(rows.len(), 15, "one row per workload x mode");
    assert!(
        rows.iter().any(|row| {
            row["workload_id"].as_str() == Some("optional_sqlite_version_probe")
                && row["skip_reason"].as_str() == Some("optional_tool_missing:sqlite3")
        }),
        "optional sqlite row should carry deterministic skip reason"
    );
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
    }
}

#[test]
fn gate_rejects_invalid_command_argv_fixture() {
    let manifest = load_manifest();
    let path = write_manifest_variant(&manifest, "workload-replay-invalid-command", |value| {
        value["workloads"][0]["command"]["argv"] = serde_json::Value::Array(vec![]);
    });
    assert_gate_fails_with(
        &path,
        "workload-replay-invalid-command-run",
        "workload_replay_invalid_command_argv",
    );
}

#[test]
fn gate_rejects_invalid_env_overlay_fixture() {
    let manifest = load_manifest();
    let path = write_manifest_variant(&manifest, "workload-replay-invalid-env", |value| {
        value["workloads"][0]["mode_expectations"]["baseline"]["env_overlay"]["LD_PRELOAD"] =
            serde_json::Value::String("/bad/lib.so".to_owned());
    });
    assert_gate_fails_with(
        &path,
        "workload-replay-invalid-env-run",
        "workload_replay_invalid_env_overlay",
    );
}

#[test]
fn gate_rejects_invalid_timeout_fixture() {
    let manifest = load_manifest();
    let path = write_manifest_variant(&manifest, "workload-replay-invalid-timeout", |value| {
        value["workloads"][0]["timeout_ms"] = serde_json::Value::Number(999_999.into());
    });
    assert_gate_fails_with(
        &path,
        "workload-replay-invalid-timeout-run",
        "workload_replay_timeout_policy_invalid",
    );
}

#[test]
fn gate_rejects_missing_optional_skip_policy_fixture() {
    let manifest = load_manifest();
    let path = write_manifest_variant(&manifest, "workload-replay-missing-skip", |value| {
        value["workloads"][4]
            .as_object_mut()
            .unwrap()
            .remove("skip_policy");
    });
    assert_gate_fails_with(
        &path,
        "workload-replay-missing-skip-run",
        "workload_replay_optional_skip_missing",
    );
}

#[test]
fn gate_rejects_stale_source_commit_fixture() {
    let manifest = load_manifest();
    let path = write_manifest_variant(&manifest, "workload-replay-stale-source", |value| {
        value["freshness_policy"]["source_commit"] =
            serde_json::Value::String("deadbeef".to_owned());
    });
    assert_gate_fails_with(
        &path,
        "workload-replay-stale-source-run",
        "workload_replay_stale_source_commit",
    );
}
