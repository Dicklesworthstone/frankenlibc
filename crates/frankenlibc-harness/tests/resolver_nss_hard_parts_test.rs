//! Integration tests for resolver/NSS hard-parts fixtures (bd-bp8fl.5.1).

use serde_json::Value;
use std::collections::HashSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "fixture_id",
    "query_kind",
    "network_state",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "h_errno",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REQUIRED_QUERY_KINDS: &[&str] = &[
    "hosts_lookup",
    "dns_success",
    "dns_failure",
    "offline_resolver",
    "missing_nss_backend",
    "malformed_packet",
    "cache_consistency",
];

const REQUIRED_INPUT_DATABASES: &[&str] = &[
    "hosts",
    "passwd",
    "group",
    "services",
    "protocols",
    "dns",
    "nsswitch",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/resolver_nss_hard_parts.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_resolver_nss_hard_parts.sh")
}

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn unique_temp_dir(label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before UNIX_EPOCH: {err}")))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-{label}-{stamp}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    let content = serde_json::to_string_pretty(value)
        .map_err(|err| test_error(format!("{} serialization failed: {err}", path.display())))?;
    std::fs::write(path, format!("{content}\n"))
        .map_err(|err| test_error(format!("{} write failed: {err}", path.display())))
}

fn field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    field(value, key, context)?
        .as_str()
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn array_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    field(value, key, context)?
        .as_array()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn object_field<'a>(
    value: &'a Value,
    key: &str,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    field(value, key, context)?
        .as_object()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an object")))
}

fn mutable_rows(manifest: &mut Value) -> TestResult<&mut Vec<Value>> {
    manifest
        .get_mut("fixture_rows")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("manifest.fixture_rows must be mutable array"))
}

fn mutable_row(manifest: &mut Value, index: usize) -> TestResult<&mut Value> {
    mutable_rows(manifest)?
        .get_mut(index)
        .ok_or_else(|| test_error(format!("manifest.fixture_rows[{index}] must exist")))
}

fn run_gate(root: &Path, manifest: Option<&Path>, out_dir: &Path) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(script_path(root))
        .current_dir(root)
        .env("FLC_RESOLVER_NSS_HARD_PARTS_OUT_DIR", out_dir)
        .env(
            "FLC_RESOLVER_NSS_HARD_PARTS_REPORT",
            out_dir.join("resolver-nss.report.json"),
        )
        .env(
            "FLC_RESOLVER_NSS_HARD_PARTS_LOG",
            out_dir.join("resolver-nss.log.jsonl"),
        )
        .env("FLC_RESOLVER_NSS_HARD_PARTS_TARGET_DIR", out_dir);
    if let Some(manifest) = manifest {
        command.env("FLC_RESOLVER_NSS_HARD_PARTS_MANIFEST", manifest);
    }
    command
        .output()
        .map_err(|err| test_error(format!("failed to run resolver/NSS gate: {err}")))
}

fn run_negative_case(root: &Path, case_name: &str, manifest: &Value) -> TestResult<Value> {
    let out_dir = unique_temp_dir(case_name)?;
    let manifest_fixture = out_dir.join(format!("{case_name}.manifest.json"));
    let report_path = out_dir.join("resolver-nss.report.json");
    write_json(&manifest_fixture, manifest)?;
    let output = run_gate(root, Some(&manifest_fixture), &out_dir)?;
    if output.status.success() {
        return Err(test_error(format!(
            "{case_name}: gate should fail\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    load_json(&report_path)
}

fn expect_failure_signature(report: &Value, signature: &str) -> TestResult {
    let errors = array_field(report, "errors", "report")?;
    if errors.iter().any(|row| {
        row.get("failure_signature").and_then(Value::as_str) == Some(signature)
            || row
                .get("message")
                .and_then(Value::as_str)
                .is_some_and(|message| message.contains(signature))
    }) {
        Ok(())
    } else {
        Err(test_error(format!(
            "report should contain failure signature {signature}: {report:#?}"
        )))
    }
}

#[test]
fn manifest_defines_resolver_nss_schema_and_required_coverage() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(string_field(&manifest, "schema_version", "manifest")?, "v1");
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-bp8fl.5.1"
    );
    assert_eq!(
        string_field(&manifest, "gate_id", "manifest")?,
        "resolver-nss-hard-parts-v1"
    );

    for key in [
        "resolver_fixture",
        "oracle_precedence_divergence",
        "support_matrix",
        "hard_parts_failure_replay_gate",
        "hard_parts_e2e_catalog",
    ] {
        let rel = string_field(field(&manifest, "sources", "manifest")?, key, "sources")?;
        assert!(root.join(rel).exists(), "missing source {key}: {rel}");
    }

    let required_log_fields = array_field(&manifest, "required_log_fields", "manifest")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_log_fields entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(required_log_fields, REQUIRED_LOG_FIELDS);

    let query_kinds: HashSet<_> = array_field(&manifest, "required_query_kinds", "manifest")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_query_kinds entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?
        .into_iter()
        .collect();
    assert_eq!(query_kinds, REQUIRED_QUERY_KINDS.iter().copied().collect());

    let databases: HashSet<_> = array_field(&manifest, "required_input_databases", "manifest")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_input_databases entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?
        .into_iter()
        .collect();
    assert_eq!(
        databases,
        REQUIRED_INPUT_DATABASES.iter().copied().collect()
    );

    let rows = array_field(&manifest, "fixture_rows", "manifest")?;
    assert!(rows.len() >= REQUIRED_QUERY_KINDS.len());
    for row in rows {
        for field in [
            "fixture_id",
            "query_kind",
            "input_database",
            "network_state",
            "nsswitch_config",
            "runtime_mode",
            "replacement_level",
            "oracle_kind",
            "allowed_divergence",
            "source_fixture_case",
        ] {
            assert!(row.get(field).is_some(), "fixture row missing {field}");
        }
        assert!(object_field(row, "expected", "fixture row")?.contains_key("h_errno"));
        assert!(object_field(row, "cleanup", "fixture row")?.contains_key("state"));
        assert!(
            object_field(row, "nss_backend_failure", "fixture row")?.contains_key("classification")
        );
        assert!(object_field(row, "dns_error_mapping", "fixture row")?.contains_key("h_errno"));
        assert!(
            object_field(row, "environment_divergence", "fixture row")?.contains_key("allowed")
        );
        assert_eq!(
            string_field(
                field(row, "direct_runner", "fixture row")?,
                "runner_kind",
                "direct"
            )?,
            "direct"
        );
        assert_eq!(
            string_field(
                field(row, "isolated_runner", "fixture row")?,
                "runner_kind",
                "isolated"
            )?,
            "isolated"
        );
    }

    Ok(())
}

#[test]
fn gate_passes_and_emits_resolver_nss_logs() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_temp_dir("resolver-nss-pass")?;
    let output = run_gate(&root, None, &out_dir)?;
    assert!(
        output.status.success(),
        "gate should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("resolver-nss.report.json"))?;
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    assert_eq!(
        field(&report, "summary", "report")?
            .get("covered_query_kind_count")
            .and_then(Value::as_u64),
        Some(REQUIRED_QUERY_KINDS.len() as u64)
    );
    assert_eq!(
        field(&report, "summary", "report")?
            .get("covered_input_database_count")
            .and_then(Value::as_u64),
        Some(REQUIRED_INPUT_DATABASES.len() as u64)
    );
    assert_eq!(
        field(&report, "summary", "report")?
            .get("runtime_mode_count")
            .and_then(Value::as_u64),
        Some(2)
    );

    let log_text = std::fs::read_to_string(out_dir.join("resolver-nss.log.jsonl"))?;
    let rows = log_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        rows.len() as u64,
        field(&report, "summary", "report")?
            .get("fixture_count")
            .and_then(Value::as_u64)
            .unwrap()
    );
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
        assert_eq!(string_field(&row, "bead_id", "log")?, "bd-bp8fl.5.1");
        assert_eq!(string_field(&row, "failure_signature", "log")?, "ok");
    }

    Ok(())
}

#[test]
fn gate_fails_closed_for_resolver_nss_fixture_drift() -> TestResult {
    let root = workspace_root();
    let base = load_json(&manifest_path(&root))?;

    let mut stale = base.clone();
    stale
        .get_mut("freshness")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("freshness must be object"))?
        .insert(
            "required_source_commit".to_string(),
            Value::String("not-current-source-commit".to_string()),
        );
    let stale_report = run_negative_case(&root, "resolver-nss-stale", &stale)?;
    expect_failure_signature(&stale_report, "stale_artifact")?;

    let mut missing_query = base.clone();
    mutable_row(&mut missing_query, 0)?
        .as_object_mut()
        .ok_or_else(|| test_error("fixture row must be object"))?
        .insert(
            "query_kind".to_string(),
            Value::String("unsupported_query".to_string()),
        );
    let missing_query_report =
        run_negative_case(&root, "resolver-nss-missing-query", &missing_query)?;
    expect_failure_signature(&missing_query_report, "missing_fixture_case")?;

    let mut nss_classification = base.clone();
    mutable_row(&mut nss_classification, 5)?
        .get_mut("nss_backend_failure")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("nss_backend_failure must be object"))?
        .insert(
            "classification".to_string(),
            Value::String("not_applicable".to_string()),
        );
    let nss_report = run_negative_case(&root, "resolver-nss-classification", &nss_classification)?;
    expect_failure_signature(&nss_report, "nss_backend_failure_classification")?;

    let mut dns_mapping = base.clone();
    mutable_row(&mut dns_mapping, 6)?
        .get_mut("dns_error_mapping")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("dns_error_mapping must be object"))?
        .insert(
            "h_errno".to_string(),
            Value::String("TRY_AGAIN".to_string()),
        );
    let dns_report = run_negative_case(&root, "resolver-nss-dns-mapping", &dns_mapping)?;
    expect_failure_signature(&dns_report, "dns_error_mapping")?;

    let mut env_divergence = base;
    mutable_row(&mut env_divergence, 3)?
        .get_mut("environment_divergence")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("environment_divergence must be object"))?
        .insert("allowed".to_string(), Value::Bool(false));
    let env_report = run_negative_case(&root, "resolver-nss-env-divergence", &env_divergence)?;
    expect_failure_signature(&env_report, "environment_divergence")?;

    Ok(())
}
