//! Integration tests for loader/dlfcn hard-parts fixtures (bd-bp8fl.5.4).

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
    "shared_object",
    "symbol",
    "version_node",
    "replacement_level",
    "runtime_mode",
    "oracle_kind",
    "expected_status",
    "actual_status",
    "loader_error",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REQUIRED_FIXTURE_KINDS: &[&str] = &[
    "dlopen_success",
    "dlopen_failure",
    "dlsym_version_lookup",
    "tls_symbol_access",
    "relocation_startup",
    "missing_symbol",
    "audit_boundary",
    "dlclose_error",
];

const REQUIRED_SYMBOLS: &[&str] = &[
    "dlopen",
    "dlsym",
    "dlvsym",
    "dlclose",
    "dlerror",
    "__call_tls_dtors",
    "relocation_startup",
    "ld_audit",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/loader_dlfcn_relocation_tls_audit.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_loader_dlfcn_relocation_tls_audit.sh")
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

fn run_gate(root: &Path, manifest: Option<&Path>, out_dir: &Path) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(script_path(root))
        .current_dir(root)
        .env("FLC_LOADER_DLFCN_OUT_DIR", out_dir)
        .env(
            "FLC_LOADER_DLFCN_REPORT",
            out_dir.join("loader-dlfcn.report.json"),
        )
        .env(
            "FLC_LOADER_DLFCN_LOG",
            out_dir.join("loader-dlfcn.log.jsonl"),
        )
        .env("FLC_LOADER_DLFCN_TARGET_DIR", out_dir);
    if let Some(manifest) = manifest {
        command.env("FLC_LOADER_DLFCN_MANIFEST", manifest);
    }
    command
        .output()
        .map_err(|err| test_error(format!("failed to run loader/dlfcn gate: {err}")))
}

fn run_negative_case(root: &Path, case_name: &str, manifest: &Value) -> TestResult<Value> {
    let out_dir = unique_temp_dir(case_name)?;
    let manifest_fixture = out_dir.join(format!("{case_name}.manifest.json"));
    let report_path = out_dir.join("loader-dlfcn.report.json");
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
fn manifest_defines_loader_dlfcn_schema_and_required_coverage() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(string_field(&manifest, "schema_version", "manifest")?, "v1");
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-bp8fl.5.4"
    );
    assert_eq!(
        string_field(&manifest, "gate_id", "manifest")?,
        "loader-dlfcn-relocation-tls-audit-v1"
    );

    for key in [
        "dlfcn_abi",
        "version_script",
        "dlfcn_fixture",
        "dlfcn_boundary_policy",
        "oracle_precedence_divergence",
        "replacement_levels",
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

    let fixture_kinds: HashSet<_> = array_field(&manifest, "required_fixture_kinds", "manifest")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_fixture_kinds entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?
        .into_iter()
        .collect();
    assert_eq!(
        fixture_kinds,
        REQUIRED_FIXTURE_KINDS.iter().copied().collect()
    );

    let symbols: HashSet<_> = array_field(&manifest, "required_symbols", "manifest")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_symbols entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?
        .into_iter()
        .collect();
    assert_eq!(symbols, REQUIRED_SYMBOLS.iter().copied().collect());

    let rows = array_field(&manifest, "fixture_rows", "manifest")?;
    assert!(rows.len() >= REQUIRED_FIXTURE_KINDS.len());
    for row in rows {
        for field in [
            "fixture_id",
            "fixture_kind",
            "shared_object",
            "symbol",
            "version_node",
            "relocation_kind",
            "tls_use",
            "dl_sequence",
            "runtime_mode",
            "replacement_level",
            "oracle_kind",
            "expected",
            "artifact_refs",
            "source_commit_state",
            "direct_runner",
            "isolated_runner",
        ] {
            assert!(row.get(field).is_some(), "row missing {field}: {row:#?}");
        }
        let expected = object_field(row, "expected", "row")?;
        for field in ["status", "errno", "loader_error", "user_diagnostic"] {
            assert!(expected.get(field).is_some(), "expected missing {field}");
        }
    }
    Ok(())
}

#[test]
fn gate_emits_pass_report_and_structured_logs() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_temp_dir("loader-dlfcn-pass")?;
    let output = run_gate(&root, None, &out_dir)?;
    assert!(
        output.status.success(),
        "gate should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("loader-dlfcn.report.json"))?;
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    let summary = object_field(&report, "summary", "report")?;
    assert_eq!(
        summary
            .get("covered_fixture_kind_count")
            .and_then(Value::as_u64),
        Some(REQUIRED_FIXTURE_KINDS.len() as u64)
    );
    assert_eq!(
        summary.get("covered_symbol_count").and_then(Value::as_u64),
        Some(REQUIRED_SYMBOLS.len() as u64)
    );
    assert_eq!(
        summary.get("runtime_mode_count").and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        summary.get("isolated_runner_count").and_then(Value::as_u64),
        Some(8)
    );

    let log = std::fs::read_to_string(out_dir.join("loader-dlfcn.log.jsonl"))?;
    let rows = log
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len(), 8);
    assert!(rows.iter().any(|row| {
        row.get("fixture_id").and_then(Value::as_str) == Some("loader.audit.boundary.hardened")
            && row.get("loader_error").and_then(Value::as_str) == Some("unsupported_audit_boundary")
    }));
    Ok(())
}

#[test]
fn gate_rejects_stale_artifact_and_missing_artifact_ref() -> TestResult {
    let root = workspace_root();
    let mut stale = load_json(&manifest_path(&root))?;
    stale["freshness"]["required_source_commit"] = Value::String("not-current".to_string());
    let stale_report = run_negative_case(&root, "loader-dlfcn-stale", &stale)?;
    expect_failure_signature(&stale_report, "stale_artifact")?;

    let mut missing_ref = load_json(&manifest_path(&root))?;
    mutable_rows(&mut missing_ref)?[0]["artifact_refs"] = Value::Array(vec![Value::String(
        "tests/conformance/does-not-exist.json".to_string(),
    )]);
    let missing_report = run_negative_case(&root, "loader-dlfcn-missing-ref", &missing_ref)?;
    expect_failure_signature(&missing_report, "missing_source_artifact")
}

#[test]
fn gate_rejects_missing_kind_bad_error_and_audit_overclaim() -> TestResult {
    let root = workspace_root();

    let mut missing_kind = load_json(&manifest_path(&root))?;
    mutable_rows(&mut missing_kind)?
        .retain(|row| row.get("fixture_kind").and_then(Value::as_str) != Some("tls_symbol_access"));
    let missing_kind_report = run_negative_case(&root, "loader-dlfcn-missing-kind", &missing_kind)?;
    expect_failure_signature(&missing_kind_report, "missing_fixture_kind")?;

    let mut bad_error = load_json(&manifest_path(&root))?;
    mutable_rows(&mut bad_error)?[1]["expected"]["loader_error"] =
        Value::String("none".to_string());
    let bad_error_report = run_negative_case(&root, "loader-dlfcn-bad-error", &bad_error)?;
    expect_failure_signature(&bad_error_report, "loader_error_normalization")?;

    let mut audit_overclaim = load_json(&manifest_path(&root))?;
    for row in mutable_rows(&mut audit_overclaim)? {
        if row.get("fixture_kind").and_then(Value::as_str) == Some("audit_boundary") {
            row["expected"]["status"] = Value::String("pass".to_string());
            row["expected"]["loader_error"] = Value::String("none".to_string());
        }
    }
    let audit_report = run_negative_case(&root, "loader-dlfcn-audit-overclaim", &audit_overclaim)?;
    expect_failure_signature(&audit_report, "unsupported_relocation_or_audit")
}
