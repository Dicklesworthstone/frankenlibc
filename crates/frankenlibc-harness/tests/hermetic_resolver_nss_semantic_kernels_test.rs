//! Integration tests for hermetic resolver/NSS semantic kernels (bd-ewv1l).

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
    "kernel_id",
    "scenario_id",
    "runtime_mode",
    "semantic_domain",
    "oracle_kind",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REQUIRED_DOMAINS: &[&str] = &[
    "hosts",
    "services",
    "passwd",
    "group",
    "resolv_conf",
    "nsswitch",
    "dns_cache",
    "dns_timeout",
    "dns_poisoning",
    "search_domain",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/hermetic_resolver_nss_semantic_kernels.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_hermetic_resolver_nss_semantic_kernels.sh")
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

fn mutable_kernels(manifest: &mut Value) -> TestResult<&mut Vec<Value>> {
    manifest
        .get_mut("semantic_kernels")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("manifest.semantic_kernels must be mutable array"))
}

fn run_gate(root: &Path, manifest: Option<&Path>, out_dir: &Path) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(script_path(root))
        .current_dir(root)
        .env("FLC_HERMETIC_RESOLVER_NSS_KERNELS_OUT_DIR", out_dir)
        .env(
            "FLC_HERMETIC_RESOLVER_NSS_KERNELS_REPORT",
            out_dir.join("semantic-kernels.report.json"),
        )
        .env(
            "FLC_HERMETIC_RESOLVER_NSS_KERNELS_LOG",
            out_dir.join("semantic-kernels.log.jsonl"),
        )
        .env("FLC_HERMETIC_RESOLVER_NSS_KERNELS_TARGET_DIR", out_dir);
    if let Some(manifest) = manifest {
        command.env("FLC_HERMETIC_RESOLVER_NSS_KERNELS_MANIFEST", manifest);
    }
    command
        .output()
        .map_err(|err| test_error(format!("failed to run semantic kernel gate: {err}")))
}

fn run_negative_case(root: &Path, case_name: &str, manifest: &Value) -> TestResult<Value> {
    let out_dir = unique_temp_dir(case_name)?;
    let manifest_fixture = out_dir.join(format!("{case_name}.manifest.json"));
    let report_path = out_dir.join("semantic-kernels.report.json");
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
fn manifest_declares_semantic_kernel_contract() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(string_field(&manifest, "schema_version", "manifest")?, "v1");
    assert_eq!(string_field(&manifest, "bead_id", "manifest")?, "bd-ewv1l");
    assert_eq!(
        string_field(&manifest, "gate_id", "manifest")?,
        "hermetic-resolver-nss-semantic-kernels-v1"
    );

    for key in [
        "lab_manifest",
        "lab_runner",
        "resolver_fixture",
        "resolver_nss_hard_parts",
        "oracle_precedence_divergence",
        "user_environment_coverage",
        "resolver_conformance_test",
        "nss_lab_execution_test",
    ] {
        let rel = string_field(field(&manifest, "sources", "manifest")?, key, "sources")?;
        assert!(root.join(rel).exists(), "missing source {key}: {rel}");
    }

    let log_fields = array_field(&manifest, "required_log_fields", "manifest")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_log_fields entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);

    let domains = array_field(&manifest, "required_semantic_domains", "manifest")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_semantic_domains entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?
        .into_iter()
        .collect::<HashSet<_>>();
    assert_eq!(domains, REQUIRED_DOMAINS.iter().copied().collect());

    let kernels = array_field(&manifest, "semantic_kernels", "manifest")?;
    assert!(kernels.len() >= REQUIRED_DOMAINS.len());
    for kernel in kernels {
        for field in [
            "kernel_id",
            "semantic_domain",
            "scenario_id",
            "runtime_modes",
            "oracle_kind",
            "fake_root_file",
            "query",
            "expected",
            "artifact_refs",
        ] {
            assert!(
                kernel.get(field).is_some(),
                "kernel missing {field}: {kernel:#?}"
            );
        }
    }
    Ok(())
}

#[test]
fn gate_runs_lab_and_emits_semantic_logs() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_temp_dir("hermetic-resolver-nss-kernels-pass")?;
    let output = run_gate(&root, None, &out_dir)?;
    assert!(
        output.status.success(),
        "gate should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("semantic-kernels.report.json"))?;
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    let summary = object_field(&report, "summary", "report")?;
    assert_eq!(
        summary
            .get("covered_semantic_domain_count")
            .and_then(Value::as_u64),
        Some(REQUIRED_DOMAINS.len() as u64)
    );
    assert_eq!(
        summary
            .get("semantic_log_row_count")
            .and_then(Value::as_u64),
        Some((REQUIRED_DOMAINS.len() * 2) as u64)
    );
    assert_eq!(
        summary
            .get("real_network_observed")
            .and_then(Value::as_bool),
        Some(false)
    );

    let log = std::fs::read_to_string(out_dir.join("semantic-kernels.log.jsonl"))?;
    let rows = log
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len(), REQUIRED_DOMAINS.len() * 2);
    assert!(rows.iter().any(|row| {
        row.get("kernel_id").and_then(Value::as_str) == Some("services-hermetic-service-tcp")
            && row
                .get("actual")
                .and_then(|actual| actual.get("port"))
                .and_then(Value::as_u64)
                == Some(4242)
    }));
    Ok(())
}

#[test]
fn gate_fails_closed_for_stale_and_missing_artifacts() -> TestResult {
    let root = workspace_root();
    let mut stale = load_json(&manifest_path(&root))?;
    stale["freshness"]["required_source_commit"] = Value::String("not-current".to_string());
    let stale_report = run_negative_case(&root, "hermetic-kernels-stale", &stale)?;
    expect_failure_signature(&stale_report, "stale_artifact")?;

    let mut missing_ref = load_json(&manifest_path(&root))?;
    mutable_kernels(&mut missing_ref)?[0]["artifact_refs"] = Value::Array(vec![Value::String(
        "tests/conformance/does-not-exist.json".to_string(),
    )]);
    let missing_report = run_negative_case(&root, "hermetic-kernels-missing-ref", &missing_ref)?;
    expect_failure_signature(&missing_report, "missing_source_artifact")
}

#[test]
fn gate_fails_closed_for_semantic_drift_and_network_overclaim() -> TestResult {
    let root = workspace_root();

    let mut wrong_addr = load_json(&manifest_path(&root))?;
    mutable_kernels(&mut wrong_addr)?[0]["expected"]["addresses"] =
        Value::Array(vec![Value::String("203.0.113.250".to_string())]);
    let mismatch_report = run_negative_case(&root, "hermetic-kernels-wrong-host", &wrong_addr)?;
    expect_failure_signature(&mismatch_report, "semantic_kernel_mismatch")?;

    let mut missing_domain = load_json(&manifest_path(&root))?;
    mutable_kernels(&mut missing_domain)?
        .retain(|kernel| kernel.get("semantic_domain").and_then(Value::as_str) != Some("services"));
    let missing_domain_report =
        run_negative_case(&root, "hermetic-kernels-missing-domain", &missing_domain)?;
    expect_failure_signature(&missing_domain_report, "missing_semantic_kernel")?;

    let mut real_network = load_json(&manifest_path(&root))?;
    real_network["execution_policy"]["real_network_allowed"] = Value::Bool(true);
    let real_network_report =
        run_negative_case(&root, "hermetic-kernels-real-network", &real_network)?;
    expect_failure_signature(&real_network_report, "real_network_required")
}
