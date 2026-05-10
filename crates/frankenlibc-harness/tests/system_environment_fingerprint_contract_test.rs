//! Conformance gate for the system environment fingerprint helper
//! (bd-6epxt).
//!
//! Validates the manifest schema + exercises the renderer / parser
//! / detector against a synthetic Components round-trip and several
//! parser-rejection paths.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use frankenlibc_harness::system_fingerprint::{
    ENV_FINGERPRINT_ERROR_KINDS, EnvFingerprintError, EnvironmentFingerprintComponents,
    detect_components, environment_fingerprint, from_components, validate_environment_fingerprint,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("system_environment_fingerprint_contract.v1.json")
}

fn load_manifest() -> TestResult<Value> {
    let root = workspace_root()?;
    let path = manifest_path(&root);
    let content = std::fs::read_to_string(&path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn json_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Value> {
    value.get(field).ok_or_else(|| format!("missing `{field}`"))
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    json_field(value, field)?
        .as_str()
        .ok_or_else(|| format!("`{field}` must be a string"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    json_field(value, field)?
        .as_array()
        .ok_or_else(|| format!("`{field}` must be an array"))
}

fn json_bool(value: &Value, field: &str) -> TestResult<bool> {
    json_field(value, field)?
        .as_bool()
        .ok_or_else(|| format!("`{field}` must be a bool"))
}

#[test]
fn manifest_anchors_to_6epxt_with_format_template() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "manifest_id")? == "system-environment-fingerprint-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-6epxt", "bead")?;
    let format = json_field(&m, "format")?;
    require(
        json_string(format, "template")? == "<os>-<arch>-<cpus>cpu-<kernel_release>",
        "template",
    )?;
    Ok(())
}

#[test]
fn manifest_function_paths_match_lib_surface() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "validator_function")?
            == "frankenlibc_harness::system_fingerprint::validate_environment_fingerprint",
        "validator_function",
    )?;
    require(
        json_string(&m, "renderer_function")?
            == "frankenlibc_harness::system_fingerprint::from_components",
        "renderer_function",
    )?;
    require(
        json_string(&m, "detector_function")?
            == "frankenlibc_harness::system_fingerprint::environment_fingerprint",
        "detector_function",
    )
}

#[test]
fn manifest_rejected_evidence_kinds_match_lib_const() -> TestResult {
    let m = load_manifest()?;
    let manifest_kinds: BTreeSet<&str> = json_array(&m, "rejected_evidence_kinds")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let lib_kinds: BTreeSet<&str> = ENV_FINGERPRINT_ERROR_KINDS.iter().copied().collect();
    require(
        manifest_kinds == lib_kinds,
        format!(
            "manifest rejected_evidence_kinds must match ENV_FINGERPRINT_ERROR_KINDS; lib={lib_kinds:?}, manifest={manifest_kinds:?}"
        ),
    )
}

#[test]
fn manifest_env_override_pins_var_name() -> TestResult {
    let m = load_manifest()?;
    let ov = json_field(&m, "env_override")?;
    require(
        json_string(ov, "var_name")? == "FRANKENLIBC_ENV_FINGERPRINT",
        "var_name",
    )
}

#[test]
fn manifest_policy_fails_closed_on_required_kinds() -> TestResult {
    let m = load_manifest()?;
    let policy = json_field(&m, "policy")?;
    for f in [
        "fail_closed_when_format_invalid",
        "fail_closed_when_component_empty",
        "fail_closed_when_cpu_count_non_numeric",
        "rejected_evidence_kinds_must_match_lib_const",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn round_trip_preserves_components() -> TestResult {
    let c = EnvironmentFingerprintComponents {
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        cpus: 64,
        kernel_release: "6.1.0-25-amd64".to_string(),
    };
    let s = from_components(&c);
    let parsed = validate_environment_fingerprint(&s).map_err(|e| format!("{e}"))?;
    require(parsed == c, format!("round trip failed: {parsed:?}"))
}

#[test]
fn validator_rejects_invalid_format() -> TestResult {
    match validate_environment_fingerprint("only-three-segments") {
        Err(EnvFingerprintError::InvalidFormat) => Ok(()),
        other => Err(format!("expected InvalidFormat; got {other:?}")),
    }
}

#[test]
fn validator_rejects_non_numeric_cpu_count() -> TestResult {
    match validate_environment_fingerprint("linux-x86_64-NaNcpu-6.1") {
        Err(EnvFingerprintError::InvalidCpuCount(_)) => Ok(()),
        other => Err(format!("expected InvalidCpuCount; got {other:?}")),
    }
}

#[test]
fn detector_returns_round_trippable_fingerprint_in_no_override_environment() -> TestResult {
    if std::env::var("FRANKENLIBC_ENV_FINGERPRINT").is_ok() {
        // Skip — there's an override in this env.
        return Ok(());
    }
    let s = environment_fingerprint();
    let parsed = validate_environment_fingerprint(&s).map_err(|e| format!("{e}"))?;
    require(!parsed.os.is_empty(), "os")?;
    require(!parsed.arch.is_empty(), "arch")?;
    require(!parsed.kernel_release.is_empty(), "kernel_release")
}

#[test]
fn detect_components_returns_expected_os_on_linux() -> TestResult {
    if !cfg!(target_os = "linux") {
        return Ok(());
    }
    let c = detect_components();
    require(c.os == "linux", format!("expected linux, got {}", c.os))
}
