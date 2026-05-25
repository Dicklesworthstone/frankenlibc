//! WS-8.3 distribution packaging contract tests.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "timestamp",
    "trace_id",
    "bead_id",
    "event",
    "status",
    "claim_status",
    "package_path",
    "install_root",
    "artifact_path",
    "artifact_refs",
    "failure_signature",
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

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/distribution_packaging_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_distribution_packaging_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let mut rows = Vec::new();
    for line in std::fs::read_to_string(path)?.lines() {
        if !line.trim().is_empty() {
            rows.push(serde_json::from_str(line)?);
        }
    }
    Ok(rows)
}

fn unique_dir(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root
        .join("target/conformance")
        .join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn string_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("missing string field {field}")))
}

fn array_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("missing array field {field}")))
}

fn command_available(name: &str) -> bool {
    Command::new(name).arg("--version").output().is_ok()
}

fn build_fixture_library(dir: &Path, name: &str) -> TestResult<Option<PathBuf>> {
    if !command_available("cc") {
        eprintln!("skipping fixture build: cc is not available");
        return Ok(None);
    }
    let source = dir.join("fixture.c");
    let output = dir.join(name);
    std::fs::write(
        &source,
        r#"
int __libc_start_main(void) { return 0; }
void *malloc(unsigned long size) { (void)size; return 0; }
void free(void *ptr) { (void)ptr; }
int printf(const char *fmt, ...) { (void)fmt; return 0; }
"#,
    )?;
    let status = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg("-Wl,-soname,libfrankenlibc_replace.so")
        .arg("-o")
        .arg(&output)
        .arg(&source)
        .status()?;
    if !status.success() {
        return Err(test_error(format!("cc fixture build failed with {status}")));
    }
    Ok(Some(output))
}

fn run_checker(
    root: &Path,
    source_artifact: &Path,
    out_dir: &Path,
) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_DISTRIBUTION_PACKAGE_CONTRACT",
            manifest_path(root),
        )
        .env("FRANKENLIBC_DISTRIBUTION_SOURCE_LIB", source_artifact)
        .env("FRANKENLIBC_DISTRIBUTION_PACKAGE_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_DISTRIBUTION_PACKAGE_REPORT",
            out_dir.join("distribution_packaging_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_DISTRIBUTION_PACKAGE_LOG",
            out_dir.join("distribution_packaging_contract.log.jsonl"),
        )
        .output()?)
}

#[test]
fn manifest_anchors_ws8_distribution_packaging_contract() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version")?,
        "distribution_packaging_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "manifest_id")?,
        "ws8-distribution-packaging-contract"
    );
    assert_eq!(string_field(&manifest, "bead")?, "bd-38x82.3");
    assert_eq!(string_field(&manifest, "parent_bead")?, "bd-38x82");
    assert!(
        array_field(&manifest, "prerequisite_beads")?
            .iter()
            .any(|value| value.as_str() == Some("bd-38x82.1"))
    );
    assert_eq!(
        string_field(
            manifest
                .get("evidence")
                .ok_or_else(|| test_error("missing evidence"))?,
            "checker"
        )?,
        "scripts/check_distribution_packaging_contract.sh"
    );
    Ok(())
}

#[test]
fn manifest_declares_real_debian_package_install_contract() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let package = manifest
        .get("package")
        .ok_or_else(|| test_error("missing package"))?;
    assert_eq!(string_field(package, "format")?, "deb");
    assert_eq!(string_field(package, "distribution_family")?, "Debian");
    assert_eq!(
        string_field(package, "installed_artifact")?,
        "/usr/lib/frankenlibc/libfrankenlibc_replace.so"
    );
    assert_eq!(
        package.get("system_paths_touched").and_then(Value::as_bool),
        Some(false)
    );
    assert!(
        string_field(package, "install_method")?.contains("dpkg --root=<isolated-root>"),
        "install method must use an isolated dpkg root"
    );

    let smoke = manifest
        .get("smoke_battery")
        .ok_or_else(|| test_error("missing smoke_battery"))?;
    for required in [
        "package_built",
        "dpkg_isolated_install",
        "installed_prefix_artifact_present",
        "installed_artifact_has_required_symbols",
    ] {
        assert!(
            array_field(smoke, "required_checks")?
                .iter()
                .any(|value| value.as_str() == Some(required)),
            "missing smoke check {required}"
        );
    }
    Ok(())
}

#[test]
fn checker_accepts_fixture_package_and_emits_prefix_smoke_evidence() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_dir(&root, "distribution-packaging-ok")?;
    let fixture_dir = out_dir.join("fixture");
    std::fs::create_dir_all(&fixture_dir)?;
    let Some(artifact) = build_fixture_library(&fixture_dir, "libfrankenlibc_replace.so")? else {
        return Ok(());
    };

    let output = run_checker(&root, &artifact, &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("distribution_packaging_contract.report.json"))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        string_field(&report, "claim_status")?,
        "distribution_package_passed"
    );
    let package = report
        .get("package")
        .ok_or_else(|| test_error("missing package report"))?;
    assert!(root.join(string_field(package, "path")?).is_file());
    assert!(
        root.join(string_field(package, "installed_artifact")?)
            .is_file()
    );
    assert_eq!(
        package.get("system_paths_touched").and_then(Value::as_bool),
        Some(false)
    );

    let rows = load_jsonl(&out_dir.join("distribution_packaging_contract.log.jsonl"))?;
    assert!(
        rows.iter()
            .any(|row| row.get("event").and_then(Value::as_str)
                == Some("distribution_packaging_prefix_smoke"))
    );
    for row in &rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}: {row}");
        }
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_source_artifact() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_dir(&root, "distribution-packaging-missing")?;
    let missing = out_dir.join("libfrankenlibc_replace.so");
    let output = run_checker(&root, &missing, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing artifact"
    );
    let report = load_json(&out_dir.join("distribution_packaging_contract.report.json"))?;
    assert_eq!(string_field(&report, "status")?, "fail");
    assert!(
        report
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(|errors| errors
                .iter()
                .any(|error| error.as_str() == Some("missing_source_artifact")))
    );
    Ok(())
}

#[test]
fn checker_rejects_wrong_artifact_name() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_dir(&root, "distribution-packaging-wrong-name")?;
    let fixture_dir = out_dir.join("fixture");
    std::fs::create_dir_all(&fixture_dir)?;
    let Some(artifact) = build_fixture_library(&fixture_dir, "libnotfrankenlibc.so")? else {
        return Ok(());
    };

    let output = run_checker(&root, &artifact, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject wrong artifact name"
    );
    let report = load_json(&out_dir.join("distribution_packaging_contract.report.json"))?;
    assert_eq!(string_field(&report, "status")?, "fail");
    assert!(
        report
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(|errors| errors.iter().any(|error| error
                .as_str()
                .is_some_and(|message| message.contains("wrong_source_artifact_name"))))
    );
    Ok(())
}

#[test]
fn checker_rejects_empty_artifact() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_dir(&root, "distribution-packaging-empty")?;
    let artifact = out_dir.join("libfrankenlibc_replace.so");
    std::fs::write(&artifact, Vec::<u8>::new())?;
    let output = run_checker(&root, &artifact, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject empty artifact"
    );
    let report = load_json(&out_dir.join("distribution_packaging_contract.report.json"))?;
    assert_eq!(string_field(&report, "status")?, "fail");
    assert!(
        report
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(|errors| errors.iter().any(|error| error
                .as_str()
                .is_some_and(|message| message.contains("empty_source_artifact"))))
    );
    Ok(())
}
