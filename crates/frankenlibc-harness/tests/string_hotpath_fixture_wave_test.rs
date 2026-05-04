//! Integration test: string hot-path fixture wave gate (bd-bp8fl.4.4).

use serde_json::Value;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "family_id",
    "symbol",
    "fixture_id",
    "runner_kind",
    "runtime_mode",
    "oracle_kind",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const FIRST_WAVE_SYMBOLS: &[&str] = &[
    "__memcmpeq",
    "__mempcpy",
    "__rawmemchr",
    "__stpcpy",
    "__stpcpy_small",
    "__stpncpy",
    "__strcasecmp",
    "__strcasecmp_l",
    "__strcasestr",
    "__strcoll_l",
    "__strcpy_small",
    "__strcspn_c1",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path() -> PathBuf {
    workspace_root().join("tests/conformance/string_hotpath_fixture_wave.v1.json")
}

fn script_path() -> PathBuf {
    workspace_root().join("scripts/check_string_hotpath_fixture_wave.sh")
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn unique_temp_dir(name: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| invalid_data(format!("system time before UNIX_EPOCH: {err}")))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("frankenlibc-{name}-{stamp}-{}", std::process::id())))
}

fn run_gate(manifest: Option<&Path>, out_dir: &Path) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(script_path())
        .current_dir(workspace_root())
        .env("FRANKENLIBC_STRING_HOTPATH_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_STRING_HOTPATH_REPORT",
            out_dir.join("string-hotpath.report.json"),
        )
        .env(
            "FRANKENLIBC_STRING_HOTPATH_LOG",
            out_dir.join("string-hotpath.log.jsonl"),
        );
    if let Some(manifest) = manifest {
        command.env("FRANKENLIBC_STRING_HOTPATH_WAVE", manifest);
    }
    Ok(command.output()?)
}

fn field<'a>(value: &'a Value, name: &str) -> TestResult<&'a Value> {
    value
        .get(name)
        .ok_or_else(|| invalid_data(format!("missing JSON field {name:?}")).into())
}

fn field_str<'a>(value: &'a Value, name: &str) -> TestResult<&'a str> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| invalid_data(format!("JSON field {name:?} must be a string")).into())
}

fn field_array<'a>(value: &'a Value, name: &str) -> TestResult<&'a Vec<Value>> {
    field(value, name)?
        .as_array()
        .ok_or_else(|| invalid_data(format!("JSON field {name:?} must be an array")).into())
}

#[test]
fn manifest_records_selected_low_risk_high_count_wave() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    assert_eq!(field_str(&manifest, "schema_version")?, "v1");
    assert_eq!(field_str(&manifest, "bead_id")?, "bd-bp8fl.4.4");
    assert_eq!(
        field_str(&manifest, "campaign_id")?,
        "fcq-string-memory-hotpaths"
    );

    let why = field(&manifest, "why_low_risk_high_count")?;
    assert_eq!(field(why, "prioritizer_rank")?.as_u64(), Some(2));
    assert!(
        field(why, "target_uncovered_before")?.as_u64().unwrap_or(0) >= 100,
        "string wave must be high-count"
    );
    assert_eq!(
        field(why, "implementation_complexity_score")?.as_u64(),
        Some(2)
    );
    assert!(field_array(why, "hard_parts_risk_tags")?.is_empty());

    let covered = field_array(&manifest, "covered_symbols")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid_data("covered symbol must be a string").into())
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(covered, FIRST_WAVE_SYMBOLS);

    let log_fields = field_array(&manifest, "required_log_fields")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid_data("log field must be a string").into())
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);
    Ok(())
}

#[test]
fn gate_passes_and_emits_required_structured_logs() -> TestResult {
    let out_dir = unique_temp_dir("string-hotpath-pass")?;
    let output = run_gate(None, &out_dir)?;
    assert!(
        output.status.success(),
        "gate should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("string-hotpath.report.json"))?;
    assert_eq!(field_str(&report, "status")?, "pass");
    assert_eq!(
        field(&report, "summary")?
            .get("covered_symbol_count")
            .and_then(Value::as_u64),
        Some(FIRST_WAVE_SYMBOLS.len() as u64)
    );
    assert!(field_array(&report, "errors")?.is_empty());

    let log_text = std::fs::read_to_string(out_dir.join("string-hotpath.log.jsonl"))?;
    let rows = log_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(
        rows.len() >= FIRST_WAVE_SYMBOLS.len() * 2,
        "direct and isolated rows must be logged"
    );
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
        assert_eq!(field_str(&row, "bead_id")?, "bd-bp8fl.4.4");
        assert_eq!(field_str(&row, "family_id")?, "string_ops");
        assert_eq!(field_str(&row, "failure_signature")?, "ok");
    }
    Ok(())
}

#[test]
fn gate_fails_closed_on_stale_symbol_coverage_artifact() -> TestResult {
    let out_dir = unique_temp_dir("string-hotpath-stale")?;
    std::fs::create_dir_all(&out_dir)?;

    let root = workspace_root();
    let mut stale_coverage =
        load_json(&root.join("tests/conformance/symbol_fixture_coverage.v1.json"))?;
    let symbols = stale_coverage
        .get_mut("symbols")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid_data("coverage symbols must be an array"))?;
    let mempcpy = symbols
        .iter_mut()
        .find(|row| row.get("symbol").and_then(Value::as_str) == Some("__mempcpy"))
        .ok_or_else(|| invalid_data("__mempcpy coverage row must exist"))?;
    mempcpy
        .as_object_mut()
        .ok_or_else(|| invalid_data("__mempcpy coverage row must be an object"))?
        .insert("covered".to_owned(), Value::Bool(false));
    let stale_coverage_path = out_dir.join("stale-symbol-fixture-coverage.json");
    std::fs::write(
        &stale_coverage_path,
        serde_json::to_string_pretty(&stale_coverage)?,
    )?;

    let mut manifest = load_json(&manifest_path())?;
    manifest
        .get_mut("coverage_artifacts")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid_data("coverage_artifacts must be an object"))?
        .insert(
            "symbol_fixture_coverage".to_owned(),
            Value::String(stale_coverage_path.display().to_string()),
        );
    let stale_manifest_path = out_dir.join("stale-manifest.json");
    std::fs::write(
        &stale_manifest_path,
        serde_json::to_string_pretty(&manifest)?,
    )?;

    let output = run_gate(Some(&stale_manifest_path), &out_dir)?;
    assert!(
        !output.status.success(),
        "gate should fail closed for stale coverage\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&out_dir.join("string-hotpath.report.json"))?;
    assert_eq!(field_str(&report, "status")?, "fail");
    let errors = field_array(&report, "errors")?;
    assert!(
        errors.iter().any(|error| matches!(
            error.as_str(),
            Some(message) if message.contains("stale_artifact") && message.contains("__mempcpy")
        )),
        "stale artifact failure must identify __mempcpy"
    );
    Ok(())
}
