// conformance_fixture_unit_tests_test.rs — bd-2hh.5
// Integration tests for conformance fixture verification and regression detection.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

type TestResult<T = ()> = Result<T, String>;

fn repo_root() -> TestResult<PathBuf> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| String::from("crate directory has no workspace parent"))?;
    let root = workspace
        .parent()
        .ok_or_else(|| String::from("workspace directory has no repository parent"))?;
    Ok(root.to_path_buf())
}

fn load_json(path: &Path) -> TestResult<serde_json::Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
}

fn required_array<'a>(
    value: &'a serde_json::Value,
    path: &str,
) -> TestResult<&'a Vec<serde_json::Value>> {
    value
        .as_array()
        .ok_or_else(|| format!("{path} must be an array"))
}

fn required_object<'a>(
    value: &'a serde_json::Value,
    path: &str,
) -> TestResult<&'a serde_json::Map<String, serde_json::Value>> {
    value
        .as_object()
        .ok_or_else(|| format!("{path} must be an object"))
}

fn required_bool(value: &serde_json::Value, path: &str) -> TestResult<bool> {
    value
        .as_bool()
        .ok_or_else(|| format!("{path} must be a boolean"))
}

fn required_u64(value: &serde_json::Value, path: &str) -> TestResult<u64> {
    value
        .as_u64()
        .ok_or_else(|| format!("{path} must be an unsigned integer"))
}

fn required_str<'a>(value: &'a serde_json::Value, path: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| format!("{path} must be a string"))
}

fn run_generator(extra_args: &[&str]) -> TestResult<std::process::Output> {
    let root = repo_root()?;
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let mut args = vec![
        root.join("scripts/generate_conformance_fixture_unit_tests.py")
            .to_string_lossy()
            .into_owned(),
        "-o".to_string(),
        report_path.to_string_lossy().into_owned(),
    ];
    args.extend(extra_args.iter().map(|value| value.to_string()));
    Command::new("python3")
        .args(args)
        .current_dir(&root)
        .output()
        .map_err(|err| format!("failed to execute fixture unit test generator: {err}"))
}

#[test]
fn fixture_unit_report_generates_successfully() -> TestResult {
    let root = repo_root()?;
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let output = run_generator(&[])?;
    assert!(
        output.status.success(),
        "Fixture unit test generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
    Ok(())
}

#[test]
fn fixture_unit_report_schema_complete() -> TestResult {
    let root = repo_root()?;
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path)?;

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-2hh.5"));

    let summary = &data["summary"];
    for field in &[
        "total_fixture_files",
        "valid_fixture_files",
        "invalid_fixture_files",
        "total_cases",
        "total_issues",
        "determinism_verified",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["regression_detection"].is_object());
    assert!(data["fixture_results"].is_array());
    assert!(data["regression_baseline"].is_object());
    assert!(data["fixture_hashes"].is_object());
    Ok(())
}

#[test]
fn fixture_unit_invalid_fixture_is_reported_deterministically() -> TestResult {
    let root = repo_root()?;
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path)?;

    let results = required_array(&data["fixture_results"], "fixture_results")?;
    assert!(!results.is_empty(), "No fixture results");
    assert_eq!(
        required_u64(
            &data["summary"]["invalid_fixture_files"],
            "summary.invalid_fixture_files"
        )?,
        0
    );
    assert_eq!(data["regression_detection"]["status"], "clean");
    assert!(
        required_array(
            &data["regression_detection"]["invalid_fixture_files"],
            "regression_detection.invalid_fixture_files"
        )?
        .is_empty()
    );

    let structured = results
        .iter()
        .find(|row| row["file"] == "setjmp_nested_edges.json")
        .ok_or_else(|| String::from("expected setjmp_nested_edges.json to be tracked"))?;
    assert!(required_bool(
        &structured["valid"],
        "setjmp_nested_edges.valid"
    )?);
    assert!(required_array(&structured["issues"], "setjmp_nested_edges.issues")?.is_empty());
    assert!(
        required_u64(&structured["case_count"], "setjmp_nested_edges.case_count")? >= 4,
        "structured fixture should synthesize regression cases"
    );
    Ok(())
}

#[test]
fn fixture_unit_determinism_verified() -> TestResult {
    let root = repo_root()?;
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path)?;

    assert!(
        required_bool(
            &data["summary"]["determinism_verified"],
            "summary.determinism_verified"
        )?,
        "Fixture parsing not deterministic"
    );
    Ok(())
}

#[test]
fn fixture_unit_regression_baseline_populated() -> TestResult {
    let root = repo_root()?;
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path)?;

    let baseline = &data["regression_baseline"];
    let symbol_count = required_u64(
        &baseline["symbol_count"],
        "regression_baseline.symbol_count",
    )?;
    assert!(
        symbol_count >= 50,
        "Only {} symbols in baseline (need >= 50)",
        symbol_count
    );

    let symbols = required_object(&baseline["symbols"], "regression_baseline.symbols")?;
    for (sym, info) in symbols {
        let count = required_u64(
            &info["count"],
            &format!("regression_baseline.symbols.{sym}.count"),
        )?;
        assert!(count > 0, "Symbol {} has 0 cases in baseline", sym);
    }

    let digest = data["regression_detection"]["baseline_fixture_digest"]
        .as_str()
        .ok_or_else(|| {
            String::from("regression_detection.baseline_fixture_digest must be a string")
        })?;
    assert_eq!(digest.len(), 64, "baseline digest should be full sha256");
    Ok(())
}

#[test]
fn fixture_unit_all_have_hashes() -> TestResult {
    let root = repo_root()?;
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path)?;

    let hashes = required_object(&data["fixture_hashes"], "fixture_hashes")?;
    let results = required_array(&data["fixture_results"], "fixture_results")?;

    assert_eq!(
        hashes.len(),
        results.len(),
        "Hash count doesn't match fixture count"
    );

    for (file, hash) in hashes {
        let h = required_str(hash, &format!("fixture_hashes.{file}"))?;
        assert!(!h.is_empty(), "Empty hash for fixture {}", file);
    }
    Ok(())
}

#[test]
fn fixture_unit_log_emission_contains_required_fields() -> TestResult {
    let root = repo_root()?;
    let log_path = root.join("target/conformance/fixture_unit_tests.log.jsonl");
    let log_path_arg = log_path.to_string_lossy().into_owned();
    let output = run_generator(&[
        "--timestamp",
        "2026-03-19T17:47:00Z",
        "--log",
        log_path_arg.as_str(),
    ])?;
    assert!(
        output.status.success(),
        "Fixture unit test generator with log failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(&log_path)
        .map_err(|err| format!("failed reading {}: {err}", log_path.display()))?;
    let rows: Vec<serde_json::Value> = content
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .map_err(|err| format!("log row should be valid json: {err}; row={line}"))
        })
        .collect::<Result<_, _>>()?;
    assert!(
        rows.len() >= 2,
        "expected per-fixture rows plus summary row in log"
    );

    for row in &rows {
        for field in [
            "timestamp",
            "trace_id",
            "bead_id",
            "scenario_id",
            "mode",
            "api_family",
            "symbol",
            "decision_path",
            "healing_action",
            "errno",
            "latency_ns",
            "artifact_refs",
            "event",
            "outcome",
        ] {
            assert!(row.get(field).is_some(), "missing log field {field}");
        }
        assert_eq!(row["bead_id"], "bd-2hh.5");
        assert_eq!(row["mode"], "fixture_validation");
    }

    let summary = rows
        .iter()
        .find(|row| row["event"] == "fixture_validation_summary")
        .ok_or_else(|| String::from("summary row should be present"))?;
    assert_eq!(summary["outcome"], "clean");
    assert_eq!(summary["invalid_fixture_files"], 0);
    Ok(())
}
