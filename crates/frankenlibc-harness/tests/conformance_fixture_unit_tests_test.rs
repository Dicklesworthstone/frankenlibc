// conformance_fixture_unit_tests_test.rs — bd-2hh.5
// Integration tests for conformance fixture verification and regression detection.

use std::path::Path;
use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> Result<serde_json::Value, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
}

fn run_generator(extra_args: &[&str]) -> Result<std::process::Output, String> {
    let root = repo_root();
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
fn fixture_unit_report_generates_successfully() -> Result<(), String> {
    let root = repo_root();
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
fn fixture_unit_report_schema_complete() -> Result<(), String> {
    let root = repo_root();
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
fn fixture_unit_invalid_fixture_is_reported_deterministically() -> Result<(), String> {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path)?;

    let results = data["fixture_results"].as_array().unwrap();
    assert!(!results.is_empty(), "No fixture results");
    assert_eq!(data["summary"]["invalid_fixture_files"], 0);
    assert_eq!(data["regression_detection"]["status"], "clean");
    assert!(
        data["regression_detection"]["invalid_fixture_files"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let structured = results
        .iter()
        .find(|row| row["file"] == "setjmp_nested_edges.json")
        .ok_or_else(|| String::from("expected setjmp_nested_edges.json to be tracked"))?;
    assert!(structured["valid"].as_bool().unwrap());
    assert!(structured["issues"].as_array().unwrap().is_empty());
    assert!(
        structured["case_count"].as_u64().unwrap() >= 4,
        "structured fixture should synthesize regression cases"
    );
    Ok(())
}

#[test]
fn fixture_unit_determinism_verified() -> Result<(), String> {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path)?;

    assert!(
        data["summary"]["determinism_verified"].as_bool().unwrap(),
        "Fixture parsing not deterministic"
    );
    Ok(())
}

#[test]
fn fixture_unit_regression_baseline_populated() -> Result<(), String> {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path)?;

    let baseline = &data["regression_baseline"];
    let symbol_count = baseline["symbol_count"].as_u64().unwrap();
    assert!(
        symbol_count >= 50,
        "Only {} symbols in baseline (need >= 50)",
        symbol_count
    );

    let symbols = baseline["symbols"].as_object().unwrap();
    for (sym, info) in symbols {
        let count = info["count"].as_u64().unwrap();
        assert!(count > 0, "Symbol {} has 0 cases in baseline", sym);
    }

    let digest = data["regression_detection"]["baseline_fixture_digest"]
        .as_str()
        .unwrap();
    assert_eq!(digest.len(), 64, "baseline digest should be full sha256");
    Ok(())
}

#[test]
fn fixture_unit_all_have_hashes() -> Result<(), String> {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path)?;

    let hashes = data["fixture_hashes"].as_object().unwrap();
    let results = data["fixture_results"].as_array().unwrap();

    assert_eq!(
        hashes.len(),
        results.len(),
        "Hash count doesn't match fixture count"
    );

    for (file, hash) in hashes {
        let h = hash.as_str().unwrap();
        assert!(!h.is_empty(), "Empty hash for fixture {}", file);
    }
    Ok(())
}

#[test]
fn fixture_unit_log_emission_contains_required_fields() -> Result<(), String> {
    let root = repo_root();
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
