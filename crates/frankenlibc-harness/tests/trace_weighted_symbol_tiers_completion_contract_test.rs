//! Completion contract tests for bd-2vv.10.1.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CONTRACT_REL: &str =
    "tests/conformance/trace_weighted_symbol_tiers_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_trace_weighted_symbol_tiers_completion_contract.sh";
const EXPECTED_COVERAGE: [&str; 3] = [
    "tests.unit.primary",
    "tests.e2e.primary",
    "telemetry.primary",
];
const REQUIRED_TELEMETRY_FIELDS: [&str; 10] = [
    "trace_id",
    "symbol",
    "tier",
    "family",
    "planned_wave",
    "rationale",
    "artifact_refs",
    "failure_signature",
    "latency_ns",
    "source_commit",
];

fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest_dir.parent().ok_or_else(|| {
        std::io::Error::other(format!(
            "{} has no parent directory",
            manifest_dir.display()
        ))
    })?;
    let root = crates_dir.parent().ok_or_else(|| {
        std::io::Error::other(format!("{} has no parent directory", crates_dir.display()))
    })?;
    Ok(root.to_path_buf())
}

fn load_json(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn load_manifest(root: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    load_json(&root.join(CONTRACT_REL))
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, Box<dyn std::error::Error>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array `{key}`").into())
}

fn output_dir(root: &Path, suffix: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let base = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("target"));
    let dir = base
        .join("conformance")
        .join("trace_weighted_symbol_tiers_completion_contract")
        .join(suffix);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(
    root: &Path,
    contract: &Path,
    suffix: &str,
) -> Result<(Output, PathBuf, PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let dir = output_dir(root, suffix)?;
    let generated = dir.join("generated.json");
    let report = dir.join("report.json");
    let log = dir.join("events.jsonl");
    let output = Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .env("TRACE_WEIGHTED_SYMBOL_TIERS_CONTRACT", contract)
        .env("TRACE_WEIGHTED_SYMBOL_TIERS_GENERATED", &generated)
        .env("TRACE_WEIGHTED_SYMBOL_TIERS_REPORT", &report)
        .env("TRACE_WEIGHTED_SYMBOL_TIERS_LOG", &log)
        .output()?;
    Ok((output, generated, report, log))
}

fn read_log_rows(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?)
}

#[test]
fn manifest_binds_unit_e2e_and_telemetry_coverage() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_manifest(&root)?;
    assert_eq!(
        manifest["schema_version"],
        "trace_weighted_symbol_tiers_completion_contract.v1"
    );
    assert_eq!(manifest["bead"], "bd-2vv.10");
    assert_eq!(manifest["completion_debt_bead"], "bd-2vv.10.1");

    let coverage = array(&manifest, "completion_coverage")?;
    for expected in EXPECTED_COVERAGE {
        let section = coverage
            .iter()
            .find(|item| item["missing_item_id"] == expected)
            .ok_or_else(|| format!("missing coverage for {expected}"))?;
        assert_eq!(section["status"], "covered");
        assert!(
            section
                .get("implementation_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| !refs.is_empty()),
            "{expected} must cite implementation refs"
        );
        assert!(
            section
                .get("test_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| !refs.is_empty()),
            "{expected} must cite test refs"
        );
    }

    let telemetry = &manifest["telemetry_contract"];
    for field in REQUIRED_TELEMETRY_FIELDS {
        let fields = telemetry["required_fields"]
            .as_array()
            .ok_or("telemetry required_fields must be an array")?;
        assert!(
            fields.iter().any(|value| value.as_str() == Some(field)),
            "telemetry contract missing {field}"
        );
    }

    for reference in array(&manifest, "implementation_refs")? {
        let path = reference["path"]
            .as_str()
            .ok_or("implementation ref path must be a string")?;
        let line = reference["line"]
            .as_u64()
            .ok_or("implementation ref line must be an integer")?;
        let anchor = reference["anchor"]
            .as_str()
            .ok_or("implementation ref anchor must be a string")?;
        let text = std::fs::read_to_string(root.join(path))?;
        assert!(
            (1..=text.lines().count() as u64).contains(&line),
            "{path}:{line} outside file"
        );
        assert!(text.contains(anchor), "{path} missing anchor {anchor}");
    }

    Ok(())
}

#[test]
fn checker_emits_report_and_symbol_telemetry_rows() -> TestResult {
    let root = workspace_root()?;
    let contract = root.join(CONTRACT_REL);
    let (output, generated_path, report_path, log_path) =
        run_checker(&root, &contract, "positive")?;
    assert!(
        output.status.success(),
        "checker failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let generated = load_json(&generated_path)?;
    let report = load_json(&report_path)?;
    assert_eq!(report["status"], "pass");
    assert_eq!(report["failure_signature"], "none");
    assert_eq!(report["roadmap_hash"], generated["roadmap_hash"]);
    assert_eq!(report["summary"]["missing_items_covered"], 3);
    assert!(
        report["symbol_count"]
            .as_u64()
            .is_some_and(|count| count >= 100),
        "generated roadmap should cover at least 100 symbols"
    );

    let rows = read_log_rows(&log_path)?;
    assert!(rows.len() >= 3, "expected sample symbol telemetry rows");
    for row in rows {
        assert_eq!(row["event"], "trace_weighted_symbol_tier_validated");
        assert_eq!(row["outcome"], "pass");
        assert_eq!(row["failure_signature"], "none");
        for field in REQUIRED_TELEMETRY_FIELDS {
            assert!(row.get(field).is_some(), "log row missing {field}");
        }
        assert!(row["tier"].as_str().is_some_and(|tier| !tier.is_empty()));
        assert!(
            row["family"]
                .as_str()
                .is_some_and(|family| !family.is_empty())
        );
        assert!(row["planned_wave"].as_u64().is_some());
        assert!(
            row["rationale"]
                .as_str()
                .is_some_and(|rationale| !rationale.is_empty())
        );
        let serialized = serde_json::to_string(&row)?;
        validate_log_line(&serialized, 1).map_err(|errors| {
            std::io::Error::other(format!("checker log row failed validation: {errors:?}"))
        })?;
    }

    Ok(())
}

#[test]
fn checker_fails_closed_when_telemetry_coverage_is_removed() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_manifest(&root)?;
    let coverage = manifest["completion_coverage"]
        .as_array_mut()
        .ok_or("completion_coverage must be an array")?;
    coverage.retain(|item| item["missing_item_id"] != "telemetry.primary");
    let telemetry_fields = manifest["telemetry_contract"]["required_fields"]
        .as_array_mut()
        .ok_or("telemetry required_fields must be an array")?;
    telemetry_fields.retain(|item| item.as_str() != Some("tier"));

    let dir = output_dir(&root, "negative")?;
    let bad_manifest = dir.join("missing_telemetry.json");
    std::fs::write(&bad_manifest, serde_json::to_string_pretty(&manifest)?)?;

    let (output, _generated_path, report_path, log_path) =
        run_checker(&root, &bad_manifest, "negative")?;
    assert!(
        !output.status.success(),
        "checker must fail closed when telemetry coverage is incomplete"
    );
    let report = load_json(&report_path)?;
    assert_eq!(report["status"], "fail");
    assert_eq!(
        report["failure_signature"],
        "trace_weighted_symbol_tiers_contract_invalid"
    );
    let errors = report["errors"]
        .as_array()
        .ok_or("failure report should carry errors")?;
    assert!(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains("telemetry.primary")),
        "failure should mention missing telemetry coverage"
    );
    assert!(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains("tier")),
        "failure should mention missing telemetry tier field"
    );

    let rows = read_log_rows(&log_path)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["event"],
        "trace_weighted_symbol_tiers_completion_contract_failed"
    );
    assert_eq!(
        rows[0]["failure_signature"],
        "trace_weighted_symbol_tiers_contract_invalid"
    );

    Ok(())
}
