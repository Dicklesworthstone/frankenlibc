//! Completion-contract tests for bd-w2c3.10.3.1 closure sweep evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str = "tests/conformance/closure_sweep_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_closure_sweep_completion_contract.sh";
const CLOSURE_REPORT_REL: &str = "tests/conformance/closure_sweep_report.v1.json";
const DOCS_MAP_REL: &str = "tests/conformance/docs_source_of_truth_map.v1.json";
const DOCS_TRACE_REL: &str = "tests/conformance/docs_source_of_truth_trace.v1.jsonl";
const EXPECTED_MISSING_ITEMS: &[&str] = &["tests.unit.primary", "tests.e2e.primary"];
const EXPECTED_SURFACES: &[&str] = &[
    "README",
    "ARCHITECTURE",
    "DEPLOYMENT",
    "SECURITY",
    "API",
    "TROUBLESHOOTING",
];
const EXPECTED_EVENTS: &[&str] = &[
    "closure_sweep_completion_contract_validated",
    "closure_sweep_report_validated",
    "docs_source_of_truth_validated",
    "docs_source_gate_replayed",
    "closure_sweep_completion_summary",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("manifest should have a crates parent"))?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| io::Error::other("manifest should live under workspace root"))?;
    Ok(root.to_path_buf())
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn workspace_relative_path(root: &Path, path: &str) -> TestResult<PathBuf> {
    let relative = Path::new(path);
    let has_escape = relative.is_absolute()
        || relative
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)));
    if has_escape {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("path must stay under workspace root: {path}"),
        )
        .into());
    }
    Ok(root.join(relative))
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string array"))?;
    let mut set = BTreeSet::new();
    for item in array {
        set.insert(
            item.as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))?
                .to_string(),
        );
    }
    Ok(set)
}

fn assert_file_line_ref_exists(root: &Path, ref_obj: &Value) -> TestResult {
    let path = ref_obj["path"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref path missing"))?;
    let line = ref_obj["line"]
        .as_u64()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref line missing"))?;
    let anchor = ref_obj["anchor"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref anchor missing"))?;
    assert!(line > 0, "line must be positive for {path}");
    let full_path = workspace_relative_path(root, path)?;
    assert!(full_path.exists(), "ref path should exist: {path}");
    if full_path.is_file() {
        let text = std::fs::read_to_string(&full_path)?;
        let lines: Vec<_> = text.lines().collect();
        assert!(
            (line as usize) <= lines.len() && !lines[line as usize - 1].trim().is_empty(),
            "ref line outside file or blank: {path}:{line}"
        );
        assert!(text.contains(anchor), "{path} missing anchor {anchor}");
    }
    Ok(())
}

fn function_exists(source_text: &str, name: &str) -> bool {
    source_text.contains(&format!("fn {name}")) || source_text.contains(&format!("def {name}"))
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = root.join("target/conformance").join(format!(
        "closure-sweep-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env("FRANKENLIBC_CLOSURE_SWEEP_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_CLOSURE_SWEEP_REPORT",
            root.join(CLOSURE_REPORT_REL),
        )
        .env(
            "FRANKENLIBC_CLOSURE_SWEEP_DOCS_MAP",
            root.join(DOCS_MAP_REL),
        )
        .env(
            "FRANKENLIBC_CLOSURE_SWEEP_DOCS_TRACE",
            root.join(DOCS_TRACE_REL),
        )
        .env("FRANKENLIBC_CLOSURE_SWEEP_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_CLOSURE_SWEEP_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_CLOSURE_SWEEP_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()?)
}

#[test]
fn manifest_binds_unit_and_e2e_completion_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("closure_sweep_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-w2c3.10.3"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-w2c3.10.3.1")
    );
    assert!(
        manifest["next_audit_score_threshold"]
            .as_u64()
            .unwrap_or_default()
            >= 800
    );

    let audit_items = string_set(&manifest["audit"]["missing_items"])?;
    assert_eq!(
        audit_items,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    let source_paths = manifest["source_paths"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_paths missing"))?;
    for path in source_paths.values() {
        let rel = path.as_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "source path must be string")
        })?;
        assert!(
            workspace_relative_path(&root, rel)?.exists(),
            "source path should exist: {rel}"
        );
    }

    let refs = manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation refs"))?;
    assert!(refs.len() >= 30, "expected concrete implementation refs");
    for ref_obj in refs {
        assert_file_line_ref_exists(&root, ref_obj)?;
    }

    let coverage = manifest["completion_coverage"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "completion_coverage"))?;
    let covered_items = coverage
        .iter()
        .map(|section| {
            section["missing_item_id"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        covered_items,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    let mut source_texts = std::collections::BTreeMap::new();
    for section in coverage {
        assert_eq!(section["status"].as_str(), Some("covered"));
        assert!(
            section["implementation_refs"]
                .as_array()
                .is_some_and(|refs| !refs.is_empty()),
            "coverage section should cite implementation refs"
        );
        let test_refs = section["test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "coverage test_refs"))?;
        assert!(!test_refs.is_empty(), "coverage section should cite tests");
        for command in section["validation_commands"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "validation commands"))?
            .iter()
            .filter_map(Value::as_str)
        {
            if command.contains("cargo ") {
                assert!(command.contains("rch "), "cargo command must use rch");
                assert!(
                    command.contains("CARGO_TARGET_DIR="),
                    "cargo command must use isolated target dir"
                );
            }
        }
        for test_ref in test_refs {
            let source = test_ref["source"].as_str().unwrap_or_default();
            let name = test_ref["name"].as_str().unwrap_or_default();
            let rel = source_paths[source].as_str().unwrap_or_default();
            let source_text = match source_texts.entry(source.to_string()) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(std::fs::read_to_string(root.join(rel))?)
                }
            };
            assert!(
                function_exists(source_text, name),
                "test ref should exist: {rel}::{name}"
            );
        }
    }
    Ok(())
}

#[test]
fn closure_report_contract_pins_unresolved_gap_summary() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;
    let report = read_json(&root.join(CLOSURE_REPORT_REL))?;
    let contract = &manifest["closure_sweep_contract"];

    assert_eq!(
        report["schema_version"].as_str(),
        contract["expected_schema_version"].as_str()
    );
    assert_eq!(report["bead"].as_str(), Some("bd-w2c3.10.3"));
    assert_eq!(
        report["status"].as_str(),
        contract["expected_status"].as_str()
    );

    let summary = &report["summary"];
    assert_eq!(
        summary["errors"].as_u64(),
        contract["expected_error_count"].as_u64()
    );
    assert_eq!(
        summary["warnings"].as_u64(),
        contract["expected_warning_count"].as_u64()
    );
    assert_eq!(
        summary["total_findings"].as_u64(),
        contract["expected_total_findings"].as_u64()
    );
    assert_eq!(
        summary["callthrough_remaining"].as_u64(),
        contract["expected_callthrough_remaining"].as_u64()
    );
    assert_eq!(
        summary["open_gap_beads"].as_u64(),
        contract["expected_open_gap_beads"].as_u64()
    );
    assert_eq!(
        summary["closure_ready"].as_bool(),
        contract["expected_closure_ready"].as_bool()
    );
    assert_eq!(
        report["drift_gates_status"].as_str(),
        contract["expected_drift_gates_status"].as_str()
    );

    let non_closure = report["non_closure_reasons"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non_closure_reasons"))?;
    let categories = non_closure
        .iter()
        .filter_map(|row| row["category"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        categories,
        string_set(&contract["required_non_closure_categories"])?
    );

    let fixture_reason = non_closure
        .iter()
        .find(|row| row["category"].as_str() == Some("fixture_coverage"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "fixture reason missing"))?;
    assert_eq!(
        string_set(&fixture_reason["modules"])?,
        string_set(&contract["expected_uncovered_zero_modules"])?
    );
    assert_eq!(
        report["callthrough_gaps"]["total_callthrough"].as_u64(),
        Some(0)
    );
    assert_eq!(report["open_gap_beads"]["count"].as_u64(), Some(0));
    Ok(())
}

#[test]
fn docs_truth_contract_covers_fresh_governance_trace() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;
    let source_map = read_json(&root.join(DOCS_MAP_REL))?;
    let trace_rows = read_jsonl(&root.join(DOCS_TRACE_REL))?;
    let contract = &manifest["docs_truth_contract"];

    assert_eq!(
        source_map["bead"].as_str(),
        contract["expected_bead"].as_str()
    );
    let summary = &source_map["summary"];
    assert_eq!(
        summary["surface_count"].as_u64(),
        contract["expected_surface_count"].as_u64()
    );
    assert_eq!(
        summary["section_count"].as_u64(),
        contract["expected_section_count"].as_u64()
    );
    assert_eq!(
        summary["fresh_section_count"].as_u64(),
        contract["expected_fresh_section_count"].as_u64()
    );
    assert_eq!(
        summary["missing_section_count"].as_u64(),
        contract["expected_missing_section_count"].as_u64()
    );

    let surfaces = source_map["surfaces"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "surfaces"))?;
    let actual_surfaces = surfaces
        .iter()
        .filter_map(|surface| surface["surface_id"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_surfaces,
        EXPECTED_SURFACES
            .iter()
            .map(|surface| (*surface).to_string())
            .collect()
    );

    let mut section_count = 0usize;
    for surface in surfaces {
        let surface_id = surface["surface_id"].as_str().unwrap_or("<unknown>");
        assert_eq!(
            surface["freshness_status"].as_str(),
            contract["expected_freshness_status"].as_str(),
            "{surface_id}: freshness_status"
        );
        assert!(
            surface["missing_inputs"]
                .as_array()
                .is_some_and(Vec::is_empty),
            "{surface_id}: missing_inputs must be empty"
        );
        let sections = surface["sections"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "sections"))?;
        section_count += sections.len();
        for section in sections {
            for key in [
                "owner",
                "review_policy",
                "backing_paths",
                "source_artifacts",
                "update_triggers",
            ] {
                assert!(
                    !section[key].is_null(),
                    "{surface_id}/{} missing {key}",
                    section["section_id"].as_str().unwrap_or("<unknown>")
                );
            }
            assert_eq!(
                section["freshness_status"].as_str(),
                contract["expected_freshness_status"].as_str()
            );
            assert!(
                section["missing_inputs"]
                    .as_array()
                    .is_some_and(Vec::is_empty),
                "section missing_inputs must be empty"
            );
        }
    }

    assert_eq!(
        trace_rows.len() as u64,
        contract["expected_trace_rows"]
            .as_u64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected_trace_rows"))?
    );
    assert_eq!(trace_rows.len(), section_count);
    let required_trace_fields = string_set(&contract["required_trace_fields"])?;
    for row in trace_rows {
        assert_eq!(row["bead_id"].as_str(), contract["expected_bead"].as_str());
        assert_eq!(
            row["freshness_status"].as_str(),
            contract["expected_freshness_status"].as_str()
        );
        for field in &required_trace_fields {
            assert!(
                !row[field].is_null(),
                "trace row should include field {field}"
            );
        }
    }
    Ok(())
}

#[test]
fn checker_emits_structured_completion_evidence() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &root.join(CONTRACT_REL), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = read_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-w2c3.10.3.1")
    );
    assert_eq!(report["completion_summary"]["failed"].as_u64(), Some(0));
    assert_eq!(
        report["source_gate_results"]["docs_source_of_truth_gate"]["exit_code"].as_i64(),
        Some(0)
    );

    let events = read_jsonl(&out_dir.join("events.jsonl"))?;
    let actual_events = events
        .iter()
        .filter_map(|event| event["event"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    for event in EXPECTED_EVENTS {
        assert!(actual_events.contains(*event), "missing event {event}");
    }
    for event in events {
        for field in [
            "timestamp",
            "trace_id",
            "source_bead",
            "completion_debt_bead",
            "event",
            "status",
            "artifact_refs",
            "failure_signature",
            "details",
        ] {
            assert!(!event[field].is_null(), "event missing {field}");
        }
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_docs_surface() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "negative")?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    manifest["docs_truth_contract"]["required_surfaces"] =
        serde_json::json!(["README", "ARCHITECTURE", "DEPLOYMENT", "SECURITY", "API"]);
    let bad_contract = out_dir.join("bad.closure_sweep_completion_contract.v1.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject a contract missing the TROUBLESHOOTING docs surface"
    );
    let report = read_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = report["errors"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "errors"))?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or_default()
            .contains("docs surface mismatch")),
        "negative report should explain the docs surface mismatch"
    );
    Ok(())
}
