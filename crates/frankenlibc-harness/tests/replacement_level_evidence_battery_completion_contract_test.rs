//! Completion-contract tests for bd-w2c3.2.3.1 replacement-level evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str =
    "tests/conformance/replacement_level_evidence_battery_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_replacement_level_evidence_battery_completion_contract.sh";
const REPLACEMENT_LEVELS_REL: &str = "tests/conformance/replacement_levels.json";
const SUPPORT_MATRIX_REL: &str = "support_matrix.json";
const CALLTHROUGH_CENSUS_REL: &str = "tests/conformance/callthrough_census.v1.json";
const RESIDUAL_BLOCKERS_REL: &str =
    "tests/conformance/residual_replacement_callthrough_blockers.v1.json";
const DASHBOARD_REL: &str = "tests/conformance/replacement_level_dashboard.v1.json";
const EXPECTED_MISSING_ITEMS: &[&str] = &["tests.unit.primary", "tests.e2e.primary"];
const EXPECTED_EVENTS: &[&str] = &[
    "replacement_level_contract_validated",
    "replacement_level_sources_validated",
    "replacement_level_gate_replayed",
    "replacement_level_completion_summary",
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

fn repo_relative_string(root: &Path, path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(root)?
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/"))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn json_array<'a>(value: &'a Value, name: &str) -> TestResult<&'a [Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid_data(format!("{name} must be array")).into())
}

fn json_array_mut<'a>(value: &'a mut Value, name: &str) -> TestResult<&'a mut Vec<Value>> {
    value
        .as_array_mut()
        .ok_or_else(|| invalid_data(format!("{name} must be array")).into())
}

fn json_object<'a>(value: &'a Value, name: &str) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid_data(format!("{name} must be object")).into())
}

fn json_str<'a>(value: &'a Value, name: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| invalid_data(format!("{name} must be string")).into())
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = json_array(value, "expected string array")?;
    let mut set = BTreeSet::new();
    for item in array {
        set.insert(json_str(item, "expected string")?.to_string());
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
        "replacement-level-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env(
            "FRANKENLIBC_REPLACEMENT_LEVEL_COMPLETION_CONTRACT",
            contract,
        )
        .env("FRANKENLIBC_REPLACEMENT_LEVEL_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_REPLACEMENT_LEVEL_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_REPLACEMENT_LEVEL_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
        .env(
            "FRANKENLIBC_REPLACEMENT_LEVEL_GATE_REPORT",
            out_dir.join("replacement_levels_l1_gate.report.json"),
        )
        .env(
            "FRANKENLIBC_REPLACEMENT_LEVEL_GATE_LOG",
            out_dir.join("replacement_levels_l1_gate.log.jsonl"),
        )
        .output()?)
}

#[test]
fn manifest_binds_replacement_level_unit_and_e2e_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("replacement_level_evidence_battery_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-w2c3.2.3"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-w2c3.2.3.1")
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

    let source_paths = json_object(&manifest["source_paths"], "source_paths")?;
    for path in source_paths.values() {
        let rel = path.as_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "source path must be string")
        })?;
        assert!(
            workspace_relative_path(&root, rel)?.exists(),
            "source path should exist: {rel}"
        );
    }

    let refs = json_array(&manifest["implementation_refs"], "implementation_refs")?;
    assert!(refs.len() >= 30, "expected concrete implementation refs");
    for ref_obj in refs {
        assert_file_line_ref_exists(&root, ref_obj)?;
    }

    let coverage = json_array(&manifest["completion_coverage"], "completion_coverage")?;
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
        assert!(
            section["test_refs"]
                .as_array()
                .is_some_and(|refs| !refs.is_empty()),
            "coverage section should cite tests"
        );
        for command in json_array(&section["validation_commands"], "validation commands")?
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
        for test_ref in json_array(&section["test_refs"], "test_refs")? {
            let source = json_str(&test_ref["source"], "test_ref source")?;
            let name = json_str(&test_ref["name"], "test_ref name")?;
            let rel = source_paths
                .get(source)
                .ok_or_else(|| invalid_data(format!("missing source path {source}")))
                .and_then(|path| {
                    path.as_str()
                        .ok_or_else(|| invalid_data("source path string"))
                })?;
            if !source_texts.contains_key(source) {
                source_texts.insert(source.to_string(), std::fs::read_to_string(root.join(rel))?);
            }
            let source_text = source_texts
                .get(source)
                .ok_or_else(|| invalid_data(format!("missing cached source text {source}")))?;
            assert!(
                function_exists(source_text, name),
                "test ref should exist: {rel}::{name}"
            );
        }
    }
    Ok(())
}

#[test]
fn manifest_matches_replacement_level_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;
    let levels = read_json(&root.join(REPLACEMENT_LEVELS_REL))?;
    let support = read_json(&root.join(SUPPORT_MATRIX_REL))?;
    let census = read_json(&root.join(CALLTHROUGH_CENSUS_REL))?;
    let residual = read_json(&root.join(RESIDUAL_BLOCKERS_REL))?;
    let dashboard = read_json(&root.join(DASHBOARD_REL))?;
    let policy = &manifest["policy_requirements"];

    let level_entries = levels["levels"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "levels missing"))?;
    let level_ids = level_entries
        .iter()
        .map(|entry| entry["level"].as_str().unwrap_or_default().to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        level_ids,
        string_set(&policy["replacement_levels"]["expected_levels"])?
    );
    assert_eq!(
        levels["current_level"].as_str(),
        policy["replacement_levels"]["current_level"].as_str()
    );
    assert_eq!(
        levels["release_tag_policy"]["current_release_level"].as_str(),
        policy["replacement_levels"]["current_release_level"].as_str()
    );

    for (level, expected_status) in json_object(
        &policy["replacement_levels"]["expected_status_by_level"],
        "expected_status_by_level",
    )? {
        let actual = level_entries
            .iter()
            .find(|entry| entry["level"].as_str() == Some(level.as_str()))
            .and_then(|entry| entry["status"].as_str())
            .unwrap_or_default();
        assert_eq!(Some(actual), expected_status.as_str(), "{level} status");
    }

    let assessment = &levels["current_assessment"];
    assert_eq!(
        assessment["callthrough"].as_u64(),
        policy["replacement_levels"]["expected_zero_counts"]["callthrough"].as_u64()
    );
    assert_eq!(
        assessment["stub"].as_u64(),
        policy["replacement_levels"]["expected_zero_counts"]["stub"].as_u64()
    );
    let support_symbols = support["symbols"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "support symbols"))?;
    assert_eq!(
        Some(support_symbols.len() as u64),
        policy["support_matrix"]["total_symbols"].as_u64()
    );
    assert_eq!(
        assessment["total_symbols"].as_u64(),
        Some(support_symbols.len() as u64)
    );

    let levels_text = serde_json::to_string(&levels)?;
    for stale_text in json_array(
        &policy["replacement_levels"]["stale_blocker_forbidden_substrings"],
        "stale_blocker_forbidden_substrings",
    )?
    .iter()
    .filter_map(Value::as_str)
    {
        assert!(
            !levels_text.contains(stale_text),
            "replacement_levels should not contain stale blocker {stale_text}"
        );
    }
    let l2_blockers = level_entries
        .iter()
        .find(|entry| entry["level"].as_str() == Some("L2"))
        .and_then(|entry| entry["blockers"].as_array())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "L2 blockers"))?;
    let required_l2 = json_str(
        &policy["replacement_levels"]["l2_required_blocker_substring"],
        "l2_required_blocker_substring",
    )?;
    assert!(
        l2_blockers
            .iter()
            .filter_map(Value::as_str)
            .any(|blocker| blocker.contains(required_l2)),
        "L2 blockers should cite pending standalone artifact packaging proof"
    );

    assert_eq!(
        census["summary"]["symbol_count"].as_u64(),
        policy["callthrough_census"]["symbol_count"].as_u64()
    );
    assert_eq!(
        residual["current_truth"]["residual_forbidden_count"].as_u64(),
        policy["residual_callthrough_blockers"]["residual_forbidden_count"].as_u64()
    );
    assert_eq!(
        dashboard["summary"]["claim_status"].as_str(),
        policy["replacement_level_dashboard"]["claim_status"].as_str()
    );

    let source_paths = json_object(&manifest["source_paths"], "source_paths")?;
    let source_anchors = json_object(&manifest["source_anchors"], "source_anchors")?;
    for (source, anchors) in source_anchors {
        let rel = source_paths
            .get(source)
            .ok_or_else(|| invalid_data(format!("missing source path {source}")))
            .and_then(|path| {
                path.as_str()
                    .ok_or_else(|| invalid_data("source path string"))
            })?;
        let text = std::fs::read_to_string(root.join(rel))?;
        for anchor in json_array(anchors, "source anchors")?
            .iter()
            .filter_map(Value::as_str)
        {
            assert!(text.contains(anchor), "{rel} missing anchor {anchor}");
        }
    }

    Ok(())
}

#[test]
fn checker_replays_replacement_level_gate_and_emits_report() -> TestResult {
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
    assert_eq!(
        report["schema_version"].as_str(),
        Some("replacement_level_evidence_battery_completion_report.v1")
    );
    assert_eq!(report["ok"].as_bool(), Some(true));
    assert_eq!(
        report["summary"]["gate_summary"]["status"].as_str(),
        Some("pass")
    );
    assert_eq!(
        report["summary"]["gate_summary"]["current_level"].as_str(),
        Some("L1")
    );
    assert_eq!(
        report["summary"]["gate_summary"]["script_failure_count"].as_u64(),
        Some(0)
    );
    assert!(
        out_dir
            .join("replacement_levels_l1_gate.report.json")
            .is_file(),
        "checker should preserve replacement-level gate report"
    );

    let gate_report = read_json(&out_dir.join("replacement_levels_l1_gate.report.json"))?;
    assert_eq!(
        gate_report["gate_id"].as_str(),
        Some("replacement_levels_l1_gate")
    );
    assert_eq!(gate_report["status"].as_str(), Some("pass"));
    assert_eq!(gate_report["current_level"].as_str(), Some("L1"));

    let gate_rows = read_jsonl(&out_dir.join("replacement_levels_l1_gate.log.jsonl"))?;
    assert!(
        gate_rows
            .iter()
            .any(|row| row["source"].as_str() == Some("l1_crt_startup_tls_proof_matrix")),
        "gate log should include L1 CRT/startup/TLS proof rows"
    );

    let events = read_jsonl(&out_dir.join("events.jsonl"))?;
    let event_names = events
        .iter()
        .map(|row| row["event"].as_str().unwrap_or_default().to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        event_names,
        EXPECTED_EVENTS
            .iter()
            .map(|event| (*event).to_string())
            .collect()
    );
    assert!(
        events
            .iter()
            .all(|row| row["status"].as_str() == Some("pass"))
    );

    Ok(())
}

#[test]
fn checker_rejects_stale_standalone_policy_blocker() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "stale-blocker")?;
    let mut levels = read_json(&root.join(REPLACEMENT_LEVELS_REL))?;
    let l2 = json_array_mut(&mut levels["levels"], "levels")?
        .iter_mut()
        .find(|entry| entry["level"].as_str() == Some("L2"))
        .ok_or_else(|| invalid_data("L2 level should exist"))?;
    json_array_mut(&mut l2["blockers"], "L2 blockers")?.push(Value::String(
        "Standalone dependency policy gate (bd-w2c3.2.2) remains incomplete".to_string(),
    ));
    let mutated_levels = out_dir.join("replacement_levels_with_stale_blocker.json");
    write_json(&mutated_levels, &levels)?;

    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    manifest["source_paths"]["replacement_levels"] =
        Value::String(repo_relative_string(&root, &mutated_levels)?);
    let drift_contract = out_dir.join("drift_contract.json");
    write_json(&drift_contract, &manifest)?;

    let output = run_checker(&root, &drift_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for stale standalone-policy blocker"
    );
    let report = read_json(&out_dir.join("report.json"))?;
    assert_eq!(report["ok"].as_bool(), Some(false));
    let errors = report["errors"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "errors missing"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        errors.contains("stale blocker"),
        "stale-blocker failure should be explicit: {errors}"
    );

    Ok(())
}
