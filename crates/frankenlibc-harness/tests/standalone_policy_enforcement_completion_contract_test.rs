//! Completion-contract tests for bd-w2c3.2.2.1 standalone policy evidence.

use serde_json::Value;
use std::collections::{BTreeSet, btree_map::Entry};
use std::error::Error;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str =
    "tests/conformance/standalone_policy_enforcement_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_standalone_policy_enforcement_completion_contract.sh";
const REPLACEMENT_PROFILE_REL: &str = "tests/conformance/replacement_profile.json";
const PACKAGING_SPEC_REL: &str = "tests/conformance/packaging_spec.json";
const SUPPORT_MATRIX_REL: &str = "support_matrix.json";
const ZERO_FIXTURE_PACK_REL: &str =
    "tests/conformance/replacement_zero_unapproved_fixtures.v1.json";
const EXPECTED_MISSING_ITEMS: &[&str] = &["tests.unit.primary", "tests.e2e.primary"];
const EXPECTED_EVENTS: &[&str] = &[
    "standalone_policy_contract_validated",
    "standalone_policy_sources_validated",
    "replacement_guard_replayed",
    "standalone_policy_completion_summary",
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
        "standalone-policy-completion-{label}-{}-{nanos}",
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
            "FRANKENLIBC_STANDALONE_POLICY_COMPLETION_CONTRACT",
            contract,
        )
        .env("FRANKENLIBC_STANDALONE_POLICY_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_STANDALONE_POLICY_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_STANDALONE_POLICY_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
        .env(
            "FRANKENLIBC_STANDALONE_POLICY_REPLACEMENT_GUARD_REPORT",
            out_dir.join("replacement_guard.report.json"),
        )
        .env(
            "FRANKENLIBC_STANDALONE_POLICY_REPLACEMENT_GUARD_LOG",
            out_dir.join("replacement_guard.log.jsonl"),
        )
        .output()?)
}

#[test]
fn manifest_binds_standalone_unit_and_e2e_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("standalone_policy_enforcement_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-w2c3.2.2"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-w2c3.2.2.1")
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
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation_refs"))?;
    assert!(refs.len() >= 24, "expected concrete implementation refs");
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
        assert!(
            section["test_refs"]
                .as_array()
                .is_some_and(|refs| !refs.is_empty()),
            "coverage section should cite tests"
        );
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
        let test_refs = section["test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_refs missing"))?;
        for test_ref in test_refs {
            let source = test_ref["source"].as_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "test_ref source missing")
            })?;
            let name = test_ref["name"].as_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "test_ref name missing")
            })?;
            let rel = source_paths
                .get(source)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("source path missing for {source}"),
                    )
                })?;
            let source_text = match source_texts.entry(source.to_string()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(std::fs::read_to_string(
                    workspace_relative_path(&root, rel)?,
                )?),
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
fn manifest_matches_standalone_policy_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;
    let profile = read_json(&root.join(REPLACEMENT_PROFILE_REL))?;
    let packaging = read_json(&root.join(PACKAGING_SPEC_REL))?;
    let support = read_json(&root.join(SUPPORT_MATRIX_REL))?;
    let zero_fixtures = read_json(&root.join(ZERO_FIXTURE_PACK_REL))?;
    let policy = &manifest["policy_requirements"];

    assert_eq!(
        profile["profiles"]["replacement"]["call_through_allowed"].as_bool(),
        policy["replacement_profile"]["call_through_allowed"].as_bool()
    );
    assert_eq!(
        string_set(&profile["callthrough_families"]["modules"])?,
        string_set(&policy["replacement_profile"]["callthrough_modules"])?
    );
    assert_eq!(
        profile["zero_unapproved_fixture_pack"]["path"].as_str(),
        policy["replacement_profile"]["zero_unapproved_fixture_pack"].as_str()
    );
    assert_eq!(
        profile["call_through_census"]["total_call_throughs"].as_u64(),
        policy["replacement_profile"]["call_through_census_total"].as_u64()
    );
    assert_eq!(
        zero_fixtures["summary"]["fixture_count"].as_u64(),
        policy["replacement_profile"]["call_through_census_total"].as_u64()
    );

    let replace = &packaging["artifacts"]["replace"];
    assert_eq!(
        replace["host_glibc_required"].as_bool(),
        policy["packaging_spec"]["replace_host_glibc_required"].as_bool()
    );
    assert_eq!(
        string_set(&replace["allowed_statuses"])?,
        string_set(&policy["packaging_spec"]["replace_allowed_statuses"])?
    );
    assert_eq!(
        string_set(&replace["cargo_features"])?,
        string_set(&policy["packaging_spec"]["replace_cargo_features"])?
    );
    assert!(
        replace["build_command"]
            .as_str()
            .is_some_and(|command| command.contains("--features=standalone"))
    );
    assert_eq!(
        string_set(&packaging["feature_gates"]["standalone"]["features"])?,
        string_set(&policy["packaging_spec"]["standalone_feature_gate"])?
    );

    assert_eq!(
        string_set(&support["taxonomy"]["artifact_applicability"]["Replace"])?,
        string_set(&policy["support_matrix"]["replace_applicable_statuses"])?
    );
    let forbidden_statuses = string_set(&policy["support_matrix"]["forbidden_statuses"])?;
    let forbidden_count = support["symbols"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "symbols missing"))?
        .iter()
        .filter(|row| {
            row["status"]
                .as_str()
                .is_some_and(|status| forbidden_statuses.contains(status))
        })
        .count();
    assert_eq!(
        Some(forbidden_count as u64),
        policy["support_matrix"]["expected_forbidden_symbol_count"].as_u64()
    );

    let source_paths = manifest["source_paths"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_paths missing"))?;
    let source_anchors = manifest["source_anchors"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_anchors missing"))?;
    for (source, anchors) in source_anchors {
        let rel = source_paths
            .get(source)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("source path missing for {source}"),
                )
            })?;
        let text = std::fs::read_to_string(workspace_relative_path(&root, rel)?)?;
        let anchor_list = anchors.as_array().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("anchors missing for {source}"),
            )
        })?;
        for anchor in anchor_list {
            let anchor = anchor.as_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("anchor must be string for {source}"),
                )
            })?;
            assert!(text.contains(anchor), "{rel} missing anchor {anchor}");
        }
    }

    Ok(())
}

#[test]
fn checker_replays_replacement_guard_and_emits_report() -> TestResult {
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
        Some("standalone_policy_enforcement_completion_report.v1")
    );
    assert_eq!(report["ok"].as_bool(), Some(true));
    assert_eq!(
        report["summary"]["replacement_guard_summary"]["mode"].as_str(),
        Some("replacement")
    );
    assert_eq!(
        report["summary"]["replacement_guard_summary"]["total_call_throughs"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["summary"]["replacement_guard_summary"]["violations"].as_u64(),
        Some(0)
    );
    assert!(
        out_dir.join("replacement_guard.report.json").is_file(),
        "checker should preserve replacement guard report"
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
fn checker_rejects_policy_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "drift")?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    manifest["policy_requirements"]["packaging_spec"]["replace_allowed_statuses"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "allowed_statuses missing"))?
        .push(Value::String("Stub".to_string()));
    let drift_contract = out_dir.join("drift_contract.json");
    write_json(&drift_contract, &manifest)?;

    let output = run_checker(&root, &drift_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for drifted allowed_statuses"
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
        errors.contains("allowed_statuses"),
        "drift failure should mention allowed_statuses: {errors}"
    );

    Ok(())
}
