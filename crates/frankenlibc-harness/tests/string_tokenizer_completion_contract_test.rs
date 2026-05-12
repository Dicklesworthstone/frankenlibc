//! Contract tests for bd-5if6f.1 string tokenizer conformance evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest must have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest must live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn read_manifest(root: &Path) -> TestResult<serde_json::Value> {
    let path = root.join("tests/conformance/string_tokenizer_completion_contract.v1.json");
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn json_string_set(value: &serde_json::Value) -> TestResult<BTreeSet<String>> {
    let values = value.as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "value should be a JSON array of strings",
        )
    })?;
    let mut result = BTreeSet::new();
    for item in values {
        let text = item.as_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "array entry should be a string")
        })?;
        result.insert(text.to_string());
    }
    Ok(result)
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &str) -> TestResult {
    let (path, line) = file_line_ref.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "file-line ref should contain ':'",
        )
    })?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "file-line ref line must be positive");
    let full_path = root.join(path);
    assert!(
        full_path.exists(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let text = std::fs::read_to_string(&full_path)?;
    let lines: Vec<&str> = text.lines().collect();
    assert!(
        line_no <= lines.len(),
        "file-line ref outside file: {file_line_ref}"
    );
    assert!(
        !lines[line_no - 1].trim().is_empty(),
        "file-line ref should not point at a blank line: {file_line_ref}"
    );
    Ok(())
}

fn source_texts(
    root: &Path,
    sources: &serde_json::Map<String, serde_json::Value>,
) -> TestResult<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for (key, path) in sources {
        let path = path.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "test source path should be a string",
            )
        })?;
        result.insert(key.clone(), std::fs::read_to_string(root.join(path))?);
    }
    Ok(result)
}

#[test]
fn manifest_binds_string_tokenizer_conformance_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_manifest(&root)?;
    let evidence = &manifest["completion_debt_evidence"];
    let conformance = &evidence["conformance_primary"];

    assert_eq!(manifest["bead"].as_str(), Some("bd-5if6f.1"));
    assert_eq!(evidence["bead"].as_str(), Some("bd-5if6f.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-5if6f"));
    assert_eq!(
        conformance["missing_item_id"].as_str(),
        Some("tests.conformance.primary")
    );
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should target a passing next audit score"
    );

    assert_eq!(
        json_string_set(&evidence["missing_items"])?,
        BTreeSet::from(["tests.conformance.primary".to_string()])
    );

    let sources = evidence["test_sources"].as_object().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "test_sources should be an object",
        )
    })?;
    let source_texts = source_texts(&root, sources)?;

    let required_symbols = json_string_set(&conformance["required_symbols"])?;
    assert_eq!(
        required_symbols,
        BTreeSet::from([
            "strsep".to_string(),
            "strtok".to_string(),
            "strtok_r".to_string()
        ])
    );
    for symbol in ["strtok", "strtok_r", "strsep"] {
        assert!(
            source_texts.values().any(|text| text.contains(symbol)),
            "declared test sources should mention symbol {symbol}"
        );
    }

    let refs = conformance["required_test_refs"]
        .as_array()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "required_test_refs should be an array",
            )
        })?;
    assert_eq!(refs.len(), 5, "contract should bind five conformance refs");
    for test_ref in refs {
        let source = test_ref["source"].as_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "test source should be a string")
        })?;
        let name = test_ref["name"].as_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "test name should be a string")
        })?;
        let text = source_texts.get(source).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "test source should be declared")
        })?;
        assert!(
            text.contains(&format!("fn {name}")),
            "contract references missing test {source}::{name}"
        );
    }

    let required_cases = json_string_set(&conformance["required_fixture_cases"])?;
    let fixture: serde_json::Value =
        serde_json::from_str(source_texts.get("fixture").ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "fixture source missing")
        })?)?;
    assert_eq!(fixture["family"].as_str(), Some("string/strtok"));
    let actual_cases: BTreeSet<String> = fixture["cases"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "fixture cases missing"))?
        .iter()
        .filter_map(|case| case["name"].as_str().map(str::to_string))
        .collect();
    assert!(
        required_cases.is_subset(&actual_cases),
        "required fixture cases must all exist in string_strtok fixture"
    );

    let scenarios = json_string_set(&conformance["required_scenarios"])?;
    for phrase in [
        "unterminated delimiter",
        "saveptr null",
        "preserves stringp",
        "differential cases",
        "isolated conformance harness",
    ] {
        assert!(
            scenarios.iter().any(|scenario| scenario.contains(phrase)),
            "contract should include scenario phrase {phrase}"
        );
    }

    let implementation_refs = evidence["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation refs missing"))?;
    assert!(
        implementation_refs.len() >= 12,
        "implementation refs should cover ABI bounds, regressions, differential, and fixture harness"
    );
    for file_line_ref in implementation_refs {
        let file_line_ref = file_line_ref.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "implementation ref should be a string",
            )
        })?;
        assert_file_line_ref_exists(&root, file_line_ref)?;
    }

    Ok(())
}

#[test]
fn checker_script_passes_and_emits_report() -> TestResult {
    let root = workspace_root()?;
    let report =
        root.join("target/conformance/string_tokenizer_completion_contract.test.report.json");
    let log = root.join("target/conformance/string_tokenizer_completion_contract.test.log.jsonl");

    let output = Command::new("bash")
        .arg(root.join("scripts/check_string_tokenizer_completion_contract.sh"))
        .env("FRANKENLIBC_STRING_TOKENIZER_REPORT", &report)
        .env("FRANKENLIBC_STRING_TOKENIZER_LOG", &log)
        .current_dir(&root)
        .output()?;
    assert!(
        output.status.success(),
        "checker failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&report)?)?;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["bead"].as_str(), Some("bd-5if6f.1"));
    assert_eq!(report_json["original_bead"].as_str(), Some("bd-5if6f"));
    assert_eq!(
        json_string_set(&report_json["missing_items_bound"])?,
        BTreeSet::from(["tests.conformance.primary".to_string()])
    );
    assert_eq!(
        report_json["required_test_refs"]
            .as_array()
            .map_or(0, |refs| refs.len()),
        5
    );
    assert_eq!(
        report_json["failure_signature"].as_str(),
        Some("string_tokenizer_unbounded_delimiter_scan_or_missing_conformance_evidence")
    );

    let log_text = std::fs::read_to_string(&log)?;
    let last_line = log_text
        .lines()
        .last()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "log should not be empty"))?;
    let event: serde_json::Value = serde_json::from_str(last_line)?;
    assert_eq!(
        event["event"].as_str(),
        Some("string_tokenizer_completion_contract_validated")
    );
    assert_eq!(event["status"].as_str(), Some("pass"));
    Ok(())
}
