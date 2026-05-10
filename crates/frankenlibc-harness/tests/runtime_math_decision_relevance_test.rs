//! Completion-debt proof tests for bd-24x.1 runtime-math decision relevance.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ARTIFACT: &str = "tests/runtime_math/runtime_math_decision_relevance.v1.json";
const SCRIPT: &str = "scripts/check_runtime_math_decision_relevance.sh";
const MOD_RS: &str = "crates/frankenlibc-membrane/src/runtime_math/mod.rs";
const MATRIX: &str = "tests/runtime_math/runtime_math_classification_matrix.v1.json";
const LINKAGE: &str = "tests/runtime_math/runtime_math_linkage.v1.json";
const REQUIRED_REPORT_FIELDS: &[&str] = &[
    "schema_version",
    "bead",
    "generated_at_utc",
    "source_commit",
    "module_count",
    "public_module_count",
    "classification_counts",
    "linkage_status_counts",
    "decision_surface_counts",
    "missing_from_classification",
    "missing_from_linkage",
    "extra_classification_modules",
    "extra_linkage_modules",
    "failed_modules",
    "artifact_refs",
    "status",
    "log_path",
];
const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "module",
    "module_path",
    "classification",
    "linkage_status",
    "decision_target",
    "decision_surface",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "failure_signature",
    "outcome",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: impl AsRef<Path>) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn unique_temp_dir(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("{label}-{}-{now}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn declared_runtime_modules(root: &Path) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(root.join(MOD_RS))?;
    let modules = content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix("pub mod ")
                .and_then(|rest| rest.strip_suffix(';'))
                .map(str::to_owned)
        })
        .collect();
    Ok(modules)
}

fn load_log_rows(path: &Path) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

#[test]
fn artifact_names_completion_debt_contract() -> TestResult {
    let root = workspace_root();
    let artifact = load_json(root.join(ARTIFACT))?;

    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-24x.1"));
    assert_eq!(artifact["parent_bead"].as_str(), Some("bd-24x"));
    assert_eq!(
        artifact["runtime_module_scope"]["expected_public_module_count"].as_u64(),
        Some(69)
    );

    let debt_items: HashSet<_> = artifact["completion_debt_items"]
        .as_array()
        .expect("completion_debt_items array")
        .iter()
        .filter_map(|item| item.as_str())
        .collect();
    for item in [
        "tests.unit.primary",
        "tests.e2e.primary",
        "telemetry.primary",
    ] {
        assert!(debt_items.contains(item), "missing debt item {item}");
    }

    let required_report_fields: HashSet<_> = artifact["required_report_fields"]
        .as_array()
        .expect("required_report_fields array")
        .iter()
        .filter_map(|item| item.as_str())
        .collect();
    for field in REQUIRED_REPORT_FIELDS {
        assert!(
            required_report_fields.contains(field),
            "artifact omits report field {field}"
        );
    }

    let required_log_fields: HashSet<_> = artifact["required_log_fields"]
        .as_array()
        .expect("required_log_fields array")
        .iter()
        .filter_map(|item| item.as_str())
        .collect();
    for field in REQUIRED_LOG_FIELDS {
        assert!(
            required_log_fields.contains(field),
            "artifact omits log field {field}"
        );
    }
    Ok(())
}

#[test]
fn public_runtime_math_modules_are_in_classification_and_linkage_ledgers() -> TestResult {
    let root = workspace_root();
    let declared = declared_runtime_modules(&root)?;
    let matrix = load_json(root.join(MATRIX))?;
    let linkage = load_json(root.join(LINKAGE))?;

    let matrix_modules: HashSet<String> = matrix["modules"]
        .as_array()
        .expect("matrix modules array")
        .iter()
        .filter_map(|row| row["module"].as_str().map(str::to_owned))
        .collect();
    let linkage_modules: HashSet<String> = linkage["modules"]
        .as_object()
        .expect("linkage modules object")
        .keys()
        .cloned()
        .collect();

    assert_eq!(declared.len(), 69, "unexpected public module count");
    assert_eq!(
        declared, matrix_modules,
        "classification matrix must cover public runtime_math module declarations"
    );
    assert_eq!(
        declared, linkage_modules,
        "linkage ledger must cover public runtime_math module declarations"
    );
    Ok(())
}

#[test]
fn checker_e2e_emits_per_module_decision_telemetry() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_temp_dir("runtime-math-decision-relevance")?;
    let output = Command::new(root.join(SCRIPT))
        .current_dir(&root)
        .env(
            "FRANKENLIBC_RUNTIME_MATH_DECISION_RELEVANCE_TARGET_DIR",
            &out_dir,
        )
        .output()?;

    assert!(
        output.status.success(),
        "checker failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = out_dir.join("runtime_math_decision_relevance.report.json");
    let log_path = out_dir.join("runtime_math_decision_relevance.log.jsonl");
    let report = load_json(&report_path)?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-24x.1"));
    assert_eq!(report["public_module_count"].as_u64(), Some(69));
    assert_eq!(report["module_count"].as_u64(), Some(69));
    assert_eq!(report["failed_modules"].as_array().map(Vec::len), Some(0));
    assert_eq!(
        report["missing_from_classification"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        report["missing_from_linkage"].as_array().map(Vec::len),
        Some(0)
    );

    for field in REQUIRED_REPORT_FIELDS {
        assert!(report.get(*field).is_some(), "missing report field {field}");
    }

    let surfaces = report["decision_surface_counts"]
        .as_object()
        .expect("surface count object");
    assert!(
        surfaces.get("decide").and_then(|v| v.as_u64()).unwrap_or(0) > 0,
        "expected at least one decide-linked module"
    );
    assert!(
        surfaces
            .get("observe_validation_result")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            > 0,
        "expected at least one observe-linked module"
    );

    let rows = load_log_rows(&log_path)?;
    assert_eq!(rows.len(), 69, "one telemetry row per public module");
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "missing log field {field}");
        }
        assert_eq!(row["bead_id"].as_str(), Some("bd-24x.1"));
        assert_eq!(row["outcome"].as_str(), Some("pass"));
        assert!(
            row["decision_target"]
                .as_str()
                .unwrap_or("")
                .contains("RuntimeMathKernel::"),
            "decision target must name RuntimeMathKernel"
        );
    }
    Ok(())
}

#[test]
fn checker_script_is_read_only_and_env_configurable() -> TestResult {
    let root = workspace_root();
    let script = std::fs::read_to_string(root.join(SCRIPT))?;
    for forbidden in [
        "br update",
        "br close",
        "br create",
        "git add",
        "git commit",
    ] {
        assert!(
            !script.contains(forbidden),
            "checker must stay read-only; found {forbidden}"
        );
    }

    let env_names = [
        "FRANKENLIBC_RUNTIME_MATH_DECISION_RELEVANCE_ARTIFACT",
        "FRANKENLIBC_RUNTIME_MATH_DECISION_RELEVANCE_TARGET_DIR",
        "FRANKENLIBC_RUNTIME_MATH_DECISION_RELEVANCE_REPORT",
        "FRANKENLIBC_RUNTIME_MATH_DECISION_RELEVANCE_LOG",
    ];
    let present: HashMap<_, _> = env_names
        .into_iter()
        .map(|name| (name, script.contains(name)))
        .collect();
    for (name, found) in present {
        assert!(found, "checker missing env override {name}");
    }
    Ok(())
}
