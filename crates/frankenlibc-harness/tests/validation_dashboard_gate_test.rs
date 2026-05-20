//! Harness coverage for the bd-2icq.11 validation-dashboard CI gate.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_validation_dashboard.sh")
}

fn unique_tmp_base(root: &Path) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "validation_dashboard_gate_tmp_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn read_text(path: &Path) -> TestResult<String> {
    std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_contains(haystack: &str, needle: &str, context: &str) {
    assert!(
        haystack.contains(needle),
        "{context} missing required marker `{needle}`"
    );
}

fn validate_checker_contract(source: &str) -> Vec<&'static str> {
    let required = [
        ("bead binding", "bd-2icq.11"),
        (
            "dashboard script path",
            "scripts/gentoo/validation_dashboard.py",
        ),
        (
            "dashboard test path",
            "tests/gentoo/test_validation_dashboard.py",
        ),
        ("json dry-run invocation", "--dry-run --format json"),
        ("both-format dry-run invocation", "--dry-run --format both"),
        (
            "schema version assertion",
            "data.get('schema_version') != 'v1'",
        ),
        ("bead assertion", "data.get('bead') != 'bd-2icq.11'"),
        (
            "sections array assertion",
            "if not isinstance(data.get('sections'), list):",
        ),
        (
            "overall status assertion",
            "if 'overall_status' not in data:",
        ),
        (
            "markdown header assertion",
            "FrankenLibC Gentoo Validation Dashboard",
        ),
        (
            "python test invocation",
            "python3 -m pytest \"${TEST_FILE}\"",
        ),
        (
            "final pass marker",
            "PASS: Validation Dashboard gate (bd-2icq.11)",
        ),
    ];

    required
        .iter()
        .filter_map(|(name, needle)| (!source.contains(needle)).then_some(*name))
        .collect()
}

fn run_checker(root: &Path) -> TestResult<Output> {
    let tmp_base = unique_tmp_base(root)?;
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("TMPDIR", tmp_base)
        .output()?)
}

#[test]
fn checker_script_pins_validation_dashboard_contract() -> TestResult {
    let root = workspace_root()?;
    let checker = checker_path(&root);
    let source = read_text(&checker)?;
    assert!(
        checker.is_file(),
        "missing checker script at {}",
        checker.display()
    );

    let failures = validate_checker_contract(&source);
    assert!(
        failures.is_empty(),
        "checker contract drifted: {failures:?}"
    );

    let ci = read_text(&root.join("scripts/ci.sh"))?;
    assert_contains(&ci, "scripts/check_validation_dashboard.sh", "CI script");

    for rel in [
        "scripts/gentoo/validation_dashboard.py",
        "tests/gentoo/test_validation_dashboard.py",
    ] {
        assert!(root.join(rel).is_file(), "{rel} must exist");
    }

    let test_source = read_text(&root.join("tests/gentoo/test_validation_dashboard.py"))?;
    for needle in [
        "class TestDashboardSection",
        "class TestDashboard",
        "class TestSectionBuilders",
        "class TestSectionBuildersWithData",
        "class TestBuildDashboard",
        "class TestCLI",
        "def test_to_dict_schema",
        "def test_json_roundtrip",
        "def test_markdown_output",
    ] {
        assert_contains(&test_source, needle, "validation dashboard test source");
    }

    Ok(())
}

#[test]
fn contract_validation_rejects_missing_overall_status_assertion() -> TestResult {
    let root = workspace_root()?;
    let source = read_text(&checker_path(&root))?;
    let mutated = source.replace(
        "if 'overall_status' not in data:",
        "# missing overall_status assertion",
    );
    let failures = validate_checker_contract(&mutated);
    assert!(
        failures.contains(&"overall status assertion"),
        "contract validator should reject a gate that no longer checks overall_status"
    );
    Ok(())
}

#[test]
fn validation_dashboard_gate_executes_without_cargo() -> TestResult {
    let root = workspace_root()?;
    let checker_source = read_text(&checker_path(&root))?;
    assert!(
        !checker_source.contains("cargo "),
        "validation dashboard gate must remain a non-cargo checker"
    );

    let output = run_checker(&root)?;
    assert!(
        output.status.success(),
        "validation dashboard gate failed: {}",
        output_text(&output)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for marker in [
        "PASS: script syntax valid",
        "PASS: JSON output schema valid",
        "PASS: markdown output valid",
        "PASS: test_validation_dashboard.py tests passed",
        "PASS: Validation Dashboard gate (bd-2icq.11) all checks passed",
    ] {
        assert_contains(&stdout, marker, "checker stdout");
    }

    Ok(())
}
