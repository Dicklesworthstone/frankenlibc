//! Harness coverage for the bd-2icq.24 flaky-quarantine CI gate.

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
    root.join("scripts/check_flaky_quarantine.sh")
}

fn unique_tmp_base(root: &Path) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "flaky_quarantine_gate_tmp_{}_{}",
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
        ("bead binding", "bd-2icq.24"),
        ("detector path", "scripts/gentoo/flaky_detector.py"),
        ("manager path", "scripts/gentoo/quarantine_manager.py"),
        ("quarantine db path", "data/gentoo/quarantine.json"),
        (
            "detector schema assertion",
            "data.get('schema_version') != 'v1'",
        ),
        (
            "detector bead assertion",
            "data.get('bead') != 'bd-2icq.24'",
        ),
        ("manager init action", "--action init"),
        ("manager add action", "--action add"),
        ("manager check action", "--action check"),
        (
            "quarantined rc assertion",
            "[[ \"${RC}\" -eq 1 ]] || fail \"quarantine check should return 1",
        ),
        (
            "python test invocation",
            "python3 -m pytest \"${TEST_FILE}\"",
        ),
        (
            "final pass marker",
            "PASS: Flaky Test Quarantine gate (bd-2icq.24)",
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
fn checker_script_pins_flaky_quarantine_contract() -> TestResult {
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
    assert_contains(&ci, "scripts/check_flaky_quarantine.sh", "CI script");

    for rel in [
        "scripts/gentoo/flaky_detector.py",
        "scripts/gentoo/quarantine_manager.py",
        "data/gentoo/quarantine.json",
        "tests/gentoo/test_flaky_detector.py",
    ] {
        assert!(root.join(rel).is_file(), "{rel} must exist");
    }

    let test_source = read_text(&root.join("tests/gentoo/test_flaky_detector.py"))?;
    for needle in [
        "class TestFlakeRateCalculation",
        "class TestFlakeDetection",
        "class TestQuarantineDB",
        "class TestImportReport",
        "class TestCLIDryRun",
        "def test_detector_dry_run",
        "def test_quarantine_add_list",
    ] {
        assert_contains(&test_source, needle, "flaky detector test source");
    }

    Ok(())
}

#[test]
fn contract_validation_rejects_missing_roundtrip_assertion() -> TestResult {
    let root = workspace_root()?;
    let source = read_text(&checker_path(&root))?;
    let mutated = source.replace(
        "[[ \"${RC}\" -eq 1 ]] || fail \"quarantine check should return 1",
        "# missing quarantine return-code assertion",
    );
    let failures = validate_checker_contract(&mutated);
    assert!(
        failures.contains(&"quarantined rc assertion"),
        "contract validator should reject a gate that no longer asserts quarantined check rc=1"
    );
    Ok(())
}

#[test]
fn flaky_quarantine_gate_executes_without_cargo() -> TestResult {
    let root = workspace_root()?;
    let checker_source = read_text(&checker_path(&root))?;
    assert!(
        !checker_source.contains("cargo "),
        "flaky quarantine gate must remain a non-cargo checker"
    );

    let output = run_checker(&root)?;
    assert!(
        output.status.success(),
        "flaky quarantine gate failed: {}",
        output_text(&output)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for marker in [
        "PASS: scripts syntax valid",
        "PASS: quarantine.json schema valid",
        "PASS: dry-run detection produces valid output",
        "PASS: quarantine manager roundtrip works",
        "PASS: test_flaky_detector.py tests passed",
        "PASS: Flaky Test Quarantine gate (bd-2icq.24) all checks passed",
    ] {
        assert_contains(&stdout, marker, "checker stdout");
    }

    Ok(())
}
