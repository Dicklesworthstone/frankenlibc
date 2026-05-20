//! Harness coverage for the bd-2icq.9 Gentoo performance benchmark CI gate.

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
    root.join("scripts/check_perf_benchmark_gentoo.sh")
}

fn unique_tmp_base(root: &Path) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "gentoo_perf_benchmark_gate_tmp_{}_{}",
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
        ("bead binding", "bd-2icq.9"),
        ("benchmark script path", "scripts/gentoo/perf-benchmark.py"),
        ("python test path", "tests/gentoo/test_perf_benchmark.py"),
        ("dry-run mode invocation", "--mode dry-run"),
        ("single package dry-run", "--packages sys-apps/coreutils"),
        ("tier1 dry-run", "--packages tier1"),
        ("schema version assertion", "data['schema_version'] != 'v1'"),
        ("bead assertion", "data['bead'] != 'bd-2icq.9'"),
        ("required schema keys", "avg_build_overhead_percent"),
        (
            "tier1 package count assertion",
            "data['total_packages'] != 5",
        ),
        ("tier1 success assertion", "data['successful'] != 5"),
        (
            "tier1 latency profile assertion",
            "if 'latency_profile' not in pkg:",
        ),
        (
            "python test invocation",
            "python3 -m pytest \"${TEST_FILE}\"",
        ),
        (
            "final pass marker",
            "PASS: Gentoo Performance Benchmark gate (bd-2icq.9)",
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
fn checker_script_pins_gentoo_perf_benchmark_contract() -> TestResult {
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
    assert_contains(&ci, "scripts/check_perf_benchmark_gentoo.sh", "CI script");

    for rel in [
        "scripts/gentoo/perf-benchmark.py",
        "tests/gentoo/test_perf_benchmark.py",
    ] {
        assert!(root.join(rel).is_file(), "{rel} must exist");
    }

    let test_source = read_text(&root.join("tests/gentoo/test_perf_benchmark.py"))?;
    for needle in [
        "class TestLatencyProfile",
        "class TestBenchmarkSuite",
        "class TestDryRunBenchmark",
        "class TestCLIDryRun",
        "def test_dry_run_cli_exit_zero",
        "def test_dry_run_tier1_all_packages",
        "def test_claim_200ns_percentile",
    ] {
        assert_contains(&test_source, needle, "perf benchmark test source");
    }

    Ok(())
}

#[test]
fn contract_validation_rejects_missing_tier1_latency_assertion() -> TestResult {
    let root = workspace_root()?;
    let source = read_text(&checker_path(&root))?;
    let mutated = source.replace(
        "if 'latency_profile' not in pkg:",
        "# missing tier1 latency profile assertion",
    );
    let failures = validate_checker_contract(&mutated);
    assert!(
        failures.contains(&"tier1 latency profile assertion"),
        "contract validator should reject a gate that no longer checks tier1 latency profiles"
    );
    Ok(())
}

#[test]
fn gentoo_perf_benchmark_gate_executes_without_cargo() -> TestResult {
    let root = workspace_root()?;
    let checker_source = read_text(&checker_path(&root))?;
    assert!(
        !checker_source.contains("cargo "),
        "Gentoo perf benchmark gate must remain a non-cargo checker"
    );

    let output = run_checker(&root)?;
    assert!(
        output.status.success(),
        "Gentoo perf benchmark gate failed: {}",
        output_text(&output)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for marker in [
        "PASS: perf-benchmark.py syntax valid",
        "PASS: dry-run produces output",
        "PASS: output schema valid",
        "PASS: tier1 dry-run produces valid 5-package results",
        "PASS: test_perf_benchmark.py tests passed",
        "PASS: Gentoo Performance Benchmark gate (bd-2icq.9) all checks passed",
    ] {
        assert_contains(&stdout, marker, "checker stdout");
    }

    Ok(())
}
