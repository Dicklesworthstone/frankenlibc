//! Harness coverage for the bd-1sp.4 EBR integration shell gate.

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
    root.join("scripts/check_ebr_integration.sh")
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
        ("bead binding", "bd-1sp.4"),
        ("validate-only mode", "--validate-only"),
        ("rch mode", "--rch"),
        ("local fallback mode", "--local"),
        ("remote-only cargo policy", "RCH_REQUIRE_REMOTE=1"),
        ("rch cargo delegation", "rch exec -- cargo test"),
        ("membrane package", "-p frankenlibc-membrane"),
        ("integration test file", "--test ebr_integration_test"),
        (
            "integration test filter",
            "ebr_e2e_emits_structured_artifacts",
        ),
        (
            "missing rch failure",
            "rch not available; rerun with --local only for manual fallback",
        ),
        ("report override", "FRANKENLIBC_EBR_E2E_REPORT"),
        ("log override", "FRANKENLIBC_EBR_E2E_LOG"),
        (
            "artifact report path",
            "target/conformance/ebr_e2e.report.json",
        ),
        ("artifact log path", "target/conformance/ebr_e2e.log.jsonl"),
        (
            "report schema assertion",
            "report.get(\"schema_version\") != \"v1\"",
        ),
        (
            "report bead assertion",
            "report.get(\"bead\") != \"bd-1sp.4\"",
        ),
        (
            "event coverage assertion",
            "for event in (\"pin_guard\", \"retire\", \"epoch_advance\", \"quarantine_enqueue\", \"quarantine_release\")",
        ),
        (
            "final pass marker",
            "PASS: EBR report + structured log validated",
        ),
    ];

    required
        .iter()
        .filter_map(|(name, needle)| (!source.contains(needle)).then_some(*name))
        .collect()
}

fn validate_fixture_dir(root: &Path) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    root.join("target").join("conformance").join(format!(
        "ebr_gate_validate_tmp_{}_{}",
        std::process::id(),
        nanos
    ))
}

fn write_valid_ebr_artifacts(dir: &Path) -> TestResult<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(dir)?;
    let report_path = dir.join("ebr_e2e.report.json");
    let log_path = dir.join("ebr_e2e.log.jsonl");

    std::fs::write(
        &report_path,
        r#"{
  "schema_version": "v1",
  "bead": "bd-1sp.4",
  "scenario_id": "ebr_reclamation_e2e",
  "trace_id": "bd-1sp.4:ebr-e2e",
  "mode": "strict",
  "ebr": {
    "global_epoch": 3,
    "observed_epoch_advances": [1, 2, 3],
    "active_threads": 0,
    "pinned_threads": 0,
    "total_retired": 1,
    "total_reclaimed": 1,
    "pending_per_epoch": [0, 0, 0]
  },
  "quarantine": {
    "configured_depth": 2,
    "reclaimed": true,
    "pending": 0
  },
  "artifacts": {
    "report_json": "target/conformance/ebr_e2e.report.json",
    "log_jsonl": "target/conformance/ebr_e2e.log.jsonl"
  }
}
"#,
    )?;

    let events = [
        "pin_guard",
        "retire",
        "epoch_advance",
        "quarantine_enqueue",
        "quarantine_release",
    ];
    let rows = events
        .into_iter()
        .map(|event| {
            format!(
                r#"{{"trace_id":"bd-1sp.4:ebr-e2e","mode":"strict","api_family":"membrane","symbol":"ebr::collector","decision_path":"validate-only-fixture","healing_action":null,"errno":0,"latency_ns":0,"artifact_refs":["scripts/check_ebr_integration.sh"],"event":"{event}"}}"#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&log_path, format!("{rows}\n"))?;

    Ok((report_path, log_path))
}

#[test]
fn checker_script_defaults_to_remote_cargo_gate() -> TestResult {
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

    assert!(
        !source.contains("exec rch exec -- cargo test"),
        "checker must validate artifacts after remote cargo succeeds"
    );
    assert_contains(
        &source,
        "elif [[ \"${MODE}\" == \"local\" ]]; then",
        "checker source",
    );

    for rel in [
        "crates/frankenlibc-membrane/tests/ebr_integration_test.rs",
        "scripts/check_ebr_integration.sh",
    ] {
        assert!(root.join(rel).is_file(), "{rel} must exist");
    }

    Ok(())
}

#[test]
fn contract_validation_rejects_bare_default_cargo_drift() -> TestResult {
    let root = workspace_root()?;
    let source = read_text(&checker_path(&root))?;
    let mutated = source
        .replace("RCH_REQUIRE_REMOTE=1", "# missing remote-only cargo policy")
        .replace("rch exec -- cargo test", "cargo test");
    let failures = validate_checker_contract(&mutated);
    assert!(
        failures.contains(&"remote-only cargo policy"),
        "contract validator should reject a missing remote-only marker"
    );
    assert!(
        failures.contains(&"rch cargo delegation"),
        "contract validator should reject bare default cargo drift"
    );
    Ok(())
}

#[test]
fn validate_only_mode_checks_env_artifacts_without_cargo() -> TestResult {
    let root = workspace_root()?;
    let artifact_dir = validate_fixture_dir(&root);
    let (report_path, log_path) = write_valid_ebr_artifacts(&artifact_dir)?;

    let output = Command::new("bash")
        .arg(checker_path(&root))
        .arg("--validate-only")
        .env("FRANKENLIBC_EBR_E2E_REPORT", &report_path)
        .env("FRANKENLIBC_EBR_E2E_LOG", &log_path)
        .current_dir(&root)
        .output()?;
    assert!(
        output.status.success(),
        "validate-only gate failed: {}",
        output_text(&output)
    );

    let report_rel = report_path
        .strip_prefix(&root)
        .expect("test report should live under workspace");
    let log_rel = log_path
        .strip_prefix(&root)
        .expect("test log should live under workspace");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for marker in [
        "=== EBR Integration Gate (bd-1sp.4) ===".to_string(),
        "PASS: EBR report + structured log validated".to_string(),
        format!("REPORT={}", report_rel.display()),
        format!("LOG={}", log_rel.display()),
    ] {
        assert_contains(&stdout, &marker, "checker stdout");
    }

    Ok(())
}
