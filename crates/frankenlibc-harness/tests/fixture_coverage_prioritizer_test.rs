//! Integration test: fixture coverage prioritizer gate (bd-bp8fl.4.1)
//!
//! Validates that fixture campaigns are derived from current coverage artifacts
//! and remain sorted by coverage gain plus real workload risk.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "symbol_family",
    "score",
    "rank",
    "coverage_state",
    "risk_factors",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];
const EXPECTED_INPUTS: &[(&str, &str)] = &[
    (
        "version_script",
        "crates/frankenlibc-abi/version_scripts/libc.map",
    ),
    (
        "abi_symbol_universe",
        "tests/conformance/symbol_universe_normalization.v1.json",
    ),
    ("support_matrix", "support_matrix.json"),
    (
        "semantic_overlay",
        "tests/conformance/support_semantic_overlay.v1.json",
    ),
    (
        "semantic_contract_join",
        "tests/conformance/semantic_contract_symbol_join.v1.json",
    ),
    (
        "symbol_fixture_coverage",
        "tests/conformance/symbol_fixture_coverage.v1.json",
    ),
    (
        "per_symbol_fixture_tests",
        "tests/conformance/per_symbol_fixture_tests.v1.json",
    ),
    (
        "user_workload_acceptance_matrix",
        "tests/conformance/user_workload_acceptance_matrix.v1.json",
    ),
    (
        "hard_parts_truth_table",
        "tests/conformance/hard_parts_truth_table.v1.json",
    ),
    (
        "hard_parts_failure_matrix",
        "tests/conformance/hard_parts_e2e_failure_matrix.v1.json",
    ),
    (
        "feature_parity_gap_groups",
        "tests/conformance/feature_parity_gap_groups.v1.json",
    ),
];
const COMPLETED_UNISTD_PROCESS_FILESYSTEM_FIRST_WAVE: &[&str] = &[
    "_Exit",
    "_Fork",
    "__cxa_atexit",
    "__cxa_finalize",
    "__fxstat",
    "__fxstat64",
    "__fxstatat",
    "__fxstatat64",
    "__gmtime_r",
    "__lxstat",
    "__lxstat64",
    "__progname",
];
const COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03: &[&str] = &[
    "addseverity",
    "adjtimex",
    "aio_cancel",
    "aio_cancel64",
    "aio_error",
    "aio_error64",
    "aio_fsync",
    "aio_fsync64",
    "aio_init",
    "aio_read",
    "aio_read64",
    "aio_return",
];
const COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04: &[&str] = &[
    "aio_return64",
    "aio_suspend",
    "aio_suspend64",
    "aio_write",
    "aio_write64",
    "alarm",
    "arc4random",
    "arc4random_buf",
    "arc4random_uniform",
    "argp_error",
    "argp_failure",
    "argp_help",
];
const COMPLETED_STDIO_LIBIO_FIRST_WAVE: &[&str] = &[
    "_IO_2_1_stderr_",
    "_IO_2_1_stdin_",
    "_IO_2_1_stdout_",
    "_IO_feof",
    "_IO_ferror",
    "_IO_flockfile",
    "_IO_ftrylockfile",
    "_IO_funlockfile",
    "_IO_getc",
    "_IO_padn",
    "_IO_peekc_locked",
    "_IO_putc",
];

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn load_prioritizer() -> serde_json::Value {
    load_json(&workspace_root().join("tests/conformance/fixture_coverage_prioritizer.v1.json"))
}

fn write_json(path: &Path, value: &serde_json::Value) {
    std::fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(value).unwrap()),
    )
    .expect("failed to write fixture-wave lifecycle JSON");
}

fn unique_output_dir(root: &Path, label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let path = root
        .join("target/conformance")
        .join(format!("{label}-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&path).expect("failed to create fixture-wave lifecycle output dir");
    path
}

fn run_prioritizer_gate(root: &Path, out_dir: &Path, envs: &[(&str, &Path)]) -> Output {
    let script = root.join("scripts/check_fixture_coverage_prioritizer.sh");
    let mut command = Command::new(&script);
    command
        .current_dir(root)
        .env("FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_SKIP_REGEN", "1")
        .env("FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_REPORT",
            out_dir.join("fixture_coverage_prioritizer.report.json"),
        )
        .env(
            "FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_LOG",
            out_dir.join("fixture_coverage_prioritizer.log.jsonl"),
        );
    for (key, value) in envs {
        command.env(key, value);
    }
    command
        .output()
        .expect("failed to run fixture coverage prioritizer gate")
}

#[test]
fn generator_self_test_and_canonical_check_pass() {
    let root = workspace_root();
    let generator = root.join("scripts/generate_fixture_coverage_prioritizer.py");
    assert!(
        generator.exists(),
        "missing {}",
        generator.strip_prefix(&root).unwrap().display()
    );

    let self_test = Command::new("python3")
        .arg(&generator)
        .arg("--self-test")
        .current_dir(&root)
        .output()
        .expect("failed to run generator self-test");
    assert!(
        self_test.status.success(),
        "generator self-test failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&self_test.stdout),
        String::from_utf8_lossy(&self_test.stderr)
    );

    let check = Command::new("python3")
        .arg(&generator)
        .arg("--check")
        .arg("--output")
        .arg(root.join("tests/conformance/fixture_coverage_prioritizer.v1.json"))
        .current_dir(&root)
        .output()
        .expect("failed to run generator check");
    assert!(
        check.status.success(),
        "generator canonical check failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn artifact_exists_and_has_required_shape() {
    let artifact = load_prioritizer();
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-bp8fl.4.1"));
    assert!(artifact["inputs"].is_object(), "inputs must be object");
    assert!(
        artifact["scoring_policy"].is_object(),
        "scoring_policy must be object"
    );
    assert!(artifact["campaigns"].is_array(), "campaigns must be array");
    assert!(
        artifact["deferred_modules"].is_array(),
        "deferred_modules must be array"
    );
    assert!(artifact["summary"].is_object(), "summary must be object");

    let root = workspace_root();
    let inputs = artifact["inputs"].as_object().unwrap();
    for (key, rel_path) in EXPECTED_INPUTS {
        assert_eq!(
            inputs.get(*key).and_then(|value| value.as_str()),
            Some(*rel_path),
            "inputs.{key} must point at the expected artifact"
        );
        assert!(
            root.join(rel_path).exists(),
            "declared input {rel_path} should exist"
        );
    }

    let log_fields: Vec<_> = artifact["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);
}

#[test]
fn feature_gap_input_is_live_and_grouped_for_prioritization() {
    let root = workspace_root();
    let artifact = load_prioritizer();
    let feature_gap_path = artifact["inputs"]["feature_parity_gap_groups"]
        .as_str()
        .expect("feature gap input should be a path");
    let feature_gaps = load_json(&root.join(feature_gap_path));

    assert_eq!(feature_gaps["schema_version"].as_str(), Some("v1"));
    assert_eq!(feature_gaps["bead"].as_str(), Some("bd-bp8fl.3.1"));
    assert!(
        feature_gaps["summary"]["ledger_gap_count"]
            .as_u64()
            .unwrap()
            > 0,
        "feature parity gap grouping input should contain live ledger gaps"
    );

    let axes: HashSet<_> = feature_gaps["required_grouping_axes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|axis| axis.as_str().unwrap())
        .collect();
    for axis in [
        "symbol_family",
        "source_owner",
        "evidence_artifacts",
        "priority",
    ] {
        assert!(axes.contains(axis), "missing grouping axis {axis}");
    }
}

#[test]
fn campaign_stats_match_fixture_coverage_inputs() {
    let root = workspace_root();
    let artifact = load_prioritizer();
    let coverage = load_json(&root.join("tests/conformance/symbol_fixture_coverage.v1.json"));
    let per_symbol = load_json(&root.join("tests/conformance/per_symbol_fixture_tests.v1.json"));

    let families: HashMap<String, serde_json::Value> = coverage["families"]
        .as_array()
        .unwrap()
        .iter()
        .map(|family| {
            (
                family["module"].as_str().unwrap().to_string(),
                family.clone(),
            )
        })
        .collect();
    let per_symbol_rows: HashMap<(String, String), serde_json::Value> =
        per_symbol["per_symbol_report"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    (
                        row["module"].as_str().unwrap().to_string(),
                        row["symbol"].as_str().unwrap().to_string(),
                    ),
                    row.clone(),
                )
            })
            .collect();

    for campaign in artifact["campaigns"].as_array().unwrap() {
        let id = campaign["campaign_id"].as_str().unwrap();
        let module = campaign["module"].as_str().unwrap();
        let family = families.get(module).expect("campaign module should exist");
        assert_eq!(
            campaign["target_total"].as_u64(),
            family["target_total"].as_u64(),
            "{id}: target_total mismatch"
        );
        assert_eq!(
            campaign["target_covered"].as_u64(),
            family["target_covered"].as_u64(),
            "{id}: target_covered mismatch"
        );
        assert_eq!(
            campaign["target_uncovered"].as_u64(),
            family["target_uncovered"].as_u64(),
            "{id}: target_uncovered mismatch"
        );
        assert_eq!(
            campaign["current_coverage_pct"].as_f64(),
            family["target_coverage_pct"].as_f64(),
            "{id}: current_coverage_pct mismatch"
        );

        let uncovered: HashSet<_> = family["target_uncovered_symbols"]
            .as_array()
            .unwrap()
            .iter()
            .map(|symbol| symbol.as_str().unwrap())
            .collect();
        let first_wave = campaign["first_wave_symbols"].as_array().unwrap();
        assert_eq!(
            campaign["first_wave_fixture_count"].as_u64(),
            Some(first_wave.len() as u64),
            "{id}: first_wave_fixture_count mismatch"
        );
        for symbol in first_wave {
            let symbol = symbol.as_str().unwrap();
            assert!(
                uncovered.contains(symbol),
                "{id}: first-wave symbol should be uncovered: {symbol}"
            );
            let row = per_symbol_rows
                .get(&(module.to_string(), symbol.to_string()))
                .expect("first-wave symbol should exist in per-symbol report");
            assert_eq!(
                row["has_fixtures"].as_bool(),
                Some(false),
                "{id}: first-wave symbol should not already have fixtures"
            );
        }
    }
}

#[test]
fn completed_unistd_first_wave_claim_has_fixture_and_harness_evidence() {
    let root = workspace_root();
    let artifact = load_prioritizer();
    let fixture =
        load_json(&root.join("tests/conformance/fixtures/unistd_process_filesystem.json"));
    let per_symbol = load_json(&root.join("tests/conformance/per_symbol_fixture_tests.v1.json"));
    let harness_path =
        root.join("crates/frankenlibc-harness/tests/unistd_process_filesystem_conformance_test.rs");
    let harness =
        std::fs::read_to_string(&harness_path).expect("unistd harness should be readable");

    let declared: Vec<_> = fixture["campaign"]["first_wave_symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|symbol| symbol.as_str().unwrap())
        .collect();
    assert_eq!(declared, COMPLETED_UNISTD_PROCESS_FILESYSTEM_FIRST_WAVE);

    let fixture_cases: HashSet<_> = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["function"].as_str().unwrap())
        .collect();
    let rows: HashMap<_, _> = per_symbol["per_symbol_report"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["module"].as_str() == Some("unistd_abi"))
        .map(|row| (row["symbol"].as_str().unwrap(), row))
        .collect();

    for symbol in COMPLETED_UNISTD_PROCESS_FILESYSTEM_FIRST_WAVE {
        assert!(
            fixture_cases.contains(symbol),
            "fixture is missing completed first-wave case for {symbol}"
        );
        let row = rows
            .get(symbol)
            .unwrap_or_else(|| panic!("per-symbol row missing for {symbol}"));
        assert_eq!(
            row["has_fixtures"].as_bool(),
            Some(true),
            "{symbol} must have fixture accounting"
        );
        assert!(
            row["case_count"].as_u64().unwrap() >= 2,
            "{symbol} must have strict+hardened cases"
        );
        let files: HashSet<_> = row["fixture_files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| file.as_str().unwrap())
            .collect();
        assert!(
            files.contains("unistd_process_filesystem.json"),
            "{symbol} must link to the unistd process/filesystem fixture"
        );
        let modes: HashSet<_> = row["modes_tested"]
            .as_array()
            .unwrap()
            .iter()
            .map(|mode| mode.as_str().unwrap())
            .collect();
        assert_eq!(
            modes,
            HashSet::from(["strict", "hardened"]),
            "{symbol} must have both runtime modes"
        );
    }

    for needle in [
        "unistd_process_filesystem_fixture_covers_first_wave_symbols_in_both_modes",
        "unistd_process_filesystem_fixture_executes_via_isolated_harness",
        "failure_signature",
    ] {
        assert!(
            harness.contains(needle),
            "harness missing required guard needle {needle}"
        );
    }

    let unistd_campaign = artifact["campaigns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|campaign| campaign["campaign_id"].as_str() == Some("fcq-unistd-process-filesystem"))
        .expect("unistd campaign should remain present");
    let next_first_wave: HashSet<_> = unistd_campaign["first_wave_symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|symbol| symbol.as_str().unwrap())
        .collect();
    for symbol in COMPLETED_UNISTD_PROCESS_FILESYSTEM_FIRST_WAVE {
        assert!(
            !next_first_wave.contains(symbol),
            "completed symbol {symbol} must not remain in the next first-wave claim"
        );
    }
    assert!(
        unistd_campaign["target_covered"].as_u64().unwrap() >= 47,
        "unistd target_covered must advance after first-wave fixture landing"
    );
    assert!(
        unistd_campaign["current_coverage_pct"].as_f64().unwrap() >= 6.33,
        "unistd coverage pct must advance after first-wave fixture landing"
    );
}

#[test]
fn completed_unistd_wave03_claim_has_fixture_and_harness_evidence() {
    let root = workspace_root();
    let artifact = load_prioritizer();
    let fixture =
        load_json(&root.join("tests/conformance/fixtures/unistd_process_filesystem_wave03.json"));
    let per_symbol = load_json(&root.join("tests/conformance/per_symbol_fixture_tests.v1.json"));
    let harness_path = root.join(
        "crates/frankenlibc-harness/tests/unistd_process_filesystem_wave03_conformance_test.rs",
    );
    let harness =
        std::fs::read_to_string(&harness_path).expect("unistd wave-03 harness should be readable");

    assert_eq!(
        fixture["campaign"]["wave_id"].as_str(),
        Some("wave-03-unistd-process-filesystem-aio-time")
    );
    let declared: Vec<_> = fixture["campaign"]["first_wave_symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|symbol| symbol.as_str().unwrap())
        .collect();
    assert_eq!(declared, COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03);

    let fixture_cases: HashSet<_> = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["function"].as_str().unwrap())
        .collect();
    let rows: HashMap<_, _> = per_symbol["per_symbol_report"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["module"].as_str() == Some("unistd_abi"))
        .map(|row| (row["symbol"].as_str().unwrap(), row))
        .collect();

    for symbol in COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03 {
        assert!(
            fixture_cases.contains(symbol),
            "fixture is missing completed wave-03 case for {symbol}"
        );
        let row = rows
            .get(symbol)
            .unwrap_or_else(|| panic!("per-symbol row missing for {symbol}"));
        assert_eq!(
            row["has_fixtures"].as_bool(),
            Some(true),
            "{symbol} must have fixture accounting"
        );
        assert!(
            row["case_count"].as_u64().unwrap() >= 2,
            "{symbol} must have strict+hardened cases"
        );
        let files: HashSet<_> = row["fixture_files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| file.as_str().unwrap())
            .collect();
        assert!(
            files.contains("unistd_process_filesystem_wave03.json"),
            "{symbol} must link to the unistd wave-03 fixture"
        );
        let modes: HashSet<_> = row["modes_tested"]
            .as_array()
            .unwrap()
            .iter()
            .map(|mode| mode.as_str().unwrap())
            .collect();
        assert_eq!(
            modes,
            HashSet::from(["strict", "hardened"]),
            "{symbol} must have both runtime modes"
        );
    }

    for needle in [
        "unistd_process_filesystem_wave03_covers_first_wave_in_both_modes",
        "unistd_process_filesystem_wave03_executes_via_isolated_harness",
        "forbid_ambient_aio_time_fd_or_scheduler_metadata",
        "failure_signature",
    ] {
        assert!(
            harness.contains(needle),
            "harness missing required guard needle {needle}"
        );
    }

    let unistd_campaign = artifact["campaigns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|campaign| campaign["campaign_id"].as_str() == Some("fcq-unistd-process-filesystem"))
        .expect("unistd campaign should remain present");
    let next_first_wave: HashSet<_> = unistd_campaign["first_wave_symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|symbol| symbol.as_str().unwrap())
        .collect();
    for symbol in COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03 {
        assert!(
            !next_first_wave.contains(symbol),
            "completed wave-03 symbol {symbol} must not remain in the next first-wave claim"
        );
    }
    assert!(
        unistd_campaign["target_covered"].as_u64().unwrap() >= 71,
        "unistd target_covered must stay at or above the wave-03 closeout"
    );
    assert!(
        unistd_campaign["target_uncovered"].as_u64().unwrap() <= 671,
        "unistd target_uncovered must stay at or below the wave-03 closeout"
    );
    assert!(
        unistd_campaign["current_coverage_pct"].as_f64().unwrap() >= 9.57,
        "unistd coverage pct must stay at or above the wave-03 closeout"
    );
    assert!(
        unistd_campaign["expected_coverage_after_first_wave_pct"]
            .as_f64()
            .unwrap()
            >= 11.19,
        "unistd next-wave expected coverage must stay at or above the wave-03 closeout"
    );
}

#[test]
fn completed_unistd_wave04_claim_has_fixture_and_harness_evidence() {
    let root = workspace_root();
    let artifact = load_prioritizer();
    let fixture =
        load_json(&root.join("tests/conformance/fixtures/unistd_process_filesystem_wave04.json"));
    let per_symbol = load_json(&root.join("tests/conformance/per_symbol_fixture_tests.v1.json"));
    let harness_path = root.join(
        "crates/frankenlibc-harness/tests/unistd_process_filesystem_wave04_conformance_test.rs",
    );
    let harness =
        std::fs::read_to_string(&harness_path).expect("unistd wave-04 harness should be readable");

    assert_eq!(
        fixture["campaign"]["wave_id"].as_str(),
        Some("wave-04-unistd-process-filesystem-aio-random-argp")
    );
    let declared: Vec<_> = fixture["campaign"]["first_wave_symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|symbol| symbol.as_str().unwrap())
        .collect();
    assert_eq!(declared, COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04);

    let fixture_cases: HashSet<_> = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["function"].as_str().unwrap())
        .collect();
    let rows: HashMap<_, _> = per_symbol["per_symbol_report"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["module"].as_str() == Some("unistd_abi"))
        .map(|row| (row["symbol"].as_str().unwrap(), row))
        .collect();

    for symbol in COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04 {
        assert!(
            fixture_cases.contains(symbol),
            "fixture is missing completed wave-04 case for {symbol}"
        );
        let row = rows
            .get(symbol)
            .unwrap_or_else(|| panic!("per-symbol row missing for {symbol}"));
        assert_eq!(
            row["has_fixtures"].as_bool(),
            Some(true),
            "{symbol} must have fixture accounting"
        );
        assert!(
            row["case_count"].as_u64().unwrap() >= 2,
            "{symbol} must have strict+hardened cases"
        );
        let files: HashSet<_> = row["fixture_files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| file.as_str().unwrap())
            .collect();
        assert!(
            files.contains("unistd_process_filesystem_wave04.json"),
            "{symbol} must link to the unistd wave-04 fixture"
        );
        let modes: HashSet<_> = row["modes_tested"]
            .as_array()
            .unwrap()
            .iter()
            .map(|mode| mode.as_str().unwrap())
            .collect();
        assert_eq!(
            modes,
            HashSet::from(["strict", "hardened"]),
            "{symbol} must have both runtime modes"
        );
    }

    for needle in [
        "unistd_process_filesystem_wave04_covers_first_wave_in_both_modes",
        "unistd_process_filesystem_wave04_executes_via_isolated_harness",
        "forbid_ambient_random_values_alarm_state_argp_streams_or_aio_fd_metadata",
        "failure_signature",
    ] {
        assert!(
            harness.contains(needle),
            "harness missing required guard needle {needle}"
        );
    }

    let unistd_campaign = artifact["campaigns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|campaign| campaign["campaign_id"].as_str() == Some("fcq-unistd-process-filesystem"))
        .expect("unistd campaign should remain present");
    let next_first_wave: HashSet<_> = unistd_campaign["first_wave_symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|symbol| symbol.as_str().unwrap())
        .collect();
    for symbol in COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04 {
        assert!(
            !next_first_wave.contains(symbol),
            "completed wave-04 symbol {symbol} must not remain in the next first-wave claim"
        );
    }
    assert!(
        unistd_campaign["target_covered"].as_u64().unwrap() >= 95,
        "unistd target_covered must stay at or above the wave-05 closeout"
    );
    assert!(
        unistd_campaign["target_uncovered"].as_u64().unwrap() <= 647,
        "unistd target_uncovered must stay at or below the wave-05 closeout"
    );
    assert!(
        unistd_campaign["current_coverage_pct"].as_f64().unwrap() >= 12.8,
        "unistd coverage pct must stay at or above the wave-05 closeout"
    );
    assert!(
        unistd_campaign["expected_coverage_after_first_wave_pct"]
            .as_f64()
            .unwrap()
            >= 14.42,
        "unistd next-wave expected coverage must stay at or above the wave-05 closeout"
    );
}

#[test]
fn completed_stdio_libio_first_wave_claim_has_fixture_and_harness_evidence() {
    let root = workspace_root();
    let artifact = load_prioritizer();
    let fixture = load_json(&root.join("tests/conformance/fixtures/stdio_libio_symbols.json"));
    let per_symbol = load_json(&root.join("tests/conformance/per_symbol_fixture_tests.v1.json"));
    let harness_path =
        root.join("crates/frankenlibc-harness/tests/stdio_libio_symbols_conformance_test.rs");
    let harness =
        std::fs::read_to_string(&harness_path).expect("stdio/libio harness should be readable");

    let declared: Vec<_> = fixture["campaign"]["first_wave_symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|symbol| symbol.as_str().unwrap())
        .collect();
    assert_eq!(declared, COMPLETED_STDIO_LIBIO_FIRST_WAVE);

    let fixture_cases: HashSet<_> = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["function"].as_str().unwrap())
        .collect();
    let rows: HashMap<_, _> = per_symbol["per_symbol_report"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["module"].as_str() == Some("stdio_abi"))
        .map(|row| (row["symbol"].as_str().unwrap(), row))
        .collect();

    for symbol in COMPLETED_STDIO_LIBIO_FIRST_WAVE {
        assert!(
            fixture_cases.contains(symbol),
            "fixture is missing completed first-wave case for {symbol}"
        );
        let row = rows
            .get(symbol)
            .unwrap_or_else(|| panic!("per-symbol row missing for {symbol}"));
        assert_eq!(
            row["has_fixtures"].as_bool(),
            Some(true),
            "{symbol} must have fixture accounting"
        );
        assert!(
            row["case_count"].as_u64().unwrap() >= 2,
            "{symbol} must have strict+hardened cases"
        );
        let files: HashSet<_> = row["fixture_files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| file.as_str().unwrap())
            .collect();
        assert!(
            files.contains("stdio_libio_symbols.json"),
            "{symbol} must link to the stdio/libio symbol fixture"
        );
        let modes: HashSet<_> = row["modes_tested"]
            .as_array()
            .unwrap()
            .iter()
            .map(|mode| mode.as_str().unwrap())
            .collect();
        assert_eq!(
            modes,
            HashSet::from(["strict", "hardened"]),
            "{symbol} must have both runtime modes"
        );
    }

    for needle in [
        "stdio_libio_symbols_cover_first_wave_in_both_modes",
        "stdio_libio_symbols_fixture_executes_via_isolated_harness",
        "failure_signature",
    ] {
        assert!(
            harness.contains(needle),
            "harness missing required guard needle {needle}"
        );
    }

    let stdio_campaign = artifact["campaigns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|campaign| campaign["campaign_id"].as_str() == Some("fcq-stdio-libio"))
        .expect("stdio/libio campaign should remain present");
    let next_first_wave: HashSet<_> = stdio_campaign["first_wave_symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|symbol| symbol.as_str().unwrap())
        .collect();
    for symbol in COMPLETED_STDIO_LIBIO_FIRST_WAVE {
        assert!(
            !next_first_wave.contains(symbol),
            "completed symbol {symbol} must not remain in the next first-wave claim"
        );
    }
    assert!(
        stdio_campaign["target_covered"].as_u64().unwrap() >= 6,
        "stdio/libio target_covered must advance after first-wave fixture landing"
    );
    assert!(
        stdio_campaign["current_coverage_pct"].as_f64().unwrap() >= 60.0,
        "stdio/libio coverage pct must advance after first-wave fixture landing"
    );
}

#[test]
fn deferred_modules_cover_every_unselected_uncovered_family() {
    let root = workspace_root();
    let artifact = load_prioritizer();
    let coverage = load_json(&root.join("tests/conformance/symbol_fixture_coverage.v1.json"));

    let campaign_modules: HashSet<String> = artifact["campaigns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|campaign| campaign["module"].as_str().unwrap().to_string())
        .collect();

    let mut expected = Vec::new();
    for family in coverage["families"].as_array().unwrap() {
        let module = family["module"].as_str().unwrap();
        let target_uncovered = family["target_uncovered"].as_u64().unwrap();
        if target_uncovered > 0 && !campaign_modules.contains(module) {
            expected.push((module.to_string(), family.clone()));
        }
    }
    expected.sort_by(|left, right| {
        let left_uncovered = left.1["target_uncovered"].as_u64().unwrap();
        let right_uncovered = right.1["target_uncovered"].as_u64().unwrap();
        right_uncovered
            .cmp(&left_uncovered)
            .then_with(|| left.0.cmp(&right.0))
    });

    let deferred = artifact["deferred_modules"].as_array().unwrap();
    assert_eq!(
        deferred.len(),
        expected.len(),
        "every uncovered non-campaign family should be explicitly deferred"
    );

    let mut deferred_uncovered = 0_u64;
    for (row, (expected_module, family)) in deferred.iter().zip(expected.iter()) {
        assert_eq!(row["module"].as_str(), Some(expected_module.as_str()));
        assert_eq!(row["target_total"], family["target_total"]);
        assert_eq!(row["target_covered"], family["target_covered"]);
        assert_eq!(row["target_uncovered"], family["target_uncovered"]);
        assert_eq!(row["current_coverage_pct"], family["target_coverage_pct"]);
        assert_eq!(row["status_breakdown"], family["status_breakdown"]);
        assert!(
            !row["deferral_reason"].as_str().unwrap().trim().is_empty(),
            "{expected_module}: deferral_reason must explain why the family is not first-wave"
        );
        assert!(
            !row["next_step"].as_str().unwrap().trim().is_empty(),
            "{expected_module}: next_step must keep the family actionable"
        );
        deferred_uncovered += row["target_uncovered"].as_u64().unwrap();
    }

    let selected_uncovered: u64 = artifact["campaigns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|campaign| campaign["target_uncovered"].as_u64().unwrap())
        .sum();
    assert_eq!(
        artifact["summary"]["deferred_module_count"].as_u64(),
        Some(deferred.len() as u64)
    );
    assert_eq!(
        artifact["summary"]["selected_target_uncovered_symbols"].as_u64(),
        Some(selected_uncovered)
    );
    assert_eq!(
        artifact["summary"]["deferred_target_uncovered_symbols"].as_u64(),
        Some(deferred_uncovered)
    );
    assert_eq!(
        artifact["summary"]["all_uncovered_target_symbols"].as_u64(),
        Some(selected_uncovered + deferred_uncovered)
    );
}

#[test]
fn priority_scores_and_summary_are_consistent() {
    let artifact = load_prioritizer();
    let campaigns = artifact["campaigns"].as_array().unwrap();
    let mut previous_score = i64::MAX;
    let mut modules = Vec::new();
    let mut domains = HashSet::new();
    let mut first_wave_total = 0_u64;

    for (index, campaign) in campaigns.iter().enumerate() {
        let id = campaign["campaign_id"].as_str().unwrap();
        assert_eq!(
            campaign["rank"].as_u64(),
            Some((index + 1) as u64),
            "{id}: rank mismatch"
        );
        let scores = &campaign["scores"];
        let coverage_gap = campaign["target_uncovered"].as_u64().unwrap().min(200);
        let priority = coverage_gap as i64
            + 300 * scores["workload_risk_score"].as_i64().unwrap()
            + 200 * scores["parity_risk_score"].as_i64().unwrap()
            - 50 * scores["implementation_complexity_score"].as_i64().unwrap();
        assert_eq!(
            scores["coverage_gap_score"].as_i64(),
            Some(coverage_gap as i64),
            "{id}: coverage_gap_score mismatch"
        );
        assert_eq!(
            scores["priority_score"].as_i64(),
            Some(priority),
            "{id}: priority_score mismatch"
        );
        assert!(
            priority <= previous_score,
            "{id}: campaigns must be sorted by descending priority"
        );
        previous_score = priority;

        modules.push(campaign["module"].as_str().unwrap().to_string());
        first_wave_total += campaign["first_wave_fixture_count"].as_u64().unwrap();
        for domain in campaign["workload_domains"].as_array().unwrap() {
            domains.insert(domain.as_str().unwrap().to_string());
        }
    }
    for source in artifact["fully_covered_workload_domain_sources"]
        .as_array()
        .unwrap()
    {
        assert_eq!(
            source["coverage_state"].as_str(),
            Some("covered"),
            "fully covered workload domain source must be closed"
        );
        assert_eq!(
            source["target_uncovered"].as_u64(),
            Some(0),
            "fully covered workload domain source must have no target gaps"
        );
        for domain in source["workload_domains"].as_array().unwrap() {
            domains.insert(domain.as_str().unwrap().to_string());
        }
    }

    modules.sort();
    let mut required_domains: Vec<_> = [
        "allocator",
        "build_tools",
        "language_runtimes",
        "locale_iconv",
        "package_manager",
        "performance_sensitive",
        "resolver_nss",
        "shell_coreutils",
        "startup_linking",
        "stdio_libio",
        "threaded_services",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    required_domains.sort();

    assert_eq!(
        artifact["summary"]["campaign_count"].as_u64(),
        Some(campaigns.len() as u64)
    );
    assert_eq!(
        artifact["summary"]["total_first_wave_fixture_count"].as_u64(),
        Some(first_wave_total)
    );
    assert_eq!(
        artifact["summary"]["covered_modules"],
        serde_json::to_value(modules).unwrap()
    );
    for domain in &required_domains {
        assert!(
            domains.contains(domain),
            "required workload domain {domain} must be covered"
        );
    }
    assert_eq!(
        artifact["summary"]["required_workload_domains_covered"],
        serde_json::to_value(required_domains).unwrap()
    );
}

#[test]
fn gate_script_passes_and_emits_structured_report_and_log() {
    let root = workspace_root();
    let script = root.join("scripts/check_fixture_coverage_prioritizer.sh");
    assert!(
        script.exists(),
        "missing {}",
        script.strip_prefix(&root).unwrap().display()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_fixture_coverage_prioritizer.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run fixture coverage prioritizer gate");
    assert!(
        output.status.success(),
        "fixture coverage prioritizer gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/fixture_coverage_prioritizer.report.json");
    let log_path = root.join("target/conformance/fixture_coverage_prioritizer.log.jsonl");
    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.4.1"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    for check in [
        "json_parse",
        "top_level_shape",
        "required_log_fields",
        "inputs_and_feature_gap_refs",
        "campaign_schema",
        "completed_unistd_first_wave_guard",
        "completed_unistd_wave03_guard",
        "completed_unistd_wave04_guard",
        "completed_stdio_libio_first_wave_guard",
        "fixture_wave_lifecycle",
        "deferred_module_inventory",
        "priority_order",
        "workload_domain_coverage",
        "summary_counts",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "report checks.{check} should pass"
        );
    }

    let log_line = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should contain at least one row")
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&log_line).expect("log row should parse");
    for key in REQUIRED_LOG_FIELDS {
        assert!(
            event.get(*key).is_some(),
            "structured log row missing {key}"
        );
    }

    let lifecycle_rows = report["fixture_wave_lifecycle"]
        .as_array()
        .expect("report should include fixture-wave lifecycle rows");
    for fixture in [
        "string_memory_hotpaths_wave05.json",
        "string_memory_hotpaths_wave06.json",
        "string_memory_hotpaths_wave10.json",
        "string_memory_hotpaths_wave11.json",
    ] {
        let row = lifecycle_rows
            .iter()
            .find(|row| row["fixture_basename"].as_str() == Some(fixture))
            .expect("missing lifecycle row for required string fixture");
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert_eq!(row["failure_signature"].as_str(), Some("none"));
        assert_eq!(row["contract_required"].as_bool(), Some(true));
        assert_eq!(row["missing_completion_contract"].as_bool(), Some(false));
        assert!(
            row["completion_contract_path"].as_str().is_some(),
            "{fixture} should bind to a completion contract"
        );
        for field in [
            "fixture_file",
            "fixture_family",
            "wave_id",
            "covered_symbols",
            "missing_coverage_artifacts",
            "missing_completion_contract",
            "failure_signature",
        ] {
            assert!(row.get(field).is_some(), "lifecycle row missing {field}");
        }
    }

    let lifecycle_log = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .any(|row| {
            row["bead_id"].as_str() == Some("bd-waaa6.3")
                && row["fixture_file"]
                    .as_str()
                    .is_some_and(|file| file.ends_with("string_memory_hotpaths_wave05.json"))
        });
    assert!(
        lifecycle_log,
        "log should include fixture-wave lifecycle rows"
    );
}

#[test]
fn gate_rejects_copied_wave_fixture_missing_coverage_accounting() {
    let root = workspace_root();
    let out_dir = unique_output_dir(&root, "fixture-wave-missing-coverage");
    let fixtures_dir = out_dir.join("fixtures");
    std::fs::create_dir_all(&fixtures_dir).unwrap();

    let mut fixture =
        load_json(&root.join("tests/conformance/fixtures/string_memory_hotpaths_wave05.json"));
    let missing_symbol = "__franken_missing_fixture_wave_symbol";
    fixture["campaign"]["first_wave_symbols"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::Value::String(missing_symbol.to_string()));
    let cases = fixture["cases"].as_array_mut().unwrap();
    cases.push(serde_json::json!({
        "name": "franken_missing_strict",
        "function": missing_symbol,
        "mode": "strict",
        "expected_output": "symbol=__franken_missing_fixture_wave_symbol;mode=strict;expected=missing;actual=missing;failure_signature=none",
        "expected_errno": 0
    }));
    cases.push(serde_json::json!({
        "name": "franken_missing_hardened",
        "function": missing_symbol,
        "mode": "hardened",
        "expected_output": "symbol=__franken_missing_fixture_wave_symbol;mode=hardened;expected=missing;actual=missing;failure_signature=none",
        "expected_errno": 0
    }));
    write_json(
        &fixtures_dir.join("string_memory_hotpaths_wave05.json"),
        &fixture,
    );

    let output = run_prioritizer_gate(
        &root,
        &out_dir,
        &[(
            "FRANKENLIBC_FIXTURE_WAVE_LIFECYCLE_FIXTURES_DIR",
            fixtures_dir.as_path(),
        )],
    );
    assert!(
        !output.status.success(),
        "gate unexpectedly passed stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("fixture_coverage_prioritizer.report.json"));
    let row = report["fixture_wave_lifecycle"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["fixture_basename"].as_str() == Some("string_memory_hotpaths_wave05.json"))
        .expect("copied wave fixture should have a lifecycle row");
    assert_eq!(
        row["failure_signature"].as_str(),
        Some("missing_coverage_artifact")
    );
    let missing_artifacts: HashSet<_> = row["missing_coverage_artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert!(missing_artifacts.contains("symbol_fixture_coverage.v1.json"));
    assert!(missing_artifacts.contains("per_symbol_fixture_tests.v1.json"));
}

#[test]
fn gate_rejects_required_wave_fixture_without_completion_contract() {
    let root = workspace_root();
    let out_dir = unique_output_dir(&root, "fixture-wave-missing-contract");
    let fixtures_dir = out_dir.join("fixtures");
    let contracts_dir = out_dir.join("contracts");
    std::fs::create_dir_all(&fixtures_dir).unwrap();
    std::fs::create_dir_all(&contracts_dir).unwrap();

    std::fs::copy(
        root.join("tests/conformance/fixtures/string_memory_hotpaths_wave05.json"),
        fixtures_dir.join("string_memory_hotpaths_wave05.json"),
    )
    .unwrap();
    let empty_contract_glob = contracts_dir.join("*.json");

    let output = run_prioritizer_gate(
        &root,
        &out_dir,
        &[
            (
                "FRANKENLIBC_FIXTURE_WAVE_LIFECYCLE_FIXTURES_DIR",
                fixtures_dir.as_path(),
            ),
            (
                "FRANKENLIBC_FIXTURE_WAVE_LIFECYCLE_CONTRACT_GLOB",
                empty_contract_glob.as_path(),
            ),
        ],
    );
    assert!(
        !output.status.success(),
        "gate unexpectedly passed stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("fixture_coverage_prioritizer.report.json"));
    let row = report["fixture_wave_lifecycle"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["fixture_basename"].as_str() == Some("string_memory_hotpaths_wave05.json"))
        .expect("required wave fixture should have a lifecycle row");
    assert_eq!(
        row["failure_signature"].as_str(),
        Some("missing_completion_contract")
    );
    assert_eq!(row["contract_required"].as_bool(), Some(true));
    assert_eq!(row["missing_completion_contract"].as_bool(), Some(true));
}
