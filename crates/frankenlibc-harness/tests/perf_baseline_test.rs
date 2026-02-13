//! Integration test: Perf baseline suite spec (bd-2wp)
//!
//! Validates that:
//! 1. The perf baseline spec JSON exists and is valid.
//! 2. Benchmark suites reference existing crates.
//! 3. Baseline file exists and covers enforced suites.
//! 4. Percentile targets are well-defined.
//! 5. Regeneration procedure is complete.
//! 6. Cross-references to perf_budget_policy are consistent.
//! 7. Summary statistics are consistent.
//! 8. Gate script exists and is executable.
//!
//! Run: cargo test -p frankenlibc-harness --test perf_baseline_test

use std::collections::HashSet;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_spec() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/perf_baseline_spec.json");
    let content = std::fs::read_to_string(&path).expect("perf_baseline_spec.json should exist");
    serde_json::from_str(&content).expect("perf_baseline_spec.json should be valid JSON")
}

fn load_baseline() -> serde_json::Value {
    let path = workspace_root().join("scripts/perf_baseline.json");
    let content = std::fs::read_to_string(&path).expect("perf_baseline.json should exist");
    serde_json::from_str(&content).expect("perf_baseline.json should be valid JSON")
}

fn load_budget_policy() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/perf_budget_policy.json");
    let content = std::fs::read_to_string(&path).expect("perf_budget_policy.json should exist");
    serde_json::from_str(&content).expect("perf_budget_policy.json should be valid JSON")
}

#[test]
fn spec_exists_and_valid() {
    let s = load_spec();
    assert!(s["schema_version"].is_number(), "Missing schema_version");
    assert!(
        s["benchmark_suites"]["suites"].is_array(),
        "Missing benchmark_suites.suites"
    );
    assert!(
        s["percentile_targets"].is_object(),
        "Missing percentile_targets"
    );
    assert!(s["regeneration"].is_object(), "Missing regeneration");
    assert!(
        s["regression_detection"].is_object(),
        "Missing regression_detection"
    );
    assert!(s["summary"].is_object(), "Missing summary");
}

#[test]
fn benchmark_suites_reference_valid_crates() {
    let s = load_spec();
    let root = workspace_root();
    let suites = s["benchmark_suites"]["suites"].as_array().unwrap();

    assert!(suites.len() >= 2, "Need at least 2 benchmark suites");

    for suite in suites {
        let sid = suite["id"].as_str().unwrap();
        let crate_name = suite["crate"].as_str().unwrap();
        let crate_dir = root.join("crates").join(crate_name);
        assert!(
            crate_dir.exists(),
            "{sid}: crate directory not found: crates/{crate_name}"
        );

        let command = suite["command"].as_str().unwrap();
        assert!(
            command.contains("--bench"),
            "{sid}: command missing --bench flag"
        );

        let benchmarks = suite["benchmarks"].as_array().unwrap();
        assert!(!benchmarks.is_empty(), "{sid}: no benchmarks defined");

        let modes = suite["modes"].as_array().unwrap();
        assert!(!modes.is_empty(), "{sid}: no modes defined");

        for bench in benchmarks {
            assert!(bench["name"].is_string(), "{sid}: benchmark missing name");
            assert!(
                bench["description"].is_string(),
                "{sid}/{}: missing description",
                bench["name"].as_str().unwrap_or("?")
            );
        }
    }
}

#[test]
fn baseline_covers_enforced_suites() {
    let s = load_spec();
    let baseline = load_baseline();
    let suites = s["benchmark_suites"]["suites"].as_array().unwrap();

    let p50 = &baseline["baseline_p50_ns_op"];

    for suite in suites {
        if !suite["enforced_in_gate"].as_bool().unwrap_or(false) {
            continue;
        }
        let sid = suite["id"].as_str().unwrap();
        assert!(
            p50[sid].is_object(),
            "Enforced suite '{sid}' missing from baseline_p50_ns_op"
        );

        for mode in suite["modes"].as_array().unwrap() {
            let mode_str = mode.as_str().unwrap();
            assert!(
                p50[sid][mode_str].is_object(),
                "{sid}/{mode_str}: mode missing from baseline"
            );

            for bench in suite["benchmarks"].as_array().unwrap() {
                let bname = bench["name"].as_str().unwrap();
                assert!(
                    p50[sid][mode_str][bname].is_number(),
                    "{sid}/{mode_str}/{bname}: missing from baseline"
                );
            }
        }
    }
}

#[test]
fn percentile_targets_well_defined() {
    let s = load_spec();
    let pct = &s["percentile_targets"];

    let captured: HashSet<&str> = pct["captured_percentiles"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    assert!(captured.contains("p50"), "Must capture p50");
    assert!(captured.contains("p95"), "Must capture p95");
    assert!(captured.contains("p99"), "Must capture p99");

    assert_eq!(
        pct["primary_gate_metric"].as_str().unwrap(),
        "p50",
        "Primary gate metric must be p50"
    );

    let gate_behavior = &pct["gate_behavior"];
    for p in &["p50", "p95", "p99"] {
        assert!(
            gate_behavior[p].is_string(),
            "Missing gate_behavior for {p}"
        );
    }
}

#[test]
fn regeneration_procedure_complete() {
    let s = load_spec();
    let regen = &s["regeneration"];

    let prereqs = regen["prerequisites"].as_array().unwrap();
    assert!(
        prereqs.len() >= 2,
        "Need at least 2 prerequisites, got {}",
        prereqs.len()
    );

    let commands = regen["command_sequence"].as_array().unwrap();
    assert!(
        commands.len() >= 2,
        "Need at least 2 commands, got {}",
        commands.len()
    );

    let cmd_text: String = commands
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    assert!(
        cmd_text.contains("cargo bench"),
        "Command sequence must include cargo bench"
    );

    let validation = &regen["validation"];
    assert!(
        validation["min_repeat_runs"].is_u64(),
        "Missing min_repeat_runs"
    );
    assert!(
        validation["max_cv_pct"].is_u64() || validation["max_cv_pct"].is_f64(),
        "Missing max_cv_pct"
    );

    assert!(
        regen["update_policy"].is_string() && !regen["update_policy"].as_str().unwrap().is_empty(),
        "Missing update_policy"
    );
}

#[test]
fn profile_artifact_contract_defined() {
    let s = load_spec();
    let artifacts = &s["profile_artifacts"];
    assert!(
        artifacts.is_object(),
        "Missing profile_artifacts section in perf_baseline_spec.json"
    );

    let required_files = artifacts["required_files"]
        .as_array()
        .expect("profile_artifacts.required_files must be an array");
    let required_set: HashSet<&str> = required_files.iter().filter_map(|v| v.as_str()).collect();
    for req in [
        "manifest.txt",
        "commands.log",
        "summary.log",
        "targets.tsv",
        "profile_report.v1.json",
        "hotspot_opportunity_matrix.v1.json",
    ] {
        assert!(
            required_set.contains(req),
            "profile_artifacts.required_files missing {req}"
        );
    }

    let per_target = artifacts["per_target_required"]
        .as_array()
        .expect("profile_artifacts.per_target_required must be an array");
    let per_target_set: HashSet<&str> = per_target.iter().filter_map(|v| v.as_str()).collect();
    for req in [
        "cpu/<slug>.top5.txt",
        "alloc/<slug>.top5.txt",
        "syscall/<slug>.top5.txt",
    ] {
        assert!(
            per_target_set.contains(req),
            "profile_artifacts.per_target_required missing {req}"
        );
    }

    let structured = &artifacts["structured_reports"];
    let profile_report_fields = structured["profile_report_v1"]["required_fields"]
        .as_array()
        .expect("profile_report_v1.required_fields must be an array");
    let profile_report_set: HashSet<&str> = profile_report_fields
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for req in [
        "schema_version",
        "generated_at_utc",
        "run",
        "targets",
        "summary",
    ] {
        assert!(
            profile_report_set.contains(req),
            "profile_report_v1.required_fields missing {req}"
        );
    }

    let hotspot_fields = structured["hotspot_opportunity_matrix_v1"]["required_fields"]
        .as_array()
        .expect("hotspot_opportunity_matrix_v1.required_fields must be an array");
    let hotspot_set: HashSet<&str> = hotspot_fields.iter().filter_map(|v| v.as_str()).collect();
    for req in [
        "schema_version",
        "generated_at_utc",
        "source_run",
        "scoring",
        "entries",
        "summary",
    ] {
        assert!(
            hotspot_set.contains(req),
            "hotspot_opportunity_matrix_v1.required_fields missing {req}"
        );
    }

    let summary_required_files = s["summary"]["profile_required_files"]
        .as_u64()
        .expect("summary.profile_required_files missing") as usize;
    assert_eq!(
        summary_required_files,
        required_files.len(),
        "summary.profile_required_files must match required_files length"
    );
}

#[test]
fn regression_thresholds_match_budget_policy() {
    let s = load_spec();
    let budget = load_budget_policy();

    let spec_max_regression = s["regression_detection"]["max_regression_pct"]
        .as_f64()
        .unwrap();
    let budget_max_regression = budget["regression_policy"]["max_regression_pct"]
        .as_f64()
        .unwrap();

    assert_eq!(
        spec_max_regression, budget_max_regression,
        "max_regression_pct must match between baseline spec ({spec_max_regression}) and budget policy ({budget_max_regression})"
    );
}

#[test]
fn summary_consistent() {
    let s = load_spec();
    let summary = &s["summary"];
    let suites = s["benchmark_suites"]["suites"].as_array().unwrap();
    let pct = s["percentile_targets"]["captured_percentiles"]
        .as_array()
        .unwrap();
    let regen_steps = s["regeneration"]["command_sequence"]
        .as_array()
        .unwrap()
        .len();
    let prereq_checks = s["regeneration"]["prerequisites"].as_array().unwrap().len();

    let total_benchmarks: usize = suites
        .iter()
        .map(|s| s["benchmarks"].as_array().unwrap().len())
        .sum();

    let enforced_count = suites
        .iter()
        .filter(|s| s["enforced_in_gate"].as_bool().unwrap_or(false))
        .count();
    let planned_count = suites
        .iter()
        .filter(|s| !s["enforced_in_gate"].as_bool().unwrap_or(false))
        .count();

    let mut modes = HashSet::new();
    for suite in suites {
        for m in suite["modes"].as_array().unwrap() {
            modes.insert(m.as_str().unwrap().to_string());
        }
    }

    assert_eq!(
        summary["total_suites"].as_u64().unwrap() as usize,
        suites.len(),
        "total_suites mismatch"
    );
    assert_eq!(
        summary["total_benchmarks"].as_u64().unwrap() as usize,
        total_benchmarks,
        "total_benchmarks mismatch"
    );
    assert_eq!(
        summary["enforced_suites"].as_u64().unwrap() as usize,
        enforced_count,
        "enforced_suites mismatch"
    );
    assert_eq!(
        summary["planned_suites"].as_u64().unwrap() as usize,
        planned_count,
        "planned_suites mismatch"
    );
    assert_eq!(
        summary["modes"].as_u64().unwrap() as usize,
        modes.len(),
        "modes mismatch"
    );
    assert_eq!(
        summary["captured_percentiles"].as_u64().unwrap() as usize,
        pct.len(),
        "captured_percentiles mismatch"
    );
    assert_eq!(
        summary["regeneration_steps"].as_u64().unwrap() as usize,
        regen_steps,
        "regeneration_steps mismatch"
    );
    assert_eq!(
        summary["prerequisite_checks"].as_u64().unwrap() as usize,
        prereq_checks,
        "prerequisite_checks mismatch"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_perf_baseline.sh");
    assert!(script.exists(), "check_perf_baseline.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_perf_baseline.sh must be executable"
        );
    }
}
