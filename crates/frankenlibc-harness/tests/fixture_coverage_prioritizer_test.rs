//! Integration test: fixture coverage prioritizer gate (bd-bp8fl.4.1)
//!
//! Validates that fixture campaigns are derived from current coverage artifacts
//! and remain sorted by coverage gain plus real workload risk.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

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
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
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
    assert!(artifact["summary"].is_object(), "summary must be object");

    let log_fields: Vec<_> = artifact["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);
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
    let per_symbol_rows: HashMap<(String, String), serde_json::Value> = per_symbol
        ["per_symbol_report"]
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
        "campaign_schema",
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
}
