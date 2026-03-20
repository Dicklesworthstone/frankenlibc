//! Integration test: Stub priority ranking (bd-4ia)
//!
//! Validates that:
//! 1. The stub priority ranking JSON exists and is valid.
//! 2. Ranked symbols match actual non-implemented symbols in support_matrix.json.
//! 3. Scores match the severity_weight * workloads_blocked formula.
//! 4. Tier assignments are consistent with symbol status and perf_class.
//! 5. Burn-down wave plan sums to total non-implemented.
//! 6. Summary statistics are consistent.
//! 7. The CI gate script exists and is executable.
//!
//! Run: cargo test -p frankenlibc-harness --test stub_priority_test

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_ranking() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/stub_priority_ranking.json");
    let content = std::fs::read_to_string(&path).expect("stub_priority_ranking.json should exist");
    serde_json::from_str(&content).expect("stub_priority_ranking.json should be valid JSON")
}

fn load_matrix() -> serde_json::Value {
    let path = workspace_root().join("support_matrix.json");
    let content = std::fs::read_to_string(&path).expect("support_matrix.json should exist");
    serde_json::from_str(&content).expect("support_matrix.json should be valid JSON")
}

fn load_workloads() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/workload_matrix.json");
    let content = std::fs::read_to_string(&path).expect("workload_matrix.json should exist");
    serde_json::from_str(&content).expect("workload_matrix.json should be valid JSON")
}

#[test]
fn ranking_exists_and_valid() {
    let r = load_ranking();
    assert!(r["schema_version"].is_number(), "Missing schema_version");
    assert!(
        r["scoring"]["severity_weights"].is_object(),
        "Missing scoring.severity_weights"
    );
    assert!(
        r["module_ranking"]["entries"].is_array(),
        "Missing module_ranking.entries"
    );
    assert!(
        r["symbol_ranking"]["tiers"].is_array(),
        "Missing symbol_ranking.tiers"
    );
    assert!(r["burn_down"].is_object(), "Missing burn_down");
    assert!(r["summary"].is_object(), "Missing summary");
}

#[test]
fn ranked_symbols_match_support_matrix() {
    let r = load_ranking();
    let m = load_matrix();

    let mut actual_non_impl: HashSet<String> = HashSet::new();
    for s in m["symbols"].as_array().unwrap() {
        let status = s["status"].as_str().unwrap_or("");
        if status == "Stub" || status == "GlibcCallThrough" {
            actual_non_impl.insert(s["symbol"].as_str().unwrap().to_string());
        }
    }

    let mut ranked: HashSet<String> = HashSet::new();
    for tier in r["symbol_ranking"]["tiers"].as_array().unwrap() {
        for sym in tier["symbols"].as_array().unwrap() {
            let name = sym["symbol"].as_str().unwrap().to_string();
            assert!(ranked.insert(name.clone()), "Duplicate: {name}");
        }
    }

    assert_eq!(
        ranked, actual_non_impl,
        "Ranked symbols must match support_matrix non-implemented"
    );
}

#[test]
fn scores_match_formula() {
    let r = load_ranking();
    let wl = load_workloads();

    let weights = &r["scoring"]["severity_weights"];
    let stub_w = weights["Stub"]["weight"].as_f64().unwrap();
    let ct_hot_w = weights["GlibcCallThrough_hotpath"]["weight"]
        .as_f64()
        .unwrap();
    let ct_cold_w = weights["GlibcCallThrough_coldpath"]["weight"]
        .as_f64()
        .unwrap();

    let impact = wl["subsystem_impact"].as_object().unwrap();
    let mut workloads_by_mod: HashMap<String, u64> = HashMap::new();
    for (k, v) in impact {
        if k == "description" {
            continue;
        }
        workloads_by_mod.insert(k.clone(), v["blocked_workloads"].as_u64().unwrap());
    }

    for tier in r["symbol_ranking"]["tiers"].as_array().unwrap() {
        for sym in tier["symbols"].as_array().unwrap() {
            let name = sym["symbol"].as_str().unwrap();
            let module = sym["module"].as_str().unwrap();
            let status = sym["status"].as_str().unwrap();
            let perf_class = sym["perf_class"].as_str().unwrap();
            let claimed = sym["score"].as_f64().unwrap();

            let w = if status == "Stub" {
                stub_w
            } else if perf_class == "strict_hotpath" {
                ct_hot_w
            } else {
                ct_cold_w
            };

            let wl_blocked = *workloads_by_mod.get(module).unwrap_or(&0) as f64;
            let expected = w * wl_blocked;

            assert!(
                (claimed - expected).abs() < 0.01,
                "{name}: claimed={claimed} expected={expected}"
            );
        }
    }
}

#[test]
fn tier_assignments_consistent() {
    let r = load_ranking();

    for tier in r["symbol_ranking"]["tiers"].as_array().unwrap() {
        let tid = tier["tier"].as_str().unwrap();
        let symbols = tier["symbols"].as_array().unwrap();
        let claimed_count = tier["count"].as_u64().unwrap() as usize;

        assert_eq!(symbols.len(), claimed_count, "{tid}: count mismatch");

        for sym in symbols {
            let name = sym["symbol"].as_str().unwrap();
            let status = sym["status"].as_str().unwrap();
            let perf_class = sym["perf_class"].as_str().unwrap();

            match tid {
                "T1_critical" => {
                    assert_eq!(status, "Stub", "{name}: T1 must be Stub");
                }
                "T2_hotpath" => {
                    assert_eq!(
                        status, "GlibcCallThrough",
                        "{name}: T2 must be GlibcCallThrough"
                    );
                    assert_eq!(
                        perf_class, "strict_hotpath",
                        "{name}: T2 must be strict_hotpath"
                    );
                }
                "T3_coldpath" => {
                    assert_eq!(
                        status, "GlibcCallThrough",
                        "{name}: T3 must be GlibcCallThrough"
                    );
                    assert_eq!(perf_class, "coldpath", "{name}: T3 must be coldpath");
                }
                _ => panic!("Unknown tier: {tid}"),
            }
        }
    }
}

#[test]
fn burn_down_consistent() {
    let r = load_ranking();
    let burn = &r["burn_down"];

    let total = burn["total_non_implemented"].as_u64().unwrap();

    // by_status sums to total
    let by_status = burn["by_status"].as_object().unwrap();
    let status_sum: u64 = by_status.values().map(|v| v.as_u64().unwrap()).sum();
    assert_eq!(status_sum, total, "by_status sum mismatch");

    // by_perf_class sums to total
    let by_perf = burn["by_perf_class"].as_object().unwrap();
    let perf_sum: u64 = by_perf.values().map(|v| v.as_u64().unwrap()).sum();
    assert_eq!(perf_sum, total, "by_perf_class sum mismatch");

    // wave symbols sum to total
    let waves = burn["wave_plan"].as_array().unwrap();
    let wave_sum: u64 = waves.iter().map(|w| w["symbols"].as_u64().unwrap()).sum();
    assert_eq!(wave_sum, total, "wave_plan symbols sum mismatch");

    // in_progress + planned + unscheduled = total
    let in_progress = burn["symbols_in_progress"].as_u64().unwrap();
    let planned = burn["symbols_planned"].as_u64().unwrap();
    let unscheduled = burn["symbols_unscheduled"].as_u64().unwrap();
    assert_eq!(
        in_progress + planned + unscheduled,
        total,
        "status breakdown mismatch"
    );
}

#[test]
fn summary_consistent() {
    let r = load_ranking();
    let m = load_matrix();
    let summary = &r["summary"];

    let actual_stubs = m["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["status"].as_str() == Some("Stub"))
        .count();
    let actual_ct = m["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["status"].as_str() == Some("GlibcCallThrough"))
        .count();

    assert_eq!(
        summary["stubs"].as_u64().unwrap() as usize,
        actual_stubs,
        "stubs mismatch"
    );
    assert_eq!(
        summary["callthroughs"].as_u64().unwrap() as usize,
        actual_ct,
        "callthroughs mismatch"
    );
    assert_eq!(
        summary["total_non_implemented"].as_u64().unwrap() as usize,
        actual_stubs + actual_ct,
        "total_non_implemented mismatch"
    );

    // Tier counts
    let tiers = r["symbol_ranking"]["tiers"].as_array().unwrap();
    let tier_counts = summary["tier_counts"].as_object().unwrap();
    for t in tiers {
        let tid = t["tier"].as_str().unwrap();
        let actual = t["symbols"].as_array().unwrap().len();
        let claimed = tier_counts[tid].as_u64().unwrap() as usize;
        assert_eq!(actual, claimed, "tier_counts.{tid} mismatch");
    }
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_stub_priority.sh");
    assert!(script.exists(), "scripts/check_stub_priority.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_stub_priority.sh must be executable"
        );
    }
}

#[test]
fn gate_script_passes() {
    let root = workspace_root();
    let script = root.join("scripts/check_stub_priority.sh");
    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run stub priority gate");
    assert!(
        output.status.success(),
        "stub priority gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
