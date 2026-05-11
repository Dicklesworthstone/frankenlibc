// symbol_universe_normalization_test.rs — bd-2vv.9
// Integration tests for symbol universe normalization and classification.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("failed to read JSON fixture");
    serde_json::from_str(&content).expect("invalid JSON fixture")
}

fn load_jsonl(path: &Path) -> Vec<serde_json::Value> {
    let content = std::fs::read_to_string(path).expect("failed to read JSONL fixture");
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("invalid JSONL fixture row"))
        .collect()
}

#[test]
fn normalization_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("target/conformance/symbol_universe_normalization.test.v1.json");
    let log_path = root.join("target/conformance/symbol_universe_normalization.test.log.jsonl");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_symbol_universe_normalization.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute normalization generator");
    assert!(
        output.status.success(),
        "Normalization generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
    assert!(log_path.exists());
}

#[test]
fn normalization_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-2vv.9"));
    assert!(data["universe_hash"].is_string());

    let summary = &data["summary"];
    for field in &[
        "total_symbols",
        "unique_symbols",
        "duplicates",
        "families",
        "native_implementation_pct",
        "unknown_action_count",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(summary["classifications"].is_object());
    assert!(summary["confidence_levels"].is_object());
    assert!(data["normalized_symbols"].is_array());
    assert!(data["family_statistics"].is_object());
    assert!(data["unknown_action_list"].is_array());
    assert!(data["classification_rules"].is_object());
    assert_eq!(
        data["source_artifacts"]["support_matrix"].as_str(),
        Some("support_matrix.json")
    );
    assert_eq!(
        data["telemetry"]["log_schema_version"].as_str(),
        Some("symbol_universe_normalization.log.v1")
    );
}

#[test]
fn normalization_all_symbols_classified() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let data = load_json(&report_path);

    let symbols = data["normalized_symbols"].as_array().unwrap();
    assert!(symbols.len() >= 100, "Too few symbols: {}", symbols.len());

    let valid_classifications = [
        "native",
        "syscall-passthrough",
        "host-wrapped",
        "host-delegated",
        "stub",
    ];
    for s in symbols {
        let name = s["symbol"].as_str().unwrap_or("?");
        let class = s["classification"].as_str().unwrap_or("unknown");
        assert!(
            valid_classifications.contains(&class),
            "Symbol {} has invalid classification: {}",
            name,
            class
        );
    }
}

#[test]
fn normalization_all_symbols_have_known_family_and_no_issues() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let data = load_json(&report_path);

    let symbols = data["normalized_symbols"].as_array().unwrap();
    let mut unknown_families = Vec::new();
    let mut issue_rows = Vec::new();
    for symbol in symbols {
        if symbol["family"].as_str() == Some("unknown") {
            unknown_families.push(symbol["symbol"].as_str().unwrap_or("?"));
        }
        if !symbol["issues"].as_array().unwrap().is_empty() {
            issue_rows.push(symbol["symbol"].as_str().unwrap_or("?"));
        }
    }

    assert!(
        unknown_families.is_empty(),
        "Unknown families remain: {:?}",
        &unknown_families[..unknown_families.len().min(10)]
    );
    assert!(
        issue_rows.is_empty(),
        "Normalization issues remain: {:?}",
        &issue_rows[..issue_rows.len().min(10)]
    );
}

#[test]
fn normalization_no_duplicates() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let data = load_json(&report_path);

    let dupes = data["summary"]["duplicates"].as_u64().unwrap();
    assert_eq!(dupes, 0, "Found {} duplicate symbols", dupes);

    // Also verify by checking names are unique
    let symbols = data["normalized_symbols"].as_array().unwrap();
    let mut names: Vec<&str> = symbols
        .iter()
        .map(|s| s["symbol"].as_str().unwrap_or(""))
        .collect();
    let total = names.len();
    names.sort();
    names.dedup();
    assert_eq!(total, names.len(), "Duplicate symbol names detected");
}

#[test]
fn normalization_rebuilds_support_matrix_status_module_perf_joins() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let support_matrix_path = root.join("support_matrix.json");
    let data = load_json(&report_path);
    let support_matrix = load_json(&support_matrix_path);

    let symbols = data["normalized_symbols"].as_array().unwrap();
    let support_symbols = support_matrix["symbols"].as_array().unwrap();
    assert_eq!(symbols.len(), support_symbols.len());
    assert_eq!(
        symbols.len() as u64,
        support_matrix["total_exported"].as_u64().unwrap()
    );

    let support_by_symbol: HashMap<&str, &serde_json::Value> = support_symbols
        .iter()
        .map(|row| (row["symbol"].as_str().unwrap(), row))
        .collect();
    let status_to_class = HashMap::from([
        ("Implemented", "native"),
        ("RawSyscall", "syscall-passthrough"),
        ("WrapsHostLibc", "host-wrapped"),
        ("GlibcCallThrough", "host-delegated"),
        ("Stub", "stub"),
    ]);

    for symbol in symbols {
        let name = symbol["symbol"].as_str().unwrap();
        let source = support_by_symbol
            .get(name)
            .expect("symbol missing from support_matrix");
        assert_eq!(symbol["module"], source["module"], "{name} module drift");
        assert_eq!(symbol["status"], source["status"], "{name} status drift");
        let expected_perf = source["perf_class"].as_str().unwrap_or("coldpath");
        assert_eq!(
            symbol["perf_class"].as_str(),
            Some(expected_perf),
            "{name} perf_class drift"
        );
        let expected = status_to_class[source["status"].as_str().unwrap()];
        assert_eq!(
            symbol["classification"].as_str(),
            Some(expected),
            "{name} classification drift"
        );
    }
}

#[test]
fn normalization_families_populated() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let data = load_json(&report_path);

    let families = data["family_statistics"].as_object().unwrap();
    assert!(
        families.len() >= 10,
        "Only {} families (need >= 10)",
        families.len()
    );

    for (fam, stats) in families {
        let total = stats["total"].as_u64().unwrap();
        assert!(total > 0, "Family {} has 0 symbols", fam);
        let native = stats["native"].as_u64().unwrap();
        assert!(
            native <= total,
            "Family {} native count {} > total {}",
            fam,
            native,
            total
        );
    }
}

#[test]
fn normalization_reproducible() {
    let root = repo_root();
    let checked_in_report_path =
        root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let report_path = root.join("target/conformance/symbol_universe_normalization.repro.v1.json");
    let log_path = root.join("target/conformance/symbol_universe_normalization.repro.log.jsonl");
    let data1 = load_json(&checked_in_report_path);

    // Re-generate
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_symbol_universe_normalization.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute normalization generator");
    assert!(output.status.success());

    let data2 = load_json(&report_path);
    assert_eq!(
        data1["universe_hash"].as_str(),
        data2["universe_hash"].as_str(),
        "Universe hash changed on regeneration — not reproducible"
    );
    assert!(log_path.exists());
}

#[test]
fn normalization_priority_scores_reasonable() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let data = load_json(&report_path);

    let symbols = data["normalized_symbols"].as_array().unwrap();
    for s in symbols {
        let name = s["symbol"].as_str().unwrap_or("?");
        let score = s["priority_score"].as_i64().unwrap();
        // Scores should be within reasonable bounds
        assert!(
            (-100..=1000).contains(&score),
            "Symbol {} has unreasonable priority score: {}",
            name,
            score
        );
    }

    // Hotpath symbols should have higher scores than coldpath
    let hotpath_avg: f64 = {
        let hp: Vec<i64> = symbols
            .iter()
            .filter(|s| s["perf_class"].as_str() == Some("strict_hotpath"))
            .map(|s| s["priority_score"].as_i64().unwrap())
            .collect();
        if hp.is_empty() {
            0.0
        } else {
            hp.iter().sum::<i64>() as f64 / hp.len() as f64
        }
    };
    let coldpath_avg: f64 = {
        let cp: Vec<i64> = symbols
            .iter()
            .filter(|s| s["perf_class"].as_str() == Some("coldpath"))
            .map(|s| s["priority_score"].as_i64().unwrap())
            .collect();
        if cp.is_empty() {
            0.0
        } else {
            cp.iter().sum::<i64>() as f64 / cp.len() as f64
        }
    };
    assert!(
        hotpath_avg > coldpath_avg,
        "Hotpath avg score ({}) should be > coldpath avg ({})",
        hotpath_avg,
        coldpath_avg
    );
}

#[test]
fn normalization_telemetry_log_covers_every_symbol() {
    let root = repo_root();
    let report_path =
        root.join("target/conformance/symbol_universe_normalization.coverage.v1.json");
    let log_path = root.join("target/conformance/symbol_universe_normalization.coverage.log.jsonl");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_symbol_universe_normalization.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute normalization generator");
    assert!(
        output.status.success(),
        "Normalization generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    let symbols = report["normalized_symbols"].as_array().unwrap();
    let log_rows = load_jsonl(&log_path);
    assert_eq!(log_rows.len(), symbols.len());

    let report_trace_ids: HashSet<&str> = symbols
        .iter()
        .map(|row| row["trace_id"].as_str().unwrap())
        .collect();
    let mut log_trace_ids = HashSet::new();
    let mut log_symbols = HashSet::new();
    for row in &log_rows {
        assert_eq!(
            row["schema_version"].as_str(),
            Some("symbol_universe_normalization.log.v1")
        );
        assert_eq!(
            row["event"].as_str(),
            Some("symbol_universe_classification")
        );
        assert_eq!(row["bead"].as_str(), Some("bd-2vv.9"));
        for field in &[
            "trace_id",
            "symbol",
            "family",
            "classification",
            "confidence",
        ] {
            assert!(
                row[field].as_str().is_some_and(|value| !value.is_empty()),
                "missing log field {field}: {row:?}"
            );
        }
        log_trace_ids.insert(row["trace_id"].as_str().unwrap());
        log_symbols.insert(row["symbol"].as_str().unwrap());
    }

    assert_eq!(log_trace_ids, report_trace_ids);
    assert_eq!(log_symbols.len(), symbols.len());
}
