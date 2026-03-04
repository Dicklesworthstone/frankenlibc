//! Integration test: Symbol latency baseline inventory (bd-3h1u.1)
//!
//! Validates that:
//! 1. Canonical artifact exists and has required schema fields.
//! 2. Summary counts are internally consistent.
//! 3. Each symbol has raw/strict/hardened p50/p95/p99 fields.
//! 4. Ingestion metadata and measured coverage are present.
//! 5. Generator/ingestion/gate scripts exist and are executable.
//! 5. Drift gate passes on clean checkout.

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

fn load_artifact() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/symbol_latency_baseline.v1.json");
    let content =
        std::fs::read_to_string(&path).expect("symbol_latency_baseline.v1.json should exist");
    serde_json::from_str(&content).expect("symbol_latency_baseline.v1.json should be valid JSON")
}

fn load_support_matrix() -> serde_json::Value {
    let path = workspace_root().join("support_matrix.json");
    let content = std::fs::read_to_string(&path).expect("support_matrix.json should exist");
    serde_json::from_str(&content).expect("support_matrix.json should be valid JSON")
}

#[test]
fn artifact_exists_and_valid() {
    let doc = load_artifact();

    assert_eq!(doc["schema_version"].as_u64(), Some(1));
    assert_eq!(doc["bead"].as_str(), Some("bd-3h1u.1"));
    assert!(doc["summary"].is_object(), "Missing summary");
    assert!(
        doc["status_breakdown"].is_object(),
        "Missing status_breakdown"
    );
    assert!(
        doc["module_breakdown"].is_array(),
        "Missing module_breakdown[]"
    );
    assert!(doc["capture_queue"].is_array(), "Missing capture_queue[]");
    assert!(doc["symbols"].is_array(), "Missing symbols[]");
    assert!(doc["ingestion"].is_object(), "Missing ingestion metadata");
    assert_eq!(doc["ingestion"]["schema_version"].as_u64(), Some(1));
}

#[test]
fn summary_counts_consistent() {
    let doc = load_artifact();
    let support = load_support_matrix();

    let symbols = doc["symbols"].as_array().unwrap();
    let support_symbols = support["symbols"].as_array().unwrap();
    let summary = &doc["summary"];

    assert_eq!(
        symbols.len(),
        support_symbols.len(),
        "symbol count mismatch"
    );
    assert_eq!(
        summary["total_symbols"].as_u64().unwrap() as usize,
        symbols.len(),
        "summary.total_symbols mismatch"
    );

    let fixture_covered_count = symbols
        .iter()
        .filter(|row| row["fixture_covered"].as_bool().unwrap_or(false))
        .count();
    assert_eq!(
        summary["fixture_covered_symbols"].as_u64().unwrap() as usize,
        fixture_covered_count,
        "summary.fixture_covered_symbols mismatch"
    );

    let measured = summary["mode_percentile_measured_counts"]
        .as_object()
        .unwrap();
    let pending = summary["mode_percentile_pending_counts"]
        .as_object()
        .unwrap();
    for mode in ["raw", "strict", "hardened"] {
        let m = measured[mode].as_object().unwrap();
        let p = pending[mode].as_object().unwrap();
        for pct in ["p50", "p95", "p99"] {
            let measured_count = m[pct].as_u64().unwrap() as usize;
            let pending_count = p[pct].as_u64().unwrap() as usize;
            assert_eq!(
                measured_count + pending_count,
                symbols.len(),
                "{mode}.{pct}: measured+pending must equal total symbols"
            );
        }
    }

    // We expect deterministic strict/hardened measurements from mutex + thread
    // hot-path samples and raw measurements from mutex+condvar captures.
    let raw_p50 = measured["raw"]["p50"].as_u64().unwrap();
    let strict_p50 = measured["strict"]["p50"].as_u64().unwrap();
    let hardened_p50 = measured["hardened"]["p50"].as_u64().unwrap();
    assert!(
        raw_p50 >= 9,
        "expected at least 9 raw p50 measurements from ingestion, got {raw_p50}"
    );
    assert!(
        strict_p50 >= 12,
        "expected at least 12 strict p50 measurements from ingestion, got {strict_p50}"
    );
    assert!(
        hardened_p50 >= 12,
        "expected at least 12 hardened p50 measurements from ingestion, got {hardened_p50}"
    );

    let ingestion = doc["ingestion"].as_object().unwrap();
    let updated_symbols = ingestion["updated_symbols"].as_u64().unwrap();
    let updated_modes = ingestion["updated_modes"].as_u64().unwrap();
    assert!(
        updated_symbols >= 12,
        "expected at least 12 symbols updated by ingestion, got {updated_symbols}"
    );
    assert!(
        updated_modes >= 33,
        "expected at least 33 mode rows updated by ingestion after raw ingestion, got {updated_modes}"
    );
}

#[test]
fn symbol_mode_records_have_required_fields() {
    let doc = load_artifact();
    let symbols = doc["symbols"].as_array().unwrap();

    for row in symbols {
        let symbol = row["symbol"].as_str().unwrap_or("?");
        let baseline = row["baseline"]
            .as_object()
            .expect("baseline must be object");

        for mode in ["raw", "strict", "hardened"] {
            let mode_row = baseline
                .get(mode)
                .and_then(|v| v.as_object())
                .unwrap_or_else(|| panic!("{symbol}: missing baseline mode {mode}"));

            for field in ["p50_ns", "p95_ns", "p99_ns", "capture_state", "source"] {
                assert!(
                    mode_row.contains_key(field),
                    "{symbol}: {mode}.{field} missing"
                );
            }
        }
    }
}

#[test]
fn scripts_exist_and_executable() {
    let root = workspace_root();
    let scripts = [
        "scripts/generate_symbol_latency_baseline.py",
        "scripts/ingest_symbol_latency_samples.py",
        "scripts/check_symbol_latency_baseline.sh",
    ];

    for rel in scripts {
        let path = root.join(rel);
        assert!(path.exists(), "{rel} must exist");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).unwrap().permissions();
            assert!(perms.mode() & 0o111 != 0, "{rel} must be executable");
        }
    }

    for rel in [
        "tests/conformance/symbol_latency_capture_map.v1.json",
        "tests/conformance/symbol_latency_samples.v1.log",
    ] {
        let path = root.join(rel);
        assert!(path.exists(), "{rel} must exist");
    }
}

#[test]
fn drift_gate_script_passes() {
    let root = workspace_root();
    let script = root.join("scripts/check_symbol_latency_baseline.sh");
    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("check_symbol_latency_baseline.sh should execute");

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "check_symbol_latency_baseline.sh failed\nstatus={:?}\nstdout:\n{}\nstderr:\n{}",
            output.status, stdout, stderr
        );
    }
}
