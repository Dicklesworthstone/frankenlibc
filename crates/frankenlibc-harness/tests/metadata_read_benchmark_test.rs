//! Integration test: metadata read benchmark artifact gate (bd-3aof.3).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

fn script_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

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
    let content = std::fs::read_to_string(path).expect("json file should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn metadata_read_gate_emits_valid_bd3aof3_artifacts() {
    let _guard = script_lock().lock().unwrap();
    let root = workspace_root();
    let script = root.join("scripts/check_metadata_read_benchmark.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_metadata_read_benchmark.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .env("FRANKENLIBC_FORCE_LOCAL_METADATA_GATE", "1")
        .current_dir(&root)
        .output()
        .expect("failed to run metadata benchmark gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = root.join("target/conformance/metadata_read_benchmark.log.jsonl");
    let report_path = root.join("target/conformance/metadata_read_benchmark.report.json");
    let bench_path = root.join("target/metadata_read_bench/metadata_benchmark_report.v1.json");

    assert!(log_path.exists(), "missing {}", log_path.display());
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(bench_path.exists(), "missing {}", bench_path.display());

    let trace = std::fs::read_to_string(&log_path).expect("log should be readable");
    let mut row_count = 0usize;
    let mut benchmark_seen = false;
    let mut unit_seen = false;
    for raw in trace.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        row_count += 1;
        let row: serde_json::Value =
            serde_json::from_str(raw).expect("trace line should be valid json");
        assert!(row["timestamp"].is_string());
        assert!(row["trace_id"].is_string());
        assert_eq!(row["event"].as_str(), Some("metadata_read_benchmark_gate"));
        assert_eq!(row["bead_id"].as_str(), Some("bd-3aof.3"));
        assert_eq!(row["mode"].as_str(), Some("shared"));
        assert_eq!(row["api_family"].as_str(), Some("metadata"));
        assert_eq!(row["symbol"].as_str(), Some("metadata_read_path"));
        assert!(row["artifact_refs"].is_array());
        match row["stream"].as_str() {
            Some("benchmark") => benchmark_seen = true,
            Some("unit") => unit_seen = true,
            other => panic!("unexpected stream: {other:?}"),
        }
    }

    assert!(row_count >= 2, "expected at least 2 gate rows");
    assert!(benchmark_seen, "benchmark stream row missing");
    assert!(unit_seen, "unit stream row missing");

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead_id"].as_str(), Some("bd-3aof.3"));
    assert_eq!(
        report["unit_tests"]["frankenlibc_bench_lib"].as_str(),
        Some("pass")
    );
    assert_eq!(report["benchmark"]["record_count"].as_u64(), Some(210));
    assert_eq!(report["benchmark"]["break_even_count"].as_u64(), Some(21));
    assert!(
        report["benchmark"]["nonnull_break_even_count"]
            .as_u64()
            .expect("nonnull_break_even_count should be numeric")
            > 0,
        "expected at least one non-null break-even row"
    );
    assert!(
        report["benchmark"]["high_read_wins"]
            .as_u64()
            .expect("high_read_wins should be numeric")
            >= 3,
        "expected at least three high-read RCU wins"
    );

    let bench = load_json(&bench_path);
    assert_eq!(bench["schema_version"].as_str(), Some("v1"));
    assert_eq!(bench["bead_id"].as_str(), Some("bd-3aof.3"));
    assert_eq!(bench["record_count"].as_u64(), Some(210));
    assert_eq!(bench["break_even_count"].as_u64(), Some(21));

    let records = bench["records"]
        .as_array()
        .expect("records should be array");
    assert_eq!(records.len(), 210);
    let break_even = bench["break_even"]
        .as_array()
        .expect("break_even should be array");
    assert_eq!(break_even.len(), 21);

    for rel in [
        "target/metadata_read_bench/throughput_vs_threads.dat",
        "target/metadata_read_bench/latency_percentiles.dat",
        "target/metadata_read_bench/break_even.dat",
        "target/metadata_read_bench/throughput_vs_threads.gp",
        "target/metadata_read_bench/latency_percentiles.gp",
        "target/metadata_read_bench/break_even.gp",
        "target/metadata_read_bench/throughput_vs_threads.svg",
        "target/metadata_read_bench/latency_percentiles.svg",
        "target/metadata_read_bench/break_even_ratio.svg",
    ] {
        let path = root.join(rel);
        assert!(path.exists(), "missing {}", path.display());
    }
}
