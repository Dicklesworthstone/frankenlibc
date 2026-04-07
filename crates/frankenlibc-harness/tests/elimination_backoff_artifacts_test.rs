//! Integration test: elimination-backoff artifact gate (bd-29j3).

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
fn elimination_backoff_gate_emits_valid_bd29j3_artifacts() {
    let _guard = script_lock().lock().unwrap();
    let root = workspace_root();
    let script = root.join("scripts/check_elimination_backoff.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_elimination_backoff.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .env("FRANKENLIBC_FORCE_LOCAL_ELIMINATION_GATE", "1")
        .current_dir(&root)
        .output()
        .expect("failed to run elimination backoff gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = root.join("target/conformance/elimination_backoff.log.jsonl");
    let report_path = root.join("target/conformance/elimination_backoff.report.json");
    let bench_path = root.join("target/elimination_backoff/elimination_benchmark.json");

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
        assert_eq!(row["event"].as_str(), Some("elimination_backoff_gate"));
        assert_eq!(row["bead_id"].as_str(), Some("bd-29j3"));
        assert_eq!(row["mode"].as_str(), Some("shared"));
        assert_eq!(row["api_family"].as_str(), Some("malloc"));
        assert_eq!(row["symbol"].as_str(), Some("allocator_elimination"));
        assert!(row["artifact_refs"].is_array());
        match row["stream"].as_str() {
            Some("benchmark") => benchmark_seen = true,
            Some("unit") => unit_seen = true,
            other => panic!("unexpected stream: {other:?}"),
        }
    }

    assert!(row_count >= 3, "expected at least 3 gate rows");
    assert!(benchmark_seen, "benchmark stream row missing");
    assert!(unit_seen, "unit stream rows missing");

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_i64(), Some(1));
    assert_eq!(report["bead_id"].as_str(), Some("bd-29j3"));
    assert_eq!(
        report["unit_tests"]["elimination_module"].as_str(),
        Some("pass")
    );
    assert_eq!(
        report["unit_tests"]["allocator_integration"].as_str(),
        Some("pass")
    );
    assert_eq!(report["benchmark"]["meets_target"].as_bool(), Some(true));
    assert!(
        report["benchmark"]["improvement_pct"]
            .as_f64()
            .expect("improvement_pct should be numeric")
            >= 20.0,
        "improvement_pct should satisfy the 20% target"
    );

    let bench = load_json(&bench_path);
    assert_eq!(bench["schema_version"].as_i64(), Some(1));
    assert_eq!(bench["bead_id"].as_str(), Some("bd-29j3"));
    assert_eq!(bench["meets_target"].as_bool(), Some(true));
    assert!(
        bench["improvement_pct"]
            .as_f64()
            .expect("improvement_pct should be numeric")
            >= 20.0,
        "benchmark artifact should record >=20% improvement"
    );

    let records = bench["records"]
        .as_array()
        .expect("records should be array");
    assert_eq!(
        records.len(),
        2,
        "expected elimination + mutex_queue records"
    );
    let elimination = records
        .iter()
        .find(|row| row["label"].as_str() == Some("elimination"))
        .expect("elimination record missing");
    let mutex_queue = records
        .iter()
        .find(|row| row["label"].as_str() == Some("mutex_queue"))
        .expect("mutex_queue record missing");

    assert!(
        elimination["throughput_ops_s"]
            .as_f64()
            .expect("elimination throughput should be numeric")
            > mutex_queue["throughput_ops_s"]
                .as_f64()
                .expect("mutex queue throughput should be numeric"),
        "elimination path should beat mutex queue throughput"
    );
    assert!(
        elimination["elimination_success_rate_ppm"]
            .as_u64()
            .expect("success rate should be numeric")
            >= 300_000,
        "elimination success rate should satisfy the 30% acceptance threshold"
    );
}
