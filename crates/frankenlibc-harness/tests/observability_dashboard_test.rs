//! Integration tests for bd-282v observability dashboard bundle generation.

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

#[test]
fn observability_capture_command_writes_exporter_bundle_files() {
    let root = workspace_root();
    let temp_dir = std::env::temp_dir().join(format!(
        "frankenlibc_observability_capture_cli_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");

    let harness_bin = std::env::var("CARGO_BIN_EXE_harness").expect("CARGO_BIN_EXE_harness");
    let run = Command::new(harness_bin)
        .current_dir(&root)
        .arg("observability-capture")
        .arg("--out-dir")
        .arg(&temp_dir)
        .arg("--bead-id")
        .arg("bd-282v")
        .arg("--run-id")
        .arg("seeded")
        .arg("--mode")
        .arg("hardened")
        .arg("--seed-sample")
        .output()
        .expect("run observability capture command");

    assert!(
        run.status.success(),
        "observability capture failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    let output = temp_dir.join("observability_dashboard.current.v1.json");
    let prom = temp_dir.join("observability_dashboard.prom");
    let statsd = temp_dir.join("observability_dashboard.statsd");
    let grafana = temp_dir.join("observability_dashboard.grafana.json");
    let alerts = temp_dir.join("observability_dashboard.alerts.yaml");
    let membrane_input = temp_dir.join("inputs/membrane_metrics.jsonl");
    let allocator_input = temp_dir.join("inputs/allocator_metrics.jsonl");
    let runtime_input = temp_dir.join("inputs/runtime_math.jsonl");

    for path in [
        &output,
        &prom,
        &statsd,
        &grafana,
        &alerts,
        &membrane_input,
        &allocator_input,
        &runtime_input,
    ] {
        assert!(path.exists(), "expected artifact {}", path.display());
    }

    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&output).expect("read json output"))
            .expect("json output should parse");
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-282v"));
    assert_eq!(report["summary"]["invalid_rows"].as_u64(), Some(0));
    assert_eq!(report["allocator"]["allocations_total"].as_u64(), Some(2));
    assert_eq!(report["allocator"]["frees_total"].as_u64(), Some(1));
    assert_eq!(report["allocator"]["active_allocations"].as_u64(), Some(1));
    assert_eq!(report["allocator"]["bytes_allocated"].as_u64(), Some(256));
    assert!(
        report["validation"]["validations_total"]
            .as_u64()
            .unwrap_or(0)
            >= 7
    );
    assert!(
        report["runtime_math"]["snapshot_decisions"]
            .as_u64()
            .unwrap_or(0)
            >= 1024
    );

    let prom_text = std::fs::read_to_string(&prom).expect("read prometheus output");
    assert!(
        prom_text.contains("frankenlibc_validations_total"),
        "prometheus bundle should contain validation gauge"
    );
    assert!(
        prom_text.contains("frankenlibc_allocator_bytes_allocated 256"),
        "prometheus bundle should contain allocator gauge"
    );
    assert!(
        prom_text.contains("frankenlibc_runtime_decisions_total"),
        "prometheus bundle should contain runtime decision totals"
    );

    let statsd_text = std::fs::read_to_string(&statsd).expect("read statsd output");
    assert!(
        statsd_text.contains("frankenlibc.allocator.allocations_total:2|g"),
        "statsd bundle should contain allocator totals"
    );

    let grafana_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&grafana).expect("read grafana output"))
            .expect("grafana output should parse");
    assert_eq!(
        grafana_json["title"].as_str(),
        Some("FrankenLibC Observability Dashboard")
    );

    let alerts_yaml = std::fs::read_to_string(&alerts).expect("read alert rules output");
    assert!(
        alerts_yaml.contains("FrankenLibCAllocatorArenaPressure"),
        "alert rules bundle should contain allocator pressure rule"
    );
}
