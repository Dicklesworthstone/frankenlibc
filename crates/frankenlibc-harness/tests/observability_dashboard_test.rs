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

fn test_rows() -> String {
    let rows = vec![
        serde_json::json!({
            "timestamp": "2026-04-06T00:00:00.000Z",
            "trace_id": "membrane::metrics::bd-282v::smoke",
            "decision_id": 1,
            "schema_version": "1.0",
            "level": "info",
            "event": "membrane_metrics_snapshot",
            "controller_id": "membrane_metrics.v1",
            "mode": "strict",
            "api_family": "pointer_validation",
            "symbol": "membrane::ptr_validator::validate",
            "decision_path": "tsm::metrics::snapshot",
            "decision_action": "observe",
            "outcome": "snapshot",
            "healing_action": serde_json::Value::Null,
            "errno": 0,
            "latency_ns": 0,
            "metrics": {
                "validations": 12,
                "tls_cache_hits": 9,
                "tls_cache_misses": 3,
                "tls_cache_hit_rate": 0.75,
                "bloom_hits": 6,
                "bloom_misses": 2,
                "bloom_hit_rate": 0.75,
                "arena_lookups": 4,
                "fingerprint_passes": 4,
                "fingerprint_failures": 1,
                "canary_passes": 4,
                "canary_failures": 0,
                "heals": 2,
                "double_frees_healed": 1,
                "foreign_frees_healed": 0,
                "size_clamps": 1
            },
            "artifact_refs": ["crates/frankenlibc-membrane/src/metrics.rs"]
        }),
        serde_json::json!({
            "timestamp": "2026-04-06T00:00:01.000Z",
            "trace_id": "tsm::pointer_validation::decision::0001",
            "span_id": "validation::stage::1",
            "parent_span_id": "validation::entry::1",
            "decision_id": 1,
            "schema_version": "1.0",
            "level": "info",
            "event": "validation_stage",
            "controller_id": "tsm_validation_pipeline.v1",
            "decision_path": "null_check",
            "decision_action": "Allow",
            "outcome": "allow",
            "mode": "strict",
            "api_family": "pointer_validation",
            "symbol": "membrane::ptr_validator::validate",
            "stage": "null_check",
            "latency_ns": 500,
            "policy_id": 7,
            "risk_upper_bound_ppm": 1200,
            "evidence_seqno": 1,
            "artifact_refs": ["crates/frankenlibc-membrane/src/ptr_validator.rs"]
        }),
        serde_json::json!({
            "trace_id": "membrane::heal::0001",
            "decision_id": 2,
            "schema_version": "1.0",
            "bead_id": "bd-282v",
            "runtime_mode": "hardened",
            "level": "warn",
            "api_family": "membrane-heal",
            "decision_path": "record",
            "outcome": "repair",
            "healing_action": "ClampSize",
            "escalated": false,
            "details": {"requested": 64, "clamped": 32}
        }),
        serde_json::json!({
            "timestamp": "2026-04-06T00:00:02.000Z",
            "trace_id": "allocator::metrics::bd-282v::smoke",
            "bead_id": "bd-282v",
            "scenario_id": "smoke",
            "decision_id": 0,
            "schema_version": "1.0",
            "level": "info",
            "event": "allocator_metrics_snapshot",
            "controller_id": "malloc_stats.v1",
            "mode": "hardened",
            "api_family": "allocator",
            "symbol": "malloc::stats",
            "decision_path": "allocator::stats::snapshot",
            "decision_action": "observe",
            "outcome": "snapshot",
            "healing_action": serde_json::Value::Null,
            "errno": 0,
            "latency_ns": 0,
            "allocations_total": 17,
            "frees_total": 11,
            "active_allocations": 6,
            "bytes_allocated": 8192,
            "thread_cache_hits": 14,
            "thread_cache_misses": 6,
            "central_bin_hits": 3,
            "spills_to_central": 1,
            "artifact_refs": ["crates/frankenlibc-abi/src/malloc_abi.rs"]
        }),
        serde_json::json!({
            "timestamp": "2026-04-06T00:00:03.000Z",
            "trace_id": "runtime_math::decision::0001",
            "bead_id": "bd-282v",
            "scenario_id": "smoke",
            "level": "warn",
            "event": "runtime_decision",
            "controller_id": "runtime_math_kernel.v1",
            "decision": "Repair",
            "decision_action": "Repair",
            "decision_path": "runtime_math::repair",
            "healing_action": "ClampSize",
            "decision_id": 3,
            "schema_version": "1.0",
            "mode": "hardened",
            "api_family": "allocator",
            "symbol": "runtime_math::allocator",
            "errno": 0,
            "latency_ns": 250,
            "policy_id": 7,
            "risk_upper_bound_ppm": 420000,
            "evidence_seqno": 1,
            "overload_state": "nominal",
            "degradation_active": false,
            "overload_policy": "pressured-fast",
            "overload_policy_count": 2,
            "pressure_score_milli": 1200,
            "pressure_raw_score_milli": 1200,
            "risk_inputs": {
                "requested_bytes": 128,
                "bloom_negative": false,
                "is_write": true,
                "contention_hint": 4,
                "addr_hint": 0,
                "pressure_epoch": 1,
                "pressure_transition_count": 1
            },
            "artifact_refs": ["crates/frankenlibc-membrane/src/runtime_math/mod.rs"]
        }),
        serde_json::json!({
            "timestamp": "2026-04-06T00:00:04.000Z",
            "trace_id": "runtime_math::snapshot::bd-282v::smoke",
            "bead_id": "bd-282v",
            "scenario_id": "smoke",
            "decision_id": 0,
            "schema_version": "1.0",
            "level": "info",
            "event": "runtime_snapshot",
            "controller_id": "runtime_math_kernel.v1",
            "mode": "hardened",
            "api_family": "runtime_math",
            "symbol": "runtime_math::kernel",
            "decision_path": "snapshot::state",
            "healing_action": serde_json::Value::Null,
            "errno": 0,
            "latency_ns": 0,
            "decisions": 5,
            "consistency_faults": 1,
            "pareto_cumulative_regret_milli": 50,
            "pareto_cap_enforcements": 0,
            "pareto_exhausted_families": 0,
            "quarantine_depth": 4096,
            "arena_utilization_ppm": 62451,
            "evidence_seqno": 2,
            "artifact_refs": ["crates/frankenlibc-membrane/src/runtime_math/mod.rs"]
        }),
    ];
    rows.into_iter()
        .map(|row| serde_json::to_string(&row).expect("row serializes"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn observability_dashboard_command_writes_bundle_files() {
    let root = workspace_root();
    let temp_dir = std::env::temp_dir().join(format!(
        "frankenlibc_observability_dashboard_cli_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");

    let input = temp_dir.join("input.jsonl");
    std::fs::write(&input, format!("{}\nnot-json", test_rows())).expect("write input log");

    let output = temp_dir.join("observability.json");
    let prom = temp_dir.join("observability.prom");
    let statsd = temp_dir.join("observability.statsd");
    let grafana = temp_dir.join("observability.grafana.json");
    let alerts = temp_dir.join("observability.alerts.yaml");

    let harness_bin = std::env::var("CARGO_BIN_EXE_harness").expect("CARGO_BIN_EXE_harness");
    let run = Command::new(harness_bin)
        .current_dir(&root)
        .arg("observability-dashboard")
        .arg("--input")
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .arg("--prometheus-output")
        .arg(&prom)
        .arg("--statsd-output")
        .arg(&statsd)
        .arg("--grafana-output")
        .arg(&grafana)
        .arg("--alerts-output")
        .arg(&alerts)
        .output()
        .expect("run observability dashboard command");

    assert!(
        run.status.success(),
        "observability dashboard generation failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&output).expect("read json output"))
            .expect("json output should parse");
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-282v"));
    assert_eq!(report["summary"]["invalid_rows"].as_u64(), Some(1));
    assert_eq!(report["validation"]["validations_total"].as_u64(), Some(12));
    assert_eq!(report["allocator"]["allocations_total"].as_u64(), Some(17));
    assert_eq!(report["allocator"]["bytes_allocated"].as_u64(), Some(8192));
    assert_eq!(
        report["healing"]["by_action"]["ClampSize"].as_u64(),
        Some(1)
    );
    assert_eq!(
        report["runtime_math"]["by_decision"]["Repair"].as_u64(),
        Some(1)
    );
    assert_eq!(report["cache"]["tls_cache_hit_rate"].as_f64(), Some(0.75));

    let prom_text = std::fs::read_to_string(&prom).expect("read prometheus output");
    assert!(
        prom_text.contains("frankenlibc_validations_total 12"),
        "prometheus bundle should contain validation gauge"
    );
    assert!(
        prom_text
            .contains("frankenlibc_runtime_decisions_by_decision_total{decision=\"Repair\"} 1"),
        "prometheus bundle should contain labeled runtime decision counter"
    );
    assert!(
        prom_text.contains("frankenlibc_allocator_quarantine_depth 4096"),
        "prometheus bundle should contain allocator pressure gauges"
    );

    let statsd_text = std::fs::read_to_string(&statsd).expect("read statsd output");
    assert!(
        statsd_text.contains("frankenlibc.healing.action.clampsize:1|c"),
        "statsd bundle should contain healing action counter"
    );
    assert!(
        statsd_text.contains("frankenlibc.allocator.bytes_allocated:8192|g"),
        "statsd bundle should contain allocator gauges"
    );

    let grafana_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&grafana).expect("read grafana output"))
            .expect("grafana output should parse");
    assert_eq!(
        grafana_json["title"].as_str(),
        Some("FrankenLibC Observability Dashboard")
    );
    assert!(
        grafana_json["panels"]
            .as_array()
            .is_some_and(|panels| panels.len() >= 10),
        "grafana template should contain panel definitions"
    );

    let alerts_yaml = std::fs::read_to_string(&alerts).expect("read alert rules output");
    assert!(
        alerts_yaml.contains("FrankenLibCAllocatorArenaPressure"),
        "alert rules bundle should contain allocator pressure rule"
    );
}
