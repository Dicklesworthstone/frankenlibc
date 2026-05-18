use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory must have workspace parent")?;
    let repo = workspace
        .parent()
        .ok_or("workspace parent must have repo parent")?;
    Ok(repo.to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/tsm_contention_e2e_lane.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_tsm_contention_e2e_lane.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "tsm_contention_e2e_lane_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_TSM_CONTENTION_E2E_LANE", manifest)
        .env("FRANKENLIBC_TSM_CONTENTION_E2E_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_TSM_CONTENTION_E2E_REPORT",
            out_dir.join("tsm_contention_e2e_lane.report.json"),
        )
        .env(
            "FRANKENLIBC_TSM_CONTENTION_E2E_LOG",
            out_dir.join("tsm_contention_e2e_lane.log.jsonl"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn write_manifest_variant(
    root: &Path,
    base: &Value,
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let out_dir = unique_out_dir(root, label)?;
    let path = out_dir.join(format!("{label}.json"));
    let mut value = base.clone();
    mutate(&mut value)?;
    write_json(&path, &value)?;
    Ok(path)
}

fn json_array<'a>(value: &'a Value, key: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be an array").into())
}

#[test]
fn manifest_separates_smoke_from_permissioned_large_host_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&manifest_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("tsm_contention_e2e_lane.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-rakj1"));
    assert_eq!(
        manifest["claim_status"].as_str(),
        Some("lane_contract_only")
    );
    assert_eq!(
        manifest["readiness_claim_policy"]["smoke_must_not_upgrade_public_claims"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["readiness_claim_policy"]["required_release_evidence_lane"].as_str(),
        Some("permissioned_large_host")
    );

    let lanes = json_array(&manifest, "lanes")?;
    let smoke = lanes
        .iter()
        .find(|lane| lane["id"].as_str() == Some("smoke_small_host"))
        .ok_or("smoke lane missing")?;
    assert_eq!(smoke["can_upgrade_public_readiness"].as_bool(), Some(false));
    assert_eq!(smoke["not_readiness_evidence"].as_bool(), Some(true));
    assert_eq!(
        smoke["execution_policy"]["thread_count_max"].as_u64(),
        Some(8)
    );

    let permissioned = lanes
        .iter()
        .find(|lane| lane["id"].as_str() == Some("permissioned_large_host"))
        .ok_or("permissioned lane missing")?;
    assert_eq!(
        permissioned["can_upgrade_public_readiness"].as_bool(),
        Some(true)
    );
    assert_eq!(
        permissioned["execution_policy"]["thread_count_min"].as_u64(),
        Some(64)
    );
    assert_eq!(
        permissioned["execution_policy"]["host_profile"]["memory_gib_min"].as_u64(),
        Some(256)
    );
    assert_eq!(
        permissioned["execution_policy"]["host_profile"]["numa_topology_required"].as_bool(),
        Some(true)
    );
    Ok(())
}

#[test]
fn manifest_requires_full_contention_metric_shape() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let required_fields: Vec<&str> = json_array(&manifest, "required_evidence_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for field in [
        "thread_count",
        "duration_ms",
        "operation_mix",
        "p50_latency_ns",
        "p95_latency_ns",
        "p99_latency_ns",
        "repair_count",
        "deny_count",
        "tls_cache_hits",
        "tls_cache_misses",
        "bloom_positive_count",
        "page_oracle_hits",
        "worker_identity",
        "raw_log_paths",
    ] {
        assert!(
            required_fields.contains(&field),
            "required_evidence_fields missing {field}"
        );
    }

    let operation_mix: Vec<&str> = json_array(&manifest, "operation_mix")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for op in [
        "abi_malloc_free",
        "abi_memcpy_memset",
        "tls_cache_validation",
        "bloom_page_oracle_lookup",
        "runtime_math_decision",
        "metrics_counter_sample",
    ] {
        assert!(operation_mix.contains(&op), "operation_mix missing {op}");
    }
    Ok(())
}

#[test]
fn checker_accepts_manifest_and_emits_shared_artifacts() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out_dir.join("tsm_contention_e2e_lane.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("tsm_contention_e2e_lane.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["lane_count"].as_u64(), Some(2));
    assert_eq!(
        report["summary"]["smoke_can_upgrade_public_readiness"].as_bool(),
        Some(false)
    );
    assert_eq!(
        report["summary"]["permissioned_min_thread_count"].as_u64(),
        Some(64)
    );

    let log_path = out_dir.join("tsm_contention_e2e_lane.log.jsonl");
    let log = std::fs::read_to_string(&log_path)?;
    let records: Vec<Value> = log
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(records.len(), 3);
    for (index, line) in log.lines().enumerate() {
        validate_log_line(line, index + 1).map_err(|errors| {
            std::io::Error::other(format!("checker log row failed validation: {errors:?}"))
        })?;
    }
    assert!(records.iter().any(|record| {
        record["event"].as_str() == Some("tsm_contention_smoke_shape_validated")
            && record["can_upgrade_public_readiness"].as_bool() == Some(false)
    }));
    assert!(records.iter().any(|record| {
        record["event"].as_str() == Some("tsm_contention_permissioned_large_host_policy_pinned")
            && record["required_remote"].as_bool() == Some(true)
            && record["min_thread_count"].as_u64() == Some(64)
    }));
    Ok(())
}

#[test]
fn checker_rejects_smoke_evidence_that_upgrades_public_readiness() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let variant = write_manifest_variant(&root, &manifest, "smoke-upgrade", |value| {
        value["smoke_fixture"]["can_upgrade_public_readiness"] = Value::Bool(true);
        value["smoke_fixture"]["readiness_claim"] = Value::String("public_readiness".to_string());
        Ok(())
    })?;
    let out_dir = unique_out_dir(&root, "smoke_upgrade_out")?;
    let output = run_checker(&root, &variant, &out_dir)?;

    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("tsm_contention_e2e_lane.report.json"))?;
    let errors = json_array(&report, "errors")?;
    assert!(
        errors.iter().filter_map(Value::as_str).any(|error| {
            error.contains("smoke_fixture must not upgrade public readiness")
                || error.contains("smoke_fixture readiness_claim must be shape_only")
        }),
        "expected smoke readiness downgrade error, got {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_permissioned_lane_without_large_host_topology() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let variant = write_manifest_variant(&root, &manifest, "missing-topology", |value| {
        let lanes = value["lanes"].as_array_mut().ok_or("lanes must be array")?;
        let permissioned = lanes
            .iter_mut()
            .find(|lane| lane["id"].as_str() == Some("permissioned_large_host"))
            .ok_or("permissioned lane missing")?;
        permissioned["execution_policy"]["host_profile"]["numa_topology_required"] =
            Value::Bool(false);
        Ok(())
    })?;
    let out_dir = unique_out_dir(&root, "missing_topology_out")?;
    let output = run_checker(&root, &variant, &out_dir)?;

    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("tsm_contention_e2e_lane.report.json"))?;
    let errors = json_array(&report, "errors")?;
    assert!(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains("NUMA topology")),
        "expected NUMA topology error, got {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_local_or_unpermissioned_large_host_command_policy() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let variant = write_manifest_variant(&root, &manifest, "missing-remote-ack", |value| {
        let lanes = value["lanes"].as_array_mut().ok_or("lanes must be array")?;
        let permissioned = lanes
            .iter_mut()
            .find(|lane| lane["id"].as_str() == Some("permissioned_large_host"))
            .ok_or("permissioned lane missing")?;
        permissioned["execution_policy"]["required_command_prefix"] =
            serde_json::json!(["rch", "exec", "--"]);
        permissioned["execution_policy"]["required_env"]
            .as_object_mut()
            .ok_or("permissioned required_env must be object")?
            .remove("FFS_TSM_CONTENTION_REAL_RUN_ACK");
        Ok(())
    })?;
    let out_dir = unique_out_dir(&root, "missing_remote_ack_out")?;
    let output = run_checker(&root, &variant, &out_dir)?;

    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("tsm_contention_e2e_lane.report.json"))?;
    let errors = json_array(&report, "errors")?;
    assert!(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains("RCH_REQUIRE_REMOTE=1")
                || error.contains("explicit TSM contention ack")),
        "expected remote/ack error, got {errors:?}"
    );
    Ok(())
}
