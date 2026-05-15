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

fn plan_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/swarm_scale_interpose_workload_evidence_plan.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_swarm_scale_interpose_workload_evidence_plan.sh")
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
        "swarm_scale_interpose_workload_evidence_plan_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, plan: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_SWARM_SCALE_INTERPOSE_PLAN", plan)
        .env("FRANKENLIBC_SWARM_SCALE_INTERPOSE_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_SWARM_SCALE_INTERPOSE_REPORT",
            out_dir.join("swarm_scale_interpose_workload_evidence_plan.report.json"),
        )
        .env(
            "FRANKENLIBC_SWARM_SCALE_INTERPOSE_LOG",
            out_dir.join("swarm_scale_interpose_workload_evidence_plan.log.jsonl"),
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

fn write_plan_variant(
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

#[test]
fn plan_binds_remote_only_swarm_interpose_policy() -> TestResult {
    let root = repo_root()?;
    let plan = load_json(&plan_path(&root))?;

    assert_eq!(
        plan["schema_version"].as_str(),
        Some("swarm_scale_interpose_workload_evidence_plan.v1")
    );
    assert_eq!(plan["bead"].as_str(), Some("bd-waaa6.5"));
    assert_eq!(plan["claim_status"].as_str(), Some("plan_only"));
    assert_eq!(
        plan["replacement_level"].as_str(),
        Some("L0_L1_interpose_evidence_only")
    );
    assert_eq!(
        plan["execution_policy"]["no_broad_local_stress"].as_bool(),
        Some(true)
    );
    assert_eq!(
        plan["execution_policy"]["required_launcher"].as_str(),
        Some("rch")
    );

    let command_prefix = plan["execution_policy"]["required_command_prefix"]
        .as_array()
        .ok_or("required_command_prefix must be array")?;
    let prefix_values: Vec<&str> = command_prefix.iter().filter_map(Value::as_str).collect();
    for required in ["RCH_FORCE_REMOTE=true", "rch", "exec"] {
        assert!(
            prefix_values.contains(&required),
            "remote command prefix missing {required}"
        );
    }

    let forbidden = plan["execution_policy"]["forbidden_evidence_markers"]
        .as_array()
        .ok_or("forbidden_evidence_markers must be array")?;
    assert!(
        forbidden
            .iter()
            .filter_map(Value::as_str)
            .any(|value| value == "[RCH] local"),
        "plan must reject rch local fallback evidence"
    );

    Ok(())
}

#[test]
fn workload_classes_cover_required_modes_budgets_and_failures() -> TestResult {
    let root = repo_root()?;
    let plan = load_json(&plan_path(&root))?;
    let classes = plan["workload_classes"]
        .as_array()
        .ok_or("workload_classes must be array")?;
    assert_eq!(classes.len(), 4);

    let required_failures = [
        "swarm_interpose_timeout",
        "swarm_interpose_segv",
        "swarm_interpose_symbol_lookup",
        "swarm_interpose_parity_mismatch",
        "swarm_interpose_performance_regression",
        "swarm_interpose_local_execution",
    ];
    let mut max_process_count = 0_u64;
    let mut max_thread_count = 0_u64;

    for class in classes {
        let id = class["id"].as_str().ok_or("class id missing")?;
        let modes: Vec<&str> = class["modes"]
            .as_array()
            .ok_or("class modes must be array")?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(modes.contains(&"strict"), "{id}: strict mode missing");
        assert!(modes.contains(&"hardened"), "{id}: hardened mode missing");
        assert_eq!(class["structured_logs"].as_bool(), Some(true));
        assert!(class["timeout_ms"].as_u64().unwrap_or(0) <= 120_000);

        let parallelism = &class["parallelism"];
        assert_eq!(parallelism["requires_min_cpu_cores"].as_u64(), Some(64));
        max_process_count =
            max_process_count.max(parallelism["process_count"].as_u64().unwrap_or(0));
        max_thread_count = max_thread_count.max(parallelism["thread_count"].as_u64().unwrap_or(0));

        let failures: Vec<&str> = class["expected_failure_signatures"]
            .as_array()
            .ok_or("expected_failure_signatures must be array")?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            failures.contains(&"swarm_interpose_local_execution"),
            "{id}: local fallback rejection missing"
        );
        assert!(
            failures
                .iter()
                .all(|failure| required_failures.contains(failure)),
            "{id}: unexpected failure signature in {failures:?}"
        );
    }

    assert!(
        max_process_count >= 192,
        "plan must include high process fanout"
    );
    assert!(
        max_thread_count >= 128,
        "plan must include high thread contention"
    );
    Ok(())
}

#[test]
fn checker_accepts_plan_and_emits_report_and_jsonl() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &plan_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("swarm_scale_interpose_workload_evidence_plan.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("swarm_scale_interpose_workload_evidence_plan.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["class_count"].as_u64(), Some(4));
    assert!(
        report["summary"]["domain_count"].as_u64().unwrap_or(0) >= 8,
        "domain coverage should span multiple runtime surfaces"
    );
    assert_eq!(report["summary"]["max_thread_count"].as_u64(), Some(128));

    let log_path = out_dir.join("swarm_scale_interpose_workload_evidence_plan.log.jsonl");
    let log = std::fs::read_to_string(&log_path)?;
    let records: Vec<Value> = log
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(records.len(), 2);
    for (index, line) in log.lines().enumerate() {
        validate_log_line(line, index + 1).map_err(|errors| {
            std::io::Error::other(format!("checker log row failed validation: {errors:?}"))
        })?;
    }
    assert!(
        records.iter().any(|record| {
            record["event"].as_str() == Some("swarm_scale_interpose_plan_execution_policy")
                && record["required_remote"].as_bool() == Some(true)
        }),
        "execution policy event must record remote-only requirement"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_remote_execution_policy() -> TestResult {
    let root = repo_root()?;
    let plan = load_json(&plan_path(&root))?;
    let variant = write_plan_variant(&root, &plan, "missing-remote-policy", |value| {
        value["execution_policy"]["required_command_prefix"] =
            serde_json::json!(["rch", "exec", "--"]);
        Ok(())
    })?;
    let out_dir = unique_out_dir(&root, "missing_remote_policy_out")?;
    let output = run_checker(&root, &variant, &out_dir)?;

    assert!(!output.status.success(), "{}", output_text(&output));
    let report =
        load_json(&out_dir.join("swarm_scale_interpose_workload_evidence_plan.report.json"))?;
    let errors = report["errors"].as_array().ok_or("errors must be array")?;
    assert!(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains("RCH_FORCE_REMOTE=true")),
        "expected remote execution error, got {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_workload_without_hardened_mode() -> TestResult {
    let root = repo_root()?;
    let plan = load_json(&plan_path(&root))?;
    let variant = write_plan_variant(&root, &plan, "missing-hardened-mode", |value| {
        value["workload_classes"][0]["modes"] = serde_json::json!(["strict"]);
        Ok(())
    })?;
    let out_dir = unique_out_dir(&root, "missing_hardened_mode_out")?;
    let output = run_checker(&root, &variant, &out_dir)?;

    assert!(!output.status.success(), "{}", output_text(&output));
    let report =
        load_json(&out_dir.join("swarm_scale_interpose_workload_evidence_plan.report.json"))?;
    let errors = report["errors"].as_array().ok_or("errors must be array")?;
    assert!(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains("modes must be strict+hardened")),
        "expected missing hardened mode error, got {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_failure_signature() -> TestResult {
    let root = repo_root()?;
    let plan = load_json(&plan_path(&root))?;
    let variant = write_plan_variant(&root, &plan, "missing-failure-signature", |value| {
        value["failure_signatures"]
            .as_object_mut()
            .ok_or("failure_signatures must be an object")?
            .remove("swarm_interpose_segv");
        Ok(())
    })?;
    let out_dir = unique_out_dir(&root, "missing_failure_signature_out")?;
    let output = run_checker(&root, &variant, &out_dir)?;

    assert!(!output.status.success(), "{}", output_text(&output));
    let report =
        load_json(&out_dir.join("swarm_scale_interpose_workload_evidence_plan.report.json"))?;
    let errors = report["errors"].as_array().ok_or("errors must be array")?;
    assert!(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains("missing failure signatures")),
        "expected missing failure signature error, got {errors:?}"
    );
    Ok(())
}
