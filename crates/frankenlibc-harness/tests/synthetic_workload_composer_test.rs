//! Integration tests for the bd-26xb.11 synthetic workload composer contract.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static CHECKER_LOCK: Mutex<()> = Mutex::new(());

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/synthetic_workload_composer.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_synthetic_workload_composer.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "synthetic-workload-composer-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_SYNTHETIC_WORKLOAD_COMPOSER", contract)
        .env("FRANKENLIBC_SYNTHETIC_WORKLOAD_COMPOSER_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_SYNTHETIC_WORKLOAD_COMPOSER_REPORT",
            out_dir.join("synthetic_workload_composer.report.json"),
        )
        .env(
            "FRANKENLIBC_SYNTHETIC_WORKLOAD_COMPOSER_LOG",
            out_dir.join("synthetic_workload_composer.log.jsonl"),
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

fn run_passing_checker(root: &Path, label: &str) -> TestResult<PathBuf> {
    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let out_dir = unique_out_dir(root, label)?;
    let output = run_checker(root, &contract_path(root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));
    Ok(out_dir)
}

fn string_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn contract_declares_trace_motifs_and_completion_debt() -> TestResult {
    let root = workspace_root();
    let contract = load_json(&contract_path(&root))?;

    assert_eq!(contract["schema_version"].as_str(), Some("v1"));
    assert_eq!(contract["bead"].as_str(), Some("bd-26xb.11"));
    assert_eq!(
        contract["completion_debt_bead"].as_str(),
        Some("bd-26xb.11.1")
    );
    assert!(contract["trace_motifs"].as_array().unwrap().len() >= 4);
    assert!(contract["composed_workloads"].as_array().unwrap().len() >= 3);

    let evidence = &contract["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-26xb.11.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-26xb.11"));
    assert_eq!(
        evidence["unit_primary"]["missing_item_id"].as_str(),
        Some("tests.unit.primary")
    );
    assert_eq!(
        evidence["e2e_primary"]["missing_item_id"].as_str(),
        Some("tests.e2e.primary")
    );
    assert_eq!(
        evidence["telemetry_primary"]["missing_item_id"].as_str(),
        Some("telemetry.primary")
    );

    let telemetry_events = string_set(&contract["telemetry_contract"]["required_events"]);
    for event in [
        "synthetic_workload_composer.motif_bound",
        "synthetic_workload_composer.composition_bound",
        "synthetic_workload_composer.tooling_bound",
        "synthetic_workload_composer.validated",
    ] {
        assert!(telemetry_events.contains(event));
    }

    Ok(())
}

#[test]
fn motifs_reference_workload_matrix() -> TestResult {
    let root = workspace_root();
    let contract = load_json(&contract_path(&root))?;
    let matrix = load_json(&root.join("tests/conformance/workload_matrix.json"))?;
    let workload_ids = string_set(&matrix["workloads"].as_array().unwrap().iter().fold(
        Value::Array(Vec::new()),
        |mut acc, row| {
            acc.as_array_mut()
                .unwrap()
                .push(row["id"].as_str().unwrap().into());
            acc
        },
    ));

    let mut seeds = BTreeSet::new();
    for motif in contract["trace_motifs"].as_array().unwrap() {
        let motif_id = motif["motif_id"].as_str().unwrap();
        for workload in motif["source_workload_ids"].as_array().unwrap() {
            let workload_id = workload.as_str().unwrap();
            assert!(
                workload_ids.contains(workload_id),
                "{motif_id} references unknown workload {workload_id}"
            );
        }
        assert!(motif["intensity"].as_u64().unwrap() > 0);
        assert!(motif["required_modules"].as_array().unwrap().len() >= 3);
        assert!(motif["critical_symbols"].as_array().unwrap().len() >= 3);
        assert!(
            seeds.insert(motif["deterministic_seed"].as_u64().unwrap()),
            "duplicate deterministic seed"
        );
    }

    Ok(())
}

#[test]
fn composed_workloads_preserve_motif_unions() -> TestResult {
    let root = workspace_root();
    let contract = load_json(&contract_path(&root))?;
    let motifs = contract["trace_motifs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|motif| (motif["motif_id"].as_str().unwrap(), motif))
        .collect::<BTreeMap<_, _>>();

    for composition in contract["composed_workloads"].as_array().unwrap() {
        let composition_id = composition["composition_id"].as_str().unwrap();
        let mut modules = BTreeSet::new();
        let mut symbols = BTreeSet::new();
        for motif_id in composition["motifs"].as_array().unwrap() {
            let motif_id = motif_id.as_str().unwrap();
            let motif = motifs
                .get(motif_id)
                .ok_or_else(|| format!("{composition_id} unknown motif {motif_id}"))?;
            modules.extend(
                motif["required_modules"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap()),
            );
            symbols.extend(
                motif["critical_symbols"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap()),
            );
        }
        let actual_modules: BTreeSet<_> = composition["required_modules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        let actual_symbols: BTreeSet<_> = composition["critical_symbols"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert!(modules.is_subset(&actual_modules), "{composition_id}");
        assert!(symbols.is_subset(&actual_symbols), "{composition_id}");
        assert!(
            composition["expected_rare_edge_uplift_pct"]
                .as_f64()
                .unwrap()
                > 0.0
        );
        assert_eq!(
            composition["preservation_checks"]["deterministic_seed_replay"].as_bool(),
            Some(true)
        );
    }

    Ok(())
}

#[test]
fn checker_passes_and_emits_report_log() -> TestResult {
    let root = workspace_root();
    let out_dir = run_passing_checker(&root, "pass")?;
    let report = load_json(&out_dir.join("synthetic_workload_composer.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["motif_count"].as_u64(), Some(4));
    assert_eq!(report["summary"]["composition_count"].as_u64(), Some(3));
    assert_eq!(
        report["summary"]["tooling"]["asupersync"].as_bool(),
        Some(true)
    );
    assert_eq!(
        report["summary"]["tooling"]["frankentui"].as_bool(),
        Some(true)
    );

    let rows = read_jsonl(&out_dir.join("synthetic_workload_composer.log.jsonl"))?;
    let events: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row["event"].as_str().map(str::to_string))
        .collect();
    for event in [
        "synthetic_workload_composer.motif_bound",
        "synthetic_workload_composer.composition_bound",
        "synthetic_workload_composer.tooling_bound",
        "synthetic_workload_composer.validated",
    ] {
        assert!(events.contains(event), "missing {event}: {events:?}");
    }
    for row in rows {
        for field in [
            "trace_id",
            "bead_id",
            "event",
            "status",
            "mode",
            "api_family",
            "symbol",
            "decision_path",
            "healing_action",
            "errno",
            "latency_ns",
            "artifact_refs",
            "source_commit",
            "composition_id",
            "motif_id",
            "edge_emphasis_score",
        ] {
            assert!(row.get(field).is_some(), "log row missing {field}: {row}");
        }
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_motif_reference() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_out_dir(&root, "missing-motif")?;
    let mut contract = load_json(&contract_path(&root))?;
    contract["composed_workloads"][0]["motifs"] = json!(["missing-motif"]);
    let mutated = out_dir.join("contract_missing_motif.json");
    write_json(&mutated, &contract)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly passed:\n{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("synthetic_workload_composer.report.json"))?;
    assert!(
        report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("missing-motif")),
        "expected missing motif error: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_disabled_tooling_traceability() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_out_dir(&root, "disabled-tooling")?;
    let mut contract = load_json(&contract_path(&root))?;
    contract["tooling_contract"]["asupersync_traceability"]["enabled"] = json!(false);
    let mutated = out_dir.join("contract_disabled_tooling.json");
    write_json(&mutated, &contract)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly passed:\n{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("synthetic_workload_composer.report.json"))?;
    assert!(
        report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("asupersync")),
        "expected asupersync tooling error: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_non_deterministic_replay() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_out_dir(&root, "nondeterministic")?;
    let mut contract = load_json(&contract_path(&root))?;
    contract["composed_workloads"][0]["preservation_checks"]["deterministic_seed_replay"] =
        json!(false);
    let mutated = out_dir.join("contract_nondeterministic.json");
    write_json(&mutated, &contract)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly passed:\n{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("synthetic_workload_composer.report.json"))?;
    assert!(
        report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("deterministic_seed_replay")),
        "expected deterministic replay error: {report}"
    );

    Ok(())
}
