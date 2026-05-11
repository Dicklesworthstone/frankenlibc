use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_SPEC_ITEMS: &[&str] = &["tests.conformance.primary", "tests.unit.primary"];
const REQUIRED_SYMBOLS: &[&str] = &[
    "ns_datetosecs",
    "ns_format_ttl",
    "ns_get16",
    "ns_get32",
    "ns_initparse",
    "ns_makecanon",
    "ns_msg_getflag",
    "ns_name_ntol",
    "ns_name_rollback",
    "ns_parse_ttl",
    "ns_parserr",
    "ns_put16",
    "ns_put32",
    "ns_samedomain",
    "ns_samename",
    "ns_skiprr",
    "ns_sprintrr",
    "ns_sprintrrf",
    "ns_subdomain",
];
const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "completion_bindings_validated",
    "export_map_validated",
    "unit_test_bindings_validated",
    "conformance_test_bindings_validated",
    "ns_libresolv_exports_completion_contract_pass",
];

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("missing workspace root")?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/ns_libresolv_exports_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_ns_libresolv_exports_completion_contract.sh")
}

fn report_path(out_dir: &Path) -> PathBuf {
    out_dir.join("ns_libresolv_exports_completion_contract.report.json")
}

fn log_path(out_dir: &Path) -> PathBuf {
    out_dir.join("ns_libresolv_exports_completion_contract.log.jsonl")
}

fn read_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn read_jsonl(path: &Path) -> Result<Vec<Value>, Box<dyn Error>> {
    let text = std::fs::read_to_string(path)?;
    Ok(text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?)
}

fn string_set(value: &Value) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected array"))?;
    Ok(array
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToString::to_string)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))
        })
        .collect::<Result<_, _>>()?)
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = root
        .join("target/conformance")
        .join(format!("ns-libresolv-exports-{label}-{nanos}"));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> io::Result<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .arg(contract)
        .env(
            "FRANKENLIBC_NS_LIBRESOLV_EXPORTS_COMPLETION_OUT_DIR",
            out_dir,
        )
        .current_dir(root)
        .output()
}

fn mutated_contract(
    root: &Path,
    out_dir: &Path,
    label: &str,
    mutate: impl FnOnce(&mut Value),
) -> TestResult<PathBuf> {
    let mut manifest = read_json(&contract_path(root))?;
    mutate(&mut manifest);
    let path = out_dir.join(format!(
        "ns_libresolv_exports_completion_contract.{label}.json"
    ));
    std::fs::write(&path, serde_json::to_string_pretty(&manifest)? + "\n")?;
    Ok(path)
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_checker_failed(output: &Output) {
    assert!(
        !output.status.success(),
        "checker unexpectedly passed\n{}",
        output_text(output)
    );
}

fn failure_signatures(report: &Value) -> BTreeSet<String> {
    report["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry["signature"].as_str())
        .map(ToString::to_string)
        .collect()
}

#[test]
fn manifest_binds_ns_libresolv_completion_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("ns_libresolv_exports_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-0j2ha.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-0j2ha"));

    let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing bindings"))?;
    assert_eq!(bindings.len(), 2);
    let specs: BTreeSet<String> = bindings
        .iter()
        .filter_map(|binding| binding["spec_item"].as_str())
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        specs,
        REQUIRED_SPEC_ITEMS
            .iter()
            .map(|item| item.to_string())
            .collect()
    );

    let runtime = &manifest["ns_libresolv_export_contract"];
    let symbols = string_set(&runtime["required_symbols"])?;
    assert_eq!(
        symbols,
        REQUIRED_SYMBOLS
            .iter()
            .map(|symbol| symbol.to_string())
            .collect()
    );
    assert_eq!(
        runtime["version_script_anchor"].as_str().unwrap(),
        "libresolv ns_* helpers implemented in resolv_abi.rs (bd-0j2ha)"
    );

    for artifact in manifest["source_artifacts"].as_array().unwrap() {
        let path = artifact["path"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact path missing"))?;
        assert!(root.join(path).exists(), "missing source artifact {path}");
    }

    let events = string_set(&manifest["completion_output_contract"]["required_events"])?;
    let required_events: BTreeSet<String> = REQUIRED_EVENTS
        .iter()
        .map(|event| event.to_string())
        .collect();
    assert_eq!(events, required_events);
    Ok(())
}

#[test]
fn checker_validates_ns_libresolv_exports_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&report_path(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["binding_count"].as_u64(), Some(2));
    assert_eq!(
        report["summary"]["required_symbol_count"].as_u64(),
        Some(19)
    );
    assert_eq!(report["summary"]["unit_test_count"].as_u64(), Some(19));
    assert_eq!(
        report["summary"]["conformance_group_count"].as_u64(),
        Some(2)
    );

    let rows = read_jsonl(&log_path(&out_dir))?;
    let events: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .map(ToString::to_string)
        .collect();
    for event in REQUIRED_EVENTS {
        assert!(events.contains(*event), "missing event {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-unit")?;
    let contract = mutated_contract(&root, &out_dir, "missing-unit", |manifest| {
        let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
            .as_array_mut()
            .expect("bindings array");
        bindings.retain(|binding| binding["spec_item"].as_str() != Some("tests.unit.primary"));
    })?;

    let output = run_checker(&root, &contract, &out_dir)?;
    assert_checker_failed(&output);

    let report = read_json(&report_path(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(signatures.contains("missing_completion_binding"));
    Ok(())
}

#[test]
fn checker_rejects_missing_required_symbol() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-symbol")?;
    let contract = mutated_contract(&root, &out_dir, "missing-symbol", |manifest| {
        let symbols = manifest["ns_libresolv_export_contract"]["required_symbols"]
            .as_array_mut()
            .expect("required symbols array");
        symbols.retain(|symbol| symbol.as_str() != Some("ns_parserr"));
    })?;

    let output = run_checker(&root, &contract, &out_dir)?;
    assert_checker_failed(&output);

    let report = read_json(&report_path(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(signatures.contains("symbol_set_drift"));
    Ok(())
}

#[test]
fn checker_rejects_conformance_binding_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "conformance-drift")?;
    let contract = mutated_contract(&root, &out_dir, "conformance-drift", |manifest| {
        manifest["ns_libresolv_export_contract"]["required_conformance_tests"][0]["tests"][1] =
            json!("missing_export_gap_test");
    })?;

    let output = run_checker(&root, &contract, &out_dir)?;
    assert_checker_failed(&output);

    let report = read_json(&report_path(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(signatures.contains("conformance_binding_drift"));
    Ok(())
}
