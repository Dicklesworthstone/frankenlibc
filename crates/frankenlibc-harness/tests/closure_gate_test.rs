//! Integration test: Closure evidence gate (bd-4rl)
//!
//! Validates that:
//! 1. The closure evidence schema exists and is valid JSON.
//! 2. Every required evidence field is defined in the schema.
//! 3. Legacy-exempt list is well-formed (and, when using beads, only covers closed critique beads).
//! 4. Non-exempt closed critique beads have matrix entries with evidence.
//! 5. The CI gate script exists and is executable.
//! 6. Matrix rows have the evidence fields the schema requires.
//!
//! Source selection:
//! - FRANKENLIBC_CLOSURE_GATE_SOURCE=beads uses .beads/issues.jsonl for closed-critique detection.
//! - Default (matrix) uses tests/conformance/verification_matrix.json to avoid stale beads in rch.
//!
//! Run: cargo test -p frankenlibc-harness --test closure_gate_test

use std::collections::{HashMap, HashSet};
use std::env;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn schema_path() -> PathBuf {
    workspace_root().join("tests/conformance/closure_evidence_schema.json")
}

fn matrix_path() -> PathBuf {
    workspace_root().join("tests/conformance/verification_matrix.json")
}

fn beads_path() -> PathBuf {
    workspace_root().join(".beads/issues.jsonl")
}

fn load_schema() -> serde_json::Value {
    let path = schema_path();
    let content =
        std::fs::read_to_string(&path).expect("closure_evidence_schema.json should exist");
    serde_json::from_str(&content).expect("closure_evidence_schema.json should be valid JSON")
}

fn load_matrix() -> serde_json::Value {
    let path = matrix_path();
    let content = std::fs::read_to_string(&path).expect("verification_matrix.json should exist");
    serde_json::from_str(&content).expect("verification_matrix.json should be valid JSON")
}

fn load_beads_latest() -> HashMap<String, serde_json::Value> {
    let path = beads_path();
    let content = std::fs::read_to_string(&path).expect(".beads/issues.jsonl should exist");
    let mut beads = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let bead: serde_json::Value =
            serde_json::from_str(line).expect("each bead line should be valid JSON");
        if let Some(id) = bead["id"].as_str() {
            beads.insert(id.to_string(), bead);
        }
    }
    beads
}

fn has_label(value: &serde_json::Value, label: &str) -> bool {
    value
        .as_array()
        .is_some_and(|labels| labels.iter().any(|v| v.as_str() == Some(label)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClosureGateSource {
    Matrix,
    Beads,
}

fn closure_gate_source() -> ClosureGateSource {
    match env::var("FRANKENLIBC_CLOSURE_GATE_SOURCE")
        .unwrap_or_else(|_| "matrix".to_string())
        .to_lowercase()
        .as_str()
    {
        "matrix" => ClosureGateSource::Matrix,
        "beads" => ClosureGateSource::Beads,
        other => {
            panic!("invalid FRANKENLIBC_CLOSURE_GATE_SOURCE={other} (expected 'matrix' or 'beads')")
        }
    }
}

fn closed_critique_from_beads(beads: &HashMap<String, serde_json::Value>) -> HashSet<String> {
    beads
        .values()
        .filter(|b| b["status"].as_str() == Some("closed") && has_label(&b["labels"], "critique"))
        .filter_map(|b| b["id"].as_str().map(String::from))
        .collect()
}

fn closed_critique_from_matrix(matrix: &serde_json::Value) -> HashSet<String> {
    matrix["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| {
            entry["status"].as_str() == Some("closed") && has_label(&entry["labels"], "critique")
        })
        .filter_map(|entry| entry["bead_id"].as_str().map(String::from))
        .collect()
}

fn closed_critique_bead_ids() -> HashSet<String> {
    match closure_gate_source() {
        ClosureGateSource::Matrix => closed_critique_from_matrix(&load_matrix()),
        ClosureGateSource::Beads => closed_critique_from_beads(&load_beads_latest()),
    }
}

#[test]
fn schema_exists_and_valid() {
    let schema = load_schema();
    assert!(
        schema["schema_version"].is_number(),
        "Missing schema_version"
    );
    assert!(
        schema["evidence_requirements"].is_object(),
        "Missing evidence_requirements"
    );
    assert!(schema["legacy_exempt"].is_array(), "Missing legacy_exempt");
    assert!(schema["enforcement"].is_object(), "Missing enforcement");
    assert!(schema["paths"].is_object(), "Missing paths");
}

#[test]
fn schema_has_required_evidence_fields() {
    let schema = load_schema();
    let reqs = schema["evidence_requirements"].as_object().unwrap();

    let expected = [
        "matrix_entry",
        "test_commands",
        "artifact_references",
        "coverage_not_missing",
        "close_blockers_empty",
    ];

    for field in &expected {
        assert!(
            reqs.contains_key(*field),
            "evidence_requirements missing '{field}'"
        );
        let req = &reqs[*field];
        assert!(
            req["required"].is_boolean(),
            "{field}: missing 'required' boolean"
        );
        assert!(
            req["description"].is_string(),
            "{field}: missing 'description'"
        );
    }
}

#[test]
fn legacy_exempt_only_contains_closed_critique_beads() {
    let schema = load_schema();
    let exempt_list = schema["legacy_exempt"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    let exempt: HashSet<String> = exempt_list.iter().map(|v| (*v).to_string()).collect();

    if closure_gate_source() == ClosureGateSource::Matrix {
        assert_eq!(
            exempt.len(),
            exempt_list.len(),
            "legacy_exempt contains duplicate entries"
        );
        return;
    }

    let closed_critique = closed_critique_bead_ids();

    let invalid: Vec<_> = exempt.difference(&closed_critique).collect();
    assert!(
        invalid.is_empty(),
        "Legacy-exempt beads that are not closed critique beads: {:?}",
        invalid
    );
}

#[test]
fn non_exempt_closed_beads_have_matrix_entries() {
    if closure_gate_source() == ClosureGateSource::Matrix {
        return;
    }

    let schema = load_schema();
    let matrix = load_matrix();

    let exempt: HashSet<String> = schema["legacy_exempt"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let matrix_ids: HashSet<String> = matrix["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["bead_id"].as_str().map(String::from))
        .collect();

    let mut missing = Vec::new();
    let closed_critique = closed_critique_bead_ids();
    for bid in closed_critique {
        if !exempt.contains(&bid) && !matrix_ids.contains(&bid) {
            missing.push(bid);
        }
    }

    assert!(
        missing.is_empty(),
        "Non-exempt closed critique beads without matrix entries: {:?}",
        missing
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_closure_gate.sh");
    assert!(script.exists(), "scripts/check_closure_gate.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_closure_gate.sh must be executable"
        );
    }
}

#[test]
fn matrix_rows_have_evidence_fields() {
    let matrix = load_matrix();
    let entries = matrix["entries"].as_array().unwrap();

    let required_row_fields = ["unit_cmds", "e2e_cmds", "artifact_paths", "close_blockers"];

    for entry in entries {
        let bid = entry["bead_id"].as_str().unwrap_or("<unknown>");
        let row = &entry["row"];
        assert!(row.is_object(), "{bid}: missing row object");

        for field in &required_row_fields {
            assert!(
                !row[field].is_null(),
                "{bid}: row missing required field '{field}'"
            );
        }

        assert!(
            entry["coverage_summary"].is_object(),
            "{bid}: missing coverage_summary"
        );
        let overall = entry["coverage_summary"]["overall"].as_str().unwrap_or("");
        assert!(
            ["missing", "partial", "complete"].contains(&overall),
            "{bid}: invalid coverage_summary.overall '{overall}'"
        );
    }
}

#[test]
fn non_exempt_closed_beads_have_evidence() {
    let schema = load_schema();
    let matrix = load_matrix();

    let exempt: HashSet<String> = schema["legacy_exempt"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let matrix_map: std::collections::HashMap<String, &serde_json::Value> = matrix["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["bead_id"].as_str().map(|id| (id.to_string(), e)))
        .collect();

    let mut violations = Vec::new();
    let closed_critique = closed_critique_bead_ids();
    for bid in closed_critique {
        if exempt.contains(&bid) {
            continue;
        }
        if let Some(entry) = matrix_map.get(&bid) {
            let row = &entry["row"];
            let cs = &entry["coverage_summary"];

            let unit_cmds = row["unit_cmds"].as_array().is_none_or(|a| a.is_empty());
            let e2e_cmds = row["e2e_cmds"].as_array().is_none_or(|a| a.is_empty());
            if unit_cmds && e2e_cmds {
                violations.push(format!("{bid}: no test commands"));
            }

            let artifacts = row["artifact_paths"]
                .as_array()
                .is_none_or(|a| a.is_empty());
            let log_refs = row["log_schema_refs"]
                .as_array()
                .is_none_or(|a| a.is_empty());
            if artifacts && log_refs {
                violations.push(format!("{bid}: no artifact references"));
            }

            if cs["overall"].as_str() == Some("missing") {
                violations.push(format!("{bid}: coverage_summary is 'missing'"));
            }

            let blockers = row["close_blockers"]
                .as_array()
                .is_some_and(|a| !a.is_empty());
            if blockers {
                violations.push(format!("{bid}: has close_blockers"));
            }
        } else {
            violations.push(format!("{bid}: no matrix entry"));
        }
    }

    assert!(
        violations.is_empty(),
        "Non-exempt closed beads with evidence violations:\n{}",
        violations.join("\n")
    );
}

// These are inputs to the evidence validator, not captured libc behavior. The
// positive really compiles and executes libtest; the planted implementation
// changes its arithmetic while leaving the two assertions unchanged.
struct EvidenceFixture {
    dir: PathBuf,
    matrix: Value,
    bead: Value,
    schema: Value,
    receipt: PathBuf,
}

fn digest(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn utc_now() -> String {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%S.%NZ"])
        .output()
        .expect("date for isolated closure window");
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

impl EvidenceFixture {
    fn new(implementation: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "closure-results-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let root = workspace_root();
        let dir = root.join("target/conformance").join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("behavior.rs");
        let source_text = format!(
            "fn increment(n: i32) -> i32 {{ {implementation} }}\n\
             #[test] fn behavior_smoke() {{ assert_eq!(increment(4), 5); }}\n\
             #[test] fn boundary() {{ assert_eq!(increment(-1), 0); }}\n"
        );
        std::fs::write(&source, &source_text).unwrap();
        let source_rel = source.strip_prefix(&root).unwrap().to_str().unwrap();
        let binary = dir.join("behavior-tests").to_str().unwrap().to_owned();
        let commit = env::var("RCH_BUILD_SOURCE")
            .map(|v| v.trim_end_matches("-dirty").to_owned())
            .unwrap_or_else(|_| {
                let output = Command::new("git")
                    .args(["rev-parse", "HEAD"])
                    .current_dir(&root)
                    .output()
                    .unwrap();
                assert!(output.status.success());
                String::from_utf8(output.stdout).unwrap().trim().to_owned()
            });
        let acceptance = "increment returns n + 1 for ordinary and boundary inputs";
        let contract = json!({
            "behavior": "isolated-increment-contract",
            "acceptance_sha256": digest(acceptance.as_bytes()),
            "claim_class": "executed_unit", "evidence_class": "executed_unit",
            "source": {"commit": commit, "files": {source_rel: digest(source_text.as_bytes())}},
            "behavior_paths": [source_rel], "test_paths": [source_rel],
            "configuration": {"architecture": env::consts::ARCH, "mode": "strict", "profile": "test", "features": []},
            "not_before": "2026-10-31T00:00:00Z",
            "gate": {
                "command": [binary, "--test-threads=1"],
                "environment": {"FRANKENLIBC_MODE": "strict"},
                "build_command": ["rustc", "--edition=2024", "--test", source_rel, "-o", binary],
                "artifacts": [binary], "result_format": "libtest",
                "required_tests": ["behavior_smoke", "boundary"]
            }
        });
        let matrix = json!({"entries": [{
            "bead_id": "bd-isolated-result", "status": "closed", "labels": [],
            "coverage_summary": {"overall": "complete"},
            "row": {"unit_cmds": ["rustc --test behavior.rs"], "e2e_cmds": [],
                    "artifact_paths": [binary], "close_blockers": [],
                    "closure_evidence": contract,
                    "result_receipts": [dir.join("run/receipt.json")]}
        }]});
        let bead = json!({"id": "bd-isolated-result", "issue_type": "task", "status": "in_progress",
                          "created_at": "2026-10-30T00:00:00Z", "acceptance_criteria": acceptance,
                          "close_reason": "Verification PASS: scripts/check_closure_gate.sh; fabricated prose alone."});
        let fixture = Self {
            receipt: dir.join("run/receipt.json"),
            dir,
            matrix,
            bead,
            schema: load_schema(),
        };
        fixture.save();
        fixture
    }

    fn save(&self) {
        std::fs::write(
            self.dir.join("matrix.json"),
            serde_json::to_vec_pretty(&self.matrix).unwrap(),
        )
        .unwrap();
        std::fs::write(self.dir.join("beads.jsonl"), format!("{}\n", self.bead)).unwrap();
        std::fs::write(
            self.dir.join("schema.json"),
            serde_json::to_vec_pretty(&self.schema).unwrap(),
        )
        .unwrap();
    }

    fn gate(&self, args: &[&str]) -> Output {
        let output = Command::new("bash")
            .arg(workspace_root().join("scripts/check_closure_gate.sh"))
            .args(args)
            .env("FRANKENLIBC_CLOSURE_MATRIX", self.dir.join("matrix.json"))
            .env("FRANKENLIBC_CLOSURE_SCHEMA", self.dir.join("schema.json"))
            .env("FRANKENLIBC_BEADS_JSONL", self.dir.join("beads.jsonl"))
            .env("FRANKENLIBC_CLOSURE_GATE_SOURCE", "matrix")
            .env_remove("FRANKENLIBC_CLOSURE_CUTOFF")
            .output()
            .unwrap();
        // Retain both streams and actual exits, including planted failures.
        static RUN: AtomicU64 = AtomicU64::new(0);
        let prefix = self
            .dir
            .join(format!("gate-{}", RUN.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(prefix.with_extension("stdout"), &output.stdout).unwrap();
        std::fs::write(prefix.with_extension("stderr"), &output.stderr).unwrap();
        std::fs::write(prefix.with_extension("exit"), output.status.to_string()).unwrap();
        output
    }

    fn record(&self) -> Output {
        self.gate(&[
            "--record",
            "bd-isolated-result",
            self.dir.join("run").to_str().unwrap(),
        ])
    }

    fn close_now(&mut self) {
        self.bead["status"] = json!("closed");
        self.bead["closed_at"] = json!(utc_now());
        self.save();
    }

    fn assert_result(output: Output, success: bool, expected: &str) {
        let text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.status.success(), success, "{text}");
        assert!(text.contains(expected), "missing {expected:?}: {text}");
    }

    fn write_receipt(&self, receipt: &Value) {
        std::fs::write(&self.receipt, serde_json::to_vec_pretty(receipt).unwrap()).unwrap();
    }
}

#[test]
fn actual_gate_consumes_nonzero_results_and_rejects_receipt_corruption() {
    let mut f = EvidenceFixture::new("n + 1");
    let refs = f.matrix["entries"][0]["row"]["result_receipts"].clone();
    f.matrix["entries"][0]["row"]["result_receipts"] = json!([]);
    f.close_now();
    EvidenceFixture::assert_result(f.gate(&[]), false, "missing_stored_execution_result");
    f.matrix["entries"][0]["row"]["result_receipts"] = refs;
    f.bead["status"] = json!("in_progress");
    f.bead.as_object_mut().unwrap().remove("closed_at");
    f.save();
    EvidenceFixture::assert_result(f.record(), true, "RECORDED");
    let execution = std::fs::read_to_string(f.dir.join("run/execution.stdout")).unwrap();
    assert!(execution.contains("test result: ok. 2 passed; 0 failed;"));
    f.close_now();
    EvidenceFixture::assert_result(f.gate(&[]), true, "POST_PASS=1");
    let original: Value = serde_json::from_slice(&std::fs::read(&f.receipt).unwrap()).unwrap();
    let controls = [
        ("/execution/exit_code", json!(1), "execution_failed"),
        ("/build/exit_code", json!(101), "build_failed"),
        ("/execution", Value::Null, "missing_execution_result"),
        ("/bead_id", json!("bd-unrelated"), "wrong_receipt_identity"),
        ("/execution/stdout", json!("absent.stdout"), "UNPROVEN"),
        (
            "/execution/stdout_sha256",
            json!("0".repeat(64)),
            "missing_or_changed_execution_stdout",
        ),
        (
            "/execution/stderr_sha256",
            json!("0".repeat(64)),
            "missing_or_changed_execution_stderr",
        ),
        (
            "/execution/command",
            json!(["cargo", "check"]),
            "wrong_execution_command",
        ),
        (
            "/contract/source/commit",
            json!("0".repeat(40)),
            "wrong_source_config_or_gate_contract",
        ),
        (
            "/contract/configuration/mode",
            json!("hardened"),
            "wrong_source_config_or_gate_contract",
        ),
        (
            "/runner_architecture",
            json!("wrong-architecture"),
            "wrong_runner_architecture",
        ),
        (
            "/execution/started_at",
            json!("2026-10-01T00:00:00Z"),
            "stale_or_future_execution_result",
        ),
        (
            "/execution/finished_at",
            json!("2099-01-01T00:00:00Z"),
            "stale_or_future_execution_result",
        ),
        (
            "/executable_sha256",
            json!("0".repeat(64)),
            "wrong_executed_binary",
        ),
        (
            "/execution/executed_cases",
            json!(0),
            "executed_count_mismatch",
        ),
        ("/source_files", json!({}), "wrong_source_manifest"),
    ];
    for (pointer, value, expected) in controls {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        f.write_receipt(&changed);
        EvidenceFixture::assert_result(f.gate(&[]), false, expected);
        println!("CONTROL {pointer}: rejected");
    }
    let mut changed = original.clone();
    let artifacts = changed["artifacts"].as_object_mut().unwrap();
    *artifacts.values_mut().next().unwrap() = json!("0".repeat(64));
    f.write_receipt(&changed);
    EvidenceFixture::assert_result(f.gate(&[]), false, "missing_or_changed_build_artifact");
    f.write_receipt(&original);
    f.bead["acceptance_criteria"] = json!("an unrelated behavior");
    f.save();
    EvidenceFixture::assert_result(f.gate(&[]), false, "wrong_acceptance_criteria");
    println!("CONTROL receipt corruption: 18/18 rejected; genuine 2-test execution admitted");
}

#[test]
fn actual_gate_rejects_wrong_live_source_and_build_configuration() {
    let mut f = EvidenceFixture::new("n + 1");
    let original = f.matrix["entries"][0]["row"]["closure_evidence"].clone();
    let controls = [
        ("/source/commit", json!("0".repeat(40)), "wrong_"),
        (
            "/configuration/architecture",
            json!("wrong-architecture"),
            "wrong_runner_architecture",
        ),
        (
            "/configuration/profile",
            json!("release"),
            "wrong_build_configuration",
        ),
        (
            "/configuration/features",
            json!(["unrelated-feature"]),
            "wrong_build_configuration",
        ),
        (
            "/configuration/mode",
            json!("hardened"),
            "mode_environment_mismatch",
        ),
        (
            "/gate/build_command",
            json!(["cargo", "check"]),
            "build_is_not_separate_test_compilation",
        ),
    ];
    for (pointer, value, expected) in controls {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        f.matrix["entries"][0]["row"]["closure_evidence"] = changed;
        f.save();
        EvidenceFixture::assert_result(f.record(), false, expected);
    }
    let mut changed = original.clone();
    *changed["source"]["files"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap() = json!("0".repeat(64));
    f.matrix["entries"][0]["row"]["closure_evidence"] = changed;
    f.save();
    EvidenceFixture::assert_result(f.record(), false, "wrong_live_source");
    for class in [
        "deployed_abi",
        "standalone",
        "measured_performance",
        "mechanized_theorem",
    ] {
        let mut changed = original.clone();
        changed["claim_class"] = json!(class);
        changed["evidence_class"] = json!(class);
        f.schema["executed_results"]["supported_classes"]
            .as_array_mut()
            .unwrap()
            .push(json!(class));
        f.matrix["entries"][0]["row"]["closure_evidence"] = changed;
        f.save();
        EvidenceFixture::assert_result(f.record(), false, "unsupported_evidence_class");
    }
    println!(
        "CONTROL live source/commit/architecture/profile/features/mode/compile-only and 4 unsupported proof classes: 11/11 rejected before execution"
    );
}

#[test]
fn actual_gate_rejects_zero_tests_compile_failure_and_wrong_implementation() {
    let mut zero = EvidenceFixture::new("n + 1");
    zero.matrix["entries"][0]["row"]["closure_evidence"]["gate"]["command"]
        .as_array_mut()
        .unwrap()
        .push(json!("matches_no_tests"));
    zero.save();
    EvidenceFixture::assert_result(zero.record(), false, "missing_nonzero_executed_result");
    let stdout = std::fs::read_to_string(zero.dir.join("run/execution.stdout")).unwrap();
    assert!(stdout.contains("test result: ok. 0 passed; 0 failed;"));
    zero.close_now();
    EvidenceFixture::assert_result(zero.gate(&[]), false, "missing_nonzero_executed_result");

    let mut compile = EvidenceFixture::new("does_not_compile(n)");
    EvidenceFixture::assert_result(compile.record(), false, "build_failed");
    compile.close_now();
    EvidenceFixture::assert_result(compile.gate(&[]), false, "build_failed");

    let mut wrong = EvidenceFixture::new("n - 1");
    EvidenceFixture::assert_result(wrong.record(), false, "execution_failed");
    let stdout = std::fs::read_to_string(wrong.dir.join("run/execution.stdout")).unwrap();
    assert!(stdout.contains("test result: FAILED. 0 passed; 2 failed;"));
    wrong.close_now();
    EvidenceFixture::assert_result(wrong.gate(&[]), false, "execution_failed");

    let mut unrelated = EvidenceFixture::new("n + 1");
    unrelated.matrix["entries"][0]["row"]["closure_evidence"]["gate"]["required_tests"] =
        json!(["absent_behavior"]);
    unrelated.save();
    EvidenceFixture::assert_result(unrelated.record(), false, "unrelated_passing_tests");
    unrelated.close_now();
    EvidenceFixture::assert_result(unrelated.gate(&[]), false, "unrelated_passing_tests");
    println!(
        "CONTROL zero/compile failure/wrong implementation/unrelated passing target: 4/4 rejected"
    );
}

#[test]
fn actual_gate_distinguishes_compiled_from_executed_evidence() {
    let mut f = EvidenceFixture::new("n + 1");
    f.bead["labels"] = json!(["compile-only"]);
    let acceptance = "Compile the named two-test fixture binary.";
    f.bead["acceptance_criteria"] = json!(acceptance);
    let contract = &mut f.matrix["entries"][0]["row"]["closure_evidence"];
    contract["acceptance_sha256"] = json!(digest(acceptance.as_bytes()));
    contract["behavior"] = json!("isolated-fixture-compilation");
    contract["claim_class"] = json!("compiled");
    contract["evidence_class"] = json!("compiled");
    let binary = contract["gate"]["artifacts"][0].clone();
    contract["gate"]["command"] = json!([
        "python3",
        "-c",
        "import pathlib,sys; assert pathlib.Path(sys.argv[1]).stat().st_size > 0; print('named test binary compiled')",
        binary
    ]);
    contract["gate"]["expected_stdout"] = json!(["named test binary compiled"]);
    f.save();
    EvidenceFixture::assert_result(f.record(), true, "RECORDED");
    f.close_now();
    EvidenceFixture::assert_result(f.gate(&[]), true, "compiled; retained results verified");
    let receipt: Value = serde_json::from_slice(&std::fs::read(&f.receipt).unwrap()).unwrap();
    assert!(receipt["execution"]["executed_cases"].is_null());
    f.bead["labels"] = json!([]);
    f.save();
    EvidenceFixture::assert_result(
        f.gate(&[]),
        false,
        "lower_evidence_class_requires_explicit_bead_label",
    );
    f.matrix["entries"][0]["row"]["closure_evidence"]["claim_class"] = json!("executed_unit");
    f.save();
    EvidenceFixture::assert_result(f.gate(&[]), false, "claim_class_mismatch");
    println!(
        "CONTROL real compiled artifact admitted only as compiled; runtime inflation rejected"
    );
}

#[test]
fn actual_gate_keeps_source_checks_and_historical_exemptions_explicit() {
    let mut f = EvidenceFixture::new("n + 1");
    f.bead["labels"] = json!(["docs-only"]);
    let acceptance = "Closure evidence schema records version 2.";
    f.bead["acceptance_criteria"] = json!(acceptance);
    let contract = &mut f.matrix["entries"][0]["row"]["closure_evidence"];
    contract["acceptance_sha256"] = json!(digest(acceptance.as_bytes()));
    contract["behavior"] = json!("closure-schema-version");
    contract["configuration"]["profile"] = json!("source");
    contract["claim_class"] = json!("source");
    contract["evidence_class"] = json!("source");
    contract["gate"] = json!({
        "command": ["python3", "-c", "import json,sys; assert json.load(open(sys.argv[1]))['schema_version'] == 2; print('closure schema version checked')", schema_path()],
        "environment": {"FRANKENLIBC_MODE": "strict"},
        "expected_stdout": ["closure schema version checked"]
    });
    contract["source"]["files"] = json!({
        "tests/conformance/closure_evidence_schema.json": digest(&std::fs::read(schema_path()).unwrap())
    });
    contract["behavior_paths"] = json!(["tests/conformance/closure_evidence_schema.json"]);
    contract["test_paths"] = json!([]);
    f.save();
    EvidenceFixture::assert_result(f.record(), true, "RECORDED");
    f.close_now();
    // Honest prose indirection that the old regex rejected is irrelevant once
    // the actual lower-class result is read. These are formatting controls,
    // not retroactive qualification of the real similarly worded closures.
    for reason in [
        "Fixed at17a473c962dbeaf0e446c74b4fe841dbb00dc759; final solo replay in comment3013.",
        "Fixed at9310843d9112b8c752f498f9b990f96b20e43c74; see comment3019.",
        "Qualified at5c0dc48169a9bd8f4bb8ecdc87876e78dba2875f; exact comparisons retained.",
        "Executed FILE ABI qualification; detailed merged DSO lifetime results retained.",
        "Original acceptance at source7cbb186c2 and SHA2566445302cfa3a3abf93b85188567ad200674e1305f95d177fb88f810837070650.",
    ] {
        f.bead["close_reason"] = json!(reason);
        f.save();
        EvidenceFixture::assert_result(f.gate(&[]), true, "source; retained results verified");
    }
    f.bead["labels"] = json!([]);
    f.save();
    EvidenceFixture::assert_result(
        f.gate(&[]),
        false,
        "lower_evidence_class_requires_explicit_bead_label",
    );
    f.bead["labels"] = json!(["docs-only"]);
    f.matrix["entries"][0]["row"]["closure_evidence"]["claim_class"] = json!("executed_unit");
    f.save();
    EvidenceFixture::assert_result(f.gate(&[]), false, "claim_class_mismatch");
    f.bead["closed_at"] = json!("2026-10-14T23:59:59Z");
    f.save();
    EvidenceFixture::assert_result(f.gate(&[]), true, "POST_TOTAL=0");
    f.close_now();
    f.schema["executed_results"]["owner_approved_deferrals"]["bd-isolated-result"] = json!({
        "owner": "isolated-test-owner", "reason": "documented bounded proof deferral",
        "approval_ref": "isolated-control-only"
    });
    f.save();
    EvidenceFixture::assert_result(f.gate(&[]), true, "POST_DEFERRED=1");
    println!(
        "CONTROL source-only admitted without runtime credit; 5 prose indirections admitted; class inflation rejected; historical cutoff and explicit deferral preserved"
    );
}

#[test]
fn support_report_uses_explicit_rch_source_over_stale_worker_git() {
    let f = EvidenceFixture::new("n + 1");
    let git_dir = f.dir.join("stale-worker");
    let init = Command::new("git")
        .args(["init", "--initial-branch=main"])
        .arg(&git_dir)
        .output()
        .unwrap();
    assert!(init.status.success(), "{init:?}");
    let commit = Command::new("git")
        .current_dir(&git_dir)
        .args([
            "-c",
            "user.name=Isolated Test",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--allow-empty",
            "-m",
            "stale worker metadata fixture",
        ])
        .output()
        .unwrap();
    assert!(commit.status.success(), "{commit:?}");
    let expected = f.matrix["entries"][0]["row"]["closure_evidence"]["source"]["commit"]
        .as_str()
        .unwrap();
    let stale = Command::new("git")
        .current_dir(&git_dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(stale.status.success());
    assert_ne!(String::from_utf8_lossy(&stale.stdout).trim(), expected);
    for (label, declared, success) in [
        ("explicit-rch", format!("{expected}-dirty"), true),
        ("malformed-rch", "short-or-branch-name".to_owned(), false),
    ] {
        let output = Command::new("bash")
            .arg(workspace_root().join("scripts/check_support_reality_regeneration.sh"))
            .arg("--validate-only")
            .env("RCH_BUILD_SOURCE", declared)
            .env("GIT_DIR", git_dir.join(".git"))
            .env("SUPPORT_REALITY_OUT_DIR", f.dir.join(label))
            .env(
                "SUPPORT_REALITY_GENERATOR_BIN",
                env!("CARGO_BIN_EXE_harness"),
            )
            .output()
            .unwrap();
        std::fs::write(f.dir.join(format!("{label}.stdout")), &output.stdout).unwrap();
        std::fs::write(f.dir.join(format!("{label}.stderr")), &output.stderr).unwrap();
        EvidenceFixture::assert_result(
            output,
            success,
            if success {
                "PASS"
            } else {
                "RCH_BUILD_SOURCE must be a full object ID"
            },
        );
    }
    let report: Value = serde_json::from_slice(
        &std::fs::read(
            f.dir
                .join("explicit-rch/support_reality_regeneration.report.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(report["source_commit"], expected);
    println!(
        "CONTROL live compiled producer + stale Git: caller source retained; malformed provenance rejected"
    );
}
