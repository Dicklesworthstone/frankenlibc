//! Conformance gate for the harness binary `evidence-ring-stress`
//! subcommand (bd-vp6xi).

use std::path::{Path, PathBuf};
use std::process::Command;

use frankenlibc_harness::evidence_ring_backpressure::REAL_RING_REPORT_REQUIRED_FIELDS;
use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("evidence_ring_stress_cli_contract.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or non-string `{field}`"))
}

fn json_bool(value: &Value, field: &str) -> TestResult<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing or non-bool `{field}`"))
}

fn cargo_target_dir_for_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_TARGET_DIR") {
        PathBuf::from(p)
    } else if let Ok(p) = std::env::var("CARGO_MANIFEST_DIR") {
        Path::new(&p)
            .parent()
            .and_then(Path::parent)
            .map(|root| root.join("target"))
            .unwrap_or_else(|| PathBuf::from("target"))
    } else {
        PathBuf::from("target")
    }
}

fn find_harness_binary() -> Option<PathBuf> {
    let root = cargo_target_dir_for_bin();
    for prof in ["debug", "release"] {
        let candidate = root.join(prof).join("harness");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

#[test]
fn manifest_anchors_to_vp6xi_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "evidence-ring-stress-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-vp6xi", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "evidence-ring-stress",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_harness::evidence_ring_backpressure::run_real_ring_stress",
        "underlying_lib_function",
    )?;
    require(
        json_string(&m, "underlying_serializer_function")?
            == "frankenlibc_harness::evidence_ring_backpressure::serialize_real_ring_report_jsonl",
        "underlying_serializer_function",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for f in [
        "fail_closed_when_source_commit_is_not_40_char_sha",
        "fail_closed_when_multiple_below_two",
        "fail_closed_when_cap_not_supported",
        "must_emit_exactly_one_jsonl_record",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_evidence_ring_stress_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("EvidenceRingStress {"),
        "harness.rs must declare EvidenceRingStress Command variant",
    )?;
    for field in ["seed", "multiple", "cap", "source_commit", "output"] {
        let anchor = format!("        {field}");
        require(
            src.contains(&anchor),
            format!("EvidenceRingStress missing field `{field}`"),
        )?;
    }
    require(
        src.contains("run_real_ring_stress::<32>")
            && src.contains("run_real_ring_stress::<128>")
            && src.contains("run_real_ring_stress::<1024>"),
        "main() must dispatch run_real_ring_stress for CAP in {32, 128, 1024}",
    )
}

#[test]
fn cli_emits_one_jsonl_record_validating_against_lib_const() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = std::env::temp_dir().join(format!(
        "bd_vp6xi_{}_{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("clock: {e}"))?
            .as_nanos()
    ));
    let source_commit = "0".repeat(40);
    let output = Command::new(&bin)
        .arg("evidence-ring-stress")
        .arg("--seed")
        .arg("12345")
        .arg("--multiple")
        .arg("4")
        .arg("--cap")
        .arg("32")
        .arg("--source-commit")
        .arg(&source_commit)
        .arg("--output")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    if !output.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "evidence-ring-stress failed: status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let body = std::fs::read_to_string(&tmp).map_err(|e| format!("read jsonl: {e}"))?;
    let _ = std::fs::remove_file(&tmp);
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    require(
        lines.len() == 1,
        format!("expected exactly 1 JSONL record; got {}", lines.len()),
    )?;
    let parsed: Value = serde_json::from_str(lines[0]).map_err(|e| format!("parse jsonl: {e}"))?;
    // The emitted record must carry every field the lib lists as
    // required — the runtime validator double-checks the same set.
    for f in REAL_RING_REPORT_REQUIRED_FIELDS {
        require(
            parsed.get(*f).is_some(),
            format!("record missing required field `{f}`"),
        )?;
    }
    require(
        parsed.get("source_commit").and_then(Value::as_str) == Some(source_commit.as_str()),
        "source_commit must propagate to the emitted record",
    )?;
    // Spot-check that the report shape is internally consistent.
    // total_pushed should equal ring_capacity * drive_to_capacity_multiple
    // (4 CAPs of pushes against a CAP=32 ring → total_pushed == 128).
    let cap_v = parsed.get("ring_capacity").and_then(Value::as_u64);
    let mult_v = parsed
        .get("drive_to_capacity_multiple")
        .and_then(Value::as_u64);
    let total_v = parsed.get("total_pushed").and_then(Value::as_u64);
    if let (Some(cap_n), Some(mul_n), Some(tot)) = (cap_v, mult_v, total_v) {
        require(
            tot == cap_n.saturating_mul(mul_n),
            format!(
                "total_pushed={tot} must equal ring_capacity*multiple={}",
                cap_n.saturating_mul(mul_n)
            ),
        )?;
    }
    require(
        parsed.get("monotone_seqno").and_then(Value::as_bool) == Some(true),
        "monotone_seqno must be true under deterministic stress",
    )
}

#[test]
fn cli_rejects_unsupported_cap_with_helpful_error() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = std::env::temp_dir().join(format!("bd_vp6xi_bad_cap_{}.jsonl", std::process::id()));
    let output = Command::new(&bin)
        .arg("evidence-ring-stress")
        .arg("--seed")
        .arg("1")
        .arg("--multiple")
        .arg("2")
        .arg("--cap")
        .arg("999")
        .arg("--source-commit")
        .arg("0".repeat(40))
        .arg("--output")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    let _ = std::fs::remove_file(&tmp);
    require(
        !output.status.success(),
        "evidence-ring-stress must exit non-zero on unsupported --cap",
    )?;
    require(
        String::from_utf8_lossy(&output.stderr).contains("--cap must be one of 32, 128, 1024"),
        "evidence-ring-stress must surface the supported-cap list on bad --cap",
    )
}

#[test]
fn cli_rejects_bad_multiple_below_two() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = std::env::temp_dir().join(format!(
        "bd_vp6xi_bad_multiple_{}.jsonl",
        std::process::id()
    ));
    let output = Command::new(&bin)
        .arg("evidence-ring-stress")
        .arg("--seed")
        .arg("1")
        .arg("--multiple")
        .arg("1")
        .arg("--cap")
        .arg("32")
        .arg("--source-commit")
        .arg("0".repeat(40))
        .arg("--output")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    let _ = std::fs::remove_file(&tmp);
    require(
        !output.status.success(),
        "evidence-ring-stress must exit non-zero on --multiple < 2",
    )?;
    require(
        String::from_utf8_lossy(&output.stderr).contains("--multiple must be >= 2"),
        "evidence-ring-stress must surface the lower bound on --multiple",
    )
}
