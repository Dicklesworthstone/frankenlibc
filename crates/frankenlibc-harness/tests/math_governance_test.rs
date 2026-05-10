//! Integration test: Math governance classification (bd-2yx)
//!
//! Validates that:
//! 1. The governance classification exists and is valid JSON.
//! 2. All three tiers are defined with required metadata.
//! 3. Every classified module exists in the production manifest.
//! 4. Every manifest module is classified (no gaps).
//! 5. No module appears in multiple tiers.
//! 6. Summary statistics match actual classifications.
//! 7. The CI gate script exists and is executable.
//!
//! Run: cargo test -p frankenlibc-harness --test math_governance_test

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_governance() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/math_governance.json");
    load_json_at(&path)
}

fn load_json_at(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("math_governance.json should exist");
    serde_json::from_str(&content).expect("JSON artifact should be valid JSON")
}

fn load_manifest() -> serde_json::Value {
    let path = workspace_root().join("tests/runtime_math/production_kernel_manifest.v1.json");
    let content =
        std::fs::read_to_string(path).expect("production_kernel_manifest.v1.json should exist");
    serde_json::from_str(&content).expect("production_kernel_manifest.v1.json should be valid JSON")
}

fn manifest_union_modules(manifest: &serde_json::Value) -> HashSet<String> {
    manifest["production_modules"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(
            manifest["research_only_modules"]
                .as_array()
                .into_iter()
                .flatten(),
        )
        .filter_map(|v| v.as_str().map(String::from))
        .collect()
}

fn load_jsonl(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .expect("JSONL artifact should exist")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("JSONL row should be valid JSON"))
        .collect()
}

fn json_str_field_is(row: &serde_json::Value, field: &str, expected: &str) -> bool {
    row.get(field)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.eq(expected))
}

fn write_json(path: &Path, value: &serde_json::Value) {
    std::fs::write(
        path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(value).expect("value should serialize")
        ),
    )
    .expect("JSON artifact should be writable");
}

fn unique_output_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let path = workspace_root()
        .join("target/conformance")
        .join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).expect("output directory should be creatable");
    path
}

fn run_gate(governance: &Path, out_dir: &Path) -> std::process::Output {
    let root = workspace_root();
    Command::new("bash")
        .arg(root.join("scripts/check_math_governance.sh"))
        .current_dir(&root)
        .env("FRANKENLIBC_MATH_GOVERNANCE", governance)
        .env(
            "FRANKENLIBC_MATH_GOVERNANCE_REPORT",
            out_dir.join("math_governance.report.json"),
        )
        .env(
            "FRANKENLIBC_MATH_GOVERNANCE_LOG",
            out_dir.join("math_governance.log.jsonl"),
        )
        .output()
        .expect("math governance gate should run")
}

#[test]
fn governance_exists_and_valid() {
    let gov = load_governance();
    assert!(gov["schema_version"].is_number(), "Missing schema_version");
    assert!(gov["tiers"].is_object(), "Missing tiers");
    assert!(
        gov["classifications"].is_object(),
        "Missing classifications"
    );
    assert!(gov["summary"].is_object(), "Missing summary");
}

#[test]
fn all_tiers_defined() {
    let gov = load_governance();
    let tiers = gov["tiers"].as_object().unwrap();

    for tier_name in ["production_core", "production_monitor", "research"] {
        assert!(
            tiers.contains_key(tier_name),
            "Missing tier definition: {tier_name}"
        );
        let tier = &tiers[tier_name];
        assert!(
            tier["description"].is_string(),
            "{tier_name}: missing description"
        );
        assert!(
            tier["feature_gate"].is_string(),
            "{tier_name}: missing feature_gate"
        );
    }
}

#[test]
fn classified_modules_exist_in_manifest() {
    let gov = load_governance();
    let manifest = load_manifest();
    let manifest_modules = manifest_union_modules(&manifest);

    let classifications = gov["classifications"].as_object().unwrap();
    let mut missing = Vec::new();

    for (tier, entries) in classifications {
        for entry in entries.as_array().unwrap() {
            let module = entry["module"].as_str().unwrap_or("<unknown>");
            if !manifest_modules.contains(module) {
                missing.push(format!("{module} (tier={tier})"));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "Classified modules not in manifest:\n{}",
        missing.join("\n")
    );
}

#[test]
fn all_manifest_modules_classified() {
    let gov = load_governance();
    let manifest = load_manifest();
    let manifest_modules = manifest_union_modules(&manifest);

    let classifications = gov["classifications"].as_object().unwrap();
    let mut classified = HashSet::new();

    for entries in classifications.values() {
        for entry in entries.as_array().unwrap() {
            if let Some(module) = entry["module"].as_str() {
                classified.insert(module.to_string());
            }
        }
    }

    let unclassified: Vec<_> = manifest_modules.difference(&classified).collect();
    assert!(
        unclassified.is_empty(),
        "Manifest modules not classified:\n{:?}",
        unclassified
    );
}

#[test]
fn no_duplicate_classifications() {
    let gov = load_governance();
    let classifications = gov["classifications"].as_object().unwrap();

    let mut seen: HashMap<String, String> = HashMap::new();
    let mut dups = Vec::new();

    for (tier, entries) in classifications {
        for entry in entries.as_array().unwrap() {
            let module = entry["module"].as_str().unwrap_or("<unknown>").to_string();
            if let Some(prev_tier) = seen.insert(module.clone(), tier.clone()) {
                dups.push(format!("{module}: in both {prev_tier} and {tier}"));
            }
        }
    }

    assert!(
        dups.is_empty(),
        "Modules in multiple tiers:\n{}",
        dups.join("\n")
    );
}

#[test]
fn summary_consistent() {
    let gov = load_governance();
    let classifications = gov["classifications"].as_object().unwrap();
    let summary = &gov["summary"];

    let mut total = 0usize;
    for tier_name in ["production_core", "production_monitor", "research"] {
        let entries = classifications
            .get(tier_name)
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let claimed = summary[tier_name].as_u64().unwrap() as usize;
        assert_eq!(
            claimed, entries,
            "summary.{tier_name} mismatch: claimed={claimed} actual={entries}"
        );
        total += entries;
    }

    let claimed_total = summary["total_modules"].as_u64().unwrap() as usize;
    assert_eq!(claimed_total, total, "summary.total_modules mismatch");
}

#[test]
fn every_entry_has_rationale() {
    let gov = load_governance();
    let classifications = gov["classifications"].as_object().unwrap();

    for (tier, entries) in classifications {
        for entry in entries.as_array().unwrap() {
            let module = entry["module"].as_str().unwrap_or("<unknown>");
            assert!(
                entry["rationale"].is_string(),
                "{module} (tier={tier}): missing rationale"
            );
            let rationale = entry["rationale"].as_str().unwrap();
            assert!(
                !rationale.is_empty(),
                "{module} (tier={tier}): empty rationale"
            );
        }
    }
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_math_governance.sh");
    assert!(
        script.exists(),
        "scripts/check_math_governance.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_math_governance.sh must be executable"
        );
    }
}

#[test]
fn completion_debt_evidence_binds_missing_items() {
    let root = workspace_root();
    let gov = load_governance();
    let evidence = gov["completion_debt_evidence"]
        .as_object()
        .expect("completion_debt_evidence should be present");
    assert_eq!(evidence["bead"].as_str(), Some("bd-2yx.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-2yx"));
    assert_eq!(
        evidence["test_source"].as_str(),
        Some("crates/frankenlibc-harness/tests/math_governance_test.rs")
    );
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "next audit threshold should force a real closeout"
    );

    let source_path = root.join(evidence["test_source"].as_str().unwrap());
    let test_source = std::fs::read_to_string(&source_path).expect("test source should exist");
    for (section, missing_item) in [
        ("unit_primary", "tests.unit.primary"),
        ("e2e_primary", "tests.e2e.primary"),
        ("migrations_primary", "migrations.primary"),
        ("telemetry_primary", "telemetry.primary"),
    ] {
        let block = evidence[section]
            .as_object()
            .expect("completion-debt evidence block should exist");
        assert_eq!(block["missing_item_id"].as_str(), Some(missing_item));
        let required = block["required_test_names"]
            .as_array()
            .expect("completion-debt evidence block should list required tests");
        assert!(!required.is_empty(), "{section} should bind tests");
        for test_name in required {
            let test_name = test_name.as_str().expect("test name should be a string");
            assert!(
                test_source.contains(&format!("fn {test_name}(")),
                "{section} references missing test {test_name}"
            );
        }
    }
}

#[test]
fn migration_contract_routes_research_modules_out_of_production() {
    let gov = load_governance();
    let manifest = load_manifest();
    let production_modules: HashSet<_> = manifest["production_modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let research_only_modules: HashSet<_> = manifest["research_only_modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let research_classified: HashSet<_> = gov["classifications"]["research"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["module"].as_str())
        .collect();

    let leaked: Vec<_> = research_classified
        .intersection(&production_modules)
        .copied()
        .collect();
    let missing: Vec<_> = research_classified
        .difference(&research_only_modules)
        .copied()
        .collect();
    assert!(
        leaked.is_empty(),
        "research modules leaked into production: {leaked:?}"
    );
    assert!(
        missing.is_empty(),
        "research modules missing from research_only_modules: {missing:?}"
    );

    let manifest_refs = gov["completion_debt_evidence"]["migrations_primary"]["manifest_refs"]
        .as_array()
        .expect("migration evidence should cite manifest refs");
    assert!(
        manifest_refs.iter().any(|value| value
            .as_str()
            .is_some_and(|text| text.contains("research_only_modules"))),
        "migration evidence should cite research_only_modules"
    );
}

#[test]
fn gate_emits_completion_debt_telemetry() {
    let root = workspace_root();
    let out_dir = unique_output_dir("math-governance-ok");
    let output = run_gate(
        &root.join("tests/conformance/math_governance.json"),
        &out_dir,
    );
    assert!(
        output.status.success(),
        "gate failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json_at(&out_dir.join("math_governance.report.json"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-2yx.1"));
    assert_eq!(report["total_modules"].as_u64(), Some(69));
    assert!(
        report["research_in_production_manifest"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "research tier must not leak into production manifest"
    );

    let rows = load_jsonl(&out_dir.join("math_governance.log.jsonl"));
    assert_eq!(rows.len(), 4, "expected 3 tier rows plus summary");
    assert!(rows.iter().any(|row| {
        json_str_field_is(row, "event", "math_governance_summary")
            && json_str_field_is(row, "completion_debt_bead", "bd-2yx.1")
            && json_str_field_is(row, "status", "pass")
    }));
    for tier in ["production_core", "production_monitor", "research"] {
        assert!(
            rows.iter().any(
                |row| json_str_field_is(row, "event", "math_governance_tier")
                    && json_str_field_is(row, "tier", tier)
                    && json_str_field_is(row, "failure_signature", "none")
            ),
            "missing telemetry row for tier {tier}"
        );
    }
}

#[test]
fn gate_rejects_stale_completion_debt_test_binding() {
    let out_dir = unique_output_dir("math-governance-fail");
    let mut gov = load_governance();
    let required_tests = gov["completion_debt_evidence"]["unit_primary"]["required_test_names"]
        .as_array_mut()
        .expect("required tests should be mutable array");
    required_tests.push(serde_json::json!("missing_math_governance_completion_test"));
    let bad_governance = out_dir.join("bad_math_governance.json");
    write_json(&bad_governance, &gov);

    let output = run_gate(&bad_governance, &out_dir);
    assert!(
        !output.status.success(),
        "gate should reject stale completion debt test binding"
    );
    let report = load_json_at(&out_dir.join("math_governance.report.json"));
    let errors = report["errors"]
        .as_array()
        .expect("failure report should include errors");
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("missing_math_governance_completion_test"))),
        "failure report should name missing test binding: {errors:?}"
    );
}
