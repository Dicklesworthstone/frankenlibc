// reverse_round_contracts_test.rs — bd-2a2.4 / bd-2a2.5 / bd-3h1u.6
// Integration tests for reverse-round contracts, cross-round composition,
// and milestone branch-diversity verification.

use std::path::Path;
use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

fn load_text(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e))
}

#[test]
fn contracts_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_reverse_round_contracts.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute contracts generator");
    assert!(
        output.status.success(),
        "Contracts generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn contracts_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-2a2.5"));
    assert!(data["report_hash"].is_string());

    let summary = &data["summary"];
    for field in &[
        "rounds_verified",
        "total_math_families",
        "modules_found",
        "invariants_specified",
        "math_class_count",
        "all_rounds_diverse",
        "implementation_steps_total",
        "verification_hooks_total",
        "verification_hooks_specified",
        "supporting_files_total",
        "supporting_files_found",
        "cross_round_checks_total",
        "cross_round_checks_passing",
        "milestones_verified",
        "milestones_diverse",
        "all_milestones_diverse",
        "max_milestone_class_share_pct",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["round_results"].is_object());
    assert!(data["cross_round_integrations"].is_object());
    assert!(data["milestone_branch_diversity"].is_object());
    assert!(data["branch_diversity_rule"].is_object());
    assert!(data["golden_output"].is_object());
}

#[test]
fn contracts_all_modules_exist() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data = load_json(&report_path);

    let rounds = data["round_results"].as_object().unwrap();
    for (round_id, round_data) in rounds {
        let families = round_data["math_families"].as_object().unwrap();
        for (fam_name, fam_data) in families {
            assert!(
                fam_data["module_exists"].as_bool().unwrap(),
                "Round {} family {} module {} not found",
                round_id,
                fam_name,
                fam_data["module"].as_str().unwrap_or("?")
            );
        }
    }
}

#[test]
fn contracts_all_invariants_specified() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data = load_json(&report_path);

    let specified = data["summary"]["invariants_specified"].as_u64().unwrap();
    let total = data["summary"]["invariants_total"].as_u64().unwrap();
    assert_eq!(
        specified,
        total,
        "{} invariants missing ({}/{})",
        total - specified,
        specified,
        total
    );
}

#[test]
fn contracts_branch_diversity() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data = load_json(&report_path);

    assert!(
        data["summary"]["all_rounds_diverse"].as_bool().unwrap(),
        "Not all rounds pass branch-diversity (>= 3 math classes)"
    );

    let rounds = data["round_results"].as_object().unwrap();
    for (round_id, round_data) in rounds {
        let diversity = &round_data["branch_diversity"];
        let class_count = diversity["class_count"].as_u64().unwrap();
        assert!(
            class_count >= 3,
            "Round {} has only {} math classes (need >= 3)",
            round_id,
            class_count
        );
    }
}

#[test]
fn contracts_legacy_surfaces_anchored() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data = load_json(&report_path);

    let rounds = data["round_results"].as_object().unwrap();
    for (round_id, round_data) in rounds {
        let surfaces = round_data["legacy_surfaces"].as_array().unwrap();
        assert!(
            !surfaces.is_empty(),
            "Round {} has no legacy surface anchors",
            round_id
        );
        assert!(
            round_data["failure_class"].is_string(),
            "Round {} missing failure class",
            round_id
        );
    }
}

#[test]
fn contracts_rounds_include_problem_focus_execution_and_verification() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data = load_json(&report_path);

    let rounds = data["round_results"].as_object().unwrap();
    for (round_id, round_data) in rounds {
        let problem_focus = round_data["problem_focus"]
            .as_str()
            .unwrap_or_else(|| panic!("{round_id}: missing problem_focus"));
        assert!(
            !problem_focus.trim().is_empty(),
            "{round_id}: problem_focus must be non-empty"
        );

        let implementation_plan = round_data["implementation_plan"]
            .as_array()
            .unwrap_or_else(|| panic!("{round_id}: implementation_plan must be array"));
        assert!(
            !implementation_plan.is_empty(),
            "{round_id}: implementation_plan must be non-empty"
        );
        for step in implementation_plan {
            let step_text = step
                .as_str()
                .unwrap_or_else(|| panic!("{round_id}: implementation steps must be strings"));
            assert!(
                !step_text.trim().is_empty(),
                "{round_id}: implementation steps must be non-empty"
            );
        }

        let verification_strategy = round_data["verification_strategy"]
            .as_array()
            .unwrap_or_else(|| panic!("{round_id}: verification_strategy must be array"));
        assert!(
            !verification_strategy.is_empty(),
            "{round_id}: verification_strategy must be non-empty"
        );
        for hook in verification_strategy {
            assert!(
                hook["description"].is_string(),
                "{round_id}: verification hook description missing"
            );
            if let Some(path) = hook["path"].as_str() {
                assert!(
                    hook["path_exists"].as_bool().unwrap_or(false),
                    "{round_id}: verification hook path missing: {path}"
                );
            }
        }

        let supporting_files = round_data["supporting_files"]
            .as_array()
            .unwrap_or_else(|| panic!("{round_id}: supporting_files must be array"));
        assert!(
            !supporting_files.is_empty(),
            "{round_id}: supporting_files must be non-empty"
        );
        for file in supporting_files {
            let path = file["path"]
                .as_str()
                .unwrap_or_else(|| panic!("{round_id}: supporting file path missing"));
            assert!(
                file["exists"].as_bool().unwrap_or(false),
                "{round_id}: supporting file missing: {path}"
            );
        }
    }
}

#[test]
fn contracts_cross_round_integrations_are_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data = load_json(&report_path);

    let integrations = data["cross_round_integrations"]
        .as_object()
        .expect("cross_round_integrations must be an object");
    assert!(
        integrations.len() >= 5,
        "expected at least 5 cross-round integrations"
    );
    assert_eq!(
        data["summary"]["cross_round_checks_total"].as_u64(),
        Some(integrations.len() as u64)
    );
    assert_eq!(
        data["summary"]["cross_round_checks_passing"].as_u64(),
        Some(integrations.len() as u64)
    );

    let temporal_bridge = integrations
        .get("loader_time64_bridge")
        .expect("expected loader_time64_bridge integration entry");
    let temporal_bridge_rounds: Vec<&str> = temporal_bridge["rounds"]
        .as_array()
        .expect("loader_time64_bridge rounds must be array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("loader_time64_bridge round must be string")
        })
        .collect();
    assert_eq!(temporal_bridge_rounds, vec!["R7", "R30"]);

    for (integration_id, integration) in integrations {
        let rounds = integration["rounds"]
            .as_array()
            .unwrap_or_else(|| panic!("{integration_id}: rounds must be an array"));
        assert_eq!(
            rounds.len(),
            2,
            "{integration_id}: expected exactly two rounds"
        );
        assert!(
            integration["passes_integration"].as_bool().unwrap_or(false),
            "{integration_id}: integration must pass"
        );
        assert!(
            integration["legacy_surfaces"]
                .as_array()
                .is_some_and(|surfaces| !surfaces.is_empty()),
            "{integration_id}: legacy surfaces must be non-empty"
        );

        let diversity = &integration["branch_diversity"];
        assert!(
            diversity["class_count"].as_u64().unwrap_or(0) >= 5,
            "{integration_id}: expected at least 5 math classes"
        );
        assert!(
            diversity["passes_diversity"].as_bool().unwrap_or(false),
            "{integration_id}: diversity gate must pass"
        );
        assert!(
            diversity["max_single_class_pct"].as_f64().unwrap_or(100.0) <= 40.0,
            "{integration_id}: class concentration must stay <= 40%"
        );

        let supporting_files = integration["supporting_files"]
            .as_array()
            .unwrap_or_else(|| panic!("{integration_id}: supporting_files must be array"));
        assert!(
            !supporting_files.is_empty(),
            "{integration_id}: supporting_files must be non-empty"
        );
        for file in supporting_files {
            let path = file["path"]
                .as_str()
                .unwrap_or_else(|| panic!("{integration_id}: supporting file path missing"));
            assert!(
                file["exists"].as_bool().unwrap_or(false),
                "{integration_id}: supporting file missing: {path}"
            );
        }

        let verification_strategy = integration["verification_strategy"]
            .as_array()
            .unwrap_or_else(|| panic!("{integration_id}: verification_strategy must be array"));
        assert!(
            !verification_strategy.is_empty(),
            "{integration_id}: verification_strategy must be non-empty"
        );
        for hook in verification_strategy {
            let path = hook["path"]
                .as_str()
                .unwrap_or_else(|| panic!("{integration_id}: verification hook path missing"));
            assert!(
                hook["path_exists"].as_bool().unwrap_or(false),
                "{integration_id}: verification hook missing: {path}"
            );
        }
    }
}

#[test]
fn contracts_r32_uses_membrane_persistence_anchor() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data = load_json(&report_path);

    let r32 = data["round_results"]["R32"]
        .as_object()
        .expect("R32 round must exist");
    let supporting_files = r32["supporting_files"]
        .as_array()
        .expect("R32 supporting_files must be an array");

    let has_root_persistence = supporting_files.iter().any(|file| {
        file["path"].as_str() == Some("crates/frankenlibc-membrane/src/persistence.rs")
            && file["exists"].as_bool().unwrap_or(false)
    });
    assert!(
        has_root_persistence,
        "R32 must anchor the membrane persistence module at crates/frankenlibc-membrane/src/persistence.rs"
    );

    let has_runtime_math_persistence = supporting_files.iter().any(|file| {
        file["path"].as_str() == Some("crates/frankenlibc-membrane/src/runtime_math/persistence.rs")
    });
    assert!(
        !has_runtime_math_persistence,
        "R32 must not reference the removed runtime_math/persistence.rs path"
    );
}

#[test]
fn contracts_milestone_branch_diversity_holds() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data = load_json(&report_path);

    let milestones = data["milestone_branch_diversity"]
        .as_object()
        .expect("milestone_branch_diversity must be an object");
    assert!(
        milestones.len() >= 3,
        "expected at least 3 milestone diversity entries"
    );
    assert_eq!(
        data["summary"]["milestones_verified"].as_u64(),
        Some(milestones.len() as u64)
    );
    assert_eq!(
        data["summary"]["milestones_diverse"].as_u64(),
        Some(milestones.len() as u64)
    );
    assert_eq!(
        data["summary"]["all_milestones_diverse"].as_bool(),
        Some(true)
    );

    let temporal_policy_milestone = milestones
        .get("loader_temporal_policy_surface")
        .expect("expected loader_temporal_policy_surface milestone entry");
    let temporal_policy_rounds: Vec<&str> = temporal_policy_milestone["rounds"]
        .as_array()
        .expect("loader_temporal_policy_surface rounds must be array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("loader_temporal_policy_surface round must be string")
        })
        .collect();
    assert_eq!(temporal_policy_rounds, vec!["R7", "R28", "R30", "R37"]);

    for (milestone_id, milestone) in milestones {
        let rounds = milestone["rounds"]
            .as_array()
            .unwrap_or_else(|| panic!("{milestone_id}: rounds must be array"));
        assert!(
            rounds.len() >= 3,
            "{milestone_id}: expected at least three rounds"
        );
        assert!(
            milestone["passes_milestone"].as_bool().unwrap_or(false),
            "{milestone_id}: milestone must pass"
        );

        let diversity = &milestone["branch_diversity"];
        assert!(
            diversity["class_count"].as_u64().unwrap_or(0) >= 5,
            "{milestone_id}: expected at least 5 classes"
        );
        assert!(
            diversity["max_single_class_pct"].as_f64().unwrap_or(100.0) <= 40.0,
            "{milestone_id}: class concentration must stay <= 40%"
        );
        assert!(
            diversity["passes_diversity"].as_bool().unwrap_or(false),
            "{milestone_id}: milestone diversity gate must pass"
        );

        let supporting_files = milestone["supporting_files"]
            .as_array()
            .unwrap_or_else(|| panic!("{milestone_id}: supporting_files must be array"));
        for file in supporting_files {
            let path = file["path"]
                .as_str()
                .unwrap_or_else(|| panic!("{milestone_id}: supporting file path missing"));
            assert!(
                file["exists"].as_bool().unwrap_or(false),
                "{milestone_id}: supporting file missing: {path}"
            );
        }
    }
}

#[test]
fn reverse_round_plan_doc_sections_include_execution_contracts() {
    let root = repo_root();
    let plan_text = load_text(&root.join("PLAN_TO_PORT_GLIBC_TO_RUST.md"));

    for heading in &[
        "### Round R7: Loader + Symbol Resolution (`elf`, `sysdeps/*/dl-*`)",
        "### Round R8: Allocator + Thread Runtime (`malloc`, `nptl`)",
        "### Round R9: Format/Wide/Locale Engine (`stdio-common`, `wcsmbs`, `locale`)",
        "### Round R10: Identity + DNS Lookup (`nss`, `resolv`)",
        "### Round R11: libm + Floating Environment (`math`, `soft-fp`, `sysdeps/ieee754`)",
    ] {
        let start = plan_text
            .find(heading)
            .unwrap_or_else(|| panic!("missing round heading: {heading}"));
        let tail = &plan_text[start..];
        let end = tail.find("\n### Round ").unwrap_or(tail.len());
        let section = &tail[..end];
        assert!(
            section.contains("Implementation plan:"),
            "{heading}: missing Implementation plan"
        );
        assert!(
            section.contains("Verification strategy:"),
            "{heading}: missing Verification strategy"
        );
    }
}

#[test]
fn gate_script_exists_and_is_executable() {
    let root = repo_root();
    let script = root.join("scripts/check_reverse_round_contracts.sh");
    assert!(
        script.exists(),
        "scripts/check_reverse_round_contracts.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_reverse_round_contracts.sh must be executable"
        );
    }
}

#[test]
fn gate_script_emits_report_and_structured_log() {
    let root = repo_root();
    let script = root.join("scripts/check_reverse_round_contracts.sh");

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run reverse-round gate");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = root.join("target/conformance/reverse_round_contracts.log.jsonl");
    let gate_report_path = root.join("target/conformance/reverse_round_contracts.report.json");

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("structured log should be readable");
    assert!(
        errors.is_empty(),
        "structured log validation errors:\n{:#?}",
        errors
    );
    assert!(
        line_count >= 10,
        "expected multiple log lines, got {line_count}"
    );

    let gate_report = load_json(&gate_report_path);
    assert_eq!(gate_report["schema_version"].as_str(), Some("v1"));
    assert_eq!(gate_report["bead"].as_str(), Some("bd-2a2.5"));
    assert_eq!(gate_report["status"].as_str(), Some("pass"));
    assert_eq!(gate_report["summary"]["failed_checks"].as_u64(), Some(0));
    assert_eq!(
        gate_report["summary"]["cross_round_checks_passing"].as_u64(),
        gate_report["summary"]["cross_round_checks_total"].as_u64()
    );
    assert_eq!(
        gate_report["summary"]["milestones_diverse"].as_u64(),
        gate_report["summary"]["milestones_verified"].as_u64()
    );
    assert_eq!(
        gate_report["summary"]["all_milestones_diverse"].as_bool(),
        Some(true)
    );

    let log_body = std::fs::read_to_string(&log_path).expect("log file should exist");
    let log_entries: Vec<serde_json::Value> = log_body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    assert_eq!(line_count, log_entries.len());
    assert!(
        log_entries.iter().any(|entry| {
            entry["symbol"].as_str() == Some("integration:loader_allocator")
                && entry["event"].as_str() == Some("reverse_round.contracts.check")
        }),
        "structured log must include loader_allocator integration evidence"
    );
    assert!(
        log_entries.iter().any(|entry| {
            entry["symbol"].as_str() == Some("integration:loader_time64_bridge")
                && entry["event"].as_str() == Some("reverse_round.contracts.check")
        }),
        "structured log must include loader_time64_bridge integration evidence"
    );
    assert!(
        log_entries.iter().any(|entry| {
            entry["symbol"].as_str() == Some("milestone:bootstrap_surface")
                && entry["event"].as_str() == Some("reverse_round.contracts.check")
        }),
        "structured log must include bootstrap_surface milestone evidence"
    );
    assert!(
        log_entries.iter().any(|entry| {
            entry["symbol"].as_str() == Some("milestone:loader_temporal_policy_surface")
                && entry["event"].as_str() == Some("reverse_round.contracts.check")
        }),
        "structured log must include loader_temporal_policy_surface milestone evidence"
    );
    assert!(
        log_entries
            .iter()
            .any(|entry| entry["event"].as_str() == Some("reverse_round.contracts.summary")),
        "structured log must include summary event"
    );
}

#[test]
fn contracts_reproducible() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data1 = load_json(&report_path);

    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_reverse_round_contracts.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute generator");
    assert!(output.status.success());

    let data2 = load_json(&report_path);
    assert_eq!(
        data1["report_hash"].as_str(),
        data2["report_hash"].as_str(),
        "Report hash changed on regeneration"
    );
}
