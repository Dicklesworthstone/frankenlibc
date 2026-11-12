//! Integration test: semantic contract inventory gate (bd-bp8fl.1.1)
//!
//! Validates that the inventory seeded from support_semantic_overlay.v1.json is
//! source-linked, summary-consistent, and backed by a deterministic report/log
//! script.
//!
//! Run:
//!   cargo test -p frankenlibc-harness --test semantic_contract_inventory_test

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn failure(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::other(message.into()).into()
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(failure(message))
    }
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let crate_dir = Path::new(manifest)
        .parent()
        .ok_or_else(|| failure("manifest directory must have crate parent"))?;
    let root = crate_dir
        .parent()
        .ok_or_else(|| failure("crate directory must have workspace parent"))?;
    Ok(root.to_path_buf())
}

fn load_json(path: &Path) -> TestResult<serde_json::Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|error| failure(format!("{} should be readable: {error}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|error| failure(format!("{} should parse as JSON: {error}", path.display())))
}

fn json_array<'a>(
    value: &'a serde_json::Value,
    context: &str,
) -> TestResult<&'a Vec<serde_json::Value>> {
    value
        .as_array()
        .ok_or_else(|| failure(format!("{context} must be an array")))
}

fn json_object<'a>(
    value: &'a serde_json::Value,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, serde_json::Value>> {
    value
        .as_object()
        .ok_or_else(|| failure(format!("{context} must be an object")))
}

fn json_str<'a>(value: &'a serde_json::Value, context: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| failure(format!("{context} must be a string")))
}

#[test]
fn artifact_exists_and_has_required_shape() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/semantic_contract_inventory.v1.json"))?;

    ensure(
        artifact["schema_version"].as_str() == Some("v1"),
        "schema_version must be v1",
    )?;
    ensure(
        artifact["bead"].as_str() == Some("bd-bp8fl.1.1"),
        "bead must be bd-bp8fl.1.1",
    )?;
    let entries = json_array(&artifact["entries"], "entries")?;
    json_object(
        &artifact["semantic_contract_classes"],
        "semantic_contract_classes",
    )?;
    json_object(&artifact["claim_policy"], "claim_policy")?;
    json_object(&artifact["summary"], "summary")?;

    ensure(
        entries.len() >= 10,
        "inventory must preserve at least the seed overlay entries",
    )?;

    for row in entries {
        let id = row["id"].as_str().unwrap_or("<missing id>");
        for field in [
            "surface",
            "symbols",
            "module",
            "source_path",
            "source_line",
            "line_marker",
            "support_matrix_status",
            "semantic_class",
            "contract_kind",
            "current_behavior",
            "user_risk",
            "required_followup",
            "evidence_artifacts",
        ] {
            ensure(!row[field].is_null(), format!("{id}: missing {field}"))?;
        }
    }

    Ok(())
}

#[test]
fn seed_overlay_entries_are_all_covered() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/semantic_contract_inventory.v1.json"))?;
    let seed = load_json(&root.join("tests/conformance/support_semantic_overlay.v1.json"))?;

    let mut seed_ids = HashSet::new();
    for row in json_array(&seed["audited_entries"], "seed audited_entries")? {
        seed_ids.insert(json_str(&row["id"], "seed audited_entries[].id")?.to_string());
    }

    let mut inventory_seed_ids = HashSet::new();
    for row in json_array(&artifact["entries"], "artifact entries")? {
        if let Some(seed_id) = row["seed_overlay_id"].as_str() {
            inventory_seed_ids.insert(seed_id.to_string());
        }
    }

    let missing: Vec<_> = seed_ids.difference(&inventory_seed_ids).collect();
    ensure(
        missing.is_empty(),
        format!("missing seed overlay ids: {missing:?}"),
    )
}

#[test]
fn summary_counts_match_entries_and_sources_are_linked() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/semantic_contract_inventory.v1.json"))?;
    let entries = json_array(&artifact["entries"], "artifact entries")?;
    let summary = json_object(&artifact["summary"], "artifact summary")?;

    let mut by_class: HashMap<String, u64> = HashMap::new();
    let mut by_source: HashMap<String, u64> = HashMap::new();
    let mut ids = HashSet::new();

    for row in entries {
        let id = json_str(&row["id"], "entry id")?;
        ensure(
            ids.insert(id.to_string()),
            format!("duplicate inventory id {id}"),
        )?;

        let class = json_str(&row["semantic_class"], "entry semantic_class")?;
        *by_class.entry(class.to_string()).or_insert(0) += 1;

        let source_path = json_str(&row["source_path"], "entry source_path")?;
        *by_source.entry(source_path.to_string()).or_insert(0) += 1;

        let source = root.join(source_path);
        ensure(
            source.exists(),
            format!("{id}: missing source {}", source.display()),
        )?;
        let source_text = std::fs::read_to_string(&source).map_err(|error| {
            failure(format!("{} should be readable: {error}", source.display()))
        })?;
        let marker = json_str(&row["line_marker"], "entry line_marker")?;
        let line = row["source_line"]
            .as_u64()
            .and_then(|line| usize::try_from(line).ok())
            .and_then(|line| line.checked_sub(1))
            .ok_or_else(|| failure(format!("{id}: invalid source_line")))?;
        ensure(
            !marker.is_empty()
                && source_text
                    .lines()
                    .nth(line)
                    .is_some_and(|text| text.contains(marker)),
            format!(
                "{id}: source {} missing marker {marker:?} at recorded line",
                source.display()
            ),
        )?;
    }

    let expected_entry_count = Some(u64::try_from(entries.len())?);
    ensure(
        summary.get("entry_count").and_then(|v| v.as_u64()) == expected_entry_count,
        "summary.entry_count mismatch",
    )?;

    let expected_by_class = serde_json::to_value(by_class)?;
    ensure(
        summary.get("by_semantic_class") == Some(&expected_by_class),
        "summary.by_semantic_class mismatch",
    )?;

    let expected_by_source = serde_json::to_value(by_source)?;
    ensure(
        summary.get("by_source_path") == Some(&expected_by_source),
        "summary.by_source_path mismatch",
    )
}

#[test]
fn gate_script_passes_and_emits_structured_report_and_log() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_semantic_contract_inventory.sh");
    ensure(script.exists(), format!("missing {}", script.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)
            .map_err(|error| failure(format!("{} metadata failed: {error}", script.display())))?
            .permissions();
        ensure(
            perms.mode() & 0o111 != 0,
            "check_semantic_contract_inventory.sh must be executable",
        )?;
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .map_err(|error| {
            failure(format!(
                "failed to run semantic contract inventory gate: {error}"
            ))
        })?;
    ensure(
        output.status.success(),
        format!(
            "semantic contract inventory gate failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ),
    )?;

    let report_path = root.join("target/conformance/semantic_contract_inventory.report.json");
    let log_path = root.join("target/conformance/semantic_contract_inventory.log.jsonl");
    ensure(
        report_path.exists(),
        format!("missing {}", report_path.display()),
    )?;
    ensure(log_path.exists(), format!("missing {}", log_path.display()))?;

    let report = load_json(&report_path)?;
    ensure(
        report["schema_version"].as_str() == Some("v1"),
        "report schema_version must be v1",
    )?;
    ensure(
        report["bead"].as_str() == Some("bd-bp8fl.1.1"),
        "report bead must be bd-bp8fl.1.1",
    )?;
    ensure(
        report["status"].as_str() == Some("pass"),
        "report status must be pass",
    )?;
    for check in [
        "json_parse",
        "top_level_shape",
        "entries_present",
        "entry_schema",
        "unique_ids",
        "seed_overlay_coverage",
        "summary_counts",
        "source_summary_counts",
        "source_markers",
        "exhaustive_export_surface",
        "semantic_claim_boundary",
    ] {
        ensure(
            report["checks"][check].as_str() == Some("pass"),
            format!("report checks.{check} should pass"),
        )?;
    }

    let log_line = std::fs::read_to_string(&log_path)
        .map_err(|error| {
            failure(format!(
                "{} should be readable: {error}",
                log_path.display()
            ))
        })?
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| failure("log should contain at least one row"))?
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&log_line)
        .map_err(|error| failure(format!("log row should parse: {error}")))?;
    for key in [
        "trace_id",
        "bead_id",
        "scenario_id",
        "runtime_mode",
        "replacement_level",
        "api_family",
        "symbol",
        "oracle_kind",
        "expected",
        "actual",
        "errno",
        "decision_path",
        "healing_action",
        "latency_ns",
        "artifact_refs",
        "source_commit",
        "target_dir",
        "failure_signature",
    ] {
        ensure(
            event.get(key).is_some(),
            format!("structured log row missing {key}"),
        )?;
    }

    Ok(())
}

#[test]
fn declared_surface_covers_both_census_profiles_without_semantic_promotion() -> TestResult {
    let root = workspace_root()?;
    let inventory = load_json(&root.join("tests/conformance/semantic_contract_inventory.v1.json"))?;
    let census = load_json(&root.join("tests/conformance/host_delegation_census.v1.json"))?;
    let surface = &inventory["export_surface"];
    ensure(
        surface["inventory_complete"].as_bool() == Some(true),
        "incomplete export inventory",
    )?;
    ensure(
        surface["semantic_review_complete"].as_bool() == Some(false),
        "source inventory is not full semantic review",
    )?;
    ensure(
        surface["source_tree_sha256"] == census["detector"]["source_tree_sha256"],
        "profile comparison requires the same source tree",
    )?;
    let groups = json_array(&surface["groups"], "export groups")?;
    let mut symbols = HashSet::new();
    for group in groups {
        ensure(
            group["semantic_status"] == "unknown",
            "source group promoted to semantics",
        )?;
        ensure(
            group["backend_review"] == "unreviewed",
            "source presence promoted to backend proof",
        )?;
        ensure(
            !json_str(&group["next_action"], "next action")?.is_empty(),
            "unknown needs a next action",
        )?;
        for symbol in json_array(&group["symbols"], "group symbols")? {
            ensure(
                symbols.insert(json_str(symbol, "symbol")?),
                "duplicate export membership",
            )?;
        }
    }
    ensure(
        surface["summary"]["declared_symbol_count"].as_u64() == Some(u64::try_from(symbols.len())?),
        "declared export count mismatch",
    )?;
    for profile in [
        "interpose-release-linux-x86_64",
        "standalone-release-linux-x86_64",
    ] {
        let actual = groups
            .iter()
            .filter(|group| {
                group["function_profiles"]
                    .as_array()
                    .is_some_and(|profiles| profiles.iter().any(|p| p == profile))
            })
            .map(|group| group["symbols"].as_array().map_or(0, Vec::len))
            .sum::<usize>();
        ensure(
            census["profile_census"][profile]["coverage"]["source_unique_export_symbol_count"]
                .as_u64()
                == Some(u64::try_from(actual)?),
            format!("{profile}: semantic source membership differs from the cfg-aware census"),
        )?;
    }
    ensure(
        surface["summary"]["full_semantics_count"].as_u64() == Some(0),
        "inventory must not claim semantic completion",
    )?;
    for symbol in [
        "sys_signame",
        "__libc_dlerror_result",
        "_itoa_lower_digits",
        "__frankenlibc_pointer_guard",
    ] {
        let group = groups
            .iter()
            .find(|group| {
                group["symbols"]
                    .as_array()
                    .is_some_and(|names| names.iter().any(|name| name == symbol))
            })
            .ok_or_else(|| failure(format!("declared data export omitted: {symbol}")))?;
        ensure(
            group["declaration_kinds"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|kind| kind == "data")),
            format!("{symbol}: data declaration must not be confused with a function"),
        )?;
    }
    Ok(())
}

#[test]
fn actual_gate_rejects_incomplete_stale_and_promoted_export_groups() -> TestResult {
    let root = workspace_root()?;
    let canonical = load_json(&root.join("tests/conformance/semantic_contract_inventory.v1.json"))?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let retained = std::env::temp_dir().join(format!(
        "frankenlibc-semantic-negative-{stamp}-{}",
        std::process::id()
    ));
    std::fs::create_dir(&retained)?;
    let mut observed = 0;
    for case in 0..10 {
        let mut mutant = canonical.clone();
        match case {
            0 => {
                ensure(
                    mutant["export_surface"]["groups"][0]["symbols"]
                        .as_array_mut()
                        .ok_or_else(|| failure("symbols"))?
                        .pop()
                        .is_some(),
                    "negative case requires a real symbol",
                )?;
                let count = mutant["export_surface"]["summary"]["declared_symbol_count"]
                    .as_u64()
                    .ok_or_else(|| failure("count"))?;
                mutant["export_surface"]["summary"]["declared_symbol_count"] = (count - 1).into();
                mutant["export_surface"]["summary"]["unknown_semantics_count"] = (count - 1).into();
            }
            1 => {
                let symbol = mutant["export_surface"]["groups"][0]["symbols"][0].clone();
                mutant["export_surface"]["groups"][0]["symbols"]
                    .as_array_mut()
                    .ok_or_else(|| failure("symbols"))?
                    .push(symbol);
            }
            2 => mutant["export_surface"]["groups"][0]["semantic_status"] = "full_semantics".into(),
            3 => {
                let groups = mutant["export_surface"]["groups"]
                    .as_array_mut()
                    .ok_or_else(|| failure("groups"))?;
                let active = groups
                    .iter_mut()
                    .find(|group| group["profiles"].as_array().is_some_and(|p| !p.is_empty()))
                    .ok_or_else(|| failure("active source group missing"))?;
                active["profiles"] = serde_json::json!([]);
            }
            4 => mutant["export_surface"]["source_tree_sha256"] = "0".repeat(64).into(),
            5 => mutant["export_surface"]["groups"][0]["next_action"] = "".into(),
            6 => mutant["export_surface"]["groups"][0]["backend_review"] = "verified".into(),
            7 => mutant["entries"][0]["evidence_artifacts"] = serde_json::json!(["README.md"]),
            8 => {
                mutant["entries"][0]["evidence_artifacts"] =
                    serde_json::json!(["missing-semantic-evidence.rs"])
            }
            9 => {
                let groups = mutant["export_surface"]["groups"]
                    .as_array_mut()
                    .ok_or_else(|| failure("groups"))?;
                let fallback = groups
                    .iter_mut()
                    .find(|group| group["support_status"] == "Stub")
                    .ok_or_else(|| failure("declared Stub group missing"))?;
                fallback["support_status"] = "Implemented".into();
            }
            _ => return Err(failure("unrecognized negative case")),
        }
        let path = retained.join(format!("case-{case}.json"));
        std::fs::write(&path, serde_json::to_vec_pretty(&mutant)?)?;
        let output = Command::new(root.join("scripts/check_semantic_contract_inventory.sh"))
            .current_dir(&root)
            .env("FLC_SEMANTIC_INVENTORY_ARTIFACT", &path)
            .output()?;
        std::fs::write(retained.join(format!("case-{case}.stdout")), &output.stdout)?;
        std::fs::write(retained.join(format!("case-{case}.stderr")), &output.stderr)?;
        ensure(
            !output.status.success(),
            format!(
                "case {case}: invalid inventory accepted; retained {}",
                retained.display()
            ),
        )?;
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        ensure(
            report["checks"]["exhaustive_export_surface"] == "fail",
            format!("case {case}: failed for unrelated reason: {report}"),
        )?;
        if matches!(case, 7 | 8) {
            ensure(
                report["checks"]["source_markers"] == "fail",
                "wrong or missing evidence must fail its own check, beyond the source binding",
            )?;
        }
        observed += 1;
    }
    ensure(observed == 10, "all planted negative controls must execute")
}

#[test]
fn refreshed_surface_cannot_hide_a_stale_source_line() -> TestResult {
    let root = workspace_root()?;
    let mut inventory =
        load_json(&root.join("tests/conformance/semantic_contract_inventory.v1.json"))?;
    let row = &mut inventory["entries"][0];
    let source = std::fs::read_to_string(root.join(json_str(&row["source_path"], "source")?))?;
    let marker = json_str(&row["line_marker"], "marker")?;
    ensure(source.contains(marker), "original marker must exist")?;
    ensure(
        !source.lines().next().unwrap_or_default().contains(marker),
        "fixture requires a different first line",
    )?;
    row["source_line"] = 1.into();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let retained = std::env::temp_dir().join(format!(
        "frankenlibc-semantic-stale-line-{stamp}-{}.json",
        std::process::id()
    ));
    std::fs::write(&retained, serde_json::to_vec_pretty(&inventory)?)?;
    let output = Command::new(root.join("scripts/check_semantic_contract_inventory.sh"))
        .arg("--refresh-surface")
        .current_dir(&root)
        .env("FLC_SEMANTIC_INVENTORY_ARTIFACT", &retained)
        .output()?;
    std::fs::write(retained.with_extension("stdout"), &output.stdout)?;
    std::fs::write(retained.with_extension("stderr"), &output.stderr)?;
    ensure(
        output.status.code() == Some(1),
        "stale source line must fail",
    )?;
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    ensure(
        report["checks"]["exhaustive_export_surface"] == "pass",
        "fixture must have fresh export/source/contract digests",
    )?;
    ensure(
        report["checks"]["source_markers"] == "fail",
        format!("stale line must fail its own check: {report}"),
    )
}

#[test]
fn unannotated_fallback_off_platform_dead_branch_and_missing_alias_stay_unknown() -> TestResult {
    let root = workspace_root()?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let retained = std::env::temp_dir().join(format!(
        "frankenlibc-semantic-source-cases-{stamp}-{}",
        std::process::id()
    ));
    std::fs::create_dir(&retained)?;
    let source = r#"
#[unsafe(no_mangle)]
pub extern "C" fn constant_result() -> i32 { 0 }
#[cfg(target_os = "windows")]
#[unsafe(no_mangle)]
pub extern "C" fn platform_enosys() -> i32 { -38 }
#[unsafe(no_mangle)]
pub extern "C" fn dead_branch() -> i32 { if false { return -1; } 7 }
"#;
    let support = serde_json::json!({"symbols": [
        {"symbol": "constant_result", "status": "Implemented"},
        {"symbol": "platform_enosys", "status": "Implemented"},
        {"symbol": "dead_branch", "status": "Implemented"},
        {"symbol": "missing_alias", "status": "Implemented"}
    ]});
    let contracts = serde_json::json!({"entries": [{
        "id": "reviewed-unsupported-platform-case",
        "symbols": ["platform_enosys"],
        "semantic_class": "unsupported_platform_contract",
        "current_behavior": "This fixture returns -ENOSYS only on Windows; Linux has no provider."
    }]});
    let support_path = retained.join("support.json");
    let contract_path = retained.join("contracts.json");
    std::fs::write(&support_path, serde_json::to_vec(&support)?)?;
    std::fs::write(&contract_path, serde_json::to_vec(&contracts)?)?;
    let mut surfaces = Vec::new();
    for (name, prefix) in [
        ("original", ""),
        (
            "moved",
            "\n\n// Independently move the same declarations.\n",
        ),
    ] {
        let fixture = retained.join(name);
        let src = fixture.join("src");
        std::fs::create_dir_all(&src)?;
        std::fs::write(src.join("lib.rs"), "pub mod fixture_abi;\n")?;
        std::fs::write(src.join("fixture_abi.rs"), format!("{prefix}{source}"))?;
        std::fs::write(
            fixture.join("libc.map"),
            "GLIBC_2.2.5 {\n    global:\n        constant_result;\n        platform_enosys;\n        dead_branch;\n        missing_alias;\n    local:\n        *;\n};\n",
        )?;
        let output = Command::new("python3")
            .arg("-c")
            .arg(r#"import importlib.util,json,pathlib,sys
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('semantic_fixture_census',sys.argv[1])
module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
root=pathlib.Path(sys.argv[2])
print(json.dumps(module.build_semantic_export_surface(root,root/'src',root/'libc.map',json.loads(pathlib.Path(sys.argv[3]).read_text()),json.loads(pathlib.Path(sys.argv[4]).read_text()))))
"#)
            .arg(root.join("scripts/generate_host_delegation_census.py"))
            .arg(&fixture)
            .arg(&support_path)
            .arg(&contract_path)
            .output()?;
        std::fs::write(fixture.join("surface.json"), &output.stdout)?;
        std::fs::write(fixture.join("stderr"), &output.stderr)?;
        ensure(
            output.status.success(),
            String::from_utf8_lossy(&output.stderr),
        )?;
        let surface: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        ensure(
            surface["summary"]["declared_symbol_count"] == 4,
            "four declared candidates",
        )?;
        ensure(
            surface["summary"]["raw_source_symbol_count"] == 3,
            "missing alias has no body",
        )?;
        ensure(
            surface["summary"]["unknown_semantics_count"] == 4,
            "all four remain unknown",
        )?;
        ensure(
            surface["summary"]["full_semantics_count"] == 0,
            "no behavioral proof",
        )?;
        ensure(
            surface["summary"]["unqualified_configuration_count"] == 2,
            "off-platform and missing alias lack Linux providers",
        )?;
        let groups = json_array(&surface["groups"], "fixture groups")?;
        for symbol in [
            "constant_result",
            "platform_enosys",
            "dead_branch",
            "missing_alias",
        ] {
            let group = groups
                .iter()
                .find(|group| {
                    group["symbols"]
                        .as_array()
                        .is_some_and(|symbols| symbols.iter().any(|s| s == symbol))
                })
                .ok_or_else(|| failure(format!("lost {symbol}")))?;
            ensure(
                group["semantic_status"] == "unknown",
                "body/label is not semantic qualification",
            )?;
            ensure(
                group["backend_review"] == "unreviewed",
                "no provider was executed",
            )?;
            ensure(
                !json_str(&group["next_action"], "next action")?.is_empty(),
                "unknown needs follow-up",
            )?;
            let profiles = json_array(&group["function_profiles"], "function profiles")?;
            ensure(
                profiles.len()
                    == if matches!(symbol, "constant_result" | "dead_branch") {
                        2
                    } else {
                        0
                    },
                format!("wrong provider profiles for {symbol}"),
            )?;
            if symbol == "platform_enosys" {
                ensure(
                    group["contract_ids"]
                        == serde_json::json!(["reviewed-unsupported-platform-case"]),
                    "limited contract remains linked without full promotion",
                )?;
            }
        }
        surfaces.push(surface);
    }
    ensure(
        surfaces[0]["groups"] == surfaces[1]["groups"],
        "moving a function must retain declared membership and unknown status",
    )?;
    ensure(
        surfaces[0]["source_tree_sha256"] != surfaces[1]["source_tree_sha256"],
        "moving a function must invalidate source identity",
    )
}
