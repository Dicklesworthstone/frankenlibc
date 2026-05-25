use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);
const CURRENT_TEST_COMMIT: &str = "1111111111111111111111111111111111111111";
const STALE_TEST_COMMIT: &str = "0000000000000000000000000000000000000000";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "workspace root not found".into())
}

fn unique_output_path(name: &str) -> TestResult<PathBuf> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    Ok(workspace_root()?.join(format!(
        "target/release_claim_gate_test/{name}.{}.{}.json",
        std::process::id(),
        id
    )))
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn run_gate(args: &[String]) -> TestResult<Output> {
    run_gate_with_env(args, &[])
}

fn run_gate_with_env(args: &[String], envs: &[(&str, String)]) -> TestResult<Output> {
    let mut command =
        Command::new(workspace_root()?.join("scripts/release/check_replacement_claim_evidence.sh"));
    command.args(args);
    for (name, value) in envs {
        command.env(name, value);
    }
    Ok(command.output()?)
}

fn read_report(path: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_file(path: &Path, contents: &str) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    Ok(())
}

fn rel_path(path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(workspace_root()?)?
        .to_string_lossy()
        .into_owned())
}

fn release_claim_refs(extra_refs: &[String]) -> TestResult<String> {
    let mut refs = vec![
        "tests/conformance/replacement_levels.json".to_owned(),
        "support_matrix.json".to_owned(),
        "tests/conformance/claim_reconciliation_report.v1.json".to_owned(),
        "tests/conformance/l1_crt_startup_tls_proof_matrix.v1.json".to_owned(),
    ];
    refs.extend(extra_refs.iter().cloned());
    Ok(refs
        .into_iter()
        .map(|value| format!(r#""{value}""#))
        .collect::<Vec<_>>()
        .join(", "))
}

fn l1_dashboard_fixture(generated_utc: &str, source_commit: &str, include_perf: bool) -> String {
    let perf_rows = if include_perf {
        r#",
    {
      "row_id": "perf-regression-prevention-no-issues",
      "row_kind": "perf",
      "evidence_artifact": "tests/conformance/perf_regression_prevention.v1.json",
      "field": "summary.total_issues",
      "expected_value": 0
    }"#
    } else {
        ""
    };
    format!(
        r#"{{
  "schema_version": "v1",
  "generated_utc": "{generated_utc}",
  "source_commit": "{source_commit}",
  "source_commit_freshness_policy": {{
    "recorded_source_commit_field": "source_commit",
    "current_head_check": "git rev-parse HEAD",
    "fresh_result": "eligible_for_row_evaluation_only",
    "stale_result": "report_blockers_no_auto_promotion",
    "promotion_allowed_when_stale": false,
    "rejected_evidence_kind": "stale_source_commit"
  }},
  "policy": {{"max_evidence_age_days": 180}},
  "rows": [
    {{
      "row_id": "standalone-artifact-forge-current",
      "row_kind": "forge",
      "evidence_artifact": "tests/conformance/standalone_replacement_artifact.v1.json",
      "field": "schema_version",
      "expected_value": "v1"
    }},
    {{
      "row_id": "crt-tls-atexit-direct-link-proof-current",
      "row_kind": "direct_link",
      "evidence_artifact": "tests/conformance/crt_tls_atexit_direct_link_run_proof_fixtures.v1.json",
      "field": "schema_version",
      "expected_value": "v1"
    }},
    {{
      "row_id": "real-program-smoke-suite-current",
      "row_kind": "real_program",
      "evidence_artifact": "tests/conformance/real_program_smoke_suite.v1.json",
      "field": "schema_version",
      "expected_value": "v1"
    }},
    {{
      "row_id": "dlfcn-sentinel-l1-blocker-count-bound",
      "row_kind": "dlfcn",
      "evidence_artifact": "tests/conformance/dlfcn_replace_boundary_l1_burndown.v1.json",
      "field": "expected_counts.l1_blocker",
      "expected_value_max": 6
    }}{perf_rows}
  ]
}}
"#
    )
}

#[test]
fn current_l0_release_policy_passes_without_l1_evidence() -> TestResult {
    let levels = unique_output_path("current-l0-levels")?;
    let readme = unique_output_path("current-l0-readme")?;
    let report = unique_output_path("current-l0-report")?;
    let log = unique_output_path("current-l0-log")?;
    let mut levels_json =
        read_report(&workspace_root()?.join("tests/conformance/replacement_levels.json"))?;
    levels_json["current_level"] = serde_json::json!("L0");
    levels_json["release_tag_policy"]["current_release_level"] = serde_json::json!("L0");
    levels_json["release_tag_policy"]["current_release_tag_example"] =
        serde_json::json!("v0.1.0-L0");
    write_file(
        &levels,
        &(serde_json::to_string_pretty(&levels_json)? + "\n"),
    )?;
    write_file(&readme, "Declared replacement level claim: **L0**\n")?;

    let output = run_gate_with_env(
        &[
            "--report".to_owned(),
            path_arg(&report),
            "--log".to_owned(),
            path_arg(&log),
        ],
        &[
            ("FRANKENLIBC_REPLACEMENT_LEVELS", path_arg(&levels)),
            ("FRANKENLIBC_README", path_arg(&readme)),
        ],
    )?;

    assert!(
        output.status.success(),
        "current L0 release policy must pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = read_report(&report)?;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["current_release_level"].as_str(), Some("L0"));
    Ok(())
}

#[test]
fn current_l1_release_policy_passes_with_objective_evidence_bundle() -> TestResult {
    let report = unique_output_path("current-l1-report")?;
    let log = unique_output_path("current-l1-log")?;
    let output = run_gate(&[
        "--report".to_owned(),
        path_arg(&report),
        "--log".to_owned(),
        path_arg(&log),
    ])?;

    assert!(
        output.status.success(),
        "current L1 release policy must pass with objective evidence\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = read_report(&report)?;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["current_release_level"].as_str(), Some("L1"));
    let claim = &report_json["claims"][0];
    let present = claim["present_evidence"]
        .as_array()
        .ok_or("present_evidence must be array")?;
    for required_ref in [
        "support_matrix.json",
        "tests/conformance/claim_reconciliation_report.v1.json",
        "tests/conformance/l1_crt_startup_tls_proof_matrix.v1.json",
        "tests/conformance/ld_preload_smoke_summary.v1.json",
        "tests/conformance/perf_regression_prevention.v1.json",
    ] {
        assert!(
            present
                .iter()
                .any(|value| value.as_str() == Some(required_ref)),
            "current L1 claim should cite {required_ref}: {claim}"
        );
    }
    let required = claim["required_evidence"]
        .as_array()
        .ok_or("required_evidence must be array")?;
    assert!(
        !required.iter().any(|value| {
            value.as_str() == Some("tests/conformance/l1_dry_run_readiness_dashboard.v1.json")
        }),
        "plain L1 release policy should not require standalone-readiness dashboard rows: {claim}"
    );
    Ok(())
}

#[test]
fn release_doc_known_limitation_claim_passes_without_l1_dashboard() -> TestResult {
    let claims = unique_output_path("known-limitation-doc-claims")?;
    let report = unique_output_path("known-limitation-doc-report")?;
    let log = unique_output_path("known-limitation-doc-log")?;
    write_file(
        &claims,
        r#"{
  "schema_version": "v1",
  "claims": [
    {
      "id": "release-doc-known-limitation",
      "tag": "v0.1.0-L0",
      "claimed_level": "L0",
      "claim_surface": "README.md",
      "claim_text": "Full standalone replacement remains planned; the current release claim is L0 interpose.",
      "artifact_refs": ["tests/conformance/replacement_levels.json"]
    }
  ]
}
"#,
    )?;

    let output = run_gate(&[
        "--claims".to_owned(),
        path_arg(&claims),
        "--report".to_owned(),
        path_arg(&report),
        "--log".to_owned(),
        path_arg(&log),
    ])?;

    assert!(
        output.status.success(),
        "known-limitation doc claim should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report_json = read_report(&report)?;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    Ok(())
}

#[test]
fn release_doc_standalone_readiness_without_l1_dashboard_fails_closed() -> TestResult {
    let claims = unique_output_path("standalone-ready-doc-claims")?;
    let report = unique_output_path("standalone-ready-doc-report")?;
    let log = unique_output_path("standalone-ready-doc-log")?;
    write_file(
        &claims,
        r#"{
  "schema_version": "v1",
  "claims": [
    {
      "id": "release-doc-standalone-ready",
      "tag": "v0.1.0-L0",
      "claimed_level": "L0",
      "claim_surface": "README.md",
      "claim_text": "FrankenLibC is ready as a standalone replacement for glibc today.",
      "artifact_refs": ["tests/conformance/replacement_levels.json"]
    }
  ]
}
"#,
    )?;

    let output = run_gate(&[
        "--claims".to_owned(),
        path_arg(&claims),
        "--report".to_owned(),
        path_arg(&report),
        "--log".to_owned(),
        path_arg(&log),
    ])?;

    assert!(
        !output.status.success(),
        "standalone-ready release doc claim must fail without dashboard evidence"
    );
    let report_json = read_report(&report)?;
    let signature = report_json["claims"][0]["failure_signature"]
        .as_str()
        .unwrap_or_default();
    assert!(
        signature.contains("release_claim_doc_standalone_readiness_requires_l1_dashboard")
            && signature.contains("release_claim_missing_l1_dry_run_dashboard_evidence"),
        "standalone-ready doc claim failures not found: {report_json}"
    );
    Ok(())
}

#[test]
fn l1_release_tag_without_evidence_file_fails_closed() -> TestResult {
    let claims = unique_output_path("missing-l1-claims")?;
    let report = unique_output_path("missing-l1-report")?;
    let log = unique_output_path("missing-l1-log")?;
    if let Some(parent) = claims.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &claims,
        r#"{
  "schema_version": "v1",
  "claims": [
    {
      "id": "bad-l1-tag",
      "tag": "v9.9.9-L1",
      "claimed_level": "L1",
      "artifact_refs": ["tests/conformance/replacement_levels.json"]
    }
  ]
}
"#,
    )?;

    let output = run_gate(&[
        "--claims".to_owned(),
        path_arg(&claims),
        "--report".to_owned(),
        path_arg(&report),
        "--log".to_owned(),
        path_arg(&log),
    ])?;

    assert!(
        !output.status.success(),
        "L1 tag without proof matrix evidence must fail"
    );

    let report_json = read_report(&report)?;
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    assert_eq!(report_json["failed_claim_count"].as_u64(), Some(1));
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_missing_l1_evidence"),
        "missing-evidence failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn stale_l1_dry_run_dashboard_fixture_blocks_release_doc_claim() -> TestResult {
    let dashboard = unique_output_path("stale-l1-dashboard")?;
    let claims = unique_output_path("stale-l1-dashboard-claims")?;
    let report = unique_output_path("stale-l1-dashboard-report")?;
    let log = unique_output_path("stale-l1-dashboard-log")?;
    write_file(
        &dashboard,
        &l1_dashboard_fixture("2000-01-01T00:00:00Z", CURRENT_TEST_COMMIT, true),
    )?;
    write_file(
        &claims,
        &format!(
            r#"{{
  "schema_version": "v1",
  "claims": [
    {{
      "id": "stale-dashboard-doc-claim",
      "tag": "v9.9.9-L1",
      "claimed_level": "L1",
      "claim_surface": "RELEASE.md",
      "claim_text": "FrankenLibC is ready as a standalone replacement for glibc today.",
      "artifact_refs": [{}]
    }}
  ]
}}
"#,
            release_claim_refs(&[rel_path(&dashboard)?])?
        ),
    )?;

    let output = run_gate_with_env(
        &[
            "--claims".to_owned(),
            path_arg(&claims),
            "--report".to_owned(),
            path_arg(&report),
            "--log".to_owned(),
            path_arg(&log),
        ],
        &[
            ("FRANKENLIBC_L1_DRY_RUN_DASHBOARD", path_arg(&dashboard)),
            ("SOURCE_COMMIT", CURRENT_TEST_COMMIT.to_owned()),
        ],
    )?;

    assert!(
        !output.status.success(),
        "stale L1 dry-run dashboard must block standalone-ready doc claims"
    );
    let report_json = read_report(&report)?;
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_stale_l1_dry_run_dashboard_evidence"),
        "stale-dashboard failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn l1_dry_run_dashboard_wrong_source_commit_blocks_release_doc_claim() -> TestResult {
    let dashboard = unique_output_path("wrong-source-l1-dashboard")?;
    let claims = unique_output_path("wrong-source-l1-dashboard-claims")?;
    let report = unique_output_path("wrong-source-l1-dashboard-report")?;
    let log = unique_output_path("wrong-source-l1-dashboard-log")?;
    write_file(
        &dashboard,
        &l1_dashboard_fixture("2026-05-05T07:00:00Z", STALE_TEST_COMMIT, true),
    )?;
    write_file(
        &claims,
        &format!(
            r#"{{
  "schema_version": "v1",
  "claims": [
    {{
      "id": "wrong-source-dashboard-doc-claim",
      "tag": "v9.9.9-L1",
      "claimed_level": "L1",
      "claim_surface": "RELEASE.md",
      "claim_text": "FrankenLibC is ready as a standalone replacement for glibc today.",
      "artifact_refs": [{}]
    }}
  ]
}}
"#,
            release_claim_refs(&[rel_path(&dashboard)?])?
        ),
    )?;

    let output = run_gate_with_env(
        &[
            "--claims".to_owned(),
            path_arg(&claims),
            "--report".to_owned(),
            path_arg(&report),
            "--log".to_owned(),
            path_arg(&log),
        ],
        &[
            ("FRANKENLIBC_L1_DRY_RUN_DASHBOARD", path_arg(&dashboard)),
            ("SOURCE_COMMIT", CURRENT_TEST_COMMIT.to_owned()),
        ],
    )?;

    assert!(
        !output.status.success(),
        "wrong L1 dry-run dashboard source_commit must block standalone-ready doc claims"
    );
    let report_json = read_report(&report)?;
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_l1_dashboard_source_commit_stale"),
        "wrong-source-commit failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn l1_dry_run_dashboard_malformed_source_policy_blocks_release_doc_claim() -> TestResult {
    let dashboard = unique_output_path("malformed-source-policy-l1-dashboard")?;
    let claims = unique_output_path("malformed-source-policy-l1-dashboard-claims")?;
    let report = unique_output_path("malformed-source-policy-l1-dashboard-report")?;
    let log = unique_output_path("malformed-source-policy-l1-dashboard-log")?;
    let mut dashboard_json: serde_json::Value = serde_json::from_str(&l1_dashboard_fixture(
        "2026-05-05T07:00:00Z",
        CURRENT_TEST_COMMIT,
        true,
    ))?;
    dashboard_json["source_commit_freshness_policy"]["fresh_result"] =
        serde_json::json!("claim_eligible_when_fresh");
    write_file(
        &dashboard,
        &(serde_json::to_string_pretty(&dashboard_json)? + "\n"),
    )?;
    write_file(
        &claims,
        &format!(
            r#"{{
  "schema_version": "v1",
  "claims": [
    {{
      "id": "malformed-source-policy-dashboard-doc-claim",
      "tag": "v9.9.9-L1",
      "claimed_level": "L1",
      "claim_surface": "RELEASE.md",
      "claim_text": "FrankenLibC is ready as a standalone replacement for glibc today.",
      "artifact_refs": [{}]
    }}
  ]
}}
"#,
            release_claim_refs(&[rel_path(&dashboard)?])?
        ),
    )?;

    let output = run_gate_with_env(
        &[
            "--claims".to_owned(),
            path_arg(&claims),
            "--report".to_owned(),
            path_arg(&report),
            "--log".to_owned(),
            path_arg(&log),
        ],
        &[
            ("FRANKENLIBC_L1_DRY_RUN_DASHBOARD", path_arg(&dashboard)),
            ("SOURCE_COMMIT", CURRENT_TEST_COMMIT.to_owned()),
        ],
    )?;

    assert!(
        !output.status.success(),
        "malformed L1 dashboard source freshness policy must block standalone-ready doc claims"
    );
    let report_json = read_report(&report)?;
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_l1_dashboard_source_commit_policy_invalid"),
        "malformed source policy failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn l1_proof_matrix_wrong_source_commit_blocks_release_claim() -> TestResult {
    let root = workspace_root()?;
    let matrix = unique_output_path("wrong-source-l1-matrix")?;
    let dashboard = unique_output_path("current-l1-dashboard")?;
    let claims = unique_output_path("wrong-source-l1-matrix-claims")?;
    let report = unique_output_path("wrong-source-l1-matrix-report")?;
    let log = unique_output_path("wrong-source-l1-matrix-log")?;

    let mut matrix_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        root.join("tests/conformance/l1_crt_startup_tls_proof_matrix.v1.json"),
    )?)?;
    matrix_json["source_commit"] = serde_json::json!(STALE_TEST_COMMIT);
    write_file(
        &matrix,
        &(serde_json::to_string_pretty(&matrix_json)? + "\n"),
    )?;
    write_file(
        &dashboard,
        &l1_dashboard_fixture("2026-05-05T07:00:00Z", CURRENT_TEST_COMMIT, true),
    )?;
    write_file(
        &claims,
        &format!(
            r#"{{
  "schema_version": "v1",
  "claims": [
    {{
      "id": "wrong-source-l1-matrix-claim",
      "tag": "v9.9.9-L1",
      "claimed_level": "L1",
      "artifact_refs": [{}]
    }}
  ]
}}
"#,
            release_claim_refs(&[rel_path(&matrix)?, rel_path(&dashboard)?])?
        ),
    )?;

    let output = run_gate_with_env(
        &[
            "--claims".to_owned(),
            path_arg(&claims),
            "--report".to_owned(),
            path_arg(&report),
            "--log".to_owned(),
            path_arg(&log),
        ],
        &[
            ("FRANKENLIBC_L1_PROOF_MATRIX", path_arg(&matrix)),
            ("FRANKENLIBC_L1_DRY_RUN_DASHBOARD", path_arg(&dashboard)),
            ("SOURCE_COMMIT", CURRENT_TEST_COMMIT.to_owned()),
        ],
    )?;

    assert!(
        !output.status.success(),
        "wrong L1 proof matrix source_commit must block replacement claims"
    );
    let report_json = read_report(&report)?;
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_l1_matrix_source_commit_stale"),
        "wrong L1 proof matrix source_commit failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn l1_dry_run_dashboard_missing_required_row_kind_blocks_release_doc_claim() -> TestResult {
    let dashboard = unique_output_path("missing-perf-l1-dashboard")?;
    let claims = unique_output_path("missing-perf-l1-dashboard-claims")?;
    let report = unique_output_path("missing-perf-l1-dashboard-report")?;
    let log = unique_output_path("missing-perf-l1-dashboard-log")?;
    write_file(
        &dashboard,
        &l1_dashboard_fixture("2026-05-05T07:00:00Z", CURRENT_TEST_COMMIT, false),
    )?;
    write_file(
        &claims,
        &format!(
            r#"{{
  "schema_version": "v1",
  "claims": [
    {{
      "id": "missing-dashboard-perf-doc-claim",
      "tag": "v9.9.9-L1",
      "claimed_level": "L1",
      "claim_surface": "README.md",
      "claim_text": "FrankenLibC is ready as a standalone replacement for glibc today.",
      "artifact_refs": [{}]
    }}
  ]
}}
"#,
            release_claim_refs(&[rel_path(&dashboard)?])?
        ),
    )?;

    let output = run_gate_with_env(
        &[
            "--claims".to_owned(),
            path_arg(&claims),
            "--report".to_owned(),
            path_arg(&report),
            "--log".to_owned(),
            path_arg(&log),
        ],
        &[
            ("FRANKENLIBC_L1_DRY_RUN_DASHBOARD", path_arg(&dashboard)),
            ("SOURCE_COMMIT", CURRENT_TEST_COMMIT.to_owned()),
        ],
    )?;

    assert!(
        !output.status.success(),
        "L1 dashboard missing the perf row kind must block doc claims"
    );
    let report_json = read_report(&report)?;
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_l1_dashboard_missing_required_row_kind:perf"),
        "missing-row-kind failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn l2_release_tag_without_standalone_matrix_fails_closed() -> TestResult {
    let claims = unique_output_path("missing-l2-claims")?;
    let report = unique_output_path("missing-l2-report")?;
    let log = unique_output_path("missing-l2-log")?;
    write_file(
        &claims,
        &format!(
            r#"{{
  "schema_version": "v1",
  "claims": [
    {{
      "id": "bad-l2-tag",
      "tag": "v9.9.9-L2",
      "claimed_level": "L2",
      "artifact_refs": [{}]
    }}
  ]
}}
"#,
            release_claim_refs(&[])?
        ),
    )?;

    let output = run_gate(&[
        "--claims".to_owned(),
        path_arg(&claims),
        "--report".to_owned(),
        path_arg(&report),
        "--log".to_owned(),
        path_arg(&log),
    ])?;

    assert!(
        !output.status.success(),
        "L2 tag without standalone evidence must fail"
    );
    let report_json = read_report(&report)?;
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_missing_l2_evidence"),
        "missing-L2 failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn l3_release_tag_without_standalone_matrix_fails_closed() -> TestResult {
    let claims = unique_output_path("missing-l3-claims")?;
    let report = unique_output_path("missing-l3-report")?;
    let log = unique_output_path("missing-l3-log")?;
    write_file(
        &claims,
        &format!(
            r#"{{
  "schema_version": "v1",
  "claims": [
    {{
      "id": "bad-l3-tag",
      "tag": "v9.9.9-L3",
      "claimed_level": "L3",
      "artifact_refs": [{}]
    }}
  ]
}}
"#,
            release_claim_refs(&[])?
        ),
    )?;

    let output = run_gate(&[
        "--claims".to_owned(),
        path_arg(&claims),
        "--report".to_owned(),
        path_arg(&report),
        "--log".to_owned(),
        path_arg(&log),
    ])?;

    assert!(
        !output.status.success(),
        "L3 tag without standalone evidence must fail"
    );
    let report_json = read_report(&report)?;
    let signature = report_json["claims"][0]["failure_signature"]
        .as_str()
        .unwrap_or_default();
    assert!(
        signature.contains("release_claim_missing_l2_evidence")
            && signature.contains("release_claim_missing_l3_evidence"),
        "missing-L2/L3 failures not found: {report_json}"
    );
    Ok(())
}

#[test]
fn stale_support_matrix_fixture_blocks_l1_claim() -> TestResult {
    let support = unique_output_path("stale-support-matrix")?;
    let claims = unique_output_path("stale-support-claims")?;
    let report = unique_output_path("stale-support-report")?;
    let log = unique_output_path("stale-support-log")?;
    write_file(
        &support,
        r#"{
  "version": 2,
  "generated_at_utc": "2000-01-01T00:00:00Z",
  "symbols": [
    {"symbol": "puts", "status": "Implemented"}
  ]
}
"#,
    )?;
    write_file(
        &claims,
        &format!(
            r#"{{
  "schema_version": "v1",
  "claims": [
    {{
      "id": "stale-support-l1",
      "tag": "v9.9.9-L1",
      "claimed_level": "L1",
      "artifact_refs": [{}]
    }}
  ]
}}
"#,
            release_claim_refs(&[rel_path(&support)?])?
        ),
    )?;

    let output = run_gate_with_env(
        &[
            "--claims".to_owned(),
            path_arg(&claims),
            "--report".to_owned(),
            path_arg(&report),
            "--log".to_owned(),
            path_arg(&log),
        ],
        &[("FRANKENLIBC_SUPPORT_MATRIX", path_arg(&support))],
    )?;

    assert!(
        !output.status.success(),
        "stale support matrix evidence must fail"
    );
    let report_json = read_report(&report)?;
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_stale_support_matrix_evidence"),
        "stale-support failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn stubbed_support_matrix_fixture_blocks_l1_claim() -> TestResult {
    let support = unique_output_path("stubbed-support-matrix")?;
    let claims = unique_output_path("stubbed-support-claims")?;
    let report = unique_output_path("stubbed-support-report")?;
    let log = unique_output_path("stubbed-support-log")?;
    write_file(
        &support,
        r#"{
  "version": 2,
  "generated_at_utc": "2026-05-03T00:00:00Z",
  "symbols": [
    {"symbol": "puts", "status": "Stub"}
  ]
}
"#,
    )?;
    write_file(
        &claims,
        &format!(
            r#"{{
  "schema_version": "v1",
  "claims": [
    {{
      "id": "stubbed-support-l1",
      "tag": "v9.9.9-L1",
      "claimed_level": "L1",
      "artifact_refs": [{}]
    }}
  ]
}}
"#,
            release_claim_refs(&[rel_path(&support)?])?
        ),
    )?;

    let output = run_gate_with_env(
        &[
            "--claims".to_owned(),
            path_arg(&claims),
            "--report".to_owned(),
            path_arg(&report),
            "--log".to_owned(),
            path_arg(&log),
        ],
        &[("FRANKENLIBC_SUPPORT_MATRIX", path_arg(&support))],
    )?;

    assert!(
        !output.status.success(),
        "Stub status in support matrix must block L1 release claims"
    );
    let report_json = read_report(&report)?;
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_support_matrix_stubs_present"),
        "stubbed-support failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn support_matrix_count_drift_blocks_release_claim() -> TestResult {
    let support = unique_output_path("drifted-support-matrix")?;
    let claims = unique_output_path("drifted-support-claims")?;
    let report = unique_output_path("drifted-support-report")?;
    let log = unique_output_path("drifted-support-log")?;
    write_file(
        &support,
        r#"{
  "version": 2,
  "generated_at_utc": "2026-05-25T00:00:00Z",
  "total_exported": 1,
  "symbols": [
    {"symbol": "puts", "status": "Implemented"}
  ],
  "summary": {
    "total": 1,
    "implemented": 0,
    "raw_syscall": 0,
    "wraps_host_libc": 1,
    "glibc_call_through": 0,
    "stub": 0
  },
  "counts": {
    "implemented": 0,
    "raw_syscall": 0,
    "wraps_host_libc": 1,
    "glibc_call_through": 0,
    "stub": 0
  },
  "implemented": 0,
  "raw_syscall": 0,
  "wraps_host_libc": 1,
  "glibc_call_through": 0,
  "stub": 0
}
"#,
    )?;
    write_file(
        &claims,
        &format!(
            r#"{{
  "schema_version": "v1",
  "claims": [
    {{
      "id": "drifted-support-l1",
      "tag": "v9.9.9-L1",
      "claimed_level": "L1",
      "artifact_refs": [{}]
    }}
  ]
}}
"#,
            release_claim_refs(&[rel_path(&support)?])?
        ),
    )?;

    let output = run_gate_with_env(
        &[
            "--claims".to_owned(),
            path_arg(&claims),
            "--report".to_owned(),
            path_arg(&report),
            "--log".to_owned(),
            path_arg(&log),
        ],
        &[("FRANKENLIBC_SUPPORT_MATRIX", path_arg(&support))],
    )?;

    assert!(
        !output.status.success(),
        "support matrix count drift must block release claims"
    );
    let report_json = read_report(&report)?;
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_support_matrix_count_drift"),
        "count-drift failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn contradictory_readme_claim_blocks_current_policy() -> TestResult {
    let readme = unique_output_path("contradictory-readme")?;
    let report = unique_output_path("contradictory-readme-report")?;
    let log = unique_output_path("contradictory-readme-log")?;
    write_file(
        &readme,
        "Declared replacement level claim: **L2 - Partial Replacement**.\n",
    )?;

    let output = run_gate_with_env(
        &[
            "--report".to_owned(),
            path_arg(&report),
            "--log".to_owned(),
            path_arg(&log),
        ],
        &[("FRANKENLIBC_README", path_arg(&readme))],
    )?;

    assert!(
        !output.status.success(),
        "README claim above current release level must fail"
    );
    let report_json = read_report(&report)?;
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_readme_overclaims_current_release_level"),
        "README overclaim failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn malformed_claims_json_without_claims_array_fails() -> TestResult {
    let claims = unique_output_path("malformed-claims")?;
    let report = unique_output_path("malformed-claims-report")?;
    let log = unique_output_path("malformed-claims-log")?;
    write_file(&claims, r#"{"schema_version":"v1","claim":{}}"#)?;

    let output = run_gate(&[
        "--claims".to_owned(),
        path_arg(&claims),
        "--report".to_owned(),
        path_arg(&report),
        "--log".to_owned(),
        path_arg(&log),
    ])?;

    assert!(
        !output.status.success(),
        "claims JSON without claims array must fail"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("claims array"),
        "schema failure should name the missing claims array\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
