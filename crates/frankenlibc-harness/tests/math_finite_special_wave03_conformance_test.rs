//! Deterministic math finite/special fixture wave-03 tests.
//!
//! Run: cargo test -p frankenlibc-harness --test math_finite_special_wave03_conformance_test

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const THIRD_WAVE_SYMBOLS: &[&str] = &[
    "__asinl_finite",
    "__atan2_finite",
    "__atan2f128_finite",
    "__atan2f_finite",
    "__atan2l_finite",
    "__atanh_finite",
    "__atanhf128_finite",
    "__atanhf_finite",
    "__atanhl_finite",
    "__clog10",
    "__clog10f",
    "__clog10l",
];

const REQUIRED_LOG_FIELDS: &[&str] = &["symbol", "mode", "expected", "actual", "failure_signature"];
const AMBIENT_POLICY: &str = "forbid_fenv_errno_host_long_double_or_f128_overclaim";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FixtureFile {
    version: String,
    family: String,
    captured_at: String,
    description: String,
    spec_reference: String,
    campaign: Campaign,
    structured_log_fields: Vec<String>,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Campaign {
    bead: String,
    campaign_id: String,
    wave_id: String,
    source_artifact: String,
    ambient_state_policy: String,
    first_wave_symbols: Vec<String>,
    residual_symbols: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FixtureCase {
    name: String,
    function: String,
    spec_section: String,
    inputs: serde_json::Value,
    expected_output: String,
    expected_errno: i32,
    mode: String,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MatrixCaseEnvelope {
    kind: String,
    #[serde(default)]
    run: Option<DifferentialExecution>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DifferentialExecution {
    host_output: String,
    impl_output: String,
    host_parity: bool,
    #[serde(default)]
    note: Option<String>,
}

fn load_fixture() -> FixtureFile {
    let path = repo_root().join("tests/conformance/fixtures/math_finite_special_wave03.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|err| panic!("invalid JSON in {}: {err}", path.display()))
}

fn execute_case_via_harness(
    function: &str,
    inputs: &serde_json::Value,
    mode: &str,
) -> Result<DifferentialExecution, String> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_harness"))
        .arg("conformance-matrix-case")
        .arg("--function")
        .arg(function)
        .arg("--mode")
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn harness subprocess: {err}"))?;

    let payload =
        serde_json::to_vec(inputs).map_err(|err| format!("failed to serialize inputs: {err}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(&payload)
            .map_err(|err| format!("failed to write subprocess stdin: {err}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait on harness subprocess: {err}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        return Err(format!(
            "harness subprocess exited with status {:?}: {}",
            output.status.code(),
            stderr
        ));
    }

    let envelope: MatrixCaseEnvelope = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("invalid harness subprocess payload: {err}"))?;
    match envelope.kind.as_str() {
        "ok" => envelope
            .run
            .ok_or_else(|| String::from("missing run payload from harness subprocess")),
        "error" => Err(envelope
            .error
            .unwrap_or_else(|| String::from("missing error payload from harness subprocess"))),
        other => Err(format!("unknown harness subprocess payload kind: {other}")),
    }
}

fn skips_host_oracle(symbol: &str) -> bool {
    symbol.contains("f128")
        || matches!(
            symbol,
            "__asinl_finite"
                | "__atan2l_finite"
                | "__atanhl_finite"
                | "__clog10"
                | "__clog10f"
                | "__clog10l"
        )
}

#[test]
fn math_finite_special_wave03_fixture_exists_and_names_campaign() {
    let path = repo_root().join("tests/conformance/fixtures/math_finite_special_wave03.json");
    assert!(
        path.exists(),
        "math_finite_special_wave03.json fixture must exist"
    );

    let fixture = load_fixture();
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "math_finite_special_wave03");
    assert_eq!(fixture.campaign.bead, "bd-gmbqy.8");
    assert_eq!(fixture.campaign.campaign_id, "fcq-math-special");
    assert_eq!(fixture.campaign.wave_id, "wave-03-math-finite-special");
    assert_eq!(
        fixture.campaign.source_artifact,
        "tests/conformance/fixture_coverage_prioritizer.v1.json"
    );
    assert_eq!(fixture.campaign.ambient_state_policy, AMBIENT_POLICY);
    for token in [
        "structured logs",
        "fenv state",
        "errno storage",
        "long-double ABI",
        "f128 ABI",
        "host complex ABI",
        "addresses",
        "timestamps",
        "stderr",
        "process-global counters",
    ] {
        assert!(
            fixture.description.contains(token),
            "fixture description must reject ambient capture token {token}"
        );
    }
}

#[test]
fn math_finite_special_wave03_covers_third_wave_in_both_modes() {
    let fixture = load_fixture();
    let expected: BTreeSet<_> = THIRD_WAVE_SYMBOLS.iter().copied().collect();
    let declared: BTreeSet<_> = fixture
        .campaign
        .first_wave_symbols
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(declared, expected, "campaign first-wave symbol drift");
    assert!(
        fixture.campaign.residual_symbols.is_empty(),
        "math finite/special wave should not leave residual symbols"
    );

    let mut modes_by_symbol: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for case in &fixture.cases {
        modes_by_symbol
            .entry(case.function.as_str())
            .or_default()
            .insert(case.mode.as_str());
    }

    for symbol in THIRD_WAVE_SYMBOLS {
        let modes = modes_by_symbol
            .get(symbol)
            .unwrap_or_else(|| panic!("missing fixture cases for {symbol}"));
        assert!(modes.contains("strict"), "missing strict case for {symbol}");
        assert!(
            modes.contains("hardened"),
            "missing hardened case for {symbol}"
        );
    }
}

#[test]
fn math_finite_special_wave03_logs_expected_classes_without_ambient_leaks() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.structured_log_fields, REQUIRED_LOG_FIELDS,
        "structured log field contract drifted"
    );

    let mut saw_domain = false;
    let mut saw_signed_finite = false;
    let mut saw_complex = false;
    let mut saw_mapped_skip = false;

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "case name must not be empty");
        assert!(!case.spec_section.is_empty(), "case spec_section missing");
        assert_eq!(
            case.inputs["ambient_state_policy"].as_str(),
            Some(AMBIENT_POLICY),
            "case {} must state ambient policy",
            case.name
        );
        let expected = case.inputs["expected"]
            .as_str()
            .unwrap_or_else(|| panic!("case {} missing expected class", case.name));
        assert!(
            matches!(
                expected,
                "DOMAIN_NAN" | "FINITE_NEGATIVE" | "FINITE_POSITIVE"
            ) || expected.starts_with("COMPLEX_FINITE_"),
            "case {} uses unsupported class {expected}",
            case.name
        );
        assert!(
            case.expected_output.starts_with(&format!(
                "symbol={};mode={};expected={expected};actual={expected};failure_signature=none",
                case.function, case.mode
            )),
            "case {} must use structured log output",
            case.name
        );

        if expected == "DOMAIN_NAN" {
            saw_domain = true;
            assert_eq!(case.expected_errno, 33, "domain class must carry EDOM");
        } else {
            assert_eq!(
                case.expected_errno, 0,
                "non-domain class must carry errno 0"
            );
        }
        if matches!(expected, "FINITE_NEGATIVE" | "FINITE_POSITIVE") {
            saw_signed_finite = true;
        }
        if expected.starts_with("COMPLEX_FINITE_") {
            saw_complex = true;
        }
        if skips_host_oracle(&case.function) {
            saw_mapped_skip = true;
            assert!(
                case.note
                    .as_deref()
                    .is_some_and(|note| note.contains("mapping") || note.contains("complex ABI")),
                "case {} must explain skipped host oracle",
                case.name
            );
        }

        for forbidden in ["0x", "errno_ptr", "timestamp", "stderr", "process_counter"] {
            assert!(
                !case.expected_output.contains(forbidden),
                "case {} leaks ambient token {forbidden}",
                case.name
            );
        }
    }

    assert!(saw_domain, "wave must include at least one domain class");
    assert!(saw_signed_finite, "wave must include signed finite classes");
    assert!(saw_complex, "wave must include complex output classes");
    assert!(
        saw_mapped_skip,
        "wave must include explicit mapped host-skip cases"
    );
}

#[test]
fn math_finite_special_wave03_spec_reference_names_required_surfaces() {
    let fixture = load_fixture();
    for token in THIRD_WAVE_SYMBOLS {
        assert!(
            fixture.spec_reference.contains(token),
            "spec reference must mention {token}"
        );
    }
}

#[test]
fn math_finite_special_wave03_executes_via_isolated_harness() {
    let fixture = load_fixture();
    for case in &fixture.cases {
        let run = execute_case_via_harness(&case.function, &case.inputs, &case.mode)
            .unwrap_or_else(|err| panic!("{} failed isolated harness execution: {err}", case.name));
        assert_eq!(run.impl_output, case.expected_output, "impl log mismatch");
        assert!(run.host_parity, "case {} must preserve parity", case.name);

        if skips_host_oracle(&case.function) {
            assert_eq!(
                run.host_output, "SKIP",
                "mapped/static symbol {} should not overclaim host output",
                case.function
            );
            assert!(
                run.note
                    .as_deref()
                    .is_some_and(|note| note.contains("mapping") || note.contains("complex ABI")),
                "mapped/static symbol {} should explain host skip",
                case.function
            );
        } else {
            assert_ne!(
                run.host_output, "SKIP",
                "direct finite alias {} should compare against libm class",
                case.function
            );
            assert_eq!(
                run.host_output, run.impl_output,
                "direct finite alias {} should match libm class",
                case.function
            );
            assert!(
                run.note.is_none(),
                "direct finite alias {} should not emit notes",
                case.function
            );
        }
    }
}
