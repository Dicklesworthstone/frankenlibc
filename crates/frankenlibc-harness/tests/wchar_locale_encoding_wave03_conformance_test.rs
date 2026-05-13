//! Deterministic wave-03 wchar/locale classification fixture tests.
//!
//! Run: cargo test -p frankenlibc-harness --test wchar_locale_encoding_wave03_conformance_test

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const FIRST_WAVE_SYMBOLS: &[&str] = &[
    "__iswlower_l",
    "__iswprint_l",
    "__iswpunct_l",
    "__iswspace_l",
    "__iswupper_l",
    "__iswxdigit_l",
    "__toascii_l",
    "__tolower_l",
    "__toupper_l",
    "__towctrans_l",
    "__towlower_l",
    "__towupper_l",
];

const REQUIRED_LOG_FIELDS: &[&str] = &["symbol", "mode", "expected", "actual", "failure_signature"];
const AMBIENT_POLICY: &str =
    "forbid_raw_locale_pointer_wide_buffer_file_path_fd_stdout_stderr_pid_or_wall_clock_capture";

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = manifest_dir.parent().ok_or_else(|| {
        format!(
            "harness manifest directory has no parent: {}",
            manifest_dir.display()
        )
    })?;
    crate_dir.parent().map(Path::to_path_buf).ok_or_else(|| {
        format!(
            "harness crate directory has no parent: {}",
            crate_dir.display()
        )
    })
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

fn load_fixture() -> Result<FixtureFile, String> {
    let path = repo_root()?.join("tests/conformance/fixtures/wchar_locale_encoding_wave03.json");
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
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

#[test]
fn wchar_locale_encoding_wave03_fixture_exists_and_names_campaign() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/wchar_locale_encoding_wave03.json");
    assert!(
        path.exists(),
        "wchar_locale_encoding_wave03.json fixture must exist"
    );

    let fixture = load_fixture()?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "wchar/locale-encoding");
    assert_eq!(fixture.campaign.bead, "bd-gmbqy.5");
    assert_eq!(fixture.campaign.campaign_id, "fcq-wchar-locale-encoding");
    assert_eq!(
        fixture.campaign.wave_id,
        "wave-03-wchar-locale-classification"
    );
    assert_eq!(
        fixture.campaign.source_artifact,
        "tests/conformance/fixture_coverage_prioritizer.v1.json"
    );
    assert_eq!(fixture.campaign.ambient_state_policy, AMBIENT_POLICY);
    assert!(
        fixture
            .description
            .contains("C/POSIX locale classification")
            && fixture.description.contains("case-mapping")
            && fixture.description.contains("invalid-codepoint")
            && fixture.description.contains("high-bit")
            && fixture.description.contains("invalid descriptor")
            && fixture.description.contains("raw locale handles")
            && fixture.description.contains("wide-buffer addresses")
            && fixture.description.contains("FILE pointers")
            && fixture.description.contains("filesystem paths")
            && fixture.description.contains("stdout bytes")
            && fixture.description.contains("stderr bytes")
            && fixture.description.contains("fd numbers")
            && fixture.description.contains("process ids")
            && fixture.description.contains("wall-clock timing"),
        "fixture description must reject ambient wchar/locale metadata capture"
    );
    Ok(())
}

#[test]
fn wchar_locale_encoding_wave03_covers_first_wave_in_both_modes() -> Result<(), String> {
    let fixture = load_fixture()?;
    let expected: BTreeSet<_> = FIRST_WAVE_SYMBOLS.iter().copied().collect();
    let declared: BTreeSet<_> = fixture
        .campaign
        .first_wave_symbols
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(declared, expected, "campaign first-wave symbol drift");
    assert!(
        fixture.campaign.residual_symbols.is_empty(),
        "wchar/locale wave should not leave residual symbols"
    );

    let mut modes_by_symbol: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for case in &fixture.cases {
        modes_by_symbol
            .entry(case.function.as_str())
            .or_default()
            .insert(case.mode.as_str());
    }

    for symbol in FIRST_WAVE_SYMBOLS {
        let modes = modes_by_symbol
            .get(symbol)
            .ok_or_else(|| format!("missing fixture cases for {symbol}"))?;
        assert!(modes.contains("strict"), "missing strict case for {symbol}");
        assert!(
            modes.contains("hardened"),
            "missing hardened case for {symbol}"
        );
    }
    Ok(())
}

#[test]
fn wchar_locale_encoding_wave03_logs_without_ambient_leaks() -> Result<(), String> {
    let fixture = load_fixture()?;
    assert_eq!(
        fixture.structured_log_fields, REQUIRED_LOG_FIELDS,
        "structured log field contract drifted"
    );

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "case name must not be empty");
        assert!(!case.spec_section.is_empty(), "case spec_section missing");
        assert_eq!(case.expected_errno, 0, "fixture should not expose errno");
        assert!(
            case.mode == "strict" || case.mode == "hardened",
            "case {} has unsupported mode {}",
            case.name,
            case.mode
        );

        let inputs = case
            .inputs
            .as_object()
            .ok_or_else(|| format!("case {} inputs must be an object", case.name))?;
        for field in [
            "symbol",
            "scenario",
            "expected",
            "oracle_source",
            "ambient_state_policy",
        ] {
            assert!(
                inputs
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .is_some(),
                "case {} missing string inputs.{field}",
                case.name
            );
        }
        assert_eq!(
            inputs.get("symbol").and_then(serde_json::Value::as_str),
            Some(case.function.as_str()),
            "case {} inputs.symbol must match function",
            case.name
        );
        assert_eq!(
            inputs
                .get("ambient_state_policy")
                .and_then(serde_json::Value::as_str),
            Some(AMBIENT_POLICY),
            "case {} ambient-state policy drifted",
            case.name
        );

        for field_prefix in [
            "symbol=",
            "mode=",
            "expected=",
            "actual=",
            "failure_signature=",
        ] {
            assert!(
                case.expected_output.contains(field_prefix),
                "case {} expected_output missing {}",
                case.name,
                field_prefix.trim_end_matches('=')
            );
        }
        for forbidden in [
            "0x",
            "/tmp/",
            "/dev/",
            "pid=",
            "fd=",
            "stdout=",
            "stderr=",
            "FILE*",
            "locale=",
            "wide_buffer=",
            "argv=",
            "envp=",
            "elapsed",
            "timestamp",
        ] {
            assert!(
                !case.expected_output.contains(forbidden),
                "case {} leaked ambient token {forbidden}",
                case.name
            );
        }
    }
    Ok(())
}

#[test]
fn wchar_locale_encoding_wave03_spec_reference_names_required_surfaces() -> Result<(), String> {
    let fixture = load_fixture()?;
    for symbol in FIRST_WAVE_SYMBOLS {
        assert!(
            fixture.spec_reference.contains(symbol),
            "spec reference missing {symbol}"
        );
    }
    assert!(
        fixture.spec_reference.contains("C/POSIX")
            && fixture.spec_reference.contains("wide-character")
            && fixture.spec_reference.contains("locale-sensitive")
            && fixture.spec_reference.contains("classification")
            && fixture.spec_reference.contains("case-mapping"),
        "spec reference must name C/POSIX wide-character locale classification and case-mapping semantics"
    );
    Ok(())
}

#[test]
fn wchar_locale_encoding_wave03_names_edge_rows() -> Result<(), String> {
    let fixture = load_fixture()?;
    let scenarios: BTreeSet<_> = fixture
        .cases
        .iter()
        .filter_map(|case| {
            case.inputs
                .get("scenario")
                .and_then(serde_json::Value::as_str)
        })
        .collect();
    assert!(
        scenarios.contains("c_locale_print_invalid_codepoint_without_locale_pointer_capture"),
        "missing invalid-codepoint classification row"
    );
    assert!(
        scenarios.contains("c_locale_toascii_masks_high_bits_without_locale_pointer_capture"),
        "missing high-bit toascii row"
    );
    assert!(
        scenarios.contains("c_locale_towctrans_invalid_descriptor_noop"),
        "missing invalid descriptor case-mapping row"
    );
    Ok(())
}

#[test]
fn wchar_locale_encoding_wave03_executes_via_isolated_harness() -> Result<(), String> {
    let fixture = load_fixture()?;
    assert_eq!(
        fixture.cases.len(),
        FIRST_WAVE_SYMBOLS.len() * 2,
        "fixture should include strict+hardened rows for every first-wave symbol"
    );

    for case in &fixture.cases {
        let result =
            execute_case_via_harness(&case.function, &case.inputs, &case.mode).map_err(|err| {
                format!(
                    "wchar/locale wave-03 case {} ({}) failed via harness: {err}",
                    case.name, case.mode
                )
            })?;
        assert_eq!(
            result.impl_output, case.expected_output,
            "fixture expected_output mismatch for {} ({})",
            case.name, case.mode
        );
        assert_eq!(
            result.host_output, "SKIP",
            "wave-03 fixture should not use ambient host outputs for {}",
            case.name
        );
        assert!(result.host_parity, "fixture executor reported failure");
        assert!(result.note.is_none(), "unexpected fixture note drift");
    }
    Ok(())
}
