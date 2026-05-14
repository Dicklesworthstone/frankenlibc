//! Deterministic wave-06 stdio/libio fixture tests.
//!
//! Run: cargo test -p frankenlibc-harness --test stdio_libio_wave06_conformance_test

use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const FIRST_WAVE_SYMBOLS: &[&str] = &[
    "open_memstream",
    "pclose",
    "popen",
    "putc",
    "putc_unlocked",
    "putchar",
    "putchar_unlocked",
    "puts",
    "putw",
    "remove",
    "rewind",
    "scanf",
];

const REQUIRED_LOG_FIELDS: &[&str] = &["symbol", "mode", "expected", "actual", "failure_signature"];
const AMBIENT_POLICY: &str =
    "forbid_ambient_stream_fd_path_address_stdout_stdin_or_uncontrolled_input_capture";

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().ok_or_else(|| {
        format!(
            "harness manifest directory has no parent: {}",
            manifest_dir.display()
        )
    })?;
    workspace_root
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "workspace root has no repository parent: {}",
                workspace_root.display()
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
    let path = repo_root()?.join("tests/conformance/fixtures/stdio_libio_wave06.json");
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
}

fn load_json_artifact(relative_path: &str) -> Result<Value, String> {
    let path = repo_root()?.join(relative_path);
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
}

fn json_array_has_str(value: &Value, expected: &str) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(expected)))
}

fn find_symbol_row<'a>(coverage: &'a Value, symbol: &str) -> Result<&'a Value, String> {
    coverage["symbols"]
        .as_array()
        .ok_or_else(|| String::from("coverage symbols must be an array"))?
        .iter()
        .find(|row| row["symbol"].as_str() == Some(symbol))
        .ok_or_else(|| format!("missing coverage row for {symbol}"))
}

fn find_campaign_row<'a>(prioritizer: &'a Value, campaign_id: &str) -> Result<&'a Value, String> {
    prioritizer["campaigns"]
        .as_array()
        .ok_or_else(|| String::from("prioritizer campaigns must be an array"))?
        .iter()
        .find(|row| row["campaign_id"].as_str() == Some(campaign_id))
        .ok_or_else(|| format!("missing prioritizer campaign {campaign_id}"))
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
fn stdio_libio_wave06_fixture_exists_and_names_campaign() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/stdio_libio_wave06.json");
    assert!(path.exists(), "stdio_libio_wave06.json fixture must exist");

    let fixture = load_fixture()?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "stdio/libio");
    assert_eq!(fixture.campaign.bead, "bd-gmbqy.2");
    assert_eq!(fixture.campaign.campaign_id, "fcq-stdio-libio");
    assert_eq!(
        fixture.campaign.wave_id,
        "wave-06-stdio-libio-memstream-process-public-writers"
    );
    assert_eq!(
        fixture.campaign.source_artifact,
        "tests/conformance/fixture_coverage_prioritizer.v1.json"
    );
    assert_eq!(fixture.campaign.ambient_state_policy, AMBIENT_POLICY);
    assert!(
        fixture
            .description
            .contains("without recording stream addresses")
            && fixture.description.contains("file descriptors")
            && fixture.description.contains("filesystem paths")
            && fixture.description.contains("stdout bytes")
            && fixture.description.contains("stderr bytes")
            && fixture.description.contains("stdin payloads")
            && fixture.description.contains("process ids")
            && fixture.description.contains("wait counters")
            && fixture.description.contains("host FILE internals"),
        "fixture description must reject ambient stdio/libio metadata capture"
    );
    Ok(())
}

#[test]
fn stdio_libio_wave06_covers_first_wave_in_both_modes() -> Result<(), String> {
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
        "wave-06 fixture should not leave residual symbols"
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
fn stdio_libio_wave06_logs_without_ambient_leaks() -> Result<(), String> {
    let fixture = load_fixture()?;
    assert_eq!(
        fixture.structured_log_fields, REQUIRED_LOG_FIELDS,
        "structured log field contract drifted"
    );

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "case name must not be empty");
        assert!(!case.spec_section.is_empty(), "case spec_section missing");
        assert!(
            matches!(case.expected_errno, 0 | 14),
            "case {} exposes unexpected errno class {}",
            case.name,
            case.expected_errno
        );
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
            inputs["symbol"].as_str(),
            Some(case.function.as_str()),
            "case {} inputs.symbol must match function",
            case.name
        );
        assert_eq!(
            inputs["ambient_state_policy"].as_str(),
            Some(AMBIENT_POLICY),
            "case {} ambient-state policy drifted",
            case.name
        );

        for field in REQUIRED_LOG_FIELDS {
            assert!(
                case.expected_output.contains(&format!("{field}=")),
                "case {} expected_output missing {field}",
                case.name
            );
        }
        for forbidden in [
            "0x",
            "fd=",
            "/tmp",
            "FILE_PTR",
            "address",
            "stream=",
            "path=",
            "stdout=",
            "stderr=",
            "stdin=",
            "payload=",
            "pid=",
            "counter=",
            "thread=",
            "timestamp",
        ] {
            assert!(
                !case.expected_output.contains(forbidden),
                "case {} expected_output leaks ambient stdio detail {forbidden}",
                case.name
            );
        }
    }
    Ok(())
}

#[test]
fn stdio_libio_wave06_spec_reference_names_required_surfaces() -> Result<(), String> {
    let fixture = load_fixture()?;
    for symbol in FIRST_WAVE_SYMBOLS {
        assert!(
            fixture.spec_reference.contains(symbol),
            "spec reference must mention {symbol}"
        );
    }
    Ok(())
}

#[test]
fn stdio_libio_wave06_coverage_artifacts_bind_first_wave() -> Result<(), String> {
    let coverage = load_json_artifact("tests/conformance/symbol_fixture_coverage.v1.json")?;
    for symbol in FIRST_WAVE_SYMBOLS {
        let row = find_symbol_row(&coverage, symbol)?;
        assert_eq!(
            row["covered"].as_bool(),
            Some(true),
            "{symbol} must be marked covered"
        );
        assert_eq!(
            row["fixture_case_count"].as_u64(),
            Some(2),
            "{symbol} must have strict+hardened fixture rows"
        );
        assert!(
            json_array_has_str(&row["fixture_files"], "stdio_libio_wave06.json"),
            "{symbol} coverage must cite stdio_libio_wave06.json"
        );
        assert!(
            json_array_has_str(&row["fixture_modes"], "strict")
                && json_array_has_str(&row["fixture_modes"], "hardened"),
            "{symbol} coverage must record both runtime modes"
        );
    }

    let prioritizer = load_json_artifact("tests/conformance/fixture_coverage_prioritizer.v1.json")?;
    let campaign = find_campaign_row(&prioritizer, "fcq-stdio-libio")?;
    assert!(
        campaign["current_coverage_pct"].as_f64().unwrap_or(0.0) >= 88.0,
        "stdio/libio coverage percent must include wave-06 fixture rows"
    );
    assert!(
        campaign["target_covered"].as_u64().unwrap_or(0) >= 113,
        "stdio/libio target_covered must include the 12 wave-06 symbols"
    );
    assert!(
        campaign["target_uncovered"].as_u64().unwrap_or(u64::MAX) <= 13,
        "stdio/libio target_uncovered must shrink after wave-06 coverage"
    );

    let next_wave: BTreeSet<_> = campaign["first_wave_symbols"]
        .as_array()
        .ok_or_else(|| String::from("campaign first_wave_symbols must be an array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for symbol in FIRST_WAVE_SYMBOLS {
        assert!(
            !next_wave.contains(symbol),
            "covered symbol {symbol} must not remain in the next prioritizer wave"
        );
    }
    Ok(())
}

#[test]
fn stdio_libio_wave06_executes_via_isolated_harness() -> Result<(), String> {
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
                    "stdio/libio wave-06 case {} ({}) failed via harness: {err}",
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
            "wave-06 fixture should not use ambient host outputs for {}",
            case.name
        );
        assert!(
            result.host_parity,
            "case {} should preserve classified parity",
            case.name
        );
        assert!(
            result.note.is_none(),
            "case {} should not emit notes",
            case.name
        );
    }
    Ok(())
}
