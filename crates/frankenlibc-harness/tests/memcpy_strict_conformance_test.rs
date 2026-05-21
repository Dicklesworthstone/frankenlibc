//! memcpy strict conformance test suite.
//!
//! Validates POSIX memcpy function with various sizes and edge cases.
//! Run: cargo test -p frankenlibc-harness --test memcpy_strict_conformance_test

use serde::Deserialize;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest_dir
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", manifest_dir.display()))?;
    let repo_root = crates_dir
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", crates_dir.display()))?;
    Ok(repo_root.to_path_buf())
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FixtureFile {
    version: String,
    family: String,
    #[serde(default)]
    captured_at: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    spec_reference: String,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FixtureCase {
    name: String,
    function: String,
    spec_section: String,
    inputs: serde_json::Value,
    #[serde(default)]
    expected_output: Option<String>,
    #[serde(default)]
    expected_errno: i32,
    mode: String,
    #[serde(default)]
    note: String,
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
    impl_output: String,
    host_parity: bool,
}

fn load_fixture(name: &str) -> Result<FixtureFile, String> {
    let path = repo_root()?.join(format!("tests/conformance/fixtures/{name}.json"));
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
}

fn execute_case_via_harness(
    function: &str,
    inputs: &Value,
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

fn case_by_name<'a>(fixture: &'a FixtureFile, name: &str) -> Result<&'a FixtureCase, String> {
    fixture
        .cases
        .iter()
        .find(|case| case.name == name)
        .ok_or_else(|| format!("missing fixture case {name}"))
}

fn inputs_object(case: &FixtureCase) -> Result<Map<String, Value>, String> {
    case.inputs
        .as_object()
        .cloned()
        .ok_or_else(|| format!("case {} inputs must be a JSON object", case.name))
}

fn input_usize(case: &FixtureCase, field: &str) -> Result<usize, String> {
    let raw = case
        .inputs
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("case {} missing numeric input `{field}`", case.name))?;
    usize::try_from(raw).map_err(|_| format!("case {} input `{field}` exceeds usize", case.name))
}

fn input_bytes(case: &FixtureCase, field: &str) -> Result<Vec<u8>, String> {
    let value = case
        .inputs
        .get(field)
        .ok_or_else(|| format!("case {} missing byte-array input `{field}`", case.name))?;
    serde_json::from_value(value.clone())
        .map_err(|err| format!("case {} invalid byte-array `{field}`: {err}", case.name))
}

fn parse_output_bytes(case_name: &str, output: &str) -> Result<Vec<u8>, String> {
    serde_json::from_str(output)
        .map_err(|err| format!("case {case_name} produced non-byte-array output {output:?}: {err}"))
}

#[test]
fn memcpy_strict_fixture_exists() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/memcpy_strict.json");
    assert!(path.exists(), "memcpy_strict.json fixture must exist");
    Ok(())
}

#[test]
fn memcpy_strict_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("memcpy_strict")?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "string/memcpy");
    assert!(
        !fixture.description.is_empty(),
        "fixture should describe its scope"
    );
    assert!(
        !fixture.spec_reference.is_empty(),
        "fixture should include top-level spec reference"
    );
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
        assert!(
            !case.spec_section.is_empty(),
            "Case {} must include spec_section",
            case.name
        );
        assert!(
            case.expected_output.is_some(),
            "Case {} must have expected_output",
            case.name
        );
    }
    Ok(())
}

#[test]
fn memcpy_strict_covers_full_copy() -> Result<(), String> {
    let fixture = load_fixture("memcpy_strict")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("full")),
        "Missing test coverage for full buffer copy"
    );
    Ok(())
}

#[test]
fn memcpy_strict_covers_partial_copy() -> Result<(), String> {
    let fixture = load_fixture("memcpy_strict")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("partial")),
        "Missing test coverage for partial buffer copy"
    );
    Ok(())
}

#[test]
fn memcpy_strict_covers_zero_size() -> Result<(), String> {
    let fixture = load_fixture("memcpy_strict")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("zero")),
        "Missing test coverage for zero-size copy"
    );
    Ok(())
}

#[test]
fn memcpy_strict_covers_single_byte() -> Result<(), String> {
    let fixture = load_fixture("memcpy_strict")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("single")),
        "Missing test coverage for single-byte copy"
    );
    Ok(())
}

#[test]
fn memcpy_strict_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("memcpy_strict")?;
    for case in &fixture.cases {
        assert!(
            matches!(case.mode.as_str(), "both" | "strict" | "hardened"),
            "Case {} has invalid mode: {}",
            case.name,
            case.mode
        );
    }
    Ok(())
}

#[test]
fn memcpy_strict_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("memcpy_strict")?;
    assert!(
        fixture.cases.len() >= 3,
        "memcpy_strict fixture has {} cases, expected at least 3",
        fixture.cases.len()
    );
    eprintln!(
        "memcpy_strict fixture has {} test cases",
        fixture.cases.len()
    );
    Ok(())
}

#[test]
fn memcpy_strict_has_posix_references() -> Result<(), String> {
    let fixture = load_fixture("memcpy_strict")?;
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference POSIX: {}",
            case.name,
            case.spec_section
        );
    }
    Ok(())
}

#[test]
fn memcpy_strict_error_codes_valid() -> Result<(), String> {
    let fixture = load_fixture("memcpy_strict")?;

    // memcpy doesn't set errno
    for case in &fixture.cases {
        assert_eq!(
            case.expected_errno, 0,
            "Case {} has unexpected errno {} (memcpy doesn't set errno)",
            case.name, case.expected_errno
        );
    }
    Ok(())
}

#[test]
fn memcpy_strict_fixture_executes_via_isolated_harness() -> Result<(), String> {
    let fixture = load_fixture("memcpy_strict")?;

    for case in fixture.cases {
        let expected_output = case
            .expected_output
            .as_deref()
            .ok_or_else(|| format!("case {} missing expected_output", case.name))?;
        let modes: &[&str] = if case.mode.eq_ignore_ascii_case("both") {
            &["strict", "hardened"]
        } else {
            &[case.mode.as_str()]
        };

        for mode in modes {
            let result =
                execute_case_via_harness(&case.function, &case.inputs, mode).map_err(|err| {
                    format!(
                        "fixture case {} ({mode}) failed to execute through harness: {err}",
                        case.name
                    )
                })?;
            assert_eq!(
                result.impl_output, expected_output,
                "fixture expected_output mismatch for {} ({mode})",
                case.name
            );
            assert!(
                result.host_parity,
                "executor reported parity failure for {} ({mode})",
                case.name
            );
        }
    }
    Ok(())
}

#[test]
fn memcpy_strict_metamorphic_relations_hold_without_golden_outputs() -> Result<(), String> {
    let fixture = load_fixture("memcpy_strict")?;

    let full = case_by_name(&fixture, "copy_full_8")?;
    assert_eq!(
        input_usize(full, "n")?,
        input_bytes(full, "src")?.len(),
        "full-copy relation requires n to match src length"
    );
    let base = execute_case_via_harness(&full.function, &full.inputs, "strict")?;
    let base_bytes = parse_output_bytes(&full.name, &base.impl_output)?;

    let suffix = vec![251_u8, 0, 17];
    let mut extended_src = input_bytes(full, "src")?;
    extended_src.extend_from_slice(&suffix);
    let mut extended_inputs = inputs_object(full)?;
    extended_inputs.insert(String::from("src"), serde_json::json!(extended_src));
    extended_inputs.insert(
        String::from("n"),
        serde_json::json!(input_usize(full, "n")? + suffix.len()),
    );
    extended_inputs.insert(
        String::from("dst_len"),
        serde_json::json!(input_usize(full, "dst_len")? + suffix.len()),
    );
    let extended_input = Value::Object(extended_inputs);
    let extended = execute_case_via_harness(&full.function, &extended_input, "strict")?;
    let extended_bytes = parse_output_bytes("copy_full_8_extended", &extended.impl_output)?;
    assert_eq!(
        extended_bytes
            .get(..base_bytes.len())
            .ok_or_else(|| String::from("extended memcpy output shorter than base output"))?,
        base_bytes.as_slice(),
        "extending src/n/dst_len must preserve the original full-copy prefix"
    );
    assert_eq!(
        extended_bytes
            .get(base_bytes.len()..)
            .ok_or_else(|| String::from("extended memcpy output missing appended suffix"))?,
        suffix.as_slice(),
        "extended full-copy output suffix must come from the appended input suffix"
    );
    assert!(
        base.host_parity && extended.host_parity,
        "metamorphic relation must run against host-parity executions"
    );

    let zero = case_by_name(&fixture, "copy_zero")?;
    assert_eq!(
        input_usize(zero, "n")?,
        0,
        "zero-copy relation requires n=0"
    );
    let zero_base = execute_case_via_harness(&zero.function, &zero.inputs, "strict")?;
    let mut zero_mutated_inputs = inputs_object(zero)?;
    zero_mutated_inputs.insert(String::from("src"), serde_json::json!([9, 8, 7, 6, 5, 4]));
    let zero_mutated_input = Value::Object(zero_mutated_inputs);
    let zero_mutated = execute_case_via_harness(&zero.function, &zero_mutated_input, "strict")?;
    assert_eq!(
        parse_output_bytes(&zero.name, &zero_base.impl_output)?,
        parse_output_bytes("copy_zero_mutated_source", &zero_mutated.impl_output)?,
        "n=0 memcpy output must be invariant under source-byte changes"
    );
    assert!(
        zero_base.host_parity && zero_mutated.host_parity,
        "zero-copy relation must run against host-parity executions"
    );

    Ok(())
}
