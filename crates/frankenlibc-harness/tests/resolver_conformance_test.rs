//! DNS resolver conformance test suite.
//!
//! Validates DNS resolver functions: resolv.conf parsing, DNS header encoding,
//! hosts file lookup, getaddrinfo, gethostbyname.
//! Run: cargo test -p frankenlibc-harness --test resolver_conformance_test

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
    #[serde(default)]
    captured_at: String,
    #[serde(default)]
    description: String,
    cases: Vec<FixtureCase>,
    #[serde(default)]
    dns_protocol: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FixtureCase {
    name: String,
    function: String,
    spec_section: String,
    inputs: serde_json::Value,
    #[serde(default)]
    expected_output: Option<serde_json::Value>,
    #[serde(default)]
    expected_errno: i32,
    mode: String,
    #[serde(default)]
    note: String,
}

fn load_fixture(name: &str) -> FixtureFile {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
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
fn resolver_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/resolver.json");
    assert!(path.exists(), "resolver.json fixture must exist");
}

#[test]
fn resolver_fixture_valid_schema() {
    let fixture = load_fixture("resolver");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "resolv/dns");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
        assert!(
            case.expected_output.is_some(),
            "Case {} must have expected_output",
            case.name
        );
    }
}

#[test]
fn resolver_covers_resolv_conf() {
    let fixture = load_fixture("resolver");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("resolv_conf"))
            .count()
            >= 3,
        "resolv.conf parsing needs at least 3 test cases"
    );
}

#[test]
fn resolver_covers_dns_header() {
    let fixture = load_fixture("resolver");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("dns_header")),
        "Missing test coverage for DNS header"
    );
}

#[test]
fn resolver_covers_domain_name_encoding() {
    let fixture = load_fixture("resolver");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("dns_encode"))
            .count()
            >= 2,
        "Domain name encoding needs at least 2 test cases"
    );
}

#[test]
fn resolver_covers_hosts_lookup() {
    let fixture = load_fixture("resolver");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("hosts_lookup"))
            .count()
            >= 3,
        "hosts file lookup needs at least 3 test cases"
    );
}

#[test]
fn resolver_covers_getaddrinfo() {
    let fixture = load_fixture("resolver");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("getaddrinfo"))
            .count()
            >= 3,
        "getaddrinfo needs at least 3 test cases"
    );
}

#[test]
fn resolver_covers_gethostbyname() {
    let fixture = load_fixture("resolver");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("gethostbyname")),
        "Missing test coverage for gethostbyname"
    );
}

#[test]
fn resolver_modes_valid() {
    let fixture = load_fixture("resolver");
    for case in &fixture.cases {
        assert!(
            case.mode == "both" || case.mode == "strict" || case.mode == "hardened",
            "Case {} has invalid mode: {}",
            case.name,
            case.mode
        );
    }
}

#[test]
fn resolver_covers_both_modes() {
    let fixture = load_fixture("resolver");
    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");
    assert!(has_strict, "resolver must have strict mode test cases");
    assert!(has_hardened, "resolver must have hardened mode test cases");
}

#[test]
fn resolver_case_count_stable() {
    let fixture = load_fixture("resolver");
    assert!(
        fixture.cases.len() >= 15,
        "resolver fixture has {} cases, expected at least 15",
        fixture.cases.len()
    );
    eprintln!("resolver fixture has {} test cases", fixture.cases.len());
}

#[test]
fn resolver_has_spec_references() {
    let fixture = load_fixture("resolver");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("resolver")
                || case.spec_section.contains("RFC")
                || case.spec_section.contains("hosts")
                || case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference resolver(5), RFC, /etc/hosts, or POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn resolver_has_dns_protocol_metadata() {
    let fixture = load_fixture("resolver");
    assert!(
        fixture.dns_protocol.is_some(),
        "resolver fixture should have dns_protocol metadata"
    );
}

#[test]
fn resolver_fixture_executes_via_harness() {
    let fixture = load_fixture("resolver");

    for case in &fixture.cases {
        let modes = if case.mode == "both" {
            vec!["strict", "hardened"]
        } else {
            vec![case.mode.as_str()]
        };

        for mode in modes {
            let result = execute_case_via_harness(&case.function, &case.inputs, mode)
                .unwrap_or_else(|err| {
                    panic!(
                        "resolver case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                });

            let expected = case
                .expected_output
                .as_ref()
                .unwrap_or_else(|| panic!("resolver case {} missing expected_output", case.name));

            match expected {
                serde_json::Value::String(expected_text) => {
                    assert_eq!(
                        result.impl_output, *expected_text,
                        "resolver case {} ({mode}) impl_output mismatch",
                        case.name
                    );
                }
                _ => {
                    let actual: serde_json::Value = serde_json::from_str(&result.impl_output)
                        .unwrap_or_else(|err| {
                            panic!(
                                "resolver case {} ({mode}) produced non-JSON output {}: {err}",
                                case.name, result.impl_output
                            )
                        });
                    assert_eq!(
                        actual, *expected,
                        "resolver case {} ({mode}) impl_output mismatch",
                        case.name
                    );
                }
            }

            assert!(
                result.host_parity,
                "resolver case {} ({mode}) lost host parity: {:?}",
                case.name, result
            );
        }
    }
}
