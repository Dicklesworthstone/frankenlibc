//! DNS resolver conformance test suite.
//!
//! Validates DNS resolver functions: resolv.conf parsing, DNS header encoding,
//! hosts file lookup, getaddrinfo, gethostbyname.
//! Run: cargo test -p frankenlibc-harness --test resolver_conformance_test

use serde::Deserialize;
use std::path::{Path, PathBuf};

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
