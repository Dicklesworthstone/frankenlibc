//! ELF loader conformance test suite.
//!
//! Validates ELF64 loader fixtures plus a differential harness against `readelf`
//! for real system binaries.
//! Run: cargo test -p frankenlibc-harness --test elf_loader_conformance_test

use frankenlibc_core::elf::{Elf64Header, ElfClass, ElfData, ElfLoader, ElfMachine, ElfType};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

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
    binary_fixtures: Vec<BinaryFixture>,
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
    expected_hex: Option<String>,
    #[serde(default)]
    expected_errno: i32,
    mode: String,
    #[serde(default)]
    note: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct BinaryFixture {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
    assertions: BinaryFixtureAssertions,
}

impl BinaryFixture {
    fn candidate_paths(&self) -> Vec<&str> {
        let mut candidates: Vec<&str> = self.paths.iter().map(String::as_str).collect();
        if let Some(path) = self.path.as_deref() {
            candidates.push(path);
        }
        candidates
    }
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct BinaryFixtureAssertions {
    #[serde(default)]
    class: Option<String>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    machine: Option<String>,
    #[serde(rename = "type", default)]
    object_type: Option<String>,
    #[serde(default)]
    min_program_headers: Option<usize>,
    #[serde(default)]
    min_load_segments: Option<usize>,
    #[serde(default)]
    require_dynamic_segment: Option<bool>,
    #[serde(default)]
    expect_relro: Option<bool>,
    #[serde(default)]
    min_dynamic_symbols: Option<usize>,
    #[serde(default)]
    required_symbols: Vec<String>,
}

#[derive(Debug)]
struct ReadElfSnapshot {
    header: ReadElfHeaderSummary,
    load_segments: usize,
    has_dynamic_segment: bool,
    has_relro_segment: bool,
    dynsym_count: usize,
    symbol_names: BTreeSet<String>,
}

#[derive(Debug)]
struct ReadElfHeaderSummary {
    class: String,
    data: String,
    machine: String,
    object_type: String,
    program_headers: usize,
}

fn load_fixture(name: &str) -> FixtureFile {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
    let content = fs::read_to_string(&path)
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
    host_output: String,
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

fn expected_output_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

fn resolve_binary_fixture_path(fixture: &BinaryFixture) -> Option<PathBuf> {
    fixture
        .candidate_paths()
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
}

fn run_readelf(path: &Path, args: &[&str]) -> Option<String> {
    match Command::new("readelf").args(args).arg(path).output() {
        Ok(output) => {
            assert!(
                output.status.success(),
                "readelf {:?} failed for {}:\n{}",
                args,
                path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
            Some(String::from_utf8_lossy(&output.stdout).into_owned())
        }
        Err(err) if err.kind() == ErrorKind::NotFound => None,
        Err(err) => panic!(
            "failed to execute readelf {:?} for {}: {}",
            args,
            path.display(),
            err
        ),
    }
}

fn build_readelf_snapshot(path: &Path) -> Option<ReadElfSnapshot> {
    let header_output = run_readelf(path, &["-h"])?;
    let program_output = run_readelf(path, &["-l"])?;
    let dynsym_output = run_readelf(path, &["--dyn-syms", "-W"])?;
    let (load_segments, has_dynamic_segment, has_relro_segment) =
        parse_program_header_summary(&program_output);
    let (dynsym_count, symbol_names) = parse_dynsym_summary(&dynsym_output);
    Some(ReadElfSnapshot {
        header: parse_readelf_header(&header_output),
        load_segments,
        has_dynamic_segment,
        has_relro_segment,
        dynsym_count,
        symbol_names,
    })
}

fn parse_readelf_header(output: &str) -> ReadElfHeaderSummary {
    ReadElfHeaderSummary {
        class: canonicalize_readelf_class(&extract_readelf_field(output, "Class:")),
        data: canonicalize_readelf_data(&extract_readelf_field(output, "Data:")),
        machine: canonicalize_readelf_machine(&extract_readelf_field(output, "Machine:")),
        object_type: canonicalize_readelf_type(&extract_readelf_field(output, "Type:")),
        program_headers: extract_readelf_field(output, "Number of program headers:")
            .parse::<usize>()
            .unwrap_or_else(|err| {
                panic!(
                    "failed to parse program header count from readelf output:\n{output}\nerror: {err}"
                )
            }),
    }
}

fn extract_readelf_field(output: &str, field: &str) -> String {
    output
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix(field)
                .map(str::trim)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| panic!("missing {field} in readelf output:\n{output}"))
}

fn parse_program_header_summary(output: &str) -> (usize, bool, bool) {
    let mut load_segments = 0usize;
    let mut has_dynamic_segment = false;
    let mut has_relro_segment = false;

    for line in output.lines() {
        match line.split_whitespace().next().unwrap_or_default() {
            "LOAD" => load_segments += 1,
            "DYNAMIC" => has_dynamic_segment = true,
            "GNU_RELRO" => has_relro_segment = true,
            _ => {}
        }
    }

    (load_segments, has_dynamic_segment, has_relro_segment)
}

fn parse_dynsym_summary(output: &str) -> (usize, BTreeSet<String>) {
    let count = output
        .lines()
        .find(|line| line.contains("Symbol table '.dynsym' contains"))
        .and_then(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            tokens
                .iter()
                .position(|token| *token == "contains")
                .and_then(|index| tokens.get(index + 1))
                .copied()
        })
        .unwrap_or_else(|| panic!("missing dynsym count in readelf output:\n{output}"))
        .parse::<usize>()
        .unwrap_or_else(|err| {
            panic!("failed to parse dynsym count from readelf output:\n{output}\nerror: {err}")
        });

    let mut symbol_names = BTreeSet::new();
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if !is_symbol_row(&tokens) {
            continue;
        }

        let raw_name = if tokens.last().is_some_and(|token| token.starts_with('(')) {
            tokens[tokens.len() - 2]
        } else {
            tokens[tokens.len() - 1]
        };
        let normalized = raw_name.split('@').next().unwrap_or(raw_name);
        if !normalized.is_empty() {
            symbol_names.insert(normalized.to_owned());
        }
    }

    (count, symbol_names)
}

fn is_symbol_row(tokens: &[&str]) -> bool {
    if tokens.len() < 8 {
        return false;
    }
    let Some(index_token) = tokens.first() else {
        return false;
    };
    let Some(index_text) = index_token.strip_suffix(':') else {
        return false;
    };
    index_text.bytes().all(|byte| byte.is_ascii_digit())
}

fn canonicalize_readelf_class(value: &str) -> String {
    match value {
        "ELF32" => "Elf32".to_owned(),
        "ELF64" => "Elf64".to_owned(),
        "none" => "None".to_owned(),
        other => other.to_owned(),
    }
}

fn canonicalize_readelf_data(value: &str) -> String {
    match value {
        "2's complement, little endian" => "Lsb".to_owned(),
        "2's complement, big endian" => "Msb".to_owned(),
        "none" => "None".to_owned(),
        other => other.to_owned(),
    }
}

fn canonicalize_readelf_machine(value: &str) -> String {
    match value {
        "Intel 80386" => "I386".to_owned(),
        "ARM" => "Arm".to_owned(),
        "Advanced Micro Devices X86-64" => "X86_64".to_owned(),
        "AArch64" => "Aarch64".to_owned(),
        "RISC-V" => "RiscV".to_owned(),
        "None" => "None".to_owned(),
        other => other.to_owned(),
    }
}

fn canonicalize_readelf_type(value: &str) -> String {
    match value.split_whitespace().next().unwrap_or_default() {
        "NONE" => "None".to_owned(),
        "REL" => "Rel".to_owned(),
        "EXEC" => "Exec".to_owned(),
        "DYN" => "Dyn".to_owned(),
        "CORE" => "Core".to_owned(),
        other => other.to_owned(),
    }
}

fn rust_class_name(class: ElfClass) -> &'static str {
    match class {
        ElfClass::None => "None",
        ElfClass::Elf32 => "Elf32",
        ElfClass::Elf64 => "Elf64",
    }
}

fn rust_data_name(data: ElfData) -> &'static str {
    match data {
        ElfData::None => "None",
        ElfData::Lsb => "Lsb",
        ElfData::Msb => "Msb",
    }
}

fn rust_machine_name(machine: ElfMachine) -> &'static str {
    match machine {
        ElfMachine::None => "None",
        ElfMachine::I386 => "I386",
        ElfMachine::Arm => "Arm",
        ElfMachine::X86_64 => "X86_64",
        ElfMachine::Aarch64 => "Aarch64",
        ElfMachine::RiscV => "RiscV",
        ElfMachine::Unknown(_) => "Unknown",
    }
}

fn rust_type_name(object_type: ElfType) -> &'static str {
    match object_type {
        ElfType::None => "None",
        ElfType::Rel => "Rel",
        ElfType::Exec => "Exec",
        ElfType::Dyn => "Dyn",
        ElfType::Core => "Core",
        ElfType::Unknown(_) => "Unknown",
    }
}

#[test]
fn elf_loader_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/elf_loader.json");
    assert!(path.exists(), "elf_loader.json fixture must exist");
}

#[test]
fn elf_loader_fixture_valid_schema() {
    let fixture = load_fixture("elf_loader");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "elf/loader");
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
fn elf_loader_covers_header_parsing() {
    let fixture = load_fixture("elf_loader");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("elf_magic"))
            .count()
            >= 2,
        "ELF header parsing needs at least 2 test cases (valid/invalid)"
    );
}

#[test]
fn elf_loader_covers_relocations() {
    let fixture = load_fixture("elf_loader");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.starts_with("reloc_"))
            .count()
            >= 4,
        "Relocations need at least 4 test cases"
    );
}

#[test]
fn elf_loader_covers_hash_functions() {
    let fixture = load_fixture("elf_loader");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("elf_hash")),
        "Missing test coverage for elf_hash"
    );
    assert!(
        case_names.iter().any(|n| n.contains("gnu_hash")),
        "Missing test coverage for gnu_hash"
    );
}

#[test]
fn elf_loader_covers_symbol_table() {
    let fixture = load_fixture("elf_loader");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("symbol_")).count() >= 4,
        "Symbol table needs at least 4 test cases"
    );
}

#[test]
fn elf_loader_covers_program_flags() {
    let fixture = load_fixture("elf_loader");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("program_flags"))
            .count()
            >= 2,
        "Program flags need at least 2 test cases"
    );
}

#[test]
fn elf_loader_modes_valid() {
    let fixture = load_fixture("elf_loader");
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
fn elf_loader_case_count_stable() {
    let fixture = load_fixture("elf_loader");
    assert!(
        fixture.cases.len() >= 12,
        "elf_loader fixture has {} cases, expected at least 12",
        fixture.cases.len()
    );
    eprintln!("elf_loader fixture has {} test cases", fixture.cases.len());
}

#[test]
fn elf_loader_has_spec_references() {
    let fixture = load_fixture("elf_loader");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("ELF")
                || case.spec_section.contains("x86_64")
                || case.spec_section.contains("GNU"),
            "Case {} spec_section should reference ELF, x86_64, or GNU: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn elf_loader_has_binary_fixtures() {
    let fixture = load_fixture("elf_loader");
    assert!(
        !fixture.binary_fixtures.is_empty(),
        "elf_loader fixture should have binary_fixtures for real ELF testing"
    );
}

#[test]
fn elf_loader_binary_fixture_schema_valid() {
    let fixture = load_fixture("elf_loader");
    assert!(
        !fixture.binary_fixtures.is_empty(),
        "elf_loader fixture should include binary fixtures"
    );
    for binary_fixture in &fixture.binary_fixtures {
        let candidates = binary_fixture.candidate_paths();
        assert!(
            !candidates.is_empty(),
            "binary fixture {} must include at least one candidate path",
            binary_fixture.name
        );

        let assertions = &binary_fixture.assertions;
        let has_any_assertion = assertions.class.is_some()
            || assertions.data.is_some()
            || assertions.machine.is_some()
            || assertions.object_type.is_some()
            || assertions.min_program_headers.is_some()
            || assertions.min_load_segments.is_some()
            || assertions.require_dynamic_segment.is_some()
            || assertions.expect_relro.is_some()
            || assertions.min_dynamic_symbols.is_some()
            || !assertions.required_symbols.is_empty();
        assert!(
            has_any_assertion,
            "binary fixture {} must define at least one assertion",
            binary_fixture.name
        );
    }
}

#[test]
fn elf_loader_fixture_executes_with_host_parity_via_harness_matrix() {
    let fixture = load_fixture("elf_loader");

    for case in &fixture.cases {
        let expected_output = case
            .expected_output
            .as_ref()
            .map(expected_output_text)
            .unwrap_or_else(|| panic!("case {} missing expected_output", case.name));
        let modes: &[&str] = if case.mode.eq_ignore_ascii_case("both") {
            &["strict", "hardened"]
        } else {
            &[case.mode.as_str()]
        };

        for mode in modes {
            let result = execute_case_via_harness(&case.function, &case.inputs, mode)
                .unwrap_or_else(|err| {
                    panic!(
                        "elf_loader case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                });
            assert!(
                result.host_parity,
                "elf_loader case {} ({mode}) lost host parity via harness: host_output={}, impl_output={}",
                case.name, result.host_output, result.impl_output
            );
            assert_eq!(
                result.impl_output, expected_output,
                "elf_loader case {} ({mode}) mismatched fixture output via harness",
                case.name
            );
        }
    }
}

#[test]
fn elf_loader_binary_fixtures_match_readelf() {
    let fixture = load_fixture("elf_loader");
    let mut executed = 0usize;

    for binary_fixture in &fixture.binary_fixtures {
        let Some(path) = resolve_binary_fixture_path(binary_fixture) else {
            eprintln!(
                "Skipping {}: no candidate binary found in [{}]",
                binary_fixture.name,
                binary_fixture.candidate_paths().join(", ")
            );
            continue;
        };

        let Some(reference) = build_readelf_snapshot(&path) else {
            eprintln!("Skipping {}: readelf not installed", binary_fixture.name);
            return;
        };

        executed += 1;

        let data = fs::read(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {}", path.display(), err));
        let header = Elf64Header::parse(&data).unwrap_or_else(|err| {
            panic!("failed to parse ELF header for {}: {}", path.display(), err)
        });
        let object = ElfLoader::new(0x7f00_0000_0000)
            .parse(&data)
            .unwrap_or_else(|err| {
                panic!("failed to parse {} with ElfLoader: {}", path.display(), err)
            });

        let rust_class = rust_class_name(header.class());
        let rust_data = rust_data_name(header.data());
        let rust_machine = rust_machine_name(header.e_machine);
        let rust_type = rust_type_name(header.e_type);
        let load_segments = object
            .program_headers
            .iter()
            .filter(|header| header.is_load())
            .count();
        let has_dynamic_segment = object
            .program_headers
            .iter()
            .any(|header| header.is_dynamic());
        let has_relro_segment = object
            .program_headers
            .iter()
            .any(|header| header.is_relro());

        assert_eq!(
            rust_class,
            reference.header.class,
            "{} class mismatch for {}",
            binary_fixture.name,
            path.display()
        );
        assert_eq!(
            rust_data,
            reference.header.data,
            "{} data encoding mismatch for {}",
            binary_fixture.name,
            path.display()
        );
        assert_eq!(
            rust_machine,
            reference.header.machine,
            "{} machine mismatch for {}",
            binary_fixture.name,
            path.display()
        );
        assert_eq!(
            rust_type,
            reference.header.object_type,
            "{} object type mismatch for {}",
            binary_fixture.name,
            path.display()
        );
        assert_eq!(
            usize::from(header.e_phnum),
            reference.header.program_headers,
            "{} program-header count mismatch in ELF header for {}",
            binary_fixture.name,
            path.display()
        );
        assert_eq!(
            object.program_headers.len(),
            reference.header.program_headers,
            "{} parsed program-header count mismatch for {}",
            binary_fixture.name,
            path.display()
        );
        assert_eq!(
            load_segments,
            reference.load_segments,
            "{} LOAD segment count mismatch for {}",
            binary_fixture.name,
            path.display()
        );
        assert_eq!(
            has_dynamic_segment,
            reference.has_dynamic_segment,
            "{} PT_DYNAMIC presence mismatch for {}",
            binary_fixture.name,
            path.display()
        );
        assert_eq!(
            has_relro_segment,
            reference.has_relro_segment,
            "{} GNU_RELRO presence mismatch for {}",
            binary_fixture.name,
            path.display()
        );
        assert_eq!(
            object.dynsym.len(),
            reference.dynsym_count,
            "{} dynsym count mismatch for {}",
            binary_fixture.name,
            path.display()
        );

        let assertions = &binary_fixture.assertions;
        if let Some(expected) = assertions.class.as_deref() {
            assert_eq!(
                rust_class, expected,
                "{} class fixture assertion failed",
                binary_fixture.name
            );
        }
        if let Some(expected) = assertions.data.as_deref() {
            assert_eq!(
                rust_data, expected,
                "{} data fixture assertion failed",
                binary_fixture.name
            );
        }
        if let Some(expected) = assertions.machine.as_deref() {
            assert_eq!(
                rust_machine, expected,
                "{} machine fixture assertion failed",
                binary_fixture.name
            );
        }
        if let Some(expected) = assertions.object_type.as_deref() {
            assert_eq!(
                rust_type, expected,
                "{} type fixture assertion failed",
                binary_fixture.name
            );
        }
        if let Some(expected) = assertions.min_program_headers {
            assert!(
                object.program_headers.len() >= expected,
                "{} expected at least {} program headers, found {}",
                binary_fixture.name,
                expected,
                object.program_headers.len()
            );
        }
        if let Some(expected) = assertions.min_load_segments {
            assert!(
                load_segments >= expected,
                "{} expected at least {} LOAD segments, found {}",
                binary_fixture.name,
                expected,
                load_segments
            );
        }
        if let Some(expected) = assertions.require_dynamic_segment {
            assert_eq!(
                has_dynamic_segment, expected,
                "{} PT_DYNAMIC fixture assertion failed",
                binary_fixture.name
            );
        }
        if let Some(expected) = assertions.expect_relro {
            assert_eq!(
                has_relro_segment, expected,
                "{} GNU_RELRO fixture assertion failed",
                binary_fixture.name
            );
        }
        if let Some(expected) = assertions.min_dynamic_symbols {
            assert!(
                object.dynsym.len() >= expected,
                "{} expected at least {} dynamic symbols, found {}",
                binary_fixture.name,
                expected,
                object.dynsym.len()
            );
        }
        for symbol in &assertions.required_symbols {
            assert!(
                reference.symbol_names.contains(symbol.as_str()),
                "{} missing required readelf symbol {} in {}",
                binary_fixture.name,
                symbol,
                path.display()
            );
            let parsed_symbol = object.lookup_symbol(symbol).unwrap_or_else(|| {
                panic!(
                    "{} missing required parsed symbol {} in {}",
                    binary_fixture.name,
                    symbol,
                    path.display()
                )
            });
            assert_eq!(
                object.symbol_name(parsed_symbol),
                Some(symbol.as_str()),
                "{} resolved wrong symbol name for {} in {}",
                binary_fixture.name,
                symbol,
                path.display()
            );
        }
    }

    if executed == 0 {
        eprintln!("Skipping ELF binary conformance: no fixture binaries available");
    }
}
