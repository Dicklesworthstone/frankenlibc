use std::path::{Path, PathBuf};

struct CleanedHarnessFile {
    bead: &'static str,
    path: &'static str,
}

#[derive(Clone, Copy)]
enum ForbiddenKind {
    Unwrap,
    Expect,
    PanicMacro,
}

struct ForbiddenToken {
    kind: ForbiddenKind,
    display: &'static str,
    needle: &'static str,
}

struct AllowlistedUse {
    path: &'static str,
    line: usize,
    kind: ForbiddenKind,
    reason: &'static str,
}

const CLEANED_HARNESS_FILES: &[CleanedHarnessFile] = &[
    CleanedHarnessFile {
        bead: "ci-perf-gate-wiring-cleanup",
        path: "crates/frankenlibc-harness/tests/ci_perf_gate_wiring_test.rs",
    },
    CleanedHarnessFile {
        bead: "bd-crm9x",
        path: "crates/frankenlibc-harness/tests/beads_sqlite_integrity_completion_contract_test.rs",
    },
    CleanedHarnessFile {
        bead: "bd-kmope",
        path: "crates/frankenlibc-harness/tests/allocator_subsystem_completion_contract_test.rs",
    },
    CleanedHarnessFile {
        bead: "l1-parser-positive-cases-cleanup",
        path: "crates/frankenlibc-harness/tests/l1_dashboard_must_remain_unset_parser_test.rs",
    },
    CleanedHarnessFile {
        bead: "separation-logic-gate-cleanup",
        path: "crates/frankenlibc-harness/tests/separation_logic_annotations_test.rs",
    },
    CleanedHarnessFile {
        bead: "evidence-ring-snapshot-cleanup",
        path: "crates/frankenlibc-harness/tests/evidence_ring_backpressure_stress_contract_test.rs",
    },
    CleanedHarnessFile {
        bead: "conformance-fixture-pipeline-cleanup",
        path: "crates/frankenlibc-harness/tests/conformance_fixture_pipeline_test.rs",
    },
    CleanedHarnessFile {
        bead: "perf-waiver-audit-cleanup",
        path: "crates/frankenlibc-harness/tests/perf_waiver_audit_test.rs",
    },
    CleanedHarnessFile {
        bead: "gentoo-telemetry-cleanup",
        path: "crates/frankenlibc-harness/tests/gentoo_test_execution_telemetry_test.rs",
    },
    CleanedHarnessFile {
        bead: "resolver-nss-gate-cleanup",
        path: "crates/frankenlibc-harness/tests/resolver_nss_hard_parts_test.rs",
    },
    CleanedHarnessFile {
        bead: "bd-l5dfe",
        path: "crates/frankenlibc-harness/tests/l3_full_replace_claim_control_completion_contract_test.rs",
    },
    CleanedHarnessFile {
        bead: "verification-matrix-maintenance-cleanup",
        path: "crates/frankenlibc-harness/tests/verification_matrix_maintenance_completion_contract_test.rs",
    },
    CleanedHarnessFile {
        bead: "extreme-optimization-loop-cleanup",
        path: "crates/frankenlibc-harness/tests/extreme_optimization_loop_completion_contract_test.rs",
    },
    CleanedHarnessFile {
        bead: "bd-z92n8",
        path: "crates/frankenlibc-harness/tests/pthread_bootstrap_completion_contract_test.rs",
    },
    CleanedHarnessFile {
        bead: "br-db-repair-cleanup",
        path: "crates/frankenlibc-harness/tests/br_db_repair_completion_contract_test.rs",
    },
    CleanedHarnessFile {
        bead: "bd-kmhto",
        path: "crates/frankenlibc-harness/tests/claim_reconciliation_completion_contract_test.rs",
    },
    CleanedHarnessFile {
        bead: "bd-rxed0",
        path: "crates/frankenlibc-harness/tests/real_program_smoke_suite_completion_contract_test.rs",
    },
    CleanedHarnessFile {
        bead: "stdio-family-cleanup",
        path: "crates/frankenlibc-harness/tests/stdio_family_completion_contract_test.rs",
    },
    CleanedHarnessFile {
        bead: "bd-y7x9e",
        path: "crates/frankenlibc-harness/tests/rch_validation_provenance_test.rs",
    },
    CleanedHarnessFile {
        bead: "bd-8wf7z",
        path: "crates/frankenlibc-harness/tests/runtime_evidence_verifier_test.rs",
    },
    CleanedHarnessFile {
        bead: "bd-2roue",
        path: "crates/frankenlibc-harness/tests/explain_dossier_contract_test.rs",
    },
    CleanedHarnessFile {
        bead: "bd-345gr",
        path: "crates/frankenlibc-harness/tests/swarm_scale_interpose_workload_evidence_plan_test.rs",
    },
];

const FORBIDDEN_TOKENS: &[ForbiddenToken] = &[
    ForbiddenToken {
        kind: ForbiddenKind::Unwrap,
        display: concat!(".", "unwrap", "("),
        needle: concat!(".", "unwrap", "("),
    },
    ForbiddenToken {
        kind: ForbiddenKind::Expect,
        display: concat!(".", "expect", "("),
        needle: concat!(".", "expect", "("),
    },
    ForbiddenToken {
        kind: ForbiddenKind::PanicMacro,
        display: concat!("panic", "!("),
        needle: concat!("panic", "!("),
    },
];

const ALLOWLIST: &[AllowlistedUse] = &[];

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest_dir
        .parent()
        .ok_or_else(|| "frankenlibc-harness manifest should have a parent".to_string())?;
    crates_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "crates directory should have workspace parent".to_string())
}

fn read_source(root: &Path, rel_path: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(rel_path))
        .map_err(|err| format!("failed to read {rel_path}: {err}"))
}

fn same_forbidden_kind(left: ForbiddenKind, right: ForbiddenKind) -> bool {
    matches!(
        (left, right),
        (ForbiddenKind::Unwrap, ForbiddenKind::Unwrap)
            | (ForbiddenKind::Expect, ForbiddenKind::Expect)
            | (ForbiddenKind::PanicMacro, ForbiddenKind::PanicMacro)
    )
}

fn is_allowlisted(path: &str, line: usize, kind: ForbiddenKind) -> bool {
    for entry in ALLOWLIST {
        if entry.line != line {
            continue;
        }
        if !entry.path.as_bytes().eq(path.as_bytes()) {
            continue;
        }
        if !same_forbidden_kind(entry.kind, kind) {
            continue;
        }
        return true;
    }
    false
}

fn validate_allowlist() -> Result<(), String> {
    let mut failures = Vec::new();
    for entry in ALLOWLIST {
        if entry.reason.trim().is_empty() {
            failures.push(format!(
                "{}:{} allowlist entry must include a reason",
                entry.path, entry.line
            ));
        }
        if !CLEANED_HARNESS_FILES
            .iter()
            .any(|cleaned| cleaned.path.as_bytes().eq(entry.path.as_bytes()))
        {
            failures.push(format!(
                "{}:{} allowlist entry targets a file outside the cleaned gate",
                entry.path, entry.line
            ));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "invalid cleaned harness panic-surface allowlist:\n{}",
            failures.join("\n")
        ))
    }
}

fn collect_violations_for_source(cleaned: &CleanedHarnessFile, source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for (line_index, line) in source.lines().enumerate() {
        let line_number = line_index + 1;
        for forbidden in FORBIDDEN_TOKENS {
            if line.contains(forbidden.needle)
                && !is_allowlisted(cleaned.path, line_number, forbidden.kind)
            {
                violations.push(format!(
                    "{}:{}: {} [{}] {}",
                    cleaned.path,
                    line_number,
                    forbidden.display,
                    cleaned.bead,
                    line.trim()
                ));
            }
        }
    }
    violations
}

fn collect_violations(root: &Path) -> Result<Vec<String>, String> {
    let mut violations = Vec::new();
    for cleaned in CLEANED_HARNESS_FILES {
        let source = read_source(root, cleaned.path)?;
        violations.extend(collect_violations_for_source(cleaned, &source));
    }
    Ok(violations)
}

#[test]
fn cleaned_harness_tests_do_not_regress_to_direct_panic_surfaces() -> Result<(), String> {
    validate_allowlist()?;
    let root = repo_root()?;
    let violations = collect_violations(&root)?;

    if violations.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "cleaned harness panic-surface regressions:\n{}",
            violations.join("\n")
        ))
    }
}

#[test]
fn synthetic_regressions_report_actionable_file_line_token_and_bead() {
    let cleaned = CleanedHarnessFile {
        bead: "bd-synthetic",
        path: "synthetic_cleaned_gate_fixture.rs",
    };
    let source = [
        "fn fixture() {",
        concat!("    let _ = maybe.", "unwrap", "();"),
        concat!("    ", "panic", "!(\"synthetic\");"),
        "}",
    ]
    .join("\n");

    let violations = collect_violations_for_source(&cleaned, &source);
    assert_eq!(violations.len(), 2, "{violations:#?}");

    assert!(
        violations.iter().any(|violation| {
            violation.contains(concat!(
                "synthetic_cleaned_gate_fixture.rs:2: ",
                ".",
                "unwrap",
                "("
            )) && violation.contains("[bd-synthetic]")
                && violation.contains(concat!("maybe.", "unwrap", "()"))
        }),
        "{violations:#?}"
    );
    assert!(
        violations.iter().any(|violation| {
            violation.contains(concat!(
                "synthetic_cleaned_gate_fixture.rs:3: ",
                "panic",
                "!("
            )) && violation.contains("[bd-synthetic]")
                && violation.contains(concat!("panic", "!(\"synthetic\")"))
        }),
        "{violations:#?}"
    );
}
