#!/usr/bin/env bash
# CI quality gates for frankenlibc.
set -euo pipefail

echo "=== frankenlibc CI ==="
echo ""

echo "--- cargo fmt --check ---"
cargo fmt --check
echo "PASS"
echo ""

echo "--- cargo check --workspace --all-targets ---"
cargo check --workspace --all-targets
echo "PASS"
echo ""

echo "--- cargo clippy --workspace --all-targets -- -D warnings ---"
cargo clippy --workspace --all-targets -- -D warnings
echo "PASS"
echo ""

echo "--- cargo test --workspace ---"
cargo test --workspace
echo "PASS"
echo ""

echo "--- cargo build -p frankenlibc-abi --release ---"
cargo build -p frankenlibc-abi --release
echo "PASS"
echo ""

if [[ "${FRANKENLIBC_EXTENDED_GATES:-0}" == "1" ]]; then
    echo "--- hard rule audit (no forbidden math on strict fast path) ---"
    scripts/hard_rule_audit.sh
    echo "PASS"
    echo ""

    echo "--- module inventory drift check ---"
    scripts/check_module_inventory.sh
    echo "PASS"
    echo ""

    echo "--- runtime_math decision linkage ledger check ---"
    scripts/check_runtime_math_linkage.sh
    echo "PASS"
    echo ""

    echo "--- runtime_math production kernel manifest check ---"
    scripts/check_runtime_math_manifest.sh
    echo "PASS"
    echo ""

    echo "--- expected-loss matrix policy artifact check ---"
    scripts/check_expected_loss_matrix.sh
    echo "PASS"
    echo ""

    echo "--- module wiring checklist ---"
    scripts/check_module_wiring.sh || echo "WARN: wiring gaps found (non-blocking)"
    echo ""

    echo "--- snapshot+test coverage matrix ---"
    scripts/check_snapshot_coverage.sh
    echo "PASS"
    echo ""

    echo "--- conformance golden gate (strict+hardened fixture verify) ---"
    scripts/conformance_golden_gate.sh
    echo "PASS"
    echo ""

    echo "--- snapshot gate (runtime_math golden) ---"
    scripts/snapshot_gate.sh
    echo "PASS"
    echo ""

    echo "--- perf gate (runtime_math + membrane) ---"
    scripts/perf_gate.sh
    echo "PASS"
    echo ""

    echo "--- ABI symbol taxonomy drift check ---"
    scripts/abi_audit.sh
    echo "PASS"
    echo ""

    echo "--- support matrix/docs reality drift check ---"
    scripts/check_support_matrix_drift.sh
    echo "PASS"
    echo ""

    echo "--- symbol fixture coverage matrix drift check ---"
    scripts/check_symbol_fixture_coverage.sh
    echo "PASS"
    echo ""

    echo "--- math governance gate ---"
    scripts/check_math_governance.sh
    echo "PASS"
    echo ""

    echo "--- runtime_math classification matrix gate ---"
    scripts/check_runtime_math_classification_matrix.sh
    echo "PASS"
    echo ""

    echo "--- math retirement gate ---"
    scripts/check_math_retirement.sh
    echo "PASS"
    echo ""

    echo "--- symbol drift guard ---"
    scripts/check_symbol_drift.sh
    echo "PASS"
    echo ""

    echo "--- mode semantics gate ---"
    scripts/check_mode_semantics.sh
    echo "PASS"
    echo ""

    echo "--- closure evidence gate ---"
    scripts/check_closure_gate.sh
    echo "PASS"
    echo ""

    echo "--- evidence compliance gate ---"
    scripts/check_evidence_compliance.sh
    echo "PASS"
    echo ""

    echo "--- closure contract gate ---"
    scripts/check_closure_contract.sh
    echo "PASS"
    echo ""

    echo "--- release gate dry-run orchestration ---"
    scripts/release_dry_run.sh --mode dry-run
    echo "PASS"
    echo ""

    echo "--- replacement levels gate ---"
    scripts/check_replacement_levels.sh
    echo "PASS"
    echo ""

    echo "--- perf budget gate ---"
    scripts/check_perf_budget.sh
    echo "PASS"
    echo ""

    echo "--- packaging gate ---"
    scripts/check_packaging.sh
    echo "PASS"
    echo ""

    echo "--- isomorphism proof gate ---"
    scripts/check_isomorphism_proof.sh
    echo "PASS"
    echo ""

    echo "--- opportunity matrix gate ---"
    scripts/check_opportunity_matrix.sh
    echo "PASS"
    echo ""

    echo "--- workload matrix gate ---"
    scripts/check_workload_matrix.sh
    echo "PASS"
    echo ""

    echo "--- C fixture suite gate ---"
    scripts/check_c_fixture_suite.sh
    echo "PASS"
    echo ""

    echo "--- stub priority ranking gate ---"
    scripts/check_stub_priority.sh
    echo "PASS"
    echo ""

    echo "--- math value proof gate ---"
    scripts/check_math_value_proof.sh
    echo "PASS"
    echo ""

    echo "--- changepoint drift policy gate ---"
    scripts/check_changepoint_drift.sh
    echo "PASS"
    echo ""

    echo "--- anytime-valid monitor gate ---"
    scripts/check_anytime_valid_monitor.sh
    echo "PASS"
    echo ""

    echo "--- perf baseline suite gate ---"
    scripts/check_perf_baseline.sh
    echo "PASS"
    echo ""

    echo "--- crash bundle gate ---"
    scripts/check_crash_bundle.sh
    echo "PASS"
    echo ""

    echo "--- CVE Arena regression gate ---"
    if [ -f scripts/cve_arena_gate.sh ]; then
        scripts/cve_arena_gate.sh
        echo "PASS"
    else
        echo "SKIP (cve_arena_gate.sh not found)"
    fi
    echo ""
else
    echo "SKIP extended gates (set FRANKENLIBC_EXTENDED_GATES=1 to run full policy/perf/snapshot checks)"
    echo ""
fi

echo "=== All gates passed ==="
