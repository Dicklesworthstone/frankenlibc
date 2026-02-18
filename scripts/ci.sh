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

echo "--- cargo test --workspace --all-targets ---"
cargo test --workspace --all-targets
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

    echo "--- runtime_math decision-law linkage proofs (production controllers) ---"
    scripts/check_runtime_math_linkage_proofs.sh
    echo "PASS"
    echo ""

    echo "--- runtime_math determinism + invariant proofs (decide+observe) ---"
    scripts/check_runtime_math_determinism_proofs.sh
    echo "PASS"
    echo ""

    echo "--- runtime_math strict-vs-hardened divergence bounds ---"
    scripts/check_runtime_math_divergence_bounds.sh
    echo "PASS"
    echo ""

    echo "--- runtime_math production kernel manifest check ---"
    scripts/check_runtime_math_manifest.sh
    echo "PASS"
    echo ""

    echo "--- runtime_math profile gates (production vs research) ---"
    scripts/check_runtime_math_profile_gates.sh
    echo "PASS"
    echo ""

    echo "--- runtime_math risk+pareto calibration gate ---"
    scripts/check_runtime_math_risk_pareto_calibration.sh
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

    echo "--- support matrix maintenance/classification gate ---"
    scripts/check_support_matrix_maintenance.sh
    echo "PASS"
    echo ""

    echo "--- hard-parts docs/parity/support/reality truth drift check ---"
    scripts/check_hard_parts_truth.sh
    echo "PASS"
    echo ""

    echo "--- hard-parts cross-boundary E2E classification gate ---"
    scripts/check_hard_parts_e2e.sh
    echo "PASS"
    echo ""

    echo "--- feature parity gap ledger extractor gate ---"
    scripts/check_feature_parity_gap_ledger.sh
    echo "PASS"
    echo ""

    echo "--- feature parity fail-fast drift gate ---"
    scripts/check_feature_parity_drift.sh
    echo "PASS"
    echo ""

    echo "--- feature parity gap→bead coverage dashboard gate ---"
    scripts/check_feature_parity_gap_bead_coverage.sh
    echo "PASS"
    echo ""

    echo "--- test-obligation coverage dashboard + blocker extraction gate ---"
    scripts/check_test_obligation_dashboard.sh
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

    echo "--- bd-1qy mutex fixture strict+hardened artifact gate ---"
    scripts/check_bd1qy_mutex_fixture.sh
    echo "PASS"
    echo ""

    echo "--- bd-1f35 pthread stress strict+hardened artifact gate ---"
    scripts/check_bd1f35_thread_stress.sh
    echo "PASS"
    echo ""

    echo "--- bd-15n.2 fixture gap-fill strict+hardened artifact gate ---"
    scripts/check_bd15n2_fixture_gap_fill.sh
    echo "PASS"
    echo ""

    echo "--- bd-13ya iconv deterministic table generation gate ---"
    scripts/check_iconv_table_generation.sh
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

    echo "--- math production-set change policy gate ---"
    scripts/check_math_production_set_policy.sh
    echo "PASS"
    echo ""

    echo "--- math value ablation gate ---"
    scripts/check_math_value_ablations.sh
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

    echo "--- perf regression attribution gate ---"
    scripts/check_perf_regression_gate.sh
    echo "PASS"
    echo ""

    echo "--- optimization proof ledger gate ---"
    scripts/check_optimization_proof_ledger.sh
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

    echo "--- Tier 1 fast validation gate (bd-2icq.18) ---"
    scripts/check_fast_validate.sh
    echo "PASS"
    echo ""

    echo "--- Gentoo perf benchmark gate (bd-2icq.9) ---"
    scripts/check_perf_benchmark_gentoo.sh
    echo "PASS"
    echo ""

    echo "--- flaky test quarantine gate (bd-2icq.24) ---"
    scripts/check_flaky_quarantine.sh
    echo "PASS"
    echo ""

    echo "--- deterministic E2E CI gate (bd-b5a.3 / bd-2ez) ---"
    scripts/check_e2e_suite.sh
    echo "PASS"
    echo ""

    echo "--- regression detection gate (bd-2icq.12) ---"
    scripts/check_regression_detector.sh
    echo "PASS"
    echo ""

    echo "--- resource constraint testing gate (bd-2icq.20) ---"
    scripts/check_resource_constraints.sh
    echo "PASS"
    echo ""

    echo "--- progress reporter gate (bd-2icq.21) ---"
    scripts/check_progress_reporter.sh
    echo "PASS"
    echo ""

    echo "--- validation dashboard gate (bd-2icq.11) ---"
    scripts/check_validation_dashboard.sh
    echo "PASS"
    echo ""

    echo "--- release qualification gate (bd-2icq.17) ---"
    scripts/check_release_gate.sh
    echo "PASS"
    echo ""

    echo "--- branch-diversity gate (bd-5fw.5) ---"
    scripts/check_branch_diversity.sh
    echo "PASS"
    echo ""

    echo "--- proof obligations binder gate (bd-5fw.4) ---"
    scripts/check_proof_binder.sh
    echo "PASS"
    echo ""
else
    echo "SKIP extended gates (set FRANKENLIBC_EXTENDED_GATES=1 to run full policy/perf/snapshot checks)"
    echo ""
fi

echo "=== All gates passed ==="
