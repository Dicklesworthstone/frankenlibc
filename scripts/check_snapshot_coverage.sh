#!/usr/bin/env bash
# check_snapshot_coverage.sh — Verify every runtime_math module has snapshot+test coverage.
#
# For each pub mod in runtime_math/mod.rs, checks:
#   1. Snapshot field(s) in RuntimeKernelSnapshot
#   2. Unit tests in the module's own .rs file
#   3. Classification (hot-path vs cadence)
#
# Exit 0 if all modules have minimum coverage, exit 1 if gaps found.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MOD_RS="$REPO_ROOT/crates/frankenlibc-membrane/src/runtime_math/mod.rs"
RT_DIR="$REPO_ROOT/crates/frankenlibc-membrane/src/runtime_math"

if [[ ! -f "$MOD_RS" ]]; then
    echo "ERROR: runtime_math/mod.rs not found" >&2
    exit 1
fi

# --- Snapshot field prefix mapping ---
# Maps module name -> field prefix(es) in RuntimeKernelSnapshot.
declare -A SNAP_PREFIX=(
    [risk]="sampled_risk"
    [bandit]="router"
    [control]="full_validation_trigger|repair_trigger"
    [cohomology]="consistency_faults"
    [eprocess]="anytime"
    [cvar]="cvar"
    [pareto]="pareto"
    [rough_path]="signature_"
    [persistence]="persistence_|topo_"
    [tropical_latency]="tropical_"
    [spectral_monitor]="spectral_"
    [large_deviations]="ld_"
    [hji_reachability]="hji_"
    [mean_field_game]="mfg_"
    [padic_valuation]="padic_"
    [symplectic_reduction]="symplectic_"
    [schrodinger_bridge]="bridge_"
    [higher_topos]="topos_"
    [commitment_audit]="audit_"
    [changepoint]="changepoint_"
    [conformal]="conformal_"
    [design]="design_"
    [sparse]="sparse_"
    [equivariant]="equivariant_"
    [fusion]="fusion_"
    [microlocal]="microlocal_"
    [serre_spectral]="serre_"
    [clifford]="clifford_"
    [ktheory]="ktheory_"
    [covering_array]="covering_"
    [derived_tstructure]="tstructure_"
    [atiyah_bott]="atiyah_bott_"
    [pomdp_repair]="pomdp_"
    [sos_invariant]="sos_"
    [admm_budget]="admm_"
    [obstruction_detector]="obstruction_"
    [operator_norm]="operator_norm_"
    [provenance_info]="provenance_"
    [grobner_normalizer]="grobner_"
    [grothendieck_glue]="grothendieck_"
    [malliavin_sensitivity]="malliavin_"
    [info_geometry]="info_geo"
    [matrix_concentration]="matrix_conc"
    [nerve_complex]="nerve_"
    [wasserstein_drift]="wasserstein_"
    [kernel_mmd]="mmd_"
    [pac_bayes]="pac_bayes_"
    [stein_discrepancy]="stein_"
    [lyapunov_stability]="lyapunov_"
    [rademacher_complexity]="rademacher_"
    [transfer_entropy]="transfer_entropy"
    [hodge_decomposition]="hodge_"
    [loss_minimizer]="loss_"
    [coupling]="coupling_"
    [doob_decomposition]="doob_"
    [fano_bound]="fano_"
    [dobrushin_contraction]="dobrushin_"
    [azuma_hoeffding]="azuma_"
    [renewal_theory]="renewal_"
    [lempel_ziv]="lz_"
    [localization_chooser]="localization_"
    [policy_table]="policy_"
    [spectral_gap]="spectral_gap_"
    [submodular_coverage]="submodular_"
    [bifurcation_detector]="bifurcation_"
    [entropy_rate]="entropy_rate_"
    [ito_quadratic_variation]="ito_qv_"
    [borel_cantelli]="borel_cantelli_"
    [dispersion_index]="dispersion_"
    [ornstein_uhlenbeck]="ou_"
    [hurst_exponent]="hurst_"
    [birkhoff_ergodic]="birkhoff_"
    [redundancy_tuner]="redundancy_"
)

# Hot-path modules (lock-free access in decide())
declare -A HOT_PATH=(
    [risk]="1"
    [cohomology]="1"
    [barrier]="1"
)

# Modules with documented rationale for missing snapshot fields.
declare -A SNAP_EXEMPT=(
    [barrier]="Stateless admissibility guard; pure function of inputs, no accumulated state to export"
    [bandit]="Profile selector using UCB; its output is the selected profile in RuntimeDecision, not accumulated state"
    [evidence]="Data-transport ring buffer (bd-kom); not a severity controller, no state for the decision kernel snapshot"
)

# --- Extract snapshot struct ---
TMPDIR=$(mktemp -d)
cleanup_tmpdir() {
    # AGENTS.md forbids rm -rf. Remove only if empty; otherwise leave for inspection.
    rmdir "$TMPDIR" 2>/dev/null || true
}
trap cleanup_tmpdir EXIT

snap_start=$(grep -n 'pub struct RuntimeKernelSnapshot {$' "$MOD_RS" | head -1 | cut -d: -f1)
snap_end=$(awk "NR>=$snap_start" "$MOD_RS" | grep -n '^}$' | head -1 | cut -d: -f1)
snap_end=$((snap_start + snap_end - 1))
sed -n "${snap_start},${snap_end}p" "$MOD_RS" > "$TMPDIR/snapshot.txt"

# --- Analysis ---
modules=$(grep -oP '^pub mod \K[a-z_]+' "$MOD_RS" | sort -u)
total=0
covered=0
gaps=0
gap_report=""

printf "%-30s %-10s %-8s %-8s %-8s\n" "MODULE" "CLASS" "SNAP" "TESTS" "STATUS"
printf "%-30s %-10s %-8s %-8s %-8s\n" "------" "-----" "----" "-----" "------"

for mod in $modules; do
    total=$((total + 1))

    # Classification
    if [[ -n "${HOT_PATH[$mod]:-}" ]]; then
        class="hot-path"
    else
        class="cadence"
    fi

    # Snapshot fields
    snap_pat="${SNAP_PREFIX[$mod]:-$mod}"
    snap_count=0
    if echo "$snap_pat" | grep -q '|'; then
        snap_count=$(grep -cP "$snap_pat" "$TMPDIR/snapshot.txt" 2>/dev/null || true)
    else
        snap_count=$(grep -cF "$snap_pat" "$TMPDIR/snapshot.txt" 2>/dev/null || true)
    fi

    # Unit tests in module .rs file
    mod_file="$RT_DIR/${mod}.rs"
    test_count=0
    if [[ -f "$mod_file" ]]; then
        test_count=$(grep -c '#\[test\]' "$mod_file" 2>/dev/null || true)
    fi

    # Status
    status="OK"
    snap_exempt="${SNAP_EXEMPT[$mod]:-}"
    if [[ "$snap_count" -eq 0 && -n "$snap_exempt" ]]; then
        if [[ "$test_count" -gt 0 ]]; then
            status="exempt"
            covered=$((covered + 1))
        else
            status="EXEMPT_NOTEST"
            gaps=$((gaps + 1))
            gap_report+="  $mod: EXEMPT_SNAPSHOT but NO_TESTS\n"
        fi
    elif [[ "$snap_count" -eq 0 && "$test_count" -eq 0 ]]; then
        status="MISSING"
        gaps=$((gaps + 1))
        gap_report+="  $mod: NO_SNAPSHOT + NO_TESTS\n"
    elif [[ "$snap_count" -eq 0 ]]; then
        status="NO_SNAP"
        gaps=$((gaps + 1))
        gap_report+="  $mod: NO_SNAPSHOT (has $test_count tests)\n"
    elif [[ "$test_count" -eq 0 ]]; then
        status="NO_TEST"
        gaps=$((gaps + 1))
        gap_report+="  $mod: NO_TESTS (has $snap_count snapshot fields)\n"
    else
        covered=$((covered + 1))
    fi

    printf "%-30s %-10s %-8s %-8s %-8s\n" "$mod" "$class" "$snap_count" "$test_count" "$status"
done

echo ""
echo "--- Summary ---"
echo "Total modules: $total"
echo "Fully covered (snapshot + tests): $covered"
echo "With gaps: $gaps"

if [[ $gaps -gt 0 ]]; then
    echo ""
    echo "=== COVERAGE GAPS ==="
    echo -e "$gap_report"
    echo "NOTE: Some gaps may be by design. Hot-path modules (risk, cohomology, barrier)"
    echo "may share snapshot fields with their parent kernel rather than having dedicated"
    echo "module-level tests if they are thin wrappers."
    exit 1
else
    echo ""
    echo "OK: All $total runtime_math modules have snapshot coverage and unit tests."
    exit 0
fi
