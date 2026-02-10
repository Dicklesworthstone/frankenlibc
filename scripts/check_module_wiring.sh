#!/usr/bin/env bash
# check_module_wiring.sh — Verify every runtime_math controller is fully wired.
#
# For each pub mod in runtime_math/mod.rs, checks 5 integration points:
#   1. Declared (pub mod) — always true by construction
#   2. Instantiated — type appears in RuntimeMathKernel struct + new()
#   3. Fed — referenced in observe_validation_result() or resample
#   4. Snapshot — state exported in RuntimeKernelSnapshot fields
#   5. Fusion — referenced in fusion severity vector construction
#
# Exit 0 if all controllers meet minimum wiring, exit 1 if unexpected gaps.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MOD_RS="$REPO_ROOT/crates/glibc-rs-membrane/src/runtime_math/mod.rs"

if [[ ! -f "$MOD_RS" ]]; then
    echo "ERROR: runtime_math/mod.rs not found" >&2
    exit 1
fi

# --- Module-to-field-name mapping ---
declare -A FIELD_MAP=(
    [bandit]="router"
    [eprocess]="anytime"
    [serre_spectral]="serre"
    [grothendieck_glue]="grothendieck"
    [large_deviations]="large_dev"
    [hji_reachability]="hji"
    [mean_field_game]="mfg"
    [padic_valuation]="padic"
    [symplectic_reduction]="symplectic"
    [higher_topos]="topos"
    [commitment_audit]="audit"
    [stein_discrepancy]="stein"
    [hodge_decomposition]="hodge"
    [rademacher_complexity]="rademacher"
    [lyapunov_stability]="lyapunov"
    [covering_array]="covering"
    [derived_tstructure]="tstructure"
    [pomdp_repair]="pomdp"
    [sos_invariant]="sos"
    [admm_budget]="admm"
    [obstruction_detector]="obstruction"
    [provenance_info]="provenance"
    [grobner_normalizer]="grobner"
    [malliavin_sensitivity]="malliavin"
    [wasserstein_drift]="wasserstein"
    [kernel_mmd]="kernel_mmd"
    [matrix_concentration]="matrix_concentration"
    [nerve_complex]="nerve_complex"
    [loss_minimizer]="loss_minimizer"
    [transfer_entropy]="transfer_entropy"
    [atiyah_bott]="atiyah_bott"
    [operator_norm]="operator_norm"
    [info_geometry]="info_geometry"
)

# Modules that are decision-time-only guards (no observation needed).
declare -A OBSERVE_EXEMPT=(
    [barrier]="Constant-time admissibility guard (read-only in decide)"
)

# Snapshot field prefix for each module
declare -A SNAP_PREFIX=(
    [eprocess]="anytime"
    [bandit]="router"
    [control]="full_validation_trigger|repair_trigger"
    [cohomology]="consistency_faults"
    [risk]="sampled_risk"
    [rough_path]="signature_"
    [persistence]="persistence_|topo_"
    [large_deviations]="ld_"
    [hji_reachability]="hji_"
    [mean_field_game]="mfg_"
    [padic_valuation]="padic_"
    [symplectic_reduction]="symplectic_"
    [higher_topos]="topos_"
    [commitment_audit]="audit_"
    [covering_array]="covering_"
    [derived_tstructure]="tstructure_"
    [pomdp_repair]="pomdp_"
    [sos_invariant]="sos_"
    [admm_budget]="admm_"
    [obstruction_detector]="obstruction_"
    [provenance_info]="provenance_"
    [grobner_normalizer]="grobner_"
    [grothendieck_glue]="grothendieck_"
    [malliavin_sensitivity]="malliavin_"
    [info_geometry]="info_geo"
    [matrix_concentration]="matrix_conc"
    [nerve_complex]="nerve_"
    [wasserstein_drift]="wasserstein_"
    [kernel_mmd]="mmd_"
    [serre_spectral]="serre_"
    [loss_minimizer]="loss_"
    [coupling]="coupling_"
    [hodge_decomposition]="hodge_"
    [rademacher_complexity]="rademacher_"
    [transfer_entropy]="transfer_entropy"
    [lyapunov_stability]="lyapunov_"
    [stein_discrepancy]="stein_"
)

# --- Extract line ranges for key sections ---
struct_range=$(grep -n 'pub struct RuntimeMathKernel {$' "$MOD_RS" | head -1 | cut -d: -f1)
snap_struct_range=$(grep -n 'pub struct RuntimeKernelSnapshot {$' "$MOD_RS" | head -1 | cut -d: -f1)
observe_range=$(grep -n 'pub fn observe_validation_result' "$MOD_RS" | head -1 | cut -d: -f1)
resample_range=$(grep -n 'fn resample_high_order_kernels' "$MOD_RS" | head -1 | cut -d: -f1)
snapshot_fn_range=$(grep -n 'pub fn snapshot.*RuntimeKernelSnapshot' "$MOD_RS" | head -1 | cut -d: -f1)

# Write temp files for section searching (avoids massive variable piping)
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

sed -n "${struct_range},+250p" "$MOD_RS" > "$TMPDIR/struct.txt"
sed -n "${snap_struct_range},+250p" "$MOD_RS" > "$TMPDIR/snap_struct.txt"
if [[ -n "$observe_range" ]]; then
    sed -n "${observe_range},$((observe_range + 1300))p" "$MOD_RS" > "$TMPDIR/observe.txt"
else
    touch "$TMPDIR/observe.txt"
fi
if [[ -n "$resample_range" ]]; then
    sed -n "${resample_range},$((resample_range + 800))p" "$MOD_RS" > "$TMPDIR/resample.txt"
else
    touch "$TMPDIR/resample.txt"
fi
# Combine observe + resample for searching
cat "$TMPDIR/observe.txt" "$TMPDIR/resample.txt" > "$TMPDIR/combined_observe.txt"

fusion_rs="$REPO_ROOT/crates/glibc-rs-membrane/src/runtime_math/fusion.rs"
if [[ -f "$fusion_rs" ]]; then
    cp "$fusion_rs" "$TMPDIR/fusion.txt"
else
    touch "$TMPDIR/fusion.txt"
fi

# --- Analysis ---
modules=$(grep -oP '^pub mod \K[a-z_]+' "$MOD_RS" | sort -u)
total=0
fully_wired=0
gaps=0
gap_report=""

printf "%-30s %-9s %-9s %-9s %-9s %-9s\n" "MODULE" "DECLARED" "STRUCT" "OBSERVE" "SNAPSHOT" "FUSION"
printf "%-30s %-9s %-9s %-9s %-9s %-9s\n" "------" "-------" "------" "-------" "--------" "------"

for mod in $modules; do
    total=$((total + 1))
    declared="yes"
    field="${FIELD_MAP[$mod]:-$mod}"

    # Collect imported types
    import_types=$(grep "^use self::${mod}::" "$MOD_RS" | grep -oP '[A-Z][A-Za-z]+' || true)

    # --- STRUCT check ---
    in_struct="no"
    if grep -qF "${field}:" "$TMPDIR/struct.txt" 2>/dev/null; then
        in_struct="yes"
    fi
    if [[ "$in_struct" == "no" && -n "$import_types" ]]; then
        for typ in $import_types; do
            if grep -qF "$typ" "$TMPDIR/struct.txt" 2>/dev/null; then
                in_struct="yes"
                break
            fi
        done
    fi

    # --- OBSERVE check ---
    in_observe="no"
    if [[ -n "${OBSERVE_EXEMPT[$mod]:-}" ]]; then
        in_observe="exempt"
    else
        # Check for self.field reference
        if grep -qF "self.${field}" "$TMPDIR/combined_observe.txt" 2>/dev/null; then
            in_observe="yes"
        fi
        # Check cached_field_state
        if [[ "$in_observe" == "no" ]]; then
            if grep -qF "cached_${field}_state" "$TMPDIR/combined_observe.txt" 2>/dev/null; then
                in_observe="yes"
            fi
        fi
        # Check _anomaly variable
        if [[ "$in_observe" == "no" ]]; then
            if grep -qF "${field}_anomaly" "$TMPDIR/combined_observe.txt" 2>/dev/null; then
                in_observe="yes"
            fi
        fi
        # Check imported type names
        if [[ "$in_observe" == "no" && -n "$import_types" ]]; then
            for typ in $import_types; do
                if grep -qF "$typ" "$TMPDIR/combined_observe.txt" 2>/dev/null; then
                    in_observe="yes"
                    break
                fi
            done
        fi
    fi

    # --- SNAPSHOT check ---
    in_snapshot="no"
    snap_pat="${SNAP_PREFIX[$mod]:-$mod}"
    # Use grep -P for alternation patterns, -F for simple ones
    if echo "$snap_pat" | grep -q '|'; then
        if grep -qP "$snap_pat" "$TMPDIR/snap_struct.txt" 2>/dev/null; then
            in_snapshot="yes"
        fi
    else
        if grep -qF "$snap_pat" "$TMPDIR/snap_struct.txt" 2>/dev/null; then
            in_snapshot="yes"
        fi
    fi

    # --- FUSION check ---
    in_fusion="no"
    if grep -qF "${field}" "$TMPDIR/fusion.txt" 2>/dev/null; then
        in_fusion="yes"
    fi

    printf "%-30s %-9s %-9s %-9s %-9s %-9s\n" "$mod" "$declared" "$in_struct" "$in_observe" "$in_snapshot" "$in_fusion"

    if [[ "$in_struct" == "yes" && ("$in_observe" == "yes" || "$in_observe" == "exempt") && "$in_snapshot" == "yes" ]]; then
        fully_wired=$((fully_wired + 1))
    else
        gaps=$((gaps + 1))
        gap_report+="  $mod:"
        [[ "$in_struct" == "no" ]] && gap_report+=" MISSING_STRUCT"
        [[ "$in_observe" == "no" ]] && gap_report+=" MISSING_OBSERVE"
        [[ "$in_snapshot" == "no" ]] && gap_report+=" MISSING_SNAPSHOT"
        gap_report+=$'\n'
    fi
done

echo ""
echo "--- Summary ---"
echo "Total modules: $total"
echo "Fully wired (struct+observe+snapshot): $fully_wired"
echo "With gaps: $gaps"

if [[ $gaps -gt 0 ]]; then
    echo ""
    echo "=== WIRING GAPS ==="
    echo "$gap_report"
    echo "(Modules marked 'exempt' have documented rationale for their wiring status.)"
    echo ""
    echo "NOTE: Some MISSING_OBSERVE entries may be by design — not all controllers"
    echo "need per-call observation. Controllers that only read state in decide()"
    echo "or are updated on cadence boundaries may legitimately lack observe wiring."
    exit 1
else
    echo ""
    echo "OK: All $total runtime_math modules are fully wired (or documented exempt)."
    exit 0
fi
