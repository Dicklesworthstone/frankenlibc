#!/usr/bin/env bash
# check_regenerate_then_diff_gate.sh — bd-3yr14.5
# Converts read-stored-JSON gates to regenerate-then-diff pattern.
#
# For each artifact (reality_report, support_matrix_maintenance_report,
# hard_parts_truth_table, proof_obligations_binder):
#   1. Regenerate the artifact from source
#   2. Diff against the committed copy
#   3. FAIL on any divergence
#
# CRITICAL: The only sanctioned update path is:
#   regenerate-from-source → commit the regenerated artifact → record in evidence ledger
# Hand-editing artifacts to make gates pass is FORBIDDEN.
#
# Usage:
#   ./check_regenerate_then_diff_gate.sh [--regenerate] [--artifact NAME]
#
# Flags:
#   --regenerate    Update committed artifacts (only for legitimate changes)
#   --artifact NAME Check only one artifact: reality_report, maintenance_report,
#                   hard_parts_truth, proof_obligations
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$REPO_ROOT/target/conformance/regenerate_then_diff"
LOG_FILE="$OUT_DIR/regenerate_then_diff.log.jsonl"
TRACE_ID="bd-3yr14.5-$(date -u +%Y%m%dT%H%M%SZ)-$$"
RUN_DIR="$OUT_DIR/$TRACE_ID"
GENERATED_ARTIFACT=""

REGENERATE=false
TARGET_ARTIFACT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --regenerate)
            REGENERATE=true
            shift
            ;;
        --artifact)
            TARGET_ARTIFACT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

mkdir -p "$OUT_DIR" "$RUN_DIR"

emit_event() {
    local level="$1"
    local event="$2"
    local artifact="$3"
    local outcome="$4"
    local details="$5"
    python3 - "$level" "$event" "$artifact" "$outcome" "$details" "$TRACE_ID" "$LOG_FILE" <<'PY'
import json, sys
from datetime import datetime, timezone

level, event, artifact, outcome, details, trace_id, log_path = sys.argv[1:8]
entry = {
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "trace_id": trace_id,
    "level": level,
    "event": event,
    "bead_id": "bd-3yr14.5",
    "artifact": artifact,
    "outcome": outcome,
    "details": details,
}
with open(log_path, "a") as f:
    f.write(json.dumps(entry, sort_keys=True) + "\n")
PY
}

check_artifact() {
    local name="$1"
    local committed="$2"
    local regenerate_cmd="$3"
    local generated="$RUN_DIR/${name}.generated.json"

    echo "--- Checking $name ---"

    if [[ ! -f "$committed" ]]; then
        echo "FAIL: committed artifact missing: $committed"
        emit_event "error" "artifact_missing" "$name" "fail" "committed file not found"
        return 1
    fi

    echo "Regenerating $name from source..."
    local regen_output="$RUN_DIR/${name}.regen.log"
    # Use a trace-specific generated path instead of clearing a persistent
    # filename. If a regenerator exits 0 without writing "$generated" (wrong
    # --output path, no-op rch invocation, etc.), no stale artifact can be
    # diffed as fresh output, and the no-output failure below fires.
    GENERATED_ARTIFACT="$generated"
    if ! eval "$regenerate_cmd" > "$regen_output" 2>&1; then
        echo "FAIL: regeneration command failed for $name"
        cat "$regen_output" | head -20
        emit_event "error" "regeneration_failed" "$name" "fail" "regeneration command failed"
        return 1
    fi

    # The regenerate functions write directly to the generated file
    if [[ ! -f "$generated" ]]; then
        # Try to use the output as the generated file
        if [[ -s "$regen_output" ]]; then
            cp "$regen_output" "$generated"
        fi
    fi

    if [[ ! -f "$generated" ]]; then
        echo "FAIL: regeneration did not produce output for $name"
        emit_event "error" "no_output" "$name" "fail" "regeneration produced no file"
        return 1
    fi

    # Normalize JSON for comparison (sort keys, consistent formatting, strip timestamps)
    local committed_normalized="$RUN_DIR/${name}.committed.normalized.json"
    local generated_normalized="$RUN_DIR/${name}.generated.normalized.json"

    # Normalize: sort keys, strip generated_at timestamps (metadata, not derived from source)
    python3 - "$committed" "$committed_normalized" <<'NORM'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
# Remove timestamp fields that aren't derived from source
for key in ["generated_at", "generated_at_utc"]:
    data.pop(key, None)
with open(sys.argv[2], "w") as f:
    json.dump(data, f, indent=2, sort_keys=True)
NORM

    python3 - "$generated" "$generated_normalized" <<'NORM'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
# Remove timestamp fields that aren't derived from source
for key in ["generated_at", "generated_at_utc"]:
    data.pop(key, None)
with open(sys.argv[2], "w") as f:
    json.dump(data, f, indent=2, sort_keys=True)
NORM

    if ! diff -q "$committed_normalized" "$generated_normalized" > /dev/null 2>&1; then
        echo "FAIL: $name diverges from source regeneration"
        echo ""
        echo "=== DIFF (committed vs regenerated) ==="
        diff -u "$committed_normalized" "$generated_normalized" | head -100 || true
        echo ""
        echo "CRITICAL: Do NOT hand-edit $committed to fix this."
        echo "The only valid fix is: regenerate from source, commit the result."

        if [[ "$REGENERATE" == "true" ]]; then
            echo ""
            echo "Updating committed artifact (--regenerate mode)..."
            cp "$generated" "$committed"
            emit_event "info" "artifact_updated" "$name" "regenerated" "artifact updated from source"
            echo "Updated: $committed"
            return 0
        fi

        emit_event "error" "divergence" "$name" "fail" "committed differs from regenerated"
        return 1
    fi

    echo "PASS: $name matches source regeneration"
    emit_event "info" "check_passed" "$name" "pass" "committed matches regenerated"
    return 0
}

# Artifact definitions
REALITY_REPORT="$REPO_ROOT/tests/conformance/reality_report.v1.json"
MAINTENANCE_REPORT="$REPO_ROOT/tests/conformance/support_matrix_maintenance_report.v1.json"
HARD_PARTS_TRUTH="$REPO_ROOT/tests/conformance/hard_parts_truth_table.v1.json"
PROOF_OBLIGATIONS="$REPO_ROOT/tests/conformance/proof_obligations_binder.v1.json"

regenerate_reality_report() {
    # Use isolated target dir to avoid rustc version conflicts in multi-agent environment
    local isolated_target="${CARGO_TARGET_DIR:-$OUT_DIR/cargo_target}"
    mkdir -p "$isolated_target"
    CARGO_TARGET_DIR="$isolated_target" \
    RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR \
    rch exec -- cargo run --quiet -p frankenlibc-harness --bin harness -- \
        reality-report \
        --support-matrix "$REPO_ROOT/support_matrix.json" \
        --output "$GENERATED_ARTIFACT" 2>&1
}

regenerate_maintenance_report() {
    python3 "$SCRIPT_DIR/generate_support_matrix_maintenance.py" \
        -o "$GENERATED_ARTIFACT" 2>&1
}

regenerate_hard_parts_truth() {
    python3 "$SCRIPT_DIR/generate_hard_parts_truth_table.py" \
        -o "$GENERATED_ARTIFACT" 2>&1
}

regenerate_proof_obligations() {
    python3 "$SCRIPT_DIR/generate_proof_obligations_binder.py" \
        -o "$GENERATED_ARTIFACT" 2>&1
}

FAILED=0

run_check() {
    local name="$1"
    local committed="$2"
    local regen_fn="$3"

    if [[ -n "$TARGET_ARTIFACT" && "$TARGET_ARTIFACT" != "$name" ]]; then
        echo "Skipping $name (--artifact filter)"
        return 0
    fi

    if ! check_artifact "$name" "$committed" "$regen_fn"; then
        FAILED=$((FAILED + 1))
    fi
}

echo "=== Regenerate-Then-Diff Gate (bd-3yr14.5) ==="
echo "Trace ID: $TRACE_ID"
echo ""

run_check "reality_report" "$REALITY_REPORT" "regenerate_reality_report"
run_check "maintenance_report" "$MAINTENANCE_REPORT" "regenerate_maintenance_report"
run_check "hard_parts_truth" "$HARD_PARTS_TRUTH" "regenerate_hard_parts_truth"
run_check "proof_obligations" "$PROOF_OBLIGATIONS" "regenerate_proof_obligations"

echo ""
if [[ $FAILED -gt 0 ]]; then
    echo "=== GATE FAILED: $FAILED artifact(s) diverge from source ==="
    echo ""
    echo "To fix legitimately changed artifacts:"
    echo "  $0 --regenerate"
    echo "Then commit the updated artifacts with evidence ledger entry."
    exit 1
fi

echo "=== GATE PASSED: All artifacts match source regeneration ==="
emit_event "info" "gate_passed" "all" "pass" "all artifacts match"
exit 0
