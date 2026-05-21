#!/usr/bin/env bash
# test_regenerate_then_diff_gate.sh — bd-3yr14.5 unit tests
# Tests the regenerate-then-diff gate behavior:
#   - Happy path: clean tree passes
#   - Edge: mutated source makes gate red
#   - Error: hand-edited artifact rejected
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$REPO_ROOT/target/conformance/regenerate_then_diff_tests"
GATE_SCRIPT="$SCRIPT_DIR/check_regenerate_then_diff_gate.sh"

# Use isolated target dir
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$OUT_DIR/cargo_target}"

PASSED=0
FAILED=0

test_case() {
    local name="$1"
    local expected_result="$2"
    shift 2
    local cmd="$*"

    echo ""
    echo "=== TEST: $name ==="
    echo "Expected: $expected_result"
    echo "Command: $cmd"

    local actual_result
    if eval "$cmd" > "$OUT_DIR/test_output.log" 2>&1; then
        actual_result="pass"
    else
        actual_result="fail"
    fi

    if [[ "$actual_result" == "$expected_result" ]]; then
        echo "PASSED: $name (result=$actual_result)"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED: $name (expected=$expected_result, got=$actual_result)"
        cat "$OUT_DIR/test_output.log" | head -30
        FAILED=$((FAILED + 1))
    fi
}

cleanup() {
    # Restore any modified files
    git checkout -- tests/conformance/hard_parts_truth_table.v1.json 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$OUT_DIR"

echo "=== Regenerate-Then-Diff Gate Unit Tests (bd-3yr14.5) ==="

# Test 1: Happy path - clean tree should pass
test_case "clean_tree_passes" "pass" \
    "bash $GATE_SCRIPT --artifact hard_parts_truth"

# Test 2: Mutated artifact should fail (simulating hand-edit)
echo ""
echo "=== Setting up mutation test ==="
cp "$REPO_ROOT/tests/conformance/hard_parts_truth_table.v1.json" "$OUT_DIR/original_hard_parts.json"
# Introduce a small mutation (change status)
python3 -c "
import json
with open('$REPO_ROOT/tests/conformance/hard_parts_truth_table.v1.json') as f:
    data = json.load(f)
data['subsystems'][0]['status'] = 'HAND_EDITED_STATUS'
with open('$REPO_ROOT/tests/conformance/hard_parts_truth_table.v1.json', 'w') as f:
    json.dump(data, f, indent=2)
"

test_case "hand_edited_artifact_rejected" "fail" \
    "bash $GATE_SCRIPT --artifact hard_parts_truth"

# Restore original
cp "$OUT_DIR/original_hard_parts.json" "$REPO_ROOT/tests/conformance/hard_parts_truth_table.v1.json"

# Test 3: After regeneration, gate should pass
test_case "after_restore_passes" "pass" \
    "bash $GATE_SCRIPT --artifact hard_parts_truth"

echo ""
echo "=== Test Summary ==="
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [[ $FAILED -gt 0 ]]; then
    echo "TESTS FAILED"
    exit 1
fi

echo "ALL TESTS PASSED"
exit 0
