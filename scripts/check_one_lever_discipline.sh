#!/usr/bin/env bash
# One-lever discipline guard (bd-w2c3.8.2)
#
# Validates that every optimization opportunity:
#   1. Declares exactly one valid lever category.
#   2. Carries replayable golden-output metadata.
#   3. Carries single-lever rollback instructions.
#   4. Carries hotspot attribution metadata.
#   5. Does not mix lever categories without an explicit waiver.
#
# Usage: bash scripts/check_one_lever_discipline.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

DISCIPLINE_SPEC="$ROOT_DIR/tests/conformance/one_lever_discipline.json"
OPP_MATRIX="$ROOT_DIR/tests/conformance/opportunity_matrix.json"

FAILURES=0

echo "=== One-Lever Discipline Guard (bd-w2c3.8.2) ==="
echo

echo "--- Check 1: Discipline spec exists ---"
if [ ! -f "$DISCIPLINE_SPEC" ]; then
    echo "FAIL: $DISCIPLINE_SPEC not found"
    FAILURES=$((FAILURES + 1))
else
    if python3 -c "import json; json.load(open('$DISCIPLINE_SPEC'))" 2>/dev/null; then
        echo "PASS: Discipline spec is valid JSON"
    else
        echo "FAIL: Discipline spec is not valid JSON"
        FAILURES=$((FAILURES + 1))
    fi
fi

echo
echo "--- Check 2: Opportunity matrix exists ---"
if [ ! -f "$OPP_MATRIX" ]; then
    echo "FAIL: $OPP_MATRIX not found"
    FAILURES=$((FAILURES + 1))
else
    echo "PASS: Opportunity matrix exists"
fi

echo
echo "--- Check 3: Entries have valid lever + wave metadata ---"
python3 - "$DISCIPLINE_SPEC" "$OPP_MATRIX" "$ROOT_DIR" <<'PYTHON' || FAILURES=$((FAILURES + 1))
import json
import os
import sys

spec_path, matrix_path, root_dir = sys.argv[1], sys.argv[2], sys.argv[3]

with open(spec_path, "r", encoding="utf-8") as handle:
    spec = json.load(handle)
with open(matrix_path, "r", encoding="utf-8") as handle:
    matrix = json.load(handle)

valid_categories = set(spec["lever_categories"]["categories"].keys())
contract = spec["entry_contract"]
required_fields = contract["required_fields"]
golden_fields = contract["golden_output_verification_fields"]
rollback_fields = contract["rollback_instruction_fields"]
attribution_fields = contract["attribution_metadata_fields"]

entries = matrix.get("entries", [])
errors = []

for entry in entries:
    eid = entry.get("id", "?")
    lever = entry.get("lever_category")
    if lever is None:
        errors.append(f"{eid}: missing lever_category")
    elif lever not in valid_categories:
        errors.append(f"{eid}: invalid lever_category '{lever}'")

    for field in required_fields:
        if field not in entry:
            errors.append(f"{eid}: missing required wave field '{field}'")

    golden = entry.get("golden_output_verification", {})
    for field in golden_fields:
        if field not in golden:
            errors.append(f"{eid}: missing golden_output_verification.{field}")
    artifact_refs = golden.get("artifact_refs", [])
    if not artifact_refs:
        errors.append(f"{eid}: golden_output_verification.artifact_refs must not be empty")
    for ref in artifact_refs:
        if not os.path.exists(os.path.join(root_dir, ref)):
            errors.append(f"{eid}: golden artifact does not exist: {ref}")
    command = golden.get("verification_command", "").strip()
    if not command:
        errors.append(f"{eid}: verification_command must not be empty")
    invariants = golden.get("invariants", [])
    if not invariants:
        errors.append(f"{eid}: invariants must not be empty")

    rollback = entry.get("rollback_instructions", {})
    for field in rollback_fields:
        if field not in rollback:
            errors.append(f"{eid}: missing rollback_instructions.{field}")
    rollback_command = rollback.get("command", "")
    if "git revert" not in rollback_command:
        errors.append(f"{eid}: rollback command must contain 'git revert'")
    if not rollback.get("artifact_regeneration_commands"):
        errors.append(f"{eid}: artifact_regeneration_commands must not be empty")
    if not rollback.get("expected_revert_scope", "").strip():
        errors.append(f"{eid}: expected_revert_scope must not be empty")
    if not rollback.get("strategy", "").strip():
        errors.append(f"{eid}: strategy must not be empty")

    attribution = entry.get("attribution_metadata", {})
    for field in attribution_fields:
        if field not in attribution:
            errors.append(f"{eid}: missing attribution_metadata.{field}")
    if not attribution.get("opportunity_owner", "").strip():
        errors.append(f"{eid}: opportunity_owner must not be empty")
    if not attribution.get("selection_basis", "").strip():
        errors.append(f"{eid}: selection_basis must not be empty")
    for field in ("baseline_artifacts", "profile_artifacts"):
        refs = attribution.get(field, [])
        if not refs:
            errors.append(f"{eid}: attribution_metadata.{field} must not be empty")
            continue
        for ref in refs:
            if not os.path.exists(os.path.join(root_dir, ref)):
                errors.append(f"{eid}: attribution artifact does not exist: {ref}")

if errors:
    print(f"FAIL: found {len(errors)} entry metadata error(s)")
    for error in errors:
        print(f"  {error}")
    sys.exit(1)

print(f"PASS: All {len(entries)} entries have valid lever and wave metadata")
PYTHON

echo
echo "--- Check 4: No multi-lever beads without waiver ---"
python3 - "$OPP_MATRIX" <<'PYTHON' || FAILURES=$((FAILURES + 1))
import json
import sys
from collections import defaultdict

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    matrix = json.load(handle)

bead_levers = defaultdict(set)
entries = matrix.get("entries", [])
for entry in entries:
    bead = entry.get("bead_id")
    lever = entry.get("lever_category")
    if bead and lever:
        bead_levers[bead].add(lever)

violations = []
for bead, levers in bead_levers.items():
    if len(levers) > 1:
        has_waiver = any(
            entry.get("bead_id") == bead and entry.get("justification_waiver")
            for entry in entries
        )
        if not has_waiver:
            violations.append(f"{bead}: {sorted(levers)}")

if violations:
    print("FAIL: beads with multiple levers and no waiver:")
    for violation in violations:
        print(f"  {violation}")
    sys.exit(1)

print(f"PASS: All {len(bead_levers)} beads reference exactly one lever category")
PYTHON

echo
echo "--- Check 5: Summary matches the contract ---"
python3 - "$DISCIPLINE_SPEC" <<'PYTHON' || FAILURES=$((FAILURES + 1))
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    spec = json.load(handle)

summary = spec["summary"]
categories = spec["lever_categories"]["categories"]
required_fields = spec["entry_contract"]["required_fields"]

errors = []
if summary.get("total_categories") != len(categories):
    errors.append(
        f"total_categories claimed={summary.get('total_categories')} actual={len(categories)}"
    )
if summary.get("required_entry_fields") != len(required_fields):
    errors.append(
        "required_entry_fields "
        f"claimed={summary.get('required_entry_fields')} actual={len(required_fields)}"
    )

category_list = set(summary.get("category_list", []))
if category_list != set(categories.keys()):
    errors.append("category_list does not match the defined categories")

if errors:
    print(f"FAIL: found {len(errors)} summary mismatch(es)")
    for error in errors:
        print(f"  {error}")
    sys.exit(1)

print("PASS: Summary matches category and contract metadata")
PYTHON

echo
echo "=== Summary ==="
echo "Failures: $FAILURES"
echo
if [ "$FAILURES" -eq 0 ]; then
    echo "check_one_lever_discipline: PASS"
    exit 0
else
    echo "check_one_lever_discipline: FAIL"
    exit 1
fi
