#!/usr/bin/env bash
# check_runtime_math_admission.sh — CI gate for bd-3ot.3
# Validates runtime-math admission policy: governance + ablation evidence
# required for production controllers, retirement lockout for research modules.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Runtime-Math Admission Gate (bd-3ot.3) ==="

python3 "$SCRIPT_DIR/runtime_math_admission_gate.py"
rc=$?

REPORT="$REPO_ROOT/tests/runtime_math/admission_gate_report.v1.json"
if [ ! -f "$REPORT" ]; then
    echo "FAIL: admission gate report not generated"
    exit 2
fi

CONTROLLER_MANIFEST="$REPO_ROOT/tests/runtime_math/controller_manifest.v1.json"
if [ ! -f "$CONTROLLER_MANIFEST" ]; then
    echo "FAIL: controller manifest not generated"
    exit 2
fi

# Validate report structure
python3 - "$REPORT" "$CONTROLLER_MANIFEST" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    report = json.load(f)
with open(sys.argv[2]) as f:
    controller_manifest = json.load(f)

required = ["schema_version", "bead", "status", "summary",
            "policies_enforced", "admission_ledger", "findings",
            "feature_gate_config", "artifacts_consumed",
            "controller_manifest_summary", "artifacts_emitted"]
missing = [k for k in required if k not in report]
if missing:
    print(f"FAIL: report missing keys: {missing}")
    sys.exit(1)

s = report["summary"]
print(f"PASS: admission gate report validated")
print(f"  Total modules: {s.get('total_modules', 0)}")
print(f"  Admitted: {s.get('admitted', 0)}")
print(f"  Retired: {s.get('retired', 0)}")
print(f"  Blocked: {s.get('blocked', 0)}")
print(f"  Policies enforced: {len(report['policies_enforced'])}")

# Validate admission ledger entries
ledger = report.get("admission_ledger", [])
for entry in ledger:
    for key in ["module", "tier", "ablation_decision", "admission_status"]:
        if key not in entry:
            print(f"FAIL: ledger entry missing key '{key}': {entry}")
            sys.exit(1)

# Validate controller manifest structure
required_manifest_keys = ["schema_version", "bead", "summary", "controllers", "sources"]
missing_manifest_keys = [k for k in required_manifest_keys if k not in controller_manifest]
if missing_manifest_keys:
    print(f"FAIL: controller manifest missing keys: {missing_manifest_keys}")
    sys.exit(1)

controllers = controller_manifest.get("controllers", [])
if not isinstance(controllers, list) or not controllers:
    print("FAIL: controller manifest controllers must be a non-empty list")
    sys.exit(1)

for controller in controllers:
    for key in [
        "module",
        "tier",
        "decision_hook",
        "invariant",
        "fallback_when_data_missing",
        "runtime_cost_target",
    ]:
        if key not in controller:
            print(f"FAIL: controller entry missing key '{key}': {controller}")
            sys.exit(1)
PY
rc2=$?

if [ "$rc" -ne 0 ]; then
    echo "FAIL: admission gate found policy violations"
    exit 1
fi
if [ "$rc2" -ne 0 ]; then
    echo "FAIL: report validation failed"
    exit 1
fi

echo "check_runtime_math_admission: PASS"
