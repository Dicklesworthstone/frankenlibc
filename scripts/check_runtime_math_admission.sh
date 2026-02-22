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
LOG_PATH="$REPO_ROOT/target/conformance/runtime_math_admission_gate.log.jsonl"
if [ ! -f "$REPORT" ]; then
    echo "FAIL: admission gate report not generated"
    exit 2
fi

CONTROLLER_MANIFEST="$REPO_ROOT/tests/runtime_math/controller_manifest.v1.json"
if [ ! -f "$CONTROLLER_MANIFEST" ]; then
    echo "FAIL: controller manifest not generated"
    exit 2
fi
if [ ! -f "$LOG_PATH" ]; then
    echo "FAIL: admission gate structured log not generated"
    exit 2
fi

# Validate report structure
python3 - "$REPORT" "$CONTROLLER_MANIFEST" "$LOG_PATH" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    report = json.load(f)
with open(sys.argv[2]) as f:
    controller_manifest = json.load(f)
with open(sys.argv[3]) as f:
    lines = [line.strip() for line in f if line.strip()]

required = ["schema_version", "bead", "status", "summary",
            "policies_enforced", "admission_ledger", "findings",
            "feature_gate_config", "artifacts_consumed",
            "controller_manifest_summary", "artifacts_emitted",
            "artifact_integrity", "tooling_contract"]
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

tooling = report.get("tooling_contract", {})
required_tooling_true = [
    "has_asupersync_dependency",
    "asupersync_feature_present",
    "default_enables_asupersync_tooling",
    "frankentui_feature_present",
    "frankentui_dependency_set_complete",
]
for key in required_tooling_true:
    if tooling.get(key) is not True:
        print(f"FAIL: tooling_contract.{key} must be true")
        sys.exit(1)
if tooling.get("parse_error"):
    print(f"FAIL: tooling_contract.parse_error present: {tooling['parse_error']}")
    sys.exit(1)

integrity = report.get("artifact_integrity", {})
if not isinstance(integrity, dict) or not integrity:
    print("FAIL: artifact_integrity must be a non-empty object")
    sys.exit(1)
for expected in [
    "governance",
    "manifest",
    "ablation_report",
    "linkage",
    "value_proof",
    "harness_cargo_manifest",
]:
    if expected not in integrity:
        print(f"FAIL: artifact_integrity missing entry '{expected}'")
        sys.exit(1)
for name, meta in integrity.items():
    for key in ("path", "sha256", "size_bytes"):
        if key not in meta:
            print(f"FAIL: artifact_integrity.{name} missing key '{key}'")
            sys.exit(1)
    sha = meta["sha256"]
    if not isinstance(sha, str) or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha.lower()):
        print(f"FAIL: artifact_integrity.{name}.sha256 is not a 64-char hex digest")
        sys.exit(1)
    size = meta["size_bytes"]
    if not isinstance(size, int) or size <= 0:
        print(f"FAIL: artifact_integrity.{name}.size_bytes must be positive integer")
        sys.exit(1)

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

if not lines:
    print("FAIL: structured log is empty")
    sys.exit(1)
try:
    event = json.loads(lines[-1])
except json.JSONDecodeError as exc:
    print(f"FAIL: structured log line is not valid JSON: {exc}")
    sys.exit(1)

for key in [
    "trace_id",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
]:
    if key not in event:
        print(f"FAIL: structured log missing key '{key}'")
        sys.exit(1)
decision_path = event.get("decision_path", "")
if "integrity" not in decision_path or "tooling_contract" not in decision_path:
    print("FAIL: structured log decision_path must include integrity and tooling_contract stages")
    sys.exit(1)
print("PASS: admission gate structured log validated")
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
