#!/usr/bin/env bash
# check_controller_ablation.sh — CI gate for bd-3ot.2
# Validates controller ablation report: partition decisions,
# manifest/governance consistency, and migration plan.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Controller Ablation Gate (bd-3ot.2) ==="

python3 "$SCRIPT_DIR/controller_ablation.py"
rc=$?

REPORT="$REPO_ROOT/tests/runtime_math/controller_ablation_report.v1.json"
if [ ! -f "$REPORT" ]; then
    echo "FAIL: ablation report not generated"
    exit 2
fi

# Validate report structure
python3 - "$REPORT" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    report = json.load(f)

required = ["schema_version", "bead", "status", "summary",
            "partition_decisions", "migration_plan",
            "expected_research_annex_omissions", "findings"]
missing = [k for k in required if k not in report]
if missing:
    print(f"FAIL: report missing keys: {missing}")
    sys.exit(1)

s = report["summary"]
warnings = s.get("warnings")
if warnings != 0:
    print(f"FAIL: expected zero warnings, got {warnings!r}")
    sys.exit(1)
expected = report.get("expected_research_annex_omissions", {})
expected_count = expected.get("count")
retire_count = s.get("research_retire")
if expected_count != retire_count:
    print(
        "FAIL: expected_research_annex_omissions.count "
        f"{expected_count!r} != research_retire {retire_count!r}"
    )
    sys.exit(1)
modules = expected.get("modules")
if not isinstance(modules, list) or len(modules) != retire_count:
    print("FAIL: expected research-annex omissions must enumerate retired modules")
    sys.exit(1)
print(f"PASS: ablation report validated")
print(f"  Total modules: {s.get('total_modules', 0)}")
print(f"  Production retain: {s.get('production_retain', 0)}")
print(f"  Research retire: {s.get('research_retire', 0)}")
print(f"  Blocked: {s.get('blocked', 0)}")
print(f"  Migration plan: {report['migration_plan']['total_to_retire']} modules to retire")
PY
rc2=$?

if [ "$rc" -ne 0 ]; then
    echo "FAIL: controller ablation found errors"
    exit 1
fi
if [ "$rc2" -ne 0 ]; then
    echo "FAIL: report validation failed"
    exit 1
fi

echo "check_controller_ablation: PASS"
