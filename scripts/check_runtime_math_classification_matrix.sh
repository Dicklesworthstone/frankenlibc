#!/usr/bin/env bash
# check_runtime_math_classification_matrix.sh — Validate runtime-math classification matrix integrity.
#
# Ensures `tests/runtime_math/runtime_math_classification_matrix.v1.json` is consistent with:
#   - tests/conformance/math_governance.json
#   - tests/runtime_math/runtime_math_linkage.v1.json
#   - tests/runtime_math/production_kernel_manifest.v1.json
#
# Emits structured JSONL logs (one event per module) to:
#   target/conformance/runtime_math_classification_matrix.log.jsonl
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${ROOT}/tests/runtime_math/runtime_math_classification_matrix.v1.json"
GOVERNANCE="${ROOT}/tests/conformance/math_governance.json"
LINKAGE="${ROOT}/tests/runtime_math/runtime_math_linkage.v1.json"
MANIFEST="${ROOT}/tests/runtime_math/production_kernel_manifest.v1.json"
OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/runtime_math_classification_matrix.log.jsonl"
REPORT_PATH="${OUT_DIR}/runtime_math_classification_matrix.report.json"

mkdir -p "${OUT_DIR}"

export FLC_ROOT="${ROOT}"

python3 - <<'PY'
from __future__ import annotations
import json
import os
from pathlib import Path
from datetime import datetime, timezone

root = Path(os.environ["FLC_ROOT"])
matrix_path = root / "tests/runtime_math/runtime_math_classification_matrix.v1.json"
gov_path = root / "tests/conformance/math_governance.json"
link_path = root / "tests/runtime_math/runtime_math_linkage.v1.json"
man_path = root / "tests/runtime_math/production_kernel_manifest.v1.json"
log_path = root / "target/conformance/runtime_math_classification_matrix.log.jsonl"
report_path = root / "target/conformance/runtime_math_classification_matrix.report.json"

def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

matrix = load_json(matrix_path)
gov = load_json(gov_path)
link = load_json(link_path)
man = load_json(man_path)

errors: list[str] = []

def err(msg: str):
    errors.append(msg)

if matrix.get("schema_version") != "v1":
    err(f"matrix.schema_version must be 'v1', got {matrix.get('schema_version')!r}")

if not isinstance(matrix.get("modules"), list):
    err("matrix.modules must be an array")
    matrix_modules = []
else:
    matrix_modules = matrix["modules"]

# Build canonical maps from governance/linkage/manifest.
gov_map: dict[str, tuple[str, str, str]] = {}
for tier, entries in gov.get("classifications", {}).items():
    if not isinstance(entries, list):
        continue
    for i, entry in enumerate(entries):
        module = entry.get("module", "")
        rationale = entry.get("rationale", "")
        rationale_ref = f"tests/conformance/math_governance.json#/classifications/{tier}/{i}/rationale"
        if module:
            gov_map[module] = (tier, rationale, rationale_ref)

link_map: dict[str, tuple[str, str]] = {}
for module, meta in link.get("modules", {}).items():
    status = meta.get("linkage_status", "")
    target = meta.get("decision_target", "")
    link_map[module] = (status, target)

prod = set(man.get("production_modules", []))
research_only = set(man.get("research_only_modules", []))

expected_modules = set(gov_map) | set(link_map) | prod | research_only

seen: set[str] = set()
module_rows: dict[str, dict] = {}
allowed_classifications = {"production_core", "production_monitor", "research"}
allowed_linkage = {"Production", "ResearchOnly"}

events = []
ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

for row in matrix_modules:
    module = row.get("module")
    if not isinstance(module, str) or not module:
        err(f"matrix row has invalid module field: {row!r}")
        continue
    if module in seen:
        err(f"duplicate matrix row for module '{module}'")
        continue
    seen.add(module)
    module_rows[module] = row

    classification = row.get("classification")
    linkage_status = row.get("linkage_status")
    rationale = row.get("rationale")
    rationale_ref = row.get("rationale_ref")
    decision_target = row.get("decision_target")
    decision_target_ref = row.get("decision_target_ref")
    in_prod = row.get("in_production_manifest")
    in_research = row.get("in_research_only_manifest")
    transition = row.get("transition")

    if classification not in allowed_classifications:
        err(f"{module}: invalid classification {classification!r}")
    if linkage_status not in allowed_linkage:
        err(f"{module}: invalid linkage_status {linkage_status!r}")
    if not isinstance(rationale, str) or not rationale:
        err(f"{module}: missing/empty rationale")
    if not isinstance(rationale_ref, str) or not rationale_ref:
        err(f"{module}: missing/empty rationale_ref")
    if not isinstance(decision_target, str) or not decision_target:
        err(f"{module}: missing/empty decision_target")
    if not isinstance(decision_target_ref, str) or not decision_target_ref:
        err(f"{module}: missing/empty decision_target_ref")
    if not isinstance(in_prod, bool):
        err(f"{module}: in_production_manifest must be bool")
    if not isinstance(in_research, bool):
        err(f"{module}: in_research_only_manifest must be bool")

    if module not in gov_map:
        err(f"{module}: not present in governance classifications")
    else:
        exp_cls, exp_rationale, exp_rationale_ref = gov_map[module]
        if classification != exp_cls:
            err(f"{module}: classification mismatch matrix={classification} governance={exp_cls}")
        if rationale != exp_rationale:
            err(f"{module}: rationale mismatch against governance")
        if rationale_ref != exp_rationale_ref:
            err(f"{module}: rationale_ref mismatch matrix={rationale_ref} expected={exp_rationale_ref}")

    if module not in link_map:
        err(f"{module}: not present in linkage ledger")
    else:
        exp_status, exp_target = link_map[module]
        if linkage_status != exp_status:
            err(f"{module}: linkage_status mismatch matrix={linkage_status} linkage={exp_status}")
        if decision_target != exp_target:
            err(f"{module}: decision_target mismatch against linkage ledger")
        exp_target_ref = f"tests/runtime_math/runtime_math_linkage.v1.json#/modules/{module}/decision_target"
        if decision_target_ref != exp_target_ref:
            err(f"{module}: decision_target_ref mismatch matrix={decision_target_ref} expected={exp_target_ref}")

    if in_prod != (module in prod):
        err(f"{module}: in_production_manifest mismatch matrix={in_prod} manifest={module in prod}")
    if in_research != (module in research_only):
        err(f"{module}: in_research_only_manifest mismatch matrix={in_research} manifest={module in research_only}")

    if not isinstance(transition, dict):
        err(f"{module}: transition must be an object")
        transition = {}

    t_stage = transition.get("target_stage")
    t_note = transition.get("note")
    if classification == "research":
        if not isinstance(t_note, str) or not t_note.strip():
            err(f"{module}: research module requires non-empty transition.note")
        if t_stage not in {"research_only", "removed", "deprecated"}:
            err(f"{module}: research transition.target_stage must be research_only/deprecated/removed")
    else:
        if t_stage != "production":
            err(f"{module}: production tier must have transition.target_stage='production'")

    events.append({
        "timestamp": ts,
        "trace_id": f"rtm-classification-{module}",
        "level": "info",
        "event": "runtime_math.classification_decision",
        "module": module,
        "decision": classification,
        "linkage_status": linkage_status,
        "rationale_ref": rationale_ref,
        "decision_target_ref": decision_target_ref,
        "transition_stage": t_stage,
        "outcome": "pass",
    })

# Coverage checks.
if seen != expected_modules:
    missing = sorted(expected_modules - seen)
    extra = sorted(seen - expected_modules)
    if missing:
        err(f"matrix missing modules: {', '.join(missing)}")
    if extra:
        err(f"matrix has unexpected modules: {', '.join(extra)}")

# Summary checks.
summary = matrix.get("summary", {})
if not isinstance(summary, dict):
    err("matrix.summary must be an object")
    summary = {}

class_counts = {"production_core": 0, "production_monitor": 0, "research": 0}
link_counts = {"Production": 0, "ResearchOnly": 0}
for module in sorted(seen):
    row = module_rows[module]
    cls = row.get("classification")
    status = row.get("linkage_status")
    if cls in class_counts:
        class_counts[cls] += 1
    if status in link_counts:
        link_counts[status] += 1

if summary.get("total_modules") != len(seen):
    err(f"summary.total_modules mismatch matrix={summary.get('total_modules')} actual={len(seen)}")
if summary.get("classification_counts") != class_counts:
    err("summary.classification_counts mismatch")
if summary.get("linkage_status_counts") != link_counts:
    err("summary.linkage_status_counts mismatch")
if summary.get("production_manifest_modules") != len(prod):
    err("summary.production_manifest_modules mismatch")
if summary.get("research_only_manifest_modules") != len(research_only):
    err("summary.research_only_manifest_modules mismatch")
actual_research_in_prod = sum(
    1
    for module in seen
    if module_rows[module].get("classification") == "research" and module_rows[module].get("in_production_manifest")
)
if summary.get("research_modules_currently_in_production_manifest") != actual_research_in_prod:
    err("summary.research_modules_currently_in_production_manifest mismatch")

# Deterministic log output.
with log_path.open("w", encoding="utf-8") as f:
    for e in sorted(events, key=lambda x: x["module"]):
        f.write(json.dumps(e, separators=(",", ":")))
        f.write("\n")

report = {
    "ok": len(errors) == 0,
    "schema": matrix.get("schema_version"),
    "module_count": len(seen),
    "classification_counts": class_counts,
    "linkage_status_counts": link_counts,
    "errors": errors,
    "log_path": str(log_path.relative_to(root)),
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

if errors:
    print("FAIL: runtime_math classification matrix integrity errors:")
    for e in errors:
        print(f"  - {e}")
    print(f"Report: {report_path}")
    print(f"Structured logs: {log_path}")
    raise SystemExit(1)

print(
    "PASS: runtime_math classification matrix covers "
    f"{len(seen)} modules (core={class_counts['production_core']} monitor={class_counts['production_monitor']} research={class_counts['research']})."
)
print(f"Structured logs: {log_path}")
print(f"Report: {report_path}")
PY
