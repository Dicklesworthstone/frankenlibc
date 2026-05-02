#!/usr/bin/env bash
# check_fixture_coverage_prioritizer.sh -- CI gate for bd-bp8fl.4.1
#
# Validates that the fixture coverage prioritizer is derived from the current
# support and fixture coverage artifacts, ranks campaigns deterministically, and
# emits report/log artifacts for closure evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_fixture_coverage_prioritizer.py"
ARTIFACT="${ROOT}/tests/conformance/fixture_coverage_prioritizer.v1.json"
COVERAGE="${ROOT}/tests/conformance/symbol_fixture_coverage.v1.json"
PER_SYMBOL="${ROOT}/tests/conformance/per_symbol_fixture_tests.v1.json"
SUPPORT="${ROOT}/support_matrix.json"
WORKLOADS="${ROOT}/tests/conformance/user_workload_acceptance_matrix.v1.json"
FEATURE_GAPS="${ROOT}/tests/conformance/feature_parity_gap_groups.v1.json"
OUT_DIR="${ROOT}/target/conformance"
GENERATED="${OUT_DIR}/fixture_coverage_prioritizer.regenerated.v1.json"
REPORT="${OUT_DIR}/fixture_coverage_prioritizer.report.json"
LOG="${OUT_DIR}/fixture_coverage_prioritizer.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 "${GEN}" --self-test >/dev/null
python3 "${GEN}" --output "${GENERATED}" >/dev/null
if ! cmp -s "${ARTIFACT}" "${GENERATED}"; then
    echo "ERROR: fixture coverage prioritizer artifact drift detected" >&2
    echo "       regenerate with: python3 scripts/generate_fixture_coverage_prioritizer.py --output tests/conformance/fixture_coverage_prioritizer.v1.json" >&2
    exit 1
fi

python3 - "${ROOT}" "${ARTIFACT}" "${COVERAGE}" "${PER_SYMBOL}" "${SUPPORT}" "${WORKLOADS}" "${FEATURE_GAPS}" "${REPORT}" "${LOG}" <<'PY'
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
coverage_path = Path(sys.argv[3])
per_symbol_path = Path(sys.argv[4])
support_path = Path(sys.argv[5])
workloads_path = Path(sys.argv[6])
feature_gaps_path = Path(sys.argv[7])
report_path = Path(sys.argv[8])
log_path = Path(sys.argv[9])

errors = []
checks = {}

EXPECTED_INPUTS = {
    "version_script": "crates/frankenlibc-abi/version_scripts/libc.map",
    "abi_symbol_universe": "tests/conformance/symbol_universe_normalization.v1.json",
    "support_matrix": "support_matrix.json",
    "semantic_overlay": "tests/conformance/support_semantic_overlay.v1.json",
    "semantic_contract_join": "tests/conformance/semantic_contract_symbol_join.v1.json",
    "symbol_fixture_coverage": "tests/conformance/symbol_fixture_coverage.v1.json",
    "per_symbol_fixture_tests": "tests/conformance/per_symbol_fixture_tests.v1.json",
    "user_workload_acceptance_matrix": "tests/conformance/user_workload_acceptance_matrix.v1.json",
    "hard_parts_truth_table": "tests/conformance/hard_parts_truth_table.v1.json",
    "hard_parts_failure_matrix": "tests/conformance/hard_parts_e2e_failure_matrix.v1.json",
    "feature_parity_gap_groups": "tests/conformance/feature_parity_gap_groups.v1.json",
}
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "symbol_family",
    "score",
    "rank",
    "coverage_state",
    "risk_factors",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_CAMPAIGN_FIELDS = [
    "rank",
    "campaign_id",
    "module",
    "title",
    "symbol_family",
    "target_total",
    "target_covered",
    "target_uncovered",
    "current_coverage_pct",
    "first_wave_symbols",
    "first_wave_fixture_count",
    "expected_coverage_after_first_wave_pct",
    "workload_domains",
    "risk_tags",
    "scores",
    "oracle_kind",
    "deterministic_e2e_scripts",
    "structured_log_fields",
    "next_step",
]
REQUIRED_DEFERRED_FIELDS = [
    "module",
    "target_total",
    "target_covered",
    "target_uncovered",
    "current_coverage_pct",
    "status_breakdown",
    "deferral_reason",
    "next_step",
]

def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return None

artifact = load_json(artifact_path)
coverage = load_json(coverage_path)
per_symbol = load_json(per_symbol_path)
support = load_json(support_path)
workloads = load_json(workloads_path)
feature_gaps = load_json(feature_gaps_path)
checks["json_parse"] = "pass" if all(isinstance(x, dict) for x in [artifact, coverage, per_symbol, support, workloads, feature_gaps]) else "fail"
if not isinstance(artifact, dict):
    artifact = {}
if not isinstance(coverage, dict):
    coverage = {}
if not isinstance(per_symbol, dict):
    per_symbol = {}
if not isinstance(support, dict):
    support = {}
if not isinstance(workloads, dict):
    workloads = {}
if not isinstance(feature_gaps, dict):
    feature_gaps = {}

if artifact.get("schema_version") == "v1" and artifact.get("bead") == "bd-bp8fl.4.1":
    checks["top_level_shape"] = "pass"
else:
    checks["top_level_shape"] = "fail"
    errors.append("artifact must declare schema_version=v1 and bead=bd-bp8fl.4.1")

if artifact.get("required_log_fields") == REQUIRED_LOG_FIELDS:
    checks["required_log_fields"] = "pass"
else:
    checks["required_log_fields"] = "fail"
    errors.append("required_log_fields must match the standard structured log contract")

inputs_ok = artifact.get("inputs") == EXPECTED_INPUTS
for key, rel_path in EXPECTED_INPUTS.items():
    if not (root / rel_path).exists():
        inputs_ok = False
        errors.append(f"declared input does not exist: {key}={rel_path}")
feature_axes = set(feature_gaps.get("required_grouping_axes", []))
feature_gap_summary = feature_gaps.get("summary", {})
feature_gap_ok = (
    feature_gaps.get("schema_version") == "v1"
    and feature_gaps.get("bead") == "bd-bp8fl.3.1"
    and feature_gap_summary.get("ledger_gap_count", 0) > 0
    and {"symbol_family", "source_owner", "evidence_artifacts", "priority"}.issubset(feature_axes)
)
if not inputs_ok:
    errors.append("inputs must exactly name the current coverage, support, workload, and feature-gap artifacts")
if not feature_gap_ok:
    errors.append("feature_parity_gap_groups input must be a live v1 gap grouping artifact with symbol/source/evidence/priority axes")
checks["inputs_and_feature_gap_refs"] = "pass" if inputs_ok and feature_gap_ok else "fail"

families = {family.get("module"): family for family in coverage.get("families", [])}
per_symbol_rows = per_symbol.get("per_symbol_report", [])
symbols_by_module = {}
for row in per_symbol_rows:
    symbols_by_module.setdefault(row.get("module"), {})[row.get("symbol")] = row
support_modules = {symbol.get("module") for symbol in support.get("symbols", [])}
required_domains = set(workloads.get("required_domains", []))

campaigns = artifact.get("campaigns", [])
campaign_ids = [campaign.get("campaign_id") for campaign in campaigns]
ranks = [campaign.get("rank") for campaign in campaigns]
modules = []
domain_coverage = Counter()
first_wave_total = 0
selected_target_uncovered = 0
campaign_ok = bool(campaigns) and len(campaign_ids) == len(set(campaign_ids)) and ranks == list(range(1, len(campaigns) + 1))

for campaign in campaigns:
    cid = campaign.get("campaign_id", "<missing campaign_id>")
    for field in REQUIRED_CAMPAIGN_FIELDS:
        if field not in campaign:
            campaign_ok = False
            errors.append(f"{cid}: missing field {field}")

    module = campaign.get("module")
    modules.append(module)
    if module not in families:
        campaign_ok = False
        errors.append(f"{cid}: module not in symbol fixture coverage: {module}")
        continue
    if module not in support_modules:
        campaign_ok = False
        errors.append(f"{cid}: module not in support_matrix symbols: {module}")

    family = families[module]
    for src_key, campaign_key in [
        ("target_total", "target_total"),
        ("target_covered", "target_covered"),
        ("target_uncovered", "target_uncovered"),
        ("target_coverage_pct", "current_coverage_pct"),
    ]:
        if campaign.get(campaign_key) != family.get(src_key):
            campaign_ok = False
            errors.append(f"{cid}: {campaign_key} does not match symbol_fixture_coverage")

    first_wave = campaign.get("first_wave_symbols", [])
    if len(first_wave) != len(set(first_wave)):
        campaign_ok = False
        errors.append(f"{cid}: first_wave_symbols contains duplicates")
    if campaign.get("first_wave_fixture_count") != len(first_wave):
        campaign_ok = False
        errors.append(f"{cid}: first_wave_fixture_count does not match first_wave_symbols length")
    first_wave_total += len(first_wave)

    uncovered_set = set(family.get("target_uncovered_symbols", []))
    for symbol in first_wave:
        if symbol not in uncovered_set:
            campaign_ok = False
            errors.append(f"{cid}: first-wave symbol is not currently uncovered: {symbol}")
        row = symbols_by_module.get(module, {}).get(symbol)
        if row is None:
            campaign_ok = False
            errors.append(f"{cid}: first-wave symbol not found in per-symbol report: {symbol}")
        elif row.get("has_fixtures"):
            campaign_ok = False
            errors.append(f"{cid}: first-wave symbol already has fixtures: {symbol}")

    expected_after = round((family.get("target_covered", 0) + len(first_wave)) * 100 / family.get("target_total", 1), 2)
    if campaign.get("expected_coverage_after_first_wave_pct") != expected_after:
        campaign_ok = False
        errors.append(f"{cid}: expected_coverage_after_first_wave_pct should be {expected_after}")

    scores = campaign.get("scores", {})
    expected_gap = min(family.get("target_uncovered", 0), 200)
    expected_priority = (
        expected_gap
        + 300 * scores.get("workload_risk_score", 0)
        + 200 * scores.get("parity_risk_score", 0)
        - 50 * scores.get("implementation_complexity_score", 0)
    )
    if scores.get("coverage_gap_score") != expected_gap:
        campaign_ok = False
        errors.append(f"{cid}: coverage_gap_score should be {expected_gap}")
    if scores.get("priority_score") != expected_priority:
        campaign_ok = False
        errors.append(f"{cid}: priority_score should be {expected_priority}")
    for key in ["workload_risk_score", "parity_risk_score"]:
        value = scores.get(key)
        if not isinstance(value, int) or value < 0 or value > 5:
            campaign_ok = False
            errors.append(f"{cid}: {key} must be an integer in 0..5")
    value = scores.get("implementation_complexity_score")
    if not isinstance(value, int) or value < 1 or value > 5:
        campaign_ok = False
        errors.append(f"{cid}: implementation_complexity_score must be an integer in 1..5")

    for script in campaign.get("deterministic_e2e_scripts", []):
        if not (root / script).exists():
            campaign_ok = False
            errors.append(f"{cid}: deterministic script does not exist: {script}")
    if campaign.get("structured_log_fields") != "required_log_fields":
        campaign_ok = False
        errors.append(f"{cid}: structured_log_fields must reference required_log_fields")
    if not campaign.get("workload_domains"):
        campaign_ok = False
        errors.append(f"{cid}: workload_domains must not be empty")
    for domain in campaign.get("workload_domains", []):
        domain_coverage[domain] += 1
    if not campaign.get("risk_tags"):
        campaign_ok = False
        errors.append(f"{cid}: risk_tags must not be empty")
    selected_target_uncovered += campaign.get("target_uncovered", 0)

checks["campaign_schema"] = "pass" if campaign_ok else "fail"

raw_deferred_modules = artifact.get("deferred_modules", [])
deferred_modules = raw_deferred_modules if isinstance(raw_deferred_modules, list) else []
uncovered_modules = {
    module
    for module, family in families.items()
    if family.get("target_uncovered", 0) > 0
}
selected_modules = set(modules)
expected_deferred_modules = sorted(
    uncovered_modules - selected_modules,
    key=lambda module: (-families[module].get("target_uncovered", 0), module),
)
actual_deferred_modules = [
    row.get("module") for row in deferred_modules if isinstance(row, dict)
]
deferred_target_uncovered = 0
deferred_ok = isinstance(raw_deferred_modules, list) and actual_deferred_modules == expected_deferred_modules
if not isinstance(raw_deferred_modules, list):
    errors.append("deferred_modules must be an array")
if actual_deferred_modules != expected_deferred_modules:
    deferred_ok = False
    errors.append("deferred_modules must cover every uncovered non-campaign module in target_uncovered desc order")

for row in deferred_modules:
    if not isinstance(row, dict):
        deferred_ok = False
        errors.append("deferred_modules entries must be objects")
        continue
    module = row.get("module", "<missing module>")
    for field in REQUIRED_DEFERRED_FIELDS:
        if field not in row:
            deferred_ok = False
            errors.append(f"{module}: missing deferred field {field}")
    if module in selected_modules:
        deferred_ok = False
        errors.append(f"{module}: selected campaign module cannot also be deferred")
    family = families.get(module)
    if family is None:
        deferred_ok = False
        errors.append(f"{module}: deferred module not found in symbol fixture coverage")
        continue
    if family.get("target_uncovered", 0) <= 0:
        deferred_ok = False
        errors.append(f"{module}: deferred module must still have uncovered target symbols")
    for src_key, row_key in [
        ("target_total", "target_total"),
        ("target_covered", "target_covered"),
        ("target_uncovered", "target_uncovered"),
        ("target_coverage_pct", "current_coverage_pct"),
        ("status_breakdown", "status_breakdown"),
    ]:
        if row.get(row_key) != family.get(src_key):
            deferred_ok = False
            errors.append(f"{module}: {row_key} does not match symbol_fixture_coverage")
    if not str(row.get("deferral_reason", "")).strip():
        deferred_ok = False
        errors.append(f"{module}: deferral_reason must be non-empty")
    if not str(row.get("next_step", "")).strip():
        deferred_ok = False
        errors.append(f"{module}: next_step must be non-empty")
    deferred_target_uncovered += row.get("target_uncovered", 0)

checks["deferred_module_inventory"] = "pass" if deferred_ok else "fail"

expected_order = sorted(
    campaigns,
    key=lambda campaign: (
        -campaign.get("scores", {}).get("priority_score", -1),
        -campaign.get("target_uncovered", -1),
        campaign.get("module", ""),
    ),
)
if [c.get("campaign_id") for c in campaigns] == [c.get("campaign_id") for c in expected_order]:
    checks["priority_order"] = "pass"
else:
    checks["priority_order"] = "fail"
    errors.append("campaigns are not sorted by priority_score desc, target_uncovered desc, module asc")

missing_required_domains = sorted(required_domains - set(domain_coverage))
if not missing_required_domains:
    checks["workload_domain_coverage"] = "pass"
else:
    checks["workload_domain_coverage"] = "fail"
    errors.append("missing required workload domains: " + ", ".join(missing_required_domains))

summary = artifact.get("summary", {})
all_uncovered_target_symbols = selected_target_uncovered + deferred_target_uncovered
summary_ok = (
    summary.get("campaign_count") == len(campaigns)
    and summary.get("deferred_module_count") == len(deferred_modules)
    and summary.get("total_first_wave_fixture_count") == first_wave_total
    and summary.get("selected_target_uncovered_symbols") == selected_target_uncovered
    and summary.get("deferred_target_uncovered_symbols") == deferred_target_uncovered
    and summary.get("all_uncovered_target_symbols") == all_uncovered_target_symbols
    and summary.get("covered_modules") == sorted(modules)
    and summary.get("required_workload_domains_covered") == sorted(required_domains)
    and summary.get("highest_priority_campaign") == campaigns[0].get("campaign_id")
    and summary.get("lowest_priority_campaign") == campaigns[-1].get("campaign_id")
)
checks["summary_counts"] = "pass" if summary_ok else "fail"
if not summary_ok:
    errors.append("summary counts do not match campaigns, modules, workload domains, and priority endpoints")

try:
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
except Exception:
    source_commit = "unknown"

status = "pass" if not errors else "fail"
artifact_refs = [
    "tests/conformance/fixture_coverage_prioritizer.v1.json",
    "tests/conformance/symbol_fixture_coverage.v1.json",
    "tests/conformance/per_symbol_fixture_tests.v1.json",
    "tests/conformance/feature_parity_gap_groups.v1.json",
    "target/conformance/fixture_coverage_prioritizer.regenerated.v1.json",
    "target/conformance/fixture_coverage_prioritizer.report.json",
    "target/conformance/fixture_coverage_prioritizer.log.jsonl",
]
report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.4.1",
    "status": status,
    "checks": checks,
    "campaign_count": len(campaigns),
    "deferred_module_count": len(deferred_modules) if isinstance(deferred_modules, list) else 0,
    "total_first_wave_fixture_count": first_wave_total,
    "selected_target_uncovered_symbols": selected_target_uncovered,
    "deferred_target_uncovered_symbols": deferred_target_uncovered,
    "all_uncovered_target_symbols": all_uncovered_target_symbols,
    "covered_modules": sorted(modules),
    "required_workload_domains_covered": sorted(required_domains),
    "missing_required_domains": missing_required_domains,
    "top_campaigns": [
        {
            "campaign_id": campaign.get("campaign_id"),
            "module": campaign.get("module"),
            "priority_score": campaign.get("scores", {}).get("priority_score"),
            "first_wave_fixture_count": campaign.get("first_wave_fixture_count"),
        }
        for campaign in campaigns[:5]
    ],
    "errors": errors,
    "artifact_refs": artifact_refs,
    "source_commit": source_commit,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def campaign_coverage_state(campaign):
    uncovered = campaign.get("target_uncovered", 0)
    covered = campaign.get("target_covered", 0)
    if uncovered == 0:
        return "covered"
    if covered == 0:
        return "uncovered"
    if campaign.get("current_coverage_pct", 0) < 80:
        return "weak"
    return "partial"

events = []
for campaign in campaigns:
    scores = campaign.get("scores", {})
    events.append(
        {
            "trace_id": "bd-bp8fl.4.1-fixture-coverage-prioritizer",
            "bead_id": "bd-bp8fl.4.1",
            "scenario_id": campaign.get("campaign_id"),
            "runtime_mode": "not_applicable",
            "replacement_level": "L0,L1_planning",
            "api_family": campaign.get("module"),
            "symbol": "*",
            "oracle_kind": campaign.get("oracle_kind"),
            "expected": "campaign ranks uncovered exported-symbol fixture work by coverage gain and real workload risk",
            "actual": status,
            "errno": None,
            "decision_path": list(checks.keys()),
            "healing_action": "none",
            "latency_ns": 0,
            "symbol_family": campaign.get("symbol_family"),
            "score": scores.get("priority_score"),
            "rank": campaign.get("rank"),
            "coverage_state": campaign_coverage_state(campaign),
            "risk_factors": {
                "risk_tags": campaign.get("risk_tags", []),
                "scores": scores,
                "workload_domains": campaign.get("workload_domains", []),
            },
            "artifact_refs": artifact_refs,
            "source_commit": source_commit,
            "target_dir": str(root / "target/conformance"),
            "failure_signature": "; ".join(errors),
            "campaign_count": len(campaigns),
            "deferred_module_count": len(deferred_modules) if isinstance(deferred_modules, list) else 0,
            "total_first_wave_fixture_count": first_wave_total,
            "selected_target_uncovered_symbols": selected_target_uncovered,
            "deferred_target_uncovered_symbols": deferred_target_uncovered,
        }
    )

log_path.write_text(
    "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
    encoding="utf-8",
)

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
