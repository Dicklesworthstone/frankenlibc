#!/usr/bin/env bash
# check_fixture_coverage_prioritizer.sh -- CI gate for bd-bp8fl.4.1
#
# Validates that the fixture coverage prioritizer is derived from the current
# support and fixture coverage artifacts, ranks campaigns deterministically, and
# emits report/log artifacts for closure evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${ROOT}/tests/conformance/fixture_coverage_prioritizer.v1.json"
COVERAGE="${ROOT}/tests/conformance/symbol_fixture_coverage.v1.json"
PER_SYMBOL="${ROOT}/tests/conformance/per_symbol_fixture_tests.v1.json"
SUPPORT="${ROOT}/support_matrix.json"
WORKLOADS="${ROOT}/tests/conformance/user_workload_acceptance_matrix.v1.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/fixture_coverage_prioritizer.report.json"
LOG="${OUT_DIR}/fixture_coverage_prioritizer.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${ARTIFACT}" "${COVERAGE}" "${PER_SYMBOL}" "${SUPPORT}" "${WORKLOADS}" "${REPORT}" "${LOG}" <<'PY'
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
report_path = Path(sys.argv[7])
log_path = Path(sys.argv[8])

errors = []
checks = {}

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
checks["json_parse"] = "pass" if all(isinstance(x, dict) for x in [artifact, coverage, per_symbol, support, workloads]) else "fail"
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

checks["campaign_schema"] = "pass" if campaign_ok else "fail"

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
summary_ok = (
    summary.get("campaign_count") == len(campaigns)
    and summary.get("total_first_wave_fixture_count") == first_wave_total
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
    "target/conformance/fixture_coverage_prioritizer.report.json",
    "target/conformance/fixture_coverage_prioritizer.log.jsonl",
]
report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.4.1",
    "status": status,
    "checks": checks,
    "campaign_count": len(campaigns),
    "total_first_wave_fixture_count": first_wave_total,
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

event = {
    "trace_id": "bd-bp8fl.4.1-fixture-coverage-prioritizer",
    "bead_id": "bd-bp8fl.4.1",
    "scenario_id": "fixture-coverage-prioritizer-gate",
    "runtime_mode": "not_applicable",
    "replacement_level": "L0,L1_planning",
    "api_family": "fixture_coverage_prioritizer",
    "symbol": "*",
    "oracle_kind": "coverage_gain_workload_risk_ranker",
    "expected": "campaigns rank uncovered exported-symbol fixture work by coverage gain and real workload risk",
    "actual": status,
    "errno": None,
    "decision_path": list(checks.keys()),
    "healing_action": "none",
    "latency_ns": 0,
    "artifact_refs": artifact_refs,
    "source_commit": source_commit,
    "target_dir": str(root / "target/conformance"),
    "failure_signature": "; ".join(errors),
    "campaign_count": len(campaigns),
    "total_first_wave_fixture_count": first_wave_total,
}
log_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
