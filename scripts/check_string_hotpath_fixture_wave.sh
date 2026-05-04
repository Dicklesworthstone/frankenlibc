#!/usr/bin/env bash
# check_string_hotpath_fixture_wave.sh -- bd-bp8fl.4.4 fixture scaling gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FRANKENLIBC_STRING_HOTPATH_WAVE:-${ROOT}/tests/conformance/string_hotpath_fixture_wave.v1.json}"
OUT_DIR="${FRANKENLIBC_STRING_HOTPATH_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_STRING_HOTPATH_REPORT:-${OUT_DIR}/string_hotpath_fixture_wave.report.json}"
LOG="${FRANKENLIBC_STRING_HOTPATH_LOG:-${OUT_DIR}/string_hotpath_fixture_wave.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]

errors = []
logs = []


def load(path, label):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label}: {path}: {exc}")
        return {}


def resolve(path_text):
    path = Path(str(path_text))
    return path if path.is_absolute() else root / path


manifest = load(manifest_path, "manifest")
if not isinstance(manifest, dict):
    manifest = {}

required_log_fields = [
    "trace_id",
    "bead_id",
    "family_id",
    "symbol",
    "fixture_id",
    "runner_kind",
    "runtime_mode",
    "oracle_kind",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
if manifest.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if manifest.get("bead_id") != "bd-bp8fl.4.4":
    errors.append("bead_id must be bd-bp8fl.4.4")
if manifest.get("campaign_id") != "fcq-string-memory-hotpaths":
    errors.append("campaign_id must be fcq-string-memory-hotpaths")
if manifest.get("required_log_fields") != required_log_fields:
    errors.append("required_log_fields mismatch")

fixture_path = resolve(manifest.get("fixture_path", ""))
test_path = resolve(manifest.get("test_path", ""))
coverage_paths = manifest.get("coverage_artifacts", {})
symbol_coverage_path = resolve(coverage_paths.get("symbol_fixture_coverage", ""))
per_symbol_path = resolve(coverage_paths.get("per_symbol_fixture_tests", ""))
prioritizer_path = resolve(coverage_paths.get("fixture_coverage_prioritizer", ""))

fixture = load(fixture_path, "fixture")
symbol_coverage = load(symbol_coverage_path, "symbol_fixture_coverage")
per_symbol = load(per_symbol_path, "per_symbol_fixture_tests")
prioritizer = load(prioritizer_path, "fixture_coverage_prioritizer")
test_text = ""
try:
    test_text = test_path.read_text(encoding="utf-8", errors="replace")
except Exception as exc:
    errors.append(f"test_path: {test_path}: {exc}")

covered_symbols = manifest.get("covered_symbols", [])
if not isinstance(covered_symbols, list) or not covered_symbols:
    errors.append("covered_symbols must be a non-empty array")
    covered_symbols = []
covered_symbols = [str(symbol) for symbol in covered_symbols]

cases = fixture.get("cases", []) if isinstance(fixture, dict) else []
case_by_symbol = {}
for case in cases:
    if isinstance(case, dict):
        case_by_symbol.setdefault(str(case.get("function", "")), []).append(case)

for symbol in covered_symbols:
    if symbol not in case_by_symbol:
        errors.append(f"{symbol}: missing fixture case")

runner = manifest.get("runner_evidence", {})
for token in runner.get("required_direct_tokens", []):
    if str(token) not in test_text:
        errors.append(f"direct runner token missing: {token}")
for token in runner.get("required_isolated_tokens", []):
    if str(token) not in test_text:
        errors.append(f"isolated runner token missing: {token}")

campaign = None
for row in prioritizer.get("campaigns", []):
    if isinstance(row, dict) and row.get("campaign_id") == manifest.get("campaign_id"):
        campaign = row
        break
if not isinstance(campaign, dict):
    errors.append("selected campaign missing from fixture coverage prioritizer")
else:
    if campaign.get("module") != "string_abi":
        errors.append("selected campaign module must be string_abi")
    if int(campaign.get("target_total", 0)) < 100:
        errors.append("selected campaign must remain high-count")
    if int(campaign.get("scores", {}).get("implementation_complexity_score", 99)) > 2:
        errors.append("selected campaign must remain low-risk implementation complexity")
    if campaign.get("scores", {}).get("hard_parts_risk_tags", []):
        errors.append("selected campaign must not consume hard-parts risk tags")

families = symbol_coverage.get("families", [])
string_family = None
for row in families:
    if isinstance(row, dict) and row.get("module") == "string_abi":
        string_family = row
        break
if not isinstance(string_family, dict):
    errors.append("symbol coverage missing string_abi family")
else:
    delta = manifest.get("coverage_delta", {})
    if int(string_family.get("target_covered", -1)) != int(delta.get("target_covered_after", -2)):
        errors.append("stale_artifact: string target_covered does not match manifest")
    if int(string_family.get("target_uncovered", -1)) != int(delta.get("target_uncovered_after", -2)):
        errors.append("stale_artifact: string target_uncovered does not match manifest")

coverage_by_symbol = {
    str(row.get("symbol", "")): row
    for row in symbol_coverage.get("symbols", [])
    if isinstance(row, dict)
}
per_symbol_rows = {
    str(row.get("symbol", "")): row
    for row in per_symbol.get("per_symbol_report", [])
    if isinstance(row, dict)
}
for symbol in covered_symbols:
    row = coverage_by_symbol.get(symbol)
    if not isinstance(row, dict) or row.get("covered") is not True:
        errors.append(f"stale_artifact: {symbol} is not covered in symbol_fixture_coverage")
    per_row = per_symbol_rows.get(symbol)
    if not isinstance(per_row, dict) or per_row.get("has_fixtures") is not True:
        errors.append(f"stale_artifact: {symbol} is not covered in per_symbol_fixture_tests")

artifact_refs = [
    str(manifest.get("fixture_path", "")),
    str(manifest.get("test_path", "")),
    str(coverage_paths.get("symbol_fixture_coverage", "")),
    str(coverage_paths.get("per_symbol_fixture_tests", "")),
    str(coverage_paths.get("fixture_coverage_prioritizer", "")),
]
for symbol in covered_symbols:
    for case in case_by_symbol.get(symbol, []):
        modes = ["strict", "hardened"] if str(case.get("mode", "")).lower() == "both" else [str(case.get("mode", ""))]
        for runner_kind in ["direct", "isolated"]:
            for runtime_mode in modes:
                logs.append(
                    {
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "trace_id": f"bd-bp8fl.4.4::{manifest.get('family_id')}::{symbol}::{runner_kind}::{runtime_mode}",
                        "bead_id": manifest.get("bead_id"),
                        "family_id": manifest.get("family_id"),
                        "symbol": symbol,
                        "fixture_id": case.get("name"),
                        "runner_kind": runner_kind,
                        "runtime_mode": runtime_mode,
                        "oracle_kind": manifest.get("oracle_kind"),
                        "expected": case.get("expected_output"),
                        "actual": "fixture_manifest_and_runner_binding_present",
                        "artifact_refs": artifact_refs,
                        "source_commit": source_commit,
                        "failure_signature": "ok",
                    }
                )

status = "fail" if errors else "pass"
if errors:
    logs.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": f"bd-bp8fl.4.4::{manifest.get('family_id')}::gate::fail",
            "bead_id": manifest.get("bead_id"),
            "family_id": manifest.get("family_id"),
            "symbol": "all",
            "fixture_id": manifest.get("family_id"),
            "runner_kind": "direct+isolated",
            "runtime_mode": "strict+hardened",
            "oracle_kind": manifest.get("oracle_kind"),
            "expected": "coverage snapshots current and runner bindings present",
            "actual": "; ".join(errors),
            "artifact_refs": artifact_refs,
            "source_commit": source_commit,
            "failure_signature": "stale_artifact",
        }
    )

report = {
    "schema_version": "v1",
    "bead_id": manifest.get("bead_id"),
    "family_id": manifest.get("family_id"),
    "campaign_id": manifest.get("campaign_id"),
    "status": status,
    "summary": {
        "covered_symbol_count": len(covered_symbols),
        "fixture_case_count": sum(len(case_by_symbol.get(symbol, [])) for symbol in covered_symbols),
        "log_row_count": len(logs),
        "target_covered_after": manifest.get("coverage_delta", {}).get("target_covered_after"),
        "target_uncovered_after": manifest.get("coverage_delta", {}).get("target_uncovered_after"),
    },
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in logs),
    encoding="utf-8",
)
if errors:
    raise SystemExit(1)
PY
