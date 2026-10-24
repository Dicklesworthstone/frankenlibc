#!/usr/bin/env bash
# check_host_delegation_census.sh — CI gate for bd-smp21.1
#
# Validates that the canonical host-delegation census is regenerated from ABI
# source and still covers the required startup, dlfcn, and pthread anchors.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_host_delegation_census.py"
ARTIFACT="${ROOT}/tests/conformance/host_delegation_census.v1.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_HOST_DELEGATION_CENSUS_REPORT:-${OUT_DIR}/host_delegation_census.report.json}"
LOG="${FRANKENLIBC_HOST_DELEGATION_CENSUS_LOG:-${OUT_DIR}/host_delegation_census.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

(
  cd "${ROOT}"
  python3 "${GEN}" --self-test-cfg
  python3 "${GEN}" --output "${ARTIFACT}" --check
)

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
artifact_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])

artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
errors = []

if artifact.get("schema_version") != "host_delegation_census.v1":
    errors.append("schema_version_mismatch")
if artifact.get("bead") != "bd-smp21.1":
    errors.append("bead_mismatch")
if artifact.get("detector", {}).get("version") != 15:
    errors.append("detector_version_mismatch")

summary = artifact.get("summary", {})
symbols = artifact.get("symbol_census", [])
callsites = artifact.get("callsite_census", [])
anchors = artifact.get("required_anchor_symbols", [])
profiles = artifact.get("profile_census", {})

if summary.get("host_delegating_symbol_count") != len(symbols):
    errors.append("symbol_count_mismatch")
if summary.get("host_delegation_callsite_count") != len(callsites):
    errors.append("callsite_count_mismatch")
if summary.get("required_anchor_present_count") != len([row for row in anchors if row.get("present")]):
    errors.append("anchor_count_mismatch")

expected_profiles = {
    "interpose-release-linux-x86_64",
    "standalone-release-linux-x86_64",
}
if not isinstance(profiles, dict) or set(profiles) != expected_profiles:
    errors.append("profile_census_shape_mismatch")
    profiles = {}
for profile_name, profile in profiles.items():
    profile_summary = profile.get("summary", {})
    cfg_diagnostics = profile.get("cfg_diagnostics", [])
    dependencies = profile.get("host_dependencies_by_symbol", {})
    terminal_counts = profile.get("reachable_terminal_counts_by_symbol", {})
    terminal_sites = profile.get("terminal_host_callsites", [])
    unknown_samples = profile.get("unknown_reachable_call_edge_samples", [])
    blockers = profile.get("admission_blockers", [])
    coverage = profile.get("coverage", {})
    support_matrix_path = root / coverage.get("support_matrix_path", "")
    recorded_matrix_sha256 = coverage.get("support_matrix_sha256")
    if not support_matrix_path.is_file():
        errors.append(f"{profile_name}:support_matrix_missing")
    elif recorded_matrix_sha256 != hashlib.sha256(support_matrix_path.read_bytes()).hexdigest():
        errors.append(f"{profile_name}:support_matrix_hash_mismatch")
    if profile.get("cfg_diagnostic_count") != len(cfg_diagnostics):
        errors.append(f"{profile_name}:cfg_diagnostic_count_mismatch")
    if profile_summary.get("exported_symbol_with_host_dependency_count") != len(dependencies):
        errors.append(f"{profile_name}:host_dependency_symbol_count_mismatch")
    if set(dependencies) != set(terminal_counts):
        errors.append(f"{profile_name}:terminal_count_symbol_partition_mismatch")
    if profile_summary.get("unique_terminal_host_callsite_count") != len(terminal_sites):
        errors.append(f"{profile_name}:terminal_host_callsite_count_mismatch")
    unknown_count = profile_summary.get("unknown_reachable_call_edge_count")
    if not isinstance(unknown_count, int) or len(unknown_samples) > unknown_count:
        errors.append(f"{profile_name}:unknown_edge_sample_count_invalid")
    if profile_summary.get("standalone_admission_ready") != (not blockers):
        errors.append(f"{profile_name}:admission_blocker_mismatch")
    coverage_complete = (
        coverage.get("support_matrix_row_count", 0) > 0
        and coverage.get("missing_from_source_count") == 0
        and coverage.get("missing_from_support_matrix_count") == 0
        and not coverage.get("duplicate_source_symbols", [])
        and not coverage.get("duplicate_support_matrix_symbols", [])
    )
    if coverage.get("complete") != coverage_complete:
        errors.append(f"{profile_name}:coverage_completeness_mismatch")
    for site in terminal_sites:
        rel_path = site.get("path")
        line = site.get("line")
        if not isinstance(rel_path, str) or not isinstance(line, int) or line <= 0:
            errors.append(f"{profile_name}:terminal_site_bad_location")
            continue
        full_path = root / rel_path
        if not full_path.is_file():
            errors.append(f"{profile_name}:terminal_site_missing_file:{rel_path}")
            continue
        text_lines = full_path.read_text(encoding="utf-8").splitlines()
        if line > len(text_lines) or site.get("expression") not in text_lines[line - 1]:
            errors.append(f"{profile_name}:terminal_site_bad_line:{rel_path}:{line}")

missing_anchors = sorted(row.get("symbol") for row in anchors if not row.get("present"))
if missing_anchors:
    errors.append("missing_required_anchor:" + ",".join(missing_anchors))

symbol_set = {row.get("symbol") for row in symbols}
callsite_ids = set()
for row in symbols:
    symbol = row.get("symbol")
    ids = row.get("callsite_ids", [])
    if not symbol or not ids:
        errors.append(f"symbol_without_callsites:{symbol}")
    if row.get("callsite_count") != len(ids):
        errors.append(f"symbol_callsite_count_mismatch:{symbol}")
    callsite_ids.update(ids)

if len(callsite_ids) != len(callsites):
    errors.append("callsite_id_coverage_mismatch")

for row in callsites:
    if row.get("exported_symbol") not in symbol_set:
        errors.append(f"callsite_unknown_symbol:{row.get('id')}")
    rel_path = row.get("path")
    line = row.get("line")
    if not isinstance(rel_path, str) or not isinstance(line, int) or line <= 0:
        errors.append(f"callsite_bad_location:{row.get('id')}")
        continue
    full_path = root / rel_path
    if not full_path.is_file():
        errors.append(f"callsite_missing_file:{row.get('id')}")
        continue
    text_lines = full_path.read_text(encoding="utf-8").splitlines()
    if line > len(text_lines) or not text_lines[line - 1].strip():
        errors.append(f"callsite_bad_line:{row.get('id')}")

status = "fail" if errors else "pass"
report = {
    "schema_version": "host_delegation_census.report.v1",
    "bead": "bd-smp21.1",
    "status": status,
    "errors": errors,
    "summary": {
        "host_delegating_symbol_count": len(symbols),
        "host_delegation_callsite_count": len(callsites),
        "required_anchor_present_count": len([row for row in anchors if row.get("present")]),
        "profile_census": {
            name: profile.get("summary", {}) for name, profile in sorted(profiles.items())
        },
    },
    "artifact_refs": [str(artifact_path.relative_to(root)), str(report_path.relative_to(root)), str(log_path.relative_to(root))],
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
event = {
    "trace_id": "bd-smp21.1:host-delegation-census",
    "event": "host_delegation_census_validated",
    "bead": "bd-smp21.1",
    "status": status,
    "failure_signature": "none" if not errors else errors[0],
    "artifact_refs": report["artifact_refs"],
    "summary": report["summary"],
}
log_path.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

if errors:
    raise SystemExit("FAIL host delegation census: " + "; ".join(errors))
print(
    "PASS host delegation census "
    f"symbols={len(symbols)} callsites={len(callsites)} "
    f"anchors={report['summary']['required_anchor_present_count']} "
    f"standalone_host_symbols={profiles['standalone-release-linux-x86_64']['summary']['exported_symbol_with_host_dependency_count']}"
)
PY
