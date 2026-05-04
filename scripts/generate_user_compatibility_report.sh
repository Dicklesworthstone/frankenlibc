#!/usr/bin/env bash
# generate_user_compatibility_report.sh -- CI gate for bd-bp8fl.10.8
#
# Generates a user-facing compatibility report from workload, semantic,
# replacement, support, oracle, freshness, smoke, and performance evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_COMPATIBILITY_MANIFEST:-${ROOT}/tests/conformance/user_compatibility_report.v1.json}"
WORKLOAD_MATRIX="${FLC_COMPATIBILITY_WORKLOAD_MATRIX:-${ROOT}/tests/conformance/user_workload_acceptance_matrix.v1.json}"
ARTIFACT_PRECEDENCE="${FLC_COMPATIBILITY_ARTIFACT_PRECEDENCE:-${ROOT}/tests/conformance/artifact_precedence.v1.json}"
SEMANTIC_JOIN="${FLC_COMPATIBILITY_SEMANTIC_JOIN:-${ROOT}/tests/conformance/semantic_contract_symbol_join.v1.json}"
SUPPORT_MATRIX="${FLC_COMPATIBILITY_SUPPORT_MATRIX:-${ROOT}/support_matrix.json}"
ORACLE_PRECEDENCE="${FLC_COMPATIBILITY_ORACLE:-${ROOT}/tests/conformance/oracle_precedence_divergence.v1.json}"
REPLACEMENT_LEVELS="${FLC_COMPATIBILITY_REPLACEMENT_LEVELS:-${ROOT}/tests/conformance/replacement_levels.json}"
SMOKE_SUMMARY="${FLC_COMPATIBILITY_SMOKE_SUMMARY:-${ROOT}/tests/conformance/ld_preload_smoke_summary.v1.json}"
PERF_REPORT="${FLC_COMPATIBILITY_PERF_REPORT:-${ROOT}/tests/conformance/perf_regression_prevention.v1.json}"
README_PATH="${FLC_COMPATIBILITY_README:-${ROOT}/README.md}"
RELEASE_NOTES_PATH="${FLC_COMPATIBILITY_RELEASE_NOTES:-${ROOT}/CHANGELOG.md}"
OUT_DIR="${FLC_COMPATIBILITY_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${OUT_DIR}/user_compatibility_report.report.json"
LOG="${OUT_DIR}/user_compatibility_report.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${MANIFEST}" "${WORKLOAD_MATRIX}" "${ARTIFACT_PRECEDENCE}" "${SEMANTIC_JOIN}" "${SUPPORT_MATRIX}" "${ORACLE_PRECEDENCE}" "${REPLACEMENT_LEVELS}" "${SMOKE_SUMMARY}" "${PERF_REPORT}" "${README_PATH}" "${RELEASE_NOTES_PATH}" "${REPORT}" "${LOG}" <<'PY'
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
workload_path = Path(sys.argv[3])
artifact_precedence_path = Path(sys.argv[4])
semantic_join_path = Path(sys.argv[5])
support_matrix_path = Path(sys.argv[6])
oracle_path = Path(sys.argv[7])
replacement_path = Path(sys.argv[8])
smoke_path = Path(sys.argv[9])
perf_path = Path(sys.argv[10])
readme_path = Path(sys.argv[11])
release_notes_path = Path(sys.argv[12])
report_path = Path(sys.argv[13])
log_path = Path(sys.argv[14])

errors = []
checks = {}
events = []
report_rows = []
missing_evidence = []
stale_evidence = []
contradictory_evidence = []
prose_override_claims = []
unsupported_workloads = []


def rel(path):
    path = Path(path)
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def load_json(path, label):
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        errors.append(f"{label}: failed to parse {path}: {exc}")
        return None


def read_text(path, label):
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{label}: failed to read {path}: {exc}")
        return ""


def git_head():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def file_sha256(path):
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return "missing"


def get_field(data, dotted):
    value = data
    for part in str(dotted).split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


manifest = load_json(manifest_path, "compatibility_manifest") or {}
workload_matrix = load_json(workload_path, "workload_matrix") or {}
artifact_precedence = load_json(artifact_precedence_path, "artifact_precedence") or {}
semantic_join = load_json(semantic_join_path, "semantic_contract_symbol_join") or {}
support_matrix = load_json(support_matrix_path, "support_matrix") or {}
oracle_precedence = load_json(oracle_path, "oracle_precedence") or {}
replacement_levels = load_json(replacement_path, "replacement_levels") or {}
smoke_summary = load_json(smoke_path, "ld_preload_smoke_summary") or {}
perf_report = load_json(perf_path, "perf_regression_prevention") or {}
readme_text = read_text(readme_path, "README")
release_notes_text = read_text(release_notes_path, "release_notes")

source_commit = git_head()
artifact_refs = [
    rel(manifest_path),
    rel(workload_path),
    rel(artifact_precedence_path),
    rel(semantic_join_path),
    rel(support_matrix_path),
    rel(oracle_path),
    rel(replacement_path),
    rel(smoke_path),
    rel(perf_path),
    rel(readme_path),
    rel(release_notes_path),
]
trace_seed = "|".join(
    [
        manifest.get("bead", "bd-bp8fl.10.8"),
        source_commit,
        file_sha256(manifest_path),
        file_sha256(workload_path),
        file_sha256(semantic_join_path),
    ]
)
trace_id = hashlib.sha256(trace_seed.encode("utf-8")).hexdigest()[:20]


def event(
    report_id="user_compatibility_report",
    workload_id="",
    environment_id="",
    runtime_mode="",
    replacement_level="",
    oracle_kind="",
    expected_status="",
    actual_status="",
    freshness_state="",
    user_recommendation="",
    failure_signature="",
    status="pass",
):
    row = {
        "trace_id": trace_id,
        "bead_id": manifest.get("bead", "bd-bp8fl.10.8"),
        "report_id": report_id,
        "workload_id": workload_id,
        "environment_id": environment_id,
        "runtime_mode": runtime_mode,
        "replacement_level": replacement_level,
        "oracle_kind": oracle_kind,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "evidence_refs": artifact_refs,
        "freshness_state": freshness_state,
        "user_recommendation": user_recommendation,
        "source_commit": source_commit,
        "target_dir": rel(report_path.parent),
        "failure_signature": failure_signature,
        "status": status,
    }
    events.append(row)
    return row


def fail(message, failure_signature, workload_id="", expected="", actual="", freshness_state="fail"):
    errors.append(message)
    event(
        workload_id=workload_id,
        expected_status=expected,
        actual_status=actual,
        freshness_state=freshness_state,
        failure_signature=failure_signature,
        status="fail",
    )


required_log_fields = [
    "trace_id",
    "bead_id",
    "report_id",
    "workload_id",
    "environment_id",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "expected_status",
    "actual_status",
    "evidence_refs",
    "freshness_state",
    "user_recommendation",
    "source_commit",
    "target_dir",
    "failure_signature",
]

manifest_ok = True
if manifest.get("schema_version") != "v1" or manifest.get("bead") != "bd-bp8fl.10.8":
    manifest_ok = False
    fail(
        "manifest must declare schema_version=v1 and bead=bd-bp8fl.10.8",
        "manifest_shape",
        expected="v1/bd-bp8fl.10.8",
        actual=f"{manifest.get('schema_version')}/{manifest.get('bead')}",
    )
if manifest.get("required_log_fields") != required_log_fields:
    manifest_ok = False
    fail(
        "required_log_fields must match compatibility report log contract",
        "manifest_shape",
        expected=str(required_log_fields),
        actual=str(manifest.get("required_log_fields")),
    )
checks["manifest_shape"] = "pass" if manifest_ok else "fail"

workloads = workload_matrix.get("workloads", [])
if not isinstance(workloads, list) or not workloads:
    missing_evidence.append({"artifact": rel(workload_path), "reason": "workloads missing"})
    fail(
        "workload matrix must contain workloads",
        "missing_workload_evidence",
        expected="workloads[]",
        actual=str(type(workloads).__name__),
    )
    workloads = []

evidence_ok = True
fresh_evidence_count = 0
required_artifacts = [
    ("artifact_precedence", artifact_precedence, "schema_version"),
    ("semantic_contract_symbol_join", semantic_join, "summary.semantic_parity_blocker_count"),
    ("support_matrix", support_matrix, "counts.implemented"),
    ("oracle_precedence", oracle_precedence, "summary.oracle_kind_count"),
    ("replacement_levels", replacement_levels, "current_level"),
    ("ld_preload_smoke_summary", smoke_summary, "summary.overall_failed"),
    ("perf_regression_prevention", perf_report, "summary.total_issues"),
    ("workload_matrix", workload_matrix, "summary.workload_count"),
]
for artifact_id, artifact, required_field in required_artifacts:
    value = get_field(artifact, required_field)
    if value is None:
        evidence_ok = False
        missing_evidence.append({"artifact": artifact_id, "required_field": required_field})
        fail(
            f"{artifact_id}: missing required evidence field {required_field}",
            "missing_evidence",
            expected=required_field,
            actual="missing",
        )
    else:
        fresh_evidence_count += 1

current_level = replacement_levels.get("current_level")
current_release_level = get_field(replacement_levels, "release_tag_policy.current_release_level")
environment = manifest.get("environment", {})
environment_id = str(environment.get("environment_id", "host-l0-preload-current"))
replacement_level = str(environment.get("replacement_level", "L0"))
runtime_modes = [str(mode) for mode in environment.get("runtime_modes", ["strict", "hardened"])]
smoke_failed = get_field(smoke_summary, "summary.overall_failed")
perf_issues = get_field(perf_report, "summary.total_issues")
semantic_blockers = get_field(semantic_join, "summary.semantic_parity_blocker_count")
semantic_entries = semantic_join.get("entries", []) if isinstance(semantic_join, dict) else []

if current_level != current_release_level:
    evidence_ok = False
    stale_evidence.append({"artifact": "replacement_levels", "reason": "current_level mismatch"})
    fail(
        "replacement_levels current_level and release_tag_policy.current_release_level diverge",
        "stale_replacement_evidence",
        expected=str(current_level),
        actual=str(current_release_level),
    )
if current_level != replacement_level:
    unsupported_workloads.append({"reason": "environment replacement level not current", "expected": current_level, "actual": replacement_level})
    fail(
        "report environment replacement level must match current replacement level",
        "unsupported_replacement_level",
        expected=str(current_level),
        actual=replacement_level,
    )
if smoke_failed is not False:
    evidence_ok = False
    stale_evidence.append({"artifact": "ld_preload_smoke_summary", "reason": "overall_failed is not false"})
    fail(
        "ld_preload_smoke_summary must be green for L0 workload-ready claims",
        "stale_smoke_evidence",
        expected="overall_failed=false",
        actual=str(smoke_failed),
    )
if perf_issues != 0:
    evidence_ok = False
    stale_evidence.append({"artifact": "perf_regression_prevention", "reason": "performance issues present"})
    fail(
        "perf_regression_prevention must have zero issues",
        "stale_perf_evidence",
        expected="0",
        actual=str(perf_issues),
    )
if semantic_blockers != len(semantic_entries):
    evidence_ok = False
    contradictory_evidence.append(
        {
            "artifact": "semantic_contract_symbol_join",
            "expected": len(semantic_entries),
            "actual": semantic_blockers,
        }
    )
    fail(
        "semantic blocker count must match semantic join entries",
        "contradictory_semantic_support",
        expected=str(len(semantic_entries)),
        actual=str(semantic_blockers),
    )
if any(entry.get("taxonomy_status_is_semantic_parity") is not False for entry in semantic_entries):
    evidence_ok = False
    contradictory_evidence.append({"artifact": "semantic_contract_symbol_join", "reason": "taxonomy promoted to parity"})
    fail(
        "semantic join must keep taxonomy status separate from semantic parity",
        "contradictory_semantic_support",
        expected="taxonomy_status_is_semantic_parity=false",
        actual="true or missing",
    )

checks["evidence_freshness"] = "pass" if evidence_ok and not missing_evidence and not stale_evidence else "fail"
checks["semantic_support_consistency"] = "pass" if not contradictory_evidence else "fail"

for doc_label, doc_path, doc_text in [
    ("README", readme_path, readme_text),
    ("release notes", release_notes_path, release_notes_text),
]:
    for line_no, line in enumerate(doc_text.splitlines(), start=1):
        lowered = line.lower()
        for row in manifest.get("prose_forbidden_patterns", []):
            try:
                matched = re.search(str(row.get("pattern", "")), line, flags=re.IGNORECASE)
            except re.error as exc:
                fail(
                    f"invalid prose override regex {row.get('id')}: {exc}",
                    "prose_override_regex",
                    expected="valid regex",
                    actual=str(exc),
                )
                continue
            if not matched:
                continue
            allowed = any(str(token).lower() in lowered for token in row.get("allowed_if_line_contains", []))
            if allowed:
                continue
            finding = {
                "document": doc_label,
                "file_path": f"{rel(doc_path)}:{line_no}",
                "pattern_id": row.get("id"),
                "line": line.strip(),
            }
            prose_override_claims.append(finding)
            fail(
                f"{doc_label} prose attempts to override generated compatibility report at {rel(doc_path)}:{line_no}",
                "prose_override_claim",
                expected="generated report controls compatibility claims",
                actual=line.strip(),
            )
checks["prose_override_guard"] = "pass" if not prose_override_claims else "fail"

support_counts = support_matrix.get("counts", {}) if isinstance(support_matrix, dict) else {}
support_matrix_row = {
    "implemented": support_counts.get("implemented"),
    "raw_syscall": support_counts.get("raw_syscall"),
    "glibc_call_through": support_counts.get("glibc_call_through"),
    "stub": support_counts.get("stub"),
}
failure_bundle_refs = [
    rel(semantic_join_path),
    rel(smoke_path),
    rel(artifact_precedence_path),
]
performance_budget_refs = [rel(perf_path)]
semantic_summary = {
    "semantic_parity_blocker_count": semantic_blockers,
    "rows_where_taxonomy_status_is_not_parity": get_field(semantic_join, "summary.rows_where_taxonomy_status_is_not_parity"),
}

for workload in workloads:
    workload_id = str(workload.get("id", ""))
    modes = workload.get("runtime_modes", [])
    levels = workload.get("replacement_levels", [])
    if replacement_level not in levels:
        unsupported_workloads.append({"workload_id": workload_id, "reason": "missing replacement level"})
        fail(
            f"{workload_id}: missing current replacement level {replacement_level}",
            "unsupported_workload",
            workload_id=workload_id,
            expected=replacement_level,
            actual=str(levels),
        )
    if any(mode not in modes for mode in runtime_modes):
        unsupported_workloads.append({"workload_id": workload_id, "reason": "missing runtime modes"})
        fail(
            f"{workload_id}: missing runtime mode coverage",
            "unsupported_workload",
            workload_id=workload_id,
            expected=str(runtime_modes),
            actual=str(modes),
        )

    support_status = "ready_l0_with_limitations"
    semantic_status = "blocked_full_semantic_replacement"
    freshness_state = "current"
    user_recommendation = "try_l0_strict_or_hardened_with_limitations"
    known_limitations = [
        "Full standalone replacement is not supported by current L0 evidence.",
        f"{semantic_blockers} semantic parity blockers remain visible in semantic_contract_symbol_join.",
    ]
    if workload.get("negative_claim_tests"):
        known_limitations.append("Unsupported and missing-evidence claims remain blocked by workload negative tests.")

    row = {
        "workload_id": workload_id,
        "title": workload.get("title"),
        "environment_id": environment_id,
        "runtime_mode": runtime_modes,
        "replacement_level": replacement_level,
        "support_status": support_status,
        "semantic_status": semantic_status,
        "support_matrix_row": support_matrix_row,
        "oracle_kind": workload.get("oracle_kind"),
        "failure_bundle_refs": failure_bundle_refs,
        "performance_budget_refs": performance_budget_refs,
        "freshness_state": freshness_state,
        "known_limitations": known_limitations,
        "user_recommendation": user_recommendation,
        "regeneration_command": "scripts/generate_user_compatibility_report.sh",
        "evidence_refs": artifact_refs,
        "semantic_summary": semantic_summary,
    }
    report_rows.append(row)
    event(
        workload_id=workload_id,
        environment_id=environment_id,
        runtime_mode=",".join(runtime_modes),
        replacement_level=replacement_level,
        oracle_kind=str(workload.get("oracle_kind")),
        expected_status="ready_l0_with_limitations",
        actual_status=support_status,
        freshness_state=freshness_state,
        user_recommendation=user_recommendation,
    )

report_fields_ok = True
required_report_fields = set(manifest.get("required_report_fields", []))
for row in report_rows:
    missing = required_report_fields - set(row)
    if missing:
        report_fields_ok = False
        fail(
            f"{row.get('workload_id')}: generated report row missing {sorted(missing)}",
            "missing_report_field",
            workload_id=str(row.get("workload_id", "")),
            expected=str(sorted(required_report_fields)),
            actual=str(sorted(row)),
        )
checks["report_rendering"] = "pass" if report_fields_ok else "fail"

summary = {
    "workload_count": len(workloads),
    "report_row_count": len(report_rows),
    "fresh_evidence_count": fresh_evidence_count,
    "blocked_semantic_claim_count": len(
        [row for row in report_rows if row["semantic_status"] == "blocked_full_semantic_replacement"]
    ),
    "ready_l0_with_limitations_count": len(
        [row for row in report_rows if row["support_status"] == "ready_l0_with_limitations"]
    ),
    "unsupported_workload_count": len(unsupported_workloads),
    "missing_evidence_count": len(missing_evidence),
    "stale_evidence_count": len(stale_evidence),
    "contradictory_evidence_count": len(contradictory_evidence),
    "prose_override_claim_count": len(prose_override_claims),
}

expected_ok = True
if not errors:
    for key, expected_value in manifest.get("expected_current_summary", {}).items():
        if summary.get(key) != expected_value:
            expected_ok = False
            fail(
                f"summary mismatch for {key}",
                "stale_expected_summary",
                expected=str(expected_value),
                actual=str(summary.get(key)),
            )
checks["expected_current_summary"] = "pass" if expected_ok else "fail"

status = "pass" if all(value == "pass" for value in checks.values()) and not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": manifest.get("bead", "bd-bp8fl.10.8"),
    "report_id": "user_compatibility_report",
    "status": status,
    "checks": checks,
    "summary": summary,
    "environment": {
        "environment_id": environment_id,
        "runtime_mode": runtime_modes,
        "replacement_level": replacement_level,
    },
    "workloads": report_rows,
    "unsupported_workloads": unsupported_workloads,
    "missing_evidence": missing_evidence,
    "stale_evidence": stale_evidence,
    "contradictory_evidence": contradictory_evidence,
    "prose_override_claims": prose_override_claims,
    "artifact_refs": artifact_refs,
    "source_commit": source_commit,
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as fh:
    for row in events:
        fh.write(json.dumps(row, sort_keys=True) + "\n")

print(json.dumps(report, indent=2, sort_keys=True))
if status != "pass":
    sys.exit(1)
PY
