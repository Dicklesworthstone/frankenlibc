#!/usr/bin/env bash
# check_artifact_precedence.sh -- CI gate for bd-bp8fl.7.7
#
# Verifies that user-facing claims are backed by current, authoritative
# artifacts instead of prose-only or out-of-order evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_ARTIFACT_PRECEDENCE_MANIFEST:-${ROOT}/tests/conformance/artifact_precedence.v1.json}"
OUT_DIR="${FLC_ARTIFACT_PRECEDENCE_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${OUT_DIR}/artifact_precedence.report.json"
LOG="${OUT_DIR}/artifact_precedence.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" <<'PY'
import datetime as dt
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

errors = []
checks = {}
events = []
missing_artifacts = []
stale_artifacts = []
conflicting_claims = []
prose_only_claims = []
out_of_order_artifacts = []


def rel(path):
    path = Path(path)
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def resolve_path(value):
    path = Path(str(value))
    if path.is_absolute():
        return path
    return root / path


def load_json(path, label):
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        errors.append(f"{label}: failed to parse {path}: {exc}")
        return None


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


def parse_time(value):
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        return dt.datetime.fromisoformat(text)
    except Exception:
        return None


def get_field(data, dotted):
    value = data
    for part in str(dotted).split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


manifest = load_json(manifest_path, "artifact_precedence") or {}
source_commit = git_head()
trace_seed = "|".join(
    [
        manifest.get("bead", "bd-bp8fl.7.7"),
        source_commit,
        file_sha256(manifest_path),
    ]
)
trace_id = hashlib.sha256(trace_seed.encode("utf-8")).hexdigest()[:20]

artifact_refs = [rel(manifest_path)]
for artifact in manifest.get("artifacts", []):
    if isinstance(artifact, dict) and artifact.get("path"):
        artifact_refs.append(str(artifact.get("path")))


def event(
    rule_id,
    artifact_id="",
    artifact_type="",
    producer_bead="",
    consumer_claim="",
    freshness_state="",
    precedence_decision="",
    expected="",
    actual="",
    failure_signature="",
    status="pass",
):
    row = {
        "trace_id": trace_id,
        "bead_id": manifest.get("bead", "bd-bp8fl.7.7"),
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "producer_bead": producer_bead,
        "consumer_claim": consumer_claim,
        "freshness_state": freshness_state,
        "precedence_decision": precedence_decision,
        "expected": expected,
        "actual": actual,
        "artifact_refs": artifact_refs,
        "source_commit": source_commit,
        "target_dir": rel(report_path.parent),
        "failure_signature": failure_signature,
        "rule_id": rule_id,
        "status": status,
    }
    events.append(row)
    return row


def fail(rule_id, message, artifact=None, consumer_claim="", expected="", actual="", failure_signature=""):
    errors.append(message)
    artifact = artifact or {}
    event(
        rule_id,
        artifact_id=str(artifact.get("id", "")),
        artifact_type=str(artifact.get("artifact_type", "")),
        producer_bead=str(artifact.get("producer_bead", "")),
        consumer_claim=consumer_claim,
        freshness_state="fail",
        precedence_decision="block",
        expected=expected,
        actual=actual,
        failure_signature=failure_signature or rule_id,
        status="fail",
    )


required_log_fields = [
    "trace_id",
    "bead_id",
    "artifact_id",
    "artifact_type",
    "producer_bead",
    "consumer_claim",
    "freshness_state",
    "precedence_decision",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]

manifest_ok = True
if manifest.get("schema_version") != "v1" or manifest.get("bead") != "bd-bp8fl.7.7":
    manifest_ok = False
    fail(
        "manifest_shape",
        "manifest must declare schema_version=v1 and bead=bd-bp8fl.7.7",
        expected="schema_version=v1 bead=bd-bp8fl.7.7",
        actual=f"schema_version={manifest.get('schema_version')} bead={manifest.get('bead')}",
        failure_signature="manifest_shape",
    )
if manifest.get("required_log_fields") != required_log_fields:
    manifest_ok = False
    fail(
        "manifest_shape",
        "required_log_fields must match artifact precedence log contract",
        expected=str(required_log_fields),
        actual=str(manifest.get("required_log_fields")),
        failure_signature="manifest_shape",
    )
if not isinstance(manifest.get("artifacts"), list) or not isinstance(manifest.get("claims"), list):
    manifest_ok = False
    fail(
        "manifest_shape",
        "manifest must declare artifacts and claims arrays",
        expected="artifacts[] claims[]",
        actual=str(type(manifest.get("artifacts")).__name__),
        failure_signature="manifest_shape",
    )
checks["manifest_shape"] = "pass" if manifest_ok else "fail"
if manifest_ok:
    event("manifest_shape", freshness_state="current", precedence_decision="pass")

artifact_rows = manifest.get("artifacts", []) if isinstance(manifest.get("artifacts"), list) else []
claim_rows = manifest.get("claims", []) if isinstance(manifest.get("claims"), list) else []
artifact_by_id = {}
artifact_data = {}
artifact_ok = True

required_artifact_fields = [
    "id",
    "artifact_type",
    "path",
    "producer_bead",
    "consumer_surfaces",
    "authority_rank",
    "freshness_rule",
    "source_commit_required",
    "regeneration_command",
    "conflict_resolution",
]

for artifact in artifact_rows:
    if not isinstance(artifact, dict):
        artifact_ok = False
        fail("artifact_shape", "artifact row must be an object", failure_signature="artifact_shape")
        continue
    artifact_id = str(artifact.get("id", ""))
    for field in required_artifact_fields:
        if field not in artifact:
            artifact_ok = False
            fail(
                "artifact_shape",
                f"{artifact_id or '<missing-id>'}: missing artifact field {field}",
                artifact=artifact,
                expected=field,
                actual="missing",
                failure_signature="missing_artifact_field",
            )
    if not artifact_id:
        artifact_ok = False
        continue
    if artifact_id in artifact_by_id:
        artifact_ok = False
        fail(
            "artifact_shape",
            f"duplicate artifact id {artifact_id}",
            artifact=artifact,
            expected="unique id",
            actual=artifact_id,
            failure_signature="duplicate_artifact_id",
        )
    artifact_by_id[artifact_id] = artifact

    path = resolve_path(artifact.get("path", ""))
    if not path.exists():
        artifact_ok = False
        missing_artifacts.append({"artifact_id": artifact_id, "path": rel(path)})
        fail(
            "artifact_exists",
            f"{artifact_id}: missing artifact {rel(path)}",
            artifact=artifact,
            expected="path exists",
            actual=rel(path),
            failure_signature="missing_artifact",
        )
        continue

    if path.suffix == ".json":
        data = load_json(path, artifact_id)
        if data is None:
            artifact_ok = False
            stale_artifacts.append({"artifact_id": artifact_id, "reason": "malformed_json"})
            fail(
                "artifact_json_parse",
                f"{artifact_id}: malformed JSON",
                artifact=artifact,
                expected="valid JSON",
                actual=rel(path),
                failure_signature="malformed_artifact",
            )
            continue
        artifact_data[artifact_id] = data
        for field in artifact.get("required_json_fields", []):
            if get_field(data, field) is None:
                artifact_ok = False
                fail(
                    "artifact_required_fields",
                    f"{artifact_id}: missing required JSON field {field}",
                    artifact=artifact,
                    expected=field,
                    actual="missing",
                    failure_signature="missing_artifact_field",
                )
    else:
        artifact_data[artifact_id] = {"path": rel(path)}

checks["artifact_shape"] = "pass" if artifact_ok else "fail"


def mark_stale(artifact, reason, expected, actual):
    stale_artifacts.append({"artifact_id": artifact.get("id"), "reason": reason, "actual": actual})
    fail(
        "artifact_freshness",
        f"{artifact.get('id')}: {reason}",
        artifact=artifact,
        expected=str(expected),
        actual=str(actual),
        failure_signature=reason,
    )


freshness_ok = True
for artifact_id, artifact in artifact_by_id.items():
    if artifact_id not in artifact_data:
        freshness_ok = False
        continue
    data = artifact_data[artifact_id]
    rule = str(artifact.get("freshness_rule", "schema_version_current"))

    if artifact.get("source_commit_required") is True:
        expected_commit = str(artifact.get("expected_source_commit", source_commit))
        actual_commit = str(data.get("source_commit", source_commit)) if isinstance(data, dict) else source_commit
        if actual_commit != expected_commit:
            freshness_ok = False
            mark_stale(artifact, "source_commit_mismatch", expected_commit, actual_commit)

    min_generated_at = artifact.get("minimum_generated_at_utc")
    if min_generated_at and isinstance(data, dict):
        actual_time = (
            parse_time(data.get("generated_at_utc"))
            or parse_time(data.get("checked_at_utc"))
            or parse_time(data.get("generated_at"))
        )
        min_time = parse_time(min_generated_at)
        if actual_time is None or min_time is None or actual_time < min_time:
            freshness_ok = False
            mark_stale(artifact, "stale_artifact", min_generated_at, data.get("generated_at_utc") or data.get("checked_at_utc") or data.get("generated_at"))

    if rule == "current_release_level_matches_current_level":
        current = data.get("current_level")
        release = get_field(data, "release_tag_policy.current_release_level")
        if current != release:
            freshness_ok = False
            mark_stale(artifact, "replacement_level_mismatch", current, release)
    elif rule == "semantic_blockers_preserved":
        blockers = get_field(data, "summary.semantic_parity_blocker_count")
        entries = data.get("entries", []) if isinstance(data, dict) else []
        if blockers != len(entries):
            freshness_ok = False
            mark_stale(artifact, "semantic_join_stale", len(entries), blockers)
    elif rule == "audited_summary_matches_entries":
        summary_entries = get_field(data, "audited_summary.entries")
        entries = data.get("audited_entries", []) if isinstance(data, dict) else []
        if summary_entries != len(entries):
            freshness_ok = False
            mark_stale(artifact, "overlay_summary_stale", len(entries), summary_entries)
    elif rule == "status_counts_match_symbols":
        symbols = data.get("symbols", []) if isinstance(data, dict) else []
        counts = data.get("counts", {}) if isinstance(data, dict) else {}
        total = sum(value for value in counts.values() if isinstance(value, int))
        if total != len(symbols):
            freshness_ok = False
            mark_stale(artifact, "support_matrix_counts_stale", len(symbols), total)
    elif rule == "required_claim_fields_present":
        fields = data.get("required_claim_fields", []) if isinstance(data, dict) else []
        if len(fields) < 8:
            freshness_ok = False
            mark_stale(artifact, "docs_claim_fields_stale", ">=8", len(fields))
    elif rule == "expected_current_summary_matches_gate":
        expected = get_field(data, "expected_current_summary.duplicate_symbol_version_count")
        if expected != 0:
            freshness_ok = False
            mark_stale(artifact, "overlay_schema_summary_stale", 0, expected)
    elif rule == "status_pass_zero_findings":
        status = data.get("status") if isinstance(data, dict) else None
        findings = get_field(data, "summary.total_findings")
        if status != "pass" or findings != 0:
            freshness_ok = False
            mark_stale(artifact, "claim_reconciliation_stale", "pass/0 findings", f"{status}/{findings}")
    elif rule == "overall_failed_false":
        failed = get_field(data, "summary.overall_failed")
        if failed is not False:
            freshness_ok = False
            mark_stale(artifact, "smoke_summary_failed", False, failed)
    elif rule == "zero_perf_issues":
        issues = get_field(data, "summary.total_issues")
        if issues != 0:
            freshness_ok = False
            mark_stale(artifact, "perf_issues_present", 0, issues)

    event(
        "artifact_freshness",
        artifact_id=artifact_id,
        artifact_type=str(artifact.get("artifact_type")),
        producer_bead=str(artifact.get("producer_bead")),
        freshness_state="current",
        precedence_decision="allow",
        expected=str(artifact.get("freshness_rule")),
        actual="pass",
    )

checks["artifact_freshness"] = "pass" if freshness_ok and not missing_artifacts else "fail"

order_ok = True
for artifact_id, artifact in artifact_by_id.items():
    rank = artifact.get("authority_rank")
    for dep_id in artifact.get("depends_on_artifacts", []):
        dep = artifact_by_id.get(dep_id)
        if dep is None:
            order_ok = False
            missing_artifacts.append({"artifact_id": dep_id, "path": "<manifest dependency>"})
            fail(
                "artifact_dependency_order",
                f"{artifact_id}: missing dependency artifact {dep_id}",
                artifact=artifact,
                expected=dep_id,
                actual="missing",
                failure_signature="missing_artifact",
            )
            continue
        dep_rank = dep.get("authority_rank")
        if not isinstance(rank, int) or not isinstance(dep_rank, int) or dep_rank >= rank:
            order_ok = False
            finding = {"artifact_id": artifact_id, "depends_on": dep_id, "rank": rank, "dep_rank": dep_rank}
            out_of_order_artifacts.append(finding)
            fail(
                "artifact_dependency_order",
                f"{artifact_id}: dependency {dep_id} must have higher precedence than consumer artifact",
                artifact=artifact,
                expected=f"{dep_id} rank < {artifact_id} rank",
                actual=f"{dep_rank} >= {rank}",
                failure_signature="out_of_order_artifact",
            )
checks["artifact_dependency_order"] = "pass" if order_ok else "fail"

claims_ok = True
for claim in claim_rows:
    claim_id = str(claim.get("id", ""))
    consumer_claim = str(claim.get("consumer_claim", claim_id))
    auth_ids = [str(value) for value in claim.get("authoritative_artifact_ids", [])]
    if claim.get("prose_only_forbidden") is True and not auth_ids:
        claims_ok = False
        prose_only_claims.append({"claim_id": claim_id, "consumer_claim": consumer_claim})
        fail(
            "claim_precedence",
            f"{claim_id}: prose-only claim advancement is forbidden",
            consumer_claim=consumer_claim,
            expected="authoritative_artifact_ids",
            actual="[]",
            failure_signature="prose_only_claim",
        )
        continue

    ranks = {}
    for artifact_id in auth_ids:
        artifact = artifact_by_id.get(artifact_id)
        if artifact is None:
            claims_ok = False
            missing_artifacts.append({"artifact_id": artifact_id, "path": "<claim reference>"})
            fail(
                "claim_precedence",
                f"{claim_id}: missing authoritative artifact {artifact_id}",
                consumer_claim=consumer_claim,
                expected=artifact_id,
                actual="missing",
                failure_signature="missing_artifact",
            )
            continue
        rank = artifact.get("authority_rank")
        if rank in ranks:
            claims_ok = False
            finding = {"claim_id": claim_id, "rank": rank, "artifact_ids": [ranks[rank], artifact_id]}
            conflicting_claims.append(finding)
            fail(
                "claim_precedence",
                f"{claim_id}: conflicting artifacts share authority rank {rank}",
                artifact=artifact,
                consumer_claim=consumer_claim,
                expected="unique authority rank per claim",
                actual=f"{ranks[rank]} and {artifact_id}",
                failure_signature="conflicting_artifact",
            )
        else:
            ranks[rank] = artifact_id

    event(
        "claim_precedence",
        consumer_claim=consumer_claim,
        freshness_state="current",
        precedence_decision="allow",
        expected="authoritative artifacts present",
        actual=",".join(auth_ids),
    )

checks["claim_precedence"] = "pass" if claims_ok else "fail"

summary = {
    "artifact_count": len(artifact_rows),
    "claim_count": len(claim_rows),
    "missing_artifact_count": len(missing_artifacts),
    "stale_artifact_count": len(stale_artifacts),
    "conflicting_claim_count": len(conflicting_claims),
    "prose_only_claim_count": len(prose_only_claims),
    "out_of_order_artifact_count": len(out_of_order_artifacts),
}

expected_ok = True
if not errors:
    for key, expected_value in manifest.get("expected_current_summary", {}).items():
        if summary.get(key) != expected_value:
            expected_ok = False
            fail(
                "expected_current_summary",
                f"summary mismatch for {key}",
                expected=str(expected_value),
                actual=str(summary.get(key)),
                failure_signature="stale_expected_summary",
            )
checks["expected_current_summary"] = "pass" if expected_ok else "fail"

status = "pass" if all(value == "pass" for value in checks.values()) and not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": manifest.get("bead", "bd-bp8fl.7.7"),
    "status": status,
    "checks": checks,
    "summary": summary,
    "missing_artifacts": missing_artifacts,
    "stale_artifacts": stale_artifacts,
    "conflicting_claims": conflicting_claims,
    "prose_only_claims": prose_only_claims,
    "out_of_order_artifacts": out_of_order_artifacts,
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
