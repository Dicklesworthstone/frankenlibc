#!/usr/bin/env bash
# Release gate for replacement-level overclaims (bd-bp8fl.6.4).
#
# This gate intentionally passes for the current L0 release policy, but fails any
# L1/L2/L3 release tag or claim unless the matching evidence artifact is cited
# and currently proves the level is unblocked.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLAIMS_PATH=""
TAG="${FRANKENLIBC_RELEASE_TAG:-}"
REPORT_PATH="${FRANKENLIBC_RELEASE_CLAIM_REPORT:-${ROOT}/target/conformance/release_claim_evidence_gate.report.json}"
LOG_PATH="${FRANKENLIBC_RELEASE_CLAIM_LOG:-${ROOT}/target/conformance/release_claim_evidence_gate.log.jsonl}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --claims)
      CLAIMS_PATH="$2"
      shift 2
      ;;
    --tag)
      TAG="$2"
      shift 2
      ;;
    --report)
      REPORT_PATH="$2"
      shift 2
      ;;
    --log)
      LOG_PATH="$2"
      shift 2
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: scripts/release/check_replacement_claim_evidence.sh [--claims claims.json] [--tag vX.Y.Z-LN]

Inputs:
  --claims PATH  Optional JSON: {"claims":[{"id":"release","tag":"v0.1.0-L1","claimed_level":"L1","artifact_refs":[...]}]}
  --tag TAG      Optional release tag. The suffix -L0, -L1, -L2, or -L3 is parsed as the claimed level.

Outputs:
  target/conformance/release_claim_evidence_gate.report.json
  target/conformance/release_claim_evidence_gate.log.jsonl
USAGE
      exit 0
      ;;
    *)
      echo "FAIL: unknown argument $1" >&2
      exit 2
      ;;
  esac
done

mkdir -p "$(dirname "${REPORT_PATH}")" "$(dirname "${LOG_PATH}")"

python3 - "$ROOT" "$CLAIMS_PATH" "$TAG" "$REPORT_PATH" "$LOG_PATH" <<'PY'
import json
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
claims_path = sys.argv[2]
tag = sys.argv[3]
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])

bead_id = "bd-bp8fl.6.4"
default_max_evidence_age_days = 180
level_rank = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}
EXPECTED_L1_DASHBOARD_SOURCE_COMMIT_FRESHNESS_POLICY = {
    "recorded_source_commit_field": "source_commit",
    "current_head_check": "git rev-parse HEAD",
    "fresh_result": "eligible_for_row_evaluation_only",
    "stale_result": "report_blockers_no_auto_promotion",
    "promotion_allowed_when_stale": False,
    "rejected_evidence_kind": "stale_source_commit",
}


def artifact_path(env_name, default):
    override = os.environ.get(env_name)
    path = Path(override) if override else Path(default)
    return path if path.is_absolute() else root / path


levels_path = artifact_path(
    "FRANKENLIBC_REPLACEMENT_LEVELS",
    "tests/conformance/replacement_levels.json",
)
l1_matrix_path = artifact_path(
    "FRANKENLIBC_L1_PROOF_MATRIX",
    "tests/conformance/l1_crt_startup_tls_proof_matrix.v1.json",
)
l1_dashboard_path = artifact_path(
    "FRANKENLIBC_L1_DRY_RUN_DASHBOARD",
    "tests/conformance/l1_dry_run_readiness_dashboard.v1.json",
)
standalone_matrix_path = artifact_path(
    "FRANKENLIBC_STANDALONE_PROOF_MATRIX",
    "tests/conformance/standalone_readiness_proof_matrix.v1.json",
)
support_matrix_path = artifact_path("FRANKENLIBC_SUPPORT_MATRIX", "support_matrix.json")
compatibility_report_path = artifact_path(
    "FRANKENLIBC_COMPATIBILITY_REPORT",
    "tests/conformance/claim_reconciliation_report.v1.json",
)
readme_path = artifact_path("FRANKENLIBC_README", "README.md")


def load_json(path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def parse_tag_level(value):
    match = re.search(r"-L([0-3])(?:$|[^0-9])", value or "")
    return f"L{match.group(1)}" if match else None


def rel(path):
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def source_commit():
    override = os.environ.get("SOURCE_COMMIT")
    if override:
        return override
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def load_claims(levels):
    if claims_path:
        data = load_json(Path(claims_path))
        claims = data.get("claims")
        if not isinstance(claims, list):
            raise SystemExit("FAIL: claims JSON must contain a claims array")
        return claims
    if tag:
        return [
            {
                "id": "release-tag",
                "tag": tag,
                "claimed_level": parse_tag_level(tag),
                "artifact_refs": [rel(levels_path)],
            }
        ]
    policy = levels.get("release_tag_policy", {})
    claimed_level = policy.get("current_release_level", "L0")
    artifact_refs = current_release_policy_refs(levels, claimed_level)
    return [
        {
            "id": "current-release-policy",
            "tag": policy.get("current_release_tag_example", ""),
            "claimed_level": claimed_level,
            "artifact_refs": artifact_refs,
        }
    ]


def current_release_policy_refs(levels, claimed_level):
    refs = [rel(levels_path)]
    if claimed_level in ("L1", "L2", "L3"):
        for level in levels.get("levels", []):
            if not isinstance(level, dict) or level.get("level") != claimed_level:
                continue
            bundle = level.get("objective_gate", {}).get("evidence_bundle", {})
            refs.extend(str(ref) for ref in bundle.get("artifact_refs", []) if ref)
            break
        refs.extend(
            [
                rel(support_matrix_path),
                rel(compatibility_report_path),
                rel(l1_matrix_path),
            ]
        )
    if claimed_level in ("L2", "L3"):
        refs.append(rel(standalone_matrix_path))
    return list(dict.fromkeys(refs))


def cited(claim, artifact):
    refs = claim.get("artifact_refs", [])
    return artifact in refs or str(root / artifact) in refs


def parse_timestamp(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def generated_at(data):
    for key in ("generated_utc", "generated_at_utc", "generated_at", "source_generated_at_utc"):
        parsed = parse_timestamp(data.get(key))
        if parsed is not None:
            return parsed
    ground_truth = data.get("ground_truth")
    if isinstance(ground_truth, dict):
        parsed = parse_timestamp(ground_truth.get("generated_at"))
        if parsed is not None:
            return parsed
    return None


def stale_evidence_errors(data, label, max_age_days):
    stamp = generated_at(data)
    if stamp is None:
        return []
    now = datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    age_days = (now - stamp).total_seconds() / 86400
    if age_days > max_age_days:
        return [f"release_claim_stale_{label}_evidence"]
    return []


def full_git_commit(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def l1_dashboard_source_commit_errors(dashboard):
    errors = []
    if (
        dashboard.get("source_commit_freshness_policy")
        != EXPECTED_L1_DASHBOARD_SOURCE_COMMIT_FRESHNESS_POLICY
    ):
        errors.append("release_claim_l1_dashboard_source_commit_policy_invalid")
    dashboard_commit = dashboard.get("source_commit")
    if dashboard_commit == "current":
        return errors
    if not full_git_commit(dashboard_commit):
        errors.append("release_claim_l1_dashboard_source_commit_invalid")
        return errors
    if commit == "unknown":
        errors.append("release_claim_l1_dashboard_source_commit_unknown")
        return errors
    if dashboard_commit != commit:
        errors.append("release_claim_l1_dashboard_source_commit_stale")
    return errors


def l1_matrix_source_commit_errors(matrix):
    matrix_commit = matrix.get("source_commit")
    if matrix_commit == "current":
        return []
    if not full_git_commit(matrix_commit):
        return ["release_claim_l1_matrix_source_commit_invalid"]
    if commit == "unknown":
        return ["release_claim_l1_matrix_source_commit_unknown"]
    if matrix_commit != commit:
        errors = ["release_claim_l1_matrix_source_commit_stale"]
        freshness_policy = matrix.get("source_commit_freshness_policy", {})
        if not isinstance(freshness_policy, dict):
            errors.append("release_claim_l1_matrix_source_commit_policy_invalid")
        else:
            if freshness_policy.get("recorded_source_commit_field") != "source_commit":
                errors.append("release_claim_l1_matrix_source_commit_policy_invalid")
            if freshness_policy.get("comparison_target") != "current git HEAD":
                errors.append("release_claim_l1_matrix_source_commit_policy_invalid")
            if (
                freshness_policy.get("stale_result")
                != "block_l1_crt_startup_tls_proof_matrix_evidence"
            ):
                errors.append("release_claim_l1_matrix_source_commit_policy_invalid")
            if (
                freshness_policy.get("startup_tls_matrix_evidence_allowed_when_stale")
                is not False
            ):
                errors.append("release_claim_l1_matrix_source_commit_policy_invalid")
            if freshness_policy.get("rejected_evidence_kind") != "stale_source_commit":
                errors.append("release_claim_l1_matrix_source_commit_policy_invalid")
        return errors
    return []


def select_field(data, field_path):
    cursor = data
    for segment in str(field_path).split("."):
        if not isinstance(cursor, dict) or segment not in cursor:
            return None
        cursor = cursor[segment]
    return cursor


def standalone_readiness_text(text):
    if not isinstance(text, str):
        return False
    normalized = " ".join(text.lower().split())
    patterns = [
        r"\b(is|are|now|today|ready)\s+(a\s+)?(full\s+)?standalone\s+(libc\s+)?replacement\b",
        r"\bready\s+as\s+a\s+(full\s+)?standalone\s+(libc\s+)?replacement\b",
        r"\b(is|are|now|today|ready)\s+(a\s+)?drop-in\s+replacement\s+for\s+glibc\b",
        r"\bstandalone\s+(libc\s+)?replacement\s+(is\s+)?(ready|supported|available|complete|done)\b",
        r"\bdrop-in\s+replacement\s+(is\s+)?(ready|supported|available|complete|done)\b",
        r"\bcan\s+replace\s+glibc\s+(today|now|as\s+a\s+standalone)\b",
    ]
    return any(re.search(pattern, normalized) for pattern in patterns)


def claim_doc_texts(claim):
    values = []
    for key in ("claim_text", "text", "summary"):
        value = claim.get(key)
        if isinstance(value, str):
            values.append(value)
    doc_claims = claim.get("doc_claims")
    if isinstance(doc_claims, list):
        for doc_claim in doc_claims:
            if isinstance(doc_claim, dict):
                text = doc_claim.get("claim_text") or doc_claim.get("text")
                if isinstance(text, str):
                    values.append(text)
            elif isinstance(doc_claim, str):
                values.append(doc_claim)
    return values


def claim_implies_standalone_readiness(claim):
    return any(standalone_readiness_text(text) for text in claim_doc_texts(claim))


def support_matrix_counts(data):
    counts = Counter()
    if isinstance(data.get("counts"), dict):
        for key, value in data["counts"].items():
            normalized = {
                "implemented": "Implemented",
                "raw_syscall": "RawSyscall",
                "wraps_host_libc": "WrapsHostLibc",
                "glibc_call_through": "GlibcCallThrough",
                "stub": "Stub",
            }.get(str(key), str(key))
            counts[normalized] += int(value)
    for symbol in data.get("symbols", []):
        status = symbol.get("status")
        if status is not None:
            counts[str(status)] += 1
    return counts


def support_matrix_errors(claim, level):
    errors = []
    support_ref = rel(support_matrix_path)
    if not cited(claim, support_ref):
        return ["release_claim_missing_support_matrix_evidence"]
    matrix = load_json(support_matrix_path)
    errors.extend(
        stale_evidence_errors(matrix, "support_matrix", default_max_evidence_age_days)
    )
    counts = support_matrix_counts(matrix)
    if counts.get("Stub", 0) > 0:
        errors.append("release_claim_support_matrix_stubs_present")
    if level in ("L2", "L3"):
        host_bound = counts.get("WrapsHostLibc", 0) + counts.get("GlibcCallThrough", 0)
        if host_bound > 0:
            errors.append("release_claim_support_matrix_host_bound_symbols_present")
    return errors


def compatibility_report_errors(claim):
    compatibility_ref = rel(compatibility_report_path)
    if not cited(claim, compatibility_ref):
        return ["release_claim_missing_compatibility_report_evidence"]
    report = load_json(compatibility_report_path)
    errors = stale_evidence_errors(
        report, "compatibility_report", default_max_evidence_age_days
    )
    if report.get("status") != "pass":
        errors.append("release_claim_compatibility_report_not_pass")
    summary = report.get("summary", {})
    if summary.get("critical", 0) != 0 or summary.get("errors", 0) != 0:
        errors.append("release_claim_compatibility_report_findings_present")
    return errors


def readme_claim_errors(current_release_level):
    if not readme_path.exists():
        return ["release_claim_readme_missing"]
    text = readme_path.read_text(encoding="utf-8")
    matches = re.findall(r"Declared replacement level claim: \*\*(L[0-3])", text)
    for level in matches:
        if level_rank[level] > level_rank[current_release_level]:
            return ["release_claim_readme_overclaims_current_release_level"]
    if standalone_readiness_text(text):
        return ["release_claim_readme_standalone_readiness_requires_l1_dashboard"]
    return []


def doc_claim_errors(claim):
    if claim_implies_standalone_readiness(claim):
        return ["release_claim_doc_standalone_readiness_requires_l1_dashboard"]
    return []


def l1_evidence_errors(claim, current_level, current_release_level):
    errors = []
    l1_ref = rel(l1_matrix_path)
    if not cited(claim, l1_ref):
        errors.append("release_claim_missing_l1_evidence")
        return errors
    if level_rank[current_level] < level_rank["L1"]:
        errors.append("release_claim_above_current_level")
    if level_rank[current_release_level] < level_rank["L1"]:
        errors.append("release_claim_above_current_release_level")
    matrix = load_json(l1_matrix_path)
    policy = matrix.get("claim_policy", {})
    summary = matrix.get("summary", {})
    max_age_days = int(policy.get("max_evidence_age_days", default_max_evidence_age_days))
    errors.extend(l1_matrix_source_commit_errors(matrix))
    errors.extend(stale_evidence_errors(matrix, "l1", max_age_days))
    if policy.get("current_claim_status") == "blocked":
        errors.append("release_claim_l1_policy_blocked")
    if summary.get("current_gate_status") != "pass":
        errors.append("release_claim_l1_gate_not_pass")
    if summary.get("blocked_row_count", 0) != 0:
        errors.append("release_claim_l1_blocked_rows_present")
    return errors


def l1_dashboard_errors(claim):
    errors = []
    dashboard_ref = rel(l1_dashboard_path)
    if not cited(claim, dashboard_ref):
        return ["release_claim_missing_l1_dry_run_dashboard_evidence"]

    dashboard = load_json(l1_dashboard_path)
    policy = dashboard.get("policy", {})
    max_age_days = int(policy.get("max_evidence_age_days", default_max_evidence_age_days))
    errors.extend(stale_evidence_errors(dashboard, "l1_dry_run_dashboard", max_age_days))
    errors.extend(l1_dashboard_source_commit_errors(dashboard))

    required_kinds = {
        "forge": "forged_artifact",
        "direct_link": "direct_link",
        "real_program": "real_program",
        "dlfcn": "dlfcn",
        "perf": "perf",
    }
    rows_by_kind = {kind: [] for kind in required_kinds}
    rows = dashboard.get("rows", [])
    if not isinstance(rows, list):
        return errors + ["release_claim_l1_dashboard_rows_missing"]

    for row in rows:
        if not isinstance(row, dict):
            continue
        kind = str(row.get("row_kind", ""))
        if kind in rows_by_kind:
            rows_by_kind[kind].append(row)

    for kind, label in required_kinds.items():
        if not rows_by_kind[kind]:
            errors.append(f"release_claim_l1_dashboard_missing_required_row_kind:{label}")

    for kind, rows in rows_by_kind.items():
        for row in rows:
            row_id = str(row.get("row_id", kind))
            artifact_rel = row.get("evidence_artifact")
            if not isinstance(artifact_rel, str) or not artifact_rel:
                errors.append(f"release_claim_l1_dashboard_row_lacks_evidence_ref:{row_id}")
                continue
            artifact = root / artifact_rel
            if not artifact.exists():
                errors.append(f"release_claim_l1_dashboard_missing_row_artifact:{row_id}")
                continue
            artifact_json = load_json(artifact)
            if stale_evidence_errors(artifact_json, "row", max_age_days):
                errors.append(f"release_claim_stale_l1_dashboard_row_evidence:{row_id}")

            field = row.get("field")
            actual = select_field(artifact_json, field)
            if actual is None:
                errors.append(f"release_claim_l1_dashboard_row_field_missing:{row_id}")
                continue
            if "expected_value" in row:
                if actual != row["expected_value"]:
                    errors.append(f"release_claim_l1_dashboard_blocked_row:{row_id}")
            elif "expected_value_max" in row:
                try:
                    if float(actual) > float(row["expected_value_max"]):
                        errors.append(f"release_claim_l1_dashboard_blocked_row:{row_id}")
                except (TypeError, ValueError):
                    errors.append(f"release_claim_l1_dashboard_blocked_row:{row_id}")
            else:
                errors.append(f"release_claim_l1_dashboard_row_missing_expectation:{row_id}")
    return errors


def standalone_evidence_errors(claim, level, current_level, current_release_level):
    errors = []
    matrix_ref = rel(standalone_matrix_path)
    if not cited(claim, matrix_ref):
        errors.append(f"release_claim_missing_{level.lower()}_evidence")
        return errors
    if level_rank[current_level] < level_rank[level]:
        errors.append("release_claim_above_current_level")
    if level_rank[current_release_level] < level_rank[level]:
        errors.append("release_claim_above_current_release_level")
    matrix = load_json(standalone_matrix_path)
    policy = matrix.get("claim_policy", {})
    summary = matrix.get("summary", {})
    errors.extend(
        stale_evidence_errors(
            matrix,
            level.lower(),
            int(policy.get("max_evidence_age_days", default_max_evidence_age_days)),
        )
    )
    policy_key = f"{level.lower()}_current_claim_status"
    if policy.get(policy_key) == "blocked":
        errors.append(f"release_claim_{level.lower()}_policy_blocked")
    if summary.get("blocked_obligation_count", 0) != 0:
        errors.append(f"release_claim_{level.lower()}_blocked_obligations_present")
    return errors


levels = load_json(levels_path)
current_level = levels.get("current_level", "L0")
release_policy = levels.get("release_tag_policy", {})
current_release_level = release_policy.get("current_release_level", "L0")
claims = load_claims(levels)

rows = []
failures = []
commit = source_commit()

for claim in claims:
    claim_id = claim.get("id") or claim.get("tag") or "release-claim"
    claimed_level = claim.get("claimed_level") or parse_tag_level(claim.get("tag", ""))
    artifact_refs = claim.get("artifact_refs", [])
    failure_signatures = []

    if claimed_level not in level_rank:
        failure_signatures.append("release_claim_level_unparseable")
    else:
        doc_requires_l1_dashboard = claim_implies_standalone_readiness(claim)
        evidence_level = claimed_level
        if doc_requires_l1_dashboard and level_rank[claimed_level] < level_rank["L1"]:
            evidence_level = "L1"
        failure_signatures.extend(readme_claim_errors(current_release_level))
        failure_signatures.extend(doc_claim_errors(claim))
        if level_rank[claimed_level] >= level_rank["L1"] or doc_requires_l1_dashboard:
            failure_signatures.extend(support_matrix_errors(claim, evidence_level))
            failure_signatures.extend(compatibility_report_errors(claim))
            failure_signatures.extend(
                l1_evidence_errors(claim, current_level, current_release_level)
            )
            if doc_requires_l1_dashboard:
                failure_signatures.extend(l1_dashboard_errors(claim))
        if level_rank[claimed_level] >= level_rank["L2"]:
            failure_signatures.extend(
                standalone_evidence_errors(
                    claim, "L2", current_level, current_release_level
                )
            )
        if level_rank[claimed_level] >= level_rank["L3"]:
            failure_signatures.extend(
                standalone_evidence_errors(
                    claim, "L3", current_level, current_release_level
                )
            )

    required_evidence = [rel(levels_path)]
    if claimed_level in ("L1", "L2", "L3") or claim_implies_standalone_readiness(claim):
        required_evidence.extend(
            [
                rel(support_matrix_path),
                rel(compatibility_report_path),
                rel(l1_matrix_path),
            ]
        )
    if claim_implies_standalone_readiness(claim):
        required_evidence.append(rel(l1_dashboard_path))
    if claimed_level in ("L2", "L3"):
        required_evidence.append(rel(standalone_matrix_path))

    decision = "claim_blocked" if failure_signatures else "claim_allowed"
    row = {
        "trace_id": os.environ.get("TRACE_ID", "release-claim-evidence-gate"),
        "bead_id": bead_id,
        "release_claim_id": claim_id,
        "replacement_level": claimed_level,
        "required_evidence": required_evidence,
        "present_evidence": artifact_refs,
        "expected_decision": "claim_allowed",
        "actual_decision": decision,
        "artifact_refs": artifact_refs,
        "source_commit": commit,
        "failure_signature": ",".join(failure_signatures),
    }
    rows.append(row)
    if failure_signatures:
        failures.append(row)

report = {
    "schema_version": "v1",
    "bead": bead_id,
    "status": "fail" if failures else "pass",
    "current_level": current_level,
    "current_release_level": current_release_level,
    "claim_count": len(rows),
    "failed_claim_count": len(failures),
    "claims": rows,
    "required_evidence_files": {
        "support_matrix": rel(support_matrix_path),
        "compatibility_report": rel(compatibility_report_path),
        "L1": rel(l1_matrix_path),
        "l1_dry_run_dashboard": rel(l1_dashboard_path),
        "L2": rel(standalone_matrix_path),
        "L3": rel(standalone_matrix_path),
    },
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
    encoding="utf-8",
)

if failures:
    for failure in failures:
        print(
            f"FAIL: {failure['release_claim_id']} {failure['replacement_level']} "
            f"{failure['failure_signature']}"
        )
    sys.exit(1)

print(f"PASS: {len(rows)} release claim(s) have required replacement-level evidence")
PY
