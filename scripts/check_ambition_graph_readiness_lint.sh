#!/usr/bin/env bash
# check_ambition_graph_readiness_lint.sh -- recurring graph-readiness lint for bd-bp8fl.2.6
#
# Produces a deterministic report plus JSONL findings for tracker graph quality.
# Findings are actionable diagnostics; the script never edits, closes, deletes,
# or narrows beads.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FRANKENLIBC_AMBITION_GRAPH_LINT_ARTIFACT:-${ROOT}/tests/conformance/ambition_graph_readiness_lint.v1.json}"
ISSUES="${FRANKENLIBC_AMBITION_GRAPH_LINT_ISSUES:-${ROOT}/.beads/issues.jsonl}"
OUT_DIR="${FRANKENLIBC_AMBITION_GRAPH_LINT_TARGET_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_AMBITION_GRAPH_LINT_REPORT:-${OUT_DIR}/ambition_graph_readiness_lint.report.json}"
LOG="${FRANKENLIBC_AMBITION_GRAPH_LINT_LOG:-${OUT_DIR}/ambition_graph_readiness_lint.log.jsonl}"
MODE="${1:---fixture-replay}"

case "${MODE}" in
  --fixture-replay|--validate-current)
    ;;
  *)
    echo "usage: $0 [--fixture-replay|--validate-current]" >&2
    exit 2
    ;;
esac

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${ARTIFACT}" "${ISSUES}" "${REPORT}" "${LOG}" "${MODE}" <<'PY'
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
issues_path = Path(sys.argv[3])
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])
mode = sys.argv[6]

BEAD = "bd-bp8fl.2.6"
LABEL_RE = re.compile(r"^[A-Za-z0-9_:-]+$")

REQUIRED_REPORT_FIELDS = [
    "schema_version",
    "bead",
    "generated_at_utc",
    "trace_id",
    "source_commit",
    "status",
    "mode",
    "tracker_state",
    "issue_count",
    "finding_count",
    "severity_counts",
    "findings_by_rule",
    "next_safe_actions",
    "summary",
    "artifact_refs",
]

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "lint_run_id",
    "bead_id",
    "rule_id",
    "severity",
    "expected",
    "actual",
    "dependency_state",
    "tracker_state",
    "evidence_refs",
    "source_commit",
    "failure_signature",
]

errors = []


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"FAIL: cannot load {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def load_jsonl(path):
    issues = []
    try:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            issue = json.loads(line)
            issue["_line_number"] = line_number
            issues.append(issue)
    except Exception as exc:
        print(f"FAIL: cannot load {path}: {exc}", file=sys.stderr)
        sys.exit(1)
    return issues


def source_commit():
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def words(issue):
    parts = [
        issue.get("id", ""),
        issue.get("title", ""),
        issue.get("description", ""),
        issue.get("acceptance_criteria", ""),
        issue.get("close_reason", ""),
        " ".join(issue.get("labels", []) or []),
    ]
    return " ".join(str(part).lower() for part in parts)


def contains_any(text, needles):
    return any(needle in text for needle in needles)


def active_issue(issue):
    return issue.get("status") in {"open", "in_progress"}


def rule_catalog(artifact):
    catalog = {}
    for rule in artifact.get("rule_catalog", []):
        rule_id = rule.get("rule_id")
        if not rule_id:
            errors.append("rule_catalog entry missing rule_id")
            continue
        catalog[rule_id] = rule
    return catalog


def add_finding(findings, catalog, issue, rule_id, actual, dependency_state="not_applicable", tracker_state="current_jsonl", evidence_refs=None):
    rule = catalog[rule_id]
    refs = evidence_refs or [rel(artifact_path)]
    issue_id = issue.get("id", "<tracker>")
    findings.append(
        {
            "trace_id": f"{artifact.get('trace_id')}::{mode}::{issue_id}::{rule_id}",
            "lint_run_id": f"{BEAD}::{mode}",
            "bead_id": issue_id,
            "rule_id": rule_id,
            "severity": rule.get("severity"),
            "expected": rule.get("expected"),
            "actual": actual,
            "dependency_state": dependency_state,
            "tracker_state": tracker_state,
            "evidence_refs": refs,
            "source_commit": commit,
            "failure_signature": rule.get("failure_signature"),
            "next_safe_action": rule.get("next_safe_action"),
        }
    )


def dependency_edges(issues):
    ids = {issue.get("id") for issue in issues}
    edges = defaultdict(list)
    missing = []
    self_edges = []
    for issue in issues:
        issue_id = issue.get("id")
        for dep in issue.get("dependencies", []) or []:
            dep_type = dep.get("type", "")
            target = dep.get("depends_on_id")
            if not target:
                continue
            if target not in ids:
                missing.append((issue, target, dep_type))
            if target == issue_id:
                self_edges.append((issue, dep_type))
            if dep_type != "parent-child":
                edges[issue_id].append(target)
    return edges, missing, self_edges


def cycle_nodes(edges):
    seen = set()
    stack = set()
    cycles = set()

    def visit(node, path):
        if node in stack:
            if node in path:
                cycles.update(path[path.index(node):])
            return
        if node in seen:
            return
        seen.add(node)
        stack.add(node)
        for target in edges.get(node, []):
            visit(target, path + [target])
        stack.remove(node)

    for node in sorted(edges):
        visit(node, [node])
    return cycles


def lint(issues, catalog, tracker_state, tracker_probes):
    findings = []
    issues_by_id = {issue.get("id"): issue for issue in issues}

    for issue in issues:
        issue_id = issue.get("id", "<missing-id>")
        labels = issue.get("labels", []) or []
        if not isinstance(labels, list):
            add_finding(findings, catalog, issue, "label_syntax", "labels is not an array", tracker_state=tracker_state, evidence_refs=[rel(issues_path)])
            continue
        for label in labels:
            if not isinstance(label, str) or not LABEL_RE.fullmatch(label):
                add_finding(
                    findings,
                    catalog,
                    issue,
                    "label_syntax",
                    f"{issue_id}: invalid label {label!r}",
                    tracker_state=tracker_state,
                    evidence_refs=[rel(issues_path)],
                )

        if active_issue(issue) and issue.get("issue_type") == "task":
            text = words(issue)
            acceptance = str(issue.get("acceptance_criteria", ""))
            acceptance_text = acceptance.lower()
            weak_bits = []
            if len(acceptance.strip()) < 80:
                weak_bits.append("missing_or_too_short_acceptance")
            if not contains_any(acceptance_text, ["unit test", "unit tests", "tests"]):
                weak_bits.append("missing_unit_test_obligation")
            if not contains_any(acceptance_text, ["e2e", "fixture", "harness", "script", "smoke", "benchmark"]):
                weak_bits.append("missing_e2e_or_harness_obligation")
            if not contains_any(acceptance_text, ["log", "jsonl", "structured", "trace_id", "failure_signature"]):
                weak_bits.append("missing_structured_log_obligation")
            if not contains_any(acceptance_text, ["artifact", "artifacts", "report"]):
                weak_bits.append("missing_artifact_obligation")
            if not contains_any(acceptance_text, ["closure", "close", "commands"]):
                weak_bits.append("missing_closure_commands")
            if not contains_any(acceptance_text, ["preserve", "no-feature-loss", "do not narrow", "existing"]):
                weak_bits.append("missing_no_feature_loss_language")
            if weak_bits:
                add_finding(
                    findings,
                    catalog,
                    issue,
                    "acceptance_contract",
                    f"{issue_id}: " + ",".join(weak_bits),
                    tracker_state=tracker_state,
                    evidence_refs=[rel(issues_path)],
                )

            if len(str(issue.get("title", "")).strip()) < 18 or len(str(issue.get("description", "")).strip()) < 80:
                add_finding(
                    findings,
                    catalog,
                    issue,
                    "scope_specificity",
                    f"{issue_id}: title/description too vague for pre-implementation handoff",
                    tracker_state=tracker_state,
                    evidence_refs=[rel(issues_path)],
                )
            elif not contains_any(text, ["user", "workload", "claim", "replacement", "conformance", "parity", "release", "external", "evidence"]):
                add_finding(
                    findings,
                    catalog,
                    issue,
                    "scope_specificity",
                    f"{issue_id}: no user-visible, conformance, parity, release, or evidence impact named",
                    tracker_state=tracker_state,
                    evidence_refs=[rel(issues_path)],
                )

            if contains_any(text, ["shipped in commit", "already shipped", "landed in commit"]) and not contains_any(text, ["remaining blocker", "stale", "reconcile"]):
                add_finding(
                    findings,
                    catalog,
                    issue,
                    "already_shipped_but_open",
                    f"{issue_id}: open row claims shipped evidence without a remaining blocker",
                    tracker_state=tracker_state,
                    evidence_refs=[rel(issues_path)],
                )

    edges, missing, self_edges = dependency_edges(issues)
    for issue, target, dep_type in missing:
        add_finding(
            findings,
            catalog,
            issue,
            "dependency_sanity",
            f"{issue.get('id')}: {dep_type} dependency target {target} is missing",
            dependency_state="missing_dependency_target",
            tracker_state=tracker_state,
            evidence_refs=[rel(issues_path)],
        )
    for issue, dep_type in self_edges:
        add_finding(
            findings,
            catalog,
            issue,
            "dependency_sanity",
            f"{issue.get('id')}: self dependency of type {dep_type}",
            dependency_state="self_dependency",
            tracker_state=tracker_state,
            evidence_refs=[rel(issues_path)],
        )
    for node in sorted(cycle_nodes(edges)):
        issue = issues_by_id.get(node, {"id": node})
        add_finding(
            findings,
            catalog,
            issue,
            "dependency_sanity",
            f"{node}: participates in a non-parent dependency cycle",
            dependency_state="cycle_detected",
            tracker_state=tracker_state,
            evidence_refs=[rel(issues_path)],
        )

    for probe in tracker_probes:
        signature = probe.get("failure_signature")
        if probe.get("exit_status") not in (0, None) or signature not in (None, "ok"):
            add_finding(
                findings,
                catalog,
                {"id": "<tracker-probe>"},
                "tracker_state",
                f"{probe.get('command')}: {probe.get('actual')}",
                dependency_state="not_checked",
                tracker_state="tracker_failure",
                evidence_refs=[rel(artifact_path)],
            )

    return findings


artifact = load_json(artifact_path)
commit = source_commit()

if artifact.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if artifact.get("bead") != BEAD:
    errors.append(f"bead must be {BEAD}")
if artifact.get("required_report_fields") != REQUIRED_REPORT_FIELDS:
    errors.append("required_report_fields drifted")
if artifact.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    errors.append("required_log_fields drifted")

catalog = rule_catalog(artifact)
expected_rules = set(artifact.get("expected_fixture_rules", []))
if mode == "--fixture-replay" and expected_rules - set(catalog):
    errors.append("expected_fixture_rules includes unknown rule ids: " + ",".join(sorted(expected_rules - set(catalog))))

if mode == "--fixture-replay":
    fixture = artifact.get("fixture_graph", {})
    issues = fixture.get("issues", [])
    tracker_state = fixture.get("tracker_state", "tracker_failure")
    tracker_probes = fixture.get("tracker_probes", [])
else:
    issues = load_jsonl(issues_path)
    tracker_state = "current_jsonl"
    tracker_probes = []

findings = lint(issues, catalog, tracker_state, tracker_probes)
rule_counts = Counter(finding["rule_id"] for finding in findings)
severity_counts = Counter(finding["severity"] for finding in findings)
hard_failures = [finding for finding in findings if finding["severity"] == "error"]
fixture_rules = set(rule_counts)

if mode == "--fixture-replay":
    missing_fixture_rules = expected_rules - fixture_rules
    if missing_fixture_rules:
        errors.append("fixture replay missed rules: " + ",".join(sorted(missing_fixture_rules)))

status = "pass"
if errors:
    status = "fail"
elif mode == "--validate-current" and hard_failures:
    status = "fail"

report = {
    "schema_version": "v1",
    "bead": BEAD,
    "generated_at_utc": utc_now(),
    "trace_id": f"{artifact.get('trace_id')}::{mode}",
    "source_commit": commit,
    "status": status,
    "mode": mode,
    "tracker_state": tracker_state if not hard_failures else "graph_failure",
    "issue_count": len(issues),
    "finding_count": len(findings),
    "severity_counts": dict(sorted(severity_counts.items())),
    "findings_by_rule": dict(sorted(rule_counts.items())),
    "next_safe_actions": sorted({finding["next_safe_action"] for finding in findings}),
    "summary": {
        "hard_failure_count": len(hard_failures),
        "label_syntax_clean": rule_counts.get("label_syntax", 0) == 0,
        "dependency_graph_clean": rule_counts.get("dependency_sanity", 0) == 0,
        "acceptance_findings": rule_counts.get("acceptance_contract", 0),
        "scope_findings": rule_counts.get("scope_specificity", 0),
        "tracker_probe_findings": rule_counts.get("tracker_state", 0),
        "actionable_without_blocking_unrelated_beads": True,
        "errors": errors,
    },
    "artifact_refs": [rel(artifact_path), rel(issues_path)],
}

missing_report = [field for field in REQUIRED_REPORT_FIELDS if field not in report]
if missing_report:
    errors.append("report missing fields: " + ",".join(missing_report))
    report["status"] = "fail"
    report["summary"]["errors"] = errors

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

with log_path.open("w", encoding="utf-8") as handle:
    for finding in findings:
        missing_log = [field for field in REQUIRED_LOG_FIELDS if field not in finding]
        if missing_log:
            errors.append(f"{finding.get('bead_id')}: missing log fields {missing_log}")
        handle.write(json.dumps({field: finding[field] for field in REQUIRED_LOG_FIELDS}, sort_keys=True) + "\n")

if errors:
    print("FAIL: " + "; ".join(errors), file=sys.stderr)
    sys.exit(1)
if mode == "--validate-current" and hard_failures:
    print(f"FAIL: current graph has {len(hard_failures)} hard graph failures; see {report_path}", file=sys.stderr)
    sys.exit(1)

print(f"PASS {mode}: {len(issues)} issues, {len(findings)} findings, report={rel(report_path)}, log={rel(log_path)}")
PY
