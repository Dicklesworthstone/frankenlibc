#!/usr/bin/env bash
# check_semantic_contract_drift.sh -- CI gate for bd-bp8fl.1.3
#
# Fails when semantic contract annotations for no-op/fallback/unsupported/
# bootstrap surfaces drift away from the inventory and semantic overlay.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FLC_SEMANTIC_DRIFT_ARTIFACT:-${ROOT}/tests/conformance/semantic_contract_drift_scan.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/semantic_contract_drift_scan.report.json"
LOG="${OUT_DIR}/semantic_contract_drift_scan.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" <<'PY'
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

errors = []
checks = {}
events = []
allowed_drift = []
newly_found_drift = []

def rel(path):
    path = Path(path)
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)

def resolve_path(value):
    path = Path(value)
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

def read_text(path, label):
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{label}: failed to read {path}: {exc}")
        return ""

def file_sha256(path):
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
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

artifact = load_json(artifact_path, "artifact")
if artifact is None:
    artifact = {}

inputs = artifact.get("inputs", {})
artifact_refs = sorted(str(value) for value in inputs.values())
source_commit = git_head()
trace_seed = "|".join(
    [
        artifact.get("bead", "bd-bp8fl.1.3"),
        source_commit,
        str(file_sha256(artifact_path) or "missing"),
    ]
)
trace_id = hashlib.sha256(trace_seed.encode("utf-8")).hexdigest()[:20]

def event(scanner_rule, symbol="*", file_path="", expected_contract="", actual_contract="", failure_signature="", status="pass"):
    row = {
        "trace_id": trace_id,
        "bead_id": artifact.get("bead", "bd-bp8fl.1.3"),
        "scanner_rule": scanner_rule,
        "symbol": symbol,
        "file_path": file_path,
        "expected_contract": expected_contract,
        "actual_contract": actual_contract,
        "artifact_refs": artifact_refs,
        "source_commit": source_commit,
        "failure_signature": failure_signature,
        "status": status,
    }
    events.append(row)
    return row

def fail(scanner_rule, message, symbol="*", file_path="", expected_contract="", actual_contract="", failure_signature=""):
    errors.append(message)
    event(
        scanner_rule,
        symbol=symbol,
        file_path=file_path,
        expected_contract=expected_contract,
        actual_contract=actual_contract,
        failure_signature=failure_signature or scanner_rule,
        status="fail",
    )

def env_path(name, input_key):
    override = os.environ.get(name)
    if override:
        return resolve_path(override)
    value = inputs.get(input_key)
    if not value:
        return root / "__missing_input__" / input_key
    return resolve_path(value)

inventory_path = env_path("FLC_SEMANTIC_DRIFT_INVENTORY", "semantic_contract_inventory")
join_path = env_path("FLC_SEMANTIC_DRIFT_JOIN", "semantic_contract_symbol_join")
overlay_path = env_path("FLC_SEMANTIC_DRIFT_OVERLAY", "support_semantic_overlay")
support_matrix_path = env_path("FLC_SEMANTIC_DRIFT_SUPPORT_MATRIX", "support_matrix")
version_script_path = env_path("FLC_SEMANTIC_DRIFT_VERSION_SCRIPT", "version_script")
readme_path = env_path("FLC_SEMANTIC_DRIFT_README", "readme")
feature_parity_path = env_path("FLC_SEMANTIC_DRIFT_FEATURE_PARITY", "feature_parity")

inventory = load_json(inventory_path, "semantic_contract_inventory")
join = load_json(join_path, "semantic_contract_symbol_join")
overlay = load_json(overlay_path, "support_semantic_overlay")
support = load_json(support_matrix_path, "support_matrix")

if all(value is not None for value in [artifact, inventory, join, overlay, support]):
    checks["json_parse"] = "pass"
else:
    checks["json_parse"] = "fail"

required_inputs = {
    "semantic_contract_inventory",
    "semantic_contract_symbol_join",
    "support_semantic_overlay",
    "support_matrix",
    "version_script",
    "readme",
    "feature_parity",
}
required_log_fields = [
    "trace_id",
    "bead_id",
    "scanner_rule",
    "symbol",
    "file_path",
    "expected_contract",
    "actual_contract",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
if (
    artifact.get("schema_version") == "v1"
    and artifact.get("bead") == "bd-bp8fl.1.3"
    and required_inputs <= set(inputs)
    and artifact.get("required_log_fields") == required_log_fields
    and isinstance(artifact.get("scanner_rules"), list)
):
    checks["artifact_shape"] = "pass"
    event("artifact_shape")
else:
    checks["artifact_shape"] = "fail"
    fail(
        "artifact_shape",
        "artifact must declare schema_version=v1, bead=bd-bp8fl.1.3, required inputs, scanner rules, and required log fields",
        expected_contract="complete semantic contract drift manifest",
        actual_contract="manifest shape mismatch",
        failure_signature="artifact_shape",
    )

inventory_entries = inventory.get("entries", []) if isinstance(inventory, dict) else []
join_entries = join.get("entries", []) if isinstance(join, dict) else []
join_summary = join.get("summary", {}) if isinstance(join, dict) else {}

if version_script_path.exists() and join_path.exists():
    checks["abi_export_input_presence"] = "pass"
    event(
        "abi_export_input_presence",
        file_path=rel(version_script_path),
        expected_contract="version script and semantic join artifact present",
        actual_contract="inputs present",
    )
else:
    checks["abi_export_input_presence"] = "fail"
    fail(
        "abi_export_input_presence",
        "ABI export inputs are missing",
        file_path=rel(version_script_path),
        expected_contract="version script and semantic join artifact present",
        actual_contract="missing input",
        failure_signature="missing_abi_export_input",
    )

def marker_positions(lines, marker):
    return [idx + 1 for idx, line in enumerate(lines) if marker in line]

radius = int(artifact.get("source_marker_radius_lines", 80))
tracked_windows = {}
marker_failures = 0
for row in inventory_entries:
    row_id = str(row.get("id", ""))
    source_path = resolve_path(row.get("source_path", ""))
    source_rel = rel(source_path)
    marker = str(row.get("line_marker", ""))
    expected_line = int(row.get("source_line", 0) or 0)
    symbols = row.get("symbols") or ["*"]
    symbol = str(symbols[0])
    if not source_path.exists():
        marker_failures += 1
        fail(
            "inventory_marker_freshness",
            f"{row_id}: source_path does not exist: {source_rel}",
            symbol=symbol,
            file_path=source_rel,
            expected_contract=marker,
            actual_contract="missing source file",
            failure_signature="missing_inventory_source",
        )
        continue
    lines = read_text(source_path, f"{row_id} source").splitlines()
    positions = marker_positions(lines, marker)
    nearby = [line for line in positions if abs(line - expected_line) <= radius]
    if not marker or not nearby:
        marker_failures += 1
        fail(
            "inventory_marker_freshness",
            f"{row_id}: stale line_marker near line {expected_line}: {marker!r}",
            symbol=symbol,
            file_path=source_rel,
            expected_contract=marker,
            actual_contract="marker missing near recorded source_line",
            failure_signature="stale_inventory_marker",
        )
        continue
    nearest = min(nearby, key=lambda line: abs(line - expected_line))
    tracked_windows.setdefault(source_rel, []).append(
        {
            "inventory_id": row_id,
            "start": max(1, nearest - radius),
            "end": nearest + radius,
            "semantic_class": row.get("semantic_class", ""),
            "symbols": [str(symbol_value) for symbol_value in (row.get("symbols") or ["*"])],
            "line_marker": marker,
            "source_line": nearest,
        }
    )
    event(
        "inventory_marker_freshness",
        symbol=symbol,
        file_path=f"{source_rel}:{nearest}",
        expected_contract=marker,
        actual_contract=lines[nearest - 1].strip(),
    )

checks["inventory_marker_freshness"] = "pass" if marker_failures == 0 else "fail"

def pattern_matches(patterns, text):
    lowered = text.lower()
    for pattern in patterns:
        if pattern.lower() in lowered:
            return pattern
    return None

term_patterns = []
for term in artifact.get("contract_terms", []):
    for pattern in term.get("patterns", []):
        term_patterns.append((term.get("id", "contract_term"), str(pattern)))
annotation_markers = [str(marker) for marker in artifact.get("annotation_markers", [])]
suffixes = set(str(suffix) for suffix in artifact.get("source_scan_suffixes", [".rs"]))

def scan_files():
    roots = artifact.get("source_scan_roots", [])
    seen = set()
    for raw in roots:
        path = resolve_path(str(raw))
        if path.is_file():
            candidates = [path]
        elif path.is_dir():
            candidates = [item for item in path.rglob("*") if item.is_file()]
        else:
            continue
        for item in candidates:
            if item in seen:
                continue
            if suffixes and item.suffix not in suffixes:
                continue
            seen.add(item)
            yield item

def tracked_match(source_rel, line_no, text):
    for window in tracked_windows.get(source_rel, []):
        if window["start"] <= line_no <= window["end"]:
            return window
        if window["line_marker"] and window["line_marker"] in text:
            return window
    return None

def allowlist_match(source_rel, line_no, text, term_id):
    for row in artifact.get("intentional_false_positive_allowlist", []):
        symbol = str(row.get("symbol", ""))
        reason = str(row.get("evidence_reason", ""))
        file_pattern = str(row.get("file_path", ""))
        pattern = str(row.get("pattern", ""))
        if not symbol or not reason or not file_pattern or not pattern:
            fail(
                "source_contract_annotation_drift",
                f"allowlist row is missing symbol/evidence_reason/file_path/pattern: {row}",
                file_path=source_rel,
                expected_contract="explicit false-positive allowlist with evidence",
                actual_contract="incomplete allowlist row",
                failure_signature="invalid_false_positive_allowlist",
            )
            continue
        if not (source_rel == file_pattern or fnmatch.fnmatchcase(source_rel, file_pattern)):
            continue
        try:
            if not re.search(pattern, text, flags=re.IGNORECASE):
                continue
        except re.error as exc:
            fail(
                "source_contract_annotation_drift",
                f"allowlist regex does not compile for {source_rel}: {exc}",
                symbol=symbol,
                file_path=source_rel,
                expected_contract="valid allowlist regex",
                actual_contract=pattern,
                failure_signature="invalid_false_positive_allowlist_regex",
            )
            continue
        allowed = {
            "symbol": symbol,
            "file_path": f"{source_rel}:{line_no}",
            "contract_class": row.get("contract_class", term_id),
            "evidence_reason": reason,
            "matched_text": text.strip(),
        }
        allowed_drift.append(allowed)
        event(
            "source_contract_annotation_drift",
            symbol=symbol,
            file_path=f"{source_rel}:{line_no}",
            expected_contract="explicit allowlist false positive",
            actual_contract=text.strip(),
        )
        return allowed
    return None

untracked_count = 0
for source_path in scan_files():
    source_rel = rel(source_path)
    lines = read_text(source_path, "source scan").splitlines()
    for line_no, line in enumerate(lines, start=1):
        term = None
        for term_id, pattern in term_patterns:
            if pattern.lower() in line.lower():
                term = (term_id, pattern)
                break
        if term is None:
            continue
        marker = pattern_matches(annotation_markers, line)
        if marker is None:
            continue
        window = tracked_match(source_rel, line_no, line)
        if window:
            event(
                "source_contract_annotation_drift",
                symbol=",".join(window["symbols"]),
                file_path=f"{source_rel}:{line_no}",
                expected_contract=window["semantic_class"],
                actual_contract=line.strip(),
            )
            continue
        if allowlist_match(source_rel, line_no, line, term[0]):
            continue
        untracked_count += 1
        drift = {
            "file_path": f"{source_rel}:{line_no}",
            "contract_class": term[0],
            "matched_term": term[1],
            "annotation_marker": marker,
            "line": line.strip(),
        }
        newly_found_drift.append(drift)
        fail(
            "source_contract_annotation_drift",
            f"untracked semantic contract annotation at {source_rel}:{line_no}: {line.strip()}",
            file_path=f"{source_rel}:{line_no}",
            expected_contract="semantic inventory row or explicit symbol allowlist",
            actual_contract=line.strip(),
            failure_signature="untracked_contract_annotation",
        )

checks["source_contract_annotation_drift"] = "pass" if untracked_count == 0 else "fail"

support_stub_count = None
if isinstance(support, dict):
    counts = support.get("counts", {})
    if isinstance(counts, dict):
        support_stub_count = counts.get("Stub", counts.get("stub"))
    if support_stub_count is None:
        support_stub_count = len(support.get("stub", [])) if isinstance(support.get("stub"), list) else 0

overlay_policy = overlay.get("coverage_policy", {}) if isinstance(overlay, dict) else {}
if support_stub_count == 0 and overlay_policy.get("is_exhaustive") is False and "Stub=0" in str(overlay_policy.get("release_blocker", "")):
    checks["support_taxonomy_claim_blocker"] = "pass"
    event(
        "support_taxonomy_claim_blocker",
        expected_contract="Stub=0 is not semantic parity",
        actual_contract="semantic overlay release blocker present",
    )
else:
    checks["support_taxonomy_claim_blocker"] = "fail"
    fail(
        "support_taxonomy_claim_blocker",
        "support taxonomy Stub=0 claim blocker is missing or stale",
        expected_contract="Stub=0 blocked by semantic overlay",
        actual_contract=f"support_stub_count={support_stub_count}, overlay_policy={overlay_policy}",
        failure_signature="missing_support_taxonomy_claim_blocker",
    )

inventory_ids = {row.get("id") for row in inventory_entries}
join_ids = {row.get("inventory_id") for row in join_entries}
semantic_class_counts = Counter(str(row.get("semantic_class", "")) for row in inventory_entries)
expected_summary = artifact.get("expected_current_summary", {})
summary_ok = True
if inventory_ids != join_ids:
    summary_ok = False
    fail(
        "semantic_join_freshness",
        f"semantic join inventory coverage mismatch missing={sorted(inventory_ids - join_ids)} extra={sorted(join_ids - inventory_ids)}",
        expected_contract="join rows cover all inventory rows",
        actual_contract="join coverage mismatch",
        failure_signature="stale_semantic_join_inventory_coverage",
    )
if join_summary.get("inventory_entry_count") != len(inventory_entries):
    summary_ok = False
    fail(
        "semantic_join_freshness",
        "semantic join inventory_entry_count is stale",
        expected_contract=str(len(inventory_entries)),
        actual_contract=str(join_summary.get("inventory_entry_count")),
        failure_signature="stale_semantic_join_summary",
    )
if join_summary.get("semantic_parity_blocker_count") != len(inventory_entries):
    summary_ok = False
    fail(
        "semantic_join_freshness",
        "semantic join semantic_parity_blocker_count is stale",
        expected_contract=str(len(inventory_entries)),
        actual_contract=str(join_summary.get("semantic_parity_blocker_count")),
        failure_signature="stale_semantic_join_blocker_count",
    )
if join_summary.get("source_missing_exact_symbol_count") != 0:
    summary_ok = False
    fail(
        "semantic_join_freshness",
        "semantic join reports missing ABI source symbols",
        expected_contract="source_missing_exact_symbol_count=0",
        actual_contract=str(join_summary.get("source_missing_exact_symbol_count")),
        failure_signature="missing_abi_source_symbol",
    )
if join_summary.get("by_semantic_class") != dict(sorted(semantic_class_counts.items())):
    summary_ok = False
    fail(
        "semantic_join_freshness",
        "semantic join class counts do not match inventory",
        expected_contract=str(dict(sorted(semantic_class_counts.items()))),
        actual_contract=str(join_summary.get("by_semantic_class")),
        failure_signature="stale_semantic_join_class_counts",
    )

if expected_summary.get("tracked_inventory_entries") not in (None, len(inventory_entries)):
    summary_ok = False
    fail(
        "semantic_join_freshness",
        "drift scan expected inventory count is stale",
        expected_contract=str(len(inventory_entries)),
        actual_contract=str(expected_summary.get("tracked_inventory_entries")),
        failure_signature="stale_drift_scan_expected_summary",
    )

checks["semantic_join_freshness"] = "pass" if summary_ok else "fail"
if summary_ok:
    event(
        "semantic_join_freshness",
        expected_contract="all inventory rows remain semantic blockers",
        actual_contract=f"{len(inventory_entries)} rows covered",
    )

readme_text = read_text(readme_path, "README")
feature_text = read_text(feature_parity_path, "FEATURE_PARITY")
docs_ok = True
for label, path, text in [
    ("README", readme_path, readme_text),
    ("FEATURE_PARITY", feature_parity_path, feature_text),
]:
    has_overlay_ref = "support_semantic_overlay.v1.json" in text
    forbidden = []
    for line in text.splitlines():
        lowered = line.lower()
        if "stub: 0" in lowered:
            makes_claim = any(word in lowered for word in ["proves", "proof", "confirms", "establishes", "means"])
            full_claim = any(word in lowered for word in ["full", "complete", "replacement", "parity"])
            blocks_claim = "not " in lowered or "block" in lowered
            if makes_claim and full_claim and not blocks_claim:
                forbidden.append(line.strip())
        if re.search(r"zero\s+(semantic\s+)?(fallback|no-op|bootstrap)\s+contracts", line, flags=re.IGNORECASE):
            if "not zero" not in lowered:
                forbidden.append(line.strip())
    if not has_overlay_ref or forbidden:
        docs_ok = False
        fail(
            "docs_claim_surface",
            f"{label} semantic-overlay claim surface is stale",
            file_path=rel(path),
            expected_contract="document references semantic overlay and avoids full-parity Stub=0 claim",
            actual_contract=f"has_overlay_ref={has_overlay_ref}, forbidden={forbidden}",
            failure_signature="stale_docs_claim_surface",
        )
    else:
        event(
            "docs_claim_surface",
            file_path=rel(path),
            expected_contract="semantic overlay referenced",
            actual_contract="claim surface blocks Stub=0 promotion",
        )

checks["docs_claim_surface"] = "pass" if docs_ok else "fail"

summary = {
    "tracked_inventory_entries": len(inventory_entries),
    "semantic_parity_blocker_count": join_summary.get("semantic_parity_blocker_count"),
    "semantic_class_counts": dict(sorted(semantic_class_counts.items())),
    "untracked_contract_annotation_count": len(newly_found_drift),
    "allowed_false_positive_count": len(allowed_drift),
    "support_matrix_stub_count": support_stub_count,
    "docs_with_semantic_overlay_reference": sum(
        1 for text in [readme_text, feature_text] if "support_semantic_overlay.v1.json" in text
    ),
}

if all(status == "pass" for status in checks.values()) and not errors:
    status = "pass"
else:
    status = "fail"

report = {
    "schema_version": "v1",
    "bead": artifact.get("bead", "bd-bp8fl.1.3"),
    "status": status,
    "checks": checks,
    "summary": summary,
    "newly_found_drift": newly_found_drift,
    "allowed_drift": allowed_drift,
    "claim_surfaces_blocked_by_findings": artifact.get("claim_blocking_policy", {}).get(
        "claim_surfaces_blocked_by_findings", []
    ),
    "artifact_refs": artifact_refs,
    "source_commit": source_commit,
    "target_dir": rel(report_path.parent),
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
