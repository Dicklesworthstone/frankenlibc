#!/usr/bin/env bash
# check_hardened_repair_deny_completion_contract.sh - bd-w2c3.3.2.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_HARDENED_REPAIR_DENY_CONTRACT:-$ROOT/tests/conformance/hardened_repair_deny_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_HARDENED_REPAIR_DENY_OUT_DIR:-$ROOT/target/conformance/hardened_repair_deny_completion_contract}"
REPORT="${FRANKENLIBC_HARDENED_REPAIR_DENY_REPORT:-$OUT_DIR/hardened_repair_deny_completion_contract.report.json}"
LOG="${FRANKENLIBC_HARDENED_REPAIR_DENY_LOG:-$OUT_DIR/hardened_repair_deny_completion_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import re
import subprocess
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "hardened_repair_deny_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "hardened_repair_deny_completion_contract.report.v1"
SOURCE_BEAD = "bd-w2c3.3.2"
COMPLETION_BEAD = "bd-w2c3.3.2.1"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
EXPECTED_EVENTS = {
    "hardened_repair_deny_contract_validated",
    "hardened_repair_deny_matrix_validated",
    "hardened_repair_deny_gate_replayed",
    "hardened_repair_deny_completion_summary",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def strings(value: Any, context: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


def repo_path(value: Any, context: str, *, must_be_file: bool = False) -> pathlib.Path | None:
    if not isinstance(value, str) or not value:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(value)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must stay repo-relative: {value}")
        return None
    full = ROOT / path
    if must_be_file and not full.is_file():
        err(f"{context} references missing file: {value}")
        return None
    if not must_be_file and not full.exists():
        err(f"{context} references missing path: {value}")
        return None
    return full


def text_for(path_text: str, context: str) -> str:
    path = repo_path(path_text, context, must_be_file=True)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        err(f"{context} is not UTF-8: {path_text}: {exc}")
        return ""


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": now(),
            "trace_id": f"{COMPLETION_BEAD}:{event}:{len(events) + 1:03d}",
            "event": event,
            "source_bead": SOURCE_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "hardened_repair_deny_completion_failed",
            "details": details,
        }
    )


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text or f"def {name}" in source_text


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, str]:
    raw = manifest.get("source_artifacts", {})
    if not isinstance(raw, dict) or not raw:
        err("source_artifacts must be a non-empty object")
        return {}
    artifacts: dict[str, str] = {}
    for key, value in raw.items():
        if repo_path(value, f"source_artifacts.{key}", must_be_file=True) is not None and isinstance(value, str):
            artifacts[str(key)] = value
    return artifacts


def validate_impl_refs(manifest: dict[str, Any]) -> None:
    refs = manifest.get("implementation_refs")
    if not isinstance(refs, list) or len(refs) < 12:
        err("implementation_refs must include at least 12 concrete source anchors")
        return
    seen: set[str] = set()
    cache: dict[str, str] = {}
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"implementation_refs[{index}] must be an object")
            continue
        kind = ref.get("kind")
        path_text = ref.get("path")
        line = ref.get("line")
        anchor = ref.get("anchor")
        if isinstance(kind, str) and kind:
            seen.add(kind)
        else:
            err(f"implementation_refs[{index}].kind must be a non-empty string")
        if not isinstance(path_text, str):
            err(f"implementation_refs[{index}].path must be a string")
            continue
        text = cache.setdefault(path_text, text_for(path_text, f"implementation_refs.{kind}"))
        lines = text.splitlines()
        if not isinstance(line, int) or line <= 0:
            err(f"{path_text} ref line must be a positive integer")
        elif line > len(lines) or not lines[line - 1].strip():
            err(f"{path_text}:{line} does not point to a non-empty line")
        if not isinstance(anchor, str) or not anchor:
            err(f"{path_text}:{line} missing anchor")
        elif anchor not in text:
            err(f"{path_text} missing anchor {anchor!r}")
    required = {
        "matrix_iconv_deny_entry",
        "matrix_summary",
        "checker_policy_hash",
        "checker_structured_log",
        "matrix_e2e_gate_test",
        "iconv_hardened_deny_fixture",
        "iconv_hardened_deny_unit",
        "healing_action_enum",
    }
    missing = required - seen
    if missing:
        err(f"implementation_refs missing required kinds: {sorted(missing)}")


def validate_test_sources(manifest: dict[str, Any]) -> int:
    raw = manifest.get("test_sources", {})
    if not isinstance(raw, dict) or not raw:
        err("test_sources must be a non-empty object")
        return 0
    count = 0
    for source_id, source in raw.items():
        if not isinstance(source, dict):
            err(f"test_sources.{source_id} must be an object")
            continue
        path_text = source.get("path")
        if not isinstance(path_text, str):
            err(f"test_sources.{source_id}.path must be a string")
            continue
        text = text_for(path_text, f"test_sources.{source_id}")
        for name in strings(source.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs"):
            count += 1
            require(function_exists(text, name), f"test_sources.{source_id} missing test ref {name}")
    return count


def validate_coverage(manifest: dict[str, Any]) -> None:
    coverage = manifest.get("completion_coverage")
    if not isinstance(coverage, list) or len(coverage) != 2:
        err("completion_coverage must contain exactly unit and e2e sections")
        return
    covered = {section.get("missing_item_id") for section in coverage if isinstance(section, dict)}
    require(covered == EXPECTED_MISSING_ITEMS, f"completion_coverage item mismatch: {covered!r}")
    for section in coverage:
        if not isinstance(section, dict):
            err("completion_coverage sections must be objects")
            continue
        require(section.get("status") == "covered", "completion_coverage sections must be covered")
        require(section.get("test_refs") and isinstance(section.get("test_refs"), list), "completion_coverage sections must cite test_refs")
        for command in strings(section.get("validation_commands"), f"completion_coverage.{section.get('missing_item_id')}.validation_commands"):
            if "cargo " in command:
                require(command.startswith("rch exec -- "), f"cargo validation command must use rch: {command}")


def validate_manifest(manifest: dict[str, Any]) -> dict[str, str]:
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
    require(manifest.get("original_bead") == SOURCE_BEAD, f"original_bead must be {SOURCE_BEAD}")
    require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")
    audit = manifest.get("audit", {})
    if not isinstance(audit, dict):
        err("audit must be an object")
        audit = {}
    require(set(strings(audit.get("missing_items"), "audit.missing_items")) == EXPECTED_MISSING_ITEMS, "audit.missing_items must bind unit+e2e primary items")
    require(audit.get("next_audit_score_threshold", 0) >= 800, "next audit score threshold must be at least 800")
    artifacts = validate_source_artifacts(manifest)
    validate_impl_refs(manifest)
    test_ref_count = validate_test_sources(manifest)
    validate_coverage(manifest)
    telemetry = manifest.get("telemetry_contract", {})
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        telemetry = {}
    require(set(strings(telemetry.get("required_events"), "telemetry_contract.required_events")) == EXPECTED_EVENTS, "telemetry_contract.required_events mismatch")
    append_event(
        "hardened_repair_deny_contract_validated",
        "pass" if not errors else "fail",
        [rel(CONTRACT)],
        {"source_artifact_count": len(artifacts), "test_ref_count": test_ref_count},
    )
    return artifacts


def extract_healing_action_variants(source: str) -> list[str]:
    marker = "pub enum HealingAction"
    start = source.find(marker)
    if start == -1:
        err("could not find HealingAction enum declaration")
        return []
    brace_start = source.find("{", start)
    if brace_start == -1:
        err("malformed HealingAction enum")
        return []
    depth = 0
    brace_end = None
    for index in range(brace_start, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                brace_end = index
                break
    if brace_end is None:
        err("malformed HealingAction enum")
        return []
    variants: list[str] = []
    for line in source[brace_start + 1 : brace_end].splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("///") or stripped.startswith("#"):
            continue
        name = stripped.split("{", 1)[0].split("(", 1)[0].split(",", 1)[0].strip()
        if name and name[0].isalpha() and name not in variants:
            variants.append(name)
    return variants


def validate_matrix_sources(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    truth = manifest.get("required_source_truth", {})
    if not isinstance(truth, dict):
        err("required_source_truth must be an object")
        truth = {}
    matrix_truth = truth.get("matrix", {}) if isinstance(truth.get("matrix"), dict) else {}
    checker_truth = truth.get("checker", {}) if isinstance(truth.get("checker"), dict) else {}
    iconv_truth = truth.get("iconv_deny_case", {}) if isinstance(truth.get("iconv_deny_case"), dict) else {}

    matrix = load_json(ROOT / artifacts.get("matrix", ""), "hardened repair/deny matrix")
    summary = matrix.get("summary", {})
    require(matrix.get("schema_version") == matrix_truth.get("schema_version"), "matrix schema_version drift")
    require(matrix.get("bead") == matrix_truth.get("bead"), "matrix bead drift")
    if isinstance(summary, dict):
        for key in [
            "total_invalid_input_classes",
            "covered_invalid_input_classes",
            "entry_count",
            "repair_entries",
            "deny_entries",
        ]:
            require(summary.get(key) == matrix_truth.get(key), f"matrix summary {key} drift")
    else:
        err("matrix summary must be an object")

    entries = [row for row in matrix.get("entries", []) if isinstance(row, dict)]
    decision_set = {str(row.get("decision_path")) for row in entries}
    require(set(strings(matrix_truth.get("required_decisions"), "required_source_truth.matrix.required_decisions")) <= decision_set, "matrix missing required Repair/Deny decisions")
    required_prefixes = strings(matrix_truth.get("required_policy_id_prefixes"), "required_source_truth.matrix.required_policy_id_prefixes")
    policy_ids = [str(row.get("policy_id", "")) for row in entries]
    for prefix in required_prefixes:
        require(any(policy_id.startswith(prefix) for policy_id in policy_ids), f"matrix missing policy id prefix {prefix}")
    require(len(policy_ids) == len(set(policy_ids)), "matrix policy ids must be unique")
    require(
        str(matrix_truth.get("required_fixture_ref", "")) in {
            ref
            for row in entries
            for ref in row.get("fixture_case_refs", [])
            if isinstance(ref, str)
        },
        "matrix missing required hardened iconv deny fixture ref",
    )

    known_actions = set(strings(matrix.get("known_healing_actions"), "matrix.known_healing_actions"))
    required_actions = set(strings(matrix_truth.get("required_healing_actions"), "required_source_truth.matrix.required_healing_actions"))
    require(known_actions == required_actions, "matrix known_healing_actions drift")
    heal_text = text_for(artifacts.get("healing_source", ""), "source_artifacts.healing_source")
    require(set(extract_healing_action_variants(heal_text)) == known_actions, "HealingAction enum and matrix known actions drift")

    iconv_fixture = load_json(ROOT / artifacts.get("iconv_fixture", ""), "iconv fixture")
    iconv_case = None
    for row in iconv_fixture.get("cases", []):
        if isinstance(row, dict) and row.get("name") == iconv_truth.get("case_name"):
            iconv_case = row
            break
    if iconv_case is None:
        err("missing hardened iconv deny fixture case")
    else:
        require(iconv_case.get("expected_output") == iconv_truth.get("expected_output"), "iconv deny fixture expected_output drift")
        require(iconv_case.get("expected_errno") == iconv_truth.get("expected_errno"), "iconv deny fixture expected_errno drift")
        require(iconv_case.get("mode") == "hardened", "iconv deny fixture must be hardened")
    conformance_text = text_for(artifacts.get("conformance_executor", ""), "source_artifacts.conformance_executor")
    require(str(iconv_truth.get("unit_test", "")) in conformance_text, "missing hardened iconv deny unit test")

    checker_text = text_for(artifacts.get("matrix_checker", ""), "source_artifacts.matrix_checker")
    for token in strings(checker_truth.get("required_tokens"), "required_source_truth.checker.required_tokens"):
        require(token in checker_text, f"matrix checker missing token {token}")
    for field in strings(checker_truth.get("required_log_fields"), "required_source_truth.checker.required_log_fields"):
        require(field in checker_text, f"matrix checker missing log field {field}")

    append_event(
        "hardened_repair_deny_matrix_validated",
        "pass" if not errors else "fail",
        [artifacts.get("matrix", ""), artifacts.get("healing_source", ""), artifacts.get("iconv_fixture", "")],
        {
            "entry_count": summary.get("entry_count") if isinstance(summary, dict) else None,
            "repair_entries": summary.get("repair_entries") if isinstance(summary, dict) else None,
            "deny_entries": summary.get("deny_entries") if isinstance(summary, dict) else None,
        },
    )
    return {"summary": summary, "policy_ids": policy_ids}


def replay_matrix_gate(artifacts: dict[str, str]) -> dict[str, Any]:
    checker = ROOT / artifacts.get("matrix_checker", "")
    if not checker.is_file():
        err("matrix checker missing before replay")
        return {}
    output = subprocess.run(
        ["bash", str(checker)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if output.returncode != 0:
        err(f"matrix checker replay failed: stdout={output.stdout} stderr={output.stderr}")
    report = load_json(ROOT / "target/conformance/hardened_repair_deny_matrix.report.json", "matrix checker report")
    log_path = ROOT / "target/conformance/hardened_repair_deny_matrix.log.jsonl"
    log_text = log_path.read_text(encoding="utf-8") if log_path.is_file() else ""
    if not log_text.strip():
        err("matrix checker replay did not emit JSONL log")
    policy_hash = report.get("summary", {}).get("policy_mapping_sha256") if isinstance(report.get("summary"), dict) else None
    require(isinstance(policy_hash, str) and re.fullmatch(r"[0-9a-f]{64}", policy_hash) is not None, "matrix checker report missing 64-char policy_mapping_sha256")
    append_event(
        "hardened_repair_deny_gate_replayed",
        "pass" if output.returncode == 0 and not errors else "fail",
        [
            artifacts.get("matrix_checker", ""),
            "target/conformance/hardened_repair_deny_matrix.report.json",
            "target/conformance/hardened_repair_deny_matrix.log.jsonl",
        ],
        {"returncode": output.returncode, "policy_mapping_sha256": policy_hash},
    )
    return {"policy_mapping_sha256": policy_hash}


def finalize(manifest: dict[str, Any], matrix_summary: dict[str, Any], gate_summary: dict[str, Any]) -> int:
    status = "fail" if errors else "pass"
    append_event(
        "hardened_repair_deny_completion_summary",
        status,
        [rel(CONTRACT), rel(REPORT), rel(LOG)],
        {
            "entry_count": matrix_summary.get("summary", {}).get("entry_count") if isinstance(matrix_summary.get("summary"), dict) else None,
            "repair_entries": matrix_summary.get("summary", {}).get("repair_entries") if isinstance(matrix_summary.get("summary"), dict) else None,
            "deny_entries": matrix_summary.get("summary", {}).get("deny_entries") if isinstance(matrix_summary.get("summary"), dict) else None,
            "policy_mapping_sha256": gate_summary.get("policy_mapping_sha256"),
        },
    )
    observed = {event["event"] for event in events}
    missing = sorted(EXPECTED_EVENTS - observed)
    if missing:
        errors.append(f"missing required telemetry events: {missing}")
        status = "fail"
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "manifest_id": manifest.get("manifest_id"),
        "source_bead": SOURCE_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "source_commit": git_head(),
        "summary": {
            "entry_count": matrix_summary.get("summary", {}).get("entry_count") if isinstance(matrix_summary.get("summary"), dict) else None,
            "repair_entries": matrix_summary.get("summary", {}).get("repair_entries") if isinstance(matrix_summary.get("summary"), dict) else None,
            "deny_entries": matrix_summary.get("summary", {}).get("deny_entries") if isinstance(matrix_summary.get("summary"), dict) else None,
            "policy_mapping_sha256": gate_summary.get("policy_mapping_sha256"),
            "events": len(events),
        },
        "events": [event["event"] for event in events],
        "errors": errors,
    }
    write_json(REPORT, report)
    write_jsonl(LOG, events)
    if status == "pass":
        print(f"PASS: hardened repair/deny completion contract validated ({rel(REPORT)})")
        return 0
    print("FAIL: hardened repair/deny completion contract failed", flush=True)
    for message in errors:
        print(f"  - {message}", flush=True)
    return 1


manifest = load_json(CONTRACT, "completion contract")
artifacts = validate_manifest(manifest)
matrix_summary = validate_matrix_sources(manifest, artifacts)
gate_summary = replay_matrix_gate(artifacts) if not errors else {}
raise SystemExit(finalize(manifest, matrix_summary, gate_summary))
PY
