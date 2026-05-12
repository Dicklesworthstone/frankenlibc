#!/usr/bin/env bash
# check_concurrency_signal_completion_contract.sh -- fail-closed gate for bd-2tq.6.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_CONCURRENCY_SIGNAL_CONTRACT:-${ROOT}/tests/conformance/concurrency_signal_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_CONCURRENCY_SIGNAL_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_CONCURRENCY_SIGNAL_REPORT:-${OUT_DIR}/concurrency_signal_completion_contract.report.json}"
LOG="${FRANKENLIBC_CONCURRENCY_SIGNAL_LOG:-${OUT_DIR}/concurrency_signal_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

BEAD_ID = "bd-2tq.6"
COMPLETION_BEAD_ID = "bd-2tq.6.1"
MANIFEST_ID = "concurrency-signal-completion-contract"
REQUIRED_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_ARTIFACTS = {
    "signal_abi_test",
    "pthread_abi_test",
    "signal_diff_test",
    "signal_fixture_pack",
    "pthread_fixture_pack",
    "fuzz_gap_contract",
    "signal_native_script",
    "pthread_native_script",
}
REQUIRED_EVENTS = {
    "concurrency_signal_source",
    "concurrency_signal_tests",
    "concurrency_signal_e2e",
    "concurrency_signal_fuzz",
    "concurrency_signal_conformance",
    "concurrency_signal_telemetry",
    "concurrency_signal_summary",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: Path, errors: list[str], context: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{context} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{context} must be a JSON object")
        return {}
    return value


def read_text(path_text: str, errors: list[str], context: str) -> str:
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} missing file: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{context} unreadable: {path_text}: {exc}")
        return ""


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def strings(value: Any, errors: list[str], context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{context} must be a non-empty array")
        return []
    out: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{context}[{index}] must be a non-empty string")
        else:
            out.append(item)
    return out


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}(" in source_text or f"fn {name}<" in source_text


def event_row(event: str, status: str, artifact_refs: list[str], **extra: Any) -> dict[str, Any]:
    row = {
        "artifact_refs": artifact_refs,
        "bead": BEAD_ID,
        "completion_debt_bead": COMPLETION_BEAD_ID,
        "event": event,
        "status": status,
        "timestamp": utc_now(),
        "trace_id": f"{COMPLETION_BEAD_ID}::{event}::{len(artifact_refs)}",
    }
    row.update(extra)
    return row


def validate_source_artifacts(
    contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]
) -> dict[str, str]:
    artifacts = contract.get("source_artifacts")
    paths: dict[str, str] = {}
    if not isinstance(artifacts, list):
        errors.append("source_artifacts must be an array")
        return paths

    seen: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("source_artifacts entries must be objects")
            continue
        artifact_id = artifact.get("artifact_id")
        path_text = artifact.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            errors.append("source artifact missing artifact_id")
            continue
        seen.add(artifact_id)
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"{artifact_id}.path missing")
            continue
        paths[artifact_id] = path_text
        text = read_text(path_text, errors, artifact_id)
        for needle in strings(artifact.get("required_needles"), errors, f"{artifact_id}.required_needles"):
            if needle not in text:
                errors.append(f"{artifact_id} missing needle {needle!r}")
        rows.append(
            event_row(
                "concurrency_signal_source",
                "pass" if text else "fail",
                [path_text],
                artifact_id=artifact_id,
            )
        )

    if seen != REQUIRED_ARTIFACTS:
        errors.append(f"source_artifacts must be exactly {sorted(REQUIRED_ARTIFACTS)}, got {sorted(seen)}")
    return paths


def validate_commands(commands: Any, errors: list[str], context: str) -> None:
    for command in strings(commands, errors, f"{context}.required_commands"):
        if "cargo " in command and "rch exec -- cargo " not in command and "rch exec -- env " not in command:
            errors.append(f"{context} cargo command must be rch-backed: {command}")


def validate_artifact_ids(
    value: Any,
    paths: dict[str, str],
    errors: list[str],
    context: str,
) -> list[str]:
    artifact_ids = strings(value, errors, f"{context}.artifact_ids")
    refs: list[str] = []
    for artifact_id in artifact_ids:
        path = paths.get(artifact_id)
        if path is None:
            errors.append(f"{context} references unknown artifact_id {artifact_id}")
        else:
            refs.append(path)
    return refs


def validate_test_groups(
    groups: Any,
    paths: dict[str, str],
    errors: list[str],
    context: str,
) -> tuple[list[str], int]:
    if not isinstance(groups, list) or not groups:
        errors.append(f"{context}.test_groups must be a non-empty array")
        return [], 0
    refs: list[str] = []
    found_count = 0
    for index, group in enumerate(groups):
        if not isinstance(group, dict):
            errors.append(f"{context}.test_groups[{index}] must be an object")
            continue
        artifact_id = group.get("artifact_id")
        if not isinstance(artifact_id, str) or artifact_id not in paths:
            errors.append(f"{context}.test_groups[{index}].artifact_id unknown")
            continue
        source_path = paths[artifact_id]
        if source_path not in refs:
            refs.append(source_path)
        source_text = read_text(source_path, errors, f"{context}.{artifact_id}")
        for name in strings(group.get("test_names"), errors, f"{context}.{artifact_id}.test_names"):
            if function_exists(source_text, name):
                found_count += 1
            else:
                errors.append(f"{context} references missing test {name} in {artifact_id}")
    return refs, found_count


def load_fuzz_modules(paths: dict[str, str], errors: list[str]) -> dict[str, set[str]]:
    fuzz_path = paths.get("fuzz_gap_contract")
    if fuzz_path is None:
        errors.append("fuzz_gap_contract artifact missing")
        return {}
    data = load_json(root / fuzz_path, errors, "fuzz_gap_contract")
    modules = data.get("required_module_fuzz_coverage")
    if not isinstance(modules, list):
        errors.append("fuzz_gap_contract.required_module_fuzz_coverage must be an array")
        return {}
    result: dict[str, set[str]] = {}
    for module in modules:
        if not isinstance(module, dict):
            continue
        module_id = module.get("module_id")
        if not isinstance(module_id, str) or not module_id:
            continue
        targets: set[str] = set()
        for target in module.get("targets", []):
            if isinstance(target, dict) and isinstance(target.get("name"), str):
                target_name = target["name"]
                targets.add(target_name)
                target_path = target.get("path")
                if isinstance(target_path, str) and not (root / target_path).is_file():
                    errors.append(f"fuzz target missing file: {target_path}")
        result[module_id] = targets
    return result


def validate_fuzz_section(
    section: dict[str, Any],
    paths: dict[str, str],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    if section.get("missing_item_id") != "tests.fuzz.primary":
        errors.append("fuzz_primary.missing_item_id must be tests.fuzz.primary")
    if section.get("contract_artifact_id") != "fuzz_gap_contract":
        errors.append("fuzz_primary.contract_artifact_id must be fuzz_gap_contract")
    validate_commands(section.get("required_commands"), errors, "fuzz_primary")
    modules = load_fuzz_modules(paths, errors)
    required_modules = strings(section.get("required_modules"), errors, "fuzz_primary.required_modules")
    required_targets = set(strings(section.get("required_targets"), errors, "fuzz_primary.required_targets"))
    covered_targets: set[str] = set()
    for module_id in required_modules:
        targets = modules.get(module_id)
        if targets is None:
            errors.append(f"fuzz_primary missing module {module_id}")
            continue
        covered_targets.update(targets)
    missing_targets = sorted(required_targets - covered_targets)
    if missing_targets:
        errors.append(f"fuzz_primary missing targets {missing_targets}")
    rows.append(
        event_row(
            "concurrency_signal_fuzz",
            "pass" if not missing_targets else "fail",
            [paths.get("fuzz_gap_contract", "")],
            module_count=len(required_modules),
            target_count=len(required_targets),
        )
    )


def validate_evidence(
    contract: dict[str, Any],
    paths: dict[str, str],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return
    if evidence.get("bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = evidence.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 900:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 900")
    missing = set(strings(evidence.get("missing_items_closed"), errors, "completion_debt_evidence.missing_items_closed"))
    if missing != REQUIRED_ITEMS:
        errors.append(f"completion_debt_evidence.missing_items_closed must be {sorted(REQUIRED_ITEMS)}")

    unit = evidence.get("unit_primary")
    if not isinstance(unit, dict):
        errors.append("unit_primary must be an object")
    else:
        if unit.get("missing_item_id") != "tests.unit.primary":
            errors.append("unit_primary.missing_item_id must be tests.unit.primary")
        validate_commands(unit.get("required_commands"), errors, "unit_primary")
        refs, test_count = validate_test_groups(unit.get("test_groups"), paths, errors, "unit_primary")
        rows.append(event_row("concurrency_signal_tests", "pass", refs, section="unit_primary", test_count=test_count))

    e2e = evidence.get("e2e_primary")
    if not isinstance(e2e, dict):
        errors.append("e2e_primary must be an object")
    else:
        if e2e.get("missing_item_id") != "tests.e2e.primary":
            errors.append("e2e_primary.missing_item_id must be tests.e2e.primary")
        validate_commands(e2e.get("required_commands"), errors, "e2e_primary")
        refs = validate_artifact_ids(e2e.get("artifact_ids"), paths, errors, "e2e_primary")
        rows.append(event_row("concurrency_signal_e2e", "pass", refs, artifact_count=len(refs)))

    fuzz = evidence.get("fuzz_primary")
    if not isinstance(fuzz, dict):
        errors.append("fuzz_primary must be an object")
    else:
        validate_fuzz_section(fuzz, paths, errors, rows)

    conformance = evidence.get("conformance_primary")
    if not isinstance(conformance, dict):
        errors.append("conformance_primary must be an object")
    else:
        if conformance.get("missing_item_id") != "tests.conformance.primary":
            errors.append("conformance_primary.missing_item_id must be tests.conformance.primary")
        validate_commands(conformance.get("required_commands"), errors, "conformance_primary")
        refs = validate_artifact_ids(conformance.get("artifact_ids"), paths, errors, "conformance_primary")
        test_refs, test_count = validate_test_groups(
            conformance.get("test_groups"), paths, errors, "conformance_primary"
        )
        for test_ref in test_refs:
            if test_ref not in refs:
                refs.append(test_ref)
        rows.append(
            event_row(
                "concurrency_signal_conformance",
                "pass",
                refs,
                artifact_count=len(refs),
                test_count=test_count,
            )
        )

    telemetry = evidence.get("telemetry_primary")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_primary must be an object")
    else:
        if telemetry.get("missing_item_id") != "telemetry.primary":
            errors.append("telemetry_primary.missing_item_id must be telemetry.primary")
        events = set(strings(telemetry.get("required_events"), errors, "telemetry_primary.required_events"))
        if events != REQUIRED_EVENTS:
            errors.append(f"telemetry_primary.required_events must be {sorted(REQUIRED_EVENTS)}")
        fields = set(strings(telemetry.get("required_fields"), errors, "telemetry_primary.required_fields"))
        for field in ("timestamp", "trace_id", "event", "status", "bead", "completion_debt_bead", "artifact_refs"):
            if field not in fields:
                errors.append(f"telemetry_primary.required_fields missing {field}")
        artifact_ids = set(strings(telemetry.get("required_artifact_ids"), errors, "telemetry_primary.required_artifact_ids"))
        if artifact_ids != REQUIRED_ARTIFACTS:
            errors.append(f"telemetry_primary.required_artifact_ids must be {sorted(REQUIRED_ARTIFACTS)}")
        for field in ("report_path", "log_path"):
            if not isinstance(telemetry.get(field), str) or not telemetry[field]:
                errors.append(f"telemetry_primary.{field} missing")
        rows.append(
            event_row(
                "concurrency_signal_telemetry",
                "pass" if events == REQUIRED_EVENTS else "fail",
                sorted(paths.values()),
                required_event_count=len(events),
            )
        )


errors: list[str] = []
rows: list[dict[str, Any]] = []
contract = load_json(contract_path, errors, "contract")

if contract.get("schema_version") != "concurrency_signal_completion_contract.v1":
    errors.append("schema_version mismatch")
if contract.get("manifest_id") != MANIFEST_ID:
    errors.append(f"manifest_id must be {MANIFEST_ID}")
if contract.get("bead") != BEAD_ID:
    errors.append(f"bead must be {BEAD_ID}")
if contract.get("completion_debt_bead") != COMPLETION_BEAD_ID:
    errors.append(f"completion_debt_bead must be {COMPLETION_BEAD_ID}")
if not isinstance(contract.get("next_audit_score_threshold"), int) or contract["next_audit_score_threshold"] < 900:
    errors.append("next_audit_score_threshold must be >= 900")

paths = validate_source_artifacts(contract, errors, rows)
validate_evidence(contract, paths, errors, rows)

status = "fail" if errors else "pass"
summary = event_row(
    "concurrency_signal_summary",
    status,
    [rel(contract_path)],
    source_count=len(paths),
    missing_item_count=len(REQUIRED_ITEMS),
)
rows.append(summary)

report = {
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "errors": errors,
    "event_count": len(rows),
    "manifest_id": contract.get("manifest_id"),
    "missing_item_count": len(REQUIRED_ITEMS),
    "source_count": len(paths),
    "status": status,
}
write_json(report_path, report)
write_jsonl(log_path, rows)

if errors:
    print("concurrency_signal_completion_contract: FAIL")
    for error in errors:
        print(f"- {error}")
    sys.exit(1)

print(
    "concurrency_signal_completion_contract: PASS "
    f"sources={len(paths)} events={len(rows)}"
)
PY
