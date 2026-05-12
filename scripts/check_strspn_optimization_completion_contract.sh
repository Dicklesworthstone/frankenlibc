#!/usr/bin/env bash
# check_strspn_optimization_completion_contract.sh -- fail-closed gate for bd-0e4vu.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_STRSPN_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/strspn_optimization_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_STRSPN_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_STRSPN_COMPLETION_REPORT:-${OUT_DIR}/strspn_optimization_completion_contract.report.json}"
LOG="${FRANKENLIBC_STRSPN_COMPLETION_LOG:-${OUT_DIR}/strspn_optimization_completion_contract.log.jsonl}"

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

BEAD_ID = "bd-0e4vu"
COMPLETION_BEAD_ID = "bd-0e4vu.1"
MANIFEST_ID = "strspn-optimization-completion-contract"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def load_json(path: Path, errors: list[str], context: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{context} unreadable: {rel(path)}: {exc}")
        return None


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


def require_strings(value: Any, errors: list[str], context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{context} must be a non-empty array")
        return []
    strings: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{context}[{index}] must be a non-empty string")
        else:
            strings.append(item)
    return strings


def validate_line_ref(ref: Any, errors: list[str], context: str) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"{context} must be a file:line string")
        return
    path_text, line_text = ref.rsplit(":", 1)
    if not line_text.isdigit() or int(line_text) <= 0:
        errors.append(f"{context} has invalid line number: {ref}")
        return
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        errors.append(f"{context} references line past EOF: {ref}")
    elif not lines[line_number - 1].strip():
        errors.append(f"{context} references blank line: {ref}")


def iter_json_values(value: Any) -> Any:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from iter_json_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_json_values(child)


def has_symbol(value: Any, symbol: str, status: str | None = None) -> bool:
    for item in iter_json_values(value):
        if item.get("symbol") != symbol:
            continue
        if status is None or item.get("status") == status:
            return True
    return False


def validate_source_artifacts(
    contract: dict[str, Any],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    artifacts = contract.get("source_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("source_artifacts must be a non-empty array")
        return
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
        if artifact_id in seen:
            errors.append(f"duplicate source artifact {artifact_id}")
        seen.add(artifact_id)
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"{artifact_id}.path missing")
            continue
        text = read_text(path_text, errors, artifact_id)
        for needle in require_strings(artifact.get("required_needles"), errors, f"{artifact_id}.required_needles"):
            if needle not in text:
                errors.append(f"{artifact_id} missing needle {needle!r}")
        for ref in artifact.get("required_line_refs", []):
            validate_line_ref(ref, errors, f"{artifact_id}.required_line_refs")
        rows.append({
            "event": "strspn_optimization.source_artifact",
            "artifact_id": artifact_id,
            "path": path_text,
            "status": "pass" if text else "fail",
            "timestamp": utc_now(),
        })
    expected = {
        "core_string_strspn",
        "abi_string_tests",
        "per_symbol_fixture_tests",
        "symbol_fixture_coverage",
        "perf_budget_policy",
        "completion_checker",
        "completion_harness_test",
    }
    if seen != expected:
        errors.append(f"source_artifacts must be exactly {sorted(expected)}, got {sorted(seen)}")


def validate_missing_item_bindings(contract: dict[str, Any], errors: list[str]) -> None:
    bindings = contract.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        errors.append("missing_item_bindings must be a non-empty array")
        return
    ids = {binding.get("id") for binding in bindings if isinstance(binding, dict)}
    if ids != REQUIRED_MISSING_ITEMS:
        errors.append(f"missing_item_bindings drifted: expected {sorted(REQUIRED_MISSING_ITEMS)}, got {sorted(ids)}")
    test_source = read_text(
        "crates/frankenlibc-harness/tests/strspn_optimization_completion_contract_test.rs",
        errors,
        "completion harness test",
    )
    for binding in bindings:
        if not isinstance(binding, dict):
            errors.append("missing_item_bindings entries must be objects")
            continue
        for test_name in binding.get("required_test_names", []):
            if not isinstance(test_name, str) or f"fn {test_name}(" not in test_source:
                errors.append(f"missing_item_bindings references missing Rust test {test_name}")


def validate_json_symbol_contracts(
    contract: dict[str, Any],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    for section_name in ["conformance_primary", "telemetry_primary"]:
        section = contract.get(section_name)
        if not isinstance(section, dict):
            errors.append(f"{section_name} must be an object")
            continue
        for artifact in section.get("required_json_symbols", []):
            if not isinstance(artifact, dict):
                errors.append(f"{section_name}.required_json_symbols entries must be objects")
                continue
            path_text = artifact.get("path")
            symbol = artifact.get("symbol")
            status = artifact.get("status")
            if not isinstance(path_text, str) or not isinstance(symbol, str):
                errors.append(f"{section_name} json symbol entry missing path/symbol")
                continue
            value = load_json(root / path_text, errors, path_text)
            if value is None:
                continue
            if not has_symbol(value, symbol, status if isinstance(status, str) else None):
                expected = f"{symbol} with status {status}" if isinstance(status, str) else symbol
                errors.append(f"{path_text} missing {expected}")
            rows.append({
                "event": f"strspn_optimization.{section_name}",
                "path": path_text,
                "symbol": symbol,
                "status": "pass",
                "timestamp": utc_now(),
            })


def main() -> int:
    errors: list[str] = []
    rows: list[dict[str, Any]] = []
    contract_value = load_json(contract_path, errors, "contract")
    contract = contract_value if isinstance(contract_value, dict) else {}
    if contract:
        if contract.get("schema_version") != "strspn_optimization_completion_contract.v1":
            errors.append("schema_version drifted")
        if contract.get("manifest_id") != MANIFEST_ID:
            errors.append("manifest_id drifted")
        if contract.get("bead") != BEAD_ID:
            errors.append(f"bead must be {BEAD_ID}")
        if contract.get("completion_debt_bead") != COMPLETION_BEAD_ID:
            errors.append(f"completion_debt_bead must be {COMPLETION_BEAD_ID}")
        validate_source_artifacts(contract, errors, rows)
        validate_missing_item_bindings(contract, errors)
        validate_json_symbol_contracts(contract, errors, rows)

    status = "fail" if errors else "pass"
    report = {
        "schema_version": "strspn_optimization_completion_contract.report.v1",
        "status": status,
        "source_bead": BEAD_ID,
        "completion_debt_bead": COMPLETION_BEAD_ID,
        "events": sorted({row["event"] for row in rows}),
        "errors": errors,
        "timestamp": utc_now(),
    }
    rows.append({
        "event": "strspn_optimization.completion_contract",
        "status": status,
        "source_bead": BEAD_ID,
        "completion_debt_bead": COMPLETION_BEAD_ID,
        "errors": errors,
        "timestamp": utc_now(),
    })
    write_json(report_path, report)
    write_jsonl(log_path, rows)
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("check_strspn_optimization_completion_contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
