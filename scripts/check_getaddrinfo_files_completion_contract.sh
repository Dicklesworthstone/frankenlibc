#!/usr/bin/env bash
# Validate bd-66s.1 getaddrinfo/getnameinfo files-backend completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_GETADDRINFO_FILES_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/getaddrinfo_files_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_GETADDRINFO_FILES_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/getaddrinfo_files_completion_contract}"
REPORT="${FRANKENLIBC_GETADDRINFO_FILES_COMPLETION_REPORT:-${OUT_DIR}/report.json}"
LOG="${FRANKENLIBC_GETADDRINFO_FILES_COMPLETION_LOG:-${OUT_DIR}/events.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(sys.argv[1])
CONTRACT = Path(sys.argv[2])
REPORT = Path(sys.argv[3])
LOG = Path(sys.argv[4])

SCHEMA = "getaddrinfo_files_completion_contract.v1"
REPORT_SCHEMA = "getaddrinfo_files_completion_contract.report.v1"
BEAD_ID = "bd-66s.1"
ORIGINAL_BEAD = "bd-66s"
TRACE_ID = "bd-66s.1::getaddrinfo-files::v1"
MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary", "telemetry.primary"}
EXPECTED_UNIT_TESTS = {
    "lookup_hosts_found",
    "lookup_service_found",
    "getaddrinfo_numeric_ipv4",
    "getaddrinfo_with_hosts_ipv4_lookup",
    "getaddrinfo_with_hosts_no_network_fallback",
    "getaddrinfo_numeric_ipv4_resolves",
    "getaddrinfo_uses_overridden_hosts_backend",
    "getnameinfo_ipv4_formats_numeric",
    "getservbyname_uses_overridden_services_backend_and_ignores_malformed_lines",
}
EXPECTED_E2E_SCENARIOS = {
    "nss-numeric-hosts-bypass",
    "nss-hosts-files-only",
    "nss-services-files-only",
}
EVENTS = {
    "source": "getaddrinfo_files_completion.source_artifacts",
    "unit": "getaddrinfo_files_completion.unit_bindings",
    "e2e": "getaddrinfo_files_completion.e2e_bindings",
    "telemetry": "getaddrinfo_files_completion.telemetry_bindings",
    "validated": "getaddrinfo_files_completion.validated",
    "failed": "getaddrinfo_files_completion.failed",
}

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def add_error(signature: str, message: str) -> None:
    errors.append({"signature": signature, "message": message})


def strings(value: Any, label: str, signature: str) -> list[str]:
    if not isinstance(value, list):
        add_error(signature, f"{label} must be an array")
        return []
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            add_error(signature, f"{label} entries must be non-empty strings")
            continue
        out.append(item)
    return out


def load_json(path: Path, label: str, signature: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{label} unreadable: {path}: {exc}")
        return {}


def workspace_path(rel: Any, signature: str) -> Path | None:
    if not isinstance(rel, str) or not rel:
        add_error(signature, f"invalid relative path: {rel!r}")
        return None
    path = Path(rel)
    if path.is_absolute() or ".." in path.parts:
        add_error(signature, f"unsafe relative path: {rel}")
        return None
    return ROOT / path


def read_workspace_text(rel: Any, signature: str) -> str:
    path = workspace_path(rel, signature)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error(signature, f"source artifact unreadable: {rel}: {exc}")
        return ""


def artifact_map(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    artifacts: dict[str, dict[str, Any]] = {}
    rows = contract.get("source_artifacts")
    if not isinstance(rows, list):
        add_error("missing_source_artifact", "source_artifacts must be an array")
        return artifacts
    for row in rows:
        if not isinstance(row, dict):
            add_error("missing_source_artifact", "source_artifacts entries must be objects")
            continue
        artifact_id = row.get("id")
        if not isinstance(artifact_id, str) or not artifact_id:
            add_error("missing_source_artifact", "source artifact id missing")
            continue
        path = workspace_path(row.get("path"), "missing_source_artifact")
        if path is None or not path.is_file():
            add_error("missing_source_artifact", f"source artifact missing: {row.get('path')}")
            continue
        text = path.read_text(encoding="utf-8")
        for needle in strings(row.get("required_needles"), f"{artifact_id}.required_needles", "missing_source_artifact"):
            if needle not in text:
                add_error("missing_source_artifact", f"{artifact_id} missing required needle: {needle}")
        artifacts[artifact_id] = row
    emit(EVENTS["source"], "pass" if not errors else "fail", {"source_count": len(artifacts)})
    return artifacts


def require_rch(commands: Any, label: str, signature: str) -> None:
    command_list = strings(commands, label, signature)
    if not command_list:
        return
    if not any("rch exec -- cargo" in command or "rch cargo" in command for command in command_list):
        add_error(signature, f"{label} must include rch cargo validation")


def emit(event: str, status: str, details: dict[str, Any] | None = None) -> None:
    details = details or {}
    row = {
        "timestamp": now(),
        "trace_id": TRACE_ID,
        "event": event,
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "status": status,
        "unit_test_count": details.get("unit_test_count", 0),
        "e2e_scenario_count": details.get("e2e_scenario_count", 0),
        "telemetry_event_count": details.get("telemetry_event_count", 0),
        "source_count": details.get("source_count", 0),
        "failure_signature": details.get("failure_signature", "none"),
    }
    events.append(row)


def validate_top_level(contract: dict[str, Any]) -> None:
    if contract.get("schema_version") != SCHEMA:
        add_error("top_level_drift", "schema_version drifted")
    if contract.get("bead_id") != BEAD_ID:
        add_error("top_level_drift", "bead_id drifted")
    if contract.get("original_bead") != ORIGINAL_BEAD:
        add_error("top_level_drift", "original_bead drifted")
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        add_error("top_level_drift", "completion_debt_evidence must be an object")
        return
    closed = set(strings(evidence.get("missing_items_closed"), "completion_debt_evidence.missing_items_closed", "top_level_drift"))
    if closed != MISSING_ITEMS:
        add_error("top_level_drift", f"missing_items_closed drifted: {sorted(closed)}")


def source_text(artifacts: dict[str, dict[str, Any]], source: str) -> str:
    artifact = artifacts.get(source)
    if artifact is None:
        add_error("missing_source_artifact", f"unknown source artifact: {source}")
        return ""
    return read_workspace_text(artifact.get("path"), "missing_source_artifact")


def validate_unit(contract: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> int:
    section = contract.get("unit_primary")
    if not isinstance(section, dict):
        add_error("missing_unit_binding", "unit_primary must be an object")
        return 0
    if section.get("missing_item_id") != "tests.unit.primary":
        add_error("missing_unit_binding", "unit_primary missing_item_id drifted")
    require_rch(section.get("required_commands"), "unit_primary.required_commands", "missing_unit_binding")
    tests = section.get("required_tests")
    if not isinstance(tests, list):
        add_error("missing_unit_binding", "unit_primary.required_tests must be an array")
        return 0
    count = 0
    cache: dict[str, str] = {}
    seen_names: set[str] = set()
    for test in tests:
        if not isinstance(test, dict):
            add_error("missing_unit_binding", "required_tests entries must be objects")
            continue
        source = test.get("source")
        name = test.get("name")
        if not isinstance(source, str) or not isinstance(name, str):
            add_error("missing_unit_binding", "required_tests need source and name")
            continue
        text = cache.setdefault(source, source_text(artifacts, source))
        if f"fn {name}" not in text:
            add_error("missing_unit_binding", f"{source} missing fn {name}")
        seen_names.add(name)
        count += 1
    if seen_names != EXPECTED_UNIT_TESTS:
        add_error(
            "missing_unit_binding",
            f"unit test bindings drifted: missing={sorted(EXPECTED_UNIT_TESTS - seen_names)} extra={sorted(seen_names - EXPECTED_UNIT_TESTS)}",
        )
    emit(EVENTS["unit"], "pass" if not errors else "fail", {"unit_test_count": count})
    return count


def validate_e2e(contract: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> int:
    section = contract.get("e2e_primary")
    if not isinstance(section, dict):
        add_error("missing_e2e_binding", "e2e_primary must be an object")
        return 0
    if section.get("missing_item_id") != "tests.e2e.primary":
        add_error("missing_e2e_binding", "e2e_primary missing_item_id drifted")
    require_rch(section.get("required_commands"), "e2e_primary.required_commands", "missing_e2e_binding")
    required = set(strings(section.get("required_scenarios"), "e2e_primary.required_scenarios", "missing_e2e_binding"))
    if required != EXPECTED_E2E_SCENARIOS:
        add_error(
            "missing_e2e_binding",
            f"required e2e scenarios drifted: missing={sorted(EXPECTED_E2E_SCENARIOS - required)} extra={sorted(required - EXPECTED_E2E_SCENARIOS)}",
        )
    modes = set(strings(section.get("required_runtime_modes"), "e2e_primary.required_runtime_modes", "missing_e2e_binding"))
    if modes != {"strict", "hardened"}:
        add_error("missing_e2e_binding", f"runtime modes drifted: {sorted(modes)}")
    manifest_artifact = artifacts.get(section.get("manifest"))
    if manifest_artifact is None:
        add_error("missing_e2e_binding", "e2e manifest artifact missing")
        return 0
    manifest_path = workspace_path(manifest_artifact.get("path"), "missing_e2e_binding")
    manifest = load_json(manifest_path, "hermetic lab manifest", "missing_e2e_binding") if manifest_path else {}
    scenarios = manifest.get("scenarios") if isinstance(manifest, dict) else None
    if not isinstance(scenarios, list):
        add_error("missing_e2e_binding", "hermetic lab scenarios must be an array")
        scenarios = []
    seen = {row.get("scenario_id") for row in scenarios if isinstance(row, dict)}
    if seen & required != required:
        add_error("missing_e2e_binding", f"missing e2e scenarios: {sorted(required - seen)}")
    for row in scenarios:
        if not isinstance(row, dict) or row.get("scenario_id") not in required:
            continue
        row_modes = set(strings(row.get("runtime_modes"), f"{row.get('scenario_id')}.runtime_modes", "missing_e2e_binding"))
        if row_modes != {"strict", "hardened"}:
            add_error("missing_e2e_binding", f"{row.get('scenario_id')} mode coverage drifted")
        if "fixture_obligation" not in row:
            add_error("missing_e2e_binding", f"{row.get('scenario_id')} missing fixture_obligation")
    runner_artifact = artifacts.get(section.get("runner"))
    if runner_artifact is None:
        add_error("missing_e2e_binding", "e2e runner artifact missing")
    emit(EVENTS["e2e"], "pass" if not errors else "fail", {"e2e_scenario_count": len(required)})
    return len(required)


def validate_telemetry(contract: dict[str, Any]) -> int:
    section = contract.get("telemetry_primary")
    if not isinstance(section, dict):
        add_error("missing_telemetry_binding", "telemetry_primary must be an object")
        return 0
    if section.get("missing_item_id") != "telemetry.primary":
        add_error("missing_telemetry_binding", "telemetry_primary missing_item_id drifted")
    required_events = set(strings(section.get("required_events"), "telemetry_primary.required_events", "missing_telemetry_binding"))
    expected = {EVENTS["source"], EVENTS["unit"], EVENTS["e2e"], EVENTS["telemetry"], EVENTS["validated"]}
    if required_events != expected:
        add_error("missing_telemetry_binding", f"telemetry events drifted: {sorted(required_events)}")
    required_fields = set(strings(section.get("required_fields"), "telemetry_primary.required_fields", "missing_telemetry_binding"))
    for field in [
        "timestamp",
        "trace_id",
        "event",
        "bead_id",
        "original_bead",
        "status",
        "unit_test_count",
        "e2e_scenario_count",
        "telemetry_event_count",
        "failure_signature",
    ]:
        if field not in required_fields:
            add_error("missing_telemetry_binding", f"required telemetry field missing: {field}")
    emit(EVENTS["telemetry"], "pass" if not errors else "fail", {"telemetry_event_count": len(required_events)})
    return len(required_events)


contract_value = load_json(CONTRACT, "contract", "json_parse")
contract = contract_value if isinstance(contract_value, dict) else {}
validate_top_level(contract)
artifacts = artifact_map(contract)
unit_count = validate_unit(contract, artifacts)
e2e_count = validate_e2e(contract, artifacts)
telemetry_count = validate_telemetry(contract)
ok = not errors
emit(
    EVENTS["validated"] if ok else EVENTS["failed"],
    "pass" if ok else "fail",
    {
        "unit_test_count": unit_count,
        "e2e_scenario_count": e2e_count,
        "telemetry_event_count": telemetry_count,
        "failure_signature": "none" if ok else ",".join(sorted({e["signature"] for e in errors})),
    },
)

REPORT.write_text(
    json.dumps(
        {
            "schema_version": REPORT_SCHEMA,
            "status": "pass" if ok else "fail",
            "bead_id": BEAD_ID,
            "original_bead": ORIGINAL_BEAD,
            "trace_id": TRACE_ID,
            "source_count": len(artifacts),
            "unit_test_count": unit_count,
            "e2e_scenario_count": e2e_count,
            "telemetry_event_count": telemetry_count,
            "missing_items": sorted(MISSING_ITEMS),
            "failure_signature": "none" if ok else ",".join(sorted({e["signature"] for e in errors})),
            "errors": errors,
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
LOG.write_text("\n".join(json.dumps(row, sort_keys=True) for row in events) + "\n", encoding="utf-8")
if ok:
    print(
        f"PASS getaddrinfo files completion contract sources={len(artifacts)} "
        f"unit_refs={unit_count} e2e_scenarios={e2e_count} telemetry_events={telemetry_count}"
    )
else:
    print(f"FAIL getaddrinfo files completion contract errors={len(errors)}", file=sys.stderr)
    for error in errors:
        print(f"- {error['signature']}: {error['message']}", file=sys.stderr)
    sys.exit(1)
PY
