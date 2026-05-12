#!/usr/bin/env bash
# check_isomorphism_proof_protocol_completion_contract.sh -- fail-closed gate for bd-2bd.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_ISOMORPHISM_PROTOCOL_CONTRACT:-${ROOT}/tests/conformance/isomorphism_proof_protocol_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_ISOMORPHISM_PROTOCOL_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_ISOMORPHISM_PROTOCOL_REPORT:-${OUT_DIR}/isomorphism_proof_protocol_completion_contract.report.json}"
LOG="${FRANKENLIBC_ISOMORPHISM_PROTOCOL_LOG:-${OUT_DIR}/isomorphism_proof_protocol_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

BEAD_ID = "bd-2bd"
COMPLETION_BEAD_ID = "bd-2bd.1"
MANIFEST_ID = "isomorphism-proof-protocol-completion-contract"
REQUIRED_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.golden.primary",
    "telemetry.primary",
}
REQUIRED_EVENTS = {
    "isomorphism_protocol_source",
    "isomorphism_protocol_template",
    "isomorphism_protocol_proof",
    "isomorphism_protocol_e2e",
    "isomorphism_protocol_summary",
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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return f"sha256:{digest.hexdigest()}"


def validate_source_artifacts(
    contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]
) -> None:
    artifacts = contract.get("source_artifacts")
    required = {
        "isomorphism_protocol",
        "isomorphism_gate",
        "isomorphism_source_tests",
    }
    if not isinstance(artifacts, list):
        errors.append("source_artifacts must be an array")
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
        seen.add(artifact_id)
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"{artifact_id}.path missing")
            continue
        text = read_text(path_text, errors, artifact_id)
        for needle in strings(artifact.get("required_needles"), errors, f"{artifact_id}.required_needles"):
            if needle not in text:
                errors.append(f"{artifact_id} missing needle {needle!r}")
        rows.append(
            {
                "event": "isomorphism_protocol_source",
                "status": "pass" if text else "fail",
                "artifact_id": artifact_id,
                "artifact_refs": [path_text],
                "timestamp": utc_now(),
            }
        )
    if seen != required:
        errors.append(f"source_artifacts must be exactly {sorted(required)}, got {sorted(seen)}")


def validate_completion_evidence(contract: dict[str, Any], errors: list[str]) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return
    if evidence.get("bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = evidence.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 800:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")
    missing = set(strings(evidence.get("missing_items_closed"), errors, "completion_debt_evidence.missing_items_closed"))
    if missing != REQUIRED_ITEMS:
        errors.append(f"completion_debt_evidence.missing_items_closed must be {sorted(REQUIRED_ITEMS)}")

    test_sources: dict[str, str] = {}
    for section in ("unit_primary", "e2e_primary", "golden_primary", "telemetry_primary"):
        item = evidence.get(section)
        if not isinstance(item, dict):
            errors.append(f"completion_debt_evidence.{section} must be an object")
            continue
        test_source = item.get("test_source") or evidence.get("unit_primary", {}).get("test_source")
        source_text = ""
        if isinstance(test_source, str):
            source_text = test_sources.setdefault(test_source, read_text(test_source, errors, f"{section}.test_source"))
        for name in strings(item.get("required_test_names"), errors, f"{section}.required_test_names"):
            if f"fn {name}(" not in source_text:
                errors.append(f"{section} references missing Rust test {name}")
    e2e = evidence.get("e2e_primary", {})
    if isinstance(e2e, dict):
        checker = e2e.get("checker")
        if not isinstance(checker, str) or not (root / checker).is_file():
            errors.append("e2e_primary.checker missing")
    golden = evidence.get("golden_primary", {})
    if isinstance(golden, dict):
        for field in ("golden_source", "checked_artifact", "checked_proof_directory"):
            value = golden.get(field)
            if not isinstance(value, str):
                errors.append(f"golden_primary.{field} missing")
                continue
            path = root / value
            if field.endswith("directory"):
                if not path.is_dir():
                    errors.append(f"golden_primary.{field} directory missing: {value}")
            elif not path.is_file():
                errors.append(f"golden_primary.{field} file missing: {value}")
    telemetry = evidence.get("telemetry_primary", {})
    if isinstance(telemetry, dict):
        for field in ("report_path", "log_path"):
            value = telemetry.get(field)
            if not isinstance(value, str) or not value:
                errors.append(f"telemetry_primary.{field} missing")


def validate_protocol(
    contract: dict[str, Any],
    protocol: dict[str, Any],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    expectations = contract.get("protocol_expectations")
    if not isinstance(expectations, dict):
        errors.append("protocol_expectations must be an object")
        return
    min_version = expectations.get("minimum_schema_version")
    if not isinstance(min_version, int):
        errors.append("protocol_expectations.minimum_schema_version must be an integer")
        min_version = 0
    if protocol.get("schema_version", 0) < min_version:
        errors.append(f"protocol schema_version must be >= {min_version}")

    categories = protocol.get("proof_categories")
    if not isinstance(categories, dict):
        errors.append("protocol proof_categories must be an object")
        categories = {}
    required_categories = set(strings(expectations.get("required_categories"), errors, "protocol_expectations.required_categories"))
    if set(categories.keys()) != required_categories:
        errors.append(f"protocol categories must be exactly {sorted(required_categories)}")

    template = protocol.get("proof_template")
    if not isinstance(template, dict):
        errors.append("protocol proof_template must be an object")
        template = {}
    required_fields = set(strings(expectations.get("required_template_fields"), errors, "protocol_expectations.required_template_fields"))
    actual_fields = set(strings(template.get("required_fields"), errors, "protocol.proof_template.required_fields"))
    missing_fields = sorted(required_fields - actual_fields)
    if missing_fields:
        errors.append(f"protocol template missing required fields {missing_fields}")
    required_statuses = set(strings(expectations.get("required_statuses"), errors, "protocol_expectations.required_statuses"))
    actual_statuses = set(strings(template.get("proof_statuses"), errors, "protocol.proof_template.proof_statuses"))
    if not required_statuses.issubset(actual_statuses):
        errors.append(f"protocol template statuses missing {sorted(required_statuses - actual_statuses)}")
    rows.append(
        {
            "event": "isomorphism_protocol_template",
            "status": "pass",
            "artifact_refs": ["tests/conformance/isomorphism_proof_protocol.json"],
            "category_count": len(categories),
            "template_field_count": len(actual_fields),
            "timestamp": utc_now(),
        }
    )

    applicable = protocol.get("applicable_modules")
    counts = expectations.get("applicable_module_counts")
    if not isinstance(applicable, dict) or not isinstance(counts, dict):
        errors.append("applicable_modules and applicable_module_counts must be objects")
    else:
        for key in ("high_priority", "medium_priority", "low_priority"):
            expected = counts.get(key)
            actual = len(applicable.get(key, [])) if isinstance(applicable.get(key), list) else None
            if expected != actual:
                errors.append(f"{key} module count expected={expected} actual={actual}")

    enforcement = expectations.get("enforcement")
    protocol_enforcement = protocol.get("enforcement")
    if not isinstance(enforcement, dict) or not isinstance(protocol_enforcement, dict):
        errors.append("enforcement expectations and protocol enforcement must be objects")
    else:
        if protocol_enforcement.get("ci_gate_script") != enforcement.get("ci_gate_script"):
            errors.append("protocol enforcement ci_gate_script drifted")
        needle = enforcement.get("merge_gate_contains")
        if not isinstance(needle, str) or needle not in str(protocol_enforcement.get("merge_gate", "")):
            errors.append("protocol enforcement merge_gate missing required wording")

    proof_dir_text = expectations.get("proof_directory")
    if not isinstance(proof_dir_text, str):
        errors.append("protocol_expectations.proof_directory missing")
        proof_dir = root / "__missing__"
    else:
        proof_dir = root / proof_dir_text
    if not proof_dir.is_dir():
        errors.append(f"proof directory missing: {proof_dir_text}")

    listed = {
        item.get("proof_path"): item
        for item in protocol.get("existing_proofs", [])
        if isinstance(item, dict)
    }
    required_proofs = expectations.get("required_existing_proofs")
    if not isinstance(required_proofs, list) or not required_proofs:
        errors.append("protocol_expectations.required_existing_proofs must be non-empty")
        required_proofs = []
    proof_fields = set(strings(contract.get("golden_expectations", {}).get("required_proof_artifact_fields"), errors, "golden_expectations.required_proof_artifact_fields"))
    for expected in required_proofs:
        if not isinstance(expected, dict):
            errors.append("required_existing_proofs entries must be objects")
            continue
        path_text = expected.get("proof_path")
        if not isinstance(path_text, str):
            errors.append("required proof missing proof_path")
            continue
        listed_item = listed.get(path_text)
        if not isinstance(listed_item, dict):
            errors.append(f"protocol missing existing_proofs entry {path_text}")
            continue
        for field in ("lever_id", "proof_status"):
            if listed_item.get(field) != expected.get(field):
                errors.append(f"{path_text}: existing_proofs {field} drifted")
        full_path = root / path_text
        proof = load_json(full_path, errors, f"proof {path_text}") if full_path.is_file() else {}
        if not proof:
            errors.append(f"proof file missing or empty: {path_text}")
            continue
        for field in proof_fields:
            if field not in proof:
                errors.append(f"{path_text}: missing proof field {field}")
        if proof.get("proof_status") != expected.get("proof_status"):
            errors.append(f"{path_text}: proof_status drifted")
        for artifact in proof.get("golden_artifacts", []):
            if not isinstance(artifact, dict):
                errors.append(f"{path_text}: golden_artifacts entries must be objects")
                continue
            artifact_path = artifact.get("path")
            expected_hash = artifact.get("sha256")
            if not isinstance(artifact_path, str) or not isinstance(expected_hash, str):
                errors.append(f"{path_text}: golden artifact path/hash missing")
                continue
            full_artifact = root / artifact_path
            if not full_artifact.is_file():
                errors.append(f"{path_text}: golden artifact missing: {artifact_path}")
                continue
            actual_hash = sha256(full_artifact)
            if actual_hash != expected_hash:
                errors.append(f"{path_text}: golden artifact hash mismatch for {artifact_path}")
        rows.append(
            {
                "event": "isomorphism_protocol_proof",
                "status": "pass",
                "artifact_refs": [path_text],
                "lever_id": proof.get("lever_id"),
                "proof_status": proof.get("proof_status"),
                "timestamp": utc_now(),
            }
        )


def validate_golden_summary(contract: dict[str, Any], protocol: dict[str, Any], errors: list[str]) -> None:
    golden = contract.get("golden_expectations")
    if not isinstance(golden, dict):
        errors.append("golden_expectations must be an object")
        return
    source = golden.get("golden_source")
    if source != "tests/conformance/isomorphism_proof_protocol.json":
        errors.append("golden_expectations.golden_source drifted")
    expected_summary = golden.get("summary")
    summary = protocol.get("summary")
    if not isinstance(expected_summary, dict) or not isinstance(summary, dict):
        errors.append("golden summary and protocol summary must be objects")
        return
    for key, expected in expected_summary.items():
        if summary.get(key) != expected:
            errors.append(f"protocol summary {key} expected={expected!r} actual={summary.get(key)!r}")


def validate_e2e(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> None:
    gate = contract.get("e2e_gate")
    if not isinstance(gate, dict):
        errors.append("e2e_gate must be an object")
        return
    command = gate.get("command")
    if command != "bash scripts/check_isomorphism_proof.sh":
        errors.append("e2e_gate.command must remain bash scripts/check_isomorphism_proof.sh")
        return
    result = subprocess.run(
        ["bash", "scripts/check_isomorphism_proof.sh"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        errors.append(
            "e2e_gate command failed "
            f"exit={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    for needle in strings(gate.get("required_stdout_needles"), errors, "e2e_gate.required_stdout_needles"):
        if needle not in result.stdout:
            errors.append(f"e2e_gate stdout missing needle {needle!r}")
    rows.append(
        {
            "event": "isomorphism_protocol_e2e",
            "status": "pass" if result.returncode == 0 else "fail",
            "artifact_refs": ["scripts/check_isomorphism_proof.sh"],
            "command": command,
            "exit_code": result.returncode,
            "timestamp": utc_now(),
        }
    )


def validate_telemetry(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> None:
    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_contract must be an object")
        return
    events = set(strings(telemetry.get("required_events"), errors, "telemetry_contract.required_events"))
    if events != REQUIRED_EVENTS:
        errors.append(f"telemetry_contract.required_events must be {sorted(REQUIRED_EVENTS)}")
    fields = set(strings(telemetry.get("required_log_fields"), errors, "telemetry_contract.required_log_fields"))
    for field in ("event", "status", "timestamp", "artifact_refs"):
        if field not in fields:
            errors.append(f"telemetry_contract.required_log_fields missing {field}")
    observed = {row.get("event") for row in rows}
    missing = events - observed
    if missing:
        errors.append(f"telemetry rows missing required events {sorted(missing)}")


def main() -> int:
    errors: list[str] = []
    rows: list[dict[str, Any]] = []
    contract = load_json(contract_path, errors, "contract")

    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_BEAD_ID}")

    validate_source_artifacts(contract, errors, rows)
    validate_completion_evidence(contract, errors)

    protocol_path = root / "tests/conformance/isomorphism_proof_protocol.json"
    protocol = load_json(protocol_path, errors, "isomorphism protocol")
    validate_protocol(contract, protocol, errors, rows)
    validate_golden_summary(contract, protocol, errors)
    validate_e2e(contract, errors, rows)

    rows.append(
        {
            "event": "isomorphism_protocol_summary",
            "status": "pass" if not errors else "fail",
            "artifact_refs": [
                rel(contract_path),
                "tests/conformance/isomorphism_proof_protocol.json",
                "scripts/check_isomorphism_proof.sh",
            ],
            "proof_count": len(protocol.get("existing_proofs", [])) if isinstance(protocol, dict) else 0,
            "timestamp": utc_now(),
        }
    )
    validate_telemetry(contract, errors, rows)

    status = "pass" if not errors else "fail"
    report = {
        "status": status,
        "manifest_id": contract.get("manifest_id"),
        "bead": contract.get("bead"),
        "completion_debt_bead": contract.get("completion_debt_bead"),
        "category_count": len(protocol.get("proof_categories", {})) if isinstance(protocol, dict) else 0,
        "proof_count": len(protocol.get("existing_proofs", [])) if isinstance(protocol, dict) else 0,
        "event_count": len(rows),
        "errors": errors,
    }
    write_json(report_path, report)
    write_jsonl(log_path, rows)

    if errors:
        print("isomorphism_proof_protocol_completion_contract: FAILED")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(
        "isomorphism_proof_protocol_completion_contract: PASS "
        f"categories={report['category_count']} proofs={report['proof_count']} events={report['event_count']}"
    )
    return 0


raise SystemExit(main())
PY
