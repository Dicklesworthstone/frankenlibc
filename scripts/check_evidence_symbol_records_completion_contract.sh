#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_EVIDENCE_SYMBOL_RECORDS_COMPLETION_CONTRACT:-$ROOT/tests/conformance/evidence_symbol_records_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_EVIDENCE_SYMBOL_RECORDS_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_EVIDENCE_SYMBOL_RECORDS_COMPLETION_REPORT:-$OUT_DIR/evidence_symbol_records_completion_contract.report.json}"
LOG="${FRANKENLIBC_EVIDENCE_SYMBOL_RECORDS_COMPLETION_LOG:-$OUT_DIR/evidence_symbol_records_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "evidence_symbol_records_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "evidence_symbol_records_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-oai.3"
COMPLETION_BEAD = "bd-oai.3.1"
TRACE_ID = "bd-oai-3-1-evidence-symbol-records-completion-v1"
PASS_EVENT = "evidence_symbol_records_completion_contract_validated"
FAIL_EVENT = "evidence_symbol_records_completion_contract_failed"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary": "unit",
    "tests.e2e.primary": "e2e",
    "telemetry.primary": "telemetry",
}
EXPECTED_EVENTS = {
    "evidence_symbol_records_source_gate",
    "evidence_symbol_records_layout_gate",
    "evidence_symbol_records_redundancy_gate",
    "evidence_symbol_records_sample_gate",
    "evidence_symbol_records_telemetry_gate",
    PASS_EVENT,
}
BASE_LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "status",
    "artifact_refs",
    "bead_id",
    "source_commit",
}

errors: list[str] = []
log_rows: list[dict[str, Any]] = []


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


COMMIT = source_commit()


def event(event_name: str, status: str, artifact_refs: list[str], **extra: Any) -> None:
    row = {
        "timestamp": utc_now(),
        "trace_id": TRACE_ID,
        "event": event_name,
        "status": status,
        "artifact_refs": artifact_refs,
        "bead_id": COMPLETION_BEAD,
        "source_commit": COMMIT,
    }
    row.update(extra)
    log_rows.append(row)


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


def string_set(value: Any, context: str, allow_empty: bool = False) -> set[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return set()
    result: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.add(item)
    return result


def read_text(path_text: str, context: str) -> str:
    path = ROOT / path_text
    if not path.is_file():
        err(f"{context} path missing: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} unreadable: {path_text}: {exc}")
        return ""


def validate_sources(contract: dict[str, Any]) -> dict[str, str]:
    artifacts = contract.get("source_artifacts")
    anchors = contract.get("source_anchors")
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}
    if not isinstance(anchors, dict) or not anchors:
        err("source_anchors must be a non-empty object")
        return {}

    paths: dict[str, str] = {}
    for key, value in artifacts.items():
        if not isinstance(value, str) or not value:
            err(f"source_artifacts.{key} must be a non-empty string")
            continue
        paths[key] = value
        text = read_text(value, f"source_artifacts.{key}")
        required = string_set(anchors.get(key), f"source_anchors.{key}")
        missing = sorted(anchor for anchor in required if anchor not in text)
        if missing:
            err(f"source_artifacts.{key} missing anchors: {missing}")
        event(
            "evidence_symbol_records_source_gate",
            "pass" if text and not missing else "fail",
            [value],
            source_key=key,
            anchor_count=len(required),
            missing_anchors=missing,
        )
    return paths


def validate_missing_items(contract: dict[str, Any]) -> None:
    bindings = contract.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        err("missing_item_bindings must be a non-empty array")
        return
    observed: dict[str, str] = {}
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            err(f"missing_item_bindings[{index}] must be an object")
            continue
        item_id = binding.get("id")
        kind = binding.get("kind")
        if not isinstance(item_id, str) or not item_id:
            err(f"missing_item_bindings[{index}].id missing")
            continue
        if not isinstance(kind, str) or not kind:
            err(f"missing_item_bindings[{item_id}].kind missing")
            continue
        observed[item_id] = kind
        evidence = binding.get("evidence")
        refs = binding.get("required_test_refs")
        if not isinstance(evidence, list) or not evidence:
            err(f"missing_item_bindings[{item_id}].evidence must be non-empty")
        if not isinstance(refs, list) or not refs:
            err(f"missing_item_bindings[{item_id}].required_test_refs must be non-empty")
    require(
        observed == EXPECTED_MISSING_ITEMS,
        f"missing_item_bindings must be {EXPECTED_MISSING_ITEMS}, got {observed}",
    )


def validate_layout(contract: dict[str, Any]) -> dict[str, Any]:
    layout = contract.get("evidence_symbol_record_contract")
    if not isinstance(layout, dict):
        err("evidence_symbol_record_contract must be an object")
        return {}
    expected_ints = {
        "record_size_bytes": 256,
        "header_size_bytes": 64,
        "payload_size_t_bytes": 128,
        "auth_tag_size_bytes": 32,
        "reserved_size_bytes": 32,
        "max_k_source": 256,
        "systematic_flag_bit": 0,
        "repair_flag_bit": 1,
        "auth_tag_flag_bit": 2,
    }
    for field, expected in expected_ints.items():
        require(layout.get(field) == expected, f"layout {field} must be {expected}, got {layout.get(field)!r}")
    require(layout.get("record_magic") == "EVR1", "record_magic must be EVR1")
    require(layout.get("payload_magic") == "EVP1", "payload_magic must be EVP1")
    require(set(layout.get("required_modes", [])) == {"strict", "hardened"}, "required_modes must be strict+hardened")
    require(
        set(layout.get("required_integrity_checks", []))
        == {"validate_basic", "verify_payload_hash_v1", "verify_chain_hash_v1"},
        "required_integrity_checks drifted",
    )
    require(
        set(layout.get("required_decoder_statuses", [])) == {"Success", "Partial", "Failed"},
        "required_decoder_statuses drifted",
    )
    record_fields = string_set(layout.get("required_record_fields"), "required_record_fields")
    for field in ["epoch_id", "seqno", "seed", "esi", "k_source", "r_repair", "payload_hash", "chain_hash"]:
        require(field in record_fields, f"required_record_fields missing {field}")
    event(
        "evidence_symbol_records_layout_gate",
        "pass",
        [rel(CONTRACT), "crates/frankenlibc-membrane/src/runtime_math/evidence.rs"],
        record_size_bytes=layout.get("record_size_bytes"),
        payload_size_t_bytes=layout.get("payload_size_t_bytes"),
        max_k_source=layout.get("max_k_source"),
    )
    return layout


def validate_redundancy(layout: dict[str, Any]) -> None:
    model = layout.get("raptorq_redundancy_model") if isinstance(layout, dict) else None
    if not isinstance(model, dict):
        err("raptorq_redundancy_model must be an object")
        return
    require(
        model.get("repair_schedule") == "deterministic_xor_repair_schedule_v1",
        "repair_schedule must name deterministic_xor_repair_schedule_v1",
    )
    require(model.get("repair_symbols_required") is True, "repair_symbols_required must be true")
    require(model.get("repair_esi_starts_at_k_source") is True, "repair_esi_starts_at_k_source must be true")
    require(model.get("loss_fraction_ppm_function") == "loss_fraction_max_ppm_v1", "loss_fraction_ppm_function drifted")
    require(model.get("decode_algorithm") == "peeling_decode", "decode_algorithm must be peeling_decode")
    require(model.get("corrupt_payloads_ignored") is True, "corrupt_payloads_ignored must be true")
    event(
        "evidence_symbol_records_redundancy_gate",
        "pass",
        [rel(CONTRACT), "crates/frankenlibc-harness/src/evidence_decode.rs"],
        repair_schedule=model.get("repair_schedule"),
        decode_algorithm=model.get("decode_algorithm"),
    )


def validate_samples(contract: dict[str, Any]) -> dict[str, Any]:
    proofs = contract.get("sample_decode_proofs")
    if not isinstance(proofs, list) or len(proofs) < 3:
        err("sample_decode_proofs must contain at least three proof rows")
        return {"sample_count": 0, "statuses": []}
    statuses: set[str] = set()
    recovered = False
    corruption = False
    for index, proof in enumerate(proofs):
        if not isinstance(proof, dict):
            err(f"sample_decode_proofs[{index}] must be an object")
            continue
        status = proof.get("status")
        if isinstance(status, str):
            statuses.add(status)
        else:
            err(f"sample_decode_proofs[{index}].status must be a string")
        for field in [
            "k_source",
            "r_repair",
            "records_total",
            "systematic_records",
            "repair_records",
            "decoded_systematic",
            "missing_systematic",
            "payload_hash_mismatches",
            "chain_hash_mismatches",
            "repair_payload_mismatches",
        ]:
            require(isinstance(proof.get(field), int), f"sample_decode_proofs[{index}].{field} must be an integer")
        k_source = proof.get("k_source", 0)
        r_repair = proof.get("r_repair", 0)
        records_total = proof.get("records_total", 0)
        require(records_total == proof.get("systematic_records", 0) + proof.get("repair_records", 0), f"sample_decode_proofs[{index}] record counts do not sum")
        require(proof.get("decoded_systematic", 0) <= k_source, f"sample_decode_proofs[{index}] decoded_systematic exceeds k_source")
        require(r_repair > 0, f"sample_decode_proofs[{index}] must include repair symbols")
        recovered |= proof.get("systematic_records", 0) < k_source and proof.get("missing_systematic") == 0 and proof.get("chain_hash_mismatches", 0) > 0
        corruption |= proof.get("payload_hash_mismatches", 0) > 0 and proof.get("missing_systematic", 0) > 0
        event(
            "evidence_symbol_records_sample_gate",
            "pass",
            [rel(CONTRACT)],
            sample_index=index,
            label=proof.get("label"),
            proof_status=status,
            k_source=k_source,
            r_repair=r_repair,
        )
    require("Success" in statuses and "Partial" in statuses, "sample_decode_proofs must include Success and Partial statuses")
    require(recovered, "sample_decode_proofs must include loss recovered by repair symbols")
    require(corruption, "sample_decode_proofs must include payload corruption detection")
    return {"sample_count": len(proofs), "statuses": sorted(statuses)}


def validate_telemetry_contract(contract: dict[str, Any]) -> None:
    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        return
    events = string_set(telemetry.get("required_events"), "telemetry_contract.required_events")
    fields = string_set(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields")
    require(events == EXPECTED_EVENTS, f"telemetry_contract.required_events mismatch: {sorted(events)}")
    require(BASE_LOG_FIELDS.issubset(fields), f"telemetry_contract.required_log_fields missing {sorted(BASE_LOG_FIELDS - fields)}")
    event(
        "evidence_symbol_records_telemetry_gate",
        "pass",
        [rel(CONTRACT)],
        required_events=sorted(events),
        required_log_fields=sorted(fields),
    )


def write_outputs(report: dict[str, Any]) -> None:
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with LOG.open("w", encoding="utf-8") as handle:
        for row in log_rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def main() -> int:
    contract = load_json(CONTRACT, "contract")

    require(contract.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
    require(contract.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
    require(contract.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")
    require(contract.get("trace_id") == TRACE_ID, f"trace_id must be {TRACE_ID}")

    validate_sources(contract)
    validate_missing_items(contract)
    layout = validate_layout(contract)
    validate_redundancy(layout)
    summary = validate_samples(contract)
    validate_telemetry_contract(contract)

    status = "pass" if not errors else "fail"
    event(
        PASS_EVENT if status == "pass" else FAIL_EVENT,
        status,
        [rel(CONTRACT), rel(REPORT), rel(LOG)],
        error_count=len(errors),
    )

    observed_events = {row.get("event") for row in log_rows}
    if status == "pass" and not EXPECTED_EVENTS.issubset(observed_events):
        errors.append(f"log missing required events: {sorted(EXPECTED_EVENTS - observed_events)}")
        status = "fail"

    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "original_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": COMMIT,
        "status": status,
        "failure_signature": "none" if status == "pass" else "evidence_symbol_records_contract_invalid",
        "summary": {
            "missing_item_count": len(EXPECTED_MISSING_ITEMS),
            "sample_count": summary.get("sample_count", 0),
            "statuses": summary.get("statuses", []),
            "event_count": len(log_rows),
            "record_size_bytes": layout.get("record_size_bytes") if isinstance(layout, dict) else None,
            "payload_size_t_bytes": layout.get("payload_size_t_bytes") if isinstance(layout, dict) else None,
            "max_k_source": layout.get("max_k_source") if isinstance(layout, dict) else None,
        },
        "artifact_refs": [
            rel(CONTRACT),
            "crates/frankenlibc-membrane/src/runtime_math/evidence.rs",
            "crates/frankenlibc-harness/src/evidence_decode.rs",
            "crates/frankenlibc-membrane/tests/runtime_math_dual_mode_e2e_test.rs",
            rel(LOG),
        ],
        "errors": errors,
    }
    write_outputs(report)

    if errors:
        print("evidence_symbol_records_completion_contract: FAILED")
        for message in errors:
            print(f"  - {message}")
        return 1

    print(
        "evidence_symbol_records_completion_contract: PASS "
        f"samples={report['summary']['sample_count']} events={report['summary']['event_count']}"
    )
    return 0


raise SystemExit(main())
PY
