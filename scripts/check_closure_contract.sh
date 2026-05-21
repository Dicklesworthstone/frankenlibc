#!/usr/bin/env bash
# check_closure_contract.sh — closure_contract.v1 validator (bd-5fw.1)
#
# Validates the closure contract schema and evaluates invariant predicates for
# the selected replacement level (default: current_level from replacement_levels).
#
# Structured JSONL logs are emitted for each invariant evaluation with:
# trace_id, level, invariant_id, check_cmd, result, artifact_ref.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_CLOSURE_CONTRACT_PATH:-${ROOT}/tests/conformance/closure_contract.v1.json}"
LOG_PATH="${FRANKENLIBC_CLOSURE_LOG:-/tmp/frankenlibc_closure_contract.log.jsonl}"
TARGET_LEVEL="${FRANKENLIBC_CLOSURE_LEVEL:-}"
FRESHNESS_EVENT="${FRANKENLIBC_CLOSURE_FRESHNESS_EVENT:-}"

python3 - "$ROOT" "$CONTRACT" "$LOG_PATH" "$TARGET_LEVEL" "$FRESHNESS_EVENT" <<'PY'
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any


def load_json(path: pathlib.Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def resolve_query(value: Any, query: str) -> Any:
    if not query:
        return value
    current = value
    for segment in query.split("."):
        if isinstance(current, list):
            try:
                idx = int(segment)
            except ValueError as exc:
                raise KeyError(
                    f"query segment '{segment}' is not a list index for query '{query}'"
                ) from exc
            if idx < 0 or idx >= len(current):
                raise KeyError(f"list index '{idx}' out of bounds for query '{query}'")
            current = current[idx]
        elif isinstance(current, dict):
            if segment not in current:
                raise KeyError(f"missing key '{segment}' in query '{query}'")
            current = current[segment]
        else:
            raise KeyError(f"cannot descend through non-container at segment '{segment}'")
    return current


def make_abs(root: pathlib.Path, p: str) -> pathlib.Path:
    path = pathlib.Path(p)
    if path.is_absolute():
        return path
    return root / path


def level_rank(level: str) -> int:
    table = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}
    if level not in table:
        raise ValueError(f"unknown level '{level}'")
    return table[level]


def normalize_utc_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty UTC timestamp string")

    text = value.strip()
    match = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$", text)
    if match:
        frac = match.group(2) or ""
        if len(frac) > 7:
            frac = frac[:7]
        tz = "+00:00" if match.group(3) == "Z" else match.group(3)
        text = f"{match.group(1)}{frac}{tz}"
    elif text.endswith("Z"):
        text = f"{text[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{field} must be RFC3339/ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def is_hex64(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-fA-F]{64}", value))


def load_freshness_event(path_text: str) -> list[dict[str, Any]]:
    if not path_text.strip():
        return []
    event_path = pathlib.Path(path_text).resolve()
    data = load_json(event_path)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        closures = data.get("closures")
        if isinstance(closures, list):
            return closures
        return [data]
    raise ValueError("FRANKENLIBC_CLOSURE_FRESHNESS_EVENT must point to an object or array")


def freshness_records(contract: dict[str, Any], event_path: str) -> list[dict[str, Any]]:
    policy = contract.get("bead_closure_freshness")
    records: list[dict[str, Any]] = []
    if isinstance(policy, dict):
        configured = policy.get("tracked_closures", [])
        if isinstance(configured, list):
            records.extend(configured)
    records.extend(load_freshness_event(event_path))
    return records


def freshness_payload(artifact: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    query = record.get("artifact_query")
    if isinstance(query, str) and query:
        payload = resolve_query(artifact, query)
    elif isinstance(artifact.get("freshness_state"), dict):
        payload = artifact["freshness_state"]
    else:
        payload = artifact
    if not isinstance(payload, dict):
        raise ValueError("completion artifact freshness payload must be an object")
    return payload


def validate_closure_freshness_record(
    root: pathlib.Path, record: dict[str, Any]
) -> tuple[bool, str, list[str], list[str]]:
    errors: list[str] = []
    artifact_refs: list[str] = []
    bead_id = record.get("bead_id")
    if not isinstance(bead_id, str) or not bead_id:
        errors.append("missing_bead_id")
        bead_id = "<missing>"

    for field in ["in_progress_at_utc", "closed_at_utc", "completion_contract_path"]:
        if not isinstance(record.get(field), str) or not record.get(field):
            errors.append(f"missing_{field}")

    if errors:
        return False, f"bead={bead_id}, failure_signature={errors[0]}", errors, artifact_refs

    artifact_rel = record["completion_contract_path"]
    artifact_refs.append(artifact_rel)
    artifact_path = make_abs(root, artifact_rel)
    if not artifact_path.is_file():
        errors.append("missing_completion_contract_artifact")
        return (
            False,
            f"bead={bead_id}, artifact={artifact_rel}, failure_signature={errors[0]}",
            errors,
            artifact_refs,
        )

    try:
        in_progress_at = normalize_utc_timestamp(record["in_progress_at_utc"], "in_progress_at_utc")
        closed_at = normalize_utc_timestamp(record["closed_at_utc"], "closed_at_utc")
    except ValueError as exc:
        errors.append(str(exc))
        return False, f"bead={bead_id}, failure_signature=invalid_bead_closure_window", errors, artifact_refs

    if closed_at < in_progress_at:
        errors.append("invalid_bead_closure_window")
        return False, f"bead={bead_id}, failure_signature=invalid_bead_closure_window", errors, artifact_refs

    try:
        artifact = load_json(artifact_path)
        if not isinstance(artifact, dict):
            raise ValueError("completion artifact must be a JSON object")
        payload = freshness_payload(artifact, record)
        generated_at = normalize_utc_timestamp(payload.get("generated_at_utc"), "generated_at_utc")
    except KeyError as exc:
        errors.append(f"missing_freshness_payload:{exc}")
        return (
            False,
            f"bead={bead_id}, artifact={artifact_rel}, failure_signature=missing_freshness_payload",
            errors,
            artifact_refs,
        )
    except ValueError as exc:
        missing_generated = "generated_at_utc" in str(exc)
        signature = (
            "missing_completion_contract_generated_at_utc"
            if missing_generated
            else "invalid_completion_contract_generated_at_utc"
        )
        errors.append(signature)
        return (
            False,
            f"bead={bead_id}, artifact={artifact_rel}, failure_signature={signature}",
            errors,
            artifact_refs,
        )

    chain_hash = payload.get("chain_hash")
    if not is_hex64(chain_hash):
        errors.append("missing_completion_contract_chain_hash")

    if generated_at < in_progress_at:
        errors.append("completion_contract_predates_in_progress")
    if generated_at > closed_at:
        errors.append("completion_contract_postdates_closed")

    if errors:
        return (
            False,
            f"bead={bead_id}, artifact={artifact_rel}, generated_at_utc={generated_at.isoformat()}, "
            f"window=[{in_progress_at.isoformat()},{closed_at.isoformat()}], "
            f"failure_signature={errors[0]}",
            errors,
            artifact_refs,
        )

    return (
        True,
        f"bead={bead_id}, artifact={artifact_rel}, generated_at_utc={generated_at.isoformat()}, "
        f"window=[{in_progress_at.isoformat()},{closed_at.isoformat()}], chain_hash=present",
        [],
        artifact_refs,
    )


def validate_schema(contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    required_root = [
        "schema_version",
        "contract_id",
        "bead",
        "description",
        "contract_sources",
        "level_order",
        "default_target_level",
        "levels",
        "transition_requirements",
        "completion_debt_evidence",
        "bead_closure_freshness",
        "structured_log_requirements",
    ]
    for key in required_root:
        if key not in contract:
            errors.append(f"missing root field '{key}'")

    if contract.get("schema_version") != 1:
        errors.append("schema_version must be 1")

    level_order = contract.get("level_order")
    if not isinstance(level_order, list) or level_order != ["L0", "L1", "L2", "L3"]:
        errors.append("level_order must be exactly ['L0', 'L1', 'L2', 'L3']")

    levels = contract.get("levels")
    if not isinstance(levels, list) or len(levels) != 4:
        errors.append("levels must contain exactly 4 entries")
        levels = []

    ids_seen: set[str] = set()
    level_ids: list[str] = []
    predicate_types = {
        "path_exists",
        "paths_exist",
        "json_eq",
        "json_lte",
        "json_gte",
        "command_exit_zero",
        "level_at_least",
    }

    for level in levels:
        if not isinstance(level, dict):
            errors.append("each level entry must be an object")
            continue
        lid = level.get("level")
        if lid not in {"L0", "L1", "L2", "L3"}:
            errors.append(f"invalid level id '{lid}'")
            continue
        level_ids.append(lid)

        obligations = level.get("obligations")
        if not isinstance(obligations, list) or not obligations:
            errors.append(f"{lid}: obligations must be a non-empty array")
            continue

        for obligation in obligations:
            if not isinstance(obligation, dict):
                errors.append(f"{lid}: each obligation must be an object")
                continue
            oid = obligation.get("invariant_id")
            if not isinstance(oid, str) or not oid:
                errors.append(f"{lid}: obligation missing invariant_id")
                continue
            if oid in ids_seen:
                errors.append(f"duplicate invariant_id '{oid}'")
            ids_seen.add(oid)

            for field in ["description", "check_cmd", "failure_message"]:
                if not isinstance(obligation.get(field), str) or not obligation.get(field):
                    errors.append(f"{oid}: missing non-empty '{field}'")

            artifacts = obligation.get("artifact_paths")
            if not isinstance(artifacts, list) or not artifacts:
                errors.append(f"{oid}: artifact_paths must be a non-empty array")

            predicate = obligation.get("predicate")
            if not isinstance(predicate, dict):
                errors.append(f"{oid}: predicate must be an object")
                continue
            ptype = predicate.get("type")
            if ptype not in predicate_types:
                errors.append(f"{oid}: unsupported predicate type '{ptype}'")
                continue

            if ptype == "path_exists":
                if not isinstance(predicate.get("path"), str) or not predicate.get("path"):
                    errors.append(f"{oid}: path_exists requires 'path'")
            elif ptype == "paths_exist":
                paths = predicate.get("paths")
                if not isinstance(paths, list) or not paths:
                    errors.append(f"{oid}: paths_exist requires non-empty 'paths'")
            elif ptype in {"json_eq", "json_lte", "json_gte"}:
                for field in ["file", "query"]:
                    if not isinstance(predicate.get(field), str) or not predicate.get(field):
                        errors.append(f"{oid}: {ptype} requires '{field}'")
                value_key = {
                    "json_eq": "expected",
                    "json_lte": "max",
                    "json_gte": "min",
                }[ptype]
                if value_key not in predicate:
                    errors.append(f"{oid}: {ptype} requires '{value_key}'")
            elif ptype == "command_exit_zero":
                if not isinstance(predicate.get("cmd"), str) or not predicate.get("cmd"):
                    errors.append(f"{oid}: command_exit_zero requires 'cmd'")
            elif ptype == "level_at_least":
                for field in ["observed_level_file", "observed_level_query", "min_level"]:
                    if not isinstance(predicate.get(field), str) or not predicate.get(field):
                        errors.append(f"{oid}: level_at_least requires '{field}'")
                min_level = predicate.get("min_level")
                if min_level not in {"L0", "L1", "L2", "L3"}:
                    errors.append(f"{oid}: level_at_least.min_level must be L0-L3")

    if sorted(level_ids) != ["L0", "L1", "L2", "L3"]:
        errors.append("levels must define exactly L0, L1, L2, L3")

    transitions = contract.get("transition_requirements")
    if not isinstance(transitions, dict):
        errors.append("transition_requirements must be an object")
    else:
        for key in ["L0_to_L1", "L1_to_L2", "L2_to_L3"]:
            ids = transitions.get(key)
            if not isinstance(ids, list) or not ids:
                errors.append(f"transition_requirements.{key} must be a non-empty array")
                continue
            for oid in ids:
                if oid not in ids_seen:
                    errors.append(f"transition_requirements.{key} references unknown '{oid}'")

    log_req = contract.get("structured_log_requirements")
    if not isinstance(log_req, dict):
        errors.append("structured_log_requirements must be an object")
    else:
        required_fields = log_req.get("required_fields")
        if not isinstance(required_fields, list) or not required_fields:
            errors.append("structured_log_requirements.required_fields must be non-empty array")

    completion = contract.get("completion_debt_evidence")
    if not isinstance(completion, dict):
        errors.append("completion_debt_evidence must be an object")
    else:
        if completion.get("bead") != "bd-5fw.1.1":
            errors.append("completion_debt_evidence.bead must be bd-5fw.1.1")
        test_source = completion.get("test_source")
        if not isinstance(test_source, str) or not test_source:
            errors.append("completion_debt_evidence.test_source must be non-empty")
            test_source_text = ""
        else:
            source_path = pathlib.Path(test_source)
            if not source_path.is_absolute():
                source_path = pathlib.Path(sys.argv[1]).resolve() / source_path
            if not source_path.is_file():
                errors.append(f"completion_debt_evidence.test_source missing: {test_source}")
                test_source_text = ""
            else:
                test_source_text = source_path.read_text(encoding="utf-8")

        for section_name in ["unit_primary", "e2e_primary"]:
            section = completion.get(section_name)
            if not isinstance(section, dict):
                errors.append(f"completion_debt_evidence.{section_name} must be an object")
                continue
            names = section.get("required_test_names")
            if not isinstance(names, list) or not names:
                errors.append(
                    f"completion_debt_evidence.{section_name}.required_test_names must be non-empty"
                )
                continue
            for name in names:
                if not isinstance(name, str) or not name:
                    errors.append(
                        f"completion_debt_evidence.{section_name}.required_test_names contains invalid test name"
                    )
                    continue
                if f"fn {name}(" not in test_source_text:
                    errors.append(
                        f"completion_debt_evidence.{section_name} references missing test '{name}'"
                    )

        telemetry = completion.get("telemetry_primary")
        if not isinstance(telemetry, dict):
            errors.append("completion_debt_evidence.telemetry_primary must be an object")
        else:
            if telemetry.get("log_env") != "FRANKENLIBC_CLOSURE_LOG":
                errors.append("telemetry_primary.log_env must be FRANKENLIBC_CLOSURE_LOG")
            if telemetry.get("default_log_path") != "/tmp/frankenlibc_closure_contract.log.jsonl":
                errors.append("telemetry_primary.default_log_path drifted")
            telemetry_fields = telemetry.get("required_fields")
            if not isinstance(telemetry_fields, list) or not telemetry_fields:
                errors.append("telemetry_primary.required_fields must be non-empty")
                telemetry_fields = []
            structured_fields = log_req.get("required_fields", []) if isinstance(log_req, dict) else []
            missing_log_fields = [
                field
                for field in structured_fields
                if field not in telemetry_fields
            ]
            if missing_log_fields:
                errors.append(
                    "telemetry_primary.required_fields must cover structured_log_requirements "
                    f"fields: {missing_log_fields}"
                )
            for field in ["mode", "gate_name", "exit_code", "duration_ms", "artifact_refs", "detail", "failure_reason"]:
                if field not in telemetry_fields:
                    errors.append(f"telemetry_primary.required_fields missing '{field}'")

    freshness = contract.get("bead_closure_freshness")
    if not isinstance(freshness, dict):
        errors.append("bead_closure_freshness must be an object")
    else:
        for field in ["bead", "description", "event_env"]:
            if not isinstance(freshness.get(field), str) or not freshness.get(field):
                errors.append(f"bead_closure_freshness.{field} must be non-empty")
        if freshness.get("event_env") != "FRANKENLIBC_CLOSURE_FRESHNESS_EVENT":
            errors.append(
                "bead_closure_freshness.event_env must be FRANKENLIBC_CLOSURE_FRESHNESS_EVENT"
            )

        required_event_fields = freshness.get("required_event_fields")
        expected_event_fields = [
            "bead_id",
            "in_progress_at_utc",
            "closed_at_utc",
            "completion_contract_path",
        ]
        if not isinstance(required_event_fields, list):
            errors.append("bead_closure_freshness.required_event_fields must be an array")
        else:
            missing = [field for field in expected_event_fields if field not in required_event_fields]
            if missing:
                errors.append(
                    "bead_closure_freshness.required_event_fields missing "
                    f"{missing}"
                )

        required_artifact_fields = freshness.get("required_artifact_freshness_fields")
        for field in ["generated_at_utc", "chain_hash"]:
            if not isinstance(required_artifact_fields, list) or field not in required_artifact_fields:
                errors.append(
                    "bead_closure_freshness.required_artifact_freshness_fields "
                    f"missing '{field}'"
                )

        signatures = freshness.get("failure_signatures")
        for signature in [
            "missing_completion_contract_generated_at_utc",
            "missing_completion_contract_chain_hash",
            "completion_contract_predates_in_progress",
            "completion_contract_postdates_closed",
        ]:
            if not isinstance(signatures, list) or signature not in signatures:
                errors.append(
                    f"bead_closure_freshness.failure_signatures missing '{signature}'"
                )

        tracked = freshness.get("tracked_closures")
        if not isinstance(tracked, list):
            errors.append("bead_closure_freshness.tracked_closures must be an array")
        else:
            for idx, record in enumerate(tracked):
                if not isinstance(record, dict):
                    errors.append(f"bead_closure_freshness.tracked_closures[{idx}] must be an object")

    return errors


def evaluate_predicate(root: pathlib.Path, predicate: dict[str, Any]) -> tuple[bool, str, int]:
    ptype = predicate["type"]

    if ptype == "path_exists":
        p = make_abs(root, predicate["path"])
        ok = p.exists()
        return ok, f"path_exists:{predicate['path']} -> {ok}", 0 if ok else 1

    if ptype == "paths_exist":
        missing = []
        for p in predicate["paths"]:
            if not make_abs(root, p).exists():
                missing.append(p)
        ok = not missing
        detail = "all paths exist" if ok else f"missing paths: {', '.join(missing)}"
        return ok, detail, 0 if ok else 1

    if ptype in {"json_eq", "json_lte", "json_gte"}:
        data = load_json(make_abs(root, predicate["file"]))
        observed = resolve_query(data, predicate["query"])
        if ptype == "json_eq":
            expected = predicate["expected"]
            ok = observed == expected
            return ok, f"observed={observed!r}, expected={expected!r}", 0 if ok else 1
        if ptype == "json_lte":
            max_value = predicate["max"]
            ok = observed <= max_value
            return ok, f"observed={observed!r}, max={max_value!r}", 0 if ok else 1
        min_value = predicate["min"]
        ok = observed >= min_value
        return ok, f"observed={observed!r}, min={min_value!r}", 0 if ok else 1

    if ptype == "command_exit_zero":
        cmd = predicate["cmd"]
        proc = subprocess.run(  # noqa: S602
            cmd,
            shell=True,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        ok = proc.returncode == 0
        detail = f"command_exit={proc.returncode}"
        if not ok:
            stderr = proc.stderr.strip()
            stdout = proc.stdout.strip()
            tail = stderr.splitlines()[-1] if stderr else (stdout.splitlines()[-1] if stdout else "")
            if tail:
                detail = f"{detail}, tail={tail}"
        return ok, detail, proc.returncode

    if ptype == "level_at_least":
        data = load_json(make_abs(root, predicate["observed_level_file"]))
        observed = resolve_query(data, predicate["observed_level_query"])
        min_level = predicate["min_level"]
        ok = level_rank(observed) >= level_rank(min_level)
        return ok, f"observed_level={observed}, min_level={min_level}", 0 if ok else 1

    raise ValueError(f"unsupported predicate type '{ptype}'")


def main() -> int:
    root = pathlib.Path(sys.argv[1]).resolve()
    contract_path = pathlib.Path(sys.argv[2]).resolve()
    log_path = pathlib.Path(sys.argv[3])
    target_level_arg = sys.argv[4]
    freshness_event_path = sys.argv[5]

    if not contract_path.exists():
        print("=== Closure Contract Gate (bd-5fw.1) ===")
        print(f"FAIL: contract file not found: {contract_path}")
        print("check_closure_contract: FAILED")
        return 1

    contract = load_json(contract_path)
    schema_errors = validate_schema(contract)

    print("=== Closure Contract Gate (bd-5fw.1) ===")
    print("")
    print("--- Check 1: Contract schema validity ---")
    if schema_errors:
        print(f"FAIL: schema has {len(schema_errors)} error(s)")
        for err in schema_errors:
            print(f"  - {err}")
        print("")
        print("check_closure_contract: FAILED")
        return 1
    print("PASS: closure_contract.v1 schema is valid")
    print("")

    target_level = target_level_arg.strip()
    if not target_level:
        source = contract["default_target_level"]
        source_data = load_json(make_abs(root, source["source_file"]))
        target_level = str(resolve_query(source_data, source["source_query"]))

    levels = {entry["level"]: entry for entry in contract["levels"]}
    if target_level not in levels:
        print("--- Check 2: Target level selection ---")
        print(f"FAIL: target level '{target_level}' not present in contract levels")
        print("")
        print("check_closure_contract: FAILED")
        return 1

    print("--- Check 2: Target level selection ---")
    print(f"PASS: evaluating target level {target_level}")
    print("")

    obligations = levels[target_level]["obligations"]
    trace_id = (
        f"closure-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        f"-{os.getpid()}"
    )
    mode = os.environ.get("FRANKENLIBC_MODE", "strict")
    results: list[dict[str, Any]] = []
    failures: list[str] = []

    print("--- Check 3: Invariant evaluation ---")
    for obligation in obligations:
        invariant_id = obligation["invariant_id"]
        check_cmd = obligation["check_cmd"]
        artifacts = obligation["artifact_paths"]
        predicate = obligation["predicate"]
        started = time.perf_counter()

        try:
            ok, detail, exit_code = evaluate_predicate(root, predicate)
        except Exception as exc:  # noqa: BLE001
            ok = False
            detail = f"exception={exc}"
            exit_code = 1

        duration_ms = int((time.perf_counter() - started) * 1000)
        failure_reason = ""
        if not ok:
            failure_reason = f"{obligation['failure_message']} ({detail})"
            failures.append(f"{invariant_id}: {failure_reason}")

        record = {
            "trace_id": trace_id,
            "mode": mode,
            "gate_name": "closure_contract",
            "level": target_level,
            "invariant_id": invariant_id,
            "check_cmd": check_cmd,
            "result": "pass" if ok else "fail",
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "artifact_ref": artifacts[0] if artifacts else "",
            "artifact_refs": artifacts,
            "detail": detail,
            "failure_reason": failure_reason,
        }
        results.append(record)

        status = "PASS" if ok else "FAIL"
        print(f"{status}: {invariant_id} ({detail})")

    print("")
    print("--- Check 4: Bead closure freshness ---")
    try:
        records = freshness_records(contract, freshness_event_path)
    except Exception as exc:  # noqa: BLE001
        records = []
        failures.append(f"bead_closure_freshness: invalid event payload ({exc})")
        print(f"FAIL: bead_closure_freshness event load failed ({exc})")

    if not records:
        print("PASS: no bead closure freshness records supplied")

    for idx, freshness_record in enumerate(records):
        started = time.perf_counter()
        if not isinstance(freshness_record, dict):
            ok = False
            detail = "failure_signature=invalid_closure_freshness_record"
            exit_code = 1
            artifact_refs = []
            freshness_failures = ["invalid_closure_freshness_record"]
            bead_id = f"record-{idx}"
        else:
            bead_id = str(freshness_record.get("bead_id", f"record-{idx}"))
            ok, detail, freshness_failures, artifact_refs = validate_closure_freshness_record(
                root, freshness_record
            )
            exit_code = 0 if ok else 1

        duration_ms = int((time.perf_counter() - started) * 1000)
        invariant_id = f"bead_closure_freshness.{bead_id}"
        failure_reason = ""
        if not ok:
            failure_reason = "; ".join(freshness_failures)
            failures.append(f"{invariant_id}: {failure_reason} ({detail})")

        record = {
            "trace_id": trace_id,
            "mode": mode,
            "gate_name": "closure_contract",
            "level": target_level,
            "invariant_id": invariant_id,
            "check_cmd": "validate_bead_closure_freshness",
            "result": "pass" if ok else "fail",
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "artifact_ref": artifact_refs[0] if artifact_refs else "",
            "artifact_refs": artifact_refs,
            "detail": detail,
            "failure_reason": failure_reason,
        }
        results.append(record)

        status = "PASS" if ok else "FAIL"
        print(f"{status}: {invariant_id} ({detail})")

    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as f:
        for record in results:
            f.write(json.dumps(record, sort_keys=True))
            f.write("\n")

    print("")
    print(f"Evaluated invariants: {len(results)}")
    print(f"Failures: {len(failures)}")
    print(f"Structured log: {log_path}")
    print("")

    if failures:
        print("Deterministic failure reasons:")
        for failure in failures:
            print(f"  - {failure}")
        print("")
        print("check_closure_contract: FAILED")
        return 1

    print("check_closure_contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
