#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_PTHREAD_MUTEX_CALLTHROUGH_CONTRACT:-${ROOT}/tests/conformance/pthread_mutex_callthrough_eradication_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_PTHREAD_MUTEX_CALLTHROUGH_REPORT:-${ROOT}/target/conformance/pthread_mutex_callthrough_eradication_completion_contract.report.json}"
LOG="${FRANKENLIBC_PTHREAD_MUTEX_CALLTHROUGH_LOG:-${ROOT}/target/conformance/pthread_mutex_callthrough_eradication_completion_contract.log.jsonl}"
RUN_GUARDS="${FRANKENLIBC_PTHREAD_MUTEX_CALLTHROUGH_RUN_GUARDS:-1}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

python3 - "$ROOT" "$CONTRACT" "$REPORT" "$LOG" "$RUN_GUARDS" <<'PY'
import json
import os
import pathlib
import subprocess
import sys
import time

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
run_guards = sys.argv[5].lower() not in {"0", "false", "no"}
start_ns = time.time_ns()

EXPECTED_SCHEMA = "pthread_mutex_callthrough_eradication_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "pthread_mutex_callthrough_eradication_completion_contract.report.v1"
EXPECTED_ORIGINAL_BEAD = "bd-1uc"
EXPECTED_COMPLETION_BEAD = "bd-1uc.1"
EXPECTED_MISSING_ITEMS = {
    "tests.conformance.primary": "conformance",
    "telemetry.primary": "telemetry",
}
EXPECTED_SOURCE_KEYS = {
    "replacement_profile",
    "replacement_guard",
    "replacement_guard_harness",
    "residual_contract",
    "residual_gate",
    "residual_harness",
    "support_matrix",
    "abi_mutex",
    "fixture",
    "conformance_harness",
    "completion_contract",
    "completion_gate",
    "completion_harness",
}
EXPECTED_MUTEX_SYMBOLS = {
    "pthread_mutex_destroy",
    "pthread_mutex_init",
    "pthread_mutex_lock",
    "pthread_mutex_trylock",
    "pthread_mutex_unlock",
}
EXPECTED_GUARD_MODES = {"replacement", "interpose"}
PASS_EVENTS = [
    "pthread_mutex_callthrough_eradication.conformance_binding",
    "pthread_mutex_callthrough_eradication.telemetry_contract",
    "pthread_mutex_callthrough_eradication.completion_contract_validated",
]
FAIL_EVENT = "pthread_mutex_callthrough_eradication.completion_contract_failed"


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except subprocess.CalledProcessError:
        return "unknown"


def rel(path: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(root))
    except ValueError:
        return str(path)


def write_json(path: pathlib.Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_log(records: list[dict]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


def fail(signature: str, message: str, **details):
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "original_bead": EXPECTED_ORIGINAL_BEAD,
        "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
        "source_commit": git_head(),
        "status": "fail",
        "failure_signature": signature,
        "message": message,
        "contract": rel(contract_path),
        "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
        "details": details,
    }
    write_json(report_path, report)
    write_log(
        [
            {
                "timestamp": now_utc(),
                "event": FAIL_EVENT,
                "status": "fail",
                "failure_signature": signature,
                "message": message,
                "details": details,
            }
        ]
    )
    raise SystemExit(f"FAIL[{signature}]: {message}")


def require(condition: bool, signature: str, message: str, **details) -> None:
    if not condition:
        fail(signature, message, **details)


def load_json(path: pathlib.Path):
    require(path.is_file(), "json_missing", f"missing json artifact: {rel(path)}", path=rel(path))
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        fail("json_invalid", f"invalid json artifact: {rel(path)}", path=rel(path), error=str(err))


def source_text(source_artifacts: dict, key: str) -> str:
    value = source_artifacts.get(key)
    require(isinstance(value, str) and value, "source_artifact_missing", f"missing source artifact {key}", key=key)
    path = root / value
    require(path.is_file(), "source_path_missing", f"source artifact missing: {value}", key=key, path=value)
    return path.read_text(encoding="utf-8")


def require_text_contains(text: str, needle: str, signature: str, message: str, **details) -> None:
    require(isinstance(needle, str) and needle, "anchor_empty", "source anchor must be non-empty", **details)
    require(needle in text, signature, message, needle=needle, **details)


def validate_source_artifacts(contract: dict) -> dict:
    source_artifacts = contract.get("source_artifacts")
    require(isinstance(source_artifacts, dict), "source_artifacts_shape", "source_artifacts must be an object")
    require(
        set(source_artifacts) == EXPECTED_SOURCE_KEYS,
        "source_artifact_key_drift",
        "source_artifacts keys drifted",
        declared=sorted(source_artifacts),
        expected=sorted(EXPECTED_SOURCE_KEYS),
    )
    for key, path in source_artifacts.items():
        require(isinstance(path, str) and path, "source_artifact_value", f"{key} must point at a path", key=key)
        require((root / path).is_file(), "source_path_missing", f"source artifact missing: {path}", key=key, path=path)
    return source_artifacts


def validate_source_anchors(contract: dict, source_artifacts: dict) -> int:
    anchors = contract.get("source_anchors")
    require(isinstance(anchors, dict), "source_anchors_shape", "source_anchors must be an object")
    require(set(anchors) <= set(source_artifacts), "source_anchor_unknown_key", "source anchors contain unknown keys")
    total = 0
    for key, needles in anchors.items():
        require(isinstance(needles, list) and needles, "source_anchor_list", f"{key} anchors must be non-empty", key=key)
        text = source_text(source_artifacts, key)
        for needle in needles:
            require_text_contains(
                text,
                needle,
                "source_anchor_missing",
                f"{key} is missing a required source anchor",
                key=key,
                path=source_artifacts[key],
            )
            total += 1
    return total


def validate_line_ref(ref: str) -> str:
    require(isinstance(ref, str) and ref, "line_ref_empty", "line ref must be a non-empty string")
    path_text, sep, line_text = ref.rpartition(":")
    require(sep == ":" and line_text.isdigit(), "line_ref_shape", "line ref must be path:line", ref=ref)
    line_no = int(line_text)
    require(line_no > 0, "line_ref_line", "line number must be positive", ref=ref)
    path = root / path_text
    require(path.is_file(), "line_ref_path_missing", "line ref path is missing", ref=ref)
    lines = path.read_text(encoding="utf-8").splitlines()
    require(line_no <= len(lines), "line_ref_out_of_range", "line ref is beyond end of file", ref=ref, line_count=len(lines))
    require(lines[line_no - 1].strip() != "", "line_ref_blank", "line ref points at a blank line", ref=ref)
    return ref


def validate_missing_items(contract: dict) -> list[dict]:
    bindings = contract.get("missing_item_bindings")
    require(isinstance(bindings, list), "missing_item_bindings_shape", "missing_item_bindings must be an array")
    actual = {}
    for binding in bindings:
        require(isinstance(binding, dict), "missing_item_shape", "missing item binding must be an object")
        item_id = binding.get("id")
        kind = binding.get("kind")
        require(isinstance(item_id, str) and item_id, "missing_item_id", "missing item id must be non-empty")
        require(isinstance(kind, str) and kind, "missing_item_kind", "missing item kind must be non-empty", item_id=item_id)
        actual[item_id] = kind
        require(
            binding.get("next_audit_threshold") == 900,
            "next_audit_threshold",
            "each missing item must pin the next audit threshold",
            item_id=item_id,
            actual=binding.get("next_audit_threshold"),
        )
        for key in ("implementation_refs", "test_refs"):
            refs = binding.get(key)
            require(isinstance(refs, list) and refs, f"{key}_missing", f"{item_id} must cite {key}", item_id=item_id)
            for ref in refs:
                validate_line_ref(ref)
        if item_id == "telemetry.primary":
            refs = binding.get("telemetry_refs")
            require(isinstance(refs, list) and refs, "telemetry_refs_missing", "telemetry.primary must cite telemetry refs")
            for ref in refs:
                validate_line_ref(ref)
            events = binding.get("required_events")
            require(events == PASS_EVENTS, "required_events_drift", "telemetry.primary required events drifted", events=events)
        commands = binding.get("required_commands")
        require(isinstance(commands, list) and commands, "required_commands_missing", f"{item_id} commands must be non-empty", item_id=item_id)
        for command in commands:
            require(isinstance(command, str) and command, "command_empty", "required command must be non-empty", item_id=item_id)
            if " cargo " in f" {command} ":
                require("rch exec -- cargo" in command, "cargo_not_rch", "cargo validation must run through rch", command=command)
    require(actual == EXPECTED_MISSING_ITEMS, "missing_item_set_drift", "completion-debt missing item set drifted", actual=actual, expected=EXPECTED_MISSING_ITEMS)
    return bindings


def validate_contract_details(contract: dict) -> dict:
    details = contract.get("pthread_mutex_callthrough_eradication_contract")
    require(isinstance(details, dict), "contract_details_shape", "pthread_mutex callthrough contract must be an object")
    symbols = details.get("required_mutex_symbols")
    require(set(symbols or []) == EXPECTED_MUTEX_SYMBOLS, "required_mutex_symbols", "required mutex symbol set drifted", actual=symbols)
    modes = details.get("guard_modes")
    require(set(modes or []) == EXPECTED_GUARD_MODES, "guard_modes", "guard modes must be replacement+interpose", actual=modes)
    require(details.get("support_matrix_required_status") == "Implemented", "support_status", "support matrix status contract drifted")
    require(details.get("support_matrix_required_module") == "pthread_abi", "support_module", "support matrix module contract drifted")
    require(details.get("next_audit_threshold") == 900, "contract_audit_threshold", "contract must pin threshold 900")
    require(details.get("fixture_required_case_count_min") == 8, "fixture_case_min", "fixture minimum case count drifted")
    return details


def validate_support_matrix(source_artifacts: dict) -> dict:
    support = load_json(root / source_artifacts["support_matrix"])
    rows = support.get("symbols")
    require(isinstance(rows, list), "support_symbols_shape", "support_matrix symbols must be an array")
    by_symbol = {row.get("symbol"): row for row in rows if isinstance(row, dict)}
    statuses = {}
    for symbol in sorted(EXPECTED_MUTEX_SYMBOLS):
        row = by_symbol.get(symbol)
        require(isinstance(row, dict), "support_symbol_missing", "required mutex symbol missing from support matrix", symbol=symbol)
        require(row.get("status") == "Implemented", "support_status_drift", "mutex symbol must be Implemented", symbol=symbol, actual=row.get("status"))
        require(row.get("module") == "pthread_abi", "support_module_drift", "mutex symbol must be owned by pthread_abi", symbol=symbol, actual=row.get("module"))
        require(row.get("default_stub") is False, "support_stub_drift", "mutex symbol must not be a default stub", symbol=symbol)
        strict_semantics = str(row.get("strict_semantics", ""))
        require(
            "Futex-managed" in strict_semantics and "mutex core" in strict_semantics,
            "support_semantics_drift",
            "mutex symbol strict semantics must cite the native futex core",
            symbol=symbol,
        )
        statuses[symbol] = {"status": row.get("status"), "module": row.get("module")}
    return statuses


def validate_fixture(source_artifacts: dict, min_cases: int) -> dict:
    fixture = load_json(root / source_artifacts["fixture"])
    cases = fixture.get("cases")
    require(isinstance(cases, list), "fixture_cases_shape", "pthread mutex fixture cases must be an array")
    require(len(cases) >= min_cases, "fixture_case_count", "pthread mutex fixture case count is below contract minimum", actual=len(cases), minimum=min_cases)
    functions = {case.get("function") for case in cases if isinstance(case, dict)}
    missing = EXPECTED_MUTEX_SYMBOLS - functions
    require(not missing, "fixture_symbol_gap", "pthread mutex fixture is missing canonical symbols", missing=sorted(missing))
    require("__pthread_mutex_trylock" in functions, "fixture_alias_trylock", "pthread mutex fixture must cover trylock alias")
    require("__pthread_mutex_unlock" in functions, "fixture_alias_unlock", "pthread mutex fixture must cover unlock alias")
    return {"case_count": len(cases), "functions": sorted(function for function in functions if isinstance(function, str))}


artifact_dir = report_path.parent
residual_path = pathlib.Path(
    os.environ.get(
        "FRANKENLIBC_PTHREAD_MUTEX_CALLTHROUGH_RESIDUAL_REPORT",
        str(artifact_dir / "residual_replacement_callthrough_blockers.report.json"),
    )
)
residual_log_path = pathlib.Path(
    os.environ.get(
        "FRANKENLIBC_PTHREAD_MUTEX_CALLTHROUGH_RESIDUAL_LOG",
        str(artifact_dir / "residual_replacement_callthrough_blockers.log.jsonl"),
    )
)
replacement_path = pathlib.Path(
    os.environ.get(
        "FRANKENLIBC_PTHREAD_MUTEX_CALLTHROUGH_REPLACEMENT_GUARD_REPORT",
        str(artifact_dir / "replacement_guard.replacement.report.json"),
    )
)
replacement_log_path = pathlib.Path(
    os.environ.get(
        "FRANKENLIBC_PTHREAD_MUTEX_CALLTHROUGH_REPLACEMENT_GUARD_LOG",
        str(artifact_dir / "replacement_guard.replacement.log.jsonl"),
    )
)
interpose_path = pathlib.Path(
    os.environ.get(
        "FRANKENLIBC_PTHREAD_MUTEX_CALLTHROUGH_INTERPOSE_GUARD_REPORT",
        str(artifact_dir / "replacement_guard.interpose.report.json"),
    )
)
interpose_log_path = pathlib.Path(
    os.environ.get(
        "FRANKENLIBC_PTHREAD_MUTEX_CALLTHROUGH_INTERPOSE_GUARD_LOG",
        str(artifact_dir / "replacement_guard.interpose.log.jsonl"),
    )
)


def run_residual_guard() -> None:
    if not run_guards:
        return
    env = os.environ.copy()
    env["RESIDUAL_REPLACEMENT_REPORT"] = str(residual_path)
    env["RESIDUAL_REPLACEMENT_LOG"] = str(residual_log_path)
    env["RESIDUAL_REPLACEMENT_GUARD_REPLACEMENT_REPORT"] = str(replacement_path)
    env["RESIDUAL_REPLACEMENT_GUARD_REPLACEMENT_LOG"] = str(replacement_log_path)
    env["RESIDUAL_REPLACEMENT_GUARD_INTERPOSE_REPORT"] = str(interpose_path)
    env["RESIDUAL_REPLACEMENT_GUARD_INTERPOSE_LOG"] = str(interpose_log_path)
    command = [str(root / "scripts/check_residual_replacement_callthrough_blockers.sh"), "--validate-only"]
    proc = subprocess.run(command, cwd=root, text=True, capture_output=True, env=env)
    if proc.returncode != 0:
        fail(
            "residual_guard_failed",
            "residual replacement callthrough blocker gate failed",
            command=" ".join(command),
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )


def validate_guard_report(path: pathlib.Path, mode: str) -> dict:
    report = load_json(path)
    require(report.get("ok") is True, "guard_report_not_ok", "replacement guard report must be ok", mode=mode, path=rel(path))
    require(report.get("mode") == mode, "guard_report_mode", "replacement guard report mode drifted", mode=mode, actual=report.get("mode"))
    for key in ("total_call_throughs", "modules_with_call_throughs", "violations", "mutex_forbidden_count"):
        require(int(report.get(key, -1)) == 0, "guard_report_nonzero", f"{mode} guard {key} must be zero", mode=mode, key=key, actual=report.get(key))
    require(
        set(report.get("mutex_forbidden_symbols", [])) == EXPECTED_MUTEX_SYMBOLS,
        "guard_mutex_symbol_set",
        "replacement guard mutex forbidden symbol set drifted",
        mode=mode,
        actual=report.get("mutex_forbidden_symbols"),
    )
    return {
        "mode": mode,
        "total_call_throughs": int(report.get("total_call_throughs", 0)),
        "modules_with_call_throughs": int(report.get("modules_with_call_throughs", 0)),
        "violations": int(report.get("violations", 0)),
        "mutex_forbidden_count": int(report.get("mutex_forbidden_count", 0)),
    }


def validate_residual_report(path: pathlib.Path) -> dict:
    report = load_json(path)
    require(report.get("schema_version") == "residual_replacement_callthrough_blockers.report.v1", "residual_report_schema", "residual report schema drifted")
    require(report.get("outcome") == "pass", "residual_report_outcome", "residual report must pass", actual=report.get("outcome"))
    summary = report.get("summary")
    require(isinstance(summary, dict), "residual_summary_shape", "residual report summary must be an object")
    for key in ("residual_forbidden_count", "replacement_total_call_throughs", "interpose_total_call_throughs"):
        require(int(summary.get(key, -1)) == 0, "residual_summary_nonzero", f"residual summary {key} must be zero", key=key, actual=summary.get(key))
    require(summary.get("followup_child_beads_created") is False, "residual_followup_drift", "residual gate should not require follow-up child beads")
    return {
        "residual_forbidden_count": int(summary.get("residual_forbidden_count", 0)),
        "replacement_total_call_throughs": int(summary.get("replacement_total_call_throughs", 0)),
        "interpose_total_call_throughs": int(summary.get("interpose_total_call_throughs", 0)),
    }


contract = load_json(contract_path)
require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "unexpected contract schema", actual=contract.get("schema_version"))
require(contract.get("original_bead") == EXPECTED_ORIGINAL_BEAD, "original_bead", "unexpected original bead", actual=contract.get("original_bead"))
require(contract.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD, "completion_debt_bead", "unexpected completion debt bead", actual=contract.get("completion_debt_bead"))

source_artifacts = validate_source_artifacts(contract)
anchor_count = validate_source_anchors(contract, source_artifacts)
bindings = validate_missing_items(contract)
details = validate_contract_details(contract)
support_statuses = validate_support_matrix(source_artifacts)
fixture_summary = validate_fixture(source_artifacts, int(details["fixture_required_case_count_min"]))

run_residual_guard()
residual_summary = validate_residual_report(residual_path)
replacement_summary = validate_guard_report(replacement_path, "replacement")
interpose_summary = validate_guard_report(interpose_path, "interpose")

records = [
    {
        "timestamp": now_utc(),
        "event": PASS_EVENTS[0],
        "status": "pass",
        "bead_id": EXPECTED_COMPLETION_BEAD,
        "details": {
            "missing_item": "tests.conformance.primary",
            "fixture_cases": fixture_summary["case_count"],
            "required_mutex_symbols": sorted(EXPECTED_MUTEX_SYMBOLS),
            "support_statuses": support_statuses,
        },
    },
    {
        "timestamp": now_utc(),
        "event": PASS_EVENTS[1],
        "status": "pass",
        "bead_id": EXPECTED_COMPLETION_BEAD,
        "details": {
            "missing_item": "telemetry.primary",
            "replacement": replacement_summary,
            "interpose": interpose_summary,
            "residual": residual_summary,
        },
    },
    {
        "timestamp": now_utc(),
        "event": PASS_EVENTS[2],
        "status": "pass",
        "bead_id": EXPECTED_COMPLETION_BEAD,
        "details": {
            "missing_item_count": len(bindings),
            "source_anchor_count": anchor_count,
            "next_audit_threshold": 900,
            "run_guards": run_guards,
        },
    },
]

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "original_bead": EXPECTED_ORIGINAL_BEAD,
    "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
    "source_commit": git_head(),
    "status": "pass",
    "failure_signature": "none",
    "contract": rel(contract_path),
    "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
    "summary": {
        "missing_item_count": len(bindings),
        "required_mutex_symbols": sorted(EXPECTED_MUTEX_SYMBOLS),
        "guard_modes": sorted(EXPECTED_GUARD_MODES),
        "fixture_case_count": fixture_summary["case_count"],
        "source_anchor_count": anchor_count,
        "next_audit_threshold": 900,
        "replacement_total_call_throughs": replacement_summary["total_call_throughs"],
        "interpose_total_call_throughs": interpose_summary["total_call_throughs"],
        "replacement_mutex_forbidden_count": replacement_summary["mutex_forbidden_count"],
        "interpose_mutex_forbidden_count": interpose_summary["mutex_forbidden_count"],
        "residual_forbidden_count": residual_summary["residual_forbidden_count"],
    },
    "artifact_refs": [
        rel(residual_path),
        rel(replacement_path),
        rel(interpose_path),
        rel(log_path),
    ],
}

write_json(report_path, report)
write_log(records)
print(
    "pthread_mutex_callthrough_eradication_completion_contract: PASS "
    f"symbols={len(EXPECTED_MUTEX_SYMBOLS)} fixture_cases={fixture_summary['case_count']} "
    f"replacement={replacement_summary['total_call_throughs']} interpose={interpose_summary['total_call_throughs']} "
    f"residual={residual_summary['residual_forbidden_count']}"
)
PY
