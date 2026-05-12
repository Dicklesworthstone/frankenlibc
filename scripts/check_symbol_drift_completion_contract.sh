#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_SYMBOL_DRIFT_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/symbol_drift_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_SYMBOL_DRIFT_COMPLETION_REPORT:-${ROOT}/target/conformance/symbol_drift_completion_contract.report.json}"
LOG="${FRANKENLIBC_SYMBOL_DRIFT_COMPLETION_LOG:-${ROOT}/target/conformance/symbol_drift_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

python3 - "$ROOT" "$CONTRACT" "$REPORT" "$LOG" <<'PY'
import json
import pathlib
import re
import subprocess
import sys
import time

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
start_ns = time.time_ns()

EXPECTED_SCHEMA = "symbol_drift_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "symbol_drift_completion_contract.report.v1"
EXPECTED_ORIGINAL_BEAD = "bd-28s"
EXPECTED_COMPLETION_BEAD = "bd-28s.1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary": "unit",
    "tests.e2e.primary": "e2e",
    "telemetry.primary": "telemetry",
}
EXPECTED_SOURCE_KEYS = {
    "support_matrix",
    "reality_report",
    "symbol_drift_gate",
    "symbol_drift_harness",
    "docs_drift_gate",
    "docs_drift_harness",
    "completion_contract",
    "completion_gate",
    "completion_harness",
}
PASS_EVENTS = [
    "symbol_drift_completion.unit_binding",
    "symbol_drift_completion.e2e_binding",
    "symbol_drift_completion.telemetry_contract",
    "symbol_drift_completion.validated",
]
FAIL_EVENT = "symbol_drift_completion.failed"
VALID_STATUSES = {
    "Implemented",
    "RawSyscall",
    "WrapsHostLibc",
    "GlibcCallThrough",
    "Stub",
}


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
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
            require(isinstance(needle, str) and needle, "source_anchor_empty", f"{key} source anchor must be non-empty", key=key)
            require(
                needle in text,
                "source_anchor_missing",
                f"{key} is missing a required source anchor",
                key=key,
                path=source_artifacts[key],
                needle=needle,
            )
            total += 1
    return total


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
        require(binding.get("next_audit_threshold") == 900, "next_audit_threshold", "each item must pin threshold 900", item_id=item_id)
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
            require(binding.get("required_events") == PASS_EVENTS, "required_events_drift", "telemetry required events drifted")
        commands = binding.get("required_commands")
        require(isinstance(commands, list) and commands, "required_commands_missing", f"{item_id} commands must be non-empty", item_id=item_id)
        for command in commands:
            require(isinstance(command, str) and command, "command_empty", "required command must be non-empty", item_id=item_id)
            if " cargo " in f" {command} ":
                require("rch exec -- cargo" in command, "cargo_not_rch", "cargo validation must run through rch", command=command)
    require(actual == EXPECTED_MISSING_ITEMS, "missing_item_set_drift", "completion-debt missing item set drifted", actual=actual, expected=EXPECTED_MISSING_ITEMS)
    return bindings


def status_counts(symbols: list[dict]) -> dict:
    counts = {status: 0 for status in VALID_STATUSES}
    for entry in symbols:
        status = entry.get("status")
        require(status in VALID_STATUSES, "invalid_status", "support_matrix contains invalid status", symbol=entry.get("symbol"), status=status)
        counts[status] += 1
    return counts


def duplicate_count(symbols: list[dict]) -> int:
    seen = set()
    duplicates = 0
    for entry in symbols:
        symbol = entry.get("symbol")
        if symbol in seen:
            duplicates += 1
        seen.add(symbol)
    return duplicates


def missing_module_count(symbols: list[dict]) -> int:
    missing = 0
    abi_src = root / "crates/frankenlibc-abi/src"
    for entry in symbols:
        module = entry.get("module", "unknown")
        if not (abi_src / f"{module}.rs").is_file():
            missing += 1
    return missing


def validate_contract_details(contract: dict, source_artifacts: dict) -> dict:
    details = contract.get("symbol_drift_contract")
    require(isinstance(details, dict), "contract_details_shape", "symbol drift contract must be an object")
    require(details.get("next_audit_threshold") == 900, "contract_audit_threshold", "contract must pin threshold 900")

    support_matrix = load_json(root / source_artifacts["support_matrix"])
    symbols = support_matrix.get("symbols")
    require(isinstance(symbols, list) and symbols, "support_matrix_symbols", "support_matrix symbols must be a non-empty array")
    require(len(symbols) == details.get("required_total_symbols"), "symbol_total_drift", "support_matrix symbol count drifted", actual=len(symbols), expected=details.get("required_total_symbols"))
    counts = status_counts(symbols)
    require(counts == details.get("required_status_counts"), "status_counts_drift", "support_matrix status counts drifted", actual=counts, expected=details.get("required_status_counts"))
    duplicates = duplicate_count(symbols)
    require(duplicates == details.get("required_duplicate_symbols"), "duplicate_symbol_drift", "duplicate symbol count drifted", actual=duplicates, expected=details.get("required_duplicate_symbols"))
    missing_modules = missing_module_count(symbols)
    require(missing_modules == details.get("required_missing_module_symbols"), "missing_module_drift", "module file count drifted", actual=missing_modules, expected=details.get("required_missing_module_symbols"))

    reality = load_json(root / source_artifacts["reality_report"])
    require(reality.get("total_exported") == details.get("required_reality_total_exported"), "reality_total_drift", "reality total_exported drifted", actual=reality.get("total_exported"), expected=details.get("required_reality_total_exported"))
    require(reality.get("counts") == details.get("required_reality_counts"), "reality_counts_drift", "reality counts drifted", actual=reality.get("counts"), expected=details.get("required_reality_counts"))
    require(reality.get("stubs") == [], "reality_stubs_drift", "reality report must keep an empty stub list")

    gate = subprocess.run(
        ["bash", "scripts/check_symbol_drift.sh"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    require(gate.returncode == 0, "symbol_drift_gate_failed", "symbol drift gate failed", stdout=gate.stdout[-2000:], stderr=gate.stderr[-2000:])
    require("check_symbol_drift: PASS" in gate.stdout, "symbol_drift_pass_missing", "symbol drift gate did not emit PASS marker")

    docs_gate = source_text(source_artifacts, "docs_drift_gate")
    require("cargo run --quiet -p frankenlibc-harness --bin harness -- reality-report" in docs_gate, "docs_gate_harness_drift", "docs drift gate must bind harness reality-report generation")
    require("log_event \"docs_drift\"" in docs_gate, "docs_gate_telemetry_drift", "docs drift gate must emit structured telemetry")

    return {
        "symbol_count": len(symbols),
        "status_counts": counts,
        "duplicate_symbol_count": duplicates,
        "missing_module_symbol_count": missing_modules,
        "reality_total_exported": reality.get("total_exported"),
        "stub_count": len(reality.get("stubs", [])),
    }


contract = load_json(contract_path)
require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "schema_version drifted")
require(contract.get("original_bead") == EXPECTED_ORIGINAL_BEAD, "original_bead", "original bead drifted")
require(contract.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD, "completion_bead", "completion bead drifted")

source_artifacts = validate_source_artifacts(contract)
anchor_count = validate_source_anchors(contract, source_artifacts)
bindings = validate_missing_items(contract)
details_summary = validate_contract_details(contract, source_artifacts)

summary = {
    "missing_item_count": len(bindings),
    "source_artifact_count": len(source_artifacts),
    "source_anchor_count": anchor_count,
    **details_summary,
}
report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "original_bead": EXPECTED_ORIGINAL_BEAD,
    "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
    "source_commit": git_head(),
    "status": "pass",
    "failure_signature": "none",
    "contract": rel(contract_path),
    "report": rel(report_path),
    "log": rel(log_path),
    "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
    "summary": summary,
}
write_json(report_path, report)
write_log(
    [
        {
            "timestamp": now_utc(),
            "event": event,
            "status": "pass",
            "original_bead": EXPECTED_ORIGINAL_BEAD,
            "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
            "source_commit": report["source_commit"],
            "summary": summary,
            "artifact_refs": {
                "contract": rel(contract_path),
                "report": rel(report_path),
                "log": rel(log_path),
            },
        }
        for event in PASS_EVENTS
    ]
)
print(
    "PASS: symbol drift completion contract "
    f"items={summary['missing_item_count']} symbols={summary['symbol_count']} "
    f"implemented={summary['status_counts']['Implemented']} raw_syscall={summary['status_counts']['RawSyscall']} "
    f"duplicates={summary['duplicate_symbol_count']} stubs={summary['stub_count']}"
)
PY
