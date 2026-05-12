#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_AARCH64_RAW_SYSCALL_TLS_CONTRACT:-${ROOT}/tests/conformance/aarch64_raw_syscall_tls_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_AARCH64_RAW_SYSCALL_TLS_REPORT:-${ROOT}/target/conformance/aarch64_raw_syscall_tls_completion_contract.report.json}"
LOG="${FRANKENLIBC_AARCH64_RAW_SYSCALL_TLS_LOG:-${ROOT}/target/conformance/aarch64_raw_syscall_tls_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "aarch64_raw_syscall_tls_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "aarch64_raw_syscall_tls_completion_contract.report.v1"
EXPECTED_ORIGINAL_BEAD = "bd-1gg.3"
EXPECTED_COMPLETION_BEAD = "bd-1gg.3.1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary": "unit",
    "tests.e2e.primary": "e2e",
    "tests.fuzz.primary": "fuzz",
    "tests.conformance.primary": "conformance",
    "telemetry.primary": "telemetry",
}
EXPECTED_SOURCE_KEYS = {
    "raw_syscall",
    "syscall_mod",
    "tls_core",
    "thread_core",
    "pthread_abi",
    "startup_abi",
    "startup_tls_contract",
    "startup_tls_matrix",
    "pthread_tls_fixture",
    "pthread_thread_fixture",
    "pthread_tls_harness",
    "pthread_thread_harness",
    "fuzz_open_syscalls",
    "fuzz_security_syscalls",
    "fuzz_sched",
    "fuzz_pthread_keys",
    "fuzz_pthread_keys_corpus",
    "completion_contract",
    "completion_gate",
    "completion_harness",
}
EXPECTED_SYSCALL_ARITY = [0, 1, 2, 3, 4, 5, 6]
EXPECTED_SYSCALL_CONSTANTS = {
    "SYS_READ": 63,
    "SYS_WRITE": 64,
    "SYS_OPEN": 56,
    "SYS_CLOSE": 57,
    "SYS_MUNMAP": 215,
    "SYS_CLONE": 220,
    "SYS_EXIT": 93,
}
EXPECTED_PROOF_ROWS = {"tls_initialization", "pthread_tls_keys"}
EXPECTED_FUZZ_TARGETS = {
    "fuzz_open_syscalls",
    "fuzz_security_syscalls",
    "fuzz_sched",
    "fuzz_pthread_keys",
}
PASS_EVENTS = [
    "aarch64_raw_syscall_tls_completion.unit_binding",
    "aarch64_raw_syscall_tls_completion.e2e_binding",
    "aarch64_raw_syscall_tls_completion.fuzz_binding",
    "aarch64_raw_syscall_tls_completion.conformance_binding",
    "aarch64_raw_syscall_tls_completion.telemetry_contract",
    "aarch64_raw_syscall_tls_completion.validated",
]
FAIL_EVENT = "aarch64_raw_syscall_tls_completion.failed"


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
        full = root / path
        if key == "fuzz_pthread_keys_corpus":
            require(full.is_dir(), "source_path_missing", f"source artifact directory missing: {path}", key=key, path=path)
        else:
            require(full.is_file(), "source_path_missing", f"source artifact missing: {path}", key=key, path=path)
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


def validate_contract_details(contract: dict, source_artifacts: dict) -> dict:
    details = contract.get("aarch64_raw_syscall_tls_contract")
    require(isinstance(details, dict), "contract_details_shape", "aarch64 contract details must be an object")
    require(details.get("required_arch") == "aarch64", "required_arch", "required arch must remain aarch64")
    require(details.get("required_syscall_arity") == EXPECTED_SYSCALL_ARITY, "syscall_arity_drift", "syscall arity list drifted")
    require(details.get("required_syscall_constants") == EXPECTED_SYSCALL_CONSTANTS, "syscall_constant_contract_drift", "syscall constant contract drifted")
    require(details.get("required_clone_tail_order") == ["parent_tid", "tls", "child_tid"], "clone_tail_order_contract_drift", "clone tail order contract drifted")
    require(set(details.get("required_proof_rows") or []) == EXPECTED_PROOF_ROWS, "proof_row_contract_drift", "proof row contract drifted")
    require(set(details.get("required_fuzz_targets") or []) == EXPECTED_FUZZ_TARGETS, "fuzz_target_contract_drift", "fuzz target contract drifted")
    require(details.get("pthread_keys_corpus_min_seeds") == 7, "corpus_seed_floor_drift", "pthread key corpus seed floor drifted")
    require(details.get("next_audit_threshold") == 900, "contract_audit_threshold", "contract must pin threshold 900")

    raw = source_text(source_artifacts, "raw_syscall")
    for arity in EXPECTED_SYSCALL_ARITY:
        pattern = rf'#\[cfg\(target_arch = "aarch64"\)\]\s+pub unsafe fn syscall{arity}\b'
        require(re.search(pattern, raw), "syscall_arity_missing", "missing aarch64 raw syscall arity", arity=arity)
    require(
        "assert_eq!(current_clone_tail_args(1, 2, 3), (1, 3, 2));" in raw,
        "clone_tail_test_missing",
        "missing aarch64 clone tail layout regression test",
    )
    require(
        "clone(flags, stack, parent_tid, tls, child_tid)" in raw,
        "clone_tail_doc_missing",
        "missing documented aarch64 clone tail order",
    )

    syscall_mod = source_text(source_artifacts, "syscall_mod")
    for name, value in EXPECTED_SYSCALL_CONSTANTS.items():
        needle = f"pub const {name}: usize = {value};"
        require(needle in syscall_mod, "syscall_constant_missing", "missing required aarch64 syscall constant", name=name, value=value)

    tls = source_text(source_artifacts, "tls_core")
    thread = source_text(source_artifacts, "thread_core")
    startup = source_text(source_artifacts, "startup_abi")
    pthread = source_text(source_artifacts, "pthread_abi")
    for control in details.get("required_tls_controls") or []:
        require(isinstance(control, str) and control, "tls_control_empty", "TLS control name must be non-empty")
        haystack = "\n".join([tls, thread, startup, pthread])
        require(control in haystack, "tls_control_missing", "missing required TLS/control primitive", control=control)

    matrix = load_json(root / source_artifacts["startup_tls_matrix"])
    rows = matrix.get("proof_rows")
    require(isinstance(rows, list), "proof_rows_shape", "startup/TLS matrix proof_rows must be an array")
    row_ids = {row.get("id") for row in rows if isinstance(row, dict)}
    require(EXPECTED_PROOF_ROWS <= row_ids, "proof_rows_missing", "startup/TLS proof rows missing", actual=sorted(row_ids))

    tls_fixture = load_json(root / source_artifacts["pthread_tls_fixture"])
    thread_fixture = load_json(root / source_artifacts["pthread_thread_fixture"])
    require(tls_fixture.get("family") == "pthread/tls_keys", "tls_fixture_family", "pthread TLS fixture family drifted")
    require(thread_fixture.get("family") == "pthread/thread", "thread_fixture_family", "pthread thread fixture family drifted")
    for fixture, required in [
        (tls_fixture, {"pthread_key_create", "pthread_key_delete", "pthread_getspecific", "pthread_setspecific"}),
        (thread_fixture, {"pthread_create", "pthread_join", "pthread_detach", "pthread_self"}),
    ]:
        functions = {case.get("function") for case in fixture.get("cases", []) if isinstance(case, dict)}
        require(required <= functions, "fixture_function_missing", "required conformance fixture functions missing", required=sorted(required), actual=sorted(functions))

    for target in EXPECTED_FUZZ_TARGETS:
        text = source_text(source_artifacts, target)
        require("fuzz_target!" in text, "fuzz_target_missing", "fuzz target macro missing", target=target)
    corpus_dir = root / source_artifacts["fuzz_pthread_keys_corpus"]
    seed_count = len([path for path in corpus_dir.iterdir() if path.is_file()])
    require(seed_count >= 7, "pthread_key_corpus_seed_floor", "pthread key corpus seed floor not met", seed_count=seed_count)
    return {
        "syscall_arity_count": len(EXPECTED_SYSCALL_ARITY),
        "syscall_constant_count": len(EXPECTED_SYSCALL_CONSTANTS),
        "proof_row_count": len(EXPECTED_PROOF_ROWS),
        "fuzz_target_count": len(EXPECTED_FUZZ_TARGETS),
        "pthread_keys_corpus_seed_count": seed_count,
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
    "PASS: aarch64 raw syscall TLS completion contract "
    f"items={summary['missing_item_count']} arities={summary['syscall_arity_count']} "
    f"constants={summary['syscall_constant_count']} fuzz_targets={summary['fuzz_target_count']} "
    f"corpus_seeds={summary['pthread_keys_corpus_seed_count']}"
)
PY
