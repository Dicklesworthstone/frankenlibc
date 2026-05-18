#!/usr/bin/env bash
# check_completion_contract_rch_proof_manifest_lint.sh - bd-waaa6.4 remote-rch proof lint.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FRANKENLIBC_RCH_PROOF_LINT_MANIFEST:-${ROOT}/tests/conformance/completion_contract_rch_proof_manifest_lint.v1.json}"
OUT_DIR="${FRANKENLIBC_RCH_PROOF_LINT_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_RCH_PROOF_LINT_REPORT:-${OUT_DIR}/completion_contract_rch_proof_manifest_lint.report.json}"
LOG="${FRANKENLIBC_RCH_PROOF_LINT_LOG:-${OUT_DIR}/completion_contract_rch_proof_manifest_lint.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import pathlib
import re
import shlex
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
MANIFEST = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])
LOG = pathlib.Path(sys.argv[4])
OUT_DIR = pathlib.Path(sys.argv[5])
SOURCE_COMMIT = sys.argv[6]

EXPECTED_SCHEMA = "completion_contract_rch_proof_manifest_lint.v1"
REPORT_SCHEMA = "completion_contract_rch_proof_manifest_lint.report.v1"
BEAD = "bd-waaa6.4"
TRACE_ID = "bd-waaa6.4::completion-contract-rch-proof-lint::v1"
EXPECTED_REPORT = "target/conformance/completion_contract_rch_proof_manifest_lint.report.json"
EXPECTED_LOG = "target/conformance/completion_contract_rch_proof_manifest_lint.log.jsonl"
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "bead",
    "status",
    "summary",
    "policy",
    "contract_reports",
    "errors",
    "artifact_refs",
    "source_commit",
    "report_path",
    "log_path",
    "report_contract_fields",
    "contract_status",
    "contract_errors",
}
RUST_TEST_RE = re.compile(r"crates/frankenlibc-harness/tests/([A-Za-z0-9_]+)\.rs")
CARGO_RE = re.compile(r"(?:^|[\s'\"])cargo\s+(test|check|clippy)\b")
TEST_TARGET_RE = re.compile(r"--test\s+([A-Za-z0-9_]+)")
SHELL_WRAPPERS = {"bash", "sh", "zsh"}
COMMAND_FIELD_NAMES = {
    "command",
    "commands",
    "checker_command",
    "completion_test_command",
    "required_cargo_fuzz_command",
    "required_commands",
    "required_validation_commands",
    "runtime_validation",
    "targeted_test_command",
    "validation_command",
    "validation_commands",
}

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def resolve(path_text: str) -> pathlib.Path:
    path = pathlib.Path(path_text)
    return path if path.is_absolute() else ROOT / path


def add_error(contract: str, signature: str, message: str) -> None:
    errors.append(
        {
            "contract_path": contract,
            "failure_signature": signature,
            "message": message,
        }
    )


def load_json(path: pathlib.Path, context: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(rel(path), "malformed_json", f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def all_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            result.extend(all_strings(item))
        return result
    if isinstance(value, dict):
        result: list[str] = []
        for item in value.values():
            result.extend(all_strings(item))
        return result
    return []


def command_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        result: list[str] = []
        for key, item in value.items():
            if key in COMMAND_FIELD_NAMES:
                result.extend(all_strings(item))
            else:
                result.extend(command_strings(item))
        return result
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            result.extend(command_strings(item))
        return result
    return []


def as_str_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list):
        add_error(rel(MANIFEST), "malformed_manifest", f"{context} must be an array")
        return []
    result = [item for item in value if isinstance(item, str)]
    if len(result) != len(value):
        add_error(rel(MANIFEST), "malformed_manifest", f"{context} must contain only strings")
    return result


def configured_report_fields(manifest: dict[str, Any]) -> list[str]:
    report_contract = manifest.get("report_contract")
    if not isinstance(report_contract, dict):
        return []
    fields = report_contract.get("must_materialize")
    if not isinstance(fields, list):
        return []
    return [field for field in fields if isinstance(field, str) and field]


def validate_report_contract(manifest: dict[str, Any]) -> None:
    report_contract = manifest.get("report_contract")
    if not isinstance(report_contract, dict):
        add_error(rel(MANIFEST), "report_contract_missing", "report_contract must be an object")
        return
    if report_contract.get("output_path") != EXPECTED_REPORT:
        add_error(rel(MANIFEST), "report_contract_output_path_mismatch", f"output_path must be {EXPECTED_REPORT}")
    if report_contract.get("log_path") != EXPECTED_LOG:
        add_error(rel(MANIFEST), "report_contract_log_path_mismatch", f"log_path must be {EXPECTED_LOG}")
    fields = set(as_str_list(report_contract.get("must_materialize"), "report_contract.must_materialize"))
    missing = sorted(REQUIRED_REPORT_FIELDS - fields)
    if missing:
        add_error(rel(MANIFEST), "report_contract_missing_required_field", f"must_materialize missing {missing}")


def cargo_kind(command: str) -> str | None:
    match = CARGO_RE.search(command)
    return match.group(1) if match else None


def test_target(command: str) -> str | None:
    match = TEST_TARGET_RE.search(command)
    return match.group(1) if match else None


def split_command(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def rch_exec_index(tokens: list[str]) -> int | None:
    for index, (left, right) in enumerate(zip(tokens, tokens[1:])):
        if left == "rch" and right == "exec":
            return index
    return None


def validate_remote_command(
    contract_path: str,
    command: str,
    required_remote_env: str,
    forbidden_target_values: set[str],
) -> list[str]:
    signatures: list[str] = []
    stripped = command.strip()
    if stripped.startswith("cargo "):
        add_error(contract_path, "bare_cargo_command", f"cargo command is bare: {command}")
        signatures.append("bare_cargo_command")
    if required_remote_env not in command:
        add_error(contract_path, "missing_remote_env", f"cargo command lacks {required_remote_env}: {command}")
        signatures.append("missing_remote_env")

    tokens = split_command(command)
    exec_index = rch_exec_index(tokens)
    if exec_index is None:
        add_error(contract_path, "missing_rch_exec", f"cargo command lacks rch exec launcher: {command}")
        signatures.append("missing_rch_exec")
        return signatures

    separator_index = exec_index + 2
    if separator_index >= len(tokens) or tokens[separator_index] != "--":
        add_error(contract_path, "missing_rch_exec", f"cargo command lacks rch exec -- separator: {command}")
        signatures.append("missing_rch_exec")
        return signatures

    payload_index = separator_index + 1
    if payload_index >= len(tokens) or tokens[payload_index] != "env":
        add_error(
            contract_path,
            "missing_rch_exec_env",
            f"cargo command must launch through rch exec -- env: {command}",
        )
        signatures.append("missing_rch_exec_env")
        if payload_index < len(tokens) and tokens[payload_index] in SHELL_WRAPPERS:
            add_error(contract_path, "shell_wrapped_cargo", f"cargo command is shell-wrapped: {command}")
            signatures.append("shell_wrapped_cargo")
        return signatures

    payload_tokens = tokens[payload_index + 1 :]
    cargo_index = next((index for index, token in enumerate(payload_tokens) if token == "cargo"), None)
    pre_cargo_tokens = payload_tokens if cargo_index is None else payload_tokens[:cargo_index]

    if any(token in SHELL_WRAPPERS for token in pre_cargo_tokens):
        add_error(contract_path, "shell_wrapped_cargo", f"cargo command is shell-wrapped: {command}")
        signatures.append("shell_wrapped_cargo")

    target_envs = [token for token in pre_cargo_tokens if token.startswith("CARGO_TARGET_DIR=")]
    if not target_envs:
        add_error(contract_path, "missing_isolated_target_dir", f"cargo command lacks CARGO_TARGET_DIR: {command}")
        signatures.append("missing_isolated_target_dir")
    else:
        for target_env in target_envs:
            _, _, target_value = target_env.partition("=")
            if target_value in forbidden_target_values:
                add_error(
                    contract_path,
                    "missing_isolated_target_dir",
                    f"cargo command uses placeholder or empty CARGO_TARGET_DIR: {command}",
                )
                signatures.append("missing_isolated_target_dir")
                break
    return signatures


def primary_signature(signatures: list[str]) -> str:
    priority = [
        "malformed_json",
        "malformed_manifest",
        "missing_contract",
        "local_fallback_marker",
        "bare_cargo_command",
        "missing_remote_env",
        "missing_rch_exec",
        "missing_rch_exec_env",
        "shell_wrapped_cargo",
        "missing_isolated_target_dir",
        "missing_targeted_test_lane",
        "missing_targeted_check_lane",
        "missing_targeted_clippy_lane",
    ]
    present = set(signatures)
    for signature in priority:
        if signature in present:
            return signature
    return "completion_contract_rch_proof_manifest_lint_failed"


def event(contract_path: str, status: str, failure_signature: str, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "trace_id": f"{TRACE_ID}::{pathlib.Path(contract_path).stem}",
        "level": "info" if status == "pass" else "error",
        "event": "completion_contract_rch_proof_manifest_linted",
        "bead_id": BEAD,
        "stream": "conformance",
        "gate": "completion_contract_rch_proof_manifest_lint",
        "scenario_id": pathlib.Path(contract_path).stem,
        "outcome": status,
        "source_commit": SOURCE_COMMIT,
        "target_dir": rel(OUT_DIR),
        "failure_signature": failure_signature,
        "artifact_refs": [rel(MANIFEST), contract_path],
        "details": details,
    }


manifest = load_json(MANIFEST, "manifest")
if not isinstance(manifest, dict):
    manifest = {}

if manifest.get("schema_version") != EXPECTED_SCHEMA:
    add_error(rel(MANIFEST), "malformed_manifest", f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("bead") != BEAD:
    add_error(rel(MANIFEST), "malformed_manifest", f"bead must be {BEAD}")
validate_report_contract(manifest)

policy = manifest.get("policy", {})
if not isinstance(policy, dict):
    add_error(rel(MANIFEST), "malformed_manifest", "policy must be an object")
    policy = {}

required_remote_env = str(policy.get("required_remote_env", "RCH_FORCE_REMOTE=true"))
forbidden_target_values = set(as_str_list(policy.get("forbidden_target_dir_values", []), "policy.forbidden_target_dir_values"))
forbidden_markers = as_str_list(policy.get("forbidden_proof_markers", ["[RCH] local"]), "policy.forbidden_proof_markers")
completion_lanes = set(as_str_list(policy.get("required_completion_test_lanes", []), "policy.required_completion_test_lanes"))
contract_paths = as_str_list(manifest.get("contract_paths", []), "contract_paths")
launcher_only_contract_paths = as_str_list(
    manifest.get("launcher_only_contract_paths", []),
    "launcher_only_contract_paths",
)

contract_reports: list[dict[str, Any]] = []
total_cargo_commands = 0
total_rust_surfaces = 0

contract_specs = [(contract_path, True) for contract_path in contract_paths] + [
    (contract_path, False) for contract_path in launcher_only_contract_paths
]

for contract_path_text, enforce_lane_matrix in contract_specs:
    contract_path = resolve(contract_path_text)
    contract_errors_before = len(errors)
    contract_signatures: list[str] = []
    if not contract_path.exists():
        add_error(contract_path_text, "missing_contract", f"contract path does not exist: {contract_path_text}")
        contract_signatures.append("missing_contract")
        strings: list[str] = []
        contract = {}
    else:
        contract = load_json(contract_path, "contract")
        strings = all_strings(contract)

    for marker in forbidden_markers:
        if any(marker in text for text in strings):
            add_error(contract_path_text, "local_fallback_marker", f"contract text contains forbidden proof marker {marker}")
            contract_signatures.append("local_fallback_marker")

    rust_surfaces = sorted({match.group(1) for text in strings for match in RUST_TEST_RE.finditer(text)})
    completion_targets = sorted(surface for surface in rust_surfaces if surface.endswith("_completion_contract_test"))
    cargo_commands = [text for text in command_strings(contract) if cargo_kind(text) is not None]
    total_cargo_commands += len(cargo_commands)
    total_rust_surfaces += len(rust_surfaces)

    command_index: dict[tuple[str, str], list[str]] = {}
    for command in cargo_commands:
        kind = cargo_kind(command)
        target = test_target(command)
        if kind is not None and target is not None:
            command_index.setdefault((kind, target), []).append(command)
        contract_signatures.extend(
            validate_remote_command(contract_path_text, command, required_remote_env, forbidden_target_values)
        )

    if enforce_lane_matrix:
        for surface in rust_surfaces:
            if ("test", surface) not in command_index:
                add_error(contract_path_text, "missing_targeted_test_lane", f"missing targeted cargo test lane for {surface}")
                contract_signatures.append("missing_targeted_test_lane")

        for target in completion_targets:
            for lane in sorted(completion_lanes):
                if (lane, target) not in command_index:
                    signature = f"missing_targeted_{lane}_lane"
                    add_error(contract_path_text, signature, f"missing targeted cargo {lane} lane for {target}")
                    contract_signatures.append(signature)

    new_errors = errors[contract_errors_before:]
    status = "pass" if not new_errors else "fail"
    failure_signature = "none" if status == "pass" else primary_signature([error["failure_signature"] for error in new_errors] + contract_signatures)
    details = {
        "rust_surfaces": rust_surfaces,
        "completion_targets": completion_targets,
        "cargo_command_count": len(cargo_commands),
        "enforce_lane_matrix": enforce_lane_matrix,
        "targeted_lanes": sorted(f"{kind}:{target}" for (kind, target) in command_index),
        "error_count": len(new_errors),
    }
    contract_reports.append(
        {
            "contract_path": contract_path_text,
            "status": status,
            "failure_signature": failure_signature,
            **details,
        }
    )
    events.append(event(contract_path_text, status, failure_signature, details))

status = "pass" if not errors else "fail"
report_contract_fields = configured_report_fields(manifest)
summary = {
    "contract_count": len(contract_specs),
    "strict_contract_count": len(contract_paths),
    "launcher_only_contract_count": len(launcher_only_contract_paths),
    "passed_contracts": sum(1 for row in contract_reports if row["status"] == "pass"),
    "failed_contracts": sum(1 for row in contract_reports if row["status"] == "fail"),
    "rust_surface_count": total_rust_surfaces,
    "cargo_command_count": total_cargo_commands,
}
report = {
    "schema_version": REPORT_SCHEMA,
    "bead": BEAD,
    "status": "pending",
    "summary": summary,
    "policy": policy,
    "contract_reports": contract_reports,
    "errors": errors,
    "artifact_refs": [rel(MANIFEST), *contract_paths, rel(REPORT), rel(LOG)],
    "source_commit": SOURCE_COMMIT,
    "report_path": rel(REPORT),
    "log_path": rel(LOG),
    "report_contract_fields": report_contract_fields,
    "contract_status": "pending",
    "contract_errors": [],
}
for field in report_contract_fields:
    if field not in report:
        add_error(rel(MANIFEST), "missing_report_field", f"report omitted required field: {field}")
status = "pass" if not errors else "fail"
contract_errors = [
    row
    for row in errors
    if row["failure_signature"].startswith("report_contract_")
    or row["failure_signature"] == "missing_report_field"
]
report["status"] = status
report["errors"] = errors
report["contract_status"] = "pass" if not contract_errors else "fail"
report["contract_errors"] = contract_errors
write_json(REPORT, report)
write_jsonl(LOG, events)

if status == "pass":
    print(
        "completion_contract_rch_proof_manifest_lint: PASS "
        f"(contracts={summary['contract_count']}, cargo_commands={summary['cargo_command_count']})"
    )
    raise SystemExit(0)

for error in errors:
    print(
        "completion_contract_rch_proof_manifest_lint: ERROR "
        f"{error['contract_path']}: {error['failure_signature']}: {error['message']}",
        file=sys.stderr,
    )
print(
    "completion_contract_rch_proof_manifest_lint: FAIL "
    f"errors={len(errors)} report={rel(REPORT)} log={rel(LOG)}",
    file=sys.stderr,
)
raise SystemExit(1)
PY
