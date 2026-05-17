#!/usr/bin/env bash
# check_ci_rch_cargo_policy.sh - static CI guard for RCH-backed cargo validation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FRANKENLIBC_CI_RCH_CARGO_POLICY_MANIFEST:-${ROOT}/tests/conformance/ci_rch_cargo_policy.v1.json}"
CI_SCRIPT="${FRANKENLIBC_CI_RCH_CARGO_POLICY_SCRIPT:-${ROOT}/scripts/ci.sh}"
OUT_DIR="${FRANKENLIBC_CI_RCH_CARGO_POLICY_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_CI_RCH_CARGO_POLICY_REPORT:-${OUT_DIR}/ci_rch_cargo_policy.report.json}"
LOG="${FRANKENLIBC_CI_RCH_CARGO_POLICY_LOG:-${OUT_DIR}/ci_rch_cargo_policy.log.jsonl}"

case "${1:---validate-only}" in
  --validate-only) ;;
  *)
    echo "usage: $0 [--validate-only]" >&2
    exit 2
    ;;
esac

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${CI_SCRIPT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import copy
import json
import pathlib
import re
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
MANIFEST = pathlib.Path(sys.argv[2])
CI_SCRIPT = pathlib.Path(sys.argv[3])
REPORT = pathlib.Path(sys.argv[4])
LOG = pathlib.Path(sys.argv[5])

EXPECTED_SCHEMA = "ci_rch_cargo_policy.v1"
REPORT_SCHEMA = "ci_rch_cargo_policy.report.v1"
EXPECTED_BEAD = "bd-dgxsh"

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except Exception:
        return str(path)


def add_error(source: str, signature: str, message: str) -> None:
    errors.append({"source": source, "failure_signature": signature, "message": message})


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(rel(path), "malformed_json", f"cannot parse JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        add_error(rel(path), "malformed_json", "manifest must be a JSON object")
        return {}
    return value


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def string_list(value: Any, source: str, field: str, *, non_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (non_empty and not value):
        add_error(source, "malformed_manifest", f"{field} must be a non-empty string array")
        return []
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            add_error(source, "malformed_manifest", f"{field} contains a non-string value")
        else:
            result.append(item)
    return result


def non_comment_lines(text: str) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        rows.append((line_no, stripped))
    return rows


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    source = rel(MANIFEST)
    if manifest.get("schema_version") != EXPECTED_SCHEMA:
        add_error(source, "schema_version", f"schema_version must be {EXPECTED_SCHEMA}")
    if manifest.get("bead") != EXPECTED_BEAD:
        add_error(source, "wrong_bead", f"bead must be {EXPECTED_BEAD}")
    policy = manifest.get("policy")
    if not isinstance(policy, dict):
        add_error(source, "malformed_manifest", "policy must be an object")
        return {}
    protected = string_list(policy.get("protected_subcommands"), source, "policy.protected_subcommands")
    if sorted(protected) != ["build", "check", "clippy", "test"]:
        add_error(source, "malformed_manifest", "protected_subcommands must be build/check/clippy/test")
    allowed_local = string_list(policy.get("allowed_local_cargo_subcommands"), source, "policy.allowed_local_cargo_subcommands")
    if allowed_local != ["fmt"]:
        add_error(source, "malformed_manifest", "only local cargo fmt may be allowed")
    if policy.get("remote_wrapper") != "run_remote_cargo":
        add_error(source, "malformed_manifest", "remote_wrapper must be run_remote_cargo")
    if policy.get("required_remote_env") != "RCH_REQUIRE_REMOTE=1":
        add_error(source, "malformed_manifest", "required_remote_env must be RCH_REQUIRE_REMOTE=1")
    if policy.get("required_launcher") != "rch exec -- env":
        add_error(source, "malformed_manifest", "required_launcher must be rch exec -- env")
    if policy.get("required_target_dir_env") != "CARGO_TARGET_DIR=":
        add_error(source, "malformed_manifest", "required_target_dir_env must be CARGO_TARGET_DIR=")

    commands = string_list(manifest.get("required_validation_commands"), source, "required_validation_commands")
    for command in commands:
        if re.search(r"\bcargo\s+(check|clippy|test|build)\b", command):
            add_error(source, "validation_command_not_static", f"validation command must not run cargo validation: {command}")
    controls = manifest.get("negative_controls")
    if not isinstance(controls, list) or len(controls) < 4:
        add_error(source, "missing_negative_controls", "negative_controls must include at least four cases")
    return policy


def validate_script(text: str, policy: dict[str, Any], source: str) -> list[dict[str, str]]:
    local_errors: list[dict[str, str]] = []

    def err(signature: str, message: str) -> None:
        local_errors.append({"source": source, "failure_signature": signature, "message": message})

    protected = set(policy.get("protected_subcommands", []))
    allowed_local = set(policy.get("allowed_local_cargo_subcommands", []))
    wrapper = str(policy.get("remote_wrapper", "run_remote_cargo"))

    if f"{wrapper}()" not in text:
        err("missing_remote_wrapper", f"{wrapper} function is missing")
    if policy.get("required_remote_env") not in text:
        err("missing_remote_env", "remote wrapper must require RCH_REQUIRE_REMOTE=1")
    if policy.get("required_launcher") not in text:
        err("missing_rch_launcher", "remote wrapper must invoke rch exec -- env")
    if policy.get("required_target_dir_env") not in text:
        err("missing_target_dir_env", "remote wrapper must set CARGO_TARGET_DIR")
    if "bash scripts/check_ci_rch_cargo_policy.sh --validate-only" not in text:
        err("ci_policy_gate_not_wired", "scripts/ci.sh must run this checker before cargo-backed gates")

    invoked: set[str] = set()
    local_allowed_seen: set[str] = set()
    bare_pattern = re.compile(r"^(?:env\s+[^;]*\s+)?cargo\s+([A-Za-z0-9_-]+)\b")
    wrapper_pattern = re.compile(rf"^{re.escape(wrapper)}\s+([A-Za-z0-9_-]+)\b")
    for line_no, stripped in non_comment_lines(text):
        bare = bare_pattern.search(stripped)
        if bare:
            subcommand = bare.group(1)
            if subcommand in protected:
                err("bare_cargo_validation_command", f"line {line_no}: protected cargo command is bare: {stripped}")
            elif subcommand in allowed_local:
                local_allowed_seen.add(subcommand)
            continue
        wrapped = wrapper_pattern.search(stripped)
        if wrapped:
            invoked.add(wrapped.group(1))

    missing_wrapped = sorted(protected - invoked)
    if missing_wrapped:
        err("missing_wrapped_cargo_validation", f"missing wrapped cargo validation commands: {missing_wrapped}")
    missing_allowed = sorted(allowed_local - local_allowed_seen)
    if missing_allowed:
        err("missing_allowed_local_cargo", f"expected local cargo commands not present: {missing_allowed}")

    return local_errors


def apply_mutation(text: str, mutation: dict[str, Any]) -> str:
    if "append_line" in mutation:
        return text + "\n" + str(mutation["append_line"]) + "\n"
    if "replace" in mutation and isinstance(mutation["replace"], dict):
        old = str(mutation["replace"].get("old", ""))
        new = str(mutation["replace"].get("new", ""))
        return text.replace(old, new, 1)
    if "remove" in mutation:
        return text.replace(str(mutation["remove"]), "", 1)
    return text


def run_negative_controls(manifest: dict[str, Any], text: str, policy: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    controls = manifest.get("negative_controls")
    if not isinstance(controls, list):
        return rows
    for control in controls:
        if not isinstance(control, dict):
            continue
        control_id = str(control.get("id"))
        expected = str(control.get("expected_failure_signature"))
        mutation = control.get("mutation")
        if not isinstance(mutation, dict):
            add_error(control_id, "malformed_negative_control", "mutation must be an object")
            continue
        mutated = apply_mutation(text, copy.deepcopy(mutation))
        control_errors = validate_script(mutated, policy, control_id)
        signatures = sorted({row["failure_signature"] for row in control_errors})
        status = "pass" if expected in signatures else "fail"
        rows.append(
            {
                "event": "ci_rch_cargo_policy_negative_control",
                "control_id": control_id,
                "expected_failure_signature": expected,
                "observed_failure_signatures": signatures,
                "status": status,
            }
        )
        if status != "pass":
            add_error(control_id, "negative_control_not_detected", f"expected {expected}, observed {signatures}")
    return rows


manifest = load_json(MANIFEST)
policy = validate_manifest(manifest)
try:
    script_text = CI_SCRIPT.read_text(encoding="utf-8")
except Exception as exc:
    script_text = ""
    add_error(rel(CI_SCRIPT), "script_unreadable", str(exc))

errors.extend(validate_script(script_text, policy, rel(CI_SCRIPT)))
negative_rows = run_negative_controls(manifest, script_text, policy)
status = "pass" if not errors else "fail"

events.append(
    {
        "event": "ci_rch_cargo_policy_validated" if status == "pass" else "ci_rch_cargo_policy_failed",
        "schema_version": REPORT_SCHEMA,
        "bead": EXPECTED_BEAD,
        "status": status,
        "failure_count": len(errors),
        "negative_control_count": len(negative_rows),
        "timestamp": utc_now(),
    }
)
events.extend(negative_rows)

report = {
    "schema_version": REPORT_SCHEMA,
    "manifest": rel(MANIFEST),
    "ci_script": rel(CI_SCRIPT),
    "bead": EXPECTED_BEAD,
    "status": status,
    "errors": errors,
    "negative_controls": negative_rows,
    "generated_at": utc_now(),
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if status != "pass":
    print(f"ci_rch_cargo_policy: FAIL errors={len(errors)} report={rel(REPORT)}", file=sys.stderr)
    for error in errors:
        print(f"{error['failure_signature']}: {error['message']}", file=sys.stderr)
    sys.exit(1)

print(
    "ci_rch_cargo_policy: pass "
    f"negative_controls={sum(1 for row in negative_rows if row['status'] == 'pass')}"
)
PY
