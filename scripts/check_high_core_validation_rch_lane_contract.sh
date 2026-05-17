#!/usr/bin/env bash
# check_high_core_validation_rch_lane_contract.sh -- remote-only proof gate for bd-brysl.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${HIGH_CORE_VALIDATION_SHARD_MANIFEST:-$ROOT/tests/conformance/high_core_validation_shards.v1.json}"
CONTRACT="${HIGH_CORE_VALIDATION_RCH_LANE_CONTRACT:-$ROOT/tests/conformance/high_core_validation_rch_lane_contract.v1.json}"
PLAN="${HIGH_CORE_VALIDATION_SHARD_PLAN:-}"
REPORT="${HIGH_CORE_VALIDATION_RCH_LANE_REPORT:-$ROOT/target/conformance/high_core_validation/rch_lane_contract.report.json}"
EVENTS="${HIGH_CORE_VALIDATION_RCH_LANE_EVENTS:-$ROOT/target/conformance/high_core_validation/rch_lane_contract.events.log.jsonl}"
OUTPUTS="${HIGH_CORE_VALIDATION_RCH_OUTPUTS:-}"
MODE="validate-only"

if [[ $# -gt 0 ]]; then
    case "$1" in
        --validate-only)
            MODE="validate-only"
            shift
            ;;
        *)
            MODE="unknown:$1"
            shift
            ;;
    esac
fi

if [[ $# -gt 0 ]]; then
    MODE="unknown:$1"
fi

cd "${ROOT}"

python3 - "${ROOT}" "${MANIFEST}" "${CONTRACT}" "${PLAN}" "${REPORT}" "${EVENTS}" "${OUTPUTS}" "${MODE}" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
contract_path = Path(sys.argv[3])
plan_path_text = sys.argv[4]
report_path = Path(sys.argv[5])
events_path = Path(sys.argv[6])
outputs_text = sys.argv[7]
mode = sys.argv[8]

violations = []


def relative_path(path):
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def load_json(path, signature):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_violation(
            "<input>",
            "input",
            "json",
            signature,
            f"{relative_path(path)} could not be read as JSON: {exc}",
            "",
            "Restore the committed contract/manifest JSON and rerun the checker.",
        )
        return {}


def command_text(command):
    if isinstance(command, list):
        return " ".join(str(part) for part in command)
    return str(command)


def rerun_command(command):
    text = command_text(command)
    if "rch" in text:
        return text
    return (
        "RCH_VISIBILITY=verbose RCH_FORCE_REMOTE=true RCH_NO_SELF_HEALING=1 "
        "RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR,RCH_FORCE_REMOTE,RCH_NO_SELF_HEALING "
        "rch --no-self-healing exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_high_core_validation "
        f"{text}"
    )


def add_violation(unit_id, execution_kind, field, signature, message, command, remediation):
    violations.append(
        {
            "unit_id": unit_id,
            "execution_kind": execution_kind,
            "field": field,
            "failure_signature": signature,
            "message": message,
            "rerun_command": rerun_command(command),
            "remediation": remediation,
        }
    )


def is_string_array(value):
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def has_cargo(command):
    return any(part == "cargo" for part in command) if isinstance(command, list) else "cargo" in str(command)


def has_bash_wrapped_cargo(command):
    if not isinstance(command, list):
        return bool(re.search(r"\b(bash|sh|zsh)\s+-c\s+['\"]?[^'\"]*cargo\b", str(command)))
    for index, token in enumerate(command):
        if token in {"bash", "sh", "zsh"} and index + 1 < len(command):
            tail = " ".join(command[index + 1 :])
            if "-c" in tail and re.search(r"\bcargo\b", tail):
                return True
    return False


def require_contract_policy(contract):
    if contract.get("schema_version") != "v1":
        add_violation(
            "<contract>",
            "input",
            "schema_version",
            "invalid_contract",
            "rch lane contract schema_version must be v1",
            "",
            "Preserve tests/conformance/high_core_validation_rch_lane_contract.v1.json schema_version=v1.",
        )
    if contract.get("bead") != "bd-brysl":
        add_violation(
            "<contract>",
            "input",
            "bead",
            "invalid_contract",
            "rch lane contract bead must be bd-brysl",
            "",
            "Preserve the contract bead binding so closeout evidence remains attributable.",
        )
    remote = contract.get("proof_classes", {}).get("remote_rch", {})
    local = contract.get("proof_classes", {}).get("local_metadata", {})
    for required in ["RCH_FORCE_REMOTE=true", "RCH_NO_SELF_HEALING=1"]:
        if required not in remote.get("required_env", []):
            add_violation(
                "<contract>",
                "remote_rch",
                "proof_classes.remote_rch.required_env",
                "missing_required_env",
                f"remote_rch policy must require {required}",
                "",
                "Restore required_env to include both remote force and no-self-healing env.",
            )
    for required in ["--no-self-healing", "exec"]:
        if required not in remote.get("required_rch_args", []):
            add_violation(
                "<contract>",
                "remote_rch",
                "proof_classes.remote_rch.required_rch_args",
                "missing_rch_arg",
                f"remote_rch policy must require rch arg {required}",
                "",
                "Restore required_rch_args so generated proof commands cannot self-heal locally.",
            )
    if "[RCH] local" not in remote.get("forbidden_output_markers", []):
        add_violation(
            "<contract>",
            "remote_rch",
            "proof_classes.remote_rch.forbidden_output_markers",
            "rch_local_fallback",
            "remote_rch policy must forbid [RCH] local output",
            "",
            "Preserve [RCH] local as invalid proof.",
        )
    if local.get("cargo_allowed") is not False:
        add_violation(
            "<contract>",
            "local_metadata",
            "proof_classes.local_metadata.cargo_allowed",
            "cargo_in_local_metadata",
            "local metadata lanes must not allow cargo",
            "",
            "Keep local_metadata.cargo_allowed=false; cargo lanes must use remote_rch.",
        )


def validate_command(unit_id, execution_kind, command, required_env, required_args):
    if not is_string_array(command) or not command:
        add_violation(
            unit_id,
            execution_kind,
            "command_template",
            "invalid_command_template",
            "command_template must be a non-empty string array",
            command,
            "Use tokenized command templates so rch proof can be classified deterministically.",
        )
        return
    text = command_text(command)
    cargo = has_cargo(command)
    if "[RCH] local" in text:
        add_violation(
            unit_id,
            execution_kind,
            "command_template",
            "rch_local_fallback",
            "command_template contains an rch local fallback marker",
            command,
            "Remove local fallback text from proof commands; only remote output may be used.",
        )
    if has_bash_wrapped_cargo(command):
        add_violation(
            unit_id,
            execution_kind,
            "command_template",
            "bash_wrapped_cargo",
            "cargo is wrapped in a shell and may bypass rch command classification",
            command,
            "Use a direct rch --no-self-healing exec -- cargo ... template.",
        )
    if execution_kind == "local_metadata" and cargo:
        add_violation(
            unit_id,
            execution_kind,
            "command_template",
            "cargo_in_local_metadata",
            "local metadata lane invokes cargo",
            command,
            "Promote the lane to remote_rch or replace the command with a cheap non-cargo metadata check.",
        )
    if cargo and (execution_kind != "remote_rch" or "rch" not in command):
        add_violation(
            unit_id,
            execution_kind,
            "command_template",
            "bare_cargo_command",
            "cargo command is not protected by remote rch proof",
            command,
            "Use RCH_FORCE_REMOTE=true RCH_NO_SELF_HEALING=1 rch --no-self-healing exec -- cargo ...",
        )
    if execution_kind == "remote_rch":
        for required in required_env:
            if required not in command:
                add_violation(
                    unit_id,
                    execution_kind,
                    "command_template",
                    "missing_required_env",
                    f"remote rch lane is missing {required}",
                    command,
                    "Add the required env token before the rch invocation.",
                )
        for required in required_args:
            if required not in command:
                add_violation(
                    unit_id,
                    execution_kind,
                    "command_template",
                    "missing_rch_arg",
                    f"remote rch lane is missing {required}",
                    command,
                    "Use rch --no-self-healing exec -- for validation proof.",
                )
        if "rch" not in command:
            add_violation(
                unit_id,
                execution_kind,
                "command_template",
                "bare_cargo_command",
                "remote_rch lane does not invoke rch",
                command,
                "Use the committed remote rch envelope for proof commands.",
            )


def validate_manifest(manifest, contract):
    remote = contract.get("proof_classes", {}).get("remote_rch", {})
    required_env = remote.get("required_env", [])
    required_args = remote.get("required_rch_args", [])
    if not is_string_array(required_env):
        required_env = []
    if not is_string_array(required_args):
        required_args = []
    units = manifest.get("units")
    if not isinstance(units, list) or not units:
        add_violation(
            "<manifest>",
            "input",
            "units",
            "manifest_units_missing",
            "manifest.units must be a non-empty array",
            "",
            "Restore tests/conformance/high_core_validation_shards.v1.json units.",
        )
        return
    for unit in units:
        if not isinstance(unit, dict):
            continue
        unit_id = unit.get("unit_id")
        if not isinstance(unit_id, str) or not unit_id:
            unit_id = "<missing-unit-id>"
        execution_kind = unit.get("execution_kind")
        if execution_kind not in {"remote_rch", "local_metadata"}:
            add_violation(
                unit_id,
                str(execution_kind),
                "execution_kind",
                "invalid_execution_kind",
                "execution_kind must be remote_rch or local_metadata",
                unit.get("command_template", ""),
                "Classify each lane as remote proof or cheap local metadata.",
            )
            continue
        validate_command(unit_id, execution_kind, unit.get("command_template"), required_env, required_args)


def validate_plan(plan, contract):
    required = contract.get("required_plan_annotations", [])
    if not is_string_array(required):
        required = []
    for lane in plan.get("lanes", []):
        if not isinstance(lane, dict):
            continue
        shard_id = lane.get("shard_id", "<missing-shard>")
        for unit in lane.get("units", []):
            if not isinstance(unit, dict):
                continue
            unit_id = unit.get("unit_id", "<missing-unit>")
            execution_kind = unit.get("execution_kind", "<missing-kind>")
            for field in required:
                if field not in unit:
                    add_violation(
                        unit_id,
                        execution_kind,
                        f"plan.{field}",
                        "missing_plan_annotation",
                        f"{unit_id}/{shard_id} missing plan annotation {field}",
                        unit.get("command_template", ""),
                        "Rerun scripts/plan_high_core_validation_shards.sh after preserving bd-brysl proof annotations.",
                    )
            if execution_kind == "remote_rch" and unit.get("proof_class") != "remote_only_rch_proof":
                add_violation(
                    unit_id,
                    execution_kind,
                    "plan.proof_class",
                    "missing_plan_annotation",
                    f"{unit_id}/{shard_id} must be annotated as remote_only_rch_proof",
                    unit.get("command_template", ""),
                    "Keep remote rch plan rows annotated with proof_class=remote_only_rch_proof.",
                )
            if execution_kind == "local_metadata" and unit.get("proof_class") != "cheap_local_metadata_check":
                add_violation(
                    unit_id,
                    execution_kind,
                    "plan.proof_class",
                    "missing_plan_annotation",
                    f"{unit_id}/{shard_id} must be annotated as cheap_local_metadata_check",
                    unit.get("command_template", ""),
                    "Keep local metadata rows annotated with proof_class=cheap_local_metadata_check.",
                )


def validate_outputs(contract):
    remote = contract.get("proof_classes", {}).get("remote_rch", {})
    forbidden = remote.get("forbidden_output_markers", ["[RCH] local"])
    if not is_string_array(forbidden):
        forbidden = ["[RCH] local"]
    paths = [Path(item) for item in outputs_text.split(os.pathsep) if item]
    for path in paths:
        try:
            body = path.read_text(encoding="utf-8")
        except Exception as exc:
            add_violation(
                "<output>",
                "remote_rch",
                "rch_output",
                "output_unreadable",
                f"{relative_path(path)} could not be read: {exc}",
                "",
                "Point HIGH_CORE_VALIDATION_RCH_OUTPUTS at readable command output artifacts.",
            )
            continue
        for marker in forbidden:
            if marker in body:
                add_violation(
                    "<output>",
                    "remote_rch",
                    "rch_output",
                    "rch_local_fallback",
                    f"{relative_path(path)} contains forbidden output marker {marker}",
                    "",
                    "Discard this proof and rerun with RCH_FORCE_REMOTE=true and --no-self-healing on a remote worker.",
                )


def write_outputs(status):
    report_path.parent.mkdir(parents=True, exist_ok=True)
    events_path.parent.mkdir(parents=True, exist_ok=True)
    signatures = sorted({item["failure_signature"] for item in violations})
    report = {
        "schema_version": "v1",
        "bead": "bd-brysl",
        "status": status,
        "source_manifest": relative_path(manifest_path),
        "source_contract": relative_path(contract_path),
        "source_plan": relative_path(Path(plan_path_text)) if plan_path_text else None,
        "failure_signatures": signatures,
        "summary": {
            "violation_count": len(violations),
            "remote_only_units": remote_only_units,
            "local_metadata_units": local_metadata_units,
        },
        "violations": violations,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    event = {
        "event": "rch_lane_contract_validated" if status == "passed" else "rch_lane_contract_failed",
        "bead": "bd-brysl",
        "status": status,
        "failure_signatures": signatures,
        "violation_count": len(violations),
        "artifact_refs": [relative_path(report_path), relative_path(contract_path), relative_path(manifest_path)],
    }
    events_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")


if mode != "validate-only":
    add_violation(
        "<checker>",
        "input",
        "mode",
        "unknown_mode",
        f"unsupported mode {mode}",
        "",
        "Run with --validate-only.",
    )

manifest = load_json(manifest_path, "manifest_unreadable")
contract = load_json(contract_path, "contract_unreadable")
remote_only_units = 0
local_metadata_units = 0
for unit in manifest.get("units", []) if isinstance(manifest.get("units"), list) else []:
    if isinstance(unit, dict):
        if unit.get("execution_kind") == "remote_rch":
            remote_only_units += 1
        if unit.get("execution_kind") == "local_metadata":
            local_metadata_units += 1

require_contract_policy(contract)
validate_manifest(manifest, contract)

if plan_path_text:
    plan_path = Path(plan_path_text)
    if plan_path.exists():
        validate_plan(load_json(plan_path, "plan_unreadable"), contract)
    else:
        add_violation(
            "<plan>",
            "input",
            "plan",
            "plan_unreadable",
            f"plan path does not exist: {plan_path}",
            "",
            "Generate the plan with scripts/plan_high_core_validation_shards.sh before checking plan annotations.",
        )

validate_outputs(contract)

if violations:
    write_outputs("failed")
    raise SystemExit(1)

write_outputs("passed")
print(
    "high_core_validation_rch_lane_contract: PASS "
    f"remote_only_units={remote_only_units} local_metadata_units={local_metadata_units}"
)
PY
