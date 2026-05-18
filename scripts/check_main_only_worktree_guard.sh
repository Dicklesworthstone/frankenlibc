#!/usr/bin/env bash
# check_main_only_worktree_guard.sh - no-cargo guard for main-only Git policy.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FRANKENLIBC_MAIN_ONLY_WORKTREE_MANIFEST:-${ROOT}/tests/conformance/main_only_worktree_guard.v1.json}"
OUT_DIR="${FRANKENLIBC_MAIN_ONLY_WORKTREE_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_MAIN_ONLY_WORKTREE_REPORT:-${OUT_DIR}/main_only_worktree_guard.report.json}"
LOG="${FRANKENLIBC_MAIN_ONLY_WORKTREE_LOG:-${OUT_DIR}/main_only_worktree_guard.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" "$@" <<'PY'
from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
MANIFEST = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])
LOG = pathlib.Path(sys.argv[4])
ARGS = sys.argv[5:]

EXPECTED_SCHEMA = "main_only_worktree_guard.v1"
REPORT_SCHEMA = "main_only_worktree_guard.report.v1"
EXPECTED_BEAD = "bd-kt64l"
EXPECTED_REPORT = "target/conformance/main_only_worktree_guard.report.json"
EXPECTED_LOG = "target/conformance/main_only_worktree_guard.log.jsonl"
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "manifest",
    "bead",
    "status",
    "source_commit",
    "current_state",
    "negative_controls",
    "errors",
    "generated_at",
    "report_path",
    "log_path",
    "report_contract_fields",
    "contract_status",
    "contract_errors",
}

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
    errors.append(
        {
            "source": source,
            "failure_signature": signature,
            "message": message,
        }
    )


def run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed with exit {result.returncode}: {result.stderr.strip()}"
        )
    return result.stdout


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


def parse_worktree_porcelain(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    row: dict[str, str] = {}
    for line in text.splitlines():
        if not line:
            if row:
                rows.append(row)
                row = {}
            continue
        key, _, value = line.partition(" ")
        row[key] = value
    if row:
        rows.append(row)
    return rows


def collect_state() -> dict[str, Any]:
    current_branch = run_git(["branch", "--show-current"]).strip()
    local_branches = [
        line.strip()
        for line in run_git(["for-each-ref", "--format=%(refname:short)", "refs/heads"]).splitlines()
        if line.strip()
    ]
    worktrees = parse_worktree_porcelain(run_git(["worktree", "list", "--porcelain"]))
    head = run_git(["rev-parse", "HEAD"]).strip()
    remote_refs = {
        "origin/main": run_git(["rev-parse", "--verify", "origin/main"]).strip(),
        "origin/master": run_git(["rev-parse", "--verify", "origin/master"]).strip(),
    }
    return {
        "current_branch": current_branch,
        "local_branches": sorted(local_branches),
        "worktrees": worktrees,
        "head": head,
        "remote_refs": remote_refs,
        "root": str(ROOT),
    }


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


def configured_report_fields(manifest: dict[str, Any]) -> list[str]:
    report_contract = manifest.get("report_contract")
    if not isinstance(report_contract, dict):
        return []
    fields = report_contract.get("must_materialize")
    if not isinstance(fields, list):
        return []
    return [field for field in fields if isinstance(field, str) and field]


def validate_report_contract(manifest: dict[str, Any], source: str) -> None:
    report_contract = manifest.get("report_contract")
    if not isinstance(report_contract, dict):
        add_error(source, "report_contract_missing", "report_contract must be an object")
        return
    if report_contract.get("output_path") != EXPECTED_REPORT:
        add_error(source, "report_contract_output_path_mismatch", f"output_path must be {EXPECTED_REPORT}")
    if report_contract.get("log_path") != EXPECTED_LOG:
        add_error(source, "report_contract_log_path_mismatch", f"log_path must be {EXPECTED_LOG}")
    fields = set(string_list(report_contract.get("must_materialize"), source, "report_contract.must_materialize"))
    missing = sorted(REQUIRED_REPORT_FIELDS - fields)
    if missing:
        add_error(source, "report_contract_missing_required_field", f"must_materialize missing {missing}")


def validate_manifest(manifest: dict[str, Any]) -> None:
    source = rel(MANIFEST)
    if manifest.get("schema_version") != EXPECTED_SCHEMA:
        add_error(source, "schema_version", f"schema_version must be {EXPECTED_SCHEMA}")
    if manifest.get("bead") != EXPECTED_BEAD:
        add_error(source, "wrong_bead", f"bead must be {EXPECTED_BEAD}")

    policy = manifest.get("policy")
    if not isinstance(policy, dict):
        add_error(source, "malformed_manifest", "policy must be an object")
        return
    if policy.get("required_current_branch") != "main":
        add_error(source, "malformed_manifest", "policy.required_current_branch must be main")
    if string_list(policy.get("allowed_local_branches"), source, "policy.allowed_local_branches") != ["main"]:
        add_error(source, "malformed_manifest", "policy.allowed_local_branches must be exactly ['main']")
    if policy.get("expected_worktree_count") != 1:
        add_error(source, "malformed_manifest", "policy.expected_worktree_count must be 1")
    if policy.get("required_worktree_branch") != "refs/heads/main":
        add_error(source, "malformed_manifest", "policy.required_worktree_branch must be refs/heads/main")
    if policy.get("forbid_linked_worktrees") is not True:
        add_error(source, "malformed_manifest", "policy.forbid_linked_worktrees must be true")
    if policy.get("forbid_local_non_main_branches") is not True:
        add_error(source, "malformed_manifest", "policy.forbid_local_non_main_branches must be true")
    if policy.get("required_remote_primary_ref") != "origin/main":
        add_error(source, "malformed_manifest", "policy.required_remote_primary_ref must be origin/main")
    if policy.get("required_legacy_mirror_ref") != "origin/master":
        add_error(source, "malformed_manifest", "policy.required_legacy_mirror_ref must be origin/master")
    if policy.get("require_legacy_mirror_sync") is not True:
        add_error(source, "malformed_manifest", "policy.require_legacy_mirror_sync must be true")
    validate_report_contract(manifest, source)

    commands = string_list(
        manifest.get("required_validation_commands"),
        source,
        "required_validation_commands",
    )
    for command in commands:
        if "cargo " in command or "rch exec" in command:
            add_error(source, "validation_command_not_static", f"command must be no-cargo/static: {command}")

    controls = manifest.get("negative_controls")
    if not isinstance(controls, list) or len(controls) < 4:
        add_error(source, "missing_negative_controls", "negative_controls must include at least four cases")
        return
    seen = set()
    for index, control in enumerate(controls):
        context = f"{source}::negative_controls[{index}]"
        if not isinstance(control, dict):
            add_error(context, "malformed_negative_control", "negative control must be an object")
            continue
        control_id = control.get("id")
        if not isinstance(control_id, str) or not control_id:
            add_error(context, "malformed_negative_control", "negative control requires id")
        elif control_id in seen:
            add_error(context, "duplicate_negative_control", f"duplicate id {control_id}")
        else:
            seen.add(control_id)
        if not isinstance(control.get("mutations"), dict) or not control.get("mutations"):
            add_error(context, "malformed_negative_control", "negative control requires mutations")
        if not isinstance(control.get("expected_failure_signature"), str):
            add_error(context, "malformed_negative_control", "negative control requires expected_failure_signature")


def validate_state(state: dict[str, Any], policy: dict[str, Any], source: str) -> list[dict[str, str]]:
    local_errors: list[dict[str, str]] = []

    def local_error(signature: str, message: str) -> None:
        local_errors.append({"source": source, "failure_signature": signature, "message": message})

    required_branch = policy.get("required_current_branch")
    if state.get("current_branch") != required_branch:
        local_error(
            "current_branch_not_main",
            f"current branch must be {required_branch}, got {state.get('current_branch')!r}",
        )

    allowed_branches = sorted(policy.get("allowed_local_branches", []))
    local_branches = sorted(state.get("local_branches", []))
    for branch in local_branches:
        if branch not in allowed_branches:
            local_error("local_non_main_branch", f"unexpected local branch {branch!r}")
    if local_branches != allowed_branches:
        local_error(
            "local_branch_set_mismatch",
            f"local branches must be exactly {allowed_branches}, got {local_branches}",
        )

    worktrees = state.get("worktrees")
    if not isinstance(worktrees, list):
        local_error("malformed_worktree_state", "worktrees must be a list")
        worktrees = []
    expected_count = policy.get("expected_worktree_count")
    if len(worktrees) != expected_count:
        local_error("worktree_count_mismatch", f"expected {expected_count} worktree, got {len(worktrees)}")
    if policy.get("forbid_linked_worktrees") is True and len(worktrees) > 1:
        local_error("linked_worktree_present", "linked worktrees are forbidden")

    root_seen = False
    required_worktree_branch = policy.get("required_worktree_branch")
    for index, worktree in enumerate(worktrees):
        if not isinstance(worktree, dict):
            local_error("malformed_worktree_state", f"worktree row {index} must be an object")
            continue
        path = worktree.get("worktree")
        if isinstance(path, str):
            try:
                root_seen = root_seen or pathlib.Path(path).resolve() == ROOT
            except Exception:
                pass
        branch = worktree.get("branch")
        if branch != required_worktree_branch:
            local_error(
                "worktree_branch_not_main",
                f"worktree {path!r} must be on {required_worktree_branch}, got {branch!r}",
            )
    if not root_seen:
        local_error("root_worktree_missing", f"root worktree {ROOT} was not present in git worktree list")

    remote_refs = state.get("remote_refs")
    if not isinstance(remote_refs, dict):
        local_error("malformed_remote_ref_state", "remote_refs must be an object")
        remote_refs = {}
    primary_ref = policy.get("required_remote_primary_ref")
    mirror_ref = policy.get("required_legacy_mirror_ref")
    primary_commit = remote_refs.get(primary_ref)
    mirror_commit = remote_refs.get(mirror_ref)
    if not isinstance(primary_commit, str) or not primary_commit:
        local_error("remote_primary_ref_missing", f"{primary_ref!r} must resolve to a commit")
    if not isinstance(mirror_commit, str) or not mirror_commit:
        local_error("legacy_mirror_ref_missing", f"{mirror_ref!r} must resolve to a commit")
    if (
        policy.get("require_legacy_mirror_sync") is True
        and isinstance(primary_commit, str)
        and primary_commit
        and isinstance(mirror_commit, str)
        and mirror_commit
        and primary_commit != mirror_commit
    ):
        local_error(
            "legacy_mirror_not_synced",
            f"{mirror_ref!r} must match {primary_ref!r}: {mirror_commit} != {primary_commit}",
        )

    return local_errors


def apply_mutations(state: dict[str, Any], mutations: dict[str, Any]) -> dict[str, Any]:
    mutated = copy.deepcopy(state)
    for key, value in mutations.items():
        if key == "append_worktree" and isinstance(value, dict):
            row = copy.deepcopy(value)
            if row.get("worktree") == "$ROOT":
                row["worktree"] = str(ROOT)
            mutated.setdefault("worktrees", []).append(row)
        elif key == "worktrees" and isinstance(value, list):
            rows = copy.deepcopy(value)
            for row in rows:
                if isinstance(row, dict) and row.get("worktree") == "$ROOT":
                    row["worktree"] = str(ROOT)
            mutated["worktrees"] = rows
        else:
            mutated[key] = copy.deepcopy(value)
    return mutated


def run_negative_controls(manifest: dict[str, Any], state: dict[str, Any]) -> list[dict[str, Any]]:
    policy = manifest.get("policy", {})
    rows: list[dict[str, Any]] = []
    for control in manifest.get("negative_controls", []):
        if not isinstance(control, dict):
            continue
        control_id = str(control.get("id"))
        expected = str(control.get("expected_failure_signature"))
        mutations = control.get("mutations")
        if not isinstance(mutations, dict):
            continue
        mutated = apply_mutations(state, mutations)
        control_errors = validate_state(mutated, policy, control_id)
        signatures = sorted({row["failure_signature"] for row in control_errors})
        detected = expected in signatures
        row = {
            "event": "main_only_worktree_negative_control",
            "control_id": control_id,
            "expected_failure_signature": expected,
            "observed_failure_signatures": signatures,
            "status": "pass" if detected else "fail",
        }
        rows.append(row)
        if not detected:
            add_error(
                control_id,
                "negative_control_not_detected",
                f"expected {expected}, observed {signatures}",
            )
    return rows


for arg in ARGS:
    if arg != "--validate-only":
        add_error("argv", "unexpected_argument", f"unexpected argument: {arg}")

manifest = load_json(MANIFEST)
validate_manifest(manifest)
policy = manifest.get("policy", {}) if isinstance(manifest.get("policy"), dict) else {}

try:
    state = collect_state()
except Exception as exc:
    state = {"root": str(ROOT)}
    add_error("git", "git_state_unavailable", str(exc))

state_errors = validate_state(state, policy, "current_git_state")
errors.extend(state_errors)

negative_rows = run_negative_controls(manifest, state)
report_contract_fields = configured_report_fields(manifest)
contract_signature_prefixes = ("report_contract_", "missing_report_field")
status = "pass" if not errors else "fail"
events.append(
    {
        "event": "main_only_worktree_guard_validated" if status == "pass" else "main_only_worktree_guard_failed",
        "schema_version": REPORT_SCHEMA,
        "bead": EXPECTED_BEAD,
        "status": status,
        "current_branch": state.get("current_branch"),
        "local_branch_count": len(state.get("local_branches", [])),
        "worktree_count": len(state.get("worktrees", [])),
        "legacy_mirror_synced": state.get("remote_refs", {}).get("origin/main")
        == state.get("remote_refs", {}).get("origin/master"),
        "failure_count": len(errors),
        "timestamp": utc_now(),
    }
)
events.extend(negative_rows)

report = {
    "schema_version": REPORT_SCHEMA,
    "manifest": rel(MANIFEST),
    "bead": EXPECTED_BEAD,
    "status": "pending",
    "source_commit": state.get("head"),
    "current_state": state,
    "negative_controls": negative_rows,
    "errors": errors,
    "generated_at": utc_now(),
    "report_path": rel(REPORT),
    "log_path": rel(LOG),
    "report_contract_fields": report_contract_fields,
    "contract_status": "pending",
    "contract_errors": [],
}
for field in report_contract_fields:
    if field not in report:
        add_error("report_contract", "missing_report_field", f"report omitted required field: {field}")
status = "pass" if not errors else "fail"
contract_errors = [
    row for row in errors if row["failure_signature"].startswith(contract_signature_prefixes)
]
report["status"] = status
report["errors"] = errors
report["contract_status"] = "pass" if not contract_errors else "fail"
report["contract_errors"] = contract_errors

write_json(REPORT, report)
write_jsonl(LOG, events)

if status != "pass":
    print(f"main_only_worktree_guard: FAIL errors={len(errors)} report={rel(REPORT)}", file=sys.stderr)
    for error in errors:
        print(f"{error['failure_signature']}: {error['message']}", file=sys.stderr)
    sys.exit(1)

print(
    "main_only_worktree_guard: pass "
    f"branch={state.get('current_branch')} "
    f"local_branches={len(state.get('local_branches', []))} "
    f"worktrees={len(state.get('worktrees', []))} "
    f"negative_controls={sum(1 for row in negative_rows if row['status'] == 'pass')}"
)
PY
