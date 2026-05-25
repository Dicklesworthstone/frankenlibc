#!/usr/bin/env bash
# plan_change_surface_validation.sh -- emit validation_manifest.v1 for changed paths.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_MANIFEST="${FRANKENLIBC_CHANGE_SURFACE_PLANNER_MANIFEST:-${ROOT}/tests/conformance/change_surface_validation_planner.v1.json}"
DEFAULT_OUTPUT="${FRANKENLIBC_CHANGE_SURFACE_VALIDATION_OUTPUT:-${ROOT}/target/conformance/change_surface_validation/validation_manifest.json}"
DEFAULT_LOG="${FRANKENLIBC_CHANGE_SURFACE_VALIDATION_LOG:-${ROOT}/target/conformance/change_surface_validation/events.log.jsonl}"

cd "${ROOT}"

python3 - "${ROOT}" "${DEFAULT_MANIFEST}" "${DEFAULT_OUTPUT}" "${DEFAULT_LOG}" "$@" <<'PY'
from __future__ import annotations

import argparse
import json
import pathlib
import shlex
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
DEFAULT_MANIFEST = pathlib.Path(sys.argv[2])
DEFAULT_OUTPUT = pathlib.Path(sys.argv[3])
DEFAULT_LOG = pathlib.Path(sys.argv[4])
ARGV = sys.argv[5:]

OUTPUT_SCHEMA = "validation_manifest.v1"
PLANNER_SCHEMA = "change_surface_validation_planner.v1"
DEFAULT_BEAD = "bd-zaijr5"
CARGO_SUBCOMMANDS = ("build", "check", "clippy", "test")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plan scoped FrankenLibC validation commands for changed paths.",
    )
    parser.add_argument("paths", nargs="*", help="Repo-relative changed paths to classify")
    parser.add_argument("--bead", default=DEFAULT_BEAD, help="Bead id for the manifest")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="Planner contract JSON")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="validation_manifest.v1 output")
    parser.add_argument("--log", default=str(DEFAULT_LOG), help="JSONL event log output")
    parser.add_argument("--paths-from", action="append", default=[], help="Read changed paths from a file")
    parser.add_argument("--proof-log", action="append", default=[], help="Scan proof logs for forbidden local fallback markers")
    return parser.parse_args(ARGV)


args = parse_args()
manifest_path = pathlib.Path(args.manifest)
output_path = pathlib.Path(args.output)
log_path = pathlib.Path(args.log)
errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    value = pathlib.Path(path)
    try:
        return value.resolve().relative_to(ROOT).as_posix()
    except Exception:
        return str(path)


def add_error(source: str, signature: str, message: str) -> None:
    errors.append({"source": source, "failure_signature": signature, "message": message})


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(rel(path), "malformed_manifest", f"cannot parse JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        add_error(rel(path), "malformed_manifest", "manifest must be a JSON object")
        return {}
    return value


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str) and item]
    return []


def read_paths_from_file(path: pathlib.Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        add_error(rel(path), "paths_from_unreadable", str(exc))
        return []
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def staged_paths() -> list[str]:
    proc = subprocess.run(
        ["git", "diff", "--name-only", "--cached"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def normalize_path(path: str) -> str | None:
    candidate = path.strip().replace("\\", "/")
    while candidate.startswith("./"):
        candidate = candidate[2:]
    if not candidate:
        return None
    pure = pathlib.PurePosixPath(candidate)
    if pure.is_absolute() or ".." in pure.parts:
        add_error(candidate, "invalid_changed_path", "changed paths must be repo-relative and may not contain '..'")
        return None
    return pure.as_posix()


def classify_path(path: str) -> dict[str, Any]:
    parts = path.split("/")
    name = parts[-1]
    suffix = pathlib.PurePosixPath(path).suffix
    result: dict[str, Any] = {
        "path": path,
        "category": "other",
        "subcategory": "",
        "affected_crate": "",
        "requires_cargo": False,
        "proof_classes": [],
    }
    if path == ".beads/issues.jsonl" or path.startswith(".beads/"):
        result.update({"category": "tracker", "subcategory": "beads_jsonl"})
    elif len(parts) >= 3 and parts[0] == "crates":
        crate = parts[1]
        category = "rust_crate_test" if len(parts) >= 4 and parts[2] == "tests" and suffix == ".rs" else "rust_crate_code"
        result.update(
            {
                "category": category,
                "subcategory": "rust",
                "affected_crate": crate,
                "requires_cargo": suffix == ".rs",
            }
        )
        if category == "rust_crate_test" and suffix == ".rs":
            result["test_target"] = pathlib.PurePosixPath(name).stem
    elif path.startswith("scripts/"):
        result.update({"category": "script", "subcategory": "shell" if suffix == ".sh" else "script"})
    elif path.startswith("tests/conformance/") and suffix == ".json":
        contract_markers = ("contract", "policy", "checklist", "planner")
        category = "contract" if any(marker in name for marker in contract_markers) else "conformance_json"
        result.update({"category": category, "subcategory": "json_artifact"})
    elif suffix in {".md", ".rst", ".txt"} or path.startswith("docs/"):
        result.update({"category": "docs", "subcategory": "text"})
    return result


def command_shell_join(items: list[str]) -> str:
    return " ".join(shlex.quote(item) for item in items)


def bead_slug(bead: str) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in bead.lower()).strip("-") or "unassigned"


def target_dir(bead: str, lane: str) -> str:
    clean_lane = "".join(ch if ch.isalnum() else "-" for ch in lane.lower()).strip("-")
    return f"/data/tmp/frankenlibc-{bead_slug(bead)}-{clean_lane}"


def remote_cargo_command(bead: str, lane: str, cargo_args: list[str]) -> tuple[str, str]:
    target = target_dir(bead, lane)
    command = (
        "RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary "
        f"rch exec -- env CARGO_TARGET_DIR={target} cargo {command_shell_join(cargo_args)}"
    )
    return command, target


def add_command(
    commands: dict[tuple[str, str], dict[str, Any]],
    *,
    command_id: str,
    command: str,
    reason: str,
    expected_scope: str,
    proof_class: str,
    source_paths: list[str],
    requires_rch_remote: bool = False,
    target: str = "",
    artifact_refs: list[str] | None = None,
) -> None:
    key = (proof_class, command)
    if key in commands:
        merged = sorted(set(commands[key]["source_paths"]) | set(source_paths))
        commands[key]["source_paths"] = merged
        return
    forbidden = proof_policy.get("forbidden_output_markers", [])
    commands[key] = {
        "command_id": command_id,
        "command": command,
        "reason": reason,
        "expected_scope": expected_scope,
        "proof_class": proof_class,
        "source_paths": sorted(source_paths),
        "requires_rch_remote": requires_rch_remote,
        "target_dir": target,
        "target_dir_isolation_guidance": (
            "Use a bead- and lane-specific CARGO_TARGET_DIR outside shared target state for every rch cargo command."
            if requires_rch_remote
            else "No cargo target directory is required for this local static check."
        ),
        "reject_local_fallback": bool(requires_rch_remote),
        "forbidden_output_markers": forbidden if requires_rch_remote else [],
        "artifact_refs": artifact_refs or [],
    }


def add_harness_test_lanes(commands: dict[tuple[str, str], dict[str, Any]], bead: str, test_name: str, source_paths: list[str], reason: str) -> None:
    lanes = [
        (
            "remote_rch_cargo_test",
            f"{test_name}-test",
            ["test", "-p", "frankenlibc-harness", "--test", test_name, "--", "--nocapture"],
            "focused harness test",
        ),
        (
            "remote_rch_cargo_check",
            f"{test_name}-check",
            ["check", "-p", "frankenlibc-harness", "--test", test_name],
            "focused harness compile check",
        ),
        (
            "remote_rch_cargo_clippy",
            f"{test_name}-clippy",
            ["clippy", "-p", "frankenlibc-harness", "--test", test_name, "--", "-D", "warnings"],
            "focused harness clippy lint",
        ),
    ]
    for proof_class, lane, cargo_args, scope in lanes:
        command, target = remote_cargo_command(bead, lane, cargo_args)
        add_command(
            commands,
            command_id=f"{proof_class}:{lane}",
            command=command,
            reason=reason,
            expected_scope=scope,
            proof_class=proof_class,
            source_paths=source_paths,
            requires_rch_remote=True,
            target=target,
            artifact_refs=source_paths,
        )


def add_crate_lanes(commands: dict[tuple[str, str], dict[str, Any]], bead: str, classification: dict[str, Any]) -> None:
    crate = classification["affected_crate"]
    path = classification["path"]
    test_target = classification.get("test_target")
    if test_target:
        lanes = [
            ("remote_rch_cargo_test", f"{crate}-{test_target}-test", ["test", "-p", crate, "--test", test_target, "--", "--nocapture"], "focused crate integration test"),
            ("remote_rch_cargo_check", f"{crate}-{test_target}-check", ["check", "-p", crate, "--test", test_target], "focused crate integration check"),
            ("remote_rch_cargo_clippy", f"{crate}-{test_target}-clippy", ["clippy", "-p", crate, "--test", test_target, "--", "-D", "warnings"], "focused crate integration clippy"),
        ]
    else:
        lanes = [
            ("remote_rch_cargo_check", f"{crate}-check", ["check", "-p", crate, "--all-targets"], "crate compile check"),
            ("remote_rch_cargo_test", f"{crate}-test", ["test", "-p", crate], "crate test suite"),
            ("remote_rch_cargo_clippy", f"{crate}-clippy", ["clippy", "-p", crate, "--all-targets", "--", "-D", "warnings"], "crate clippy lint"),
        ]
    for proof_class, lane, cargo_args, scope in lanes:
        command, target = remote_cargo_command(bead, lane, cargo_args)
        add_command(
            commands,
            command_id=f"{proof_class}:{lane}",
            command=command,
            reason=f"{path} changes Rust behavior in package {crate}",
            expected_scope=scope,
            proof_class=proof_class,
            source_paths=[path],
            requires_rch_remote=True,
            target=target,
            artifact_refs=[path],
        )


def validate_cargo_command(command: str, source: str) -> None:
    cargo_token = any(f"cargo {subcommand}" in command for subcommand in CARGO_SUBCOMMANDS)
    if not cargo_token:
        return
    stripped = command.strip()
    if stripped.startswith("cargo "):
        add_error(source, "bare_local_cargo_proof", "cargo validation commands must not be local")
    if "RCH_REQUIRE_REMOTE=1" not in command:
        add_error(source, "missing_remote_env", "cargo proof must require RCH_REQUIRE_REMOTE=1")
    if "rch exec -- env" not in command:
        add_error(source, "missing_rch_exec_env", "cargo proof must use rch exec -- env")
    if "CARGO_TARGET_DIR=" not in command:
        add_error(source, "missing_isolated_target_dir", "cargo proof must set CARGO_TARGET_DIR")


manifest = load_json(manifest_path)
if manifest.get("schema_version") != PLANNER_SCHEMA:
    add_error(rel(manifest_path), "manifest_schema_mismatch", f"schema_version must be {PLANNER_SCHEMA}")
if manifest.get("bead") != DEFAULT_BEAD:
    add_error(rel(manifest_path), "manifest_bead_mismatch", f"bead must be {DEFAULT_BEAD}")
proof_policy = manifest.get("proof_policy") if isinstance(manifest.get("proof_policy"), dict) else {}
script_test_mappings = manifest.get("script_test_mappings") if isinstance(manifest.get("script_test_mappings"), dict) else {}
artifact_test_mappings = manifest.get("artifact_test_mappings") if isinstance(manifest.get("artifact_test_mappings"), dict) else {}

raw_paths = list(args.paths)
for path_text in args.paths_from:
    raw_paths.extend(read_paths_from_file(pathlib.Path(path_text)))
if not raw_paths:
    raw_paths = staged_paths()

changed_paths: list[str] = []
for raw_path in raw_paths:
    normalized = normalize_path(raw_path)
    if normalized is not None and normalized not in changed_paths:
        changed_paths.append(normalized)

if not changed_paths:
    add_error("paths", "no_changed_paths", "provide paths, --paths-from, or staged changes")

classifications = [classify_path(path) for path in changed_paths]
commands: dict[tuple[str, str], dict[str, Any]] = {}

quoted_all_paths = command_shell_join(changed_paths) if changed_paths else ""
if changed_paths:
    add_command(
        commands,
        command_id="static-diff-check",
        command=f"git diff --check -- {quoted_all_paths}",
        reason="Whitespace/conflict-marker scan for all changed paths.",
        expected_scope="all changed paths",
        proof_class="static_diff_check",
        source_paths=changed_paths,
        artifact_refs=changed_paths,
    )

for item in classifications:
    path = item["path"]
    category = item["category"]
    quoted_path = shlex.quote(path)
    if category == "tracker":
        add_command(
            commands,
            command_id="tracker-jsonl-parse",
            command="python3 -c 'import json,pathlib; [json.loads(line) for line in pathlib.Path(\".beads/issues.jsonl\").read_text(encoding=\"utf-8\").splitlines() if line.strip()]'",
            reason="Tracker edits must preserve JSONL parseability.",
            expected_scope="beads tracker JSONL",
            proof_class="tracker_jsonl_parse",
            source_paths=[path],
            artifact_refs=[path],
        )
        add_command(
            commands,
            command_id="tracker-graph-cycles",
            command="br dep cycles --json",
            reason="Tracker edits must not introduce dependency cycles.",
            expected_scope="beads dependency graph",
            proof_class="tracker_graph_health",
            source_paths=[path],
            artifact_refs=[path],
        )
        add_command(
            commands,
            command_id="tracker-lint",
            command="br lint --json",
            reason="Tracker edits must preserve bead metadata contract health.",
            expected_scope="open bead metadata",
            proof_class="tracker_graph_health",
            source_paths=[path],
            artifact_refs=[path],
        )
    elif category in {"rust_crate_code", "rust_crate_test"} and item.get("requires_cargo"):
        add_crate_lanes(commands, args.bead, item)
    elif category == "script":
        add_command(
            commands,
            command_id=f"shell-syntax:{path}",
            command=f"bash -n {quoted_path}",
            reason=f"{path} is an executable shell/script validation surface.",
            expected_scope="script syntax",
            proof_class="static_shell_syntax",
            source_paths=[path],
            artifact_refs=[path],
        )
        mapped_test = script_test_mappings.get(path)
        if isinstance(mapped_test, str) and mapped_test:
            item["affected_crate"] = "frankenlibc-harness"
            item["requires_cargo"] = True
            add_harness_test_lanes(commands, args.bead, mapped_test, [path], f"{path} is covered by harness test {mapped_test}.")
    elif category in {"contract", "conformance_json"}:
        add_command(
            commands,
            command_id=f"json-parse:{path}",
            command=f"python3 -m json.tool {quoted_path} >/dev/null",
            reason=f"{path} is a conformance JSON artifact.",
            expected_scope="JSON artifact parse",
            proof_class="static_json_parse",
            source_paths=[path],
            artifact_refs=[path],
        )
        mapped_test = artifact_test_mappings.get(path)
        if isinstance(mapped_test, str) and mapped_test:
            item["affected_crate"] = "frankenlibc-harness"
            item["requires_cargo"] = True
            add_harness_test_lanes(commands, args.bead, mapped_test, [path], f"{path} is covered by harness test {mapped_test}.")
    elif category == "docs":
        item["proof_classes"].append("static_diff_check")

for command in commands.values():
    validate_cargo_command(command["command"], command["command_id"])

for proof_log in args.proof_log:
    path = pathlib.Path(proof_log)
    try:
        body = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        add_error(rel(path), "proof_log_unreadable", str(exc))
        continue
    for marker in string_list(proof_policy.get("forbidden_output_markers")):
        if marker and marker in body:
            add_error(rel(path), "local_fallback_marker", f"proof log contains forbidden marker: {marker}")
            events.append(
                {
                    "event": "proof_log_rejected",
                    "bead_id": args.bead,
                    "proof_log": rel(path),
                    "failure_signature": "local_fallback_marker",
                    "marker": marker,
                }
            )

command_list = sorted(commands.values(), key=lambda item: (item["proof_class"], item["command_id"], item["command"]))
command_proof_classes = sorted({command["proof_class"] for command in command_list})
for item in classifications:
    item["proof_classes"] = sorted(
        {
            command["proof_class"]
            for command in command_list
            if item["path"] in command["source_paths"]
        }
    )

categories = sorted({item["category"] for item in classifications})
crates = sorted({item["affected_crate"] for item in classifications if item.get("affected_crate")})
cargo_required = any(command["requires_rch_remote"] for command in command_list)
mixed = len(categories) > 1
tracker_only = bool(classifications) and all(item["category"] == "tracker" for item in classifications)
status = "fail" if errors else "pass"

for item in classifications:
    events.append(
        {
            "event": "path_classified",
            "bead_id": args.bead,
            "path": item["path"],
            "category": item["category"],
            "affected_crate": item.get("affected_crate", ""),
            "requires_cargo": item.get("requires_cargo", False),
            "proof_classes": item["proof_classes"],
        }
    )

for command in command_list:
    events.append(
        {
            "event": "command_planned",
            "bead_id": args.bead,
            "command_id": command["command_id"],
            "proof_class": command["proof_class"],
            "requires_rch_remote": command["requires_rch_remote"],
            "source_paths": command["source_paths"],
            "target_dir": command["target_dir"],
        }
    )

events.append(
    {
        "event": "planner_summary",
        "bead_id": args.bead,
        "status": status,
        "changed_path_count": len(changed_paths),
        "command_count": len(command_list),
        "categories": categories,
        "crates": crates,
        "mixed": mixed,
        "tracker_only": tracker_only,
        "cargo_required": cargo_required,
        "failure_signatures": sorted({error["failure_signature"] for error in errors}),
    }
)

report = {
    "schema_version": OUTPUT_SCHEMA,
    "planner_schema_version": PLANNER_SCHEMA,
    "bead_id": args.bead,
    "status": status,
    "generated_at_utc": utc_now(),
    "source_manifest": rel(manifest_path),
    "changed_paths": changed_paths,
    "classifications": classifications,
    "surface_summary": {
        "category_count": len(categories),
        "categories": categories,
        "crates": crates,
        "mixed": mixed,
        "tracker_only": tracker_only,
        "cargo_required": cargo_required,
        "command_count": len(command_list),
        "commands_by_proof_class": {
            proof_class: sum(1 for command in command_list if command["proof_class"] == proof_class)
            for proof_class in command_proof_classes
        },
    },
    "rch_policy": {
        "cargo_requires_rch": bool(proof_policy.get("cargo_requires_rch", True)),
        "required_remote_env": string_list(proof_policy.get("required_remote_env")) or ["RCH_REQUIRE_REMOTE=1"],
        "required_launcher": proof_policy.get("required_launcher", "rch exec -- env"),
        "required_target_dir_env": proof_policy.get("required_target_dir_env", "CARGO_TARGET_DIR="),
        "target_dir_template": proof_policy.get("target_dir_template", "/data/tmp/frankenlibc-{bead_slug}-{lane}"),
        "local_fallback_invalid": bool(proof_policy.get("local_fallback_invalid", True)),
        "forbidden_output_markers": string_list(proof_policy.get("forbidden_output_markers")),
    },
    "commands": command_list,
    "artifact_refs": [rel(output_path), rel(log_path), rel(manifest_path)],
    "agent_mail_handoff": {
        "subject": f"[{args.bead}] validation_manifest.v1",
        "body_md": f"Generated validation_manifest.v1 for {len(changed_paths)} changed path(s); status={status}; commands={len(command_list)}.",
    },
    "close_reason_snippet": (
        f"validation_manifest.v1 status={status}; paths={len(changed_paths)}; "
        f"categories={','.join(categories) if categories else 'none'}; "
        f"rch_remote_required={'yes' if cargo_required else 'no'}; "
        f"commands={len(command_list)}; artifact={rel(output_path)}"
    ),
    "errors": errors,
    "failure_signatures": sorted({error["failure_signature"] for error in errors}),
}

write_json(output_path, report)
write_jsonl(log_path, events)

if errors:
    print(f"FAIL: change-surface validation planner found {len(errors)} error(s)", file=sys.stderr)
    for error in errors:
        print(f"- {error['failure_signature']}: {error['source']}: {error['message']}", file=sys.stderr)
    raise SystemExit(1)

print(f"OK: wrote validation_manifest.v1 for {len(changed_paths)} changed path(s)")
print(f"Manifest: {output_path}")
print(f"Log: {log_path}")
PY
