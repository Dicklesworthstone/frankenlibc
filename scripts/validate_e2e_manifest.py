#!/usr/bin/env python3
"""validate_e2e_manifest.py

Deterministic E2E scenario-manifest validation and lookup helpers.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ALLOWED_CLASSES = {"smoke", "stress", "fault", "stability"}
REQUIRED_ROOT_KEYS = {
    "schema_version",
    "manifest_id",
    "description",
    "replay_defaults",
    "scenarios",
}
REQUIRED_MODE_KEYS = {"strict", "hardened"}
REQUIRED_EXPECTATION_KEYS = {"expected_outcome", "pass_condition", "allowed_exit_codes"}
REQUIRED_ARTIFACT_POLICY_KEYS = {
    "capture_stdout",
    "capture_stderr",
    "capture_env_on_failure",
    "capture_bundle_on_failure",
    "required_artifacts",
}
REQUIRED_REPLAY_KEYS = {"seed_key", "env_keys", "deterministic_inputs"}


class ManifestValidationError(RuntimeError):
    pass


def _load_json(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestValidationError(f"unable to read manifest '{path}': {exc}") from exc
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManifestValidationError(f"manifest is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ManifestValidationError("manifest root must be a JSON object")
    return parsed


def _require_keys(obj: dict[str, Any], required: set[str], context: str) -> list[str]:
    errors: list[str] = []
    missing = sorted(required - set(obj.keys()))
    for key in missing:
        errors.append(f"{context}: missing key '{key}'")
    return errors


def _validate_manifest(doc: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    errors.extend(_require_keys(doc, REQUIRED_ROOT_KEYS, "root"))

    if doc.get("schema_version") != "v1":
        errors.append(
            f"root: unsupported schema_version '{doc.get('schema_version')}', expected 'v1'"
        )

    manifest_id = doc.get("manifest_id", "")
    if not isinstance(manifest_id, str) or not manifest_id.strip():
        errors.append("root: manifest_id must be a non-empty string")

    replay_defaults = doc.get("replay_defaults")
    if not isinstance(replay_defaults, dict):
        errors.append("root: replay_defaults must be an object")
    else:
        errors.extend(_require_keys(replay_defaults, REQUIRED_REPLAY_KEYS, "root.replay_defaults"))

    scenarios = doc.get("scenarios")
    if not isinstance(scenarios, list):
        errors.append("root: scenarios must be an array")
        return errors
    if not scenarios:
        errors.append("root: scenarios must not be empty")
        return errors

    seen_ids: set[str] = set()
    for idx, scenario in enumerate(scenarios):
        ctx = f"scenario[{idx}]"
        if not isinstance(scenario, dict):
            errors.append(f"{ctx}: must be an object")
            continue

        for key in ("id", "class", "label", "priority", "description", "command"):
            if key not in scenario:
                errors.append(f"{ctx}: missing key '{key}'")

        scenario_id = scenario.get("id", "")
        scenario_class = scenario.get("class", "")
        label = scenario.get("label", "")

        if not isinstance(scenario_id, str) or not scenario_id.strip():
            errors.append(f"{ctx}: id must be a non-empty string")
        elif scenario_id in seen_ids:
            errors.append(f"{ctx}: duplicate id '{scenario_id}'")
        else:
            seen_ids.add(scenario_id)

        if scenario_class not in ALLOWED_CLASSES:
            errors.append(
                f"{ctx}: class must be one of {sorted(ALLOWED_CLASSES)}, got '{scenario_class}'"
            )

        if not isinstance(label, str) or not label.strip():
            errors.append(f"{ctx}: label must be a non-empty string")

        if (
            isinstance(scenario_id, str)
            and scenario_id
            and isinstance(scenario_class, str)
            and isinstance(label, str)
        ):
            expected_id = f"{scenario_class}.{label}"
            if scenario_id != expected_id:
                errors.append(f"{ctx}: id '{scenario_id}' must equal '{expected_id}'")

        priority = scenario.get("priority")
        if not isinstance(priority, int) or priority < 0:
            errors.append(f"{ctx}: priority must be a non-negative integer")

        description = scenario.get("description")
        if not isinstance(description, str) or not description.strip():
            errors.append(f"{ctx}: description must be a non-empty string")

        command = scenario.get("command")
        if not isinstance(command, list) or not command:
            errors.append(f"{ctx}: command must be a non-empty array")
        else:
            for arg_i, arg in enumerate(command):
                if not isinstance(arg, str):
                    errors.append(f"{ctx}.command[{arg_i}]: must be a string")
                elif arg_i == 0 and not arg:
                    errors.append(f"{ctx}.command[0]: executable token must be non-empty")

        mode_expectations = scenario.get("mode_expectations")
        if not isinstance(mode_expectations, dict):
            errors.append(f"{ctx}: mode_expectations must be an object")
        else:
            missing_modes = REQUIRED_MODE_KEYS - set(mode_expectations.keys())
            for mode in sorted(missing_modes):
                errors.append(f"{ctx}: mode_expectations missing '{mode}'")
            for mode in sorted(REQUIRED_MODE_KEYS):
                expectation = mode_expectations.get(mode)
                mctx = f"{ctx}.mode_expectations.{mode}"
                if not isinstance(expectation, dict):
                    errors.append(f"{mctx}: must be an object")
                    continue
                errors.extend(_require_keys(expectation, REQUIRED_EXPECTATION_KEYS, mctx))
                expected_outcome = expectation.get("expected_outcome")
                if not isinstance(expected_outcome, str) or not expected_outcome.strip():
                    errors.append(f"{mctx}.expected_outcome: must be a non-empty string")
                pass_condition = expectation.get("pass_condition")
                if not isinstance(pass_condition, str) or not pass_condition.strip():
                    errors.append(f"{mctx}.pass_condition: must be a non-empty string")
                allowed_exit_codes = expectation.get("allowed_exit_codes")
                if not isinstance(allowed_exit_codes, list) or not allowed_exit_codes:
                    errors.append(f"{mctx}.allowed_exit_codes: must be a non-empty array")
                else:
                    for code_i, code in enumerate(allowed_exit_codes):
                        if not isinstance(code, int):
                            errors.append(f"{mctx}.allowed_exit_codes[{code_i}]: must be an integer")

        artifact_policy = scenario.get("artifact_policy")
        if not isinstance(artifact_policy, dict):
            errors.append(f"{ctx}: artifact_policy must be an object")
        else:
            errors.extend(_require_keys(artifact_policy, REQUIRED_ARTIFACT_POLICY_KEYS, f"{ctx}.artifact_policy"))
            req = artifact_policy.get("required_artifacts")
            if not isinstance(req, list) or not req:
                errors.append(f"{ctx}.artifact_policy.required_artifacts: must be a non-empty array")
            else:
                for art_i, artifact in enumerate(req):
                    if not isinstance(artifact, str) or not artifact.strip():
                        errors.append(
                            f"{ctx}.artifact_policy.required_artifacts[{art_i}]: must be a non-empty string"
                        )

        replay = scenario.get("replay")
        if not isinstance(replay, dict):
            errors.append(f"{ctx}: replay must be an object")
        else:
            errors.extend(_require_keys(replay, REQUIRED_REPLAY_KEYS, f"{ctx}.replay"))
            seed_key = replay.get("seed_key")
            if not isinstance(seed_key, str) or not seed_key.strip():
                errors.append(f"{ctx}.replay.seed_key: must be a non-empty string")
            env_keys = replay.get("env_keys")
            if not isinstance(env_keys, list) or not env_keys:
                errors.append(f"{ctx}.replay.env_keys: must be a non-empty array")
            else:
                for env_i, env_key in enumerate(env_keys):
                    if not isinstance(env_key, str) or not env_key.strip():
                        errors.append(f"{ctx}.replay.env_keys[{env_i}]: must be a non-empty string")
            deterministic_inputs = replay.get("deterministic_inputs")
            if not isinstance(deterministic_inputs, str) or not deterministic_inputs.strip():
                errors.append(f"{ctx}.replay.deterministic_inputs: must be a non-empty string")

    return errors


def _normalize_label(label: str) -> str:
    return re.sub(r"_[0-9]+$", "", label)


def _scenario_index(doc: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for scenario in doc["scenarios"]:
        scenario_class = scenario["class"]
        label = scenario["label"]
        index[(scenario_class, label)] = scenario
    return index


def _metadata(doc: dict[str, Any], scenario_class: str, label: str, mode: str) -> tuple[str, str, str, str]:
    index = _scenario_index(doc)
    scenario = index.get((scenario_class, label))
    if scenario is None:
        scenario = index.get((scenario_class, _normalize_label(label)))
    if scenario is None:
        raise ManifestValidationError(
            f"no scenario metadata found for class='{scenario_class}' label='{label}'"
        )
    expectation = scenario["mode_expectations"].get(mode)
    if expectation is None:
        raise ManifestValidationError(
            f"scenario '{scenario['id']}' missing mode expectation for '{mode}'"
        )
    artifact_policy_json = json.dumps(scenario["artifact_policy"], separators=(",", ":"))
    return (
        scenario["id"],
        expectation["expected_outcome"],
        expectation["pass_condition"],
        artifact_policy_json,
    )


def _cmd_validate(manifest: Path) -> int:
    doc = _load_json(manifest)
    errors = _validate_manifest(doc)
    if errors:
        for err in errors:
            print(f"MANIFEST_ERROR: {err}", file=sys.stderr)
        return 1
    print(f"manifest_ok\t{manifest}")
    return 0


def _cmd_list(manifest: Path, scenario_class: str) -> int:
    doc = _load_json(manifest)
    errors = _validate_manifest(doc)
    if errors:
        for err in errors:
            print(f"MANIFEST_ERROR: {err}", file=sys.stderr)
        return 1

    for scenario in doc["scenarios"]:
        if scenario_class != "all" and scenario["class"] != scenario_class:
            continue
        print(f"{scenario['class']}\t{scenario['label']}")
    return 0


def _cmd_metadata(manifest: Path, scenario_class: str, label: str, mode: str) -> int:
    doc = _load_json(manifest)
    errors = _validate_manifest(doc)
    if errors:
        for err in errors:
            print(f"MANIFEST_ERROR: {err}", file=sys.stderr)
        return 1
    try:
        scenario_id, expected_outcome, pass_condition, artifact_policy_json = _metadata(
            doc, scenario_class, label, mode
        )
    except ManifestValidationError as exc:
        print(f"MANIFEST_ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        "\t".join(
            [scenario_id, expected_outcome, pass_condition, artifact_policy_json]
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and query FrankenLibC E2E manifests")
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="Validate manifest schema + invariants")
    p_validate.add_argument("--manifest", required=True, type=Path)

    p_list = sub.add_parser("list", help="List scenario-class/label pairs")
    p_list.add_argument("--manifest", required=True, type=Path)
    p_list.add_argument(
        "--scenario-class",
        default="all",
        choices=["all", "smoke", "stress", "fault", "stability"],
    )

    p_meta = sub.add_parser("metadata", help="Lookup metadata for one scenario+mode")
    p_meta.add_argument("--manifest", required=True, type=Path)
    p_meta.add_argument(
        "--scenario-class",
        required=True,
        choices=["smoke", "stress", "fault", "stability"],
    )
    p_meta.add_argument("--label", required=True)
    p_meta.add_argument("--mode", required=True, choices=["strict", "hardened"])

    args = parser.parse_args(argv)

    if args.command == "validate":
        return _cmd_validate(args.manifest)
    if args.command == "list":
        return _cmd_list(args.manifest, args.scenario_class)
    if args.command == "metadata":
        return _cmd_metadata(args.manifest, args.scenario_class, args.label, args.mode)

    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
