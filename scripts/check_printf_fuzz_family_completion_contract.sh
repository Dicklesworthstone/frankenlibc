#!/usr/bin/env bash
# check_printf_fuzz_family_completion_contract.sh -- fail-closed gate for bd-1oz.3.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_PRINTF_FUZZ_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/printf_fuzz_family_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_PRINTF_FUZZ_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_PRINTF_FUZZ_COMPLETION_REPORT:-${OUT_DIR}/printf_fuzz_family_completion_contract.report.json}"
LOG="${FRANKENLIBC_PRINTF_FUZZ_COMPLETION_LOG:-${OUT_DIR}/printf_fuzz_family_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import shlex
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

BEAD_ID = "bd-1oz.3"
COMPLETION_BEAD_ID = "bd-1oz.3.1"
MANIFEST_ID = "printf-fuzz-family-completion-contract"
REQUIRED_TARGETS = ["fuzz_printf", "fuzz_printf_adversarial", "fuzz_asprintf"]
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def load_json(path: Path, errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"contract unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append("contract must be a JSON object")
        return {}
    return value


def read_text(path_text: str, errors: list[str], context: str) -> str:
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} missing file: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{context} unreadable: {path_text}: {exc}")
        return ""


def require_strings(value: Any, errors: list[str], context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{context} must be a non-empty array")
        return []
    strings: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{context}[{index}] must be a non-empty string")
        else:
            strings.append(item)
    return strings


def command_contract_failures(command: str) -> list[str]:
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        return [f"command is not shell-tokenizable: {command}: {exc}"]
    if "cargo" not in tokens:
        return []
    failures: list[str] = []
    cargo_index = tokens.index("cargo")
    try:
        rch_index = tokens.index("rch")
    except ValueError:
        failures.append(f"cargo command must run through rch exec: {command}")
        return failures
    if rch_index > cargo_index:
        failures.append(f"rch must appear before cargo: {command}")
        return failures
    if "RCH_REQUIRE_REMOTE=1" not in tokens[:rch_index]:
        failures.append(f"cargo command must set RCH_REQUIRE_REMOTE=1 before rch: {command}")
    if tokens[rch_index + 1 : rch_index + 3] != ["exec", "--"]:
        failures.append(f"cargo command must use 'rch exec --': {command}")
    payload = tokens[rch_index + 3 : cargo_index]
    if not payload or payload[0] != "env":
        failures.append(f"cargo command must place env assignments inside rch payload: {command}")
    if not any(token.startswith("CARGO_TARGET_DIR=") for token in payload[1:]):
        failures.append(f"cargo command must set CARGO_TARGET_DIR inside rch env payload: {command}")
    return failures


def validate_runtime_target(
    contract: dict[str, Any],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    runtime_target = contract.get("runtime_target")
    if not isinstance(runtime_target, dict):
        errors.append("runtime_target must be an object")
        return
    commands = require_strings(
        runtime_target.get("allowed_command_prefixes"),
        errors,
        "runtime_target.allowed_command_prefixes",
    )
    cargo_command_count = 0
    for command in commands:
        failures = command_contract_failures(command)
        if failures:
            errors.extend(f"runtime target command contract failed: {failure}" for failure in failures)
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = []
        if "cargo" in tokens:
            cargo_command_count += 1
    if cargo_command_count != 2:
        errors.append(f"runtime_target must bind exactly 2 cargo proof commands, got {cargo_command_count}")
    rows.append({
        "event": "printf_fuzz_family.runtime_target",
        "cargo_command_count": cargo_command_count,
        "status": "pass" if cargo_command_count == 2 else "fail",
        "timestamp": utc_now(),
    })


def validate_line_ref(ref: Any, errors: list[str], context: str) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"{context} must be a file:line string")
        return
    path_text, line_text = ref.rsplit(":", 1)
    if not line_text.isdigit() or int(line_text) <= 0:
        errors.append(f"{context} has invalid line number: {ref}")
        return
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        errors.append(f"{context} references line past EOF: {ref}")
    elif not lines[line_number - 1].strip():
        errors.append(f"{context} references blank line: {ref}")


def validate_source_artifacts(
    contract: dict[str, Any],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    artifacts = contract.get("source_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("source_artifacts must be a non-empty array")
        return
    seen: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("source_artifacts entries must be objects")
            continue
        artifact_id = artifact.get("artifact_id")
        path_text = artifact.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            errors.append("source artifact missing artifact_id")
            continue
        if artifact_id in seen:
            errors.append(f"duplicate source artifact {artifact_id}")
        seen.add(artifact_id)
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"{artifact_id}.path missing")
            continue
        text = read_text(path_text, errors, artifact_id)
        for needle in require_strings(
            artifact.get("required_needles"),
            errors,
            f"{artifact_id}.required_needles",
        ):
            if needle not in text:
                errors.append(f"{artifact_id} missing needle {needle!r}")
        for ref in artifact.get("required_line_refs", []):
            validate_line_ref(ref, errors, f"{artifact_id}.required_line_refs")
        rows.append({
            "event": "printf_fuzz_family.source_artifact",
            "artifact_id": artifact_id,
            "path": path_text,
            "status": "pass" if text else "fail",
            "timestamp": utc_now(),
        })
    required = {
        "fuzz_cargo_manifest",
        "fuzz_printf_target",
        "fuzz_printf_adversarial_target",
        "fuzz_asprintf_target",
        "nightly_runner",
        "completion_checker",
        "completion_harness_test",
    }
    if seen != required:
        errors.append(f"source_artifacts must be exactly {sorted(required)}, got {sorted(seen)}")


def load_fuzz_bins(errors: list[str]) -> dict[str, str]:
    manifest = root / "crates/frankenlibc-fuzz/Cargo.toml"
    try:
        parsed = tomllib.loads(manifest.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"failed to parse fuzz Cargo.toml: {exc}")
        return {}
    bins: dict[str, str] = {}
    for entry in parsed.get("bin", []):
        name = entry.get("name")
        path = entry.get("path")
        if isinstance(name, str) and isinstance(path, str):
            bins[name] = path
    return bins


def validate_runner_targets(
    expected_targets: list[str],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    command = ["bash", "scripts/fuzz_nightly.sh", "--target-group", "printf-family", "--list-targets"]
    try:
        output = subprocess.run(
            command,
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except Exception as exc:
        errors.append(f"nightly runner list command failed to start: {exc}")
        return
    actual = [line.strip() for line in output.stdout.splitlines() if line.strip()]
    if output.returncode != 0:
        errors.append(
            "nightly runner list command failed: "
            f"rc={output.returncode} stderr={output.stderr.strip()}"
        )
    if actual != expected_targets:
        errors.append(f"printf-family runner target list drifted: expected {expected_targets}, got {actual}")
    rows.append({
        "event": "printf_fuzz_family.e2e_runner_list",
        "command": " ".join(command),
        "expected_targets": expected_targets,
        "actual_targets": actual,
        "status": "pass" if actual == expected_targets and output.returncode == 0 else "fail",
        "timestamp": utc_now(),
    })


def validate_target_contracts(
    contract: dict[str, Any],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> list[str]:
    targets = contract.get("required_targets")
    if not isinstance(targets, list) or not targets:
        errors.append("required_targets must be a non-empty array")
        return []
    bins = load_fuzz_bins(errors)
    names: list[str] = []
    for entry in targets:
        if not isinstance(entry, dict):
            errors.append("required_targets entries must be objects")
            continue
        name = entry.get("target")
        source = entry.get("source")
        if not isinstance(name, str) or not name:
            errors.append("target missing target name")
            continue
        if not isinstance(source, str) or not source:
            errors.append(f"{name} missing source")
            continue
        names.append(name)
        expected_manifest_path = source.removeprefix("crates/frankenlibc-fuzz/")
        if bins.get(name) != expected_manifest_path:
            errors.append(
                f"{name} Cargo.toml bin path drifted: expected {expected_manifest_path}, got {bins.get(name)}"
            )
        if not (root / source).is_file():
            errors.append(f"{name} target source missing: {source}")
        source_text = read_text(source, errors, name)
        for needle in require_strings(entry.get("required_source_needles"), errors, f"{name}.required_source_needles"):
            if needle not in source_text:
                errors.append(f"{name} source missing needle {needle!r}")
        corpus = entry.get("corpus")
        if not isinstance(corpus, dict):
            errors.append(f"{name}.corpus must be an object")
            seed_names: list[str] = []
            corpus_dir = ""
            min_seeds = 0
        else:
            corpus_dir = corpus.get("path")
            seed_names = require_strings(corpus.get("required_seeds"), errors, f"{name}.corpus.required_seeds")
            min_seeds = corpus.get("min_seed_count", 0)
            if not isinstance(corpus_dir, str) or not corpus_dir:
                errors.append(f"{name}.corpus.path missing")
                corpus_dir = ""
            if not isinstance(min_seeds, int) or min_seeds < 1:
                errors.append(f"{name}.corpus.min_seed_count must be positive")
                min_seeds = 0
        if corpus_dir:
            seed_files = [path for path in (root / corpus_dir).glob("*") if path.is_file()]
            if len(seed_files) < min_seeds:
                errors.append(f"{name} corpus has {len(seed_files)} seeds, expected at least {min_seeds}")
            for seed in seed_names:
                if not (root / corpus_dir / seed).is_file():
                    errors.append(f"{name} corpus missing seed {seed}")
        for ref in entry.get("evidence_line_refs", []):
            validate_line_ref(ref, errors, f"{name}.evidence_line_refs")
        rows.append({
            "event": "printf_fuzz_family.target_contract",
            "target": name,
            "source": source,
            "corpus": corpus_dir,
            "status": "pass",
            "timestamp": utc_now(),
        })
    if names != REQUIRED_TARGETS:
        errors.append(f"required_targets must be {REQUIRED_TARGETS}, got {names}")
    return names


def validate_missing_item_bindings(contract: dict[str, Any], errors: list[str]) -> None:
    bindings = contract.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        errors.append("missing_item_bindings must be a non-empty array")
        return
    ids = {binding.get("id") for binding in bindings if isinstance(binding, dict)}
    if ids != REQUIRED_MISSING_ITEMS:
        errors.append(f"missing_item_bindings drifted: expected {sorted(REQUIRED_MISSING_ITEMS)}, got {sorted(ids)}")
    test_source = read_text(
        "crates/frankenlibc-harness/tests/printf_fuzz_family_completion_contract_test.rs",
        errors,
        "completion harness test",
    )
    for binding in bindings:
        if not isinstance(binding, dict):
            errors.append("missing_item_bindings entries must be objects")
            continue
        for test_name in binding.get("required_test_names", []):
            if not isinstance(test_name, str) or f"fn {test_name}(" not in test_source:
                errors.append(f"missing_item_bindings references missing Rust test {test_name}")


def main() -> int:
    errors: list[str] = []
    rows: list[dict[str, Any]] = []
    contract = load_json(contract_path, errors)
    if contract:
        if contract.get("schema_version") != "printf_fuzz_family_completion_contract.v1":
            errors.append("schema_version drifted")
        if contract.get("manifest_id") != MANIFEST_ID:
            errors.append("manifest_id drifted")
        if contract.get("bead") != BEAD_ID:
            errors.append(f"bead must be {BEAD_ID}")
        if contract.get("completion_debt_bead") != COMPLETION_BEAD_ID:
            errors.append(f"completion_debt_bead must be {COMPLETION_BEAD_ID}")
        validate_runtime_target(contract, errors, rows)
        validate_source_artifacts(contract, errors, rows)
        validate_missing_item_bindings(contract, errors)
        targets = validate_target_contracts(contract, errors, rows)
        validate_runner_targets(targets, errors, rows)

    status = "fail" if errors else "pass"
    report = {
        "schema_version": "printf_fuzz_family_completion_contract.report.v1",
        "status": status,
        "source_bead": BEAD_ID,
        "completion_debt_bead": COMPLETION_BEAD_ID,
        "target_group": "printf-family",
        "required_targets": REQUIRED_TARGETS,
        "events": sorted({row["event"] for row in rows}),
        "errors": errors,
        "timestamp": utc_now(),
    }
    rows.append({
        "event": "printf_fuzz_family.completion_contract",
        "status": status,
        "source_bead": BEAD_ID,
        "completion_debt_bead": COMPLETION_BEAD_ID,
        "errors": errors,
        "timestamp": utc_now(),
    })
    write_json(report_path, report)
    write_jsonl(log_path, rows)
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("check_printf_fuzz_family_completion_contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
