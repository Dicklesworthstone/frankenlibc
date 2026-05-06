#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${TOOLING_DEP_BOUNDARY_CONTRACT:-$ROOT/tests/conformance/tooling_dependency_boundary.v1.json}"
REPORT="${TOOLING_DEP_BOUNDARY_REPORT:-$ROOT/target/conformance/tooling_dependency_boundary.report.json}"
LOG="${TOOLING_DEP_BOUNDARY_LOG:-$ROOT/target/conformance/tooling_dependency_boundary.log.jsonl}"
WORKSPACE_CARGO="${TOOLING_DEP_BOUNDARY_WORKSPACE_CARGO:-$ROOT/Cargo.toml}"
ABI_CARGO="${TOOLING_DEP_BOUNDARY_ABI_CARGO:-$ROOT/crates/frankenlibc-abi/Cargo.toml}"
CORE_CARGO="${TOOLING_DEP_BOUNDARY_CORE_CARGO:-$ROOT/crates/frankenlibc-core/Cargo.toml}"
MEMBRANE_CARGO="${TOOLING_DEP_BOUNDARY_MEMBRANE_CARGO:-$ROOT/crates/frankenlibc-membrane/Cargo.toml}"
LEGACY_CARGO="${TOOLING_DEP_BOUNDARY_LEGACY_CARGO:-$ROOT/crates/frankenlibc/Cargo.toml}"
HARNESS_CARGO="${TOOLING_DEP_BOUNDARY_HARNESS_CARGO:-$ROOT/crates/frankenlibc-harness/Cargo.toml}"
CONFORMANCE_CARGO="${TOOLING_DEP_BOUNDARY_CONFORMANCE_CARGO:-$ROOT/crates/frankenlibc_conformance/Cargo.toml}"
FIXTURE_EXEC_CARGO="${TOOLING_DEP_BOUNDARY_FIXTURE_EXEC_CARGO:-$ROOT/crates/frankenlibc-fixture-exec/Cargo.toml}"
BENCH_CARGO="${TOOLING_DEP_BOUNDARY_BENCH_CARGO:-$ROOT/crates/frankenlibc-bench/Cargo.toml}"
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

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

python3 - "$ROOT" "$CONTRACT" "$REPORT" "$LOG" "$MODE" "$WORKSPACE_CARGO" "$ABI_CARGO" "$CORE_CARGO" "$MEMBRANE_CARGO" "$LEGACY_CARGO" "$HARNESS_CARGO" "$CONFORMANCE_CARGO" "$FIXTURE_EXEC_CARGO" "$BENCH_CARGO" <<'PY'
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
import tomllib
from collections import deque

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
mode = sys.argv[5]
manifest_paths = {
    "Cargo.toml": pathlib.Path(sys.argv[6]),
    "crates/frankenlibc-abi/Cargo.toml": pathlib.Path(sys.argv[7]),
    "crates/frankenlibc-core/Cargo.toml": pathlib.Path(sys.argv[8]),
    "crates/frankenlibc-membrane/Cargo.toml": pathlib.Path(sys.argv[9]),
    "crates/frankenlibc/Cargo.toml": pathlib.Path(sys.argv[10]),
    "crates/frankenlibc-harness/Cargo.toml": pathlib.Path(sys.argv[11]),
    "crates/frankenlibc_conformance/Cargo.toml": pathlib.Path(sys.argv[12]),
    "crates/frankenlibc-fixture-exec/Cargo.toml": pathlib.Path(sys.argv[13]),
    "crates/frankenlibc-bench/Cargo.toml": pathlib.Path(sys.argv[14]),
}
start_ns = time.time_ns()

EXPECTED_SCHEMA = "tooling_dependency_boundary.v1"
EXPECTED_BEAD = "bd-0agsk.13"
EXPECTED_COMMAND = "scripts/check_tooling_dependency_boundary.sh --validate-only"
EXPECTED_TODOS = {"TODO-0901", "TODO-0902", "TODO-0903"}


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except subprocess.CalledProcessError:
        return "unknown"


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def finish(outcome: str, signature: str, message: str, **summary):
    report = {
        "schema_version": "tooling_dependency_boundary.report.v1",
        "bead": EXPECTED_BEAD,
        "trace_id": f"tooling-dependency-boundary-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{id(summary)}",
        "source_commit": git_head(),
        "mode": mode,
        "outcome": outcome,
        "failure_signature": signature,
        "message": message,
        "contract": rel(contract_path),
        "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
        "inputs": {key: rel(path) for key, path in sorted(manifest_paths.items())},
        "summary": summary,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_path.write_text(
        json.dumps(
            {
                "timestamp": now_utc(),
                "event": "tooling_dependency_boundary_validated"
                if outcome == "pass"
                else "tooling_dependency_boundary_failed",
                "bead": EXPECTED_BEAD,
                "outcome": outcome,
                "failure_signature": signature,
                "summary": summary,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    if outcome != "pass":
        raise SystemExit(f"FAIL[{signature}]: {message}")


def fail(signature: str, message: str, **summary):
    finish("fail", signature, message, **summary)


def require(condition: bool, signature: str, message: str, **summary):
    if not condition:
        fail(signature, message, **summary)


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_toml(path: pathlib.Path):
    with path.open("rb") as handle:
        return tomllib.load(handle)


def package_name(manifest: dict) -> str:
    return str(manifest.get("package", {}).get("name", ""))


def dep_package_names(table: dict) -> set[str]:
    names: set[str] = set()
    for key, spec in table.items():
        names.add(str(key))
        if isinstance(spec, dict) and isinstance(spec.get("package"), str):
            names.add(spec["package"])
    return names


def table_by_path(manifest: dict, section: str) -> dict:
    table = manifest
    for part in section.split("."):
        if not isinstance(table, dict):
            return {}
        table = table.get(part, {})
    return table if isinstance(table, dict) else {}


def dependency_table(manifest: dict, section: str) -> dict:
    table = table_by_path(manifest, section)
    return table if isinstance(table, dict) else {}


def dependency_version(manifest: dict, section: str, name: str) -> str | None:
    spec = dependency_table(manifest, section).get(name)
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        value = spec.get("version")
        if isinstance(value, str):
            return value
    return None


def dependency_is_optional(manifest: dict, section: str, name: str) -> bool:
    spec = dependency_table(manifest, section).get(name)
    return isinstance(spec, dict) and spec.get("optional") is True


def features(manifest: dict) -> dict[str, list[str]]:
    raw = manifest.get("features", {})
    if not isinstance(raw, dict):
        return {}
    return {str(key): [str(item) for item in value] for key, value in raw.items() if isinstance(value, list)}


def internal_normal_deps(manifest: dict, workspace_names: set[str]) -> set[str]:
    deps = dependency_table(manifest, "dependencies")
    return {name for name in dep_package_names(deps) if name in workspace_names}


def manifest_for_rel(rel_path: str) -> dict:
    path = manifest_paths.get(rel_path, root / rel_path)
    require(path.is_file(), "input_missing", f"manifest missing: {path}", path=str(path))
    return load_toml(path)


if mode != "validate-only":
    fail("unknown_mode", f"only --validate-only is supported; got {mode}")

require(contract_path.is_file(), "input_missing", f"contract missing: {contract_path}", path=str(contract_path))
contract = load_json(contract_path)

require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "unexpected schema_version", actual=contract.get("schema_version"))
require(contract.get("generated_by_bead") == EXPECTED_BEAD, "generated_by_bead", "unexpected generated_by_bead", actual=contract.get("generated_by_bead"))
require(set(contract.get("source_todo_ids", [])) == EXPECTED_TODOS, "todo_set_drift", "source TODO ids drifted", actual=contract.get("source_todo_ids"))
require(contract.get("canonical_command") == EXPECTED_COMMAND, "canonical_command", "unexpected canonical_command", actual=contract.get("canonical_command"))

for rel_path in contract.get("input_artifacts", []):
    require((root / rel_path).is_file(), "input_artifact_missing", f"input artifact missing: {rel_path}", artifact=rel_path)

workspace = manifest_for_rel("Cargo.toml")
expected_workspace = contract.get("workspace_companion_dependencies", {})
for dep, expected_version in expected_workspace.items():
    actual = dependency_version(workspace, "workspace.dependencies", dep)
    require(actual == expected_version, "workspace_companion_version_drift", f"{dep}: workspace version drifted", dependency=dep, expected=expected_version, actual=actual)

forbidden_names = set(contract.get("forbidden_runtime_dependency_names", []))
runtime_rows = contract.get("runtime_crates", [])
tooling_rows = contract.get("tooling_crates", [])
require(isinstance(runtime_rows, list) and runtime_rows, "runtime_crates_missing", "runtime_crates must be non-empty")
require(isinstance(tooling_rows, list) and tooling_rows, "tooling_crates_missing", "tooling_crates must be non-empty")

manifests_by_crate: dict[str, dict] = {}
manifests_by_path: dict[str, dict] = {}
for row in runtime_rows + tooling_rows:
    rel_manifest = str(row.get("manifest", ""))
    manifest = manifest_for_rel(rel_manifest)
    crate = package_name(manifest)
    require(crate == row.get("crate"), "crate_manifest_mismatch", f"{rel_manifest}: package.name mismatch", expected=row.get("crate"), actual=crate)
    manifests_by_crate[crate] = manifest
    manifests_by_path[rel_manifest] = manifest

for rel_manifest in [
    "crates/frankenlibc-fixture-exec/Cargo.toml",
    "crates/frankenlibc-bench/Cargo.toml",
]:
    manifest = manifest_for_rel(rel_manifest)
    manifests_by_crate[package_name(manifest)] = manifest
    manifests_by_path[rel_manifest] = manifest

runtime_leaks: list[dict] = []
runtime_cdylib_checked = 0
for row in runtime_rows:
    crate = str(row.get("crate"))
    manifest = manifests_by_crate[crate]
    for crate_type in row.get("crate_type_requires", []):
        crate_types = manifest.get("lib", {}).get("crate-type", [])
        if isinstance(crate_types, list):
            runtime_cdylib_checked += 1
            require(crate_type in crate_types, "runtime_cdylib_policy", f"{crate}: required crate type missing", crate=crate, crate_type=crate_type, actual=crate_types)
    for section in row.get("dependency_sections_forbid_tooling", []):
        deps = dep_package_names(dependency_table(manifest, section))
        leaked = sorted(deps & forbidden_names)
        if leaked:
            runtime_leaks.append({"crate": crate, "section": section, "dependencies": leaked})

require(not runtime_leaks, "runtime_dependency_leakage", "tooling dependencies leaked into runtime dependency sections", leaks=runtime_leaks)

tooling_optional_count = 0
for row in tooling_rows:
    crate = str(row.get("crate"))
    manifest = manifests_by_crate[crate]
    feat = features(manifest)
    expected_default = row.get("expected_default_features", [])
    require(feat.get("default", []) == expected_default, "tooling_default_feature_drift", f"{crate}: default features drifted", crate=crate, expected=expected_default, actual=feat.get("default", []))
    for dep in row.get("optional_dependencies", []):
        tooling_optional_count += 1
        require(dependency_is_optional(manifest, "dependencies", dep), "tooling_optional_dependency_missing", f"{crate}: optional dependency missing", crate=crate, dependency=dep)
    for feature, expected_items in row.get("features", {}).items():
        actual_items = set(feat.get(feature, []))
        missing = sorted(set(expected_items) - actual_items)
        require(not missing, "tooling_feature_binding_missing", f"{crate}:{feature} missing dependency bindings", crate=crate, feature=feature, missing=missing)

policy = contract.get("runtime_transitive_policy", {})
workspace_names = set(manifests_by_crate)
graph = {
    crate: internal_normal_deps(manifest, workspace_names)
    for crate, manifest in manifests_by_crate.items()
}
reachable: set[str] = set()
queue = deque(str(item) for item in policy.get("start_crates", []))
while queue:
    crate = queue.popleft()
    if crate in reachable:
        continue
    reachable.add(crate)
    queue.extend(sorted(graph.get(crate, set()) - reachable))

forbidden_reachable = sorted(reachable & set(policy.get("forbidden_workspace_crates", [])))
require(not forbidden_reachable, "runtime_dependency_leakage", "runtime normal dependency graph reaches tooling crates", reachable=sorted(reachable), forbidden_reachable=forbidden_reachable)
expected_reachable = sorted(policy.get("expected_reachable_crates", []))
require(sorted(reachable) == expected_reachable, "runtime_dependency_graph_drift", "runtime normal dependency graph drifted", expected=expected_reachable, actual=sorted(reachable))

feature_proofs = contract.get("feature_path_proofs", [])
expected = contract.get("expected_current", {})
require(isinstance(feature_proofs, list) and feature_proofs, "feature_path_proof_missing", "feature_path_proofs must be non-empty")
require(expected.get("feature_path_proof_count") == len(feature_proofs), "feature_path_proof_missing", "feature path proof count drifted", expected=expected.get("feature_path_proof_count"), actual=len(feature_proofs))
seen_proof_ids: set[str] = set()
for row in feature_proofs:
    proof_id = str(row.get("id", ""))
    crate = str(row.get("crate", ""))
    feature = str(row.get("feature", ""))
    source_path = root / str(row.get("source_path", ""))
    required_tokens = row.get("required_tokens", [])
    require(proof_id and proof_id not in seen_proof_ids, "feature_path_proof_missing", "feature proof id missing or duplicated", proof_id=proof_id)
    seen_proof_ids.add(proof_id)
    require(crate in manifests_by_crate, "feature_path_proof_missing", f"{proof_id}: unknown crate", proof_id=proof_id, crate=crate)
    require(feature in features(manifests_by_crate[crate]), "feature_path_proof_missing", f"{proof_id}: feature missing from manifest", proof_id=proof_id, crate=crate, feature=feature)
    require(source_path.is_file(), "feature_path_proof_missing", f"{proof_id}: source path missing", proof_id=proof_id, source_path=str(source_path))
    text = source_path.read_text(encoding="utf-8")
    missing_tokens = [token for token in required_tokens if token not in text]
    require(not missing_tokens, "feature_path_proof_missing", f"{proof_id}: required source tokens missing", proof_id=proof_id, missing_tokens=missing_tokens)

negative_signatures = {
    row.get("expected_failure_signature")
    for row in contract.get("negative_tests", [])
    if isinstance(row, dict)
}
for signature in contract.get("required_failure_signatures", []):
    require(signature in negative_signatures, "negative_test_missing", f"missing negative test declaration for {signature}", expected_signature=signature)

require(expected.get("runtime_crate_count") == len(runtime_rows), "count_drift", "runtime crate count drifted", expected=expected.get("runtime_crate_count"), actual=len(runtime_rows))
require(expected.get("tooling_crate_count") == len(tooling_rows), "count_drift", "tooling crate count drifted", expected=expected.get("tooling_crate_count"), actual=len(tooling_rows))
require(expected.get("runtime_dependency_leakage_count") == len(runtime_leaks), "runtime_dependency_leakage", "runtime dependency leakage count drifted", expected=expected.get("runtime_dependency_leakage_count"), actual=len(runtime_leaks))
require(expected.get("runtime_forbidden_workspace_reachable_count") == len(forbidden_reachable), "runtime_dependency_leakage", "runtime forbidden workspace reachability count drifted", expected=expected.get("runtime_forbidden_workspace_reachable_count"), actual=len(forbidden_reachable))
require(expected.get("tooling_optional_dependency_count") == tooling_optional_count, "count_drift", "tooling optional dependency count drifted", expected=expected.get("tooling_optional_dependency_count"), actual=tooling_optional_count)

finish(
    "pass",
    "none",
    "tooling dependency boundary validated",
    runtime_crates=[str(row.get("crate")) for row in runtime_rows],
    tooling_crates=[str(row.get("crate")) for row in tooling_rows],
    runtime_dependency_leakage_count=len(runtime_leaks),
    runtime_reachable_crates=sorted(reachable),
    runtime_cdylib_checks=runtime_cdylib_checked,
    tooling_optional_dependency_count=tooling_optional_count,
    feature_path_proof_count=len(feature_proofs),
)
PY

echo "PASS: tooling dependency boundary validated"
