#!/usr/bin/env bash
# Validate the architecture and migration-state evidence report.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${ARCH_MIGRATION_STATE_REPORT_CONTRACT:-${ROOT}/tests/conformance/architecture_migration_state_report.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${ARCH_MIGRATION_STATE_REPORT_REPORT:-${OUT_DIR}/architecture_migration_state_report.report.json}"
LOG="${ARCH_MIGRATION_STATE_REPORT_LOG:-${OUT_DIR}/architecture_migration_state_report.log.jsonl}"
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

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${MODE}" <<'PY'
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time
from collections import Counter

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
mode = sys.argv[5]
start_ns = time.time_ns()

EXPECTED_SCHEMA = "architecture_migration_state_report.v1"
EXPECTED_BEAD = "bd-0agsk.16"
EXPECTED_TODOS = {"TODO-1001", "TODO-1002", "TODO-1003"}
EXPECTED_COMMAND = "scripts/check_architecture_migration_state_report.sh --validate-only"
STATUS_KEYS = ["Implemented", "RawSyscall", "WrapsHostLibc", "GlibcCallThrough", "Stub"]
REQUIRED_GLOSSARY = {"strict_mode", "hardened_mode", "both_modes", "startup_evidence"}
NEGATIVE_SIGNATURES = {
    "legacy_branch_reference",
    "source_artifact_missing",
    "module_family_count_drift",
    "module_family_coverage_drift",
}


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except subprocess.CalledProcessError:
        return "unknown"


def rel(path: pathlib.Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def finish(outcome: str, signature: str, message: str, **summary):
    report = {
        "schema_version": "architecture_migration_state_report.report.v1",
        "bead": EXPECTED_BEAD,
        "trace_id": f"architecture-migration-state-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}",
        "source_commit": git_head(),
        "mode": mode,
        "outcome": outcome,
        "failure_signature": signature,
        "message": message,
        "contract": rel(contract_path),
        "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
        "summary": summary,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_path.write_text(
        json.dumps(
            {
                "timestamp": now_utc(),
                "event": "architecture_migration_state_report_validated"
                if outcome == "pass"
                else "architecture_migration_state_report_failed",
                "bead": EXPECTED_BEAD,
                "outcome": outcome,
                "failure_signature": signature,
                "contract": rel(contract_path),
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


def require_rel_path(raw, field: str) -> pathlib.Path:
    require(isinstance(raw, str) and raw.strip(), "field_missing", f"{field} must be a non-empty string", field=field)
    path = pathlib.Path(raw)
    require(not path.is_absolute(), "absolute_path_declared", f"{field} must be project-relative", field=field, path=raw)
    require(".." not in path.parts, "parent_path_declared", f"{field} must not contain parent traversal", field=field, path=raw)
    return path


def require_existing(raw, field: str, signature: str = "source_artifact_missing") -> pathlib.Path:
    path = require_rel_path(raw, field)
    abs_path = root / path
    require(abs_path.exists(), signature, f"{field} missing: {path}", field=field, path=path.as_posix())
    return path


def normalized_counts(rows: list[dict]) -> dict[str, int]:
    counts = {key: 0 for key in STATUS_KEYS}
    for row in rows:
        status = row.get("status")
        if status in counts:
            counts[status] += 1
    return counts


def command_tokens(command: str, field: str) -> list[str]:
    require(isinstance(command, str) and command.strip(), "field_missing", f"{field} must be a non-empty command", field=field)
    try:
        tokens = shlex.split(command)
    except ValueError as err:
        fail("command_parse_error", f"{field} could not be parsed: {err}", field=field, command=command)
    require(tokens, "command_parse_error", f"{field} parsed to no tokens", field=field, command=command)
    return tokens


if mode != "validate-only":
    fail("unknown_mode", f"only --validate-only is supported; got {mode}")

require(contract_path.is_file(), "contract_missing", f"contract file missing: {contract_path}")
raw_text = contract_path.read_text(encoding="utf-8")
legacy_branch_term = "ma" + "ster"
require(legacy_branch_term not in raw_text.lower(), "legacy_branch_reference", "report contains a forbidden legacy branch alias")

contract = json.loads(raw_text)
require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "unexpected schema_version", actual=contract.get("schema_version"))
require(contract.get("generated_by_bead") == EXPECTED_BEAD, "generated_by_bead", "unexpected generated_by_bead", actual=contract.get("generated_by_bead"))
require(set(contract.get("source_todo_ids", [])) == EXPECTED_TODOS, "todo_set_drift", "source TODO ids drifted", actual=contract.get("source_todo_ids"))
require(contract.get("canonical_command") == EXPECTED_COMMAND, "canonical_command", "unexpected canonical command", actual=contract.get("canonical_command"))

source_artifacts = contract.get("source_artifacts")
require(isinstance(source_artifacts, list) and source_artifacts, "source_artifacts_missing", "source_artifacts must be non-empty")
source_ids = set()
for idx, artifact in enumerate(source_artifacts):
    require(isinstance(artifact, dict), "source_artifacts_missing", f"source_artifacts[{idx}] must be an object")
    artifact_id = artifact.get("id")
    require(isinstance(artifact_id, str) and artifact_id, "source_artifacts_missing", f"source_artifacts[{idx}].id must be non-empty")
    require(artifact_id not in source_ids, "source_artifact_duplicate", f"duplicate source artifact id: {artifact_id}", artifact_id=artifact_id)
    source_ids.add(artifact_id)
    require_existing(artifact.get("path"), f"source_artifacts[{idx}].path")

scripts = contract.get("relevant_scripts")
require(isinstance(scripts, list) and scripts, "scripts_missing", "relevant_scripts must be non-empty")
for idx, script in enumerate(scripts):
    path = root / require_rel_path(script, f"relevant_scripts[{idx}]")
    require(path.is_file(), "script_missing", f"script missing: {script}", script=script)
    require(os.access(path, os.X_OK), "script_not_executable", f"script is not executable: {script}", script=script)

support_matrix = load_json(root / "support_matrix.json")
symbols = support_matrix.get("symbols", [])
require(isinstance(symbols, list) and symbols, "support_matrix_invalid", "support_matrix symbols must be non-empty")
computed_summary = {
    "total_exported": len(symbols),
    "status_counts": normalized_counts(symbols),
}
declared_summary = contract.get("support_matrix_summary", {})
require(declared_summary.get("total_exported") == computed_summary["total_exported"], "support_summary_drift", "total_exported drifted", declared=declared_summary.get("total_exported"), actual=computed_summary["total_exported"])
require(declared_summary.get("status_counts") == computed_summary["status_counts"], "support_summary_drift", "status_counts drifted", declared=declared_summary.get("status_counts"), actual=computed_summary["status_counts"])
host_backed = computed_summary["status_counts"]["WrapsHostLibc"] + computed_summary["status_counts"]["GlibcCallThrough"]
native_total = computed_summary["status_counts"]["Implemented"] + computed_summary["status_counts"]["RawSyscall"]
require(declared_summary.get("native_surface_pct") == round(native_total * 100.0 / len(symbols), 1), "support_summary_drift", "native_surface_pct drifted")
require(declared_summary.get("host_callthrough_surface_pct") == round(host_backed * 100.0 / len(symbols), 1), "support_summary_drift", "host_callthrough_surface_pct drifted")

replacement_levels = load_json(root / "tests/conformance/replacement_levels.json")
claim_summary = contract.get("claim_summary", {})
require(claim_summary.get("current_level") == replacement_levels.get("current_level"), "claim_summary_drift", "current_level drifted")
release_level = replacement_levels.get("release_tag_policy", {}).get("current_release_level")
require(claim_summary.get("current_release_level") == release_level, "claim_summary_drift", "current_release_level drifted")

smoke = load_json(root / "tests/conformance/ld_preload_smoke_summary.v1.json")
smoke_summary = smoke.get("summary", {})
smoke_modes = smoke.get("modes", {})
declared_smoke = claim_summary.get("ld_preload_smoke_summary", {})
require(declared_smoke.get("total_cases") == smoke_summary.get("total_cases"), "claim_summary_drift", "smoke total_cases drifted")
require(declared_smoke.get("passes") == smoke_summary.get("passes"), "claim_summary_drift", "smoke passes drifted")
require(declared_smoke.get("fails") == smoke_summary.get("fails"), "claim_summary_drift", "smoke fails drifted")
require(declared_smoke.get("skips") == smoke_summary.get("skips"), "claim_summary_drift", "smoke skips drifted")
require(declared_smoke.get("strict_status") == smoke_modes.get("strict", {}).get("status"), "claim_summary_drift", "strict smoke status drifted")
require(declared_smoke.get("hardened_status") == smoke_modes.get("hardened", {}).get("status"), "claim_summary_drift", "hardened smoke status drifted")

symbols_by_module: dict[str, list[dict]] = {}
for symbol in symbols:
    module = symbol.get("module")
    require(isinstance(module, str) and module, "support_matrix_invalid", "support_matrix symbol missing module")
    symbols_by_module.setdefault(module, []).append(symbol)

family_rows = contract.get("module_family_status")
require(isinstance(family_rows, list) and family_rows, "module_family_rows_missing", "module_family_status must be non-empty")
covered_modules = []
for idx, row in enumerate(family_rows):
    require(isinstance(row, dict), "module_family_rows_missing", f"module_family_status[{idx}] must be an object")
    family = row.get("family")
    require(isinstance(family, str) and family, "module_family_rows_missing", f"module_family_status[{idx}].family must be non-empty")
    modules = row.get("modules")
    require(isinstance(modules, list) and modules, "module_family_rows_missing", f"{family}: modules must be non-empty", family=family)
    family_symbols = []
    for module in modules:
        require(module in symbols_by_module, "module_family_unknown_module", f"{family}: unknown support_matrix module {module}", family=family, module=module)
        covered_modules.append(module)
        family_symbols.extend(symbols_by_module[module])
    expected_counts = normalized_counts(family_symbols)
    require(row.get("total_symbols") == len(family_symbols), "module_family_count_drift", f"{family}: total_symbols drifted", family=family, declared=row.get("total_symbols"), actual=len(family_symbols))
    require(row.get("status_counts") == expected_counts, "module_family_count_drift", f"{family}: status_counts drifted", family=family, declared=row.get("status_counts"), actual=expected_counts)
    require(row.get("interpose_ready") in {"evidence_backed"}, "module_family_claim_drift", f"{family}: unexpected interpose readiness", family=family)
    require(
        row.get("replacement_ready")
        in {
            "taxonomy_clean_claim_blocked",
            "blocked_by_startup_tls_proof",
            "blocked_by_nss_resolver_backend",
            "blocked_by_loader_and_host_independence_evidence",
        },
        "module_family_claim_drift",
        f"{family}: unexpected replacement readiness",
        family=family,
        actual=row.get("replacement_ready"),
    )
    for evidence_index, evidence in enumerate(row.get("evidence_artifacts", [])):
        require_existing(evidence, f"module_family_status[{idx}].evidence_artifacts[{evidence_index}]")

duplicates = sorted(module for module, count in Counter(covered_modules).items() if count != 1)
missing = sorted(set(symbols_by_module) - set(covered_modules))
extra = sorted(set(covered_modules) - set(symbols_by_module))
require(not duplicates and not missing and not extra, "module_family_coverage_drift", "module families must cover each support_matrix module exactly once", duplicates=duplicates, missing=missing, extra=extra)

crate_flows = contract.get("crate_to_artifact_flow")
require(isinstance(crate_flows, list) and crate_flows, "crate_flow_missing", "crate_to_artifact_flow must be non-empty")
for idx, flow in enumerate(crate_flows):
    require_existing(flow.get("crate_path"), f"crate_to_artifact_flow[{idx}].crate_path")
    for field in ["source_paths", "evidence_artifacts", "scripts"]:
        values = flow.get(field)
        require(isinstance(values, list) and values, "crate_flow_missing", f"crate_to_artifact_flow[{idx}].{field} must be non-empty")
        for value_index, value in enumerate(values):
            signature = "script_missing" if field == "scripts" else "source_artifact_missing"
            require_existing(value, f"crate_to_artifact_flow[{idx}].{field}[{value_index}]", signature=signature)
    expected_outputs = flow.get("expected_outputs")
    require(isinstance(expected_outputs, list) and expected_outputs, "crate_flow_missing", f"crate_to_artifact_flow[{idx}].expected_outputs must be non-empty")
    for output_index, output in enumerate(expected_outputs):
        require_rel_path(output, f"crate_to_artifact_flow[{idx}].expected_outputs[{output_index}]")

glossary = contract.get("strict_hardened_glossary")
require(isinstance(glossary, list) and glossary, "glossary_missing", "strict_hardened_glossary must be non-empty")
glossary_terms = {row.get("term") for row in glossary if isinstance(row, dict)}
require(glossary_terms == REQUIRED_GLOSSARY, "glossary_term_drift", "glossary term set drifted", expected=sorted(REQUIRED_GLOSSARY), actual=sorted(glossary_terms))
for idx, row in enumerate(glossary):
    for artifact_index, artifact in enumerate(row.get("evidence_artifacts", [])):
        require_existing(artifact, f"strict_hardened_glossary[{idx}].evidence_artifacts[{artifact_index}]")

validation_commands = contract.get("validation_commands")
require(isinstance(validation_commands, list) and validation_commands, "validation_commands_missing", "validation_commands must be non-empty")
for idx, command in enumerate(validation_commands):
    tokens = command_tokens(command, f"validation_commands[{idx}]")
    if tokens[0].startswith("scripts/"):
        path = root / require_rel_path(tokens[0], f"validation_commands[{idx}].script")
        require(path.is_file(), "validation_command_path_missing", f"validation script missing: {tokens[0]}", command=command)
    if tokens[0] == "jq":
        require(len(tokens) >= 3, "validation_command_path_missing", "jq command must name an artifact", command=command)
        require_existing(tokens[-1], f"validation_commands[{idx}].artifact")

negative_tests = contract.get("negative_tests")
require(isinstance(negative_tests, list) and negative_tests, "negative_tests_missing", "negative_tests must be non-empty")
actual_negative = {
    test.get("expected_failure_signature")
    for test in negative_tests
    if isinstance(test, dict)
}
require(NEGATIVE_SIGNATURES.issubset(actual_negative), "negative_test_missing", "negative tests missing required signatures", expected=sorted(NEGATIVE_SIGNATURES), actual=sorted(actual_negative))

summary = contract.get("summary", {})
require(summary.get("source_artifact_count") == len(source_artifacts), "summary_count_drift", "source_artifact_count drifted")
require(summary.get("script_count") == len(scripts), "summary_count_drift", "script_count drifted")
require(summary.get("crate_flow_count") == len(crate_flows), "summary_count_drift", "crate_flow_count drifted")
require(summary.get("module_family_count") == len(family_rows), "summary_count_drift", "module_family_count drifted")
require(summary.get("glossary_term_count") == len(glossary), "summary_count_drift", "glossary_term_count drifted")
require(summary.get("total_symbols") == len(symbols), "summary_count_drift", "total_symbols drifted")
require(summary.get("implemented") == computed_summary["status_counts"]["Implemented"], "summary_count_drift", "implemented count drifted")
require(summary.get("raw_syscall") == computed_summary["status_counts"]["RawSyscall"], "summary_count_drift", "raw syscall count drifted")
require(summary.get("host_backed_status_count") == host_backed, "summary_count_drift", "host-backed status count drifted")
require(summary.get("stub_count") == computed_summary["status_counts"]["Stub"], "summary_count_drift", "stub count drifted")

finish(
    "pass",
    "none",
    "architecture migration-state report validated",
    source_artifacts=len(source_artifacts),
    scripts=len(scripts),
    module_families=len(family_rows),
    total_symbols=len(symbols),
    current_level=claim_summary.get("current_level"),
)
PY

echo "PASS: architecture migration-state report validated"
