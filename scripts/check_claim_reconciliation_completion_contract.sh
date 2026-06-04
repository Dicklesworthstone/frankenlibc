#!/usr/bin/env bash
# Validate bd-w2c3.10.1.1 claim-reconciliation completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${1:-${ROOT}/tests/conformance/claim_reconciliation_completion_contract.v1.json}"
OUT_DIR="${2:-${ROOT}/target/conformance}"
REPORT_PATH="${OUT_DIR}/claim_reconciliation_completion_contract.report.json"
LOG_PATH="${OUT_DIR}/claim_reconciliation_completion_contract.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT_PATH}" "${REPORT_PATH}" "${LOG_PATH}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
from collections import Counter
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT_PATH = pathlib.Path(sys.argv[2]).resolve()
REPORT_PATH = pathlib.Path(sys.argv[3]).resolve()
LOG_PATH = pathlib.Path(sys.argv[4]).resolve()

EXPECTED_SCHEMA = "claim_reconciliation_completion_contract.v1"
EXPECTED_BEAD = "bd-w2c3.10.1"
EXPECTED_COMPLETION_BEAD = "bd-w2c3.10.1.1"
EXPECTED_MISSING_ITEMS = ["tests.unit.primary", "tests.e2e.primary"]
EXPECTED_SOURCE_KEYS = {
    "claim_reconciliation_engine",
    "claim_reconciliation_gate",
    "claim_reconciliation_report",
    "claim_reconciliation_test",
    "support_matrix",
    "reality_report",
    "replacement_levels",
    "smoke_summary",
    "hard_parts_truth_table",
    "feature_parity",
    "readme",
    "release_claim_control_contract",
    "release_claim_control_checker",
    "completion_checker",
    "completion_test",
}
EXPECTED_INPUT_ARTIFACTS = [
    "support_matrix.json",
    "tests/conformance/reality_report.v1.json",
    "tests/conformance/replacement_levels.json",
    "tests/conformance/ld_preload_smoke_summary.v1.json",
    "tests/conformance/hard_parts_truth_table.v1.json",
    "FEATURE_PARITY.md",
    "README.md",
]
EXPECTED_ENV_OVERRIDES = [
    "FLC_CLAIM_RECON_SUPPORT_MATRIX",
    "FLC_CLAIM_RECON_REALITY_REPORT",
    "FLC_CLAIM_RECON_REPLACEMENT_LEVELS",
    "FLC_CLAIM_RECON_SMOKE_SUMMARY",
    "FLC_CLAIM_RECON_HARD_PARTS",
    "FLC_CLAIM_RECON_FEATURE_PARITY",
    "FLC_CLAIM_RECON_README",
    "FLC_CLAIM_RECON_CANONICAL_REPORT",
]
EXPECTED_ENGINE_FUNCTIONS = {
    "env_path",
    "load_json",
    "repo_relative",
    "normalize_source_name",
    "enrich_findings",
    "build_owner_summary",
    "extract_md_counts",
    "check_count_consistency",
    "check_replacement_levels",
    "check_replacement_level_text_consistency",
    "check_replacement_level_smoke_obligations",
    "check_module_taxonomy",
    "check_hard_parts",
    "check_timestamp_consistency",
    "check_readme_claims",
    "check_readme_replacement_smoke_claims",
    "check_readme_smoke_summary_claims",
    "check_feature_parity_done_claims",
    "main",
}
EXPECTED_UNIT_REFS = {
    ("claim_reconciliation_test", "claim_reconciliation_gate_passes"),
    ("claim_reconciliation_test", "claim_reconciliation_detects_readme_drift_and_routes_owner"),
    ("claim_reconciliation_test", "claim_reconciliation_detects_replacement_level_smoke_drift_and_routes_owner"),
    ("claim_reconciliation_test", "claim_reconciliation_detects_readme_smoke_overclaim_and_routes_replacement_owner"),
    ("claim_reconciliation_test", "claim_reconciliation_detects_readme_smoke_summary_drift_and_routes_owner"),
}
EXPECTED_E2E_ARTIFACTS = {
    "support_matrix",
    "reality_report",
    "replacement_levels",
    "smoke_summary",
    "hard_parts_truth_table",
    "feature_parity",
    "readme",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def load_json(path: pathlib.Path, label: str) -> Any:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        err(f"{label} JSON load failed: {exc}")
        return {}


def read_text(path: pathlib.Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} read failed: {exc}")
        return ""


def sha256_file(path: pathlib.Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def append_event(event: str, status: str, details: dict[str, Any]) -> None:
    events.append(
        {
            "schema_version": "claim_reconciliation_completion_contract.log.v1",
            "event": event,
            "status": status,
            "outcome": status,
            "bead": EXPECTED_COMPLETION_BEAD,
            "bead_id": EXPECTED_COMPLETION_BEAD,
            "source_bead": EXPECTED_BEAD,
            "trace_id": f"{EXPECTED_COMPLETION_BEAD}::{event}",
            "mode": "strict+hardened",
            "api_family": "claim_reconciliation",
            "symbol": "claim-reconciliation",
            "decision_path": "completion_contract>claim_reconciliation_gate",
            "healing_action": "none",
            "errno": 0,
            "latency_ns": 0,
            "artifact_refs": [rel(CONTRACT_PATH), rel(REPORT_PATH)],
            "details": details,
        }
    )


def artifact_path(value: Any, context: str) -> pathlib.Path | None:
    if not isinstance(value, str) or not value:
        err(f"{context} must be a non-empty string path")
        return None
    path = (ROOT / value).resolve()
    if ROOT not in path.parents and path != ROOT:
        err(f"{context} escapes workspace: {value}")
        return None
    if not path.is_file():
        err(f"{context} missing file: {value}")
        return None
    return path


def string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        err(f"{context} must be a list of strings")
        return []
    return list(value)


def validate_rch_commands(section: dict[str, Any], section_name: str) -> None:
    commands = string_list(section.get("required_commands"), f"{section_name}.required_commands")
    for command in commands:
        if "cargo " in command:
            require(command.startswith("rch exec --"), f"non-rch cargo validation command: {command}")


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, pathlib.Path]:
    source_artifacts = manifest.get("source_artifacts")
    if not isinstance(source_artifacts, dict):
        err("source_artifacts must be an object")
        return {}
    missing = EXPECTED_SOURCE_KEYS - set(source_artifacts)
    extra = set(source_artifacts) - EXPECTED_SOURCE_KEYS
    require(not missing, f"source_artifacts missing keys: {sorted(missing)}")
    require(not extra, f"source_artifacts unexpected keys: {sorted(extra)}")

    paths: dict[str, pathlib.Path] = {}
    for key in sorted(EXPECTED_SOURCE_KEYS):
        path = artifact_path(source_artifacts.get(key), f"source_artifacts.{key}")
        if path is not None:
            paths[key] = path
    append_event(
        "claim_reconciliation_completion.source_artifacts",
        "fail" if errors else "pass",
        {"artifact_count": len(paths), "keys": sorted(paths)},
    )
    return paths


def validate_refs(section: dict[str, Any], paths: dict[str, pathlib.Path]) -> list[str]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list):
        err("unit_primary.required_test_refs must be a list")
        refs = []
    got = {
        (ref.get("artifact"), ref.get("name"))
        for ref in refs
        if isinstance(ref, dict)
        and isinstance(ref.get("artifact"), str)
        and isinstance(ref.get("name"), str)
    }
    require(got == EXPECTED_UNIT_REFS, f"unit_primary test refs mismatch: got {sorted(got)}")
    test_text = read_text(paths["claim_reconciliation_test"], "claim_reconciliation_test")
    for _, name in EXPECTED_UNIT_REFS:
        pattern = re.compile(rf"\bfn\s+{re.escape(name)}\b")
        require(bool(pattern.search(test_text)), f"missing claim reconciliation test function {name}")
    validate_rch_commands(section, "unit_primary")
    return [f"{artifact}::{name}" for artifact, name in sorted(EXPECTED_UNIT_REFS)]


def validate_engine_functions(section: dict[str, Any], paths: dict[str, pathlib.Path]) -> list[str]:
    declared = set(string_list(section.get("required_engine_functions"), "unit_primary.required_engine_functions"))
    require(declared == EXPECTED_ENGINE_FUNCTIONS, f"engine functions mismatch: got {sorted(declared)}")
    engine_text = read_text(paths["claim_reconciliation_engine"], "claim_reconciliation_engine")
    for name in EXPECTED_ENGINE_FUNCTIONS:
        pattern = re.compile(rf"^def\s+{re.escape(name)}\b", re.MULTILINE)
        require(bool(pattern.search(engine_text)), f"claim_reconciliation.py missing function {name}")
    for env_name in EXPECTED_ENV_OVERRIDES:
        require(env_name in engine_text, f"claim_reconciliation.py missing env override {env_name}")
    return sorted(EXPECTED_ENGINE_FUNCTIONS)


def support_counts(paths: dict[str, pathlib.Path]) -> dict[str, int]:
    support = load_json(paths["support_matrix"], "support_matrix")
    counts = Counter()
    for row in support.get("symbols", []) if isinstance(support, dict) else []:
        if isinstance(row, dict):
            counts[row.get("status", "unknown")] += 1
    counts["total"] = sum(counts.values())
    return {
        "total": counts["total"],
        "Implemented": counts.get("Implemented", 0),
        "RawSyscall": counts.get("RawSyscall", 0),
        "GlibcCallThrough": counts.get("GlibcCallThrough", 0),
        "Stub": counts.get("Stub", 0),
    }


def validate_report(paths: dict[str, pathlib.Path], required: dict[str, Any]) -> dict[str, Any]:
    report = load_json(paths["claim_reconciliation_report"], "claim_reconciliation_report")
    if not isinstance(report, dict):
        err("claim_reconciliation_report must be an object")
        report = {}
    require(report.get("schema_version") == required.get("schema_version"), "report schema_version mismatch")
    require(report.get("bead") == required.get("bead"), "report bead mismatch")
    require(report.get("status") == required.get("status"), "report status mismatch")
    require(
        report.get("report_artifact_path") == required.get("report_artifact_path"),
        "report_artifact_path mismatch",
    )
    require(report.get("input_artifacts") == EXPECTED_INPUT_ARTIFACTS, "report input_artifacts mismatch")
    require(report.get("owner_summary") == [], "report owner_summary must be empty for pass state")
    require(report.get("findings") == [], "report findings must be empty for pass state")

    summary = report.get("summary", {})
    expected_summary = required.get("summary", {})
    if not isinstance(summary, dict) or not isinstance(expected_summary, dict):
        err("report summary contract must be objects")
    else:
        for key, value in expected_summary.items():
            require(summary.get(key) == value, f"report summary.{key} mismatch: {summary.get(key)!r}")

    truth = report.get("ground_truth", {})
    expected_counts = support_counts(paths)
    if not isinstance(truth, dict):
        err("report ground_truth must be an object")
        truth = {}
    require(truth.get("source") == "support_matrix.json", "ground_truth source mismatch")
    for key, value in expected_counts.items():
        require(truth.get(key) == value, f"ground_truth.{key} mismatch: {truth.get(key)!r} != {value!r}")

    return {
        "status": report.get("status"),
        "summary": summary,
        "ground_truth": expected_counts,
    }


def validate_gate_wrapper(paths: dict[str, pathlib.Path]) -> None:
    gate_text = read_text(paths["claim_reconciliation_gate"], "claim_reconciliation_gate")
    required_snippets = [
        "python3 scripts/claim_reconciliation.py",
        "mktemp",
        "mv \"$TMP_REPORT\" \"$REPORT_OUT\"",
        "PASS: No contradictions detected across canonical artifacts.",
        "FAIL: Contradictions detected.",
        "ERROR: Missing critical artifacts.",
    ]
    for snippet in required_snippets:
        require(snippet in gate_text, f"check_claim_reconciliation.sh missing snippet: {snippet}")


def validate_docs_and_release_links(paths: dict[str, pathlib.Path]) -> None:
    readme = read_text(paths["readme"], "readme")
    feature_parity = read_text(paths["feature_parity"], "feature_parity")
    replacement = load_json(paths["replacement_levels"], "replacement_levels")
    release_contract = load_json(paths["release_claim_control_contract"], "release_claim_control_contract")
    release_checker = read_text(paths["release_claim_control_checker"], "release_claim_control_checker")

    require("total_exported=4119" in readme, "README missing checked total_exported claim")
    require("Canonical checked smoke artifact: `tests/conformance/ld_preload_smoke_summary.v1.json`" in readme, "README missing canonical checked smoke line")
    require("total_exported=4119" in feature_parity, "FEATURE_PARITY missing checked total_exported claim")
    require("claim_reconciliation_clean" in json.dumps(replacement), "replacement_levels missing claim_reconciliation_clean gate")

    artifacts = release_contract.get("source_artifacts", {}) if isinstance(release_contract, dict) else {}
    require(
        artifacts.get("claim_reconciliation_report") == "tests/conformance/claim_reconciliation_report.v1.json",
        "release claim-control contract missing claim reconciliation report artifact",
    )
    require(
        artifacts.get("claim_reconciliation_checker") == "scripts/check_claim_reconciliation.sh",
        "release claim-control contract missing claim reconciliation checker artifact",
    )
    require("claim_reconciliation_gate_passes" in json.dumps(release_contract), "release claim-control contract missing gate test ref")
    require("claim_reconciliation_bound" in release_checker, "release claim-control checker missing claim_reconciliation_bound event")


def validate_e2e(section: dict[str, Any], paths: dict[str, pathlib.Path]) -> list[str]:
    artifacts = section.get("required_artifacts")
    if not isinstance(artifacts, list):
        err("e2e_primary.required_artifacts must be a list")
        artifacts = []
    got = {
        artifact.get("artifact")
        for artifact in artifacts
        if isinstance(artifact, dict) and isinstance(artifact.get("artifact"), str)
    }
    require(got == EXPECTED_E2E_ARTIFACTS, f"e2e artifacts mismatch: got {sorted(got)}")
    validate_rch_commands(section, "e2e_primary")
    report_summary = validate_report(paths, section.get("required_report_contract", {}))
    validate_gate_wrapper(paths)
    validate_docs_and_release_links(paths)
    return sorted(EXPECTED_E2E_ARTIFACTS), report_summary


def validate_manifest(manifest: dict[str, Any], paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
    require(manifest.get("bead") == EXPECTED_BEAD, "bead mismatch")
    require(manifest.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD, "completion_debt_bead mismatch")

    debt = manifest.get("completion_debt")
    if not isinstance(debt, dict):
        err("completion_debt must be an object")
        debt = {}
    require(debt.get("missing_items_closed") == EXPECTED_MISSING_ITEMS, "missing_items_closed mismatch")

    surface = manifest.get("claim_reconciliation_surface")
    if not isinstance(surface, dict):
        err("claim_reconciliation_surface must be an object")
        surface = {}
    require(surface.get("input_artifacts") == EXPECTED_INPUT_ARTIFACTS, "claim_reconciliation_surface input_artifacts mismatch")
    require(surface.get("env_overrides") == EXPECTED_ENV_OVERRIDES, "claim_reconciliation_surface env_overrides mismatch")

    evidence = manifest.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        err("completion_debt_evidence must be an object")
        evidence = {}
    require(set(evidence) == {"unit_primary", "e2e_primary"}, f"completion_debt_evidence keys mismatch: {sorted(evidence)}")

    unit_section = evidence.get("unit_primary", {})
    e2e_section = evidence.get("e2e_primary", {})
    if not isinstance(unit_section, dict):
        err("unit_primary must be an object")
        unit_section = {}
    if not isinstance(e2e_section, dict):
        err("e2e_primary must be an object")
        e2e_section = {}

    engine_functions = validate_engine_functions(unit_section, paths)
    unit_bindings = validate_refs(unit_section, paths)
    e2e_artifacts, report_summary = validate_e2e(e2e_section, paths)

    append_event(
        "claim_reconciliation_completion.bindings",
        "fail" if errors else "pass",
        {
            "engine_functions": len(engine_functions),
            "unit_bindings": len(unit_bindings),
            "e2e_artifacts": len(e2e_artifacts),
            "input_artifacts": len(EXPECTED_INPUT_ARTIFACTS),
        },
    )

    artifact_hashes = {
        key: sha256_file(path)
        for key, path in sorted(paths.items())
        if key in {
            "claim_reconciliation_engine",
            "claim_reconciliation_gate",
            "claim_reconciliation_report",
            "claim_reconciliation_test",
            "support_matrix",
            "reality_report",
            "replacement_levels",
            "smoke_summary",
            "hard_parts_truth_table",
            "feature_parity",
            "readme",
            "completion_checker",
            "completion_test",
        }
    }

    return {
        "engine_functions": engine_functions,
        "unit_bindings": unit_bindings,
        "e2e_artifacts": e2e_artifacts,
        "input_artifacts": EXPECTED_INPUT_ARTIFACTS,
        "report_contract": report_summary,
        "source_summary": {"artifact_hashes": artifact_hashes},
    }


manifest = load_json(CONTRACT_PATH, "contract")
paths = validate_source_artifacts(manifest if isinstance(manifest, dict) else {})
summary: dict[str, Any] = {}
if isinstance(manifest, dict) and paths:
    summary = validate_manifest(manifest, paths)

status = "fail" if errors else "pass"
append_event(
    "claim_reconciliation_completion.final",
    status,
    {"error_count": len(errors), "input_artifact_count": len(EXPECTED_INPUT_ARTIFACTS)},
)

report = {
    "schema_version": "claim_reconciliation_completion_contract.report.v1",
    "status": status,
    "bead": EXPECTED_COMPLETION_BEAD,
    "source_bead": EXPECTED_BEAD,
    "contract": rel(CONTRACT_PATH),
    "errors": errors,
    **summary,
}
REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG_PATH.write_text(
    "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
    encoding="utf-8",
)

if errors:
    print(f"claim reconciliation completion contract failed: {REPORT_PATH}", file=sys.stderr)
    for message in errors:
        print(f"  - {message}", file=sys.stderr)
    sys.exit(1)

print(f"claim reconciliation completion contract passed: {REPORT_PATH}")
PY
