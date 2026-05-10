#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_PATH="${STRUCTURED_LOG_ARTIFACT_INDEX_CONTRACT:-${ROOT_DIR}/tests/conformance/structured_log_artifact_index_completion_contract.v1.json}"
REPORT_PATH="${STRUCTURED_LOG_ARTIFACT_INDEX_REPORT:-${ROOT_DIR}/target/conformance/structured_log_artifact_index_completion_contract.report.json}"
LOG_PATH="${STRUCTURED_LOG_ARTIFACT_INDEX_LOG:-${ROOT_DIR}/target/conformance/structured_log_artifact_index_completion_contract.jsonl}"

mkdir -p "$(dirname -- "${REPORT_PATH}")" "$(dirname -- "${LOG_PATH}")"

python3 - "${ROOT_DIR}" "${CONTRACT_PATH}" "${REPORT_PATH}" "${LOG_PATH}" <<'PY'
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(sys.argv[1])
CONTRACT = Path(sys.argv[2])
REPORT = Path(sys.argv[3])
LOG = Path(sys.argv[4])
START_NS = time.monotonic_ns()

EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "migrations.primary",
    "telemetry.primary",
}

REQUIRED_TRIAGE_KEYS = {
    "trace_id",
    "span_id",
    "controller_id",
    "decision_id",
    "policy_id",
    "evidence_seqno",
    "artifact_refs",
    "failure_signature",
}

REQUIRED_ARTIFACT_INDEX_FIELDS = {
    "index_version",
    "run_id",
    "bead_id",
    "generated_utc",
    "artifacts",
}

REQUIRED_ARTIFACT_ENTRY_FIELDS = {"path", "kind", "sha256"}
REQUIRED_JOIN_KEYS = {
    "trace_ids",
    "span_ids",
    "decision_ids",
    "policy_ids",
    "evidence_seqnos",
}
REQUIRED_LEGACY_ALIASES = {
    "trace_id",
    "span_id",
    "decision_id",
    "policy_id",
    "evidence_seqno",
}
REQUIRED_MIGRATION_CASES = {
    "legacy_run_id_default",
    "legacy_generated_utc_default",
    "legacy_trace_id_alias",
    "legacy_span_id_alias",
    "legacy_decision_id_alias",
    "legacy_policy_id_alias",
    "legacy_evidence_seqno_alias",
    "canonical_reserialize",
}
REQUIRED_TELEMETRY_FIELDS = {
    "trace_id",
    "span_id",
    "controller_id",
    "decision_id",
    "policy_id",
    "evidence_seqno",
    "artifact_refs",
    "failure_signature",
    "latency_ns",
    "source_commit",
}
REQUIRED_TELEMETRY_EVENTS = {
    "structured_log_artifact_index_completion_contract_validated",
    "structured_log_artifact_index_completion_contract_failed",
}


def source_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "--short=12", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def rel_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def read_text(rel: str, errors: list[str]) -> str:
    path = ROOT / rel
    if not path.exists():
        errors.append(f"missing path: {rel}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        errors.append(f"{rel} is not UTF-8: {exc}")
        return ""


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def list_values(value) -> list:
    return value if isinstance(value, list) else []


def string_set(value) -> set[str]:
    return {item for item in list_values(value) if isinstance(item, str)}


def validate_file_ref(ref: dict, errors: list[str]) -> None:
    path = ref.get("path")
    line = ref.get("line")
    anchor = ref.get("anchor")
    if not isinstance(path, str):
        errors.append(f"implementation ref missing path: {ref!r}")
        return
    text = read_text(path, errors)
    if not text:
        return
    lines = text.splitlines()
    require(isinstance(line, int), f"{path} ref line is not an integer", errors)
    if isinstance(line, int):
        require(1 <= line <= len(lines), f"{path}:{line} outside 1..{len(lines)}", errors)
    if isinstance(anchor, str) and anchor:
        require(anchor in text, f"{path} missing anchor {anchor!r}", errors)


def validate_source_anchors(manifest: dict, errors: list[str]) -> None:
    source_paths = manifest.get("source_paths", {})
    anchors_by_source = manifest.get("source_anchors", {})
    require(isinstance(source_paths, dict), "source_paths must be an object", errors)
    require(isinstance(anchors_by_source, dict), "source_anchors must be an object", errors)
    for source, anchors in anchors_by_source.items():
        rel = source_paths.get(source)
        require(isinstance(rel, str), f"source path missing for {source}", errors)
        if not isinstance(rel, str):
            continue
        text = read_text(rel, errors)
        for anchor in list_values(anchors):
            require(isinstance(anchor, str), f"non-string anchor in {source}", errors)
            if isinstance(anchor, str):
                require(anchor in text, f"{rel} missing source anchor {anchor!r}", errors)


def validate_test_refs(manifest: dict, coverage: list[dict], errors: list[str]) -> int:
    source_paths = manifest.get("source_paths", {})
    texts: dict[str, str] = {}
    count = 0
    for section in coverage:
        for ref in list_values(section.get("test_refs")):
            name = ref.get("name") if isinstance(ref, dict) else None
            source = ref.get("source") if isinstance(ref, dict) else None
            require(isinstance(name, str), f"test ref missing name: {ref!r}", errors)
            require(isinstance(source, str), f"test ref missing source: {ref!r}", errors)
            if not isinstance(name, str) or not isinstance(source, str):
                continue
            rel = source_paths.get(source)
            require(isinstance(rel, str), f"test ref {name} has unknown source {source}", errors)
            if not isinstance(rel, str):
                continue
            text = texts.setdefault(rel, read_text(rel, errors))
            require(f"fn {name}(" in text, f"{rel} missing test function fn {name}(", errors)
            count += 1
    return count


def validate_log_schema(manifest: dict, errors: list[str]) -> None:
    source_paths = manifest.get("source_paths", {})
    schema_rel = source_paths.get("artifact_schema")
    require(isinstance(schema_rel, str), "artifact_schema source path missing", errors)
    if not isinstance(schema_rel, str):
        return
    schema = load_json(ROOT / schema_rel)
    artifact_schema = schema.get("artifact_index_schema")
    require(isinstance(artifact_schema, dict), "log_schema missing artifact_index_schema", errors)
    required_fields = set((artifact_schema or {}).get("required_fields", {}).keys())
    require(
        REQUIRED_ARTIFACT_INDEX_FIELDS <= required_fields,
        f"artifact_index_schema missing fields {sorted(REQUIRED_ARTIFACT_INDEX_FIELDS - required_fields)}",
        errors,
    )
    artifacts = (((artifact_schema or {}).get("required_fields") or {}).get("artifacts") or {})
    props = (((artifacts.get("items") or {}).get("properties")) or {})
    entry_required = set((artifacts.get("items") or {}).get("required") or [])
    require(
        REQUIRED_ARTIFACT_ENTRY_FIELDS <= entry_required,
        f"artifact entry schema missing required fields {sorted(REQUIRED_ARTIFACT_ENTRY_FIELDS - entry_required)}",
        errors,
    )
    join_props = set((((props.get("join_keys") or {}).get("properties")) or {}).keys())
    require(
        REQUIRED_JOIN_KEYS <= join_props,
        f"join_keys schema missing {sorted(REQUIRED_JOIN_KEYS - join_props)}",
        errors,
    )
    example = ((schema.get("examples") or {}).get("artifact_index") or {})
    require(example.get("index_version") == 1, "artifact_index example must use index_version=1", errors)
    require(isinstance(example.get("artifacts"), list), "artifact_index example missing artifacts array", errors)
    first_artifact = (example.get("artifacts") or [{}])[0]
    first_join = first_artifact.get("join_keys") or {}
    require(
        REQUIRED_JOIN_KEYS <= set(first_join.keys()),
        f"artifact_index example missing join keys {sorted(REQUIRED_JOIN_KEYS - set(first_join.keys()))}",
        errors,
    )


def validate_contract(manifest: dict, errors: list[str]) -> dict:
    require(
        manifest.get("schema_version") == "structured_log_artifact_index_completion_contract.v1",
        "unexpected schema_version",
        errors,
    )
    require(manifest.get("bead") == "bd-w2c3.9.3", "unexpected bead id", errors)
    require(
        manifest.get("completion_debt_bead") == "bd-w2c3.9.3.1",
        "unexpected completion debt bead id",
        errors,
    )

    for ref in list_values(manifest.get("implementation_refs")):
        if isinstance(ref, dict):
            validate_file_ref(ref, errors)
        else:
            errors.append(f"implementation ref is not an object: {ref!r}")

    validate_source_anchors(manifest, errors)
    validate_log_schema(manifest, errors)

    triage_keys = string_set((manifest.get("one_command_triage") or {}).get("join_keys"))
    require(
        REQUIRED_TRIAGE_KEYS <= triage_keys,
        f"one-command triage missing keys {sorted(REQUIRED_TRIAGE_KEYS - triage_keys)}",
        errors,
    )

    contract = manifest.get("artifact_index_contract") or {}
    require(
        REQUIRED_ARTIFACT_INDEX_FIELDS <= string_set(contract.get("required_fields")),
        "artifact_index_contract missing required top-level fields",
        errors,
    )
    require(
        REQUIRED_ARTIFACT_ENTRY_FIELDS <= string_set(contract.get("artifact_required_fields")),
        "artifact_index_contract missing artifact entry fields",
        errors,
    )
    require(
        REQUIRED_JOIN_KEYS <= string_set(contract.get("join_key_fields")),
        "artifact_index_contract missing canonical join key fields",
        errors,
    )
    require(
        REQUIRED_LEGACY_ALIASES <= string_set(contract.get("legacy_join_key_aliases")),
        "artifact_index_contract missing legacy alias fields",
        errors,
    )

    coverage = list_values(manifest.get("completion_coverage"))
    coverage_by_id = {
        section.get("missing_item_id"): section
        for section in coverage
        if isinstance(section, dict) and isinstance(section.get("missing_item_id"), str)
    }
    missing_ids = EXPECTED_MISSING_ITEMS - set(coverage_by_id.keys())
    extra_ids = set(coverage_by_id.keys()) - EXPECTED_MISSING_ITEMS
    require(not missing_ids, f"completion coverage missing ids {sorted(missing_ids)}", errors)
    require(not extra_ids, f"completion coverage has unexpected ids {sorted(extra_ids)}", errors)
    for item_id, section in coverage_by_id.items():
        require(section.get("status") == "covered", f"{item_id} status is not covered", errors)
        require(
            isinstance(section.get("validation_command"), str)
            and "rch exec" in section["validation_command"] or item_id in {"tests.conformance.primary", "telemetry.primary"},
            f"{item_id} validation command must be an rch cargo command or checker command",
            errors,
        )
    test_ref_count = validate_test_refs(manifest, coverage, errors)

    migration = coverage_by_id.get("migrations.primary") or {}
    migration_cases = string_set(migration.get("migration_cases"))
    require(
        REQUIRED_MIGRATION_CASES <= migration_cases,
        f"migration coverage missing cases {sorted(REQUIRED_MIGRATION_CASES - migration_cases)}",
        errors,
    )

    telemetry = coverage_by_id.get("telemetry.primary") or {}
    telemetry_fields = string_set(telemetry.get("required_fields"))
    telemetry_events = string_set(telemetry.get("events"))
    require(
        REQUIRED_TELEMETRY_FIELDS <= telemetry_fields,
        f"telemetry coverage missing fields {sorted(REQUIRED_TELEMETRY_FIELDS - telemetry_fields)}",
        errors,
    )
    require(
        REQUIRED_TELEMETRY_EVENTS <= telemetry_events,
        f"telemetry coverage missing events {sorted(REQUIRED_TELEMETRY_EVENTS - telemetry_events)}",
        errors,
    )

    artifact_refs = []
    for section in coverage:
        if not isinstance(section, dict):
            continue
        artifact_refs.extend(item for item in list_values(section.get("artifact_refs")) if isinstance(item, str))
    for artifact in artifact_refs:
        if not artifact.startswith("target/"):
            require((ROOT / artifact).exists(), f"artifact ref missing from repo: {artifact}", errors)

    return {
        "missing_items_covered": len(set(coverage_by_id.keys()) & EXPECTED_MISSING_ITEMS),
        "test_ref_count": test_ref_count,
        "artifact_ref_count": len(artifact_refs),
        "telemetry_field_count": len(telemetry_fields),
        "migration_case_count": len(migration_cases),
        "coverage_ids": sorted(coverage_by_id.keys()),
        "artifact_refs": artifact_refs,
        "telemetry_fields": sorted(telemetry_fields),
    }


def write_outputs(manifest: dict | None, errors: list[str], metrics: dict) -> None:
    elapsed_ns = max(1, time.monotonic_ns() - START_NS)
    ok = not errors
    commit = source_commit()
    bead = manifest.get("bead") if isinstance(manifest, dict) else "bd-w2c3.9.3"
    completion_bead = (
        manifest.get("completion_debt_bead")
        if isinstance(manifest, dict)
        else "bd-w2c3.9.3.1"
    )
    report = {
        "schema_version": "structured_log_artifact_index_completion_contract.report.v1",
        "status": "pass" if ok else "fail",
        "bead": bead,
        "completion_debt_bead": completion_bead,
        "source_commit": commit,
        "contract_path": rel_path(CONTRACT),
        "report_path": rel_path(REPORT),
        "log_path": rel_path(LOG),
        "latency_ns": elapsed_ns,
        "failure_signature": "none" if ok else "structured_log_artifact_index_contract_invalid",
        "errors": errors,
        "summary": metrics,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    required_refs = [
        rel_path(CONTRACT),
        rel_path(REPORT),
        rel_path(LOG),
        "tests/conformance/log_schema.json",
        "crates/frankenlibc-harness/src/structured_log.rs",
    ]
    for artifact in metrics.get("artifact_refs", []):
        if artifact not in required_refs:
            required_refs.append(artifact)
    log_row = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "trace_id": f"{completion_bead}::artifact-index-contract::001",
        "span_id": "structured_log::artifact_index::completion_contract",
        "level": "info" if ok else "error",
        "event": (
            "structured_log_artifact_index_completion_contract_validated"
            if ok
            else "structured_log_artifact_index_completion_contract_failed"
        ),
        "bead_id": bead,
        "stream": "conformance",
        "gate": "structured_log_artifact_index_completion_contract",
        "mode": "strict",
        "runtime_mode": "strict",
        "api_family": "harness",
        "symbol": "structured_log_artifact_index",
        "decision_path": "contract->implementation_refs->schema->tests->telemetry",
        "healing_action": "None",
        "controller_id": "structured_log_artifact_index_completion_contract.v1",
        "decision_id": 9303001,
        "policy_id": 9303,
        "evidence_seqno": 1,
        "outcome": "pass" if ok else "fail",
        "errno": 0 if ok else 1,
        "latency_ns": elapsed_ns,
        "source_commit": commit,
        "target_dir": os.environ.get("CARGO_TARGET_DIR", "target"),
        "failure_signature": "none" if ok else "structured_log_artifact_index_contract_invalid",
        "artifact_refs": required_refs,
        "details": {
            "completion_debt_bead": completion_bead,
            "missing_items_covered": metrics.get("missing_items_covered", 0),
            "test_ref_count": metrics.get("test_ref_count", 0),
            "telemetry_fields": metrics.get("telemetry_fields", []),
            "errors": errors,
        },
    }
    LOG.write_text(json.dumps(log_row, sort_keys=True) + "\n", encoding="utf-8")


errors: list[str] = []
metrics: dict = {}
manifest = None
try:
    manifest = load_json(CONTRACT)
    metrics = validate_contract(manifest, errors)
except Exception as exc:
    errors.append(f"checker exception: {type(exc).__name__}: {exc}")

write_outputs(manifest, errors, metrics)
if errors:
    for error in errors:
        print(f"structured-log artifact-index contract error: {error}", file=sys.stderr)
    sys.exit(1)

print(f"structured-log artifact-index completion contract passed: {REPORT}")
PY
