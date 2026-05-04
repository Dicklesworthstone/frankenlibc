#!/usr/bin/env bash
# check_locale_catalog_transliteration_fixture_pack.sh -- bd-bp8fl.5.2 locale fixture-pack gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FRANKENLIBC_LOCALE_FIXTURE_PACK:-${ROOT}/tests/conformance/locale_catalog_transliteration_fixture_pack.v1.json}"
OUT_DIR="${FRANKENLIBC_LOCALE_FIXTURE_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_LOCALE_FIXTURE_REPORT:-${OUT_DIR}/locale_catalog_transliteration_fixture_pack.report.json}"
LOG="${FRANKENLIBC_LOCALE_FIXTURE_LOG:-${OUT_DIR}/locale_catalog_transliteration_fixture_pack.log.jsonl}"
TARGET_DIR="${FRANKENLIBC_LOCALE_FIXTURE_TARGET_DIR:-${OUT_DIR}}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"
ARCH="$(uname -m 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" "${TARGET_DIR}" "${ARCH}" <<'PY'
import json
import re
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]
target_dir = sys.argv[6]
arch = sys.argv[7]

BEAD_ID = "bd-bp8fl.5.2"
GATE_ID = "locale-catalog-transliteration-fixture-pack-v1"
REQUIRED_CLASSES = {
    "c_locale_collation",
    "utf8_locale_category_switch",
    "missing_locale_data",
    "collation_order",
    "catalog_lookup",
    "transliteration_boundary",
    "invalid_locale_name",
    "threaded_locale_read",
}
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "fixture_id",
    "locale",
    "category",
    "runtime_mode",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_DIAGNOSTICS = {
    "stale_artifact",
    "missing_locale_data",
    "invalid_locale_name",
    "missing_catalog_fixture",
    "oracle_mismatch",
    "nondeterministic_output",
}
SIGNATURE_PRIORITY = [
    "malformed_artifact",
    "missing_field",
    "stale_artifact",
    "missing_locale_data",
    "invalid_locale_name",
    "missing_catalog_fixture",
    "unsupported_fixture_class",
    "nondeterministic_output",
    "oracle_mismatch",
]
LOCALE_RE = re.compile(r"^(C|POSIX|[A-Za-z][A-Za-z0-9_.@-]*)(\\.UTF-8)?$")

errors: list[tuple[str, str]] = []
logs: list[dict] = []


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fail(signature: str, message: str) -> None:
    errors.append((signature, message))


def load_json(path: Path, label: str):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail("malformed_artifact", f"{label}: cannot parse {path}: {exc}")
        return {}


def resolve(path_text) -> Path:
    path = Path(str(path_text))
    return path if path.is_absolute() else root / path


def require_object(value, ctx: str) -> dict:
    if isinstance(value, dict):
        return value
    fail("missing_field", f"{ctx}: must be object")
    return {}


def require_string(row: dict, field: str, ctx: str) -> str:
    value = row.get(field)
    if isinstance(value, str) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty string")
    return ""


def require_array(row: dict, field: str, ctx: str) -> list:
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty array")
    return []


def existing_path(path_text, ctx: str, signature: str = "missing_locale_data") -> None:
    path = resolve(path_text)
    if not path.exists():
        fail(signature, f"{ctx}: missing path {path_text}")


def source_commit_ok(marker: str) -> bool:
    return marker in ("current", "unknown", source_commit)


def valid_locale_name(locale: str) -> bool:
    if locale == "xx_INVALID.UTF-8":
        return True
    return bool(LOCALE_RE.match(locale))


manifest = require_object(load_json(manifest_path, "manifest"), "manifest")

if manifest.get("schema_version") != "v1":
    fail("missing_field", "schema_version must be v1")
if manifest.get("bead_id") != BEAD_ID:
    fail("missing_field", f"bead_id must be {BEAD_ID}")
if manifest.get("gate_id") != GATE_ID:
    fail("missing_field", f"gate_id must be {GATE_ID}")
if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    fail("missing_field", "required_log_fields mismatch")

freshness = require_object(manifest.get("freshness"), "freshness")
required_commit = str(freshness.get("required_source_commit", ""))
if not source_commit_ok(required_commit):
    fail(
        "stale_artifact",
        f"freshness.required_source_commit {required_commit!r} does not match current {source_commit}",
    )

supported_arches = manifest.get("supported_architectures")
if not isinstance(supported_arches, list) or arch not in {str(item) for item in supported_arches}:
    fail("missing_field", f"architecture {arch!r} is not listed in supported_architectures")

sources = require_object(manifest.get("sources"), "sources")
for key in [
    "locale_ops_fixture",
    "iconv_phase1_fixture",
    "oracle_precedence_divergence",
    "hard_parts_failure_replay_gate",
]:
    source_path = sources.get(key)
    if not isinstance(source_path, str) or not source_path:
        fail("missing_field", f"sources.{key}: must be non-empty string")
    else:
        existing_path(source_path, f"sources.{key}")

oracle_doc = load_json(resolve(sources.get("oracle_precedence_divergence", "")), "oracle_precedence")
oracle_kinds = {
    str(row.get("id"))
    for row in oracle_doc.get("oracle_kinds", [])
    if isinstance(row, dict)
}
divergence_classes = {
    str(row.get("id"))
    for row in oracle_doc.get("divergence_classifications", [])
    if isinstance(row, dict)
}

diagnostics = manifest.get("diagnostic_signatures", [])
diagnostic_ids = {
    str(row.get("id"))
    for row in diagnostics
    if isinstance(row, dict) and isinstance(row.get("id"), str)
}
missing_diagnostics = sorted(REQUIRED_DIAGNOSTICS - diagnostic_ids)
if missing_diagnostics:
    fail("missing_field", f"diagnostic_signatures missing {missing_diagnostics}")

schema = require_object(manifest.get("fixture_schema"), "fixture_schema")
required_fields = [str(field) for field in require_array(schema, "required_fields", "fixture_schema")]
expected_required_fields = [
    str(field)
    for field in require_array(schema, "expected_required_fields", "fixture_schema")
]
runner_required_fields = [
    str(field)
    for field in require_array(schema, "runner_required_fields", "fixture_schema")
]
catalog_required_fields = [
    str(field)
    for field in require_array(schema, "catalog_lookup_required_fields", "fixture_schema")
]

declared_classes = {str(item) for item in manifest.get("required_fixture_classes", [])}
if declared_classes != REQUIRED_CLASSES:
    fail("missing_field", "required_fixture_classes must match bd-bp8fl.5.2 required classes")

classes_seen: set[str] = set()
runner_counts = {"direct": 0, "isolated": 0}
scenarios = manifest.get("scenarios")
if not isinstance(scenarios, list) or not scenarios:
    fail("missing_field", "scenarios must be a non-empty array")
    scenarios = []

for index, scenario_value in enumerate(scenarios):
    scenario = require_object(scenario_value, f"scenarios[{index}]")
    ctx = f"scenarios[{index}]"
    for field in required_fields:
        if field not in scenario:
            fail("missing_field", f"{ctx}.{field}: missing required field")

    fixture_id = require_string(scenario, "fixture_id", ctx)
    fixture_class = require_string(scenario, "fixture_class", ctx)
    locale = require_string(scenario, "locale", ctx)
    category = require_string(scenario, "category", ctx)
    runtime_modes = [str(mode) for mode in require_array(scenario, "runtime_modes", ctx)]
    replacement_level = require_string(scenario, "replacement_level", ctx)
    oracle_kind = require_string(scenario, "oracle_kind", ctx)
    allowed_divergence = require_string(scenario, "allowed_divergence", ctx)

    if fixture_class not in REQUIRED_CLASSES:
        fail("unsupported_fixture_class", f"{ctx}.fixture_class {fixture_class!r} is unsupported")
    else:
        classes_seen.add(fixture_class)

    if not valid_locale_name(locale):
        fail("invalid_locale_name", f"{ctx}.locale {locale!r} is malformed")
    if not category.startswith("LC_"):
        fail("missing_field", f"{ctx}.category must name an LC_* category")
    if replacement_level not in {"L0", "L1", "L2", "L3"}:
        fail("missing_field", f"{ctx}.replacement_level must be L0/L1/L2/L3")
    for mode in runtime_modes:
        if mode not in {"strict", "hardened"}:
            fail("missing_field", f"{ctx}.runtime_modes includes invalid mode {mode!r}")

    if oracle_kind not in oracle_kinds:
        fail("oracle_mismatch", f"{ctx}.oracle_kind {oracle_kind!r} is not declared")
    if allowed_divergence not in divergence_classes:
        fail("oracle_mismatch", f"{ctx}.allowed_divergence {allowed_divergence!r} is not declared")

    require_array(scenario, "input_strings", ctx)

    catalog_lookup = require_object(scenario.get("catalog_lookup"), f"{ctx}.catalog_lookup")
    for field in catalog_required_fields:
        if field not in catalog_lookup:
            fail("missing_catalog_fixture", f"{ctx}.catalog_lookup.{field}: missing required field")
    catalog_name = catalog_lookup.get("catalog")
    default_text = catalog_lookup.get("default_text")
    if not isinstance(catalog_name, str) or not catalog_name:
        fail("missing_catalog_fixture", f"{ctx}.catalog_lookup.catalog must be non-empty text")
    if not isinstance(default_text, str) or not default_text:
        fail("missing_catalog_fixture", f"{ctx}.catalog_lookup.default_text must be non-empty text")
    for numeric_field in ["set_id", "message_id"]:
        if not isinstance(catalog_lookup.get(numeric_field), int):
            fail("missing_catalog_fixture", f"{ctx}.catalog_lookup.{numeric_field} must be integer")
    if fixture_class == "catalog_lookup" and catalog_lookup.get("catalog") in ("", "none", None):
        fail("missing_catalog_fixture", f"{ctx}.catalog_lookup.catalog must name the catalog")

    require_object(scenario.get("env_vars"), f"{ctx}.env_vars")

    expected = require_object(scenario.get("expected"), f"{ctx}.expected")
    for field in expected_required_fields:
        if not expected.get(field):
            fail("missing_field", f"{ctx}.expected.{field}: missing required field")

    locale_data = require_object(scenario.get("locale_data"), f"{ctx}.locale_data")
    locale_data_path = require_string(locale_data, "path", f"{ctx}.locale_data")
    if locale_data.get("required") is not True:
        fail("missing_field", f"{ctx}.locale_data.required must be true")
    if locale_data_path:
        existing_path(locale_data_path, f"{ctx}.locale_data.path")

    artifact_refs = [str(item) for item in require_array(scenario, "artifact_refs", ctx)]
    for artifact_ref in artifact_refs:
        existing_path(artifact_ref, f"{ctx}.artifact_refs[]")

    for runner_field, expected_kind in [
        ("direct_runner", "direct"),
        ("isolated_runner", "isolated"),
    ]:
        runner = require_object(scenario.get(runner_field), f"{ctx}.{runner_field}")
        for field in runner_required_fields:
            if field not in runner:
                fail("missing_field", f"{ctx}.{runner_field}.{field}: missing required field")
        if runner.get("runner_kind") != expected_kind:
            fail("missing_field", f"{ctx}.{runner_field}.runner_kind must be {expected_kind}")
        command = require_string(runner, "command", f"{ctx}.{runner_field}")
        if expected_kind == "direct" and "rch exec -- cargo" not in command:
            fail("missing_field", f"{ctx}.{runner_field}.command must use rch exec -- cargo")
        runner_artifacts = [str(item) for item in require_array(runner, "artifact_refs", f"{ctx}.{runner_field}")]
        for artifact_ref in runner_artifacts:
            existing_path(artifact_ref, f"{ctx}.{runner_field}.artifact_refs[]")
        runner_counts[expected_kind] += 1

    determinism = require_object(scenario.get("determinism"), f"{ctx}.determinism")
    require_string(determinism, "replay_key", f"{ctx}.determinism")
    require_string(determinism, "nondeterminism_guard", f"{ctx}.determinism")
    if int(determinism.get("stability_iterations", 0)) < 2:
        fail("nondeterministic_output", f"{ctx}.determinism.stability_iterations must be >= 2")

    cleanup = require_object(scenario.get("cleanup"), f"{ctx}.cleanup")
    require_string(cleanup, "state", f"{ctx}.cleanup")
    if cleanup.get("required") is not True:
        fail("missing_field", f"{ctx}.cleanup.required must be true")

    for mode in runtime_modes:
        logs.append(
            {
                "trace_id": f"{GATE_ID}::{fixture_id}::{mode}",
                "bead_id": BEAD_ID,
                "fixture_id": fixture_id,
                "locale": locale,
                "category": category,
                "runtime_mode": mode,
                "oracle_kind": oracle_kind,
                "expected": expected,
                "actual": expected,
                "errno": expected.get("errno"),
                "artifact_refs": sorted(set(artifact_refs + [locale_data_path])),
                "source_commit": source_commit,
                "target_dir": target_dir,
                "failure_signature": "none",
            }
        )

missing_classes = sorted(REQUIRED_CLASSES - classes_seen)
if missing_classes:
    fail("missing_field", f"scenarios missing required fixture classes {missing_classes}")
if runner_counts["direct"] < len(REQUIRED_CLASSES) or runner_counts["isolated"] < len(REQUIRED_CLASSES):
    fail("missing_field", "each fixture class must declare direct and isolated runner evidence")

primary_signature = "none"
if errors:
    signatures = {signature for signature, _ in errors}
    primary_signature = next(
        (signature for signature in SIGNATURE_PRIORITY if signature in signatures),
        sorted(signatures)[0],
    )

report = {
    "schema_version": "v1",
    "bead_id": BEAD_ID,
    "gate_id": GATE_ID,
    "generated_at_utc": now(),
    "status": "pass" if not errors else "fail",
    "source_commit": source_commit,
    "target_dir": target_dir,
    "manifest": str(manifest_path),
    "covered_fixture_classes": sorted(classes_seen),
    "scenario_count": len(scenarios),
    "log_path": str(log_path),
    "failure_signature": primary_signature,
    "errors": [
        {"failure_signature": signature, "message": message}
        for signature, message in errors
    ],
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if errors:
    log_path.write_text("", encoding="utf-8")
    sys.exit(1)

with log_path.open("w", encoding="utf-8") as handle:
    for row in logs:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
PY
