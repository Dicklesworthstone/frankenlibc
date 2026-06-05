#!/usr/bin/env bash
# check_locale_iconv_completion_contract.sh - bd-1j4.4.1 completion evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_LOCALE_ICONV_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/locale_iconv_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_LOCALE_ICONV_COMPLETION_REPORT:-${ROOT}/target/conformance/locale_iconv_completion_contract.report.json}"
LOG="${FRANKENLIBC_LOCALE_ICONV_COMPLETION_LOG:-${ROOT}/target/conformance/locale_iconv_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]

ORIGINAL_BEAD = "bd-1j4.4"
COMPLETION_DEBT_BEAD = "bd-1j4.4.1"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_EVENTS = {
    "locale_iconv_completion.source_ref",
    "locale_iconv_completion.missing_item_bound",
    "locale_iconv_completion.fuzz_corpus_bound",
    "locale_iconv_completion.conformance_artifact_bound",
    "locale_iconv_completion.table_checksum_bound",
    "locale_iconv_completion.completion_contract_validated",
}
REQUIRED_REPORT_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "missing_items",
    "artifact_refs",
    "unit_test_ref_count",
    "e2e_artifact_count",
    "fuzz_corpus_seed_count",
    "conformance_test_ref_count",
    "conformance_artifact_count",
    "table_checksum_count",
    "failure_signature",
}
REQUIRED_ICONV_CODECS = {"UTF-8", "ISO-8859-1", "UTF-16LE", "UTF-32"}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha_json(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def workspace_path(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def require_dict(value: Any, label: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return {}
    return value


def require_list(value: Any, label: str, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{label} must be an array")
        return []
    return value


def require_string_list(value: Any, label: str, errors: list[str]) -> list[str]:
    items = require_list(value, label, errors)
    result: list[str] = []
    for index, item in enumerate(items):
        if isinstance(item, str) and item:
            result.append(item)
        else:
            errors.append(f"{label}[{index}] must be a non-empty string")
    return result


def load_json(path: Path, label: str, errors: list[str]) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(data, dict):
        errors.append(f"{label} must be a JSON object")
        return {}
    return data


def row(event: str, status: str = "pass", **fields: Any) -> dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "trace_id": f"{COMPLETION_DEBT_BEAD}:locale-iconv-completion",
        "event": event,
        "completion_debt_bead": COMPLETION_DEBT_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": source_commit,
        "status": status,
        **fields,
    }


def validate_line_ref(ref: Any, label: str, errors: list[str]) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"{label} must be file:line")
        return
    path_text, line_text = ref.rsplit(":", 1)
    if not line_text.isdigit() or int(line_text) <= 0:
        errors.append(f"{label} has invalid line number: {ref}")
        return
    path = workspace_path(path_text)
    if not path.is_file():
        errors.append(f"{label} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        errors.append(f"{label} references line past EOF: {ref}")
    elif not lines[line_number - 1].strip():
        errors.append(f"{label} references blank line: {ref}")


def validate_artifacts(
    evidence: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]
) -> tuple[dict[str, str], dict[str, Path]]:
    artifacts = require_dict(evidence.get("artifacts"), "completion_debt_evidence.artifacts", errors)
    directory_artifacts = set(
        require_string_list(evidence.get("directory_artifacts"), "directory_artifacts", errors)
    )
    texts: dict[str, str] = {}
    paths: dict[str, Path] = {}
    for artifact_id, path_value in artifacts.items():
        if not isinstance(path_value, str) or not path_value:
            errors.append(f"artifact {artifact_id} path must be a non-empty string")
            continue
        path = workspace_path(path_value)
        paths[artifact_id] = path
        if artifact_id in directory_artifacts:
            if not path.is_dir():
                errors.append(f"artifact {artifact_id} missing directory: {path_value}")
                continue
        else:
            if not path.is_file():
                errors.append(f"artifact {artifact_id} missing file: {path_value}")
                continue
            try:
                texts[artifact_id] = path.read_text(encoding="utf-8")
            except Exception as exc:
                errors.append(f"artifact {artifact_id} unreadable: {path_value}: {exc}")
                continue
        rows.append(row("locale_iconv_completion.source_ref", artifact_id=artifact_id, path=path_value))

    for ref in require_list(evidence.get("implementation_refs"), "implementation_refs", errors):
        validate_line_ref(ref, "implementation_refs", errors)

    needles = require_dict(evidence.get("source_needles"), "source_needles", errors)
    for artifact_id, required_needles in needles.items():
        text = texts.get(artifact_id, "")
        for needle in require_string_list(required_needles, f"source_needles.{artifact_id}", errors):
            if needle not in text:
                errors.append(f"{artifact_id} missing required needle {needle!r}")
    return texts, paths


def validate_missing_bindings(
    evidence: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]
) -> list[str]:
    bindings = require_list(evidence.get("missing_item_bindings"), "missing_item_bindings", errors)
    actual: set[str] = set()
    sections: set[str] = set()
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            errors.append(f"missing_item_bindings[{index}] must be an object")
            continue
        item_id = binding.get("missing_item_id")
        section = binding.get("evidence_section")
        if isinstance(item_id, str):
            actual.add(item_id)
        else:
            errors.append(f"missing_item_bindings[{index}].missing_item_id missing")
        if isinstance(section, str):
            sections.add(section)
        else:
            errors.append(f"missing_item_bindings[{index}].evidence_section missing")
        if isinstance(item_id, str) and isinstance(section, str):
            rows.append(row("locale_iconv_completion.missing_item_bound", item_id=item_id, section=section))
    if actual != REQUIRED_MISSING_ITEMS:
        errors.append(f"missing items must be {sorted(REQUIRED_MISSING_ITEMS)}, got {sorted(actual)}")
    for required_section in [
        "unit_primary",
        "e2e_primary",
        "fuzz_primary",
        "conformance_primary",
        "telemetry_primary",
    ]:
        if required_section not in sections or not isinstance(evidence.get(required_section), dict):
            errors.append(f"{required_section} must be bound and present")
    return sorted(actual)


def validate_test_refs(section: dict[str, Any], texts: dict[str, str], label: str, errors: list[str]) -> int:
    count = 0
    for index, ref in enumerate(require_list(section.get("required_test_refs"), f"{label}.required_test_refs", errors)):
        if not isinstance(ref, dict):
            errors.append(f"{label}.required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not isinstance(name, str):
            errors.append(f"{label}.required_test_refs[{index}] source/name missing")
            continue
        if name not in texts.get(source, ""):
            errors.append(f"{label} test ref {name!r} missing from source {source}")
        count += 1
    return count


def validate_required_artifacts(
    section: dict[str, Any],
    paths: dict[str, Path],
    label: str,
    errors: list[str],
    rows: list[dict[str, Any]] | None = None,
) -> int:
    count = 0
    for artifact_id in require_string_list(section.get("required_artifacts"), f"{label}.required_artifacts", errors):
        if artifact_id not in paths:
            errors.append(f"{label} references unknown artifact {artifact_id}")
        elif not paths[artifact_id].exists():
            errors.append(f"{label} artifact {artifact_id} does not exist")
        else:
            count += 1
            if rows is not None:
                rows.append(row("locale_iconv_completion.conformance_artifact_bound", artifact_id=artifact_id))
    return count


def validate_rch_commands(section: dict[str, Any], label: str, errors: list[str]) -> list[str]:
    commands = require_string_list(section.get("commands"), f"{label}.commands", errors)
    for command in commands:
        if (
            "cargo " in command
            and not command.startswith("rch exec --")
            and not command.startswith("cargo fuzz run ")
        ):
            errors.append(f"{label} cargo command must use rch: {command}")
    return commands


def validate_fuzz(
    evidence: dict[str, Any],
    paths: dict[str, Path],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> int:
    fuzz = require_dict(evidence.get("fuzz_primary"), "fuzz_primary", errors)
    commands = validate_rch_commands(fuzz, "fuzz_primary", errors)
    if not any("fuzz_iconv" in command for command in commands):
        errors.append("fuzz_primary.commands must include fuzz_iconv")
    if not any("fuzz_locale" in command for command in commands):
        errors.append("fuzz_primary.commands must include fuzz_locale")
    requirements = require_list(fuzz.get("corpus_requirements"), "fuzz_primary.corpus_requirements", errors)
    seen: set[str] = set()
    total = 0
    for index, requirement in enumerate(requirements):
        if not isinstance(requirement, dict):
            errors.append(f"fuzz_primary.corpus_requirements[{index}] must be an object")
            continue
        artifact_id = requirement.get("artifact")
        min_seed_files = requirement.get("min_seed_files")
        if not isinstance(artifact_id, str) or artifact_id not in paths:
            errors.append(f"fuzz corpus requirements reference unknown artifact {artifact_id!r}")
            continue
        if not isinstance(min_seed_files, int) or min_seed_files <= 0:
            errors.append(f"fuzz corpus requirement {artifact_id} has invalid min_seed_files")
            continue
        seed_count = sum(1 for child in paths[artifact_id].iterdir() if child.is_file())
        if seed_count < min_seed_files:
            errors.append(
                f"fuzz corpus {artifact_id} has {seed_count} seeds, needs at least {min_seed_files}"
            )
        seen.add(artifact_id)
        total += seed_count
        rows.append(
            row(
                "locale_iconv_completion.fuzz_corpus_bound",
                artifact_id=artifact_id,
                seed_count=seed_count,
                min_seed_files=min_seed_files,
            )
        )
    if seen != {"fuzz_iconv_corpus", "fuzz_locale_corpus"}:
        errors.append(f"fuzz corpus requirements must bind fuzz_iconv_corpus and fuzz_locale_corpus, got {sorted(seen)}")
    return total


def validate_fixture_matrix(
    conformance: dict[str, Any], paths: dict[str, Path], errors: list[str]
) -> None:
    required_locale = set(
        require_string_list(conformance.get("required_locale_functions"), "conformance_primary.required_locale_functions", errors)
    )
    required_iconv = set(
        require_string_list(conformance.get("required_iconv_functions"), "conformance_primary.required_iconv_functions", errors)
    )
    required_codecs = set(
        require_string_list(conformance.get("required_codecs"), "conformance_primary.required_codecs", errors)
    )
    if required_codecs != REQUIRED_ICONV_CODECS:
        errors.append(f"conformance required codecs must be {sorted(REQUIRED_ICONV_CODECS)}, got {sorted(required_codecs)}")
    errno_values = require_list(conformance.get("required_errno_values"), "conformance_primary.required_errno_values", errors)
    required_errno = {value for value in errno_values if isinstance(value, int)}
    if len(required_errno) != len(errno_values):
        errors.append("conformance_primary.required_errno_values must contain integers")

    locale_fixture = load_json(paths["locale_fixture"], "locale fixture", errors)
    locale_cases = require_list(locale_fixture.get("cases"), "locale_fixture.cases", errors)
    locale_functions = {case.get("function") for case in locale_cases if isinstance(case, dict)}
    locale_modes = {case.get("mode") for case in locale_cases if isinstance(case, dict)}
    if not required_locale.issubset(locale_functions):
        errors.append(f"locale fixture missing functions {sorted(required_locale - locale_functions)}")
    if not {"strict", "hardened"}.issubset(locale_modes):
        errors.append(f"locale fixture must include strict and hardened modes, got {sorted(str(mode) for mode in locale_modes)}")

    iconv_fixture = load_json(paths["iconv_fixture"], "iconv fixture", errors)
    iconv_cases = require_list(iconv_fixture.get("cases"), "iconv_fixture.cases", errors)
    iconv_functions = {case.get("function") for case in iconv_cases if isinstance(case, dict)}
    iconv_modes = {case.get("mode") for case in iconv_cases if isinstance(case, dict)}
    iconv_errno = {case.get("expected_errno") for case in iconv_cases if isinstance(case, dict)}
    if not required_iconv.issubset(iconv_functions):
        errors.append(f"iconv fixture missing functions {sorted(required_iconv - iconv_functions)}")
    if not {"strict", "hardened"}.issubset(iconv_modes):
        errors.append(f"iconv fixture must include strict and hardened modes, got {sorted(str(mode) for mode in iconv_modes)}")
    if not required_errno.issubset(iconv_errno):
        errors.append(f"iconv fixture missing errno values {sorted(required_errno - iconv_errno)}")

    scope = load_json(paths["iconv_scope_ledger"], "iconv scope ledger", errors)
    included = {
        row.get("canonical")
        for row in require_list(scope.get("included_codecs"), "iconv_scope_ledger.included_codecs", errors)
        if isinstance(row, dict)
    }
    if not required_codecs.issubset(included):
        errors.append(f"iconv scope ledger missing codecs {sorted(required_codecs - included)}")
    mapping = require_dict(scope.get("support_matrix_mapping"), "iconv_scope_ledger.support_matrix_mapping", errors)
    if mapping.get("module") != "iconv_abi":
        errors.append(f"iconv scope support module must be iconv_abi, got {mapping.get('module')!r}")
    if set(mapping.get("symbols", [])) != required_iconv:
        errors.append("iconv scope support symbols mismatch")

    breadth = load_json(paths["locale_iconv_breadth_ledger"], "locale/iconv breadth ledger", errors)
    implemented = {
        row.get("canonical")
        for row in require_list(breadth.get("implemented_bootstrap_codecs"), "locale_iconv_breadth_ledger.implemented_bootstrap_codecs", errors)
        if isinstance(row, dict)
    }
    if not required_codecs.issubset(implemented):
        errors.append(f"locale/iconv breadth ledger missing bootstrap codecs {sorted(required_codecs - implemented)}")

    stateful = load_json(paths["iconv_stateful_fixture_pack"], "iconv stateful fixture pack", errors)
    if len(require_list(stateful.get("fixture_rows"), "iconv_stateful_fixture_pack.fixture_rows", errors)) < 10:
        errors.append("iconv stateful fixture pack must contain at least 10 rows")
    locale_catalog = load_json(paths["locale_catalog_fixture_pack"], "locale catalog fixture pack", errors)
    if len(require_list(locale_catalog.get("scenarios"), "locale_catalog_fixture_pack.scenarios", errors)) < 8:
        errors.append("locale catalog fixture pack must contain at least 8 scenarios")


def validate_table_checksums(paths: dict[str, Path], errors: list[str], rows: list[dict[str, Any]]) -> int:
    pack = load_json(paths["iconv_table_pack"], "iconv table pack", errors)
    checksums = load_json(paths["iconv_table_checksums"], "iconv table checksums", errors)
    tables = require_list(pack.get("included_codec_tables"), "iconv_table_pack.included_codec_tables", errors)
    if len(tables) < len(REQUIRED_ICONV_CODECS):
        errors.append(
            f"iconv table pack must contain at least the required bootstrap tables, got {len(tables)}"
        )
    for table in tables:
        if not isinstance(table, dict):
            errors.append("iconv table row must be an object")
            continue
        canonical = table.get("canonical")
        body = dict(table)
        recorded = body.pop("table_sha256", None)
        recomputed = sha_json(body)
        if recorded != recomputed:
            errors.append(f"table digest mismatch for {canonical}")
        rows.append(row("locale_iconv_completion.table_checksum_bound", codec=canonical, digest=recorded))

    pack_body = dict(pack)
    recorded_pack_digest = pack_body.pop("table_pack_sha256", None)
    recomputed_pack_digest = sha_json(pack_body)
    if recorded_pack_digest != recomputed_pack_digest:
        errors.append("table_pack_sha256 mismatch")
    if checksums.get("table_pack_sha256") != recorded_pack_digest:
        errors.append("checksums.table_pack_sha256 must match table pack digest")

    codec_digests = require_dict(checksums.get("codec_table_sha256"), "iconv_table_checksums.codec_table_sha256", errors)
    codec_names = {table.get("canonical") for table in tables if isinstance(table, dict)}
    if not REQUIRED_ICONV_CODECS.issubset(codec_names):
        errors.append(
            f"iconv table codecs must include {sorted(REQUIRED_ICONV_CODECS)}, got {sorted(str(name) for name in codec_names)}"
        )
    codec_digest_names = set(codec_digests)
    if codec_digest_names != codec_names:
        errors.append(
            "iconv checksum manifest codec set must match table pack codec set: "
            f"missing={sorted(str(name) for name in codec_names - codec_digest_names)} "
            f"extra={sorted(str(name) for name in codec_digest_names - codec_names)}"
        )
    for table in tables:
        if isinstance(table, dict):
            canonical = table.get("canonical")
            if codec_digests.get(canonical) != table.get("table_sha256"):
                errors.append(f"checksum manifest mismatch for codec {canonical}")

    checksums_body = dict(checksums)
    recorded_checksums_digest = checksums_body.pop("checksums_sha256", None)
    checksums_body.pop("artifact_paths", None)
    if recorded_checksums_digest != sha_json(checksums_body):
        errors.append("checksums_sha256 mismatch")
    return len(codec_digests)


def validate_telemetry(evidence: dict[str, Any], errors: list[str]) -> None:
    telemetry = require_dict(evidence.get("telemetry_primary"), "telemetry_primary", errors)
    events = set(require_string_list(telemetry.get("required_events"), "telemetry_primary.required_events", errors))
    if not REQUIRED_EVENTS.issubset(events):
        errors.append(f"telemetry events missing {sorted(REQUIRED_EVENTS - events)}")
    fields = set(require_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields", errors))
    if not REQUIRED_REPORT_FIELDS.issubset(fields):
        errors.append(f"telemetry fields missing {sorted(REQUIRED_REPORT_FIELDS - fields)}")


errors: list[str] = []
rows: list[dict[str, Any]] = []
contract = load_json(contract_path, "completion contract", errors)

if contract.get("schema_version") != "locale_iconv_completion_contract.v1":
    errors.append("schema_version must be locale_iconv_completion_contract.v1")
if contract.get("bead") != ORIGINAL_BEAD:
    errors.append(f"bead must be {ORIGINAL_BEAD}")
if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD}")

evidence = require_dict(contract.get("completion_debt_evidence"), "completion_debt_evidence", errors)
texts, paths = validate_artifacts(evidence, errors, rows)
missing_items = validate_missing_bindings(evidence, errors, rows)

unit = require_dict(evidence.get("unit_primary"), "unit_primary", errors)
validate_rch_commands(unit, "unit_primary", errors)
unit_ref_count = validate_test_refs(unit, texts, "unit_primary", errors)
if unit_ref_count < 17:
    errors.append(f"unit_primary must bind at least 17 unit refs, got {unit_ref_count}")

e2e = require_dict(evidence.get("e2e_primary"), "e2e_primary", errors)
e2e_commands = validate_rch_commands(e2e, "e2e_primary", errors)
if not any("check_iconv_locale_family_completion_contract.sh" in command for command in e2e_commands):
    errors.append("e2e_primary.commands must include iconv/locale family completion checker")
e2e_artifact_count = validate_required_artifacts(e2e, paths, "e2e_primary", errors)

fuzz_seed_count = validate_fuzz(evidence, paths, errors, rows)

conformance = require_dict(evidence.get("conformance_primary"), "conformance_primary", errors)
validate_rch_commands(conformance, "conformance_primary", errors)
conformance_artifact_count = validate_required_artifacts(conformance, paths, "conformance_primary", errors, rows)
conformance_ref_count = validate_test_refs(conformance, texts, "conformance_primary", errors)
if conformance_ref_count < 9:
    errors.append(f"conformance_primary must bind at least 9 conformance refs, got {conformance_ref_count}")
validate_fixture_matrix(conformance, paths, errors)
table_checksum_count = validate_table_checksums(paths, errors, rows)

validate_telemetry(evidence, errors)

status = "fail" if errors else "pass"
failure_signature = "locale_iconv_completion_contract_failed" if errors else "none"
report = {
    "schema_version": "locale_iconv_completion_contract.report.v1",
    "timestamp": utc_now(),
    "trace_id": f"{COMPLETION_DEBT_BEAD}:locale-iconv-completion",
    "event": "locale_iconv_completion.completion_contract_validated" if not errors else "locale_iconv_completion.completion_contract_failed",
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "missing_items": missing_items,
    "artifact_refs": sorted(str(path.relative_to(root)) for path in paths.values() if path.exists()),
    "unit_test_ref_count": unit_ref_count,
    "e2e_artifact_count": e2e_artifact_count,
    "fuzz_corpus_seed_count": fuzz_seed_count,
    "conformance_test_ref_count": conformance_ref_count,
    "conformance_artifact_count": conformance_artifact_count,
    "table_checksum_count": table_checksum_count,
    "failure_signature": failure_signature,
    "errors": errors,
}

rows.append(row(report["event"], status=status, failure_signature=failure_signature))
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("\n".join(json.dumps(item, sort_keys=True) for item in rows) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL: locale/iconv completion contract errors={len(errors)}", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS: locale/iconv completion contract "
    f"unit_refs={unit_ref_count} e2e_artifacts={e2e_artifact_count} "
    f"fuzz_seeds={fuzz_seed_count} conformance_refs={conformance_ref_count} "
    f"table_checksums={table_checksum_count}"
)
PY
