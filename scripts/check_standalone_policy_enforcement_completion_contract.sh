#!/usr/bin/env bash
# check_standalone_policy_enforcement_completion_contract.sh - bd-w2c3.2.2.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_STANDALONE_POLICY_COMPLETION_CONTRACT:-$ROOT/tests/conformance/standalone_policy_enforcement_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_STANDALONE_POLICY_COMPLETION_OUT_DIR:-$ROOT/target/conformance/standalone_policy_enforcement_completion_contract}"
REPORT="${FRANKENLIBC_STANDALONE_POLICY_COMPLETION_REPORT:-$OUT_DIR/standalone_policy_enforcement_completion_contract.report.json}"
LOG="${FRANKENLIBC_STANDALONE_POLICY_COMPLETION_LOG:-$OUT_DIR/standalone_policy_enforcement_completion_contract.log.jsonl}"
REPLACEMENT_GUARD_REPORT="${FRANKENLIBC_STANDALONE_POLICY_REPLACEMENT_GUARD_REPORT:-$OUT_DIR/replacement_guard.report.json}"
REPLACEMENT_GUARD_LOG="${FRANKENLIBC_STANDALONE_POLICY_REPLACEMENT_GUARD_LOG:-$OUT_DIR/replacement_guard.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$REPLACEMENT_GUARD_REPORT")" "$(dirname "$REPLACEMENT_GUARD_LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
REPLACEMENT_GUARD_REPORT="$REPLACEMENT_GUARD_REPORT" \
REPLACEMENT_GUARD_LOG="$REPLACEMENT_GUARD_LOG" \
python3 - <<'PY'
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import subprocess
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
REPLACEMENT_GUARD_REPORT = pathlib.Path(os.environ["REPLACEMENT_GUARD_REPORT"])
REPLACEMENT_GUARD_LOG = pathlib.Path(os.environ["REPLACEMENT_GUARD_LOG"])

EXPECTED_SCHEMA = "standalone_policy_enforcement_completion_contract.v1"
SOURCE_BEAD = "bd-w2c3.2.2"
COMPLETION_BEAD = "bd-w2c3.2.2.1"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
EXPECTED_SOURCE_KEYS = {
    "abi_build_script",
    "replacement_guard",
    "replacement_profile",
    "packaging_spec",
    "support_matrix",
    "zero_fixture_pack",
    "replacement_guard_harness",
    "completion_contract",
    "completion_checker",
    "completion_harness",
}
EXPECTED_EVENTS = {
    "standalone_policy_contract_validated",
    "standalone_policy_sources_validated",
    "replacement_guard_replayed",
    "standalone_policy_completion_summary",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def repo_path(value: Any, context: str, *, must_be_file: bool = False) -> pathlib.Path | None:
    if not isinstance(value, str) or not value:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(value)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must stay repo-relative: {value}")
        return None
    full = ROOT / path
    if must_be_file and not full.is_file():
        err(f"{context} references missing file: {value}")
        return None
    if not must_be_file and not full.exists():
        err(f"{context} references missing path: {value}")
        return None
    return full


def text_for(path_text: str, context: str) -> str:
    path = repo_path(path_text, context, must_be_file=True)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        err(f"{context} is not UTF-8: {path_text}: {exc}")
        return ""


def string_list(value: Any, context: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def object_at(value: dict[str, Any], key: str, context: str) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        err(f"{context}.{key} must be an object")
        return {}
    return child


def expect_set(actual: list[str], expected: list[str], context: str) -> None:
    if set(actual) != set(expected):
        err(f"{context} mismatch: expected={sorted(expected)} got={sorted(actual)}")


def validate_impl_ref(ref: Any, source_text_cache: dict[str, str]) -> str | None:
    if not isinstance(ref, dict):
        err(f"implementation_refs entry must be an object: {ref!r}")
        return None
    kind = ref.get("kind")
    path_text = ref.get("path")
    line = ref.get("line")
    anchor = ref.get("anchor")
    if not isinstance(kind, str) or not kind:
        err(f"implementation_refs entry missing kind: {ref!r}")
    if not isinstance(path_text, str):
        err(f"implementation_refs entry missing path: {ref!r}")
        return kind if isinstance(kind, str) else None
    text = source_text_cache.setdefault(path_text, text_for(path_text, f"implementation_refs.{kind}"))
    lines = text.splitlines()
    if not isinstance(line, int) or line <= 0:
        err(f"{path_text} ref line must be a positive integer")
    elif line > len(lines) or not lines[line - 1].strip():
        err(f"{path_text}:{line} does not point to a non-empty line")
    if not isinstance(anchor, str) or not anchor:
        err(f"{path_text}:{line} missing anchor")
    elif anchor not in text:
        err(f"{path_text} missing anchor {anchor!r}")
    return kind if isinstance(kind, str) else None


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": now(),
            "trace_id": f"{COMPLETION_BEAD}:{event}:{len(events) + 1:03d}",
            "source_bead": SOURCE_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "event": event,
            "status": status,
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "standalone_policy_completion_failed",
            "details": details,
        }
    )


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def validate_contract(manifest: dict[str, Any]) -> dict[str, str]:
    if manifest.get("schema_version") != EXPECTED_SCHEMA:
        err(f"schema_version must be {EXPECTED_SCHEMA}")
    if manifest.get("bead") != SOURCE_BEAD:
        err(f"bead must be {SOURCE_BEAD}")
    if manifest.get("completion_debt_bead") != COMPLETION_BEAD:
        err(f"completion_debt_bead must be {COMPLETION_BEAD}")
    if int(manifest.get("next_audit_score_threshold", 0) or 0) < 800:
        err("next_audit_score_threshold must be at least 800")

    audit = object_at(manifest, "audit", "manifest")
    missing_items = set(string_list(audit.get("missing_items"), "audit.missing_items"))
    if missing_items != EXPECTED_MISSING_ITEMS:
        err(f"audit.missing_items mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(missing_items)}")

    raw_source_paths = manifest.get("source_paths")
    if not isinstance(raw_source_paths, dict):
        err("source_paths must be an object")
        source_paths: dict[str, str] = {}
    else:
        source_paths = {}
        missing_keys = EXPECTED_SOURCE_KEYS - set(raw_source_paths)
        if missing_keys:
            err(f"source_paths missing required keys: {sorted(missing_keys)}")
        for source, path_text in raw_source_paths.items():
            if isinstance(path_text, str):
                source_paths[str(source)] = path_text
            repo_path(path_text, f"source_paths.{source}")

    source_text_cache: dict[str, str] = {}
    impl_kinds = {
        kind
        for kind in (validate_impl_ref(ref, source_text_cache) for ref in manifest.get("implementation_refs", []))
        if kind
    }
    if len(impl_kinds) < 24:
        err(f"implementation_refs should cite at least 24 concrete anchors, got {len(impl_kinds)}")

    anchors = manifest.get("source_anchors", {})
    if not isinstance(anchors, dict):
        err("source_anchors must be an object")
    else:
        for source, required_anchors in anchors.items():
            path_text = source_paths.get(str(source))
            if not path_text:
                err(f"source_anchors.{source} has no matching source_paths entry")
                continue
            text = source_text_cache.setdefault(path_text, text_for(path_text, f"source_anchors.{source}"))
            for anchor in string_list(required_anchors, f"source_anchors.{source}"):
                if anchor not in text:
                    err(f"{path_text} missing source anchor {anchor!r}")

    coverage = manifest.get("completion_coverage")
    if not isinstance(coverage, list) or not coverage:
        err("completion_coverage must be a non-empty array")
    else:
        covered_items = set()
        for index, section in enumerate(coverage):
            if not isinstance(section, dict):
                err(f"completion_coverage[{index}] must be an object")
                continue
            item_id = section.get("missing_item_id")
            if isinstance(item_id, str):
                covered_items.add(item_id)
            if section.get("status") != "covered":
                err(f"completion_coverage[{index}].status must be covered")
            for ref_kind in string_list(section.get("implementation_refs"), f"completion_coverage[{index}].implementation_refs"):
                if ref_kind not in impl_kinds:
                    err(f"coverage references unknown implementation ref {ref_kind}")
            test_refs = section.get("test_refs")
            if not isinstance(test_refs, list) or not test_refs:
                err(f"completion_coverage[{index}].test_refs must be non-empty")
            else:
                for test_ref in test_refs:
                    if not isinstance(test_ref, dict):
                        err(f"completion_coverage[{index}].test_refs entries must be objects")
                        continue
                    source = test_ref.get("source")
                    name = test_ref.get("name")
                    if not isinstance(source, str) or source not in source_paths:
                        err(f"test_ref source is unknown: {source!r}")
                        continue
                    if not isinstance(name, str) or not name:
                        err(f"test_ref name is missing for source {source}")
                        continue
                    text = source_text_cache.setdefault(
                        source_paths[source],
                        text_for(source_paths[source], f"test_ref.{source}"),
                    )
                    if f"fn {name}" not in text and f"def {name}" not in text:
                        err(f"test ref {source}::{name} does not exist in {source_paths[source]}")
            for command in string_list(section.get("validation_commands"), f"completion_coverage[{index}].validation_commands"):
                if "cargo " in command:
                    if "rch " not in command:
                        err(f"cargo validation command must use rch: {command}")
                    if "CARGO_TARGET_DIR=" not in command:
                        err(f"cargo validation command must use isolated CARGO_TARGET_DIR: {command}")
        if covered_items != EXPECTED_MISSING_ITEMS:
            err(f"completion_coverage missing items mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(covered_items)}")

    expected_events = set(string_list(manifest.get("expected_events"), "expected_events"))
    if expected_events != EXPECTED_EVENTS:
        err(f"expected_events mismatch: expected={sorted(EXPECTED_EVENTS)} got={sorted(expected_events)}")

    return source_paths


def validate_policy_sources(manifest: dict[str, Any], source_paths: dict[str, str]) -> dict[str, Any]:
    policy = object_at(manifest, "policy_requirements", "manifest")
    profile_req = object_at(policy, "replacement_profile", "policy_requirements")
    packaging_req = object_at(policy, "packaging_spec", "policy_requirements")
    support_req = object_at(policy, "support_matrix", "policy_requirements")

    profile = load_json(ROOT / source_paths.get("replacement_profile", ""), "replacement profile")
    packaging = load_json(ROOT / source_paths.get("packaging_spec", ""), "packaging spec")
    support_matrix = load_json(ROOT / source_paths.get("support_matrix", ""), "support matrix")
    fixture_pack = load_json(ROOT / source_paths.get("zero_fixture_pack", ""), "zero fixture pack")

    profile_callthrough = (
        profile.get("profiles", {})
        .get("replacement", {})
        .get("call_through_allowed")
    )
    if profile_callthrough is not profile_req.get("call_through_allowed"):
        err("replacement_profile profiles.replacement.call_through_allowed does not match contract")

    profile_modules = string_list(
        profile.get("callthrough_families", {}).get("modules"),
        "replacement_profile.callthrough_families.modules",
        allow_empty=True,
    )
    expect_set(
        profile_modules,
        string_list(profile_req.get("callthrough_modules"), "policy_requirements.replacement_profile.callthrough_modules", allow_empty=True),
        "replacement_profile.callthrough_families.modules",
    )

    expected_pack = profile_req.get("zero_unapproved_fixture_pack")
    actual_pack = profile.get("zero_unapproved_fixture_pack", {}).get("path")
    if actual_pack != expected_pack:
        err(f"replacement_profile zero fixture pack mismatch: expected={expected_pack} got={actual_pack}")
    if fixture_pack.get("summary", {}).get("fixture_count") != profile_req.get("call_through_census_total"):
        err("zero fixture pack fixture_count must match current zero call-through census")
    if profile.get("call_through_census", {}).get("total_call_throughs") != profile_req.get("call_through_census_total"):
        err("replacement_profile call_through_census.total_call_throughs mismatch")

    replace = packaging.get("artifacts", {}).get("replace", {})
    if replace.get("host_glibc_required") != packaging_req.get("replace_host_glibc_required"):
        err("packaging_spec artifacts.replace.host_glibc_required mismatch")
    expect_set(
        string_list(replace.get("allowed_statuses"), "packaging_spec.artifacts.replace.allowed_statuses"),
        string_list(packaging_req.get("replace_allowed_statuses"), "policy_requirements.packaging_spec.replace_allowed_statuses"),
        "packaging_spec artifacts.replace.allowed_statuses",
    )
    expect_set(
        string_list(replace.get("cargo_features"), "packaging_spec.artifacts.replace.cargo_features"),
        string_list(packaging_req.get("replace_cargo_features"), "policy_requirements.packaging_spec.replace_cargo_features"),
        "packaging_spec artifacts.replace.cargo_features",
    )
    build_command = replace.get("build_command", "")
    if not isinstance(build_command, str) or "--features=standalone" not in build_command:
        err("packaging_spec artifacts.replace.build_command must include --features=standalone")
    standalone_gate = packaging.get("feature_gates", {}).get("standalone", {})
    expect_set(
        string_list(standalone_gate.get("features"), "packaging_spec.feature_gates.standalone.features"),
        string_list(packaging_req.get("standalone_feature_gate"), "policy_requirements.packaging_spec.standalone_feature_gate"),
        "packaging_spec feature_gates.standalone.features",
    )

    replace_statuses = string_list(
        support_matrix.get("taxonomy", {}).get("artifact_applicability", {}).get("Replace"),
        "support_matrix.taxonomy.artifact_applicability.Replace",
    )
    expected_replace_statuses = string_list(
        support_req.get("replace_applicable_statuses"),
        "policy_requirements.support_matrix.replace_applicable_statuses",
    )
    expect_set(replace_statuses, expected_replace_statuses, "support_matrix taxonomy Replace statuses")

    forbidden_statuses = set(
        string_list(
            support_req.get("forbidden_statuses"),
            "policy_requirements.support_matrix.forbidden_statuses",
        )
    )
    forbidden_symbols = [
        row.get("symbol", "<unknown>")
        for row in support_matrix.get("symbols", [])
        if isinstance(row, dict) and row.get("status") in forbidden_statuses
    ]
    if len(forbidden_symbols) != support_req.get("expected_forbidden_symbol_count"):
        err(
            "support_matrix forbidden standalone status count mismatch: "
            f"expected={support_req.get('expected_forbidden_symbol_count')} got={len(forbidden_symbols)} examples={forbidden_symbols[:5]}"
        )

    return {
        "profile_call_through_allowed": profile_callthrough,
        "profile_callthrough_modules": len(profile_modules),
        "replace_allowed_statuses": sorted(replace.get("allowed_statuses", [])),
        "replace_cargo_features": sorted(replace.get("cargo_features", [])),
        "support_matrix_forbidden_symbols": len(forbidden_symbols),
        "fixture_count": fixture_pack.get("summary", {}).get("fixture_count"),
    }


def replay_replacement_guard(manifest: dict[str, Any], source_paths: dict[str, str]) -> dict[str, Any]:
    guard_req = object_at(object_at(manifest, "policy_requirements", "manifest"), "replacement_guard", "policy_requirements")
    mode = guard_req.get("mode", "replacement")
    guard_path = ROOT / source_paths.get("replacement_guard", "scripts/check_replacement_guard.sh")
    env = os.environ.copy()
    env["FRANKENLIBC_REPLACEMENT_GUARD_REPORT"] = str(REPLACEMENT_GUARD_REPORT)
    env["FRANKENLIBC_REPLACEMENT_GUARD_LOG"] = str(REPLACEMENT_GUARD_LOG)
    proc = subprocess.run(
        ["bash", str(guard_path), str(mode)],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        err(f"replacement guard replay failed with exit {proc.returncode}: stdout={proc.stdout} stderr={proc.stderr}")

    report = load_json(REPLACEMENT_GUARD_REPORT, "replacement guard report")
    if report.get("ok") is not True:
        err("replacement guard report ok must be true")
    if report.get("mode") != mode:
        err(f"replacement guard report mode mismatch: expected={mode} got={report.get('mode')}")
    expected_numeric = {
        "total_call_throughs": guard_req.get("expected_total_call_throughs"),
        "modules_with_call_throughs": guard_req.get("expected_modules_with_call_throughs"),
        "violations": guard_req.get("expected_violations"),
        "mutex_forbidden_count": guard_req.get("expected_mutex_forbidden"),
    }
    for key, expected in expected_numeric.items():
        if report.get(key) != expected:
            err(f"replacement guard report {key} mismatch: expected={expected} got={report.get(key)}")
    fixture_count = sum(
        int(report.get("policy_summary", {}).get(name, 0) or 0)
        for name in ("interpose_fixture_cases", "replacement_fixture_cases")
    )
    if fixture_count and fixture_count != guard_req.get("expected_fixture_cases"):
        err(f"replacement guard report fixture count mismatch: expected={guard_req.get('expected_fixture_cases')} got={fixture_count}")
    if guard_req.get("expected_total_call_throughs") == 0:
        try:
            nonempty_rows = [line for line in REPLACEMENT_GUARD_LOG.read_text(encoding="utf-8").splitlines() if line.strip()]
        except Exception as exc:
            err(f"replacement guard log unreadable: {exc}")
            nonempty_rows = []
        if nonempty_rows:
            err("replacement guard log should be empty when the call-through scan is empty")

    return {
        "exit_code": proc.returncode,
        "stdout_lines": proc.stdout.splitlines()[-12:],
        "stderr": proc.stderr,
        "report": rel(REPLACEMENT_GUARD_REPORT),
        "log": rel(REPLACEMENT_GUARD_LOG),
        "mode": report.get("mode"),
        "total_call_throughs": report.get("total_call_throughs"),
        "violations": report.get("violations"),
        "mutex_forbidden_count": report.get("mutex_forbidden_count"),
    }


start_errors = len(errors)
manifest = load_json(CONTRACT, "standalone policy completion contract")
source_paths = validate_contract(manifest)
append_event(
    "standalone_policy_contract_validated",
    "pass" if len(errors) == start_errors else "fail",
    [rel(CONTRACT)],
    {"error_count": len(errors) - start_errors, "source_paths": sorted(source_paths)},
)

source_errors = len(errors)
source_summary = validate_policy_sources(manifest, source_paths) if source_paths else {}
append_event(
    "standalone_policy_sources_validated",
    "pass" if len(errors) == source_errors else "fail",
    [
        source_paths.get("abi_build_script", "crates/frankenlibc-abi/build.rs"),
        source_paths.get("replacement_profile", "tests/conformance/replacement_profile.json"),
        source_paths.get("packaging_spec", "tests/conformance/packaging_spec.json"),
        source_paths.get("support_matrix", "support_matrix.json"),
    ],
    source_summary,
)

guard_errors = len(errors)
guard_summary = replay_replacement_guard(manifest, source_paths) if source_paths else {}
append_event(
    "replacement_guard_replayed",
    "pass" if len(errors) == guard_errors else "fail",
    [rel(REPLACEMENT_GUARD_REPORT), rel(REPLACEMENT_GUARD_LOG)],
    guard_summary,
)

event_names = {row["event"] for row in events}
if event_names != EXPECTED_EVENTS - {"standalone_policy_completion_summary"}:
    err(f"internal event emission mismatch: got={sorted(event_names)}")

summary_status = "pass" if not errors else "fail"
append_event(
    "standalone_policy_completion_summary",
    summary_status,
    [rel(CONTRACT), rel(REPORT), rel(LOG)],
    {
        "ok": not errors,
        "error_count": len(errors),
        "source_bead": SOURCE_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "git_head": git_head(),
    },
)

report = {
    "schema_version": "standalone_policy_enforcement_completion_report.v1",
    "source_bead": SOURCE_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "ok": not errors,
    "generated_at": now(),
    "git_head": git_head(),
    "contract": rel(CONTRACT),
    "replacement_guard_report": rel(REPLACEMENT_GUARD_REPORT),
    "replacement_guard_log": rel(REPLACEMENT_GUARD_LOG),
    "summary": {
        "errors": len(errors),
        "events": len(events),
        "expected_events": sorted(EXPECTED_EVENTS),
        "emitted_events": sorted(row["event"] for row in events),
        "source_summary": source_summary,
        "replacement_guard_summary": guard_summary,
    },
    "errors": errors,
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print("check_standalone_policy_enforcement_completion_contract: FAILED")
    for message in errors:
        print(f"  {message}")
    print(f"Report: {rel(REPORT)}")
    print(f"Log: {rel(LOG)}")
    raise SystemExit(1)

print("check_standalone_policy_enforcement_completion_contract: PASS")
print(f"Report: {rel(REPORT)}")
print(f"Log: {rel(LOG)}")
PY
