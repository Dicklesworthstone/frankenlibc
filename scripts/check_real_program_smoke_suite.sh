#!/usr/bin/env bash
# check_real_program_smoke_suite.sh -- deterministic real-program smoke gate for bd-bp8fl.10.2
#
# Validates and optionally runs the L0/L1 real-program smoke manifest. Missing,
# stale, optional, standalone, dry-run, and diagnostic-fixture rows produce
# structured blocked/skip evidence and cannot be counted as supported cases.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${ROOT}/tests/conformance/real_program_smoke_suite.v1.json"
OUT_ROOT="${REAL_PROGRAM_SMOKE_TARGET_DIR:-${ROOT}/target/real_program_smoke_suite}"
RUN_ID="${REAL_PROGRAM_SMOKE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
RUN_DIR="${OUT_ROOT}/${RUN_ID}"
REPORT="${REAL_PROGRAM_SMOKE_REPORT:-${ROOT}/target/conformance/real_program_smoke_suite.report.json}"
LOG="${REAL_PROGRAM_SMOKE_LOG:-${ROOT}/target/conformance/real_program_smoke_suite.log.jsonl}"
MODE="run"

case "${1:-}" in
  "")
    MODE="run"
    ;;
  --run)
    MODE="run"
    ;;
  --dry-run)
    MODE="dry-run"
    ;;
  --validate-only)
    MODE="validate-only"
    ;;
  --bundle-fixtures)
    MODE="bundle-fixtures"
    ;;
  *)
    echo "usage: $0 [--run|--dry-run|--validate-only|--bundle-fixtures]" >&2
    exit 2
    ;;
esac

mkdir -p "${RUN_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${RUN_DIR}" "${REPORT}" "${LOG}" "${MODE}" <<'PY'
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
run_dir = Path(sys.argv[3])
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])
mode = sys.argv[6]

REQUIRED_CASE_FIELDS = [
    "case_id",
    "workload_id",
    "domain",
    "command",
    "argv",
    "env",
    "timeout_ms",
    "runtime_mode",
    "replacement_level",
    "artifact_kind",
    "expected",
    "allowed_divergence",
    "cleanup",
    "oracle_kind",
    "support_claim",
]
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "workload_id",
    "command",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "expected_status",
    "actual_status",
    "errno",
    "duration_ms",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "bundle_id",
    "failure_class",
    "next_safe_action",
    "failure_signature",
]
REQUIRED_DOMAINS = {
    "shell_coreutils",
    "build_tool",
    "resolver_nss",
    "locale_iconv",
    "stdio_file",
    "threaded",
    "failure_unsupported",
    "standalone_future",
}
REQUIRED_MODES = {"strict", "hardened"}
REQUIRED_LEVELS = {"L0", "L1"}
NON_SUPPORT_STATUSES = {"blocked", "claim_blocked", "dry_run", "skipped", "validated"}
NO_BUNDLE = {
    "bundle_id": "none",
    "artifact_ref": None,
    "failure_class": "none",
    "next_safe_action": "none",
}
SYMBOL_RE = re.compile(
    r"(?:undefined symbol|symbol lookup error|missing symbol)[:= ]+([A-Za-z_][A-Za-z0-9_@.]*)",
    re.IGNORECASE,
)

errors = []
checks = {}
log_rows = []
case_results = []


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return {}


manifest = load_json(manifest_path)

try:
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
except Exception:
    source_commit = "unknown"

try:
    head_epoch = int(
        subprocess.check_output(
            ["git", "log", "-1", "--format=%ct", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    )
except Exception:
    head_epoch = 0


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def write_text(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path, value):
    write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def append_log(
    *,
    event,
    workload_id,
    command,
    runtime_mode,
    replacement_level,
    oracle_kind,
    expected_status,
    actual_status,
    errno,
    duration_ms,
    artifact_refs,
    failure_signature,
    bundle_id="none",
    failure_class="none",
    next_safe_action="none",
    support_claimed=False,
    skip_reason=None,
    blocked_reason=None,
):
    trace_id = (
        f"{log_bead_id()}::{run_dir.name}::"
        f"{workload_id}::{runtime_mode}::{event}"
    )
    row = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": "error" if actual_status == "fail" else "info",
        "event": event,
        "trace_id": trace_id,
        "bead_id": log_bead_id(),
        "workload_id": workload_id,
        "command": command,
        "runtime_mode": runtime_mode,
        "replacement_level": replacement_level,
        "oracle_kind": oracle_kind,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "errno": errno,
        "duration_ms": duration_ms,
        "artifact_refs": artifact_refs,
        "source_commit": source_commit,
        "target_dir": str(run_dir),
        "bundle_id": bundle_id,
        "failure_class": failure_class,
        "next_safe_action": next_safe_action,
        "failure_signature": failure_signature,
        "support_claimed": support_claimed,
        "skip_reason": skip_reason,
        "blocked_reason": blocked_reason,
    }
    for field in REQUIRED_LOG_FIELDS:
        if field not in row:
            errors.append(f"log row missing field {field}")
    log_rows.append(row)


def candidate_paths(env_name, names):
    paths = []
    env_path = os.environ.get(env_name)
    if env_path:
        paths.append(Path(env_path))
    if os.environ.get("REAL_PROGRAM_SMOKE_IGNORE_DEFAULT_ARTIFACTS") == "1":
        return paths
    cargo_target = os.environ.get("CARGO_TARGET_DIR")
    if cargo_target:
        for name in names:
            paths.append(Path(cargo_target) / "release" / name)
            paths.append(Path(cargo_target) / "debug" / name)
    for name in names:
        paths.append(root / "target" / "release" / name)
        paths.append(root / "target" / "debug" / name)
    return paths


def classify_library(env_name, required_name):
    for path in candidate_paths(env_name, [required_name]):
        if not path.exists():
            continue
        if path.name != required_name:
            return {
                "status": "wrong_profile",
                "path": str(path),
                "failure_signature": "wrong_artifact_profile",
                "detail": f"expected {required_name}",
            }
        try:
            mtime = int(path.stat().st_mtime)
        except OSError:
            mtime = 0
        if head_epoch and mtime < head_epoch:
            return {
                "status": "stale",
                "path": str(path),
                "mtime": mtime,
                "head_epoch": head_epoch,
                "failure_signature": "artifact_stale",
                "detail": "artifact predates source HEAD",
            }
        return {
            "status": "current",
            "path": str(path),
            "mtime": mtime,
            "head_epoch": head_epoch,
            "failure_signature": "none",
            "detail": None,
        }
    return {
        "status": "missing",
        "path": None,
        "failure_signature": "artifact_missing",
        "detail": f"{required_name} not supplied or discovered",
    }


artifact_policy = manifest.get("artifact_policy", {})
failure_bundle_policy = manifest.get("failure_bundle_policy", {})
interpose_state = classify_library(
    artifact_policy.get("interpose_library_env", "FRANKENLIBC_SMOKE_LIB_PATH"),
    artifact_policy.get("required_interpose_artifact_name", "libfrankenlibc_abi.so"),
)


def log_bead_id():
    return failure_bundle_policy.get("bead") or manifest.get("bead")
standalone_state = classify_library(
    artifact_policy.get("standalone_library_env", "FRANKENLIBC_STANDALONE_LIB"),
    artifact_policy.get("required_standalone_artifact_name", "libfrankenlibc_replace.so"),
)


def validate_manifest():
    checks["json_parse"] = "pass" if isinstance(manifest, dict) else "fail"
    if manifest.get("schema_version") != "v1":
        errors.append("manifest must declare schema_version=v1")
    if manifest.get("bead") != "bd-bp8fl.10.2":
        errors.append("manifest must be linked to bead bd-bp8fl.10.2")
    checks["top_level_shape"] = "pass" if not errors else "fail"

    if manifest.get("required_case_fields") == REQUIRED_CASE_FIELDS:
        checks["required_case_fields"] = "pass"
    else:
        checks["required_case_fields"] = "fail"
        errors.append("required_case_fields do not match the smoke-case schema contract")

    if manifest.get("required_log_fields") == REQUIRED_LOG_FIELDS:
        checks["required_log_fields"] = "pass"
    else:
        checks["required_log_fields"] = "fail"
        errors.append("required_log_fields do not match the structured log contract")

    cases = manifest.get("cases", [])
    case_ids = [case.get("case_id") for case in cases]
    domains = Counter()
    modes = Counter()
    levels = Counter()
    support_never = 0
    case_ok = bool(cases) and len(case_ids) == len(set(case_ids))
    for case in cases:
        case_id = case.get("case_id", "<missing case_id>")
        for field in REQUIRED_CASE_FIELDS:
            if field not in case:
                case_ok = False
                errors.append(f"{case_id}: missing field {field}")
        domain = case.get("domain")
        if domain not in REQUIRED_DOMAINS:
            case_ok = False
            errors.append(f"{case_id}: unknown domain {domain}")
        domains[domain] += 1
        modes[case.get("runtime_mode")] += 1
        levels[case.get("replacement_level")] += 1
        if case.get("timeout_ms", 0) > manifest.get("timeout_policy", {}).get("max_timeout_ms", 15000):
            case_ok = False
            errors.append(f"{case_id}: timeout_ms exceeds max_timeout_ms")
        if case.get("cleanup", {}).get("policy") != "case_dir_scoped":
            case_ok = False
            errors.append(f"{case_id}: cleanup.policy must be case_dir_scoped")
        if case.get("support_claim") == "never":
            support_never += 1
        if case.get("artifact_kind") == "standalone_direct_link_future":
            expected = case.get("expected", {}).get("status")
            if expected != "claim_blocked" or case.get("support_claim") != "never":
                case_ok = False
                errors.append(f"{case_id}: standalone future rows must remain claim_blocked and never support")

    checks["case_rows"] = "pass" if case_ok else "fail"
    if not case_ok:
        errors.append("case rows must be unique, complete, scoped, and fail-closed")

    missing_domains = sorted(REQUIRED_DOMAINS - set(domains))
    checks["domain_coverage"] = "pass" if not missing_domains else "fail"
    if missing_domains:
        errors.append("missing required domains: " + ", ".join(missing_domains))

    checks["runtime_mode_coverage"] = "pass" if REQUIRED_MODES <= set(modes) else "fail"
    if checks["runtime_mode_coverage"] != "pass":
        errors.append("manifest must cover strict and hardened runtime modes")

    checks["replacement_level_coverage"] = "pass" if REQUIRED_LEVELS <= set(levels) else "fail"
    if checks["replacement_level_coverage"] != "pass":
        errors.append("manifest must cover L0 and L1 replacement levels")

    summary = manifest.get("summary", {})
    summary_ok = (
        summary.get("case_count") == len(cases)
        and summary.get("strict_case_count") == modes.get("strict", 0)
        and summary.get("hardened_case_count") == modes.get("hardened", 0)
        and summary.get("l0_case_count") == levels.get("L0", 0)
        and summary.get("l1_case_count") == levels.get("L1", 0)
        and summary.get("non_support_claim_policy_rows") == support_never
        and summary.get("required_domain_coverage") == dict(domains)
    )
    checks["summary_counts"] = "pass" if summary_ok else "fail"
    if not summary_ok:
        errors.append("summary counts do not match case rows")

    result_policy = manifest.get("result_policy", {})
    no_overclaim = (
        result_policy.get("unsupported_or_skipped_claims_support") is False
        and result_policy.get("dry_run_claims_support") is False
        and result_policy.get("supported_case_requires_actual_status") == "pass"
    )
    checks["no_overclaim_policy"] = "pass" if no_overclaim else "fail"
    if not no_overclaim:
        errors.append("result_policy must forbid support claims from skipped, blocked, or dry-run rows")

    bundle_policy = manifest.get("failure_bundle_policy", {})
    required_bundle_fields = bundle_policy.get("required_bundle_fields", [])
    required_failure_classes = set(bundle_policy.get("required_failure_classes", []))
    fixture_classes = {
        fixture.get("failure_class")
        for fixture in bundle_policy.get("synthetic_failure_cases", [])
        if isinstance(fixture, dict)
    }
    bundle_policy_ok = (
        bundle_policy.get("bead") == "bd-bp8fl.10.3"
        and bundle_policy.get("bundle_filename") == "failure.bundle.json"
        and isinstance(required_bundle_fields, list)
        and len(required_bundle_fields) >= 20
        and required_failure_classes <= fixture_classes
        and bool(bundle_policy.get("next_safe_actions"))
    )
    checks["failure_bundle_policy"] = "pass" if bundle_policy_ok else "fail"
    if not bundle_policy_ok:
        errors.append("failure_bundle_policy must define schema fields, classes, actions, and fixtures for bd-bp8fl.10.3")


def validate_prior_report():
    prior_path = os.environ.get(artifact_policy.get("prior_report_env", "REAL_PROGRAM_SMOKE_PRIOR_REPORT"))
    if not prior_path:
        checks["prior_result_freshness"] = "pass"
        return False
    prior = load_json(prior_path)
    prior_commit = prior.get("source_commit")
    stale = prior_commit != source_commit
    checks["prior_result_freshness"] = "pass" if stale else "pass"
    if stale:
        append_log(
            event="stale_result_rejected",
            workload_id="prior_report",
            command=str(prior_path),
            runtime_mode="n/a",
            replacement_level="L0,L1",
            oracle_kind="stale_result_rejection",
            expected_status="source_commit matches HEAD",
            actual_status="claim_blocked",
            errno=None,
            duration_ms=0,
            artifact_refs=[rel(prior_path)],
            failure_signature="stale_result_rejected",
            support_claimed=False,
            blocked_reason="prior report source_commit does not match HEAD",
        )
    return stale


def resolve_command(command):
    path = Path(command)
    if path.is_absolute():
        return str(path) if path.exists() and os.access(path, os.X_OK) else None
    found = shutil.which(command)
    return found


def isolated_env(case, *, candidate=False, library_path=None):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", str(root)),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    for key, value in case.get("env", {}).get("set", {}).items():
        env[key] = value
    for key in case.get("env", {}).get("unset", []):
        env.pop(key, None)
    env.pop("LD_PRELOAD", None)
    if candidate:
        env["FRANKENLIBC_MODE"] = case["runtime_mode"]
        if library_path:
            env["LD_PRELOAD"] = library_path
    return env


def redacted_env(env):
    patterns = failure_bundle_policy.get("redacted_env_key_patterns", [])
    redacted = {}
    redacted_keys = []
    for key in sorted(env):
        value = env[key]
        if any(re.search(pattern, key, re.IGNORECASE) for pattern in patterns):
            redacted[key] = "<redacted>"
            redacted_keys.append(key)
        else:
            redacted[key] = value
    return redacted, redacted_keys


def runner_env_subset():
    selected = {}
    for key, value in os.environ.items():
        if (
            key.startswith("FRANKENLIBC_")
            or key.startswith("REAL_PROGRAM_")
            or key in {"CARGO_TARGET_DIR", "LD_PRELOAD", "RUST_BACKTRACE"}
        ):
            selected[key] = value
    return redacted_env(selected)


def read_limited(path, limit=4096):
    try:
        content = Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {"artifact_ref": rel(path), "available": False, "excerpt": ""}
    truncated = len(content) > limit
    return {
        "artifact_ref": rel(path),
        "available": True,
        "excerpt": content[:limit],
        "truncated": truncated,
    }


def semantic_keywords_for(case, failure_class):
    domain = case.get("domain", "")
    mapping = {
        "resolver_nss": ["nss", "resolver", "resolv", "getaddrinfo", "gethost"],
        "locale_iconv": ["locale", "iconv", "wcsmbs", "codec"],
        "stdio_file": ["stdio", "libio", "_io", "stream"],
        "threaded": ["pthread", "thread", "cancel", "futex"],
        "standalone_future": ["standalone", "loader", "elf", "relocation", "startup"],
        "shell_coreutils": ["startup", "elf", "dl", "relocation"],
        "build_tool": ["startup", "elf", "dl", "relocation"],
        "failure_unsupported": ["unsupported", "fallback", "compat_noop", "stub"],
        "allocator_ownership": ["malloc", "allocator", "free", "realloc", "ownership"],
    }
    keywords = list(mapping.get(domain, []))
    if failure_class == "symbol_missing":
        keywords.extend(["missing", "version_script", "symbol"])
    if failure_class == "semantic_divergence":
        keywords.extend(["semantic", "fallback", "compat_noop"])
    return [keyword.lower() for keyword in keywords]


_semantic_entries = None


def load_semantic_entries():
    global _semantic_entries
    if _semantic_entries is not None:
        return _semantic_entries
    path = root / failure_bundle_policy.get(
        "semantic_join_path", "tests/conformance/semantic_contract_symbol_join.v1.json"
    )
    data = load_json(path)
    entries = data.get("entries", []) if isinstance(data, dict) else []
    _semantic_entries = entries if isinstance(entries, list) else []
    return _semantic_entries


def semantic_matches_for_case(case, failure_class):
    keywords = semantic_keywords_for(case, failure_class)
    matches = []
    for row in load_semantic_entries():
        haystack = " ".join(
            [
                str(row.get("inventory_id", "")),
                str(row.get("surface", "")),
                str(row.get("source_path", "")),
                str(row.get("semantic_class", "")),
                str(row.get("semantic_parity_status", "")),
                " ".join(str(symbol) for symbol in row.get("symbol_refs", [])),
            ]
        ).lower()
        if keywords and not any(keyword in haystack for keyword in keywords):
            continue
        matches.append(
            {
                "inventory_id": row.get("inventory_id"),
                "surface": row.get("surface"),
                "semantic_class": row.get("semantic_class"),
                "semantic_parity_status": row.get("semantic_parity_status"),
                "symbol_refs": row.get("symbol_refs", [])[:8],
                "claim_effect": row.get("claim_effect"),
            }
        )
        if len(matches) >= 5:
            break
    return matches


def classify_failure(case, failure_signature, actual_status):
    if actual_status in {"pass", "dry_run", "validated"} and failure_signature == "none":
        return "none"
    domain = case.get("domain")
    if failure_signature == "startup_timeout":
        return "timeout_failure"
    if domain == "resolver_nss":
        return "resolver_nss"
    if domain == "locale_iconv":
        return "locale_iconv"
    if domain == "allocator_ownership" or "allocator" in failure_signature:
        return "allocator_ownership"
    if (
        domain == "standalone_future"
        or "symbol" in failure_signature
        or "artifact" in failure_signature
        or "command_unavailable" in failure_signature
    ):
        return "symbol_missing"
    if (
        "stdout" in failure_signature
        or "stderr" in failure_signature
        or "status_mismatch" in failure_signature
        or domain == "failure_unsupported"
    ):
        return "semantic_divergence"
    return "runtime_failure"


def next_safe_action_for(failure_class):
    actions = failure_bundle_policy.get("next_safe_actions", {})
    return actions.get(failure_class) or actions.get("runtime_failure") or {
        "bead": "bd-bp8fl.10.6",
        "action": "preserve the bundle and keep the workload unsupported until a diagnostic bead closes",
    }


def parse_missing_symbols(*texts):
    symbols = []
    for text in texts:
        for match in SYMBOL_RE.finditer(text or ""):
            symbols.append(match.group(1))
    return sorted(set(symbols))


def fixture_diffs(case_dir):
    baseline = load_json(case_dir / "baseline.result.json") if (case_dir / "baseline.result.json").exists() else {}
    candidate = load_json(case_dir / "candidate.result.json") if (case_dir / "candidate.result.json").exists() else {}
    if not baseline or not candidate:
        return {
            "status": "missing_candidate_or_baseline",
            "baseline_ref": rel(case_dir / "baseline.result.json"),
            "candidate_ref": rel(case_dir / "candidate.result.json"),
        }
    return {
        "status_equal": baseline.get("returncode") == candidate.get("returncode"),
        "stdout_equal": baseline.get("stdout") == candidate.get("stdout"),
        "stderr_equal": baseline.get("stderr") == candidate.get("stderr"),
        "baseline_ref": rel(case_dir / "baseline.result.json"),
        "candidate_ref": rel(case_dir / "candidate.result.json"),
    }


def regeneration_command():
    env_parts = [
        f"REAL_PROGRAM_SMOKE_RUN_ID={shlex.quote(run_dir.name)}",
        f"REAL_PROGRAM_SMOKE_TARGET_DIR={shlex.quote(str(run_dir.parent))}",
        f"REAL_PROGRAM_SMOKE_REPORT={shlex.quote(str(report_path))}",
        f"REAL_PROGRAM_SMOKE_LOG={shlex.quote(str(log_path))}",
    ]
    return " ".join(env_parts + ["bash", "scripts/check_real_program_smoke_suite.sh", "--run"])


def emit_failure_bundle(
    case,
    *,
    case_dir,
    artifact_refs,
    command_text,
    actual_status,
    failure_signature,
    stdout_ref=None,
    stderr_ref=None,
    blocked_reason=None,
    skip_reason=None,
    forced_failure_class=None,
):
    if actual_status == "pass":
        return dict(NO_BUNDLE)
    failure_class = forced_failure_class or classify_failure(case, failure_signature, actual_status)
    action = next_safe_action_for(failure_class)
    semantic_rows = semantic_matches_for_case(case, failure_class)
    unsupported_symbols = sorted(
        {
            str(symbol)
            for row in semantic_rows
            for symbol in row.get("symbol_refs", [])
            if str(symbol)
        }
    )[:16]
    stderr_text = ""
    stdout_text = ""
    if stderr_ref:
        stderr_text = Path(stderr_ref).read_text(encoding="utf-8", errors="replace") if Path(stderr_ref).exists() else ""
    if stdout_ref:
        stdout_text = Path(stdout_ref).read_text(encoding="utf-8", errors="replace") if Path(stdout_ref).exists() else ""

    candidate_env = isolated_env(
        case,
        candidate=case.get("artifact_kind") == "ld_preload_interpose",
        library_path=interpose_state.get("path"),
    )
    case_env, case_redacted = redacted_env(candidate_env)
    runner_env, runner_redacted = runner_env_subset()
    bundle_id = f"{run_dir.name}::{case['case_id']}::{failure_class}"
    bundle_path = case_dir / failure_bundle_policy.get("bundle_filename", "failure.bundle.json")
    bundle_ref = rel(bundle_path)
    bundle = {
        "schema_version": "v1",
        "bundle_id": bundle_id,
        "bead_id": log_bead_id(),
        "workload_id": case["workload_id"],
        "case_id": case["case_id"],
        "command": {
            "line": command_text,
            "argv": [case["command"], *case.get("argv", [])],
        },
        "cwd": str(case_dir),
        "environment": {
            "case_env": case_env,
            "runner_env": runner_env,
        },
        "loaded_libraries": {
            "interpose": interpose_state,
            "standalone": standalone_state,
        },
        "replacement_level": case["replacement_level"],
        "runtime_mode": case["runtime_mode"],
        "semantic_overlay_rows": semantic_rows,
        "missing_symbols": parse_missing_symbols(stderr_text, stdout_text),
        "unsupported_symbols": unsupported_symbols,
        "fixture_diffs": fixture_diffs(case_dir),
        "logs": {
            "log_path": rel(log_path),
            "blocked_reason": blocked_reason,
            "skip_reason": skip_reason,
        },
        "stdout": read_limited(stdout_ref or case_dir / "candidate.stdout.txt"),
        "stderr": read_limited(stderr_ref or case_dir / "candidate.stderr.txt"),
        "failure_signature": failure_signature,
        "failure_class": failure_class,
        "next_safe_action": action,
        "regeneration_command": regeneration_command(),
        "source_commit": source_commit,
        "target_dir": str(run_dir),
        "artifact_refs": [*artifact_refs, bundle_ref],
        "redaction": {
            "patterns": failure_bundle_policy.get("redacted_env_key_patterns", []),
            "redacted_keys": sorted(set(case_redacted + runner_redacted)),
        },
    }
    required = failure_bundle_policy.get("required_bundle_fields", [])
    missing = [field for field in required if field not in bundle]
    if missing:
        errors.append(f"{case['case_id']}: failure bundle missing fields {missing}")
    write_json(bundle_path, bundle)
    max_size = int(failure_bundle_policy.get("max_bundle_size_bytes", 262144))
    try:
        if bundle_path.stat().st_size > max_size:
            errors.append(f"{case['case_id']}: failure bundle exceeds max_bundle_size_bytes")
    except OSError as exc:
        errors.append(f"{case['case_id']}: failure bundle stat failed: {exc}")
    return {
        "bundle_id": bundle_id,
        "artifact_ref": bundle_ref,
        "failure_class": failure_class,
        "next_safe_action": action.get("action", "none"),
    }


def run_command(argv, *, cwd, env, timeout_ms):
    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(timeout_ms / 1000.0, 0.001),
            check=False,
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "timed_out": False,
            "duration_ms": duration_ms,
        }
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        return {
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "timeout",
            "timed_out": True,
            "duration_ms": duration_ms,
        }


def output_matches(case, result):
    expected = case.get("expected", {})
    expected_status = expected.get("status")
    if isinstance(expected_status, int) and result["returncode"] != expected_status:
        return False, f"status_mismatch_expected_{expected_status}_actual_{result['returncode']}"
    if expected_status == "any_nonzero" and result["returncode"] == 0:
        return False, "status_mismatch_expected_nonzero_actual_0"
    if "stdout_exact" in expected and result["stdout"] != expected["stdout_exact"]:
        return False, "stdout_exact_mismatch"
    if "stderr_exact" in expected and result["stderr"] != expected["stderr_exact"]:
        return False, "stderr_exact_mismatch"
    if "stdout_contains" in expected and expected["stdout_contains"] not in result["stdout"]:
        return False, "stdout_contains_mismatch"
    if "stderr_contains" in expected and expected["stderr_contains"] not in result["stderr"]:
        return False, "stderr_contains_mismatch"
    return True, "none"


def row_support_claimed(case, actual_status):
    return case.get("support_claim") == "on_pass" and actual_status == "pass"


def run_case(case):
    case_dir = run_dir / case["case_id"]
    case_dir.mkdir(parents=True, exist_ok=True)
    write_json(case_dir / "case.json", case)
    artifact_refs = [rel(case_dir / "case.json")]
    command_text = " ".join([case["command"], *case.get("argv", [])])
    expected_status = case.get("expected", {}).get("status")

    if mode == "validate-only":
        actual_status = "validated"
        append_log(
            event="case_validated",
            workload_id=case["workload_id"],
            command=command_text,
            runtime_mode=case["runtime_mode"],
            replacement_level=case["replacement_level"],
            oracle_kind=case["oracle_kind"],
            expected_status=str(expected_status),
            actual_status=actual_status,
            errno=case.get("expected", {}).get("errno"),
            duration_ms=0,
            artifact_refs=artifact_refs,
            failure_signature="none",
            support_claimed=False,
        )
        return {
            "case_id": case["case_id"],
            "workload_id": case["workload_id"],
            "actual_status": actual_status,
            "support_claimed": False,
            "artifact_refs": artifact_refs,
            "failure_signature": "none",
            "bundle_id": "none",
            "failure_class": "none",
            "next_safe_action": "none",
        }

    if case["artifact_kind"] == "standalone_direct_link_future":
        actual_status = "claim_blocked"
        failure_signature = (
            "standalone_artifact_missing"
            if standalone_state["status"] == "missing"
            else standalone_state["failure_signature"]
        )
        blocked_reason = standalone_state["detail"] or "standalone direct-link proof is not part of L0/L1 support"
        write_json(
            case_dir / "candidate.blocked.json",
            {
                "artifact_state": standalone_state,
                "actual_status": actual_status,
                "failure_signature": failure_signature,
                "support_claimed": False,
            },
        )
        artifact_refs.append(rel(case_dir / "candidate.blocked.json"))
        bundle = emit_failure_bundle(
            case,
            case_dir=case_dir,
            artifact_refs=artifact_refs,
            command_text=command_text,
            actual_status=actual_status,
            failure_signature=failure_signature,
            blocked_reason=blocked_reason,
        )
        if bundle["artifact_ref"]:
            artifact_refs.append(bundle["artifact_ref"])
        append_log(
            event="standalone_future_blocked",
            workload_id=case["workload_id"],
            command=command_text,
            runtime_mode=case["runtime_mode"],
            replacement_level=case["replacement_level"],
            oracle_kind=case["oracle_kind"],
            expected_status=str(expected_status),
            actual_status=actual_status,
            errno=None,
            duration_ms=0,
            artifact_refs=artifact_refs,
            failure_signature=failure_signature,
            bundle_id=bundle["bundle_id"],
            failure_class=bundle["failure_class"],
            next_safe_action=bundle["next_safe_action"],
            support_claimed=False,
            blocked_reason=blocked_reason,
        )
        return {
            "case_id": case["case_id"],
            "workload_id": case["workload_id"],
            "actual_status": actual_status,
            "support_claimed": False,
            "artifact_refs": artifact_refs,
            "failure_signature": failure_signature,
            "blocked_reason": blocked_reason,
            "bundle_id": bundle["bundle_id"],
            "failure_class": bundle["failure_class"],
            "next_safe_action": bundle["next_safe_action"],
        }

    resolved = resolve_command(case["command"])
    if resolved is None:
        actual_status = "skipped" if case.get("optional") else "blocked"
        failure_signature = "command_unavailable_optional" if case.get("optional") else "command_unavailable"
        write_json(
            case_dir / "command_unavailable.json",
            {
                "command": case["command"],
                "optional": bool(case.get("optional")),
                "actual_status": actual_status,
                "support_claimed": False,
            },
        )
        artifact_refs.append(rel(case_dir / "command_unavailable.json"))
        bundle = emit_failure_bundle(
            case,
            case_dir=case_dir,
            artifact_refs=artifact_refs,
            command_text=command_text,
            actual_status=actual_status,
            failure_signature=failure_signature,
            skip_reason=failure_signature if actual_status == "skipped" else None,
            blocked_reason=failure_signature if actual_status == "blocked" else None,
        )
        if bundle["artifact_ref"]:
            artifact_refs.append(bundle["artifact_ref"])
        append_log(
            event="command_unavailable",
            workload_id=case["workload_id"],
            command=command_text,
            runtime_mode=case["runtime_mode"],
            replacement_level=case["replacement_level"],
            oracle_kind=case["oracle_kind"],
            expected_status=str(expected_status),
            actual_status=actual_status,
            errno=None,
            duration_ms=0,
            artifact_refs=artifact_refs,
            failure_signature=failure_signature,
            bundle_id=bundle["bundle_id"],
            failure_class=bundle["failure_class"],
            next_safe_action=bundle["next_safe_action"],
            support_claimed=False,
            skip_reason=failure_signature if actual_status == "skipped" else None,
            blocked_reason=failure_signature if actual_status == "blocked" else None,
        )
        return {
            "case_id": case["case_id"],
            "workload_id": case["workload_id"],
            "actual_status": actual_status,
            "support_claimed": False,
            "artifact_refs": artifact_refs,
            "failure_signature": failure_signature,
            "bundle_id": bundle["bundle_id"],
            "failure_class": bundle["failure_class"],
            "next_safe_action": bundle["next_safe_action"],
        }

    argv = [resolved, *case.get("argv", [])]
    baseline_result = run_command(
        argv,
        cwd=case_dir,
        env=isolated_env(case),
        timeout_ms=case.get("timeout_ms", 5000),
    )
    baseline_artifact = {
        "argv": argv,
        "returncode": baseline_result["returncode"],
        "stdout": baseline_result["stdout"],
        "stderr": baseline_result["stderr"],
        "timed_out": baseline_result["timed_out"],
        "duration_ms": baseline_result["duration_ms"],
    }
    write_json(case_dir / "baseline.result.json", baseline_artifact)
    write_text(case_dir / "baseline.stdout.txt", baseline_result["stdout"])
    write_text(case_dir / "baseline.stderr.txt", baseline_result["stderr"])
    write_text(case_dir / "baseline.exit_code", f"{baseline_result['returncode']}\n")
    artifact_refs.extend(
        [
            rel(case_dir / "baseline.result.json"),
            rel(case_dir / "baseline.stdout.txt"),
            rel(case_dir / "baseline.stderr.txt"),
            rel(case_dir / "baseline.exit_code"),
        ]
    )

    if mode == "dry-run":
        actual_status = "dry_run"
        write_json(
            case_dir / "candidate.dry_run.json",
            {
                "interpose_state": interpose_state,
                "support_claimed": False,
                "actual_status": actual_status,
            },
        )
        artifact_refs.append(rel(case_dir / "candidate.dry_run.json"))
        append_log(
            event="candidate_dry_run",
            workload_id=case["workload_id"],
            command=command_text,
            runtime_mode=case["runtime_mode"],
            replacement_level=case["replacement_level"],
            oracle_kind=case["oracle_kind"],
            expected_status=str(expected_status),
            actual_status=actual_status,
            errno=case.get("expected", {}).get("errno"),
            duration_ms=baseline_result["duration_ms"],
            artifact_refs=artifact_refs,
            failure_signature="none",
            support_claimed=False,
        )
        return {
            "case_id": case["case_id"],
            "workload_id": case["workload_id"],
            "actual_status": actual_status,
            "support_claimed": False,
            "artifact_refs": artifact_refs,
            "failure_signature": "none",
            "bundle_id": "none",
            "failure_class": "none",
            "next_safe_action": "none",
        }

    if interpose_state["status"] != "current":
        actual_status = "claim_blocked"
        failure_signature = (
            "interpose_artifact_missing"
            if interpose_state["status"] == "missing"
            else interpose_state["failure_signature"]
        )
        write_json(
            case_dir / "candidate.blocked.json",
            {
                "interpose_state": interpose_state,
                "actual_status": actual_status,
                "support_claimed": False,
                "failure_signature": failure_signature,
            },
        )
        artifact_refs.append(rel(case_dir / "candidate.blocked.json"))
        bundle = emit_failure_bundle(
            case,
            case_dir=case_dir,
            artifact_refs=artifact_refs,
            command_text=command_text,
            actual_status=actual_status,
            failure_signature=failure_signature,
            stdout_ref=case_dir / "baseline.stdout.txt",
            stderr_ref=case_dir / "baseline.stderr.txt",
            blocked_reason=interpose_state["detail"],
        )
        if bundle["artifact_ref"]:
            artifact_refs.append(bundle["artifact_ref"])
        append_log(
            event="candidate_claim_blocked",
            workload_id=case["workload_id"],
            command=command_text,
            runtime_mode=case["runtime_mode"],
            replacement_level=case["replacement_level"],
            oracle_kind=case["oracle_kind"],
            expected_status=str(expected_status),
            actual_status=actual_status,
            errno=case.get("expected", {}).get("errno"),
            duration_ms=baseline_result["duration_ms"],
            artifact_refs=artifact_refs,
            failure_signature=failure_signature,
            bundle_id=bundle["bundle_id"],
            failure_class=bundle["failure_class"],
            next_safe_action=bundle["next_safe_action"],
            support_claimed=False,
            blocked_reason=interpose_state["detail"],
        )
        return {
            "case_id": case["case_id"],
            "workload_id": case["workload_id"],
            "actual_status": actual_status,
            "support_claimed": False,
            "artifact_refs": artifact_refs,
            "failure_signature": failure_signature,
            "blocked_reason": interpose_state["detail"],
            "bundle_id": bundle["bundle_id"],
            "failure_class": bundle["failure_class"],
            "next_safe_action": bundle["next_safe_action"],
        }

    candidate_result = run_command(
        argv,
        cwd=case_dir,
        env=isolated_env(case, candidate=True, library_path=interpose_state["path"]),
        timeout_ms=case.get("timeout_ms", 5000),
    )
    ok, failure_signature = output_matches(case, candidate_result)
    actual_status = "pass" if ok else "fail"
    if candidate_result["timed_out"]:
        actual_status = "fail"
        failure_signature = manifest.get("timeout_policy", {}).get(
            "timeout_failure_signature", "startup_timeout"
        )
    support_claimed = row_support_claimed(case, actual_status)
    write_json(
        case_dir / "candidate.result.json",
        {
            "argv": argv,
            "returncode": candidate_result["returncode"],
            "stdout": candidate_result["stdout"],
            "stderr": candidate_result["stderr"],
            "timed_out": candidate_result["timed_out"],
            "duration_ms": candidate_result["duration_ms"],
            "actual_status": actual_status,
            "support_claimed": support_claimed,
            "failure_signature": failure_signature,
        },
    )
    write_text(case_dir / "candidate.stdout.txt", candidate_result["stdout"])
    write_text(case_dir / "candidate.stderr.txt", candidate_result["stderr"])
    write_text(case_dir / "candidate.exit_code", f"{candidate_result['returncode']}\n")
    artifact_refs.extend(
        [
            rel(case_dir / "candidate.result.json"),
            rel(case_dir / "candidate.stdout.txt"),
            rel(case_dir / "candidate.stderr.txt"),
            rel(case_dir / "candidate.exit_code"),
        ]
    )
    bundle = dict(NO_BUNDLE)
    if actual_status == "fail":
        bundle = emit_failure_bundle(
            case,
            case_dir=case_dir,
            artifact_refs=artifact_refs,
            command_text=command_text,
            actual_status=actual_status,
            failure_signature=failure_signature,
            stdout_ref=case_dir / "candidate.stdout.txt",
            stderr_ref=case_dir / "candidate.stderr.txt",
        )
        if bundle["artifact_ref"]:
            artifact_refs.append(bundle["artifact_ref"])
    append_log(
        event="candidate_run",
        workload_id=case["workload_id"],
        command=command_text,
        runtime_mode=case["runtime_mode"],
        replacement_level=case["replacement_level"],
        oracle_kind=case["oracle_kind"],
        expected_status=str(expected_status),
        actual_status=actual_status,
        errno=case.get("expected", {}).get("errno"),
        duration_ms=candidate_result["duration_ms"],
        artifact_refs=artifact_refs,
        failure_signature=failure_signature,
        bundle_id=bundle["bundle_id"],
        failure_class=bundle["failure_class"],
        next_safe_action=bundle["next_safe_action"],
        support_claimed=support_claimed,
    )
    if actual_status == "fail":
        errors.append(f"{case['case_id']}: candidate failed with {failure_signature}")
    return {
        "case_id": case["case_id"],
        "workload_id": case["workload_id"],
        "actual_status": actual_status,
        "support_claimed": support_claimed,
        "artifact_refs": artifact_refs,
        "failure_signature": failure_signature,
        "bundle_id": bundle["bundle_id"],
        "failure_class": bundle["failure_class"],
        "next_safe_action": bundle["next_safe_action"],
    }


def run_bundle_fixture_case(fixture):
    case = {
        "case_id": fixture["case_id"],
        "workload_id": fixture["workload_id"],
        "domain": fixture["domain"],
        "command": fixture["command"],
        "argv": fixture.get("argv", []),
        "env": {"set": {"LC_ALL": "C"}, "unset": ["LD_PRELOAD"]},
        "timeout_ms": 1000,
        "runtime_mode": fixture["runtime_mode"],
        "replacement_level": fixture["replacement_level"],
        "artifact_kind": "failure_bundle_fixture",
        "expected": {"status": fixture.get("expected_status"), "errno": None},
        "allowed_divergence": [],
        "cleanup": {"policy": "case_dir_scoped"},
        "oracle_kind": "failure_bundle_fixture",
        "support_claim": "never",
    }
    case_dir = run_dir / case["case_id"]
    case_dir.mkdir(parents=True, exist_ok=True)
    write_json(case_dir / "case.json", case)
    command_text = " ".join([case["command"], *case.get("argv", [])])
    stdout_text = fixture.get("stdout", "")
    stderr_text = fixture.get("stderr", "")
    actual_status = fixture["actual_status"]
    failure_signature = fixture["failure_signature"]
    write_json(
        case_dir / "candidate.result.json",
        {
            "argv": [case["command"], *case.get("argv", [])],
            "returncode": 124 if failure_signature == "startup_timeout" else 1,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "timed_out": failure_signature == "startup_timeout",
            "duration_ms": 1000 if failure_signature == "startup_timeout" else 0,
            "actual_status": actual_status,
            "support_claimed": False,
            "failure_signature": failure_signature,
        },
    )
    write_text(case_dir / "candidate.stdout.txt", stdout_text)
    write_text(case_dir / "candidate.stderr.txt", stderr_text)
    artifact_refs = [
        rel(case_dir / "case.json"),
        rel(case_dir / "candidate.result.json"),
        rel(case_dir / "candidate.stdout.txt"),
        rel(case_dir / "candidate.stderr.txt"),
    ]
    bundle = emit_failure_bundle(
        case,
        case_dir=case_dir,
        artifact_refs=artifact_refs,
        command_text=command_text,
        actual_status=actual_status,
        failure_signature=failure_signature,
        stdout_ref=case_dir / "candidate.stdout.txt",
        stderr_ref=case_dir / "candidate.stderr.txt",
        forced_failure_class=fixture["failure_class"],
    )
    if bundle["artifact_ref"]:
        artifact_refs.append(bundle["artifact_ref"])
    append_log(
        event="failure_bundle_fixture",
        workload_id=case["workload_id"],
        command=command_text,
        runtime_mode=case["runtime_mode"],
        replacement_level=case["replacement_level"],
        oracle_kind=case["oracle_kind"],
        expected_status=str(fixture.get("expected_status")),
        actual_status=actual_status,
        errno=None,
        duration_ms=0,
        artifact_refs=artifact_refs,
        failure_signature=failure_signature,
        bundle_id=bundle["bundle_id"],
        failure_class=bundle["failure_class"],
        next_safe_action=bundle["next_safe_action"],
        support_claimed=False,
    )
    return {
        "case_id": case["case_id"],
        "workload_id": case["workload_id"],
        "actual_status": actual_status,
        "support_claimed": False,
        "artifact_refs": artifact_refs,
        "failure_signature": failure_signature,
        "bundle_id": bundle["bundle_id"],
        "failure_class": bundle["failure_class"],
        "next_safe_action": bundle["next_safe_action"],
    }


validate_manifest()
stale_prior_result_rejected = validate_prior_report()

if mode not in {"run", "dry-run", "validate-only", "bundle-fixtures"}:
    errors.append(f"unknown mode {mode}")

if not errors or mode == "validate-only":
    if mode == "bundle-fixtures":
        for fixture in failure_bundle_policy.get("synthetic_failure_cases", []):
            case_results.append(run_bundle_fixture_case(fixture))
    else:
        for case in manifest.get("cases", []):
            case_results.append(run_case(case))

summary = Counter(result["actual_status"] for result in case_results)
failure_class_summary = Counter(
    result.get("failure_class", "none")
    for result in case_results
    if result.get("bundle_id") not in {None, "none"}
)
failure_bundle_count = sum(
    1 for result in case_results if result.get("bundle_id") not in {None, "none"}
)
support_claimed_count = sum(1 for result in case_results if result.get("support_claimed"))
bad_support_rows = [
    result["case_id"]
    for result in case_results
    if result.get("support_claimed") and result.get("actual_status") != "pass"
]
if bad_support_rows:
    errors.append("non-pass rows claimed support: " + ", ".join(bad_support_rows))

status = "pass" if not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": manifest.get("bead"),
    "manifest": rel(manifest_path),
    "mode": mode,
    "status": status,
    "checks": checks,
    "source_commit": source_commit,
    "target_dir": str(run_dir),
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "artifact_state": {
        "interpose": interpose_state,
        "standalone": standalone_state,
    },
    "summary": {
        "cases": len(case_results),
        "passed": summary.get("pass", 0),
        "failed": summary.get("fail", 0),
        "skipped": summary.get("skipped", 0),
        "blocked": summary.get("blocked", 0),
        "claim_blocked": summary.get("claim_blocked", 0),
        "dry_run": summary.get("dry_run", 0),
        "validated": summary.get("validated", 0),
        "bundle_fixture": summary.get("bundle_fixture", 0),
        "failure_bundles": failure_bundle_count,
        "failure_classes": dict(failure_class_summary),
        "support_claimed": support_claimed_count,
        "non_support_statuses_do_not_claim_support": not bad_support_rows,
        "stale_prior_result_rejected": stale_prior_result_rejected,
    },
    "rows": case_results,
    "errors": errors,
}

write_json(report_path, report)
write_text(
    log_path,
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows),
)

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
