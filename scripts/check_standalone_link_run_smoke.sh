#!/usr/bin/env bash
# check_standalone_link_run_smoke.sh -- direct-link smoke gate for bd-bp8fl.6.2
#
# This gate is intentionally distinct from LD_PRELOAD smoke. It compiles and
# runs host-baseline C fixtures, then attempts direct standalone linking only
# when a current libfrankenlibc_replace.so artifact is present. Missing or stale
# standalone artifacts produce structured claim_blocked evidence, not an L2+
# success claim.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${STANDALONE_SMOKE_MANIFEST:-${ROOT}/tests/conformance/standalone_link_run_smoke.v1.json}"
LEVELS="${ROOT}/tests/conformance/replacement_levels.json"
PACKAGING="${ROOT}/tests/conformance/packaging_spec.json"
OUT_ROOT="${STANDALONE_SMOKE_TARGET_DIR:-${ROOT}/target/standalone_link_run_smoke}"
RUN_ID="${STANDALONE_SMOKE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
RUN_DIR="${OUT_ROOT}/${RUN_ID}"
REPORT="${STANDALONE_SMOKE_REPORT:-${ROOT}/target/conformance/standalone_link_run_smoke.report.json}"
LOG="${STANDALONE_SMOKE_LOG:-${ROOT}/target/conformance/standalone_link_run_smoke.log.jsonl}"
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
  *)
    echo "usage: $0 [--run|--dry-run|--validate-only]" >&2
    exit 2
    ;;
esac

mkdir -p "${RUN_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${LEVELS}" "${PACKAGING}" "${RUN_DIR}" "${REPORT}" "${LOG}" "${MODE}" <<'PY'
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

root = Path(sys.argv[1]).resolve()
manifest_path = Path(sys.argv[2]).resolve()
levels_path = Path(sys.argv[3]).resolve()
packaging_path = Path(sys.argv[4]).resolve()
run_dir = Path(sys.argv[5]).resolve()
report_path = Path(sys.argv[6]).resolve()
log_path = Path(sys.argv[7]).resolve()
mode = sys.argv[8]

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "smoke_id",
    "compiler",
    "link_args",
    "runtime_mode",
    "replacement_level",
    "expected_status",
    "actual_status",
    "loader_error",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_CATEGORIES = {
    "minimal",
    "stdio_file",
    "pthread_tls",
    "resolver_locale",
    "negative_missing_obligation",
    "loader_symbol_bootstrap",
    "vm_syscall_ipc",
    "diagnostics_session",
    "profiling_fenv",
    "loader_process_negative_missing_obligation",
}
NEGATIVE_CATEGORIES = {
    "negative_missing_obligation",
    "loader_process_negative_missing_obligation",
}
POSITIVE_CATEGORIES = REQUIRED_CATEGORIES - NEGATIVE_CATEGORIES
EXPECTED_SOURCE_COMMIT_FRESHNESS_POLICY = {
    "recorded_source_commit_field": "source_commit",
    "comparison_target": "current git HEAD",
    "stale_result": "block_standalone_link_run_smoke_evidence",
    "standalone_smoke_evidence_allowed_when_stale": False,
    "rejected_evidence_kind": "stale_source_commit",
}

errors = []
checks = {}
log_rows = []
row_results = []


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return {}


manifest = load_json(manifest_path)
levels = load_json(levels_path)
packaging = load_json(packaging_path)

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

source_input_epoch = max(
    (
        int(path.stat().st_mtime)
        for path in [
            manifest_path,
            levels_path,
            packaging_path,
            root / "scripts" / "check_standalone_link_run_smoke.sh",
        ]
        if path.exists()
    ),
    default=0,
)
freshness_epoch = head_epoch or source_input_epoch


def compiler_argv():
    raw = os.environ.get("CC", "cc")
    argv = shlex.split(raw)
    return argv if argv else ["cc"]


compiler = compiler_argv()
compiler_name = " ".join(compiler)


def json_dump(value):
    return json.dumps(value, sort_keys=True)


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def append_log(
    *,
    event,
    smoke_id,
    owner_bead=None,
    runtime_mode,
    replacement_level,
    expected_status,
    actual_status,
    failure_signature,
    link_args=None,
    loader_error=None,
    artifact_refs=None,
):
    bead_id = owner_bead or manifest.get("bead")
    trace_id = f"{bead_id or 'unknown'}::{run_dir.name}::{smoke_id}::{runtime_mode}::{event}"
    row = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": "info" if actual_status in {"pass", "blocked", "claim_blocked", "validated"} else "error",
        "event": event,
        "trace_id": trace_id,
        "bead_id": bead_id,
        "smoke_id": smoke_id,
        "compiler": compiler_name,
        "link_args": link_args or [],
        "runtime_mode": runtime_mode,
        "replacement_level": replacement_level,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "loader_error": loader_error,
        "artifact_refs": artifact_refs or [],
        "source_commit": source_commit,
        "target_dir": str(run_dir),
        "failure_signature": failure_signature,
    }
    log_rows.append(row)


def render_template(tokens, replacements):
    rendered = []
    for token in tokens:
        if token == "${CC}":
            rendered.extend(compiler)
            continue
        value = token
        for key, replacement in replacements.items():
            value = value.replace("${" + key + "}", str(replacement))
        rendered.append(value)
    return rendered


def standalone_library_candidates():
    candidates = []
    env_path = os.environ.get("FRANKENLIBC_STANDALONE_LIB")
    if env_path:
        candidates.append(Path(env_path))
    cargo_target = os.environ.get("CARGO_TARGET_DIR")
    if cargo_target:
        candidates.append(Path(cargo_target) / "release" / "libfrankenlibc_replace.so")
        candidates.append(Path(cargo_target) / "debug" / "libfrankenlibc_replace.so")
    candidates.append(root / "target" / "release" / "libfrankenlibc_replace.so")
    candidates.append(root / "target" / "debug" / "libfrankenlibc_replace.so")
    return candidates


def run_probe_command(command):
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "timeout",
        }
    except OSError as exc:
        return {
            "returncode": 127,
            "stdout": "",
            "stderr": str(exc),
        }


def classify_artifact():
    for candidate in standalone_library_candidates():
        if not candidate.exists():
            continue
        if candidate.name != "libfrankenlibc_replace.so":
            return {
                "status": "wrong_profile",
                "path": str(candidate),
                "failure_signature": "wrong_artifact_profile",
                "loader_error": "standalone artifact must be named libfrankenlibc_replace.so",
            }
        try:
            mtime = int(candidate.stat().st_mtime)
        except OSError:
            mtime = 0
        if freshness_epoch and mtime < freshness_epoch:
            return {
                "status": "stale",
                "path": str(candidate),
                "mtime": mtime,
                "head_epoch": head_epoch,
                "freshness_epoch": freshness_epoch,
                "failure_signature": "standalone_artifact_stale",
                "loader_error": "standalone artifact predates source HEAD",
            }
        readelf_dynamic = run_probe_command(["readelf", "-d", str(candidate)])
        ldd = run_probe_command(["ldd", str(candidate)])
        if readelf_dynamic["returncode"] != 0 or ldd["returncode"] != 0:
            return {
                "status": "inspection_failed",
                "path": str(candidate),
                "mtime": mtime,
                "head_epoch": head_epoch,
                "freshness_epoch": freshness_epoch,
                "failure_signature": "artifact_dependency_inspection_failed",
                "loader_error": "dependency inspection failed for standalone artifact",
            }
        dep_text = "\n".join(
            [
                readelf_dynamic["stdout"],
                readelf_dynamic["stderr"],
                ldd["stdout"],
                ldd["stderr"],
            ]
        )
        if "libc.so" in dep_text or "ld-linux" in dep_text:
            return {
                "status": "host_dependent",
                "path": str(candidate),
                "mtime": mtime,
                "head_epoch": head_epoch,
                "freshness_epoch": freshness_epoch,
                "failure_signature": "host_glibc_dependency",
                "loader_error": "standalone artifact still depends on host libc or loader",
            }
        return {
            "status": "current",
            "path": str(candidate),
            "mtime": mtime,
            "head_epoch": head_epoch,
            "freshness_epoch": freshness_epoch,
            "failure_signature": "none",
            "loader_error": None,
        }
    return {
        "status": "missing",
        "path": None,
        "failure_signature": "standalone_artifact_missing",
        "loader_error": "libfrankenlibc_replace.so not supplied or discovered",
    }


artifact_state = classify_artifact()


def full_git_commit(value):
    return isinstance(value, str) and len(value) == 40 and all(
        byte in "0123456789abcdefABCDEF" for byte in value
    )


def source_commit_marker_is_current(value):
    return value == "current" or (source_commit != "unknown" and value == source_commit)


def validate_manifest():
    checks["json_parse"] = "pass" if isinstance(manifest, dict) and isinstance(levels, dict) else "fail"
    if manifest.get("schema_version") != "v1":
        errors.append("manifest must declare schema_version=v1")
    if manifest.get("bead") != "bd-bp8fl.6.2":
        errors.append("manifest must be linked to bead bd-bp8fl.6.2")
    checks["top_level_shape"] = "pass" if not errors else "fail"

    freshness = manifest.get("freshness", {})
    required_source_commit = freshness.get("required_source_commit") if isinstance(freshness, dict) else None
    source_commit_policy = freshness.get("source_commit_policy", "") if isinstance(freshness, dict) else ""
    source_commit_matches = (
        required_source_commit == "current" or source_commit_marker_is_current(required_source_commit)
    )
    freshness_ok = (
        isinstance(freshness, dict)
        and source_commit_matches
        and isinstance(source_commit_policy, str)
        and "current git HEAD" in source_commit_policy
        and "reject" in source_commit_policy
    )
    checks["source_commit_freshness"] = "pass" if freshness_ok else "fail"
    if not freshness_ok:
        errors.append(
            "freshness.required_source_commit must be 'current' or match current git HEAD, "
            "and source_commit_policy must reject stale manifest source commits"
        )
    manifest_source_commit = manifest.get("source_commit")
    recorded_source_commit_current = source_commit_marker_is_current(manifest_source_commit)
    source_commit_policy_ok = (
        (manifest_source_commit == "current" or full_git_commit(manifest_source_commit))
        and manifest.get("source_commit_freshness_policy") == EXPECTED_SOURCE_COMMIT_FRESHNESS_POLICY
    )
    checks["source_commit_freshness_policy"] = "pass" if source_commit_policy_ok else "fail"
    checks["recorded_source_commit_freshness"] = (
        "pass" if source_commit_policy_ok and recorded_source_commit_current else "fail"
    )
    if not source_commit_policy_ok:
        errors.append("source_commit_freshness_policy does not match script contract")
    elif not recorded_source_commit_current:
        errors.append("source_commit must be 'current' or match current git HEAD")

    if manifest.get("required_log_fields") == REQUIRED_LOG_FIELDS:
        checks["required_log_fields"] = "pass"
    else:
        checks["required_log_fields"] = "fail"
        errors.append("required_log_fields do not match bd-bp8fl.6.2 log contract")

    policy = manifest.get("current_claim_policy", {})
    allowed_non_standalone_levels = policy.get(
        "current_levels_allowed_without_standalone_claim", ["L0"]
    )
    policy_ok = (
        isinstance(allowed_non_standalone_levels, list)
        and set(allowed_non_standalone_levels) == {"L0", "L1"}
        and policy.get("ld_preload_evidence_accepted") is False
        and policy.get("missing_or_stale_candidate_result") == "claim_blocked"
        and policy.get("host_glibc_dependency_result") == "claim_blocked"
        and policy.get("standalone_evidence_starts_at") == "L2"
    )
    checks["claim_policy"] = "pass" if policy_ok else "fail"
    if not policy_ok:
        errors.append("current_claim_policy must reject LD_PRELOAD/host-libc substitution and fail closed")

    allowed_non_standalone_levels = set(
        allowed_non_standalone_levels
        if isinstance(allowed_non_standalone_levels, list)
        else ["L0"]
    )
    current_level_ok = (
        levels.get("current_level") in allowed_non_standalone_levels
        and levels.get("release_tag_policy", {}).get("current_release_level") in allowed_non_standalone_levels
    )
    checks["replacement_level_guard"] = "pass" if current_level_ok else "fail"
    if not current_level_ok:
        errors.append("replacement_levels current_level and release_tag_policy must remain below L2")

    replace_artifact = packaging.get("artifacts", {}).get("replace", {})
    artifact_ok = (
        replace_artifact.get("artifact_name") == "libfrankenlibc_replace.so"
        and replace_artifact.get("host_glibc_required") is False
        and "standalone" in replace_artifact.get("cargo_features", [])
    )
    checks["packaging_replace_profile"] = "pass" if artifact_ok else "fail"
    if not artifact_ok:
        errors.append("packaging_spec replace artifact must name libfrankenlibc_replace.so and require standalone feature")

    rows = manifest.get("smoke_rows", [])
    row_ids = [row.get("smoke_id") for row in rows]
    categories = {row.get("category") for row in rows}
    rows_ok = bool(rows) and len(row_ids) == len(set(row_ids)) and REQUIRED_CATEGORIES <= categories
    positive_count = 0
    negative_count = 0
    for row in rows:
        smoke_id = row.get("smoke_id", "<missing smoke_id>")
        required_fields = [
            "smoke_id",
            "category",
            "description",
            "source_filename",
            "c_source",
            "replacement_level",
            "runtime_modes",
            "link_command",
            "runtime_env",
            "expected_loader_startup",
            "symbol_version_requirements",
            "expected_output",
            "cleanup",
        ]
        for field in required_fields:
            if field not in row:
                rows_ok = False
                errors.append(f"{smoke_id}: missing field {field}")
        if row.get("negative_case"):
            negative_count += 1
            if not row.get("missing_obligations"):
                rows_ok = False
                errors.append(f"{smoke_id}: negative row must list missing_obligations")
        else:
            positive_count += 1
            if row.get("category") not in POSITIVE_CATEGORIES:
                rows_ok = False
                errors.append(f"{smoke_id}: positive row has unexpected category")
        command = row.get("link_command", {})
        for key in ["baseline_template", "candidate_template"]:
            template = command.get(key, [])
            if not isinstance(template, list) or not template:
                rows_ok = False
                errors.append(f"{smoke_id}: link_command.{key} must be a non-empty array")
            if any("LD_PRELOAD" in str(token) for token in template):
                rows_ok = False
                errors.append(f"{smoke_id}: link command must not contain LD_PRELOAD")
        forbidden_env = row.get("runtime_env", {}).get("forbidden", [])
        if "LD_PRELOAD" not in forbidden_env:
            rows_ok = False
            errors.append(f"{smoke_id}: runtime_env.forbidden must include LD_PRELOAD")
        if set(row.get("runtime_modes", [])) != {"strict", "hardened"}:
            rows_ok = False
            errors.append(f"{smoke_id}: runtime_modes must be strict+hardened")

    summary = manifest.get("summary", {})
    summary_ok = (
        summary.get("row_count") == len(rows)
        and summary.get("positive_row_count") == positive_count
        and summary.get("negative_row_count") == negative_count
        and set(summary.get("required_categories", [])) == REQUIRED_CATEGORIES
        and summary.get("ld_preload_smoke_substitutes_for_standalone") is False
    )
    checks["smoke_rows"] = "pass" if rows_ok else "fail"
    checks["summary_counts"] = "pass" if summary_ok else "fail"
    if not rows_ok:
        errors.append("smoke rows must cover required categories with direct-link contracts")
    if not summary_ok:
        errors.append("summary counts/categories do not match smoke_rows")


def write_text(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def run_command(command, *, cwd, env=None, timeout=10):
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "timeout",
            "timed_out": True,
        }


def run_rows():
    if mode == "validate-only":
        append_log(
            event="manifest_validated",
            smoke_id="manifest",
            runtime_mode="n/a",
            replacement_level="L2,L3",
            expected_status="schema_valid",
            actual_status="validated",
            failure_signature="none" if not errors else "manifest_validation_failed",
            artifact_refs=[rel(manifest_path), rel(report_path), rel(log_path)],
        )
        return

    if shutil.which(compiler[0]) is None:
        errors.append(f"required compiler not found: {compiler[0]}")
        return

    for index, row in enumerate(manifest.get("smoke_rows", []), start=1):
        smoke_id = row["smoke_id"]
        case_dir = run_dir / f"{index:02d}-{smoke_id.replace('.', '_')}"
        source_path = case_dir / row["source_filename"]
        baseline_bin = case_dir / "baseline.bin"
        candidate_bin = case_dir / "candidate.bin"
        write_text(source_path, row["c_source"])
        replacements = {
            "CC": compiler_name,
            "source": source_path,
            "baseline_binary": baseline_bin,
            "candidate_binary": candidate_bin,
            "standalone_library": artifact_state["path"] or "${standalone_library}",
            "standalone_library_dir": str(Path(artifact_state["path"]).parent)
            if artifact_state.get("path")
            else "${standalone_library_dir}",
        }
        baseline_cmd = render_template(
            row["link_command"]["baseline_template"],
            replacements,
        )
        candidate_cmd = render_template(
            row["link_command"]["candidate_template"],
            replacements,
        )
        artifact_refs = [
            rel(source_path),
            rel(case_dir / "baseline.link.txt"),
            rel(case_dir / "candidate.link.txt"),
        ]
        write_text(case_dir / "baseline.link.txt", shlex.join(baseline_cmd) + "\n")
        write_text(case_dir / "candidate.link.txt", shlex.join(candidate_cmd) + "\n")

        baseline_status = "skipped"
        baseline_rc = None
        baseline_failure = "none"
        if mode == "run":
            compile_result = run_command(baseline_cmd, cwd=root)
            write_text(case_dir / "baseline.compile.stdout.txt", compile_result["stdout"])
            write_text(case_dir / "baseline.compile.stderr.txt", compile_result["stderr"])
            artifact_refs.extend(
                [
                    rel(case_dir / "baseline.compile.stdout.txt"),
                    rel(case_dir / "baseline.compile.stderr.txt"),
                ]
            )
            if compile_result["returncode"] != 0:
                baseline_status = "fail"
                baseline_rc = compile_result["returncode"]
                baseline_failure = "baseline_compile_failed"
            else:
                run_result = run_command([str(baseline_bin)], cwd=case_dir)
                write_text(case_dir / "baseline.stdout.txt", run_result["stdout"])
                write_text(case_dir / "baseline.stderr.txt", run_result["stderr"])
                write_text(case_dir / "baseline.exit_code", f"{run_result['returncode']}\n")
                artifact_refs.extend(
                    [
                        rel(baseline_bin),
                        rel(case_dir / "baseline.stdout.txt"),
                        rel(case_dir / "baseline.stderr.txt"),
                        rel(case_dir / "baseline.exit_code"),
                    ]
                )
                expected = row["expected_output"]
                stdout_contains = expected.get("stdout_contains", "")
                stderr_contains = expected.get("stderr_contains", "")
                baseline_rc = run_result["returncode"]
                if (
                    run_result["returncode"] == expected.get("baseline_status")
                    and (not stdout_contains or stdout_contains in run_result["stdout"])
                    and (not stderr_contains or stderr_contains in run_result["stderr"])
                ):
                    baseline_status = "pass"
                else:
                    baseline_status = "fail"
                    baseline_failure = "baseline_output_mismatch"
        else:
            baseline_status = "dry_run"

        append_log(
            event="baseline_compile_run",
            smoke_id=smoke_id,
            owner_bead=row.get("owner_bead"),
            runtime_mode="baseline",
            replacement_level="host-baseline",
            expected_status="exit_code=0",
            actual_status=baseline_status,
            failure_signature=baseline_failure,
            link_args=baseline_cmd,
            loader_error=None,
            artifact_refs=artifact_refs,
        )

        if baseline_status == "fail":
            errors.append(f"{smoke_id}: baseline failed with {baseline_failure}")

        candidate_results = []
        for runtime_mode in row["runtime_modes"]:
            candidate_refs = list(artifact_refs)
            expected_candidate = row["expected_output"]["candidate_status_when_artifact_current"]
            actual_status = "blocked"
            failure_signature = artifact_state["failure_signature"]
            loader_error = artifact_state["loader_error"]
            candidate_rc = None
            if row.get("negative_case"):
                expected_candidate = "claim_blocked"
                actual_status = "claim_blocked"
                failure_signature = "missing_obligation"
                loader_error = ",".join(row.get("missing_obligations", []))
            elif artifact_state["status"] != "current":
                expected_candidate = "claim_blocked"
                actual_status = "claim_blocked"
            elif mode == "dry-run":
                actual_status = "dry_run_current_artifact"
                failure_signature = "none"
                loader_error = None
            elif mode == "run":
                compile_result = run_command(candidate_cmd, cwd=root)
                write_text(case_dir / f"candidate.{runtime_mode}.compile.stdout.txt", compile_result["stdout"])
                write_text(case_dir / f"candidate.{runtime_mode}.compile.stderr.txt", compile_result["stderr"])
                candidate_refs.extend(
                    [
                        rel(candidate_bin),
                        rel(case_dir / f"candidate.{runtime_mode}.compile.stdout.txt"),
                        rel(case_dir / f"candidate.{runtime_mode}.compile.stderr.txt"),
                    ]
                )
                if compile_result["returncode"] != 0:
                    actual_status = "fail"
                    candidate_rc = compile_result["returncode"]
                    failure_signature = "symbol_version_mismatch"
                    loader_error = compile_result["stderr"].strip()
                else:
                    env = os.environ.copy()
                    env.pop("LD_PRELOAD", None)
                    env["FRANKENLIBC_MODE"] = runtime_mode
                    if row["category"] == "resolver_locale":
                        env["LC_ALL"] = "C"
                    run_result = run_command([str(candidate_bin)], cwd=case_dir, env=env)
                    candidate_rc = run_result["returncode"]
                    write_text(case_dir / f"candidate.{runtime_mode}.stdout.txt", run_result["stdout"])
                    write_text(case_dir / f"candidate.{runtime_mode}.stderr.txt", run_result["stderr"])
                    write_text(case_dir / f"candidate.{runtime_mode}.exit_code", f"{run_result['returncode']}\n")
                    candidate_refs.extend(
                        [
                            rel(case_dir / f"candidate.{runtime_mode}.stdout.txt"),
                            rel(case_dir / f"candidate.{runtime_mode}.stderr.txt"),
                            rel(case_dir / f"candidate.{runtime_mode}.exit_code"),
                        ]
                    )
                    stdout_contains = row["expected_output"].get("stdout_contains", "")
                    stderr_contains = row["expected_output"].get("stderr_contains", "")
                    if (
                        run_result["returncode"] == expected_candidate
                        and (not stdout_contains or stdout_contains in run_result["stdout"])
                        and (not stderr_contains or stderr_contains in run_result["stderr"])
                    ):
                        actual_status = "pass"
                        failure_signature = "none"
                        loader_error = None
                    else:
                        actual_status = "fail"
                        failure_signature = "loader_startup_failure"
                        loader_error = run_result["stderr"].strip()

            append_log(
                event="candidate_direct_link",
                smoke_id=smoke_id,
                owner_bead=row.get("owner_bead"),
                runtime_mode=runtime_mode,
                replacement_level=row["replacement_level"],
                expected_status=str(expected_candidate),
                actual_status=actual_status,
                failure_signature=failure_signature,
                link_args=candidate_cmd,
                loader_error=loader_error,
                artifact_refs=candidate_refs,
            )
            candidate_results.append(
                {
                    "runtime_mode": runtime_mode,
                    "expected_status": expected_candidate,
                    "actual_status": actual_status,
                    "returncode": candidate_rc,
                    "failure_signature": failure_signature,
                    "loader_error": loader_error,
                }
            )

            if row.get("negative_case"):
                if actual_status != "claim_blocked":
                    errors.append(f"{smoke_id}/{runtime_mode}: negative row must remain claim_blocked")
            elif artifact_state["status"] == "current" and mode == "run" and actual_status != "pass":
                errors.append(f"{smoke_id}/{runtime_mode}: current standalone artifact did not pass")

        row_results.append(
            {
                "smoke_id": smoke_id,
                "category": row["category"],
                "replacement_level": row["replacement_level"],
                "negative_case": bool(row.get("negative_case", False)),
                "baseline_status": baseline_status,
                "baseline_returncode": baseline_rc,
                "candidate_results": candidate_results,
                "case_dir": str(case_dir),
                "artifact_refs": artifact_refs,
            }
        )


validate_manifest()
run_rows()

positive_rows = [row for row in row_results if not row["negative_case"]]
negative_rows = [row for row in row_results if row["negative_case"]]
candidate_passed = sum(
    1
    for row in positive_rows
    for result in row["candidate_results"]
    if result["actual_status"] == "pass"
)
candidate_blocked = sum(
    1
    for row in row_results
    for result in row["candidate_results"]
    if result["actual_status"] == "claim_blocked"
)
candidate_failed = sum(
    1
    for row in row_results
    for result in row["candidate_results"]
    if result["actual_status"] == "fail"
)
baseline_passed = sum(1 for row in row_results if row["baseline_status"] == "pass")
baseline_failed = sum(1 for row in row_results if row["baseline_status"] == "fail")
baseline_dry_run = sum(1 for row in row_results if row["baseline_status"] == "dry_run")

current_level = levels.get("current_level", "unknown")
release_level = levels.get("release_tag_policy", {}).get("current_release_level", "unknown")
all_positive_passed = bool(positive_rows) and all(
    all(result["actual_status"] == "pass" for result in row["candidate_results"])
    for row in positive_rows
)
all_negative_blocked = all(
    all(result["actual_status"] == "claim_blocked" for result in row["candidate_results"])
    for row in negative_rows
)

if current_level in {"L2", "L3"} or release_level in {"L2", "L3"}:
    if not all_positive_passed or not all_negative_blocked:
        errors.append("L2/L3 claim is not allowed without passing standalone rows and blocked negative rows")

claim_status = "standalone_evidence_passed" if all_positive_passed and all_negative_blocked else "claim_blocked"
if mode == "validate-only":
    claim_status = "schema_validated"

status = "pass" if not errors else "fail"
checks["standalone_artifact_state"] = artifact_state["status"]
checks["ld_preload_separation"] = "pass"
for row in manifest.get("smoke_rows", []):
    serialized = json.dumps(row)
    if "LD_PRELOAD" in serialized and '"forbidden"' not in serialized:
        checks["ld_preload_separation"] = "fail"
        errors.append(f"{row.get('smoke_id')}: LD_PRELOAD appears outside forbidden env declaration")
        break

artifact_refs = [
    rel(manifest_path),
    rel(levels_path),
    rel(packaging_path),
    rel(report_path),
    rel(log_path),
    rel(run_dir),
]
report = {
    "schema_version": "v1",
    "bead": manifest.get("bead"),
    "manifest_id": manifest.get("manifest_id"),
    "mode": mode,
    "run_id": run_dir.name,
    "status": status,
    "claim_status": claim_status,
    "current_level": current_level,
    "current_release_level": release_level,
    "ld_preload_evidence_accepted": manifest.get("current_claim_policy", {}).get("ld_preload_evidence_accepted"),
    "artifact_state": artifact_state,
    "checks": checks,
    "summary": {
        "rows": len(row_results),
        "positive_rows": len(positive_rows),
        "negative_rows": len(negative_rows),
        "baseline_passed": baseline_passed,
        "baseline_failed": baseline_failed,
        "baseline_dry_run": baseline_dry_run,
        "candidate_passed": candidate_passed,
        "candidate_blocked": candidate_blocked,
        "candidate_failed": candidate_failed,
    },
    "rows": row_results,
    "errors": errors,
    "required_log_fields": REQUIRED_LOG_FIELDS,
    "artifact_refs": artifact_refs,
    "source_commit": source_commit,
    "target_dir": str(run_dir),
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if not log_rows:
    append_log(
        event="gate_report",
        smoke_id="gate",
        runtime_mode="n/a",
        replacement_level="L2,L3",
        expected_status="report_written",
        actual_status=status,
        failure_signature="none" if status == "pass" else "gate_failed",
        artifact_refs=artifact_refs,
    )
for row in log_rows:
    missing = [field for field in REQUIRED_LOG_FIELDS if field not in row]
    if missing:
        errors.append(f"log row missing required fields: {missing}")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows), encoding="utf-8")

if errors and status == "pass":
    status = "fail"
    report["status"] = status
    report["errors"] = errors
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
