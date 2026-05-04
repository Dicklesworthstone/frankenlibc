#!/usr/bin/env bash
# run_user_workload_replay_traces.sh -- trace capture runner for bd-b92jd.3.2
#
# Consumes the bd-b92jd.3.1 workload replay manifest, runs safe baseline rows,
# and records strict/hardened comparison rows. Missing preload artifacts and
# optional tools become structured blocked/skipped evidence, not support claims.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${USER_WORKLOAD_REPLAY_MANIFEST:-$ROOT/tests/conformance/user_workload_replay_manifest.v1.json}"
RUN_ID="${USER_WORKLOAD_REPLAY_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
TARGET_ROOT="${USER_WORKLOAD_REPLAY_TARGET_DIR:-$ROOT/target/user_workload_replay_traces}"
RUN_DIR="${TARGET_ROOT}/${RUN_ID}"
REPORT="${USER_WORKLOAD_REPLAY_TRACE_REPORT:-$ROOT/target/conformance/user_workload_replay_traces.report.json}"
LOG="${USER_WORKLOAD_REPLAY_TRACE_LOG:-$ROOT/target/conformance/user_workload_replay_traces.log.jsonl}"
MODE="${1:---run}"

case "${MODE}" in
  --run|--validate-only)
    ;;
  *)
    echo "usage: $0 [--run|--validate-only]" >&2
    exit 2
    ;;
esac

python3 - "${ROOT}" "${MANIFEST}" "${RUN_DIR}" "${REPORT}" "${LOG}" "${MODE}" <<'PY'
import hashlib
import json
import os
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

BEAD_ID = "bd-b92jd.3.2"
SOURCE_BEAD_ID = "bd-b92jd.3.1"
REQUIRED_MODES = ["baseline", "strict", "hardened"]
REQUIRED_TRACE_FIELDS = [
    "trace_id",
    "workload_id",
    "mode",
    "command",
    "env",
    "baseline_exit",
    "preload_exit",
    "expected_stdout_digest",
    "actual_stdout_digest",
    "stderr_signature",
    "latency_ns",
    "failure_signature",
    "source_commit",
    "target_dir",
    "artifact_refs",
]

errors = []
trace_rows = []
baseline_results = {}


def current_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def head_epoch():
    try:
        return int(
            subprocess.check_output(
                ["git", "log", "-1", "--format=%ct", "HEAD"],
                cwd=root,
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        )
    except Exception:
        return 0


SOURCE_COMMIT = current_commit()
HEAD_EPOCH = head_epoch()


def rel(path):
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return {}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def safe_name(text):
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(text))


def digest_bytes(data):
    return "sha256:" + hashlib.sha256(data or b"").hexdigest()


def stderr_signature(stderr):
    if not stderr:
        return "none"
    excerpt = stderr.decode("utf-8", errors="replace").strip().splitlines()
    first = excerpt[0] if excerpt else ""
    if "No such file" in first:
        return "stderr_no_such_file"
    if "cannot open shared object file" in first or "ld.so" in first:
        return "stderr_loader"
    return "stderr_sha256:" + hashlib.sha256(stderr).hexdigest()[:16]


def command_display(workload):
    command = workload.get("command", {})
    kind = command.get("kind")
    if kind == "pipeline":
        display = []
        for index, stage in enumerate(command.get("stages", [])):
            if index:
                display.append("|")
            display.extend(stage.get("argv", []))
        return display
    if kind == "c_fixture":
        return list(command.get("argv", []))
    return list(command.get("argv", []))


def base_env():
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", str(root)),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }


def resolve_env_overlay(env_overlay, preload_path):
    env = base_env()
    for key, value in sorted((env_overlay or {}).items()):
        if value == "${FRANKENLIBC_ABI_LIB}":
            env[key] = preload_path or ""
        else:
            env[key] = str(value)
    if not env.get("LD_PRELOAD"):
        env.pop("LD_PRELOAD", None)
    return env


def trace_env(env):
    selected = {}
    for key in ["FRANKENLIBC_MODE", "LD_PRELOAD", "PATH", "TMPDIR"]:
        if key in env:
            selected[key] = env[key]
    return selected


def classify_preload_artifact():
    path_text = os.environ.get("FRANKENLIBC_ABI_LIB") or os.environ.get("FRANKENLIBC_SMOKE_LIB_PATH")
    if not path_text:
        return {"status": "missing", "path": None, "failure_signature": "interpose_artifact_missing"}
    path = Path(path_text)
    if not path.exists():
        return {"status": "missing", "path": str(path), "failure_signature": "interpose_artifact_missing"}
    if path.name != "libfrankenlibc_abi.so":
        return {"status": "wrong_name", "path": str(path), "failure_signature": "interpose_artifact_wrong_name"}
    try:
        if HEAD_EPOCH and int(path.stat().st_mtime) < HEAD_EPOCH:
            return {"status": "stale", "path": str(path), "failure_signature": "interpose_artifact_stale"}
    except OSError:
        return {"status": "unreadable", "path": str(path), "failure_signature": "interpose_artifact_unreadable"}
    return {"status": "current", "path": str(path), "failure_signature": "none"}


def forced_missing_tools():
    raw = os.environ.get("USER_WORKLOAD_REPLAY_FORCE_MISSING_TOOLS", "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def optional_skip_reason(workload):
    if not workload.get("optional"):
        return None
    skip_policy = workload.get("skip_policy", {})
    tool = skip_policy.get("tool")
    if not tool:
        return "optional_tool_missing:<missing>"
    if tool in forced_missing_tools() or shutil.which(tool) is None:
        return skip_policy.get("deterministic_skip_reason") or f"optional_tool_missing:{tool}"
    return None


def normalize_argv(argv):
    if not isinstance(argv, list) or not argv:
        return None
    normalized = []
    for item in argv:
        if not isinstance(item, str) or not item:
            return None
        normalized.append(item)
    return normalized


def run_argv(argv, env, timeout_ms, cwd):
    normalized = normalize_argv(argv)
    if normalized is None:
        return {"status": "fail", "exit": None, "stdout": b"", "stderr": b"invalid argv", "latency_ns": 0, "failure_signature": "invalid_command_argv"}
    if Path(normalized[0]).is_absolute() and not Path(normalized[0]).exists():
        return {"status": "fail", "exit": None, "stdout": b"", "stderr": b"command unavailable", "latency_ns": 0, "failure_signature": "command_unavailable"}
    if not Path(normalized[0]).is_absolute() and shutil.which(normalized[0], path=env.get("PATH")) is None:
        return {"status": "fail", "exit": None, "stdout": b"", "stderr": b"command unavailable", "latency_ns": 0, "failure_signature": "command_unavailable"}
    start = time.monotonic_ns()
    try:
        proc = subprocess.run(
            normalized,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(timeout_ms / 1000.0, 0.001),
            check=False,
        )
        latency = time.monotonic_ns() - start
        return {
            "status": "pass" if proc.returncode == 0 else "fail",
            "exit": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "latency_ns": latency,
            "failure_signature": "none" if proc.returncode == 0 else "exit_mismatch",
        }
    except subprocess.TimeoutExpired as exc:
        latency = time.monotonic_ns() - start
        return {
            "status": "fail",
            "exit": 124,
            "stdout": exc.stdout or b"",
            "stderr": exc.stderr or b"timeout",
            "latency_ns": latency,
            "failure_signature": "startup_timeout",
        }


def run_pipeline(stages, env, timeout_ms):
    input_data = None
    stderr_parts = []
    total_latency = 0
    last_exit = None
    stdout = b""
    for stage in stages:
        result = run_argv(stage.get("argv"), env, timeout_ms, root)
        total_latency += result["latency_ns"]
        stderr_parts.append(result["stderr"])
        last_exit = result["exit"]
        stdout = result["stdout"]
        if result["status"] != "pass":
            return {
                "status": "fail",
                "exit": last_exit,
                "stdout": stdout,
                "stderr": b"".join(stderr_parts),
                "latency_ns": total_latency,
                "failure_signature": result["failure_signature"],
            }
        input_data = stdout
        if stage is not stages[-1]:
            next_index = stages.index(stage) + 1
            next_stage = stages[next_index]
            argv = normalize_argv(next_stage.get("argv"))
            if argv is None:
                return {"status": "fail", "exit": None, "stdout": b"", "stderr": b"invalid argv", "latency_ns": total_latency, "failure_signature": "invalid_command_argv"}
            start = time.monotonic_ns()
            try:
                proc = subprocess.run(
                    argv,
                    input=input_data,
                    cwd=root,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=max(timeout_ms / 1000.0, 0.001),
                    check=False,
                )
                total_latency += time.monotonic_ns() - start
                stdout = proc.stdout
                stderr_parts.append(proc.stderr)
                last_exit = proc.returncode
                if proc.returncode != 0:
                    return {
                        "status": "fail",
                        "exit": proc.returncode,
                        "stdout": stdout,
                        "stderr": b"".join(stderr_parts),
                        "latency_ns": total_latency,
                        "failure_signature": "exit_mismatch",
                    }
            except subprocess.TimeoutExpired as exc:
                total_latency += time.monotonic_ns() - start
                return {
                    "status": "fail",
                    "exit": 124,
                    "stdout": exc.stdout or b"",
                    "stderr": (exc.stderr or b"") + b"timeout",
                    "latency_ns": total_latency,
                    "failure_signature": "startup_timeout",
                }
            break
    return {
        "status": "pass" if last_exit == 0 else "fail",
        "exit": last_exit,
        "stdout": stdout,
        "stderr": b"".join(stderr_parts),
        "latency_ns": total_latency,
        "failure_signature": "none" if last_exit == 0 else "exit_mismatch",
    }


def fixture_binary_path(workload):
    workload_id = workload.get("workload_id", "c_fixture")
    return run_dir / "c_fixtures" / safe_name(workload_id)


def build_c_fixture(workload, env):
    command = workload.get("command", {})
    build_argv = normalize_argv(command.get("build_argv"))
    if build_argv is None:
        return {"ok": False, "failure_signature": "invalid_command_argv", "stderr": b"invalid build argv"}
    out_path = fixture_binary_path(workload)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    build_argv = list(build_argv)
    build_argv[-1] = str(out_path)
    result = run_argv(build_argv, env, int(workload.get("timeout_ms", 7000)), root)
    return {
        "ok": result["status"] == "pass",
        "failure_signature": result["failure_signature"],
        "stderr": result["stderr"],
    }


def run_workload(workload, runtime_mode, env, preload_artifact):
    command = workload.get("command", {})
    kind = command.get("kind")
    timeout_ms = int(workload.get("timeout_ms", 5000))
    if runtime_mode in {"strict", "hardened"} and preload_artifact["status"] != "current":
        return {
            "status": "claim_blocked",
            "exit": None,
            "stdout": b"",
            "stderr": preload_artifact["failure_signature"].encode(),
            "latency_ns": 0,
            "failure_signature": preload_artifact["failure_signature"],
        }
    if kind in {"argv", "dynamic_runtime"}:
        return run_argv(command.get("argv"), env, timeout_ms, root)
    if kind == "pipeline":
        return run_pipeline(command.get("stages", []), env, timeout_ms)
    if kind == "c_fixture":
        binary_path = fixture_binary_path(workload)
        if runtime_mode == "baseline" or not binary_path.exists():
            build = build_c_fixture(workload, env)
            if not build["ok"]:
                return {
                    "status": "fail",
                    "exit": None,
                    "stdout": b"",
                    "stderr": build["stderr"],
                    "latency_ns": 0,
                    "failure_signature": build["failure_signature"],
                }
        return run_argv([str(binary_path)], env, timeout_ms, root)
    return {"status": "fail", "exit": None, "stdout": b"", "stderr": b"unknown command kind", "latency_ns": 0, "failure_signature": "invalid_command_argv"}


def expected_stdout_digest(workload, baseline):
    expected = workload.get("mode_expectations", {}).get("baseline", {}).get("expected", {})
    stdout = expected.get("stdout", {})
    kind = stdout.get("kind")
    if kind == "exact" and isinstance(stdout.get("value"), str):
        return digest_bytes(stdout.get("value").encode())
    return digest_bytes((baseline or {}).get("stdout", b""))


def compare_candidate(result, baseline):
    if result["status"] in {"claim_blocked", "skipped"}:
        return result["failure_signature"]
    if baseline is None or baseline.get("status") != "pass":
        return "baseline_unavailable"
    if result["exit"] != baseline["exit"]:
        return "exit_mismatch"
    if digest_bytes(result["stdout"]) != digest_bytes(baseline["stdout"]):
        return "stdout_digest_mismatch"
    return result["failure_signature"]


def write_trace_artifacts(workload_id, runtime_mode, env, result, row):
    row_dir = run_dir / safe_name(workload_id) / runtime_mode
    row_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = row_dir / "stdout.txt"
    stderr_path = row_dir / "stderr.txt"
    env_path = row_dir / "env.json"
    trace_path = row_dir / "trace.json"
    stdout_path.write_bytes(result.get("stdout", b""))
    stderr_path.write_bytes(result.get("stderr", b""))
    write_json(env_path, trace_env(env))
    write_json(trace_path, row)
    return [rel(stdout_path), rel(stderr_path), rel(env_path), rel(trace_path)]


def existing_workload_artifact_refs(workload):
    refs = []
    for artifact_ref in workload.get("artifact_refs", []):
        if not isinstance(artifact_ref, str) or not artifact_ref:
            continue
        path = root / artifact_ref
        if artifact_ref.startswith("target/") and not path.exists():
            continue
        refs.append(artifact_ref)
    return refs


def append_trace(workload, runtime_mode, env, result, baseline, preload_artifact):
    workload_id = workload.get("workload_id")
    failure_signature = result["failure_signature"]
    if runtime_mode in {"strict", "hardened"}:
        failure_signature = compare_candidate(result, baseline)
    expected_digest = expected_stdout_digest(workload, baseline)
    row = {
        "trace_id": f"{BEAD_ID}::{run_dir.name}::{workload_id}::{runtime_mode}",
        "bead_id": BEAD_ID,
        "workload_id": workload_id,
        "mode": runtime_mode,
        "command": command_display(workload),
        "env": trace_env(env),
        "baseline_exit": None if baseline is None else baseline.get("exit"),
        "preload_exit": None if runtime_mode == "baseline" else result.get("exit"),
        "expected_stdout_digest": expected_digest,
        "actual_stdout_digest": digest_bytes(result.get("stdout", b"")),
        "stderr_signature": stderr_signature(result.get("stderr", b"")),
        "latency_ns": result.get("latency_ns", 0),
        "failure_signature": failure_signature,
        "source_commit": SOURCE_COMMIT,
        "target_dir": str(run_dir),
        "artifact_refs": existing_workload_artifact_refs(workload),
        "status": result.get("status"),
        "category": workload.get("category"),
        "preload_artifact_status": preload_artifact.get("status"),
    }
    row["artifact_refs"].extend(write_trace_artifacts(workload_id, runtime_mode, env, result, row))
    missing = [field for field in REQUIRED_TRACE_FIELDS if field not in row]
    if missing:
        errors.append(f"{workload_id}.{runtime_mode}: trace row missing {missing}")
    trace_rows.append(row)


manifest = read_json(manifest_path)
workloads = manifest.get("workloads", []) if isinstance(manifest, dict) else []
preload_artifact = classify_preload_artifact()

if manifest.get("schema_version") != "v1" or manifest.get("bead") != SOURCE_BEAD_ID:
    errors.append("manifest must declare schema_version=v1 and bead=bd-b92jd.3.1")
if manifest.get("freshness_policy", {}).get("source_commit") not in {"current", SOURCE_COMMIT}:
    errors.append("manifest freshness_policy.source_commit is stale")
if manifest.get("runtime_mode_policy", {}).get("required_modes") != REQUIRED_MODES:
    errors.append("manifest must require baseline, strict, hardened modes")
if not isinstance(workloads, list) or not workloads:
    errors.append("manifest workloads must be non-empty")

run_dir.mkdir(parents=True, exist_ok=True)

if mode == "--validate-only":
    workloads = []

for workload in workloads:
    workload_id = workload.get("workload_id", "<missing>")
    skip_reason = optional_skip_reason(workload)
    if skip_reason:
        for runtime_mode in REQUIRED_MODES:
            env = resolve_env_overlay(
                workload.get("mode_expectations", {}).get(runtime_mode, {}).get("env_overlay", {}),
                preload_artifact.get("path"),
            )
            result = {
                "status": "skipped",
                "exit": None,
                "stdout": b"",
                "stderr": skip_reason.encode(),
                "latency_ns": 0,
                "failure_signature": skip_reason,
            }
            append_trace(workload, runtime_mode, env, result, None, preload_artifact)
        continue

    baseline_env = resolve_env_overlay(
        workload.get("mode_expectations", {}).get("baseline", {}).get("env_overlay", {}),
        preload_artifact.get("path"),
    )
    baseline = run_workload(workload, "baseline", baseline_env, preload_artifact)
    baseline_results[workload_id] = baseline
    append_trace(workload, "baseline", baseline_env, baseline, baseline, preload_artifact)

    for runtime_mode in ["strict", "hardened"]:
        env = resolve_env_overlay(
            workload.get("mode_expectations", {}).get(runtime_mode, {}).get("env_overlay", {}),
            preload_artifact.get("path"),
        )
        result = run_workload(workload, runtime_mode, env, preload_artifact)
        append_trace(workload, runtime_mode, env, result, baseline, preload_artifact)

log_path.parent.mkdir(parents=True, exist_ok=True)
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in trace_rows), encoding="utf-8")

mode_counts = Counter(row["mode"] for row in trace_rows)
status_counts = Counter(row["status"] for row in trace_rows)
failure_counts = Counter(row["failure_signature"] for row in trace_rows)
baseline_failures = [
    row for row in trace_rows if row["mode"] == "baseline" and row["status"] not in {"pass", "skipped"}
]
unexpected_candidate_failures = [
    row
    for row in trace_rows
    if row["mode"] in {"strict", "hardened"}
    and row["status"] == "fail"
    and row["failure_signature"] not in {"interpose_artifact_missing", "interpose_artifact_stale"}
]
report = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "source_bead": SOURCE_BEAD_ID,
    "status": "pass" if not errors and not baseline_failures and not unexpected_candidate_failures else "fail",
    "errors": errors,
    "source_commit": SOURCE_COMMIT,
    "manifest": rel(manifest_path),
    "run_id": run_dir.name,
    "target_dir": str(run_dir),
    "log_path": rel(log_path),
    "trace_row_count": len(trace_rows),
    "workload_count": len(workloads),
    "mode_counts": dict(sorted(mode_counts.items())),
    "status_counts": dict(sorted(status_counts.items())),
    "failure_counts": dict(sorted(failure_counts.items())),
    "baseline_failure_count": len(baseline_failures),
    "unexpected_candidate_failure_count": len(unexpected_candidate_failures),
    "preload_artifact": preload_artifact,
    "required_trace_fields": REQUIRED_TRACE_FIELDS,
    "artifact_refs": [
        "tests/conformance/user_workload_replay_manifest.v1.json",
        "scripts/run_user_workload_replay_traces.sh",
        rel(report_path),
        rel(log_path),
        rel(run_dir),
    ],
}

write_json(report_path, report)
print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if report["status"] == "pass" else 1)
PY
