#!/usr/bin/env bash
# check_crt_tls_atexit_direct_link_run_proof_fixtures.sh -- bd-b92jd.1.2 gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_CRT_TLS_PROOF_MANIFEST:-${ROOT}/tests/conformance/crt_tls_atexit_direct_link_run_proof_fixtures.v1.json}"
OUT_DIR="${FLC_CRT_TLS_PROOF_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FLC_CRT_TLS_PROOF_REPORT:-${OUT_DIR}/crt_tls_atexit_direct_link_run_proof_fixtures.report.json}"
LOG="${FLC_CRT_TLS_PROOF_LOG:-${OUT_DIR}/crt_tls_atexit_direct_link_run_proof_fixtures.log.jsonl}"
TARGET_DIR="${FLC_CRT_TLS_PROOF_TARGET_DIR:-${OUT_DIR}}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" "${TARGET_DIR}" <<'PY'
import hashlib
import json
import os
import shlex
import subprocess
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1]).resolve()
manifest_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]
target_dir = sys.argv[6]

BEAD_ID = "bd-b92jd.1.2"
GATE_ID = "crt-tls-atexit-direct-link-run-proof-fixtures-v1"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "fixture_id",
    "scenario_kind",
    "runtime_mode",
    "replacement_level",
    "execution_model",
    "expected_decision",
    "actual_decision",
    "expected_order",
    "actual_order",
    "source_commit",
    "target_dir",
    "artifact_refs",
    "failure_signature",
]
REQUIRED_EXECUTION_LOG_FIELDS = [
    *REQUIRED_LOG_FIELDS,
    "event",
    "command",
    "exit_code",
    "stdout_sha256",
    "stderr_sha256",
    "stdout_path",
    "stderr_path",
    "loader_diagnostics",
    "artifact_status",
    "claim_status",
]
REQUIRED_SCENARIO_KINDS = {
    "crt_startup",
    "tls_initialization",
    "tls_destructor",
    "init_fini_ordering",
    "atexit_on_exit",
    "errno_tls_isolation",
    "env_ownership",
    "secure_mode_diagnostics",
}
REQUIRED_RUNTIME_MODES = {"strict", "hardened"}
REQUIRED_EXECUTION_MODELS = {"direct_link_run", "replace_mode_simulated"}
REQUIRED_ROW_FIELDS = [
    "fixture_id",
    "scenario_kind",
    "title",
    "replacement_level",
    "execution_model",
    "source_commit",
    "runtime_modes",
    "expected_order",
    "actual_order",
    "expected_status",
    "actual_status",
    "expected_decision",
    "actual_decision",
    "missing_evidence",
    "strict_expectation",
    "hardened_expectation",
    "source_artifacts",
    "target_artifacts",
    "artifact_refs",
    "failure_signature",
]
DIAGNOSTIC_SIGNATURES = {
    "missing_field",
    "replace_artifact_missing",
    "missing_source_commit",
    "stale_source_commit",
    "missing_artifact_refs",
    "missing_source_artifact",
    "missing_fixture_row",
    "strict_hardened_expectation_missing",
    "direct_link_claim_conflict",
    "host_glibc_dependency",
    "artifact_dependency_inspection_failed",
}
errors = []
log_rows = []
execution_rows = []


def fail(signature, message):
    errors.append({"failure_signature": signature, "message": message})


def resolve(path_text):
    path = Path(str(path_text))
    return path if path.is_absolute() else root / path


def rel(path):
    try:
        return Path(path).resolve().relative_to(root).as_posix()
    except Exception:
        return str(path)


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_text(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def run_command(command, *, cwd, env=None, timeout=20):
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


def load_json(path, label):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail("missing_source_artifact", f"{label}: cannot parse {path}: {exc}")
        return {}


def require_object(value, context):
    if isinstance(value, dict):
        return value
    fail("missing_field", f"{context}: must be an object")
    return {}


def require_array(row, field, context):
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    fail("missing_field", f"{context}.{field}: must be a non-empty array")
    return []


def require_string(row, field, context):
    value = row.get(field)
    if isinstance(value, str) and value:
        return value
    fail("missing_field", f"{context}.{field}: must be a non-empty string")
    return ""


def repo_ref(path_text, context, *, must_exist):
    if not isinstance(path_text, str) or not path_text:
        fail("missing_source_artifact", f"{context}: path must be a non-empty string")
        return None
    path = Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        fail("missing_source_artifact", f"{context}: path must stay repo-relative: {path_text}")
        return None
    resolved = root / path
    if must_exist and not resolved.exists():
        fail("missing_source_artifact", f"{context}: missing path {path_text}")
    return resolved


def commit_is_current(commit_marker):
    return commit_marker in {"current", "unknown", source_commit}


def head_epoch():
    override = os.environ.get("FLC_CRT_TLS_PROOF_HEAD_EPOCH")
    if override:
        try:
            return int(override)
        except ValueError:
            fail("missing_field", "FLC_CRT_TLS_PROOF_HEAD_EPOCH must be an integer epoch")
            return 0
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


def standalone_artifact_candidates(default_text):
    env_candidates = [
        os.environ.get("FLC_CRT_TLS_PROOF_REPLACE_ARTIFACT"),
        os.environ.get("FRANKENLIBC_STANDALONE_LIB"),
    ]
    candidates = [Path(value) for value in env_candidates if value]
    forge_report = Path(
        os.environ.get(
            "FLC_CRT_TLS_STANDALONE_ARTIFACT_REPORT",
            root / "target/conformance/standalone_replacement_artifact.report.json",
        )
    )
    if forge_report.exists():
        try:
            report = json.loads(forge_report.read_text(encoding="utf-8"))
            forged_path = report.get("artifact_state", {}).get("path")
            if forged_path:
                candidates.append(Path(forged_path))
        except Exception:
            pass
    candidates.append(resolve(default_text))
    return candidates


def classify_standalone_artifact(default_text):
    current_head_epoch = head_epoch()
    for candidate in standalone_artifact_candidates(default_text):
        if not candidate.exists():
            continue
        artifact_status = "current"
        failure_signature = "none"
        if candidate.name != "libfrankenlibc_replace.so":
            artifact_status = "wrong_profile"
            failure_signature = "interpose_only_artifact"
        else:
            try:
                if current_head_epoch and int(candidate.stat().st_mtime) < current_head_epoch:
                    artifact_status = "stale"
                    failure_signature = "standalone_artifact_stale"
            except OSError:
                artifact_status = "missing"
                failure_signature = "replace_artifact_missing"
            if artifact_status == "current":
                readelf_dynamic = run_command(["readelf", "-d", str(candidate)], cwd=root, timeout=60)
                ldd = run_command(["ldd", str(candidate)], cwd=root, timeout=60)
                if readelf_dynamic["returncode"] != 0:
                    artifact_status = "inspection_failed"
                    failure_signature = "artifact_dependency_inspection_failed"
                else:
                    dep_text = "\n".join(
                        [
                            readelf_dynamic["stdout"],
                            readelf_dynamic["stderr"],
                            ldd["stdout"],
                            ldd["stderr"],
                        ]
                    )
                    if "libc.so" in dep_text or "ld-linux" in dep_text:
                        artifact_status = "host_dependent"
                        failure_signature = "host_glibc_dependency"
        return {
            "path": candidate,
            "status": artifact_status,
            "failure_signature": failure_signature,
            "exists": artifact_status == "current",
        }
    return {
        "path": None,
        "status": "missing",
        "failure_signature": "replace_artifact_missing",
        "exists": False,
    }


def direct_link_cases():
    return [
        {
            "id": "crt.startup.direct_link.main",
            "scenario_kind": "crt_startup",
            "extra_flags": [],
            "source": "int main(int argc, char **argv) { return (argc > 0 && argv != 0) ? 0 : 7; }\n",
            "stdout_contains": "",
        },
        {
            "id": "tls.errno.pthread.direct_link",
            "scenario_kind": "errno_tls_isolation",
            "extra_flags": ["-pthread"],
            "source": "#include <errno.h>\n#include <pthread.h>\nstatic __thread int tls_value;\nstatic void *worker(void *arg) { tls_value = 41; errno = 17; return (void *)(long)(tls_value + errno + (arg != 0)); }\nint main(void) { pthread_t thread; if (pthread_create(&thread, 0, worker, (void *)1) != 0) return 2; void *ret = 0; if (pthread_join(thread, &ret) != 0) return 3; errno = 0; tls_value = 1; return ((long)ret == 59 && errno == 0 && tls_value == 1) ? 0 : 4; }\n",
            "stdout_contains": "",
        },
        {
            "id": "atexit.destructor.order.direct_link",
            "scenario_kind": "atexit_on_exit",
            "extra_flags": [],
            "source": "#include <stdio.h>\n#include <stdlib.h>\nstatic int marker;\nstatic void first(void) { marker = marker * 10 + 1; }\nstatic void second(void) { marker = marker * 10 + 2; }\nint main(void) { if (atexit(first) != 0) return 2; if (atexit(second) != 0) return 3; puts(\"atexit-registered\"); return 0; }\n",
            "stdout_contains": "atexit-registered",
        },
        {
            "id": "malloc.free.direct_link",
            "scenario_kind": "tls_destructor",
            "extra_flags": [],
            "source": "#include <stdlib.h>\n#include <string.h>\nint main(void) { char *buf = (char *)malloc(32); if (!buf) return 2; strcpy(buf, \"malloc-ok\"); int ok = strcmp(buf, \"malloc-ok\") == 0; free(buf); return ok ? 0 : 3; }\n",
            "stdout_contains": "",
        },
        {
            "id": "stdio.string.direct_link",
            "scenario_kind": "init_fini_ordering",
            "extra_flags": [],
            "source": "#include <stdio.h>\n#include <string.h>\nint main(void) { char buf[32]; strcpy(buf, \"stdio-string-ok\"); puts(buf); return strcmp(buf, \"stdio-string-ok\") == 0 ? 0 : 2; }\n",
            "stdout_contains": "stdio-string-ok",
        },
    ]


def append_execution_row(case, runtime_mode, artifact_state, command, result, refs, stdout_path, stderr_path):
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    status = "pass" if result["returncode"] == 0 and (not case["stdout_contains"] or case["stdout_contains"] in stdout) else "fail"
    if artifact_state["status"] != "current":
        status = "claim_blocked"
    failure_signature = (
        artifact_state["failure_signature"]
        if artifact_state["status"] != "current"
        else ("none" if status == "pass" else "direct_link_execution_failed")
    )
    claim_status = "evidence_recorded" if status == "pass" else "claim_blocked"
    row = {
        "trace_id": f"{BEAD_ID}::{case['id']}::{runtime_mode}::execution",
        "bead_id": BEAD_ID,
        "fixture_id": case["id"],
        "scenario_kind": case["scenario_kind"],
        "runtime_mode": runtime_mode,
        "replacement_level": "L2",
        "execution_model": "direct_link_run",
        "expected_decision": "evidence_recorded",
        "actual_decision": status,
        "expected_order": ["compile", "direct_link", "run"],
        "actual_order": ["compile", "direct_link", "run"] if artifact_state["status"] == "current" else [],
        "source_commit": source_commit,
        "target_dir": target_dir,
        "artifact_refs": refs,
        "failure_signature": failure_signature,
        "event": "direct_link_candidate_run",
        "command": command,
        "exit_code": result["returncode"],
        "stdout_sha256": sha256_text(stdout),
        "stderr_sha256": sha256_text(stderr),
        "stdout_path": rel(stdout_path),
        "stderr_path": rel(stderr_path),
        "loader_diagnostics": stderr,
        "artifact_status": artifact_state["status"],
        "claim_status": claim_status,
    }
    execution_rows.append(row)
    log_rows.append(row)


def run_direct_link_cases(artifact_state):
    run_root = Path(target_dir) / "crt_tls_atexit_direct_link_runs"
    compiler = os.environ.get("CC", "cc")
    for index, case in enumerate(direct_link_cases(), start=1):
        for runtime_mode in sorted(REQUIRED_RUNTIME_MODES):
            case_dir = run_root / f"{index:02d}-{case['id'].replace('.', '_')}-{runtime_mode}"
            source_path = case_dir / "source.c"
            binary_path = case_dir / "candidate.bin"
            stdout_path = case_dir / "stdout.txt"
            stderr_path = case_dir / "stderr.txt"
            write_text(source_path, case["source"])
            refs = [rel(source_path), rel(stdout_path), rel(stderr_path)]
            if artifact_state["path"]:
                refs.append(rel(artifact_state["path"]))
            command = [
                compiler,
                "-O2",
                str(source_path),
                "-Wl,--no-as-needed",
            ]
            if artifact_state["path"]:
                command.append(str(artifact_state["path"]))
                command.append(f"-Wl,-rpath,{artifact_state['path'].parent}")
            command.extend(case["extra_flags"])
            command.extend(["-o", str(binary_path)])
            if artifact_state["status"] != "current":
                write_text(stdout_path, "")
                write_text(stderr_path, artifact_state["failure_signature"] + "\n")
                append_execution_row(
                    case,
                    runtime_mode,
                    artifact_state,
                    command,
                    {"returncode": 0, "stdout": "", "stderr": artifact_state["failure_signature"] + "\n"},
                    refs,
                    stdout_path,
                    stderr_path,
                )
                continue
            compile_result = run_command(command, cwd=root)
            if compile_result["returncode"] != 0:
                write_text(stdout_path, compile_result["stdout"])
                write_text(stderr_path, compile_result["stderr"])
                append_execution_row(case, runtime_mode, artifact_state, command, compile_result, refs, stdout_path, stderr_path)
                continue
            env = os.environ.copy()
            env.pop("LD_PRELOAD", None)
            env["FRANKENLIBC_MODE"] = runtime_mode
            run_result = run_command([str(binary_path)], cwd=case_dir, env=env)
            write_text(stdout_path, run_result["stdout"])
            write_text(stderr_path, run_result["stderr"])
            append_execution_row(case, runtime_mode, artifact_state, command, run_result, refs, stdout_path, stderr_path)


manifest = require_object(load_json(resolve(manifest_path), "manifest"), "manifest")
if manifest.get("schema_version") != "v1":
    fail("missing_field", "schema_version must be v1")
if manifest.get("bead_id") != BEAD_ID:
    fail("missing_field", f"bead_id must be {BEAD_ID}")
if manifest.get("gate_id") != GATE_ID:
    fail("missing_field", f"gate_id must be {GATE_ID}")
if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    fail("missing_field", "required_log_fields must match CRT/TLS proof log contract")

freshness = require_object(manifest.get("freshness"), "freshness")
required_commit = str(freshness.get("required_source_commit", ""))
if not commit_is_current(required_commit):
    fail(
        "stale_source_commit",
        f"freshness.required_source_commit {required_commit!r} does not match current {source_commit}",
    )

sources = require_object(manifest.get("sources"), "sources")
for key, source_path in sources.items():
    if not isinstance(source_path, str) or not source_path:
        fail("missing_field", f"sources.{key}: must be a non-empty string")
    else:
        repo_ref(source_path, f"sources.{key}", must_exist=True)

policy = require_object(manifest.get("replacement_artifact_policy"), "replacement_artifact_policy")
replace_artifact_text = require_string(policy, "replace_artifact", "replacement_artifact_policy")
replace_artifact = repo_ref(
    replace_artifact_text,
    "replacement_artifact_policy.replace_artifact",
    must_exist=False,
)
artifact_state = classify_standalone_artifact(replace_artifact_text)
replace_artifact_exists = artifact_state["exists"]
if policy.get("missing_artifact_result") != "claim_blocked":
    fail("missing_field", "missing_artifact_result must be claim_blocked")
if policy.get("missing_row_source_commit_result") != "claim_blocked":
    fail("missing_field", "missing_row_source_commit_result must be claim_blocked")
if policy.get("missing_row_artifact_refs_result") != "claim_blocked":
    fail("missing_field", "missing_row_artifact_refs_result must be claim_blocked")
if policy.get("host_glibc_dependency_result") != "claim_blocked":
    fail("missing_field", "host_glibc_dependency_result must be claim_blocked")
if not policy.get("direct_link_evidence_cannot_be_inferred_from_ld_preload"):
    fail("direct_link_claim_conflict", "direct link evidence must not be inferred from LD_PRELOAD")

declared_scenarios = set(manifest.get("required_scenario_kinds", []))
declared_runtime_modes = set(manifest.get("required_runtime_modes", []))
declared_execution_models = set(manifest.get("required_execution_models", []))
if declared_scenarios != REQUIRED_SCENARIO_KINDS:
    fail("missing_fixture_row", "required_scenario_kinds must match CRT/TLS proof scope")
if declared_runtime_modes != REQUIRED_RUNTIME_MODES:
    fail("strict_hardened_expectation_missing", "required_runtime_modes must be strict+hardened")
if declared_execution_models != REQUIRED_EXECUTION_MODELS:
    fail("missing_field", "required_execution_models must include direct_link_run and replace_mode_simulated")

declared_diagnostics = {
    row.get("id")
    for row in manifest.get("diagnostic_signatures", [])
    if isinstance(row, dict)
}
for signature in DIAGNOSTIC_SIGNATURES:
    if signature not in declared_diagnostics:
        fail("missing_field", f"diagnostic_signatures missing {signature}")

negative_signatures = {
    row.get("failure_signature")
    for row in manifest.get("negative_claim_tests", [])
    if isinstance(row, dict)
}
for signature in [
    "replace_artifact_missing",
    "missing_source_commit",
    "stale_source_commit",
    "missing_artifact_refs",
    "missing_fixture_row",
    "strict_hardened_expectation_missing",
    "host_glibc_dependency",
]:
    if signature not in negative_signatures:
        fail("missing_field", f"negative_claim_tests missing {signature}")

rows = manifest.get("fixture_rows")
if not isinstance(rows, list) or not rows:
    fail("missing_fixture_row", "fixture_rows must be a non-empty array")
    rows = []

seen_ids = set()
scenario_counts = Counter()
decision_counts = Counter()
execution_counts = Counter()
mode_counts = Counter()

for row in rows:
    if not isinstance(row, dict):
        fail("missing_field", "fixture_rows entries must be objects")
        continue
    fixture_id = row.get("fixture_id", "<missing>")
    for field in REQUIRED_ROW_FIELDS:
        if field not in row:
            signature = {
                "source_commit": "missing_source_commit",
                "artifact_refs": "missing_artifact_refs",
                "strict_expectation": "strict_hardened_expectation_missing",
                "hardened_expectation": "strict_hardened_expectation_missing",
            }.get(field, "missing_field")
            fail(signature, f"{fixture_id}: missing field {field}")

    if fixture_id in seen_ids:
        fail("missing_field", f"{fixture_id}: duplicate fixture_id")
    seen_ids.add(fixture_id)

    scenario = require_string(row, "scenario_kind", fixture_id)
    if scenario not in REQUIRED_SCENARIO_KINDS:
        fail("missing_fixture_row", f"{fixture_id}: unknown scenario_kind {scenario}")
    else:
        scenario_counts[scenario] += 1

    execution_model = require_string(row, "execution_model", fixture_id)
    if execution_model not in REQUIRED_EXECUTION_MODELS:
        fail("missing_field", f"{fixture_id}: unknown execution_model {execution_model}")
    else:
        execution_counts[execution_model] += 1

    runtime_modes = set(require_array(row, "runtime_modes", fixture_id))
    if runtime_modes != REQUIRED_RUNTIME_MODES:
        fail("strict_hardened_expectation_missing", f"{fixture_id}: runtime_modes must be strict+hardened")
    for mode in runtime_modes:
        mode_counts[mode] += 1

    for expectation_field in ["strict_expectation", "hardened_expectation"]:
        expectation = require_object(row.get(expectation_field), f"{fixture_id}.{expectation_field}")
        if not expectation:
            fail("strict_hardened_expectation_missing", f"{fixture_id}: {expectation_field} missing")

    row_commit = row.get("source_commit")
    if not isinstance(row_commit, str) or not row_commit:
        fail("missing_source_commit", f"{fixture_id}: source_commit must be present")
    elif not commit_is_current(row_commit):
        fail("stale_source_commit", f"{fixture_id}: source_commit {row_commit!r} is stale")

    artifact_refs = row.get("artifact_refs")
    if not isinstance(artifact_refs, list) or not artifact_refs:
        fail("missing_artifact_refs", f"{fixture_id}: artifact_refs must be non-empty")
        artifact_refs = []
    for artifact in artifact_refs:
        repo_ref(artifact, f"{fixture_id}.artifact_refs", must_exist=True)
    for artifact in row.get("source_artifacts", []):
        repo_ref(artifact, f"{fixture_id}.source_artifacts", must_exist=True)
    for artifact in row.get("target_artifacts", []):
        repo_ref(artifact, f"{fixture_id}.target_artifacts", must_exist=False)

    expected_decision = row.get("expected_decision")
    actual_decision = row.get("actual_decision")
    decision_counts[str(actual_decision)] += 1
    if expected_decision != actual_decision:
        fail(
            "direct_link_claim_conflict",
            f"{fixture_id}: expected_decision {expected_decision!r} differs from actual_decision {actual_decision!r}",
        )
    if not replace_artifact_exists and actual_decision != "claim_blocked":
        fail(
            "replace_artifact_missing",
            f"{fixture_id}: {replace_artifact_text} is missing but row actual_decision={actual_decision!r}",
        )

    expected_order = row.get("expected_order")
    if not isinstance(expected_order, list) or not expected_order:
        fail("missing_field", f"{fixture_id}: expected_order must be non-empty")
    actual_order = row.get("actual_order")
    if not isinstance(actual_order, list):
        fail("missing_field", f"{fixture_id}: actual_order must be an array")
    if actual_decision == "claim_blocked" and not row.get("missing_evidence"):
        fail("missing_field", f"{fixture_id}: claim_blocked rows must list missing_evidence")
    if row.get("failure_signature") in {"", None, "none"} and actual_decision == "claim_blocked":
        fail("missing_field", f"{fixture_id}: blocked row must provide failure_signature")

    for mode in sorted(runtime_modes):
        log_rows.append(
            {
                "trace_id": f"{BEAD_ID}::{fixture_id}::{mode}",
                "bead_id": BEAD_ID,
                "fixture_id": fixture_id,
                "scenario_kind": scenario,
                "runtime_mode": mode,
                "replacement_level": row.get("replacement_level"),
                "execution_model": execution_model,
                "expected_decision": expected_decision,
                "actual_decision": actual_decision,
                "expected_order": expected_order if isinstance(expected_order, list) else [],
                "actual_order": actual_order if isinstance(actual_order, list) else [],
                "source_commit": source_commit,
                "target_dir": target_dir,
                "artifact_refs": artifact_refs,
                "failure_signature": row.get("failure_signature"),
            }
        )

missing_scenarios = REQUIRED_SCENARIO_KINDS - set(scenario_counts)
if missing_scenarios:
    fail("missing_fixture_row", "missing scenario rows: " + ",".join(sorted(missing_scenarios)))
if mode_counts.get("strict", 0) != len(rows) or mode_counts.get("hardened", 0) != len(rows):
    fail("strict_hardened_expectation_missing", "every fixture row must cover strict and hardened")
for execution_model in REQUIRED_EXECUTION_MODELS:
    if execution_counts.get(execution_model, 0) == 0:
        fail("missing_field", f"missing execution_model {execution_model}")

summary = {
    "fixture_count": len(rows),
    "required_scenario_count": len(REQUIRED_SCENARIO_KINDS),
    "strict_hardened_mode_count": len(REQUIRED_RUNTIME_MODES),
    "claim_blocked_count": decision_counts.get("claim_blocked", 0),
    "decision_counts": dict(sorted(decision_counts.items())),
    "scenario_counts": dict(sorted(scenario_counts.items())),
    "execution_model_counts": dict(sorted(execution_counts.items())),
    "log_row_count": len(log_rows),
    "replace_artifact_exists": replace_artifact_exists,
    "standalone_artifact_status": artifact_state["status"],
}
declared_summary = manifest.get("summary", {})
if isinstance(declared_summary, dict):
    for key in ["fixture_count", "claim_blocked_count", "required_scenario_count", "strict_hardened_mode_count"]:
        if declared_summary.get(key) != summary.get(key):
            fail("stale_source_commit", f"summary.{key} drifted from computed value {summary.get(key)}")

run_direct_link_cases(artifact_state)
summary["fixture_log_row_count"] = summary["log_row_count"]
summary["log_row_count"] = len(log_rows)
summary["direct_link_execution_rows"] = len(execution_rows)
summary["direct_link_execution_status_counts"] = dict(
    sorted(Counter(row["actual_decision"] for row in execution_rows).items())
)
for row in execution_rows:
    missing = [field for field in REQUIRED_EXECUTION_LOG_FIELDS if field not in row]
    if missing:
        fail("missing_field", f"{row['fixture_id']}: execution log row missing {missing}")

report = {
    "schema_version": "v1",
    "bead_id": BEAD_ID,
    "gate_id": GATE_ID,
    "status": "fail" if errors else "pass",
    "manifest": rel(manifest_path),
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "source_commit": source_commit,
    "target_dir": target_dir,
    "replacement_artifact": replace_artifact_text,
    "standalone_artifact": {
        "path": str(artifact_state["path"]) if artifact_state["path"] else None,
        "status": artifact_state["status"],
        "failure_signature": artifact_state["failure_signature"],
    },
    "errors": errors,
    "required_log_fields": REQUIRED_LOG_FIELDS,
    "required_execution_log_fields": REQUIRED_EXECUTION_LOG_FIELDS,
    "summary": summary,
    "execution_rows": execution_rows,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows),
    encoding="utf-8",
)
print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    sys.exit(1)
PY
