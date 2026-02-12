#!/usr/bin/env bash
# check_runtime_math_profile_gates.sh — Build-profile gates for runtime_math (bd-1iya)
#
# Validates:
# - Manifest feature-set intent matches Cargo feature configuration.
# - Production build path is not accidentally built without runtime math.
# - Research profile can be explicitly enabled without breaking the build.
#
# Emits structured JSONL logs + a small summary report to:
# - target/conformance/runtime_math_profile_gates.log.jsonl
# - target/conformance/runtime_math_profile_gates.report.json
#
# Notes:
# - This gate is intentionally conservative: it focuses on feature/build boundaries,
#   not on pruning controllers (that is governed by manifest/governance beads).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/runtime_math_profile_gates.log.jsonl"
REPORT_PATH="${OUT_DIR}/runtime_math_profile_gates.report.json"

mkdir -p "${OUT_DIR}"

export FLC_ROOT="${ROOT}"
export FLC_LOG_PATH="${LOG_PATH}"
export FLC_REPORT_PATH="${REPORT_PATH}"

python3 - <<'PY'
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import tomllib

root = Path(os.environ["FLC_ROOT"])
log_path = Path(os.environ["FLC_LOG_PATH"])
report_path = Path(os.environ["FLC_REPORT_PATH"])

ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

MANIFEST = root / "tests/runtime_math/production_kernel_manifest.v1.json"
MEMBRANE_TOML = root / "crates/frankenlibc-membrane/Cargo.toml"
MEMBRANE_LIB = root / "crates/frankenlibc-membrane/src/lib.rs"

events: list[dict[str, Any]] = []
failures: list[str] = []


def emit(*, trace_id: str, level: str, event: str, outcome: str, details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": ts,
            "trace_id": trace_id,
            "level": level,
            "event": event,
            "outcome": outcome,
            "details": details,
        }
    )


def fail(msg: str) -> None:
    failures.append(msg)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def run(
    *,
    trace_id: str,
    cmd: str,
    expect_success: bool,
    cwd: Path,
) -> bool:
    proc = subprocess.run(  # noqa: S602
        cmd,
        shell=True,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    ok = proc.returncode == 0
    outcome = "pass" if (ok == expect_success) else "fail"
    tail = ""
    stderr = proc.stderr.strip()
    stdout = proc.stdout.strip()
    if stderr:
        tail = stderr.splitlines()[-1]
    elif stdout:
        tail = stdout.splitlines()[-1]
    emit(
        trace_id=trace_id,
        level="info" if outcome == "pass" else "error",
        event="runtime_math.profile_gate",
        outcome=outcome,
        details={
            "cmd": cmd,
            "expect_success": expect_success,
            "exit_code": proc.returncode,
            "tail": tail,
        },
    )
    if outcome != "pass":
        fail(f"{trace_id}: expected_success={expect_success} got_exit={proc.returncode}")
    return outcome == "pass"


print("=== Runtime Math Profile Gates (bd-1iya) ===")

if not MANIFEST.exists():
    fail(f"manifest missing: {MANIFEST}")
if not MEMBRANE_TOML.exists():
    fail(f"membrane Cargo.toml missing: {MEMBRANE_TOML}")
if not MEMBRANE_LIB.exists():
    fail(f"membrane lib.rs missing: {MEMBRANE_LIB}")

if failures:
    # Still write report/logs for determinism.
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("", encoding="utf-8")
    report_path.write_text(json.dumps({"ok": False, "failures": failures}, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(1)

manifest = load_json(MANIFEST)

with MEMBRANE_TOML.open("rb") as f:
    cargo = tomllib.load(f)
features = cargo.get("features", {})
default_features = features.get("default", [])

expected_default_feature_set = manifest.get("default_feature_set", [])
expected_optional_feature_set = manifest.get("optional_feature_set", [])

if default_features != expected_default_feature_set:
    emit(
        trace_id="rtm-profile-default-feature-set",
        level="error",
        event="runtime_math.profile_gate_manifest_check",
        outcome="fail",
        details={
            "problem": "default feature set mismatch",
            "cargo_default": default_features,
            "manifest_default_feature_set": expected_default_feature_set,
        },
    )
    fail("default feature set mismatch (Cargo.toml vs manifest)")
else:
    emit(
        trace_id="rtm-profile-default-feature-set",
        level="info",
        event="runtime_math.profile_gate_manifest_check",
        outcome="pass",
        details={"cargo_default": default_features},
    )

if expected_optional_feature_set != ["runtime-math-research"]:
    emit(
        trace_id="rtm-profile-optional-feature-set",
        level="error",
        event="runtime_math.profile_gate_manifest_check",
        outcome="fail",
        details={"manifest_optional_feature_set": expected_optional_feature_set},
    )
    fail("manifest optional_feature_set must be ['runtime-math-research']")
else:
    emit(
        trace_id="rtm-profile-optional-feature-set",
        level="info",
        event="runtime_math.profile_gate_manifest_check",
        outcome="pass",
        details={"manifest_optional_feature_set": expected_optional_feature_set},
    )

research_deps = features.get("runtime-math-research", [])
if research_deps != ["runtime-math-production"]:
    emit(
        trace_id="rtm-profile-research-deps",
        level="error",
        event="runtime_math.profile_gate_manifest_check",
        outcome="fail",
        details={"runtime-math-research": research_deps},
    )
    fail("runtime-math-research must depend on runtime-math-production")
else:
    emit(
        trace_id="rtm-profile-research-deps",
        level="info",
        event="runtime_math.profile_gate_manifest_check",
        outcome="pass",
        details={"runtime-math-research": research_deps},
    )

lib_text = MEMBRANE_LIB.read_text(encoding="utf-8")
compile_error_snippet = "requires the `runtime-math-production` feature"
if compile_error_snippet not in lib_text:
    emit(
        trace_id="rtm-profile-compile-error",
        level="error",
        event="runtime_math.profile_gate_manifest_check",
        outcome="fail",
        details={"missing": compile_error_snippet},
    )
    fail("membrane lib.rs must compile_error! when runtime-math-production is disabled")
else:
    emit(
        trace_id="rtm-profile-compile-error",
        level="info",
        event="runtime_math.profile_gate_manifest_check",
        outcome="pass",
        details={"present": compile_error_snippet},
    )

# Build checks
run(
    trace_id="rtm-profile-build-default",
    cmd="cargo check -p frankenlibc-membrane --all-targets",
    expect_success=True,
    cwd=root,
)
run(
    trace_id="rtm-profile-build-research",
    cmd="cargo check -p frankenlibc-membrane --all-targets --features runtime-math-research",
    expect_success=True,
    cwd=root,
)
run(
    trace_id="rtm-profile-build-no-default",
    cmd="cargo check -p frankenlibc-membrane --all-targets --no-default-features",
    expect_success=False,
    cwd=root,
)

ok = not failures

log_path.parent.mkdir(parents=True, exist_ok=True)
with log_path.open("w", encoding="utf-8") as f:
    for row in events:
        f.write(json.dumps(row, sort_keys=True))
        f.write("\n")

report = {
    "ok": ok,
    "generated_at": ts,
    "bead": "bd-1iya",
    "event_count": len(events),
    "failure_count": len(failures),
    "failures": failures,
    "artifacts": {
        "log_jsonl": str(log_path.relative_to(root)),
        "report_json": str(report_path.relative_to(root)),
    },
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if not ok:
    print(f"FAIL: {len(failures)} failure(s). See {report_path}")
    raise SystemExit(1)

print("PASS: runtime_math profile gate checks passed.")
print(f"Structured logs: {log_path}")
print(f"Report: {report_path}")
PY

