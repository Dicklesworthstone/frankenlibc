#!/usr/bin/env bash
# bd-gq1kz7.14: WS8 soak artifact freshness preflight.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${WS8_SOAK_FRESHNESS_ARTIFACT:-${FRANKENLIBC_STANDALONE_LIB:-${ROOT}/target/standalone_replacement_artifact/cargo-target/release/libfrankenlibc_replace.so}}"
REPORT="${WS8_SOAK_FRESHNESS_REPORT:-${ROOT}/target/conformance/standalone_replacement_artifact.report.json}"
EXPECTED_PROFILE="${WS8_SOAK_FRESHNESS_EXPECTED_PROFILE:-release}"
EXPECTED_FEATURES="${WS8_SOAK_FRESHNESS_EXPECTED_FEATURES:-standalone,owned-unwind-stub,owned-tls-cache}"
SOURCE_EPOCH="${WS8_SOAK_FRESHNESS_SOURCE_EPOCH:-}"

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${EXPECTED_PROFILE}" "${EXPECTED_FEATURES}" "${SOURCE_EPOCH}" <<'PY'
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
artifact = Path(sys.argv[2])
report_path = Path(sys.argv[3])
expected_profile = sys.argv[4]
expected_features = [item for item in sys.argv[5].split(",") if item]
source_epoch_override = sys.argv[6]


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git(args: list[str], default: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    value = proc.stdout.strip()
    return value if proc.returncode == 0 and value else default


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def same_path(left: str | None, right: Path) -> bool:
    if not left:
        return False
    try:
        return Path(left).resolve() == right.resolve()
    except Exception:
        return str(left) == str(right)


def command_features(command: Any) -> list[str]:
    if not isinstance(command, list):
        return []
    features: list[str] = []
    for index, item in enumerate(command):
        if not isinstance(item, str):
            continue
        if item.startswith("--features="):
            features.extend(part for part in item.split("=", 1)[1].split(",") if part)
        elif item == "--features" and index + 1 < len(command) and isinstance(command[index + 1], str):
            features.extend(part for part in command[index + 1].split(",") if part)
    return sorted(set(features))


failure_signatures: list[str] = []
head = git(["rev-parse", "HEAD"], "unknown")
head_epoch_source = "git"
if source_epoch_override:
    head_epoch_text = source_epoch_override
    head_epoch_source = "env"
else:
    head_epoch_text = git(["log", "-1", "--format=%ct"], "0")

try:
    head_epoch = int(head_epoch_text)
except ValueError:
    head_epoch = 0
    head_epoch_source = "invalid"
    failure_signatures.append("source_timestamp_invalid")

artifact_exists = artifact.is_file() and artifact.stat().st_size > 0 if artifact.exists() else False
artifact_hash: str | None = None
artifact_mtime: int | None = None
artifact_size = 0
artifact_staleness = 0
artifact_is_stale = False

if not artifact_exists:
    failure_signatures.append("artifact_missing")
elif artifact.name != "libfrankenlibc_replace.so":
    failure_signatures.append("wrong_artifact_profile")
else:
    stat = artifact.stat()
    artifact_mtime = int(stat.st_mtime)
    artifact_size = int(stat.st_size)
    artifact_hash = sha256(artifact)
    artifact_staleness = max(head_epoch - artifact_mtime, 0)
    artifact_is_stale = artifact_staleness > 0
    if artifact_is_stale:
        failure_signatures.append("stale_artifact")

report = load_json(report_path)
report_exists = report is not None
report_state = report.get("artifact_state", {}) if isinstance(report, dict) else {}
report_provenance = report.get("build_provenance", {}) if isinstance(report, dict) else {}
report_command = report_provenance.get("build_command") if isinstance(report_provenance, dict) else []
report_features = command_features(report_command)

report_source_commit = report.get("source_commit") if isinstance(report, dict) else None
report_artifact_path = report_state.get("path") if isinstance(report_state, dict) else None
report_artifact_sha = report_state.get("sha256") if isinstance(report_state, dict) else None
report_artifact_status = report_state.get("status") if isinstance(report_state, dict) else None
report_claim_status = report.get("claim_status") if isinstance(report, dict) else None
report_profile = report_provenance.get("cargo_profile") if isinstance(report_provenance, dict) else None

source_commit_matches = report_source_commit == head
artifact_path_matches = same_path(report_artifact_path, artifact)
artifact_sha_matches = artifact_hash is not None and report_artifact_sha == artifact_hash
artifact_status_current = report_artifact_status == "current"
cargo_profile_matches = report_profile == expected_profile
cargo_features_match = sorted(set(expected_features)) == report_features

if not report_exists:
    failure_signatures.append("artifact_provenance_missing")
else:
    if not source_commit_matches:
        failure_signatures.append("stale_source_commit")
    if not artifact_path_matches or not artifact_sha_matches or not artifact_status_current:
        failure_signatures.append("artifact_report_mismatch")
    if not cargo_profile_matches:
        failure_signatures.append("artifact_profile_mismatch")
    if not cargo_features_match:
        failure_signatures.append("artifact_features_mismatch")

failure_signatures = sorted(set(failure_signatures))
status = "pass" if not failure_signatures else "fail"
payload = {
    "schema_version": "ws8_soak_artifact_freshness.v1",
    "gate": "bd-gq1kz7.14",
    "timestamp": utc_now(),
    "status": status,
    "soak_ready": status == "pass",
    "source_commit": head,
    "head_epoch": head_epoch,
    "head_epoch_source": head_epoch_source,
    "required_artifact": {
        "name": "libfrankenlibc_replace.so",
        "cargo_profile": expected_profile,
        "cargo_features": expected_features,
    },
    "artifact": {
        "path": str(artifact),
        "exists": artifact_exists,
        "size_bytes": artifact_size,
        "mtime_epoch": artifact_mtime,
        "sha256": artifact_hash,
        "name_matches": artifact.name == "libfrankenlibc_replace.so",
        "is_stale": artifact_is_stale,
        "staleness_seconds": artifact_staleness,
    },
    "report": {
        "path": str(report_path),
        "exists": report_exists,
        "source_commit": report_source_commit,
        "source_commit_matches": source_commit_matches,
        "artifact_path": report_artifact_path,
        "artifact_path_matches": artifact_path_matches,
        "artifact_sha256": report_artifact_sha,
        "artifact_sha256_matches": artifact_sha_matches,
        "artifact_status": report_artifact_status,
        "artifact_status_current": artifact_status_current,
        "claim_status": report_claim_status,
        "cargo_profile": report_profile,
        "cargo_profile_matches": cargo_profile_matches,
        "cargo_features": report_features,
        "cargo_features_match": cargo_features_match,
    },
    "failure_signatures": failure_signatures,
}

print(json.dumps(payload, indent=2, sort_keys=True))
raise SystemExit(0 if status == "pass" else 1)
PY
