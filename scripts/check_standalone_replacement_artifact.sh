#!/usr/bin/env bash
# check_standalone_replacement_artifact.sh -- forge/evidence gate for bd-srtkq
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${STANDALONE_REPLACEMENT_MANIFEST:-${ROOT}/tests/conformance/standalone_replacement_artifact.v1.json}"
PACKAGING="${ROOT}/tests/conformance/packaging_spec.json"
LEVELS="${ROOT}/tests/conformance/replacement_levels.json"
OUT_DIR="${STANDALONE_REPLACEMENT_OUT_DIR:-${ROOT}/target/standalone_replacement_artifact}"
CARGO_TARGET_DIR_VALUE="${STANDALONE_REPLACEMENT_CARGO_TARGET_DIR:-${OUT_DIR}/cargo-target}"
REPORT="${STANDALONE_REPLACEMENT_REPORT:-${ROOT}/target/conformance/standalone_replacement_artifact.report.json}"
LOG="${STANDALONE_REPLACEMENT_LOG:-${ROOT}/target/conformance/standalone_replacement_artifact.log.jsonl}"
MODE="check"

case "${1:-}" in
  "")
    MODE="check"
    ;;
  --check)
    MODE="check"
    ;;
  --forge)
    MODE="forge"
    ;;
  --validate-only)
    MODE="validate-only"
    ;;
  *)
    echo "usage: $0 [--check|--forge|--validate-only]" >&2
    exit 2
    ;;
esac

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")" "${CARGO_TARGET_DIR_VALUE}/release"

python3 - "${ROOT}" "${MANIFEST}" "${PACKAGING}" "${LEVELS}" "${OUT_DIR}" "${CARGO_TARGET_DIR_VALUE}" "${REPORT}" "${LOG}" "${MODE}" <<'PY'
import hashlib
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
packaging_path = Path(sys.argv[3])
levels_path = Path(sys.argv[4])
out_dir = Path(sys.argv[5])
cargo_target_dir = Path(sys.argv[6])
report_path = Path(sys.argv[7])
log_path = Path(sys.argv[8])
mode = sys.argv[9]

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "event",
    "mode",
    "artifact_path",
    "artifact_status",
    "claim_status",
    "source_commit",
    "artifact_sha256",
    "command",
    "exit_code",
    "failure_signature",
    "artifact_refs",
]

REQUIRED_REPORT_FIELDS = [
    "artifact_state.dependency_breakdown.needed_libraries",
    "artifact_state.dependency_breakdown.ldd_libraries",
    "artifact_state.dependency_breakdown.host_needed_libraries",
    "artifact_state.dependency_breakdown.undefined_symbols",
    "artifact_state.dependency_breakdown.undefined_unwind_symbols",
    "artifact_state.dependency_breakdown.undefined_glibc_symbols",
    "artifact_state.dependency_breakdown.undefined_tls_symbols",
    "artifact_state.dependency_breakdown.version_needs",
    "artifact_state.dependency_breakdown.host_version_requirements",
    "artifact_state.dependency_breakdown.loader_needed",
    "artifact_state.dependency_breakdown.blocking_reasons",
    "tool_evidence.*.exit_code",
    "tool_evidence.*.timed_out",
    "tool_evidence.*.timeout_secs",
    "tool_evidence.*.path",
    "artifact_state.dependency_breakdown.host_direct_needed_libraries",
    "artifact_state.dependency_breakdown.host_resolved_libraries",
    "artifact_state.sampled_symbols_present",
    "artifact_state.symbol_samples",
    "claim_status",
    "source_commit",
    "artifact_state.status",
    "artifact_state.failure_signature",
    "artifact_state.host_glibc_dependency",
    "artifact_state.path",
    "artifact_state.sha256",
    "artifact_state.mtime",
]

REQUIRED_TOOLS = ["rch", "cargo", "readelf", "nm", "ldd"]

REQUIRED_EVIDENCE_FILES = [
    "build.stdout.txt",
    "build.stderr.txt",
    "artifact.sha256",
    "artifact.readelf.dynamic.txt",
    "artifact.readelf.symbols.txt",
    "artifact.readelf.version.txt",
    "artifact.nm.dynamic.txt",
    "artifact.ldd.txt",
]

EXPECTED_HASH_EVIDENCE_POLICY = {
    "algorithm": "sha256",
    "implementation": "python3 hashlib.sha256",
    "reported_field": "artifact_state.sha256",
    "evidence_file": "artifact.sha256",
}

INSPECTION_TIMEOUT_ENV = "STANDALONE_REPLACEMENT_INSPECTION_TIMEOUT_SECS"
INSPECTION_TIMEOUT_DEFAULT_SECS = 60
INSPECTION_TIMEOUT_MIN_SECS = 1
INSPECTION_TIMEOUT_MAX_SECS = 300
INSPECTION_TIMEOUT_EXIT_CODE = 124
TOOL_EVIDENCE_REQUIRED_FIELDS = [
    "exit_code",
    "timed_out",
    "timeout_secs",
    "path",
]

errors = []
checks = {}
log_rows = []
tool_evidence = {}


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return {}


manifest = load_json(manifest_path)
packaging = load_json(packaging_path)
levels = load_json(levels_path)


def empty_symbol_samples():
    samples = manifest.get("symbol_samples", [])
    if not isinstance(samples, list):
        return {}
    return {str(symbol): False for symbol in samples}


def git_output(args, default):
    try:
        return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return default


source_commit = git_output(["rev-parse", "HEAD"], "unknown")
head_epoch_raw = git_output(["log", "-1", "--format=%ct", "HEAD"], "0")
try:
    head_epoch = int(head_epoch_raw)
except ValueError:
    head_epoch = 0


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def unique_sorted(values):
    return sorted({value for value in values if value})


def env_bounded_int(name, default, *, minimum, maximum):
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        errors.append(f"{name} must be an integer from {minimum} to {maximum}")
        return default
    if value < minimum or value > maximum:
        errors.append(f"{name} must be from {minimum} to {maximum}")
        return default
    return value


inspection_timeout = env_bounded_int(
    INSPECTION_TIMEOUT_ENV,
    INSPECTION_TIMEOUT_DEFAULT_SECS,
    minimum=INSPECTION_TIMEOUT_MIN_SECS,
    maximum=INSPECTION_TIMEOUT_MAX_SECS,
)


def empty_dependency_breakdown():
    return {
        "needed_libraries": [],
        "ldd_libraries": [],
        "host_needed_libraries": [],
        "host_direct_needed_libraries": [],
        "host_resolved_libraries": [],
        "undefined_symbols": [],
        "undefined_unwind_symbols": [],
        "undefined_glibc_symbols": [],
        "undefined_tls_symbols": [],
        "version_needs": {},
        "host_version_requirements": [],
        "loader_needed": False,
        "libc_needed": False,
        "libgcc_needed": False,
        "blocking_reasons": [],
    }


def parse_needed_libraries(readelf_dynamic_text):
    return unique_sorted(
        match.group(1)
        for match in re.finditer(r"Shared library:\s*\[([^\]]+)\]", readelf_dynamic_text)
    )


def parse_ldd_libraries(ldd_text):
    libraries = []
    for line in ldd_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("linux-vdso.so"):
            continue
        if "=>" in stripped:
            name = stripped.split("=>", 1)[0].strip()
        else:
            name = stripped.split()[0]
        if name and name not in {"statically", "not"}:
            libraries.append(name)
    return unique_sorted(libraries)


def parse_undefined_symbols(nm_text):
    symbols = []
    for line in nm_text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-2] == "U":
            symbols.append(parts[-1])
    return unique_sorted(symbols)


def parse_version_needs(readelf_version_text):
    needs = {}
    in_needs = False
    current_file = None
    for line in readelf_version_text.splitlines():
        if line.startswith("Version needs section"):
            in_needs = True
            current_file = None
            continue
        if not in_needs:
            continue
        file_match = re.search(r"\bFile:\s+(\S+)\s+Cnt:", line)
        if file_match:
            current_file = file_match.group(1)
            needs.setdefault(current_file, [])
            continue
        if current_file is None:
            continue
        name_match = re.search(r"\bName:\s+(\S+)\s+Flags:", line)
        if name_match:
            needs[current_file].append(name_match.group(1))
    return {
        provider: unique_sorted(versions)
        for provider, versions in sorted(needs.items())
    }


def symbol_base(symbol):
    return symbol.split("@", 1)[0]


def is_host_runtime_library(name):
    return (
        name.startswith("libc.so")
        or name.startswith("libgcc_s.so")
        or name.startswith("libpthread.so")
        or name.startswith("libdl.so")
        or name.startswith("libm.so")
        or name.startswith("librt.so")
        or "ld-linux" in name
    )


def build_dependency_breakdown(readelf_dynamic, readelf_version, nm_dynamic, ldd):
    breakdown = empty_dependency_breakdown()
    needed_libraries = parse_needed_libraries(readelf_dynamic["stdout"])
    ldd_libraries = parse_ldd_libraries(ldd["stdout"] + "\n" + ldd["stderr"])
    all_libraries = unique_sorted([*needed_libraries, *ldd_libraries])
    undefined_symbols = parse_undefined_symbols(nm_dynamic["stdout"])
    version_needs = parse_version_needs(readelf_version["stdout"] + "\n" + readelf_version["stderr"])
    undefined_unwind_symbols = [
        symbol
        for symbol in undefined_symbols
        if symbol_base(symbol).startswith("_Unwind_")
        or symbol_base(symbol) == "__gcc_personality_v0"
    ]
    undefined_glibc_symbols = [
        symbol
        for symbol in undefined_symbols
        if "@GLIBC_" in symbol or symbol_base(symbol).startswith("__libc_")
    ]
    undefined_tls_symbols = [
        symbol
        for symbol in undefined_symbols
        if symbol_base(symbol) == "__tls_get_addr" or "tls" in symbol_base(symbol).lower()
    ]

    loader_needed = any("ld-linux" in library for library in all_libraries)
    libc_needed = any(library.startswith("libc.so") for library in all_libraries)
    libgcc_needed = any(library.startswith("libgcc_s.so") for library in all_libraries)
    host_needed_libraries = [library for library in all_libraries if is_host_runtime_library(library)]
    host_direct_needed_libraries = [
        library for library in needed_libraries if is_host_runtime_library(library)
    ]
    host_resolved_libraries = [
        library for library in ldd_libraries if is_host_runtime_library(library)
    ]
    host_version_requirements = [
        f"{provider}:{version}"
        for provider, versions in version_needs.items()
        if is_host_runtime_library(provider)
        for version in versions
    ]
    blocking_reasons = []
    if host_needed_libraries:
        blocking_reasons.append("host_needed_libraries_present")
    if loader_needed:
        blocking_reasons.append("host_loader_dependency")
    if libc_needed:
        blocking_reasons.append("host_libc_dependency")
    if libgcc_needed:
        blocking_reasons.append("libgcc_runtime_dependency")
    if undefined_unwind_symbols:
        blocking_reasons.append("undefined_unwind_symbols")
    if undefined_glibc_symbols:
        blocking_reasons.append("undefined_glibc_symbols")
    if undefined_tls_symbols:
        blocking_reasons.append("undefined_tls_symbols")
    if host_version_requirements:
        blocking_reasons.append("host_version_requirements")

    breakdown.update(
        {
            "needed_libraries": needed_libraries,
            "ldd_libraries": ldd_libraries,
            "host_needed_libraries": host_needed_libraries,
            "host_direct_needed_libraries": host_direct_needed_libraries,
            "host_resolved_libraries": host_resolved_libraries,
            "undefined_symbols": undefined_symbols,
            "undefined_unwind_symbols": unique_sorted(undefined_unwind_symbols),
            "undefined_glibc_symbols": unique_sorted(undefined_glibc_symbols),
            "undefined_tls_symbols": unique_sorted(undefined_tls_symbols),
            "version_needs": version_needs,
            "host_version_requirements": unique_sorted(host_version_requirements),
            "loader_needed": loader_needed,
            "libc_needed": libc_needed,
            "libgcc_needed": libgcc_needed,
            "blocking_reasons": blocking_reasons,
        }
    )
    return breakdown


def write_text(path, content):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content, encoding="utf-8")


def run_command(command, *, env=None, cwd=root, timeout=900):
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
            "execution_error": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": INSPECTION_TIMEOUT_EXIT_CODE,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "timeout",
            "timed_out": True,
            "execution_error": False,
        }
    except OSError as exc:
        return {
            "returncode": 127,
            "stdout": "",
            "stderr": str(exc),
            "timed_out": False,
            "execution_error": True,
        }


def append_log(event, *, artifact_path, artifact_status, claim_status, artifact_hash, command, exit_code, failure_signature, refs):
    row = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": "info" if exit_code == 0 else "error",
        "trace_id": f"{manifest.get('bead', 'unknown')}::{source_commit}::{event}",
        "bead_id": manifest.get("bead"),
        "event": event,
        "mode": mode,
        "artifact_path": str(artifact_path) if artifact_path else None,
        "artifact_status": artifact_status,
        "claim_status": claim_status,
        "source_commit": source_commit,
        "artifact_sha256": artifact_hash,
        "command": command,
        "exit_code": exit_code,
        "failure_signature": failure_signature,
        "artifact_refs": refs,
    }
    log_rows.append(row)


def validate_manifest():
    checks["json_parse"] = "pass" if isinstance(manifest, dict) and isinstance(packaging, dict) else "fail"
    if manifest.get("schema_version") != "v1":
        errors.append("manifest schema_version must be v1")
    if manifest.get("bead") != "bd-srtkq":
        errors.append("manifest must be linked to bd-srtkq")
    if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
        errors.append("required_log_fields do not match script contract")
    if manifest.get("required_report_fields") != REQUIRED_REPORT_FIELDS:
        errors.append("required_report_fields do not match script contract")
    if manifest.get("required_evidence_files") != REQUIRED_EVIDENCE_FILES:
        errors.append("required_evidence_files do not match script contract")
    if manifest.get("required_tools") != REQUIRED_TOOLS:
        errors.append("required_tools do not match script contract")
    if manifest.get("hash_evidence_policy") != EXPECTED_HASH_EVIDENCE_POLICY:
        errors.append("hash_evidence_policy does not match script contract")
    timeout_policy = manifest.get("inspection_timeout_policy", {})
    expected_timeout_policy = {
        "env": INSPECTION_TIMEOUT_ENV,
        "default_secs": INSPECTION_TIMEOUT_DEFAULT_SECS,
        "min_secs": INSPECTION_TIMEOUT_MIN_SECS,
        "max_secs": INSPECTION_TIMEOUT_MAX_SECS,
        "timeout_exit_code": INSPECTION_TIMEOUT_EXIT_CODE,
        "reported_field": "tool_evidence.*.timeout_secs",
    }
    if timeout_policy != expected_timeout_policy:
        errors.append("inspection_timeout_policy does not match script contract")

    artifact_policy = manifest.get("artifact_policy", {})
    replace_spec = packaging.get("artifacts", {}).get("replace", {})
    if artifact_policy.get("canonical_artifact_name") != "libfrankenlibc_replace.so":
        errors.append("canonical artifact must be libfrankenlibc_replace.so")
    if artifact_policy.get("source_cdylib_name") != "libfrankenlibc_abi.so":
        errors.append("source cdylib must be libfrankenlibc_abi.so")
    if replace_spec.get("artifact_name") != artifact_policy.get("canonical_artifact_name"):
        errors.append("packaging_spec replace artifact name must match forge manifest")
    if "standalone" not in replace_spec.get("cargo_features", []):
        errors.append("packaging_spec replace profile must require standalone feature")
    if replace_spec.get("host_glibc_required") is not False:
        errors.append("packaging_spec replace profile must declare host_glibc_required=false")
    if levels.get("current_level") != "L0":
        errors.append("replacement level must remain L0 while this gate only forges evidence")

    checks["manifest_contract"] = "pass" if not errors else "fail"


def build_command():
    raw = os.environ.get("STANDALONE_REPLACEMENT_BUILD_CMD")
    if raw:
        return shlex.split(raw)
    return [
        "rch",
        "exec",
        "--",
        "cargo",
        "build",
        "-p",
        "frankenlibc-abi",
        "--release",
        "--features=standalone",
    ]


def forge_artifact():
    source_override = os.environ.get("STANDALONE_REPLACEMENT_SOURCE_LIB")
    skip_build = os.environ.get("STANDALONE_REPLACEMENT_SKIP_BUILD") == "1"
    command = build_command()
    build_stdout = out_dir / "build.stdout.txt"
    build_stderr = out_dir / "build.stderr.txt"
    if mode == "forge" and not skip_build:
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(cargo_target_dir)
        allowlist = env.get("RCH_ENV_ALLOWLIST", "")
        allowed = [item for item in allowlist.split(",") if item]
        if "CARGO_TARGET_DIR" not in allowed:
            allowed.append("CARGO_TARGET_DIR")
        env["RCH_ENV_ALLOWLIST"] = ",".join(allowed)
        result = run_command(command, env=env)
        write_text(build_stdout, result["stdout"])
        write_text(build_stderr, result["stderr"])
        append_log(
            "build",
            artifact_path=None,
            artifact_status="build_failed" if result["returncode"] != 0 else "build_completed",
            claim_status="claim_blocked" if result["returncode"] != 0 else "build_completed",
            artifact_hash=None,
            command=command,
            exit_code=result["returncode"],
            failure_signature="build_failed" if result["returncode"] != 0 else "none",
            refs=[rel(build_stdout), rel(build_stderr)],
        )
        if result["returncode"] != 0:
            errors.append("standalone replacement build command failed")
            return None
    elif mode == "forge":
        write_text(build_stdout, "build skipped by STANDALONE_REPLACEMENT_SKIP_BUILD=1\n")
        write_text(build_stderr, "")

    source = Path(source_override) if source_override else cargo_target_dir / "release" / "libfrankenlibc_abi.so"
    target = cargo_target_dir / "release" / "libfrankenlibc_replace.so"
    if mode == "forge":
        if not source.exists():
            errors.append(f"source cdylib missing: {source}")
            return target
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        os.utime(target, None)
    return target


def inspect_artifact(artifact):
    refs = []
    if artifact is None or not Path(artifact).exists():
        return {
            "status": "missing",
            "path": str(artifact) if artifact else None,
            "sha256": None,
            "mtime": None,
            "failure_signature": "standalone_artifact_missing",
            "host_glibc_dependency": None,
            "sampled_symbols_present": False,
            "dependency_breakdown": empty_dependency_breakdown(),
            "refs": refs,
        }

    artifact = Path(artifact)
    artifact_hash = sha256(artifact)
    hash_path = out_dir / "artifact.sha256"
    write_text(hash_path, f"{artifact_hash}  {artifact.name}\n")
    refs.append(rel(hash_path))

    if artifact.name != "libfrankenlibc_replace.so":
        return {
            "status": "wrong_profile",
            "path": str(artifact),
            "sha256": artifact_hash,
            "mtime": int(artifact.stat().st_mtime),
            "failure_signature": "wrong_artifact_profile",
            "host_glibc_dependency": None,
            "sampled_symbols_present": False,
            "dependency_breakdown": empty_dependency_breakdown(),
            "refs": refs,
        }

    readelf_dynamic = run_command(["readelf", "-d", str(artifact)], timeout=inspection_timeout)
    readelf_symbols = run_command(["readelf", "-Ws", str(artifact)], timeout=inspection_timeout)
    readelf_version = run_command(["readelf", "--version-info", str(artifact)], timeout=inspection_timeout)
    nm_dynamic = run_command(["nm", "-D", str(artifact)], timeout=inspection_timeout)
    ldd = run_command(["ldd", str(artifact)], timeout=inspection_timeout)
    evidence_commands = {
        "artifact.readelf.dynamic.txt": readelf_dynamic,
        "artifact.readelf.symbols.txt": readelf_symbols,
        "artifact.readelf.version.txt": readelf_version,
        "artifact.nm.dynamic.txt": nm_dynamic,
        "artifact.ldd.txt": ldd,
    }
    for filename, result in evidence_commands.items():
        path = out_dir / filename
        write_text(path, result["stdout"] + result["stderr"])
        refs.append(rel(path))
        tool_evidence[filename] = {
            "exit_code": result["returncode"],
            "timed_out": result["timed_out"],
            "timeout_secs": inspection_timeout,
            "path": rel(path),
        }

    mtime = int(artifact.stat().st_mtime)
    dependency_breakdown = build_dependency_breakdown(readelf_dynamic, readelf_version, nm_dynamic, ldd)
    readelf_dynamic_execution_failed = (
        readelf_dynamic["timed_out"] or readelf_dynamic.get("execution_error", False)
    )
    inspection_failed = any(
        result["returncode"] != 0 or result["timed_out"]
        for filename, result in evidence_commands.items()
        if filename != "artifact.readelf.dynamic.txt"
    ) or readelf_dynamic_execution_failed
    if head_epoch and mtime < head_epoch:
        return {
            "status": "stale",
            "path": str(artifact),
            "sha256": artifact_hash,
            "mtime": mtime,
            "failure_signature": "standalone_artifact_stale",
            "host_glibc_dependency": None,
            "sampled_symbols_present": False,
            "dependency_breakdown": dependency_breakdown,
            "refs": refs,
        }
    if readelf_dynamic["returncode"] != 0 and not readelf_dynamic_execution_failed:
        return {
            "status": "non_elf",
            "path": str(artifact),
            "sha256": artifact_hash,
            "mtime": mtime,
            "failure_signature": "non_elf_artifact",
            "host_glibc_dependency": None,
            "sampled_symbols_present": False,
            "dependency_breakdown": dependency_breakdown,
            "refs": refs,
        }
    if inspection_failed:
        return {
            "status": "inspection_failed",
            "path": str(artifact),
            "sha256": artifact_hash,
            "mtime": mtime,
            "failure_signature": "artifact_dependency_inspection_failed",
            "host_glibc_dependency": None,
            "sampled_symbols_present": False,
            "dependency_breakdown": dependency_breakdown,
            "refs": refs,
        }

    dep_text = readelf_dynamic["stdout"] + "\n" + ldd["stdout"] + "\n" + ldd["stderr"]
    host_glibc_dependency = (
        "libc.so" in dep_text
        or "ld-linux" in dep_text
        or bool(dependency_breakdown["blocking_reasons"])
    )
    symbol_text = readelf_symbols["stdout"] + "\n" + nm_dynamic["stdout"]
    samples = manifest.get("symbol_samples", [])
    present = {symbol: (symbol in symbol_text) for symbol in samples}
    sampled_symbols_present = all(present.values()) if samples else True
    if host_glibc_dependency:
        failure = "host_glibc_dependency"
    elif not sampled_symbols_present:
        failure = "symbol_evidence_missing"
    else:
        failure = "none"

    return {
        "status": "current",
        "path": str(artifact),
        "sha256": artifact_hash,
        "mtime": mtime,
        "failure_signature": failure,
        "host_glibc_dependency": host_glibc_dependency,
        "sampled_symbols_present": sampled_symbols_present,
        "dependency_breakdown": dependency_breakdown,
        "symbol_samples": present,
        "refs": refs,
    }


validate_manifest()
artifact_path = None
if mode == "validate-only":
    artifact_state = {
        "status": "not_checked",
        "path": None,
        "sha256": None,
        "failure_signature": "none" if not errors else "manifest_validation_failed",
        "dependency_breakdown": empty_dependency_breakdown(),
        "refs": [],
    }
else:
    if mode == "forge":
        artifact_path = forge_artifact()
    else:
        env_artifact = os.environ.get("FRANKENLIBC_STANDALONE_LIB")
        artifact_path = Path(env_artifact) if env_artifact else cargo_target_dir / "release" / "libfrankenlibc_replace.so"
    artifact_state = inspect_artifact(artifact_path)

artifact_state.setdefault("sampled_symbols_present", False)
artifact_state.setdefault("symbol_samples", empty_symbol_samples())
artifact_state.setdefault("host_glibc_dependency", None)
artifact_state.setdefault("path", None)
artifact_state.setdefault("sha256", None)
artifact_state.setdefault("mtime", None)

if artifact_state["failure_signature"] == "none" and artifact_state["status"] in {"current", "not_checked"}:
    claim_status = "artifact_current" if artifact_state["status"] == "current" else "schema_validated"
elif artifact_state["failure_signature"] == "non_elf_artifact":
    claim_status = "failed"
else:
    claim_status = "claim_blocked"

exit_code = 0 if not errors and artifact_state["failure_signature"] != "non_elf_artifact" else 1
append_log(
    "artifact_inspected" if mode != "validate-only" else "manifest_validated",
    artifact_path=artifact_state.get("path"),
    artifact_status=artifact_state["status"],
    claim_status=claim_status,
    artifact_hash=artifact_state.get("sha256"),
    command=[] if mode != "forge" else build_command(),
    exit_code=exit_code,
    failure_signature=artifact_state["failure_signature"],
    refs=[rel(manifest_path), rel(packaging_path), rel(levels_path), *artifact_state.get("refs", [])],
)

for row in log_rows:
    missing = [field for field in REQUIRED_LOG_FIELDS if field not in row]
    if missing:
        errors.append(f"log row missing required fields: {missing}")

for filename, evidence in tool_evidence.items():
    missing = [field for field in TOOL_EVIDENCE_REQUIRED_FIELDS if field not in evidence]
    if missing:
        errors.append(f"{filename}: tool_evidence missing required fields: {missing}")

status = "pass" if not errors and artifact_state["failure_signature"] != "non_elf_artifact" else "fail"
report = {
    "schema_version": "v1",
    "bead": manifest.get("bead"),
    "manifest_id": manifest.get("manifest_id"),
    "mode": mode,
    "status": status,
    "claim_status": claim_status,
    "source_commit": source_commit,
    "head_epoch": head_epoch,
    "cargo_target_dir": str(cargo_target_dir),
    "checks": checks,
    "artifact_state": artifact_state,
    "tool_evidence": tool_evidence,
    "inspection_timeout_policy": {
        "env": INSPECTION_TIMEOUT_ENV,
        "default_secs": INSPECTION_TIMEOUT_DEFAULT_SECS,
        "min_secs": INSPECTION_TIMEOUT_MIN_SECS,
        "max_secs": INSPECTION_TIMEOUT_MAX_SECS,
        "timeout_exit_code": INSPECTION_TIMEOUT_EXIT_CODE,
        "reported_field": "tool_evidence.*.timeout_secs",
    },
    "errors": errors,
    "required_log_fields": REQUIRED_LOG_FIELDS,
    "required_report_fields": REQUIRED_REPORT_FIELDS,
    "artifact_refs": [rel(manifest_path), rel(packaging_path), rel(levels_path), rel(report_path), rel(log_path), rel(out_dir)],
}
write_text(report_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
write_text(log_path, "".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows))
print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
