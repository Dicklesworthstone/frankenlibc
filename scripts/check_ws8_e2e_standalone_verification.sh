#!/usr/bin/env bash
# check_ws8_e2e_standalone_verification.sh -- End-to-end L3 standalone verification gate (bd-38x82.6)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
MANIFEST="${WS8_E2E_MANIFEST:-${ROOT}/tests/conformance/ws8_e2e_standalone_verification.v1.json}"
OUT_DIR="${WS8_E2E_OUT_DIR:-${ROOT}/target/conformance/ws8_e2e}"
REPORT="${WS8_E2E_REPORT:-${OUT_DIR}/ws8_e2e_standalone_verification.report.json}"
LOG="${WS8_E2E_LOG:-${OUT_DIR}/ws8_e2e_standalone_verification.log.jsonl}"
MODE="${1:---check}"

if [[ "${MODE}" == "--help" || "${MODE}" == "-h" ]]; then
    echo "Usage: $0 [--build|--check|--json|--preflight|--help]"
    echo "Requires explicit WS8_E2E_X86_ARTIFACT, WS8_E2E_AARCH64_ARTIFACT and matching .ws8-build.json receipts."
    echo "WS8_E2E_X86_PROBE / WS8_E2E_AARCH64_PROBE select provider-aware fixture_malloc executables."
    echo "WS8_E2E_PACKAGE selects the Debian package to extract and execute."
    echo "WS8_E2E_PACKAGE_PROBE supplies a prebuilt, source-bound installed-artifact probe outside --build."
    echo "WS8_E2E_QEMU_SYSROOT is required when executing a non-native architecture."
    echo "--preflight never builds or promotes; --check/--json execute probes and RCH companion tests."
    echo "--build builds the native standalone library/probe on RCH and writes source-bound receipts after success."
    exit 0
fi
if [[ "${MODE}" == "--build" ]]; then
    export RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=1800
    exec rch exec --job --result-dir target/conformance/ws8_e2e -- bash scripts/check_ws8_e2e_standalone_verification.sh --worker
fi
case "${MODE}" in --check|--json|--preflight|--worker) ;; *) echo "Unknown mode: ${MODE}" >&2; exit 1 ;; esac

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${OUT_DIR}" "${REPORT}" "${LOG}" "${MODE}" <<'PY'
from __future__ import annotations

import json
import hashlib
import os
import pathlib
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
MANIFEST_PATH = pathlib.Path(sys.argv[2]).resolve()
OUT_DIR = pathlib.Path(sys.argv[3]).resolve()
REPORT_PATH = pathlib.Path(sys.argv[4]).resolve()
LOG_PATH = pathlib.Path(sys.argv[5]).resolve()
MODE = sys.argv[6]

trace_id = f"ws8-e2e-{int(time.time() * 1000)}"
log_entries: list[dict[str, Any]] = []

def emit_log(event: str, scenario_id: str, status: str, details: dict[str, Any]) -> None:
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trace_id": trace_id,
        "bead_id": "bd-38x82.6",
        "event": event,
        "scenario_id": scenario_id,
        "status": status,
        "details": details,
    }
    log_entries.append(entry)

def run_cmd(args: list[str], cwd: pathlib.Path | None = None, env: dict[str, str] | None = None, timeout: int = 30) -> dict[str, Any]:
    cmd_env = os.environ.copy()
    cmd_env.pop("LD_PRELOAD", None)
    cmd_env.pop("LD_AUDIT", None)
    if env:
        cmd_env.update(env)
    started = time.monotonic()
    result = {"command": args, "exit_code": None, "stdout": "", "stderr": "", "executed": False}
    try:
        proc = subprocess.Popen(args, cwd=cwd or ROOT, env=cmd_env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, start_new_session=True)
        result["executed"] = True
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()
            result["timed_out"] = True
        result.update(exit_code=proc.returncode, stdout=stdout, stderr=stderr)
    except OSError as exc:
        result["stderr"] = str(exc)
    result["elapsed_seconds"] = time.monotonic() - started
    return result


def aggregate(rows: list[dict[str, Any]]) -> str:
    if any(row.get("status") == "fail" for row in rows):
        return "fail"
    if not rows or any(row.get("status") != "pass" for row in rows):
        return "blocked"
    return "pass"


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_identity() -> dict[str, str]:
    revision = run_cmd(["git", "rev-parse", "HEAD"])
    files = run_cmd(["git", "ls-files", "-z", "Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml", "support_matrix.json", "packaging_spec.json", ".cargo", "crates", "tools", "tests/conformance", "tests/integration/fixture_malloc.c", "scripts/check_ws8_e2e_standalone_verification.sh"])
    if revision["exit_code"] != 0 or files["exit_code"] != 0 or not files["stdout"]:
        raise ValueError(f"source_identity_unavailable: {revision} {files}")
    hasher = hashlib.sha256()
    for name in sorted(filter(None, files["stdout"].split("\0"))):
        path = ROOT / name
        hasher.update(name.encode() + b"\0" + path.read_bytes() + b"\0")
    return {"source_commit": revision["stdout"].strip(), "source_hash": hasher.hexdigest()}


FEATURES = ["owned-tls-cache", "owned-unwind-stub", "standalone"]
HOST_LIBRARY = re.compile(r"^(?:libc[.-]|libpthread[.-]|libdl[.-]|libm[.-]|librt[.-]|libgcc_s[.-]|ld-linux|ld-musl)")
REQUIRED_PROVIDERS = {"malloc", "free", "calloc", "realloc", "strlen", "memcpy", "memmove", "strcmp", "snprintf",
                      "__frankenlibc_healing_action_count", "__frankenlibc_is_runtime_ready"}
REQUIRED_CHECKS = {
    "string_pipeline": {"copy_exact", "length_exact", "overlap_move"},
    "memory_lifecycle": {"calloc_zeroed", "realloc_grow_preserves", "realloc_shrink_preserves"},
    "format_stdio": {"format_exact", "format_truncation"},
    "edge_boundary": {"format_zero_capacity", "empty_format", "empty_string", "zero_allocation_then_live_allocation"},
    "error_handling": {"null_strlen_healed", "foreign_free_healed", "double_free_allocation", "double_free_healed"},
}


def inspect_artifact(path: pathlib.Path, arch: str, receipt_path: pathlib.Path | None = None) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size == 0:
        return {"status": "blocked", "reason": "artifact_missing_or_empty", "artifact": str(path)}
    receipt_path = receipt_path or pathlib.Path(str(path) + ".ws8-build.json")
    try:
        receipt = json.loads(receipt_path.read_text())
        if (not isinstance(receipt, dict) or any(receipt.get(k) != v for k, v in identity.items())
                or receipt.get("artifact_sha256") != digest(path)
                or receipt.get("features") != FEATURES or receipt.get("profile") != "release"
                or receipt.get("architecture") != arch or receipt.get("exit_code") != 0
                or not isinstance(receipt.get("command"), list) or not receipt["command"]):
            return {"status": "fail", "reason": "stale_or_wrong_configuration_receipt", "artifact": str(path)}
    except (OSError, ValueError, TypeError) as exc:
        return {"status": "blocked", "reason": "build_receipt_missing_or_invalid", "detail": str(exc), "artifact": str(path)}
    evidence = {"nm": run_cmd(["nm", "-D", "--undefined-only", str(path)]),
                "elf": run_cmd(["readelf", "-h", "-d", "--dyn-syms", "--wide", str(path)])}
    row = {"artifact": str(path), "artifact_sha256": digest(path), "build": receipt, "inspection": evidence}
    if any(e["exit_code"] != 0 or e.get("timed_out") for e in evidence.values()):
        return dict(row, status="fail", reason="artifact_inspection_failed")
    elf = evidence["elf"]["stdout"]
    machine = "Advanced Micro Devices X86-64" if arch == "x86_64" else "AArch64"
    # Empty nm output can mean no undefined symbols; empty ELF inspection cannot.
    if "ELF Header:" not in elf or machine not in elf or "DYN (Shared object file)" not in elf:
        return dict(row, status="fail", reason="missing_or_wrong_elf_identity")
    needed = re.findall(r"\(NEEDED\).*?\[(.*?)\]", elf)
    undefined = evidence["nm"]["stdout"].splitlines()
    defined = {line.split()[-1].split("@")[0] for line in elf.splitlines()
               if len(line.split()) >= 8 and line.split()[0].rstrip(":").isdigit() and line.split()[6] != "UND"}
    if not {"malloc", "free", "strlen", "snprintf"}.issubset(defined):
        return dict(row, status="fail", reason="required_exports_missing")
    if any(HOST_LIBRARY.match(name) for name in needed) or any("GLIBC" in line for line in undefined):
        return dict(row, status="blocked", reason="host_runtime_dependency", needed=needed, undefined=undefined)
    return dict(row, status="pass", reason="inspection_only_not_boot_proof", needed=needed)


def evaluate_probe(run: dict[str, Any], case: str, mode: str, artifact: pathlib.Path) -> dict[str, Any]:
    result = {"execution": run, "status": "fail", "case_id": case, "mode": mode}
    if run["exit_code"] != 0 or not run["executed"] or run.get("timed_out"):
        return dict(result, reason="probe_execution_failed")
    try:
        observed = json.loads(run["stdout"])
        checks = observed["checks"]
        providers = observed["providers"]
        maps = observed["maps"]
        if (observed["case_id"] != case or observed["mode"] != mode or observed["status"] != "pass"
                or not isinstance(checks, list) or not checks
                or observed["executed"] != len(checks)
                or not all(isinstance(c, dict) and c.get("passed") is True and c.get("name") for c in checks)
                or not isinstance(providers, list) or not providers or not isinstance(maps, str) or not maps):
            return dict(result, reason="invalid_or_failed_probe_observations", observed=observed)
        expected = REQUIRED_CHECKS[case] | {"runtime_ready", "child_maps_complete"}
        if (set(c["name"] for c in checks) != expected or len(checks) != len(expected)
                or {p["symbol"] for p in providers} != REQUIRED_PROVIDERS
                or len(providers) != len(REQUIRED_PROVIDERS)):
            return dict(result, reason="missing_or_duplicate_workload_evidence", observed=observed)
        mappings = []
        for line in maps.splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) < 5:
                raise ValueError("malformed maps row")
            low, high = (int(n, 16) for n in fields[0].split("-"))
            mappings.append((low, high, fields[1], fields[5] if len(fields) == 6 else ""))
        for provider in providers:
            address = int(provider["address"], 16)
            if not any(low <= address < high and "x" in perms and pathlib.Path(name).resolve() == artifact.resolve()
                       for low, high, perms, name in mappings if name.startswith("/")):
                return dict(result, reason="wrong_runtime_provider", observed=observed)
        host = [name for _, _, _, name in mappings if HOST_LIBRARY.match(pathlib.Path(name).name)]
        if host:
            return dict(result, status="blocked", reason="host_runtime_mapped", observed=observed,
                        host_mappings=sorted(set(host)), supported_abi_execution=True)
        return dict(result, status="pass", observed=observed, supported_abi_execution=True)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return dict(result, reason="malformed_probe_evidence", detail=str(exc))


def companion_result(run: dict[str, Any], suites: list[str]) -> dict[str, Any]:
    counts = re.findall(r"test result: ok\. ([0-9]+) passed; ([0-9]+) failed;", run["stdout"])
    passed = sum(int(n) for n, _ in counts)
    valid = (bool(suites) and passed > 0 and run["exit_code"] == 0 and run["executed"] and not run.get("timed_out")
             and len(counts) == len(suites) and all(int(n) > 0 and int(f) == 0 for n, f in counts))
    return {"status": "pass" if valid else "fail", "reason": "executed_companion_tests" if valid else "companion_tests_failed_or_zero",
            "suites": suites, "passed_tests": passed, "execution": run}

# Workload orchestration helpers; no child runs until the entrypoint below.
CASES = ["string_pipeline", "memory_lifecycle", "format_stdio", "edge_boundary", "error_handling"]
SUITES = ["standalone_replacement_artifact_test", "aarch64_toolchain_test", "aarch64_smoke_runner_test",
          "distribution_packaging_contract_test", "ws8_soak_test", "soak_freshness_test",
          "hardened_mode_2x_bound_contract_test"]


def run_architecture(arch: str, artifact: pathlib.Path | None = None, artifact_receipt: pathlib.Path | None = None,
                     probe_override: pathlib.Path | None = None) -> dict[str, Any]:
    prefix = "WS8_E2E_X86" if arch == "x86_64" else "WS8_E2E_AARCH64"
    selected = os.environ.get(prefix + "_ARTIFACT")
    if artifact is None and not selected:
        return {"status": "blocked", "reason": "explicit_artifact_required", "cases": {}}
    artifact = artifact or pathlib.Path(selected).resolve()
    inspection = inspect_artifact(artifact, arch, artifact_receipt)
    row = {"status": inspection["status"], "inspection": inspection, "cases": {}}
    if inspection["status"] != "pass" and inspection.get("reason") != "host_runtime_dependency":
        return row
    probe_name = str(probe_override) if probe_override else os.environ.get(prefix + "_PROBE")
    if not probe_name or not pathlib.Path(probe_name).is_file():
        return dict(row, status="blocked", reason="provider_probe_missing")
    probe = pathlib.Path(probe_name).resolve()
    # Receipts bind the executable too; an old probe cannot certify current work.
    try:
        receipt = json.loads(pathlib.Path(str(probe) + ".ws8-build.json").read_text())
        if (any(receipt.get(k) != v for k, v in identity.items())
                or receipt.get("artifact_sha256") != digest(probe)
                or receipt.get("architecture") != arch or receipt.get("exit_code") != 0
                or not receipt.get("command")):
            return dict(row, status="fail", reason="stale_or_wrong_probe_receipt")
    except (OSError, ValueError, AttributeError) as exc:
        return dict(row, status="blocked", reason="probe_receipt_missing_or_invalid", detail=str(exc))
    runner = []
    if os.uname().machine != arch:
        executable = shutil.which("qemu-aarch64" if arch == "aarch64" else "qemu-x86_64")
        sysroot = os.environ.get("WS8_E2E_QEMU_SYSROOT")
        if not executable or not sysroot or not pathlib.Path(sysroot).is_dir():
            return dict(row, status="blocked", reason="cross_runner_or_sysroot_missing")
        # A runner is only transport. The child still has to report its own
        # mappings and provider addresses, and they must independently agree.
        runner = [executable, "-L", str(pathlib.Path(sysroot).resolve())]
    if MODE == "--preflight":
        return dict(row, status="blocked", reason="preflight_does_not_execute")
    for case in CASES:
        modes = ["hardened"] if case == "error_handling" else ["strict", "hardened"]
        for mode in modes:
            execution = run_cmd(runner + [str(probe), "--ws8-case", case, str(artifact)], env={"FRANKENLIBC_MODE": mode})
            row["cases"][case + ":" + mode] = evaluate_probe(execution, case, mode, artifact)
    row.update(status=aggregate([inspection] + list(row["cases"].values())), probe_sha256=digest(probe), probe_build=receipt)
    if digest(probe) != receipt["artifact_sha256"] or digest(artifact) != inspection["artifact_sha256"]:
        row.update(status="fail", reason="artifact_changed_during_execution")
    return row


def package_result() -> dict[str, Any]:
    package = os.environ.get("WS8_E2E_PACKAGE")
    if not package or not pathlib.Path(package).is_file():
        return {"status": "blocked", "reason": "package_missing"}
    if MODE == "--preflight":
        return {"status": "blocked", "reason": "preflight_does_not_execute"}
    prefix = pathlib.Path(tempfile.mkdtemp(prefix="package-", dir=OUT_DIR))
    extract = run_cmd(["dpkg-deb", "--extract", str(pathlib.Path(package).resolve()), str(prefix)])
    if extract["exit_code"] != 0:
        return {"status": "fail", "reason": "package_extraction_failed", "execution": extract}
    candidates = list(prefix.rglob("libfrankenlibc_replace.so"))
    if len(candidates) != 1 or not candidates[0].resolve().is_relative_to(prefix):
        return {"status": "fail", "reason": "package_artifact_missing_ambiguous_or_external", "prefix": str(prefix)}
    installed = candidates[0].resolve()
    canonical = os.environ.get("WS8_E2E_X86_ARTIFACT")
    if not canonical:
        return {"status": "blocked", "reason": "package_source_artifact_required", "extraction": extract}
    receipt_path = pathlib.Path(canonical + ".ws8-build.json")
    # The existing package need not duplicate metadata. Compare installed bytes
    # against the source-bound build receipt supplied for its canonical artifact.
    inspection = inspect_artifact(installed, "x86_64", receipt_path)
    if inspection["status"] != "pass":
        return inspection
    if MODE == "--worker":
        probe = prefix / "installed_provider_probe"
        compilation = compile_provider_probe(installed, probe, "x86_64")
        if compilation["status"] != "pass":
            return compilation
    else:
        selected_probe = os.environ.get("WS8_E2E_PACKAGE_PROBE")
        if not selected_probe:
            return {"status": "blocked", "reason": "package_probe_missing_use_build_or_explicit_probe", "inspection": inspection}
        probe = pathlib.Path(selected_probe).resolve()
    execution = run_architecture("x86_64", installed, receipt_path, probe)
    return {"status": execution["status"], "package_sha256": digest(pathlib.Path(package)),
            "prefix": str(prefix), "extraction": extract, "installed_execution": execution}


def compile_provider_probe(artifact: pathlib.Path, probe: pathlib.Path, arch: str) -> dict[str, Any]:
    command = ["cc", "-O0", "-fno-builtin", "-Wall", "-Wextra", "tests/integration/fixture_malloc.c",
               "-Wl,--no-as-needed", str(artifact), "-Wl,-rpath," + str(artifact.parent), "-ldl", "-o", str(probe)]
    compilation = run_cmd(command, timeout=120)
    if compilation["exit_code"] != 0 or compilation.get("timed_out"):
        return {"status": "fail", "reason": "probe_compilation_failed", "execution": compilation}
    if source_identity() != identity:
        return {"status": "fail", "reason": "source_changed_during_build"}
    receipt = dict(identity, artifact_sha256=digest(probe), architecture=arch,
                   command=compilation["command"], exit_code=compilation["exit_code"])
    pathlib.Path(str(probe) + ".ws8-build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return {"status": "pass", "execution": compilation}


def build_native() -> dict[str, Any]:
    arch = os.uname().machine
    if arch not in ("x86_64", "aarch64"):
        return {"status": "blocked", "reason": "unsupported_build_architecture"}
    target = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target"))).resolve()
    # RCH preserves source mtimes. A changed file can predate the last worker
    # build, so timestamp freshness alone can certify an obsolete artifact.
    command = ["cargo", "build", "-Z", "checksum-freshness", "-p", "frankenlibc-abi", "--release", "--features", ",".join(FEATURES), "--target-dir", str(target)]
    build = run_cmd(command, timeout=1800)
    if build["exit_code"] != 0 or build.get("timed_out"):
        return {"status": "blocked", "reason": "standalone_build_did_not_succeed", "execution": build}
    artifact = target / "release/libfrankenlibc_abi.so"
    probe = OUT_DIR / "ws8_provider_probe"
    compile_probe = compile_provider_probe(artifact, probe, arch)
    if compile_probe["status"] != "pass":
        return compile_probe
    if source_identity() != identity:
        return {"status": "fail", "reason": "source_changed_during_build"}
    for path, invocation in ((artifact, build),):
        receipt = dict(identity, artifact_sha256=digest(path), architecture=arch, features=FEATURES,
                       profile="release", command=invocation["command"], exit_code=invocation["exit_code"],
                       timestamp_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        pathlib.Path(str(path) + ".ws8-build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    prefix = "WS8_E2E_X86" if arch == "x86_64" else "WS8_E2E_AARCH64"
    os.environ[prefix + "_ARTIFACT"] = str(artifact)
    os.environ[prefix + "_PROBE"] = str(probe)
    return {"status": "pass", "reason": "build_only_not_isolation", "execution": build, "probe_compilation": compile_probe}


# Execution entrypoint. Unit tests load only the helpers above this boundary.
# Invalidate prior promotion evidence before any potentially long-running child.
REPORT_PATH.write_text(json.dumps({"status": "blocked", "phase": "running", "trace_id": trace_id}) + "\n")
LOG_PATH.write_text(json.dumps({"status": "blocked", "event": "run_started", "trace_id": trace_id}) + "\n")
manifest = {}
scenarios = {}
architectures = {}
try:
    manifest = json.loads(MANIFEST_PATH.read_text())
    if not isinstance(manifest, dict) or manifest.get("manifest_id") != "ws8-e2e-standalone-verification":
        raise ValueError("invalid WS8 manifest")
    identity = source_identity()
    if MODE == "--worker":
        scenarios["native_build"] = build_native()
    architectures = {arch: run_architecture(arch) for arch in ("x86_64", "aarch64")}
    scenarios["standalone_boot_isolation"] = architectures["x86_64"]
    scenarios["aarch64_cross_smoke_execution"] = architectures["aarch64"]
    scenarios["distro_package_prefix_inspection"] = package_result()
    for case in ("edge_boundary", "error_handling"):
        rows = [row for arch in architectures.values() for key, row in arch["cases"].items() if key.startswith(case + ":")]
        # Each required architecture must actually execute its entire battery.
        scenarios["curated_workload_" + case] = {"status": aggregate(list(architectures.values()) + rows), "executions": rows}
    if MODE == "--preflight":
        scenarios["companion_unit_tests_pass"] = {"status": "blocked", "reason": "preflight_does_not_execute", "passed_tests": 0}
    else:
        command = ([] if MODE == "--worker" else ["rch", "exec", "--"]) + ["cargo", "test", "-Z", "checksum-freshness", "-p", "frankenlibc-harness", "--no-default-features", "--no-fail-fast"]
        for suite in SUITES:
            command.extend(["--test", suite])
        command.extend(["--", "--nocapture"])
        scenarios["companion_unit_tests_pass"] = companion_result(run_cmd(command, env={"RCH_REQUIRE_REMOTE": "1"}, timeout=1800), SUITES)
    # Reject edits during the run instead of publishing a mixed-revision receipt.
    if source_identity() != identity:
        scenarios["source_freshness"] = {"status": "fail", "reason": "source_changed_during_execution"}
except (OSError, ValueError, TypeError, KeyError) as exc:
    scenarios["input_validation"] = {"status": "fail", "reason": str(exc)}

overall = aggregate(list(scenarios.values()))
for name, row in scenarios.items():
    emit_log("scenario_executed" if row.get("cases") or row.get("executions") else "scenario_evaluated", name, row["status"], row)
report = {
    "schema_version": "v1", "manifest_id": "ws8-e2e-standalone-verification",
    "bead_id": "bd-38x82.6", "repair_bead": "bd-reality-202609-lx578q.1", "parent_bead": "bd-38x82",
    "status": overall, "trace_id": trace_id, "mode": MODE,
    "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "source": globals().get("identity"), "architectures": architectures, "scenarios": scenarios,
    "companion_beads": {"bd-38x82.1": architectures.get("x86_64", {}).get("status", "blocked"),
                        "bd-38x82.2": architectures.get("aarch64", {}).get("status", "blocked"),
                        "bd-38x82.3": scenarios.get("distro_package_prefix_inspection", {}).get("status", "blocked"),
                        "bd-38x82.4": "not_assessed", "bd-38x82.5": "not_assessed"},
    "distro_package": scenarios.get("distro_package_prefix_inspection", {"status": "blocked"}),
    "workload_battery": {case: {"status": aggregate(list(architectures.values())),
                               "executions": [row for arch in architectures.values() for key, row in arch.get("cases", {}).items() if key.startswith(case + ":")]}
                         for case in CASES},
    "summary": {"scenarios_evaluated": len(scenarios),
                "workload_processes_executed": sum(bool(row.get("execution", {}).get("executed"))
                    for arch in architectures.values() for row in arch.get("cases", {}).values()),
                "companion_tests_passed": scenarios.get("companion_unit_tests_pass", {}).get("passed_tests", 0),
                "scenarios_passed": sum(row["status"] == "pass" for row in scenarios.values()),
                "scenarios_failed": sum(row["status"] == "fail" for row in scenarios.values()),
                "scenarios_blocked": sum(row["status"] == "blocked" for row in scenarios.values()),
                "overall_status": overall},
}
REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n")
LOG_PATH.write_text("".join(json.dumps(entry) + "\n" for entry in log_entries))
if MODE in ("--json", "--preflight"):
    print(json.dumps(report, indent=2))
else:
    print(f"WS-8 standalone E2E: {overall.upper()} (report: {REPORT_PATH}; log: {LOG_PATH})")
sys.exit({"pass": 0, "fail": 1, "blocked": 2}[overall])
PY
