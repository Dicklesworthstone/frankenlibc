#!/usr/bin/env python3
"""Exercise allocation integrity through a provider-pinned LD_PRELOAD artifact.

Corrupt allocations have no host-libc correctness oracle. These probes verify
their explicit hardened contract, with logging disabled for the cache lane and
separate JSONL audit runs. Every timeout, missing probe, provider mismatch,
malformed result, or missing repair fails the gate. Existing parity and deployed
performance gates remain independently required by ld_preload_smoke.sh.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


CASE_IDS = (
    "intact", "corrupt-legacy-fold", "corrupt-symmetric-pair", "corrupt-header",
    "corrupt-after-warm-tls-write", "corrupt-header-after-warm-tls",
    "corrupt-after-warm-tls-read", "corrupt-after-warm-tls-strcpy",
    "corrupt-after-warm-tls-memset", "corrupt-after-warm-tls-memmove",
    "corrupt-after-warm-tls-strncpy", "corrupt-after-warm-tls-stpncpy",
    "corrupt-after-warm-tls-strcat", "corrupt-after-warm-tls-strncat",
    "corrupt-after-warm-tls-strlcpy", "corrupt-after-warm-tls-strlcat",
    "corrupt-after-warm-tls-snprintf", "corrupt-after-warm-tls-snprintf-string",
    "corrupt-after-warm-tls-vsnprintf", "corrupt-after-warm-tls-sprintf",
    "corrupt-after-warm-tls-vsprintf", "corrupt-after-warm-tls-count-store",
    "corrupt-header-after-warm-tls-snprintf", "corrupt-after-warm-tls-snprintf-terminator",
    "corrupt-after-warm-tls-wmemcpy", "corrupt-after-warm-tls-wmemmove",
    "corrupt-after-warm-tls-wmemset",
)
PROVIDERS = {
    "malloc", "free", "mprobe", "memcpy", "__frankenlibc_healing_action_count",
    "__frankenlibc_is_runtime_ready", "strlen", "strcpy", "memset", "memmove",
    "strncpy", "stpncpy", "strcat", "strncat", "strlcpy", "strlcat",
    "snprintf", "vsnprintf", "sprintf", "vsprintf",
    "wmemcpy", "wmemmove", "wmemset",
}
OBSERVATIONS = (
    "allocation_address", "capacity", "header_generation", "header_size",
    "mprobe_initial", "mprobe_mutated", "mprobe_freed", "detection_calls",
    "clamp_before", "clamp_after", "free_clamp_before", "free_clamp_after",
    "boundary_before", "boundary_after",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def required_checks(case_id: str, mode: str) -> set[str]:
    names = {"runtime_ready", "allocation_non_null", "mprobe_initial_ok", "mprobe_after_free"}
    if mode == "hardened":
        names.update(("header_layout_24b", "tail_not_disclosed_by_header", "tail_not_legacy_fold"))
    if case_id == "intact":
        names.update(("memcpy_intact_allowed", "intact_boundary_writes_emit_no_clamp",
                      "intact_snprintf_zero_size_no_write", "intact_snprintf_size_one_terminator"))
        names.update(f"intact_boundary_{symbol}_allowed" for symbol in (
            "memcpy", "memmove", "memset", "strcpy", "strncpy", "stpncpy",
            "strcat", "strncat", "strlcpy", "strlcat",
            "snprintf", "vsnprintf", "sprintf", "vsprintf", "snprintf_literal",
            "wmemcpy", "wmemmove", "wmemset",
        ))
    elif case_id == "corrupt-legacy-fold":
        names.update(("mprobe_detects_legacy_fold_tail", "membrane_rejects_legacy_fold_canary",
                      "corrupt_free_emits_quarantine_clamp"))
    elif case_id == "corrupt-symmetric-pair":
        names.update(("mprobe_detects_symmetric_pair_tail", "membrane_rejects_symmetric_pair_canary",
                      "corrupt_free_emits_quarantine_clamp"))
    elif case_id == "corrupt-header":
        names.update(("mprobe_detects_header_corruption", "membrane_rejects_corrupted_header",
                      "mprobe_restored_ok"))
    else:
        names.update(("warm_strlen_allowed", "warm_corruption_emits_clamp",
                      "mprobe_agrees_with_warm_rejection", "corrupt_free_emits_quarantine_clamp"))
        names.add("warm_read_detected_within_16_calls" if case_id.endswith("-read")
                  else "boundary_write_denied_immediately")
        if any(symbol in case_id for symbol in ("printf", "count-store")):
            names.add("format_return_preserves_required_length")
    return names


def validate_contract(data: dict, case_id: str, mode: str) -> dict:
    require(isinstance(data, dict), "fixture output must be a JSON object")
    require(data.get("case_id") == case_id and data.get("mode") == mode,
            "fixture case/mode does not match invocation")
    require(data.get("status") == "pass", "fixture reported a failed assertion")
    checks = data.get("checks")
    require(isinstance(checks, list) and bool(checks), "missing executed checks")
    require(all(isinstance(check, dict) and check.get("passed") is True for check in checks),
            "a check failed or was not a boolean true")
    names = [check.get("name") for check in checks]
    require(all(isinstance(name, str) for name in names), "invalid check name")
    require(len(names) == len(set(names)), "duplicate checks")
    require(set(names) == required_checks(case_id, mode), "missing or unexpected contract checks")
    require(type(data.get("executed")) is int and data["executed"] == len(checks),
            "executed count does not match required nonempty checks")

    providers = data.get("providers")
    require(isinstance(providers, list) and len(providers) == len(PROVIDERS),
            "missing provider-pinned symbols")
    require(all(isinstance(provider, dict) for provider in providers), "invalid provider record")
    require({provider.get("symbol") for provider in providers} == PROVIDERS,
            "wrong provider symbol set")
    require(all(isinstance(provider.get("address"), str)
                and int(provider["address"], 16) > 0 for provider in providers),
            "null or malformed provider address")

    for field in OBSERVATIONS[:-2]:
        require(type(data.get(field)) is int, f"missing integer observation: {field}")
    warm = "warm-tls" in case_id
    corrupt = case_id != "intact"
    require(data["allocation_address"] > 0, "no allocation was exercised")
    require(data["capacity"] == (1024 if warm else 32), "wrong allocation size")
    require(data["mprobe_initial"] == 0 and data["mprobe_freed"] == 1,
            "allocation lifetime probes disagree")
    expected_mutation = (2 if "header" in case_id else 3) if corrupt else -1
    require(data["mprobe_mutated"] == expected_mutation, "wrong corruption classification")
    if mode == "hardened":
        require(data["header_generation"] > 0 and data["header_size"] == data["capacity"],
                "trusted allocation geometry was not observed")
    for field in ("clamp_before", "clamp_after", "free_clamp_before", "free_clamp_after"):
        require(data[field] >= 0, f"negative counter: {field}")
    clamp_delta = data["clamp_after"] - data["clamp_before"]
    free_delta = data["free_clamp_after"] - data["free_clamp_before"]
    require(clamp_delta > 0 if corrupt else clamp_delta == 0,
            "access repair counter does not match the operation")
    corrupt_at_free = corrupt and case_id != "corrupt-header"
    require(free_delta > 0 if corrupt_at_free else free_delta == 0,
            "free repair counter does not match retirement state")
    if case_id.endswith("-read"):
        require(1 <= data["detection_calls"] <= 16, "warm read exceeded its detection bound")
    else:
        require(data["detection_calls"] == 0, "unexpected read retry loop")
    for field in ("boundary_before", "boundary_after"):
        require(isinstance(data.get(field), list) and len(data[field]) == 8
                and all(type(value) is int and 0 <= value <= 255 for value in data[field]),
                f"missing eight-byte observation: {field}")
    if warm:
        require(data["boundary_before"] == data["boundary_after"],
                "a corrupt allocation was modified")
    return {"access_clamp_delta": clamp_delta, "free_clamp_delta": free_delta}


def validate_audit(path: Path, data: dict, case_id: str) -> dict:
    require(path.is_file(), "configured runtime JSONL audit was not created")
    records = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        require(bool(line.strip()), f"blank audit record at line {line_number}")
        record = json.loads(line)
        require(isinstance(record, dict), f"non-object audit record at line {line_number}")
        records.append(record)
    require(bool(records), "configured runtime JSONL audit is empty")
    reason = "header_fingerprint" if "header" in case_id else "trailing_canary"
    address = data["allocation_address"]
    quarantine = [record for record in records
                  if record.get("event") == "allocation_corruption_quarantined"
                  and record.get("api_family") == "allocator" and record.get("symbol") == "free"
                  and record.get("address") == address and record.get("reason") == reason
                  and record.get("action") == "ClampSize"
                  and record.get("requested") == data["capacity"] and record.get("clamped") == 0]
    free_repairs = [record for record in records
                    if record.get("event") == "repair" and record.get("symbol") == "free"
                    and record.get("api_family") == "allocator"
                    and record.get("runtime_mode") == "hardened"
                    and record.get("address") == hex(address)
                    and record.get("healing_action") == "ClampSize"
                    and record.get("details") == {"requested": data["capacity"], "clamped": 0}]
    access_address = hex(address + data["capacity"] - 8)
    cached_symbol = "cached_header_integrity" if "header" in case_id else "cached_tail_integrity"
    access_repairs = [record for record in records
                     if record.get("event") == "repair"
                     and (record.get("api_family"), record.get("symbol")) in {
                         ("string_memory", "memcpy"), ("stdio", "snprintf"),
                         ("pointer_validation", cached_symbol)}
                     and record.get("runtime_mode") == "hardened"
                     and record.get("address") == access_address
                     and record.get("healing_action") == "ClampSize"
                     and record.get("details") == {"requested": 8, "clamped": 0}]
    require(bool(quarantine), "missing address-matched structured quarantine diagnostic")
    require(bool(free_repairs), "missing address-matched non-None free repair audit")
    require(bool(access_repairs), "missing address-matched access-denial repair audit")
    return {"records": len(records), "quarantine_diagnostics": len(quarantine),
            "free_repairs": len(free_repairs), "access_repairs": len(access_repairs),
            "path": str(path)}


def decoded(value: bytes | str | None) -> str:
    return value.decode("utf-8", errors="backslashreplace") if isinstance(value, bytes) else value or ""


def execute(command: list[str], env: dict, directory: Path, timeout: int) -> dict:
    directory.mkdir()
    started = time.monotonic_ns()
    try:
        result = subprocess.run(command, env=env, capture_output=True, timeout=timeout)
        stdout, stderr, returncode, timed_out = result.stdout, result.stderr, result.returncode, False
    except subprocess.TimeoutExpired as error:
        stdout, stderr, returncode, timed_out = error.stdout, error.stderr, None, True
    stdout, stderr = decoded(stdout), decoded(stderr)
    (directory / "stdout.json").write_text(stdout)
    (directory / "stderr.txt").write_text(stderr)
    return {"command": command, "returncode": returncode, "timed_out": timed_out,
            "latency_ns": time.monotonic_ns() - started, "stdout": stdout, "stderr": stderr,
            "artifacts": str(directory)}


def run(args: argparse.Namespace) -> int:
    require(sys.platform == "linux", "LD_PRELOAD allocation probes require Linux")
    require(args.timeout > 0, "timeout must be positive")
    library = args.library.resolve(strict=True)
    require(library.is_file(), "library must be a regular file")
    compiler = shutil.which("cc")
    require(compiler is not None, "required C compiler 'cc' not found")
    root = Path(__file__).resolve().parents[1]
    source = root / "tests/integration/fixture_malloc.c"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    binary = output / "fixture_malloc"
    env = dict(os.environ, LC_ALL="C")
    for name in ("LD_PRELOAD", "LD_AUDIT", "LD_DEBUG", "FRANKENLIBC_LOG",
                 "FRANKENLIBC_HEAL_LOG", "FRANKENLIBC_MODE"):
        env.pop(name, None)
    build = execute([compiler, "-O2", "-fno-builtin", str(source), "-o", str(binary), "-ldl"],
                    env, output / "build", args.timeout)
    require(build["returncode"] == 0, f"fixture compilation failed: {build['stderr']}")

    control = execute([str(binary), "--canary-case", "intact", str(library)],
                      dict(env, FRANKENLIBC_MODE="strict"), output / "wrong-provider", args.timeout)
    provider_control = (control["returncode"] == 2
                        and "wrong/missing provider" in control["stderr"])
    cases = [("strict", "intact", False)]
    cases.extend(("hardened", case_id, False) for case_id in CASE_IDS)
    cases.extend(("hardened", case_id, True) for case_id in (
        "corrupt-after-warm-tls-write", "corrupt-header-after-warm-tls",
        "corrupt-after-warm-tls-snprintf", "corrupt-header-after-warm-tls-snprintf"))
    records = []
    for mode, case_id, logging in cases:
        label = f"{mode}-{case_id}-{'audit' if logging else 'cache'}"
        directory = output / label
        runtime_log = directory / "runtime.jsonl"
        child_env = dict(env, LD_PRELOAD=str(library), FRANKENLIBC_MODE=mode)
        if logging:
            # The deployed sink must work independently of the optional heap
            # backed diagnostic mirror. Cache probes above keep LOG absent.
            child_env.update(FRANKENLIBC_LOG=str(runtime_log), FRANKENLIBC_HEAL_LOG="0")
        result = execute([str(binary), "--canary-case", case_id, str(library)],
                         child_env, directory, args.timeout)
        record = {"schema_version": "v1", "event": "allocation_integrity_case",
                  "mode": mode, "case_id": case_id, "runtime_log_configured": logging,
                  "returncode": result["returncode"], "timed_out": result["timed_out"],
                  "latency_ns": result["latency_ns"], "artifacts": result["artifacts"],
                  "status": "fail", "checks_executed": 0}
        try:
            require(result["returncode"] == 0, "fixture failed, crashed, or timed out")
            data = json.loads(result["stdout"])
            record.update(validate_contract(data, case_id, mode))
            record["observations"] = {field: data[field] for field in OBSERVATIONS}
            record["checks_executed"] = data["executed"]
            if logging:
                record["audit"] = validate_audit(runtime_log, data, case_id)
            record["status"] = "pass"
        except (ValueError, TypeError, KeyError, OSError) as error:
            record["failure"] = str(error)
        records.append(record)
        line = json.dumps(record, sort_keys=True) + "\n"
        with (output / "cases.jsonl").open("a") as stream:
            stream.write(line)
        if args.trace:
            with args.trace.open("a") as stream:
                stream.write(line)
        print(f"allocation_integrity {label}: {record['status']}"
              + (f" ({record['failure']})" if "failure" in record else ""), flush=True)

    failures = sum(record["status"] != "pass" for record in records)
    passed = provider_control and not failures and len(records) == len(cases)
    report = {"schema_version": "v1", "scope": "deployed_allocation_integrity",
              "library": str(library), "library_sha256": sha256(library),
              "fixture_source_sha256": sha256(source), "fixture_sha256": sha256(binary),
              "wrong_provider_control": {"passed": provider_control,
                                         "returncode": control["returncode"],
                                         "artifacts": control["artifacts"]},
              "summary": {"required_cases": len(cases), "executed_cases": len(records),
                          "passes": len(records) - failures, "failures": failures,
                          "checks_executed": sum(record["checks_executed"] for record in records),
                          "passed": passed}, "cases": records}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"allocation_integrity report: {output / 'report.json'}", flush=True)
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="fresh artifact directory")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--trace", type=Path, help="append per-case JSONL records to this trace")
    args = parser.parse_args()
    try:
        return run(args)
    except (ValueError, OSError) as error:
        print(f"allocation_integrity setup failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
