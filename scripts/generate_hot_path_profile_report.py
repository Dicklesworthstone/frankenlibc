#!/usr/bin/env python3
"""Generate the hot-path profile report for bd-bp8fl.8.3.

The report is deliberately derived from committed evidence:
  * membrane overhead baselines from bd-bp8fl.8.2,
  * symbol latency baselines with raw host comparison rows,
  * benchmark coverage inventory gaps owned by bd-bp8fl.8.3,
  * parity proof and fixture artifacts that keep optimization profile-first.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BEAD_ID = "bd-bp8fl.8.3"
SCHEMA_VERSION = "v1"
PROFILE_REPORT_PATH = "tests/conformance/hot_path_profile_report.v1.json"
REQUIRED_MODES = ("strict", "hardened")
MAX_GAP_RECORDS = 50
TOP_LOG_RECORDS = 25

INPUT_PATHS = {
    "benchmark_coverage_inventory": "tests/conformance/benchmark_coverage_inventory.v1.json",
    "membrane_overhead_baseline": "tests/conformance/membrane_overhead_baseline.v1.json",
    "symbol_latency_baseline": "tests/conformance/symbol_latency_baseline.v1.json",
    "perf_baseline": "scripts/perf_baseline.json",
    "perf_baseline_spec": "tests/conformance/perf_baseline_spec.json",
    "profile_pipeline": "scripts/profile_pipeline.sh",
    "optimization_proof_ledger": "tests/conformance/optimization_proof_ledger.v1.json",
}

REQUIRED_PROFILE_FIELDS = [
    "profile_id",
    "workload_or_microbenchmark",
    "api_family",
    "symbol",
    "runtime_mode",
    "replacement_level",
    "profile_tool",
    "sample_count",
    "hotness_score",
    "baseline_artifact",
    "parity_proof_refs",
    "host_baseline",
    "coverage_state",
    "artifact_refs",
    "failure_signature",
]

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "profile_id",
    "api_family",
    "symbol",
    "runtime_mode",
    "hotness_score",
    "baseline_ref",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]

MODULE_FAMILIES = {
    "string_abi": "string",
    "wchar_abi": "string",
    "malloc_abi": "malloc",
    "stdio_abi": "stdio",
    "pthread_abi": "pthread",
    "c11threads_abi": "pthread",
    "unistd_abi": "syscall",
    "io_abi": "syscall",
    "dirent_abi": "syscall",
    "resource_abi": "syscall",
    "socket_abi": "syscall",
    "poll_abi": "syscall",
    "time_abi": "syscall",
}

FAMILY_PARITY_REFS = {
    "membrane": [
        "tests/conformance/healing_oracle_report.v1.json",
        "tests/conformance/mode_semantics_matrix.json",
        "tests/conformance/membrane_overhead_baseline.v1.json",
    ],
    "runtime_math": [
        "tests/runtime_math/runtime_math_classification_matrix.v1.json",
        "tests/runtime_math/golden/kernel_snapshot_smoke.v1.json",
    ],
    "string": [
        "tests/conformance/fixtures/string_memory_full.json",
        "tests/conformance/fixtures/string_ops.json",
        "tests/conformance/symbol_latency_baseline.v1.json",
    ],
    "malloc": [
        "tests/conformance/fixtures/allocator.json",
        "tests/conformance/c_fixture_spec.json",
        "tests/conformance/benchmark_coverage_inventory.v1.json",
    ],
    "stdio": [
        "tests/conformance/fixtures/stdio_file_ops.json",
        "tests/conformance/fixtures/printf_conformance.json",
        "tests/conformance/stdio_invariants.v1.json",
    ],
    "pthread": [
        "tests/conformance/fixtures/pthread_mutex.json",
        "tests/conformance/fixtures/pthread_cond.json",
        "tests/conformance/proofs/mutex-hotpath-nochange-v1.json",
        "tests/conformance/proofs/condvar-nochange-v1.json",
        "tests/conformance/proofs/thread-bootstrap-nochange-v1.json",
    ],
    "syscall": [
        "tests/conformance/fixtures/unistd_ops.json",
        "tests/conformance/e2e_scenario_manifest.v1.json",
        "tests/conformance/workload_matrix.json",
    ],
}

PROOF_REFS_BY_SYMBOL = {
    "pthread_mutex_lock": ["tests/conformance/proofs/mutex-hotpath-nochange-v1.json"],
    "pthread_mutex_trylock": ["tests/conformance/proofs/mutex-hotpath-nochange-v1.json"],
    "pthread_mutex_unlock": ["tests/conformance/proofs/mutex-hotpath-nochange-v1.json"],
    "pthread_cond_broadcast": ["tests/conformance/proofs/condvar-nochange-v1.json"],
    "pthread_cond_destroy": ["tests/conformance/proofs/condvar-nochange-v1.json"],
    "pthread_cond_init": ["tests/conformance/proofs/condvar-nochange-v1.json"],
    "pthread_cond_signal": ["tests/conformance/proofs/condvar-nochange-v1.json"],
    "pthread_cond_timedwait": ["tests/conformance/proofs/condvar-nochange-v1.json"],
    "pthread_cond_wait": ["tests/conformance/proofs/condvar-nochange-v1.json"],
    "pthread_create": ["tests/conformance/proofs/thread-bootstrap-nochange-v1.json"],
    "pthread_detach": ["tests/conformance/proofs/thread-bootstrap-nochange-v1.json"],
    "pthread_join": ["tests/conformance/proofs/thread-bootstrap-nochange-v1.json"],
}


class HotPathProfileError(ValueError):
    """Raised when profile evidence cannot produce a trustworthy report."""


def repo_root() -> Path:
    root = Path(__file__).resolve().parent.parent
    if not (root / "Cargo.toml").exists():
        raise SystemExit(f"Could not locate repo root from {__file__}")
    return root


def load_json(path: Path) -> Any:
    try:
        return json.JSONDecoder().decode(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise HotPathProfileError(f"{path}: could not read JSON input: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise HotPathProfileError(f"{path}: invalid JSON: {exc}") from exc


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise HotPathProfileError(f"{path}: could not hash input: {exc}") from exc


def relative(path: Path, root: Path) -> str:
    return str(path.relative_to(root))


def source_commit(root: Path) -> str:
    git_dir = root / ".git"
    head_path = git_dir / "HEAD"
    try:
        head = head_path.read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"
    if not head.startswith("ref: "):
        return head[:8] if head else "unknown"

    ref_name = head.removeprefix("ref: ").strip()
    ref_path = git_dir / ref_name
    try:
        ref_value = ref_path.read_text(encoding="utf-8").strip()
        return ref_value[:8] if ref_value else "unknown"
    except OSError:
        pass

    packed_refs = git_dir / "packed-refs"
    try:
        for line in packed_refs.read_text(encoding="utf-8").splitlines():
            if line.startswith("#") or line.startswith("^"):
                continue
            fields = line.split()
            if len(fields) == 2 and fields[1] == ref_name:
                return fields[0][:8]
    except OSError:
        pass
    return "unknown"


def input_digests(root: Path) -> dict[str, str]:
    return {
        name: sha256_file(root / rel_path)
        for name, rel_path in sorted(INPUT_PATHS.items())
    }


def normalized_report(report: dict[str, object]) -> dict[str, object]:
    normalized = deepcopy(report)
    normalized.pop("generated_at_utc", None)
    normalized.pop("source_commit", None)
    return normalized


def attach_artifact_hash(report: dict[str, object]) -> None:
    stable = normalized_report(report)
    stable.pop("artifact_hash", None)
    report["artifact_hash"] = sha256_bytes(stable_json(stable).encode("utf-8"))


def reports_match(generated: dict[str, object], current: dict[str, object]) -> bool:
    return normalized_report(generated) == normalized_report(current)


def family_for_module(module: str) -> str:
    return MODULE_FAMILIES.get(module, "unknown")


def replacement_level(symbol_row: dict[str, object] | None, family: str) -> str:
    if family in {"membrane", "runtime_math"}:
        return "internal-control-plane"
    status = str((symbol_row or {}).get("status", "unknown"))
    if status == "RawSyscall":
        return "L1-native-raw-syscall"
    if status == "Implemented":
        return "L1-native-rust"
    if status == "GlibcCallThrough":
        return "L0-host-call-through"
    return "L0-interpose"


def existing_refs(root: Path, refs: list[str]) -> list[str]:
    return [ref for ref in refs if (root / ref).exists()]


def parity_refs(root: Path, family: str, symbol: str) -> list[str]:
    refs = list(PROOF_REFS_BY_SYMBOL.get(symbol, []))
    refs.extend(FAMILY_PARITY_REFS.get(family, []))
    seen: set[str] = set()
    kept: list[str] = []
    for ref in existing_refs(root, refs):
        if ref not in seen:
            kept.append(ref)
            seen.add(ref)
    return kept


def p50_target(mode: str, benchmark: str, threshold: float | int | None) -> float | None:
    if threshold is not None:
        return float(threshold)
    if benchmark.startswith("validate_"):
        return 20.0 if mode == "strict" else 200.0
    return None


def membrane_hotness(record: dict[str, object]) -> float:
    latency = float(record.get("latency_ns", 0.0) or 0.0)
    threshold = p50_target(
        str(record.get("runtime_mode", "")),
        str(record.get("benchmark", "")),
        record.get("threshold") if isinstance(record.get("threshold"), (int, float)) else None,
    )
    ratio = latency / threshold if threshold and threshold > 0 else 1.0
    variance = record.get("variance", {})
    p99_spread = 0.0
    if isinstance(variance, dict) and isinstance(variance.get("p99_minus_p50_ns"), (int, float)):
        p99_spread = float(variance["p99_minus_p50_ns"])
    if str(record.get("decision")) == "captured_over_target_for_optimization":
        return round(300.0 + ratio * 10.0 + min(latency / 10.0, 500.0) + min(p99_spread / 10.0, 50.0), 3)
    return round(80.0 + min(ratio * 10.0, 100.0) + min(latency / 20.0, 100.0), 3)


def latency_hotness(symbol_row: dict[str, object], mode: str) -> float:
    baseline = symbol_row.get("baseline", {})
    mode_data = baseline.get(mode, {}) if isinstance(baseline, dict) else {}
    raw_data = baseline.get("raw", {}) if isinstance(baseline, dict) else {}
    p50 = float(mode_data.get("p50_ns", 0.0) or 0.0) if isinstance(mode_data, dict) else 0.0
    p99 = float(mode_data.get("p99_ns", p50) or p50) if isinstance(mode_data, dict) else p50
    raw_p50 = float(raw_data.get("p50_ns", 0.0) or 0.0) if isinstance(raw_data, dict) else 0.0
    priority = float(symbol_row.get("capture_priority_score", 0.0) or 0.0)
    ratio = p50 / raw_p50 if raw_p50 > 0.0 else 1.0
    tail_ratio = p99 / p50 if p50 > 0.0 else 1.0
    log_latency = math.log10(p50 + 1.0) * 30.0 if p50 > 0.0 else 0.0
    return round(priority + min(log_latency, 300.0) + max(0.0, ratio - 1.0) * 60.0 + min(tail_ratio, 10.0) * 3.0, 3)


def gap_hotness(row: dict[str, object]) -> float:
    exposure = row.get("user_workload_exposure", {})
    if not isinstance(exposure, dict):
        exposure = {}
    critical = int(exposure.get("critical_symbol_workload_count", 0) or 0)
    workloads = int(exposure.get("workload_count", 0) or 0)
    user_workloads = int(exposure.get("user_workload_count", 0) or 0)
    reason = str(row.get("missing_benchmark_reason", "unknown"))
    reason_weight = {
        "missing_benchmark_target": 55.0,
        "missing_perf_baseline_spec_suite": 50.0,
        "missing_symbol_specific_benchmark": 42.0,
        "missing_p50_baseline": 34.0,
        "benchmark_not_strict_hardened_mode_aware": 28.0,
    }.get(reason, 20.0)
    family_weight = {
        "syscall": 35.0,
        "malloc": 30.0,
        "pthread": 28.0,
        "string": 25.0,
        "stdio": 24.0,
    }.get(str(row.get("api_family")), 10.0)
    return round(70.0 + reason_weight + family_weight + critical * 16.0 + workloads * 3.0 + user_workloads * 2.0, 3)


def host_baseline_from_symbol(symbol_row: dict[str, object], mode: str) -> dict[str, object]:
    baseline = symbol_row.get("baseline", {})
    mode_data = baseline.get(mode, {}) if isinstance(baseline, dict) else {}
    raw_data = baseline.get("raw", {}) if isinstance(baseline, dict) else {}
    raw_p50 = raw_data.get("p50_ns") if isinstance(raw_data, dict) else None
    mode_p50 = mode_data.get("p50_ns") if isinstance(mode_data, dict) else None
    available = (
        isinstance(raw_data, dict)
        and raw_data.get("capture_state") == "measured"
        and isinstance(raw_p50, (int, float))
    )
    ratio = None
    if available and isinstance(mode_p50, (int, float)) and float(raw_p50) > 0.0:
        ratio = round(float(mode_p50) / float(raw_p50), 6)
    return {
        "available": available,
        "kind": "raw_host_glibc_baseline" if available else "raw_host_glibc_pending",
        "p50_ns": raw_p50 if available else None,
        "p95_ns": raw_data.get("p95_ns") if available else None,
        "p99_ns": raw_data.get("p99_ns") if available else None,
        "comparison_ratio_p50": ratio,
        "source": raw_data.get("source") if available else None,
        "limit": None if available else "raw host baseline is not captured for this symbol yet",
    }


def no_host_equivalent(limit: str) -> dict[str, object]:
    return {
        "available": False,
        "kind": "not_applicable",
        "p50_ns": None,
        "p95_ns": None,
        "p99_ns": None,
        "comparison_ratio_p50": None,
        "source": None,
        "limit": limit,
    }


def latency_mode_measured(symbol_row: dict[str, object], mode: str) -> bool:
    baseline = symbol_row.get("baseline", {})
    mode_data = baseline.get(mode, {}) if isinstance(baseline, dict) else {}
    return (
        isinstance(mode_data, dict)
        and mode_data.get("capture_state") == "measured"
        and isinstance(mode_data.get("p50_ns"), (int, float))
    )


def host_comparison_available(record: dict[str, object]) -> bool:
    host = record.get("host_baseline", {})
    available = host.get("available") if isinstance(host, dict) else False
    return isinstance(available, bool) and available


def latency_baseline_artifact(symbol_row: dict[str, object], mode: str) -> dict[str, object]:
    mode_data = symbol_row["baseline"][mode]
    return {
        "path": "tests/conformance/symbol_latency_baseline.v1.json",
        "source": mode_data.get("source"),
        "runtime_mode": mode,
        "p50_ns": mode_data.get("p50_ns"),
        "p95_ns": mode_data.get("p95_ns"),
        "p99_ns": mode_data.get("p99_ns"),
        "present": True,
    }


def membrane_profile_records(root: Path, membrane: dict[str, object]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for record in membrane.get("benchmark_records", []):
        if not isinstance(record, dict):
            continue
        mode = str(record.get("runtime_mode", ""))
        benchmark = str(record.get("benchmark", ""))
        if mode not in REQUIRED_MODES or not benchmark:
            continue
        profile_id = f"membrane:{mode}:{benchmark}"
        threshold = p50_target(
            mode,
            benchmark,
            record.get("threshold") if isinstance(record.get("threshold"), (int, float)) else None,
        )
        artifact_refs = sorted(
            set(
                [
                    "scripts/profile_pipeline.sh",
                    "tests/conformance/membrane_overhead_baseline.v1.json",
                    "scripts/perf_baseline.json",
                    "tests/conformance/perf_baseline_spec.json",
                ]
                + [str(ref) for ref in record.get("artifact_refs", []) if isinstance(ref, str)]
            )
        )
        rows.append(
            {
                "profile_id": profile_id,
                "workload_or_microbenchmark": record.get("benchmark_id", profile_id),
                "api_family": "membrane",
                "symbol": benchmark,
                "runtime_mode": mode,
                "replacement_level": "internal-control-plane",
                "profile_tool": "criterion+profile_pipeline",
                "sample_count": int(record.get("sample_count", 0) or 0),
                "hotness_score": membrane_hotness(record),
                "baseline_artifact": {
                    "path": "tests/conformance/membrane_overhead_baseline.v1.json",
                    "benchmark_id": record.get("benchmark_id"),
                    "runtime_mode": mode,
                    "p50_ns": record.get("latency_ns"),
                    "target_p50_ns": threshold,
                    "present": True,
                },
                "parity_proof_refs": parity_refs(root, "membrane", benchmark),
                "host_baseline": no_host_equivalent("membrane validation stages have no host-glibc equivalent"),
                "coverage_state": "measured",
                "artifact_refs": artifact_refs,
                "failure_signature": record.get("failure_signature") or "none",
                "rank_inputs": {
                    "decision": record.get("decision"),
                    "validation_path": record.get("validation_path"),
                    "variance": record.get("variance", {}),
                },
            }
        )
    return rows


def symbol_profile_records(root: Path, latency: dict[str, object]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for symbol_row in latency.get("symbols", []):
        if not isinstance(symbol_row, dict):
            continue
        module = str(symbol_row.get("module", "unknown"))
        family = family_for_module(module)
        if family == "unknown":
            continue
        symbol = str(symbol_row.get("symbol", ""))
        if not symbol:
            continue
        for mode in REQUIRED_MODES:
            if not latency_mode_measured(symbol_row, mode):
                continue
            profile_id = f"{family}:{mode}:{symbol}"
            artifact_refs = sorted(
                set(
                    [
                        "scripts/profile_pipeline.sh",
                        "tests/conformance/symbol_latency_baseline.v1.json",
                        "tests/conformance/symbol_latency_capture_map.v1.json",
                    ]
                    + parity_refs(root, family, symbol)
                )
            )
            baseline_artifact = latency_baseline_artifact(symbol_row, mode)
            rows.append(
                {
                    "profile_id": profile_id,
                    "workload_or_microbenchmark": baseline_artifact["source"] or profile_id,
                    "api_family": family,
                    "symbol": symbol,
                    "runtime_mode": mode,
                    "replacement_level": replacement_level(symbol_row, family),
                    "profile_tool": "symbol_latency_capture+profile_pipeline",
                    "sample_count": 1,
                    "hotness_score": latency_hotness(symbol_row, mode),
                    "baseline_artifact": baseline_artifact,
                    "parity_proof_refs": parity_refs(root, family, symbol),
                    "host_baseline": host_baseline_from_symbol(symbol_row, mode),
                    "coverage_state": "measured",
                    "artifact_refs": artifact_refs,
                    "failure_signature": "none",
                    "rank_inputs": {
                        "capture_priority_score": symbol_row.get("capture_priority_score"),
                        "perf_class": symbol_row.get("perf_class"),
                        "fixture_covered": symbol_row.get("fixture_covered"),
                    },
                }
            )
    return rows


def gap_profile_record(root: Path, row: dict[str, object]) -> dict[str, object]:
    family = str(row.get("api_family", "unknown"))
    symbol = str(row.get("symbol", "unknown"))
    mode = str(row.get("runtime_mode", "unknown"))
    profile_id = f"{family}:{mode}:{symbol}:missing"
    benchmark = row.get("current_benchmark", {})
    benchmark_id = benchmark.get("benchmark_id") if isinstance(benchmark, dict) else row.get("benchmark_id")
    artifact_refs = sorted(
        set(
            [str(ref) for ref in row.get("artifact_refs", []) if isinstance(ref, str)]
            + [
                "scripts/profile_pipeline.sh",
                "tests/conformance/benchmark_coverage_inventory.v1.json",
            ]
            + parity_refs(root, family, symbol)
        )
    )
    return {
        "profile_id": profile_id,
        "workload_or_microbenchmark": benchmark_id or f"{family}/<missing>",
        "api_family": family,
        "symbol": symbol,
        "runtime_mode": mode,
        "replacement_level": row.get("replacement_level", "L0-interpose"),
        "profile_tool": "benchmark_inventory_gap+profile_pipeline",
        "sample_count": 0,
        "hotness_score": gap_hotness(row),
        "baseline_artifact": {
            "path": "tests/conformance/benchmark_coverage_inventory.v1.json",
            "benchmark_id": benchmark_id,
            "runtime_mode": mode,
            "present": False,
            "missing_benchmark_reason": row.get("missing_benchmark_reason"),
        },
        "parity_proof_refs": parity_refs(root, family, symbol),
        "host_baseline": no_host_equivalent("host comparison is blocked until the profile/baseline slot is captured"),
        "coverage_state": "missing_profile",
        "artifact_refs": artifact_refs,
        "failure_signature": row.get("failure_signature") or f"missing_profile:{family}:{symbol}:{mode}",
        "rank_inputs": {
            "missing_benchmark_reason": row.get("missing_benchmark_reason"),
            "user_workload_exposure": row.get("user_workload_exposure", {}),
        },
    }


def gap_profile_records(root: Path, inventory: dict[str, object]) -> list[dict[str, object]]:
    candidates = [
        row
        for row in inventory.get("inventory_rows", [])
        if isinstance(row, dict)
        and row.get("owner_bead") == BEAD_ID
        and row.get("coverage_state") != "covered"
        and row.get("runtime_mode") in REQUIRED_MODES
    ]
    candidates.sort(
        key=lambda row: (
            -gap_hotness(row),
            str(row.get("api_family", "")),
            str(row.get("symbol", "")),
            str(row.get("runtime_mode", "")),
        )
    )
    return [gap_profile_record(root, row) for row in candidates[:MAX_GAP_RECORDS]]


def sort_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(
        records,
        key=lambda row: (
            -float(row["hotness_score"]),
            str(row["api_family"]),
            str(row["symbol"]),
            str(row["runtime_mode"]),
            str(row["profile_id"]),
        ),
    )


def validate_profile_records(records: list[dict[str, object]]) -> None:
    errors: list[str] = []
    seen: set[str] = set()
    last_score: float | None = None
    for record in records:
        profile_id = str(record.get("profile_id", "<unknown>"))
        missing = [field for field in REQUIRED_PROFILE_FIELDS if field not in record]
        if missing:
            errors.append(f"{profile_id}: missing profile fields {missing}")
        if profile_id in seen:
            errors.append(f"duplicate profile_id: {profile_id}")
        seen.add(profile_id)
        score = record.get("hotness_score")
        if not isinstance(score, (int, float)) or float(score) < 0.0:
            errors.append(f"{profile_id}: hotness_score must be a non-negative number")
        elif last_score is not None and float(score) > last_score:
            errors.append(f"{profile_id}: records are not sorted by descending hotness_score")
        if isinstance(score, (int, float)):
            last_score = float(score)
        if record.get("runtime_mode") not in REQUIRED_MODES:
            errors.append(f"{profile_id}: invalid runtime_mode")
        if not isinstance(record.get("baseline_artifact"), dict):
            errors.append(f"{profile_id}: baseline_artifact must be an object")
        if not isinstance(record.get("host_baseline"), dict):
            errors.append(f"{profile_id}: host_baseline must be an object")
        refs = record.get("parity_proof_refs")
        if not isinstance(refs, list) or not refs:
            errors.append(f"{profile_id}: parity_proof_refs must be non-empty")
        artifacts = record.get("artifact_refs")
        if not isinstance(artifacts, list) or not artifacts:
            errors.append(f"{profile_id}: artifact_refs must be non-empty")
        sample_count = record.get("sample_count")
        if not isinstance(sample_count, int) or sample_count < 0:
            errors.append(f"{profile_id}: sample_count must be a non-negative integer")
        if record.get("coverage_state") == "measured" and sample_count == 0:
            errors.append(f"{profile_id}: measured records need samples")
    if errors:
        raise HotPathProfileError("; ".join(errors))


def event_for_record(
    record: dict[str, object],
    commit: str,
    target_dir: str,
    elapsed_ns: int,
) -> dict[str, object]:
    baseline = record.get("baseline_artifact", {})
    baseline_ref = baseline.get("path") if isinstance(baseline, dict) else None
    return {
        "trace_id": f"{BEAD_ID}:{record['profile_id']}",
        "bead_id": BEAD_ID,
        "profile_id": record["profile_id"],
        "api_family": record["api_family"],
        "symbol": record["symbol"],
        "runtime_mode": record["runtime_mode"],
        "hotness_score": record["hotness_score"],
        "baseline_ref": baseline_ref or "unknown",
        "artifact_refs": record["artifact_refs"],
        "source_commit": commit,
        "target_dir": target_dir,
        "failure_signature": record["failure_signature"],
        "event": "hot_path_profile_ranked",
        "elapsed_ns": elapsed_ns,
        "profile_tool": record["profile_tool"],
        "sample_count": record["sample_count"],
    }


def build_report(root: Path, target_dir: str) -> tuple[dict[str, object], list[dict[str, object]]]:
    start = time.perf_counter_ns()
    inventory = load_json(root / INPUT_PATHS["benchmark_coverage_inventory"])
    membrane = load_json(root / INPUT_PATHS["membrane_overhead_baseline"])
    latency = load_json(root / INPUT_PATHS["symbol_latency_baseline"])
    perf_baseline = load_json(root / INPUT_PATHS["perf_baseline"])
    load_json(root / INPUT_PATHS["perf_baseline_spec"])
    load_json(root / INPUT_PATHS["optimization_proof_ledger"])

    records = sort_records(
        membrane_profile_records(root, membrane)
        + symbol_profile_records(root, latency)
        + gap_profile_records(root, inventory)
    )
    validate_profile_records(records)
    elapsed_ns = time.perf_counter_ns() - start
    commit = source_commit(root)

    measured = [row for row in records if row["coverage_state"] == "measured"]
    missing = [row for row in records if row["coverage_state"] == "missing_profile"]
    host_available = [row for row in records if host_comparison_available(row)]
    host_unavailable = [row for row in records if not host_comparison_available(row)]
    membrane_over_target = [
        row
        for row in records
        if row["api_family"] == "membrane"
        and row["baseline_artifact"].get("target_p50_ns")
        and row["baseline_artifact"].get("p50_ns")
        and float(row["baseline_artifact"]["p50_ns"]) > float(row["baseline_artifact"]["target_p50_ns"])
    ]
    families = sorted({str(row["api_family"]) for row in records})

    report = {
        "schema_version": SCHEMA_VERSION,
        "bead": BEAD_ID,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_commit": commit,
        "purpose": "Rank the next optimization targets from measured hot-path profiles, host raw baselines, and missing profile slots.",
        "inputs": INPUT_PATHS,
        "input_digests": input_digests(root),
        "required_profile_fields": REQUIRED_PROFILE_FIELDS,
        "required_log_fields": REQUIRED_LOG_FIELDS,
        "summary": {
            "profile_record_count": len(records),
            "measured_profile_record_count": len(measured),
            "missing_profile_record_count": len(missing),
            "families": families,
            "host_comparison_available_count": len(host_available),
            "host_comparison_limited_count": len(host_unavailable),
            "parity_proofed_record_count": sum(1 for row in records if row["parity_proof_refs"]),
            "top_hotness_score": records[0]["hotness_score"] if records else 0.0,
            "top_hot_paths": [
                {
                    "profile_id": row["profile_id"],
                    "api_family": row["api_family"],
                    "symbol": row["symbol"],
                    "runtime_mode": row["runtime_mode"],
                    "hotness_score": row["hotness_score"],
                    "failure_signature": row["failure_signature"],
                }
                for row in records[:10]
            ],
            "membrane_over_target_record_count": len(membrane_over_target),
            "missing_inventory_rows_sampled": len(missing),
            "runtime_math_decide_p50_ns": perf_baseline.get("baseline_p50_ns_op", {})
            .get("runtime_math", {})
            .get("strict", {})
            .get("decide"),
        },
        "profile_record_contract": {
            "description": "Every row is either measured profile evidence or a missing profile slot ranked for capture.",
            "required_fields": REQUIRED_PROFILE_FIELDS,
            "stale_rejection": "input_digests and normalized artifact comparison must match current source artifacts",
            "ranking": "descending hotness_score, then family, symbol, mode, profile_id",
            "parity_policy": "No optimization target is accepted without at least one fixture or proof reference.",
        },
        "host_comparison_limits": [
            {
                "scope": "membrane",
                "limit": "TSM validation stages have no host-glibc analogue; host comparison starts at symbol-level raw rows.",
            },
            {
                "scope": "missing_profile_rows",
                "limit": "Raw host baselines are unavailable until the symbol or benchmark slot is captured.",
            },
        ],
        "deterministic_profiling_scripts": [
            {
                "script": "scripts/profile_pipeline.sh",
                "strict_command": "MODE=strict PROFILE_TIME=2 scripts/profile_pipeline.sh",
                "hardened_command": "MODE=hardened PROFILE_TIME=2 scripts/profile_pipeline.sh",
                "emits": [
                    "target/profiles/<run>/<mode>/profile_report.v1.json",
                    "target/profiles/<run>/<mode>/hotspot_opportunity_matrix.v1.json",
                ],
            },
            {
                "script": "scripts/generate_hot_path_profile_report.py",
                "check_command": f"python3 scripts/generate_hot_path_profile_report.py --check --output {PROFILE_REPORT_PATH}",
                "emits": [PROFILE_REPORT_PATH, "target/conformance/hot_path_profile_report.log.jsonl"],
            },
        ],
        "optimization_beads_to_create": [
            {
                "title": "Reduce full membrane validate_* entrypoint p50 before expanding hardened defaults",
                "seed_profiles": [
                    row["profile_id"]
                    for row in membrane_over_target
                    if str(row["symbol"]).startswith("validate_")
                ][:6],
            },
            {
                "title": "Capture and optimize missing strict/hardened string and malloc profile slots",
                "seed_profiles": [
                    row["profile_id"]
                    for row in missing
                    if row["api_family"] in {"string", "malloc"}
                ][:8],
            },
            {
                "title": "Split pthread thread churn from condvar/mutex fast paths under raw host comparison",
                "seed_profiles": [
                    row["profile_id"]
                    for row in records
                    if row["api_family"] == "pthread" and row["coverage_state"] == "measured"
                ][:8],
            },
            {
                "title": "Add syscall benchmark suite before syscall hot-path optimization",
                "seed_profiles": [
                    row["profile_id"]
                    for row in missing
                    if row["api_family"] == "syscall"
                ][:8],
            },
        ],
        "profile_records": records,
        "closure_evidence": {
            "generator": "scripts/generate_hot_path_profile_report.py",
            "gate": "scripts/check_hot_path_profile_report.sh",
            "committed_artifact": PROFILE_REPORT_PATH,
            "target_report": "target/conformance/hot_path_profile_report.report.json",
            "target_log": "target/conformance/hot_path_profile_report.log.jsonl",
        },
    }
    attach_artifact_hash(report)
    events = [event_for_record(row, commit, target_dir, elapsed_ns) for row in records[:TOP_LOG_RECORDS]]
    return report, events


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def fake_profile(profile_id: str, score: float = 1.0) -> dict[str, object]:
    return {
        "profile_id": profile_id,
        "workload_or_microbenchmark": "synthetic",
        "api_family": "string",
        "symbol": profile_id,
        "runtime_mode": "strict",
        "replacement_level": "L1-native-rust",
        "profile_tool": "synthetic",
        "sample_count": 1,
        "hotness_score": score,
        "baseline_artifact": {"path": "synthetic.json", "present": True},
        "parity_proof_refs": ["tests/conformance/fixtures/string_ops.json"],
        "host_baseline": {"available": True, "p50_ns": 1.0},
        "coverage_state": "measured",
        "artifact_refs": ["synthetic.json"],
        "failure_signature": "none",
    }


def self_test() -> None:
    sorted_rows = sort_records(
        [
            fake_profile("z-low", 10.0),
            fake_profile("a-high", 20.0),
            fake_profile("b-high", 20.0),
        ]
    )
    assert [row["profile_id"] for row in sorted_rows] == ["a-high", "b-high", "z-low"]
    validate_profile_records(sorted_rows)

    duplicate = [fake_profile("dup", 2.0), fake_profile("dup", 1.0)]
    try:
        validate_profile_records(duplicate)
    except HotPathProfileError as exc:
        assert "duplicate profile_id" in str(exc)
    else:
        raise AssertionError("duplicate profile_id was not rejected")

    missing_parity = [fake_profile("missing-parity")]
    missing_parity[0]["parity_proof_refs"] = []
    try:
        validate_profile_records(missing_parity)
    except HotPathProfileError as exc:
        assert "parity_proof_refs" in str(exc)
    else:
        raise AssertionError("missing parity proof refs were not rejected")

    generated = {"schema_version": SCHEMA_VERSION, "input_digests": {"a": "new"}}
    attach_artifact_hash(generated)
    stale = deepcopy(generated)
    stale["input_digests"]["a"] = "old"
    attach_artifact_hash(stale)
    assert not reports_match(generated, stale), "stale profile artifact was not rejected"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--output", help="report output path")
    parser.add_argument("--log", help="JSONL event log output path")
    parser.add_argument(
        "--target-dir",
        default="target/conformance",
        help="target dir label stored in structured log rows",
    )
    parser.add_argument("--check", action="store_true", help="Compare generated report to --output")
    parser.add_argument("--self-test", action="store_true", help="Run generator unit self-tests")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    root = repo_root()
    try:
        report, events = build_report(root, args.target_dir)
    except HotPathProfileError as exc:
        raise SystemExit(f"hot-path profile report input error: {exc}") from exc

    output_path = (
        root / args.output
        if args.output and not Path(args.output).is_absolute()
        else Path(args.output) if args.output else None
    )
    if args.check:
        if output_path is None:
            raise SystemExit("--check requires --output")
        try:
            current = load_json(output_path)
        except HotPathProfileError as exc:
            raise SystemExit(f"hot-path profile report check failed: {exc}") from exc
        if not isinstance(current, dict) or not reports_match(report, current):
            print(f"ERROR: {output_path} is stale; regenerate with {Path(__file__).name}", file=sys.stderr)
            raise SystemExit(1)
        return

    if output_path is not None:
        write_json(output_path, report)
    else:
        print(json.dumps(report, indent=2, sort_keys=False))

    if args.log:
        log_path = root / args.log if not Path(args.log).is_absolute() else Path(args.log)
        write_jsonl(log_path, events)


if __name__ == "__main__":
    main()
