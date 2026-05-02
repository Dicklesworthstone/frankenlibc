#!/usr/bin/env python3
"""Generate per-family fixture coverage thresholds for bd-bp8fl.4.3.

The artifact is intentionally a claim gate, not a scorecard. Low coverage is
expected today, but every exported family must have a visible threshold record
that explains whether current evidence is enough for readiness claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any


BEAD_ID = "bd-bp8fl.4.3"
SCHEMA_VERSION = "v1"
TARGET_STATUSES = {"Implemented", "RawSyscall"}
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "family_id",
    "threshold_id",
    "expected_coverage",
    "actual_coverage",
    "decision",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]

INPUT_PATHS = {
    "support_matrix": "support_matrix.json",
    "conformance_coverage_snapshot": "tests/conformance/conformance_coverage_snapshot.v1.json",
    "conformance_coverage_baseline": "tests/conformance/conformance_coverage_baseline.v1.json",
    "symbol_fixture_coverage": "tests/conformance/symbol_fixture_coverage.v1.json",
    "per_symbol_fixture_tests": "tests/conformance/per_symbol_fixture_tests.v1.json",
    "fixture_coverage_prioritizer": "tests/conformance/fixture_coverage_prioritizer.v1.json",
    "user_workload_acceptance_matrix": "tests/conformance/user_workload_acceptance_matrix.v1.json",
    "workload_matrix": "tests/conformance/workload_matrix.json",
    "hard_parts_truth_table": "tests/conformance/hard_parts_truth_table.v1.json",
    "hard_parts_e2e_failure_matrix": "tests/conformance/hard_parts_e2e_failure_matrix.v1.json",
    "replacement_levels": "tests/conformance/replacement_levels.json",
}

HARD_PART_MODULES = {
    "startup": {"startup_abi", "process_abi", "dlfcn_abi"},
    "threading": {"pthread_abi"},
    "resolver": {"resolv_abi"},
    "nss": {"pwd_abi", "grp_abi", "resolv_abi"},
    "locale": {"locale_abi", "wchar_abi"},
    "iconv": {"iconv_abi", "wchar_abi"},
}


class ThresholdInputError(ValueError):
    """Raised when source artifacts cannot support trustworthy thresholds."""


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ThresholdInputError(f"failed to read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ThresholdInputError(f"invalid JSON in {path}: {exc}") from exc


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ThresholdInputError(f"failed to hash {path}: {exc}") from exc


def _pct(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 100.0
    return round((numerator * 100.0) / denominator, 2)


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _current_commit(repo_root: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def _rows_by_symbol(rows: list[dict[str, Any]], source: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
    out: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    for row in rows:
        symbol = row.get("symbol")
        if not isinstance(symbol, str) or not symbol:
            continue
        if symbol in out:
            duplicates.append(f"{source}:{symbol}")
        out[symbol] = row
    return out, duplicates


def _status_target(row: dict[str, Any]) -> bool:
    return str(row.get("status", "")) in TARGET_STATUSES


def _json_true(value: Any) -> bool:
    return isinstance(value, bool) and value


def _module_for_hard_part(module: str) -> list[str]:
    return sorted(name for name, modules in HARD_PART_MODULES.items() if module in modules)


def _campaign_index(prioritizer: dict[str, Any]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for campaign in prioritizer.get("campaigns", []):
        module = campaign.get("module")
        if isinstance(module, str) and module:
            indexed[module] = campaign
    for deferred in prioritizer.get("deferred_modules", []):
        module = deferred.get("module")
        if isinstance(module, str) and module and module not in indexed:
            indexed[module] = deferred
    return indexed


def _regression_findings(
    snapshot: dict[str, Any], baseline: dict[str, Any]
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    snap_summary = snapshot.get("summary", {})
    base_summary = baseline.get("summary", {})
    summary_checks = [
        ("total_fixture_files", "fixture_file_count"),
        ("total_fixture_cases", "fixture_case_count"),
        ("coverage_pct", "coverage_pct"),
    ]
    for field, category in summary_checks:
        actual = snap_summary.get(field, 0)
        expected = base_summary.get(field, 0)
        if isinstance(actual, (int, float)) and isinstance(expected, (int, float)) and actual < expected:
            findings.append(
                {
                    "category": category,
                    "expected": expected,
                    "actual": actual,
                    "failure_signature": f"regression:{field}:{actual}<baseline:{expected}",
                }
            )

    snap_modules = snapshot.get("module_coverage", {})
    base_modules = baseline.get("module_coverage", {})
    for module, base_row in sorted(base_modules.items()):
        snap_row = snap_modules.get(module, {})
        actual = int(snap_row.get("covered", 0))
        expected = int(base_row.get("covered", 0))
        if actual < expected:
            findings.append(
                {
                    "category": "module_coverage",
                    "module": module,
                    "expected": expected,
                    "actual": actual,
                    "failure_signature": f"regression:{module}:covered:{actual}<baseline:{expected}",
                }
            )
    return findings


def _validate_inputs(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    support_symbols = data["support_matrix"].get("symbols", [])
    symbol_rows = data["symbol_fixture_coverage"].get("symbols", [])
    per_rows = data["per_symbol_fixture_tests"].get("per_symbol_report", [])

    support_by_symbol, support_dupes = _rows_by_symbol(support_symbols, "support_matrix")
    coverage_by_symbol, coverage_dupes = _rows_by_symbol(symbol_rows, "symbol_fixture_coverage")
    per_by_symbol, per_dupes = _rows_by_symbol(per_rows, "per_symbol_fixture_tests")
    for duplicate in support_dupes + coverage_dupes + per_dupes:
        errors.append(f"duplicate symbol row: {duplicate}")

    support_target_modules = {
        str(row.get("module", ""))
        for row in support_symbols
        if isinstance(row, dict) and _status_target(row)
    }
    coverage_modules = {
        str(row.get("module", ""))
        for row in data["symbol_fixture_coverage"].get("families", [])
        if isinstance(row, dict)
    }
    missing_modules = sorted(module for module in support_target_modules if module not in coverage_modules)
    if missing_modules:
        errors.append("missing family rows in symbol_fixture_coverage: " + ",".join(missing_modules))

    missing_coverage_symbols = sorted(
        symbol for symbol in support_by_symbol if symbol not in coverage_by_symbol
    )
    if missing_coverage_symbols:
        errors.append(
            "symbol_fixture_coverage missing support symbols: "
            + ",".join(missing_coverage_symbols[:10])
        )

    missing_per_symbol = sorted(symbol for symbol in support_by_symbol if symbol not in per_by_symbol)
    if missing_per_symbol:
        errors.append(
            "per_symbol_fixture_tests missing support symbols: "
            + ",".join(missing_per_symbol[:10])
        )

    support_total = len(support_by_symbol)
    symbol_total = int(
        data["symbol_fixture_coverage"].get("summary", {}).get("total_exported_symbols", -1)
    )
    per_total = int(data["per_symbol_fixture_tests"].get("summary", {}).get("total_symbols", -1))
    snapshot_total = int(data["conformance_coverage_snapshot"].get("summary", {}).get("total_symbols", -1))
    if len({support_total, symbol_total, per_total, snapshot_total}) != 1:
        errors.append(
            "stale symbol universe totals: "
            f"support={support_total} symbol_fixture={symbol_total} "
            f"per_symbol={per_total} snapshot={snapshot_total}"
        )

    fixture_json_files = int(
        data["symbol_fixture_coverage"].get("fixture_inventory", {}).get("fixture_json_files", -1)
    )
    per_fixture_files = int(
        data["per_symbol_fixture_tests"].get("summary", {}).get("total_fixture_files", -1)
    )
    snapshot_fixture_files = int(
        data["conformance_coverage_snapshot"].get("summary", {}).get("total_fixture_files", -1)
    )
    if len({fixture_json_files, per_fixture_files, snapshot_fixture_files}) != 1:
        errors.append(
            "stale fixture inventory totals: "
            f"symbol_fixture={fixture_json_files} per_symbol={per_fixture_files} "
            f"snapshot={snapshot_fixture_files}"
        )

    for finding in _regression_findings(
        data["conformance_coverage_snapshot"], data["conformance_coverage_baseline"]
    ):
        errors.append(finding["failure_signature"])

    return errors


def _thresholds_for(
    family: dict[str, Any], campaign: dict[str, Any] | None, hard_parts: list[str]
) -> dict[str, Any]:
    target_total = int(family.get("target_total", 0))
    if target_total == 0:
        return {
            "min_target_coverage_pct": 0.0,
            "min_direct_coverage_pct": 0.0,
            "min_isolated_coverage_pct": 0.0,
            "min_dual_mode_coverage_pct": 0.0,
            "reason": "no Implemented/RawSyscall target symbols in this family",
        }

    workload_count = int(family.get("workload_blocked_count", 0))
    rank = int(campaign.get("rank", 9999)) if campaign else 9999
    risk_tag_count = len(campaign.get("risk_tags", [])) if campaign else 0

    min_target = 80.0
    min_direct = 25.0
    min_isolated = 10.0
    min_dual = 10.0
    reasons = ["base threshold: weak target families must reach 80% coverage"]

    if target_total <= 4:
        min_target = max(min_target, 100.0)
        min_direct = max(min_direct, 50.0)
        reasons.append("small family: require complete target coverage before readiness")
    if hard_parts:
        min_target = max(min_target, 90.0)
        min_direct = max(min_direct, 40.0)
        min_isolated = max(min_isolated, 20.0)
        min_dual = max(min_dual, 20.0)
        reasons.append("hard-parts family: higher direct, isolated, and dual-mode proof")
    if workload_count >= 4:
        min_target = max(min_target, 90.0)
        min_direct = max(min_direct, 50.0)
        min_isolated = max(min_isolated, 20.0)
        min_dual = max(min_dual, 20.0)
        reasons.append("high user-workload exposure")
    if rank <= 5 or risk_tag_count >= 4:
        min_target = max(min_target, 85.0)
        min_dual = max(min_dual, 15.0)
        reasons.append("prioritizer risk score selected this family for first-wave attention")

    return {
        "min_target_coverage_pct": min_target,
        "min_direct_coverage_pct": min_direct,
        "min_isolated_coverage_pct": min_isolated,
        "min_dual_mode_coverage_pct": min_dual,
        "reason": "; ".join(reasons),
    }


def _family_record(
    family: dict[str, Any],
    symbols: list[dict[str, Any]],
    per_symbol: dict[str, dict[str, Any]],
    campaign: dict[str, Any] | None,
    hard_parts: list[str],
    input_paths: dict[str, str],
) -> dict[str, Any]:
    module = str(family.get("module", "unknown"))
    target_symbols = [row for row in symbols if _status_target(row)]
    covered_symbols = [row for row in target_symbols if _json_true(row.get("covered"))]
    direct_symbols = [
        row for row in target_symbols if "fixture_json" in row.get("fixture_sources", [])
    ]
    isolated_symbols = [
        row for row in target_symbols if "c_fixture_spec" in row.get("fixture_sources", [])
    ]
    strict_symbols = [
        row
        for row in target_symbols
        if {"strict", "both"}.intersection(set(row.get("fixture_modes", [])))
    ]
    hardened_symbols = [
        row
        for row in target_symbols
        if {"hardened", "both"}.intersection(set(row.get("fixture_modes", [])))
    ]
    strict_names = {row["symbol"] for row in strict_symbols}
    hardened_names = {row["symbol"] for row in hardened_symbols}
    dual_names = strict_names & hardened_names

    fixture_files = sorted(
        {
            file
            for row in target_symbols
            for file in row.get("fixture_files", [])
            if isinstance(file, str)
        }
    )
    fixture_ids = sorted(
        {
            fixture_id
            for row in target_symbols
            for fixture_id in row.get("fixture_ids", [])
            if isinstance(fixture_id, str)
        }
    )
    fixture_case_count = sum(int(row.get("fixture_case_count", 0)) for row in target_symbols)
    c_fixture_mentions = sum(int(row.get("c_fixture_mentions", 0)) for row in target_symbols)
    edge_case_symbols = sum(
        1
        for row in target_symbols
        if per_symbol.get(row["symbol"], {}).get("edge_cases_covered")
    )
    errno_symbols = sum(
        1
        for row in target_symbols
        if _json_true(per_symbol.get(row["symbol"], {}).get("has_errno_check"))
    )

    target_total = len(target_symbols)
    target_covered = len(covered_symbols)
    thresholds = _thresholds_for(family, campaign, hard_parts)
    coverage = {
        "target_coverage_pct": _pct(target_covered, target_total),
        "direct_coverage_pct": _pct(len(direct_symbols), target_total),
        "isolated_coverage_pct": _pct(len(isolated_symbols), target_total),
        "strict_mode_coverage_pct": _pct(len(strict_symbols), target_total),
        "hardened_mode_coverage_pct": _pct(len(hardened_symbols), target_total),
        "dual_mode_coverage_pct": _pct(len(dual_names), target_total),
        "edge_case_symbol_pct": _pct(edge_case_symbols, target_total),
        "errno_check_symbol_pct": _pct(errno_symbols, target_total),
        "l0_replacement_pct": _pct(target_covered, target_total),
        "l1_replacement_pct": _pct(len(dual_names), target_total),
        "l2_replacement_pct": 0.0,
        "l3_replacement_pct": 0.0,
    }

    failures = []
    checks = [
        ("target", "min_target_coverage_pct", "target_coverage_pct"),
        ("direct", "min_direct_coverage_pct", "direct_coverage_pct"),
        ("isolated", "min_isolated_coverage_pct", "isolated_coverage_pct"),
        ("dual_mode", "min_dual_mode_coverage_pct", "dual_mode_coverage_pct"),
    ]
    for label, threshold_key, actual_key in checks:
        if coverage[actual_key] < float(thresholds[threshold_key]):
            failures.append(
                f"{label}:{coverage[actual_key]}<threshold:{thresholds[threshold_key]}"
            )

    if target_total == 0:
        decision = "not_applicable"
        failure_signature = "none"
    elif failures:
        decision = "fail"
        failure_signature = "coverage_threshold:" + "|".join(failures)
    else:
        decision = "pass"
        failure_signature = "none"

    risk_tags = []
    workload_domains = []
    rank = None
    if campaign:
        risk_tags = sorted([tag for tag in campaign.get("risk_tags", []) if isinstance(tag, str)])
        workload_domains = sorted(
            [domain for domain in campaign.get("workload_domains", []) if isinstance(domain, str)]
        )
        rank = campaign.get("rank")

    return {
        "family_id": module,
        "threshold_id": f"fct-{module}-v1",
        "track": family.get("track"),
        "symbol_count": {
            "total": int(family.get("total_symbols", 0)),
            "target": target_total,
            "covered": target_covered,
            "uncovered": target_total - target_covered,
        },
        "fixture_count": {
            "fixture_cases": fixture_case_count,
            "fixture_files": len(fixture_files),
            "fixture_file_refs": fixture_files,
            "isolated_fixture_mentions": c_fixture_mentions,
            "isolated_fixture_ids": fixture_ids,
        },
        "coverage": coverage,
        "thresholds": thresholds,
        "mode_coverage": {
            "strict_or_both_symbols": len(strict_symbols),
            "hardened_or_both_symbols": len(hardened_symbols),
            "dual_mode_symbols": len(dual_names),
        },
        "replacement_level_coverage": {
            "L0": {
                "coverage_pct": coverage["l0_replacement_pct"],
                "claim_state": "measured_from_current_fixture_inventory",
            },
            "L1": {
                "coverage_pct": coverage["l1_replacement_pct"],
                "claim_state": "requires strict+hardened fixture evidence",
            },
            "L2": {
                "coverage_pct": 0.0,
                "claim_state": "blocked_until_standalone_host_dependency_evidence",
            },
            "L3": {
                "coverage_pct": 0.0,
                "claim_state": "blocked_until_cross_environment_standalone_evidence",
            },
        },
        "hard_parts_risk": {
            "subsystems": hard_parts,
            "risk_level": "high" if hard_parts else "normal",
            "risk_tags": risk_tags,
        },
        "user_workload_exposure": {
            "blocked_workload_count": int(family.get("workload_blocked_count", 0)),
            "workload_ids": family.get("workload_ids", []),
            "workload_domains": workload_domains,
            "prioritizer_rank": rank,
        },
        "freshness_state": {
            "decision": "fresh",
            "source_artifacts": [
                input_paths["symbol_fixture_coverage"],
                input_paths["per_symbol_fixture_tests"],
                input_paths["conformance_coverage_snapshot"],
            ],
        },
        "decision": decision,
        "failure_signature": failure_signature,
        "artifact_refs": [
            input_paths["symbol_fixture_coverage"],
            input_paths["per_symbol_fixture_tests"],
            input_paths["conformance_coverage_snapshot"],
            input_paths["fixture_coverage_prioritizer"],
        ],
    }


def build_from_data(data: dict[str, Any], input_paths: dict[str, str], input_digests: dict[str, str]) -> dict[str, Any]:
    errors = _validate_inputs(data)
    if errors:
        raise ThresholdInputError("; ".join(errors))

    symbol_rows = data["symbol_fixture_coverage"].get("symbols", [])
    per_by_symbol, _ = _rows_by_symbol(
        data["per_symbol_fixture_tests"].get("per_symbol_report", []),
        "per_symbol_fixture_tests",
    )
    by_module: dict[str, list[dict[str, Any]]] = {}
    for row in symbol_rows:
        module = str(row.get("module", "unknown"))
        by_module.setdefault(module, []).append(row)

    campaigns = _campaign_index(data["fixture_coverage_prioritizer"])
    records = []
    for family in sorted(
        data["symbol_fixture_coverage"].get("families", []),
        key=lambda row: str(row.get("module", "")),
    ):
        module = str(family.get("module", "unknown"))
        records.append(
            _family_record(
                family=family,
                symbols=by_module.get(module, []),
                per_symbol=per_by_symbol,
                campaign=campaigns.get(module),
                hard_parts=_module_for_hard_part(module),
                input_paths=input_paths,
            )
        )

    pass_count = sum(1 for row in records if row["decision"] == "pass")
    fail_count = sum(1 for row in records if row["decision"] == "fail")
    not_applicable_count = sum(1 for row in records if row["decision"] == "not_applicable")
    target_total = sum(row["symbol_count"]["target"] for row in records)
    target_covered = sum(row["symbol_count"]["covered"] for row in records)

    gap_rows = [
        {
            "family_id": row["family_id"],
            "threshold_id": row["threshold_id"],
            "decision": row["decision"],
            "failure_signature": row["failure_signature"],
            "target_uncovered": row["symbol_count"]["uncovered"],
            "next_step": (
                "add direct+isolated dual-mode fixtures before advancing readiness claims"
                if row["decision"] == "fail"
                else "preserve threshold evidence during fixture regeneration"
            ),
        }
        for row in records
        if row["decision"] == "fail"
    ]

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "bead": BEAD_ID,
        "purpose": (
            "Per-family fixture coverage thresholds for exported symbol families. "
            "This artifact records current pass/fail decisions without hiding low-priority gaps."
        ),
        "inputs": input_paths,
        "input_digests": input_digests,
        "required_log_fields": REQUIRED_LOG_FIELDS,
        "coverage_model": {
            "target_statuses": sorted(TARGET_STATUSES),
            "direct_coverage_source": "symbol_fixture_coverage symbols with fixture_sources containing fixture_json",
            "isolated_coverage_source": "symbol_fixture_coverage symbols with fixture_sources containing c_fixture_spec",
            "mode_coverage_rule": "strict_or_both and hardened_or_both both required for dual-mode coverage",
            "replacement_level_rule": {
                "L0": "current fixture coverage",
                "L1": "strict+hardened dual-mode fixture coverage",
                "L2": "blocked until standalone host-dependency evidence exists",
                "L3": "blocked until cross-environment standalone evidence exists",
            },
        },
        "threshold_policy": {
            "base": {
                "min_target_coverage_pct": 80.0,
                "min_direct_coverage_pct": 25.0,
                "min_isolated_coverage_pct": 10.0,
                "min_dual_mode_coverage_pct": 10.0,
            },
            "small_family_adjustment": "families with <=4 target symbols require 100% target coverage",
            "hard_parts_adjustment": "hard-parts families require >=90% target, >=40% direct, >=20% isolated, >=20% dual-mode",
            "workload_adjustment": "families blocking >=4 workloads require >=90% target and >=50% direct coverage",
            "prioritizer_adjustment": "top-5 or high-risk prioritizer families require at least 85% target and 15% dual-mode coverage",
        },
        "summary": {
            "family_count": len(records),
            "pass_count": pass_count,
            "fail_count": fail_count,
            "not_applicable_count": not_applicable_count,
            "target_total_symbols": target_total,
            "target_covered_symbols": target_covered,
            "target_uncovered_symbols": target_total - target_covered,
            "target_coverage_pct": _pct(target_covered, target_total),
            "snapshot_paths": [
                input_paths["conformance_coverage_snapshot"],
                input_paths["symbol_fixture_coverage"],
                input_paths["per_symbol_fixture_tests"],
            ],
            "claim_gate_decision": "blocked" if fail_count else "ready",
        },
        "threshold_records": records,
        "gaps_requiring_fixture_beads": gap_rows,
    }
    artifact["artifact_hash"] = hashlib.sha256(_stable_json(artifact).encode()).hexdigest()
    return artifact


def load_repo_data(repo_root: Path) -> tuple[dict[str, Any], dict[str, str], dict[str, str]]:
    data: dict[str, Any] = {}
    digests: dict[str, str] = {}
    for key, rel in INPUT_PATHS.items():
        path = repo_root / rel
        data[key] = _load_json(path)
        digests[key] = _sha256(path)
    return data, dict(INPUT_PATHS), digests


def generate(repo_root: Path) -> dict[str, Any]:
    data, input_paths, input_digests = load_repo_data(repo_root)
    return build_from_data(data, input_paths, input_digests)


def _synthetic_data() -> tuple[dict[str, Any], dict[str, str], dict[str, str]]:
    support_symbols = [
        {"symbol": "alpha_ok", "module": "alpha_abi", "status": "Implemented"},
        {"symbol": "alpha_edge", "module": "alpha_abi", "status": "RawSyscall"},
        {"symbol": "beta_gap", "module": "beta_abi", "status": "Implemented"},
    ]
    symbol_rows = [
        {
            "symbol": "alpha_ok",
            "module": "alpha_abi",
            "status": "Implemented",
            "covered": True,
            "fixture_sources": ["fixture_json", "c_fixture_spec"],
            "fixture_modes": ["both"],
            "fixture_case_count": 3,
            "c_fixture_mentions": 1,
            "fixture_files": ["alpha.json"],
            "fixture_ids": ["alpha-c"],
        },
        {
            "symbol": "alpha_edge",
            "module": "alpha_abi",
            "status": "RawSyscall",
            "covered": True,
            "fixture_sources": ["fixture_json", "c_fixture_spec"],
            "fixture_modes": ["strict", "hardened"],
            "fixture_case_count": 4,
            "c_fixture_mentions": 1,
            "fixture_files": ["alpha.json"],
            "fixture_ids": ["alpha-c"],
        },
        {
            "symbol": "beta_gap",
            "module": "beta_abi",
            "status": "Implemented",
            "covered": False,
            "fixture_sources": [],
            "fixture_modes": [],
            "fixture_case_count": 0,
            "c_fixture_mentions": 0,
            "fixture_files": [],
            "fixture_ids": [],
        },
    ]
    data = {
        "support_matrix": {"symbols": support_symbols},
        "symbol_fixture_coverage": {
            "summary": {"total_exported_symbols": 3},
            "fixture_inventory": {"fixture_json_files": 2},
            "families": [
                {
                    "module": "alpha_abi",
                    "track": "alpha",
                    "total_symbols": 2,
                    "target_total": 2,
                    "target_covered": 2,
                    "target_uncovered": 0,
                    "workload_blocked_count": 0,
                    "workload_ids": [],
                },
                {
                    "module": "beta_abi",
                    "track": "beta",
                    "total_symbols": 1,
                    "target_total": 1,
                    "target_covered": 0,
                    "target_uncovered": 1,
                    "workload_blocked_count": 5,
                    "workload_ids": ["wl-beta"],
                },
            ],
            "symbols": symbol_rows,
        },
        "per_symbol_fixture_tests": {
            "summary": {"total_symbols": 3, "total_fixture_files": 2},
            "per_symbol_report": [
                {
                    "symbol": "alpha_ok",
                    "edge_cases_covered": ["zero_length"],
                    "has_errno_check": True,
                },
                {
                    "symbol": "alpha_edge",
                    "edge_cases_covered": ["boundary"],
                    "has_errno_check": True,
                },
                {"symbol": "beta_gap", "edge_cases_covered": [], "has_errno_check": False},
            ],
        },
        "conformance_coverage_snapshot": {
            "summary": {
                "total_symbols": 3,
                "total_fixture_files": 2,
                "total_fixture_cases": 7,
                "coverage_pct": 67,
            },
            "module_coverage": {
                "alpha_abi": {"covered": 2},
                "beta_abi": {"covered": 0},
            },
        },
        "conformance_coverage_baseline": {
            "summary": {
                "total_symbols": 3,
                "total_fixture_files": 1,
                "total_fixture_cases": 2,
                "coverage_pct": 30,
            },
            "module_coverage": {
                "alpha_abi": {"covered": 1},
                "beta_abi": {"covered": 0},
            },
        },
        "fixture_coverage_prioritizer": {
            "campaigns": [
                {
                    "module": "beta_abi",
                    "rank": 1,
                    "risk_tags": ["semantic_divergence", "mode_pair_mismatch"],
                    "workload_domains": ["shell_coreutils"],
                }
            ],
            "deferred_modules": [{"module": "alpha_abi"}],
        },
        "user_workload_acceptance_matrix": {},
        "workload_matrix": {},
        "hard_parts_truth_table": {"subsystems": []},
        "hard_parts_e2e_failure_matrix": {"classes": []},
        "replacement_levels": {"levels": []},
    }
    input_paths = {key: f"synthetic/{key}.json" for key in INPUT_PATHS}
    input_digests = {key: hashlib.sha256(key.encode()).hexdigest() for key in INPUT_PATHS}
    return data, input_paths, input_digests


def self_test() -> None:
    data, paths, digests = _synthetic_data()
    artifact = build_from_data(data, paths, digests)
    records = {row["family_id"]: row for row in artifact["threshold_records"]}
    assert records["alpha_abi"]["decision"] == "pass"
    assert records["beta_abi"]["decision"] == "fail"
    assert artifact["summary"]["fail_count"] == 1

    first = _stable_json(artifact)
    second = _stable_json(build_from_data(deepcopy(data), paths, digests))
    assert first == second, "generation must be deterministic"

    stale = deepcopy(data)
    stale["conformance_coverage_snapshot"]["summary"]["total_symbols"] = 2
    try:
        build_from_data(stale, paths, digests)
    except ThresholdInputError as exc:
        assert "stale symbol universe totals" in str(exc)
    else:
        raise AssertionError("stale snapshot was not rejected")

    missing_family = deepcopy(data)
    missing_family["symbol_fixture_coverage"]["families"] = [
        row
        for row in missing_family["symbol_fixture_coverage"]["families"]
        if row["module"] != "beta_abi"
    ]
    try:
        build_from_data(missing_family, paths, digests)
    except ThresholdInputError as exc:
        assert "missing family rows" in str(exc)
    else:
        raise AssertionError("missing family row was not rejected")

    duplicate = deepcopy(data)
    duplicate["per_symbol_fixture_tests"]["per_symbol_report"].append(
        {"symbol": "alpha_ok", "edge_cases_covered": [], "has_errno_check": False}
    )
    try:
        build_from_data(duplicate, paths, digests)
    except ThresholdInputError as exc:
        assert "duplicate symbol row" in str(exc)
    else:
        raise AssertionError("duplicate per-symbol row was not rejected")

    regression = deepcopy(data)
    regression["conformance_coverage_baseline"]["summary"]["coverage_pct"] = 90
    try:
        build_from_data(regression, paths, digests)
    except ThresholdInputError as exc:
        assert "regression:coverage_pct" in str(exc)
    else:
        raise AssertionError("coverage regression was not rejected")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument(
        "--output",
        default="tests/conformance/family_coverage_thresholds.v1.json",
        help="Output artifact path",
    )
    parser.add_argument("--check", action="store_true", help="Compare generated output to --output")
    parser.add_argument("--self-test", action="store_true", help="Run generator self-tests")
    parser.add_argument("--emit-logs", action="store_true", help="Emit JSONL family decisions")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0

    repo_root = Path(args.repo_root).resolve()
    artifact = generate(repo_root)
    output_path = (repo_root / args.output).resolve()

    if args.emit_logs:
        source_commit = _current_commit(repo_root)
        for row in artifact["threshold_records"]:
            print(
                json.dumps(
                    {
                        "trace_id": f"{BEAD_ID}-{artifact['artifact_hash'][:12]}",
                        "bead_id": BEAD_ID,
                        "family_id": row["family_id"],
                        "threshold_id": row["threshold_id"],
                        "expected_coverage": row["thresholds"],
                        "actual_coverage": row["coverage"],
                        "decision": row["decision"],
                        "artifact_refs": row["artifact_refs"],
                        "source_commit": source_commit,
                        "failure_signature": row["failure_signature"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )

    if args.check:
        current = _load_json(output_path)
        if current != artifact:
            print(f"ERROR: {output_path} is stale; regenerate with {Path(__file__).name}", file=sys.stderr)
            return 1
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
