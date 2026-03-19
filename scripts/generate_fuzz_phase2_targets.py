#!/usr/bin/env python3
"""generate_fuzz_phase2_targets.py — bd-1oz.7

Fuzz phase-2 target readiness and nightly-gate report:
  1. Phase-2 target inventory for resolver, locale/iconv, and runtime-math.
  2. Target readiness and smoke-run suitability.
  3. Symbol/family coverage summary.
  4. Nightly crash and risk threshold policy.

Generates a JSON report to stdout (or --output).
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def find_repo_root():
    p = Path(__file__).resolve().parent.parent
    if (p / "Cargo.toml").exists():
        return p
    return Path.cwd()


def load_json_file(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


PHASE2_TARGETS = [
    "fuzz_resolver",
    "fuzz_resolv",
    "fuzz_iconv",
    "fuzz_runtime_math",
]

TARGET_INFO = {
    "fuzz_resolver": {
        "symbols": [
            "res_mkquery",
            "res_send",
            "res_ninit",
            "res_nclose",
        ],
        "family": "resolver",
        "transition_family": "resolver",
        "attack_surface": "dns-packet, name-compression, resolv-conf, parser-state",
        "cwe_targets": ["CWE-20", "CWE-400", "CWE-787"],
    },
    "fuzz_resolv": {
        "symbols": [
            "getaddrinfo",
            "getnameinfo",
            "lookup_hosts",
            "lookup_service",
        ],
        "family": "resolver",
        "transition_family": "resolver",
        "attack_surface": "hosts-services parsing, addrinfo branching, lookup determinism",
        "cwe_targets": ["CWE-20", "CWE-125", "CWE-400"],
    },
    "fuzz_iconv": {
        "symbols": [
            "iconv_open",
            "iconv",
            "iconv_close",
        ],
        "family": "locale",
        "transition_family": "locale",
        "attack_surface": "codec dispatch, invalid descriptors, conversion-state drift",
        "cwe_targets": ["CWE-190", "CWE-400", "CWE-787"],
    },
    "fuzz_runtime_math": {
        "symbols": [
            "runtime_policy::decide",
            "RuntimeMathKernel::decide",
            "RuntimeMathKernel::observe_validation_result",
        ],
        "family": "runtime_math",
        "transition_family": "runtime-math",
        "attack_surface": "mode switching, risk thresholds, controller-state transitions",
        "cwe_targets": ["CWE-670", "CWE-682", "CWE-835"],
    },
}

FAMILY_TO_MODULES = {
    "resolver": ["resolv_abi", "inet_abi"],
    "locale": ["iconv_abi", "locale_abi"],
}


def analyze_target_source(source_path):
    try:
        content = source_path.read_text(encoding="utf-8")
    except OSError:
        return {"error": f"Cannot read {source_path}", "ready": False}

    lines = content.splitlines()
    todos = [line.strip() for line in lines if "TODO" in line]
    uses_frankenlibc = "frankenlibc_" in content or "frankenlibc::" in content
    has_size_guard = bool(re.search(r"len\(\)\.min|len\(\)\s*>|len\(\)\s*<|is_empty\(", content))
    has_iteration = "for " in content or "while " in content
    has_determinism_check = "determin" in content.lower() or "assert_eq!" in content
    has_transition_logic = "observe_validation_result" in content or "match input.op" in content
    logic_lines = len(
        [
            line
            for line in lines
            if line.strip() and not line.strip().startswith("//")
        ]
    )
    ready = has_size_guard and has_iteration and not todos

    return {
        "source_exists": True,
        "total_lines": len(lines),
        "logic_lines": logic_lines,
        "todo_count": len(todos),
        "todos": todos,
        "uses_frankenlibc_crates": uses_frankenlibc,
        "has_size_guard": has_size_guard,
        "has_iteration": has_iteration,
        "has_determinism_check": has_determinism_check,
        "has_transition_logic": has_transition_logic,
        "ready": ready,
    }


def compute_target_coverage(target_name, support_matrix_path):
    target = TARGET_INFO[target_name]
    target_symbols = set(target["symbols"])
    if target["family"] == "runtime_math":
        return {
            "target_symbols": sorted(target_symbols),
            "available_symbols": sorted(target_symbols),
            "covered_count": len(target_symbols),
            "available_count": len(target_symbols),
            "coverage_pct": 100.0,
            "uncovered": [],
        }

    available = set()
    if support_matrix_path.exists():
        matrix = load_json_file(support_matrix_path)
        for entry in matrix.get("symbols", []):
            sym_module = entry.get("module", "")
            sym_name = entry.get("symbol", "")
            if sym_module in FAMILY_TO_MODULES.get(target["family"], []):
                available.add(sym_name)

    covered = target_symbols & available
    coverage_pct = round(len(covered) / len(available) * 100, 1) if available else 0.0
    return {
        "target_symbols": sorted(target_symbols),
        "available_symbols": sorted(available),
        "covered_count": len(covered),
        "available_count": len(available),
        "coverage_pct": coverage_pct,
        "uncovered": sorted(available - target_symbols),
    }


def readiness_score(source_analysis, coverage):
    score = 0
    if source_analysis.get("ready"):
        score += 35
    if source_analysis.get("uses_frankenlibc_crates"):
        score += 20
    if source_analysis.get("has_determinism_check"):
        score += 15
    if source_analysis.get("has_transition_logic"):
        score += 15
    if source_analysis.get("has_size_guard"):
        score += 10
    score += min(coverage.get("covered_count", 0) * 2, 5)
    return min(score, 100)


def build_smoke_test_configs():
    return {
        "fuzz_resolver": {
            "max_total_time_secs": 45,
            "runs": 20000,
            "expected_outcome": "no_crash",
        },
        "fuzz_resolv": {
            "max_total_time_secs": 45,
            "runs": 20000,
            "expected_outcome": "no_crash",
        },
        "fuzz_iconv": {
            "max_total_time_secs": 45,
            "runs": 20000,
            "expected_outcome": "no_crash",
        },
        "fuzz_runtime_math": {
            "max_total_time_secs": 45,
            "runs": 25000,
            "expected_outcome": "no_crash",
        },
    }


def build_nightly_policy():
    return {
        "target_group": "phase2",
        "runs_per_target": 1000000,
        "timeout_seconds": 1800,
        "max_crashes": 0,
        "required_targets": PHASE2_TARGETS,
        "required_transition_families": ["resolver", "locale", "runtime-math"],
        "risk_thresholds": {
            "crash_regression": "fail_on_any_new_crash",
            "missing_target_execution": "fail",
            "missing_transition_family": "fail",
        },
        "coverage_thresholds": {
            "min_phase2_targets": len(PHASE2_TARGETS),
            "min_transition_families": 3,
            "min_symbol_coverage": 10,
        },
        "artifacts": [
            "artifacts/ci/fuzz-runs/*.log",
            "artifacts/ci/fuzz-summary.v1.json",
            "tests/conformance/fuzz_phase2_targets.v1.json",
        ],
    }


def compute_validation_hash(report):
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def main():
    parser = argparse.ArgumentParser(
        description="Phase-2 fuzz target readiness and nightly gate generator"
    )
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()
    fuzz_dir = root / "crates" / "frankenlibc-fuzz" / "fuzz_targets"
    support_matrix_path = root / "support_matrix.json"

    assessments = []
    all_symbols = set()
    all_cwes = set()
    transition_families = set()

    for target_name in PHASE2_TARGETS:
        source_path = fuzz_dir / f"{target_name}.rs"
        source = analyze_target_source(source_path)
        coverage = compute_target_coverage(target_name, support_matrix_path)
        info = TARGET_INFO[target_name]
        score = readiness_score(source, coverage)
        smoke_viable = source.get("ready", False)
        assessments.append(
            {
                "target": target_name,
                "family": info["family"],
                "transition_family": info["transition_family"],
                "attack_surface": info["attack_surface"],
                "cwe_targets": info["cwe_targets"],
                "source_analysis": source,
                "symbol_coverage": coverage,
                "readiness_score": score,
                "implementation_status": "functional" if smoke_viable else "partial",
                "smoke_viable": smoke_viable,
            }
        )
        all_symbols.update(coverage["target_symbols"])
        all_cwes.update(info["cwe_targets"])
        transition_families.add(info["transition_family"])

    summary = {
        "phase": 2,
        "total_targets": len(assessments),
        "functional_targets": sum(
            1 for item in assessments if item["implementation_status"] == "functional"
        ),
        "smoke_viable_targets": sum(1 for item in assessments if item["smoke_viable"]),
        "average_readiness_score": round(
            sum(item["readiness_score"] for item in assessments) / len(assessments), 1
        ),
        "total_symbols_covered": len(all_symbols),
        "total_cwes_targeted": len(all_cwes),
        "transition_families_covered": len(transition_families),
        "nightly_policy_checks": 6,
    }

    report = {
        "schema_version": "v1",
        "bead": "bd-1oz.7",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": summary,
        "target_assessments": assessments,
        "smoke_test_configs": build_smoke_test_configs(),
        "nightly_policy": build_nightly_policy(),
        "coverage_summary": {
            "all_symbols": sorted(all_symbols),
            "all_cwes": sorted(all_cwes),
            "transition_families": sorted(transition_families),
        },
    }
    report["validation_hash"] = compute_validation_hash(report)

    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)


if __name__ == "__main__":
    main()
