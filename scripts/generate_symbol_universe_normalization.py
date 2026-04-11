#!/usr/bin/env python3
"""generate_symbol_universe_normalization.py — bd-2vv.9

Full symbol-universe normalization and support classification pipeline:
  1. Import — load support_matrix.json as canonical symbol source.
  2. Normalize — deduplicate, validate names, assign canonical families.
  3. Classify — assign support state + confidence to every symbol.
  4. Unknown/unverified — flag symbols with ambiguous or missing state.
  5. Report — produce reproducible, diff-friendly classification dataset.

Generates a JSON report to stdout (or --output).
"""
import argparse
import hashlib
import json
import sys
from collections import defaultdict
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


# Canonical module-to-family mapping
MODULE_TO_FAMILY = {
    "ctype_abi": "ctype",
    "dirent_abi": "dirent",
    "dlfcn_abi": "dlfcn",
    "errno_abi": "errno",
    "grp_abi": "grp",
    "iconv_abi": "iconv",
    "inet_abi": "inet",
    "io_abi": "io",
    "locale_abi": "locale",
    "malloc_abi": "malloc",
    "math_abi": "math",
    "mmap_abi": "mmap",
    "poll_abi": "poll",
    "process_abi": "process",
    "pthread_abi": "pthread",
    "pwd_abi": "pwd",
    "resolv_abi": "resolv",
    "resource_abi": "resource",
    "signal_abi": "signal",
    "socket_abi": "socket",
    "startup_abi": "startup",
    "stdio_abi": "stdio",
    "stdlib_abi": "stdlib",
    "string_abi": "string",
    "termios_abi": "termios",
    "time_abi": "time",
    "unistd_abi": "unistd",
    "wchar_abi": "wchar",
}

# Valid support states
VALID_STATUSES = {"Implemented", "RawSyscall", "WrapsHostLibc", "GlibcCallThrough", "Stub"}

# Valid perf classes
VALID_PERF_CLASSES = {"strict_hotpath", "coldpath", "hardened_hotpath"}

# Classification confidence levels
CONFIDENCE_RULES = {
    "Implemented": {
        "strict_hotpath": "high",
        "coldpath": "high",
        "hardened_hotpath": "high",
    },
    "RawSyscall": {
        "strict_hotpath": "medium",
        "coldpath": "medium",
        "hardened_hotpath": "medium",
    },
    "WrapsHostLibc": {
        "strict_hotpath": "low",
        "coldpath": "low",
        "hardened_hotpath": "low",
    },
    "GlibcCallThrough": {
        "strict_hotpath": "low",
        "coldpath": "low",
        "hardened_hotpath": "low",
    },
    "Stub": {
        "strict_hotpath": "low",
        "coldpath": "low",
        "hardened_hotpath": "low",
    },
}

# Runtime impact weights
RUNTIME_IMPACT = {
    "strict_hotpath": 5,
    "hardened_hotpath": 3,
    "coldpath": 1,
}

# Replacement complexity by module
MODULE_COMPLEXITY = {
    "string_abi": "low",
    "ctype_abi": "low",
    "errno_abi": "low",
    "malloc_abi": "medium",
    "math_abi": "medium",
    "stdlib_abi": "medium",
    "wchar_abi": "medium",
    "stdio_abi": "high",
    "pthread_abi": "high",
    "socket_abi": "high",
    "resolv_abi": "high",
    "dlfcn_abi": "high",
    "signal_abi": "high",
    "iconv_abi": "medium",
    "locale_abi": "medium",
    "inet_abi": "medium",
    "grp_abi": "medium",
    "pwd_abi": "medium",
    "process_abi": "medium",
    "unistd_abi": "medium",
    "mmap_abi": "medium",
    "poll_abi": "low",
    "dirent_abi": "low",
    "io_abi": "low",
    "resource_abi": "low",
    "startup_abi": "low",
    "termios_abi": "low",
    "time_abi": "low",
}

COMPLEXITY_WEIGHTS = {"low": 1, "medium": 2, "high": 3}


def normalize_symbol(sym_entry):
    """Normalize a symbol entry into canonical form."""
    issues = []

    symbol = sym_entry.get("symbol", "").strip()
    if not symbol:
        issues.append("empty symbol name")

    status = sym_entry.get("status", "")
    if status not in VALID_STATUSES:
        issues.append(f"unknown status: {status}")

    module = sym_entry.get("module", "")
    family = MODULE_TO_FAMILY.get(module, "unknown")
    if family == "unknown" and module:
        issues.append(f"unmapped module: {module}")

    perf_class = sym_entry.get("perf_class", "coldpath")
    if perf_class not in VALID_PERF_CLASSES:
        issues.append(f"unknown perf_class: {perf_class}")

    # Confidence
    confidence = CONFIDENCE_RULES.get(status, {}).get(perf_class, "unknown")

    # Runtime impact score
    impact = RUNTIME_IMPACT.get(perf_class, 0)

    # Replacement complexity
    complexity_label = MODULE_COMPLEXITY.get(module, "medium")
    complexity = COMPLEXITY_WEIGHTS.get(complexity_label, 2)

    # Priority score: higher = more important to have natively implemented
    priority_score = impact * 100 - complexity * 10

    # Support classification
    if status == "Implemented":
        classification = "native"
    elif status == "RawSyscall":
        classification = "syscall-passthrough"
    elif status == "WrapsHostLibc":
        classification = "host-wrapped"
    elif status == "GlibcCallThrough":
        classification = "host-delegated"
    elif status == "Stub":
        classification = "stub"
    else:
        classification = "unknown"

    return {
        "symbol": symbol,
        "module": module,
        "family": family,
        "status": status,
        "perf_class": perf_class,
        "classification": classification,
        "confidence": confidence,
        "runtime_impact": impact,
        "replacement_complexity": complexity_label,
        "priority_score": priority_score,
        "default_stub": sym_entry.get("default_stub", False),
        "strict_semantics": sym_entry.get("strict_semantics", ""),
        "hardened_semantics": sym_entry.get("hardened_semantics", ""),
        "issues": issues,
    }


def compute_universe_hash(normalized_symbols):
    """Compute deterministic hash of the full normalized symbol set."""
    canonical = json.dumps(
        [{"s": s["symbol"], "c": s["classification"]} for s in normalized_symbols],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def main():
    parser = argparse.ArgumentParser(
        description="Symbol universe normalization and classification pipeline")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()
    matrix_path = root / "support_matrix.json"

    if not matrix_path.exists():
        print("ERROR: support_matrix.json not found", file=sys.stderr)
        sys.exit(1)

    matrix = load_json_file(matrix_path)
    symbols_list = matrix.get("symbols", [])

    # Normalize all symbols
    normalized = []
    seen_names = set()
    duplicates = []

    for entry in symbols_list:
        norm = normalize_symbol(entry)
        name = norm["symbol"]
        if name in seen_names:
            duplicates.append(name)
        seen_names.add(name)
        normalized.append(norm)

    # Sort for reproducibility
    normalized.sort(key=lambda s: s["symbol"])

    # Classification summary
    by_classification = defaultdict(list)
    by_family = defaultdict(list)
    by_confidence = defaultdict(list)
    by_perf = defaultdict(list)

    for s in normalized:
        by_classification[s["classification"]].append(s["symbol"])
        by_family[s["family"]].append(s["symbol"])
        by_confidence[s["confidence"]].append(s["symbol"])
        by_perf[s["perf_class"]].append(s["symbol"])

    # Unknown/unverified symbols
    unknown_action_list = []
    for s in normalized:
        if s["issues"]:
            unknown_action_list.append({
                "symbol": s["symbol"],
                "issues": s["issues"],
                "action": "investigate",
            })
        elif s["classification"] == "host-delegated" and s["perf_class"] == "strict_hotpath":
            unknown_action_list.append({
                "symbol": s["symbol"],
                "issues": ["hotpath symbol delegated to host glibc"],
                "action": "prioritize-replacement",
            })

    # Family statistics
    family_stats = {}
    for fam, syms in sorted(by_family.items()):
        native_count = sum(
            1 for s in normalized
            if s["family"] == fam and s["classification"] == "native"
        )
        family_stats[fam] = {
            "total": len(syms),
            "native": native_count,
            "native_pct": round(native_count / len(syms) * 100, 1) if syms else 0,
            "symbols": sorted(syms),
        }

    universe_hash = compute_universe_hash(normalized)

    report = {
        "schema_version": "v1",
        "bead": "bd-2vv.9",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "universe_hash": universe_hash,
        "summary": {
            "total_symbols": len(normalized),
            "unique_symbols": len(seen_names),
            "duplicates": len(duplicates),
            "families": len(by_family),
            "classifications": {
                k: len(v) for k, v in sorted(by_classification.items())
            },
            "confidence_levels": {
                k: len(v) for k, v in sorted(by_confidence.items())
            },
            "perf_classes": {
                k: len(v) for k, v in sorted(by_perf.items())
            },
            "unknown_action_count": len(unknown_action_list),
            "native_implementation_pct": round(
                len(by_classification.get("native", [])) / len(normalized) * 100, 1
            ) if normalized else 0,
        },
        "normalized_symbols": normalized,
        "family_statistics": family_stats,
        "unknown_action_list": unknown_action_list,
        "classification_rules": {
            "native": "Implemented in safe Rust (status=Implemented)",
            "syscall-passthrough": "Direct syscall forwarding (status=RawSyscall)",
            "host-delegated": "Delegates to host glibc (status=GlibcCallThrough)",
            "unknown": "Classification could not be determined",
        },
        "confidence_rules": {
            "high": "Implemented natively with verified semantics",
            "medium": "Syscall passthrough with known ABI contract",
            "low": "Host-delegated, verification depends on host glibc version",
            "unknown": "Could not determine confidence level",
        },
    }

    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
