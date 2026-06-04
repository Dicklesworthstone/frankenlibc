#!/usr/bin/env python3
"""Generate deterministic inventory for documented FRANKENLIBC_* environment keys."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

KEY_RE = re.compile(r"\b(FRANKENLIBC_[A-Z0-9_]+)\b")

SCAN_ROOTS = ("crates", "scripts", "tests")
SCAN_EXTS = {".rs", ".sh", ".py"}
SKIP_PATH_SUBSTRINGS = (
    "runtime_env_inventory.v1.json",
    "runtime_env_inventory_test.rs",
    "docs_env_mismatch_test.rs",
    "generate_runtime_env_inventory.py",
    "check_runtime_env_inventory.sh",
    "generate_docs_env_mismatch_report.py",
    "check_docs_env_mismatch.sh",
)


SEMANTICS: dict[str, dict[str, Any]] = {
    "FRANKENLIBC_BENCH_PIN": {
        "default_value": "0",
        "allowed_values": ["0", "1"],
        "parse_rule": "enabled only when value == \"1\"",
        "mutability": "read_per_process_start",
        "mode_impact": "benchmark-only CPU pinning control; no semantic libc behavior change",
        "owner": "bench",
        "safety_impact": "low",
    },
    "FRANKENLIBC_CLOSURE_CONTRACT_PATH": {
        "default_value": "tests/conformance/closure_contract.v1.json",
        "allowed_values": ["filesystem path"],
        "parse_rule": "shell parameter expansion path override",
        "mutability": "per-invocation",
        "mode_impact": "tooling-only gate input path",
        "owner": "harness/scripts",
        "safety_impact": "low",
    },
    "FRANKENLIBC_CLOSURE_LEVEL": {
        "default_value": "empty (auto-select from contract)",
        "allowed_values": ["L0", "L1", "L2", "L3", "empty"],
        "parse_rule": "shell string passthrough to closure gate evaluator",
        "mutability": "per-invocation",
        "mode_impact": "tooling-only release target-level override",
        "owner": "harness/scripts",
        "safety_impact": "low",
    },
    "FRANKENLIBC_CLOSURE_LOG": {
        "default_value": "/tmp/frankenlibc_closure_contract.log.jsonl",
        "allowed_values": ["filesystem path"],
        "parse_rule": "shell parameter expansion path override",
        "mutability": "per-invocation",
        "mode_impact": "tooling-only evidence log destination",
        "owner": "harness/scripts",
        "safety_impact": "low",
    },
    "FRANKENLIBC_E2E_SEED": {
        "default_value": "42",
        "allowed_values": ["integer >= 0"],
        "parse_rule": "shell numeric string consumed as deterministic seed",
        "mutability": "per-e2e-run",
        "mode_impact": "deterministic scenario replay only",
        "owner": "harness/scripts",
        "safety_impact": "low",
    },
    "FRANKENLIBC_E2E_STRESS_ITERS": {
        "default_value": "5",
        "allowed_values": ["integer >= 1"],
        "parse_rule": "shell numeric string consumed as stress loop count",
        "mutability": "per-e2e-run",
        "mode_impact": "stress workload duration only",
        "owner": "harness/scripts",
        "safety_impact": "low",
    },
    "FRANKENLIBC_EXTENDED_GATES": {
        "default_value": "0",
        "allowed_values": ["0", "1"],
        "parse_rule": "enabled only when value == \"1\"",
        "mutability": "per-ci-run",
        "mode_impact": "enables extended policy/perf/snapshot gates",
        "owner": "scripts/ci",
        "safety_impact": "medium",
    },
    "FRANKENLIBC_HOOKS_LOADED": {
        "default_value": "0",
        "allowed_values": ["0", "1"],
        "parse_rule": "set to \"1\" after first hook source to enforce idempotent shell loading",
        "mutability": "per-shell-session",
        "mode_impact": "Portage hook bootstrap guard only",
        "owner": "scripts/gentoo",
        "safety_impact": "low",
    },
    "FRANKENLIBC_LIB": {
        "default_value": "auto-detected target/release/libfrankenlibc_abi.so",
        "allowed_values": ["filesystem path"],
        "parse_rule": "shell path lookup with existence check",
        "mutability": "per-runner-invocation",
        "mode_impact": "tooling library path override for CVE arena and Gentoo LD_PRELOAD hooks",
        "owner": "tests/cve_arena,scripts/gentoo",
        "safety_impact": "medium",
    },
    "FRANKENLIBC_LOG": {
        "default_value": "unset",
        "allowed_values": ["filesystem path"],
        "parse_rule": "shell export consumed by runtime evidence/metrics logging",
        "mutability": "per-process-start",
        "mode_impact": "runtime evidence log destination",
        "owner": "membrane/metrics,scripts/gentoo",
        "safety_impact": "medium",
    },
    "FRANKENLIBC_LOG_FILE": {
        "default_value": "unset (aliases FRANKENLIBC_LOG when provided by Gentoo tooling)",
        "allowed_values": ["filesystem path"],
        "parse_rule": "shell path alias; exported into FRANKENLIBC_LOG for runtime consumption",
        "mutability": "per-build-or-test-invocation",
        "mode_impact": "tooling-friendly log path variable for Gentoo runners and hooks",
        "owner": "scripts/gentoo,tests/gentoo",
        "safety_impact": "low",
    },
    "FRANKENLIBC_LOG_DIR": {
        "default_value": "/var/log/frankenlibc/portage",
        "allowed_values": ["filesystem path"],
        "parse_rule": "shell path prefix for per-atom/phase log placement",
        "mutability": "per-ebuild-run",
        "mode_impact": "Portage hook directory root for FRANKENLIBC_LOG files",
        "owner": "scripts/gentoo",
        "safety_impact": "low",
    },
    "FRANKENLIBC_MODE": {
        "default_value": "strict",
        "allowed_values": [
            "strict",
            "hardened",
            "default",
            "abi",
            "repair",
            "tsm",
            "full",
        ],
        "parse_rule": "case-insensitive parser in membrane config; unknown values resolve to strict",
        "mutability": "process-immutable after first resolution",
        "mode_impact": "selects strict ABI mode vs hardened repair mode",
        "owner": "membrane/config",
        "safety_impact": "high",
    },
    "FRANKENLIBC_PACKAGE_BLOCKLIST": {
        "default_value": "sys-libs/glibc sys-apps/shadow",
        "allowed_values": ["whitespace-delimited package atom list"],
        "parse_rule": "shell word-membership check against CATEGORY/PF atom",
        "mutability": "per-ebuild-run",
        "mode_impact": "blocks LD_PRELOAD injection for sensitive packages",
        "owner": "scripts/gentoo",
        "safety_impact": "medium",
    },
    "FRANKENLIBC_PACKAGE": {
        "default_value": "unset",
        "allowed_values": ["Gentoo atom string (<category>/<package-version>)"],
        "parse_rule": "set by hook from CATEGORY/PF for per-phase context annotation",
        "mutability": "per-phase",
        "mode_impact": "observability context only for hook/session logs",
        "owner": "scripts/gentoo",
        "safety_impact": "low",
    },
    "FRANKENLIBC_PERF_ALLOW_TARGET_VIOLATION": {
        "default_value": "1",
        "allowed_values": ["0", "1"],
        "parse_rule": "shell numeric flag",
        "mutability": "per-perf-gate-run",
        "mode_impact": "policy for perf target budget enforcement strictness",
        "owner": "scripts/perf_gate",
        "safety_impact": "medium",
    },
    "FRANKENLIBC_PERF_ENABLE_KERNEL_SUITE": {
        "default_value": "0",
        "allowed_values": ["0", "1"],
        "parse_rule": "shell numeric flag",
        "mutability": "per-perf-gate-run",
        "mode_impact": "enables additional kernel perf suite branch",
        "owner": "scripts/perf_gate",
        "safety_impact": "low",
    },
    "FRANKENLIBC_PHASE_ACTIVE": {
        "default_value": "unset/0",
        "allowed_values": ["0", "1"],
        "parse_rule": "internal shell phase-activation flag set/unset by hook enter/exit",
        "mutability": "per-hook-invocation",
        "mode_impact": "ensures balanced teardown for temporary preload/log environment",
        "owner": "scripts/gentoo",
        "safety_impact": "low",
    },
    "FRANKENLIBC_PHASE": {
        "default_value": "unset",
        "allowed_values": ["Portage phase identifier (e.g. src_test, pkg_test)"],
        "parse_rule": "set by hook from EBUILD_PHASE when instrumentation is active",
        "mutability": "per-phase",
        "mode_impact": "observability context only for hook/session logs",
        "owner": "scripts/gentoo",
        "safety_impact": "low",
    },
    "FRANKENLIBC_PHASE_ALLOWLIST": {
        "default_value": "src_test pkg_test",
        "allowed_values": ["whitespace-delimited phase names"],
        "parse_rule": "shell word-membership check with src_/pkg_ alias normalization",
        "mutability": "per-ebuild-run",
        "mode_impact": "limits which Portage phases activate FrankenLibC",
        "owner": "scripts/gentoo",
        "safety_impact": "medium",
    },
    "FRANKENLIBC_PORTAGE_ENABLE": {
        "default_value": "1",
        "allowed_values": ["0", "1"],
        "parse_rule": "enabled only when value == \"1\"",
        "mutability": "per-ebuild-run",
        "mode_impact": "global kill-switch for Gentoo Portage hooks",
        "owner": "scripts/gentoo",
        "safety_impact": "medium",
    },
    "FRANKENLIBC_PORTAGE_LOG": {
        "default_value": "/tmp/frankenlibc-portage-hooks.log",
        "allowed_values": ["filesystem path"],
        "parse_rule": "shell path override for hook decision log append",
        "mutability": "per-ebuild-run",
        "mode_impact": "records hook enable/skip decisions for troubleshooting",
        "owner": "scripts/gentoo",
        "safety_impact": "low",
    },
    "FRANKENLIBC_PERF_MAX_LOAD_FACTOR": {
        "default_value": "0.85",
        "allowed_values": ["float > 0"],
        "parse_rule": "shell numeric string parsed by gate",
        "mutability": "per-perf-gate-run",
        "mode_impact": "host load cutoff for overloaded-run skipping",
        "owner": "scripts/perf_gate",
        "safety_impact": "low",
    },
    "FRANKENLIBC_PERF_MAX_REGRESSION_PCT": {
        "default_value": "15",
        "allowed_values": ["integer/float >= 0"],
        "parse_rule": "shell numeric string parsed as percentage threshold",
        "mutability": "per-perf-gate-run",
        "mode_impact": "perf regression fail threshold",
        "owner": "scripts/perf_gate",
        "safety_impact": "medium",
    },
    "FRANKENLIBC_PERF_SKIP_OVERLOADED": {
        "default_value": "1",
        "allowed_values": ["0", "1"],
        "parse_rule": "shell numeric flag",
        "mutability": "per-perf-gate-run",
        "mode_impact": "whether perf gate skips on overloaded hosts",
        "owner": "scripts/perf_gate",
        "safety_impact": "low",
    },
    "FRANKENLIBC_RELEASE_SIMULATE_FAIL_GATE": {
        "default_value": "empty",
        "allowed_values": ["gate name string", "empty"],
        "parse_rule": "python os.environ.get(...).strip(); empty means disabled",
        "mutability": "per-release-dry-run",
        "mode_impact": "injects deterministic release-gate failure for test paths",
        "owner": "scripts/release_dry_run",
        "safety_impact": "low",
    },
    "FRANKENLIBC_RUNTIME_MATH": {
        "default_value": "on",
        "allowed_values": ["on", "off", "1", "true", "unset", "other"],
        "parse_rule": "case-insensitive parser; only off disables, on/1/true/absent/invalid resolve to enabled",
        "mutability": "process-immutable after first runtime-policy resolution",
        "mode_impact": "enables or skips runtime-math kernel consultation before ABI decisions",
        "owner": "abi/runtime_policy",
        "safety_impact": "high",
    },
    "FRANKENLIBC_SKIP_STATIC": {
        "default_value": "1",
        "allowed_values": ["0", "1"],
        "parse_rule": "enabled only when value == \"1\" and USE contains static-libs",
        "mutability": "per-ebuild-run",
        "mode_impact": "skips preload for static-libs builds that cannot use dynamic interposition",
        "owner": "scripts/gentoo",
        "safety_impact": "medium",
    },
    "FRANKENLIBC_STARTUP_DELEGATE": {
        "default_value": "0",
        "allowed_values": ["0", "1", "unset", "other"],
        "parse_rule": "owned startup is default; exact value \"1\" delegates __libc_start_main to host glibc",
        "mutability": "process-startup-time",
        "mode_impact": "opts out of owned startup path for compatibility debugging",
        "owner": "abi/startup_abi",
        "safety_impact": "high",
    },
    "FRANKENLIBC_STARTUP_PHASE0": {
        "default_value": "0",
        "allowed_values": ["0", "1"],
        "parse_rule": "enabled only when value == \"1\"",
        "mutability": "process-startup-time",
        "mode_impact": "gates phase-0 startup path in __libc_start_main",
        "owner": "abi/startup_abi",
        "safety_impact": "high",
    },
    "FRANKENLIBC_THREAD_DELEGATE": {
        "default_value": "0",
        "allowed_values": ["0", "1", "unset", "other"],
        "parse_rule": "native threading is default; exact value \"1\" opts pthread lifecycle calls back to host fallbacks",
        "mutability": "process-startup-time prewarm policy",
        "mode_impact": "opts out of native pthread lifecycle implementation for compatibility debugging",
        "owner": "abi/pthread_abi",
        "safety_impact": "high",
    },
    "FRANKENLIBC_TMPDIR": {
        "default_value": "unset (fallback to TMPDIR then /tmp)",
        "allowed_values": ["filesystem path"],
        "parse_rule": "python os.environ lookup chain",
        "mutability": "per-release-dry-run",
        "mode_impact": "tooling artifact temp-root location",
        "owner": "scripts/release_dry_run",
        "safety_impact": "low",
    },
}


def classify_scope(path: str) -> str:
    if path.startswith("crates/frankenlibc-membrane/"):
        return "membrane"
    if path.startswith("crates/frankenlibc-abi/"):
        return "abi"
    if path.startswith("crates/frankenlibc-core/"):
        return "core"
    if path.startswith("crates/frankenlibc-harness/"):
        return "harness"
    if path.startswith("crates/frankenlibc-bench/"):
        return "bench"
    if path.startswith("scripts/"):
        return "scripts"
    if path.startswith("tests/"):
        return "tests"
    return "other"


def strip_comments(line: str, suffix: str) -> str:
    stripped = line.strip()
    if suffix == ".rs":
        if stripped.startswith("//"):
            return ""
        if "//" in line:
            line = line[: line.index("//")]
        return line.rstrip()
    if suffix in {".sh", ".py"}:
        if stripped.startswith("#"):
            return ""
        return line.rstrip()
    return line.rstrip()


def classify_operation(snippet: str, key: str) -> str:
    read_markers = (
        "std::env::var(",
        "env::var(",
        "std::env::var_os(",
        "env::var_os(",
        "os.environ.get(",
        "os.getenv(",
        "os.environ[",
        "${" + key,
    )
    write_markers = (
        f'export {key}=',
        f'{key}=',
        f'.env("{key}"',
        f"-e \"{key}=",
        f"-e '{key}=",
    )

    has_read = any(marker in snippet for marker in read_markers)

    has_write = False
    for marker in write_markers:
        if marker in snippet:
            has_write = True
            break

    if has_read and has_write:
        return "read_write"
    if has_read:
        return "read"
    if has_write:
        return "write"
    return "reference"


def scan_sources(root: Path) -> dict[str, list[dict[str, Any]]]:
    findings: dict[str, list[dict[str, Any]]] = {}
    for scan_root in SCAN_ROOTS:
        base = root / scan_root
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in SCAN_EXTS:
                continue
            rel = path.relative_to(root).as_posix()
            if rel.startswith("target/") or rel.startswith(".git/"):
                continue
            if any(skip in rel for skip in SKIP_PATH_SUBSTRINGS):
                continue

            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue

            for idx, original in enumerate(lines, start=1):
                snippet = strip_comments(original, path.suffix)
                if not snippet:
                    continue
                keys = sorted(set(KEY_RE.findall(snippet)))
                if not keys:
                    continue
                for key in keys:
                    findings.setdefault(key, []).append(
                        {
                            "path": rel,
                            "line": idx,
                            "scope": classify_scope(rel),
                            "operation": classify_operation(snippet, key),
                            "snippet": snippet.strip(),
                        }
                    )
    return findings


def build_inventory(findings: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    inventory: list[dict[str, Any]] = []
    unknown_or_ambiguous: list[dict[str, Any]] = []

    # This inventory is the canonical set of documented runtime/tooling env knobs.
    # Test-only probes and ad hoc gate-local overrides are intentionally excluded
    # unless they are promoted into the documented semantics table.
    for key in sorted(findings):
        if key not in SEMANTICS:
            continue
        accesses = sorted(findings[key], key=lambda row: (row["path"], row["line"]))
        counts = {"read": 0, "write": 0, "read_write": 0, "reference": 0}
        for access in accesses:
            counts[access["operation"]] += 1

        metadata = SEMANTICS.get(key)
        if metadata is None:
            unknown_or_ambiguous.append(
                {
                    "env_key": key,
                    "reason": "missing_semantic_metadata",
                    "locations": [
                        {"path": row["path"], "line": row["line"]} for row in accesses[:10]
                    ],
                }
            )
            metadata = {
                "default_value": "unknown",
                "allowed_values": ["unknown"],
                "parse_rule": "unknown",
                "mutability": "unknown",
                "mode_impact": "unknown",
                "owner": "unknown",
                "safety_impact": "unknown",
            }

        inventory.append(
            {
                "env_key": key,
                "metadata": metadata,
                "access_count": len(accesses),
                "read_count": counts["read"] + counts["read_write"],
                "write_count": counts["write"] + counts["read_write"],
                "reference_count": counts["reference"],
                "accesses": accesses,
            }
        )

    summary = {
        "total_keys": len(inventory),
        "keys_with_reads": sum(1 for row in inventory if row["read_count"] > 0),
        "keys_with_writes": sum(1 for row in inventory if row["write_count"] > 0),
        "unknown_or_ambiguous_count": len(unknown_or_ambiguous),
        "scanned_roots": list(SCAN_ROOTS),
        "scanned_extensions": sorted(SCAN_EXTS),
    }

    return {
        "schema_version": "v1",
        "generator": "scripts/generate_runtime_env_inventory.py",
        "inventory": inventory,
        "unknown_or_ambiguous": unknown_or_ambiguous,
        "summary": summary,
    }


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic FRANKENLIBC runtime env inventory."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Workspace root (default: repo root)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("tests/conformance/runtime_env_inventory.v1.json"),
        help="Output JSON path relative to --root",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when output differs from generated content",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print generated JSON to stdout",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    output_path = (root / args.output).resolve()
    findings = scan_sources(root)
    payload = build_inventory(findings)
    rendered = canonical_json(payload)

    if args.stdout:
        sys.stdout.write(rendered)
        if not args.check:
            return 0

    if args.check:
        if not output_path.exists():
            print(f"FAIL: missing inventory file: {output_path}", file=sys.stderr)
            return 1
        current = output_path.read_text(encoding="utf-8")
        if current != rendered:
            print(
                "FAIL: runtime env inventory drift detected. "
                "Regenerate with scripts/generate_runtime_env_inventory.py",
                file=sys.stderr,
            )
            return 1
        print(
            f"PASS: runtime env inventory is up-to-date ({payload['summary']['total_keys']} keys)",
            file=sys.stderr if args.stdout else sys.stdout,
        )
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    print(f"Wrote {output_path.relative_to(root)} ({payload['summary']['total_keys']} keys)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
