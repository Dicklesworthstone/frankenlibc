#!/usr/bin/env python3
"""Generate fixture coverage campaign priorities for bd-bp8fl.4.1."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BEAD_ID = "bd-bp8fl.4.1"
SCHEMA_VERSION = "v1"
FIRST_WAVE_LIMIT = 12

DEFAULT_INPUTS = {
    "version_script": "crates/frankenlibc-abi/version_scripts/libc.map",
    "abi_symbol_universe": "tests/conformance/symbol_universe_normalization.v1.json",
    "support_matrix": "support_matrix.json",
    "semantic_overlay": "tests/conformance/support_semantic_overlay.v1.json",
    "semantic_contract_join": "tests/conformance/semantic_contract_symbol_join.v1.json",
    "symbol_fixture_coverage": "tests/conformance/symbol_fixture_coverage.v1.json",
    "per_symbol_fixture_tests": "tests/conformance/per_symbol_fixture_tests.v1.json",
    "user_workload_acceptance_matrix": "tests/conformance/user_workload_acceptance_matrix.v1.json",
    "hard_parts_truth_table": "tests/conformance/hard_parts_truth_table.v1.json",
    "hard_parts_failure_matrix": "tests/conformance/hard_parts_e2e_failure_matrix.v1.json",
    "feature_parity_gap_groups": "tests/conformance/feature_parity_gap_groups.v1.json",
}

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "symbol_family",
    "score",
    "rank",
    "coverage_state",
    "risk_factors",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]


@dataclass(frozen=True)
class CampaignPolicy:
    campaign_id: str
    title: str
    symbol_family: str
    workload_domains: tuple[str, ...]
    risk_tags: tuple[str, ...]
    workload_risk_score: int
    parity_risk_score: int
    implementation_complexity_score: int
    oracle_kind: str
    deterministic_e2e_scripts: tuple[str, ...]
    next_step: str


CAMPAIGN_POLICIES: dict[str, CampaignPolicy] = {
    "unistd_abi": CampaignPolicy(
        "fcq-unistd-process-filesystem",
        "unistd/process/filesystem syscall fixture wave",
        "process control, filesystem metadata, cwd, exec, exit, and low-level unistd wrappers",
        ("shell_coreutils", "build_tools", "package_manager", "startup_linking"),
        ("startup_linking_failure", "semantic_divergence", "filesystem_state", "errno_mapping"),
        5,
        5,
        3,
        "glibc_fixture_oracle",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/e2e_suite.sh"),
        "Add strict/hardened fixtures for process, stat-family, and exit-path symbols before broad syscall tail work.",
    ),
    "string_abi": CampaignPolicy(
        "fcq-string-memory-hotpaths",
        "string and memory hot-path fixture wave",
        "mem*, str*, collation-adjacent string helpers, and GNU string extensions",
        ("performance_sensitive", "shell_coreutils", "allocator", "language_runtimes"),
        ("semantic_divergence", "buffer_boundary", "locale_sensitive", "performance_regression"),
        5,
        5,
        2,
        "glibc_fixture_oracle",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/ld_preload_smoke.sh"),
        "Grow boundary, overlap, empty, invalid pointer, locale, and perf guard fixtures for uncovered string families.",
    ),
    "stdio_abi": CampaignPolicy(
        "fcq-stdio-libio",
        "stdio/libio stream semantics fixture wave",
        "FILE state, _IO compatibility names, locking, formatted IO, buffering, and stream errors",
        ("stdio_libio", "shell_coreutils", "build_tools", "package_manager"),
        ("stdio_libio_divergence", "semantic_divergence", "buffering_order", "diagnostics_gap"),
        5,
        5,
        3,
        "stdio_fixture_or_replay",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/e2e_suite.sh"),
        "Add stream-state and _IO alias fixtures that prove behavior before native stdio replacement claims advance.",
    ),
    "pthread_abi": CampaignPolicy(
        "fcq-pthread-sync",
        "pthread synchronization and cancellation fixture wave",
        "pthread lifecycle, mutex, condvar, TLS keys, cancellation, and GNU extensions",
        ("threaded_services", "language_runtimes", "performance_sensitive"),
        ("pthread_cancellation", "mode_pair_mismatch", "deadlock_timeout", "performance_regression"),
        5,
        5,
        4,
        "threaded_mode_pair_replay",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/e2e_suite.sh"),
        "Prioritize deterministic mode-pair tests for pthread primitives that real runtimes and services depend on.",
    ),
    "malloc_abi": CampaignPolicy(
        "fcq-malloc-membrane",
        "allocator ownership and membrane fixture wave",
        "malloc, alignment, usable-size, stats, trimming, and hardened ownership behavior",
        ("allocator", "threaded_services", "performance_sensitive", "language_runtimes"),
        ("allocator_ownership", "hardened_repair", "foreign_free", "performance_regression"),
        5,
        5,
        3,
        "membrane_allocator_oracle",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/e2e_suite.sh"),
        "Add allocator parity and hardened invalid-pointer fixtures before optimizing allocator or membrane hot paths.",
    ),
    "process_abi": CampaignPolicy(
        "fcq-process-spawn",
        "process spawn and privilege-sensitive fixture wave",
        "exit, clone, exec, spawn actions, chroot, and uid/gid result contracts",
        ("shell_coreutils", "build_tools", "package_manager", "startup_linking"),
        ("startup_linking_failure", "process_status", "errno_mapping", "semantic_divergence"),
        5,
        5,
        4,
        "mode_pair_process_replay",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/e2e_suite.sh"),
        "Add exec/spawn/action fixtures with exact status, errno, and file-action diagnostics.",
    ),
    "resolv_abi": CampaignPolicy(
        "fcq-resolver-nss-core",
        "resolver service lookup fixture wave",
        "getaddrinfo-adjacent status, host/service/protocol lookup, and h_errno behavior",
        ("resolver_nss", "language_runtimes", "package_manager", "threaded_services"),
        ("resolver_nss_failure", "semantic_divergence", "timeout_policy", "claim_blocked"),
        5,
        5,
        4,
        "resolver_nss_fixture_oracle",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/e2e_suite.sh"),
        "Finish resolver fixture coverage with localhost, invalid, service, protocol, reverse, and h_errno cases.",
    ),
    "dlfcn_abi": CampaignPolicy(
        "fcq-dlfcn-loader",
        "loader symbol versioning fixture wave",
        "dl_iterate_phdr, dlvsym, loader namespace, and versioned symbol behavior",
        ("startup_linking", "language_runtimes", "build_tools"),
        ("startup_linking_failure", "symbol_missing", "version_node", "standalone_blocker"),
        5,
        5,
        4,
        "loader_symbol_replay",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/e2e_suite.sh"),
        "Close the small but high-risk dlfcn fixture gap with versioned-symbol and phdr iteration tests.",
    ),
    "poll_abi": CampaignPolicy(
        "fcq-poll-event-loop",
        "poll/epoll/eventfd/timerfd fixture wave",
        "poll, select, epoll, eventfd, timerfd, pselect, ppoll, and scheduler-yield contracts",
        ("threaded_services", "performance_sensitive", "package_manager"),
        ("mode_pair_mismatch", "timeout_policy", "event_loop", "performance_regression"),
        5,
        4,
        3,
        "threaded_service_replay",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/e2e_suite.sh"),
        "Add deterministic timeout, readiness, invalid-fd, and mode-pair cases for event-loop syscalls.",
    ),
    "socket_abi": CampaignPolicy(
        "fcq-socket-network",
        "socket send/recv/connect fixture wave",
        "accept/connect/socketpair/send/recv/socket options with loopback-only deterministic behavior",
        ("threaded_services", "package_manager", "language_runtimes", "resolver_nss"),
        ("network_semantics", "timeout_policy", "errno_mapping", "mode_pair_mismatch"),
        5,
        4,
        4,
        "loopback_network_replay",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/e2e_suite.sh"),
        "Add loopback-only socket fixtures with deterministic peer, timeout, and errno normalization.",
    ),
    "wchar_abi": CampaignPolicy(
        "fcq-wchar-locale-encoding",
        "wide-character and multibyte fixture wave",
        "wchar, mbstate, wcs*, wcsto*, and locale-sensitive multibyte conversion behavior",
        ("locale_iconv", "language_runtimes", "shell_coreutils"),
        ("locale_sensitive", "stateful_encoding", "semantic_divergence", "buffer_boundary"),
        4,
        5,
        4,
        "locale_mode_pair_oracle",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/e2e_suite.sh"),
        "Add stateful mb/wchar fixtures with invalid sequence, short buffer, and locale variation cases.",
    ),
    "locale_abi": CampaignPolicy(
        "fcq-locale-collation",
        "locale catalog and collation fixture wave",
        "locale_t, nl_langinfo, gettext-adjacent catalog, collation, and transliteration behavior",
        ("locale_iconv", "shell_coreutils", "language_runtimes", "package_manager"),
        ("locale_sensitive", "claim_blocked", "semantic_divergence", "transliteration"),
        4,
        5,
        5,
        "locale_fixture_oracle",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/e2e_suite.sh"),
        "Add pinned-locale fixtures before user-facing locale or transliteration support claims advance.",
    ),
    "fortify_abi": CampaignPolicy(
        "fcq-fortify-bounds",
        "fortify and checked-variant fixture wave",
        "__*_chk fortified wrappers, object-size behavior, and deny/repair diagnostics",
        ("performance_sensitive", "shell_coreutils", "build_tools"),
        ("buffer_boundary", "hardened_repair", "diagnostics_gap", "claim_blocked"),
        4,
        5,
        4,
        "hardened_bounds_oracle",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/e2e_suite.sh"),
        "Add positive and negative checked-wrapper fixtures before fortify safety claims expand.",
    ),
    "time_abi": CampaignPolicy(
        "fcq-time-clock",
        "time clock and calendar fixture wave",
        "clock_gettime, timers, tz-sensitive calendar conversion, and pinned-time behavior",
        ("build_tools", "language_runtimes", "package_manager"),
        ("temporal_discontinuity", "errno_mapping", "semantic_divergence", "timeout_policy"),
        4,
        4,
        3,
        "pinned_time_fixture_oracle",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/e2e_suite.sh"),
        "Add pinned-time and invalid-clock fixtures with deterministic tolerance rules.",
    ),
    "math_abi": CampaignPolicy(
        "fcq-math-special",
        "math finite/special-function fixture wave",
        "finite aliases, special functions, fpclassify/signbit, libm edge cases, and exception-adjacent behavior",
        ("language_runtimes", "performance_sensitive", "build_tools"),
        ("semantic_divergence", "numeric_boundary", "fenv_adjacent", "performance_regression"),
        3,
        5,
        5,
        "glibc_fixture_oracle",
        ("scripts/check_fixture_coverage_prioritizer.sh",),
        "Start with finite aliases and fpclassification before expanding to the long libm tail.",
    ),
    "signal_abi": CampaignPolicy(
        "fcq-signal-async",
        "signal and async-observable fixture wave",
        "signal masks, alternate stacks, RT min/max, pause, and async-visible diagnostics",
        ("threaded_services", "shell_coreutils", "language_runtimes"),
        ("semantic_divergence", "async_signal", "pthread_cancellation", "diagnostics_gap"),
        4,
        4,
        4,
        "mode_pair_process_replay",
        ("scripts/check_fixture_coverage_prioritizer.sh", "scripts/e2e_suite.sh"),
        "Add deterministic signal-mask and alternate-stack fixtures before broader async-cancellation campaigns.",
    ),
    "glibc_internal_abi": CampaignPolicy(
        "fcq-glibc-internal-compat",
        "glibc internal compatibility triage fixture wave",
        "exported glibc internals, compatibility names, diagnostics, backtrace, argz, and resolver helpers",
        ("startup_linking", "build_tools", "diagnostics"),
        ("unsupported_claim", "symbol_missing", "diagnostics_gap", "compatibility_internal"),
        2,
        4,
        5,
        "symbol_coverage_gate",
        ("scripts/check_fixture_coverage_prioritizer.sh",),
        "Split compatibility internals into supported, deterministic-fallback, and claim-blocked fixture groups.",
    ),
    "rpc_abi": CampaignPolicy(
        "fcq-rpc-legacy-network",
        "legacy RPC compatibility fixture wave",
        "sunrpc/auth/xdr compatibility and deterministic unsupported behavior",
        ("resolver_nss", "package_manager", "legacy_network"),
        ("unsupported_claim", "legacy_network", "semantic_divergence", "deterministic_fallback"),
        2,
        3,
        4,
        "claim_reconciliation_gate",
        ("scripts/check_fixture_coverage_prioritizer.sh",),
        "Add deterministic compatibility/unsupported fixtures before claiming RPC-related coverage.",
    ),
}

DEFERRED_NOTES = {
    "stdlib_abi": (
        "Lower workload and parity risk than the first-wave campaigns, but still tracked to prevent silent loss of stdlib conversion, random, exit, and environment fixture coverage.",
        "Create a follow-up stdlib fixture campaign after current process, stdio, string, pthread, malloc, resolver, loader, and math waves have generated closure evidence.",
    ),
    "io_internal_abi": (
        "Internal I/O coverage is related to stdio and low-level I/O waves but needs a narrower oracle plan before it should displace user-facing campaigns.",
        "Split internal I/O fixtures by public behavior proxy after stdio and syscall fixture logs identify the shared surface.",
    ),
    "ctype_abi": (
        "Character classification is important for locale users but has less immediate standalone replacement risk than the selected locale, wchar, and stdio campaigns.",
        "Add ctype boundary fixtures alongside the next locale and transliteration evidence wave.",
    ),
    "io_abi": (
        "Low-level I/O is partially represented by unistd, process, poll, socket, and stdio campaigns; a separate wave should avoid duplicate syscall fixture coverage.",
        "Derive an io_abi campaign from syscall coverage deltas after the unistd and poll waves land.",
    ),
    "pwd_abi": (
        "Password database behavior belongs with NSS and resolver hard-parts but needs controlled host database fixtures before first-wave expansion.",
        "Add pwd/group/NSS fixtures with deterministic passwd and group databases after resolver campaign evidence is in place.",
    ),
    "err_abi": (
        "Err/warn helpers are user-visible diagnostics but low breadth compared with selected high-risk runtime and syscall campaigns.",
        "Create a compact stderr and errno formatting fixture pack once stdio buffering evidence is stable.",
    ),
    "fenv_abi": (
        "Floating-point environment behavior is high precision work but should be paired with the math exceptional-path fixture pack instead of this broad first queue.",
        "Add fenv fixtures with soft-fp and math exception cases in the dedicated math/fenv wave.",
    ),
    "inet_abi": (
        "inet address helpers are partially covered and have lower workload risk than resolver, socket, and NSS behavior.",
        "Extend network conversion fixtures after resolver and socket campaigns expose shared address-family gaps.",
    ),
    "dirent_abi": (
        "Directory operations have partial coverage and should be tied to filesystem state fixtures from the unistd/process wave.",
        "Add deterministic directory traversal fixtures after filesystem metadata and cwd cases are expanded.",
    ),
    "mmap_abi": (
        "Memory mapping behavior is critical but needs allocator, membrane, and syscall interaction evidence before isolated fixture prioritization.",
        "Create mmap fixtures after malloc/membrane and syscall campaign logs identify strict versus hardened expectations.",
    ),
    "isoc_abi": (
        "ISOC compatibility surface is small and lower impact than the selected broad ABI families.",
        "Add the ISOC fixture pack as a compact cleanup campaign after high-risk exported families have threshold coverage.",
    ),
    "termios_abi": (
        "Terminal controls matter for interactive programs but have partial coverage and require pseudo-terminal fixture isolation.",
        "Add termios pty fixtures once process and stdio fixture infrastructure has stable subprocess logging.",
    ),
    "grp_abi": (
        "Group database behavior should be verified with pwd and NSS fixtures rather than as an isolated first-wave campaign.",
        "Fold group fixtures into the follow-up deterministic passwd/group/NSS campaign.",
    ),
    "setjmp_abi": (
        "Setjmp semantics belong with signal and cancellation boundary tests and should not be decoupled from async-control evidence.",
        "Add setjmp fixtures in the signal and async-cancellation boundary fixture pack.",
    ),
    "c11threads_abi": (
        "C11 thread coverage is already high and lower marginal gain than pthread synchronization and cancellation fixtures.",
        "Add remaining C11 thread edge fixtures after pthread robust mutex and TLS destructor coverage lands.",
    ),
    "resource_abi": (
        "Resource-limit surface is tiny and lower priority than broad process, allocator, and runtime replacement blockers.",
        "Add resource fixtures as part of syscall tail cleanup after first-wave campaigns complete.",
    ),
    "runtime_policy": (
        "Runtime policy is a control-plane surface rather than a user-facing exported symbol family and needs dedicated strict/hardened mode evidence.",
        "Add runtime-policy fixtures with replacement-level gates after mode-pair workload evidence is refreshed.",
    ),
    "startup_abi": (
        "Startup coverage has a small residual gap and is already represented in loader, process, and user workload smoke evidence.",
        "Close the remaining startup fixture in the L0/L1 real-program smoke suite.",
    ),
}


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc


def canonical_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def pct(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 100.0
    return round(numerator * 100.0 / denominator, 2)


def latest_generated_at(inputs: dict[str, Any], *, exclude: set[str] | None = None) -> str:
    exclude = exclude or set()
    values = []
    for key, data in inputs.items():
        if key in exclude:
            continue
        if isinstance(data, dict):
            value = data.get("generated_at_utc") or data.get("generated_at")
            if isinstance(value, str) and value:
                values.append(value)
    return max(values) if values else "unknown"


def validate_inputs(root: Path, paths: dict[str, str], data: dict[str, Any]) -> None:
    for key, rel_path in paths.items():
        if not (root / rel_path).exists():
            raise ValueError(f"missing input {key}: {rel_path}")
    if not isinstance(data["support_matrix"].get("symbols"), list):
        raise ValueError("support_matrix symbols must be an array")
    if not isinstance(data["symbol_fixture_coverage"].get("families"), list):
        raise ValueError("symbol_fixture_coverage families must be an array")
    if not isinstance(data["per_symbol_fixture_tests"].get("per_symbol_report"), list):
        raise ValueError("per_symbol_fixture_tests per_symbol_report must be an array")
    axes = set(data["feature_parity_gap_groups"].get("required_grouping_axes", []))
    required_axes = {"symbol_family", "source_owner", "evidence_artifacts", "priority"}
    missing_axes = sorted(required_axes - axes)
    if missing_axes:
        raise ValueError("feature parity gap grouping missing axes: " + ", ".join(missing_axes))


def support_modules(support: dict[str, Any]) -> set[str]:
    modules = set()
    for row in support.get("symbols", []):
        module = row.get("module") if isinstance(row, dict) else None
        if isinstance(module, str) and module:
            modules.add(module)
    return modules


def per_symbol_index(per_symbol: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    duplicates = []
    for row in per_symbol.get("per_symbol_report", []):
        if not isinstance(row, dict):
            continue
        module = row.get("module")
        symbol = row.get("symbol")
        if not isinstance(module, str) or not isinstance(symbol, str):
            continue
        key = (module, symbol)
        if key in index:
            duplicates.append(f"{module}:{symbol}")
        index[key] = row
    if duplicates:
        raise ValueError("duplicate per-symbol fixture rows: " + ", ".join(sorted(duplicates)[:10]))
    return index


def indexed_families(coverage: dict[str, Any]) -> dict[str, dict[str, Any]]:
    families: dict[str, dict[str, Any]] = {}
    for row in coverage.get("families", []):
        if not isinstance(row, dict):
            continue
        module = row.get("module")
        if not isinstance(module, str) or not module:
            continue
        if module in families:
            raise ValueError(f"duplicate coverage family: {module}")
        families[module] = row
    return families


def first_wave_symbols(
    module: str,
    family: dict[str, Any],
    symbol_rows: dict[tuple[str, str], dict[str, Any]],
) -> list[str]:
    selected = []
    for symbol in family.get("target_uncovered_symbols", []):
        if not isinstance(symbol, str) or not symbol:
            continue
        row = symbol_rows.get((module, symbol))
        if row is None:
            raise ValueError(f"{module}:{symbol} missing from per-symbol report")
        if row.get("has_fixtures"):
            raise ValueError(f"{module}:{symbol} is marked uncovered but already has fixtures")
        selected.append(symbol)
        if len(selected) == FIRST_WAVE_LIMIT:
            break
    return selected


def coverage_state(family: dict[str, Any]) -> str:
    uncovered = int(family.get("target_uncovered", 0))
    total = int(family.get("target_total", 0))
    covered = int(family.get("target_covered", 0))
    if uncovered == 0:
        return "covered"
    if covered == 0:
        return "uncovered"
    if total and pct(covered, total) < 80.0:
        return "weak"
    return "partial"


def semantic_risk_for_module(module: str, semantic_join: dict[str, Any]) -> int:
    score = 0
    needle = module.removesuffix("_abi")
    for entry in semantic_join.get("entries", []):
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("source_path", ""))
        refs = entry.get("symbol_refs", [])
        if needle in path or module in path:
            score += 1
        if isinstance(refs, list) and refs and module in path:
            score += 1
    return min(score, 3)


def feature_gap_risk_for_module(module: str, feature_gaps: dict[str, Any]) -> int:
    module_token = module.removesuffix("_abi")
    count = 0
    for batch in feature_gaps.get("batches", []):
        if not isinstance(batch, dict):
            continue
        text = json.dumps(batch, sort_keys=True)
        if module in text or module_token in text:
            count += int(batch.get("gap_count", 1))
    if count >= 8:
        return 3
    if count >= 3:
        return 2
    if count > 0:
        return 1
    return 0


def hard_parts_risk_for_module(module: str, hard_parts: dict[str, Any]) -> list[str]:
    module_token = module.removesuffix("_abi")
    tags = []
    for row in hard_parts.get("subsystems", []):
        if not isinstance(row, dict):
            continue
        text = json.dumps(row, sort_keys=True)
        if module_token in text or module in text:
            tags.append(str(row.get("id", module_token)))
    return sorted(set(tags))


def build_campaign(
    module: str,
    policy: CampaignPolicy,
    family: dict[str, Any],
    symbol_rows: dict[tuple[str, str], dict[str, Any]],
    support_module_set: set[str],
    semantic_join: dict[str, Any],
    hard_parts: dict[str, Any],
    feature_gaps: dict[str, Any],
) -> dict[str, Any]:
    if module not in support_module_set:
        raise ValueError(f"{module}: campaign module is missing from support_matrix")
    first_wave = first_wave_symbols(module, family, symbol_rows)
    target_total = int(family.get("target_total", 0))
    target_covered = int(family.get("target_covered", 0))
    target_uncovered = int(family.get("target_uncovered", 0))
    semantic_risk = semantic_risk_for_module(module, semantic_join)
    feature_gap_risk = feature_gap_risk_for_module(module, feature_gaps)
    hard_parts_tags = hard_parts_risk_for_module(module, hard_parts)
    parity_risk = min(5, max(policy.parity_risk_score, semantic_risk + feature_gap_risk))
    coverage_gap = min(target_uncovered, 200)
    priority = (
        coverage_gap
        + 300 * policy.workload_risk_score
        + 200 * parity_risk
        - 50 * policy.implementation_complexity_score
    )
    risk_tags = sorted(set(policy.risk_tags + tuple(hard_parts_tags)))
    return {
        "campaign_id": policy.campaign_id,
        "current_coverage_pct": family.get("target_coverage_pct"),
        "deterministic_e2e_scripts": list(policy.deterministic_e2e_scripts),
        "expected_coverage_after_first_wave_pct": pct(
            target_covered + len(first_wave), target_total
        ),
        "first_wave_fixture_count": len(first_wave),
        "first_wave_symbols": first_wave,
        "module": module,
        "next_step": policy.next_step,
        "oracle_kind": policy.oracle_kind,
        "risk_tags": risk_tags,
        "scores": {
            "coverage_gap_score": coverage_gap,
            "feature_gap_risk_score": feature_gap_risk,
            "hard_parts_risk_tags": hard_parts_tags,
            "implementation_complexity_score": policy.implementation_complexity_score,
            "parity_risk_score": parity_risk,
            "priority_score": priority,
            "semantic_risk_score": semantic_risk,
            "workload_risk_score": policy.workload_risk_score,
        },
        "structured_log_fields": "required_log_fields",
        "symbol_family": policy.symbol_family,
        "target_covered": target_covered,
        "target_total": target_total,
        "target_uncovered": target_uncovered,
        "title": policy.title,
        "workload_domains": list(policy.workload_domains),
    }


def build_deferred(module: str, family: dict[str, Any]) -> dict[str, Any]:
    reason, next_step = DEFERRED_NOTES.get(
        module,
        (
            "Not selected for the first fixture campaign because its workload or parity risk is lower than the ranked first-wave families, but uncovered symbols remain tracked.",
            "Create a follow-up fixture campaign after the first-wave queue has produced direct and isolated execution evidence.",
        ),
    )
    return {
        "module": module,
        "target_total": int(family.get("target_total", 0)),
        "target_covered": int(family.get("target_covered", 0)),
        "target_uncovered": int(family.get("target_uncovered", 0)),
        "current_coverage_pct": family.get("target_coverage_pct"),
        "status_breakdown": family.get("status_breakdown", {}),
        "coverage_state": coverage_state(family),
        "deferral_reason": reason,
        "next_step": next_step,
    }


def build_payload(root: Path, paths: dict[str, str]) -> dict[str, Any]:
    data = {key: load_json(root / rel_path) for key, rel_path in paths.items() if rel_path.endswith(".json")}
    validate_inputs(root, paths, data)
    families = indexed_families(data["symbol_fixture_coverage"])
    symbol_rows = per_symbol_index(data["per_symbol_fixture_tests"])
    support_module_set = support_modules(data["support_matrix"])

    campaigns = []
    for module, policy in sorted(CAMPAIGN_POLICIES.items()):
        family = families.get(module)
        if family is None or int(family.get("target_uncovered", 0)) <= 0:
            continue
        campaigns.append(
            build_campaign(
                module,
                policy,
                family,
                symbol_rows,
                support_module_set,
                data["semantic_contract_join"],
                data["hard_parts_truth_table"],
                data["feature_parity_gap_groups"],
            )
        )

    campaigns.sort(
        key=lambda row: (
            -int(row["scores"]["priority_score"]),
            -int(row["target_uncovered"]),
            str(row["module"]),
        )
    )
    for index, campaign in enumerate(campaigns, start=1):
        campaign["rank"] = index

    selected_modules = {campaign["module"] for campaign in campaigns}
    deferred_modules = []
    for module, family in families.items():
        if int(family.get("target_uncovered", 0)) > 0 and module not in selected_modules:
            deferred_modules.append(build_deferred(module, family))
    deferred_modules.sort(key=lambda row: (-row["target_uncovered"], row["module"]))

    first_wave_total = sum(int(campaign["first_wave_fixture_count"]) for campaign in campaigns)
    selected_uncovered = sum(int(campaign["target_uncovered"]) for campaign in campaigns)
    deferred_uncovered = sum(int(row["target_uncovered"]) for row in deferred_modules)
    campaign_domains = {
        domain for campaign in campaigns for domain in campaign["workload_domains"]
    }
    required_domains = sorted(
        data["user_workload_acceptance_matrix"].get("required_domains", [])
    )
    missing_required_domains = sorted(set(required_domains) - campaign_domains)
    if missing_required_domains:
        raise ValueError(
            "campaign policies do not cover required workload domains: "
            + ", ".join(missing_required_domains)
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "bead": BEAD_ID,
        "generated_at_utc": latest_generated_at(
            data,
            exclude={
                "per_symbol_fixture_tests",
            },
        ),
        "purpose": "Rank fixture campaigns by exported-symbol coverage gain, real workload risk, semantic parity risk, hard-parts exposure, and implementation complexity so coverage expansion is countable and user-driven.",
        "inputs": paths,
        "scoring_policy": {
            "coverage_gap_score": "min(target_uncovered, 200)",
            "priority_score": "coverage_gap_score + 300 * workload_risk_score + 200 * parity_risk_score - 50 * implementation_complexity_score",
            "workload_risk_score_range": [0, 5],
            "parity_risk_score_range": [0, 5],
            "implementation_complexity_score_range": [1, 5],
            "sort_order": "priority_score_desc_then_target_uncovered_desc_then_module_asc",
            "risk_inputs": {
                "version_script_exports": paths["version_script"],
                "abi_symbol_universe": paths["abi_symbol_universe"],
                "support_matrix_statuses": paths["support_matrix"],
                "semantic_overlay": paths["semantic_overlay"],
                "semantic_contract_join": paths["semantic_contract_join"],
                "fixture_inventory": paths["symbol_fixture_coverage"],
                "per_symbol_fixture_quality": paths["per_symbol_fixture_tests"],
                "user_workload_matrix": paths["user_workload_acceptance_matrix"],
                "hard_parts_truth": paths["hard_parts_truth_table"],
                "hard_parts_failure_classes": paths["hard_parts_failure_matrix"],
                "historical_failure_groups": paths["feature_parity_gap_groups"],
            },
        },
        "required_log_fields": REQUIRED_LOG_FIELDS,
        "campaigns": campaigns,
        "deferred_modules": deferred_modules,
        "summary": {
            "campaign_count": len(campaigns),
            "deferred_module_count": len(deferred_modules),
            "total_first_wave_fixture_count": first_wave_total,
            "selected_target_uncovered_symbols": selected_uncovered,
            "deferred_target_uncovered_symbols": deferred_uncovered,
            "all_uncovered_target_symbols": selected_uncovered + deferred_uncovered,
            "covered_modules": sorted(selected_modules),
            "required_workload_domains_covered": required_domains,
            "highest_priority_campaign": campaigns[0]["campaign_id"] if campaigns else None,
            "lowest_priority_campaign": campaigns[-1]["campaign_id"] if campaigns else None,
        },
    }


def run_self_tests() -> None:
    def ensure(condition: bool, message: str) -> None:
        if not condition:
            raise AssertionError(message)

    synthetic_family = {
        "module": "string_abi",
        "target_total": 3,
        "target_covered": 1,
        "target_uncovered": 2,
        "target_coverage_pct": 33.33,
        "target_uncovered_symbols": ["a", "b"],
        "status_breakdown": {"Implemented": 3},
    }
    per_symbol = {
        ("string_abi", "a"): {"has_fixtures": False},
        ("string_abi", "b"): {"has_fixtures": False},
    }
    campaign = build_campaign(
        "string_abi",
        CAMPAIGN_POLICIES["string_abi"],
        synthetic_family,
        per_symbol,
        {"string_abi"},
        {"entries": []},
        {"subsystems": []},
        {"batches": []},
    )
    ensure(campaign["first_wave_symbols"] == ["a", "b"], "first-wave ordering")
    ensure(campaign["scores"]["coverage_gap_score"] == 2, "coverage gap score")
    ensure(campaign["scores"]["priority_score"] > 0, "positive priority")
    ensure(
        campaign["expected_coverage_after_first_wave_pct"] == 100.0,
        "first-wave coverage projection",
    )

    stale_per_symbol = {("string_abi", "a"): {"has_fixtures": True}}
    try:
        first_wave_symbols("string_abi", synthetic_family, stale_per_symbol)
    except ValueError as exc:
        ensure(
            "already has fixtures" in str(exc) or "missing" in str(exc),
            "stale fixture error message",
        )
    else:
        raise AssertionError("stale fixture inventory should fail")

    duplicate_report = {
        "per_symbol_report": [
            {"module": "m", "symbol": "x"},
            {"module": "m", "symbol": "x"},
        ]
    }
    try:
        per_symbol_index(duplicate_report)
    except ValueError as exc:
        ensure("duplicate per-symbol fixture rows" in str(exc), "duplicate row error")
    else:
        raise AssertionError("duplicate per-symbol rows should fail")

    ordered = sorted(
        [
            {"module": "b", "target_uncovered": 10, "scores": {"priority_score": 5}},
            {"module": "a", "target_uncovered": 1, "scores": {"priority_score": 6}},
        ],
        key=lambda row: (-row["scores"]["priority_score"], -row["target_uncovered"], row["module"]),
    )
    ensure([row["module"] for row in ordered] == ["a", "b"], "deterministic ordering")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="tests/conformance/fixture_coverage_prioritizer.v1.json")
    parser.add_argument("--check", action="store_true", help="Compare generated output with --output")
    parser.add_argument("--self-test", action="store_true", help="Run generator unit self-tests")
    for key, rel_path in DEFAULT_INPUTS.items():
        parser.add_argument(f"--{key.replace('_', '-')}", default=rel_path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_tests()
        print("generate_fixture_coverage_prioritizer: self-test PASS")
        return 0

    root = Path.cwd()
    paths = {
        key: getattr(args, key)
        for key in DEFAULT_INPUTS
    }
    payload = build_payload(root, paths)
    output = Path(args.output)
    text = canonical_json(payload)
    if args.check:
        try:
            existing = output.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: failed to read {output}: {exc}", file=sys.stderr)
            return 1
        if existing != text:
            print(f"ERROR: fixture coverage prioritizer drift detected for {output}", file=sys.stderr)
            return 1
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    print(
        json.dumps(
            {
                "trace_id": "bd-bp8fl.4.1-fixture-coverage-prioritizer-generator",
                "bead_id": BEAD_ID,
                "artifact_ref": str(output),
                "campaign_count": payload["summary"]["campaign_count"],
                "deferred_module_count": payload["summary"]["deferred_module_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
