#!/usr/bin/env bash
# check_standalone_replacement_artifact.sh -- forge/evidence gate for bd-srtkq
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${STANDALONE_REPLACEMENT_MANIFEST:-${ROOT}/tests/conformance/standalone_replacement_artifact.v1.json}"
COMPILER_RUNTIME_EXPERIMENT_MANIFEST="${STANDALONE_COMPILER_RUNTIME_EXPERIMENT_MANIFEST:-${ROOT}/tests/conformance/standalone_compiler_runtime_experiment.v1.json}"
HOST_DEPENDENCY_PROBE_PLAN="${STANDALONE_HOST_DEPENDENCY_PROBE_PLAN:-${ROOT}/tests/conformance/standalone_host_dependency_probe_plan.v1.json}"
PACKAGING="${ROOT}/tests/conformance/packaging_spec.json"
LEVELS="${ROOT}/tests/conformance/replacement_levels.json"
OUT_DIR="${STANDALONE_REPLACEMENT_OUT_DIR:-${ROOT}/target/standalone_replacement_artifact}"
CARGO_TARGET_DIR_VALUE="${STANDALONE_REPLACEMENT_CARGO_TARGET_DIR:-${OUT_DIR}/cargo-target}"
REPORT="${STANDALONE_REPLACEMENT_REPORT:-${ROOT}/target/conformance/standalone_replacement_artifact.report.json}"
LOG="${STANDALONE_REPLACEMENT_LOG:-${ROOT}/target/conformance/standalone_replacement_artifact.log.jsonl}"
COMPILER_RUNTIME_EXPERIMENT_REPORT="${STANDALONE_COMPILER_RUNTIME_EXPERIMENT_REPORT:-${ROOT}/target/conformance/standalone_compiler_runtime_experiment.report.json}"
COMPILER_RUNTIME_EXPERIMENT_LOG="${STANDALONE_COMPILER_RUNTIME_EXPERIMENT_LOG:-${ROOT}/target/conformance/standalone_compiler_runtime_experiment.log.jsonl}"
COMPILER_RUNTIME_EXPERIMENT_TARGET_ROOT="${STANDALONE_COMPILER_RUNTIME_EXPERIMENT_TARGET_ROOT:-${OUT_DIR}/compiler-runtime-experiment-targets}"
OWNED_UNWIND_EXPERIMENT_MANIFEST="${STANDALONE_OWNED_UNWIND_EXPERIMENT_MANIFEST:-${ROOT}/tests/conformance/standalone_owned_unwind_experiment.v1.json}"
OWNED_UNWIND_EXPERIMENT_REPORT="${STANDALONE_OWNED_UNWIND_EXPERIMENT_REPORT:-${ROOT}/target/conformance/standalone_owned_unwind_experiment.report.json}"
OWNED_UNWIND_EXPERIMENT_LOG="${STANDALONE_OWNED_UNWIND_EXPERIMENT_LOG:-${ROOT}/target/conformance/standalone_owned_unwind_experiment.log.jsonl}"
OWNED_UNWIND_EXPERIMENT_TARGET_ROOT="${STANDALONE_OWNED_UNWIND_EXPERIMENT_TARGET_ROOT:-${OUT_DIR}/owned-unwind-experiment-targets}"
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
  --compiler-runtime-experiment)
    MODE="compiler-runtime-experiment"
    ;;
  --owned-unwind-experiment)
    MODE="owned-unwind-experiment"
    ;;
  *)
    echo "usage: $0 [--check|--forge|--validate-only|--compiler-runtime-experiment|--owned-unwind-experiment]" >&2
    exit 2
    ;;
esac

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")" "${CARGO_TARGET_DIR_VALUE}/release" "$(dirname "${COMPILER_RUNTIME_EXPERIMENT_REPORT}")" "$(dirname "${COMPILER_RUNTIME_EXPERIMENT_LOG}")" "${COMPILER_RUNTIME_EXPERIMENT_TARGET_ROOT}" "$(dirname "${OWNED_UNWIND_EXPERIMENT_REPORT}")" "$(dirname "${OWNED_UNWIND_EXPERIMENT_LOG}")" "${OWNED_UNWIND_EXPERIMENT_TARGET_ROOT}"

python3 - "${ROOT}" "${MANIFEST}" "${PACKAGING}" "${LEVELS}" "${OUT_DIR}" "${CARGO_TARGET_DIR_VALUE}" "${REPORT}" "${LOG}" "${MODE}" "${COMPILER_RUNTIME_EXPERIMENT_MANIFEST}" "${COMPILER_RUNTIME_EXPERIMENT_REPORT}" "${COMPILER_RUNTIME_EXPERIMENT_LOG}" "${COMPILER_RUNTIME_EXPERIMENT_TARGET_ROOT}" "${HOST_DEPENDENCY_PROBE_PLAN}" "${OWNED_UNWIND_EXPERIMENT_MANIFEST}" "${OWNED_UNWIND_EXPERIMENT_REPORT}" "${OWNED_UNWIND_EXPERIMENT_LOG}" "${OWNED_UNWIND_EXPERIMENT_TARGET_ROOT}" <<'PY'
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
compiler_runtime_manifest_path = Path(sys.argv[10])
compiler_runtime_report_path = Path(sys.argv[11])
compiler_runtime_log_path = Path(sys.argv[12])
compiler_runtime_target_root = Path(sys.argv[13])
host_dependency_probe_plan_path = Path(sys.argv[14])
owned_unwind_manifest_path = Path(sys.argv[15])
owned_unwind_report_path = Path(sys.argv[16])
owned_unwind_log_path = Path(sys.argv[17])
owned_unwind_target_root = Path(sys.argv[18])

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
    "artifact_state.dependency_breakdown.undefined_symbol_rows",
    "artifact_state.dependency_breakdown.undefined_unwind_symbols",
    "artifact_state.dependency_breakdown.undefined_glibc_symbols",
    "artifact_state.dependency_breakdown.undefined_tls_symbols",
    "artifact_state.dependency_breakdown.version_needs",
    "artifact_state.dependency_breakdown.host_version_requirements",
    "artifact_state.dependency_breakdown.host_version_requirement_rows",
    "artifact_state.dependency_breakdown.loader_needed",
    "artifact_state.dependency_breakdown.soname",
    "artifact_state.dependency_breakdown.rpath",
    "artifact_state.dependency_breakdown.runpath",
    "artifact_state.dependency_breakdown.dynamic_shape_valid",
    "artifact_state.dependency_breakdown.dynamic_shape_errors",
    "artifact_state.dependency_breakdown.blocking_reasons",
    "blocking_reasons",
    "artifact_state.dependency_breakdown.blocker_catalog",
    "artifact_state.dependency_breakdown.blocker_action_rows",
    "tool_evidence.*.exit_code",
    "tool_evidence.*.timed_out",
    "tool_evidence.*.timeout_secs",
    "tool_evidence.*.path",
    "artifact_state.dependency_breakdown.host_direct_needed_libraries",
    "artifact_state.dependency_breakdown.host_resolved_libraries",
    "artifact_state.dependency_breakdown.direct_host_needed_library_rows",
    "artifact_state.dependency_breakdown.host_resolved_library_rows",
    "artifact_state.sampled_symbols_present",
    "artifact_state.symbol_samples",
    "claim_status",
    "source_commit",
    "artifact_state.status",
    "artifact_state.failure_signature",
    "artifact_state.host_glibc_dependency",
    "artifact_state.elf_header.type",
    "artifact_state.elf_header.entry_point",
    "artifact_state.elf_header.entry_point_zero",
    "artifact_state.path",
    "artifact_state.sha256",
    "artifact_state.mtime",
    "build_provenance.rustc_version",
    "build_provenance.cargo_profile",
    "build_provenance.target_triple",
    "build_provenance.cargo_target_dir",
    "build_provenance.build_command",
    "build_provenance.sanitized_env",
    "build_provenance.linker.path",
    "build_provenance.linker.version",
    "blocker_delta.baseline_source",
    "blocker_delta.delta_classification",
    "blocker_delta.added_host_needed_libraries",
    "blocker_delta.added_host_direct_needed_libraries",
    "blocker_delta.added_host_resolved_libraries",
    "blocker_delta.added_undefined_symbols",
    "blocker_delta.added_version_requirements",
    "blocker_delta.removed_host_needed_libraries",
    "blocker_delta.removed_host_direct_needed_libraries",
    "blocker_delta.removed_host_resolved_libraries",
    "blocker_delta.removed_undefined_symbols",
    "blocker_delta.removed_version_requirements",
    "blocker_delta.refresh_required",
    "blocker_delta.refresh_note_present",
]

REQUIRED_TOOLS = ["rch", "cargo", "readelf", "nm", "ldd"]

REQUIRED_EVIDENCE_FILES = [
    "build.stdout.txt",
    "build.stderr.txt",
    "artifact.sha256",
    "artifact.readelf.header.txt",
    "artifact.readelf.dynamic.txt",
    "artifact.readelf.symbols.txt",
    "artifact.readelf.version.txt",
    "artifact.nm.dynamic.txt",
    "artifact.ldd.txt",
]

EXPECTED_MANIFEST_ID = "standalone-replacement-artifact"

EXPECTED_SOURCE_COMMIT_FRESHNESS_POLICY = {
    "recorded_source_commit_field": "source_commit",
    "comparison_target": "current git HEAD",
    "stale_result": "block_standalone_replacement_artifact_evidence",
    "standalone_artifact_evidence_allowed_when_stale": False,
    "rejected_evidence_kind": "stale_source_commit",
}

EXPECTED_INPUTS = {
    "packaging_spec": "tests/conformance/packaging_spec.json",
    "replacement_levels": "tests/conformance/replacement_levels.json",
    "standalone_host_dependency_probe_plan": "tests/conformance/standalone_host_dependency_probe_plan.v1.json",
    "standalone_link_run_smoke": "tests/conformance/standalone_link_run_smoke.v1.json",
}

EXPECTED_SUMMARY = {
    "bead": "bd-srtkq",
    "row_count": 1,
    "ld_preload_substitutes_for_standalone": False,
    "next_consumers": [
        "bd-4xk24",
        "tests/conformance/standalone_link_run_smoke.v1.json",
    ],
}

EXPECTED_HASH_EVIDENCE_POLICY = {
    "algorithm": "sha256",
    "implementation": "python3 hashlib.sha256",
    "reported_field": "artifact_state.sha256",
    "evidence_file": "artifact.sha256",
}

BUILD_PROVENANCE_ENV_KEYS = [
    "CARGO_PROFILE_RELEASE_PANIC",
    "RCH_REQUIRE_REMOTE",
    "RUSTFLAGS",
    "RUSTC_WRAPPER",
    "RCH_ENV_ALLOWLIST",
    "RCH_PRIORITY",
    "RCH_VISIBILITY",
    "RCH_QUEUE_WHEN_BUSY",
]
REDACTED_ENV_VALUE = "<redacted>"
EXPECTED_BUILD_PROVENANCE_POLICY = {
    "reported_field": "build_provenance",
    "rustc_version_command": "rustc -Vv",
    "target_triple_source": "CARGO_BUILD_TARGET or rustc host",
    "linker_discovery_order": [
        "CARGO_TARGET_<TRIPLE>_LINKER",
        "RUSTFLAGS -C linker=<path>",
        "cc",
    ],
    "sanitized_env_keys": BUILD_PROVENANCE_ENV_KEYS,
    "sensitive_env_values_redacted": True,
    "redacted_env_value": REDACTED_ENV_VALUE,
}

BLOCKER_DELTA_REFRESH_NOTE_ENV = "STANDALONE_REPLACEMENT_BLOCKER_DELTA_REFRESH_NOTE"
BLOCKER_DELTA_BASELINE_SOURCE = (
    "tests/conformance/standalone_host_dependency_probe_plan.v1.json"
    "#current_forge_blocker_projection.current_forge_blocker_value_snapshot"
)
EXPECTED_BLOCKER_DELTA_POLICY = {
    "reported_field": "blocker_delta",
    "baseline_source": BLOCKER_DELTA_BASELINE_SOURCE,
    "compared_fields": [
        "host_needed_libraries",
        "host_direct_needed_libraries",
        "host_resolved_libraries",
        "undefined_symbols",
        "version_needs",
    ],
    "added_values_classification": "regression",
    "added_values_result": "fail_closed",
    "removed_values_without_note_classification": "expected_refresh_needed",
    "removed_values_without_note_result": "fail_closed",
    "removed_values_with_note_classification": "improvement",
    "refresh_note_env": BLOCKER_DELTA_REFRESH_NOTE_ENV,
    "refresh_required_on_blocker_delta": True,
    "promotion_allowed": False,
}

EXPECTED_SYMBOL_SAMPLES = [
    "__libc_start_main",
    "malloc",
    "free",
    "printf",
    "pthread_create",
    "getaddrinfo",
]

EXPECTED_ARTIFACT_POLICY = {
    "canonical_artifact_name": "libfrankenlibc_replace.so",
    "source_cdylib_name": "libfrankenlibc_abi.so",
    "cargo_package": "frankenlibc-abi",
    "cargo_profile": "release",
    "cargo_features": ["standalone", "owned-unwind-stub", "owned-tls-cache"],
    "build_std_components": ["std", "panic_abort"],
    "panic_strategy": "immediate-abort",
    "default_cargo_target_dir": "target/standalone_replacement_artifact/cargo-target",
    "default_build_command": [
        "rch",
        "exec",
        "--",
        "cargo",
        "build",
        "-Z",
        "build-std=std,panic_abort",
        "-p",
        "frankenlibc-abi",
        "--release",
        "--features=standalone,owned-unwind-stub,owned-tls-cache",
    ],
    "default_build_env": {
        "CARGO_PROFILE_RELEASE_PANIC": "immediate-abort",
        "RCH_REQUIRE_REMOTE": "1",
    },
    "default_remote_env_allowlist": [
        "CARGO_TARGET_DIR",
        "CARGO_PROFILE_RELEASE_PANIC",
    ],
    "artifact_env": "FRANKENLIBC_STANDALONE_LIB",
    "source_artifact_env": "STANDALONE_REPLACEMENT_SOURCE_LIB",
    "cargo_target_dir_env": "STANDALONE_REPLACEMENT_CARGO_TARGET_DIR",
    "build_command_env": "STANDALONE_REPLACEMENT_BUILD_CMD",
    "skip_build_env": "STANDALONE_REPLACEMENT_SKIP_BUILD",
    "stale_if_older_than_head": True,
    "ld_preload_substitutes_allowed": False,
}
DEFAULT_BUILD_COMMAND = EXPECTED_ARTIFACT_POLICY["default_build_command"]
DEFAULT_BUILD_ENV = EXPECTED_ARTIFACT_POLICY["default_build_env"]
DEFAULT_REMOTE_ENV_ALLOWLIST = EXPECTED_ARTIFACT_POLICY["default_remote_env_allowlist"]

EXPECTED_COMPILER_RUNTIME_EXPERIMENT_MANIFEST_ID = "standalone-compiler-runtime-experiment"
EXPECTED_COMPILER_RUNTIME_EXPERIMENT_POLICY = {
    "report_only": True,
    "promotion_allowed": False,
    "replacement_level_change_allowed": False,
    "default_forge_path_change_allowed": False,
    "default_build_profile_change_allowed": False,
    "non_baseline_lanes_require_explicit_mode": True,
    "required_mode": "--compiler-runtime-experiment",
    "stale_result": "block_compiler_runtime_experiment_refresh",
}
EXPECTED_COMPILER_RUNTIME_EXPERIMENT_INPUTS = {
    "standalone_replacement_artifact": "tests/conformance/standalone_replacement_artifact.v1.json",
    "standalone_compiler_runtime_blocker_diagnostics": "tests/conformance/standalone_compiler_runtime_blocker_diagnostics.v1.json",
    "standalone_host_dependency_probe_plan": "tests/conformance/standalone_host_dependency_probe_plan.v1.json",
}
EXPECTED_COMPILER_RUNTIME_EXPERIMENT_REQUIRED_REPORT_FIELDS = [
    "lanes.*.lane_id",
    "lanes.*.build_command",
    "lanes.*.cargo_target_dir",
    "lanes.*.needed_libraries",
    "lanes.*.undefined_unwind_symbols",
    "lanes.*.version_needs",
    "lanes.*.claim_status",
    "comparison.baseline_lane",
    "comparison.experiment_lane",
    "comparison.removed_needed_libraries",
    "comparison.added_needed_libraries",
    "comparison.removed_undefined_unwind_symbols",
    "comparison.added_undefined_unwind_symbols",
    "comparison.removed_version_requirements",
    "comparison.added_version_requirements",
    "comparison.delta_classification",
]
EXPECTED_COMPILER_RUNTIME_EXPERIMENT_LANES = [
    {
        "lane_id": "baseline-release-standalone",
        "role": "baseline",
        "cargo_target_dir_suffix": "baseline-release-standalone",
        "build_command": [
            "rch",
            "exec",
            "--",
            "cargo",
            "build",
            "-p",
            "frankenlibc-abi",
            "--release",
            "--features=standalone",
        ],
        "panic_strategy": "implicit-unwind",
        "env": {},
        "report_only": True,
        "expected_claim_status": "claim_blocked",
        "must_not_change_default_profile": True,
    },
    {
        "lane_id": "panic-abort-compiler-runtime-minimized",
        "role": "experiment",
        "cargo_target_dir_suffix": "panic-abort-compiler-runtime-minimized",
        "build_command": [
            "rch",
            "exec",
            "--",
            "cargo",
            "build",
            "-p",
            "frankenlibc-abi",
            "--release",
            "--features=standalone",
        ],
        "panic_strategy": "abort",
        "env": {"CARGO_PROFILE_RELEASE_PANIC": "abort"},
        "report_only": True,
        "expected_claim_status": "report_only",
        "must_not_change_default_profile": True,
    },
]
EXPECTED_COMPILER_RUNTIME_EXPERIMENT_SUMMARY = {
    "bead": "bd-zyck1.88",
    "lane_count": 2,
    "baseline_lane": "baseline-release-standalone",
    "experiment_lane": "panic-abort-compiler-runtime-minimized",
    "report_only": True,
    "default_forge_path_unchanged": True,
}

EXPECTED_OWNED_UNWIND_EXPERIMENT_MANIFEST_ID = "standalone-owned-unwind-experiment"
EXPECTED_OWNED_UNWIND_EXPERIMENT_POLICY = {
    "report_only": True,
    "promotion_allowed": False,
    "replacement_level_change_allowed": False,
    "default_forge_path_change_allowed": False,
    "default_build_profile_change_allowed": False,
    "panic_strategy_change_allowed_on_baseline": False,
    "non_baseline_lanes_require_explicit_mode": True,
    "required_mode": "--owned-unwind-experiment",
    "claim_status_until_all_symbols_exit": "claim_blocked",
}
EXPECTED_OWNED_UNWIND_EXPERIMENT_LANES = [
    {
        "lane_id": "baseline-release-standalone",
        "role": "baseline",
        "panic_strategy": "implicit-unwind",
        "expected_claim_status": "claim_blocked",
    },
    {
        "lane_id": "panic-abort-compiler-runtime-minimized",
        "role": "comparison",
        "panic_strategy": "abort",
        "expected_claim_status": "report_only",
    },
    {
        "lane_id": "owned-unwind-stub-experiment",
        "role": "experiment",
        "panic_strategy": "abort",
        "expected_claim_status": "report_only",
    },
]
EXPECTED_OWNED_UNWIND_EXPERIMENT_SUMMARY = {
    "bead": "bd-juvqm.4",
    "lane_count": 3,
    "baseline_lane": "baseline-release-standalone",
    "experiment_lane": "owned-unwind-stub-experiment",
    "report_only": True,
    "default_forge_path_unchanged": True,
}
EXPECTED_OWNED_UNWIND_LIVE_DEPENDENCY_CONTRACT = {
    "lane_id": "owned-unwind-stub-experiment",
    "expected_undefined_unwind_symbol_count": 0,
    "forbidden_needed_libraries": ["libgcc_s.so.1"],
    "forbidden_version_providers": ["libgcc_s.so.1"],
    "forbidden_undefined_symbol_prefixes": ["_Unwind_"],
    "status_on_violation": "fail_closed",
    "promotion_allowed_on_pass": False,
}
OWNED_UNWIND_SYMBOL_COUNT = 12

EXPECTED_FAILURE_CLASSIFICATIONS = {
    "standalone_artifact_missing": "claim_blocked",
    "standalone_artifact_stale": "claim_blocked",
    "wrong_artifact_profile": "claim_blocked",
    "non_elf_artifact": "fail",
    "host_glibc_dependency": "claim_blocked",
    "artifact_dynamic_shape_invalid": "claim_blocked",
    "artifact_dependency_inspection_failed": "claim_blocked",
    "symbol_evidence_missing": "claim_blocked",
    "rch_local_fallback": "claim_blocked",
}

EXPECTED_CLAIM_POLICY = {
    "current_level_must_remain": "L1",
    "successful_forge_is_not_promotion": True,
    "claim_unblocked_only_when": [
        "artifact_status=current",
        "artifact_name=libfrankenlibc_replace.so",
        "readelf_dynamic_status=pass",
        "ldd_status=pass",
        "host_glibc_dependency=false",
        "sampled_symbols_present=true",
        "source_commit matches HEAD",
    ],
}

BLOCKER_CATALOG_DEFINITIONS = {
    "host_needed_libraries_present": {
        "owner_surface": "runtime_linkage",
        "severity": "claim_blocking",
        "evidence_fields": ["host_needed_libraries"],
        "next_action": "Remove every host runtime library from NEEDED and ldd evidence before treating the artifact as standalone.",
    },
    "host_direct_needed_libraries_present": {
        "owner_surface": "direct_dynamic_dependencies",
        "severity": "claim_blocking",
        "evidence_fields": ["host_direct_needed_libraries", "needed_libraries"],
        "next_action": "Eliminate direct NEEDED edges to host runtime libraries from the replacement cdylib link.",
    },
    "host_resolved_libraries_present": {
        "owner_surface": "loader_resolution",
        "severity": "claim_blocking",
        "evidence_fields": ["host_resolved_libraries", "ldd_libraries"],
        "next_action": "Make the loader resolve no host runtime libraries for the candidate replacement artifact.",
    },
    "host_loader_dependency": {
        "owner_surface": "loader_startup",
        "severity": "claim_blocking",
        "evidence_fields": ["loader_needed", "needed_libraries", "ldd_libraries"],
        "next_action": "Replace host loader/startup dependency with owned CRT, dynamic loader, and init/fini evidence.",
    },
    "host_libc_dependency": {
        "owner_surface": "libc_surface",
        "severity": "claim_blocking",
        "evidence_fields": ["host_needed_libraries", "host_resolved_libraries"],
        "next_action": "Remove host libc resolution from the replacement artifact and rerun direct-link smoke evidence.",
    },
    "libgcc_runtime_dependency": {
        "owner_surface": "compiler_runtime",
        "severity": "claim_blocking",
        "evidence_fields": ["needed_libraries", "host_needed_libraries", "version_needs"],
        "next_action": "Burn down libgcc runtime dependence or document an owned compiler-runtime substitute for replacement mode.",
    },
    "undefined_unwind_symbols": {
        "owner_surface": "unwind_runtime",
        "severity": "claim_blocking",
        "evidence_fields": ["undefined_unwind_symbols", "undefined_symbols"],
        "next_action": "Provide owned unwinder/personality symbols or prove the standalone artifact has no unresolved unwind edges.",
    },
    "undefined_glibc_symbols": {
        "owner_surface": "glibc_symbol_surface",
        "severity": "claim_blocking",
        "evidence_fields": ["undefined_glibc_symbols", "undefined_symbols"],
        "next_action": "Implement or eliminate unresolved GLIBC-versioned symbols before accepting standalone replacement evidence.",
    },
    "undefined_tls_symbols": {
        "owner_surface": "tls_startup",
        "severity": "claim_blocking",
        "evidence_fields": ["undefined_tls_symbols", "undefined_symbols"],
        "next_action": "Provide owned TLS access/startup support or prove no __tls_get_addr dependency remains.",
    },
    "host_version_requirements": {
        "owner_surface": "symbol_versioning",
        "severity": "claim_blocking",
        "evidence_fields": ["host_version_requirements", "version_needs"],
        "next_action": "Remove host-provided version needs or bind them to owned version nodes in the replacement artifact.",
    },
}

BLOCKER_ACTION_PRIMARY_PROBE_IDS = {
    "host_needed_libraries_present": "readelf_dynamic_dependencies",
    "host_direct_needed_libraries_present": "readelf_dynamic_dependencies",
    "host_resolved_libraries_present": "ldd_runtime_resolution",
    "host_loader_dependency": "ldd_runtime_resolution",
    "host_libc_dependency": "ldd_runtime_resolution",
    "libgcc_runtime_dependency": "readelf_dynamic_dependencies",
    "undefined_unwind_symbols": "nm_dynamic_undefined_symbols",
    "undefined_glibc_symbols": "nm_dynamic_undefined_symbols",
    "undefined_tls_symbols": "nm_dynamic_undefined_symbols",
    "host_version_requirements": "readelf_version_needs",
}

BLOCKER_ACTION_EXIT_CRITERIA = {
    "host_needed_libraries_present": [
        "artifact_state.dependency_breakdown.host_needed_libraries is empty",
        "blocking_reasons omits host_needed_libraries_present",
    ],
    "host_direct_needed_libraries_present": [
        "artifact_state.dependency_breakdown.host_direct_needed_libraries is empty",
        "blocking_reasons omits host_direct_needed_libraries_present",
    ],
    "host_resolved_libraries_present": [
        "artifact_state.dependency_breakdown.host_resolved_libraries is empty",
        "blocking_reasons omits host_resolved_libraries_present",
    ],
    "host_loader_dependency": [
        "artifact_state.dependency_breakdown.host_needed_libraries contains no loader path",
        "blocking_reasons omits host_loader_dependency",
    ],
    "host_libc_dependency": [
        "artifact_state.dependency_breakdown.host_needed_libraries contains no libc.so entry",
        "blocking_reasons omits host_libc_dependency",
    ],
    "libgcc_runtime_dependency": [
        "artifact_state.dependency_breakdown.host_needed_libraries contains no libgcc_s entry",
        "artifact_state.dependency_breakdown.host_version_requirements contains no libgcc_s entry",
        "blocking_reasons omits libgcc_runtime_dependency",
    ],
    "undefined_unwind_symbols": [
        "artifact_state.dependency_breakdown.undefined_unwind_symbols is empty",
        "blocking_reasons omits undefined_unwind_symbols",
    ],
    "undefined_glibc_symbols": [
        "artifact_state.dependency_breakdown.undefined_glibc_symbols is empty",
        "blocking_reasons omits undefined_glibc_symbols",
    ],
    "undefined_tls_symbols": [
        "artifact_state.dependency_breakdown.undefined_tls_symbols is empty",
        "blocking_reasons omits undefined_tls_symbols",
    ],
    "host_version_requirements": [
        "artifact_state.dependency_breakdown.host_version_requirements is empty",
        "blocking_reasons omits host_version_requirements",
    ],
}
EXPECTED_BLOCKER_CATALOG_CONTRACT = {
    "required_row_fields": [
        "owner_surface",
        "severity",
        "evidence_fields",
        "next_action",
    ],
    "definitions": BLOCKER_CATALOG_DEFINITIONS,
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
host_dependency_probe_plan = load_json(host_dependency_probe_plan_path)
compiler_runtime_manifest = (
    load_json(compiler_runtime_manifest_path)
    if mode == "compiler-runtime-experiment"
    else {}
)
owned_unwind_manifest = (
    load_json(owned_unwind_manifest_path)
    if mode == "owned-unwind-experiment"
    else {}
)
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


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def unique_sorted(values):
    return sorted({value for value in values if value})


def env_key_fragment(value):
    return re.sub(r"[^A-Z0-9]+", "_", str(value).upper()).strip("_")


def flatten_version_needs(version_needs):
    if not isinstance(version_needs, dict):
        return []
    return unique_sorted(
        f"{provider}:{version}"
        for provider, versions in version_needs.items()
        if isinstance(versions, list)
        for version in versions
    )


def set_delta(before, after):
    before_set = set(before)
    after_set = set(after)
    return unique_sorted(before_set - after_set), unique_sorted(after_set - before_set)


def string_list(value):
    if not isinstance(value, list):
        return []
    return unique_sorted(str(item) for item in value if isinstance(item, str) and item)


def forge_blocker_snapshot():
    projection = host_dependency_probe_plan.get("current_forge_blocker_projection", {})
    if not isinstance(projection, dict):
        return {}
    snapshot = projection.get("current_forge_blocker_value_snapshot", {})
    return snapshot if isinstance(snapshot, dict) else {}


def snapshot_undefined_symbols(snapshot):
    explicit = string_list(snapshot.get("undefined_symbols"))
    if explicit:
        return explicit
    return unique_sorted(
        [
            *string_list(snapshot.get("undefined_unwind_symbols")),
            *string_list(snapshot.get("undefined_glibc_symbols")),
            *string_list(snapshot.get("undefined_tls_symbols")),
        ]
    )


def blocker_delta_not_checked(reason):
    return {
        "status": "not_checked",
        "delta_classification": "not_checked",
        "reason": reason,
        "baseline_source": BLOCKER_DELTA_BASELINE_SOURCE,
        "compared_fields": EXPECTED_BLOCKER_DELTA_POLICY["compared_fields"],
        "baseline_source_commit": None,
        "current_source_commit": source_commit,
        "baseline_host_needed_libraries": [],
        "current_host_needed_libraries": [],
        "added_host_needed_libraries": [],
        "removed_host_needed_libraries": [],
        "baseline_host_direct_needed_libraries": [],
        "current_host_direct_needed_libraries": [],
        "added_host_direct_needed_libraries": [],
        "removed_host_direct_needed_libraries": [],
        "baseline_host_resolved_libraries": [],
        "current_host_resolved_libraries": [],
        "added_host_resolved_libraries": [],
        "removed_host_resolved_libraries": [],
        "baseline_undefined_symbols": [],
        "current_undefined_symbols": [],
        "added_undefined_symbols": [],
        "removed_undefined_symbols": [],
        "baseline_version_requirements": [],
        "current_version_requirements": [],
        "added_version_requirements": [],
        "removed_version_requirements": [],
        "refresh_required": False,
        "refresh_note_env": BLOCKER_DELTA_REFRESH_NOTE_ENV,
        "refresh_note_present": False,
        "promotion_allowed": False,
    }


def build_blocker_delta(artifact_state):
    active = (
        artifact_state.get("status") == "current"
        and artifact_state.get("sampled_symbols_present") is True
    )
    if not active:
        return blocker_delta_not_checked(
            "artifact must be current with sampled symbol evidence before blocker deltas are comparable"
        )

    snapshot = forge_blocker_snapshot()
    if not snapshot:
        delta = blocker_delta_not_checked("committed forge blocker snapshot is missing")
        delta["status"] = "fail"
        delta["delta_classification"] = "snapshot_missing"
        delta["refresh_required"] = True
        return delta

    breakdown = artifact_state.get("dependency_breakdown", {})
    if not isinstance(breakdown, dict):
        breakdown = {}

    baseline_host = string_list(snapshot.get("host_needed_libraries"))
    current_host = string_list(breakdown.get("host_needed_libraries"))
    removed_host, added_host = set_delta(baseline_host, current_host)

    baseline_direct = string_list(snapshot.get("host_direct_needed_libraries"))
    current_direct = string_list(breakdown.get("host_direct_needed_libraries"))
    removed_direct, added_direct = set_delta(baseline_direct, current_direct)

    baseline_resolved = string_list(snapshot.get("host_resolved_libraries"))
    current_resolved = string_list(breakdown.get("host_resolved_libraries"))
    removed_resolved, added_resolved = set_delta(baseline_resolved, current_resolved)

    baseline_undefined = snapshot_undefined_symbols(snapshot)
    current_undefined = string_list(breakdown.get("undefined_symbols"))
    removed_undefined, added_undefined = set_delta(baseline_undefined, current_undefined)

    baseline_versions = flatten_version_needs(snapshot.get("version_needs"))
    current_versions = flatten_version_needs(breakdown.get("version_needs"))
    removed_versions, added_versions = set_delta(baseline_versions, current_versions)

    added_any = bool(
        added_host
        or added_direct
        or added_resolved
        or added_undefined
        or added_versions
    )
    removed_any = bool(
        removed_host
        or removed_direct
        or removed_resolved
        or removed_undefined
        or removed_versions
    )
    refresh_note = os.environ.get(BLOCKER_DELTA_REFRESH_NOTE_ENV, "").strip()
    if added_any:
        classification = "regression"
        status_value = "fail"
        refresh_required = True
    elif removed_any and not refresh_note:
        classification = "expected_refresh_needed"
        status_value = "fail"
        refresh_required = True
    elif removed_any:
        classification = "improvement"
        status_value = "pass"
        refresh_required = False
    else:
        classification = "unchanged"
        status_value = "pass"
        refresh_required = False

    return {
        "status": status_value,
        "delta_classification": classification,
        "reason": "compared live forge blocker values against committed snapshot",
        "baseline_source": BLOCKER_DELTA_BASELINE_SOURCE,
        "compared_fields": EXPECTED_BLOCKER_DELTA_POLICY["compared_fields"],
        "baseline_source_commit": snapshot.get("source_commit"),
        "current_source_commit": source_commit,
        "baseline_host_needed_libraries": baseline_host,
        "current_host_needed_libraries": current_host,
        "added_host_needed_libraries": added_host,
        "removed_host_needed_libraries": removed_host,
        "baseline_host_direct_needed_libraries": baseline_direct,
        "current_host_direct_needed_libraries": current_direct,
        "added_host_direct_needed_libraries": added_direct,
        "removed_host_direct_needed_libraries": removed_direct,
        "baseline_host_resolved_libraries": baseline_resolved,
        "current_host_resolved_libraries": current_resolved,
        "added_host_resolved_libraries": added_resolved,
        "removed_host_resolved_libraries": removed_resolved,
        "baseline_undefined_symbols": baseline_undefined,
        "current_undefined_symbols": current_undefined,
        "added_undefined_symbols": added_undefined,
        "removed_undefined_symbols": removed_undefined,
        "baseline_version_requirements": baseline_versions,
        "current_version_requirements": current_versions,
        "added_version_requirements": added_versions,
        "removed_version_requirements": removed_versions,
        "refresh_required": refresh_required,
        "refresh_note_env": BLOCKER_DELTA_REFRESH_NOTE_ENV,
        "refresh_note_present": bool(refresh_note),
        "promotion_allowed": False,
    }


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
        "direct_host_needed_library_rows": [],
        "host_resolved_library_rows": [],
        "undefined_symbols": [],
        "undefined_symbol_rows": [],
        "undefined_unwind_symbols": [],
        "undefined_glibc_symbols": [],
        "undefined_tls_symbols": [],
        "version_needs": {},
        "host_version_requirements": [],
        "host_version_requirement_rows": [],
        "loader_needed": False,
        "soname": None,
        "rpath": [],
        "runpath": [],
        "dynamic_shape_valid": None,
        "dynamic_shape_errors": [],
        "libc_needed": False,
        "libgcc_needed": False,
        "blocking_reasons": [],
        "blocker_catalog": {},
        "blocker_action_rows": [],
    }


def empty_elf_header():
    return {
        "type": None,
        "entry_point": None,
        "entry_point_zero": None,
    }


def parse_elf_header(readelf_header_text):
    header = empty_elf_header()
    for line in readelf_header_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Type:"):
            header["type"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Entry point address:"):
            header["entry_point"] = stripped.split(":", 1)[1].strip()
    entry = header["entry_point"]
    if isinstance(entry, str) and entry:
        try:
            header["entry_point_zero"] = int(entry, 16) == 0
        except ValueError:
            header["entry_point_zero"] = False
    return header


def parse_needed_libraries(readelf_dynamic_text):
    return unique_sorted(
        match.group(1)
        for match in re.finditer(r"Shared library:\s*\[([^\]]+)\]", readelf_dynamic_text)
    )


def parse_dynamic_tag_values(readelf_dynamic_text, tag):
    return unique_sorted(
        match.group(1)
        for match in re.finditer(
            rf"\({re.escape(tag)}\)\s+[^\[]*\[([^\]]*)\]",
            readelf_dynamic_text,
        )
    )


def dynamic_shape_errors(elf_header, soname, rpath, runpath):
    errors = []
    header_type = elf_header.get("type")
    if not isinstance(header_type, str) or "DYN" not in header_type:
        errors.append("elf_header.type must be DYN shared object")
    if elf_header.get("entry_point_zero") is not True:
        errors.append("elf_header.entry_point must be 0x0 for a libc shared object")
    if soname not in {None, "", "libfrankenlibc_replace.so"}:
        errors.append("dynamic SONAME must be absent or libfrankenlibc_replace.so")
    if rpath:
        errors.append("dynamic section must not contain RPATH")
    if runpath:
        errors.append("dynamic section must not contain RUNPATH")
    return errors


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


def parse_ldd_resolution_paths(ldd_text):
    paths_by_library = {}
    for line in ldd_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("linux-vdso.so"):
            continue
        if "=>" in stripped:
            name, rest = stripped.split("=>", 1)
            name = name.strip()
            path = rest.strip().split()[0] if rest.strip() else ""
        else:
            parts = stripped.split()
            name = parts[0] if parts else ""
            path = name
        if name and name not in {"statically", "not"} and path:
            paths_by_library.setdefault(name, []).append(path)
    return {
        library: unique_sorted(paths)
        for library, paths in sorted(paths_by_library.items())
    }


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


def symbol_version_suffix(symbol):
    parts = symbol.split("@", 1)
    return parts[1] if len(parts) == 2 else None


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


def ldd_paths_for_library(library, ldd_resolution_paths):
    matches = []
    for name, paths in ldd_resolution_paths.items():
        name_base = Path(name).name
        for path in paths:
            path_base = Path(path).name
            if name == library or name_base == library or path_base == library:
                matches.append(path)
    return unique_sorted(matches)


def library_matches(left, right):
    left_base = Path(left).name
    right_base = Path(right).name
    return left == right or left_base == right or left == right_base or left_base == right_base


def matching_direct_needed_libraries(library, host_direct_needed_libraries):
    return unique_sorted(
        direct
        for direct in host_direct_needed_libraries
        if library_matches(library, direct)
    )


def version_requirements_for_library(library, version_needs):
    requirements = []
    for provider, versions in version_needs.items():
        if library_matches(library, provider):
            requirements.extend(f"{provider}:{version}" for version in versions)
    return unique_sorted(requirements)


def library_or_path_has_base(library, resolved_paths, base_prefix):
    candidates = [library, *resolved_paths]
    return any(Path(candidate).name.startswith(base_prefix) for candidate in candidates)


def library_or_path_contains(library, resolved_paths, needle):
    candidates = [library, *resolved_paths]
    return any(needle in candidate for candidate in candidates)


def direct_needed_blocking_reasons(library, resolved_paths, version_needs, blocking_reasons):
    reasons = []
    if "host_needed_libraries_present" in blocking_reasons:
        reasons.append("host_needed_libraries_present")
    if "host_direct_needed_libraries_present" in blocking_reasons:
        reasons.append("host_direct_needed_libraries_present")
    if resolved_paths and "host_resolved_libraries_present" in blocking_reasons:
        reasons.append("host_resolved_libraries_present")
    if "ld-linux" in library and "host_loader_dependency" in blocking_reasons:
        reasons.append("host_loader_dependency")
    if library.startswith("libc.so") and "host_libc_dependency" in blocking_reasons:
        reasons.append("host_libc_dependency")
    if library.startswith("libgcc_s.so") and "libgcc_runtime_dependency" in blocking_reasons:
        reasons.append("libgcc_runtime_dependency")
    if version_needs.get(library) and "host_version_requirements" in blocking_reasons:
        reasons.append("host_version_requirements")
    return reasons


def build_direct_host_needed_library_rows(
    host_direct_needed_libraries,
    ldd_resolution_paths,
    version_needs,
    blocking_reasons,
):
    direct_catalog = BLOCKER_CATALOG_DEFINITIONS["host_direct_needed_libraries_present"]
    rows = []
    for library in host_direct_needed_libraries:
        resolved_paths = ldd_paths_for_library(library, ldd_resolution_paths)
        versions = unique_sorted(version_needs.get(library, []))
        rows.append(
            {
                "library": library,
                "owner_surface": direct_catalog["owner_surface"],
                "primary_probe_id": "readelf_dynamic_dependencies",
                "direct_needed_present": True,
                "resolved_paths": resolved_paths,
                "version_requirements": [
                    f"{library}:{version}" for version in versions
                ],
                "blocking_reasons": direct_needed_blocking_reasons(
                    library, resolved_paths, version_needs, blocking_reasons
                ),
                "evidence_fields": direct_catalog["evidence_fields"],
                "next_action": direct_catalog["next_action"],
                "promotion_allowed": False,
            }
        )
    return rows


def symbol_blocking_reasons(
    symbol,
    undefined_unwind_symbols,
    undefined_glibc_symbols,
    undefined_tls_symbols,
    blocking_reasons,
):
    reasons = []
    if symbol in undefined_unwind_symbols and "undefined_unwind_symbols" in blocking_reasons:
        reasons.append("undefined_unwind_symbols")
    if symbol in undefined_glibc_symbols and "undefined_glibc_symbols" in blocking_reasons:
        reasons.append("undefined_glibc_symbols")
    if symbol in undefined_tls_symbols and "undefined_tls_symbols" in blocking_reasons:
        reasons.append("undefined_tls_symbols")
    return reasons


def primary_undefined_symbol_reason(symbol, symbol_reasons):
    base = symbol_base(symbol)
    if "undefined_tls_symbols" in symbol_reasons:
        return "undefined_tls_symbols"
    if "undefined_unwind_symbols" in symbol_reasons:
        return "undefined_unwind_symbols"
    if "undefined_glibc_symbols" in symbol_reasons:
        return "undefined_glibc_symbols"
    if base.startswith("_Unwind_") or base == "__gcc_personality_v0":
        return "undefined_unwind_symbols"
    if base == "__tls_get_addr" or "tls" in base.lower():
        return "undefined_tls_symbols"
    if "@GLIBC_" in symbol or base.startswith("__libc_"):
        return "undefined_glibc_symbols"
    return "undefined_symbols"


def undefined_symbol_evidence_fields(symbol_reasons):
    fields = []
    for reason in symbol_reasons:
        definition = BLOCKER_CATALOG_DEFINITIONS.get(reason)
        if definition:
            fields.extend(definition["evidence_fields"])
    return unique_sorted(fields or ["undefined_symbols"])


def build_undefined_symbol_rows(
    undefined_symbols,
    undefined_unwind_symbols,
    undefined_glibc_symbols,
    undefined_tls_symbols,
    blocking_reasons,
):
    rows = []
    for symbol in undefined_symbols:
        symbol_reasons = symbol_blocking_reasons(
            symbol,
            undefined_unwind_symbols,
            undefined_glibc_symbols,
            undefined_tls_symbols,
            blocking_reasons,
        )
        primary_reason = primary_undefined_symbol_reason(symbol, symbol_reasons)
        primary_catalog = BLOCKER_CATALOG_DEFINITIONS.get(primary_reason, {})
        rows.append(
            {
                "symbol": symbol,
                "symbol_base": symbol_base(symbol),
                "version_suffix": symbol_version_suffix(symbol),
                "owner_surface": primary_catalog.get("owner_surface", "unknown"),
                "primary_probe_id": "nm_dynamic_undefined_symbols",
                "blocking_reasons": symbol_reasons,
                "evidence_fields": undefined_symbol_evidence_fields(symbol_reasons),
                "next_action": primary_catalog.get(
                    "next_action",
                    "Classify this undefined symbol before using it as replacement claim evidence.",
                ),
                "promotion_allowed": False,
            }
        )
    return rows


def resolved_library_blocking_reasons(
    library,
    resolved_paths,
    direct_needed_present,
    version_requirements,
    blocking_reasons,
):
    reasons = []
    if "host_needed_libraries_present" in blocking_reasons:
        reasons.append("host_needed_libraries_present")
    if direct_needed_present and "host_direct_needed_libraries_present" in blocking_reasons:
        reasons.append("host_direct_needed_libraries_present")
    if "host_resolved_libraries_present" in blocking_reasons:
        reasons.append("host_resolved_libraries_present")
    if library_or_path_contains(library, resolved_paths, "ld-linux") and "host_loader_dependency" in blocking_reasons:
        reasons.append("host_loader_dependency")
    if library_or_path_has_base(library, resolved_paths, "libc.so") and "host_libc_dependency" in blocking_reasons:
        reasons.append("host_libc_dependency")
    if library_or_path_has_base(library, resolved_paths, "libgcc_s.so") and "libgcc_runtime_dependency" in blocking_reasons:
        reasons.append("libgcc_runtime_dependency")
    if version_requirements and "host_version_requirements" in blocking_reasons:
        reasons.append("host_version_requirements")
    return reasons


def build_host_resolved_library_rows(
    host_resolved_libraries,
    host_direct_needed_libraries,
    ldd_resolution_paths,
    version_needs,
    blocking_reasons,
):
    resolved_catalog = BLOCKER_CATALOG_DEFINITIONS["host_resolved_libraries_present"]
    rows = []
    for library in host_resolved_libraries:
        resolved_paths = ldd_paths_for_library(library, ldd_resolution_paths)
        direct_matches = matching_direct_needed_libraries(library, host_direct_needed_libraries)
        direct_needed_present = bool(direct_matches)
        version_requirements = version_requirements_for_library(library, version_needs)
        rows.append(
            {
                "library": library,
                "owner_surface": resolved_catalog["owner_surface"],
                "primary_probe_id": "ldd_runtime_resolution",
                "direct_needed_present": direct_needed_present,
                "resolution_kind": "direct" if direct_needed_present else "transitive",
                "resolved_paths": resolved_paths,
                "version_requirements": version_requirements,
                "blocking_reasons": resolved_library_blocking_reasons(
                    library,
                    resolved_paths,
                    direct_needed_present,
                    version_requirements,
                    blocking_reasons,
                ),
                "evidence_fields": resolved_catalog["evidence_fields"],
                "next_action": resolved_catalog["next_action"],
                "promotion_allowed": False,
            }
        )
    return rows


def related_undefined_symbols_for_version(provider, version, undefined_symbols):
    return unique_sorted(
        symbol
        for symbol in undefined_symbols
        if symbol_version_suffix(symbol) == version
        and (
            (provider.startswith("libgcc_s.so") and symbol_base(symbol).startswith("_Unwind_"))
            or (provider.startswith("libgcc_s.so") and symbol_base(symbol) == "__gcc_personality_v0")
            or ("ld-linux" in provider and symbol_base(symbol) == "__tls_get_addr")
            or ("ld-linux" in provider and "@GLIBC_" in symbol)
        )
    )


def related_host_libraries_for_version_provider(
    provider,
    host_needed_libraries,
    host_direct_needed_libraries,
    host_resolved_libraries,
):
    return unique_sorted(
        library
        for library in [
            *host_needed_libraries,
            *host_direct_needed_libraries,
            *host_resolved_libraries,
        ]
        if library_matches(provider, library)
    )


def version_requirement_blocking_reasons(
    provider,
    related_symbols,
    related_libraries,
    blocking_reasons,
):
    reasons = []
    if "host_version_requirements" in blocking_reasons:
        reasons.append("host_version_requirements")
    if related_libraries and "host_needed_libraries_present" in blocking_reasons:
        reasons.append("host_needed_libraries_present")
    if provider in related_libraries and "host_direct_needed_libraries_present" in blocking_reasons:
        reasons.append("host_direct_needed_libraries_present")
    if any(Path(library).name == provider for library in related_libraries) and "host_resolved_libraries_present" in blocking_reasons:
        reasons.append("host_resolved_libraries_present")
    if "ld-linux" in provider and "host_loader_dependency" in blocking_reasons:
        reasons.append("host_loader_dependency")
    if provider.startswith("libgcc_s.so") and "libgcc_runtime_dependency" in blocking_reasons:
        reasons.append("libgcc_runtime_dependency")
    if any(symbol_base(symbol).startswith("_Unwind_") for symbol in related_symbols) and "undefined_unwind_symbols" in blocking_reasons:
        reasons.append("undefined_unwind_symbols")
    if any(symbol_base(symbol) == "__tls_get_addr" for symbol in related_symbols) and "undefined_tls_symbols" in blocking_reasons:
        reasons.append("undefined_tls_symbols")
    if any("@GLIBC_" in symbol for symbol in related_symbols) and "undefined_glibc_symbols" in blocking_reasons:
        reasons.append("undefined_glibc_symbols")
    return reasons


def version_requirement_owner_surface(provider, related_symbols):
    if provider.startswith("libgcc_s.so"):
        return "compiler_runtime_and_unwind_runtime"
    if "ld-linux" in provider and any(symbol_base(symbol) == "__tls_get_addr" for symbol in related_symbols):
        return "loader_tls_runtime"
    if "ld-linux" in provider:
        return "loader_startup"
    return BLOCKER_CATALOG_DEFINITIONS["host_version_requirements"]["owner_surface"]


def version_requirement_next_action(provider, related_symbols):
    if provider.startswith("libgcc_s.so"):
        return "Remove or own compiler-runtime and unwinder ABI edges until readelf reports no libgcc_s provider version needs."
    if "ld-linux" in provider and any(symbol_base(symbol) == "__tls_get_addr" for symbol in related_symbols):
        return "Provide owned TLS startup/access support or eliminate the dynamic TLS edge so readelf reports no host loader GLIBC version need."
    if "ld-linux" in provider:
        return "Replace host loader/startup dependency with owned CRT and loader evidence before clearing this version need."
    return BLOCKER_CATALOG_DEFINITIONS["host_version_requirements"]["next_action"]


def evidence_fields_for_blocking_reasons(reasons, fallback):
    fields = []
    for reason in reasons:
        definition = BLOCKER_CATALOG_DEFINITIONS.get(reason)
        if definition:
            fields.extend(definition["evidence_fields"])
    return unique_sorted(fields or fallback)


def build_host_version_requirement_rows(
    version_needs,
    host_version_requirements,
    undefined_symbols,
    host_needed_libraries,
    host_direct_needed_libraries,
    host_resolved_libraries,
    blocking_reasons,
):
    rows = []
    host_requirement_set = set(host_version_requirements)
    for provider, versions in version_needs.items():
        if not is_host_runtime_library(provider):
            continue
        related_libraries = related_host_libraries_for_version_provider(
            provider,
            host_needed_libraries,
            host_direct_needed_libraries,
            host_resolved_libraries,
        )
        for version in versions:
            requirement_id = f"{provider}:{version}"
            if requirement_id not in host_requirement_set:
                continue
            related_symbols = related_undefined_symbols_for_version(
                provider,
                version,
                undefined_symbols,
            )
            reasons = version_requirement_blocking_reasons(
                provider,
                related_symbols,
                related_libraries,
                blocking_reasons,
            )
            rows.append(
                {
                    "requirement_id": requirement_id,
                    "provider_library": provider,
                    "version_node": version,
                    "owner_surface": version_requirement_owner_surface(
                        provider,
                        related_symbols,
                    ),
                    "primary_probe_id": "readelf_version_needs",
                    "blocking_reasons": reasons,
                    "evidence_fields": evidence_fields_for_blocking_reasons(
                        reasons,
                        ["host_version_requirements", "version_needs"],
                    ),
                    "related_undefined_symbols": related_symbols,
                    "related_host_libraries": related_libraries,
                    "next_action": version_requirement_next_action(
                        provider,
                        related_symbols,
                    ),
                    "promotion_allowed": False,
                }
            )
    return rows


def host_values_with_name(libraries, needle):
    return unique_sorted(
        library
        for library in libraries
        if needle in Path(library).name or needle in library
    )


def build_blocker_action_rows(
    blocking_reasons,
    host_needed_libraries,
    host_direct_needed_libraries,
    host_resolved_libraries,
    undefined_unwind_symbols,
    undefined_glibc_symbols,
    undefined_tls_symbols,
    host_version_requirements,
):
    host_library_values = [
        *host_needed_libraries,
        *host_direct_needed_libraries,
        *host_resolved_libraries,
    ]
    current_values_by_reason = {
        "host_needed_libraries_present": host_needed_libraries,
        "host_direct_needed_libraries_present": host_direct_needed_libraries,
        "host_resolved_libraries_present": host_resolved_libraries,
        "host_loader_dependency": host_values_with_name(host_library_values, "ld-linux"),
        "host_libc_dependency": host_values_with_name(host_library_values, "libc.so"),
        "libgcc_runtime_dependency": [
            *host_values_with_name(host_library_values, "libgcc_s.so"),
            *[
                requirement
                for requirement in host_version_requirements
                if requirement.startswith("libgcc_s.so")
            ],
        ],
        "undefined_unwind_symbols": undefined_unwind_symbols,
        "undefined_glibc_symbols": undefined_glibc_symbols,
        "undefined_tls_symbols": undefined_tls_symbols,
        "host_version_requirements": host_version_requirements,
    }
    rows = []
    for reason in blocking_reasons:
        definition = BLOCKER_CATALOG_DEFINITIONS.get(reason, {})
        rows.append(
            {
                "blocking_reason": reason,
                "owner_surface": definition.get("owner_surface", "unknown"),
                "primary_probe_id": BLOCKER_ACTION_PRIMARY_PROBE_IDS.get(
                    reason,
                    "unclassified_blocker_probe",
                ),
                "evidence_fields": definition.get("evidence_fields", []),
                "next_action": definition.get(
                    "next_action",
                    "Classify this blocker before using it as replacement claim evidence.",
                ),
                "exit_criteria": BLOCKER_ACTION_EXIT_CRITERIA.get(
                    reason,
                    [f"blocking_reasons omits {reason}"],
                ),
                "current_blocker_values": unique_sorted(
                    current_values_by_reason.get(reason, [])
                ),
                "promotion_allowed": False,
            }
        )
    return rows


def build_dependency_breakdown(readelf_header, readelf_dynamic, readelf_version, nm_dynamic, ldd):
    breakdown = empty_dependency_breakdown()
    elf_header = parse_elf_header(readelf_header["stdout"] + "\n" + readelf_header["stderr"])
    needed_libraries = parse_needed_libraries(readelf_dynamic["stdout"])
    sonames = parse_dynamic_tag_values(readelf_dynamic["stdout"], "SONAME")
    soname = sonames[0] if sonames else None
    rpath = parse_dynamic_tag_values(readelf_dynamic["stdout"], "RPATH")
    runpath = parse_dynamic_tag_values(readelf_dynamic["stdout"], "RUNPATH")
    shape_errors = dynamic_shape_errors(elf_header, soname, rpath, runpath)
    ldd_text = ldd["stdout"] + "\n" + ldd["stderr"]
    ldd_libraries = parse_ldd_libraries(ldd_text)
    ldd_resolution_paths = parse_ldd_resolution_paths(ldd_text)
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
    if host_direct_needed_libraries:
        blocking_reasons.append("host_direct_needed_libraries_present")
    if host_resolved_libraries:
        blocking_reasons.append("host_resolved_libraries_present")
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
            "direct_host_needed_library_rows": build_direct_host_needed_library_rows(
                host_direct_needed_libraries,
                ldd_resolution_paths,
                version_needs,
                blocking_reasons,
            ),
            "host_resolved_library_rows": build_host_resolved_library_rows(
                host_resolved_libraries,
                host_direct_needed_libraries,
                ldd_resolution_paths,
                version_needs,
                blocking_reasons,
            ),
            "undefined_symbols": undefined_symbols,
            "undefined_symbol_rows": build_undefined_symbol_rows(
                undefined_symbols,
                unique_sorted(undefined_unwind_symbols),
                unique_sorted(undefined_glibc_symbols),
                unique_sorted(undefined_tls_symbols),
                blocking_reasons,
            ),
            "undefined_unwind_symbols": unique_sorted(undefined_unwind_symbols),
            "undefined_glibc_symbols": unique_sorted(undefined_glibc_symbols),
            "undefined_tls_symbols": unique_sorted(undefined_tls_symbols),
            "version_needs": version_needs,
            "host_version_requirements": unique_sorted(host_version_requirements),
            "host_version_requirement_rows": build_host_version_requirement_rows(
                version_needs,
                unique_sorted(host_version_requirements),
                undefined_symbols,
                host_needed_libraries,
                host_direct_needed_libraries,
                host_resolved_libraries,
                blocking_reasons,
            ),
            "loader_needed": loader_needed,
            "soname": soname,
            "rpath": rpath,
            "runpath": runpath,
            "dynamic_shape_valid": not shape_errors,
            "dynamic_shape_errors": shape_errors,
            "libc_needed": libc_needed,
            "libgcc_needed": libgcc_needed,
            "blocking_reasons": blocking_reasons,
            "blocker_catalog": build_blocker_catalog(blocking_reasons),
            "blocker_action_rows": build_blocker_action_rows(
                blocking_reasons,
                host_needed_libraries,
                host_direct_needed_libraries,
                host_resolved_libraries,
                unique_sorted(undefined_unwind_symbols),
                unique_sorted(undefined_glibc_symbols),
                unique_sorted(undefined_tls_symbols),
                unique_sorted(host_version_requirements),
            ),
        }
    )
    return breakdown


def build_blocker_catalog(blocking_reasons):
    catalog = {}
    for reason in blocking_reasons:
        definition = BLOCKER_CATALOG_DEFINITIONS.get(reason)
        if definition is None:
            catalog[reason] = {
                "owner_surface": "unknown",
                "severity": "claim_blocking",
                "evidence_fields": [],
                "next_action": "Classify this blocker before using it as replacement claim evidence.",
            }
        else:
            catalog[reason] = dict(definition)
    return catalog


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


def detected_rch_local_fallback(command, result):
    if not command or Path(command[0]).name != "rch":
        return False
    return "[RCH] local" in (result["stdout"] + "\n" + result["stderr"])


def first_nonempty_line(text):
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def rustc_version_text():
    result = run_command(["rustc", "-Vv"], timeout=5)
    return (result["stdout"] + result["stderr"]).strip() or "unknown"


def rustc_host_triple(version_text):
    for line in version_text.splitlines():
        if line.startswith("host:"):
            return line.split(":", 1)[1].strip()
    return "unknown"


def rustflags_linker():
    raw = os.environ.get("RUSTFLAGS", "")
    if not raw:
        return None
    try:
        parts = shlex.split(raw)
    except ValueError:
        return None
    for idx, part in enumerate(parts):
        if part == "-C" and idx + 1 < len(parts) and parts[idx + 1].startswith("linker="):
            return parts[idx + 1].split("=", 1)[1]
        if part.startswith("-Clinker="):
            return part.split("=", 1)[1]
    return None


def using_default_build_command():
    return not bool(os.environ.get("STANDALONE_REPLACEMENT_BUILD_CMD"))


def effective_build_env_overrides():
    return dict(DEFAULT_BUILD_ENV) if using_default_build_command() else {}


def sanitized_env_snapshot():
    default_env = effective_build_env_overrides()
    snapshot = {}
    for key in BUILD_PROVENANCE_ENV_KEYS:
        value = os.environ.get(key)
        if value is None and key in default_env:
            value = default_env[key]
        if value is None:
            snapshot[key] = {
                "present": False,
                "value": None,
                "sha256": None,
                "redacted": False,
            }
        else:
            snapshot[key] = {
                "present": True,
                "value": REDACTED_ENV_VALUE,
                "sha256": sha256_text(value),
                "redacted": True,
            }
    return snapshot


def linker_provenance(target_triple):
    linker_env_key = f"CARGO_TARGET_{env_key_fragment(target_triple)}_LINKER"
    configured = os.environ.get(linker_env_key) or rustflags_linker() or "cc"
    try:
        configured_parts = shlex.split(configured)
    except ValueError:
        configured_parts = [configured]
    executable = configured_parts[0] if configured_parts else "cc"
    path = shutil.which(executable)
    version = None
    command = [executable, "--version"]
    result = run_command(command, timeout=5)
    if result["returncode"] == 0:
        version = first_nonempty_line(result["stdout"] + result["stderr"])
    return {
        "env_key": linker_env_key,
        "configured": configured,
        "path": path,
        "version": version,
        "version_command": command,
        "discovered": bool(path or version),
    }


def collect_build_provenance():
    version_text = rustc_version_text()
    target_triple = os.environ.get("CARGO_BUILD_TARGET") or rustc_host_triple(version_text)
    return {
        "rustc_version": version_text,
        "cargo_profile": manifest.get("artifact_policy", {}).get("cargo_profile"),
        "target_triple": target_triple,
        "cargo_target_dir": str(cargo_target_dir),
        "build_command": build_command(),
        "sanitized_env": sanitized_env_snapshot(),
        "linker": linker_provenance(target_triple),
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


def full_git_commit(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{40}", value) is not None


def source_commit_marker_is_current(value):
    return value == "current" or (source_commit != "unknown" and value == source_commit)


def validate_manifest():
    checks["json_parse"] = "pass" if isinstance(manifest, dict) and isinstance(packaging, dict) else "fail"
    if manifest.get("schema_version") != "v1":
        errors.append("manifest schema_version must be v1")
    if manifest.get("bead") != "bd-srtkq":
        errors.append("manifest must be linked to bd-srtkq")
    if manifest.get("manifest_id") != EXPECTED_MANIFEST_ID:
        errors.append("manifest_id does not match script contract")
    manifest_source_commit = manifest.get("source_commit")
    recorded_source_commit_current = source_commit_marker_is_current(manifest_source_commit)
    source_commit_policy_ok = (
        (manifest_source_commit == "current" or full_git_commit(manifest_source_commit))
        and manifest.get("source_commit_freshness_policy") == EXPECTED_SOURCE_COMMIT_FRESHNESS_POLICY
    )
    checks["source_commit_freshness_policy"] = "pass" if source_commit_policy_ok else "fail"
    checks["recorded_source_commit_freshness"] = (
        "pass" if source_commit_policy_ok and recorded_source_commit_current else "fail"
    )
    if not source_commit_policy_ok:
        errors.append("source_commit_freshness_policy does not match script contract")
    elif not recorded_source_commit_current:
        errors.append("source_commit must be 'current' or match current git HEAD")
    if manifest.get("inputs") != EXPECTED_INPUTS:
        errors.append("inputs do not match script contract")
    if manifest.get("summary") != EXPECTED_SUMMARY:
        errors.append("summary does not match script contract")
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
    if manifest.get("build_provenance_policy") != EXPECTED_BUILD_PROVENANCE_POLICY:
        errors.append("build_provenance_policy does not match script contract")
    if manifest.get("blocker_delta_policy") != EXPECTED_BLOCKER_DELTA_POLICY:
        errors.append("blocker_delta_policy does not match script contract")
    if manifest.get("symbol_samples") != EXPECTED_SYMBOL_SAMPLES:
        errors.append("symbol_samples do not match script contract")
    classifications = manifest.get("expected_failure_classifications", [])
    classification_map = {}
    if isinstance(classifications, list):
        for entry in classifications:
            if isinstance(entry, dict) and isinstance(entry.get("failure_signature"), str):
                classification_map[entry["failure_signature"]] = entry.get("expected_result")
    if classification_map != EXPECTED_FAILURE_CLASSIFICATIONS:
        errors.append("expected_failure_classifications do not match script contract")
    if manifest.get("claim_policy") != EXPECTED_CLAIM_POLICY:
        errors.append("claim_policy does not match script contract")
    if manifest.get("blocker_catalog_contract") != EXPECTED_BLOCKER_CATALOG_CONTRACT:
        errors.append("blocker_catalog_contract does not match script contract")
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
    if artifact_policy != EXPECTED_ARTIFACT_POLICY:
        errors.append("artifact_policy does not match script contract")
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
    if levels.get("current_level") != "L1":
        errors.append("replacement level must remain L1 while this gate only forges evidence")

    checks["manifest_contract"] = "pass" if not errors else "fail"


def validate_compiler_runtime_experiment_manifest():
    if compiler_runtime_manifest.get("schema_version") != "v1":
        errors.append("compiler runtime experiment schema_version must be v1")
    if compiler_runtime_manifest.get("manifest_id") != EXPECTED_COMPILER_RUNTIME_EXPERIMENT_MANIFEST_ID:
        errors.append("compiler runtime experiment manifest_id does not match script contract")
    if compiler_runtime_manifest.get("bead") != "bd-zyck1.88":
        errors.append("compiler runtime experiment manifest must be linked to bd-zyck1.88")
    manifest_source_commit = compiler_runtime_manifest.get("source_commit")
    source_commit_policy = compiler_runtime_manifest.get("source_commit_freshness_policy")
    expected_source_commit_policy = {
        "recorded_source_commit_field": "source_commit",
        "comparison_target": "current git HEAD",
        "stale_result": "block_compiler_runtime_experiment_refresh",
        "experiment_evidence_allowed_when_stale": False,
        "rejected_evidence_kind": "stale_compiler_runtime_experiment",
    }
    source_commit_policy_ok = (
        (manifest_source_commit == "current" or full_git_commit(manifest_source_commit))
        and source_commit_policy == expected_source_commit_policy
    )
    checks["compiler_runtime_experiment_source_commit_freshness_policy"] = (
        "pass" if source_commit_policy_ok else "fail"
    )
    checks["compiler_runtime_experiment_recorded_source_commit_freshness"] = (
        "pass"
        if source_commit_policy_ok and source_commit_marker_is_current(manifest_source_commit)
        else "fail"
    )
    if not source_commit_policy_ok:
        errors.append("compiler runtime experiment source_commit_freshness_policy does not match script contract")
    elif not source_commit_marker_is_current(manifest_source_commit):
        errors.append("compiler runtime experiment source_commit must be 'current' or match current git HEAD")
    if compiler_runtime_manifest.get("inputs") != EXPECTED_COMPILER_RUNTIME_EXPERIMENT_INPUTS:
        errors.append("compiler runtime experiment inputs do not match script contract")
    if compiler_runtime_manifest.get("report_policy") != EXPECTED_COMPILER_RUNTIME_EXPERIMENT_POLICY:
        errors.append("compiler runtime experiment report_policy does not match script contract")
    if compiler_runtime_manifest.get("required_report_fields") != EXPECTED_COMPILER_RUNTIME_EXPERIMENT_REQUIRED_REPORT_FIELDS:
        errors.append("compiler runtime experiment required_report_fields do not match script contract")
    if compiler_runtime_manifest.get("experiment_lanes") != EXPECTED_COMPILER_RUNTIME_EXPERIMENT_LANES:
        errors.append("compiler runtime experiment lanes do not match script contract")
    if compiler_runtime_manifest.get("summary") != EXPECTED_COMPILER_RUNTIME_EXPERIMENT_SUMMARY:
        errors.append("compiler runtime experiment summary does not match script contract")
    checks["compiler_runtime_experiment_manifest_contract"] = (
        "pass"
        if not any(error.startswith("compiler runtime experiment") for error in errors)
        else "fail"
    )


def validate_owned_unwind_experiment_manifest():
    if owned_unwind_manifest.get("schema_version") != "v1":
        errors.append("owned unwind experiment schema_version must be v1")
    if owned_unwind_manifest.get("manifest_id") != EXPECTED_OWNED_UNWIND_EXPERIMENT_MANIFEST_ID:
        errors.append("owned unwind experiment manifest_id does not match script contract")
    if owned_unwind_manifest.get("bead") != EXPECTED_OWNED_UNWIND_EXPERIMENT_SUMMARY["bead"]:
        errors.append("owned unwind experiment manifest must be linked to bd-juvqm.4")

    manifest_source_commit = owned_unwind_manifest.get("source_commit")
    source_commit_policy = owned_unwind_manifest.get("source_commit_freshness_policy")
    expected_source_commit_policy = {
        "recorded_source_commit_field": "source_commit",
        "comparison_target": "current git HEAD",
        "stale_result": "block_owned_unwind_experiment",
        "experiment_evidence_allowed_when_stale": False,
        "rejected_evidence_kind": "stale_owned_unwind_experiment",
    }
    source_commit_policy_ok = (
        (manifest_source_commit == "current" or full_git_commit(manifest_source_commit))
        and source_commit_policy == expected_source_commit_policy
    )
    checks["owned_unwind_experiment_source_commit_freshness_policy"] = (
        "pass" if source_commit_policy_ok else "fail"
    )
    checks["owned_unwind_experiment_recorded_source_commit_freshness"] = (
        "pass"
        if source_commit_policy_ok and source_commit_marker_is_current(manifest_source_commit)
        else "fail"
    )
    if not source_commit_policy_ok:
        errors.append("owned unwind experiment source_commit_freshness_policy does not match script contract")
    elif not source_commit_marker_is_current(manifest_source_commit):
        errors.append("owned unwind experiment source_commit must be 'current' or match current git HEAD")

    policy = owned_unwind_manifest.get("report_policy", {})
    for key, expected in EXPECTED_OWNED_UNWIND_EXPERIMENT_POLICY.items():
        if policy.get(key) != expected:
            errors.append(f"owned unwind experiment report_policy.{key} does not match script contract")

    lanes = owned_unwind_manifest.get("experiment_lanes", [])
    if not isinstance(lanes, list):
        errors.append("owned unwind experiment lanes must be an array")
        lanes = []
    lane_by_id = {
        lane.get("lane_id"): lane
        for lane in lanes
        if isinstance(lane, dict) and isinstance(lane.get("lane_id"), str)
    }
    if set(lane_by_id) != {lane["lane_id"] for lane in EXPECTED_OWNED_UNWIND_EXPERIMENT_LANES}:
        errors.append("owned unwind experiment lanes do not match script contract")
    for expected in EXPECTED_OWNED_UNWIND_EXPERIMENT_LANES:
        lane = lane_by_id.get(expected["lane_id"], {})
        for key, value in expected.items():
            if lane.get(key) != value:
                errors.append(
                    f"owned unwind experiment lane {expected['lane_id']} {key} does not match script contract"
                )
        if lane.get("must_not_change_default_profile") is not True:
            errors.append(
                f"owned unwind experiment lane {expected['lane_id']} must keep default profile locked"
            )
        if expected["lane_id"] == EXPECTED_OWNED_UNWIND_EXPERIMENT_SUMMARY["experiment_lane"]:
            command = lane.get("build_command", [])
            rustflags = lane.get("rustflags", [])
            env = lane.get("env", {})
            if "--features=standalone,owned-unwind-stub" not in command:
                errors.append("owned unwind experiment lane must build standalone,owned-unwind-stub")
            if rustflags != ["-C", "link-arg=-Wl,--no-undefined"]:
                errors.append("owned unwind experiment lane must pin no-undefined rustflags")
            if env.get("CARGO_PROFILE_RELEASE_PANIC") != "abort":
                errors.append("owned unwind experiment lane must set panic=abort through env")

    rows = owned_unwind_manifest.get("symbol_disposition_rows", [])
    if not isinstance(rows, list):
        errors.append("owned unwind experiment symbol_disposition_rows must be an array")
        rows = []
    baseline_undefined = [
        row for row in rows
        if isinstance(row, dict)
        and row.get("baseline_disposition") == "still_undefined"
        and isinstance(row.get("symbol"), str)
        and row.get("bare_symbol", "").startswith("_Unwind_")
    ]
    owned_substitutes = [
        row for row in rows
        if isinstance(row, dict) and row.get("owned_unwind_disposition") == "owned_substitute"
    ]
    if len(baseline_undefined) != OWNED_UNWIND_SYMBOL_COUNT:
        errors.append("owned unwind experiment must track all 12 baseline _Unwind_* symbols")
    if len(owned_substitutes) != OWNED_UNWIND_SYMBOL_COUNT:
        errors.append("owned unwind experiment must mark all 12 symbols as owned substitutes")
    if owned_unwind_manifest.get("summary", {}).get("claim_status") not in {"claim_blocked", "report_only"}:
        errors.append("owned unwind experiment summary must remain claim_blocked or report_only")
    contract = owned_unwind_manifest.get("live_dependency_evidence_contract", {})
    for key, expected in EXPECTED_OWNED_UNWIND_LIVE_DEPENDENCY_CONTRACT.items():
        if contract.get(key) != expected:
            errors.append(
                f"owned unwind experiment live_dependency_evidence_contract.{key} does not match script contract"
            )
    checks["owned_unwind_experiment_manifest_contract"] = (
        "pass"
        if not any(error.startswith("owned unwind experiment") for error in errors)
        else "fail"
    )


def build_command():
    raw = os.environ.get("STANDALONE_REPLACEMENT_BUILD_CMD")
    if raw:
        return shlex.split(raw)
    return list(DEFAULT_BUILD_COMMAND)


def forge_artifact():
    source_override = os.environ.get("STANDALONE_REPLACEMENT_SOURCE_LIB")
    skip_build = os.environ.get("STANDALONE_REPLACEMENT_SKIP_BUILD") == "1"
    command = build_command()
    build_stdout = out_dir / "build.stdout.txt"
    build_stderr = out_dir / "build.stderr.txt"
    if mode == "forge" and not skip_build:
        env = os.environ.copy()
        env.update(effective_build_env_overrides())
        env["CARGO_TARGET_DIR"] = str(cargo_target_dir)
        allowlist = env.get("RCH_ENV_ALLOWLIST", "")
        allowed = [item for item in allowlist.split(",") if item]
        for key in DEFAULT_REMOTE_ENV_ALLOWLIST:
            if key not in allowed and (key == "CARGO_TARGET_DIR" or env.get(key) is not None):
                allowed.append(key)
        env["RCH_ENV_ALLOWLIST"] = ",".join(allowed)
        result = run_command(command, env=env)
        write_text(build_stdout, result["stdout"])
        write_text(build_stderr, result["stderr"])
        rch_local_fallback = detected_rch_local_fallback(command, result)
        build_failed = result["returncode"] != 0 or rch_local_fallback
        append_log(
            "build",
            artifact_path=None,
            artifact_status="build_failed" if build_failed else "build_completed",
            claim_status="claim_blocked" if build_failed else "build_completed",
            artifact_hash=None,
            command=command,
            exit_code=result["returncode"],
            failure_signature=(
                "rch_local_fallback"
                if rch_local_fallback
                else ("build_failed" if result["returncode"] != 0 else "none")
            ),
            refs=[rel(build_stdout), rel(build_stderr)],
        )
        if rch_local_fallback:
            errors.append("rch local fallback is not valid standalone replacement proof")
            return None
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


def inspect_artifact(artifact, *, evidence_out_dir=out_dir, tool_evidence_sink=None):
    if tool_evidence_sink is None:
        tool_evidence_sink = tool_evidence
    refs = []
    if artifact is None or not Path(artifact).exists():
        return {
            "status": "missing",
            "path": str(artifact) if artifact else None,
            "sha256": None,
            "mtime": None,
            "failure_signature": "standalone_artifact_missing",
            "host_glibc_dependency": None,
            "elf_header": empty_elf_header(),
            "sampled_symbols_present": False,
            "dependency_breakdown": empty_dependency_breakdown(),
            "refs": refs,
        }

    artifact = Path(artifact)
    artifact_hash = sha256(artifact)
    hash_path = evidence_out_dir / "artifact.sha256"
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
            "elf_header": empty_elf_header(),
            "sampled_symbols_present": False,
            "dependency_breakdown": empty_dependency_breakdown(),
            "refs": refs,
        }

    readelf_header = run_command(["readelf", "-h", str(artifact)], timeout=inspection_timeout)
    readelf_dynamic = run_command(["readelf", "-d", str(artifact)], timeout=inspection_timeout)
    readelf_symbols = run_command(["readelf", "-Ws", str(artifact)], timeout=inspection_timeout)
    readelf_version = run_command(["readelf", "--version-info", str(artifact)], timeout=inspection_timeout)
    nm_dynamic = run_command(["nm", "-D", str(artifact)], timeout=inspection_timeout)
    ldd = run_command(["ldd", str(artifact)], timeout=inspection_timeout)
    evidence_commands = {
        "artifact.readelf.header.txt": readelf_header,
        "artifact.readelf.dynamic.txt": readelf_dynamic,
        "artifact.readelf.symbols.txt": readelf_symbols,
        "artifact.readelf.version.txt": readelf_version,
        "artifact.nm.dynamic.txt": nm_dynamic,
        "artifact.ldd.txt": ldd,
    }
    for filename, result in evidence_commands.items():
        path = evidence_out_dir / filename
        write_text(path, result["stdout"] + result["stderr"])
        refs.append(rel(path))
        tool_evidence_sink[filename] = {
            "exit_code": result["returncode"],
            "timed_out": result["timed_out"],
            "timeout_secs": inspection_timeout,
            "path": rel(path),
        }

    mtime = int(artifact.stat().st_mtime)
    dependency_breakdown = build_dependency_breakdown(readelf_header, readelf_dynamic, readelf_version, nm_dynamic, ldd)
    elf_header = parse_elf_header(readelf_header["stdout"] + "\n" + readelf_header["stderr"])
    readelf_header_execution_failed = (
        readelf_header["timed_out"] or readelf_header.get("execution_error", False)
    )
    readelf_dynamic_execution_failed = (
        readelf_dynamic["timed_out"] or readelf_dynamic.get("execution_error", False)
    )
    inspection_failed = any(
        result["returncode"] != 0 or result["timed_out"]
        for filename, result in evidence_commands.items()
        if filename != "artifact.readelf.dynamic.txt"
    ) or readelf_dynamic_execution_failed or readelf_header_execution_failed
    if head_epoch and mtime < head_epoch:
        return {
            "status": "stale",
            "path": str(artifact),
            "sha256": artifact_hash,
            "mtime": mtime,
            "failure_signature": "standalone_artifact_stale",
            "host_glibc_dependency": None,
            "elf_header": elf_header,
            "sampled_symbols_present": False,
            "dependency_breakdown": dependency_breakdown,
            "refs": refs,
        }
    if (
        readelf_header["returncode"] != 0
        and not readelf_header_execution_failed
        or readelf_dynamic["returncode"] != 0
        and not readelf_dynamic_execution_failed
    ):
        return {
            "status": "non_elf",
            "path": str(artifact),
            "sha256": artifact_hash,
            "mtime": mtime,
            "failure_signature": "non_elf_artifact",
            "host_glibc_dependency": None,
            "elf_header": elf_header,
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
            "elf_header": elf_header,
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
    if not dependency_breakdown.get("dynamic_shape_valid", False):
        failure = "artifact_dynamic_shape_invalid"
    elif host_glibc_dependency:
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
        "elf_header": elf_header,
        "sampled_symbols_present": sampled_symbols_present,
        "dependency_breakdown": dependency_breakdown,
        "symbol_samples": present,
        "refs": refs,
    }


def artifact_claim_status(artifact_state):
    if artifact_state["failure_signature"] == "none" and artifact_state["status"] in {"current", "not_checked"}:
        return "artifact_current" if artifact_state["status"] == "current" else "schema_validated"
    if artifact_state["failure_signature"] == "non_elf_artifact":
        return "failed"
    return "claim_blocked"


def experiment_source_override(lane_id, env_prefix):
    specific_env = f"{env_prefix}_{env_key_fragment(lane_id)}_SOURCE_LIB"
    return os.environ.get(specific_env) or os.environ.get("STANDALONE_REPLACEMENT_SOURCE_LIB")


def run_experiment_lane(lane, *, target_root, out_subdir, source_env_prefix):
    lane_id = lane["lane_id"]
    lane_out_dir = out_dir / out_subdir / lane_id
    lane_target_dir = target_root / lane["cargo_target_dir_suffix"]
    lane_out_dir.mkdir(parents=True, exist_ok=True)
    (lane_target_dir / "release").mkdir(parents=True, exist_ok=True)
    command = lane["build_command"]
    build_stdout = lane_out_dir / "build.stdout.txt"
    build_stderr = lane_out_dir / "build.stderr.txt"
    skip_build = os.environ.get("STANDALONE_COMPILER_RUNTIME_EXPERIMENT_SKIP_BUILD") == "1"
    build_status = "skipped" if skip_build else "not_started"
    build_exit_code = 0

    if not skip_build:
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(lane_target_dir)
        for key, value in lane.get("env", {}).items():
            env[key] = value
        rustflags = lane.get("rustflags", [])
        if isinstance(rustflags, list) and rustflags:
            existing = env.get("RUSTFLAGS", "").strip()
            manifest_flags = " ".join(str(flag) for flag in rustflags)
            env["RUSTFLAGS"] = f"{existing} {manifest_flags}".strip()
        allowlist = env.get("RCH_ENV_ALLOWLIST", "")
        allowed = [item for item in allowlist.split(",") if item]
        for key in ["CARGO_TARGET_DIR", *lane.get("env", {}).keys()]:
            if key not in allowed:
                allowed.append(key)
        if isinstance(rustflags, list) and rustflags and "RUSTFLAGS" not in allowed:
            allowed.append("RUSTFLAGS")
        env["RCH_ENV_ALLOWLIST"] = ",".join(allowed)
        result = run_command(command, env=env)
        build_exit_code = result["returncode"]
        rch_local_fallback = detected_rch_local_fallback(command, result)
        build_status = "pass" if result["returncode"] == 0 and not rch_local_fallback else "fail"
        write_text(build_stdout, result["stdout"])
        write_text(build_stderr, result["stderr"])
    else:
        write_text(build_stdout, "build skipped by STANDALONE_COMPILER_RUNTIME_EXPERIMENT_SKIP_BUILD=1\n")
        write_text(build_stderr, "")

    source_override = experiment_source_override(lane_id, source_env_prefix)
    source = Path(source_override) if source_override else lane_target_dir / "release" / "libfrankenlibc_abi.so"
    target = lane_target_dir / "release" / "libfrankenlibc_replace.so"
    lane_tool_evidence = {}
    if build_status == "fail":
        failure_signature = "rch_local_fallback" if not skip_build and rch_local_fallback else "build_failed"
        artifact_state = {
            "status": "build_failed",
            "path": str(target),
            "sha256": None,
            "mtime": None,
            "failure_signature": failure_signature,
            "host_glibc_dependency": None,
            "sampled_symbols_present": False,
            "symbol_samples": empty_symbol_samples(),
            "dependency_breakdown": empty_dependency_breakdown(),
            "refs": [rel(build_stdout), rel(build_stderr)],
        }
    else:
        if source.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            os.utime(target, None)
        artifact_state = inspect_artifact(
            target,
            evidence_out_dir=lane_out_dir,
            tool_evidence_sink=lane_tool_evidence,
        )
        artifact_state.setdefault("symbol_samples", empty_symbol_samples())
        artifact_state["refs"] = [rel(build_stdout), rel(build_stderr), *artifact_state.get("refs", [])]

    breakdown = artifact_state.get("dependency_breakdown", empty_dependency_breakdown())
    artifact_status = artifact_claim_status(artifact_state)
    lane_claim_status = "report_only" if lane.get("role") != "baseline" else artifact_status
    lane_report = {
        "lane_id": lane_id,
        "role": lane["role"],
        "status": "pass" if build_status != "fail" and artifact_state["failure_signature"] != "non_elf_artifact" else "fail",
        "build_status": build_status,
        "build_exit_code": build_exit_code,
        "build_command": command,
        "cargo_target_dir": str(lane_target_dir),
        "panic_strategy": lane["panic_strategy"],
        "env": lane.get("env", {}),
        "report_only": lane["report_only"],
        "must_not_change_default_profile": lane["must_not_change_default_profile"],
        "claim_status": lane_claim_status,
        "artifact_claim_status": artifact_status,
        "artifact_state": artifact_state,
        "needed_libraries": breakdown.get("needed_libraries", []),
        "undefined_unwind_symbols": breakdown.get("undefined_unwind_symbols", []),
        "version_needs": breakdown.get("version_needs", {}),
        "version_requirements": flatten_version_needs(breakdown.get("version_needs", {})),
        "host_version_requirements": breakdown.get("host_version_requirements", []),
        "blocking_reasons": breakdown.get("blocking_reasons", []),
        "tool_evidence": lane_tool_evidence,
    }
    return lane_report


def run_compiler_runtime_lane(lane):
    return run_experiment_lane(
        lane,
        target_root=compiler_runtime_target_root,
        out_subdir="compiler-runtime-experiment",
        source_env_prefix="STANDALONE_COMPILER_RUNTIME",
    )


def run_owned_unwind_lane(lane):
    return run_experiment_lane(
        lane,
        target_root=owned_unwind_target_root,
        out_subdir="owned-unwind-experiment",
        source_env_prefix="STANDALONE_OWNED_UNWIND",
    )


def lane_dependency_comparison(lanes, *, baseline_id, experiment_id):
    by_id = {lane["lane_id"]: lane for lane in lanes}
    baseline = by_id.get(baseline_id, {})
    experiment = by_id.get(experiment_id, {})
    removed_needed, added_needed = set_delta(
        baseline.get("needed_libraries", []),
        experiment.get("needed_libraries", []),
    )
    removed_unwind, added_unwind = set_delta(
        baseline.get("undefined_unwind_symbols", []),
        experiment.get("undefined_unwind_symbols", []),
    )
    removed_versions, added_versions = set_delta(
        baseline.get("version_requirements", []),
        experiment.get("version_requirements", []),
    )
    if baseline.get("status") != "pass" or experiment.get("status") != "pass":
        delta = "inconclusive"
    elif added_needed or added_unwind or added_versions:
        delta = "regression"
    elif removed_needed or removed_unwind or removed_versions:
        delta = "improvement"
    else:
        delta = "unchanged"
    return {
        "baseline_lane": baseline_id,
        "experiment_lane": experiment_id,
        "removed_needed_libraries": removed_needed,
        "added_needed_libraries": added_needed,
        "removed_undefined_unwind_symbols": removed_unwind,
        "added_undefined_unwind_symbols": added_unwind,
        "removed_version_requirements": removed_versions,
        "added_version_requirements": added_versions,
        "delta_classification": delta,
    }


def compiler_runtime_comparison(lanes):
    return lane_dependency_comparison(
        lanes,
        baseline_id=EXPECTED_COMPILER_RUNTIME_EXPERIMENT_SUMMARY["baseline_lane"],
        experiment_id=EXPECTED_COMPILER_RUNTIME_EXPERIMENT_SUMMARY["experiment_lane"],
    )


def owned_unwind_comparison(lanes):
    return lane_dependency_comparison(
        lanes,
        baseline_id=EXPECTED_OWNED_UNWIND_EXPERIMENT_SUMMARY["baseline_lane"],
        experiment_id=EXPECTED_OWNED_UNWIND_EXPERIMENT_SUMMARY["experiment_lane"],
    )


def write_compiler_runtime_experiment_report():
    validate_compiler_runtime_experiment_manifest()
    contract_failed = any(error.startswith("compiler runtime experiment") for error in errors)
    lanes = []
    if not contract_failed:
        lanes = [
            run_compiler_runtime_lane(lane)
            for lane in compiler_runtime_manifest.get("experiment_lanes", [])
            if isinstance(lane, dict)
        ]
    if len(lanes) != len(EXPECTED_COMPILER_RUNTIME_EXPERIMENT_LANES):
        errors.append("compiler runtime experiment did not produce every required lane")
    for lane in lanes:
        if lane["status"] != "pass":
            errors.append(f"compiler runtime experiment lane failed: {lane['lane_id']}")
    comparison = compiler_runtime_comparison(lanes)
    status = "pass" if not errors else "fail"
    report = {
        "schema_version": "v1",
        "manifest_id": compiler_runtime_manifest.get("manifest_id"),
        "bead": compiler_runtime_manifest.get("bead"),
        "mode": mode,
        "status": status,
        "claim_status": "report_only",
        "source_commit": source_commit,
        "report_policy": compiler_runtime_manifest.get("report_policy", {}),
        "cargo_target_root": str(compiler_runtime_target_root),
        "lanes": lanes,
        "comparison": comparison,
        "checks": checks,
        "errors": errors,
        "required_report_fields": EXPECTED_COMPILER_RUNTIME_EXPERIMENT_REQUIRED_REPORT_FIELDS,
        "artifact_refs": [
            rel(compiler_runtime_manifest_path),
            rel(manifest_path),
            rel(packaging_path),
            rel(levels_path),
            rel(compiler_runtime_report_path),
            rel(compiler_runtime_log_path),
            rel(out_dir / "compiler-runtime-experiment"),
        ],
    }
    log_rows = []
    for lane in lanes:
        log_rows.append(
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "level": "info" if lane["status"] == "pass" else "error",
                "trace_id": f"{compiler_runtime_manifest.get('bead', 'unknown')}::{source_commit}::{lane['lane_id']}",
                "bead_id": compiler_runtime_manifest.get("bead"),
                "event": "compiler_runtime_experiment_lane",
                "mode": mode,
                "lane_id": lane["lane_id"],
                "build_command": lane["build_command"],
                "cargo_target_dir": lane["cargo_target_dir"],
                "claim_status": lane["claim_status"],
                "artifact_claim_status": lane["artifact_claim_status"],
                "source_commit": source_commit,
                "exit_code": 0 if lane["status"] == "pass" else 1,
                "failure_signature": lane["artifact_state"].get("failure_signature"),
                "artifact_refs": lane["artifact_state"].get("refs", []),
            }
        )
    write_text(compiler_runtime_report_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
    write_text(compiler_runtime_log_path, "".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows))
    print(json.dumps(report, indent=2, sort_keys=True))
    sys.exit(0 if status == "pass" else 1)


def owned_unwind_symbol_rows(lanes):
    by_id = {lane["lane_id"]: lane for lane in lanes}
    owned_lane = by_id.get(EXPECTED_OWNED_UNWIND_EXPERIMENT_SUMMARY["experiment_lane"], {})
    undefined = {
        symbol_base(symbol)
        for symbol in owned_lane.get("undefined_unwind_symbols", [])
        if isinstance(symbol, str)
    }
    rows = []
    for row in owned_unwind_manifest.get("symbol_disposition_rows", []):
        if not isinstance(row, dict):
            continue
        bare_symbol = row.get("bare_symbol")
        if not isinstance(bare_symbol, str):
            continue
        observed_undefined = bare_symbol in undefined
        rows.append(
            {
                "symbol": row.get("symbol"),
                "bare_symbol": bare_symbol,
                "provider_library": row.get("provider_library"),
                "owned_unwind_disposition": row.get("owned_unwind_disposition"),
                "owned_surface_status": row.get("owned_surface_status"),
                "claim_status_until_exit": row.get("claim_status_until_exit"),
                "observed_undefined_in_owned_lane": observed_undefined,
                "observed_disposition": "still_undefined" if observed_undefined else "owned_or_absent",
            }
        )
    return rows


def owned_unwind_live_dependency_contract(lanes):
    contract = owned_unwind_manifest.get("live_dependency_evidence_contract", {})
    lane_id = contract.get("lane_id")
    by_id = {lane["lane_id"]: lane for lane in lanes if isinstance(lane, dict)}
    lane = by_id.get(lane_id)
    result = {
        "lane_id": lane_id,
        "status": "pass",
        "checked": True,
        "expected_undefined_unwind_symbol_count": contract.get("expected_undefined_unwind_symbol_count"),
        "forbidden_needed_libraries": string_list(contract.get("forbidden_needed_libraries")),
        "forbidden_version_providers": string_list(contract.get("forbidden_version_providers")),
        "forbidden_undefined_symbol_prefixes": string_list(contract.get("forbidden_undefined_symbol_prefixes")),
        "observed_needed_libraries": [],
        "observed_version_providers": [],
        "observed_undefined_unwind_symbols": [],
        "observed_forbidden_undefined_symbols": [],
        "violations": [],
        "promotion_allowed_on_pass": contract.get("promotion_allowed_on_pass"),
    }
    if lane is None:
        result["status"] = "fail"
        result["checked"] = False
        result["violations"].append(f"missing lane {lane_id}")
        return result
    if lane.get("status") != "pass":
        result["status"] = "not_checked"
        result["checked"] = False
        result["reason"] = "owned unwind lane did not pass, so dependency contract is covered by lane failure"
        return result

    needed_libraries = string_list(lane.get("needed_libraries"))
    version_needs = lane.get("version_needs")
    if not isinstance(version_needs, dict):
        version_needs = {}
    version_providers = unique_sorted(str(provider) for provider in version_needs.keys())
    undefined_unwind_symbols = string_list(lane.get("undefined_unwind_symbols"))
    breakdown = lane.get("artifact_state", {}).get("dependency_breakdown", {})
    if not isinstance(breakdown, dict):
        breakdown = {}
    undefined_symbols = string_list(breakdown.get("undefined_symbols"))
    forbidden_prefixes = result["forbidden_undefined_symbol_prefixes"]
    forbidden_undefined = unique_sorted(
        symbol
        for symbol in undefined_symbols
        if any(symbol_base(symbol).startswith(prefix) for prefix in forbidden_prefixes)
    )

    result["observed_needed_libraries"] = needed_libraries
    result["observed_version_providers"] = version_providers
    result["observed_undefined_unwind_symbols"] = undefined_unwind_symbols
    result["observed_forbidden_undefined_symbols"] = forbidden_undefined

    forbidden_needed = set(result["forbidden_needed_libraries"])
    forbidden_providers = set(result["forbidden_version_providers"])
    needed_hits = sorted(forbidden_needed.intersection(needed_libraries))
    provider_hits = sorted(forbidden_providers.intersection(version_providers))
    expected_count = result["expected_undefined_unwind_symbol_count"]
    if needed_hits:
        result["violations"].append(
            f"forbidden needed libraries present: {', '.join(needed_hits)}"
        )
    if provider_hits:
        result["violations"].append(
            f"forbidden version providers present: {', '.join(provider_hits)}"
        )
    if isinstance(expected_count, int) and len(undefined_unwind_symbols) != expected_count:
        result["violations"].append(
            f"undefined unwind symbol count {len(undefined_unwind_symbols)} != expected {expected_count}"
        )
    if forbidden_undefined:
        result["violations"].append(
            f"forbidden undefined symbols present: {', '.join(forbidden_undefined)}"
        )
    if result["violations"]:
        result["status"] = "fail"
    return result


def write_owned_unwind_experiment_report():
    validate_owned_unwind_experiment_manifest()
    contract_failed = any(error.startswith("owned unwind experiment") for error in errors)
    lanes = []
    if not contract_failed:
        lanes = [
            run_owned_unwind_lane(lane)
            for lane in owned_unwind_manifest.get("experiment_lanes", [])
            if isinstance(lane, dict)
        ]
    if len(lanes) != EXPECTED_OWNED_UNWIND_EXPERIMENT_SUMMARY["lane_count"]:
        errors.append("owned unwind experiment did not produce every required lane")
    for lane in lanes:
        if lane["status"] != "pass":
            errors.append(f"owned unwind experiment lane failed: {lane['lane_id']}")
    comparison = owned_unwind_comparison(lanes)
    symbol_rows = owned_unwind_symbol_rows(lanes)
    live_dependency_contract = owned_unwind_live_dependency_contract(lanes)
    for violation in live_dependency_contract.get("violations", []):
        errors.append(f"owned unwind live dependency contract violation: {violation}")
    owned_unresolved = [
        row["bare_symbol"]
        for row in symbol_rows
        if row["observed_undefined_in_owned_lane"]
    ]
    status = "pass" if not errors else "fail"
    report = {
        "schema_version": "v1",
        "manifest_id": owned_unwind_manifest.get("manifest_id"),
        "bead": owned_unwind_manifest.get("bead"),
        "mode": mode,
        "status": status,
        "claim_status": "report_only" if not owned_unresolved else "claim_blocked",
        "source_commit": source_commit,
        "report_policy": owned_unwind_manifest.get("report_policy", {}),
        "cargo_target_root": str(owned_unwind_target_root),
        "lanes": lanes,
        "comparison": comparison,
        "live_dependency_evidence_contract": live_dependency_contract,
        "symbol_disposition_rows": symbol_rows,
        "owned_unwind_unresolved_symbols": owned_unresolved,
        "checks": checks,
        "errors": errors,
        "artifact_refs": [
            rel(owned_unwind_manifest_path),
            rel(manifest_path),
            rel(owned_unwind_report_path),
            rel(owned_unwind_log_path),
            rel(out_dir / "owned-unwind-experiment"),
        ],
    }
    log_rows = []
    for lane in lanes:
        log_rows.append(
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "level": "info" if lane["status"] == "pass" else "error",
                "trace_id": f"{owned_unwind_manifest.get('bead', 'unknown')}::{source_commit}::{lane['lane_id']}",
                "bead_id": owned_unwind_manifest.get("bead"),
                "event": "owned_unwind_experiment_lane",
                "mode": mode,
                "lane_id": lane["lane_id"],
                "build_command": lane["build_command"],
                "cargo_target_dir": lane["cargo_target_dir"],
                "claim_status": lane["claim_status"],
                "artifact_claim_status": lane["artifact_claim_status"],
                "source_commit": source_commit,
                "exit_code": 0 if lane["status"] == "pass" else 1,
                "failure_signature": lane["artifact_state"].get("failure_signature"),
                "artifact_refs": lane["artifact_state"].get("refs", []),
            }
        )
    write_text(owned_unwind_report_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
    write_text(owned_unwind_log_path, "".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows))
    print(json.dumps(report, indent=2, sort_keys=True))
    sys.exit(0 if status == "pass" else 1)


if mode == "compiler-runtime-experiment":
    write_compiler_runtime_experiment_report()
if mode == "owned-unwind-experiment":
    write_owned_unwind_experiment_report()


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
artifact_state.setdefault("elf_header", empty_elf_header())
artifact_state.setdefault("path", None)
artifact_state.setdefault("sha256", None)
artifact_state.setdefault("mtime", None)

claim_status = artifact_claim_status(artifact_state)
build_provenance = collect_build_provenance()
blocker_delta = build_blocker_delta(artifact_state)
if blocker_delta.get("delta_classification") == "regression":
    errors.append("blocker_delta regression: new host libraries, undefined symbols, or version needs observed")
elif blocker_delta.get("delta_classification") == "expected_refresh_needed":
    errors.append("blocker_delta expected_refresh_needed: refresh committed blocker snapshot before accepting blocker removals")
elif blocker_delta.get("delta_classification") == "snapshot_missing":
    errors.append("blocker_delta snapshot_missing: committed forge blocker snapshot is unavailable")

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
    "build_provenance": build_provenance,
    "blocker_delta": blocker_delta,
    "checks": checks,
    "artifact_state": artifact_state,
    "blocking_reasons": artifact_state.get("dependency_breakdown", {}).get("blocking_reasons", []),
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
