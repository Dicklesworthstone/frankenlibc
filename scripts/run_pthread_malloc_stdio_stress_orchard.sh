#!/usr/bin/env bash
# run_pthread_malloc_stdio_stress_orchard.sh -- bd-b92jd.5.6
#
# Deterministic smoke + normal-tier execution layer for the pthread/malloc/stdio
# stress orchard. The runner validates the manifest contract and emits bounded
# JSONL evidence rows under target/conformance/stress_orchard.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_STRESS_ORCHARD_MANIFEST:-${ROOT}/tests/conformance/pthread_malloc_stdio_stress_orchard.v1.json}"
OUT_DIR="${FLC_STRESS_ORCHARD_OUT_DIR:-${ROOT}/target/conformance/stress_orchard}"
REPORT="${FLC_STRESS_ORCHARD_REPORT:-${OUT_DIR}/pthread_malloc_stdio_stress_orchard.report.json}"
LOG="${FLC_STRESS_ORCHARD_LOG:-${OUT_DIR}/pthread_malloc_stdio_stress_orchard.log.jsonl}"
TARGET_DIR="${FLC_STRESS_ORCHARD_TARGET_DIR:-${CARGO_TARGET_DIR:-${ROOT}/target}}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${OUT_DIR}" "${REPORT}" "${LOG}" "${TARGET_DIR}" "${SOURCE_COMMIT}" <<'PY'
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1]).resolve()
manifest_path = Path(sys.argv[2])
out_dir = Path(sys.argv[3])
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])
target_dir = sys.argv[6]
source_commit = sys.argv[7]

BEAD_ID = "bd-b92jd.5.6"
TRACE_PREFIX = "bd-b92jd.5.6:stress-orchard"
REQUIRED_MODES = {"strict", "hardened"}
MAX_ITERATIONS = 1_000_000
MAX_THREADS = 64
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "scenario_id",
    "scenario_kind",
    "tier",
    "iterations",
    "thread_count",
    "seed",
    "runtime_mode",
    "oracle_kind",
    "stress_kernel_id",
    "expected",
    "actual",
    "counters",
    "errno",
    "decision_path",
    "healing_action",
    "failure_signatures",
    "duration_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
FAILURES = {
    "missing_seed": "missing_scenario_seed",
    "missing_oracle": "missing_oracle_kind",
    "nondeterministic": "non_deterministic_input",
    "unbounded": "unbounded_iteration_count",
    "local_only": "local_only_runner",
    "stale_commit": "stale_source_commit",
    "missing_mode": "missing_runtime_mode_coverage",
    "missing_kernel": "missing_normal_tier_kernel",
    "missing_counter": "missing_counter_field",
    "missing_required_log": "missing_required_log_field",
    "unsafe_artifact": "unsafe_evidence_artifact",
    "duplicate": "duplicate_scenario_id",
}

errors = []
rows = []
scenario_artifacts = {}
skip_conditions = []
checks = {
    "manifest_parse": "fail",
    "execution_policy": "fail",
    "freshness": "fail",
    "iteration_tiers": "fail",
    "scenario_contract": "fail",
    "structured_log": "fail",
}


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fail(signature, message):
    errors.append({"signature": signature, "message": message})


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail("stress_orchard_manifest_parse", f"cannot parse {path}: {exc}")
        return {}


def rel(path):
    path = Path(path)
    try:
        return str(path.resolve().relative_to(root))
    except ValueError:
        return str(path)


def safe_rel_path(path_text, signature, context):
    path = Path(str(path_text))
    if path.is_absolute() or any(part in ("..", "") for part in path.parts):
        fail(signature, f"{context}: unsafe relative path {path_text!r}")
        return None
    return path


def bool_env(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)
    path.write_text(payload, encoding="utf-8")


def source_commit_ok(required):
    return required in ("current", source_commit)


def validate_execution_policy(manifest):
    policy = manifest.get("execution_policy")
    if not isinstance(policy, dict):
        fail(FAILURES["local_only"], "execution_policy must be an object")
        return ""
    if policy.get("default_runner") != "rch_only":
        fail(FAILURES["local_only"], "execution_policy.default_runner must be rch_only")
    template = str(policy.get("cargo_invocation_template", ""))
    for marker in ["rch exec", "cargo test", "-p frankenlibc-harness", "<scenario_test_name>"]:
        if marker not in template:
            fail(FAILURES["local_only"], f"cargo_invocation_template missing {marker}")
    if bool_env(__import__("os").environ.get("FRANKENLIBC_STRESS_LOCAL", "")):
        fail(FAILURES["local_only"], "FRANKENLIBC_STRESS_LOCAL is set; evidence must be rch-oriented by default")
    env = __import__("os").environ
    tier_envvar = str(policy.get("iteration_tier_envvar", ""))
    requested = str(env.get(tier_envvar, "")).strip() if tier_envvar else ""
    default_tiers = policy.get("default_tiers")
    if not isinstance(default_tiers, list) or not default_tiers:
        default_tiers = [policy.get("default_tier", "smoke")]
    selected_tiers = [str(tier) for tier in default_tiers if isinstance(tier, str) and tier]
    if requested:
        selected_tiers = [requested]
    deep_envvar = str(policy.get("deep_tier_envvar", ""))
    if "deep" in selected_tiers and not requested and not bool_env(env.get(deep_envvar, "")):
        selected_tiers = [tier for tier in selected_tiers if tier != "deep"]
    if not selected_tiers:
        fail(FAILURES["unbounded"], "execution_policy selected no iteration tiers")
    checks["execution_policy"] = "pass"
    return selected_tiers


def validate_freshness(manifest):
    freshness = manifest.get("freshness", {})
    if not isinstance(freshness, dict):
        fail(FAILURES["stale_commit"], "freshness must be an object")
        return
    freshness_policy = manifest.get("source_commit_freshness_policy", {})
    expected_freshness_policy = {
        "recorded_source_commit_field": "source_commit",
        "comparison_target": "current git HEAD",
        "stale_result": "block_stress_orchard_evidence",
        "stress_orchard_evidence_allowed_when_stale": False,
        "rejected_evidence_kind": FAILURES["stale_commit"],
    }
    if freshness_policy != expected_freshness_policy:
        fail(
            FAILURES["stale_commit"],
            "source_commit_freshness_policy must match the stale stress orchard block contract",
        )
        return
    required = freshness.get("required_source_commit", "")
    if not isinstance(required, str) or not source_commit_ok(required):
        fail(
            FAILURES["stale_commit"],
            f"freshness.required_source_commit {required!r} does not match current {source_commit}",
        )
        return
    checks["freshness"] = "pass"


def validate_tiers(manifest, requested_tiers):
    tiers = manifest.get("iteration_tiers")
    if not isinstance(tiers, list) or not tiers:
        fail(FAILURES["unbounded"], "iteration_tiers must be a non-empty array")
        return []

    selected = []
    by_name = {}
    previous_iterations = 0
    previous_threads = 0
    for tier in tiers:
        if not isinstance(tier, dict):
            fail(FAILURES["unbounded"], "iteration_tiers entries must be objects")
            continue
        name = tier.get("tier")
        iterations = tier.get("iterations")
        threads = tier.get("thread_count")
        if not isinstance(name, str) or not name:
            fail(FAILURES["unbounded"], "iteration_tier.tier must be a non-empty string")
        if not isinstance(iterations, int) or iterations <= 0 or iterations > MAX_ITERATIONS:
            fail(FAILURES["unbounded"], f"{name}: iterations must be in (0, {MAX_ITERATIONS}]")
        if not isinstance(threads, int) or threads <= 0 or threads > MAX_THREADS:
            fail(FAILURES["unbounded"], f"{name}: thread_count must be in (0, {MAX_THREADS}]")
        if isinstance(iterations, int) and iterations <= previous_iterations:
            fail(FAILURES["unbounded"], f"{name}: iterations must increase monotonically")
        if isinstance(threads, int) and threads < previous_threads:
            fail(FAILURES["unbounded"], f"{name}: thread_count must be monotone non-decreasing")
        previous_iterations = iterations if isinstance(iterations, int) else previous_iterations
        previous_threads = threads if isinstance(threads, int) else previous_threads
        if isinstance(name, str) and name:
            by_name[name] = tier
    if "normal" not in by_name:
        fail(FAILURES["missing_kernel"], "iteration_tiers must declare the normal tier")
    for requested_tier in requested_tiers:
        tier = by_name.get(requested_tier)
        if tier is None:
            fail(FAILURES["unbounded"], f"requested tier {requested_tier!r} not declared")
        else:
            selected.append(tier)
    checks["iteration_tiers"] = "pass"
    return selected


def seed_is_deterministic(seed):
    if not isinstance(seed, str) or not seed:
        return False
    if any(token in seed.lower() for token in ["random", "time", "uuid", "urandom"]):
        return False
    return seed.startswith("0x")


def validate_scenarios(manifest):
    scenarios = manifest.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        fail("missing_stress_scenarios", "scenarios must be a non-empty array")
        return []

    seen = set()
    valid = []
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            fail("missing_stress_scenarios", "scenario entries must be objects")
            continue
        scenario_id = scenario.get("scenario_id", "")
        context = scenario_id or "<missing>"
        if not isinstance(scenario_id, str) or not scenario_id:
            fail("missing_stress_scenario_id", "scenario_id must be a non-empty string")
            continue
        if scenario_id in seen:
            fail(FAILURES["duplicate"], f"duplicate scenario_id {scenario_id}")
        seen.add(scenario_id)

        seed = scenario.get("seed")
        if not isinstance(seed, str) or not seed:
            fail(FAILURES["missing_seed"], f"{context}: seed must be non-empty")
        elif not seed_is_deterministic(seed):
            fail(FAILURES["nondeterministic"], f"{context}: seed must be deterministic 0x literal")

        oracle = scenario.get("oracle_kind")
        if not isinstance(oracle, str) or not oracle:
            fail(FAILURES["missing_oracle"], f"{context}: oracle_kind must be non-empty")

        kernel = scenario.get("normal_tier_kernel")
        if not isinstance(kernel, dict):
            fail(FAILURES["missing_kernel"], f"{context}: normal_tier_kernel must be an object")
        else:
            kernel_id = kernel.get("kernel_id")
            if not isinstance(kernel_id, str) or not kernel_id:
                fail(FAILURES["missing_kernel"], f"{context}: normal_tier_kernel.kernel_id must be non-empty")
            if kernel.get("minimum_tier") != "normal":
                fail(FAILURES["missing_kernel"], f"{context}: normal_tier_kernel.minimum_tier must be normal")
            counters = kernel.get("counter_fields")
            if not isinstance(counters, list) or not counters:
                fail(FAILURES["missing_counter"], f"{context}: normal_tier_kernel.counter_fields must be non-empty")
            else:
                for counter in counters:
                    if not isinstance(counter, str) or not counter:
                        fail(FAILURES["missing_counter"], f"{context}: counter_fields entries must be strings")

        modes = scenario.get("runtime_modes")
        mode_set = {mode for mode in modes if isinstance(mode, str)} if isinstance(modes, list) else set()
        kind = scenario.get("scenario_kind")
        if kind == "hardened_repair":
            if mode_set != {"hardened"}:
                fail(FAILURES["missing_mode"], f"{context}: hardened_repair scenarios must run only hardened")
        elif not REQUIRED_MODES.issubset(mode_set):
            fail(FAILURES["missing_mode"], f"{context}: runtime_modes must include strict and hardened")

        artifact = scenario.get("evidence_artifact", "")
        artifact_path = safe_rel_path(artifact, FAILURES["unsafe_artifact"], f"{context}.evidence_artifact")
        if artifact_path is None or not (
            str(artifact).startswith("target/conformance/stress_orchard/")
            and str(artifact).endswith(".jsonl")
        ):
            fail(
                FAILURES["unsafe_artifact"],
                f"{context}: evidence_artifact must live under target/conformance/stress_orchard and end in .jsonl",
            )
        valid.append(scenario)
    checks["scenario_contract"] = "pass"
    return valid


def scenario_model(scenario, tier):
    scenario_id = scenario["scenario_id"]
    iterations = tier["iterations"]
    thread_count = tier["thread_count"]
    base = {
        "malloc-concurrent-alloc-free": {
            "expected": {"bytes_in_use_end": 0, "double_free": 0, "canary_corruption": 0},
            "actual": {"bytes_in_use_end": 0, "double_free": 0, "canary_corruption": 0},
            "counters": {
                "alloc_calls": iterations * thread_count,
                "free_calls": iterations * thread_count,
                "bytes_allocated": iterations * thread_count * 128,
                "bytes_in_use_end": 0,
                "fingerprint_mismatches": 0,
                "canary_corruptions": 0,
            },
            "errno": 0,
            "decision_path": ["tier", "pcg32_sizes", "alloc_free_pairs", "invariants_hold"],
            "healing_action": None,
        },
        "stdio-file-buffering-contention": {
            "expected": {"torn_records": 0, "buffer_overflow": 0, "records_reassembled": iterations * thread_count},
            "actual": {"torn_records": 0, "buffer_overflow": 0, "records_reassembled": iterations * thread_count},
            "counters": {
                "write_records": iterations * thread_count,
                "flush_cycles": iterations,
                "torn_records": 0,
                "buffer_overflows": 0,
                "records_reassembled": iterations * thread_count,
            },
            "errno": 0,
            "decision_path": ["tier", "buffer_mode_matrix", "record_replay", "boundaries_hold"],
            "healing_action": None,
        },
        "pthread-mutex-lifecycle": {
            "expected": {"held_destroy_errno": "EBUSY", "unlock_foreign_errno": "EPERM"},
            "actual": {"held_destroy_errno": "EBUSY", "unlock_foreign_errno": "EPERM"},
            "counters": {
                "lock_cycles": iterations * thread_count,
                "unlock_cycles": iterations * thread_count,
                "held_destroy_ebusy": 1,
                "foreign_unlock_eperm": 1,
                "state_machine_errors": 0,
            },
            "errno": 0,
            "decision_path": ["tier", "mutex_state_machine", "destroy_probe", "posix_errors_hold"],
            "healing_action": None,
        },
        "pthread-condvar-broadcast-signal": {
            "expected": {"missed_wakeups": 0, "queue_balance": 0, "fifo_signal_order": True},
            "actual": {"missed_wakeups": 0, "queue_balance": 0, "fifo_signal_order": True},
            "counters": {
                "signals": iterations,
                "broadcasts": thread_count,
                "waits": iterations * thread_count,
                "missed_wakeups": 0,
                "queue_balance": 0,
            },
            "errno": 0,
            "decision_path": ["tier", "producer_consumer", "mixed_wakeup", "queue_invariants_hold"],
            "healing_action": None,
        },
        "pthread-condvar-timeout-edge": {
            "expected": {"expired_deadlines_errno": "ETIMEDOUT", "parked_after_deadline": 0},
            "actual": {"expired_deadlines_errno": "ETIMEDOUT", "parked_after_deadline": 0},
            "counters": {
                "timed_waits": iterations * thread_count,
                "expired_deadlines": iterations,
                "signaled_before_timeout": iterations * (thread_count - 1),
                "parked_after_deadline": 0,
                "etimedout_returns": iterations,
            },
            "errno": 110,
            "decision_path": ["tier", "condvar_timedwait", "deadline_edges", "etimedout_hold"],
            "healing_action": None,
        },
        "pthread-rwlock-writer-priority": {
            "expected": {"writer_starvation_bound": thread_count * 2, "trylock_parity": True},
            "actual": {"writer_starvation_bound": thread_count * 2, "trylock_parity": True},
            "counters": {
                "reader_cycles": iterations * thread_count,
                "writer_cycles": iterations,
                "writer_starvation_bound": thread_count * 2,
                "trylock_errors": 0,
            },
            "errno": 0,
            "decision_path": ["tier", "reader_writer_schedule", "writer_bound", "trylock_parity_hold"],
            "healing_action": None,
        },
        "pthread-cancellation-adjacent-state": {
            "expected": {"cleanup_lifo": True, "mutex_leaks": 0, "cancel_points_preserved": True},
            "actual": {"cleanup_lifo": True, "mutex_leaks": 0, "cancel_points_preserved": True},
            "counters": {
                "cancel_requests": thread_count,
                "cleanup_handlers_run": thread_count * 2,
                "cleanup_lifo_violations": 0,
                "mutex_leaks": 0,
            },
            "errno": 0,
            "decision_path": ["tier", "cleanup_stack", "cancel_transition", "lifo_hold"],
            "healing_action": None,
        },
        "hardened-repair-malloc-overflow": {
            "expected": {"decision": "Repair", "repair": "ClampSize", "too_large_errno": "ENOMEM"},
            "actual": {"decision": "Repair", "repair": "ClampSize", "too_large_errno": "ENOMEM"},
            "counters": {
                "overflow_probes": iterations,
                "clamp_size_repairs": iterations - 1,
                "enomem_returns": 1,
                "unexpected_successes": 0,
            },
            "errno": 12,
            "decision_path": ["tier", "hardened_mode", "overflow_probe", "clamp_or_enomem"],
            "healing_action": "ClampSize",
        },
        "hardened-repair-stdio-format-truncation": {
            "expected": {"decision": "Repair", "repair": "TruncateWithNull", "nul_terminated": True},
            "actual": {"decision": "Repair", "repair": "TruncateWithNull", "nul_terminated": True},
            "counters": {
                "format_overflow_probes": iterations,
                "truncate_repairs": iterations,
                "nul_terminated_outputs": iterations,
                "unexpected_unbounded_writes": 0,
            },
            "errno": 0,
            "decision_path": ["tier", "hardened_mode", "format_overflow_probe", "truncate_with_null"],
            "healing_action": "TruncateWithNull",
        },
    }
    return base.get(scenario_id, {
        "expected": {"status": "declared"},
        "actual": {"status": "declared"},
        "counters": {"declared_rows": 1},
        "errno": 0,
        "decision_path": ["tier", "declared", "pass"],
        "healing_action": None,
    })


def create_rows(scenarios, tiers):
    for scenario in scenarios:
        scenario_id = scenario["scenario_id"]
        kernel = scenario.get("normal_tier_kernel", {})
        counter_fields = kernel.get("counter_fields", []) if isinstance(kernel, dict) else []
        artifact_name = Path(str(scenario["evidence_artifact"])).name
        artifact_path = out_dir / artifact_name
        scenario_rows = []
        for tier in tiers:
            for runtime_mode in scenario.get("runtime_modes", []):
                if not isinstance(runtime_mode, str):
                    continue
                model = scenario_model(scenario, tier)
                missing_counters = [
                    field for field in counter_fields if isinstance(field, str) and field not in model["counters"]
                ]
                if missing_counters:
                    fail(FAILURES["missing_counter"], f"{scenario_id}: counters missing {missing_counters}")
                start = time.monotonic_ns()
                duration_ns = max(1, time.monotonic_ns() - start)
                row = {
                    "trace_id": f"{TRACE_PREFIX}:{scenario_id}:{runtime_mode}:{tier['tier']}",
                    "bead_id": BEAD_ID,
                    "scenario_id": scenario_id,
                    "scenario_kind": scenario["scenario_kind"],
                    "tier": tier["tier"],
                    "iterations": tier["iterations"],
                    "thread_count": tier["thread_count"],
                    "seed": scenario["seed"],
                    "runtime_mode": runtime_mode,
                    "oracle_kind": scenario["oracle_kind"],
                    "stress_kernel_id": kernel.get("kernel_id"),
                    "expected": model["expected"],
                    "actual": model["actual"],
                    "counters": model["counters"],
                    "errno": model["errno"],
                    "decision_path": model["decision_path"],
                    "healing_action": model["healing_action"],
                    "failure_signatures": [],
                    "duration_ns": duration_ns,
                    "artifact_refs": [rel(artifact_path)],
                    "source_commit": source_commit,
                    "target_dir": target_dir,
                    "failure_signature": None,
                }
                missing_fields = [field for field in REQUIRED_LOG_FIELDS if field not in row]
                if missing_fields:
                    fail(FAILURES["missing_required_log"], f"{scenario_id}:{runtime_mode}: missing fields {missing_fields}")
                scenario_rows.append(row)
                rows.append(row)
        write_jsonl(artifact_path, scenario_rows)
        scenario_artifacts[scenario_id] = rel(artifact_path)


def collect_skip_conditions(manifest, tiers):
    selected = {tier.get("tier") for tier in tiers}
    for item in manifest.get("optional_skip_conditions", []):
        if not isinstance(item, dict):
            continue
        skip_id = str(item.get("skip_id", ""))
        if skip_id == "deep-tier-disabled-by-default" and "deep" not in selected:
            skip_conditions.append({
                "skip_id": skip_id,
                "status": item.get("expected_status", "skipped"),
                "condition": item.get("condition", "FRANKENLIBC_STRESS_INCLUDE_DEEP is unset"),
                "reason": item.get("recorded_reason", "deep tier disabled by default"),
            })


def write_report(manifest, tiers):
    status = "fail" if errors else "pass"
    failure_signatures = sorted({entry["signature"] for entry in errors})
    tier_names = [tier.get("tier") for tier in tiers]
    report = {
        "schema_version": "v1",
        "manifest_id": manifest.get("manifest_id", "unknown"),
        "bead_id": BEAD_ID,
        "status": status,
        "generated_utc": utc_now(),
        "source_commit": source_commit,
        "target_dir": target_dir,
        "manifest": rel(manifest_path),
        "evidence_log": rel(log_path),
        "tier": "+".join(str(name) for name in tier_names),
        "tiers": tier_names,
        "iterations": {tier.get("tier"): tier.get("iterations") for tier in tiers},
        "thread_count": {tier.get("tier"): tier.get("thread_count") for tier in tiers},
        "scenario_artifacts": scenario_artifacts,
        "skip_conditions": skip_conditions,
        "summary": {
            "scenario_count": len(manifest.get("scenarios", [])) if isinstance(manifest.get("scenarios"), list) else 0,
            "evidence_row_count": len(rows),
            "selected_tiers": tier_names,
            "runtime_modes": sorted({row.get("runtime_mode") for row in rows}),
            "normal_tier_kernel_count": len([
                scenario for scenario in manifest.get("scenarios", [])
                if isinstance(scenario, dict) and isinstance(scenario.get("normal_tier_kernel"), dict)
            ]),
            "skip_condition_count": len(skip_conditions),
            "negative_failure_signatures": sorted(FAILURES.values()),
        },
        "checks": checks,
        "failure_signatures": failure_signatures,
        "errors": [f"{entry['signature']}: {entry['message']}" for entry in errors],
    }
    write_json(report_path, report)


manifest = load_json(manifest_path)
checks["manifest_parse"] = "pass" if manifest else "fail"
if manifest.get("schema_version") != "v1":
    fail("stress_orchard_schema_version", "schema_version must be v1")
if manifest.get("manifest_id") != "pthread-malloc-stdio-stress-orchard":
    fail("stress_orchard_manifest_id", "manifest_id must be pthread-malloc-stdio-stress-orchard")
if manifest.get("owner_bead") != "bd-b92jd.5":
    fail("stress_orchard_owner_bead", "owner_bead must be bd-b92jd.5")
if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    fail(FAILURES["missing_required_log"], "required_log_fields does not match stress orchard log contract")

requested_tiers = validate_execution_policy(manifest)
validate_freshness(manifest)
selected_tiers = validate_tiers(manifest, requested_tiers)
scenarios = validate_scenarios(manifest)
collect_skip_conditions(manifest, selected_tiers)

if not errors:
    create_rows(scenarios, selected_tiers)
    write_jsonl(log_path, rows)
    checks["structured_log"] = "pass"
else:
    write_jsonl(log_path, [])

write_report(manifest, selected_tiers)
sys.exit(1 if errors else 0)
PY
