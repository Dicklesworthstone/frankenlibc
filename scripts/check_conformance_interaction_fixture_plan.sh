#!/usr/bin/env bash
# check_conformance_interaction_fixture_plan.sh -- bd-bp8fl.9.2
#
# Static fail-closed validator for the conformance interaction fixture scheduler
# artifact. Generates a deterministic report and JSONL coverage diagnostics.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN="${FRANKENLIBC_CONFORMANCE_INTERACTION_PLAN:-${ROOT}/tests/conformance/conformance_interaction_fixture_plan.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_CONFORMANCE_INTERACTION_REPORT:-${OUT_DIR}/conformance_interaction_fixture_plan.report.json}"
LOG="${FRANKENLIBC_CONFORMANCE_INTERACTION_LOG:-${OUT_DIR}/conformance_interaction_fixture_plan.log.jsonl}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${PLAN}" "${REPORT}" "${LOG}" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
plan_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

BEAD_ID = "bd-bp8fl.9.2"
PLAN_ID = "conformance-interaction-fixture-plan-v1"
TRACE_ID = f"{BEAD_ID}:{PLAN_ID}"
SCORE_FORMULA = (
    "risk_weight*100 + user_workload_exposure*10 + "
    "fixture_gap_weight + hard_parts_weight"
)
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "plan_id",
    "interaction_tuple",
    "coverage_level",
    "selected",
    "reason",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
REQUIRED_INPUTS = [
    "symbols",
    "modes",
    "locale_env_thread_state",
    "invalid_input_classes",
    "replacement_levels",
    "risk_weights",
    "fixture_inventory",
    "user_workload_exposure",
]
REQUIRED_CANDIDATE_FIELDS = [
    "candidate_id",
    "symbol",
    "campaign_id",
    "symbol_family",
    "runtime_mode",
    "locale_env_thread_state",
    "invalid_input_class",
    "replacement_level",
    "risk_weight",
    "user_workload_exposure",
    "fixture_gap_weight",
    "hard_parts_weight",
    "priority_score",
    "feasible",
    "reason",
]
CHECK_NAMES = [
    "json_parse",
    "top_level_shape",
    "scheduler_inputs",
    "fixture_inventory_freshness",
    "candidate_contract",
    "deterministic_selection",
    "coverage_constraints",
    "blocked_combination_diagnostics",
    "structured_log",
]

errors = []
logs = []
checks = {name: "fail" for name in CHECK_NAMES}


def fail(message):
    errors.append(message)


def load_json(path, label):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{label}: cannot parse {path}: {exc}")
        return None


def safe_rel_path(rel):
    path = Path(str(rel))
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe relative path: {rel}")
    return root / path


def source_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


SOURCE_COMMIT = source_commit()


def log_row(interaction_tuple, coverage_level, selected, reason, artifact_refs, failure_signature=""):
    row = {
        "trace_id": TRACE_ID,
        "bead_id": BEAD_ID,
        "plan_id": PLAN_ID,
        "interaction_tuple": interaction_tuple,
        "coverage_level": coverage_level,
        "selected": selected,
        "reason": reason,
        "artifact_refs": artifact_refs,
        "source_commit": SOURCE_COMMIT,
        "failure_signature": failure_signature,
    }
    logs.append(row)
    return row


def calculated_score(row):
    return (
        int(row.get("risk_weight", 0)) * 100
        + int(row.get("user_workload_exposure", 0)) * 10
        + int(row.get("fixture_gap_weight", 0))
        + int(row.get("hard_parts_weight", 0))
    )


def matches(candidate, interaction):
    axes = interaction.get("axes", [])
    values = interaction.get("values", [])
    if len(axes) != len(values) or not axes:
        return False
    return all(candidate.get(axis) == value for axis, value in zip(axes, values))


def combo_matches(candidate, combo):
    for key in (
        "candidate_id",
        "symbol_family",
        "runtime_mode",
        "locale_env_thread_state",
        "invalid_input_class",
        "replacement_level",
    ):
        if key in combo and candidate.get(key) != combo.get(key):
            return False
    return True


plan = load_json(plan_path, "plan")
inventory = None
candidate_by_id = {}
selected_candidates = []
metrics = {
    "selected_count": 0,
    "blocked_count": 0,
    "pairwise_required": 0,
    "pairwise_covered": 0,
    "pairwise_coverage_pct": 0.0,
    "twise_required": 0,
    "twise_covered": 0,
    "twise_coverage_pct": 0.0,
}

if plan is not None:
    checks["json_parse"] = "pass"
    if (
        plan.get("schema_version") == "v1"
        and plan.get("bead") == BEAD_ID
        and plan.get("plan_id") == PLAN_ID
        and plan.get("required_log_fields") == REQUIRED_LOG_FIELDS
        and isinstance(plan.get("candidates"), list)
        and isinstance(plan.get("selected_plan"), list)
        and isinstance(plan.get("blocked_combinations"), list)
    ):
        checks["top_level_shape"] = "pass"
    else:
        fail("top_level_shape: schema, bead, plan_id, log fields, or core arrays are invalid")

    inputs = plan.get("scheduler_inputs")
    if isinstance(inputs, dict):
        input_ok = True
        for key in REQUIRED_INPUTS:
            value = inputs.get(key)
            if key not in inputs:
                fail(f"scheduler_inputs: missing {key}")
                input_ok = False
            elif key in {"risk_weights", "fixture_inventory"}:
                if not isinstance(value, dict) or not value:
                    fail(f"scheduler_inputs.{key}: must be a non-empty object")
                    input_ok = False
            elif not isinstance(value, list) or not value:
                fail(f"scheduler_inputs.{key}: must be a non-empty array")
                input_ok = False
        policy = plan.get("selection_policy", {})
        if (
            not isinstance(policy, dict)
            or policy.get("score_formula") != SCORE_FORMULA
            or int(policy.get("max_selected", 0)) <= 0
            or policy.get("tie_break") != "candidate_id"
        ):
            fail("selection_policy: formula, max_selected, or tie_break is invalid")
            input_ok = False
        if input_ok:
            checks["scheduler_inputs"] = "pass"
    else:
        fail("scheduler_inputs: must be an object")
        inputs = {}

    inventory_spec = inputs.get("fixture_inventory", {}) if isinstance(inputs, dict) else {}
    if isinstance(inventory_spec, dict) and "artifact" in inventory_spec:
        try:
            inventory_path = safe_rel_path(inventory_spec["artifact"])
            inventory = load_json(inventory_path, "fixture_inventory")
            campaigns = inventory.get("campaigns", []) if isinstance(inventory, dict) else []
            expected_count = int(inventory_spec.get("expected_campaign_count", -1))
            expected_top = inventory_spec.get("expected_top_campaign_id")
            actual_top = campaigns[0].get("campaign_id") if campaigns else None
            if (
                isinstance(campaigns, list)
                and len(campaigns) == expected_count
                and actual_top == expected_top
            ):
                checks["fixture_inventory_freshness"] = "pass"
            else:
                fail(
                    "fixture_inventory_freshness: expected "
                    f"{expected_count}/{expected_top}, got {len(campaigns)}/{actual_top}"
                )
        except Exception as exc:
            fail(f"fixture_inventory_freshness: {exc}")
            campaigns = []
    else:
        fail("fixture_inventory_freshness: fixture_inventory.artifact is required")
        campaigns = []

    campaign_by_id = {
        row.get("campaign_id"): row
        for row in campaigns
        if isinstance(row, dict) and row.get("campaign_id")
    }

    candidate_ok = True
    seen_ids = set()
    input_symbols = set(inputs.get("symbols", [])) if isinstance(inputs, dict) else set()
    input_modes = set(inputs.get("modes", [])) if isinstance(inputs, dict) else set()
    input_states = set(inputs.get("locale_env_thread_state", [])) if isinstance(inputs, dict) else set()
    input_invalids = set(inputs.get("invalid_input_classes", [])) if isinstance(inputs, dict) else set()
    input_levels = set(inputs.get("replacement_levels", [])) if isinstance(inputs, dict) else set()
    candidates = plan.get("candidates", [])
    if not isinstance(candidates, list) or not candidates:
        fail("candidate_contract: candidates must be a non-empty array")
        candidate_ok = False
        candidates = []
    for row in candidates:
        if not isinstance(row, dict):
            fail("candidate_contract: candidate entries must be objects")
            candidate_ok = False
            continue
        missing = [key for key in REQUIRED_CANDIDATE_FIELDS if key not in row]
        if missing:
            fail(f"candidate_contract: {row.get('candidate_id', '<unknown>')} missing {missing}")
            candidate_ok = False
            continue
        cid = row["candidate_id"]
        if cid in seen_ids:
            fail(f"candidate_contract: duplicate candidate_id {cid}")
            candidate_ok = False
        seen_ids.add(cid)
        candidate_by_id[cid] = row
        if not row.get("feasible") and not row.get("blocked_reason"):
            fail(f"candidate_contract: {cid} blocked candidates need blocked_reason")
            candidate_ok = False
        expected_score = calculated_score(row)
        if row.get("priority_score") != expected_score:
            fail(
                f"candidate_contract: {cid} priority_score {row.get('priority_score')} "
                f"does not match {expected_score}"
            )
            candidate_ok = False
        if row.get("symbol") not in input_symbols:
            fail(f"candidate_contract: {cid} symbol missing from scheduler_inputs.symbols")
            candidate_ok = False
        if row.get("runtime_mode") not in input_modes:
            fail(f"candidate_contract: {cid} mode missing from scheduler_inputs.modes")
            candidate_ok = False
        if row.get("locale_env_thread_state") not in input_states:
            fail(f"candidate_contract: {cid} state missing from scheduler inputs")
            candidate_ok = False
        if row.get("invalid_input_class") not in input_invalids:
            fail(f"candidate_contract: {cid} invalid class missing from scheduler inputs")
            candidate_ok = False
        if row.get("replacement_level") not in input_levels:
            fail(f"candidate_contract: {cid} replacement level missing from scheduler inputs")
            candidate_ok = False
        campaign = campaign_by_id.get(row.get("campaign_id"))
        if campaign is None:
            fail(f"candidate_contract: {cid} references unknown campaign {row.get('campaign_id')}")
            candidate_ok = False
        elif row.get("symbol") not in campaign.get("first_wave_symbols", []):
            fail(f"candidate_contract: {cid} symbol is not in campaign first_wave_symbols")
            candidate_ok = False
    if candidate_ok:
        checks["candidate_contract"] = "pass"

    selected_ids = plan.get("selected_plan", [])
    max_selected = int(plan.get("selection_policy", {}).get("max_selected", 0) or 0)
    expected_selected = [
        row["candidate_id"]
        for row in sorted(
            [row for row in candidates if isinstance(row, dict) and row.get("feasible") is True],
            key=lambda item: (-int(item.get("priority_score", 0)), item.get("candidate_id", "")),
        )[:max_selected]
    ]
    if selected_ids == expected_selected and all(cid in candidate_by_id for cid in selected_ids):
        checks["deterministic_selection"] = "pass"
    else:
        fail(f"deterministic_selection: expected {expected_selected}, got {selected_ids}")

    selected_candidates = [candidate_by_id[cid] for cid in selected_ids if cid in candidate_by_id]
    metrics["selected_count"] = len(selected_candidates)
    metrics["blocked_count"] = len([row for row in candidates if isinstance(row, dict) and not row.get("feasible")])

    pairwise = plan.get("required_pairwise_interactions", [])
    twise = plan.get("required_twise_interactions", [])
    coverage_ok = True
    for level, rows in (("pairwise", pairwise), ("t-wise", twise)):
        if not isinstance(rows, list) or not rows:
            fail(f"coverage_constraints: {level} interactions must be non-empty")
            coverage_ok = False
            continue
        covered = 0
        for interaction in rows:
            hit = next((row for row in selected_candidates if matches(row, interaction)), None)
            if hit is not None:
                covered += 1
                log_row(
                    interaction,
                    level,
                    True,
                    f"covered_by:{hit['candidate_id']}",
                    [
                        str(plan_path.relative_to(root)) if plan_path.is_relative_to(root) else str(plan_path),
                        inputs.get("fixture_inventory", {}).get("artifact", ""),
                    ],
                )
            else:
                coverage_ok = False
                fail(f"coverage_constraints: missing {level} interaction {interaction}")
                log_row(
                    interaction,
                    level,
                    False,
                    "missing_required_interaction",
                    [str(plan_path)],
                    "coverage_missing",
                )
        if level == "pairwise":
            metrics["pairwise_required"] = len(rows)
            metrics["pairwise_covered"] = covered
            metrics["pairwise_coverage_pct"] = round(100.0 * covered / len(rows), 2)
        else:
            metrics["twise_required"] = len(rows)
            metrics["twise_covered"] = covered
            metrics["twise_coverage_pct"] = round(100.0 * covered / len(rows), 2)
    if coverage_ok:
        checks["coverage_constraints"] = "pass"

    blocked_ok = True
    blocked_combinations = plan.get("blocked_combinations", [])
    if not isinstance(blocked_combinations, list) or not blocked_combinations:
        fail("blocked_combination_diagnostics: blocked_combinations must be non-empty")
        blocked_ok = False
    else:
        for combo in blocked_combinations:
            cid = combo.get("candidate_id")
            candidate = candidate_by_id.get(cid)
            if candidate is None or candidate.get("feasible") is not False:
                fail(f"blocked_combination_diagnostics: {cid} must map to an infeasible candidate")
                blocked_ok = False
            if not combo.get("blocked_reason"):
                fail(f"blocked_combination_diagnostics: {cid} missing blocked_reason")
                blocked_ok = False
            if any(combo_matches(row, combo) for row in selected_candidates):
                fail(f"blocked_combination_diagnostics: selected plan includes blocked combo {cid}")
                blocked_ok = False
                log_row(combo, "blocked", True, "blocked_combo_selected", [str(plan_path)], "blocked_selected")
            else:
                log_row(
                    combo,
                    "blocked",
                    False,
                    f"blocked:{combo.get('blocked_reason')}",
                    [
                        str(plan_path.relative_to(root)) if plan_path.is_relative_to(root) else str(plan_path),
                        inputs.get("fixture_inventory", {}).get("artifact", ""),
                    ],
                )
    if blocked_ok:
        checks["blocked_combination_diagnostics"] = "pass"

    structured_ok = True
    for row in logs:
        missing = [field for field in REQUIRED_LOG_FIELDS if field not in row]
        if missing:
            fail(f"structured_log: row missing {missing}")
            structured_ok = False
    if logs and structured_ok:
        checks["structured_log"] = "pass"

status = "pass" if not errors and all(value == "pass" for value in checks.values()) else "fail"
report = {
    "status": status,
    "bead": BEAD_ID,
    "plan_id": PLAN_ID,
    "trace_id": TRACE_ID,
    "source_commit": SOURCE_COMMIT,
    "checks": checks,
    "metrics": metrics,
    "selected_plan": plan.get("selected_plan", []) if isinstance(plan, dict) else [],
    "blocked_combinations": plan.get("blocked_combinations", []) if isinstance(plan, dict) else [],
    "artifact_refs": [
        str(plan_path.relative_to(root)) if plan_path.is_relative_to(root) else str(plan_path),
        (
            plan.get("scheduler_inputs", {})
            .get("fixture_inventory", {})
            .get("artifact", "")
            if isinstance(plan, dict)
            else ""
        ),
        str(report_path.relative_to(root)) if report_path.is_relative_to(root) else str(report_path),
        str(log_path.relative_to(root)) if log_path.is_relative_to(root) else str(log_path),
    ],
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in logs),
    encoding="utf-8",
)

if status != "pass":
    raise SystemExit("FAIL: conformance interaction fixture plan validation failed")
print(json.dumps(report, indent=2, sort_keys=True))
PY
