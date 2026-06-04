#!/usr/bin/env bash
# check_fixture_coverage_prioritizer.sh -- CI gate for bd-bp8fl.4.1
#
# Validates that the fixture coverage prioritizer is derived from the current
# support and fixture coverage artifacts, ranks campaigns deterministically, and
# emits report/log artifacts for closure evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_fixture_coverage_prioritizer.py"
ARTIFACT="${FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_ARTIFACT:-${ROOT}/tests/conformance/fixture_coverage_prioritizer.v1.json}"
COVERAGE="${FRANKENLIBC_SYMBOL_FIXTURE_COVERAGE_ARTIFACT:-${ROOT}/tests/conformance/symbol_fixture_coverage.v1.json}"
PER_SYMBOL="${FRANKENLIBC_PER_SYMBOL_FIXTURE_ARTIFACT:-${ROOT}/tests/conformance/per_symbol_fixture_tests.v1.json}"
SUPPORT="${ROOT}/support_matrix.json"
WORKLOADS="${ROOT}/tests/conformance/user_workload_acceptance_matrix.v1.json"
FEATURE_GAPS="${ROOT}/tests/conformance/feature_parity_gap_groups.v1.json"
FIXTURES_DIR="${FRANKENLIBC_FIXTURE_WAVE_LIFECYCLE_FIXTURES_DIR:-${ROOT}/tests/conformance/fixtures}"
COMPLETION_CONTRACT_GLOB="${FRANKENLIBC_FIXTURE_WAVE_LIFECYCLE_CONTRACT_GLOB:-tests/conformance/*completion_contract*.v1.json}"
OUT_DIR="${FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_OUT_DIR:-${ROOT}/target/conformance}"
GENERATED="${OUT_DIR}/fixture_coverage_prioritizer.regenerated.v1.json"
REPORT="${FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_REPORT:-${OUT_DIR}/fixture_coverage_prioritizer.report.json}"
LOG="${FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_LOG:-${OUT_DIR}/fixture_coverage_prioritizer.log.jsonl}"

mkdir -p "${OUT_DIR}"

if [[ "${FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_SKIP_REGEN:-0}" != "1" ]]; then
    python3 "${GEN}" --self-test >/dev/null
    python3 "${GEN}" --output "${GENERATED}" >/dev/null
    if ! cmp -s "${ARTIFACT}" "${GENERATED}"; then
        echo "ERROR: fixture coverage prioritizer artifact drift detected" >&2
        echo "       regenerate with: python3 scripts/generate_fixture_coverage_prioritizer.py --output tests/conformance/fixture_coverage_prioritizer.v1.json" >&2
        exit 1
    fi
fi

python3 - "${ROOT}" "${ARTIFACT}" "${COVERAGE}" "${PER_SYMBOL}" "${SUPPORT}" "${WORKLOADS}" "${FEATURE_GAPS}" "${REPORT}" "${LOG}" "${FIXTURES_DIR}" "${COMPLETION_CONTRACT_GLOB}" <<'PY'
import json
import glob
import subprocess
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
coverage_path = Path(sys.argv[3])
per_symbol_path = Path(sys.argv[4])
support_path = Path(sys.argv[5])
workloads_path = Path(sys.argv[6])
feature_gaps_path = Path(sys.argv[7])
report_path = Path(sys.argv[8])
log_path = Path(sys.argv[9])
fixtures_dir = Path(sys.argv[10])
completion_contract_glob = sys.argv[11]

errors = []
checks = {}

EXPECTED_INPUTS = {
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
REQUIRED_CAMPAIGN_FIELDS = [
    "rank",
    "campaign_id",
    "module",
    "title",
    "symbol_family",
    "target_total",
    "target_covered",
    "target_uncovered",
    "current_coverage_pct",
    "first_wave_symbols",
    "first_wave_fixture_count",
    "expected_coverage_after_first_wave_pct",
    "workload_domains",
    "risk_tags",
    "scores",
    "oracle_kind",
    "deterministic_e2e_scripts",
    "structured_log_fields",
    "next_step",
]
REQUIRED_DEFERRED_FIELDS = [
    "module",
    "target_total",
    "target_covered",
    "target_uncovered",
    "current_coverage_pct",
    "status_breakdown",
    "deferral_reason",
    "next_step",
]
REQUIRED_FULLY_COVERED_DOMAIN_SOURCE_FIELDS = [
    "module",
    "target_total",
    "target_covered",
    "target_uncovered",
    "current_coverage_pct",
    "coverage_state",
    "workload_domains",
]
REQUIRED_FIXTURE_WAVE_LIFECYCLE_REPORT_FIELDS = [
    "fixture_file",
    "fixture_family",
    "wave_id",
    "covered_symbols",
    "missing_coverage_artifacts",
    "missing_completion_contract",
    "failure_signature",
]
CONTRACT_REQUIRED_WAVE_FIXTURES = {
    "string_memory_hotpaths_wave05.json",
    "string_memory_hotpaths_wave06.json",
    "string_memory_hotpaths_wave10.json",
    "string_memory_hotpaths_wave11.json",
    "unistd_process_filesystem_wave02.json",
    "unistd_process_filesystem_wave03.json",
    "unistd_process_filesystem_wave04.json",
    "unistd_process_filesystem_wave05.json",
}
COMPLETED_UNISTD_PROCESS_FILESYSTEM_FIRST_WAVE = [
    "_Exit",
    "_Fork",
    "__cxa_atexit",
    "__cxa_finalize",
    "__fxstat",
    "__fxstat64",
    "__fxstatat",
    "__fxstatat64",
    "__gmtime_r",
    "__lxstat",
    "__lxstat64",
    "__progname",
]
COMPLETED_UNISTD_PROCESS_FILESYSTEM_FIXTURE = Path(
    "tests/conformance/fixtures/unistd_process_filesystem.json"
)
COMPLETED_UNISTD_PROCESS_FILESYSTEM_HARNESS = Path(
    "crates/frankenlibc-harness/tests/unistd_process_filesystem_conformance_test.rs"
)
COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03 = [
    "addseverity",
    "adjtimex",
    "aio_cancel",
    "aio_cancel64",
    "aio_error",
    "aio_error64",
    "aio_fsync",
    "aio_fsync64",
    "aio_init",
    "aio_read",
    "aio_read64",
    "aio_return",
]
COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04 = [
    "aio_return64",
    "aio_suspend",
    "aio_suspend64",
    "aio_write",
    "aio_write64",
    "alarm",
    "arc4random",
    "arc4random_buf",
    "arc4random_uniform",
    "argp_error",
    "argp_failure",
    "argp_help",
]
COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03_FIXTURE = Path(
    "tests/conformance/fixtures/unistd_process_filesystem_wave03.json"
)
COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03_HARNESS = Path(
    "crates/frankenlibc-harness/tests/unistd_process_filesystem_wave03_conformance_test.rs"
)
COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04_FIXTURE = Path(
    "tests/conformance/fixtures/unistd_process_filesystem_wave04.json"
)
COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04_HARNESS = Path(
    "crates/frankenlibc-harness/tests/unistd_process_filesystem_wave04_conformance_test.rs"
)
COMPLETED_STDIO_LIBIO_FIRST_WAVE = [
    "_IO_2_1_stderr_",
    "_IO_2_1_stdin_",
    "_IO_2_1_stdout_",
    "_IO_feof",
    "_IO_ferror",
    "_IO_flockfile",
    "_IO_ftrylockfile",
    "_IO_funlockfile",
    "_IO_getc",
    "_IO_padn",
    "_IO_peekc_locked",
    "_IO_putc",
]
COMPLETED_STDIO_LIBIO_FIXTURE = Path(
    "tests/conformance/fixtures/stdio_libio_symbols.json"
)
COMPLETED_STDIO_LIBIO_HARNESS = Path(
    "crates/frankenlibc-harness/tests/stdio_libio_symbols_conformance_test.rs"
)

def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return None

artifact = load_json(artifact_path)
coverage = load_json(coverage_path)
per_symbol = load_json(per_symbol_path)
support = load_json(support_path)
workloads = load_json(workloads_path)
feature_gaps = load_json(feature_gaps_path)
checks["json_parse"] = "pass" if all(isinstance(x, dict) for x in [artifact, coverage, per_symbol, support, workloads, feature_gaps]) else "fail"
if not isinstance(artifact, dict):
    artifact = {}
if not isinstance(coverage, dict):
    coverage = {}
if not isinstance(per_symbol, dict):
    per_symbol = {}
if not isinstance(support, dict):
    support = {}
if not isinstance(workloads, dict):
    workloads = {}
if not isinstance(feature_gaps, dict):
    feature_gaps = {}

if artifact.get("schema_version") == "v1" and artifact.get("bead") == "bd-bp8fl.4.1":
    checks["top_level_shape"] = "pass"
else:
    checks["top_level_shape"] = "fail"
    errors.append("artifact must declare schema_version=v1 and bead=bd-bp8fl.4.1")

if artifact.get("required_log_fields") == REQUIRED_LOG_FIELDS:
    checks["required_log_fields"] = "pass"
else:
    checks["required_log_fields"] = "fail"
    errors.append("required_log_fields must match the standard structured log contract")

inputs_ok = artifact.get("inputs") == EXPECTED_INPUTS
for key, rel_path in EXPECTED_INPUTS.items():
    if not (root / rel_path).exists():
        inputs_ok = False
        errors.append(f"declared input does not exist: {key}={rel_path}")
feature_axes = set(feature_gaps.get("required_grouping_axes", []))
feature_gap_summary = feature_gaps.get("summary", {})
feature_gap_ok = (
    feature_gaps.get("schema_version") == "v1"
    and feature_gaps.get("bead") == "bd-bp8fl.3.1"
    and feature_gap_summary.get("ledger_gap_count", 0) > 0
    and {"symbol_family", "source_owner", "evidence_artifacts", "priority"}.issubset(feature_axes)
)
if not inputs_ok:
    errors.append("inputs must exactly name the current coverage, support, workload, and feature-gap artifacts")
if not feature_gap_ok:
    errors.append("feature_parity_gap_groups input must be a live v1 gap grouping artifact with symbol/source/evidence/priority axes")
checks["inputs_and_feature_gap_refs"] = "pass" if inputs_ok and feature_gap_ok else "fail"

families = {family.get("module"): family for family in coverage.get("families", [])}
per_symbol_rows = per_symbol.get("per_symbol_report", [])
symbols_by_module = {}
for row in per_symbol_rows:
    symbols_by_module.setdefault(row.get("module"), {})[row.get("symbol")] = row
support_modules = {symbol.get("module") for symbol in support.get("symbols", [])}
required_domains = set(workloads.get("required_domains", []))

campaigns = artifact.get("campaigns", [])
fully_covered_domain_sources = artifact.get("fully_covered_workload_domain_sources", [])
campaign_ids = [campaign.get("campaign_id") for campaign in campaigns]
ranks = [campaign.get("rank") for campaign in campaigns]
modules = []
domain_coverage = Counter()
fully_covered_domain_coverage = Counter()
first_wave_total = 0
selected_target_uncovered = 0
campaign_ok = bool(campaigns) and len(campaign_ids) == len(set(campaign_ids)) and ranks == list(range(1, len(campaigns) + 1))

for campaign in campaigns:
    cid = campaign.get("campaign_id", "<missing campaign_id>")
    for field in REQUIRED_CAMPAIGN_FIELDS:
        if field not in campaign:
            campaign_ok = False
            errors.append(f"{cid}: missing field {field}")

    module = campaign.get("module")
    modules.append(module)
    if module not in families:
        campaign_ok = False
        errors.append(f"{cid}: module not in symbol fixture coverage: {module}")
        continue
    if module not in support_modules:
        campaign_ok = False
        errors.append(f"{cid}: module not in support_matrix symbols: {module}")

    family = families[module]
    for src_key, campaign_key in [
        ("target_total", "target_total"),
        ("target_covered", "target_covered"),
        ("target_uncovered", "target_uncovered"),
        ("target_coverage_pct", "current_coverage_pct"),
    ]:
        if campaign.get(campaign_key) != family.get(src_key):
            campaign_ok = False
            errors.append(f"{cid}: {campaign_key} does not match symbol_fixture_coverage")

    first_wave = campaign.get("first_wave_symbols", [])
    if len(first_wave) != len(set(first_wave)):
        campaign_ok = False
        errors.append(f"{cid}: first_wave_symbols contains duplicates")
    if campaign.get("first_wave_fixture_count") != len(first_wave):
        campaign_ok = False
        errors.append(f"{cid}: first_wave_fixture_count does not match first_wave_symbols length")
    first_wave_total += len(first_wave)

    uncovered_set = set(family.get("target_uncovered_symbols", []))
    for symbol in first_wave:
        if symbol not in uncovered_set:
            campaign_ok = False
            errors.append(f"{cid}: first-wave symbol is not currently uncovered: {symbol}")
        row = symbols_by_module.get(module, {}).get(symbol)
        if row is None:
            campaign_ok = False
            errors.append(f"{cid}: first-wave symbol not found in per-symbol report: {symbol}")
        elif row.get("has_fixtures"):
            campaign_ok = False
            errors.append(f"{cid}: first-wave symbol already has fixtures: {symbol}")

    expected_after = round((family.get("target_covered", 0) + len(first_wave)) * 100 / family.get("target_total", 1), 2)
    if campaign.get("expected_coverage_after_first_wave_pct") != expected_after:
        campaign_ok = False
        errors.append(f"{cid}: expected_coverage_after_first_wave_pct should be {expected_after}")

    scores = campaign.get("scores", {})
    expected_gap = min(family.get("target_uncovered", 0), 200)
    expected_priority = (
        expected_gap
        + 300 * scores.get("workload_risk_score", 0)
        + 200 * scores.get("parity_risk_score", 0)
        - 50 * scores.get("implementation_complexity_score", 0)
    )
    if scores.get("coverage_gap_score") != expected_gap:
        campaign_ok = False
        errors.append(f"{cid}: coverage_gap_score should be {expected_gap}")
    if scores.get("priority_score") != expected_priority:
        campaign_ok = False
        errors.append(f"{cid}: priority_score should be {expected_priority}")
    for key in ["workload_risk_score", "parity_risk_score"]:
        value = scores.get(key)
        if not isinstance(value, int) or value < 0 or value > 5:
            campaign_ok = False
            errors.append(f"{cid}: {key} must be an integer in 0..5")
    value = scores.get("implementation_complexity_score")
    if not isinstance(value, int) or value < 1 or value > 5:
        campaign_ok = False
        errors.append(f"{cid}: implementation_complexity_score must be an integer in 1..5")

    for script in campaign.get("deterministic_e2e_scripts", []):
        if not (root / script).exists():
            campaign_ok = False
            errors.append(f"{cid}: deterministic script does not exist: {script}")
    if campaign.get("structured_log_fields") != "required_log_fields":
        campaign_ok = False
        errors.append(f"{cid}: structured_log_fields must reference required_log_fields")
    if not campaign.get("workload_domains"):
        campaign_ok = False
        errors.append(f"{cid}: workload_domains must not be empty")
    for domain in campaign.get("workload_domains", []):
        domain_coverage[domain] += 1
    if not campaign.get("risk_tags"):
        campaign_ok = False
        errors.append(f"{cid}: risk_tags must not be empty")
    selected_target_uncovered += campaign.get("target_uncovered", 0)

checks["campaign_schema"] = "pass" if campaign_ok else "fail"

fully_covered_sources_ok = isinstance(fully_covered_domain_sources, list)
if not fully_covered_sources_ok:
    errors.append("fully_covered_workload_domain_sources must be a list")
    fully_covered_domain_sources = []

seen_fully_covered_modules = set()
for source in fully_covered_domain_sources:
    for field in REQUIRED_FULLY_COVERED_DOMAIN_SOURCE_FIELDS:
        if field not in source:
            fully_covered_sources_ok = False
            errors.append(f"fully-covered workload domain source missing field {field}")

    module = source.get("module")
    if module in seen_fully_covered_modules:
        fully_covered_sources_ok = False
        errors.append(f"{module}: duplicate fully-covered workload domain source")
    seen_fully_covered_modules.add(module)

    family = families.get(module)
    if family is None:
        fully_covered_sources_ok = False
        errors.append(f"{module}: fully-covered workload domain source not in symbol fixture coverage")
        continue
    for src_key, source_key in [
        ("target_total", "target_total"),
        ("target_covered", "target_covered"),
        ("target_uncovered", "target_uncovered"),
        ("target_coverage_pct", "current_coverage_pct"),
    ]:
        if source.get(source_key) != family.get(src_key):
            fully_covered_sources_ok = False
            errors.append(f"{module}: fully-covered {source_key} does not match symbol_fixture_coverage")
    if family.get("target_total", 0) <= 0 or family.get("target_uncovered", 0) != 0:
        fully_covered_sources_ok = False
        errors.append(f"{module}: fully-covered workload domain source must have complete target coverage")
    if source.get("coverage_state") != "covered":
        fully_covered_sources_ok = False
        errors.append(f"{module}: fully-covered workload domain source must have covered coverage_state")
    if not source.get("workload_domains"):
        fully_covered_sources_ok = False
        errors.append(f"{module}: fully-covered workload domain source must list workload_domains")
    for domain in source.get("workload_domains", []):
        fully_covered_domain_coverage[domain] += 1

checks["fully_covered_workload_domain_sources"] = "pass" if fully_covered_sources_ok else "fail"

completed_unistd_ok = True
fixture_path = root / COMPLETED_UNISTD_PROCESS_FILESYSTEM_FIXTURE
harness_path = root / COMPLETED_UNISTD_PROCESS_FILESYSTEM_HARNESS
fixture = load_json(fixture_path) if fixture_path.exists() else None
if not fixture_path.exists():
    completed_unistd_ok = False
    errors.append(f"completed unistd first wave fixture missing: {COMPLETED_UNISTD_PROCESS_FILESYSTEM_FIXTURE}")
if not harness_path.exists():
    completed_unistd_ok = False
    errors.append(f"completed unistd first wave harness missing: {COMPLETED_UNISTD_PROCESS_FILESYSTEM_HARNESS}")
else:
    harness_text = harness_path.read_text(encoding="utf-8")
    for needle in [
        "unistd_process_filesystem_fixture_covers_first_wave_symbols_in_both_modes",
        "unistd_process_filesystem_fixture_executes_via_isolated_harness",
        "failure_signature",
    ]:
        if needle not in harness_text:
            completed_unistd_ok = False
            errors.append(f"completed unistd first wave harness missing needle: {needle}")

if isinstance(fixture, dict):
    declared = fixture.get("campaign", {}).get("first_wave_symbols", [])
    if declared != COMPLETED_UNISTD_PROCESS_FILESYSTEM_FIRST_WAVE:
        completed_unistd_ok = False
        errors.append("completed unistd first wave fixture symbols drifted")
    cases = fixture.get("cases", [])
    symbols_in_cases = sorted({case.get("function") for case in cases if isinstance(case, dict)})
    missing_fixture_symbols = sorted(set(COMPLETED_UNISTD_PROCESS_FILESYSTEM_FIRST_WAVE) - set(symbols_in_cases))
    if missing_fixture_symbols:
        completed_unistd_ok = False
        errors.append("completed unistd first wave fixture is missing cases for: " + ", ".join(missing_fixture_symbols))

per_symbol_by_symbol = {row.get("symbol"): row for row in per_symbol_rows if row.get("module") == "unistd_abi"}
for symbol in COMPLETED_UNISTD_PROCESS_FILESYSTEM_FIRST_WAVE:
    row = per_symbol_by_symbol.get(symbol)
    if row is None:
        completed_unistd_ok = False
        errors.append(f"completed unistd first wave symbol missing from per-symbol report: {symbol}")
        continue
    if row.get("has_fixtures") is not True:
        completed_unistd_ok = False
        errors.append(f"completed unistd first wave symbol lacks fixture accounting: {symbol}")
    if row.get("case_count", 0) < 2:
        completed_unistd_ok = False
        errors.append(f"completed unistd first wave symbol lacks strict+hardened cases: {symbol}")
    if "unistd_process_filesystem.json" not in row.get("fixture_files", []):
        completed_unistd_ok = False
        errors.append(f"completed unistd first wave symbol lacks fixture file backlink: {symbol}")
    if set(row.get("modes_tested", [])) != {"strict", "hardened"}:
        completed_unistd_ok = False
        errors.append(f"completed unistd first wave symbol lacks strict+hardened mode accounting: {symbol}")

unistd_campaign = next((campaign for campaign in campaigns if campaign.get("campaign_id") == "fcq-unistd-process-filesystem"), None)
if unistd_campaign is None:
    completed_unistd_ok = False
    errors.append("fcq-unistd-process-filesystem campaign missing after first-wave completion")
else:
    stale_symbols = sorted(set(COMPLETED_UNISTD_PROCESS_FILESYSTEM_FIRST_WAVE) & set(unistd_campaign.get("first_wave_symbols", [])))
    if stale_symbols:
        completed_unistd_ok = False
        errors.append("completed unistd first wave symbols still appear in next first-wave claim: " + ", ".join(stale_symbols))
    if unistd_campaign.get("target_covered", 0) < 47:
        completed_unistd_ok = False
        errors.append("fcq-unistd-process-filesystem target_covered did not advance to at least 47")
    if float(unistd_campaign.get("current_coverage_pct", 0.0)) < 6.33:
        completed_unistd_ok = False
        errors.append("fcq-unistd-process-filesystem current_coverage_pct did not advance to at least 6.33")

checks["completed_unistd_first_wave_guard"] = "pass" if completed_unistd_ok else "fail"

completed_unistd_wave03_ok = True
wave03_fixture_path = root / COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03_FIXTURE
wave03_harness_path = root / COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03_HARNESS
wave03_fixture = load_json(wave03_fixture_path) if wave03_fixture_path.exists() else None
if not wave03_fixture_path.exists():
    completed_unistd_wave03_ok = False
    errors.append(f"completed unistd wave-03 fixture missing: {COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03_FIXTURE}")
if not wave03_harness_path.exists():
    completed_unistd_wave03_ok = False
    errors.append(f"completed unistd wave-03 harness missing: {COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03_HARNESS}")
else:
    wave03_harness_text = wave03_harness_path.read_text(encoding="utf-8")
    for needle in [
        "unistd_process_filesystem_wave03_covers_first_wave_in_both_modes",
        "unistd_process_filesystem_wave03_executes_via_isolated_harness",
        "forbid_ambient_aio_time_fd_or_scheduler_metadata",
        "failure_signature",
    ]:
        if needle not in wave03_harness_text:
            completed_unistd_wave03_ok = False
            errors.append(f"completed unistd wave-03 harness missing needle: {needle}")

if isinstance(wave03_fixture, dict):
    campaign = wave03_fixture.get("campaign", {})
    declared = campaign.get("first_wave_symbols", [])
    if declared != COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03:
        completed_unistd_wave03_ok = False
        errors.append("completed unistd wave-03 fixture symbols drifted")
    if campaign.get("wave_id") != "wave-03-unistd-process-filesystem-aio-time":
        completed_unistd_wave03_ok = False
        errors.append("completed unistd wave-03 fixture wave_id drifted")
    cases = wave03_fixture.get("cases", [])
    symbols_in_cases = sorted({case.get("function") for case in cases if isinstance(case, dict)})
    missing_fixture_symbols = sorted(set(COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03) - set(symbols_in_cases))
    if missing_fixture_symbols:
        completed_unistd_wave03_ok = False
        errors.append("completed unistd wave-03 fixture is missing cases for: " + ", ".join(missing_fixture_symbols))

for symbol in COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03:
    row = per_symbol_by_symbol.get(symbol)
    if row is None:
        completed_unistd_wave03_ok = False
        errors.append(f"completed unistd wave-03 symbol missing from per-symbol report: {symbol}")
        continue
    if row.get("has_fixtures") is not True:
        completed_unistd_wave03_ok = False
        errors.append(f"completed unistd wave-03 symbol lacks fixture accounting: {symbol}")
    if row.get("case_count", 0) < 2:
        completed_unistd_wave03_ok = False
        errors.append(f"completed unistd wave-03 symbol lacks strict+hardened cases: {symbol}")
    if "unistd_process_filesystem_wave03.json" not in row.get("fixture_files", []):
        completed_unistd_wave03_ok = False
        errors.append(f"completed unistd wave-03 symbol lacks fixture file backlink: {symbol}")
    if set(row.get("modes_tested", [])) != {"strict", "hardened"}:
        completed_unistd_wave03_ok = False
        errors.append(f"completed unistd wave-03 symbol lacks strict+hardened mode accounting: {symbol}")

if unistd_campaign is None:
    completed_unistd_wave03_ok = False
    errors.append("fcq-unistd-process-filesystem campaign missing after wave-03 completion")
else:
    stale_symbols = sorted(set(COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE03) & set(unistd_campaign.get("first_wave_symbols", [])))
    if stale_symbols:
        completed_unistd_wave03_ok = False
        errors.append("completed unistd wave-03 symbols still appear in next first-wave claim: " + ", ".join(stale_symbols))
    if unistd_campaign.get("target_covered", 0) < 71:
        completed_unistd_wave03_ok = False
        errors.append("fcq-unistd-process-filesystem target_covered did not advance to at least 71")
    if unistd_campaign.get("target_uncovered", 10**9) > 671:
        completed_unistd_wave03_ok = False
        errors.append("fcq-unistd-process-filesystem target_uncovered did not shrink to at most 671")
    if float(unistd_campaign.get("current_coverage_pct", 0.0)) < 9.57:
        completed_unistd_wave03_ok = False
        errors.append("fcq-unistd-process-filesystem current_coverage_pct did not advance to at least 9.57")

checks["completed_unistd_wave03_guard"] = "pass" if completed_unistd_wave03_ok else "fail"

completed_unistd_wave04_ok = True
wave04_fixture_path = root / COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04_FIXTURE
wave04_harness_path = root / COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04_HARNESS
wave04_fixture = load_json(wave04_fixture_path) if wave04_fixture_path.exists() else None
if not wave04_fixture_path.exists():
    completed_unistd_wave04_ok = False
    errors.append(f"completed unistd wave-04 fixture missing: {COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04_FIXTURE}")
if not wave04_harness_path.exists():
    completed_unistd_wave04_ok = False
    errors.append(f"completed unistd wave-04 harness missing: {COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04_HARNESS}")
if wave04_harness_path.exists():
    wave04_harness_text = wave04_harness_path.read_text(encoding="utf-8")
    for needle in [
        "unistd_process_filesystem_wave04_covers_first_wave_in_both_modes",
        "unistd_process_filesystem_wave04_executes_via_isolated_harness",
        "forbid_ambient_random_values_alarm_state_argp_streams_or_aio_fd_metadata",
        "failure_signature",
    ]:
        if needle not in wave04_harness_text:
            completed_unistd_wave04_ok = False
            errors.append(f"completed unistd wave-04 harness missing needle: {needle}")

if isinstance(wave04_fixture, dict):
    campaign = wave04_fixture.get("campaign", {})
    declared = campaign.get("first_wave_symbols", [])
    if declared != COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04:
        completed_unistd_wave04_ok = False
        errors.append("completed unistd wave-04 fixture symbols drifted")
    if campaign.get("wave_id") != "wave-04-unistd-process-filesystem-aio-random-argp":
        completed_unistd_wave04_ok = False
        errors.append("completed unistd wave-04 fixture wave_id drifted")
    cases = wave04_fixture.get("cases", [])
    symbols_in_cases = {case.get("function") for case in cases if isinstance(case, dict)}
    missing_fixture_symbols = sorted(set(COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04) - set(symbols_in_cases))
    if missing_fixture_symbols:
        completed_unistd_wave04_ok = False
        errors.append("completed unistd wave-04 fixture is missing cases for: " + ", ".join(missing_fixture_symbols))

for symbol in COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04:
    row = symbols_by_module.get("unistd_abi", {}).get(symbol)
    if not row:
        completed_unistd_wave04_ok = False
        errors.append(f"completed unistd wave-04 symbol missing from per-symbol report: {symbol}")
        continue
    if not row.get("has_fixtures"):
        completed_unistd_wave04_ok = False
        errors.append(f"completed unistd wave-04 symbol lacks fixture accounting: {symbol}")
    if row.get("case_count", 0) < 2:
        completed_unistd_wave04_ok = False
        errors.append(f"completed unistd wave-04 symbol lacks strict+hardened cases: {symbol}")
    if "unistd_process_filesystem_wave04.json" not in row.get("fixture_files", []):
        completed_unistd_wave04_ok = False
        errors.append(f"completed unistd wave-04 symbol lacks fixture file backlink: {symbol}")
    if sorted(row.get("modes_tested", [])) != ["hardened", "strict"]:
        completed_unistd_wave04_ok = False
        errors.append(f"completed unistd wave-04 symbol lacks strict+hardened mode accounting: {symbol}")

if not unistd_campaign:
    completed_unistd_wave04_ok = False
    errors.append("fcq-unistd-process-filesystem campaign missing after wave-04 completion")
else:
    stale_symbols = sorted(set(COMPLETED_UNISTD_PROCESS_FILESYSTEM_WAVE04) & set(unistd_campaign.get("first_wave_symbols", [])))
    if stale_symbols:
        completed_unistd_wave04_ok = False
        errors.append("completed unistd wave-04 symbols still appear in next first-wave claim: " + ", ".join(stale_symbols))
    if unistd_campaign.get("target_covered", 0) < 83:
        completed_unistd_wave04_ok = False
        errors.append("fcq-unistd-process-filesystem target_covered did not advance to at least 83")
    if unistd_campaign.get("target_uncovered", 10**9) > 659:
        completed_unistd_wave04_ok = False
        errors.append("fcq-unistd-process-filesystem target_uncovered did not shrink to at most 659")
    if float(unistd_campaign.get("current_coverage_pct", 0.0)) < 11.19:
        completed_unistd_wave04_ok = False
        errors.append("fcq-unistd-process-filesystem current_coverage_pct did not advance to at least 11.19")

checks["completed_unistd_wave04_guard"] = "pass" if completed_unistd_wave04_ok else "fail"

completed_stdio_ok = True
stdio_fixture_path = root / COMPLETED_STDIO_LIBIO_FIXTURE
stdio_harness_path = root / COMPLETED_STDIO_LIBIO_HARNESS
stdio_fixture = load_json(stdio_fixture_path) if stdio_fixture_path.exists() else None
if not stdio_fixture_path.exists():
    completed_stdio_ok = False
    errors.append(f"completed stdio/libio first wave fixture missing: {COMPLETED_STDIO_LIBIO_FIXTURE}")
if not stdio_harness_path.exists():
    completed_stdio_ok = False
    errors.append(f"completed stdio/libio first wave harness missing: {COMPLETED_STDIO_LIBIO_HARNESS}")
else:
    stdio_harness_text = stdio_harness_path.read_text(encoding="utf-8")
    for needle in [
        "stdio_libio_symbols_cover_first_wave_in_both_modes",
        "stdio_libio_symbols_fixture_executes_via_isolated_harness",
        "failure_signature",
    ]:
        if needle not in stdio_harness_text:
            completed_stdio_ok = False
            errors.append(f"completed stdio/libio first wave harness missing needle: {needle}")

if isinstance(stdio_fixture, dict):
    declared = stdio_fixture.get("campaign", {}).get("first_wave_symbols", [])
    if declared != COMPLETED_STDIO_LIBIO_FIRST_WAVE:
        completed_stdio_ok = False
        errors.append("completed stdio/libio first wave fixture symbols drifted")
    cases = stdio_fixture.get("cases", [])
    symbols_in_cases = sorted({case.get("function") for case in cases if isinstance(case, dict)})
    missing_fixture_symbols = sorted(set(COMPLETED_STDIO_LIBIO_FIRST_WAVE) - set(symbols_in_cases))
    if missing_fixture_symbols:
        completed_stdio_ok = False
        errors.append("completed stdio/libio first wave fixture is missing cases for: " + ", ".join(missing_fixture_symbols))

per_symbol_by_symbol = {row.get("symbol"): row for row in per_symbol_rows if row.get("module") == "stdio_abi"}
for symbol in COMPLETED_STDIO_LIBIO_FIRST_WAVE:
    row = per_symbol_by_symbol.get(symbol)
    if row is None:
        completed_stdio_ok = False
        errors.append(f"completed stdio/libio first wave symbol missing from per-symbol report: {symbol}")
        continue
    if row.get("has_fixtures") is not True:
        completed_stdio_ok = False
        errors.append(f"completed stdio/libio first wave symbol lacks fixture accounting: {symbol}")
    if row.get("case_count", 0) < 2:
        completed_stdio_ok = False
        errors.append(f"completed stdio/libio first wave symbol lacks strict+hardened cases: {symbol}")
    if "stdio_libio_symbols.json" not in row.get("fixture_files", []):
        completed_stdio_ok = False
        errors.append(f"completed stdio/libio first wave symbol lacks fixture file backlink: {symbol}")
    if set(row.get("modes_tested", [])) != {"strict", "hardened"}:
        completed_stdio_ok = False
        errors.append(f"completed stdio/libio first wave symbol lacks strict+hardened mode accounting: {symbol}")

stdio_campaign = next((campaign for campaign in campaigns if campaign.get("campaign_id") == "fcq-stdio-libio"), None)
if stdio_campaign is None:
    completed_stdio_ok = False
    errors.append("fcq-stdio-libio campaign missing after first-wave completion")
else:
    stale_symbols = sorted(set(COMPLETED_STDIO_LIBIO_FIRST_WAVE) & set(stdio_campaign.get("first_wave_symbols", [])))
    if stale_symbols:
        completed_stdio_ok = False
        errors.append("completed stdio/libio first wave symbols still appear in next first-wave claim: " + ", ".join(stale_symbols))
    if stdio_campaign.get("target_covered", 0) < 6:
        completed_stdio_ok = False
        errors.append("fcq-stdio-libio target_covered did not advance to at least 6")
    if float(stdio_campaign.get("current_coverage_pct", 0.0)) < 60.0:
        completed_stdio_ok = False
        errors.append("fcq-stdio-libio current_coverage_pct did not advance to at least 60.0")

checks["completed_stdio_libio_first_wave_guard"] = "pass" if completed_stdio_ok else "fail"

def rel_path(path):
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return path.as_posix()

def resolve_input_path(path):
    path = Path(path)
    return path if path.is_absolute() else root / path

def contract_paths_from_glob(pattern_text):
    paths = []
    for raw_pattern in [part for part in pattern_text.split(":") if part.strip()]:
        pattern = Path(raw_pattern)
        glob_pattern = pattern if pattern.is_absolute() else root / pattern
        paths.extend(Path(path) for path in glob.glob(str(glob_pattern)))
    return sorted({path.resolve() for path in paths if path.is_file()})

def matching_contract_path(fixture_rel, fixture_name, contract_texts):
    for path, text in contract_texts:
        if fixture_rel in text or fixture_name in text:
            return rel_path(path)
    return None

coverage_rows_by_symbol = {}
for row in coverage.get("symbols", []):
    if isinstance(row, dict):
        coverage_rows_by_symbol.setdefault(row.get("symbol"), []).append(row)
per_symbol_rows_by_symbol = {}
for row in per_symbol_rows:
    if isinstance(row, dict):
        per_symbol_rows_by_symbol.setdefault(row.get("symbol"), []).append(row)
campaign_by_id = {
    campaign.get("campaign_id"): campaign
    for campaign in campaigns
    if isinstance(campaign, dict) and isinstance(campaign.get("campaign_id"), str)
}
contract_texts = []
for contract_path in contract_paths_from_glob(completion_contract_glob):
    try:
        contract_texts.append((contract_path, contract_path.read_text(encoding="utf-8")))
    except Exception as exc:
        errors.append(f"cannot read completion contract candidate {rel_path(contract_path)}: {exc}")

fixture_wave_rows = []
fixture_wave_ok = True
resolved_fixtures_dir = resolve_input_path(fixtures_dir)
if not resolved_fixtures_dir.is_dir():
    fixture_wave_ok = False
    errors.append(f"fixture wave lifecycle fixtures directory missing: {rel_path(resolved_fixtures_dir)}")
    fixture_paths = []
else:
    fixture_paths = sorted(resolved_fixtures_dir.glob("*wave*.json"))
    if not fixture_paths:
        fixture_wave_ok = False
        errors.append(f"fixture wave lifecycle found no wave fixtures under {rel_path(resolved_fixtures_dir)}")

for fixture_path in fixture_paths:
    fixture_rel = rel_path(fixture_path)
    fixture_name = fixture_path.name
    fixture = load_json(fixture_path)
    missing_coverage_artifacts = set()
    malformed_reasons = []
    completed_stale_symbols = []
    contract_required = fixture_name in CONTRACT_REQUIRED_WAVE_FIXTURES
    completion_contract_path = matching_contract_path(fixture_rel, fixture_name, contract_texts)
    missing_completion_contract = bool(contract_required and completion_contract_path is None)

    if not isinstance(fixture, dict):
        fixture = {}
        malformed_reasons.append("fixture root must be an object")
    family = fixture.get("family")
    campaign = fixture.get("campaign")
    if not isinstance(family, str) or not family:
        malformed_reasons.append("fixture family must be a non-empty string")
        family = "<missing family>"
    if not isinstance(campaign, dict):
        malformed_reasons.append("fixture campaign must be an object")
        campaign = {}
    wave_id = campaign.get("wave_id")
    campaign_id = campaign.get("campaign_id")
    declared_symbols = campaign.get("first_wave_symbols")
    if not isinstance(wave_id, str) or not wave_id:
        malformed_reasons.append("fixture campaign.wave_id must be a non-empty string")
        wave_id = "<missing wave_id>"
    if not isinstance(campaign_id, str) or not campaign_id:
        missing_coverage_artifacts.add("fixture_coverage_prioritizer.v1.json")
    if not isinstance(declared_symbols, list) or not all(isinstance(symbol, str) for symbol in declared_symbols):
        malformed_reasons.append("fixture campaign.first_wave_symbols must be a string array")
        declared_symbols = []
    if len(declared_symbols) != len(set(declared_symbols)):
        malformed_reasons.append("fixture campaign.first_wave_symbols contains duplicates")

    cases = fixture.get("cases")
    if not isinstance(cases, list):
        malformed_reasons.append("fixture cases must be an array")
        cases = []
    case_modes_by_symbol = {}
    for case in cases:
        if not isinstance(case, dict):
            malformed_reasons.append("fixture cases must contain objects")
            continue
        symbol = case.get("function")
        mode = case.get("mode")
        if isinstance(symbol, str) and isinstance(mode, str):
            case_modes_by_symbol.setdefault(symbol, set()).add(mode)

    campaign_row = campaign_by_id.get(campaign_id)
    campaign_next_wave = set(campaign_row.get("first_wave_symbols", [])) if isinstance(campaign_row, dict) else set()

    for symbol in declared_symbols:
        modes = case_modes_by_symbol.get(symbol, set())
        if not {"strict", "hardened"}.issubset(modes):
            malformed_reasons.append(f"{symbol}: fixture lacks strict+hardened cases")

        coverage_matches = [
            row
            for row in coverage_rows_by_symbol.get(symbol, [])
            if fixture_name in row.get("fixture_files", [])
        ]
        if not coverage_matches or not any(row.get("covered") is True for row in coverage_matches):
            missing_coverage_artifacts.add("symbol_fixture_coverage.v1.json")
        elif not any({"strict", "hardened"}.issubset(set(row.get("fixture_modes", []))) for row in coverage_matches):
            missing_coverage_artifacts.add("symbol_fixture_coverage.v1.json")

        per_symbol_matches = [
            row
            for row in per_symbol_rows_by_symbol.get(symbol, [])
            if fixture_name in row.get("fixture_files", [])
        ]
        if not per_symbol_matches:
            missing_coverage_artifacts.add("per_symbol_fixture_tests.v1.json")
        elif not any(
            row.get("has_fixtures") is True
            and int(row.get("case_count", 0)) >= 2
            and {"strict", "hardened"}.issubset(set(row.get("modes_tested", [])))
            for row in per_symbol_matches
        ):
            missing_coverage_artifacts.add("per_symbol_fixture_tests.v1.json")

        if symbol in campaign_next_wave:
            missing_coverage_artifacts.add("fixture_coverage_prioritizer.v1.json")
            completed_stale_symbols.append(symbol)

    if malformed_reasons:
        failure_signature = "malformed_fixture_wave"
    elif completed_stale_symbols:
        failure_signature = "completed_symbol_still_claimed"
    elif missing_coverage_artifacts:
        failure_signature = "missing_coverage_artifact"
    elif missing_completion_contract:
        failure_signature = "missing_completion_contract"
    else:
        failure_signature = "none"

    row = {
        "fixture_file": fixture_rel,
        "fixture_basename": fixture_name,
        "fixture_family": family,
        "wave_id": wave_id,
        "campaign_id": campaign_id,
        "covered_symbols": sorted(declared_symbols),
        "missing_coverage_artifacts": sorted(missing_coverage_artifacts),
        "contract_required": contract_required,
        "missing_completion_contract": missing_completion_contract,
        "completion_contract_path": completion_contract_path,
        "completed_symbol_still_claimed": sorted(completed_stale_symbols),
        "malformed_reasons": sorted(set(malformed_reasons)),
        "failure_signature": failure_signature,
        "status": "pass" if failure_signature == "none" else "fail",
    }
    for field in REQUIRED_FIXTURE_WAVE_LIFECYCLE_REPORT_FIELDS:
        if field not in row:
            fixture_wave_ok = False
            row["failure_signature"] = "missing_required_report_field"
    if row["status"] != "pass":
        fixture_wave_ok = False
        errors.append(f"{fixture_rel}: fixture wave lifecycle failed: {row['failure_signature']}")
    fixture_wave_rows.append(row)

checks["fixture_wave_lifecycle"] = "pass" if fixture_wave_ok else "fail"

raw_deferred_modules = artifact.get("deferred_modules", [])
deferred_modules = raw_deferred_modules if isinstance(raw_deferred_modules, list) else []
uncovered_modules = {
    module
    for module, family in families.items()
    if family.get("target_uncovered", 0) > 0
}
selected_modules = set(modules)
expected_deferred_modules = sorted(
    uncovered_modules - selected_modules,
    key=lambda module: (-families[module].get("target_uncovered", 0), module),
)
actual_deferred_modules = [
    row.get("module") for row in deferred_modules if isinstance(row, dict)
]
deferred_target_uncovered = 0
deferred_ok = isinstance(raw_deferred_modules, list) and actual_deferred_modules == expected_deferred_modules
if not isinstance(raw_deferred_modules, list):
    errors.append("deferred_modules must be an array")
if actual_deferred_modules != expected_deferred_modules:
    deferred_ok = False
    errors.append("deferred_modules must cover every uncovered non-campaign module in target_uncovered desc order")

for row in deferred_modules:
    if not isinstance(row, dict):
        deferred_ok = False
        errors.append("deferred_modules entries must be objects")
        continue
    module = row.get("module", "<missing module>")
    for field in REQUIRED_DEFERRED_FIELDS:
        if field not in row:
            deferred_ok = False
            errors.append(f"{module}: missing deferred field {field}")
    if module in selected_modules:
        deferred_ok = False
        errors.append(f"{module}: selected campaign module cannot also be deferred")
    family = families.get(module)
    if family is None:
        deferred_ok = False
        errors.append(f"{module}: deferred module not found in symbol fixture coverage")
        continue
    if family.get("target_uncovered", 0) <= 0:
        deferred_ok = False
        errors.append(f"{module}: deferred module must still have uncovered target symbols")
    for src_key, row_key in [
        ("target_total", "target_total"),
        ("target_covered", "target_covered"),
        ("target_uncovered", "target_uncovered"),
        ("target_coverage_pct", "current_coverage_pct"),
        ("status_breakdown", "status_breakdown"),
    ]:
        if row.get(row_key) != family.get(src_key):
            deferred_ok = False
            errors.append(f"{module}: {row_key} does not match symbol_fixture_coverage")
    if not str(row.get("deferral_reason", "")).strip():
        deferred_ok = False
        errors.append(f"{module}: deferral_reason must be non-empty")
    if not str(row.get("next_step", "")).strip():
        deferred_ok = False
        errors.append(f"{module}: next_step must be non-empty")
    deferred_target_uncovered += row.get("target_uncovered", 0)

checks["deferred_module_inventory"] = "pass" if deferred_ok else "fail"

expected_order = sorted(
    campaigns,
    key=lambda campaign: (
        -campaign.get("scores", {}).get("priority_score", -1),
        -campaign.get("target_uncovered", -1),
        campaign.get("module", ""),
    ),
)
if [c.get("campaign_id") for c in campaigns] == [c.get("campaign_id") for c in expected_order]:
    checks["priority_order"] = "pass"
else:
    checks["priority_order"] = "fail"
    errors.append("campaigns are not sorted by priority_score desc, target_uncovered desc, module asc")

workload_domain_coverage = set(domain_coverage) | set(fully_covered_domain_coverage)
missing_required_domains = sorted(required_domains - workload_domain_coverage)
if not missing_required_domains:
    checks["workload_domain_coverage"] = "pass"
else:
    checks["workload_domain_coverage"] = "fail"
    errors.append("missing required workload domains: " + ", ".join(missing_required_domains))

summary = artifact.get("summary", {})
all_uncovered_target_symbols = selected_target_uncovered + deferred_target_uncovered
summary_ok = (
    summary.get("campaign_count") == len(campaigns)
    and summary.get("deferred_module_count") == len(deferred_modules)
    and summary.get("total_first_wave_fixture_count") == first_wave_total
    and summary.get("selected_target_uncovered_symbols") == selected_target_uncovered
    and summary.get("deferred_target_uncovered_symbols") == deferred_target_uncovered
    and summary.get("all_uncovered_target_symbols") == all_uncovered_target_symbols
    and summary.get("covered_modules") == sorted(modules)
    and summary.get("required_workload_domains_covered") == sorted(required_domains)
    and summary.get("highest_priority_campaign") == campaigns[0].get("campaign_id")
    and summary.get("lowest_priority_campaign") == campaigns[-1].get("campaign_id")
)
checks["summary_counts"] = "pass" if summary_ok else "fail"
if not summary_ok:
    errors.append("summary counts do not match campaigns, modules, workload domains, and priority endpoints")

try:
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
except Exception:
    source_commit = "unknown"

status = "pass" if not errors else "fail"
artifact_refs = [
    "tests/conformance/fixture_coverage_prioritizer.v1.json",
    "tests/conformance/symbol_fixture_coverage.v1.json",
    "tests/conformance/per_symbol_fixture_tests.v1.json",
    "tests/conformance/feature_parity_gap_groups.v1.json",
    rel_path(resolved_fixtures_dir),
    completion_contract_glob,
    "target/conformance/fixture_coverage_prioritizer.regenerated.v1.json",
    "target/conformance/fixture_coverage_prioritizer.report.json",
    "target/conformance/fixture_coverage_prioritizer.log.jsonl",
]
report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.4.1",
    "status": status,
    "checks": checks,
    "campaign_count": len(campaigns),
    "deferred_module_count": len(deferred_modules) if isinstance(deferred_modules, list) else 0,
    "total_first_wave_fixture_count": first_wave_total,
    "selected_target_uncovered_symbols": selected_target_uncovered,
    "deferred_target_uncovered_symbols": deferred_target_uncovered,
    "all_uncovered_target_symbols": all_uncovered_target_symbols,
    "covered_modules": sorted(modules),
    "required_workload_domains_covered": sorted(required_domains),
    "missing_required_domains": missing_required_domains,
    "fixture_wave_lifecycle": fixture_wave_rows,
    "fixture_wave_lifecycle_required_report_fields": REQUIRED_FIXTURE_WAVE_LIFECYCLE_REPORT_FIELDS,
    "top_campaigns": [
        {
            "campaign_id": campaign.get("campaign_id"),
            "module": campaign.get("module"),
            "priority_score": campaign.get("scores", {}).get("priority_score"),
            "first_wave_fixture_count": campaign.get("first_wave_fixture_count"),
        }
        for campaign in campaigns[:5]
    ],
    "errors": errors,
    "artifact_refs": artifact_refs,
    "source_commit": source_commit,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def campaign_coverage_state(campaign):
    uncovered = campaign.get("target_uncovered", 0)
    covered = campaign.get("target_covered", 0)
    if uncovered == 0:
        return "covered"
    if covered == 0:
        return "uncovered"
    if campaign.get("current_coverage_pct", 0) < 80:
        return "weak"
    return "partial"

events = []
for campaign in campaigns:
    scores = campaign.get("scores", {})
    events.append(
        {
            "trace_id": "bd-bp8fl.4.1-fixture-coverage-prioritizer",
            "bead_id": "bd-bp8fl.4.1",
            "scenario_id": campaign.get("campaign_id"),
            "runtime_mode": "not_applicable",
            "replacement_level": "L0,L1_planning",
            "api_family": campaign.get("module"),
            "symbol": "*",
            "oracle_kind": campaign.get("oracle_kind"),
            "expected": "campaign ranks uncovered exported-symbol fixture work by coverage gain and real workload risk",
            "actual": status,
            "errno": None,
            "decision_path": list(checks.keys()),
            "healing_action": "none",
            "latency_ns": 0,
            "symbol_family": campaign.get("symbol_family"),
            "score": scores.get("priority_score"),
            "rank": campaign.get("rank"),
            "coverage_state": campaign_coverage_state(campaign),
            "risk_factors": {
                "risk_tags": campaign.get("risk_tags", []),
                "scores": scores,
                "workload_domains": campaign.get("workload_domains", []),
            },
            "artifact_refs": artifact_refs,
            "source_commit": source_commit,
            "target_dir": str(root / "target/conformance"),
            "failure_signature": "; ".join(errors),
            "campaign_count": len(campaigns),
            "deferred_module_count": len(deferred_modules) if isinstance(deferred_modules, list) else 0,
            "total_first_wave_fixture_count": first_wave_total,
            "selected_target_uncovered_symbols": selected_target_uncovered,
            "deferred_target_uncovered_symbols": deferred_target_uncovered,
        }
    )

for row in fixture_wave_rows:
    events.append(
        {
            "trace_id": "bd-waaa6.3-fixture-wave-lifecycle",
            "bead_id": "bd-waaa6.3",
            "scenario_id": row.get("wave_id"),
            "runtime_mode": "not_applicable",
            "replacement_level": "L0,L1_conformance_lifecycle",
            "api_family": row.get("campaign_id"),
            "symbol": ",".join(row.get("covered_symbols", [])),
            "oracle_kind": "fixture_wave_lifecycle_gate",
            "expected": "wave fixtures are reflected in coverage artifacts, prioritizer state, and required completion contracts",
            "actual": row.get("status"),
            "errno": None,
            "decision_path": ["fixture_wave_lifecycle"],
            "healing_action": "none",
            "latency_ns": 0,
            "symbol_family": row.get("fixture_family"),
            "score": 0,
            "rank": None,
            "coverage_state": "covered" if row.get("status") == "pass" else "drift",
            "risk_factors": {
                "missing_coverage_artifacts": row.get("missing_coverage_artifacts", []),
                "missing_completion_contract": row.get("missing_completion_contract"),
                "completed_symbol_still_claimed": row.get("completed_symbol_still_claimed", []),
                "malformed_reasons": row.get("malformed_reasons", []),
            },
            "artifact_refs": artifact_refs,
            "source_commit": source_commit,
            "target_dir": str(root / "target/conformance"),
            "failure_signature": row.get("failure_signature"),
            "fixture_file": row.get("fixture_file"),
            "fixture_family": row.get("fixture_family"),
            "wave_id": row.get("wave_id"),
            "covered_symbols": row.get("covered_symbols", []),
            "missing_coverage_artifacts": row.get("missing_coverage_artifacts", []),
            "missing_completion_contract": row.get("missing_completion_contract"),
        }
    )

log_path.write_text(
    "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
    encoding="utf-8",
)

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
