#!/usr/bin/env bash
# c_fixture_suite.sh — Compile and run C fixture suite under LD_PRELOAD (bd-3jh)
#
# Compiles all fixture_*.c files, runs each under LD_PRELOAD with both
# strict and hardened modes, and produces structured results.
#
# Exit codes:
#   0 — all fixtures pass in both modes
#   1 — one or more fixtures failed
#   2 — setup error (missing compiler, library, etc.)
set -euo pipefail
shopt -s nullglob

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_DIR="${ROOT}/tests/integration"
OUT_ROOT="${ROOT}/target/c_fixture_suite"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${OUT_ROOT}/${RUN_ID}"
BIN_DIR="${RUN_DIR}/bin"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
BEAD_ID="${BEAD_ID:-bd-3jh}"
TRACE_FILE="${RUN_DIR}/trace.jsonl"
ARTIFACT_INDEX="${RUN_DIR}/artifact_index.json"
TRACE_SEQ=0
FIXTURE_FILTER="${FIXTURE_FILTER:-fixture_*.c}"
SPEC="${ROOT}/tests/conformance/c_fixture_spec.json"
# Optional command prefix for each fixture run, e.g. "qemu-x86_64 -cpu Nehalem"
# to run the suite on an emulated CPU without AVX (bd-rc0923-epic-eeuy4f.13).
# The emulator must be statically linked: LD_PRELOAD is set for the whole
# command and has to reach the guest, not the emulator.
FIXTURE_RUNNER="${FIXTURE_RUNNER:-}"
read -r -a RUNNER_ARGV <<< "${FIXTURE_RUNNER}"

LIB_CANDIDATES=()
# An explicit library wins (scripts/check_baseline_isa.sh runs a given artifact).
if [[ -n "${FRANKENLIBC_LIB:-}" ]]; then
  if [[ ! -f "${FRANKENLIBC_LIB}" ]]; then
    echo "c_fixture_suite: FRANKENLIBC_LIB=${FRANKENLIBC_LIB} does not exist" >&2
    exit 2
  fi
  LIB_CANDIDATES+=("${FRANKENLIBC_LIB}")
fi
# Honour caller-supplied CARGO_TARGET_DIR (bd-gilq3).
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  LIB_CANDIDATES+=(
    "${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so"
    "${CARGO_TARGET_DIR}/debug/libfrankenlibc_abi.so"
  )
fi
LIB_CANDIDATES+=(
  "${ROOT}/target/release/libfrankenlibc_abi.so"
  "/data/tmp/cargo-target/release/libfrankenlibc_abi.so"
)

LIB_PATH=""
for candidate in "${LIB_CANDIDATES[@]}"; do
  if [[ -f "${candidate}" ]]; then
    LIB_PATH="${candidate}"
    break
  fi
done

mkdir -p "${RUN_DIR}" "${BIN_DIR}"
: > "${TRACE_FILE}"

now_iso_utc() {
  date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

emit_trace() {
  local level="$1"
  local event="$2"
  local mode="$3"
  local symbol="$4"
  local decision_path="$5"
  local outcome="$6"
  local errno_val="$7"
  local latency_ns="$8"
  local artifact_refs_json="$9"

  TRACE_SEQ=$((TRACE_SEQ + 1))
  local trace_id
  trace_id="${BEAD_ID}::${RUN_ID}::$(printf '%03d' "${TRACE_SEQ}")"

  printf '{"timestamp":"%s","trace_id":"%s","level":"%s","event":"%s","bead_id":"%s","run_id":"%s","mode":"%s","api_family":"integration-fixture","symbol":"%s","decision_path":"%s","healing_action":"None","outcome":"%s","errno":%s,"latency_ns":%s,"artifact_refs":%s}\n' \
    "$(now_iso_utc)" \
    "${trace_id}" \
    "${level}" \
    "${event}" \
    "${BEAD_ID}" \
    "${RUN_ID}" \
    "${mode}" \
    "${symbol}" \
    "${decision_path}" \
    "${outcome}" \
    "${errno_val}" \
    "${latency_ns}" \
    "${artifact_refs_json}" >> "${TRACE_FILE}"
}

# Build library if needed
if [[ -z "${LIB_PATH}" ]]; then
  echo "c_fixture_suite: building frankenlibc-abi release artifact..."
  if ! command -v rch >/dev/null 2>&1; then
    echo "c_fixture_suite: rch is required for cargo build offload but was not found in PATH" >&2
    exit 2
  fi
  rch exec -- cargo build -p frankenlibc-abi --release
  for candidate in "${LIB_CANDIDATES[@]}"; do
    if [[ -f "${candidate}" ]]; then
      LIB_PATH="${candidate}"
      break
    fi
  done
fi

if [[ -z "${LIB_PATH}" ]]; then
  echo "c_fixture_suite: could not locate libfrankenlibc_abi.so" >&2
  exit 2
fi

if ! command -v cc >/dev/null 2>&1; then
  echo "c_fixture_suite: required compiler 'cc' not found" >&2
  exit 2
fi

echo "=== C Fixture Suite (bd-3jh) ==="
echo "run_dir=${RUN_DIR}"
echo "lib=${LIB_PATH}"
echo "timeout=${TIMEOUT_SECONDS}s"
echo "bead_id=${BEAD_ID}"
echo "fixture_filter=${FIXTURE_FILTER}"
echo "fixture_runner=${FIXTURE_RUNNER:-native}"
echo ""

# Compile all fixtures
echo "--- Compiling fixtures ---"
compile_fails=0
fixture_bins=()

if [[ "${FIXTURE_FILTER}" == "fixture_*.c" && -f "${SPEC}" ]]; then
  mapfile -t matched_sources < <(python3 - "${ROOT}" "${SPEC}" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
spec = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
for fixture in spec.get("fixtures", []):
    source = fixture.get("source")
    if isinstance(source, str) and source:
        print(root / source)
PY
  )
else
  matched_sources=("${FIXTURE_DIR}"/${FIXTURE_FILTER})
fi
if [[ "${#matched_sources[@]}" -eq 0 ]]; then
  echo "c_fixture_suite: no fixtures matched filter '${FIXTURE_FILTER}'" >&2
  exit 2
fi

for src in "${matched_sources[@]}"; do
  name="$(basename "${src}" .c)"
  name="${name%.cpp}"
  bin="${BIN_DIR}/${name}"

  cflags="-O2 -Wall -Wextra"
  ldflags=""
  compiler=cc
  if [[ "${src}" == *.cpp ]]; then
    compiler=c++
    ldflags="-pthread"
  elif [[ "${name}" == fixture_pthread* ]]; then
    ldflags="-pthread"
  elif [[ "${name}" == "fixture_math" ]]; then
    ldflags="-lm"
  fi
  if [[ "${name}" == "fixture_hardened_first_heal" ]]; then
    cflags+=" -fno-builtin-strlen"
    ldflags+=" -Wl,-z,now"
  fi

  if "${compiler}" ${cflags} "${src}" -o "${bin}" ${ldflags} 2>"${RUN_DIR}/${name}_compile.log"; then
    echo "[OK] ${name}"
    fixture_bins+=("${bin}")
  else
    echo "[FAIL] ${name} (compile error)"
    compile_fails=$((compile_fails + 1))
  fi
done

echo ""

if [[ "${compile_fails}" -gt 0 ]]; then
  echo "c_fixture_suite: ${compile_fails} compile failure(s)" >&2
  exit 1
fi

# Run each fixture under LD_PRELOAD for both modes
passes=0
fails=0
total=0

validate_runtime_log() {
  local log_path="$1"
  local fixture_name="$2"
  local mode="$3"

  python3 - "${ROOT}" "${log_path}" "${fixture_name}" "${mode}" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
log_path = pathlib.Path(sys.argv[2])
fixture_name = sys.argv[3]
mode = sys.argv[4]
sys.path.insert(0, str(root / "scripts/gentoo"))

from log_parser import LogParser  # noqa: E402
from log_validator import LogValidator  # noqa: E402

entries = list(LogParser(strict=True).parse_file(log_path))
if not entries:
    raise SystemExit("runtime log is empty")
issues = LogValidator().validate(entries)
if issues:
    rendered = "; ".join(f"line {issue.line}: {issue.message}" for issue in issues)
    raise SystemExit(f"runtime log validation failed: {rendered}")
if not any(entry.event == "exit_summary" for entry in entries):
    raise SystemExit("runtime log is missing exit_summary")
if fixture_name == "fixture_hardened_first_heal":
    before_path = pathlib.Path(f"{log_path}.pre_fork")
    if not before_path.is_file():
        raise SystemExit("runtime log fork probe is missing the pre-fork inode")
    before_entries = list(LogParser(strict=True).parse_file(before_path))
    before_issues = LogValidator().validate(before_entries)
    if before_issues:
        rendered = "; ".join(
            f"line {issue.line}: {issue.message}" for issue in before_issues
        )
        raise SystemExit(f"pre-fork runtime log validation failed: {rendered}")
    child_pids = {entry.pid for entry in entries if entry.pid is not None}
    parent_pids = {entry.pid for entry in before_entries if entry.pid is not None}
    if len(child_pids) != 1 or len(parent_pids) != 1:
        raise SystemExit(
            f"fork probe expected one child pid and one parent pid; "
            f"child={sorted(child_pids)} parent={sorted(parent_pids)}"
        )
    if not child_pids.isdisjoint(parent_pids):
        raise SystemExit(
            "fork child kept the parent's inherited runtime-log descriptor "
            "instead of reopening the rotated path"
        )
    all_entries = entries + before_entries
    for label, stream_entries in (("child", entries), ("parent", before_entries)):
        sequences = [entry.raw.get("seq") for entry in stream_entries]
        if any(type(seq) is not int or seq <= 0 for seq in sequences):
            raise SystemExit(
                f"{mode} {label} runtime log has invalid sequence values: {sequences!r}"
            )
        if len(sequences) != len(set(sequences)):
            raise SystemExit(
                f"{mode} {label} runtime log has duplicate sequence values: "
                f"{sequences!r}"
            )
    invalid_repair_symbols = [
        entry
        for entry in all_entries
        if entry.event == "repair"
        and (
            not isinstance(entry.raw.get("symbol"), str)
            or not entry.raw["symbol"].strip()
            or entry.raw["symbol"].strip().casefold() == "unknown"
        )
    ]
    if invalid_repair_symbols:
        rendered = ", ".join(
            f"line {entry.source_line}: {entry.raw.get('symbol')!r}"
            for entry in invalid_repair_symbols
        )
        raise SystemExit(f"runtime logs contain invalid repair symbols: {rendered}")
    repair_rows = [entry.raw for entry in all_entries if entry.event == "repair"]
    invalid_repair_errnos = [
        row.get("errno")
        for row in repair_rows
        if type(row.get("errno")) is not int
        or not -(2**31) <= row["errno"] < 2**31
    ]
    if invalid_repair_errnos:
        raise SystemExit(
            f"runtime repair rows have invalid decision-owned errno values: "
            f"{invalid_repair_errnos!r}"
        )
    denial_rows = [entry.raw for entry in all_entries if entry.event == "deny"]
    if mode == "hardened":
        invalid_repair_addresses = [
            row.get("address")
            for row in repair_rows
            if not isinstance(row.get("address"), str)
            or re.fullmatch(r"0x[0-9a-fA-F]+", row["address"]) is None
        ]
        if invalid_repair_addresses:
            raise SystemExit(
                "hardened fixture repair rows have invalid primary addresses: "
                f"{invalid_repair_addresses!r}"
            )
        invalid_hints = [
            row.get("addr_hint")
            for row in denial_rows
            if not isinstance(row.get("addr_hint"), str)
            or re.fullmatch(r"0x[0-9a-fA-F]+", row["addr_hint"]) is None
        ]
        if invalid_hints:
            raise SystemExit(
                f"hardened denial rows have invalid addr_hint values: {invalid_hints!r}"
            )
    else:
        disclosed_addresses = [row["address"] for row in repair_rows if "address" in row]
        if disclosed_addresses:
            raise SystemExit(
                f"{mode} repair rows disclosed hardened-only address values: "
                f"{disclosed_addresses!r}"
            )
        disclosed_hints = [row["addr_hint"] for row in denial_rows if "addr_hint" in row]
        if disclosed_hints:
            raise SystemExit(
                f"{mode} denial rows disclosed hardened-only addr_hint values: "
                f"{disclosed_hints!r}"
            )
    def event_signature(entry):
        if entry.event == "repair":
            return (
                "repair",
                entry.raw.get("api_family"),
                entry.call,
                entry.action,
                entry.raw.get("signal_context"),
            )
        if entry.event == "deny":
            return (
                "deny",
                entry.raw.get("api_family"),
                entry.call,
                entry.raw.get("reason"),
                entry.raw.get("errno"),
                entry.raw.get("signal_context"),
            )
        return (entry.event,)

    normal_deny = ("deny", "Signal", "kill", "invalid_signal_number", 22, False)
    signal_deny = ("deny", "Signal", "pthread_kill", "invalid_signal_number", 22, True)
    child_expected = [normal_deny, ("exit_summary",)]
    parent_expected = [signal_deny, normal_deny, normal_deny]
    if mode == "hardened":
        signal_repair = ("repair", "string_memory", "strlen", "ReturnSafeDefault", True)
        normal_repair = ("repair", "string_memory", "memcpy", "ClampSize", False)
        parent_expected = [
            signal_repair,
            signal_deny,
            normal_repair,
            normal_deny,
            normal_deny,
        ]
        child_expected = [normal_repair, normal_deny, ("exit_summary",)]

    rate_limit = 1024
    rate_limit_attempts = 1100
    rate_limited = rate_limit_attempts - rate_limit
    parent_expected.extend([normal_deny] * rate_limit)
    parent_expected.append(("exit_summary",))

    parent_actual = [event_signature(entry) for entry in before_entries]
    child_actual = [event_signature(entry) for entry in entries]
    if parent_actual != parent_expected:
        raise SystemExit(
            f"{mode} parent runtime event sequence mismatch: "
            f"expected={parent_expected!r} actual={parent_actual!r}"
        )
    if child_actual != child_expected:
        raise SystemExit(
            f"{mode} child runtime event sequence mismatch: "
            f"expected={child_expected!r} actual={child_actual!r}"
        )

    parent_summary = before_entries[-1].raw
    child_summary = entries[-1].raw
    expected_parent_counters = {
        "total_heals": 2 if mode == "hardened" else 0,
        "size_clamps": 1 if mode == "hardened" else 0,
        "safe_defaults": 1 if mode == "hardened" else 0,
        "denials": 3 + rate_limit_attempts,
        "runtime_log_dropped_records": rate_limited,
        "runtime_log_rate_limited_records": rate_limited,
        "runtime_log_admission_clock_failures": 0,
    }
    expected_child_counters = {
        "total_heals": 3 if mode == "hardened" else 0,
        "size_clamps": 2 if mode == "hardened" else 0,
        "safe_defaults": 1 if mode == "hardened" else 0,
        "denials": 3,
        "runtime_log_dropped_records": 0,
        "runtime_log_rate_limited_records": 0,
        "runtime_log_admission_clock_failures": 0,
    }
    for field, expected in expected_parent_counters.items():
        if parent_summary.get(field) != expected:
            raise SystemExit(
                f"{mode} parent summary {field} expected {expected}, "
                f"got {parent_summary.get(field)!r}"
            )
    for field, expected in expected_child_counters.items():
        if child_summary.get(field) != expected:
            raise SystemExit(
                f"{mode} child summary {field} expected {expected}, "
                f"got {child_summary.get(field)!r}"
            )
PY
}

run_fixture() {
  local mode="$1"
  local bin="$2"
  local name
  name="$(basename "${bin}")"
  local case_dir="${RUN_DIR}/${mode}/${name}"
  local runtime_log="${case_dir}/runtime.jsonl"
  mkdir -p "${case_dir}"
  : > "${runtime_log}"
  : > "${case_dir}/runtime_log_validation.txt"

  total=$((total + 1))
  local start_ns
  start_ns="$(date +%s%N)"

  set +e
  timeout "${TIMEOUT_SECONDS}" \
    env FRANKENLIBC_MODE="${mode}" FRANKENLIBC_LOG="${runtime_log}" \
      LD_PRELOAD="${LIB_PATH}" "${RUNNER_ARGV[@]}" "${bin}" \
    > "${case_dir}/stdout.txt" 2> "${case_dir}/stderr.txt"
  local rc=$?
  set -e

  if [[ "${rc}" -eq 0 ]]; then
    set +e
    validate_runtime_log "${runtime_log}" "${name}" "${mode}" \
      > "${case_dir}/runtime_log_validation.txt" 2>&1
    local validation_rc=$?
    set -e
    if [[ "${validation_rc}" -ne 0 ]]; then
      rc=86
    fi
  fi

  local end_ns
  end_ns="$(date +%s%N)"
  local elapsed_ns=$((end_ns - start_ns))

  echo "${rc}" > "${case_dir}/exit_code"

  local refs_json
  if [[ -f "${runtime_log}.pre_fork" ]]; then
    refs_json="$(printf '["%s/%s/stdout.txt","%s/%s/stderr.txt","%s/%s/exit_code","%s/%s/runtime.jsonl","%s/%s/runtime.jsonl.pre_fork","%s/%s/runtime_log_validation.txt"]' "${mode}" "${name}" "${mode}" "${name}" "${mode}" "${name}" "${mode}" "${name}" "${mode}" "${name}" "${mode}" "${name}")"
  else
    refs_json="$(printf '["%s/%s/stdout.txt","%s/%s/stderr.txt","%s/%s/exit_code","%s/%s/runtime.jsonl","%s/%s/runtime_log_validation.txt"]' "${mode}" "${name}" "${mode}" "${name}" "${mode}" "${name}" "${mode}" "${name}" "${mode}" "${name}")"
  fi

  if [[ "${rc}" -eq 0 ]]; then
    passes=$((passes + 1))
    echo "[PASS] mode=${mode} ${name}"
    emit_trace "info" "fixture_result" "${mode}" "${name}" "fixture_exit_code" "pass" 0 "${elapsed_ns}" "${refs_json}"
  elif [[ "${rc}" -eq 124 || "${rc}" -eq 125 ]]; then
    fails=$((fails + 1))
    echo "[FAIL] mode=${mode} ${name} (timeout ${TIMEOUT_SECONDS}s)"
    emit_trace "error" "fixture_result" "${mode}" "${name}" "timeout" "fail" "${rc}" "${elapsed_ns}" "${refs_json}"
  else
    fails=$((fails + 1))
    echo "[FAIL] mode=${mode} ${name} (exit ${rc})"
    emit_trace "error" "fixture_result" "${mode}" "${name}" "nonzero_exit" "fail" "${rc}" "${elapsed_ns}" "${refs_json}"
  fi
}

for mode in strict hardened; do
  echo "--- Mode: ${mode} ---"
  for bin in "${fixture_bins[@]}"; do
    run_fixture "${mode}" "${bin}"
  done
  echo ""
done

# Write structured results
python3 -c "
import json, os, glob

results = {
    'run_id': '${RUN_ID}',
    'bead_id': '${BEAD_ID}',
    'lib_path': '${LIB_PATH}',
    'total': ${total},
    'passes': ${passes},
    'fails': ${fails},
    'trace_log': '${TRACE_FILE#${ROOT}/}',
    'artifact_index': '${ARTIFACT_INDEX#${ROOT}/}',
    'fixtures': []
}

for mode in ['strict', 'hardened']:
    mode_dir = '${RUN_DIR}/' + mode
    if not os.path.isdir(mode_dir):
        continue
    for name_dir in sorted(glob.glob(mode_dir + '/fixture_*')):
        name = os.path.basename(name_dir)
        exit_file = os.path.join(name_dir, 'exit_code')
        rc = int(open(exit_file).read().strip()) if os.path.exists(exit_file) else -1
        stdout = open(os.path.join(name_dir, 'stdout.txt')).read().strip() if os.path.exists(os.path.join(name_dir, 'stdout.txt')) else ''
        stderr_txt = open(os.path.join(name_dir, 'stderr.txt')).read().strip() if os.path.exists(os.path.join(name_dir, 'stderr.txt')) else ''
        results['fixtures'].append({
            'name': name,
            'mode': mode,
            'exit_code': rc,
            'pass': rc == 0,
            'stdout': stdout[:500],
            'stderr': stderr_txt[:500]
        })

with open('${RUN_DIR}/results.json', 'w') as f:
    json.dump(results, f, indent=2)
"

summary_refs="$(printf '["%s","%s"]' "${TRACE_FILE#${ROOT}/}" "${RUN_DIR#${ROOT}/}/results.json")"
if [[ "${fails}" -eq 0 ]]; then
  emit_trace "info" "run_summary" "strict+hardened" "c_fixture_suite" "aggregate_exit" "pass" 0 0 "${summary_refs}"
else
  emit_trace "error" "run_summary" "strict+hardened" "c_fixture_suite" "aggregate_exit" "fail" "${fails}" 0 "${summary_refs}"
fi

python3 - "${ROOT}" "${RUN_DIR}" "${ARTIFACT_INDEX}" "${RUN_ID}" "${BEAD_ID}" <<'PY'
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

root = Path(sys.argv[1])
run_dir = Path(sys.argv[2])
index_path = Path(sys.argv[3])
run_id = sys.argv[4]
bead_id = sys.argv[5]

def sha256_hex(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

paths = []
for rel in ("results.json", "trace.jsonl"):
    p = run_dir / rel
    if p.exists():
        paths.append(p)

for pattern in (
    "strict/fixture_*/stdout.txt",
    "strict/fixture_*/stderr.txt",
    "strict/fixture_*/exit_code",
    "strict/fixture_*/runtime.jsonl",
    "strict/fixture_*/runtime.jsonl.pre_fork",
    "strict/fixture_*/runtime_log_validation.txt",
    "hardened/fixture_*/stdout.txt",
    "hardened/fixture_*/stderr.txt",
    "hardened/fixture_*/exit_code",
    "hardened/fixture_*/runtime.jsonl",
    "hardened/fixture_*/runtime.jsonl.pre_fork",
    "hardened/fixture_*/runtime_log_validation.txt",
    "*_compile.log",
):
    paths.extend(sorted(run_dir.glob(pattern)))

artifacts = []
for path in paths:
    rel = path.relative_to(root).as_posix()
    if rel.endswith(".jsonl") or rel.endswith(".jsonl.pre_fork"):
        kind = "log"
    elif rel.endswith("results.json"):
        kind = "report"
    elif rel.endswith("_compile.log"):
        kind = "compile_log"
    elif rel.endswith("stdout.txt"):
        kind = "stdout"
    elif rel.endswith("stderr.txt"):
        kind = "stderr"
    elif rel.endswith("runtime_log_validation.txt"):
        kind = "validation"
    elif rel.endswith("exit_code"):
        kind = "status"
    else:
        kind = "artifact"

    artifacts.append(
        {
            "path": rel,
            "kind": kind,
            "sha256": sha256_hex(path),
            "size_bytes": path.stat().st_size,
            "description": "c fixture suite artifact",
        }
    )

payload = {
    "index_version": 1,
    "run_id": run_id,
    "bead_id": bead_id,
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "artifacts": artifacts,
}
index_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY

echo "=== Summary ==="
echo "Total: ${total} | Passes: ${passes} | Fails: ${fails}"
echo "Results: ${RUN_DIR}/results.json"
echo "Trace: ${TRACE_FILE}"
echo "Artifact index: ${ARTIFACT_INDEX}"

if [[ "${fails}" -gt 0 ]]; then
  echo ""
  echo "c_fixture_suite: FAILED"
  exit 1
fi

echo ""
echo "c_fixture_suite: PASS"
