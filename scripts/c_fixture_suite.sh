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
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-10}"
BEAD_ID="${BEAD_ID:-bd-3jh}"
TRACE_FILE="${RUN_DIR}/trace.jsonl"
ARTIFACT_INDEX="${RUN_DIR}/artifact_index.json"
TRACE_SEQ=0
FIXTURE_FILTER="${FIXTURE_FILTER:-fixture_*.c}"

LIB_CANDIDATES=(
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
  cargo build -p frankenlibc-abi --release
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
echo ""

# Compile all fixtures
echo "--- Compiling fixtures ---"
compile_fails=0
fixture_bins=()

matched_sources=("${FIXTURE_DIR}"/${FIXTURE_FILTER})
if [[ "${#matched_sources[@]}" -eq 0 ]]; then
  echo "c_fixture_suite: no fixtures matched filter '${FIXTURE_FILTER}'" >&2
  exit 2
fi

for src in "${matched_sources[@]}"; do
  name="$(basename "${src}" .c)"
  bin="${BIN_DIR}/${name}"

  cflags="-O2 -Wall -Wextra"
  ldflags=""
  if [[ "${name}" == fixture_pthread* ]]; then
    ldflags="-pthread"
  elif [[ "${name}" == "fixture_math" ]]; then
    ldflags="-lm"
  fi

  if cc ${cflags} "${src}" -o "${bin}" ${ldflags} 2>"${RUN_DIR}/${name}_compile.log"; then
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

run_fixture() {
  local mode="$1"
  local bin="$2"
  local name
  name="$(basename "${bin}")"
  local case_dir="${RUN_DIR}/${mode}/${name}"
  mkdir -p "${case_dir}"

  total=$((total + 1))
  local start_ns
  start_ns="$(date +%s%N)"

  set +e
  timeout "${TIMEOUT_SECONDS}" \
    env FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB_PATH}" "${bin}" \
    > "${case_dir}/stdout.txt" 2> "${case_dir}/stderr.txt"
  local rc=$?
  set -e

  local end_ns
  end_ns="$(date +%s%N)"
  local elapsed_ns=$((end_ns - start_ns))

  echo "${rc}" > "${case_dir}/exit_code"

  local refs_json
  refs_json="$(printf '["%s/%s/stdout.txt","%s/%s/stderr.txt","%s/%s/exit_code"]' "${mode}" "${name}" "${mode}" "${name}" "${mode}" "${name}")"

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
    "hardened/fixture_*/stdout.txt",
    "hardened/fixture_*/stderr.txt",
    "hardened/fixture_*/exit_code",
    "*_compile.log",
):
    paths.extend(sorted(run_dir.glob(pattern)))

artifacts = []
for path in paths:
    rel = path.relative_to(root).as_posix()
    if rel.endswith(".jsonl"):
        kind = "log"
    elif rel.endswith("results.json"):
        kind = "report"
    elif rel.endswith("_compile.log"):
        kind = "compile_log"
    elif rel.endswith("stdout.txt"):
        kind = "stdout"
    elif rel.endswith("stderr.txt"):
        kind = "stderr"
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
