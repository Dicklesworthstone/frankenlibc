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

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_DIR="${ROOT}/tests/integration"
OUT_ROOT="${ROOT}/target/c_fixture_suite"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${OUT_ROOT}/${RUN_ID}"
BIN_DIR="${RUN_DIR}/bin"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-10}"

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
echo ""

# Compile all fixtures
echo "--- Compiling fixtures ---"
compile_fails=0
fixture_bins=()

for src in "${FIXTURE_DIR}"/fixture_*.c; do
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

  set +e
  timeout "${TIMEOUT_SECONDS}" \
    env FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB_PATH}" "${bin}" \
    > "${case_dir}/stdout.txt" 2> "${case_dir}/stderr.txt"
  local rc=$?
  set -e

  echo "${rc}" > "${case_dir}/exit_code"

  if [[ "${rc}" -eq 0 ]]; then
    passes=$((passes + 1))
    echo "[PASS] mode=${mode} ${name}"
  elif [[ "${rc}" -eq 124 || "${rc}" -eq 125 ]]; then
    fails=$((fails + 1))
    echo "[FAIL] mode=${mode} ${name} (timeout ${TIMEOUT_SECONDS}s)"
  else
    fails=$((fails + 1))
    echo "[FAIL] mode=${mode} ${name} (exit ${rc})"
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
    'lib_path': '${LIB_PATH}',
    'total': ${total},
    'passes': ${passes},
    'fails': ${fails},
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

echo "=== Summary ==="
echo "Total: ${total} | Passes: ${passes} | Fails: ${fails}"
echo "Results: ${RUN_DIR}/results.json"

if [[ "${fails}" -gt 0 ]]; then
  echo ""
  echo "c_fixture_suite: FAILED"
  exit 1
fi

echo ""
echo "c_fixture_suite: PASS"
