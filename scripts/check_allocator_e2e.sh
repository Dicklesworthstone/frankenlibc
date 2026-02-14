#!/usr/bin/env bash
# check_allocator_e2e.sh — allocator-focused E2E + glibc differential check (bd-2x5.5)
#
# Validates:
# 1) Concurrent alloc/free workload fixture passes under strict+hardened.
# 2) Fragmentation wave fixture passes under strict+hardened.
# 3) Strict+hardened outcomes/stdout match host glibc baseline for the same fixtures.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${ROOT}/target/allocator_e2e"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${OUT_ROOT}/${RUN_ID}"
BIN_DIR="${RUN_DIR}/bin"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-20}"

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

if [[ -z "${LIB_PATH}" ]]; then
  echo "check_allocator_e2e: building frankenlibc-abi release artifact..."
  cargo build -p frankenlibc-abi --release
  for candidate in "${LIB_CANDIDATES[@]}"; do
    if [[ -f "${candidate}" ]]; then
      LIB_PATH="${candidate}"
      break
    fi
  done
fi

if [[ -z "${LIB_PATH}" ]]; then
  echo "check_allocator_e2e: could not locate libfrankenlibc_abi.so" >&2
  exit 2
fi

if ! command -v cc >/dev/null 2>&1; then
  echo "check_allocator_e2e: required compiler 'cc' not found" >&2
  exit 2
fi

fixtures=(
  "fixture_malloc"
  "fixture_malloc_stress"
)

compile_fixture() {
  local name="$1"
  local src="${ROOT}/tests/integration/${name}.c"
  local bin="${BIN_DIR}/${name}"
  local cflags="-O2 -Wall -Wextra"
  local ldflags=""
  if [[ "${name}" == *"stress" ]]; then
    ldflags="-pthread"
  fi
  if [[ ! -f "${src}" ]]; then
    echo "check_allocator_e2e: missing fixture source ${src}" >&2
    return 1
  fi
  cc ${cflags} "${src}" -o "${bin}" ${ldflags}
}

run_case() {
  local fixture="$1"
  local mode="$2" # host|strict|hardened
  local bin="${BIN_DIR}/${fixture}"
  local case_dir="${RUN_DIR}/${fixture}/${mode}"
  mkdir -p "${case_dir}"

  local rc=0
  if [[ "${mode}" == "host" ]]; then
    set +e
    timeout "${TIMEOUT_SECONDS}" "${bin}" >"${case_dir}/stdout.txt" 2>"${case_dir}/stderr.txt"
    rc=$?
    set -e
  else
    set +e
    timeout "${TIMEOUT_SECONDS}" \
      env FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB_PATH}" "${bin}" \
      >"${case_dir}/stdout.txt" 2>"${case_dir}/stderr.txt"
    rc=$?
    set -e
  fi
  echo "${rc}" > "${case_dir}/exit_code"
}

echo "=== allocator_e2e (bd-2x5.5) ==="
echo "run_dir=${RUN_DIR}"
echo "lib=${LIB_PATH}"
echo "timeout=${TIMEOUT_SECONDS}s"
echo ""

for fixture in "${fixtures[@]}"; do
  compile_fixture "${fixture}"
done

echo "--- Running baseline + strict/hardened ---"
for fixture in "${fixtures[@]}"; do
  run_case "${fixture}" "host"
  run_case "${fixture}" "strict"
  run_case "${fixture}" "hardened"
done

REPORT_PATH="${RUN_DIR}/report.json"
RUN_DIR_ARG="${RUN_DIR}" \
REPORT_PATH_ARG="${REPORT_PATH}" \
python3 - <<'PY'
import json
import os
import re
from pathlib import Path

run_dir = Path(os.environ["RUN_DIR_ARG"])
report_path = Path(os.environ["REPORT_PATH_ARG"])
fixtures = ["fixture_malloc", "fixture_malloc_stress"]

CHECKSUM_PATTERN = re.compile(r"checksum=\d+")

def load_case(fixture: str, mode: str) -> dict:
    base = run_dir / fixture / mode
    exit_code = int((base / "exit_code").read_text().strip())
    stdout = (base / "stdout.txt").read_text(errors="replace")
    stderr = (base / "stderr.txt").read_text(errors="replace")
    return {
        "fixture": fixture,
        "mode": mode,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
    }


def normalize_stdout(value: str) -> str:
    # Stress fixtures may include allocator-dependent checksum bytes derived from
    # uninitialized realloc growth tails; normalize that dynamic suffix.
    return CHECKSUM_PATTERN.sub("checksum=<dynamic>", value.strip())

overall_ok = True
rows = []
for fixture in fixtures:
    host = load_case(fixture, "host")
    strict = load_case(fixture, "strict")
    hardened = load_case(fixture, "hardened")

    strict_match = (
        strict["exit_code"] == host["exit_code"]
        and normalize_stdout(strict["stdout"]) == normalize_stdout(host["stdout"])
    )
    hardened_match = (
        hardened["exit_code"] == host["exit_code"]
        and normalize_stdout(hardened["stdout"]) == normalize_stdout(host["stdout"])
    )

    fixture_ok = host["exit_code"] == 0 and strict_match and hardened_match
    overall_ok = overall_ok and fixture_ok

    rows.append(
        {
            "fixture": fixture,
            "host": {"exit_code": host["exit_code"]},
            "strict": {
                "exit_code": strict["exit_code"],
                "matches_host": strict_match,
            },
            "hardened": {
                "exit_code": hardened["exit_code"],
                "matches_host": hardened_match,
            },
            "fixture_ok": fixture_ok,
        }
    )

payload = {
    "schema_version": "v1",
    "bead": "bd-2x5.5",
    "run_dir": str(run_dir),
    "fixtures": rows,
    "overall_ok": overall_ok,
}
report_path.write_text(json.dumps(payload, indent=2) + "\n")

for row in rows:
    print(
        f"[{'PASS' if row['fixture_ok'] else 'FAIL'}] {row['fixture']} "
        f"host={row['host']['exit_code']} strict={row['strict']['exit_code']} "
        f"hardened={row['hardened']['exit_code']} "
        f"strict_match={row['strict']['matches_host']} "
        f"hardened_match={row['hardened']['matches_host']}"
    )

if not overall_ok:
    raise SystemExit(1)
PY

echo ""
echo "report=${REPORT_PATH}"
echo "allocator_e2e: PASS"
