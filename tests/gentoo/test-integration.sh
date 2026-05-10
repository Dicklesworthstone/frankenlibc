#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_IMAGE="${BASE_IMAGE:-frankenlibc/gentoo-builder:latest}"
INTEGRATION_IMAGE="${INTEGRATION_IMAGE:-frankenlibc/gentoo-frankenlibc:latest}"

write_sample_logs() {
    local log_root="$1"
    mkdir -p "${log_root}/portage"
    printf "%s\n" "{\"timestamp\":\"2026-02-13T00:00:00Z\",\"event\":\"enable\",\"atom\":\"sys-apps/coreutils-9.9-r1\",\"phase\":\"src_test\",\"pid\":123,\"message\":\"sample\"}" > "${log_root}/portage/hooks.jsonl"
    printf "%s\n" "{\"timestamp\":\"2026-02-13T00:00:01Z\",\"package\":\"sys-apps/coreutils-9.9-r1\",\"phase\":\"src_test\",\"pid\":124,\"call\":\"malloc\",\"args\":{\"size\":4096},\"action\":\"ClampSize\",\"original_size\":4096,\"clamped_size\":4096,\"latency_ns\":180}" > "${log_root}/portage/runtime.jsonl"
}

assert_summary_contract() {
    local summary_path="$1"
    python3 - "${summary_path}" <<'PY'
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert summary["records_total"] == 2, summary
assert summary["parse_errors"] == 0, summary
assert summary["events"]["enable"] == 1, summary
assert any(call == "malloc" and count == 1 for call, count in summary["top_calls"]), summary
assert any(action == "ClampSize" and count == 1 for action, count in summary["top_actions"]), summary
assert summary["latency_ns"] == {"count": 1, "min": 180, "max": 180, "avg": 180}, summary
PY
}

if [[ "${FRANKENLIBC_INTEGRATION_TELEMETRY_ONLY:-0}" == "1" ]]; then
    RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    LOG_ROOT="${ROOT}/target/gentoo-integration-telemetry/${RUN_ID}/logs"
    OUTPUT_ROOT="${ROOT}/target/gentoo-integration-telemetry/${RUN_ID}/collected"
    SUMMARY_PATH="${OUTPUT_ROOT}/summary.json"
    write_sample_logs "${LOG_ROOT}"
    "${ROOT}/scripts/gentoo/collect-logs.sh" --log-root "${LOG_ROOT}" --output "${OUTPUT_ROOT}" --no-tar
    test -s "${SUMMARY_PATH}"
    assert_summary_contract "${SUMMARY_PATH}"
    echo "PASS: gentoo frankenlibc telemetry integration validation completed"
    exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not installed"
    exit 0
fi

echo "=== Gentoo FrankenLibC Integration Validation ==="
echo "ROOT=${ROOT}"
echo "BASE_IMAGE=${BASE_IMAGE}"
echo "INTEGRATION_IMAGE=${INTEGRATION_IMAGE}"

if ! docker image inspect "${BASE_IMAGE}" >/dev/null 2>&1; then
    echo "INFO: base image missing, building base images first"
    "${ROOT}/scripts/gentoo/build-base-image.sh"
fi

docker build \
  --build-arg "BASE_IMAGE=${BASE_IMAGE}" \
  -f "${ROOT}/docker/gentoo/Dockerfile.frankenlibc" \
  -t "${INTEGRATION_IMAGE}" \
  "${ROOT}" >/tmp/frankenlibc-integration-build.log

echo "--- check: integration artifacts exist ---"
docker run --rm "${INTEGRATION_IMAGE}" bash -lc \
  "test -f /etc/portage/bashrc && \
   test -f /opt/frankenlibc/etc/frankenlibc.toml && \
   test -x /opt/frankenlibc/scripts/gentoo/frankenlibc-ebuild-hooks.sh && \
   test -x /opt/frankenlibc/scripts/gentoo/build-package.sh && \
   test -x /opt/frankenlibc/scripts/gentoo/collect-artifacts.sh && \
   test -x /opt/frankenlibc/scripts/gentoo/collect-logs.sh && \
   test -x /opt/frankenlibc/scripts/gentoo/analyze-logs.py && \
   test -f /etc/portage/env/no-frankenlibc.conf"

echo "--- check: preload activates for allowed phase ---"
docker run --rm "${INTEGRATION_IMAGE}" bash -lc '
  set -euo pipefail
  mkdir -p /opt/frankenlibc/lib
  : > /opt/frankenlibc/lib/libfrankenlibc_abi.so
  export CATEGORY=sys-apps PN=coreutils PF=coreutils-9.9-r1 EBUILD_PHASE=src_test USE=""
  source /etc/portage/bashrc
  pre_src_test
  [[ "${LD_PRELOAD:-}" == *"/opt/frankenlibc/lib/libfrankenlibc_abi.so"* ]]
  [[ -n "${FRANKENLIBC_LOG_FILE:-}" ]]
  [[ "${FRANKENLIBC_LOG_FILE}" == */src_test.jsonl ]]
  post_src_test
  [[ -z "${LD_PRELOAD:-}" ]]
'

echo "--- check: blocklisted package disables preload ---"
docker run --rm "${INTEGRATION_IMAGE}" bash -lc '
  set -euo pipefail
  mkdir -p /opt/frankenlibc/lib
  : > /opt/frankenlibc/lib/libfrankenlibc_abi.so
  export CATEGORY=sys-libs PN=glibc PF=glibc-2.39 EBUILD_PHASE=src_test USE=""
  source /etc/portage/bashrc
  pre_src_test
  [[ -z "${LD_PRELOAD:-}" ]]
'

echo "--- check: log collection + analysis tooling ---"
docker run --rm "${INTEGRATION_IMAGE}" bash -lc '
  set -euo pipefail
  mkdir -p /var/log/frankenlibc/portage
  printf "%s\n" "{\"timestamp\":\"2026-02-13T00:00:00Z\",\"event\":\"enable\",\"atom\":\"sys-apps/coreutils-9.9-r1\",\"phase\":\"src_test\",\"pid\":123,\"message\":\"sample\"}" > /var/log/frankenlibc/portage/hooks.jsonl
  printf "%s\n" "{\"timestamp\":\"2026-02-13T00:00:01Z\",\"package\":\"sys-apps/coreutils-9.9-r1\",\"phase\":\"src_test\",\"pid\":124,\"call\":\"malloc\",\"args\":{\"size\":4096},\"action\":\"ClampSize\",\"original_size\":4096,\"clamped_size\":4096,\"latency_ns\":180}" > /var/log/frankenlibc/portage/runtime.jsonl
  /opt/frankenlibc/scripts/gentoo/collect-logs.sh --log-root /var/log/frankenlibc --output /tmp/frankenlibc-collected --no-tar
  python3 /opt/frankenlibc/scripts/gentoo/analyze-logs.py /tmp/frankenlibc-collected --output /tmp/summary.json --json-only >/dev/null
  test -s /tmp/summary.json
  python3 - /tmp/summary.json <<PY
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert summary["records_total"] == 2, summary
assert summary["parse_errors"] == 0, summary
assert summary["events"]["enable"] == 1, summary
assert any(call == "malloc" and count == 1 for call, count in summary["top_calls"]), summary
assert any(action == "ClampSize" and count == 1 for action, count in summary["top_actions"]), summary
assert summary["latency_ns"] == {"count": 1, "min": 180, "max": 180, "avg": 180}, summary
PY
'

echo "PASS: gentoo frankenlibc integration validation completed"
