#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGE3_IMAGE="${STAGE3_IMAGE:-frankenlibc/gentoo-stage3:latest}"
BUILDER_IMAGE="${BUILDER_IMAGE:-frankenlibc/gentoo-builder:latest}"
RUN_FULL_EMERGE="${FLC_GENTOO_TEST_FULL_EMERGE:-0}"
GOLDEN_PATH="${FLC_GENTOO_BASE_IMAGE_GOLDEN:-${ROOT}/tests/gentoo/base-image-contract.golden.json}"
GOLDEN_REPORT="${FLC_GENTOO_BASE_IMAGE_GOLDEN_REPORT:-${ROOT}/target/gentoo/base-image-contract.report.json}"
GOLDEN_ONLY="${FLC_GENTOO_BASE_IMAGE_GOLDEN_ONLY:-0}"

validate_golden_contract() {
    python3 - "${ROOT}" "${GOLDEN_PATH}" "${GOLDEN_REPORT}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
golden_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])

payload = json.loads(golden_path.read_text(encoding="utf-8"))
checks = []


def require(condition, check_id, detail):
    checks.append({"id": check_id, "passed": bool(condition), "detail": detail})
    if not condition:
        raise SystemExit(f"FAIL: {check_id}: {detail}")


def check_required_lines(section_name):
    section = payload[section_name]
    rel_path = section["path"]
    body = (root / rel_path).read_text(encoding="utf-8")
    for index, expected in enumerate(section["required_lines"], start=1):
        require(
            expected in body,
            f"{section_name}.required_lines.{index}",
            f"{rel_path} must contain {expected!r}",
        )


for section_name in ("stage3", "builder", "make_conf", "build_script", "runtime_test"):
    check_required_lines(section_name)

report = {
    "schema_version": payload["schema_version"],
    "bead_id": payload["bead_id"],
    "contract": payload["contract"],
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "golden_path": str(golden_path),
    "checks_total": len(checks),
    "checks_passed": sum(1 for check in checks if check["passed"]),
    "checks": checks,
}
report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"PASS: golden base image contract checks={report['checks_passed']}/{report['checks_total']}")
PY
}

echo "--- check: base image golden contract ---"
validate_golden_contract

if [[ "${GOLDEN_ONLY}" == "1" ]]; then
    echo "PASS: gentoo base image golden validation completed"
    exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not installed"
    exit 0
fi

echo "=== Gentoo Base Image Validation ==="
echo "ROOT=${ROOT}"
echo "STAGE3_IMAGE=${STAGE3_IMAGE}"
echo "BUILDER_IMAGE=${BUILDER_IMAGE}"
echo "RUN_FULL_EMERGE=${RUN_FULL_EMERGE}"

if ! docker image inspect "${STAGE3_IMAGE}" >/dev/null 2>&1; then
    echo "FAIL: missing image ${STAGE3_IMAGE}"
    echo "Hint: run scripts/gentoo/build-base-image.sh"
    exit 1
fi
if ! docker image inspect "${BUILDER_IMAGE}" >/dev/null 2>&1; then
    echo "FAIL: missing image ${BUILDER_IMAGE}"
    echo "Hint: run scripts/gentoo/build-base-image.sh"
    exit 1
fi

echo "--- check: emerge --info works ---"
docker run --rm "${STAGE3_IMAGE}" bash -lc "emerge --info >/tmp/emerge-info.txt && test -s /tmp/emerge-info.txt"

echo "--- check: make.conf copied ---"
docker run --rm "${STAGE3_IMAGE}" bash -lc "test -f /etc/portage/make.conf && grep -q 'FEATURES=\"parallel-fetch test\"' /etc/portage/make.conf"

echo "--- check: stage3 toolchain baseline exists ---"
docker run --rm "${STAGE3_IMAGE}" bash -lc "command -v gcc && command -v ld && command -v make"

echo "--- check: builder has hook files ---"
docker run --rm "${BUILDER_IMAGE}" bash -lc "test -f /etc/portage/bashrc && test -x /opt/frankenlibc/scripts/gentoo/frankenlibc-ebuild-hooks.sh"

echo "--- check: coreutils dependency plan resolves ---"
docker run --rm "${STAGE3_IMAGE}" bash -lc "emerge -p sys-apps/coreutils >/tmp/coreutils-plan.txt && test -s /tmp/coreutils-plan.txt"

if [[ "${RUN_FULL_EMERGE}" == "1" ]]; then
    echo "--- check: full coreutils emerge (slow) ---"
    docker run --rm "${STAGE3_IMAGE}" bash -lc "emerge -1v sys-apps/coreutils"
else
    echo "INFO: skipped full emerge build (set FLC_GENTOO_TEST_FULL_EMERGE=1 to enable)"
fi

echo "PASS: gentoo base image validation completed"
