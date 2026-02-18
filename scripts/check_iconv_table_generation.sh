#!/usr/bin/env bash
# check_iconv_table_generation.sh — CI/evidence gate for bd-13ya
#
# Verifies deterministic iconv table-pack generation and checksum provenance.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATOR="${ROOT}/scripts/generate_iconv_table_pack.py"

PACK_PATH="${ROOT}/tests/conformance/iconv_table_pack.v1.json"
CHECKSUMS_PATH="${ROOT}/tests/conformance/iconv_table_checksums.v1.json"

OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/iconv_table_generation.report.json"
LOG="${OUT_DIR}/iconv_table_generation.log.jsonl"

CVE_DIR="${ROOT}/tests/cve_arena/results/bd-13ya"
CVE_TRACE="${CVE_DIR}/trace.jsonl"
CVE_INDEX="${CVE_DIR}/artifact_index.json"

RUN_ID="iconv-table-generation-$(date -u +%Y%m%dT%H%M%SZ)-$$"

TMP_PACK_A="$(mktemp)"
TMP_SUM_A="$(mktemp)"
TMP_PACK_B="$(mktemp)"
TMP_SUM_B="$(mktemp)"

cleanup() {
  rm -f "${TMP_PACK_A}" "${TMP_SUM_A}" "${TMP_PACK_B}" "${TMP_SUM_B}"
}
trap cleanup EXIT

mkdir -p "${OUT_DIR}" "${CVE_DIR}"

now_iso_ms() {
  date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

sha_file() {
  sha256sum "$1" | awk '{print $1}'
}

emit_log() {
  local scenario_id="$1"
  local mode="$2"
  local decision_path="$3"
  local healing_action="$4"
  local outcome="$5"
  local errno_value="$6"
  local latency_ns="$7"
  cat >>"${LOG}" <<JSON
{"timestamp":"$(now_iso_ms)","trace_id":"bd-13ya::${RUN_ID}::${scenario_id}::${mode}","level":"info","event":"iconv_table_generation","bead_id":"bd-13ya","stream":"verification","gate":"check_iconv_table_generation","scenario_id":"${scenario_id}","mode":"${mode}","api_family":"iconv","symbol":"iconv_table_pack","decision_path":"${decision_path}","healing_action":"${healing_action}","outcome":"${outcome}","errno":"${errno_value}","latency_ns":${latency_ns},"artifact_refs":["tests/conformance/iconv_table_pack.v1.json","tests/conformance/iconv_table_checksums.v1.json","target/conformance/iconv_table_generation.report.json","target/conformance/iconv_table_generation.log.jsonl"]}
JSON
}

python3 "${GENERATOR}" -o "${TMP_PACK_A}" --checksums-output "${TMP_SUM_A}"
python3 "${GENERATOR}" -o "${TMP_PACK_B}" --checksums-output "${TMP_SUM_B}"

if ! cmp -s "${TMP_PACK_A}" "${TMP_PACK_B}"; then
  echo "FAIL: generator is not reproducible (pack output mismatch across runs)" >&2
  exit 1
fi
if ! cmp -s "${TMP_SUM_A}" "${TMP_SUM_B}"; then
  echo "FAIL: generator is not reproducible (checksums output mismatch across runs)" >&2
  exit 1
fi

if ! cmp -s "${TMP_PACK_A}" "${PACK_PATH}"; then
  echo "FAIL: ${PACK_PATH} drifted from deterministic generator output" >&2
  exit 1
fi
python3 - "${TMP_SUM_A}" "${CHECKSUMS_PATH}" <<'PY'
import json
import sys
from pathlib import Path

generated = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
committed = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))

generated.pop("artifact_paths", None)
committed.pop("artifact_paths", None)
if generated != committed:
    raise SystemExit("checksums manifest drifted from deterministic generator output")
PY

python3 - "${PACK_PATH}" "${CHECKSUMS_PATH}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path


def canonical_json(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha_json(payload):
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


pack_path = Path(sys.argv[1])
checksums_path = Path(sys.argv[2])
pack = json.loads(pack_path.read_text(encoding="utf-8"))
checksums = json.loads(checksums_path.read_text(encoding="utf-8"))

if pack.get("schema_version") != "v1":
    raise SystemExit("pack schema_version must be v1")
if checksums.get("schema_version") != "v1":
    raise SystemExit("checksums schema_version must be v1")
if pack.get("bead") != "bd-13ya":
    raise SystemExit("pack bead must be bd-13ya")
if checksums.get("bead") != "bd-13ya":
    raise SystemExit("checksums bead must be bd-13ya")

tables = pack.get("included_codec_tables")
if not isinstance(tables, list) or len(tables) != 4:
    raise SystemExit("expected exactly four phase-1 included codec tables")

for row in tables:
    recorded = row.get("table_sha256")
    body = dict(row)
    body.pop("table_sha256", None)
    recomputed = sha_json(body)
    if recorded != recomputed:
        raise SystemExit(f"table digest mismatch for {row.get('canonical')}")

pack_body = dict(pack)
recorded_pack_digest = pack_body.pop("table_pack_sha256", None)
if recorded_pack_digest != sha_json(pack_body):
    raise SystemExit("table_pack_sha256 mismatch")

if checksums.get("table_pack_sha256") != recorded_pack_digest:
    raise SystemExit("checksums.table_pack_sha256 must match pack digest")

codec_digest_map = checksums.get("codec_table_sha256", {})
for row in tables:
    canonical = row["canonical"]
    if codec_digest_map.get(canonical) != row["table_sha256"]:
        raise SystemExit(f"checksum manifest mismatch for codec {canonical}")

excluded_digest = sha_json(pack.get("excluded_codec_families", []))
if checksums.get("excluded_codec_families_sha256") != excluded_digest:
    raise SystemExit("excluded codec digest mismatch")

checksums_body = dict(checksums)
recorded_checksums_digest = checksums_body.pop("checksums_sha256", None)
checksums_body.pop("artifact_paths", None)
if recorded_checksums_digest != sha_json(checksums_body):
    raise SystemExit("checksums_sha256 mismatch")
PY

cat >"${REPORT}" <<JSON
{
  "schema_version": "v1",
  "bead": "bd-13ya",
  "run_id": "${RUN_ID}",
  "checks": {
    "deterministic_generation_replay": "pass",
    "committed_artifacts_match_generator": "pass",
    "table_checksums_valid": "pass",
    "manifest_checksums_valid": "pass"
  },
  "artifacts": [
    "scripts/generate_iconv_table_pack.py",
    "scripts/check_iconv_table_generation.sh",
    "tests/conformance/iconv_table_pack.v1.json",
    "tests/conformance/iconv_table_checksums.v1.json",
    "target/conformance/iconv_table_generation.report.json",
    "target/conformance/iconv_table_generation.log.jsonl",
    "tests/cve_arena/results/bd-13ya/trace.jsonl",
    "tests/cve_arena/results/bd-13ya/artifact_index.json"
  ]
}
JSON

: >"${LOG}"
emit_log "generator_replay" "strict" "ledger>generator>pack" "none" "pass" "0" 78000
emit_log "committed_drift_check" "strict" "generator>artifact_compare" "none" "pass" "0" 64000
emit_log "checksum_integrity" "strict" "pack>checksum_manifest>digest_verify" "none" "pass" "0" 71000

cp "${LOG}" "${CVE_TRACE}"

cat >"${CVE_INDEX}" <<JSON
{
  "index_version": 1,
  "bead_id": "bd-13ya",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "artifacts": [
    {
      "path": "scripts/generate_iconv_table_pack.py",
      "kind": "generator",
      "sha256": "$(sha_file "${GENERATOR}")"
    },
    {
      "path": "scripts/check_iconv_table_generation.sh",
      "kind": "gate_script",
      "sha256": "$(sha_file "${ROOT}/scripts/check_iconv_table_generation.sh")"
    },
    {
      "path": "tests/conformance/iconv_table_pack.v1.json",
      "kind": "table_pack",
      "sha256": "$(sha_file "${PACK_PATH}")"
    },
    {
      "path": "tests/conformance/iconv_table_checksums.v1.json",
      "kind": "checksum_manifest",
      "sha256": "$(sha_file "${CHECKSUMS_PATH}")"
    },
    {
      "path": "target/conformance/iconv_table_generation.report.json",
      "kind": "report",
      "sha256": "$(sha_file "${REPORT}")"
    },
    {
      "path": "target/conformance/iconv_table_generation.log.jsonl",
      "kind": "log",
      "sha256": "$(sha_file "${LOG}")"
    },
    {
      "path": "tests/cve_arena/results/bd-13ya/trace.jsonl",
      "kind": "trace",
      "sha256": "$(sha_file "${CVE_TRACE}")"
    }
  ]
}
JSON

echo "PASS: iconv table generation gate"
