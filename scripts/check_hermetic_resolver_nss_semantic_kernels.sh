#!/usr/bin/env bash
# check_hermetic_resolver_nss_semantic_kernels.sh -- bd-ewv1l semantic NSS/resolver gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_HERMETIC_RESOLVER_NSS_KERNELS_MANIFEST:-${ROOT}/tests/conformance/hermetic_resolver_nss_semantic_kernels.v1.json}"
OUT_DIR="${FLC_HERMETIC_RESOLVER_NSS_KERNELS_OUT_DIR:-${ROOT}/target/conformance/hermetic_resolver_nss_semantic_kernels}"
REPORT="${FLC_HERMETIC_RESOLVER_NSS_KERNELS_REPORT:-${OUT_DIR}/hermetic_resolver_nss_semantic_kernels.report.json}"
LOG="${FLC_HERMETIC_RESOLVER_NSS_KERNELS_LOG:-${OUT_DIR}/hermetic_resolver_nss_semantic_kernels.log.jsonl}"
LAB_OUT_DIR="${FLC_HERMETIC_RESOLVER_NSS_KERNELS_LAB_OUT_DIR:-${OUT_DIR}/nss_lab}"
LAB_REPORT="${LAB_OUT_DIR}/hermetic_nss_resolver_lab.report.json"
LAB_LOG="${LAB_OUT_DIR}/hermetic_nss_resolver_lab.log.jsonl"
TARGET_DIR="${FLC_HERMETIC_RESOLVER_NSS_KERNELS_TARGET_DIR:-${CARGO_TARGET_DIR:-${ROOT}/target}}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "${LAB_OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

FLC_NSS_LAB_OUT_DIR="${LAB_OUT_DIR}" \
FLC_NSS_LAB_REPORT="${LAB_REPORT}" \
FLC_NSS_LAB_LOG="${LAB_LOG}" \
FLC_NSS_LAB_TARGET_DIR="${TARGET_DIR}" \
bash "${ROOT}/scripts/run_hermetic_nss_resolver_lab.sh" >/dev/null

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" "${LAB_REPORT}" "${LAB_LOG}" "${SOURCE_COMMIT}" "${TARGET_DIR}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
lab_report_path = Path(sys.argv[5])
lab_log_path = Path(sys.argv[6])
source_commit = sys.argv[7]
target_dir = sys.argv[8]

BEAD_ID = "bd-ewv1l"
GATE_ID = "hermetic-resolver-nss-semantic-kernels-v1"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "kernel_id",
    "scenario_id",
    "runtime_mode",
    "semantic_domain",
    "oracle_kind",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_DOMAINS = {
    "hosts",
    "services",
    "passwd",
    "group",
    "resolv_conf",
    "nsswitch",
    "dns_cache",
    "dns_timeout",
    "dns_poisoning",
    "search_domain",
}
REQUIRED_MODES = {"strict", "hardened"}
DIAGNOSTIC_SIGNATURES = {
    "missing_field",
    "stale_artifact",
    "missing_source_artifact",
    "missing_semantic_kernel",
    "real_network_required",
    "semantic_kernel_mismatch",
    "unexpected_dns_egress",
    "unsupported_lookup_family",
}
SUPPORTED_DOMAINS = REQUIRED_DOMAINS

errors = []
logs = []


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fail(signature, message):
    errors.append({"failure_signature": signature, "message": message})


def load_json(path, label):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail("missing_source_artifact", f"{label}: cannot parse {path}: {exc}")
        return {}


def load_jsonl(path, label):
    rows = []
    try:
        for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if raw.strip():
                rows.append(json.loads(raw))
    except Exception as exc:
        fail("missing_source_artifact", f"{label}: cannot parse {path}:{line_no}: {exc}")
    return rows


def resolve(path_text):
    path = Path(str(path_text))
    return path if path.is_absolute() else root / path


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(root))
    except ValueError:
        return str(path)


def require_object(value, ctx):
    if isinstance(value, dict):
        return value
    fail("missing_field", f"{ctx}: must be object")
    return {}


def require_array(row, field, ctx):
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty array")
    return []


def require_string(row, field, ctx):
    value = row.get(field)
    if isinstance(value, str) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty string")
    return ""


def existing_path(path_text, ctx):
    path = resolve(path_text)
    if not path.exists():
        fail("missing_source_artifact", f"{ctx}: missing path {path_text}")


def source_commit_ok(marker):
    return marker in ("current", "unknown", source_commit)


def strip_comment(line):
    return line.split("#", 1)[0].strip()


def parse_hosts(content, query):
    addrs = []
    query_lower = query.lower()
    for raw in content.splitlines():
        line = strip_comment(raw)
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and query_lower in [part.lower() for part in parts[1:]]:
            addrs.append(parts[0])
    return addrs


def parse_services(content, query):
    name, proto = query.split("/", 1)
    for raw in content.splitlines():
        line = strip_comment(raw)
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        port_proto = parts[1].split("/", 1)
        if len(port_proto) == 2 and parts[0] == name and port_proto[1] == proto:
            return {"service": name, "port": int(port_proto[0]), "protocol": proto}
    return {}


def parse_passwd(content, query):
    for raw in content.splitlines():
        line = strip_comment(raw)
        if not line:
            continue
        fields = line.split(":")
        if len(fields) >= 7 and fields[0] == query:
            return {
                "name": fields[0],
                "uid": int(fields[2]),
                "gid": int(fields[3]),
                "home": fields[5],
                "shell": fields[6],
            }
    return {}


def parse_group(content, query):
    for raw in content.splitlines():
        line = strip_comment(raw)
        if not line:
            continue
        fields = line.split(":")
        if len(fields) >= 4 and fields[0] == query:
            members = [member for member in fields[3].split(",") if member]
            return {"name": fields[0], "gid": int(fields[2]), "members": members}
    return {}


def parse_resolv(content):
    result = {"nameserver_loopback": False, "timeout": None, "attempts": None, "search": []}
    for raw in content.splitlines():
        line = strip_comment(raw)
        if not line:
            continue
        parts = line.split()
        if parts[0] == "nameserver" and len(parts) >= 2:
            result["nameserver_loopback"] = (
                parts[1].startswith("127.")
                or parts[1] == "::1"
                or parts[1].startswith("[::1]")
                or parts[1] == "localhost"
            )
        if parts[0] == "options":
            for item in parts[1:]:
                if item.startswith("timeout:"):
                    result["timeout"] = int(item.split(":", 1)[1])
                if item.startswith("attempts:"):
                    result["attempts"] = int(item.split(":", 1)[1])
        if parts[0] == "search":
            result["search"] = parts[1:]
    return result


def parse_nsswitch(content):
    result = {}
    for raw in content.splitlines():
        line = strip_comment(raw)
        if not line or ":" not in line:
            continue
        db, rest = line.split(":", 1)
        result[db.strip()] = rest.split()
    return result


def expected_subset(actual, expected):
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key, value in expected.items():
            if key not in actual:
                return False, f"missing key {key}"
            ok, reason = expected_subset(actual[key], value)
            if not ok:
                return False, f"{key}.{reason}"
        return True, ""
    return (actual == expected, f"expected {expected!r}, got {actual!r}")


manifest = require_object(load_json(manifest_path, "manifest"), "manifest")
lab_report = require_object(load_json(lab_report_path, "lab_report"), "lab_report")
lab_rows = load_jsonl(lab_log_path, "lab_log")

if manifest.get("schema_version") != "v1":
    fail("missing_field", "schema_version must be v1")
if manifest.get("bead_id") != BEAD_ID:
    fail("missing_field", f"bead_id must be {BEAD_ID}")
if manifest.get("gate_id") != GATE_ID:
    fail("missing_field", f"gate_id must be {GATE_ID}")
if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    fail("missing_field", "required_log_fields must match semantic kernel contract")

freshness = require_object(manifest.get("freshness"), "freshness")
required_commit = str(freshness.get("required_source_commit", ""))
if not source_commit_ok(required_commit):
    fail(
        "stale_artifact",
        f"freshness.required_source_commit {required_commit!r} does not match current {source_commit}",
    )
if lab_report.get("source_commit") != source_commit:
    fail("stale_artifact", "lab_report.source_commit must match semantic gate source_commit")

policy = require_object(manifest.get("execution_policy"), "execution_policy")
if policy.get("real_network_allowed") is not False:
    fail("real_network_required", "execution_policy.real_network_allowed must be false")
if lab_report.get("real_network_observed") is not False:
    fail("unexpected_dns_egress", "lab report observed real network traffic")

sources = require_object(manifest.get("sources"), "sources")
for key in [
    "lab_manifest",
    "lab_runner",
    "resolver_fixture",
    "resolver_nss_hard_parts",
    "oracle_precedence_divergence",
    "user_environment_coverage",
    "resolver_conformance_test",
    "nss_lab_execution_test",
]:
    path_text = sources.get(key)
    if isinstance(path_text, str) and path_text:
        existing_path(path_text, f"sources.{key}")
    else:
        fail("missing_field", f"sources.{key}: must be non-empty string")

declared_signatures = {
    str(row.get("id"))
    for row in manifest.get("diagnostic_signatures", [])
    if isinstance(row, dict) and row.get("id")
}
for signature in DIAGNOSTIC_SIGNATURES:
    if signature not in declared_signatures:
        fail("missing_field", f"diagnostic_signatures missing {signature}")

if set(map(str, manifest.get("required_semantic_domains", []))) != REQUIRED_DOMAINS:
    fail("missing_semantic_kernel", "required_semantic_domains must match semantic kernel domains")
if set(map(str, manifest.get("required_runtime_modes", []))) != REQUIRED_MODES:
    fail("missing_semantic_kernel", "required_runtime_modes must include strict and hardened")

rows_by_scenario_mode = {}
for row in lab_rows:
    scenario_id = row.get("scenario_id")
    runtime_mode = row.get("runtime_mode")
    if isinstance(scenario_id, str) and isinstance(runtime_mode, str):
        rows_by_scenario_mode[(scenario_id, runtime_mode)] = row

fake_roots = require_object(lab_report.get("fake_roots"), "lab_report.fake_roots")

seen_domains = set()
seen_modes = set()
seen_kernel_modes = set()
kernel_rows = manifest.get("semantic_kernels")
if not isinstance(kernel_rows, list) or not kernel_rows:
    fail("missing_semantic_kernel", "semantic_kernels must be a non-empty array")
    kernel_rows = []

for index, value in enumerate(kernel_rows):
    kernel = require_object(value, f"semantic_kernels[{index}]")
    ctx = f"semantic_kernels[{index}]"
    kernel_id = require_string(kernel, "kernel_id", ctx)
    semantic_domain = require_string(kernel, "semantic_domain", ctx)
    scenario_id = require_string(kernel, "scenario_id", ctx)
    runtime_modes = set(map(str, require_array(kernel, "runtime_modes", ctx)))
    oracle_kind = require_string(kernel, "oracle_kind", ctx)
    fake_root_file = require_string(kernel, "fake_root_file", ctx)
    query = require_string(kernel, "query", ctx)
    expected = require_object(kernel.get("expected"), f"{ctx}.expected")
    artifact_refs = require_array(kernel, "artifact_refs", ctx)

    seen_domains.add(semantic_domain)
    seen_modes.update(runtime_modes)
    if semantic_domain not in SUPPORTED_DOMAINS:
        fail("unsupported_lookup_family", f"{kernel_id}: unsupported semantic_domain {semantic_domain}")
    if not REQUIRED_MODES.issubset(runtime_modes):
        fail("missing_semantic_kernel", f"{kernel_id}: runtime_modes must include strict and hardened")

    for ref in artifact_refs:
        existing_path(ref, f"{kernel_id}.artifact_refs")

    fake_root_rel = fake_roots.get(scenario_id)
    if not isinstance(fake_root_rel, str):
        fail("missing_source_artifact", f"{kernel_id}: lab report missing fake root for {scenario_id}")
        continue
    fake_file = root / fake_root_rel / fake_root_file
    if not fake_file.exists():
        fail("missing_source_artifact", f"{kernel_id}: missing fake-root file {fake_file}")
        continue
    content = fake_file.read_text(encoding="utf-8")

    if semantic_domain == "hosts":
        actual = {
            "addresses": parse_hosts(content, query),
            "lookup_source": "files",
            "dns_fallback": False,
        }
    elif semantic_domain == "services":
        actual = parse_services(content, query)
    elif semantic_domain == "passwd":
        actual = parse_passwd(content, query)
    elif semantic_domain == "group":
        actual = parse_group(content, query)
    elif semantic_domain == "resolv_conf":
        actual = parse_resolv(content)
    elif semantic_domain == "nsswitch":
        actual = parse_nsswitch(content)
    else:
        actual = {}

    for runtime_mode in sorted(runtime_modes):
        seen_kernel_modes.add((kernel_id, runtime_mode))
        lab_row = rows_by_scenario_mode.get((scenario_id, runtime_mode))
        if lab_row is None:
            fail("missing_source_artifact", f"{kernel_id}: missing lab row for {scenario_id}/{runtime_mode}")
            continue
        if semantic_domain in {"dns_cache", "dns_timeout", "dns_poisoning", "search_domain"}:
            actual = {
                "resolved_addrs": lab_row.get("resolved_addrs"),
                "resolved_errno": lab_row.get("resolved_errno"),
                **require_object(lab_row.get("actual"), f"{kernel_id}.lab_row.actual"),
            }
        ok, reason = expected_subset(actual, expected)
        failure_signature = "none"
        if not ok:
            failure_signature = "semantic_kernel_mismatch"
            fail("semantic_kernel_mismatch", f"{kernel_id}/{runtime_mode}: {reason}")
        log_row = {
            "trace_id": f"{BEAD_ID}::{kernel_id}::{runtime_mode}",
            "bead_id": BEAD_ID,
            "kernel_id": kernel_id,
            "scenario_id": scenario_id,
            "runtime_mode": runtime_mode,
            "semantic_domain": semantic_domain,
            "oracle_kind": oracle_kind,
            "expected": expected,
            "actual": actual,
            "artifact_refs": sorted(set(list(map(str, artifact_refs)) + [rel(fake_file), rel(lab_log_path), rel(lab_report_path)])),
            "source_commit": source_commit,
            "target_dir": target_dir,
            "failure_signature": failure_signature,
        }
        logs.append(log_row)

missing_domains = sorted(REQUIRED_DOMAINS - seen_domains)
missing_modes = sorted(REQUIRED_MODES - seen_modes)
if missing_domains:
    fail("missing_semantic_kernel", f"missing semantic domains: {missing_domains}")
if missing_modes:
    fail("missing_semantic_kernel", f"missing runtime modes: {missing_modes}")

summary = {
    "semantic_kernel_count": len(kernel_rows),
    "semantic_log_row_count": len(logs),
    "covered_semantic_domain_count": len(seen_domains),
    "runtime_mode_count": len(seen_modes),
    "lab_evidence_row_count": len(lab_rows),
    "fake_root_count": len(fake_roots),
    "real_network_observed": lab_report.get("real_network_observed"),
}

report = {
    "schema_version": "v1",
    "bead_id": BEAD_ID,
    "gate_id": GATE_ID,
    "status": "fail" if errors else "pass",
    "generated_at_utc": now(),
    "source_commit": source_commit,
    "target_dir": target_dir,
    "summary": summary,
    "errors": errors,
    "report_artifacts": {
        "manifest": str(manifest_path),
        "report": str(report_path),
        "log": str(log_path),
        "lab_report": str(lab_report_path),
        "lab_log": str(lab_log_path),
    },
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as handle:
    for row in logs:
        handle.write(json.dumps(row, sort_keys=True) + "\n")

print(json.dumps(report, sort_keys=True))
if errors:
    sys.exit(1)
PY
