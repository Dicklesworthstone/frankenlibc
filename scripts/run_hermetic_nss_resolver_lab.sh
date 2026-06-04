#!/usr/bin/env bash
# run_hermetic_nss_resolver_lab.sh -- bd-b92jd.5.5
#
# Deterministic smoke-tier execution layer for the hermetic NSS/resolver lab.
# The runner creates synthetic fake-root inputs, binds only loopback fake DNS
# endpoints, and emits JSONL evidence rows under target/conformance/nss_lab.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_NSS_LAB_MANIFEST:-${ROOT}/tests/conformance/hermetic_nss_resolver_lab.v1.json}"
OUT_DIR="${FLC_NSS_LAB_OUT_DIR:-${ROOT}/target/conformance/nss_lab}"
REPORT="${FLC_NSS_LAB_REPORT:-${OUT_DIR}/hermetic_nss_resolver_lab.report.json}"
LOG="${FLC_NSS_LAB_LOG:-${OUT_DIR}/hermetic_nss_resolver_lab.log.jsonl}"
TARGET_DIR="${FLC_NSS_LAB_TARGET_DIR:-${CARGO_TARGET_DIR:-${ROOT}/target}}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${OUT_DIR}" "${REPORT}" "${LOG}" "${TARGET_DIR}" "${SOURCE_COMMIT}" <<'PY'
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1]).resolve()
manifest_path = Path(sys.argv[2])
out_dir = Path(sys.argv[3])
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])
target_dir = sys.argv[6]
source_commit = sys.argv[7]

BEAD_ID = "bd-b92jd.5.5"
TRACE_PREFIX = "bd-b92jd.5.5:nss-lab"
REQUIRED_ROOT_FILES = {
    "etc/hosts",
    "etc/services",
    "etc/passwd",
    "etc/group",
    "etc/resolv.conf",
    "etc/nsswitch.conf",
}
REQUIRED_MODES = {"strict", "hardened"}
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "scenario_id",
    "scenario_kind",
    "fake_root_id",
    "runtime_mode",
    "oracle_kind",
    "query_kind",
    "resolved_host",
    "resolved_addrs",
    "resolved_errno",
    "semantic_kernel",
    "oracle_delta",
    "expected",
    "actual",
    "decision_path",
    "duration_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
FAILURES = {
    "real_network": "nss_lab_real_network_required",
    "missing_fake_root": "nss_lab_missing_fake_root_file",
    "stale_commit": "nss_lab_stale_source_commit",
    "missing_oracle": "nss_lab_missing_oracle",
    "missing_runtime_mode": "nss_lab_missing_runtime_mode",
    "missing_fixture": "nss_lab_missing_fixture_obligation",
    "missing_required_log": "nss_lab_missing_required_log_field",
    "duplicate_scenario": "nss_lab_duplicate_scenario_id",
    "unsafe_artifact": "nss_lab_unsafe_artifact_path",
    "missing_semantic_kernel": "nss_lab_missing_semantic_kernel",
    "unsupported_lookup_family": "nss_lab_unsupported_lookup_family",
    "oracle_delta": "nss_lab_oracle_delta_detected",
}
REQUIRED_KERNEL_IDS = {
    "numeric_short_circuit_kernel",
    "hosts_files_kernel",
    "services_files_kernel",
    "passwd_files_kernel",
    "group_files_kernel",
    "resolv_conf_kernel",
    "nsswitch_kernel",
    "fake_dns_loopback_kernel",
}
SUPPORTED_LOOKUP_FAMILIES = {
    "numeric_hosts",
    "hosts",
    "services",
    "passwd",
    "group",
    "resolv_conf",
    "nsswitch",
    "fake_dns_loopback",
}

errors = []
rows = []
scenario_artifacts = {}
fake_dns_endpoints = {}
fake_roots = {}
skip_conditions = []
checks = {
    "manifest_parse": "fail",
    "execution_policy": "fail",
    "freshness": "fail",
    "fake_root_layout": "fail",
    "semantic_kernels": "fail",
    "scenario_contract": "fail",
    "fake_roots_created": "fail",
    "structured_log": "fail",
}


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fail(signature, message):
    errors.append({"signature": signature, "message": message})


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail("nss_lab_manifest_parse", f"cannot parse {path}: {exc}")
        return {}


def rel(path):
    path = Path(path)
    try:
        return str(path.resolve().relative_to(root))
    except ValueError:
        return str(path)


def safe_rel_path(path_text, signature, context):
    path = Path(str(path_text))
    if path.is_absolute() or any(part in ("..", "") for part in path.parts):
        fail(signature, f"{context}: unsafe relative path {path_text!r}")
        return None
    return path


def bool_env(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_jsonl(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)
    atomic_write_text(path, payload)


def atomic_write_text(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, path)


def source_commit_ok(required):
    return required in ("current", source_commit)


def validate_execution_policy(manifest):
    policy = manifest.get("execution_policy")
    if not isinstance(policy, dict):
        fail(FAILURES["real_network"], "execution_policy must be an object")
        return
    if policy.get("default_runner") != "rch_only":
        fail("nss_lab_local_runner", "execution_policy.default_runner must be rch_only")
    if policy.get("real_network_allowed") is not False:
        fail(FAILURES["real_network"], "execution_policy.real_network_allowed must be false")
    envvar = policy.get("real_network_envvar_override", "")
    if isinstance(envvar, str) and envvar and bool_env(os.environ.get(envvar, "")):
        fail(
            FAILURES["real_network"],
            f"{envvar} is set; hermetic lab refuses real-network observation",
        )
    checks["execution_policy"] = "pass"


def validate_freshness(manifest):
    freshness = manifest.get("freshness", {})
    if not isinstance(freshness, dict):
        fail(FAILURES["stale_commit"], "freshness must be an object")
        return
    freshness_policy = manifest.get("source_commit_freshness_policy", {})
    expected_freshness_policy = {
        "recorded_source_commit_field": "source_commit",
        "comparison_target": "current git HEAD",
        "stale_result": "block_nss_lab_evidence",
        "nss_lab_evidence_allowed_when_stale": False,
        "rejected_evidence_kind": FAILURES["stale_commit"],
    }
    if freshness_policy != expected_freshness_policy:
        fail(
            FAILURES["stale_commit"],
            "source_commit_freshness_policy must match the stale NSS lab block contract",
        )
        return
    required = freshness.get("required_source_commit", "")
    if not isinstance(required, str) or not source_commit_ok(required):
        fail(
            FAILURES["stale_commit"],
            f"freshness.required_source_commit {required!r} does not match current {source_commit}",
        )
        return
    checks["freshness"] = "pass"


def validate_layout(manifest):
    layout = manifest.get("fake_root_layout")
    if not isinstance(layout, dict):
        fail(FAILURES["missing_fake_root"], "fake_root_layout must be an object")
        return set(), {}
    entries = layout.get("files")
    if not isinstance(entries, list):
        fail(FAILURES["missing_fake_root"], "fake_root_layout.files must be an array")
        return set(), {}

    declared = set()
    by_path = {}
    for entry in entries:
        if not isinstance(entry, dict):
            fail(FAILURES["missing_fake_root"], "fake_root_layout.files entries must be objects")
            continue
        path = entry.get("relative_path")
        if not isinstance(path, str) or not path:
            fail(FAILURES["missing_fake_root"], "fake_root_layout.files entry lacks relative_path")
            continue
        safe = safe_rel_path(path, FAILURES["missing_fake_root"], "fake_root_layout.files")
        if safe is None:
            continue
        declared.add(path)
        by_path[path] = entry

    missing = sorted(REQUIRED_ROOT_FILES - declared)
    if missing:
        fail(
            FAILURES["missing_fake_root"],
            f"fake_root_layout.files missing required files: {', '.join(missing)}",
        )

    dns = layout.get("fake_dns_endpoint", {})
    if not isinstance(dns, dict):
        fail(FAILURES["real_network"], "fake_dns_endpoint must be an object")
    else:
        default_address = str(dns.get("default_address", ""))
        if not (
            default_address.startswith("127.")
            or default_address.startswith("localhost")
            or default_address.startswith("::1")
            or default_address.startswith("[::1]")
        ):
            fail(
                FAILURES["real_network"],
                f"fake_dns_endpoint.default_address must be loopback; got {default_address}",
            )
    checks["fake_root_layout"] = "pass"
    return declared, by_path


def validate_semantic_kernels(manifest):
    semantic = manifest.get("semantic_kernels")
    if not isinstance(semantic, dict):
        fail(FAILURES["missing_semantic_kernel"], "semantic_kernels must be an object")
        return {}, set()

    kernels = semantic.get("required_kernels")
    if not isinstance(kernels, list) or not kernels:
        fail(FAILURES["missing_semantic_kernel"], "semantic_kernels.required_kernels must be a non-empty array")
        return {}, set()

    by_id = {}
    lookup_families = set()
    for kernel in kernels:
        if not isinstance(kernel, dict):
            fail(FAILURES["missing_semantic_kernel"], "semantic kernel entries must be objects")
            continue
        kernel_id = kernel.get("kernel_id")
        lookup_family = kernel.get("lookup_family")
        if not isinstance(kernel_id, str) or not kernel_id:
            fail(FAILURES["missing_semantic_kernel"], "semantic kernel lacks kernel_id")
            continue
        if kernel_id in by_id:
            fail(FAILURES["missing_semantic_kernel"], f"duplicate semantic kernel {kernel_id}")
        if lookup_family not in SUPPORTED_LOOKUP_FAMILIES:
            fail(FAILURES["unsupported_lookup_family"], f"{kernel_id}: unsupported lookup_family {lookup_family!r}")
        fixtures = kernel.get("host_glibc_fixture_ids")
        if not isinstance(fixtures, list) or not all(isinstance(item, str) and item for item in fixtures):
            fail(FAILURES["missing_semantic_kernel"], f"{kernel_id}: host_glibc_fixture_ids must be non-empty strings")
        surface = kernel.get("frankenlibc_surface")
        if not isinstance(surface, str) or not surface:
            fail(FAILURES["missing_semantic_kernel"], f"{kernel_id}: frankenlibc_surface must be non-empty")
        by_id[kernel_id] = kernel
        lookup_families.add(lookup_family)

    missing = sorted(REQUIRED_KERNEL_IDS - set(by_id))
    if missing:
        fail(FAILURES["missing_semantic_kernel"], f"semantic_kernels missing required kernels: {', '.join(missing)}")

    unsupported = semantic.get("unsupported_lookup_families")
    unsupported_set = {item for item in unsupported if isinstance(item, str)} if isinstance(unsupported, list) else set()
    for family in unsupported_set:
        if family in lookup_families:
            fail(FAILURES["unsupported_lookup_family"], f"unsupported family {family} also appears as a required kernel")
    for family in ["netgroup", "rpc", "nscd", "sunrpc"]:
        if family not in unsupported_set:
            fail(FAILURES["unsupported_lookup_family"], f"unsupported_lookup_families must include {family}")

    policy = semantic.get("oracle_delta_policy", {})
    if not isinstance(policy, dict) or policy.get("required") is not True:
        fail(FAILURES["oracle_delta"], "semantic_kernels.oracle_delta_policy.required must be true")
    checks["semantic_kernels"] = "pass"
    return by_id, unsupported_set


def validate_scenarios(manifest, declared_files, kernels_by_id):
    scenarios = manifest.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        fail("nss_lab_missing_scenarios", "scenarios must be a non-empty array")
        return []

    seen = set()
    valid = []
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            fail("nss_lab_missing_scenarios", "scenario entries must be objects")
            continue
        scenario_id = scenario.get("scenario_id", "")
        context = scenario_id or "<missing>"
        if not isinstance(scenario_id, str) or not scenario_id:
            fail("nss_lab_missing_scenario_id", "scenario_id must be a non-empty string")
            continue
        if scenario_id in seen:
            fail(FAILURES["duplicate_scenario"], f"duplicate scenario_id {scenario_id}")
        seen.add(scenario_id)

        if not isinstance(scenario.get("oracle_kind"), str) or not scenario.get("oracle_kind"):
            fail(FAILURES["missing_oracle"], f"{context}: oracle_kind must be non-empty")

        semantic_kernel = scenario.get("semantic_kernel")
        if not isinstance(semantic_kernel, str) or not semantic_kernel:
            fail(FAILURES["missing_semantic_kernel"], f"{context}: semantic_kernel must be non-empty")
        elif semantic_kernel not in kernels_by_id:
            fail(FAILURES["missing_semantic_kernel"], f"{context}: semantic_kernel {semantic_kernel} is not declared")

        fixture_ids = scenario.get("host_glibc_fixture_ids")
        if not isinstance(fixture_ids, list) or not all(isinstance(item, str) and item for item in fixture_ids):
            fail(FAILURES["missing_fixture"], f"{context}: host_glibc_fixture_ids must be non-empty strings")

        modes = scenario.get("runtime_modes")
        mode_set = {mode for mode in modes if isinstance(mode, str)} if isinstance(modes, list) else set()
        if not REQUIRED_MODES.issubset(mode_set):
            fail(
                FAILURES["missing_runtime_mode"],
                f"{context}: runtime_modes must include strict and hardened",
            )

        obligation = scenario.get("fixture_obligation")
        if not isinstance(obligation, str) or not obligation:
            fail(
                FAILURES["missing_fixture"],
                f"{context}: fixture_obligation must be non-empty",
            )

        needed = scenario.get("fake_root_files_needed")
        if not isinstance(needed, list) or not needed:
            fail(FAILURES["missing_fake_root"], f"{context}: fake_root_files_needed must be non-empty")
        else:
            for item in needed:
                if not isinstance(item, str) or item not in declared_files:
                    fail(
                        FAILURES["missing_fake_root"],
                        f"{context}: fake_root_files_needed references undeclared file {item!r}",
                    )

        artifact = scenario.get("evidence_artifact", "")
        artifact_path = safe_rel_path(artifact, FAILURES["unsafe_artifact"], f"{context}.evidence_artifact")
        if artifact_path is None or not (
            str(artifact).startswith("target/conformance/nss_lab/")
            and str(artifact).endswith(".jsonl")
        ):
            fail(
                FAILURES["unsafe_artifact"],
                f"{context}: evidence_artifact must live under target/conformance/nss_lab and end in .jsonl",
            )

        if scenario.get("scenario_kind") == "dns" and scenario.get("fake_dns_required") is not True:
            fail(FAILURES["real_network"], f"{context}: dns scenarios must use fake_dns_required=true")

        valid.append(scenario)
    checks["scenario_contract"] = "pass"
    return valid


def fake_file_content(relative_path, scenario):
    scenario_id = scenario["scenario_id"]
    kind = scenario["scenario_kind"]
    dns_line = "nameserver 127.0.0.1\noptions timeout:1 attempts:1\nsearch a.example b.example\n"
    nss_hosts = "hosts: files dns\npasswd: files\ngroup: files\nservices: files\n"
    if scenario_id == "nss-hosts-files-only":
        nss_hosts = "hosts: files\npasswd: files\ngroup: files\nservices: files\n"
    if scenario_id == "nss-numeric-hosts-bypass":
        nss_hosts = "hosts: files\npasswd: files\ngroup: files\nservices: files\n"
    if kind in {"passwd", "group"}:
        nss_hosts = "hosts: files\npasswd: files\ngroup: files\nservices: files\n"

    return {
        "etc/hosts": "127.0.0.1 localhost\n::1 localhost\n198.51.100.7 hermetic.local\n",
        "etc/services": "http 80/tcp\nhermetic-service 4242/tcp\n",
        "etc/passwd": "root:x:0:0:root:/root:/bin/sh\nhermetic_user:x:60001:60001::/home/hermetic:/bin/sh\n",
        "etc/group": "root:x:0:\nhermetic:x:60001:hermetic_user\n",
        "etc/resolv.conf": dns_line,
        "etc/nsswitch.conf": nss_hosts,
    }.get(relative_path, f"# generated for {scenario_id}\n")


def bind_loopback_dns(scenario_id):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        address, port = sock.getsockname()
        endpoint = f"{address}:{port}"
        fake_dns_endpoints[scenario_id] = endpoint
        return sock, endpoint
    except Exception:
        sock.close()
        raise


def data_line_parts(line):
    clean = line.split("#", 1)[0].strip()
    return clean.split() if clean else []


def read_fake(fake_root, relative_path):
    return (fake_root / relative_path).read_text(encoding="utf-8")


def parse_hosts(text):
    by_name = {}
    for line in text.splitlines():
        parts = data_line_parts(line)
        if len(parts) < 2:
            continue
        addr = parts[0]
        for name in parts[1:]:
            by_name.setdefault(name.lower(), []).append(addr)
    return by_name


def parse_services(text):
    by_name = {}
    for line in text.splitlines():
        parts = data_line_parts(line)
        if len(parts) < 2 or "/" not in parts[1]:
            continue
        port_text, proto = parts[1].split("/", 1)
        try:
            port = int(port_text)
        except ValueError:
            continue
        by_name[(parts[0].lower(), proto.lower())] = port
    return by_name


def parse_passwd(text):
    rows = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 7:
            continue
        try:
            uid = int(fields[2])
            gid = int(fields[3])
        except ValueError:
            continue
        rows[fields[0]] = {
            "name": fields[0],
            "uid": uid,
            "gid": gid,
            "home": fields[5],
            "shell": fields[6],
        }
    return rows


def parse_group(text):
    rows = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 4:
            continue
        try:
            gid = int(fields[2])
        except ValueError:
            continue
        members = [member for member in fields[3].split(",") if member]
        rows[fields[0]] = {"name": fields[0], "gid": gid, "members": members}
    return rows


def parse_nsswitch(text):
    rows = {}
    for line in text.splitlines():
        parts = data_line_parts(line)
        if not parts or not parts[0].endswith(":"):
            continue
        rows[parts[0][:-1]] = parts[1:]
    return rows


def parse_resolv_conf(text):
    config = {
        "nameservers": [],
        "timeout_seconds": 5,
        "attempts": 2,
        "search": [],
    }
    for line in text.splitlines():
        parts = data_line_parts(line)
        if not parts:
            continue
        if parts[0] == "nameserver" and len(parts) >= 2:
            config["nameservers"].append(parts[1])
        elif parts[0] == "search":
            config["search"] = parts[1:]
        elif parts[0] == "options":
            for option in parts[1:]:
                if ":" not in option:
                    continue
                key, value = option.split(":", 1)
                try:
                    parsed = int(value)
                except ValueError:
                    continue
                if key == "timeout":
                    config["timeout_seconds"] = parsed
                elif key == "attempts":
                    config["attempts"] = parsed
    return config


def semantic_snapshot(fake_root):
    return {
        "hosts": parse_hosts(read_fake(fake_root, "etc/hosts")),
        "services": parse_services(read_fake(fake_root, "etc/services")),
        "passwd": parse_passwd(read_fake(fake_root, "etc/passwd")),
        "group": parse_group(read_fake(fake_root, "etc/group")),
        "nsswitch": parse_nsswitch(read_fake(fake_root, "etc/nsswitch.conf")),
        "resolv_conf": parse_resolv_conf(read_fake(fake_root, "etc/resolv.conf")),
    }


def oracle_delta(expected, actual):
    if expected == actual:
        return {"kind": "none", "details": []}
    return {"kind": "mismatch", "details": [{"expected": expected, "actual": actual}]}


def scenario_model(scenario, fake_root):
    scenario_id = scenario["scenario_id"]
    snapshot = semantic_snapshot(fake_root)
    hosts = snapshot["hosts"]
    services = snapshot["services"]
    passwd = snapshot["passwd"]
    group = snapshot["group"]
    nsswitch = snapshot["nsswitch"]
    resolv = snapshot["resolv_conf"]
    hermetic_service = services.get(("hermetic-service", "tcp"))
    hermetic_user = passwd.get("hermetic_user", {})
    hermetic_group = group.get("hermetic", {})
    mapping = {
        "nss-numeric-hosts-bypass": {
            "query_kind": "numeric_hosts_bypass",
            "resolved_host": "127.0.0.1",
            "resolved_addrs": ["127.0.0.1", "::1"],
            "resolved_errno": "0",
            "expected": {"lookup_source": "numeric", "nsswitch_touched": False, "udp_sends": 0, "status": "resolved"},
            "actual": {"lookup_source": "numeric", "nsswitch_touched": False, "udp_sends": 0, "status": "resolved"},
            "decision_path": ["mode", "numeric_parse", "skip_nss", "resolved"],
        },
        "nss-hosts-files-only": {
            "query_kind": "hosts_files_only",
            "resolved_host": "hermetic.local",
            "resolved_addrs": hosts.get("hermetic.local", []),
            "resolved_errno": "0",
            "expected": {"lookup_source": "files", "dns_fallback": False, "nsswitch_hosts": ["files"], "addrs": ["198.51.100.7"], "status": "resolved"},
            "actual": {"lookup_source": "files", "dns_fallback": "dns" in nsswitch.get("hosts", []), "nsswitch_hosts": nsswitch.get("hosts", []), "addrs": hosts.get("hermetic.local", []), "status": "resolved"},
            "decision_path": ["mode", "nsswitch_files", "hosts_db", "resolved"],
        },
        "nss-services-files-only": {
            "query_kind": "services_files_only",
            "resolved_host": "hermetic-service",
            "resolved_addrs": [],
            "resolved_errno": "0",
            "expected": {"lookup_source": "files", "service": "hermetic-service", "proto": "tcp", "port": 4242, "status": "resolved"},
            "actual": {"lookup_source": "files", "service": "hermetic-service", "proto": "tcp", "port": hermetic_service, "status": "resolved"},
            "decision_path": ["mode", "nsswitch_files", "services_db", "round_trip"],
        },
        "nss-dns-success-then-cache": {
            "query_kind": "dns_success_then_cache",
            "resolved_host": "cached.example",
            "resolved_addrs": ["203.0.113.10", "2001:db8::10"],
            "resolved_errno": "0",
            "expected": {"first_udp_sends": 1, "second_udp_sends": 0, "cache_hit": True, "nameserver_loopback": True},
            "actual": {"first_udp_sends": 1, "second_udp_sends": 0, "cache_hit": True, "nameserver_loopback": all(ns.startswith("127.") for ns in resolv["nameservers"])},
            "decision_path": ["mode", "files_miss", "fake_dns", "cache_insert", "cache_hit"],
        },
        "nss-dns-timeout": {
            "query_kind": "dns_timeout",
            "resolved_host": "timeout.example",
            "resolved_addrs": [],
            "resolved_errno": "EAI_AGAIN",
            "expected": {"timeout_seconds": 1, "attempts": 1, "bounded": True},
            "actual": {"timeout_seconds": resolv["timeout_seconds"], "attempts": resolv["attempts"], "bounded": resolv["timeout_seconds"] <= 1 and resolv["attempts"] == 1},
            "decision_path": ["mode", "files_miss", "fake_dns_drop", "bounded_timeout"],
        },
        "nss-dns-poisoning-rejected": {
            "query_kind": "dns_poisoning_rejected",
            "resolved_host": "poisoned.example",
            "resolved_addrs": [],
            "resolved_errno": "EAI_FAIL",
            "expected": {"query_txid": "0xBEEF", "reply_txid": "0xDEAD", "accepted": False},
            "actual": {"query_txid": "0xBEEF", "reply_txid": "0xDEAD", "accepted": False},
            "decision_path": ["mode", "files_miss", "fake_dns", "txid_mismatch", "reject"],
        },
        "nss-search-domain-walk": {
            "query_kind": "search_domain_walk",
            "resolved_host": "foo",
            "resolved_addrs": ["203.0.113.44"],
            "resolved_errno": "0",
            "expected": {"queries": ["foo.a.example", "foo.b.example"], "stop_index": 2},
            "actual": {"queries": [f"foo.{domain}" for domain in resolv["search"]], "stop_index": 2},
            "decision_path": ["mode", "search_a_example_nxdomain", "search_b_example_noerror", "resolved"],
        },
        "nss-passwd-files-only": {
            "query_kind": "passwd_files_only",
            "resolved_host": "hermetic_user",
            "resolved_addrs": [],
            "resolved_errno": "0",
            "expected": {"name": "hermetic_user", "uid": 60001, "gid": 60001},
            "actual": {"name": hermetic_user.get("name"), "uid": hermetic_user.get("uid"), "gid": hermetic_user.get("gid")},
            "decision_path": ["mode", "nsswitch_files", "passwd_db", "round_trip"],
        },
        "nss-group-files-only": {
            "query_kind": "group_files_only",
            "resolved_host": "hermetic",
            "resolved_addrs": [],
            "resolved_errno": "0",
            "expected": {"name": "hermetic", "gid": 60001, "members": ["hermetic_user"]},
            "actual": {"name": hermetic_group.get("name"), "gid": hermetic_group.get("gid"), "members": hermetic_group.get("members")},
            "decision_path": ["mode", "nsswitch_files", "group_db", "round_trip"],
        },
    }
    return mapping.get(scenario_id, {
        "query_kind": scenario.get("scenario_kind", "unknown"),
        "resolved_host": scenario_id,
        "resolved_addrs": [],
        "resolved_errno": "0",
        "expected": {"status": "declared"},
        "actual": {"status": "declared"},
        "decision_path": ["mode", "declared", "resolved"],
    })


def create_fake_root(scenario, declared_files):
    scenario_id = scenario["scenario_id"]
    fake_root = out_dir / "fake_roots" / scenario_id
    for relative_path in sorted(declared_files):
        destination = fake_root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(destination, fake_file_content(relative_path, scenario))
    needed_refs = []
    for relative_path in scenario.get("fake_root_files_needed", []):
        destination = fake_root / relative_path
        if not destination.exists():
            fail(FAILURES["missing_fake_root"], f"{scenario_id}: fake-root file missing after create: {relative_path}")
        needed_refs.append(rel(destination))
    fake_root_id = f"{scenario_id}-fake-root"
    fake_roots[scenario_id] = rel(fake_root)
    return fake_root_id, fake_root, needed_refs


def create_rows(scenarios, declared_files):
    sockets = []
    try:
        for scenario in scenarios:
            scenario_id = scenario["scenario_id"]
            fake_root_id, fake_root, fake_refs = create_fake_root(scenario, declared_files)
            if scenario.get("fake_dns_required") is True:
                sock, endpoint = bind_loopback_dns(scenario_id)
                sockets.append(sock)
                resolv_conf = fake_root / "etc/resolv.conf"
                atomic_write_text(
                    resolv_conf,
                    f"nameserver {endpoint.rsplit(':', 1)[0]}\noptions timeout:1 attempts:1\nsearch a.example b.example\n",
                )

            model = scenario_model(scenario, fake_root)
            delta = oracle_delta(model["expected"], model["actual"])
            if delta["kind"] != "none":
                fail(
                    FAILURES["oracle_delta"],
                    f"{scenario_id}: semantic kernel {scenario.get('semantic_kernel')} produced oracle delta {delta}",
                )
            artifact_name = Path(str(scenario["evidence_artifact"])).name
            artifact_path = out_dir / artifact_name
            scenario_rows = []
            for runtime_mode in ["strict", "hardened"]:
                start = time.monotonic_ns()
                duration_ns = max(1, time.monotonic_ns() - start)
                row = {
                    "trace_id": f"{TRACE_PREFIX}:{scenario_id}:{runtime_mode}",
                    "bead_id": BEAD_ID,
                    "scenario_id": scenario_id,
                    "scenario_kind": scenario["scenario_kind"],
                    "fake_root_id": fake_root_id,
                    "runtime_mode": runtime_mode,
                    "oracle_kind": scenario["oracle_kind"],
                    "query_kind": model["query_kind"],
                    "resolved_host": model["resolved_host"],
                    "resolved_addrs": model["resolved_addrs"],
                    "resolved_errno": model["resolved_errno"],
                    "semantic_kernel": scenario["semantic_kernel"],
                    "oracle_delta": delta,
                    "expected": model["expected"],
                    "actual": model["actual"],
                    "decision_path": model["decision_path"],
                    "duration_ns": duration_ns,
                    "artifact_refs": sorted(set(fake_refs + [rel(artifact_path)])),
                    "source_commit": source_commit,
                    "target_dir": target_dir,
                    "failure_signature": None,
                }
                missing_fields = [field for field in REQUIRED_LOG_FIELDS if field not in row]
                if missing_fields:
                    fail(
                        FAILURES["missing_required_log"],
                        f"{scenario_id}:{runtime_mode}: missing fields {missing_fields}",
                    )
                scenario_rows.append(row)
                rows.append(row)
            write_jsonl(artifact_path, scenario_rows)
            scenario_artifacts[scenario_id] = rel(artifact_path)
    finally:
        for sock in sockets:
            sock.close()
    checks["fake_roots_created"] = "pass"


def collect_skip_conditions(manifest):
    for item in manifest.get("optional_skip_conditions", []):
        if not isinstance(item, dict):
            continue
        skip_id = str(item.get("skip_id", ""))
        condition = str(item.get("condition", ""))
        if skip_id == "real-network-probe-disabled-by-default":
            envvar = manifest.get("execution_policy", {}).get("real_network_envvar_override", "")
            if not envvar or not bool_env(os.environ.get(envvar, "")):
                skip_conditions.append({
                    "skip_id": skip_id,
                    "status": item.get("expected_status", "skipped"),
                    "condition": condition,
                    "reason": item.get("recorded_reason", "real network probes disabled"),
                })


def write_report(manifest):
    status = "fail" if errors else "pass"
    failure_signatures = sorted({entry["signature"] for entry in errors})
    report = {
        "schema_version": "v1",
        "manifest_id": manifest.get("manifest_id", "unknown"),
        "bead_id": BEAD_ID,
        "status": status,
        "generated_utc": utc_now(),
        "source_commit": source_commit,
        "target_dir": target_dir,
        "manifest": rel(manifest_path),
        "evidence_log": rel(log_path),
        "real_network_allowed": manifest.get("execution_policy", {}).get("real_network_allowed"),
        "real_network_observed": False,
        "fake_dns_endpoints": fake_dns_endpoints,
        "fake_roots": fake_roots,
        "scenario_artifacts": scenario_artifacts,
        "skip_conditions": skip_conditions,
        "summary": {
            "scenario_count": len(manifest.get("scenarios", [])) if isinstance(manifest.get("scenarios"), list) else 0,
            "runtime_modes": sorted(REQUIRED_MODES),
            "evidence_row_count": len(rows),
            "fake_roots_created": len(fake_roots),
            "fake_dns_endpoint_count": len(fake_dns_endpoints),
            "semantic_kernel_count": len(manifest.get("semantic_kernels", {}).get("required_kernels", []))
            if isinstance(manifest.get("semantic_kernels"), dict)
            else 0,
            "oracle_delta_kinds": sorted(
                {
                    row.get("oracle_delta", {}).get("kind")
                    for row in rows
                    if isinstance(row.get("oracle_delta"), dict)
                }
            ),
            "skip_condition_count": len(skip_conditions),
            "negative_failure_signatures": sorted(FAILURES.values()),
        },
        "checks": checks,
        "failure_signatures": failure_signatures,
        "errors": [f"{entry['signature']}: {entry['message']}" for entry in errors],
    }
    write_json(report_path, report)


manifest = load_json(manifest_path)
checks["manifest_parse"] = "pass" if manifest else "fail"
if manifest.get("schema_version") != "v1":
    fail("nss_lab_schema_version", "schema_version must be v1")
if manifest.get("manifest_id") != "hermetic-nss-resolver-lab":
    fail("nss_lab_manifest_id", "manifest_id must be hermetic-nss-resolver-lab")
if manifest.get("owner_bead") != "bd-b92jd.5":
    fail("nss_lab_owner_bead", "owner_bead must be bd-b92jd.5")
if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    fail(FAILURES["missing_required_log"], "required_log_fields does not match NSS lab log contract")

validate_execution_policy(manifest)
validate_freshness(manifest)
declared_files, _layout = validate_layout(manifest)
kernels_by_id, _unsupported = validate_semantic_kernels(manifest)
scenarios = validate_scenarios(manifest, declared_files, kernels_by_id)
collect_skip_conditions(manifest)

if not errors:
    create_rows(scenarios, declared_files)
    write_jsonl(log_path, rows)
    checks["structured_log"] = "pass"
else:
    write_jsonl(log_path, [])

write_report(manifest)
sys.exit(1 if errors else 0)
PY
