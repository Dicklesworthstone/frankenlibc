#!/usr/bin/env bash
# check_docs_semantic_claims.sh -- CI gate for bd-bp8fl.1.4
#
# Validates that README.md and FEATURE_PARITY.md keep support taxonomy,
# semantic parity, oracle precedence, and replacement-level claims separate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FLC_DOCS_SEMANTIC_ARTIFACT:-${ROOT}/tests/conformance/docs_semantic_claims.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/docs_semantic_claims.report.json"
LOG="${OUT_DIR}/docs_semantic_claims.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" <<'PY'
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

errors = []
checks = {}
events = []
forbidden_claims = []

def rel(path):
    path = Path(path)
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)

def resolve_path(value):
    path = Path(value)
    if path.is_absolute():
        return path
    return root / path

def load_json(path, label):
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        errors.append(f"{label}: failed to parse {path}: {exc}")
        return None

def read_text(path, label):
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{label}: failed to read {path}: {exc}")
        return ""

def file_sha256(path):
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return None

def source_identity():
    declared = os.environ.get("RCH_BUILD_SOURCE")
    if declared is not None:
        commit = declared.removesuffix("-dirty")
        if re.fullmatch(r"[0-9a-f]{40}", commit):
            return commit, None
        return "unknown", "RCH_BUILD_SOURCE must be a full source object ID, optionally followed by -dirty"
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        if re.fullmatch(r"[0-9a-f]{40}", commit):
            return commit, None
        return "unknown", "git HEAD did not report a full source object ID"
    except (OSError, subprocess.CalledProcessError) as exc:
        return "unknown", f"source identity unavailable: {exc}"

artifact = load_json(artifact_path, "artifact") or {}
inputs = artifact.get("inputs", {})
evidence_refs = sorted(str(value) for value in inputs.values())
source_commit, source_identity_error = source_identity()
trace_seed = "|".join(
    [
        artifact.get("bead", "bd-bp8fl.1.4"),
        source_commit,
        str(file_sha256(artifact_path) or "missing"),
    ]
)
trace_id = hashlib.sha256(trace_seed.encode("utf-8")).hexdigest()[:20]

def event(rule, doc_surface="", symbol_or_section="", previous_claim="", generated_claim="", failure_signature="", status="pass"):
    row = {
        "trace_id": trace_id,
        "bead_id": artifact.get("bead", "bd-bp8fl.1.4"),
        "doc_surface": doc_surface,
        "symbol_or_section": symbol_or_section,
        "previous_claim": previous_claim,
        "generated_claim": generated_claim,
        "evidence_refs": evidence_refs,
        "source_commit": source_commit,
        "failure_signature": failure_signature,
        "status": status,
        "rule_id": rule,
    }
    events.append(row)
    return row

def fail(rule, message, doc_surface="", symbol_or_section="", previous_claim="", generated_claim="", failure_signature=""):
    errors.append(message)
    event(
        rule,
        doc_surface=doc_surface,
        symbol_or_section=symbol_or_section,
        previous_claim=previous_claim,
        generated_claim=generated_claim,
        failure_signature=failure_signature or rule,
        status="fail",
    )

if source_identity_error:
    checks["source_identity"] = "fail"
    fail("source_identity", source_identity_error, failure_signature="unproven_source_identity")
else:
    checks["source_identity"] = "pass"
    event("source_identity", generated_claim=source_commit)

def env_path(name, key):
    override = os.environ.get(name)
    if override:
        return resolve_path(override)
    return resolve_path(inputs.get(key, f"__missing_input__/{key}"))

readme_path = env_path("FLC_DOCS_SEMANTIC_README", "readme")
feature_path = env_path("FLC_DOCS_SEMANTIC_FEATURE_PARITY", "feature_parity")
deployment_path = env_path("FLC_DOCS_SEMANTIC_DEPLOYMENT", "deployment")
security_path = env_path("FLC_DOCS_SEMANTIC_SECURITY", "security")
compatibility_path = env_path("FLC_DOCS_SEMANTIC_COMPATIBILITY", "compatibility")
parity_coverage_path = env_path("FLC_DOCS_SEMANTIC_PARITY_COVERAGE", "parity_coverage")
support_path = env_path("FLC_DOCS_SEMANTIC_SUPPORT_MATRIX", "support_matrix")
overlay_path = env_path("FLC_DOCS_SEMANTIC_OVERLAY", "support_semantic_overlay")
inventory_path = env_path("FLC_DOCS_SEMANTIC_INVENTORY", "semantic_contract_inventory")
join_path = env_path("FLC_DOCS_SEMANTIC_JOIN", "semantic_contract_symbol_join")
oracle_path = env_path("FLC_DOCS_SEMANTIC_ORACLE", "oracle_precedence")
replacement_path = env_path("FLC_DOCS_SEMANTIC_REPLACEMENT_LEVELS", "replacement_levels")
plan_path = resolve_path(os.environ.get("FLC_DOCS_SEMANTIC_PLAN", "PLAN_TO_PORT_GLIBC_TO_RUST.md"))
core_lib_path = resolve_path(os.environ.get("FLC_DOCS_SEMANTIC_CORE_LIB_RS", "crates/frankenlibc-core/src/lib.rs"))
core_src_dir = resolve_path(os.environ.get("FLC_DOCS_SEMANTIC_CORE_SRC_DIR", "crates/frankenlibc-core/src"))
beads_jsonl_override = os.environ.get("FLC_DOCS_SEMANTIC_BEADS_JSONL")
beads_jsonl_path = resolve_path(beads_jsonl_override) if beads_jsonl_override else resolve_path(".beads/issues.jsonl")
reality_report_path = resolve_path(os.environ.get("FLC_DOCS_SEMANTIC_REALITY_REPORT", "tests/conformance/reality_report.v1.json"))
smoke_path = resolve_path(os.environ.get("FLC_DOCS_SEMANTIC_SMOKE_SUMMARY", "tests/conformance/ld_preload_smoke_summary.v1.json"))

support = load_json(support_path, "support_matrix")
overlay = load_json(overlay_path, "support_semantic_overlay")
inventory = load_json(inventory_path, "semantic_contract_inventory")
join = load_json(join_path, "semantic_contract_symbol_join")
oracle = load_json(oracle_path, "oracle_precedence")
replacement = load_json(replacement_path, "replacement_levels")

if all(value is not None for value in [artifact, support, overlay, inventory, join, oracle, replacement]):
    checks["json_parse"] = "pass"
else:
    checks["json_parse"] = "fail"

required_inputs = {
    "readme",
    "feature_parity",
    "support_matrix",
    "support_semantic_overlay",
    "semantic_contract_inventory",
    "semantic_contract_symbol_join",
    "oracle_precedence",
    "replacement_levels",
}
required_log_fields = [
    "trace_id",
    "bead_id",
    "doc_surface",
    "symbol_or_section",
    "previous_claim",
    "generated_claim",
    "evidence_refs",
    "source_commit",
    "failure_signature",
]
if (
    artifact.get("schema_version") == "v1"
    and artifact.get("bead") == "bd-bp8fl.1.4"
    and required_inputs <= set(inputs)
    and artifact.get("required_log_fields") == required_log_fields
    and len(artifact.get("required_claim_fields", [])) >= 8
):
    checks["artifact_shape"] = "pass"
    event("artifact_shape", generated_claim="docs semantic claim manifest is complete")
else:
    checks["artifact_shape"] = "fail"
    fail(
        "artifact_shape",
        "artifact must declare schema_version=v1, bead=bd-bp8fl.1.4, required inputs, claim fields, and log fields",
        generated_claim="manifest shape mismatch",
        failure_signature="artifact_shape",
    )

docs = {
    "README": (readme_path, read_text(readme_path, "README")),
    "FEATURE_PARITY": (feature_path, read_text(feature_path, "FEATURE_PARITY")),
}
operator_docs = {
    "DEPLOYMENT": (deployment_path, read_text(deployment_path, "DEPLOYMENT")),
    "SECURITY": (security_path, read_text(security_path, "SECURITY")),
    "COMPATIBILITY": (compatibility_path, read_text(compatibility_path, "COMPATIBILITY")),
    "PARITY_COVERAGE": (parity_coverage_path, read_text(parity_coverage_path, "PARITY_COVERAGE")),
}
all_docs = {**docs, **operator_docs}
plan_text = read_text(plan_path, "PLAN_TO_PORT_GLIBC_TO_RUST")
core_lib_text = read_text(core_lib_path, "CORE_LIB_RS")
extended_docs = {
    **all_docs,
    "PLAN_TO_PORT_GLIBC_TO_RUST": (plan_path, plan_text),
    "CORE_LIB_RS": (core_lib_path, core_lib_text),
}

readme_text = docs["README"][1]
feature_text = docs["FEATURE_PARITY"][1]
parity_coverage_text = operator_docs["PARITY_COVERAGE"][1]

def count_lines(path):
    try:
        with path.open("r", encoding="utf-8") as fh:
            return sum(1 for _ in fh)
    except Exception as exc:
        errors.append(f"numeric claims: failed to count lines in {path}: {exc}")
        return -1

def tracked_files(pathspec):
    if (root / ".git").exists() and ".rch-target" not in os.environ.get("CARGO_TARGET_DIR", ""):
        try:
            output = subprocess.check_output(
                ["git", "ls-files", "-z", "--", pathspec],
                cwd=root,
                stderr=subprocess.DEVNULL,
            )
            return sorted(
                root / os.fsdecode(raw_path)
                for raw_path in output.split(b"\0")
                if raw_path
            )
        except Exception:
            pass
    try:
        glob_pat = pathspec.removeprefix(":(glob)")
        return sorted(
            path
            for path in root.glob(glob_pat)
            if (path.is_file() or path.is_symlink())
            and not path.name.startswith("zz_")
            and "target" not in path.parts
            and "c_probes" not in path.parts
        )
    except Exception as exc:
        errors.append(f"numeric claims: failed to list tracked files for {pathspec}: {exc}")
        return []

numeric_claims = []

def expect_numeric_claim(surface, claim_id, expected):
    text = all_docs[surface][1]
    numeric_claims.append((surface, claim_id, expected))
    if expected not in text:
        fail(
            "numeric_claim_freshness",
            f"{surface}: missing current numeric claim {claim_id}: {expected}",
            doc_surface=surface,
            symbol_or_section=claim_id,
            generated_claim=expected,
            failure_signature="stale_numeric_claim",
        )

completion_paths = tracked_files(":(glob)tests/conformance/*completion_contract*.json")
cli_contract_paths = tracked_files(":(glob)tests/conformance/*cli_contract*.json")
fixture_paths = tracked_files(":(glob)tests/conformance/fixtures/*.json")
completion_count = len(completion_paths)
cli_contract_count = len(cli_contract_paths)
fixture_families = set()
for fixture_path in fixture_paths:
    fixture = load_json(fixture_path, f"numeric fixture {rel(fixture_path)}")
    if isinstance(fixture, dict) and fixture.get("family"):
        fixture_families.add(str(fixture["family"]))

fuzz_target_paths = tracked_files(":(glob)crates/frankenlibc-fuzz/fuzz_targets/*.rs")
proof_note_paths = tracked_files(":(glob)docs/proofs/*.md")
crate_rust_paths = tracked_files(":(glob)crates/**/*.rs")
abi_rust_paths = tracked_files(":(glob)crates/frankenlibc-abi/src/**/*.rs")
membrane_rust_paths = tracked_files(":(glob)crates/frankenlibc-membrane/src/**/*.rs")
core_rust_paths = tracked_files(":(glob)crates/frankenlibc-core/src/**/*.rs")
runtime_math_paths = tracked_files(":(glob)crates/frankenlibc-membrane/src/runtime_math/*.rs")
integration_c_paths = tracked_files(":(glob)tests/integration/**/*.c")
scripts_paths = tracked_files(":(glob)scripts/*")
fuzz_target_count = len(fuzz_target_paths)
proof_note_count = len(proof_note_paths)
crate_rust_count = len(crate_rust_paths)
abi_rust_count = len(abi_rust_paths)
membrane_rust_count = len(membrane_rust_paths)
core_rust_count = len(core_rust_paths)
runtime_math_count = len(runtime_math_paths)
integration_c_count = len(integration_c_paths)
scripts_file_count = len(scripts_paths)
abi_line_count = sum(count_lines(path) for path in abi_rust_paths)
membrane_line_count = sum(count_lines(path) for path in membrane_rust_paths)
core_line_count = sum(count_lines(path) for path in core_rust_paths)

expect_numeric_claim(
    "README",
    "fixture_counts",
    f"**{len(fixture_paths)} fixture JSONs covering {len(fixture_families)} distinct `family` values**",
)
expect_numeric_claim("README", "completion_contract_count", f"**{completion_count} completion-contract artifacts**")
expect_numeric_claim("README", "cli_contract_count", f"**{cli_contract_count} CLI-contract manifests**")
expect_numeric_claim("README", "fuzz_target_count", f"**{fuzz_target_count} `cargo-fuzz` targets**")
expect_numeric_claim("README", "proof_note_count", f"and {proof_note_count} proof notes / obligation mappings")
expect_numeric_claim("README", "crate_rust_count", f"| Tracked Rust files in `crates/` | {crate_rust_count:,} |")
expect_numeric_claim(
    "README",
    "abi_source_size",
    f"| `crates/frankenlibc-abi/src/` | {abi_rust_count} Rust files, {abi_line_count:,} lines |",
)
expect_numeric_claim(
    "README",
    "membrane_source_size",
    f"| `crates/frankenlibc-membrane/src/` | {membrane_rust_count} Rust files, {membrane_line_count:,} lines |",
)
expect_numeric_claim(
    "README",
    "core_source_size",
    f"| `crates/frankenlibc-core/src/` | {core_rust_count} Rust files, {core_line_count:,} lines including generated codec tables |",
)
expect_numeric_claim("README", "runtime_math_count", f"| Runtime math controllers | {runtime_math_count} modules |")
expect_numeric_claim("README", "integration_c_count", f"| C integration fixtures | {integration_c_count} |")
expect_numeric_claim("README", "scripts_file_count", f"| Top-level shell/scripts files | {scripts_file_count} files under `scripts/` |")
expect_numeric_claim(
    "README",
    "startup_source_lines",
    f"( {count_lines(root / 'crates/frankenlibc-abi/src/startup_abi.rs'):,} lines at this snapshot)".replace("( ", "("),
)
expect_numeric_claim(
    "README",
    "membrane_build_lines",
    f"`crates/frankenlibc-membrane/build.rs` is {count_lines(root / 'crates/frankenlibc-membrane/build.rs'):,} lines at this snapshot",
)
expect_numeric_claim(
    "README",
    "version_script_lines",
    f"| GNU ld version script | {count_lines(root / 'crates/frankenlibc-abi/version_scripts/libc.map'):,} lines, `GLIBC_2.2.5` |",
)

toolchain_text = read_text(root / "rust-toolchain.toml", "rust-toolchain")
toolchain_match = re.search(r'^channel\s*=\s*"([^"]+)"', toolchain_text, flags=re.MULTILINE)
if toolchain_match:
    expect_numeric_claim("README", "rust_toolchain", f"`{toolchain_match.group(1)}`")
else:
    fail(
        "numeric_claim_freshness",
        "rust-toolchain.toml does not declare a channel",
        symbol_or_section="rust_toolchain",
        failure_signature="missing_toolchain_channel",
    )

smoke = load_json(smoke_path, "smoke summary")
if isinstance(smoke, dict):
    smoke_summary = smoke.get("summary", {})
    smoke_commit = str(smoke.get("source_commit", ""))
    expect_numeric_claim("README", "smoke_run_id", f"run `{smoke.get('run_id')}`")
    expect_numeric_claim("README", "smoke_checked_date", str(smoke.get("checked_date_display", "")))
    expect_numeric_claim("README", "smoke_source_commit", f"source commit `{smoke_commit[:8]}…`")
    expect_numeric_claim(
        "README",
        "smoke_summary",
        f"{smoke_summary.get('passes')} pass / {smoke_summary.get('fails')} fail / {smoke_summary.get('skips')} optional skips across strict and hardened modes, plus {smoke_summary.get('xfails')} xfail",
    )
    for mode_name in ("strict", "hardened"):
        mode = smoke.get("modes", {}).get(mode_name, {})
        expect_numeric_claim(
            "README",
            f"smoke_{mode_name}_row",
            f"| `{mode_name}` | {mode.get('passes')} | {mode.get('fails')} | {mode.get('skips')} | {mode.get('xfails')} |",
        )

if isinstance(support, dict):
    support_summary = support.get("summary", {})
    expect_numeric_claim(
        "README",
        "support_taxonomy_counts",
        f"**{support_summary.get('implemented'):,} `Implemented` + {support_summary.get('raw_syscall'):,} `RawSyscall` = {support_summary.get('implemented') + support_summary.get('raw_syscall'):,} / {support_summary.get('total'):,}",
    )
    generated_date = str(support.get("generated_at_utc", ""))[:10]
    expect_numeric_claim("FEATURE_PARITY", "support_snapshot_date", f"`generated_at_utc` is {generated_date}")
    expect_numeric_claim(
        "PARITY_COVERAGE",
        "parity_coverage_native_subset",
        f"**Native-classified:** {support_summary.get('implemented') + support_summary.get('raw_syscall'):,} symbols (`Implemented + RawSyscall`).",
    )
    expect_numeric_claim(
        "PARITY_COVERAGE",
        "parity_coverage_implemented_row",
        f"| Implemented | {support_summary.get('implemented')} |",
    )
    expect_numeric_claim(
        "PARITY_COVERAGE",
        "parity_coverage_raw_syscall_row",
        f"| RawSyscall | {support_summary.get('raw_syscall')} |",
    )
    expect_numeric_claim(
        "PARITY_COVERAGE",
        "parity_coverage_wraps_host_row",
        f"| WrapsHostLibc | {support_summary.get('wraps_host_libc')} |",
    )
    expect_numeric_claim(
        "PARITY_COVERAGE",
        "parity_coverage_stub_row",
        f"| Stub | {support_summary.get('stub')} |",
    )
    if isinstance(overlay, dict):
        overlay_counts = overlay.get("support_matrix_snapshot", {}).get("status_counts", {})
        support_counts = support.get("counts", {})
        status_map = {
            "Implemented": "implemented",
            "RawSyscall": "raw_syscall",
            "WrapsHostLibc": "wraps_host_libc",
            "GlibcCallThrough": "glibc_call_through",
            "Stub": "stub",
        }
        for key, count_key in status_map.items():
            if overlay_counts.get(key) != support_counts.get(count_key):
                fail(
                    "numeric_claim_freshness",
                    f"support_semantic_overlay: status_counts.{key}={overlay_counts.get(key)} does not match support_matrix.json counts.{count_key}={support_counts.get(count_key)}",
                    doc_surface="support_semantic_overlay",
                    symbol_or_section=f"status_counts.{key}",
                    previous_claim=str(overlay_counts.get(key)),
                    generated_claim=str(support_counts.get(count_key)),
                    failure_signature="stale_overlay_taxonomy_counts",
                )

stale_numeric_patterns = {
    "old_cli_contract_count": r"\b68 such manifests\b|\b68 CLI-contract",
    "old_completion_contract_count": r"\b258 completion-contract",
    "old_fixture_count": r"\b134 fixture",
    "old_c_fixture_count": r"\b17 C (?:test|integration)|\(17 fixtures\)",
    "old_membrane_build_size": r"\b1,030 lines\b",
    "old_smoke_total": r"\b60/0/4\b|\b60 pass(?:es)? / 0 fail(?:s)? / 4",
    "old_toolchain_pin": r"nightly-2026-04-28",
}
for surface, (_, text) in all_docs.items():
    for claim_id, pattern in stale_numeric_patterns.items():
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            fail(
                "numeric_claim_freshness",
                f"{surface}: stale numeric claim {claim_id}: {match.group(0)}",
                doc_surface=surface,
                symbol_or_section=claim_id,
                previous_claim=match.group(0),
                generated_claim="remove or replace with an artifact-derived current claim",
                failure_signature="stale_numeric_literal",
            )

numeric_failures = [row for row in events if row["rule_id"] == "numeric_claim_freshness" and row["status"] == "fail"]
checks["numeric_claim_freshness"] = "fail" if numeric_failures else "pass"
if not numeric_failures:
    event(
        "numeric_claim_freshness",
        generated_claim=f"{len(numeric_claims)} checked documentation counts match the working tree and evidence artifacts",
    )

field_ids = [str(row.get("id", "")) for row in artifact.get("required_claim_fields", [])]
doc_surfaces = {row.get("id"): row for row in artifact.get("doc_surfaces", [])}
operator_surfaces = {row.get("id"): row for row in artifact.get("operator_guide_surfaces", [])}
missing_fields = []
missing_phrases = []
for surface_id, (path, text) in docs.items():
    surface = doc_surfaces.get(surface_id, {})
    section = surface.get("required_section", "")
    if section not in text:
        missing_phrases.append((surface_id, section))
        fail(
            "docs_claim_surface",
            f"{surface_id}: missing required section {section}",
            doc_surface=surface_id,
            symbol_or_section=section,
            generated_claim="missing required docs claim section",
            failure_signature="missing_docs_claim_section",
        )
    for field_id in field_ids:
        if f"`{field_id}`" not in text:
            missing_fields.append((surface_id, field_id))
            fail(
                "docs_claim_fields",
                f"{surface_id}: missing claim field {field_id}",
                doc_surface=surface_id,
                symbol_or_section=field_id,
                generated_claim="missing claim field",
                failure_signature="missing_claim_field",
            )
    for phrase in surface.get("required_phrases", []):
        if str(phrase) not in text:
            missing_phrases.append((surface_id, phrase))
            fail(
                "docs_claim_surface",
                f"{surface_id}: missing required phrase {phrase}",
                doc_surface=surface_id,
                symbol_or_section=phrase,
                generated_claim="missing evidence phrase",
                failure_signature="missing_evidence_phrase",
            )
    event(
        "docs_claim_surface",
        doc_surface=surface_id,
        symbol_or_section=section,
        generated_claim=f"{surface_id} declares semantic claim fields",
    )

missing_operator_phrases = []
for surface_id, (path, text) in operator_docs.items():
    surface = operator_surfaces.get(surface_id, {})
    section = surface.get("required_section", "")
    if section and section not in text:
        missing_operator_phrases.append((surface_id, section))
        fail(
            "operator_guides_surface",
            f"{surface_id}: missing required section {section}",
            doc_surface=surface_id,
            symbol_or_section=section,
            generated_claim="missing required operator guide section",
            failure_signature="missing_operator_guide_section",
        )
    for phrase in surface.get("required_phrases", []):
        if str(phrase) not in text:
            missing_operator_phrases.append((surface_id, phrase))
            fail(
                "operator_guides_surface",
                f"{surface_id}: missing required phrase {phrase}",
                doc_surface=surface_id,
                symbol_or_section=phrase,
                generated_claim="missing operator guide evidence phrase",
                failure_signature="missing_operator_guide_phrase",
            )
    event(
        "operator_guides_surface",
        doc_surface=surface_id,
        symbol_or_section=section,
        generated_claim=f"{surface_id} preserves canonical L0 and bounded safety scope",
    )

operator_failures = [row for row in events if row["rule_id"] == "operator_guides_surface" and row["status"] == "fail"]
checks["docs_claim_fields"] = "pass" if not missing_fields else "fail"
checks["docs_claim_surface"] = "pass" if not missing_phrases else "fail"
checks["operator_guides_surface"] = "pass" if not operator_failures else "fail"

required_readme_facts = [
    ("build_elf_script", "build_elf.rs"),
    ("fromfp_version_script", "version_scripts/fromfp.map"),
    ("abi_release_codegen_units", "[profile.release.package.frankenlibc-abi]"),
    ("nss_tuple_lookup", "tries `gethostbyname4_r` first (`nss_module.rs`)"),
    ("fingerprint_24byte_layout", "[hash:8][generation:8][size:8]"),
    ("canary_dual_key_siphash", "SipHash13(K_tail"),
    ("deployed_malloc_provider_separation", "deployed `malloc` in `crates/frankenlibc-abi/src/malloc_abi.rs` does not call this core slab/magazine model"),
    ("stdio_cancellation_admission", "retain their public caller's cancellation admission around the underlying raw syscall"),
]
for fact_id, needle in required_readme_facts:
    if needle not in readme_text:
        fail(
            "semantic_architecture_facts",
            f"README: missing required architectural fact {fact_id}: {needle}",
            doc_surface="README",
            symbol_or_section=fact_id,
            generated_claim=needle,
            failure_signature="missing_semantic_architecture_fact",
        )
arch_failures = [row for row in events if row["rule_id"] == "semantic_architecture_facts" and row["status"] == "fail"]
checks["semantic_architecture_facts"] = "pass" if not arch_failures else "fail"
if not arch_failures:
    event(
        "semantic_architecture_facts",
        doc_surface="README",
        generated_claim=f"{len(required_readme_facts)} source/build/provider semantic facts verified",
    )

for surface_id, (path, text) in all_docs.items():
    for line_no, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        for row in artifact.get("forbidden_claim_patterns", []):
            pattern = str(row.get("pattern", ""))
            try:
                matched = re.search(pattern, line, flags=re.IGNORECASE)
            except re.error as exc:
                fail(
                    "forbidden_claim_patterns",
                    f"invalid forbidden claim regex {row.get('id')}: {exc}",
                    doc_surface=surface_id,
                    symbol_or_section=row.get("id", ""),
                    failure_signature="invalid_forbidden_claim_regex",
                )
                continue
            if not matched:
                continue
            allowed = any(str(token).lower() in lowered for token in row.get("allowed_if_line_contains", []))
            if allowed:
                continue
            finding = {
                "doc_surface": surface_id,
                "file_path": f"{rel(path)}:{line_no}",
                "pattern_id": row.get("id"),
                "line": line.strip(),
            }
            forbidden_claims.append(finding)
            fail(
                "forbidden_claim_patterns",
                f"{surface_id}: forbidden claim {row.get('id')} at {rel(path)}:{line_no}",
                doc_surface=surface_id,
                symbol_or_section=row.get("id", ""),
                previous_claim=line.strip(),
                generated_claim="claim must be blocked unless backed by semantic parity evidence",
                failure_signature="forbidden_claim",
            )

checks["forbidden_claim_patterns"] = "pass" if not forbidden_claims else "fail"

# (a) Multi-occurrence & cross-guide smoke counts and support-taxonomy rollups
def is_dated_historical_line(line_text):
    lowered_line = line_text.lower()
    return any(tok in lowered_line for tok in ("historical", "superseded", "earlier ", "former "))

multi_guide_ok = True
stale_guide_tokens = [
    ("stale_sept_smoke_pass", "189 pass"),
    ("stale_sept_smoke_xfail", "1 xfail"),
    ("stale_sept_smoke_commit", "a8a4110b"),
    ("stale_nov_early_smoke_pass", "344 pass"),
    ("stale_nov_early_smoke_run", "20261111T045420Z"),
    ("stale_oct_smoke_pass", "310 pass"),
    ("stale_oct_smoke_commit", "7fafe5bee"),
    ("stale_plan_stub_count", "44 Stub"),
    ("stale_invalid_row_count", "1,085"),
    ("stale_orphaned_feature_sha", "b70205895"),
]
expected_smoke_tuple = None
if isinstance(smoke, dict) and isinstance(smoke.get("summary"), dict):
    sm = smoke["summary"]
    expected_smoke_tuple = (
        int(sm.get("passes", -1)),
        int(sm.get("fails", -1)),
        int(sm.get("skips", -1)),
    )

smoke_triplet_re = re.compile(
    r"(\d+)\s+pass(?:es)?\s*/\s*(\d+)\s+fail(?:s)?\s*/\s*(\d+)\s+(?:optional\s+)?skips?",
    flags=re.IGNORECASE,
)
for surface_id, (path, text) in extended_docs.items():
    for line_no, line in enumerate(text.splitlines(), start=1):
        if is_dated_historical_line(line):
            continue
        for token_id, token in stale_guide_tokens:
            if token.lower() in line.lower():
                multi_guide_ok = False
                fail(
                    "multi_guide_consistency",
                    f"{surface_id}: stale cross-guide claim {token_id} ({token!r}) at {rel(path)}:{line_no}",
                    doc_surface=surface_id,
                    symbol_or_section=token_id,
                    previous_claim=line.strip(),
                    generated_claim="must match current ld_preload_smoke_summary.v1.json and support_matrix.json",
                    failure_signature="cross_guide_smoke_drift",
                )
        if expected_smoke_tuple is not None:
            for match in smoke_triplet_re.finditer(line):
                observed = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
                if observed != expected_smoke_tuple:
                    multi_guide_ok = False
                    fail(
                        "multi_guide_consistency",
                        f"{surface_id}: smoke triplet {match.group(0)!r} at {rel(path)}:{line_no} contradicts canonical {expected_smoke_tuple}",
                        doc_surface=surface_id,
                        symbol_or_section="ld_preload_smoke_summary",
                        previous_claim=match.group(0),
                        generated_claim=f"{expected_smoke_tuple[0]} pass / {expected_smoke_tuple[1]} fail / {expected_smoke_tuple[2]} optional skips",
                        failure_signature="cross_guide_smoke_drift",
                    )

if isinstance(support, dict):
    sup_sum = support.get("summary", {})
    expected_plan_phrases = [
        ("plan_total_classified", f"{sup_sum.get('total'):,} exported symbols classified"),
        (
            "plan_native_rollup",
            f"{sup_sum.get('implemented'):,} Implemented + {sup_sum.get('raw_syscall'):,} RawSyscall = {sup_sum.get('implemented', 0) + sup_sum.get('raw_syscall', 0):,}",
        ),
        (
            "plan_non_native_rollup",
            f"{sup_sum.get('wraps_host_libc'):,} WrapsHostLibc, {sup_sum.get('glibc_call_through')} GlibcCallThrough, {sup_sum.get('stub')} Stub",
        ),
    ]
    for claim_id, phrase in expected_plan_phrases:
        if phrase not in plan_text:
            multi_guide_ok = False
            fail(
                "multi_guide_consistency",
                f"PLAN_TO_PORT_GLIBC_TO_RUST: missing current taxonomy rollup {claim_id}: {phrase}",
                doc_surface="PLAN_TO_PORT_GLIBC_TO_RUST",
                symbol_or_section=claim_id,
                generated_claim=phrase,
                failure_signature="cross_guide_taxonomy_drift",
            )
checks["multi_guide_consistency"] = "pass" if multi_guide_ok else "fail"
if multi_guide_ok:
    event(
        "multi_guide_consistency",
        generated_claim=f"all occurrences across {len(extended_docs)} surfaces agree on smoke and taxonomy counts",
    )

# (b) Multi-occurrence crate file/LOC table consistency in README.md
loc_ok = True
expected_crate_sizes = {
    "abi": (abi_rust_count, abi_line_count),
    "membrane": (membrane_rust_count, membrane_line_count),
    "core": (core_rust_count, core_line_count),
}
exact_src_row_re = re.compile(
    r"\|\s*`crates/frankenlibc-(abi|membrane|core)/src/`\s*\|\s*(\d+)\s+Rust files,\s*([\d,]+)\s+lines"
)
approx_crate_re = re.compile(
    r"(?:crates/)?`?frankenlibc-(abi|membrane|core)`?[^\n]*?(\d+)\s+Rust(?:\s+source)?\s+files(?:,\s*~(\d+(?:\.\d+)?)\s*(kLOC|MLOC))?"
)
for line_no, line in enumerate(readme_text.splitlines(), start=1):
    if is_dated_historical_line(line):
        continue
    for match in exact_src_row_re.finditer(line):
        crate_key = match.group(1)
        obs_files = int(match.group(2))
        obs_lines = int(match.group(3).replace(",", ""))
        exp_files, exp_lines = expected_crate_sizes[crate_key]
        if (obs_files, obs_lines) != (exp_files, exp_lines):
            loc_ok = False
            fail(
                "multi_occurrence_loc_consistency",
                f"README: crates/frankenlibc-{crate_key}/src/ row at line {line_no} reports ({obs_files} files, {obs_lines:,} lines) != ({exp_files} files, {exp_lines:,} lines)",
                doc_surface="README",
                symbol_or_section=f"crates/frankenlibc-{crate_key}/src/",
                previous_claim=line.strip(),
                generated_claim=f"{exp_files} Rust files, {exp_lines:,} lines",
                failure_signature="duplicate_contradictory_loc_claim",
            )
    if exact_src_row_re.search(line):
        continue
    for match in approx_crate_re.finditer(line):
        crate_key = match.group(1)
        obs_files = int(match.group(2))
        exp_files, exp_lines = expected_crate_sizes[crate_key]
        approx_bad = obs_files != exp_files
        if match.group(3) and match.group(4):
            approx_val = float(match.group(3))
            unit = match.group(4)
            if unit == "kLOC" and abs(approx_val - (exp_lines / 1000.0)) > 5.0:
                approx_bad = True
            elif unit == "MLOC" and abs(approx_val - (exp_lines / 1_000_000.0)) > 0.05:
                approx_bad = True
        if approx_bad:
            loc_ok = False
            fail(
                "multi_occurrence_loc_consistency",
                f"README: frankenlibc-{crate_key} summary at line {line_no} contradicts ({exp_files} files, {exp_lines:,} lines)",
                doc_surface="README",
                symbol_or_section=f"frankenlibc-{crate_key}",
                previous_claim=line.strip(),
                generated_claim=f"{exp_files} Rust files (~{exp_lines:,} lines)",
                failure_signature="duplicate_contradictory_loc_claim",
            )
checks["multi_occurrence_loc_consistency"] = "pass" if loc_ok else "fail"
if loc_ok:
    event(
        "multi_occurrence_loc_consistency",
        doc_surface="README",
        generated_claim="all crate file/LOC occurrences in README agree with working tree",
    )

# (c) Closed beads cited as open in README Known-broken section
bead_status_ok = True
if beads_jsonl_override and not beads_jsonl_path.exists():
    bead_status_ok = False
    fail(
        "bead_status_consistency",
        f"configured FLC_DOCS_SEMANTIC_BEADS_JSONL does not exist: {beads_jsonl_path}",
        doc_surface="README",
        symbol_or_section="Known broken or not yet freshly evidenced under preload",
        failure_signature="missing_beads_jsonl",
    )
elif beads_jsonl_path.exists():
    bead_status_by_id = {}
    for raw_bead_line in read_text(beads_jsonl_path, "beads_jsonl").splitlines():
        if not raw_bead_line.strip():
            continue
        try:
            bead_obj = json.loads(raw_bead_line)
            if isinstance(bead_obj, dict) and bead_obj.get("id"):
                bead_status_by_id[str(bead_obj["id"])] = str(bead_obj.get("status", ""))
        except Exception as exc:
            bead_status_ok = False
            fail(
                "bead_status_consistency",
                f"invalid JSON in {rel(beads_jsonl_path)}: {exc}",
                doc_surface="README",
                failure_signature="malformed_beads_jsonl",
            )
            break
    known_hdr = "### Known broken or not yet freshly evidenced under preload"
    if known_hdr in readme_text:
        after_hdr = readme_text.split(known_hdr, 1)[1]
        section_end = re.search(r"\n(?:## |### |---)", after_hdr)
        known_section = after_hdr[: section_end.start()] if section_end else after_hdr
        for bullet_line in known_section.splitlines():
            for match in re.finditer(r"`(bd-[a-z0-9]+(?:[-.][a-z0-9]+)+)`", bullet_line):
                bid = match.group(1)
                if bead_status_by_id.get(bid) != "closed":
                    continue
                # Check the enclosing parenthetical (or line if unparenthesized) for explicit resolved/closed marker
                open_paren = bullet_line.rfind("(", 0, match.start())
                close_paren = bullet_line.find(")", match.end())
                scope_slice = (
                    bullet_line[open_paren : close_paren + 1].lower()
                    if open_paren != -1 and close_paren != -1
                    else bullet_line.lower()
                )
                if "resolved" not in scope_slice and "closed" not in scope_slice:
                    bead_status_ok = False
                    fail(
                        "bead_status_consistency",
                        f"README: closed bead {bid} is cited as open without resolved/closed qualifier",
                        doc_surface="README",
                        symbol_or_section="Known broken or not yet freshly evidenced under preload",
                        previous_claim=bullet_line.strip(),
                        generated_claim=f"{bid} has status=closed in .beads/issues.jsonl",
                        failure_signature="closed_bead_cited_as_open",
                    )
checks["bead_status_consistency"] = "pass" if bead_status_ok else "fail"
if bead_status_ok:
    event(
        "bead_status_consistency",
        doc_surface="README",
        generated_claim="no closed beads cited as open in README preload limitations",
    )

# (d) frankenlibc-core #[allow(unsafe_code)] module allow-list and attribute budget
approved_core_unsafe_files = {
    "float128.rs",
    "lib.rs",
    "math/mod.rs",
    "pthread/cond.rs",
    "pthread/mod.rs",
    "pthread/thread.rs",
    "pthread/tls.rs",
    "rcu/mod.rs",
    "string/str.rs",
    "syscall/mod.rs",
    "termios/mod.rs",
}
unsafe_allow_re = re.compile(r"#!?\[allow\([^\]]*\bunsafe_code\b[^\]]*\)\]")
core_unsafe_ok = True
if "No `unsafe` code is permitted" in core_lib_text:
    core_unsafe_ok = False
    fail(
        "core_unsafe_allow_budget",
        "CORE_LIB_RS: blanket 'No `unsafe` code is permitted' claim contradicts boundary exemptions",
        doc_surface="CORE_LIB_RS",
        symbol_or_section="lib.rs",
        failure_signature="false_zero_unsafe_claim",
    )
if not core_src_dir.is_dir():
    core_unsafe_ok = False
    fail(
        "core_unsafe_allow_budget",
        f"core_src_dir is missing: {core_src_dir}",
        doc_surface="CORE_LIB_RS",
        failure_signature="missing_core_src_dir",
    )
else:
    observed_unsafe_files = {}
    for rs_path in sorted(core_src_dir.rglob("*.rs")):
        if not rs_path.is_file():
            continue
        rel_rs = rs_path.relative_to(core_src_dir).as_posix()
        rs_text = read_text(rs_path, f"core {rel_rs}")
        code_only = "\n".join(line.split("//", 1)[0] for line in rs_text.splitlines())
        count = len(unsafe_allow_re.findall(code_only))
        if count > 0:
            observed_unsafe_files[rel_rs] = count
            if rel_rs not in approved_core_unsafe_files:
                core_unsafe_ok = False
                fail(
                    "core_unsafe_allow_budget",
                    f"CORE_LIB_RS: unapproved #[allow(unsafe_code)] ({count}) in crates/frankenlibc-core/src/{rel_rs}",
                    doc_surface="CORE_LIB_RS",
                    symbol_or_section=rel_rs,
                    previous_claim=f"{count} #[allow(unsafe_code)] attributes",
                    generated_claim=f"only {sorted(approved_core_unsafe_files)} are approved boundary modules",
                    failure_signature="unapproved_core_unsafe_allow",
                )
    total_unsafe_attrs = sum(observed_unsafe_files.values())
    budget_match = re.search(
        r"\(`(\d+)`\s+attributes\s+across\s*\n?\s*//!?\s*`(\d+)`\s+(?:boundary\s+)?files",
        core_lib_text,
    )
    if not budget_match:
        core_unsafe_ok = False
        fail(
            "core_unsafe_allow_budget",
            "CORE_LIB_RS: missing explicit (`<N>` attributes across `<M>` boundary files) unsafe budget declaration",
            doc_surface="CORE_LIB_RS",
            symbol_or_section="unsafe_budget_declaration",
            generated_claim=f"(`{total_unsafe_attrs}` attributes across `{len(observed_unsafe_files)}` boundary files)",
            failure_signature="missing_core_unsafe_budget_claim",
        )
    else:
        declared_attrs = int(budget_match.group(1))
        declared_files = int(budget_match.group(2))
        if (declared_attrs, declared_files) != (total_unsafe_attrs, len(observed_unsafe_files)):
            core_unsafe_ok = False
            fail(
                "core_unsafe_allow_budget",
                f"CORE_LIB_RS: declared unsafe budget ({declared_attrs} attrs across {declared_files} files) != observed ({total_unsafe_attrs} attrs across {len(observed_unsafe_files)} files)",
                doc_surface="CORE_LIB_RS",
                symbol_or_section="unsafe_budget_declaration",
                previous_claim=f"{declared_attrs} attrs / {declared_files} files",
                generated_claim=f"{total_unsafe_attrs} attrs / {len(observed_unsafe_files)} files",
                failure_signature="unapproved_core_unsafe_allow",
            )
    for m_readme in re.finditer(
        r"`(\d+)`\s+`#\[allow\(unsafe_code\)\]`\s*/\s*`#!\[allow\(unsafe_code\)\]`\s+attributes\s+across\s+`(\d+)`",
        readme_text,
    ):
        rm_attrs, rm_files = int(m_readme.group(1)), int(m_readme.group(2))
        if (rm_attrs, rm_files) != (total_unsafe_attrs, len(observed_unsafe_files)):
            core_unsafe_ok = False
            fail(
                "core_unsafe_allow_budget",
                f"README: core unsafe attribute count ({rm_attrs} across {rm_files}) != observed ({total_unsafe_attrs} across {len(observed_unsafe_files)})",
                doc_surface="README",
                symbol_or_section="frankenlibc-core unsafe policy",
                previous_claim=m_readme.group(0),
                generated_claim=f"`{total_unsafe_attrs}` attributes across `{len(observed_unsafe_files)}` files",
                failure_signature="unapproved_core_unsafe_allow",
            )
checks["core_unsafe_allow_budget"] = "pass" if core_unsafe_ok else "fail"
if core_unsafe_ok:
    event(
        "core_unsafe_allow_budget",
        doc_surface="CORE_LIB_RS",
        generated_claim=f"{sum(observed_unsafe_files.values())} #[allow(unsafe_code)] attributes confined to {len(observed_unsafe_files)} approved boundary files",
    )

# (e) source_commit SHA provenance in FEATURE_PARITY.md and canonical JSON artifacts
provenance_ok = True
reality_report = load_json(reality_report_path, "reality_report")
support_commit = str(support.get("source_commit", "")) if isinstance(support, dict) else ""
reality_commit = str(reality_report.get("source_commit", "")) if isinstance(reality_report, dict) else ""
smoke_full_commit = str(smoke.get("source_commit", "")) if isinstance(smoke, dict) else ""

if not re.fullmatch(r"[0-9a-f]{40}", support_commit):
    provenance_ok = False
    fail(
        "source_commit_provenance",
        f"support_matrix.json source_commit is not 40-hex: {support_commit!r}",
        doc_surface="support_matrix",
        symbol_or_section="source_commit",
        previous_claim=support_commit,
        failure_signature="orphaned_source_commit_sha",
    )
else:
    expected_fp_ref = f"as `support_matrix.json` (`{support_commit[:9]}`)"
    if expected_fp_ref not in feature_text:
        provenance_ok = False
        fail(
            "source_commit_provenance",
            f"FEATURE_PARITY: missing or mismatched support_matrix.json source_commit prefix (expected {expected_fp_ref})",
            doc_surface="FEATURE_PARITY",
            symbol_or_section="source_commit",
            generated_claim=expected_fp_ref,
            failure_signature="orphaned_source_commit_sha",
        )
    if reality_commit != support_commit:
        provenance_ok = False
        fail(
            "source_commit_provenance",
            f"reality_report.v1.json source_commit ({reality_commit}) != support_matrix.json ({support_commit})",
            doc_surface="reality_report",
            symbol_or_section="source_commit",
            previous_claim=reality_commit,
            generated_claim=support_commit,
            failure_signature="orphaned_source_commit_sha",
        )

def git_blob_exists(repo_path: Path, file_path: Path) -> bool:
    try:
        raw = file_path.read_bytes()
    except OSError:
        return False
    oid = hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()
    return (
        subprocess.run(
            ["git", "-C", str(repo_path), "cat-file", "-e", oid],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


verify_git_objects = (
    os.environ.get("FLC_DOCS_SEMANTIC_VERIFY_GIT_OBJECTS") == "1"
    or (
        os.environ.get("RCH_BUILD_SOURCE") is None
        and os.environ.get("GIT_DIR") is None
        and (root / ".git").exists()
        and git_blob_exists(root, root / "tests/conformance/verification_matrix.json")
        and git_blob_exists(root, root / "tests/conformance/semantic_contract_inventory.v1.json")
    )
)
if verify_git_objects:
    git_repo = resolve_path(os.environ.get("FLC_DOCS_SEMANTIC_GIT_REPO", str(root)))
    commits_to_verify = [
        ("support_matrix", support_commit),
        ("reality_report", reality_commit),
        ("ld_preload_smoke_summary", smoke_full_commit),
    ]
    for fp_line in feature_text.splitlines():
        if "source commit" in fp_line.lower() or "amendment in" in fp_line.lower():
            for sha_tok in re.findall(r"`([0-9a-f]{7,40})`", fp_line):
                commits_to_verify.append(("FEATURE_PARITY", sha_tok))
    for surface_label, sha_val in commits_to_verify:
        if not sha_val:
            continue
        chk = subprocess.run(
            ["git", "-C", str(git_repo), "cat-file", "-e", f"{sha_val}^{{commit}}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if chk.returncode != 0:
            provenance_ok = False
            fail(
                "source_commit_provenance",
                f"{surface_label}: source_commit {sha_val} does not exist in git repository",
                doc_surface=surface_label,
                symbol_or_section="source_commit",
                previous_claim=sha_val,
                generated_claim="existing git commit object",
                failure_signature="orphaned_source_commit_sha",
            )
checks["source_commit_provenance"] = "pass" if provenance_ok else "fail"
if provenance_ok:
    event(
        "source_commit_provenance",
        doc_surface="FEATURE_PARITY",
        generated_claim="source_commit references resolve and match canonical artifacts",
    )

join_summary = join.get("summary", {}) if isinstance(join, dict) else {}
inventory_entries = inventory.get("entries", []) if isinstance(inventory, dict) else []
join_entries = join.get("entries", []) if isinstance(join, dict) else []
taxonomy_semantic_conflicts = [
    row
    for row in join_entries
    if row.get("taxonomy_status_is_semantic_parity") is False
    and str(row.get("semantic_parity_status", "")).startswith("blocked_")
]
semantic_ok = True
if join_summary.get("semantic_parity_blocker_count") != len(inventory_entries):
    semantic_ok = False
    fail(
        "semantic_evidence_freshness",
        "semantic join blocker count does not match inventory",
        symbol_or_section="semantic_parity_blocker_count",
        previous_claim=str(join_summary.get("semantic_parity_blocker_count")),
        generated_claim=str(len(inventory_entries)),
        failure_signature="stale_semantic_join",
    )
if {row.get("id") for row in inventory_entries} != {row.get("inventory_id") for row in join_entries}:
    semantic_ok = False
    fail(
        "semantic_evidence_freshness",
        "semantic join does not cover every inventory row",
        symbol_or_section="inventory_coverage",
        generated_claim="join rows must cover inventory rows",
        failure_signature="stale_semantic_join",
    )
if len(taxonomy_semantic_conflicts) != len(inventory_entries):
    semantic_ok = False
    fail(
        "semantic_evidence_freshness",
        "semantic join does not preserve conflicting support/semantic rows",
        symbol_or_section="taxonomy_status_is_semantic_parity",
        previous_claim=str(len(taxonomy_semantic_conflicts)),
        generated_claim=str(len(inventory_entries)),
        failure_signature="conflicting_support_semantic_rows",
    )
if not semantic_ok:
    checks["semantic_evidence_freshness"] = "fail"
else:
    checks["semantic_evidence_freshness"] = "pass"
    event(
        "semantic_evidence_freshness",
        symbol_or_section="semantic_parity_blocker_count",
        generated_claim=f"{len(inventory_entries)} semantic blockers covered",
    )

claim_policy = artifact.get("claim_policy", {})
if (
    claim_policy.get("support_taxonomy_status_is_not_semantic_parity") is True
    and claim_policy.get("docs_must_reference_semantic_join") is True
    and claim_policy.get("docs_must_reference_oracle_precedence") is True
    and claim_policy.get("docs_must_reference_replacement_levels") is True
):
    checks["claim_policy"] = "pass"
    event("claim_policy", generated_claim="docs claim policy blocks prose-only promotion")
else:
    checks["claim_policy"] = "fail"
    fail(
        "claim_policy",
        "claim policy does not block taxonomy-only or prose-only promotion",
        generated_claim=str(claim_policy),
        failure_signature="stale_claim_policy",
    )

summary = {
    "doc_surface_count": len(docs),
    "operator_guide_surface_count": len(operator_docs),
    "required_claim_field_count": len(field_ids),
    "semantic_parity_blocker_count": join_summary.get("semantic_parity_blocker_count"),
    "taxonomy_semantic_conflict_count": len(taxonomy_semantic_conflicts),
    "inventory_entry_count": len(inventory_entries),
    "forbidden_claim_count": len(forbidden_claims),
    "numeric_claim_count": len(numeric_claims),
    "missing_claim_field_count": len(missing_fields),
    "missing_evidence_phrase_count": len(missing_phrases),
}

status = "pass" if all(value == "pass" for value in checks.values()) and not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": artifact.get("bead", "bd-bp8fl.1.4"),
    "status": status,
    "checks": checks,
    "summary": summary,
    "forbidden_claims": forbidden_claims,
    "changed_claim_categories": field_ids,
    "evidence_refs": evidence_refs,
    "source_commit": source_commit,
    "target_dir": rel(report_path.parent),
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as fh:
    for row in events:
        fh.write(json.dumps(row, sort_keys=True) + "\n")

print(json.dumps(report, indent=2, sort_keys=True))
if status != "pass":
    sys.exit(1)
PY
