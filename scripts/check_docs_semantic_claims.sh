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

def git_head():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"

artifact = load_json(artifact_path, "artifact") or {}
inputs = artifact.get("inputs", {})
evidence_refs = sorted(str(value) for value in inputs.values())
source_commit = git_head()
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

def env_path(name, key):
    override = os.environ.get(name)
    if override:
        return resolve_path(override)
    return resolve_path(inputs.get(key, f"__missing_input__/{key}"))

readme_path = env_path("FLC_DOCS_SEMANTIC_README", "readme")
feature_path = env_path("FLC_DOCS_SEMANTIC_FEATURE_PARITY", "feature_parity")
support_path = env_path("FLC_DOCS_SEMANTIC_SUPPORT_MATRIX", "support_matrix")
overlay_path = env_path("FLC_DOCS_SEMANTIC_OVERLAY", "support_semantic_overlay")
inventory_path = env_path("FLC_DOCS_SEMANTIC_INVENTORY", "semantic_contract_inventory")
join_path = env_path("FLC_DOCS_SEMANTIC_JOIN", "semantic_contract_symbol_join")
oracle_path = env_path("FLC_DOCS_SEMANTIC_ORACLE", "oracle_precedence")
replacement_path = env_path("FLC_DOCS_SEMANTIC_REPLACEMENT_LEVELS", "replacement_levels")

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

readme_text = docs["README"][1]
feature_text = docs["FEATURE_PARITY"][1]

def count_lines(path):
    try:
        with path.open("r", encoding="utf-8") as fh:
            return sum(1 for _ in fh)
    except Exception as exc:
        errors.append(f"numeric claims: failed to count lines in {path}: {exc}")
        return -1

def tracked_files(pathspec):
    try:
        output = subprocess.check_output(
            ["git", "ls-files", "-z", "--", pathspec],
            cwd=root,
        )
        return sorted(
            root / os.fsdecode(raw_path)
            for raw_path in output.split(b"\0")
            if raw_path
        )
    except Exception as exc:
        errors.append(f"numeric claims: failed to list tracked files for {pathspec}: {exc}")
        return []

numeric_claims = []

def expect_numeric_claim(surface, claim_id, expected):
    text = readme_text if surface == "README" else feature_text
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

smoke_path = root / "tests/conformance/ld_preload_smoke_summary.v1.json"
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

stale_numeric_patterns = {
    "old_cli_contract_count": r"\b68 such manifests\b|\b68 CLI-contract",
    "old_completion_contract_count": r"\b258 completion-contract",
    "old_fixture_count": r"\b134 fixture",
    "old_c_fixture_count": r"\b17 C (?:test|integration)|\(17 fixtures\)",
    "old_membrane_build_size": r"\b1,030 lines\b",
    "old_smoke_total": r"\b60/0/4\b|\b60 pass(?:es)? / 0 fail(?:s)? / 4",
    "old_toolchain_pin": r"nightly-2026-04-28",
}
for surface, (_, text) in docs.items():
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

checks["docs_claim_fields"] = "pass" if not missing_fields else "fail"
checks["docs_claim_surface"] = "pass" if not missing_phrases else "fail"

for surface_id, (path, text) in docs.items():
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
