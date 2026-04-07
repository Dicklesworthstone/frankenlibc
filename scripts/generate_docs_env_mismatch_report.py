#!/usr/bin/env python3
"""Generate docs env inventory, mismatch classifications, and docs governance."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

KEY_RE = re.compile(r"\b(FRANKENLIBC_[A-Z0-9_]+)\b")

DOC_FILES = (
    "README.md",
    "AGENTS.md",
    "FEATURE_PARITY.md",
    "PLAN_TO_PORT_GLIBC_TO_RUST.md",
    "PROPOSED_ARCHITECTURE.md",
    "EXISTING_GLIBC_STRUCTURE.md",
)

DOC_GOVERNANCE_SURFACES: tuple[dict[str, Any], ...] = (
    {
        "surface_id": "README",
        "surface_title": "Public status, quickstart, and evidence narrative",
        "target_path": "README.md",
        "future_target_path": "README.md",
        "split_status": "materialized",
        "sections": (
            {
                "section_id": "status-and-quickstart",
                "section_title": "Current State / Quick Start / Artifact Matrix",
                "backing_paths": ("README.md", "FEATURE_PARITY.md"),
                "source_artifacts": (
                    "tests/conformance/reality_report.v1.json",
                    "tests/conformance/support_matrix_maintenance_report.v1.json",
                    "tests/conformance/replacement_levels.json",
                    "tests/conformance/packaging_spec.json",
                ),
                "owner": "docs.release",
                "review_policy": (
                    "release-integrity review required when support taxonomy, "
                    "replacement level, or packaging claims change"
                ),
                "update_triggers": (
                    "scripts/check_support_matrix_drift.sh",
                    "scripts/check_replacement_levels.sh",
                    "scripts/check_packaging.sh",
                ),
            },
            {
                "section_id": "smoke-status-and-claim-governance",
                "section_title": "Smoke status / checked artifact / claim reconciliation",
                "backing_paths": ("README.md",),
                "source_artifacts": (
                    "tests/conformance/ld_preload_smoke_summary.v1.json",
                    "tests/conformance/claim_reconciliation_report.v1.json",
                    "tests/conformance/replacement_levels.json",
                ),
                "owner": "docs.release",
                "review_policy": (
                    "release-integrity review required when README smoke status, "
                    "checked artifact counts, or replacement-level readiness "
                    "claims change"
                ),
                "update_triggers": (
                    "scripts/check_claim_reconciliation.sh",
                    "scripts/ld_preload_smoke.sh",
                ),
            },
            {
                "section_id": "verification-and-troubleshooting",
                "section_title": "Verification Model / Troubleshooting / Common Commands",
                "backing_paths": ("README.md",),
                "source_artifacts": (
                    "tests/conformance/release_gate_dag.v1.json",
                    "tests/conformance/release_gate_runner_runbook.md",
                    "scripts/ci.sh",
                    "scripts/e2e_suite.sh",
                ),
                "owner": "docs.verification",
                "review_policy": (
                    "harness owner reviews command examples and failure triage "
                    "whenever gates or replay flows change"
                ),
                "update_triggers": (
                    "scripts/check_docs_env_mismatch.sh",
                    "scripts/check_e2e_suite.sh",
                ),
            },
        ),
    },
    {
        "surface_id": "ARCHITECTURE",
        "surface_title": "TSM, runtime-mode, and runtime-math design contract",
        "target_path": "PROPOSED_ARCHITECTURE.md",
        "future_target_path": "ARCHITECTURE.md",
        "split_status": "backed_by_existing_docs_until_split",
        "sections": (
            {
                "section_id": "tsm-and-runtime-modes",
                "section_title": "TSM pipeline / runtime modes / ABI boundary",
                "backing_paths": (
                    "PROPOSED_ARCHITECTURE.md",
                    "AGENTS.md",
                    "README.md",
                ),
                "source_artifacts": (
                    "crates/frankenlibc-membrane/src/ptr_validator.rs",
                    "crates/frankenlibc-membrane/src/config.rs",
                    "tests/conformance/mode_semantics_matrix.json",
                ),
                "owner": "docs.architecture",
                "review_policy": (
                    "membrane owner review required for boundary, mode, or "
                    "validation-order changes"
                ),
                "update_triggers": (
                    "scripts/check_mode_semantics.sh",
                    "scripts/check_mode_contract_lock.sh",
                ),
            },
            {
                "section_id": "runtime-math-control-plane",
                "section_title": "Runtime math controller set and production policy",
                "backing_paths": ("PROPOSED_ARCHITECTURE.md", "README.md"),
                "source_artifacts": (
                    "crates/frankenlibc-membrane/src/runtime_math/mod.rs",
                    "tests/conformance/math_production_set_policy.v1.json",
                    "tests/conformance/math_value_proof.json",
                ),
                "owner": "docs.runtime_math",
                "review_policy": (
                    "runtime-math owner review required for controller inventory, "
                    "policy-table, or proof-linkage changes"
                ),
                "update_triggers": (
                    "scripts/check_runtime_math_manifest.sh",
                    "scripts/check_runtime_math_linkage_proofs.sh",
                ),
            },
        ),
    },
    {
        "surface_id": "DEPLOYMENT",
        "surface_title": "Interpose and Gentoo deployment guidance",
        "target_path": "README.md",
        "future_target_path": "DEPLOYMENT.md",
        "split_status": "backed_by_existing_docs_until_split",
        "sections": (
            {
                "section_id": "interpose-workflows",
                "section_title": "Interpose artifact build, install, and smoke workflows",
                "backing_paths": ("README.md",),
                "source_artifacts": (
                    "tests/conformance/packaging_spec.json",
                    "tests/conformance/replacement_levels.json",
                    "scripts/ld_preload_smoke.sh",
                    "scripts/e2e_suite.sh",
                ),
                "owner": "docs.deployment",
                "review_policy": (
                    "release-packaging review required when install commands, "
                    "artifact names, or preload flows change"
                ),
                "update_triggers": (
                    "scripts/check_packaging.sh",
                    "scripts/check_replacement_levels.sh",
                ),
            },
            {
                "section_id": "gentoo-operations",
                "section_title": "Gentoo runner, Portage hook, and validation operations",
                "backing_paths": (
                    "docs/gentoo/USER-GUIDE.md",
                    "docs/gentoo/OPERATIONS.md",
                    "docs/gentoo/VALIDATION-REPORT-TEMPLATE.md",
                ),
                "source_artifacts": (
                    "scripts/gentoo/build-runner.py",
                    "scripts/gentoo/frankenlibc-ebuild-hooks.sh",
                    "scripts/gentoo/validate-docs.py",
                    "tests/conformance/reality_report.v1.json",
                ),
                "owner": "docs.gentoo",
                "review_policy": (
                    "Gentoo workflow owner reviews any change to Portage hooks, "
                    "runner behavior, or validation report schema"
                ),
                "update_triggers": (
                    "scripts/gentoo/validate-docs.py",
                    "scripts/check_structured_logs.sh",
                ),
            },
        ),
    },
    {
        "surface_id": "SECURITY",
        "surface_title": "Threat model, hardened-mode guarantees, and healing evidence",
        "target_path": "README.md",
        "future_target_path": "SECURITY.md",
        "split_status": "backed_by_existing_docs_until_split",
        "sections": (
            {
                "section_id": "threat-model-and-healing",
                "section_title": "Threat Model / Healing actions / Hardened guarantees",
                "backing_paths": (
                    "README.md",
                    "AGENTS.md",
                    "docs/proofs/hardened_mode_safety.md",
                ),
                "source_artifacts": (
                    "tests/conformance/hardened_repair_deny_matrix.v1.json",
                    "tests/cve_arena/results/paired_mode_evidence.v1.json",
                    "scripts/check_structured_logs.sh",
                ),
                "owner": "docs.security",
                "review_policy": (
                    "security owner review required for threat-model language, "
                    "hardened actions, or CVE evidence changes"
                ),
                "update_triggers": (
                    "scripts/check_cve_paired_mode_runner.sh",
                    "scripts/check_structured_logs.sh",
                ),
            },
        ),
    },
    {
        "surface_id": "API",
        "surface_title": "API support taxonomy, parity, and fixture coverage",
        "target_path": "FEATURE_PARITY.md",
        "future_target_path": "API.md",
        "split_status": "backed_by_existing_docs_until_split",
        "sections": (
            {
                "section_id": "classification-and-parity",
                "section_title": "Support taxonomy / parity claims / implementation reality",
                "backing_paths": ("FEATURE_PARITY.md", "README.md"),
                "source_artifacts": (
                    "tests/conformance/reality_report.v1.json",
                    "tests/conformance/verification_matrix.json",
                    "tests/conformance/support_matrix_maintenance_report.v1.json",
                ),
                "owner": "docs.api",
                "review_policy": (
                    "ABI support owner review required whenever symbol "
                    "classification or parity narratives change"
                ),
                "update_triggers": (
                    "scripts/check_support_matrix_drift.sh",
                    "scripts/check_conformance_coverage.sh",
                ),
            },
            {
                "section_id": "fixture-and-traceability",
                "section_title": "Fixture coverage / traceability / verification depth",
                "backing_paths": ("FEATURE_PARITY.md",),
                "source_artifacts": (
                    "tests/conformance/per_symbol_fixture_tests.v1.json",
                    "tests/conformance/symbol_fixture_coverage.v1.json",
                    "tests/conformance/fixtures/iconv_phase1.json",
                ),
                "owner": "docs.conformance",
                "review_policy": (
                    "conformance owner review required when fixture families or "
                    "traceability coverage change"
                ),
                "update_triggers": (
                    "scripts/check_conformance_fixture_unit_tests.sh",
                    "scripts/check_conformance_coverage.sh",
                ),
            },
        ),
    },
    {
        "surface_id": "TROUBLESHOOTING",
        "surface_title": "Failure triage and operator guidance",
        "target_path": "README.md",
        "future_target_path": "TROUBLESHOOTING.md",
        "split_status": "backed_by_existing_docs_until_split",
        "sections": (
            {
                "section_id": "common-failures",
                "section_title": "Common failures / gate triage / operator runbooks",
                "backing_paths": (
                    "README.md",
                    "tests/conformance/release_gate_runner_runbook.md",
                ),
                "source_artifacts": (
                    "scripts/check_support_matrix_drift.sh",
                    "scripts/check_packaging.sh",
                    "tests/conformance/release_gate_dag.v1.json",
                ),
                "owner": "docs.triage",
                "review_policy": (
                    "release-integrity owner reviews operator guidance when gate "
                    "signatures or remediation steps change"
                ),
                "update_triggers": (
                    "scripts/check_feature_parity_drift.sh",
                    "scripts/check_release_gate.sh",
                ),
            },
            {
                "section_id": "docs-governance",
                "section_title": "Documentation drift and ownership workflow",
                "backing_paths": ("README.md",),
                "source_artifacts": (
                    "tests/conformance/env_docs_code_mismatch_report.v1.json",
                    "tests/conformance/docs_env_inventory.v1.json",
                    "scripts/check_docs_env_mismatch.sh",
                ),
                "owner": "docs.governance",
                "review_policy": (
                    "docs-governance owner reviews mapping changes and confirms "
                    "regenerated artifacts before merge"
                ),
                "update_triggers": (
                    "scripts/check_docs_env_mismatch.sh",
                    "crates/frankenlibc-harness/tests/docs_env_mismatch_test.rs",
                ),
            },
        ),
    },
)


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def canonical_jsonl(rows: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)


def collect_docs_mentions(root: Path) -> dict[str, list[dict[str, Any]]]:
    findings: dict[str, list[dict[str, Any]]] = {}
    for rel in DOC_FILES:
        path = root / rel
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines, start=1):
            keys = sorted(set(KEY_RE.findall(line)))
            if not keys:
                continue
            snippet = line.strip()
            for key in keys:
                findings.setdefault(key, []).append(
                    {"path": rel, "line": idx, "snippet": snippet}
                )
    return findings


def build_docs_inventory(mentions: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    keys: list[dict[str, Any]] = []
    total_mentions = 0
    for key in sorted(mentions):
        rows = sorted(mentions[key], key=lambda row: (row["path"], row["line"]))
        total_mentions += len(rows)
        keys.append(
            {
                "env_key": key,
                "mention_count": len(rows),
                "mentions": rows,
            }
        )

    return {
        "schema_version": "v1",
        "generator": "scripts/generate_docs_env_mismatch_report.py",
        "docs_files": [rel for rel in DOC_FILES],
        "keys": keys,
        "summary": {
            "total_keys": len(keys),
            "total_mentions": total_mentions,
        },
    }


def classify_inputs(root: Path, paths: tuple[str, ...]) -> tuple[str, list[str]]:
    missing = [rel for rel in paths if not (root / rel).exists()]
    if missing:
        return "missing_inputs", missing
    return "fresh", []


def build_docs_governance_artifacts(
    root: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    surfaces: list[dict[str, Any]] = []
    trace_rows: list[dict[str, Any]] = []
    owner_roles: dict[str, dict[str, Any]] = {}
    fresh_section_count = 0
    missing_section_count = 0

    for surface in DOC_GOVERNANCE_SURFACES:
        section_rows: list[dict[str, Any]] = []
        surface_missing: list[str] = []

        for section in surface["sections"]:
            input_paths = tuple(
                list(section["backing_paths"])
                + list(section["source_artifacts"])
                + list(section["update_triggers"])
            )
            freshness_status, missing_inputs = classify_inputs(root, input_paths)
            if missing_inputs:
                surface_missing.extend(missing_inputs)

            if freshness_status == "fresh":
                fresh_section_count += 1
            else:
                missing_section_count += 1

            row = {
                "section_id": section["section_id"],
                "section_title": section["section_title"],
                "backing_paths": list(section["backing_paths"]),
                "source_artifacts": list(section["source_artifacts"]),
                "owner": section["owner"],
                "review_policy": section["review_policy"],
                "update_triggers": list(section["update_triggers"]),
                "freshness_status": freshness_status,
                "missing_inputs": missing_inputs,
            }
            section_rows.append(row)

            owner_roles.setdefault(
                section["owner"],
                {
                    "owner": section["owner"],
                    "review_policies": [],
                    "surfaces": set(),
                },
            )
            owner_roles[section["owner"]]["review_policies"].append(
                section["review_policy"]
            )
            owner_roles[section["owner"]]["surfaces"].add(surface["surface_id"])

            trace_rows.append(
                {
                    "trace_id": (
                        f"bd-3rw.3::{surface['surface_id'].lower()}::"
                        f"{section['section_id']}"
                    ),
                    "bead_id": "bd-3rw.3",
                    "doc_surface": surface["surface_id"],
                    "doc_section": section["section_title"],
                    "backing_path": section["backing_paths"][0],
                    "source_artifact": section["source_artifacts"][0],
                    "freshness_status": freshness_status,
                    "owner": section["owner"],
                    "review_policy": section["review_policy"],
                    "update_trigger": section["update_triggers"][0],
                    "artifact_refs": list(section["source_artifacts"])
                    + list(section["backing_paths"]),
                }
            )

        surfaces.append(
            {
                "surface_id": surface["surface_id"],
                "surface_title": surface["surface_title"],
                "target_path": surface["target_path"],
                "future_target_path": surface["future_target_path"],
                "split_status": surface["split_status"],
                "freshness_status": "fresh" if not surface_missing else "missing_inputs",
                "missing_inputs": sorted(set(surface_missing)),
                "sections": section_rows,
            }
        )

    owners = []
    for owner, payload in sorted(owner_roles.items()):
        policies = sorted(set(payload["review_policies"]))
        owners.append(
            {
                "owner": owner,
                "surfaces": sorted(payload["surfaces"]),
                "review_policies": policies,
            }
        )

    governance_map = {
        "schema_version": "v1",
        "bead": "bd-3rw.3",
        "generator": "scripts/generate_docs_env_mismatch_report.py",
        "surfaces": surfaces,
        "owner_roles": owners,
        "workflow": {
            "required_commands": [
                "python3 scripts/generate_docs_env_mismatch_report.py --check",
                "bash scripts/check_docs_env_mismatch.sh",
                "cargo test -p frankenlibc-harness --test docs_env_mismatch_test",
            ],
            "steps": [
                {
                    "step_id": "detect_trigger",
                    "description": (
                        "When a backing doc, source artifact, or gate script "
                        "changes, the corresponding owner updates the mapped "
                        "documentation surface before merge."
                    ),
                },
                {
                    "step_id": "regenerate",
                    "description": (
                        "Regenerate docs env inventory, mismatch report, source-"
                        "of-truth map, and trace log in one command."
                    ),
                },
                {
                    "step_id": "review",
                    "description": (
                        "The section owner reviews prose changes; docs.governance "
                        "confirms cross-surface mapping completeness."
                    ),
                },
                {
                    "step_id": "merge_gate",
                    "description": (
                        "The gate script and harness test must both pass with "
                        "fresh artifacts before merge."
                    ),
                },
            ],
        },
        "summary": {
            "surface_count": len(surfaces),
            "section_count": fresh_section_count + missing_section_count,
            "fresh_section_count": fresh_section_count,
            "missing_section_count": missing_section_count,
            "owner_count": len(owners),
        },
    }
    return governance_map, trace_rows


def load_code_inventory(path: Path) -> tuple[set[str], dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    keys = {
        row["env_key"]
        for row in payload.get("inventory", [])
        if isinstance(row, dict) and "env_key" in row
    }
    return keys, payload


def classify_mismatches(
    docs_mentions: dict[str, list[dict[str, Any]]],
    docs_inventory_path: str,
    code_inventory_path: str,
    code_keys: set[str],
) -> dict[str, Any]:
    docs_keys = set(docs_mentions.keys())

    missing_in_docs = sorted(code_keys - docs_keys)
    missing_in_code = sorted(docs_keys - code_keys)
    semantic_drift: list[dict[str, Any]] = []

    mode_mentions = docs_mentions.get("FRANKENLIBC_MODE", [])
    if mode_mentions and not any(
        "strict|hardened" in row["snippet"] or "strict" in row["snippet"]
        for row in mode_mentions
    ):
        semantic_drift.append(
            {
                "env_key": "FRANKENLIBC_MODE",
                "mismatch_class": "semantic_drift",
                "evidence": mode_mentions,
                "details": "docs mention FRANKENLIBC_MODE but strict/hardened contract phrasing was not found",
                "remediation_action": "clarify_strict_hardened_contract_in_docs",
            }
        )

    classifications: list[dict[str, Any]] = []

    for key in missing_in_docs:
        classifications.append(
            {
                "env_key": key,
                "mismatch_class": "missing_in_docs",
                "evidence": [{"path": code_inventory_path, "source": "code_inventory"}],
                "details": "key appears in code inventory but not in selected docs",
                "remediation_action": "document_knob_or_mark_internal_only",
            }
        )

    for key in missing_in_code:
        classifications.append(
            {
                "env_key": key,
                "mismatch_class": "missing_in_code",
                "evidence": docs_mentions.get(key, []),
                "details": "key appears in docs but no code inventory entry exists",
                "remediation_action": "implement_knob_or_mark_deprecated_in_docs",
            }
        )

    classifications.extend(semantic_drift)
    classifications = sorted(
        classifications, key=lambda row: (row["mismatch_class"], row["env_key"])
    )

    unresolved = [
        row
        for row in classifications
        if not row.get("remediation_action")
        or row.get("remediation_action") == "unknown"
    ]

    summary = {
        "docs_keys": len(docs_keys),
        "code_keys": len(code_keys),
        "missing_in_docs_count": len(missing_in_docs),
        "missing_in_code_count": len(missing_in_code),
        "semantic_drift_count": len(semantic_drift),
        "total_classifications": len(classifications),
        "unresolved_ambiguous_count": len(unresolved),
    }

    return {
        "schema_version": "v1",
        "generator": "scripts/generate_docs_env_mismatch_report.py",
        "docs_inventory_path": docs_inventory_path,
        "code_inventory_path": code_inventory_path,
        "classifications": classifications,
        "summary": summary,
        "unresolved_ambiguous": unresolved,
    }


def compare_or_write(path: Path, rendered: str, check: bool) -> int:
    if check:
        if not path.exists():
            print(f"FAIL: missing file: {path}", file=sys.stderr)
            return 1
        current = path.read_text(encoding="utf-8")
        if current != rendered:
            print(f"FAIL: drift detected for {path}", file=sys.stderr)
            return 1
        return 0

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate docs env inventory and mismatch classifications."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Workspace root",
    )
    parser.add_argument(
        "--code-inventory",
        type=Path,
        default=Path("tests/conformance/runtime_env_inventory.v1.json"),
        help="Code inventory JSON path relative to --root",
    )
    parser.add_argument(
        "--docs-output",
        type=Path,
        default=Path("tests/conformance/docs_env_inventory.v1.json"),
        help="Docs inventory output path relative to --root",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=Path("tests/conformance/env_docs_code_mismatch_report.v1.json"),
        help="Mismatch report output path relative to --root",
    )
    parser.add_argument(
        "--source-map-output",
        type=Path,
        default=Path("tests/conformance/docs_source_of_truth_map.v1.json"),
        help="Docs governance/source-of-truth output path relative to --root",
    )
    parser.add_argument(
        "--trace-output",
        type=Path,
        default=Path("tests/conformance/docs_source_of_truth_trace.v1.jsonl"),
        help="Structured docs governance trace output path relative to --root",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when checked files differ from generated output",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    code_inventory_path = (root / args.code_inventory).resolve()
    docs_output = (root / args.docs_output).resolve()
    report_output = (root / args.report_output).resolve()
    source_map_output = (root / args.source_map_output).resolve()
    trace_output = (root / args.trace_output).resolve()

    if not code_inventory_path.exists():
        print(f"FAIL: missing code inventory file: {code_inventory_path}", file=sys.stderr)
        return 1

    docs_mentions = collect_docs_mentions(root)
    docs_inventory = build_docs_inventory(docs_mentions)
    code_keys, _ = load_code_inventory(code_inventory_path)
    report = classify_mismatches(
        docs_mentions=docs_mentions,
        docs_inventory_path=args.docs_output.as_posix(),
        code_inventory_path=args.code_inventory.as_posix(),
        code_keys=code_keys,
    )
    source_map, trace_rows = build_docs_governance_artifacts(root)

    rc = 0
    rc |= compare_or_write(docs_output, canonical_json(docs_inventory), args.check)
    rc |= compare_or_write(report_output, canonical_json(report), args.check)
    rc |= compare_or_write(source_map_output, canonical_json(source_map), args.check)
    rc |= compare_or_write(trace_output, canonical_jsonl(trace_rows), args.check)
    if rc != 0:
        return 1

    if args.check:
        print(
            "PASS: docs env inventory + mismatch report + governance map are "
            "up-to-date "
            f"(classifications={report['summary']['total_classifications']}, "
            f"surfaces={source_map['summary']['surface_count']}, "
            f"sections={source_map['summary']['section_count']})"
        )
    else:
        print(
            "Wrote docs env artifacts: "
            f"{docs_output.relative_to(root)}, "
            f"{report_output.relative_to(root)}, "
            f"{source_map_output.relative_to(root)}, and "
            f"{trace_output.relative_to(root)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
