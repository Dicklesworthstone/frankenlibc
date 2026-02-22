#!/usr/bin/env python3
"""runtime_math_admission_gate.py — bd-3ot.3
CI admission gate for runtime-math controllers.

Enforces:
  1. ADMISSION: Every controller in production_kernel_manifest must have
     governance classification AND ablation evidence (RETAIN decision).
  2. RETIREMENT LOCKOUT: Controllers with RETIRE decision in ablation report
     must NOT appear in production feature set without runtime-math-research gate.
  3. UNKNOWN BLOCK: Unclassified controllers are blocked from admission.
  4. CONTROLLER MANIFEST COVERAGE: Every production-manifest controller has an
     explicit decision hook, invariant, fallback behavior, and measurable
     value target.

Reads:
  - tests/conformance/math_governance.json
  - tests/runtime_math/production_kernel_manifest.v1.json
  - tests/runtime_math/controller_ablation_report.v1.json
  - tests/runtime_math/runtime_math_linkage.v1.json
  - tests/conformance/math_value_proof.json

Produces:
  - tests/runtime_math/admission_gate_report.v1.json
  - tests/runtime_math/controller_manifest.v1.json

Exit codes:
  0 = all admission policies pass
  1 = policy violations detected
  2 = missing required artifact
"""
import json
import os
import sys
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _cost_target_for_tier(tier: str) -> dict[str, Any]:
    if tier == "production_core":
        return {
            "strict_hot_path_ns_max": 20,
            "hardened_hot_path_ns_max": 200,
            "cadence": "per_call",
        }
    if tier == "production_monitor":
        return {
            "strict_hot_path_ns_max": None,
            "hardened_hot_path_ns_max": None,
            "cadence": "cadence_gated",
        }
    return {
        "strict_hot_path_ns_max": None,
        "hardened_hot_path_ns_max": None,
        "cadence": "research_or_unclassified",
    }


def _extract_value_targets(value_proof: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], float]:
    retention_threshold_raw = (
        value_proof.get("scoring_methodology", {}).get("retention_threshold", 0.0)
    )
    try:
        retention_threshold = float(retention_threshold_raw)
    except (TypeError, ValueError):
        retention_threshold = 0.0

    targets: dict[str, dict[str, Any]] = {}
    for key in ("production_core_assessments", "production_monitor_assessments"):
        entries = value_proof.get(key, [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            module = entry.get("module")
            if not isinstance(module, str) or not module:
                continue
            targets[module] = {
                "value_category": entry.get("value_category"),
                "baseline_alternative": entry.get("baseline_alternative"),
                "measurable_benefit": entry.get("measurable_benefit"),
                "impact": entry.get("impact"),
                "confidence": entry.get("confidence"),
                "effort": entry.get("effort"),
                "score": entry.get("score"),
                "retention_threshold": retention_threshold,
                "verdict": entry.get("verdict"),
            }
    return targets, retention_threshold


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_integrity_snapshot(
    repo_root: Path,
    artifacts: dict[str, Path],
) -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = {}
    for key, path in artifacts.items():
        snapshot[key] = {
            "path": str(path.relative_to(repo_root)),
            "sha256": _sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
    return snapshot


def _analyze_harness_tooling_contract(repo_root: Path, harness_cargo_path: Path) -> dict[str, Any]:
    contract: dict[str, Any] = {
        "cargo_manifest": str(harness_cargo_path.relative_to(repo_root)),
        "parse_mode": "tomllib" if tomllib is not None else "text_fallback",
        "has_asupersync_dependency": False,
        "has_ftui_harness_dependency": False,
        "asupersync_feature_present": False,
        "default_enables_asupersync_tooling": False,
        "frankentui_feature_present": False,
        "frankentui_dependency_set_complete": False,
    }
    if not harness_cargo_path.exists():
        contract["parse_error"] = "missing_harness_cargo_toml"
        return contract

    content = harness_cargo_path.read_text(encoding="utf-8")
    if tomllib is not None:
        try:
            cargo = tomllib.loads(content)
        except Exception as exc:  # pragma: no cover - defensive parsing guard
            contract["parse_error"] = f"toml_parse_error: {exc}"
        else:
            features = cargo.get("features", {})
            deps = cargo.get("dependencies", {})

            default_features = set(features.get("default", []))
            asupersync_feature = set(features.get("asupersync-tooling", []))
            frankentui_feature = set(features.get("frankentui-ui", []))

            contract["has_asupersync_dependency"] = "asupersync-conformance" in deps
            contract["has_ftui_harness_dependency"] = "ftui-harness" in deps
            contract["asupersync_feature_present"] = (
                "asupersync-tooling" in features and "dep:asupersync-conformance" in asupersync_feature
            )
            contract["default_enables_asupersync_tooling"] = "asupersync-tooling" in default_features
            contract["frankentui_feature_present"] = (
                "frankentui-ui" in features and "dep:ftui-harness" in frankentui_feature
            )
            contract["frankentui_dependency_set_complete"] = all(
                dep in deps
                for dep in (
                    "ftui-harness",
                    "ftui-core",
                    "ftui-layout",
                    "ftui-render",
                    "ftui-style",
                    "ftui-widgets",
                )
            )
            return contract

    # Fallback parsing for older Python builds that do not ship tomllib.
    contract["has_asupersync_dependency"] = "asupersync-conformance" in content
    contract["has_ftui_harness_dependency"] = "ftui-harness" in content
    contract["asupersync_feature_present"] = (
        "asupersync-tooling" in content and "dep:asupersync-conformance" in content
    )
    contract["default_enables_asupersync_tooling"] = (
        'default = ["asupersync-tooling"]' in content
    )
    contract["frankentui_feature_present"] = (
        "frankentui-ui" in content and "dep:ftui-harness" in content
    )
    contract["frankentui_dependency_set_complete"] = all(
        needle in content
        for needle in (
            "ftui-harness",
            "ftui-core",
            "ftui-layout",
            "ftui-render",
            "ftui-style",
            "ftui-widgets",
        )
    )
    return contract


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    start_ns = time.time_ns()
    trace_id = (
        f"bd-w2c3.5.3::admission-gate::"
        f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}::{os.getpid()}"
    )

    governance_path = repo_root / "tests/conformance/math_governance.json"
    manifest_path = repo_root / "tests/runtime_math/production_kernel_manifest.v1.json"
    ablation_path = repo_root / "tests/runtime_math/controller_ablation_report.v1.json"
    linkage_path = repo_root / "tests/runtime_math/runtime_math_linkage.v1.json"
    value_proof_path = repo_root / "tests/conformance/math_value_proof.json"
    harness_cargo_path = repo_root / "crates/frankenlibc-harness/Cargo.toml"
    controller_manifest_path = repo_root / "tests/runtime_math/controller_manifest.v1.json"
    structured_log_path = repo_root / "target/conformance/runtime_math_admission_gate.log.jsonl"

    governance = load_json(governance_path)
    manifest = load_json(manifest_path)
    ablation = load_json(ablation_path)
    linkage = load_json(linkage_path)
    value_proof = load_json(value_proof_path)

    # Check required artifacts exist
    missing = []
    if governance is None:
        missing.append("math_governance.json")
    if manifest is None:
        missing.append("production_kernel_manifest.v1.json")
    if ablation is None:
        missing.append("controller_ablation_report.v1.json")
    if linkage is None:
        missing.append("runtime_math_linkage.v1.json")
    if value_proof is None:
        missing.append("math_value_proof.json")
    if not harness_cargo_path.exists():
        missing.append("crates/frankenlibc-harness/Cargo.toml")

    if missing:
        print(f"FAIL: missing required artifacts: {missing}", file=sys.stderr)
        return 2

    artifacts_consumed_paths = {
        "governance": governance_path,
        "manifest": manifest_path,
        "ablation_report": ablation_path,
        "linkage": linkage_path,
        "value_proof": value_proof_path,
        "harness_cargo_manifest": harness_cargo_path,
    }
    artifact_integrity = _artifact_integrity_snapshot(repo_root, artifacts_consumed_paths)

    # Extract governance modules by tier
    governance_modules: dict[str, str] = {}  # module -> tier
    for tier_name, entries in governance.get("classifications", {}).items():
        for entry in entries:
            governance_modules[entry["module"]] = tier_name

    # Extract manifest module partitions.
    def normalize_modules(raw: Any) -> list[str]:
        if not isinstance(raw, list):
            return []
        normalized: list[str] = []
        for item in raw:
            name = item.get("name", item) if isinstance(item, dict) else item
            if isinstance(name, str) and name:
                normalized.append(name)
        return normalized

    production_modules_raw = manifest.get(
        "production_modules",
        manifest.get(
            "modules",
            manifest.get("production_set", manifest.get("controllers", [])),
        ),
    )
    research_only_modules_raw = manifest.get("research_only_modules", [])

    production_modules = sorted(set(normalize_modules(production_modules_raw)))
    research_only_modules = sorted(set(normalize_modules(research_only_modules_raw)))
    manifest_modules = sorted(set(production_modules) | set(research_only_modules))

    # Extract ablation decisions
    ablation_decisions: dict[str, dict] = {}
    for d in ablation.get("partition_decisions", []):
        ablation_decisions[d["module"]] = d

    linkage_modules = linkage.get("modules", {})
    if not isinstance(linkage_modules, dict):
        linkage_modules = {}

    value_targets, retention_threshold = _extract_value_targets(value_proof)

    # Extract feature sets
    default_features = set(manifest.get("default_feature_set", []))
    optional_features = set(manifest.get("optional_feature_set", []))
    tooling_contract = _analyze_harness_tooling_contract(repo_root, harness_cargo_path)

    findings: list[dict[str, str]] = []

    # === POLICY 1: ADMISSION GATE ===
    # Every manifest module must have governance classification + ablation RETAIN
    for module in sorted(set(manifest_modules)):
        # Check governance classification exists
        if module not in governance_modules:
            findings.append({
                "severity": "error",
                "policy": "admission",
                "rule": "governance_classification_required",
                "module": module,
                "message": f"Module '{module}' in manifest but has no governance classification — admission blocked",
            })
            continue

        # Check ablation evidence exists
        if module not in ablation_decisions:
            findings.append({
                "severity": "error",
                "policy": "admission",
                "rule": "ablation_evidence_required",
                "module": module,
                "message": f"Module '{module}' in manifest but has no ablation evidence — admission blocked",
            })
            continue

    # === POLICY 1B: CONTROLLER MANIFEST COVERAGE ===
    # Every production-manifest module must have explicit decision linkage
    # + invariant + fallback + value target.
    for module in sorted(production_modules):
        linkage_entry = linkage_modules.get(module)
        tier = governance_modules.get(module, "unclassified")

        if not isinstance(linkage_entry, dict):
            findings.append({
                "severity": "error",
                "policy": "controller_manifest",
                "rule": "linkage_required",
                "module": module,
                "message": f"Production module '{module}' missing linkage entry",
            })
            continue

        for key in ("decision_target", "invariant", "fallback_when_data_missing"):
            value = linkage_entry.get(key)
            if not isinstance(value, str) or not value.strip():
                findings.append({
                    "severity": "error",
                    "policy": "controller_manifest",
                    "rule": f"{key}_required",
                    "module": module,
                    "message": (
                        f"Production module '{module}' missing required linkage field '{key}'"
                    ),
                })

        if tier in {"production_core", "production_monitor"}:
            target = value_targets.get(module)
            if target is None:
                findings.append({
                    "severity": "error",
                    "policy": "controller_manifest",
                    "rule": "value_target_required",
                    "module": module,
                    "message": (
                        f"Production-tier module '{module}' missing value-proof target entry"
                    ),
                })
            else:
                score = target.get("score")
                verdict = str(target.get("verdict", "")).strip().lower()
                if not isinstance(score, (int, float)):
                    findings.append({
                        "severity": "error",
                        "policy": "controller_manifest",
                        "rule": "value_target_score_required",
                        "module": module,
                        "message": f"Production-tier module '{module}' value target missing numeric score",
                    })
                elif float(score) < retention_threshold:
                    findings.append({
                        "severity": "warning",
                        "policy": "controller_manifest",
                        "rule": "score_below_retention_threshold",
                        "module": module,
                        "message": (
                            f"Production-tier module '{module}' score {float(score):.2f} "
                            f"is below retention threshold {retention_threshold:.2f}"
                        ),
                    })
                if verdict != "retain":
                    findings.append({
                        "severity": "warning",
                        "policy": "controller_manifest",
                        "rule": "non_retain_verdict",
                        "module": module,
                        "message": (
                            f"Production-tier module '{module}' has non-retain verdict '{verdict}'"
                        ),
                    })

    # === POLICY 2: RETIREMENT LOCKOUT ===
    # Modules with RETIRE decision must not be in default (production) feature set
    # They are only allowed behind optional runtime-math-research gate
    retired_modules = {
        m for m, d in ablation_decisions.items()
        if d["decision"] == "RETIRE"
    }
    production_feature = "runtime-math-production"
    research_feature = "runtime-math-research"

    # Check: retired modules must only be in optional research feature set.
    # Manifest membership is the union of production and research-only sets.
    # "ADMITTED" modules must still come from production_modules.
    for module in sorted(retired_modules):
        tier = governance_modules.get(module, "unknown")
        if module in production_modules:
            findings.append({
                "severity": "error",
                "policy": "retirement_lockout",
                "rule": "retired_module_not_in_production_manifest",
                "module": module,
                "message": f"Module '{module}' is RETIRE but still present in production_modules",
            })
        if tier == "research":
            # Research modules are expected to be retired — verify they are
            # acknowledged as needing research feature gate
            decision = ablation_decisions.get(module, {})
            if decision.get("migration_action", "") == "none":
                findings.append({
                    "severity": "error",
                    "policy": "retirement_lockout",
                    "rule": "research_must_have_migration_action",
                    "module": module,
                    "message": f"Research module '{module}' has RETIRE decision but no migration action",
                })

    if production_feature not in default_features:
        findings.append({
            "severity": "error",
            "policy": "retirement_lockout",
            "rule": "production_feature_must_be_default",
            "module": production_feature,
            "message": f"Manifest default_feature_set must include '{production_feature}'",
        })
    if research_feature not in optional_features:
        findings.append({
            "severity": "error",
            "policy": "retirement_lockout",
            "rule": "research_feature_must_be_optional",
            "module": research_feature,
            "message": f"Manifest optional_feature_set must include '{research_feature}'",
        })

    # === POLICY 3: UNKNOWN BLOCK ===
    # Modules with BLOCK decision in ablation are hard-blocked
    blocked_modules = {
        m for m, d in ablation_decisions.items()
        if d["decision"] == "BLOCK"
    }
    for module in sorted(blocked_modules):
        findings.append({
            "severity": "error",
            "policy": "unknown_block",
            "rule": "unclassified_module_blocked",
            "module": module,
            "message": f"Module '{module}' has BLOCK decision — unclassified modules cannot be admitted",
        })

    # === POLICY 4: PRODUCTION CORE COMPLETENESS ===
    # All production_core modules in governance must exist in the production set.
    for module, tier in sorted(governance_modules.items()):
        if tier == "production_core" and module not in production_modules:
            findings.append({
                "severity": "warning",
                "policy": "completeness",
                "rule": "production_core_must_be_in_manifest",
                "module": module,
                "message": f"Production core module '{module}' classified in governance but missing from manifest",
            })

    # === POLICY 5: RETIREMENT REACTIVATION GUARD ===
    # Cross-check: if a module was RETIRE in the ablation but somehow
    # has tier changed to production_core without re-ablation, flag it
    for module in sorted(retired_modules):
        tier = governance_modules.get(module, "unknown")
        if tier in ("production_core", "production_monitor"):
            findings.append({
                "severity": "error",
                "policy": "retirement_lockout",
                "rule": "retired_module_cannot_be_production",
                "module": module,
                "message": (
                    f"Module '{module}' has RETIRE ablation decision but governance "
                    f"tier is '{tier}' — possible silent reactivation. "
                    f"Re-run ablation after governance reclassification."
                ),
            })

    # === POLICY 6: TOOLING CONTRACT ===
    # Admission evidence must be traceable through asupersync + frankentui tooling hooks.
    if "parse_error" in tooling_contract:
        findings.append({
            "severity": "error",
            "policy": "tooling_contract",
            "rule": "harness_manifest_parseable_required",
            "module": "frankenlibc-harness",
            "message": (
                f"Harness Cargo manifest parse failed: {tooling_contract['parse_error']}"
            ),
        })
    tooling_rules = [
        (
            "asupersync_dependency_required",
            "has_asupersync_dependency",
            "Harness must depend on asupersync-conformance",
        ),
        (
            "asupersync_feature_required",
            "asupersync_feature_present",
            "Harness must expose asupersync-tooling feature bound to dep:asupersync-conformance",
        ),
        (
            "asupersync_default_enable_required",
            "default_enables_asupersync_tooling",
            "Harness default feature set must include asupersync-tooling",
        ),
        (
            "frankentui_feature_required",
            "frankentui_feature_present",
            "Harness must expose frankentui-ui feature bound to dep:ftui-harness",
        ),
        (
            "frankentui_dependency_set_required",
            "frankentui_dependency_set_complete",
            "Harness frankentui-ui feature requires ftui-* dependency set",
        ),
    ]
    for rule, key, message in tooling_rules:
        if not tooling_contract.get(key, False):
            findings.append({
                "severity": "error",
                "policy": "tooling_contract",
                "rule": rule,
                "module": "frankenlibc-harness",
                "message": message,
            })

    # Build controller manifest dossier entries (explicit audit surface).
    controller_manifest_entries: list[dict[str, Any]] = []
    for module in sorted(set(manifest_modules) | set(governance_modules.keys())):
        tier = governance_modules.get(module, "unclassified")
        linkage_entry = linkage_modules.get(module)
        value_target = value_targets.get(module)
        cost_target = _cost_target_for_tier(tier)

        if not isinstance(linkage_entry, dict):
            linkage_entry = {}

        controller_manifest_entries.append({
            "module": module,
            "tier": tier,
            "in_manifest": module in manifest_modules,
            "in_production_manifest": module in production_modules,
            "in_research_only_manifest": module in research_only_modules,
            "decision_hook": linkage_entry.get("decision_target"),
            "invariant": linkage_entry.get("invariant"),
            "fallback_when_data_missing": linkage_entry.get("fallback_when_data_missing"),
            "action_outputs": linkage_entry.get("action_outputs", []),
            "evidence_inputs": linkage_entry.get("evidence_inputs", []),
            "runtime_cost_target": cost_target,
            "benefit_target": value_target,
        })

    # Build summary
    errors = sum(1 for f in findings if f["severity"] == "error")
    warnings = sum(1 for f in findings if f["severity"] == "warning")
    status = "pass" if errors == 0 else "fail"

    controller_manifest_summary = {
        "total_entries": len(controller_manifest_entries),
        "production_manifest_entries": sum(
            1 for e in controller_manifest_entries if e["in_production_manifest"]
        ),
        "missing_decision_hook": sum(
            1
            for e in controller_manifest_entries
            if e["in_production_manifest"] and not e.get("decision_hook")
        ),
        "missing_invariant": sum(
            1
            for e in controller_manifest_entries
            if e["in_production_manifest"] and not e.get("invariant")
        ),
        "missing_fallback": sum(
            1
            for e in controller_manifest_entries
            if e["in_production_manifest"] and not e.get("fallback_when_data_missing")
        ),
        "missing_benefit_target": sum(
            1
            for e in controller_manifest_entries
            if e["in_production_manifest"]
            and e.get("tier") in {"production_core", "production_monitor"}
            and not e.get("benefit_target")
        ),
    }

    # Build admission ledger: per-module policy status
    admission_ledger = []
    for module in sorted(set(manifest_modules) | set(governance_modules.keys())):
        tier = governance_modules.get(module, "unclassified")
        decision = ablation_decisions.get(module, {}).get("decision", "NO_EVIDENCE")
        in_manifest = module in manifest_modules
        in_production_manifest = module in production_modules
        in_research_only_manifest = module in research_only_modules
        in_governance = module in governance_modules

        if decision == "RETAIN" and in_production_manifest and in_governance:
            admission_status = "ADMITTED"
        elif decision == "RETIRE":
            admission_status = "RETIRED"
        elif decision == "BLOCK":
            admission_status = "BLOCKED"
        elif not in_governance:
            admission_status = "BLOCKED_NO_GOVERNANCE"
        elif not in_manifest:
            admission_status = "NOT_IN_MANIFEST"
        else:
            admission_status = "REVIEW"

        admission_ledger.append({
            "module": module,
            "tier": tier,
            "ablation_decision": decision,
            "admission_status": admission_status,
            "in_manifest": in_manifest,
            "in_production_manifest": in_production_manifest,
            "in_research_only_manifest": in_research_only_manifest,
            "in_governance": in_governance,
        })

    report = {
        "schema_version": "v1",
        "bead": "bd-w2c3.5.3",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": status,
        "summary": {
            "total_modules": len(set(manifest_modules) | set(governance_modules.keys())),
            "admitted": sum(1 for a in admission_ledger if a["admission_status"] == "ADMITTED"),
            "retired": sum(1 for a in admission_ledger if a["admission_status"] == "RETIRED"),
            "blocked": sum(1 for a in admission_ledger if a["admission_status"].startswith("BLOCKED")),
            "errors": errors,
            "warnings": warnings,
        },
        "controller_manifest_summary": controller_manifest_summary,
        "policies_enforced": [
            "admission: governance_classification_required",
            "admission: ablation_evidence_required",
            "controller_manifest: linkage_required",
            "controller_manifest: decision_target_required",
            "controller_manifest: invariant_required",
            "controller_manifest: fallback_when_data_missing_required",
            "controller_manifest: value_target_required",
            "retirement_lockout: research_must_have_migration_action",
            "retirement_lockout: retired_module_not_in_production_manifest",
            "retirement_lockout: production_feature_must_be_default",
            "retirement_lockout: research_feature_must_be_optional",
            "retirement_lockout: retired_module_cannot_be_production",
            "unknown_block: unclassified_module_blocked",
            "completeness: production_core_must_be_in_manifest",
            "tooling_contract: asupersync_dependency_required",
            "tooling_contract: asupersync_feature_required",
            "tooling_contract: asupersync_default_enable_required",
            "tooling_contract: frankentui_feature_required",
            "tooling_contract: frankentui_dependency_set_required",
        ],
        "admission_ledger": admission_ledger,
        "findings": findings,
        "feature_gate_config": {
            "default": sorted(default_features),
            "optional": sorted(optional_features),
            "production_gate": production_feature,
            "research_gate": research_feature,
        },
        "artifacts_consumed": {
            "governance": str(governance_path.relative_to(repo_root)),
            "manifest": str(manifest_path.relative_to(repo_root)),
            "ablation_report": str(ablation_path.relative_to(repo_root)),
            "linkage": str(linkage_path.relative_to(repo_root)),
            "value_proof": str(value_proof_path.relative_to(repo_root)),
            "harness_cargo_manifest": str(harness_cargo_path.relative_to(repo_root)),
        },
        "artifact_integrity": artifact_integrity,
        "tooling_contract": tooling_contract,
        "artifacts_emitted": {
            "admission_gate_report": "tests/runtime_math/admission_gate_report.v1.json",
            "controller_manifest": "tests/runtime_math/controller_manifest.v1.json",
            "structured_log": "target/conformance/runtime_math_admission_gate.log.jsonl",
        },
    }

    controller_manifest = {
        "schema_version": "v1",
        "bead": "bd-w2c3.5.3",
        "generated_at": report["generated_at"],
        "description": (
            "Controller-by-controller runtime-math manifest linking decision hook, "
            "invariant, fallback behavior, runtime cost target, and measurable value target."
        ),
        "retention_threshold": retention_threshold,
        "sources": {
            "governance": str(governance_path.relative_to(repo_root)),
            "manifest": str(manifest_path.relative_to(repo_root)),
            "linkage": str(linkage_path.relative_to(repo_root)),
            "value_proof": str(value_proof_path.relative_to(repo_root)),
            "ablation_report": str(ablation_path.relative_to(repo_root)),
        },
        "summary": controller_manifest_summary,
        "controllers": controller_manifest_entries,
    }

    print(json.dumps(report, indent=2))

    # Write artifacts
    artifact_path = repo_root / "tests/runtime_math/admission_gate_report.v1.json"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    with artifact_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")

    controller_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with controller_manifest_path.open("w", encoding="utf-8") as f:
        json.dump(controller_manifest, f, indent=2)
        f.write("\n")

    log_event = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "trace_id": trace_id,
        "level": "error" if errors > 0 else "info",
        "event": "runtime_math_admission_gate",
        "bead_id": "bd-w2c3.5.3",
        "mode": "strict",
        "api_family": "runtime_math",
        "symbol": "production_admission_retirement_gate",
        "decision_path": "governance+ablation+linkage+value_target+integrity+tooling_contract",
        "healing_action": "None",
        "outcome": "fail" if errors > 0 else "pass",
        "errno": 1 if errors > 0 else 0,
        "latency_ns": time.time_ns() - start_ns,
        "artifact_refs": [
            str(artifact_path.relative_to(repo_root)),
            str(controller_manifest_path.relative_to(repo_root)),
            str(structured_log_path.relative_to(repo_root)),
            str(governance_path.relative_to(repo_root)),
            str(manifest_path.relative_to(repo_root)),
            str(ablation_path.relative_to(repo_root)),
            str(linkage_path.relative_to(repo_root)),
            str(value_proof_path.relative_to(repo_root)),
            str(harness_cargo_path.relative_to(repo_root)),
        ],
        "details": {
            "status": status,
            "summary": report["summary"],
            "finding_count": len(findings),
            "policies_enforced": report["policies_enforced"],
            "artifact_integrity": report["artifact_integrity"],
            "tooling_contract": report["tooling_contract"],
        },
    }
    structured_log_path.parent.mkdir(parents=True, exist_ok=True)
    with structured_log_path.open("w", encoding="utf-8") as f:
        f.write(json.dumps(log_event, separators=(",", ":")) + "\n")

    if errors > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
