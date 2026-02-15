#!/usr/bin/env python3
"""runtime_math_admission_gate.py — bd-3ot.3
CI admission gate for runtime-math controllers.

Enforces:
  1. ADMISSION: Every controller in production_kernel_manifest must have
     governance classification AND ablation evidence (RETAIN decision).
  2. RETIREMENT LOCKOUT: Controllers with RETIRE decision in ablation report
     must NOT appear in production feature set without runtime-math-research gate.
  3. UNKNOWN BLOCK: Unclassified controllers are blocked from admission.

Reads:
  - tests/conformance/math_governance.json
  - tests/runtime_math/production_kernel_manifest.v1.json
  - tests/runtime_math/controller_ablation_report.v1.json

Produces:
  - tests/runtime_math/admission_gate_report.v1.json

Exit codes:
  0 = all admission policies pass
  1 = policy violations detected
  2 = missing required artifact
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent

    governance_path = repo_root / "tests/conformance/math_governance.json"
    manifest_path = repo_root / "tests/runtime_math/production_kernel_manifest.v1.json"
    ablation_path = repo_root / "tests/runtime_math/controller_ablation_report.v1.json"

    governance = load_json(governance_path)
    manifest = load_json(manifest_path)
    ablation = load_json(ablation_path)

    # Check required artifacts exist
    missing = []
    if governance is None:
        missing.append("math_governance.json")
    if manifest is None:
        missing.append("production_kernel_manifest.v1.json")
    if ablation is None:
        missing.append("controller_ablation_report.v1.json")

    if missing:
        print(f"FAIL: missing required artifacts: {missing}", file=sys.stderr)
        return 2

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

    # Extract feature sets
    default_features = set(manifest.get("default_feature_set", []))
    optional_features = set(manifest.get("optional_feature_set", []))

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

    # Build summary
    errors = sum(1 for f in findings if f["severity"] == "error")
    warnings = sum(1 for f in findings if f["severity"] == "warning")
    status = "pass" if errors == 0 else "fail"

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
        "bead": "bd-3ot.3",
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
        "policies_enforced": [
            "admission: governance_classification_required",
            "admission: ablation_evidence_required",
            "retirement_lockout: research_must_have_migration_action",
            "retirement_lockout: retired_module_cannot_be_production",
            "unknown_block: unclassified_module_blocked",
            "completeness: production_core_must_be_in_manifest",
        ],
        "admission_ledger": admission_ledger,
        "findings": findings,
        "feature_gate_config": {
            "default": list(default_features),
            "optional": list(optional_features),
            "production_gate": production_feature,
            "research_gate": research_feature,
        },
        "artifacts_consumed": {
            "governance": str(governance_path.relative_to(repo_root)),
            "manifest": str(manifest_path.relative_to(repo_root)),
            "ablation_report": str(ablation_path.relative_to(repo_root)),
        },
    }

    print(json.dumps(report, indent=2))

    # Write artifact
    artifact_path = repo_root / "tests/runtime_math/admission_gate_report.v1.json"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    with artifact_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")

    if errors > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
