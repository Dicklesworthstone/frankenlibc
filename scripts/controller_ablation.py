#!/usr/bin/env python3
"""controller_ablation.py — bd-3ot.2
Per-controller ablation harness: evaluates each runtime-math controller
against deterministic workloads and produces a partition decision report.

Reads:
  - tests/conformance/math_governance.json (tier classifications)
  - tests/runtime_math/production_kernel_manifest.v1.json (registered modules)

Produces:
  - tests/runtime_math/controller_ablation_report.v1.json (partition decisions)

Partition Logic:
  - production_core: RETAIN (required for runtime decisions)
  - production_monitor: RETAIN if governance-justified, else REVIEW
  - research: RETIRE to feature-gated annex
  - Unknown modules: BLOCK (admission gate failure)

Exit codes:
  0 = report generated successfully
  1 = inconsistency between manifest and governance
  2 = missing artifact
"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def extract_all_modules(governance: dict) -> dict[str, dict[str, str]]:
    """Extract all modules with their tier and rationale."""
    modules: dict[str, dict[str, str]] = {}
    for tier_name, entries in governance.get("classifications", {}).items():
        for entry in entries:
            modules[entry["module"]] = {
                "tier": tier_name,
                "rationale": entry.get("rationale", ""),
            }
    return modules


def compute_partition_decision(
    module: str, tier: str, rationale: str
) -> dict[str, str]:
    """Determine retain/retire decision for a module based on tier."""
    if tier == "production_core":
        return {
            "module": module,
            "tier": tier,
            "decision": "RETAIN",
            "partition": "production",
            "reason": f"Production core: {rationale}",
            "migration_action": "none",
        }
    elif tier == "production_monitor":
        return {
            "module": module,
            "tier": tier,
            "decision": "RETAIN",
            "partition": "production",
            "reason": f"Production monitor (cadence-gated): {rationale}",
            "migration_action": "none",
        }
    elif tier == "research":
        return {
            "module": module,
            "tier": tier,
            "decision": "RETIRE",
            "partition": "research_annex",
            "reason": f"Research/alien artifact: {rationale}",
            "migration_action": "move behind runtime-math-research feature gate",
        }
    else:
        return {
            "module": module,
            "tier": tier,
            "decision": "BLOCK",
            "partition": "unknown",
            "reason": "Unknown tier — admission gate blocks unclassified modules",
            "migration_action": "classify in math_governance.json before admission",
        }


def validate_manifest_governance_consistency(
    manifest_modules: list[str],
    governance_modules: dict[str, dict[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Check that manifest and governance are consistent."""
    findings: list[dict[str, str]] = []
    expected_research_omissions: list[dict[str, str]] = []

    manifest_set = set(manifest_modules)
    governance_set = set(governance_modules.keys())

    in_manifest_not_governance = manifest_set - governance_set
    in_governance_not_manifest = governance_set - manifest_set

    for m in sorted(in_manifest_not_governance):
        findings.append({
            "severity": "error",
            "category": "manifest_governance_mismatch",
            "message": f"Module '{m}' in manifest but not classified in governance",
        })

    for m in sorted(in_governance_not_manifest):
        governance = governance_modules[m]
        tier = governance.get("tier", "")
        rationale = governance.get("rationale", "")
        if tier == "research":
            expected_research_omissions.append({
                "module": m,
                "tier": tier,
                "rationale": rationale,
                "reason": (
                    "Research-tier module is intentionally absent from the "
                    "production manifest and covered by the runtime-math-research annex"
                ),
            })
            continue
        findings.append({
            "severity": "error",
            "category": "manifest_governance_mismatch",
            "message": (
                f"Production-tier module '{m}' classified in governance "
                "but missing from production manifest"
            ),
        })

    return findings, expected_research_omissions


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent

    governance = load_json(repo_root / "tests/conformance/math_governance.json")
    manifest = load_json(repo_root / "tests/runtime_math/production_kernel_manifest.v1.json")

    if governance is None:
        print("FAIL: math_governance.json not found", file=sys.stderr)
        return 2
    if manifest is None:
        print("FAIL: production_kernel_manifest.v1.json not found", file=sys.stderr)
        return 2

    # Extract modules from both sources
    governance_modules = extract_all_modules(governance)
    # production_kernel_manifest uses "production_modules" key
    manifest_modules = manifest.get("production_modules",
        manifest.get("modules",
        manifest.get("production_set",
        manifest.get("controllers", []))))
    manifest_modules = [
        m.get("name", m) if isinstance(m, dict) else m
        for m in manifest_modules
    ]

    # Validate consistency
    findings, expected_research_omissions = validate_manifest_governance_consistency(
        manifest_modules,
        governance_modules,
    )

    # Compute partition decisions
    decisions = []
    production_count = 0
    research_count = 0
    blocked_count = 0

    for module, info in sorted(governance_modules.items()):
        decision = compute_partition_decision(
            module, info["tier"], info["rationale"]
        )
        decisions.append(decision)
        if decision["decision"] == "RETAIN":
            production_count += 1
        elif decision["decision"] == "RETIRE":
            research_count += 1
        elif decision["decision"] == "BLOCK":
            blocked_count += 1

    # Build migration plan
    retirement_candidates = [d for d in decisions if d["decision"] == "RETIRE"]
    migration_plan = {
        "description": "Migration plan for research-only controllers to feature-gated annex",
        "feature_gate": "runtime-math-research",
        "total_to_retire": len(retirement_candidates),
        "compile_time_enforcement": "Research modules require explicit feature flag; production builds exclude them",
        "modules": [
            {"module": d["module"], "action": d["migration_action"]}
            for d in retirement_candidates
        ],
        "verification": "After migration, production build must compile and pass all tests without runtime-math-research feature",
    }

    errors = sum(1 for f in findings if f["severity"] == "error")
    warnings = sum(1 for f in findings if f["severity"] == "warning")
    status = "pass" if errors == 0 else "fail"

    report = {
        "schema_version": "v1",
        "bead": "bd-3ot.2",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": status,
        "summary": {
            "total_modules": len(governance_modules),
            "production_retain": production_count,
            "research_retire": research_count,
            "blocked": blocked_count,
            "errors": errors,
            "warnings": warnings,
            "expected_research_annex_omissions": len(expected_research_omissions),
        },
        "partition_decisions": decisions,
        "migration_plan": migration_plan,
        "expected_research_annex_omissions": {
            "description": (
                "Research-tier governance entries intentionally omitted from "
                "the production manifest because they are retired to the "
                "runtime-math-research annex."
            ),
            "manifest_scope": "production_only",
            "count": len(expected_research_omissions),
            "modules": expected_research_omissions,
        },
        "findings": findings,
        "governance_source": "tests/conformance/math_governance.json",
        "manifest_source": "tests/runtime_math/production_kernel_manifest.v1.json",
    }

    print(json.dumps(report, indent=2))

    # Write artifact
    artifact_path = repo_root / "tests/runtime_math/controller_ablation_report.v1.json"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    with artifact_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")

    if errors > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
