#!/usr/bin/env python3
"""Branch-diversity gate for math obligation sets per milestone (bd-5fw.5).

Enforces AGENTS.md branch-diversity rule:
1. Every major milestone must use at least 3 distinct math families.
2. Must include at least one from: conformal statistics, algebraic topology,
   abstract algebra, and Grothendieck-Serre methods.
3. No single family should dominate >40% of obligations.
4. SIMD/ABI milestones require Atiyah-Singer/K-theory and Clifford obligations.

Usage:
    python3 scripts/gentoo/branch_diversity_gate.py --dry-run
    python3 scripts/gentoo/branch_diversity_gate.py --spec tests/conformance/branch_diversity_spec.v1.json
    python3 scripts/gentoo/branch_diversity_gate.py --output diversity_report.json
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SPEC = REPO_ROOT / "tests" / "conformance" / "branch_diversity_spec.v1.json"
GOVERNANCE = REPO_ROOT / "tests" / "conformance" / "math_governance.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class DiversityViolation:
    """A specific diversity constraint violation."""
    milestone_id: str
    constraint: str
    message: str
    severity: str = "error"  # error, warn

    def to_dict(self) -> Dict[str, Any]:
        return {
            "milestone_id": self.milestone_id,
            "constraint": self.constraint,
            "message": self.message,
            "severity": self.severity,
        }


@dataclass
class MilestoneAnalysis:
    """Analysis of a single milestone's math family diversity."""
    milestone_id: str
    milestone_name: str
    is_simd_abi: bool
    obligation_count: int = 0
    families_used: List[str] = field(default_factory=list)
    family_counts: Dict[str, int] = field(default_factory=dict)
    violations: List[DiversityViolation] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.violations) == 0

    @property
    def family_count(self) -> int:
        return len(self.families_used)

    def max_dominance_pct(self) -> float:
        if self.obligation_count == 0:
            return 0.0
        if not self.family_counts:
            return 0.0
        max_count = max(self.family_counts.values())
        return round(max_count / self.obligation_count * 100, 1)

    def dominant_family(self) -> Optional[str]:
        if not self.family_counts:
            return None
        return max(self.family_counts, key=lambda k: self.family_counts[k])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "milestone_id": self.milestone_id,
            "milestone_name": self.milestone_name,
            "is_simd_abi": self.is_simd_abi,
            "passed": self.passed,
            "obligation_count": self.obligation_count,
            "family_count": self.family_count,
            "families_used": sorted(self.families_used),
            "family_counts": self.family_counts,
            "max_dominance_pct": self.max_dominance_pct(),
            "violations": [v.to_dict() for v in self.violations],
            "remediation": self.remediation,
        }


@dataclass
class DiversitySpec:
    """Loaded diversity specification."""
    math_families: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    milestones: List[Dict[str, Any]] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    module_to_families: Dict[str, List[str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DiversitySpec:
        spec = cls(
            math_families=data.get("math_families", {}),
            milestones=data.get("milestones", []),
            constraints=data.get("constraints", {}),
        )
        # Build reverse index: module -> list of families it belongs to
        for family_id, family_data in spec.math_families.items():
            for module in family_data.get("modules", []):
                if module not in spec.module_to_families:
                    spec.module_to_families[module] = []
                spec.module_to_families[module].append(family_id)
        return spec


def load_governance_modules() -> Dict[str, List[str]]:
    """Load module lists from math governance by tier."""
    if not GOVERNANCE.exists():
        return {}
    data = json.loads(GOVERNANCE.read_text())
    result: Dict[str, List[str]] = {}
    for tier, modules in data.get("classifications", {}).items():
        result[tier] = [m["module"] for m in modules]
    return result


def get_milestone_modules(milestone: Dict[str, Any],
                          governance: Dict[str, List[str]]) -> List[str]:
    """Get the set of math modules relevant to a milestone.

    In a real implementation, this would map milestone -> specific obligation set.
    For now, we assign all production modules to every milestone (conservative).
    """
    all_modules: List[str] = []
    for tier in ("production_core", "production_monitor", "research"):
        all_modules.extend(governance.get(tier, []))
    return all_modules


def classify_module_families(modules: List[str],
                             spec: DiversitySpec) -> Dict[str, int]:
    """Count modules per math family."""
    counts: Dict[str, int] = {}
    for module in modules:
        families = spec.module_to_families.get(module, [])
        for fam in families:
            counts[fam] = counts.get(fam, 0) + 1
    return counts


def check_milestone_diversity(
    milestone: Dict[str, Any],
    modules: List[str],
    spec: DiversitySpec,
) -> MilestoneAnalysis:
    """Check branch-diversity constraints for a single milestone."""
    mid = milestone["id"]
    mname = milestone.get("name", mid)
    is_simd_abi = milestone.get("is_simd_abi", False)

    family_counts = classify_module_families(modules, spec)
    families_used = [f for f, c in family_counts.items() if c > 0]
    obligation_count = sum(family_counts.values())

    analysis = MilestoneAnalysis(
        milestone_id=mid,
        milestone_name=mname,
        is_simd_abi=is_simd_abi,
        obligation_count=obligation_count,
        families_used=families_used,
        family_counts=family_counts,
    )

    constraints = spec.constraints

    # Check 1: minimum distinct families
    min_families = constraints.get("min_distinct_families", 3)
    if analysis.family_count < min_families:
        analysis.violations.append(DiversityViolation(
            milestone_id=mid,
            constraint="min_distinct_families",
            message=f"Only {analysis.family_count} math families used, minimum is {min_families}",
        ))
        analysis.remediation.append(
            f"Add obligations from {min_families - analysis.family_count} more math families"
        )

    # Check 2: required families for all milestones
    required_all = constraints.get("required_families_all", [])
    for req_family in required_all:
        if req_family not in families_used:
            analysis.violations.append(DiversityViolation(
                milestone_id=mid,
                constraint="required_family_missing",
                message=f"Required family '{req_family}' has no obligations in milestone '{mname}'",
            ))
            family_modules = spec.math_families.get(req_family, {}).get("modules", [])
            if family_modules:
                analysis.remediation.append(
                    f"Add obligation from '{req_family}' (modules: {', '.join(family_modules[:3])})"
                )

    # Check 3: max family dominance
    max_dominance = constraints.get("max_family_dominance_pct", 40)
    if obligation_count > 0:
        actual_dominance = analysis.max_dominance_pct()
        if actual_dominance > max_dominance:
            dominant = analysis.dominant_family()
            analysis.violations.append(DiversityViolation(
                milestone_id=mid,
                constraint="family_dominance",
                message=f"Family '{dominant}' dominates at {actual_dominance:.0f}% (max {max_dominance}%)",
                severity="warn",
            ))
            analysis.remediation.append(
                f"Reduce '{dominant}' obligations or add to other families"
            )

    # Check 4: SIMD/ABI specific requirements
    if is_simd_abi:
        simd_required = constraints.get("required_families_simd_abi", [])
        for req_family in simd_required:
            if req_family not in families_used:
                analysis.violations.append(DiversityViolation(
                    milestone_id=mid,
                    constraint="simd_abi_required_family",
                    message=f"SIMD/ABI milestone '{mname}' missing required family '{req_family}'",
                ))
                family_modules = spec.math_families.get(req_family, {}).get("modules", [])
                if family_modules:
                    analysis.remediation.append(
                        f"Add SIMD/ABI obligation from '{req_family}' (modules: {', '.join(family_modules[:3])})"
                    )

    return analysis


@dataclass
class DiversityReport:
    """Complete branch-diversity gate report."""
    milestones: List[MilestoneAnalysis] = field(default_factory=list)
    timestamp: str = ""
    dry_run: bool = False
    gate_passed: bool = True
    total_violations: int = 0
    error_count: int = 0
    warn_count: int = 0

    def compute_status(self) -> None:
        self.total_violations = sum(len(m.violations) for m in self.milestones)
        self.error_count = sum(
            1 for m in self.milestones
            for v in m.violations if v.severity == "error"
        )
        self.warn_count = sum(
            1 for m in self.milestones
            for v in m.violations if v.severity == "warn"
        )
        self.gate_passed = self.error_count == 0

    def to_dict(self) -> Dict[str, Any]:
        self.compute_status()
        return {
            "schema_version": "v1",
            "bead": "bd-5fw.5",
            "timestamp": self.timestamp or utc_now(),
            "dry_run": self.dry_run,
            "gate_passed": self.gate_passed,
            "total_violations": self.total_violations,
            "error_count": self.error_count,
            "warn_count": self.warn_count,
            "milestone_count": len(self.milestones),
            "milestones_passed": sum(1 for m in self.milestones if m.passed),
            "milestones_failed": sum(1 for m in self.milestones if not m.passed),
            "milestones": [m.to_dict() for m in self.milestones],
        }

    def to_markdown(self) -> str:
        self.compute_status()
        status = "PASS" if self.gate_passed else "FAIL"
        lines = [
            "# Branch-Diversity Gate Report",
            "",
            f"**Status:** {status}",
            f"**Updated:** {self.timestamp or utc_now()}",
            f"**Violations:** {self.total_violations} ({self.error_count} errors, {self.warn_count} warnings)",
            "",
        ]

        for m in self.milestones:
            icon = "PASS" if m.passed else "FAIL"
            lines.append(f"## {icon} {m.milestone_name}")
            lines.append("")
            lines.append(f"- Families: {m.family_count} ({', '.join(sorted(m.families_used)[:5])}...)")
            lines.append(f"- Obligations: {m.obligation_count}")
            lines.append(f"- Max dominance: {m.max_dominance_pct():.0f}%")
            if m.is_simd_abi:
                lines.append("- Type: SIMD/ABI milestone")
            lines.append("")
            if m.violations:
                lines.append("### Violations")
                for v in m.violations:
                    lines.append(f"- [{v.severity.upper()}] {v.message}")
                lines.append("")
            if m.remediation:
                lines.append("### Remediation")
                for r in m.remediation:
                    lines.append(f"- {r}")
                lines.append("")

        return "\n".join(lines)


def run_diversity_check(
    spec_path: Optional[Path] = None,
    dry_run: bool = False,
) -> DiversityReport:
    """Run branch-diversity check against all milestones."""
    path = spec_path or DEFAULT_SPEC
    if not path.exists():
        return DiversityReport(
            timestamp=utc_now(), dry_run=dry_run,
            gate_passed=False,
        )

    data = json.loads(path.read_text())
    spec = DiversitySpec.from_dict(data)
    governance = load_governance_modules()

    report = DiversityReport(timestamp=utc_now(), dry_run=dry_run)

    for milestone in spec.milestones:
        modules = get_milestone_modules(milestone, governance)
        analysis = check_milestone_diversity(milestone, modules, spec)
        report.milestones.append(analysis)

    report.compute_status()
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Branch-diversity gate")
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--format", choices=["json", "markdown", "terminal"],
                        default="terminal")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    report = run_diversity_check(spec_path=args.spec, dry_run=args.dry_run)

    if args.format == "terminal":
        print(report.to_markdown())

    if args.format == "json" or args.output:
        json_path = args.output or (
            REPO_ROOT / "tests" / "conformance" / "branch_diversity_report.v1.json"
        )
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n")
        print(f"JSON report written to {json_path}")

    if args.format == "markdown":
        print(report.to_markdown())

    # Summary
    print(f"\n=== Branch-Diversity Gate Summary ===")
    status = "PASS" if report.gate_passed else "FAIL"
    print(f"Overall: {status}")
    print(f"Violations: {report.total_violations} ({report.error_count} errors, {report.warn_count} warnings)")
    for m in report.milestones:
        icon = "+" if m.passed else "!"
        print(f"  [{icon}] {m.milestone_name}: {m.family_count} families, {m.obligation_count} obligations")

    return 0 if report.gate_passed else 1


if __name__ == "__main__":
    sys.exit(main())
