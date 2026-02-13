#!/usr/bin/env python3
"""Proof obligations binder validator (bd-5fw.4).

Validates the proof obligations binder: checks that every obligation has
valid evidence artifacts and enforcing gates, reports missing/invalid entries.

Usage:
    python3 scripts/gentoo/proof_binder_validator.py --dry-run
    python3 scripts/gentoo/proof_binder_validator.py --binder tests/conformance/proof_obligations_binder.v1.json
    python3 scripts/gentoo/proof_binder_validator.py --output validation_report.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BINDER = (
    REPO_ROOT / "tests" / "conformance" / "proof_obligations_binder.v1.json"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_sha256(path: Path) -> Optional[str]:
    """Compute SHA-256 hash of a file."""
    if not path.exists():
        return None
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


@dataclass
class ObligationViolation:
    """A validation violation for a proof obligation."""
    obligation_id: str
    violation_code: str
    message: str
    remediation_hint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "obligation_id": self.obligation_id,
            "violation_code": self.violation_code,
            "message": self.message,
        }
        if self.remediation_hint:
            d["remediation_hint"] = self.remediation_hint
        return d


@dataclass
class ObligationStatus:
    """Validation status of a single proof obligation."""
    obligation_id: str
    statement: str
    category: str
    valid: bool = True
    evidence_found: int = 0
    evidence_missing: int = 0
    gates_found: int = 0
    gates_missing: int = 0
    violations: List[ObligationViolation] = field(default_factory=list)
    evidence_hashes: Dict[str, Optional[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "statement": self.statement,
            "category": self.category,
            "valid": self.valid,
            "evidence_found": self.evidence_found,
            "evidence_missing": self.evidence_missing,
            "gates_found": self.gates_found,
            "gates_missing": self.gates_missing,
            "violations": [v.to_dict() for v in self.violations],
            "evidence_hashes": self.evidence_hashes,
        }


@dataclass
class BinderValidationReport:
    """Complete binder validation report."""
    obligations: List[ObligationStatus] = field(default_factory=list)
    timestamp: str = ""
    dry_run: bool = False
    binder_valid: bool = True
    total_obligations: int = 0
    valid_obligations: int = 0
    invalid_obligations: int = 0
    total_violations: int = 0
    categories_covered: List[str] = field(default_factory=list)

    def compute_status(self) -> None:
        self.total_obligations = len(self.obligations)
        self.valid_obligations = sum(1 for o in self.obligations if o.valid)
        self.invalid_obligations = self.total_obligations - self.valid_obligations
        self.total_violations = sum(len(o.violations) for o in self.obligations)
        self.binder_valid = self.invalid_obligations == 0
        cats: Set[str] = set()
        for o in self.obligations:
            cats.add(o.category)
        self.categories_covered = sorted(cats)

    def to_dict(self) -> Dict[str, Any]:
        self.compute_status()
        return {
            "schema_version": "v1",
            "bead": "bd-5fw.4",
            "timestamp": self.timestamp or utc_now(),
            "dry_run": self.dry_run,
            "binder_valid": self.binder_valid,
            "total_obligations": self.total_obligations,
            "valid_obligations": self.valid_obligations,
            "invalid_obligations": self.invalid_obligations,
            "total_violations": self.total_violations,
            "categories_covered": self.categories_covered,
            "obligations": [o.to_dict() for o in self.obligations],
        }

    def to_markdown(self) -> str:
        self.compute_status()
        status = "PASS" if self.binder_valid else "FAIL"
        lines = [
            "# Proof Obligations Binder Validation",
            "",
            f"**Status:** {status}",
            f"**Updated:** {self.timestamp or utc_now()}",
            f"**Obligations:** {self.valid_obligations}/{self.total_obligations} valid",
            f"**Categories:** {len(self.categories_covered)}",
            "",
        ]

        by_cat: Dict[str, List[ObligationStatus]] = {}
        for o in self.obligations:
            by_cat.setdefault(o.category, []).append(o)

        for cat in sorted(by_cat.keys()):
            lines.append(f"## {cat}")
            lines.append("")
            for o in by_cat[cat]:
                icon = "PASS" if o.valid else "FAIL"
                lines.append(f"- [{icon}] **{o.obligation_id}**: {o.statement[:80]}")
                if o.violations:
                    for v in o.violations:
                        lines.append(f"  - {v.violation_code}: {v.message}")
                        if v.remediation_hint:
                            lines.append(f"    Hint: {v.remediation_hint}")
            lines.append("")

        return "\n".join(lines)


def validate_obligation(
    obligation: Dict[str, Any],
    repo_root: Path,
    check_hashes: bool = True,
) -> ObligationStatus:
    """Validate a single proof obligation."""
    oid = obligation.get("id", "unknown")
    status = ObligationStatus(
        obligation_id=oid,
        statement=obligation.get("statement", ""),
        category=obligation.get("category", "unknown"),
    )

    # Check evidence artifacts exist
    for artifact_path in obligation.get("evidence_artifacts", []):
        full_path = repo_root / artifact_path
        if full_path.exists():
            status.evidence_found += 1
            if check_hashes:
                status.evidence_hashes[artifact_path] = file_sha256(full_path)
        else:
            status.evidence_missing += 1
            status.valid = False
            status.violations.append(ObligationViolation(
                obligation_id=oid,
                violation_code="EVIDENCE_MISSING",
                message=f"Evidence artifact not found: {artifact_path}",
                remediation_hint=f"Create or generate the artifact at {artifact_path}",
            ))

    # Check gates exist
    for gate_path in obligation.get("gates", []):
        full_path = repo_root / gate_path
        if full_path.exists():
            status.gates_found += 1
        else:
            status.gates_missing += 1
            status.valid = False
            status.violations.append(ObligationViolation(
                obligation_id=oid,
                violation_code="GATE_MISSING",
                message=f"Enforcing gate not found: {gate_path}",
                remediation_hint=f"Create the gate script at {gate_path}",
            ))

    # Check join keys present
    join_keys = obligation.get("join_keys", [])
    if not join_keys:
        status.violations.append(ObligationViolation(
            obligation_id=oid,
            violation_code="MISSING_JOIN_KEYS",
            message="No join keys defined for obligation",
            remediation_hint="Add join_keys (mode, gate, family, module) for traceability",
        ))
        status.valid = False

    # Check scope defined
    scope = obligation.get("scope", {})
    if not scope:
        status.violations.append(ObligationViolation(
            obligation_id=oid,
            violation_code="MISSING_SCOPE",
            message="No scope defined for obligation",
            remediation_hint="Add scope (modes, families, input_domain)",
        ))
        status.valid = False

    return status


def validate_binder(
    binder_path: Path,
    repo_root: Path,
    dry_run: bool = False,
    check_hashes: bool = True,
) -> BinderValidationReport:
    """Validate the complete proof obligations binder."""
    report = BinderValidationReport(timestamp=utc_now(), dry_run=dry_run)

    if not binder_path.exists():
        report.binder_valid = False
        return report

    data = json.loads(binder_path.read_text())

    # Schema validation
    if data.get("schema_version") != "v1":
        report.binder_valid = False
        return report

    obligations = data.get("obligations", [])

    # Check for duplicate IDs
    seen_ids: Set[str] = set()
    for ob in obligations:
        oid = ob.get("id", "")
        if oid in seen_ids:
            report.obligations.append(ObligationStatus(
                obligation_id=oid,
                statement=ob.get("statement", ""),
                category=ob.get("category", "unknown"),
                valid=False,
                violations=[ObligationViolation(
                    obligation_id=oid,
                    violation_code="DUPLICATE_ID",
                    message=f"Duplicate obligation ID: {oid}",
                )],
            ))
            continue
        seen_ids.add(oid)

        status = validate_obligation(ob, repo_root, check_hashes=check_hashes)
        report.obligations.append(status)

    report.compute_status()
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Proof binder validator")
    parser.add_argument("--binder", type=Path, default=DEFAULT_BINDER)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--format", choices=["json", "markdown", "terminal"],
                        default="terminal")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-hashes", action="store_true",
                        help="Skip SHA-256 hash computation")
    args = parser.parse_args(argv)

    report = validate_binder(
        args.binder, REPO_ROOT,
        dry_run=args.dry_run,
        check_hashes=not args.no_hashes,
    )

    if args.format == "terminal":
        print(report.to_markdown())

    if args.format == "json" or args.output:
        json_path = args.output or (
            REPO_ROOT / "tests" / "conformance" / "proof_binder_validation.v1.json"
        )
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n")
        print(f"JSON report written to {json_path}")

    if args.format == "markdown":
        print(report.to_markdown())

    # Summary
    print(f"\n=== Proof Binder Validation Summary ===")
    status = "PASS" if report.binder_valid else "FAIL"
    print(f"Overall: {status}")
    print(f"Obligations: {report.valid_obligations}/{report.total_obligations} valid")
    print(f"Violations: {report.total_violations}")
    for o in report.obligations:
        icon = "+" if o.valid else "!"
        print(f"  [{icon}] {o.obligation_id}: evidence={o.evidence_found}/{o.evidence_found + o.evidence_missing} gates={o.gates_found}/{o.gates_found + o.gates_missing}")

    return 0 if report.binder_valid else 1


if __name__ == "__main__":
    sys.exit(main())
