#!/usr/bin/env python3
"""Proof obligations binder validator (bd-5fw.4, bd-w2c3.6).

Validates the proof obligations binder: checks that every obligation has
valid evidence artifacts and enforcing gates, reports missing/invalid entries.
For obligations in `planned` status, enforces owner/artifact-schema/
verification-command completeness.

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
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

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


def parse_source_ref(ref: str) -> Optional[Tuple[str, int]]:
    """Parse a `path:line` source reference."""
    if ":" not in ref:
        return None

    path_part, line_part = ref.rsplit(":", 1)
    if not path_part or not line_part.isdigit():
        return None

    line_number = int(line_part)
    if line_number <= 0:
        return None

    return path_part, line_number


def clean_string(value: Any) -> str:
    """Return a trimmed string, or empty string when not a string."""
    if isinstance(value, str):
        return value.strip()
    return ""


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
    status: str = "planned"
    owner: str = ""
    artifact_schema: str = ""
    verification_command: str = ""
    valid: bool = True
    evidence_found: int = 0
    evidence_missing: int = 0
    gates_found: int = 0
    gates_missing: int = 0
    source_refs_total: int = 0
    source_refs_valid: int = 0
    source_refs_invalid: int = 0
    violations: List[ObligationViolation] = field(default_factory=list)
    evidence_hashes: Dict[str, Optional[str]] = field(default_factory=dict)
    source_ref_results: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "statement": self.statement,
            "category": self.category,
            "status": self.status,
            "owner": self.owner,
            "artifact_schema": self.artifact_schema,
            "verification_command": self.verification_command,
            "valid": self.valid,
            "evidence_found": self.evidence_found,
            "evidence_missing": self.evidence_missing,
            "gates_found": self.gates_found,
            "gates_missing": self.gates_missing,
            "source_refs_total": self.source_refs_total,
            "source_refs_valid": self.source_refs_valid,
            "source_refs_invalid": self.source_refs_invalid,
            "violations": [v.to_dict() for v in self.violations],
            "evidence_hashes": self.evidence_hashes,
            "source_ref_results": self.source_ref_results,
        }


@dataclass
class CounterexampleWitness:
    """Minimal regression witness for an invalid proof obligation."""

    counterexample_id: str
    obligation_id: str
    statement: str
    category: str
    primary_violation_code: str
    primary_message: str
    remediation_hint: str
    reproduction_command: str
    minimized_inputs: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "counterexample_id": self.counterexample_id,
            "obligation_id": self.obligation_id,
            "statement": self.statement,
            "category": self.category,
            "primary_violation_code": self.primary_violation_code,
            "primary_message": self.primary_message,
            "remediation_hint": self.remediation_hint,
            "reproduction_command": self.reproduction_command,
            "minimized_inputs": self.minimized_inputs,
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
    counterexamples: List[CounterexampleWitness] = field(default_factory=list)

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
            "counterexamples": [c.to_dict() for c in self.counterexamples],
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
            f"**Counterexamples:** {len(self.counterexamples)} minimized witness(es)",
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

        if self.counterexamples:
            lines.append("## Counterexamples")
            lines.append("")
            for witness in self.counterexamples:
                lines.append(
                    f"- **{witness.counterexample_id}** ({witness.obligation_id}) "
                    f"{witness.primary_violation_code}: {witness.primary_message}"
                )
                lines.append(f"  - Repro: `{witness.reproduction_command}`")
                if witness.remediation_hint:
                    lines.append(f"  - Hint: {witness.remediation_hint}")
            lines.append("")

        return "\n".join(lines)


VIOLATION_PRIORITY: Dict[str, int] = {
    "MISSING_OWNER": 0,
    "MISSING_ARTIFACT_SCHEMA": 1,
    "MISSING_VERIFICATION_COMMAND": 2,
    "EVIDENCE_MISSING": 3,
    "GATE_MISSING": 4,
    "MISSING_JOIN_KEYS": 5,
    "MISSING_SCOPE": 6,
    "SOURCE_REF_INVALID_FORMAT": 7,
    "SOURCE_REF_MISSING_FILE": 8,
    "SOURCE_REF_BAD_LINE": 9,
    "DUPLICATE_ID": 10,
}


def _priority_for_violation(code: str) -> int:
    return VIOLATION_PRIORITY.get(code, len(VIOLATION_PRIORITY) + 100)


def build_counterexample_witness(
    status: ObligationStatus,
    obligation: Dict[str, Any],
    binder_path: Path,
) -> Optional[CounterexampleWitness]:
    """Build a single minimized witness for the most actionable failure in an obligation."""
    if status.valid or not status.violations:
        return None

    primary = min(
        status.violations,
        key=lambda violation: (_priority_for_violation(violation.violation_code), violation.message),
    )

    minimized_inputs: Dict[str, List[str]] = {}
    if primary.violation_code == "EVIDENCE_MISSING":
        for artifact in obligation.get("evidence_artifacts", []):
            if not (REPO_ROOT / artifact).exists():
                minimized_inputs["evidence_artifacts"] = [artifact]
                break
    elif primary.violation_code == "GATE_MISSING":
        for gate in obligation.get("gates", []):
            gate_path = REPO_ROOT / gate
            if not gate_path.exists():
                minimized_inputs["gates"] = [gate]
                break
    elif primary.violation_code.startswith("SOURCE_REF_"):
        invalid_refs = [
            source_ref
            for source_ref, result in sorted(status.source_ref_results.items())
            if result != "valid"
        ]
        if invalid_refs:
            minimized_inputs["source_refs"] = [invalid_refs[0]]
    elif primary.violation_code == "MISSING_JOIN_KEYS":
        minimized_inputs["join_keys"] = []
    elif primary.violation_code == "MISSING_SCOPE":
        minimized_inputs["scope"] = []

    try:
        binder_arg = str(binder_path.relative_to(REPO_ROOT))
    except ValueError:
        binder_arg = str(binder_path)

    return CounterexampleWitness(
        counterexample_id=f"CE-{status.obligation_id}",
        obligation_id=status.obligation_id,
        statement=status.statement,
        category=status.category,
        primary_violation_code=primary.violation_code,
        primary_message=primary.message,
        remediation_hint=primary.remediation_hint,
        reproduction_command=(
            f"python3 scripts/gentoo/proof_binder_validator.py --binder {binder_arg} "
            "--format json --no-hashes"
        ),
        minimized_inputs=minimized_inputs,
    )


def validate_obligation(
    obligation: Dict[str, Any],
    repo_root: Path,
    check_hashes: bool = True,
) -> ObligationStatus:
    """Validate a single proof obligation."""
    oid = obligation.get("id", "unknown")
    obligation_status = clean_string(obligation.get("status"))
    reported_status = obligation_status or "unspecified"
    owner = clean_string(obligation.get("owner"))
    artifact_schema = clean_string(obligation.get("artifact_schema"))
    verification_command = clean_string(obligation.get("verification_command"))

    status = ObligationStatus(
        obligation_id=oid,
        statement=obligation.get("statement", ""),
        category=obligation.get("category", "unknown"),
        status=reported_status,
        owner=owner,
        artifact_schema=artifact_schema,
        verification_command=verification_command,
    )

    if obligation_status.lower() == "planned":
        required_fields = [
            (
                "owner",
                owner,
                "MISSING_OWNER",
                "Set owner to a responsible track/bead (for example `bd-w2c3.6.1`).",
            ),
            (
                "artifact_schema",
                artifact_schema,
                "MISSING_ARTIFACT_SCHEMA",
                "Set artifact_schema to the record schema id (for example `proof_obligation_record.v1`).",
            ),
            (
                "verification_command",
                verification_command,
                "MISSING_VERIFICATION_COMMAND",
                "Set verification_command to the deterministic gate command (for example `bash scripts/check_proof_binder.sh`).",
            ),
        ]
        for field_name, value, code, remediation_hint in required_fields:
            if not value:
                status.valid = False
                status.violations.append(
                    ObligationViolation(
                        obligation_id=oid,
                        violation_code=code,
                        message=(
                            f"Planned obligation missing required field: {field_name}"
                        ),
                        remediation_hint=remediation_hint,
                    )
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

    # Optional source traceability references (path:line).
    for source_ref in obligation.get("source_refs", []):
        status.source_refs_total += 1
        parsed = parse_source_ref(source_ref)
        if parsed is None:
            status.source_refs_invalid += 1
            status.valid = False
            status.source_ref_results[source_ref] = "invalid_format"
            status.violations.append(ObligationViolation(
                obligation_id=oid,
                violation_code="SOURCE_REF_INVALID_FORMAT",
                message=f"Invalid source ref format (expected path:line): {source_ref}",
                remediation_hint="Use repo-relative references like crates/foo.rs:42",
            ))
            continue

        rel_path, line_number = parsed
        full_path = repo_root / rel_path
        if not full_path.exists():
            status.source_refs_invalid += 1
            status.valid = False
            status.source_ref_results[source_ref] = "missing_file"
            status.violations.append(ObligationViolation(
                obligation_id=oid,
                violation_code="SOURCE_REF_MISSING_FILE",
                message=f"Source ref path not found: {rel_path}",
                remediation_hint=f"Ensure file exists or update ref: {source_ref}",
            ))
            continue

        line_count = len(full_path.read_text(encoding="utf-8", errors="replace").splitlines())
        if line_number > line_count:
            status.source_refs_invalid += 1
            status.valid = False
            status.source_ref_results[source_ref] = "line_out_of_range"
            status.violations.append(ObligationViolation(
                obligation_id=oid,
                violation_code="SOURCE_REF_BAD_LINE",
                message=f"Source ref line {line_number} exceeds {line_count}: {source_ref}",
                remediation_hint="Update line anchors to current file positions",
            ))
            continue

        status.source_refs_valid += 1
        status.source_ref_results[source_ref] = "valid"

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
        witness = build_counterexample_witness(status, ob, binder_path)
        if witness is not None:
            report.counterexamples.append(witness)

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
    print(f"Counterexamples: {len(report.counterexamples)}")
    for o in report.obligations:
        icon = "+" if o.valid else "!"
        refs = (
            f" refs={o.source_refs_valid}/{o.source_refs_total}"
            if o.source_refs_total > 0
            else ""
        )
        print(
            f"  [{icon}] {o.obligation_id}: "
            f"evidence={o.evidence_found}/{o.evidence_found + o.evidence_missing} "
            f"gates={o.gates_found}/{o.gates_found + o.gates_missing}{refs}"
        )

    return 0 if report.binder_valid else 1


if __name__ == "__main__":
    sys.exit(main())
