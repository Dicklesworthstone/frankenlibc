#!/usr/bin/env python3
"""Security analyzer for FrankenLibC Gentoo validation.

Correlates healing actions with known CVEs to demonstrate security value.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class HealingAction:
    """A single healing action from FrankenLibC."""

    timestamp: str
    action: str
    call: str
    original_size: Optional[int] = None
    clamped_size: Optional[int] = None
    metadata: Dict[str, object] = field(default_factory=dict)


@dataclass
class CVE:
    """CVE vulnerability record."""

    id: str
    cve_class: str
    severity: str
    cvss: float
    description: str
    expected_prevention: bool
    prevention_mechanism: str
    name: Optional[str] = None


@dataclass
class PackageCVEs:
    """CVEs associated with a package."""

    package: str
    cves: List[CVE]


@dataclass
class SecurityAnalysis:
    """Security analysis result for a package."""

    package: str
    healing_actions: List[HealingAction]
    cves: List[CVE]
    healing_by_class: Dict[str, int]
    prevention_evidence: Dict[str, Dict[str, object]]
    security_score: float
    analysis_timestamp: str


class CVEDatabase:
    """CVE database for security analysis."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._data: Dict[str, object] = {}
        self._load()

    def _load(self) -> None:
        if self.db_path.exists():
            self._data = json.loads(self.db_path.read_text(encoding="utf-8"))

    def get_cve_classes(self) -> Dict[str, Dict[str, object]]:
        """Get CVE class definitions."""
        return self._data.get("cve_classes", {})

    def get_package_cves(self, package: str) -> List[CVE]:
        """Get CVEs for a specific package."""
        packages = self._data.get("packages", {})
        pkg_data = packages.get(package, {})
        cves = []
        for cve_data in pkg_data.get("cves", []):
            cves.append(
                CVE(
                    id=cve_data.get("id", ""),
                    cve_class=cve_data.get("class", "unknown"),
                    severity=cve_data.get("severity", "unknown"),
                    cvss=float(cve_data.get("cvss", 0)),
                    description=cve_data.get("description", ""),
                    expected_prevention=bool(cve_data.get("expected_prevention", False)),
                    prevention_mechanism=cve_data.get("prevention_mechanism", ""),
                    name=cve_data.get("name"),
                )
            )
        return cves

    def get_healing_actions_for_class(self, cve_class: str) -> List[str]:
        """Get healing actions that prevent a CVE class."""
        classes = self.get_cve_classes()
        class_data = classes.get(cve_class, {})
        return class_data.get("healing_actions", [])

    def all_packages(self) -> List[str]:
        """Get all packages in the database."""
        return list(self._data.get("packages", {}).keys())


class HealingLogParser:
    """Parser for FrankenLibC healing action logs."""

    def parse_file(self, path: Path) -> List[HealingAction]:
        """Parse a JSONL healing log file."""
        if not path.exists():
            return []

        actions = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                actions.append(
                    HealingAction(
                        timestamp=str(data.get("timestamp", "")),
                        action=str(data.get("action", "")),
                        call=str(data.get("call", "")),
                        original_size=data.get("original_size"),
                        clamped_size=data.get("clamped_size"),
                        metadata={k: v for k, v in data.items() if k not in {"timestamp", "action", "call"}},
                    )
                )
            except json.JSONDecodeError:
                continue
        return actions

    def parse_directory(self, path: Path, glob: str = "**/*.jsonl") -> List[HealingAction]:
        """Parse all healing logs in a directory."""
        all_actions = []
        for log_file in path.glob(glob):
            all_actions.extend(self.parse_file(log_file))
        return all_actions


class SecurityAnalyzer:
    """Analyzes healing actions for security value."""

    # Mapping from healing actions to CVE classes they prevent
    ACTION_TO_CLASS: Dict[str, Set[str]] = {
        "ClampSize": {"buffer_overflow", "buffer_over_read", "integer_overflow"},
        "GenerationCheck": {"use_after_free"},
        "QuarantinePointer": {"use_after_free"},
        "IgnoreDoubleFree": {"double_free"},
        "UpgradeToSafeVariant": {"format_string"},
        "ReturnSafeDefault": {"null_pointer_deref"},
        "ZeroInitialize": {"uninitialized_memory"},
        "SaturatingArithmetic": {"integer_overflow"},
    }

    def __init__(self, cve_db: CVEDatabase) -> None:
        self.cve_db = cve_db

    def analyze_package(
        self,
        package: str,
        healing_actions: List[HealingAction],
    ) -> SecurityAnalysis:
        """Analyze security implications of healing actions for a package."""
        cves = self.cve_db.get_package_cves(package)

        # Count healing actions by class
        healing_by_class: Dict[str, int] = {}
        for action in healing_actions:
            classes = self.ACTION_TO_CLASS.get(action.action, set())
            for cls in classes:
                healing_by_class[cls] = healing_by_class.get(cls, 0) + 1

        # Build prevention evidence
        prevention_evidence: Dict[str, Dict[str, object]] = {}
        prevented_count = 0

        for cve in cves:
            cve_class = cve.cve_class
            healing_count = healing_by_class.get(cve_class, 0)

            if cve.expected_prevention and healing_count > 0:
                would_prevent = True
                prevented_count += 1
                confidence = min(1.0, healing_count / 10)  # More actions = more confidence
            elif cve.expected_prevention:
                would_prevent = False  # Expected but no evidence
                confidence = 0.0
            else:
                would_prevent = False  # Not expected to prevent
                confidence = 1.0  # Confident it won't prevent

            prevention_evidence[cve.id] = {
                "would_prevent": would_prevent,
                "mechanism": cve.prevention_mechanism,
                "healing_actions_for_class": healing_count,
                "confidence": round(confidence, 2),
                "cve_class": cve_class,
            }

        # Calculate security score
        if cves:
            preventable_cves = [c for c in cves if c.expected_prevention]
            if preventable_cves:
                security_score = prevented_count / len(preventable_cves)
            else:
                security_score = 1.0  # No preventable CVEs = 100%
        else:
            security_score = 1.0  # No known CVEs = 100%

        return SecurityAnalysis(
            package=package,
            healing_actions=healing_actions,
            cves=cves,
            healing_by_class=healing_by_class,
            prevention_evidence=prevention_evidence,
            security_score=round(security_score, 2),
            analysis_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    def to_report(self, analysis: SecurityAnalysis) -> Dict[str, object]:
        """Convert analysis to report format."""
        return {
            "package": analysis.package,
            "timestamp": analysis.analysis_timestamp,
            "known_cves": [
                {
                    "id": cve.id,
                    "name": cve.name,
                    "class": cve.cve_class,
                    "severity": cve.severity,
                    "cvss": cve.cvss,
                }
                for cve in analysis.cves
            ],
            "healing_actions_by_class": analysis.healing_by_class,
            "total_healing_actions": len(analysis.healing_actions),
            "prevention_analysis": analysis.prevention_evidence,
            "security_score": analysis.security_score,
        }


def analyze_package_logs(
    package: str,
    log_dir: Path,
    cve_db_path: Path,
) -> Dict[str, object]:
    """Convenience function to analyze a package's security."""
    cve_db = CVEDatabase(cve_db_path)
    parser = HealingLogParser()
    analyzer = SecurityAnalyzer(cve_db)

    # Find logs for this package
    pkg_safe = package.replace("/", "__")
    pkg_log_dir = log_dir / pkg_safe

    if pkg_log_dir.exists():
        actions = parser.parse_directory(pkg_log_dir)
    else:
        # Try to find any matching logs
        actions = []
        for log_file in log_dir.glob(f"**/{pkg_safe}*/*.jsonl"):
            actions.extend(parser.parse_file(log_file))

    analysis = analyzer.analyze_package(package, actions)
    return analyzer.to_report(analysis)


def main() -> int:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Analyze FrankenLibC security impact")
    parser.add_argument("--package", required=True, help="Package atom to analyze")
    parser.add_argument("--log-dir", required=True, type=Path, help="Directory containing healing logs")
    parser.add_argument("--cve-db", default="data/gentoo/cve_database.json", type=Path, help="CVE database path")
    parser.add_argument("--output", type=Path, help="Output JSON file")
    args = parser.parse_args()

    result = analyze_package_logs(args.package, args.log_dir, args.cve_db)

    output_json = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(output_json + "\n", encoding="utf-8")
    else:
        print(output_json)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
