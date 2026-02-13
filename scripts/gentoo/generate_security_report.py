#!/usr/bin/env python3
"""Generate aggregate security report for FrankenLibC Gentoo validation."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from security_analyzer import CVEDatabase, HealingLogParser, SecurityAnalyzer


@dataclass
class AggregateSecurityReport:
    """Aggregate security report across all packages."""

    timestamp: str
    total_packages: int
    packages_with_cves: int
    total_cves: int
    prevented_cves: int
    not_prevented_cves: int
    prevention_rate: float
    total_healing_actions: int
    healing_by_class: Dict[str, int]
    by_severity: Dict[str, Dict[str, int]]
    package_reports: List[Dict[str, object]]
    methodology: Dict[str, object]


def generate_aggregate_report(
    log_dir: Path,
    cve_db_path: Path,
    packages: List[str] | None = None,
) -> AggregateSecurityReport:
    """Generate aggregate security report."""
    cve_db = CVEDatabase(cve_db_path)
    parser = HealingLogParser()
    analyzer = SecurityAnalyzer(cve_db)

    # Use all packages from CVE database if not specified
    if packages is None:
        packages = cve_db.all_packages()

    package_reports: List[Dict[str, object]] = []
    total_healing_actions = 0
    aggregate_healing_by_class: Dict[str, int] = {}
    total_cves = 0
    prevented_cves = 0
    packages_with_cves = 0
    by_severity: Dict[str, Dict[str, int]] = {
        "critical": {"total": 0, "prevented": 0},
        "high": {"total": 0, "prevented": 0},
        "medium": {"total": 0, "prevented": 0},
        "low": {"total": 0, "prevented": 0},
    }

    for package in packages:
        pkg_safe = package.replace("/", "__")

        # Find logs for this package
        actions = []
        for pattern in [f"{pkg_safe}/**/*.jsonl", f"**/{pkg_safe}/*.jsonl", f"{pkg_safe}*.jsonl"]:
            for log_file in log_dir.glob(pattern):
                actions.extend(parser.parse_file(log_file))

        analysis = analyzer.analyze_package(package, actions)
        report = analyzer.to_report(analysis)
        package_reports.append(report)

        # Aggregate statistics
        total_healing_actions += len(actions)

        for cls, count in analysis.healing_by_class.items():
            aggregate_healing_by_class[cls] = aggregate_healing_by_class.get(cls, 0) + count

        if analysis.cves:
            packages_with_cves += 1
            total_cves += len(analysis.cves)

            for cve in analysis.cves:
                evidence = analysis.prevention_evidence.get(cve.id, {})
                if evidence.get("would_prevent", False):
                    prevented_cves += 1
                    by_severity[cve.severity]["prevented"] += 1
                by_severity[cve.severity]["total"] += 1

    prevention_rate = prevented_cves / total_cves if total_cves > 0 else 1.0

    return AggregateSecurityReport(
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        total_packages=len(packages),
        packages_with_cves=packages_with_cves,
        total_cves=total_cves,
        prevented_cves=prevented_cves,
        not_prevented_cves=total_cves - prevented_cves,
        prevention_rate=round(prevention_rate, 2),
        total_healing_actions=total_healing_actions,
        healing_by_class=aggregate_healing_by_class,
        by_severity=by_severity,
        package_reports=package_reports,
        methodology={
            "description": "Security analysis correlates FrankenLibC healing actions with known CVEs",
            "prevention_criteria": "A CVE is considered 'prevented' if healing actions matching its class were observed",
            "limitations": [
                "Analysis based on healing action logs, not actual exploit attempts",
                "Some CVEs are logic bugs, not preventable by memory safety",
                "Prevention assumes healing action would fire before exploitation",
            ],
            "healing_action_mappings": {
                "ClampSize": ["buffer_overflow", "buffer_over_read", "integer_overflow"],
                "GenerationCheck": ["use_after_free"],
                "IgnoreDoubleFree": ["double_free"],
                "UpgradeToSafeVariant": ["format_string"],
                "ZeroInitialize": ["uninitialized_memory"],
            },
        },
    )


def render_markdown(report: AggregateSecurityReport) -> str:
    """Render report as markdown."""
    lines = [
        "# FrankenLibC Security Validation Report",
        "",
        f"**Generated:** {report.timestamp}",
        "",
        "## Executive Summary",
        "",
        f"- **Total Packages Analyzed:** {report.total_packages}",
        f"- **Packages with Known CVEs:** {report.packages_with_cves}",
        f"- **Total CVEs Analyzed:** {report.total_cves}",
        f"- **CVEs Prevented:** {report.prevented_cves} ({report.prevention_rate:.0%})",
        f"- **CVEs Not Prevented:** {report.not_prevented_cves}",
        f"- **Total Healing Actions Observed:** {report.total_healing_actions}",
        "",
        "## Prevention by Severity",
        "",
        "| Severity | Total | Prevented | Rate |",
        "|----------|-------|-----------|------|",
    ]

    for severity in ["critical", "high", "medium", "low"]:
        data = report.by_severity.get(severity, {"total": 0, "prevented": 0})
        total = data["total"]
        prevented = data["prevented"]
        rate = prevented / total if total > 0 else 0
        lines.append(f"| {severity.capitalize()} | {total} | {prevented} | {rate:.0%} |")

    lines.extend(
        [
            "",
            "## Healing Actions by CVE Class",
            "",
            "| CVE Class | Healing Actions |",
            "|-----------|-----------------|",
        ]
    )

    for cls, count in sorted(report.healing_by_class.items(), key=lambda x: -x[1]):
        lines.append(f"| {cls} | {count} |")

    lines.extend(
        [
            "",
            "## Package Details",
            "",
        ]
    )

    for pkg_report in sorted(report.package_reports, key=lambda x: x["package"]):
        pkg = pkg_report["package"]
        score = pkg_report["security_score"]
        cve_count = len(pkg_report["known_cves"])
        actions = pkg_report["total_healing_actions"]

        lines.append(f"### {pkg}")
        lines.append("")
        lines.append(f"- **Security Score:** {score:.0%}")
        lines.append(f"- **Known CVEs:** {cve_count}")
        lines.append(f"- **Healing Actions:** {actions}")

        if pkg_report["known_cves"]:
            lines.append("")
            lines.append("| CVE | Severity | Would Prevent? |")
            lines.append("|-----|----------|----------------|")
            for cve in pkg_report["known_cves"]:
                cve_id = cve["id"]
                severity = cve["severity"]
                evidence = pkg_report["prevention_analysis"].get(cve_id, {})
                would_prevent = "Yes" if evidence.get("would_prevent", False) else "No"
                lines.append(f"| {cve_id} | {severity} | {would_prevent} |")

        lines.append("")

    lines.extend(
        [
            "## Methodology",
            "",
            report.methodology["description"],
            "",
            "### Limitations",
            "",
        ]
    )

    for limitation in report.methodology["limitations"]:
        lines.append(f"- {limitation}")

    return "\n".join(lines)


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Generate aggregate security report")
    parser.add_argument("--log-dir", required=True, type=Path, help="Directory containing healing logs")
    parser.add_argument("--cve-db", default="data/gentoo/cve_database.json", type=Path, help="CVE database path")
    parser.add_argument("--output-json", type=Path, help="Output JSON file")
    parser.add_argument("--output-md", type=Path, help="Output markdown file")
    parser.add_argument("--packages", nargs="*", help="Specific packages to analyze")
    args = parser.parse_args()

    report = generate_aggregate_report(
        log_dir=args.log_dir,
        cve_db_path=args.cve_db,
        packages=args.packages if args.packages else None,
    )

    # Convert to dict for JSON
    report_dict = {
        "timestamp": report.timestamp,
        "total_packages": report.total_packages,
        "packages_with_cves": report.packages_with_cves,
        "total_cves": report.total_cves,
        "prevented_cves": report.prevented_cves,
        "not_prevented_cves": report.not_prevented_cves,
        "prevention_rate": report.prevention_rate,
        "total_healing_actions": report.total_healing_actions,
        "healing_by_class": report.healing_by_class,
        "by_severity": report.by_severity,
        "package_reports": report.package_reports,
        "methodology": report.methodology,
    }

    if args.output_json:
        args.output_json.write_text(json.dumps(report_dict, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"JSON report written to: {args.output_json}")

    if args.output_md:
        args.output_md.write_text(render_markdown(report) + "\n", encoding="utf-8")
        print(f"Markdown report written to: {args.output_md}")

    if not args.output_json and not args.output_md:
        print(render_markdown(report))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
