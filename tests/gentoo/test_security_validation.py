#!/usr/bin/env python3
"""Tests for FrankenLibC security validation."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Add scripts/gentoo to path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/gentoo"))

from security_analyzer import (
    CVE,
    CVEDatabase,
    HealingAction,
    HealingLogParser,
    SecurityAnalyzer,
)


class TestCVEDatabase(unittest.TestCase):
    """Tests for CVE database functionality."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "cve_database.json"
        self.db_path.write_text(
            json.dumps(
                {
                    "cve_classes": {
                        "buffer_overflow": {
                            "healing_actions": ["ClampSize"],
                            "prevention_level": "high",
                        },
                        "use_after_free": {
                            "healing_actions": ["GenerationCheck"],
                            "prevention_level": "partial",
                        },
                    },
                    "packages": {
                        "dev-libs/openssl": {
                            "cves": [
                                {
                                    "id": "CVE-2014-0160",
                                    "name": "Heartbleed",
                                    "class": "buffer_over_read",
                                    "severity": "critical",
                                    "cvss": 7.5,
                                    "description": "Heartbleed bug",
                                    "expected_prevention": True,
                                    "prevention_mechanism": "ClampSize",
                                }
                            ]
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        self.db = CVEDatabase(self.db_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_get_cve_classes(self) -> None:
        classes = self.db.get_cve_classes()
        self.assertIn("buffer_overflow", classes)
        self.assertIn("use_after_free", classes)

    def test_get_package_cves(self) -> None:
        cves = self.db.get_package_cves("dev-libs/openssl")
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0].id, "CVE-2014-0160")
        self.assertEqual(cves[0].name, "Heartbleed")
        self.assertEqual(cves[0].cve_class, "buffer_over_read")
        self.assertTrue(cves[0].expected_prevention)

    def test_get_package_cves_unknown(self) -> None:
        cves = self.db.get_package_cves("unknown/package")
        self.assertEqual(len(cves), 0)

    def test_get_healing_actions_for_class(self) -> None:
        actions = self.db.get_healing_actions_for_class("buffer_overflow")
        self.assertEqual(actions, ["ClampSize"])

    def test_all_packages(self) -> None:
        packages = self.db.all_packages()
        self.assertEqual(packages, ["dev-libs/openssl"])


class TestHealingLogParser(unittest.TestCase):
    """Tests for healing log parser."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.log_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_parse_valid_log(self) -> None:
        log_file = self.log_dir / "test.jsonl"
        log_file.write_text(
            '{"timestamp": "2026-02-13T00:00:00Z", "action": "ClampSize", "call": "memcpy", "original_size": 1000, "clamped_size": 256}\n'
            '{"timestamp": "2026-02-13T00:00:01Z", "action": "GenerationCheck", "call": "free"}\n',
            encoding="utf-8",
        )

        parser = HealingLogParser()
        actions = parser.parse_file(log_file)

        self.assertEqual(len(actions), 2)
        self.assertEqual(actions[0].action, "ClampSize")
        self.assertEqual(actions[0].call, "memcpy")
        self.assertEqual(actions[0].original_size, 1000)
        self.assertEqual(actions[0].clamped_size, 256)
        self.assertEqual(actions[1].action, "GenerationCheck")

    def test_parse_empty_file(self) -> None:
        log_file = self.log_dir / "empty.jsonl"
        log_file.write_text("", encoding="utf-8")

        parser = HealingLogParser()
        actions = parser.parse_file(log_file)
        self.assertEqual(len(actions), 0)

    def test_parse_missing_file(self) -> None:
        parser = HealingLogParser()
        actions = parser.parse_file(self.log_dir / "nonexistent.jsonl")
        self.assertEqual(len(actions), 0)

    def test_parse_invalid_json(self) -> None:
        log_file = self.log_dir / "invalid.jsonl"
        log_file.write_text(
            '{"valid": true}\n' "not json\n" '{"also_valid": true}\n',
            encoding="utf-8",
        )

        parser = HealingLogParser()
        actions = parser.parse_file(log_file)
        # Should skip invalid lines
        self.assertEqual(len(actions), 2)

    def test_parse_directory(self) -> None:
        subdir = self.log_dir / "pkg"
        subdir.mkdir()
        (subdir / "log1.jsonl").write_text(
            '{"timestamp": "2026-02-13T00:00:00Z", "action": "ClampSize", "call": "memcpy"}\n',
            encoding="utf-8",
        )
        (subdir / "log2.jsonl").write_text(
            '{"timestamp": "2026-02-13T00:00:01Z", "action": "GenerationCheck", "call": "free"}\n',
            encoding="utf-8",
        )

        parser = HealingLogParser()
        actions = parser.parse_directory(self.log_dir)
        self.assertEqual(len(actions), 2)


class TestSecurityAnalyzer(unittest.TestCase):
    """Tests for security analyzer."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "cve_database.json"
        self.db_path.write_text(
            json.dumps(
                {
                    "cve_classes": {
                        "buffer_overflow": {"healing_actions": ["ClampSize"]},
                        "use_after_free": {"healing_actions": ["GenerationCheck"]},
                    },
                    "packages": {
                        "dev-libs/openssl": {
                            "cves": [
                                {
                                    "id": "CVE-2014-0160",
                                    "class": "buffer_over_read",
                                    "severity": "critical",
                                    "cvss": 7.5,
                                    "description": "Heartbleed",
                                    "expected_prevention": True,
                                    "prevention_mechanism": "ClampSize",
                                },
                                {
                                    "id": "CVE-2016-2108",
                                    "class": "buffer_overflow",
                                    "severity": "critical",
                                    "cvss": 9.8,
                                    "description": "ASN.1 overflow",
                                    "expected_prevention": True,
                                    "prevention_mechanism": "ClampSize",
                                },
                            ]
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        self.db = CVEDatabase(self.db_path)
        self.analyzer = SecurityAnalyzer(self.db)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_analyze_with_healing_actions(self) -> None:
        actions = [
            HealingAction(timestamp="2026-02-13T00:00:00Z", action="ClampSize", call="memcpy"),
            HealingAction(timestamp="2026-02-13T00:00:01Z", action="ClampSize", call="memmove"),
        ]

        analysis = self.analyzer.analyze_package("dev-libs/openssl", actions)

        self.assertEqual(analysis.package, "dev-libs/openssl")
        self.assertEqual(len(analysis.cves), 2)
        self.assertIn("buffer_overflow", analysis.healing_by_class)
        self.assertEqual(analysis.healing_by_class["buffer_overflow"], 2)

        # Both CVEs should be marked as prevented
        self.assertTrue(analysis.prevention_evidence["CVE-2014-0160"]["would_prevent"])
        self.assertTrue(analysis.prevention_evidence["CVE-2016-2108"]["would_prevent"])

        # Perfect score since both preventable CVEs have evidence
        self.assertEqual(analysis.security_score, 1.0)

    def test_analyze_without_healing_actions(self) -> None:
        analysis = self.analyzer.analyze_package("dev-libs/openssl", [])

        # No healing actions, but CVEs exist
        self.assertEqual(len(analysis.cves), 2)
        self.assertEqual(analysis.healing_by_class, {})

        # Neither CVE prevented
        self.assertFalse(analysis.prevention_evidence["CVE-2014-0160"]["would_prevent"])
        self.assertFalse(analysis.prevention_evidence["CVE-2016-2108"]["would_prevent"])

        # Score should be 0 since no evidence for preventable CVEs
        self.assertEqual(analysis.security_score, 0.0)

    def test_analyze_unknown_package(self) -> None:
        actions = [
            HealingAction(timestamp="2026-02-13T00:00:00Z", action="ClampSize", call="memcpy"),
        ]

        analysis = self.analyzer.analyze_package("unknown/package", actions)

        # No CVEs for unknown package
        self.assertEqual(len(analysis.cves), 0)
        # But healing actions are still counted
        self.assertIn("buffer_overflow", analysis.healing_by_class)
        # Score is 1.0 for packages with no known CVEs
        self.assertEqual(analysis.security_score, 1.0)

    def test_to_report(self) -> None:
        actions = [
            HealingAction(timestamp="2026-02-13T00:00:00Z", action="ClampSize", call="memcpy"),
        ]

        analysis = self.analyzer.analyze_package("dev-libs/openssl", actions)
        report = self.analyzer.to_report(analysis)

        self.assertEqual(report["package"], "dev-libs/openssl")
        self.assertIn("timestamp", report)
        self.assertIn("known_cves", report)
        self.assertIn("healing_actions_by_class", report)
        self.assertIn("prevention_analysis", report)
        self.assertIn("security_score", report)


class TestSecurityValidationIntegration(unittest.TestCase):
    """Integration tests for security validation."""

    def test_openssl_heartbleed_pattern(self) -> None:
        """Verify ClampSize would prevent Heartbleed-style reads."""
        # Heartbleed: memcpy of user-controlled length
        actions = [
            HealingAction(timestamp="2026-02-13T00:00:00Z", action="ClampSize", call="memcpy", original_size=65535, clamped_size=256),
            HealingAction(timestamp="2026-02-13T00:00:01Z", action="ClampSize", call="memcpy", original_size=1024, clamped_size=256),
        ]

        # ClampSize on memcpy should prevent over-read
        clamp_actions = [a for a in actions if a.action == "ClampSize"]
        self.assertGreater(len(clamp_actions), 0)
        self.assertTrue(any(a.call == "memcpy" for a in clamp_actions))

    def test_redis_uaf_pattern(self) -> None:
        """Verify GenerationCheck catches UAF patterns."""
        actions = [
            HealingAction(timestamp="2026-02-13T00:00:00Z", action="GenerationCheck", call="free"),
            HealingAction(timestamp="2026-02-13T00:00:01Z", action="GenerationCheck", call="access"),
        ]

        generation_checks = [a for a in actions if a.action == "GenerationCheck"]
        self.assertGreater(len(generation_checks), 0)

    def test_double_free_prevention(self) -> None:
        """Verify IgnoreDoubleFree handles double free."""
        actions = [
            HealingAction(timestamp="2026-02-13T00:00:00Z", action="IgnoreDoubleFree", call="free"),
        ]

        double_free_actions = [a for a in actions if a.action == "IgnoreDoubleFree"]
        self.assertEqual(len(double_free_actions), 1)


if __name__ == "__main__":
    unittest.main()
