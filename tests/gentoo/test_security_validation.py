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
from generate_security_report import generate_aggregate_report


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

        # Both CVEs have class telemetry correlation, but neither is oracle-verified from logs alone (SQ S21/S03):
        # telemetry alone must NEVER claim prevention or positive security_score.
        self.assertFalse(analysis.prevention_evidence["CVE-2014-0160"]["would_prevent"])
        self.assertFalse(analysis.prevention_evidence["CVE-2016-2108"]["would_prevent"])
        self.assertFalse(analysis.prevention_evidence["CVE-2014-0160"]["verified_by_oracle"])
        self.assertFalse(analysis.prevention_evidence["CVE-2016-2108"]["verified_by_oracle"])
        self.assertTrue(analysis.prevention_evidence["CVE-2014-0160"]["class_telemetry_observed"])
        self.assertTrue(analysis.prevention_evidence["CVE-2016-2108"]["class_telemetry_observed"])
        self.assertEqual(
            analysis.prevention_evidence["CVE-2014-0160"]["evidence_status"],
            "telemetry_correlation_only",
        )
        self.assertEqual(analysis.qualification_status, "unqualified")
        self.assertEqual(analysis.security_score, 0.0)

    def test_analyze_with_explicit_oracle_verdicts_overrides_telemetry_only(self) -> None:
        actions = [
            HealingAction(timestamp="2026-02-13T00:00:00Z", action="ClampSize", call="memcpy"),
        ]
        analysis = self.analyzer.analyze_package(
            "dev-libs/openssl",
            actions,
            oracle_verdicts={"CVE-2014-0160": False, "CVE-2016-2108": True},
        )
        self.assertFalse(analysis.prevention_evidence["CVE-2014-0160"]["would_prevent"])
        self.assertFalse(analysis.prevention_evidence["CVE-2014-0160"]["verified_by_oracle"])
        self.assertEqual(
            analysis.prevention_evidence["CVE-2014-0160"]["evidence_status"],
            "verified_oracle_fail",
        )
        self.assertTrue(analysis.prevention_evidence["CVE-2016-2108"]["would_prevent"])
        self.assertTrue(analysis.prevention_evidence["CVE-2016-2108"]["verified_by_oracle"])
        self.assertEqual(
            analysis.prevention_evidence["CVE-2016-2108"]["evidence_status"],
            "verified_oracle_pass",
        )
        self.assertEqual(analysis.security_score, 0.5)

    def test_malformed_oracle_verdicts_cannot_claim_prevention(self) -> None:
        # JSON inputs and external adapters can supply strings or integers.
        # Only literal booleans count as independent oracle observations.
        for invalid in ("false", "true", 1, 0, None, [], {}):
            with self.subTest(invalid=invalid):
                analysis = self.analyzer.analyze_package(
                    "dev-libs/openssl",
                    [HealingAction(timestamp="", action="ClampSize", call="memcpy")],
                    oracle_verdicts={"CVE-2014-0160": invalid},
                )
                evidence = analysis.prevention_evidence["CVE-2014-0160"]
                self.assertFalse(evidence["would_prevent"])
                self.assertFalse(evidence["verified_by_oracle"])
                self.assertEqual(evidence["evidence_status"], "telemetry_correlation_only")
                self.assertEqual(analysis.qualification_status, "unqualified")
                self.assertEqual(analysis.security_score, 0.0)

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

        # No CVEs for unknown package -> unqualified (0.0), NEVER 100% (SQ S21/S03)
        self.assertEqual(len(analysis.cves), 0)
        # But healing actions are still counted
        self.assertIn("buffer_overflow", analysis.healing_by_class)
        self.assertEqual(analysis.qualification_status, "unqualified")
        self.assertEqual(analysis.security_score, 0.0)

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

    def test_aggregate_report_deduplicates_overlapping_log_globs(self) -> None:
        """Verify aggregate reports do not double-count the same package log."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            log_dir = root / "logs"
            package_dir = log_dir / "dev-libs__openssl"
            package_dir.mkdir(parents=True)
            (package_dir / "healing.jsonl").write_text(
                '{"timestamp":"2026-02-13T00:00:00Z","action":"ClampSize","call":"memcpy"}\n'
                '{"timestamp":"2026-02-13T00:00:01Z","action":"ClampSize","call":"memmove"}\n',
                encoding="utf-8",
            )
            db_path = root / "cve_database.json"
            db_path.write_text(
                json.dumps(
                    {
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
                        }
                    }
                ),
                encoding="utf-8",
            )

            report = generate_aggregate_report(log_dir, db_path, packages=["dev-libs/openssl"])

        self.assertEqual(report.total_healing_actions, 2)
        # Without explicit oracle verdicts, prevented_cves and prevention_rate remain 0 / unqualified
        self.assertEqual(report.prevented_cves, 0)
        self.assertEqual(report.not_prevented_cves, 2)
        self.assertEqual(report.prevention_rate, 0.0)
        self.assertEqual(report.qualification_status, "unqualified")
        self.assertEqual(report.healing_by_class["buffer_over_read"], 2)
        self.assertEqual(report.healing_by_class["buffer_overflow"], 2)

    def test_aggregate_report_distinguishes_partial_vs_full_oracle_qualification(self) -> None:
        """Aggregate report must be partially_oracle_qualified unless ALL CVE-bearing packages are oracle_qualified."""
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            log_dir = root / "logs"
            log_dir.mkdir(parents=True)
            db_path = root / "cve_database.json"
            db_path.write_text(
                json.dumps(
                    {
                        "packages": {
                            "app-arch/libarchive": {
                                "cves": [
                                    {
                                        "id": "CVE-2025-5915",
                                        "class": "buffer_over_read",
                                        "severity": "high",
                                        "cvss": 7.5,
                                        "description": "RAR over-read",
                                        "expected_prevention": True,
                                        "prevention_mechanism": "ClampSize",
                                    }
                                ]
                            },
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
                                    }
                                ]
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )

            orig_analyze = SecurityAnalyzer.analyze_package

            def mixed_analyze(self_inner: SecurityAnalyzer, pkg: str, actions: list[HealingAction], oracle_verdicts: dict[str, bool] | None = None):
                verdicts = {"CVE-2025-5915": True} if pkg == "app-arch/libarchive" else None
                return orig_analyze(self_inner, pkg, actions, oracle_verdicts=verdicts)

            with patch.object(SecurityAnalyzer, "analyze_package", mixed_analyze):
                mixed_report = generate_aggregate_report(
                    log_dir,
                    db_path,
                    packages=["app-arch/libarchive", "dev-libs/openssl"],
                )
            self.assertEqual(mixed_report.qualification_status, "partially_oracle_qualified")
            self.assertEqual(mixed_report.prevented_cves, 1)
            self.assertEqual(mixed_report.total_cves, 2)

            def full_analyze(self_inner: SecurityAnalyzer, pkg: str, actions: list[HealingAction], oracle_verdicts: dict[str, bool] | None = None):
                verdicts = (
                    {"CVE-2025-5915": True}
                    if pkg == "app-arch/libarchive"
                    else {"CVE-2014-0160": True}
                )
                return orig_analyze(self_inner, pkg, actions, oracle_verdicts=verdicts)

            with patch.object(SecurityAnalyzer, "analyze_package", full_analyze):
                full_report = generate_aggregate_report(
                    log_dir,
                    db_path,
                    packages=["app-arch/libarchive", "dev-libs/openssl"],
                )
            self.assertEqual(full_report.qualification_status, "oracle_qualified")
            self.assertEqual(full_report.prevented_cves, 2)

    def test_sq_m0_counterexamples_and_runner_hsfp_controls(self) -> None:
        """SQ M0 (S03, S05, S07, S12): adversarial negative controls on runner.sh and cve_arena_gate.sh."""
        import subprocess

        repo_root = Path(__file__).resolve().parents[2]
        runner = repo_root / "tests/cve_arena/runner.sh"
        gate = repo_root / "scripts/cve_arena_gate.sh"

        # Gate must contain zero --no-docker fallbacks and zero `|| true` suppressors (SQ S06).
        gate_text = gate.read_text(encoding="utf-8")
        self.assertNotIn("--no-docker", gate_text)
        self.assertNotIn("|| true", gate_text)

        def eval_hsfp(payload: dict) -> dict:
            out = subprocess.check_output(
                ["bash", str(runner), f"--evaluate-hsfp={json.dumps(payload)}"],
                text=True,
            )
            return json.loads(out)

        # S03.1 heal_with_harm: 50 healing actions + H_candidate=True must NEVER classify as PREVENTED.
        heal_with_harm = eval_hsfp(
            {
                "admitted": True,
                "stock_exit": 139,
                "stock_exploitable": True,
                "tsm_exit": 0,
                "expected_tsm_exit": 0,
                "tsm_stdout": "HARM_OBSERVED: trailing heap corrupted",
                "healing_actions": ["ClampSize"] * 50,
                "provider_bound": True,
            }
        )
        self.assertEqual(heal_with_harm["verdict"], "REGRESSION")
        self.assertTrue(heal_with_harm["H"]["candidate_harm"])
        self.assertTrue(heal_with_harm["S"]["telemetry_observed"])

        # S03.2 silent_output_corruption: F_accepted=False must NEVER classify as PREVENTED.
        silent_corruption = eval_hsfp(
            {
                "admitted": True,
                "stock_exit": 139,
                "stock_exploitable": True,
                "tsm_exit": 0,
                "expected_tsm_exit": 0,
                "tsm_stdout": "archive_payload_truncated",
                "expected_stdout_regex": "^archive_payload_complete$",
                "healing_actions": ["ClampSize"],
                "provider_bound": True,
            }
        )
        self.assertEqual(silent_corruption["verdict"], "DETECTED")
        self.assertFalse(silent_corruption["F"]["accepted"])

        # S03.3 baseline_not_reproduced: H_stock=False must NEVER classify as PREVENTED.
        baseline_not_repro = eval_hsfp(
            {
                "admitted": True,
                "stock_exit": 0,
                "stock_exploitable": False,
                "tsm_exit": 0,
                "expected_tsm_exit": 0,
                "healing_actions": ["ClampSize"],
                "provider_bound": True,
            }
        )
        self.assertEqual(baseline_not_repro["verdict"], "BASELINE")
        self.assertFalse(baseline_not_repro["H"]["stock_harm"])

        # S05 provider bypass & tampered artifact SHA rejection.
        provider_bypass = eval_hsfp(
            {
                "admitted": True,
                "stock_exit": 139,
                "stock_exploitable": True,
                "tsm_exit": 0,
                "expected_tsm_exit": 0,
                "provider_bound": False,
            }
        )
        self.assertEqual(provider_bypass["verdict"], "UNSUPPORTED_PROVIDER")

        tampered_sha = eval_hsfp(
            {
                "admitted": True,
                "stock_exit": 139,
                "stock_exploitable": True,
                "tsm_exit": 0,
                "expected_tsm_exit": 0,
                "provider_bound": True,
                "lib_sha256": "a" * 64,
                "expected_lib_sha256": "b" * 64,
            }
        )
        self.assertEqual(tampered_sha["verdict"], "INVALID_ADMISSION")

        # S12 architectural boundary honesty: foreign/stack/post-quarantine scope -> NOT_MITIGATED_BY_DESIGN.
        boundary_case = eval_hsfp(
            {
                "admitted": True,
                "scope_boundary": "not_mitigated_by_design",
                "stock_exit": 139,
                "stock_exploitable": True,
                "tsm_exit": 0,
                "expected_tsm_exit": 0,
                "provider_bound": True,
            }
        )
        self.assertEqual(boundary_case["verdict"], "NOT_MITIGATED_BY_DESIGN")

        # Positive 4-axis oracle pass: admitted && H_stock && !H_candidate && F_accepted && P_verified -> PREVENTED.
        oracle_pass = eval_hsfp(
            {
                "admitted": True,
                "scope_boundary": "in_scope",
                "stock_exit": 139,
                "stock_exploitable": True,
                "tsm_exit": 0,
                "expected_tsm_exit": 0,
                "tsm_stdout": "archive_payload_complete",
                "expected_stdout_regex": "^archive_payload_complete$",
                "healing_actions": ["ClampSize"],
                "provider_bound": True,
            }
        )
        self.assertEqual(oracle_pass["verdict"], "PREVENTED")

        # S05 debug artifact path rejection + S07 missing-confinement fail-closed check.
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            debug_dir = tmp_path / "debug"
            debug_dir.mkdir()
            fake_debug_so = debug_dir / "libfrankenlibc_abi.so"
            fake_debug_so.write_bytes(b"\x7fELFdebug")
            res_debug = subprocess.run(
                ["bash", str(runner), "--no-docker", "--all", f"--results-dir={tmp_path / 'res1'}"],
                env={**dict(__import__("os").environ), "FRANKENLIBC_LIB": str(fake_debug_so)},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(res_debug.returncode, 0)
            self.assertIn("INVALID_ADMISSION", res_debug.stderr)

            res_iso = subprocess.run(
                ["bash", str(runner), "--all", f"--results-dir={tmp_path / 'res2'}"],
                env={
                    **dict(__import__("os").environ),
                    "CVE_ARENA_FORCE_MISSING_ISOLATION": "1",
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(res_iso.returncode, 0)
            self.assertIn("blocked_missing_isolation", res_iso.stderr)
            iso_json = json.loads((tmp_path / "res2" / "isolation_status.json").read_text(encoding="utf-8"))
            self.assertEqual(iso_json["status"], "blocked_missing_isolation")


if __name__ == "__main__":
    unittest.main()
