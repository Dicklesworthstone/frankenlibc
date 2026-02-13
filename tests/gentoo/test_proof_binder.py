#!/usr/bin/env python3
"""Tests for proof obligations binder validator (bd-5fw.4).

Validates:
- ObligationViolation and ObligationStatus models
- Obligation validation logic (evidence, gates, join keys, scope)
- Binder validation (schema, duplicates, full check)
- Report generation and schema
- Failure injection (missing artifacts, missing gates)
- CLI execution
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_SCRIPT = REPO_ROOT / "scripts" / "gentoo" / "proof_binder_validator.py"
BINDER_PATH = REPO_ROOT / "tests" / "conformance" / "proof_obligations_binder.v1.json"

import importlib.util

spec = importlib.util.spec_from_file_location("proof_binder_validator", str(VALIDATOR_SCRIPT))
pbv_mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
sys.modules["proof_binder_validator"] = pbv_mod
spec.loader.exec_module(pbv_mod)  # type: ignore[union-attr]

ObligationViolation = pbv_mod.ObligationViolation
ObligationStatus = pbv_mod.ObligationStatus
BinderValidationReport = pbv_mod.BinderValidationReport
validate_obligation = pbv_mod.validate_obligation
validate_binder = pbv_mod.validate_binder
file_sha256 = pbv_mod.file_sha256


class TestObligationViolation(unittest.TestCase):
    def test_to_dict(self) -> None:
        v = ObligationViolation(
            obligation_id="PO-01",
            violation_code="EVIDENCE_MISSING",
            message="Not found",
            remediation_hint="Create it",
        )
        d = v.to_dict()
        self.assertEqual(d["obligation_id"], "PO-01")
        self.assertEqual(d["violation_code"], "EVIDENCE_MISSING")
        self.assertIn("remediation_hint", d)

    def test_no_hint(self) -> None:
        v = ObligationViolation("PO-01", "CODE", "msg")
        d = v.to_dict()
        self.assertNotIn("remediation_hint", d)


class TestObligationStatus(unittest.TestCase):
    def test_valid(self) -> None:
        s = ObligationStatus(
            obligation_id="PO-01", statement="Test", category="core",
            evidence_found=1, gates_found=1,
        )
        self.assertTrue(s.valid)
        d = s.to_dict()
        self.assertEqual(d["obligation_id"], "PO-01")

    def test_invalid(self) -> None:
        s = ObligationStatus(
            obligation_id="PO-01", statement="Test", category="core",
            valid=False,
            violations=[ObligationViolation("PO-01", "CODE", "msg")],
        )
        self.assertFalse(s.valid)
        d = s.to_dict()
        self.assertEqual(len(d["violations"]), 1)


class TestValidateObligation(unittest.TestCase):
    def test_valid_obligation(self) -> None:
        ob = {
            "id": "PO-01",
            "statement": "Test theorem",
            "category": "core_safety",
            "evidence_artifacts": ["tests/conformance/proof_obligations_binder.v1.json"],
            "gates": ["scripts/gentoo/proof_binder_validator.py"],
            "join_keys": ["gate=test"],
            "scope": {"modes": ["strict"]},
        }
        status = validate_obligation(ob, REPO_ROOT, check_hashes=False)
        self.assertTrue(status.valid)
        self.assertEqual(status.evidence_found, 1)
        self.assertEqual(status.gates_found, 1)

    def test_missing_evidence(self) -> None:
        ob = {
            "id": "PO-X",
            "statement": "Test",
            "category": "core",
            "evidence_artifacts": ["nonexistent/file.json"],
            "gates": ["scripts/gentoo/proof_binder_validator.py"],
            "join_keys": ["gate=test"],
            "scope": {"modes": ["strict"]},
        }
        status = validate_obligation(ob, REPO_ROOT, check_hashes=False)
        self.assertFalse(status.valid)
        self.assertEqual(status.evidence_missing, 1)
        codes = [v.violation_code for v in status.violations]
        self.assertIn("EVIDENCE_MISSING", codes)

    def test_missing_gate(self) -> None:
        ob = {
            "id": "PO-X",
            "statement": "Test",
            "category": "core",
            "evidence_artifacts": ["tests/conformance/proof_obligations_binder.v1.json"],
            "gates": ["nonexistent/gate.sh"],
            "join_keys": ["gate=test"],
            "scope": {"modes": ["strict"]},
        }
        status = validate_obligation(ob, REPO_ROOT, check_hashes=False)
        self.assertFalse(status.valid)
        codes = [v.violation_code for v in status.violations]
        self.assertIn("GATE_MISSING", codes)

    def test_missing_join_keys(self) -> None:
        ob = {
            "id": "PO-X",
            "statement": "Test",
            "category": "core",
            "evidence_artifacts": ["tests/conformance/proof_obligations_binder.v1.json"],
            "gates": ["scripts/gentoo/proof_binder_validator.py"],
            "join_keys": [],
            "scope": {"modes": ["strict"]},
        }
        status = validate_obligation(ob, REPO_ROOT, check_hashes=False)
        self.assertFalse(status.valid)
        codes = [v.violation_code for v in status.violations]
        self.assertIn("MISSING_JOIN_KEYS", codes)

    def test_missing_scope(self) -> None:
        ob = {
            "id": "PO-X",
            "statement": "Test",
            "category": "core",
            "evidence_artifacts": ["tests/conformance/proof_obligations_binder.v1.json"],
            "gates": ["scripts/gentoo/proof_binder_validator.py"],
            "join_keys": ["gate=test"],
            "scope": {},
        }
        status = validate_obligation(ob, REPO_ROOT, check_hashes=False)
        self.assertFalse(status.valid)
        codes = [v.violation_code for v in status.violations]
        self.assertIn("MISSING_SCOPE", codes)

    def test_sha256_computed(self) -> None:
        ob = {
            "id": "PO-X",
            "statement": "Test",
            "category": "core",
            "evidence_artifacts": ["tests/conformance/proof_obligations_binder.v1.json"],
            "gates": ["scripts/gentoo/proof_binder_validator.py"],
            "join_keys": ["gate=test"],
            "scope": {"modes": ["strict"]},
        }
        status = validate_obligation(ob, REPO_ROOT, check_hashes=True)
        self.assertIn("tests/conformance/proof_obligations_binder.v1.json",
                       status.evidence_hashes)
        h = status.evidence_hashes["tests/conformance/proof_obligations_binder.v1.json"]
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 64)  # SHA-256 hex digest


class TestValidateBinder(unittest.TestCase):
    def test_real_binder(self) -> None:
        report = validate_binder(BINDER_PATH, REPO_ROOT, check_hashes=False)
        self.assertGreater(report.total_obligations, 0)

    def test_missing_binder(self) -> None:
        report = validate_binder(Path("/nonexistent"), REPO_ROOT)
        self.assertFalse(report.binder_valid)

    def test_bad_schema(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"schema_version": "v99"}, f)
            f.flush()
            report = validate_binder(Path(f.name), REPO_ROOT)
        self.assertFalse(report.binder_valid)

    def test_duplicate_ids(self) -> None:
        binder = {
            "schema_version": "v1",
            "bead": "test",
            "obligations": [
                {"id": "PO-01", "statement": "A", "category": "c",
                 "evidence_artifacts": [], "gates": [],
                 "join_keys": ["k"], "scope": {"m": "v"}},
                {"id": "PO-01", "statement": "B", "category": "c",
                 "evidence_artifacts": [], "gates": [],
                 "join_keys": ["k"], "scope": {"m": "v"}},
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(binder, f)
            f.flush()
            report = validate_binder(Path(f.name), REPO_ROOT, check_hashes=False)
        dup_violations = [
            v for o in report.obligations
            for v in o.violations if v.violation_code == "DUPLICATE_ID"
        ]
        self.assertGreater(len(dup_violations), 0)

    def test_failure_injection_missing_evidence(self) -> None:
        binder = {
            "schema_version": "v1",
            "bead": "test",
            "obligations": [
                {
                    "id": "PO-INJ",
                    "statement": "Injected failure",
                    "category": "test",
                    "evidence_artifacts": ["nonexistent/proof.json"],
                    "gates": ["nonexistent/gate.sh"],
                    "join_keys": ["gate=test"],
                    "scope": {"modes": ["strict"]},
                },
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(binder, f)
            f.flush()
            report = validate_binder(Path(f.name), REPO_ROOT, check_hashes=False)
        self.assertFalse(report.binder_valid)
        self.assertEqual(report.invalid_obligations, 1)
        codes = [
            v.violation_code for o in report.obligations for v in o.violations
        ]
        self.assertIn("EVIDENCE_MISSING", codes)
        self.assertIn("GATE_MISSING", codes)


class TestBinderValidationReport(unittest.TestCase):
    def test_empty(self) -> None:
        report = BinderValidationReport(timestamp="2025-01-01T00:00:00Z")
        d = report.to_dict()
        self.assertEqual(d["schema_version"], "v1")
        self.assertEqual(d["bead"], "bd-5fw.4")
        self.assertTrue(d["binder_valid"])

    def test_with_obligations(self) -> None:
        o = ObligationStatus(
            obligation_id="PO-01", statement="Test", category="core",
            evidence_found=1, gates_found=1,
        )
        report = BinderValidationReport(
            obligations=[o],
            timestamp="2025-01-01T00:00:00Z",
        )
        d = report.to_dict()
        self.assertEqual(d["total_obligations"], 1)
        self.assertEqual(d["valid_obligations"], 1)
        self.assertTrue(d["binder_valid"])

    def test_markdown(self) -> None:
        o = ObligationStatus(
            obligation_id="PO-01", statement="Test theorem", category="core",
        )
        report = BinderValidationReport(
            obligations=[o],
            timestamp="2025-01-01T00:00:00Z",
        )
        md = report.to_markdown()
        self.assertIn("Proof Obligations Binder", md)
        self.assertIn("PO-01", md)


class TestFileSha256(unittest.TestCase):
    def test_existing_file(self) -> None:
        h = file_sha256(BINDER_PATH)
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 64)

    def test_missing_file(self) -> None:
        h = file_sha256(Path("/nonexistent"))
        self.assertIsNone(h)


class TestCLI(unittest.TestCase):
    def test_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            result = subprocess.run(
                [sys.executable, str(VALIDATOR_SCRIPT),
                 "--dry-run", "--format", "json",
                 "--no-hashes", "--output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertTrue(output.exists(), f"stderr: {result.stderr[-300:]}")
            data = json.loads(output.read_text())
            self.assertEqual(data["schema_version"], "v1")
            self.assertEqual(data["bead"], "bd-5fw.4")
            self.assertIn("obligations", data)

    def test_terminal_mode(self) -> None:
        result = subprocess.run(
            [sys.executable, str(VALIDATOR_SCRIPT),
             "--dry-run", "--format", "terminal", "--no-hashes"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertIn("Proof Obligations Binder", result.stdout)


if __name__ == "__main__":
    unittest.main()
