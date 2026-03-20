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
CounterexampleWitness = pbv_mod.CounterexampleWitness
validate_obligation = pbv_mod.validate_obligation
validate_binder = pbv_mod.validate_binder
build_counterexample_witness = pbv_mod.build_counterexample_witness
file_sha256 = pbv_mod.file_sha256
parse_source_ref = pbv_mod.parse_source_ref


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

    def test_planned_obligation_requires_owner_schema_and_command(self) -> None:
        ob = {
            "id": "PO-PLAN-MISSING",
            "statement": "Planned theorem",
            "status": "planned",
            "category": "core_safety",
            "evidence_artifacts": ["tests/conformance/proof_obligations_binder.v1.json"],
            "gates": ["scripts/gentoo/proof_binder_validator.py"],
            "join_keys": ["gate=test"],
            "scope": {"modes": ["strict"]},
        }
        status = validate_obligation(ob, REPO_ROOT, check_hashes=False)
        self.assertFalse(status.valid)
        codes = {v.violation_code for v in status.violations}
        self.assertIn("MISSING_OWNER", codes)
        self.assertIn("MISSING_ARTIFACT_SCHEMA", codes)
        self.assertIn("MISSING_VERIFICATION_COMMAND", codes)

    def test_planned_obligation_with_required_metadata_passes(self) -> None:
        ob = {
            "id": "PO-PLAN-OK",
            "statement": "Planned theorem",
            "status": "planned",
            "owner": "bd-w2c3.6.1",
            "artifact_schema": "proof_obligation_record.v1",
            "verification_command": "bash scripts/check_proof_binder.sh",
            "category": "core_safety",
            "evidence_artifacts": ["tests/conformance/proof_obligations_binder.v1.json"],
            "gates": ["scripts/gentoo/proof_binder_validator.py"],
            "join_keys": ["gate=test"],
            "scope": {"modes": ["strict"]},
        }
        status = validate_obligation(ob, REPO_ROOT, check_hashes=False)
        self.assertTrue(status.valid)

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

    def test_valid_source_ref(self) -> None:
        ob = {
            "id": "PO-SRC",
            "statement": "Source refs",
            "category": "core",
            "evidence_artifacts": ["tests/conformance/proof_obligations_binder.v1.json"],
            "gates": ["scripts/gentoo/proof_binder_validator.py"],
            "join_keys": ["gate=test"],
            "scope": {"modes": ["strict"]},
            "source_refs": ["tests/conformance/proof_obligations_binder.v1.json:1"],
        }
        status = validate_obligation(ob, REPO_ROOT, check_hashes=False)
        self.assertTrue(status.valid)
        self.assertEqual(status.source_refs_total, 1)
        self.assertEqual(status.source_refs_valid, 1)
        self.assertEqual(status.source_refs_invalid, 0)

    def test_missing_source_ref_file(self) -> None:
        ob = {
            "id": "PO-SRC",
            "statement": "Source refs",
            "category": "core",
            "evidence_artifacts": ["tests/conformance/proof_obligations_binder.v1.json"],
            "gates": ["scripts/gentoo/proof_binder_validator.py"],
            "join_keys": ["gate=test"],
            "scope": {"modes": ["strict"]},
            "source_refs": ["does/not/exist.rs:10"],
        }
        status = validate_obligation(ob, REPO_ROOT, check_hashes=False)
        self.assertFalse(status.valid)
        self.assertEqual(status.source_refs_total, 1)
        self.assertEqual(status.source_refs_valid, 0)
        self.assertEqual(status.source_refs_invalid, 1)
        codes = [v.violation_code for v in status.violations]
        self.assertIn("SOURCE_REF_MISSING_FILE", codes)

    def test_source_ref_line_out_of_range(self) -> None:
        ob = {
            "id": "PO-SRC",
            "statement": "Source refs",
            "category": "core",
            "evidence_artifacts": ["tests/conformance/proof_obligations_binder.v1.json"],
            "gates": ["scripts/gentoo/proof_binder_validator.py"],
            "join_keys": ["gate=test"],
            "scope": {"modes": ["strict"]},
            "source_refs": ["tests/conformance/proof_obligations_binder.v1.json:999999"],
        }
        status = validate_obligation(ob, REPO_ROOT, check_hashes=False)
        self.assertFalse(status.valid)
        codes = [v.violation_code for v in status.violations]
        self.assertIn("SOURCE_REF_BAD_LINE", codes)

    def test_source_ref_invalid_format(self) -> None:
        ob = {
            "id": "PO-SRC",
            "statement": "Source refs",
            "category": "core",
            "evidence_artifacts": ["tests/conformance/proof_obligations_binder.v1.json"],
            "gates": ["scripts/gentoo/proof_binder_validator.py"],
            "join_keys": ["gate=test"],
            "scope": {"modes": ["strict"]},
            "source_refs": ["bad-format-without-line"],
        }
        status = validate_obligation(ob, REPO_ROOT, check_hashes=False)
        self.assertFalse(status.valid)
        codes = [v.violation_code for v in status.violations]
        self.assertIn("SOURCE_REF_INVALID_FORMAT", codes)


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
        ce = CounterexampleWitness(
            counterexample_id="CE-PO-01",
            obligation_id="PO-01",
            statement="Test",
            category="core",
            primary_violation_code="EVIDENCE_MISSING",
            primary_message="missing",
            remediation_hint="fix it",
            reproduction_command="python3 scripts/gentoo/proof_binder_validator.py",
        )
        report = BinderValidationReport(
            obligations=[o],
            counterexamples=[ce],
            timestamp="2025-01-01T00:00:00Z",
        )
        d = report.to_dict()
        self.assertEqual(d["total_obligations"], 1)
        self.assertEqual(d["valid_obligations"], 1)
        self.assertTrue(d["binder_valid"])
        self.assertEqual(len(d["counterexamples"]), 1)

    def test_markdown(self) -> None:
        o = ObligationStatus(
            obligation_id="PO-01", statement="Test theorem", category="core",
            valid=False,
            violations=[ObligationViolation("PO-01", "EVIDENCE_MISSING", "missing")],
        )
        ce = CounterexampleWitness(
            counterexample_id="CE-PO-01",
            obligation_id="PO-01",
            statement="Test theorem",
            category="core",
            primary_violation_code="EVIDENCE_MISSING",
            primary_message="missing",
            remediation_hint="create artifact",
            reproduction_command="python3 scripts/gentoo/proof_binder_validator.py",
        )
        report = BinderValidationReport(
            obligations=[o],
            counterexamples=[ce],
            timestamp="2025-01-01T00:00:00Z",
        )
        md = report.to_markdown()
        self.assertIn("Proof Obligations Binder", md)
        self.assertIn("PO-01", md)
        self.assertIn("Counterexamples", md)
        self.assertIn("CE-PO-01", md)


class TestCounterexampleWitness(unittest.TestCase):
    def test_to_dict(self) -> None:
        witness = CounterexampleWitness(
            counterexample_id="CE-PO-X",
            obligation_id="PO-X",
            statement="Theorem",
            category="core",
            primary_violation_code="GATE_MISSING",
            primary_message="missing gate",
            remediation_hint="add gate",
            reproduction_command="python3 scripts/gentoo/proof_binder_validator.py",
            minimized_inputs={"gates": ["scripts/missing.sh"]},
        )
        data = witness.to_dict()
        self.assertEqual(data["counterexample_id"], "CE-PO-X")
        self.assertEqual(data["minimized_inputs"]["gates"], ["scripts/missing.sh"])

    def test_build_counterexample_prefers_missing_evidence(self) -> None:
        obligation = {
            "id": "PO-CE",
            "statement": "Counterexample theorem",
            "category": "core",
            "evidence_artifacts": ["nonexistent/proof.json"],
            "gates": ["nonexistent/gate.sh"],
            "join_keys": ["gate=test"],
            "scope": {"modes": ["strict"]},
        }
        status = validate_obligation(obligation, REPO_ROOT, check_hashes=False)
        witness = build_counterexample_witness(status, obligation, BINDER_PATH)
        self.assertIsNotNone(witness)
        assert witness is not None
        self.assertEqual(witness.primary_violation_code, "EVIDENCE_MISSING")
        self.assertEqual(
            witness.minimized_inputs["evidence_artifacts"],
            ["nonexistent/proof.json"],
        )
        self.assertIn("proof_binder_validator.py", witness.reproduction_command)


class TestFileSha256(unittest.TestCase):
    def test_existing_file(self) -> None:
        h = file_sha256(BINDER_PATH)
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 64)

    def test_missing_file(self) -> None:
        h = file_sha256(Path("/nonexistent"))
        self.assertIsNone(h)


class TestParseSourceRef(unittest.TestCase):
    def test_parse_valid(self) -> None:
        parsed = parse_source_ref("crates/frankenlibc-core/src/errno/mod.rs:69")
        self.assertEqual(parsed, ("crates/frankenlibc-core/src/errno/mod.rs", 69))

    def test_parse_invalid(self) -> None:
        self.assertIsNone(parse_source_ref("missing-line"))
        self.assertIsNone(parse_source_ref("bad-line:abc"))
        self.assertIsNone(parse_source_ref("bad-line:0"))


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
            self.assertIn("counterexamples", data)

    def test_terminal_mode(self) -> None:
        result = subprocess.run(
            [sys.executable, str(VALIDATOR_SCRIPT),
             "--dry-run", "--format", "terminal", "--no-hashes"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertIn("Proof Obligations Binder", result.stdout)


if __name__ == "__main__":
    unittest.main()
