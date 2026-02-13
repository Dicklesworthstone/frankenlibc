#!/usr/bin/env python3
"""Tests for branch-diversity gate (bd-5fw.5).

Validates:
- DiversitySpec loading and module-to-family indexing
- MilestoneAnalysis calculations
- Diversity constraint checks (min families, required families, dominance, SIMD/ABI)
- Report generation and schema
- CLI execution
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE_SCRIPT = REPO_ROOT / "scripts" / "gentoo" / "branch_diversity_gate.py"

import importlib.util

spec = importlib.util.spec_from_file_location("branch_diversity_gate", str(GATE_SCRIPT))
bdg_mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
sys.modules["branch_diversity_gate"] = bdg_mod
spec.loader.exec_module(bdg_mod)  # type: ignore[union-attr]

DiversityViolation = bdg_mod.DiversityViolation
MilestoneAnalysis = bdg_mod.MilestoneAnalysis
DiversitySpec = bdg_mod.DiversitySpec
DiversityReport = bdg_mod.DiversityReport
classify_module_families = bdg_mod.classify_module_families
check_milestone_diversity = bdg_mod.check_milestone_diversity
run_diversity_check = bdg_mod.run_diversity_check


def make_spec(
    families: Dict[str, List[str]] | None = None,
    constraints: Dict[str, Any] | None = None,
) -> DiversitySpec:
    """Create a test spec."""
    if families is None:
        families = {
            "family_a": ["mod1", "mod2"],
            "family_b": ["mod3", "mod4"],
            "family_c": ["mod5"],
            "family_d": ["mod6"],
        }
    data = {
        "math_families": {
            fam: {"modules": mods} for fam, mods in families.items()
        },
        "milestones": [],
        "constraints": constraints or {
            "min_distinct_families": 3,
            "max_family_dominance_pct": 40,
            "required_families_all": ["family_a", "family_b"],
            "required_families_simd_abi": ["family_c"],
        },
    }
    return DiversitySpec.from_dict(data)


class TestDiversityViolation(unittest.TestCase):
    def test_to_dict(self) -> None:
        v = DiversityViolation(
            milestone_id="test", constraint="min_families",
            message="Too few families",
        )
        d = v.to_dict()
        self.assertEqual(d["milestone_id"], "test")
        self.assertEqual(d["constraint"], "min_families")
        self.assertEqual(d["severity"], "error")


class TestMilestoneAnalysis(unittest.TestCase):
    def test_empty(self) -> None:
        a = MilestoneAnalysis(milestone_id="test", milestone_name="Test",
                               is_simd_abi=False)
        self.assertTrue(a.passed)
        self.assertEqual(a.family_count, 0)
        self.assertEqual(a.max_dominance_pct(), 0.0)
        self.assertIsNone(a.dominant_family())

    def test_with_data(self) -> None:
        a = MilestoneAnalysis(
            milestone_id="test", milestone_name="Test",
            is_simd_abi=False,
            obligation_count=10,
            families_used=["fam_a", "fam_b", "fam_c"],
            family_counts={"fam_a": 5, "fam_b": 3, "fam_c": 2},
        )
        self.assertEqual(a.family_count, 3)
        self.assertEqual(a.max_dominance_pct(), 50.0)
        self.assertEqual(a.dominant_family(), "fam_a")

    def test_passed_with_violations(self) -> None:
        a = MilestoneAnalysis(
            milestone_id="test", milestone_name="Test", is_simd_abi=False,
            violations=[DiversityViolation("test", "c", "msg")],
        )
        self.assertFalse(a.passed)

    def test_to_dict(self) -> None:
        a = MilestoneAnalysis(
            milestone_id="test", milestone_name="Test", is_simd_abi=True,
            obligation_count=5, families_used=["a", "b"],
            family_counts={"a": 3, "b": 2},
        )
        d = a.to_dict()
        self.assertIn("milestone_id", d)
        self.assertIn("passed", d)
        self.assertIn("family_count", d)
        self.assertIn("max_dominance_pct", d)


class TestDiversitySpec(unittest.TestCase):
    def test_from_dict(self) -> None:
        spec = make_spec()
        self.assertIn("family_a", spec.math_families)
        self.assertIn("mod1", spec.module_to_families)
        self.assertEqual(spec.module_to_families["mod1"], ["family_a"])

    def test_module_in_multiple_families(self) -> None:
        spec = make_spec(families={
            "fam_x": ["shared_mod"],
            "fam_y": ["shared_mod"],
        })
        self.assertEqual(len(spec.module_to_families["shared_mod"]), 2)


class TestClassifyModuleFamilies(unittest.TestCase):
    def test_basic(self) -> None:
        spec = make_spec()
        counts = classify_module_families(["mod1", "mod3", "mod5"], spec)
        self.assertEqual(counts["family_a"], 1)
        self.assertEqual(counts["family_b"], 1)
        self.assertEqual(counts["family_c"], 1)

    def test_unknown_module(self) -> None:
        spec = make_spec()
        counts = classify_module_families(["unknown_mod"], spec)
        self.assertEqual(len(counts), 0)

    def test_multiple_from_same_family(self) -> None:
        spec = make_spec()
        counts = classify_module_families(["mod1", "mod2"], spec)
        self.assertEqual(counts["family_a"], 2)


class TestCheckMilestoneDiversity(unittest.TestCase):
    def test_all_pass(self) -> None:
        spec = make_spec()
        milestone = {"id": "test", "name": "Test", "is_simd_abi": False}
        modules = ["mod1", "mod3", "mod5", "mod6"]
        analysis = check_milestone_diversity(milestone, modules, spec)
        self.assertTrue(analysis.passed)
        self.assertEqual(len(analysis.violations), 0)

    def test_too_few_families(self) -> None:
        spec = make_spec()
        milestone = {"id": "test", "name": "Test", "is_simd_abi": False}
        modules = ["mod1", "mod2"]  # only family_a
        analysis = check_milestone_diversity(milestone, modules, spec)
        self.assertFalse(analysis.passed)
        constraints = [v.constraint for v in analysis.violations]
        self.assertIn("min_distinct_families", constraints)

    def test_missing_required_family(self) -> None:
        spec = make_spec()
        milestone = {"id": "test", "name": "Test", "is_simd_abi": False}
        modules = ["mod1", "mod5", "mod6"]  # missing family_b
        analysis = check_milestone_diversity(milestone, modules, spec)
        self.assertFalse(analysis.passed)
        constraints = [v.constraint for v in analysis.violations]
        self.assertIn("required_family_missing", constraints)

    def test_family_dominance(self) -> None:
        spec = make_spec(constraints={
            "min_distinct_families": 2,
            "max_family_dominance_pct": 40,
            "required_families_all": [],
            "required_families_simd_abi": [],
        })
        milestone = {"id": "test", "name": "Test", "is_simd_abi": False}
        # family_a gets 3 out of 4 = 75% dominance
        modules = ["mod1", "mod2", "mod1", "mod3"]
        analysis = check_milestone_diversity(milestone, modules, spec)
        dominance_violations = [
            v for v in analysis.violations if v.constraint == "family_dominance"
        ]
        self.assertGreater(len(dominance_violations), 0)

    def test_simd_abi_requires_extra(self) -> None:
        spec = make_spec()
        milestone = {"id": "test", "name": "Test", "is_simd_abi": True}
        modules = ["mod1", "mod3", "mod6"]  # missing family_c for SIMD
        analysis = check_milestone_diversity(milestone, modules, spec)
        simd_violations = [
            v for v in analysis.violations if v.constraint == "simd_abi_required_family"
        ]
        self.assertGreater(len(simd_violations), 0)

    def test_simd_abi_passes_with_required(self) -> None:
        spec = make_spec()
        milestone = {"id": "test", "name": "Test", "is_simd_abi": True}
        modules = ["mod1", "mod3", "mod5", "mod6"]  # includes family_c
        analysis = check_milestone_diversity(milestone, modules, spec)
        simd_violations = [
            v for v in analysis.violations if v.constraint == "simd_abi_required_family"
        ]
        self.assertEqual(len(simd_violations), 0)

    def test_remediation_provided(self) -> None:
        spec = make_spec()
        milestone = {"id": "test", "name": "Test", "is_simd_abi": False}
        modules = ["mod1"]
        analysis = check_milestone_diversity(milestone, modules, spec)
        self.assertGreater(len(analysis.remediation), 0)


class TestDiversityReport(unittest.TestCase):
    def test_empty(self) -> None:
        report = DiversityReport(timestamp="2025-01-01T00:00:00Z")
        d = report.to_dict()
        self.assertEqual(d["schema_version"], "v1")
        self.assertEqual(d["bead"], "bd-5fw.5")
        self.assertTrue(d["gate_passed"])

    def test_with_violations(self) -> None:
        analysis = MilestoneAnalysis(
            milestone_id="test", milestone_name="Test", is_simd_abi=False,
            violations=[DiversityViolation("test", "c", "msg")],
        )
        report = DiversityReport(
            milestones=[analysis],
            timestamp="2025-01-01T00:00:00Z",
        )
        d = report.to_dict()
        self.assertFalse(d["gate_passed"])
        self.assertEqual(d["error_count"], 1)

    def test_warn_only_passes(self) -> None:
        analysis = MilestoneAnalysis(
            milestone_id="test", milestone_name="Test", is_simd_abi=False,
            violations=[DiversityViolation("test", "c", "msg", severity="warn")],
        )
        report = DiversityReport(
            milestones=[analysis],
            timestamp="2025-01-01T00:00:00Z",
        )
        d = report.to_dict()
        self.assertTrue(d["gate_passed"])
        self.assertEqual(d["warn_count"], 1)

    def test_markdown(self) -> None:
        analysis = MilestoneAnalysis(
            milestone_id="test", milestone_name="Test", is_simd_abi=False,
            obligation_count=5, families_used=["a", "b", "c"],
            family_counts={"a": 2, "b": 2, "c": 1},
        )
        report = DiversityReport(
            milestones=[analysis],
            timestamp="2025-01-01T00:00:00Z",
        )
        md = report.to_markdown()
        self.assertIn("Branch-Diversity Gate Report", md)
        self.assertIn("PASS", md)
        self.assertIn("Test", md)


class TestRunDiversityCheck(unittest.TestCase):
    def test_with_repo_spec(self) -> None:
        report = run_diversity_check()
        self.assertEqual(len(report.milestones), 10)
        for m in report.milestones:
            self.assertGreater(m.obligation_count, 0)
            self.assertGreater(m.family_count, 0)

    def test_missing_spec(self) -> None:
        report = run_diversity_check(spec_path=Path("/nonexistent"))
        self.assertFalse(report.gate_passed)


class TestCLI(unittest.TestCase):
    def test_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            result = subprocess.run(
                [sys.executable, str(GATE_SCRIPT),
                 "--dry-run", "--format", "json", "--output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            # May fail if constraints are violated, but should produce output
            self.assertTrue(output.exists(), f"stderr: {result.stderr[-300:]}")
            data = json.loads(output.read_text())
            self.assertEqual(data["schema_version"], "v1")
            self.assertEqual(data["bead"], "bd-5fw.5")
            self.assertIn("milestones", data)

    def test_terminal_mode(self) -> None:
        result = subprocess.run(
            [sys.executable, str(GATE_SCRIPT), "--dry-run", "--format", "terminal"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertIn("Branch-Diversity Gate", result.stdout)


if __name__ == "__main__":
    unittest.main()
