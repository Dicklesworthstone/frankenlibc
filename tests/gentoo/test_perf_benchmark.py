#!/usr/bin/env python3
"""Tests for Gentoo performance benchmarking infrastructure (bd-2icq.9).

Validates:
- LatencyProfile statistics and percentile calculations
- PackageBenchmark data model
- BenchmarkSuite aggregation
- Dry-run mode produces valid structured output
- CLI argument parsing
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PERF_BENCHMARK = REPO_ROOT / "scripts" / "gentoo" / "perf-benchmark.py"

# Import the module under test (filename has a hyphen so we use importlib)
import importlib.util

spec = importlib.util.spec_from_file_location("perf_benchmark", str(PERF_BENCHMARK))
perf_benchmark = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
sys.modules["perf_benchmark"] = perf_benchmark  # register before exec to fix dataclass
spec.loader.exec_module(perf_benchmark)  # type: ignore[union-attr]

LatencyProfile = perf_benchmark.LatencyProfile
PackageBenchmark = perf_benchmark.PackageBenchmark
BenchmarkSuite = perf_benchmark.BenchmarkSuite
benchmark_package_dry = perf_benchmark.benchmark_package_dry
load_packages = perf_benchmark.load_packages
main = perf_benchmark.main


class TestLatencyProfile(unittest.TestCase):
    """Validate LatencyProfile statistics calculations."""

    def test_empty_profile(self) -> None:
        p = LatencyProfile()
        self.assertEqual(p.total_calls, 0)
        self.assertEqual(p.avg_ns, 0.0)
        self.assertEqual(p.percentile(50), 0)
        self.assertEqual(p.percentile(99), 0)
        self.assertEqual(p.claim_200ns_percentile(), 100.0)
        self.assertEqual(p.top_hotspots(), [])

    def test_single_record(self) -> None:
        p = LatencyProfile()
        p.record("malloc", 100)
        self.assertEqual(p.total_calls, 1)
        self.assertEqual(p.avg_ns, 100.0)
        self.assertEqual(p.latency_max_ns, 100)
        self.assertEqual(p.percentile(50), 100)
        self.assertEqual(p.by_call["malloc"], 1)

    def test_multiple_records(self) -> None:
        p = LatencyProfile()
        p.record("malloc", 50)
        p.record("free", 30)
        p.record("malloc", 70)
        self.assertEqual(p.total_calls, 3)
        self.assertEqual(p.latency_sum_ns, 150)
        self.assertEqual(p.latency_max_ns, 70)
        self.assertAlmostEqual(p.avg_ns, 50.0)
        self.assertEqual(p.by_call["malloc"], 2)
        self.assertEqual(p.by_call["free"], 1)

    def test_healing_action_tracking(self) -> None:
        p = LatencyProfile()
        p.record("malloc", 100, "ClampSize")
        p.record("malloc", 50)
        p.record("strcpy", 200, "TruncateWithNull")
        self.assertEqual(p.healing_actions, 2)
        self.assertEqual(p.by_action["ClampSize"], 1)
        self.assertEqual(p.by_action["TruncateWithNull"], 1)

    def test_percentile_calculation(self) -> None:
        p = LatencyProfile()
        # Add 100 values: 1..100
        for i in range(1, 101):
            p.record("test", i)
        self.assertEqual(p.percentile(50), 50)
        self.assertEqual(p.percentile(95), 95)
        self.assertEqual(p.percentile(99), 99)
        self.assertEqual(p.percentile(100), 100)

    def test_claim_200ns_percentile(self) -> None:
        p = LatencyProfile()
        # 80 calls under 200ns, 20 calls over
        for _ in range(80):
            p.record("fast", 100)
        for _ in range(20):
            p.record("slow", 300)
        self.assertAlmostEqual(p.claim_200ns_percentile(), 80.0)

    def test_top_hotspots(self) -> None:
        p = LatencyProfile()
        # malloc: 10 calls x 100ns = 1000ns total
        for _ in range(10):
            p.record("malloc", 100)
        # free: 5 calls x 200ns = 1000ns total
        for _ in range(5):
            p.record("free", 200)
        # strlen: 1 call x 50ns = 50ns total
        p.record("strlen", 50)

        hotspots = p.top_hotspots(2)
        self.assertEqual(len(hotspots), 2)
        # Both malloc and free have 1000ns total
        calls = {h["call"] for h in hotspots}
        self.assertIn("malloc", calls)
        self.assertIn("free", calls)

    def test_to_dict_schema(self) -> None:
        p = LatencyProfile()
        p.record("malloc", 100, "ClampSize")
        d = p.to_dict()
        required_keys = {
            "total_calls", "avg_latency_ns", "p50_latency_ns",
            "p95_latency_ns", "p99_latency_ns", "max_latency_ns",
            "healing_actions", "claim_200ns_percentile",
            "top_hotspots", "by_action",
        }
        self.assertEqual(required_keys, set(d.keys()))
        self.assertEqual(d["total_calls"], 1)
        self.assertEqual(d["healing_actions"], 1)
        self.assertIn("ClampSize", d["by_action"])


class TestPackageBenchmark(unittest.TestCase):
    """Validate PackageBenchmark data model."""

    def test_basic_to_dict(self) -> None:
        b = PackageBenchmark(
            package="sys-apps/coreutils",
            build_time_baseline_s=100.0,
            build_time_instrumented_s=105.0,
            build_overhead_percent=5.0,
            mode="hardened",
            dry_run=True,
            timestamp="2026-01-01T00:00:00Z",
        )
        d = b.to_dict()
        self.assertEqual(d["package"], "sys-apps/coreutils")
        self.assertEqual(d["build_overhead_percent"], 5.0)
        self.assertTrue(d["dry_run"])
        self.assertNotIn("error", d)
        self.assertNotIn("latency_profile", d)

    def test_error_included(self) -> None:
        b = PackageBenchmark(
            package="sys-apps/coreutils",
            error="baseline build failed (rc=1)",
        )
        d = b.to_dict()
        self.assertIn("error", d)
        self.assertEqual(d["error"], "baseline build failed (rc=1)")

    def test_latency_profile_included(self) -> None:
        profile = {"total_calls": 10, "avg_latency_ns": 50.0}
        b = PackageBenchmark(
            package="sys-apps/coreutils",
            latency_profile=profile,
        )
        d = b.to_dict()
        self.assertIn("latency_profile", d)
        self.assertEqual(d["latency_profile"]["total_calls"], 10)


class TestBenchmarkSuite(unittest.TestCase):
    """Validate BenchmarkSuite aggregation."""

    def test_empty_suite(self) -> None:
        s = BenchmarkSuite()
        agg = s.aggregate()
        self.assertEqual(agg["total_packages"], 0)
        self.assertEqual(agg["successful"], 0)

    def test_all_successful(self) -> None:
        s = BenchmarkSuite(timestamp="2026-01-01T00:00:00Z", mode="hardened")
        s.add(PackageBenchmark(package="a/b", build_overhead_percent=4.0))
        s.add(PackageBenchmark(package="c/d", build_overhead_percent=6.0))
        agg = s.aggregate()
        self.assertEqual(agg["total_packages"], 2)
        self.assertEqual(agg["successful"], 2)
        self.assertEqual(agg["failed"], 0)
        self.assertAlmostEqual(agg["avg_build_overhead_percent"], 5.0)
        self.assertEqual(agg["schema_version"], "v1")
        self.assertEqual(agg["bead"], "bd-2icq.9")

    def test_mixed_success_failure(self) -> None:
        s = BenchmarkSuite()
        s.add(PackageBenchmark(package="a/b", build_overhead_percent=5.0))
        s.add(PackageBenchmark(package="c/d", error="build failed"))
        agg = s.aggregate()
        self.assertEqual(agg["successful"], 1)
        self.assertEqual(agg["failed"], 1)
        self.assertAlmostEqual(agg["avg_build_overhead_percent"], 5.0)

    def test_all_failed(self) -> None:
        s = BenchmarkSuite()
        s.add(PackageBenchmark(package="a/b", error="fail1"))
        s.add(PackageBenchmark(package="c/d", error="fail2"))
        agg = s.aggregate()
        self.assertEqual(agg["successful"], 0)
        self.assertEqual(agg["failed"], 2)

    def test_median_overhead(self) -> None:
        s = BenchmarkSuite()
        s.add(PackageBenchmark(package="a/b", build_overhead_percent=2.0))
        s.add(PackageBenchmark(package="c/d", build_overhead_percent=4.0))
        s.add(PackageBenchmark(package="e/f", build_overhead_percent=10.0))
        agg = s.aggregate()
        # Median of [2.0, 4.0, 10.0] is 4.0 (index 1)
        self.assertAlmostEqual(agg["median_build_overhead_percent"], 4.0)


class TestDryRunBenchmark(unittest.TestCase):
    """Validate dry-run benchmark mode."""

    def test_dry_run_produces_valid_result(self) -> None:
        result = benchmark_package_dry("sys-apps/coreutils", "hardened")
        self.assertEqual(result.package, "sys-apps/coreutils")
        self.assertTrue(result.dry_run)
        self.assertEqual(result.mode, "hardened")
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.latency_profile)
        self.assertGreater(result.build_time_baseline_s, 0)
        self.assertGreater(result.build_time_instrumented_s, 0)
        self.assertGreater(result.build_overhead_percent, 0)

    def test_dry_run_deterministic(self) -> None:
        """Same package produces same results (seeded random)."""
        r1 = benchmark_package_dry("sys-apps/coreutils", "hardened")
        r2 = benchmark_package_dry("sys-apps/coreutils", "hardened")
        self.assertEqual(r1.build_time_baseline_s, r2.build_time_baseline_s)
        self.assertEqual(r1.build_overhead_percent, r2.build_overhead_percent)

    def test_dry_run_latency_profile_schema(self) -> None:
        result = benchmark_package_dry("dev-libs/json-c", "hardened")
        profile = result.latency_profile
        self.assertIsNotNone(profile)
        self.assertIn("total_calls", profile)
        self.assertIn("avg_latency_ns", profile)
        self.assertIn("p50_latency_ns", profile)
        self.assertIn("p95_latency_ns", profile)
        self.assertIn("p99_latency_ns", profile)
        self.assertIn("top_hotspots", profile)
        self.assertIn("claim_200ns_percentile", profile)
        self.assertGreater(profile["total_calls"], 0)


class TestLoadPackages(unittest.TestCase):
    """Validate package loading."""

    def test_load_tier1(self) -> None:
        packages = load_packages("tier1")
        if not packages:
            self.skipTest("tier1-mini.txt not found")
        self.assertEqual(len(packages), 5)

    def test_load_single_atom(self) -> None:
        packages = load_packages("sys-apps/coreutils")
        self.assertEqual(packages, ["sys-apps/coreutils"])


class TestCLIDryRun(unittest.TestCase):
    """Validate CLI dry-run execution."""

    def test_dry_run_cli_exit_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "results.json"
            result = subprocess.run(
                [
                    sys.executable, str(PERF_BENCHMARK),
                    "--mode", "dry-run",
                    "--packages", "sys-apps/coreutils",
                    "--output", str(output_path),
                ],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(
                result.returncode, 0,
                f"dry-run failed: {result.stderr[-500:]}",
            )
            self.assertTrue(output_path.exists(), "Output file not created")

            data = json.loads(output_path.read_text())
            self.assertEqual(data["schema_version"], "v1")
            self.assertEqual(data["bead"], "bd-2icq.9")
            self.assertEqual(data["total_packages"], 1)
            self.assertEqual(data["successful"], 1)
            self.assertTrue(data["dry_run"])

    def test_dry_run_tier1_all_packages(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "results.json"
            result = subprocess.run(
                [
                    sys.executable, str(PERF_BENCHMARK),
                    "--mode", "dry-run",
                    "--packages", "tier1",
                    "--output", str(output_path),
                ],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(
                result.returncode, 0,
                f"dry-run failed: {result.stderr[-500:]}",
            )
            data = json.loads(output_path.read_text())
            self.assertEqual(data["total_packages"], 5)
            self.assertEqual(data["successful"], 5)
            self.assertEqual(data["failed"], 0)

            # Each package should have latency profile
            for pkg in data["packages"]:
                self.assertIn("latency_profile", pkg)
                self.assertGreater(pkg["latency_profile"]["total_calls"], 0)

    def test_dry_run_summary_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "results.json"
            result = subprocess.run(
                [
                    sys.executable, str(PERF_BENCHMARK),
                    "--mode", "dry-run",
                    "--packages", "sys-apps/coreutils",
                    "--output", str(output_path),
                ],
                capture_output=True, text=True, timeout=30,
            )
            self.assertIn("Performance Benchmark Summary", result.stdout)
            self.assertIn("Packages:", result.stdout)
            self.assertIn("Avg overhead:", result.stdout)


if __name__ == "__main__":
    unittest.main()
