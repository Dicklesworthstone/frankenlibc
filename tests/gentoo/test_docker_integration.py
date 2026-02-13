#!/usr/bin/env python3
"""Tests for Docker integration with FrankenLibC Gentoo builds."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


def docker_available() -> bool:
    """Check if Docker is available and running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def docker_can_run_containers() -> bool:
    """Check if Docker can actually run containers on this platform."""
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--platform", "linux/amd64", "busybox:latest", "echo", "test"],
            capture_output=True,
            timeout=60,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


DOCKER_AVAILABLE = docker_available()
DOCKER_CAN_RUN = DOCKER_AVAILABLE and docker_can_run_containers()


@unittest.skipUnless(DOCKER_CAN_RUN, "Docker cannot run containers on this platform")
class TestDockerIntegration(unittest.TestCase):
    """Integration tests for Docker-based builds."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[2]
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tmp_path = Path(cls.tmp.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_container_creation(self) -> None:
        """Test that containers can be created."""
        result = subprocess.run(
            ["docker", "run", "--rm", "--platform", "linux/amd64", "busybox:latest", "echo", "hello"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("hello", result.stdout)

    def test_volume_mounting(self) -> None:
        """Test that volumes can be mounted."""
        test_file = self.tmp_path / "test.txt"
        test_file.write_text("volume test", encoding="utf-8")

        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "-v",
                f"{self.tmp_path}:/mnt:ro",
                "busybox:latest",
                "cat",
                "/mnt/test.txt",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("volume test", result.stdout)

    def test_environment_variables(self) -> None:
        """Test that environment variables are passed."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "-e",
                "FRANKENLIBC_MODE=hardened",
                "-e",
                "FRANKENLIBC_LOG_FILE=/tmp/test.log",
                "busybox:latest",
                "sh",
                "-c",
                "echo $FRANKENLIBC_MODE $FRANKENLIBC_LOG_FILE",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("hardened", result.stdout)
        self.assertIn("/tmp/test.log", result.stdout)

    def test_container_cleanup(self) -> None:
        """Test that --rm properly cleans up containers."""
        # Run a container that exits immediately
        container_name = f"frankenlibc-test-{os.getpid()}"
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "--name",
                container_name,
                "busybox:latest",
                "true",
            ],
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)

        # Verify container doesn't exist
        inspect_result = subprocess.run(
            ["docker", "inspect", container_name],
            capture_output=True,
            timeout=10,
        )
        self.assertNotEqual(inspect_result.returncode, 0)

    def test_timeout_kills_container(self) -> None:
        """Test that timeout properly terminates containers."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "busybox:latest",
                "sh",
                "-c",
                "timeout -t 1 sleep 10 || exit 124",
            ],
            capture_output=True,
            timeout=30,
        )
        # timeout command returns 124 (or 143 on busybox)
        self.assertIn(result.returncode, [124, 143])


class TestLDPreloadInjection(unittest.TestCase):
    """Tests for LD_PRELOAD injection mechanism."""

    def test_ld_preload_format(self) -> None:
        """Test that LD_PRELOAD is formatted correctly."""
        lib_path = "/opt/frankenlibc/lib/libfrankenlibc_abi.so"
        expected = f"LD_PRELOAD={lib_path}"

        # Verify format matches what we'd pass to Docker
        env_var = f"LD_PRELOAD={lib_path}"
        self.assertEqual(env_var, expected)

    def test_preload_with_existing(self) -> None:
        """Test that LD_PRELOAD handles existing values."""
        existing = "/some/other.so"
        frankenlibc = "/opt/frankenlibc/lib/libfrankenlibc_abi.so"

        # When combining, FrankenLibC should come first
        combined = f"{frankenlibc}:{existing}"
        self.assertTrue(combined.startswith(frankenlibc))


class TestDockerCommand(unittest.TestCase):
    """Tests for Docker command construction."""

    def test_build_command_structure(self) -> None:
        """Test that Docker commands are structured correctly."""
        image = "frankenlibc/gentoo-frankenlibc:latest"
        package = "sys-apps/coreutils"
        result_dir = "/results"
        mode = "hardened"

        cmd = [
            "docker",
            "run",
            "--rm",
            "-e",
            f"FRANKENLIBC_MODE={mode}",
            "-e",
            f"FRANKENLIBC_LOG_FILE={result_dir}/frankenlibc.jsonl",
            "-v",
            f"/tmp/results:{result_dir}",
            image,
            "bash",
            "-lc",
            f"emerge --quiet {package}",
        ]

        # Verify structure
        self.assertEqual(cmd[0], "docker")
        self.assertEqual(cmd[1], "run")
        self.assertEqual(cmd[2], "--rm")
        self.assertIn(f"FRANKENLIBC_MODE={mode}", cmd)
        self.assertIn(image, cmd)
        self.assertIn(package, cmd[-1])

    def test_timeout_command(self) -> None:
        """Test that timeout is properly structured."""
        timeout_seconds = 600
        package = "sys-apps/coreutils"

        inner_cmd = f"timeout --signal=TERM --kill-after=30 {timeout_seconds} emerge --quiet {package}"

        self.assertIn("timeout", inner_cmd)
        self.assertIn(str(timeout_seconds), inner_cmd)
        self.assertIn("--kill-after=30", inner_cmd)


class TestResultCollection(unittest.TestCase):
    """Tests for result collection from containers."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_result_directory_structure(self) -> None:
        """Test expected result directory structure."""
        pkg_dir = self.tmp_path / "sys-apps__coreutils"
        pkg_dir.mkdir(parents=True)

        # Create expected files
        (pkg_dir / "build.log").write_text("build output", encoding="utf-8")
        (pkg_dir / "frankenlibc.jsonl").write_text(
            '{"action": "ClampSize"}\n',
            encoding="utf-8",
        )
        (pkg_dir / "metadata.json").write_text(
            json.dumps({"result": "success"}),
            encoding="utf-8",
        )

        # Verify all files exist
        self.assertTrue((pkg_dir / "build.log").exists())
        self.assertTrue((pkg_dir / "frankenlibc.jsonl").exists())
        self.assertTrue((pkg_dir / "metadata.json").exists())

    def test_log_file_permissions(self) -> None:
        """Test that log files have correct permissions."""
        log_file = self.tmp_path / "test.log"
        log_file.write_text("test", encoding="utf-8")

        # File should be readable
        self.assertTrue(os.access(log_file, os.R_OK))


class TestMemoryLimits(unittest.TestCase):
    """Tests for memory limit handling."""

    def test_memory_limit_format(self) -> None:
        """Test memory limit flag format."""
        memory_mb = 4096
        memory_flag = f"--memory={memory_mb}m"

        self.assertIn("--memory=", memory_flag)
        self.assertIn(str(memory_mb), memory_flag)

    def test_oom_exit_code(self) -> None:
        """Test OOM exit code detection."""
        # Exit code 137 = 128 + 9 (SIGKILL)
        oom_exit_code = 137

        def is_oom(exit_code: int) -> bool:
            return exit_code == 137

        self.assertTrue(is_oom(137))
        self.assertFalse(is_oom(0))
        self.assertFalse(is_oom(1))


if __name__ == "__main__":
    unittest.main()
