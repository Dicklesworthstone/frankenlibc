#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def load_build_runner_module(repo_root: Path):
    script_path = repo_root / "scripts/gentoo/build-runner.py"
    spec = importlib.util.spec_from_file_location("build_runner_module", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


class BuildRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.module = load_build_runner_module(Path(__file__).resolve().parents[2])

        data_dir = self.root / "data/gentoo"
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "build-order.txt").write_text("sys-devel/binutils\nsys-devel/gcc\n", encoding="utf-8")
        (data_dir / "build-waves.json").write_text(
            json.dumps({"waves": [{"packages": ["sys-devel/binutils"]}, {"packages": ["sys-devel/gcc"]}]}),
            encoding="utf-8",
        )
        (data_dir / "dependency-graph.json").write_text(
            json.dumps({"edges": [{"from": "sys-devel/binutils", "to": "sys-devel/gcc"}]}),
            encoding="utf-8",
        )

        self.config = self.module.BuildConfig(
            image="frankenlibc/gentoo-frankenlibc:latest",
            build_order=data_dir / "build-order.txt",
            build_waves=data_dir / "build-waves.json",
            dependency_graph=data_dir / "dependency-graph.json",
            results_dir=self.root / "artifacts",
            state_file=self.root / "artifacts/state.json",
            binpkg_cache=Path("/var/cache/binpkgs"),
            distfiles_cache=Path("/var/cache/distfiles"),
            parallelism=1,
            max_retries=2,
            timeout_seconds=30,
            mode="hardened",
            resume=True,
            dry_run=False,
            stop_on_failure=False,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _result(self, package: str, result: str, attempts: int = 1):
        return self.module.PackageResult(
            package=package,
            version="",
            result=result,
            build_time_seconds=1,
            frankenlibc_healing_actions=0,
            frankenlibc_mode="hardened",
            log_file="build.log",
            frankenlibc_log="frankenlibc.jsonl",
            binary_package="",
            exit_code=0 if result == "success" else 1,
            timestamp="2026-02-13T00:00:00Z",
            attempts=attempts,
            reason="",
        )

    def test_dependency_skip_when_parent_fails(self) -> None:
        runner = self.module.BuildRunner(self.config)

        with patch.object(
            runner,
            "_run_package_once",
            side_effect=[
                self._result("sys-devel/binutils", "failed", 1),
                self._result("sys-devel/binutils", "failed", 2),
                self._result("sys-devel/binutils", "failed", 3),
            ],
        ):
            results = runner.run()

        self.assertEqual(results["sys-devel/binutils"].result, "failed")
        self.assertEqual(results["sys-devel/gcc"].result, "skipped")
        self.assertEqual(results["sys-devel/gcc"].reason, "dependency_failed")

    def test_retry_until_success(self) -> None:
        runner = self.module.BuildRunner(self.config)

        with patch.object(
            runner,
            "_run_package_once",
            side_effect=[
                self._result("sys-devel/binutils", "transient", 1),
                self._result("sys-devel/binutils", "success", 2),
                self._result("sys-devel/gcc", "success", 1),
            ],
        ):
            results = runner.run()

        self.assertEqual(results["sys-devel/binutils"].result, "success")
        self.assertEqual(results["sys-devel/binutils"].attempts, 2)
        self.assertEqual(results["sys-devel/gcc"].result, "success")

    def test_resume_skips_existing_results(self) -> None:
        state_payload = {
            "updated_at": "2026-02-13T00:00:00Z",
            "results": {
                "sys-devel/binutils": {
                    "package": "sys-devel/binutils",
                    "version": "",
                    "result": "success",
                    "build_time_seconds": 1,
                    "frankenlibc_healing_actions": 0,
                    "frankenlibc_mode": "hardened",
                    "log_file": "build.log",
                    "frankenlibc_log": "frankenlibc.jsonl",
                    "binary_package": "",
                    "exit_code": 0,
                    "timestamp": "2026-02-13T00:00:00Z",
                    "attempts": 1,
                    "reason": "",
                }
            },
        }
        self.config.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.config.state_file.write_text(json.dumps(state_payload), encoding="utf-8")

        runner = self.module.BuildRunner(self.config)
        with patch.object(runner, "_run_package_once", return_value=self._result("sys-devel/gcc", "success", 1)) as mocked:
            results = runner.run()

        self.assertEqual(results["sys-devel/binutils"].result, "success")
        self.assertEqual(results["sys-devel/gcc"].result, "success")
        mocked.assert_called_once()

    def test_dry_run_writes_telemetry_contract(self) -> None:
        self.config.dry_run = True
        runner = self.module.BuildRunner(self.config)

        results = runner.run()

        result = results["sys-devel/binutils"]
        self.assertEqual(result.result, "success")
        self.assertEqual(result.reason, "dry_run")
        self.assertEqual(result.instrumented_phase_events, 1)
        self.assertEqual(result.frankenlibc_log_files, 1)

        telemetry_log = Path(result.telemetry_log)
        portage_hook_log = Path(result.portage_hook_log)
        self.assertTrue(telemetry_log.exists())
        self.assertTrue(portage_hook_log.exists())

        telemetry_event = json.loads(telemetry_log.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(telemetry_event["event"], "finish")
        self.assertEqual(telemetry_event["package"], "sys-devel/binutils")
        self.assertEqual(telemetry_event["portage_enabled"], "1")
        self.assertEqual(telemetry_event["instrumented_phase_events"], 1)

        state_payload = json.loads(self.config.state_file.read_text(encoding="utf-8"))
        state_record = state_payload["results"]["sys-devel/binutils"]
        self.assertEqual(state_record["telemetry_log"], result.telemetry_log)
        self.assertEqual(state_record["portage_hook_log"], result.portage_hook_log)

    def test_docker_command_enables_portage_instrumentation_env(self) -> None:
        runner = self.module.BuildRunner(self.config)
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        with patch.object(self.module.subprocess, "run", return_value=completed) as mocked:
            result = runner._run_package_once("sys-devel/binutils", 1)

        self.assertEqual(result.result, "success")
        cmd = mocked.call_args.args[0]
        env_values = [cmd[index + 1] for index, value in enumerate(cmd[:-1]) if value == "-e"]
        self.assertIn("FRANKENLIBC_MODE=hardened", env_values)
        self.assertIn("FLC_BUILD_TIMEOUT_SECONDS=30", env_values)
        self.assertIn("FRANKENLIBC_PORTAGE_ENABLE=1", env_values)
        self.assertIn("FRANKENLIBC_LOG_DIR=/results/portage-frankenlibc", env_values)
        self.assertIn("FRANKENLIBC_PORTAGE_LOG=/results/portage-hooks.jsonl", env_values)
        self.assertIn("FRANKENLIBC_RUNNER_TELEMETRY=/results/build-telemetry.jsonl", env_values)
        self.assertIn("/opt/frankenlibc/scripts/gentoo/build-package.sh sys-devel/binutils /results", cmd[-1])

    def test_build_package_wrapper_emits_telemetry_contract(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        wrapper = repo_root / "scripts/gentoo/build-package.sh"
        bin_dir = self.root / "bin"
        out_dir = self.root / "wrapper-out"
        bin_dir.mkdir(parents=True, exist_ok=True)

        fake_emerge = bin_dir / "emerge"
        fake_emerge.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
mkdir -p "${FRANKENLIBC_LOG_DIR}/app-misc__hello"
printf '{"event":"enable","message":"enabled: fake emerge"}\n' >> "${FRANKENLIBC_PORTAGE_LOG}"
printf '{"call":"malloc","action":"ClampSize"}\n' >> "${FRANKENLIBC_LOG_DIR}/app-misc__hello/src_test.jsonl"
printf '{"call":"free","action":"ReturnSafeDefault"}\n' >> "${FRANKENLIBC_LOG_FILE}"
printf 'fake emerge %s\n' "$*"
""",
            encoding="utf-8",
        )
        fake_emerge.chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["FRANKENLIBC_MODE"] = "strict"

        completed = subprocess.run(
            ["bash", str(wrapper), "app-misc/hello", str(out_dir)],
            cwd=repo_root,
            env=env,
            text=True,
            capture_output=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        metadata = json.loads((out_dir / "metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["package"], "app-misc/hello")
        self.assertEqual(metadata["result"], "success")
        self.assertEqual(metadata["frankenlibc_mode"], "strict")
        self.assertEqual(metadata["frankenlibc_healing_actions"], 2)
        self.assertEqual(metadata["instrumented_phase_events"], 1)
        self.assertGreaterEqual(metadata["frankenlibc_log_files"], 2)
        self.assertEqual(metadata["telemetry_log"], str(out_dir / "build-telemetry.jsonl"))
        self.assertEqual(metadata["portage_hook_log"], str(out_dir / "portage-hooks.jsonl"))
        self.assertEqual(metadata["portage_log_dir"], str(out_dir / "portage-frankenlibc"))

        telemetry_events = [
            json.loads(line)
            for line in (out_dir / "build-telemetry.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual([event["event"] for event in telemetry_events], ["start", "finish"])
        self.assertEqual(telemetry_events[-1]["result"], "success")
        self.assertEqual(telemetry_events[-1]["healing_actions"], 2)
        self.assertEqual(telemetry_events[-1]["instrumented_phase_events"], 1)


if __name__ == "__main__":
    unittest.main()
