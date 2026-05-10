#!/usr/bin/env python3
"""FrankenLibC Gentoo build runner.

Builds packages in dependency order (wave-aware), executes builds in Docker
with FrankenLibC instrumentation enabled, records structured per-package state,
and supports retry/resume.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Set

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_atom(atom: str) -> str:
    return atom.replace("/", "__")


@dataclass
class BuildConfig:
    image: str
    build_order: Path
    build_waves: Path | None
    dependency_graph: Path
    results_dir: Path
    state_file: Path
    binpkg_cache: Path
    distfiles_cache: Path
    parallelism: int = 4
    max_retries: int = 3
    timeout_seconds: int = 7200
    mode: str = "hardened"
    resume: bool = True
    dry_run: bool = False
    stop_on_failure: bool = False

    @classmethod
    def from_toml(cls, path: Path) -> "BuildConfig":
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
        runner = payload.get("runner", {})
        paths = payload.get("paths", {})
        if path.parent.name == "gentoo":
            root = path.parent.parent.parent
        else:
            root = Path(".")

        def p(name: str, default: str) -> Path:
            raw = str(paths.get(name, default))
            candidate = Path(raw)
            if candidate.is_absolute():
                return candidate
            return (root / candidate).resolve()

        build_waves_raw = paths.get("build_waves")
        build_waves = p("build_waves", "data/gentoo/build-waves.json") if build_waves_raw else None

        return cls(
            image=str(runner.get("image", "frankenlibc/gentoo-frankenlibc:latest")),
            build_order=p("build_order", "data/gentoo/build-order.txt"),
            build_waves=build_waves,
            dependency_graph=p("dependency_graph", "data/gentoo/dependency-graph.json"),
            results_dir=p("results_dir", "artifacts/gentoo-builds"),
            state_file=p("state_file", "artifacts/gentoo-builds/state.json"),
            binpkg_cache=Path(str(paths.get("binpkg_cache", "/var/cache/binpkgs"))),
            distfiles_cache=Path(str(paths.get("distfiles_cache", "/var/cache/distfiles"))),
            parallelism=int(runner.get("parallelism", 4)),
            max_retries=int(runner.get("max_retries", 3)),
            timeout_seconds=int(runner.get("timeout_seconds", 7200)),
            mode=str(runner.get("mode", "hardened")),
            resume=bool(runner.get("resume", True)),
            dry_run=bool(runner.get("dry_run", False)),
            stop_on_failure=bool(runner.get("stop_on_failure", False)),
        )


@dataclass
class PackageResult:
    package: str
    version: str
    result: str
    build_time_seconds: int
    frankenlibc_healing_actions: int
    frankenlibc_mode: str
    log_file: str
    frankenlibc_log: str
    binary_package: str
    exit_code: int
    timestamp: str
    attempts: int
    reason: str = ""
    telemetry_log: str = ""
    portage_hook_log: str = ""
    portage_log_dir: str = ""
    instrumented_phase_events: int = 0
    frankenlibc_log_files: int = 0


class BuildRunner:
    def __init__(self, config: BuildConfig) -> None:
        self.config = config
        self.results: Dict[str, PackageResult] = {}
        self.order = self._load_build_order()
        self.dependencies = self._load_dependencies()
        self.waves = self._load_waves()

    def _load_build_order(self) -> List[str]:
        lines = self.config.build_order.read_text(encoding="utf-8").splitlines()
        return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]

    def _load_waves(self) -> List[List[str]]:
        if self.config.build_waves and self.config.build_waves.exists():
            payload = json.loads(self.config.build_waves.read_text(encoding="utf-8"))
            waves = []
            for item in payload.get("waves", []):
                pkgs = [str(x) for x in item.get("packages", []) if str(x)]
                if pkgs:
                    waves.append(pkgs)
            if waves:
                return waves
        return [self.order]

    def _load_dependencies(self) -> Dict[str, Set[str]]:
        payload = json.loads(self.config.dependency_graph.read_text(encoding="utf-8"))
        deps: Dict[str, Set[str]] = {pkg: set() for pkg in self.order}
        for edge in payload.get("edges", []):
            dep = str(edge.get("from", "")).strip()
            to = str(edge.get("to", "")).strip()
            if not dep or not to:
                continue
            deps.setdefault(to, set()).add(dep)
            deps.setdefault(dep, set())
        return deps

    def _load_state(self) -> None:
        if not self.config.resume or not self.config.state_file.exists():
            return
        payload = json.loads(self.config.state_file.read_text(encoding="utf-8"))
        for package, record in payload.get("results", {}).items():
            self.results[package] = PackageResult(**record)

    def _save_state(self) -> None:
        self.config.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": utc_now(),
            "results": {pkg: asdict(res) for pkg, res in sorted(self.results.items())},
        }
        tmp = self.config.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self.config.state_file)

    def _is_dependency_satisfied(self, package: str) -> bool:
        for dep in self.dependencies.get(package, set()):
            result = self.results.get(dep)
            if result is None or result.result != "success":
                return False
        return True

    def _skip_due_to_dependency(self, package: str) -> PackageResult:
        return PackageResult(
            package=package,
            version="",
            result="skipped",
            build_time_seconds=0,
            frankenlibc_healing_actions=0,
            frankenlibc_mode=self.config.mode,
            log_file="",
            frankenlibc_log="",
            binary_package="",
            exit_code=0,
            timestamp=utc_now(),
            attempts=0,
            reason="dependency_failed",
        )

    def _classify_failure(self, exit_code: int, build_log: Path) -> str:
        if exit_code == 124:
            return "timeout"
        if build_log.exists():
            body = build_log.read_text(encoding="utf-8", errors="ignore").lower()
            if "cannot allocate memory" in body or "out of memory" in body or "oom" in body:
                return "oom"
            if "connection timed out" in body or "temporary failure" in body:
                return "transient"
        return "failed"

    def _run_package_once(self, package: str, attempt: int) -> PackageResult:
        package_key = sanitize_atom(package)
        attempt_dir = self.config.results_dir / "packages" / package_key / f"attempt-{attempt}"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        metadata_path = attempt_dir / "metadata.json"
        container_log = attempt_dir / "container.log"

        started = time.time()
        if self.config.dry_run:
            telemetry_log = attempt_dir / "build-telemetry.jsonl"
            portage_hook_log = attempt_dir / "portage-hooks.jsonl"
            portage_log_dir = attempt_dir / "portage-frankenlibc"
            result = PackageResult(
                package=package,
                version="",
                result="success",
                build_time_seconds=1,
                frankenlibc_healing_actions=0,
                frankenlibc_mode=self.config.mode,
                log_file=str(attempt_dir / "build.log"),
                frankenlibc_log=str(attempt_dir / "frankenlibc.jsonl"),
                binary_package="",
                exit_code=0,
                timestamp=utc_now(),
                attempts=attempt,
                reason="dry_run",
                telemetry_log=str(telemetry_log),
                portage_hook_log=str(portage_hook_log),
                portage_log_dir=str(portage_log_dir),
                instrumented_phase_events=1,
                frankenlibc_log_files=1,
            )
            portage_log_dir.mkdir(parents=True, exist_ok=True)
            portage_hook_log.write_text(
                json.dumps(
                    {
                        "timestamp": utc_now(),
                        "event": "enable",
                        "package": package,
                        "phase": "dry_run",
                        "mode": self.config.mode,
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            telemetry_log.write_text(
                json.dumps(
                    {
                        "timestamp": utc_now(),
                        "event": "finish",
                        "package": package,
                        "result": "success",
                        "exit_code": 0,
                        "frankenlibc_mode": self.config.mode,
                        "portage_enabled": "1",
                        "instrumented_phase_events": 1,
                        "frankenlibc_log_files": 1,
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            metadata_path.write_text(json.dumps(asdict(result), indent=2) + "\n", encoding="utf-8")
            return result

        cmd = [
            "docker",
            "run",
            "--rm",
            "-e",
            f"FRANKENLIBC_MODE={self.config.mode}",
            "-e",
            f"FLC_BUILD_TIMEOUT_SECONDS={self.config.timeout_seconds}",
            "-e",
            "FRANKENLIBC_PORTAGE_ENABLE=1",
            "-e",
            "FRANKENLIBC_LOG_DIR=/results/portage-frankenlibc",
            "-e",
            "FRANKENLIBC_PORTAGE_LOG=/results/portage-hooks.jsonl",
            "-e",
            "FRANKENLIBC_RUNNER_TELEMETRY=/results/build-telemetry.jsonl",
            "-v",
            f"{attempt_dir.resolve()}:/results",
            "-v",
            f"{self.config.binpkg_cache}:/var/cache/binpkgs",
            "-v",
            f"{self.config.distfiles_cache}:/var/cache/distfiles",
            self.config.image,
            "bash",
            "-lc",
            f"/opt/frankenlibc/scripts/gentoo/build-package.sh {shlex.quote(package)} /results",
        ]
        proc = subprocess.run(cmd, text=True, capture_output=True)
        container_log.write_text((proc.stdout or "") + (proc.stderr or ""), encoding="utf-8")

        elapsed = int(time.time() - started)
        if metadata_path.exists():
            payload = json.loads(metadata_path.read_text(encoding="utf-8"))
            result = PackageResult(
                package=package,
                version=str(payload.get("version", "")),
                result=str(payload.get("result", "failed")),
                build_time_seconds=int(payload.get("build_time_seconds", elapsed)),
                frankenlibc_healing_actions=int(payload.get("frankenlibc_healing_actions", 0)),
                frankenlibc_mode=str(payload.get("frankenlibc_mode", self.config.mode)),
                log_file=str(payload.get("log_file", attempt_dir / "build.log")),
                frankenlibc_log=str(payload.get("frankenlibc_log", attempt_dir / "frankenlibc.jsonl")),
                binary_package=str(payload.get("binary_package", "")),
                exit_code=int(payload.get("exit_code", proc.returncode)),
                timestamp=str(payload.get("timestamp", utc_now())),
                attempts=attempt,
                reason=str(payload.get("reason", "")),
                telemetry_log=str(payload.get("telemetry_log", attempt_dir / "build-telemetry.jsonl")),
                portage_hook_log=str(payload.get("portage_hook_log", attempt_dir / "portage-hooks.jsonl")),
                portage_log_dir=str(payload.get("portage_log_dir", attempt_dir / "portage-frankenlibc")),
                instrumented_phase_events=int(payload.get("instrumented_phase_events", 0)),
                frankenlibc_log_files=int(payload.get("frankenlibc_log_files", 0)),
            )
            return result

        build_log = attempt_dir / "build.log"
        result_kind = "success" if proc.returncode == 0 else self._classify_failure(proc.returncode, build_log)
        return PackageResult(
            package=package,
            version="",
            result=result_kind,
            build_time_seconds=elapsed,
            frankenlibc_healing_actions=0,
            frankenlibc_mode=self.config.mode,
            log_file=str(build_log),
            frankenlibc_log=str(attempt_dir / "frankenlibc.jsonl"),
            binary_package="",
            exit_code=proc.returncode,
            timestamp=utc_now(),
            attempts=attempt,
            reason="",
            telemetry_log=str(attempt_dir / "build-telemetry.jsonl"),
            portage_hook_log=str(attempt_dir / "portage-hooks.jsonl"),
            portage_log_dir=str(attempt_dir / "portage-frankenlibc"),
        )

    def _build_package(self, package: str) -> PackageResult:
        attempts = self.config.max_retries + 1
        last_result: PackageResult | None = None
        for attempt in range(1, attempts + 1):
            result = self._run_package_once(package, attempt)
            last_result = result
            if result.result == "success":
                return result
            if attempt < attempts and result.result in {"failed", "timeout", "oom", "transient"}:
                time.sleep(min(5, attempt))
                continue
            return result
        assert last_result is not None
        return last_result

    def run(self) -> Dict[str, PackageResult]:
        self.config.results_dir.mkdir(parents=True, exist_ok=True)
        self._load_state()

        for wave in self.waves:
            pending = [pkg for pkg in wave if pkg not in self.results]
            if not pending:
                continue

            buildable: List[str] = []
            for package in pending:
                if not self._is_dependency_satisfied(package):
                    skipped = self._skip_due_to_dependency(package)
                    self.results[package] = skipped
                    self._save_state()
                else:
                    buildable.append(package)

            if not buildable:
                continue

            workers = max(1, min(self.config.parallelism, len(buildable)))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(self._build_package, pkg): pkg for pkg in buildable}
                for future in as_completed(futures):
                    package = futures[future]
                    result = future.result()
                    self.results[package] = result
                    self._save_state()
                    if self.config.stop_on_failure and result.result != "success":
                        raise RuntimeError(f"Stopping on failure: {package} -> {result.result}")

        return self.results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Gentoo package builds with FrankenLibC instrumentation.")
    parser.add_argument("--config", default="configs/gentoo/build-config.toml", help="Path to runner TOML config")
    parser.add_argument("--dry-run", action="store_true", help="Do not run docker; emit synthetic success")
    parser.add_argument("--package", action="append", default=[], help="Limit to specific package atom(s)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cfg = BuildConfig.from_toml(Path(args.config).resolve())
    if args.dry_run:
        cfg.dry_run = True
        cfg.resume = False

    runner = BuildRunner(cfg)
    if args.package:
        selected = set(args.package)
        runner.order = [pkg for pkg in runner.order if pkg in selected]
        runner.waves = [[pkg for pkg in wave if pkg in selected] for wave in runner.waves]

    results = runner.run()
    by_result: Dict[str, int] = {}
    for record in results.values():
        by_result[record.result] = by_result.get(record.result, 0) + 1

    summary = {
        "timestamp": utc_now(),
        "total_packages": len(results),
        "by_result": by_result,
        "instrumented_phase_events": sum(record.instrumented_phase_events for record in results.values()),
        "telemetry_logs": sorted(
            record.telemetry_log for record in results.values() if record.telemetry_log
        ),
        "state_file": str(cfg.state_file),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
