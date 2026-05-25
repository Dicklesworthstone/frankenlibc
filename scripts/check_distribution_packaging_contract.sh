#!/usr/bin/env bash
# check_distribution_packaging_contract.sh -- fail-closed WS-8.3 package gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_DISTRIBUTION_PACKAGE_CONTRACT:-${ROOT}/tests/conformance/distribution_packaging_contract.v1.json}"
PACKAGING="${FRANKENLIBC_DISTRIBUTION_PACKAGING_SPEC:-${ROOT}/tests/conformance/packaging_spec.json}"
OUT_DIR="${FRANKENLIBC_DISTRIBUTION_PACKAGE_OUT_DIR:-${ROOT}/target/conformance/distribution_packaging_contract}"
REPORT="${FRANKENLIBC_DISTRIBUTION_PACKAGE_REPORT:-${ROOT}/target/conformance/distribution_packaging_contract.report.json}"
LOG="${FRANKENLIBC_DISTRIBUTION_PACKAGE_LOG:-${ROOT}/target/conformance/distribution_packaging_contract.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${PACKAGING}" "${OUT_DIR}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1]).resolve()
contract_path = Path(sys.argv[2]).resolve()
packaging_path = Path(sys.argv[3]).resolve()
out_dir = Path(sys.argv[4]).resolve()
report_path = Path(sys.argv[5]).resolve()
log_path = Path(sys.argv[6]).resolve()

BEAD_ID = "bd-38x82.3"
MANIFEST_ID = "ws8-distribution-packaging-contract"
SCHEMA_VERSION = "distribution_packaging_contract.v1"
TRACE_ID = f"{BEAD_ID}-{int(time.time())}-{os.getpid()}"


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root).as_posix()
    except Exception:
        return str(path)


def load_json(path: Path, errors: list[str], label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{label} must be a JSON object")
        return {}
    return value


def command_text(argv: list[str]) -> str:
    return " ".join(subprocess.list2cmdline([part]) for part in argv)


def run(
    argv: list[str],
    *,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
    cwd: Path | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    started = time.time()
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd or root),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        exit_code = completed.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        exit_code = 124
        timed_out = True

    if stdout_path is not None:
        stdout_path.write_text(stdout, encoding="utf-8")
    if stderr_path is not None:
        stderr_path.write_text(stderr, encoding="utf-8")

    return {
        "command": argv,
        "command_text": command_text(argv),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_ms": round((time.time() - started) * 1000),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_path": rel(stdout_path) if stdout_path is not None else None,
        "stderr_path": rel(stderr_path) if stderr_path is not None else None,
    }


def git_head() -> tuple[str, int]:
    rev = run(["git", "rev-parse", "HEAD"])
    ts = run(["git", "show", "-s", "--format=%ct", "HEAD"])
    commit = rev["stdout"].strip() if rev["exit_code"] == 0 else "unknown"
    try:
        commit_time = int(ts["stdout"].strip()) if ts["exit_code"] == 0 else 0
    except ValueError:
        commit_time = 0
    return commit, commit_time


def tool_path(name: str) -> str | None:
    return shutil.which(name)


def emit(
    events: list[dict[str, Any]],
    *,
    event: str,
    status: str,
    claim_status: str,
    package_path: Path | None,
    install_root: Path | None,
    artifact_path: Path | None,
    artifact_refs: list[str],
    failure_signature: str = "none",
    extra: dict[str, Any] | None = None,
) -> None:
    row = {
        "timestamp": utc_now(),
        "trace_id": TRACE_ID,
        "bead_id": BEAD_ID,
        "event": event,
        "status": status,
        "claim_status": claim_status,
        "package_path": rel(package_path) if package_path else "",
        "install_root": rel(install_root) if install_root else "",
        "artifact_path": rel(artifact_path) if artifact_path else "",
        "artifact_refs": artifact_refs,
        "failure_signature": failure_signature,
    }
    if extra:
        row.update(extra)
    events.append(row)


def write_outputs(report: dict[str, Any], events: list[dict[str, Any]]) -> None:
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in events),
        encoding="utf-8",
    )


def validate_manifest(contract: dict[str, Any], packaging: dict[str, Any], errors: list[str]) -> None:
    if contract.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("parent_bead") != "bd-38x82":
        errors.append("parent_bead must be bd-38x82")
    if "bd-38x82.1" not in contract.get("prerequisite_beads", []):
        errors.append("prerequisite_beads must include bd-38x82.1")

    source = contract.get("source_artifact")
    if not isinstance(source, dict):
        errors.append("source_artifact must be an object")
        return

    replace = packaging.get("artifacts", {}).get("replace", {})
    if replace.get("artifact_name") != source.get("artifact_name"):
        errors.append("source_artifact.artifact_name must match packaging_spec replace artifact")
    if replace.get("host_glibc_required") is not False:
        errors.append("packaging_spec replace artifact must not require host glibc")
    if set(replace.get("allowed_statuses", [])) != {"Implemented", "RawSyscall"}:
        errors.append("packaging_spec replace allowed_statuses must be Implemented + RawSyscall")

    package = contract.get("package")
    if not isinstance(package, dict):
        errors.append("package must be an object")
        return
    if package.get("format") != "deb":
        errors.append("package.format must be deb")
    if package.get("distribution_family") != "Debian":
        errors.append("package.distribution_family must be Debian")
    if package.get("system_paths_touched") is not False:
        errors.append("package.system_paths_touched must be false")


def resolve_source_artifact(contract: dict[str, Any], errors: list[str]) -> tuple[Path | None, str]:
    source = contract.get("source_artifact", {})
    override_env = source.get("override_env", "FRANKENLIBC_DISTRIBUTION_SOURCE_LIB")
    override = os.environ.get(override_env)
    expected_name = source.get("must_be_named") or source.get("artifact_name")
    failure = "none"

    if override:
        candidate = Path(override)
        if not candidate.is_absolute():
            candidate = root / candidate
    else:
        candidate = None
        for item in source.get("default_candidates", []):
            path = root / str(item)
            if path.exists():
                candidate = path
                break
        if candidate is None and source.get("default_candidates"):
            candidate = root / str(source["default_candidates"][0])

    if candidate is None or not candidate.exists():
        errors.append("missing_source_artifact")
        return candidate, "missing_source_artifact"
    if candidate.is_dir():
        errors.append(f"source artifact is a directory: {rel(candidate)}")
        return candidate, "missing_source_artifact"
    if source.get("must_be_non_empty", True) and candidate.stat().st_size <= 0:
        errors.append(f"empty_source_artifact: {rel(candidate)}")
        if failure == "none":
            failure = "empty_source_artifact"
    if expected_name and candidate.name != expected_name:
        errors.append(f"wrong_source_artifact_name: expected {expected_name}, got {candidate.name}")
        if failure == "none":
            failure = "wrong_source_artifact_name"

    if source.get("must_be_fresh_against_head", True):
        _, head_time = git_head()
        if head_time and int(candidate.stat().st_mtime) < head_time:
            errors.append(f"stale_source_artifact: {rel(candidate)} predates git HEAD")
            if failure == "none":
                failure = "stale_source_artifact"

    return candidate, failure


def failure_signature(errors: list[str]) -> str:
    known = [
        "missing_required_tool",
        "missing_source_artifact",
        "empty_source_artifact",
        "wrong_source_artifact_name",
        "stale_source_artifact",
        "package_build_failed",
        "dpkg_metadata_invalid",
        "package_install_failed",
        "installed_artifact_missing",
        "installed_smoke_failed",
    ]
    for error in errors:
        for signature in known:
            if error.startswith(signature):
                return signature
    return "unknown" if errors else "none"


def parse_needed(dynamic_text: str) -> list[str]:
    needed: list[str] = []
    for line in dynamic_text.splitlines():
        if "(NEEDED)" not in line:
            continue
        match = re.search(r"\[([^\]]+)\]", line)
        needed.append(match.group(1) if match else line.strip())
    return needed


def symbol_names(nm_text: str) -> set[str]:
    names: set[str] = set()
    for line in nm_text.splitlines():
        parts = line.split()
        if not parts:
            continue
        names.add(parts[-1].split("@", 1)[0])
    return names


def host_needed_libraries(needed: list[str], needles: list[str]) -> list[str]:
    return [lib for lib in needed if any(needle in lib for needle in needles)]


def undefined_glibc_symbols(undefined_text: str) -> list[str]:
    rows = []
    for line in undefined_text.splitlines():
        if "@GLIBC" in line or "GLIBC_" in line:
            rows.append(line.strip())
    return rows


def write_control_file(path: Path, package: dict[str, Any], version: str, arch: str, installed_size: int) -> None:
    control = "\n".join(
        [
            f"Package: {package['package_name']}",
            f"Version: {version}",
            "Section: libs",
            "Priority: optional",
            f"Architecture: {arch}",
            "Maintainer: FrankenLibC maintainers <noreply@example.invalid>",
            f"Installed-Size: {installed_size}",
            "Description: FrankenLibC standalone replacement artifact package",
            " Experimental package for validating the WS-8.3 distribution packaging",
            " contract in an isolated root. It installs the replacement artifact under",
            " /usr/lib/frankenlibc without modifying system libc links.",
            "",
        ]
    )
    path.write_text(control, encoding="utf-8")


def main() -> int:
    errors: list[str] = []
    events: list[dict[str, Any]] = []
    checks: dict[str, Any] = {}
    evidence_files: list[str] = []
    source_commit, _ = git_head()
    claim_status = "claim_blocked"
    package_path: Path | None = None
    install_root: Path | None = None
    installed_artifact: Path | None = None

    contract = load_json(contract_path, errors, "contract")
    packaging = load_json(packaging_path, errors, "packaging_spec")
    validate_manifest(contract, packaging, errors)

    tools = {}
    for name in contract.get("required_tools", []):
        tools[name] = tool_path(str(name))
        if tools[name] is None:
            errors.append(f"missing_required_tool: {name}")

    source_artifact, source_failure = resolve_source_artifact(contract, errors)
    artifact_refs = [rel(contract_path), rel(packaging_path)]
    if source_artifact is not None:
        artifact_refs.append(rel(source_artifact))

    emit(
        events,
        event="distribution_packaging_source_artifact",
        status="pass" if source_failure == "none" else "fail",
        claim_status=claim_status,
        package_path=None,
        install_root=None,
        artifact_path=source_artifact,
        artifact_refs=artifact_refs,
        failure_signature=source_failure,
    )

    package = contract.get("package", {})
    smoke = contract.get("smoke_battery", {})
    if not errors and source_artifact is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        short_commit = source_commit[:12] if source_commit != "unknown" else "unknown"
        version = f"{package['version_prefix']}.{short_commit}"
        arch_result = run(["dpkg", "--print-architecture"])
        arch = arch_result["stdout"].strip() if arch_result["exit_code"] == 0 else "amd64"

        work_dir = out_dir / f"package-{short_commit}-{os.getpid()}-{int(time.time())}"
        package_root = work_dir / "pkgroot"
        debian_dir = package_root / "DEBIAN"
        payload_dir = package_root / "usr/lib/frankenlibc"
        doc_dir = package_root / "usr/share/doc/frankenlibc-replace"
        install_root = work_dir / "install-root"
        debian_dir.mkdir(parents=True, exist_ok=True)
        payload_dir.mkdir(parents=True, exist_ok=True)
        doc_dir.mkdir(parents=True, exist_ok=True)
        (install_root / "var/lib/dpkg").mkdir(parents=True, exist_ok=True)
        (install_root / "var/lib/dpkg/status").write_text("", encoding="utf-8")

        payload_artifact = payload_dir / source_artifact.name
        shutil.copy2(source_artifact, payload_artifact)
        installed_size = max(1, (payload_artifact.stat().st_size + 1023) // 1024)
        write_control_file(debian_dir / "control", package, version, arch, installed_size)
        (doc_dir / "README.Debian").write_text(
            "\n".join(
                [
                    "FrankenLibC replacement package",
                    f"source_commit={source_commit}",
                    f"source_artifact={rel(source_artifact)}",
                    "This package is generated by scripts/check_distribution_packaging_contract.sh.",
                    "It installs under /usr/lib/frankenlibc and does not relink system libc paths.",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        package_path = work_dir / f"{package['package_name']}_{version}_{arch}.deb"
        package_alias = work_dir / "package.deb"
        build_result = run(["fakeroot", "dpkg-deb", "--build", str(package_root), str(package_path)])
        checks["package_built"] = build_result
        if build_result["exit_code"] != 0:
            errors.append("package_build_failed")
            emit_status = "fail"
            failure = "package_build_failed"
        else:
            shutil.copy2(package_path, package_alias)
            evidence_files.append(rel(package_alias))
            emit_status = "pass"
            failure = "none"

        emit(
            events,
            event="distribution_packaging_package_built",
            status=emit_status,
            claim_status=claim_status,
            package_path=package_path,
            install_root=install_root,
            artifact_path=source_artifact,
            artifact_refs=artifact_refs + ([rel(package_path)] if package_path.exists() else []),
            failure_signature=failure,
            extra={"command": build_result["command_text"], "exit_code": build_result["exit_code"]},
        )

        if not errors:
            info_path = work_dir / "dpkg.info.txt"
            contents_path = work_dir / "dpkg.contents.txt"
            info_result = run(["dpkg-deb", "--info", str(package_path)], stdout_path=info_path)
            contents_result = run(["dpkg-deb", "--contents", str(package_path)], stdout_path=contents_path)
            checks["dpkg_metadata_valid"] = {
                "info": info_result,
                "contents": contents_result,
            }
            evidence_files.extend([rel(info_path), rel(contents_path)])
            if info_result["exit_code"] != 0 or contents_result["exit_code"] != 0:
                errors.append("dpkg_metadata_invalid")

            stdout_path = work_dir / "dpkg.install.stdout.txt"
            stderr_path = work_dir / "dpkg.install.stderr.txt"
            install_result = run(
                [
                    "dpkg",
                    f"--root={install_root}",
                    f"--admindir={install_root / 'var/lib/dpkg'}",
                    f"--instdir={install_root}",
                    "--force-not-root",
                    "--force-script-chrootless",
                    "--install",
                    str(package_path),
                ],
                stdout_path=stdout_path,
                stderr_path=stderr_path,
            )
            checks["dpkg_isolated_install"] = install_result
            evidence_files.extend([rel(stdout_path), rel(stderr_path)])
            if install_result["exit_code"] != 0:
                errors.append("package_install_failed")

            emit(
                events,
                event="distribution_packaging_package_installed",
                status="pass" if install_result["exit_code"] == 0 else "fail",
                claim_status=claim_status,
                package_path=package_path,
                install_root=install_root,
                artifact_path=source_artifact,
                artifact_refs=artifact_refs + [rel(package_path), rel(stdout_path), rel(stderr_path)],
                failure_signature="none" if install_result["exit_code"] == 0 else "package_install_failed",
                extra={"command": install_result["command_text"], "exit_code": install_result["exit_code"]},
            )

        if not errors:
            installed_artifact = install_root / package["installed_artifact"].lstrip("/")
            if not installed_artifact.is_file():
                errors.append("installed_artifact_missing")
            else:
                file_path = work_dir / "installed.file.txt"
                readelf_header_path = work_dir / "installed.readelf.header.txt"
                readelf_dynamic_path = work_dir / "installed.readelf.dynamic.txt"
                nm_dynamic_path = work_dir / "installed.nm.dynamic.txt"
                nm_undefined_path = work_dir / "installed.nm.undefined.txt"

                file_result = run(["file", str(installed_artifact)], stdout_path=file_path)
                header_result = run(["readelf", "-h", str(installed_artifact)], stdout_path=readelf_header_path)
                dynamic_result = run(["readelf", "-d", str(installed_artifact)], stdout_path=readelf_dynamic_path)
                nm_result = run(["nm", "-D", "--defined-only", str(installed_artifact)], stdout_path=nm_dynamic_path)
                undefined_result = run(["nm", "-D", "--undefined-only", str(installed_artifact)], stdout_path=nm_undefined_path)
                evidence_files.extend(
                    [
                        rel(file_path),
                        rel(readelf_header_path),
                        rel(readelf_dynamic_path),
                        rel(nm_dynamic_path),
                        rel(nm_undefined_path),
                    ]
                )

                names = symbol_names(nm_result["stdout"])
                required_symbols = set(smoke.get("required_symbols", []))
                missing_symbols = sorted(required_symbols - names)
                needed = parse_needed(dynamic_result["stdout"])
                host_needed = host_needed_libraries(needed, smoke.get("host_library_needles", []))
                undefined_host = undefined_glibc_symbols(undefined_result["stdout"])
                is_elf_shared = (
                    file_result["exit_code"] == 0
                    and "ELF" in file_result["stdout"]
                    and "shared object" in file_result["stdout"]
                    and header_result["exit_code"] == 0
                    and "Type:" in header_result["stdout"]
                    and "DYN" in header_result["stdout"]
                )

                smoke_checks = {
                    "installed_prefix_artifact_present": True,
                    "installed_artifact_is_elf_shared_object": is_elf_shared,
                    "installed_artifact_has_required_symbols": not missing_symbols,
                    "installed_artifact_has_no_host_needed_libraries": not host_needed,
                    "installed_artifact_has_no_glibc_versioned_undefined_symbols": not undefined_host,
                    "missing_symbols": missing_symbols,
                    "needed_libraries": needed,
                    "host_needed_libraries": host_needed,
                    "undefined_glibc_symbols": undefined_host,
                    "tool_results": {
                        "file": file_result,
                        "readelf_header": header_result,
                        "readelf_dynamic": dynamic_result,
                        "nm_dynamic": nm_result,
                        "nm_undefined": undefined_result,
                    },
                }
                checks["installed_prefix_smoke"] = smoke_checks
                if not all(
                    bool(smoke_checks[key])
                    for key in [
                        "installed_prefix_artifact_present",
                        "installed_artifact_is_elf_shared_object",
                        "installed_artifact_has_required_symbols",
                        "installed_artifact_has_no_host_needed_libraries",
                        "installed_artifact_has_no_glibc_versioned_undefined_symbols",
                    ]
                ):
                    errors.append("installed_smoke_failed")

                emit(
                    events,
                    event="distribution_packaging_prefix_smoke",
                    status="pass" if "installed_smoke_failed" not in errors else "fail",
                    claim_status=claim_status,
                    package_path=package_path,
                    install_root=install_root,
                    artifact_path=installed_artifact,
                    artifact_refs=artifact_refs + [rel(package_path), rel(installed_artifact)] + evidence_files,
                    failure_signature="none" if "installed_smoke_failed" not in errors else "installed_smoke_failed",
                    extra={
                        "missing_symbols": missing_symbols,
                        "host_needed_libraries": host_needed,
                        "undefined_glibc_symbols": undefined_host,
                    },
                )

    status = "pass" if not errors else "fail"
    claim_status = "distribution_package_passed" if status == "pass" else "claim_blocked"
    emit(
        events,
        event="distribution_packaging_contract_summary",
        status=status,
        claim_status=claim_status,
        package_path=package_path,
        install_root=install_root,
        artifact_path=installed_artifact or source_artifact,
        artifact_refs=artifact_refs + ([rel(package_path)] if package_path else []) + evidence_files,
        failure_signature="none" if status == "pass" else failure_signature(errors),
        extra={"error_count": len(errors)},
    )

    report = {
        "schema_version": "distribution_packaging_contract.report.v1",
        "manifest_id": MANIFEST_ID,
        "bead": BEAD_ID,
        "status": status,
        "claim_status": claim_status,
        "trace_id": TRACE_ID,
        "source_commit": source_commit,
        "source_artifact": {
            "path": rel(source_artifact) if source_artifact else "",
            "exists": bool(source_artifact and source_artifact.exists()),
            "size": source_artifact.stat().st_size if source_artifact and source_artifact.exists() else 0,
            "failure_signature": source_failure,
        },
        "package": {
            "format": package.get("format", ""),
            "distribution_family": package.get("distribution_family", ""),
            "path": rel(package_path) if package_path else "",
            "install_root": rel(install_root) if install_root else "",
            "installed_artifact": rel(installed_artifact) if installed_artifact else "",
            "system_paths_touched": False,
        },
        "tools": tools,
        "checks": checks,
        "evidence_files": evidence_files,
        "errors": errors,
        "log_path": rel(log_path),
        "report_path": rel(report_path),
    }
    write_outputs(report, events)

    if status == "pass":
        print(
            "distribution_packaging_contract: PASS "
            f"package={report['package']['path']} install_root={report['package']['install_root']}"
        )
        return 0
    print("distribution_packaging_contract: FAIL " + "; ".join(errors), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
PY
