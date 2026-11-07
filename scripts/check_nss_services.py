#!/usr/bin/env python3
"""Compare deployed services NSS entry points with a live GNU module oracle.

The C fixture pins all eight public functions to the requested DSO, including
errno and addrinfo deallocation. Each policy runs in a fresh process. Outputs
are retained on failure; neither missing tools nor a missing candidate passes.
--oracle-only exercises GNU and the fixture without qualifying a candidate.
"""

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys


POLICIES = (
    "files", "files fltest", "fltest files",
    "fltest [SUCCESS=continue] files", "fltest [NOTFOUND=return] files",
    "fltest [TRYAGAIN=return] files", "fltest [TRYAGAIN=continue] files",
    "fltest [UNAVAIL=return] files", "fltest [UNAVAIL=continue] files",
    "fltest [!SUCCESS=return] files", "flmissing files", "compat", "fltest",
)
COUNTS = {"queries": 52, "profiles": 48, "reverse": 12, "reentrant": 85,
          "range-stop": 29, "unchanged-errno": 10, "callback": 1}
CASES = [(policy, scenario) for policy in POLICIES
         for scenario in ("queries", "profiles", "reverse")]
CASES += [("fltest", "reentrant"), ("compat", "reentrant"),
          ("fltest [TRYAGAIN=continue] files", "range-stop"),
          ("fltest", "unchanged-errno"), ("fltest", "callback")]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv, env, log, expected=0):
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=15)
    log.with_suffix(".stdout").write_text(result.stdout)
    log.with_suffix(".stderr").write_text(result.stderr)
    if result.returncode != expected:
        raise RuntimeError(f"{argv!r}: exit {result.returncode}, expected {expected}; see {log}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", action="append", choices=("strict", "hardened"))
    parser.add_argument("--oracle-only", action="store_true")
    args = parser.parse_args()
    if args.oracle_only == (args.candidate is not None):
        parser.error("choose exactly one of --candidate and --oracle-only")
    candidate = args.candidate.resolve(strict=True) if args.candidate else None
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("FRANKENLIBC_", "FLTEST_", "NSS_SOURCE_"))
           and key not in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH")}
    env["LC_ALL"] = "C"
    env["LD_LIBRARY_PATH"] = str(output)
    compiler = shlex.split(os.environ.get("CC", "cc"))
    fixture = root / "tests/integration/fixture_nss_modules.c"
    module_source = root / "tests/integration/fixture_nss_module_lib.c"
    module = output / "libnss_fltest.so.2"
    probe = output / "nss-services-probe"
    flags = ["-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror"]
    command(compiler + flags + ["-shared", "-fPIC", str(module_source), "-o", str(module)],
            env, output / "build-module")
    command(compiler + flags + [str(fixture), "-ldl", "-pthread", "-o", str(probe)],
            env, output / "build-probe")
    report = {"qualification": "GNU oracle only" if args.oracle_only else "deployed ABI differential",
              "candidate": str(candidate) if candidate else None,
              "candidate_sha256": digest(candidate) if candidate else None,
              "fixture_sha256": digest(fixture), "module_source_sha256": digest(module_source),
              "module_sha256": digest(module), "probe_sha256": digest(probe),
              "services_file_sha256": digest(Path("/etc/services")),
              "cases": [], "negative_controls": [], "observations": 0,
              "processes": 0, "passed": False}
    try:
        host = command([str(probe), "services", "host", "fltest", "identity"],
                       env, output / "host-identity").strip()
        report["gnu_provider"] = host
        report["gnu_sha256"] = digest(Path(host))
        if candidate:
            # A candidate path that resolves to GNU must not self-compare.
            command([str(probe), "services", host, "fltest", "queries"],
                    env, output / "reject-gnu-provider", expected=91)
            report["negative_controls"].append("GNU substitution rejected")
            # A DSO's dependency may export a required symbol; that still is
            # not the requested provider and must fail before comparisons.
            stub = output / "dependency-only.c"
            stub.write_text("int nss_services_dependency_only(void) { return 0; }\n")
            stub_dso = output / "dependency-only.so"
            command(compiler + flags + ["-shared", "-fPIC", str(stub),
                    "-Wl,--no-as-needed", "-lc", "-o", str(stub_dso)],
                    env, output / "build-dependency-control")
            command([str(probe), "services", str(stub_dso), "fltest", "queries"],
                    env, output / "reject-dependency-provider", expected=91)
            report["negative_controls"].append("dependency symbol fallback rejected")
        for mode in args.mode or ("strict", "hardened"):
            for index, (policy, scenario) in enumerate(CASES):
                tag = f"{mode}-{index:02d}-{scenario}"
                config = output / f"{tag}.conf"
                config.write_text(f"services: {policy}\n")
                case_env = dict(env, FRANKENLIBC_MODE=mode,
                                FRANKENLIBC_NSSWITCH_CONF=str(config))
                expected = command([str(probe), "services", "host", policy, scenario],
                                   case_env, output / f"{tag}-gnu")
                report["processes"] += 1
                if len(expected.splitlines()) != COUNTS[scenario]:
                    raise RuntimeError(f"{tag}: incomplete GNU transcript")
                if policy == "fltest" and scenario == "queries":
                    if "fltest-service/tcp/4343" not in expected or "3072:s:s" not in expected:
                        raise RuntimeError("GNU did not execute the installed service module")
                if candidate:
                    actual = command([str(probe), "services", str(candidate), policy, scenario],
                                     case_env, output / f"{tag}-candidate")
                    report["processes"] += 1
                    if actual != expected:
                        difference = "".join(difflib.unified_diff(
                            expected.splitlines(True), actual.splitlines(True),
                            fromfile="GNU", tofile="candidate"))
                        (output / f"{tag}.diff").write_text(difference)
                        raise RuntimeError(f"{tag}: differential mismatch; see {tag}.diff")
                report["cases"].append({"mode": mode, "policy": policy, "scenario": scenario,
                                        "observations": COUNTS[scenario],
                                        "transcript_sha256": hashlib.sha256(expected.encode()).hexdigest()})
                report["observations"] += COUNTS[scenario]
                print(f"PASS {tag}: {policy!r} ({COUNTS[scenario]} observations)", flush=True)
        report["passed"] = True
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
        print(f"FAIL: {error}", file=sys.stderr)
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if not report["passed"]:
        return 1
    print(f"PASS {report['qualification']}: {len(report['cases'])} cases, "
          f"{report['observations']} observations, {report['processes']} lookup processes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
