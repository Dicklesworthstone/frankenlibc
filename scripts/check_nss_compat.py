#!/usr/bin/env python3
"""Qualify compat identity lookup against the installed GNU NSS provider.

Every case binds a private /etc directory. The independent GNU process and
the candidate use the same files, real libnss_compat and test account backend.
The candidate runs through pinned dlsym exports and through LD_PRELOAD. Missing
providers are an explicit unavailable result, never an empty successful lookup.
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


LOCAL = {
    "passwd": "root:x:0:0:root:/root:/bin/sh\nlocal:x:9001:9001:Local:/local:/bin/sh\n",
    "group": "root:x:0:\nlocal:x:9001:local,fltest1\n",
    "shadow": "root:!:0:0:99999:7:::\nlocal:!:1:0:99999:7:::\n",
}
DIRECTIVES = {
    "local": {"passwd": "", "group": "", "shadow": ""},
    "all": {"passwd": "+\n", "group": "+\n", "shadow": "+\n"},
    "exclude": {"passwd": "-fltest2\n+\n", "group": "-fltestgrp2\n+\n",
                "shadow": "-fltest2\n+\n"},
    "selected": {"passwd": "+fltest1:override:::Override User:/special:/bin/false\n",
                 "group": "+fltestgrp:override::local\n",
                 "shadow": "+fltest1:override:::::::\n"},
    "netgroup": {"passwd": "-@block\n+@allow\n+\n", "group": "+\n",
                 "shadow": "-@block\n+@allow\n+\n"},
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, env, log, expected=0):
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
    log.with_suffix(".stdout").write_text(result.stdout)
    log.with_suffix(".stderr").write_text(result.stderr)
    if result.returncode != expected:
        raise RuntimeError(f"exit {result.returncode}, expected {expected}: {command!r}; see {log}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--oracle-only", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", action="append", choices=("strict", "hardened"))
    args = parser.parse_args()
    if args.oracle_only == (args.candidate is not None):
        parser.error("choose exactly one of --candidate and --oracle-only")
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    candidate = args.candidate.resolve(strict=True) if args.candidate else None
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("FRANKENLIBC_", "FLTEST_", "NSS_SOURCE_"))
           and key not in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH")}
    env.update(LC_ALL="C", LD_LIBRARY_PATH=str(output))
    cc = shlex.split(os.environ.get("CC", "cc"))
    flags = ["-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror"]
    fixture = root / "tests/integration/fixture_nss_compat.c"
    backend_source = root / "tests/integration/fixture_nss_module_lib.c"
    probe = output / "nss-compat-probe"
    backend = output / "libnss_fltest.so.2"
    report = {"qualified": False, "passed": False, "cases": [], "controls": [],
              "candidate": str(candidate) if candidate else None,
              "candidate_sha256": digest(candidate) if candidate else None,
              "fixture_sha256": digest(fixture), "backend_source_sha256": digest(backend_source),
              "processes": 0}
    try:
        run(cc + flags + [str(fixture), "-ldl", "-o", str(probe)], env, output / "build-probe")
        run(cc + flags + ["-shared", "-fPIC", str(backend_source), "-o", str(backend)],
            env, output / "build-backend")
        report.update(probe_sha256=digest(probe), backend_sha256=digest(backend))
        run(["bwrap", "--ro-bind", "/", "/", "/bin/true"], env, output / "sandbox")
        host = run([str(probe), "host", "provider"], env, output / "provider").strip()
        report.update(gnu_provider=host, gnu_sha256=digest(Path(host)))
        run([str(probe), host, "lookup"], env, output / "reject-gnu", expected=91)
        report["controls"].append("GNU substitution rejected")
        empty_source = output / "empty-provider.c"
        empty_source.write_text("int compat_empty_provider(void) { return 0; }\n")
        empty = output / "empty-provider.so"
        run(cc + flags + ["-shared", "-fPIC", str(empty_source), "-Wl,--no-as-needed", "-lc",
                          "-o", str(empty)], env, output / "build-empty")
        run([str(probe), str(empty), "lookup"], env, output / "reject-dependency", expected=91)
        report["controls"].append("dependency exports rejected")

        for case, directives in DIRECTIVES.items():
            etc = output / f"etc-{case}"
            etc.mkdir()
            for name, content in LOCAL.items():
                (etc / name).write_text(content + directives[name])
            (etc / "netgroup").write_text("allow (,fltest1,)\nblock (,fltest2,)\n")
            (etc / "nsswitch.conf").write_text(
                "passwd: compat\ngroup: compat\nshadow: compat\n"
                "passwd_compat: fltest\ngroup_compat: fltest\nshadow_compat: fltest\n"
                "netgroup: files\n")
            prefix = ["bwrap", "--ro-bind", "/", "/", "--ro-bind", str(etc), "/etc"]
            for scenario in ("lookup", "enumeration", "groups", "module"):
                label = f"{case}-{scenario}"
                expected = run(prefix + [str(probe), "host", scenario], env, output / f"{label}-gnu")
                report["processes"] += 1
                if len(expected.splitlines()) < 9:
                    raise RuntimeError(f"vacuous GNU transcript: {label}")
                if case == "all" and scenario == "lookup":
                    for value in ("fltest1:x:4201:4301:", "fltest2:*:4202:4302:", "fltestgrp:x:4301:"):
                        if value not in expected:
                            raise RuntimeError(f"GNU did not execute the backend: {value}")
                if case in ("exclude", "netgroup") and scenario == "lookup":
                    lines = [line for line in expected.splitlines() if line.startswith("pw fltest2 ")]
                    if len(lines) != 1 or not lines[0].endswith(" NULL"):
                        raise RuntimeError("GNU exclusion did not execute")
                if case == "selected" and scenario == "lookup" and "Override User:/special:/bin/false" not in expected:
                    raise RuntimeError("GNU field override did not execute")
                for mode in args.mode or ("strict", "hardened"):
                    for dispatch in ("pinned", "preload") if candidate else ("oracle",):
                        tag = f"{label}-{mode}-{dispatch}"
                        if candidate:
                            case_env = dict(env, FRANKENLIBC_MODE=mode)
                            command = prefix + [str(probe), str(candidate), scenario]
                            if dispatch == "preload":
                                # Apply preload to the subject process, after the
                                # mount namespace is established by the host runner.
                                command = prefix + ["--setenv", "LD_PRELOAD", str(candidate),
                                                    str(probe), str(candidate), scenario]
                            actual = run(command, case_env, output / tag)
                            report["processes"] += 1
                            if actual != expected:
                                (output / f"{tag}.diff").write_text("".join(difflib.unified_diff(
                                    expected.splitlines(True), actual.splitlines(True),
                                    fromfile="GNU", tofile="candidate")))
                                raise RuntimeError(f"differential mismatch: {tag}")
                        report["cases"].append({"case": case, "scenario": scenario, "mode": mode,
                                                "dispatch": dispatch, "observations": len(expected.splitlines()),
                                                "transcript_sha256": hashlib.sha256(expected.encode()).hexdigest()})
                        print(f"PASS {tag}", flush=True)

        if candidate:
            for control in ("missing", "recursive"):
                directory = output / control
                directory.mkdir()
                substitute = directory / "libnss_compat.so.2"
                link = [str(candidate)] if control == "recursive" else ["-lc"]
                run(cc + flags + ["-shared", "-fPIC", str(empty_source), "-Wl,--no-as-needed"] +
                    link + ["-o", str(substitute)], env, output / f"build-{control}")
                for mode in args.mode or ("strict", "hardened"):
                    case_env = dict(env, FRANKENLIBC_MODE=mode, LD_LIBRARY_PATH=str(directory))
                    run([str(probe), str(candidate), "unavailable"], case_env,
                        output / f"{control}-{mode}")
                    report["processes"] += 1
                    report["controls"].append(f"{control} provider returns UNAVAIL in {mode}")
        report["passed"] = True
        report["qualified"] = candidate is not None
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
        print(f"FAIL: {error}", file=sys.stderr)
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
