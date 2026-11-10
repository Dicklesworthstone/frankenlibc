#!/usr/bin/env python3
"""Compare deployed services and runtime NSS configuration with a GNU oracle.

The C fixture pins every public function to the requested DSO, including errno
and addrinfo deallocation. Each policy runs in a fresh process. Runtime source
overrides use a private /etc for both providers. Outputs are retained on failure;
neither missing tools nor a missing candidate passes.
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
CONFIGURE_COUNTS = {"accounts": 18, "initgroups": 14, "hosts": 10, "services": 12,
                    "errors": 19, "snapshot": 18, "snapshot-hosts": 18,
                    "shadow-snapshot": 11, "callback": 5}
CONFIGURE_REQUIRED = {
    "accounts": ("passwd fltest1 uid=4201", "shadow fltest1 changed=19001",
                 "group fltestgrp gid=4301", "passwd NULL uid=0"),
    "initgroups": ("initgroups rc=4 n=4 4301 4302 4303 0", "initgroups rc=1 n=1 4301"),
    "hosts": ("hosts fltest-host.example 192.0.2.41 192.0.2.42", "hosts NULL"),
    "services": ("service http -> module-http/42480", "address-service rc=0 4343",
                 "service http -> http/80", "service http -> NULL/0"),
    "errors": ("configure passwd [fltest []] rc=-1 errno=22", "passwd fltest1 uid=4201",
               "configure fl_no_such_database [files] rc=-1 errno=731", "passwd NULL uid=0"),
    "snapshot": ("group fltestgrp gid=4301", "shadow fltest1 changed=19001", "hosts NULL"),
    "snapshot-hosts": ("group fltestgrp gid=4301", "shadow fltest1 changed=19001", "hosts NULL"),
    "shadow-snapshot": ("shadow fltest1 changed=19001", "shadow NULL changed=0"),
    "callback": ("service fltest-reentry -> fltest-reentry/4347",
                 "configure callback observed=1", "service http -> http/80"),
}
CONFIGURE_INITIAL = "passwd: files\ngroup: files\nhosts: files\n"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv, env, log, expected=0):
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=15)
    log.with_suffix(".stdout").write_text(result.stdout)
    log.with_suffix(".stderr").write_text(result.stderr)
    if result.returncode != expected:
        raise RuntimeError(f"{argv!r}: exit {result.returncode}, expected {expected}; see {log}")
    return result.stdout


def private_etc_sandbox(env, output):
    """Require an operational mount namespace; never mutate the host's /etc."""
    for name, argv in (
        ("bwrap", ["bwrap", "--dev-bind", "/", "/", "true"]),
        ("unshare", ["unshare", "-m", "--propagation", "private", "true"]),
    ):
        try:
            result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=15)
        except FileNotFoundError:
            continue
        (output / f"sandbox-{name}.stdout").write_text(result.stdout)
        (output / f"sandbox-{name}.stderr").write_text(result.stderr)
        if result.returncode == 0:
            return name
    raise RuntimeError("runtime NSS oracle needs bwrap or a root mount namespace (unshare -m)")


def private_etc_command(sandbox, files, argv):
    if sandbox == "bwrap":
        wrapped = ["bwrap", "--dev-bind", "/", "/"]
        for name, path in files.items():
            wrapped += ["--bind", str(path), f"/etc/{name}"]
        return wrapped + argv
    mounts = [f"mount --bind {shlex.quote(str(path))} {shlex.quote('/etc/' + name)}"
              for name, path in files.items()]
    script = " && ".join(mounts + ['exec "$@"'])
    return ["unshare", "-m", "--propagation", "private", "sh", "-c", script, "sh"] + argv


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
           and key not in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "NSS_CONFIGURE_PRIVATE_FILE")}
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
              "processes": 0, "candidate_qualified": False, "passed": False}
    try:
        host = command([str(probe), "services", "host", "fltest", "identity"],
                       env, output / "host-identity").strip()
        report["gnu_provider"] = host
        report["gnu_sha256"] = digest(Path(host))
        # A candidate path that resolves to GNU must not self-compare. Run the
        # controls even in oracle-only mode, which qualifies only the fixture.
        command([str(probe), "services", host, "fltest", "queries"],
                env, output / "reject-gnu-provider", expected=91)
        report["negative_controls"].append("GNU substitution rejected")
        # A dependency's symbols are not exports from the requested provider.
        stub = output / "dependency-only.c"
        stub.write_text("int nss_services_dependency_only(void) { return 0; }\n")
        stub_dso = output / "dependency-only.so"
        command(compiler + flags + ["-shared", "-fPIC", str(stub),
                "-Wl,--no-as-needed", "-lc", "-o", str(stub_dso)],
                env, output / "build-dependency-control")
        command([str(probe), "services", str(stub_dso), "fltest", "queries"],
                env, output / "reject-dependency-provider", expected=91)
        report["negative_controls"].append("dependency symbol fallback rejected")
        for label, provider in (("gnu", host), ("dependency", str(stub_dso))):
            command([str(probe), "configure", provider, "accounts"],
                    env, output / f"reject-configure-{label}-provider", expected=91)
            report["negative_controls"].append(f"configure {label} provider rejected")

        sandbox = private_etc_sandbox(env, output)
        report["configure_sandbox"] = sandbox
        files = {}
        for name, content in {
            "passwd": "root:x:0:0:root:/root:/bin/sh\n",
            "group": "root:x:0:\n",
            "shadow": "root:!:0:0:99999:7:::\n",
            "hosts": "127.0.0.1 localhost\n",
        }.items():
            path = output / f"configure-{name}"
            path.write_text(content)
            files[name] = path
        report["configure_files_sha256"] = {name: digest(path) for name, path in files.items()}
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
                report["cases"].append({"family": "services", "mode": mode,
                                        "policy": policy, "scenario": scenario,
                                        "observations": COUNTS[scenario],
                                        "transcript_sha256": hashlib.sha256(expected.encode()).hexdigest()})
                report["observations"] += COUNTS[scenario]
                print(f"PASS {tag}: {policy!r} ({COUNTS[scenario]} observations)", flush=True)
            for scenario, count in CONFIGURE_COUNTS.items():
                tag = f"{mode}-configure-{scenario}"
                config = output / f"{tag}.conf"
                case_files = dict(files, **{"nsswitch.conf": config})
                case_env = dict(env, FRANKENLIBC_MODE=mode,
                                NSS_CONFIGURE_PRIVATE_FILE=str(config))
                # Snapshot cases rewrite this same bind-mounted inode. Reset
                # it before each provider to ensure independent initial state.
                config.write_text(CONFIGURE_INITIAL)
                expected = command(private_etc_command(sandbox, case_files,
                                   [str(probe), "configure", "host", scenario]),
                                   case_env, output / f"{tag}-gnu")
                report["processes"] += 1
                lines = expected.splitlines()
                if len(lines) != count or any(line not in lines for line in CONFIGURE_REQUIRED[scenario]):
                    raise RuntimeError(f"{tag}: incomplete or vacuous GNU configure transcript")
                if candidate:
                    config.write_text(CONFIGURE_INITIAL)
                    actual = command(private_etc_command(sandbox, case_files,
                                     [str(probe), "configure", str(candidate), scenario]),
                                     case_env, output / f"{tag}-candidate")
                    report["processes"] += 1
                    if actual != expected:
                        difference = "".join(difflib.unified_diff(
                            expected.splitlines(True), actual.splitlines(True),
                            fromfile="GNU", tofile="candidate"))
                        (output / f"{tag}.diff").write_text(difference)
                        raise RuntimeError(f"{tag}: differential mismatch; see {tag}.diff")
                report["cases"].append({"family": "configure", "mode": mode,
                                        "scenario": scenario, "observations": count,
                                        "transcript_sha256": hashlib.sha256(expected.encode()).hexdigest()})
                report["observations"] += count
                print(f"PASS {tag} ({count} observations)", flush=True)
        report["passed"] = True
        report["candidate_qualified"] = candidate is not None
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
