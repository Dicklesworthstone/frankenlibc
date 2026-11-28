#!/usr/bin/env python3
"""Qualify compat identity lookup against the installed GNU NSS provider.

Every case binds a private /etc directory. The independent GNU process uses
the installed compat provider; the candidate uses the same files and account
backend through its own pinned exports and LD_PRELOAD. Separate interoperability
audits execute the real GNU module and verify its imports of private callbacks.
Missing providers are an explicit unavailable result, never an empty successful
lookup. --native-compat additionally poisons the GNU compat module while retaining
the selected account backend. Its private-helper audit still explicitly executes
the real GNU module. --component-proof excludes the public identity dispatcher,
the complete ABI, allocator provenance, and owned thread-local storage.
"""

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys


LOCAL = {
    "passwd": "root:x:0:0:root:/root:/bin/sh\nlocal:x:9001:9001:Local:/local:/bin/sh\n",
    "group": "root:x:0:\nlocal:x:9001:local,fltest1\n",
    "shadow": "root:!:0:0:99999:7:::\nlocal:!:1:0:99999:7:::\n",
}
AFTER = {
    "passwd": "after:x:9002:9002:After:/after:/bin/sh\n",
    "group": "after:x:9002:\n",
    "shadow": "after:!:2:0:99999:7:::\n",
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
    "netgroup-only": {"passwd": "+@allow\n", "group": "+fltestgrp\n",
                      "shadow": "+@allow\n"},
    "netgroup-exclude": {"passwd": "-@block\n+\n", "group": "-fltestgrp2\n+\n",
                         "shadow": "-@block\n+\n"},
    "netgroup-nested": {"passwd": "-@block-parent\n+@allow-parent\n", "group": "+fltestgrp\n",
                        "shadow": "-@block-parent\n+@allow-parent\n"},
}
NATIVE_DIRECTIVES = {
    "duplicates": {"passwd": "+fltest1\n+fltest1\n+\n",
                   "group": "+fltestgrp\n+fltestgrp\n+\n",
                   "shadow": "+fltest1\n+fltest1\n+\n"},
    "excluded-then-selected": {"passwd": "-fltest1\n+fltest1\n+\n",
                               "group": "-fltestgrp\n+fltestgrp\n+\n",
                               "shadow": "-fltest1\n+fltest1\n+\n"},
    "selected-then-excluded": {"passwd": "+fltest1\n-fltest1\n+\n",
                               "group": "+fltestgrp\n-fltestgrp\n+\n",
                               "shadow": "+fltest1\n-fltest1\n+\n"},
    "local-collision": {"passwd": "fltest1:l:9101:9101:Local Remote:/local:/bin/sh\n+\n",
                        "group": "fltestgrp:l:9101:fltest1\n+\n",
                        "shadow": "fltest1:l:99:3:88:4:::\n+\n"},
    "excluded-local-collision": {
        "passwd": "-fltest1\nfltest1:l:9101:9101:Local Remote:/local:/bin/sh\n+\n",
        "group": "-fltestgrp\nfltestgrp:l:9101:fltest1\n+\n",
        "shadow": "-fltest1\nfltest1:l:99:3:88:4:::\n+\n"},
    "numeric-overrides": {"passwd": "+fltest1:override:123:456:New:/new:/bin/false\n",
                          "group": "+fltestgrp:override:123:local\n",
                          "shadow": "+fltest1:override:123:456:789:10:11:12:13\n"},
    "invalid-overrides": {
        "passwd": "+fltest1:bad:-1:4301:Bad:/bad:/bad\n+fltest1:bad:4294967296:4301:::\n+\n",
        "group": "+fltestgrp:bad:-1:local\n+fltestgrp:bad:4294967296:local\n+\n",
        "shadow": "+fltest1:bad:-1::::::\n+fltest1:bad:999999999999999999999999::::::\n+\n"},
    "colonless": {"passwd": "+fltest1\n", "group": "+fltestgrp\n", "shadow": "+fltest1\n"},
    "missing-selected": {"passwd": "+after\n", "group": "+after\n", "shadow": "+after\n"},
    "netgroup-empty-user": {"passwd": "+@empty-user\n", "group": "+\n",
                            "shadow": "+@empty-user\n"},
    "netgroup-empty-exclusion": {"passwd": "-@empty-user\n+\n", "group": "+\n",
                                 "shadow": "-@empty-user\n+\n"},
    "netgroup-foreign-domain": {"passwd": "+@foreign-domain\n", "group": "+\n",
                                "shadow": "+@foreign-domain\n"},
    "netgroup-foreign-host": {"passwd": "+@foreign-host\n", "group": "+\n",
                              "shadow": "+@foreign-host\n"},
    "duplicate-gids": {"passwd": "+\n", "group": "same:x:4302:fltest1\n+\n", "shadow": "+\n"},
    "first-provider-only": {"passwd": "+\n", "group": "+\n", "shadow": "+\n"},
    "group-enumeration-backend": {"passwd": "+\n", "group": "+\n", "shadow": "+\n"},
    "backend-enumeration-unavailable": {"passwd": "+\n", "group": "+\n", "shadow": "+\n"},
    "backend-unavailable": {"passwd": "+\n", "group": "+\n", "shadow": "+\n"},
    "backend-tryagain": {"passwd": "+\n", "group": "+\n", "shadow": "+\n"},
}
NATIVE_ENV = {
    "backend-enumeration-unavailable": {"FLTEST_ACCOUNT_ENUM": "get-unavail"},
    "backend-unavailable": {"FLTEST_STATUS": "unavail"},
    "backend-tryagain": {"FLTEST_STATUS": "tryagain"},
}
PRIVATE_IMPORTS = (
    "__nss_files_fopen", "__nss_database_get", "__nss_lookup_function",
    "__internal_setnetgrent", "__internal_getnetgrent_r", "__internal_endnetgrent",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, env, log, expected=0):
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
    log.with_suffix(".stdout").write_text(result.stdout)
    log.with_suffix(".stderr").write_text(result.stderr)
    if result.returncode != expected:
        raise RuntimeError(f"exit {result.returncode}, expected {expected}: {command!r}; see {log}")
    return result.stdout


def check_records(case, scenario, transcript):
    """Check oracle coverage as well as equality, including forbidden accounts."""
    if case not in DIRECTIVES or scenario not in ("lookup", "enumeration", "module"):
        return
    lines = transcript.splitlines()
    prefixes = ({"pw": "pw ", "gr": "gr ", "sp": "sp "} if scenario == "lookup" else
                {tag: f"{tag} retry " for tag in ("pw", "gr", "sp")} if scenario == "enumeration" else
                {tag: f"module {tag} next=1 " for tag in ("pw", "gr", "sp")})
    for tag, prefix in prefixes.items():
        records = [line for line in lines if line.startswith(prefix)]
        database = {"pw": "passwd", "gr": "group", "sp": "shadow"}[tag]
        # GNU's bare '+' finishes this traversal even when local rows follow
        # it. Keep those rows in the transcript; require tail survival for the
        # selected-name and netgroup forms that return to the local file.
        names = ("root", "local")
        if "+" not in DIRECTIVES[case][database].splitlines():
            names += ("after",)
        for name in names:
            if not any(f" {name}:" in line for line in records):
                raise RuntimeError(f"GNU lost local {tag} entry {name} in {case}/{scenario}")
        if tag in ("pw", "sp") and case != "local":
            if not any(" fltest1:" in line for line in records):
                raise RuntimeError(f"GNU did not include fltest1 in {case}/{scenario}/{tag}")
        if tag in ("pw", "sp") and (case in ("exclude", "selected") or case.startswith("netgroup")):
            if any(" fltest2:" in line for line in records):
                raise RuntimeError(f"GNU did not exclude fltest2 in {case}/{scenario}/{tag}")


def check_native_records(case, scenario, transcript):
    """Keep non-vacuous invariants independent of candidate/oracle equality."""
    if scenario not in ("module", "module-state"):
        return
    prefix = "module" if scenario == "module" else "state"
    rows = [line for line in transcript.splitlines() if line.startswith(f"{prefix} pw next=1 ")]
    remote = [line for line in rows if " fltest1:x:4201:4301:" in line]
    local = [line for line in rows if " fltest1:l:9101:9101:" in line]
    if case in ("duplicates", "selected-then-excluded", "local-collision") and len(remote) != 1:
        raise RuntimeError(f"GNU remote duplicate handling was not exercised: {case}/{scenario}")
    if case == "local-collision" and len(local) != 1:
        raise RuntimeError("GNU local/remote collision did not retain the local record")
    if case == "excluded-local-collision" and (len(local) != 1 or remote):
        raise RuntimeError("GNU exclusion incorrectly removed a local record or admitted the remote one")
    if case == "excluded-then-selected" and remote:
        raise RuntimeError("GNU selected directive incorrectly bypassed an earlier exclusion")
    if case == "numeric-overrides":
        for value in ("fltest1:override:4201:4301:New:/new:/bin/false",
                      "fltestgrp:x:4301:fltest1,fltest2",
                      "fltest1:override:123:456:789:10:11:12:13"):
            if value not in transcript:
                raise RuntimeError(f"GNU override contract was not exercised: {value}")
    if case == "first-provider-only" and any(" fltest" in line for line in rows):
        raise RuntimeError("GNU unexpectedly traversed the second compat source")
    if case in ("netgroup-empty-user", "netgroup-foreign-domain"):
        if remote:
            raise RuntimeError("GNU netgroup enumeration unexpectedly admitted a filtered user")
        if scenario == "module-state" and "state pw name=fltest1 rc=1 " not in transcript:
            raise RuntimeError("GNU netgroup keyed/enumeration distinction was not exercised")


def check_selected_retry(actual, keyed_oracle, module_oracle, enumeration_oracle):
    """Require native account retention without concealing GNU record loss.

    GNU compat on the measured host blacklists a selected +name before its
    backend lookup succeeds. After backend ERANGE, GNU enumeration skips that
    account. We retain both raw transcripts and their diff. The native result
    must instead preserve the exact record and scratch admission observed in
    independent GNU keyed lookups, then return the following local account.
    This is explicitly a native invariant, not an equality comparison with
    GNU enumeration. The direct backend control rules out provider cursor loss.
    """
    wanted = []
    for tag in ("pw", "gr", "sp"):
        local = [line for line in enumeration_oracle.splitlines()
                 if line.startswith(f"budget {tag} local=")]
        if len(local) != 2:
            raise RuntimeError("retry oracle did not establish both initial local records")
        wanted.extend(local)
        keyed = [line for line in keyed_oracle.splitlines()
                 if line.startswith(f"budget {tag} name capacity=")]
        found = False
        for line in keyed:
            wanted.append(line.replace(" name capacity=", " next capacity=", 1))
            if " rc=1 " in line:
                found = True
                break
        if not found:
            raise RuntimeError("retry oracle never returned the selected account")
        following = [line.split(" after:", 1)[1] for line in module_oracle.splitlines()
                     if line.startswith(f"module {tag} next=1 ") and " after:" in line]
        if len(following) != 1:
            raise RuntimeError("retry oracle did not establish the following local account")
        wanted.append(f"budget {tag} following=1 error=619 after:{following[0]}")
    if actual != "\n".join(wanted) + "\n":
        raise RuntimeError("native selected-account retry lost an account or violated caller scratch capacity")


def check_bindings(path, candidate):
    bindings = {}
    pattern = re.compile(r"binding file (.+?) \[\d+\] to (.+?) \[\d+\]:.*?symbol [`']([^']+)'")
    for line in path.read_text().splitlines():
        match = pattern.search(line)
        if not match:
            continue
        source, target, name = match.groups()
        if Path(source).name != "libnss_compat.so.2" or name not in PRIVATE_IMPORTS:
            continue
        if not Path(target).samefile(candidate):
            raise RuntimeError(f"GNU compat import {name} bypassed candidate: {target}")
        bindings[name] = {"source": source, "target": target}
    missing = set(PRIVATE_IMPORTS) - bindings.keys()
    if missing:
        raise RuntimeError(f"missing real compat import bindings: {sorted(missing)}")
    return bindings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--oracle-only", action="store_true")
    parser.add_argument("--component-proof", action="store_true")
    parser.add_argument("--native-compat", action="store_true",
                        help="test owned compat policies with the GNU compat DSO poisoned")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", action="append", choices=("strict", "hardened"))
    args = parser.parse_args()
    if args.oracle_only == (args.candidate is not None):
        parser.error("choose exactly one of --candidate and --oracle-only")
    if args.component_proof and (args.oracle_only or args.mode):
        parser.error("--component-proof requires a candidate and has no full-ABI runtime modes")
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    candidate = args.candidate.resolve(strict=True) if args.candidate else None
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("FRANKENLIBC_", "FLTEST_", "NSS_SOURCE_"))
           and key not in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "LD_DEBUG", "LD_DEBUG_OUTPUT")}
    env.update(LC_ALL="C", LD_LIBRARY_PATH=str(output))
    cc = shlex.split(os.environ.get("CC", "cc"))
    flags = ["-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror"]
    fixture = root / "tests/integration/fixture_nss_compat.c"
    backend_source = root / "tests/integration/fixture_nss_module_lib.c"
    probe = output / "nss-compat-probe"
    backend = output / "libnss_fltest.so.2"
    report = {"qualified": False, "full_abi_qualified": False, "component_passed": False,
              "qualification": ("GNU oracle only" if args.oracle_only else
                                "exact-source native-compat component" if args.component_proof and args.native_compat else
                                "exact-source host-interop component" if args.component_proof else
                                "deployed ABI differential"),
              "passed": False, "cases": [], "controls": [], "binding_audits": [],
              "native_retry_invariants": [], "intentional_differences": [],
              "candidate": str(candidate) if candidate else None,
              "candidate_sha256": digest(candidate) if candidate else None,
              "fixture_sha256": digest(fixture), "backend_source_sha256": digest(backend_source),
              "native_compat": args.native_compat, "provider_isolation": [],
              "processes": 0}
    if args.component_proof:
        report["component_scope"] = {
            "production": ["compat module loader and 15 delegates", "six private host callbacks",
                           "raw host symbol resolver and proc-maps lookup"],
            "excluded": ["public native passwd/group/shadow dispatcher", "complete ABI",
                         "owned TLS", "allocator provenance and membrane"],
            "adapters": ["host errno and allocation context; see component build receipt"],
        }
        if args.native_compat:
            report["component_scope"]["production"] = [
                "native compat provider and exported NSS callbacks", "NSS configuration and account module dispatch",
                "compat policy and account parsers", "netgroup session", "result packers",
                "six private host callbacks and raw host symbol resolver"]
    try:
        run(cc + flags + [str(fixture), "-ldl", "-o", str(probe)], env, output / "build-probe")
        run(cc + flags + ["-shared", "-fPIC", str(backend_source), "-o", str(backend)],
            env, output / "build-backend")
        report.update(probe_sha256=digest(probe), backend_sha256=digest(backend))
        if args.native_compat:
            fallback = output / "libnss_fltestnoig.so.2"
            run(cc + flags + ["-shared", "-fPIC", "-DSERVICE=fltestnoig", "-DNO_INITGROUPS",
                              str(backend_source), "-o", str(fallback)], env, output / "build-fallback")
            report["fallback_backend_sha256"] = digest(fallback)
            retry_env = dict(env, FLTEST_ACCOUNT_SCRATCH="fltest", FLTEST_ACCOUNT_ENUM_SCRATCH="fltest")
            direct_retry = run([str(probe), "host", "backend-retry"], retry_env, output / "backend-retry")
            if len(direct_retry.splitlines()) != 18:
                raise RuntimeError("direct backend retry control did not execute all three databases")
            report["processes"] += 1
            report["controls"].append("direct backend preserves result storage and enumeration cursor on ERANGE")
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

        poison = None
        if args.native_compat and candidate:
            poison = output / "poison-compat"
            poison.mkdir()
            source = poison / "poison.c"
            source.write_text("#include <unistd.h>\n"
                              "__attribute__((constructor)) static void reject(void) { _exit(97); }\n")
            run(cc + flags + ["-shared", "-fPIC", str(source), "-o", str(poison / "libnss_compat.so.2")],
                env, output / "build-poison")
            poison_env = dict(env, LD_LIBRARY_PATH=f"{poison}:{output}")
            run([str(probe), "host", "module"], poison_env, output / "reject-gnu-compat", expected=97)
            report["controls"].append("GNU compat poison was executed by the independent provider control")

        modes = ("component",) if args.component_proof else (args.mode or ("strict", "hardened"))
        module_oracles = {}
        budget_oracles = {}
        directories = {}
        policies = dict(DIRECTIVES)
        if args.native_compat:
            policies.update(NATIVE_DIRECTIVES)
        for case, directives in policies.items():
            etc = output / f"etc-{case}"
            etc.mkdir()
            directories[case] = etc
            for name, content in LOCAL.items():
                (etc / name).write_text(content + directives[name] + AFTER[name])
            (etc / "netgroup").write_text(
                "allow (,fltest1,)\nblock (,fltest2,)\n"
                "allow-parent allow allow-leaf allow\nallow-leaf (,fltest1,)\n"
                "block-parent block\nempty-user (,,)\n"
                "foreign-domain (,fltest1,fl-foreign-domain.invalid)\n"
                "foreign-host (fl-foreign-host.invalid,fltest1,)\n")
            selected_backend = ("flmissing [UNAVAIL=continue] fltest" if case == "first-provider-only" else
                                "fltestnoig" if case == "group-enumeration-backend" else "fltest")
            (etc / "nsswitch.conf").write_text(
                "passwd: compat\ngroup: compat\nshadow: compat\n"
                f"passwd_compat: {selected_backend}\ngroup_compat: {selected_backend}\nshadow_compat: {selected_backend}\n"
                "netgroup: files\n")
            prefix = ["bwrap", "--ro-bind", "/", "/", "--ro-bind", str(etc), "/etc"]
            scenarios = ("module",) if args.component_proof else ("lookup", "enumeration", "groups", "module")
            if args.native_compat:
                scenarios += ("module-state",)
                if case in ("all", "selected", "numeric-overrides", "colonless"):
                    scenarios += ("module-budget", "module-retry-budget")
            if case == "netgroup":
                scenarios += ("private",)
            for scenario in scenarios:
                label = f"{case}-{scenario}"
                scenario_env = dict(env)
                if args.native_compat:
                    scenario_env.update(NATIVE_ENV.get(case, {}))
                    scenario_env["FLTEST_TRACE"] = "1"
                if scenario in ("module-budget", "module-retry-budget"):
                    scenario_env.update(FLTEST_ACCOUNT_SCRATCH="fltest", FLTEST_ACCOUNT_ENUM_SCRATCH="fltest")
                expected = run(prefix + [str(probe), "host", scenario], scenario_env, output / f"{label}-gnu")
                report["processes"] += 1
                if len(expected.splitlines()) < 9:
                    raise RuntimeError(f"vacuous GNU transcript: {label}")
                check_records(case, scenario, expected)
                if args.native_compat:
                    check_native_records(case, scenario, expected)
                if scenario == "module":
                    module_oracles[case] = expected
                if scenario == "module-budget":
                    budget_oracles[case] = expected
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
                for mode in modes:
                    for dispatch in ("pinned", "preload") if candidate else ("oracle",):
                        tag = f"{label}-{mode}-{dispatch}"
                        comparison = "oracle"
                        if candidate:
                            case_env = dict(scenario_env)
                            if args.native_compat and scenario != "private":
                                case_env.update(LD_LIBRARY_PATH=f"{poison}:{output}",
                                                FLTEST_COMPAT_REQUIRE_NATIVE="1")
                            if mode != "component":
                                case_env["FRANKENLIBC_MODE"] = mode
                            command = prefix + [str(probe), str(candidate), scenario]
                            if dispatch == "preload":
                                case_env["FLTEST_COMPAT_REQUIRE_INTERPOSITION"] = "1"
                                # Apply preload to the subject process, after the
                                # mount namespace is established by the host runner.
                                command = prefix + ["--setenv", "LD_PRELOAD", str(candidate),
                                                    str(probe), str(candidate), scenario]
                            actual = run(command, case_env, output / tag)
                            report["processes"] += 1
                            comparison = "gnu_exact"
                            if args.native_compat and case == "all" and scenario == "module":
                                trace = (output / f"{tag}.stderr").read_text()
                                required_calls = ("fltest:getpwent_r", "fltest:getgrent_r", "fltest:getspent_r")
                                if any(call not in trace for call in required_calls):
                                    raise RuntimeError("native compat bypassed the selected account backend")
                                report["provider_isolation"].append({
                                    "case": tag, "backend_calls": list(required_calls),
                                    "trace_sha256": hashlib.sha256(trace.encode()).hexdigest()})
                            selected_retry = (args.native_compat and scenario == "module-retry-budget"
                                              and case != "all")
                            if selected_retry:
                                check_selected_retry(actual, budget_oracles[case], module_oracles[case], expected)
                                report["native_retry_invariants"].append({"case": tag, "databases": 3,
                                    "invariant": "selected account retained after backend ERANGE; real caller scratch admission"})
                            if actual != expected:
                                (output / f"{tag}.diff").write_text("".join(difflib.unified_diff(
                                    expected.splitlines(True), actual.splitlines(True),
                                    fromfile="GNU", tofile="candidate")))
                                if selected_retry:
                                    comparison = "native_retry_invariant"
                                    report["intentional_differences"].append({
                                        "case": tag, "databases": 3, "status": "native preserves selected accounts",
                                        "gnu_behavior": "selected +name enumeration drops account after backend ERANGE",
                                        "gnu_transcript": f"{label}-gnu.stdout", "candidate_transcript": f"{tag}.stdout",
                                        "diff": f"{tag}.diff"})
                                else:
                                    raise RuntimeError(f"differential mismatch: {tag}")
                        report["cases"].append({"case": case, "scenario": scenario, "mode": mode,
                                                "dispatch": dispatch, "comparison": comparison,
                                                "observations": len(expected.splitlines()),
                                                "transcript_sha256": hashlib.sha256(expected.encode()).hexdigest()})
                        print(f"PASS {tag}", flush=True)

        if poison:
            report["provider_isolation"].append({
                "poison": str(poison / "libnss_compat.so.2"),
                "poison_sha256": digest(poison / "libnss_compat.so.2"),
                "gnu_control_exit": 97, "candidate_maps_checked_in_each_native_process": True,
                "account_backend_retained": str(backend)})

        if candidate:
            # dlsym(handle) ownership does not prove that a foreign module's
            # versioned imports bind to the candidate. Capture the loader's
            # real bindings in both an ordinary backend and a netgroup path.
            for case in ("all", "netgroup"):
                label = f"bindings-{case}"
                case_env = dict(env, FLTEST_COMPAT_REQUIRE_INTERPOSITION="1")
                if not args.component_proof:
                    case_env["FRANKENLIBC_MODE"] = modes[0]
                command = ["bwrap", "--ro-bind", "/", "/", "--ro-bind", str(directories[case]), "/etc",
                           "--setenv", "LD_PRELOAD", str(candidate), "--setenv", "LD_DEBUG", "bindings",
                           "--setenv", "LD_BIND_NOW", "1",
                           str(probe), str(candidate), "host-module" if args.native_compat else "module"]
                actual = run(command, case_env, output / label)
                report["processes"] += 1
                if actual != module_oracles[case]:
                    raise RuntimeError(f"binding audit changed functional result: {case}")
                bindings = check_bindings(output / f"{label}.stderr", candidate)
                report["binding_audits"].append({"case": case, "imports": bindings})
                print(f"PASS {label}", flush=True)
            for control in () if args.native_compat else ("missing", "recursive"):
                directory = output / control
                directory.mkdir()
                substitute = directory / "libnss_compat.so.2"
                link = [str(candidate)] if control == "recursive" else ["-lc"]
                run(cc + flags + ["-shared", "-fPIC", str(empty_source), "-Wl,--no-as-needed"] +
                    link + ["-o", str(substitute)], env, output / f"build-{control}")
                for mode in modes:
                    case_env = dict(env, LD_LIBRARY_PATH=str(directory))
                    if mode != "component":
                        case_env["FRANKENLIBC_MODE"] = mode
                    run([str(probe), str(candidate), "unavailable"], case_env,
                        output / f"{control}-{mode}")
                    report["processes"] += 1
                    report["controls"].append(f"{control} provider returns UNAVAIL in {mode}")
        report["passed"] = True
        report["qualified"] = candidate is not None and not args.component_proof
        report["full_abi_qualified"] = report["qualified"]
        report["component_passed"] = bool(candidate) and args.component_proof
        report["gnu_exact_match"] = bool(candidate) and not report["intentional_differences"]
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
        print(f"FAIL: {error}", file=sys.stderr)
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
