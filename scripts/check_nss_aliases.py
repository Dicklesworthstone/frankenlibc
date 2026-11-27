#!/usr/bin/env python3
"""Exercise native aliases and configured NSS against an independent GNU process.

The runner binds private /etc data, pins every callable and errno to the selected
DSO, and checks caller-buffer canaries and aligned member pointers. Full ABI runs
cover pinned and LD_PRELOAD dispatch in strict and hardened modes. The explicit
--component-proof option labels a smaller exact-source component honestly: it
does not qualify the complete ABI, allocator membrane, or owned TLS.
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
    "flalias", "flalias files", "flalias [NOTFOUND=return] files",
    "flalias [TRYAGAIN=return] files", "flalias [TRYAGAIN=continue] files",
    "flalias [UNAVAIL=return] files", "flalias [SUCCESS=continue] files",
    "flmissing files", "files [SUCCESS=continue] flmissing",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, env, log, expected=0):
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=20)
    log.with_suffix(".stdout").write_text(result.stdout)
    log.with_suffix(".stderr").write_text(result.stderr)
    if result.returncode != expected:
        raise RuntimeError(f"exit {result.returncode}, expected {expected}: {command!r}; see {log}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--oracle-only", action="store_true")
    parser.add_argument("--component-proof", action="store_true")
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
           if not key.startswith(("FRANKENLIBC_", "FLALIAS_", "NSS_SOURCE_"))
           and key not in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH")}
    env.update(LC_ALL="C", LD_LIBRARY_PATH=str(output))
    cc = shlex.split(os.environ.get("CC", "cc"))
    flags = ["-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror"]
    fixture = root / "tests/integration/fixture_nss_aliases.c"
    backend_source = root / "tests/integration/fixture_nss_aliases_module.c"
    probe = output / "nss-aliases-probe"
    backend = output / "libnss_flalias.so.2"
    qualification = ("GNU oracle only" if args.oracle_only else
                     "exact-source component differential" if args.component_proof else
                     "deployed ABI differential")
    report = {
        "qualification": qualification, "passed": False, "full_abi_qualified": False,
        "component_passed": False, "cases": [], "controls": [], "processes": 0,
        "candidate": str(candidate) if candidate else None,
        "candidate_sha256": digest(candidate) if candidate else None,
        "fixture_sha256": digest(fixture), "backend_source_sha256": digest(backend_source),
        "compatibility_notes": [
            "GNU cold non-reentrant buffer growth can skip oversized records. "
            "The non-reentrant differential warms buffer capacity and rewinds before recording; "
            "no recorded output, status, errno, or failure is normalized. "
            "A separate candidate-only cold-growth invariant requires every record."
        ],
    }
    if args.component_proof:
        report["component_scope"] = {
            "production": ["aliases parser and ABI", "NSS dispatch and configuration cache"],
            "adapters": ["host dynamic loader and errno", "hosted Rust TLS",
                         "secure environment passthrough", "unknown allocator provenance"],
            "excluded": ["complete ABI qualification", "allocator membrane", "owned TLS"],
        }
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
        empty_source = output / "dependency-only.c"
        empty_source.write_text("int aliases_dependency_only(void) { return 0; }\n")
        empty_dso = output / "dependency-only.so"
        run(cc + flags + ["-shared", "-fPIC", str(empty_source), "-Wl,--no-as-needed", "-lc",
                          "-o", str(empty_dso)], env, output / "build-dependency")
        run([str(probe), str(empty_dso), "lookup"], env, output / "reject-dependency", expected=91)
        report["controls"].append("dependency exports rejected")

        database = (
            b"# private aliases fixture\nfirst: alice, bob\n"
            b"folded: one\n  two,three # inline\n\tfour\n"
            b"included: before,:include:/etc/alias-members,after\n"
            b"empty:\nmissing-include: :include:/etc/no-such-alias-members\n"
            b"space   :  member  , other\r\n"
            + b"n" * 400 + b": long-name-member\n"
            + b"many: " + b",".join(f"member{index:03d}".encode() for index in range(80)) + b"\n"
            + b"large: " + b"v" * 5000 + b"\ntail: done\n"
        )
        datasets = {
            "records": database,
            "short": b"first: a\n",
            "empty": b"",
            "missing": None,
            "long-before-match": b"#" + b"c" * 100 + b"\nother: " + b"x" * 100 + b"\nfirst: a\n",
        }
        directories = {}
        for name, content in datasets.items():
            directory = output / f"etc-{name}"
            directory.mkdir()
            (directory / "nsswitch.conf").write_text("aliases: files\n")
            (directory / "alias-members").write_bytes(
                b"included-one, included-two  # comment\n  included-three\n"
                b":include:/etc/alias-members\n")
            if content is not None:
                (directory / "aliases").write_bytes(content)
            directories[name] = directory
        cases = [("records", "lookup", None), ("records", "enumeration", None)]
        cases += [(name, "bounds", None) for name in ("short", "empty", "missing", "long-before-match")]
        cases += [(name, "enumeration", None) for name in ("empty", "missing")]
        cases += [("short", "policy", policy) for policy in POLICIES]
        cases.append(("missing", "recovery", None))
        modes = ("component",) if args.component_proof else (args.mode or ("strict", "hardened"))

        def recovery_mount(tag):
            directory = output / f"{tag}-etc"
            directory.mkdir()
            (directory / "nsswitch.conf").write_text("aliases: files\n")
            return ["bwrap", "--ro-bind", "/", "/", "--bind", str(directory), "/etc"]

        for index, (dataset, scenario, policy) in enumerate(cases):
            label = f"{index:02d}-{dataset}-{scenario}"
            prefix = ["bwrap", "--ro-bind", "/", "/", "--ro-bind", str(directories[dataset]), "/etc"]
            if scenario == "recovery":
                prefix = recovery_mount(f"{label}-gnu")
            arguments = [scenario] + ([policy] if policy is not None else [])
            expected = run(prefix + [str(probe), "host"] + arguments, env, output / f"{label}-gnu")
            report["processes"] += 1
            lines = expected.splitlines()
            if len(lines) < (10 if scenario == "recovery" else 12):
                raise RuntimeError(f"vacuous GNU transcript: {label}")
            if dataset == "records" and scenario == "lookup":
                for required in ("count=80", "5000:", "6e" * 400, "count=6"):
                    if required not in expected:
                        raise RuntimeError(f"GNU records fixture missed {required[:40]!r}")
            if policy == "flalias" and "name=6d6f64756c652d686974" not in expected:
                raise RuntimeError("GNU did not execute the external aliases module")
            for mode in modes:
                dispatches = ("pinned",) if args.component_proof else ("pinned", "preload")
                for dispatch in dispatches if candidate else ("oracle",):
                    tag = f"{label}-{mode}-{dispatch}"
                    if candidate:
                        case_env = dict(env)
                        if mode != "component":
                            case_env["FRANKENLIBC_MODE"] = mode
                        candidate_prefix = recovery_mount(tag) if scenario == "recovery" else prefix
                        command = candidate_prefix + [str(probe), str(candidate)] + arguments
                        if dispatch == "preload":
                            command = candidate_prefix + ["--setenv", "LD_PRELOAD", str(candidate),
                                                          str(probe), str(candidate)] + arguments
                        actual = run(command, case_env, output / tag)
                        report["processes"] += 1
                        if actual != expected:
                            (output / f"{tag}.diff").write_text("".join(difflib.unified_diff(
                                expected.splitlines(True), actual.splitlines(True),
                                fromfile="GNU", tofile="candidate")))
                            raise RuntimeError(f"differential mismatch: {tag}")
                    report["cases"].append({
                        "dataset": dataset, "scenario": scenario, "policy": policy,
                        "mode": mode, "dispatch": dispatch, "observations": len(lines),
                        "transcript_sha256": hashlib.sha256(expected.encode()).hexdigest(),
                    })
                    print(f"PASS {tag}", flush=True)

        if candidate:
            for mode in modes:
                case_env = dict(env)
                if mode != "component":
                    case_env["FRANKENLIBC_MODE"] = mode
                # GNU uses a nonrecursive global alias lock. Only the candidate
                # executes this intentional callback reentry: it must return
                # EDEADLK to the nested call while completing the outer record.
                prefix = ["bwrap", "--ro-bind", "/", "/", "--ro-bind", str(directories["short"]), "/etc"]
                text = run(prefix + [str(probe), str(candidate), "reentry"], case_env,
                           output / f"reentry-{mode}")
                if "reentry nested-EDEADLK=1" not in text:
                    raise RuntimeError("recursive callback did not reach the candidate guard")
                report["processes"] += 1
                report["controls"].append(f"recursive enumeration returns EDEADLK: {mode}")
                # GNU can lose oversized records during its cold static-buffer
                # growth. The native implementation deliberately retains them;
                # assert this feature directly rather than copying that loss.
                prefix = ["bwrap", "--ro-bind", "/", "/", "--ro-bind", str(directories["records"]), "/etc"]
                text = run(prefix + [str(probe), str(candidate), "growing"], case_env,
                           output / f"growing-{mode}")
                if "growing entries=8 many=1 large=1 long-name=1" not in text:
                    raise RuntimeError("cold buffer growth lost an alias record")
                report["processes"] += 1
                report["controls"].append(f"cold buffer growth retains every oversized record: {mode}")
        report["passed"] = True
        report["full_abi_qualified"] = candidate is not None and not args.component_proof
        report["component_passed"] = args.component_proof
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
        print(f"FAIL: {error}", file=sys.stderr)
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["passed"]:
        print(f"PASS {qualification}: {len(report['cases'])} cases, {report['processes']} processes")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
