#!/usr/bin/env python3
"""Compare native descriptor, socket, sleep and signal cancellation with GNU libc."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time


POLL_CASES = tuple(
    f"{entry}-{case}"
    for entry in ("poll", "ppoll")
    for case in (
        "pending", "blocked", "disabled", "signal", "signal-restart", "ready",
        "reuse", "empty-blocked",
    )
) + (
    "ppoll-mask-unblock", "ppoll-mask-block", "ppoll-mask-cancel", "ppoll-mask-cancel-block",
    "ppoll-readonly-timeout",
    "ppoll-alias-blocked", "ppoll-alias-pending",
)
EPOLL_CASES = tuple(
    f"{entry}-{case}"
    for entry in ("epoll-wait", "epoll-pwait", "epoll-pwait2")
    for case in (
        "pending", "blocked", "disabled", "signal", "signal-restart", "ready",
        "reuse", "empty-blocked", "timeout", "ready-late", "edge-ready", "errors",
    )
) + tuple(
    f"{entry}-{case}"
    for entry in ("epoll-pwait", "epoll-pwait2")
    for case in ("mask-unblock", "mask-block", "mask-cancel", "mask-cancel-block")
) + (
    "epoll-pwait2-readonly-timeout",
    "epoll-wait-alias-blocked", "epoll-wait-alias-pending",
    "epoll-pwait-alias-blocked", "epoll-pwait-alias-pending",
)
SLEEP_CASES = tuple(
    f"sleep-{entry}-{case}"
    for entry in ("nano", "clock", "absolute", "seconds", "micro", "c11")
    for case in (
        "pending", "blocked", "disabled", "signal", "signal-restart", "timeout",
        "mask-block", "zero",
    )
) + tuple(
    f"sleep-{entry}-{case}"
    for entry in ("nano", "clock", "absolute", "c11")
    for case in (
        "readonly-request", "unaligned-request", "remainder", "alias-remainder",
        "readonly-remainder", "errors",
    )
) + tuple(
    f"sleep-{entry}-alias-{case}"
    for entry in ("nano", "clock")
    for case in ("pending", "blocked")
)
SELECT_CASES = tuple(
    f"{entry}-{case}"
    for entry in ("select", "pselect")
    for case in (
        "pending", "blocked", "disabled", "signal", "signal-restart", "ready",
        "reuse", "empty-blocked", "timeout", "ready-late", "remainder", "errors",
        "alias-pending", "alias-blocked",
    )
) + (
    "pselect-mask-unblock", "pselect-mask-block", "pselect-mask-cancel",
    "pselect-mask-cancel-block", "pselect-readonly-timeout",
)
SUSPEND_CASES = tuple(
    f"{entry}-{case}"
    for entry in ("pause", "sigsuspend")
    for case in (
        "pending", "blocked", "disabled", "signal", "signal-restart", "mask-block",
        "alias-pending", "alias-blocked",
    )
) + (
    "sigsuspend-mask-unblock", "sigsuspend-mask-cancel", "sigsuspend-mask-cancel-block",
    "sigsuspend-errors", "sigsuspend-guarded-mask",
)
RECEIVE_CASES = tuple(
    f"{entry}-{case}"
    for entry in ("recv", "recvfrom")
    for case in (
        "blocked", "pending", "disabled", "ready", "ready-late", "peek",
        "nonblock", "dontwait", "timeout", "signal", "signal-restart", "competing", "errors",
        "length-zero",
    )
) + (
    "recv-waitall", "recv-lowat", "recv-eof", "recvfrom-zero", "recvfrom-truncate",
    "recv-alias-blocked", "recv-alias-pending",
    "recv-fortified-blocked", "recv-fortified-pending",
    "recvfrom-fortified-blocked", "recvfrom-fortified-pending",
) + tuple(
    f"recvmsg-{case}"
    for case in (
        "blocked", "pending", "disabled", "ready", "ready-late", "peek",
        "nonblock", "dontwait", "timeout", "signal", "signal-restart", "competing", "errors",
        "length-zero", "waitall", "lowat", "eof", "alias-blocked", "alias-pending",
        "datagram-blocked", "datagram-pending", "datagram-ready-late", "datagram-zero",
        "datagram-truncate", "rights", "rights-cloexec", "control-truncate",
        "mapped-blocked", "mapped-pending", "mapped-ready-late",
    )
)
SEND_CASES = tuple(
    f"{entry}-{case}"
    for entry in ("send", "sendto")
    for case in (
        "blocked", "pending", "disabled", "ready", "ready-late", "nonblock", "dontwait",
        "timeout", "signal", "signal-restart", "errors", "length-zero", "peer-closed", "seqpacket",
    )
) + (
    "send-partial", "send-partial-error", "sendto-address", "sendto-oversize",
    "send-alias-blocked", "send-alias-pending",
    "sendto-alias-blocked", "sendto-alias-pending",
)
# GNU 2.41 preserves a send prefix when cancellation arrives after progress.
# The hosted bridge still uses its documented asynchronous window; validate
# this stronger contract for the native adapter in the GNU 2.41 socket job.
SEND_NATIVE_CASES = ("send-partial-cancel",)

# Suspension cleanup follows the GNU 2.41 oracle in its dedicated CI job.
# Keep the existing descriptor/sleep gate on its established GNU baseline.
CASES = POLL_CASES + EPOLL_CASES + SLEEP_CASES + SELECT_CASES + RECEIVE_CASES + SEND_CASES


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if not __debug__:
        raise RuntimeError("the cancellation runner requires Python assertions to be enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--host-only", action="store_true",
        help="Run only the GNU oracle; report no candidate validation.",
    )
    parser.add_argument(
        "--suspend-only", action="store_true",
        help="Run only pause/sigsuspend cases and the provider/backend negative controls.",
    )
    parser.add_argument(
        "--receive-only", action="store_true",
        help="Run only socket receive cases and the provider/backend negative controls.",
    )
    parser.add_argument(
        "--send-only", action="store_true",
        help="Run socket send cases against GNU 2.41, including native partial cancellation.",
    )
    args = parser.parse_args()
    if sum((args.suspend_only, args.receive_only, args.send_only)) > 1:
        parser.error("--suspend-only, --receive-only and --send-only are mutually exclusive")
    if not args.host_only and args.library is None:
        parser.error("--library is required unless --host-only is selected")
    root = Path(__file__).resolve().parents[1]
    cases = (SUSPEND_CASES if args.suspend_only else RECEIVE_CASES if args.receive_only else
             SEND_CASES + SEND_NATIVE_CASES if args.send_only else CASES)
    native_only_cases = SEND_NATIVE_CASES if args.send_only else ()
    candidate_cases = 0 if args.host_only else 4 * len(cases) - 2 * len(native_only_cases)
    source = root / "tests/integration/fixture_pthread_native_poll.c"
    library = args.library.resolve(strict=True) if args.library is not None else None
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    binary = out / "fixture_pthread_native_poll"
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith("FRANKENLIBC_") and key not in ("LD_PRELOAD", "LD_AUDIT")
    }
    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=c11", "-O2", "-fno-builtin", "-fno-exceptions", "-Wall", "-Wextra", "-Werror",
        str(source), "-o", str(binary), "-pthread", "-ldl",
    ]
    compiled = subprocess.run(command, env=env, capture_output=True, timeout=60)
    (out / "compile.stdout").write_bytes(compiled.stdout)
    (out / "compile.stderr").write_bytes(compiled.stderr)
    if compiled.returncode:
        print(compiled.stderr.decode(errors="replace"), file=sys.stderr)
        return 1
    linked = subprocess.run(["ldd", str(binary)], env=env, capture_output=True, text=True, timeout=10)
    (out / "ldd.txt").write_text(linked.stdout + linked.stderr)
    match = re.search(r"^\s*libc\.so\.6\s+=>\s+(\S+)", linked.stdout, re.MULTILINE)
    if linked.returncode or match is None:
        raise RuntimeError("cannot identify the GNU libc provider of the fixture")
    host = Path(match.group(1)).resolve(strict=True)
    revision = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], env=env,
        capture_output=True, text=True, timeout=10,
    )
    rows: list[dict] = []

    def execute(label: str, case: str, provider: Path, run_env: dict,
                expected_code: int = 0, expected_error: str = "") -> dict:
        started = time.monotonic()
        try:
            run = subprocess.run(
                [str(binary), case, str(provider)], env=run_env,
                capture_output=True, timeout=12, start_new_session=True,
            )
            code, stdout, stderr = run.returncode, run.stdout, run.stderr
        except subprocess.TimeoutExpired as error:
            code = 124
            stdout, stderr = error.stdout or b"", error.stderr or b""
            stderr += b"fixture exceeded the 12-second subprocess deadline\n"
        (out / f"{label}.stdout").write_bytes(stdout)
        (out / f"{label}.stderr").write_bytes(stderr)
        expected_output = f"pthread-native-poll:{case}:PASS\n" if expected_code == 0 else ""
        skipped = code == 77 and stdout == f"pthread-native-poll:{case}:SKIP\n".encode()
        passed = (
            code == expected_code and stdout == expected_output.encode()
            and stderr == expected_error.encode()
        )
        status = "PASS" if passed else "SKIP" if skipped else "FAIL"
        row = {
            "label": label, "case": case, "status": status, "returncode": code,
            "seconds": round(time.monotonic() - started, 6),
            "stdout": f"{label}.stdout", "stderr": f"{label}.stderr",
        }
        if skipped:
            row["reason"] = stderr.decode(errors="replace").strip()
        rows.append(row)
        print(f"{status} {label}", flush=True)
        if not passed:
            print(stderr.decode(errors="replace")[-4000:], file=sys.stderr, flush=True)
        return row

    for case in cases:
        # GNU need not export our reserved alias. The candidate must provide
        # and pin the exact alias; its oracle exercises the public contract.
        oracle = case.replace("ppoll-alias-", "ppoll-").replace(
            "epoll-wait-alias-", "epoll-wait-"
        ).replace("epoll-pwait-alias-", "epoll-pwait-").replace(
            "pselect-alias-", "pselect-"
        ).replace("select-alias-", "select-").replace(
            "recv-alias-", "recv-"
        ).replace("recvmsg-alias-", "recvmsg-").replace(
            "send-alias-", "send-"
        ).replace("sendto-alias-", "sendto-").replace(
            "pause-alias-", "pause-"
        ).replace("sigsuspend-alias-", "sigsuspend-")
        if "-alias-" in case and not case.endswith("-alias-remainder"):
            oracle = oracle.replace("sleep-nano-alias-", "sleep-nano-").replace(
                "sleep-clock-alias-", "sleep-clock-"
            )
        execute(f"host-{case}", oracle, host, env)
        if not args.host_only:
            assert library is not None
            for mode in ("strict", "hardened"):
                for native in (("1",) if case in native_only_cases else ("0", "1")):
                    execute(
                        f"{mode}-native{native}-{case}", case, library,
                        dict(env, LD_PRELOAD=str(library), FRANKENLIBC_MODE=mode,
                             FRANKENLIBC_THREAD_NATIVE=native, FRANKENLIBC_RUNTIME_MATH="off"),
                    )

    # Deliberately omit preload while asking for the candidate provider. A
    # host-only probe uses the executable inode, which cannot provide pthreads.
    wrong_provider = binary if args.host_only else library
    assert wrong_provider is not None
    execute(
        "provider-negative", "poll-blocked", wrong_provider, env, 86,
        "pthread-native-poll:provider-mismatch:pthread_create\n",
    )
    execute(
        "backend-negative", "poll-blocked", host,
        dict(env, FRANKENLIBC_THREAD_NATIVE="1"), 1,
        "pthread-native-poll:poll-blocked:FAIL:"
        "thread backend does not match inherited/native or hosted TP\n",
    )

    expected_rows = len(cases) + candidate_cases + 2
    assert len(rows) == expected_rows
    failures = [row["label"] for row in rows if row["status"] != "PASS"]
    report = {
        "schema_version": 2,
        "validation_scope": "GNU oracle only" if args.host_only else "GNU and deployed candidate ABI",
        "case_scope": "pause/sigsuspend only" if args.suspend_only else
                      "socket receives only" if args.receive_only else
                      "socket sends only" if args.send_only else "poll/epoll/sleep/select/socket",
        "revision": revision.stdout.strip() if revision.returncode == 0 else None,
        "fixture_sha256": digest(source), "runner_sha256": digest(Path(__file__)),
        "binary_sha256": digest(binary), "library_sha256": digest(library) if library else None,
        "gnu_provider": str(host), "gnu_provider_sha256": digest(host),
        "compiler_command": command, "case_count": len(cases),
        "poll_cases": 0 if args.suspend_only or args.receive_only or args.send_only else len(POLL_CASES),
        "epoll_cases": 0 if args.suspend_only or args.receive_only or args.send_only else len(EPOLL_CASES),
        "sleep_cases": 0 if args.suspend_only or args.receive_only or args.send_only else len(SLEEP_CASES),
        "select_cases": 0 if args.suspend_only or args.receive_only or args.send_only else len(SELECT_CASES),
        "suspend_cases": len(SUSPEND_CASES) if args.suspend_only else 0,
        "receive_cases": 0 if args.suspend_only or args.send_only else len(RECEIVE_CASES),
        "send_cases": 0 if args.suspend_only or args.receive_only else
                      len(SEND_CASES) + len(native_only_cases),
        "native_only_cases": list(native_only_cases),
        "oracle_cases": len(cases), "candidate_cases": candidate_cases,
        "provider_negatives": 1, "backend_negatives": 1,
        "explicit_skips": [row["label"] for row in rows if row["status"] == "SKIP"],
        "failures": failures, "results": rows,
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        print("Required poll/select/epoll/sleep/suspend/socket coverage failed or was unavailable: " + ", ".join(failures), file=sys.stderr)
        return 1
    candidate = "no candidate validation" if args.host_only else f"{candidate_cases} candidate cases"
    print(f"Native poll/select/epoll/sleep/suspend/socket: {len(cases)} GNU oracle cases, {candidate}, 2 negative controls passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
