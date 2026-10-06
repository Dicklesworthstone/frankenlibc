#!/usr/bin/env python3
"""Run host-oracle cases against the host C probe; no external libraries/network."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

def execute(command, **kwargs):
    completed = subprocess.run(command, capture_output=True, text=True, timeout=20, **kwargs)
    if completed.returncode:
        raise RuntimeError(f"{command!r}: {completed.returncode}\n{completed.stdout}\n{completed.stderr}")
    return completed

def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"Usage: {sys.argv[0]} /absolute/path/to/host-probe")
    probe = Path(sys.argv[1]).resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="frankenlibc-candidate-oracle-"))
    bad, good = root / "bad", root / "good"
    bad.mkdir()
    good.mkdir()
    provider, consumer = root / "provider.c", root / "consumer.c"
    provider.write_text("int candidate_value(void) { return 73; }\n")
    consumer.write_text("extern int candidate_value(void);\nint candidate_entry(void) { return candidate_value() + 1; }\n")
    cc = os.environ.get("CC", "cc")
    soname = "libfrankenlibc_candidate_probe.so"
    execute([cc, "-shared", "-fPIC", "-nostdlib", str(provider), f"-Wl,-soname,{soname}", "-o", str(good / soname)])
    native = (good / soname).read_bytes()
    assert native[:7] == b"\x7fELF\x02\x01\x01"
    foreign = 183 if int.from_bytes(native[18:20], "little") == 62 else 62
    def changed(offset, value):
        output = bytearray(native)
        output[offset:offset + len(value)] = value
        return output
    cases = [
        ("wrong-class", changed(4, b"\x01"), True),
        ("wrong-machine", changed(18, foreign.to_bytes(2, "little")), True),
        ("bad-magic", changed(0, b"\0"), False),
        ("bad-version", changed(20, (2).to_bytes(4, "little")), False),
        ("short-header", native[:63], False),
        ("native", native, True),
    ]
    invocations = 0
    for search in ["runpath", "rpath", "environment"]:
        parent = root / f"parent-{search}.so"
        extra = []
        if search != "environment":
            extra += ["-Wl,-rpath,$ORIGIN/bad:$ORIGIN/good",
                      "-Wl,--disable-new-dtags" if search == "rpath" else "-Wl,--enable-new-dtags"]
        execute([cc, "-shared", "-fPIC", "-nostdlib", str(consumer), f"-L{good}", f"-l:{soname}", *extra, "-o", str(parent)])
        for case, contents, succeeds in cases:
            (bad / soname).write_bytes(contents)
            env = dict(os.environ)
            env.pop("LD_LIBRARY_PATH", None)
            env.pop("LD_PRELOAD", None)
            if search == "environment":
                env["LD_LIBRARY_PATH"] = f"{bad}:{good}"
            result = execute([str(probe), str(parent), "success" if succeeds else "failure"], env=env)
            print(f"PASS {search}/{case}: {result.stdout.strip()}", flush=True)
            invocations += 1
    (bad / soname).write_bytes(native)
    env = dict(os.environ)
    env.pop("LD_LIBRARY_PATH", None)
    env.pop("LD_PRELOAD", None)
    result = execute([str(probe), str(root / "parent-runpath.so"), "success", "resident"], env=env)
    print(f"PASS resident-inode: {result.stdout.strip()}", flush=True)
    invocations += 1
    assert invocations == 19
    print(f"host-glibc candidate search: {invocations} passed; fixtures {root}")

if __name__ == "__main__":
    main()
