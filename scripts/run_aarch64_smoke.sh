#!/bin/bash
# bd-rc0923-epic-eeuy4f.41: execute the linked library, never a static host proxy.
# The release build is separate; all generated sources, binaries and logs remain.
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
    printf '{"status":"blocked","reason":"python3_missing","processes_executed":0}\n'
    exit 2
fi
exec python3 - "$0" "$@" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import time

ROOT = Path(sys.argv[1]).resolve().parent.parent
MODE = sys.argv[2] if len(sys.argv) == 3 else "run" if len(sys.argv) == 2 else "invalid"
ARTIFACT = Path(os.environ.get("FRANKENLIBC_AARCH64_ARTIFACT",
                              ROOT / "target/aarch64-unknown-linux-gnu/release/libfrankenlibc_abi.so"))
REQUIRED = ("malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset",
            "strlen", "strcmp", "printf", "snprintf", "__memcpy_chk", "__errno_location",
            "pthread_create", "pthread_join",
            "getpid", "pipe", "read", "write", "close", "setjmp", "_setjmp",
            "__sigsetjmp", "longjmp", "siglongjmp", "__longjmp_chk")

def emit(status, **fields):
    print(json.dumps(dict(status=status, gate="bd-gq1kz7.12", **fields), indent=2))

if MODE == "contract":
    emit("contract", contract={
        "runner_types": ["qemu-aarch64", "qemu-aarch64-static", "native"],
        "environment": {
            "FRANKENLIBC_AARCH64_ARTIFACT": "Explicit linked AArch64 library",
            "FRANKENLIBC_AARCH64_CC": "Compiler argv; default native cc or aarch64-linux-gnu-gcc",
            "FRANKENLIBC_AARCH64_OUT_DIR": "Fresh output directory; existing evidence is preserved",
            "QEMU_TIMEOUT": "Per-process timeout in seconds (default: 60)",
            "QEMU_SYSROOT": "AArch64 glibc sysroot (default: /usr/aarch64-linux-gnu)",
        },
        "artifact": "target/aarch64-unknown-linux-gnu/release/libfrankenlibc_abi.so",
        "preflight_checks": ["artifact_exists", "aarch64_shared_elf", "required_exports",
                             "compiler_available", "runner_available", "sysroot_exists"],
        "smoke_tests": list(REQUIRED) + ["constructor", "thread_tls", "setjmp_edges"],
        "runtime_modes": ["strict", "hardened"],
        "timeout_behavior": "Nonzero failure; retain stdout, stderr and timed_out",
        "failure_evidence": "JSON command/exit, library/probe hashes, providers and executed cases",
        "scope": "L0 interposition correctness; not standalone or ARM hardware performance",
    })
    sys.exit(0)
if MODE not in ("run", "preflight"):
    emit("blocked", reason="usage", usage="run_aarch64_smoke.sh {run|preflight|contract}",
         processes_executed=0)
    sys.exit(2)

def elf_header(path):
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("not_elf64_little_endian")
    kind, machine = struct.unpack_from("<HH", data, 16)
    if machine != 183:
        raise ValueError("wrong_architecture")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if size < 56 or count == 0 or offset + size * count > len(data):
        raise ValueError("invalid_program_headers")
    interpreter = any(struct.unpack_from("<I", data, offset + i * size)[0] == 3
                      for i in range(count))
    return kind, interpreter

try:
    if not ARTIFACT.is_file():
        raise ValueError("artifact_missing")
    ARTIFACT = ARTIFACT.resolve(strict=True)
    if any(c.isspace() or c == ':' for c in str(ARTIFACT)):
        raise ValueError("artifact_path_not_representable_in_ld_preload")
    if elf_header(ARTIFACT) != (3, False):
        raise ValueError("artifact_not_shared_library")
    timeout = float(os.environ.get("QEMU_TIMEOUT", "60"))
    if not 0 < timeout <= 600:
        raise ValueError("invalid_timeout")
    native = platform.system() == "Linux" and platform.machine() in ("aarch64", "arm64")
    compiler = shlex.split(os.environ.get("FRANKENLIBC_AARCH64_CC",
                                         "cc" if native else "aarch64-linux-gnu-gcc"))
    if not compiler or not shutil.which(compiler[0]):
        raise ValueError("compiler_missing")
    readelf = shutil.which("aarch64-linux-gnu-readelf") or shutil.which("readelf")
    if not readelf:
        raise ValueError("readelf_missing")
    runner = []
    if not native:
        qemu = shutil.which("qemu-aarch64") or shutil.which("qemu-aarch64-static")
        sysroot = Path(os.environ.get("QEMU_SYSROOT", "/usr/aarch64-linux-gnu"))
        if not qemu:
            raise ValueError("qemu_missing")
        if not (sysroot / "lib/ld-linux-aarch64.so.1").is_file():
            raise ValueError("sysroot_missing")
        runner = [qemu, "-L", str(sysroot)]
    symbols = subprocess.run([readelf, "--dyn-syms", "--wide", str(ARTIFACT)],
                             capture_output=True, text=True, timeout=timeout)
    if symbols.returncode:
        raise ValueError("export_inspection_failed: " + symbols.stderr)
    exported = {row.split()[-1].split("@")[0] for row in symbols.stdout.splitlines()
                if len(row.split()) >= 8 and row.split()[6] != "UND"}
    missing = sorted(set(REQUIRED) - exported)
    if missing:
        raise ValueError("missing_exports: " + ",".join(missing))
except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
    emit("blocked", reason=str(exc), artifact=str(ARTIFACT), processes_executed=0)
    sys.exit(2)

if MODE == "preflight":
    emit("ready", artifact=str(ARTIFACT), runner=runner or ["native"],
         required_exports=len(REQUIRED), processes_executed=0)
    sys.exit(0)

SOURCE = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void *__memcpy_chk(void *, const void *, size_t, size_t);
extern void __longjmp_chk(jmp_buf, int) __attribute__((noreturn));

static int constructed;
static __thread int tls_value = 7;
static int *parent_errno;
static unsigned checks, providers;

__attribute__((constructor)) static void before_main(void) {
    char *p = malloc(32);
    if (!p) return;
    memset(p, 'x', 31); p[31] = 0;
    constructed = strlen(p) == 31;
    free(p);
}

static int check(int condition, const char *name) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        return 0;
    }
    checks++;
    return 1;
}

static int provider(const char *name, void *binding, const char *expected) {
    void *address = dlsym(RTLD_DEFAULT, name);
    Dl_info info;
    char actual[PATH_MAX];
    /* Check the executable's binding as well as RTLD_DEFAULT. A versioned
     * call must not slip through to glibc while dlsym finds our default. */
    if (!address || address != binding || !dladdr(binding, &info) || !info.dli_fname ||
        !realpath(info.dli_fname, actual) || strcmp(actual, expected)) {
        fprintf(stderr, "FAIL: wrong/missing provider: %s\n", name);
        return 0;
    }
    providers++;
    return 1;
}

static void *thread_body(void *unused) {
    (void)unused;
    if (tls_value != 7 || __errno_location() == parent_errno) return (void *)1;
    tls_value = 41; errno = EDOM;
    char *p = calloc(8, 1);
    if (!p) return (void *)2;
    int ok = p[0] == 0 && p[7] == 0 && tls_value == 41 && errno == EDOM;
    free(p);
    return ok ? NULL : (void *)3;
}

int main(void) {
    const char *expected = getenv("FRANKENLIBC_EXPECT_LIBRARY");
    const char *mode = getenv("FRANKENLIBC_MODE");
    char canonical[PATH_MAX];
    if (!expected || !realpath(expected, canonical) || !mode ||
        (strcmp(mode, "strict") && strcmp(mode, "hardened"))) return 2;
#define BOUND(function) { #function, (void *)&function }
    const struct { const char *name; void *binding; } functions[] = {
        BOUND(malloc), BOUND(calloc), BOUND(realloc), BOUND(free),
        BOUND(memcpy), BOUND(memmove), BOUND(memset), BOUND(strlen), BOUND(strcmp),
        BOUND(printf), BOUND(snprintf), BOUND(__memcpy_chk), BOUND(__errno_location),
        BOUND(pthread_create), BOUND(pthread_join), BOUND(getpid), BOUND(pipe),
        BOUND(read), BOUND(write), BOUND(close), BOUND(setjmp), BOUND(_setjmp),
        BOUND(__sigsetjmp), BOUND(longjmp), BOUND(siglongjmp), BOUND(__longjmp_chk)
    };
#undef BOUND
    for (size_t i = 0; i < sizeof functions / sizeof functions[0]; i++)
        if (!provider(functions[i].name, functions[i].binding, canonical)) return 3;
    if (!check(constructed, "constructor allocation/string")) return 4;
    char *p = malloc(64);
    if (!check(p != NULL, "malloc")) return 4;
    memset(p, 'A', 63); p[63] = 0;
    if (!check(strlen(p) == 63, "memset/strlen")) return 4;
    p = realloc(p, 128);
    if (!check(p != NULL && p[0] == 'A' && p[62] == 'A', "realloc preservation")) return 4;
    char copy[128];
    memcpy(copy, p, 64);
    memmove(copy + 1, copy, 64);
    if (!check(copy[1] == 'A' && copy[64] == 0, "copy/overlap")) return 4;
    free(p);
    char *zero = calloc(32, 1);
    if (!check(zero != NULL, "calloc")) return 4;
    for (size_t i = 0; i < 32; i++)
        if (!check(zero[i] == 0, "calloc zero")) return 4;
    free(zero);
    void *(*checked_copy)(void *, const void *, size_t, size_t) =
        (void *(*)(void *, const void *, size_t, size_t))dlsym(RTLD_DEFAULT, "__memcpy_chk");
    if (!check(checked_copy(copy, "fortify", 8, sizeof copy) == copy &&
               strcmp(copy, "fortify") == 0, "FORTIFY valid copy")) return 4;
    char formatted[32];
    if (!check(snprintf(formatted, sizeof formatted, "%s:%d", "arm", 64) == 6 &&
               strcmp(formatted, "arm:64") == 0, "snprintf")) return 4;
    int fds[2]; char byte = 0;
    if (!check(getpid() > 0 && pipe(fds) == 0, "pid/pipe")) return 4;
    if (!check(write(fds[1], "Z", 1) == 1 && read(fds[0], &byte, 1) == 1 &&
               byte == 'Z', "raw IO")) return 4;
    if (!check(close(fds[0]) == 0 && close(fds[1]) == 0, "close")) return 4;
    errno = 0;
    if (!check(read(-1, &byte, 1) == -1 && errno == EBADF, "syscall errno")) return 4;
    parent_errno = __errno_location(); errno = ERANGE; tls_value = 19;
    pthread_t thread; void *result = (void *)4;
    if (!check(pthread_create(&thread, NULL, thread_body, NULL) == 0 &&
               pthread_join(thread, &result) == 0 && result == NULL &&
               tls_value == 19 && errno == ERANGE, "thread/TLS/errno isolation")) return 4;
    jmp_buf jump;
    volatile int value = setjmp(jump);
    if (value == 0) longjmp(jump, 9);
    if (!check(value == 9, "setjmp/longjmp")) return 4;
    sigjmp_buf signal_jump;
    volatile int signal_value = sigsetjmp(signal_jump, 1);
    if (signal_value == 0) siglongjmp(signal_jump, 11);
    if (!check(signal_value == 11, "sigsetjmp/siglongjmp")) return 4;
    void (*checked_jump)(jmp_buf, int) =
        (void (*)(jmp_buf, int))dlsym(RTLD_DEFAULT, "__longjmp_chk");
    volatile int checked_value = setjmp(jump);
    if (checked_value == 0) checked_jump(jump, 13);
    if (!check(checked_value == 13, "FORTIFY longjmp")) return 4;
    printf("{\"status\":\"pass\",\"mode\":\"%s\",\"architecture\":\"aarch64\","
           "\"providers\":%u,\"checks\":%u}\n", mode, providers, checks);
    return 0;
}
'''

out = Path(os.environ.get("FRANKENLIBC_AARCH64_OUT_DIR",
                          ROOT / "target/conformance/aarch64-smoke" /
                          (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + str(os.getpid()))))
try:
    out.mkdir(parents=True, exist_ok=False)
except OSError as exc:
    emit("blocked", reason="fresh_output_directory_required: " + str(exc), processes_executed=0)
    sys.exit(2)
out = out.resolve()
source, binary = out / "smoke.c", out / "smoke"
source.write_text(SOURCE)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
rows = []
library_hash = hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()
edges_source = ROOT / "tests/integration/fixture_setjmp_edges.c"
edges_hash = hashlib.sha256(edges_source.read_bytes()).hexdigest()

def run(name, command, environment=None):
    env = os.environ.copy()
    for key in ("LD_PRELOAD", "LD_AUDIT"):
        env.pop(key, None)
    if environment:
        env.update(environment)
    row = dict(name=name, command=command, exit_code=None, timed_out=False)
    try:
        process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, errors="replace",
                                   start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            row["timed_out"] = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # It exited between the deadline and the group kill.
            stdout, stderr = process.communicate()
        row.update(exit_code=process.returncode, stdout=stdout, stderr=stderr)
    except OSError as exc:
        row.update(stdout="", stderr=str(exc))
    for stream in ("stdout", "stderr"):
        (out / (name + "." + stream)).write_text(row[stream])
    rows.append(row)
    return row

compile_row = run("compile", compiler + ["-std=c11", "-O2", "-fno-builtin", "-Wall",
                                      "-Wextra", "-Werror", "-fPIE", "-pie", "-pthread", str(source),
                                      "-ldl", "-o", str(binary)])
failures = []
if compile_row["timed_out"] or compile_row["exit_code"] != 0:
    failures.append("compile_failed")
else:
    try:
        if not elf_header(binary)[1]:
            raise ValueError("static_probe_rejected")
    except (OSError, ValueError) as exc:
        failures.append(str(exc))

def probe_command(mode, preload, program=binary):
    values = {"FRANKENLIBC_MODE": mode, "FRANKENLIBC_EXPECT_LIBRARY": str(ARTIFACT)}
    if preload:
        values["LD_PRELOAD"] = str(ARTIFACT)
    if runner:
        command = list(runner)
        for key, value in values.items():
            command.extend(["-E", key + "=" + value])
        return command + [str(program)], {}
    return [str(program)], values

if not failures:
    for mode in ("strict", "hardened"):
        command, env = probe_command(mode, True)
        row = run(mode, command, env)
        try:
            observed = json.loads(row["stdout"])
            valid = (not row["timed_out"] and row["exit_code"] == 0 and
                     observed["status"] == "pass" and
                     observed["mode"] == mode and observed["architecture"] == "aarch64" and
                     observed["providers"] == len(REQUIRED) and observed["checks"] == 48)
        except (ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            failures.append(mode + "_runtime_failed")
        command, env = probe_command(mode, False)
        negative = run(mode + "-no-preload", command, env)
        if (negative["timed_out"] or negative["exit_code"] != 3 or
                "wrong/missing provider" not in negative["stderr"]):
            failures.append(mode + "_provider_negative_failed")
    edges = out / "setjmp_edges"
    row = run("compile-setjmp", compiler + ["-O2", "-fno-builtin", "-Wall", "-Wextra",
                                          "-Werror", "-fPIE", "-pie", str(edges_source),
                                          "-o", str(edges)])
    if row["timed_out"] or row["exit_code"] != 0:
        failures.append("setjmp_compile_failed")
    else:
        try:
            if not elf_header(edges)[1]:
                raise ValueError("static_setjmp_probe_rejected")
        except (OSError, ValueError) as exc:
            failures.append(str(exc))
        else:
            for mode in ("strict", "hardened"):
                command, env = probe_command(mode, True, edges)
                row = run(mode + "-setjmp-edges", command, env)
                if row["timed_out"] or row["exit_code"] != 0 or row["stdout"].strip() != (
                        "fixture_setjmp_edges: PASS (longjmp0->1 sigsetjmp->siglongjmp)"):
                    failures.append(mode + "_setjmp_edges_failed")
if hashlib.sha256(ARTIFACT.read_bytes()).hexdigest() != library_hash:
    failures.append("artifact_changed_during_run")
if hashlib.sha256(edges_source.read_bytes()).hexdigest() != edges_hash:
    failures.append("setjmp_source_changed_during_run")
report = dict(status="fail" if failures else "pass", gate="bd-gq1kz7.12",
              artifact=str(ARTIFACT), library_sha256=library_hash,
              probe_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
              setjmp_source_sha256=edges_hash,
              runner=runner or ["native"], rows=rows, failures=failures,
              processes_executed=sum(not row["name"].startswith("compile") for row in rows),
              process_count_scope="Top-level probe invocations; fixture fork children are additional",
              scope="L0 interposition correctness; not standalone or hardware performance")
(out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(dict(report, output_dir=str(out)), indent=2))
sys.exit(1 if failures else 0)
PY
