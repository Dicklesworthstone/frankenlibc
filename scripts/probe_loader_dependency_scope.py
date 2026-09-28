#!/usr/bin/env python3
"""Build real ELF dependency graphs and probe the selected host dynamic loader.

The result is reference evidence, NOT execution of the Rust implementation.
All generated files are kept under --output-dir for inspection.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess


def run(args: list[str], cwd: Path) -> str:
    # The reference must not accidentally run under the candidate interposer
    # or resolve a fixture name through an ambient library search path.
    reference_env = os.environ.copy()
    for name in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"):
        reference_env.pop(name, None)
    result = subprocess.run(args, cwd=cwd, env=reference_env,
                            text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"{args!r} failed ({result.returncode})\n{result.stdout}\n{result.stderr}")
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    args = parser.parse_args()
    if not shutil.which(args.cc):
        raise SystemExit(f"C compiler not found: {args.cc}")
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sources = {
        "leaf.c": "int provider(void) { return 111; }\n",
        "left.c": "int left_anchor(void) { return 1; }\n",
        "right.c": "int provider(void) { return 222; }\n",
        "root.c": "int root_anchor(void) { return 1; }\n",
        "a.c": """extern int b_value(void);
extern void record_event(char);
__attribute__((constructor)) static void init(void) { record_event('A'); }
__attribute__((destructor)) static void fini(void) { record_event('a'); }
int a_marker(void) { return 7; }
int cycle_value(void) { return 10 + b_value(); }
""",
        "b.c": """extern int a_marker(void);
extern void record_event(char);
__attribute__((constructor)) static void init(void) { record_event('B'); }
__attribute__((destructor)) static void fini(void) { record_event('b'); }
int b_value(void) { return 32; }
int cycle_from_b(void) { return a_marker(); }
""",
        "probe.c": r'''#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char events[32];
static size_t event_count;
void record_event(char event) {
    if (event_count >= sizeof events - 1) { abort(); }
    events[event_count++] = event;
}
static void *open_checked(const char *path) {
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "%s: %s\n", path, dlerror()); exit(1); }
    return handle;
}
static int invoke(void *handle, const char *name) {
    dlerror();
    void *address = dlsym(handle, name);
    const char *error = dlerror();
    if (error || !address) {
        fprintf(stderr, "%s: %s\n", name, error ? error : "null symbol"); exit(1);
    }
    int (*function)(void);
    _Static_assert(sizeof function == sizeof address, "POSIX function pointer size");
    memcpy(&function, &address, sizeof function);
    return function();
}
int main(void) {
    void *root = open_checked("./libroot.so");
    int provider = invoke(root, "provider");
    if (provider != 222) { fprintf(stderr, "provider=%d, wanted direct dependency 222\n", provider); return 1; }
    if (dlclose(root) != 0) { return 1; }
    void *cycle = open_checked("./liba.so");
    int value = invoke(cycle, "cycle_value");
    int from_b = invoke(cycle, "cycle_from_b");
    if (value != 42 || from_b != 7) { return 1; }
    if (event_count != 2 || !strchr(events, 'A') || !strchr(events, 'B')) { return 1; }
    if (dlclose(cycle) != 0) { return 1; }
    if (event_count != 4 || !strchr(events + 2, 'a') || !strchr(events + 2, 'b')) { return 1; }
    printf("{\"breadth_first_provider\":%d,\"cycle_value\":%d,\"cycle_from_b\":%d,\"cycle_lifecycle\":\"%s\"}\n", provider, value, from_b, events);
    return 0;
}
''',
    }
    for name, text in sources.items():
        (out / name).write_text(text)

    def dso(name: str, source: str, dependencies: tuple[str, ...] = ()) -> None:
        run([args.cc, "-shared", "-fPIC", "-nostdlib", "-Wall", "-Wextra", "-Werror",
             f"-Wl,-soname,lib{name}.so", "-Wl,-rpath,$ORIGIN", source,
             "-L.", "-Wl,--no-as-needed", *[f"-l{dep}" for dep in dependencies],
             "-o", f"lib{name}.so"], out)

    dso("leaf", "leaf.c")
    dso("left", "left.c", ("leaf",))
    dso("right", "right.c")
    dso("root", "root.c", ("left", "right"))
    dso("b", "b.c")  # Bootstrap the second vertex, then close the dependency loop.
    dso("a", "a.c", ("b",))
    dso("b", "b.c", ("a",))
    run([args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "probe.c",
         "-Wl,--export-dynamic", "-ldl", "-o", "probe"], out)
    report = json.loads(run([str(out / "probe")], out))
    report["evidence_kind"] = "host_loader_oracle_only"
    report["cc"] = run([args.cc, "--version"], out).splitlines()[0]
    if shutil.which("getconf"):
        report["libc"] = run(["getconf", "GNU_LIBC_VERSION"], out).strip()
    if shutil.which("readelf"):
        for name in ("root", "left", "a", "b"):
            text = run(["readelf", "--dynamic", f"lib{name}.so"], out)
            (out / f"lib{name}.dynamic.txt").write_text(text)
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
