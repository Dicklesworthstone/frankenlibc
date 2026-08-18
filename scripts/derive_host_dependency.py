#!/usr/bin/env python3
"""Derive, per SYMBOL, whether a C-ABI entry point can reach the host libc.

WHY. `support_matrix.json` marks 1309 exported symbols `WrapsHostLibc`, and
`build.rs` refuses the `standalone` feature partly on that count — which is what
blocks the deployed configuration from building at all (bd-haor6r). But the file
carries `generated_at_utc = 2026-06-03`, nothing in the tree regenerates it, and
a module-granularity check already showed 715 of those 1309 live in modules whose
source cannot reach the host by any route. Module granularity is too coarse to
act on in either direction, so this derives the answer per symbol.

WHAT COUNTS AS REACHING THE HOST. Three routes, because using fewer silently
under-reports — the campaign already made that mistake once, when
`check_replacement_guard.sh` reported "0 call-throughs" while 182 `host_*()`
sites existed that its `libc::` pattern never matched:

  1. `libc::name(...)`      — the pattern the existing guard scans for;
  2. `host_something()`     — dlsym'd host accessors, e.g. host_resolve.rs;
  3. `extern "C" { fn f; }` — a declaration with no definition in this crate.
     Note route 3 is NOT automatically a host call: if FrankenLibC exports `f`
     itself, the declaration binds to fl in a release build. math_abi declares
     fegetround/feraiseexcept/feclearexcept/fetestexcept and all four are
     defined with no_mangle in fl's own fenv_abi.rs, so treating route 3 as a
     host dependency without that check would misreport 509 math symbols.

TRANSITIVITY. A wrapper that calls a private helper that calls the host is host
-dependent, so reachability propagates over intra-crate calls to a fixed point.

LIMITS, stated because the number is meant to be acted on. This is a textual
analysis, not a compiler: it resolves calls by bare name, so same-named functions
in different modules are conflated (over-approximating), and calls through
function pointers or trait dispatch are invisible (under-approximating). It
ignores `cfg`, so a host call live only in a debug build still counts. Treat the
output as a well-founded estimate that replaces a stale hand-maintained file,
not as proof about any single symbol.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "crates" / "frankenlibc-abi" / "src"

FN_DEF = re.compile(
    r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?'
    r'(?:extern\s+"C"\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)'
)
EXPORTED_FN = re.compile(r'^\s*pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)')
LIBC_CALL = re.compile(r'\blibc::([a-z_][a-z0-9_]*)\s*\(')
HOST_CALL = re.compile(r'\b(host_[a-z0-9_]+)\s*\(')
CALL = re.compile(r'\b([a-z_][a-z0-9_]*)\s*\(')
EXTERN_BLOCK = re.compile(r'^\s*(?:unsafe\s+)?extern\s+"C"\s*\{')
EXTERN_FN = re.compile(r'^\s*(?:pub\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)')


def function_bodies(text: str) -> dict[str, str]:
    """Map function name -> body text, by brace matching from the signature.

    Crude but adequate: braces inside string literals can skew a body's end, so
    a body may run long. That over-approximates reachability (more calls seen),
    which is the safe direction for a "can this reach the host" question.
    """
    lines = text.splitlines()
    bodies: dict[str, str] = {}
    for index, line in enumerate(lines):
        match = FN_DEF.match(line)
        if not match:
            continue
        depth = 0
        started = False
        collected: list[str] = []
        for probe in lines[index:]:
            depth += probe.count("{") - probe.count("}")
            collected.append(probe)
            if "{" in probe:
                started = True
            if started and depth <= 0:
                break
        bodies.setdefault(match.group(1), "\n".join(collected))
    return bodies


def externally_declared(text: str) -> set[str]:
    """Names declared in `extern "C" { ... }` blocks — no definition here."""
    names: set[str] = set()
    lines = text.splitlines()
    inside = False
    for line in lines:
        if EXTERN_BLOCK.match(line):
            inside = True
            continue
        if inside:
            if line.strip().startswith("}"):
                inside = False
                continue
            found = EXTERN_FN.match(line)
            if found:
                names.add(found.group(1))
    return names


def main() -> int:
    check_only = "--check" in sys.argv
    bodies: dict[str, str] = {}
    exported: set[str] = set()
    declared: set[str] = set()
    defined_c_abi: set[str] = set()

    for path in sorted(SRC.rglob("*.rs")):
        text = path.read_text()
        for name, body in function_bodies(text).items():
            bodies.setdefault(name, body)
        for line in text.splitlines():
            found = EXPORTED_FN.match(line)
            if found:
                exported.add(found.group(1))
                defined_c_abi.add(found.group(1))
        declared |= externally_declared(text)

    # Route 3 only counts when FrankenLibC does not define the symbol itself.
    host_externs = declared - defined_c_abi

    direct: set[str] = set()
    for name, body in bodies.items():
        if LIBC_CALL.search(body) or HOST_CALL.search(body):
            direct.add(name)
            continue
        if any(re.search(rf'\b{re.escape(ext)}\s*\(', body) for ext in host_externs):
            direct.add(name)

    # Propagate over intra-crate calls to a fixed point.
    callers: dict[str, set[str]] = defaultdict(set)
    for name, body in bodies.items():
        for callee in set(CALL.findall(body)):
            if callee in bodies and callee != name:
                callers[callee].add(name)

    reaching = set(direct)
    frontier = list(direct)
    while frontier:
        current = frontier.pop()
        for caller in callers.get(current, ()):
            if caller not in reaching:
                reaching.add(caller)
                frontier.append(caller)

    matrix_path = ROOT / "support_matrix.json"
    matrix = json.loads(matrix_path.read_text())
    wraps = [s for s in matrix["symbols"] if s["status"] == "WrapsHostLibc"]

    own_body = [s for s in wraps if s["symbol"] in direct]
    transitive = [s for s in wraps if s["symbol"] in reaching]

    print(f"HOST_DEP functions_analysed={len(bodies)} direct={len(direct)} "
          f"transitively_reaching={len(reaching)}")
    print(f"HOST_DEP host_extern_decls={len(host_externs)} "
          f"exported_c_abi={len(exported)}")
    print()
    print(f"matrix marks WrapsHostLibc:                       {len(wraps)}")
    print(f"  ...of which the symbol's OWN body calls a host: {len(own_body)}")
    print(f"  ...of which the transitive closure reaches one: {len(transitive)}")
    print()
    print("READ THESE AS DIFFERENT QUESTIONS, not as competing estimates.")
    print("  own body   -- 'this wrapper delegates its operation to the host',")
    print("                which is what the taxonomy's WrapsHostLibc means.")
    print("  transitive -- 'control flow can reach a host call at all'. It is")
    print("                near-useless here: every ABI entry point calls the")
    print("                membrane/policy layer, which touches the host")
    print("                somewhere, so the closure covers "
          f"{len(reaching)} of {len(bodies)} functions.")
    print("                Shared infrastructure swamps the signal.")

    # Control: the same test applied to symbols the matrix calls Implemented.
    # If `own body` fired indiscriminately this would be large too.
    implemented = [
        s for s in matrix["symbols"]
        if s["status"] == "Implemented" and s["symbol"] in direct
    ]
    print(f"\nCONTROL Implemented-with-direct-host-call={len(implemented)} "
          f"(large would mean the test fires indiscriminately)")

    by_module: dict[str, int] = defaultdict(int)
    for symbol in own_body:
        by_module[symbol["module"]] += 1
    print("\ndirect host delegation by module:")
    for module, count in sorted(by_module.items(), key=lambda kv: -kv[1])[:12]:
        print(f"    {module:26s} {count:5d}")

    if not check_only:
        return 0

    # --check FAILS ON ONE DIRECTION ONLY, deliberately.
    #
    # A symbol marked Implemented -- "no host libc dependency" -- that calls the
    # host is the dangerous error: `Implemented` is NOT in build.rs's forbidden
    # set, so it passes the standalone gate silently and a standalone artifact
    # ships believing the symbol is host-free.
    #
    # The opposite error (WrapsHostLibc on a symbol that no longer touches the
    # host) is merely over-strict: it blocks a build that might work, which is
    # visible and annoying rather than silent. There are ~1252 of those, tracked
    # as debt on bd-haor6r, and failing on them would just make this check red
    # forever and therefore ignored.
    print()
    for symbol in implemented:
        print(f"  UNDERSTATED {symbol['symbol']} in {symbol['module']} "
              f"is marked Implemented but calls the host directly")
    if implemented:
        print(
            f"FAIL: {len(implemented)} symbol(s) claim no host dependency while "
            "calling the host. Either fix the implementation or correct the "
            "status in support_matrix.json. See bd-haor6r."
        )
        return 1
    print(f"OK: no symbol marked Implemented calls the host directly "
          f"({len(own_body)} WrapsHostLibc rows do, as expected).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
