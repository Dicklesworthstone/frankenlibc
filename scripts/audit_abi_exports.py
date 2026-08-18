#!/usr/bin/env python3
"""Gate: every C-ABI function FrankenLibC implements must actually be exported.

WHY THIS EXISTS. Thirteen libc functions were implemented in frankenlibc-abi and
never exported from the cdylib, because the definition lacked
`#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`. A program loading
FrankenLibC silently got glibc's version of each. `strchr` was among them, and it
has a shipped SIMD campaign whose wins could not reach a program through the
deployed object. Nothing in the suite asserted the export, which is why it
survived (bd-6xstqa).

WHAT IT CHECKS, and why it is per-NAME. A C symbol is exported if ANY definition
of that name exports it. Two shapes in this tree make the per-definition question
misleading:

  * `glibc_internal_abi::cfgetibaud` and friends are Rust-visible forwarders
    whose own comment says the public C symbol is exported once by `termios_abi`;
  * the `setjmp` family has one definition per `cfg(target_arch)` /
    `cfg(debug_assertions)` arm, and only some arms carry the attribute.

Flagging a definition that a sibling already exports is noise: it was 13 of the
first scan's 34 hits. Aggregating per name removes all 13.

VALIDATED AGAINST THE OBJECT, not against itself. On 2026-08-18 the built
`libfrankenlibc_abi.so` (sha256 05f8316f..., every row carrying `in_dynsym` as a
positive control, via `cargo run --example abi_disasm_probe`) was compared with
this scan's output: zero false positives and zero misses. Re-validate the same
way after changing the parser -- an earlier attempt to handle multi-line
attributes by bracket balance over-reached into the PREVIOUS function's
attributes and silently dropped `nexttoward{,f,l}` and the two `_Unwind_`
entries. For a gate, a false negative is worse than a false positive, so the
attribute walk below stays deliberately conservative.
"""

from __future__ import annotations

import re
import sys
import pathlib
from collections import defaultdict

SRC = pathlib.Path(__file__).resolve().parent.parent / "crates" / "frankenlibc-abi" / "src"
DEFINITION = re.compile(r'\s*pub (?:unsafe )?extern "C" fn (\w+)\s*[(<]')

# Deliberately internal: bench drivers and test hooks that are `extern "C"` for
# call-shape reasons and must NOT appear in the deployed ABI surface.
INTERNAL = {
    "bench_malloc_orig_strict_path",
    "bench_free_orig_strict_path",
    "bsearch_strict_slice_for_bench",
    "__frankenlibc_set_startup_host_delegate_for_tests",
}

# Known unexported implementations, tracked by bd-6xstqa. The gate fails on
# anything NEW; these are debt, not permission. Two of them are plausibly
# deliberate and want a decision rather than a patch:
#   _Unwind_RaiseException / _Unwind_Resume -- exporting hijacks unwinding
#   vfprintf                                -- risks recursion through fl printf
KNOWN_UNEXPORTED = {
    "_Unwind_RaiseException",
    "_Unwind_Resume",
    "cospi",
    "dprintf",
    "freopen",
    "nexttoward",
    "nexttowardf",
    "nexttowardl",
    "posix_spawn_file_actions_addclose",
    "vfprintf",
}


def exports(lines: list[str], index: int) -> bool:
    """Whether the definition at `index` carries an export attribute.

    Walks back over contiguous attribute, comment and blank lines only. See the
    module docstring for why this is not made cleverer.
    """
    j = index - 1
    while j >= 0:
        line = lines[j].strip()
        if line.startswith("#["):
            if "no_mangle" in line:
                return True
        elif line.startswith("//") or not line:
            pass
        else:
            break
        j -= 1
    return False


def scan() -> dict[str, list[tuple[str, int]]]:
    definitions: dict[str, list[tuple[str, int, bool]]] = defaultdict(list)
    for path in sorted(SRC.rglob("*.rs")):
        lines = path.read_text().splitlines()
        for index, line in enumerate(lines):
            match = DEFINITION.match(line)
            if match:
                definitions[match.group(1)].append(
                    (str(path), index + 1, exports(lines, index))
                )
    return {
        name: [(path, line) for path, line, _ in sites]
        for name, sites in definitions.items()
        if not any(exported for _, _, exported in sites)
    }


def main() -> int:
    at_risk = scan()
    unexpected = {n: s for n, s in at_risk.items() if n not in INTERNAL | KNOWN_UNEXPORTED}
    healed = sorted(KNOWN_UNEXPORTED - at_risk.keys())

    print(f"ABI_EXPORT_AUDIT names_at_risk={len(at_risk)} unexpected={len(unexpected)}")

    for name in sorted(unexpected):
        for path, line in unexpected[name]:
            rel = path.split("frankenlibc/")[-1]
            print(f"  UNEXPORTED {name} at {rel}:{line}")

    if healed:
        # Not a failure, but it must be said: a name that left the debt set
        # should leave the list too, or the set rots into a lie.
        print(f"  FIXED (drop from KNOWN_UNEXPORTED): {', '.join(healed)}")

    if unexpected:
        print(
            "FAIL: implemented C-ABI functions with no exporting definition. "
            "Add #[cfg_attr(not(debug_assertions), unsafe(no_mangle))], or add "
            "the name to INTERNAL with a reason. See bd-6xstqa."
        )
        return 1

    print("OK: every implemented C-ABI name has an exporting definition "
          "(or is tracked debt).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
