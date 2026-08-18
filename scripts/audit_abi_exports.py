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

# Defined by a global_asm! trampoline AND compiled only under
# `standalone,owned-unwind-stub` (lib.rs gates the whole owned_unwind_abi
# module). Their absence from a default-feature object is the module not being
# compiled, NOT a missing export -- the module doc says they are "intentionally
# gated". I first recorded these as debt with the reasoning "exporting them
# hijacks unwinding", which was wrong: nothing is being withheld, the code is
# simply not in the build.
FEATURE_GATED = {
    "_Unwind_RaiseException",
    "_Unwind_Resume",
}

# Known unexported implementations, tracked by bd-6xstqa. The gate fails on
# anything NEW; these are debt, not permission.
KNOWN_UNEXPORTED: set[str] = set()


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


# A `.global NAME` inside a global_asm! block does NOT export NAME from a
# cdylib. Established by controlled experiment: build a cdylib whose only
# definitions are a #[no_mangle] Rust fn and a global_asm! block declaring
# `.global`, and the asm symbol lands in .symtab as lowercase `t` -- local --
# and never in .dynsym, whether or not anything references it. Referencing only
# decides survival; an unreferenced block is dropped entirely (--gc-sections at
# section granularity).
#
# The working pattern for an asm-implemented C entry point is the one x86_64
# setjmp uses (setjmp_abi.rs:260): a #[unsafe(naked)] #[unsafe(no_mangle)]
# extern "C" fn whose body is naked_asm!. That exports by attribute.
#
# Blocks gated to another target_arch are skipped -- they are not compiled here,
# so their symbols are not expected in this object.
ASM_GLOBAL = re.compile(r'"\.global\s+([A-Za-z_][A-Za-z0-9_]*)"')
OTHER_ARCH = re.compile(r'target_arch\s*=\s*"(?!x86_64)')


def asm_declared_globals(path: pathlib.Path) -> list[tuple[str, int]]:
    """Names declared `.global` in a global_asm! block compiled for x86_64."""
    lines = path.read_text().splitlines()
    found: list[tuple[str, int]] = []
    inside = False
    gated_elsewhere = False
    for index, line in enumerate(lines):
        if "global_asm!(" in line:
            inside = True
            # Look back over the attribute block for a foreign target_arch gate.
            gated_elsewhere = any(
                OTHER_ARCH.search(lines[back])
                for back in range(max(0, index - 4), index)
                if lines[back].strip().startswith("#[")
            )
            continue
        if inside:
            if line.strip() == ");":
                inside = False
                continue
            if not gated_elsewhere:
                match = ASM_GLOBAL.search(line)
                if match:
                    found.append((match.group(1), index + 1))
    return found


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

    # Names that exist ONLY as an asm `.global` are unexported for a different
    # reason and need a different fix, so they are reported separately rather
    # than folded into the same list.
    asm_only: dict[str, tuple[str, int]] = {}
    for path in sorted(SRC.rglob("*.rs")):
        for name, line in asm_declared_globals(path):
            if name not in FEATURE_GATED:
                asm_only.setdefault(name, (str(path), line))
    unexpected = {n: s for n, s in at_risk.items() if n not in INTERNAL | KNOWN_UNEXPORTED | FEATURE_GATED}
    healed = sorted(KNOWN_UNEXPORTED - at_risk.keys())

    print(
        f"ABI_EXPORT_AUDIT names_at_risk={len(at_risk)} unexpected={len(unexpected)} "
        f"asm_only={len(asm_only)}"
    )

    for name in sorted(unexpected):
        for path, line in unexpected[name]:
            rel = path.split("frankenlibc/")[-1]
            print(f"  UNEXPORTED {name} at {rel}:{line}")

    # Only a name with NO exporting definition anywhere is a problem. A symbol
    # declared `.global` in a test-only asm block while a naked #[no_mangle] fn
    # exports it in release is correct, not asm-only -- that is exactly the shape
    # the nexttoward* fix produced, and flagging it would make the gate red on
    # the very change that fixed it.
    unexpected_asm = {
        n: w for n, w in asm_only.items() if n in at_risk and n not in KNOWN_UNEXPORTED
    }
    for name in sorted(unexpected_asm):
        path, line = unexpected_asm[name]
        rel = path.split("frankenlibc/")[-1]
        print(
            f"  ASM_ONLY {name} at {rel}:{line} -- a global_asm! `.global` is "
            f"LOCAL in a cdylib; use #[unsafe(naked)] #[unsafe(no_mangle)] instead"
        )

    if healed:
        # Not a failure, but it must be said: a name that left the debt set
        # should leave the list too, or the set rots into a lie.
        print(f"  FIXED (drop from KNOWN_UNEXPORTED): {', '.join(healed)}")

    if unexpected or unexpected_asm:
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
