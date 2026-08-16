#!/usr/bin/env python3
"""Find differential gates whose "host glibc" arm may not reach host glibc.

WHY THIS EXISTS (bd-v0388t). A gate in this suite compares FrankenLibC against
the host by calling fl through a Rust path and glibc through an `extern "C"`
declaration. That second arm is an oracle only if the reference binds to
libc.so.6. fl exports the same symbols into the same test binary, so the linker
may satisfy the declaration locally -- and then BOTH arms are fl and every
assertion in the gate passes while proving nothing. The suite stays green
precisely because it has stopped testing.

That is measured, not hypothetical. Of the first nine gates audited by hand, two
were affected:

  conformance_diff_fma      vacuous: 40,000+ random triples plus engineered
                            double-rounding cases, all comparing fl to fl.
  conformance_diff_catopen  vacuous AND concealing a live defect: catopen("")
                            set errno 22 (EINVAL) where glibc sets 2 (ENOENT).
                            Both implementations failed the call, so ONLY the
                            errno differed -- which is what a caller branches on,
                            and exactly what a hollow arm cannot see.

WHAT THE SCRIPT LOOKS FOR, and why naming is not enough. Three disguises have
been found so far, all of which defeat a reviewer auditing by name:

  host_ prefix   `#[link_name="alphasort"] fn host_alphasort(..)`
                 reads as host-resolved; is not.
  rename         `#[link_name="__loc_aton"] fn loc_aton(..)`
                 Rust name differs from the symbol.
  abbreviation   `#[link_name="cfsetbaud"] fn h_setbaud(..)`
                 name says nothing either way.

One file even carried a comment asserting it "linked directly against libc.so.6"
-- which is what the declaration intends, not what it guarantees. So this script
deliberately ignores names and comments and reports on MECHANISM: the linked
symbol, whether fl exports it, and whether the file resolves anything at runtime.

WHAT A CLEAN GATE LOOKS LIKE. Resolve the host arm with `dlsym` on an explicit
`libc.so.6`/`libm.so.6` handle -- `dlvsym` for compat-only symbols (bd-86hcwh) --
and assert the resolved address is NOT fl's own function address. That is correct
in every build profile and turns the remaining doubt into a failing test.

EXIT STATUS: 0 always. This reports; it does not gate. Wiring it into CI as a
hard gate would need the allowlist below to be complete first.

USAGE
    python3 scripts/audit_oracle_arms.py             # summary + per-file detail
    python3 scripts/audit_oracle_arms.py --summary   # counts only
    python3 scripts/audit_oracle_arms.py --symbols   # flat symbol list, for xargs
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
TESTS = REPO / "crates" / "frankenlibc-abi" / "tests"
SRC = REPO / "crates" / "frankenlibc-abi" / "src"

# `pub extern "C" fn foo(` / `pub unsafe extern "C" fn foo(` -- fl's C entry points.
FL_EXPORT = re.compile(r'^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+([A-Za-z0-9_]+)', re.M)

# A whole `unsafe extern "C" { ... }` block, non-greedy to the first closing brace
# at column zero. Test files declare these at module level, so that is sufficient
# and avoids needing a brace matcher.
EXTERN_BLOCK = re.compile(r'(?:unsafe\s+)?extern\s+"C"\s*\{(.*?)\n\}', re.S)

# Inside a block: an optional #[link_name="sym"] immediately preceding `fn name(`.
# When link_name is present it is the symbol that gets linked; otherwise the Rust
# name is. Capturing both is what lets the report show the disguise.
DECL = re.compile(
    r'(?:#\[link_name\s*=\s*"([A-Za-z0-9_]+)"\]\s*)?'
    r'(?:pub\s+)?(?:unsafe\s+)?fn\s+([A-Za-z0-9_]+)\s*\(',
    re.S,
)

RUNTIME_RESOLVE = re.compile(r'\bdl(?:v)?sym\b')

# Symbols that are NOT fl-vs-glibc oracles even when declared at link time:
# test infrastructure and loader plumbing. Listed explicitly so the report does
# not cry wolf, and so additions are a deliberate edit rather than a silent
# heuristic.
INFRASTRUCTURE = {
    "dlopen", "dlsym", "dlvsym", "dlclose", "dladdr", "dlerror",
    "fork", "waitpid", "_exit", "raise", "abort", "kill",
    "__errno_location", "pipe", "close", "read", "write", "unlink",
    "mkstemp", "signal", "sigaction", "sigprocmask", "sigemptyset",
    "sigaddset", "sigismember", "feclearexcept", "fetestexcept",
}


def fl_exported_symbols() -> set[str]:
    """Every C entry point fl defines, across the ABI crate."""
    names: set[str] = set()
    for path in sorted(SRC.glob("*.rs")):
        names.update(FL_EXPORT.findall(path.read_text(encoding="utf-8", errors="replace")))
    return names


def strip_comments(src: str) -> str:
    """Remove Rust comments before any pattern matching.

    NOT cosmetic. Without this the scan counts PROSE as a declaration: a gate
    that has been correctly converted to dlsym typically documents what it
    replaced, e.g.

        /// A link-time `unsafe extern "C" { fn memccpy(..) }` is not reliably
        /// glibc in an abi test binary...

    and `EXTERN_BLOCK` matches that sentence. The effect is perverse -- the
    better a conversion is documented, the more certain the tool is that it did
    not happen -- so converted gates never leave the at-risk list and the
    burn-down cannot converge. Confirmed on conformance_diff_memccpy and
    conformance_diff_fma, both of which resolve their oracle with dlsym and were
    still reported as at risk.

    Block comments are removed first, then line comments. String literals are
    left alone: a `//` inside a string would be dropped by a naive pass, but no
    declaration is expressed inside a string literal, so the only risk is
    over-stripping prose, which is what we want gone anyway.
    """
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def audit_file(path: pathlib.Path, exports: set[str]) -> tuple[list[tuple[str, str]], bool]:
    """Return ([(linked_symbol, rust_name)], file_resolves_at_runtime)."""
    src = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
    resolves = bool(RUNTIME_RESOLVE.search(src))
    at_risk: list[tuple[str, str]] = []
    for block in EXTERN_BLOCK.findall(src):
        for link_name, rust_name in DECL.findall(block):
            symbol = link_name or rust_name
            if symbol in INFRASTRUCTURE:
                continue
            if symbol in exports:
                at_risk.append((symbol, rust_name))
    return at_risk, resolves


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", action="store_true", help="counts only")
    parser.add_argument("--symbols", action="store_true", help="flat symbol list")
    parser.add_argument(
        "--review",
        action="store_true",
        help="only the REVIEW gates: files that resolve SOMETHING at runtime and "
        "still declare an fl-exported symbol at link time",
    )
    args = parser.parse_args()

    exports = fl_exported_symbols()
    if not exports:
        print("REFUSING: found no fl exports to compare against — the pattern that "
              "locates them has probably drifted, and an empty set would report "
              "every gate as clean.", file=sys.stderr)
        return 0

    findings: list[tuple[pathlib.Path, list[tuple[str, str]], bool]] = []
    for path in sorted(TESTS.glob("conformance_diff_*.rs")):
        at_risk, resolves = audit_file(path, exports)
        if at_risk:
            findings.append((path, at_risk, resolves))

    unresolved = [f for f in findings if not f[2]]
    mixed = [f for f in findings if f[2]]
    total_syms = sum(len(f[1]) for f in unresolved)

    if args.symbols:
        for _, at_risk, _ in unresolved:
            for symbol, _rust in at_risk:
                print(symbol)
        return 0

    print(f"fl C entry points found: {len(exports)}")
    print(f"gates scanned: {len(list(TESTS.glob('conformance_diff_*.rs')))}")
    print()
    print(f"AT RISK  {len(unresolved)} gates / {total_syms} symbols "
          f"— link-time arm on an fl-exported symbol, NO dlsym anywhere in the file")
    print(f"REVIEW   {len(mixed)} gates — link-time arm on an fl-exported symbol, "
          f"but the file does resolve something at runtime; check which arm is which")

    if args.review:
        # The REVIEW set deserves its own view because it is the easiest to skip.
        # A file with no dlsym at least LOOKS unconverted. A file with some dlsym
        # signals diligence and invites the reviewer to stop reading -- while a
        # different arm in the same file is still link-bound. That is the same
        # trap as a `host_` prefix, one level up, and it is the category a scan
        # that skips any file containing "dlsym" cannot see at all.
        for path, at_risk, _ in mixed:
            print(f"\n{path.name}")
            for symbol, rust in at_risk:
                disguise = "" if symbol == rust else f"   (declared as `{rust}`)"
                print(f"    {symbol}{disguise}")
        return 0

    if args.summary:
        return 0

    for header, group in (("AT RISK", unresolved), ("REVIEW", mixed)):
        if not group:
            continue
        print(f"\n=== {header} ===")
        for path, at_risk, _ in group:
            print(f"\n{path.name}")
            for symbol, rust in at_risk:
                # Showing both names is the point: the gap between them IS the
                # disguise, and it is what a name-based audit misses.
                disguise = "" if symbol == rust else f"   (declared as `{rust}`)"
                print(f"    {symbol}{disguise}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
