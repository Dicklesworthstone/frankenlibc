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

# Runtime resolution, in any of the forms this suite actually uses.
#
# `\bdlsym\b` ALONE IS WRONG and silently under-reports. `_` is a word character,
# so that pattern does not match `dlsym_oracle::host_fn(..)` -- the shared helper
# most converted gates now call. Left uncorrected it reports every gate using the
# helper as having no host arm at all, which manufactured a 99-gate "finding" that
# included gates converted the same day. Match the helper's entry points by name
# as well as the raw libc calls.
RUNTIME_RESOLVE = re.compile(
    r'\bdl(?:v)?sym\b|\bdlsym_oracle\b|\bhost_fn\b|\bhost_addr\b'
)

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


# A gate may reach the host by spawning something instead of calling it. Rare,
# but a subprocess oracle IS a host arm and must not be reported as absent.
SUBPROCESS_ORACLE = re.compile(r"\bCommand::new\b|\bstd::process::Command\b")

# `libc::foo(..)` -- a CALL, not a type or constant, so `libc::c_int` and
# `libc::EINVAL` are excluded by requiring the open paren.
#
# THIS IS A LINK-TIME ARM AND CARRIES THE SAME CAPTURE RISK as a hand-written
# `extern "C"` block. The `libc` crate declares these as ordinary `extern "C"`
# imports, so the linker resolves them exactly the same way, and fl exporting the
# same symbol into the test binary can satisfy them. A reviewer reading
# `libc::strchr(..)` sees "the libc crate", which reads as "definitely the host" --
# it is not; it is a declaration like any other.
#
# Discovered while checking a `--no-host-arm` result by hand: `conformance_diff_strchr`
# and `_memcpy` were reported as having NO host arm, yet both plainly compare
# against glibc -- through `libc::strchr` and `libc::memcpy`. Two detector bugs in
# one scan is the reason this file now states its mechanisms explicitly instead of
# pattern-matching for the word "dlsym".
LIBC_CRATE_CALL = re.compile(r"\blibc::(\w+)\s*\(")


def has_any_host_arm(path: pathlib.Path) -> tuple[bool, str]:
    """Does this gate reach host glibc AT ALL, by any mechanism?

    Returns (has_arm, mechanism).

    WHY THIS IS A SEPARATE QUESTION from the link-time audit above. That audit
    asks "is this file's declared oracle reliable?" and can only see files that
    declare one. A gate that declares NOTHING is invisible to it -- and three such
    gates were found by hand: `conformance_diff_strftime_oor_names`,
    `_strptime_ampm_yday` and `_strptime_field_backoff`. All three are named
    `conformance_diff_*`, all three claim parity with glibc in their headers, two
    have test names ending in `_matches_glibc`, and none of them ever called
    glibc. Their expected values were, per their own headers, "golden values
    captured from a gcc strptime oracle": read off glibc once, offline, and frozen
    into literals.

    Frozen literals are not equivalent to an oracle, because glibc moves. glibc
    2.42 rewrote `ecvt`/`fcvt` to shortest-representation and broke four gates in
    this suite. Worse, some pinned behaviour is UNSPECIFIED -- what `strftime`
    does with a `tm_wday` of 99 is a glibc implementation detail, exactly the kind
    of thing a release may retune -- so the literal records what one glibc did
    once, while the test name promises ongoing parity.

    A golden-value test is legitimate. What is not legitimate is a golden-value
    test WEARING A DIFFERENTIAL NAME, because a reader auditing coverage counts it
    as a live comparison. This function finds them.
    """
    src = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
    if RUNTIME_RESOLVE.search(src):
        return True, "dlsym"
    if SUBPROCESS_ORACLE.search(src):
        return True, "subprocess"
    for block in EXTERN_BLOCK.findall(src):
        for link_name, rust_name in DECL.findall(block):
            symbol = link_name or rust_name
            if symbol not in INFRASTRUCTURE:
                return True, "link-time"
    if any(s not in INFRASTRUCTURE for s in LIBC_CRATE_CALL.findall(src)):
        return True, "libc-crate"
    return False, "NONE"


def libc_crate_arms(path: pathlib.Path, exports: set[str]) -> set[str]:
    """`libc::foo(..)` calls where fl also exports `foo`.

    Same capture risk as a hand-written extern block, and invisible to the
    link-time audit above, so the AT RISK totals it reports UNDERCOUNT by
    whatever this finds.
    """
    src = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
    return {
        s
        for s in LIBC_CRATE_CALL.findall(src)
        if s in exports and s not in INFRASTRUCTURE
    }


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
    parser.add_argument(
        "--libc-calls",
        action="store_true",
        help="gates reaching the host through `libc::foo(..)` where fl also "
        "exports foo — a link-time arm with the same capture risk as an extern "
        "block, which the AT RISK scan does not inspect",
    )
    parser.add_argument(
        "--no-host-arm",
        action="store_true",
        help="gates that never reach glibc by ANY mechanism — no dlsym, no "
        "subprocess, no non-infrastructure link-time declaration. These are "
        "golden-value tests wearing a differential name, and the link-time "
        "audit is structurally blind to them",
    )
    args = parser.parse_args()

    if args.libc_calls:
        # `exports` is computed further down, after the early-exit modes; this
        # mode needs it, so resolve it here rather than reordering main().
        exports = fl_exported_symbols()
        if not exports:
            print("REFUSING: found no fl exports to compare against.", file=sys.stderr)
            return 0
        gates = sorted(TESTS.glob("conformance_diff_*.rs"))
        rows = [(p, libc_crate_arms(p, exports)) for p in gates]
        rows = [(p, syms) for p, syms in rows if syms]
        total = sum(len(s) for _, s in rows)
        print(f"gates scanned: {len(gates)}")
        print(
            f"LIBC-CRATE ARM  {len(rows)} gates / {total} symbols — reach the host "
            f"via `libc::foo(..)` on a symbol fl also exports. Same link-time "
            f"capture risk as an extern block; NOT counted in the AT RISK total."
        )
        for p, syms in rows:
            print(f"    {p.name}: {', '.join(sorted(syms))}")
        return 0

    if args.no_host_arm:
        gates = sorted(TESTS.glob("conformance_diff_*.rs"))
        missing = [p for p in gates if not has_any_host_arm(p)[0]]
        print(f"gates scanned: {len(gates)}")
        print(
            f"NO HOST ARM  {len(missing)} gates — named conformance_diff_*, but no "
            f"dlsym, no subprocess and no link-time host declaration anywhere in "
            f"the file. Each compares fl against frozen literals only."
        )
        for p in missing:
            src = p.read_text(encoding="utf-8", errors="replace")
            # Surface the tell: a test name promising parity it never measures.
            promises = sorted(
                set(re.findall(r"fn\s+(\w*(?:matches|parity|vs)_?\w*glibc\w*)\s*\(", src))
            )
            note = f"   [test name claims parity: {', '.join(promises)}]" if promises else ""
            print(f"    {p.name}{note}")
        return 0

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
