#!/usr/bin/env python3
"""Fleet-policy audit: how much of our claimed ground rests on a vs-incumbent
ratio measured with the incumbent LIVE IN THE SAME INVOCATION?

Fleet policy: a perf KEEP requires a vs-incumbent ratio. A self-speedup
(old-us vs new-us) is maintenance and must never be quoted competitively.

Three buckets, and the third is the one that matters most:
  SUPPORTED      same-invocation live-incumbent evidence present
  UNSUPPORTED    a glibc incumbent EXISTS for this surface, nobody measured it
  NO-ARM         no incumbent arm can exist (FrankenLibC-internal machinery),
                 so this is permanently maintenance, NOT a measurement backlog

Unsupported claims are then ranked by how load-bearing they are in public,
user-facing docs, because an unsupported claim a user might act on is worse
than an unsupported claim buried in a ledger.

Usage: python3 scripts/audit_incumbent_coverage.py [--queue N]
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "docs" / "NEGATIVE_EVIDENCE.md"

# Docs a user actually reads.
PUBLIC_DOCS = [
    "README.md", "COMPATIBILITY.md", "FEATURE_PARITY.md", "PARITY-COVERAGE.md",
    "DEPLOYMENT.md", "CHANGELOG.md", "docs/RELEASE_READINESS_SCORECARD.md",
]

# A claim we HOLD: the disposition says we are standing behind it. The negation
# guard matters -- "NOT SHIPPED", "INVALID" and "REJECTED" headings contain the
# token SHIPPED and would otherwise be counted as claimed ground we do not hold,
# inflating both the total and the backlog.
HELD = re.compile(r"\bWIN\b|\bKEEP\b|\bSHIPPED\b")
NOT_HELD = re.compile(
    r"NOT SHIPPED|\bINVALID\b|\bREJECTED?\b|\bRETRACTED\b|\bREFUTED\b|"
    r"\bWIN-PENDING\b|\bDISPROVEN\b|\bVOID\b", re.I)

# TIER A -- machine-checkable. The incumbent object is identified from INSIDE
# the measuring process, or the row carries a modern harness's structured
# fl-vs-glibc contract line. This is the only bar a tool can verify.
TIER_A = re.compile(
    r"INCUMBENT_OBJECT|INCUMBENT_LINKAGE|kind=fl_glibc|glibc_median_ns",
    re.I)
# TIER B -- human-checkable. Prose explicitly asserts the incumbent ran in the
# same invocation, but nothing in the row lets a tool confirm it.
TIER_B = re.compile(
    r"same[- ]invocation.{0,60}(incumbent|glibc)|"
    r"(incumbent|glibc).{0,60}same[- ]invocation",
    re.I | re.S)
# TIER C -- a glibc number is quoted, with no statement of how it was obtained.
TIER_C = re.compile(r"glibc", re.I)

# FrankenLibC-internal machinery: glibc has no such surface, so no incumbent
# arm can exist. Matched against the HEADING ONLY, on purpose. Matching the
# body over-collects badly: a row about `nl_langinfo` -- a real glibc symbol --
# mentions the membrane in passing and would be misfiled as unconvertible,
# which would flatter the number by shrinking the backlog.
NO_ARM = re.compile(
    r"PageOracle|MetricRing|SeqLock|BRAVO|\bEBR\b|bandit|approachability|"
    r"decide\(\)|observe\(\)|runtime_policy|elimination.backoff|"
    r"profile-state|proof.carrying|\bPCC\b|slab class|tombstone",
    re.I)

SYMBOL = re.compile(r"`([A-Za-z_][A-Za-z0-9_]{2,})")

# Generic tokens that are not libc symbols. Without this stoplist the ranking
# is garbage: a row about `fpclassify` also backticks `f64`, `f64` appears in
# README, and the row scores "named in README, a user could act on it" on the
# strength of a primitive type name. Measured 2026-07-31 -- the entire original
# top-of-queue was ranked by `f64`, `while`, and `free`, not by its own symbol.
STOP = set(
    """f32 f64 u8 u16 u32 u64 i8 i16 i32 i64 usize isize bool char str String Vec
    Option Result Some None true false let fn pub mut impl self crate use mod ref
    dyn box const static NaN IEEE SIMD AVX2 SSE glibc FrankenLibC release debug
    strict hardened test bench null while for if else return match loop struct
    enum trait type where""".split()
)

# A public doc is only load-bearing for a PERFORMANCE claim where it quotes a
# performance NUMBER next to the symbol. README lists `snprintf` under API
# surface and fuzz targets and quotes no per-symbol ratio anywhere; treating
# that as exposure ranks documentation breadth, not claim risk.
PERF_NUMBER = re.compile(r"[0-9]+(?:\.[0-9]+)?\s*(?:x\b|ns\b)")


def sections(lines):
    starts = [i for i, l in enumerate(lines) if l.startswith("## ")]
    starts.append(len(lines))
    for a, b in zip(starts, starts[1:]):
        yield a + 1, lines[a], "\n".join(lines[a:b])


def main():
    queue_n = 30
    if "--queue" in sys.argv:
        queue_n = int(sys.argv[sys.argv.index("--queue") + 1])

    public = {}
    for rel in PUBLIC_DOCS:
        p = ROOT / rel
        public[rel] = p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""

    public_lines = {rel: text.splitlines() for rel, text in public.items()}

    def exposure(head):
        """Rank a claim by whether a public doc quotes a performance NUMBER on
        the same line as one of the claim's own symbols."""
        syms = [s for s in SYMBOL.findall(head) if s not in STOP]
        score, where = 0, []
        for rel, doc_lines in public_lines.items():
            for s in syms:
                # Mere presence ranks docs by breadth: README lists most of
                # libc under API surface and fuzz targets while quoting no
                # per-symbol ratio at all.
                if any(
                    re.search(rf"\b{re.escape(s)}\b", line) and PERF_NUMBER.search(line)
                    for line in doc_lines
                ):
                    score = max(score, 3 if rel == "README.md" else 2)
                    if rel not in where:
                        where.append(rel)
                    break
        return score, syms[:3], where[:3]

    lines = LEDGER.read_text(encoding="utf-8").splitlines()
    tier_a, tier_b, tier_c, unsupported, no_arm = [], [], [], [], []
    # The conversion queue spans EVERY unconverted held claim, tier C included.
    # Ranking only the 13 tier-D1 rows hid the 202 tier-C rows, which are just
    # as unconverted -- they quote a glibc number of unstated provenance. That
    # omission is what put `fpclassify` at the head of the queue instead of
    # `snprintf`, the most-quoted symbol in the public scorecard.
    queue = []

    for line_no, head, body in sections(lines):
        if not HELD.search(head) or NOT_HELD.search(head):
            continue
        if TIER_A.search(body):
            tier_a.append((line_no, head))
            continue
        if TIER_B.search(body):
            tier_b.append((line_no, head))
            continue
        if NO_ARM.search(head):
            no_arm.append((line_no, head))
            continue
        score, syms, where = exposure(head)
        if TIER_C.search(body):
            tier_c.append((line_no, head))
            queue.append((score, line_no, head, syms, where, "C"))
        else:
            unsupported.append((score, line_no, head, syms, where))
            queue.append((score, line_no, head, syms, where, "D1"))

    total = (len(tier_a) + len(tier_b) + len(tier_c) + len(unsupported)
             + len(no_arm))
    pct = lambda n: f"{100*n/max(total,1):.1f}%"
    print("=" * 78)
    print("INCUMBENT COVERAGE OF HELD CLAIMS  (fleet policy: a KEEP needs a "
          "vs-incumbent ratio)")
    print("=" * 78)
    print(f"held claims total (WIN / KEEP / SHIPPED) ...... {total}")
    print(f"  A machine-checkable same-invocation incumbent {len(tier_a):>4}"
          f"   ({pct(len(tier_a))})")
    print(f"  B prose asserts same invocation, unverifiable {len(tier_b):>4}"
          f"   ({pct(len(tier_b))})")
    print(f"  C glibc number quoted, provenance unstated .. {len(tier_c):>4}"
          f"   ({pct(len(tier_c))})")
    print(f"  D no incumbent reference at all ............. "
          f"{len(unsupported)+len(no_arm):>4}"
          f"   ({pct(len(unsupported)+len(no_arm))})")
    print(f"      D1 convertible, incumbent exists ........ {len(unsupported):>4}")
    print(f"      D2 NO ARM POSSIBLE (internal machinery) . {len(no_arm):>4}")
    print()
    print(f"  CARRY A VS-INCUMBENT RATIO (A+B) ............ {len(tier_a)+len(tier_b):>4}"
          f"   ({pct(len(tier_a)+len(tier_b))})")
    print(f"  DO NOT (C+D) ................................ "
          f"{len(tier_c)+len(unsupported)+len(no_arm):>4}"
          f"   ({pct(len(tier_c)+len(unsupported)+len(no_arm))})")
    print()
    print(f"CONVERSION QUEUE ({len(queue)} unconverted: tier C + D1), ranked by "
          f"public-doc exposure (top {queue_n}):")
    print("  3 = the symbol appears beside a perf NUMBER in README.md | 2 = in "
          "another public doc | 0 = ledger-only")
    queue.sort(key=lambda r: (-r[0], r[1]))
    for score, line_no, head, syms, where, tier in queue[:queue_n]:
        title = head[3:].strip()
        title = title[:88] + ("..." if len(title) > 88 else "")
        print(f"  [{score}][{tier}] L{line_no:<6} {title}")
        if where:
            print(f"        quotes a perf number in: {', '.join(where)}  syms={syms}")
    print()
    print(f"NO-ARM group ({len(no_arm)}) — permanently maintenance, not a backlog:")
    for line_no, head in no_arm[:12]:
        print(f"        L{line_no:<6} {head[3:100].strip()}")
    if len(no_arm) > 12:
        print(f"        ... and {len(no_arm)-12} more")


if __name__ == "__main__":
    main()
