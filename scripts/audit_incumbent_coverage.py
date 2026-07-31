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

    lines = LEDGER.read_text(encoding="utf-8").splitlines()
    tier_a, tier_b, tier_c, unsupported, no_arm = [], [], [], [], []

    for line_no, head, body in sections(lines):
        if not HELD.search(head) or NOT_HELD.search(head):
            continue
        if TIER_A.search(body):
            tier_a.append((line_no, head))
        elif TIER_B.search(body):
            tier_b.append((line_no, head))
        elif NO_ARM.search(head):
            no_arm.append((line_no, head))
        elif TIER_C.search(body):
            tier_c.append((line_no, head))
        else:
            syms = SYMBOL.findall(head)
            score, where = 0, []
            for rel, text in public.items():
                for s in syms:
                    if s and re.search(rf"\b{re.escape(s)}\b", text):
                        weight = 3 if rel == "README.md" else 2
                        score = max(score, weight)
                        if rel not in where:
                            where.append(rel)
                        break
            unsupported.append((score, line_no, head, syms[:3], where[:3]))

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
    print(f"CONVERSION QUEUE, ranked by public-doc exposure (top {queue_n}):")
    print("  3 = named in README.md, a user could act on it | 2 = other public "
          "doc | 0 = ledger-only")
    unsupported.sort(key=lambda r: (-r[0], r[1]))
    for score, line_no, head, syms, where in unsupported[:queue_n]:
        title = head[3:].strip()
        title = title[:94] + ("..." if len(title) > 94 else "")
        print(f"  [{score}] L{line_no:<6} {title}")
        if where:
            print(f"        exposed in: {', '.join(where)}  syms={syms}")
    print()
    print(f"NO-ARM group ({len(no_arm)}) — permanently maintenance, not a backlog:")
    for line_no, head in no_arm[:12]:
        print(f"        L{line_no:<6} {head[3:100].strip()}")
    if len(no_arm) > 12:
        print(f"        ... and {len(no_arm)-12} more")


if __name__ == "__main__":
    main()
