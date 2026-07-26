#!/usr/bin/env python3
"""Perf-ledger integrity gate — institutionalises the frankenfs taxonomy.

Ledger integrity DECAYS. The fleet's 2026-07-26 finding: repos that audited once and
then enforced the check mechanically sit at ~1.7% void; repos that audited once and
banked the wins drift back to 25-91%. So this is not a one-time cleanup script — it is
the thing that stops the void population regrowing.

Two modes, both cheap and offline (no build, no worker):

  preflight  Before you touch source for a perf lever, ask whether the ledger already
             covers it. Exit 2 = BLOCKED (a sound prior rejection exists). Exit 0 with
             a RESURRECTION notice = only void rows cover it, so it is re-attackable.

  lint       Refuse a NEW reject row that records neither an A/A null control nor a
             counted mechanism. This is the rule that makes the dominant void class
             (VOID-NONULL) unwriteable going forward.

Classification follows frankenfs verbatim: VALID-PROFILE / VALID-MECHANISM /
VALID-AB / VOID-CV / VOID-ZEROSELF / VOID-NONULL. Screening is triage; every
row in the audit document is hand-adjudicated before it enters the queue.

  scripts/check_perf_ledger_integrity.py preflight strspn pcmpistri
  scripts/check_perf_ledger_integrity.py lint --since origin/main
  scripts/check_perf_ledger_integrity.py report
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LEDGER = REPO / "docs" / "NEGATIVE_EVIDENCE.md"

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_BLOCKED = 2

# Worst A/A (source-identical arm vs itself) median ever measured in this repo.
NULL_LO, NULL_HI = 0.905, 1.105

# The ledger uses dated `##` headings with `###` evidence subsections. Subsections
# stay attached to their parent row; splitting them loses the evidence that makes a
# rejection admissible.
HEADING = re.compile(r"^## (\d{4}-\d{2}-\d{2})\s*(?:\(([^)]*)\))?\s*[-—]+\s*(.*)$")

# Word-boundary matching matters: "fast-reject" contains "REJECT" and was pulling
# LANDED WIN rows into the reject population.
REJECT_TOKENS = (
    "REJECT",
    "INVALID",
    "NO-SHIP",
    "LOSS/DROP",
    "KILLED",
    "NOT SHIPPED",
    "✗",
    "0-GAIN",
)
WIN_TOKENS = ("WIN", "LANDED", "SHIPPED", "✅", "RETRY EXECUTED")

RATIO = re.compile(r"(\d+\.\d+)\s*[x×]")
NULL_CTL = re.compile(
    r"null control|A/A|null floor|null median|paired\(base, ?base\)|"
    r"source-identical|FL/FL|identical-code floor",
    re.I,
)
# A counted mechanism refutes a lever by showing the WORK did not change. A null
# control cannot change the fact that no work was removed.
MECHANISM = re.compile(
    r"instructions?\b|\bcycles\b|\bsyscalls?\b|\ballocations?\b|\bpage[- ]faults?\b|"
    r"\bicount\b|\bperf stat\b|\bretired\b|\bbranch-misses\b",
    re.I,
)
SELFTIME_PCT = re.compile(
    r"(\d+\.?\d*)\s*%\s*(?:exact\s*)?self-?time|self-?time[^0-9%]{0,30}(\d+\.?\d*)\s*%",
    re.I,
)
CV_GATE = re.compile(r"cv\s*<\s*5|all-CV|CV gate|INVALID-CV|<5% .{0,12}CV", re.I)
PROFILE_FIRST = re.compile(
    r"before (?:any )?source edit|profile-first|Amdahl ceiling|"
    r"rejected before source|no source (?:or harness )?changed",
    re.I,
)
SHA256 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", re.I)
ZERO_GAIN = re.compile(
    r"~0-gain|~0 gain|no change in performance|within noise|inside the null|"
    r"indistinguishable|no measurable|below the noise|inside the floor|no gain",
    re.I,
)


class Row:
    __slots__ = ("line", "date", "who", "title", "raw", "body", "cls")

    def __init__(self, line: int, date: str, who: str, title: str, raw: str) -> None:
        self.line = line
        self.date = date
        self.who = who
        self.title = title
        # The verbatim heading, so `lint --since` can match it against git-diff
        # output. Reconstructing it from `title` does not work: `title` is only the
        # fragment after the em dash.
        self.raw = raw
        self.body: list[str] = []
        self.cls = ""

    @property
    def text(self) -> str:
        return "\n".join(self.body)

    def is_reject(self) -> bool:
        h = self.title.upper()
        if any(h.startswith(w) for w in WIN_TOKENS):
            return False
        return any(
            re.search(r"(?<![A-Z-])" + re.escape(t), h) for t in REJECT_TOKENS
        )

    def is_keep(self) -> bool:
        h = self.title.upper()
        if any(h.startswith(w) for w in WIN_TOKENS):
            return True
        return bool(re.search(r"\b(?:KEEP|SHIPPED|LANDED|WIN)\b", h))

    def has_binary_sha256(self) -> bool:
        return bool(SHA256.search(self.text))

    def classify(self) -> str:
        body = self.text
        ratios = [float(x) for x in RATIO.findall(body)]
        outside = [r for r in ratios if r < NULL_LO or r > NULL_HI]
        near = [r for r in ratios if NULL_LO <= r <= NULL_HI]
        has_null = bool(NULL_CTL.search(body))
        has_mech = bool(MECHANISM.search(body))
        zero_gain = bool(ZERO_GAIN.search(body))
        cv = bool(CV_GATE.search(body)) or "INVALID-CV" in self.title.upper()

        st = SELFTIME_PCT.search(body)
        st_val = None
        if st:
            try:
                st_val = float(st.group(1) or st.group(2))
            except (TypeError, ValueError):
                st_val = None

        # Decision language outranks context ratios: rows routinely quote a large
        # candidate-vs-glibc number next to a neutral candidate-vs-base result.
        if PROFILE_FIRST.search(self.title + "\n" + body) and st_val is not None and st_val >= 0.5:
            return "VALID-PROFILE"
        cv_only = bool(
            re.search(
                r"INVALID-CV|EVIDENCE GATE ONLY|ALL-SIX-CV|WORKER STABILITY|"
                r"rejected (?:because|on|by) .*CV|CV .*reject",
                self.title + "\n" + body,
                re.I,
            )
        )
        if cv_only and not has_mech:
            return "VOID-CV"
        if has_null and near and not outside:
            return "VALID-AB"
        if has_mech:
            return "VALID-MECHANISM"
        if st_val is not None and st_val < 0.5:
            return "VOID-ZEROSELF"
        if cv and not outside:
            return "VOID-CV"
        # A near-one wall result without a null, counted mechanism, or profile
        # attribution is the dominant epidemic: it cannot distinguish lever from
        # harness. Keep this fallback conservative for rows with no usable ratio too.
        if zero_gain or not outside:
            return "VOID-NONULL"
        # The six-class taxonomy has no VALID-DECISIVE bucket. A decisive A/B that
        # carries no admissibility basis is still not a VOID-NONULL near-one result;
        # classify it as VALID-AB only when an A/A was actually recorded, otherwise
        # require a mechanism/profile row before treating it as sound.
        return "VOID-NONULL"


def parse(path: Path) -> list[Row]:
    rows: list[Row] = []
    cur: Row | None = None
    for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
        m = HEADING.match(line)
        if m:
            if cur:
                rows.append(cur)
            cur = Row(i, m.group(1), m.group(2) or "?", m.group(3), line.strip())
        elif cur:
            cur.body.append(line)
    if cur:
        rows.append(cur)
    for r in rows:
        r.cls = r.classify()
    return rows


def cmd_preflight(args: argparse.Namespace) -> int:
    """Block a lever the ledger already soundly rejected; flag void rows as re-attackable."""
    terms = [t.lower() for t in args.terms]
    if not terms:
        print("preflight: give at least one keyword for the lever you intend to build")
        return EXIT_USAGE

    rows = [r for r in parse(LEDGER) if r.is_reject()]
    hits = [
        r
        for r in rows
        if all(t in (r.title + "\n" + r.text).lower() for t in terms)
    ]

    if not hits:
        print(f"PREFLIGHT OK — no prior reject row matches {terms!r}.")
        print("  Record an A/A null control or a counted mechanism when you write the result,")
        print("  or `lint` will refuse the row.")
        return EXIT_OK

    sound = [r for r in hits if r.cls.startswith("VALID")]
    void = [r for r in hits if r.cls.startswith("VOID")]

    for r in sound:
        print(f"BLOCKED  L{r.line}  [{r.cls}]  {r.title[:100]}")
        print(f"         retry: {_retry_predicate(r)}")
    for r in void:
        print(f"VOID     L{r.line}  [{r.cls}]  {r.title[:100]}")
        print(f"         retry: {_retry_predicate(r)}")

    if sound:
        print()
        print(f"PREFLIGHT BLOCKED: {len(sound)} sound prior rejection(s) cover this lever.")
        print("  Read them before spending a turn:")
        for r in sound[:5]:
            print(f"    sed -n '{r.line},+40p' docs/NEGATIVE_EVIDENCE.md")
        print("  If you believe a row is wrong, say why IN the new row — do not silently retry.")
        return EXIT_BLOCKED

    print()
    print(f"PREFLIGHT OK (RESURRECTION): {len(void)} prior row(s), all void — re-attackable.")
    print("  The prior verdict could not have detected the lever. Re-run under the contract:")
    print("  self-reported ELF sha, in-invocation A/A null, median-CI gate, behavior proof first.")
    return EXIT_OK


def _added_heading_lines(since: str) -> set[str]:
    try:
        diff = subprocess.run(
            ["git", "diff", "--unified=0", since, "--", str(LEDGER)],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"lint: cannot diff against {since!r}: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE) from exc
    return {
        ln[1:].strip()
        for ln in diff.split("\n")
        if ln.startswith("+## ")
    }


def _added_heading_lines_staged() -> set[str]:
    """Return newly staged dated ledger headings, without consulting a remote ref."""
    try:
        diff = subprocess.run(
            ["git", "diff", "--cached", "--unified=0", "--", str(LEDGER)],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"lint: cannot inspect staged ledger diff: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE) from exc
    return {
        ln[1:].strip()
        for ln in diff.split("\n")
        if ln.startswith("+## ")
    }


def _retry_predicate(row: Row) -> str:
    match = re.search(
        r"(?:retry predicate|retry condition|retry only|reopen only|reopen when)[^\n.]{0,360}",
        row.text,
        re.I,
    )
    return match.group(0).strip() if match else "(no concrete retry predicate recorded)"


def cmd_lint(args: argparse.Namespace) -> int:
    """Refuse undecidable new REJECT rows and KEEP rows without an in-process SHA."""
    rows = parse(LEDGER)
    if args.staged:
        added = _added_heading_lines_staged()
        rows = [r for r in rows if r.raw in added]
        scope = "staged ledger rows"
    elif args.since:
        added = _added_heading_lines(args.since)
        rows = [r for r in rows if r.raw in added]
        scope = f"rows added since {args.since}"
    else:
        scope = "all ledger rows"

    rejects = [r for r in rows if r.is_reject()]
    keeps = [r for r in rows if r.is_keep()]
    bad = [r for r in rejects if r.cls in {"VOID-NONULL", "VOID-CV", "VOID-ZEROSELF"}]
    bad_keeps = [r for r in keeps if not r.has_binary_sha256()]
    for r in bad:
        print(f"REFUSED  L{r.line}  {r.title[:100]}")
        print(
            f"         [{r.cls}] lacks an admissibility basis; record an A/A null or"
            " counted mechanism (VALID-PROFILE also requires named non-zero self-time"
            " plus an Amdahl ceiling)."
        )
    for r in bad_keeps:
        print(f"REFUSED  L{r.line}  {r.title[:100]}")
        print("         KEEP rows must carry the 64-hex SHA-256 reported by the executing ELF.")

    print()
    print(
        f"LINT: {len(rejects)} REJECT row(s), {len(keeps)} KEEP row(s) in scope ({scope}); "
        f"{len(bad) + len(bad_keeps)} refused."
    )
    if bad or bad_keeps:
        print()
        print("  A reject row must record ONE of:")
        print("    - an A/A null control measured in the SAME invocation, or")
        print("    - a counted mechanism showing the work did not change")
        print("      (instructions / cycles / syscalls / allocations / faults), or")
        print("    - a profile frame with non-zero self-time, if you rejected before editing source.")
        print("  A near-1.0 wall ratio on its own is not evidence — it is an unmeasured claim.")
        print("  A KEEP row must record the executing ELF's 64-hex SHA-256.")
        return EXIT_BLOCKED
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    """Print the current class census — the number that decays if nobody watches it."""
    all_rows = parse(LEDGER)
    rows = [r for r in all_rows if r.is_reject()]
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.cls] = counts.get(r.cls, 0) + 1
    void = sum(v for k, v in counts.items() if k.startswith("VOID"))
    total = len(rows)

    print(f"ledger:          {LEDGER.relative_to(REPO)}")
    print(f"entries parsed:  {len(all_rows)}")
    print(f"reject audited:  {total}")
    for k in (
        "VALID-AB",
        "VALID-PROFILE",
        "VALID-MECHANISM",
        "VOID-NONULL",
        "VOID-CV",
        "VOID-ZEROSELF",
    ):
        print(f"  {k:17s} {counts.get(k, 0)}")
    pct = (100.0 * void / total) if total else 0.0
    print(f"void total:      {void} ({pct:.1f}%)")
    print()
    print("Screening is TRIAGE, not a verdict — hand-adjudicate before acting on any row.")
    return EXIT_OK


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("preflight", help="block a lever the ledger already soundly rejected")
    p.add_argument("terms", nargs="*", help="keywords describing the lever")
    p.set_defaults(fn=cmd_preflight)

    p = sub.add_parser("lint", help="refuse undecidable REJECTs and KEEP rows without SHA")
    p.add_argument("--since", help="git ref; lint only rows added since it")
    p.add_argument("--staged", action="store_true", help="lint only staged ledger rows")
    p.set_defaults(fn=cmd_lint)

    p = sub.add_parser("report", help="class census over the whole ledger")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("audit", help="alias for report: mechanical taxonomy census")
    p.set_defaults(fn=cmd_report)

    args = ap.parse_args()
    if not LEDGER.exists():
        print(f"ledger not found: {LEDGER}", file=sys.stderr)
        return EXIT_USAGE
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
