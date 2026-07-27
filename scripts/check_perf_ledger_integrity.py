#!/usr/bin/env python3
"""Perf-ledger integrity gate — institutionalises the frankenfs taxonomy.

Ledger integrity DECAYS. The fleet's 2026-07-26 finding: repos that audited once and
then enforced the check mechanically sit at ~1.7% void; repos that audited once and
banked the wins drift back to 25-91%. So this is not a one-time cleanup script — it is
the thing that stops the void population regrowing.

Five modes, all cheap and offline (no build, no worker):

  preflight  Before you touch source for a perf lever, name both the proposed
             mechanism and the target surface. Exit 2 = BLOCKED when a prior REJECT
             covers that surface, and print its concrete retry predicate.

  lint       Refuse a new or modified REJECT that records neither a counted mechanism
             nor a numeric same-invocation A/A plus bootstrap median CI. Refuse a
             timed KEEP without null/effect bootstrap median CIs, that A/A witness,
             or an in-process executing-ELF SHA-256.
             Refuse every positive CV gate. Policy failures exit 2; infrastructure
             failures exit 64.

  report     Mechanical six-class census. This is triage, never a substitute for
             reading and hand-adjudicating every row.

  self-test  Exercise the policy recognizers without Cargo or fixtures.

  ledger-self-check
             Exercise the same policy against this repository's real historical
             rows, authoritative hand manifest, and live downstream citations.

Classification follows frankenfs verbatim: VALID-PROFILE / VALID-MECHANISM /
VALID-AB / VOID-CV / VOID-ZEROSELF / VOID-NONULL. Screening is triage; every
row in the audit document is hand-adjudicated before it enters the queue.

  scripts/check_perf_ledger_integrity.py preflight \
      --lever "pcmpistri span scan" --surface "strspn span_pshufb_ascii"
  scripts/check_perf_ledger_integrity.py lint --since origin/main
  scripts/check_perf_ledger_integrity.py report
  scripts/check_perf_ledger_integrity.py self-test
  scripts/check_perf_ledger_integrity.py ledger-self-check
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LEDGER = REPO / "docs" / "NEGATIVE_EVIDENCE.md"
AUDIT = REPO / "docs" / "LEDGER_RESURRECTION.md"
FRONTIER = REPO / "docs" / "PERF_FRONTIER_FINAL.md"
RUNTIME_POLICY = REPO / "crates" / "frankenlibc-abi" / "src" / "runtime_policy.rs"
BEADS = REPO / ".beads" / "issues.jsonl"

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_BLOCKED = 2
EXIT_INFRA = 64

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
HISTORICAL_NULL_VALUE = re.compile(
    r"(?:A/A(?:/B)?|null(?:[- ]control| floor| median)|FL/FL|"
    r"source-identical|identical-code floor)"
    r"[^|\n]{0,120}(?:0|1|2)\.\d+(?:\s*(?:x|×))?"
    r"|(?:0|1|2)\.\d+(?:\s*(?:x|×))?[^|\n]{0,120}"
    r"(?:A/A(?:/B)?|null(?:[- ]control| floor| median)|FL/FL|"
    r"source-identical|identical-code floor)",
    re.I,
)
# A counted mechanism refutes a lever by showing the WORK did not change. A null
# control cannot change the fact that no work was removed.
COUNTED_MECHANISM = re.compile(
    r"instructions? (?:count )?(?:un)?changed|"
    r"instructions? (?:BASE|DOWN|UP|~|-?\d)|"
    r"cycles? (?:NEUTRAL|neutral|~|unchanged|flat)|"
    r"syscalls? (?:NEUTRAL|neutral|~|unchanged|flat)|strace counted|"
    r"\d+ vs \d+ (?:fsync|syscalls?)|"
    r"(?:allocation|alloc) count (?:unchanged|flat|~|\d)|faults? unchanged|"
    r"\b\d[\d,]*\s+(?:instructions?|cycles?|syscalls?|allocations?|faults?)"
    r"[^|\n]{0,80}(?:vs|->|→|to)\s*\d[\d,]*",
    re.I,
)
SELFTIME_PCT = re.compile(
    r"(\d+\.?\d*)\s*%\s*(?:exact\s*)?self-?time|self-?time[^0-9%]{0,30}(\d+\.?\d*)\s*%",
    re.I,
)
PROFILE_FIRST = re.compile(
    r"before (?:any )?source edit|profile-first|Amdahl ceiling|"
    r"rejected before source|no source (?:or harness )?changed",
    re.I,
)
AMDAHL = re.compile(r"\bAmdahl(?:'s)?\b[^.\n]{0,80}\b(?:ceiling|bound)\b", re.I)
FULL_SHA256 = r"[0-9a-f]{64}"
SHA256_VALUE = re.compile(rf"(?<![0-9a-f]){FULL_SHA256}(?![0-9a-f])", re.I)
EXECUTION_SELF_REPORT = re.compile(
    r"in[- ]process|self[- ]report(?:ed|ing)?|current_exe|executing",
    re.I,
)
ELF_OR_BINARY = re.compile(r"\b(?:ELF|binary|executable)\b", re.I)
EXECUTING_ELF_SHA256 = re.compile(
    rf"(?:bench_elf_sha256|executing_elf_sha256|current_exe_sha256)"
    rf"\s*[:=]\s*`?{FULL_SHA256}`?"
    rf"|bench_evidence\s*,\s*binary_sha256\s*=\s*`?{FULL_SHA256}`?"
    rf"|(?:in[- ]process|self[- ]report(?:ed|ing)?|executing)"
    rf"[^|\n]{{0,96}}\bELF\b[^|\n]{{0,64}}`?\b{FULL_SHA256}\b`?"
    rf"|(?:in[- ]process|self[- ]report(?:ed|ing)?|executing)"
    rf"[^|\n]{{0,160}}\b(?:ELF|binary)\b[^|\n]{{0,160}}"
    rf"(?:sha-?256|hash)[^|\n]{{0,48}}\b{FULL_SHA256}\b",
    re.I,
)
CONTRACT_NULL_VALUE = re.compile(
    r"(?:A/A(?:/B)?|null(?:[- ]control| floor)|null_median_ratio)"
    r"[^|\n]{0,120}(?:0|1|2)\.\d+(?:\s*(?:x|×))?"
    r"|(?:0|1|2)\.\d+(?:\s*(?:x|×))?[^|\n]{0,120}"
    r"(?:A/A(?:/B)?|null(?:[- ]control| floor)|null_median_ratio)",
    re.I,
)
EFFECT_VALUE = re.compile(
    r"(?:A/B|candidate|effect|cand(?:idate)?/(?:orig(?:inal)?|base|retained)|"
    r"FL/glibc|CAND/ORIG)"
    r"[^|\n]{0,120}(?:0|1|2)\.\d+(?:\s*(?:x|×))?"
    r"|(?:0|1|2)\.\d+(?:\s*(?:x|×))?[^|\n]{0,120}"
    r"(?:A/B|candidate|effect|cand(?:idate)?/(?:orig(?:inal)?|base|retained)|"
    r"FL/glibc|CAND/ORIG)",
    re.I,
)
SAME_INVOCATION_WITNESS = re.compile(
    r"same[- ]invocation|A/A/B|interleaved A/A|in[- ]invocation A/A",
    re.I,
)
BOOTSTRAP = re.compile(r"\bbootstrap(?:ped|ping)?\b|\bresampl(?:e|ed|es|ing)\b", re.I)
MEDIAN = re.compile(r"\bmedian\b", re.I)
CONFIDENCE_INTERVAL = re.compile(r"\bCI\b|\bconfidence interval\b", re.I)
CV_MENTION = re.compile(r"\bCVs?\b|\bcoefficients? of variation\b", re.I)
CV_DISCLAIMER = re.compile(
    r"\bcv_used\s*=\s*false\b|"
    r"\b(?:no|not an?|without an?)\s+"
    r"(?:CVs?|coefficients? of variation)\s+"
    r"(?:gate|threshold|decision|input)\b|"
    r"\b(?:never|not|no)\b[^.;|\n]{0,48}"
    r"\b(?:gate(?:d|s|ing)?|input|decision|consult(?:ed|s|ing)?|used?)\b"
    r"[^.;|\n]{0,48}\b(?:CVs?|coefficients? of variation)\b|"
    r"\b(?:CVs?|coefficients? of variation)\b[^.;|\n]{0,48}"
    r"\b(?:never|not|no)\b[^.;|\n]{0,48}"
    r"\b(?:gate(?:d|s|ing)?|input|inputs|decision|consulted|used)\b",
    re.I,
)
CV_GATE_WORD = re.compile(
    r"\b(?:gate(?:d|s|ing)?|threshold|ceiling|admission|admitted|acceptance|"
    r"accepted|rejection|rejected|decide(?:d|s)?|decision|verdict|required?|"
    r"requirement|mandatory)\b",
    re.I,
)
CV_COMPARISON = re.compile(
    r"(?:\bCVs?\b|\bcoefficients? of variation\b)"
    r"[^.;|\n]{0,40}(?:<=|>=|<|>|≤|≥|\bbelow\b|\bunder\b|\babove\b|\bover\b)"
    r"|(?:<=|>=|<|>|≤|≥|\bbelow\b|\bunder\b|\babove\b|\bover\b)"
    r"[^.;|\n]{0,40}(?:\bCVs?\b|\bcoefficients? of variation\b)",
    re.I,
)
RETRY_START = re.compile(
    r"(?:\*\*)?(?:concrete )?[Rr]etry (?:only )?"
    r"(?:predicate|condition|if|on|when)",
)
ZERO_GAIN = re.compile(
    r"~0-gain|~0 gain|no change in performance|within noise|inside the null|"
    r"indistinguishable|no measurable|below the noise|inside the floor|no gain",
    re.I,
)


def decision_evidence(text: str) -> str:
    """Exclude future retry requirements from evidence about the completed run."""
    retry = RETRY_START.search(text)
    return text[: retry.start()] if retry else text


def _anchored_window_has(
    evidence: str,
    anchor: re.Pattern[str],
    requirements: tuple[re.Pattern[str], ...],
) -> bool:
    """Require related evidence in the anchor's paragraph, not anywhere in a row."""
    for match in anchor.finditer(evidence):
        start_marker = evidence.rfind("\n\n", 0, match.start())
        block_start = 0 if start_marker < 0 else start_marker + 2
        end_marker = evidence.find("\n\n", match.end())
        block_end = len(evidence) if end_marker < 0 else end_marker
        block = evidence[block_start:block_end]
        if all(requirement.search(block) for requirement in requirements):
            return True
    return False


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
        if self.is_reject():
            return False
        h = self.title.upper()
        if any(h.startswith(w) for w in WIN_TOKENS):
            return True
        return bool(re.search(r"\b(?:KEEP|SHIPPED|LANDED|WIN)\b", h))

    def completed_run_evidence(self) -> str:
        return decision_evidence(self.text)

    def has_historical_null_control(self) -> bool:
        return bool(HISTORICAL_NULL_VALUE.search(self.completed_run_evidence()))

    def has_counted_mechanism(self) -> bool:
        return bool(COUNTED_MECHANISM.search(self.completed_run_evidence()))

    def has_same_invocation_null_control(self) -> bool:
        evidence = self.completed_run_evidence()
        return bool(
            CONTRACT_NULL_VALUE.search(evidence)
            and SAME_INVOCATION_WITNESS.search(evidence)
        )

    def has_executing_elf_sha256(self) -> bool:
        evidence = self.completed_run_evidence()
        if EXECUTING_ELF_SHA256.search(evidence):
            return True
        return any(
            SHA256_VALUE.search(block)
            and EXECUTION_SELF_REPORT.search(block)
            and ELF_OR_BINARY.search(block)
            for block in re.split(r"\n\s*\n", evidence)
        )

    def has_bootstrap_median_ci(self) -> bool:
        evidence = self.completed_run_evidence()
        return any(
            BOOTSTRAP.search(clause)
            and MEDIAN.search(clause)
            and CONFIDENCE_INTERVAL.search(clause)
            for clause in re.split(r"\n|\|", evidence)
        )

    def has_null_bootstrap_median_ci(self) -> bool:
        return _anchored_window_has(
            self.completed_run_evidence(),
            CONTRACT_NULL_VALUE,
            (BOOTSTRAP, MEDIAN, CONFIDENCE_INTERVAL),
        )

    def has_effect_bootstrap_median_ci(self) -> bool:
        return _anchored_window_has(
            self.completed_run_evidence(),
            EFFECT_VALUE,
            (BOOTSTRAP, MEDIAN, CONFIDENCE_INTERVAL),
        )

    def has_valid_profile_basis(self) -> bool:
        evidence = self.title + "\n" + self.completed_run_evidence()
        st = SELFTIME_PCT.search(evidence)
        if not st:
            return False
        try:
            self_time = float(st.group(1) or st.group(2))
        except (TypeError, ValueError):
            return False
        return bool(
            self_time > 0.0
            and PROFILE_FIRST.search(evidence)
            and AMDAHL.search(evidence)
            and re.search(r"`[A-Za-z_][A-Za-z0-9_:<>-]*`", evidence)
        )

    def uses_cv_as_gate(self) -> bool:
        # CV prohibition includes retry predicates: a new row must not instruct
        # the next agent to resurrect the invalid gate. Split into short clauses
        # so an explicit cv_used=false does not excuse a positive threshold later.
        for clause in re.split(r"(?<=[.;])\s+|\n|\|", self.text):
            if not CV_MENTION.search(clause):
                continue
            if CV_DISCLAIMER.search(clause):
                continue
            if CV_GATE_WORD.search(clause) or CV_COMPARISON.search(clause):
                return True
        return False

    def contract_violations(self) -> list[str]:
        bad: list[str] = []
        if self.uses_cv_as_gate():
            bad.append("CV is used as a gate or threshold (bootstrap median CI is mandatory)")
        if self.is_reject():
            if self.has_counted_mechanism() or self.has_valid_profile_basis():
                return bad
            if not self.has_same_invocation_null_control():
                bad.append("no counted mechanism and no numeric same-invocation A/A null")
            elif not self.has_null_bootstrap_median_ci():
                bad.append("numeric same-invocation A/A has no nearby bootstrap median CI")
        elif self.is_keep():
            if not self.has_executing_elf_sha256():
                bad.append("no in-process self-report of the executing ELF's SHA-256")
            if not self.has_same_invocation_null_control():
                bad.append("timed KEEP has no numeric same-invocation A/A null")
            elif not self.has_null_bootstrap_median_ci():
                bad.append("timed KEEP's A/A null has no nearby bootstrap median CI")
            if not self.has_effect_bootstrap_median_ci():
                bad.append("timed KEEP's effect has no nearby bootstrap median CI")
        return bad

    def classify(self) -> str:
        body = self.completed_run_evidence()
        ratios = [float(x) for x in RATIO.findall(body)]
        outside = [r for r in ratios if r < NULL_LO or r > NULL_HI]
        near = [r for r in ratios if NULL_LO <= r <= NULL_HI]
        has_null = self.has_historical_null_control()
        has_mech = self.has_counted_mechanism()
        zero_gain = bool(ZERO_GAIN.search(body))
        cv = self.uses_cv_as_gate() or "INVALID-CV" in self.title.upper()

        st = SELFTIME_PCT.search(body)
        st_val = None
        if st:
            try:
                st_val = float(st.group(1) or st.group(2))
            except (TypeError, ValueError):
                st_val = None

        # Decision language outranks context ratios: rows routinely quote a large
        # candidate-vs-glibc number next to a neutral candidate-vs-base result.
        if self.has_valid_profile_basis():
            return "VALID-PROFILE"
        cv_only = bool(
            re.search(
                r"INVALID-CV|EVIDENCE GATE ONLY|ALL-SIX-CV|WORKER STABILITY|"
                r"rejected (?:because|on|by) .*CV|CV .*reject",
                self.title + "\n" + body,
                re.I,
            )
        )
        if cv_only and not has_mech and not has_null:
            return "VOID-CV"
        if has_null and near and not outside:
            return "VALID-AB"
        if has_mech:
            return "VALID-MECHANISM"
        if st_val is not None and st_val < 0.5:
            return "VOID-ZEROSELF"
        if cv and not outside and not has_null:
            return "VOID-CV"
        # A near-one wall result without a null, counted mechanism, or profile
        # attribution is the dominant epidemic: it cannot distinguish lever from
        # harness. Keep this fallback conservative for rows with no usable ratio too.
        if zero_gain or (near and not outside):
            return "VOID-NONULL"
        # This is deliberately a screen state, not a seventh verdict class. The
        # six-class taxonomy does not define a decisive A/B with no null or counted
        # mechanism. Calling it VOID-NONULL would violate the "near-1.0" definition;
        # calling it valid would invent evidence. A human must adjudicate it.
        return "TRIAGE-UNRESOLVED"


def parse_text(text: str) -> list[Row]:
    rows: list[Row] = []
    cur: Row | None = None
    for i, line in enumerate(text.split("\n"), 1):
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


def parse(path: Path) -> list[Row]:
    return parse_text(path.read_text(encoding="utf-8", errors="replace"))


STOP_WORDS = {
    "the",
    "and",
    "for",
    "from",
    "into",
    "with",
    "this",
    "that",
    "lever",
    "perf",
    "fast",
    "faster",
    "slow",
    "using",
    "new",
    "add",
    "src",
    "mod",
}


def _terms(text: str) -> list[str]:
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text.lower())
    return [word for word in dict.fromkeys(words) if word not in STOP_WORDS]


def _candidate_match(
    row: Row,
    lever_terms: list[str],
    surface_terms: list[str],
    threshold: int,
) -> tuple[int, list[str], list[str]] | None:
    low = (row.title + "\n" + row.text).lower()
    surface_hits = [word for word in surface_terms if word in low]
    lever_hits = [word for word in lever_terms if word in low]
    all_hits = list(dict.fromkeys(surface_hits + lever_hits))
    if not surface_hits or len(all_hits) < threshold:
        return None
    qualified = [word for word in surface_terms if "_" in word or "::" in word]
    if qualified and not any(word in surface_hits for word in qualified):
        return None
    return 100 * len(surface_hits) + len(all_hits), surface_hits, lever_hits


def cmd_preflight(args: argparse.Namespace) -> int:
    """Block a proposal whose target surface already has a REJECT row."""
    lever_terms = _terms(args.lever)
    surface_terms = _terms(args.surface)
    if not lever_terms or not surface_terms:
        print(
            "preflight: --lever and --surface must contain searchable terms",
            file=sys.stderr,
        )
        return EXIT_INFRA

    hits: list[tuple[int, list[str], list[str], Row]] = []
    for row in parse(LEDGER):
        if not row.is_reject():
            continue
        match = _candidate_match(row, lever_terms, surface_terms, args.threshold)
        if match:
            score, surface_hits, lever_hits = match
            hits.append((score, surface_hits, lever_hits, row))

    if not hits:
        print(
            "PREFLIGHT OK — no prior REJECT covers "
            f"surface={surface_terms[:6]} proposal={lever_terms[:6]}."
        )
        print("  Record an A/A null control or a counted mechanism when you write the result,")
        print("  or `lint` will refuse the row.")
        return EXIT_OK

    hits.sort(key=lambda hit: -hit[0])
    print("PREFLIGHT BLOCKED — a prior REJECT covers this target surface.\n")
    for _, surface_hits, lever_hits, row in hits[:5]:
        print(f"  docs/NEGATIVE_EVIDENCE.md:{row.line}  [{row.cls}]")
        print(f"    target matches: {', '.join(surface_hits[:8])}")
        print(f"    proposal matches: {', '.join(lever_hits[:8]) or '(none)'}")
        print(f"    {row.title[:180]}")
        print(f"    retry: {_retry_predicate(row)}\n")
    print("Satisfy and cite the retry predicate, or switch veins.")
    print("A VOID row is resurrectable evidence debt, not permission to ignore its predicate.")
    return EXIT_BLOCKED


def _git_capture(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"git {' '.join(args)} failed: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit {result.returncode}"
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def _changed_line_numbers(*, since: str | None, staged: bool) -> set[int]:
    rel = LEDGER.relative_to(REPO).as_posix()
    args = ["diff"]
    if staged:
        args.append("--cached")
    args.append("-U0")
    if since:
        args.append(f"{since}...HEAD")
    args.extend(["--", rel])
    diff = _git_capture(args)
    added: set[int] = set()
    for hunk in re.finditer(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@", diff, re.M):
        start = int(hunk.group(1))
        count = int(hunk.group(2) or 1)
        added.update(range(start, start + count))
    return added


def _ledger_text(*, staged: bool, at_head: bool) -> str:
    rel = LEDGER.relative_to(REPO).as_posix()
    if staged:
        return _git_capture(["show", f":{rel}"])
    if at_head:
        return _git_capture(["show", f"HEAD:{rel}"])
    return LEDGER.read_text(encoding="utf-8", errors="replace")


def _row_line_span(row: Row) -> range:
    return range(row.line, row.line + max(1, len((row.raw + "\n" + row.text).splitlines())))


def _retry_predicate(row: Row) -> str:
    concrete = re.search(
        r"(?:\*\*)?CONCRETE RETRY PREDICATE(?:\s*\([^)]*\))?"
        r"[\s*:.\u2014-]*(.{0,1200}?)(?=\n\n|^## |\Z)",
        row.text,
        re.I | re.M | re.S,
    )
    if concrete:
        return " ".join(concrete.group(1).split())[:800]
    matches = list(
        re.finditer(
            r"(?:retry condition|retry only|reopen only|reopen when)[^\n.]{0,500}",
            row.text,
            re.I,
        )
    )
    if matches:
        return " ".join(matches[-1].group(0).split())
    return "(no concrete retry predicate recorded)"


def cmd_lint(args: argparse.Namespace) -> int:
    """Refuse staged decisions that violate the forward evidence contract."""
    if args.staged and args.since:
        print("lint: --staged and --since are mutually exclusive", file=sys.stderr)
        return EXIT_INFRA
    selective = args.staged or args.since is not None
    try:
        touched = (
            _changed_line_numbers(since=args.since, staged=args.staged)
            if selective
            else None
        )
        text = _ledger_text(staged=args.staged, at_head=args.since is not None)
        rows = parse_text(text)
    except (OSError, RuntimeError) as exc:
        print(f"lint: infrastructure failure: {exc}", file=sys.stderr)
        return EXIT_INFRA

    if touched is not None:
        rows = [row for row in rows if touched.intersection(_row_line_span(row))]
    decisions = [row for row in rows if row.is_reject() or row.is_keep()]
    bad = [(row, row.contract_violations()) for row in decisions]
    bad = [(row, why) for row, why in bad if why]

    scope = (
        "staged index"
        if args.staged
        else (f"committed since {args.since}" if args.since else "whole ledger")
    )
    for row, violations in bad:
        print(f"REFUSED  L{row.line}  {row.title[:100]}")
        for violation in violations:
            print(f"         {violation}")

    reject_count = sum(row.is_reject() for row in decisions)
    keep_count = sum(row.is_keep() for row in decisions)
    print()
    print(
        f"LINT: {reject_count} REJECT row(s), {keep_count} KEEP row(s) in {scope}; "
        f"{len(bad)} refused."
    )
    if bad:
        print()
        print("  A reject row must record ONE of:")
        print("    - a numeric A/A null measured in the SAME invocation, with")
        print("      a bootstrap median confidence interval, or")
        print("    - a counted mechanism showing the work did not change")
        print("      (instructions / cycles / syscalls / allocations / faults), or")
        print("    - a named non-zero profile frame plus computed Amdahl ceiling")
        print("      when the lever was rejected before editing source.")
        print("  A near-1.0 wall ratio on its own is not evidence — it is an unmeasured claim.")
        print("  A timed KEEP must record numeric same-invocation A/A, nearby")
        print("  null/effect bootstrap median CIs, and the executing ELF's")
        print("  in-process self-reported 64-hex SHA-256.")
        print("  CV may be provenance, but it must never be a decision gate.")
        return EXIT_BLOCKED
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    """Print the mechanical screen; hand adjudication owns the final census."""
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
        "TRIAGE-UNRESOLVED",
    ):
        print(f"  {k:17s} {counts.get(k, 0)}")
    pct = (100.0 * void / total) if total else 0.0
    print(f"void total:      {void} ({pct:.1f}%)")
    print(
        "executing ELF:   "
        f"{sum(row.has_executing_elf_sha256() for row in rows)} in-process SHA witness(es)"
    )
    print(
        "numeric null:    "
        f"{sum(row.has_historical_null_control() for row in rows)} A/A witness(es)"
    )
    print()
    print("Screening is TRIAGE, not a verdict — read and hand-adjudicate every row.")
    print("TRIAGE-UNRESOLVED is not a seventh class; it refuses to fabricate a verdict")
    print("for a decisive A/B with no null, profile basis, or counted mechanism.")
    if args.rows:
        print()
        for row in rows:
            print(f"L{row.line:05d}  {row.cls:18s}  {row.title}")
    return EXIT_OK


def cmd_self_test(args: argparse.Namespace) -> int:
    """Exercise the forward policy without Cargo, git mutation, or fixtures."""
    sha = "a" * 64

    def row(title: str, body: str = "") -> Row:
        item = Row(1, "2026-07-27", "self-test", title, f"## 2026-07-27 — {title}")
        item.body = body.splitlines()
        item.cls = item.classify()
        return item

    checks: list[tuple[str, bool]] = [
        (
            "near-one reject without basis is refused",
            bool(row("REJECT: neutral candidate", "wall ratio 1.01x").contract_violations()),
        ),
        (
            "negated A/A mention is not evidence",
            not row("REJECT: neutral", "No A/A null control was recorded.")
            .has_historical_null_control(),
        ),
        (
            "A/A without numeric value is not evidence",
            not row("REJECT: neutral", "A/A was discussed.").has_historical_null_control(),
        ),
        (
            "numeric A/A without same-invocation witness is refused",
            bool(
                row("REJECT: neutral", "A/A null control 1.004x.")
                .contract_violations()
            ),
        ),
        (
            "future retry A/A does not count as completed-run evidence",
            not row(
                "REJECT: neutral",
                "wall ratio 1.01x. Retry only when A/A null 1.004x is in the same invocation.",
            ).has_same_invocation_null_control(),
        ),
        (
            "same-invocation A/A without median CI is refused",
            bool(
                row(
                    "REJECT: neutral",
                    "A/A null control 1.004x in the same invocation.",
                ).contract_violations()
            ),
        ),
        (
            "same-invocation A/A with bootstrap median CI is admitted",
            not row(
                "REJECT: neutral",
                "A/A null control 1.004x in the same invocation; "
                "deterministic bootstrap median 95% CI [0.998, 1.009].",
            ).contract_violations(),
        ),
        (
            "unrelated effect CI does not satisfy the A/A null CI",
            not row(
                "REJECT: neutral",
                "A/A null control 1.004x in the same invocation.\n\n"
                "Candidate deterministic bootstrap median 95% CI [0.88, 0.92].",
            ).has_null_bootstrap_median_ci(),
        ),
        (
            "unrelated bootstrap mean and median do not synthesize a CI",
            not row(
                "REJECT: neutral",
                "bootstrap mean CI [0.99, 1.01] | "
                "A/A null control median 1.004x in the same invocation",
            ).has_bootstrap_median_ci(),
        ),
        (
            "bare mechanism noun is not a count",
            not row(
                "REJECT: neutral",
                "No instruction count or syscall count was recorded.",
            ).has_counted_mechanism(),
        ),
        (
            "unchanged instruction count admits a reject",
            not row(
                "REJECT: mechanism",
                "perf stat: instructions unchanged at 12,345 vs 12,345.",
            ).contract_violations(),
        ),
        (
            "future counted mechanism does not count as run evidence",
            not row(
                "REJECT: neutral",
                "wall ratio 1.01x. Retry only when instructions unchanged.",
            ).has_counted_mechanism(),
        ),
        (
            "profile without Amdahl ceiling is refused",
            bool(
                row(
                    "REJECT: profile-first",
                    "Before source edit, frame `foo` was 3.2% self-time.",
                ).contract_violations()
            ),
        ),
        (
            "named non-zero profile plus Amdahl ceiling is admitted",
            not row(
                "REJECT: profile-first",
                "Before source edit, frame `foo` was 3.2% self-time; "
                "computed Amdahl ceiling 1.033x.",
            ).contract_violations(),
        ),
        (
            "unrelated bare digest is not execution proof",
            not row("KEEP: win", f"fixture digest {sha}.").has_executing_elf_sha256(),
        ),
        (
            "adjacent sha256sum is not execution proof",
            not row(
                "KEEP: win",
                f"binary SHA-256 {sha} from sha256sum beside the run.",
            ).has_executing_elf_sha256(),
        ),
        (
            "future hash retry is not execution proof",
            not row(
                "KEEP: win",
                f"ratio 0.90x. Retry only when bench_elf_sha256={sha}.",
            ).has_executing_elf_sha256(),
        ),
        (
            "machine-readable current ELF self-report is accepted",
            row("KEEP: win", f"bench_elf_sha256={sha}.").has_executing_elf_sha256(),
        ),
        (
            "bench evidence ELF self-report is accepted",
            row(
                "KEEP: win",
                f"bench_evidence,binary_sha256={sha},worker=ovh-a.",
            ).has_executing_elf_sha256(),
        ),
        (
            "prose in-process ELF self-report is accepted",
            row(
                "KEEP: win",
                f"in-process executing ELF SHA-256 {sha}.",
            ).has_executing_elf_sha256(),
        ),
        (
            "KEEP with self-hash but no median CI is refused",
            bool(row("KEEP: win", f"bench_elf_sha256={sha}.").contract_violations()),
        ),
        (
            "KEEP with only an effect CI is refused for missing A/A",
            bool(
                row(
                    "KEEP: win",
                    f"bench_elf_sha256={sha}; candidate 0.900x deterministic "
                    "bootstrap median 95% CI [0.88, 0.92].",
                ).contract_violations()
            ),
        ),
        (
            "KEEP with self-hash, A/A CI, and effect CI is admitted",
            not row(
                "KEEP: win",
                f"bench_elf_sha256={sha}; A/A null control 1.004x in the same "
                "invocation with deterministic bootstrap median 95% CI "
                "[0.998, 1.009]; candidate/original 0.900x with deterministic "
                "bootstrap median 95% CI [0.88, 0.92].",
            ).contract_violations(),
        ),
        (
            "positive CV gate is refused",
            row(
                "REJECT: mechanism",
                "instructions unchanged; CV gate passed at 4%.",
            ).uses_cv_as_gate(),
        ),
        (
            "CV gate hidden in retry predicate is refused",
            row(
                "REJECT: mechanism",
                "instructions unchanged. Retry only when CV < 5%.",
            ).uses_cv_as_gate(),
        ),
        (
            "machine-readable CV non-use witness is accepted",
            not row(
                "KEEP: win",
                f"bench_elf_sha256={sha}; deterministic bootstrap median 95% "
                "CI [0.88, 0.92]; cv_used=false.",
            ).uses_cv_as_gate(),
        ),
        (
            "prose never-CV witness is accepted",
            not row(
                "REJECT: mechanism",
                "instructions unchanged; never gate on CV.",
            ).uses_cv_as_gate(),
        ),
        (
            "REJECT title containing NOT SHIPPED is not a KEEP",
            not row("REJECT (NOT SHIPPED): candidate").is_keep(),
        ),
        (
            "decisive no-null screen remains unresolved, not falsely VOID",
            row("REJECT: regression", "candidate/original 1.84x.").cls
            == "TRIAGE-UNRESOLVED",
        ),
    ]

    candidate = row(
        "REJECT: SnapshotRegistry publication-prefix atomic batching",
        "Atomic stores were batched. Retry only when publication exceeds 5% self-time.",
    )
    checks.append(
        (
            "candidate matching requires the named target surface",
            _candidate_match(
                candidate,
                _terms("batch atomic publication stores"),
                _terms("SnapshotRegistry publication"),
                3,
            )
            is not None
            and _candidate_match(
                candidate,
                _terms("batch atomic publication stores"),
                _terms("unrelated extent decoder"),
                3,
            )
            is None,
        )
    )
    checks.append(
        (
            "row span contains its heading and body only",
            list(_row_line_span(row("KEEP: win", "one\nsecond"))) == [1, 2, 3],
        )
    )
    retry = row(
        "REJECT: retry extraction",
        "Do not repeat the old shape.\n\n"
        "**CONCRETE RETRY PREDICATE:** Reopen only with a counted allocation delta.",
    )
    checks.append(
        (
            "explicit concrete retry predicate wins extraction",
            _retry_predicate(retry)
            == "Reopen only with a counted allocation delta.",
        )
    )

    failures = [name for name, passed in checks if not passed]
    if failures:
        print("SELF-TEST FAILED", file=sys.stderr)
        for name in failures:
            print(f"  {name}", file=sys.stderr)
        return EXIT_USAGE
    print(f"SELF-TEST OK — {len(checks)} policy checks")
    return EXIT_OK


def cmd_ledger_self_check(args: argparse.Namespace) -> int:
    """Run the hardened policy against real repository evidence and dependents."""
    try:
        ledger_text = LEDGER.read_text(encoding="utf-8", errors="replace")
        audit_text = AUDIT.read_text(encoding="utf-8", errors="replace")
        frontier_text = FRONTIER.read_text(encoding="utf-8", errors="replace")
        runtime_policy_text = RUNTIME_POLICY.read_text(
            encoding="utf-8", errors="replace"
        )
        issues = {
            issue["id"]: issue
            for line in BEADS.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
            for issue in (json.loads(line),)
        }
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"LEDGER SELF-CHECK infrastructure failure: {exc}", file=sys.stderr)
        return EXIT_INFRA

    rows = parse_text(ledger_text)
    decisions = [row for row in rows if row.is_reject() or row.is_keep()]
    refused = [
        (row, violations)
        for row in decisions
        if (violations := row.contract_violations())
    ]

    def unique_row(marker: str) -> Row | None:
        hits = [row for row in rows if marker in row.title]
        return hits[0] if len(hits) == 1 else None

    real_undecidable = unique_row("bd-us7dho")
    adjacent_hash = next(
        (
            row
            for row in decisions
            if row.is_keep()
            and SHA256_VALUE.search(row.completed_run_evidence())
            and not row.has_executing_elf_sha256()
        ),
        None,
    )
    entrypoint = unique_row("cc-entrypoint-scope-split-2026-07-25")

    manifest_match = re.search(
        r"### Complete hand manifest\n(?P<body>.*?)"
        r"\nThe strict provenance pass",
        audit_text,
        re.S,
    )
    manifest_anchors = (
        re.findall(r"\bL\d+\b", manifest_match.group("body"))
        if manifest_match
        else []
    )

    verdict_match = re.search(
        r"### 23-commit model-integrity audit\n(?P<body>.*?)"
        r"\nResult: \*\*10 SOUND, 10 CORRECTED, 3 RETRACTED\*\*\.",
        audit_text,
        re.S,
    )
    verdict_body = verdict_match.group("body") if verdict_match else ""
    verdict_counts = {
        verdict: len(
            re.findall(
                rf"^\| `[0-9a-f]+` \| \*\*{verdict}\*\* \|",
                verdict_body,
                re.M,
            )
        )
        for verdict in ("SOUND", "CORRECTED", "RETRACTED")
    }

    non_sound = (
        "858dc7ae4",
        "7c9d0d8c2",
        "529df86c0",
        "b5de2730a",
        "bd8a65351",
        "77e305c6f",
        "46a783ea0",
        "9ab364ffa",
        "0c3c12e29",
        "c8775a018",
        "83b760709",
        "09b4ff404",
        "8412380e1",
    )
    reconciliation_match = re.search(
        r"### Non-SOUND verdict-to-fix reconciliation\n(?P<body>.*?)"
        r"\nReconciliation: \*\*13/13",
        audit_text,
        re.S,
    )
    reconciliation = (
        reconciliation_match.group("body") if reconciliation_match else ""
    )

    expected_census = {
        "VALID-PROFILE": 0,
        "VALID-MECHANISM": 1,
        "VALID-AB": 9,
        "VOID-CV": 8,
        "VOID-ZEROSELF": 0,
        "VOID-NONULL": 29,
    }
    census_ok = all(
        re.search(
            rf"^\| `{re.escape(cls)}` \|.*\| {count} \|$",
            audit_text,
            re.M,
        )
        for cls, count in expected_census.items()
    )
    reconciliation_ok = all(
        re.search(
            rf"^\| `{commit}` \|.*\| \*\*LANDED\*\* \|$",
            reconciliation,
            re.M,
        )
        for commit in non_sound
    )

    bead_text = {
        issue_id: "\n".join(
            str(issues.get(issue_id, {}).get(field, ""))
            for field in ("title", "description", "notes", "close_reason")
        )
        for issue_id in ("bd-3ollh0", "bd-q7b7xf", "bd-9j6h0d", "bd-65p87u")
    }
    preflight_match = (
        _candidate_match(
            entrypoint,
            _terms("hot cold split"),
            _terms("entrypoint_scope"),
            2,
        )
        if entrypoint
        else None
    )

    checks: list[tuple[str, bool]] = [
        (
            "real undecidable REJECT is refused",
            bool(
                real_undecidable
                and any(
                    "no counted mechanism" in violation
                    for violation in real_undecidable.contract_violations()
                )
            ),
        ),
        (
            "real adjacent hash is not execution proof",
            bool(
                adjacent_hash
                and any(
                    "executing ELF" in violation
                    for violation in adjacent_hash.contract_violations()
                )
            ),
        ),
        (
            "whole-ledger policy finds historical evidence debt",
            len(refused) > 0,
        ),
        (
            "preflight resolves a real prior surface and concrete retry",
            bool(
                entrypoint
                and preflight_match
                and _retry_predicate(entrypoint)
                != "(no concrete retry predicate recorded)"
            ),
        ),
        (
            "six-class hand census is exact",
            census_ok,
        ),
        (
            "hand manifest has 130 unique anchors",
            len(manifest_anchors) == 130
            and len(set(manifest_anchors)) == 130,
        ),
        (
            "23-commit verdict totals are exact",
            verdict_counts
            == {"SOUND": 10, "CORRECTED": 10, "RETRACTED": 3},
        ),
        (
            "all 13 non-SOUND verdicts map to landed fixes",
            reconciliation_ok,
        ),
        (
            "39-of-93 census is quarantined and frontier is corrected",
            "RETRACTED CENSUS" in ledger_text
            and "39 of 93 REJECT rows decided INSIDE" not in frontier_text
            and "VOID-NONULL 29" in frontier_text,
        ),
        (
            "6-to-1 conclusion is quarantined",
            bool(
                unique_row("cc-alloc-layer-split-2026-07-25")
                and "RETRACTED"
                in unique_row("cc-alloc-layer-split-2026-07-25").title
                and "38.3% vs 6.4%" not in bead_text["bd-9j6h0d"]
            ),
        ),
        (
            "PCC dependents use matched 6.68-percent attribution",
            "22.18% of process self-time" not in runtime_policy_text
            and "6.68% of process" in runtime_policy_text
            and "22.18% self-time" not in bead_text["bd-q7b7xf"]
            and "6.68%" in bead_text["bd-q7b7xf"],
        ),
        (
            "three-RMW correction reached ledger and bead",
            bool(
                unique_row("cc-alloc-three-rmw-executions-2026-07-25")
                and "THREE" in bead_text["bd-65p87u"]
                and "two lock-prefixed RMWs per malloc/free pair"
                not in bead_text["bd-65p87u"]
            ),
        ),
        (
            "resurrection bead no longer carries 39-of-93 title",
            "39 of 93" not in bead_text["bd-3ollh0"]
            and "six-class" in bead_text["bd-3ollh0"].lower(),
        ),
    ]

    failures = [name for name, passed in checks if not passed]
    if failures:
        print("LEDGER SELF-CHECK BLOCKED", file=sys.stderr)
        for name in failures:
            print(f"  {name}", file=sys.stderr)
        print(
            f"  real decisions refused by forward contract: {len(refused)}",
            file=sys.stderr,
        )
        return EXIT_BLOCKED

    # Exercise the public preflight path last. A real prior row must produce the
    # fleet-standard exit 2, and the outer self-check treats that block as success.
    preflight_exit = cmd_preflight(
        argparse.Namespace(
            lever="hot cold split",
            surface="entrypoint_scope",
            threshold=2,
        )
    )
    if preflight_exit != EXIT_BLOCKED:
        print(
            f"LEDGER SELF-CHECK BLOCKED: preflight returned {preflight_exit}, expected 2",
            file=sys.stderr,
        )
        return EXIT_BLOCKED

    print(
        "LEDGER SELF-CHECK OK — "
        f"{len(checks)} repository checks; "
        f"{len(refused)} historical decisions refused; preflight exit 2 confirmed"
    )
    if real_undecidable:
        print(
            f"  real undecidable exemplar: L{real_undecidable.line} "
            f"{real_undecidable.title}"
        )
    if adjacent_hash:
        print(
            f"  adjacent-hash exemplar: L{adjacent_hash.line} "
            f"{adjacent_hash.title}"
        )
    return EXIT_OK


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("preflight", help="block a lever whose surface has a prior REJECT")
    p.add_argument("--lever", required=True, help="proposed mechanism")
    p.add_argument("--surface", required=True, help="target function/module/benchmark surface")
    p.add_argument(
        "--threshold",
        type=int,
        default=1,
        help="combined term overlap needed to call the surface covered",
    )
    p.set_defaults(fn=cmd_preflight)

    p = sub.add_parser(
        "lint",
        help="enforce decidable REJECTs and the full timed-KEEP evidence contract",
    )
    p.add_argument("--since", help="git ref; lint only rows added since it")
    p.add_argument("--staged", action="store_true", help="lint only staged ledger rows")
    p.set_defaults(fn=cmd_lint)

    p = sub.add_parser("report", help="class census over the whole ledger")
    p.add_argument("--rows", action="store_true", help="print every screened REJECT anchor")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("audit", help="alias for report: mechanical taxonomy census")
    p.add_argument("--rows", action="store_true", help="print every screened REJECT anchor")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("self-test", help="exercise policy predicates without Cargo")
    p.set_defaults(fn=cmd_self_test)

    p = sub.add_parser(
        "ledger-self-check",
        help="exercise policy against the real ledger and remediation dependents",
    )
    p.set_defaults(fn=cmd_ledger_self_check)

    args = ap.parse_args()
    if not LEDGER.exists():
        print(f"ledger not found: {LEDGER}", file=sys.stderr)
        return EXIT_USAGE
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
