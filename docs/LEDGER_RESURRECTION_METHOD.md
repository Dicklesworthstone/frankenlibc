# The Ledger Resurrection Method

**A portable procedure for recovering buried wins from a negative-evidence ledger.**

Written up from frankenlibc's run of it on 2026-07-25, at the campaign's request, so the other ten
repos can copy it rather than re-derive it. frankenlibc is the proof case only because it went first;
nothing here is frankenlibc-specific.

Method extraction and audit: MagentaCondor. Queue execution and final yield reconciliation:
SwiftCastle.

**Result of the worked example: 131 rejections audited, 130 void, 27 worth re-attacking, 7 lever
families rerun, 6 kept.** The audit's complete top-five queue produced **four keeps and one surfaced
frontier**.

---

## 0. The claim, stated so it can be falsified

A negative-evidence ledger is supposed to stop you re-deriving dead ends. It does that job well. What
it silently *also* does is convert **"we could not measure this"** into **"this does not work"** —
and those are not the same statement. Every row that made that conversion is design work you already
paid for, sitting behind a verdict that the evidence never supported.

This method finds those rows. It does **not** find new ideas, and it does not tell you a lever works.
A void verdict says only: *the ledger does not contain evidence that it doesn't.*

**If your ledger's rejections all carry a binary hash, a null control, and a self-time figure for the
frame under test, this method will find nothing and you should skip it.** In practice, run the three
coverage counts in §2 first — they take a minute and they tell you whether to bother.

---

## 1. Pin the target before you read a single row

Everything downstream is a claim about a specific file at a specific instant, and agents are editing
these files continuously.

```bash
sha256sum docs/NEGATIVE_EVIDENCE.md    # the audit target
git rev-parse HEAD                     # the tree it was read at
wc -l docs/NEGATIVE_EVIDENCE.md
```

Record all three at the top of the audit. Anchor every verdict to the **line number of the row's
heading** in that pinned file, so any reader can re-derive it:

```bash
sed -n '21341,+40p' docs/NEGATIVE_EVIDENCE.md
```

Without this, an audit is unreviewable six hours later.

## 2. Measure your provenance coverage first — it decides whether to continue

Three numbers, over REJECT-class rows only:

| count | frankenlibc | what it means |
|---|---|---|
| rows carrying a **binary SHA-256** | 12 / 131 (9.2%) | below ~50%, most rejections are unreproducible in principle |
| rows carrying **any null control** | 22 / 131 (16.8%) | below ~50%, most rejections have no idea what "no effect" looks like |
| rows carrying a **self-time figure** | 16 / 131 (12.2%) | below ~50%, most rejections never checked the bench ran the code |

If all three are high, stop — you have a healthy ledger. frankenlibc's were 9%, 17% and 12%, which is
why 130 of 131 rows turned out void.

## 3. Define the population mechanically, and handle heading drift

A row is REJECT-class if its heading contains `REJECT`, `INVALID`, `NO-SHIP`, `LOSS/DROP`, `KILLED`,
`NOT SHIPPED`, `✗`, or `0-GAIN`, **and does not open with** `WIN`, `LANDED`, `SHIPPED`, `✅`, or
`RETRY EXECUTED` — a win row that retires a prior reject is a win, not a reject.

**Expect several heading grammars.** frankenlibc's ledger has three, accumulated over months:

```
## 2026-07-16 (cod / codex-root) — REJECTED: …
## 2026-07-09 - REJECTED `strchr` SSE4.2 …
## 2026-07-04 — ✗ fallback-cache clear elision REJECTED — …
```

Parsing only the newest grammar found **270** entries. Parsing all three found **514**, and the
REJECT population went from 69 to 131 — **nearly half the population was invisible to the first
parser.** Check your matched count against `grep -c '^## '` before trusting any total.

## 4. Classify: void if any criterion fires

| id | criterion |
|---|---|
| **V1** | every decision ratio the row quotes lies inside the A/A null floor, or it is decided on `~0-gain` / `within noise` with no ratio outside the floor |
| **V2** | no null control was recorded at all |
| **V3** | the target function's self-time was ~0% in the profile the bench actually exercised |
| **V4** | the gate applied was `cv < 5%` on a shared, unpinnable worker |
| **V5** | no binary SHA-256, and concurrent agents were editing the crate in that window |

For the **null floor**, use the *worst* A/A (source-identical arm against itself) median your repo has
ever measured, not a nominal figure. frankenlibc's is 0.9048, giving `[0.905, 1.105]`. Using the worst
observed value is deliberately conservative: it under-counts V1.

### Then split the void set by severity — this is the step that makes it useful

Applied literally, "any criterion" makes almost everything void (130 of 131 here). That number is a
finding about the ledger, but it is useless as a work queue. So tag every void row:

- **decision-defective** — V1, V3 or V4 fired. The verdict *could not have been reached* from the
  measurement. **27 rows.** This is the re-attack pool.
- **provenance-only** — only V2 and/or V5. The verdict is probably right (77 of frankenlibc's 103
  quote a ratio decisively outside the floor, usually a candidate that was measurably *slower*) but
  nobody can check it.

**Rank on the decision-defective subset.** Re-running a row whose candidate was honestly 1.84× slower
is a repeat, not a resurrection.

Note that V3 is usually unevaluable — you cannot check self-time on rows that never recorded any. So
the decision-defective count is a **lower bound**, and provenance-tagged rows may yet be
decision-defective.

## 5. Rank by decidable effect × frame size, then read the top rows by hand

Machine-rank candidates by the largest **per-op** time the row quotes (`11.16 ns/call`). Two traps:

- **Bench configuration is not frame size.** An early pass ranked four rows at "500 ms" — that was
  `at least 500 ms per arm`, a sample length. Filter time quantities sitting in a configuration
  context, and prefer explicitly per-op forms.
- **Audit rows are not levers.** Exclude the ledger's own meta/audit entries from the queue.

Then **read the top rows in full before queueing them.** The machine list is a candidate list. The
two frankenlibc rows that paid were both obvious on reading and neither was top by raw frame size.

## 6. What a resurrection re-run must carry

A rehabilitated row has to clear a bar the original did not, or you have just moved the problem:

1. **Self-reported binary SHA-256** — the binary hashes its own `current_exe()` and prints it. A hash
   computed by a shell step *next to* the run proves nothing about which ELF executed.
2. **An A/A null control in the same invocation**, printed always.
3. **Gate on the median against that null, never on `cv`.** `cv` does not track decidability.
4. **Match the null's unit of analysis to the decision's.** See §7 — this one is subtle and it will
   inflate your margins if you get it wrong.
5. **Behavior proof before timing**, not after.

## 7. Three traps that cost frankenlibc real work — check for these before you publish

**`--call-graph dwarf` destroys flat self-time.** A `perf record -g --call-graph=dwarf` profile
charged one function **22.18%** self-time, 99% of it on the epilogue `ret`. The same binary, workload,
pinned core and sample rate with **no call-graph collection** said **6.68%**. Other frames moved just
as far (`segment_free` 4.77 → 22.85). A published structural conclusion built on the first profile
**fully reversed**. Use dwarf to find *callers*; never to rank self-time.

**Reconcile the profile against the A/B before publishing either.** 22.18% of process cycles cannot
produce a measured 5.4% improvement. 6.68% can. *A profile attribution that cannot be reconciled with
the A/B it motivated is evidence the profile is wrong* — that check costs one minute and would have
caught the above immediately.

**An A/A null has a unit of analysis.** For a two-binary A/B:

| null | value | measures |
|---|---|---|
| in-invocation (arm vs itself, same process) | 0.9999, envelope **±0.03** | within-process noise |
| cross-invocation (base runs vs base runs) | **±0.046** | whole-process noise: layout, ASLR, page colouring |

The second is 1.5× wider, and a two-binary comparison is decided *across* invocations. Using the
tighter floor scored a lever at 2.4× margin; the correct floor scored it 2.03×.

## 8. And one trap about the resurrections themselves

**Shape plausibility is not evidence.** frankenlibc found a defect shape, fixed one instance, measured
it, and shipped at 0.9463×. The *second* instance of the identical shape — same annotate signature,
same clean gates, a larger frame — measured 0.813× on one host and **null on two others**. It was
rejected and stashed.

The difference was not the idea. The shipped one carried a **byte-identical control arm that stayed
inside its null** and **replicated under a changed instrument**. The rejected one replicated nowhere.
When you resurrect a row, you are re-running something a previous agent already believed in; that
belief is not evidence either. Replication is especially important for marginal whole-binary effects
or when one host's absolute timings are anomalous; a second host or changed instrument is the retry,
not a requirement to burn scarce workers on every decisive multi-fold effect. **Distrust a favorable
host whose absolute numbers are 2× the others.**

## 9. Reporting

Emit one row per audited REJECT:

| Entry | Ratio claimed | Frame | Self-time | Sha? | Null? | Verdict | Severity | Criteria | Row |

Plus: the pinned target (§1), the coverage counts (§2), the ranked queue with hand adjudication (§5),
and a **yield table** — audited / void / decision-defective / re-run / re-won — updated as re-runs
land. Publish the yield even when it is zero; a queue that produces nothing is itself a result about
the ranking.

## 10. The checklist

```
[ ] Pin file sha256 + commit + line count; anchor every verdict to a line number
[ ] Count binary-sha / null-control / self-time coverage; stop here if all are high
[ ] Enumerate heading grammars; check matched count against grep -c '^## '
[ ] Classify V1–V5; tag each void row decision-defective vs provenance-only
[ ] Use the WORST observed A/A median as the null floor
[ ] Rank the decision-defective subset by per-op frame size; exclude audit rows
[ ] Read the top rows in full before queueing
[ ] Re-run under: self-reported ELF sha, in-invocation A/A, median-CI gate, behavior proof first
[ ] Match the null's unit of analysis to the decision's
[ ] Re-profile without --call-graph dwarf; reconcile profile share against measured effect
[ ] For marginal/outlier-host effects, replicate on a second quiet host or changed instrument
[ ] Publish the yield table, including zeros
```

---

## Worked example — frankenlibc, 2026-07-25

Target `docs/NEGATIVE_EVIDENCE.md`, sha256 `b296d67a…`, commit `a8308bbda`, 22,582 lines, 691
headings → 514 dated entries → **131 REJECT-class rows** spanning 2026-06-25…07-22.

| metric | value |
|---|---|
| audited | 131 |
| VOID (any of V1–V5) | 130 (99.2%) |
| — decision-defective | **27** |
| — provenance-only | 103 |
| SOUND | 1 |
| re-run | **7** |
| **re-won / kept** | **6** |
| surfaced with no production keep | **1** |

| row | lever | why void | outcome |
|---|---|---|---|
| L6150 | lock-free `native_stdio` FILE\*-cache | V1: `~0-gain`, 56.7 → 60.4 ms against its own 15–74 ms spread | `ad465633f` — MT `fgetc` **17.5–18.7×** |
| L18406 family | per-thread segment magazines | V4: an all-six-CV gate included three arms the decision did not use | `15f58c419` — **18.7–19.4%** vs ORIG |
| L21341 | exact `strftime("%A")` transducer leaf | V4: rejected because the *null's* CV was 5.10%, 0.10 over the gate | `ac74b07bc` — FL/glibc median **0.5406** |
| L21570 | `textdomain(NULL)` mutex → atomic publication | V4: decisive 5.5969 ratio, 1.0016 null, rejected on raw-arm CV | `8320a0b4a` — **11.32 ns → 2.58 ns** |
| L16566 | general-loop `strftime` fixed floor | V1+V2: ~0-gain sub-lever did not attack the named floor | exact/literal claim narrowed; non-exact mixed-name path **9.2778× slower** — **SURFACE** |
| L21545 | exact `%FT%T` `wcsftime` alias | V1+V4: 1.05 center inside the floor, rejected on CV | `3c03993b1` — candidate/original **0.067613** |
| L21131 / L21277 | allocation-free hosts scanner | V4: file-backed fixture obscured the mechanism | `3aedb3f69` — candidate/original **0.428468** on immutable in-memory snapshot |

The top five demonstrate three distinct rehabilitation moves: rerun a strong old signal under the
correct gate (ranks 1–2), change the workload when the old retry predicate says the fixture is
non-discriminating (ranks 4–5), and publish a narrowed residual when the rerun does not justify a
source keep (rank 3). A resurrection method that records only wins is another biased ledger.

**Cost:** roughly one agent-session for the audit, plus a re-run each. **The design work was already
paid for; only the measurement had to be redone.**

Full audit and per-row table: [`LEDGER_RESURRECTION.md`](LEDGER_RESURRECTION.md).
