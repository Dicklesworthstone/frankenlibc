# The Ledger Resurrection Method

**Corrected 2026-07-27 procedure, adopting frankenfs's six-class taxonomy verbatim.**

This section is the published method. The original 2026-07-25 V1-V5 procedure is retained after the
retraction marker only as incident history; its census and conclusions must not be copied.

## 1. Pin the audit object

Record the ledger path, Git commit, blob/file SHA-256, line count, heading count, and exact parser
rule before classifying anything. Line anchors are valid only for that pinned object.

The mechanical parser is triage. It may find candidate headings and evidence markers, but it may not
issue a final verdict. Read each candidate section from its heading through the next peer heading.

## 2. Use exactly these six classes

| Class | Definition |
|---|---|
| `VALID-PROFILE` | Rejected before any source edit on a named frame with non-zero self-time plus a computed Amdahl ceiling. |
| `VALID-MECHANISM` | No A/A null, but a counted mechanism refuted the lever: instructions, cycles, syscalls, allocations, or faults did not change. |
| `VALID-AB` | An A/B recorded an A/A null and the effect sits inside it. |
| `VOID-CV` | The row was killed **only** by a `cv < 5` gate. |
| `VOID-ZEROSELF` | The target frame had approximately zero self-time in the profile the benchmark actually ran. |
| `VOID-NONULL` | A near-1.0 A/B wall result has no A/A null and no counted mechanism. |

Apply `VALID-MECHANISM` in both directions. A real count can rescue a row from being wrongly voided;
a noun such as “allocations” or a planned future count cannot.

Do not broaden the definitions to force every regex hit into a class. `INVALID` rows that never
timed, audits, `SURFACE`/`EMPTY` notes, correctness blockers, and design scopes are not rejection
experiments. Exclude them from the six-class denominator after recording their anchors.

The taxonomy also deliberately gives no valid label to a decisive wall-time A/B that has neither an
A/A null nor a counted mechanism. Do not call such a row `VOID-NONULL` when the result is not
near 1.0, and do not call it valid by intuition. Mark it **triage unresolved**, preserve its retry
predicate, and require a human decision. “Triage unresolved” is a screen state, not a seventh class.

## 3. Hand-adjudicate every candidate

For each section, answer in this order:

1. Did a candidate actually execute and produce a decision?
2. Did the workload route through the target code?
3. Is the target frame named and non-zero in the profile the benchmark ran?
4. Is the purported behavior-preservation proof sound for the actual production boundary?
5. Is the rejection based on counted work, an A/A-bounded effect, CV alone, or an unbounded wall
   ratio?
6. Does the body quote future retry evidence as if it belonged to the completed run?
7. What concrete predicate would make a retry different?

Negated evidence does not count: “no A/A was recorded” is not an A/A. Evidence promised under
“retry only when …” belongs to the future and must be excluded from the completed verdict.

## 4. Build and execute the queue

Rank **VOID rows by the target frame's recorded self-time**, descending. Do not substitute total
benchmark duration, a quoted operation latency, or a glibc gap for target-frame self-time. Rows with
no target self-time remain unranked until a valid profile exists.

Read the ranked rows again before scheduling work. Several anchors may be one family or may already
be superseded by later corrected evidence; do not rerun the same mechanism five times merely because
five historical rows occupy the top five positions.

For each actual rerun:

1. The process hashes `current_exe()` and prints the executing ELF SHA-256.
2. The same invocation runs a source-identical A/A null at the same unit of analysis as A/B.
3. Both null and effect report deterministic bootstrap median confidence intervals.
4. The verdict gates on the median CI, never on CV.
5. Behavior parity is proved before timing.

For the fleet contract, let
`half_width = max(abs(null_ci_low - 1), abs(null_ci_high - 1))`.
A claimed effect must be on the favorable side of 1.0, its bootstrap median CI must exclude 1.0,
and `abs(effect_median - 1) > 2 * half_width`. CV may be printed as telemetry but is never an
admission, keep, reject, or retry threshold.

Three consecutive REJECTs trigger the no-ceiling rule: switch veins. A rejection streak is routing
evidence, not permission to stop.

## 5. Institutionalize the forward gate

The audit is incomplete until the repo makes undecidable rows mechanically unwritable:

- `preflight --lever ... --surface ...` searches the target surface, prints the prior retry
  predicate, and exits 2 when a prior REJECT covers it.
- A new or modified REJECT must carry either a counted mechanism or a numeric same-invocation A/A
  with a nearby bootstrap median CI.
- A timed KEEP must carry the same-invocation A/A/null CI, the effect's bootstrap median CI, and an
  in-process executing-ELF SHA-256.
- Any positive CV gate is refused.
- The check runs from the pre-commit chain; exit 2 is a policy block and exit 64 is infrastructure
  failure.

The gate must inspect modified existing rows as well as newly appended headings. It must read the
Git index under `--staged`, ignore evidence that appears only in a future retry predicate, and reject
an adjacent shell `sha256sum` as execution proof.

## 6. Corrected frankenlibc proof case

Pinned target: `docs/NEGATIVE_EVIDENCE.md` at
`0bad50199470b42c15fcc0d35bef8b4fdf6dd9ad`, file SHA-256
`b5dcc5c4c798a98d949fbb2b1a7ef82dae7c269d7bcb154d90d871be300ac49f`, 527 parsed entries and
130 mechanically selected headings.

All 130 sections were read. Forty-seven were actual experiments to which one of the six definitions
could honestly be applied:

| Class | Hand count |
|---|---:|
| `VALID-PROFILE` | 0 |
| `VALID-MECHANISM` | 1 |
| `VALID-AB` | 9 |
| `VOID-CV` | 8 |
| `VOID-ZEROSELF` | 0 |
| `VOID-NONULL` | 29 |

Thus 37/47 classifiable experiments are VOID, and `VOID-NONULL` is 29/37 (78.4%) of the void set.
CV is not the dominant defect. Of the remaining screen hits, 29 are not rejection experiments and
54 are decisive, mixed, correctness-failing, or substrate-invalid rows that the six definitions do
not honestly classify.

The corrected top-five self-time queue is one allocator family:
L17797 (99.56%), L17758 (98.83%), L17903 (96.67%), L18455 (20.23%), and L18406 (19.75%).
Later corrected evidence already executed this family: the membership primitive cleared the median
gate and the per-thread segment-magazine composition subsequently shipped. Lane B therefore does
not rerun those five historical harnesses; it records them as superseded by the corrected sequence.

Thirteen of 130 selected rows contain a 64-hex digest, but only L22998 explicitly records that the
compared binaries self-reported their executing ELF. A digest computed beside a run remains
non-proof.

The complete hand manifest and the 23-commit model-integrity audit are in
[`LEDGER_RESURRECTION.md`](LEDGER_RESURRECTION.md).

## Checklist

```text
[ ] Pin commit, blob/file SHA-256, line count, heading count, and parser rule
[ ] Run the mechanical screen only to build candidate anchors
[ ] Read every candidate section through the next peer heading
[ ] Apply the six definitions verbatim; do not invent evidence or a seventh verdict
[ ] Separate non-decisions and triage-unresolved rows from the class denominator
[ ] Rank VOID only by recorded target-frame self-time
[ ] Collapse duplicate/superseded anchors before rerunning
[ ] Rerun with in-process ELF SHA, same-invocation A/A, and bootstrap median CIs
[ ] Gate on the median CI, never CV; prove behavior first
[ ] After three REJECTs switch veins
[ ] Install and self-test the staged pre-commit gate
```

---

# RETRACTED historical V1-V5 method (2026-07-25)

Everything below this marker is retained only to make the model-integrity correction auditable.
Its V1-V5 taxonomy, 130/131 census, proxy ranking, and six-of-seven yield claim are superseded.

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

## 7. Three measurement traps — check for these before you publish

**`--call-graph dwarf` destroys flat self-time.** A `perf record -g --call-graph=dwarf` profile
charges attribution onto return instructions: one function measured **22.18%** self-time under dwarf,
99% of it on the epilogue `ret`, and **6.68%** on the same binary, workload, pinned core and sample
rate with **no call-graph collection**. Other frames move as far (`segment_free` 4.77 → 22.85), which
is enough to invert a ranking and any structural conclusion drawn from one. Use dwarf to find
*callers*; never to rank self-time.

**Reconcile the profile against the A/B before publishing either.** 22.18% of process cycles cannot
produce a measured 5.4% improvement; 6.68% can. *A profile attribution that cannot be reconciled with
the A/B it motivated is evidence the profile is wrong.* The check costs one minute and catches this
entire class of error.

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
