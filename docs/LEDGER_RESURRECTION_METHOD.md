# The Ledger Resurrection Method

**Current 2026-07-27 procedure, using frankenfs's six-class taxonomy verbatim.**

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

Read the ranked rows again before scheduling work. Several anchors may be one family or later
evidence may already satisfy the current contract; do not rerun the same mechanism five times merely
because five historical rows occupy the top five positions.

For each actual rerun:

1. The process hashes `current_exe()` and prints the executing ELF SHA-256.
2. The same invocation runs a source-identical A/A null at the same unit of analysis as A/B.
3. Both null and effect report deterministic bootstrap median confidence intervals.
4. The verdict gates on the median CI, never on CV.
5. Behavior parity is proved before timing.
6. The result is labelled `campaign-win` or `self-speedup`.

A `campaign-win` compares FrankenLibC against the actual legacy incumbent side-by-side in that same
invocation. In this repo that means host glibc, resolved through an interposition-proof arm such as
`dlmopen(LM_ID_NEWLM)`. A before-versus-after comparison of FrankenLibC is a `self-speedup`: it can
justify maintenance, but it is not campaign output or a competitive claim.

For the fleet contract, let
`half_width = max(abs(null_ci_low - 1), abs(null_ci_high - 1))`.
A claimed effect must be on the favorable side of 1.0, its bootstrap median CI must exclude 1.0,
and `abs(effect_median - 1) > 2 * half_width`. CV may be printed as telemetry but is never an
admission, keep, reject, or retry threshold.

Three consecutive REJECTs trigger the no-ceiling rule: switch veins. A rejection streak is routing
evidence, not permission to stop.

## 5. Institutionalize the forward gate

The audit is incomplete until the repo makes undecidable rows mechanically unwritable:

- `preflight --lever ... --surface ... --comparison legacy-incumbent --incumbent host-glibc`
  searches the target surface, records the intended evidence class, prints the prior retry
  predicate, and exits 2 when a prior REJECT covers it. Use `--comparison self` for maintenance.
- A new or modified REJECT must carry either a counted mechanism or a numeric same-invocation A/A
  with a nearby bootstrap median CI.
- A timed positive must carry the same-invocation A/A/null CI, the effect's bootstrap median CI, and an
  in-process executing-ELF SHA-256.
- Every timed positive row must carry an exact `result_class=campaign-win` or
  `result_class=self-speedup` field. A campaign win additionally requires
  `legacy_incumbent=host-glibc`, an interposition-proof incumbent-provenance field, a
  same-invocation witness, structured incumbent/null bootstrap median CIs, an incumbent-ratio CI
  entirely below 1.0, and the 2× null-half-width margin. A self-speedup must be titled as
  maintenance, never as a win.
- Any positive CV gate is refused.
- The check runs from the pre-commit chain; exit 2 is a policy block and exit 64 is infrastructure
  failure.

The gate must inspect modified existing rows as well as newly appended headings. It must read the
Git index under `--staged`, ignore evidence that appears only in a future retry predicate, and reject
an adjacent shell `sha256sum` as execution proof.

## 6. Frankenlibc proof case

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

The top-five self-time queue is one allocator family:
L17797 (99.56%), L17758 (98.83%), L17903 (96.67%), L18455 (20.23%), and L18406 (19.75%).
The membership primitive and per-thread segment-magazine composition already exercise this family
under the current gate, so the five anchors do not require duplicate harness runs.

Thirteen of 130 selected rows contain a 64-hex digest, but only L22998 explicitly records that the
compared binaries self-reported their executing ELF. A digest computed beside a run remains
non-proof.

The complete hand manifest and supporting evidence are in
[`LEDGER_RESURRECTION.md`](LEDGER_RESURRECTION.md).

## Checklist

```text
[ ] Pin commit, blob/file SHA-256, line count, heading count, and parser rule
[ ] Run the mechanical screen only to build candidate anchors
[ ] Read every candidate section through the next peer heading
[ ] Apply the six definitions verbatim; do not invent evidence or a seventh verdict
[ ] Separate non-decisions and triage-unresolved rows from the class denominator
[ ] Rank VOID only by recorded target-frame self-time
[ ] Collapse duplicate or already-covered anchors before rerunning
[ ] Rerun with in-process ELF SHA, same-invocation A/A, and bootstrap median CIs
[ ] Gate on the median CI, never CV; prove behavior first
[ ] Label incumbent comparisons as campaign-win and before/after comparisons as self-speedup
[ ] After three REJECTs switch veins
[ ] Install and self-test the staged pre-commit gate
```
