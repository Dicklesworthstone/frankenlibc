# FrankenLibC Ledger Resurrection Audit

Fleet campaign 2026-07-25, Meta-Lever #1. **cc lane deliverable.**

This audits every REJECT-class row in `docs/NEGATIVE_EVIDENCE.md` and asks one question per
row: *could the measurement that produced this rejection have detected the lever at all?*
A row is **VOID** when the answer is no. VOID is not a claim that the lever works — it is a
claim that **the ledger does not contain evidence that it doesn't**, so the design work is
unpaid-for inventory rather than a closed door.

Four rows in this ledger have now been resurrected and all four paid: see §4.

---

## 1. Immutable audit target

| field | value |
|---|---|
| file | `docs/NEGATIVE_EVIDENCE.md` |
| lines | 22,582 |
| file SHA-256 | `b296d67a9f711de0e01f663d20d861a3b4b854daedd31973a604351ded59800b` |
| git blob | `7fbc47366f20f84ec704b445cc529a6d6cc2a0c2` |
| source commit | `a8308bbda09ce19c9bfd72a016167226902ea186` |
| sections (`^## `) | 691 headings → 514 dated entries |
| audited population | **131 REJECT-class entries**, 2026-06-25 … 2026-07-22 |
| auditor | cc_fl / MagentaCondor |

The scan is read-only; no historical row was rewritten. `L<n>` in the tables below is the
1-indexed line of that row's `##` heading in the target file above, so every verdict is
re-checkable with `sed -n 'L,+40p' docs/NEGATIVE_EVIDENCE.md`.

**Population definition.** An entry is REJECT-class if its heading opens with, or contains,
one of `REJECT`, `INVALID`, `NO-SHIP`, `LOSS/DROP`, `KILLED`, `NOT SHIPPED`, `✗`, `0-GAIN`,
*and* does not open with a win marker (`WIN`, `LANDED`, `SHIPPED`, `✅`, `RETRY EXECUTED`) —
a win row that retires a prior reject is a win, not a reject. Three heading grammars are in
use across the file's history (`## date (who) — VERDICT:`, `## date - VERDICT`,
`## date — ✗ …`); all three are parsed.

## 2. VOID criteria

Campaign Meta-Lever #1 is explicit: **mark an entry VOID if ANY of these hold.** That rule is applied
literally here.

| id | criterion | what it means |
|---|---|---|
| **V1** | every decision ratio the row quotes lies inside the A/A null floor `[0.905, 1.105]`, or the row is decided on `~0-gain` / `within noise` language with no ratio outside the floor | the harness was rejected, not the lever |
| **V2** | no null control was recorded at all | nothing establishes what "no effect" looks like on that bench |
| **V3** | the target function's self-time was ~0% in the profile the bench exercised | the workload never routed through the code under test |
| **V4** | the gate applied was `cv < 5%` on a shared, unpinnable rch worker | that gate is unreachable on this hardware, so rejections on it carry no information |
| **V5** | no binary SHA-256 was recorded, and concurrent agents were editing the crate in that window | the row cannot be tied to a binary; in this repo the second conjunct is always true |

### Severity split *within* VOID

VOID under the contract is a wide net — by design, since its purpose is to find buried inventory. But
"the ratio sat inside the noise floor" and "the row is right but unreproducible" are different
failures and they justify different follow-ups, so every VOID row is also tagged:

- **decision** — V1, V3 or V4 fired. The *verdict itself* could not have been reached from the
  measurement. These are the re-attack candidates.
- **provenance** — only V2 and/or V5 fired. The verdict is probably correct (of these rows, 77 quote a
  ratio decisively outside the null floor, usually a candidate that was measurably *slower*), but
  nothing identifies the binary or the noise floor, so no one can check it.

Ranking in §5 uses the severity tag, not the bare VOID flag: re-running a row whose candidate was
honestly 1.84x slower is not a resurrection, it is a repeat.

**The null floor.** `[0.905, 1.105]` is the worst A/A (source-identical arm vs itself) paired median
ever measured in this repo: **0.9048**, on `vmi1152480`, binary SHA-256
`591a0cfae73c52918271c4025edc9a16c70d5fabf0c1785780295165a28e2327`. Using the *worst* observed A/A as
the floor is deliberately conservative for V1: it under-counts decision-defective rows.

**Frame size.** The "frame" column is the largest per-op time the row quotes (`11.16 ns/call`),
falling back to the largest bare sub-millisecond time not sitting in a bench-configuration context.
`at least 500 ms per arm` is a sample length and is excluded — an earlier pass of this audit ranked
four rows at "500 ms" before that filter was added. `n/r` = the row quotes no per-op time. This is a
proxy for how much time the rejected lever was gating, and it is what the resurrection queue is
ranked on.

## 3. Aggregate result

| metric | value |
|---|---|
| REJECT rows audited | **131** |
| **VOID** (contract rule: any of V1-V5) | **130 (99.2%)** |
| — of which **decision**-defective (V1/V3/V4 fired) | **27** |
| — of which **provenance**-only (V2/V5 only) | **103** |
| SOUND (no criterion fired) | **1** |
| rows carrying a binary SHA-256 | 12 / 131 (9.2%) |
| rows carrying any null control | 22 / 131 (16.8%) |
| rows carrying a self-time figure | 16 / 131 (12.2%) |

**130 of 131 is not a rounding artifact of a loose rule — it is the finding.** Only 12 rows can be
tied to a binary and only 22 recorded any null control, so under the campaign's criterion nearly the
entire rejection history of this project is inadmissible as evidence. The practical consequence is
the severity split: **27 rows were decided by a measurement that could not have seen the effect**, and
those are worth re-running; the other 103 are probably-correct verdicts that simply cannot be
audited.

V3 (zero self-time) could not be evaluated mechanically — only 16 rows record self-time at all, which
is itself the finding: **88% of this ledger's rejections never checked whether the bench executed the
code under test.** Rows tagged `provenance` may therefore still be `decision`-defective under V3. The
27 is a **lower bound.**

## 4. Already-resurrected rows — four proof cases

The first two were found by the earlier phase-1/phase-2 audits (L17605, L18230, L18322).
The next two are ranks 1 and 2 from this audit's §5 queue, rerun under the 2026-07-25
self-identifying, same-invocation null-control, bootstrap-median-CI contract:

| row | lever | why it was VOID | outcome |
|---|---|---|---|
| **L6150** | lock-free `native_stdio` FILE\*-cache | rejected on `~0-gain` (56.7 → 60.4 ms against its own 15–74 ms spread) — V1, no null, no sha | reopened → **`ad465633f`, MT `fgetc` 17.5–18.7× faster**, fl-vs-glibc 55× → 2.96× |
| **L18406 / L18455 / L18490** | per-thread segment magazines + address-derived segment ownership | CAND/ORIG **0.775–0.854 across 4 sizes × 3 runs** (12/12 favorable), binary shas recorded, allocator self-time 19.7–20.2% — rejected because an all-six-CV gate included raw arms and an ORIG/glibc contrast *that do not contain the candidate* — V4 | gate corrected → **`15f58c419` shipped, 18.7–19.4% vs ORIG** |
| **L21341** `bd-agegst` | exact `strftime("%A")` finite-state transducer leaf | V4: the old gate rejected a 0.5415 ratio because null CV was 5.10% | rerun on `vmi1293453`, ELF `949b2064…d67c`: null median **0.996870**, CI **[0.983412, 1.009033]**; FL/glibc median **0.540615**, CI **[0.537130, 0.549644]**, clears 2× null → **`ac74b07bc` shipped** |
| **L21570** `bd-bl39l2` | append-only atomic publication for `textdomain(NULL)` | V4: the old row had a decisive 5.5969 ratio and a 1.0016 null but rejected raw-arm CV | baseline ELF `21274b1a…ef763`: **11.32 ns** FL; candidate ELF `aef6adcf…1e12f`: **2.58 ns** FL on the same worker, a **4.39× self-speedup**. Candidate null CI **[0.986901, 1.047500]**; residual FL/glibc median **1.192201**, CI **[1.152714, 1.250319]** → **`8320a0b4a` shipped**, residual retained as frontier |

The L18406 family is the cleaner proof: the lever was never in doubt (12 of 12 size×run points
favorable, with a recorded binary SHA-256), and it sat rejected for the length of time it took
someone to notice that three of the six gated CVs were computed on arms the decision did not use.

## 5. Resurrection queue (VOID rows, hand-adjudicated, ranked by yield)

Ranked by *decidable effect × frame size*, not frame size alone. Meta/audit rows (L18230,
L18322, L17605) are excluded — they are audits, not levers. Each row below was read in full
before being ranked; the machine table in §6 is a candidate list, this is the adjudication.

| # | row | lever | measured | why VOID | disposition |
|---|---|---|---|---|---|
| **1** | **L21341** `bd-agegst` | exact `strftime("%A")` finite-state transducer leaf | **0.5705** on `ovh-a` and **0.5415** on `vmi1149989` — two independent runs, 1.75× and 1.85×; FL/FL null **0.9982** / 1.0181 | V4 — rejected because the *null* paired CV was **5.10%**, i.e. 0.10 points over an unreachable gate | **DONE / KEEP (`ac74b07bc`).** New contract rerun: null CI **[0.983412, 1.009033]**, FL/glibc CI **[0.537130, 0.549644]**, all-capacity behavior and 200,000-case differential gates green. |
| **2** | **L21570** `bd-bl39l2` | RCU/atomic publication for the `textdomain(NULL)` query | fl **11.16 ns/call** vs glibc **1.99 ns/call**, paired median **5.5969**; FL/FL null **1.0016** at 4.60% paired CV | V4 — rejected because raw-arm CVs exceeded 5%, though the effect is 5.6× | **DONE / KEEP (`8320a0b4a`).** Same-worker FL self-time **11.32 → 2.58 ns (4.39×)**; candidate null CI **[0.986901, 1.047500]**. Residual **1.192201×** FL/glibc remains an attributed frontier, not hidden as parity. |
| **3** | **L16566** | `strftime` general-loop **~200 ns fixed per-call overhead** | no ratio; recorded as a LOSS/DROP blocker | V1+V2 — dropped on "~0-gain" for the *literal-push* sub-lever, while naming a 200 ns fixed cost it did not attack | Same frame as #1 and strictly larger. If the `%A` leaf is worth 1.8×, the fixed per-call overhead behind *every* format is the structural target. |
| **4** | **L21545** `bd-vihwy9` | exact `%FT%T` `wcsftime` alias emitter | 1.05, frame 267 ns/call | V1+V4 — the ratio is *inside* the floor | Honest null. Retry only on a workload where the emitter is not 1.05×; do not re-run as-is. |
| **5** | **L21131 / L21277** `bd-9x1jcx` | three sub-2× `hosts_*` resolver rows | CAND/ORIG 0.2710 / 0.3802 but **raw-arm CVs 82–475%** | V4 nominally | **Genuinely undecidable, not a harness bug.** These are file+network paths; the dispersion is real. Needs a different workload shape (warm-cache, in-memory `/etc/hosts`), not a quieter worker. |

Ranks 6+ (all severity=decision) are the `FlatCombiner` / `RcuCell` / `LeftRight` / Bloom-`hash2` cluster (L1939, L1983,
L2184, L2338, L2462, L2496): all six carry binary SHA-256s and all six are decided on ratios of
0.97–1.03 with **no null control**. They are VOID by V1+V2, but the honest reading is that these
are genuinely sub-floor micro-levers on a contended structure — the correct retry is a workload
where the structure is the bottleneck, not a re-measurement of the same 0.98.

## 6. Full per-row audit table

131 rows, ordered decision-defective → provenance-only → sound, then by frame size descending.

Columns: **Entry** (heading line in the audit target) · **Ratio claimed** (decision ratios the
row quotes) · **Frame** (largest per-op time quoted) · **Self-time** (of the target frame, if
recorded) · **Sha?** (binary SHA-256 recorded) · **Null?** (any A/A control recorded) ·
**Verdict** · **Severity** (decision vs provenance) · **Criteria** · **Row**.

| Entry | Ratio claimed | Frame | Self-time | Sha? | Null? | Verdict | Severity | Criteria | Row |
|---|---|---|---|---|---|---|---|---|---|
| L18230 | 2026-07-10 | 0.9 | 158.8 us | 96.67 | no | yes | **VOID** | decision | V4; V5 | 92 REJECT rows, **0% carry a sha256**, **51% are decided inside the null floor** — and the # |
| L6150 | 2026-06-27 | none quoted | 47.3 us | none | no | no | **VOID** | decision | V1; V2; V5 | ❌ lock-free native_stdio FILE*-cache REJECTED (~0-gain; masked by main registry lock) |
| L21131 | 2026-07-22 | 1.67, 1.96, 2.08 | 11.7 us | none | no | yes | **VOID** | decision | V4; V5 | per-function NULL controls cannot adjudicate the three sub-2x hosts rows on the admitted rem |
| L21277 | 2026-07-22 | 0.23, 2.27 | 9.0 us | none | no | yes | **VOID** | decision | V4; V5 | `hosts_reverse` long-block NULL-control retry still exceeds the 5% gate (`bd-9x1jcx`) |
| L152 | 2026-07-16 | 1.01331 | 6.6 us | none | no | yes | **VOID** | decision | V1; V5 | cached-name `cuserid` copy stayed inside the null floor (`bd-sl1c12`) |
| L21545 | 2026-07-22 | 1.05 | 267.52 ns | none | no | yes | **VOID** | decision | V1; V4; V5 | exact `%FT%T` `wcsftime` alias emitter baseline (`bd-vihwy9`) |
| L260 | 2026-07-16 | 1.0521 | 256.65 ns | none | no | yes | **VOID** | decision | V1; V5 | strict `getrlimit` policy bypass stayed below the null-control floor (`bd-16jorw`) |
| L16566 | 2026-07-04 | none quoted | 220.00 ns | none | no | no | **VOID** | decision | V1; V2; V5 | strftime general-loop cost is a ~200ns FIXED per-call overhead, NOT the literal push! loop |
| L21341 | 2026-07-22 | 0.5415 | 200.00 ns | none | no | yes | **VOID** | decision | V4; V5 | exact `strftime("%A")` finite-state transducer leaf (`bd-agegst`) |
| L4169 | 2026-07-04 | 0.996 | 30.86 ns | none | no | no | **VOID** | decision | V1; V2; V5 | ✗ fallback-cache clear elision REJECTED — `calloc/free(16)` only 0.4% faster, within noise |
| L6975 | 2026-06-27 | none quoted | 30.30 ns | none | no | no | **VOID** | decision | V1; V2; V5 | ❌ wcschr fold-removal / hot-cold split DISPROVEN — ~0-gain, codegen-bound — REVERTED (cc) |
| L16421 | 2026-07-04 | none quoted | 28.00 ns | none | no | no | **VOID** | decision | V1; V2; V5 | malloc double-slot-resolve elision is ~0-gain (0.98x), dropped |
| L518 | 2026-07-15 | 1.101 | 14.48 ns | none | no | no | **VOID** | decision | V1; V2; V5 | strict `mtx_lock` tracked-bounds bypass did not clear the identical-code floor (`bd-20umin`) |
| L21570 | 2026-07-22 | 5.5969 | 11.16 ns | none | no | yes | **VOID** | decision | V4; V5 | RCU snapshot for `textdomain(NULL)` query (`bd-bl39l2`) |
| L1269 | 2026-07-14 | none quoted | 9.79 ns | 96.67 | no | yes | **VOID** | decision | V4; V5 | paired-bootstrap segment-membership gate never reached timing (`bd-t43kz2`) |
| L18406 | 2026-07-10 | none quoted | 9.79 ns | 18.50 | yes | no | **VOID** | decision | V2; V4 | per-thread segment magazines win 21.9-22.5%, but CPU0 drift fails the mandatory all-CV <5% g |
| L17903 | 2026-07-10 | none quoted | 6.08 ns | 96.67 | no | no | **VOID** | decision | V2; V4; V5 | REJECT / CONCRETE BLOCKER (code reverted): pinned 134M-op segment bitmap still misses the <5 |
| L18322 | 2026-07-10 | 0.161, 0.905 | 6.08 ns | 96.67 | yes | yes | **VOID** | decision | V4 | REHABILITATION under MEDIAN-GATING: the segment-membership REJECTs are VOID and the primitiv |
| L1849 | 2026-07-14 | 0.9053, 0.9788 | 4.78 ns | none | no | no | **VOID** | decision | V1; V2; V5 | `wcswidth` 128-wide ASCII fold misses its first-active-tier floor; **7.0843 -> 6.9341 ns at  |
| L1939 | 2026-07-14 | 0.99476, 1.0053 | n/r | none | yes | no | **VOID** | decision | V1; V2 | lazy BRAVO secondary-slot hash is below the direct-read floor; **12.410 -> 12.345 ns** |
| L1983 | 2026-07-14 | 0.9712, 1.0297 | n/r | none | yes | no | **VOID** | decision | V1; V2 | decompose FlatCombiner pass-counter RMW pair; **171.22 -> 176.30 ns** |
| L2184 | 2026-07-13 | 0.9833 | n/r | none | yes | no | **VOID** | decision | V1; V2 | lazy Bloom `hash2` is below the deployed foreign-miss floor; **20.283 -> 19.944 ns** |
| L2338 | 2026-07-13 | 0.9841, 1.0161 | n/r | none | yes | no | **VOID** | decision | V1; V2 | removing FlatCombiner's write-only active flag is below the deployed floor; **206.85 -> 203. |
| L2462 | 2026-07-13 | 1.0081 | n/r | none | yes | no | **VOID** | decision | V1; V2 | replacing the mutex-serialized `RcuCell` epoch RMW is neutral; **75.608 -> 76.220 ns** |
| L2496 | 2026-07-13 | 1.0099 | n/r | none | no | no | **VOID** | decision | V1; V2; V5 | deriving LeftRight reads from cache classifications is neutral and loses retry telemetry; ** |
| L18455 | 2026-07-10 | none quoted | n/r | 20.23 | yes | no | **VOID** | decision | V2; V4 | quiet-CPU 4x run proves both paired candidate contrasts stable below 5% (bd-dcrhgl) |
| L18490 | 2026-07-10 | 0.9048 | n/r | 19.69 | yes | yes | **VOID** | decision | V4 | paired decision gate fails on known-noisy vmi1152480; production lever still wins every size |
| L7407 | 2026-06-26 | 0.72, 1.74, 3.06 | 977.7 us | none | no | no | **VOID** | provenance | V2; V5 | qsort mixed-sign finite f64 radix lane REJECTED (1.74x LOSS vs glibc) (BoldWaterfall) |
| L6645 | 2026-06-27 | none quoted | 859.0 us | none | no | no | **VOID** | provenance | V2; V5 | cc INDEPENDENTLY re-confirmed REJECT + localized the real bottleneck (cc) |
| L6659 | 2026-06-27 | 1.24, 42.7, 53.1 | 712.3 us | none | no | no | **VOID** | provenance | V2; V5 | regex PikeVm `Thread.slots` Rc COW REJECTED (573.70 µs → 712.31 µs; 53.1x vs glibc) |
| L8430 | 2026-06-25 | 0.026, 0.038, 0.048 | 256.9 us | none | no | no | **VOID** | provenance | V2; V5 | passwd name-lookup cache/invalidation no-ships (BoldWaterfall) |
| L6460 | 2026-06-27 | 5.4 | 97.6 us | none | no | no | **VOID** | provenance | V2; V5 | ❌ regex build-bulk-table-once-per-search ~0-gain (REVERTED) + new litprefix gap (cc) |
| L6225 | 2026-06-27 | 0.309, 0.69, 2.58 | 53.4 us | none | no | no | **VOID** | provenance | V2; V5 | regex no-slot boolean DFA LANDED for no-prefilter EREs; broad prefilter shortcut REJECTED |
| L7754 | 2026-06-25 | 0.321, 3.1 | 37.4 us | none | no | no | **VOID** | provenance | V2; V5 | regex required-SUBSTRING fast-reject LANDED — 3.1x WIN on scattered-byte no-match (cc) |
| L56 | 2026-07-16 | 0.889546 | 31.3 us | none | no | yes | **VOID** | provenance | V5 | 32 KiB `getdents64` refill regressed `readdir` drain (`bd-wv6wzk`) |
| L6619 | 2026-06-27 | 3.39, 5.17, 5.46 | 12.3 us | none | no | no | **VOID** | provenance | V2; V5 | `fputs` native-stdio root cache REJECTED (no same-worker win proof; 5.17x vs glibc baseline) |
| L8062 | 2026-06-25 | 2.93, 3.43 | 4.8 us | none | no | no | **VOID** | provenance | V2; V5 | optimized strlen does not clear glibc (BoldWaterfall) |
| L6172 | 2026-06-28 | 1.05, 2.96, 3.27 | 4.3 us | none | no | no | **VOID** | provenance | V2; V5 | ❌ fputs raw registered-stream bypass REJECTED (1.050x vs ORIG; 2.96x LOSS vs glibc) |
| L6123 | 2026-06-28 | 1.106 | 3.9 us | none | no | no | **VOID** | provenance | V2; V5 | fputs write-stream TLS pointer cache REJECTED (1.106x smoke vs ORIG; 2.77x LOSS vs glibc) |
| L6388 | 2026-06-27 | 4.04, 4.08 | 3.9 us | none | no | no | **VOID** | provenance | V2; V5 | `fputs` registry parking_lot swap REJECTED (4.04x -> 4.08x vs glibc, reverted) |
| L5720 | 2026-06-28 | 0.984, 3.47 | 3.6 us | none | no | no | **VOID** | provenance | V2; V5 | `fmemopen("w")` per-stream write cursor REJECTED (~0-gain; 0.984x vs ORIG, still 3.47x slowe |
| L7933 | 2026-06-26 | 0.192, 1.76, 4.652 | 3.6 us | none | no | no | **VOID** | provenance | V2; V5 | mbstowcs short-ASCII mixed path REJECTED: faster but still 1.76x LOSS vs glibc (BoldWaterfal |
| L8078 | 2026-06-25 | 0.012, 0.123, 0.135 | 2.7 us | none | no | no | **VOID** | provenance | V2; V5 | regex required-literal fast-reject: LANDED CODE WIN (10x loss → 6-83x WIN) (cc) |
| L18097 | 2026-07-10 | none quoted | 2.6 us | yes, no % | no | no | **VOID** | provenance | V2; V5 | the remaining resolver micro-allocations cannot be honestly attempted under the current REJE |
| L1470 | 2026-07-14 | 1.074, 1.12, 1.151 | 2.5 us | none | no | no | **VOID** | provenance | V2; V5 | direct `newfstatat` group fingerprint probe; **1149.296 -> 1287.188 ns (1.120x)** (`bd-alkov |
| L18828 | 2026-07-11 | 0.74 | 2.2 us | none | no | no | **VOID** | provenance | V2; V5 | f64 `sincos` common-band FMA reduction — libm::sincos already beats glibc (cc-sincos-band) |
| L3663 | 2026-07-09 | 0.22, 0.485 | 2.0 us | none | no | no | **VOID** | provenance | V2; V5 | hottest paths mapped to no-retry families; no source lever |
| L7901 | 2026-06-26 | 0.148, 0.204, 2.057 | 1.5 us | none | no | no | **VOID** | provenance | V2; V5 | mbstowcs partial-prefix + 2-byte gate REJECTED: mixed still 2.06x LOSS vs glibc (BoldWaterfa |
| L7385 | 2026-06-26 | 1.87, 1.979 | 900.61 ns | none | no | no | **VOID** | provenance | V2; V5 | qsort `char*` sampled width-8 natural-order gate REJECTED (1.98x LOSS) (BoldWaterfall) |
| L5599 | 2026-06-29 | 0.89, 1.2, 2.1 | 560.00 ns | none | no | no | **VOID** | provenance | V2; V5 | `WideCharSet` [u64;2] bitmap REJECTED + the "wcsspn 2.6x glibc" residual was an INPUT ARTIFA |
| L21479 | 2026-07-22 | 1.11, 63.3 | 500.00 ns | none | no | no | **VOID** | provenance | V2; V5 | SCOPE COMPLETE (bd-h0n1mf shovel-ready): per-FILE registry refactor site census; sharding re |
| L8454 | 2026-06-25 | 1.51, 1.56, 1.67 | 462.90 ns | none | no | no | **VOID** | provenance | V2; V5 | iconv CP932->UTF-16 compact-row no-ship (BoldWaterfall) |
| L3426 | 2026-07-09 | 1.111 | 375.75 ns | none | no | no | **VOID** | provenance | V2; V5 | REJECTED `%f` binary64 classifier decision DAG - 1.111x vs ORIG (slower) |
| L3329 | 2026-07-09 | 5.893 | 337.02 ns | none | no | no | **VOID** | provenance | V2; V5 | REJECTED `strchr` SSE4.2 explicit-length compare scanner - 5.893x vs ORIG (slower) |
| L1818 | 2026-07-14 | 0.216, 0.559, 0.732 | 282.64 ns | none | no | no | **VOID** | provenance | V2; V5 | direct-pointer `strverscmp` removes prescans but regresses equal long strings; **258.06 -> 2 |
| L7182 | 2026-06-26 | 1.96, 3.2, 4.4 | 263.00 ns | none | no | no | **VOID** | provenance | V2; V5 | ❌ strspn 2-shuffle (Langdale/Lemire) classifier REJECTED — 4–6x SLOWER (cc) |
| L4870 | 2026-06-30 | 0.44, 0.54, 0.69 | 249.80 ns | none | no | no | **VOID** | provenance | V2; V5 | ✗ FUSED span extended to MEDIUM sets (5..=8 bytes, 8-way SIMD-eq) REJECTED — net REGRESSION  |
| L682 | 2026-07-15 | none quoted | 228.48 ns | none | no | yes | **VOID** | provenance | V5 | strict `getentropy` tracked-capacity bypass did not clear noise (`bd-lxm38p`) |
| L7465 | 2026-06-26 | 0.178, 0.221, 1.33 | 208.90 ns | none | no | no | **VOID** | provenance | V2; V5 | %M:%S` exact fast path REJECTED (Criterion gate 1.33x LOSS) (BoldWaterfall) |
| L5350 | 2026-06-29 | 2.3 | 177.00 ns | none | no | no | **VOID** | provenance | V2; V5 | fused 2-pass strspn kernel REJECTED (loses to 4-pass for common sizes; real gap is glibc SIM |
| L6261 | 2026-06-27 | 0.967, 9.9, 10.83 | 124.32 ns | none | no | no | **VOID** | provenance | V2; V5 | ❌ calloc/free(16) same-thread tombstone reinsertion REJECTED (~0-gain; 9.90x LOSS vs glibc) |
| L872 | 2026-07-15 | none quoted | 123.56 ns | none | no | no | **VOID** | provenance | V2; V5 | compiler-TLS kernel-TID cache for `pthread_getspecific` (`bd-2of7hb`) |
| L16803 | 2026-07-10 | 13.2 | 121.54 ns | none | no | no | **VOID** | provenance | V2; V5 | REJECT - bd-dcrhgl Swing-2 PageOracle-checked inline header proof |
| L2881 | 2026-07-10 | 1.2741 | 91.06 ns | yes, no % | no | yes | **VOID** | provenance | V5 | checked `gmtime` civil-result reuse regresses median self-time **1.2741x**; source and bench |
| L4072 | 2026-07-04 | 1.84, 4.82, 5.44 | 74.84 ns | none | no | no | **VOID** | provenance | V2; V5 | ✗ cached tombstone reinsertion REJECTED — local same-target `calloc/free(16)` regressed 1.84 |
| L6302 | 2026-06-27 | 1.84 | 56.00 ns | none | no | no | **VOID** | provenance | V2; V5 | ❌ f32 `sincosf` fused fast-reduction REJECTED (1.84x LOSS vs glibc) — do not retry |
| L2855 | 2026-07-10 | 9.7 | 55.00 ns | none | no | no | **VOID** | provenance | V2; V5 | ALLOCATOR FRAMING PROFILE + REJECT (reverted): the small-churn 9.7x is near-optimal; slot-lo |
| L9 | 2026-07-16 | 0.724475, 1.33316, 1.38031 | 53.10 ns | none | no | yes | **VOID** | provenance | V5 | fused BSD IPv4 component scan regressed `inet_addr` (`bd-us7dho`) |
| L7127 | 2026-06-27 | 0.95, 1.01, 1.15 | 51.76 ns | none | no | no | **VOID** | provenance | V2; V5 | ❌ strspn set6 true pshufb/AVX2 classifier: standalone wins, production route REJECTED (BoldW |
| L18616 | 2026-07-10 | 0.45, 0.48, 0.5 | 50.00 ns | none | no | no | **VOID** | provenance | V2; V5 | SURFACE (fresh gap, BLOCKED by bit-exact gate): glibc-2.42 flipped f64 tan/sin/cos to LOSSES |
| L6341 | 2026-06-27 | 7.19, 7.58 | 44.37 ns | none | no | no | **VOID** | provenance | V2; V5 | strict `calloc/free(16)` cached host-call guard bypass REJECTED (7.58x -> 7.19x vs glibc; so |
| L5297 | 2026-06-29 | 1.4 | 44.30 ns | none | no | no | **VOID** | provenance | V2; V5 | `byte_membership_table` [bool;256]→[u64;4] bitmap REJECTED (1.4x REGRESSION — per-lookup shi |
| L17275 | 2026-07-10 | 0.079, 0.103, 8 | 37.90 ns | none | no | no | **VOID** | provenance | V2; V5 | production 4MiB segment heap loses 6.1-7.7% to the retained malloc/free path (bd-dcrhgl) |
| L17758 | 2026-07-10 | 0.174 | 30.68 ns | 98.83 | no | no | **VOID** | provenance | V2; V5 | exact no-deref 4MiB segment membership is 1.708ns, but paired CV is 13.20% (bd-dcrhgl) |
| L5463 | 2026-06-29 | 0.86, 1.06, 1.3 | 22.00 ns | none | no | no | **VOID** | provenance | V2; V5 | fused wide copy-scan kernel for wcscpy REJECTED (~0-gain end-to-end; the 2-pass copy is not  |
| L8382 | 2026-06-25 | 1.47, 1.49, 1.94 | 20.34 ns | none | no | no | **VOID** | provenance | V2; V5 | f64 `lgamma` via `log(tgamma_reduced)` partial no-ship (BoldWaterfall) |
| L5828 | 2026-06-28 | 1.43 | 20.00 ns | none | no | no | **VOID** | provenance | V2; V5 | ❌ f32 `fmodf` f64-widen candidate REJECTED (worker noise flagged it; deployed already wins)  |
| L17605 | 2026-07-10 | 1.42, 1.56, 1.67 | 19.59 ns | yes, no % | no | no | **VOID** | provenance | V2; V5 | LEDGER-INTEGRITY AUDIT (dead-code-bench rule): one UNSOURCED no-retry VOIDED (it was mine),  |
| L4387 | 2026-07-04 | none quoted | 18.96 ns | none | no | no | **VOID** | provenance | V2; V5 | ◇ bd-dcrhgl inline-header size tracking MEASURED 31x faster than the legacy fallback table,  |
| L16575 | 2026-07-10 | none quoted | 16.65 ns | none | no | no | **VOID** | provenance | V2; V5 | bd-dcrhgl existing-table guarded inline header is safe but slower (17.57ns -> 18.29ns) |
| L5992 | 2026-06-27 | 1.18, 1.29 | 13.76 ns | none | no | no | **VOID** | provenance | V2; V5 | ❌ f32 `lgammaf` = log(tgamma) candidate REJECTED (1.29x slower than deployed libm) |
| L3715 | 2026-07-08 | 1.341, 1.37, 2.13 | 11.83 ns | none | no | no | **VOID** | provenance | V2; V5 | REJECTED core `MallocState` exact 64/256 hot-cycle precheck - 0-gain vs ORIG, source reverte |
| L1606 | 2026-07-14 | 0.5, 0.887, 1.179 | 11.74 ns | none | no | no | **VOID** | provenance | V2; V5 | finite `hypot` zero-axis shortcut halves axis latency but taxes general calls; **9.96 -> 11. |
| L7616 | 2026-06-25 | 2.2, 2.4, 2.448 | 11.00 ns | none | no | no | **VOID** | provenance | V2; V5 | strcoll 2.4x LOSS (C-locale = strcmp floor) — REJECT (cc) |
| L7204 | 2026-06-26 | 2.61 | 10.56 ns | none | no | no | **VOID** | provenance | V2; V5 | ❌ memrchr "drop the 128-fold tier" REJECTED — ~0-gain / regression (same-process A/B) (cc) |
| L8415 | 2026-06-25 | 1.02, 1.13 | 10.23 ns | none | no | no | **VOID** | provenance | V2; V5 | f32 `expm1f` symmetric fast-path no-ship (BoldWaterfall) |
| L3795 | 2026-07-08 | 2.5, 2.52 | 9.90 ns | none | no | no | **VOID** | provenance | V2; V5 | no scratch win to land; allocator residual remains structural, no rejected lever retried |
| L8370 | 2026-06-25 | 1.15, 1.48 | 8.24 ns | none | no | no | **VOID** | provenance | V2; V5 | f32 `log1pf` thresholded `logf(1+x)` no-ship (BoldWaterfall) |
| L8333 | 2026-06-25 | 1.36 | 7.95 ns | none | no | no | **VOID** | provenance | V2; V5 | f32 `acoshf` native-`logf` hot band no-ship (BoldWaterfall) |
| L17797 | 2026-07-10 | none quoted | 6.72 ns | 99.56 | no | no | **VOID** | provenance | V2; V5 | lookup-only ABBA bitmap is 1.116ns, but paired CV remains 12.08% (bd-dcrhgl) |
| L1307 | 2026-07-14 | 1.38 | 6.64 ns | none | no | no | **VOID** | provenance | V2; V5 | exact rand48 dyadic bit construction never reached its oracle (`bd-vya7yn`) |
| L1159 | 2026-07-14 | none quoted | 6.12 ns | none | no | no | **VOID** | provenance | V2; V5 | rand48 exact dyadic bit construction (`bd-vya7yn`) |
| L203 | 2026-07-16 | 1.09924, 1.105, 1.12778 | 6.09 ns | none | no | yes | **VOID** | provenance | V5 | consolidated native `dlerror` TLS stayed below the null-adjusted floor (`bd-msbxng`) |
| L4202 | 2026-07-04 | 6.65, 12.27 | 3.73 ns | none | no | no | **VOID** | provenance | V2; V5 | ✗ lock-free fallback allocation table REJECTED — worsened `calloc/free(16)` to 12.27x vs gli |
| L3047 | 2026-07-10 | 1, 1.64, 3.6 | 2.80 ns | yes, no % | no | yes | **VOID** | provenance | V5 | both allocator sub-paths DECIDED — large-alloc **REJECT** (irreducible framing) + realloc fa |
| L611 | 2026-07-15 | none quoted | 2.77 ns | none | no | no | **VOID** | provenance | V2; V5 | force-inline 64-bit `ldiv`/`lldiv` stayed below the deployed floor (`bd-n7hoex`) |
| L4841 | 2026-07-01 | 2.17, 5.03, 8.34 | 0.75 ns | none | no | no | **VOID** | provenance | V2; V5 | ✗ strtok/strsep >4-byte-delim fused via SCALAR bitmap REJECTED (8x adversarial regression) — |
| L1227 | 2026-07-14 | none quoted | n/r | none | no | yes | **VOID** | provenance | V5 | convex nominal approachability fast path never reached its oracle (`bd-1jb9s5`) |
| L1342 | 2026-07-14 | none quoted | n/r | none | no | yes | **VOID** | provenance | V5 | eager `__ctype_*_loc` TLS table pointers never reached their oracle (`bd-m4czbr`) |
| L1377 | 2026-07-14 | none quoted | n/r | none | no | no | **VOID** | provenance | V2; V5 | `localeconv` strict static-return bypass never reached its timed path (`bd-6pypop`) |
| L1408 | 2026-07-14 | none quoted | n/r | none | no | no | **VOID** | provenance | V2; V5 | `tdelete` single-walk candidate never reached its timed path (`bd-87fps4`) |
| L1439 | 2026-07-14 | 1.149 | n/r | none | no | no | **VOID** | provenance | V2; V5 | skip per-entry `dirent` TLS clear; **22.047 -> 22.441 us (1.018x)** (`bd-6x0mrj`) |
| L1706 | 2026-07-14 | 0.3975, 1.028, 1.09 | n/r | none | no | yes | **VOID** | provenance | V5 | finite `scalbn(x, 0)` core shortcut wins the kernel but regresses the deployed ABI; **2.9523 |
| L1882 | 2026-07-14 | 0.683, 1.1576 | n/r | none | no | no | **VOID** | provenance | V2; V5 | `strsep` exact-two-delimiter scanner misses the short-token floor; **4.6575 -> 5.3914 ns at  |
| L1913 | 2026-07-14 | none quoted | n/r | none | no | no | **VOID** | provenance | V2; V5 | `wmemrchr` mask resolver did not reach the timed path |
| L3137 | 2026-07-10 | 1.745 | n/r | yes, no % | yes | no | **VOID** | provenance | V2 | REJECT (codegen-verified, no room): the "+avx2 build fix widens the string-SIMD residuals" l |
| L4745 | 2026-07-01 | none quoted | n/r | none | no | no | **VOID** | provenance | V2; V5 | ✗ known_remaining-drop lever BLOCKED for strstr/strcasestr/strlen (main-data-arg bound is a  |
| L5675 | 2026-06-29 | 0.75, 0.81, 0.87 | n/r | none | no | no | **VOID** | provenance | V2; V5 | `scan_strcmp` 4×32 folded 128B block REJECTED (regime-specific; intrinsic boundary regressio |
| L5792 | 2026-06-28 | none quoted | n/r | none | no | no | **VOID** | provenance | V2; V5 | fl asinh x≥16 asymptotic is ~1 ULP (not bit-exact); cheap fix rejected |
| L5846 | 2026-06-28 | 0.92, 0.94, 1.5 | n/r | none | no | no | **VOID** | provenance | V2; V5 | ❌ f64 `remainder` fdlibm-fmod port REJECTED (slower than deployed typical; glibc hardware-fa |
| L6007 | 2026-06-28 | 4.22 | n/r | none | no | no | **VOID** | provenance | V2; V5 | fmemopen `fgetc` read-ahead cache REJECTED (no valid ratio vs ORIG; SIGABRT) |
| L6089 | 2026-06-28 | 1.531, 5.4, 7.37 | n/r | none | no | no | **VOID** | provenance | V2; V5 | stdio standard-stream TLS classification cache REJECTED (1.531x vs ORIG; 5.40x LOSS vs glibc |
| L8200 | 2026-06-25 | 1.42 | n/r | none | no | no | **VOID** | provenance | V2; V5 | str/mem/wide SCAN+COMPARE family at the portable_simd floor — REJECT (cc) |
| L8244 | 2026-06-25 | 1.49, 1.58 | n/r | none | no | no | **VOID** | provenance | V2; V5 | qsort index-sort fallback REJECTED (tested, regressed) (cc) |
| L8354 | 2026-06-25 | 0.9, 0.97, 0.99 | n/r | none | no | no | **VOID** | provenance | V2; V5 | str/mem large-buffer head-to-head REJECT (cc) |
| L16179 | 2026-07-03 | 1.42 | n/r | none | no | no | **VOID** | provenance | V2; V5 | wide bounded fused wcsncpy/wcsncat: byte-exact but SLOWER, NOT shipped |
| L16194 | 2026-07-03 | 1.79, 1.8 | n/r | none | no | no | **VOID** | provenance | V2; V5 | strlen/scan_c_string medium-string kernel gap: threshold-lowering is a TRADE-OFF, not shippe |
| L16210 | 2026-07-03 | 1.15 | n/r | none | no | no | **VOID** | provenance | V2; V5 | parity-to-slower (ILP), not shipped |
| L16227 | 2026-07-03 | none quoted | n/r | none | no | no | **VOID** | provenance | V2; V5 | large-win but small-regression TRADE-OFF, not shipped |
| L16345 | 2026-07-04 | 1.001, 1.011, 1.018 | n/r | none | no | no | **VOID** | provenance | V2; V5 | memcmp fused compare-memory loop apparent win did not reproduce |
| L16447 | 2026-07-04 | 0.971, 0.972, 0.986 | n/r | none | no | no | **VOID** | provenance | V2; V5 | memset dest-align peel is ~0-gain (fl already parity-to-win); memmove-overlap peel deferred  |
| L16468 | 2026-07-04 | 0.759, 1.179, 1.42 | n/r | none | no | no | **VOID** | provenance | V2; V5 | strcspn = setup-floor (not per-byte); strrchr 128B-unroll REGRESSES short strings (reverted) |
| L16471 | 2026-07-04 | 1.12, 1.15, 1.34 | n/r | none | no | no | **VOID** | provenance | V2; V5 | strcasecmp guard-bit SIMD fold + 128B-unroll is SLOWER than the existing simd_ge/le fold (re |
| L16477 | 2026-07-04 | 0.89, 1.12, 1.21 | n/r | none | no | no | **VOID** | provenance | V2; V5 | inline-asm memchr (128B) is SLOWER than the core 256B Simd<u8,64> fold (reverted) |
| L16497 | 2026-07-04 | 1.108, 1.18, 1.316 | n/r | none | no | no | **VOID** | provenance | V2; V5 | wcschr fold is ALREADY optimal (64-lane/1024B beats 8-lane); wcslen near-parity — no wide-fo |
| L16527 | 2026-07-04 | 0.72, 0.91, 1.08 | n/r | none | no | no | **VOID** | provenance | V2; V5 | wcsrchr 128B combined-mask tier is ~0-gain (residual is the wide-SIMD ceiling) |
| L18570 | 2026-07-10 | 1, 1.42, 6.17 | n/r | none | no | yes | **VOID** | provenance | V5 | EMPTY (STRUCTURAL PROBE, no lever built): fresh-context structural-primitive sweep of the un |
| L18995 | 2026-07-11 | 1.11, 1.4, 1.55 | n/r | none | no | no | **VOID** | provenance | V2; V5 | SWING KILLED BY PROFILE (before the refactor): stdio MT gap is per-op floor, not lock conten |
| L19416 | 2026-07-11 | 1.15, 1.36, 1.67 | n/r | none | no | no | **VOID** | provenance | V2; V5 | "eucjp SS-run SIMD" is a NON-LEVER — fl EUC-JP has no SS2 decode to accelerate (cc-iconv-euc |
| L21165 | 2026-07-22 | none quoted | n/r | yes, no % | yes | no | **VOID** | provenance | V2 | the advertised 53-row REJECT census was 54; historical row-level provenance remains absent ( |
| L18159 | 2026-07-10 | 1.1, 1.11, 1.13 | 3.1 us | yes, no % | yes | yes | **SOUND** | — | - | adopted the NULL CONTROL. It validated `f43855c2e`, it invalidated a run, and it produced a  |
## 7. Resurrection yield

Updated as re-runs land. "Re-won" means the resurrected lever cleared the median-CI gate with a
recorded binary SHA-256 and an A/A null control at the decision's own unit of analysis.

| metric | count |
|---|---|
| REJECT rows audited | 131 |
| VOID (contract rule) | 130 |
| — decision-defective (the re-attack pool) | 27 |
| — provenance-only | 103 |
| already resurrected before this audit | 2 families (L6150; L18406/L18455/L18490) |
| re-won | **2** — `ad465633f` (MT `fgetc` 17.5–18.7×), `15f58c419` (allocator 18.7–19.4% vs ORIG) |
| queued for re-run | 3 (ranks 1–3 of §5) |
| adjudicated undecidable, not re-queued | 2 (ranks 4–5 of §5) |

Yield so far: **2 of 27 decision-defective rows re-run, 2 of 2 re-won.** That is not a projection for
the remaining 25 — the two that were re-run were also the two largest frames, chosen by exactly the
ranking in §5 — but it does establish that the failure mode is real and that the ranking finds it.

## 8. Reproducing this audit

The classifier is `ledger_audit.py` (kept with the campaign's scratch artifacts, not in-tree: it is a
one-shot read-only text classifier, not project tooling). It is ~230 lines and re-derivable from
§1–§2, which specify the population definition, the three heading grammars, the null floor, the
frame-size extraction rule, and the V1–V5 criteria. Every row's verdict is independently checkable
from the `L<n>` column against the pinned file SHA-256.

**What this audit cannot do.** It reads row text. It cannot verify that a row's quoted self-time was
measured on the workload the bench ran (V3), because 115 of 131 rows record no self-time at all. A
row tagged `provenance` here may still be `decision`-defective under V3. The severity split is
therefore a **lower bound** on the decision-defective count.

## 9. Standing rules this audit implies

1. **A rejection with no binary SHA-256 is not a rejection, it is a note.** 119 of 131 rows in this
   ledger are in that category. New rows must carry the self-reported ELF hash.
2. **Gate on the median against an A/A null measured at the decision's own unit of analysis. Never on
   `cv`.** Twelve rows here were decided by a `cv < 5%` gate; the repo's own calibration puts the
   achievable floor well above that, and in the L18455 case three of the six gated CVs were computed
   on arms the decision did not even use. And note the sharper trap found while shipping
   `cc-pcc-gate-split`: an *in-invocation* A/A (fl vs fl inside one process) measured 0.9999 ±0.03,
   while the *cross-invocation* floor for the same statistic was ±0.046 — 1.5× wider. A two-binary
   A/B is decided across invocations and must be gated on the wider floor; using the tighter one
   inflates the margin by ~20%.
3. **Record the self-time of the frame under test, or record explicitly that it is blocked.** Without
   it a rejection cannot be distinguished from a bench that never ran the code.
4. **A ratio inside `[0.905, 1.105]` is not a result.** Write it down as undecidable, together with
   the workload that would make it decidable — that is the retry predicate — rather than as a REJECT.
