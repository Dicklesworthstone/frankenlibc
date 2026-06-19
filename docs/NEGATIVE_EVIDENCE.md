# FrankenLibC Perf Negative-Evidence Ledger

Measured head-to-head **vs host glibc** for perf optimizations that were committed
"code-first, batch-test pending". Records **every** result — win, loss, or neutral —
so dead ends are never retried and real wins are confirmed with numbers.

## Method

- Bench harness: `crates/frankenlibc-bench` (criterion). Run per-crate, not workspace-wide:
  `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- \
   cargo bench -p frankenlibc-bench --bench <NAME> --features=abi-bench`
- Each bench group compares `frankenlibc_abi` vs `host_glibc` on a realistic workload.
- **ratio = fl_median / glibc_median** (lower is better; <1 = fl faster, >1 = fl slower).
- **Verdict:** `WIN` ratio ≤ 0.95 · `NEUTRAL` 0.95–1.05 · `LOSS` ratio ≥ 1.05.
- **Action on LOSS / NEUTRAL-with-cost:** revert the optimization (keep conformance green),
  unless the lever's value is correctness/safety rather than speed (noted).

## Results

| Date | Lever / bead | Bench | fl | glibc | ratio | verdict | action |
|------|--------------|-------|----|----|-------|---------|--------|
| 2026-06-19 | `%s\n` direct payload fast path (`bd-0m5vaw`) | `stdio_glibc_baseline_snprintf_s_newline` | 471.49 ns | 550.41 ns | 0.856x | WIN | Keep. Head-to-head Criterion on `vmi1227854`, cache miss; conservative CI ratio still < 0.90. |
| 2026-06-19 | Wide printf format TLS pool (`bd-fgnxc0`) | `stdio_glibc_baseline_swprintf_wide_format` | 317.94 ns | 1.0154 us | 0.313x | WIN | Keep. Head-to-head Criterion on `vmi1227854`, cache miss; outliers noted but conservative CI ratio still < 0.34. |
| 2026-06-19 | stdio registry local hasher (bd-2jgvp9) | stdio_glibc_baseline_fgetc_4096 | 5.5212 ms | 9.5712 ms | 0.577x | WIN | Keep. thin-LTO Criterion (BlackThrush, frankenlibc-cc, 72s warm build). fl buffered fgetc ~1.73x faster than glibc (registry local-hasher + buffered-getc path). VALIDATES the methodology finding — the no-LTO run had shown a spurious 1.157x "loss" on fgetc_unlocked. Conformance: cargo check green + order-audit clear (no test pins flush order). |

<!-- rows appended as benches complete -->

## 2026-06-19 stdio cod-b gauntlet notes

- Bench command, `%s\n`: `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo bench -p frankenlibc-bench --features abi-bench --bench stdio_glibc_baseline_bench snprintf_s_newline -- --noplot`
- Bench command, wide printf: `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo bench -p frankenlibc-bench --features abi-bench --bench stdio_glibc_baseline_bench swprintf_wide_format -- --noplot`
- Both benches selected worker `vmi1227854`; RCH rewrote the target dir to `/data/projects/frankenlibc/.rch-target-vmi1227854-pool-2740363b0b76e0a08f9b35b4f209a994`.
- Both RCH runs reported `Cache: MISS`; total wall time is not used as evidence.
- Validation: `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-abi` passed locally with pre-existing warning debt.
- Test caveat: `cargo test -p frankenlibc-abi ...` without `--lib` is blocked by pre-existing `zz_scratch_divmin` integration-test compile errors. `cargo test -p frankenlibc-abi --lib -- --list` shows `stdio_abi` and `wchar_abi` inline tests are not present because those modules are `#[cfg(not(test))]` in `crates/frankenlibc-abi/src/lib.rs`.
- RCH caveat: an attempted `--lib` guard run on `ovh-b` failed in `blake3` build script with SIGILL before crate compilation; not counted as conformance evidence.

## METHODOLOGY — CRITICAL: bench fl WITH thin-LTO (no-LTO invalidates fl ratios)

fl depends on cross-crate **LTO inlining** (`abi` → `core`); host glibc is a precompiled
system library that needs no LTO. Disabling LTO (`CARGO_PROFILE_BENCH_LTO=false`) for a
faster build **handicaps fl specifically** and produces invalid ratios. Evidence
(BlackThrush, no-LTO run on `frankenlibc-cc`, remote build finished in 240s):

- `swprintf_wide_format`: fl 2.769 µs / glibc 2.787 µs = **0.994× (spurious NEUTRAL)** —
  directly contradicts cod-b's thin-LTO **0.313× WIN** on the identical bench.
- `snprintf_s_newline`: fl 1.623 µs / glibc 1.656 µs = **0.981×** vs cod-b's thin-LTO **0.856×**.
- `fgetc_unlocked_4096`: fl 11.26 ms / glibc 9.73 ms = **1.157× (spurious LOSS)**.

→ **Always use the default bench profile (thin-LTO, codegen-units=1).** no-LTO medians are
NOT recorded as fl results. no-LTO build ≈ 4 min vs thin-LTO ≈ 25+ min, but the speed is not
worth an invalid measurement. **This measurement dead-end is logged so it is never retried.**

## 2026-06-19 stdio head-to-head re-measurement (BlackThrush, thin-LTO, CURRENT bench)

Full `stdio_glibc_baseline_bench` (thin-LTO `--noplot`, all 4 functions, one consistent run):

| Function | fl | glibc | ratio | verdict |
|----------|----|-------|-------|---------|
| `fgetc_4096` | 5.2211 ms | 9.4612 ms | **0.552×** | WIN (confirms bd-2jgvp9; robust — 0.577× on the prior run) |
| `fgetc_unlocked_4096` | 9.5617 ms | 9.5556 ms | 1.001× | NEUTRAL |
| `snprintf_s_newline` (bd-0m5vaw) | 945.5 ns | 947.5 ns | 0.998× | NEUTRAL |
| `swprintf_wide_format` (bd-fgnxc0) | 2.6351 µs | 2.6217 µs | 1.005× | NEUTRAL |

**Honest reconciliation with cod-b's earlier rows:** cod-b measured bd-0m5vaw **0.856×** and
bd-fgnxc0 **0.313×**; these do **NOT reproduce** on the current bench (mine: 0.998×, 1.005×).
The glibc *absolute* times also differ ~2.6× (swprintf glibc: cod-b 1.015 µs vs mine 2.622 µs),
so the **bench workload changed between runs** — cod-b's wins were on an earlier, lighter
`stdio_glibc_baseline_bench`; the current (heavier) bench shows fl ≈ glibc. Net: on the CURRENT
bench, bd-0m5vaw and bd-fgnxc0 are **NEUTRAL**, not wins. They remain correct + byte-identical
(low complexity), so they are **not regressions** — revert is *optional* and **deferred**: the
fast paths plausibly still win on their true target (short strings / bare formats), which the
heavier bench dilutes; reverting correct, harmless, zero-cost code yields nothing.

**CURIOSITY → new lever:** fl's *locked* `fgetc` (5.22 ms — registry-hasher + buffered path) is
~1.8× **faster** than fl's own `getc_unlocked` (9.56 ms). The unlocked path is unoptimized
(it should be ≤ the locked path). NEW optimization opportunity: bring `getc_unlocked` to
`fgetc`'s level (filing as a bead).

**Bottom line:** only **bd-2jgvp9 / `fgetc` (0.552×) is a robust WIN** vs glibc; the printf
composite fast-paths are workload-dependent (win on light/short inputs per cod-b, neutral on
the current heavier bench). All measured honestly; conformance unaffected (no reverts needed —
nothing regressed).

## 2026-06-19 mem/string head-to-head — memset_abi_bench (BlackThrush, thin-LTO)

This bench reports fl-new vs glibc directly (`vs glibc` column; >1 = fl faster). Per function,
small (64 B) → large (64 KB):

| Function | 64 B | 4096 B | 65536 B | verdict |
|----------|------|--------|---------|---------|
| memset | 5.56× | 1.14× | 1.00× | **WIN** (≥ glibc at every size; fl self-improved up to 6.76× old→new) |
| memmove (fwd) | 10.15× | 1.20× | 1.02× | **WIN** (every size) |
| memcpy (raw bulk) | 11.22× | 1.23× | **0.55×** | WIN small/med, **LOSS @64 KB** (fl 2208 ns vs glibc 1204 ns) |
| scan_c_string (strlen/NUL) | 6.44× | 0.90× | 0.85× | WIN small, **LOSS @≥4 KB** |
| strchr (absent full scan) | **0.22×** | **0.05×** | **0.06×** | **LOSS — glibc 2–16× faster at all sizes** |

- **WINS:** memset, memmove — fl beats glibc across all sizes (small-buffer dispatch + SIMD).
- **LOSSES vs glibc's hand-tuned AVX (gaps, filed):** `strchr` (severe — fl ~7 GB/s vs glibc
  ~111 GB/s at 64 KB), `memcpy` @64 KB, `strlen` @≥4 KB.
- **No reverts:** the "new" path beats fl's own "old" everywhere relevant (the optimizations are
  real self-improvements); the losses are *gaps to glibc's AVX*, not regressions — reverting
  would make fl strictly slower. The fix is to close the gap (better large-size SIMD), not revert.

## 2026-06-19 COMPREHENSIVE head-to-head — glibc_baseline_bench (BlackThrush, thin-LTO, 67 functions)

Parsed the bench's structured `GLIBC_BASELINE_BENCH … p50_ns_op=` lines (`frankenlibc_core`/`_abi`
vs `host_glibc`). **fl WINS on ~58 of 67 functions** at the benched workloads:

- **Overwhelming WINS** (fl ≪ glibc): `strstr_absent` 0.001× (fl 76 ns vs glibc 86 µs), `wcsstr`
  0.004×, `malloc_free_*` 0.008× (~100× faster), `fnmatch_*` 0.007–0.017×, `malloc_cache_pressure` 0.015×.
- **Strong WINS**: strcmp 0.051×, strlen 0.077×, strncmp 0.085×, memcmp 0.173×, scanf 0.19–0.24×,
  strspn 0.251×, strtol/strtoul 0.40–0.45×, memcpy_4096 0.486×, memchr 0.533×, memmove 0.655×, strpbrk 0.688×.
- **MATH WINS** (fl 2–4× faster — surprising vs glibc's tuned libm; warrants a spot-check but the
  powf losses below show the measurement discriminates): exp2 0.257×, log2 0.278×, exp 0.293×, cos
  0.473×, sin 0.487×, tan 0.514×, pow 0.398×, erf 0.487×, cbrt 0.594× — all ~25 math fns WIN.
- **NEUTRAL**: `printf_f_6` (bare-%f, bd-ifl0s9) 0.953×, `qsort_128_i32` 0.992×, `getenv` 1.011×,
  `memset_4096` 1.037×, `strchr_absent` 1.038×.
- **LOSSES**: `strcpy_4096` 1.345× (fl 74 ns vs glibc 55 ns), `powf_irrational` 2.248×,
  `powf_int` 2.686× (fl `powf` 2–2.7× SLOWER than glibc).

**Reconciliation with memset_abi_bench (size sweep):** glibc_baseline tests single (small/4 K) sizes
→ fl wins/neutral; memset_abi's strchr/memcpy LARGE-size losses (0.05–0.55× at 16–64 K) are
**size-specific** (glibc's AVX scales better at large). Not contradictory — fl wins small/medium,
loses at large. So bd-4rxozm/bd-4ibo52 are **large-size** gaps, not all-size.

**NET RELEASE PICTURE: fl BEATS glibc on the large majority of the surface** (string, small/medium
mem, malloc, scanf, math) with a few specific gaps: `powf` (2.7×, new — filing), `strcpy` (1.35×),
and large-size `strchr`/`memcpy`/`strlen`.

## 2026-06-19 measurement caveats + head-to-head coverage status (BlackThrush)

**Honest caveats for the 67-fn head-to-head:**
- The bench links fl **statically (LTO-inlined)** vs glibc **dynamically (PLT)**. PLT overhead is
  ~sub-ns steady-state, so it does NOT explain the wins on slow functions (math ~300 ns) — those
  are robust. For very fast functions (strcmp 5 ns, strchr 41 ns) interpret the absolute ratio with care.
- Some fast-function wins are **workload-specific fl fast-paths** — e.g. `strcmp_256_equal` (0.051×)
  hits fl's `strcmp_exact_256_equal_nul_terminated` short-circuit; general strcmp may differ.
- **Robust wins** (large margin and/or slow fn and/or size-swept): math (2–4×), malloc, strstr,
  memcpy/memmove small-med, fgetc (0.552×).

**Head-to-head coverage = COMPLETE for existing paired benches:** `glibc_baseline_bench` (67 fns),
`stdio_glibc_baseline_bench` (4), `memset_abi_bench` (5, size-swept). The remaining bench files
(`iconv_bench`, `string_bench`, `wchar_bench`, `malloc_bench`) are **fl-only** (no glibc comparison
built in) — extending them to head-to-head requires adding glibc baselines (bench-building; a
follow-up). All available paired infrastructure has been measured honestly.

**SESSION SUMMARY (BlackThrush, gauntlet/measurement phase):**
- fl beats glibc on ~58/67 functions; robust wins across string/mem-small/malloc/scanf/scalar-math.
- Genuine losses pinned + filed: `powf` 2.2–2.7× (bd-z8p3mx), `strcpy` 1.35×, large-size
  strchr/memcpy/strlen (bd-4rxozm/bd-4ibo52), getc_unlocked unoptimized (bd-djtvqq).
- 2 earlier-claimed printf wins reconciled to NEUTRAL on the current bench.
- Critical LTO methodology trap logged (no-LTO invalidates fl).
- No reverts: all losses are gaps-to-glibc, not regressions vs fl's own prior code.

## 2026-06-19 CRITICAL caveat — the 67-fn head-to-head measures fl CORE, not the deployed ABI

Verified the bench's impl labels: **38 `frankenlibc_core` + 4 `frankenlibc_core_state` vs only 1
`frankenlibc_abi`** (getenv). So nearly all the "fl wins" measure fl's **pure core algorithms**,
NOT the deployed `frankenlibc_abi` path that adds the per-call **membrane / runtime-policy /
registry** overhead. Tellingly, the ONE real-ABI data point — `getenv` via `frankenlibc_abi` — was
**NEUTRAL (1.011×)**, and `malloc` uses `frankenlibc_core_state` (a simplified allocate-free state,
not the real `frankenlibc_abi::malloc` with arena+membrane), so its "100×" is not the deployed
allocator.

**IMPLICATION (release-readiness):** fl's **core algorithms are competitive-to-faster than glibc**
— a real, strong result. But the **deployed fl ABI** (the `.so` callers actually use) carries a
fixed per-call membrane cost that the core benches exclude; the getenv-abi-neutral point shows that
cost can erase a core win on cheap functions. A true deployed-vs-glibc claim needs **abi-labelled**
head-to-heads (measure `frankenlibc_abi::*` directly), which is the key remaining measurement gap.
The stdio/memset clusters I measured DO use the abi path (`fl::fgetc`, `fl::snprintf`) — those
(fgetc 0.552× WIN, snprintf/swprintf NEUTRAL, memset/memmove WIN) are deployed-representative.

## 2026-06-19 DEPLOYED-ABI math head-to-head — the membrane ERASES the core win (BlackThrush, thin-LTO)

Built `bench_math_abi`: the real `frankenlibc_abi` math entry points (through `unary_entry`'s
`runtime_policy::decide`+`observe` membrane, per call) vs glibc.

| fn | deployed fl_abi | glibc | deployed ratio | (core ratio for contrast) |
|----|-----------------|-------|----------------|----------------------------|
| exp  | 679 ns | 679 ns | **1.000× NEUTRAL** | core 0.293× |
| sin  | 676 ns | 675 ns | **1.002× NEUTRAL** | core 0.487× |
| cos  | 706 ns | 721 ns | **0.979× NEUTRAL** | core 0.473× |
| log  | 803 ns | 805 ns | **0.998× NEUTRAL** | core 0.366× |
| exp2 | 686 ns | 666 ns | **1.031× NEUTRAL** | core 0.257× |
| log2 | 572 ns | 559 ns | **1.023× NEUTRAL** | core 0.278× |

**DECISIVE:** the math ABI membrane (`unary_entry`) adds **~150–200 ns/call**, which ERASES the
core's 2–4× win → **deployed fl math is parity (NEUTRAL) with glibc**, not faster. E.g. core sin
496 ns → deployed sin_abi 676 ns ≈ glibc 675 ns; the membrane cost ≈ the core's advantage.

**CONTRAST — the membrane cost is PATH-SPECIFIC:** `memset_abi` (also an ABI path) is 2.8 ns at
64 B (WIN 6.84×) and `fgetc` (abi) WINS 0.552× — those paths are thin. Only the math path
(`unary_entry`) carries the full decide/observe cost. So **deployed fl is MIXED**: thin-path fns
(memset/memmove/fgetc) WIN; membrane-heavy fns (math) NEUTRAL.

**RELEASE IMPLICATION:** the "fl math 2–4× faster than glibc" result is a CORE-kernel fact, NOT a
deployed one — the runtime-policy membrane on the math path consumes the entire advantage. This is
the single most important honesty correction of the session: **deployed fl math = glibc parity.**
LEVER (filing): cheapen/fast-path `unary_entry`'s decide+observe for pure finite-math inputs to
recover the core win for the deployed path (design tradeoff: membrane adaptivity vs per-call cost).

## 2026-06-19 CORRECTION — memset_abi_bench measures RAW CORE primitives, NOT deployed public fns

Verified the source: `memset_abi_bench` calls `frankenlibc_abi::string_abi::bench_raw_memset_bytes`
/ `bench_raw_memcpy_bytes` / `bench_scan_c_string` — **bench-only raw-primitive exposers** that
SKIP the membrane. So the memset/memmove/memcpy/strlen "wins" recorded above are **CORE-primitive
wins (thin path), NOT the deployed public `memset`/`memcpy`/`strlen`**. I over-attributed them as
"deployed" earlier — corrected here.

The deployed PUBLIC functions DO carry the membrane: `string_abi::strcmp` has `stage_context_two`
+ `runtime_policy::decide` (string_abi.rs:2337), like math's `unary_entry` (~150–200 ns/call). So
deployed public mem/string is **UNMEASURED**, and by analogy to the proven math finding the
membrane likely erodes small-size wins (a ~180 ns membrane dwarfs a 3–19 ns core op → deployed
small `memset`/`strcmp` could be NEUTRAL-to-LOSS).

**CONFIRMED deployed-representative (public abi, with membrane):**
- `fgetc` 0.552× WIN, `fgetc_unlocked` 1.001× NEUTRAL (stdio).
- `snprintf_s_newline` 0.998×, `swprintf` 1.005× NEUTRAL (stdio).
- math exp/sin/cos/log/exp2/log2 0.98–1.03× NEUTRAL (membrane erased the 2–4× core win).

**CORE-only (raw, no membrane) = fl's algorithmic ceiling, NOT deployed:** glibc_baseline 67 fns
(~58/67 wins), memset_abi raw primitives (memset/memmove win).

**KEY REMAINING MEASUREMENT:** bench the DEPLOYED PUBLIC mem/string (`string_abi::memset`/`strcmp`/
`strlen` WITH membrane) vs glibc — strcmp-has-membrane + the math-membrane cost predict deployed
small ops are at risk. This is the next decisive head-to-head.

## 2026-06-19 DEPLOYED-ABI mem/string head-to-head — membrane is PATH-SPECIFIC; deployed = parity-to-win

`bench_memstring_abi` (public `string_abi` fns WITH membrane) vs glibc:

| fn | deployed fl_abi | glibc | ratio | verdict |
|----|-----------------|-------|-------|---------|
| strlen_4096      | 121.5 ns | 309.7 ns | **0.392×** | WIN |
| strcmp_256_equal | 87.0 ns  | 86.6 ns  | 1.005× | NEUTRAL |
| memset_64        | 1.3 ns   | 1.2 ns   | 1.030× | NEUTRAL |
| memset_4096      | 496.2 ns | 493.2 ns | 1.006× | NEUTRAL |

**FINDING — the membrane cost is PATH-SPECIFIC, not uniform:**
- memset: **~1 ns** (THIN fast path, no heavy decide; deployed ≈ glibc at both sizes).
- strcmp: **~82 ns** (stage_context + decide; brings the 5 ns core strcmp to 87 ns ≈ glibc 86 ns).
- math: **~180 ns** (unary_entry; erases the 2–4× core win).

My earlier "deployed small ops at risk of LOSS" was **too pessimistic** — on these workloads they
are NEUTRAL (the membrane brings core wins to parity, not loss). **EXCEPTION:** strcmp's *fixed*
~82 ns membrane means SHORT-string / early-mismatch strcmp (glibc ~5 ns) would deployed-LOSE; the
bench's 256-equal full-scan (glibc 86 ns) hides this — a workload caveat to keep honest.

**REVISED DEPLOYED PICTURE (public abi, confirmed across stdio + mem/string + math):**
- **WINS:** `fgetc` 0.552×, `strlen` 0.392× (SIMD + membrane amortized over the buffer).
- **NEUTRAL:** memset (both sizes), strcmp (256-equal), all math, snprintf/swprintf, fgetc_unlocked.
- **No catastrophic deployed losses** on the measured workloads. The membrane is the **upside
  ceiling** on hot small ops, recoverable via bd-n40in2 (the fast-path lever generalizes beyond
  math: strcmp's ~82 ns membrane is the same class of cost).

**NET:** fl is **competitive (parity-to-faster) than glibc on the deployed path**; its core
algorithms are 2–4× faster but the per-call membrane caps that to parity on hot small functions.
Closing the membrane fast-path (bd-n40in2) is the single highest-leverage deployed-perf lever.

## 2026-06-19 RIGOR CORRECTION — the "~180 ns membrane" was a per-batch misread; membrane is ~2-3 ns/call

Two errors in the earlier math-membrane analysis, found while measuring short-strcmp:

1. **Per-batch misread.** `bench_math`/`bench_math_abi` sum **64 inputs per criterion iteration**, so
   the reported 676 ns (deployed) / 496 ns (core) are BATCH totals → **membrane ≈ (676−496)/64 ≈
   2.85 ns/call**, NOT ~180 ns. The membrane is LIGHT. (Confirmed independently: deployed `memset_64`
   0.7 ns, `strcmp` ≈ glibc within ~2 ns — all consistent with a ~0–3 ns/call membrane.)
2. **Cross-run confounding.** The core-vs-deployed math gap compared SEPARATE rch runs on different
   workers with different glibc baselines (core-run glibc sin ≈ 15.9 ns/call vs abi-run ≈ 10.5 ns/call).
   So "the membrane erases the core win" is NOT cleanly established — it conflates membrane cost with
   worker variance. A same-run core+abi+glibc measurement is required (building it).

**The short-strcmp prediction also FAILED:** `strcmp_short_mismatch_abi` = **1.040× NEUTRAL** (fl
55.8 ns vs glibc 53.7 ns), not the big loss I predicted — because glibc's short strcmp here is
53.7 ns (call/harness floor), not ~3 ns, and the deployed membrane is ~2 ns (light), not ~82 ns.

**CORRECTED deployed mem/string (within-run-valid, run b8fe9o723):**
| fn | fl_abi | glibc | ratio | verdict |
|----|--------|-------|-------|---------|
| strlen_4096 | 92.5 ns | 375.2 ns | **0.247×** | WIN |
| memset_64 | 0.7 ns | 0.7 ns | 0.983× | NEUTRAL |
| strcmp_256_equal | 59.2 ns | 58.9 ns | 1.006× | NEUTRAL |
| memset_4096 | 662 ns | 645 ns | 1.026× | NEUTRAL |
| strcmp_short_mismatch | 55.8 ns | 53.7 ns | 1.040× | NEUTRAL |

**NET (corrected):** the deployed membrane is LIGHT (~2–3 ns/call), not a heavy ceiling. Deployed fl
is parity-to-win (strlen/fgetc WIN; memset/strcmp/math NEUTRAL) with NO losses. Whether the light
membrane meaningfully erodes the FAST math wins needs a SAME-RUN core+abi+glibc measurement —
pending. bd-n40in2's premise (~180 ns) is corrected to ~2–3 ns/call; its value is now uncertain
until the same-run delta is measured. This is an honest correction of my own propagated misread.
