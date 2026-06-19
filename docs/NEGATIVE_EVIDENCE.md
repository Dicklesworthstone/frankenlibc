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
| 2026-06-19 | exact `strcpy_4096` eight-block unroll (`bd-2g7oyh.478`) | `glibc_baseline_strcpy_4096` | 68.555 ns | 54.857 ns | 1.250x | LOSS | Reverted. Focused thin-LTO rch Criterion on `hz1`; mean also slower (72.159 ns vs 65.354 ns, 1.104x). Restored the prior counted loop; focused guards + `cargo check -p frankenlibc-core` passed. |
| 2026-06-19 | fused getopt optstring lookup (`bd-2g7oyh.487`) | `getopt_short_bundle_glibc_comparable` | 93.699 ns | 168.676 ns | 0.556x | WIN | Keep. Corrected host harness uses `dlmopen` plus process/global `opt*` reset to avoid FrankenLibC `optind` interposition; preflight asserts checksum and final `optind`. Focused getopt tests passed. |
| 2026-06-19 | NSS services decimal byte parser (`bd-9ran7n`) | `glibc_baseline_resolv_services_protocols/getservbyname_http_tcp` | 28.532 us | 435.582 us | 0.0655x | WIN | Keep. Real ABI `getservbyname("http","tcp")` against host glibc on `hz1`; mean ratio 0.0692x. |
| 2026-06-19 | NSS protocols decimal byte parser (`bd-9ran7n`) | `glibc_baseline_resolv_services_protocols/getprotobyname_tcp` | 125.854 us | 129.508 us | 0.9718x | NEUTRAL | Keep as part of same resolver parser lever: no regression, mean ratio 0.9639x, and services lookup is a large deployed ABI win. |
| 2026-06-19 | `/etc/group` splitn colon-tail parser (`bd-2g7oyh.481`, pre-correction) | `glibc_baseline_grp_lookup/getgrnam_root` | 17.203 us | 23.977 us | 0.717x | WIN | Earlier `hz1` run before signed-gid correction; kept as evidence but final verdict uses the corrected-source rerun. |
| 2026-06-19 | `/etc/group` splitn colon-tail parser (`bd-2g7oyh.481`, pre-correction) | `glibc_baseline_grp_lookup/getgrgid_0` | 23.447 us | 21.284 us | 1.102x | LOSS | Earlier `hz1` run before signed-gid correction; recorded as negative evidence and forced a final-source rerun. |
| 2026-06-19 | `/etc/group` splitn colon-tail parser (`bd-2g7oyh.481`, final source) | `glibc_baseline_grp_lookup/getgrnam_root` | 9.788 us | 24.779 us | 0.395x | WIN | Partial keep. Real ABI `getgrnam("root")` against host glibc on `hz2`; mean ratio 0.393x. Conformance green after rejecting signed gid fields again. |
| 2026-06-19 | `/etc/group` splitn colon-tail parser (`bd-2g7oyh.481`, final source) | `glibc_baseline_grp_lookup/getgrgid_0` | 24.631 us | 24.435 us | 1.008x | NEUTRAL | Do not count as a win. Route the gid lookup/cache path deeper; retained splitn parser because the same deployed parser lever gives a clear `getgrnam` win. |

<!-- rows appended as benches complete -->

## 2026-06-19 stdio cod-b gauntlet notes

- Bench command, `%s\n`: `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo bench -p frankenlibc-bench --features abi-bench --bench stdio_glibc_baseline_bench snprintf_s_newline -- --noplot`
- Bench command, wide printf: `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo bench -p frankenlibc-bench --features abi-bench --bench stdio_glibc_baseline_bench swprintf_wide_format -- --noplot`
- Both benches selected worker `vmi1227854`; RCH rewrote the target dir to `/data/projects/frankenlibc/.rch-target-vmi1227854-pool-2740363b0b76e0a08f9b35b4f209a994`.
- Both RCH runs reported `Cache: MISS`; total wall time is not used as evidence.
- Validation: `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-abi` passed locally with pre-existing warning debt.
- Test caveat: `cargo test -p frankenlibc-abi ...` without `--lib` is blocked by pre-existing `zz_scratch_divmin` integration-test compile errors. `cargo test -p frankenlibc-abi --lib -- --list` shows `stdio_abi` and `wchar_abi` inline tests are not present because those modules are `#[cfg(not(test))]` in `crates/frankenlibc-abi/src/lib.rs`.
- RCH caveat: an attempted `--lib` guard run on `ovh-b` failed in `blake3` build script with SIGILL before crate compilation; not counted as conformance evidence.

## 2026-06-19 `bd-2g7oyh.478` strcpy4096 unroll rejection + revert

Focused gauntlet target: the code-first exact-block `strcpy_4096` unroll in
`crates/frankenlibc-core/src/string/str.rs`.

Candidate run:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b/criterion-bd-2g7oyh-478-20260619T0314 \
rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

- Worker: `hz1`.
- FrankenLibC core: p50 `68.555 ns`, mean `72.159 ns`.
- Host glibc: p50 `54.857 ns`, mean `65.354 ns`.
- Ratio vs glibc: p50 `1.250x`, mean `1.104x` (`>1` is slower).
- Verdict: **LOSS**. The bead's own keep gate required a stable improvement;
  instead the candidate remained slower than glibc and worsened the prior
  candidate-center recorded in the bead artifact.
- Action: **reverted** only the `15b99939` unroll shape, restoring the counted
  `512`-byte block loop and removing `copy_strcpy_4096_block`.

Post-revert checks:

- `cargo check -p frankenlibc-core`: passed with pre-existing iconv warnings.
- `cargo test -p frankenlibc-core string::str::tests::test_strcpy_exact_4096_path -- --nocapture`:
  2 focused tests passed.
- Cross-worker post-revert reruns stayed slower than glibc, so `strcpy_4096`
  remains an open glibc gap after the revert:
  - `ovh-a`: fl `47.040 ns` vs glibc `36.501 ns`, p50 ratio `1.289x`.
  - `vmi1149989`: fl `56.942 ns` vs glibc `37.649 ns`, p50 ratio `1.513x`
    with noisy high-tail FL mean.

Retry-condition predicate: do not retry exact-block unrolling for `strcpy_4096`.
Return only with a materially different generated/backend primitive or a
different ABI-level `strcpy` path after a fresh focused profile proves that is
the bottleneck.

## 2026-06-19 `bd-2g7oyh.487` getopt fused lookup keep

Focused gauntlet target: the code-first fused optstring lookup in
`crates/frankenlibc-core/src/getopt/{parse,state}.rs`.

Candidate run:

```bash
AGENT_NAME=cod-a \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench baseline_capture_bench getopt_short_bundle_glibc_comparable -- --noplot
```

- Worker: `ovh-a`.
- FrankenLibC core fused lookup: p50 `93.699 ns`, mean `96.687 ns`.
- Host glibc `getopt`: p50 `168.676 ns`, mean `188.519 ns`.
- Ratio vs glibc: p50 `0.556x`, mean `0.513x` (`<1` is faster).
- Verdict: **WIN**. The fused lookup stays.

Harness notes:

- The host glibc path uses `dlmopen(LM_ID_NEWLM, "libc.so.6", ...)` and resets
  both isolated libc and process-visible `optarg`/`opterr`/`optind`/`optopt`.
  This avoids `frankenlibc_abi`'s exported `optind` interposing glibc's state.
- A preflight asserts option-stream checksum and final `optind` parity before
  Criterion timing starts.
- Earlier `dlopen`/`RTLD_DEEPBIND` attempts are **not** counted as perf
  evidence: one observed mismatched `optind`, and `RTLD_DEEPBIND` failed to load
  libc on the remote worker.
- Post-revert context with the corrected host harness also beat glibc on `hz2`
  (`61.777 ns` vs `105.433 ns`, ratio `0.586x`), but that was the two-scan
  baseline, not the fused candidate.

Validation:

- `rustfmt --edition 2024 --check` on the touched getopt and bench files passed.
- `cargo test -p frankenlibc-core getopt --lib` via `rch`: 39 passed.
- `cargo clippy -p frankenlibc-core --lib -- -D warnings` via `rch`: blocked
  because `cargo-clippy` is not installed for the selected nightly toolchain on
  the worker.

## 2026-06-19 `bd-9ran7n` NSS decimal parser measured keep

Focused gauntlet target: the code-first byte decimal parser in
`crates/frankenlibc-core/src/resolv/mod.rs`, exercised through the deployed ABI
resolver functions against host glibc.

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b/criterion-bd-9ran7n-20260619T0341 \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench glibc_baseline_bench -- \
  glibc_baseline_resolv_services_protocols --noplot \
  --sample-size 80 --warm-up-time 1 --measurement-time 3
```

- Worker: `hz1`.
- `getservbyname("http","tcp")`: FrankenLibC p50 `28.532 us`, mean `29.085 us`;
  host glibc p50 `435.582 us`, mean `420.606 us`.
- Service ratio vs glibc: p50 `0.0655x`, mean `0.0692x`. Verdict: **WIN**.
- `getprotobyname("tcp")`: FrankenLibC p50 `125.854 us`, mean `126.718 us`;
  host glibc p50 `129.508 us`, mean `131.459 us`.
- Protocol ratio vs glibc: p50 `0.9718x`, mean `0.9639x`. Verdict: **NEUTRAL**.
- Action: **keep**. The protocol row is not a material regression, and the
  same parser lever produces a large deployed-ABI services win.

Post-benchmark guards:

- `cargo check -p frankenlibc-bench --features abi-bench --bench glibc_baseline_bench`: passed.
- `cargo test -p frankenlibc-core resolv::tests::decimal_u32_byte_parser_rejects_signs_non_digits_and_overflow -- --nocapture`: passed.
- `cargo test -p frankenlibc-core resolv::tests::parse_services -- --nocapture`: 7 passed.
- `cargo test -p frankenlibc-core resolv::tests::protocol_ -- --nocapture`: 11 passed.
- `cargo test -p frankenlibc-abi --test conformance_diff_netdb_aliases -- --nocapture`: passed.
- `cargo test -p frankenlibc-abi --test conformance_diff_protoent_r_aliases -- --nocapture`: passed.
- `cargo test -p frankenlibc-abi --test conformance_diff_netdb_r_aliases -- --nocapture`: passed.
- `cargo fmt --check -p frankenlibc-bench`: blocked by pre-existing formatting
  drift in existing bench files, including unrelated `bench_math_abi`,
  `bench_memstring_abi`, `memset_abi_bench`, `resolv_parsers_bench`,
  `stdio_glibc_baseline_bench`, and `wchar_bench` hunks. Not normalized here to
  avoid staging unrelated churn.
- `cargo clippy -p frankenlibc-bench --features abi-bench --bench glibc_baseline_bench -- -D warnings`:
  blocked before bench linting by pre-existing `frankenlibc-core` lint debt in
  iconv/resolv/printf modules.

Retry-condition predicate: do not revisit byte-decimal parsing for resolver
rows unless a future same-worker deployed ABI run shows a material regression.
The next resolver/NSS performance work should target a different parser,
database-scan, or caching primitive with its own head-to-head proof.

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

## 2026-06-19 CLEAN same-run core+abi+glibc math — membrane VALIDATED at ~8–11 ns/call (not 180)

Same-run (ONE worker, `bench_math_abi` 3-way), per-call ns (batch/64):

| fn | core | deployed abi | glibc | abi/glibc | membrane (abi−core) |
|----|------|--------------|-------|-----------|---------------------|
| exp  | 4.49 | 15.51 | 15.30 | 1.014 NEUT | 11.0 |
| sin  | 7.61 | 15.36 | 15.74 | 0.976 NEUT |  7.8 |
| cos  | 7.66 | 16.12 | 15.90 | 1.014 NEUT |  8.5 |
| log  | 7.76 | 18.54 | 19.08 | 0.972 NEUT | 10.8 |
| exp2 | 3.76 | 14.92 | 15.09 | 0.989 NEUT | 11.2 |
| log2 | 3.59 | 12.83 | 12.54 | 1.023 NEUT |  9.3 |

**RESOLVED (no cross-run confounding now):**
- **CORE math is genuinely 2–4× faster than glibc** (3.6–7.8 ns vs 12.5–19 ns) — the algorithmic win is REAL.
- The `unary_entry` membrane adds **~8–11 ns/call**, bringing DEPLOYED abi math to glibc **parity (NEUTRAL)**.
- So my ORIGINAL conclusion (the membrane erases the core math win) is **CORRECT**; only the magnitude
  was wrong (~9 ns/call, not the per-batch-misread 180 ns). The cross-run confounding worry is now
  eliminated — this is one worker, core+abi+glibc side by side.

**bd-n40in2 VALIDATED (corrected magnitude):** cheapening `unary_entry`'s decide+observe (memset's
path proves a ~1 ns membrane is achievable) would recover **~2× on deployed math** (core 4–8 ns vs
glibc 13–19 ns). HIGH-value, now grounded in clean same-run numbers. This is the definitive
deployed-math result.

## 2026-06-19 `bd-2g7oyh.481` group parser measured partial keep

Focused gauntlet target: the code-first `splitn(4)` parser in
`crates/frankenlibc-core/src/grp/mod.rs`, exercised through real ABI group
lookups against host glibc.

Command:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b/criterion-bd-2g7oyh-481-final-20260619T0414 \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench glibc_baseline_bench -- glibc_baseline_grp_lookup \
  --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

- Worker: `hz2`.
- `getgrnam("root")`: FrankenLibC p50 `9.788 us`, glibc p50 `24.779 us`,
  ratio `0.395x`; mean ratio `0.393x`; **WIN**.
- `getgrgid(0)`: FrankenLibC p50 `24.631 us`, glibc p50 `24.435 us`, ratio
  `1.008x`; mean ratio `1.012x`; **NEUTRAL**.
- Verdict: **partial keep**. Keep the splitn parser for the name lookup win,
  but record the gid lookup as negative evidence and route the lookup/cache path
  deeper.

Earlier same-turn `hz1` evidence before the signed-gid conformance correction is
also recorded in the top table: `getgrnam("root")` was a win at `0.717x`; `getgrgid(0)`
was a loss at `1.102x`. The `hz2` rows above are the corrected-source verdict.

Validation:

- `cargo check -p frankenlibc-bench --features abi-bench --bench glibc_baseline_bench`: passed.
- `cargo test -p frankenlibc-core grp::tests:: -- --nocapture`: 37 passed.
- `cargo test -p frankenlibc-abi --test grp_abi_test getgr -- --nocapture`:
  initially exposed signed-gid acceptance; after rejecting signed gid fields
  again, 35 passed and 5 were ignored.
- `cargo test -p frankenlibc-abi --test conformance_diff_getbyid_r -- --nocapture`: 3 passed.
- `cargo test -p frankenlibc-abi --test conformance_diff_getgrent -- --nocapture`: 1 passed.

Retry-condition predicate: do not retry colon-tail parser reshaping for the
`getgrgid(0)` neutral/gap. The next lever must target gid lookup/cache behavior
or another profile-backed path.

## 2026-06-19 `bd-2g7oyh.482` passwd parser measured reject + revert

Focused gauntlet target: the code-first `/etc/passwd` field scanner in
`crates/frankenlibc-core/src/pwd/mod.rs`, exercised through deployed ABI passwd
lookups against host glibc.

Command:

```bash
AGENT_NAME=cod-a \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-a/criterion-bd-2g7oyh-482-passwd \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench baseline_capture_bench nss_passwd_lookup -- --noplot
```

- Worker: `ovh-a`.
- `getpwnam("root")`: FrankenLibC p50 `10.906 us`, glibc p50 `10.013 us`,
  ratio `1.089x`; mean ratio `1.088x`; **LOSS**.
- `getpwuid(0)`: FrankenLibC p50 `31.495 us`, glibc p50 `9.957 us`,
  ratio `3.163x`; mean ratio `3.326x`; **LOSS**.
- Verdict: **reject**. The splitn/byte-decimal scanner did not beat the original
  glibc deployed workload and exposed a much larger uid-lookup gap.
- Action: **reverted** the parser optimization shape back to the prior
  colon-field `Vec<&[u8]>`, shell-tail `join`, and UTF-8 + `str::parse` numeric
  path while preserving existing compatibility semantics.

Validation:

- `cargo test -p frankenlibc-core pwd:: --lib`: 79 passed.
- `cargo check -p frankenlibc-bench --features abi-bench --bench baseline_capture_bench`: passed.
- `rustfmt --edition 2024 --config skip_children=true --check` on
  `crates/frankenlibc-core/src/pwd/mod.rs` and
  `crates/frankenlibc-bench/benches/baseline_capture_bench.rs`: passed.
- `cargo clippy -p frankenlibc-core --lib -- -D warnings`: blocked because
  `cargo-clippy` is not installed for the selected `nightly-2026-04-28`
  rch toolchain.

Retry-condition predicate: do not retry passwd colon-field scanner or byte-decimal
reshaping as a standalone performance lever. The next passwd/NSS perf work should
target lookup/cache behavior, especially the `getpwuid(0)` scan path, with a
fresh deployed ABI vs glibc benchmark.

## 2026-06-19 cod-a parser batch measured classification

This batch used `resolv_parsers_bench`, which is a FrankenLibC-core parser
microbench with no host-glibc comparator. These rows are therefore **not**
ratio-vs-glibc evidence; they are old-source vs current-source keep/reject
evidence for pending code-first parser leaves.

Method:

- Baseline source: `00cf7152d1f659397dec42616a8e660a64a8c849`, with only
  the benchmark rows backported into a detached scratch worktree.
- Worker: `vmi1153651` for baseline, candidate, and post-reversal confirmation.
- Baseline command used `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a-parser-base`
  and `CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-a/criterion-parser-base-harnessbackport-00cf7152d-20260619`.
- Candidate command used `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a`
  and `CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-a/criterion-parser-head-ec77915a8-20260619`.
- Post-reversal confirmation used
  `CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-a/criterion-parser-reverted-ec77915a8-20260619`.

| Bead / row | Baseline p50 / mean | Candidate p50 / mean | Ratio p50 / mean | Verdict | Action |
|---|---:|---:|---:|---|---|
| `bd-2g7oyh.484` shadow byte scan, `parse_shadow_line_typical` | 390.734 ns / 393.690 ns | 145.133 ns / 187.200 ns | 0.371x / 0.475x | WIN | Keep. Post-reversal source still measured 114.707 ns / 120.211 ns. |
| `bd-2g7oyh.489` ndots early exit, `resolver_should_try_absolute_first_typical` | 11.271 ns / 10.927 ns | 8.834 ns / 8.958 ns | 0.784x / 0.820x | WIN | Keep. Post-reversal source measured 8.825 ns / 8.580 ns. |
| `bd-2g7oyh.480` + `.491` proc route flags/field scan, `parse_proc_net_route_has_ipv4_typical` | 193.540 ns / 194.125 ns | 186.230 ns / 189.373 ns | 0.962x / 0.976x | WEAK WIN | Keep as a combined route-parser batch. Post-reversal source measured 164.474 ns / 165.508 ns. |
| `bd-2g7oyh.486` proc maps byte numeric, `parse_maps_line_typical` | 173.755 ns / 175.686 ns | 243.944 ns / 235.462 ns | 1.404x / 1.340x | LOSS | Reverted only the numeric-parser source shape; kept overflow guards and bench row. |
| `bd-rpc-byte-program-number-wq60gz` RPC byte number parse, `parse_rpc_line_typical` | 166.474 ns / 168.749 ns | 164.140 ns / 179.322 ns | 0.986x / 1.063x | NEUTRAL/LOSS | Reverted only the byte-number source shape; p50 was noise, mean/tail regressed. |
| `bd-v4t889` + `bd-2g7oyh.488` resolv.conf numeric/field scanners, `parse_resolv_conf_options_typical` | 262.342 ns / 270.402 ns | 310.177 ns / 317.729 ns | 1.182x / 1.175x | LOSS | Reverted both source shapes; kept resolver option contract guards. |
| `bd-2g7oyh.490` if_inet6 field scanner, `parse_proc_net_if_inet6_has_ipv6_typical` | 226.138 ns / 242.667 ns | 305.105 ns / 306.780 ns | 1.349x / 1.264x | LOSS | Reverted only the if_inet6 field-scanner source shape; kept behavior guards. |

Validation:

- `cargo test -p frankenlibc-core resolv::tests::parse_proc_net`: 6 passed.
- `cargo test -p frankenlibc-core pwd::shadow::tests::parse_`: 13 passed.
- `cargo test -p frankenlibc-core proc_maps::tests::parse_`: 17 passed.
- `cargo test -p frankenlibc-core rpc::tests::parse_`: 13 passed.
- `cargo test -p frankenlibc-core resolv::config::tests::test_should_try_absolute_first`: 2 passed.
- `cargo test -p frankenlibc-core resolv::config::tests::test_parse_line_byte_field_scanner_spacing_and_caps`: 1 passed.
- Targeted `rustfmt --edition 2024 --check` passed on the four parser files touched by the reversion.
- Full `cargo test -p frankenlibc-core` is blocked by unrelated iconv/glob failures
  (3167 passed, 11 failed).
- `cargo check --workspace --all-targets` is blocked by unrelated
  `crates/frankenlibc-abi/tests/zz_scratch_divmin.rs` compile errors.
- `cargo fmt --check` is blocked by broad pre-existing formatting drift in
  generated/math/iconv and unrelated files.
- `cargo clippy --workspace --all-targets -- -D warnings` is blocked before
  local lints by missing packaged files in `asupersync-conformance 0.3.4`.
