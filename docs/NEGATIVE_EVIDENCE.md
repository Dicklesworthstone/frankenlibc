# FrankenLibC Perf Negative-Evidence Ledger

Measured perf evidence for optimizations that were committed "code-first,
batch-test pending". Most rows are head-to-head **vs host glibc**; controlled
old-vs-new rows are explicitly labeled when no host-glibc comparator exists.
Records **every** result — win, loss, or neutral — so dead ends are never
retried and real wins are confirmed with numbers.

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
| 2026-06-20 | add `ApiFamily::Stdio` to the `decide()` STRICT high-frequency fast-path (skip per-op kernel evidence consult + reentry guard) (`bd-2g7oyh`, cc/BlackThrush) | `stdio_glibc_baseline_bench fgetc_4096` | fl 300 us | glibc 612 us | same-run 0.52x → 0.49x (fl ~2x faster than glibc) | WIN (marginal, pure skip) | Keep. In strict-passthrough, stdio `decide()` fell to `decide_strict_observation` (consults the membrane kernel via `runtime_policy_guard(|| k.decide())` for EVIDENCE, then FORCES `action: Allow` — strict mode is ABI-faithful, never denies). The 6 high-freq families skip that; `Stdio` (per-char `fgetc`/`fputc`/`fread`, no strict bypass) did not. Added `| ApiFamily::Stdio` to the STRICT list ONLY (left the hardened/secure-mode list untouched). Byte-identical: the action is `Allow` either way — this only skips the per-char kernel-evidence call + guard (same telemetry-skip class as the observe row below, plus removes a per-char kernel consult = MT-relevant). Marginal single-thread delta has cross-worker uncertainty but is a pure skip (cannot regress). decide()'s deny/validation path is unchanged for non-stdio and for hardened mode. |
| 2026-06-20 | add `ApiFamily::Stdio` to the `observe()` high-frequency fast-path (skip per-op telemetry: 2x cert lookups + reentry guard) (`bd-2g7oyh`, cc/BlackThrush) | `stdio_glibc_baseline_bench fgetc_4096` (observe called per char x4096), same-bench same-metric A/B vs the immediately-prior cookie-lock-only build | fl 1.46 ms (was 7.99 ms on the prior build's worker) | glibc 2.79 ms | same-run ratio 0.74x → **0.52x** (fl now 1.9x faster than glibc) | WIN | Keep. `observe()` fast-path skipped telemetry for `Allocator/StringMemory/Ctype/Loader/Stdlib/MathFenv` but NOT `Stdio` — so every non-adverse `fgetc`/`fputc`/`fread` (which, unlike puts/fputs/snprintf, has no strict `decide`/`observe` bypass) paid the full `observe()` slow path (2x `lookup_active_ffi_pcc_certificate` + `enter_policy_reentry_guard`) PER CHAR. Added `| ApiFamily::Stdio`. observe() is POST-op telemetry (not validation), gated `cfg!(not(test)) && !adverse`, so functional behavior is unchanged and a pure skip cannot regress; mirrors the 6 existing families. Clean attribution: only delta vs the prior fgetc_4096 build is this line. (Magnitude has some cross-worker uncertainty but the direction is certain — skip-only.) Adverse/error stdio ops still run full observe. Decide() NOT touched (validation core). |
| 2026-06-20 | `is_cookie_stream` lock-free fast path — skip the global `cookie_registry` mutex when no `fopencookie` stream exists (`bd-hqo6b6`, cc/BlackThrush) | `stdio_glibc_baseline_bench fgetc_4096` (4096 is_cookie_stream calls/iter) + `fputs_glibc_bench` | fgetc_4096 fl 7.99 ms (wins); fputs same-run ratios noisy | glibc fgetc_4096 10.78 ms | fgetc 0.74x (fl wins 1.35x) | NEUTRAL single-thread / KEEP (MT lock-contention) | Keep. Every `fgetc`/`fputc`/`fputs`/`fread`/`fwrite` called `is_cookie_stream(id)` which took a GLOBAL `cookie_registry` Mutex just to answer "no" — a serialization point on EVERY stdio op even when no cookie stream exists (the universal case). Added a monotonic `COOKIE_STREAMS_PRESENT: AtomicBool` (set on `fopencookie`, Acquire/Release, never reset) so the hot path skips the lock entirely until the first cookie stream. Byte-identical, semantically IDENTICAL (pure lock skip, no bound/scan change — unlike the reverted fputs strlen swap), cannot regress. Single-thread delta (~one uncontended mutex, ~15 ns) is below the rch fleet noise floor (could not isolate cleanly across noisy workers; 8B fputs ratio 6.1x→5.1x, 38B noise-regressed), but it removes a real global serialization point for multi-threaded stdio. fgetc still wins glibc 0.74x same-run. Deployed abi build GREEN (via bench compile). |
| 2026-06-20 | strict `sprintf("%s")` SWAR fast path mirroring snprintf (`bd-2g7oyh`, cc/BlackThrush) | `sprintf_s_glibc_bench` end-to-end REAL `fl::sprintf` (variadic) vs host glibc, `hz1` | fl 8B 41-43 ns | glibc 8B 33 ns | 1.25-1.3x | LOSS / REVERTED | Reverted (net-zero). Added a strict `%s` fast-path to `sprintf` (bypasses decide()+known_remaining, same kernel as the snprintf win). But the REAL `fl::sprintf` is VARIADIC — the va_list ABI setup + strict-dispatch (strict_passthrough check + literal-scan + exact_s match + next_arg) dominate at small sizes, so fl still LOSES ~1.3x to glibc at 8B even with the fast-path. **META-FINDING: the kernel A/B (snprintf_s_strict_ab_bench) measures NON-variadic direct kernel calls and OVERSTATES the win — the real variadic formatter path pays overhead the kernel A/B never sees.** Could not get clean 38B/200B same-run data (dlmopen host arm crashes intermittently after the first group). Per the fputs end-to-end-validation discipline, an unproven hot-path change is reverted. Bench not committed (flaky host arm). |
| 2026-06-20 | deployed strict `snprintf("%s")` SWAR/SIMD strlen+memcpy (`bd-2g7oyh`, cc/BlackThrush) | NEW `snprintf_s_strict_ab_bench` IN-PROCESS A/B (old-kernel vs new-kernel vs host `libc::snprintf`, all in ONE process so worker load cancels in the ratio — defeats the rch cross-worker variance that hid this signal for 2 prior turns) | new 8B 8.61 / 38B 8.53 / 200B 13.03 ns | glibc 8B 24.70 / 38B 25.72 / 200B 23.37 ns | 0.35x / 0.33x / 0.56x | WIN (kernel) — see CAVEAT | Keep (commit `6d2cd0c79`). **CAVEAT (added later): these ratios are the KERNEL (non-variadic direct calls). The REAL variadic `fl::snprintf("%s")` additionally pays va_list ABI + strict-dispatch overhead (~20-30 ns floor, same as the reverted sprintf row above), so the real-path vs-glibc ratio is closer to PARITY than 0.33x. The change is still a genuine keep: the kernel is strictly faster (byte-loop→SWAR) and byte-identical, narrowing the prior 1.15x real-path loss toward parity. But do NOT cite 0.33x as the end-to-end snprintf-vs-glibc number.** Replaced the fused scalar scan+copy byte loop in `strict_direct_snprintf_s` with `scan_c_string` (page-safe SWAR/SIMD, the exact scanner deployed `strlen` uses; NOT `c_str_bytes`→`known_remaining`, the measured 5x-regression trap from the prior turn) + `memcpy`. Beats glibc at EVERY size; beats old fl 2.1x@38B / 8.9x@200B (old 17.82 / 116.42 ns). Tiny <=8B costs +2.5ns vs old fl (SIMD prologue) but still 2.9x faster than glibc. Byte-identity PROVEN by the bench's `verify()` (new==old across truncation / `%s\n` / NULL→"(null)" / empty / size-0 / size-1, and new==glibc for plain `%s`) which runs in deployed config before every measurement — a lib unit test cannot reach it because `pub mod stdio_abi` is `#[cfg(not(test))]`. Deployed abi release build GREEN. |
| 2026-06-20 | **MEASUREMENT** — end-to-end `fputs` vs host glibc (`fputs_glibc_bench`, cc/BlackThrush; new committed bench, dlmopen host, 64 fputs + 1 rewind/iter on `vmi1227854`) | `fputs_8B`/`fputs_38B`/`fputs_200B` | fl 6.72 / 11.74 / 13.09 us (105 / 183 / ~205 ns per call) | glibc 1.10 / 1.08 / ~1.1 us (17 ns per call) | 6.1x / 10.9x / ~12x | LOSS (architectural, bd-hqo6b6) | No revert — pure measurement. fl `fputs` is 6-12x slower than glibc end-to-end. The cost is the per-call `canonical_stream_id` + global `registry().lock()` mutex + `write_bytes_without_runtime_policy` path, NOT the strlen. glibc does a lock-free inline buffer append. This is the stdio global-registry-lock issue (bd-hqo6b6: move to per-FILE/sharded locking) — a real, large deployed loss that needs the architectural refactor, not a micro-lever. |
| 2026-06-20 | `printf`/`fprintf`/`vprintf`/`dprintf` bare-`%s` length: `c_str_bytes`→`scan_c_string` (`bd-2g7oyh`, cc/BlackThrush) | end-to-end `fputs_glibc_bench` (the writers share fputs's stream-write path) | strlen is <2% of the ~183 ns/call fl writer cost | glibc 17 ns/call | ~1.00x net (strlen change negligible) | NEUTRAL / REVERTED | Reverted (the snprintf-style swap was right for snprintf, which is strlen-DOMINATED, but the FILE writers are registry-lock+write-DOMINATED — strlen is noise). Restored `c_str_bytes`. The real loss here is the registry-lock write path (bd-hqo6b6), above. |
| 2026-06-20 | deployed `puts`/`fputs` fast-path strlen: `scan_c_str_len`→`scan_c_string` (`bd-2g7oyh`, cc/BlackThrush) | end-to-end `fputs_glibc_bench` | strlen is <2% of the 105-183 ns/call fl fputs cost | glibc 17 ns/call | ~1.00x net (strlen change negligible) | NEUTRAL / REVERTED | Reverted. End-to-end measurement (added this turn) proved the strlen swap is ~0-gain: fputs is dominated by the registry-lock write path (6-12x loss row above), not the strlen. The kernel A/B (snprintf_s_strict_ab_bench) showed SWAR strlen beats the byte loop, but that win is invisible behind fputs's lock+write. Restored `scan_c_str_len`. Lesson: a kernel-level win must be validated END-TO-END before claiming it for a function whose dominant cost is elsewhere. |
| 2026-06-20 | wide-printf OUTPUT buffer pooling — `render_wprintf` returns pooled `ScratchVec` instead of `.into_vec()` (cc/BlackThrush) | `stdio_glibc_baseline_swprintf_wide_format` | fl 1.361 us | glibc 1.358 us | 1.002x | NEUTRAL | Keep (commit `99de4dee3`). Distinct from the bd-fgnxc0 INPUT-side `wide_to_narrow` pool row below: this stops `swprintf`/`wprintf`/`fwprintf`/`vswprintf`/`vwprintf`/`vfwprintf` from allocating+discarding a fresh ~256B Vec per call (the narrow snprintf family already pools). Microbench-neutral single-threaded (swprintf cost dominated by wide<->narrow conversion) but a strict allocation reduction (zero added cost, helps allocator pressure / multithread) — kept under the correctness/hygiene exception, not as a speed win. Byte-identical; abi lib tests 202/0. |
| 2026-06-20 | deployed strict single-threaded `getenv` exact-name hot cache (`bd-2g7oyh.496`, BlackThrush/cod-b) | `strtol_glibc_bench` `getenv_hit`/`getenv_miss`, same-worker `vmi1152480` A/B | hit 41.20 -> 12.43 ns; miss 64.90 -> 21.45 ns | hit 17.21 / 15.93 ns; miss 25.60 / 23.34 ns | 2.39x -> 0.78x / 2.53x -> 0.92x | WIN / WIN | Keep. Single-entry TLS cache keyed by exact name length plus packed first 16 bytes, guarded by `ENVIRON_EPOCH` invalidated on successful `setenv`/`unsetenv`/`putenv`/`clearenv`; disabled in tests and after `__libc_single_threaded` flips to 0. Touched-file rustfmt and `git diff --check` passed; local getenv conformance passed 2/0 + 9/0; rch release build passed on `vmi1152480`; rch focused conformance passed on `vmi1227854` after worker reroute. Full final bench rows in `tests/artifacts/perf/bd-2g7oyh-getenv-hot-cache.md`. |
| 2026-06-20 | BSD `snprintb` streaming bit-name visitor (`bd-2g7oyh.485`, BlackThrush/cod-b) | `stdio_bench` `stdio_snprintb/named_bits_stream_12`, same-worker `vmi1149989` old-vs-new; no host-glibc comparator exists for BSD `snprintb` | streaming visitor p50 1.3500 us | old collect-Vec p50 1.3316 us | 1.014x old-vs-new; host glibc N/A | NEUTRAL/REJECT | Reverted source to `collect_set_names`; kept benchmark hook and behavior guard. Do not retry this streaming visitor without an allocation-dominant or multiline-specific profile. Evidence: `tests/artifacts/perf/bd-2g7oyh.485-snprintb-stream-names.md`. |
| 2026-06-20 | strict `calloc/free` bounded hot-class slab + global live table (`bd-deployed-malloc-membrane-50x-vmuu73`, BlackThrush/cod-b) | `calloc_glibc_bench calloc_cycle`, same-worker `vmi1227854` baseline vs candidate | candidate p50 16/256/4096/65536/262144/1048576/4194304 B = 120.002 / 251.255 / 295.500 / 611.348 / 1863.658 / 8560.236 / 41947.353 ns | 4.584 / 19.587 / 48.217 / 406.034 / 1491.685 / 8265.335 / 42680.307 ns | 26.18x / 12.83x / 6.13x / 1.51x / 1.25x / 1.04x / 0.98x | LOSS vs glibc / REJECT vs prior FL | Reverted. Current-head baseline FL p50 on the same worker was 79.578 / 211.482 / 247.232 / 612.980 / 1815.999 / 8515.143 / 43437.303 ns, so the target hot classes regressed 1.508x / 1.188x / 1.195x. The slab avoided fallback-table participation but added live-table probes plus mandatory zeroing; do not retry bounded exact hot-class slab caching as a standalone strict allocator lever. Evidence: `tests/artifacts/perf/bd-deployed-malloc-membrane-50x-vmuu73-cod-b-slab.md`. |
| 2026-06-20 | strict `calloc/free` one-slot recycle + live-slot + inline zero candidate (`bd-f874go`, BlackThrush/cod-b) | `calloc_glibc_bench calloc_cycle`, final same-worker `vmi1153651` run | p50 16/256/4096/65536/262144/1048576/4194304 B = 91.418 / 421.490 / 487.234 / 1496.238 / 4924.500 / 21254.030 / 104458.013 ns | 11.196 / 37.891 / 116.207 / 1016.709 / 4422.657 / 20124.078 / 103633.044 ns | 8.16x / 11.12x / 4.19x / 1.47x / 1.11x / 1.06x / 1.01x | LOSS vs glibc / REJECT vs prior FL | Reverted. It only self-won 16 B (0.223x vs `fl_old` p50); target 256 B lost vs `fl_old` (1.012x), 4096 B lost (1.054x), 65536 B lost (1.018x), and 4 MiB p50/tails regressed. Local routing baseline plus simple-slot and live-slot remote candidates are recorded below. Do not retry one-slot hot-class recycle without a new ownership model or a multi-block/thread-local slab with same-worker proof. |
| 2026-06-20 | vDSO timing direct-pointer cache + buffered hit counters, then narrowed `time()`-only cache (`bd-2g7oyh`, BlackThrush/cod-a) | `strtol_glibc_bench` `clock_gettime`/`time`, same-worker `hz2` A/B | baseline clock 30.29 ns / time 3.52 ns; candidate A clock 31.36 ns / time 2.44 ns; candidate B clock 30.29 ns / time 3.79 ns | baseline clock 25.43 ns / time 2.17 ns; candidate A clock 25.43 ns / time 2.44 ns; candidate B clock 25.43 ns / time 2.16 ns | baseline 1.19x / 1.63x; candidate A 1.23x / 1.00x; candidate B 1.19x / 1.75x | MIXED then LOSS | Reverted all source. Candidate A cut `time()` to parity but regressed `clock_gettime`; candidate B restored `clock_gettime` but made `time()` worse than baseline. Do not retry the resolved-vDSO-pointer cache or TLS-buffered hit-counter family. Focused vDSO tests passed 10/10 before rejection. Evidence: `tests/artifacts/perf/bd-2g7oyh-vdso-time-cache-reject.md`. |
| 2026-06-20 | deployed strict `getenv` fused name validation + raw pointer environ compare (`bd-2g7oyh`, BlackThrush/cod-a) | `strtol_glibc_bench` `getenv_hit`/`getenv_miss`, same-worker `vmi1227854` A/B | hit 26.42 -> 19.15 ns; miss 36.10 -> 27.66 ns | hit 10.56 / 10.14 ns; miss 13.58 / 14.68 ns | 2.50x -> 1.89x / 2.66x -> 1.88x | WIN gap-cut / still LOSS vs glibc | Keep. Fuses the strict fast-path NUL scan and `=` validation, then compares environment entries by raw pointer+length to avoid a second name pass. Focused getenv differential conformance passed 2/0, metamorphic getenv passed 9/0, and `cargo build -p frankenlibc-abi --release` passed via `rch` on `vmi1227854`. Evidence: `tests/artifacts/perf/bd-2g7oyh-getenv-fused-name-scan.md`. |
| 2026-06-20 | `qsort_16_i32` deployed small-sort measurement apparatus (`bd-2g7oyh`, BlackThrush/cod-a) | `glibc_baseline_bench` `qsort_16_i32`; core screen on `hz1`, ABI screen on `vmi1293453` | core 160.522 ns; ABI 12562.578 ns | core 244.160 ns; ABI 12476.459 ns | core 0.657x / ABI 1.007x | WIN core / NEUTRAL ABI | No qsort source change. Added the small-qsort bench row and an ABI arm to disprove the stale deployed 12x-loss route: the core algorithm already wins, and deployed ABI is effectively parity. Evidence: `tests/artifacts/perf/bd-2g7oyh-getenv-fused-name-scan.md`. |
| 2026-06-20 | strict pure-literal `snprintf("literal")` read-only format cache + inlined word copy (`bd-zexi06`, BlackThrush/cod-b) | `stdio_glibc_baseline_bench` literal group, final same-worker `hz1` run | baseline 1.9118 us -> final 10.960 ns mean | baseline 26.287 ns; final 22.036 ns mean | 72.73x loss -> 0.497x WIN | WIN | Keep. The first no-render shortcut still lost on `vmi1227854` (55.287 vs 14.563 ns, 3.80x) and the read-only length cache still lost on `vmi1149989` (27.941 vs 17.671 ns, 1.58x); only the cache plus exact unaligned word copy beat glibc. Adjacent exact string guards on `hz1` still win: `%s\n` 24.130 vs 35.897 ns (0.672x), `%s` 23.474 vs 28.263 ns (0.831x). Focused `diff_snprintf` conformance passed 7/0; `cargo build -p frankenlibc-abi --release` passed. Evidence: `tests/artifacts/perf/bd-zexi06-cod-b-literal-snprintf.md`. |
| 2026-06-20 | strict exact `snprintf("%s")` / `snprintf("%s\n")` fused direct copy (`bd-0ft0w3`, BlackThrush/cod-b) | `stdio_glibc_baseline_bench` exact string groups, final fused run on `vmi1153651` | `%s\n` 67.224 ns mean; `%s` 63.297 ns mean | `%s\n` 86.029 ns mean; `%s` 93.254 ns mean | 0.781x / 0.679x | WIN / WIN | Keep. Current-head baselines were `%s\n` 392.83 vs 32.120 ns (12.23x loss, `hz1`) and `%s` 561.55 vs 84.221 ns (6.67x loss, `vmi1293453`). The first strict shortcut still lost (1.93x / 2.26x), then fused scan+copy converted the final in-run rows to wins. Hardened mode and non-exact formats stay on the existing membrane/printf-engine path. Evidence: `tests/artifacts/perf/bd-0ft0w3-cod-b-snprintf-direct.md`. |
| 2026-06-20 | deployed `strtol` base-10/base-16 direct C-string parser (`bd-2g7oyh`, BlackThrush/cod-a) | `strtol_glibc_bench`, same-worker `vmi1152480`, clean `e464f5c31` baseline vs candidate | `short` 14.21 -> 7.65 ns; `long` 34.25 -> 22.16 ns; `hex` 37.68 -> 21.38 ns | `short` 8.76 / 4.82 ns; `long` 18.07 / 17.88 ns; `hex` 18.24 / 18.02 ns | 1.62x -> 1.59x / 1.90x -> 1.24x / 2.07x -> 1.19x | WIN gap-cut / NEUTRAL short | Keep. A fused C-string transducer removes the NUL pre-scan, slice construction, and core re-scan for deployed base-10/base-16 `strtol` while preserving exact overflow and `endptr` behavior. `strtol_dec_long` and `strtol_hex` are real same-worker gap cuts; `strtol_dec_short` is only neutral by ratio. Fuzz: 1,000,000 comparisons vs host glibc, 0 divergences. Evidence: `tests/artifacts/perf/bd-2g7oyh-strtol-direct-cstring.md`. |
| 2026-06-20 | deployed `atoi`/`atol`/`atoll` base-10 single-pass parser (`bd-2g7oyh`, BlackThrush/cod-a) | `strtol_glibc_bench` deployed `ato*`, final clean post-rebase same-worker `vmi1149989` | `atoi` 2.97/7.51 ns; `atol` 2.80/9.31 ns; `atoll` 2.53/7.57 ns | `atoi` 5.25/14.67 ns; `atol` 4.91/10.77 ns; `atoll` 4.92/10.99 ns | 0.57x / 0.51x / 0.57x / 0.87x / 0.52x / 0.69x | WIN | Keep. Original same-worker baseline rows were all losses (`2.54x-3.43x` vs glibc); final clean candidate is `3.8x-11.2x` faster than that baseline FL and still beats host glibc on all six `ato*` rows after rebasing over upstream's weaker membrane fast path. Same-run `strtol_*` and `strtod_int`/`strtod_sci` rows remain residual losses (`2.05x-3.11x`, `1.37x`, `1.69x`) and are routed deeper; `strtod_simple` stays an unrelated win. Evidence: `tests/artifacts/perf/bd-2g7oyh-strtol-atoi-fastpath.md`. |
| 2026-06-20 | strict fallback-tracked `realloc` same-size / same-small-class in-place fast path (`bd-f874go`, BlackThrush/cod-b) | `calloc_glibc_bench realloc_cycle` on `vmi1149989`: `same_256`, `same_class_shrink_256_to_240`, `cross_class_shrink_256_to_128`, `same_class_shrink_4096_to_3584` | candidate p50 13.333 / 170.314 / 239.357 / 171.915 ns | candidate p50 3.288 / 7.480 / 17.063 / 24.170 ns | 4.06x / 22.77x / 14.03x / 7.11x | LOSS vs glibc / WIN vs prior FL | Keep. Same-worker p50 vs current-head FL improved 0.193x / 0.750x / 0.739x / 0.607x, with mean 0.296x / 0.560x / 0.948x / 0.648x. Still loses every row to glibc, so this is only a measured gap-narrowing allocator keep, not a perf-closeout. Conformance: focused `malloc_abi_test realloc` passed 7/0; release build passed. Evidence: `tests/artifacts/perf/bd-f874go-realloc-same-class.md`. |
| 2026-06-20 | fallback allocation table deletion-time tombstone compaction (`bd-2g7oyh`, BlackThrush/cod-a) | `calloc_glibc_bench` deployed `calloc/free`, `vmi1293453` | 16 B 126.620 ns; 256 B 747.608 ns; 4096 B 823.597 ns; 1 MiB 21035.057 ns; 4 MiB 108814.652 ns | 16 B 11.529 ns; 256 B 37.921 ns; 4096 B 153.098 ns; 1 MiB 19578.059 ns; 4 MiB 118209.750 ns | 10.98x / 19.72x / 5.38x / 1.07x / 0.92x | MIXED / REVERTED | Reverted. Mid-size p50 improved versus the 2026-06-19 same-worker artifact, but 16 B regressed, 1 MiB and 4 MiB regressed in absolute p50, and 256 KiB mean regressed from 6490.414 ns to 11097.125 ns. The target small/medium rows still lose badly to glibc, so deletion-time tombstone clearing is not a shippable allocator lever. See `tests/artifacts/perf/bd-2g7oyh-calloc-strict-fastpath.md`. |
| 2026-06-20 | `snprintf` exact `%s` / `%s\n` parser bypass (`bd-2g7oyh`, BlackThrush/cod-a) | `stdio_glibc_baseline_bench snprintf_s` with host `snprintf` resolved by `dlmopen(LM_ID_NEWLM)` | `%s\n`: 615.58 ns; `%s`: 679.92 ns | `%s\n`: 65.319 ns; `%s`: 88.771 ns | 9.424x / 7.659x vs glibc | LOSS vs glibc / WIN vs prior FL | Partial keep. Same-worker A/B with the bypass disabled: `%s\n` 785.41 ns -> 615.58 ns (0.784x, 1.28x faster), `%s` 1.1712 us -> 679.92 ns (0.581x, 1.72x faster). Keeps the measured self-win and the `dlmopen` host-bench fix, but deployed `snprintf` remains a real glibc loss. |
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
| 2026-06-19 | gid hot-result cache + gid-only C stat fingerprint (`bd-2g7oyh.492`) | `glibc_baseline_grp_lookup/getgrnam_root` | 9.791 us | 24.739 us | 0.396x | WIN | Guard held on `hz2`: keeping the direct stat probe on gid lookup only preserves the prior name-lookup win. |
| 2026-06-19 | gid hot-result cache + gid-only C stat fingerprint (`bd-2g7oyh.492`) | `glibc_baseline_grp_lookup/getgrgid_0` | 14.687 us | 15.179 us | 0.968x | NEUTRAL | Partial keep, not p50 domination. FrankenLibC p50 improved from the previous `hz2` corrected-source 24.631 us to 14.687 us; mean ratio 0.939x and p95 ratio 0.931x vs glibc. Route remaining p50 gap deeper. |
| 2026-06-19 | default `/etc/group` hot-hit stat skip (`bd-2g7oyh.493`, candidate A) | `glibc_baseline_grp_lookup/getgrnam_root` | 9.798 us | 25.077 us | 0.391x | WIN | Guard only. Rejected/not landed because target `getgrgid_0` lost same-run p50. |
| 2026-06-19 | default `/etc/group` hot-hit stat skip (`bd-2g7oyh.493`, candidate A) | `glibc_baseline_grp_lookup/getgrgid_0` | 10.056 us | 9.029 us | 1.114x | LOSS | Rejected/not landed. Same-run `hz2` target p50 and mean/tail stayed slower than glibc despite absolute FL improvement versus the neutral baseline. |
| 2026-06-19 | default hot-hit stat skip + libc `getenv` probe (`bd-2g7oyh.493`, candidate B) | `glibc_baseline_grp_lookup/getgrnam_root` | 16.181 us | 40.272 us | 0.402x | WIN | Cross-worker guard only; `rch` routed to `hz1` despite an `hz2` preference. Rejected/not landed because target `getgrgid_0` lost same-run p50. |
| 2026-06-19 | default hot-hit stat skip + libc `getenv` probe (`bd-2g7oyh.493`, candidate B) | `glibc_baseline_grp_lookup/getgrgid_0` | 16.152 us | 10.022 us | 1.612x | LOSS | Rejected/not landed. Same-run `hz1` loss; do not retry default-only stat/env bypass as the residual fix. |
| 2026-06-19 | strict `grp` runtime-policy bypass (`bd-2g7oyh.494`, candidate) | `glibc_baseline_grp_lookup/getgrgid_0` | 9.831 us | 11.091 us | 0.886x | WIN / NO-SHIP | Rejected/not landed as a gain. Candidate run on `vmi1293453` beat glibc, but the clean `HEAD` baseline that completed was on `vmi1153651` (FL already 0.851x glibc), and the same-path `vmi1167313` baseline hung before structured/host output. Cross-worker absolute speedup is routing evidence only. See `tests/artifacts/perf/bd-2g7oyh.494-strict-grp-policy-bypass-reject.md`. |
| 2026-06-20 | passwd uid hot-result cache + uid-only C stat fingerprint (`bd-2g7oyh.495`) | `nss_passwd_lookup/getpwuid_0_glibc_comparable` | 17.881 us | 13.144 us | 1.361x | LOSS vs glibc / WIN vs old fl | Partial keep. Same-worker `hz1` old-vs-new improves FrankenLibC p50 23.970 -> 17.881 us (0.746x, -25.4%) and Criterion estimate 22.650 -> 19.038 us (0.840x), but p50 still loses vs glibc. `ovh-a` corroboration: 11.426 us vs 10.099 us, 1.131x p50 loss / 0.943x mean win. Route remaining gap to a per-generation uid index or lower-cost invalidation primitive. |
| 2026-06-20 | passwd uid hot-result cache guard (`bd-2g7oyh.495`) | `nss_passwd_lookup/getpwnam_root_glibc_comparable` | 9.386 us | 10.109 us | 0.929x | WIN guard | Cross-worker `ovh-a` guard only; the lever is uid-only and should not be credited as a name-lookup win. Same-worker `hz1` name timings were noisy with both FL and glibc slower in the candidate run, so this row records no regression signal, not target progress. |
| 2026-06-19 | calloc `alloc_zeroed` fresh-mmap skip (`bd-7ak6cm`) | `calloc_glibc_bench` 1 MiB (new vs old) | 13028.9 ns (new) | 12522.4 ns (old) | 1.040x | LOSS | Reverted. `ovh-a`, single-process controlled new-vs-old (calloc/alloc_zeroed vs malloc+write_bytes). NEUTRAL 256 B–4 MiB (band 0.98–1.04), slight loss at 1 MiB. Root cause: arena forces `align=32 > MIN_ALIGN(16)`, so Rust `System::alloc_zeroed` never forwards to libc `calloc` — it does `alloc`+`write_bytes` identically to baseline, so the mmap-zeroed skip is unreachable. Kept reusable bench harness; see `tests/artifacts/perf/bd-7ak6cm-calloc-alloc-zeroed.md`. glibc 1 MiB p50 11792.4 ns (~6% under `fl_old`; fixed membrane overhead, not memset). |
| 2026-06-19 | general `powf` f64 `exp(y·ln x)` route (`bd-z8p3mx`) | `powf_glibc_bench` general_big_e | 30.85 ns (fl) | 7.89 ns (glibc) | 3.91x | LOSS-vs-glibc / **WIN-vs-fl_old 0.689x** | KEPT — strict improvement, no regression. fl general powf 1.4–1.6x faster than the prior `libm::powf` fallback (general_big_e 0.689x, general_small_1p7 0.609x, general_big_pi 0.726x vs fl_old) but still ~3.9x slower than glibc's fused f32 kernel (two f64 transcendentals vs one fused f32). Accuracy ≤1 ULP over 6981 inputs (new gate `conformance_diff_powf_general`); overflow/underflow/subnormal defer to libm so errno/FE parity holds. Follow-up bead filed for the fused-kernel port. See `tests/artifacts/perf/bd-z8p3mx-powf-general-f64-route.md`. |
| 2026-06-19 | fused single-pass f32 `powf` kernel — glibc `__ieee754_powf` port (`bd-z8p3mx` / `bd-fused-f32-powf-kernel`) | `powf_glibc_bench` general_big_e | 9.27 ns (fl) | 7.53 ns (glibc) | 1.23x | **near-parity / WIN-vs-fl_old 0.206x** | KEPT — supersedes the f64 route above. Ported ARM optimized-routines `powf.c` + tables (same algorithm glibc ships). **4.8x faster than the prior libm fallback** (general 0.205–0.206x, medium 0.215x vs fl_old) and within **1.23x of glibc**, down from the f64 route's 3.9x. **Bit-exact (0 ULP)** over 6981 inputs — it is glibc's algorithm. Placing it ahead of the int/medium gauntlet also halved the medium-box path (18.9→9.4 ns) and neutralized the exponent-1.337 overfit grid. Residual 1.23x is Rust call/branch overhead vs glibc leaf asm. Conformance green (powf_general bit-exact, 1.337 gate, errno, fp_exceptions). See `tests/artifacts/perf/bd-z8p3mx-powf-general-f64-route.md`. |
| 2026-06-19 | `/etc/aliases` manual member scanner (`bd-4crkqx`) | `resolv_parsers_bench` `parse_aliases_line_typical` (old-vs-new, no host glibc) | 106.877 ns (candidate) | 91.103 ns (baseline) | 1.173x | LOSS | Reverted to split/filter/collect. Same-worker `hz2`; mean 1.272x slower, p95 1.803x slower, p99 1.996x slower. Retry only with a new SIMD/memchr-backed multi-delimiter primitive or a long-row workload profile. |
| 2026-06-19 | `/etc/networks` byte network-number parser (`bd-xxrfvu`) | `resolv_parsers_bench` `parse_networks_line_typical` (old-vs-new, no host glibc) | 195.091 ns (candidate) | 243.090 ns (baseline) | 0.803x | WIN | Keep. Same-worker `vmi1153651`; mean 0.501x, p95 0.144x, p99 0.224x, throughput 1.997x. No source revert. |
| 2026-06-19 | fused f32 `exp2f` kernel — glibc `__ieee754_exp2f` port (`bd-fused-f32-exp-log-kernels`) | `exp_log_glibc_bench` exp2f | 2.36 ns (fl) | 5.22 ns (glibc) | 0.45x | **WIN** | Ported ARM optimized-routines `exp2f.c` (reuses the in-tree exp2 table from powf). 2.2x faster than glibc, 1.3x over libm (3.13 ns). **Bit-exact (0 ULP)** over 22 493 inputs (`conformance_diff_exp2f_general`). Caveat: part of the glibc margin is `math::` inlining (vs glibc's opaque extern call); the robust result is the libm win + glibc-identical algorithm/accuracy. See `tests/artifacts/perf/bd-fused-f32-exp-log-kernels.md`. |
| 2026-06-19 | fused f32 `log2f` kernel — glibc `__ieee754_log2f` port (`bd-fused-f32-exp-log-kernels`) | `exp_log_glibc_bench` log2f | 2.68 ns (fl) | 5.62 ns (glibc) | 0.48x | **WIN** | Ported ARM `log2f.c` (reuses `POWF_LOG2_TAB` + standalone deg-4 poly), replacing the dyadic-profile overfit grid. 2.1x faster than glibc and libm (5.71 ns). **Bit-exact (0 ULP)** over 216 369 inputs. Same inlining caveat. |
| 2026-06-19 | fused f32 `expf` kernel — glibc `__ieee754_expf` port (`bd-fused-f32-exp-log-kernels`) | `exp_log_glibc_bench` expf (x>5) | 3.01 ns (fl) | 5.46 ns (glibc) | 0.55x | **WIN** | Ported ARM `expf.c` (reuses the exp2 table + scaled poly) for 5<|x|<87; the existing [-5,5] path is kept. 1.8x faster than glibc, 2.5x over libm (7.51 ns). Bit-exact in the kernel range. Same inlining caveat. |
| 2026-06-19 | fused f32 `logf` kernel — glibc `__ieee754_logf` port (`bd-fused-f32-exp-log-kernels`) | `exp_log_glibc_bench` logf | 2.45 ns (fl) | 5.18 ns (glibc) | 0.47x | **WIN** | Ported ARM `logf.c` (reuses `POWF_LOG2_OFF` + dedicated `ln(c)` table). 2.1x faster than glibc, 1.8x over libm (4.38 ns). **Bit-exact (0 ULP)** over 216 369 inputs (`conformance_diff_logf_general`). Same inlining caveat. Completes the f32 math-overfit vein (powf/exp2f/log2f/expf/logf all glibc-class fused). |
| 2026-06-19 | fused f64 `exp2` kernel — glibc `__ieee754_exp2` port (`bd-fused-f64-pow-exp-log-kernels`) | `exp2_f64_glibc_bench` | 3.27 ns (fl) | 5.43 ns (glibc) | 0.60x | **WIN** | Ported ARM `exp2.c` table kernel (256-u64 `__exp_data.tab` N=128, extracted programmatically). 1.66x faster than glibc, 1.25x over libm (4.12 ns). ≤4 ULP over 221 546 inputs (`conformance_diff_exp2_f64_general`), worst 1 ULP at the near-subnormal tail (FMA-vs-non-FMA, not a bug). Routes normal-result interior; tiny/overflow/underflow/special defer to libm. Same inlining caveat. `__exp_data` table now in-tree for the f64 `exp`/`pow` ports. See `tests/artifacts/perf/bd-fused-f64-pow-exp-log-kernels.md`. |
| 2026-06-19 | strchr page-safe 32-byte SIMD scan (`bd-4rxozm`) | `strchr_glibc_bench` 64 KiB (before vs after) | 955.5 ns (SIMD) | 7464.6 ns (SWAR) | 0.128x | **WIN** | Widened deployed `scan_c_string_for_byte` (strchr/strchrnul) from SWAR 8B to page-safe 32B portable SIMD (mirrors the in-file `scan_c_str_len` page guard). **2.9–7.8x faster than the prior SWAR** (16K 7.17x, 64K 7.81x, 256K 7.35x), closing the glibc gap from ~14–18x to **~1.8–2.5x** at large sizes. Controlled same-worker before/after; glibc via `dlmopen`. Conformance green (3 differential gates); **page-safety proven** by new `strchr_guard_page_safety` (NUL at every offset in the last 40 B of a page with the next page `PROT_NONE` — no over-read). Residual small-size 5.5x = membrane per-call overhead, not the scan. See `tests/artifacts/perf/bd-4rxozm-strchr-simd.md`. |
| 2026-06-19 | strchr folded 4×32=128B tier on top of the 32B SIMD (`bd-4rxozm`) | `strchr_glibc_bench` (fl/glibc, in-run control) | 1.24–1.61x (large) / 8.18x (64 B) | 1.79–2.46x / 5.80x (32B) | mixed | **REVERTED** | Folded tier (one `.any()` per 128 B, mirrors `find_byte_or_nul`) closed the large-size glibc gap further (256K 1.88x→1.24x, 64K 1.79x→1.31x) but **regressed short strings** (64 B 5.80x→8.18x normalized) by doing 128-byte work for sub-128 strings. Typical strchr operates on short strings, so the common-case regression outweighs the rare large-buffer gain → reverted to the committed 32B tier. Correctness + guard-page still passed. Retry only with a length-escalation guard (32B tier first, fold after confirming a long string). |
| 2026-06-19 | strchr **length-escalated** folded-128 tier (`bd-4rxozm`) | `strchr_glibc_bench` 256 KiB (vs committed 32B, ~identical glibc control) | 2537 ns (escalated) | 3980 ns (32B) | 0.64x | **WIN** | The folded reject's retry predicate, realized: gate the folded 4×32=128B tier on `i >= 128` so short strings terminate in the 32B/SWAR tiers and never pay it. **1.35–1.57x faster than the committed 32B at large sizes** (16K 1.35x, 64K 1.41x, 256K 1.57x) with **no short-string regression** (64 B 5.93x vs 5.80x = in-noise). fl/glibc at 256K 1.88x→**1.20x** (near parity), 64K 1.79x→1.26x. Conformance green (strchr/strchrnul gates); page-safety re-proven (`strchr_guard_page_safety`, folded tier exercised near the boundary). Supersedes the reverted un-gated folded row above. |
| 2026-06-19 | strlen folded-128 tier on `scan_c_string` (`bd-4ibo52`) | `strlen_glibc_bench` (folded vs 32B, ~identical glibc control) | 567/1451/4871 ns (folded) | 569/1433/4805 ns (32B) | ~1.00x | **NEUTRAL → REVERTED** | The escalated folded tier that won 1.35–1.57x for strchr is **NEUTRAL for strlen** (16K/64K/256K all within noise) — reverted. Unlike strchr's 2-comparison panel, strlen's single-NUL-comparison scan is already reduction-light, and the deployed strlen cost is dominated elsewhere. **Gap finding (kept the bench):** deployed `string_abi::strlen` is **~2.1x slower than glibc at 256K** (4805 vs 2312 ns) and **~35x at 1 KiB** (288 vs 8 ns) — the small-size cost is per-call membrane + `select_string_simd_dispatch` overhead (architectural, same class as deployed-malloc 50x / strchr small-size), the large-size ~2x is 32B portable_simd vs glibc's wider/unrolled AVX. Not closable by folding. New reusable `strlen_glibc_bench`; guard-page test extended to cover strlen. |
| 2026-06-19 | strlen skip dead `select_string_simd_dispatch` certify (`bd-strlen-dead-dispatch-certify`) | `strlen_glibc_bench` (no-dispatch vs dispatch, same glibc control) | 31.7/288.1/548 ns (no-disp) | 31.9/288.5/569 ns (disp) | ~1.00x | **NEUTRAL → REVERTED** | The strlen path computes `select_string_simd_dispatch` + a Clifford-isomorphism certification whose `lane_bytes` is **provably discarded** by `raw_lane_strlen_bytes` — looked like expensive dead computation. Removing it is **behavior-neutral** (all strlen gates green) but **perf-NEUTRAL**: the certify is *cheap* (std-cached `is_x86_feature_detected` + a fixed `len_hint=64` proof). The real ~30ns/call overhead (vs glibc 2.5ns) is `entrypoint_scope` tracing-span creation + `known_remaining` lookup — the membrane entrypoint machinery, architectural (bd-deployed-malloc-membrane-50x class). Reverted (no gain + drops the dispatch observability log). Corrects an earlier over-eager hypothesis that the certify was the bottleneck. |
| 2026-06-19 | strlen **hoist fast path above `entrypoint_scope`** (entrypoint-tax lever, BlackThrush) | `strlen_glibc_bench` 64 B, same-worker A/B (`ovh-a`, mt=4, thin-LTO) | 27.045 ns (cand) | 27.112 ns (HEAD) | **1.00x** (fl/glibc 12.49x vs 12.57x) | **NEUTRAL → not landed** | Directly tests the line-above hypothesis. The strict-mode raw-scan fast path returns **without ever reading** the `TraceContext` that `entrypoint_scope` installs (only hardened-mode `decide`/PCC paths consult it; `known_remaining`/`select_string_simd_dispatch` don't touch it), so hoisting it above the scope provably elides a TLS trace-seq RMW + 24-arm symbol str-match + two TLS writes per call — **behavior-identical**. Measured **perfectly neutral** (Δp50 = 0.07 ns, fl/glibc ratio unchanged). **Confirms** `entrypoint_scope` is NOT the strlen bottleneck (consistent with the "membrane ~8–11 ns/call" correction below). Reverted; do not retry per-symbol entrypoint hoists as a strlen lever. |
| 2026-06-19 | **lock-free `fallback_remaining`/`fallback_size` reads** (`known_remaining` lever, BlackThrush) | `strlen_glibc_bench` 64 B, same-worker A/B (`ovh-a`, mt=4, thin-LTO) | 39.329 ns (cand, fl/glibc **12.30x**) | 27.112 ns (HEAD, fl/glibc **12.57x**) | **0.98x** ratio (neutral; abs. run was ~48% noisier — glibc 3.20 vs 2.16 ns same-run) | **NEUTRAL → REVERTED** | Tests the other half of the line-above hypothesis. The read probes never mutate the table, so they don't need the writer spinlock: inserts publish `SIZES`(Relaxed)→`PTRS`(Release), so an `Acquire` load of `PTRS` that sees a published key also sees its `SIZES` — **sound** lock elision, distinct from the rejected per-slot-CAS *insert* rewrite (writers keep the lock). Removes an uncontended CAS+release-store from every `known_remaining` read (string ops + free). **Single-thread NEUTRAL** (ratio 0.98, within noise); the uncontended spinlock is too cheap to see here. A multi-thread reader-contention benefit is plausible but **unmeasured**, so reverted under the MEASURED discipline. Retry only with a multi-threaded contention bench. |
| 2026-06-19 | strrchr **bounded-path** 32B SIMD skip (`scan_c_string_last_byte`, BlackThrush) | `memset_abi_bench` strrchr bounded vs unbounded(SIMD)/glibc, same-run `ovh-a` | bnded 65536 **6690→1160 ns** | unbnd 922 / glibc 1378 ns | bnd/unbnd 7.25x→**1.11x** | **WIN → landed** | The unbounded (`None`) strrchr scan already had the 32B portable-SIMD skip; the bounded (`Some(limit)`, membrane-tracked-buffer) path was still 8B SWAR — measured **~7x slower** than the SIMD path at 64 KiB and ~7x slower than glibc. Mirrored the proven unbounded skip (panel with no target & no NUL advances 32; bound-guard `i+32<=limit` + page-guard; any hit drops to the exact SWAR resolve). Now **~5.4–5.8x faster** (4096 6.02x→1.31x, 16384 6.95x→1.31x, 65536 7.25x→1.11x bnd/unbnd) and **beats glibc** at 64 KiB (1160 vs 1378 ns, 0.84x). Byte-identical: existing `conformance_diff_strrchr`/`_simd` + `strchr_guard_page_safety` green, plus a NEW `conformance_strrchr_bounded` gate (>1000 randomized cases across head/skip/tail tiers + NUL/target/limit edges vs a scalar spec, 2/2). Reuses the strchr 32B-SIMD technique (bd-4rxozm) on the last remaining narrow scanner. |
| 2026-06-19 | wcschr **folded 128B SIMD tier** (`wide_find_or_nul_simd`, BlackThrush) | `memset_abi_bench` wcschr (absent target, full wide scan to NUL) vs `libc::wcschr`, same-run `ovh-a` | 65536 **4750→3114 ns** | glibc 3182 ns | vs glibc 0.69x→**1.02x** | **WIN → landed** | Broad-sweep found wcschr was the lone wide-fn LOSS: ~**1.4x slower than glibc at ≥1024 wchars** (1024 0.70x, 4096 0.73x, 16384 0.71x, 65536 0.69x) while winning at ≤256. Root cause: the deployed wide find was a plain 8-lane (32B) panel with one `.any()` per 32 bytes — no unrolling, vs glibc's unrolled wcschr. Added a length-escalated folded **4×8=32-lane (128B)** tier (one combined reduction per 128B), gated on `i>=32` + page-guarded — the exact strchr folded-128 pattern (bd-4rxozm), which pays here because the panel does 2 comparisons (c|NUL). Result: now **parity-or-faster at every size** (1024 **1.21x**, 4096 1.05x, 16384 1.01x, 65536 1.02x — fl beats glibc) with **no short-string regression** (16/64 still 2.5-2.7x wins). Byte-identical + page-safe: `conformance_diff_wcschr` 3/3 (incl golden-sha256 + unmapped-page guard), `wcs_family` 4/4, `wchar_abi_test` 118/0. |
| 2026-06-19 | wcsrchr folded 128B SIMD tier (`wide_last_before_nul_simd`, BlackThrush) | `memset_abi_bench` wcsrchr (added fl-hook + glibc arms), same-run `ovh-a` | 65536 fl 2561→2542 ns | glibc 2606→2572 ns | fl/glibc 1.02x→**1.01x** | **NEUTRAL → reverted** | Tried the same folded-128 tier that won big for wcschr. But wcsrchr is NOT a loss: fl's plain 32-byte scan **already beats glibc at every size** (16 2.7x … 65536 1.02x — glibc's wcsrchr is less optimized than its wcschr). So there's no room: folded was within noise at ≥1024 (65536 1.02→1.01x, 1024 1.17→1.20x) and **regressed 256** (1.61→1.47x, the i≥32 gate makes the cache-resident 256-wchar case pay the folded reads). Reverted the tier; **kept** the new `bench_wide_last_before_nul_simd` hook + a corrected wcsrchr bench arm (the old arm mislabeled scalar-vs-glibc as "old/abi"; now old/fl/glibc) as the permanent fl-vs-glibc apparatus + evidence that fl wcsrchr already wins. Conformance `conformance_diff_wcsrchr` green. LESSON: the folded-128 lever only pays where fl actually LOSES; on functions fl already wins it adds short-string overhead. |
| 2026-06-19 | iconv **ASCII→UTF-16/32 SIMD widen** fast path (`iconv/mod.rs` convert loop, BlackThrush) | NEW `iconv_glibc_bench` (fl C ABI vs glibc dlmopen), `utf8_to_utf16le_ascii` 1 KiB, `ovh-a` | **6892→550 ns** | glibc 1247 ns | fl/glibc **5.55x → 0.44x** | **WIN → landed** | A fl-vs-glibc iconv sweep (new bench) found UTF-8→UTF-16LE of ASCII was the lone iconv LOSS: **5.55x slower than glibc** (6892 vs 1247 ns) — an outlier even vs fl's own other conversions (283-1195 ns) and a ubiquitous conversion (Windows/Java/JS interop). Root cause: the convert loop had a SIMD 2-byte (Cyrillic) → UTF-16 path and a 1→1-byte `fast_ascii` bulk-copy, but **no ASCII→fixed-width path** — ASCII runs fell to the per-char decode/encode scalar loop. Added a SIMD ASCII-widen tier (16 bytes/window, one high-bit test, widen byte→`[b,0]`/`[0,b]`/UTF-32), same guards as the 2-byte block. Result: **12.5x self-speedup (6892→550 ns), now 2.3x FASTER than glibc** (0.44x), other conversions unchanged (fl already wins latin1 5x, Cyrillic 1.5-1.9x). Byte-identical: `conformance_diff_iconv` 2/2 + NEW `conformance_iconv_ascii_widen` 3/3 (all 16-byte-window lengths/boundaries, mixed ASCII/non-ASCII transitions, E2BIG mid-run vs scalar ref). NOTE: 8 pre-existing SBCS-codec core test failures (koi8u/cp851/mik/rk1048/… RED on main per bd-k4ct23, an unrelated DBCS-table gap) are provably independent — this change is gated to UTF-16/32 targets only. |
| 2026-06-19 | iconv **UTF-16/32→UTF-8 ASCII 1-byte SIMD run** (`iconv/mod.rs`, BlackThrush) | `iconv_glibc_bench` `utf16le_ascii_to_utf8` 1 KiB, `ovh-a` | **524382→2510 ns** | glibc ~1435-2086 ns | fl/glibc **365x → 1.20x** | **WIN → landed** | Expanding the iconv head-to-head to the REVERSE direction exposed a CATASTROPHIC gap: UTF-16LE ASCII→UTF-8 was **365x slower than glibc** (524 µs vs 1.4 µs / 1 KiB = 512 ns/char). Root cause: the SIMD UTF-16/32→UTF-8 encoder had a 2-byte run (0x80-0x7FF) and a 3-byte run (0x800-0xFFFF) but **no 1-byte (ASCII <0x80) run**, so ASCII fell to the pathological per-char generic body. Added a 1-byte run mirroring the others (read 8 source units, SIMD-check all <0x80, narrow low byte). Result: **208x self-speedup (524382→2510 ns), now ~parity (1.20x)** with glibc. Byte-identical: `conformance_diff_iconv` 2/2 + `conformance_iconv_ascii_widen` 4/4 (added a reverse UTF-16/32→UTF-8 narrow test across the 8-unit window boundaries). NOTE: same 8 pre-existing SBCS failures (bd-k4ct23), unrelated. FOLLOW-UP gap found same sweep: `utf8_cjk_to_gb18030` 1.72x slower (GB18030 reverse-table encode) — separate lever, queued. |
| 2026-06-19 | iconv **CP932/IBM943/IBM932 added to DBCS→UTF-8 fast-path guard** (`iconv/mod.rs`, BlackThrush) | `iconv_glibc_bench` `cp932_to_utf8` 1 KiB, `ovh-a` | **26968→2689 ns** | glibc 333 ns | fl/glibc **81x → 8.08x** | **WIN → landed** | Decode-side iconv sweep found `CP932→UTF-8` was **81x slower than glibc** (27 µs / 512 JP chars). Root cause: the DBCS→UTF-8 fast-path GUARD (24124) listed 9 encodings but the `match` body handled 12 — **Cp932, Ibm943, Ibm932 were in the match but missing from the guard**, so they bypassed the fast path to the slow per-char generic body. Added them to the guard (the match already decodes them → byte-identical). Result: **10x self-speedup (26968→2689 ns)**, 81x→8.08x. Still 8x off glibc's exceptionally fast CP932 decode (separate harder lever = SIMD the DBCS decode). Byte-identical: `conformance_diff_iconv` 2/2 + `conformance_diff_iconv_cp932` 3/3. FOLLOW-UPS (measurable via iconv_glibc_bench, queued): GB18030→UTF-8 157 µs (IN the guard already — likely entangled with the bd-k4ct23 DBCS-table decode gap, a correctness bug, NOT touched); CP932 residual 8x (glibc SIMD-class DBCS decode). |
| 2026-06-20 | iconv **CP932-family packed BMP3 UTF-8 direct decode** (`bd-2g7oyh`, BlackThrush) | `iconv_glibc_bench` `cp932_to_utf8` 1 KiB, `hz1` | **27169.4→509.5 ns** | glibc 493.0 ns | fl/glibc **56.27x→1.033x** | **NEUTRAL vs glibc / huge WIN vs old fl** | Keep. Built a 64 Ki entry `DBCS key -> packed UTF-8 triple` table for CP932/IBM943/IBM932 BMP-3 pairs and emits 4 pairs per loop before falling through to the generic path for exact error ordering. Same-worker p50 self-speedup is **53.3x**; final paired score is 1 WIN (`utf8_jp_to_cp932` 2025.2 vs 2335.7 ns, 0.867x) and 1 NEUTRAL (`cp932_to_utf8` 509.5 vs 493.0 ns, 1.033x), 0 losses. Conformance: `conformance_diff_iconv_cp932` 3/3 green; `cargo check -p frankenlibc-core` green with pre-existing warnings. Residual 3.3% decode gap is routed deeper only if future workers expose a stable post-table loss. |
| 2026-06-20 | iconv **GB18030 packed BMP3 transducers** (`bd-2g7oyh`, BlackThrush) | `iconv_glibc_bench` `utf8_cjk_to_gb18030` + `gb18030_to_utf8` 1 KiB CJK | encode **5622.3→1401.1 ns**, decode **121728.2→976.4 ns** | final glibc 2592.7 ns / 2206.2 ns | final fl/glibc **0.540x / 0.443x** | **WIN / WIN** | Keep. Added packed direct tables for UTF-8 BMP-3 -> GB18030 2-byte keys and GB18030 2-byte keys -> UTF-8 triples, emitting 4 code points per loop and falling back before consuming on ASCII, invalid, 4-byte-only, single-byte, incomplete, or output-tail cases. Baseline was on `hz1` (losses 1.609x encode, 46.756x decode); final `rch` selected `hz2` despite `hz1` preference, so self-speedup is directional, but final in-run fl/glibc ratios are valid deployed head-to-head wins. Scorecard: 2 WIN / 0 NEUTRAL / 0 LOSS. Conformance: `iconv_cjk_differential_fuzz_vs_glibc` 216000 conversions, 0 divergences; `cargo check -p frankenlibc-core` and `git diff --check` green. Evidence: `tests/artifacts/perf/bd-2g7oyh-gb18030-direct-codec.md`. |
<!-- rows appended as benches complete -->

## 2026-06-20 `bd-2g7oyh.496` getenv hot-cache final `strtol_glibc_bench` rows

Final candidate run on `vmi1152480`, `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b`, `cargo bench -p frankenlibc-bench --features abi-bench --bench strtol_glibc_bench -- --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2`.

| Workload | FrankenLibC | glibc | Ratio | Verdict |
|---|---:|---:|---:|---|
| `strtol_dec_short` | 8.75 ns | 9.41 ns | 0.93x | WIN |
| `strtol_dec_long` | 22.67 ns | 18.40 ns | 1.23x | LOSS |
| `strtol_hex` | 22.48 ns | 19.69 ns | 1.14x | LOSS |
| `atoi_short` | 4.27 ns | 11.90 ns | 0.36x | WIN |
| `atoi_long` | 11.39 ns | 21.11 ns | 0.54x | WIN |
| `atol_short` | 4.04 ns | 10.72 ns | 0.38x | WIN |
| `atol_long` | 10.77 ns | 20.53 ns | 0.52x | WIN |
| `atoll_short` | 4.07 ns | 10.57 ns | 0.38x | WIN |
| `atoll_long` | 11.37 ns | 20.08 ns | 0.57x | WIN |
| `strtod_int` | 12.73 ns | 39.97 ns | 0.32x | WIN |
| `strtod_simple` | 71.46 ns | 71.56 ns | 1.00x | NEUTRAL |
| `strtod_sci` | 22.69 ns | 48.10 ns | 0.47x | WIN |
| `rand` | 3.71 ns | 5.03 ns | 0.74x | WIN |
| `getenv_hit` | 12.43 ns | 15.93 ns | 0.78x | WIN |
| `getenv_miss` | 21.45 ns | 23.34 ns | 0.92x | WIN |
| `clock_gettime` | 35.45 ns | 26.28 ns | 1.35x | LOSS |
| `time` | 4.05 ns | 2.43 ns | 1.66x | LOSS |
| `pthread_self` | 1.90 ns | 2.00 ns | 0.95x | WIN |

Target result: `getenv_hit`/`getenv_miss` moved from 2.39x/2.53x losses to
0.78x/0.92x wins on the same worker. Residual routed losses: long/hex
`strtol`, `clock_gettime`, and `time`; `strtod_simple` is neutral.

## 2026-06-19 GAUNTLET SCORECARD — broad fl-vs-glibc sweep, ~50 functions (BlackThrush)

Swept `glibc_baseline_bench` (core primitives, Rust-to-Rust) + `memset_abi_bench`
(scan hooks + wide) on `ovh-a`. **Caveat:** the core bench's thin-LTO inlines fl
but calls glibc `extern` (see the LTO-artifact row above), so it FAVORS fl —
meaning any fl *loss* here is conservatively real, and small fl *wins* (1.0-1.5x)
may be partly inlining. Ratio = fl_p50 / glibc_p50 (lower = fl faster).

**fl DOMINATES (ratio ≪ 1):** memmem 0.002x (~500x), strstr 0.005x (~200x),
memcmp 0.054x (~18x), fnmatch_bracket 0.245x, qsort_128_i32 0.286x, scanf 0.30x,
strspn_long 0.317x, fnmatch_adversarial 0.364x, strtol_hex 0.52x, pow 0.52x,
strtol_long 0.56x, fnmatch_pathname 0.586x, strcmp_256 0.643x, strrchr 0.757x,
memset_4096 0.789x, strchr_absent 0.870x, strlen_4096 0.871x, strtol_short 0.888x,
strpbrk 0.94x, memcpy_4096 0.958x. Wide (memset_abi_bench): wcsstr ~5.7x,
**wcschr now 1.02-1.21x (this session's fix)**, wcsrchr 1.02-2.7x, wcscmp/
wcscasecmp/wmemcmp parity.

**fl LOSES (ratio > 1.05) — the residual gap list:**
| fn | fl/glibc | note |
|---|---|---|
| memmove_4096 (core slice variant) | 1.174x | RESOLVED: not a deployed loss. The two benches call DIFFERENT fl fns — `glibc_baseline_bench` runs the core slice `frankenlibc_core::string::mem::memmove` (the 1.174x loser), `memset_abi_bench` runs `raw_memmove_bytes` (wins 1.17x). The DEPLOYED `memmove` ABI uses `raw_memmove_bytes` (string_abi.rs:1685) → real programs get the WIN. The slow core slice variant is off the deployed hot path (contested mem* area, not pursued). |
| strncasecmp_256_equal | 1.099x | ~10% at 256B equal; scan_strcasecmp already 32B-SIMD; residual is per-call/dual-page-guard, membrane-noise class |
| strncmp_256_equal | 1.052x | ~5% at 256B equal; scan_strcmp already 32B dual-ptr SIMD; marginal |
| deployed strlen @256K | ~1.25-2x | 32B portable_simd vs glibc wider AVX; folded-128 measured NEUTRAL (single NUL compare); needs AVX-512 = not closable on these workers |
| deployed malloc small | "50-71x" | mostly host-heap-isolation ARTIFACT + ~2x diffuse membrane (see decomposition above), not a point-fixable hotspot |

**Conclusion:** after ~50 functions measured, fl beats or ties glibc on the
overwhelming majority; the only residual losses are contested (memmove),
marginal-at-256B (strncmp/strncasecmp ~5-10%, membrane-noise class), or documented
ceilings/artifacts (strlen-AVX, malloc-isolation). The string/wide scan SWAR→SIMD
vein is fully closed (strchr/strrchr/strlen/strcmp/wcschr all SIMD; the last two
landed this session: strrchr-bounded + wcschr-folded). No clean uncontested
significant new lever remains on this surface.

## 2026-06-19 deployed calloc/malloc scorecard refresh + small/large size anomaly (BlackThrush)

Same-worker `ovh-a` thin-LTO `calloc_glibc_bench` at HEAD (mt=3), p50 ns/op
(`fl` = deployed `calloc(1,n)+free`; `fl_old` = `malloc(n)+memset+free`; `glibc`
via `dlmopen` isolated namespace):

| size | fl (calloc) | fl_old (malloc) | glibc | fl/glibc |
|---|---|---|---|---|
| 16 B | 39.9 | **3452.9** | 4.8 | 8.3x |
| 256 B | 1195.6 | 1197.3 | 16.7 | 71.6x |
| 4096 B | 1233.8 | 1227.7 | 42.5 | 29.0x |
| 65536 B | 1664.5 | — | — | — |

Two **non-fixed-cost anomalies** that contradict a "per-call membrane tax"
explanation (the membrane is ~8–11 ns/call per the correction below):

1. **`fl` calloc jumps 39.9 ns → 1195.6 ns between 16 B and 256 B** (≈30x for a
   16x size step) while glibc moves only 4.8 → 16.7 ns. The fl-specific ~1155 ns
   penalty appears *above ~16 B* and is size-independent thereafter — the shape
   of an open-addressing **probe/tombstone degradation in the global
   `FALLBACK_ALLOC_*` table under alloc/free churn** (clustered glibc addresses →
   long probe chains under the writer spinlock), not the allocator and not a
   fixed entrypoint cost.
2. **`fl_old` malloc(16) = 3452.9 ns vs `fl` calloc(1,16) = 39.9 ns** — the only
   code delta is malloc's `proof_carried_fast_path_active` + `decide`/`observe`
   path (calloc's strict host fast-path returns *before* those), and it is
   pathological *only at 16 B* (at 256 B malloc≈calloc≈1197 ns). Allocation-
   pattern/probe-length dependent, not fixed overhead.

**Lead (filed):** the real deployed-malloc lever is the `FALLBACK_ALLOC_*`
table's behaviour under churn, not the entrypoint machinery. A prior **per-slot
CAS insert rewrite REGRESSED** (see the rejected-attempts table) — so the next
attempt must be a *different* shape (e.g. a per-thread last-freed (ptr,size)
absorber in front of the global table, or tombstone-rehash compaction), proven
on a churn bench with a same-worker A/B before landing. Read-path lock elision
(above) is sound but single-thread-neutral.

## 2026-06-19 deployed calloc 1155 ns root-cause hunt — table & check_ownership RULED OUT, free-reorder landed (BlackThrush, bd-f874go)

Decisive same-worker `ovh-a` A/B experiments to attribute the ~1155 ns deployed
calloc/free penalty (calloc p50 256 B 1195.6 ns vs glibc 16.7 ns = 71.6x). All
runs `calloc_glibc_bench`, mt=3, glibc arm as same-run noise normalizer.

| Experiment | calloc 256 B p50 | vs HEAD | conclusion |
|---|---|---|---|
| HEAD baseline (262144-slot table) | 1195.6 ns | — | — |
| **Shrink `FALLBACK_ALLOC_TABLE_SLOTS` 262144 → 16384** (fits L2) | 1199.2 ns | +0.3% | **RULES OUT the fallback table** size/cache as the cost — last section's "probe/tombstone/cache degradation" hypothesis is **wrong**. Diagnostic only, reverted. |
| **Free reorder: skip `check_ownership` (PageOracle::query) for fallback-tracked frees** | 1147.9 ns | **−4.0%** | `check_ownership`/`PageOracle::query` is only **~4% (~47 ns)** of the cost — also not the big lever. Landed (see below). |

So the bench is **calloc-dominated**: free is ~150 ns (of which check_ownership
~47 ns); the remaining **~1000 ns lives in the `calloc` strict host path**
(`native_libc_calloc` ≈ 17 ns + `fallback_insert_sized` ≈ spinlock + ` record_alloc_stats`).
Summing every readable piece (native calloc/free ~27, fallback insert/remove ~14,
`FlatCombiningStats` HTM/lock + full `state.snapshot()` per op ~100, check_ownership
~47) ≈ **~190 ns** — leaving **~960 ns unexplained by code reading**. The 16 B
calloc (39.9 ns) uniquely escapes it; ≥256 B all sit at ~1150–1660 ns. Cause is
NOT the entrypoint tax, NOT the fallback table, NOT check_ownership. **Next step
is an actual flamegraph (`perf record`) of the 256 B calloc loop** — the cost is
in something a static read can't see (candidate: `FlatCombiningStats` HTM-abort
storm if TSX is fused-off on the worker, building+discarding a full snapshot per
op; or glibc address-rotation interacting with a per-call structure). Updated on
bd-f874go.

| Date | Lever / bead | Bench | fl | glibc | ratio | verdict | action |
|------|--------------|-------|----|----|-------|---------|--------|
| 2026-06-19 | free: skip `check_ownership` PageOracle query for fallback-tracked frees (`bd-f874go`, BlackThrush) | `calloc_glibc_bench` 256 B (same-worker `ovh-a`, glibc-stable in-run) | 1147.9 ns | 16.67 ns | fl 256 B **0.960x** vs prior fl (4096 B 0.960x, 16 B 0.965x) | **MARGINAL WIN → landed** | Honest: ratio-vs-prior-fl 0.96 is just under the 0.95 WIN bar, but it is a *reproducible* (3 sizes, glibc stable 16.671 vs 16.674 ns) **non-regression that strictly removes work** — a `PageOracle` RwLock query gone from every deployed strict free of a tracked pointer (the common case), with multi-thread lock-contention upside. Behavior-preserving: such pointers always satisfied `!check_ownership` under the old gate; conformance GREEN (malloc_abi 53/0, foreign_adoption 4/0, malloc_edges/aligned_alloc/realloc_shrink all pass). Does not address the ~960 ns calloc-side residual (needs profiling). |

## 2026-06-19 ⭐ the deployed-calloc "50–71× gap" is MOSTLY a baseline-isolation artifact, NOT membrane overhead (BlackThrush, bd-f874go)

`perf` is unavailable on the workers (`perf_event_paranoid=4`), so instead of a
flamegraph I added a third bench arm to `calloc_glibc_bench`: **`fl_native`** =
the bare main-namespace host glibc `calloc`/`free` that the deployed strict path
delegates to, with **NO membrane bookkeeping** (new `#[doc(hidden)]`
`native_calloc_probe_for_bench`/`native_free_probe_for_bench` in `malloc_abi.rs`).
This three-way split (same-worker `ovh-a`, mt=3) finally decomposes the gap:

| size | `fl` deployed | `fl_native` (bare host, no membrane) | `glibc` (dlmopen isolated) |
|---|---|---|---|
| 256 B | 1143.2 ns | **566.1 ns** | 16.7 ns |
| 4096 B | 1190.0 ns | **600.2 ns** | 41.2 ns |

**Decomposition of the headline 256 B "71×":**
- **~35×** of it (16.7 → 566 ns) is the **bare host glibc allocator running on
  the fl-loaded process's MAIN-namespace heap** — *zero* fl membrane code. fl
  routes ordinary allocations through its own path, so the main glibc arena's
  256 B tcache stays cold and every `calloc` takes glibc's slow path. The
  `glibc` baseline column uses a **pristine `dlmopen(LM_ID_NEWLM)` heap** that the
  bench keeps hot — an unrealistically favorable comparator.
- **~2×** (566 → 1143 ns) is the **actual membrane bookkeeping** (fallback-table
  insert + flat-combining stats + strict-path guards).

So the oft-quoted "deployed malloc 50–71× slower than glibc" **massively
overstates the membrane's real cost (~2×)**; roughly half the gap is a
measurement-methodology artifact of the isolated-heap baseline. (The `fl` 16 B =
39 ns figure is an init-state/bump-alloc artifact of the first-measured arm —
`fl_native` 16 B is 543 ns, i.e. the host main-arena cost is ~flat ~550 ns across
sizes.) Apparatus kept in-tree (additive `fl_native` arm + probes) as the honest
way to measure membrane-vs-host cost; conformance unaffected (no existing path
changed). The remaining fl-controllable lever is the ~2× membrane (~577 ns), not
the headline 71× — and a fair vs-glibc target must compare against `fl_native`
(busy main heap), not the pristine dlmopen heap. Updated bd-f874go.

**Membrane (~577 ns) further bisected — no single hotspot, residual is diffuse:**
all individually-isolable membrane operations are small, so the ~2× is *not*
attackable by removing one piece:

| Membrane piece | Isolation method | Δ on fl 256 B | verdict |
|---|---|---|---|
| `check_ownership` / `PageOracle::query` (free) | reorder to skip for tracked ptrs | −47 ns | landed (ee49d5e16) |
| `record_alloc_stats`+`record_free_stats` (FlatCombiningStats HTM) | no-op both (diagnostic) | **−12 ns** | NOT the cost — reverted (stats are ~12 ns, not the ~500 ns suspected) |
| `FALLBACK_ALLOC_*` table size/cache | shrink 262144→16384 | 0 ns | ruled out (prior section) |

Sum of isolable membrane pieces ≈ 60 ns, but the membrane delta is ~577 ns →
**~500 ns is diffuse** (i-cache/branch/TLB pressure from traversing the large
deployed `malloc_abi` code path: double reentry guards, bootstrap/strict checks,
fallback insert+remove, entrypoint scope). No single lever removes it; closing it
needs a hot-path code-size reduction (aggressive inlining / a slim fast path),
which is a broad membrane-core refactor — filed thinking on bd-f874go, not
attempted unilaterally. **Net: the deployed allocator is ~2× the bare host on a
busy heap, and that 2× has no single fixable hotspot.**

## 2026-06-20 `bd-f874go` strict native allocator reentry-slot reuse (BlackThrush / cod-b)

The first kept code-size/touch-count reduction in the diffuse strict allocator
path is to reuse the already-acquired public allocator reentry slot when the
strict host path calls the native host `calloc`/`free` trampolines. Baseline and
candidate were both routed by `rch` to `vmi1152480` with the same worker-scoped
target pool. p50 ns/op:

| size | baseline fl | baseline glibc | baseline fl/glibc | candidate fl | candidate glibc | candidate fl/glibc | candidate/base fl | verdict | action |
|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 16 B | 85.087 | 7.230 | 11.77x | 86.020 | 7.148 | 12.03x | 1.011x | LOSS | Negative row; keep only because the overall deployed path wins elsewhere. |
| 256 B | 454.890 | 23.275 | 19.55x | 237.286 | 21.068 | 11.26x | 0.522x | LOSS vs glibc / WIN vs baseline | Keep; biggest small-allocation gap improved 47.8%. |
| 4096 B | 446.897 | 81.206 | 5.50x | 273.946 | 47.993 | 5.71x | 0.613x | LOSS vs glibc / ratio neutral-loss | Keep overall; absolute FrankenLibC p50 improved 38.7%, but glibc also sped up. |
| 65536 B | 903.792 | 526.206 | 1.72x | 711.313 | 430.895 | 1.65x | 0.787x | LOSS vs glibc / WIN vs baseline | Keep. |
| 262144 B | 2911.750 | 1644.329 | 1.77x | 1862.715 | 1561.114 | 1.19x | 0.640x | LOSS vs glibc / WIN vs baseline | Keep; normalized gap narrowed sharply. |
| 1048576 B | 14664.400 | 9440.443 | 1.55x | 10027.183 | 9393.547 | 1.07x | 0.684x | LOSS by strict 1.05 cutoff / near parity | Keep; near-parity after 31.6% absolute speedup. |
| 4194304 B | 47376.372 | 48195.740 | 0.98x | 47365.083 | 67326.391 | 0.70x | 1.000x | WIN vs glibc / neutral vs baseline | Keep; deployed FrankenLibC did not regress at the largest size. |

Decision: **KEEP**, but do not score this as allocator dominance. It is a real
deployed fast-path reduction that cuts the worst measured small-row ratio
19.55x -> 11.26x at 256 B and moves 1 MiB from 1.55x to 1.07x, while leaving
16 B negative and 4 KiB still far behind glibc. The live allocator bead remains
open for a slimmer strict fast path or deeper metadata-layout change. Evidence:
`tests/artifacts/perf/bd-f874go-native-reentry-slot.md`.

## 2026-06-20 deployed calloc tombstone compaction measured reject (BlackThrush, bd-2g7oyh)

Focused gauntlet target: deletion-time compaction in the open-addressed
`FALLBACK_ALLOC_*` table. The candidate changed `fallback_remove_sized` so a
removed slot became `EMPTY` when the next slot was empty, then coalesced adjacent
backward tombstones. The intended lever was to reduce probe/tombstone drag under
strict `calloc/free` churn without changing lookup semantics.

Command:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
RCH_VERBOSE=1 \
RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench calloc_glibc_bench -- --measurement-time 2 --warm-up-time 1 --noplot
```

Final candidate worker: `vmi1293453`. A same-worker historical baseline was
available in `tests/artifacts/perf/bd-deployed-malloc-membrane-50x-vmuu73.md`
from 2026-06-19, using the same target dir and bench shape.

Final head-to-head p50 ratios versus same-run glibc:

| size | candidate fl p50 | glibc p50 | fl/glibc | verdict |
|---|---:|---:|---:|---|
| 16 B | 126.620 ns | 11.529 ns | 10.98x | LOSS |
| 256 B | 747.608 ns | 37.921 ns | 19.72x | LOSS |
| 4096 B | 823.597 ns | 153.098 ns | 5.38x | LOSS |
| 65536 B | 1890.445 ns | 1094.101 ns | 1.73x | LOSS |
| 262144 B | 5016.522 ns | 4126.736 ns | 1.22x | LOSS |
| 1048576 B | 21035.057 ns | 19578.059 ns | 1.07x | LOSS |
| 4194304 B | 108814.652 ns | 118209.750 ns | 0.92x | WIN p50 only |

Same-worker historical absolute comparison against the 2026-06-19
`vmi1293453` artifact:

| size | baseline fl p50 | candidate fl p50 | candidate / baseline | decision |
|---|---:|---:|---:|---|
| 16 B | 123.295 ns | 126.620 ns | 1.027x | regression |
| 256 B | 780.699 ns | 747.608 ns | 0.958x | small win |
| 4096 B | 890.361 ns | 823.597 ns | 0.925x | win |
| 65536 B | 2062.725 ns | 1890.445 ns | 0.916x | win |
| 262144 B | 5567.124 ns | 5016.522 ns | 0.901x | p50 win, mean regression |
| 1048576 B | 19433.662 ns | 21035.057 ns | 1.082x | regression |
| 4194304 B | 86130.730 ns | 108814.652 ns | 1.263x | regression |

The candidate was **reverted**. It does not dominate glibc on the target
small/medium sizes, and it introduces absolute regressions at 16 B, 1 MiB, and
4 MiB relative to the same-worker artifact. The 262 KiB row is especially
untrustworthy: p50 improved, but mean degraded from 6490.414 ns to 11097.125 ns
because the candidate run had a large p99 tail.

Retry predicate: do not retry deletion-time tombstone clearing or local
tombstone coalescing as the allocator fix. The next allocator attempt needs a
materially different shape, preferably a slim strict `calloc/free` fast path or
a same-run paired profile that explains the diffuse allocator overhead before
changing metadata policy.

## 2026-06-19 `bd-djtvqq` getc_unlocked "1.8× slower" is a Rust-bench LTO-inlining ARTIFACT, not a real gap (BlackThrush)

bd-djtvqq claimed `getc_unlocked` ~1.8× slower than `fgetc` (9.56 ms vs 5.22 ms).
Reproduced on `ovh-a` `stdio_glibc_baseline_bench` (4 KiB fmemopen sweep), HEAD:
`fgetc`/fl **5.39 ms**, `fgetc_unlocked`/fl **9.33 ms**, and crucially
`fgetc_unlocked`/**glibc 9.33 ms** (a tie), `fgetc`/glibc 9.37 ms.

`getc_unlocked → getc → fgetc` and `fgetc_unlocked → fgetc` are all pure
trampolines. Hypothesis: the extra `#[no_mangle]` symbol hops cost a PLT thunk
per byte. **Tested + DISPROVEN:** extracted the shared body into a private
`#[inline] fgetc_impl` and routed every alias through a *direct* (non-PLT) call —
conformance GREEN (stdio_unlocked_io/query, fmemopen, fread all pass) but the
bench was **unchanged** (`fgetc_unlocked`/fl still 9.38 ms). So the call-hop/PLT
cost is negligible. Reverted (neutral, pure churn).

**Real finding:** since both fl funcs are now identical code yet measure 5.48 vs
9.38 ms, the difference is **thin-LTO inlining luck** — the bench's `fl::fgetc`
call site gets cross-crate-inlined+optimized into the loop (5.4 ms), while
`fl::fgetc_unlocked` is left as a symbol call (9.4 ms). The glibc arms (extern
symbol, never inlinable) are both ~9.3 ms. **Implication:** for realistic,
non-inlinable C callers fl `getc`/`fgetc` is at **parity with glibc (~9.3 ms)**,
NOT 1.7× faster — the `fgetc` "win" (bd-2jgvp9) and the `getc_unlocked` "loss"
(bd-djtvqq) are the SAME artifact with opposite sign. Corroborates this file's
standing caveat that Rust-to-Rust benches inline fl but call glibc `extern`,
systematically flattering fl. bd-djtvqq is not a real gap; downgraded.

## 2026-06-19 `bd-4crkqx` aliases scanner measured reject

Focused gauntlet target: the code-first single-pass `/etc/aliases` member
scanner in `crates/frankenlibc-core/src/aliases/mod.rs`.

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cc \
FRANKENLIBC_RESOLV_BENCH_MODE=strict \
RCH_VERBOSE=1 \
rch exec -- cargo bench -p frankenlibc-bench --bench resolv_parsers_bench --profile release
```

- Worker: `hz2` (`root@178.104.77.29`) for both baseline and candidate.
- Baseline worktree: `/data/projects/.scratch/frankenlibc-cc-bd4crkqx-baseline-20260619T174620Z`
  at `f819823d8^` (`7cdf69121`).
- Candidate worktree: `/data/projects/.scratch/frankenlibc-cc-bd4crkqx-candidate-20260619T174620Z`
  at `f819823d8`.
- RCH did not forward the requested mode label; the bench printed `mode=raw`
  for both runs, so this is like-for-like old-vs-new evidence but not a
  strict-mode-labeled row.

Focused row: `parse_aliases_line_typical`.

| Metric | Baseline split/filter/collect | Candidate manual scanner | Candidate / baseline |
|---|---:|---:|---:|
| p50 ns/op | 91.103 | 106.877 | 1.173x slower |
| mean ns/op | 91.762 | 116.684 | 1.272x slower |
| p95 ns/op | 95.303 | 171.807 | 1.803x slower |
| p99 ns/op | 96.391 | 192.406 | 1.996x slower |
| throughput ops/s | 10,897,706.887 | 8,570,123.415 | 0.786x |

Action: **reverted** the manual comma scanner and restored the prior
split/filter/collect parser. The added whitespace-only-member unit guard stays
because it is valid for the restored parser.

Post-revert validation:

- `rustfmt --check --edition 2024 crates/frankenlibc-core/src/aliases/mod.rs`:
  passed.
- `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cc cargo test -p frankenlibc-core aliases --lib -- --nocapture`:
  30 passed, 0 failed, 3149 filtered.
- `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cc cargo check -p frankenlibc-core`:
  passed with existing unrelated iconv warnings.

Retry-condition predicate: do not retry this manual scanner/reserve-shape family
for short `/etc/aliases` rows. Return only with a materially different
SIMD/memchr-backed multi-delimiter primitive shared across parser families, or
with a profile proving long aliases rows dominate enough to amortize setup and
branch costs.

## 2026-06-19 `bd-xxrfvu` byte network-number parser measured keep

Focused gauntlet target: the code-first byte-level `/etc/networks` number parser
in `crates/frankenlibc-core/src/resolv/mod.rs`.

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
RCH_VERBOSE=1 \
FRANKENLIBC_RESOLV_BENCH_MODE=strict \
rch exec -- cargo bench -p frankenlibc-bench --bench resolv_parsers_bench --profile release
```

- Worker: `vmi1153651` (`root@38.242.134.66`) for both baseline and candidate.
- Baseline worktree: `/data/projects/.scratch/frankenlibc-cod-a-bdxxrfvu-baseline-20260619T180525Z`
  at `db8919ba3^` (`e79873169`).
- Candidate worktree: `/data/projects/.scratch/frankenlibc-cod-a-bdxxrfvu-candidate-20260619T180525Z`
  at `db8919ba3`.
- This is old-vs-new parser evidence. No host-glibc comparator was run for this
  parser microbench.

Focused row: `parse_networks_line_typical`.

| Metric | Baseline UTF-8 + str split | Candidate byte parser | Candidate / baseline |
|---|---:|---:|---:|
| p50 ns/op | 243.090 | 195.091 | 0.803x |
| mean ns/op | 446.336 | 223.541 | 0.501x |
| p95 ns/op | 1603.047 | 230.951 | 0.144x |
| p99 ns/op | 3399.881 | 761.473 | 0.224x |
| throughput ops/s | 2,240,464.663 | 4,473,445.794 | 1.997x |

Action: **kept** the byte parser. Same-worker proof clears the campaign gate;
the row is a p50 win and a mean/tail win. Retry condition is now closed for
this bead unless a later deployed ABI resolver bench exposes a distinct
host-glibc gap.

Post-keep validation:

- `rustfmt --check --edition 2024 crates/frankenlibc-core/src/resolv/mod.rs`:
  passed.
- `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo test -p frankenlibc-core netnum --lib -- --nocapture`:
  12 passed, 0 failed, 3167 filtered.
- `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo test -p frankenlibc-core network_ --lib -- --nocapture`:
  15 passed, 0 failed, 3164 filtered.
- `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a cargo check -p frankenlibc-core`:
  passed with existing unrelated iconv warnings and the known missing SMT
  solver notice.

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

## 2026-06-19 `bd-2g7oyh.492` gid hot-result cache partial keep

Focused gauntlet target: the follow-up `getgrgid(0)` neutral gap from
`bd-2g7oyh.481`, without retrying the group-line parser. The kept lever caches
the most recent successful gid lookup for the current file generation and uses a
gid-only C `stat` fingerprint probe so the name lookup guard stays on the prior
metadata path.

Final candidate command:

```bash
RCH_WORKER=hz1 RCH_PREFERRED_WORKER=hz1 RCH_WORKERS=hz1 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
rch exec -- env AGENT_NAME=BlackThrush FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b-candidate-hz1 \
  CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b-candidate-hz1/criterion-bd-2g7oyh-492-candidate-gidstat-hz1-20260619T0540 \
  cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench glibc_baseline_bench -- glibc_baseline_grp_lookup \
  --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

- Worker actually selected by `rch`: `hz2`.
- `getgrnam("root")` guard: FrankenLibC p50 `9.791 us`, host glibc p50
  `24.739 us`, ratio `0.396x`; mean ratio `0.391x`; **WIN**.
- `getgrgid(0)`: FrankenLibC p50 `14.687 us`, host glibc p50 `15.179 us`,
  ratio `0.968x`; mean ratio `0.939x`; p95 ratio `0.931x`; p99 ratio `0.890x`;
  **p50 NEUTRAL, mean/tail WIN**.
- Same-worker prior corrected-source p50 was `24.631 us` for FrankenLibC on
  `hz2`, so the implementation removes about `40.4%` of FrankenLibC's own
  deployed gid lookup latency, but it does not yet clear the ledger's p50 win
  gate against glibc.

Negative evidence:

- Hot-result cache alone was insufficient on a controlled `hz1` candidate:
  FrankenLibC `28.450 us` vs glibc `18.726 us`, ratio `1.519x`, with worse p95.
- Applying the direct C stat probe to all group refreshes made `getgrgid` faster
  but regressed the `getgrnam` guard; the kept version restricts that probe to
  the gid lookup path.
- This is a partial keep, not a domination claim. The next p50 attempt should
  target the remaining per-call fingerprint/stat cost or a different NSS cache
  primitive.

Validation:

- `rustfmt --edition 2024 --check crates/frankenlibc-abi/src/grp_abi.rs crates/frankenlibc-abi/tests/grp_abi_test.rs`: passed.
- `cargo test -p frankenlibc-abi --test grp_abi_test getgrgid_hot_lookup_reuses_tls_result_and_invalidates_on_reload -- --nocapture`: passed.
- Earlier focused guards in the same turn also passed:
  `cargo check -p frankenlibc-abi`;
  `cargo test -p frankenlibc-abi --test grp_abi_test getgr -- --nocapture`;
  `cargo test -p frankenlibc-abi --test conformance_diff_getbyid_r -- --nocapture`;
  `cargo test -p frankenlibc-abi --test conformance_diff_getgrent -- --nocapture`.
- Workspace `cargo fmt --check` and clippy are still blocked by broad
  pre-existing unrelated drift/warnings outside this bead; they are not counted
  as this change's focused validation.

Retry-condition predicate: do not retry group-line parser reshaping or a
hot-result-only gid cache. Return only with a materially cheaper fingerprint
probe, a correctness-preserving cache invalidation primitive, or a new measured
NSS lookup structure that clears the p50 win gate.

## 2026-06-19 `bd-2g7oyh.493` default hot-hit stat bypass measured reject

Focused gauntlet target: the residual `getgrgid(0)` p50 gap after
`bd-2g7oyh.492`, without retrying the group-line parser or hot-result-only
cache. The rejected lever tried an immutable-default-source fast path: after
checking the `FRANKENLIBC_GROUP_PATH` override, repeated default `/etc/group`
gid hits already materialized in TLS returned before the per-call file
fingerprint/stat probe. Candidate B additionally replaced the common unset-path
Rust environment lookup with a libc `getenv` probe.

Baseline command from clean `e2d4018c72ae`:

```bash
RCH_WORKER=hz2 RCH_PREFERRED_WORKER=hz2 RCH_WORKERS=hz2 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
rch exec -- env AGENT_NAME=BlackThrush FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b-493-baseline \
  CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b-493-baseline/criterion-bd-2g7oyh-493-baseline-hz2-20260619T0602 \
  cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench glibc_baseline_bench -- glibc_baseline_grp_lookup \
  --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

- Worker: `hz2`.
- `getgrnam("root")`: FrankenLibC p50 `9.522 us`, host glibc p50
  `23.909 us`, ratio `0.398x`; **WIN**.
- `getgrgid(0)`: FrankenLibC p50 `15.068 us`, host glibc p50 `14.968 us`,
  ratio `1.007x`; **NEUTRAL**.

Candidate A command:

```bash
RCH_WORKER=hz2 RCH_PREFERRED_WORKER=hz2 RCH_WORKERS=hz2 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
rch exec -- env AGENT_NAME=BlackThrush FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b/criterion-bd-2g7oyh-493-default-hot-skipstat-hz2-20260619T0610 \
  cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench glibc_baseline_bench -- glibc_baseline_grp_lookup \
  --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

- Worker: `hz2`.
- `getgrnam("root")` guard: FrankenLibC p50 `9.798 us`, host glibc p50
  `25.077 us`, ratio `0.391x`; **WIN**.
- `getgrgid(0)`: FrankenLibC p50 `10.056 us`, host glibc p50 `9.029 us`,
  ratio `1.114x`; mean ratio `1.115x`; p95 ratio `1.111x`; p99 ratio `1.115x`;
  **LOSS**.
- Candidate A improved FrankenLibC absolute p50 versus the clean `hz2`
  baseline, but glibc was faster in the same run and the target lost the
  ledger win gate. **Rejected/not landed.**

Candidate B command:

```bash
RCH_WORKER=hz2 RCH_PREFERRED_WORKER=hz2 RCH_WORKERS=hz2 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
rch exec -- env AGENT_NAME=BlackThrush FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b/criterion-bd-2g7oyh-493-getenv-hot-skipstat-hz2-20260619T0618 \
  cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench glibc_baseline_bench -- glibc_baseline_grp_lookup \
  --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

- Worker actually selected by `rch`: `hz1`, despite the `hz2` preference.
  Absolute time is not compared to the `hz2` baseline; only same-run ratios are
  used.
- `getgrnam("root")` guard: FrankenLibC p50 `16.181 us`, host glibc p50
  `40.272 us`, ratio `0.402x`; **WIN**.
- `getgrgid(0)`: FrankenLibC p50 `16.152 us`, host glibc p50 `10.022 us`,
  ratio `1.612x`; mean ratio `1.613x`; p95 ratio `1.422x`; p99 ratio `1.379x`;
  **LOSS**.
- Candidate B is also **rejected/not landed**. The libc `getenv` probe did not
  make the default-only stat bypass a keeper.

Validation:

- `rustfmt --edition 2024 --check crates/frankenlibc-abi/src/grp_abi.rs crates/frankenlibc-abi/tests/grp_abi_test.rs`:
  passed for both candidates in the scratch worktree.
- `cargo test -p frankenlibc-abi --test grp_abi_test getgrgid_hot_lookup_reuses_tls_result_and_invalidates_on_reload -- --nocapture`:
  passed for both candidates; custom `FRANKENLIBC_GROUP_PATH` file-rewrite
  invalidation stayed exact.
- The source candidates were kept out of `main`, so no post-reject code revert
  was required in the main checkout.

Retry-condition predicate: do not retry default-source-only stat/env bypasses
for `getgrgid(0)`. The next p50 attempt should build a materially different
NSS structure, such as a per-generation gid index over the parsed group snapshot
or a shared immutable metadata epoch that removes lookup work without relying on
default-path special casing.

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

## 2026-06-20 `bd-2g7oyh.495` passwd uid hot-result cache partial keep

Focused gauntlet target: the residual deployed ABI `getpwuid(0)` loss left by
the rejected passwd parser attempt above.

Lever:

- Add a generation-scoped hot cache for the most recent successful uid lookup in
  `pwd_abi` TLS storage.
- Reuse the already-materialized `libc::passwd` when the same uid is requested
  for the same passwd-file generation.
- Use the faster C `stat` fingerprint probe only on uid lookup paths, mirroring
  the group gid-cache shape from `bd-2g7oyh.492`.
- Do not retry the parser scanner/byte-decimal shape.

Commands:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR,AGENT_NAME \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench baseline_capture_bench nss_passwd_lookup \
  -- --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2
```

Same-worker comparison used a detached baseline worktree at `c1d89cd58`
(`perf(math): fused f64 pow log+exp kernel`) and the candidate scratch worktree.
Both completed on `hz1`. The first pre-edit run on `hz2` is retained only as
routing evidence.

| Run | Workload | FrankenLibC p50 | glibc p50 | fl/glibc | FrankenLibC Criterion estimate | glibc Criterion estimate | Verdict |
|---|---|---:|---:|---:|---:|---:|---|
| `hz1` baseline `c1d89cd58` | `getpwuid_0` | 23.970 us | 9.042 us | 2.651x | 22.650 us | 9.097 us | LOSS |
| `hz1` candidate | `getpwuid_0` | 17.881 us | 13.144 us | 1.361x | 19.038 us | 13.302 us | LOSS vs glibc, WIN vs old fl |
| `ovh-a` candidate corroboration | `getpwuid_0` | 11.426 us | 10.099 us | 1.131x | 11.578 us | 10.016 us | p50 LOSS, mean WIN |
| `ovh-a` candidate guard | `getpwnam_root` | 9.386 us | 10.109 us | 0.929x | 9.135 us | 10.106 us | WIN guard |

Same-worker target improvement on `hz1`:

- FrankenLibC p50 `23.970 -> 17.881 us`, ratio `0.746x` (`-25.4%`).
- FrankenLibC Criterion estimate `22.650 -> 19.038 us`, ratio `0.840x`
  (`-16.0%`).
- FrankenLibC p95 `34.776 -> 27.371 us`, ratio `0.787x`.

Verdict: **partial keep**, not p50 domination. The target path is materially
faster and the `ovh-a` run corroborates that the candidate can approach glibc,
but `getpwuid(0)` remains a p50 loss against host glibc under the formal ledger
rule.

Validation:

- `rustfmt --edition 2024 --check crates/frankenlibc-abi/src/pwd_abi.rs crates/frankenlibc-abi/tests/pwd_abi_test.rs`: passed.
- `cargo check -p frankenlibc-abi`: passed on rch (`hz1`) before rebase and
  on the post-rebase tree via rch `ovh-a`; both runs had only unrelated
  pre-existing warnings.
- `cargo test -p frankenlibc-abi --test pwd_abi_test getpwuid_refreshes_cached_uid_after_backend_change`:
  passed on rch (`hz1`) before rebase and on the post-rebase tree via rch
  `vmi1152480`, 1 passed.
- `cargo build -p frankenlibc-abi --release`: passed on the post-rebase tree via
  rch `vmi1152480`, with only unrelated pre-existing warnings.
- `git diff --check HEAD~1..HEAD` and touched-file `rustfmt --check`: passed
  after rebase.

Retry-condition predicate: do not retry passwd parser reshaping or a hot-result
cache alone. The next attempt should remove lookup work rather than just reuse
the last result, for example a per-generation uid index over a parsed snapshot,
or a lower-cost immutable file-epoch/invalidation primitive shared with group.

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

## 2026-06-19 `bd-fused-f64-pow-exp-log-kernels-iw3rwz` f64 exp2 keep

The f64 `exp2` subtask was converted from libm delegation to an ARM/glibc
`__ieee754_exp2`-style table kernel and measured head-to-head on `vmi1227854`.

| Workload | FrankenLibC | Comparator | Ratio | Verdict | Action |
|---|---:|---:|---:|---|---|
| dedicated `exp2_f64`, fused core vs old libm fallback | 2.4008 ns p50 / 2.5758 ns mean | 3.0104 ns p50 / 3.3109 ns mean | 0.798x / 0.778x | WIN | Keep fused f64 exp2 kernel. |
| dedicated `exp2_f64`, fused core vs host glibc | 2.4008 ns p50 / 2.5758 ns mean | 4.8920 ns p50 / 7.7200 ns mean | 0.491x / 0.334x | WIN | Keep. |
| `glibc_baseline_math/exp2`, core vs host glibc | 163.950 ns p50 / 162.282 ns mean | 621.670 ns p50 / 651.402 ns mean | 0.264x / 0.249x | WIN | Keep. |
| `glibc_baseline_math_abi/exp2_abi`, deployed ABI vs host glibc | 610.605 ns p50 / 656.530 ns mean | 662.209 ns p50 / 657.528 ns mean | 0.922x / 0.998x | WIN p50 / NEUTRAL mean | Keep; membrane absorbs most core gain on deployed path. |

Win/loss/neutral score: 4 win dimensions, 0 losses, 1 neutral mean dimension.

Conformance stayed green for the focused path:
`cargo test -p frankenlibc-abi --test conformance_diff_exp2_f64_general -- --nocapture`
passed 1 test over 221,546 interior inputs, worst 1 ULP vs host glibc, with
boundary/special inputs exact.
After the final clippy cleanup of the range guard, a dedicated final-source
sanity run on `ovh-a` confirmed the same shape: fused core 2.1742 ns p50 /
2.3905 ns mean, old libm 2.6395 / 2.7566, host glibc 4.4255 / 6.7257.

Retry-condition predicate: do not reroute f64 pow through the standalone
`math::exp2` kernel alone; the current `pow_medium_log2_exp2_fast_path` remains
on its measured libm composition. The remaining f64 pow opportunity is a true
single-routine fused log+exp port with its own conformance gate.

## 2026-06-19 `bd-deployed-malloc-membrane-50x-vmuu73` deployed calloc rejects

Focused gauntlet target: deployed ABI `calloc` + `free` versus isolated host
glibc in `calloc_glibc_bench`.

Method:

- Worker: `vmi1293453`.
- Target dir: `/data/projects/.rch-targets/frankenlibc-cod-a`.
- Command:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
RCH_VERBOSE=1 \
RCH_WORKER=vmi1293453 \
RCH_WORKERS=vmi1293453 \
RCH_PREFERRED_WORKER=vmi1293453 \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench calloc_glibc_bench -- --measurement-time 2 --warm-up-time 1 --noplot
```

Current-head baseline still shows a real deployed allocator gap: p50+mean score
2 wins, 0 neutral, 12 losses versus host glibc. The largest p50 losses are 256B
`22.16x`, 16B `10.86x`, and 4096B `8.29x`.

Rejected attempts:

| Attempt | Key evidence | Verdict | Action |
|---|---|---|---|
| Lock-free fallback table with per-slot CAS reservation | 16B FL regressed from 123.295 ns p50 / 146.359 ns mean to 153.918 ns / 195.183 ns; 256B FL regressed from 780.699 ns / 810.707 ns to 854.457 ns / 943.974 ns. | LOSS | Reverted. |
| Strict-mode `free` skips `check_ownership` before host free | Candidate p50+mean score vs glibc: 1 win, 1 neutral, 12 losses. Criterion reported regressions for `fl/1048576`; 4 MiB regressed to 101202.424 ns p50 / 147881.717 ns mean versus current-head 86130.730 ns / 110318.416 ns. | LOSS | Reverted. |

Focused checks passed during the experiment:
`rustfmt --edition 2024 --check crates/frankenlibc-abi/src/malloc_abi.rs`,
`cargo test -p frankenlibc-abi --test malloc_abi_test -- --nocapture`,
`cargo check -p frankenlibc-bench --features abi-bench --bench calloc_glibc_bench`,
and `cargo check -p frankenlibc-abi --lib`.
Post-revert final-tree confirmation repeated the malloc ABI test and
`calloc_glibc_bench` check successfully.

Retry-condition predicate: do not retry a global fallback-table CAS rewrite or
strict free-path ownership elision as standalone allocator levers. Next work
should isolate `calloc` zero-fill versus `free` metadata cost and then benchmark
a deeper metadata/allocator deployment change.

## 2026-06-19 `bd-gzslkk` fused f64 `pow` log+exp kernel — bit-exact + parity

Target: the f64 `pow` general/medium path, which previously routed through an
unfused 2-call `exp2(y*log2(x))` medium composition (≈1 ULP) or the slow
`libm::pow` fdlibm fallback (out of medium range). Landed a verbatim port of
glibc 2.42 / ARM optimized-routines `e_pow.c` (FMA branch) as
`frankenlibc_core::math::exp::pow_fused`: the `__pow_log_data` double-double log
table + base-e `__exp_data` exp kernel (the exp `tab` is shared with — and was
verified bit-identical to — the existing `EXP2D_TAB`). Fidelity rule applied
throughout: glibc `__builtin_fma` → Rust `mul_add` (one rounding), glibc plain
`a*b+c` → `a*b+c` (two roundings; Rust does not auto-contract).

Correctness (the headline result): `pow_fused` is **bit-exact vs the host glibc
`pow`** — 0 ULP over 400,000 random bit-pattern pairs plus a curated IEEE edge
grid (zeros/±inf/nan/subnormals/negatives/integer-odd-even/over-underflow), via
`pow_fused_bit_exact_vs_glibc`. The saturation helpers reproduce glibc's value
**and** FP-exception flags (FE_OVERFLOW/UNDERFLOW/DIVBYZERO via the real
`0x1p769*0x1p769` / `0x1p-767*0x1p-767` / `1/0` ops, plus the `specialcase`
subnormal underflow barrier), so `conformance_diff_fp_exceptions` (incl. the
`pow(0.1,400)` FE_UNDERFLOW case), `conformance_math_errno` (20), and
`conformance_diff_{pow_special,math,math_exact,math_special}` all stay green.

Perf — measured fl-vs-glibc, custom in-tree bench pinned to `ovh-a`, 3 runs,
back-to-back same-machine arms (1000-element irrational-exponent sweep):

| arm | exponent | fl ns/call | glibc ns/call | ratio |
|---|---|---|---|---|
| `pow_fused` direct | 2.1 / -2.3 / 0.7 | ~14.2 | ~14.1 | **0.99–1.02 (parity)** |
| half-integer fast path | 1.5 | ~7.8 | ~14.2 | **0.55 (win, retained)** |
| full `pow()` (gauntlet) | 2.1 / -2.3 / 0.7 | ~19.4 | ~14.1 | 1.36 |

The fused kernel is at glibc parity (same algorithm → that is the ceiling) and
is strictly faster than the prior fl medium path (one fused kernel vs two
inlined log2+exp2 calls) and the `libm::pow` fallback. Integer (powi squaring)
and half-integer (sqrt) fast paths are retained and still win. The
bench-overfit `pow_profile_exp_1_337` path is now strictly dominated by the
glibc-exact `pow_fused` and was removed from the live path.

Negative evidence: the full `pow()` shows 1.36x in the micro-bench because its
integer/half-integer gauntlet inlines into the bench's tight accumulation loop;
`#[inline(never)]` on `pow_fused` did **not** move it (so it is the inlined
gauntlet branches in the hot loop, not register-spill bloat). This is a bench
artifact for the in-tree symbol — the deployed `extern "C" pow` dispatches
through the `binary_entry` membrane (~180 ns, `bd-n40in2`) which dwarfs the
~5 ns gauntlet, so the gauntlet is not worth trimming at the cost of the
integer-exponent wins. Win/loss/neutral: 1 correctness win (bit-exact, was
1–4 ULP), 1 kernel-perf parity (up from a slower 2-call/libm path), 0 perf
regressions; integer/half-integer wins retained.

Retry-condition predicate: do not re-attempt to beat glibc `pow` on the **same**
algorithm — `pow_fused` is a verbatim glibc port, so it is at parity by
construction; a further win needs either a lower-latency pow algorithm or
removing the membrane (`bd-n40in2`), not kernel micro-tuning. Do not re-pin the
pow golden corpora to pre-fused bits.

## 2026-06-20 `bd-n40in2` math ABI membrane fast-path — tax removed, parity restored

Target: the deployed math ABI membrane. `bench_math_abi` (3-way core/abi/glibc,
same-run) showed the `unary_entry`/`binary_entry` `decide()`+`observe()`
machinery adding **+8–12 ns/call**, dragging deployed math from its 2–4× core
win down to a ~1.08× glibc *loss*. The dominant cost is `record_last_explainability`
building a full `DecisionExplainability` struct on every hardened-mode call (its
own comment notes "~300x overhead for python3").

Key observation that makes the fast-path safe: in deployed (non-`cfg(test)`)
builds `decide()` hard-returns `Allow`/`Full` for `ApiFamily::MathFenv` via the
high-frequency-family fast-path *before* any kernel consult, so the membrane can
never `Deny` a math call, and since `Repair`/heal only originates from a kernel
decision math never reaches, it can never heal one either. The deployed math
result is therefore bit-identical to the raw kernel result. Added
`runtime_policy::math_membrane_fastpath()` (`= cfg!(not(test))`, coupled to that
same gate) and a fast-path in all four entries (`unary_entry`, `binary_entry`,
`unary_entry_f32`, `binary_entry_f32`): compute `f(x)` and return it directly for
the common finite case, skipping `decide()` entirely. Finite→non-finite "adverse"
results fall through to the full path so observation (and any future deny/heal)
stays reachable.

Verification — the fast-path is exercised by the *integration* gates (the lib
compiles without `cfg(test)` as a test dependency): `math_abi_test` (118),
`conformance_diff_math` (20), `conformance_diff_pow_special` (2),
`conformance_math_errno`, `conformance_diff_fp_exceptions` all green — values, FP
flags and errno are unchanged on the deployed path. Unit (`cfg(test)`) membrane
tests keep the full path. (The 2 `ffi_pcc_*` lib-unit failures under the
`runtime_policy` filter are PRE-EXISTING test-ordering pollution — reproduced on
the stashed baseline, and worse there: 2 failures vs 1 with this change; unrelated
to math.)

Perf — `bench_math_abi` pinned to `ovh-a`, per-call (÷64), `runtime_mode=strict`.
The glibc-variance-free measure is the **abi−core delta** (membrane tax, same
run):

| symbol | tax baseline | tax post | abi/glibc (quiet run) |
|---|---|---|---|
| exp | +12.0 ns | +3.3 ns | 1.00 |
| sin | +8.0 ns | +0.1 ns | 1.00 |
| cos | +8.5 ns | +0.4 ns | 1.00 |
| log | ~+9 ns | +2.6 ns | 1.00 / 0.74 |
| exp2 | +11.2 ns | +2.5 ns | 1.00 |
| log2 | +9.3 ns | +2.6 ns | 0.99 |

The membrane `decide()`/`record_explainability` tax is eliminated; the residual
+2.5–4 ns abi-over-core is the extern-C wrapper frame + the `fn`-pointer indirect
call to the core kernel inside the generic entry (glibc pays its own extern-C
frame too, so the head-to-head is parity). Deployed math moves from a consistent
~1.08× loss to **parity-to-win vs glibc** across the whole MathFenv family
(~100+ exported functions), incl. the new `pow_fused`. Win/loss/neutral: broad
parity-restoration win (1 documented loss removed), 0 regressions, conformance
green.

Negative evidence / ceiling: this does NOT reach the bead's hoped ~2× — that
prediction assumed glibc at 13–19 ns, but on quiet workers glibc math is ~5–8 ns
and the core kernel is ~3–5 ns, so once the membrane is gone the extern-C frame
floors the head-to-head at parity. The residual ~3 ns is the `fn`-pointer
indirection into the generic entry; removing it needs monomorphizing the entry
per-symbol (macro/`const` fn), a ~100-wrapper refactor for ~3 ns — deferred as
low-value. Retry-condition predicate: do not chase the residual abi-over-core ns
via decide/observe tuning (already skipped); only the entry-monomorphization
refactor remains, and only if a profile shows math entry dominating.

## 2026-06-20 ctype ABI membrane fast-path — ~3x LOSS → 1.3-4x WIN vs glibc

Same lever as the math membrane (`bd-n40in2`), applied to the ctype family.
`classify_with_mask`/`convert_with_table` (the cores of `isalpha`/`isdigit`/.../
`tolower`/`toupper` and all their `_l` and `__`-prefixed variants — ~50 exported
symbols) called `runtime_policy::decide()`+`observe()` on every call: a ~4 ns
membrane tax on a 1 ns table lookup. Ctype is in the always-Allow
high-frequency-family set, takes an `int` and returns an `int` (no pointer/heap
effect), and has no heal/adverse path (its `observe()` is already a Ctype-family
no-op), so the membrane can never change a classification. Added
`runtime_policy::ctype_membrane_fastpath()` (`= cfg!(not(test))`) and guarded the
`decide()`/`observe()` block in both helpers; the table lookup runs directly.
Unit-test builds keep the full path (deny/observe reachable + tested).

Measured (zz_scratch_ctype_bench, pinned ovh-a; glibc resolved via
`dlmopen(LM_ID_NEWLM,"libc.so.6")` so fl's `no_mangle` ctype symbols don't shadow
it — without dlmopen *both* arms silently resolve to fl):

| symbol | fl before | fl after | glibc | after/glibc |
|---|---|---|---|---|
| isalpha | 5.24 ns | 1.34 ns | 1.73 ns | **0.77x** |
| isdigit | (5.2 ns) | 0.44 ns | 1.74 ns | **0.25x** |
| isspace | 5.46 ns | 1.31 ns | 1.74 ns | **0.75x** |
| tolower | 5.27 ns | 1.31 ns | 1.74 ns | **0.75x** |

fl ctype went from a ~3x glibc LOSS (5.2 ns, membrane-bound) to a clean 1.3-4x
WIN across the whole family. Conformance green on the deployed fast-path
(integration gates compile the lib non-test): `conformance_diff_ctype` (19, a
real vs-glibc differential) + `ctype_abi_test` (39) — values unchanged.
Win/loss/neutral: broad WIN (a ~3x loss removed across ~50 hot symbols), 0
regressions. METHOD NOTE: any fl-vs-glibc microbench of a `no_mangle`-exported
symbol MUST resolve glibc via `dlmopen(LM_ID_NEWLM)` — a plain `extern`/`libc::`
binding resolves to fl's shadowing symbol and silently measures fl-vs-fl (the
tell: identical numbers in both arms every run).

## 2026-06-20 deployed `snprintf` 20x loss — Stdio kernel-consult is NOT the cause (REVERTED)

Found via a dlmopen microbench (real glibc, un-shadowed): deployed `snprintf("%s")`
is a large, real loss — **fl ~300–1200 ns vs glibc ~15–60 ns, ratio swinging
12–34x run-to-run**. The `glibc_baseline_bench` malloc/string `libc::` arms hide
this (fl's `no_mangle` symbols shadow `libc::`, measuring fl-vs-fl).

Hypothesis tested: `ApiFamily::Stdio` is missing from the high-frequency-family
fast-path set in `decide()`/`observe()`, so every stdio call falls to
`decide_strict_observation` — a `#[cold]` kernel consult (reentry guard + panic
hook + `k.decide()` with locks). That function always overrides to `Allow`
(verified), so the consult is pure telemetry and skipping it is behavior-
preserving (stdio buffer validation/healing runs off `known_remaining`).

| Attempt | Key evidence | Verdict | Action |
|---|---|---|---|
| Add `Stdio` to the strict-mode `decide`+`observe` fast-path family sets | Controlled back-to-back A/B on `ovh-a`, 3 runs each: WITH-fix fl/glibc ratio 19.8 / 22.4 / 23.0 (median **22.4**); WITHOUT-fix 34.4 / 19.7 / 16.7 (median **19.7**). The microbench variance (worker load, the variadic call, TLS) dwarfs the per-call consult cost — the medians OVERLAP and even slightly favor the no-fix arm. No measurable win. | NEUTRAL (unmeasurable) | **Reverted.** |

Conformance was green during the experiment
(`conformance_diff_{printf_fastpaths,asprintf,dprintf,printf_null_string,
printf_pointer}`), and the change is structurally consistent with the 6 sibling
high-frequency families — but with NO measurable benefit and the multi-thread
telemetry implications of dropping stdio observation unverified, it is not
shipped. (An initial single-run measurement read 1198→753 ns / 26x→12x; the
follow-up 6-run A/B showed that was cross-run noise, not the change. Lesson: this
snprintf microbench is too noisy for a single before/after — always A/B
back-to-back, and even then the consult cost is below the noise floor.)

Real bottleneck for the snprintf 20x loss (negative evidence): NOT the membrane
decision. Stubbing `entrypoint_scope` out of `snprintf` did not reduce the time
either (it rose, within noise). The cost is the **variadic va-arg extraction +
format-segment parse + `entrypoint_scope` TLS** (`std::thread_local!` `try_with`,
general-dynamic-TLS `__tls_get_addr`; the bundling `owned-tls-cache` feature is
OFF by default) — i.e. fl's printf *architecture*, not its membrane. Closing it
is a deep printf hot-path refactor with a reliable (criterion, dlmopen) stdio
bench, not a one-line family-set tweak.

Retry-condition predicate: do not re-add `Stdio` to the membrane fast-path sets
as a perf lever without a reliable, low-variance stdio bench that can resolve a
sub-50 ns per-call delta; the gain (if any) is below this microbench's noise.

## 2026-06-20 large-argument sin/cos/tan — 7-10x LOSS → 0.73-0.75x WIN vs glibc

A reliable dlmopen head-to-head survey of 14 f64 math functions (sin/cos/tan/
asin/acos/atan/sinh/cosh/tanh/cbrt/expm1/log1p over small/medium/large/unit
ranges) found fl **dominates or ties glibc everywhere except large-argument
trig**: fl wins small sin/cos (0.65x) and ties medium, but for |x| above
~2^20·π/2 (≈1.6e6) `libm`'s reduction falls to its slow Payne-Hanek path —
**sin/cos ~10x and tan ~7x slower than glibc** (glibc stays flat ~10 ns across
all ranges via its IBM `__branred` reduction).

Fix (`crates/frankenlibc-core/src/math/trig.rs`): for the magnitude band
[1.647e6, 1e15] reduce with an **FMA-based 3-part π/2 Cody-Waite** (159-bit split
TWO_OVER_PI/PIO2H/PIO2M/PIO2L; three `mul_add` steps, no Payne-Hanek table) to
`(n mod 4, r)` with `r ∈ [-π/4, π/4]`, then evaluate the reduced small arg on the
already-fast `libm` kernel (`sin`/`cos`/`tan` of `r`) with the quadrant fix-up.
|x| < 1.647e6 keeps `libm` (already fast); |x| > 1e15 keeps `libm` (the 3-part
split runs out of bits — rare astronomical case keeps full accuracy).

Measured (dlmopen glibc, ovh-a):

| case | fl before | fl after | glibc | after/glibc |
|---|---|---|---|---|
| sin large | ~108 ns | 14.7 ns | 20.0 ns | **0.74x** |
| cos large | ~109 ns | 14.9 ns | 19.7 ns | **0.75x** |
| tan large | ~118 ns | 21.3 ns | 29.1 ns | **0.73x** |

Win/loss/neutral: clean WIN — a 7-10x loss flipped to a ~1.3x win, with
small/medium trig unchanged (still routed to `libm`, still winning). Correctness:
the 4-ULP `diff_sin_cos_tan_within_4_ulps` gate (incl ±1e10) stays green, and a
**300,000-sample sweep across the whole [2.1e6, 1e15] band vs dlmopen glibc shows
worst 2 ULP, 0 fails** (>4 ULP). All math gates green
(`conformance_diff_math` 20, `_exact` 2, `_multi_output` 1, `_special` 9).

Retry-condition predicate: do NOT extend the 3-part reduction above ~1e15 — the
159-bit split leaves too few bits once `n` exceeds ~2^50; that range genuinely
needs a Payne-Hanek table and must stay on `libm`.

## 2026-06-20 f32 sinf/cosf large arg — 2-3x LOSS → parity-to-win vs glibc

A reliable dlmopen survey of ~18 more math functions (f64 lgamma/tgamma/erf/erfc/
exp10/log10/j0/j1/y0/cbrt/atan2/hypot + f32 sinf/cosf/tanf) found the f32 trig
parallel to the f64 trig gap: `libm::sinf`/`cosf` lose **2-3x to glibc for ALL
|x| > ~7** (above musl's 9π/4 small-poly path) — sinf ~1e2 2.2x, ~1e4 3.0x,
~1e6 2.7x, ~1e7 3.2x; glibc is flat ~7 ns. (Other survey results, all
already-good: tgamma 0.32x WIN, atan2 0.74x, hypot 0.70x WIN; erfc 1.58x / exp10
1.64x / bessel 1.18-1.21x are minor + tiny-absolute; `exp10` already fused.)

Fix (`crates/frankenlibc-core/src/math/float32.rs`): for |x| in [7, 1e15] reduce
in f64 with a **2-part π/2 split** (TWO_OVER_PI/PIO2H/PIO2M; two `mul_add` steps
— f64's 106-bit split is far more than an f32 result needs) to `(n mod 4, r)`,
then evaluate the fast small-arg `libm::sinf/cosf` on `r as f32` with quadrant
fix-up. |x| < 7 keeps `libm::sinf` (already wins, 0.6x); |x| > 1e15 / nan / inf
keep `libm`. `tanf` left on `libm` (it already wins large, 0.73x).

Measured (dlmopen glibc, ovh-a, warm): sinf ~1e4 0.99x, ~1e6 0.90x, large 0.83x;
cosf large 0.80x — a 2-3x LOSS flipped to **0.80-0.99x (parity-to-win)**, small
unchanged (still 0.6x win). Correctness: the bit-exact `conformance_diff_trig_
special` gate (sinf/cosf at 100 and 1e15) STAYS GREEN (the reduced-arg result
rounds identically to glibc), plus a **400,000-sample sweep over [8, 1e15] vs
dlmopen glibc shows worst 1 ULP, 0 fails (>2 ULP)**; conformance_diff_math (20),
inv_trig_special (2), fp_exceptions all green.

Win/loss/neutral: clean WIN — 0 regressions; the bit-exact trig gate (which pins
sinf(100)/sinf(1e15)) constrained the approach but the FMA reduction happens to
be correctly-rounded enough to satisfy it. Retry predicate: do not raise
F32_RED_HI above ~1e15 (2-part split runs out for n > ~2^50).

## 2026-06-20 f32 tgammaf — 7x LOSS → 1.49x (5.1x faster) + bit-exact, via the f64 tgamma kernel

An f32-specials dlmopen survey (erff/erfcf/lgammaf/tgammaf/exp10f/j0f/j1f/asinf/
acosf/atanf/sinhf/coshf/tanhf/expm1f/log1pf/cbrtf) found **tgammaf was 7.05x
slower than glibc** (94.92 ns vs 13.46 ns) — striking because f64 `tgamma` is a
3x WIN. Root cause: `tgammaf` delegated to `libm::tgammaf` (the slow fdlibm
port), while the in-tree f64 `tgamma` has a fast custom kernel (`tgamma_reduced`,
~0.3x glibc on f64). Fix (`float32.rs`): `tgammaf(x) = tgamma(x as f64) as f32`
(f32 widens exactly; the f64 kernel's ~4-ULP-f64 result is far more accurate than
an f32 needs, so the cast is correctly-rounded). Pole/FE_INVALID handling kept.

Measured (dlmopen glibc, ovh-a): **94.92 ns → 18.67 ns (5.1x faster)**, ratio
7.05x → **1.49x**. Correctness: a 300,000-sample sweep over the finite-gamma
domain (-33.5, 35.5) vs glibc tgammaf shows **worst 0 ULP, 0 fails** — the routed
result is BIT-EXACT to glibc (better than the old libm). math_abi_test (118),
conformance_math_errno, conformance_diff_fp_exceptions all green.

Win/loss/neutral: a 7x loss cut to a residual 1.49x (the f64 kernel computes at
f64 precision, ~6 ns more than an f32-native kernel would need) + a correctness
improvement to bit-exact. Other f32 specials that LOSE (erff 2.1x, sinhf 1.9x,
exp10f 1.9x, tanhf 1.7x, coshf 1.5x, erfcf 1.5x, j0f/j1f ~1.25x) have NO faster
f64 sibling to route through (their f64 versions are already only ~parity), so
they would each need a dedicated ARM-optimized-routines-class f32 kernel port —
filed as remaining gaps, not attempted here. asinf/acosf/atanf/lgammaf/cbrtf
already win/tie.

## 2026-06-20 f32 erff — 2.14x LOSS → 0.99x (parity), via ARM optimized-routines port

`erff` delegated to `libm::erff` (fdlibm), measured **2.14x slower than glibc**
(~10-15 ns vs ~4.7 ns). erff has no strict gate (only a loose math_abi_test
basic), so it is free to optimize. Ported the ARM optimized-routines `erff`
(`float32.rs`) — the algorithm glibc 2.42 ships: a pure 6-term polynomial on
|x| < 0.875, `exp`(-7-term-poly) on [0.875, 4) (using the in-tree fast `expf`),
±1 beyond, with the rare |x| < 2^-28 tiny case deferred to `libm::erff` for exact
underflow flags. Constants (poly_A[6], poly_B[7], 2/√π−1) converted from the ARM
hex-float source to `f32::from_bits`; `fmaf` → `mul_add`.

Measured (dlmopen glibc, ovh-a): **~10-15 ns → 4.49 ns**, ratio 2.14x → **0.99x
(parity)** — a ~2.2x speedup that erases the loss. Correctness: a **400,000-sample
sweep over [-6, 6] vs glibc erff shows worst 1 ULP, 0 fails** (glibc uses the same
ARM kernel, so the residual ~1 ULP is just the expf path). math_abi_test (118),
conformance_math_errno, conformance_diff_fp_exceptions all green.

Win/loss/neutral: clean WIN (2.14x loss → parity), 0 regressions.

### Rejected same-turn: f32 exp10f libm::exp2 → fused math::exp2 (NEUTRAL)
`exp10f`'s f64 fallback used `libm::exp2` while the comment claimed "the fast
exp2 kernel". Swapped to the in-tree fused `crate::math::exp2`: bit-identical
output (the `exp10f_profile_band_preserves_fallback_bits` unit gate stayed green)
but **no measurable speedup** (survey: fl ~7.4→8.0 ns, within worker noise; the
1.92→1.75x ratio shift was glibc-side variance). Reverted — no measured win.
Retry predicate: f32 exp10f/hyperbolic need a dedicated fast f32 kernel; routing
through f64 helpers is neutral (the f64 exp2/exp are not enough faster than
glibc's f32 versions). coshf specifically is blocked from the fast f32-`expf`
route by the **bit-exact** `conformance_diff_hyperbolic_special` gate (it pins
coshf at 0.5/1.0/20.0); only a correctly-rounded kernel — i.e. the slow f64-exp
route (why sinhf still loses 1.9x) or a real ARM-class f32 erf/hyperbolic kernel —
satisfies it.

## 2026-06-20 f32 erfcf — 1.46x LOSS → 1.02x (parity), via the new fast erff

Follow-on to the erff port. `erfcf` delegated to `libm::erfcf` (~1.46x slower than
glibc). ARM optimized-routines ships NO erfcf (404; nor sinhf/coshf/tanhf/cbrtf —
only sinf/cosf/expf/logf/powf/erff for f32), so no kernel to port. Instead built
erfcf from the now-fast in-tree `erff` over the **well-conditioned** sub-domains
(`float32.rs`):
  - x <= 0:        erfc = 1 + erf(|x|)   (result in [1,2], no cancellation)
  - 0 < x <= 0.8:  erfc = 1 - erf(x)     (erfc >= ~0.26, cancellation <= ~3 ULP)
The small-erfc tail (x > 0.8, where 1-erf loses precision and the result
eventually underflows) stays on `libm::erfcf`, preserving the exact
subnormal/FE_UNDERFLOW flag handling. Threshold 0.8 chosen so the cancellation
amplification (erf/erfc ratio) keeps the routed region within ~3 ULP.

Measured (dlmopen glibc, ovh-a): **~17.9 ns → 8.7 ns**, ratio 1.46x → **1.02x
(parity)**. Correctness: a **400,000-sample sweep over [-4, 10] (incl. the
underflow tail) vs glibc erfcf shows worst 3 ULP, 0 fails** (>4 ULP).
math_abi_test (118), conformance_math_errno, conformance_diff_fp_exceptions green.

Win/loss/neutral: clean WIN (1.46x loss → parity), 0 regressions. Note: ARM's f32
math set is now exhausted for fl's losers — remaining f32-specials losses (sinhf
1.9x, coshf 1.5x, tanhf 1.7x bit-exact-gated; exp10f 1.9x neutral via f64; j0f/j1f
1.25x bessel) all need bespoke correctly-rounded f32 kernels, not a port.

## 2026-06-20 f32 tanhf — 1.73x LOSS → 0.93x WIN, by widening the existing expf fast band

`tanhf` already had an `(e^2x-1)/(e^2x+1)` fast path via the fast f32 `expf`, but
it was capped at |x| <= 2.5 — so the survey's [2.5,5] (and the near-0 cancellation
band) fell to slow `libm::tanhf`, leaving it 1.73x behind glibc. The
`(u-1)/(u+1)` form has no cancellation for |x| >= 0.5 and **self-saturates to ±1
exactly in f32** as `u=expf(2x)` grows (the ∓1 vanishes against the huge u), so
the band can be widened all the way to |x| = 40 (just below where `expf(2x)`
overflows at x≈44.3). Changed `TANHF_FAST_ABS_MAX` 2.5 → 40.0.

Measured (dlmopen glibc, ovh-a): **~11.9 ns → 6.37 ns**, ratio 1.73x → **0.93x
(WIN)**. Correctness: the **bit-exact** `conformance_diff_hyperbolic_special` gate
stays green (its CASES — 0.5, 1.0 already in-band; 20.0 now in-band but saturates
to the same 1.0 as glibc), plus a **400,000-sample sweep over [-45,45] vs glibc
tanhf shows worst 3 ULP, 0 fails** (>4 ULP); math_abi_test (118),
conformance_diff_fp_exceptions green. Residual: the near-0 [-0.5,0.5] band still
uses libm (the (u-1) cancellation there needs an `expm1f`-based form or a poly).

Win/loss/neutral: clean WIN.

Same turn, sinhf widened too (cap 2.5 → 5.0, fl's f64-`exp` fast-path limit):
**1.95x → 1.29x** (gates green: hyperbolic_special, math_abi_test 118). This only
*reduces* the loss — it does not win, because sinhf's bit-exact CASES (0.5/1.0)
are satisfied only by the correctly-rounded **f64**-exp route (an f32-expf
`0.5*(u-1/u)` is ~1-2 ULP, two exp + a subtraction, and would risk the bit-exact
gate), and that f64 route is only ~parity with glibc; the near-0 [-0.5,0.5] band
also stays on libm.

## 2026-06-20 f32 coshf — 1.49x LOSS → 0.68x WIN, f64-exp fast path on the whole [0,5]

`coshf` was pure `libm::coshf` (no fast path at all), 1.49x slower than glibc.
Unlike sinhf, coshf = `(u + 1/u)/2` is a **sum** with NO cancellation anywhere
(result >= 1, even near 0), so the correctly-rounded f64-exp route can cover the
ENTIRE common band [0, 5] (not just |x| >= 0.5). Added it (even function, `ax =
|x|`; |x| > 5 → libm for exact overflow/FE). Because the whole survey range is now
on the fast f64 `exp` kernel — and that kernel beats glibc's own coshf path —
this is a clear win, not just parity (the lesson sinhf's residual taught: sinhf
stayed 1.29x only because its near-0 band can't use this route).

Measured (dlmopen glibc, ovh-a): **~10 ns → 4.99 ns**, ratio 1.49x → **0.68x
(WIN)**. Correctness: a **400,000-sample sweep over [-9, 9] vs glibc coshf shows
worst 1 ULP, 0 fails** (the f64 route is correctly-rounded for f32); the bit-exact
`conformance_diff_hyperbolic_special` gate stays green (CASES 0.5/1.0 in-band,
20.0 on libm), math_abi_test (118), fp_exceptions green.

Win/loss/neutral: clean WIN. The f32 hyperbolic family is now tanhf 0.93x WIN,
coshf 0.68x WIN, sinhf 1.29x (loss-reduced; near-0 cancellation band needs an
expm1f-based form for the rest).

## 2026-06-20 CORRECTION + float32.rs codegen-coupling: sinhf is ALREADY a WIN; near-0 poly REGRESSED coshf

Two findings from trying to finish sinhf's near-0 [-0.5,0.5] band with a Maclaurin
poly (`x + x^3/6 + x^5/120 + ...`, no cancellation, bit-exact at tiny x):

1. **The committed sinhf is already a WIN, not 1.29x.** A controlled back-to-back
   A/B on a *quiet* `ovh-a` showed the committed (b71517500) sinhf at **4.76 ns /
   0.68x** and coshf at **5.03 ns / 0.56x**. The "1.29x" recorded above was a
   single noisy measurement on a loaded worker — the whole f32 hyperbolic family
   is in fact a WIN: sinhf ~0.68x, coshf ~0.56-0.68x, tanhf ~0.88x.

2. **`float32.rs` has tight codegen coupling — adding code regresses neighbours.**
   The sinhf near-0 poly (4 f32 consts + 4 `mul_add`s + a branch) was correct
   (worst 1 ULP / 400k, tiny-x bit-exact, all gates green) BUT, measured on the
   same quiet worker, it pushed sinhf 4.76 → 7.85 ns AND coshf 5.03 → 7.79 ns —
   i.e. it deoptimised an *unrelated committed win* (coshf) by ~55%, almost
   certainly by tripping the module's inlining budget so `crate::math::exp::exp`
   stopped inlining into the f64-exp hot paths. **Reverted.**

Retry/avoidance predicate: do NOT add inline polynomial/table code to
`float32.rs` hot functions without an A/B that re-measures the NEIGHBOURING
functions (sinhf/coshf/tanhf/expf/erff) — the module is at an inlining cliff and a
local "improvement" can silently regress a sibling. If a near-0 poly is ever
needed, put it behind `#[cold] #[inline(never)]` so it cannot perturb the hot
path's codegen. (And the near-0 sinhf band is not worth it: sinhf already wins.)
The f64 `erfc`-from-`erf` complement is separately a documented reject
(special.rs: ">4 ULP in dense replay").

## 2026-06-20 strtod/strtof membrane fast-path — simple-case loss cut ~0.4-0.6x (bd-n40in2 sibling)

A dlmopen strtod survey found fl WINS the hard cases (subnormal 0.53x, 1.79e308
0.65x, 17-digit 0.74x — the SWAR/fast_float parser pays off) but LOSES the simple
common ones: integer "12345" **1.52x**, "1.234e10" **1.73x**, hex "0x1.fp10"
**2.29x**. The core parser is already fast (Lemire SWAR); the gap is the ABI
wrapper's per-call `decide()`+`observe()` Stdlib membrane (a non-inlined call with
several atomics, ~5-10 ns, large next to a ~34 ns simple parse).

Fix (`stdlib_abi.rs` + `runtime_policy.rs`): `Stdlib` is in the high-frequency
fast-path family set, so in deployed (non-test) builds `decide()` always returns
`Allow` (never `Repair` → the repair `bound` is always `None`, scan unbounded
either way) and the parse reads the string regardless of the decision. Added
`stdlib_membrane_fastpath()` (`= cfg!(not(test))`) and skipped decide()+observe()
in `strtod`/`strtof` (strtold delegates to strtod). Unit-test builds keep the full
path (deny/observe exercised).

Measured — controlled back-to-back A/B on `ovh-a` (ratios normalise the worker):
strtod **int 1.52x → 1.15x, sci 1.73x → 1.26x, hex 2.29x → 1.66x** (the fl
absolute for "12345" dropped 50.4 → 39.8 ns — the membrane removed). Still a
residual loss (the rest is the wrapper's two-pass scan: `scan_terminated_numeric_
string` then `strtod_impl` re-scans), but the membrane tax is gone. Conformance
green on the deployed fast-path: `conformance_diff_strtod_edges`,
`strtod_strtof_live_differential_probe` (live vs-glibc value+endptr+errno),
`strtod_strtof_signbit_differential_fuzz`, `conformance_math_errno`.

Win/loss/neutral: loss-reduction WIN across the strtod/strtof float-parse family,
0 regressions. The strtol/strtoul int family has the same pattern (and TWO decides
— nptr + a redundant always-Allow endptr decide) — a follow-up; the residual
strtod two-pass scan is the deeper lever after that.

## 2026-06-20 METHODOLOGY: the cargo-test dlmopen membrane microbench runs with cfg(test)=true — strtol "20-50x loss" is largely a TEST-BUILD ARTIFACT (strtol fast-path REVERTED)

Chasing the strtol follow-up, a dlmopen bench showed deployed `strtol` at ~330 ns
vs glibc ~6-15 ns (22-52x). Applying the same membrane fast-path + a plain-strlen
scan (skipping `scan_c_string`'s `allocation_bound`→`known_remaining`) did NOT fix
it. Bisecting, then changing ONLY `runtime_policy::stdlib_membrane_fastpath()`
from `cfg!(not(test))` to a literal `true`, cut strtol 341→132 ns. That is
impossible unless `cfg!(not(test))` was **false** — i.e. **`cargo test -p
frankenlibc-abi --test <x>` compiles the lib with `cfg(test)=true`** (at least in
this rch/workspace setup), contradicting the assumption recorded in
NEGATIVE/memory that integration gates exercise the deployed fast-path.

Consequences (airtight first, then inference):
  - AIRTIGHT: the `*_membrane_fastpath()` predicates are FALSE in these benches,
    so they measure the SLOW path — full decide()+observe() + `known_remaining`.
  - In `cfg(test)`, `known_remaining`→`validate_ptr`/`test_allocation_bound`
    (a `Mutex`) — hundreds of ns on a `.rodata` pointer. In DEPLOYED strict mode
    `strict_passthrough_active()` routes `known_remaining`→`fallback_remaining`
    (cheap), and the family fast-path makes decide() cheap — so deployed strtol is
    very likely fine, and the 20-50x "loss" is mostly the test build.

Action: **REVERTED** this turn's speculative strtol/strtoul/strtoll/strtoull
membrane fast-path + `scan_numeric_c_string` (an unmeasurable change must not
ship — MEASURED/REVERT discipline). Scratch bench removed.

CAVEAT propagated: last turn's strtod/strtof fast-path commit (57cf54f99) and the
math/ctype membrane wins were measured the same dlmopen-cargo-test way; their
small deltas may be partly noise. They are BENIGN in deployment (skip cheap
membrane work, test path unchanged, conformance green) — not regressions — but a
TRUSTWORTHY deployed-ABI perf number requires the real cdylib + LD_PRELOAD (or a
bench in the `frankenlibc-bench` crate, which builds the lib WITHOUT cfg(test)),
not a `--test` integration bench. That harness is the prerequisite for any
further deployed-membrane perf claim.

## 2026-06-20 strtol/strtoul/strtoll/strtoull membrane fast-path — REAL deployed win (built the valid harness)

Acting on the prerequisite above: wrote `frankenlibc-bench/benches/strtol_glibc_
bench.rs` — a criterion bench (lib built WITHOUT cfg(test) → deployed fast-paths
LIVE, `known_remaining`→`fallback_remaining` cheap), glibc via dlmopen. This is
the VALID deployed measurement the `--test` bench could not give.

It confirmed BOTH points: the cfg(test) bench's 22-52x was inflated, AND there is
a REAL deployed loss — strtol "42" **28 ns vs glibc ~6 ns (~4.5x)**, dec_long
~2.8x, hex ~2.7x; strtod competitive (0.79-1.39x, already fast-pathed).

Re-applied (now measurable) the int-family fast-path: skip the always-Allow
decide()+observe() (strtol pays it twice — nptr + endptr) and route the arg-length
scan through `scan_numeric_c_string` (plain NUL scan, no `allocation_bound`→
`known_remaining` lookup). Controlled back-to-back A/B on `ovh-a` (fl absolute,
the glibc dlmopen baseline is too noisy run-to-run to trust — 4.5-8.5 ns swings):
  - strtol "42":     37.9 → 23.1 ns
  - strtol dec_long: 43.5 → 33.7 ns
  - strtol hex:      45.3 → 29.6 ns
~10-16 ns saved (well above the ~±8 ns worker noise; strtod_int, unchanged this
turn, swung 38-47 ns as the noise gauge). So strtol goes ~5x → ~3x vs glibc — a
~40% loss-reduction on a ubiquitous function. The residual ~3x is the Rust ABI
frame + the two-pass (scan-then-parse) shape vs glibc's single incremental pass —
the deeper lever. Conformance green: conformance_strtol_family,
strtol_family_differential_fuzz (live vs-glibc), conformance_diff_strtod_edges,
strtod_strtof_live_differential_probe.

Win/loss/neutral: loss-reduction WIN (5x→3x) across the strtol int family,
0 regressions. Lesson banked: the `*_glibc_bench` criterion harness is how to
measure ANY deployed-membrane change — never the `--test` path.

## 2026-06-20 atoi/atol/atoll membrane fast-path — deployed ~30→21 ns (~30%) vs glibc

Extended the valid `strtol_glibc_bench` to atoi (super-common). Deployed atoi "42"
benched **~30 ns vs glibc ~10 ns** with only the scan fix (last turn) — its
`decide()`+`observe()` membrane was still live (atoi/atol were not in the prior
int-family fast-path). Applied the same `(profile, bound)` fast-path to
atoi/atol (atoll delegates to atol). atoi has ONE decide (vs strtol's two), so a
smaller saving — and below the cross-run dlmopen-glibc noise, so measured by
3 CONSECUTIVE same-worker runs (the tight signal): atoi "42" WITH fast-path =
**20.15 / 20.96 / 22.12 ns** (median ~21 ns) vs ~30 ns without — a consistent
~9 ns / ~30% drop. Conformance green: conformance_strtol_family,
strtol_family_differential_fuzz (live vs-glibc).

Win/loss/neutral: loss-reduction WIN (atoi ~3x→~2x), 0 regressions. Note: the
fl-absolute on 3 consecutive runs is the trustworthy read here — a single
WITH-vs-WITHOUT A/B was inconclusive because a sub-10 ns saving sits under the
~±8 ns worker swing (the WITHOUT run happened to land on a fast worker, glibc
6.9 ns). The whole strto*/ato* numeric-parse family is now fast-pathed.

## 2026-06-20 bd-f874go fallback-table exact hot-slot — REJECTED/REVERTED

Targeted the remaining deployed strict `calloc/free` small-size gap after the
native reentry-slot keep. The attempted lever cached the exact fallback-table
slot in the current allocator reentry slot and let strict `free` try an atomic
same-slot remove before the existing locked fallback-table remove. This was a
different shape from the rejected whole-table CAS route and the tombstone
compaction route.

Baseline current head on `vmi1153651` via `calloc_glibc_bench`:

| Size | FL p50 | glibc p50 | p50 ratio | FL mean | glibc mean | mean ratio | Verdict |
|---:|---:|---:|---:|---:|---:|---:|---|
| 16 | 114.960 ns | 10.819 ns | 10.63x | 140.949 ns | 25.417 ns | 5.55x | LOSS |
| 256 | 435.260 ns | 37.111 ns | 11.73x | 562.837 ns | 56.385 ns | 9.98x | LOSS |
| 4096 | 498.224 ns | 104.550 ns | 4.77x | 538.890 ns | 156.296 ns | 3.45x | LOSS |
| 65536 | 1536.001 ns | 1042.184 ns | 1.47x | 1865.195 ns | 1358.150 ns | 1.37x | LOSS |
| 262144 | 4372.561 ns | 4142.734 ns | 1.06x | 5460.396 ns | 4884.627 ns | 1.12x | LOSS |
| 1048576 | 20454.473 ns | 20917.348 ns | 0.98x | 23103.947 ns | 29813.969 ns | 0.77x | WIN |
| 4194304 | 102830.806 ns | 96288.569 ns | 1.07x | 158753.434 ns | 117990.544 ns | 1.35x | LOSS |

Candidate screen selected `vmi1167313` despite the `vmi1153651` preference, so
it cannot be used as same-worker keep proof. It still failed the in-run
deployed FL-vs-glibc screen:

| Size | Candidate FL p50 | glibc p50 | p50 ratio | Candidate FL mean | glibc mean | mean ratio | Verdict |
|---:|---:|---:|---:|---:|---:|---:|---|
| 16 | 114.149 ns | 10.126 ns | 11.27x | 151.006 ns | 25.867 ns | 5.84x | LOSS |
| 256 | 413.707 ns | 34.482 ns | 12.00x | 542.141 ns | 46.782 ns | 11.59x | LOSS |
| 4096 | 497.501 ns | 144.469 ns | 3.44x | 13213.080 ns | 193.641 ns | 68.24x | LOSS/tail outlier |
| 65536 | 1474.389 ns | 1016.307 ns | 1.45x | 1781.323 ns | 1227.567 ns | 1.45x | LOSS |
| 262144 | 4895.259 ns | 3977.730 ns | 1.23x | 5544.162 ns | 4793.244 ns | 1.16x | LOSS |
| 1048576 | 20201.254 ns | 19162.883 ns | 1.05x | 26756.896 ns | 22411.227 ns | 1.19x | LOSS |
| 4194304 | 95059.017 ns | 94918.658 ns | 1.00x | 128244.779 ns | 120525.788 ns | 1.06x | NEUTRAL p50 / LOSS mean |

Win/loss/neutral: baseline score 2 wins / 0 neutral / 12 losses across p50+mean;
candidate screen score 0 wins / 1 neutral / 13 losses. Action: source reverted;
kept only evidence. Retry predicate: do not retry the per-thread exact
fallback-slot cache as a standalone lever. Next allocator attempt needs either a
same-run substage split (host allocator vs fallback metadata vs stats vs reentry
guard) or a materially different proof-carrying path that removes fallback-table
participation for common strict `calloc/free` pairs.

Evidence: `tests/artifacts/perf/bd-f874go-fallback-hot-slot.md`.

## 2026-06-20 bd-f874go strict calloc one-slot recycle/live-slot — REJECTED/REVERTED

Targeted the biggest remaining deployed strict `calloc/free` rows by trying a
bounded exact-class cache for 16/256/4096-byte blocks. The alien-graveyard
allocator shape was intentionally radical but small: retain one freed host block
per hot class, skip fallback-table participation while the block is live, and
zero recycled blocks directly. Three remote candidates were measured and the
source was manually reverted because the target 256/4096 rows did not improve.

Local fallback routing baseline (not acceptance evidence; `rch` remote preflight
timed out and ran local):

| Size | FL p50 | glibc p50 | FL/glibc | Verdict |
|---:|---:|---:|---:|---|
| 16 | 44.015 ns | 5.243 ns | 8.40x | LOSS |
| 256 | 1110.918 ns | 18.938 ns | 58.66x | LOSS |
| 4096 | 1279.538 ns | 48.138 ns | 26.58x | LOSS |
| 65536 | 1761.087 ns | 585.685 ns | 3.01x | LOSS |
| 262144 | 3441.133 ns | 2200.207 ns | 1.56x | LOSS |
| 1048576 | 14152.584 ns | 11401.449 ns | 1.24x | LOSS |
| 4194304 | 49718.937 ns | 48043.578 ns | 1.03x | NEUTRAL |

Candidate A: simple recycle slot, remote `vmi1156319`.

| Size | FL p50 | `fl_old` p50 | glibc p50 | FL/glibc | FL/old | Verdict |
|---:|---:|---:|---:|---:|---:|---|
| 16 | 100.707 ns | 528.753 ns | 10.669 ns | 9.44x | 0.190x | self-WIN / glibc-LOSS |
| 256 | 570.316 ns | 569.806 ns | 35.971 ns | 15.86x | 1.001x | NEUTRAL/LOSS |
| 4096 | 761.901 ns | 731.443 ns | 148.259 ns | 5.14x | 1.042x | LOSS |
| 65536 | 1498.860 ns | 1502.169 ns | 1047.607 ns | 1.43x | 0.998x | NEUTRAL/LOSS |
| 262144 | 4795.098 ns | 4796.953 ns | 4311.876 ns | 1.11x | 1.000x | NEUTRAL/LOSS |
| 1048576 | 21769.371 ns | 21324.687 ns | 20645.461 ns | 1.05x | 1.021x | LOSS |
| 4194304 | 98737.060 ns | 93648.625 ns | 94639.786 ns | 1.04x | 1.054x | LOSS |

Candidate B: add cached-live metadata slot to bypass fallback table while the
recycled block is checked out, remote `vmi1153651`.

| Size | FL p50 | `fl_old` p50 | glibc p50 | FL/glibc | FL/old | Verdict |
|---:|---:|---:|---:|---:|---:|---|
| 16 | 101.979 ns | 568.087 ns | 12.271 ns | 8.31x | 0.180x | self-WIN / glibc-LOSS |
| 256 | 571.500 ns | 558.744 ns | 37.211 ns | 15.36x | 1.023x | LOSS |
| 4096 | 784.407 ns | 863.198 ns | 151.651 ns | 5.17x | 0.909x | self-WIN / glibc-LOSS |
| 65536 | 1616.794 ns | 1571.560 ns | 1160.581 ns | 1.39x | 1.029x | LOSS |
| 262144 | 5254.861 ns | 5360.870 ns | 4571.917 ns | 1.15x | 0.980x | LOSS vs glibc |
| 1048576 | 22434.757 ns | 22069.578 ns | 20248.738 ns | 1.11x | 1.017x | LOSS |
| 4194304 | 100970.802 ns | 99175.500 ns | 106888.532 ns | 0.94x | 1.018x | glibc-WIN / old-LOSS |

Candidate C: inline recycled-zero writes (`u128` for 16 B, `rep stosq` for
256/4096 B), final same-worker remote `vmi1153651`.

| Size | FL p50 | `fl_old` p50 | glibc p50 | FL/glibc | FL/old | Verdict |
|---:|---:|---:|---:|---:|---:|---|
| 16 | 91.418 ns | 410.785 ns | 11.196 ns | 8.16x | 0.223x | self-WIN / glibc-LOSS |
| 256 | 421.490 ns | 416.309 ns | 37.891 ns | 11.12x | 1.012x | LOSS |
| 4096 | 487.234 ns | 462.130 ns | 116.207 ns | 4.19x | 1.054x | LOSS |
| 65536 | 1496.238 ns | 1469.634 ns | 1016.709 ns | 1.47x | 1.018x | LOSS |
| 262144 | 4924.500 ns | 5075.574 ns | 4422.657 ns | 1.11x | 0.970x | glibc-LOSS |
| 1048576 | 21254.030 ns | 22711.327 ns | 20124.078 ns | 1.06x | 0.936x | glibc-LOSS |
| 4194304 | 104458.013 ns | 100715.574 ns | 103633.044 ns | 1.01x | 1.037x | NEUTRAL/LOSS |

Win/loss/neutral: the final candidate scored 1 useful self-win (16 B) but
missed the target rows: 256 B and 4096 B both regressed versus `fl_old`, and the
4 MiB row showed noisy p50/tail regression. Action: source and test hunks
reverted; central evidence kept. Retry predicate: do not retry one-slot hot-class
recycling. A future allocator lever needs either a multi-block/thread-local slab
with same-worker proof, or a proof-carrying path that removes fallback metadata
for strict `calloc/free` without changing strict ownership semantics.

## 2026-06-20 rand() — 1.64x deployed loss (single-threaded lock-skip fix BUILT but HELD: pre-existing conformance red)

`rand()`/`random()` take a `std::sync::Mutex` lock on EVERY call (core
`random_sv::random`). glibc's `rand()` skips its lock while
`__libc_single_threaded` is set — the common single-threaded case. Measured via
`strtol_glibc_bench` (deployed criterion path; fl's flag stays 1 because criterion
spawns std/glibc threads, not fl's `pthread_create`): **rand fl=12.3 ns vs glibc
7.5 ns (1.64x)** — and glibc is single-threaded-fast here, so the gap is purely
fl's unconditional lock.

Implemented the glibc-matching fix: restructured `random_sv` GLOBAL to
`UnsafeCell<RandomState>` + a `LOCK: Mutex<()>` + a `SINGLE_THREADED` flag
(cleared by abi `pthread_create`), with a `with_state` helper that locks only when
multi-threaded OR `cfg!(test)` (tests can't trust the flag). Value-preserving:
verified the rand sequence is BYTE-IDENTICAL to main (both produce the canonical
`srand(1)`→1804289383).

**HELD, not shipped.** Running `conformance_diff_stdlib_random` to verify, it
SIGABRTs on `rand/srand divergences` — but **it does so on main too (changes
stashed)**, so this is a PRE-EXISTING red gate, not my regression. Notably fl
returns **1804289383** (the canonical glibc `srand(1)`→`rand()` value) while the
test's host `rand()` returns **846930886** (exactly the SECOND value) — i.e. the
test's live-glibc baseline is advanced one call, smelling like a harness
state-leak (the dlsym'd host `rand()` is invoked once during setup, or fl's
`no_mangle rand` interposes inconsistently). So fl's rand is very likely correct
and the gate a false-negative — but per MEASURED/conformance-GREEN discipline I do
NOT ship a perf change into a function with a failing gate. Reverted the perf
change; left the `rand` case in the bench as a measurement asset.

Two findings for the next session: (1) the rand single-threaded lock-skip is a
real, value-preserving ~1.6x win ready to land once the gate is resolved; (2) the
`conformance_diff_stdlib_random` rand/srand sub-case is a pre-existing red worth
investigating (likely the test harness, since fl matches canonical glibc).

## 2026-06-20 RESOLVED: conformance_diff_stdlib_random was a harness false-negative — fl rand/rand48 is byte-exact; gate now GREEN

Confirmed the suspicion above. A fresh-`dlmopen` comparison (clean glibc, no
interposition) showed fl's ENTIRE process-global RNG family is byte-identical to
glibc — rand/srand (`srand(1)`→`[1804289383,846930886]`), srand48/lrand48,
drand48, seed48 (+ prior-state) all match exactly across seeds. The gate's
SIGABRT was a **harness false-negative**: it declared the host functions as
linked `extern "C"`, but fl exports `no_mangle` `rand`/`srand`/`*rand48`, so
link-time resolution interposed them inconsistently (e.g. `srand`→fl while
`rand`→glibc), leaving the host generator unseeded and one call ahead.

Fix (test only): resolve all process-global host RNG functions
(rand/srand/srand48/drand48/lrand48/mrand48/seed48/lcong48 + erand48/nrand48/
jrand48 for the post-lcong48 cases) from a SINGLE private `dlmopen("libc.so.6",
LM_ID_NEWLM)` namespace via a `HostRng` struct — the same robust pattern the
`*_glibc_bench` benches use. `conformance_diff_stdlib_random` now **11 passed / 0
failed** (was SIGABRT). This is a real conformance-infra fix AND it unblocks the
held rand() single-threaded lock-skip perf win (which was already verified
value-preserving). Caller-state externs (rand_r, standalone e/n/jrand48) keep
their linked decls — they're pure-of-their-args so interposition can't offset
them.

## 2026-06-20 rand()/random() single-threaded lock-skip — LANDED: 1.64x LOSS → 0.63x WIN

With the conformance gate now green (above), shipped the previously-held fix.
fl `random_sv` took a `std::sync::Mutex` on every `random()`/`srandom()` call;
glibc skips its lock while single-threaded. Restructured GLOBAL to
`UnsafeCell<RandomState>` + `LOCK: Mutex<()>` + a `SINGLE_THREADED` flag
(`AtomicU8`, cleared at abi `pthread_create`'s existing `__libc_single_threaded`
site via `mark_multithreaded()`), with a `with_state` helper that locks ONLY when
multi-threaded OR `cfg!(test)` (tests can't trust the flag — fl thread tracking
isn't wired through `std::thread`). `#[allow(unsafe_code)]` on the two unsafe
spots (core is `#![deny(unsafe_code)]` with 397 sanctioned exceptions).

Measured (strtol_glibc_bench rand case, deployed criterion path, 3 consecutive
runs): fl **12.3 ns → 3.2-3.6 ns**, ratio **1.64x → 0.58-0.63x WIN** (~3.6x
faster; now BEATS glibc's 5.6 ns, which still locks). Value-preserving:
`conformance_diff_stdlib_random` stays **11 passed / 0 failed** with the change
(rand sequence byte-identical). In a deployed multi-threaded process the flag
flips at the first `pthread_create`, so all concurrent `rand()` callers serialize
on `LOCK` exactly as before — correctness is unchanged; only the single-threaded
common case is accelerated, exactly as glibc does it.

Win/loss/neutral: clean WIN (1.64x loss → 0.6x win), 0 regressions, gate green.

## 2026-06-20 getenv() — 40.7x LOSS → 1.97x: a gettid() SYSCALL per call, killed by the single-threaded lock-skip

Benched deployed getenv via a fresh `dlmopen` glibc whose private `environ` is
pointed at the process table (both walk the same env; fl exports no_mangle getenv
so dlmopen avoids interposition). Deployed getenv("PATH") was **560 ns vs glibc
14 ns (40.7x)**, miss 592 ns (23x) — catastrophic for a ubiquitous call.

Root cause: `native_getenv` takes `ENVIRON_LOCK`, an `AbiReentrantMutex` whose
`lock()` calls `current_tid()` = **`sys_gettid()` — a SYSCALL — every call**. The
membrane fast-path (applied same turn: skip the always-Allow Stdlib
decide()+observe() and use a plain bounded name scan instead of `scan_c_string`'s
`allocation_bound` lookup) trimmed a little, but the syscall dominated.

Fix (same single-threaded lever as rand): the lock guards only against a
concurrent `setenv` reallocating the table; while `__libc_single_threaded` is set
there is no concurrent setenv, so skip the lock (and its gettid syscall) — exactly
as glibc skips its lock single-threaded. The flag flips to 0 at the first
pthread_create, restoring the lock for all concurrent access.

Measured: getenv **560 → 25.8 ns (40.7x → 1.97x)**, miss 592 → 47 ns (23x →
1.80x) — a ~22x speedup. Conformance green: conformance_diff_getenv,
metamorphic_getenv, conformance_diff_setenv, conformance_diff_secure_getenv (all
pass; the walk/result is unchanged). Residual ~2x = `getenv_bootstrap_sensitive`
(5 reentry/init context checks per call) + the name scan vs glibc's bare walk.
**GENERAL FINDING: any fl hot path guarded by `AbiReentrantMutex` pays a gettid()
syscall per call; the single-threaded skip (or a cached tid) is a huge lever —
audit other reentrant-mutex users.**

Win/loss/neutral: clean WIN (40.7x loss → 1.97x), 0 regressions, gates green.

## 2026-06-20 pthread_self() — 40x LOSS → 0.88x WIN: lazy per-thread cache kills the gettid() syscall

Auditing hot per-call syscalls (the getenv lever), benched pthread_self: **fl 72 ns
vs glibc 2.6 ns (40x)** — `native_pthread_self` calls `core_self_tid()` =
`gettid()` SYSCALL every call. fl already had a `current_pthread_self_cache` in
pthread TLS, but it was checked ONLY for the HOST backend and populated ONLY at
`pthread_create` — so the MAIN thread (kernel-created, where most code runs, in
both bench AND deployed) and native-backend threads paid the syscall on every
call. pthread_self is constant per thread, so: check the cache for ALL threads,
and lazily populate it on the first call. glibc reads its TCB pointer the same way
(no syscall).

Measured: pthread_self **72 → 2.30 ns (40x loss → 0.88x WIN)**, ~31x faster, now
beats glibc. Value-preserving (cached == recomputed). Conformance green:
conformance_diff_pthread (7), pthread_abi_test, pthread_thread_lifecycle_test (0
failures). The bench main thread is kernel-created exactly like a deployed
process's main thread, so this is representative (no startup-state confound).

UNRESOLVED / SUSPECTED-ARTIFACT (NOT pursued): the same audit benched
`clock_gettime` 4.8x and `time` 45x slow, but their vDSO fast path is gated on
`is_runtime_ready() && !pipeline_initialization_active()` — full deployed startup
state the criterion bench can't replicate (signalling runtime-ready alone only got
clock_gettime 271→122 ns; the pipeline-init gate stays set). So those are LIKELY
deployed-startup bench artifacts (deployed clock_gettime uses the vDSO ~25 ns),
not real losses — but CONFIRMING needs an LD_PRELOAD harness (fl as the actual
libc). Removed from the committed bench to avoid misleading numbers; flagged here.

Win/loss/neutral: clean WIN (40x loss → 0.88x), 0 regressions, gates green.

## 2026-06-20 clock_gettime() — 27x DEPLOYED LOSS → 1.14x: vDSO symbol resolution was a STUB; implemented the ELF parse

The earlier "clock_gettime/time suspected bench artifacts" suspicion was WRONG —
an **LD_PRELOAD ground-truth** test (built the fl cdylib, ran a C loop of 3M
clock_gettime calls under `LD_PRELOAD=libfrankenlibc_abi.so` vs glibc) proved it
REAL: **fl 1.87 s vs glibc 0.07 s (~27x)**. Root cause: `resolve_vdso_symbols`
in time_abi.rs was a STUB — it set only a `mapping_present` diagnostic bool and
returned `clock_gettime: None`, so `raw_clock_gettime` ALWAYS fell back to the raw
`clock_gettime` syscall; the vDSO was never used. (The stub's comment worried
about "re-entering glibc loader state", but that only applies to a *dynamic-linker*
resolve — a direct ELF parse from AT_SYSINFO_EHDR has no linker involvement.)

Fix: implemented `parse_vdso` — a port of the kernel's reference parse_vdso using
ONLY direct memory reads of the mapped vDSO ELF at AT_SYSINFO_EHDR (Elf64 Ehdr →
PT_LOAD bias + PT_DYNAMIC → DT_SYMTAB/STRTAB/HASH → iterate DT_HASH nchain symbols
→ match `__vdso_clock_gettime`/`__vdso_gettimeofday`, addr = load_offset+st_value).
Any structural anomaly returns `None` → callers fall back to the syscall, so a
parse failure is never fatal and never yields a bad pointer.

Measured: clock_gettime **LD_PRELOAD 1.87 s → 0.08 s (~27x → ~1.14x)**; criterion
bench (runtime-ready) 122 → 44.6 ns (4.8x → 1.36x; residual = fl's valid-clock-id
+ vdso-enabled checks around the call). `time()` (routes through raw_clock_gettime)
260 ns/89x → 37 ns/14.6x — the 14x remainder is that glibc `time()` uses the
dedicated `__vdso_time` vvar read (~2.5 ns) vs fl's full clock_gettime; a
follow-up. Correctness: conformance_diff_clock (6), conformance_diff_gmtime (2)
green; the 3M-call LD_PRELOAD loop ran without a fault (bad pointer would segv).

Win/loss/neutral: clean WIN (clock_gettime ~27x deployed loss → ~1.14x), 0
regressions, gates green. **KEY METHOD: LD_PRELOAD the fl cdylib + a C micro-loop
is the GROUND TRUTH for startup-state-gated deployed paths the criterion bench
can't reach — it disproved my "bench artifact" call and is now THE tool for vDSO/
startup-gated perf. fl IS LD_PRELOAD-able (didn't crash).**

## 2026-06-20 time() — 89x → 1.14x: added __vdso_time (vvar read); + gettimeofday fixed free by the parser

Follow-up to the vDSO parser. Two more vDSO wins:
- **gettimeofday was already fixed free** by last commit: `raw_gettimeofday` was
  already wired to `symbols.gettimeofday`, which the parser now resolves
  (`__vdso_gettimeofday`). No code change needed.
- **time()**: glibc's `time()` reads the seconds straight from the vvar page via
  `__vdso_time` (~2 ns); fl's did a full `clock_gettime` (which the parser already
  sped up, 89x→14.6x). Added `__vdso_time` to the parser (3rd symbol) + a vDSO
  fast path in `time()` (call `__vdso_time(NULL)`, store into `tloc` ourselves so
  the membrane bounds-check stays the sole writer; a valid second count is always
  positive, anything else falls through to clock_gettime).

Measured: time() criterion bench **37 → 2.18 ns (14.6x → 1.14x)**; LD_PRELOAD
ground truth **fl 0.02 s vs glibc 0.01 s** over 3M calls (was ~89x as a raw
syscall) — fault-free. Across the two commits, time() went **89x → ~1.14x**.
Conformance green: conformance_diff_clock (6), conformance_diff_gmtime (2).

Win/loss/neutral: clean WIN (time 89x→1.14x, gettimeofday free), 0 regressions.
The vDSO clock family (clock_gettime/gettimeofday/time) is now all near-parity
with glibc. Remaining clock_gettime ~1.36x residual = fl's per-call
valid-clock-id + vdso-enabled wrapper checks around the vDSO call.

## 2026-06-20 LD_PRELOAD sweep of hot deployed functions — strlen 16x + malloc 21x (the criterion bench HIDES these); entrypoint_scope TLS tax is the broad lever (confounded)

Used the LD_PRELOAD ground-truth harness (C micro-loop, 3M iters each, fl cdylib
vs glibc) to sweep hot functions the criterion bench reports as "fine":
  - malloc/free 64B:   glibc 0.01s  fl 0.21s  ~21x  (known; owned/membrane)
  - strlen 255B:       glibc 0.01s  fl 0.16s  ~16x  (!! supposedly SIMD-done)
  - pthread_mutex l/u: glibc 0.02s  fl 0.04s  ~2x
  - memcpy 256B:       glibc 0.01s  fl 0.02s  ~2x
  - pthread_rwlock:    glibc 0.02s  fl 0.02s  parity
  - strcmp equal:      ~parity

strlen 16x is the surprise — the SIMD core is fast, but the DEPLOYED wrapper
(`string_abi::strlen`) pays, per call: `runtime_policy::entrypoint_scope("strlen")`
(pure telemetry — sets+restores a trace context via TWO `thread_local!`
`TRACE_CONTEXT.try_with` accesses) + `known_remaining` (ptr lookup), on top of the
~10 ns scan. entrypoint_scope is the BROADEST lever in the codebase — EVERY ABI
function calls it; its trace context is consumed only by FFI-PCC cert lookup +
hardened `record_last_explainability` + tests, so it is pure overhead in deployed
strict and is gate-able to a no-op.

NOT fixed this turn — TWO confounds make the magnitude untrustworthy AND the fix
high-risk: (1) under LD_PRELOAD fl's TLS is **general-dynamic** (slow
`__tls_get_addr`); a true-deployed fl (the libc/interpreter) may get
**initial-exec** TLS (~2 ns) → the entrypoint_scope tax could be much smaller
deployed. (2) building the cdylib with `--features owned-tls-cache` (the
"faster TLS" path) made strlen **WORSE** (0.16→7.89s) — a pessimization, not a
fix, so the right mechanism is unclear. And `entrypoint_scope`/`known_remaining`
live in the shared, load-bearing-adjacent `runtime_policy`/`malloc_abi` core
(string_abi is also actively SIMD-optimised by another agent) — a wrong gate
breaks FFI-PCC verification. Shipping unverified here violates MEASURED/REVERT.

Action: documented as the highest-value remaining deployed lever. To pursue
safely: measure entrypoint_scope with a true-libc (not LD_PRELOAD) TLS model, then
gate it to a no-op when `!(ffi_pcc_active || hardened || cfg!(test))`. malloc 21x
is the other big one (owned). The criterion `*_glibc_bench` does NOT exercise the
entrypoint_scope/known_remaining wrapper tax — only LD_PRELOAD does; ledger this so
the membrane/string/malloc owners can act.

## 2026-06-20 strtol direct C-string parser - deployed loss cut to 1.19x-1.24x on long/hex

The post-`ato*` residual was deployed `strtol`: the ABI path scanned the C string
for a numeric prefix, built a Rust slice, then delegated to the core parser which
rescanned for whitespace, sign, base prefix, digits, overflow, and `endptr`.
The kept lever is a fused direct C-string transducer for the hot measured bases
10 and 16. It reads exactly once, handles whitespace/sign and `0x` prefix
semantics, computes overflow with cutoff/cutlim, and writes `endptr` from the
same cursor that found the first non-digit. Other bases still use the generic
path. I did not add wide speculative vector loads because page-safe C-string
over-read risk would outweigh the current gap.

Same-worker `vmi1152480`, clean `e464f5c31` baseline vs candidate, identical
bench command and target dir:

| Workload | Baseline FL | Baseline glibc | Baseline ratio | Candidate FL | Candidate glibc | Final ratio | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| `strtol_dec_short` | 14.21 ns | 8.76 ns | 1.62x | 7.65 ns | 4.82 ns | 1.59x | NEUTRAL gap-cut |
| `strtol_dec_long` | 34.25 ns | 18.07 ns | 1.90x | 22.16 ns | 17.88 ns | 1.24x | WIN gap-cut |
| `strtol_hex` | 37.68 ns | 18.24 ns | 2.07x | 21.38 ns | 18.02 ns | 1.19x | WIN gap-cut |

Validation: `rustfmt --edition 2024 --check
crates/frankenlibc-abi/src/stdlib_abi.rs` passed, and
`RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p frankenlibc-abi --test
strtol_family_differential_fuzz -- --nocapture` passed on `vmi1152480` with
1,000,000 comparisons and 0 divergences vs host glibc. The release bench also
compiled the ABI crate in release mode through the same `rch` target dir.

Verdict: keep. This is not a full `strtol` closeout because the short row remains
1.59x vs glibc and the bench still shows unrelated residual `strtod` and
environment/time rows. The next credible parser lever is either an even lower
entrypoint/endptr overhead for short `strtol` or a direct `strtod` parser; do not
retry another generic membrane branch tweak for this exact loss.

## 2026-06-20 entrypoint_scope no-op in strict-passthrough — safe per-call telemetry skip on EVERY ABI entry

Acting on the prior LD_PRELOAD finding (entrypoint_scope = the broadest wrapper
tax). `runtime_policy::entrypoint_scope(symbol)` runs on EVERY ABI entry and sets
a trace context via `next_trace_seq` + `ffi_pcc_certificate_index_for_symbol`
lookup + TWO `thread_local!` accesses (set here, restore on drop). That context is
ONLY consumed by the FFI-PCC certificate lookup inside `decide()` and by
`record_last_explainability`. In `strict_passthrough_active()` mode (the deployed
default) `decide()` returns at the high-frequency-family fast-path BEFORE the
FFI-PCC lookup, and explainability runs only hardened — so the context is provably
never read. Gated entrypoint_scope to a no-op guard (added a `skipped` flag so the
Drop also skips the restore-TLS write) when `strict_passthrough_active()` (a cheap
atomic that is `false` under cfg(test), so unit tests keep the full path).

Measured (LD_PRELOAD): strlen **0.16 → 0.13 s** (~10 ns/call saved — the
entrypoint_scope work). Modest for strlen (its remaining ~13x is `known_remaining`
+ SIMD-dispatch select, in owned string/malloc core — left for those owners), but
this saves the telemetry overhead on EVERY ABI function in deployed strict.
NOTE: the LD_PRELOAD TLS is general-dynamic (slow), so the true-deployed saving
(initial-exec TLS) is smaller (~atomic + lookup + 2 fast TLS) but still real.

Correctness: runtime_policy lib tests (37), cross-family conformance
(strtod/strtol/math/ctype/getenv/clock — 0 failures) green — the trace context is
unused where it's skipped, and tests exercise the full path. Win/loss/neutral:
small but broad WIN (every ABI entry in strict-passthrough), 0 regressions.

## 2026-06-20 LD_PRELOAD gauntlet batch 2 — qsort 12x + snprintf 47x; all remaining big deployed losses are OWNED

Second LD_PRELOAD ground-truth sweep (2M-iter C loops, fl cdylib vs glibc):
  - localtime:  glibc 5.40s  fl 0.08s  → fl WINS ~67x (glibc is oddly slow here)
  - gmtime:     glibc 0.04s  fl 0.07s  → ~1.75x (modest; membrane wrapper)
  - snprintf:   glibc 0.10s  fl 4.69s  → ~47x LOSS  (owned: stdio_abi)
  - qsort 16xi: glibc 0.02s  fl 0.24s  → ~12x LOSS  (owned: core sort.rs)
  - strncmp/memset/abs: parity/too-fast-to-measure

qsort root cause (for the sort owner): `core::stdlib::sort` first tries an
integer-radix lane (`try_integer_unstable_lanes`, width 4/8/...) — but that probe
rejects the ubiquitous `return *(int*)a - *(int*)b` comparator (it isn't a correct
total order: subtraction overflows), so a standard-int qsort falls to
`pdqsort_recurse`, whose per-comparison `elem(buf,width,i) = &buf[i*width..]`
(sort.rs:127) is a BOUNDS-CHECKED slice access — ~16 ns/comparison vs glibc's
~1.3 ns (raw `char*` arithmetic). Likely fixable with `get_unchecked` on the
provably-in-bounds element accesses in the pdqsort hot loop, OR by widening the
radix probe to accept the overflow-prone-but-monotone int comparator.

CAMPAIGN STATE: the clean criterion-bench wins are exhausted, and EVERY remaining
big deployed loss now lives in actively-owned files — strlen/memcpy (string_abi,
SIMD agent: known_remaining + select_string_simd_dispatch per call), malloc
(malloc_abi), snprintf (stdio_abi), qsort (core sort.rs, sort agent). Documented
for those owners rather than risk-poking owned code mid-flight. My own
non-owned broad lever (entrypoint_scope) is done. Caveat (recurring): the
criterion `*_glibc_bench` does NOT show these — only the LD_PRELOAD harness does.

## 2026-06-20 setenv/putenv/unsetenv/clearenv — 6x → ~1x: ENVIRON_LOCK single-threaded skip (the getenv lever, write paths)

The getenv fix skipped `ENVIRON_LOCK`'s per-call `gettid()` syscall on the READ
path; the env WRITE family still paid it. LD_PRELOAD: setenv **6.2x** (fl 1.36s vs
glibc 0.22s/1M), unsetenv **5.8x**. Added a shared `environ_lock_guard()` →
`Option<AbiReentrantMutexGuard>` (Some only when `__libc_single_threaded == 0`)
and routed all 7 `ENVIRON_LOCK.lock()` write/helper sites (setenv/putenv/unsetenv/
clearenv/...) through it. The lock only guards against a concurrent setenv
reallocating the table; single-threaded there is none, so skip it (and its
syscall), exactly as glibc elides its lock single-threaded. Flag flips at first
pthread_create.

Measured (LD_PRELOAD): setenv **1.36 → 0.27 s (6.2x → 1.17x)**, unsetenv
**1.22 → 0.12 s (5.8x → 0.57x WIN)** — ~5-10x faster, now at/under glibc.
Conformance green: conformance_diff_setenv (2), conformance_diff_getenv (2),
metamorphic_getenv (9), conformance_diff_secure_getenv (6). Value-preserving (same
env mutations; the lock is skipped only where there is no concurrent access).

Win/loss/neutral: clean WIN across the env write family (6x→~1x), 0 regressions.
The whole getenv/setenv/putenv/unsetenv/clearenv family is now de-syscalled.

## 2026-06-20 deployed `strtod` exact-integer fast path - keep

The deployed `strtod` path now recognizes decimal tokens that normalize to an
exactly representable `f64` integer and returns directly from the ABI layer,
writing `endptr` from the same cursor. Fractional, rounded, hex, NaN/Inf,
overflow, and extreme-exponent cases stay on the existing full parser.

Baseline `strtol_glibc_bench` on `vmi1152480` showed `strtod_int` at 38.73 ns vs
glibc 35.21 ns (1.10x LOSS), `strtod_simple` at 53.14 ns vs 69.35 ns (0.77x
WIN), and `strtod_sci` at 68.09 ns vs 49.20 ns (1.38x LOSS). Candidate RCH
selected `hz1`, so old/new nanoseconds are cross-worker; the candidate
ratio-vs-glibc rows are still direct head-to-head on that worker:

| Workload | FrankenLibC | glibc | Ratio | Verdict | Action |
|---|---:|---:|---:|---|---|
| `strtol_dec_short` | 9.66 ns | 10.81 ns | 0.89x | WIN | Sentinel; unchanged family. |
| `strtol_dec_long` | 27.76 ns | 18.52 ns | 1.50x | LOSS | Existing residual; not touched. |
| `strtol_hex` | 20.13 ns | 18.52 ns | 1.09x | LOSS | Existing residual; not touched. |
| `atoi_short` | 4.03 ns | 9.88 ns | 0.41x | WIN | Sentinel; unchanged family. |
| `atoi_long` | 11.43 ns | 19.44 ns | 0.59x | WIN | Sentinel; unchanged family. |
| `atol_short` | 3.72 ns | 8.96 ns | 0.41x | WIN | Sentinel; unchanged family. |
| `atol_long` | 11.42 ns | 18.82 ns | 0.61x | WIN | Sentinel; unchanged family. |
| `atoll_short` | 3.72 ns | 8.65 ns | 0.43x | WIN | Sentinel; unchanged family. |
| `atoll_long` | 11.42 ns | 18.52 ns | 0.62x | WIN | Sentinel; unchanged family. |
| `strtod_int` | 11.73 ns | 34.89 ns | 0.34x | WIN | Keep exact-integer fast path. |
| `strtod_simple` | 55.85 ns | 65.76 ns | 0.85x | WIN | Existing full parser remains winning. |
| `strtod_sci` | 20.09 ns | 45.58 ns | 0.44x | WIN | Keep exact-integer fast path. |
| `rand` | 3.15 ns | 6.38 ns | 0.49x | WIN | Sentinel; unchanged family. |
| `getenv_hit` | 47.49 ns | 20.56 ns | 2.31x | LOSS | Existing residual; not touched. |
| `getenv_miss` | 74.01 ns | 29.20 ns | 2.54x | LOSS | Existing residual; not touched. |
| `clock_gettime` | 35.78 ns | 30.54 ns | 1.17x | LOSS | Existing residual; not touched. |
| `time` | 4.94 ns | 3.10 ns | 1.60x | LOSS | Existing residual; not touched. |
| `pthread_self` | 2.17 ns | 2.47 ns | 0.88x | WIN | Sentinel; unchanged family. |

Correctness: `strtod_strtof_live_differential_probe` passed via `rch` on
`vmi1227854`: 8071 inputs, 0 divergences vs host glibc, including `12345`,
`1.234567e10`, `-0e10`, and malformed exponent `1e+` cases. Full evidence:
`tests/artifacts/perf/bd-2g7oyh-strtod-exact-fastpath.md`.
