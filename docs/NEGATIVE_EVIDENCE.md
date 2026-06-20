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
<!-- rows appended as benches complete -->

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
