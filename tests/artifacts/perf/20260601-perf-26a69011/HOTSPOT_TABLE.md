# FrankenLibC Performance Profiling — Ranked Hotspot Table

- **Run ID:** 20260601-perf-26a69011
- **git SHA:** 26a690118f664e7d519ef6a3906f71a5fbc7ddfc
- **Owner:** SnowyMill (cc/opus-4.8) — PROFILING pass (measurement only; no optimization applied)
- **Execution:** rch remote worker `vmi1153651` (AMD EPYC Processor, with IBPB), bench profile (release+LTO), isolated per-job target dir.
- **Build profile:** `bench` (inherits release: opt-level=3, lto=thin, codegen-units=1). `release-perf` (debug=line-tables-only, strip=false) available for flamegraphs.
- **Scenario / success metric:** per-operation membrane cost in ns/op (p50/p95) vs the project's own budgets `FAST_PATH_BUDGET_NS=20`, `FULL_PATH_BUDGET_NS=200` (runtime_math/mod.rs:213-214; README "strict <20ns, hardened <200ns membrane overhead").
- **Caveat:** shared multi-tenant VPS worker → ns-scale tails (p99) are noise-prone and conservative. **Rankings and median deltas are robust**; the smoke lane's 2679ns runtime_math tail was pure noise (vanished at 64 samples). The custom overhead harness has a ~85ns/op fixed measurement floor that masks sub-100ns family differences — `membrane_bench` (criterion, billions of inner iters) is the authoritative sub-100ns attribution source.

## Ranked hotspots (criterion `membrane_bench`, strict mode, ≥69 samples, 1.5M–5.5B inner iterations)

| Rank | Location (`frankenlibc-membrane`) | Metric | p50 | p95 | Budget | Over | Evidence |
|------|-----------------------------------|--------|-----|-----|--------|------|----------|
| 1 | `ptr_validator.rs:676` `ValidationPipeline::validate` (null path → validate_null) | latency/op | **2131 ns** | 2868 ns | 20 ns (FAST) | **~106×** | membrane_bench.raw.log:27-29 |
| 2 | `ptr_validator.rs:676` `validate` (known-allocation path → validate_known) | latency/op | **2095 ns** | 2945 ns | 200 ns (FULL) | **~10×** | membrane_bench.raw.log:48-50 |
| 3 | `ptr_validator.rs:761` `validate_with_security_context` (foreign path → validate_foreign) | latency/op | **1334 ns** | 1437 ns | 200 ns (FULL) | **~7×** | membrane_bench.raw.log:34-36 |
| 4 | `validate_foreign_nonempty_oracle` (foreign w/ populated arena) | latency/op | 1333 ns | 1444 ns | 200 ns | ~7× | membrane_bench.raw.log:41-43 |
| 5 | `ptr_validator.rs` `stage_fingerprint_verify` (isolated stage) | latency/op | 12.8 ns | 34 ns | 20 ns | within | membrane_bench.raw.log:6-8 |
| 6 | `stage_page_oracle_foreign_nonempty` (isolated stage) | latency/op | 2.7 ns | 5 ns | — | within | membrane_bench (structured) |
| 7 | `stage_bounds_check` (isolated stage) | latency/op | 0.49 ns | 1.9 ns | 5 ns | within | membrane_bench.raw.log:20-22 |
| 8 | `stage_canary_verify` (isolated stage) | latency/op | 0.43 ns | 5 ns | 10 ns | within | membrane_bench.raw.log:13-15 |

**The signal:** isolated pipeline stages (ranks 5–8) are all at/under their per-stage budget (≤13 ns). The *composed* `validate_*` entry points (ranks 1–4) cost **1.3–2.1 µs** — a **100–200× gap** over the summed stage cost (~16 ns). The cost is in the validate *entry machinery*, not the safety stages. The null path (which the README budgets at ~1 ns) is the single worst offender at 2131 ns.

## Family-level overhead matrix (custom harness, FULL lane, 64 samples × 1024 inner-iters)

| Family (symbol) | strict p50 | strict p95 | hardened p50 | hardened p95 |
|-----------------|-----------|-----------|--------------|--------------|
| math_fenv (sin) | 107 | 131 | 100 | 124 |
| string_memory (memcpy) | 103 | 184 | 82 | 106 |
| pthread_sync (mutex_lock) | 93 | 137 | 86 | 106 |
| allocator (malloc/free) | 89 | 110 | 82 | 103 |
| stdio_buffer (fwrite) | 89 | 108 | 83 | 102 |
| runtime_math (decide) | 90 | 107 | 82 | 102 |
| ctype (isalpha) | 88 | 107 | 82 | 101 |

All families floor at ~82–107 ns/op including `isalpha` (intrinsically ~1 ns) → this harness is **measurement-floor-limited (~85 ns/op)** and cannot validate the 20 ns strict budget. Use it for cross-mode/cross-family *ranking* only, not absolute sub-100ns claims. (Filed as a tooling note, not a code hotspot.)

## Hypothesis ledger

```
H1 validate entry routes ALL calls through the heavy path : SUPPORTS
   ptr_validator.rs:677 — the ~1ns fast paths (validate_null_without_trace_feedback,
   try_validate_cached_*, try_validate_empty_oracle_*) are gated behind
   `!validation_logging_enabled() && !runtime_math.validation_feedback_enabled()`.
   OBSERVE_FEEDBACK_STATE defaults to ENABLED (runtime_math/mod.rs:101), so
   validation_feedback_enabled()==true by default → fast paths SKIPPED → every
   validate() (incl. null) falls through to validate_with_security_context +
   observe_validation_result. Measured null path 2131ns vs 1ns budget. PRIMARY.

H2 runtime-math control-plane decision dominates the heavy path : LIKELY (needs flamegraph)
   validate_with_security_context invokes the runtime_math decision + feedback
   (risk/bandit/control/barrier/... kernels). validate_known (full pipeline) 2095ns ≈
   validate_null 2131ns despite null doing no stage work → cost is the decision/feedback
   machinery, not arena/fingerprint/canary stages (those measure ≤13ns isolated).

H3 individual safety stages are the bottleneck : REJECTS
   fingerprint 12.8ns, page_oracle 2.7ns, bounds 0.49ns, canary 0.43ns — all within
   per-stage budget. Summed ≈16ns ≪ 2131ns composed.

H4 hardened repair logic is the bottleneck : REJECTS
   hardened p50 ≤ strict p50 for every family (overhead harness). Repair fast-path is
   not the cost driver; the runtime-math feedback gate (H1) is mode-independent.

H5 shared-VPS noise explains the 2µs : REJECTS
   2131ns is the p50 over 69 samples × 1.5M inner iters (criterion), stable across
   validate_null/validate_known. Noise inflates p99 tails, not the median.
```

## Recommended follow-up measurement (not blocking the hand-off)
- Flamegraph `validate_with_security_context` on `release-perf` with `RUSTFLAGS=-C force-frame-pointers=yes` to attribute the 2µs across runtime_math decision vs observe_validation_result vs metrics/locking. (Blocked locally by perf_event_paranoid=4; run under rch worker with paranoid≤1 or use the bench's own ns/op instrumentation.)
- Run `malloc_bench` + `string_bench` criterion suites for allocator/hot-string-kernel ranking (deferred this pass; overhead-harness family data shows them measurement-floor-limited at ~85ns and not standout).

## Filed beads (optimizer hand-off)
- **bd-tti4cb** (P2, perf/membrane) — ranks 1–4: `ValidationPipeline::validate` 1.3–2.1µs vs 20/200ns budget; root cause = feedback gate bypasses fast paths.
- **bd-qe3hmn** (P3, perf/tooling) — overhead harness ~85ns/op measurement floor; cannot validate the 20ns strict budget.
