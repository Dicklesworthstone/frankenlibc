# bd-2g7oyh.336: pass64 memcmp_4096 routing-only closeout

Date: 2026-06-11
Agent: CodexOpt
Scope: no source edit

## Coordination

This scratch worktree was detached at `7433abe3`, while `origin/main` had
already advanced to:

- `d44bda81` / `bd-2g7oyh.336` / `printf_g_6` no-code rejection
- `b761e6e1` / `bd-2g7oyh.337` / `cbrt` no-code rejection

The local Beads DB was stale and created a local child also named
`bd-2g7oyh.336`. That local bead is this routing-only record and collides with
the newer origin `%g` bead. Do not merge this tracker row without parent
reconciliation.

RCH also showed concurrent `memcmp_4096` activity:

- pass64 completed build `29879662679166316`, project
  `frankenlibc-perf-20260611-pass64-8846f80f`
- older pass63 project `frankenlibc-opt-pass63-c7551aa7` had active
  `glibc_baseline_memcmp_4096` build `29879662679166319`

Because ownership was unclear, no `crates/frankenlibc-core/src/string/mem.rs`
edit was attempted.

## Prior Gates

Recent origin closeouts already screened the other pass64 routes:

- `printf_g_6`: focused RCH build `29879662679166284`, FrankenLibC faster than
  host by Criterion estimates (`139.096 ns` median / `140.704 ns` mean vs host
  `140.419 ns` / `143.642 ns`).
- `lgamma`: focused RCH build `29879662679166301`, emitted rows showed
  FrankenLibC `528.370 ns` p50 / `535.257 ns` mean vs host `633.021 ns` /
  `685.158 ns`.
- math routing sweep: RCH build `29879662679166309`; sampled unowned math rows
  were faster than host on this worker (`sinh`, `cosh`, `log10`, `expm1`,
  `log1p`, `cbrt`, `atan`, `erf`, `erfc`, `tgamma`, and matched f32 variants).

## Focused RCH Evidence

Command:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- env \
AGENT_NAME=CodexOpt FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass64-memcmp-focused-baseline \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_memcmp_4096 --noplot --sample-size 50 \
--warm-up-time 1 --measurement-time 3
```

RCH selected `vmi1227854`, build `29879662679166316`.

Criterion estimates:

| impl | median ns | mean ns | sample p50 ns | sample p95 ns | sample p99 ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | 51.252 | 52.568 | 51.367 | 60.258 | 62.262 |
| host glibc | 43.308 | 45.066 | 43.316 | 58.456 | 63.826 |

This is routing evidence for a residual, not permission to edit, because the
same worker simultaneously had an older pass63 `memcmp_4096` probe active.

## Behavior Proof

No source changed. Current file digests:

```text
561924f9cec259aaeb5f38c20cc40325b18b6eea2a2ca52cf6d3cb1ea78d79dd  crates/frankenlibc-core/src/string/mem.rs
b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c  crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

Ordering, first-difference tie-breaking, floating-point state, RNG state, and
golden outputs are unchanged by construction.

## Decision

No-code rejected / routing-only closeout.

Score: `(Impact 0 * Confidence 5) / Effort 1 = 0.0`.

Next route: do not edit `memcmp_4096` until ownership is clear. The next
admissible memcmp primitive must be codegen/IR/disassembly-backed and
structurally different from folded equality certificates, loop unrolling,
broadword extraction, XOR/test-zero retuning, and rank-select repeats.
