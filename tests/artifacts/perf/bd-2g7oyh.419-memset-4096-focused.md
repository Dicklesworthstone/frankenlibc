# bd-2g7oyh.419 memset_4096 focused no-code gate

Date: 2026-06-15
Agent: BoldFalcon
Worker: ovh-a
Commit under test: 6df554e7e

## Route

Current-head broad RCH routing on ovh-a selected
`glibc_baseline_memset_4096/memset_4096` as a possible residual:

- FrankenLibC p50/mean: 40.050 / 41.038 ns
- host glibc p50/mean: 32.373 / 33.630 ns

The broad row was treated as routing evidence only. Prior campaign records show
this memory-fill row has repeatedly flipped under focused gates, so source work
requires a focused same-worker reproduction first.

## Focused Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-419-baseline cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- memset_4096 --sample-size 20 --warm-up-time 1 --measurement-time 3
```

Focused same-worker result on `ovh-a`:

- FrankenLibC Criterion interval: [28.214 ns 28.275 ns 28.333 ns]
- FrankenLibC p50/mean: 28.309 / 32.223 ns
- host glibc Criterion interval: [28.145 ns 28.224 ns 28.300 ns]
- host glibc p50/mean: 28.451 / 34.175 ns

## Verdict

NO-CODE REJECTED. The focused gate does not reproduce a vs-host gap;
FrankenLibC is faster than host on both p50 and mean on the focused worker.

Score: 0.0. No implementation source changed.

## Behavior Proof

Behavior is unchanged by construction:

- Byte content/count: unchanged; `memset` implementation is untouched.
- Ordering/tie-breaking: not applicable to this byte-fill workload.
- Floating-point/RNG behavior: unchanged; no math or RNG code changed.
- Golden output: existing `string_memory_full` conformance fixtures remain
  applicable; no new output was generated.

## Reroute

Do not optimize `memset_4096` from the broad ovh-a row alone. Reprofile current
head and select a target whose focused same-worker p50 and mean both reproduce a
material gap.
