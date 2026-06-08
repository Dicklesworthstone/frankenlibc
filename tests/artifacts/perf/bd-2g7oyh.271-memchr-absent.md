# bd-2g7oyh.271 - memchr_absent focused baseline miss

## Target

- Bead: `bd-2g7oyh.271`
- Function family: `memchr_absent`
- Source scope considered: `crates/frankenlibc-core/src/string/mem.rs`

## Broad Profile Basis

The bead was created from a clean-source broad profile on RCH worker `vmi1152480`:

- FrankenLibC: p50 `36.488 ns`, mean `93.220 ns`
- Host glibc: p50 `21.234 ns`, mean `23.973 ns`

That profile made `memchr_absent` look like the strongest low-risk residual after recent string and memory closeouts.

## Focused Reproduction

Two focused crate-scoped Criterion baselines did not reproduce a vs-host gap.

### RCH `vmi1264463`

Command:

```text
RCH exec cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memchr_absent --noplot --sample-size 35 --warm-up-time 1 --measurement-time 2
```

Result:

- FrankenLibC: p50 `47.628 ns`, mean `55.997 ns`
- Host glibc: p50 `50.719 ns`, mean `59.276 ns`

### RCH `vmi1167313`

Command:

```text
RCH_VISIBILITY=full rch exec -v -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memchr_absent --noplot --sample-size 20 --warm-up-time 1 --measurement-time 2
```

Result:

- FrankenLibC: p50 `41.956 ns`, p95 `85.000 ns`, p99 `180.000 ns`, mean `45.905 ns`
- Host glibc: p50 `50.725 ns`, p95 `72.750 ns`, p99 `190.000 ns`, mean `52.075 ns`

## Decision

Rejected with no source edit.

The focused baselines show FrankenLibC faster than host glibc on p50 and mean, so there is no profile-backed `memchr_absent` lever to ship in this pass. Golden-output SHA is unchanged by construction because no source changed.

Score: `(Impact 0 * Confidence 5) / Effort 1 = 0.0`.

## Next Route

Reprofile and attack a different measured residual. Do not retry the already-tested `memchr` microfamilies without fresh focused evidence:

- folded-panel widening,
- SWAR word-group scans,
- 64-lane mask/rank-select,
- indexed folded-scan control-flow rewrites.
