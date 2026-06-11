# bd-2g7oyh.330 strncasecmp_256_equal focused gate

## Target

`bd-2g7oyh.330` targeted `glibc_baseline_strncasecmp_256_equal` after
`bd-2g7oyh.329` closed rejected and no unowned ready perf child remained.

The route basis was pass-54 broad profiling on `vmi1227854`, which had shown a
possible residual:

- FrankenLibC p50 `11.562 ns`, mean `13.406 ns`
- host glibc p50 `9.415 ns`, mean `11.137 ns`

Prior focused gates (`bd-2g7oyh.270`, `bd-2g7oyh.276`) had already missed or
failed the Score>=2.0 rule, so this pass required a fresh focused gate before
any source edit.

## Focused RCH Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_TEST_SLOTS=1 RCH_VISIBILITY=summary \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=120 \
rch exec -- cargo bench -j 1 -p frankenlibc-bench \
  --bench glibc_baseline_bench -- glibc_baseline_strncasecmp_256_equal \
  --noplot --sample-size 30 --warm-up-time 1 --measurement-time 3
```

Worker and job:

- RCH worker: `vmi1227854`
- RCH job: `29879662679165718`
- RCH result: exit `0`, remote duration `234.9s`

Criterion interval output:

- FrankenLibC: `[11.480 ns 11.593 ns 11.710 ns]`
- host glibc: `[10.287 ns 10.562 ns 10.887 ns]`

`GLIBC_BASELINE_BENCH` sampled output:

- FrankenLibC: p50 `11.481 ns`, p95 `17.500 ns`, p99 `40.000 ns`,
  mean `13.692 ns`, throughput `86774082.327 ops/s`
- host glibc: p50 `11.791 ns`, p95 `20.000 ns`, p99 `45.000 ns`,
  mean `13.896 ns`, throughput `85903264.652 ops/s`

## Proof

No source edit was made. Behavior is unchanged by construction:

- `crates/frankenlibc-core/src/string/str.rs` sha256:
  `5eb2974530ce7264233c9788e0ded187cd318aeb794ebaf88a4d94ef7fbbe8ef`
- `git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`
  passed.
- Ordering, tie-breaking, NUL handling, bounded-`n` semantics, ASCII case
  folding, FP state, and RNG behavior were not touched.

## Verdict

NO-CODE REJECTED, Score `0.0`.

The focused gate did not reproduce a material actionable gap. The Criterion
interval showed only a small candidate gap, while the benchmark's emitted
p50/mean sample lines reversed in FrankenLibC's favor. A source edit would
violate the profile-backed target rule.

Next route: reprofile when RCH has a clean worker and pick a different
reproduced unowned residual. Do not retry the prior folded-control or
ASCII-case panel families for `strncasecmp_256_equal` without a materially
different generated-code primitive and a fresh focused gap.
