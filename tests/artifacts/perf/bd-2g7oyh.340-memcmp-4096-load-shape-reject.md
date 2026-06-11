# bd-2g7oyh.341 memcmp_4096 load-shape rejection

Date: 2026-06-11
Agent: BoldFalcon
Worker: vmi1153651
Base commit: 276e728a

Note: this artifact was created before rebase as `bd-2g7oyh.340-*`.
The concurrent strpbrk closeout took `bd-2g7oyh.340` on `origin/main`, so
this memcmp closeout is tracked as `bd-2g7oyh.341` after rebase.

## Target

`glibc_baseline_memcmp_4096` was selected from the pass-68 broad RCH profile after excluding active peer-owned work:

- `bd-2g7oyh.125` pow/math, assignee MossyFern
- `bd-2g7oyh.65` strncmp/string, assignee SilverCedar

Broad route row on vmi1153651:

- FrankenLibC: p50 95.433 ns, mean 105.677 ns
- host glibc: p50 69.939 ns, mean 74.350 ns

## Focused Baseline

Command:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-340-memcmp-baseline \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_memcmp_4096 --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

Result:

- RCH job: remote vmi1153651, 485.5 s
- FrankenLibC: p50 95.648 ns, p95 155.503 ns, p99 175.452 ns, mean 102.794 ns
- host glibc: p50 61.221 ns, p95 349.046 ns, p99 400.362 ns, mean 100.609 ns

The focused gate reproduced a p50 residual, but host tails were noisy and mean was nearly tied.

## Lever Tested

One source lever was tested and then reverted:

- file: `crates/frankenlibc-core/src/string/mem.rs`
- change: replace the manual index loop over 128-byte folded SIMD blocks with a `chunks_exact(SIMD_FOLD_BYTES)` cursor while keeping the same `ne_simd_folded_128` predicate and the same 32-byte panel resolver.

Isomorphism:

- Ordering unchanged: the first differing 128-byte block is still resolved in increasing 32-byte panel order and then byte order.
- Tie-breaking unchanged: equal blocks are skipped; the first differing byte still determines `Less`/`Greater`.
- Floating point: N/A.
- RNG: N/A.
- Golden output proof: `memcmp_golden_output_sha256` passed.

## Behavior Proof

Broad test attempt:

```bash
cargo test -j 1 -p frankenlibc-core memcmp -- --nocapture
```

This was blocked by unrelated integration-test compile drift in `crates/frankenlibc-core/tests/strftime_differential_probe.rs`:

- `BrokenDownTime` initializer missing `tm_gmtoff`
- `BrokenDownTime` initializer missing `zone`

Scoped proof command:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-340-memcmp-libtests \
cargo test -j 1 -p frankenlibc-core --lib memcmp -- --nocapture
```

Result:

- RCH job: remote vmi1153651, 318.2 s
- 31 passed, 0 failed, 3052 filtered out
- Included `memcmp_golden_output_sha256`, `prop_memcmp_is_antisymmetric`, and `prop_memcmp_matches_std_lexicographic`

Known unrelated warnings observed:

- missing SMT solver for generated stdio proof
- pre-existing `regex.rs` dead-code warning

## Post Benchmark

Command:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-340-memcmp-post \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_memcmp_4096 --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

Result:

- RCH job: remote vmi1153651, 529.7 s
- FrankenLibC: p50 82.947 ns, p95 187.261 ns, p99 434.409 ns, mean 105.597 ns
- host glibc: p50 62.343 ns, p95 82.413 ns, p99 109.812 ns, mean 65.616 ns

## Verdict

Rejected and source restored.

The lever improved FrankenLibC p50 from 95.648 ns to 82.947 ns, but mean regressed from 102.794 ns to 105.597 ns and the Criterion central estimate moved from 98.682 ns to 104.81 ns with worse tail behavior. That is not a real Score>=2.0 win.

Retained source hashes:

- `crates/frankenlibc-core/src/string/mem.rs`: `561924f9cec259aaeb5f38c20cc40325b18b6eea2a2ca52cf6d3cb1ea78d79dd`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`: `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`

Score: 0.0

## Next Route

Do not retry `memcmp_4096` with chunk cursor, folded-panel widening, exact-size certificates, rank/select, broadword extraction, or cross-crate inline variants. The next memcmp attempt needs a generated codegen/disassembly-backed load/test primitive that changes the lowering materially, or the campaign should move to another focused, unowned residual from the next profile.
