# bd-2g7oyh.442 memcmp_256 array-equality lowering rejection

Date: 2026-06-16
Agent: BoldFalcon
Worker: vmi1227854
Commit under test: 7b6aae850

## Route

Pass 156 broad RCH routing on `vmi1227854` showed
`glibc_baseline_memcmp_256` as a remaining residual:

- FrankenLibC p50/mean: 4.840 / 8.566 ns
- host glibc p50/mean: 3.715 / 5.126 ns

Prior rejected families included exact-256 `u128` panels, folded-panel widening,
chunk cursor, rank/select, cross-crate inline, and scalar panel reshapes. The
only admissible source test was a materially different backend/compiler-lowering
primitive.

## Baseline

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=2400 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass159-memcmp256-target-baseline \
CRITERION_HOME=/data/tmp/frankenlibc-pass159-memcmp256-criterion-baseline \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
memcmp_256 --noplot --sample-size 100 --warm-up-time 1 --measurement-time 4
```

Focused baseline on `vmi1227854`:

- FrankenLibC Criterion interval: [4.3507 ns 4.4187 ns 4.4919 ns]
- FrankenLibC p50/mean: 4.373 / 5.271 ns
- host glibc Criterion interval: [3.2341 ns 3.3006 ns 3.3743 ns]
- host glibc p50/mean: 3.256 / 3.832 ns

Baseline log SHA256:

```text
cfe14a537b0261c8a20ce6e15595a39fe65eb6005145c9dd25ba876c3af0474e  /data/tmp/frankenlibc-pass159-memcmp256-baseline-vmi1227854.log
```

## Candidate

One lever tested and restored: replace the exact-256 four-panel portable-SIMD
equality certificate with a fixed `[u8; 256]` array equality certificate:

- equal exact-256 inputs could return `Ordering::Equal` through backend array
  equality lowering;
- every non-equal exact-256 input still fell through to the existing ordered
  resolver;
- non-256 sizes, exact-16, exact-4096, `n` clamping, zero-length behavior,
  unsigned byte ordering, and first-difference tie-breaking were unchanged.

This was a compiler-lowering primitive, not another native-word or SIMD panel
reshape.

## Behavior Proof

RCH proof on candidate source:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 \
FRANKENLIBC_PROPTEST_CASES=512 \
cargo test -j 1 -p frankenlibc-core --lib memcmp -- --nocapture --test-threads=1
```

Result: passed 32/32 filtered tests, including `memcmp_golden_output_sha256`,
antisymmetry, std-lexicographic properties, exact-256 guard, exact-4096 guard,
timingsafe memcmp, and wide memcmp tests. Existing unrelated warnings remained
in `iconv`.

Separate property golden:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 \
FRANKENLIBC_PROPTEST_CASES=512 \
cargo test -j 1 -p frankenlibc-core --test property_tests \
golden_memcmp_corpus_sha256 -- --nocapture --test-threads=1
```

Result: passed 1/1.

Golden hashes covered by those tests:

- `string::mem::tests::memcmp_golden_output_sha256`:
  `458c0ae019afaffccbfc5a6aacfeb4713dab611eac4b6257398016a7eae45ef9`
- `string_properties::golden_memcmp_corpus_sha256`:
  `23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e`

Hygiene:

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`
  passed.
- `git diff --check` passed.
- `cargo fmt --check -p frankenlibc-core` remains blocked by pre-existing
  unrelated formatting drift in generated/tabled and other core files; it did
  not report the touched `mem.rs` hunk.

## Post Benchmark

Same-worker post command used the same sample, warmup, and measurement settings
as the baseline.

Post result on `vmi1227854`:

- Candidate FrankenLibC Criterion interval: [5.6252 ns 5.7377 ns 5.8552 ns]
- Candidate FrankenLibC p50/mean: 6.250 / 7.207 ns
- host glibc Criterion interval: [3.3808 ns 3.4298 ns 3.4782 ns]
- host glibc p50/mean: 3.461 / 4.863 ns

Candidate delta vs baseline:

- p50: 4.373 -> 6.250 ns, 42.9% slower
- mean: 5.271 -> 7.207 ns, 36.7% slower

Post log SHA256:

```text
f6357d9a11ec34a21bc3e6b285bbc62a61aa194cb8b02c9baa92efb54899f2ea  /data/tmp/frankenlibc-pass159-memcmp256-post-vmi1227854.log
```

## Verdict

REJECTED-RESTORED. Score: 0.0.

The candidate preserved behavior but regressed the profiled row, so the source
was restored. Restored source proof:

```text
78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d  crates/frankenlibc-core/src/string/mem.rs
```

`git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs` passed after
restore.

## Reroute

Do not retry exact-256 array-equality lowering. Return to `memcmp_256` only with
a genuinely generated/backend-dispatch primitive or disassembly-backed lowering
that changes the equal-buffer path materially. Otherwise reprofile current head
and select a different focused residual.
