# bd-2g7oyh.166 - memchr 512-byte wide-fold rejection

Status: rejected and restored.

## Target

- Bead: `bd-2g7oyh.166`
- Hotspot: `glibc_baseline_memchr_absent`
- Source attempted: `crates/frankenlibc-core/src/string/mem.rs`
- Lever: prepend the existing 256-byte folded `memchr` absent scan with a
  512-byte certificate made from eight 64-lane portable-SIMD panels.

The positive block resolver stayed ordered: resolve panels from low address to
high address and return the first set bit in the first matching panel.

## Baseline

Focused RCH baseline on `vmi1149989` before source edit:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memchr_absent --noplot --sample-size 50 \
  --warm-up-time 1 --measurement-time 3
```

- FrankenLibC: p50 `21.709 ns`, p95 `28.012 ns`, p99 `45.000 ns`,
  mean `23.658 ns`.
- Host glibc: p50 `20.035 ns`, p95 `25.969 ns`, p99 `70.000 ns`,
  mean `22.441 ns`.

## Behavior Proof

Focused proof command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_166_memchr_test \
  RUST_TEST_THREADS=1 cargo test -p frankenlibc-core memchr --lib -- \
  --nocapture --test-threads=1
```

RCH selected `vmi1227854`; result passed 11/11 focused tests, including:

- `string::mem::tests::memchr_golden_output_sha256`
- `string::mem::tests::prop_memchr_matches_scalar_position`
- `string::mem::tests::test_memchr_wide_folded_simd_block_resolves_first_match`

Local checks:

```bash
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
git diff --check -- crates/frankenlibc-core/src/string/mem.rs
```

Both passed.

Isomorphism ledger:

- Ordering preserved: yes; absent blocks are skipped only when every panel mask
  is empty, and positive blocks resolve panels in increasing address order.
- Tie-breaking preserved: yes; the first positive 64-lane panel returns its
  lowest set bit.
- Bounds preserved: yes; `n.min(haystack.len())` remains the only clipping rule.
- Empty input and NUL byte semantics preserved: yes, exercised through the
  existing scalar-position property and golden corpus.
- Floating point: N/A.
- RNG: N/A.
- Golden output: `memchr_golden_output_sha256` remained
  `04930b6afad5d9eb3047ad0fd21c4db13061e93ee506bcf740787790f8ae3500`.

## Post Benchmark

Focused same-worker RCH post on `vmi1149989`:

```bash
RCH_WORKER=vmi1149989 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memchr_absent --noplot --sample-size 50 \
  --warm-up-time 1 --measurement-time 3
```

- FrankenLibC: p50 `27.160 ns`, p95 `64.797 ns`, p99 `91.188 ns`,
  mean `33.552 ns`.
- Host glibc: p50 `22.322 ns`, p95 `26.699 ns`, p99 `70.000 ns`,
  mean `23.759 ns`.

Same-worker target row regressed:

- p50: `21.709 ns -> 27.160 ns`
- mean: `23.658 ns -> 33.552 ns`

## Verdict

Rejected and restored. Score `(Impact 1 * Confidence 1) / Effort 2 = 0.5`.

The wider portable-SIMD certificate increased instruction/register pressure more
than it reduced loop overhead on the profiled 4096-byte absent scan. Do not retry
this as another wider folded-panel variant. If `memchr_absent` remains a
profile-backed gap after the next reprofile, the next distinct primitive should
be a lower-register-pressure SWAR/word-group certificate or a shuffle-based
byte-mask resolver, not a larger SIMD block.
