# bd-hn9q5g: memcmp u8x64 folded probe rejected

Date: 2026-06-05
Agent: BlackThrush
Target: `crates/frankenlibc-core/src/string/mem.rs`

## Profile-backed target

Bead `bd-hn9q5g` tracks the measured `memcmp` 256-byte equal-buffer gap.
Existing evidence: 128-byte folded scan narrowed the 256B gap; previous
8-panel folding and small-size branchless dispatch attempts were rejected.

## Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 \
  rch exec -- env FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-hn9q5g-memcmp256-baseline-ts2 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench \
  'glibc_baseline_memcmp_256' -- --sample-size 50 \
  --measurement-time 3 --warm-up-time 1 --noplot
```

Result on worker `ts2`:

- FrankenLibC `memcmp_256`: p50 `7.669 ns/op`, mean `10.024 ns/op`
- host glibc `memcmp_256`: p50 `5.015 ns/op`, mean `6.274 ns/op`

## One lever attempted

Replace the 128-byte equal-block mismatch probe from four `Simd<u8, 32>`
panels to two `Simd<u8, 64>` panels. The first-difference resolver stayed
unchanged: after a block mismatch, the existing 32-byte panel scan and
byte-order comparison still determine the returned ordering.

## Behavior proof

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 \
  rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-hn9q5g-memcmp-u8x64-test-ts2 \
  cargo test -p frankenlibc-core memcmp -- --nocapture --test-threads=1
```

Result: passed on `ts2`.

Coverage:

- 28 memcmp/timingsafe/wmemcmp tests passed.
- `small_memcmp_matches_scalar` passed.
- `prop_memcmp_is_antisymmetric` passed.
- `prop_memcmp_matches_std_lexicographic` passed.
- `golden_memcmp_corpus_sha256` passed.

Golden output SHA-256:

```text
golden_memcmp_corpus_sha256 = 23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e
```

Isomorphism notes:

- Ordering and tie-breaking are preserved because the lever only changes the
  coarse equal-block probe; the first differing byte is still found by the
  existing 32-byte panel resolver and byte-order comparison.
- No floating-point operations are involved.
- No RNG state is used by `memcmp`; the golden corpus generator is test-local
  deterministic input construction only.

## After benchmark

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 \
  rch exec -- env FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-hn9q5g-memcmp256-u8x64-post-ts2 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench \
  'glibc_baseline_memcmp_256' -- --sample-size 50 \
  --measurement-time 3 --warm-up-time 1 --noplot
```

Result on worker `ts2`:

- FrankenLibC `memcmp_256`: p50 `8.541 ns/op`, mean `11.124 ns/op`
- host glibc `memcmp_256`: p50 `6.036 ns/op`, mean `7.417 ns/op`

## Decision

Rejected. Same-worker p50 regressed `7.669 -> 8.541 ns/op` and mean regressed
`10.024 -> 11.124 ns/op`, so the lever scores below the keep threshold.
The source change was not kept.

Next primitive: stop widening the current portable-SIMD fold. Attack a
different memcmp kernel: a safe-Rust SWAR/word-mask first-difference primitive
that computes the first mismatching byte from packed equality masks, or a
generated size-dispatch kernel that avoids the current panel-resolution loop.
