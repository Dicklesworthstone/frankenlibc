# bd-2g7oyh.167 memchr_absent SWAR word-group rejection

## Target

- Bead: `bd-2g7oyh.167`
- Hotspot: `glibc_baseline_memchr_absent`
- Scope: `crates/frankenlibc-core/src/string/mem.rs`
- Constraint: one lever, safe Rust, crate-scoped RCH only, no peer-owned `str.rs` or `math/exp.rs` work.

## Profile-Backed Baseline

Broad reprofile on `ts1` showed `memchr_absent` as the strongest unowned string/memory residual:

- FrankenLibC: p50 `32.289 ns/op`, mean `33.780 ns/op`
- host glibc: p50 `20.971 ns/op`, mean `22.765 ns/op`

Focused same-worker baseline before editing:

```text
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memchr_absent --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

- FrankenLibC: p50 `25.050 ns/op`, p95 `40.500`, p99 `54.104`, mean `28.275`
- host glibc: p50 `22.480 ns/op`, p95 `28.378`, p99 `35.000`, mean `24.353`

## Lever Attempted

Replaced the 256-byte folded portable-SIMD absent scan with a 64-byte SWAR word-group scan:

- eight `u64` words per group
- `((x - 0x01..) & !x & 0x80..)` byte-lane marker detection
- endian-aware first-marker resolution
- exact low-to-high first-match resolution before the SIMD and byte tails

This was a fundamentally different primitive from the previous wider folded SIMD rejection: word-lane SWAR marker extraction instead of widening the SIMD fold.

## Behavior Proof

RCH proof command:

```text
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_167_memchr_test \
  RUST_TEST_THREADS=1 cargo test -p frankenlibc-core memchr --lib -- \
  --nocapture --test-threads=1
```

Result: passed `10/10` filtered tests:

- `memchr_golden_output_sha256`
- `prop_memchr_matches_scalar_position`
- `glibc_memchr_n_zero_returns_none`
- fixed found/not-found cases
- folded block first-match ordering case
- wmemchr parity cases

Golden output SHA-256 stayed:

```text
04930b6afad5d9eb3047ad0fd21c4db13061e93ee506bcf740787790f8ae3500
```

Isomorphism notes:

- Ordering/tie-breaking: preserved first occurrence by resolving candidate words low-to-high, then first byte lane in the matching word.
- Floating point: not applicable.
- RNG: not applicable.
- Error behavior: `n` is still clamped by `haystack.len()`; `n == 0` still returns `None`.

## Post-Benchmark

Same worker post-benchmark:

```text
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memchr_absent --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

- FrankenLibC post: p50 `222.668 ns/op`, p95 `276.745`, p99 `299.113`, mean `229.467`
- host glibc post: p50 `22.167 ns/op`, p95 `25.321`, p99 `40.000`, mean `23.671`

The lever regressed the target by `8.89x` p50 and `8.12x` mean relative to the focused baseline.

## Decision

- Score: `0.0` (`Impact` negative, `Confidence` high, `Effort` moderate)
- Source: restored to the prior folded-SIMD implementation
- Status: rejected/restored

Next primitive: do not retry a per-word `chunks_exact(WORD)` inner loop. The next `memchr_absent` attack should be a mask-producing vector/shuffle primitive that extracts the first matching lane without scalar per-word iterator overhead, or route to another profile-evident unowned hotspot if ownership changes.
