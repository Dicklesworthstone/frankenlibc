# bd-2g7oyh.157 - memmove inline hint rejection

Verdict: rejected and restored. The one-line source candidate regressed the
same-worker focused benchmark, so no source change is retained.

## Target

Profile-backed target from the broad RCH glibc-baseline run on `vmi1227854`:

- `memmove_4096` FrankenLibC p50 `31.375 ns/op`, mean `35.787`
- `memmove_4096` host glibc p50 `28.728 ns/op`, mean `34.478`

The follow-up focused same-worker lane selected `ts2` and showed that `memcpy`
was not an actionable gap on that worker, while `memmove` still was:

```text
Command:
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env \
  FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-157-copy-baseline \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench \
  'glibc_baseline_memcpy_4096|glibc_baseline_memmove_4096' -- \
  --sample-size 30 --measurement-time 2 --warm-up-time 1 --noplot

Worker: ts2

memcpy_4096 FrankenLibC: p50 53.674 ns/op, p95 56.250, p99 75.500, mean 56.539
memcpy_4096 host glibc:  p50 53.159 ns/op, p95 69.685, p99 80.500, mean 56.732

memmove_4096 FrankenLibC: p50 59.188 ns/op, p95 61.386, p99 80.000, mean 61.808
memmove_4096 host glibc:  p50 50.376 ns/op, p95 56.726, p99 70.000, mean 53.399
```

## Candidate Lever

One lever only:

- add `#[inline(always)]` to `frankenlibc_core::string::mem::memmove`

This did not repeat the previously rejected `memcpy` exact full-slice branch
(`bd-2g7oyh.44`) and did not touch `memcpy`, `memset`, `memchr`, or the bench
harness.

## Behavior Proof

Isomorphism:

- Only an inlining attribute changed; the executed Rust expression tree stays
  `count = min(n, dest.len(), src.len())`, then
  `dest[..count].copy_from_slice(&src[..count])`, then `count`.
- Copied byte prefix, returned length, and untouched tail behavior are
  identical for every input accepted by the safe-slice API.
- Ordering and tie-breaking are not involved; `memmove` performs no comparison.
- Floating-point, RNG, errno, allocation, and ABI-visible state are unaffected.

RCH proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env \
  RUST_TEST_THREADS=1 FRANKENLIBC_PROPTEST_CASES=256 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-157-memmove-proof \
  cargo test -p frankenlibc-core string::mem::tests:: --lib -- \
  --test-threads=1 --nocapture

Worker: ts2
Result: passed, 50 passed / 1 ignored
Includes: memchr_golden_output_sha256, memmem_golden_output_sha256
```

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env \
  RUST_TEST_THREADS=1 FRANKENLIBC_PROPTEST_CASES=256 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-157-memmove-prop \
  cargo test -p frankenlibc-core --test property_tests \
  prop_memmove_with_overlap -- --test-threads=1 --nocapture

Worker: ts2
Result: passed, 1 passed
```

Golden fixture hashes before and after the candidate were unchanged:

```text
94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4  tests/conformance/fixtures/string_memory_full.json
6bdd6fb00bff508d07eb985bdc7c258a1a10f8ea96de72cf7e392483e886c233  tests/conformance/fixtures/memcpy_strict.json
cb9f0236ec8460c90bca05cfb5e7077fcb9e174f5db741dc4c69d54e8ff853eb  tests/conformance/golden/fixture_verify_strict_hardened.v1.md
```

`rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`
passed locally.

## Re-Benchmark

```text
Command:
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env \
  FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-157-copy-post \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench \
  'glibc_baseline_memcpy_4096|glibc_baseline_memmove_4096' -- \
  --sample-size 30 --measurement-time 2 --warm-up-time 1 --noplot

Worker: ts2

memmove_4096 FrankenLibC post: p50 62.522 ns/op, p95 69.369, p99 85.000, mean 66.450
memmove_4096 host glibc post:  p50 53.409 ns/op, p95 56.568, p99 75.500, mean 56.755
```

Compared to the focused baseline:

```text
FrankenLibC memmove_4096 p50: 59.188 -> 62.522 ns/op
FrankenLibC memmove_4096 mean: 61.808 -> 66.450 ns/op
```

Collateral `memcpy_4096` also worsened on the same post run:

```text
FrankenLibC memcpy_4096 p50: 53.674 -> 63.403 ns/op
FrankenLibC memcpy_4096 mean: 56.539 -> 66.364 ns/op
```

## Decision

Rejected. Score after measurement: `0.0`. The candidate failed the
`Score >= 2.0` keep gate and `crates/frankenlibc-core/src/string/mem.rs` was
restored to a clean diff.

Next primitive: do not continue wrapper-hint or exact-slice micro-levers here.
If `memmove_4096` remains the selected target after re-profile, attack a
fundamentally different safe-Rust copy primitive: a cache-line/tile-aware
directional copy kernel with a proof-carrying overlap classifier at the ABI
boundary and a safe-slice non-overlap fast lane. Target ratio: `memmove_4096`
p50 at or below host p50 on the same worker (`<= 53 ns` on the current `ts2`
lane). If a higher-scored non-reserved bead appears, pivot to that profile row
first.
