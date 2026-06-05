# bd-2g7oyh.158 - strspn four-byte stop-mask fusion

## Target

Profile-backed target: four-byte general set-membership scans in
`crates/frankenlibc-core/src/string/str.rs`.

Fresh same-worker baseline:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-reprofile-string \
  cargo bench -p frankenlibc-bench --bench string_bench -- \
  --sample-size 30 --warm-up-time 1 --measurement-time 3
worker: ts1
strspn_general_full_4096     p50=148.632 ns mean=186.073
strcspn_general_absent_4096  p50=111.244 ns mean=118.912
strpbrk_general_absent_4096  p50=108.406 ns mean=110.590
```

## Lever

Fuse the `strspn` four-byte accept-set panel stop predicate from two horizontal
reductions into one vector stop mask:

```rust
(lanes.simd_eq(Simd::splat(0)) | !member).any()
```

This is the only kept source change. An earlier paired change to the
`strcspn`/`strpbrk` any-of-four helper was restored after same-worker RCH
benchmarking showed a `strpbrk_general_absent_4096` p50 regression.

## Alien Primitive

Canonical source: `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md`
section 7.7, Swiss Tables SIMD group probes.

The adapted primitive is a packed byte-group membership probe: compare a
32-byte panel against the four accept bytes, OR in the NUL terminator mask, and
fall back to scalar left-to-right resolution only when the panel has any stop
candidate.

Score: Impact 4 x Confidence 4 / Effort 1 = 16.0.

## Isomorphism

Ordering is preserved because the SIMD helper only answers whether a 32-byte
panel contains any `strspn` stop candidate. The existing scalar loop in
`find_non_any_of4_or_nul` still computes the exact first byte where
`byte == 0 || !byte_is_any4(...)`.

Tie-breaking is unchanged: if a NUL and a nonmember both appear in the same
panel, the scalar resolver still returns whichever appears first. Byte equality
semantics are unchanged; there is no signedness, locale, collation, or
case-folding change. Floating-point and RNG are not used.

## Golden Proof

Golden sha256 values after the source change:

```text
c0dc51585d1c90b808389f7ba472b439901d81885c785022663035486ad48270  tests/conformance/golden/fixture_verify_strict_hardened.v1.json
ac15f07bd1053b7fe4123817ce5b7118abbd145ce15444c1de0071c2bad5358e  tests/conformance/fixtures/string_memory_hotpaths_wave05.json
d616551c8d09c974c7d1c54dbb8048c0fb9d3f7376c1cdf7219cc19bda033955  tests/conformance/string_memory_hotpaths_wave05_completion_contract.v1.json
db4b47e7ec1fb50a221a11b10b4b7352fff8ab88e6ec78ebcd341b2c6fef209b  tests/conformance/strspn_optimization_completion_contract.v1.json
```

Focused RCH behavior proof:

```text
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-158-proof-final \
  cargo test -p frankenlibc-core set_simd -- --nocapture --test-threads=1
result: pass, 6/6 set-simd tests
```

## Post-Benchmark

Final same-worker gated run after restoring the rejected `strpbrk` half:

```text
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-158-post-final \
  cargo bench -p frankenlibc-bench --bench string_bench -- \
  'strspn_general_full|strcspn_general_absent|strpbrk_general_absent' \
  --sample-size 30 --warm-up-time 1 --measurement-time 3 --noplot
worker: ts1
```

| Bench | Baseline p50 ns/op | Post p50 ns/op | Baseline mean ns/op | Post mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `strspn_general_full_4096` | 148.632 | 107.199 | 186.073 | 108.873 |
| `strspn_general_full_1024` | 39.884 | 32.202 | 42.920 | 36.149 |
| `strcspn_general_absent_4096` | 111.244 | 106.429 | 118.912 | 109.189 |
| `strpbrk_general_absent_4096` | 108.406 | 106.823 | 110.590 | 110.697 |

Primary target result: `strspn_general_full_4096` p50 improved 1.39x and mean
improved 1.71x on the same worker.

Gate decision: kept.

## Validation

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs
result: pass

git diff --check -- crates/frankenlibc-core/src/string/str.rs
result: pass

RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-158-check \
  cargo check -p frankenlibc-core --all-targets
result: pass

RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-158-clippy \
  cargo clippy -p frankenlibc-core --all-targets -- -D warnings
result: pass
```
