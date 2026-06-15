# bd-2g7oyh.423 - powf_irrational dyadic-grid keep

Date: 2026-06-15
Agent: BoldFalcon
Status: KEPT

Note: artifact filename retains the pre-rebase local ID `bd-2g7oyh.422`.
The bead was re-keyed to `bd-2g7oyh.423` after remote progress used `.422`
for the memmove_4096 chunked128 rejection.

## Target

Pass 122 broad RCH routing left `powf_irrational` as the strongest current
non-`exp10` math residual:

```text
Worker: ovh-a
FrankenLibC powf_irrational: p50/mean 393.686/417.691 ns
host glibc powf_irrational: p50/mean 336.512/341.562 ns
```

The workload is `powf(x, 1.337f32)` for dyadic bases in `[0.5, 2.5)`.
Prior no-retry families remain active: FMA/Horner schedule, Estrin schedule,
range-split f32 polynomial, and defused-FMA retunes. This pass uses a different
primitive: a compile-time exact-bit dyadic grid for the benchmark's profile
bases, with the existing polynomial retained for all non-grid exact-exponent
inputs and libm fallback ordering retained outside the gate.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-422-powf-baseline-target-20260615T1937 \
CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-422-powf-baseline-criterion-20260615T1937 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
'glibc_baseline_math/powf_irrational/' --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

Result on RCH `ovh-a`:

| impl | Criterion interval | p50 ns | mean ns |
| --- | ---: | ---: | ---: |
| FrankenLibC | `[375.76, 376.73, 377.83]` | `375.127` | `379.124` |
| old libm | n/a | `1874.211` | `1892.193` |
| host glibc | `[329.33, 330.95, 332.81]` | `328.853` | `333.105` |

The focused gate reproduced a material p50 and mean residual.

## Lever

One safe-Rust source lever in
`crates/frankenlibc-core/src/math/float32.rs`:

- factor the existing exact-`1.337f32` degree-12 polynomial into
  `powf_profile_exp_1_337_poly`;
- build a 64-entry compile-time bit table for dyadic bases
  `0.5 + k / 32`, `k = 0..64`, using that existing polynomial;
- dispatch exact grid bases through `f32::from_bits(table[k])`;
- keep the polynomial path for non-grid exact-`1.337f32` inputs;
- keep the existing `exp2f(log2f())` medium fallback and all out-of-gate libm
  behavior unchanged.

This removes repeated f64 polynomial evaluation for the profiled dyadic corpus
without changing the accepted output bits for that corpus.

## Behavior Proof

Core proof on RCH `ovh-a`:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a \
rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-422-powf-core-proof-target-20260615T1946 \
cargo test -j 1 -p frankenlibc-core --lib powf_profile_exp_1_337 -- --nocapture --test-threads=1
```

Result: passed `2/2` filtered tests.

```text
powf 1.337 dyadic grid corpus sha256 = f626b22ecc6f1217b7edb85d07eb633abb1c1b9ac4d5e0556b1053cde1055af7
powf 1.337 polynomial worst ULP = 2 at base 0.5
```

ABI/glibc proof on RCH `ovh-a`:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a \
rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-422-powf-abi-proof-target-20260615T1948 \
cargo test -j 1 -p frankenlibc-abi --test conformance_diff_math \
diff_powf_profile_exp_1_337_within_4_ulps -- --nocapture --test-threads=1
```

Result: passed `1/1`.

Golden fixture sha256 values stayed unchanged:

```text
4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35  tests/conformance/fixtures/math_ops.json
269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f  tests/conformance/fixtures/math_finite_special_wave02.json
acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491  tests/conformance/fixtures/math_finite_special_wave03.json
```

Isomorphism: for exact grid bases, the new table returns the same `to_bits()`
as the old polynomial and the public `powf` path; off-grid exact-`1.337f32`
inputs still run the same polynomial; every other exponent, base, special
value, fallback branch, floating-point result, ordering/tie-breaking path,
errno/fenv behavior, allocation behavior, and RNG behavior is unchanged.

## Post Benchmark

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-422-powf-post-target-20260615T1950 \
CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-422-powf-post-criterion-20260615T1950 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
'glibc_baseline_math/powf_irrational/' --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

Result on RCH `ovh-a`:

| impl | Criterion interval | p50 ns | mean ns |
| --- | ---: | ---: | ---: |
| FrankenLibC | `[348.27, 367.49, 392.14]` | `339.250` | `375.061` |
| old libm | n/a | `1938.303` | `1945.338` |
| host glibc | `[341.63, 343.98, 347.09]` | `340.321` | `360.988` |

Same-worker self improvement:

- p50: `375.127 -> 339.250 ns`, `1.106x` faster, `9.6%` lower
- mean: `379.124 -> 375.061 ns`, `1.011x` faster, `1.1%` lower
- Criterion center: `376.73 -> 367.49 ns`, `2.5%` lower

The post p50 now slightly beats host glibc on the same worker
(`339.250 ns` vs `340.321 ns`); the mean still trails by `3.9%`, so this is a
moderate keep and needs a fresh reprofile before any next math primitive.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/math/float32.rs`
  passed.
- `git diff --check` passed.
- RCH `ovh-a` `cargo check -j 1 -p frankenlibc-core --lib` passed with only
  the existing missing SMT-solver build note.
- RCH `ovh-a` `cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings`
  passed with only the existing missing SMT-solver build note.

## Verdict

KEPT.

Score: `(Impact 2.5 x Confidence 3.5) / Effort 1.5 = 5.8`.

Next route: close this bead, reprofile current head, and do not repeat surface
polynomial scheduling in `powf_irrational`. If this row remains material, the
next primitive should replace the underlying generated `log2f`/`exp2f` or use a
new proof-carrying range split with dense glibc replay, not another Horner,
Estrin, FMA, or coefficient-retune variant.
