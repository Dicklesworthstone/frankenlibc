# bd-2g7oyh.272 - powf_irrational FMA polynomial evaluation

Date: 2026-06-08
Agent: BoldFalcon
Target bead: `bd-2g7oyh.272`
Profile row: `glibc_baseline_math/powf_irrational`

## Target

Fresh profile showed `powf(x, 1.337)` remained slower than host glibc after the
existing exact-exponent polynomial fast path:

- RCH `vmi1156319` broad profile: FrankenLibC p50 `1484.172 ns/op`, mean
  `1511.605 ns/op`; host glibc p50 `912.490 ns/op`, mean `935.244 ns/op`.

Prior f32 log-widening work was rejected, so this pass stayed on the existing
exact-exponent polynomial and changed only the evaluation primitive.

## Lever

In `crates/frankenlibc-core/src/math/float32.rs`, the exact
`powf(x, 1.337)` polynomial branch now evaluates the existing degree-12
Horner chain with `f64::mul_add` instead of separate multiply/add operations.

No coefficients, range checks, exponent-bit checks, fallback paths, ordering
rules, or RNG state were changed.

## Same-worker RCH A/B

Command shape:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1264463 \
  rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-boldfalcon-powf-fma-<side> \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'powf_irrational' --sample-size 30 --measurement-time 3 --warm-up-time 1 --noplot
```

Worker: `vmi1264463`

| Side | Impl | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | --- | ---: | ---: | ---: | ---: |
| baseline | frankenlibc_core | 1658.851 | 1940.542 | 3959.826 | 5561.725 |
| candidate | frankenlibc_core | 1360.692 | 1516.800 | 2507.296 | 3015.832 |
| baseline | host_glibc | 1020.126 | 5036.598 | 30431.493 | 115490.344 |
| candidate | host_glibc | 1037.187 | 1459.280 | 2647.298 | 11929.402 |

FrankenLibC delta:

- p50: `1658.851 -> 1360.692 ns/op`, `17.97%` faster.
- mean: `1940.542 -> 1516.800 ns/op`, `21.84%` faster.
- Host rows were noisy in the tail, but the FrankenLibC p50 and mean improved
  in the same-worker pair.

## Behavior Proof

Core polynomial envelope:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1264463 \
  rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-boldfalcon-powf-fma-proof-core \
  cargo test -p frankenlibc-core powf_profile_exp_1_337_poly_within_4_ulps -- --nocapture --test-threads=1
```

Result:

- Passed on RCH `vmi1264463`.
- `powf 1.337 polynomial worst ULP = 2 at base 0.5`.

ABI differential path:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1264463 \
  rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-boldfalcon-powf-fma-proof-abi \
  cargo test -p frankenlibc-abi --test conformance_diff_math \
  diff_powf_profile_exp_1_337_within_4_ulps -- --nocapture --test-threads=1
```

Result:

- Passed on RCH `vmi1264463`.
- `diff_powf_profile_exp_1_337_within_4_ulps ... ok`.

Fixture SHA-256:

```text
4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35  tests/conformance/fixtures/math_ops.json
269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f  tests/conformance/fixtures/math_finite_special_wave02.json
acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491  tests/conformance/fixtures/math_finite_special_wave03.json
```

Isomorphism notes:

- Exponent dispatch is unchanged: only `exponent.to_bits() ==
  POWF_PROFILE_EXP_1_337_BITS` takes this branch.
- Base dispatch is unchanged: only finite positive bases in `[0.5, 2.5)` take
  this branch.
- Horner coefficient order is unchanged.
- `mul_add` changes the rounding primitive to single-round fused multiply-add;
  the existing glibc differential envelope remains satisfied with worst ULP 2.
- Floating-point fallback, NaN/inf/zero/negative handling, integer-exponent
  handling, ordering, tie-breaking, and RNG state are unchanged or not
  applicable.

## Score

Impact `3.0` x Confidence `3.0` / Effort `1.0` = `9.0`.

Verdict: KEPT.

Next route: reprofile math rows after closeout. If `powf_irrational` remains
top, use a different algorithmic primitive such as a true f32-specialized
minimax/Estrin route or a range-split table polynomial, not another scalar
Horner micro-tweak.
