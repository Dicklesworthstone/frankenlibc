# bd-2g7oyh.301 powf/log2f range-split rejection

## Target

- Bead: `bd-2g7oyh.301`
- Pass: 30
- Target row: `glibc_baseline_math/powf_irrational`
- Candidate root: exact `powf(x, 1.337)` lane inside the existing positive finite medium-domain fast path.

The fresh routing scan selected `powf_irrational` as the strongest current math
residual, with `log2f` as the likely root component. A focused same-worker
baseline on `vmi1227854` reproduced a smaller but real gap before any edit:

```text
powf_irrational frankenlibc_core p50 441.000 ns mean 458.797 ns
powf_irrational host_glibc        p50 424.256 ns mean 436.291 ns

log2f           frankenlibc_core p50 325.055 ns mean 327.627 ns
log2f           host_glibc        p50 307.862 ns mean 312.334 ns
```

Because RCH later admitted proof/benchmark work on `ovh-a`, a clean detached
`HEAD` comparison worktree under `/data/projects/frankenlibc-bd301-clean-baseline`
was used for the final same-worker baseline.

## Candidate

One lever only: replace the exact-exponent global degree-12 f64 Horner
polynomial for `powf(x, 1.337)` with a 16-segment degree-4 local polynomial over
`[0.5, 2.5)`, using local `t in [-1, 1]`.

No other base/exponent paths changed. Integer exponents, half-integers,
special values, out-of-range inputs, and the generic `libm::powf` fallback kept
their existing ordering.

Offline screen against host `powf` over dense plus deterministic random samples
reported worst error `1 ULP`, so the lever was behavior-plausible and worth a
remote proof/bench gate.

## Proof

Core ULP proof on RCH `ovh-a`:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_BUILD_SLOTS=1 rch exec -- \
  env AGENT_NAME=BoldFalcon RUST_TEST_THREADS=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd301-core-lib-proof-20260609d \
  cargo test -j 1 -p frankenlibc-core --lib \
  powf_profile_exp_1_337_poly_within_4_ulps -- --nocapture --test-threads=1
```

Result:

```text
test math::float32::tests::powf_profile_exp_1_337_poly_within_4_ulps ... powf 1.337 polynomial worst ULP = 1 at base 0.5
ok
```

ABI differential proof on RCH `ovh-a`:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_BUILD_SLOTS=1 rch exec -- \
  env AGENT_NAME=BoldFalcon RUST_TEST_THREADS=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd301-abi-proof-20260609 \
  cargo test -j 1 -p frankenlibc-abi --test conformance_diff_math \
  diff_powf_profile_exp_1_337_within_4_ulps -- --nocapture --test-threads=1
```

Result:

```text
test diff_powf_profile_exp_1_337_within_4_ulps ... ok
```

Golden fixture SHA256 stayed unchanged; no fixture was edited:

```text
4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35  tests/conformance/fixtures/math_ops.json
269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f  tests/conformance/fixtures/math_finite_special_wave02.json
acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491  tests/conformance/fixtures/math_finite_special_wave03.json
```

Isomorphism notes:

- Ordering/tie-breaking: scalar math function; not applicable.
- Floating point: only exact exponent bits `0x3fab_22d1` inside the existing
  finite positive `[0.5, 2.5)` gate changed; proof bounded this lane to
  `<= 4 ULP` versus host glibc and core reference sweeps.
- Fallback preservation: every non-gated exponent and out-of-domain base kept
  the previous route.
- RNG: production path has no RNG; proof sweeps use deterministic test-local
  pseudo-random samples.

## Benchmark

Same-worker clean-HEAD baseline on RCH `ovh-a`:

```text
powf_irrational frankenlibc_core p50 442.733 ns p95 471.360 ns p99 573.341 ns mean 450.326 ns
powf_irrational host_glibc        p50 334.986 ns p95 364.760 ns p99 411.000 ns mean 338.860 ns

log2f           frankenlibc_core p50 306.513 ns p95 323.352 ns p99 356.000 ns mean 309.104 ns
log2f           host_glibc        p50 286.827 ns p95 314.412 ns p99 320.500 ns mean 289.745 ns
```

Patched post on the same RCH worker `ovh-a`:

```text
powf_irrational frankenlibc_core p50 567.779 ns p95 932.000 ns p99 951.345 ns mean 677.792 ns
powf_irrational host_glibc        p50 337.285 ns p95 385.963 ns p99 420.000 ns mean 342.570 ns

log2f           frankenlibc_core p50 299.309 ns p95 408.250 ns p99 446.000 ns mean 326.794 ns
log2f           host_glibc        p50 282.952 ns p95 310.266 ns p99 371.000 ns mean 288.084 ns
```

The candidate regressed the target row:

- p50: `442.733 -> 567.779 ns` (`28.2%` slower)
- mean: `450.326 -> 677.792 ns` (`50.5%` slower)
- p95: `471.360 -> 932.000 ns` (`97.7%` slower)

## Verdict

Rejected and restored. Score `0.0`: negative impact, high confidence, low
effort. `git diff --exit-code -- crates/frankenlibc-core/src/math/float32.rs`
passed after restoration, and touched-file rustfmt passed.

Do not retry this 16-segment degree-4 local polynomial family for
`powf(x, 1.337)`. The next powf/log2f attack should replace the root primitive:
a true f32 log2 range-reduction artifact, table-driven `2^r` reconstruction, or
an Estrin/Remez kernel with codegen proof that removes the libm-classifier cost
without adding indirect table latency.
