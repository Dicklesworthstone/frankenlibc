# bd-2g7oyh.297 erf/erfc special-function residual

Status: rejected and restored.
Date: 2026-06-09.
Agent: BoldFalcon.
Base commit: `2653adf255960a44d88648a2c3a3775bff6d5691`.

## Target

Broad profile selected the double special-function residual:

- `glibc_baseline_math/erf`
- `glibc_baseline_math/erfc`

The focused target uses Criterion through RCH:

```text
cargo bench -j 2 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/erf --noplot --sample-size 60 --warm-up-time 1 --measurement-time 4
```

## Baseline

First clean baseline on `vmi1227854` reproduced a gap, but was not used for
scoring because the candidate was subsequently routed to `ovh-a`:

- `erf` FrankenLibC p50 977.860 ns/op, mean 1003.169 ns/op; host p50 863.495 ns/op, mean 833.221 ns/op.
- `erfc` FrankenLibC p50 923.359 ns/op, mean 1052.788 ns/op; host p50 682.241 ns/op, mean 689.145 ns/op.

Two attempted candidate runs on `ovh-a` were canceled before scoring because
they did not match the first worker:

- job `29879662679164448`
- job `29879662679164451`

Comparable clean baseline on `ovh-a`:

- `erf` FrankenLibC p50 835.438 ns/op, mean 837.550 ns/op; host p50 669.358 ns/op, mean 677.190 ns/op.
- `erfc` FrankenLibC p50 832.054 ns/op, mean 836.921 ns/op; host p50 667.443 ns/op, mean 719.671 ns/op.

## Candidate

One lever tested: local hot-range nonnegative `erf`/`erfc` rational approximation
front end for `[0, 2.5]`, falling back to `libm` outside the profiled range.

Same-worker post on `ovh-a`:

- `erf` FrankenLibC p50 866.332 ns/op, mean 997.591 ns/op; host p50 673.969 ns/op, mean 699.845 ns/op.
- `erfc` FrankenLibC p50 814.070 ns/op, mean 819.621 ns/op; host p50 665.409 ns/op, mean 693.230 ns/op.

Decision:

- `erfc` mean improved 836.921 -> 819.621 ns/op, about 2.1%.
- `erf` mean regressed 837.550 -> 997.591 ns/op, about 19.1%, with high-severe outliers.
- Combined lever Score: 0.0. It does not clear Score >= 2.0 because one profiled symbol regressed.
- Source restored; no candidate source is kept.

## Behavior Proof

Final source identity:

```text
44e4292a21ed3c6743a36bf934e95ec8e5ddf96bc6aea856698d8db53da72e42  crates/frankenlibc-core/src/math/special.rs
44e4292a21ed3c6743a36bf934e95ec8e5ddf96bc6aea856698d8db53da72e42  HEAD:crates/frankenlibc-core/src/math/special.rs
```

RCH proof command:

```text
cargo test -j 2 -p frankenlibc-abi --test conformance_diff_math_special diff_erf_within_4_ulps -- --nocapture --test-threads=1
```

Result on `ovh-a`: passed, `1 passed; 0 failed`.

Golden fixture SHA256:

```text
4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35  tests/conformance/fixtures/math_ops.json
269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f  tests/conformance/fixtures/math_finite_special_wave02.json
acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491  tests/conformance/fixtures/math_finite_special_wave03.json
```

Isomorphism: no retained code change. Ordering, tie-breaking, floating-point
rounding, fenv behavior, and RNG behavior are identical to `HEAD` because the
final `special.rs` content hashes exactly match `HEAD`.

## Next Attack

The rejected micro-front-end means the next math attempt should not retune this
same copied range split. The deeper primitive to pursue is a clean-room minimax
or table-assisted approximation with proof-bounded ULP error and a separate
`erf`/`erfc` cost model, or reroute to the next profiler-backed non-owned gap if
focused baseline says this row is not the best current target.
