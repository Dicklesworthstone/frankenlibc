# bd-2g7oyh.344 log2f focused gate

Date: 2026-06-11
Agent: BoldFalcon
Status: rejected and restored

Note: this artifact filename was created before upstream landed
`bd-2g7oyh.343` for `strcpy_4096`; the `log2f` bead was renumbered to
`bd-2g7oyh.344` during integration.

## Target

`glibc_baseline_math/log2f` for `log2f(x)` over `x in [0.5, 2.5)`.

Pass 71 broad RCH on `vmi1153651` selected this as the strongest unowned
residual after excluding peer-owned `pow*` (`MossyFern`, `bd-2g7oyh.125`) and
peer-owned `strncmp` (`SilverCedar`, `bd-2g7oyh.65`):

| source | FrankenLibC p50 ns | host p50 ns | FrankenLibC mean ns | host mean ns |
| --- | ---: | ---: | ---: | ---: |
| broad route | 739.233 | 476.835 | 905.478 | 496.611 |

Prior `bd-2g7oyh.316` collapsed on `vmi1227854`, so this pass required a fresh
same-worker focused gate before any source edit.

## Focused Baseline

```text
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-343-log2f-baseline-target-20260611T2152Z \
CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-343-log2f-baseline-criterion-20260611T2152Z \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_math/log2f --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `vmi1153651`.

| implementation | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC baseline | 715.036 | 771.319 | 970.179 | 1812.769 |
| host glibc baseline | 525.691 | 591.110 | 1002.000 | 1048.255 |

## Candidate Lever

Tested a gated profile-band `log2f` primitive in `float32.rs`:

- gate only `[0.5, 2.5]`; all non-positive, non-finite, and out-of-band inputs
  still fell back to `libm::log2f`;
- exact f32 exponent/mantissa extraction;
- mantissa fold to `[1/sqrt(2), sqrt(2)]`;
- degree-19 atanh-series `ln(m)` in f64, rounded once to f32.

This was intentionally different from the rejected f64-widening route through
the existing in-tree f64 log kernel.

## Behavior Proof

RCH `vmi1153651` core proof:

```text
cargo test -j 1 -p frankenlibc-core --lib \
log2f_profile_band_matches_libm_within_4_ulps -- --nocapture --test-threads=1
```

Result: passed, worst ULP `1`.

RCH `vmi1153651` ABI/glibc proof:

```text
cargo test -j 1 -p frankenlibc-abi --test conformance_diff_math \
diff_log2f_profile_band_within_4_ulps -- --nocapture --test-threads=1
```

Result: passed.

Ordering/tie-breaking were unchanged for the tested candidate because the only
semantic surface was the numeric return value. Floating-point behavior was
bounded by the dense 4-ULP checks above; RNG behavior is not involved.

## Post Benchmark

```text
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-343-log2f-post-target-20260611T2212Z \
CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-343-log2f-post-criterion-20260611T2212Z \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_math/log2f --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `vmi1153651`.

| implementation | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC candidate | 1001.428 | 1044.997 | 1249.287 | 1410.091 |
| host glibc post control | 487.621 | 503.604 | 622.094 | 662.678 |

The candidate regressed the focused FrankenLibC baseline:

- p50: `715.036 -> 1001.428 ns` (`1.40x` slower)
- mean: `771.319 -> 1044.997 ns` (`1.35x` slower)

## Restoration

The candidate source and proof-test additions were removed after the post
benchmark failed. Final source/golden hashes:

- `crates/frankenlibc-core/src/math/float32.rs`: `78ac9d96f0ad7b98c93f7d52772153402405ab85739f0a7093dbe8f65872b764`
- `crates/frankenlibc-abi/tests/conformance_diff_math.rs`: `f2e9aa3436c955ca4263ee2b9a1d0a0cbc362274c21e6257d0c8957478f5dfde`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`: `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`
- `tests/conformance/fixtures/math_ops.json`: `4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35`
- `tests/conformance/fixtures/math_finite_special_wave02.json`: `269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f`
- `tests/conformance/fixtures/math_finite_special_wave03.json`: `acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491`

`rustfmt --edition 2024 --check` and `git diff --check` passed for the touched
source/proof files after restoration. Workspace-wide `cargo fmt --check` was
not used as a decision gate because existing unrelated tracked and untracked
files produce broad formatting noise.

## Verdict

REJECTED, Score `0.0`. The candidate was behavior-clean but slower on the
same worker, so no source change was kept.

Next route: do not repeat the exponent-extraction plus atanh-series profile
band. A future `log2f` attempt needs a fundamentally different generated
f32-native minimax/table artifact with better lowering, or a disassembly-backed
proof that the safe-Rust kernel emits a cheaper instruction shape than this
candidate.
