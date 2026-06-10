# bd-2g7oyh.316 - log2f focused gate

Date: 2026-06-10
Agent: BoldFalcon
Status: no-code rejected

## Target

`log2f(x)` for the profiled math workload `x in [0.5, 2.5)`.

The target came from the broad RCH sweep after `bd-2g7oyh.315`, where
`log2f` appeared as a residual:

- FrankenLibC: p50 `414.740 ns`, mean `410.591 ns`
- host glibc: p50 `322.736 ns`, mean `329.229 ns`
- worker: `vmi1227854`

The existing implementation is:

```rust
pub fn log2f(x: f32) -> f32 {
    libm::log2f(x)
}
```

`float32.rs` already documents a rejected f64-widening route through the
in-tree `log2` kernel, so the next viable source lever would need to be a
different safe-Rust f32 primitive with dense glibc ULP proof.

## Focused Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN' \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-316-log2f-baseline-target-20260610T055936Z \
CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-316-log2f-baseline-criterion-20260610T055936Z \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_math/log2f --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH selected worker `vmi1227854`.

Criterion summary:

| implementation | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 326.298 | 337.853 | 387.731 | 396.396 |
| host glibc | 332.818 | 338.344 | 352.282 | 377.121 |

Criterion confidence interval:

- FrankenLibC: `[350.44 ns, 362.34 ns, 371.40 ns]`
- host glibc: `[327.24 ns, 332.61 ns, 338.91 ns]`

## Behavior Proof

No source files were edited. Ordering, tie-breaking, floating-point behavior,
and RNG behavior are unchanged by construction.

Fixture hashes:

- `tests/conformance/fixtures/math_ops.json`: `4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35`
- `tests/conformance/fixtures/math_finite_special_wave02.json`: `269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f`
- `tests/conformance/fixtures/math_finite_special_wave03.json`: `acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491`

## Verdict

Rejected with no code change. The focused same-worker gate showed FrankenLibC
already slightly faster by p50 and effectively tied by mean:

- p50 ratio: `0.98x` (`326.298 / 332.818`)
- mean ratio: `1.00x` (`337.853 / 338.344`)

Score: `0.0`.

No `log2f` source lever should be attempted from this broad-sweep evidence.
If `log2f` reappears with a material focused same-worker gap, the next route is
a true f32 reduced-domain/minimax artifact with dense 4-ULP glibc differential
coverage, not the already-rejected f64-widening path.
