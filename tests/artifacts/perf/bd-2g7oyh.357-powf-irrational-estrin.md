# bd-2g7oyh.357 powf irrational Estrin schedule

## Target

- Bead: `bd-2g7oyh.357`
- Workload: `glibc_baseline_math/powf_irrational`
- Symbol: `powf(x, 1.337)` over `x in [0.5, 2.5)`
- Worker: RCH `ovh-a`
- Lever: keep the accepted degree-12 f64 polynomial and exact exponent gate, but evaluate it with an Estrin tree instead of a serial Horner chain.

## Baseline

Command:

```bash
RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass76-powf-baseline-target-20260612T2244 \
  CRITERION_HOME=/data/tmp/frankenlibc-pass76-powf-baseline-criterion-20260612T2244 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_math/powf_irrational --noplot --sample-size 50 \
  --warm-up-time 1 --measurement-time 3
```

Results:

| impl | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC current | 433.938 | 439.484 | 452.750 | 481.000 |
| old libm | 1878.891 | 1883.592 | n/a | n/a |
| host glibc | 326.785 | 333.560 | 351.387 | 401.000 |

## Behavior proof

Command:

```bash
RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass76-powf-proof-target-20260612T2248 \
  cargo test -j 1 -p frankenlibc-core --lib \
  powf_profile_exp_1_337_poly_within_4_ulps -- --nocapture --test-threads=1
```

Result: passed. The dense proof sweep reported `powf 1.337 polynomial worst ULP = 2 at base 0.5`. The lever preserves the same input gate, coefficient table, fallback route, FP special-case ordering, and no RNG state exists. It only changes the dependency tree used to evaluate the same polynomial.

Golden math fixture SHA-256 values remain unchanged:

| fixture | sha256 |
| --- | --- |
| `tests/conformance/fixtures/math_ops.json` | `4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35` |
| `tests/conformance/fixtures/math_finite_special_wave02.json` | `269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f` |
| `tests/conformance/fixtures/math_finite_special_wave03.json` | `acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491` |

## Post-benchmark

Command:

```bash
RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass76-powf-post-target-20260612T2250 \
  CRITERION_HOME=/data/tmp/frankenlibc-pass76-powf-post-criterion-20260612T2250 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_math/powf_irrational --noplot --sample-size 50 \
  --warm-up-time 1 --measurement-time 3
```

Results:

| impl | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC candidate | 344.789 | 365.924 | 547.250 | 601.000 |
| old libm | 1881.066 | 1882.207 | 1910.239 | 2000.316 |
| host glibc | 329.354 | 333.136 | 348.250 | 361.000 |

Same-worker delta against baseline:

- FrankenLibC p50: `433.938 ns -> 344.789 ns` (`20.5%` faster)
- FrankenLibC mean: `439.484 ns -> 365.924 ns` (`16.7%` faster)
- p50 gap to host: `107.153 ns -> 15.435 ns`

## Validation

- Local `rustfmt --edition 2024 --check crates/frankenlibc-core/src/math/float32.rs`: passed.
- Local `git diff --check`: passed.
- RCH `ovh-a` `cargo check -j 1 -p frankenlibc-core --lib`: passed.
- RCH `ovh-a` strict `cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings`: blocked by unrelated existing lint debt in `math/exp.rs`, `stdlib/sort.rs`, `string/fnmatch.rs`, and `string/regex.rs`.
- RCH `ovh-a` allowlisted `cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings -A clippy::excessive_precision -A clippy::collapsible_if -A clippy::manual_contains -A clippy::type_complexity -A clippy::unnecessary_map_or`: passed.

## Verdict

KEPT. Score: `9.0` (Impact 3 x Confidence 3 / Effort 1). The lever preserves the accepted safe-Rust root primitive and removes most of the serial FMA dependency depth that the focused profile exposed.
