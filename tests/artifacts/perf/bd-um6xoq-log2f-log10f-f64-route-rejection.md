# bd-um6xoq: f32 log f64-intermediate route rejection

## Target

Profile-backed target: `glibc_baseline_math/log2f` and
`glibc_baseline_math/log10f`.

Bead: `bd-um6xoq`.

Claim/reservation:

- `bd-um6xoq` claimed by `BlackThrush`.
- Exclusive reservations were taken for
  `crates/frankenlibc-core/src/math/float32.rs` and
  `crates/frankenlibc-abi/tests/conformance_diff_math.rs`.

## Baseline

Focused RCH baseline on `ts2` from the shared tree before editing:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-um6xoq-logf-baseline cargo bench -p frankenlibc-bench --bench glibc_baseline_bench 'glibc_baseline_math/(log2f|log10f)' -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

| row | impl | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | --- | ---: | ---: | ---: | ---: |
| `log10f` | `frankenlibc_core` | 557.957 | 621.000 | 695.490 | 581.896 |
| `log10f` | `host_glibc` | 515.642 | 556.000 | 651.046 | 523.897 |
| `log2f` | `frankenlibc_core` | 527.123 | 660.527 | 751.500 | 548.637 |
| `log2f` | `host_glibc` | 492.521 | 515.604 | 557.534 | 495.937 |

Clean-HEAD baseline from detached worktree
`/data/projects/.scratch/frankenlibc-bd-um6xoq-baseline-20260605` on `ts2`:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-um6xoq-logf-baseline-old cargo bench -p frankenlibc-bench --bench glibc_baseline_bench 'glibc_baseline_math/(log2f|log10f)' -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

| row | impl | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | --- | ---: | ---: | ---: | ---: |
| `log10f` | `frankenlibc_core` | 559.189 | 601.209 | 626.000 | 564.106 |
| `log10f` | `host_glibc` | 525.253 | 555.216 | 601.704 | 532.181 |
| `log2f` | `frankenlibc_core` | 526.346 | 570.122 | 611.000 | 532.758 |
| `log2f` | `host_glibc` | 498.940 | 520.981 | 526.000 | 501.650 |

## Rejected Lever

Route normal positive f32 inputs through the already-proven f64 kernels:

```rust
log2f(x) = super::log2(x as f64) as f32
log10f(x) = super::log10(x as f64) as f32
```

Special values, non-positive values, subnormals, and exact powers of two for
`log2f` stayed on the old `libm::*f` fallback during the trial.

## Isomorphism Proof

The proof passed, but the lever was rejected on performance.

- Ordering/tie-breaking: not applicable.
- Floating-point contract: deterministic 4-ULP comparison to host glibc passed.
- RNG: deterministic xorshift seed only in proof tests; runtime RNG unchanged.
- Fallback bits: special/non-normal fallback cases preserved old `libm::*f` bits
  during the trial.
- Golden fixtures unchanged:
  - `tests/conformance/fixtures/math_ops.json`
    `4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35`
  - `tests/conformance/fixtures/math_finite_special_wave02.json`
    `269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f`
  - `tests/conformance/fixtures/math_finite_special_wave03.json`
    `acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491`

Proof commands:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-um6xoq-tests cargo test -p frankenlibc-core --lib log2f_log10f -- --nocapture --test-threads=1
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-um6xoq-abi-logf cargo test -p frankenlibc-abi --test conformance_diff_math diff_log2f_log10f_within_4_ulps -- --nocapture --test-threads=1
```

Results:

- Core proof passed 2/2 on `ts2`; worst observed ULP was `log2f=1`,
  `log10f=0`.
- ABI proof passed 1/1 against host glibc on `ts1`.
- `rustfmt --edition 2024 --check` and `git diff --check` passed for both
  edited files during the trial.

## Post Benchmark

Cross-worker post runs on `ts1` were treated as signal only because the
baseline was on `ts2`.

Same-worker `ts2` confirmation:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-um6xoq-logf-post-confirm cargo bench -p frankenlibc-bench --bench glibc_baseline_bench 'glibc_baseline_math/(log2f|log10f)' -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

| row | impl | pre p50 | post p50 | pre mean | post mean | verdict |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `log10f` | `frankenlibc_core` | 559.189 | 751.153 | 564.106 | 766.042 | rejected |
| `log2f` | `frankenlibc_core` | 526.346 | 802.082 | 532.758 | 803.953 | rejected |
| `log10f` | `host_glibc` | 525.253 | 515.645 | 532.181 | 519.121 | noise check |
| `log2f` | `host_glibc` | 498.940 | 493.566 | 501.650 | 496.142 | noise check |

Score: `(Impact 0 * Confidence 5) / Effort 1 = 0`, below the keep gate.

The source and ABI test edits were restored. Post-restore hashes:

- `crates/frankenlibc-core/src/math/float32.rs`
  `17f68de0f8d65b1ec0328e67710c6cca6a58d8eb175454403091c75aa55e8ed7`
- `crates/frankenlibc-abi/tests/conformance_diff_math.rs`
  `9454fd73dca638cdbcb54f0899227e30fdbc23fc1fc52a649563b4fb12db6678`

## Next Primitive

Do not retry the f64-intermediate route for f32 logs. The f64 call/rounding
path is too expensive for these batch rows even though it is accurate.

Next attack for `bd-um6xoq`: a true f32-specialized kernel family, either:

- table-driven f32 `log2f` / `log10f` with mantissa range reduction and a
  minimax polynomial that rounds within 4 ULP, or
- cancellation-aware `tanhf` / `expm1f` kernels that avoid the known `expf`
  cancellation amplification near zero.

Target ratio: at least `1.25x` faster than current FrankenLibC on the selected
row while staying within the 4-ULP glibc contract.
