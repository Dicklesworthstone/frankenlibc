# bd-um6xoq - rejected f32 log f64-route

## Target

Profile-backed target: f32 `log2f` and `log10f` rows in
`glibc_baseline_math`, measured after `7629eb05`.

Clean-HEAD baseline came from detached worktree
`/data/projects/.scratch/frankenlibc-bd-um6xoq-baseline-7629eb05-119839` so
the pre-lever code was measured without reverting the shared dirty tree.

```text
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-um6xoq-baseline-target \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'log2f|log10f|powf_irrational|tanhf|expm1f|sinhf|coshf' \
  --sample-size 30 --warm-up-time 1 --measurement-time 3 --noplot
worker: ts1
```

| Bench | Franken p50 ns/op | Franken mean ns/op | Host p50 ns/op | Host mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `log2f` | 327.808 | 348.326 | 318.722 | 331.358 |
| `log10f` | 357.941 | 379.189 | 332.327 | 349.427 |
| `tanhf` | 655.038 | 668.263 | 372.267 | 574.462 |
| `expm1f` | 529.615 | 540.080 | 332.875 | 340.265 |
| `powf_irrational` | 974.617 | 985.510 | 362.172 | 367.114 |

## Lever Tested

Route positive normal `log2f`/`log10f` through the existing f64 kernels and
cast back to f32. The attempted code preserved `log2f` exact powers through the
old `libm::log2f` fallback to avoid bit drift on exact powers.

## Isomorphism Proof Attempt

The attempted proof shape was:

- Ordering/tie-breaking: N/A for unary math calls.
- Floating-point: require <=4 ULP vs host glibc over a deterministic
  1,000,000-point f32 sample in `[0.5, 2.5)` plus special values.
- RNG: deterministic xorshift sample; no runtime RNG.
- Special values: zero, negative, subnormal, infinity, and NaN retain fallback
  behavior.

This proof did not matter for shipping because the performance gate failed.

## Post-Benchmark

Dirty-candidate post run on the same worker:

```text
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-um6xoq-post-target \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'log2f|log10f|powf_irrational|tanhf|expm1f|sinhf|coshf' \
  --sample-size 30 --warm-up-time 1 --measurement-time 3 --noplot
worker: ts1
```

| Bench | Baseline p50 ns/op | Post p50 ns/op | Baseline mean ns/op | Post mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `log2f` | 327.808 | 524.606 | 348.326 | 532.795 |
| `log10f` | 357.941 | 501.662 | 379.189 | 511.764 |

Gate decision: rejected. Same-worker target p50 and mean both regressed, so the
lever was not kept.

## Restore

No source change from this lever is kept. RCH artifact return restored the
attempted `float32.rs` and `conformance_diff_math.rs` edits before closeout;
`git diff` showed no remaining diff in either file.

## Next Primitive

The next attack should not retry the f64 route. The profile still points at
deeper f32 math gaps:

- `bd-cosbg1`: fused/minimax `powf` for `powf_irrational`, replacing the
  decomposed `exp2f(y * log2f(x))` structure.
- `tanhf` / `expm1f`: cancellation-aware reduced-domain kernels with a
  4-ULP-vs-glibc proof, not wrapper reroutes.
