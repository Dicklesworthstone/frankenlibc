# bd-2g7oyh.376 exp10f profile-band table/residual kernel

Date: 2026-06-13
Agent: BoldFalcon
Status: KEPT
Score: 6.0

## Target

- Bead: `bd-2g7oyh.376`
- Scope: `crates/frankenlibc-core/src/math/float32.rs`
- Profile row: `glibc_baseline_math/exp10f`
- Workload: `exp10f(x)` for `x in [0.5, 2.5)`

The post-pow focused gate on RCH worker `vmi1153651` reproduced a material
FrankenLibC-side gap:

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC baseline | 672.555 | 675.040 | 789.234 | 808.628 |
| host glibc baseline | 447.632 | 512.057 | 509.147 | 701.000 |

The prior simple f32 `exp2f(x * LOG2_10)` route is still rejected because it
fails the full-domain 4-ULP contract around subnormal outputs near `x ~= -39`.

## Lever

One source lever:

- Keep the existing integer-exponent exact path first.
- Add a finite `[0.5, 2.5]` profile-window kernel.
- Quantize to the nearest sixteenth, look up `10^(k/16)` for `k = 8..40`, and
  evaluate a degree-5 Estrin residual for `10^r`, `|r| <= 1/32`.
- Leave all traffic outside the certified band on the existing f64 `exp2`
  fallback.

This is the table/residual primitive requested by the earlier `.275` closeout,
not the rejected all-domain f32 route.

## Isomorphism

- Ordering: integer exactness remains the first branch, so `exp10f(1.0)`,
  `exp10f(2.0)`, etc. keep the exact `powi` results.
- Tie-breaking: the profile kernel chooses nearest sixteenth by
  `(x * 16.0 + 0.5) as i32` for positive profiled inputs; bucket boundaries are
  deterministic and tested.
- Floating point: the fast path changes only finite `[0.5, 2.5]` non-integers;
  the residual is evaluated in f64 and rounded once to f32. Full-domain ABI
  differential remains within 4 ULP.
- Fallback: values below `0.5`, above `2.5`, infinities, overflow/underflow
  traffic, and the previously failing low/subnormal region still use the
  previous f64 `exp2(x * LOG2_10)` expression. `exp10f_profile_band_preserves_fallback_bits`
  checks exact fallback bits.
- RNG: not involved.
- Golden SHA-256 for the benchmark-window corpus:
  `d27316211664f96669fdc0dd45c618aeba051833b5876979af94beca3ba1df38`.

## Proof

Final-source checks:

```text
rustfmt --edition 2024 --check \
  crates/frankenlibc-core/src/math/float32.rs \
  crates/frankenlibc-abi/tests/conformance_diff_math.rs
git diff --check -- \
  crates/frankenlibc-core/src/math/float32.rs \
  crates/frankenlibc-abi/tests/conformance_diff_math.rs
```

Both passed.

```text
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1153651 RCH_WORKERS=vmi1153651 \
RCH_BUILD_SLOTS=1 RCH_VISIBILITY=summary rch exec -- env \
AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
cargo test -j 1 -p frankenlibc-core --lib exp10f -- --nocapture --test-threads=1
```

RCH worker `vmi1153651`: 4 passed. The profile-window randomized sweep reported
worst `3 ULP` at `1.7461293`; the full-domain sanity sweep reported worst
`4 ULP`.

```text
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1153651 RCH_WORKERS=vmi1153651 \
RCH_BUILD_SLOTS=1 RCH_VISIBILITY=summary rch exec -- env \
AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
cargo test -j 1 -p frankenlibc-abi --test conformance_diff_math \
  diff_exp10f_within_4_ulps -- --nocapture --test-threads=1
```

RCH worker `vmi1153651`: 1 passed. Existing unrelated warning:
`crates/frankenlibc-abi/src/wchar_abi.rs:1069` unused assignment.

```text
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1153651 RCH_WORKERS=vmi1153651 \
RCH_BUILD_SLOTS=1 RCH_VISIBILITY=summary rch exec -- env \
AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
cargo check -j 1 -p frankenlibc-core --lib
```

RCH worker `vmi1153651`: passed.

Strict local clippy initially reported one new `approx_constant` finding for
the residual `LN_10` coefficient; that was fixed by using
`core::f64::consts::LN_10`. After the fix:

```text
cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings \
  -A clippy::excessive_precision -A clippy::collapsible_if \
  -A clippy::manual_contains -A clippy::type_complexity \
  -A clippy::unnecessary_map_or -A dead_code
```

passed locally. Strict clippy remains blocked by pre-existing debt in
`exp.rs`, `sort.rs`, `fnmatch.rs`, and `regex.rs`. Remote clippy on
`vmi1153651` did not reach code because that worker lacks `cargo-clippy` for
`nightly-2026-04-28`.

## Benchmark

Same-worker focused baseline on `vmi1153651`:

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC baseline | 672.555 | 675.040 | 789.234 | 808.628 |
| host glibc baseline | 447.632 | 512.057 | 509.147 | 701.000 |

Same-worker post on `vmi1153651` after the table/residual lever, before the
source-equivalent `LN_10` literal-to-const spelling fix:

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC post | 590.751 | 605.113 | 735.982 | 812.000 |
| host glibc post | 477.017 | 827.570 | 3132.887 | 4338.666 |

FrankenLibC same-worker delta: p50 `-81.804 ns` (`1.138x` faster than
baseline) and mean `-69.927 ns` (`1.116x` faster than baseline).

Final-source post also ran after the `LN_10` spelling fix, but RCH routed it to
`vmi1227854` despite the requested worker pin, so it is recorded only as a
non-comparable confirmation:

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC final source | 294.669 | 301.520 | 411.000 | 421.000 |
| host glibc final source | 329.019 | 328.709 | 347.735 | 360.500 |

## Verdict

KEPT. Score: `6.0` (`Impact 3 x Confidence 2 / Effort 1`).

The same-worker FrankenLibC p50 and mean wins are material and the final-source
proofs pass. The residual host p50 gap on `vmi1153651` is not closed; reprofile
before choosing the next exp10f or math primitive.
