# bd-2g7oyh.384 - exp10f profile-band f32 exp2 route

Status: rejected/restored, Score 0.0.

## Profile target

Post-`bd-2g7oyh.382` math routing on RCH `vmi1153651` showed `exp10f`
still slower than host in the profiled `[0.5, 2.5)` workload:

- FrankenLibC: p50 `606.143 ns`, mean `1031.150 ns`
- host glibc: p50 `514.231 ns`, mean `607.521 ns`

The bead was re-based onto current `origin/main` `6fcb2f76` before editing.

## Focused baseline

RCH focused baseline on `vmi1153651`:

```text
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/exp10f --noplot
```

Result:

- FrankenLibC `exp10f`: Criterion `[612.26 ns 652.47 ns 687.58 ns]`,
  p50 `601.500 ns`, p95 `731.000 ns`, p99 `817.719 ns`, mean `624.003 ns`
- host glibc `exp10f`: Criterion `[465.96 ns 498.39 ns 572.99 ns]`,
  p50 `487.179 ns`, p95 `852.000 ns`, p99 `877.870 ns`, mean `538.723 ns`

The gap reproduced, so a source lever was allowed.

## Lever tested

One bounded lever was tested in `crates/frankenlibc-core/src/math/float32.rs`:

- Replace only the existing `[0.5, 2.5]` `exp10f_profile_band` table/residual
  kernel with a fast `exp2f` route.
- Preserve exact integer exponents before the profile-band gate.
- Preserve the existing f64 fallback outside the profile band, including the
  low/subnormal range where the prior full-domain f32 route was known to fail.

Candidate variants tested:

1. `libm::exp2f(x * f32::LOG2_10)`
2. `libm::exp2f((x as f64 * f64::LOG2_10) as f32)`
3. deterministic one-ULP downward corrections on the f64-reduced result.

## Behavior proof

Ordering, tie-breaking, errno, RNG, and FP special-case routing were unchanged
for all non-profile-band paths by construction. The only changed path was finite
positive non-integer `x in [0.5, 2.5]`.

The f32 product candidate failed the existing 4-ULP contract:

- `exp10f(2.4858856)=306.11557` vs `306.11572` (`5 ULP`)
- `exp10f(2.1065679)=127.81086` vs `127.8109` (`5 ULP`)
- candidate golden SHA: `3f78266e9d6c4bc648fd6b5001c44c6e315e7e542c3647a7bce48ac179677557`

The f64-reduced candidate also failed:

- `exp10f(1.7461293)=55.735172` vs `55.735153` (`5 ULP`)
- diagnostic corpus: current `(max 6 ULP, 191 misses over 4 ULP)`;
  down-all `(max 5 ULP, 196 misses)`; down-lt2 and down-mid each had
  `4` misses over 4 ULP
- candidate golden SHA: `2a5b4cc92324b81425f5b18b803c908212276491e2bc4fca75626a7675b6d5bf`

Because behavior proof failed, no post-benchmark keep gate was run.

## Restoration

The original table/residual kernel and tests were restored. Final source check:

- `git diff -- crates/frankenlibc-core/src/math/float32.rs` is empty
- restored `float32.rs` SHA256:
  `db496ceab3a4debae6a3a2a639faf0936426cb48f0c6507461be7aa1b5f59d07`

No source behavior change is retained.

## Next route

Do not retry full-domain or profile-band `exp2f(x * log2(10))` correction
micro-levers for `exp10f`. The next `exp10f` attempt should use a materially
different artifact: generated f32-native minimax/table coefficients with a
formal 4-ULP proof over `[0.5, 2.5]`, or an underlying `exp2f` kernel replacement
with its own proof and focused benchmark.
