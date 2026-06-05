# bd-pha1c7: tgamma lanczos13 hot-path rejected

Date: 2026-06-05
Agent: BlackThrush
Target: `crates/frankenlibc-core/src/math/special.rs`

## Profile-backed target

Bead `bd-pha1c7` tracks `glibc_baseline_math/tgamma`, the current worst
special-function gap.

## Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 \
  rch exec -- env FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-pha1c7-tgamma-baseline-ts2 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench \
  'glibc_baseline_math/tgamma' -- --sample-size 50 \
  --measurement-time 3 --warm-up-time 1 --noplot
```

Result on worker `ts2`:

- FrankenLibC `tgamma`: p50 `6195.108 ns/op`, mean `6243.184 ns/op`
- host glibc `tgamma`: p50 `2579.864 ns/op`, mean `2666.587 ns/op`

## One lever attempted

Use Boost-style `lanczos13m53` rational coefficients for a hot positive
range, leaving poles, negative arguments, large values, and other out-of-range
cases on the existing `libm::tgamma` path.

Two arithmetic forms were tested inside the same coefficient-table lever:

- `exp((x - 0.5) * log(x + g - 0.5) - (x + g - 0.5))`
- `pow(x + g - 0.5, x - 0.5) * exp(-(x + g - 0.5))`

## Behavior proof

Core proof against the existing libm bitstream:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 \
  rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-pha1c7-tgamma-core-proof2-ts2 \
  cargo test -p frankenlibc-core tgamma_hot_range_matches_libm_within_4_ulps \
  -- --nocapture --test-threads=1
```

Result: failed on `ts2`; expanded `log/exp` form had worst `15 ULP` at
`x=1.990999999999915`.

Corrected direct-`pow` form:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 \
  rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-pha1c7-tgamma-core-proof3-ts2 \
  cargo test -p frankenlibc-core tgamma_hot_range_matches_libm_within_4_ulps \
  -- --nocapture --test-threads=1
```

Result: failed on `ts2`; worst `8 ULP` at `x=1.1069000000000124`.

Existing ABI sample proof against host glibc:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 \
  rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-pha1c7-tgamma-abi-proof-ts2 \
  cargo test -p frankenlibc-abi --test conformance_diff_math_special \
  diff_tgamma_within_4_ulps -- --nocapture --test-threads=1
```

Result: passed on `ts2`.

Dense hot-range ABI proof against host glibc was added in scratch and run:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 \
  rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-pha1c7-tgamma-abi-grid-proof-ts2 \
  cargo test -p frankenlibc-abi --test conformance_diff_math_special \
  diff_tgamma_hot_range_grid_within_4_ulps -- --nocapture --test-threads=1
```

Result: failed on `ts2`; the full `[0.5, 2.5)` gate produced multiple
5+ ULP glibc divergences. A narrower `[1.25, 2.5)` gate was also tried and
failed the same dense proof.

## Golden fixtures

No fixture files were edited. Existing math fixture hashes remained:

```text
math_ops.json = 4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35
math_finite_special_wave02.json = 269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f
math_finite_special_wave03.json = acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491
```

## Decision

Rejected before after-benchmark. The source change does not preserve the
current libm bitstream within the 4-ULP proof gate, and the dense host-glibc
proof does not pass for the attempted hot gates. The source/test edits were
not kept.

Next primitive: generate a correction-bearing tgamma artifact instead of
copying the rational table alone. Candidate: higher-order Pugh/Godfrey
coefficients or a split minimax correction against a high-precision oracle,
with proof over the whole hot interval before benchmarking.
