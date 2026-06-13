# bd-2g7oyh.374 pow_irrational Estrin keep

## Target

- Bead: `bd-2g7oyh.374`
- Duplicate tracker: `bd-2g7oyh.375`
- Profile-backed hotspot: `glibc_baseline_math/pow_irrational`
- Workload: `pow(x, 1.337)` for `x in [0.5, 2.5)`
- Baseline source: HEAD `4108467b`, RCH worker `vmi1227854`

Baseline focused row:

```text
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=frankenlibc_core p50_ns_op=1069.352 p95_ns_op=1309.407 p99_ns_op=1313.211 mean_ns_op=1077.657
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=host_glibc p50_ns_op=723.255 p95_ns_op=886.829 p99_ns_op=1025.906 mean_ns_op=739.991
```

Baseline command:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/pow_irrational --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

## Lever

One source lever only in `crates/frankenlibc-core/src/math/exp.rs`:

- Keep the exact exponent gate: `exponent.to_bits() == 0x3ff5_645a_1cac_0831`.
- Keep the exact base envelope: `[0.5, 2.5)`.
- Keep the accepted 16-segment degree-10 Chebyshev coefficient table as the proof-carrying source artifact.
- Add a `const fn` Chebyshev-to-power conversion so runtime uses precomputed power-basis coefficients.
- Replace runtime Clenshaw recurrence with a degree-10 Estrin tree.

This follows the no-gaps directive's one-lever profile/proof/rebench loop and the FrankenLibC alien-artifact mapping for `math`/`fenv`: regime partitions with prevalidated approximation tables and compact deterministic runtime kernels.

## Post-Benchmark

Same-worker post benchmark on RCH worker `vmi1227854`:

```text
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=frankenlibc_core api_family=math symbol=pow workload="pow(x,1.337) x in [0.5,2.5)" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=61 p50_ns_op=738.305 p95_ns_op=954.032 p99_ns_op=959.685 mean_ns_op=767.543 throughput_ops_s=1365200.492 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=crates/frankenlibc-core/src/math/
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=host_glibc api_family=math symbol=pow workload="pow(x,1.337) x in [0.5,2.5)" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=61 p50_ns_op=776.336 p95_ns_op=921.500 p99_ns_op=986.626 mean_ns_op=790.930 throughput_ops_s=1321761.680 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=crates/frankenlibc-core/src/math/
```

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/pow_irrational --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

Result:

- FrankenLibC p50: `1069.352 -> 738.305 ns/op` (`31.0%` lower)
- FrankenLibC mean: `1077.657 -> 767.543 ns/op` (`28.8%` lower)
- FrankenLibC p95: `1309.407 -> 954.032 ns/op` (`27.1%` lower)
- FrankenLibC p99: `1313.211 -> 959.685 ns/op` (`26.9%` lower)
- Same-worker host row in post run: p50 `776.336 ns/op`, mean `790.930 ns/op`; FrankenLibC now beats host p50/mean for this profile row.
- Keep score: Impact `4` x Confidence `4` / Effort `2` = `8.0`

## Behavior Proof

RCH core proof on `vmi1227854`:

```bash
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 cargo test -j 1 -p frankenlibc-core --lib pow_profile_exp_1_337 -- --nocapture --test-threads=1
```

Result:

```text
test math::exp::tests::golden_pow_profile_exp_1_337_corpus_sha256 ... ok
test math::exp::tests::pow_profile_exp_1_337_estrin_within_4_ulps ... ok
test math::exp::tests::pow_profile_exp_1_337_preserves_non_profile_dispatch ... ok
```

RCH ABI differential proof on `vmi1227854`:

```bash
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 cargo test -j 1 -p frankenlibc-abi --test conformance_diff_math diff_pow_profile_exp_1_337_within_4_ulps -- --nocapture --test-threads=1
```

Result:

```text
test diff_pow_profile_exp_1_337_within_4_ulps ... ok
```

Golden hash:

```text
pow 1.337 segment corpus: a55ce2571c9313994a6f82d9a0361017d72f8588f0a0ed9ef616e72f59ca002d
```

Isomorphism notes:

- Ordering/tie-breaking: not applicable; scalar math function.
- Floating point: only the exact exponent bit pattern `0x3ff5_645a_1cac_0831` inside `[0.5, 2.5)` changes; dense plus deterministic randomized core sweeps and ABI differential sweeps stay within `<= 4` ULP versus host/glibc `pow`.
- Fallback preservation: adjacent exponent bit patterns keep the generic medium `exp2(log2())` route; special, negative, zero, non-finite, and out-of-range cases stay bit-identical to `libm::pow`.
- RNG: production has no RNG; proof sweeps use deterministic LCG seeds only.

## Validation

```bash
rustfmt +nightly --edition 2024 --check crates/frankenlibc-core/src/math/exp.rs
git diff --check -- crates/frankenlibc-core/src/math/exp.rs .beads/issues.jsonl
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 cargo check -j 1 -p frankenlibc-core --lib
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings -A clippy::excessive_precision -A clippy::collapsible_if -A clippy::manual_contains -A clippy::type_complexity -A clippy::unnecessary_map_or -A dead_code
```

Results:

- `rustfmt --check`: pass
- `git diff --check`: pass
- RCH `cargo check -j 1 -p frankenlibc-core --lib`: pass on `vmi1227854`
- RCH strict focused clippy: exit 101 on pre-existing lint debt in `exp.rs` LOG2 constants plus unrelated `stdlib/sort.rs`, `string/fnmatch.rs`, and `string/regex.rs`
- RCH allowlisted focused clippy for those known lint families: pass on `vmi1227854`
- Broad `cargo test -p frankenlibc-core pow_profile_exp_1_337` without `--lib` is blocked by pre-existing `BrokenDownTime` field drift in `crates/frankenlibc-core/tests/strftime_differential_probe.rs`; the narrowed `--lib` proof above passed.
