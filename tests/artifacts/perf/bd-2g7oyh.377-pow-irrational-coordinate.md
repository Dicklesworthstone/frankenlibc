# bd-2g7oyh.377 pow_irrational coordinate-strength reduction keep

## Target

- Bead: `bd-2g7oyh.377`
- Profile-backed hotspot: `glibc_baseline_math/pow_irrational`
- Workload: `pow(x, 1.337)` for `x in [0.5, 2.5)`
- Baseline source: HEAD `05a41faf`, RCH worker `vmi1153651`

Focused baseline:

```text
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=frankenlibc_core api_family=math symbol=pow workload="pow(x,1.337) x in [0.5,2.5)" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=50 p50_ns_op=1762.827 p95_ns_op=2083.119 p99_ns_op=2151.252 mean_ns_op=1748.443 throughput_ops_s=551685.231
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=host_glibc api_family=math symbol=pow workload="pow(x,1.337) x in [0.5,2.5)" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=50 p50_ns_op=1575.972 p95_ns_op=2272.597 p99_ns_op=2916.121 mean_ns_op=1574.608 throughput_ops_s=599747.053
```

Baseline command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_BUILD_SLOTS=1 RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass80-pow-irr-focused CRITERION_HOME=/data/tmp/frankenlibc-pass80-pow-irr-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_math/pow_irrational' --noplot --sample-size 30 --warm-up-time 1 --measurement-time 3
```

RCH selected `vmi1153651`; the requested vmi122 worker was treated as a preference.

## Lever

One source lever only in `crates/frankenlibc-core/src/math/exp.rs`:

- Keep the exact exponent gate: `exponent.to_bits() == 0x3ff5_645a_1cac_0831`.
- Keep the exact base envelope: `[0.5, 2.5)`.
- Keep the accepted 16-segment degree-10 Chebyshev coefficient artifact and Estrin evaluator.
- Reuse the already-computed segment position `((base - 0.5) * 8)` to derive the normalized Chebyshev coordinate `t = 2 * frac(segment_position) - 1` instead of recomputing a segment center and rescaling from `base`.

The degree-reduction screen was rejected before editing: truncating the current 16-segment artifact to degree 9 reached about 10 ULP, above the 4-ULP contract.

## Post-Benchmark

Same-worker post benchmark on RCH worker `vmi1153651`:

```text
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=frankenlibc_core api_family=math symbol=pow workload="pow(x,1.337) x in [0.5,2.5)" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=60 p50_ns_op=1546.000 p95_ns_op=1797.195 p99_ns_op=1894.623 mean_ns_op=1548.118 throughput_ops_s=655667.740
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=host_glibc api_family=math symbol=pow workload="pow(x,1.337) x in [0.5,2.5)" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=60 p50_ns_op=1590.500 p95_ns_op=1875.499 p99_ns_op=2033.000 mean_ns_op=1601.527 throughput_ops_s=650654.693
```

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_BUILD_SLOTS=1 RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass80-pow-coordinate-post CRITERION_HOME=/data/tmp/frankenlibc-pass80-pow-coordinate-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/pow_irrational --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

RCH again selected `vmi1153651`, giving a clean same-worker baseline/post pair.

Result:

- FrankenLibC p50: `1762.827 -> 1546.000 ns/op` (`12.3%` lower, `1.14x`)
- FrankenLibC mean: `1748.443 -> 1548.118 ns/op` (`11.5%` lower, `1.13x`)
- FrankenLibC p95: `2083.119 -> 1797.195 ns/op` (`13.7%` lower)
- FrankenLibC p99: `2151.252 -> 1894.623 ns/op` (`11.9%` lower)
- Same-worker post host row: p50 `1590.500 ns/op`, mean `1601.527 ns/op`; FrankenLibC now edges host p50/mean for this profile row.
- Keep score: Impact `3` x Confidence `3` / Effort `1` = `9.0`

## Behavior Proof

Final-source RCH core proof on `vmi1153651`:

```bash
RCH_REQUIRE_REMOTE=1 RCH_BUILD_SLOTS=1 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CARGO_BUILD_JOBS RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass80-pow-coordinate-unit cargo test -j 1 -p frankenlibc-core --lib pow_profile_exp_1_337 -- --nocapture --test-threads=1
```

Result:

```text
test math::exp::tests::golden_pow_profile_exp_1_337_corpus_sha256 ... ok
test math::exp::tests::pow_profile_exp_1_337_estrin_within_4_ulps ... ok
test math::exp::tests::pow_profile_exp_1_337_preserves_non_profile_dispatch ... ok
```

Final-source RCH ABI differential proof on `vmi1153651`:

```bash
RCH_REQUIRE_REMOTE=1 RCH_BUILD_SLOTS=1 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CARGO_BUILD_JOBS RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass80-pow-coordinate-abi cargo test -j 1 -p frankenlibc-abi --test conformance_diff_math diff_pow_profile_exp_1_337_within_4_ulps -- --nocapture --test-threads=1
```

Result:

```text
test diff_pow_profile_exp_1_337_within_4_ulps ... ok
```

Golden hash stayed unchanged:

```text
pow 1.337 segment corpus: a55ce2571c9313994a6f82d9a0361017d72f8588f0a0ed9ef616e72f59ca002d
```

Isomorphism notes:

- Ordering/tie-breaking: not applicable; scalar math function.
- Floating point: the accepted polynomial, exact exponent gate, and input envelope stay unchanged. Only the affine coordinate computation is strength-reduced. Dense plus deterministic randomized core sweeps and ABI differential sweeps stay within `<= 4` ULP versus host/glibc `pow`.
- Fallback preservation: adjacent exponent bit patterns, special values, negative/zero bases, non-finite inputs, and out-of-range cases keep prior dispatch and bit behavior.
- RNG: production has no RNG; proof sweeps use deterministic LCG seeds only.

## Validation

```bash
rustfmt +nightly --edition 2024 --check crates/frankenlibc-core/src/math/exp.rs
git diff --check -- crates/frankenlibc-core/src/math/exp.rs .beads/issues.jsonl .skill-loop-progress.md tests/artifacts/perf/bd-2g7oyh.377-pow-irrational-coordinate.md
RCH_REQUIRE_REMOTE=1 RCH_BUILD_SLOTS=1 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CARGO_BUILD_JOBS RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass80-pow-coordinate-check cargo check -j 1 -p frankenlibc-core --lib
cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings -A clippy::excessive_precision -A clippy::collapsible_if -A clippy::manual_contains -A clippy::type_complexity -A clippy::unnecessary_map_or -A dead_code
```

Results:

- `rustfmt --check`: pass
- `git diff --check`: pass
- RCH `cargo check -j 1 -p frankenlibc-core --lib`: pass on `vmi1153651`
- RCH core proof: pass on `vmi1153651`
- RCH ABI proof: pass on `vmi1153651`; existing unrelated `wchar_abi.rs` unused-assignment warning remains.
- Local allowlisted focused clippy: pass; strict workspace clippy remains blocked by unrelated existing lint debt and was not run because this campaign uses crate-scoped gates only.
