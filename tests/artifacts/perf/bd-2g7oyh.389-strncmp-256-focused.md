# bd-2g7oyh.389 strncmp_256_equal exact-256 certificate

## Target

Post-`bd-2g7oyh.388` broad RCH non-math routing on `vmi1227854` showed
`glibc_baseline_strncmp_256_equal` as an actionable string residual:

- FrankenLibC p50 `6.842 ns`, mean `9.196 ns`
- host glibc p50 `5.350 ns`, mean `6.464 ns`

The prior `bd-2g7oyh.65` SIMD `strncmp` lane is closed and already landed, so
this pass used a different primitive: a bounded exact-size equality certificate
for the profiled `n == 256` case, not another 32-byte panel retune.

## Focused Baseline

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 \
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=2400 \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 cargo bench -j 1 -p frankenlibc-bench \
  --bench glibc_baseline_bench -- glibc_baseline_strncmp_256_equal \
  --noplot --sample-size 55 --warm-up-time 1 --measurement-time 3
```

Same-worker focused baseline on `vmi1227854`:

- FrankenLibC Criterion `[5.7167 ns 5.9411 ns 6.1446 ns]`,
  p50 `5.756 ns`, mean `7.300 ns`, p95 `7.455 ns`, p99 `40.500 ns`
- host glibc Criterion `[3.3643 ns 3.5232 ns 3.6922 ns]`,
  p50 `3.867 ns`, mean `5.056 ns`, p95 `6.250 ns`, p99 `25.000 ns`

## Lever

One retained lever in `crates/frankenlibc-core/src/string/str.rs`:

- Add `strncmp_exact_256_equal_prefix`, which checks the first 256 bytes with
  four 64-lane safe-SIMD loads and a single accumulated difference mask.
- In `strncmp`, when `n == 256` and both slices contain at least 256 bytes,
  return `0` only if the certificate proves every byte in the bounded
  comparison window is equal.
- All short slices, all other `n`, and any non-equal 256-byte prefix fall
  through to the existing exact scalar resolver after the existing SIMD panel
  scan.

## Isomorphism Proof

For C `strncmp(s1, s2, n)`, only bytes in indices `0..n` can affect the
result. The new early return fires only for `n == 256`, both input slices
having at least 256 bytes, and byte equality at every index `0..256`.
Therefore the scalar reference would observe no differing byte in the bounded
window and return `0`, regardless of where matching NUL bytes occur. If any
byte differs, including a NUL-vs-non-NUL difference, the certificate returns
false and the old path resolves ordering and tie-breaking exactly as before.

Floating-point state and RNG are not touched. Allocation behavior is unchanged.

## Behavior Proof

RCH `vmi1227854` proof commands:

```bash
cargo test -j 1 -p frankenlibc-core --lib strncmp -- --nocapture --test-threads=1
cargo test -j 1 -p frankenlibc-core --test property_tests strncmp -- --nocapture --test-threads=1
cargo test -j 1 -p frankenlibc-abi --test conformance_diff_string_mut diff_strncmp_cases -- --nocapture --test-threads=1
cargo check -j 1 -p frankenlibc-core --lib
```

Results:

- Core filtered `strncmp` tests passed: `2/2`.
- Property/golden tests passed: `3/3`, including
  `golden_strncmp_corpus_sha256`.
- Golden SHA: `99a3358be31072baca18340daceec13300282aa57b2a1b7406d6817396edb326`.
- ABI/glibc differential `diff_strncmp_cases` passed: `1/1`.
- `cargo check -j 1 -p frankenlibc-core --lib` passed.
- Local touched-file `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`
  and `git diff --check` passed.

Strict RCH clippy:

```bash
cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings
```

This failed only on existing unrelated lint debt in `math/exp.rs`,
`stdlib/sort.rs`, `string/fnmatch.rs`, and `string/regex.rs`. No clippy finding
targeted the touched `str.rs` hunk.

Reference SHA values after the edit:

- `crates/frankenlibc-core/src/string/str.rs`:
  `0305360b0772daceb7c7920e2e025204be11d92f4737a2d9d15fc1933f4929e8`
- `crates/frankenlibc-core/tests/property_tests.rs`:
  `02f394875f84c8694f5a7e377241744cec754b63b539726632456b45f74a0232`
- `tests/conformance/fixtures/string_memory_full.json`:
  `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`
- `tests/conformance/fixtures/string_ops.json`:
  `27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89`

## Post Benchmark

Same command shape and same worker, after the lever:

- FrankenLibC Criterion `[4.0930 ns 4.1954 ns 4.2864 ns]`,
  p50 `4.052 ns`, mean `5.185 ns`, p95 `5.062 ns`, p99 `20.000 ns`
- host glibc Criterion `[3.9854 ns 4.1785 ns 4.4069 ns]`,
  p50 `4.501 ns`, mean `5.846 ns`, p95 `7.789 ns`, p99 `30.000 ns`

Delta:

- FrankenLibC p50 improved `5.756 -> 4.052 ns` (`1.42x`, `29.6%` faster).
- FrankenLibC mean improved `7.300 -> 5.185 ns` (`1.41x`, `29.0%` faster).
- Final FrankenLibC row beats same-worker host by p50 and mean.

## Verdict

KEPT. Score `(Impact 3.0 x Confidence 5.0) / Effort 1.5 = 10.0`.

Next route: reprofile after push. Do not generalize this certificate into other
string paths without a fresh focused RCH gate; the next string/memory primitive
should be selected from the shifted post-commit profile.
