# bd-2g7oyh.132 bcmp sub-SIMD gate certificate

## Target

- Bead: `bd-2g7oyh.132`
- Function: `frankenlibc_core::string::bcmp`
- Profile-backed target: 16-byte equal-buffer `bcmp` pays folded-block and SIMD-panel iterator setup before reaching the byte tail.
- Lever: for `count < SIMD_LANES`, scan pairs directly and return `1` on the first mismatch, otherwise `0`.

## Baseline

RCH command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_memccpy_bcmp_baseline cargo bench -p frankenlibc-bench --bench string_bench -- 'bcmp_equal|memccpy_absent' --warm-up-time 1 --measurement-time 3 --sample-size 40 --noplot
```

Worker: `ts1`

Relevant rows:

| row | Criterion estimate | STRING_BENCH p50 | STRING_BENCH mean |
| --- | ---: | ---: | ---: |
| `bcmp_equal/raw/simd/16` | 7.5135 ns | 7.503 ns | 9.254 ns |
| `bcmp_equal/raw/scalar/16` | 4.9017 ns | 4.918 ns | 8.149 ns |
| `bcmp_equal/raw/simd/64` | 2.0392 ns | 2.045 ns | 3.329 ns |
| `bcmp_equal/raw/scalar/64` | 17.011 ns | 17.061 ns | 24.866 ns |

Conclusion: the 16-byte row was the only profiled `bcmp_equal` size where the current path lost to the scalar reference; 64B and up were already decisively SIMD-favorable.

## Post-change proof benchmark

Temporary proof instrumentation added a local pre-gate sub-32B reference that reproduces the old folded-block/panel iterator setup for a 16-byte input, then removed it before the final diff.

RCH command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_bcmp_inrun_proof cargo bench -p frankenlibc-bench --bench string_bench -- bcmp_equal --warm-up-time 1 --measurement-time 3 --sample-size 40 --noplot
```

Worker: `ts2`

Same-process rows:

| row | Criterion estimate | STRING_BENCH p50 | STRING_BENCH mean |
| --- | ---: | ---: | ---: |
| new `bcmp_equal/raw/simd/16` | 9.1013 ns | 9.059 ns | 11.432 ns |
| old-path `bcmp_equal/raw/pre_gate/16` | 10.901 ns | 10.919 ns | 15.998 ns |
| scalar reference `bcmp_equal/raw/scalar/16` | 7.3802 ns | 7.377 ns | 9.438 ns |

Same-process speedup: `10.901 / 9.1013 = 1.20x` by Criterion estimate, `10.919 / 9.059 = 1.21x` by STRING_BENCH p50.

Regression guard rows from the same run:

| row | Criterion estimate | STRING_BENCH p50 | scalar Criterion estimate |
| --- | ---: | ---: | ---: |
| `bcmp_equal/raw/simd/64` | 3.1248 ns | 3.082 ns | 26.449 ns |
| `bcmp_equal/raw/simd/256` | 5.1473 ns | 5.155 ns | 109.27 ns |
| `bcmp_equal/raw/simd/1024` | 17.369 ns | 17.442 ns | 405.20 ns |
| `bcmp_equal/raw/simd/4096` | 65.985 ns | 65.987 ns | 1.5934 us |

The >=32B branch still takes the existing folded/SIMD path and remains far faster than scalar.

## Behavior proof

- Clamp semantics unchanged: `count = min(n, a.len(), b.len())` is computed before branching.
- For `count < SIMD_LANES`, old behavior had no 128B blocks and no 32B panels, then compared the byte tail left-to-right. The new branch performs the same left-to-right equality-only comparison directly.
- Return contract unchanged: `bcmp` exposes only `0` for equal prefixes and nonzero for unequal prefixes. The implementation continues to normalize mismatch to `1`.
- Ordering and tie-breaking: N/A for `bcmp`; it never reports lexical order or first-difference position.
- Floating point: N/A.
- RNG/state: N/A.
- For `count >= SIMD_LANES`, the source path is byte-for-byte the prior folded 128B / 32B panel / tail implementation.

## Golden hashes

```text
a70dc7fad4679910cf938a65e8a18b3fec0823d9c739f931345624e0b406bdc1  tests/conformance/golden/fixture_verify_strict_hardened.v1.suite.json
65311119dd6d169d9584ed825329f856739cf66b76a1c431eb7417dd56ece845  tests/conformance/fixtures/string_memory_hotpaths_wave10.json
```

## Validation

- `rustfmt +nightly --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`: pass.
- `git diff --check -- crates/frankenlibc-core/src/string/mem.rs`: pass.
- RCH `cargo test -p frankenlibc-core bcmp --lib -- --nocapture`: pass on `ts2`, 14/14 tests including `test_bcmp_sub_simd_gate_matches_equality_contract`.
- RCH `cargo check -p frankenlibc-core --all-targets`: pass on `ts1`.
- RCH `cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: blocked by pre-existing unrelated lint debt in `regex.rs`, `wide.rs`, `sort.rs`, `fnmatch.rs`, and `str.rs`; no `mem.rs` diagnostics were emitted.
- Temporary bench instrumentation was removed; final runtime diff is limited to `crates/frankenlibc-core/src/string/mem.rs`.

## Score

Score = `(Impact 3 * Confidence 4) / Effort 2 = 6.0`.

Keep rationale: the target is profile-backed, the same-process proof shows a real 16B win, larger rows stay on the faster SIMD path, and the behavior proof is exact for `bcmp`'s equality-only contract.
