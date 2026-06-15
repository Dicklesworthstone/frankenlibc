# bd-snpy1o strncasecmp_256 exact-fold rejection

Date: 2026-06-15
Agent: BoldFalcon
Base commit: 3efc6b661
Worker: ovh-a

## Target

Profile-backed row from the pass 118 broad RCH sweep:

- Benchmark: `glibc_baseline_strncasecmp_256_equal`
- FrankenLibC broad p50/mean: `10.441/15.568 ns`
- host glibc broad p50/mean: `9.221/10.699 ns`

Focused same-worker baseline:

- Command: `cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strncasecmp_256_equal --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3`
- FrankenLibC Criterion: `[10.129 ns 10.168 ns 10.214 ns]`
- FrankenLibC p50/mean: `10.178/10.909 ns`
- host glibc Criterion: `[6.6702 ns 6.7009 ns 6.7350 ns]`
- host glibc p50/mean: `6.699/8.656 ns`

## Candidate

Tested and restored a single source lever in `crates/frankenlibc-core/src/string/str.rs`:

- Add a `n == 256` case-insensitive equality certificate using four 64-lane safe-SIMD loads.
- Return `0` only after proving all 256 folded bytes equal and no left-side NUL was present.
- All short slices, non-256 lengths, NUL-containing prefixes, and mismatches fell through to the existing scalar resolver.

## Behavior proof

RCH `ovh-a` proof commands while the candidate was present:

- `cargo test -j 1 -p frankenlibc-core --test property_tests strcasecmp -- --nocapture --test-threads=1`
  - Passed `string_properties::golden_strcasecmp_corpus_sha256`.
  - Passed `string_properties::prop_strcasecmp_matches_scalar_reference`.
  - Golden SHA remained `a530194ccf71c311a33c76a479c1db79832ab66ced74b16c338273157c7cd842`.
- `cargo test -j 1 -p frankenlibc-core --test property_tests string_properties::prop_strncasecmp_matches_scalar_reference -- --exact --nocapture --test-threads=1`
  - Passed `string_properties::prop_strncasecmp_matches_scalar_reference`.

Isomorphism: ordering, tie-breaking, and NUL termination behavior were preserved by construction because the early return fired only after proving the complete `n == 256` folded-equal, NUL-free prefix. Floating-point, RNG, allocation, errno, and locale state were untouched.

## Post benchmark

Same-worker post benchmark on `ovh-a`:

- FrankenLibC Criterion: `[12.123 ns 12.205 ns 12.289 ns]`
- FrankenLibC p50/mean: `12.283/14.803 ns`
- host glibc Criterion: `[11.920 ns 12.081 ns 12.252 ns]`
- host glibc p50/mean: `12.191/13.229 ns`

Verdict: rejected and restored. FrankenLibC regressed from `10.178/10.909 ns` to `12.283/14.803 ns`; Score `0.0`.

Restored source SHA256:

`0305360b0772daceb7c7920e2e025204be11d92f4737a2d9d15fc1933f4929e8  crates/frankenlibc-core/src/string/str.rs`

## Routing

Do not retry exact 256 folded-equality certificates or lane-count reshaping for `strncasecmp_256_equal`. Return to this row only with a fundamentally different primitive, such as generated-code/backend-dispatch evidence, a branchless byte-transducer that changes the scalar resolver structure, or ABI-level classification with a fresh focused same-worker gap.
