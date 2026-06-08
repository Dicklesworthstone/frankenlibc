# bd-2g7oyh.270 strncasecmp_256_equal folded-control mask fusion

Status: REJECTED on 2026-06-08.

## Target

Fresh broad RCH profile on `vmi1227854` showed `strncasecmp_256_equal` still
behind host glibc:

- FrankenLibC: p50 `11.523 ns/op`, mean `17.417 ns/op`
- host glibc: p50 `8.113 ns/op`, mean `10.471 ns/op`

The focused pre-change baseline first selected `vmi1149989`:

- FrankenLibC: p50 `11.189 ns/op`, mean `14.855 ns/op`, p95 `17.500`, p99 `60.500`
- host glibc: p50 `9.797 ns/op`, mean `10.727 ns/op`

## Candidate

One lever only: fuse the folded-byte inequality predicate and left-NUL predicate
inside `fold_equal_and_no_nul_simd_32` into one SIMD control mask and one
horizontal reduction.

Behavior contract:

- Ordering and tie-breaking stay scalar-defined because the helper only skips a
  full 32-byte panel when all folded bytes compare equal and the left panel has
  no NUL.
- If the right panel has a NUL and the left panel does not, the folded-diff mask
  remains true and prevents the skip.
- If both panels have matching NUL bytes, the left-NUL mask prevents the skip.
- Floating-point and RNG behavior are irrelevant for this string-only path.

## Proof

Pre-change proof:

- RCH `vmi1149989` `cargo test -p frankenlibc-core --test property_tests strcasecmp -- --nocapture --test-threads=1` passed:
  - `string_properties::golden_strcasecmp_corpus_sha256`
  - `string_properties::prop_strcasecmp_matches_scalar_reference`
- RCH `vmi1153651` `cargo test -p frankenlibc-core strcasecmp --lib -- --nocapture --test-threads=1` passed:
  - `string::str::tests::glibc_strcasecmp_case_insensitive`

Post-change proof:

- RCH `vmi1149989` `cargo test -p frankenlibc-core --test property_tests strcasecmp -- --nocapture --test-threads=1` passed the same golden SHA and scalar-reference property.
- RCH `vmi1153651` direct lib regression passed.

Golden fixture SHA-256 values before the edit were recorded:

- `tests/conformance/fixtures/string_ops.json`: `27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89`
- `tests/conformance/fixtures/string_memory_full.json`: `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`
- `crates/frankenlibc-core/tests/property_tests.rs`: `0d1b6b93fe1521f4a7e0e55b7405a07e0fe6269ffb65aad7603514daee5b555f`

## Paired benchmark

The first post-change run selected `vmi1293453`, so a clean detached baseline
worktree at `b9e890e3` was used to produce a paired same-worker A side through
RCH.

Same-worker clean baseline on `vmi1293453`:

- `strcmp_256_equal` FrankenLibC p50 `3.676 ns/op`, mean `5.114 ns/op`
- `strncmp_256_equal` FrankenLibC p50 `6.222 ns/op`, mean `7.383 ns/op`
- `strncasecmp_256_equal` FrankenLibC p50 `10.993 ns/op`, mean `13.349 ns/op`, p95 `12.599`, p99 `40.000`

Same-worker candidate on `vmi1293453`:

- `strcmp_256_equal` FrankenLibC p50 `3.721 ns/op`, mean `5.085 ns/op`
- `strncmp_256_equal` FrankenLibC p50 `6.353 ns/op`, mean `8.111 ns/op`
- `strncasecmp_256_equal` FrankenLibC p50 `10.870 ns/op`, mean `14.094 ns/op`, p95 `17.625`, p99 `45.000`

Target delta:

- p50: `10.993 -> 10.870 ns/op` (`+1.1%`)
- mean: `13.349 -> 14.094 ns/op` (`-5.6%`)
- p95: `12.599 -> 17.625 ns/op` (`-39.9%`)

## Verdict

Rejected. The p50-only improvement is below the Score >= 2.0 keep threshold and
the mean/tail regressions make the lever a net loss. Source was restored to the
pre-change implementation.

Next route: do not repeat folded-control mask fusion for this helper. Attack a
different primitive from the next profile, such as a wider ASCII panel strategy
that changes panel width/dataflow rather than reducing one existing mask.
